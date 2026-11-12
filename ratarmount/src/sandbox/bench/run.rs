//! Admission completes before private roots or runtime execution are created.
use super::{io as owned, record, runtime, schedule, source, BenchArgs, RuntimeKind};
use crate::sandbox::{
    client, inspection, process,
    protocol::{self, Base, BaseOptions, OperationV2, Request},
};
use owned::invalid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct Manifest {
    platforms: Vec<Platform>,
    tasks: Vec<Task>,
}
#[derive(Deserialize)]
struct Platform {
    id: String,
    image: String,
    os: String,
    architecture: String,
}
#[derive(Deserialize)]
struct Task {
    id: String,
    artifact: Artifact,
    commands: BTreeMap<String, PhaseCommand>,
    environment: BTreeMap<String, String>,
    resources: Resources,
    placement: BTreeMap<String, String>,
}
#[derive(Deserialize)]
struct Artifact {
    path: String,
    sha256: String,
    tar_stream_sha256: String,
}
#[derive(Deserialize)]
struct PhaseCommand {
    argv: Vec<String>,
    timeout_seconds: u64,
}
#[derive(Deserialize)]
struct Resources {
    max_load: f64,
    memory_bytes: u64,
    disk_bytes: u64,
    cpus: u32,
    pids: u32,
}
#[derive(Serialize, Debug)]
struct Load {
    reading: Option<f64>,
    error: Option<String>,
    maximum: f64,
    allow_high_load: bool,
}
fn load(reading: io::Result<f64>, maximum: f64, allow_high_load: bool) -> io::Result<Load> {
    let (reading, error) = match reading {
        Ok(value) if value.is_finite() && value >= 0.0 => (Some(value), None),
        Ok(_) => (None, Some("invalid host-load reading".into())),
        Err(error) => (None, Some(error.to_string())),
    };
    if !allow_high_load && (error.is_some() || reading.is_some_and(|v| v > maximum)) {
        return Err(invalid(
            "host-load check failed or exceeds max_load; use --allow-high-load",
        ));
    }
    Ok(Load {
        reading,
        error,
        maximum,
        allow_high_load,
    })
}
fn host_load() -> io::Result<f64> {
    let mut reading = 0.0;
    // Bench is compiled only by the existing Linux dispatch; no pathname acquisition.
    if unsafe { libc::getloadavg(&mut reading, 1) } != 1 {
        return Err(io::Error::other("getloadavg did not return one reading"));
    }
    Ok(reading)
}
// Resolve existing ancestors as well as lexical paths, exposing symlink aliases
// even for an output or placement root that has not been created yet.
fn resolve(path: &Path) -> io::Result<PathBuf> {
    if path.exists() {
        return path.canonicalize();
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("invalid placement path"))?;
    owned::component(name)?;
    Ok(resolve(parent)?.join(name))
}
fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn substitute(text: &str, jobs: u32) -> String {
    text.replace("{jobs}", &jobs.to_string())
}

pub(super) fn execute(
    args: &BenchArgs,
    bytes: &[u8],
    entries: &[schedule::Entry],
) -> Result<i32, String> {
    let started = Instant::now();
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let admitted = (|| -> io::Result<_> {
        for entry in entries {
            if !entry.runnable {
                return Err(invalid(
                    "execution requires qualified warm tar.zst-single-frame selections (native or FUSE)",
                ));
            }
        }
        match args.runtime_kind {
            None => {
                return Err(invalid(
                    "--runtime-kind docker|stub is required for execution",
                ))
            }
            Some(RuntimeKind::Podman) => {
                return Err(invalid("--runtime-kind podman is not yet qualified"))
            }
            _ => {}
        }
        let executable = args
            .runtime
            .as_ref()
            .ok_or_else(|| invalid("--runtime PATH is required for execution"))?
            .canonicalize()?;
        let metadata = executable.metadata()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid("runtime must be an executable regular file"));
        }
        let out = resolve(
            args.out
                .as_deref()
                .ok_or_else(|| invalid("--out is required"))?,
        )?;
        if !out.parent().is_some_and(Path::is_dir) {
            return Err(invalid("--out parent must exist as a directory"));
        }
        if out.symlink_metadata().is_ok() {
            return Err(invalid("--out must be a fresh directory"));
        }
        let work = args.work_root.canonicalize()?;
        let work_parent = owned::open_directory(&work)?;
        let id = format!(
            "rrs-bench-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos()
        );
        #[cfg(test)]
        let id = tests::fixed_id().unwrap_or(id);
        if entries.iter().any(|e| e.backend == schedule::Backend::Fuse) {
            validate_sockets(&work, &id)?;
        }
        let fuse = entries
            .iter()
            .any(|e| e.backend == schedule::Backend::Fuse)
            .then(|| {
                BenchMountConfig::new(
                    args.runtime_kind.unwrap(),
                    &work,
                    &id,
                    rustix::process::geteuid().as_raw(),
                    rustix::process::getegid().as_raw(),
                )
            })
            .transpose()?;
        let leaf = work.join(&id);
        for path in [&out, &work] {
            if path.to_str().is_none_or(|s| s.contains([':', '\n', '\r'])) {
                return Err(invalid("unsupported runtime bind path"));
            }
        }
        let catalog = args.manifest().canonicalize()?;
        let parent = catalog
            .parent()
            .ok_or_else(|| invalid("manifest has no parent"))?;
        let mut files = BTreeMap::new();
        let mut artifacts = BTreeMap::new();
        let maximum = manifest
            .tasks
            .iter()
            .filter(|t| entries.iter().any(|e| e.cell.task == t.id))
            .map(|t| t.resources.max_load)
            .fold(f64::INFINITY, f64::min);
        let load = load(host_load(), maximum, args.allow_high_load)?;
        for task in manifest
            .tasks
            .iter()
            .filter(|t| entries.iter().any(|e| e.cell.task == t.id))
        {
            for phase in task.commands.values() {
                runtime::timeout(phase.timeout_seconds)?;
            }
            let candidate = parent.join(&task.artifact.path);
            let artifact_parent = candidate
                .parent()
                .ok_or_else(|| invalid("artifact parent"))?;
            let artifact_name = candidate
                .file_name()
                .ok_or_else(|| invalid("artifact name"))?;
            let artifact = resolve(artifact_parent)?.join(artifact_name);
            let source = resolve(&parent.join(&task.placement["source"]))?;
            let output = resolve(&parent.join(&task.placement["output"]))?;
            let scratch = resolve(&parent.join(&task.placement["scratch"]))?;
            let artifact_dir = resolve(artifact_parent)?;
            if work == parent || work == artifact_dir {
                return Err(invalid("work-root equals catalog or artifact parent"));
            }
            if work.starts_with(&source) {
                return Err(invalid("work-root equals or is under placement.source"));
            }
            if executable.starts_with(&work) {
                return Err(invalid(
                    "work-root is an ancestor of the runtime executable",
                ));
            }
            if work != Path::new("/var/tmp") {
                for (path, reason) in [
                    (out.as_path(), "work-root is an ancestor of --out"),
                    (parent, "work-root is an ancestor of the catalog directory"),
                    (
                        &artifact_dir,
                        "work-root is an ancestor of the artifact parent",
                    ),
                    (&source, "work-root is an ancestor of placement.source"),
                    (&output, "work-root is an ancestor of placement.output"),
                ] {
                    if path.starts_with(&work) {
                        return Err(invalid(reason));
                    }
                }
            }
            let groups = [
                vec![
                    artifact.clone(),
                    source,
                    catalog.clone(),
                    executable.clone(),
                ],
                vec![out.clone(), output],
                vec![leaf.clone(), scratch],
            ];
            for i in 0..groups.len() {
                for j in i + 1..groups.len() {
                    if groups[i]
                        .iter()
                        .any(|a| groups[j].iter().any(|b| overlap(a, b)))
                    {
                        return Err(invalid("overlapping source/output/scratch roots"));
                    }
                }
            }
            let mut file = owned::open_artifact(&artifact)?;
            source::verify_artifact(&mut file, &task.artifact.sha256, task.resources.disk_bytes)?;
            #[cfg(test)]
            if inject("admission-slow").is_err() {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            artifacts.insert(task.id.clone(), artifact);
            files.insert(task.id.clone(), file);
        }
        let paths = record::AdmittedPaths { catalog, artifacts };
        Ok((
            executable,
            out,
            work,
            work_parent,
            id,
            files,
            load,
            paths,
            fuse,
        ))
    })();
    let (executable, out, work, work_parent, id, mut files, load, paths, fuse) = match admitted {
        Ok(value) => value,
        Err(error) => {
            eprintln!("sandbox bench: selection: {error}");
            return Ok(2);
        }
    };
    let signals = runtime::Signals::install().map_err(|e| e.to_string())?;
    for platform in manifest
        .platforms
        .iter()
        .filter(|p| entries.iter().any(|e| e.cell.platform == p.id))
    {
        let host = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        if platform.architecture != host {
            eprintln!("sandbox bench: selection: unsupported host architecture");
            return Ok(2);
        }
        if let Err(error) = runtime::inspect(
            &executable,
            &platform.image,
            &platform.os,
            &platform.architecture,
        ) {
            eprintln!("sandbox bench: selection: {error}");
            return Ok(2);
        }
    }
    let result = execute_owned(
        &manifest,
        entries,
        &executable,
        &out,
        Scratch {
            started,
            fuse,
            args,
            bytes,
            paths: &paths,
            work: &work,
            parent: &work_parent,
            id: &id,
        },
        &mut files,
        &load,
    );
    drop(signals);
    let (code, message) = presentation(result)?;
    eprintln!("{message}");
    Ok(code)
}
fn presentation(result: io::Result<record::Finished>) -> Result<(i32, String), String> {
    let finished = match result {
        Ok(finished) => finished,
        Err(error) => {
            let interrupted = runtime::interrupted();
            let message = record::lifecycle_error(interrupted, &error);
            return if interrupted {
                Ok((1, message))
            } else {
                Err(message)
            };
        }
    };
    if let Err(error) = finished.result {
        let interrupted = finished.status.status == "interrupted";
        let mut message = record::lifecycle_error(interrupted, &error);
        if !interrupted && finished.status.interrupt_observed {
            message.push_str("; interrupt observed");
        }
        return if interrupted {
            Ok((1, message))
        } else {
            Err(message)
        };
    }
    Ok(finished.status.presentation())
}

struct Scratch<'a> {
    started: Instant,
    fuse: Option<BenchMountConfig>,
    args: &'a BenchArgs,
    bytes: &'a [u8],
    paths: &'a record::AdmittedPaths,
    work: &'a Path,
    parent: &'a rustix::fd::OwnedFd,
    id: &'a str,
}
#[cfg(test)]
thread_local! {
    static FAULTS: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
    static CLEANUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static EXTRACTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(super) fn inject(name: &str) -> io::Result<()> {
    if FAULTS.with(|f| f.borrow().contains(&name)) {
        Err(io::Error::other(name.to_owned()))
    } else {
        Ok(())
    }
}
fn cleanup(parent: &rustix::fd::OwnedFd, name: &str) -> io::Result<()> {
    #[cfg(test)]
    {
        CLEANUPS.with(|count| count.set(count.get() + 1));
        inject("cleanup-fail")?;
    }
    owned::remove_tree(parent, name)
}
pub(super) fn record(outcomes: &mut File, row: &serde_json::Value) -> io::Result<()> {
    #[cfg(test)]
    inject("record-fail")?;
    serde_json::to_writer(&mut *outcomes, row)?;
    outcomes.write_all(b"\n")?;
    outcomes.sync_all()
}
const SUPERVISOR_SECONDS: u64 = 3600;
fn socket_paths(work: &Path, id: &str) -> [PathBuf; 2] {
    let leaf = work.join(format!("{id}-fuse"));
    [
        leaf.join("supervisor.sock"),
        leaf.join("state/attempts/attempt-XXXXXX/inspect.sock"),
    ]
}
fn validate_sockets(work: &Path, id: &str) -> io::Result<()> {
    for path in socket_paths(work, id) {
        inspection::validate_socket_path(&path)
            .map_err(|e| invalid(format!("{e}; choose a shorter --work-root")))?;
    }
    Ok(())
}
struct BenchMountConfig {
    options: BaseOptions,
    leaf: PathBuf,
    socket: PathBuf,
}
impl BenchMountConfig {
    fn new(kind: RuntimeKind, work: &Path, id: &str, uid: u32, gid: u32) -> io::Result<Self> {
        let allow_other = match kind {
            RuntimeKind::Docker => true,
            RuntimeKind::Stub => false,
            RuntimeKind::Podman => {
                return Err(invalid("--runtime-kind podman is not yet qualified"))
            }
        };
        let options = BaseOptions {
            allow_other,
            uid: Some(uid),
            gid: Some(gid),
            passthrough: Some("off".into()),
            ..Default::default()
        };
        if options.allow_other != matches!(kind, RuntimeKind::Docker) {
            return Err(invalid("bench mount/runtime invariant"));
        }
        Ok(Self {
            options,
            leaf: work.join(format!("{id}-fuse")),
            socket: socket_paths(work, id)[0].clone(),
        })
    }
    fn base(&self, task: &Task, path: &Path) -> Base {
        Base {
            name: task.id.clone(),
            source: path.to_string_lossy().into_owned(),
            options: self.options.clone(),
        }
    }
    fn worker(&self, base: &Base) -> Vec<String> {
        process::base_args(base, &self.leaf.join("state/indexes").join(&base.name))
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }
    fn value(&self) -> Value {
        serde_json::json!({"applicable":true,"allow_other":self.options.allow_other,"passthrough":self.options.passthrough,"uid":self.options.uid,"gid":self.options.gid,"auto_unmount":false,"leaf":self.leaf})
    }
}
fn preflight(options: &[String]) -> io::Result<()> {
    let mount = options
        .windows(2)
        .find(|p| p[0] == "-o")
        .ok_or_else(|| invalid("missing expected mount options"))?;
    #[cfg(test)]
    if tests::hook_active() {
        return tests::validate(&mount[1]);
    }
    ratarmount_fuse::validate_allow_other(&mount[1])
}
fn bench_now() -> Instant {
    #[cfg(test)]
    if let Some(now) = tests::clock() {
        return now;
    }
    Instant::now()
}
fn bench_pause() {
    #[cfg(test)]
    if tests::advance(Duration::from_millis(10)) {
        return;
    }
    std::thread::sleep(Duration::from_millis(10));
}
trait Wire: Read + Write {
    fn timeout(&mut self, duration: Duration) -> io::Result<()>;
}
impl Wire for std::os::unix::net::UnixStream {
    fn timeout(&mut self, duration: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(duration))?;
        self.set_write_timeout(Some(duration))
    }
}
fn bench_connect(
    path: &Path,
    left: &dyn Fn() -> io::Result<Duration>,
) -> io::Result<Box<dyn Wire>> {
    #[cfg(test)]
    if tests::hook_active() {
        return tests::connect(path, left);
    }
    Ok(Box::new(inspection::connect(path, left)?))
}
struct BenchClient {
    spawned: Instant,
    socket: PathBuf,
}
impl BenchClient {
    fn exchange(&self, operation: OperationV2, one_slice: bool) -> (io::Result<Value>, Duration) {
        let started = bench_now();
        let deadline =
            started + Duration::from_secs(if one_slice { 1 } else { SUPERVISOR_SECONDS });
        #[cfg(test)]
        if tests::hook_active() {
            tests::observe_deadline(deadline);
        }
        // Ordinary connect relies on single-threaded bench's signal/EINTR handling.
        let left = || {
            if !one_slice && runtime::interrupted() {
                return Err(io::Error::other("interrupted"));
            }
            deadline
                .checked_duration_since(bench_now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "bench supervisor deadline exhausted",
                    )
                })
        };
        let request = Request::new(operation);
        let result = (|| {
            let mut bytes = serde_json::to_vec(&request)?;
            let operation = serde_json::from_slice::<Value>(&bytes)?["op"]
                .as_str()
                .unwrap()
                .to_owned();
            bytes.push(b'\n');
            let mut stream = bench_connect(&self.socket, &left).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("bench supervisor {operation} connect: {e}"),
                )
            })?;
            let mut offset = 0;
            while offset < bytes.len() {
                stream.timeout(left()?.min(Duration::from_secs(1)))?;
                match stream.write(&bytes[offset..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "supervisor write returned zero",
                        ))
                    }
                    Ok(n) => offset += n,
                    Err(e)
                        if !one_slice
                            && matches!(
                                e.kind(),
                                io::ErrorKind::Interrupted
                                    | io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                            ) =>
                    {
                        continue
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut line = Vec::new();
            let mut chunk = [0; 8192];
            loop {
                stream.timeout(left()?.min(Duration::from_secs(1)))?;
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let end = chunk[..n]
                            .iter()
                            .position(|b| *b == b'\n')
                            .map_or(n, |i| i + 1);
                        line.extend_from_slice(&chunk[..end]);
                        if line.ends_with(b"\n") || line.len() > protocol::MAX_RESPONSE {
                            break;
                        }
                    }
                    Err(e)
                        if !one_slice
                            && matches!(
                                e.kind(),
                                io::ErrorKind::Interrupted
                                    | io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                            ) =>
                    {
                        continue
                    }
                    Err(e) => return Err(e),
                }
            }
            let response = client::decode_response(&line, &request).map_err(io::Error::other)?;
            if !response.ok {
                let error = response
                    .error
                    .ok_or_else(|| invalid("missing supervisor error"))?;
                return Err(io::Error::other(format!(
                    "{}: {}",
                    error.code, error.message
                )));
            }
            Ok(response.result.unwrap_or(Value::Null))
        })();
        (result, bench_now().saturating_duration_since(started))
    }
}
// Adapter internals are review-only: the injected tests observe call sites.
enum Daemon {
    Child(std::process::Child),
    #[cfg(test)]
    Fixture,
}
impl Daemon {
    fn spawn(argv: &[String], stdout: File, stderr: File) -> io::Result<Self> {
        #[cfg(test)]
        if tests::hook_active() {
            tests::spawn(argv, &stdout, &stderr);
            return Ok(Self::Fixture);
        }
        use std::os::unix::process::CommandExt;
        Ok(Self::Child(
            std::process::Command::new(std::env::current_exe()?)
                .args(argv)
                .process_group(0)
                .stdin(std::process::Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .spawn()?,
        ))
    }
    fn pid(&self) -> u32 {
        match self {
            Self::Child(child) => child.id(),
            #[cfg(test)]
            Self::Fixture => 4242,
        }
    }
    fn poll(&mut self) -> io::Result<Option<String>> {
        match self {
            Self::Child(child) => Ok(child.try_wait()?.map(|s| s.to_string())),
            #[cfg(test)]
            Self::Fixture => Ok(tests::poll()),
        }
    }
    fn kill_reap(&mut self) -> io::Result<()> {
        match self {
            Self::Child(child) => {
                let kill = child.kill();
                let wait = child.wait().map(|_| ());
                kill.and(wait)
            }
            #[cfg(test)]
            Self::Fixture => {
                tests::killed();
                Ok(())
            }
        }
    }
}
fn readiness(client: &BenchClient, daemon: &mut Daemon) -> io::Result<()> {
    let deadline = client.spawned + Duration::from_secs(30);
    let left = || {
        if runtime::interrupted() {
            return Err(io::Error::other("interrupted"));
        }
        deadline
            .checked_duration_since(bench_now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "supervisor readiness timed out")
            })
    };
    loop {
        left()?;
        if let Some(status) = daemon.poll()? {
            return Err(io::Error::other(format!(
                "supervisor exited during readiness: {status}"
            )));
        }
        match bench_connect(&client.socket, &left) {
            Ok(_) => return Ok(()),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ECONNREFUSED)) => {
                bench_pause()
            }
            Err(e) => return Err(e),
        }
    }
}
struct FuseEntry<'a> {
    task: &'a Task,
    file: &'a mut File,
    artifact: &'a Path,
    name: &'a str,
    executable: &'a Path,
    logs: &'a rustix::fd::OwnedFd,
    out: &'a Path,
    parent: &'a rustix::fd::OwnedFd,
    row: &'a mut Value,
}
struct FuseBatch {
    config: BenchMountConfig,
    client: BenchClient,
    daemon: Option<Daemon>,
    owned: bool,
    keep: bool,
    bases: std::collections::BTreeSet<String>,
    attempt: Option<String>,
}
impl FuseBatch {
    fn new(config: BenchMountConfig) -> Self {
        Self {
            client: BenchClient {
                spawned: bench_now(),
                socket: config.socket.clone(),
            },
            config,
            daemon: None,
            owned: false,
            keep: false,
            bases: Default::default(),
            attempt: None,
        }
    }
    fn call(&self, operation: OperationV2, row: &mut Value, key: &str) -> io::Result<Value> {
        let (result, elapsed) = self.client.exchange(operation, false);
        row["lifecycle_ms"][key] = serde_json::json!(elapsed.as_millis());
        result
    }
    fn recovery(&self, out: &Path) -> Value {
        serde_json::json!({"daemon_pid":self.daemon.as_ref().map(Daemon::pid),"socket":self.config.socket,"state":self.config.leaf.join("state"),"stdout_log":out.join("fuse-daemon.stdout.log"),"stderr_log":out.join("fuse-daemon.stderr.log")})
    }
    fn prepare(&mut self, context: FuseEntry<'_>) -> io::Result<PathBuf> {
        let FuseEntry {
            task,
            file,
            artifact,
            name,
            executable,
            logs,
            out,
            parent,
            row,
        } = context;
        let base = self.config.base(task, artifact);
        let preparing = bench_now();
        let prepared: io::Result<()> = (|| {
            if self.daemon.is_none() {
                preflight(&self.config.worker(&base))?;
                let leaf_name = self.config.leaf.file_name().unwrap().to_str().unwrap();
                owned::create_directory(parent, leaf_name)?;
                self.owned = true;
                let argv = vec![
                    "sandbox".into(),
                    "--socket".into(),
                    self.config.socket.to_string_lossy().into_owned(),
                    "daemon".into(),
                    "--state-dir".into(),
                    self.config
                        .leaf
                        .join("state")
                        .to_string_lossy()
                        .into_owned(),
                    "--timeout".into(),
                    SUPERVISOR_SECONDS.to_string(),
                ];
                let stdout = owned::create_output(logs, "fuse-daemon.stdout.log")?;
                let stderr = owned::create_output(logs, "fuse-daemon.stderr.log")?;
                self.client.spawned = bench_now();
                self.daemon = Some(Daemon::spawn(&argv, stdout, stderr)?);
                self.keep = true; // Remains uncertain until readiness and every create/new answer.
                row["recovery"] = serde_json::json!(out.join("fuse-recovery.json"));
                write_recovery(logs, "fuse-recovery.json", &self.recovery(out))?;
                readiness(&self.client, self.daemon.as_mut().unwrap())?;
                self.keep = false;
            }
            row["recovery"] = serde_json::json!(out.join("fuse-recovery.json"));
            if !self.bases.contains(&task.id) {
                source::verify_artifact(file, &task.artifact.sha256, task.resources.disk_bytes)?;
                self.keep = true;
                self.client
                    .exchange(
                        OperationV2::CreateBase {
                            name: base.name,
                            source: base.source,
                            options: base.options,
                        },
                        false,
                    )
                    .0?;
                self.bases.insert(task.id.clone());
            }
            self.keep = false;
            Ok(())
        })();
        row["preparation_ms"] =
            serde_json::json!(bench_now().saturating_duration_since(preparing).as_millis());
        prepared?;
        self.keep = true; // An aborted new may create a late, unnamed attempt.
        let value = self.call(
            OperationV2::New {
                base: task.id.clone(),
                count: 1,
                overlay: protocol::Overlay::Disk,
                quota: None,
                readonly_globs: vec![],
                request_id: Some(name.into()),
                lowers: vec![],
                journal: None,
                retain: false,
            },
            row,
            "new",
        )?;
        let attempt: protocol::Attempt = serde_json::from_value(
            value
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .ok_or_else(|| invalid("missing new attempt"))?,
        )?;
        self.attempt = Some(attempt.id.clone());
        let mut recovery = self.recovery(out);
        for (key, value) in serde_json::json!({"runtime":executable,"container":name,"request_id":name,"finalize_request_id":format!("{name}-finalize"),"attempt":attempt.id,"mount":attempt.path}).as_object().unwrap() { recovery[key] = value.clone(); }
        let index = row["index"].as_u64().unwrap();
        let filename = format!("{index}-recovery.json");
        write_recovery(logs, &filename, &recovery)?;
        row["recovery"] = serde_json::json!(out.join(filename));
        row["mount"]["path"] = serde_json::json!(attempt.path);
        Ok(attempt.path)
    }
    fn complete(&mut self, name: &str, row: &mut Value) -> io::Result<()> {
        if runtime::interrupted() {
            return Err(io::Error::other("interrupted"));
        }
        let id = self
            .attempt
            .clone()
            .ok_or_else(|| invalid("missing live attempt"))?;
        row["finalize"] = self.call(
            OperationV2::Finalize {
                id: id.clone(),
                pack: false,
                request_id: Some(format!("{name}-finalize")),
            },
            row,
            "finalize",
        )?;
        self.call(
            OperationV2::Destroy {
                id: Some(id),
                base: None,
            },
            row,
            "destroy",
        )?;
        self.attempt = None;
        self.keep = false;
        Ok(())
    }
    fn finish(&mut self, parent: &rustix::fd::OwnedFd) -> io::Result<()> {
        let result = (|| {
            if let Some(daemon) = &mut self.daemon {
                if self.keep || self.attempt.is_some() {
                    return Ok(());
                }
                // Choose mode at send time, including a late batch-end signal.
                self.client
                    .exchange(OperationV2::Shutdown {}, runtime::interrupted())
                    .0?;
                let deadline = bench_now() + Duration::from_secs(2);
                while daemon.poll()?.is_none() {
                    if bench_now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "supervisor reap timed out",
                        ));
                    }
                    bench_pause();
                }
            }
            if self.owned {
                owned::remove_tree(
                    parent,
                    self.config.leaf.file_name().unwrap().to_str().unwrap(),
                )?;
                self.owned = false;
            }
            Ok(())
        })();
        if self.owned {
            self.keep = true;
            if let Some(daemon) = &mut self.daemon {
                return match result {
                    Err(e) => Err(owned::with_cleanup(e, daemon.kill_reap())),
                    Ok(()) => daemon.kill_reap(),
                };
            }
        }
        result
    }
}
fn write_recovery(logs: &rustix::fd::OwnedFd, name: &str, value: &Value) -> io::Result<()> {
    let mut file = owned::create_output(logs, name)?;
    serde_json::to_writer(&mut file, value)?;
    file.sync_all()
}
fn finish_fuse(
    fuse: &mut Option<FuseBatch>,
    parent: &rustix::fd::OwnedFd,
    result: io::Result<()>,
) -> io::Result<()> {
    let cleanup = fuse.as_mut().map_or(Ok(()), |f| f.finish(parent));
    match result {
        Err(e) => Err(owned::with_cleanup(e, cleanup)),
        Ok(()) => cleanup,
    }
}

fn execute_owned(
    manifest: &Manifest,
    entries: &[schedule::Entry],
    executable: &Path,
    out: &Path,
    location: Scratch<'_>,
    files: &mut BTreeMap<String, File>,
    load: &Load,
) -> io::Result<record::Finished> {
    let host = record::uname()?;
    let load = serde_json::to_value(load).map_err(io::Error::from);
    #[cfg(test)]
    let load = load.and_then(|value| inject("load-serialize").map(|()| value));
    let load = load.map_err(|error| io::Error::new(error.kind(), format!("host load: {error}")))?;
    let Scratch {
        started,
        fuse,
        args,
        bytes,
        paths,
        work,
        parent: work_parent,
        id,
    } = location;
    let out_parent = owned::open_directory(
        out.parent()
            .ok_or_else(|| invalid("output has no parent"))?,
    )?;
    let out_name = out
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| invalid("output name"))?;
    let logs = owned::create_directory(&out_parent, out_name)?;
    let mut fuse = fuse.map(FuseBatch::new);
    let header = record::batch(args, bytes, entries, executable, paths, host, load).map(|mut header| {
        header["settings"]["fuse"] = fuse.as_ref().map_or(serde_json::json!({"applicable":false}), |f| {
            let bases: Vec<_> = manifest.tasks.iter().filter(|t| entries.iter().any(|e| e.backend == schedule::Backend::Fuse && e.cell.task == t.id)).map(|t| {
                let base = f.config.base(t, &paths.artifacts[&t.id]);
                serde_json::json!({"base":base,"expected_worker_options":f.config.worker(&base)})
            }).collect();
            serde_json::json!({"runtime_kind":args.runtime_kind,"executable":executable,"mount":f.config.value(),"bases":bases})
        });
        header
    });
    let records =
        header.and_then(|header| record::Records::create(&logs, id, header, entries, started));
    #[cfg(test)]
    let records = records.and_then(|file| inject("outcomes-create").map(|()| file));
    let mut records = match records {
        Ok(records) => records,
        Err(error) => {
            return Err(owned::with_cleanup(
                error,
                owned::remove_tree(&out_parent, out_name),
            ))
        }
    };
    let scratch_path = work.join(id);
    let mut row = records.row(0, &entries[0], Some(&scratch_path.join("0")));
    row["mount"] = serde_json::json!({"applicable":false});
    if entries[0].backend == schedule::Backend::Fuse {
        row["mount"] = fuse.as_ref().unwrap().config.value();
        row["tree"] = Value::Null;
        row["lifecycle_ms"] =
            serde_json::json!({"extract":null,"new":null,"finalize":null,"destroy":null,"total":0});
    }
    let scratch_directory = owned::create_directory(work_parent, id);
    #[cfg(test)]
    let scratch_directory = scratch_directory.and_then(|fd| inject("scratch-create").map(|()| fd));
    let scratch = match scratch_directory {
        Ok(fd) => fd,
        Err(error) => {
            let cleanup = if error.kind() == io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                cleanup(work_parent, id)
            };
            let error = owned::with_cleanup(error, cleanup);
            let (primary, secondary) = owned::error_parts(&error);
            row["reason"] = primary.clone().into();
            row["execution_error"] = primary.into();
            row["cleanup_error"] = serde_json::json!(secondary);
            let recorded = records.terminal(&row);
            return Ok(records.finish(entries, Err(owned::with_cleanup(error, recorded))));
        }
    };
    for (index, entry) in entries.iter().enumerate() {
        let task = manifest
            .tasks
            .iter()
            .find(|t| t.id == entry.cell.task)
            .unwrap();
        let platform = manifest
            .platforms
            .iter()
            .find(|p| p.id == entry.cell.platform)
            .unwrap();
        let name = format!("{id}-{index}");
        let tree_path = scratch_path.join(index.to_string());
        let is_fuse = entry.backend == schedule::Backend::Fuse;
        let probe = entry.is_probe();
        let mut started = std::time::Instant::now();
        row = records.row(index, entry, if is_fuse { None } else { Some(&tree_path) });
        row["mount"] = if is_fuse {
            fuse.as_ref().unwrap().config.value()
        } else {
            serde_json::json!({"applicable":false})
        };
        if is_fuse {
            row["lifecycle_ms"] = serde_json::json!({"extract":null,"new":null,"finalize":null,"destroy":null,"total":0});
        }
        #[cfg(test)]
        if inject("interrupt-entry").is_err() {
            runtime::test_set_interrupted();
        }
        if runtime::interrupted() {
            row["execution_error"] = "interrupted".into();
            row["stop_error"] = serde_json::Value::Null;
            let cleanup = cleanup(work_parent, id);
            row["cleanup_error"] =
                serde_json::json!(cleanup.as_ref().err().map(ToString::to_string));
            row["outcome"] = "interrupted".into();
            row["reason"] = "interrupted".into();
            row["lifecycle_ms"]["total"] = serde_json::json!(started.elapsed().as_millis());
            let recorded = records.terminal(&row);
            let result = match recorded {
                Ok(()) => cleanup,
                Err(error) => Err(owned::with_cleanup(error, cleanup)),
            };
            return Ok(records.finish(entries, finish_fuse(&mut fuse, work_parent, result)));
        }
        let prepared = (|| -> io::Result<PathBuf> {
            if is_fuse {
                let result = fuse.as_mut().unwrap().prepare(FuseEntry {
                    task,
                    file: files.get_mut(&task.id).unwrap(),
                    artifact: &paths.artifacts[&task.id],
                    name: &name,
                    executable,
                    logs: &logs,
                    out,
                    parent: work_parent,
                    row: &mut row,
                });
                started += Duration::from_millis(row["preparation_ms"].as_u64().unwrap_or(0));
                return result;
            }
            let file = files.get_mut(&task.id).unwrap();
            source::verify_artifact(file, &task.artifact.sha256, task.resources.disk_bytes)?;
            #[cfg(test)]
            inject("pre-runtime-create")?;
            let tree_root = owned::create_directory(&scratch, &index.to_string())?;
            #[cfg(test)]
            EXTRACTS.with(|count| count.set(count.get() + 1));
            source::extract(
                file,
                tree_root,
                &task.artifact.tar_stream_sha256,
                task.resources.disk_bytes,
            )?;
            let recovery =
                serde_json::json!({"runtime":executable,"container":name,"tree":tree_path});
            let recovery_file = owned::create_output(&logs, &format!("{index}-recovery.json"))?;
            #[cfg(test)]
            inject("recovery-write")?;
            serde_json::to_writer(recovery_file, &recovery)?;
            row["recovery"] = serde_json::json!(out.join(format!("{index}-recovery.json")));
            Ok(tree_path.clone())
        })();
        row["lifecycle_ms"]["extract"] = if is_fuse {
            Value::Null
        } else {
            serde_json::json!(started.elapsed().as_millis())
        };
        let prepared = prepared.and_then(|path| {
            #[cfg(test)]
            inject("mount-utf8")?;
            path.to_str()
                .ok_or_else(|| invalid("unsupported runtime bind path"))
                .map(str::to_owned)
        });
        let mount = match prepared {
            Ok(mount) => mount,
            Err(error) => {
                let error = owned::with_cleanup(error, cleanup(work_parent, id));
                row["lifecycle_ms"]["total"] = serde_json::json!(started.elapsed().as_millis());
                let (primary, secondary) = owned::error_parts(&error);
                row["reason"] = primary.clone().into();
                row["execution_error"] = primary.into();
                row["cleanup_error"] = serde_json::json!(secondary);
                if is_fuse && runtime::interrupted() {
                    row["outcome"] = "interrupted".into();
                }
                let recorded = records.terminal(&row);
                return Ok(records.finish(
                    entries,
                    finish_fuse(
                        &mut fuse,
                        work_parent,
                        Err(owned::with_cleanup(error, recorded)),
                    ),
                ));
            }
        };
        let mut runtime =
            runtime::Runtime::new(runtime::Local::new(executable), &logs, name.clone());
        let mut phases = Vec::new();
        let mut startup_succeeded = false;
        let execution = (|| -> io::Result<()> {
            let resources = &task.resources;
            let mut startup: Vec<String> = "run -d --init --pull=never --name"
                .split_ascii_whitespace()
                .map(String::from)
                .collect();
            startup.extend([
                name.clone(),
                "-v".into(),
                format!("{mount}:/repo"),
                "-w".into(),
                "/repo".into(),
            ]);
            startup.extend(
                "--network none --cap-drop ALL --security-opt no-new-privileges"
                    .split_ascii_whitespace()
                    .map(String::from),
            );
            for (flag, value) in [
                ("--pids-limit", resources.pids.to_string()),
                (
                    "--user",
                    format!(
                        "{}:{}",
                        rustix::process::getuid().as_raw(),
                        rustix::process::getgid().as_raw()
                    ),
                ),
                ("--cpus", resources.cpus.to_string()),
                ("--memory", resources.memory_bytes.to_string()),
            ] {
                startup.extend([flag.into(), value]);
            }
            startup.extend([platform.image.clone(), "sleep".into(), "infinity".into()]);
            #[cfg(test)]
            if inject("interrupt-spawn").is_err() {
                runtime::test_set_interrupted();
            }
            row["startup_argv"] = serde_json::json!(startup);
            phases.push(runtime.invoke("run", &startup, 30, true)?);
            if !phases.last().unwrap().success() {
                return Ok(());
            }
            startup_succeeded = true;
            if probe {
                return Ok(());
            }
            #[cfg(test)]
            inject("execution-fail")?;
            for phase in ["configure", "build", "test"] {
                let command = &task.commands[phase];
                let mut argv = vec!["exec".into()];
                for (key, value) in &task.environment {
                    argv.extend([
                        "-e".into(),
                        format!("{key}={}", substitute(value, entry.cell.jobs)),
                    ]);
                }
                argv.push(name.clone());
                argv.extend(command.argv.iter().map(|s| substitute(s, entry.cell.jobs)));
                phases.push(runtime.invoke(phase, &argv, command.timeout_seconds, true)?);
                if !phases.last().unwrap().success() {
                    break;
                }
            }
            Ok(())
        })();
        let execution = execution.and_then(|()| {
            if is_fuse && !runtime::interrupted() {
                let f = fuse.as_ref().unwrap();
                row["overlay_usage"] = f
                    .client
                    .exchange(
                        OperationV2::Stats {
                            id: f.attempt.clone().unwrap(),
                        },
                        false,
                    )
                    .0?;
            }
            Ok(())
        });
        let stop = runtime.stop();
        let cleanup = if is_fuse {
            if stop.is_err() || execution.is_err() {
                Err(io::Error::other(
                    "FUSE state preserved after execution/stop error",
                ))
            } else {
                fuse.as_mut().unwrap().complete(&name, &mut row)
            }
        } else if stop.is_ok() {
            cleanup(&scratch, &index.to_string())
        } else {
            Err(io::Error::other(
                "tree preserved because runtime stop failed",
            ))
        };
        let serialized = serde_json::to_value(&phases).map_err(io::Error::from);
        #[cfg(test)]
        let serialized = serialized.and_then(|value| {
            if inject("interrupt-phases-serialize").is_err() {
                runtime::test_set_interrupted();
            }
            inject("phases-serialize").map(|()| value)
        });
        let execution = match (serialized, execution) {
            (Ok(value), execution) => {
                row["phases"] = value;
                execution
            }
            // The row retains phases: [] when serialization fails.
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(primary)) => Err(io::Error::new(
                primary.kind(),
                format!("{primary}; phase serialization: {error}"),
            )),
        };
        row["execution_error"] =
            serde_json::json!(execution.as_ref().err().map(ToString::to_string));
        row["stop_error"] = serde_json::json!(stop.as_ref().err().map(ToString::to_string));
        row["cleanup_error"] = serde_json::json!(cleanup.as_ref().err().map(ToString::to_string));
        row["lifecycle_ms"]["total"] = serde_json::json!(started.elapsed().as_millis());
        if (is_fuse && runtime::interrupted())
            || (execution.is_ok()
                && phases
                    .iter()
                    .any(|p| p.error.as_deref() == Some("interrupted")))
        {
            row["outcome"] = "interrupted".into();
            row["reason"] = "interrupted".into();
        } else if execution.is_ok() && stop.is_ok() && cleanup.is_ok() {
            if probe {
                if startup_succeeded {
                    row["outcome"] = "passed".into();
                    row["reason"] = "lifecycle-only probe: not suite-graded".into();
                } else {
                    row["reason"] = "probe startup failed".into();
                }
            } else {
                records.grade(&mut row, entry, &phases);
            }
        }
        if row["outcome"] == "error" && row["reason"].is_null() {
            row["reason"] = row["execution_error"]
                .as_str()
                .or(row["stop_error"].as_str())
                .or(row["cleanup_error"].as_str())
                .map(serde_json::Value::from)
                .unwrap_or_default();
        }
        let recorded = records.terminal(&row);
        let stopped = stop.is_ok();
        let result = match (execution, stop, cleanup) {
            (Err(error), stop, cleanup) => Err(owned::with_cleanup(
                owned::with_cleanup(error, stop),
                cleanup,
            )),
            (Ok(()), Err(error), cleanup) => Err(owned::with_cleanup(error, cleanup)),
            (Ok(()), Ok(()), cleanup) => cleanup,
        };
        let result = match result {
            Err(error) => Err(owned::with_cleanup(error, recorded)),
            Ok(()) => recorded,
        };
        if let Err(error) = result {
            let error = if stopped || is_fuse {
                owned::with_cleanup(error, self::cleanup(work_parent, id))
            } else {
                error
            };
            return Ok(records.finish(entries, finish_fuse(&mut fuse, work_parent, Err(error))));
        }
        #[cfg(test)]
        if inject("interrupt-between").is_err() {
            runtime::test_set_interrupted();
        }
        if row["outcome"] != "passed" {
            break;
        }
    }
    // Also runs after the phase-failure break; the interrupt arm cleans up and returns above.
    #[cfg(test)]
    if inject("interrupt-after-last").is_err() {
        runtime::test_set_interrupted();
    }
    let result = cleanup(work_parent, id);
    #[cfg(test)]
    let result = result.and_then(|()| inject("cleanup-final-fail"));
    Ok(records.finish(entries, finish_fuse(&mut fuse, work_parent, result)))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Regression: T0 isolates supervisor effects and time without starting a mount or a daemon.
    struct Hook {
        epoch: Instant,
        elapsed: Duration,
        connect_delay: Duration,
        read_delay: Duration,
        refusals: usize,
        connects: usize,
        writes: usize,
        exited: bool,
        readiness_interrupt: bool,
        connect_error: Option<String>,
        raw_reply: Option<Vec<u8>>,
        steps: std::collections::VecDeque<(u64, bool)>,
        requests: Vec<Value>,
        deadlines: Vec<Instant>,
        argv: Vec<String>,
        stdio: Vec<bool>,
        kills: usize,
        fail: String,
        interrupt_op: String,
        validator_error: bool,
        validated: Vec<String>,
        batch: Option<PathBuf>,
        record_seen: Vec<bool>,
        fixed: Option<String>,
    }
    impl Hook {
        fn new() -> Self {
            Self {
                epoch: Instant::now(),
                elapsed: Duration::ZERO,
                connect_delay: Duration::ZERO,
                read_delay: Duration::ZERO,
                refusals: 0,
                connects: 0,
                writes: 0,
                exited: false,
                readiness_interrupt: false,
                connect_error: None,
                raw_reply: None,
                steps: Default::default(),
                requests: vec![],
                deadlines: vec![],
                argv: vec![],
                stdio: vec![],
                kills: 0,
                fail: String::new(),
                interrupt_op: String::new(),
                validator_error: false,
                validated: vec![],
                batch: None,
                record_seen: vec![],
                fixed: None,
            }
        }
    }
    thread_local! { static HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) }; }
    struct HookScope;
    impl HookScope {
        fn new() -> Self {
            HOOK.with(|h| *h.borrow_mut() = Some(Hook::new()));
            Self
        }
    }
    impl Drop for HookScope {
        fn drop(&mut self) {
            HOOK.with(|h| *h.borrow_mut() = None);
        }
    }
    fn hook<T>(f: impl FnOnce(&mut Hook) -> T) -> T {
        HOOK.with(|h| f(h.borrow_mut().as_mut().unwrap()))
    }
    pub(super) fn hook_active() -> bool {
        HOOK.with(|h| h.borrow().is_some())
    }
    pub(super) fn fixed_id() -> Option<String> {
        HOOK.with(|h| h.borrow().as_ref().and_then(|h| h.fixed.clone()))
    }
    pub(super) fn clock() -> Option<Instant> {
        HOOK.with(|h| h.borrow().as_ref().map(|h| h.epoch + h.elapsed))
    }
    pub(super) fn advance(d: Duration) -> bool {
        if !hook_active() {
            return false;
        }
        hook(|h| h.elapsed += d);
        true
    }
    pub(super) fn validate(options: &str) -> io::Result<()> {
        hook(|h| {
            h.validated.push(options.into());
            if h.validator_error {
                assert_eq!(options, "noatime,uid=1000,gid=1001,allow_other");
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    VALIDATOR_ERROR,
                ))
            } else {
                Ok(())
            }
        })
    }
    const VALIDATOR_ERROR: &str = "allow_other requested by a non-root user: add the uncommented line user_allow_other to /etc/fuse.conf";
    pub(super) fn spawn(argv: &[String], stdout: &File, stderr: &File) {
        use std::os::fd::AsRawFd;
        hook(|h| {
            h.argv = argv.to_vec();
            h.stdio = vec![
                true,
                stdout.metadata().unwrap().is_file(),
                stderr.metadata().unwrap().is_file(),
                stdout.as_raw_fd() != stderr.as_raw_fd(),
            ];
        });
        let at = argv.iter().position(|a| a == "--state-dir").unwrap();
        std::fs::create_dir_all(&argv[at + 1]).unwrap();
    }
    pub(super) fn poll() -> Option<String> {
        hook(|h| {
            (h.exited || h.requests.iter().any(|v| v["op"] == "shutdown"))
                .then(|| "exit status: 0".into())
        })
    }
    pub(super) fn observe_deadline(deadline: Instant) {
        hook(|h| h.deadlines.push(deadline));
    }
    pub(super) fn killed() {
        hook(|h| h.kills += 1);
    }
    pub(super) fn connect(
        _path: &Path,
        left: &dyn Fn() -> io::Result<Duration>,
    ) -> io::Result<Box<dyn Wire>> {
        left()?;
        hook(|h| {
            h.connects += 1;
            h.record_seen
                .push(h.batch.as_ref().is_none_or(|p| p.is_file()));
            h.elapsed += h.connect_delay;
            if h.readiness_interrupt {
                runtime::test_set_interrupted();
            }
            if let Some(error) = &h.connect_error {
                return Err(io::Error::new(io::ErrorKind::TimedOut, error.clone()));
            }
            if h.refusals > 0 {
                h.refusals -= 1;
                return Err(io::Error::from_raw_os_error(if h.refusals % 2 == 0 {
                    libc::ECONNREFUSED
                } else {
                    libc::ENOENT
                }));
            }
            Ok(Box::new(FakeWire {
                sent: vec![],
                reply: std::io::Cursor::new(vec![]),
                operation: String::new(),
                timeout: Duration::ZERO,
            }) as Box<dyn Wire>)
        })
    }
    struct FakeWire {
        sent: Vec<u8>,
        reply: std::io::Cursor<Vec<u8>>,
        operation: String,
        timeout: Duration,
    }
    impl Wire for FakeWire {
        fn timeout(&mut self, d: Duration) -> io::Result<()> {
            self.timeout = d;
            Ok(())
        }
    }
    impl Write for FakeWire {
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let step = hook(|h| {
                h.writes += 1;
                h.steps.pop_front()
            });
            let mut n = bytes.len();
            if let Some((seconds, eintr)) = step {
                advance(Duration::from_secs(seconds));
                if eintr {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                n = n.min(1);
            }
            self.sent.extend_from_slice(&bytes[..n]);
            if self.sent.ends_with(b"\n") {
                let request: Value = serde_json::from_slice(&self.sent).unwrap();
                self.operation = request["op"].as_str().unwrap().into();
                hook(|h| h.requests.push(request));
                let mut result = Value::Null;
                if self.operation == "new" {
                    let root = hook(|h| {
                        let i = h.argv.iter().position(|a| a == "--state-dir").unwrap();
                        PathBuf::from(&h.argv[i + 1])
                    });
                    let mount = root.join("attempts/attempt-abcdef/mnt");
                    std::fs::create_dir_all(&mount).unwrap();
                    std::fs::write(mount.join("source.txt"), "source").unwrap();
                    result = serde_json::json!([{"id":"attempt-abcdef","base":"mojo","path":mount,"overlay_dir":root.join("top"),"status":"ready"}]);
                }
                self.reply = std::io::Cursor::new(hook(|h| {
                    h.raw_reply.clone().unwrap_or_else(|| {
                    let failed = h.fail == self.operation || (self.operation == "finalize" && h.fail == "writers_active");
                    let mut response = serde_json::json!({"version":2,"ok":!failed,"result":result});
                    if failed { response["error"] = serde_json::json!({"code":if h.fail == "writers_active" {"writers_active"} else {"io"},"message":"injected failure"}); }
                    let mut bytes = serde_json::to_vec(&response).unwrap(); bytes.push(b'\n'); bytes
                })
                }));
            }
            Ok(n)
        }
    }
    impl Read for FakeWire {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let interrupt = hook(|h| h.interrupt_op == self.operation);
            if interrupt {
                runtime::test_set_interrupted();
                advance(self.timeout);
                return Err(io::ErrorKind::Interrupted.into());
            }
            let delay = hook(|h| std::mem::take(&mut h.read_delay));
            advance(delay);
            self.reply.read(bytes)
        }
    }
    fn fuse_fixture() -> Fixture {
        let mut f = Fixture::new();
        f.entries = vec![schedule::build(
            &f.bytes,
            &super::super::Selection {
                backend: vec![schedule::Backend::Fuse],
                cache: vec![schedule::Cache::Warm],
                base_form: vec![schedule::BaseForm::TarZstSingleFrame],
                repeats: Some(1),
                ..Default::default()
            },
        )
        .unwrap()
        .last()
        .unwrap()
        .clone()];
        hook(|h| h.batch = Some(f.dir.path().join("out/fuse-recovery.json")));
        f
    }
    fn request_count(op: &str) -> usize {
        hook(|h| h.requests.iter().filter(|r| r["op"] == op).count())
    }
    fn client() -> BenchClient {
        BenchClient {
            spawned: hook(|h| h.epoch),
            socket: "/test/supervisor.sock".into(),
        }
    }
    fn shutdown() -> OperationV2 {
        OperationV2::Shutdown {}
    }
    fn keep_assertions(f: &Fixture, case: &str) {
        assert_eq!(request_count("destroy"), 0, "{case}: destroy lost state");
        assert_eq!(request_count("shutdown"), 0, "{case}: Shutdown lost state");
        assert_eq!(hook(|h| h.kills), 1, "{case}: Child::kill missing");
        assert!(
            f.dir.path().join("work/owned-test-fuse/state").is_dir(),
            "{case}: leaf lost"
        );
        assert!(
            !f.dir.path().join("work/owned-test").exists(),
            "{case}: scratch leaked"
        );
    }
    // Regression: connect and reply reset their deadlines, and a later exchange inherited spawn's deadline.
    #[test]
    fn regression_bench_client_deadline_includes_connect_and_reply() {
        let _signals = runtime::InterruptScope::new();
        let _hooks = HookScope::new();
        hook(|h| {
            h.connect_delay = Duration::from_secs(2);
            h.read_delay = Duration::from_secs(3599);
            h.raw_reply = Some(b"{}".to_vec());
        });
        let (result, elapsed) = client().exchange(shutdown(), false);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("deadline exhausted"));
        assert_eq!(elapsed, Duration::from_secs(3601));
        // Regression: a complete reply succeeds even when its final read spends the deadline.
        hook(|h| {
            h.raw_reply = None;
            h.read_delay = Duration::from_secs(3599);
        });
        assert!(client().exchange(shutdown(), false).0.is_ok());
        // Regression: TB1 exchange deadline is per exchange, even beyond 3600 seconds after spawn.
        hook(|h| {
            h.connect_delay = Duration::ZERO;
            h.elapsed = Duration::ZERO;
            h.requests.clear();
        });
        let mut f = fuse_fixture();
        assert_eq!(f.run().unwrap().status, "passed");
        hook(|h| h.elapsed = Duration::from_secs(3700));
        let started = bench_now();
        assert!(
            client().exchange(shutdown(), false).0.is_ok(),
            "TB1: late exchange refused"
        );
        assert_eq!(
            hook(|h| *h.deadlines.last().unwrap()),
            started + Duration::from_secs(3600),
            "TB1: deadline not from exchange start"
        );
        assert!(
            hook(|h| h.argv.windows(2).any(|w| w == ["--timeout", "3600"])),
            "TB1: daemon default timeout"
        );
    }
    // Regression: short writes and bare EINTR must recompute the same absolute deadline.
    #[test]
    fn regression_bench_client_short_writes_and_interrupts_share_deadline() {
        let _signals = runtime::InterruptScope::new();
        let _hooks = HookScope::new();
        hook(|h| h.steps = [(1800, false), (1801, true)].into());
        let (result, elapsed) = client().exchange(shutdown(), false);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("deadline exhausted"));
        assert_eq!(elapsed, Duration::from_secs(3601));
        assert_eq!(hook(|h| h.writes), 2);
        hook(|h| h.steps = [(1, true), (1, false)].into());
        assert!(
            client().exchange(shutdown(), false).0.is_ok(),
            "bare EINTR aborted without interrupt flag"
        );
    }
    // Regression: connect failures lost elapsed time/context or bypassed the legacy decode rules (T4).
    #[test]
    fn regression_bench_client_failed_exchange_retains_elapsed() {
        let _signals = runtime::InterruptScope::new();
        let _hooks = HookScope::new();
        hook(|h| {
            h.connect_delay = Duration::from_secs(4);
            h.connect_error =
                Some("inspection timed out: /test/supervisor.sock accepted no connection".into());
        });
        let op = || OperationV2::New {
            base: "x".into(),
            count: 1,
            overlay: protocol::Overlay::Disk,
            quota: None,
            readonly_globs: vec![],
            request_id: None,
            lowers: vec![],
            journal: None,
            retain: false,
        };
        let (result, elapsed) = client().exchange(op(), false);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "bench supervisor new connect: inspection timed out: /test/supervisor.sock accepted no connection");
        assert_eq!(elapsed, Duration::from_secs(4));
        hook(|h| {
            h.connect_error = None;
            h.connect_delay = Duration::from_secs(3601);
        });
        assert!(client()
            .exchange(shutdown(), false)
            .0
            .unwrap_err()
            .to_string()
            .contains("deadline exhausted"));
        hook(|h| h.connect_delay = Duration::ZERO);
        for line in [b"{}".to_vec(), vec![b'x'; protocol::MAX_RESPONSE + 1], b"{bad}\n".to_vec(), b"{\"version\":1,\"ok\":true}\n".to_vec(), b"{\"version\":1,\"ok\":false,\"error\":{\"code\":\"unsupported_version\",\"message\":\"old daemon\"}}\n".to_vec()] {
            // Regression: incomplete/oversized/Serde/version and old-daemon errors retain legacy decoding.
            let expected = client::decode_response(&line, &Request::new(shutdown())).map(|r| { let error = r.error.unwrap(); format!("{}: {}",error.code,error.message) }).unwrap_or_else(|e|e);
            hook(|h| h.raw_reply = Some(line));
            assert_eq!(client().exchange(shutdown(), false).0.unwrap_err().to_string(), expected);
        }
    }
    // Regression: readiness wrote early, used the operation bound, or lost crash diagnostics and interrupted state.
    #[test]
    fn regression_bench_supervisor_readiness_retries_refused_connect() {
        let _signals = runtime::InterruptScope::new();
        for case in [
            // Regression: retry refused and absent sockets without early request bytes.
            "retry",
            // Regression: an exited daemon must fail readiness before writing.
            "exited",
            // Regression: readiness must stop at 30 seconds, not the operation cap.
            "timeout",
            // Regression: readiness interrupt must stop connects immediately and keep state.
            "interrupt",
        ] {
            let _signals = runtime::Signals::install().unwrap();
            let _hooks = HookScope::new();
            let mut f = fuse_fixture();
            hook(|h| {
                h.refusals = if case == "retry" { 3 } else { usize::MAX };
                h.exited = case == "exited";
                h.readiness_interrupt = case == "interrupt";
                if case == "timeout" {
                    h.connect_delay = Duration::from_secs(1);
                }
            });
            let result = f.run();
            if case == "retry" {
                assert!(result.is_ok(), "retry: readiness did not recover");
                assert_eq!(result.unwrap().status, "passed");
                assert_eq!(hook(|h| h.connects), 10); // Four readiness + six exchanges.
                assert_eq!(
                    hook(|h| h.writes),
                    6,
                    "retry: request written before readiness"
                );
            } else {
                assert!(result.is_err(), "{case}: readiness error ignored");
                assert_eq!(hook(|h| h.writes), 0, "{case}: bytes before readiness");
                keep_assertions(&f, case);
                if case == "timeout" {
                    assert!(
                        hook(|h| h.elapsed) >= Duration::from_secs(30)
                            && hook(|h| h.elapsed) < Duration::from_secs(32),
                        "timeout: readiness not bounded at 30 s"
                    );
                }
                if case == "interrupt" {
                    assert_eq!(hook(|h| h.connects), 1);
                    assert!(hook(|h| h.elapsed) < Duration::from_secs(1));
                    assert_eq!(f.rows()[0]["outcome"], "interrupted");
                }
            }
            let recovery: Value = serde_json::from_slice(
                &std::fs::read(f.dir.path().join("out/fuse-recovery.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(recovery["daemon_pid"], 4242);
            for key in ["socket", "state", "stdout_log", "stderr_log"] {
                assert!(
                    recovery[key]
                        .as_str()
                        .unwrap()
                        .contains(if key.ends_with("log") {
                            "out/fuse-daemon."
                        } else {
                            "owned-test-fuse/"
                        }),
                    "{case}: {key}"
                );
            }
            assert!(
                hook(|h| h.record_seen.iter().all(|seen| *seen)),
                "{case}: recovery record late"
            );
            assert_eq!(
                hook(|h| h.stdio.clone()),
                vec![true; 4],
                "{case}: owned separate logs"
            );
        }
    }
    // Regression: supervisor.sock fit but the daemon's later inspect.sock exceeded the actual sockaddr bound.
    #[test]
    fn regression_bench_fuse_inspect_socket_too_long_refused_before_creation() {
        let _signals = runtime::InterruptScope::new();
        let _hooks = HookScope::new();
        let id = "fixed-bench-id";
        hook(|h| h.fixed = Some(id.into()));
        let limit = (1..1024)
            .find(|n| inspection::validate_socket_path(Path::new(&"x".repeat(*n))).is_err())
            .unwrap();
        let mut f = fuse_fixture();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let wanted = limit - id.len() - 49;
        let candidate = f.dir.path().canonicalize().unwrap();
        let fallback = root.path().canonicalize().unwrap();
        let base = if candidate.as_os_str().len() + 1 < wanted {
            candidate.as_path()
        } else {
            fallback.as_path()
        };
        assert!(
            base.as_os_str().len() + 1 < wanted,
            "short socket test root must be buildable"
        );
        let work = base.join("w".repeat(wanted - base.as_os_str().len() - 1));
        assert_eq!(work.as_os_str().len(), wanted);
        std::fs::create_dir(&work).unwrap();
        f.args.work_root = work.clone();
        f.args.allow_high_load = true;
        let paths = socket_paths(&work, id);
        assert!(inspection::validate_socket_path(&paths[0]).is_ok());
        assert!(inspection::validate_socket_path(&paths[1]).is_err());
        let validated = validate_sockets(&work, id);
        assert!(validated.is_err(), "inspect socket must fail admission");
        assert!(validated
            .unwrap_err()
            .to_string()
            .contains("choose a shorter --work-root"));
        assert_eq!(execute(&f.args, &f.bytes, &f.entries).unwrap(), 2);
        assert_eq!(std::fs::read_dir(&work).unwrap().count(), 0);
        assert!(!f.dir.path().join("out").exists());
        assert!(hook(|h| h.argv.is_empty()
            && h.validated.is_empty()
            && h.requests.is_empty()));
    }
    // Regression: Docker could not traverse an owner-only mount, or stub enabled allow_other/passthrough.
    #[test]
    fn regression_bench_container_mount_requests_allow_other() {
        for (case, kind, other) in [
            // Regression: regression_bench_container_mount_requests_allow_other requires container access.
            (
                "regression_bench_container_mount_requests_allow_other",
                RuntimeKind::Docker,
                true,
            ),
            // Regression: regression_bench_stub_mount_is_owner_only must keep the fixture owner-only.
            (
                "regression_bench_stub_mount_is_owner_only",
                RuntimeKind::Stub,
                false,
            ),
        ] {
            let config = BenchMountConfig::new(kind, Path::new("/tmp"), "x", 1000, 1001);
            assert!(
                config.is_ok(),
                "{case}: mount invariant refused configuration"
            );
            let config = config.unwrap();
            let f = Fixture::new();
            let base = config.base(&f.manifest.tasks[0], Path::new("/source"));
            let worker = config.worker(&base);
            assert_eq!(config.options.allow_other, other, "{case}");
            assert!(
                worker.windows(2).any(|p| p == ["--passthrough", "off"]),
                "{case}: passthrough"
            );
            assert!(
                worker.windows(2).any(|p| p
                    == [
                        "-o",
                        if other {
                            "noatime,uid=1000,gid=1001,allow_other"
                        } else {
                            "noatime,uid=1000,gid=1001"
                        }
                    ]),
                "{case}: mount options"
            );
        }
    }
    // Regression: allow_other validation happened after FUSE effects or swallowed its kind/message (NB2).
    #[test]
    fn regression_bench_allow_other_validator_error_preserved_before_effects() {
        let _signals = runtime::InterruptScope::new();
        let _hooks = HookScope::new();
        let mut f = fuse_fixture();
        let mut fuse = FuseBatch::new(
            BenchMountConfig::new(
                RuntimeKind::Docker,
                &f.dir.path().join("work"),
                "owned-test",
                1000,
                1001,
            )
            .unwrap(),
        );
        let logs = owned::open_directory(&f.dir.path().join("state")).unwrap();
        let parent = owned::open_directory(&f.dir.path().join("work")).unwrap();
        let mut file = owned::open_artifact(&f.dir.path().join("archive")).unwrap();
        let mut row = serde_json::json!({"index":0,"lifecycle_ms":{},"mount":{}});
        hook(|h| h.validator_error = true);
        let mut prepare = |fuse: &mut FuseBatch, task: &Task, row: &mut Value| {
            fuse.prepare(FuseEntry {
                task,
                file: &mut file,
                artifact: Path::new("/source"),
                name: "x",
                executable: Path::new("/runtime"),
                logs: &logs,
                out: &f.dir.path().join("state"),
                parent: &parent,
                row,
            })
        };
        let result = prepare(&mut fuse, &f.manifest.tasks[0], &mut row);
        assert!(result.is_err(), "validator error swallowed");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), VALIDATOR_ERROR);
        assert_eq!(
            hook(|h| h.validated.clone()),
            ["noatime,uid=1000,gid=1001,allow_other"]
        );
        assert!(hook(|h| h.argv.is_empty() && h.requests.is_empty()));
        assert_eq!(
            std::fs::read_dir(f.dir.path().join("work"))
                .unwrap()
                .count(),
            0
        );
        assert!(f.calls().is_empty());
        hook(|h| h.validator_error = false);
        let digest = std::mem::take(&mut f.manifest.tasks[0].artifact.sha256);
        // Regression: first-entry verification failure after readiness has no attempt to keep.
        assert!(prepare(&mut fuse, &f.manifest.tasks[0], &mut row)
            .unwrap_err()
            .to_string()
            .contains("artifact sha256 mismatch"));
        // Regression: readiness success must clear keep before source verification can fail.
        assert!(!fuse.keep);
        f.manifest.tasks[0].artifact.sha256 = digest;
        f.manifest.tasks[0].id = "later".into();
        row["recovery"] = Value::Null;
        hook(|h| h.fail = "create_base".into());
        // Regression: a later create_base failure with an existing daemon retains batch recovery.
        assert!(prepare(&mut fuse, &f.manifest.tasks[0], &mut row)
            .unwrap_err()
            .to_string()
            .contains("io: injected failure"));
        // Regression: the fresh row points at the batch file even before create_base succeeds.
        assert_eq!(
            row["recovery"],
            serde_json::json!(f.dir.path().join("state/fuse-recovery.json"))
        );
        // Regression: the batch recovery pointer names the file already written at spawn.
        assert!(f.dir.path().join("state/fuse-recovery.json").is_file());
    }
    // Regression: native-only records omitted explicit FUSE inapplicability.
    #[test]
    fn regression_bench_native_only_records_fuse_not_applicable() {
        let _signals = runtime::InterruptScope::new();
        let mut f = Fixture::new();
        f.run().unwrap();
        let header: Value =
            serde_json::from_slice(&std::fs::read(f.dir.path().join("out/batch.json")).unwrap())
                .unwrap();
        assert_eq!(
            header["settings"]["fuse"],
            serde_json::json!({"applicable":false})
        );
        assert!(f
            .executed()
            .iter()
            .all(|r| r["mount"] == serde_json::json!({"applicable":false})));
    }
    // Regression: finalize errors or in-flight interrupts destroyed state during native scratch cleanup.
    #[test]
    fn regression_bench_fuse_failed_finalize_preserves_attempt() {
        let _signals = runtime::InterruptScope::new();
        for (case, failure, interrupt) in [
            // Regression: io finalize failure must retain state.
            ("io", "finalize", ""),
            // Regression: regression_bench_writers_active_finalize_keeps_state is single-shot.
            (
                "regression_bench_writers_active_finalize_keeps_state",
                "writers_active",
                "",
            ),
            // Regression: interrupt during finalize aborts the exchange before its deadline.
            (
                "interrupt during finalize aborts the exchange",
                "",
                "finalize",
            ),
            // Regression: interrupt during new keeps without Shutdown; a late attempt id is unknown.
            (
                "interrupt during new keeps without Shutdown", // raised while awaiting reply
                "",
                "new",
            ),
        ] {
            let _signals = runtime::Signals::install().unwrap();
            let _hooks = HookScope::new();
            let mut f = fuse_fixture();
            hook(|h| {
                h.fail = failure.into();
                h.interrupt_op = interrupt.into();
            });
            assert!(f.run().is_err(), "{case}: failure ignored");
            keep_assertions(&f, case);
            if interrupt == "new" {
                assert_eq!(
                    f.rows()[0]["recovery"],
                    serde_json::json!(f.dir.path().join("out/fuse-recovery.json"))
                );
                assert!(!f.dir.path().join("out/0-recovery.json").exists());
                continue;
            }
            assert_eq!(request_count("finalize"), 1, "{case}: retried finalize");
            let request = hook(|h| {
                h.requests
                    .iter()
                    .find(|r| r["op"] == "finalize")
                    .unwrap()
                    .clone()
            });
            assert_eq!(
                request["request_id"], "owned-test-0-finalize",
                "{case}: finalize id"
            );
            assert!(!request["pack"].as_bool().unwrap_or(false));
            let recovery: Value = serde_json::from_slice(
                &std::fs::read(f.dir.path().join("out/0-recovery.json")).unwrap(),
            )
            .unwrap();
            for key in [
                "daemon_pid",
                "socket",
                "state",
                "request_id",
                "finalize_request_id",
                "attempt",
                "mount",
            ] {
                assert!(!recovery[key].is_null(), "{case}: {key}");
            }
            assert_eq!(
                f.rows()[0]["recovery"],
                serde_json::json!(f.dir.path().join("out/0-recovery.json"))
            );
            if !interrupt.is_empty() {
                assert_eq!(f.rows()[0]["outcome"], "interrupted");
                assert!(
                    hook(|h| h.elapsed) < Duration::from_secs(2),
                    "{case}: waited for deadline"
                );
            }
            if failure == "writers_active" {
                assert!(f.rows()[0]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("writers_active"));
            }
        }
    }
    // Regression: lifecycle-only probes were suite-graded or passed failed startup/finalize lifecycles.
    #[test]
    fn regression_bench_empty_top_probe_excluded_from_suite() {
        let _signals = runtime::InterruptScope::new();
        for case in [
            // Regression: success requires one Shutdown and removal of the reaped daemon's leaf.
            "success", // Regression: a failed finalize must never pass the probe.
            "finalize",
            // Regression: nonzero startup must remain an error with its exit status.
            "startup",
        ] {
            let _hooks = HookScope::new();
            let mut f = fuse_fixture();
            if case == "finalize" {
                hook(|h| h.fail = "finalize".into());
            }
            if case == "startup" {
                std::fs::write(f.dir.path().join("state/run-fail"), "").unwrap();
            }
            let result = f.run();
            let row = &f.rows()[0];
            assert_eq!(
                row["phases"].as_array().unwrap().len(),
                1,
                "{case}: probe ran suite"
            );
            assert!(row["summary"].is_null(), "{case}: probe was graded");
            assert_eq!(row["tree"], Value::Null);
            assert!(row["lifecycle_ms"]["extract"].is_null());
            assert!(!row["preparation_ms"].is_null());
            if case == "success" {
                assert_eq!(request_count("shutdown"), 1);
                assert_eq!(result.unwrap().status, "passed");
                assert_eq!(row["outcome"], "passed");
                assert_eq!(row["reason"], "lifecycle-only probe: not suite-graded");
                assert!(!f.dir.path().join("work/owned-test-fuse").exists());
            } else {
                assert_ne!(row["outcome"], "passed", "{case}: failed lifecycle passed");
                if case == "startup" {
                    assert_eq!(row["outcome"], "error");
                    assert_eq!(row["phases"][0]["exit_code"], 17);
                }
            }
        }
    }
    // Regression: the runtime bind exposed the attempt parent instead of the returned mount.
    #[test]
    fn regression_bench_only_returned_attempt_path_passed_to_stub() {
        let _signals = runtime::InterruptScope::new();
        let _hooks = HookScope::new();
        let mut f = fuse_fixture();
        f.run().unwrap();
        let row = &f.rows()[0];
        let mount = f
            .dir
            .path()
            .join("work/owned-test-fuse/state/attempts/attempt-abcdef/mnt");
        assert_eq!(row["mount"]["path"], serde_json::json!(mount));
        assert_eq!(row["startup_argv"][7], format!("{}:/repo", mount.display()));
        assert!(f.calls().contains(&format!("{}:/repo", mount.display())));
        assert_eq!(request_count("new"), 1);
        assert_eq!(request_count("destroy"), 1);
    }
    // Regression: interrupt after new sent destroy/Shutdown, losing the live attempt.
    #[test]
    fn regression_bench_interrupt_with_live_attempt_keeps_state() {
        let _signals = runtime::InterruptScope::new();
        let _hooks = HookScope::new();
        let mut f = fuse_fixture();
        let _fault = FaultScope::new(&["interrupt-spawn"]);
        // Regression: a live-attempt interrupt must also return the interrupted error.
        assert!(f.run().unwrap_err().to_string().contains("interrupted"));
        keep_assertions(&f, "live attempt");
        assert_eq!(request_count("new"), 1);
        assert_eq!(f.rows()[0]["outcome"], "interrupted");
        assert!(f.dir.path().join("out/0-recovery.json").is_file());
    }
    // Regression: uname must fail explicitly before creating output or scratch (5b).
    #[test]
    fn regression_bench_uname_failure_creates_nothing() {
        let _signals = runtime::InterruptScope::new();
        let mut f = Fixture::new();
        let _fault = FaultScope::new(&["uname-fail"]);
        assert!(f
            .run()
            .unwrap_err()
            .to_string()
            .contains("host identity: uname failed"));
        assert!(!f.dir.path().join("out").exists());
        assert!(!f.dir.path().join("work/owned-test").exists());
        assert!(!f.calls().contains("run -d"));
    }
    // Regression: every outer lifecycle error retains the interrupt form, including uname and host-load serialization before output creation.
    #[test]
    fn regression_bench_outer_lifecycle_error_keeps_interrupted_form() {
        let _scope = runtime::InterruptScope::new();
        for fault in ["outcomes-create", "uname-fail", "load-serialize"] {
            for interrupted in [false, true] {
                let _signals = runtime::Signals::install().unwrap();
                let mut f = Fixture::new();
                let _fault = FaultScope::new(&[fault]);
                if interrupted {
                    runtime::test_set_interrupted();
                }
                let result = f.run_finished();
                let error = match fault {
                    "uname-fail" => "host identity: uname failed: uname-fail",
                    "load-serialize" => "host load: load-serialize",
                    _ => "outcomes-create",
                };
                assert_eq!(result.as_ref().unwrap_err().to_string(), error);
                assert_eq!(
                    presentation(result),
                    if interrupted {
                        Ok((1, format!("sandbox bench: interrupted: batch incomplete; lifecycle error: {error}")))
                    } else {
                        Err(format!("bench native lifecycle: {error}"))
                    }
                );
                assert!(!f.dir.path().join("out").exists());
                assert!(!f.dir.path().join("out/batch-end.json").exists());
                if fault == "load-serialize" {
                    assert!(!f.dir.path().join("work/owned-test").exists());
                }
            }
        }
    }
    // Regression: header failures leaked output and end-marker/dir-fsync/final-cleanup failures claimed passed (N2/N6).
    #[test]
    fn regression_bench_record_header_and_end_failures() {
        let _signals = runtime::InterruptScope::new();
        for (name, fault) in [
            ("batch.json", "record-header-fail:batch.json"),
            ("schedule.jsonl", "record-header-fail:schedule.jsonl"),
            ("batch-end.json", "record-header-fail:batch-end.json"),
            ("batch-end.json", "record-end-fsync-fail:batch-end.json"),
        ] {
            let mut f = Fixture::new();
            let _fault = FaultScope::new(&[fault]);
            let result = f.run_finished();
            let error = match &result {
                Ok(finished) => finished.result.as_ref().unwrap_err(),
                Err(error) => error,
            };
            assert_eq!(owned::error_parts(error).0, fault);
            let shown = presentation(result).unwrap_err();
            assert!(shown.starts_with("bench native lifecycle:"));
            if fault == "record-end-fsync-fail:batch-end.json" {
                assert_eq!(shown, format!("bench native lifecycle: {fault}"));
            }
            assert!(!f.dir.path().join("out/batch-end.json").exists());
            assert!(!f.dir.path().join("out/.batch-end.json.tmp").exists());
            assert_eq!(f.dir.path().join("out").exists(), name == "batch-end.json");
            assert!(!f.dir.path().join("work/owned-test").exists());
        }
        let mut f = Fixture::new();
        let _fault = FaultScope::new(&["cleanup-final-fail"]);
        assert!(f
            .run()
            .unwrap_err()
            .to_string()
            .contains("cleanup-final-fail"));
        let end = f.end();
        assert_eq!(end["status"], "error");
        assert_eq!(end["error"], "cleanup-final-fail");
        owned::remove_tree(
            &owned::open_directory(&f.dir.path().join("work")).unwrap(),
            "owned-test",
        )
        .unwrap();
    }
    // Regression: a late interrupt rewrote completed outcomes or a failure's blocked reason (14/N4).
    #[test]
    fn regression_bench_interrupt_after_last_entry_keeps_outcomes() {
        let _signals = runtime::InterruptScope::new();
        for fails in [false, true] {
            let signals = runtime::Signals::install().unwrap();
            let mut f = Fixture::new();
            if fails {
                std::fs::write(f.dir.path().join("state/tap-fail-zero"), "").unwrap();
            }
            let _fault = FaultScope::new(&["interrupt-after-last"]);
            let status = f.run().unwrap();
            assert_eq!(status.status, if fails { "failed" } else { "passed" });
            assert!(status.interrupt_observed);
            assert!(status.presentation().1.contains("; interrupt observed"));
            assert!(status
                .presentation()
                .1
                .contains(if fails { "failed:" } else { "passed:" }));
            let rows = f.rows();
            assert_eq!(rows.len(), 3);
            assert_eq!(f.executed().len(), if fails { 1 } else { 3 });
            if fails {
                assert_eq!(rows[0]["outcome"], "failed");
                assert!(rows[1..]
                    .iter()
                    .all(|r| r["outcome"] == "blocked" && r["reason"] == "FAIL with exit 0"));
            } else {
                assert!(rows.iter().all(|r| r["outcome"] == "passed"));
            }
            assert_eq!(f.end()["status"], status.status);
            assert_eq!(f.end()["interrupt_observed"], true);
            drop(signals);
        }
    }
    // Regression: late signals and lifecycle errors made stderr disagree with the frozen end marker.
    #[test]
    fn regression_bench_late_signal_lifecycle_status_matches_end() {
        let _scope = runtime::InterruptScope::new();
        for (fault, lifecycle_error) in [
            ("interrupt-after-status", true),
            ("interrupt-after-last", true),
            ("interrupt-after-status", false),
        ] {
            let _signals = runtime::Signals::install().unwrap();
            let mut f = Fixture::new();
            let mut faults = vec![fault];
            if lifecycle_error {
                faults.push("cleanup-final-fail");
            }
            let _fault = FaultScope::new(&faults);
            let finished = f.run_finished().unwrap();
            assert!(runtime::interrupted());
            let end = f.end();
            assert_eq!(
                end["status"],
                if lifecycle_error { "error" } else { "passed" }
            );
            assert_eq!(end["status"], finished.status.status);
            assert_eq!(end["interrupt_observed"], fault == "interrupt-after-last");
            assert_eq!(
                end["interrupt_observed"],
                finished.status.interrupt_observed
            );
            let shown = presentation(Ok(finished));
            if lifecycle_error {
                assert_eq!(
                    shown.unwrap_err(),
                    if fault == "interrupt-after-last" {
                        "bench native lifecycle: cleanup-final-fail; interrupt observed"
                    } else {
                        "bench native lifecycle: cleanup-final-fail"
                    }
                );
                assert_eq!(end["error"], "cleanup-final-fail");
            } else {
                let (code, message) = shown.unwrap();
                assert_eq!(code, 0);
                assert_eq!(message, "sandbox bench: passed: 3 runs graded; batch complete; stub fixture, not publishable");
            }
        }
        // Regression: the observation suffix follows the entire cleanup error chain (D1).
        let _signals = runtime::Signals::install().unwrap();
        let mut f = Fixture::new();
        let _fault = FaultScope::new(&["interrupt-after-last", "cleanup-final-fail"]);
        let mut finished = f.run_finished().unwrap();
        assert!(finished.status.interrupt_observed);
        assert_eq!(f.end()["status"], finished.status.status);
        finished.result = Err(owned::with_cleanup(
            finished.result.unwrap_err(),
            Err(io::Error::other("x")),
        ));
        assert_eq!(
            presentation(Ok(finished)),
            Err(
                "bench native lifecycle: cleanup-final-fail; cleanup: x; interrupt observed".into()
            )
        );
    }
    // Regression: an unavailable or excessive load silently passed without a recorded override.
    #[test]
    fn regression_bench_load_check_failure_and_override_recorded() {
        assert!(load(Err(io::Error::other("unavailable")), 4.0, false).is_err());
        assert!(load(Ok(4.1), 4.0, false).is_err());
        assert_eq!(load(Ok(4.0), 4.0, false).unwrap().reading, Some(4.0));
        let report = load(Err(io::Error::other("unavailable")), 4.0, true).unwrap();
        assert!(report.allow_high_load);
        assert_eq!(report.error.as_deref(), Some("unavailable"));
        for (value, expected) in [(4.1, Some(4.1)), (f64::NAN, None), (-1.0, None)] {
            let report = load(Ok(value), 4.0, true).unwrap();
            assert!(report.allow_high_load);
            assert_eq!(report.reading, expected);
        }
    }
    struct FaultScope;
    impl FaultScope {
        fn new(faults: &[&'static str]) -> Self {
            FAULTS.with(|f| *f.borrow_mut() = faults.to_vec());
            EXTRACTS.with(|count| count.set(0));
            CLEANUPS.with(|count| count.set(0));
            Self
        }
    }
    impl Drop for FaultScope {
        fn drop(&mut self) {
            FAULTS.with(|f| f.borrow_mut().clear());
        }
    }
    struct Fixture {
        dir: tempfile::TempDir,
        manifest: Manifest,
        entries: Vec<schedule::Entry>,
        files: BTreeMap<String, File>,
        bytes: Vec<u8>,
        args: BenchArgs,
    }
    impl Fixture {
        fn new() -> Self {
            use sha2::{Digest, Sha256};
            let dir = tempfile::tempdir().unwrap();
            for name in ["work", "state"] {
                std::fs::create_dir(dir.path().join(name)).unwrap();
            }
            let mut builder = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_ustar();
            header.set_mode(0o600);
            header.set_size(6);
            header.set_cksum();
            builder
                .append_data(&mut header, "source.txt", &b"source"[..])
                .unwrap();
            let tar = builder.into_inner().unwrap();
            let archive = zstd::encode_all(tar.as_slice(), 1).unwrap();
            let mut value = super::super::tests::fixture();
            value["tasks"][0]["artifact"]["sha256"] =
                format!("sha256:{:x}", Sha256::digest(&archive)).into();
            value["tasks"][0]["artifact"]["tar_stream_sha256"] =
                format!("sha256:{:x}", Sha256::digest(&tar)).into();
            let bytes = serde_json::to_vec(&value).unwrap();
            std::fs::write(dir.path().join("tasks.json"), &bytes).unwrap();
            let manifest = serde_json::from_slice(&bytes).unwrap();
            let entries = schedule::build(
                &bytes,
                &super::super::Selection {
                    backend: vec![schedule::Backend::Native],
                    cache: vec![schedule::Cache::Warm],
                    base_form: vec![schedule::BaseForm::TarZstSingleFrame],
                    repeats: Some(1),
                    ..Default::default()
                },
            )
            .unwrap();
            std::fs::write(dir.path().join("archive"), archive).unwrap();
            let files = BTreeMap::from([(
                "mojo".into(),
                owned::open_artifact(&dir.path().join("archive")).unwrap(),
            )]);
            let script = format!(
                "#!/bin/sh\nexport BENCH_STUB_STATE='{}'\nexec '{}' \"$@\"\n",
                dir.path().join("state").display(),
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../test-harness/sandbox-bench/runtime.sh"
                )
            );
            std::fs::write(dir.path().join("runtime"), script).unwrap();
            std::fs::set_permissions(
                dir.path().join("runtime"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let args = BenchArgs {
                command: None,
                manifest: Some(dir.path().join("tasks.json")),
                validate_only: false,
                dry_run: false,
                require_pins: false,
                out: Some(dir.path().join("out")),
                runtime: Some(dir.path().join("runtime")),
                runtime_kind: Some(RuntimeKind::Stub),
                work_root: dir.path().join("work"),
                allow_high_load: false,
                selection: super::super::Selection::default(),
            };
            Self {
                bytes,
                args,
                dir,
                manifest,
                entries,
                files,
            }
        }
        fn run(&mut self) -> io::Result<record::Status> {
            let finished = self.run_finished()?;
            finished.result.map(|()| finished.status)
        }
        fn run_finished(&mut self) -> io::Result<record::Finished> {
            let work = self.dir.path().join("work");
            let parent = owned::open_directory(&work)?;
            execute_owned(
                &self.manifest,
                &self.entries,
                &self.dir.path().join("runtime"),
                &self.dir.path().join("out"),
                Scratch {
                    started: Instant::now(),
                    fuse: self
                        .entries
                        .iter()
                        .any(|e| e.backend == schedule::Backend::Fuse)
                        .then(|| {
                            BenchMountConfig::new(
                                self.args.runtime_kind.unwrap(),
                                &work,
                                "owned-test",
                                rustix::process::geteuid().as_raw(),
                                rustix::process::getegid().as_raw(),
                            )
                            .unwrap()
                        }),
                    args: &self.args,
                    bytes: &self.bytes,
                    paths: &record::AdmittedPaths {
                        catalog: self.args.manifest().to_owned(),
                        artifacts: BTreeMap::from([(
                            "mojo".into(),
                            self.dir.path().join("archive"),
                        )]),
                    },
                    work: &work,
                    parent: &parent,
                    id: "owned-test",
                },
                &mut self.files,
                &load(Ok(0.0), 4.0, false)?,
            )
        }
        fn rows(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(self.dir.path().join("out/runs.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        fn executed(&self) -> Vec<serde_json::Value> {
            self.rows()
                .into_iter()
                .filter(|r| r["outcome"] != "blocked")
                .collect()
        }
        fn end(&self) -> serde_json::Value {
            serde_json::from_slice(
                &std::fs::read(self.dir.path().join("out/batch-end.json")).unwrap(),
            )
            .unwrap()
        }
        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("state/calls")).unwrap_or_default()
        }
    }
    // Regression: wall time omitted shared artifact admission before the record header (R-CLOCK).
    #[test]
    fn regression_bench_batch_wall_time_includes_admission() {
        let _signals = runtime::InterruptScope::new();
        let _fault = FaultScope::new(&["admission-slow"]);
        let mut f = Fixture::new();
        let mut value: serde_json::Value = serde_json::from_slice(&f.bytes).unwrap();
        value["platforms"][0]["architecture"] = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        }
        .into();
        let artifact = value["tasks"][0]["artifact"]["path"].as_str().unwrap();
        std::fs::write(
            f.dir.path().join(artifact),
            std::fs::read(f.dir.path().join("archive")).unwrap(),
        )
        .unwrap();
        f.bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(f.args.manifest(), &f.bytes).unwrap();
        f.args.allow_high_load = true;
        assert_eq!(execute(&f.args, &f.bytes, &f.entries).unwrap(), 0);
        let header: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.dir.path().join("out/batch.json")).unwrap())
                .unwrap();
        let end = f.end();
        let difference = i128::from(end["wall_ms"].as_u64().unwrap())
            - (i128::from(end["finished_unix_ms"].as_u64().unwrap())
                - i128::from(header["started_unix_ms"].as_u64().unwrap()));
        eprintln!("admission clock difference: {difference} ms");
        assert!(
            difference >= 400,
            "admission clock difference: {difference} ms"
        );
        assert_eq!(
            std::fs::read_dir(f.dir.path().join("work"))
                .unwrap()
                .count(),
            0
        );
    }
    // Regression: pre-runtime create/write failures leaked roots or omitted error terminals (R-1).
    #[test]
    fn regression_bench_pre_runtime_failures_recorded_and_removed() {
        let _signals = runtime::InterruptScope::new();
        for fault in [
            "pre-runtime-create",
            "recovery-write",
            "outcomes-create",
            "scratch-create",
            "verify-before-create",
        ] {
            let mut f = Fixture::new();
            if fault == "verify-before-create" {
                f.manifest.tasks[0].artifact.sha256 = "sha256:wrong".into();
            }
            let _fault = FaultScope::new(&[fault]);
            let error = f.run().unwrap_err().to_string();
            assert!(
                error.contains(if fault == "verify-before-create" {
                    "artifact sha256 mismatch"
                } else {
                    fault
                }),
                "{error}"
            );
            assert!(!f.calls().contains("run -d"));
            assert!(!f.dir.path().join("work/owned-test").exists());
            if fault == "outcomes-create" {
                assert!(!f.dir.path().join("out").exists());
            } else {
                let rows = f.rows();
                assert_eq!(rows.len(), 3);
                assert_eq!(rows[0]["outcome"], "error");
                assert!(rows[1..]
                    .iter()
                    .all(|r| r["outcome"] == "blocked" && r["blocked_by"] == 0));
                assert!(rows[0]["execution_error"].is_string());
                assert_eq!(rows[0]["phases"], serde_json::json!([]));
                assert!(rows[0]["cleanup_error"].is_null());
                if fault == "recovery-write" {
                    assert!(f.dir.path().join("out/0-recovery.json").exists());
                }
            }
        }
    }
    // Regression: cleanup masked the primary extract error, or verification created a tree first (R-2/R-1).
    #[test]
    fn regression_bench_extract_primary_error_survives_cleanup_failure() {
        let _signals = runtime::InterruptScope::new();
        for verify in [false, true] {
            let mut f = Fixture::new();
            if verify {
                f.manifest.tasks[0].artifact.sha256 = "wrong".into();
            } else {
                f.manifest.tasks[0].artifact.tar_stream_sha256 = "wrong".into();
            }
            let _fault = FaultScope::new(&["cleanup-fail"]);
            let primary = if verify {
                "artifact sha256 mismatch"
            } else {
                "tar-stream sha256 mismatch"
            };
            let error = f.run().unwrap_err().to_string();
            assert!(
                error.starts_with(primary) && error.contains("cleanup-fail"),
                "{error}"
            );
            let row = &f.rows()[0];
            assert_eq!(row["outcome"], "error");
            assert_eq!(row["execution_error"], primary);
            assert_eq!(row["cleanup_error"], "cleanup-fail");
            assert_eq!(row["phases"], serde_json::json!([]));
            assert!(!f.calls().contains("run -d"));
            assert_eq!(f.dir.path().join("work/owned-test/0").exists(), !verify);
            let parent = owned::open_directory(&f.dir.path().join("work")).unwrap();
            owned::remove_tree(&parent, "owned-test").unwrap();
        }
    }
    // Regression: an EEXIST scratch collision deleted a directory this run did not create.
    #[test]
    fn regression_bench_scratch_already_exists_preserved() {
        let _signals = runtime::InterruptScope::new();
        let mut f = Fixture::new();
        let existing = f.dir.path().join("work/owned-test");
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("sentinel"), b"previous run").unwrap();
        let error = f.run().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(existing.join("sentinel")).unwrap(),
            b"previous run"
        );
        let row = &f.rows()[0];
        assert_eq!(row["outcome"], "error");
        assert_eq!(row["execution_error"], error.to_string());
        assert!(row["cleanup_error"].is_null());
        assert_eq!(row["phases"], serde_json::json!([]));
        assert!(f.calls().is_empty());
    }
    // Regression: an outcomes write error masked primary and cleanup failures in all three error arms.
    #[test]
    fn regression_bench_record_failure_preserves_primary_and_cleanup() {
        let _signals = runtime::InterruptScope::new();
        for primary in ["scratch-create", "recovery-write", "execution-fail"] {
            for cleanup_fails in [false, true] {
                let mut f = Fixture::new();
                let mut faults = vec![primary, "record-fail"];
                if cleanup_fails {
                    faults.push("cleanup-fail");
                }
                let _fault = FaultScope::new(&faults);
                let error = f.run().unwrap_err();
                let (reason, secondary) = owned::error_parts(&error);
                assert_eq!(reason, primary);
                let secondary = secondary.unwrap();
                assert!(secondary.contains("record-fail"), "{error}");
                assert_eq!(secondary.contains("cleanup-fail"), cleanup_fails, "{error}");
                assert_eq!(f.calls().contains("run -d"), primary == "execution-fail");
                assert!(f.rows().is_empty());
                let parent = owned::open_directory(&f.dir.path().join("work")).unwrap();
                if !cleanup_fails {
                    assert!(!f.dir.path().join("work/owned-test").exists());
                }
                owned::remove_tree(&parent, "owned-test").unwrap();
            }
        }
    }
    // Regression: interrupt-entry record failures leaked the leaf and cleanup failures were lost.
    #[test]
    fn regression_bench_interrupt_record_and_cleanup_outcomes() {
        let _scope = runtime::InterruptScope::new();
        for record_fails in [false, true] {
            for cleanup_fails in [false, true] {
                let signals = runtime::Signals::install().unwrap();
                let mut f = Fixture::new();
                let mut faults = vec!["interrupt-entry"];
                if record_fails {
                    faults.push("record-fail");
                }
                if cleanup_fails {
                    faults.push("cleanup-fail");
                }
                let _fault = FaultScope::new(&faults);
                let finished = f.run_finished().unwrap();
                let result = &finished.result;
                CLEANUPS.with(|count| assert_eq!(count.get(), 1));
                if record_fails {
                    let error = result.as_ref().unwrap_err();
                    assert_eq!(
                        owned::error_parts(error),
                        (
                            "record-fail".into(),
                            cleanup_fails.then(|| "cleanup-fail".into())
                        )
                    );
                    assert!(f.rows().is_empty());
                    assert!(!f.dir.path().join("out/batch-end.json").exists());
                    let suffix = if cleanup_fails {
                        "; cleanup: cleanup-fail"
                    } else {
                        ""
                    };
                    assert_eq!(presentation(Ok(finished)), Ok((1, format!("sandbox bench: interrupted: batch incomplete; lifecycle error: record-fail{suffix}"))));
                } else {
                    if cleanup_fails {
                        assert_eq!(
                            owned::error_parts(result.as_ref().unwrap_err()),
                            ("cleanup-fail".into(), None)
                        );
                    } else {
                        result.as_ref().unwrap();
                    }
                    let rows = f.rows();
                    assert_eq!(rows.len(), 3);
                    assert_eq!(rows[0]["outcome"], "interrupted");
                    assert!(rows[1..]
                        .iter()
                        .all(|r| r["outcome"] == "blocked" && r["reason"] == "interrupted"));
                    let end: serde_json::Value = serde_json::from_slice(
                        &std::fs::read(f.dir.path().join("out/batch-end.json")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(end["status"], "interrupted");
                    assert_eq!(
                        end["error"],
                        serde_json::json!(cleanup_fails.then_some("cleanup-fail"))
                    );
                    let row = &rows[0];
                    assert_eq!(row["execution_error"], "interrupted");
                    assert_eq!(row["phases"], serde_json::json!([]));
                    assert!(row["stop_error"].is_null());
                    assert_eq!(
                        row["cleanup_error"],
                        serde_json::json!(cleanup_fails.then_some("cleanup-fail"))
                    );
                }
                assert!(!f.calls().contains("run -d"));
                assert_eq!(f.dir.path().join("work/owned-test").exists(), cleanup_fails);
                let parent = owned::open_directory(&f.dir.path().join("work")).unwrap();
                owned::remove_tree(&parent, "owned-test").unwrap();
                drop(signals);
            }
        }
    }
    fn leak_exit(fault: &'static str, interrupted: bool) {
        let _scope = runtime::InterruptScope::new();
        let mut f = Fixture::new();
        let mut faults = vec![fault];
        if interrupted {
            faults.push("interrupt-phases-serialize");
        }
        let _fault = FaultScope::new(&faults);
        let finished = f.run_finished();
        assert!(finished.is_ok(), "error exit must finish records");
        let finished = finished.unwrap();
        assert_eq!(
            owned::error_parts(finished.result.as_ref().unwrap_err()),
            (fault.into(), None)
        );
        let rows = f.rows();
        assert_eq!(rows.len(), f.entries.len());
        assert_eq!(rows[0]["outcome"], "error");
        assert_eq!(rows[0]["reason"], fault);
        assert_eq!(rows[0]["execution_error"], fault);
        assert!(rows[0]["cleanup_error"].is_null());
        assert_eq!(rows[0]["phases"], serde_json::json!([]));
        assert!(rows[1..].iter().all(|r| r["outcome"] == "blocked"));
        assert!(!f.dir.path().join("work/owned-test").exists());
        assert_eq!(f.end()["status"], "error");
        assert_eq!(f.end()["interrupt_observed"], interrupted);
        let mut expected = format!("bench native lifecycle: {fault}");
        if interrupted {
            expected.push_str("; interrupt observed");
        }
        assert_eq!(presentation(Ok(finished)), Err(expected));
    }
    // Regression: bind-path conversion skipped scratch cleanup and the terminal row (L1).
    #[test]
    fn regression_bench_mount_utf8_error_finishes_and_removes_scratch() {
        leak_exit("mount-utf8", false);
    }
    // Regression: phase serialization skipped scratch cleanup and the terminal row (L2).
    #[test]
    fn regression_bench_phases_serialize_error_finishes_and_removes_scratch() {
        leak_exit("phases-serialize", false);
        leak_exit("phases-serialize", true);
        let _scope = runtime::InterruptScope::new();
        let mut f = Fixture::new();
        let _fault = FaultScope::new(&["execution-fail", "phases-serialize"]);
        let finished = f.run_finished().unwrap();
        let error = "execution-fail; phase serialization: phases-serialize";
        assert_eq!(
            owned::error_parts(finished.result.as_ref().unwrap_err()),
            (error.into(), None)
        );
        let rows = f.rows();
        assert_eq!(rows.len(), f.entries.len());
        assert_eq!(rows[0]["outcome"], "error");
        assert_eq!(rows[0]["execution_error"], error);
        assert_eq!(rows[0]["reason"], error);
        assert!(rows[0]["cleanup_error"].is_null());
        assert_eq!(rows[0]["phases"], serde_json::json!([]));
        assert!(rows[1..].iter().all(|r| r["outcome"] == "blocked"));
        assert!(!f.dir.path().join("work/owned-test").exists());
        assert_eq!(
            presentation(Ok(finished)),
            Err(format!("bench native lifecycle: {error}"))
        );
        let mut f = Fixture::new();
        let _fault = FaultScope::new(&[
            "execution-fail",
            "phases-serialize",
            "interrupt-phases-serialize",
            "record-fail",
        ]);
        let finished = f.run_finished().unwrap();
        assert_eq!(
            finished.result.as_ref().unwrap_err().to_string(),
            "execution-fail; phase serialization: phases-serialize; cleanup: record-fail"
        );
        assert_eq!(presentation(Ok(finished)), Ok((1, "sandbox bench: interrupted: batch incomplete; lifecycle error: execution-fail; phase serialization: phases-serialize; cleanup: record-fail".into())));
        assert!(!f.dir.path().join("work/owned-test").exists());
    }
    // Regression: execution I/O failure after startup removed the tree but leaked its empty scratch leaf.
    #[test]
    fn regression_bench_execution_error_removes_scratch_leaf() {
        let _signals = runtime::InterruptScope::new();
        let mut f = Fixture::new();
        let _fault = FaultScope::new(&["execution-fail"]);
        assert_eq!(f.run().unwrap_err().to_string(), "execution-fail");
        let row = &f.rows()[0];
        assert_eq!(row["outcome"], "error");
        assert_eq!(row["execution_error"], "execution-fail");
        assert!(row["stop_error"].is_null() && row["cleanup_error"].is_null());
        assert_eq!(row["phases"].as_array().unwrap().len(), 1);
        assert!(f.calls().contains("kill ") && f.calls().contains("rm -f "));
        assert!(!f.dir.path().join("work/owned-test").exists());
    }
    // Regression: successful outer removal lost source recovery's secondary failure (R-2).
    #[test]
    fn regression_bench_source_cleanup_failure_recorded_after_removal() {
        let _signals = runtime::InterruptScope::new();
        let mut f = Fixture::new();
        f.manifest.tasks[0].artifact.tar_stream_sha256 = "wrong".into();
        let _fault = FaultScope::new(&["make-removable-fail"]);
        let error = f.run().unwrap_err().to_string();
        assert!(
            error.starts_with("tar-stream sha256 mismatch")
                && error.contains("make-removable-fail")
        );
        let row = &f.rows()[0];
        assert_eq!(row["outcome"], "error");
        assert_eq!(row["execution_error"], "tar-stream sha256 mismatch");
        assert_eq!(row["cleanup_error"], "make-removable-fail");
        assert_eq!(row["phases"], serde_json::json!([]));
        assert!(!f.calls().contains("run -d"));
        assert!(!f.dir.path().join("work/owned-test").exists());
    }
    // Regression: pre-extract/pre-spawn interrupts started work, or lost their distinct row shapes.
    #[test]
    fn regression_bench_interrupt_entry_spawn_and_between_rows() {
        let _signals = runtime::InterruptScope::new();
        for fault in ["interrupt-entry", "interrupt-spawn", "interrupt-between"] {
            // The scope serializes global writers; clear only while holding it.
            let signals = runtime::Signals::install().unwrap();
            let mut f = Fixture::new();
            let _fault = FaultScope::new(&[fault]);
            let status = f.run().unwrap();
            assert!(status.presentation().1.ends_with(&format!(
                "{} runs not executed",
                if fault == "interrupt-between" { 2 } else { 3 }
            )));
            let rows = f.rows();
            let interrupted = usize::from(fault == "interrupt-between");
            let row = &rows[interrupted];
            assert_eq!(row["outcome"], "interrupted");
            if interrupted == 1 {
                assert_eq!(rows[0]["outcome"], "passed");
            }
            assert!(rows[interrupted + 1..]
                .iter()
                .all(|r| r["outcome"] == "blocked"));
            if fault == "interrupt-spawn" {
                assert_eq!(row["phases"][0]["error"], "interrupted");
                assert_eq!(row["phases"][0]["stdout_log"], "");
                assert_eq!(row["phases"][0]["stderr_log"], "");
                assert!(row["execution_error"].is_null());
                assert!(f.calls().contains("kill ") && f.calls().contains("rm -f "));
                assert!(std::fs::read_dir(f.dir.path().join("out"))
                    .unwrap()
                    .all(|e| !e.unwrap().file_name().to_string_lossy().contains("-run.")));
            } else {
                assert_eq!(row["execution_error"], "interrupted");
                assert_eq!(row["phases"], serde_json::json!([]));
            }
            let runs = f
                .calls()
                .lines()
                .filter(|s| s.starts_with("run -d"))
                .count();
            assert_eq!(runs, usize::from(fault == "interrupt-between"));
            EXTRACTS.with(|count| assert_eq!(count.get(), usize::from(fault != "interrupt-entry")));
            assert_eq!(rows.len(), 3);
            assert!(!f.dir.path().join("work/owned-test").exists());
            assert!(
                !f.dir
                    .path()
                    .join(format!(
                        "out/{}-recovery.json",
                        if fault == "interrupt-between" { 1 } else { 0 }
                    ))
                    .exists()
                    || fault == "interrupt-spawn"
            );
            drop(signals);
        }
    }
}
