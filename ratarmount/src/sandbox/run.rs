//! One-shot container runner. The mount child owns the only overlay writer.

use crate::control_socket_path;
use clap::Args;
use ratarmount_compositing::overlay_changes::{self, ChangeOptions, Normalize};
use ratarmount_compositing::{overlay_fsck, overlay_seal, OverlayMeta, HIDDEN_DB};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(25);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
static SIGNAL: AtomicI32 = AtomicI32::new(0);

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long)]
    base: PathBuf,
    #[arg(long)]
    lower: Vec<PathBuf>,
    #[arg(long)]
    top: PathBuf,
    /// Trust a known sha256:<hex> base digest (from `overlay digest-base` or `snapshot`), or `none`.
    #[arg(long, value_name = "sha256:HEX|none")]
    base_digest: Option<ratarmount_compositing::BaseDigestRequest>,
    /// Use a private RAM overlay; copy it to --top after unmount.
    #[arg(long)]
    tmpfs: bool,
    #[arg(long)]
    image: String,
    #[arg(long, default_value = "/repo")]
    bind: String,
    #[arg(long = "env")]
    env: Vec<String>,
    #[arg(long)]
    cpus: Option<String>,
    #[arg(long)]
    memory: Option<String>,
    #[arg(long, default_value = "none", value_parser = ["none", "bridge", "host"])]
    network: String,
    /// Maximum number of processes in the container (docker/podman `--pids-limit`).
    #[arg(long, default_value_t = 4096, allow_hyphen_values = true)]
    pids_limit: i64,
    /// Add a Linux capability back (all are dropped by default); repeatable.
    #[arg(long, value_name = "CAP", value_parser = parse_cap)]
    cap_add: Vec<String>,
    #[arg(long)]
    journal: bool,
    #[arg(long)]
    readonly: Vec<String>,
    #[arg(long)]
    allow: Vec<String>,
    #[arg(long, value_parser = ratarmount_compositing::parse_overlay_size)]
    quota: Option<u64>,
    #[arg(long)]
    timeout: Option<u64>,
    #[arg(long, value_parser = ["docker", "podman"])]
    runtime: Option<String>,
    #[arg(long)]
    seal: bool,
    #[arg(long)]
    pack: Option<PathBuf>,
    /// Suppress harness progress on stderr. Stdout is always one JSON object.
    #[arg(long)]
    json: bool,
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

fn parse_cap(value: &str) -> Result<String, String> {
    if !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        Ok(value.to_string())
    } else {
        Err(format!(
            "invalid capability name {value:?} (use [A-Za-z0-9_]+)"
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessIdentity {
    pid: u32,
    start: Option<String>,
}

impl ProcessIdentity {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            start: process_start(pid),
        }
    }

    fn alive(&self) -> bool {
        if self.pid == 0 || self.pid > i32::MAX as u32 {
            return false;
        }
        if let Some(start) = &self.start {
            return process_start(self.pid).as_ref() == Some(start);
        }
        // On platforms without /proc, conservatively treat a live PID as busy.
        unsafe { libc::kill(self.pid as i32, 0) == 0 }
    }
}

fn is_runner(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let same_exe =
            fs::read_link(format!("/proc/{pid}/exe")).ok() == std::env::current_exe().ok();
        let argv = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let words: Vec<_> = argv.split(|b| *b == 0).collect();
        same_exe
            && words
                .windows(2)
                .any(|w| w == [b"sandbox".as_slice(), b"run".as_slice()])
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true
    }
}

fn process_start(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm can contain spaces and ')'; starttime is field 22.
    let fields = stat.rsplit_once(") ")?.1;
    if fields.starts_with("Z ") {
        return None;
    }
    Some(fields.split_whitespace().nth(19)?.into())
}

#[derive(Debug, Serialize, Deserialize)]
struct PidRecord {
    #[serde(flatten)]
    owner: ProcessIdentity,
    mountpoint: PathBuf,
    container: String,
    runtime: PathBuf,
    mount_child: Option<ProcessIdentity>,
    #[serde(default)]
    runtime_child: Option<ProcessIdentity>,
    ram_top: Option<PathBuf>,
}

/// Kept separately from the replaceable PID record to serialize stale recovery
/// and publication, including when two callers open the same old PID inode.
struct RunLock(File);
impl RunLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::other("another sandbox run owns this top"));
        }
        Ok(Self(file))
    }
}
impl Drop for RunLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

extern "C" fn on_signal(signal: libc::c_int) {
    SIGNAL.store(signal, Ordering::Relaxed);
}
struct Signals(Vec<(libc::c_int, libc::sigaction)>);
impl Signals {
    fn install() -> io::Result<Self> {
        SIGNAL.store(0, Ordering::Relaxed);
        let mut guard = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous = unsafe { std::mem::zeroed() };
            action.sa_sigaction = on_signal as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(io::Error::last_os_error());
            }
            guard.0.push((signal, previous));
        }
        Ok(guard)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, previous) in &self.0 {
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}

fn sidecar(top: &Path, suffix: &str) -> PathBuf {
    let mut path = top.as_os_str().to_os_string();
    path.push(suffix);
    path.into()
}
fn pid_path(top: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(top.file_name().expect("validated top"));
    name.push(".ratarmount-run.pid");
    top.with_file_name(name)
}
fn absolute_top(top: &Path) -> io::Result<PathBuf> {
    let path = std::path::absolute(top)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("--top must name a directory, not /"))?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("--top needs a parent"))?;
    fs::create_dir_all(parent)?;
    let path = parent.canonicalize()?.join(name);
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(io::Error::other("--top must be a directory, not a symlink"));
        }
    }
    Ok(path)
}

fn executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}
fn find_runtime(args: &RunArgs) -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("RATARMOUNT_SANDBOX_RUNTIME") {
        let path = PathBuf::from(path);
        if !executable(&path) {
            return Err(io::Error::other(
                "RATARMOUNT_SANDBOX_RUNTIME must name an executable",
            ));
        }
        return path.canonicalize();
    }
    for name in args
        .runtime
        .as_deref()
        .map_or_else(|| vec!["docker", "podman"], |r| vec![r])
    {
        for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let path = dir.join(name);
            if executable(&path) {
                return path.canonicalize();
            }
        }
    }
    Err(io::Error::other(
        "no container runtime found; install docker or podman, or set RATARMOUNT_SANDBOX_RUNTIME",
    ))
}

fn runtime_argv(args: &RunArgs, mount: &Path, name: &str, uid: u32, gid: u32) -> Vec<OsString> {
    let mut volume = mount.as_os_str().to_os_string();
    volume.push(":");
    volume.push(&args.bind);
    let mut argv: Vec<OsString> = ["run", "--rm", "--name", name, "-v"]
        .into_iter()
        .map(Into::into)
        .collect();
    argv.push(volume);
    argv.extend(["-w", &args.bind, "--network", &args.network].map(Into::into));
    for (flag, value) in [("--cpus", &args.cpus), ("--memory", &args.memory)] {
        if let Some(value) = value {
            argv.extend([flag.into(), value.into()]);
        }
    }
    for env in &args.env {
        argv.extend(["-e".into(), env.into()]);
    }
    argv.extend([
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        args.pids_limit.to_string().into(),
    ]);
    for cap in &args.cap_add {
        argv.extend(["--cap-add".into(), cap.into()]);
    }
    argv.extend([
        "--user".into(),
        format!("{uid}:{gid}").into(),
        args.image.clone().into(),
    ]);
    argv.extend(args.command.iter().cloned());
    argv
}

fn supervised(command: &mut Command) -> &mut Command {
    command.process_group(0);
    #[cfg(target_os = "linux")]
    {
        let parent = std::process::id() as libc::pid_t;
        // Only async-signal-safe syscalls between fork and exec. This closes
        // the SIGKILL window before spawn returns and the child PID is saved.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    libc::_exit(125);
                }
                Ok(())
            });
        }
    }
    command
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            child.kill()?;
            child.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child cleanup timed out",
            ));
        }
        std::thread::sleep(POLL);
    }
}
fn runtime_control(record: &PidRecord, verb: &str) -> io::Result<()> {
    let mut diagnostic = tempfile::tempfile()?;
    let mut command = Command::new(&record.runtime);
    command.arg(verb);
    if verb == "rm" {
        command.arg("-f");
    }
    let mut child = command
        .arg(&record.container)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(diagnostic.try_clone()?)
        .spawn()?;
    let status = wait_bounded(&mut child, CLEANUP_TIMEOUT)?;
    if status.success() {
        return Ok(());
    }
    diagnostic.rewind()?;
    let mut message = String::new();
    diagnostic.take(64 * 1024).read_to_string(&mut message)?;
    let lower = message.to_ascii_lowercase();
    // --rm normally wins this race. Other errors must retain recovery state;
    // killing the local CLI alone does not stop a container in the daemon.
    if lower.contains("no such container")
        || lower.contains("no container with name")
        || (verb == "kill" && lower.contains("is not running"))
    {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "runtime {verb} failed ({status}): {message}"
    )))
}

fn mounted(path: &Path) -> io::Result<bool> {
    Ok(super::process::mountpoints()?.iter().any(|p| p == path))
}
fn unmount(path: &Path) -> io::Result<()> {
    if !mounted(path)? {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    let attempts = [
        ("fusermount3", vec!["-u"]),
        ("fusermount3", vec!["-u", "-z"]),
    ];
    #[cfg(not(target_os = "linux"))]
    let attempts = [("umount", vec![]), ("umount", vec!["-f"])];
    for (program, flags) in attempts {
        if let Ok(mut child) = Command::new(program)
            .args(flags)
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let _ = wait_bounded(&mut child, CLEANUP_TIMEOUT);
        }
        if !mounted(path)? {
            return Ok(());
        }
    }
    Err(io::Error::other(format!(
        "cannot unmount {} (recovery record retained)",
        path.display()
    )))
}
fn wait_database(top: &Path) -> io::Result<()> {
    if !top.join(HIDDEN_DB).exists() {
        return Ok(());
    }
    let start = Instant::now();
    loop {
        match OverlayMeta::read(top) {
            Ok(_) => return Ok(()),
            Err(error) if error.is_locked() && start.elapsed() < CLEANUP_TIMEOUT => {
                std::thread::sleep(POLL)
            }
            Err(error) => return Err(io::Error::other(error)),
        }
    }
}

/// Longest control socket path the platforms accept (`sun_path`, macOS 104).
const MAX_SOCKET_PATH: usize = 100;

/// The private `ratarmount-run-XXXXXX` parent: a 0700 directory owned by the
/// caller that holds the mountpoint (`mnt`) and the mount child's control
/// socket, outside the container's bind. A user who is not the caller cannot
/// traverse it, so `allow_other` does not expose the mounted tree. Under `/tmp`
/// when the default temporary directory would make the socket path too long
/// for `sun_path`.
fn create_run_dir() -> io::Result<PathBuf> {
    create_run_dir_in(&std::env::temp_dir())
}

fn create_run_dir_in(default: &Path) -> io::Result<PathBuf> {
    // The directory is canonicalized after creation (`run` resolves it), so the
    // socket length must be judged on the resolved path: a short `TMPDIR`
    // symlink to a long directory would otherwise overflow `sun_path`.
    let resolved = default.canonicalize();
    let default = resolved.as_deref().unwrap_or(default);
    let probe = control_socket_path(Path::new(""), u32::MAX);
    let mut builder = tempfile::Builder::new();
    builder.prefix(RUN_DIR_PREFIX);
    let long = default.as_os_str().len()
        + format!("/{RUN_DIR_PREFIX}XXXXXX").len()
        + 1
        + probe.as_os_str().len()
        > MAX_SOCKET_PATH;
    let dir = if long {
        // `/tmp` is a symlink to `/private/tmp` on macOS; the directory is
        // judged (and later canonicalized) at its resolved, longer path.
        let tmp = Path::new("/tmp");
        builder.tempdir_in(tmp.canonicalize().as_deref().unwrap_or(tmp))?
    } else {
        builder.tempdir_in(default)?
    };
    // Created with the umask's mode: restrict it before anything is placed
    // inside (the mode is asserted, not assumed).
    fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    Ok(dir.keep())
}

/// Name prefix of the private parent (also the container name's prefix).
const RUN_DIR_PREFIX: &str = "ratarmount-run-";

/// The private parent of a recorded mountpoint, when the mountpoint is
/// `<parent>/mnt` and the parent is one this module made: named
/// `ratarmount-run-*`, not `/tmp`, owned by the caller, mode 0700. Records
/// written before the private parent existed (mountpoint directly in `/tmp`)
/// have none.
fn private_parent(mountpoint: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    if mountpoint.file_name()? != "mnt" {
        return None;
    }
    let parent = mountpoint.parent()?;
    if parent == Path::new("/tmp")
        || !parent
            .file_name()?
            .to_string_lossy()
            .starts_with(RUN_DIR_PREFIX)
    {
        return None;
    }
    let meta = fs::symlink_metadata(parent).ok()?;
    let (uid, _) = crate::caller_ids();
    (meta.is_dir() && meta.uid() == uid && meta.mode() & 0o7777 == 0o700)
        .then(|| parent.to_path_buf())
}

struct Cleanup {
    control_dir: Option<PathBuf>,
    record: PidRecord,
    pid_file: PathBuf,
    top: PathBuf,
    mount_child: Option<Child>,
    runtime_child: Option<Child>,
    stopped: bool,
    runtime_stopped: bool,
}
impl Cleanup {
    fn save(&self) -> io::Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(self.pid_file.parent().unwrap())?;
        serde_json::to_writer(&mut file, &self.record)?;
        file.as_file().sync_all()?;
        file.persist(&self.pid_file).map_err(io::Error::other)?;
        Ok(())
    }

    fn stop_runtime(&mut self) -> io::Result<()> {
        if self.runtime_stopped {
            return Ok(());
        }
        let kill_result = runtime_control(&self.record, "kill");
        let rm_result = runtime_control(&self.record, "rm");
        let had_client = self.runtime_child.is_some() || self.record.runtime_child.is_some();
        if let Some(mut child) = self.runtime_child.take() {
            let _ = wait_bounded(&mut child, CLEANUP_TIMEOUT);
        } else if let Some(child) = &self.record.runtime_child {
            if child.start.is_some() && child.alive() {
                unsafe {
                    libc::kill(child.pid as i32, libc::SIGKILL);
                }
            }
        }
        if had_client {
            // A timeout can fire before `run` has created the container. Reap
            // the client before a second removal so it cannot create it later.
            let _ = runtime_control(&self.record, "kill");
            runtime_control(&self.record, "rm")?;
        } else {
            kill_result.and(rm_result)?;
        }
        self.runtime_stopped = true;
        Ok(())
    }

    fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        // Attempt all cleanup steps even if the runtime is broken.
        let runtime_result = self.stop_runtime();
        let unmount_result = unmount(&self.record.mountpoint);
        if let Some(mut child) = self.mount_child.take() {
            let _ = wait_bounded(&mut child, CLEANUP_TIMEOUT);
        } else if let Some(child) = &self.record.mount_child {
            // A stale foreground child may still be initializing. Never signal a reused PID.
            if child.start.is_some() && child.alive() {
                unsafe {
                    libc::kill(child.pid as i32, libc::SIGTERM);
                }
                let start = Instant::now();
                while child.alive() && start.elapsed() < CLEANUP_TIMEOUT {
                    std::thread::sleep(POLL);
                }
                if child.alive() {
                    unsafe {
                        libc::kill(child.pid as i32, libc::SIGKILL);
                    }
                }
            }
        }
        // Catch a mount that completed while the stale child was being stopped.
        unmount_result?;
        unmount(&self.record.mountpoint)?;
        runtime_result?;
        let source = self.record.ram_top.as_deref().unwrap_or(&self.top);
        wait_database(source)?;
        if let Some(ram) = &self.record.ram_top {
            if ram.exists() {
                copy_tree(ram, &self.top)?;
                fs::remove_dir_all(ram)?;
            }
        }
        let _ = fs::remove_dir(&self.record.mountpoint);
        // The private parent also holds the control socket: removing it whole
        // leaves nothing behind however the mount child died. A recovered
        // record has no `control_dir`; derive it under the same ownership rule.
        let parent = self
            .control_dir
            .take()
            .or_else(|| private_parent(&self.record.mountpoint));
        if let Some(dir) = parent {
            let _ = fs::remove_dir_all(dir);
        }
        self.stopped = true;
        Ok(())
    }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        match self.stop() {
            Ok(()) => {
                let _ = fs::remove_file(&self.pid_file);
            }
            Err(error) => eprintln!(
                "sandbox run cleanup: {error}; retained {}",
                self.pid_file.display()
            ),
        }
    }
}

fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        let meta = fs::symlink_metadata(entry.path())?;
        // This destination is empty on first use. A partial recovery copy may
        // exist; never follow one of its symlinks while resuming the copy.
        if let Ok(existing) = fs::symlink_metadata(&target) {
            if !existing.is_dir() || !meta.is_dir() {
                fs::remove_file(&target)?;
            }
        }
        if meta.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, target)?;
        } else if meta.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if meta.is_file() {
            fs::copy(entry.path(), &target)?;
            File::open(&target)?
                .set_times(std::fs::FileTimes::new().set_modified(meta.modified()?))?;
        } else {
            return Err(io::Error::other(
                "RAM overlay contains an unsupported special file",
            ));
        }
    }
    fs::set_permissions(destination, fs::metadata(source)?.permissions())?;
    Ok(())
}

fn recover(pid_file: &Path, top: &Path) -> io::Result<()> {
    let bytes = match fs::read(pid_file) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let record: PidRecord = serde_json::from_slice(&bytes)?;
    if record.owner.alive() && is_runner(record.owner.pid) {
        return Err(io::Error::other("recorded sandbox run is still alive"));
    }
    let mut cleanup = Cleanup {
        control_dir: None,
        record,
        pid_file: pid_file.into(),
        top: top.into(),
        mount_child: None,
        runtime_child: None,
        stopped: false,
        runtime_stopped: false,
    };
    cleanup.stop()
}

fn mount_argv(args: &RunArgs, top: &Path, mount: &Path, journal: &Path) -> Vec<OsString> {
    let mut argv: Vec<OsString> = [
        "-f",
        "--sandbox",
        "--control-interface",
        "--control-socket-only",
        "-w",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    argv.push(top.into());
    for lower in &args.lower {
        argv.extend(["--lower".into(), lower.into()]);
    }
    for rule in &args.readonly {
        argv.extend(["--overlay-readonly".into(), rule.into()]);
    }
    for rule in &args.allow {
        argv.extend(["--overlay-allow".into(), rule.into()]);
    }
    if let Some(quota) = args.quota {
        argv.extend(["--overlay-quota".into(), quota.to_string().into()]);
    }
    if args.journal {
        argv.extend(["--journal".into(), journal.into()]);
    }
    // Before `--`: after it clap would read the flag as a positional input.
    match &args.base_digest {
        Some(ratarmount_compositing::BaseDigestRequest::Supplied(digest)) => {
            argv.extend(["--base-digest".into(), digest.into()]);
        }
        Some(ratarmount_compositing::BaseDigestRequest::None) => {
            argv.extend(["--base-digest".into(), "none".into()]);
        }
        _ => {}
    }
    argv.extend(["--".into(), args.base.as_os_str().into(), mount.into()]);
    argv
}

/// The mount keeps its overlay, journal and report files beside `--top`; a
/// `--top` inside a directory base would change that base's identity.
fn refuse_top_inside_base(args: &RunArgs) -> io::Result<()> {
    if !args.base.is_dir() {
        return Ok(());
    }
    let (_, inside) =
        ratarmount_compositing::resolve_base_excludes(&args.base, std::slice::from_ref(&args.top))
            .map_err(io::Error::other)?;
    if inside.paths().is_empty() {
        Ok(())
    } else {
        Err(io::Error::other("--top must be outside --base"))
    }
}

fn mount_ready(cleanup: &mut Cleanup, stderr: &mut File, base: &Path) -> io::Result<()> {
    let start = Instant::now();
    loop {
        if mounted(&cleanup.record.mountpoint)? {
            return Ok(());
        }
        let exited = cleanup.mount_child.as_mut().unwrap().try_wait()?.is_some();
        if exited
            || start.elapsed() >= Duration::from_secs(60)
            || SIGNAL.load(Ordering::Relaxed) != 0
        {
            stderr.rewind()?;
            let mut diagnostic = String::new();
            stderr.take(64 * 1024).read_to_string(&mut diagnostic)?;
            // Defence in depth: the mount child already redacts, but a library
            // error may still echo the raw `--base` URL it was given.
            let raw = base.to_string_lossy();
            let shown = ratarmount_core::redact_base_url(&raw);
            if shown != raw {
                diagnostic = diagnostic.replace(raw.as_ref(), &shown);
            }
            // A library may also echo a rewritten form (`webdav://` as `http://`).
            let diagnostic = ratarmount_core::redact_urls_in_text(&diagnostic);
            return Err(io::Error::other(format!(
                "mount did not become ready: {diagnostic}"
            )));
        }
        std::thread::sleep(POLL);
    }
}

/// Ask the mount's control socket for `status` (5 s timeouts).
fn control_status(socket: &Path) -> io::Result<String> {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
    let timeout = Some(Duration::from_secs(5));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    stream.write_all(b"status\n")?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    Ok(reply)
}

fn counters(socket: &Path) -> io::Result<u64> {
    parse_erofs_denied(&control_status(socket)?)
}

fn parse_erofs_denied(status: &str) -> io::Result<u64> {
    // The mount only installs a quota/rule policy when one was requested.
    status
        .lines()
        .find_map(|line| line.strip_prefix("erofs_denied "))
        .map(|v| v.trim().parse().map_err(io::Error::other))
        .transpose()
        .map(|count| count.unwrap_or(0))
}

pub fn run(args: &RunArgs) -> io::Result<()> {
    let _signals = Signals::install()?;
    let result = pipeline(args);
    let interrupted = SIGNAL.load(Ordering::Relaxed) != 0;
    report_result(result, interrupted, &mut io::stdout().lock())
}

/// Write the JSON report and return the pipeline's result to `main`. The error
/// also goes to `main`, which prints it to stderr: it must not carry a signed
/// URL a library put in its text (finish() reopens the base).
fn report_result(
    result: io::Result<Value>,
    interrupted: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    let value = match &result {
        Ok(report) => report.clone(),
        Err(error) => {
            json!({"error":ratarmount_core::redact_urls_in_text(&error.to_string()), "interrupted":interrupted})
        }
    };
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    result.map(|_| ()).map_err(redacted_error)
}

fn redacted_error(error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        ratarmount_core::redact_urls_in_text(&error.to_string()),
    )
}

fn pipeline(args: &RunArgs) -> io::Result<Value> {
    let start = Instant::now();
    if !args.bind.starts_with('/') || args.bind.contains(':') || args.image.starts_with('-') {
        return Err(io::Error::other("--bind must be an absolute container path without ':'; --image must not start with '-'"));
    }
    if args
        .env
        .iter()
        .any(|e| !e.split_once('=').is_some_and(|(k, _)| !k.is_empty()))
    {
        return Err(io::Error::other("--env requires K=V"));
    }
    refuse_top_inside_base(args)?;
    let top = absolute_top(&args.top)?;
    let pid_file = pid_path(&top);
    let _lock = RunLock::acquire(&sidecar(&pid_file, ".lock"))?;
    recover(&pid_file, &top)?;
    let runtime = find_runtime(args)?;
    ratarmount_fuse::validate_allow_other("allow_other")?;
    wait_database(&top)?;
    let ram = if args.tmpfs {
        if top.exists() && fs::read_dir(&top)?.next().is_some() {
            return Err(io::Error::other(
                "--tmpfs requires an absent or empty --top",
            ));
        }
        Some(crate::create_tmpfs_overlay()?)
    } else {
        None
    };
    let control_dir = create_run_dir()?.canonicalize()?;
    let container = control_dir
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let mountpoint = control_dir.join("mnt");
    fs::create_dir(&mountpoint)?;
    fs::set_permissions(
        &mountpoint,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let record = PidRecord {
        owner: ProcessIdentity::new(std::process::id()),
        mountpoint,
        container,
        runtime,
        mount_child: None,
        runtime_child: None,
        ram_top: ram.map(tempfile::TempDir::keep),
    };
    let mut cleanup = Cleanup {
        control_dir: Some(control_dir.clone()),
        record,
        pid_file,
        top: top.clone(),
        mount_child: None,
        runtime_child: None,
        stopped: false,
        runtime_stopped: false,
    };
    cleanup.save()?;
    let journal = sidecar(&top, ".journal.jsonl");
    let overlay = cleanup.record.ram_top.as_deref().unwrap_or(&top);
    let mut mount_stderr = tempfile::tempfile()?;
    if !args.json {
        eprintln!(
            "sandbox run: mounting {}",
            cleanup.record.mountpoint.display()
        );
    }
    let child = supervised(&mut Command::new(std::env::current_exe()?))
        .args(mount_argv(
            args,
            overlay,
            &cleanup.record.mountpoint,
            &journal,
        ))
        .env("TMPDIR", &control_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(mount_stderr.try_clone()?))
        .stderr(Stdio::from(mount_stderr.try_clone()?))
        .spawn()?;
    let control_socket = control_socket_path(&control_dir, child.id());
    cleanup.record.mount_child = Some(ProcessIdentity::new(child.id()));
    cleanup.mount_child = Some(child);
    cleanup.save()?;
    mount_ready(&mut cleanup, &mut mount_stderr, &args.base)?;
    if !args.json {
        eprintln!("sandbox run: starting {}", args.image);
    }
    let (uid, gid) = crate::caller_ids();
    cleanup.runtime_child = Some(
        supervised(&mut Command::new(&cleanup.record.runtime))
            .args(runtime_argv(
                args,
                &cleanup.record.mountpoint,
                &cleanup.record.container,
                uid,
                gid,
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::from(io::stderr()))
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    cleanup.record.runtime_child = Some(ProcessIdentity::new(
        cleanup.runtime_child.as_ref().unwrap().id(),
    ));
    cleanup.save()?;
    let command_start = Instant::now();
    let mut timed_out = false;
    let exit_code = loop {
        let signal = SIGNAL.load(Ordering::Relaxed);
        if signal != 0 {
            break 128 + signal;
        }
        if let Some(status) = cleanup.runtime_child.as_mut().unwrap().try_wait()? {
            use std::os::unix::process::ExitStatusExt;
            break status.code().unwrap_or(128 + status.signal().unwrap_or(0));
        }
        if args
            .timeout
            .is_some_and(|s| command_start.elapsed() >= Duration::from_secs(s))
        {
            timed_out = true;
            break 124;
        }
        std::thread::sleep(POLL);
    };
    // Stop all writers before reading counters, then drop the mount's DB lock.
    cleanup.stop_runtime()?;
    let erofs_denied = counters(&control_socket)?;
    cleanup.stop()?;
    let bytes_written = ratarmount_compositing::OverlayQuota::new(&top, None, None)?
        .usage()
        .bytes;
    if !args.json {
        eprintln!("sandbox run: checking and hashing overlay");
    }
    finish(
        args,
        &top,
        &journal,
        Execution {
            exit_code,
            timed_out,
            erofs_denied,
            bytes_written,
            start,
        },
    )
}

struct Execution {
    exit_code: i32,
    timed_out: bool,
    erofs_denied: u64,
    bytes_written: u64,
    start: Instant,
}

fn finish(args: &RunArgs, top: &Path, journal: &Path, execution: Execution) -> io::Result<Value> {
    let Execution {
        exit_code,
        timed_out,
        erofs_denied,
        bytes_written,
        start,
    } = execution;
    let fsck = overlay_fsck::fsck(top, true)?;
    if !fsck.is_clean() {
        return Err(io::Error::other(format!("fsck: {}", fsck.result())));
    }
    // Factory and lazy source progress must never contaminate the JSON report.
    let _progress = crate::diff::ProgressToStderr::new()?;
    let mut options = ratarmount_core::OpenOptions {
        write_index: false,
        index_in_memory: true,
        ..Default::default()
    };
    let base = ratarmount_session::factory::build_mount_source_ex(
        std::slice::from_ref(&args.base),
        &mut options,
        false,
        ratarmount_session::factory::CompositingOptions::default(),
    )
    .map_err(io::Error::other)?
    .source;
    let lower = crate::MountLowerStack::compose(base, &args.lower)?;
    if args.seal || args.pack.is_some() {
        overlay_seal::seal(top, lower.clone())?;
    }
    let bundle = args.pack.as_ref().map(std::path::absolute).transpose()?;
    if let Some(bundle) = &bundle {
        crate::overlay_pack::pack(
            top,
            bundle,
            lower.clone(),
            &crate::overlay_pack::PackOptions {
                include_journal: args.journal.then(|| journal.to_path_buf()),
                ..Default::default()
            },
        )?;
    }
    let options = ChangeOptions {
        normalize: Normalize::Strict,
        ..Default::default()
    };
    let changes = overlay_changes::change_set(top, lower, &options)?;
    let hash = overlay_changes::canonical_hash(&changes, &options)?;
    let manifest = sidecar(top, ".manifest.jsonl");
    overlay_changes::write_manifest(&changes, &mut File::create(&manifest)?)?;
    let meta = OverlayMeta::read(top)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("overlay metadata missing"))?;
    let summary = if args.journal {
        let summary =
            crate::journal_cmd::summarize(BufReader::new(File::open(journal)?), None, None)?;
        let path = sidecar(top, ".journal.summary.json");
        serde_json::to_writer(File::create(&path)?, &summary)?;
        Some(
            json!({"path":path, "files_read":summary.files_read.len(), "files_read_then_written":summary.files_read_then_written.len(), "files_written_blind":summary.files_written_blind.len()}),
        )
    } else {
        None
    };
    Ok(json!({
        "exit_code":exit_code, "timed_out":timed_out, "interrupted":SIGNAL.load(Ordering::Relaxed) != 0,
        "wall_time_s":start.elapsed().as_secs_f64(),
        "patch_hash":{"patch":hash, "base":meta.known_base_digest(), "stack":meta.stack_digest(), "files":changes.len(), "normalize":"strict", "algo":"sha256", "excludes":[], "sealed":meta.layer_sealed(), "base_pending":meta.base_digest_kind() == Some("pending"), "base_digest_state":meta.base_digest_state()},
        "manifest_path":manifest, "journal_summary":summary, "overlay":top, "bundle":bundle,
        "erofs_denied":erofs_denied, "bytes_written":bytes_written, "fsck_result":fsck.result()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::sync::Arc;

    /// Regression: an error from `finish()` (a library-rewritten signed URL in
    /// its text) went to `main` and stderr unredacted; only the JSON was clean.
    #[test]
    fn regression_run_error_returned_to_main_is_redacted() {
        let raw = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "http: HTTP 403 for http://u:s3cr3t@127.0.0.1:1/f.tar?token=deadbeef&X-Amz-Signature=abc",
        );
        let clean = redacted_error(raw);
        assert_eq!(clean.kind(), io::ErrorKind::PermissionDenied);
        let text = clean.to_string();
        for secret in ["s3cr3t", "deadbeef", "X-Amz-Signature=abc"] {
            assert!(!text.contains(secret), "{text}");
        }
        assert!(text.contains("403"), "{text}");
    }

    /// Regression: the error `run` returns to `main` (printed on stderr) must
    /// be redacted at the return boundary itself, not only in the JSON report.
    #[test]
    fn regression_run_return_boundary_redacts_error() {
        let raw = io::Error::other(
            "http: HTTP 403 for http://u:s3cr3t@127.0.0.1:1/f.tar?token=deadbeef&X-Amz-Signature=abc",
        );
        let mut report = Vec::new();
        let error = report_result(Err(raw), false, &mut report).unwrap_err();
        let (returned, printed) = (error.to_string(), String::from_utf8(report).unwrap());
        for secret in ["s3cr3t", "deadbeef", "X-Amz-Signature=abc"] {
            assert!(!returned.contains(secret), "returned: {returned}");
            assert!(!printed.contains(secret), "report: {printed}");
        }
        assert!(returned.contains("403"), "{returned}");
        let ok = report_result(Ok(json!({"a":1})), false, &mut Vec::new());
        assert!(ok.is_ok());
    }

    fn args(extra: &[&str]) -> RunArgs {
        let mut argv = vec![
            "ratarmount sandbox",
            "run",
            "--base",
            "/base",
            "--top",
            "/top",
            "--image",
            "busybox",
        ];
        argv.extend(extra);
        argv.extend(["--", "sh", "-c", "echo hello"]);
        let parsed = super::super::SandboxArgs::try_parse_from(argv).unwrap();
        match parsed.command {
            super::super::Command::Run(args) => *args,
            _ => unreachable!(),
        }
    }

    /// Regression: `sandbox run` had no `--base-digest`, so cpanmine could not
    /// pass its snapshot digest; the flag must precede `--` in the mount argv.
    #[test]
    fn regression_run_mount_argv_passes_base_digest() {
        let digest = format!("sha256:{}", "b".repeat(64));
        for (extra, want) in [
            (vec![], None),
            (
                vec!["--base-digest", digest.as_str()],
                Some(digest.as_str()),
            ),
            (vec!["--base-digest", "none"], Some("none")),
        ] {
            let args = args(&extra);
            let argv = mount_argv(&args, Path::new("/top"), Path::new("/mnt"), Path::new("/j"));
            let separator = argv.iter().position(|a| a == "--").unwrap();
            assert_eq!(&argv[separator + 1..], ["/base", "/mnt"]);
            match want {
                None => assert!(!argv.iter().any(|a| a == "--base-digest")),
                Some(want) => {
                    let at = argv.iter().position(|a| a == "--base-digest").unwrap();
                    assert!(at < separator);
                    assert_eq!(argv[at + 1], want);
                }
            }
        }
    }

    /// Regression: a `--top` inside a directory `--base` would be hashed as base content.
    #[test]
    fn regression_run_refuses_top_inside_directory_base() {
        let dir = tempfile::tempdir().unwrap();
        let mut run = args(&[]);
        run.base = dir.path().to_path_buf();
        run.top = dir.path().join("top");
        let error = refuse_top_inside_base(&run).unwrap_err().to_string();
        assert!(error.contains("--top must be outside --base"), "{error}");
        let outside = tempfile::tempdir().unwrap();
        run.top = outside.path().join("top");
        refuse_top_inside_base(&run).unwrap();
        // Not a directory base: nothing to protect.
        run.base = dir.path().join("a.tar");
        run.top = dir.path().join("top");
        refuse_top_inside_base(&run).unwrap();
    }

    /// Regression: docker/podman options must not absorb command flags or interpolate env values.
    #[test]
    fn regression_run_runtime_argv_preserves_arguments() {
        for runtime in ["docker", "podman"] {
            let args = args(&[
                "--runtime",
                runtime,
                "--env",
                "TOKEN=a b;$x",
                "--cpus",
                "2",
                "--memory",
                "1G",
                "--network",
                "bridge",
            ]);
            let argv = runtime_argv(
                &args,
                Path::new("/mount path"),
                "ratarmount-run-test",
                123,
                456,
            );
            assert_eq!(
                argv,
                [
                    "run",
                    "--rm",
                    "--name",
                    "ratarmount-run-test",
                    "-v",
                    "/mount path:/repo",
                    "-w",
                    "/repo",
                    "--network",
                    "bridge",
                    "--cpus",
                    "2",
                    "--memory",
                    "1G",
                    "-e",
                    "TOKEN=a b;$x",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "4096",
                    "--user",
                    "123:456",
                    "busybox",
                    "sh",
                    "-c",
                    "echo hello"
                ]
                .map(OsString::from)
            );
        }
    }

    /// Regression: the container ran with docker's default capabilities and no
    /// process cap; `--pids-limit` and `--cap-add` adjust the new defaults.
    #[test]
    fn regression_run_pids_limit_and_cap_add_override() {
        let args = args(&[
            "--pids-limit",
            "64",
            "--cap-add",
            "NET_BIND_SERVICE",
            "--cap-add",
            "CHOWN",
        ]);
        let argv = runtime_argv(&args, Path::new("/m"), "n", 1, 2);
        let text: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let at = text.iter().position(|a| a == "--cap-drop").unwrap();
        assert_eq!(
            text[at..at + 10],
            [
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--cap-add",
                "NET_BIND_SERVICE",
                "--cap-add",
                "CHOWN"
            ]
        );
        assert_eq!(text[at + 10], "--user");
        let unlimited = super::super::SandboxArgs::try_parse_from([
            "s",
            "run",
            "--base",
            "/b",
            "--top",
            "/t",
            "--image",
            "i",
            "--pids-limit",
            "-1",
            "--",
            "true",
        ])
        .is_ok();
        assert!(unlimited, "-1 means unlimited");
        for bad in ["", "A B", "CAP;x", "--user"] {
            assert!(parse_cap(bad).is_err(), "{bad:?}");
        }
    }

    /// Regression: run dispatch must not require a daemon socket or steal command options.
    #[test]
    fn regression_run_cli_and_mount_flags() {
        let args = args(&[
            "--lower",
            "/lower",
            "--readonly",
            "t/**",
            "--allow",
            "t/agent/**",
            "--quota",
            "1M",
            "--journal",
            "--tmpfs",
        ]);
        let argv = mount_argv(
            &args,
            Path::new("/ram"),
            Path::new("/mnt"),
            Path::new("/top.journal.jsonl"),
        );
        assert_eq!(
            argv,
            [
                "-f",
                "--sandbox",
                "--control-interface",
                "--control-socket-only",
                "-w",
                "/ram",
                "--lower",
                "/lower",
                "--overlay-readonly",
                "t/**",
                "--overlay-allow",
                "t/agent/**",
                "--overlay-quota",
                "1048576",
                "--journal",
                "/top.journal.jsonl",
                "--",
                "/base",
                "/mnt"
            ]
            .map(OsString::from)
        );
        let parsed = super::super::SandboxArgs::try_parse_from([
            "sandbox", "run", "--base", "base", "--top", "top", "--image", "busybox", "--", "echo",
        ])
        .unwrap();
        assert_eq!(super::super::error_exit_code(&parsed), 2);
    }

    /// Regression: stale/reused PIDs must not identify an unrelated live process as this run.
    #[test]
    fn regression_run_pid_parse_staleness_and_lock() {
        let record = PidRecord {
            owner: ProcessIdentity::new(std::process::id()),
            mountpoint: "/tmp/mount".into(),
            container: "ratarmount-run-test".into(),
            runtime: "/bin/true".into(),
            mount_child: None,
            runtime_child: None,
            ram_top: None,
        };
        let parsed: PidRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(parsed.owner.alive());
        assert!(!ProcessIdentity {
            pid: 0,
            start: None
        }
        .alive());
        assert!(!ProcessIdentity {
            pid: std::process::id(),
            start: Some("wrong-start".into())
        }
        .alive());
        assert!(serde_json::from_str::<PidRecord>("{\"pid\":123}").is_err());
        #[cfg(target_os = "linux")]
        assert!(!is_runner(std::process::id()));
        let temp = tempfile::tempdir().unwrap();
        let lock_path = temp.path().join("lock");
        let lock = RunLock::acquire(&lock_path).unwrap();
        assert!(RunLock::acquire(&lock_path).is_err());
        drop(lock);
        assert!(RunLock::acquire(&lock_path).is_ok());
        assert_eq!(
            pid_path(Path::new("/a/top")),
            Path::new("/a/.top.ratarmount-run.pid")
        );
    }

    /// Regression: stale recovery must stop the old runtime, copy RAM data, and retire its PID record.
    #[test]
    fn regression_run_stale_recovery_copies_ram_and_retires_record() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        fs::write(
            &runtime,
            b"#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$0.log\"\n",
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let top = temp.path().join("top");
        let mountpoint = temp.path().join("mount");
        let ram = temp.path().join("ram");
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&ram).unwrap();
        fs::write(ram.join("payload"), b"survived").unwrap();
        let record = PidRecord {
            owner: ProcessIdentity {
                pid: 0,
                start: None,
            },
            mountpoint: mountpoint.clone(),
            container: "ratarmount-run-stale".into(),
            runtime: runtime.clone(),
            mount_child: None,
            runtime_child: None,
            ram_top: Some(ram.clone()),
        };
        let pid = pid_path(&top);
        fs::write(&pid, serde_json::to_vec(&record).unwrap()).unwrap();
        recover(&pid, &top).unwrap();
        assert_eq!(fs::read(top.join("payload")).unwrap(), b"survived");
        assert!(!ram.exists());
        assert!(!mountpoint.exists());
        assert!(!pid.exists());
        assert_eq!(
            fs::read_to_string(sidecar(&runtime, ".log")).unwrap(),
            "kill\nrm\n"
        );
    }

    /// Regression: a failed runtime removal must not be mistaken for an already removed container.
    #[test]
    fn regression_run_cleanup_failure_keeps_recovery_record() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        fs::write(
            &runtime,
            b"#!/bin/sh\necho 'daemon unavailable' >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let top = temp.path().join("top");
        let pid = pid_path(&top);
        let record = PidRecord {
            owner: ProcessIdentity {
                pid: 0,
                start: None,
            },
            mountpoint: temp.path().join("mount"),
            container: "ratarmount-run-stale".into(),
            runtime,
            mount_child: None,
            runtime_child: None,
            ram_top: None,
        };
        fs::write(&pid, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(recover(&pid, &top)
            .unwrap_err()
            .to_string()
            .contains("daemon unavailable"));
        assert!(pid.exists());
    }

    /// Regression: timeout during container creation must remove a container published after the first rm.
    #[test]
    fn regression_run_timeout_during_runtime_start_removes_late_container() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        fs::write(&runtime, b"#!/bin/sh\ncase $1 in\nrun) sleep 0.1; touch \"$0.container\" ;;\nrm) rm -f \"$0.container\" ;;\nesac\n").unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let child = Command::new(&runtime).arg("run").spawn().unwrap();
        let record = PidRecord {
            owner: ProcessIdentity::new(std::process::id()),
            mountpoint: temp.path().join("mount"),
            container: "ratarmount-run-starting".into(),
            runtime: runtime.clone(),
            mount_child: None,
            runtime_child: Some(ProcessIdentity::new(child.id())),
            ram_top: None,
        };
        let top = temp.path().join("top");
        let mut cleanup = Cleanup {
            control_dir: None,
            record,
            pid_file: pid_path(&top),
            top,
            mount_child: None,
            runtime_child: Some(child),
            stopped: false,
            runtime_stopped: false,
        };
        cleanup.stop_runtime().unwrap();
        assert!(cleanup.runtime_child.is_none());
        assert!(!sidecar(&runtime, ".container").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "subprocess helper for regression_run_child_dies_with_supervisor"]
    fn run_child_death_probe() {
        let Some(marker) = std::env::var_os("RATARMOUNT_RUN_DEATH_PROBE") else {
            return;
        };
        let mut child = supervised(Command::new("/bin/sleep").arg("60"))
            .spawn()
            .unwrap();
        fs::write(
            marker,
            serde_json::to_vec(&ProcessIdentity::new(child.id())).unwrap(),
        )
        .unwrap();
        child.wait().unwrap();
    }

    /// Regression: SIGKILL before a child PID is recorded must not leave a late-starting mount process.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_run_child_dies_with_supervisor() {
        if !Path::new("/bin/sleep").exists() {
            eprintln!("skip: /bin/sleep unavailable");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("child.json");
        let mut supervisor = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::run::tests::run_child_death_probe",
                "--ignored",
            ])
            .env("RATARMOUNT_RUN_DEATH_PROBE", &marker)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let child: ProcessIdentity = loop {
            if let Ok(bytes) = fs::read(&marker) {
                if let Ok(child) = serde_json::from_slice(&bytes) {
                    break child;
                }
            }
            if start.elapsed() > Duration::from_secs(5) {
                let _ = supervisor.kill();
                let _ = supervisor.wait();
                panic!("child probe did not start");
            }
            std::thread::sleep(POLL);
        };
        assert!(child.alive());
        supervisor.kill().unwrap();
        supervisor.wait().unwrap();
        let start = Instant::now();
        while child.alive() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(POLL);
        }
        assert!(!child.alive(), "child outlived its killed supervisor");
    }

    /// Regression: persisted RAM overlays must preserve DB bytes, modes and symlinks without following them.
    #[test]
    fn regression_run_ram_copy_preserves_modes_symlinks_and_database() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("ram");
        let target = temp.path().join("top");
        fs::create_dir(&source).unwrap();
        fs::write(source.join(HIDDEN_DB), b"db bytes").unwrap();
        fs::write(source.join("exec"), b"executable").unwrap();
        fs::set_permissions(source.join("exec"), fs::Permissions::from_mode(0o751)).unwrap();
        std::os::unix::fs::symlink("/outside/never/read", source.join("link")).unwrap();
        copy_tree(&source, &target).unwrap();
        copy_tree(&source, &target).unwrap(); // interrupted copy retry
        assert_eq!(fs::read(target.join(HIDDEN_DB)).unwrap(), b"db bytes");
        assert_eq!(
            fs::metadata(target.join("exec"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        assert_eq!(
            fs::read_link(target.join("link")).unwrap(),
            Path::new("/outside/never/read")
        );
    }

    /// Regression: offline run finalization must fsck, seal, pack, and emit the diff hash object.
    #[test]
    fn regression_run_report_hash_manifest_seal_pack() {
        use ratarmount_compositing::{
            BaseDigestRequest, FolderMountSource, OverlayCreateInfo, WriteOverlay,
        };
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let top = temp.path().join("top");
        fs::create_dir(&base).unwrap();
        let source = Arc::new(FolderMountSource::new(&base).unwrap());
        let info = OverlayCreateInfo {
            base_url: base.to_string_lossy().into_owned(),
            base_digest: BaseDigestRequest::None,
            ..Default::default()
        };
        let overlay = WriteOverlay::new_with_create_info(source, &top, &info).unwrap();
        overlay.create_symlink("/link", "/target").unwrap();
        drop(overlay);
        let mut args = args(&[]);
        args.base = base;
        args.top = top.clone();
        args.pack = Some(temp.path().join("bundle.tar.zst"));
        let report = finish(
            &args,
            &top,
            &sidecar(&top, ".journal.jsonl"),
            Execution {
                exit_code: 7,
                timed_out: false,
                erofs_denied: 2,
                bytes_written: 0,
                start: Instant::now(),
            },
        )
        .unwrap();
        assert_eq!(report["exit_code"], 7);
        assert_eq!(report["timed_out"], false);
        assert_eq!(report["patch_hash"]["files"], 1);
        assert_eq!(report["patch_hash"]["normalize"], "strict");
        assert_eq!(report["patch_hash"]["algo"], "sha256");
        assert_eq!(report["patch_hash"]["sealed"], true);
        // `--base-digest none` is the `none` state; base_pending stays for compatibility.
        assert_eq!(report["patch_hash"]["base_digest_state"], "none");
        assert_eq!(report["patch_hash"]["base_pending"], false);
        assert_eq!(report["erofs_denied"], 2);
        assert_eq!(report["fsck_result"], "ok");
        assert!(report["journal_summary"].is_null());
        assert!(report["wall_time_s"].is_number());
        assert!(args.pack.unwrap().is_file());
        assert_eq!(
            fs::read_to_string(sidecar(&top, ".manifest.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        let options = ChangeOptions {
            normalize: Normalize::Strict,
            ..Default::default()
        };
        let lower = Arc::new(FolderMountSource::new(&args.base).unwrap());
        let changes = overlay_changes::change_set(&top, lower, &options).unwrap();
        assert_eq!(
            report["patch_hash"]["patch"],
            overlay_changes::canonical_hash(&changes, &options).unwrap()
        );
    }

    /// Regression (J): the private parent is 0700 and only a directory this
    /// module made (`ratarmount-run-*/mnt`, caller-owned, 0700, not `/tmp`) is
    /// removed with a recovered record.
    #[test]
    fn regression_run_private_parent_rules() {
        use std::os::unix::fs::PermissionsExt;
        let dir = create_run_dir().unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o700);
        assert!(dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("ratarmount-run-"));
        let mnt = dir.join("mnt");
        assert_eq!(private_parent(&mnt), Some(dir.clone()));
        // Old records: the mountpoint itself sits in the shared directory.
        assert_eq!(private_parent(&dir), None);
        assert_eq!(private_parent(Path::new("/tmp/mnt")), None);
        // Not named like ours, or wider than 0700: refused.
        let other = tempfile::tempdir().unwrap();
        assert_eq!(private_parent(&other.path().join("mnt")), None);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(private_parent(&mnt), None);
        fs::remove_dir_all(dir).unwrap();
    }

    /// Regression: the socket-length check measured `TMPDIR` as written, but
    /// the run directory is canonicalized afterwards, so a short symlink to a
    /// long directory passed the check and the socket path overflowed
    /// `sun_path`. The check must use the resolved directory.
    #[test]
    fn regression_run_dir_checks_socket_length_after_canonicalizing_tmpdir() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut long = root.path().canonicalize().unwrap();
        while long.as_os_str().len() < 120 {
            long.push("a_long_directory_component");
        }
        fs::create_dir_all(&long).unwrap();
        let short = root.path().join("s");
        std::os::unix::fs::symlink(&long, &short).unwrap();
        assert!(short.as_os_str().len() < 40);
        let dir = create_run_dir_in(&short).unwrap().canonicalize().unwrap();
        let socket = control_socket_path(&dir, u32::MAX);
        assert!(socket.as_os_str().len() <= MAX_SOCKET_PATH, "{socket:?}");
        assert!(!dir.starts_with(&long), "{dir:?} is under the long dir");
        fs::remove_dir_all(&dir).unwrap();
        // A short real directory is still used as is.
        let direct = tempfile::tempdir_in("/tmp").unwrap();
        // (`/tmp` is a symlink to `/private/tmp` on macOS: compare resolved paths.)
        let dir = create_run_dir_in(direct.path())
            .unwrap()
            .canonicalize()
            .unwrap();
        assert!(
            dir.starts_with(direct.path().canonicalize().unwrap()),
            "{dir:?}"
        );
        // The fallback under `/tmp` also yields a short enough socket path.
        let socket = control_socket_path(&dir, u32::MAX);
        assert!(socket.as_os_str().len() <= MAX_SOCKET_PATH, "{socket:?}");
    }

    /// Regression: `sandbox run` reads `erofs_denied` from the mount's control
    /// socket (the in-FS control folder is not mounted) and the socket path is
    /// `<dir>/ratarmount-control-<pid>.sock`.
    #[test]
    fn regression_control_socket_counters_and_path() {
        use std::io::{Read, Write};
        let dir = create_run_dir().unwrap();
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&dir).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o700);
        let socket = control_socket_path(&dir, 4242);
        assert_eq!(socket, dir.join("ratarmount-control-4242.sock"));
        assert!(socket.as_os_str().len() <= MAX_SOCKET_PATH, "{socket:?}");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            for reply in ["mounted /m\nerofs_denied 7\n", "mounted /m\n"] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 7];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"status\n");
                stream.write_all(reply.as_bytes()).unwrap();
            }
        });
        assert_eq!(counters(&socket).unwrap(), 7);
        // No quota/rule policy: the line is absent and the count is zero.
        assert_eq!(counters(&socket).unwrap(), 0);
        server.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
