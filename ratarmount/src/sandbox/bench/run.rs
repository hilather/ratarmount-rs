//! Admission completes before private roots or runtime execution are created.
use super::{io as owned, runtime, schedule, source, BenchArgs};
use owned::invalid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let admitted = (|| -> io::Result<_> {
        // B5a1a replaces this FUSE refusal; no mount/finalize work is done here.
        if entries.iter().any(|e| e.backend == schedule::Backend::Fuse) {
            return Err(invalid(
                "FUSE execution unavailable: lifecycle deferred to B5a1a",
            ));
        }
        for entry in entries {
            if !entry.runnable {
                return Err(invalid(
                    "execution requires qualified native/warm/tar.zst-single-frame selections",
                ));
            }
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
        let leaf = work.join(&id);
        for path in [&out, &work] {
            if path.to_str().is_none_or(|s| s.contains([':', '\n', '\r'])) {
                return Err(invalid("unsupported runtime bind path"));
            }
        }
        let catalog = args.manifest.canonicalize()?;
        let parent = catalog
            .parent()
            .ok_or_else(|| invalid("manifest has no parent"))?;
        let mut files = BTreeMap::new();
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
            if executable.starts_with(&work)
                || (work != Path::new("/var/tmp")
                    && [&out, parent, &artifact_dir, &source, &output]
                        .iter()
                        .any(|p| p.starts_with(&work)))
            {
                return Err(invalid(
                    "work-root ancestor containment of protected root refused",
                ));
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
            files.insert(task.id.clone(), file);
        }
        Ok((executable, out, work, work_parent, id, files, load))
    })();
    let (executable, out, work, work_parent, id, mut files, load) = match admitted {
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
            work: &work,
            parent: &work_parent,
            id: &id,
        },
        &mut files,
        &load,
    );
    drop(signals);
    result.map_err(|e| format!("bench native lifecycle: {e}"))?;
    eprintln!("sandbox bench: ungraded: benchmark verification unavailable until B4a2");
    Ok(1) // B4a2 is required for benchmark verification; never a successful benchmark.
}
struct Scratch<'a> {
    work: &'a Path,
    parent: &'a rustix::fd::OwnedFd,
    id: &'a str,
}
#[cfg(test)]
thread_local! {
    static FAULTS: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
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
    inject("cleanup-fail")?;
    owned::remove_tree(parent, name)
}
fn record(outcomes: &mut File, row: &serde_json::Value) -> io::Result<()> {
    #[cfg(test)]
    inject("record-fail")?;
    serde_json::to_writer(&mut *outcomes, row)?;
    outcomes.write_all(b"\n")?;
    outcomes.sync_all()
}
fn execute_owned(
    manifest: &Manifest,
    entries: &[schedule::Entry],
    executable: &Path,
    out: &Path,
    location: Scratch<'_>,
    files: &mut BTreeMap<String, File>,
    load: &Load,
) -> io::Result<()> {
    let Scratch {
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
    let outcomes_file = owned::create_output(&logs, "outcomes.jsonl");
    #[cfg(test)]
    let outcomes_file = outcomes_file.and_then(|file| inject("outcomes-create").map(|()| file));
    let mut outcomes = match outcomes_file {
        Ok(file) => file,
        Err(error) => {
            return Err(owned::with_cleanup(
                error,
                owned::remove_tree(&out_parent, out_name),
            ))
        }
    };
    let scratch_path = work.join(id);
    let mut row = serde_json::json!({"schema":"rrs-perl-bench-ungraded/1","outcome":"ungraded","verification_available":false,"reason":"benchmark verification unavailable until B4a2","schedule":entries.first(),"tree":scratch_path.join("0"),"load":load,"phases":[],"execution_error":null,"stop_error":null,"cleanup_error":null});
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
            row["execution_error"] = primary.into();
            row["cleanup_error"] = serde_json::json!(secondary);
            return Err(owned::with_cleanup(error, record(&mut outcomes, &row)));
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
        row["schedule"] = serde_json::to_value(entry)?;
        row["tree"] = serde_json::json!(tree_path);
        row["phases"] = serde_json::json!([]);
        #[cfg(test)]
        if inject("interrupt-entry").is_err() {
            runtime::test_set_interrupted();
        }
        if runtime::interrupted() {
            row["execution_error"] = "interrupted".into();
            record(&mut outcomes, &row)?;
            break;
        }
        let prepared = (|| -> io::Result<()> {
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
            Ok(())
        })();
        if let Err(error) = prepared {
            let error = owned::with_cleanup(error, cleanup(work_parent, id));
            let (primary, secondary) = owned::error_parts(&error);
            row["execution_error"] = primary.into();
            row["cleanup_error"] = serde_json::json!(secondary);
            return Err(owned::with_cleanup(error, record(&mut outcomes, &row)));
        }
        let mount = tree_path
            .to_str()
            .ok_or_else(|| invalid("unsupported runtime bind path"))?;
        let mut runtime =
            runtime::Runtime::new(runtime::Local::new(executable), &logs, name.clone());
        let mut phases = Vec::new();
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
            phases.push(runtime.invoke("run", &startup, 30, true)?);
            if !phases.last().unwrap().success() {
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
        let stop = runtime.stop();
        let cleanup = if stop.is_ok() {
            cleanup(&scratch, &index.to_string())
        } else {
            Err(io::Error::other(
                "tree preserved because runtime stop failed",
            ))
        };
        row["phases"] = serde_json::to_value(&phases)?;
        row["execution_error"] =
            serde_json::json!(execution.as_ref().err().map(ToString::to_string));
        row["stop_error"] = serde_json::json!(stop.as_ref().err().map(ToString::to_string));
        row["cleanup_error"] = serde_json::json!(cleanup.as_ref().err().map(ToString::to_string));
        let recorded = record(&mut outcomes, &row);
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
            return Err(if stopped {
                owned::with_cleanup(error, self::cleanup(work_parent, id))
            } else {
                error
            });
        }
        #[cfg(test)]
        if inject("interrupt-between").is_err() {
            runtime::test_set_interrupted();
        }
        if phases.iter().any(|p| !p.success()) {
            break;
        }
    }
    cleanup(work_parent, id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
            Self {
                dir,
                manifest,
                entries,
                files,
            }
        }
        fn run(&mut self) -> io::Result<()> {
            let work = self.dir.path().join("work");
            let parent = owned::open_directory(&work)?;
            execute_owned(
                &self.manifest,
                &self.entries,
                &self.dir.path().join("runtime"),
                &self.dir.path().join("out"),
                Scratch {
                    work: &work,
                    parent: &parent,
                    id: "owned-test",
                },
                &mut self.files,
                &load(Ok(0.0), 4.0, false)?,
            )
        }
        fn rows(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(self.dir.path().join("out/outcomes.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("state/calls")).unwrap_or_default()
        }
    }
    // Regression: pre-runtime create/write failures leaked roots or omitted ungraded outcomes (R-1).
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
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["outcome"], "ungraded");
                assert_eq!(rows[0]["verification_available"], false);
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
    // Regression: execution I/O failure after startup removed the tree but leaked its empty scratch leaf.
    #[test]
    fn regression_bench_execution_error_removes_scratch_leaf() {
        let _signals = runtime::InterruptScope::new();
        let mut f = Fixture::new();
        let _fault = FaultScope::new(&["execution-fail"]);
        assert_eq!(f.run().unwrap_err().to_string(), "execution-fail");
        let row = &f.rows()[0];
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
            f.run().unwrap();
            let rows = f.rows();
            let row = rows.last().unwrap();
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
            assert_eq!(rows.len(), if fault == "interrupt-between" { 2 } else { 1 });
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
