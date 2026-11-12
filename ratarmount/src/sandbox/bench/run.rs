//! Admission completes before private roots or runtime execution are created.
use super::{io as owned, record, runtime, schedule, source, BenchArgs, RuntimeKind};
use owned::invalid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

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
        Ok((executable, out, work, work_parent, id, files, load, paths))
    })();
    let (executable, out, work, work_parent, id, mut files, load, paths) = match admitted {
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
    let header = record::batch(args, bytes, entries, executable, paths, host, load);
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
        let started = std::time::Instant::now();
        row = records.row(index, entry, Some(&tree_path));
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
            return Ok(records.finish(entries, result));
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
            row["recovery"] = serde_json::json!(out.join(format!("{index}-recovery.json")));
            Ok(())
        })();
        row["lifecycle_ms"]["extract"] = serde_json::json!(started.elapsed().as_millis());
        let prepared = prepared.and_then(|()| {
            #[cfg(test)]
            inject("mount-utf8")?;
            tree_path
                .to_str()
                .ok_or_else(|| invalid("unsupported runtime bind path"))
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
                let recorded = records.terminal(&row);
                return Ok(records.finish(entries, Err(owned::with_cleanup(error, recorded))));
            }
        };
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
            row["startup_argv"] = serde_json::json!(startup);
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
        if execution.is_ok()
            && phases
                .iter()
                .any(|p| p.error.as_deref() == Some("interrupted"))
        {
            row["outcome"] = "interrupted".into();
            row["reason"] = "interrupted".into();
        } else if execution.is_ok() && stop.is_ok() && cleanup.is_ok() {
            records.grade(&mut row, entry, &phases);
        }
        if row["outcome"] == "error" {
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
            let error = if stopped {
                owned::with_cleanup(error, self::cleanup(work_parent, id))
            } else {
                error
            };
            return Ok(records.finish(entries, Err(error)));
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
    Ok(records.finish(entries, result))
}

#[cfg(test)]
mod tests {
    use super::*;
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
