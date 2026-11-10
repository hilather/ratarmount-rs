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
        if out.symlink_metadata().is_ok() {
            return Err(invalid("--out must be a fresh directory"));
        }
        let work = args.work_root.canonicalize()?;
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
            let groups = [
                vec![
                    artifact.clone(),
                    source,
                    catalog.clone(),
                    executable.clone(),
                ],
                vec![out.clone(), output],
                vec![work.clone(), scratch],
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
        Ok((executable, out, work, files, load))
    })();
    let (executable, out, work, mut files, load) = match admitted {
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
        &work,
        &mut files,
        &load,
    );
    drop(signals);
    result.map_err(|e| format!("bench native lifecycle: {e}"))?;
    eprintln!("sandbox bench: ungraded: benchmark verification unavailable until B4a2");
    Ok(1) // B4a2 is required for benchmark verification; never a successful benchmark.
}
fn execute_owned(
    manifest: &Manifest,
    entries: &[schedule::Entry],
    executable: &Path,
    out: &Path,
    work: &Path,
    files: &mut BTreeMap<String, File>,
    load: &Load,
) -> io::Result<()> {
    let out_parent = owned::open_directory(
        out.parent()
            .ok_or_else(|| invalid("output has no parent"))?,
    )?;
    let logs = owned::create_directory(
        &out_parent,
        out.file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| invalid("output name"))?,
    )?;
    let work_parent = owned::open_directory(work)?;
    let id = format!(
        "rrs-bench-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    );
    let scratch = owned::create_directory(&work_parent, &id)?;
    let scratch_path = work.join(&id);
    let mut outcomes = owned::create_output(&logs, "outcomes.jsonl")?;
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
        let tree_root = owned::create_directory(&scratch, &index.to_string())?;
        let file = files.get_mut(&task.id).unwrap();
        source::verify_artifact(file, &task.artifact.sha256, task.resources.disk_bytes)?;
        let tree = match source::extract(
            file,
            tree_root,
            &task.artifact.tar_stream_sha256,
            task.resources.disk_bytes,
        ) {
            Ok(tree) => tree,
            Err(error) => {
                // Extraction failed before a runtime started; all private trees can be removed.
                let cleanup = std::fs::remove_dir_all(&tree_path)
                    .and_then(|()| std::fs::remove_dir(&scratch_path));
                serde_json::to_writer(
                    &mut outcomes,
                    &serde_json::json!({"schema":"rrs-perl-bench-ungraded/1","outcome":"ungraded","verification_available":false,"reason":"benchmark verification unavailable until B4a2","schedule":entry,"tree":tree_path,"load":load,"phases":[],"execution_error":error.to_string(),"stop_error":null,"cleanup_error":cleanup.as_ref().err().map(ToString::to_string)}),
                )?;
                outcomes.write_all(b"\n")?;
                outcomes.sync_all()?;
                cleanup?;
                return Err(error);
            }
        };
        let mount = tree_path
            .to_str()
            .filter(|s| !s.contains([':', '\n', '\r']))
            .ok_or_else(|| invalid("unsupported runtime bind path"))?;
        let recovery = serde_json::json!({"runtime":executable,"container":name,"tree":tree_path});
        serde_json::to_writer(
            owned::create_output(&logs, &format!("{index}-recovery.json"))?,
            &recovery,
        )?;
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
            phases.push(runtime.invoke("run", &startup, 30, true)?);
            if !phases.last().unwrap().success() {
                return Ok(());
            }
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
            tree.make_removable()
                .and_then(|()| std::fs::remove_dir_all(&tree_path))
        } else {
            Err(io::Error::other(
                "tree preserved because runtime stop failed",
            ))
        };
        serde_json::to_writer(
            &mut outcomes,
            &serde_json::json!({"schema":"rrs-perl-bench-ungraded/1","outcome":"ungraded","verification_available":false,"reason":"benchmark verification unavailable until B4a2","schedule":entry,"tree":tree_path,"load":load,"phases":phases,"execution_error":execution.as_ref().err().map(ToString::to_string),"stop_error":stop.as_ref().err().map(ToString::to_string),"cleanup_error":cleanup.as_ref().err().map(ToString::to_string)}),
        )?;
        outcomes.write_all(b"\n")?;
        outcomes.sync_all()?;
        stop?;
        cleanup?;
        execution?;
        if phases.iter().any(|p| !p.success()) {
            break;
        }
    }
    std::fs::remove_dir(&scratch_path)?;
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
}
