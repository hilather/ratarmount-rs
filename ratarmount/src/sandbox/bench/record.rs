//! Grading and durable, fixture-labelled records through owned output helpers.
//! Input paths are admission snapshots; this module does not canonicalize or stat them.
use super::{io as owned, run, runtime, schedule, BenchArgs, RuntimeKind};
use rustix::fd::OwnedFd;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "rrs-perl-bench/1";
#[derive(Clone, Debug, Serialize)]
pub(super) struct Summary {
    files: Option<u64>,
    tests: Option<u64>,
    skipped: Option<u64>,
    result: Option<String>,
}
pub(super) fn grade(phases: &[runtime::Phase]) -> Result<Summary, String> {
    for phase in phases {
        if !phase.success() {
            return Err(format!(
                "phase {} exit {}",
                phase.phase(),
                phase
                    .error
                    .as_deref()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{:?}", phase.exit_code))
            ));
        }
    }
    let text = phases
        .iter()
        .rev()
        .find(|p| p.phase() == "test")
        .and_then(runtime::Phase::stdout)
        .unwrap_or("");
    if text.contains("Bailout called") || text.contains("Bail out!") {
        return Err("bailout".into());
    }
    let counts = text
        .lines()
        .filter_map(|line| {
            let (files, rest) = line.strip_prefix("Files=")?.split_once(", Tests=")?;
            let (tests, _) = rest.split_once(',')?;
            let number = |s: &str| {
                (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| s.parse::<u64>().ok())
                    .flatten()
            };
            Some((number(files)?, number(tests)?))
        })
        .next_back();
    let result = text
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .and_then(|line| line.strip_prefix("Result: "));
    match result {
        Some("FAIL") => return Err("FAIL with exit 0".into()),
        Some("NOTESTS") => return Err("NOTESTS".into()),
        Some("PASS") if counts.is_some() => {}
        _ => return Err("missing or malformed prove summary".into()),
    }
    let (files, tests) = counts.unwrap();
    if files == 0 || tests == 0 {
        return Err("non-positive file/test count".into());
    }
    Ok(Summary {
        files: Some(files),
        tests: Some(tests),
        skipped: None,
        result: Some("PASS".into()),
    })
}
pub(super) fn compare(reference: &Summary, run: &Summary) -> Result<(), String> {
    if reference.files != run.files || reference.tests != run.tests {
        Err("test counts differ from native reference".into())
    } else {
        Ok(())
    }
}
#[derive(Serialize)]
pub(super) struct Host {
    sysname: String,
    release: String,
    version: String,
    machine: String,
}
pub(super) fn host_identity(result: io::Result<libc::utsname>) -> io::Result<Host> {
    let value = result.map_err(|e| io::Error::other(format!("uname failed: {e}")))?;
    // Bound each field even for malformed input; nodename is deliberately omitted.
    let text = |name, p: &[libc::c_char]| -> io::Result<String> {
        let bytes: Vec<u8> = p.iter().map(|&c| c as u8).collect();
        CStr::from_bytes_until_nul(&bytes)
            .map(|s| s.to_string_lossy().into_owned())
            .map_err(|_| io::Error::other(format!("uname field {name} missing NUL terminator")))
    };
    Ok(Host {
        sysname: text("sysname", &value.sysname)?,
        release: text("release", &value.release)?,
        version: text("version", &value.version)?,
        machine: text("machine", &value.machine)?,
    })
}
pub(super) fn uname() -> io::Result<Host> {
    // SAFETY: utsname is a C struct of c_char arrays; all-zero is a valid value.
    let mut value = unsafe { std::mem::zeroed() };
    // SAFETY: value is aligned, valid and exclusively borrowed. uname writes NUL-terminated
    // fields on success; -1 is mapped to last_os_error below.
    let result = if unsafe { libc::uname(&mut value) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    };
    #[cfg(test)]
    let result = run::inject("uname-fail").and(result);
    host_identity(result).map_err(|e| io::Error::other(format!("host identity: {e}")))
}
fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
fn labels(row: &mut Value, kind: RuntimeKind) {
    row["fixture"] = json!(kind == RuntimeKind::Stub);
    row["publishable"] = json!(kind != RuntimeKind::Stub);
}
pub(super) struct AdmittedPaths {
    pub catalog: PathBuf,
    pub artifacts: BTreeMap<String, PathBuf>,
}
pub(super) fn batch(
    args: &BenchArgs,
    bytes: &[u8],
    entries: &[schedule::Entry],
    executable: &Path,
    paths: &AdmittedPaths,
    host: Host,
    load: Value,
) -> io::Result<Value> {
    let catalog: Value = serde_json::from_slice(bytes)?;
    let platforms: Vec<_> = catalog["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| entries.iter().any(|e| e.cell.platform == p["id"]))
        .cloned()
        .collect();
    let tasks: Vec<_> = catalog["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| entries.iter().any(|e| e.cell.task == t["id"]))
        .map(|t| {
            let mut artifact = t["artifact"].clone();
            artifact["resolved_path"] = json!(paths.artifacts[t["id"].as_str().unwrap()]);
            json!({"id":t["id"],"artifact":artifact,"test_inventory":t["test_inventory"],
                "commands":t["commands"],"environment":t["environment"],"resources":t["resources"]})
        })
        .collect();
    let entry = serde_json::to_value(entries.first())?;
    let base_forms: BTreeSet<_> = entries.iter().map(|e| e.cell.base_form).collect();
    let caches: BTreeSet<_> = entries.iter().map(|e| e.cell.cache).collect();
    let jobs: BTreeSet<_> = entries.iter().map(|e| e.cell.jobs).collect();
    let mut value = json!({"schema":SCHEMA,"record":"batch","catalog_revision":catalog["catalog_revision"],
        "manifest_path":paths.catalog,"manifest_sha256":format!("sha256:{:x}",Sha256::digest(bytes)),"platforms":platforms,"tasks":tasks,"host":host,
        "runtime":{"kind":args.runtime_kind.unwrap(),"path":executable},
        "settings":{"native":{"base_form":base_forms,"cache":caches,"jobs":jobs,
            "seed":entry["seed"],"repeats":entry["repeats"],"attempts":entry["attempts"],"allow_high_load":args.allow_high_load,
            "allow_oversubscription":args.selection.allow_oversubscription,"work_root":args.work_root}},
        "load":load,"started_unix_ms":unix_ms()});
    labels(&mut value, args.runtime_kind.unwrap());
    Ok(value)
}
fn write_record_file(dir: &OwnedFd, name: &str, rows: &[Value]) -> io::Result<()> {
    let atomic = name == "batch-end.json";
    let temporary = if atomic { ".batch-end.json.tmp" } else { name };
    let mut file = owned::create_output(dir, temporary)?;
    let mut published = false;
    let result = (|| -> io::Result<()> {
        #[cfg(test)]
        run::inject(&format!("record-header-fail:{name}"))?;
        for row in rows {
            serde_json::to_writer(&mut file, row)?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
        if atomic {
            rustix::fs::renameat(dir, temporary, dir, name)?;
            published = true;
            #[cfg(test)]
            run::inject(&format!("record-end-fsync-fail:{name}"))?;
            rustix::fs::fsync(dir)?;
        }
        Ok(())
    })();
    match result {
        Err(error) if atomic => Err(owned::with_cleanup(
            error,
            owned::remove_tree(dir, if published { name } else { temporary }),
        )),
        result => result,
    }
}
#[derive(Debug)]
pub(super) struct Finished {
    pub status: Status,
    pub result: io::Result<()>,
}
#[derive(Debug)]
pub(super) struct Status {
    pub status: &'static str,
    pub interrupt_observed: bool,
    counts: BTreeMap<String, usize>,
    fixture: bool,
}
impl Status {
    pub fn presentation(&self) -> (i32, String) {
        let message = match self.status {
            "passed" => format!(
                "passed: {} runs graded; batch complete{}",
                self.counts["passed"],
                if self.fixture {
                    "; stub fixture, not publishable"
                } else {
                    ""
                }
            ),
            "interrupted" => format!(
                "interrupted: batch incomplete; {} runs not executed",
                self.counts["blocked"] + self.counts["interrupted"]
            ),
            "error" => format!(
                "error: batch stopped with {} errored, {} failed and {} blocked runs; see runs.jsonl",
                self.counts["error"], self.counts["failed"], self.counts["blocked"]
            ),
            _ => format!(
                "failed: batch complete with {} failed and {} blocked runs; see runs.jsonl",
                self.counts["failed"], self.counts["blocked"]
            ),
        };
        let suffix = if self.interrupt_observed && self.status != "interrupted" {
            if self.status == "error" {
                "; interrupt observed"
            } else {
                "; interrupt observed after completion"
            }
        } else {
            ""
        };
        (
            i32::from(self.status != "passed"),
            format!("sandbox bench: {message}{suffix}"),
        )
    }
}
pub(super) fn lifecycle_error(interrupted: bool, error: &io::Error) -> String {
    if interrupted {
        format!("sandbox bench: interrupted: batch incomplete; lifecycle error: {error}")
    } else {
        format!("bench native lifecycle: {error}")
    }
}
pub(super) struct Records<'a> {
    dir: &'a OwnedFd,
    runs: File,
    header: Value,
    started: Instant,
    next: usize,
    broken: bool,
    counts: BTreeMap<String, usize>,
    blocker: Option<(usize, String)>,
    references: BTreeMap<String, (usize, Summary)>,
}
impl<'a> Records<'a> {
    pub fn create(
        dir: &'a OwnedFd,
        id: &str,
        mut header: Value,
        entries: &[schedule::Entry],
    ) -> io::Result<Self> {
        let started = Instant::now();
        header["batch_id"] = id.into();
        write_record_file(dir, "batch.json", &[header.clone()])?;
        let rows: Vec<_> = entries.iter().enumerate().map(|(index,entry)| json!({"schema":SCHEMA,"record":"schedule", "batch_id":id,"run_id":format!("{id}-{index}"),"sequence":index,"entry":entry})).collect();
        write_record_file(dir, "schedule.jsonl", &rows)?;
        let runs = owned::create_output(dir, "runs.jsonl")?;
        Ok(Self {
            dir,
            runs,
            header,
            started,
            next: 0,
            broken: false,
            counts: ["passed", "failed", "blocked", "interrupted", "error"]
                .into_iter()
                .map(|k| (k.into(), 0))
                .collect(),
            blocker: None,
            references: BTreeMap::new(),
        })
    }
    pub fn row(&self, index: usize, entry: &schedule::Entry, tree: Option<&Path>) -> Value {
        let task = self.header["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == entry.cell.task)
            .unwrap();
        let substitute = |s: &str| s.replace("{jobs}", &entry.cell.jobs.to_string());
        let environment: BTreeMap<_, _> = task["environment"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k, substitute(v.as_str().unwrap())))
            .collect();
        let argv: BTreeMap<_, _> = task["commands"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                (
                    k,
                    v["argv"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|a| substitute(a.as_str().unwrap()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let timeouts: BTreeMap<_, _> = task["commands"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k, &v["timeout_seconds"]))
            .collect();
        json!({"schema":SCHEMA,"record":"run","batch_id":self.header["batch_id"],"run_id":format!("{}-{index}",self.header["batch_id"].as_str().unwrap()),
            "index":index,"schedule":entry,"outcome":"error","reason":null,"blocked_by":null,"summary":null,"reference":null,
            "runtime":self.header["runtime"],"fixture":self.header["fixture"],"publishable":self.header["publishable"],
            "startup_argv":[],"argv":argv,"environment":environment,"limits":{"cpus":task["resources"]["cpus"],"memory_bytes":task["resources"]["memory_bytes"],"pids":task["resources"]["pids"],"timeouts":timeouts,"startup_timeout_seconds":30,"control_timeout_seconds":5},
            "lifecycle_ms":{"extract":0,"total":0},"tree":tree,"recovery":null,"load":self.header["load"],"phases":[],"execution_error":null,"stop_error":null,"cleanup_error":null})
    }
    pub fn grade(&mut self, row: &mut Value, entry: &schedule::Entry, phases: &[runtime::Phase]) {
        let key = serde_json::to_string(&entry.cell).expect("scalar cell identity");
        let result = grade(phases).and_then(|summary| {
            row["summary"] = json!(summary);
            if entry.is_reference() {
                self.references
                    .insert(key, (row["index"].as_u64().unwrap() as usize, summary));
            } else {
                let (index, reference) = self
                    .references
                    .get(&key)
                    .ok_or("missing native reference")?;
                row["reference"] =
                    json!({"index":index,"files":reference.files,"tests":reference.tests});
                compare(reference, &summary)?;
            }
            Ok(())
        });
        row["outcome"] = if result.is_ok() { "passed" } else { "failed" }.into();
        row["reason"] = json!(result.err());
    }
    pub fn terminal(&mut self, row: &Value) -> io::Result<()> {
        if let Err(error) = run::record(&mut self.runs, row) {
            self.broken = true;
            return Err(error);
        }
        let outcome = row["outcome"].as_str().unwrap();
        *self.counts.get_mut(outcome).unwrap() += 1;
        if outcome != "passed" && outcome != "blocked" {
            self.blocker = Some((
                self.next,
                row["reason"].as_str().unwrap_or(outcome).to_owned(),
            ));
        }
        self.next += 1;
        Ok(())
    }
    // Call only after the final owned scratch cleanup. A failed terminal append leaves no end marker.
    pub fn finish(&mut self, entries: &[schedule::Entry], result: io::Result<()>) -> Finished {
        let blocked = (|| {
            if !self.broken {
                if let Some((index, reason)) = self.blocker.clone() {
                    for (i, entry) in entries.iter().enumerate().skip(self.next) {
                        let mut row = self.row(i, entry, None);
                        row["outcome"] = "blocked".into();
                        row["reason"] = json!(reason);
                        row["blocked_by"] = json!(index);
                        self.terminal(&row)?;
                    }
                }
            }
            Ok(())
        })();
        let result = match result {
            Err(error) => Err(owned::with_cleanup(error, blocked)),
            Ok(()) => blocked,
        };
        // Freeze once, before publication, for both the marker and all presentation paths.
        let status = self.status(result.is_err());
        #[cfg(test)]
        if run::inject("interrupt-after-status").is_err() {
            runtime::test_set_interrupted();
        }
        let write_end = if self.broken {
            Ok(())
        } else {
            write_record_file(
                self.dir,
                "batch-end.json",
                &[
                    json!({"schema":SCHEMA,"record":"batch-end","batch_id":self.header["batch_id"],
                "status":status.status,"interrupt_observed":status.interrupt_observed,"error":result.as_ref().err().map(ToString::to_string),
                "counts":self.counts,"finished_unix_ms":unix_ms(),"wall_ms":self.started.elapsed().as_millis()}),
                ],
            )
        };
        let result = match result {
            Err(error) => Err(owned::with_cleanup(error, write_end)),
            Ok(()) => write_end,
        };
        Finished { status, result }
    }
    fn status(&self, error: bool) -> Status {
        let interrupt_observed = runtime::interrupted();
        let status = if self.counts["interrupted"] > 0 || (self.broken && interrupt_observed) {
            "interrupted"
        } else if error || self.counts["error"] > 0 {
            "error"
        } else if self.counts["failed"] > 0 || self.counts["blocked"] > 0 {
            "failed"
        } else {
            "passed"
        };
        Status {
            status,
            interrupt_observed,
            counts: self.counts.clone(),
            fixture: self.header["fixture"] == true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn phase(name: &str, text: &str, exit: Option<i32>, error: Option<&str>) -> runtime::Phase {
        serde_json::from_value(json!({"phase":name,"stdout":text,"stderr":"", "stdout_log":"", "stderr_log":"",
            "exit_code":exit,"error":error,"elapsed_ms":0,"stdout_truncated":false,"stderr_truncated":false,"argv":[],"environment":{}})).unwrap()
    }
    fn passed() -> runtime::Phase {
        phase(
            "test",
            "Files=1, Tests=10, 0 wallclock secs\nResult: PASS\n",
            Some(0),
            None,
        )
    }
    // Regression: a failing prove result with exit zero was accepted.
    #[test]
    fn regression_bench_tap_fail_with_zero_exit() {
        let error = grade(&[phase(
            "test",
            "Files=1, Tests=10,\nResult: FAIL\n",
            Some(0),
            None,
        )])
        .unwrap_err();
        assert!(error.contains("FAIL"), "{error}");
    }
    // Regression: missing/malformed, empty and bailed-out suites claimed success.
    #[test]
    fn regression_bench_tap_missing_notests_and_bailout() {
        for (text, reason) in [
            ("", "missing or malformed"),
            ("Files=x, Tests=10,\nResult: PASS", "missing or malformed"),
            ("Files=1, Tests=10,\nResult: ???", "missing or malformed"),
            (
                "Files=1, Tests=10,\nResult: PASS\ntrailing output",
                "missing or malformed",
            ),
            (
                "Files=1, Tests=10,\nResult: PASS\nResult: ???",
                "missing or malformed",
            ),
            ("Files=0, Tests=0,\nResult: NOTESTS", "NOTESTS"),
            ("Files=0, Tests=10,\nResult: PASS", "non-positive"),
            ("Files=1, Tests=0,\nResult: PASS", "non-positive"),
            (
                "Bailout called. x\nFiles=1, Tests=10,\nResult: PASS",
                "bailout",
            ),
            ("Bail out! x\nResult: PASS", "bailout"),
        ] {
            assert!(
                grade(&[phase("test", text, Some(0), None)])
                    .unwrap_err()
                    .contains(reason),
                "{text}"
            );
        }
    }
    // Regression: measurements with changed file or test counts matched their reference.
    #[test]
    fn regression_bench_test_counts_must_equal_reference() {
        let reference = grade(&[passed()]).unwrap();
        assert!(compare(&reference, &reference).is_ok());
        for (files, tests) in [(0, 10), (2, 10), (1, 9), (1, 11)] {
            let mut run = reference.clone();
            run.files = Some(files);
            run.tests = Some(tests);
            assert_eq!(
                compare(&reference, &run).unwrap_err(),
                "test counts differ from native reference"
            );
        }
    }
    // Regression: nonzero phase exits, signals, timeout and interruption hid behind PASS.
    #[test]
    fn regression_bench_nonzero_phase_exit_fails() {
        for name in ["configure", "build", "test"] {
            for (exit, error) in [
                (Some(7), None),
                (Some(137), None),
                (Some(143), None),
                (None, Some("timeout")),
                (None, Some("interrupted")),
            ] {
                let p = phase(name, "Files=1, Tests=10,\nResult: PASS", exit, error);
                assert!(grade(&[passed(), p])
                    .unwrap_err()
                    .contains(&format!("phase {name} exit")));
            }
        }
    }
    // Regression: uname failure silently produced an empty host identity or included NULs.
    #[test]
    fn regression_bench_uname_failure_has_explicit_reason() {
        assert!(
            host_identity(Err(io::Error::from_raw_os_error(libc::EFAULT)))
                .err()
                .unwrap()
                .to_string()
                .contains("uname failed")
        );
        let mut value: libc::utsname = unsafe { std::mem::zeroed() };
        value.sysname[0] = b'L' as libc::c_char;
        let host = host_identity(Ok(value)).unwrap();
        assert_eq!(host.sysname, "L");
        assert_eq!(host.release, "");
        for field in ["sysname", "release", "version", "machine"] {
            let mut value: libc::utsname = unsafe { std::mem::zeroed() };
            match field {
                "sysname" => value.sysname.fill(1),
                "release" => value.release.fill(1),
                "version" => value.version.fill(1),
                _ => value.machine.fill(1),
            }
            assert_eq!(
                host_identity(Ok(value)).err().unwrap().to_string(),
                format!("uname field {field} missing NUL terminator")
            );
        }
    }
    fn records(dir: &Path, kind: RuntimeKind) -> (OwnedFd, Value, Vec<schedule::Entry>) {
        let bytes = serde_json::to_vec(&super::super::tests::fixture()).unwrap();
        let entries = schedule::build(&bytes, &super::super::Selection::default()).unwrap();
        let fd = owned::open_directory(dir).unwrap();
        let manifest = dir.join("tasks.json");
        std::fs::write(&manifest, &bytes).unwrap();
        let args = BenchArgs {
            manifest,
            validate_only: false,
            dry_run: false,
            require_pins: false,
            out: Some(dir.join("out")),
            work_root: dir.into(),
            runtime: Some("runtime".into()),
            runtime_kind: Some(kind),
            allow_high_load: false,
            selection: super::super::Selection::default(),
        };
        let host = host_identity(Ok(unsafe { std::mem::zeroed() })).unwrap();
        let header = batch(
            &args,
            &bytes,
            &entries,
            Path::new("runtime"),
            &AdmittedPaths {
                catalog: dir.join("admitted-catalog.json"),
                artifacts: BTreeMap::from([("mojo".into(), dir.join("admitted-artifact"))]),
            },
            host,
            json!({}),
        )
        .unwrap();
        (fd, header, entries)
    }
    // Regression: Docker records were fixture-labelled or stub output was publishable (7a).
    #[test]
    fn regression_bench_runtime_kind_recorded_and_fixture_derived() {
        for kind in [RuntimeKind::Docker, RuntimeKind::Stub] {
            let fixture = kind == RuntimeKind::Stub;
            let dir = tempfile::tempdir().unwrap();
            let (fd, header, entries) = records(dir.path(), kind);
            let records = Records::create(&fd, "id", header, &entries).unwrap();
            let batch: Value =
                serde_json::from_slice(&std::fs::read(dir.path().join("batch.json")).unwrap())
                    .unwrap();
            // Regression: records must retain admission paths even when those names have disappeared.
            assert_eq!(
                batch["manifest_path"],
                json!(dir.path().join("admitted-catalog.json"))
            );
            assert_eq!(
                batch["tasks"][0]["artifact"]["resolved_path"],
                json!(dir.path().join("admitted-artifact"))
            );
            let row = records.row(0, &entries[0], None);
            for record in [batch, row] {
                assert_eq!(record["runtime"]["kind"], json!(kind));
                assert_eq!(record["fixture"], fixture);
                assert_eq!(record["publishable"], !fixture);
            }
        }
    }
    // Regression: a defensive error status must not claim a completed failed batch.
    #[test]
    fn regression_bench_error_status_presentation_is_explicit() {
        let mut status = Status {
            status: "error",
            interrupt_observed: false,
            fixture: false,
            counts: BTreeMap::from([
                ("error".into(), 1),
                ("failed".into(), 0),
                ("blocked".into(), 2),
            ]),
        };
        let message = "sandbox bench: error: batch stopped with 1 errored, 0 failed and 2 blocked runs; see runs.jsonl";
        assert_eq!(status.presentation(), (1, message.into()));
        status.interrupt_observed = true;
        assert_eq!(
            status.presentation(),
            (1, format!("{message}; interrupt observed"))
        );
    }
    // Regression: a broken append of any terminal must retain an observed interrupt.
    #[test]
    fn regression_bench_broken_records_status_follows_interrupt() {
        let _scope = runtime::InterruptScope::new();
        for interrupted in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (fd, header, entries) = records(dir.path(), RuntimeKind::Stub);
            let mut records = Records::create(&fd, "id", header, &entries).unwrap();
            records.broken = true;
            if interrupted {
                runtime::test_set_interrupted();
            }
            let finished = records.finish(&entries, Err(io::Error::other("append-fail")));
            assert_eq!(
                finished.status.status,
                if interrupted { "interrupted" } else { "error" }
            );
            assert_eq!(finished.status.interrupt_observed, interrupted);
            assert!(!dir.path().join("batch-end.json").exists());
        }
    }
    // Regression: interrupted lifecycle errors lost their distinct stderr presentation (N3).
    #[test]
    fn regression_bench_interrupted_lifecycle_error_presentation() {
        let error = io::Error::other("cleanup-fail");
        assert_eq!(
            lifecycle_error(true, &error),
            "sandbox bench: interrupted: batch incomplete; lifecycle error: cleanup-fail"
        );
        assert_eq!(
            lifecycle_error(false, &error),
            "bench native lifecycle: cleanup-fail"
        );
    }
}
