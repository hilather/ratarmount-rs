//! Regression: one-shot sandbox sequencing with a host stub and optional Docker.
#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn stub() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-harness/sandbox-run/runtime.sh")
}

/// A `ratarmount` command whose process (and so the `sandbox run` child and
/// the command it runs) has umask 022, whatever the test process's: FUSE
/// create applies the caller's umask, and canonical rows include modes
/// (R1c-1 T1b).
fn ratarmount() -> Command {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    // SAFETY: umask is async-signal-safe and touches only the child.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    command
}

/// T1b's fixture (R1c-1 §7): every JSON document `sandbox run` printed in
/// these tests, normalized, recorded on the code before `finalize_top`
/// (plan step 2a); the refactor must leave each one byte-identical.
const REPORTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/sandbox-run-reports.jsonl"
);
/// Set to record [`REPORTS`] instead of comparing with it; only on the code
/// before the refactor, on a FUSE host where no test prints `skip:`.
const RECORD: &str = "RATARMOUNT_RECORD_SANDBOX_RUN_REPORTS";

/// How one report is normalized, by name, never by value pattern.
#[derive(Default)]
struct Normalize<'a> {
    /// Temporary directories, replaced (longest first) by `$TMP1`, `$TMP2`,
    /// … in this order, in their given and canonical spellings.
    dirs: Vec<&'a Path>,
    /// The HTTP stub's port, which the test knows: `127.0.0.1:<port>`.
    port: Option<String>,
    /// Report fields masked as `"<masked>"` (dotted paths), each of which
    /// must exist. `wall_time_s` is always masked where it exists.
    fields: &'a [&'a str],
}

fn mask(report: &mut Value, field: &str) {
    let mut node = &mut *report;
    for part in field.split('.') {
        node = node
            .get_mut(part)
            .unwrap_or_else(|| panic!("T1b masks the missing field {field}"));
    }
    *node = json!("<masked>");
}

/// `report` normalized as `how` says.
fn normalized(report: &Value, how: &Normalize<'_>) -> String {
    let mut report = report.clone();
    if report.get("wall_time_s").is_some() {
        assert!(report["wall_time_s"].is_number(), "{report}");
        mask(&mut report, "wall_time_s");
    }
    for field in how.fields {
        mask(&mut report, field);
    }
    let mut text = serde_json::to_string(&report).unwrap();
    let mut forms: Vec<(String, String)> = Vec::new();
    for (i, dir) in how.dirs.iter().enumerate() {
        let placeholder = format!("$TMP{}", i + 1);
        for form in [Some(dir.to_path_buf()), dir.canonicalize().ok()]
            .into_iter()
            .flatten()
        {
            forms.push((form.to_str().unwrap().to_owned(), placeholder.clone()));
        }
    }
    forms.sort_by_key(|(form, _)| std::cmp::Reverse(form.len()));
    for (form, placeholder) in forms {
        text = text.replace(&form, &placeholder);
    }
    if let Some(port) = &how.port {
        text = text.replace(&format!("127.0.0.1:{port}"), "127.0.0.1:<port>");
    }
    text
}

/// Compares `report`, normalized, with T1b's fixture entry `test`/`case`,
/// or records that entry when [`RECORD`] is exactly `1`, saying so (a
/// recording run compares nothing).
fn check_report(test: &str, case: &str, report: &Value, how: &Normalize<'_>) {
    static FILE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let text = normalized(report, how);
    let key = format!("{test}/{case}");
    let _file = FILE.lock().unwrap_or_else(|e| e.into_inner());
    let mut entries: std::collections::BTreeMap<String, String> = fs::read_to_string(REPORTS)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let entry: Value = serde_json::from_str(line).unwrap();
            (
                entry["key"].as_str().unwrap().to_owned(),
                entry["report"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let record = std::env::var_os(RECORD);
    assert!(
        record.is_none() || record.as_deref() == Some("1".as_ref()),
        "{RECORD} must be 1 to record T1b's fixture"
    );
    if record.is_some() {
        eprintln!("T1b: recording {key} into {REPORTS}, comparing nothing");
        entries.insert(key, text);
        let mut out = String::new();
        for (key, report) in &entries {
            out.push_str(&json!({"key": key, "report": report}).to_string());
            out.push('\n');
        }
        fs::create_dir_all(Path::new(REPORTS).parent().unwrap()).unwrap();
        fs::write(REPORTS, out).unwrap();
        return;
    }
    let expected = entries.get(&key).unwrap_or_else(|| {
        panic!("T1b has no fixture for {key}; record {REPORTS} with {RECORD}=1 on the code before the refactor")
    });
    assert_eq!(&text, expected, "T1b report {key}");
}

/// The summed sizes of the regular files `files` in `top`, each of which the
/// script must have written, plus those of `optional` that exist: what a
/// test whose script writes host-dependent bytes checks `bytes_written`
/// against (T1b masks it).
fn written(top: &Path, files: &[&str], optional: &[&str]) -> u64 {
    let size = |name: &str| {
        let meta = fs::symlink_metadata(top.join(name))
            .unwrap_or_else(|e| panic!("the script did not write {name}: {e}"));
        assert!(meta.is_file(), "{name} is not a regular file");
        meta.len()
    };
    let required: u64 = files.iter().map(|name| size(name)).sum();
    let present: u64 = optional
        .iter()
        .filter(|name| fs::symlink_metadata(top.join(name)).is_ok())
        .map(|name| size(name))
        .sum();
    required + present
}
fn available() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return false;
    }
    if let Err(error) = ratarmount_fuse::validate_allow_other("allow_other") {
        eprintln!("skip: {error}");
        return false;
    }
    for tool in ["fusermount3", "bash", "setsid"] {
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!("skip: {tool} unavailable");
            return false;
        }
    }
    true
}
struct Fixture {
    temp: tempfile::TempDir,
    base: PathBuf,
    top: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base.tar");
        let top = temp.path().join("top");
        let mut tar = tar::Builder::new(fs::File::create(&base).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "input", &b"base"[..]).unwrap();
        tar.finish().unwrap();
        Self { temp, base, top }
    }
    fn pid(&self) -> PathBuf {
        self.temp.path().join(".top.ratarmount-run.pid")
    }
    /// T1b: `report` against its fixture, this fixture's directory `$TMP1`
    /// and `dirs` after it, `fields` masked.
    fn check(&self, test: &str, case: &str, report: &Value, dirs: &[&Path], fields: &[&str]) {
        let mut all = vec![self.temp.path()];
        all.extend_from_slice(dirs);
        check_report(
            test,
            case,
            report,
            &Normalize {
                dirs: all,
                port: None,
                fields,
            },
        );
    }
    fn command(&self, flags: &[&str], script: &str) -> Command {
        let mut command = ratarmount();
        command
            .args(["sandbox", "run", "--base"])
            .arg(&self.base)
            .arg("--top")
            .arg(&self.top)
            .args(["--image", "busybox", "--json"])
            .args(flags)
            .args(["--", "sh", "-c", script])
            .env("RATARMOUNT_SANDBOX_RUNTIME", stub())
            .env("RATARMOUNT_STUB_STATE", self.temp.path().join("runtime"));
        command
    }
    fn run(&self, flags: &[&str], script: &str) -> Value {
        let stdout = tempfile::tempfile().unwrap();
        let mut command = self.command(flags, script);
        let mut child = command.stdout(stdout.try_clone().unwrap()).spawn().unwrap();
        let status = wait(&mut child);
        assert!(status.success(), "harness failed: {status}");
        use std::io::{Read, Seek};
        let mut stdout = stdout;
        stdout.rewind().unwrap();
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            !self.pid().exists(),
            "recovery record survived successful cleanup"
        );
        report
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(bytes) = fs::read(self.pid()) {
            if let Ok(record) = serde_json::from_slice::<Value>(&bytes) {
                for verb in ["kill", "rm"] {
                    let _ = Command::new(stub())
                        .arg(verb)
                        .arg(record["container"].as_str().unwrap_or_default())
                        .env("RATARMOUNT_STUB_STATE", self.temp.path().join("runtime"))
                        .status();
                }
                let _ = Command::new("fusermount3")
                    .arg("-uz")
                    .arg(record["mountpoint"].as_str().unwrap_or_default())
                    .status();
            }
        }
    }
}
fn wait(child: &mut Child) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("sandbox test timed out");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn wait_for(path: &Path, child: &mut Child) {
    wait_until(path, child, |path| path.exists());
}
/// Waits until `path` holds `content`: a run killed only after its write
/// completed leaves the same top every time (T1b), where `wait_for` races
/// the write that follows the file's creation.
fn wait_for_content(path: &Path, content: &[u8], child: &mut Child) {
    wait_until(path, child, |path| {
        fs::read(path).is_ok_and(|bytes| bytes == content)
    });
}
fn wait_until(path: &Path, child: &mut Child, done: impl Fn(&Path) -> bool) {
    let start = Instant::now();
    while !done(path) {
        assert!(
            child.try_wait().unwrap().is_none(),
            "sandbox exited before marker"
        );
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "marker timed out"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn assert_unmounted(path: &str) {
    let info = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(!info
        .lines()
        .any(|line| line.split_whitespace().nth(4) == Some(path)));
}

#[test]
fn regression_run_stub_executes_in_bind_and_preserves_environment() {
    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("skip: setsid unavailable");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new("bash")
        .arg(stub())
        .args(["run", "--rm", "--name", "test", "-v"])
        .arg(format!("{}:/repo", temp.path().display()))
        .args([
            "-w",
            "/repo",
            "--network",
            "none",
            "--user",
            "1:2",
            "-e",
            "LITERAL=a b;$x",
            "busybox",
            "sh",
            "-c",
            "printf '%s' \"$LITERAL\" > output; exit 7",
        ])
        .env("RATARMOUNT_STUB_STATE", temp.path().join("state"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(fs::read(temp.path().join("output")).unwrap(), b"a b;$x");
}

#[test]
fn regression_run_fuse_writes_manifest_seal_pack_and_journal() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let bundle = fixture.temp.path().join("bundle.tar.zst");
    let report = fixture.run(
        &["--seal", "--pack", bundle.to_str().unwrap(), "--journal"],
        "printf one > one; printf two > two; echo command-stdout; exit 7",
    );
    assert_eq!(report["exit_code"], 7);
    assert_eq!(report["patch_hash"]["files"], 2);
    assert_eq!(report["patch_hash"]["sealed"], true);
    assert_eq!(report["bytes_written"], 6);
    assert!(Path::new(report["manifest_path"].as_str().unwrap()).exists());
    assert!(Path::new(report["journal_summary"]["path"].as_str().unwrap()).exists());
    assert!(bundle.exists());
    // The script's opens drive the journal counts; their exact values
    // depend on the host's shell (T1b).
    fixture.check(
        "writes_manifest_seal_pack_and_journal",
        "report",
        &report,
        &[],
        &[
            "journal_summary.files_read",
            "journal_summary.files_read_then_written",
            "journal_summary.files_written_blind",
        ],
    );
}

#[test]
fn regression_run_fuse_timeout_unmounts() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let report = fixture.run(&["--timeout", "1"], "pwd > mountpath; sleep 60");
    assert_eq!(report["exit_code"], 124);
    assert_eq!(report["timed_out"], true);
    assert_unmounted(
        fs::read_to_string(fixture.top.join("mountpath"))
            .unwrap()
            .trim(),
    );
    // `pwd` writes a host path into the top (T1b): checked by measurement.
    assert_eq!(
        report["bytes_written"],
        written(&fixture.top, &["mountpath"], &[])
    );
    fixture.check(
        "timeout_unmounts",
        "report",
        &report,
        &[],
        &["bytes_written", "patch_hash.patch"],
    );
}

#[test]
fn regression_run_fuse_sigkill_next_run_recovers_stale_mount() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let mut child = fixture
        .command(&[], "echo ready > ready; sleep 60")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_content(&fixture.top.join("ready"), b"ready\n", &mut child);
    let record: Value = serde_json::from_slice(&fs::read(fixture.pid()).unwrap()).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(fixture.pid().exists());
    let report = fixture.run(&[], "echo recovered > recovered");
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["patch_hash"]["files"], 2);
    assert_unmounted(record["mountpoint"].as_str().unwrap());
    fixture.check("sigkill_next_run_recovers", "report", &report, &[], &[]);
}

#[test]
fn regression_run_fuse_signals_report_interrupted_and_unmount() {
    use std::os::unix::process::CommandExt;
    if !available() {
        return;
    }
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let fixture = Fixture::new();
        let output = fixture.temp.path().join("report.json");
        let mut child = fixture
            .command(&[], "pwd > mountpath; echo ready > ready; sleep 60")
            .process_group(0)
            .stdout(fs::File::create(&output).unwrap())
            .spawn()
            .unwrap();
        wait_for(&fixture.top.join("ready"), &mut child);
        // Like a terminal interrupt, signal the supervisor's whole group.
        unsafe {
            libc::kill(-(child.id() as i32), signal);
        }
        assert!(wait(&mut child).success());
        let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(report["interrupted"], true);
        assert_eq!(report["exit_code"], 128 + signal);
        assert_unmounted(
            fs::read_to_string(fixture.top.join("mountpath"))
                .unwrap()
                .trim(),
        );
        // `pwd` writes a host path into the top (T1b): checked by measurement.
        assert_eq!(
            report["bytes_written"],
            written(&fixture.top, &["mountpath", "ready"], &[])
        );
        fixture.check(
            "signals_report_interrupted",
            &format!("signal {signal}"),
            &report,
            &[],
            &["bytes_written", "patch_hash.patch"],
        );
    }
}

#[test]
fn regression_run_fuse_readonly_allow_denials_counted() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let report = fixture.run(
        &[
            "--readonly",
            "input",
            "--readonly",
            "allowed",
            "--allow",
            "allowed",
            "--journal",
        ],
        "echo denied > input; echo allowed > allowed",
    );
    assert_eq!(report["exit_code"], 0);
    assert!(report["erofs_denied"].as_u64().unwrap() > 0);
    assert_eq!(report["patch_hash"]["files"], 1);
    // The script drives the denial and journal counts, which depend on how
    // the host's shell and kernel issue opens (T1b).
    fixture.check(
        "readonly_allow_denials_counted",
        "report",
        &report,
        &[],
        &[
            "erofs_denied",
            "journal_summary.files_read",
            "journal_summary.files_read_then_written",
            "journal_summary.files_written_blind",
        ],
    );
}

#[test]
fn regression_run_fuse_tmpfs_persists_top_after_unmount() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let report = fixture.run(
        &["--tmpfs", "--seal"],
        "echo payload > output; ln -s input link; chmod 751 output",
    );
    assert_eq!(report["patch_hash"]["files"], 2);
    assert_eq!(report["patch_hash"]["sealed"], true);
    assert_eq!(
        fs::read_link(fixture.top.join("link")).unwrap(),
        Path::new("input")
    );
    fixture.check("tmpfs_persists_top", "report", &report, &[], &[]);
}

#[test]
fn regression_run_real_docker_opt_in() {
    if std::env::var("RATARMOUNT_TEST_DOCKER").as_deref() != Ok("1") {
        eprintln!("skip: set RATARMOUNT_TEST_DOCKER=1 for real busybox Docker test");
        return;
    }
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let mut command = fixture.command(&["--runtime", "docker"], "echo container > output");
    command.env_remove("RATARMOUNT_SANDBOX_RUNTIME");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["patch_hash"]["files"], 1);
}

#[test]
fn regression_run_harness_error_is_single_json_and_exit_two() {
    let fixture = Fixture::new();
    let output = fixture
        .command(&["--bind", "relative"], "exit 0")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["error"].as_str().unwrap().contains("--bind"));
    assert_eq!(report["interrupted"], false);
    assert!(!fixture.pid().exists());
    fixture.check("harness_error_single_json", "error", &report, &[], &[]);
}

#[test]
fn regression_run_stub_kill_removes_sleeping_process_group() {
    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("skip: setsid unavailable");
        return;
    }
    // Regression: each verb must stop a fresh live group; kill removes the
    // state file, so rm after kill would exercise only an absent record.
    for verb in ["kill", "rm"] {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let mut child = Command::new("bash")
            .arg(stub())
            .args(["run", "--rm", "--name", "test", "-v"])
            .arg(format!("{}:/repo", temp.path().display()))
            .args(["busybox", "sleep", "60"])
            .env("RATARMOUNT_STUB_STATE", &state)
            .spawn()
            .unwrap();
        wait_for(&state.join("test"), &mut child);
        // Wait for setsid to create the process group, not just the PID file.
        let pid: i32 = fs::read_to_string(state.join("test"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let start = Instant::now();
        while unsafe { libc::getpgid(pid) } != pid {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(Command::new("bash")
            .arg(stub())
            .args([verb, "test"])
            .env("RATARMOUNT_STUB_STATE", &state)
            .status()
            .unwrap()
            .success());
        assert!(!wait(&mut child).success());
        assert!(!state.join("test").exists());
    }
}

/// Regression: the stub runtime's `kill`/`rm` sent SIGKILL to the process group its state file
/// named without checking that the recorded leader still ran, so a stale file whose pid was
/// reused could kill an unrelated group. A group whose leader has another start time (or a
/// record without one) is left alone, and the stale file is still removed.
#[test]
fn regression_run_stub_kill_skips_reused_pid() {
    use std::os::unix::process::CommandExt;
    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("skip: setsid unavailable");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    fs::create_dir(&state).unwrap();
    // A live group led by the recorded pid, but not the process the record describes.
    let mut unrelated = Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .unwrap();
    for record in [
        format!("{} 0\n", unrelated.id()),
        format!("{}\n", unrelated.id()),
    ] {
        for verb in ["kill", "rm"] {
            fs::write(state.join("test"), &record).unwrap();
            assert!(Command::new("bash")
                .arg(stub())
                .args([verb, "test"])
                .env("RATARMOUNT_STUB_STATE", &state)
                .status()
                .unwrap()
                .success());
            assert!(!state.join("test").exists(), "{verb} kept {record:?}");
        }
    }
    let alive = unrelated.try_wait().unwrap().is_none();
    let _ = unrelated.kill();
    let _ = unrelated.wait();
    assert!(
        alive,
        "the stub signalled a group its state file does not describe"
    );
}

/// Regression: `/proc/PID/stat` embeds `comm` between parentheses; a newline in
/// `comm` made `read -r` truncate the record so `start_time` returned empty and
/// both `kill` and `rm` skipped signalling while still deleting the state file.
#[test]
fn regression_run_stub_kill_signals_leader_with_newline_in_comm() {
    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("skip: setsid unavailable");
        return;
    }
    if Command::new("python3").arg("-V").output().is_err() {
        eprintln!("skip: python3 unavailable");
        return;
    }
    for verb in ["kill", "rm"] {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        // Child sets its own comm (embedded newline via prctl) then sleeps under
        // the same PID the stub recorded, so start_time must parse a multi-line
        // /proc/PID/stat.
        let mut child = Command::new("bash")
            .arg(stub())
            .args(["run", "--rm", "--name", "test", "-v"])
            .arg(format!("{}:/repo", temp.path().display()))
            .args([
                "busybox",
                "python3",
                "-c",
                "import ctypes,time; ctypes.CDLL(None, use_errno=True).prctl(15, b'line\\nbreak', 0, 0, 0); time.sleep(60)",
            ])
            .env("RATARMOUNT_STUB_STATE", &state)
            .spawn()
            .unwrap();
        wait_for(&state.join("test"), &mut child);
        let pid: i32 = fs::read_to_string(state.join("test"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let start = Instant::now();
        while unsafe { libc::getpgid(pid) } != pid {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        // /proc/PID/comm always ends with a newline when read; wait until the
        // name itself embeds one (multi-line /proc/PID/stat before the last ')').
        let start = Instant::now();
        loop {
            let stat = fs::read(format!("/proc/{pid}/stat")).unwrap_or_default();
            let has_embedded = match (
                stat.iter().position(|&b| b == b'('),
                stat.iter().rposition(|&b| b == b')'),
            ) {
                (Some(a), Some(b)) if b > a => stat[a..b].contains(&b'\n'),
                _ => false,
            };
            if has_embedded {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "leader never took a newline-bearing comm; stat={stat:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(Command::new("bash")
            .arg(stub())
            .args([verb, "test"])
            .env("RATARMOUNT_STUB_STATE", &state)
            .status()
            .unwrap()
            .success());
        assert!(!wait(&mut child).success(), "{verb} left the group running");
        assert!(!state.join("test").exists());
    }
}

/// Regression: `sandbox run --top` inside a directory `--base` would change
/// the base's identity; the CLI refuses before mounting anything.
#[test]
fn regression_run_refuses_top_inside_directory_base() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), b"one").unwrap();
    let top = base.join("top");
    let output = ratarmount()
        .args(["sandbox", "run", "--base"])
        .arg(&base)
        .arg("--top")
        .arg(&top)
        .args(["--image", "busybox", "--", "true"])
        .env("RATARMOUNT_SANDBOX_RUNTIME", stub())
        .env("RATARMOUNT_STUB_STATE", temp.path().join("runtime"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("--top must be outside --base"), "{stderr}");
    assert!(!top.exists(), "nothing was created under the base");
    assert_eq!(fs::read_dir(&base).unwrap().count(), 1);
}

/// Regression: `sandbox run` had no `--base-digest`, so a directory or archive
/// base was always re-measured per attempt. The supplied value is recorded.
#[test]
fn regression_run_base_digest_recorded() {
    use sha2::{Digest, Sha256};
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let digest = format!(
        "sha256:{}",
        Sha256::digest(fs::read(&fixture.base).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let report = fixture.run(&["--seal", "--base-digest", &digest], "printf x > out");
    assert_eq!(report["patch_hash"]["base"], digest.as_str());
    fixture.check("base_digest_recorded", "report", &report, &[], &[]);
    let home = fixture.temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "info", "--json"])
        .arg(&fixture.top)
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let info: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["base_digest"], digest.as_str());
    assert_eq!(info["base_digest_source"], "supplied");
    assert_eq!(info["base_digest_kind"], "strong");
}

#[path = "support/http_tar.rs"]
mod http_tar;

fn assert_no_secrets(text: &str, what: &str) {
    for secret in ["s3cr3t", "deadbeef"] {
        assert!(!text.contains(secret), "{what} leaked {secret}: {text}");
    }
}

/// Regression: `sandbox run --base URL` put the credentialed URL in the mount
/// error text and JSON report.
#[test]
fn regression_run_credentialed_base_url_is_redacted_in_failure() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let command = fixture.command(&[], "exit 0");
    let url = "http://user:s3cr3t@127.0.0.1:1/b.tar?X-Amz-Signature=deadbeef";
    let args: Vec<_> = command
        .get_args()
        .map(|a| a.to_os_string())
        .map(|a| {
            if a == fixture.base.as_os_str() {
                url.into()
            } else {
                a
            }
        })
        .collect();
    let mut command = ratarmount();
    command
        .args(args)
        .env("RATARMOUNT_SANDBOX_RUNTIME", stub())
        .env("RATARMOUNT_STUB_STATE", fixture.temp.path().join("runtime"));
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert_no_secrets(&String::from_utf8_lossy(&output.stdout), "stdout");
    assert_no_secrets(&String::from_utf8_lossy(&output.stderr), "stderr");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    fixture.check("credentialed_url_failure", "error", &report, &[], &[]);
}

/// An HTTP stub that answers every request with `403 Forbidden`.
fn serve_forbidden() -> u16 {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut socket) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let _ = socket.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    port
}

/// Regression: a `webdav://host/f?token=SECRET` base is rewritten to an HTTP
/// URL before the request, so the 403 error text named the rewritten URL and
/// the exact-string replacement of the original base missed the token.
#[test]
fn regression_run_transformed_url_in_error_is_redacted() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let port = serve_forbidden();
    for scheme in ["webdav", "http"] {
        let url = format!("{scheme}://user:s3cr3t@127.0.0.1:{port}/f.tar?token=deadbeef");
        let mut command = ratarmount();
        command
            .args(["sandbox", "run", "--base", &url, "--top"])
            .arg(fixture.temp.path().join(format!("top-{scheme}")))
            .args(["--image", "busybox", "--json", "--", "true"])
            .env("RATARMOUNT_SANDBOX_RUNTIME", stub())
            .env("RATARMOUNT_STUB_STATE", fixture.temp.path().join("runtime"))
            .env("HOME", fixture.temp.path().join("home"))
            .env("XDG_CACHE_HOME", fixture.temp.path().join("home/.cache"));
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{scheme}: {stdout}\n{stderr}");
        assert!(
            stdout.contains("403") || stderr.contains("403"),
            "{scheme}: {stdout}\n{stderr}"
        );
        assert_no_secrets(&stdout, "stdout");
        assert_no_secrets(&stderr, "stderr");
        check_report(
            "transformed_url_error",
            scheme,
            &serde_json::from_str(&stdout).unwrap(),
            &Normalize {
                dirs: vec![fixture.temp.path()],
                port: Some(port.to_string()),
                fields: &[],
            },
        );
    }
}

/// Regression: a successful `sandbox run` over a credentialed URL base printed
/// the secrets in mount progress, the report or the overlay it left behind.
#[test]
fn regression_run_credentialed_base_url_is_redacted_on_success() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let port = http_tar::serve_tar_stub();
    let port = port.rsplit(':').next().unwrap().to_owned();
    let url = format!("http://user:s3cr3t@127.0.0.1:{port}/b.tar?X-Amz-Signature=deadbeef");
    let mut command = ratarmount();
    command
        .args(["sandbox", "run", "--base", &url, "--top"])
        .arg(&fixture.top)
        .args([
            "--image",
            "busybox",
            "--json",
            "--seal",
            "--",
            "sh",
            "-c",
            "printf x > out",
        ])
        .env("RATARMOUNT_SANDBOX_RUNTIME", stub())
        .env("RATARMOUNT_STUB_STATE", fixture.temp.path().join("runtime"))
        .env("HOME", fixture.temp.path().join("home"))
        .env("XDG_CACHE_HOME", fixture.temp.path().join("home/.cache"));
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert_no_secrets(&stdout, "stdout");
    assert_no_secrets(&stderr, "stderr");
    let meta = ratarmount_compositing::OverlayMeta::read(&fixture.top)
        .unwrap()
        .unwrap();
    for (key, value) in meta.values() {
        assert_no_secrets(value, key);
    }
    // A remote base's weak digest hashes its (redacted) URL, which holds the
    // stub's ephemeral port, and the stack digest covers it (T1b): both are
    // checked against what the top recorded.
    let report: Value = serde_json::from_str(&stdout).unwrap();
    let base = meta.known_base_digest();
    assert!(
        base.is_some_and(|base| base.starts_with("weak:")),
        "{report}"
    );
    assert_eq!(report["patch_hash"]["base"], json!(base), "{report}");
    assert_eq!(
        report["patch_hash"]["stack"],
        json!(meta.stack_digest()),
        "{report}"
    );
    check_report(
        "credentialed_url_success",
        "report",
        &report,
        &Normalize {
            dirs: vec![fixture.temp.path()],
            port: Some(port),
            fields: &["patch_hash.base", "patch_hash.stack"],
        },
    );
}

/// Regression: the signed URL expires while the command runs, so `finish()`
/// reopening the base fails with an error naming the URL; the original error
/// reached `main` and stderr unredacted (only the JSON was sanitized).
#[test]
fn regression_run_finalization_error_is_redacted() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let forbid = fixture.temp.path().join("forbid");
    let port = http_tar::serve_tar_stub_forbidding(Some(forbid.clone()));
    let port = port.rsplit(':').next().unwrap().to_owned();
    let url = format!("http://user:s3cr3t@127.0.0.1:{port}/b.tar?X-Amz-Signature=deadbeef");
    let mut command = ratarmount();
    command
        .args(["sandbox", "run", "--base", &url, "--top"])
        .arg(&fixture.top)
        .args(["--image", "busybox", "--json", "--", "sh", "-c"])
        .arg(format!("printf x > out; touch {}", forbid.display()))
        .env("RATARMOUNT_SANDBOX_RUNTIME", stub())
        .env("RATARMOUNT_STUB_STATE", fixture.temp.path().join("runtime"))
        .env("HOME", fixture.temp.path().join("home"))
        .env("XDG_CACHE_HOME", fixture.temp.path().join("home/.cache"));
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("403") || stderr.contains("403"),
        "failure did not come from the reopened base: {stdout}\n{stderr}"
    );
    assert_no_secrets(&stdout, "stdout");
    assert_no_secrets(&stderr, "stderr");
    check_report(
        "finalization_error",
        "error",
        &serde_json::from_str(&stdout).unwrap(),
        &Normalize {
            dirs: vec![fixture.temp.path()],
            port: Some(port),
            fields: &[],
        },
    );
}

/// Regression (Keystone (a)): the in-FS `/.ratarmount-control/` (host pid,
/// memory stats, an `unmount` file) was bound into the container and visible
/// to the graded mount. The counters now come over a private socket.
#[test]
fn regression_run_container_tree_has_no_control_dir() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let private = tempfile::Builder::new()
        .prefix("rrs-run-tmp-")
        .tempdir_in("/tmp")
        .unwrap();
    let mut command = fixture.command(
        &["--readonly", "input"],
        "ls -a . > seen.txt; ls .ratarmount-control/status > status.txt 2>&1; \
         cat .ratarmount-control/pid > pid.txt 2>/dev/null; echo denied > input; true",
    );
    let output = command.env("TMPDIR", private.path()).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let seen = fs::read_to_string(fixture.top.join("seen.txt")).unwrap();
    assert!(!seen.contains(".ratarmount-control"), "{seen}");
    assert!(!seen.contains("ratarmount-control-"), "{seen}");
    let status = fs::read_to_string(fixture.top.join("status.txt")).unwrap();
    assert!(status.contains("No such file"), "{status}");
    assert!(
        !fixture.top.join("pid.txt").exists()
            || fs::read(fixture.top.join("pid.txt")).unwrap().is_empty()
    );
    // The counter is read over the socket, not the in-FS status file.
    assert!(report["erofs_denied"].as_u64().unwrap() > 0, "{report}");
    let left: Vec<_> = fs::read_dir(private.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !left.iter().any(|n| n.starts_with("ratarmount-run-")),
        "run dir leaked: {left:?}"
    );
    // The host `ls` writes its own error text into the top, and the script
    // drives the denial count (T1b): bytes checked by measurement.
    assert_eq!(
        report["bytes_written"],
        written(&fixture.top, &["seen.txt", "status.txt"], &["pid.txt"])
    );
    fixture.check(
        "container_tree_has_no_control_dir",
        "report",
        &report,
        &[private.path()],
        &["bytes_written", "patch_hash.patch", "erofs_denied"],
    );
}

/// Regression (J): the mountpoint used to be a directory made directly in the
/// shared temporary directory, so with `allow_other` other local users could
/// enter the mounted tree. It now sits inside a private 0700 parent that also
/// holds the control socket, and the whole parent is removed afterwards.
#[test]
fn regression_run_mountpoint_parent_is_private_0700() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    // A world-writable sticky directory stands in for a shared `/tmp`.
    let shared = tempfile::Builder::new()
        .prefix("rrs-j-tmp-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(shared.path(), fs::Permissions::from_mode(0o1777)).unwrap();
    let mut command = fixture.command(
        &[],
        "stat -c '%a %u' .. > parent.txt; (cd .. && pwd -P) > parent-path.txt; \
         ls -a .. > parent-ls.txt; pwd -P > mount-path.txt",
    );
    let output = command.env("TMPDIR", shared.path()).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // A user ID, real paths and the control socket's PID go into the top
    // (T1b): bytes checked by measurement.
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["bytes_written"],
        written(
            &fixture.top,
            &[
                "parent.txt",
                "parent-path.txt",
                "parent-ls.txt",
                "mount-path.txt"
            ],
            &[]
        )
    );
    fixture.check(
        "mountpoint_parent_private",
        "report",
        &report,
        &[shared.path()],
        &["bytes_written", "patch_hash.patch"],
    );
    let parent = fs::read_to_string(fixture.top.join("parent.txt")).unwrap();
    let (mode, uid) = parent.trim().split_once(' ').unwrap();
    assert_eq!(mode, "700", "mountpoint parent mode: {parent}");
    assert_eq!(uid, unsafe { libc::geteuid() }.to_string());
    let parent_path = fs::read_to_string(fixture.top.join("parent-path.txt")).unwrap();
    let parent_name = Path::new(parent_path.trim())
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(parent_name.starts_with("ratarmount-run-"), "{parent_path}");
    let mount_path = fs::read_to_string(fixture.top.join("mount-path.txt")).unwrap();
    assert_eq!(
        Path::new(mount_path.trim()),
        Path::new(parent_path.trim()).join("mnt")
    );
    // The control socket lives in the private parent, beside the mount.
    let listing = fs::read_to_string(fixture.top.join("parent-ls.txt")).unwrap();
    assert!(listing.contains("ratarmount-control-"), "{listing}");
    // Nothing is left in the shared directory afterwards.
    let left: Vec<_> = fs::read_dir(shared.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(left.is_empty(), "left behind: {left:?}");
    assert!(fs::metadata(shared.path()).unwrap().mode() & 0o1000 != 0);
}

fn names_in(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

/// Regression (F): the mount child's `ratarmount-control-<pid>.sock` stayed in
/// `TMPDIR` after `sandbox run` unmounted it externally. It now lives in the
/// private run directory, which is removed, and a socket another process left
/// in the same `TMPDIR` is never touched.
#[test]
fn regression_run_removes_own_control_socket_and_keeps_foreign_one() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let private = tempfile::Builder::new()
        .prefix("rrs-f-tmp-")
        .tempdir_in("/tmp")
        .unwrap();
    let foreign = private.path().join("ratarmount-control-1.sock");
    fs::write(&foreign, b"").unwrap();
    let output = fixture
        .command(&[], "echo ok > ok")
        .env("TMPDIR", private.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        names_in(private.path()),
        vec!["ratarmount-control-1.sock".to_string()]
    );
    fixture.check(
        "removes_own_control_socket",
        "report",
        &serde_json::from_slice(&output.stdout).unwrap(),
        &[private.path()],
        &[],
    );
}

/// Regression (F): after the runner is SIGKILLed, the next run's recovery also
/// removes the dead run's private directory and its socket.
#[test]
fn regression_run_sigkill_recovery_leaves_no_socket_or_run_dir() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let private = tempfile::Builder::new()
        .prefix("rrs-f2-tmp-")
        .tempdir_in("/tmp")
        .unwrap();
    let mut child = fixture
        .command(&[], "echo ready > ready; sleep 60")
        .env("TMPDIR", private.path())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_content(&fixture.top.join("ready"), b"ready\n", &mut child);
    let during = names_in(private.path());
    assert!(
        during.iter().any(|n| n.starts_with("ratarmount-run-")),
        "{during:?}"
    );
    child.kill().unwrap();
    child.wait().unwrap();
    let output = fixture
        .command(&[], "echo recovered > recovered")
        .env("TMPDIR", private.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let left = names_in(private.path());
    assert!(left.is_empty(), "left behind: {left:?}");
    fixture.check(
        "sigkill_recovery_leaves_no_socket",
        "report",
        &serde_json::from_slice(&output.stdout).unwrap(),
        &[private.path()],
        &[],
    );
}

fn recorded_argv(fixture: &Fixture) -> Vec<String> {
    let state = fixture.temp.path().join("runtime");
    let file = fs::read_dir(&state)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "argv"))
        .expect("stub recorded no argv");
    fs::read_to_string(file)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn flag_values(argv: &[String], flag: &str) -> Vec<String> {
    argv.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .collect()
}

/// Regression (I): containers ran with default capabilities, privilege
/// escalation allowed and no process limit.
#[test]
fn regression_run_container_is_hardened_by_default() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let report = fixture.run(&[], "true");
    fixture.check("container_is_hardened", "report", &report, &[], &[]);
    let argv = recorded_argv(&fixture);
    assert_eq!(flag_values(&argv, "--cap-drop"), ["ALL"], "{argv:?}");
    assert_eq!(
        flag_values(&argv, "--security-opt"),
        ["no-new-privileges"],
        "{argv:?}"
    );
    assert_eq!(flag_values(&argv, "--pids-limit"), ["4096"], "{argv:?}");
    assert!(flag_values(&argv, "--cap-add").is_empty(), "{argv:?}");
}

/// Regression (I): `--pids-limit` overrides the default and `--cap-add` adds
/// capabilities back.
#[test]
fn regression_run_pids_limit_and_cap_add_reach_the_runtime() {
    if !available() {
        return;
    }
    let fixture = Fixture::new();
    let report = fixture.run(
        &["--pids-limit", "64", "--cap-add", "NET_BIND_SERVICE"],
        "true",
    );
    fixture.check("pids_limit_and_cap_add", "report", &report, &[], &[]);
    let argv = recorded_argv(&fixture);
    assert_eq!(flag_values(&argv, "--pids-limit"), ["64"], "{argv:?}");
    assert_eq!(
        flag_values(&argv, "--cap-add"),
        ["NET_BIND_SERVICE"],
        "{argv:?}"
    );
    assert_eq!(flag_values(&argv, "--cap-drop"), ["ALL"], "{argv:?}");
}
