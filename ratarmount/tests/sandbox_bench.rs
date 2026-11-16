//! Validation and schedule CLI regressions; no FUSE, network or runtime prerequisites.

use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .arg("sandbox")
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// Regression: hidden bench leaked into parent help or lacked its explicit help contract.
#[test]
fn regression_bench_cli_hidden_and_explicit_help() {
    let parent = cli(&["--help"]);
    assert!(parent.status.success());
    assert!(!String::from_utf8_lossy(&parent.stdout).contains("bench"));
    let leaf = cli(&["bench", "--help"]);
    #[cfg(target_os = "linux")]
    {
        assert!(leaf.status.success(), "{}", stderr(&leaf));
        let help = String::from_utf8_lossy(&leaf.stdout);
        assert!(!help.contains("Choosing requires"), "{help}");
        for expected in [
            "Example:",
            "Linux",
            "Exit status:",
            "Inherited `--socket` is rejected; bench owns its supervisor.",
            "Example: ratarmount sandbox bench --manifest tasks.json --dry-run",
            "--runtime-kind",
            "every run passed (stub batches are fixtures)",
            "interrupted or incomplete batch",
            "--dry-run",
            "JSONL schedule without execution or file creation",
        ] {
            assert!(help.contains(expected), "{help}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(leaf.status.code(), Some(2));
        assert!(stderr(&leaf).contains("unrecognized subcommand 'bench'"));
    }
}

#[cfg(target_os = "linux")]
fn draft() -> serde_json::Value {
    let guide = include_str!("../../docs/sandbox-benchmarking.md");
    let json = guide
        .split("```json\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
    let template = v["tasks"][0].clone();
    for (id, role, distribution) in [
        ("text-csv-xs", "XS", "Text-CSV_XS"),
        ("moosex-getopt", "Moose consumer", "MooseX-Getopt"),
    ] {
        let mut row = template.clone();
        row["id"] = id.into();
        row["role"] = role.into();
        row["distribution"] = distribution.into();
        v["tasks"].as_array_mut().unwrap().push(row);
    }
    v
}

// Regression: bench positionals were stolen by the mount parser, or PR-C drafts needed schema widening.
#[test]
#[cfg(target_os = "linux")]
fn regression_bench_cli_no_positional_steal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks.json");
    std::fs::write(&path, serde_json::to_vec(&draft()).unwrap()).unwrap();
    let path = path.to_str().unwrap();
    for args in [
        vec!["bench", "--manifest", path, "--validate-only"],
        vec!["bench", "--validate-only", "--manifest", path],
    ] {
        let result = cli(&args);
        assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("external qualification not verified")
        );
    }
    let strict = cli(&[
        "bench",
        "--manifest",
        path,
        "--validate-only",
        "--require-pins",
    ]);
    assert_eq!(strict.status.code(), Some(2));
    assert!(stderr(&strict).starts_with("sandbox bench: unresolved pins:"));
    assert!(stderr(&strict).contains("unpinned"));
    let positional = cli(&["bench", "--manifest", path, "--validate-only", "mountpoint"]);
    assert_eq!(positional.status.code(), Some(2));
    assert!(stderr(&positional).contains("the subcommand 'mountpoint' cannot be used with:"));
    let hash = format!("sha256:{}", "a".repeat(64));
    let mut pinned = draft();
    pinned["tasks"].as_array_mut().unwrap().truncate(1);
    pinned["platforms"][0] = serde_json::json!({"id":"linux-amd64","os":"linux","architecture":"amd64","image":format!("perl@{hash}"),"toolchain_sha256":hash,"dependency_lock":{"path":"deps.lock","sha256":hash}});
    for (key, value) in serde_json::json!({"version":"9.42","cpan":{"path":"authors/id/S/SR/SRI/Mojolicious-9.42.tar.gz","sha256":hash},"git":{"repository":"https://github.com/mojolicious/mojo.git","commit":"a".repeat(40),"tree":"a".repeat(40)},"artifact":{"path":"mojo.tar.zst","sha256":hash,"tar_stream_sha256":hash},"test_inventory":{"state":"known","count":10,"sha256":hash},"backends":["native"],"platforms":[{"platform_id":"linux-amd64","candidate_jobs":[1],"supported_jobs":[1],"qualification":{"qualified":true,"reasons":[],"evidence":[{"jobs":1,"backend":"native","passed":true,"source_sha256":hash,"image":format!("perl@{hash}"),"dependency_lock_sha256":hash,"test_inventory_sha256":hash}]}}]}).as_object().unwrap() {
        pinned["tasks"][0][key] = value.clone();
    }
    std::fs::write(path, serde_json::to_vec(&pinned).unwrap()).unwrap();
    let pins = "--require-pins";
    let strict = cli(&["bench", "--manifest", path, "--validate-only", pins]);
    assert_eq!(strict.status.code(), Some(0), "{}", stderr(&strict));
}

// Regression: invalid arguments, unsafe manifest types and operational errors shared the wrong status.
#[test]
#[cfg(target_os = "linux")]
fn regression_bench_cli_invalid_arguments_exit_two() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.json");
    std::fs::write(&path, b"{}").unwrap();
    let file = path.to_str().unwrap();
    for args in [
        vec!["bench"],
        vec!["bench", "--manifest", file],
        vec!["bench", "--validate-only"],
        vec!["bench", "--manifest", file, "--validate-only"],
        vec!["bench", "--manifest", file, "--validate-only", "--dry-run"],
    ] {
        let output = cli(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        if args.contains(&"--dry-run") {
            assert!(stderr(&output).contains("cannot be used with"));
            assert!(!stderr(&output).contains("unexpected argument"));
        }
    }
    let invalid = cli(&[
        "bench",
        "--manifest",
        file,
        "--validate-only",
        "--require-pins",
    ]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(stderr(&invalid).starts_with("sandbox bench: invalid manifest:"));
    let missing = dir.path().join("does-not-exist");
    let result = cli(&[
        "bench",
        "--manifest",
        missing.to_str().unwrap(),
        "--validate-only",
    ]);
    assert_eq!(result.status.code(), Some(1));
    assert!(stderr(&result).contains("manifest-open"));
    std::fs::write(&path, serde_json::to_vec(&draft()).unwrap()).unwrap();
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    let fifo = dir.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR,
        0,
    )
    .unwrap();
    let socket = dir.path().join("socket");
    let large = dir.path().join("oversized.json");
    std::fs::write(&large, vec![b' '; 1024 * 1024 + 1]).unwrap();
    for path in [
        &link,
        &fifo,
        &large,
        dir.path(),
        std::path::Path::new("/dev/null"),
        &socket,
    ] {
        let listener =
            (path == socket).then(|| std::os::unix::net::UnixListener::bind(&socket).unwrap());
        let result = cli(&[
            "bench",
            "--manifest",
            path.to_str().unwrap(),
            "--validate-only",
        ]);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{}: {}",
            path.display(),
            stderr(&result)
        );
        // Link and socket: manifest-open; fifo, oversized, directory and /dev/null: type/size checks.
        assert!(
            stderr(&result).contains(if path == link || path == socket {
                "manifest-open"
            } else {
                "manifest must be a regular file of at most 1 MiB"
            }),
            "descriptor case {}: {}",
            path.display(),
            stderr(&result)
        );
        drop(listener);
    }
    for (mode, expected) in [("--validate-only", "validation"), ("--dry-run", "schedule")] {
        bench_report_to_full(file, mode, expected);
    }
}

#[cfg(target_os = "linux")]
fn bench_report_to_full(file: &str, mode: &str, expected: &str) {
    let report = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["sandbox", "bench", "--manifest", file, mode])
        .stdout(
            std::fs::File::options()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(report.status.code(), Some(1));
    assert!(stderr(&report).contains(&format!("bench {expected} report")));
}

// Regression: inherited sockets in either position reached manifest I/O first.
#[test]
#[cfg(target_os = "linux")]
fn regression_bench_cli_socket_rejected_before_manifest_io() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("NONEXISTENT.json");
    let path = missing.to_str().unwrap();
    for args in [
        vec![
            "--socket",
            "api.sock",
            "bench",
            "--manifest",
            path,
            "--validate-only",
        ],
        vec![
            "bench",
            "--socket",
            "api.sock",
            "--manifest",
            path,
            "--validate-only",
        ],
    ] {
        for mode in ["--validate-only", "--dry-run"] {
            let args: Vec<_> = args
                .iter()
                .map(|a| if *a == "--validate-only" { mode } else { *a })
                .collect();
            let output = cli(&args);
            assert_eq!(output.status.code(), Some(2));
            let error = stderr(&output);
            assert!(error.contains("--socket is rejected"), "{error}");
            assert!(!error.contains("manifest-open"), "{error}");
        }
    }
    assert!(!missing.exists());
}

#[cfg(target_os = "linux")]
fn bench(path: &std::path::Path, options: &str) -> Output {
    let mut args = vec!["bench", "--manifest", path.to_str().unwrap()];
    args.extend(options.split_ascii_whitespace());
    cli(&args)
}
#[cfg(target_os = "linux")]
fn schedule_rows(output: Output) -> Vec<serde_json::Value> {
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
// Regression: dry-run ignored selections, emitted prose, or created preparation/output files.
#[test]
#[cfg(target_os = "linux")]
fn regression_bench_cli_dry_run_emits_schedule_without_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks.json");
    let bytes = serde_json::to_vec(&draft()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let args = "sandbox bench --manifest tasks.json --dry-run --task mojolicious --backend native,fuse --base-form git,tar.zst-single-frame --jobs 1,2,8 --cache cold,warm --repeats 3 --seed 42 --attempts 1 --allow-oversubscription";
    let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(args.split_ascii_whitespace())
        .current_dir(dir.path())
        .output()
        .unwrap();
    let rows = schedule_rows(output);
    assert_eq!(rows.len(), 108);
    for row in &rows {
        assert_eq!(row["schema"], "rrs-perl-bench-schedule/1");
        assert_eq!(row["cell"]["task"], "mojolicious");
        assert_eq!(row["seed"], 42);
        assert_eq!(row["repeats"], 3);
        assert_eq!(row["attempts"], 1);
        assert_eq!(row["allow_oversubscription"], true);
        assert_eq!(row["oversubscribed"], row["cell"]["jobs"] == 8);
    }
    assert_eq!(rows.iter().filter(|r| r["kind"] == "measured").count(), 72);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    for option in [
        "--repeats 0",
        "--repeats 101",
        "--attempts 2",
        "--jobs 0",
        "--backend overlay2",
        "--base-form zip",
        "--cache hot",
        "--task missing",
    ] {
        let result = bench(&path, &format!("--dry-run {option}"));
        assert_eq!(
            result.status.code(),
            Some(2),
            "{option}: {}",
            stderr(&result)
        );
        assert!(result.stdout.is_empty());
        assert!(option != "--repeats 101" || stderr(&result).contains("1..=100"));
    }
    for option in [
        "--task mojolicious",
        "--backend native",
        "--base-form git",
        "--jobs 1",
        "--cache warm",
        "--repeats 2",
        "--seed 2",
        "--attempts 1",
        "--allow-oversubscription",
    ] {
        let result = bench(&path, &format!("--validate-only {option}"));
        assert_eq!(
            result.status.code(),
            Some(2),
            "{option}: {}",
            stderr(&result)
        );
        assert!(stderr(&result).contains("cannot be used with"));
    }
    // Regression: the total-entry cap must refuse via selection/exit 2 before a full schedule is built.
    let mut large = draft();
    let template = large["tasks"][0].clone();
    large["tasks"] = serde_json::Value::Array(
        (0..124)
            .map(|i| {
                let mut task = template.clone();
                task["id"] = format!("task-{i}").into();
                task
            })
            .collect(),
    );
    std::fs::write(&path, serde_json::to_vec(&large).unwrap()).unwrap();
    let capped = bench(&path, "--dry-run --repeats 100");
    assert_eq!(capped.status.code(), Some(2));
    assert!(stderr(&capped).starts_with("sandbox bench: selection:"));
    assert!(stderr(&capped).contains("100000 total-entry cap"));
    assert!(capped.stdout.is_empty());
    large["tasks"].as_array_mut().unwrap().pop();
    std::fs::write(&path, serde_json::to_vec(&large).unwrap()).unwrap();
    let admitted = schedule_rows(bench(&path, "--dry-run --repeats 100"));
    assert_eq!(admitted.len(), 99_876);
}

// Regression: draft schedules asserted runnable qualification or skipped B2 validation/statuses.
#[test]
#[cfg(target_os = "linux")]
fn regression_bench_cli_draft_schedule_is_not_runnable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks.json");
    let missing = bench(&path, "--dry-run");
    assert_eq!(missing.status.code(), Some(1));
    assert!(stderr(&missing).contains("manifest-open"));
    std::fs::write(&path, b"{}").unwrap();
    let bad = bench(&path, "--dry-run --task missing");
    assert_eq!(bad.status.code(), Some(2));
    assert!(stderr(&bad).starts_with("sandbox bench: invalid manifest:"));
    std::fs::write(&path, serde_json::to_vec(&draft()).unwrap()).unwrap();
    let rows = schedule_rows(bench(&path, "--dry-run"));
    assert_eq!(rows.len(), 156);
    for row in rows {
        assert_eq!(row["qualified"], false);
        assert_eq!(row["execution_available"], false);
        assert_eq!(row["runnable"], false);
        let reasons = row["reasons"].as_array().unwrap();
        assert!(reasons
            .iter()
            .any(|r| r == "Pins and offline qualification unresolved"));
        assert!(reasons.iter().any(|r| {
            r == "execution unavailable: selection or qualification unsupported by native lifecycle"
        }));
    }
    let strict = bench(&path, "--dry-run --require-pins");
    assert_eq!(strict.status.code(), Some(2));
    assert!(stderr(&strict).starts_with("sandbox bench: unresolved pins:"));
    assert!(strict.stdout.is_empty());
}
// Regression: bench dispatch changed sandbox run's status 2 or legacy success/error paths.
#[test]
fn regression_bench_cli_legacy_exit_statuses_preserved() {
    let failed = cli(&["list"]);
    assert_eq!(failed.status.code(), Some(1));
    assert!(stderr(&failed).contains("sandbox: --socket PATH is required"));
    #[cfg(target_os = "linux")]
    {
        use std::io::{BufRead, BufReader, Write};
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("missing.tar");
        let run = cli(&[
            "run",
            "--base",
            base.to_str().unwrap(),
            "--top",
            dir.path().to_str().unwrap(),
            "--image",
            "busybox",
            "--bind",
            "relative",
            "--",
            "true",
        ]);
        assert_eq!(run.status.code(), Some(2));
        assert!(stderr(&run).contains("sandbox: --bind must be"));
        assert!(!base.exists());
        let path = dir.path().join("api.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            for ok in [true, false] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = String::new();
                BufReader::new(&mut stream).read_line(&mut request).unwrap();
                assert!(request.contains("list"), "{request}");
                writeln!(stream, "{{\"version\":1,\"ok\":{ok}}}").unwrap();
            }
        });
        for code in [0, 1] {
            let output = cli(&["--socket", path.to_str().unwrap(), "list"]);
            assert_eq!(output.status.code(), Some(code), "{}", stderr(&output));
        }
        server.join().unwrap();
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;
    use std::process::Stdio;
    struct Fixture {
        dir: tempfile::TempDir,
        value: Value,
        path: PathBuf,
        runtime: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_directories(tempfile::tempdir().unwrap(), 0)
        }
        fn with_directories(dir: tempfile::TempDir, count: usize) -> Self {
            let mut tar = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_ustar();
            header.set_size(6);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "source.txt", &b"source"[..])
                .unwrap();
            for (name, mode) in [("archive-zero", 0o000), ("archive-write", 0o300)] {
                let mut header = tar::Header::new_ustar();
                header.set_mode(mode);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();
                tar.append_data(&mut header, name, &b""[..]).unwrap();
                let mut header = tar::Header::new_ustar();
                header.set_mode(0o600);
                header.set_size(1);
                header.set_cksum();
                tar.append_data(&mut header, format!("{name}/child"), &b"x"[..])
                    .unwrap();
            }
            for index in 0..count {
                let mut header = tar::Header::new_ustar();
                header.set_mode(0o755);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();
                tar.append_data(&mut header, format!("directory-{index}"), &b""[..])
                    .unwrap();
            }
            let tar = tar.into_inner().unwrap();
            let archive = zstd::encode_all(tar.as_slice(), 1).unwrap();
            let hash = |bytes: &[u8]| format!("sha256:{:x}", Sha256::digest(bytes));
            let pin = format!("sha256:{}", "a".repeat(64));
            let image = format!("perl@{pin}");
            let mut value = draft();
            value["tasks"].as_array_mut().unwrap().truncate(1);
            value["platforms"][0] = json!({"id":"linux-amd64","os":"linux","architecture":if std::env::consts::ARCH == "aarch64" {"arm64"} else {"amd64"},"image":image,"toolchain_sha256":pin,"dependency_lock":{"path":"deps.lock","sha256":pin}});
            let task = &mut value["tasks"][0];
            task["version"] = json!("9.42");
            task["cpan"] =
                json!({"path":"authors/id/S/SR/SRI/Mojolicious-9.42.tar.gz","sha256":pin});
            task["git"] = json!({"repository":"https://github.com/mojolicious/mojo.git","commit":"a".repeat(40),"tree":"a".repeat(40)});
            task["artifact"] = json!({"path":"source.tar.zst","sha256":hash(&archive),"tar_stream_sha256":hash(&tar)});
            task["test_inventory"] = json!({"state":"known","count":1,"sha256":pin});
            task["backends"] = json!(["native"]);
            task["platforms"] = json!([{"platform_id":"linux-amd64","candidate_jobs":[1],"supported_jobs":[1],"qualification":{"qualified":true,"reasons":[],"evidence":[{"jobs":1,"backend":"native","passed":true,"source_sha256":hash(&tar),"image":image,"dependency_lock_sha256":pin,"test_inventory_sha256":pin}]}}]);
            for phase in ["configure", "build", "test"] {
                task["commands"][phase] = json!({"argv":[phase,"{jobs}"],"timeout_seconds":1});
            }
            std::fs::write(dir.path().join("source.tar.zst"), archive).unwrap();
            std::fs::create_dir(dir.path().join("work")).unwrap();
            std::fs::create_dir(dir.path().join("state")).unwrap();
            let path = dir.path().join("tasks.json");
            let runtime = PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test-harness/sandbox-bench/runtime.sh"
            ));
            let fixture = Self {
                dir,
                value,
                path,
                runtime,
            };
            fixture.save();
            fixture
        }
        fn save(&self) {
            std::fs::write(&self.path, serde_json::to_vec(&self.value).unwrap()).unwrap();
        }
        fn command(&self) -> Command {
            self.command_at(
                &self.dir.path().join("out"),
                Some(&self.dir.path().join("work")),
                "native",
                "warm",
            )
        }
        fn command_at(
            &self,
            out: &std::path::Path,
            work: Option<&std::path::Path>,
            backend: &str,
            cache: &str,
        ) -> Command {
            self.command_at_kind(out, work, backend, cache, Some("stub"))
        }
        fn command_at_kind(
            &self,
            out: &std::path::Path,
            work: Option<&std::path::Path>,
            backend: &str,
            cache: &str,
            kind: Option<&str>,
        ) -> Command {
            let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
            command
                .args(["sandbox", "bench", "--manifest"])
                .arg(&self.path)
                .arg("--out")
                .arg(out)
                .arg("--runtime")
                .arg(&self.runtime)
                .args([
                    "--allow-high-load",
                    "--backend",
                    backend,
                    "--base-form",
                    "tar.zst-single-frame",
                    "--cache",
                    cache,
                    "--repeats",
                    "1",
                ])
                .env("BENCH_STUB_STATE", self.dir.path().join("state"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(kind) = kind {
                command.args(["--runtime-kind", kind]);
            }
            if let Some(work) = work {
                command.arg("--work-root").arg(work);
            }
            command
        }
        fn fault(&self, fault: &str) {
            std::fs::write(self.dir.path().join("state").join(fault), "").unwrap();
        }
        fn rows(&self) -> Vec<Value> {
            std::fs::read_to_string(self.dir.path().join("out/runs.jsonl"))
                .unwrap()
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect()
        }
        fn executed(&self) -> Vec<Value> {
            self.rows()
                .into_iter()
                .filter(|r| r["outcome"] != "blocked")
                .collect()
        }
        fn read(&self, name: &str) -> Value {
            serde_json::from_slice(&std::fs::read(self.dir.path().join("out").join(name)).unwrap())
                .unwrap()
        }
        fn kind(&self, kind: Option<&str>) -> Command {
            self.command_at_kind(
                &self.dir.path().join("out"),
                Some(&self.dir.path().join("work")),
                "native",
                "warm",
                kind,
            )
        }
        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("state/calls")).unwrap_or_default()
        }
        fn no_containers(&self) {
            assert!(std::fs::read_dir(self.dir.path().join("state"))
                .unwrap()
                .all(|e| !e
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with("container.")));
        }
        fn remove_preserved_tree(&self, row: &Value) {
            use std::os::unix::fs::PermissionsExt;
            let tree = std::path::Path::new(row["tree"].as_str().unwrap());
            for name in ["archive-zero", "archive-write"] {
                let child = tree.join(name);
                if child.exists() {
                    std::fs::set_permissions(child, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
            }
            let scratch = tree.parent().unwrap();
            std::fs::remove_dir_all(scratch).unwrap();
            assert!(!scratch.exists());
        }
    }
    // Regression: execution accepted unresolved pins, invalid deadlines or unsupported selections before setup.
    // Extraction refusals must record the failure and remove partial trees without starting a runtime.
    #[test]
    fn regression_bench_manifest_unpinned_execution_refused() {
        for case in [
            "pin",
            "timeout",
            "fuse",
            "cold",
            "git",
            "overlap",
            "image",
            "artifact",
            "source",
            "symlink",
            "missing-artifact",
        ] {
            let mut f = Fixture::new();
            match case {
                "pin" => {
                    f.value["tasks"][0]["git"]["repository"] = json!("unpinned");
                    f.value["tasks"][0]["platforms"][0]["supported_jobs"] = json!([]);
                    f.value["tasks"][0]["platforms"][0]["qualification"] =
                        json!({"qualified":false,"reasons":["draft"],"evidence":[]});
                }
                "timeout" => {
                    f.value["tasks"][0]["commands"]["build"]["timeout_seconds"] = json!(u64::MAX)
                }
                "overlap" => f.value["tasks"][0]["placement"]["source"] = json!("work"),
                "image" => f.fault("identity-mismatch"),
                "artifact" => {
                    f.value["tasks"][0]["artifact"]["sha256"] =
                        json!(format!("sha256:{}", "b".repeat(64)))
                }
                "fuse" => {
                    f.value["tasks"][0]["backends"] = json!(["native", "fuse"]);
                    let evidence =
                        &mut f.value["tasks"][0]["platforms"][0]["qualification"]["evidence"];
                    let mut fuse = evidence[0].clone();
                    fuse["backend"] = json!("fuse");
                    evidence.as_array_mut().unwrap().push(fuse);
                }
                "source" => {
                    f.value["tasks"][0]["artifact"]["tar_stream_sha256"] =
                        json!(format!("sha256:{}", "b".repeat(64)));
                    f.value["tasks"][0]["platforms"][0]["qualification"]["evidence"][0]
                        ["source_sha256"] =
                        f.value["tasks"][0]["artifact"]["tar_stream_sha256"].clone();
                }
                "symlink" => {
                    std::os::unix::fs::symlink("source.tar.zst", f.dir.path().join("alias.zst"))
                        .unwrap();
                    f.value["tasks"][0]["artifact"]["path"] = json!("alias.zst");
                }
                "missing-artifact" => {
                    std::fs::remove_file(f.dir.path().join("source.tar.zst")).unwrap();
                }
                _ => {}
            }
            f.save();
            let mut command = if case == "fuse" {
                f.command_at(
                    &f.dir.path().join("out"),
                    Some(&f.dir.path().join("work")),
                    "fuse",
                    "cold",
                )
            } else {
                f.command()
            };
            match case {
                "fuse" => {
                    // A cold native reference precedes FUSE; the whole selection must name B5a1a.
                    let dry = bench(
                        &f.path,
                        "--dry-run --backend fuse --cache cold --base-form tar.zst-single-frame",
                    );
                    let rows = schedule_rows(dry);
                    assert_eq!(rows[0]["backend"], "native");
                    assert!(rows.iter().any(|r| r["backend"] == "fuse"));
                }
                "cold" => {
                    command.args(["--cache", "cold"]);
                }
                "git" => {
                    command.args(["--base-form", "git"]);
                }
                _ => {}
            }
            let result = command.output().unwrap();
            if case == "source" {
                assert_eq!(result.status.code(), Some(1), "{}", stderr(&result));
                assert!(stderr(&result).contains("tar-stream sha256 mismatch"));
                let rows = f.rows();
                assert_eq!(rows.len(), 3);
                assert_eq!(rows[0]["outcome"], "error");
                assert!(rows[1..].iter().all(|r| r["outcome"] == "blocked"
                    && r["blocked_by"] == 0
                    && r["tree"].is_null()));
                assert_eq!(rows[0]["execution_error"], "tar-stream sha256 mismatch");
                assert!(rows[0]["phases"].as_array().unwrap().is_empty());
                assert!(rows[0]["cleanup_error"].is_null());
                assert!(!std::path::Path::new(rows[0]["tree"].as_str().unwrap()).exists());
                assert_eq!(
                    std::fs::read_dir(f.dir.path().join("work"))
                        .unwrap()
                        .count(),
                    0
                );
                f.no_containers();
            } else {
                assert_eq!(result.status.code(), Some(2), "{case}: {}", stderr(&result));
                assert!(!f.dir.path().join("out").exists(), "{case}");
            }
            assert!(result.stdout.is_empty());
            assert!(!f.calls().contains("run -d"));
            if case == "fuse" {
                assert!(stderr(&result)
                    .contains("FUSE execution unavailable: lifecycle deferred to B5a1a"));
            }
            if case == "pin" {
                assert!(stderr(&result).starts_with("sandbox bench: unresolved pins:"));
            }
            if case == "timeout" {
                assert!(stderr(&result).contains("1..=86400"));
            }
            if case == "missing-artifact" {
                assert!(stderr(&result).starts_with("sandbox bench: selection:"));
            }
        }
    }
    // Regression: native grading lost phase exits; phase exits and stop failure lost diagnostics/state.
    #[test]
    fn regression_bench_cli_native_outcome_and_stop_failure_recorded() {
        use std::os::unix::fs::PermissionsExt;
        for fault in ["", "fail-configure", "fail-build", "fail-test", "stop-fail"] {
            let f = Fixture::new();
            if !fault.is_empty() {
                f.fault(fault);
            }
            let output = f.command().output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(i32::from(!fault.is_empty())),
                "{}",
                stderr(&output)
            );
            let rows = f.rows();
            assert_eq!(rows.len(), 3);
            assert!(rows[if fault.is_empty() { 0 } else { 1 }..]
                .iter()
                .all(|r| r["outcome"]
                    == if fault.is_empty() {
                        "passed"
                    } else {
                        "blocked"
                    }));
            for row in f.executed() {
                assert_eq!(
                    row["outcome"],
                    if fault.is_empty() {
                        "passed"
                    } else if fault == "stop-fail" {
                        "error"
                    } else {
                        "failed"
                    }
                );
                assert!(row.get("throughput").is_none());
                assert!(row.get("verified").is_none());
                let phases = row["phases"].as_array().unwrap();
                assert_eq!(phases[0]["exit_code"], 0);
                if fault.starts_with("fail-") {
                    assert_eq!(phases.last().unwrap()["exit_code"], 7);
                    assert_eq!(
                        phases.last().unwrap()["phase"],
                        fault.trim_start_matches("fail-")
                    );
                }
                if fault == "stop-fail" {
                    assert!(row["stop_error"].is_string());
                    assert!(std::path::Path::new(row["tree"].as_str().unwrap()).is_dir());
                    f.remove_preserved_tree(&row);
                } else {
                    assert!(row["stop_error"].is_null());
                }
                assert_eq!(row["load"]["allow_high_load"], true);
            }
            assert_eq!(
                std::fs::metadata(f.dir.path().join("out"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("coverage:"));
            if fault != "stop-fail" {
                assert!(stderr(&output).contains(if fault.is_empty() {
                    "passed:"
                } else {
                    "failed:"
                }));
                f.no_containers();
            }
        }
    }
    // Regression: a phase timeout killed only the client and left its container/tree owned.
    #[test]
    fn regression_bench_cli_native_timeout_removes_container() {
        let f = Fixture::new();
        f.fault("exec-hang");
        let output = f.command().output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let rows = f.rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["outcome"], "failed");
        assert!(rows[1..].iter().all(|r| r["outcome"] == "blocked"));
        assert_eq!(rows[0]["phases"][1]["error"], "timeout");
        f.no_containers();
        assert_eq!(
            std::fs::read_dir(f.dir.path().join("work"))
                .unwrap()
                .count(),
            0
        );
        assert!(f.calls().contains("kill "));
        assert!(f.calls().contains("rm -f "));
        // Integration startup race: interrupt while run is still capable of creating the container.
        let f = Fixture::new();
        f.fault("late");
        let child = f.command().spawn().unwrap();
        let started = std::time::Instant::now();
        while !f.dir.path().join("state/starting").exists() {
            assert!(started.elapsed().as_secs() < 5);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(f.rows()[0]["phases"][0]["error"], "interrupted");
        f.no_containers();
        assert_eq!(
            f.calls()
                .lines()
                .filter(|s| s.starts_with("rm -f "))
                .count(),
            2
        );
        assert_eq!(
            std::fs::read_dir(f.dir.path().join("work"))
                .unwrap()
                .count(),
            0
        );
    }
    // Regression: reference, warm-up and measured runs reused a mutated source tree.
    #[test]
    fn regression_bench_cli_native_fresh_tree_per_run() {
        let f = Fixture::new();
        let output = f.command().output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let rows = f.rows();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r["outcome"] == "passed"));
        let trees: std::collections::BTreeSet<_> =
            rows.iter().map(|r| r["tree"].as_str().unwrap()).collect();
        assert_eq!(trees.len(), 3);
        assert!(trees.iter().all(|p| !std::path::Path::new(p).exists()));
        assert!(rows
            .iter()
            .all(|r| r["phases"].as_array().unwrap().len() == 4
                && r["phases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|p| p["exit_code"] == 0)));
        f.no_containers();
        assert_eq!(
            std::fs::read_dir(f.dir.path().join("work"))
                .unwrap()
                .count(),
            0
        );
    }
    // Regression: explicit work-root without out bypassed its requires-out rule.
    #[test]
    fn regression_bench_work_root_requires_out() {
        let f = Fixture::new();
        for mode in ["--dry-run", "--validate-only"] {
            let result = bench(&f.path, &format!("{mode} --work-root /var/tmp"));
            assert_eq!(result.status.code(), Some(2));
            let error = stderr(&result);
            assert!(
                error.contains("required") && error.contains("--out"),
                "{error}"
            );
        }
        assert_eq!(bench(&f.path, "--dry-run").status.code(), Some(0));
        assert_eq!(bench(&f.path, "--validate-only").status.code(), Some(0));
        assert!(!f.dir.path().join("out").exists());
    }
    // Regression: missing output parents and canonical work-root overlaps reached runtime setup.
    #[test]
    fn regression_bench_out_parent_and_work_root_refusals() {
        for case in [
            "out-parent-missing",
            "catalog-parent",
            "artifact-parent",
            "ancestor",
            "contains-source",
            "contains-output",
            "under-source",
            "scratch-in-out",
            "host-alias",
        ] {
            let mut f = Fixture::new();
            let mut out = f.dir.path().join("out");
            let mut work = f.dir.path().join("work");
            let reason = match case {
                "out-parent-missing" => {
                    out = f.dir.path().join("missing/out");
                    "--out parent must exist"
                }
                "catalog-parent" => {
                    work = f.dir.path().to_owned();
                    "equals catalog or artifact parent"
                }
                "artifact-parent" => {
                    std::fs::create_dir(f.dir.path().join("artifacts")).unwrap();
                    std::fs::rename(
                        f.dir.path().join("source.tar.zst"),
                        f.dir.path().join("artifacts/source.tar.zst"),
                    )
                    .unwrap();
                    f.value["tasks"][0]["artifact"]["path"] = json!("artifacts/source.tar.zst");
                    work = f.dir.path().join("artifacts");
                    "equals catalog or artifact parent"
                }
                "ancestor" => {
                    work = "/".into();
                    "work-root is an ancestor of the runtime executable"
                }
                "contains-source" => {
                    f.value["tasks"][0]["placement"]["source"] = json!("work/src");
                    "work-root is an ancestor of placement.source"
                }
                "contains-output" => {
                    f.value["tasks"][0]["placement"]["output"] = json!("work/output");
                    "work-root is an ancestor of placement.output"
                }
                "under-source" => {
                    f.value["tasks"][0]["placement"]["source"] = json!("work");
                    work = work.join("child");
                    std::fs::create_dir(&work).unwrap();
                    "under placement.source"
                }
                "host-alias" => {
                    std::os::unix::fs::symlink(f.dir.path(), work.join("alias")).unwrap();
                    work = work.join("alias");
                    "equals catalog or artifact parent"
                }
                _ => {
                    f.value["tasks"][0]["placement"]["scratch"] = json!("out/scratch");
                    "overlapping source/output/scratch roots"
                }
            };
            f.save();
            let result = f
                .command_at(&out, Some(&work), "native", "warm")
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(2), "{case}: {}", stderr(&result));
            assert!(stderr(&result).contains("sandbox bench: selection:"));
            assert!(
                stderr(&result).contains(reason),
                "{case}: {}",
                stderr(&result)
            );
            assert!(!stderr(&result).contains("bench native lifecycle:"));
            assert!(!out.exists());
            assert!(!f.calls().contains("image inspect"));
            assert!(!f.calls().contains("run -d"));
        }
    }
    // Regression: each protected-root ancestor refusal must identify its own isolated rule.
    #[test]
    fn regression_bench_work_root_ancestor_specific_reasons() {
        use std::os::unix::fs::symlink;
        for (case, reason) in [
            ("contains-out", "work-root is an ancestor of --out"),
            (
                "contains-catalog",
                "work-root is an ancestor of the catalog directory",
            ),
            (
                "contains-artifact-parent",
                "work-root is an ancestor of the artifact parent",
            ),
        ] {
            let mut f = Fixture::new();
            let work = f.dir.path().join(if case == "contains-out" {
                "outputs"
            } else {
                "work"
            });
            let out = if case == "contains-out" {
                std::fs::create_dir_all(work.join("run")).unwrap();
                work.join("run/out")
            } else {
                f.dir.path().join("out")
            };
            if case == "contains-catalog" {
                let catalog = work.join("catalog");
                std::fs::create_dir(&catalog).unwrap();
                f.path = catalog.join("tasks.json");
            }
            let artifact = if case == "contains-artifact-parent" {
                let artifacts = work.join("artifacts");
                std::fs::create_dir(&artifacts).unwrap();
                let artifact = artifacts.join("source.tar.zst");
                std::fs::rename(f.dir.path().join("source.tar.zst"), &artifact).unwrap();
                artifact
            } else {
                f.dir.path().join("source.tar.zst")
            };
            f.value["tasks"][0]["artifact"]["path"] = json!(artifact);
            let catalog = f.path.parent().unwrap();
            // Existing outward targets are outside work and are not ancestors of work.
            for field in ["source", "output"] {
                let target = f.dir.path().join(format!("external-{field}"));
                std::fs::create_dir(&target).unwrap();
                let target = target.canonicalize().unwrap();
                let work = work.canonicalize().unwrap();
                assert!(!target.starts_with(&work) && !work.starts_with(&target));
                let link = format!("placement-{field}");
                let relative_target = if case == "contains-catalog" {
                    PathBuf::from("../..").join(format!("external-{field}"))
                } else {
                    PathBuf::from(format!("external-{field}"))
                };
                symlink(relative_target, catalog.join(&link)).unwrap();
                assert_eq!(catalog.join(&link).canonicalize().unwrap(), target);
                f.value["tasks"][0]["placement"][field] = json!(link);
            }
            f.save();
            let work = work.canonicalize().unwrap();
            let artifact_parent = artifact.parent().unwrap().canonicalize().unwrap();
            // Fresh --out has an existing parent; resolve ancestors before appending its leaf.
            let resolved_out = out
                .parent()
                .unwrap()
                .canonicalize()
                .unwrap()
                .join(out.file_name().unwrap());
            // Exactly one of the six ancestor clauses applies, even before ordered dispatch.
            assert_eq!(
                [
                    f.runtime.canonicalize().unwrap().starts_with(&work),
                    resolved_out.starts_with(&work),
                    catalog.canonicalize().unwrap().starts_with(&work),
                    artifact_parent.starts_with(&work),
                    catalog
                        .join("placement-source")
                        .canonicalize()
                        .unwrap()
                        .starts_with(&work),
                    catalog
                        .join("placement-output")
                        .canonicalize()
                        .unwrap()
                        .starts_with(&work),
                ]
                .into_iter()
                .filter(|matches| *matches)
                .count(),
                1
            );
            let result = f
                .command_at(&out, Some(&work), "native", "warm")
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(2), "{case}: {}", stderr(&result));
            assert!(
                stderr(&result).contains(&format!("sandbox bench: selection: {reason}")),
                "{case}: {}",
                stderr(&result)
            );
            assert!(!out.exists());
            assert!(f.calls().is_empty());
        }
    }
    fn runtime_ancestor_refused(case: &str) {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let mut f = if case == "var-tmp" {
            Fixture::with_directories(tempfile::tempdir_in("/var/tmp").unwrap(), 0)
        } else {
            Fixture::new()
        };
        let work = if case == "var-tmp" {
            PathBuf::from("/var/tmp")
        } else {
            f.dir.path().join("work")
        };
        let runtime = f.dir.path().join("work/runtime");
        std::fs::write(&runtime, std::fs::read(&f.runtime).unwrap()).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        f.runtime = if case == "host-alias" {
            let alias = f.dir.path().join("runtime-alias");
            symlink(&runtime, &alias).unwrap();
            alias
        } else {
            runtime
        };
        let out = f.dir.path().join("out");
        let result = f
            .command_at(&out, Some(&work), "native", "warm")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2), "{case}: {}", stderr(&result));
        let error = stderr(&result);
        assert!(
            error.contains("sandbox bench: selection:")
                && error.contains("work-root is an ancestor of the runtime executable"),
            "{case}: {error}"
        );
        assert!(!error.contains("bench native lifecycle:"));
        assert!(!out.exists());
        assert!(f.calls().is_empty());
    }
    // Regression: work-root ancestors of the resolved runtime were admitted, including host symlink aliases.
    #[test]
    fn regression_bench_work_root_runtime_ancestor_refused() {
        for case in ["contained", "host-alias"] {
            runtime_ancestor_refused(case);
        }
    }
    // Regression: /var/tmp incorrectly exempted contained runtime executables from refusal.
    #[test]
    fn regression_bench_var_tmp_runtime_ancestor_refused() {
        runtime_ancestor_refused("var-tmp");
    }
    // Regression: default /var/tmp falsely overlapped outputs/catalogs beneath it (S-4).
    #[test]
    fn regression_bench_var_tmp_default_and_sibling_work_admitted() {
        for kind in ["default", "explicit-default", "sibling"] {
            // Deliberately independent of process TMPDIR, including catalog and artifact.
            let f = Fixture::with_directories(tempfile::tempdir_in("/var/tmp").unwrap(), 0);
            let sibling = f.dir.path().join("work");
            let work = match kind {
                "default" => None,
                "explicit-default" => Some(std::path::Path::new("/var/tmp")),
                _ => Some(sibling.as_path()),
            };
            let result = f
                .command_at(&f.dir.path().join("out"), work, "native", "warm")
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(0), "{kind}: {}", stderr(&result));
            assert!(stderr(&result).contains("passed:"));
            let rows = f.rows();
            assert_eq!(rows.len(), 3);
            assert!(rows.iter().all(|r| r["outcome"] == "passed"));
            for row in rows {
                assert!(row["execution_error"].is_null());
                assert!(row["cleanup_error"].is_null());
                let tree = std::path::Path::new(row["tree"].as_str().unwrap());
                assert_eq!(
                    tree.parent().unwrap().parent().unwrap(),
                    work.unwrap_or(std::path::Path::new("/var/tmp"))
                );
                assert!(!tree.exists());
                assert!(!tree.parent().unwrap().exists());
            }
            assert!(std::path::Path::new("/var/tmp").is_dir());
            f.no_containers();
        }
    }
    // Regression: one held descriptor per archive directory exhausted RLIMIT_NOFILE (T-8).
    #[test]
    fn regression_bench_many_directories_under_fd_limit() {
        use std::os::unix::process::CommandExt;
        let f = Fixture::with_directories(tempfile::tempdir().unwrap(), 1100);
        f.fault("many-directories");
        let mut command = f.command();
        unsafe {
            command.pre_exec(|| {
                let mut limit = std::mem::zeroed();
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                limit.rlim_cur = limit.rlim_cur.min(64);
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let result = command.output().unwrap();
        assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
        assert_eq!(f.rows().len(), 3);
        assert!(f.rows().iter().all(|r| r["execution_error"].is_null()
            && r["cleanup_error"].is_null()
            && r["phases"].as_array().unwrap().len() == 4));
        f.no_containers();
    }
    // Regression: runtime-created restrictive dirs, run-after-create failure, or between-entry INT leaked trees.
    #[test]
    fn regression_bench_runtime_fault_cleanup_and_between_entry_interrupt() {
        for fault in [
            "mode-000",
            "mode-0500",
            "archive-modes",
            "run-fail",
            "interrupt-after-stop",
            "depth-257",
        ] {
            let f = Fixture::new();
            f.fault(fault);
            let result = f.command().output().unwrap();
            assert_eq!(
                result.status.code(),
                Some(i32::from(matches!(
                    fault,
                    "run-fail" | "interrupt-after-stop" | "depth-257"
                ))),
                "{fault}: {}",
                stderr(&result)
            );
            let rows = f.rows();
            assert_eq!(rows.len(), 3);
            f.no_containers();
            assert!(f.calls().contains("kill ") && f.calls().contains("rm -f "));
            if fault == "depth-257" {
                assert_eq!(rows[0]["outcome"], "error");
                assert!(rows[1..].iter().all(|r| r["outcome"] == "blocked"));
                assert!(rows[0]["cleanup_error"]
                    .as_str()
                    .unwrap()
                    .contains("depth exceeds 256; remaining tree preserved"));
                assert!(std::path::Path::new(rows[0]["tree"].as_str().unwrap()).exists());
                f.remove_preserved_tree(&rows[0]);
            } else {
                assert!(rows.iter().all(|r| r["cleanup_error"].is_null()));
                for row in f.executed() {
                    let tree = std::path::Path::new(row["tree"].as_str().unwrap());
                    assert!(!tree.exists() && !tree.parent().unwrap().exists());
                }
            }
            if fault == "archive-modes" {
                assert_eq!(rows.len(), 3);
                assert!(rows.iter().all(|row| row["stop_error"].is_null()
                    && row["phases"].as_array().unwrap().len() == 4
                    && row["phases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|phase| phase["exit_code"] == 0)));
            }
            if fault == "run-fail" {
                assert_eq!(f.executed().len(), 1);
                assert_eq!(rows[0]["phases"][0]["exit_code"], 17);
                assert_eq!(rows[0]["phases"].as_array().unwrap().len(), 1);
            }
            if fault == "interrupt-after-stop" {
                assert_eq!(rows.len(), 3);
                assert_eq!(rows[1]["outcome"], "interrupted");
                assert_eq!(rows[2]["outcome"], "blocked");
                assert_eq!(rows[1]["execution_error"], "interrupted");
                assert_eq!(rows[1]["phases"], json!([]));
                assert!(rows[0]["execution_error"].is_null());
                assert_eq!(
                    f.calls()
                        .lines()
                        .filter(|s| s.starts_with("run -d"))
                        .count(),
                    1
                );
                assert!(!f.dir.path().join("out/1-recovery.json").exists());
                assert!(!stderr(&result).contains("bench native lifecycle: interrupted"));
                assert!(stderr(&result).contains("interrupted:"));
            }
        }
    }
    fn no_performance_claims(value: &Value) {
        match value {
            Value::Object(fields) => {
                assert!(!fields.contains_key("throughput") && !fields.contains_key("verified"));
                for child in fields.values() {
                    no_performance_claims(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    no_performance_claims(child);
                }
            }
            _ => {}
        }
    }
    // Regression: a failed native reference ran dependent measurements (6).
    #[test]
    fn regression_bench_reference_failure_blocks_measurements() {
        let f = Fixture::new();
        f.fault("fail-test");
        let output = f.command().output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let rows = f.rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["outcome"], "failed");
        assert!(rows[1..].iter().all(|r| r["outcome"] == "blocked"
            && r["blocked_by"] == 0
            && r["reason"].as_str().unwrap().contains("phase test exit")));
        assert_eq!(f.read("batch-end.json")["status"], "failed");
        assert_eq!(
            f.calls()
                .lines()
                .filter(|s| s.starts_with("run -d"))
                .count(),
            1
        );
    }
    // Regression: runtime classification was inferred from the executable or omitted (7).
    #[test]
    fn regression_bench_runtime_kind_is_explicit_and_recorded() {
        let f = Fixture::new();
        let output = f.kind(None).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr(&output).contains("--runtime-kind docker|stub is required"));
        assert!(!f.dir.path().join("out").exists());
        assert!(f.calls().is_empty());
        assert_eq!(
            std::fs::read_dir(f.dir.path().join("work"))
                .unwrap()
                .count(),
            0
        );
        let output = f.command().output().unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(f.read("batch.json")["runtime"]["kind"], "stub");
        assert!(f.rows().iter().all(|r| r["runtime"]["kind"] == "stub"));
    }
    // Regression: unqualified Podman reached inspect/setup, or hid the FUSE refusal (8/N1).
    #[test]
    fn regression_bench_podman_not_yet_qualified_refused_before_setup() {
        let f = Fixture::new();
        let output = f.kind(Some("podman")).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr(&output).contains("not yet qualified"));
        assert!(!f.dir.path().join("out").exists());
        assert!(f.calls().is_empty());
        assert_eq!(
            std::fs::read_dir(f.dir.path().join("work"))
                .unwrap()
                .count(),
            0
        );
        let mut f = Fixture::new();
        f.value["tasks"][0]["backends"] = json!(["native", "fuse"]);
        let mut evidence =
            f.value["tasks"][0]["platforms"][0]["qualification"]["evidence"][0].clone();
        evidence["backend"] = "fuse".into();
        f.value["tasks"][0]["platforms"][0]["qualification"]["evidence"]
            .as_array_mut()
            .unwrap()
            .push(evidence);
        f.save();
        for kind in [None, Some("podman")] {
            let output = f
                .command_at_kind(
                    &f.dir.path().join("out"),
                    Some(&f.dir.path().join("work")),
                    "fuse",
                    "warm",
                    kind,
                )
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(
                stderr(&output).contains("FUSE execution unavailable"),
                "{}",
                stderr(&output)
            );
            assert!(f.calls().is_empty());
            assert!(!f.dir.path().join("out").exists());
        }
    }
    // Regression: stub results could be mistaken for publishable measurements (9).
    #[test]
    fn regression_bench_stub_records_are_fixture_only() {
        let f = Fixture::new();
        let output = f.command().output().unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(stderr(&output).contains("stub fixture, not publishable"));
        let batch = f.read("batch.json");
        assert_eq!(batch["fixture"], true);
        assert_eq!(batch["publishable"], false);
        assert!(f
            .rows()
            .iter()
            .all(|r| r["fixture"] == true && r["publishable"] == false));
    }
    // Regression: summarize required a manifest/runtime or accepted execution flags (B4b-5a/5).
    #[test]
    fn regression_bench_cli_summarize_needs_no_manifest_or_runtime() {
        let help = cli(&["bench", "--help"]);
        assert!(help.status.success(), "{}", stderr(&help));
        let help = String::from_utf8_lossy(&help.stdout);
        for expected in [
            "Validate a Perl benchmark manifest, emit a dry-run schedule, run native lifecycles",
            "summarize records (Linux only)",
            "Commands:",
            "summarize",
        ] {
            assert!(help.contains(expected), "{help}");
        }
        let dir = tempfile::tempdir().unwrap();
        let entry = json!({"schema":"rrs-perl-bench-schedule/1","catalog_revision":"fixture-1",
            "cell":{"task":"task","platform":"platform","base_form":"tar.zst-single-frame","jobs":1,"cache":"warm"},
            "backend":"native","kind":"measured","repeat":1,"paired":false,"seed":1,"repeats":1,"attempts":1,
            "cpus":1,"allow_oversubscription":false,"oversubscribed":false,"qualified":true});
        let header = json!({"schema":"rrs-perl-bench/1","record":"batch","batch_id":"fixture",
            "catalog_revision":"fixture-1","tasks":[{"id":"task"}],"platforms":[{"id":"platform"}],
            "fixture":true,"publishable":false,"runtime":{"kind":"stub"},"load":{},
            "settings":{"native":{"seed":1,"repeats":1,"attempts":1,"base_form":["tar.zst-single-frame"],"cache":["warm"],"jobs":[1]}}});
        for (name, row) in [
            ("batch.json", header.clone()),
            (
                "schedule.jsonl",
                json!({"schema":"rrs-perl-bench/1","record":"schedule","batch_id":"fixture","run_id":"fixture-0","sequence":0,"entry":entry}),
            ),
            (
                "runs.jsonl",
                json!({"schema":"rrs-perl-bench/1","record":"run","batch_id":"fixture","run_id":"fixture-0","index":0,"schedule":entry,"outcome":"passed","runtime":header["runtime"],"fixture":true,"publishable":false,"load":{},"lifecycle_ms":{"total":100}}),
            ),
            (
                "batch-end.json",
                json!({"schema":"rrs-perl-bench/1","record":"batch-end","batch_id":"fixture","status":"passed","error":null,"wall_ms":1000,"counts":{"passed":1,"failed":0,"blocked":0,"interrupted":0,"error":0}}),
            ),
        ] {
            std::fs::write(dir.path().join(name), format!("{row}\n")).unwrap();
        }
        let result = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .args(["sandbox", "bench", "summarize"])
            .arg(dir.path())
            .env("PATH", "")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["status"], "passed");
        assert_eq!(report["groups"][0]["samples"], 1);
        assert_eq!(report["verified_attempts_per_hour"], 3600.0);
        assert_eq!(stderr(&result).lines().count(), 1);
        let path = dir.path().to_str().unwrap();
        for flags in [
            vec!["bench", "--manifest", "absent.json", "summarize", path],
            vec!["bench", "--out", "absent-output", "summarize", path],
        ] {
            let result = cli(&flags);
            assert_eq!(result.status.code(), Some(2), "{}", stderr(&result));
            assert!(
                stderr(&result).contains("cannot be used"),
                "{}",
                stderr(&result)
            );
        }
        for (args, required) in [
            (vec!["bench", "--dry-run"], "--manifest"),
            (
                vec!["bench", "--manifest", "absent.json"],
                "--validate-only",
            ),
        ] {
            let result = cli(&args);
            assert_eq!(result.status.code(), Some(2), "{}", stderr(&result));
            assert!(stderr(&result).contains(required), "{}", stderr(&result));
            assert!(stderr(&result).contains("required"), "{}", stderr(&result));
        }
    }
    // Regression: real stub producer records failed to round-trip through summarize (B4b-5a/6).
    #[test]
    fn regression_bench_cli_native_producer_round_trips_summary() {
        for failed in [false, true] {
            let f = Fixture::new();
            if failed {
                f.fault("tap-fail-zero");
            }
            let produced = f.command().output().unwrap();
            assert_eq!(
                produced.status.code(),
                Some(i32::from(failed)),
                "{}",
                stderr(&produced)
            );
            let summarized = cli(&[
                "bench",
                "summarize",
                f.dir.path().join("out").to_str().unwrap(),
            ]);
            assert_eq!(
                summarized.status.code(),
                Some(i32::from(failed)),
                "{}",
                stderr(&summarized)
            );
            let report: Value = serde_json::from_slice(&summarized.stdout).unwrap();
            assert_eq!(report["status"], if failed { "failed" } else { "passed" });
            assert_eq!(report["fixture"], true);
            assert_eq!(report["publishable"], false);
            assert_eq!(report["ratios"], json!([]));
            assert_eq!(
                String::from_utf8_lossy(&summarized.stdout).lines().count(),
                1
            );
            let message = stderr(&summarized);
            assert_eq!(message.lines().count(), 1);
            assert!(message.starts_with("sandbox bench summarize:"), "{message}");
            assert!(
                message.contains("stub fixture, not publishable"),
                "{message}"
            );
            if failed {
                assert!(report["verified_attempts_per_hour"].is_null());
            } else {
                let schedule =
                    std::fs::read_to_string(f.dir.path().join("out/schedule.jsonl")).unwrap();
                let measured = schedule
                    .lines()
                    .map(|s| serde_json::from_str::<Value>(s).unwrap())
                    .filter(|s| s["entry"]["kind"] == "measured")
                    .count();
                let samples: u64 = report["groups"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|g| g["samples"].as_u64().unwrap())
                    .sum();
                assert_eq!(samples, measured as u64);
                assert!(report["verified_attempts_per_hour"].as_f64().unwrap() > 0.0);
            }
            f.no_containers();
        }
    }
    // Regression: a successful stub batch lacked canonical identities, summaries or execution details (10/N5).
    #[test]
    fn regression_bench_cli_native_stub_success_records_jsonl() {
        let mut f = Fixture::new();
        // Regression: command -e arguments must not be recorded as environment options.
        f.value["tasks"][0]["commands"]["configure"]["argv"] =
            json!(["configure", "-e", "POSITIONAL_ONLY=1", "{jobs}"]);
        // Regression: record the resolved artifact path through a symlinked parent.
        let actual = f.dir.path().join("artifact-target");
        std::fs::create_dir(&actual).unwrap();
        std::fs::rename(
            f.dir.path().join("source.tar.zst"),
            actual.join("source.tar.zst"),
        )
        .unwrap();
        std::os::unix::fs::symlink("artifact-target", f.dir.path().join("artifact-alias")).unwrap();
        f.value["tasks"][0]["artifact"]["path"] = "artifact-alias/source.tar.zst".into();
        f.save();
        let output = f.command().output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(stderr(&output).starts_with("sandbox bench: passed:"));
        let batch = f.read("batch.json");
        assert_eq!(
            batch["tasks"][0]["artifact"]["path"],
            "artifact-alias/source.tar.zst"
        );
        assert_eq!(
            batch["tasks"][0]["artifact"]["resolved_path"],
            actual.join("source.tar.zst").to_str().unwrap()
        );

        let end = f.read("batch-end.json");
        let runs = f.rows();
        let schedule: Vec<Value> = std::fs::read_to_string(f.dir.path().join("out/schedule.jsonl"))
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(schedule.len(), 3);
        assert_eq!(runs.len(), 3);
        assert_eq!(end["status"], "passed");
        assert_eq!(batch["record"], "batch");
        assert_eq!(end["record"], "batch-end");
        assert!(batch["manifest_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(batch["host"]["machine"].is_string());
        assert!(batch["host"].get("nodename").is_none());
        assert_eq!(batch["tasks"][0]["test_inventory"]["count"], 1);
        assert_eq!(
            batch["platforms"][0]["toolchain_sha256"],
            f.value["platforms"][0]["toolchain_sha256"]
        );
        for record in std::iter::once(&batch)
            .chain(std::iter::once(&end))
            .chain(schedule.iter())
            .chain(runs.iter())
        {
            assert_eq!(record["schema"], "rrs-perl-bench/1");
            assert_eq!(record["batch_id"], batch["batch_id"]);
        }
        for (index, (planned, run)) in schedule.iter().zip(&runs).enumerate() {
            assert_eq!(planned["record"], "schedule");
            assert_eq!(run["record"], "run");
            assert_eq!(planned["sequence"], index);
            assert_eq!(run["index"], index);
            assert_eq!(planned["run_id"], run["run_id"]);
            assert_eq!(
                run["run_id"],
                format!("{}-{index}", batch["batch_id"].as_str().unwrap())
            );
            assert_eq!(planned["entry"], run["schedule"]);
            assert_eq!(run["outcome"], "passed");
            assert_eq!(run["summary"]["files"], 1);
            assert_eq!(run["summary"]["tests"], 10);
            assert_eq!(run["summary"]["result"], "PASS");
            assert!(run["summary"]["skipped"].is_null());
            if index > 0 {
                assert_eq!(run["reference"], json!({"index":0,"files":1,"tests":10}));
            }
            assert_eq!(run["environment"], f.value["tasks"][0]["environment"]);
            assert_eq!(run["environment"]["TZ"], "UTC");
            assert_eq!(run["environment"]["PERL_HASH_SEED"], "0");
            assert_eq!(
                &run["startup_argv"].as_array().unwrap()[..4],
                &[
                    json!("run"),
                    json!("-d"),
                    json!("--init"),
                    json!("--pull=never")
                ]
            );
            for phase in run["phases"].as_array().unwrap() {
                assert!(phase["elapsed_ms"].is_number());
                assert!(phase["argv"].is_array());
                assert_eq!(phase["stdout_truncated"], false);
                assert_eq!(phase["stderr_truncated"], false);
                if phase["phase"] != "run" {
                    assert_eq!(phase["environment"], run["environment"]);
                }
            }
            assert!(run["lifecycle_ms"]["total"].is_number());
            assert!(run["lifecycle_ms"]["extract"].is_number());
        }
        assert!(!f.dir.path().join("out/outcomes.jsonl").exists());
        f.no_containers();
    }
    // Regression: grading failures/count drift returned success or omitted blocked terminals (11/N9).
    #[test]
    fn regression_bench_cli_native_failure_batch_nonzero() {
        for (fault, reason) in [
            ("fail-build", "phase build exit"),
            ("count-drift", "test counts differ from native reference"),
            ("tap-fail-zero", "FAIL with exit 0"),
            ("tap-notests", "NOTESTS"),
            ("tap-bailout", "bailout"),
            ("tap-missing", "missing or malformed prove summary"),
        ] {
            let f = Fixture::new();
            f.fault(fault);
            let output = f.command().output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(1),
                "{fault}: {}",
                stderr(&output)
            );
            assert!(stderr(&output).starts_with("sandbox bench: failed:"));
            let rows = f.rows();
            assert_eq!(rows.len(), 3);
            let failed = usize::from(fault == "count-drift");
            assert_eq!(rows[failed]["outcome"], "failed");
            assert!(
                rows[failed]["reason"].as_str().unwrap().contains(reason),
                "{fault}: {}",
                rows[failed]
            );
            assert!(rows[..failed].iter().all(|r| r["outcome"] == "passed"));
            assert!(rows[failed + 1..].iter().all(|r| r["outcome"] == "blocked"
                && r["blocked_by"] == failed
                && r["reason"] == rows[failed]["reason"]
                && r["tree"].is_null()));
            assert_eq!(f.read("batch-end.json")["status"], "failed");
            no_performance_claims(&json!(rows));
            no_performance_claims(&f.read("batch.json"));
            no_performance_claims(&f.read("batch-end.json"));
            for line in std::fs::read_to_string(f.dir.path().join("out/schedule.jsonl"))
                .unwrap()
                .lines()
            {
                no_performance_claims(&serde_json::from_str::<Value>(line).unwrap());
            }
            f.no_containers();
        }
    }
    // Regression: SIGTERM during startup shared the successful/failed completion presentation (12).
    #[test]
    fn regression_bench_cli_interrupted_batch_presentation_distinct() {
        let f = Fixture::new();
        f.fault("late");
        let child = f.command().spawn().unwrap();
        let started = std::time::Instant::now();
        while !f.dir.path().join("state/starting").exists() {
            assert!(started.elapsed().as_secs() < 5);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let message = stderr(&output);
        assert!(
            message.starts_with("sandbox bench: interrupted:"),
            "{message}"
        );
        for forbidden in ["passed:", "failed:", "ungraded"] {
            assert!(!message.contains(forbidden));
        }
        assert_eq!(f.read("batch-end.json")["status"], "interrupted");
        let rows = f.rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["outcome"], "interrupted");
        assert!(rows[1..]
            .iter()
            .all(|r| r["outcome"] == "blocked" && r["reason"] == "interrupted"));
        f.no_containers();
        assert_eq!(
            std::fs::read_dir(f.dir.path().join("work"))
                .unwrap()
                .count(),
            0
        );
    }
    // Regression: interruption plus a cleanup failure lost interrupted stderr/end status (N3).
    #[test]
    fn regression_bench_cli_interrupted_lifecycle_error_presentation() {
        let f = Fixture::new();
        f.fault("exec-hang");
        f.fault("depth-257");
        let child = f.command().spawn().unwrap();
        let started = std::time::Instant::now();
        while !f.dir.path().join("state/executing").exists() {
            assert!(started.elapsed().as_secs() < 5);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let message = stderr(&output);
        assert!(
            message.starts_with("sandbox bench: interrupted: batch incomplete; lifecycle error:"),
            "{message}"
        );
        assert!(message.contains("depth exceeds 256"));
        assert!(!message.contains("passed:"));
        let end = f.read("batch-end.json");
        assert_eq!(end["status"], "interrupted");
        assert!(end["error"].as_str().unwrap().contains("depth exceeds 256"));
        let rows = f.rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["outcome"], "interrupted");
        assert!(rows[1..]
            .iter()
            .all(|r| r["outcome"] == "blocked" && r["reason"] == "interrupted"));
        f.no_containers();
        f.remove_preserved_tree(&rows[0]);
    }
}
