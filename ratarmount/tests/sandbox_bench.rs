//! Validation-only CLI regressions; no FUSE, network or runtime prerequisites.

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
        for expected in [
            "Example:",
            "Linux",
            "Exit status:",
            "Inherited `--socket` is rejected; bench owns its supervisor.",
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
    assert!(stderr(&positional).contains("unexpected argument 'mountpoint'"));
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
        // Oversized files and /dev/null hit descriptor/size checks before JSON parsing.
        assert!(stderr(&result).contains(if path == link || path == socket {
            "manifest-open"
        } else {
            "manifest must be a regular file of at most 1 MiB"
        }));
        drop(listener);
    }
    let report = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["sandbox", "bench", "--manifest", file, "--validate-only"])
        .stdout(
            std::fs::File::options()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(report.status.code(), Some(1));
    assert!(stderr(&report).contains("bench validation report"));
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
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        let error = stderr(&output);
        assert!(error.contains("--socket is rejected"), "{error}");
        assert!(!error.contains("manifest-open"), "{error}");
    }
    assert!(!missing.exists());
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
