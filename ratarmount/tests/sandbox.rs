//! Sandbox protocol over a real socket; FUSE tests skip without the device.
#![cfg(target_os = "linux")]

use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon {
    root: Option<tempfile::TempDir>,
    socket: PathBuf,
    child: Child,
}

impl Daemon {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("api.sock");
        let log = root.path().join("daemon.log");
        let child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .args(["sandbox", "daemon", "--socket"])
            .arg(&socket)
            .arg("--state-dir")
            .arg(root.path().join("state"))
            .args(["--max-attempts", "64", "--timeout", "30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let mut daemon = Self {
            root: Some(root),
            socket,
            child,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&daemon.socket).is_err() {
            assert!(
                daemon.child.try_wait().unwrap().is_none(),
                "{}",
                fs::read_to_string(&log).unwrap()
            );
            assert!(Instant::now() < deadline, "daemon socket timeout");
            thread::sleep(Duration::from_millis(20));
        }
        daemon
    }

    fn call(&self, mut request: Value) -> Value {
        request["version"] = json!(1);
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        writeln!(stream, "{request}").unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["ok"], true, "{response}");
        response["result"].clone()
    }

    fn base(&self) {
        let tar = self.root.as_ref().unwrap().path().join("base.tar");
        let mut file = fs::File::create(&tar).unwrap();
        write_ustar_members(
            &mut file,
            &[UstarMember {
                path: "base.txt",
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                xattrs: &[],
                payload: UstarPayload::File {
                    bytes: b"original\n",
                },
            }],
        )
        .unwrap();
        write_tar_eof(&mut file).unwrap();
        drop(file);
        self.call(json!({"op":"create_base", "name":"task", "source":tar}));
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Ok(mut stream) = UnixStream::connect(&self.socket) {
            let _ = stream.write_all(b"{\"version\":1,\"op\":\"shutdown\"}\n");
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Never let TempDir recurse through a still-mounted base on test failure.
        if let Some(root) = self.root.take() {
            if fs::read_dir(root.path().join("state/attempts"))
                .is_ok_and(|mut entries| entries.next().is_some())
            {
                eprintln!(
                    "retaining failed test state for cleanup: {}",
                    root.keep().display()
                );
            }
        }
    }
}

/// Regression: malformed/versioned requests, pipelining and idle clients cannot take down the daemon.
#[test]
fn regression_sandbox_socket_protocol_and_restart() {
    let mut daemon = Daemon::start();
    let idle = UnixStream::connect(&daemon.socket).unwrap();
    let stream = UnixStream::connect(&daemon.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    reader
        .get_mut()
        .write_all(b"{bad}\n{\"version\":9,\"op\":\"list\"}\n{\"version\":1,\"op\":\"list\"}\n")
        .unwrap();
    for code in [Some("invalid_request"), Some("unsupported_version"), None] {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        if let Some(code) = code {
            assert_eq!(value["error"]["code"], code);
        } else {
            assert_eq!(value["result"], json!([]));
        }
    }
    drop(idle);
    assert_eq!(
        fs::metadata(&daemon.socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    daemon.base();
    let rejected = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["sandbox", "create-base", "--socket"])
        .arg(&daemon.socket)
        .arg("invalid")
        .arg(daemon.root.as_ref().unwrap().path().join("missing.tar"))
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&rejected.stdout).unwrap()["error"]["code"],
        "base_open_failed"
    );
    let persisted: Value = serde_json::from_slice(
        &fs::read(
            daemon
                .root
                .as_ref()
                .unwrap()
                .path()
                .join("state/bases.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(persisted["bases"].get("invalid").is_none());
    assert!(daemon
        .root
        .as_ref()
        .unwrap()
        .path()
        .join("state/bases.json")
        .is_file());
    let index_root = daemon
        .root
        .as_ref()
        .unwrap()
        .path()
        .join("state/indexes/task");
    assert!(fs::read_dir(index_root).unwrap().any(|e| e
        .unwrap()
        .path()
        .extension()
        .is_some_and(|s| s == "sqlite")));
    let listed = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["sandbox", "list", "--socket"])
        .arg(&daemon.socket)
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&listed.stdout).unwrap()["result"],
        json!([])
    );
    if !Path::new("/dev/fuse").exists() {
        let failed = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .args(["sandbox", "new", "--socket"])
            .arg(&daemon.socket)
            .args(["task", "--count", "2"])
            .output()
            .unwrap();
        assert!(!failed.status.success());
        let response: Value = serde_json::from_slice(&failed.stdout).unwrap();
        assert_eq!(response["error"]["code"], "mount_failed", "{response}");
        assert_eq!(daemon.call(json!({"op":"list"})), json!([]));
    }
    daemon.call(json!({"op":"shutdown"}));
    let deadline = Instant::now() + Duration::from_secs(5);
    while daemon.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    }
    // Use a different CWD to ensure the persisted base is independent of it.
    daemon.child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["sandbox", "daemon", "--socket"])
        .arg(&daemon.socket)
        .arg("--state-dir")
        .arg(daemon.root.as_ref().unwrap().path().join("state"))
        .current_dir("/")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while UnixStream::connect(&daemon.socket).is_err() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(daemon.call(json!({"op":"list","base":"task"})), json!([]));
}

fn mounts(count: usize) {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: sandbox mount integration requires /dev/fuse");
        return;
    }
    if Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: sandbox mount integration requires fusermount3");
        return;
    }
    let daemon = Daemon::start();
    daemon.base();
    let start = Instant::now();
    let result = daemon.call(json!({"op":"new", "base":"task", "count":count, "overlay":"disk"}));
    let setup = start.elapsed();
    let attempts = result.as_array().unwrap();
    assert_eq!(attempts.len(), count);
    for (i, attempt) in attempts.iter().enumerate() {
        let path = Path::new(attempt["path"].as_str().unwrap());
        assert_eq!(fs::read(path.join("base.txt")).unwrap(), b"original\n");
        fs::write(
            path.join(format!("attempt-{i}.txt")),
            format!("change-{i}\n"),
        )
        .unwrap();
    }
    for (i, attempt) in attempts.iter().enumerate() {
        let diff = daemon.call(json!({"op":"diff", "id":attempt["id"], "git":true}));
        let patch = diff["patch"].as_str().unwrap();
        assert!(patch.contains(&format!("+change-{i}\n")), "{patch}");
        assert_eq!(
            patch.matches("diff --git").count(),
            1,
            "sibling leaked into patch: {patch}"
        );
        let stats = daemon.call(json!({"op":"stats", "id":attempt["id"]}));
        assert_eq!(stats["files_present"], 1);
    }
    let start = Instant::now();
    daemon.call(json!({"op":"destroy", "base":"task"}));
    let teardown = start.elapsed();
    assert_eq!(daemon.call(json!({"op":"list"})), json!([]));
    for attempt in attempts {
        assert!(!Path::new(attempt["path"].as_str().unwrap()).exists());
    }
    eprintln!(
        "{count} attempts: setup {:.3} ms/attempt, teardown {:.3} ms/attempt (warm base)",
        setup.as_secs_f64() * 1000. / count as f64,
        teardown.as_secs_f64() * 1000. / count as f64
    );
}

/// Regression: eight simultaneous writable mounts must not share attempt contents.
#[test]
fn regression_sandbox_eight_mounts_isolate_writes_and_diffs() {
    mounts(8);
}

/// Regression: measure supervisor setup/teardown at the requested 64-attempt scale.
#[test]
#[ignore = "requires /dev/fuse; benchmark for orchestrator"]
fn sandbox_64_attempt_setup_teardown_timing() {
    mounts(64);
}
