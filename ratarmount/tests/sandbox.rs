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
        let child = Self::spawn(root.path(), &socket);
        let mut daemon = Self {
            root: Some(root),
            socket,
            child,
        };
        daemon.wait_for_socket();
        daemon
    }

    fn spawn(root: &Path, socket: &Path) -> Child {
        Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .args(["sandbox", "daemon", "--socket"])
            .arg(socket)
            .arg("--state-dir")
            .arg(root.join("state"))
            .args(["--max-attempts", "64", "--timeout", "30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(root.join("daemon.log")).unwrap())
            .spawn()
            .unwrap()
    }

    fn wait_for_socket(&mut self) {
        let log = self.root.as_ref().unwrap().path().join("daemon.log");
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&self.socket).is_err() {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "{}",
                fs::read_to_string(&log).unwrap()
            );
            assert!(Instant::now() < deadline, "daemon socket timeout");
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Stops the daemon with `shutdown` and starts it again on the same state.
    fn restart(&mut self) {
        self.call(json!({"op":"shutdown"}));
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "daemon did not stop");
            thread::sleep(Duration::from_millis(20));
        }
        self.child = Self::spawn(self.root.as_ref().unwrap().path(), &self.socket);
        self.wait_for_socket();
    }

    fn call(&self, request: Value) -> Value {
        let response = self.envelope(request);
        assert_eq!(response["ok"], true, "{response}");
        response["result"].clone()
    }

    /// Sends `request` with its explicit integer `version` of 1 or 2, or 1 when
    /// it has none, and asserts the answer carries that version. Invalid
    /// versions are written raw instead, as the protocol test does.
    fn envelope(&self, mut request: Value) -> Value {
        let version = match request.get("version") {
            None => 1,
            Some(version) if version.as_u64() == Some(1) || version.as_u64() == Some(2) => {
                version.as_u64().unwrap()
            }
            Some(other) => panic!("envelope sends version 1 or 2, not {other}"),
        };
        request["version"] = json!(version);
        let response = self.send_line(&request.to_string());
        assert_eq!(response["version"], version, "{response}");
        response
    }

    fn send_line(&self, line: &str) -> Value {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        writeln!(stream, "{line}").unwrap();
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply).unwrap();
        serde_json::from_str(&reply).unwrap()
    }

    fn requests_log(&self) -> PathBuf {
        self.root
            .as_ref()
            .unwrap()
            .path()
            .join("state/requests.jsonl")
    }

    fn base(&self) {
        let tar = self.root.as_ref().unwrap().path().join("base.tar");
        let mut file = fs::File::create(&tar).unwrap();
        write_ustar_members(
            &mut file,
            &[
                UstarMember {
                    path: "delete-me.txt",
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    xattrs: &[],
                    payload: UstarPayload::File {
                        bytes: b"delete me\n",
                    },
                },
                UstarMember {
                    path: "base.txt",
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    xattrs: &[],
                    payload: UstarPayload::File {
                        bytes: b"original\n",
                    },
                },
            ],
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

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/sandbox/testdata/v1-golden.jsonl"
);
const MAX_REQUEST: usize = 1024 * 1024;

/// Waits until the daemon has read every byte written to `stream` (Linux
/// `SIOCOUTQ`: the sender's bytes the peer has not consumed).
fn wait_consumed(stream: &UnixStream) {
    use std::os::fd::AsRawFd;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut unread: libc::c_int = 0;
        // SAFETY: SIOCOUTQ (TIOCOUTQ) writes one int to the pointer.
        let status = unsafe { libc::ioctl(stream.as_raw_fd(), libc::TIOCOUTQ as _, &mut unread) };
        assert_eq!(status, 0, "{}", std::io::Error::last_os_error());
        if unread == 0 {
            return;
        }
        assert!(Instant::now() < deadline, "the daemon stopped reading");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Writes `line` and its newline so that the daemon's read that takes the
/// line's last byte also takes the newline: everything but that byte first,
/// then, once the daemon has consumed it, the byte and the newline in one
/// two-byte write, which no short send can split (Keystone N4, Codex sweep 1).
fn write_terminated(stream: &mut UnixStream, line: &[u8]) {
    let (head, last) = line.split_at(line.len() - 1);
    stream.write_all(head).unwrap();
    wait_consumed(stream);
    assert_eq!(stream.write(&[last[0], b'\n']).unwrap(), 2);
}

/// Regression: the golden's envelope-error replies come from the real `serve`,
/// not only from the per-line path the unit replay drives (Claude sweep 4 N1).
#[test]
fn regression_sandbox_envelope_errors_match_golden_over_socket() {
    let daemon = Daemon::start();
    let entries: Vec<Value> = fs::read_to_string(GOLDEN)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let unsupported = entries.iter().find(|e| e["request"] == "{}").unwrap()["response"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut checked = 0;
    for entry in entries.iter().filter(|e| e["envelope"] == true) {
        let line = match entry["generated"].as_u64() {
            Some(size) => vec![b'x'; size as usize],
            None => entry["request"].as_str().unwrap().as_bytes().to_vec(),
        };
        let stream = UnixStream::connect(&daemon.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        // A terminated oversize line must reach serve's terminated branch, as
        // in the unit replay, never its unterminated one.
        write_terminated(reader.get_mut(), &line);
        let mut reply = String::new();
        reader.read_line(&mut reply).unwrap();
        assert_eq!(reply, entry["response"].as_str().unwrap(), "{entry}");
        // Every terminated line keeps its connection open.
        reader.get_mut().write_all(b"{}\n").unwrap();
        let mut next = String::new();
        reader.read_line(&mut next).unwrap();
        assert_eq!(next, unsupported);
        checked += 1;
    }
    // {}, version 3, "1", 1.0, malformed JSON, and lines of 1 MiB and 1 MiB + 1.
    assert_eq!(checked, 7);
    // Exactly one byte over the limit and unterminated: serve must read all of
    // it to pass the limit, answers, and closes with nothing unread, so the
    // client sees a clean EOF however the write is split.
    let mut stream = UnixStream::connect(&daemon.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream.write_all(&vec![b'x'; MAX_REQUEST + 1]).unwrap();
    let mut reply = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut reply).unwrap();
    assert_eq!(
        String::from_utf8(reply).unwrap(),
        "{\"version\":1,\"ok\":false,\"error\":{\"code\":\"invalid_request\",\"message\":\"request exceeds 1 MiB\"}}\n"
    );
}

/// Regression: `Daemon::envelope` really sends version 2: the daemon answers
/// v2 requests, accepted or refused, in v2 envelopes (old blocker 6).
#[test]
fn regression_sandbox_v2_envelopes_over_socket() {
    let daemon = Daemon::start();
    assert_eq!(daemon.call(json!({"version":2, "op":"list"})), json!([]));
    let refused = daemon.envelope(json!({"version":2, "op":"new", "base":"task", "lowers":["l"]}));
    assert_eq!(refused["error"]["code"], "invalid_request", "{refused}");
    assert_eq!(daemon.call(json!({"op":"list"})), json!([]));
}

/// Makes `new` of base `task` fail with `mount_failed` before any FUSE work.
fn corrupt_prepared_index(daemon: &Daemon) {
    let cache = daemon
        .root
        .as_ref()
        .unwrap()
        .path()
        .join("state/indexes/task");
    let index = fs::read_dir(&cache)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "sqlite"))
        .unwrap();
    fs::write(&index, b"invalid prepared SQLite index").unwrap();
}

/// The attempt a `mount_failed` message names.
fn failed_attempt(response: &Value) -> String {
    assert_eq!(response["error"]["code"], "mount_failed", "{response}");
    let message = response["error"]["message"].as_str().unwrap();
    message
        .strip_prefix("attempt ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap()
        .to_owned()
}

/// Regression: a v2 `request_id` over a real socket, without FUSE: refused in
/// v1; a `retryable` outcome runs again under the same ID and body, another
/// body conflicts, and the binding survives a restart.
#[test]
fn regression_sandbox_v2_request_id_over_socket() {
    let mut daemon = Daemon::start();
    daemon.base();
    corrupt_prepared_index(&daemon);
    let refused = daemon.envelope(json!({"op":"new", "base":"task", "request_id":"r1"}));
    assert_eq!(refused["error"]["code"], "invalid_request", "{refused}");
    let request = json!({"version":2, "op":"new", "base":"task", "request_id":"r1"});
    let first = failed_attempt(&daemon.envelope(request.clone()));
    let second = failed_attempt(&daemon.envelope(request.clone()));
    assert_ne!(first, second, "a retryable record runs again");
    let other = json!({"version":2, "op":"new", "base":"task", "count":2, "request_id":"r1"});
    assert_eq!(
        daemon.envelope(other.clone())["error"]["code"],
        "idempotency_conflict"
    );
    assert_eq!(daemon.call(json!({"op":"list"})), json!([]));
    daemon.restart();
    assert_eq!(
        daemon.envelope(other)["error"]["code"],
        "idempotency_conflict"
    );
    let third = failed_attempt(&daemon.envelope(request));
    assert!(third != first && third != second);
    let meta = fs::symlink_metadata(daemon.requests_log()).unwrap();
    assert!(meta.is_file());
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
}

/// Whether the prepared-index FUSE tests run; with
/// `RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE=1` a missing prerequisite fails.
fn prepared_fuse() -> bool {
    let required = std::env::var_os("RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    prepared_fuse_check(
        required,
        Path::new("/dev/fuse").exists(),
        Command::new("fusermount3")
            .arg("--version")
            .output()
            .is_ok(),
    )
    .expect("required prepared-index FUSE acceptance prerequisite missing")
}

/// Regression: a `done` request ID replays its result instead of mounting a
/// second batch, also after a restart that discarded the attempts.
#[test]
fn regression_sandbox_v2_request_id_replay_fuse() {
    if !prepared_fuse() {
        return;
    }
    let mut daemon = Daemon::start();
    daemon.base();
    let request = json!({"version":2, "op":"new", "base":"task", "count":2, "request_id":"r2"});
    let first = daemon.call(request.clone());
    assert_eq!(first.as_array().unwrap().len(), 2);
    assert_eq!(daemon.call(request.clone()), first);
    assert_eq!(
        daemon.call(json!({"op":"list"})).as_array().unwrap().len(),
        2
    );
    daemon.restart();
    assert_eq!(daemon.call(request), first);
    assert_eq!(daemon.call(json!({"op":"list"})), json!([]));
}

/// Regression: two clients send the same request ID and body while both are
/// in flight. The serial serve loop (one daemon under `daemon.lock`) runs one
/// batch; the other client gets its stored result byte for byte (Keystone N1).
#[test]
fn regression_sandbox_v2_request_id_in_flight_retry_fuse() {
    if !prepared_fuse() {
        return;
    }
    let daemon = Daemon::start();
    daemon.base();
    let line = r#"{"version":2,"op":"new","base":"task","count":3,"request_id":"inflight"}"#;
    let streams: Vec<_> = (0..2)
        .map(|_| {
            let mut stream = UnixStream::connect(&daemon.socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(60)))
                .unwrap();
            writeln!(stream, "{line}").unwrap();
            stream
        })
        .collect();
    let replies: Vec<String> = streams
        .into_iter()
        .map(|stream| {
            let mut reply = String::new();
            BufReader::new(stream).read_line(&mut reply).unwrap();
            reply
        })
        .collect();
    assert_eq!(replies[0], replies[1]);
    let reply: Value = serde_json::from_str(&replies[0]).unwrap();
    assert_eq!(reply["version"], 2);
    assert_eq!(reply["result"].as_array().unwrap().len(), 3, "{reply}");
    assert_eq!(
        daemon.call(json!({"op":"list"})).as_array().unwrap().len(),
        3
    );
    // One running and one done line: the second request never ran.
    let states: Vec<String> = fs::read_to_string(daemon.requests_log())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record["id"] == "inflight")
        .map(|record| record["t"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(states, ["running", "done"]);
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

fn shared_snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            (path.file_name().unwrap() != "prepare.log")
                .then(|| (path.file_name().unwrap().into(), fs::read(path).unwrap()))
        })
        .collect()
}

fn prepared_fuse_check(required: bool, device: bool, helper: bool) -> Result<bool, &'static str> {
    let reason = if !device {
        Some("/dev/fuse")
    } else if !helper {
        Some("fusermount3")
    } else {
        None
    };
    match reason {
        Some(reason) if required => Err(reason),
        Some(reason) => {
            eprintln!("skip: prepared-index mount integration requires {reason}");
            Ok(false)
        }
        None => Ok(true),
    }
}

/// Regression: the required Linux acceptance mode must fail instead of skipping mounts.
#[test]
fn regression_prepared_index_fuse_requirement_refuses_skip() {
    for (device, helper) in [(false, false), (false, true), (true, false)] {
        assert!(prepared_fuse_check(true, device, helper).is_err());
        assert!(!prepared_fuse_check(false, device, helper).unwrap());
    }
    assert!(prepared_fuse_check(true, true, true).unwrap());
}

/// Regression: three simultaneous -w processes must isolate same-member writes.
#[test]
fn regression_prepared_index_three_writable_workers_are_isolated() {
    let required = std::env::var_os("RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    if !prepared_fuse_check(
        required,
        Path::new("/dev/fuse").exists(),
        Command::new("fusermount3")
            .arg("--version")
            .output()
            .is_ok(),
    )
    .expect("required prepared-index FUSE acceptance prerequisite missing")
    {
        return;
    }
    let daemon = Daemon::start();
    daemon.base();
    let root = daemon.root.as_ref().unwrap().path();
    let base = root.join("base.tar");
    let cache = root.join("state/indexes/task");
    let original = fs::read(&base).unwrap();
    let before = shared_snapshot(&cache);
    let attempts = daemon.call(json!({"op":"new", "base":"task", "count":3, "overlay":"disk"}));
    let attempts = attempts.as_array().unwrap();
    assert_eq!(attempts.len(), 3);
    let mut paths = std::collections::BTreeSet::new();
    let mut overlays = std::collections::BTreeSet::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut writers = Vec::new();
    for (i, attempt) in attempts.iter().enumerate() {
        assert_eq!(attempt["status"], "ready");
        let path = PathBuf::from(attempt["path"].as_str().unwrap());
        assert!(path.is_absolute());
        assert!(paths.insert(path.clone()));
        assert!(overlays.insert(attempt["overlay_dir"].as_str().unwrap()));
        let barrier = barrier.clone();
        let tx = tx.clone();
        writers.push(thread::spawn(move || {
            barrier.wait();
            fs::write(path.join("base.txt"), format!("worker-{i}\n")).unwrap();
            fs::write(
                path.join(format!("worker-{i}.txt")),
                format!("addition-{i}\n"),
            )
            .unwrap();
            if i == 0 {
                fs::remove_file(path.join("delete-me.txt")).unwrap();
            }
            tx.send(i).unwrap();
        }));
    }
    drop(tx);
    for _ in 0..3 {
        rx.recv_timeout(Duration::from_secs(20))
            .expect("concurrent FUSE writes timed out");
    }
    for writer in writers {
        writer.join().unwrap();
    }
    for (i, attempt) in attempts.iter().enumerate() {
        let path = Path::new(attempt["path"].as_str().unwrap());
        assert_eq!(
            fs::read(path.join("base.txt")).unwrap(),
            format!("worker-{i}\n").as_bytes()
        );
        assert_eq!(
            fs::read(path.join(format!("worker-{i}.txt"))).unwrap(),
            format!("addition-{i}\n").as_bytes()
        );
        assert_eq!(path.join("delete-me.txt").exists(), i != 0);
        for j in 0..3 {
            assert_eq!(path.join(format!("worker-{j}.txt")).exists(), i == j);
        }
        let diff = daemon.call(json!({"op":"diff", "id":attempt["id"], "git":true}));
        let patch = diff["patch"].as_str().unwrap();
        assert!(patch.contains(&format!("+worker-{i}\n")), "{patch}");
        let stats = daemon.call(json!({"op":"stats", "id":attempt["id"]}));
        assert_eq!(stats["files_present"], 2, "{stats}");
    }
    assert_eq!(fs::read(&base).unwrap(), original);
    assert_eq!(
        shared_snapshot(&cache),
        before,
        "shared index changed while workers alive"
    );
    daemon.call(json!({"op":"destroy", "base":"task"}));
    assert_eq!(daemon.call(json!({"op":"list"})), json!([]));
    for path in paths {
        assert!(!path.exists());
    }
    assert_eq!(shared_snapshot(&cache), before);
    // Remount the same preparation with another independent batch.
    let remount = daemon.call(json!({"op":"new", "base":"task", "count":1}));
    let path = Path::new(remount[0]["path"].as_str().unwrap());
    assert_eq!(fs::read(path.join("base.txt")).unwrap(), b"original\n");
    assert!(path.join("delete-me.txt").exists());
    daemon.call(json!({"op":"destroy", "base":"task"}));
    assert_eq!(shared_snapshot(&cache), before);
    assert_eq!(fs::read(&base).unwrap(), original);
}

/// Regression: detected invalid cache preparation must fail before FUSE, unchanged.
#[test]
fn regression_prepared_index_sandbox_worker_refuses_invalid_cache() {
    for fault in ["missing", "corrupt", "size", "backend", "wal", "journal"] {
        let daemon = Daemon::start();
        daemon.base();
        let root = daemon.root.as_ref().unwrap().path();
        let cache = root.join("state/indexes/task");
        let base = root.join("base.tar");
        let index = fs::read_dir(&cache)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "sqlite"))
            .unwrap();
        let writer = if fault == "wal" {
            let writer = rusqlite::Connection::open(&index).unwrap();
            writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; INSERT INTO metadata(key,value) VALUES('pending','not checkpointed')").unwrap();
            Some(writer)
        } else {
            match fault {
                "missing" => fs::remove_file(&index).unwrap(),
                "corrupt" => fs::write(&index, b"invalid prepared SQLite index").unwrap(),
                "journal" => fs::write(
                    format!("{}-journal", index.display()),
                    b"unfinished journal",
                )
                .unwrap(),
                "size" | "backend" => {
                    let writer = rusqlite::Connection::open(&index).unwrap();
                    if fault == "size" {
                        writer.execute("UPDATE metadata SET value = json_set(value, '$.st_size', 1) WHERE key = 'tarstats'", []).unwrap();
                    } else {
                        writer.execute("UPDATE metadata SET value = 'wrong-backend' WHERE key = 'backendName'", []).unwrap();
                    }
                }
                _ => unreachable!(),
            }
            None
        };
        let before = shared_snapshot(&cache);
        let original = fs::read(&base).unwrap();
        let response = daemon.envelope(json!({"op":"new", "base":"task", "count":1}));
        assert_eq!(response["ok"], false, "{fault}: {response}");
        assert_eq!(
            response["error"]["code"], "mount_failed",
            "{fault}: {response}"
        );
        let message = response["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("index") || message.contains("prepar"),
            "{fault}: {message}"
        );
        assert!(!message.contains("/dev/fuse"), "{fault}: {message}");
        assert_eq!(daemon.call(json!({"op":"list"})), json!([]));
        assert_eq!(
            shared_snapshot(&cache),
            before,
            "{fault}: invalid shared state was changed"
        );
        assert_eq!(fs::read(&base).unwrap(), original);
        drop(writer);
    }
}

fn strict_no_mount(base: &Path, cache: &Path, bind: &str) {
    let out = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args([
            "--no-mount",
            "--no-recreate-index",
            "--no-file-versions",
            "--index-folders",
        ])
        .arg(serde_json::to_string(&[cache]).unwrap())
        .args(["--bind", bind])
        .arg(base)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn tiny_tar(path: &Path, payload: &[u8]) {
    let mut file = fs::File::create(path).unwrap();
    write_ustar_members(
        &mut file,
        &[UstarMember {
            path: "content",
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
            payload: UstarPayload::File { bytes: payload },
        }],
    )
    .unwrap();
    write_tar_eof(&mut file).unwrap();
}

/// Regression: the actual supervisor preparer must finalize every selected artifact.
#[test]
fn regression_prepared_index_prepare_finalizes_each_selected_source() {
    let daemon = Daemon::start();
    let root = daemon.root.as_ref().unwrap().path();
    let base = root.join("base.tar.zst");
    let second = root.join("second.tar.zst");
    for path in [&base, &second] {
        let plain = root.join("temporary.tar");
        tiny_tar(&plain, b"prepared source\n");
        fs::write(
            path,
            zstd::encode_all(fs::File::open(&plain).unwrap(), 1).unwrap(),
        )
        .unwrap();
        fs::remove_file(plain).unwrap();
    }
    let cache = root.join("state/indexes/multi");
    fs::create_dir_all(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    let unrelated = rusqlite::Connection::open(cache.join("unrelated.sqlite")).unwrap();
    unrelated.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE untouched(value TEXT); INSERT INTO untouched VALUES('pending unrelated WAL')").unwrap();
    let unrelated_before = shared_snapshot(&cache);
    let bind = format!("/other={}", second.display());
    daemon.call(
        json!({"op":"create_base", "name":"multi", "source":base, "options":{"binds":[bind]}}),
    );
    let cache = root.join("state/indexes/multi");
    let before = shared_snapshot(&cache);
    for (name, bytes) in &unrelated_before {
        assert_eq!(
            before.get(name),
            Some(bytes),
            "unrelated SQLite changed during preparation"
        );
    }
    assert_eq!(
        before
            .keys()
            .filter(|p| p.extension().is_some_and(|e| e == "sqlite")
                && p.file_name().unwrap() != "unrelated.sqlite")
            .count(),
        2
    );
    for path in before
        .keys()
        .filter(|p| !p.to_string_lossy().starts_with("unrelated.sqlite"))
    {
        if path.extension().is_some_and(|e| e == "sqlite") {
            let db = ratarmount_index::SqliteIndex::open_prepared(cache.join(path)).unwrap();
            assert!(db.file_count().unwrap() > 0);
        }
        assert!(!path.to_string_lossy().ends_with("-wal"));
    }
    strict_no_mount(&base, &cache, &bind);
    assert_eq!(shared_snapshot(&cache), before);
    // Classified no-mount preparation exercises the second artifact handoff arm.
    let out = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["--no-mount", "--no-file-versions", "--index-folders"])
        .arg(serde_json::to_string(&[&cache]).unwrap())
        .args(["--bind", &bind, "-w"])
        .arg(root.join("classified-overlay"))
        .arg(&base)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    strict_no_mount(&base, &cache, &bind);
    assert_eq!(shared_snapshot(&cache), before);
    drop(unrelated);
}

/// Regression: an unindexed bind must require/finalize no sidecar of its own.
#[test]
fn regression_prepared_index_mixed_tar_and_unindexed_bind() {
    let daemon = Daemon::start();
    let root = daemon.root.as_ref().unwrap().path();
    let base = root.join("base.tar");
    let plain = root.join("plain.txt");
    tiny_tar(&base, b"base\n");
    fs::write(&plain, b"plain bind bytes\n").unwrap();
    let candidate = PathBuf::from(format!("{}.index.sqlite", plain.display()));
    fs::write(&candidate, b"unrelated candidate must stay untouched").unwrap();
    let bind = format!("/plain={}", plain.display());
    daemon.call(
        json!({"op":"create_base", "name":"mixed", "source":base, "options":{"binds":[bind]}}),
    );
    let cache = root.join("state/indexes/mixed");
    let before = shared_snapshot(&cache);
    assert_eq!(before.len(), 1);
    strict_no_mount(&base, &cache, &bind);
    let mut options = ratarmount_core::OpenOptions {
        read_only_index: true,
        write_index: false,
        index_folders: vec![cache.clone()],
        ..Default::default()
    };
    let bundle = ratarmount_session::factory::build_mount_source_with_bindings(
        std::slice::from_ref(&base),
        &mut options,
        false,
        Default::default(),
        ratarmount_session::factory::SourceBindings {
            binds: vec![bind.parse().unwrap()],
            ..Default::default()
        },
    )
    .unwrap();
    use std::io::Read;
    let info = bundle.source.lookup("/plain/plain.txt", 0).unwrap();
    let mut reader = bundle.source.open(&info, 0).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"plain bind bytes\n");
    drop(reader);
    drop(bundle);
    assert_eq!(shared_snapshot(&cache), before);
    assert_eq!(
        fs::read(candidate).unwrap(),
        b"unrelated candidate must stay untouched"
    );
}
