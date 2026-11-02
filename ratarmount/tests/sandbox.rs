//! Sandbox protocol over a real socket; FUSE tests skip without the device.
#![cfg(target_os = "linux")]

#[path = "support/token.rs"]
mod token;
#[path = "support/unmount.rs"]
mod unmount;

use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon {
    root: Option<tempfile::TempDir>,
    socket: PathBuf,
    child: Child,
    /// Added to the daemon's environment, which its mount children and its
    /// unmount helper inherit.
    env: Vec<(&'static str, OsString)>,
}

impl Daemon {
    fn start() -> Self {
        Self::start_with_env(Vec::new())
    }

    /// `start` with `env` added to the daemon's environment.
    fn start_with_env(env: Vec<(&'static str, OsString)>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("api.sock");
        let child = Self::spawn(root.path(), &socket, &env);
        let mut daemon = Self {
            root: Some(root),
            socket,
            child,
            env,
        };
        daemon.wait_for_socket();
        daemon
    }

    fn spawn(root: &Path, socket: &Path, env: &[(&'static str, OsString)]) -> Child {
        Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .args(["sandbox", "daemon", "--socket"])
            .arg(socket)
            .arg("--state-dir")
            .arg(root.join("state"))
            .args(["--max-attempts", "64", "--timeout", "30"])
            // Children cache lower bundles here, not in the developer's cache.
            .env("XDG_CACHE_HOME", root.join("cache"))
            .envs(env.iter().map(|(key, value)| (*key, value)))
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
        self.child = Self::spawn(self.root.as_ref().unwrap().path(), &self.socket, &self.env);
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
            } else {
                // Sealed layers and bundle cache entries have no write
                // bits, which TempDir's removal needs.
                make_writable(root.path());
            }
        }
    }
}

/// Restores write access under `path` so `TempDir` can remove the sealed
/// (read-only) trees a test leaves. Runs from a destructor, so it never
/// panics, and it never descends into another filesystem (a mount that a
/// failure left behind).
fn make_writable(path: &Path) {
    if let Ok(root) = fs::symlink_metadata(path) {
        make_writable_under(path, root.dev());
    }
}

fn make_writable_under(path: &Path, dev: u64) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() || meta.dev() != dev {
        return;
    }
    let extra = if meta.is_dir() { 0o700 } else { 0o200 };
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(meta.mode() | extra));
    if meta.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_writable_under(&entry.path(), dev);
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
    let refused = daemon.envelope(json!({"version":2, "op":"new", "base":"task", "retain":true}));
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

/// The factory's source of `tar`, opened as the supervisor's base is, with
/// its index kept in memory (no sidecar beside the tar).
fn tar_source(tar: &Path) -> ratarmount_session::factory::MountBundle {
    let mut options = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..Default::default()
    };
    ratarmount_session::factory::build_mount_source_with_bindings(
        &[tar.to_path_buf()],
        &mut options,
        false,
        Default::default(),
        Default::default(),
    )
    .unwrap()
}

/// A layer sealed over `tar` and `lowers`, built without mounting: created
/// over the tar's factory source, repaired, and sealed with an archive token
/// of the tar, so it records the tar's strong digest.
fn sealed_layer(tar: &Path, dir: &Path, lowers: &[&Path], files: &[(&str, &str)]) {
    use ratarmount_compositing::{compose_stack, Immutability, LowerLayerRecord, OverlayMeta};
    let source = tar_source(tar);
    let layers: Vec<_> = lowers
        .iter()
        .map(|path| (path.to_path_buf(), Immutability::Immutable))
        .collect();
    let view = compose_stack(source.source.clone(), &layers).unwrap();
    let records = lowers
        .iter()
        .map(|path| {
            let meta = OverlayMeta::read(path).unwrap().unwrap();
            LowerLayerRecord {
                path: path.canonicalize().unwrap(),
                layer_digest: meta.get("layer_digest").unwrap().into(),
                sealed_at: meta.get("sealed_at").unwrap().into(),
            }
        })
        .collect();
    let overlay = token::overlay_over(view.clone(), dir, tar.to_str().unwrap(), records).unwrap();
    drop(overlay);
    for (path, content) in files {
        fs::write(dir.join(path), content).unwrap();
    }
    ratarmount_compositing::overlay_fsck::fsck(dir, true).unwrap();
    let token = token::ClassifiedBaseOver::archive(view.clone(), tar);
    ratarmount_compositing::overlay_seal::seal(dir, &token, view).unwrap();
    let meta = OverlayMeta::read(dir).unwrap().unwrap();
    assert_eq!(meta.get("base_kind"), Some("archive"));
    assert_eq!(meta.base_digest_kind(), Some("strong"));
}

/// The layers F1 and F2 use over the tar `Daemon::base()` registers: `A`
/// over the tar, `B` over `[A]` (disjoint changes), and `B` packed with the
/// real binary (pack defaults to the recorded base and lowers).
struct Layers {
    a: PathBuf,
    b: PathBuf,
    bundle: PathBuf,
}

/// F2's layers, built without mounting (plan §7 F2).
fn layers(daemon: &Daemon) -> Layers {
    let root = daemon.root.as_ref().unwrap().path();
    let tar = root.join("base.tar");
    let dir = root.join("layers");
    fs::create_dir(&dir).unwrap();
    let a = dir.join("a");
    sealed_layer(&tar, &a, &[], &[("a.txt", "from a\n")]);
    let b = dir.join("b");
    sealed_layer(&tar, &b, &[&a], &[("b.txt", "from b\n")]);
    let bundle = dir.join("b.tar.zst");
    pack(&b, &bundle);
    Layers { a, b, bundle }
}

/// F1's layers, authored by the real binary (plan §7 F1).
fn authored_layers(daemon: &Daemon) -> Layers {
    let root = daemon.root.as_ref().unwrap().path();
    let tar = root.join("base.tar");
    let dir = root.join("layers");
    fs::create_dir(&dir).unwrap();
    let a = dir.join("a");
    authored_layer(&tar, &a, &[], &[("a.txt", "from a\n")]);
    let b = dir.join("b");
    authored_layer(&tar, &b, &[&a], &[("b.txt", "from b\n")]);
    let bundle = dir.join("b.tar.zst");
    pack(&b, &bundle);
    Layers { a, b, bundle }
}

/// `ratarmount overlay pack DIR BUNDLE`, which defaults to the recorded base
/// and lowers.
fn pack(dir: &Path, bundle: &Path) {
    let packed = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "pack"])
        .arg(dir)
        .arg(bundle)
        .output()
        .unwrap();
    assert!(packed.status.success(), "{packed:?}");
}

/// A foreground `-w` mount of the real binary that authors a layer:
/// `finish` unmounts it and requires a clean exit; a failing test detaches
/// it and kills the child instead.
struct Authoring {
    child: Child,
    mnt: PathBuf,
}

impl Authoring {
    fn finish(mut self) {
        unmount::unmount_within(&self.mnt, Duration::from_secs(10), "authoring mount").unwrap();
        let status = self.child.wait().unwrap();
        assert!(status.success(), "authoring mount exited {status}");
        std::mem::forget(self);
    }
}

impl Drop for Authoring {
    fn drop(&mut self) {
        let _ = Command::new("fusermount3")
            .arg("-uz")
            .arg(&self.mnt)
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A layer authored with the real binary only: `top` is mounted with `-w`
/// over `tar` and `lowers`, `files` are written through the mount, the mount
/// is unmounted, and `overlay fsck --repair` and `overlay seal` (which
/// default to the recorded base and lowers) finish it. So `B`'s
/// `lower_layers` row is what a mount over `[A]` records.
fn authored_layer(tar: &Path, top: &Path, lowers: &[&Path], files: &[(&str, &str)]) {
    let dir = top.parent().unwrap();
    let home = dir.join("authoring-home");
    fs::create_dir_all(&home).unwrap();
    let ratarmount = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command
            .env("HOME", &home)
            .env("XDG_CACHE_HOME", home.join("cache"));
        command
    };
    let mnt = dir.join(format!(
        "{}-mnt",
        top.file_name().unwrap().to_string_lossy()
    ));
    fs::create_dir(&mnt).unwrap();
    let mut mount = ratarmount();
    mount.args(["-f", "--passthrough", "off", "--index-file", ":memory:"]);
    for lower in lowers {
        mount.arg("--lower").arg(lower);
    }
    let child = mount
        .arg("-w")
        .arg(top)
        .arg(tar)
        .arg(&mnt)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut authoring = Authoring {
        child,
        mnt: mnt.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while !mnt.join("base.txt").exists() {
        assert!(
            authoring.child.try_wait().unwrap().is_none(),
            "authoring mount exited"
        );
        assert!(Instant::now() < deadline, "authoring mount timeout");
        thread::sleep(Duration::from_millis(50));
    }
    for (path, content) in files {
        fs::write(mnt.join(path), content).unwrap();
    }
    authoring.finish();
    for verb in [&["fsck", "--repair"][..], &["seal"]] {
        let out = ratarmount()
            .arg("overlay")
            .arg(verb[0])
            .arg(top)
            .args(&verb[1..])
            .output()
            .unwrap();
        assert!(out.status.success(), "overlay {verb:?}: {out:?}");
    }
    let meta = ratarmount_compositing::OverlayMeta::read(top)
        .unwrap()
        .unwrap();
    assert_eq!(meta.get("base_kind"), Some("archive"));
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    // The stack the mount recorded, which the supervisor's stack check reads.
    let recorded: Vec<Value> = meta
        .get("lower_layers")
        .map_or_else(Vec::new, |row| serde_json::from_str(row).unwrap());
    let recorded: Vec<_> = recorded
        .iter()
        .map(|record| record["layer_digest"].as_str().unwrap().to_owned())
        .collect();
    let expected: Vec<_> = lowers.iter().map(|lower| layer_digest(lower)).collect();
    assert_eq!(recorded, expected);
}

fn layer_digest(dir: &Path) -> String {
    ratarmount_compositing::OverlayMeta::read(dir)
        .unwrap()
        .unwrap()
        .get("layer_digest")
        .unwrap()
        .to_owned()
}

/// Every file below `dir` and its bytes.
fn tree_bytes(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(tree_bytes(&path));
        } else {
            files.insert(path.clone(), fs::read(&path).unwrap());
        }
    }
    files
}

fn root_xattr(mount: &Path, name: &str) -> String {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(mount.as_os_str().as_bytes()).unwrap();
    let name = std::ffi::CString::new(name).unwrap();
    let mut buffer = vec![0u8; 64 * 1024];
    // SAFETY: both names are NUL-terminated; the buffer outlives the call.
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    assert!(n >= 0, "getxattr: {}", std::io::Error::last_os_error());
    buffer.truncate(n as usize);
    String::from_utf8(buffer).unwrap()
}

/// Regression (R1b F1): a v2 `new` over `[A, bundle(B)]` mounts each attempt
/// on base + A + B, with writes only in its own top; `diff` shows only the
/// top's changes, against base + lowers (an edit of A's file is a change of
/// it, not a new file; sweep 2); the mount root names both layers; the lowers
/// are unchanged. The layers are authored by the real binary (`-w` mounts,
/// `overlay fsck --repair`, `overlay seal`, `overlay pack`; sweep 3).
#[test]
fn regression_sandbox_v2_layered_attempt_fuse() {
    if !prepared_fuse() {
        return;
    }
    let daemon = Daemon::start();
    daemon.base();
    let Layers { a, b, bundle } = authored_layers(&daemon);
    let (layer_before, bundle_before) = (tree_bytes(&a), fs::read(&bundle).unwrap());
    let digests = [layer_digest(&a), layer_digest(&b)];
    let request =
        json!({"version": 2, "op": "new", "base": "task", "count": 2, "lowers": [a, bundle]});
    let attempts = daemon.call(request);
    let attempts = attempts.as_array().unwrap();
    assert_eq!(attempts.len(), 2);
    for (i, attempt) in attempts.iter().enumerate() {
        let path = Path::new(attempt["path"].as_str().unwrap());
        assert_eq!(fs::read(path.join("base.txt")).unwrap(), b"original\n");
        assert_eq!(fs::read(path.join("a.txt")).unwrap(), b"from a\n");
        assert_eq!(fs::read(path.join("b.txt")).unwrap(), b"from b\n");
        fs::write(path.join(format!("top-{i}.txt")), format!("change-{i}\n")).unwrap();
        fs::write(path.join("a.txt"), format!("edited by {i}\n")).unwrap();
        let layers: Value =
            serde_json::from_str(&root_xattr(path, "user.ratarmount.layers")).unwrap();
        let taken: Vec<_> = layers
            .as_array()
            .unwrap()
            .iter()
            .map(|layer| layer["layer_digest"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(taken, digests);
    }
    for (i, attempt) in attempts.iter().enumerate() {
        let other = Path::new(attempts[1 - i]["path"].as_str().unwrap());
        assert!(!other.join(format!("top-{i}.txt")).exists());
        assert_eq!(
            fs::read(other.join("a.txt")).unwrap(),
            format!("edited by {}\n", 1 - i).as_bytes()
        );
        assert!(!a.join(format!("top-{i}.txt")).exists());
        for version in [1, 2] {
            let diff = daemon
                .call(json!({"version": version, "op": "diff", "id": attempt["id"], "git": true}));
            let patch = diff["patch"].as_str().unwrap();
            assert!(patch.contains(&format!("+change-{i}\n")), "{patch}");
            // Against the bare base, a.txt would be a new file.
            assert!(
                patch.contains(&format!("-from a\n+edited by {i}\n")),
                "{patch}"
            );
            assert_eq!(patch.matches("diff --git").count(), 2, "{patch}");
        }
    }
    daemon.call(json!({"op": "destroy", "base": "task"}));
    assert_eq!(daemon.call(json!({"op": "list"})), json!([]));
    assert_eq!(tree_bytes(&a), layer_before);
    assert_eq!(fs::read(&bundle).unwrap(), bundle_before);
    assert!(ratarmount_compositing::OverlayMeta::read(&a)
        .unwrap()
        .unwrap()
        .layer_sealed());
}

/// Regression (R1b F2, old blocker 2): the real daemon refuses a lower whose
/// recorded prefix is missing, as a bundle and as a directory, before any
/// attempt exists.
#[test]
fn regression_sandbox_v2_lower_prefix_refused_over_socket() {
    let daemon = Daemon::start();
    daemon.base();
    let Layers { b, bundle, .. } = layers(&daemon);
    for lower in [&bundle, &b] {
        let reply = daemon.envelope(
            json!({"version": 2, "op": "new", "base": "task", "count": 2, "lowers": [lower]}),
        );
        assert_eq!(reply["error"]["code"], "invalid_request", "{reply}");
        let message = reply["error"]["message"].as_str().unwrap();
        assert!(message.contains(lower.to_str().unwrap()), "{message}");
        assert!(message.contains("was sealed over the lowers"), "{message}");
    }
    let attempts = daemon.root.as_ref().unwrap().path().join("state/attempts");
    assert_eq!(fs::read_dir(attempts).unwrap().count(), 0);
    assert_eq!(daemon.call(json!({"op": "list"})), json!([]));
}

/// Regression (R1b F3): a v2 `new` with a journal writes
/// `attempts/ID/journal.jsonl` naming the attempt's mount; marks and
/// summaries work on it, excluded paths are not recorded, and `destroy`
/// removes it.
#[test]
fn regression_sandbox_v2_journal_fuse() {
    if !prepared_fuse() {
        return;
    }
    let daemon = Daemon::start();
    daemon.base();
    let attempts = daemon.call(json!({
        "version": 2, "op": "new", "base": "task",
        "journal": {"exclude": ["skip/**"], "reads": "first"}
    }));
    let path = PathBuf::from(attempts[0]["path"].as_str().unwrap());
    let journal = path.parent().unwrap().join("journal.jsonl");
    let header: Value = serde_json::from_str(
        fs::read_to_string(&journal)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["mount"], path.to_str().unwrap(), "{header}");
    let marked = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["journal", "mark"])
        .arg(&path)
        .arg("turn 1")
        .output()
        .unwrap();
    assert!(marked.status.success(), "{marked:?}");
    assert_eq!(fs::read(path.join("base.txt")).unwrap(), b"original\n");
    fs::create_dir(path.join("skip")).unwrap();
    fs::write(path.join("skip/x"), b"excluded\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let summary = loop {
        let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .args(["journal", "summarize"])
            .arg(&journal)
            .arg("--json")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        if summary["reads_by_mark"]["turn 1"]
            .as_array()
            .is_some_and(|paths| paths.contains(&json!("base.txt")))
        {
            break summary;
        }
        assert!(Instant::now() < deadline, "no flushed read: {summary}");
        thread::sleep(Duration::from_millis(50));
    };
    assert!(summary["paths"].get("skip/x").is_none(), "{summary}");
    for line in fs::read_to_string(&journal).unwrap().lines() {
        let record: Value = serde_json::from_str(line).unwrap();
        assert_ne!(record["path"], "skip/x", "{line}");
    }
    daemon.call(json!({"op": "destroy", "id": attempts[0]["id"]}));
    assert!(!journal.exists());
}

/// Regression (R1b F4): a lower sealed over another tar records that tar's
/// strong digest; the child refuses it at mount (its strong-digest message),
/// so `new` is `mount_failed` and the batch is rolled back.
#[test]
fn regression_sandbox_v2_lower_other_base_fuse() {
    if !prepared_fuse() {
        return;
    }
    let daemon = Daemon::start();
    daemon.base();
    let root = daemon.root.as_ref().unwrap().path();
    let other = root.join("other.tar");
    tiny_tar(&other, b"another base\n");
    let lower = root.join("other-layer");
    sealed_layer(&other, &lower, &[], &[("a.txt", "from a\n")]);
    let reply = daemon.envelope(
        json!({"version": 2, "op": "new", "base": "task", "count": 2, "lowers": [lower]}),
    );
    assert_eq!(reply["error"]["code"], "mount_failed", "{reply}");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.contains("was sealed against"), "{message}");
    assert!(message.contains(lower.to_str().unwrap()), "{message}");
    assert_eq!(daemon.call(json!({"op": "list"})), json!([]));
    assert_eq!(
        fs::read_dir(root.join("state/attempts")).unwrap().count(),
        0
    );
}

/// R1b timings (Keystone note (a), Risk 1): F1's `new` with `count` 2 and 8
/// over its small bundle; the supervisor's validation of a bundle with 256 MiB
/// of payload (refused by the stack check after its full read, so validation
/// alone) and of the same layer as a sealed directory; and the per-child cost
/// of that bundle. Prints to stderr: run with `--release` and
/// `-- --ignored --nocapture`.
#[test]
#[ignore = "requires /dev/fuse; benchmark for the R1b PR"]
fn sandbox_lower_bundle_validation_timing() {
    if !prepared_fuse() {
        return;
    }
    let daemon = Daemon::start();
    daemon.base();
    let root = daemon.root.as_ref().unwrap().path().to_owned();
    let tar = root.join("base.tar");
    let Layers { a, bundle, .. } = layers(&daemon);
    for count in [2, 8] {
        let request = json!({
            "version": 2, "op": "new", "base": "task", "count": count, "lowers": [a, bundle]
        });
        let started = Instant::now();
        let attempts = daemon.call(request);
        let took = started.elapsed();
        assert_eq!(attempts.as_array().unwrap().len(), count);
        daemon.call(json!({"op": "destroy", "base": "task"}));
        eprintln!(
            "new count {count} over [A, bundle(B)] ({} bytes): {:.3} s",
            fs::metadata(&bundle).unwrap().len(),
            took.as_secs_f64()
        );
    }
    // A large layer: 1024 files of 256 KiB of hex text (about 2:1
    // compressible), sealed over [A] and packed.
    let big = root.join("layers/big");
    {
        use ratarmount_compositing::{compose_stack, Immutability, LowerLayerRecord, OverlayMeta};
        let source = tar_source(&tar);
        let view = compose_stack(
            source.source.clone(),
            &[(a.clone(), Immutability::Immutable)],
        )
        .unwrap();
        let meta = OverlayMeta::read(&a).unwrap().unwrap();
        let record = LowerLayerRecord {
            path: a.canonicalize().unwrap(),
            layer_digest: meta.get("layer_digest").unwrap().into(),
            sealed_at: meta.get("sealed_at").unwrap().into(),
        };
        let overlay = token::overlay_over(view.clone(), &big, tar.to_str().unwrap(), vec![record]);
        drop(overlay.unwrap());
        let mut state = 0x9e3779b97f4a7c15u64;
        let hex = b"0123456789abcdef";
        fs::create_dir(big.join("deps")).unwrap();
        for file in 0..1024 {
            let mut bytes = Vec::with_capacity(256 << 10);
            while bytes.len() < 256 << 10 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                for shift in (0..64).step_by(4) {
                    bytes.push(hex[((state >> shift) & 15) as usize]);
                }
            }
            fs::write(big.join(format!("deps/f{file:04}.txt")), &bytes).unwrap();
        }
        ratarmount_compositing::overlay_fsck::fsck(&big, true).unwrap();
        let token = token::ClassifiedBaseOver::archive(view.clone(), &tar);
        ratarmount_compositing::overlay_seal::seal(&big, &token, view).unwrap();
    }
    let big_bundle = root.join("layers/big.tar.zst");
    let started = Instant::now();
    let packed = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "pack"])
        .arg(&big)
        .arg(&big_bundle)
        .output()
        .unwrap();
    assert!(packed.status.success(), "{packed:?}");
    eprintln!(
        "large layer: 1024 x 256 KiB of hex text; bundle {} bytes; pack {:.3} s",
        fs::metadata(&big_bundle).unwrap().len(),
        started.elapsed().as_secs_f64()
    );
    // Validation alone: [bundle(big)] without its lower A is refused by the
    // stack check after the supervisor has read the whole bundle.
    let mut runs = Vec::new();
    for _ in 0..3 {
        let request = json!({"version": 2, "op": "new", "base": "task", "lowers": [big_bundle]});
        let started = Instant::now();
        let reply = daemon.envelope(request);
        runs.push(started.elapsed().as_secs_f64());
        assert_eq!(reply["error"]["code"], "invalid_request", "{reply}");
    }
    eprintln!("validation of [bundle(large)], refused after its full read: {runs:.3?} s");
    // The same layer as a sealed directory: validation reads only its database.
    let mut runs = Vec::new();
    for _ in 0..3 {
        let request = json!({"version": 2, "op": "new", "base": "task", "lowers": [big]});
        let started = Instant::now();
        let reply = daemon.envelope(request);
        runs.push(started.elapsed().as_secs_f64());
        assert_eq!(reply["error"]["code"], "invalid_request", "{reply}");
    }
    eprintln!("validation of [large] as a sealed directory: {runs:.3?} s");
    // Per-child cost: each child copies, hashes, extracts and verifies it.
    for count in [1, 2] {
        let request = json!({
            "version": 2, "op": "new", "base": "task", "count": count, "lowers": [a, big_bundle]
        });
        let started = Instant::now();
        let reply = daemon.envelope(request);
        let took = started.elapsed().as_secs_f64();
        let status = if reply["ok"] == true {
            "ok".to_owned()
        } else {
            reply["error"].to_string()
        };
        eprintln!("new count {count} over [A, bundle(large)]: {took:.3} s ({status})");
        daemon.call(json!({"op": "destroy", "base": "task"}));
    }
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

// ---------------------------------------------------------------------------
// R1c-1: the supervisor's finalize with the real binary (plan
// `docs/tasks/plans/localai-r1c1-finalize-retain.md` §7 T5b, F1, F2).
// ---------------------------------------------------------------------------

/// Writes the executable `/bin/sh` script `dir/name`: it appends one record
/// to `log` (its name and each argument, every one NUL-terminated, then the
/// byte 0x1e, so an argument may hold a newline) and then runs `then`.
fn recording_script(dir: &Path, name: &str, log: &Path, then: &str) {
    let log = log.to_str().unwrap();
    assert!(!log.contains('\''), "{log}");
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\0' '{name}' >> '{log}'\n\
         for arg in \"$@\"; do printf '%s\\0' \"$arg\" >> '{log}'; done\n\
         printf '\\036' >> '{log}'\n\
         {then}\n"
    );
    let path = dir.join(name);
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The invocations recording scripts appended to `log` from byte `from`
/// on, each as its program name and arguments.
fn invocations(log: &Path, from: u64) -> Vec<Vec<String>> {
    let bytes = match fs::read(log) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => panic!("{}: {e}", log.display()),
    };
    bytes[from as usize..]
        .split(|byte| *byte == 0x1e)
        .filter(|record| !record.is_empty())
        .map(|record| {
            let mut fields: Vec<String> = record
                .split(|byte| *byte == 0)
                .map(|field| String::from_utf8(field.to_vec()).unwrap())
                .collect();
            assert_eq!(fields.pop().as_deref(), Some(""), "torn record: {fields:?}");
            fields
        })
        .collect()
}

fn log_len(log: &Path) -> u64 {
    fs::metadata(log).map_or(0, |meta| meta.len())
}

/// `dir` first, then the test process's own `PATH`.
fn path_with(dir: &Path) -> OsString {
    let original = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&original)))
        .unwrap()
}

/// What a fake `fusermount3` prints for a mount the kernel refuses with
/// EBUSY (`$2` is the path of `-u PATH`), and for any other refusal.
const FUSERMOUNT_BUSY: &str =
    "printf 'fusermount3: failed to unmount %s: Device or resource busy\\n' \"$2\" >&2\nexit 1";
const FUSERMOUNT_NOT_PERMITTED: &str =
    "printf 'fusermount3: failed to unmount %s: Operation not permitted\\n' \"$2\" >&2\nexit 1";

/// One run of the supervisor's unmount helper, `ratarmount -u -- TARGET`.
struct HelperRun {
    status: std::process::ExitStatus,
    took: Duration,
    stderr: String,
    /// Every recorded `fusermount3`, `fusermount` and `umount` run, in order.
    calls: Vec<Vec<String>>,
}

impl HelperRun {
    /// The line the supervisor classifies: the last non-empty stderr line,
    /// trimmed (`ProcessMounter::unmount_helper`).
    fn last_line(&self) -> &str {
        self.stderr
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
            .unwrap_or("")
    }
}

/// Runs the real helper as the supervisor does (`RUST_LOG=off`, stdin
/// closed), with a `PATH` whose first directory holds a recording
/// `fusermount3` that ends with `then`, and recording `fusermount` and
/// `umount` that fail, so a fallback would show in the record.
fn run_unmount_helper(target: &Path, then: &str) -> HelperRun {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let log = dir.path().join("calls");
    recording_script(&bin, "fusermount3", &log, then);
    recording_script(&bin, "fusermount", &log, "exit 1");
    recording_script(&bin, "umount", &log, "exit 1");
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["-u", "--"])
        .arg(target)
        .env("PATH", path_with(&bin))
        .env("RUST_LOG", "off")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    HelperRun {
        status: output.status,
        took: started.elapsed(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        calls: invocations(&log, 0),
    }
}

/// Regression (R1c-1 T5b, ruling 7): the real unmount helper the supervisor
/// runs to stop an attempt must never force: a busy mount is retried about
/// 1 s with exactly `fusermount3 -u PATH` (no `-z`, no force flag, no
/// `fusermount` or `umount` fallback) and ends in the busy error that
/// `is_busy_unmount_error` classifies from the last stderr line; any other
/// refusal is one try and not busy, also when the path echoes the busy text.
#[test]
fn regression_supervisor_stop_real_helper_policy() {
    if !Path::new("/bin/sh").exists() {
        eprintln!("skip: the recording fusermount3 needs /bin/sh");
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let plain = scratch.path().join("mnt");
    // The diagnostic's own words and a newline inside the echoed path: the
    // words end an earlier stderr line, or sit inside the last one.
    let odd = scratch
        .path()
        .join("x: Device or resource busy (busy)\ntail");
    let odd_last = scratch.path().join("y\nz: Device or resource busy (busy)");
    for target in [&plain, &odd, &odd_last] {
        let shown = target.to_str().unwrap();
        let expected: Vec<String> = vec!["fusermount3".into(), "-u".into(), shown.into()];
        let busy = run_unmount_helper(target, FUSERMOUNT_BUSY);
        assert_eq!(busy.status.code(), Some(1), "{shown:?}: {}", busy.stderr);
        assert!(busy.calls.len() >= 2, "{shown:?}: {:?}", busy.calls);
        assert!(
            busy.calls.iter().all(|call| call == &expected),
            "{shown:?}: {:?}",
            busy.calls
        );
        assert!(busy.took < Duration::from_secs(3), "{:?}", busy.took);
        let last = busy.last_line();
        assert!(
            last.contains(&format!(
                "(still busy after {} attempts over ~",
                busy.calls.len()
            )),
            "{last}"
        );
        assert!(ratarmount_fuse::is_busy_unmount_error(last), "{last}");
        let refused = run_unmount_helper(target, FUSERMOUNT_NOT_PERMITTED);
        assert_eq!(
            refused.status.code(),
            Some(1),
            "{shown:?}: {}",
            refused.stderr
        );
        assert_eq!(refused.calls, std::slice::from_ref(&expected));
        let last = refused.last_line();
        assert!(last.ends_with(": Operation not permitted"), "{last}");
        assert!(!ratarmount_fuse::is_busy_unmount_error(last), "{last}");
        if target == &odd {
            // The echoed path ended earlier lines with the busy words; only
            // the last line, the real diagnostic, decides.
            assert!(
                refused
                    .stderr
                    .lines()
                    .any(ratarmount_fuse::is_busy_unmount_error),
                "{}",
                refused.stderr
            );
        }
        if target == &odd_last {
            // The words are on the last line itself, before its real end.
            assert!(last.contains(": Device or resource busy (busy)"), "{last}");
        }
        eprintln!(
            "{shown:?}: busy: {} tries in {:?}; not permitted: 1 try",
            busy.calls.len(),
            busy.took
        );
    }
}

/// Sends a v2 `finalize` until it answers. `writers_active` is retried with
/// the same request for a bounded time, as the docs tell clients to: a
/// desktop prober (`gvfsd-trash`) can hold a new mount past the helper's own
/// busy retries. Any other refusal fails.
fn finalize_done(daemon: &Daemon, request: &Value, mnt: &Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let response = daemon.envelope(request.clone());
        if response["ok"] == true {
            return response["result"].clone();
        }
        assert_eq!(response["error"]["code"], "writers_active", "{response}");
        assert!(Instant::now() < deadline, "attempt stayed busy: {response}");
        eprintln!("finalize answered writers_active; retrying: {response}");
        unmount::log_holders(mnt);
        thread::sleep(Duration::from_secs(1));
    }
}

/// `root/layers/a` over `tar`, authored by the real binary (F1, F3).
fn authored_a(root: &Path, tar: &Path) -> PathBuf {
    let dir = root.join("layers");
    fs::create_dir(&dir).unwrap();
    let a = dir.join("a");
    authored_layer(tar, &a, &[], &[("a.txt", "from a\n")]);
    a
}

/// `ratarmount ARGS` with HOME and the cache under `home`.
fn cli_output(home: &Path, args: &[&Path]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join("cache"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// [`cli_output`]'s stdout, once its exit status is `code`.
fn cli(home: &Path, args: &[&Path], code: i32) -> String {
    let out = cli_output(home, args);
    assert_eq!(
        out.status.code(),
        Some(code),
        "ratarmount {args:?}: {out:?}"
    );
    String::from_utf8(out.stdout).unwrap()
}

fn sha256_of(path: &Path) -> String {
    format!(
        "sha256:{}",
        ratarmount_index::sha256_hex_stream(&mut fs::File::open(path).unwrap()).unwrap()
    )
}

/// Regression (R1c-1 F1): a layered, journaled attempt finalized by the real
/// supervisor must report the sealed layer every offline verb computes:
/// `patch_hash.files` counts only the top's file, `layer_digest` is `overlay
/// verify --json`'s `computed` digest over the worker's index folder and
/// `diff --hash`'s, a repeated `overlay seal` only reads it back, and the
/// journal counts are `journal summarize --json`'s.
#[test]
fn regression_sandbox_v2_finalize_layered_fuse() {
    if !prepared_fuse() {
        return;
    }
    let daemon = Daemon::start();
    daemon.base();
    let root = daemon.root.as_ref().unwrap().path().to_path_buf();
    let tar = root.join("base.tar");
    let a = authored_a(&root, &tar);
    let attempts = daemon.call(json!({
        "version": 2, "op": "new", "base": "task", "lowers": [a], "journal": {}
    }));
    let id = attempts[0]["id"].as_str().unwrap().to_owned();
    let mnt = PathBuf::from(attempts[0]["path"].as_str().unwrap());
    let overlay = PathBuf::from(attempts[0]["overlay_dir"].as_str().unwrap());
    let dir = mnt.parent().unwrap().to_path_buf();
    // The agent reads the base and the lower and writes one new file.
    assert_eq!(fs::read(mnt.join("base.txt")).unwrap(), b"original\n");
    assert_eq!(fs::read(mnt.join("a.txt")).unwrap(), b"from a\n");
    let payload = b"written by the agent\n";
    fs::write(mnt.join("agent.txt"), payload).unwrap();
    let report = finalize_done(
        &daemon,
        &json!({"version": 2, "op": "finalize", "id": id, "pack": true, "request_id": "f"}),
        &mnt,
    );
    assert_eq!(report["status"], "finalized", "{report}");
    assert_eq!(
        report["attempt"],
        json!({"id": id, "base": "task", "path": mnt, "overlay_dir": overlay, "status": "finalized"})
    );
    let digest = report["layer_digest"].as_str().unwrap();
    let sealed_at = report["sealed_at"].as_str().unwrap();
    assert!(digest.starts_with("sha256:"), "{report}");
    assert!(!sealed_at.is_empty(), "{report}");
    let patch_hash = &report["patch_hash"];
    // Only the top's file: A's file and the base are beneath the layer.
    assert_eq!(patch_hash["files"], 1, "{report}");
    assert!(patch_hash["patch"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(patch_hash["normalize"], "strict");
    assert_eq!(patch_hash["algo"], "sha256");
    assert_eq!(patch_hash["excludes"], json!([]));
    assert_eq!(patch_hash["sealed"], true);
    assert_eq!(patch_hash["stack"], report["stack_digest"]);
    // The seal resolved the worker's `pending` base digest by hashing the tar.
    assert_eq!(patch_hash["base"], json!(sha256_of(&tar)), "{report}");
    assert_eq!(patch_hash["base_pending"], false);
    assert_eq!(patch_hash["base_digest_state"], "present");
    assert_eq!(report["fsck_result"], "ok", "{report}");
    assert_eq!(report["bytes_written"], payload.len(), "{report}");
    assert_eq!(report["erofs_denied"], 0, "{report}");
    assert_eq!(report["manifest_path"], json!(dir.join("manifest.jsonl")));
    assert_eq!(report["bundle"], json!(dir.join("bundle.tar.zst")));
    assert!(dir.join("bundle.tar.zst").is_file());
    let manifest: Vec<Value> = fs::read_to_string(dir.join("manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(manifest.len(), 1, "{manifest:?}");
    assert_eq!(manifest[0]["path"], "agent.txt", "{manifest:?}");
    // The layer itself: sealed over the base and A.
    let meta = ratarmount_compositing::OverlayMeta::read_no_recovery(&overlay)
        .unwrap()
        .unwrap();
    assert_eq!(meta.get("layer_digest"), Some(digest));
    assert_eq!(meta.get("sealed_at"), Some(sealed_at));
    assert_eq!(meta.stack_digest(), report["stack_digest"].as_str());
    let lowers = meta.lower_layers().unwrap();
    assert_eq!(lowers.len(), 1, "{lowers:?}");
    assert_eq!(lowers[0].path, a.canonicalize().unwrap());
    assert_eq!(lowers[0].layer_digest, layer_digest(&a));
    // Every offline verb computes the reported digest, with the worker's
    // index folder (`--index-folders`, as `process::base_args` spells it).
    let home = root.join("cli-home");
    let indexes = serde_json::to_string(&[root.join("state/indexes/task")]).unwrap();
    let (o, p) = (overlay.as_path(), Path::new);
    let folders = p(indexes.as_str());
    let verified: Value = serde_json::from_str(&cli(
        &home,
        &[
            p("overlay"),
            p("--index-folders"),
            folders,
            p("verify"),
            o,
            p("--json"),
        ],
        0,
    ))
    .unwrap();
    assert_eq!(verified["ok"], true, "{verified}");
    assert_eq!(verified["computed"], digest, "{verified}");
    assert_eq!(verified["recorded"], digest, "{verified}");
    assert_eq!(verified["base_ok"], true, "{verified}");
    let hash = cli(
        &home,
        &[p("diff"), o, p("--hash"), p("--index-folders"), folders],
        0,
    );
    assert_eq!(hash.trim(), digest);
    // A repeated seal is a consistency read: the recorded values, nothing
    // in the layer changed.
    let before = tree_bytes(o);
    let resealed: Value = serde_json::from_str(&cli(
        &home,
        &[
            p("overlay"),
            p("--index-folders"),
            folders,
            p("seal"),
            o,
            p("--json"),
        ],
        0,
    ))
    .unwrap();
    assert_eq!(
        resealed,
        json!({"layer_digest": digest, "sealed_at": sealed_at})
    );
    assert_eq!(tree_bytes(o), before, "a repeated seal changed the layer");
    // The journal summary is `journal summarize --json`'s.
    let journal = dir.join("journal.jsonl");
    let summary: Value = serde_json::from_str(&cli(
        &home,
        &[p("journal"), p("summarize"), journal.as_path(), p("--json")],
        0,
    ))
    .unwrap();
    let count = |key: &str| summary[key].as_array().unwrap().len();
    assert_eq!(
        report["journal_summary"],
        json!({
            "path": dir.join("journal.summary.json"),
            "files_read": count("files_read"),
            "files_read_then_written": count("files_read_then_written"),
            "files_written_blind": count("files_written_blind"),
        })
    );
    assert!(
        summary["files_written_blind"]
            .as_array()
            .unwrap()
            .contains(&json!("agent.txt")),
        "{summary}"
    );
    let written: Value =
        serde_json::from_slice(&fs::read(dir.join("journal.summary.json")).unwrap()).unwrap();
    assert_eq!(written, summary);
}

/// Whether `path` is a mount point in `/proc/self/mountinfo` (its fifth
/// field, octal escapes decoded).
fn in_mountinfo(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    fn unescape(field: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();
        let mut i = 0;
        while i < field.len() {
            let octal = |b: &u8| (b'0'..=b'7').contains(b);
            if field[i] == b'\\' && i + 3 < field.len() && field[i + 1..i + 4].iter().all(octal) {
                let digit = |at: usize| u32::from(field[at] - b'0');
                decoded.push((digit(i + 1) * 64 + digit(i + 2) * 8 + digit(i + 3)) as u8);
                i += 4;
            } else {
                decoded.push(field[i]);
                i += 1;
            }
        }
        decoded
    }
    fs::read("/proc/self/mountinfo")
        .unwrap()
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.split(|byte| *byte == b' ').nth(4))
        .any(|field| unescape(field) == path.as_os_str().as_bytes())
}

/// The overlay's `meta` rows, read without a lock (`immutable=1`). A serving
/// child holds its overlay database in SQLite's exclusive locking mode
/// (`write_overlay.rs`, `LOCKING_MODE = EXCLUSIVE`), which refuses every
/// other reader, `overlay info` and `OverlayMeta` included; the database
/// keeps a rollback journal, so every committed row is in its main file.
fn meta_unlocked(overlay: &Path) -> std::collections::BTreeMap<String, String> {
    use rusqlite::OpenFlags;
    let db = overlay.join(ratarmount_compositing::HIDDEN_DB);
    let uri = format!("file:{}?immutable=1", db.to_str().unwrap());
    let conn = rusqlite::Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .unwrap();
    let mut rows = conn.prepare("SELECT key, value FROM meta").unwrap();
    let meta = rows
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    meta
}

/// The states `requests.jsonl` recorded for request `id`, in order.
fn request_states(daemon: &Daemon, id: &str) -> Vec<String> {
    fs::read_to_string(daemon.requests_log())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record["id"] == id)
        .map(|record| record["t"].as_str().unwrap().to_owned())
        .collect()
}

/// Regression (R1c-1 F2, ruling 7): a finalize of an attempt whose mount a
/// process still uses must answer `writers_active` from the real helper's
/// real EBUSY, with only non-forcing `-u` unmounts, leaving the attempt
/// mounted, `ready`, unsealed and readable by its holder; once the holder
/// exits, the same request ID finalizes.
#[test]
fn regression_sandbox_v2_finalize_writers_active_fuse() {
    use std::io::{Read, Seek, SeekFrom};
    if !prepared_fuse() {
        return;
    }
    // Every fusermount3 the daemon, its mount children and its unmount
    // helper run is recorded, then the real one runs (found by absolute path
    // before PATH is overridden), so mounting still works.
    let original = std::env::var_os("PATH").unwrap_or_default();
    let real = std::env::split_paths(&original)
        .map(|dir| dir.join("fusermount3"))
        .find(|path| path.is_file())
        .expect("fusermount3 on PATH");
    let real = real.to_str().unwrap();
    assert!(!real.contains('\''), "{real}");
    let wrapper = tempfile::tempdir().unwrap();
    let bin = wrapper.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let log = wrapper.path().join("fusermount3.log");
    recording_script(&bin, "fusermount3", &log, &format!("exec '{real}' \"$@\""));
    let daemon = Daemon::start_with_env(vec![("PATH", path_with(&bin))]);
    daemon.base();
    let attempts = daemon.call(json!({"op": "new", "base": "task"}));
    let id = attempts[0]["id"].as_str().unwrap().to_owned();
    let mnt = PathBuf::from(attempts[0]["path"].as_str().unwrap());
    let overlay = PathBuf::from(attempts[0]["overlay_dir"].as_str().unwrap());
    fs::write(mnt.join("agent.txt"), b"agent\n").unwrap();
    // A writer (an agent's container) still holds a file in the mount.
    let mut holder = fs::File::open(mnt.join("base.txt")).unwrap();
    let request = json!({"version": 2, "op": "finalize", "id": id, "request_id": "f"});
    let unmount = vec![
        "fusermount3".to_owned(),
        "-u".into(),
        mnt.to_str().unwrap().into(),
    ];
    let from = log_len(&log);
    let refused = daemon.envelope(request.clone());
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(refused["error"]["code"], "writers_active", "{refused}");
    // The real helper's busy retries, each a plain `-u`: no `-z`, no force
    // flag, nothing but the attempt's own mount point.
    let calls = invocations(&log, from);
    assert!(calls.len() >= 2, "{calls:?}");
    assert!(calls.iter().all(|call| call == &unmount), "{calls:?}");
    eprintln!(
        "writers_active after {} `fusermount3 -u` tries",
        calls.len()
    );
    // Nothing was detached, stopped or sealed.
    assert!(in_mountinfo(&mnt), "{} is no longer mounted", mnt.display());
    let listed = daemon.call(json!({"op": "list"}));
    let entry = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|attempt| attempt["id"] == id.as_str())
        .unwrap();
    assert_eq!(entry["status"], "ready", "{listed}");
    // The child still holds its overlay database, so `overlay info` cannot
    // read it; the unlocked read shows no seal row.
    let home = wrapper.path().join("cli-home");
    let (o, p) = (overlay.as_path(), Path::new);
    let info = cli_output(&home, &[p("overlay"), p("info"), o, p("--json")]);
    assert_eq!(info.status.code(), Some(1), "{info:?}");
    assert!(
        String::from_utf8_lossy(&info.stderr).contains("is in use by another ratarmount process"),
        "{info:?}"
    );
    let meta = meta_unlocked(&overlay);
    assert!(meta.contains_key("format_version"), "{meta:?}");
    assert!(!meta.contains_key("sealed_at"), "{meta:?}");
    assert!(!meta.contains_key("layer_digest"), "{meta:?}");
    assert!(!overlay.join(".ratarmount-sealed").exists());
    assert_ne!(
        fs::metadata(&overlay).unwrap().permissions().mode() & 0o200,
        0
    );
    // The holder still reads its open file through the mount, and the mount
    // still serves new opens.
    let mut content = String::new();
    holder.seek(SeekFrom::Start(0)).unwrap();
    holder.read_to_string(&mut content).unwrap();
    assert_eq!(content, "original\n");
    assert_eq!(fs::read(mnt.join("agent.txt")).unwrap(), b"agent\n");
    // Once the holder exits, the same request ID finalizes.
    drop(holder);
    let from = log_len(&log);
    let report = finalize_done(&daemon, &request, &mnt);
    assert_eq!(report["status"], "finalized", "{report}");
    let calls = invocations(&log, from);
    assert!(calls.contains(&unmount), "{calls:?}");
    assert!(!in_mountinfo(&mnt));
    // `done`: the stored report answers without running anything.
    let from = log_len(&log);
    assert_eq!(daemon.call(request), report);
    assert_eq!(log_len(&log), from);
    let states = request_states(&daemon, "f");
    assert_eq!(states[..2], ["running", "retryable"], "{states:?}");
    assert_eq!(
        states.last().map(String::as_str),
        Some("done"),
        "{states:?}"
    );
    // Sealed now: `overlay info` reads the seal rows, and the unlocked
    // reader agrees with it.
    let info: Value =
        serde_json::from_str(&cli(&home, &[p("overlay"), p("info"), o, p("--json")], 0)).unwrap();
    assert_eq!(info["sealed_at"], report["sealed_at"], "{info}");
    assert_eq!(info["layer_digest"], report["layer_digest"], "{info}");
    let meta = meta_unlocked(&overlay);
    assert_eq!(json!(meta["sealed_at"]), report["sealed_at"]);
    assert_eq!(json!(meta["layer_digest"]), report["layer_digest"]);
}
