//! Request IDs and `requests.jsonl` (plan §5.3–§5.6): U5–U16.

use super::daemon::{respond, Supervisor};
use super::protocol::{BaseOptions, Op, Operation, Request};
use super::requests::{
    self, Append, BatchError, Fault, Limits, RequestLog, Status, INTERRUPTED, LINE_BOUND,
};
use super::tests::{private_tempdir, setup, Fake};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn v2_new(base: &str, count: usize, id: Option<&str>) -> Vec<u8> {
    let mut request = json!({"version": 2, "op": "new", "base": base, "count": count});
    if let Some(id) = id {
        request["request_id"] = json!(id);
    }
    serde_json::to_vec(&request).unwrap()
}

fn answer(supervisor: &mut Supervisor<Fake>, line: &[u8]) -> Value {
    serde_json::from_slice(&respond(supervisor, line)).unwrap()
}

fn code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("")
}

fn spawns(fake: &Fake) -> usize {
    fake.0.lock().unwrap().spawns
}

fn log_file(supervisor: &Supervisor<Fake>) -> PathBuf {
    supervisor.root.join(requests::NAME)
}

fn log_lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn reopen(root: &Path, fake: &Fake) -> Supervisor<Fake> {
    Supervisor::open(root, 8, Duration::from_secs(1), fake.clone()).unwrap()
}

fn small_limits(live_bytes: u64, floor: u64) -> Limits {
    Limits::new(1000, live_bytes, live_bytes.min(4 << 20), floor).unwrap()
}

/// Sets the `limits()` override for the supervisors this thread opens.
struct LimitsOverride;

impl LimitsOverride {
    fn set(limits: Limits) -> Self {
        requests::TEST_LIMITS.with(|l| l.set(Some(limits)));
        Self
    }
}

impl Drop for LimitsOverride {
    fn drop(&mut self) {
        requests::TEST_LIMITS.with(|l| l.set(None));
    }
}

fn arm_open_faults(faults: Vec<Fault>) {
    requests::TEST_FAULTS.with(|f| *f.borrow_mut() = faults);
}

fn hash(line: &str) -> String {
    let Op::V2(operation) = Request::parse(line.as_bytes()).unwrap().operation else {
        panic!("v2 line");
    };
    requests::op_hash(&operation)
}

/// Regression: `op_hash` ignores key order, defaults and `request_id`, and its
/// golden digest pins the definition for later slices (§5.4).
#[test]
fn regression_request_hash_canonical_and_default_free() {
    let base = hash(r#"{"version":2,"op":"new","base":"task"}"#);
    for same in [
        r#"{"base":"task","op":"new","version":2}"#,
        r#"{"version":2,"op":"new","base":"task","count":1,"overlay":"disk","quota":null,"readonly_globs":[]}"#,
        r#"{"readonly_globs":[],"quota":null,"overlay":"disk","count":1,"base":"task","op":"new","version":2}"#,
        r#"{"version":2,"op":"new","base":"task","request_id":"r"}"#,
        r#"{"version":2,"op":"new","base":"task","request_id":"other","count":1}"#,
    ] {
        assert_eq!(hash(same), base, "{same}");
    }
    let globs = hash(r#"{"version":2,"op":"new","base":"task","readonly_globs":["a","b"]}"#);
    for other in [
        r#"{"version":2,"op":"new","base":"task","count":2}"#,
        r#"{"version":2,"op":"new","base":"task","overlay":"tmpfs"}"#,
        r#"{"version":2,"op":"new","base":"task","quota":0}"#,
        r#"{"version":2,"op":"new","base":"other"}"#,
    ] {
        assert_ne!(hash(other), base, "{other}");
    }
    assert_ne!(globs, base);
    // Reordered readonly_globs are another request: arrays keep their order.
    assert_ne!(
        hash(r#"{"version":2,"op":"new","base":"task","readonly_globs":["b","a"]}"#),
        globs
    );
    // Golden constant: R1b and R1c must keep it. Only top-level defaults are
    // dropped; R1b adds `journal: Some({})` != `None` with that field.
    assert_eq!(
        hash(r#"{"version":2,"op":"new","base":"task","request_id":"r"}"#),
        "sha256:7c90b0d547f54b6b875948f96f3781758eb2820c17b9a32d2a8dd2536ebc135e"
    );
    assert_eq!(
        base,
        format!(
            "sha256:{:x}",
            Sha256::digest(br#"{"base":"task","op":"new","version":2}"#)
        )
    );
}

/// Regression (Keystone #4, R1b L1): key order, at the top level and inside
/// `journal`, never changes `op_hash`; the order of `lowers` and of
/// `journal.exclude` does, and so does `journal` absent vs `{}`. An empty
/// `lowers` hashes as absent and `{}` as every default spelled out. R1a's
/// golden digest is unchanged and a second one pins `lowers` and `journal`.
/// `null` and unknown members are refused in both versions.
#[test]
fn regression_request_hash_nested_lowers_and_journal() {
    let layered = hash(
        r#"{"version":2,"op":"new","base":"task","lowers":["/layers/a","/layers/b.tar.zst"],"journal":{"exclude":["x/**"],"reads":"first","sync":true},"request_id":"r"}"#,
    );
    for same in [
        r#"{"journal":{"sync":true,"reads":"first","exclude":["x/**"]},"lowers":["/layers/a","/layers/b.tar.zst"],"base":"task","op":"new","version":2}"#,
        r#"{"version":2,"journal":{"reads":"first","exclude":["x/**"],"sync":true},"op":"new","request_id":"other","lowers":["/layers/a","/layers/b.tar.zst"],"base":"task","count":1}"#,
    ] {
        assert_eq!(hash(same), layered, "{same}");
    }
    for other in [
        r#"{"version":2,"op":"new","base":"task","lowers":["/layers/b.tar.zst","/layers/a"],"journal":{"exclude":["x/**"],"reads":"first","sync":true}}"#,
        r#"{"version":2,"op":"new","base":"task","lowers":["/layers/a/","/layers/b.tar.zst"],"journal":{"exclude":["x/**"],"reads":"first","sync":true}}"#,
        r#"{"version":2,"op":"new","base":"task","lowers":["/layers/a","/layers/b.tar.zst"],"journal":{"exclude":["x/**"],"reads":"all","sync":true}}"#,
        r#"{"version":2,"op":"new","base":"task","lowers":["/layers/a","/layers/b.tar.zst"]}"#,
    ] {
        assert_ne!(hash(other), layered, "{other}");
    }
    let excludes =
        hash(r#"{"version":2,"op":"new","base":"task","journal":{"exclude":["a","b"]}}"#);
    assert_ne!(
        hash(r#"{"version":2,"op":"new","base":"task","journal":{"exclude":["b","a"]}}"#),
        excludes
    );
    let plain = hash(r#"{"version":2,"op":"new","base":"task"}"#);
    assert_eq!(
        hash(r#"{"version":2,"op":"new","base":"task","lowers":[]}"#),
        plain
    );
    let journal = hash(r#"{"version":2,"op":"new","base":"task","journal":{}}"#);
    assert_ne!(journal, plain);
    assert_eq!(
        hash(
            r#"{"version":2,"op":"new","base":"task","journal":{"exclude":[],"reads":"all","sync":false}}"#
        ),
        journal
    );
    assert_ne!(
        hash(r#"{"version":2,"op":"new","base":"task","journal":{"reads":"first"}}"#),
        journal
    );
    // The canonical writer sorts members itself, whatever their order.
    let mut filled = serde_json::Map::new();
    filled.insert("z".into(), json!({"y": 1, "b": [2, 1]}));
    filled.insert("a".into(), json!(null));
    let mut text = Vec::new();
    requests::canonical(&Value::Object(filled), &mut text);
    assert_eq!(text, br#"{"a":null,"z":{"b":[2,1],"y":1}}"#);
    // R1a's golden digest, and R1b's.
    assert_eq!(
        hash(r#"{"version":2,"op":"new","base":"task","request_id":"r"}"#),
        "sha256:7c90b0d547f54b6b875948f96f3781758eb2820c17b9a32d2a8dd2536ebc135e"
    );
    assert_eq!(
        layered,
        "sha256:2515151256494fa1f4a8a11de16a36449bb8a69ae0d83fc73932edbb2926c53a"
    );
    assert_eq!(
        layered,
        format!(
            "sha256:{:x}",
            Sha256::digest(
                br#"{"base":"task","journal":{"exclude":["x/**"],"reads":"first","sync":true},"lowers":["/layers/a","/layers/b.tar.zst"],"op":"new","version":2}"#
            )
        )
    );
    // `null` is never "absent", and unknown members are refused.
    for (line, version) in [
        (r#"{"version":2,"op":"new","base":"t","lowers":null}"#, 2),
        (r#"{"version":2,"op":"new","base":"t","journal":null}"#, 2),
        (
            r#"{"version":2,"op":"new","base":"t","journal":{"x":1}}"#,
            2,
        ),
        (
            r#"{"version":2,"op":"new","base":"t","journal":{"reads":"some"}}"#,
            2,
        ),
        (
            r#"{"version":2,"op":"new","base":"t","journal":{"exclude":null}}"#,
            2,
        ),
        (r#"{"version":1,"op":"new","base":"t","lowers":["/l"]}"#, 1),
        (r#"{"version":1,"op":"new","base":"t","journal":{}}"#, 1),
    ] {
        let rejection = Request::parse(line.as_bytes()).unwrap_err();
        assert_eq!(
            (rejection.version, rejection.error.code.as_str()),
            (version, "invalid_request"),
            "{line}: {}",
            rejection.error.message
        );
    }
    // Regression (sweep 1): a struct's derived `Deserialize` also takes an
    // array of its fields, so `journal: []` was a journal with every default.
    for line in [
        r#"{"version":2,"op":"new","base":"t","journal":[]}"#,
        r#"{"version":2,"op":"new","base":"t","journal":[[],"first",true]}"#,
        r#"{"version":2,"op":"new","base":"t","journal":[["x/**"]]}"#,
        r#"{"version":2,"op":"new","base":"t","journal":true}"#,
        r#"{"version":2,"op":"new","base":"t","journal":"first"}"#,
    ] {
        let rejection = Request::parse(line.as_bytes()).unwrap_err();
        assert_eq!(
            (rejection.version, rejection.error.code.as_str()),
            (2, "invalid_request"),
            "{line}"
        );
        assert!(
            rejection
                .error
                .message
                .contains("expected a journal object"),
            "{line}: {}",
            rejection.error.message
        );
    }
    // Regression (sweep 4): a derived enum also takes the map form, so
    // `reads: {"first": null}` was `first`.
    for line in [
        r#"{"version":2,"op":"new","base":"t","journal":{"reads":{"first":null}}}"#,
        r#"{"version":2,"op":"new","base":"t","journal":{"reads":{"all":null}}}"#,
        r#"{"version":2,"op":"new","base":"t","journal":{"reads":["first"]}}"#,
    ] {
        let rejection = Request::parse(line.as_bytes()).unwrap_err();
        assert_eq!(
            (rejection.version, rejection.error.code.as_str()),
            (2, "invalid_request"),
            "{line}"
        );
        assert!(
            rejection.error.message.contains("expected a string"),
            "{line}: {}",
            rejection.error.message
        );
    }
    for reads in ["all", "first"] {
        let line =
            format!(r#"{{"version":2,"op":"new","base":"t","journal":{{"reads":"{reads}"}}}}"#);
        Request::parse(line.as_bytes()).unwrap();
    }
}

/// Regression: the same request ID and body never start a second batch, and
/// the replay's bytes equal the first answer's (source test 2).
#[test]
fn regression_request_id_same_body_one_spawn() {
    let (_root, mut supervisor, fake) = setup(8);
    let line = v2_new("task", 2, Some("r1"));
    let first = respond(&mut supervisor, &line);
    let value: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(value["version"], 2);
    assert_eq!(value["result"].as_array().unwrap().len(), 2, "{value}");
    let before = spawns(&fake);
    let second = respond(&mut supervisor, &line);
    assert_eq!(second, first);
    assert_eq!(spawns(&fake), before);
    assert_eq!(supervisor.attempts.len(), 2);
    let conflict = answer(&mut supervisor, &v2_new("task", 1, Some("r1")));
    assert_eq!(conflict["version"], 2);
    assert_eq!(code(&conflict), "idempotency_conflict", "{conflict}");
    assert_eq!(supervisor.attempts.len(), 2);
    let log = fs::read(log_file(&supervisor)).unwrap();
    for _ in 0..2 {
        let spawned = spawns(&fake);
        let response = answer(&mut supervisor, &v2_new("task", 1, None));
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["version"], 2);
        assert_eq!(spawns(&fake), spawned + 1);
    }
    assert_eq!(supervisor.attempts.len(), 4);
    assert_eq!(fs::read(log_file(&supervisor)).unwrap(), log);
    supervisor.destroy_all().unwrap();
}

/// Regression: a `retryable` record re-runs under its ID until it is `done`;
/// a `failed` record with kept attempts replays its error byte for byte.
#[test]
fn regression_request_id_retryable_reruns_and_failed_replays() {
    let (_root, mut supervisor, fake) = setup(8);
    fake.0.lock().unwrap().fail_spawn = Some(spawns(&fake) + 1);
    let line = v2_new("task", 1, Some("r"));
    let failed = answer(&mut supervisor, &line);
    assert_eq!(code(&failed), "spawn_failed", "{failed}");
    assert_eq!(failed["version"], 2);
    assert_eq!(supervisor.requests.status("r"), Some(Status::Retryable));
    assert!(supervisor.attempts.is_empty());
    let conflict = answer(&mut supervisor, &v2_new("task", 2, Some("r")));
    assert_eq!(code(&conflict), "idempotency_conflict");
    let before = spawns(&fake);
    let done = respond(&mut supervisor, &line);
    assert_eq!(spawns(&fake), before + 1);
    assert_eq!(supervisor.requests.status("r"), Some(Status::Done));
    assert_eq!(respond(&mut supervisor, &line), done);
    assert_eq!(spawns(&fake), before + 1);
    // A rollback that keeps its attempt stores `failed` with the kept ID.
    {
        let mut state = fake.0.lock().unwrap();
        state.fail_spawn = Some(state.spawns + 1);
        state.refuse_cleanup = true;
    }
    let line = v2_new("task", 1, Some("f"));
    let first = respond(&mut supervisor, &line);
    let value: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(code(&value), "spawn_failed");
    assert!(value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("retained attempts"));
    assert_eq!(supervisor.requests.status("f"), Some(Status::Failed));
    let kept = log_lines(&log_file(&supervisor)).last().unwrap()["attempts"].clone();
    let kept = kept.as_array().unwrap()[0].as_str().unwrap().to_owned();
    assert!(supervisor.attempts.contains_key(&kept));
    let before = spawns(&fake);
    assert_eq!(respond(&mut supervisor, &line), first);
    assert_eq!(spawns(&fake), before);
    assert!(supervisor.requests.is_reserved(&kept));
    fake.0.lock().unwrap().refuse_cleanup = false;
    supervisor.destroy_all().unwrap();
    assert!(supervisor.requests.is_reserved(&kept));
}

/// Regression: a refusal before any attempt exists records `retryable` and
/// spawns nothing; a malformed `request_id` writes no line at all.
#[test]
fn regression_request_id_refusal_is_retryable() {
    let (_root, mut supervisor, fake) = setup(2);
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 2, None))["ok"],
        true
    );
    let before = spawns(&fake);
    let line = v2_new("task", 1, Some("cap"));
    assert_eq!(code(&answer(&mut supervisor, &line)), "capacity");
    let unknown = v2_new("missing", 1, Some("nb"));
    assert_eq!(code(&answer(&mut supervisor, &unknown)), "not_found");
    assert_eq!(spawns(&fake), before);
    let lines = log_lines(&log_file(&supervisor));
    let states: Vec<_> = lines
        .iter()
        .map(|l| (l["id"].as_str().unwrap(), l["t"].as_str().unwrap()))
        .collect();
    assert_eq!(
        states,
        [
            ("cap", "running"),
            ("cap", "retryable"),
            ("nb", "running"),
            ("nb", "retryable")
        ]
    );
    let log = fs::read(log_file(&supervisor)).unwrap();
    let long = "a".repeat(129);
    for bad in ["", "-dash", "a/b", "sp ace", "é", long.as_str()] {
        let response = answer(&mut supervisor, &v2_new("task", 1, Some(bad)));
        assert_eq!(code(&response), "invalid_request", "{bad}: {response}");
        assert_eq!(response["version"], 2);
    }
    assert_eq!(
        fs::read(log_file(&supervisor)).unwrap(),
        log,
        "a malformed request_id writes no line"
    );
    // The longest valid ID is recorded: running, then retryable.
    let longest = "a".repeat(128);
    assert_eq!(
        code(&answer(&mut supervisor, &v2_new("task", 1, Some(&longest)))),
        "capacity"
    );
    assert_eq!(spawns(&fake), before);
    let lines = log_lines(&log_file(&supervisor));
    assert_eq!(lines.len(), log.iter().filter(|c| **c == b'\n').count() + 2);
    let added: Vec<_> = lines[lines.len() - 2..]
        .iter()
        .map(|l| (l["id"].as_str().unwrap(), l["t"].as_str().unwrap()))
        .collect();
    assert_eq!(
        added,
        [
            (longest.as_str(), "running"),
            (longest.as_str(), "retryable")
        ]
    );
    let id = supervisor.attempts.keys().next().unwrap().clone();
    supervisor.destroy(&id).unwrap();
    let response = answer(&mut supervisor, &line);
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(supervisor.requests.status("cap"), Some(Status::Done));
    assert_eq!(
        code(&answer(&mut supervisor, &v2_new("task", 2, Some("cap")))),
        "idempotency_conflict"
    );
    assert_eq!(
        code(&answer(&mut supervisor, &v2_new("task", 2, Some("nb")))),
        "idempotency_conflict"
    );
    supervisor.destroy_all().unwrap();
}

const KILL_ROLE: &str = "RATARMOUNT_SANDBOX_KILL_ROLE";
const KILL_STATE: &str = "RATARMOUNT_SANDBOX_KILL_STATE";
const KILL_MARKER: &str = "RATARMOUNT_SANDBOX_KILL_MARKER";

/// The re-exec child: runs one request-ID'd `new` until the parent kills it.
fn kill_child(role: &str) {
    let root = PathBuf::from(std::env::var_os(KILL_STATE).unwrap());
    let marker = PathBuf::from(std::env::var_os(KILL_MARKER).unwrap());
    let fake = Fake::default();
    {
        let mut state = fake.0.lock().unwrap();
        state.marker = true;
        state.stuck = role == "k1";
    }
    if role == "k2" {
        requests::BEFORE_OUTCOME.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::write(&marker, b"before outcome").unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }));
        });
    }
    // Readiness must never time out before the parent's kill.
    let mut supervisor = Supervisor::open(&root, 8, Duration::from_secs(60), fake).unwrap();
    supervisor
        .handle(Operation::CreateBase {
            name: "task".into(),
            source: "/fake.tar".into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    let response = respond(&mut supervisor, &v2_new("task", 2, Some("k")));
    panic!(
        "the parent should have killed this child: {}",
        String::from_utf8_lossy(&response)
    );
}

/// Starts a kill child and SIGKILLs it once `ready` holds; at most 30 s.
fn kill_at(role: &str, root: &Path, marker: &Path, ready: impl Fn() -> bool) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sandbox::requests_tests::regression_restart_running_new_reports_interrupted",
            "--nocapture",
        ])
        .env(KILL_ROLE, role)
        .env(KILL_STATE, root)
        .env(KILL_MARKER, marker)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !ready() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("{role} child exited early: {status}");
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{role} child never reached its kill point");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Regression: a `new` cut off by SIGKILL is `failed interrupted` after the
/// restart; its attempts are gone, and the ID stays bound (source test 3).
#[test]
fn regression_restart_running_new_reports_interrupted() {
    if let Ok(role) = std::env::var(KILL_ROLE) {
        return kill_child(&role);
    }
    for role in ["k1", "k2"] {
        let root = private_tempdir();
        let markers = private_tempdir();
        let marker = markers.path().join("marker");
        let processes = ratarmount_index::test_process::spawning();
        let attempts = root.path().join("attempts");
        kill_at(role, root.path(), &marker, || match role {
            // K1: every attempt exists and spawning has begun.
            "k1" => fs::read_dir(&attempts).is_ok_and(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.path().join("spawned").exists())
                    .count()
                    == 2
            }),
            // K2: paused just before the outcome append.
            _ => marker.exists(),
        });
        drop(processes);
        let _processes = ratarmount_index::test_process::exclusive();
        let fake = Fake::default();
        let mut supervisor = reopen(root.path(), &fake);
        assert_eq!(fs::read_dir(&attempts).unwrap().count(), 0, "{role}");
        assert!(supervisor.attempts.is_empty());
        assert_eq!(supervisor.requests.status("k"), Some(Status::Failed));
        let last = log_lines(&log_file(&supervisor)).pop().unwrap();
        assert_eq!(last["t"], "failed", "{role}");
        assert_eq!(last["error"]["code"], "interrupted");
        assert_eq!(last["attempts"], json!([]));
        assert_eq!(
            String::from_utf8(respond(&mut supervisor, &v2_new("task", 2, Some("k")))).unwrap(),
            format!("{{\"version\":2,\"ok\":false,\"error\":{{\"code\":\"interrupted\",\"message\":\"{INTERRUPTED}\"}}}}\n")
        );
        let conflict = answer(&mut supervisor, &v2_new("task", 1, Some("k")));
        assert_eq!(code(&conflict), "idempotency_conflict", "{role}");
        assert_eq!(spawns(&fake), 0);
    }
}

/// Regression: finished records survive a restart: `done` and `failed` replay
/// their original bytes although the attempts are gone, `retryable` re-runs,
/// and the reserved IDs stay reserved (§5.3 Restart).
#[test]
fn regression_restart_keeps_finished_request_records() {
    let _processes = ratarmount_index::test_process::exclusive();
    let (root, mut supervisor, fake) = setup(8);
    let done_line = v2_new("task", 1, Some("d"));
    let done = respond(&mut supervisor, &done_line);
    let done_id = supervisor.attempts.keys().next().unwrap().clone();
    {
        let mut state = fake.0.lock().unwrap();
        state.fail_spawn = Some(state.spawns + 1);
        state.refuse_cleanup = true;
    }
    let failed_line = v2_new("task", 1, Some("f"));
    let failed = respond(&mut supervisor, &failed_line);
    let kept = supervisor
        .attempts
        .keys()
        .find(|id| **id != done_id)
        .unwrap()
        .clone();
    {
        let mut state = fake.0.lock().unwrap();
        state.fail_spawn = Some(state.spawns + 1);
        state.refuse_cleanup = false;
    }
    let retry_line = v2_new("task", 1, Some("r"));
    assert_eq!(code(&answer(&mut supervisor, &retry_line)), "spawn_failed");
    // Clear refuse_cleanup before reopening, or reconcile refuses the start.
    fake.0.lock().unwrap().refuse_cleanup = false;
    drop(supervisor);
    let mut supervisor = reopen(root.path(), &fake);
    assert!(supervisor.attempts.is_empty());
    assert!(supervisor.requests.is_reserved(&done_id));
    assert!(supervisor.requests.is_reserved(&kept));
    let before = spawns(&fake);
    assert_eq!(respond(&mut supervisor, &done_line), done);
    assert_eq!(respond(&mut supervisor, &failed_line), failed);
    assert_eq!(spawns(&fake), before);
    let response = answer(&mut supervisor, &retry_line);
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(spawns(&fake), before + 1);
    supervisor.destroy_all().unwrap();
}

/// A dropped supervisor with one stale attempt whose overlay holds `keep`.
fn stale_state() -> (tempfile::TempDir, PathBuf) {
    let (root, mut supervisor, _) = setup(8);
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, Some("d")))["ok"],
        true
    );
    let overlay = supervisor
        .attempts
        .values()
        .next()
        .unwrap()
        .overlay_dir
        .clone();
    fs::write(overlay.join("keep"), "stale attempt data").unwrap();
    drop(supervisor);
    (root, overlay.join("keep"))
}

/// Opens the stale state expecting a refusal before `reconcile`.
fn refused_before_reconcile(root: &Path, keep: &Path) -> super::protocol::ApiError {
    let fake = Fake::default();
    let error = Supervisor::open(root, 8, Duration::from_secs(1), fake.clone())
        .err()
        .expect("the start must be refused");
    assert_eq!(fs::read(keep).unwrap(), b"stale attempt data");
    assert!(fake.0.lock().unwrap().cleaned.is_empty());
    error
}

/// Regression: a torn last line is truncated and the start succeeds; damage
/// before the last line or a schema error refuses it, naming the byte offset;
/// both syncs come before any lookup or append, and failed open-time writes
/// refuse the start before `reconcile` (§5.5 Open).
#[test]
fn regression_request_log_torn_tail_and_corrupt_middle() {
    let _processes = ratarmount_index::test_process::exclusive();
    for torn in [
        b"{\"v\":1,\"id\":\"x\",\"t\":\"run".to_vec(),
        b"\0\0\0\0\0\0\0\0\n".to_vec(),
        // A valid prefix with an unknown key, then zero bytes: not JSON, so
        // torn, although a typed parse stops at the key (Codex sweep 1 #2).
        b"{\"v\":1,\"seq\":3,\"id\":\"x\"}\0\0\0\0\n".to_vec(),
    ] {
        let (root, _) = stale_state();
        let log = root.path().join(requests::NAME);
        let good = fs::read(&log).unwrap();
        let mut bytes = good.clone();
        bytes.extend_from_slice(&torn);
        fs::write(&log, &bytes).unwrap();
        let supervisor = reopen(root.path(), &Fake::default());
        assert_eq!(fs::read(&log).unwrap(), good);
        assert_eq!(supervisor.requests.status("d"), Some(Status::Done));
        let events = supervisor.requests.events.borrow().clone();
        assert_eq!(&events[..4], ["file_sync", "dir_sync", "read", "truncate"]);
    }
    let (root, keep) = stale_state();
    let log = root.path().join(requests::NAME);
    let good = fs::read(&log).unwrap();
    let valid = String::from_utf8(good.clone()).unwrap();
    let running = valid.lines().next().unwrap().to_owned();
    let done = valid.lines().nth(1).unwrap().to_owned();
    // Appends a member to a one-line JSON object.
    let with = |line: &str, member: &str| format!("{},{member}}}", &line[..line.len() - 1]);
    let failed = with(
        &running.replace("\"t\":\"running\"", "\"t\":\"failed\""),
        r#""attempts":[],"error":{"code":"x","message":"y"}"#,
    );
    let null_result = {
        let mut value: Value = serde_json::from_str(&done).unwrap();
        value["result"] = Value::Null;
        serde_json::to_string(&value).unwrap()
    };
    let bad_lines = [
        ("damaged", "not json".to_owned()),
        (
            "damaged suffix",
            format!(
                "{}\0\0\0",
                running.replace("\"v\":1,", "\"v\":1,\"seq\":3,")
            ),
        ),
        // A member another state owns is refused even when null (Codex sweep 1 #1).
        (
            "null attempts on running",
            with(&running, r#""attempts":null"#),
        ),
        (
            "empty attempts on running",
            with(&running, r#""attempts":[]"#),
        ),
        (
            "null result on retryable",
            with(
                &running.replace("\"t\":\"running\"", "\"t\":\"retryable\""),
                r#""result":null"#,
            ),
        ),
        ("null result on failed", with(&failed, r#""result":null"#)),
        ("null error on done", with(&done, r#""error":null"#)),
        ("null required result on done", null_result),
        ("v", running.replace("\"v\":1", "\"v\":2")),
        (
            "t",
            running.replace("\"t\":\"running\"", "\"t\":\"paused\""),
        ),
        (
            "op",
            running.replace("\"op\":\"new\"", "\"op\":\"finalize\""),
        ),
        (
            "op_hash",
            serde_json::to_string(&{
                let mut value: Value = serde_json::from_str(&running).unwrap();
                value.as_object_mut().unwrap().remove("op_hash");
                value
            })
            .unwrap(),
        ),
        ("extra", running.replace("\"v\":1,", "\"v\":1,\"seq\":3,")),
    ];
    for (what, bad) in bad_lines {
        // The bad line sits before a valid last line; a schema error refuses
        // the start even as the last line, a damaged line only before it.
        let damaged = what.starts_with("damaged");
        for last in [false, true] {
            if damaged && last {
                continue;
            }
            let mut bytes = good.clone();
            bytes.extend_from_slice(bad.as_bytes());
            bytes.push(b'\n');
            if !last {
                bytes.extend_from_slice(running.as_bytes());
                bytes.push(b'\n');
            }
            fs::write(&log, &bytes).unwrap();
            let error = refused_before_reconcile(root.path(), &keep);
            assert_eq!(error.code, "invalid_request", "{what}: {}", error.message);
            let kind = if damaged { "damaged" } else { "unsupported" };
            assert!(
                error
                    .message
                    .contains(&format!("{kind} request record at byte {}", good.len()))
                    && error.message.contains("move it aside"),
                "{what}: {}",
                error.message
            );
            assert_eq!(
                fs::read(&log).unwrap(),
                bytes,
                "{what}: the log is unchanged"
            );
        }
    }
    fs::write(&log, &good).unwrap();
    // A torn tail whose truncation fails, and failed syncs, refuse with io.
    let mut torn = good.clone();
    torn.extend_from_slice(b"{\"v\":1");
    for fault in [Fault::OpenSyncFile, Fault::OpenSyncDir, Fault::OpenTruncate] {
        fs::write(&log, &torn).unwrap();
        arm_open_faults(vec![fault]);
        let error = refused_before_reconcile(root.path(), &keep);
        assert_eq!(error.code, "io", "{fault:?}: {}", error.message);
        assert!(error.message.contains(requests::NAME), "{}", error.message);
    }
    // A leftover whose removal fails is ignored.
    fs::write(&log, &good).unwrap();
    let leftover = root
        .path()
        .join(format!("{}.a1B2c3.compact", requests::NAME));
    fs::write(&leftover, "leftover").unwrap();
    arm_open_faults(vec![Fault::RemoveLeftover]);
    let fake = Fake::default();
    let supervisor = reopen(root.path(), &fake);
    assert!(leftover.exists());
    // Sync order: both syncs before any read, lookup or append.
    let mut supervisor = supervisor;
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, Some("d")))["ok"],
        true
    );
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, Some("e")))["ok"],
        true
    );
    let events = supervisor.requests.events.borrow().clone();
    assert_eq!(
        &events[..3],
        ["file_sync", "dir_sync", "read"],
        "{events:?}"
    );
    assert!(events[3..].contains(&"lookup") && events[3..].contains(&"append"));
    assert!(!events[3..]
        .iter()
        .any(|e| *e == "file_sync" || *e == "dir_sync"));
    supervisor.destroy_all().unwrap();
}

/// Fills capacity, then re-runs `retryable` refusals of `id` until the next
/// outcome append compacts the log.
fn compact_with_refusals(supervisor: &mut Supervisor<Fake>, id: &str) {
    let line = v2_new("task", 1, Some(id));
    for _ in 0..1000 {
        let compactions = supervisor
            .requests
            .events
            .borrow()
            .iter()
            .filter(|e| **e == "compact")
            .count();
        assert_eq!(code(&answer(supervisor, &line)), "capacity");
        if supervisor
            .requests
            .events
            .borrow()
            .iter()
            .filter(|e| **e == "compact")
            .count()
            > compactions
        {
            return;
        }
    }
    panic!("no compaction");
}

/// Regression: compaction keeps every live last line verbatim, so `op_hash`
/// still binds compacted IDs, before and after a reopen (sweep 4 B1).
#[test]
fn regression_request_log_compaction_keeps_op_hash() {
    let _processes = ratarmount_index::test_process::exclusive();
    let _limits = LimitsOverride::set(small_limits(64 << 10, 4 << 10));
    let (root, mut supervisor, fake) = setup(2);
    let done_line = v2_new("task", 1, Some("d"));
    let done = respond(&mut supervisor, &done_line);
    let reserved = supervisor.attempts.keys().next().unwrap().clone();
    // A failed record whose rollback kept its attempt; capacity is then full.
    {
        let mut state = fake.0.lock().unwrap();
        state.fail_spawn = Some(state.spawns + 1);
        state.refuse_cleanup = true;
    }
    let failed_line = v2_new("task", 1, Some("f"));
    let failed = respond(&mut supervisor, &failed_line);
    let kept = supervisor
        .attempts
        .keys()
        .find(|id| **id != reserved)
        .unwrap()
        .clone();
    let retry_line = v2_new("task", 1, Some("r"));
    assert_eq!(code(&answer(&mut supervisor, &retry_line)), "capacity");
    let path = log_file(&supervisor);
    let before: Vec<Vec<u8>> = fs::read(&path)
        .unwrap()
        .split_inclusive(|c| *c == b'\n')
        .map(<[u8]>::to_vec)
        .collect();
    compact_with_refusals(&mut supervisor, "r");
    let compacted = fs::read(&path).unwrap();
    assert_eq!(compacted, supervisor.requests.live_lines().concat());
    let lines: Vec<&[u8]> = compacted.split_inclusive(|c| *c == b'\n').collect();
    assert_eq!(lines.len(), 3, "d, f and r are the live records");
    assert_eq!(lines[0], &before[1][..], "the done line, verbatim");
    assert_eq!(lines[1], &before[3][..], "the failed line, verbatim");
    // The descriptor is the inode now at the name.
    let descriptor = supervisor
        .requests
        .descriptor()
        .unwrap()
        .metadata()
        .unwrap();
    let at_name = fs::metadata(&path).unwrap();
    assert_eq!(
        (descriptor.dev(), descriptor.ino()),
        (at_name.dev(), at_name.ino())
    );
    let check = |supervisor: &mut Supervisor<Fake>| {
        assert_eq!(respond(supervisor, &done_line), done);
        assert_eq!(respond(supervisor, &failed_line), failed);
        for id in ["d", "f", "r"] {
            assert_eq!(
                code(&answer(supervisor, &v2_new("task", 2, Some(id)))),
                "idempotency_conflict",
                "{id}"
            );
        }
        assert!(supervisor.requests.is_reserved(&reserved));
        assert!(supervisor.requests.is_reserved(&kept));
    };
    check(&mut supervisor);
    assert_eq!(code(&answer(&mut supervisor, &retry_line)), "capacity");
    // A line appended after compaction survives a reopen.
    assert_eq!(
        code(&answer(&mut supervisor, &v2_new("task", 1, Some("late")))),
        "capacity"
    );
    let leftover = root
        .path()
        .join(format!("{}.Z9y8X7.compact", requests::NAME));
    fs::write(&leftover, "leftover").unwrap();
    let foreign = root.path().join(".tmpAbCdEf");
    fs::write(&foreign, "atomic_json leftover").unwrap();
    let linked = root
        .path()
        .join(format!("{}.symlnk.compact", requests::NAME));
    std::os::unix::fs::symlink(&foreign, &linked).unwrap();
    // Clear refuse_cleanup before reopening, or reconcile refuses the start.
    fake.0.lock().unwrap().refuse_cleanup = false;
    drop(supervisor);
    let mut supervisor = reopen(root.path(), &fake);
    assert!(!leftover.exists());
    assert!(foreign.exists() && fs::symlink_metadata(&linked).is_ok());
    assert_eq!(supervisor.requests.status("late"), Some(Status::Retryable));
    check(&mut supervisor);
    let response = answer(&mut supervisor, &retry_line);
    assert_eq!(
        response["ok"], true,
        "the retryable record re-runs: {response}"
    );
    supervisor.destroy_all().unwrap();
}

/// Regression: both caps evict the oldest finished records, a reused evicted
/// ID reloads the same live set, the per-record preflight is exact, and open
/// streams any amount of history (§5.5 Caps, Codex sweep 1 #1).
#[test]
fn regression_request_log_caps_and_record_preflight() {
    let _processes = ratarmount_index::test_process::exclusive();
    assert!(Limits::new(10, 100, 101, 0).is_err());
    assert!(Limits::new(10, 64 << 20, (4 << 20) + 1, 0).is_err());
    let dir = private_tempdir();
    let outcome =
        |bytes: usize| -> requests::Outcome { Ok((Vec::new(), json!("x".repeat(bytes)))) };
    let hash = format!("sha256:{}", "0".repeat(64));
    {
        // Count cap: the oldest finished record goes; `running` never does.
        let mut log = RequestLog::open(
            dir.path(),
            Limits::new(2, 1 << 20, 1 << 20, 1 << 30).unwrap(),
        )
        .unwrap();
        log.begin("held", &hash).unwrap();
        for id in ["a", "b", "c"] {
            log.begin(id, &hash).unwrap();
            log.finish(id, &hash, outcome(10)).unwrap();
        }
        assert_eq!(log.status("held"), Some(Status::Running));
        assert_eq!(log.status("a"), None);
        assert_eq!(log.status("b"), None);
        assert_eq!(log.status("c"), Some(Status::Done));
    }
    let dir = private_tempdir();
    {
        // Byte cap: a large record evicts older ones; the newest always stays.
        let mut log =
            RequestLog::open(dir.path(), Limits::new(100, 2000, 2000, 1 << 30).unwrap()).unwrap();
        for id in ["a", "b", "c"] {
            log.begin(id, &hash).unwrap();
            log.finish(id, &hash, outcome(200)).unwrap();
        }
        let error = super::protocol::ApiError::new("mount_failed", "x".repeat(4000));
        log.begin("big", &hash).unwrap();
        let kept = vec!["attempt-AAAAAA".to_owned()];
        assert!(log
            .finish("big", &hash, Err(BatchError { error, kept }))
            .is_err());
        for id in ["a", "b", "c"] {
            assert_eq!(log.status(id), None);
        }
        assert_eq!(log.status("big"), Some(Status::Failed));
        assert!(log.is_reserved("attempt-AAAAAA"));
        drop(log);
        let log =
            RequestLog::open(dir.path(), Limits::new(100, 2000, 2000, 1 << 30).unwrap()).unwrap();
        assert_eq!(log.live_lines().len(), 1);
        assert_eq!(log.status("big"), Some(Status::Failed));
    }
    // Reuse of an evicted ID (Codex sweep 1 #1): a (count 1), b (count 8) and
    // c (count 4) under a byte cap that evicts a and b, then b with count 1.
    let size = |supervisor: &Supervisor<Fake>, id: &str| {
        supervisor
            .requests
            .live_lines()
            .iter()
            .find(|l| l.starts_with(format!("{{\"v\":1,\"id\":\"{id}\"").as_bytes()))
            .map(|l| l.len() as u64)
    };
    let abc = |supervisor: &mut Supervisor<Fake>| {
        let mut sizes = Vec::new();
        for (id, count) in [("a", 1), ("b", 8), ("c", 4)] {
            assert_eq!(
                answer(supervisor, &v2_new("task", count, Some(id)))["ok"],
                true
            );
            sizes.push(size(supervisor, id));
            supervisor.destroy_all().unwrap();
        }
        sizes
    };
    // Line sizes follow the state path's length: measure them in a state
    // directory of the same length first.
    let (_scratch, mut supervisor, _) = setup(16);
    let [a, b, c] = abc(&mut supervisor)[..] else {
        unreachable!()
    };
    let (a, b, c) = (a.unwrap(), b.unwrap(), c.unwrap());
    drop(supervisor);
    // a and b fit; c evicts a, then b. A replay that kept the last line per ID
    // and capped afterwards would reload a beside c and b (a + c <= b).
    let cap = a + b;
    assert!(a + c <= b && b + c > cap, "{a} {b} {c}");
    let _limits = LimitsOverride::set(Limits::new(1000, cap, cap, 1 << 30).unwrap());
    let (root, mut supervisor, fake) = setup(16);
    assert_eq!(abc(&mut supervisor), [Some(a), Some(b), Some(c)]);
    assert_eq!(supervisor.requests.status("a"), None);
    assert_eq!(supervisor.requests.status("b"), None);
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, Some("b")))["ok"],
        true
    );
    let live = |supervisor: &Supervisor<Fake>| {
        ["a", "b", "c"]
            .into_iter()
            .filter(|id| supervisor.requests.status(id).is_some())
            .collect::<Vec<_>>()
    };
    assert_eq!(live(&supervisor), ["b", "c"]);
    let lines = supervisor.requests.live_lines();
    supervisor.destroy_all().unwrap();
    drop(supervisor);
    let supervisor = reopen(root.path(), &fake);
    assert_eq!(supervisor.requests.live_lines(), lines);
    // Compaction, then a reopen: the same live set, a still unbound.
    drop(supervisor);
    drop(_limits);
    let _limits = LimitsOverride::set(Limits::new(1000, cap, cap, 1).unwrap());
    let mut supervisor = reopen(root.path(), &fake);
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, Some("z")))["ok"],
        true
    );
    assert!(supervisor.requests.events.borrow().contains(&"compact"));
    supervisor.destroy_all().unwrap();
    drop(supervisor);
    let supervisor = reopen(root.path(), &fake);
    assert_eq!(live(&supervisor), ["b", "c"]);
    assert_eq!(
        supervisor.requests.live_lines()[..2],
        lines[..],
        "c then b, verbatim"
    );
    drop(supervisor);
    drop(_limits);
    // Preflight over an escaped state path (N4): measure the exact done line,
    // then refuse one byte under it and accept at it.
    let parent = private_tempdir();
    let root = parent.path().join("st\"a\\te\u{1}");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let open = |record: u64| {
        let _limits = LimitsOverride::set(Limits::new(1000, 1 << 20, record, 1 << 30).unwrap());
        let fake = Fake::default();
        let mut supervisor =
            Supervisor::open(&root, 8, Duration::from_secs(1), fake.clone()).unwrap();
        supervisor
            .handle(Operation::CreateBase {
                name: "task".into(),
                source: "/fake.tar".into(),
                options: BaseOptions::default(),
            })
            .ok();
        (supervisor, fake)
    };
    let (mut supervisor, _) = open(1 << 20);
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 3, Some("p1")))["ok"],
        true
    );
    let exact = size(&supervisor, "p1").unwrap();
    let raw = String::from_utf8(supervisor.requests.live_lines().concat()).unwrap();
    assert!(raw.contains(r#"st\"a\\te\u0001"#), "escaped paths: {raw}");
    supervisor.destroy_all().unwrap();
    drop(supervisor);
    let (mut supervisor, fake) = open(exact - 1);
    let refused = answer(&mut supervisor, &v2_new("task", 3, Some("p2")));
    assert_eq!(code(&refused), "capacity", "{refused}");
    assert_eq!(spawns(&fake), 0);
    assert_eq!(supervisor.requests.status("p2"), Some(Status::Retryable));
    drop(supervisor);
    let (mut supervisor, _) = open(exact);
    let accepted = answer(&mut supervisor, &v2_new("task", 3, Some("p3")));
    assert_eq!(accepted["ok"], true, "{accepted}");
    assert_eq!(size(&supervisor, "p3").unwrap(), exact);
    supervisor.destroy_all().unwrap();
    drop(supervisor);
    // Small Limits reach `Supervisor::open` through the override.
    let limits = Limits::new(7, 777, 777, 7).unwrap();
    {
        let _limits = LimitsOverride::set(limits);
        let (_root, supervisor, _) = setup(8);
        assert_eq!(supervisor.requests.limits(), limits);
    }
    // Streaming open: history many times the live cap reopens to the live
    // set the caps keep, reading one line at a time. The history is written
    // directly (no thousands of synced appends); its lines have one length,
    // so the caps keep exactly the last live-cap / length of them.
    let dir = private_tempdir();
    let limits = Limits::new(1000, 4096, 4096, 1 << 30).unwrap();
    let history: Vec<Vec<u8>> = (0..2000)
        .map(|i| requests::done_line(&format!("h{i:04}"), &hash, &[], &json!("x".repeat(100))))
        .collect();
    let path = dir.path().join(requests::NAME);
    fs::write(&path, history.concat()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let length = history[0].len();
    assert!(history.iter().all(|line| line.len() == length));
    let kept = 4096 / length;
    assert!(history.len() * length > 50 * 4096);
    let log = RequestLog::open(dir.path(), limits).unwrap();
    assert_eq!(log.live_lines(), history[history.len() - kept..]);
    assert_eq!(log.line_high_water, length, "one line buffered at a time");
    assert!(log.line_high_water as u64 <= LINE_BOUND);
    drop(log);
    // Oversized lines (N4): the bound is a fixed constant, not the caps. A
    // line of exactly LINE_BOUND bytes reads back under any Limits; one byte
    // more is a torn tail as the last line and damage before it.
    let line_of = |id: &str, len: u64| {
        let empty = requests::done_line(id, &hash, &[], &json!("")).len() as u64;
        let padding = "x".repeat((len - empty) as usize);
        let line = requests::done_line(id, &hash, &[], &json!(padding));
        assert_eq!(line.len() as u64, len);
        line
    };
    let small = line_of("small", 200);
    let exact = line_of("exact", LINE_BOUND);
    let over = line_of("over", LINE_BOUND + 1);
    let dir = private_tempdir();
    let path = dir.path().join(requests::NAME);
    let write = |bytes: &[u8]| {
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    };
    write(&[&small[..], &exact[..]].concat());
    let tiny = Limits::new(10, 1000, 1000, 1 << 30).unwrap();
    let log = RequestLog::open(dir.path(), tiny).unwrap();
    assert_eq!(log.status("exact"), Some(Status::Done));
    assert_eq!(log.line_high_water as u64, LINE_BOUND);
    drop(log);
    for tail in [&over[..], &over[..over.len() - 1]] {
        write(&[&small[..], tail].concat());
        let log = RequestLog::open(dir.path(), requests::limits()).unwrap();
        assert_eq!(log.status("over"), None);
        assert_eq!(log.status("small"), Some(Status::Done));
        assert!(log.line_high_water as u64 <= LINE_BOUND);
        assert_eq!(
            fs::read(&path).unwrap(),
            small,
            "the torn tail is truncated"
        );
    }
    write(&[&small[..], &over[..], &small[..]].concat());
    let error = RequestLog::open(dir.path(), requests::limits())
        .err()
        .unwrap();
    assert_eq!(error.code, "invalid_request");
    assert!(
        error
            .message
            .contains(&format!("damaged request record at byte {}", small.len())),
        "{}",
        error.message
    );
    // A maximal `failed` line: 4,096 kept IDs twice and an 8 KiB mount.log
    // excerpt of control characters stays within the line bound.
    let dir = private_tempdir();
    let mut log = RequestLog::open(dir.path(), requests::limits()).unwrap();
    let kept: Vec<String> = (0..4096).map(|i| format!("attempt-{i:06}")).collect();
    let message = format!(
        "attempt {} exited or lost its mount during setup: {}; cleanup failed, retained attempts: {}",
        kept[0],
        "\u{1}".repeat(8192),
        kept.join(", ")
    );
    let error = super::protocol::ApiError::new("mount_failed", message.clone());
    log.begin("max", &hash).unwrap();
    let failed = BatchError {
        error,
        kept: kept.clone(),
    };
    assert!(log.finish("max", &hash, Err(failed)).is_err());
    drop(log);
    let line_len = fs::read(dir.path().join(requests::NAME))
        .unwrap()
        .split_inclusive(|c| *c == b'\n')
        .map(<[u8]>::len)
        .max()
        .unwrap() as u64;
    assert!(line_len > 150_000 && line_len < LINE_BOUND, "{line_len}");
    let log = RequestLog::open(dir.path(), requests::limits()).unwrap();
    let stored = log.stored("max").unwrap_err();
    assert_eq!(
        (stored.code.as_str(), stored.message),
        ("mount_failed", message)
    );
    assert!(kept.iter().all(|id| log.is_reserved(id)));
}

/// Regression: failed appends keep memory equal to the file or leave the log
/// `Broken` (no second batch either way), failed compactions back off, and an
/// append after compaction leaves no gap (§5.5 `Broken`, Codex sweep 1 #2).
#[test]
fn regression_request_log_append_failures_and_broken_state() {
    let _processes = ratarmount_index::test_process::exclusive();
    // A failed running write or sync for a new ID: truncated, still open.
    for fault in [Fault::Write(Append::Running), Fault::Sync(Append::Running)] {
        let (_root, mut supervisor, fake) = setup(8);
        let log = fs::read(log_file(&supervisor)).unwrap();
        supervisor.requests.faults = vec![fault];
        let line = v2_new("task", 1, Some("n"));
        assert_eq!(code(&answer(&mut supervisor, &line)), "io", "{fault:?}");
        assert_eq!(fs::read(log_file(&supervisor)).unwrap(), log);
        assert!(!supervisor.requests.is_broken());
        assert_eq!(supervisor.requests.status("n"), None);
        assert_eq!(spawns(&fake), 0);
        assert_eq!(answer(&mut supervisor, &line)["ok"], true);
        supervisor.destroy_all().unwrap();
    }
    // From a retryable record: the record, its hash and position stay.
    for fault in [Fault::Write(Append::Running), Fault::Sync(Append::Running)] {
        let (root, mut supervisor, fake) = setup(1);
        assert_eq!(
            answer(&mut supervisor, &v2_new("task", 1, None))["ok"],
            true
        );
        let line = v2_new("task", 1, Some("r"));
        assert_eq!(code(&answer(&mut supervisor, &line)), "capacity");
        let lines = supervisor.requests.live_lines();
        supervisor.requests.faults = vec![fault];
        assert_eq!(code(&answer(&mut supervisor, &line)), "io", "{fault:?}");
        assert_eq!(supervisor.requests.status("r"), Some(Status::Retryable));
        assert_eq!(supervisor.requests.live_lines(), lines);
        let other = v2_new("task", 2, Some("r"));
        assert_eq!(
            code(&answer(&mut supervisor, &other)),
            "idempotency_conflict"
        );
        drop(supervisor);
        let mut supervisor = reopen(root.path(), &fake);
        assert_eq!(
            code(&answer(&mut supervisor, &other)),
            "idempotency_conflict"
        );
    }
    // A written running line whose sync and truncation both fail: Broken, no
    // spawn, and after a reopen the record is interrupted.
    let (root, mut supervisor, fake) = setup(8);
    supervisor.requests.faults = vec![Fault::Sync(Append::Running), Fault::Truncate];
    let line = v2_new("task", 1, Some("s"));
    assert_eq!(code(&answer(&mut supervisor, &line)), "io");
    assert!(supervisor.requests.is_broken());
    assert_eq!(spawns(&fake), 0);
    let refused = answer(&mut supervisor, &line);
    assert_eq!(code(&refused), "io");
    assert!(refused["error"]["message"]
        .as_str()
        .unwrap()
        .contains("restart the daemon"));
    drop(supervisor);
    let mut supervisor = reopen(root.path(), &fake);
    let interrupted = answer(&mut supervisor, &line);
    assert_eq!(code(&interrupted), "interrupted");
    assert_eq!(interrupted["error"]["message"], INTERRUPTED);
    assert_eq!(spawns(&fake), 0);
    drop(supervisor);
    // A failed outcome write or sync after spawning.
    for fault in [Fault::Write(Append::Outcome), Fault::Sync(Append::Outcome)] {
        let (root, mut supervisor, fake) = setup(8);
        let done_line = v2_new("task", 1, Some("d"));
        let done = respond(&mut supervisor, &done_line);
        supervisor.requests.faults = vec![fault];
        let line = v2_new("task", 1, Some("o"));
        assert_eq!(code(&answer(&mut supervisor, &line)), "io", "{fault:?}");
        assert!(supervisor.requests.is_broken());
        assert_eq!(
            supervisor.attempts.len(),
            2,
            "its attempt stays until destroy"
        );
        let last = log_lines(&log_file(&supervisor)).pop().unwrap();
        assert_eq!(
            (last["id"].as_str(), last["t"].as_str()),
            (Some("o"), Some("running"))
        );
        // While a record is running under Broken.
        let spawned = spawns(&fake);
        assert_eq!(code(&answer(&mut supervisor, &line)), "io");
        assert_eq!(
            code(&answer(&mut supervisor, &v2_new("task", 2, Some("o")))),
            "idempotency_conflict"
        );
        assert_eq!(
            code(&answer(&mut supervisor, &v2_new("task", 1, Some("p")))),
            "io"
        );
        assert_eq!(spawns(&fake), spawned);
        assert_eq!(respond(&mut supervisor, &done_line), done);
        assert_eq!(
            answer(&mut supervisor, &v2_new("task", 1, None))["ok"],
            true
        );
        drop(supervisor);
        let mut supervisor = reopen(root.path(), &fake);
        assert_eq!(code(&answer(&mut supervisor, &line)), "interrupted");
    }
    // The outcome is written, then its sync and the truncation both fail.
    let (root, mut supervisor, fake) = setup(8);
    supervisor.requests.faults = vec![Fault::Sync(Append::Outcome), Fault::Truncate];
    let line = v2_new("task", 1, Some("w"));
    assert_eq!(code(&answer(&mut supervisor, &line)), "io");
    assert_eq!(code(&answer(&mut supervisor, &line)), "io");
    let spawned = spawns(&fake);
    drop(supervisor);
    let mut supervisor = reopen(root.path(), &fake);
    let replay = answer(&mut supervisor, &line);
    assert_eq!(
        replay["ok"], true,
        "the surviving done line replays: {replay}"
    );
    assert_eq!(spawns(&fake), spawned);
    drop(supervisor);
    let (root, mut supervisor, fake) = setup(1);
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, None))["ok"],
        true
    );
    supervisor.requests.faults = vec![Fault::Sync(Append::Outcome), Fault::Truncate];
    let line = v2_new("task", 1, Some("q"));
    assert_eq!(code(&answer(&mut supervisor, &line)), "io");
    drop(supervisor);
    let mut supervisor =
        Supervisor::open(root.path(), 8, Duration::from_secs(1), fake.clone()).unwrap();
    let spawned = spawns(&fake);
    assert_eq!(
        answer(&mut supervisor, &line)["ok"],
        true,
        "retryable runs again"
    );
    assert_eq!(spawns(&fake), spawned + 1);
    supervisor.destroy_all().unwrap();
    drop(supervisor);
    // Compaction: a failed directory sync after the rename leaves the log
    // Broken and the unlinked old inode unchanged; the trigger still answers.
    let _limits = LimitsOverride::set(small_limits(64 << 10, 2 << 10));
    let (_root, mut supervisor, _) = setup(1);
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, None))["ok"],
        true
    );
    let old = fs::File::open(log_file(&supervisor)).unwrap();
    supervisor.requests.faults = vec![Fault::CompactDirSync];
    compact_with_refusals(&mut supervisor, "c");
    assert!(supervisor.requests.is_broken());
    let size = old.metadata().unwrap().len();
    assert_eq!(
        code(&answer(&mut supervisor, &v2_new("task", 1, Some("x")))),
        "io"
    );
    assert_eq!(old.metadata().unwrap().len(), size);
    assert_ne!(
        old.metadata().unwrap().ino(),
        fs::metadata(log_file(&supervisor)).unwrap().ino()
    );
    drop(supervisor);
    // A failure before the rename keeps the old descriptor and no temp file,
    // and later appends wait for as many bytes as the live set first. The
    // `done` record makes the live set larger than one request's appends.
    let (_root, mut supervisor, _) = setup(4);
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 3, Some("big")))["ok"],
        true
    );
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, None))["ok"],
        true
    );
    supervisor.requests.faults = vec![Fault::CompactSync];
    compact_with_refusals(&mut supervisor, "c");
    assert!(!supervisor.requests.is_broken());
    let descriptor = supervisor
        .requests
        .descriptor()
        .unwrap()
        .metadata()
        .unwrap();
    assert_eq!(
        descriptor.ino(),
        fs::metadata(log_file(&supervisor)).unwrap().ino()
    );
    assert!(!fs::read_dir(&supervisor.root)
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().ends_with(".compact")));
    let live: u64 = supervisor
        .requests
        .live_lines()
        .iter()
        .map(|l| l.len() as u64)
        .sum();
    let mut appended = 0;
    let mut per_request = 0;
    let line = v2_new("task", 1, Some("c"));
    let compactions = |supervisor: &Supervisor<Fake>| {
        supervisor
            .requests
            .events
            .borrow()
            .iter()
            .filter(|e| **e == "compact")
            .count()
    };
    let failed = compactions(&supervisor);
    loop {
        let len = fs::metadata(log_file(&supervisor)).unwrap().len();
        assert_eq!(code(&answer(&mut supervisor, &line)), "capacity");
        if compactions(&supervisor) > failed {
            break;
        }
        per_request = fs::metadata(log_file(&supervisor)).unwrap().len() - len;
        appended += per_request;
        assert!(appended < live + 1000, "the retry never ran");
    }
    // The retry ran with the first outcome append that brought the bytes
    // appended since the failure to the live set's.
    assert!(
        per_request > 0 && appended < live && appended + per_request >= live,
        "{appended} {per_request} {live}"
    );
    // After a compaction an injected failed append is truncated, and the next
    // append lands at the end with no zero-filled gap.
    supervisor.requests.faults = vec![Fault::Write(Append::Running)];
    assert_eq!(code(&answer(&mut supervisor, &line)), "io");
    assert_eq!(code(&answer(&mut supervisor, &line)), "capacity");
    let bytes = fs::read(log_file(&supervisor)).unwrap();
    assert!(!bytes.contains(&0));
    let root = supervisor.root.clone();
    drop(supervisor);
    drop(_limits);
    let supervisor = reopen(&root, &Fake::default());
    assert_eq!(supervisor.requests.status("c"), Some(Status::Retryable));
    drop(supervisor);
    // A failed restart resolution refuses the start; the next start resolves it.
    let (root, mut supervisor, fake) = setup(8);
    supervisor.requests.faults = vec![Fault::Write(Append::Outcome)];
    assert_eq!(
        code(&answer(&mut supervisor, &v2_new("task", 1, Some("i")))),
        "io"
    );
    drop(supervisor);
    for fault in [
        Fault::Write(Append::Resolution),
        Fault::Sync(Append::Resolution),
    ] {
        arm_open_faults(vec![fault]);
        let error = Supervisor::open(root.path(), 8, Duration::from_secs(1), fake.clone())
            .err()
            .unwrap();
        assert_eq!(error.code, "io", "{fault:?}");
        assert!(error.message.contains(requests::NAME));
    }
    let mut supervisor = reopen(root.path(), &fake);
    assert_eq!(supervisor.requests.status("i"), Some(Status::Failed));
    assert_eq!(
        code(&answer(&mut supervisor, &v2_new("task", 1, Some("i")))),
        "interrupted"
    );
}

/// Regression: an attempt ID named by a live record is redrawn for every
/// `new`, v1 included, and 16 reserved draws in a row fail like any other
/// error in the attempt loop (sweep 5 B1, Codex sweep 3 B1).
#[test]
fn regression_attempt_id_never_reuses_logged_ids() {
    let _processes = ratarmount_index::test_process::exclusive();
    let _limits = LimitsOverride::set(small_limits(64 << 10, 2 << 10));
    let (root, mut supervisor, fake) = setup(8);
    supervisor.test_ids = Some(Default::default());
    assert_eq!(
        answer(&mut supervisor, &v2_new("task", 1, Some("d")))["ok"],
        true
    );
    let done = "attempt-000001".to_owned();
    assert!(supervisor.requests.is_reserved(&done));
    {
        let mut state = fake.0.lock().unwrap();
        state.fail_spawn = Some(state.spawns + 1);
        state.refuse_cleanup = true;
    }
    assert_eq!(
        code(&answer(&mut supervisor, &v2_new("task", 1, Some("f")))),
        "spawn_failed"
    );
    let failed = "attempt-000002".to_owned();
    assert_eq!(supervisor.requests.status("f"), Some(Status::Failed));
    assert!(supervisor.requests.is_reserved(&failed));
    fake.0.lock().unwrap().refuse_cleanup = false;
    supervisor.destroy_all().unwrap();
    // A v1 `new` whose first draw is reserved answers an ordinary v1 envelope.
    let draw = |supervisor: &mut Supervisor<Fake>, queue: &[&str], line: &[u8]| {
        let ids = supervisor.test_ids.as_mut().unwrap();
        ids.queue = queue.iter().map(|s| s.to_string()).collect();
        answer(supervisor, line)
    };
    for reserved in [&done, &failed] {
        let response = draw(
            &mut supervisor,
            &[reserved],
            br#"{"version":1,"op":"new","base":"task"}"#,
        );
        assert_eq!(response["version"], 1);
        let id = response["result"][0]["id"].as_str().unwrap().to_owned();
        assert_ne!(&id, reserved);
        assert!(id.starts_with("attempt-"));
        supervisor.destroy(&id).unwrap();
    }
    // After compaction and a reopen the reservations remain. Re-running one
    // retryable ID supersedes its lines, which is what compaction discards.
    for _ in 0..200 {
        let response = answer(&mut supervisor, &v2_new("missing", 1, Some("n")));
        assert_eq!(code(&response), "not_found");
        if supervisor.requests.events.borrow().contains(&"compact") {
            break;
        }
    }
    assert!(supervisor.requests.events.borrow().contains(&"compact"));
    drop(supervisor);
    let mut supervisor = reopen(root.path(), &fake);
    supervisor.test_ids = Some(Default::default());
    for reserved in [&done, &failed] {
        let response = draw(&mut supervisor, &[reserved], &v2_new("task", 1, None));
        let id = response["result"][0]["id"].as_str().unwrap().to_owned();
        assert_ne!(&id, reserved);
        supervisor.destroy(&id).unwrap();
    }
    // Exhaustion on the first attempt: retryable, nothing spawned or left.
    let sixteen = [done.as_str(); 16];
    let spawned = spawns(&fake);
    let response = draw(&mut supervisor, &sixteen, &v2_new("task", 1, Some("x")));
    assert_eq!(code(&response), "io");
    assert_eq!(
        response["error"]["message"],
        "could not allocate a unique attempt ID"
    );
    assert_eq!(supervisor.requests.status("x"), Some(Status::Retryable));
    assert_eq!(spawns(&fake), spawned);
    assert_eq!(
        fs::read_dir(root.path().join("attempts")).unwrap().count(),
        0
    );
    // Fifteen reserved draws, then a free one, succeed.
    let mut fifteen = vec![done.as_str(); 15];
    fifteen.push("attempt-FREE01");
    let response = draw(&mut supervisor, &fifteen, &v2_new("task", 1, None));
    assert_eq!(response["result"][0]["id"], "attempt-FREE01");
    supervisor.destroy_all().unwrap();
    // count 2: the first attempt spawns, the second exhausts.
    let mut queue = vec!["attempt-FREE02"];
    queue.extend([done.as_str(); 16]);
    let response = draw(&mut supervisor, &queue, &v2_new("task", 2, Some("y")));
    assert_eq!(code(&response), "io");
    assert_eq!(spawns(&fake), spawned + 2);
    assert_eq!(supervisor.requests.status("y"), Some(Status::Retryable));
    assert!(supervisor.attempts.is_empty());
    let mut queue = vec!["attempt-FREE03"];
    queue.extend([done.as_str(); 16]);
    fake.0.lock().unwrap().refuse_cleanup = true;
    let line = v2_new("task", 2, Some("z"));
    let first = draw(&mut supervisor, &queue, &line);
    assert_eq!(code(&first), "io");
    assert_eq!(supervisor.requests.status("z"), Some(Status::Failed));
    assert!(supervisor.requests.is_reserved("attempt-FREE03"));
    let spawned = spawns(&fake);
    assert_eq!(answer(&mut supervisor, &line), first);
    assert_eq!(spawns(&fake), spawned);
    fake.0.lock().unwrap().refuse_cleanup = false;
    supervisor.destroy_all().unwrap();
}

/// Regression: `Supervisor::open` refuses a symlinked, hard-linked or
/// group-readable `requests.jsonl` before `reconcile` touches stale attempts.
#[test]
fn regression_request_log_refuses_unsafe_file() {
    let _processes = ratarmount_index::test_process::exclusive();
    let (root, keep) = stale_state();
    let log = root.path().join(requests::NAME);
    let moved = root.path().join("moved.jsonl");
    fs::rename(&log, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &log).unwrap();
    let error = refused_before_reconcile(root.path(), &keep);
    assert_eq!(error.code, "io", "{}", error.message);
    assert!(
        error
            .message
            .contains(&std::io::Error::from_raw_os_error(libc::ELOOP).to_string()),
        "{}",
        error.message
    );
    fs::remove_file(&log).unwrap();
    fs::rename(&moved, &log).unwrap();
    let link = root.path().join("second-link");
    fs::hard_link(&log, &link).unwrap();
    let error = refused_before_reconcile(root.path(), &keep);
    assert_eq!(error.code, "unsafe_path", "{}", error.message);
    assert_eq!(
        error.message,
        "requests.jsonl must be a private, owned regular file"
    );
    fs::remove_file(&link).unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o640)).unwrap();
    let error = refused_before_reconcile(root.path(), &keep);
    assert_eq!(error.code, "unsafe_path", "{}", error.message);
    fs::set_permissions(&log, fs::Permissions::from_mode(0o600)).unwrap();
    let supervisor = reopen(root.path(), &Fake::default());
    assert!(
        !keep.exists(),
        "an accepted start reconciles the stale attempt"
    );
    drop(supervisor);
}

/// Times the outcome append that compacts a live set near the 64 MiB cap
/// (plan Risk 3: compaction blocks the serve loop). Not a regression test.
#[test]
#[ignore = "timing for the PR: cargo test -p ratarmount --bin ratarmount request_log_compaction_timing -- --ignored --nocapture"]
fn request_log_compaction_timing() {
    // On the target directory's disk, not a tmpfs /tmp.
    let dir = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"))
        .unwrap();
    let hash = format!("sha256:{}", "0".repeat(64));
    let mut log = RequestLog::open(dir.path(), requests::limits()).unwrap();
    // 15 records just under 4 MiB, then the same IDs again until the dead
    // bytes exceed the live ones and an outcome append compacts.
    let payload = json!("x".repeat((4 << 20) - 256));
    for round in 0..3 {
        for i in 0..15 {
            let id = format!("r{i}");
            log.begin(&id, &hash).unwrap();
            let start = std::time::Instant::now();
            log.finish(&id, &hash, Ok((Vec::new(), payload.clone())))
                .unwrap();
            let elapsed = start.elapsed();
            if log.events.borrow().contains(&"compact") {
                let live: usize = log.live_lines().iter().map(Vec::len).sum();
                eprintln!(
                    "round {round}: the outcome append that compacted {live} live bytes took {:.3} s",
                    elapsed.as_secs_f64()
                );
                return;
            }
        }
    }
    panic!("no compaction");
}
