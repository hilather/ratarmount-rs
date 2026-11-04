//! `requests.jsonl`: the append log behind protocol v2 request IDs (Keystone #5),
//! one instance of the state-log engine (`state_log.rs`), which owns the file.
//!
//! Every line is one self-contained record state: `op` and `op_hash` are on
//! every state, so a record's last line alone decides it. A line is written by
//! one `write_all` and synced before memory changes, so while the log is open
//! memory equals a replay of the file. Open replays the file in order with the
//! append-time eviction rule; compaction rewrites the live last lines verbatim.

use super::daemon::validate_name;
use super::protocol::{one, ApiError, OperationV2, Overlay, VERSION_2};
pub use super::state_log::Append;
#[cfg(test)]
pub use super::state_log::Fault;
use super::state_log::{failure, LineError, Records, StateLog};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

type Result<T> = std::result::Result<T, ApiError>;

/// A failed `new` batch: its error and the attempt IDs its failed rollback
/// kept. Nothing kept means nothing changed, so the request is `retryable`.
#[derive(Debug)]
pub struct BatchError {
    pub error: ApiError,
    pub kept: Vec<String>,
}

impl From<ApiError> for BatchError {
    fn from(error: ApiError) -> Self {
        Self {
            error,
            kept: Vec::new(),
        }
    }
}

/// What a `new` batch left: its attempt IDs and result, or a `BatchError`.
pub type Outcome = std::result::Result<(Vec<String>, Value), BatchError>;

pub const NAME: &str = "requests.jsonl";
const RECORD_BYTES: u64 = 4 << 20;
/// Longest line open reads, newline included. It is fixed rather than derived
/// from `Limits`, so other caps never turn a valid older line into damage
/// (Keystone N4). A `done` line is at most the per-record cap; the largest
/// `failed` line (4,096 kept IDs twice and an escaped 8 KiB `mount.log`
/// excerpt) is about 185 KB. R1b's lower re-check messages are cut to the
/// same 8 KiB (`lowers::MESSAGE_BYTES`).
pub const LINE_BOUND: u64 = RECORD_BYTES + (512 << 10);
/// The answer to a retry of a request cut off by a restart (§5.3).
pub const INTERRUPTED: &str = "request was cut off by a supervisor restart before it finished; any attempts it created were discarded; retry with a new request_id";

/// Caps on the live record set (§5.5). A release with other caps keeps or
/// drops other records; either way no second batch starts, because a restart
/// discards every attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    records: usize,
    live_bytes: u64,
    record_bytes: u64,
    compaction_floor: u64,
}

impl Limits {
    pub fn new(
        records: usize,
        live_bytes: u64,
        record_bytes: u64,
        compaction_floor: u64,
    ) -> std::result::Result<Self, String> {
        if record_bytes > live_bytes {
            return Err("the per-record cap must not exceed the live-byte cap".into());
        }
        if record_bytes > RECORD_BYTES {
            return Err(format!(
                "the per-record cap must not exceed {RECORD_BYTES} bytes, the done-line part of the fixed line bound"
            ));
        }
        Ok(Self {
            records,
            live_bytes,
            record_bytes,
            compaction_floor,
        })
    }

    pub fn record_bytes(&self) -> u64 {
        self.record_bytes
    }
}

/// The caps `Supervisor::open` uses: the defaults, or in test builds the
/// override a test set on its thread before opening.
pub fn limits() -> Limits {
    #[cfg(test)]
    if let Some(limits) = TEST_LIMITS.with(std::cell::Cell::get) {
        return limits;
    }
    Limits::new(65_536, 64 << 20, RECORD_BYTES, 8 << 20).expect("default request-log limits")
}

#[cfg(test)]
thread_local! {
    // `limits()` override for tests that open a supervisor with small caps.
    pub static TEST_LIMITS: std::cell::Cell<Option<Limits>> = const { std::cell::Cell::new(None) };
    // One-shot fault points; the next `RequestLog::open` on this thread takes them.
    pub static TEST_FAULTS: std::cell::RefCell<Vec<Fault>> = const { std::cell::RefCell::new(Vec::new()) };
    // Runs just before an outcome append (U9 pauses a child there).
    pub static BEFORE_OUTCOME: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Running,
    Done,
    Retryable,
    Failed,
}

/// The operation a record belongs to: `new` (line schema `v: 1`, R1a) or
/// `finalize` (line schema `v: 2`, R1c-1 ruling 5).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    New,
    Finalize,
}

/// The attempt a finalize record names, resolved once before `running` is
/// written (ruling 5): its ID and the random instance it got when `new`
/// recorded it. A retry acts on this attempt only, never on a name drawn
/// again.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub instance: String,
}

/// Whether `instance` is an attempt instance: 32 lowercase hex digits.
pub(super) fn is_instance(instance: &str) -> bool {
    instance.len() == 32
        && instance
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// What a record is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A `new` batch (line schema 1, R1a's members byte for byte).
    New,
    /// A finalize of one attempt (line schema 2, with `target` in every state).
    Finalize(Target),
}

impl Subject {
    fn kind(&self) -> Kind {
        match self {
            Self::New => Kind::New,
            Self::Finalize(_) => Kind::Finalize,
        }
    }

    fn target(&self) -> Option<&Target> {
        match self {
            Self::New => None,
            Self::Finalize(target) => Some(target),
        }
    }
}

/// The answer to a retry of a finalize a restart cut off.
pub const FINALIZE_INTERRUPTED: &str =
    "finalize was cut off by a supervisor restart before it finished; an attempt that was not retained was discarded, and a retained one is kept on disk";

#[derive(Serialize)]
struct LineOut<'a> {
    v: u32,
    id: &'a str,
    t: Status,
    op: Kind,
    op_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a Target>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempts: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a ApiError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LineIn {
    v: u32,
    id: String,
    t: Status,
    op: Kind,
    op_hash: String,
    target: Option<Target>,
    attempts: Option<Vec<String>>,
    result: Option<Value>,
    error: Option<StoredError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredError {
    code: String,
    message: String,
}

/// One line: `v: 1` for a `new` record (R1a's bytes), `v: 2` with `target`
/// for a finalize record.
fn encode_line(
    id: &str,
    subject: &Subject,
    t: Status,
    op_hash: &str,
    attempts: Option<&[String]>,
    result: Option<&Value>,
    error: Option<&ApiError>,
) -> Vec<u8> {
    let mut line = serde_json::to_vec(&LineOut {
        v: match subject {
            Subject::New => 1,
            Subject::Finalize(_) => 2,
        },
        id,
        t,
        op: subject.kind(),
        op_hash,
        target: subject.target(),
        attempts,
        result,
        error,
    })
    .expect("request records serialize to JSON");
    line.push(b'\n');
    line
}

/// The exact `done` line of a `new` record; the stored-record preflight
/// measures it in advance.
pub fn done_line(id: &str, op_hash: &str, attempts: &[String], result: &Value) -> Vec<u8> {
    encode_line(
        id,
        &Subject::New,
        Status::Done,
        op_hash,
        Some(attempts),
        Some(result),
        None,
    )
}

/// A parsed line: the record it decides.
pub struct Parsed {
    id: String,
    subject: Subject,
    t: Status,
    op_hash: String,
    attempts: Vec<String>,
}

fn parse_line(line: &[u8]) -> std::result::Result<Parsed, LineError> {
    // The whole line must be JSON before its schema is judged: a typed parse
    // stops at an unknown key before it reaches a damaged suffix.
    let value: Value = serde_json::from_slice(line).map_err(|_| LineError::Damaged)?;
    let schema = |why: &str| Err(LineError::Schema(why.into()));
    let Value::Object(members) = &value else {
        return schema("not an object");
    };
    // Keyed on `t`: exactly the members of that state, so a member another
    // state owns is refused even when it is null.
    let wanted: &[&str] = match members.get("t").and_then(Value::as_str) {
        Some("running" | "retryable") => &[],
        Some("done") => &["attempts", "result"],
        Some("failed") => &["attempts", "error"],
        _ => return schema("unknown or missing t"),
    };
    // Keyed on `v` too: line schema 2 adds `target` to every state.
    let common: &[&str] = if members.get("v").and_then(Value::as_u64) == Some(2) {
        &["v", "id", "t", "op", "op_hash", "target"]
    } else {
        &["v", "id", "t", "op", "op_hash"]
    };
    if let Some(key) = members
        .keys()
        .find(|key| !common.contains(&key.as_str()) && !wanted.contains(&key.as_str()))
    {
        return schema(&format!("unexpected member {key}"));
    }
    if let Some(key) = common
        .iter()
        .chain(wanted)
        .find(|key| !members.contains_key(**key))
    {
        return schema(&format!("missing member {key}"));
    }
    let input: LineIn =
        serde_json::from_value(value).map_err(|e| LineError::Schema(e.to_string()))?;
    if validate_name(&input.id).is_err() {
        return schema("invalid id");
    }
    if !is_op_hash(&input.op_hash) {
        return schema("invalid op_hash");
    }
    // `v: 1` is R1a's `new` record; `v: 2` is a finalize record.
    let subject = match (input.v, input.op, input.target) {
        (1, Kind::New, None) => Subject::New,
        (2, Kind::Finalize, Some(target)) => {
            if validate_name(&target.id).is_err() {
                return schema("invalid target id");
            }
            if !is_instance(&target.instance) {
                return schema("invalid target instance");
            }
            Subject::Finalize(target)
        }
        (1 | 2, op, _) => return schema(&format!("op {op:?} with v {}", input.v)),
        (v, ..) => return schema(&format!("unknown v {v}")),
    };
    // The members are the state's; a required one must not be null either.
    let attempts = match (input.t, input.attempts, input.result, input.error) {
        (Status::Running | Status::Retryable, None, None, None) => Vec::new(),
        (Status::Done, Some(attempts), Some(_), None) => attempts,
        (Status::Failed, Some(attempts), None, Some(_)) => attempts,
        (t, ..) => return schema(&format!("null member on t {t:?}")),
    };
    if attempts.iter().any(|id| validate_name(id).is_err()) {
        return schema("invalid attempt id");
    }
    // A finalize `done` reserves its target, as its stored report names it; a
    // `failed` one stores no answer that names it.
    if let Subject::Finalize(target) = &subject {
        let expected: &[String] = match input.t {
            Status::Done => std::slice::from_ref(&target.id),
            _ => &[],
        };
        if attempts != expected {
            return schema("finalize attempts other than its target");
        }
    }
    Ok(Parsed {
        id: input.id,
        subject,
        t: input.t,
        op_hash: input.op_hash,
        attempts,
    })
}

fn is_op_hash(hash: &str) -> bool {
    hash.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

/// `op_hash` (§5.4): `sha256:` and the hex SHA-256 of the canonical form of
/// the typed operation, without `request_id` and without top-level members
/// equal to their typed default, plus `"version": 2`. Omitting defaults keeps
/// an R1a record's hash when later slices add defaulted fields; nested values
/// are hashed whole.
pub fn op_hash(operation: &OperationV2) -> String {
    let mut value = serde_json::to_value(operation).expect("operations serialize to JSON");
    let members = value
        .as_object_mut()
        .expect("operations serialize as objects");
    members.remove("request_id");
    for (key, default) in defaults(operation) {
        if members.get(key) == Some(&default) {
            members.remove(key);
        }
    }
    members.insert("version".into(), json!(VERSION_2));
    let mut text = Vec::new();
    canonical(&value, &mut text);
    format!("sha256:{:x}", Sha256::digest(&text))
}

/// The typed default of every defaulted top-level field. Later slices add
/// their fields here; U5's golden digest holds them to R1a's hashes. An
/// absent `journal` is never serialized, and `journal: {}` is not a default:
/// it spells out every member.
fn defaults(operation: &OperationV2) -> Vec<(&'static str, Value)> {
    match operation {
        OperationV2::New { .. } => vec![
            ("count", json!(one())),
            ("overlay", json!(Overlay::default())),
            ("quota", json!(None::<u64>)),
            ("readonly_globs", json!(Vec::<String>::new())),
            ("lowers", json!(Vec::<String>::new())),
            ("retain", json!(false)),
        ],
        OperationV2::Finalize { .. } => vec![("pack", json!(false))],
        _ => Vec::new(),
    }
}

/// Object members sorted by their UTF-8 key bytes at every depth, arrays in
/// order, no whitespace, serde_json's scalar encoding. Sorting here keeps the
/// hash independent of serde_json's `preserve_order` feature.
pub(super) fn canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(members) => {
            let mut members: Vec<_> = members.iter().collect();
            members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (key, member)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).expect("keys serialize");
                out.push(b':');
                canonical(member, out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical(item, out);
            }
            out.push(b']');
        }
        scalar => serde_json::to_writer(&mut *out, scalar).expect("scalars serialize"),
    }
}

struct Record {
    subject: Subject,
    t: Status,
    op_hash: String,
    /// The exact last line, newline included: replays and compaction reuse it.
    line: Vec<u8>,
    /// Order of the last line in the file.
    position: u64,
    /// Attempt IDs the last line names; reserved while the record lives.
    attempts: Vec<String>,
}

/// The record rules of `requests.jsonl`: the live records, their order,
/// eviction under the caps and the attempt IDs they reserve.
pub struct RequestRecords {
    records: HashMap<String, Record>,
    /// Position of each record's last line to its ID, oldest first.
    order: BTreeMap<u64, String>,
    next_position: u64,
    live_bytes: u64,
    reserved: HashMap<String, usize>,
    limits: Limits,
    /// `None` from open until the supervisor knows which targets exist.
    /// Only the running log consults pins (admission and [`make_room`]);
    /// replay never does, so it evicts exactly what the run evicted.
    ///
    /// [`make_room`]: StateLog::make_room
    pins: Option<Pins>,
}

/// The finalize targets that still exist (Keystone approval note (a)): a
/// finalize record whose target is pinned is never evicted. The supervisor
/// pins every attempt it records, by ID and instance, until `destroy`;
/// retained attempts stay pinned. `ids` pins every instance of an ID: a name
/// under `retained/` whose instance no record names.
#[derive(Clone, Debug, Default)]
pub struct Pins {
    pub targets: HashSet<Target>,
    pub ids: HashSet<String>,
}

impl Pins {
    fn holds(&self, target: &Target) -> bool {
        self.targets.contains(target) || self.ids.contains(&target.id)
    }
}

/// `requests.jsonl` through the state-log engine.
pub type RequestLog = StateLog<RequestRecords>;

impl RequestRecords {
    pub fn new(limits: Limits) -> Self {
        Self {
            records: HashMap::new(),
            order: BTreeMap::new(),
            next_position: 0,
            live_bytes: 0,
            reserved: HashMap::new(),
            limits,
            pins: None,
        }
    }

    /// Whether `record` is a finalize record whose target is pinned (every
    /// finalize record while the pins are unknown).
    fn pinned(&self, record: &Record) -> bool {
        match &record.subject {
            Subject::New => false,
            Subject::Finalize(target) => self.pins.as_ref().is_none_or(|pins| pins.holds(target)),
        }
    }

    /// Whether `record` may make room for a new one: finished and not pinned.
    fn evictable(&self, record: &Record) -> bool {
        record.t != Status::Running && !self.pinned(record)
    }

    /// The records [`apply`](Self::apply) would evict for a line of `bytes`
    /// for `id`, oldest first.
    fn victims(&self, id: &str, bytes: u64) -> Vec<String> {
        let (mut count, mut live) = (self.records.len(), self.live_bytes + bytes);
        match self.records.get(id) {
            Some(old) => live -= old.line.len() as u64,
            None => count += 1,
        }
        let mut victims = Vec::new();
        for victim in self.order.values() {
            if count <= self.limits.records && live <= self.limits.live_bytes {
                break;
            }
            let record = &self.records[victim];
            if victim == id || record.t == Status::Running {
                continue;
            }
            count -= 1;
            live -= record.line.len() as u64;
            victims.push(victim.clone());
        }
        victims
    }

    /// The line replaces its ID's record, or creates it, as the newest; then
    /// the oldest records other than it and other than `running` ones are
    /// evicted until both caps hold (R1a's rule). Pins play no part, so a
    /// replay of the file evicts exactly what the run evicted: the run keeps
    /// a pinned finalize record by re-appending its line before it writes a
    /// line that would evict it ([`StateLog::make_room`]), and refuses a new
    /// record that only evicting a pinned one could make room for (`admit`).
    fn apply(&mut self, parsed: Parsed, line: Vec<u8>) {
        self.remove(&parsed.id);
        let position = self.next_position;
        self.next_position += 1;
        for id in &parsed.attempts {
            *self.reserved.entry(id.clone()).or_default() += 1;
        }
        self.live_bytes += line.len() as u64;
        self.order.insert(position, parsed.id.clone());
        self.records.insert(
            parsed.id.clone(),
            Record {
                subject: parsed.subject,
                t: parsed.t,
                op_hash: parsed.op_hash,
                line,
                position,
                attempts: parsed.attempts,
            },
        );
        self.evict(Some(&parsed.id));
    }

    /// Evicts the oldest records other than `keep` and other than `running`
    /// ones until both caps hold, or none is left.
    fn evict(&mut self, keep: Option<&str>) {
        while self.records.len() > self.limits.records || self.live_bytes > self.limits.live_bytes {
            let victim = self
                .order
                .values()
                .find(|id| Some(id.as_str()) != keep && self.records[*id].t != Status::Running)
                .cloned();
            match victim {
                Some(victim) => self.remove(&victim),
                None => break,
            }
        }
    }

    /// Whether a new record `id` with a line of `bytes` would fit the caps
    /// once every evictable record were evicted. The record is counted at its
    /// largest (the per-record cap), so its outcome line, which is never
    /// refused, can always be made room for without a pinned record. Refuses
    /// with `capacity` otherwise, before anything is written (approval note
    /// (a): a pinned finalize record is never evicted to make room). With no
    /// pinned record there is nothing to protect, and R1a's rule stands: the
    /// set may stay over a cap by its running records, and nothing is refused.
    fn admit(&self, id: &str, bytes: u64) -> Result<()> {
        let protect = self
            .records
            .iter()
            .any(|(key, record)| key != id && record.t != Status::Running && self.pinned(record));
        if !protect {
            return Ok(());
        }
        let bytes = bytes.max(self.limits.record_bytes);
        let (mut count, mut live) = (self.records.len() + 1, self.live_bytes + bytes);
        if let Some(old) = self.records.get(id) {
            count -= 1;
            live -= old.line.len() as u64;
        }
        for (key, record) in &self.records {
            if key != id && self.evictable(record) {
                count -= 1;
                live -= record.line.len() as u64;
            }
        }
        if count > self.limits.records || live > self.limits.live_bytes {
            return Err(ApiError::new(
                "capacity",
                format!(
                    "the request log is full of records that may not be evicted ({count} records and {live} bytes of at most {} and {}): finalize records whose attempts still exist, or requests still running; destroy the attempts those finalize requests name, then retry — for a retained attempt, which cannot be destroyed in this release, stop the daemon and move requests.jsonl aside, losing the retry records",
                    self.limits.records, self.limits.live_bytes
                ),
            ));
        }
        Ok(())
    }

    fn remove(&mut self, id: &str) {
        let Some(record) = self.records.remove(id) else {
            return;
        };
        self.order.remove(&record.position);
        self.live_bytes -= record.line.len() as u64;
        for attempt in &record.attempts {
            if let Some(count) = self.reserved.get_mut(attempt) {
                *count -= 1;
                if *count == 0 {
                    self.reserved.remove(attempt);
                }
            }
        }
    }
}

impl Records for RequestRecords {
    type Parsed = Parsed;
    const NAME: &'static str = NAME;
    const LINE_BOUND: u64 = LINE_BOUND;
    const RECORD: &'static str = "request record";
    const ADVICE: &'static str = "move it aside to start without request records";
    const LOG: &'static str = "request log";

    fn parse(line: &[u8]) -> std::result::Result<Parsed, LineError> {
        parse_line(line)
    }

    fn apply(&mut self, parsed: Parsed, line: Vec<u8>) {
        RequestRecords::apply(self, parsed, line);
    }

    fn live_lines(&self) -> Vec<&[u8]> {
        self.order
            .values()
            .map(|id| self.records[id].line.as_slice())
            .collect()
    }

    fn live_bytes(&self) -> u64 {
        self.live_bytes
    }

    /// No record is running (§5.5 Compaction).
    fn may_compact(&self) -> bool {
        !self.records.values().any(|r| r.t == Status::Running)
    }

    fn compaction_floor(&self) -> u64 {
        self.limits.compaction_floor
    }

    #[cfg(test)]
    fn take_test_faults() -> Vec<Fault> {
        TEST_FAULTS.with(|faults| faults.take())
    }
}

impl StateLog<RequestRecords> {
    /// Opens the log of the state directory `dir` (§5.5 Open) through the
    /// engine: the checked open, file and directory syncs before anything is
    /// acted on, the streaming replay with torn-tail truncation, then removal
    /// of leftover compaction temp files. Every refusal comes before
    /// `reconcile`, which discards every attempt, so nothing is pinned yet.
    pub fn open(dir: &Path, limits: Limits) -> Result<Self> {
        Self::open_with(dir, RequestRecords::new(limits))
    }

    pub fn limits(&self) -> Limits {
        self.records.limits
    }

    /// The live record of `id`: its state and `op_hash`.
    pub fn lookup(&self, id: &str) -> Option<(Status, &str)> {
        self.event("lookup");
        self.records
            .records
            .get(id)
            .map(|r| (r.t, r.op_hash.as_str()))
    }

    /// The stored target of the live finalize record `id` (ruling 5).
    pub fn target(&self, id: &str) -> Option<&Target> {
        self.records
            .records
            .get(id)
            .and_then(|record| record.subject.target())
    }

    /// Whether a live record names attempt `id` (§5.6).
    pub fn is_reserved(&self, id: &str) -> bool {
        self.records.reserved.contains_key(id)
    }

    /// Pins `target`: its finalize records are never evicted until
    /// [`unpin`](Self::unpin) (approval note (a)).
    pub fn pin(&mut self, target: Target) {
        self.records
            .pins
            .get_or_insert_with(Pins::default)
            .targets
            .insert(target);
    }

    /// Unpins `target`, whose attempt is gone; its records become evictable.
    pub fn unpin(&mut self, target: &Target) {
        if let Some(pins) = &mut self.records.pins {
            pins.targets.remove(target);
        }
    }

    /// The targets that exist after a restart, replacing every pin. Replay
    /// already evicted exactly what the run evicted, so nothing is evicted
    /// here.
    pub fn set_pins(&mut self, pins: Pins) {
        self.records.pins = Some(pins);
    }

    /// Before a line of `bytes` for `id` is written (approval note (a)):
    /// each pinned record that line would evict is appended again, byte for
    /// byte, which moves it to the end of the retry window, so the line
    /// evicts only unpinned records. A replay applies the same lines in the
    /// same order and so evicts what the run evicted, without pins. A failed
    /// append is truncated away when possible, else the log is `Broken`.
    fn make_room(&mut self, id: &str, bytes: u64) -> Result<()> {
        let mut moved = HashSet::new();
        loop {
            let pinned = self
                .records
                .victims(id, bytes)
                .into_iter()
                .find(|victim| self.records.pinned(&self.records.records[victim]));
            // Every candidate pinned is what `admit` keeps from happening.
            let Some(victim) = pinned.filter(|victim| moved.insert(victim.clone())) else {
                return Ok(());
            };
            let record = &self.records.records[&victim];
            let (line, subject, t, op_hash, attempts) = (
                record.line.clone(),
                record.subject.clone(),
                record.t,
                record.op_hash.clone(),
                record.attempts.clone(),
            );
            if let Err((error, truncated)) = self.write(&line, Append::Rotation) {
                let error = failure(self.path(), "cannot append to", error);
                if !truncated {
                    self.broken = Some(format!(
                        "a failed append moving request record {victim} could not be truncated ({})",
                        error.message
                    ));
                }
                return Err(error);
            }
            self.apply_new(&victim, subject, t, &op_hash, attempts, line);
        }
    }

    /// The stored answer of a `done` (`Ok(result)`) or `failed` (`Err(error)`)
    /// record, unchanged since it was first answered.
    pub fn stored(&self, id: &str) -> Result<Value> {
        let unreadable =
            || ApiError::new("io", format!("stored request record {id} is unreadable"));
        let record = self.records.records.get(id).ok_or_else(unreadable)?;
        let input: LineIn = serde_json::from_slice(&record.line).map_err(|_| unreadable())?;
        match (input.result, input.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(ApiError::new(&error.code, error.message)),
            _ => Err(unreadable()),
        }
    }

    /// Appends `running` before the request runs (§5.3 step 4). A failed
    /// write or sync is truncated away: if that works the log stays open and
    /// memory is exactly as before, else the log is `Broken`.
    pub fn begin(&mut self, id: &str, op_hash: &str) -> Result<()> {
        self.begin_with(id, Subject::New, op_hash)
    }

    /// [`begin`](Self::begin) for a finalize of `target`: a `v: 2` line that
    /// stores the target (ruling 5).
    pub fn begin_finalize(&mut self, id: &str, op_hash: &str, target: &Target) -> Result<()> {
        self.begin_with(id, Subject::Finalize(target.clone()), op_hash)
    }

    fn begin_with(&mut self, id: &str, subject: Subject, op_hash: &str) -> Result<()> {
        if self.broken.is_some() {
            return Err(self.unavailable());
        }
        let line = encode_line(id, &subject, Status::Running, op_hash, None, None, None);
        // Fail closed (approval note (a)): no pinned finalize record is ever
        // evicted to make room.
        self.records.admit(id, line.len() as u64)?;
        self.make_room(id, line.len() as u64)?;
        if let Err((error, truncated)) = self.write(&line, Append::Running) {
            let error = failure(self.path(), "cannot append to", error);
            if !truncated {
                self.broken = Some(format!(
                    "a failed running append for {id} could not be truncated ({})",
                    error.message
                ));
            }
            return Err(error);
        }
        self.apply_new(id, subject, Status::Running, op_hash, Vec::new(), line);
        Ok(())
    }

    /// Appends the outcome of the running request `id` (§5.3 step 6), then
    /// answers it. A failed append leaves the log `Broken` with the record
    /// still `running` and answers `io`; the line is truncated back when
    /// possible. Compaction never changes the answer.
    pub fn finish(&mut self, id: &str, op_hash: &str, outcome: Outcome) -> Result<Value> {
        let (t, attempts, line, answer) = match outcome {
            Ok((attempts, result)) => {
                let line = done_line(id, op_hash, &attempts, &result);
                (Status::Done, attempts, line, Ok(result))
            }
            Err(BatchError { error, kept }) if kept.is_empty() => {
                let line = encode_line(
                    id,
                    &Subject::New,
                    Status::Retryable,
                    op_hash,
                    None,
                    None,
                    None,
                );
                (Status::Retryable, kept, line, Err(error))
            }
            Err(BatchError { error, kept }) => {
                let line = encode_line(
                    id,
                    &Subject::New,
                    Status::Failed,
                    op_hash,
                    Some(kept.as_slice()),
                    None,
                    Some(&error),
                );
                (Status::Failed, kept, line, Err(error))
            }
        };
        self.finish_with(id, Subject::New, op_hash, t, attempts, line, answer)
    }

    /// The outcome of the running finalize `id` of `target`: `done` with its
    /// report, which names and so reserves the target's ID, or `retryable`:
    /// every finalize error is retryable (nothing needs undoing; a retry
    /// resumes on the same target). Only a restart writes `failed`.
    pub fn finish_finalize(
        &mut self,
        id: &str,
        op_hash: &str,
        target: &Target,
        outcome: Result<Value>,
    ) -> Result<Value> {
        let subject = Subject::Finalize(target.clone());
        let (t, attempts, line) = match &outcome {
            Ok(report) => {
                let attempts = vec![target.id.clone()];
                let line = encode_line(
                    id,
                    &subject,
                    Status::Done,
                    op_hash,
                    Some(&attempts),
                    Some(report),
                    None,
                );
                (Status::Done, attempts, line)
            }
            Err(_) => {
                let line = encode_line(id, &subject, Status::Retryable, op_hash, None, None, None);
                (Status::Retryable, Vec::new(), line)
            }
        };
        self.finish_with(id, subject, op_hash, t, attempts, line, outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_with(
        &mut self,
        id: &str,
        subject: Subject,
        op_hash: &str,
        t: Status,
        attempts: Vec<String>,
        line: Vec<u8>,
        answer: Result<Value>,
    ) -> Result<Value> {
        #[cfg(test)]
        BEFORE_OUTCOME.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
        let written = self.make_room(id, line.len() as u64).and_then(|()| {
            self.write(&line, Append::Outcome)
                .map_err(|(error, _)| failure(self.path(), "cannot append to", error))
        });
        if let Err(error) = written {
            self.broken = Some(format!(
                "the outcome append for {id} failed ({})",
                error.message
            ));
            return Err(error);
        }
        self.apply_new(id, subject, t, op_hash, attempts, line);
        self.maybe_compact();
        answer
    }

    /// Resolves every record a restart cut off to `failed interrupted`, one
    /// synced append each, after `reconcile` has discarded every attempt and
    /// before anything is served (§5.3 Restart). A finalize record keeps its
    /// target and gets the finalize message.
    pub fn resolve_interrupted(&mut self) -> Result<()> {
        let running: Vec<(String, Subject, String)> = self
            .records
            .order
            .values()
            .filter_map(|id| {
                let record = &self.records.records[id];
                (record.t == Status::Running)
                    .then(|| (id.clone(), record.subject.clone(), record.op_hash.clone()))
            })
            .collect();
        for (id, subject, op_hash) in running {
            let message = match subject {
                Subject::New => INTERRUPTED,
                Subject::Finalize(_) => FINALIZE_INTERRUPTED,
            };
            let error = ApiError::new("interrupted", message);
            let line = encode_line(
                &id,
                &subject,
                Status::Failed,
                &op_hash,
                Some(&[][..]),
                None,
                Some(&error),
            );
            self.make_room(&id, line.len() as u64)?;
            if let Err((error, _)) = self.write(&line, Append::Resolution) {
                return Err(failure(
                    self.path(),
                    "cannot resolve an interrupted request in",
                    error,
                ));
            }
            self.apply_new(&id, subject, Status::Failed, &op_hash, Vec::new(), line);
        }
        Ok(())
    }

    /// Applies a durable line to memory, as replay does.
    fn apply_new(
        &mut self,
        id: &str,
        subject: Subject,
        t: Status,
        op_hash: &str,
        attempts: Vec<String>,
        line: Vec<u8>,
    ) {
        self.records.apply(
            Parsed {
                id: id.into(),
                subject,
                t,
                op_hash: op_hash.into(),
                attempts,
            },
            line,
        );
    }

    #[cfg(test)]
    pub fn status(&self, id: &str) -> Option<Status> {
        self.records.records.get(id).map(|r| r.t)
    }
}
