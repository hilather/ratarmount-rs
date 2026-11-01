//! `requests.jsonl`: the append log behind protocol v2 request IDs (Keystone #5).
//!
//! Every line is one self-contained record state: `op` and `op_hash` are on
//! every state, so a record's last line alone decides it. A line is written by
//! one `write_all` and synced before memory changes, so while the log is open
//! memory equals a replay of the file. Open replays the file in order with the
//! append-time eviction rule; compaction rewrites the live last lines verbatim.

use super::daemon::validate_name;
use super::protocol::{one, ApiError, OperationV2, Overlay, VERSION_2};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

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
/// excerpt) is about 185 KB.
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

/// Test-only fault points; each armed point fails its next hit once.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    OpenSyncFile,
    OpenSyncDir,
    OpenTruncate,
    RemoveLeftover,
    /// A short write: half the line reaches the file, then the write fails.
    Write(Append),
    /// After the whole line was written.
    Sync(Append),
    Truncate,
    CompactSync,
    CompactDirSync,
}

/// Which append a line is, for messages and fault points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Append {
    Running,
    Outcome,
    Resolution,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Running,
    Done,
    Retryable,
    Failed,
}

/// The operation a record belongs to; R1c adds `finalize`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    New,
}

#[derive(Serialize)]
struct LineOut<'a> {
    v: u32,
    id: &'a str,
    t: Status,
    op: Kind,
    op_hash: &'a str,
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

fn encode_line(
    id: &str,
    t: Status,
    op_hash: &str,
    attempts: Option<&[String]>,
    result: Option<&Value>,
    error: Option<&ApiError>,
) -> Vec<u8> {
    let mut line = serde_json::to_vec(&LineOut {
        v: 1,
        id,
        t,
        op: Kind::New,
        op_hash,
        attempts,
        result,
        error,
    })
    .expect("request records serialize to JSON");
    line.push(b'\n');
    line
}

/// The exact `done` line; the stored-record preflight measures it in advance.
pub fn done_line(id: &str, op_hash: &str, attempts: &[String], result: &Value) -> Vec<u8> {
    encode_line(
        id,
        Status::Done,
        op_hash,
        Some(attempts),
        Some(result),
        None,
    )
}

/// A parsed line: the record it decides.
struct Parsed {
    id: String,
    t: Status,
    op_hash: String,
    attempts: Vec<String>,
}

enum LineError {
    /// Not valid JSON (a short write, or zero-filled pages after a crash).
    Damaged,
    /// Valid JSON with another schema: corruption or a later release.
    Schema(String),
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
    let common = ["v", "id", "t", "op", "op_hash"];
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
    if input.v != 1 {
        return schema(&format!("unknown v {}", input.v));
    }
    if validate_name(&input.id).is_err() {
        return schema("invalid id");
    }
    if !is_op_hash(&input.op_hash) {
        return schema("invalid op_hash");
    }
    // Every record R1a writes is a `new`; an unknown `op` failed above.
    let Kind::New = input.op;
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
    Ok(Parsed {
        id: input.id,
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
/// their fields here; U5's golden digest holds them to R1a's hashes.
fn defaults(operation: &OperationV2) -> Vec<(&'static str, Value)> {
    match operation {
        OperationV2::New { .. } => vec![
            ("count", json!(one())),
            ("overlay", json!(Overlay::default())),
            ("quota", json!(None::<u64>)),
            ("readonly_globs", json!(Vec::<String>::new())),
        ],
        _ => Vec::new(),
    }
}

/// Object members sorted by their UTF-8 key bytes at every depth, arrays in
/// order, no whitespace, serde_json's scalar encoding. Sorting here keeps the
/// hash independent of serde_json's `preserve_order` feature.
fn canonical(value: &Value, out: &mut Vec<u8>) {
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
    t: Status,
    op_hash: String,
    /// The exact last line, newline included: replays and compaction reuse it.
    line: Vec<u8>,
    /// Order of the last line in the file.
    position: u64,
    /// Attempt IDs the last line names; reserved while the record lives.
    attempts: Vec<String>,
}

pub struct RequestLog {
    path: PathBuf,
    dir: PathBuf,
    /// `None` only after a compaction published the new file but could not
    /// sync its directory; the log is then `Broken` until a restart.
    file: Option<File>,
    /// End of the last durable line.
    len: u64,
    records: HashMap<String, Record>,
    /// Position of each record's last line to its ID, oldest first.
    order: BTreeMap<u64, String>,
    next_position: u64,
    live_bytes: u64,
    reserved: HashMap<String, usize>,
    /// Why appends are refused until a restart (§5.5 `Broken`).
    broken: Option<String>,
    limits: Limits,
    /// Bytes appended since a compaction failed before its rename (backoff).
    since_failed_compaction: Option<u64>,
    #[cfg(test)]
    pub faults: Vec<Fault>,
    #[cfg(test)]
    pub events: std::cell::RefCell<Vec<&'static str>>,
    #[cfg(test)]
    pub line_high_water: usize,
}

/// Opens `requests.jsonl` without following symlinks, creating it if missing,
/// and checks the descriptor as `daemon::lock` does.
fn open_checked(path: &Path) -> Result<File> {
    let file = {
        #[expect(
            clippy::disallowed_types,
            reason = r###"internal-read:v1 {"id":"IR-E0143-T01","item":"ratarmount::sandbox::requests::open_checked","disposition":"support","category":"builder-type-support","reason":"Builder type support: Open the sandbox request log for append.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
        )]
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0143-M01","item":"ratarmount::sandbox::requests::open_checked","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."}}"###
        )]
        let mut __inventory_value_0 = fs::OpenOptions::new();
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0143-M02","item":"ratarmount::sandbox::requests::open_checked","disposition":"output-owner","category":"request-log","reason":"Permit creating the sandbox request log while preserving an existing log inode.","creation":{"policy":"append-or-create","basis":"Read and append with NOFOLLOW/CLOEXEC, 0600 and truncate(false); owner/type/mode/nlink checks run on the acquired descriptor."}}"###
        )]
        let __inventory_value_1 = __inventory_value_0.read(true).append(true).create(true);
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0143-M03","item":"ratarmount::sandbox::requests::open_checked","disposition":"output-owner","category":"request-log","reason":"Open the sandbox request log once per daemon start; compaction keeps its own persisted descriptor.","creation":{"policy":"append-or-create","basis":"Read and append with NOFOLLOW/CLOEXEC, 0600 and truncate(false); owner/type/mode/nlink checks run on the acquired descriptor."}}"###
        )]
        let __inventory_value_2 = __inventory_value_1
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path);
        __inventory_value_2
    }
    .map_err(|e| failure(path, "cannot open", e))?;
    let meta = file
        .metadata()
        .map_err(|e| failure(path, "cannot stat", e))?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(ApiError::new(
            "unsafe_path",
            "requests.jsonl must be a private, owned regular file",
        ));
    }
    Ok(file)
}

/// Makes the state directory's entries durable (creation, compaction rename).
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0145-M01","item":"ratarmount::sandbox::requests::sync_dir","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"directory handle opened only to fsync a directory entry","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this site creates no pathname."}}"###
    )]
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn failure(path: &Path, what: &str, error: io::Error) -> ApiError {
    ApiError::new("io", format!("{}: {what}: {error}", path.display()))
}

/// Skips the rest of an over-long line, returning the bytes skipped.
fn skip_line(reader: &mut impl BufRead) -> io::Result<u64> {
    let mut skipped = 0;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(skipped);
        }
        match buffer.iter().position(|c| *c == b'\n') {
            Some(end) => {
                reader.consume(end + 1);
                return Ok(skipped + end as u64 + 1);
            }
            None => {
                let n = buffer.len();
                reader.consume(n);
                skipped += n as u64;
            }
        }
    }
}

impl RequestLog {
    /// Opens the log of the state directory `dir` (§5.5 Open): the checked
    /// open, file and directory syncs before anything is acted on, the
    /// streaming replay with torn-tail truncation, then removal of leftover
    /// compaction temp files. Every refusal comes before `reconcile`.
    pub fn open(dir: &Path, limits: Limits) -> Result<Self> {
        let path = dir.join(NAME);
        let file = open_checked(&path)?;
        let mut log = Self {
            path,
            dir: dir.into(),
            file: Some(file),
            len: 0,
            records: HashMap::new(),
            order: BTreeMap::new(),
            next_position: 0,
            live_bytes: 0,
            reserved: HashMap::new(),
            broken: None,
            limits,
            since_failed_compaction: None,
            #[cfg(test)]
            faults: TEST_FAULTS.with(|faults| faults.take()),
            #[cfg(test)]
            events: Default::default(),
            #[cfg(test)]
            line_high_water: 0,
        };
        // Make durable whatever a killed daemon left visible but unsynced (a
        // line whose sync never ran, a compaction rename whose directory sync
        // never ran, the file's creation) before acting on it (codex-9 #2).
        log.sync_file()
            .map_err(|e| failure(&log.path, "cannot sync", e))?;
        log.event("file_sync");
        log.sync_state_dir()
            .map_err(|e| failure(&log.path, "cannot sync the directory of", e))?;
        log.event("dir_sync");
        let file = log.file.take().expect("the log was just opened");
        let replayed = log.replay(&file);
        log.file = Some(file);
        replayed?;
        log.remove_leftovers();
        Ok(log)
    }

    /// Reads one line at a time through the checked descriptor and replays
    /// each valid line with the append rule, so memory holds the capped live
    /// set and one line buffer however much history the file has.
    fn replay(&mut self, file: &File) -> Result<()> {
        let mut reader = BufReader::with_capacity(64 << 10, file);
        let mut line = Vec::new();
        let mut offset = 0;
        loop {
            line.clear();
            let read = (&mut reader)
                .take(LINE_BOUND)
                .read_until(b'\n', &mut line)
                .map_err(|e| failure(&self.path, "cannot read", e))?;
            if read == 0 {
                break;
            }
            if offset == 0 {
                self.event("read");
            }
            #[cfg(test)]
            {
                self.line_high_water = self.line_high_water.max(line.len());
            }
            let start = offset;
            offset += read as u64;
            let terminated = line.ends_with(b"\n");
            if !terminated && read as u64 == LINE_BOUND {
                offset +=
                    skip_line(&mut reader).map_err(|e| failure(&self.path, "cannot read", e))?;
            }
            let last = reader
                .fill_buf()
                .map_err(|e| failure(&self.path, "cannot read", e))?
                .is_empty();
            let parsed = if terminated {
                parse_line(&line)
            } else {
                Err(LineError::Damaged)
            };
            match parsed {
                Ok(parsed) => self.apply(parsed, std::mem::take(&mut line)),
                // Every append is synced before the next starts, so only the
                // last line can be physically damaged: it is torn.
                Err(LineError::Damaged) if last => {
                    self.truncate_tail(file, start)
                        .map_err(|e| failure(&self.path, "cannot truncate the torn tail of", e))?;
                    self.event("truncate");
                    offset = start;
                    break;
                }
                Err(LineError::Damaged) => {
                    return Err(ApiError::new(
                        "invalid_request",
                        format!(
                            "{}: damaged request record at byte {start}; move it aside to start without request records",
                            self.path.display()
                        ),
                    ))
                }
                Err(LineError::Schema(why)) => {
                    return Err(ApiError::new(
                        "invalid_request",
                        format!(
                            "{}: unsupported request record at byte {start} ({why}); move it aside to start without request records",
                            self.path.display()
                        ),
                    ))
                }
            }
        }
        self.len = offset;
        Ok(())
    }

    /// Removes leftover compaction temp files (regular files only). A
    /// leftover is harmless, so a failed removal is logged and ignored.
    fn remove_leftovers(&mut self) {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) => {
                log::warn!(
                    "cannot list {} for compaction leftovers: {error}",
                    self.dir.display()
                );
                return;
            }
        };
        let prefix = format!("{NAME}.");
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !(name.len() > prefix.len() + ".compact".len()
                && name.starts_with(&prefix)
                && name.ends_with(".compact"))
            {
                continue;
            }
            let path = entry.path();
            if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
                continue;
            }
            if let Err(error) = self.remove_leftover(&path) {
                log::warn!(
                    "cannot remove compaction leftover {}: {error}",
                    path.display()
                );
            }
        }
    }

    fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("the request log is not open"))
    }

    // Each fault point is one `#[cfg(test)]` statement in a small helper.

    fn sync_file(&mut self) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::OpenSyncFile)?;
        self.file()?.sync_all()
    }

    fn sync_state_dir(&mut self) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::OpenSyncDir)?;
        sync_dir(&self.dir)
    }

    fn truncate_tail(&mut self, file: &File, start: u64) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::OpenTruncate)?;
        file.set_len(start)?;
        file.sync_data()
    }

    fn remove_leftover(&mut self, path: &Path) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::RemoveLeftover)?;
        fs::remove_file(path)
    }

    fn sync_compacted_dir(&mut self) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::CompactDirSync)?;
        sync_dir(&self.dir)
    }

    #[cfg(test)]
    fn check_fault(&mut self, point: Fault) -> io::Result<()> {
        match self.faults.iter().position(|armed| *armed == point) {
            Some(i) => {
                self.faults.remove(i);
                Err(io::Error::other(format!("injected {point:?} failure")))
            }
            None => Ok(()),
        }
    }

    fn event(&self, _name: &'static str) {
        #[cfg(test)]
        self.events.borrow_mut().push(_name);
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// The live record of `id`: its state and `op_hash`.
    pub fn lookup(&self, id: &str) -> Option<(Status, &str)> {
        self.event("lookup");
        self.records.get(id).map(|r| (r.t, r.op_hash.as_str()))
    }

    /// Whether a live record names attempt `id` (§5.6).
    pub fn is_reserved(&self, id: &str) -> bool {
        self.reserved.contains_key(id)
    }

    /// The refusal while the log is `Broken`.
    pub fn unavailable(&self) -> ApiError {
        ApiError::new(
            "io",
            format!(
                "request log unavailable since {}; restart the daemon",
                self.broken.as_deref().unwrap_or("an append failed")
            ),
        )
    }

    /// The stored answer of a `done` (`Ok(result)`) or `failed` (`Err(error)`)
    /// record, unchanged since it was first answered.
    pub fn stored(&self, id: &str) -> Result<Value> {
        let unreadable =
            || ApiError::new("io", format!("stored request record {id} is unreadable"));
        let record = self.records.get(id).ok_or_else(unreadable)?;
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
        if self.broken.is_some() {
            return Err(self.unavailable());
        }
        let line = encode_line(id, Status::Running, op_hash, None, None, None);
        if let Err((error, truncated)) = self.write(&line, Append::Running) {
            let error = failure(&self.path, "cannot append to", error);
            if !truncated {
                self.broken = Some(format!(
                    "a failed running append for {id} could not be truncated ({})",
                    error.message
                ));
            }
            return Err(error);
        }
        self.apply_new(id, Status::Running, op_hash, Vec::new(), line);
        Ok(())
    }

    /// Appends the outcome of the running request `id` (§5.3 step 6), then
    /// answers it. A failed append leaves the log `Broken` with the record
    /// still `running` and answers `io`; the line is truncated back when
    /// possible. Compaction never changes the answer.
    pub fn finish(&mut self, id: &str, op_hash: &str, outcome: Outcome) -> Result<Value> {
        #[cfg(test)]
        BEFORE_OUTCOME.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
        let (t, attempts, line, answer) = match outcome {
            Ok((attempts, result)) => {
                let line = done_line(id, op_hash, &attempts, &result);
                (Status::Done, attempts, line, Ok(result))
            }
            Err(BatchError { error, kept }) if kept.is_empty() => {
                let line = encode_line(id, Status::Retryable, op_hash, None, None, None);
                (Status::Retryable, kept, line, Err(error))
            }
            Err(BatchError { error, kept }) => {
                let line = encode_line(
                    id,
                    Status::Failed,
                    op_hash,
                    Some(kept.as_slice()),
                    None,
                    Some(&error),
                );
                (Status::Failed, kept, line, Err(error))
            }
        };
        if let Err((error, _)) = self.write(&line, Append::Outcome) {
            let error = failure(&self.path, "cannot append to", error);
            self.broken = Some(format!(
                "the outcome append for {id} failed ({})",
                error.message
            ));
            return Err(error);
        }
        self.apply_new(id, t, op_hash, attempts, line);
        self.maybe_compact();
        answer
    }

    /// Resolves every record a restart cut off to `failed interrupted`, one
    /// synced append each, after `reconcile` has discarded every attempt and
    /// before anything is served (§5.3 Restart).
    pub fn resolve_interrupted(&mut self) -> Result<()> {
        let running: Vec<(String, String)> = self
            .order
            .values()
            .filter_map(|id| {
                let record = &self.records[id];
                (record.t == Status::Running).then(|| (id.clone(), record.op_hash.clone()))
            })
            .collect();
        for (id, op_hash) in running {
            let error = ApiError::new("interrupted", INTERRUPTED);
            let line = encode_line(
                &id,
                Status::Failed,
                &op_hash,
                Some(&[][..]),
                None,
                Some(&error),
            );
            if let Err((error, _)) = self.write(&line, Append::Resolution) {
                return Err(failure(
                    &self.path,
                    "cannot resolve an interrupted request in",
                    error,
                ));
            }
            self.apply_new(&id, Status::Failed, &op_hash, Vec::new(), line);
        }
        Ok(())
    }

    /// One `write_all` of the whole line, then `sync_data`; on failure the line
    /// is truncated away when possible: `Err((error, truncated))`. Only the
    /// log's length changes here; callers change memory after this returns.
    fn write(&mut self, line: &[u8], append: Append) -> std::result::Result<(), (io::Error, bool)> {
        self.event("append");
        if let Err(error) = self.write_and_sync(line, append) {
            let truncated = self.truncate(self.len).is_ok();
            return Err((error, truncated));
        }
        self.len += line.len() as u64;
        if let Some(appended) = &mut self.since_failed_compaction {
            *appended += line.len() as u64;
        }
        Ok(())
    }

    fn write_and_sync(&mut self, line: &[u8], _append: Append) -> io::Result<()> {
        #[cfg(test)]
        if self.check_fault(Fault::Write(_append)).is_err() {
            self.file()?.write_all(&line[..line.len() / 2])?;
            return Err(io::Error::other("injected short write"));
        }
        self.file()?.write_all(line)?;
        #[cfg(test)]
        self.check_fault(Fault::Sync(_append))?;
        self.file()?.sync_data()
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::Truncate)?;
        let file = self.file()?;
        file.set_len(len)?;
        file.sync_data()
    }

    /// Applies a durable line to memory, as replay does.
    fn apply_new(
        &mut self,
        id: &str,
        t: Status,
        op_hash: &str,
        attempts: Vec<String>,
        line: Vec<u8>,
    ) {
        self.apply(
            Parsed {
                id: id.into(),
                t,
                op_hash: op_hash.into(),
                attempts,
            },
            line,
        );
    }

    /// The line replaces its ID's record, or creates it, as the newest; then
    /// the oldest finished records other than it are evicted until both caps
    /// hold. A `running` record is never evicted.
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
                t: parsed.t,
                op_hash: parsed.op_hash,
                line,
                position,
                attempts: parsed.attempts,
            },
        );
        while self.records.len() > self.limits.records || self.live_bytes > self.limits.live_bytes {
            let victim = self
                .order
                .values()
                .find(|id| **id != parsed.id && self.records[*id].t != Status::Running)
                .cloned();
            match victim {
                Some(victim) => self.remove(&victim),
                None => break,
            }
        }
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

    /// Compacts after an outcome append when the file is over twice the live
    /// bytes and over the floor, no record is running, and any backoff after a
    /// failure before the rename has passed (§5.5 Compaction).
    fn maybe_compact(&mut self) {
        if self.broken.is_some()
            || self.len <= 2 * self.live_bytes
            || self.len <= self.limits.compaction_floor
            || self.records.values().any(|r| r.t == Status::Running)
            || self
                .since_failed_compaction
                .is_some_and(|appended| appended < self.live_bytes)
        {
            return;
        }
        self.event("compact");
        let (temp, written) = match self.write_compacted() {
            Ok(written) => written,
            Err(error) => {
                log::warn!("cannot compact {}: {error}", self.path.display());
                self.since_failed_compaction = Some(0);
                return;
            }
        };
        let file = match temp.persist(&self.path) {
            Ok(file) => file,
            Err(error) => {
                // Dropping the returned temp file removes it.
                log::warn!("cannot compact {}: {}", self.path.display(), error.error);
                self.since_failed_compaction = Some(0);
                return;
            }
        };
        // The old descriptor now names an unlinked inode: drop it at once so
        // nothing lands there, and refuse appends until the rename is durable.
        self.broken = Some(format!(
            "a compaction of {} published the file before its directory was synced",
            self.path.display()
        ));
        self.file = None;
        match self.sync_compacted_dir() {
            Ok(()) => {
                // `persist` returned the temp file's own O_APPEND descriptor of the
                // published inode, so a failed append's truncation leaves no gap.
                self.file = Some(file);
                self.len = written;
                self.broken = None;
                self.since_failed_compaction = None;
            }
            Err(error) => {
                self.broken = Some(format!(
                    "a compaction could not sync the directory of {} ({error})",
                    self.path.display()
                ));
            }
        }
    }

    /// Writes every live last line, byte for byte and in file order, to a
    /// synced temp file beside the log.
    fn write_compacted(&mut self) -> io::Result<(tempfile::NamedTempFile, u64)> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0144-M01","item":"<ratarmount::sandbox::requests::RequestLog>::write_compacted","disposition":"output-owner","category":"request-log-compaction","reason":"Stage the compacted sandbox request log beside requests.jsonl before an atomic rename.","creation":{"policy":"exclusive-new-file","basis":"tempfile creates the name with O_EXCL, mode 0600 and append inside the 0700 state directory; persist renames it over the log."}}"###
        )]
        let mut temp = tempfile::Builder::new()
            .prefix(&format!("{NAME}."))
            .suffix(".compact")
            .append(true)
            .tempfile_in(&self.dir)?;
        let mut written = 0;
        for id in self.order.values() {
            let line = &self.records[id].line;
            temp.write_all(line)?;
            written += line.len() as u64;
        }
        #[cfg(test)]
        self.check_fault(Fault::CompactSync)?;
        temp.as_file().sync_all()?;
        Ok((temp, written))
    }

    #[cfg(test)]
    pub fn live_lines(&self) -> Vec<Vec<u8>> {
        self.order
            .values()
            .map(|id| self.records[id].line.clone())
            .collect()
    }

    #[cfg(test)]
    pub fn is_broken(&self) -> bool {
        self.broken.is_some()
    }

    #[cfg(test)]
    pub fn status(&self, id: &str) -> Option<Status> {
        self.records.get(id).map(|r| r.t)
    }

    #[cfg(test)]
    pub fn descriptor(&self) -> Option<&File> {
        self.file.as_ref()
    }
}
