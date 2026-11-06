//! Retained attempts (R1c-1 §5.5–§5.8): `retain` on `new`, the commit of a
//! finalized attempt into `state/retained/ID`, `retained.jsonl` (the
//! state-log engine's second instance), the retained map, the `held`
//! set behind `--max-retained` and the reserved IDs, and the
//! `retained/ID/overlay` lower exception.
//!
//! Identity (ruling 3): every record holds what restart recovery (R1c-2)
//! resolves by: the attempt ID and instance, the paths, `layer_digest`,
//! `sealed_at`, the prefix (each lower's path, digest and `sealed_at`) and
//! `over` (the retained attempts it was stacked on, by requested path).
//! Nothing here looks a layer up by its digest.

use super::daemon::{io_error, validate_name, Supervisor};
use super::finalize::{scope_preflight, Scope};
use super::lowers;
use super::process::Mounter;
use super::protocol::{ApiError, Attempt, Base, Overlay};
#[cfg(test)]
use super::state_log::Fault;
use super::state_log::{failure, Append, LineError, Records, StateLog};
use ratarmount_compositing::{LowerLayerRecord, OverlayError, OverlayMeta};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

type Result<T> = std::result::Result<T, ApiError>;

pub const NAME: &str = "retained.jsonl";
/// Longest `retained.jsonl` line, newline included: a report of about
/// 3 KiB, `over`, and 32 prefix records with paths of up to about 1.8 KiB.
pub const LINE_BOUND: u64 = 64 << 10;
/// `--max-retained`'s default and cap: at most 256 MiB of live lines.
pub const MAX_RETAINED: usize = 4096;
/// The directory of the retained trees in the state directory.
pub const DIR: &str = "retained";

#[cfg(test)]
thread_local! {
    // One-shot fault points; the next `RetainedLog::open` on this thread takes them.
    pub static TEST_FAULTS: std::cell::RefCell<Vec<Fault>> = const { std::cell::RefCell::new(Vec::new()) };
    // Installed before `Supervisor::open`; consumed by that startup only.
    pub static TEST_STARTUP_SEAMS: std::cell::RefCell<Option<super::finalize::Seams>> = const { std::cell::RefCell::new(None) };
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Retained,
    Aborted,
}

/// Where a retained attempt's layer and bundle are.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    pub overlay: PathBuf,
    pub bundle: Option<PathBuf>,
}

/// One `retained.jsonl` line (`v: 1`). A `retained` line carries every
/// member; an `aborted` line only `v`, `id` and `t`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Line {
    v: u32,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<String>,
    t: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    layer_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_at: Option<String>,
    // `prefix` reuses R1b's `LowerLayerRecord`, which is also the overlay
    // metadata's shape and stays open to unknown members: a member a later
    // release adds inside it is dropped in memory (the envelope is what is
    // strict), while compaction copies the line byte for byte, so nothing
    // is lost on disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<Vec<LowerLayerRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    over: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paths: Option<Paths>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<Value>,
}

/// What a `retained` record says, the identity R1c-2 resolves by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retained {
    pub id: String,
    pub instance: String,
    pub base: String,
    pub layer_digest: String,
    pub sealed_at: String,
    pub prefix: Vec<LowerLayerRecord>,
    pub over: Vec<String>,
    pub paths: Paths,
    pub report: Value,
}

impl Retained {
    fn line(&self) -> Result<Vec<u8>> {
        let mut line = serde_json::to_vec(&Line {
            v: 1,
            id: self.id.clone(),
            instance: Some(self.instance.clone()),
            t: Kind::Retained,
            base: Some(self.base.clone()),
            layer_digest: Some(self.layer_digest.clone()),
            sealed_at: Some(self.sealed_at.clone()),
            prefix: Some(self.prefix.clone()),
            over: Some(self.over.clone()),
            paths: Some(self.paths.clone()),
            report: Some(self.report.clone()),
        })
        .map_err(|error| {
            ApiError::new(
                "io",
                format!(
                    "the retained record of {} cannot be serialized: {error}",
                    self.id
                ),
            )
        })?;
        line.push(b'\n');
        Ok(line)
    }
}

fn aborted_line(id: &str) -> Vec<u8> {
    let mut line = serde_json::to_vec(&Line {
        v: 1,
        id: id.into(),
        instance: None,
        t: Kind::Aborted,
        base: None,
        layer_digest: None,
        sealed_at: None,
        prefix: None,
        over: None,
        paths: None,
        report: None,
    })
    .expect("retained records serialize to JSON");
    line.push(b'\n');
    line
}

/// A parsed `retained.jsonl` line.
pub enum Parsed {
    Retained(Box<Retained>),
    Aborted(String),
}

fn parse_line(line: &[u8]) -> std::result::Result<Parsed, LineError> {
    let value: Value = serde_json::from_slice(line).map_err(|_| LineError::Damaged)?;
    let schema = |why: &str| Err(LineError::Schema(why.into()));
    let Value::Object(members) = &value else {
        return schema("not an object");
    };
    // Exactly the members of its `t`, as `requests.jsonl` does: an unknown
    // `t` (a later release's, such as R1c-2's `forgotten`) fails closed.
    let wanted: &[&str] = match members.get("t").and_then(Value::as_str) {
        Some("retained") => &[
            "v",
            "id",
            "instance",
            "t",
            "base",
            "layer_digest",
            "sealed_at",
            "prefix",
            "over",
            "paths",
            "report",
        ],
        Some("aborted") => &["v", "id", "t"],
        _ => return schema("unknown or missing t"),
    };
    if let Some(key) = members.keys().find(|key| !wanted.contains(&key.as_str())) {
        return schema(&format!("unexpected member {key}"));
    }
    if let Some(key) = wanted.iter().find(|key| !members.contains_key(**key)) {
        return schema(&format!("missing member {key}"));
    }
    let input: Line =
        serde_json::from_value(value).map_err(|e| LineError::Schema(e.to_string()))?;
    if input.v != 1 {
        return schema(&format!("unknown v {}", input.v));
    }
    if super::daemon::validate_name(&input.id).is_err() {
        return schema("invalid id");
    }
    match input {
        Line {
            id,
            t: Kind::Aborted,
            ..
        } => Ok(Parsed::Aborted(id)),
        Line {
            id,
            instance: Some(instance),
            t: Kind::Retained,
            base: Some(base),
            layer_digest: Some(layer_digest),
            sealed_at: Some(sealed_at),
            prefix: Some(prefix),
            over: Some(over),
            paths: Some(paths),
            report: Some(report),
            ..
        } => {
            if !super::requests::is_instance(&instance) {
                return schema("invalid instance");
            }
            if super::daemon::validate_name(&base).is_err()
                || over
                    .iter()
                    .any(|id| super::daemon::validate_name(id).is_err())
            {
                return schema("invalid base or over");
            }
            Ok(Parsed::Retained(Box::new(Retained {
                id,
                instance,
                base,
                layer_digest,
                sealed_at,
                prefix,
                over,
                paths,
                report,
            })))
        }
        _ => schema("null member on t retained"),
    }
}

struct Live {
    record: Retained,
    line: Vec<u8>,
    position: u64,
}

/// The record rules of `retained.jsonl`: a record is live while its last
/// line is `retained`; `aborted` ends it. No eviction: `--max-retained`
/// bounds the live set.
#[derive(Default)]
pub struct RetainedRecords {
    live: HashMap<String, Live>,
    order: BTreeMap<u64, String>,
    next_position: u64,
    live_bytes: u64,
}

impl RetainedRecords {
    fn remove(&mut self, id: &str) {
        if let Some(live) = self.live.remove(id) {
            self.order.remove(&live.position);
            self.live_bytes -= live.line.len() as u64;
        }
    }
}

impl Records for RetainedRecords {
    type Parsed = Parsed;
    const NAME: &'static str = NAME;
    const LINE_BOUND: u64 = LINE_BOUND;
    const RECORD: &'static str = "retained record";
    const ADVICE: &'static str =
        "moving it aside keeps every retained/ tree; the records restart recovery reads are lost";
    const LOG: &'static str = "retained log";

    fn parse(line: &[u8]) -> std::result::Result<Parsed, LineError> {
        parse_line(line)
    }

    fn apply(&mut self, parsed: Parsed, line: Vec<u8>) {
        match parsed {
            Parsed::Aborted(id) => self.remove(&id),
            Parsed::Retained(record) => {
                self.remove(&record.id);
                let position = self.next_position;
                self.next_position += 1;
                self.live_bytes += line.len() as u64;
                self.order.insert(position, record.id.clone());
                self.live.insert(
                    record.id.clone(),
                    Live {
                        record: *record,
                        line,
                        position,
                    },
                );
            }
        }
    }

    fn live_lines(&self) -> Vec<&[u8]> {
        self.order
            .values()
            .map(|id| self.live[id].line.as_slice())
            .collect()
    }

    fn live_bytes(&self) -> u64 {
        self.live_bytes
    }

    fn may_compact(&self) -> bool {
        true
    }

    fn compaction_floor(&self) -> u64 {
        1 << 20
    }

    #[cfg(test)]
    fn take_test_faults() -> Vec<Fault> {
        TEST_FAULTS.with(|faults| faults.take())
    }
}

/// `retained.jsonl` through the state-log engine.
pub type RetainedLog = StateLog<RetainedRecords>;

impl StateLog<RetainedRecords> {
    pub fn open(dir: &Path) -> Result<Self> {
        Self::open_with(dir, RetainedRecords::default())
    }

    /// The live record of `id`.
    pub fn live(&self, id: &str) -> Option<&Retained> {
        self.records.live.get(id).map(|live| &live.record)
    }

    /// Every ID a live record holds.
    pub fn live_ids(&self) -> impl Iterator<Item = &String> {
        self.records.live.keys()
    }

    pub fn broken(&self) -> bool {
        self.broken.is_some()
    }

    /// Appends a `retained` record (the commit's R2), synced before memory
    /// changes; a failed append is truncated away, else the log is `Broken`.
    pub fn append_retained(&mut self, record: &Retained) -> Result<()> {
        let line = record.line()?;
        self.append(
            line,
            Parsed::Retained(Box::new(record.clone())),
            Append::Retained,
        )
    }

    /// Appends `aborted` for `id`, whose commit rename did not happen.
    pub fn append_aborted(&mut self, id: &str) -> Result<()> {
        self.append(
            aborted_line(id),
            Parsed::Aborted(id.into()),
            Append::Aborted,
        )
    }

    fn append(&mut self, line: Vec<u8>, parsed: Parsed, append: Append) -> Result<()> {
        if self.broken.is_some() {
            return Err(self.unavailable());
        }
        if line.len() as u64 > LINE_BOUND {
            return Err(ApiError::new(
                "capacity",
                format!(
                    "the retained record would take {} bytes, over its {LINE_BOUND}-byte bound",
                    line.len()
                ),
            ));
        }
        #[cfg(test)]
        crate::overlay_pack::events::record(&format!("append {append:?}"), self.path());
        if let Err((error, truncated)) = self.write(&line, append) {
            let error = failure(self.path(), "cannot append to", error);
            if !truncated {
                self.broken = Some(format!(
                    "a failed append could not be truncated ({})",
                    error.message
                ));
            }
            return Err(error);
        }
        self.records.apply(parsed, line);
        self.maybe_compact();
        Ok(())
    }
}

/// A retained attempt this daemon run serves (§5.7).
pub struct RetainedEntry {
    /// The attempt with its `retained/ID/…` paths and status `retained`.
    pub attempt: Attempt,
    pub instance: String,
    /// The report the commit stored and answered.
    pub report: Value,
    /// The layers its child took (for `diff` and step S).
    pub records: Option<Vec<LowerLayerRecord>>,
    /// R4 completed: `retained/` and `attempts/` were synced after the
    /// rename. Until then it is listed as `finalizing` and refused as a lower.
    pub acknowledged: bool,
}

/// Validate without creating paths, recovering a database, or opening any
/// lower. A bad or unreadable top is kept and reserved, but not served.
fn restore_entry(dir: &Path, record: &Retained) -> Option<RetainedEntry> {
    let root = dir.join(&record.id);
    let overlay = root.join("overlay");
    for path in [&root, &overlay] {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return None,
            Err(error) => {
                if error.kind() != io::ErrorKind::NotFound {
                    log::warn!("cannot inspect retained path {}: {error}", path.display());
                }
                return None;
            }
        }
    }
    let report = &record.report;
    let attempt: Attempt = serde_json::from_value(report.get("attempt")?.clone()).ok()?;
    let optional_number = |value: &Value| value.is_null() || value.as_u64().is_some();
    let optional_string = |value: &Value| value.is_null() || value.is_string();
    let stack = report.get("stack_digest")?;
    let hash = report.get("patch_hash")?.as_object()?;
    if report.get("status")?.as_str()? != "retained"
        || hash.get("patch")?.as_str().is_none()
        || !optional_string(hash.get("base")?)
        || hash.get("stack")? != stack
        || hash.get("files")?.as_u64().is_none()
        || hash.get("normalize")?.as_str()? != "strict"
        || hash.get("algo")?.as_str()? != "sha256"
        || !hash.get("excludes")?.is_array()
        || !hash.get("sealed")?.as_bool()?
        || hash.get("base_pending")?.as_bool().is_none()
        || hash.get("base_digest_state")?.as_str().is_none()
        || report.get("fsck_result")?.as_str().is_none()
        || !optional_string(stack)
        || !optional_number(report.get("bytes_written")?)
        || !optional_number(report.get("erofs_denied")?)
        || attempt.id != record.id
        || attempt.base != record.base
        || attempt.status != "retained"
        || attempt.path.as_os_str() != root.join("mnt").as_os_str()
        || attempt.overlay_dir.as_os_str() != overlay.as_os_str()
        || record.paths.overlay.as_os_str() != overlay.as_os_str()
        || report.get("layer_digest")?.as_str()? != record.layer_digest
        || report.get("sealed_at")?.as_str()? != record.sealed_at
        || report.get("manifest_path")? != &json!(root.join("manifest.jsonl"))
    {
        return None;
    }
    let bundle = report.get("bundle")?;
    if bundle.is_null() {
        if record.paths.bundle.is_some() {
            return None;
        }
    } else if bundle != &json!(root.join("bundle.tar.zst"))
        || record.paths.bundle.as_ref().map(|p| p.as_os_str())
            != Some(root.join("bundle.tar.zst").as_os_str())
    {
        return None;
    }
    let summary = report.get("journal_summary")?;
    if !summary.is_null() {
        if summary.get("path")? != &json!(root.join("journal.summary.json")) {
            return None;
        }
        for key in [
            "files_read",
            "files_read_then_written",
            "files_written_blind",
        ] {
            summary.get(key)?.as_u64()?;
        }
    }
    let meta = match OverlayMeta::read_no_recovery(&overlay) {
        Ok(Some(meta)) => meta,
        Ok(None) => return None,
        Err(error) => {
            log::warn!(
                "cannot read retained overlay {}: {error}",
                overlay.display()
            );
            return None;
        }
    };
    let prefix = meta.lower_layers().ok()?;
    if !meta.layer_sealed()
        || meta.get("layer_digest") != Some(record.layer_digest.as_str())
        || meta.get("sealed_at") != Some(record.sealed_at.as_str())
        || prefix.len() != record.prefix.len()
        || prefix.iter().zip(&record.prefix).any(|(actual, saved)| {
            actual.path.as_os_str() != saved.path.as_os_str()
                || actual.layer_digest != saved.layer_digest
                || actual.sealed_at != saved.sealed_at
        })
    {
        return None;
    }
    Some(RetainedEntry {
        attempt,
        instance: record.instance.clone(),
        report: record.report.clone(),
        records: (!record.prefix.is_empty()).then(|| record.prefix.clone()),
        acknowledged: false,
    })
}

/// The not-served refusal of an ID a retained record holds that names no
/// live attempt and no retained-map entry.
fn not_served_error(id: &str) -> ApiError {
    ApiError::new(
        "invalid_request",
        format!(
            "attempt {id} is reserved as retained but this daemon does not serve it: its retained record or tree could not be validated, or its commit did not complete"
        ),
    )
}

fn retained_error(id: &str) -> ApiError {
    ApiError::new(
        "retained",
        format!("attempt {id} is retained; retained attempts are never destroyed"),
    )
}

/// The widest report a retained record of this stack can carry, for the
/// record preflight: every field at its widest.
pub(super) fn widest_report(attempt: &Attempt, root: &Path) -> Value {
    let digest = format!("sha256:{}", "f".repeat(64));
    // A Git base in a SHA-256 repository records `git-tree:` and 64 digits —
    // the widest `patch_hash.base` (a `weak:` stamp is shorter).
    let base = format!("git-tree:{}", "f".repeat(64));
    let path = |name: &str| root.join(name);
    json!({
        "status": "retained",
        "attempt": {
            "id": attempt.id, "base": attempt.base, "path": attempt.path,
            "overlay_dir": attempt.overlay_dir, "status": "retained"
        },
        "patch_hash": {"patch": digest, "base": base, "stack": digest, "files": u64::MAX,
            "normalize": "strict", "algo": "sha256", "excludes": [], "sealed": true,
            "base_pending": false, "base_digest_state": "present"},
        "layer_digest": digest,
        "sealed_at": "0000-00-00T00:00:00.000000000+00:00",
        "stack_digest": digest,
        "fsck_result": format!("repaired:{}", u64::MAX),
        "bytes_written": u64::MAX,
        "erofs_denied": u64::MAX,
        "manifest_path": path("manifest.jsonl"),
        "journal_summary": {"path": path("journal.summary.json"), "files_read": u64::MAX,
            "files_read_then_written": u64::MAX, "files_written_blind": u64::MAX},
        "bundle": path("bundle.tar.zst"),
    })
}

impl<M: Mounter> Supervisor<M> {
    pub(super) fn retained_dir(&self) -> PathBuf {
        self.root.join(DIR)
    }

    /// Every ID `--max-retained` counts and the redraw check refuses: the
    /// live records (this run's, and those from before a restart, also a
    /// record whose rename never happened), the names found under
    /// `retained/` without a record, and the live attempts created with
    /// `retain`. Each once.
    pub(super) fn held(&self) -> BTreeSet<String> {
        self.retained_log
            .live_ids()
            .cloned()
            .chain(self.bare_retained.iter().cloned())
            .chain(
                self.attempt_state
                    .iter()
                    .filter(|(id, state)| state.retain && self.attempts.contains_key(*id))
                    .map(|(id, _)| id.clone()),
            )
            .collect()
    }

    pub(super) fn not_served(&self, id: &str) -> ApiError {
        not_served_error(id)
    }

    /// The target of the retained-map entry `id`.
    pub(super) fn retained_target(&self, id: &str) -> Option<super::requests::Target> {
        self.retained.get(id).map(|entry| super::requests::Target {
            id: id.into(),
            instance: entry.instance.clone(),
        })
    }

    /// Whether `target` was retained and is kept but not served: a live
    /// record holds its ID and instance, and
    /// `retained/ID/overlay` is that record's layer, sealed with its
    /// `layer_digest` and `sealed_at`. A stray directory proves nothing. A
    /// metadata read that fails is the check's own error, never "not the
    /// layer".
    pub(super) fn kept_unserved(
        &self,
        target: &super::requests::Target,
    ) -> std::result::Result<bool, ratarmount_compositing::OverlayError> {
        let Some(record) = self.retained_log.live(&target.id) else {
            return Ok(false);
        };
        if record.instance != target.instance {
            return Ok(false);
        }
        let overlay = self.retained_dir().join(&target.id).join("overlay");
        match OverlayMeta::read_no_recovery(&overlay) {
            // No overlay at all is no layer: a stray tree proves nothing.
            Err(OverlayError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
            Ok(meta) => Ok(meta.is_some_and(|meta| {
                meta.layer_sealed()
                    && meta.get("layer_digest") == Some(record.layer_digest.as_str())
                    && meta.get("sealed_at") == Some(record.sealed_at.as_str())
            })),
        }
    }

    /// `destroy {id}` of a retained-map entry, acknowledged or not, or of an
    /// ID a retained record holds that names no live attempt: `retained`.
    pub(super) fn refuse_retained_destroy(&self, id: &str) -> Result<()> {
        if self.retained.contains_key(id)
            || (!self.attempts.contains_key(id) && self.held().contains(id))
        {
            return Err(retained_error(id));
        }
        Ok(())
    }

    /// The attempt `diff` and `stats` read: a live attempt (with its
    /// recorded lowers), else a retained-map entry; an ID a retained record
    /// holds otherwise is not served.
    #[allow(clippy::type_complexity)]
    pub(super) fn served(
        &self,
        id: &str,
    ) -> Result<(Attempt, Option<Option<Vec<LowerLayerRecord>>>)> {
        if let Some(attempt) = self.attempts.get(id) {
            return Ok((attempt.clone(), self.taken_lowers.get(id).cloned()));
        }
        if let Some(entry) = self.retained.get(id) {
            return Ok((entry.attempt.clone(), entry.records.clone().map(Some)));
        }
        if self.held().contains(id) {
            return Err(not_served_error(id));
        }
        Err(ApiError::new("not_found", "unknown attempt"))
    }

    /// v2 `list` with `all`: the attempts, then the served retained entries
    /// in ID order (`finalizing` until their commit is acknowledged).
    pub(super) fn list_all(&self, base: Option<String>) -> Result<Value> {
        if let Some(name) = &base {
            self.base(name)?;
        }
        let keep = |attempt: &Attempt| base.as_ref().is_none_or(|b| b == &attempt.base);
        let mut items: Vec<Value> = self
            .attempts
            .values()
            .filter(|attempt| keep(attempt))
            .map(|attempt| json!(attempt))
            .collect();
        for entry in self.retained.values() {
            if keep(&entry.attempt) {
                let mut attempt = entry.attempt.clone();
                if !entry.acknowledged {
                    attempt.status = "finalizing".into();
                }
                items.push(json!(attempt));
            }
        }
        Ok(Value::Array(items))
    }

    /// The acknowledged retained IDs R1b's place rule accepts as lowers.
    pub(super) fn retained_lowers(&self) -> BTreeSet<String> {
        self.retained
            .iter()
            .filter(|(_, entry)| entry.acknowledged)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// `over`: the retained IDs whose `retained/<ID>/overlay` the stack
    /// names, from the requested paths (never from a digest, ruling 3).
    pub(super) fn over(&self, layered: &[lowers::Lower]) -> Vec<String> {
        let dir = self.retained_dir();
        layered
            .iter()
            .filter_map(|lower| {
                let rest = lower.path.strip_prefix(&dir).ok()?;
                let mut parts = rest.components();
                let id = parts.next()?.as_os_str().to_str()?.to_owned();
                (parts.next()?.as_os_str() == "overlay" && parts.next().is_none()).then_some(id)
            })
            .collect()
    }

    /// The `retain` rules of the scope preflight before any lower is read
    /// (§5.5): the base and archive rules, a disk overlay, room under
    /// `--max-retained`, a usable `retained.jsonl`, and the durability rule
    /// for `attempts/` and `indexes/<base>/` and their chains.
    pub(super) fn retain_preflight(
        &self,
        base: &Base,
        overlay: Overlay,
        count: usize,
    ) -> Result<()> {
        let indexes = self.indexes(&base.name);
        scope_preflight(base, &indexes, Scope::Retain)?;
        if let Overlay::Tmpfs = overlay {
            return Err(ApiError::new(
                "invalid_request",
                "retain needs a disk overlay: a RAM overlay lives outside attempts/ID, so the commit could not move it into retained/",
            ));
        }
        let held = self.held().len();
        if held + count > self.max_retained {
            return Err(ApiError::new(
                "capacity",
                format!(
                    "retaining {count} more attempts would pass --max-retained {} ({held} IDs are held by retained records and attempts created with retain)",
                    self.max_retained
                ),
            ));
        }
        if self.retained_log.broken() {
            return Err(self.retained_log.unavailable());
        }
        // `attempts/` holds the running attempts' `mnt` mounts, so it is
        // the one exemption from §5.5's mount check here; the
        // prepared-index tree never holds a live mount.
        let attempts = self.root.join("attempts");
        self.retain_trees_preflight(attempts.as_path(), false)?;
        self.retain_trees_preflight(indexes.as_path(), true)
    }

    /// After R1b's validation, with its canonical paths: the durability rule
    /// for each lower (a directory lower's root; a bundle position's cache
    /// directory, or its deepest existing ancestor), then the record
    /// preflight: the `retained.jsonl` line an attempt would write, at its
    /// widest, must fit 64 KiB.
    pub(super) fn retain_lower_preflight(
        &self,
        base: &Base,
        layered: &[lowers::Lower],
        over: &[String],
    ) -> Result<Option<PathBuf>> {
        // Resolve once: the estimate, durability check and every child in a
        // batch must all use exactly the same bundle cache directory.
        let cache = if layered
            .iter()
            .any(|lower| lower.kind == lowers::Kind::Bundle)
        {
            Some(self.retain_cache_path()?)
        } else {
            None
        };
        let mut prefix = Vec::new();
        for lower in layered {
            match lower.kind {
                lowers::Kind::Directory => {
                    self.lowers_preflight([lower.path.as_path()])?;
                    prefix.push(LowerLayerRecord {
                        path: lower.path.clone(),
                        layer_digest: lower.layer_digest().into(),
                        sealed_at: lower.sealed_at().into(),
                    });
                }
                lowers::Kind::Bundle => {
                    prefix.push(LowerLayerRecord {
                        path: cache
                            .as_ref()
                            .expect("bundle cache resolved")
                            .join("f".repeat(64)),
                        layer_digest: lower.layer_digest().into(),
                        sealed_at: lower.sealed_at().into(),
                    });
                }
            }
        }
        // The future line, with the real state paths and an ID of the
        // drawn IDs' fixed length.
        const PLACEHOLDER: &str = "attempt-000000";
        let root = self.retained_dir().join(PLACEHOLDER);
        let attempt = Attempt {
            id: PLACEHOLDER.into(),
            base: base.name.clone(),
            path: root.join("mnt"),
            overlay_dir: root.join("overlay"),
            status: "retained".into(),
        };
        let record = Retained {
            id: PLACEHOLDER.into(),
            instance: "f".repeat(32),
            base: base.name.clone(),
            layer_digest: format!("sha256:{}", "f".repeat(64)),
            sealed_at: "0000-00-00T00:00:00.000000000+00:00".into(),
            prefix,
            over: over.to_vec(),
            paths: Paths {
                overlay: root.join("overlay"),
                bundle: Some(root.join("bundle.tar.zst")),
            },
            report: widest_report(&attempt, &root),
        };
        let size = record.line()?.len() as u64;
        if size > LINE_BOUND {
            return Err(ApiError::new(
                "capacity",
                format!(
                    "the retained record of this stack would take {size} bytes, over its {LINE_BOUND}-byte bound; use fewer or shorter lower paths"
                ),
            ));
        }
        Ok(cache)
    }

    /// Resolve the existing portion before judging the future cache tree.
    /// A missing component followed by `..` cannot be normalized safely:
    /// creating the missing directory may lead to a different filesystem.
    fn retain_cache_path(&self) -> Result<PathBuf> {
        let root = self.cache_root().ok_or_else(|| {
            ApiError::new(
                "invalid_request",
                "a bundle lower needs a cache directory: neither XDG_CACHE_HOME nor HOME is set",
            )
        })?;
        let layers = root.join("ratarmount/layers");
        let layers = if layers.is_absolute() {
            layers
        } else {
            std::env::current_dir()
                .map_err(|e| io_error("the bundle cache path", &layers, e))?
                .join(layers)
        };
        let mut existing = layers.as_path();
        let resolved = loop {
            match existing.canonicalize() {
                Ok(path) => break path,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    existing = existing.parent().ok_or_else(|| {
                        ApiError::new(
                            "invalid_request",
                            "the bundle cache has no existing ancestor",
                        )
                    })?;
                }
                Err(error) => {
                    return Err(ApiError::new(
                        "invalid_request",
                        format!(
                            "the bundle cache path {} cannot be resolved: {error}",
                            layers.display()
                        ),
                    ));
                }
            }
        };
        let suffix = layers.strip_prefix(existing).expect("cache ancestor");
        if suffix.components().any(|part| part == Component::ParentDir) {
            return Err(ApiError::new(
                "invalid_request",
                format!(
                    "the unresolved bundle cache path {} contains '..'",
                    layers.display()
                ),
            ));
        }
        let canonical = resolved.join(suffix);
        if canonical.to_str().is_none() {
            return Err(ApiError::new(
                "invalid_request",
                format!(
                    "the bundle cache path {} is not UTF-8, so a retained record cannot name it",
                    layers.display()
                ),
            ));
        }
        // Only the eventual cache tree itself can contain a mount relevant
        // to this check; mounts elsewhere below an ancestor are unrelated.
        self.retain_trees_preflight(&resolved, existing == layers)?;
        Ok(canonical)
    }

    /// The bundle cache root the child will use (`XDG_CACHE_HOME`, else
    /// `$HOME/.cache`; the child inherits the daemon's environment).
    fn cache_root(&self) -> Option<PathBuf> {
        #[cfg(test)]
        if let Some(root) = &self.seams.cache_root {
            return Some(root.clone());
        }
        std::env::var_os("XDG_CACHE_HOME")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cache")))
    }

    /// At finalize of an attempt created with `retain`, before the stop: the
    /// rules that can change after `new` (`--max-retained` counted it then).
    pub(super) fn retain_finalize_preflight(&self, attempt: &Attempt) -> Result<()> {
        if self.retained_log.broken() {
            return Err(self.retained_log.unavailable());
        }
        if !attempt
            .overlay_dir
            .starts_with(attempt.path.parent().expect("attempt root"))
        {
            return Err(ApiError::new(
                "invalid_request",
                "retain needs a disk overlay",
            ));
        }
        Ok(())
    }

    /// The commit of a finalized attempt (§5.6 R2–R5); S (R1) ran already.
    pub(super) fn commit_retained(
        &mut self,
        target: &super::requests::Target,
        attempt: &Attempt,
        report: Value,
        records: &[LowerLayerRecord],
    ) -> Result<Value> {
        let id = target.id.clone();
        let old_root = attempt.path.parent().expect("attempt root").to_path_buf();
        let new_root = self.retained_dir().join(&id);
        let retained_attempt = Attempt {
            id: id.clone(),
            base: attempt.base.clone(),
            path: new_root.join("mnt"),
            overlay_dir: new_root.join("overlay"),
            status: "retained".into(),
        };
        // The report names the final paths.
        let mut report = report;
        report["status"] = json!("retained");
        report["attempt"] = json!(retained_attempt);
        for key in ["manifest_path", "bundle"] {
            if let Some(path) = report[key].as_str() {
                let moved = Path::new(path)
                    .strip_prefix(&old_root)
                    .map(|rest| new_root.join(rest))
                    .unwrap_or_else(|_| PathBuf::from(path));
                report[key] = json!(moved);
            }
        }
        if let Some(path) = report["journal_summary"]["path"].as_str() {
            let moved = Path::new(path)
                .strip_prefix(&old_root)
                .map(|rest| new_root.join(rest))
                .unwrap_or_else(|_| PathBuf::from(path));
            report["journal_summary"]["path"] = json!(moved);
        }
        let over = self.attempt_state[&id].over.clone();
        let record = Retained {
            id: id.clone(),
            instance: target.instance.clone(),
            base: attempt.base.clone(),
            layer_digest: report["layer_digest"].as_str().unwrap_or("").into(),
            sealed_at: report["sealed_at"].as_str().unwrap_or("").into(),
            prefix: records.to_vec(),
            over,
            paths: Paths {
                overlay: retained_attempt.overlay_dir.clone(),
                bundle: report["bundle"].as_str().map(PathBuf::from),
            },
            report: report.clone(),
        };
        #[cfg(test)]
        self.commit_point("after_sync");
        // R2: the record, durable before the rename.
        self.retained_log.append_retained(&record)?;
        #[cfg(test)]
        self.commit_point("after_record");
        // R3: the rename, which never replaces anything.
        let renamed = crate::overlay_pack::rename_no_replace(
            rustix::fs::CWD,
            old_root.to_str().expect("UTF-8 state directory"),
            rustix::fs::CWD,
            new_root.to_str().expect("UTF-8 state directory"),
        );
        #[cfg(test)]
        crate::overlay_pack::events::record("rename", &new_root);
        if let Err(errno) = renamed {
            let why = if errno == rustix::io::Errno::INVAL {
                format!(
                    "{errno}: the filesystem of {} does not support no-replace renames (use ext4, xfs, btrfs or tmpfs)",
                    self.root.display()
                )
            } else {
                errno.to_string()
            };
            // The record names a commit that never happened.
            if let Err(error) = self.retained_log.append_aborted(&id) {
                log::warn!("cannot end the retained record of {id}: {}", error.message);
            }
            return Err(io_error(
                &format!("retain of attempt {id}: moving it into retained/"),
                &new_root,
                why,
            ));
        }
        #[cfg(test)]
        self.commit_point("after_rename");
        // The entry leaves the attempts map at once: memory always names
        // where the tree is.
        self.attempt_state.remove(&id).expect("attempt state");
        self.attempts.remove(&id);
        let taken = self.taken_lowers.remove(&id).flatten();
        self.mounter.forget_child(&attempt.path);
        self.retained.insert(
            id.clone(),
            RetainedEntry {
                attempt: retained_attempt,
                instance: target.instance.clone(),
                report: report.clone(),
                records: taken,
                acknowledged: false,
            },
        );
        // R4: the rename made durable.
        self.acknowledge(&id)?;
        Ok(report)
    }

    /// R4: `retained/`, then `attempts/`, synced. A failed fsync poisons the
    /// state filesystem. Startup uses one R4 for the whole restored batch.
    fn sync_rename_dirs(&mut self) -> Result<()> {
        let retained = self.retained_dir();
        let attempts = self.root.join("attempts");
        self.sync_dir_strict(&retained)?;
        self.sync_dir_strict(&attempts)?;
        Ok(())
    }

    /// Complete R4 for one in-run commit or retry.
    fn acknowledge(&mut self, id: &str) -> Result<()> {
        self.sync_rename_dirs()?;
        #[cfg(test)]
        self.commit_point("after_acknowledge");
        if let Some(entry) = self.retained.get_mut(id) {
            entry.acknowledged = true;
        }
        Ok(())
    }

    /// A finalize of a retained-map entry: the fast path over `retained/ID`
    /// (S again over what the stored report references), and R4 when the
    /// commit's was not acknowledged.
    pub(super) fn finalize_retained(
        &mut self,
        target: &super::requests::Target,
        pack: bool,
    ) -> Result<Value> {
        let id = target.id.clone();
        let entry = &self.retained[&id];
        let report = entry.report.clone();
        if pack && report["bundle"].is_null() {
            return Err(ApiError::new(
                "invalid_request",
                format!(
                    "attempt {id} was finalized without a bundle; run `ratarmount overlay pack` on its layer"
                ),
            ));
        }
        let attempt = entry.attempt.clone();
        let records = entry.records.clone().unwrap_or_default();
        lowers::recorded_layers(&records).map_err(super::finalize::lower_changed)?;
        let base = self.base(&attempt.base)?.clone();
        let indexes = self.indexes(&base.name);
        let root = attempt.path.parent().expect("retained root").to_path_buf();
        self.retained_trees_preflight(&attempt, &root, &indexes, &records)?;
        self.sync_step(&attempt, &root, &indexes, &records)?;
        if !self.retained[&id].acknowledged {
            self.acknowledge(&id)?;
        }
        Ok(report)
    }

    /// Restore only records whose exact retained tree, report and top seal
    /// agree. The record precedes the rename, so a record alone proves
    /// nothing. Reconcile runs later and may remove a stale attempts/ID even
    /// when a fully validated retained/ID also exists.
    pub(super) fn restore_retained(&mut self) {
        if !cfg!(target_os = "linux") {
            return;
        }
        let ids: Vec<_> = self.retained_log.live_ids().cloned().collect();
        for id in ids {
            if let Some(entry) = self
                .retained_log
                .live(&id)
                .and_then(|record| restore_entry(&self.retained_dir(), record))
            {
                self.retained.insert(id, entry);
            }
        }
        if self.retained.is_empty() {
            return;
        }
        match self.sync_rename_dirs() {
            Ok(()) => {
                for entry in self.retained.values_mut() {
                    entry.acknowledged = true;
                }
            }
            Err(error) => log::warn!(
                "cannot acknowledge restored retained attempts: {}; they remain finalizing",
                error.message
            ),
        }
    }

    #[cfg(test)]
    fn commit_point(&mut self, point: &str) {
        if let Some(hook) = self.seams.commit_points.as_mut() {
            hook(point);
        }
    }

    /// Opens `retained/` and `retained.jsonl` at start, between the request
    /// log and `reconcile` (§5.7 restart): the names under `retained/`
    /// without a live record are kept, never entered or served.
    pub(super) fn open_retained(root: &Path) -> Result<(RetainedLog, BTreeSet<String>)> {
        super::daemon::private_dir(&root.join(DIR))?;
        let log = RetainedLog::open(root)?;
        let mut bare = BTreeSet::new();
        for entry in fs::read_dir(root.join(DIR))
            .map_err(|e| io_error("start: listing retained attempts", &root.join(DIR), e))?
        {
            let entry = entry
                .map_err(|e| io_error("start: listing retained attempts", &root.join(DIR), e))?;
            let Ok(name) = entry.file_name().into_string() else {
                return Err(ApiError::new(
                    "invalid_request",
                    format!(
                        "{}: a name under retained/ is not UTF-8; move it aside",
                        root.join(DIR).display()
                    ),
                ));
            };
            // As `reconcile` asks of `attempts/` entries: an attempt-ID name
            // of a real directory (a file or link is never a kept attempt).
            // A stray entry is refused, never counted toward --max-retained
            // or served.
            let meta = fs::symlink_metadata(entry.path())
                .map_err(|e| io_error("start: checking a retained entry", &entry.path(), e))?;
            if validate_name(&name).is_err() || !meta.is_dir() {
                return Err(ApiError::new(
                    "invalid_request",
                    format!(
                        "{}: not a directory with an attempt-ID name; move it aside",
                        entry.path().display()
                    ),
                ));
            }
            if log.live(&name).is_none() {
                bare.insert(name);
            }
        }
        Ok((log, bare))
    }
}
