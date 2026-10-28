//! Overlay identity, creation metadata, and cheap remount verification.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ratarmount_index::{
    cached_archive_digest_cancellable, peek_archive_digest_for_open, sha256_hex, sha256_hex_stream,
    ArchiveDigestStamp,
};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::write_overlay::Result;
use crate::{OverlayError, HIDDEN_DB};

pub const META_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BaseDigestRequest {
    #[default]
    Compute,
    Supplied(String),
    None,
}

impl std::str::FromStr for BaseDigestRequest {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if value == "none" {
            return Ok(Self::None);
        }
        if let Some(hex) = value.strip_prefix("sha256:") {
            if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(Self::Supplied(format!(
                    "sha256:{}",
                    hex.to_ascii_lowercase()
                )));
            }
        }
        Err("base digest must be sha256:<64 hex digits> or none".into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LowerLayerRecord {
    pub path: PathBuf,
    pub layer_digest: String,
    pub sealed_at: String,
}

/// Identity supplied by a caller that knows the original base positional.
/// `local_path` may differ from `base_url` (for example a pinned remote download).
/// Set `index_path` only for an existing index whose cache may be updated.
///
/// Not public: it is built only from a classified base
/// (`ActualBase::create_info`), or by the in-crate tests.
#[derive(Clone, Debug, Default)]
pub(crate) struct OverlayCreateInfo {
    pub base_url: String,
    pub base_digest: BaseDigestRequest,
    pub lower_layers: Vec<LowerLayerRecord>,
    pub force_base_mismatch: bool,
    pub local_path: Option<PathBuf>,
    /// Built from a classified base: `local_path` is then the only local path,
    /// and the typed `base_url` is never read as one (`rclone+r:p`, `restic:/r`).
    pub classified: bool,
    pub index_path: Option<PathBuf>,
    /// Selected prepared index for immutable creation-time digest reads. This
    /// is separate from the writable cache path persisted in overlay metadata.
    pub prepared_index_for_peek: Option<PathBuf>,
    pub read_only_index: bool,
    /// Tree id of the source actually mounted, after any Git subtree selection.
    pub git_tree: Option<String>,
    /// Cheap remote identity, e.g. ETag or Content-Length + Last-Modified.
    pub remote_token: Option<String>,
    /// Paths of the caller (journal file, `--lower` layer directories) that may
    /// lie inside a directory base and must stay out of its digest.
    pub weak_exclude: Vec<PathBuf>,
}

/// Exclusions for a directory base, resolved before the overlay directory exists.
pub(crate) struct ExcludePlan {
    pub base: PathBuf,
    pub excludes: BaseExcludes,
    /// Entry for the overlay directory itself (when it lies inside the base).
    pub overlay: Option<PathBuf>,
}

/// Resolve the exclusion set for a directory base. Must run before the
/// overlay directory is created: the topmost-new rule depends on what exists.
pub(crate) fn plan_excludes(
    info: &OverlayCreateInfo,
    overlay: &Path,
) -> Result<Option<ExcludePlan>> {
    if info.git_tree.is_some() {
        return Ok(None);
    }
    // `--base-digest none` only applies at creation: it skips the walk for a
    // new overlay, but a reopen compares the recorded identity regardless.
    if info.base_digest == BaseDigestRequest::None && crate::overlay_db_absent(overlay) {
        return Ok(None);
    }
    let Some(path) = info.path().filter(|p| p.is_dir()) else {
        return Ok(None);
    };
    let (base, own) = resolve_base_excludes(path, &[overlay.to_path_buf()])?;
    let mut paths = vec![overlay.to_path_buf()];
    paths.extend(info.weak_exclude.iter().cloned());
    let (_, excludes) = resolve_base_excludes(path, &paths)?;
    Ok(Some(ExcludePlan {
        base,
        excludes,
        overlay: own.paths().first().cloned(),
    }))
}

/// `SQLITE_READONLY_ROLLBACK`: a read-only open found a hot rollback journal
/// (a writer died mid-transaction) that only a read-write open can play back.
fn is_hot_journal(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if code.extended_code == rusqlite::ffi::SQLITE_READONLY_ROLLBACK
    )
}

/// Roll back the hot journal an interrupted writer (a SIGKILLed `overlay
/// import`) left behind, so the read verbs can report on the overlay (fsck
/// then names `import_incomplete`). Only an unsealed overlay whose database
/// and directory are writable is touched; a sealed or read-only one gets an
/// error naming the interrupted write and its journal stays as it is.
/// `required` is the caller's latched requirement; the result is that latch
/// OR'ed with this open's own (a marker seen here is kept for the retry).
fn recover_hot_journal(dir: &Path, db: &Path, required: bool) -> Result<bool> {
    let journal = PathBuf::from(format!("{}-journal", db.display()));
    let refuse = |why: &str| {
        OverlayError::Msg(format!(
            "an interrupted write left {} ({why}); mount -w once on a writable \
             copy to roll it back, or discard the overlay and re-import",
            journal.display()
        ))
    };
    // Sealing exists only where `overlay_seal` is compiled.
    #[cfg(unix)]
    {
        if fs::symlink_metadata(dir.join(crate::overlay_seal::SENTINEL)).is_ok() {
            return Err(refuse("the overlay is sealed and is not rolled back"));
        }
    }
    if !path_writable(dir) || !path_writable(db) {
        return Err(refuse("the overlay or its directory is read-only"));
    }
    let conn = crate::overlay_db::open_overlay_db_required(
        &dir.join(HIDDEN_DB),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        crate::DbName::Path,
        required,
    )?;
    let required = required || conn.required_record();
    conn.busy_timeout(std::time::Duration::ZERO)?;
    // Any read takes the shared lock, which plays the journal back.
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    }) {
        Ok(_) => Ok(required),
        Err(error) if is_hot_journal(&error) => Err(refuse("it could not be rolled back here")),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn path_writable(path: &Path) -> bool {
    rustix::fs::access(path, rustix::fs::Access::WRITE_OK).is_ok()
}

#[cfg(not(unix))]
fn path_writable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| !m.permissions().readonly())
}

/// Highest overlay `format_version` this build reads. Additive keys
/// (`base_weak_digest`, `base_digest_source`, `import_in_progress`, ...) stay
/// within version 2.
pub const MAX_FORMAT_VERSION: u32 = 2;

#[cfg(test)]
thread_local! {
    /// Runs once between the `files` check and the `meta` read of
    /// [`OverlayMeta::from_connection_required`].
    pub(crate) static BETWEEN_REQUIRED_READS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// The refusal of a used overlay's database that has no `files` table.
pub(crate) const NO_FILES_TABLE: &str =
    "the overlay database has no files table (the record of a used overlay is lost)";

/// Does `conn` have the `files` table? Plain SQL (no transaction of its own).
pub(crate) fn has_files_table(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'files')",
        [],
        |row| row.get(0),
    )
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(transparent)]
pub struct OverlayMeta {
    values: BTreeMap<String, String>,
}

impl OverlayMeta {
    /// Read without creating a directory, database, or table. `None` means an
    /// existing legacy database with no meta table; a missing DB is an error.
    pub fn read(dir: impl AsRef<Path>) -> Result<Option<Self>> {
        Self::read_with(dir.as_ref(), true)
    }

    /// [`Self::read`] that never rolls an overlay database's hot `-journal`
    /// back: a hot journal is an error (the caller defers to the open that may
    /// write). For classification before any recovery writes.
    pub fn read_no_recovery(dir: impl AsRef<Path>) -> Result<Option<Self>> {
        Self::read_with(dir.as_ref(), false)
    }

    /// [`Self::read_no_recovery`] of a record that must have a `files` table
    /// when `required` (a marked overlay: its record is the one it used).
    pub(crate) fn read_no_recovery_required(dir: &Path, required: bool) -> Result<Option<Self>> {
        Self::read_with_required(dir, false, required, false)
    }

    /// [`Self::read_no_recovery_required`] that accepts a database entry that
    /// is a symlink to a regular file, as the offline gate's open does (an
    /// offline commit's record, R10-FIX7).
    pub(crate) fn read_no_recovery_required_followed(
        dir: &Path,
        required: bool,
    ) -> Result<Option<Self>> {
        Self::read_with_required(dir, false, required, true)
    }

    fn read_with(dir: &Path, recover_hot: bool) -> Result<Option<Self>> {
        // A marked overlay was used: its database must hold the `files`
        // table, or its record is lost, never "unrecorded" (R10-B).
        let required = !crate::write_overlay::overlay_markers(dir)?.is_empty();
        Self::read_with_required(dir, recover_hot, required, false)
    }

    /// `follow`: the database entry may be a symlink to a regular file (the
    /// open follows it); otherwise it must itself be a regular file.
    fn read_with_required(
        dir: &Path,
        recover_hot: bool,
        required: bool,
        follow: bool,
    ) -> Result<Option<Self>> {
        let latched = std::cell::Cell::new(required);
        Self::read_latched(dir, recover_hot, &latched, follow)
    }

    /// Read metadata while returning all acquired requirement observations to
    /// the caller's operation latch, including observations during recovery.
    pub(crate) fn read_for_operation(
        dir: &Path,
        required: &std::cell::Cell<bool>,
    ) -> Result<Option<Self>> {
        required.set(required.get() || !crate::write_overlay::overlay_markers(dir)?.is_empty());
        Self::read_latched(dir, true, required, false)
    }

    fn read_latched(
        dir: &Path,
        recover_hot: bool,
        latched: &std::cell::Cell<bool>,
        follow: bool,
    ) -> Result<Option<Self>> {
        let db = dir.join(HIDDEN_DB);
        let entry = if follow {
            fs::metadata(&db)?
        } else {
            fs::symlink_metadata(&db)?
        };
        if !entry.is_file() {
            return Err(OverlayError::Msg(format!(
                "overlay database {} must be a regular file",
                db.display()
            )));
        }
        // The requirement is a latch across the hot-journal recovery and the
        // retry: a marker any open saw stays required (S3 skeptic #2).
        let read = || -> Result<Option<Self>> {
            let conn = crate::overlay_db::open_overlay_db_required(
                &db,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                crate::DbName::Path,
                latched.get(),
            )?;
            latched.set(latched.get() || conn.required_record());
            conn.busy_timeout(std::time::Duration::ZERO)?;
            // One read transaction: the `files` check and the `meta` rows
            // describe the same database state.
            let tx = conn.unchecked_transaction()?;
            Self::from_connection_required(&tx, latched.get())
        };
        let result = match read() {
            Err(OverlayError::Sqlite(error)) if recover_hot && is_hot_journal(&error) => {
                recover_hot_journal(dir, &db, latched.get()).and_then(|required| {
                    latched.set(required);
                    read()
                })
            }
            other => other,
        };
        result.map_err(|error| match error {
            OverlayError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                OverlayError::Sqlite(rusqlite::Error::SqliteFailure(
                    code,
                    Some(format!("overlay {} is in use", dir.display())),
                ))
            }
            error => error,
        })
    }

    /// [`Self::from_connection`] of a record that must exist when `required`:
    /// a used (marked) overlay, or a mount's own database, without a `files`
    /// table has lost its record, which must refuse rather than read as an
    /// unrecorded overlay (R10-B). The `files` check and the `meta` read are
    /// one snapshot: outside a transaction this opens a read transaction of
    /// its own (R10-FIX6: a `DROP TABLE files; DROP TABLE meta` committed
    /// between two autocommit reads read as "unrecorded"); inside the
    /// caller's transaction, that one covers both reads.
    pub fn from_connection_required(conn: &Connection, required: bool) -> Result<Option<Self>> {
        if !conn.is_autocommit() {
            return Self::from_transaction_required(conn, required);
        }
        // Read-only: dropping the transaction rolls it back.
        let tx = conn.unchecked_transaction()?;
        Self::from_transaction_required(&tx, required)
    }

    /// [`Self::from_connection_required`] of a validated open, with the
    /// requirement it latched ([`crate::OverlayDb::required_record`]).
    pub fn from_opened(db: &crate::OverlayDb) -> Result<Option<Self>> {
        Self::from_connection_required(db, db.required_record())
    }

    /// [`Self::from_connection_required`] inside a transaction the caller
    /// holds (both reads see its snapshot).
    fn from_transaction_required(conn: &Connection, required: bool) -> Result<Option<Self>> {
        debug_assert!(!conn.is_autocommit(), "a transaction covers both reads");
        if required && !has_files_table(conn)? {
            return Err(OverlayError::Msg(NO_FILES_TABLE.to_owned()));
        }
        #[cfg(test)]
        if let Some(hook) = BETWEEN_REQUIRED_READS.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
        Self::from_connection(conn)
    }

    pub fn from_connection(conn: &Connection) -> Result<Option<Self>> {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
            [],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
        let mut statement = conn.prepare("SELECT key, value FROM meta ORDER BY key")?;
        let values = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let meta = Self { values };
        let version = meta.format_version()?;
        if let Some(version) = version.filter(|v| *v > MAX_FORMAT_VERSION) {
            return Err(OverlayError::Msg(format!(
                "overlay format_version {version} is newer than this ratarmount supports \
                 ({MAX_FORMAT_VERSION}); upgrade ratarmount"
            )));
        }
        Ok(Some(meta))
    }

    pub fn values(&self) -> &BTreeMap<String, String> {
        &self.values
    }
    /// `values()` with every URL-bearing key passed through the redactor, for
    /// overlays written by a build that stored credentials.
    pub fn redacted_values(&self) -> BTreeMap<String, String> {
        redact_meta_values(&self.values)
    }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    pub fn format_version(&self) -> Result<Option<u32>> {
        self.get("format_version")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| OverlayError::Msg("invalid overlay format_version".into()))
            })
            .transpose()
    }
    pub fn legacy(&self) -> bool {
        self.get("format_version").is_none_or(|v| v == "1")
    }
    pub fn base_url(&self) -> Option<&str> {
        self.get("base_url")
    }
    pub fn base_digest(&self) -> Option<&str> {
        self.get("base_digest")
    }
    /// The base digest when one is actually known: not `pending` (recorded as
    /// the empty string until resolved) and not empty.
    pub fn known_base_digest(&self) -> Option<&str> {
        self.base_digest()
            .filter(|d| !d.is_empty() && self.base_digest_kind() != Some("pending"))
    }
    pub fn base_digest_kind(&self) -> Option<&str> {
        self.get("base_digest_kind")
    }
    /// The stable `base_digest_state` contract (docs/sandbox.md, "Digest
    /// states"): `pending`, `none` or `present`.
    pub fn base_digest_state(&self) -> &'static str {
        base_digest_state(self.base_digest_kind(), self.base_digest().unwrap_or(""))
    }
    pub fn stack_digest(&self) -> Option<&str> {
        self.get("stack_digest")
    }
    pub fn layer_sealed(&self) -> bool {
        self.get("sealed_at").is_some()
    }
    pub fn lower_layers(&self) -> Result<Vec<LowerLayerRecord>> {
        self.get("lower_layers").map_or(Ok(Vec::new()), |value| {
            serde_json::from_str(value)
                .map_err(|e| OverlayError::Msg(format!("invalid lower_layers: {e}")))
        })
    }

    /// Write through the caller's connection (and transaction, if any).
    pub fn set(conn: &Connection, key: &str, value: &str) -> Result<()> {
        Self::set_many(conn, &[(key, value)])
    }

    /// Delete one key through the caller's connection.
    pub fn remove(conn: &Connection, key: &str) -> Result<()> {
        conn.execute("DELETE FROM meta WHERE key=?1", params![key])?;
        Ok(())
    }

    /// An atomic batch, also safe within a caller-owned transaction.
    pub fn set_many(conn: &Connection, values: &[(&str, &str)]) -> Result<()> {
        conn.execute_batch("SAVEPOINT overlay_meta_write")?;
        let result = (|| -> rusqlite::Result<()> {
            for (key, value) in values {
                conn.execute("INSERT INTO meta (key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, value])?;
            }
            conn.execute_batch("RELEASE overlay_meta_write")
        })();
        if result.is_err() {
            let _ =
                conn.execute_batch("ROLLBACK TO overlay_meta_write; RELEASE overlay_meta_write");
        }
        result.map_err(Into::into)
    }
}

/// Digest of the base and ordered lower-layer digests, including the final LF.
pub fn stack_digest(base: &str, layers: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for digest in std::iter::once(base).chain(layers.iter().copied()) {
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

thread_local! {
    static DIRECTORY_DIGEST_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static WEAK_WALKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Strong directory digests started on this thread (test instrumentation).
pub fn directory_digest_calls_this_thread() -> u64 {
    DIRECTORY_DIGEST_CALLS.with(std::cell::Cell::get)
}

/// Weak directory walks started on this thread (test instrumentation).
pub fn directory_weak_walks_this_thread() -> u64 {
    WEAK_WALKS.with(std::cell::Cell::get)
}

/// Base-relative paths a directory digest leaves out (the overlay directory,
/// the journal, `--lower` layers living inside the base). Sorted, duplicate
/// free and never containing the base root itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BaseExcludes(Vec<PathBuf>);

impl BaseExcludes {
    pub fn new(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut paths: Vec<PathBuf> = paths.into_iter().collect();
        paths.sort_by(|a, b| {
            a.as_os_str()
                .as_encoded_bytes()
                .cmp(b.as_os_str().as_encoded_bytes())
        });
        paths.dedup();
        Self(paths)
    }
    pub fn paths(&self) -> &[PathBuf] {
        &self.0
    }
    /// True when `rel` equals an entry or lies below one.
    pub fn covers(&self, rel: &Path) -> bool {
        self.0.iter().any(|entry| rel.starts_with(entry))
    }
    /// JSON array of `/`-separated paths, as stored in `base_weak_excludes`.
    pub fn to_json(&self) -> Result<String> {
        let names = self
            .0
            .iter()
            .map(|p| {
                p.to_str()
                    .map(|s| s.replace(std::path::MAIN_SEPARATOR, "/"))
                    .ok_or_else(|| {
                        OverlayError::Msg(format!(
                            "cannot exclude non-UTF-8 path {} from the base digest",
                            p.display()
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        serde_json::to_string(&names).map_err(|e| OverlayError::Msg(e.to_string()))
    }
    pub fn from_json(text: &str) -> Result<Self> {
        let names: Vec<String> = serde_json::from_str(text)
            .map_err(|e| OverlayError::Msg(format!("invalid base_weak_excludes: {e}")))?;
        Ok(Self::new(names.into_iter().map(PathBuf::from)))
    }
}

/// Resolve paths that may not exist yet to canonical base-relative excludes.
///
/// The longest existing ancestor is canonicalized and the rest appended
/// lexically. Topmost-new rule: when part of the path does not exist, only the
/// first missing component is recorded (the directory creation that follows
/// will add it to the base). Paths outside the base are dropped.
pub fn resolve_base_excludes(base: &Path, paths: &[PathBuf]) -> Result<(PathBuf, BaseExcludes)> {
    let base = base.canonicalize()?;
    let mut out = Vec::new();
    for path in paths {
        let mut existing = std::path::absolute(path)?;
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        while fs::symlink_metadata(&existing).is_err() {
            let Some(name) = existing.file_name().map(|n| n.to_owned()) else {
                return Err(OverlayError::Msg(format!(
                    "exclude path {}: cannot normalise a non-existent '..'",
                    path.display()
                )));
            };
            tail.push(name);
            existing.pop();
        }
        let canonical = existing.canonicalize()?;
        let Ok(rel) = canonical.strip_prefix(&base) else {
            continue;
        };
        let mut entry = rel.to_path_buf();
        if let Some(first) = tail.last() {
            entry.push(first);
        }
        if entry.as_os_str().is_empty() {
            return Err(OverlayError::Msg(
                "cannot use the base directory itself as the overlay".into(),
            ));
        }
        out.push(entry);
    }
    Ok((base, BaseExcludes::new(out)))
}

/// Union `new` into the stored `base_weak_excludes`. Append-only: no entry is
/// ever removed or rewritten.
pub fn append_base_excludes(conn: &Connection, new: &[PathBuf]) -> Result<()> {
    let meta = OverlayMeta::from_connection(conn)?.unwrap_or_default();
    let mut all: Vec<PathBuf> = match meta.get("base_weak_excludes") {
        Some(text) => BaseExcludes::from_json(text)?.0,
        None => Vec::new(),
    };
    all.extend(new.iter().cloned());
    OverlayMeta::set(
        conn,
        "base_weak_excludes",
        &BaseExcludes::new(all).to_json()?,
    )
}

/// What a directory walk saw at one path.
struct WalkEntry {
    rel: PathBuf,
    kind: u8,
    size: u64,
    mtime_ns: i128,
    target: Vec<u8>,
}

#[cfg(unix)]
fn mtime_ns(meta: &fs::Metadata) -> i128 {
    use std::os::unix::fs::MetadataExt;
    i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec())
}

#[cfg(not(unix))]
fn mtime_ns(meta: &fs::Metadata) -> i128 {
    match meta.modified() {
        Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i128,
            Err(e) => -(e.duration().as_nanos() as i128),
        },
        Err(_) => 0,
    }
}

fn special_kind(file_type: &fs::FileType) -> u8 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_fifo() {
            return b'p';
        }
        if file_type.is_socket() {
            return b's';
        }
        if file_type.is_char_device() {
            return b'c';
        }
        if file_type.is_block_device() {
            return b'b';
        }
    }
    let _ = file_type;
    b'o'
}

/// Names in one directory listing, for the sibling test of the sidecar predicate.
fn read_names(rd: fs::ReadDir) -> Result<Vec<std::ffi::OsString>> {
    rd.map(|e| Ok(e?.file_name())).collect()
}

fn is_sidecar(name: &std::ffi::OsStr, names: &std::collections::HashSet<&str>) -> bool {
    name.to_str().is_some_and(|name| {
        crate::base_sidecars::is_ratarmount_sidecar_name(name, &|stem| names.contains(stem))
    })
}

fn weak_walk(
    root: &Path,
    rel: &Path,
    rd: fs::ReadDir,
    excludes: &BaseExcludes,
    out: &mut Vec<WalkEntry>,
) -> Result<()> {
    let names = read_names(rd)?;
    let utf8: std::collections::HashSet<&str> = names.iter().filter_map(|n| n.to_str()).collect();
    for name in &names {
        let child = rel.join(name);
        if excludes.covers(&child) {
            continue;
        }
        let path = root.join(&child);
        let meta = fs::symlink_metadata(&path)?;
        let file_type = meta.file_type();
        if file_type.is_dir() {
            match fs::read_dir(&path) {
                Ok(sub) => {
                    out.push(WalkEntry {
                        rel: child.clone(),
                        kind: b'd',
                        size: 0,
                        mtime_ns: 0,
                        target: Vec::new(),
                    });
                    weak_walk(root, &child, sub, excludes, out)?;
                }
                Err(_) => out.push(WalkEntry {
                    rel: child,
                    kind: b'u',
                    size: 0,
                    mtime_ns: 0,
                    target: Vec::new(),
                }),
            }
            continue;
        }
        if is_sidecar(name, &utf8) {
            continue;
        }
        let (kind, size, target) = if file_type.is_file() {
            (b'f', meta.len(), Vec::new())
        } else if file_type.is_symlink() {
            let target = fs::read_link(&path)?;
            (b'l', 0, target.as_os_str().as_encoded_bytes().to_vec())
        } else {
            (special_kind(&file_type), 0, Vec::new())
        };
        out.push(WalkEntry {
            rel: child,
            kind,
            size,
            mtime_ns: mtime_ns(&meta),
            target,
        });
    }
    Ok(())
}

/// Cheap identity of a directory base: a sorted manifest of path, type, size
/// and mtime (symlink targets included). Only `lstat`/`readlink`/`readdir`:
/// no file is opened, so FIFOs and unreadable files cannot block or fail it.
/// A content edit that keeps size and mtime is invisible to it.
pub fn directory_weak_digest(root: &Path, excludes: &BaseExcludes) -> Result<String> {
    WEAK_WALKS.with(|c| c.set(c.get() + 1));
    let mut entries = Vec::new();
    weak_walk(
        root,
        Path::new(""),
        fs::read_dir(root)?,
        excludes,
        &mut entries,
    )?;
    entries.sort_by(|a, b| {
        a.rel
            .as_os_str()
            .as_encoded_bytes()
            .cmp(b.rel.as_os_str().as_encoded_bytes())
    });
    let mut hasher = Sha256::new();
    hasher.update(b"ratarmount-weak-dir-v1\0");
    for e in entries {
        let name = e.rel.as_os_str().as_encoded_bytes();
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name);
        hasher.update([e.kind]);
        match e.kind {
            b'f' => {
                hasher.update(e.size.to_le_bytes());
                hasher.update(e.mtime_ns.to_le_bytes());
            }
            b'l' => {
                hasher.update((e.target.len() as u64).to_le_bytes());
                hasher.update(&e.target);
                hasher.update(e.mtime_ns.to_le_bytes());
            }
            b'd' | b'u' => {}
            _ => hasher.update(e.mtime_ns.to_le_bytes()),
        }
    }
    Ok(format!("weak:{:x}", hasher.finalize()))
}

/// Sorted, length-framed manifest of relative OS path bytes, mode, size and
/// content SHA-256. Symlinks hash their target bytes and are never followed.
/// Directories use size zero; special files are refused instead of opened.
pub fn directory_digest(root: &Path) -> Result<String> {
    directory_digest_excluding(root, &BaseExcludes::default())
}

/// [`directory_digest`] leaving out `excludes` and ratarmount's own sidecar
/// names. Refuses a directory that still holds an un-excluded write overlay.
pub fn directory_digest_excluding(root: &Path, excludes: &BaseExcludes) -> Result<String> {
    DIRECTORY_DIGEST_CALLS.with(|c| c.set(c.get() + 1));
    fn visit(
        root: &Path,
        rel: &Path,
        excludes: &BaseExcludes,
        paths: &mut Vec<PathBuf>,
    ) -> Result<()> {
        paths.push(rel.to_path_buf());
        let names = read_names(fs::read_dir(root.join(rel))?)?;
        let utf8: std::collections::HashSet<&str> =
            names.iter().filter_map(|n| n.to_str()).collect();
        for name in &names {
            let child = rel.join(name);
            if excludes.covers(&child) {
                continue;
            }
            if fs::symlink_metadata(root.join(&child))?
                .file_type()
                .is_dir()
            {
                visit(root, &child, excludes, paths)?;
            } else if name.to_str() == Some(HIDDEN_DB) {
                return Err(OverlayError::Msg(format!(
                    "directory {} contains a write overlay at {}; pass --exclude-overlay {} to leave it out of the digest (a mount with that overlay inside the base measures without it)",
                    root.display(),
                    root.join(rel).display(),
                    root.join(rel).display(),
                )));
            } else if !is_sidecar(name, &utf8) {
                paths.push(child);
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    visit(root, Path::new(""), excludes, &mut paths)?;
    paths.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    let mut hasher = Sha256::new();
    for rel in paths {
        let path = root.join(&rel);
        let meta = fs::symlink_metadata(&path)?;
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0153-M01","item":"ratarmount_compositing::overlay_meta::directory_digest_excluding","disposition":"managed-read","regression":"regression_directory_strong_digest_keeps_sqlar_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let (size, content) = if meta.is_dir() {
            (0, String::new())
        } else if meta.is_file() {
            // Managed (#151): a base file may be a database open here.
            (
                meta.len(),
                ratarmount_index::managed_read::sha256_hex(&path)?,
            )
        } else if meta.is_symlink() {
            let target = fs::read_link(&path)?;
            let bytes = target.as_os_str().as_encoded_bytes();
            (bytes.len() as u64, sha256_hex(bytes))
        } else {
            return Err(OverlayError::Msg(format!(
                "cannot digest special file {}",
                path.display()
            )));
        };
        let name = rel.as_os_str().as_encoded_bytes();
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name);
        hasher.update(ratarmount_core::metadata_mode(&meta).to_le_bytes());
        hasher.update(size.to_le_bytes());
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(content.as_bytes());
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Map a recorded `base_digest_kind` and `base_digest` to `base_digest_state`:
/// `pending` while an archive base is not hashed yet, `none` when no digest
/// was asked for (kind `none`, or nothing recorded), otherwise `present`
/// (strong, weak and git-tree digests are all `present`; the kind says which).
pub fn base_digest_state(kind: Option<&str>, digest: &str) -> &'static str {
    match kind {
        Some("pending") => "pending",
        Some("none") => "none",
        _ if digest.is_empty() || digest == "none" => "none",
        _ => "present",
    }
}

/// A `pending` archive base: what the background hasher or an offline verb
/// hashes, with the stamp recorded at creation.
#[derive(Clone, Debug)]
pub struct PendingBase {
    pub path: PathBuf,
    pub index: Option<PathBuf>,
    pub size: u64,
    pub mtime_ns: i128,
}

impl PendingBase {
    /// `Some` when the overlay's base digest is still `pending`.
    pub fn from_meta(meta: &OverlayMeta) -> Result<Option<Self>> {
        if meta.base_digest_kind() != Some("pending") {
            return Ok(None);
        }
        let field = |key: &str| {
            meta.get(key)
                .ok_or_else(|| OverlayError::Msg(format!("pending base digest: no {key} recorded")))
        };
        let parse = |key: &str| {
            field(key)?
                .parse::<i128>()
                .map_err(|e| OverlayError::Msg(format!("pending base digest: bad {key}: {e}")))
        };
        Ok(Some(Self {
            path: PathBuf::from(field("base_local_path")?),
            index: meta.get("base_index_path").map(PathBuf::from),
            size: u64::try_from(parse("base_size")?).map_err(|e| {
                OverlayError::Msg(format!("pending base digest: bad base_size: {e}"))
            })?,
            mtime_ns: parse("base_mtime_ns")?,
        }))
    }

    /// Whether a hash computed now would be cached in the base's index. The
    /// mount's background hasher leaves the digest pending when it would not:
    /// an archive digest is computed once and cached, never on every mount.
    pub fn cache_available(&self) -> bool {
        ratarmount_index::archive_digest_cache_available(self.index.as_deref())
    }

    fn stamp_matches(&self) -> Result<bool> {
        let now = ArchiveDigestStamp::read(&self.path)?;
        Ok(now.size == self.size && now.mtime_ns == self.mtime_ns)
    }

    /// SHA-256 of the archive (a cache hit is free). `check` is polled between
    /// chunks; an error from it abandons the hash and nothing is cached. The
    /// stamp must still equal the recorded one before and after.
    pub fn hash(&self, check: &dyn Fn() -> std::io::Result<()>) -> Result<String> {
        if !self.stamp_matches()? {
            return Err(OverlayError::Msg(format!(
                "base {} changed since the overlay was created; its digest cannot be resolved (use --force-base-mismatch when remounting)",
                self.path.display()
            )));
        }
        let digest =
            cached_archive_digest_cancellable(&self.path, self.index.as_deref(), check, |path| {
                struct Checked<'a, R>(R, &'a dyn Fn() -> std::io::Result<()>);
                impl<R: std::io::Read> std::io::Read for Checked<'_, R> {
                    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                        (self.1)()?;
                        self.0.read(buf)
                    }
                }
                test_hash_seam(path);
                // Managed (#151): the archive may be a database open here.
                #[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0154-M01","item":"<ratarmount_compositing::overlay_meta::PendingBase>::hash","disposition":"managed-read","regression":"regression_pending_base_hash_keeps_index_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###)]
let cursor = ratarmount_index::managed_read::ManagedReadCursor::open(path)?;
                sha256_hex_stream(&mut Checked(cursor, check))
            })
            .map_err(|e| {
                OverlayError::Msg(format!("cannot hash base {}: {e}", self.path.display()))
            })?;
        if !self.stamp_matches()? {
            return Err(OverlayError::Msg("base changed while hashing".into()));
        }
        Ok(digest)
    }

    /// Bind seal hashing (including cache hits) to its managed byte reader.
    pub(crate) fn hash_seal(&self, guard: &SealArchive) -> Result<String> {
        guard.check_path(&self.path)?;
        if !self.stamp_matches()? {
            return Err(OverlayError::Msg("base changed before sealing".into()));
        }
        let stamp = ArchiveDigestStamp::from_metadata(guard.metadata())?;
        let digest = ratarmount_index::cached_archive_digest_cancellable_for_snapshot(
            &self.path,
            self.index.as_deref(),
            &stamp,
            &|| Ok(()),
            |path| {
                test_hash_seam(path);
                guard.check_path(path)?;
                let digest = sha256_hex_stream(&mut guard.reader.independent_cursor())?;
                guard.check_path(path)?;
                Ok(digest)
            },
        )
        .map_err(|e| OverlayError::Msg(format!("cannot hash base {}: {e}", self.path.display())))?;
        guard.check_path(&self.path)?;
        Ok(digest)
    }
}

/// A seal's byte source, without an archive lock or a raw descriptor close.
/// The overlay lock excludes commit; the stamp and VFS moved-file check bind
/// hashing/cache lookup and publication to this one archive file.
pub(crate) struct SealArchive {
    reader: ratarmount_index::managed_read::ManagedReadCursor,
    metadata: fs::Metadata,
}

impl SealArchive {
    pub(crate) fn open(path: &Path, metadata: fs::Metadata) -> std::io::Result<Self> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-V4-SEAL-READER","item":"<ratarmount_compositing::overlay_meta::SealArchive>::open","disposition":"managed-read","category":"managed-read","regression":"regression_240_reader_transaction_survives_seal_and_commit","reason":"Bind seal digest reads to one SQLite-managed byte reader so disposal preserves in-process reader locks.","creation":{"policy":"none","basis":"Read an existing archive through SQLite VFS without creating it or taking its archive lock."}}"###
        )]
        let reader = ratarmount_index::managed_read::ManagedReadCursor::open(path)?;
        let archive = Self { reader, metadata };
        archive.check_path(path)?;
        Ok(archive)
    }

    pub(crate) fn metadata(&self) -> &fs::Metadata {
        &self.metadata
    }

    pub(crate) fn check_path(&self, path: &Path) -> std::io::Result<()> {
        if self.reader.has_moved()?
            || self.reader.len()? != self.metadata.len()
            || !ratarmount_compress::commit_journal::same_stamp(
                &self.metadata,
                &fs::metadata(path)?,
            )
        {
            return Err(std::io::Error::other(
                "archive changed while sealing; reopen it and retry sealing",
            ));
        }
        Ok(())
    }
}

/// Test seam, read only where a full archive hash really starts: append one
/// line to `RATARMOUNT_TEST_HASH_LOG` (so separate mount processes can be
/// counted), sleep `RATARMOUNT_TEST_HASH_DELAY_MS` (widens race windows) and
/// block until the path in `RATARMOUNT_TEST_HASH_HOLD` exists (an explicit
/// release instead of a timed delay; capped at 60 s so a lost test cannot hang).
#[cfg(any(test, feature = "test-hooks"))]
fn test_hash_seam(path: &Path) {
    #[cfg(test)]
    if let Some(hook) = DURING_PENDING_HASH.with(|s| s.borrow_mut().take()) {
        hook();
    }

    use std::io::Write;
    if let Some(log) = std::env::var_os("RATARMOUNT_TEST_HASH_LOG") {
        if let Ok(mut file) = {
            #[expect(
                clippy::disallowed_types,
                reason = r###"internal-read:v1 {"id":"IR-E0003-T01","item":"ratarmount_compositing::overlay_meta::test_hash_seam","disposition":"support","category":"builder-type-support","reason":"Builder type support: Append archive hash-start events to the explicit RATARMOUNT_TEST_HASH_LOG instrumentation path when test-hooks is enabled.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
            )]
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0003-M01","item":"ratarmount_compositing::overlay_meta::test_hash_seam","disposition":"out-of-family","category":"feature-test-hook","reason":"Append archive hash-start events to the explicit RATARMOUNT_TEST_HASH_LOG instrumentation path when test-hooks is enabled.","creation":{"policy":"append-or-create","basis":"The hook opens append/create, never truncates an existing log, and uses platform-default file permissions."}}"###
            )]
            let mut __inventory_value_0 = fs::OpenOptions::new();
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0003-M02","item":"ratarmount_compositing::overlay_meta::test_hash_seam","disposition":"out-of-family","category":"feature-test-hook","reason":"Append archive hash-start events to the explicit RATARMOUNT_TEST_HASH_LOG instrumentation path when test-hooks is enabled.","creation":{"policy":"append-or-create","basis":"The hook opens append/create, never truncates an existing log, and uses platform-default file permissions."}}"###
            )]
            let __inventory_value_1 = __inventory_value_0.create(true);
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0003-M03","item":"ratarmount_compositing::overlay_meta::test_hash_seam","disposition":"out-of-family","category":"feature-test-hook","reason":"Append archive hash-start events to the explicit RATARMOUNT_TEST_HASH_LOG instrumentation path when test-hooks is enabled.","creation":{"policy":"append-or-create","basis":"The hook opens append/create, never truncates an existing log, and uses platform-default file permissions."}}"###
            )]
            let __inventory_value_2 = __inventory_value_1.append(true).open(log);
            __inventory_value_2
        } {
            let _ = file.write_all(format!("{}\n", path.display()).as_bytes());
        }
    }
    if let Some(ms) = std::env::var("RATARMOUNT_TEST_HASH_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    if let Some(hold) = std::env::var_os("RATARMOUNT_TEST_HASH_HOLD").map(PathBuf::from) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !hold.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// Release builds read none of the `RATARMOUNT_TEST_*` variables.
#[cfg(not(any(test, feature = "test-hooks")))]
fn test_hash_seam(_path: &Path) {}

/// Test seam (`test-hooks` feature or unit tests): the path in
/// `RATARMOUNT_TEST_HASH_GATE`; the background base hash waits until it
/// exists. Always `None` in release builds.
pub fn test_hash_gate() -> Option<PathBuf> {
    #[cfg(any(test, feature = "test-hooks"))]
    {
        std::env::var_os("RATARMOUNT_TEST_HASH_GATE").map(PathBuf::from)
    }
    #[cfg(not(any(test, feature = "test-hooks")))]
    {
        None
    }
}

/// Test seam (`test-hooks` feature or unit tests): when
/// `RATARMOUNT_TEST_PACK_HOLD` names a file, `overlay pack` creates it as the
/// ready signal once its output temp file exists and then blocks (60 s cap)
/// so a test can SIGKILL it mid-write. A no-op in release builds.
pub fn test_pack_hold() {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(ready) = std::env::var_os("RATARMOUNT_TEST_PACK_HOLD") {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0004-M01","item":"ratarmount_compositing::overlay_meta::test_pack_hold","disposition":"out-of-family","category":"feature-test-hook","reason":"Write the RATARMOUNT_TEST_PACK_HOLD readiness marker before the bounded pack hold.","creation":{"policy":"create-or-truncate","basis":"The test-hooks readiness marker is explicit instrumentation output, written through fs::write with ordinary umask permissions."}}"###
        )]
        let _ = fs::write(ready, b"ready");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static DURING_PENDING_HASH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Compare-and-set a pending digest to `strong`. A no-op (`false`) unless the
/// kind is still `pending` and the recorded stamp still equals `pending`'s, so
/// a supplied digest, a forced reopen or a commit that moved the stamp wins.
pub fn record_base_digest(conn: &Connection, pending: &PendingBase, digest: &str) -> Result<bool> {
    record_base_digest_required(conn, pending, digest, false)
}

pub(crate) fn record_base_digest_required(
    conn: &Connection,
    pending: &PendingBase,
    digest: &str,
    required: bool,
) -> Result<bool> {
    conn.execute_batch("SAVEPOINT overlay_record_base_digest")?;
    let result = (|| -> Result<bool> {
        let meta = OverlayMeta::from_connection_required(conn, required)?;
        let Some(meta) = meta.filter(|m| m.base_digest_kind() == Some("pending")) else {
            return Ok(false);
        };
        if meta.get("base_size") != Some(pending.size.to_string().as_str())
            || meta.get("base_mtime_ns") != Some(pending.mtime_ns.to_string().as_str())
        {
            return Ok(false);
        }
        let layers = meta.lower_layers()?;
        let stack = stack_digest(
            digest,
            &layers
                .iter()
                .map(|l| l.layer_digest.as_str())
                .collect::<Vec<_>>(),
        );
        OverlayMeta::set_many(
            conn,
            &[
                ("base_digest", digest),
                ("base_digest_kind", "strong"),
                ("stack_digest", &stack),
            ],
        )?;
        Ok(true)
    })();
    match result {
        Ok(done) => {
            conn.execute_batch("RELEASE overlay_record_base_digest")?;
            Ok(done)
        }
        Err(e) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO overlay_record_base_digest; RELEASE overlay_record_base_digest",
            );
            Err(e)
        }
    }
}

/// Hash and record a `pending` base digest through `conn`. `false` when the
/// digest was not pending. Offline verbs that need the digest call this.
pub fn resolve_pending_base_digest(conn: &Connection) -> Result<bool> {
    resolve_pending_base_digest_for(conn, None)
}

/// [`resolve_pending_base_digest`] for a caller whose gate already accepted a
/// classified base: the digest is of THAT archive, not of the place the
/// overlay recorded (an accepted move leaves the recorded place stale, and the
/// old place may be gone or hold other bytes with the recorded stamp).
pub(crate) fn resolve_pending_base_digest_for(
    conn: &Connection,
    base: Option<&crate::ClassifiedBase>,
) -> Result<bool> {
    resolve_pending_base_digest_required(conn, base, false, None)
}

pub(crate) fn resolve_pending_base_digest_required(
    conn: &Connection,
    base: Option<&crate::ClassifiedBase>,
    required: bool,
    archive_guard: Option<&SealArchive>,
) -> Result<bool> {
    let Some(meta) = OverlayMeta::from_connection_required(conn, required)? else {
        return Ok(false);
    };
    let Some(mut pending) = PendingBase::from_meta(&meta)? else {
        return Ok(false);
    };
    if let Some(actual) = base.map(crate::ClassifiedBase::actual) {
        if let (
            crate::overlay_identity::BaseKind::Archive,
            Some(crate::BaseLocation::Local(path)),
        ) = (actual.kind(), actual.location())
        {
            if *path != pending.path {
                pending.path = path.clone();
                // The recorded index belongs to the old place.
                pending.index = None;
            }
        }
    }
    let digest = match archive_guard {
        Some(guard) => pending.hash_seal(guard)?,
        None => pending.hash(&|| Ok(()))?,
    };
    record_base_digest_required(conn, &pending, &digest, required)
}

pub(crate) fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl OverlayCreateInfo {
    fn path(&self) -> Option<&Path> {
        self.local_path.as_deref().or_else(|| {
            (!self.classified
                && !self.base_url.is_empty()
                && !self.base_url.contains("://")
                && self.git_tree.is_none()
                && self.remote_token.is_none())
            .then(|| Path::new(&self.base_url))
        })
    }

    fn stamp(&self) -> Result<Option<ArchiveDigestStamp>> {
        self.path()
            .filter(|p| p.is_file())
            .map(ArchiveDigestStamp::read)
            .transpose()
            .map_err(Into::into)
    }

    /// `dir_weak` is the weak manifest of a directory base, measured by the caller.
    fn digest(&self, dir_weak: Option<&str>) -> Result<(String, &'static str)> {
        match &self.base_digest {
            BaseDigestRequest::Supplied(digest) => {
                let validated: BaseDigestRequest = digest.parse().map_err(OverlayError::Msg)?;
                let BaseDigestRequest::Supplied(digest) = validated else {
                    return Err(OverlayError::Msg(
                        "supplied digest must be sha256:<hex>".into(),
                    ));
                };
                return Ok((digest, "strong"));
            }
            BaseDigestRequest::None => return Ok(("none".into(), "none")),
            BaseDigestRequest::Compute => {}
        }
        if let Some(tree) = &self.git_tree {
            return Ok((format!("git-tree:{tree}"), "git-tree"));
        }
        if let Some(path) = self.path() {
            if path.is_dir() {
                let weak = match dir_weak {
                    Some(weak) => weak.to_owned(),
                    None => directory_weak_digest(path, &BaseExcludes::default())?,
                };
                return Ok((weak, "weak"));
            }
            // Hashing happens after the mount is serving (spec 1.2): a miss is
            // recorded as `pending` and resolved by the mount's background
            // hasher or by the first verb that needs the digest.
            let index = if self.read_only_index {
                self.prepared_index_for_peek.as_deref()
            } else {
                self.index_path.as_deref()
            };
            let cached = peek_archive_digest_for_open(path, index, self.read_only_index)
                .map_err(|e| OverlayError::Msg(format!("cannot read base digest cache: {e}")))?;
            return Ok(match cached {
                Some(digest) => (digest, "strong"),
                None => (String::new(), "pending"),
            });
        }
        let token = serde_json::to_vec(&(
            ratarmount_core::redact_base_url(&self.base_url),
            &self.remote_token,
        ))
        .expect("strings serialize");
        Ok((format!("weak:{}", sha256_hex(&token)), "weak"))
    }
}

/// Redact credentials in `base_url` and `base_remote_token` (a JSON array of
/// inputs, or `url:<URL>`; an etag object has no URL and is left alone).
pub fn redact_meta_values(values: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = values.clone();
    if let Some(url) = out.get_mut("base_url") {
        let clean = ratarmount_core::redact_base_url(url);
        if clean != *url {
            // The default index path embeds the credentialed URL.
            out.remove("base_index_path");
        }
        out.insert("base_url".into(), clean);
    }
    if let Some(token) = out.get_mut("base_remote_token") {
        if token.starts_with('[') {
            *token = match serde_json::from_str::<Vec<String>>(token) {
                Ok(items) => serde_json::to_string(
                    &items
                        .iter()
                        .map(|i| ratarmount_core::redact_base_url(i))
                        .collect::<Vec<_>>(),
                )
                .expect("strings serialize"),
                Err(_) => ratarmount_core::redact_base_url(token),
            };
        } else if let Some(url) = token.strip_prefix("url:") {
            *token = format!("url:{}", ratarmount_core::redact_base_url(url));
        }
    }
    out
}

/// Called only during WriteOverlay open, before tombstone repair or COW sweep.
pub(crate) fn initialize(
    conn: &Connection,
    had_files: bool,
    info: Option<&OverlayCreateInfo>,
    plan: Option<&ExcludePlan>,
    identity: Option<&crate::ClassifiedBase>,
) -> Result<()> {
    let previous = OverlayMeta::from_connection(conn)?;
    if had_files {
        if let Some(meta) = previous.filter(|m| !m.values.is_empty()) {
            if let (Some(base), Some(info)) = (identity, info) {
                return reopen_classified(conn, &meta, info, plan, base);
            }
            if !meta.legacy() {
                if let Some(info) = info {
                    let _ = verify(conn, &meta, info, plan)?;
                }
            }
            return Ok(());
        }
        // A schema-only migration must never claim to know a legacy base.
        OverlayMeta::set(conn, "format_version", "1")?;
        // The first `-w` open of an overlay made by a released build records
        // what the opener served (kind, place), and no digest.
        if let Some(base) = identity {
            crate::overlay_gate::write_accepted_identity(conn, None, base)?;
        }
        return Ok(());
    }
    let default = OverlayCreateInfo {
        base_digest: BaseDigestRequest::None,
        ..Default::default()
    };
    let info = info.unwrap_or(&default);
    let dir_weak = plan
        .filter(|_| info.base_digest != BaseDigestRequest::None)
        .map(|plan| directory_weak_digest(&plan.base, &plan.excludes))
        .transpose()?;
    let before = info.stamp()?;
    let (digest, kind) = info.digest(dir_weak.as_deref())?;
    if info.stamp()? != before {
        return Err(OverlayError::Msg("base changed while hashing".into()));
    }
    let mut values = BTreeMap::from([
        ("format_version", "2".to_owned()),
        ("ratarmount_version", env!("CARGO_PKG_VERSION").to_owned()),
        ("created_at", timestamp()),
        ("base_url", ratarmount_core::redact_base_url(&info.base_url)),
        ("base_digest", digest.clone()),
        ("base_digest_kind", kind.to_owned()),
        (
            "lower_layers",
            serde_json::to_string(&info.lower_layers)
                .map_err(|e| OverlayError::Msg(e.to_string()))?,
        ),
    ]);
    // A pending base has no stack digest until its digest is known.
    if kind != "pending" {
        values.insert(
            "stack_digest",
            stack_digest(
                &digest,
                &info
                    .lower_layers
                    .iter()
                    .map(|l| l.layer_digest.as_str())
                    .collect::<Vec<_>>(),
            ),
        );
    }
    if kind != "none" {
        let supplied = matches!(info.base_digest, BaseDigestRequest::Supplied(_));
        values.insert(
            "base_digest_source",
            if supplied { "supplied" } else { "computed" }.to_owned(),
        );
    }
    if let (Some(plan), Some(weak)) = (plan, &dir_weak) {
        values.insert("base_weak_digest", weak.clone());
        values.insert("base_weak_excludes", plan.excludes.to_json()?);
    }
    if let Some(stamp) = before {
        values.insert("base_size", stamp.size.to_string());
        values.insert("base_mtime_ns", stamp.mtime_ns.to_string());
    }
    if let Some(path) = info.path().filter(|p| p.is_file()) {
        values.insert(
            "base_local_path",
            path.canonicalize()?.to_string_lossy().into_owned(),
        );
    }
    // The default index name embeds the whole URL, credentials included.
    let credentialed = ratarmount_core::redact_base_url(&info.base_url) != info.base_url;
    if let Some(index) = info.index_path.as_ref().filter(|_| !credentialed) {
        values.insert(
            "base_index_path",
            std::path::absolute(index)?.to_string_lossy().into_owned(),
        );
    }
    if let Some(tree) = &info.git_tree {
        values.insert("base_git_tree", tree.clone());
    }
    // An overlay created without naming its base records no kind; the
    // comparison rows then identify it.
    if let Some(base) = identity {
        values.insert("base_kind", base.actual().kind().as_str().to_owned());
        if let Some(location) = base.actual().location() {
            values.insert("base_location", location.row());
        }
    } else if info.git_tree.is_some() || info.path().is_some() || !info.base_url.is_empty() {
        // Only the in-crate test constructors reach this: a real base is
        // always classified by its opener.
        let kind = if info.git_tree.is_some() {
            "git"
        } else if info.path().is_some_and(Path::is_dir) {
            "directory"
        } else if info.path().is_some_and(Path::is_file) {
            "archive"
        } else {
            "remote"
        };
        values.insert("base_kind", kind.to_owned());
    }
    if let Some(token) = &info.remote_token {
        values.insert("base_remote_token", token.clone());
    }
    OverlayMeta::set_many(
        conn,
        &values
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect::<Vec<_>>(),
    )
}

/// Advance the baseline only after archive persistence succeeds. Legacy overlays
/// retain their unknown identity. The caller holds the commit gate / DB lock.
///
/// With the mount's token, the token is re-pointed at the committed archive
/// (the caller stores it so the next commit starts from it); a token that is
/// not an archive writes no base rows at all (the commit target of a union
/// is not the overlay's base). Without a token (the legacy constructors) the
/// previous behaviour is kept.
pub(crate) fn refresh_committed_base(
    conn: &Connection,
    base: Option<&crate::ClassifiedBase>,
    archive: &Path,
) -> Result<Option<crate::ClassifiedBase>> {
    let Some(meta) = OverlayMeta::from_connection(conn)? else {
        return Ok(None);
    };
    // A released overlay is refreshed only once it has gained a kind row.
    if meta.legacy() && (base.is_none() || meta.get("base_kind").is_none()) {
        return Ok(None);
    }
    if base.is_some_and(|b| b.actual().kind() != crate::overlay_identity::BaseKind::Archive) {
        return Ok(None);
    }
    let archive = archive.canonicalize()?;
    let stamp = ArchiveDigestStamp::read(&archive)?;
    let sibling = PathBuf::from(format!("{}.index.sqlite", archive.display()));
    let index = if meta.get("base_local_path") == archive.to_str() {
        meta.get("base_index_path")
            .map(Path::new)
            .unwrap_or(&sibling)
    } else {
        &sibling
    };
    let digest = match meta.base_digest_kind() {
        // A commit rewrites the archive anyway; its new digest also resolves
        // a digest that was still pending.
        Some("strong" | "pending") => {
            ratarmount_index::refresh_archive_digest(&archive, Some(index)).map_err(|error| {
                OverlayError::Msg(format!("cannot hash committed base: {error}"))
            })?
        }
        Some("weak") => format!("weak:size={},mtime_ns={}", stamp.size, stamp.mtime_ns),
        _ => meta.base_digest().unwrap_or("none").to_owned(),
    };
    if ArchiveDigestStamp::read(&archive)? != stamp {
        return Err(OverlayError::Msg(
            "base changed while hashing committed archive".into(),
        ));
    }
    let layers = meta.lower_layers()?;
    let stack = stack_digest(
        &digest,
        &layers
            .iter()
            .map(|l| l.layer_digest.as_str())
            .collect::<Vec<_>>(),
    );
    let kind = if meta.base_digest_kind() == Some("pending") {
        "strong"
    } else {
        meta.base_digest_kind().unwrap_or("none")
    };
    let mut values = vec![
        ("base_size", stamp.size.to_string()),
        ("base_mtime_ns", stamp.mtime_ns.to_string()),
        ("base_digest", digest),
        ("base_digest_kind", kind.to_owned()),
        ("stack_digest", stack),
        ("base_committed_at", timestamp()),
        ("base_local_path", archive.to_string_lossy().into_owned()),
        ("base_index_path", index.to_string_lossy().into_owned()),
        (
            "base_kind",
            crate::overlay_identity::BaseKind::Archive
                .as_str()
                .to_owned(),
        ),
    ];
    let moved = base.map(|b| b.repointed(&archive));
    if let Some(moved) = &moved {
        let actual = moved.actual();
        if let Some(location) = actual.location() {
            values.push(("base_location", location.row()));
        }
        if !actual.base_url().is_empty() && meta.base_url() != Some(actual.base_url()) {
            values.push(("base_url", actual.base_url().to_owned()));
        }
    }
    OverlayMeta::set_many(
        conn,
        &values
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect::<Vec<_>>(),
    )?;
    Ok(moved)
}

pub(crate) fn refresh_committed_base_offline(
    overlay: &Path,
    base: Option<&crate::ClassifiedBase>,
    archive: &Path,
) -> Result<()> {
    let db = overlay.join(HIDDEN_DB);
    // Some offline callers commit a directory of files without an overlay DB.
    // Only a missing entry is "none" (R7-E2): anything else is opened (never
    // created) and fails if unreadable.
    if crate::overlay_db_absent(overlay) {
        return Ok(());
    }
    let conn = crate::open_overlay_db(&db, OpenFlags::SQLITE_OPEN_READ_WRITE, crate::DbName::Path)?;
    conn.busy_timeout(std::time::Duration::ZERO)?;
    refresh_committed_base(&conn, base, archive).map(|_| ())
}

/// How strong a [`BaseCheck`] comparison is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseStrength {
    /// A content digest (archive bytes, or file contents of a directory).
    Strong,
    /// The lstat manifest of a directory: blind to a same-size edit whose
    /// mtime was restored.
    Weak,
}

impl BaseStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strong => "strong",
            Self::Weak => "weak",
        }
    }
}

/// Result of [`verify_base`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseCheck {
    Matches {
        current: String,
        strength: BaseStrength,
    },
    Mismatch {
        recorded: String,
        current: String,
        strength: BaseStrength,
    },
    Skipped {
        reason: String,
    },
}

/// Compare `base` with the digest the overlay recorded at creation, without
/// resolving or writing anything and without the index digest cache (which can
/// reuse a stale hash after a size-and-mtime-preserving edit).
///
/// A strong digest (computed archive digest, or any supplied one) is
/// recomputed from the bytes; a weak directory digest is recomputed from the
/// lstat manifest with the *recorded* exclusions. Git trees, remote bases,
/// `none`, `pending` and unreadable bases are `Skipped`.
pub(crate) fn verify_base_path(dir: &Path, base: &Path) -> BaseCheck {
    let skipped = |reason: &str| BaseCheck::Skipped {
        reason: reason.to_owned(),
    };
    let meta = match OverlayMeta::read(dir) {
        Ok(Some(meta)) => meta,
        Ok(None) => return skipped("overlay has no metadata"),
        Err(error) => return skipped(&format!("cannot read overlay metadata: {error}")),
    };
    let kind = meta.base_digest_kind();
    if meta.get("base_git_tree").is_some() {
        return skipped("git-tree base");
    }
    let Some(recorded) = meta.base_digest().filter(|d| !d.is_empty()) else {
        return skipped("no base digest recorded");
    };
    // Follow a root symlink: the base is what it points at (as when mounting).
    let Ok(base_meta) = fs::metadata(base) else {
        return skipped("base is not a local path");
    };
    let excludes = || match meta.get("base_weak_excludes") {
        Some(text) => BaseExcludes::from_json(text),
        None => Ok(BaseExcludes::default()),
    };
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0155-M01","item":"ratarmount_compositing::overlay_meta::verify_base_path","disposition":"managed-read","regression":"regression_strong_base_verification_keeps_sqlar_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let result: Result<(String, String, BaseStrength)> = if base_meta.is_dir() {
        match kind {
            Some("strong") => excludes()
                .and_then(|e| directory_digest_excluding(base, &e))
                .map(|now| (recorded.to_owned(), now, BaseStrength::Strong)),
            Some("weak") => match meta.get("base_weak_digest") {
                Some(weak) => excludes()
                    .and_then(|e| directory_weak_digest(base, &e))
                    .map(|now| (weak.to_owned(), now, BaseStrength::Weak)),
                None => return skipped("no weak directory digest recorded"),
            },
            Some("pending") => return skipped("base digest is still pending"),
            _ => return skipped("no comparable base digest"),
        }
    } else if base_meta.is_file() {
        match kind {
            // Managed (#151): the base may be a database open here.
            Some("strong") => ratarmount_index::managed_read::ManagedReadCursor::open(base)
                .and_then(|mut f| {
                    test_hash_seam(base);
                    sha256_hex_stream(&mut f)
                })
                .map(|hex| {
                    (
                        recorded.to_owned(),
                        format!("sha256:{hex}"),
                        BaseStrength::Strong,
                    )
                })
                .map_err(Into::into),
            Some("pending") => return skipped("base digest is still pending"),
            _ => return skipped("no comparable base digest"),
        }
    } else {
        return skipped("base is not a file or directory");
    };
    match result {
        Ok((recorded, current, strength)) if recorded == current => {
            BaseCheck::Matches { current, strength }
        }
        Ok((recorded, current, strength)) => BaseCheck::Mismatch {
            recorded,
            current,
            strength,
        },
        Err(error) => {
            let reason = format!("cannot hash: {error}");
            // Not eprintln!: a closed stderr must not panic a read-only verb.
            let _ = std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!("warning: base check skipped: {reason}\n"),
            );
            BaseCheck::Skipped { reason }
        }
    }
}

/// What the content comparison measures: the local path of the base the
/// opener served (never guessed), its Git tree, and the caller's own paths.
pub(crate) struct ContentProbe<'a> {
    /// Local path of a directory or archive base; `None` for remote bases.
    pub path: Option<&'a Path>,
    /// Tree id of a pinned Git base.
    pub git_tree: Option<&'a str>,
    /// A supplied `--base-digest`.
    pub supplied: Option<&'a str>,
    /// Index sidecar whose digest cache may already hold the archive's digest.
    pub index: Option<&'a Path>,
    pub read_only_index: bool,
    /// Base-relative paths of the caller's own overlay, journal and mount
    /// point, left out of the walk in addition to the recorded set.
    pub extra_excludes: &'a [PathBuf],
}

/// Result of [`crate::overlay_gate::compare_base_identity`].
#[derive(Debug, Default)]
pub struct BaseComparison {
    /// The base's own identity: the supplied digest, the weak manifest, the
    /// tree id or an archive's cached digest; empty when it is not known
    /// without hashing.
    pub identity: String,
    /// `Some(current identity)` when the base differs from the recorded one
    /// and nothing cheap confirms it.
    pub mismatch: Option<String>,
    /// The directory walk, when one was made.
    pub weak: Option<String>,
    /// The archive's size/mtime stamp, when one was read.
    pub stamp: Option<ArchiveDigestStamp>,
    /// The archive digest the index cache already holds (never hashed here).
    pub cached_digest: Option<String>,
    /// A recorded row (tree id, manifest or stamp) was compared with the base.
    pub compared: bool,
}

/// The one cheap identity check: reopen, `overlay seal`/`pack`, `diff` and the
/// `--lower` mount all compare a base with what the overlay recorded through
/// this. Metadata only, never a content read:
///
/// * directories: the weak walk with the *recorded* exclusions (plus the
///   caller's own paths);
/// * archives: the size/mtime stamp;
/// * Git: the tree id;
/// * when the stamp or walk differs but the recorded kind is `strong`, the
///   base is still accepted if the supplied digest or the digest already cached
///   in the archive's index equals the recorded one. A supplied digest that
///   contradicts a strong record is a mismatch even if the walk agrees.
///
/// A recorded kind of `none` (or no metadata) recorded no identity to compare.
///
/// This is the content half: the kind and place the opener reported are
/// compared first by [`crate::overlay_gate::shape_verdict`].
pub(crate) fn compare_content(
    meta: Option<&OverlayMeta>,
    probe: &ContentProbe,
) -> std::result::Result<BaseComparison, String> {
    let get = |key: &str| meta.and_then(|m| m.get(key));
    let decidable = meta.is_some_and(|m| m.base_digest_kind().is_some_and(|k| k != "none"));
    let strong = meta.is_some_and(|m| m.base_digest_kind() == Some("strong"));
    let recorded_digest = meta.and_then(OverlayMeta::base_digest);
    let recorded_weak = get("base_weak_digest");
    let recorded_stamp = get("base_size").zip(get("base_mtime_ns"));
    let recorded_tree = get("base_git_tree");
    // A strong record is confirmed by the same digest from elsewhere.
    let confirms = |digest: Option<&str>| strong && digest.is_some() && digest == recorded_digest;
    let mut out = BaseComparison::default();
    let mut mismatch: Option<String> = None;
    if let Some(tree) = probe.git_tree {
        let current = format!("git-tree:{tree}");
        out.compared = recorded_tree.is_some();
        if decidable && recorded_tree.is_some_and(|r| r != tree) {
            mismatch = Some(current.clone());
        }
        out.identity = current;
    } else if let Some(dir) = probe.path.filter(|p| p.is_dir()) {
        let need_walk = probe.supplied.is_none() || (decidable && recorded_weak.is_some());
        if need_walk {
            // The recorded set measured the digest; the caller's own paths are
            // added so they cannot count as edits.
            let recorded = match get("base_weak_excludes") {
                Some(text) => BaseExcludes::from_json(text).map_err(|e| e.to_string())?,
                None => BaseExcludes::default(),
            };
            let excludes =
                BaseExcludes::new(recorded.paths().iter().chain(probe.extra_excludes).cloned());
            out.weak = Some(
                directory_weak_digest(dir, &excludes)
                    .map_err(|e| format!("cannot measure base {}: {e}", dir.display()))?,
            );
        }
        out.compared = recorded_weak.is_some();
        if decidable {
            let differs = match (recorded_weak, &out.weak) {
                (Some(recorded), Some(now)) => recorded != now,
                _ => false,
            };
            if differs && !confirms(probe.supplied) {
                mismatch = out.weak.clone().or_else(|| Some("a directory".into()));
            }
        }
        out.identity = probe
            .supplied
            .map(str::to_owned)
            .or_else(|| out.weak.clone())
            .unwrap_or_default();
    } else if let Some(file) = probe.path.filter(|p| p.is_file()) {
        if decidable {
            let stamp = ArchiveDigestStamp::read(file)
                .map_err(|e| format!("cannot stat base {}: {e}", file.display()))?;
            out.stamp = Some(stamp);
        }
        if probe.supplied.is_none() || (decidable && strong) {
            let cached = peek_archive_digest_for_open(file, probe.index, probe.read_only_index);
            out.cached_digest = if probe.read_only_index {
                cached.map_err(|e| format!("cannot read prepared base digest cache: {e}"))?
            } else {
                cached.ok().flatten()
            };
        }
        out.compared = recorded_stamp.is_some();
        if let Some(stamp) = &out.stamp {
            let differs = match recorded_stamp {
                Some((size, mtime)) => {
                    stamp.size.to_string() != size || stamp.mtime_ns.to_string() != mtime
                }
                None => false,
            };
            if differs && !confirms(probe.supplied) && !confirms(out.cached_digest.as_deref()) {
                mismatch = Some(format!("size={},mtime_ns={}", stamp.size, stamp.mtime_ns));
            }
        }
        out.identity = probe
            .supplied
            .map(str::to_owned)
            .or_else(|| out.cached_digest.clone())
            .unwrap_or_default();
    } else {
        out.identity = probe.supplied.unwrap_or_default().to_owned();
    }
    // A strong record with nothing local to compare (an overlay made over an
    // HTTP base has no stamp, manifest or tree) agrees with a local base only
    // if the same strong digest comes from elsewhere.
    if mismatch.is_none() && decidable && strong && !out.compared {
        let local =
            probe.git_tree.is_some() || probe.path.is_some_and(|p| p.is_dir() || p.is_file());
        if local && !confirms(probe.supplied) && !confirms(out.cached_digest.as_deref()) {
            mismatch = Some(if out.identity.is_empty() {
                "a base with no recorded comparison".to_owned()
            } else {
                out.identity.clone()
            });
        }
    }
    // A supplied digest that is not the strong one recorded is a different base.
    if mismatch.is_none() && decidable && strong {
        if let Some(supplied) = probe.supplied.filter(|s| Some(*s) != recorded_digest) {
            mismatch = Some(supplied.to_owned());
        }
    }
    out.mismatch = mismatch;
    Ok(out)
}

/// Every row that compares a base with the overlay's record (not
/// `base_weak_excludes`: the overlay's own exclusions are not identity, and the
/// seal's change set depends on them). A forced
/// seal or pack replaces the record wholesale: rows of the previous base kind
/// (an archive's stamp, a directory's walk, a Git tree, the old paths) must not
/// survive to match the old base later.
pub const BASE_COMPARISON_KEYS: [&str; 9] = [
    "base_kind",
    "base_location",
    "base_digest_source",
    "base_size",
    "base_mtime_ns",
    "base_local_path",
    "base_index_path",
    "base_weak_digest",
    "base_git_tree",
];

impl OverlayMeta {
    /// A copy with `rows` written over it (a forced pack's bundle metadata),
    /// after dropping every old comparison row.
    pub fn with_rows(&self, rows: &BTreeMap<String, String>) -> Self {
        let mut values = self.values.clone();
        for key in BASE_COMPARISON_KEYS {
            values.remove(key);
        }
        values.extend(rows.iter().map(|(k, v)| (k.clone(), v.clone())));
        Self { values }
    }
}

/// Write `rows` into an unsealed overlay's `meta` table (a forced seal). Not
/// public: [`crate::overlay_gate::record_forced_base_rows`] is the entry, and
/// it demands the classified base the rows describe.
pub(crate) fn record_base_rows_offline(
    overlay: &Path,
    rows: &BTreeMap<String, String>,
) -> Result<()> {
    // NOFOLLOW rejects a symlink in any component; the shared open resolves
    // the directory first (every macOS temp dir lives under /var -> /private/var).
    let conn = crate::open_overlay_db(
        &overlay.join(HIDDEN_DB),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        crate::DbName::Path,
    )?;
    conn.busy_timeout(std::time::Duration::ZERO)?;
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = apply_comparison_rows(&conn, rows);
    match result {
        Ok(()) => conn.execute_batch("COMMIT").map_err(Into::into),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Reopen over a classified base: the kind-and-place verdict first (for every
/// record that names a kind, legacy or not), then the digest check on the
/// records that have one, then the rows for an accepted change of place. A
/// forced override records the base now in use.
fn reopen_classified(
    conn: &Connection,
    meta: &OverlayMeta,
    info: &OverlayCreateInfo,
    plan: Option<&ExcludePlan>,
    base: &crate::ClassifiedBase,
) -> Result<()> {
    use crate::overlay_gate::{forced_base_record, shape_verdict, BaseProbe, Verdict};
    let probe = BaseProbe {
        supplied: match &info.base_digest {
            BaseDigestRequest::Supplied(digest) => Some(digest.as_str()),
            _ => None,
        },
        extra_excludes: &[],
    };
    let forced_rows = |conn: &Connection| -> Result<()> {
        let rows = forced_base_record(meta, base, &probe).map_err(OverlayError::Msg)?;
        apply_comparison_rows(conn, &rows)
    };
    match shape_verdict(Some(meta), base.actual(), &probe) {
        Verdict::Refuse(reason) => {
            if !info.force_base_mismatch {
                return Err(OverlayError::Msg(format!(
                    "base mismatch: {reason}; use --force-base-mismatch to override"
                )));
            }
            return forced_rows(conn);
        }
        Verdict::PreparationError(reason) => return Err(OverlayError::Msg(reason)),
        Verdict::Same | Verdict::Confirmed(_) => {}
        Verdict::Content => {
            let mut overridden = false;
            // Same kind at the same place with a changed content: a forced
            // run overrides this open only (`base_mismatch_forced_at`); the
            // recorded digest stays, so a later offline verb still refuses.
            if !meta.legacy() {
                // A strong archive record is confirmed by the same comparator
                // every other gate uses (supplied or cached SHA-256), so a
                // byte-identical copy with another mtime reopens. Anything the
                // comparator does not accept falls to the stamp/manifest/
                // exclusion checks of `verify`, which name the mismatch.
                let confirmed = if base.actual().kind() == crate::BaseKind::Archive
                    && meta.base_digest_kind() == Some("strong")
                {
                    let comparison =
                        crate::overlay_gate::compare_base_identity(Some(meta), base, &probe);
                    if base.actual().read_only_index() {
                        comparison.map_err(OverlayError::Msg)?.mismatch.is_none()
                    } else {
                        comparison.is_ok_and(|cmp| cmp.mismatch.is_none())
                    }
                } else {
                    false
                };
                if !confirmed {
                    overridden = verify(conn, meta, info, plan)?;
                }
            }
            if overridden {
                // A forced open over content that differs from the record
                // overrides this open only: the stamp / manifest stay, so the
                // next unforced open or gate still compares the recorded base.
                return Ok(());
            }
        }
    }
    if !matches!(
        crate::overlay_gate::Recorded::from_meta(Some(meta)),
        crate::overlay_gate::Recorded::Nothing
    ) {
        crate::overlay_gate::write_accepted_identity(conn, Some(meta), base)?;
    }
    Ok(())
}

/// Replace every comparison row with `rows` through the caller's connection.
pub(crate) fn apply_comparison_rows(
    conn: &Connection,
    rows: &BTreeMap<String, String>,
) -> Result<()> {
    for key in BASE_COMPARISON_KEYS {
        OverlayMeta::remove(conn, key)?;
    }
    OverlayMeta::set_many(
        conn,
        &rows
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
    )
}

/// Compare the base with the record by stamp, manifest, tree or digest.
/// `Ok(true)` when a mismatch was overridden by `--force-base-mismatch` (the
/// record is then left as it was: the open is forced, the baseline is not
/// moved to a base nothing confirmed).
fn verify(
    conn: &Connection,
    meta: &OverlayMeta,
    info: &OverlayCreateInfo,
    plan: Option<&ExcludePlan>,
) -> Result<bool> {
    if meta.base_digest_kind() == Some("none") {
        return Ok(false);
    }
    let old = match meta.base_digest_kind() {
        Some("pending") => "pending",
        _ => meta.base_digest().unwrap_or("none"),
    };
    let mut to_append: Vec<PathBuf> = Vec::new();
    let mut mismatch = if let Some(recorded) = meta.get("base_git_tree") {
        (info.git_tree.as_deref() != Some(recorded)).then(|| {
            format!(
                "git-tree:{}",
                info.git_tree.as_deref().unwrap_or("unavailable")
            )
        })
    } else if let (Some(size), Some(mtime)) = (meta.get("base_size"), meta.get("base_mtime_ns")) {
        match info.stamp()? {
            Some(now) if now.size.to_string() == size && now.mtime_ns.to_string() == mtime => None,
            // The archive carries its OWN pending commit journal that was
            // started for the recorded base (or the rows already describe the
            // committed bytes): recovery after the gates settles it, so the
            // stamp difference is not a foreign base.
            Some(now)
                if info.path().is_some_and(|p| {
                    crate::journal_recovery::own_pending_journal_agrees(
                        meta,
                        p,
                        (now.size, now.mtime_ns),
                    )
                }) =>
            {
                None
            }
            Some(now) => Some(format!(
                "weak:size={},mtime_ns={} (current SHA-256 not recomputed)",
                now.size, now.mtime_ns
            )),
            None => Some("unavailable (local archive missing)".into()),
        }
    } else if let (Some(recorded_weak), Some(plan)) = (meta.get("base_weak_digest"), plan) {
        // Always re-walk with the *recorded* exclusions; this invocation's
        // paths only matter for the append check below.
        let recorded = match meta.get("base_weak_excludes") {
            Some(text) => BaseExcludes::from_json(text)?,
            None => BaseExcludes::new(plan.overlay.iter().cloned()),
        };
        for entry in plan.excludes.paths() {
            if recorded.covers(entry) {
                continue;
            }
            if fs::symlink_metadata(plan.base.join(entry)).is_ok() {
                return Err(OverlayError::Msg(format!(
                    "{} is inside the base and already exists, so it is base content; it cannot be excluded after the overlay was created. Move the journal outside the base, or remove that file from the base",
                    plan.base.join(entry).display()
                )));
            }
            to_append.push(entry.clone());
        }
        let current = directory_weak_digest(&plan.base, &recorded)?;
        (current != recorded_weak).then_some(current)
    } else {
        None
    };
    mismatch = mismatch.or_else(|| match &info.base_digest {
        BaseDigestRequest::Supplied(digest) if digest != old => Some(digest.clone()),
        _ => None,
    });
    if let Some(current) = mismatch {
        if !info.force_base_mismatch {
            return Err(OverlayError::Msg(format!("base mismatch: recorded digest {old}; current digest {current}; use --force-base-mismatch to override")));
        }
        OverlayMeta::set(conn, "base_mismatch_forced_at", &timestamp())?;
        return Ok(true);
    } else if !to_append.is_empty() {
        append_base_excludes(conn, &to_append)?;
    }
    Ok(false)
}

#[cfg(test)]
mod tests;
