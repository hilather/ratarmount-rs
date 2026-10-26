//! Overlay identity, creation metadata, and cheap remount verification.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ratarmount_index::{
    cached_archive_digest_cancellable, peek_archive_digest, sha256_hex, sha256_hex_stream,
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
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(log) {
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
    resolve_pending_base_digest_required(conn, base, false)
}

pub(crate) fn resolve_pending_base_digest_required(
    conn: &Connection,
    base: Option<&crate::ClassifiedBase>,
    required: bool,
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
    let digest = pending.hash(&|| Ok(()))?;
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
            let cached = peek_archive_digest(path, self.index_path.as_deref())
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
            out.cached_digest = peek_archive_digest(file, probe.index).ok().flatten();
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
                let confirmed = base.actual().kind() == crate::BaseKind::Archive
                    && meta.base_digest_kind() == Some("strong")
                    && crate::overlay_gate::compare_base_identity(Some(meta), base, &probe)
                        .is_ok_and(|cmp| cmp.mismatch.is_none());
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
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::{FolderMountSource, WriteOverlay};
    use ratarmount_core::{ArchiveRead, FileInfo, ListResult, MountSource};
    use std::io;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn base(root: &Path) -> Arc<dyn MountSource> {
        Arc::new(FolderMountSource::new(root).unwrap())
    }

    fn info(path: &Path) -> OverlayCreateInfo {
        OverlayCreateInfo {
            base_url: path.to_str().unwrap().into(),
            ..Default::default()
        }
    }

    fn meta_with(rows: &[(&str, &str)]) -> OverlayMeta {
        OverlayMeta {
            values: rows
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn probe<'a>(
        path: Option<&'a Path>,
        git_tree: Option<&'a str>,
        supplied: Option<&'a str>,
        index: Option<&'a Path>,
    ) -> ContentProbe<'a> {
        ContentProbe {
            path,
            git_tree,
            supplied,
            index,
            extra_excludes: &[],
        }
    }

    /// Regression (Keystone mutant `recorded_tree != tree` -> `==`): the Git
    /// branch of the `--lower` / seal / pack / diff base check refuses another
    /// tree and accepts the recorded one.
    #[test]
    fn regression_compare_base_git_tree_mismatch_and_match() {
        let meta = meta_with(&[
            ("base_digest_kind", "git-tree"),
            ("base_digest", "git-tree:aaa"),
            ("base_git_tree", "aaa"),
        ]);
        let other = compare_content(Some(&meta), &probe(None, Some("bbb"), None, None)).unwrap();
        assert_eq!(other.mismatch.as_deref(), Some("git-tree:bbb"));
        assert_eq!(other.identity, "git-tree:bbb");
        let same = compare_content(Some(&meta), &probe(None, Some("aaa"), None, None)).unwrap();
        assert_eq!(same.mismatch, None);
        // Kind `none` recorded nothing to compare.
        let none = meta_with(&[("base_digest_kind", "none"), ("base_git_tree", "aaa")]);
        assert_eq!(
            compare_content(Some(&none), &probe(None, Some("bbb"), None, None))
                .unwrap()
                .mismatch,
            None
        );
    }

    /// Regression (R4-S3): a strong record with no stamp, manifest or tree (an
    /// overlay made over an HTTP base) was accepted over any unrelated local
    /// directory, archive or Git tree. Only the same strong digest, supplied or
    /// cached, confirms it; a remote probe (no local path) keeps its behaviour.
    #[test]
    fn regression_compare_base_strong_without_local_rows_needs_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("f"), b"unrelated").unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"not the base").unwrap();
        let strong = format!("sha256:{}", "a".repeat(64));
        let other = format!("sha256:{}", "b".repeat(64));
        let record = meta_with(&[
            ("base_digest_kind", "strong"),
            ("base_digest", strong.as_str()),
            ("base_kind", "remote"),
        ]);
        // The same record taken over a directory / archive (kind row, no
        // manifest or stamp) needs the digest to confirm.
        for (path, kind) in [(dir.path(), "directory"), (archive.as_path(), "archive")] {
            let record = meta_with(&[
                ("base_digest_kind", "strong"),
                ("base_digest", strong.as_str()),
                ("base_kind", kind),
            ]);
            let bad = compare_content(Some(&record), &probe(Some(path), None, None, None)).unwrap();
            assert!(bad.mismatch.is_some(), "{path:?} accepted unconfirmed");
            let wrong =
                compare_content(Some(&record), &probe(Some(path), None, Some(&other), None))
                    .unwrap();
            assert!(wrong.mismatch.is_some(), "{path:?} accepted a wrong digest");
            let ok = compare_content(Some(&record), &probe(Some(path), None, Some(&strong), None))
                .unwrap();
            assert_eq!(ok.mismatch, None, "{path:?}");
        }
        let git = compare_content(Some(&record), &probe(None, Some("abc"), None, None)).unwrap();
        assert!(git.mismatch.is_some(), "git tree accepted unconfirmed");
        let remote = compare_content(Some(&record), &probe(None, None, None, None)).unwrap();
        assert_eq!(remote.mismatch, None);
    }

    /// Regression (Keystone mutant on `need_walk`): a supplied digest skips the
    /// walk only when there is no recorded manifest to compare; with one, the
    /// walk runs and a strong record is confirmed by the supplied digest.
    #[test]
    fn regression_compare_base_need_walk_with_supplied_digest() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("f"), b"one").unwrap();
        let weak = directory_weak_digest(dir.path(), &BaseExcludes::default()).unwrap();
        let strong = format!("sha256:{}", "a".repeat(64));
        fs::write(dir.path().join("f"), b"edited").unwrap();
        let record = |extra: &[(&'static str, &str)]| {
            let mut rows = vec![
                ("base_digest_kind", "strong"),
                ("base_digest", strong.as_str()),
                ("base_kind", "directory"),
            ];
            rows.extend_from_slice(extra);
            meta_with(&rows)
        };
        // Recorded manifest + supplied digest: walked (the edit is seen), then
        // confirmed by the equal supplied digest.
        let with_weak = record(&[("base_weak_digest", weak.as_str())]);
        let walks = directory_weak_walks_this_thread();
        let ok = compare_content(
            Some(&with_weak),
            &probe(Some(dir.path()), None, Some(&strong), None),
        )
        .unwrap();
        assert_eq!(directory_weak_walks_this_thread() - walks, 1);
        assert!(ok.weak.as_ref().is_some_and(|w| *w != weak));
        assert_eq!(ok.mismatch, None);
        assert_eq!(ok.identity, strong);
        // A different supplied digest, or none, is a mismatch.
        let other = format!("sha256:{}", "b".repeat(64));
        for supplied in [Some(other.as_str()), None] {
            let bad = compare_content(
                Some(&with_weak),
                &probe(Some(dir.path()), None, supplied, None),
            )
            .unwrap();
            assert!(bad.mismatch.is_some(), "{supplied:?}");
        }
        // No recorded manifest and a supplied digest: nothing to walk.
        let without = record(&[]);
        let walks = directory_weak_walks_this_thread();
        let ok = compare_content(
            Some(&without),
            &probe(Some(dir.path()), None, Some(&strong), None),
        )
        .unwrap();
        assert_eq!(directory_weak_walks_this_thread(), walks);
        assert_eq!((ok.weak, ok.mismatch), (None, None));
        // Kind `none` with a recorded manifest: undecidable, so no walk either.
        let none = meta_with(&[
            ("base_digest_kind", "none"),
            ("base_weak_digest", weak.as_str()),
        ]);
        let walks = directory_weak_walks_this_thread();
        let ok = compare_content(
            Some(&none),
            &probe(Some(dir.path()), None, Some(&strong), None),
        )
        .unwrap();
        assert_eq!(directory_weak_walks_this_thread(), walks);
        assert_eq!(ok.mismatch, None);
    }

    /// An archive whose stamp differs is confirmed by the digest already
    /// cached in its index (never hashed here), or by a supplied one.
    #[test]
    fn regression_compare_base_archive_confirmed_by_cached_or_supplied_digest() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("copy.tar");
        fs::write(&archive, b"bytes").unwrap();
        let index = dir.path().join("copy.tar.index.sqlite");
        let digest = format!("sha256:{}", "c".repeat(64));
        let record = meta_with(&[
            ("base_digest_kind", "strong"),
            ("base_digest", digest.as_str()),
            ("base_size", "999"),
            ("base_mtime_ns", "1"),
        ]);
        // Nothing cached: not confirmed.
        let miss = compare_content(
            Some(&record),
            &probe(Some(&archive), None, None, Some(&index)),
        )
        .unwrap();
        assert!(miss.mismatch.is_some());
        // Cache the (recorded) digest without hashing anything here.
        Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        ratarmount_index::cached_archive_digest_with(
            &archive,
            Some(&index),
            |_| Ok("c".repeat(64)),
        )
        .unwrap();
        let hit = compare_content(
            Some(&record),
            &probe(Some(&archive), None, None, Some(&index)),
        )
        .unwrap();
        assert_eq!(
            (hit.mismatch, hit.identity.as_str()),
            (None, digest.as_str())
        );
        // A cached digest that is not the recorded one does not confirm.
        let other = meta_with(&[
            ("base_digest_kind", "strong"),
            ("base_digest", "sha256:dd"),
            ("base_size", "999"),
            ("base_mtime_ns", "1"),
        ]);
        assert!(compare_content(
            Some(&other),
            &probe(Some(&archive), None, None, Some(&index))
        )
        .unwrap()
        .mismatch
        .is_some());
        // Supplied equals recorded: confirmed even with no cache.
        let supplied = compare_content(
            Some(&record),
            &probe(Some(&archive), None, Some(&digest), None),
        )
        .unwrap();
        assert_eq!(supplied.mismatch, None);
        // A weak record is never rescued by a digest.
        let weak = meta_with(&[
            ("base_digest_kind", "weak"),
            ("base_digest", digest.as_str()),
            ("base_size", "999"),
            ("base_mtime_ns", "1"),
        ]);
        assert!(compare_content(
            Some(&weak),
            &probe(Some(&archive), None, Some(&digest), Some(&index))
        )
        .unwrap()
        .mismatch
        .is_some());
    }

    /// Regression: committing must preserve digest opt-out and legacy identities.
    #[test]
    fn regression_overlay_meta_commit_preserves_kind_and_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        fs::write(&archive, b"after commit").unwrap();
        for kind in ["none", "weak"] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(META_SCHEMA).unwrap();
            OverlayMeta::set_many(
                &conn,
                &[
                    ("format_version", "2"),
                    ("base_digest_kind", kind),
                    ("base_digest", kind),
                    ("lower_layers", "[]"),
                ],
            )
            .unwrap();
            refresh_committed_base(&conn, None, &archive).unwrap();
            let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
            assert_eq!(meta.base_digest_kind(), Some(kind));
            assert_eq!(meta.get("base_size"), Some("12"));
            assert!(meta.get("base_committed_at").is_some());
            if kind == "none" {
                assert_eq!(meta.base_digest(), Some("none"));
            } else {
                assert!(meta.base_digest().unwrap().starts_with("weak:size=12,"));
            }
        }
        let conn = Connection::open_in_memory().unwrap();
        refresh_committed_base(&conn, None, &archive).unwrap();
        assert!(OverlayMeta::from_connection(&conn).unwrap().is_none());
        conn.execute_batch(META_SCHEMA).unwrap();
        OverlayMeta::set(&conn, "format_version", "1").unwrap();
        refresh_committed_base(&conn, None, &archive).unwrap();
        let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
        assert_eq!(meta.values().len(), 1);
        assert!(meta.legacy());
    }

    /// Regression: new overlays lacked creation identity and stack ordering.
    #[test]
    fn regression_overlay_meta_creation_keys_and_stack_vector() {
        assert_eq!(
            stack_digest("sha256:base", &["sha256:first", "sha256:second"]),
            "sha256:4e3fef1cc62d99d7f6cb7fd49747c58d4f5f72e513cb7f3ed443c7fc44c31a6c"
        );
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("base.tar");
        fs::write(&archive, b"abc").unwrap();
        let overlay = root.path().join("overlay");
        let mut info = info(&archive);
        info.lower_layers.push(LowerLayerRecord {
            path: "prepared".into(),
            layer_digest: "sha256:first".into(),
            sealed_at: "2026-10-17T00:00:00Z".into(),
        });
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &info)
                .unwrap(),
        );
        // An uncached archive is `pending` until something resolves it.
        assert_eq!(meta_of(&overlay).base_digest_kind(), Some("pending"));
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        assert!(resolve_pending_base_digest(&conn).unwrap());
        drop(conn);
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        for key in [
            "format_version",
            "ratarmount_version",
            "created_at",
            "base_url",
            "base_digest",
            "base_digest_kind",
            "lower_layers",
            "stack_digest",
            "base_size",
            "base_mtime_ns",
        ] {
            assert!(meta.get(key).is_some(), "missing {key}");
        }
        chrono::DateTime::parse_from_rfc3339(meta.get("created_at").unwrap()).unwrap();
        assert_eq!(meta.format_version().unwrap(), Some(2));
        assert!(!meta.legacy());
        assert!(!meta.layer_sealed());
        assert_eq!(meta.base_digest_kind(), Some("strong"));
        assert_eq!(meta.base_url(), Some(info.base_url.as_str()));
        assert_eq!(
            meta.base_digest(),
            Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(meta.lower_layers().unwrap(), info.lower_layers);
        assert_eq!(
            meta.stack_digest(),
            Some(stack_digest(meta.base_digest().unwrap(), &["sha256:first"]).as_str())
        );
    }

    /// Regression: `--base-digest none` on REOPEN of a weak directory overlay
    /// suppressed the exclusion plan, skipped the recorded weak comparison and
    /// accepted a changed base without `--force-base-mismatch`. The flag only
    /// applies at creation; a reopen always compares the recorded identity.
    #[test]
    fn regression_reopen_with_base_digest_none_still_compares_recorded_weak() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("f"), b"abc").unwrap();
        let overlay = root.path().join("overlay");
        drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
        assert!(OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .get("base_weak_digest")
            .is_some());
        fs::write(basedir.join("f"), b"abcdef").unwrap();
        let mut request = info(&basedir);
        request.base_digest = BaseDigestRequest::None;
        request.force_base_mismatch = false;
        let err = open_dir_base(&basedir, &overlay, &request)
            .err()
            .expect("changed base must be refused")
            .to_string();
        assert!(err.contains("base mismatch"), "{err}");
        assert!(err.contains("--force-base-mismatch"), "{err}");
        // Forced: accepted, and the override is recorded.
        request.force_base_mismatch = true;
        drop(open_dir_base(&basedir, &overlay, &request).unwrap());
        assert!(OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .get("base_mismatch_forced_at")
            .is_some());
        // A new overlay created with `none` still records no walk.
        let fresh = root.path().join("fresh");
        drop(open_dir_base(&basedir, &fresh, &request).unwrap());
        let meta = OverlayMeta::read(&fresh).unwrap().unwrap();
        assert_eq!(meta.base_digest_kind(), Some("none"));
        assert!(meta.get("base_weak_digest").is_none());
    }

    /// Regression: legacy overlays must keep tombstones and remain digest-free after migration.
    #[test]
    fn regression_overlay_meta_legacy_migration_preserves_deletions() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("deleted"), b"base").unwrap();
        let overlay = root.path().join("overlay");
        fs::create_dir(&overlay).unwrap();
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        conn.execute_batch("CREATE TABLE files (path TEXT, name TEXT, mtime REAL, mode INTEGER, uid INTEGER, gid INTEGER, deleted BOOL, PRIMARY KEY(path,name)); INSERT INTO files VALUES ('','deleted',0,33188,0,0,1);").unwrap();
        drop(conn);
        assert!(OverlayMeta::read(&overlay).unwrap().is_none());
        let mut context = info(Path::new("missing base that must never be hashed"));
        context.force_base_mismatch = false;
        let ov =
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
                .unwrap();
        assert!(ov.lookup("/deleted", 0).is_none());
        drop(ov);
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        assert!(meta.legacy());
        assert_eq!(
            meta.values(),
            &BTreeMap::from([("format_version".into(), "1".into())])
        );
    }

    struct CountingBase(AtomicUsize);
    impl MountSource for CountingBase {
        fn is_immutable(&self) -> bool {
            true
        }
        fn list(&self, _: &str) -> Option<ListResult> {
            None
        }
        fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
            None
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ArchiveRead>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("base payload must not be read"))
        }
    }

    /// Regression: a caller-supplied digest must never hash or open base payloads.
    #[test]
    fn regression_overlay_meta_supplied_digest_reads_no_base_bytes() {
        let root = tempfile::tempdir().unwrap();
        let source = Arc::new(CountingBase(AtomicUsize::new(0)));
        // A nonexistent local file would make the real file hasher fail.
        let mut context = info(&root.path().join("unreadable-base"));
        context.base_digest = BaseDigestRequest::Supplied(format!("sha256:{}", "a".repeat(64)));
        let overlay = root.path().join("overlay");
        drop(
            WriteOverlay::new_with_create_info_for_tests(source.clone(), &overlay, &context)
                .unwrap(),
        );
        assert_eq!(source.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            OverlayMeta::read(&overlay).unwrap().unwrap().base_digest(),
            Some(format!("sha256:{}", "a".repeat(64)).as_str())
        );
    }

    /// Regression: unchanged remounts rehashed bytes; changed bases were silently accepted.
    #[test]
    fn regression_overlay_meta_remount_mismatch_and_force() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let overlay = root.path().join("overlay");
        let mut context = info(&archive);
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
                .unwrap(),
        );
        resolve_pending_base_digest(&Connection::open(overlay.join(HIDDEN_DB)).unwrap()).unwrap();
        let old = OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .base_digest()
            .unwrap()
            .to_owned();
        // Deliberately preserving size and mtime demonstrates the documented
        // cheap check: a remount must not compare newly hashed contents.
        let modified = fs::metadata(&archive).unwrap().modified().unwrap();
        fs::write(&archive, b"xyz").unwrap();
        fs::File::options()
            .write(true)
            .open(&archive)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        context.index_path = Some(root.path().join("missing-index"));
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
                .unwrap(),
        );
        assert!(!context.index_path.as_ref().unwrap().exists());
        fs::write(&archive, b"changed").unwrap();
        let error =
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
                .err()
                .unwrap()
                .to_string();
        assert!(
            error.contains(&old) && error.contains("current digest weak:size=7"),
            "{error}"
        );
        assert!(OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .get("base_mismatch_forced_at")
            .is_none());
        context.force_base_mismatch = true;
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
                .unwrap(),
        );
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        assert!(meta.get("base_mismatch_forced_at").is_some());
        assert_eq!(meta.base_digest(), Some(old.as_str()));
    }

    /// Regression: Git refs need a tree identity, while unavailable remote metadata stays weak.
    #[test]
    fn regression_overlay_meta_git_remote_and_none_kinds() {
        let root = tempfile::tempdir().unwrap();
        let mut context = OverlayCreateInfo {
            base_url: "repo@main".into(),
            git_tree: Some("a".repeat(40)),
            ..Default::default()
        };
        let overlay = root.path().join("git");
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
                .unwrap(),
        );
        assert_eq!(
            OverlayMeta::read(&overlay)
                .unwrap()
                .unwrap()
                .base_digest_kind(),
            Some("git-tree")
        );
        context.git_tree = Some("b".repeat(40));
        let error =
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
                .err()
                .unwrap()
                .to_string();
        assert!(
            error.contains(&format!("git-tree:{}", "a".repeat(40)))
                && error.contains(&format!("git-tree:{}", "b".repeat(40)))
        );
        let remote = OverlayCreateInfo {
            base_url: "hf://datasets/a/b@main/snapshot.tar".into(),
            ..Default::default()
        };
        assert_eq!(remote.digest(None).unwrap().1, "weak");
        assert_eq!(remote.digest(None).unwrap(), remote.digest(None).unwrap());
        let with_token = OverlayCreateInfo {
            remote_token: Some("etag:123".into()),
            ..remote.clone()
        };
        assert_ne!(
            remote.digest(None).unwrap().0,
            with_token.digest(None).unwrap().0
        );
        let overlay = root.path().join("no-context");
        drop(WriteOverlay::new_for_tests(base(root.path()), &overlay).unwrap());
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        assert_eq!(meta.base_digest_kind(), Some("none"));
        assert_eq!(meta.format_version().unwrap(), Some(2));
    }

    /// Regression: a directory digest depended on creation order or followed symlinks.
    #[test]
    fn regression_overlay_meta_directory_digest_deterministic() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        for (root, names) in [(a.path(), ["one", "two"]), (b.path(), ["two", "one"])] {
            for name in names {
                fs::write(root.join(name), name).unwrap();
            }
            fs::create_dir(root.join("empty")).unwrap();
        }
        assert_eq!(
            directory_digest(a.path()).unwrap(),
            directory_digest(b.path()).unwrap()
        );
        fs::write(b.path().join("one"), "changed").unwrap();
        assert_ne!(
            directory_digest(a.path()).unwrap(),
            directory_digest(b.path()).unwrap()
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/absent-target", a.path().join("link")).unwrap();
            assert!(directory_digest(a.path()).is_ok());
            use std::os::unix::fs::PermissionsExt;
            let before = directory_digest(a.path()).unwrap();
            fs::set_permissions(a.path().join("one"), fs::Permissions::from_mode(0o755)).unwrap();
            assert_ne!(directory_digest(a.path()).unwrap(), before);
        }
    }

    fn meta_of(overlay: &Path) -> OverlayMeta {
        OverlayMeta::read(overlay).unwrap().unwrap()
    }

    fn open_dir_base(
        base_dir: &Path,
        overlay: &Path,
        context: &OverlayCreateInfo,
    ) -> Result<WriteOverlay> {
        WriteOverlay::new_with_create_info_for_tests(base(base_dir), overlay, context)
    }

    fn set_mtime(path: &Path, secs: u64) {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
            .unwrap();
    }

    /// Regression: a directory base was hashed (every file read) at overlay
    /// creation; it now records the cheap weak manifest and reads no content.
    #[test]
    fn regression_mount_without_base_digest_hashes_no_directory_content() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir_all(basedir.join("sub")).unwrap();
        fs::write(basedir.join("sub/a"), b"a").unwrap();
        let (dirs, streams, walks) = (
            directory_digest_calls_this_thread(),
            ratarmount_index::sha256_stream_calls_this_thread(),
            directory_weak_walks_this_thread(),
        );
        let overlay = root.path().join("overlay");
        drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
        // Reopen, and an overlay inside the base.
        drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
        drop(open_dir_base(&basedir, &basedir.join(".ov"), &info(&basedir)).unwrap());
        assert_eq!(directory_digest_calls_this_thread(), dirs);
        assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), streams);
        assert_eq!(directory_weak_walks_this_thread(), walks + 3);
        let meta = meta_of(&overlay);
        assert_eq!(meta.base_digest_kind(), Some("weak"));
        assert!(meta.base_digest().unwrap().starts_with("weak:"));
        assert_eq!(meta.get("base_weak_digest"), meta.base_digest());
        assert_eq!(meta.get("base_digest_source"), Some("computed"));
        // Positive controls: the counters are wired.
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let ov2 = root.path().join("ov2");
        drop(open_dir_base(root.path(), &ov2, &info(&archive)).unwrap());
        resolve_pending_base_digest(&Connection::open(ov2.join(HIDDEN_DB)).unwrap()).unwrap();
        assert!(ratarmount_index::sha256_stream_calls_this_thread() > streams);
        directory_digest(root.path().join("base").join("sub").as_path()).unwrap();
        assert_eq!(directory_digest_calls_this_thread(), dirs + 1);
    }

    /// Regression: a base holding a FIFO or an unreadable file failed creation
    /// ("cannot digest special file"); the weak walk never opens anything.
    #[cfg(unix)]
    #[test]
    fn regression_directory_base_with_fifo_creates_weak() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir_all(basedir.join("locked")).unwrap();
        fs::write(basedir.join("secret"), b"x").unwrap();
        fs::set_permissions(basedir.join("secret"), fs::Permissions::from_mode(0o0)).unwrap();
        fs::write(basedir.join("locked/in"), b"x").unwrap();
        fs::set_permissions(basedir.join("locked"), fs::Permissions::from_mode(0o0)).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(basedir.join("pipe"))
            .status()
            .unwrap()
            .success());
        let (tx, rx) = std::sync::mpsc::channel();
        let (b, o) = (basedir.clone(), root.path().join("overlay"));
        std::thread::spawn(move || {
            let result = open_dir_base(&b, &o, &info(&b)).map(drop);
            let _ = tx.send(result.map_err(|e| e.to_string()));
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(20));
        fs::set_permissions(basedir.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
        result.expect("creation blocked on the FIFO").unwrap();
        assert_eq!(
            meta_of(&root.path().join("overlay")).base_digest_kind(),
            Some("weak")
        );
    }

    /// `verify_base` table: recorded kind and base type decide strength; a
    /// FIFO under a strong directory digest, `none` and a missing digest are
    /// `Skipped`, never an error.
    #[cfg(unix)]
    #[test]
    fn verify_base_strong_weak_skipped_table() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("f"), b"abc").unwrap();
        // Weak (default) directory digest.
        let overlay = root.path().join("weak");
        open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap();
        assert!(matches!(
            verify_base_path(&overlay, &basedir),
            BaseCheck::Matches {
                strength: BaseStrength::Weak,
                ..
            }
        ));
        fs::write(basedir.join("f"), b"abcd").unwrap();
        assert!(matches!(
            verify_base_path(&overlay, &basedir),
            BaseCheck::Mismatch {
                strength: BaseStrength::Weak,
                ..
            }
        ));
        fs::write(basedir.join("f"), b"abc").unwrap();
        // Strong (supplied) directory digest; a FIFO added later cannot be hashed.
        let strong = root.path().join("strong");
        let mut request = info(&basedir);
        request.base_digest = BaseDigestRequest::Supplied(directory_digest(&basedir).unwrap());
        open_dir_base(&basedir, &strong, &request).unwrap();
        assert!(matches!(
            verify_base_path(&strong, &basedir),
            BaseCheck::Matches {
                strength: BaseStrength::Strong,
                ..
            }
        ));
        assert!(std::process::Command::new("mkfifo")
            .arg(basedir.join("pipe"))
            .status()
            .unwrap()
            .success());
        assert!(matches!(
            verify_base_path(&strong, &basedir),
            BaseCheck::Skipped { .. }
        ));
        fs::remove_file(basedir.join("pipe")).unwrap();
        // `none` and a missing base are skipped.
        let none = root.path().join("none");
        let mut request = info(&basedir);
        request.base_digest = BaseDigestRequest::None;
        open_dir_base(&basedir, &none, &request).unwrap();
        assert!(matches!(
            verify_base_path(&none, &basedir),
            BaseCheck::Skipped { .. }
        ));
        assert!(matches!(
            verify_base_path(&overlay, &root.path().join("missing")),
            BaseCheck::Skipped { .. }
        ));
        // A git-tree base is skipped.
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        OverlayMeta::set(&conn, "base_git_tree", "abc").unwrap();
        drop(conn);
        assert!(matches!(
            verify_base_path(&overlay, &basedir),
            BaseCheck::Skipped { .. }
        ));
    }

    /// Regression: `verify` through a symlink to the base classified the root
    /// by `symlink_metadata`, so it was neither file nor directory and the
    /// base check was skipped; an edited base verified (exit 0).
    #[cfg(unix)]
    #[test]
    fn regression_verify_base_follows_a_root_symlink() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("f"), b"abc").unwrap();
        let overlay = root.path().join("ov");
        open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&basedir, &link).unwrap();
        assert!(matches!(
            verify_base_path(&overlay, &link),
            BaseCheck::Matches {
                strength: BaseStrength::Weak,
                ..
            }
        ));
        fs::write(basedir.join("f"), b"abcd").unwrap();
        assert!(matches!(
            verify_base_path(&overlay, &link),
            BaseCheck::Mismatch { .. }
        ));
        // An archive base reached through a symlink is hashed too.
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let (strong, _) = pending_overlay(root.path(), &archive, "strong");
        let conn = Connection::open(strong.join(HIDDEN_DB)).unwrap();
        assert!(resolve_pending_base_digest(&conn).unwrap());
        drop(conn);
        let alink = root.path().join("alink");
        std::os::unix::fs::symlink(&archive, &alink).unwrap();
        fs::write(&archive, b"abX").unwrap();
        assert!(matches!(
            verify_base_path(&strong, &alink),
            BaseCheck::Mismatch { .. }
        ));
    }

    /// Regression: the weak digest is order independent and sees exactly
    /// path, type, size, mtime and symlink targets.
    #[test]
    fn regression_directory_weak_digest_deterministic_and_sensitive() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        for (root, names) in [(a.path(), ["one", "two"]), (b.path(), ["two", "one"])] {
            for name in names {
                fs::write(root.join(name), name).unwrap();
                set_mtime(&root.join(name), 1_000_000);
            }
            fs::create_dir(root.join("empty")).unwrap();
        }
        let none = BaseExcludes::default();
        let digest = |p: &Path| directory_weak_digest(p, &none).unwrap();
        assert_eq!(digest(a.path()), digest(b.path()));
        assert!(digest(a.path()).starts_with("weak:"));
        let before = digest(a.path());
        // Same size, restored mtime: invisible (documented limitation).
        fs::write(a.path().join("one"), "ONE").unwrap();
        set_mtime(&a.path().join("one"), 1_000_000);
        assert_eq!(digest(a.path()), before);
        // Size, mtime, new/removed entries: visible.
        fs::write(a.path().join("one"), "longer").unwrap();
        set_mtime(&a.path().join("one"), 1_000_000);
        assert_ne!(digest(a.path()), before);
        fs::write(a.path().join("one"), "ONE").unwrap();
        set_mtime(&a.path().join("one"), 1_000_001);
        assert_ne!(digest(a.path()), before);
        set_mtime(&a.path().join("one"), 1_000_000);
        assert_eq!(digest(a.path()), before);
        fs::write(a.path().join("new"), "").unwrap();
        assert_ne!(digest(a.path()), before);
        fs::remove_file(a.path().join("new")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::os::unix::fs::symlink("/aaa", a.path().join("link")).unwrap();
            let linked = digest(a.path());
            fs::remove_file(a.path().join("link")).unwrap();
            std::os::unix::fs::symlink("/bbb", a.path().join("link")).unwrap();
            assert_ne!(digest(a.path()), linked, "same-length retarget must show");
            // Directory mode never counts.
            let now = digest(a.path());
            fs::set_permissions(a.path().join("empty"), fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(digest(a.path()), now);
        }
        // Sidecars written by ratarmount are invisible; look-alikes are not.
        let now = digest(a.path());
        fs::write(a.path().join("a.tar"), "x").unwrap();
        let with_tar = digest(a.path());
        for name in [
            "a.tar.index.sqlite",
            "a.tar.index.ptr",
            "a.tar.rgzi",
            "a.tar.ratarmount-commit-journal",
        ] {
            fs::write(a.path().join(name), "x").unwrap();
        }
        assert_eq!(digest(a.path()), with_tar);
        assert_ne!(with_tar, now);
        fs::write(a.path().join("x.index.txt"), "x").unwrap();
        assert_ne!(digest(a.path()), with_tar);
    }

    /// Regression: reopening an overlay over an edited directory base was never
    /// checked; it now refuses naming `--force-base-mismatch`.
    #[test]
    fn regression_overlay_meta_directory_reopen_refuses_after_edit_naming_force_flag() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("f"), b"one").unwrap();
        let overlay = root.path().join("overlay");
        let mut context = info(&basedir);
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        // A sidecar written into the base does not count.
        fs::write(basedir.join("f.index.sqlite"), b"idx").unwrap();
        fs::write(basedir.join("f.ratarmount-commit-journal"), b"j").unwrap();
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        fs::write(basedir.join("f"), b"edited!").unwrap();
        let error = open_dir_base(&basedir, &overlay, &context)
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("--force-base-mismatch") && error.contains("weak:"),
            "{error}"
        );
        assert!(meta_of(&overlay).get("base_mismatch_forced_at").is_none());
        context.force_base_mismatch = true;
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        assert!(meta_of(&overlay).get("base_mismatch_forced_at").is_some());
    }

    /// Regression: `Compute` refused an overlay inside a directory base. It is
    /// now excluded from the digest, so writing through it never changes it.
    #[test]
    fn regression_overlay_inside_directory_base_excluded_from_weak_digest() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("f"), b"one").unwrap();
        let outside = directory_weak_digest(&basedir, &BaseExcludes::default()).unwrap();
        let overlay = basedir.join(".ov");
        let context = info(&basedir);
        let ov = open_dir_base(&basedir, &overlay, &context).unwrap();
        ov.create_file("/new.txt", 0o644).unwrap();
        drop(ov);
        let meta = meta_of(&overlay);
        assert_eq!(meta.base_digest(), Some(outside.as_str()));
        assert_eq!(meta.get("base_weak_excludes"), Some(r#"[".ov"]"#));
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        fs::write(basedir.join("f"), b"changed").unwrap();
        let error = open_dir_base(&basedir, &overlay, &context)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("--force-base-mismatch"), "{error}");
        // The overlay may never be the base itself.
        let error = open_dir_base(&basedir, &basedir, &context)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("base directory itself"), "{error}");
        // A supplied digest still records the weak companion.
        let supplied = OverlayCreateInfo {
            base_digest: BaseDigestRequest::Supplied(format!("sha256:{}", "a".repeat(64))),
            ..info(&basedir)
        };
        let overlay = basedir.join(".ov2");
        drop(open_dir_base(&basedir, &overlay, &supplied).unwrap());
        let meta = meta_of(&overlay);
        assert_eq!(meta.base_digest_kind(), Some("strong"));
        assert_eq!(meta.get("base_digest_source"), Some("supplied"));
        assert!(meta.get("base_weak_digest").unwrap().starts_with("weak:"));
        fs::write(basedir.join("f"), b"changed again").unwrap();
        assert!(open_dir_base(&basedir, &overlay, &supplied).is_err());
    }

    /// Regression: an overlay in a not-yet-existing parent (`B/new/ov`) must
    /// record `new` (topmost-new), since creating the overlay adds `B/new`.
    #[test]
    fn regression_overlay_in_new_parent_remount_and_verify_pass() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("f"), b"one").unwrap();
        let expected = directory_weak_digest(&basedir, &BaseExcludes::default()).unwrap();
        let overlay = basedir.join("new/ov");
        let context = info(&basedir);
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        let meta = meta_of(&overlay);
        assert_eq!(meta.get("base_weak_excludes"), Some(r#"["new"]"#));
        assert_eq!(meta.base_digest(), Some(expected.as_str()));
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    }

    /// Regression: the recorded exclusion set only ever grows, and a journal
    /// added on a later mount is appended (absent) or refused (base content).
    #[test]
    fn regression_journal_added_later_is_appended_and_recorded_excludes_are_append_only() {
        let a = BaseExcludes::new(["a".into(), "c".into()]);
        assert_eq!(a.to_json().unwrap(), r#"["a","c"]"#);
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(META_SCHEMA).unwrap();
        OverlayMeta::set(&conn, "base_weak_excludes", r#"["a","c"]"#).unwrap();
        append_base_excludes(&conn, &["b".into()]).unwrap();
        append_base_excludes(&conn, &["a".into()]).unwrap();
        let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
        assert_eq!(meta.get("base_weak_excludes"), Some(r#"["a","b","c"]"#));

        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("existing.txt"), b"x").unwrap();
        let overlay = basedir.join(".ov");
        let mut context = info(&basedir);
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        context.weak_exclude = vec![basedir.join("j.jsonl")];
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        assert_eq!(
            meta_of(&overlay).get("base_weak_excludes"),
            Some(r#"[".ov","j.jsonl"]"#)
        );
        // The journal grows; a journal-free remount still passes.
        fs::write(basedir.join("j.jsonl"), b"lots of lines").unwrap();
        context.weak_exclude.clear();
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        // A journal path that is base content is refused and appends nothing.
        context.weak_exclude = vec![basedir.join("existing.txt")];
        context.force_base_mismatch = true;
        let error = open_dir_base(&basedir, &overlay, &context)
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("already exists, so it is base content"),
            "{error}"
        );
        assert_eq!(
            meta_of(&overlay).get("base_weak_excludes"),
            Some(r#"[".ov","j.jsonl"]"#)
        );
    }

    /// Regression: exclusion paths that do not exist yet, symlinks and `..`.
    #[cfg(unix)]
    #[test]
    fn regression_resolve_base_excludes_cases() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir_all(basedir.join("real")).unwrap();
        fs::create_dir(basedir.join("new_parent")).unwrap();
        std::os::unix::fs::symlink(basedir.join("real"), basedir.join("link")).unwrap();
        let rel = |paths: &[PathBuf]| -> Vec<PathBuf> {
            resolve_base_excludes(&basedir, paths)
                .unwrap()
                .1
                .paths()
                .to_vec()
        };
        assert_eq!(
            rel(&[basedir.join("new_parent/ov")]),
            [PathBuf::from("new_parent/ov")]
        );
        assert_eq!(rel(&[basedir.join("a/b/c")]), [PathBuf::from("a")]);
        assert_eq!(rel(&[basedir.join("link/ov")]), [PathBuf::from("real/ov")]);
        assert_eq!(rel(&[basedir.join("link/x/ov")]), [PathBuf::from("real/x")]);
        assert_eq!(rel(&[basedir.join("real")]), [PathBuf::from("real")]);
        assert!(rel(&[root.path().join("outside/ov")]).is_empty());
        let error = resolve_base_excludes(&basedir, &[basedir.join("a/../b")])
            .err()
            .unwrap();
        assert!(error.to_string().contains("'..'"), "{error}");
        // A symlink loop and a dangling link never get followed by the walk.
        std::os::unix::fs::symlink("/absent-target", basedir.join("dangling")).unwrap();
        std::os::unix::fs::symlink("b", basedir.join("loop_a")).unwrap();
        std::os::unix::fs::symlink("loop_a", basedir.join("b")).unwrap();
        directory_weak_digest(&basedir, &BaseExcludes::default()).unwrap();
    }

    /// Regression: read-only metadata inspection created files or hid SQLITE_BUSY.
    #[test]
    fn regression_overlay_meta_read_only_missing_and_in_use() {
        let root = tempfile::tempdir().unwrap();
        let overlay = root.path().join("overlay");
        assert!(OverlayMeta::read(&overlay).is_err());
        assert!(!overlay.exists());
        let ov = WriteOverlay::new_for_tests(base(root.path()), &overlay).unwrap();
        let error = OverlayMeta::read(&overlay).unwrap_err().to_string();
        assert!(error.contains("in use"), "{error}");
        drop(ov);
        let db = overlay.join(HIDDEN_DB);
        let before = fs::read(&db).unwrap();
        assert!(OverlayMeta::read(&overlay).unwrap().is_some());
        assert_eq!(before, fs::read(&db).unwrap());
    }

    /// Regression: metadata batches must roll back together and respect caller transactions.
    #[test]
    fn regression_overlay_meta_set_many_atomic_in_transaction() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(META_SCHEMA).unwrap();
        conn.execute_batch("CREATE TRIGGER reject_bad BEFORE INSERT ON meta WHEN NEW.key='bad' BEGIN SELECT RAISE(ABORT, 'bad key'); END;").unwrap();
        let tx = conn.transaction().unwrap();
        OverlayMeta::set(&tx, "kept", "yes").unwrap();
        assert!(OverlayMeta::set_many(&tx, &[("rolled_back", "yes"), ("bad", "no")]).is_err());
        let meta = OverlayMeta::from_connection(&tx).unwrap().unwrap();
        assert_eq!(meta.get("kept"), Some("yes"));
        assert_eq!(meta.get("rolled_back"), None);
        tx.rollback().unwrap();
        assert!(OverlayMeta::from_connection(&conn)
            .unwrap()
            .unwrap()
            .values()
            .is_empty());
    }

    /// The `base_digest_state` mapping: pending, none, and present for every
    /// recorded digest (strong, weak, git-tree); legacy overlays map by digest.
    #[test]
    fn base_digest_state_mapping() {
        assert_eq!(base_digest_state(Some("pending"), ""), "pending");
        assert_eq!(base_digest_state(Some("none"), "none"), "none");
        for kind in ["strong", "weak", "git-tree"] {
            assert_eq!(base_digest_state(Some(kind), "sha256:x"), "present");
        }
        assert_eq!(base_digest_state(None, ""), "none");
        assert_eq!(base_digest_state(None, "sha256:x"), "present");
    }

    fn pending_overlay(root: &Path, archive: &Path, name: &str) -> (PathBuf, PendingBase) {
        let overlay = root.join(name);
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root), &overlay, &info(archive))
                .unwrap(),
        );
        let meta = meta_of(&overlay);
        let pending = PendingBase::from_meta(&meta).unwrap().expect("pending");
        (overlay, pending)
    }

    /// Regression: an uncached archive base was hashed on the mount's critical
    /// path; it is now `pending` with no digest and no stack digest.
    #[test]
    fn regression_pending_archive_base_records_no_digest_until_resolved() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let before = ratarmount_index::sha256_stream_calls_this_thread();
        let (overlay, _) = pending_overlay(root.path(), &archive, "overlay");
        assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
        let meta = meta_of(&overlay);
        assert_eq!(meta.base_digest_kind(), Some("pending"));
        assert_eq!(meta.base_digest(), Some(""));
        assert_eq!(meta.stack_digest(), None);
        assert_eq!(meta.get("base_digest_source"), Some("computed"));
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        assert!(resolve_pending_base_digest(&conn).unwrap());
        assert!(!resolve_pending_base_digest(&conn).unwrap());
        drop(conn);
        let meta = meta_of(&overlay);
        assert_eq!(meta.base_digest_kind(), Some("strong"));
        assert_eq!(
            meta.base_digest(),
            Some(format!("sha256:{:x}", Sha256::digest(b"abc")).as_str())
        );
        assert_eq!(
            meta.stack_digest(),
            Some(stack_digest(meta.base_digest().unwrap(), &[]).as_str())
        );
        assert!(ratarmount_index::sha256_stream_calls_this_thread() > before);
    }

    /// Regression: `record_base_digest` must be a compare-and-set on `pending`
    /// for the recorded stamp, so a supplied digest or a moved archive wins.
    #[test]
    fn regression_pending_cas_loses_to_supplied_digest_and_changed_stamp() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let (overlay, pending) = pending_overlay(root.path(), &archive, "overlay");
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        let digest = format!("sha256:{}", "b".repeat(64));
        // A changed stamp (a commit moved the archive) records nothing.
        let moved = PendingBase {
            size: pending.size + 1,
            ..pending.clone()
        };
        assert!(!record_base_digest(&conn, &moved, &digest).unwrap());
        assert_eq!(meta_of(&overlay).base_digest_kind(), Some("pending"));
        // A digest recorded by someone else first wins.
        OverlayMeta::set_many(
            &conn,
            &[
                ("base_digest", "sha256:supplied"),
                ("base_digest_kind", "strong"),
            ],
        )
        .unwrap();
        assert!(!record_base_digest(&conn, &pending, &digest).unwrap());
        assert_eq!(meta_of(&overlay).base_digest(), Some("sha256:supplied"));
    }

    /// Regression: a pending reopen must still run the size/mtime check
    /// before anything is hashed, naming `--force-base-mismatch`.
    #[test]
    fn regression_pending_reopen_size_mtime_check_still_refuses() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let (overlay, _) = pending_overlay(root.path(), &archive, "overlay");
        drop(
            WriteOverlay::new_with_create_info_for_tests(
                base(root.path()),
                &overlay,
                &info(&archive),
            )
            .unwrap(),
        );
        fs::write(&archive, b"changed").unwrap();
        let before = ratarmount_index::sha256_stream_calls_this_thread();
        let error = WriteOverlay::new_with_create_info_for_tests(
            base(root.path()),
            &overlay,
            &info(&archive),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(
            error.contains("base mismatch") && error.contains("recorded digest pending"),
            "{error}"
        );
        assert!(error.contains("--force-base-mismatch"), "{error}");
        assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
        // The stale record cannot be resolved against the changed archive.
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        let error = resolve_pending_base_digest(&conn).unwrap_err().to_string();
        assert!(
            error.contains("changed since the overlay was created"),
            "{error}"
        );
        assert_eq!(meta_of(&overlay).base_digest_kind(), Some("pending"));
    }

    /// Regression: a digest resolved once is cached in the index, so a second
    /// overlay on the same archive records `strong` at creation (no pending).
    #[test]
    fn regression_pending_reopen_after_exit_resolves_via_cache() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let index = root.path().join("a.tar.index.sqlite");
        Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        let mut context = info(&archive);
        context.index_path = Some(index);
        let first = root.path().join("first");
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &first, &context)
                .unwrap(),
        );
        assert_eq!(meta_of(&first).base_digest_kind(), Some("pending"));
        let conn = Connection::open(first.join(HIDDEN_DB)).unwrap();
        assert!(resolve_pending_base_digest(&conn).unwrap());
        drop(conn);
        let second = root.path().join("second");
        let before = ratarmount_index::sha256_stream_calls_this_thread();
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &second, &context)
                .unwrap(),
        );
        assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
        assert_eq!(meta_of(&second).base_digest_kind(), Some("strong"));
        assert_eq!(
            meta_of(&second).base_digest(),
            meta_of(&first).base_digest()
        );
    }

    /// Regression (archive half of "with --base-digest no base file is
    /// opened for hashing"): a supplied digest hashes nothing, and without it
    /// creation hashes nothing either but resolving does (positive control).
    #[test]
    fn regression_base_digest_flag_opens_no_base_file_for_hashing() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let mut context = info(&archive);
        context.base_digest = BaseDigestRequest::Supplied(format!("sha256:{}", "c".repeat(64)));
        let before = ratarmount_index::sha256_stream_calls_this_thread();
        let overlay = root.path().join("supplied");
        drop(
            WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
                .unwrap(),
        );
        assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
        assert_eq!(meta_of(&overlay).base_digest_kind(), Some("strong"));
        let (overlay, _) = pending_overlay(root.path(), &archive, "computed");
        assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        resolve_pending_base_digest(&conn).unwrap();
        assert!(ratarmount_index::sha256_stream_calls_this_thread() > before);
    }

    fn dir_names(dir: &Path) -> std::collections::BTreeSet<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect()
    }

    /// Everything new or left over since `before`, except `declared`, must be
    /// invisible to the digest according to the shared predicate.
    fn assert_new_names_are_sidecars(
        dir: &Path,
        before: &std::collections::BTreeSet<String>,
        declared: &[&str],
        what: &str,
    ) {
        for name in dir_names(dir).difference(before) {
            if declared.contains(&name.as_str()) {
                continue;
            }
            assert!(
                crate::base_sidecars::is_ratarmount_sidecar_name(name, &|stem| dir
                    .join(stem)
                    .exists()),
                "{what}: {name} is written by ratarmount but the predicate does not hide it"
            );
        }
    }

    /// A directory base with an archive `a.tar`, a gzip `a.gz` and a plain file.
    fn writer_base(root: &Path) -> PathBuf {
        use std::io::Write;
        let base = root.join("base");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("a.tar"), vec![0u8; 2048]).unwrap();
        fs::write(base.join("plain.txt"), b"plain").unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&b"hello world\n".repeat(4096)).unwrap();
        fs::write(base.join("a.gz"), gz.finish().unwrap()).unwrap();
        base
    }

    /// Run the real index writers inside `base` (publish, pointer, rotate and a
    /// cold build observed mid-way), calling `check(label)` after each step.
    fn run_index_writers(base: &Path, outside: &Path, check: &mut dyn FnMut(&str)) {
        let archive = base.join("a.tar");
        let dest = base.join("a.tar.index.sqlite");
        let mut index = ratarmount_index::SqliteIndex::create_writable(Some(&dest)).unwrap();
        check("cold build staging (mid-build)");
        index.publish_tmp().unwrap();
        drop(index);
        check("index published");
        for round in 0..3 {
            let blob = outside.join(format!("blob{round}.sqlite"));
            fs::copy(&dest, &blob).unwrap();
            fs::write(
                &blob,
                [fs::read(&dest).unwrap(), vec![round as u8; 16]].concat(),
            )
            .unwrap();
            ratarmount_index::publish_index_pointer(&archive, &blob, None).unwrap();
            check(&format!("pointer publish/rotate {round}"));
        }
    }

    /// Regression: every file a ratarmount writer leaves beside a base archive
    /// (index, pointer, rotated snapshot, staging, commit journal, manifest,
    /// every repack mode) must satisfy the predicate the digest walks use.
    #[test]
    fn regression_sidecar_predicate_covers_every_writer_output() {
        let root = tempfile::tempdir().unwrap();
        let base = writer_base(root.path());
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let mut before = dir_names(&base);
        {
            let b = base.clone();
            run_index_writers(&base, &outside, &mut |what| {
                assert_new_names_are_sidecars(&b, &before, &[], what);
                before = dir_names(&b);
            });
        }
        // Provenance manifest beside the archive.
        let mut manifest = base.join("a.tar").into_os_string();
        manifest.push(crate::base_sidecars::MANIFEST_SIDECAR_SUFFIX);
        fs::write(&manifest, b"{}\n").unwrap();
        assert_new_names_are_sidecars(&base, &before, &[], "manifest");
        // The commit journal exists while a suffix replacement is in flight.
        fs::copy(base.join("a.tar"), base.join("c.tar")).unwrap();
        before = dir_names(&base);
        let mut suffix = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut suffix, &[1u8; 512]).unwrap();
        std::io::Seek::rewind(&mut suffix).unwrap();
        let mut seen_journal = false;
        let replaced = ratarmount_compress::commit_journal::replace_suffix_with_hook(
            &base.join("c.tar"),
            512,
            &mut suffix,
            &mut |_phase| {
                seen_journal |= dir_names(&base).iter().any(|n| {
                    n.ends_with(ratarmount_compress::commit_journal::COMMIT_JOURNAL_SUFFIX)
                });
                assert_new_names_are_sidecars(&base, &before, &[], "commit journal");
                Ok(())
            },
        );
        match replaced {
            Ok(()) => assert!(seen_journal, "the hook never saw the commit journal"),
            Err(error) => eprintln!("skip: commit journal needs inode xattrs: {error}"),
        }
        assert_new_names_are_sidecars(&base, &before, &[], "after commit");
        // Every repack mode: only the declared output may be new content.
        use ratarmount_compress::{repack_seekable, GzipSidecar, RepackOptions};
        let runs: [(&str, GzipSidecar, bool); 5] = [
            ("o_rgzi.gz", GzipSidecar::Rgzi, false),
            ("o_gzidx.gz", GzipSidecar::Gzidx, false),
            ("o_both.gz", GzipSidecar::Both, false),
            ("o_rgzi.gz", GzipSidecar::Both, true),
            ("o_zstd.zst", GzipSidecar::Rgzi, false),
        ];
        for (out, sidecar, overwrite) in runs {
            before = dir_names(&base);
            let opts = RepackOptions {
                gzip_sidecar: sidecar,
                overwrite,
                ..Default::default()
            };
            repack_seekable(&base.join("a.gz"), &base.join(out), &opts).unwrap();
            assert_new_names_are_sidecars(&base, &before, &[out], &format!("repack {out}"));
        }
    }

    /// Regression: index publish/rotate/staging inside a directory base moved
    /// its digest (the plan's `.rgzi` gap). Part 1: sidecar-only writers leave
    /// weak and strong digests unchanged and reopen passes. Part 2 (documented
    /// behaviour, G6): a legitimate repack writes an archive, which IS base
    /// content, so reopen is refused naming `--force-base-mismatch`, while the
    /// sidecars it leaves stay invisible.
    #[test]
    fn regression_index_publish_and_rotate_inside_directory_base_keeps_reopen() {
        use ratarmount_compress::{repack_seekable, GzipSidecar, RepackOptions};
        let root = tempfile::tempdir().unwrap();
        let base = writer_base(root.path());
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let none = BaseExcludes::default();
        let weak = directory_weak_digest(&base, &none).unwrap();
        let strong = directory_digest(&base).unwrap();
        let ov_weak = root.path().join("ov_weak");
        let ov_strong = root.path().join("ov_strong");
        let strong_info = OverlayCreateInfo {
            base_digest: BaseDigestRequest::Supplied(strong.clone()),
            ..info(&base)
        };
        drop(open_dir_base(&base, &ov_weak, &info(&base)).unwrap());
        drop(open_dir_base(&base, &ov_strong, &strong_info).unwrap());
        let b = base.clone();
        run_index_writers(&base, &outside, &mut |what| {
            assert_eq!(directory_weak_digest(&b, &none).unwrap(), weak, "{what}");
            assert_eq!(directory_digest(&b).unwrap(), strong, "{what}");
        });
        drop(open_dir_base(&base, &ov_weak, &info(&base)).unwrap());
        drop(open_dir_base(&base, &ov_strong, &strong_info).unwrap());

        // Part 2: baseline files the repack does not touch.
        let stamp = |name: &str| {
            let meta = fs::metadata(base.join(name)).unwrap();
            (fs::read(base.join(name)).unwrap(), meta.modified().unwrap())
        };
        let baseline: Vec<_> = ["a.tar", "plain.txt", "a.gz"]
            .iter()
            .map(|n| (*n, stamp(n)))
            .collect();
        let runs: [(&str, GzipSidecar, bool); 4] = [
            ("o_rgzi.gz", GzipSidecar::Rgzi, false),
            ("o_gzidx.gz", GzipSidecar::Gzidx, false),
            ("o_both.gz", GzipSidecar::Both, false),
            ("o_rgzi.gz", GzipSidecar::Both, true),
        ];
        for (n, (out, sidecar, overwrite)) in runs.into_iter().enumerate() {
            let overlay = root.path().join(format!("ov_repack{n}"));
            let context = info(&base);
            drop(open_dir_base(&base, &overlay, &context).unwrap());
            let recorded = meta_of(&overlay).base_digest().unwrap().to_string();
            let before = dir_names(&base);
            let with_output = BaseExcludes::new([PathBuf::from(out)]);
            let digest_before = directory_weak_digest(&base, &with_output).unwrap();
            let opts = RepackOptions {
                gzip_sidecar: sidecar,
                overwrite,
                ..Default::default()
            };
            repack_seekable(&base.join("a.gz"), &base.join(out), &opts).unwrap();
            // (ii) every other new name is a sidecar and invisible to the digest.
            assert_new_names_are_sidecars(&base, &before, &[out], out);
            // (i) only the output body counts: the digest moved, the reopen refuses.
            assert_ne!(
                directory_weak_digest(&base, &none).unwrap(),
                recorded,
                "{out}"
            );
            let error = open_dir_base(&base, &overlay, &context)
                .err()
                .unwrap_or_else(|| panic!("repack {out} did not change the digest"))
                .to_string();
            assert!(error.contains("--force-base-mismatch"), "{error}");
            let mut forced = context.clone();
            forced.force_base_mismatch = true;
            drop(open_dir_base(&base, &overlay, &forced).unwrap());
            // Excluding just the output makes the walk identical to before the repack
            // for a fresh output; an overwrite already counted the old body.
            if !overwrite {
                assert_eq!(
                    directory_weak_digest(&base, &with_output).unwrap(),
                    digest_before,
                    "{out}: sidecars/staging names must not count"
                );
            }
        }
        // (iii) untouched baseline files are byte- and mtime-identical.
        for (name, before) in baseline {
            assert_eq!(stamp(name), before, "{name} was collateral damage");
        }
    }

    /// Regression: an invocation path the caller passed in `weak_exclude` (a
    /// journal or a lower layer) created inside the base after the digest was
    /// taken changed the weak digest on remount. The recorded excluded set
    /// covers it; topmost-new records it.
    #[test]
    fn regression_late_created_weak_exclude_is_in_the_recorded_excluded_set() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("f"), b"one").unwrap();
        let expected = directory_weak_digest(&basedir, &BaseExcludes::default()).unwrap();
        // Overlay beside the base, excluded path inside it, not created yet.
        let overlay = root.path().join("overlay");
        let context = OverlayCreateInfo {
            weak_exclude: vec![basedir.join("j.jsonl")],
            ..info(&basedir)
        };
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        assert_eq!(
            meta_of(&overlay).get("base_weak_excludes"),
            Some(r#"["j.jsonl"]"#)
        );
        // The journal is written afterwards and grows.
        fs::write(basedir.join("j.jsonl"), b"lots of lines").unwrap();
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        assert_eq!(meta_of(&overlay).base_digest(), Some(expected.as_str()));
        // Overlay inside the base as well, excluded path in a not-yet-existing parent.
        let overlay = basedir.join(".ov");
        let context = OverlayCreateInfo {
            weak_exclude: vec![basedir.join("journals/j1.jsonl")],
            ..info(&basedir)
        };
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        assert_eq!(
            meta_of(&overlay).get("base_weak_excludes"),
            Some(r#"[".ov","journals"]"#)
        );
        fs::create_dir_all(basedir.join("journals")).unwrap();
        fs::write(basedir.join("journals/j1.jsonl"), b"j").unwrap();
        drop(open_dir_base(&basedir, &overlay, &context).unwrap());
        // A journal-free remount still passes (recorded set).
        drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
    }

    fn bump_format_version(overlay: &Path, version: &str) {
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        OverlayMeta::set(&conn, "format_version", version).unwrap();
    }

    /// Regression: a `format_version` newer than this build read as valid and
    /// was served and sealed as if it were format 2.
    #[test]
    fn regression_format_version_3_is_refused_by_every_reader() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().join("base");
        fs::create_dir(&basedir).unwrap();
        fs::write(basedir.join("f"), b"x").unwrap();
        let overlay = root.path().join("overlay");
        drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
        bump_format_version(&overlay, "3");
        let newer = |error: String| {
            assert!(
                error.contains("format_version 3 is newer") && error.contains("upgrade"),
                "{error}"
            )
        };
        newer(OverlayMeta::read(&overlay).unwrap_err().to_string());
        newer(
            open_dir_base(&basedir, &overlay, &info(&basedir))
                .err()
                .expect("WriteOverlay::new must refuse")
                .to_string(),
        );
        newer(
            crate::overlay_seal::verify(&overlay, base(&basedir))
                .unwrap_err()
                .to_string(),
        );
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        newer(OverlayMeta::from_connection(&conn).unwrap_err().to_string());
        // Version 2 and an unparsable value keep their messages.
        bump_format_version(&overlay, "2");
        assert!(OverlayMeta::read(&overlay).unwrap().is_some());
        bump_format_version(&overlay, "two");
        assert!(OverlayMeta::read(&overlay)
            .unwrap_err()
            .to_string()
            .contains("invalid overlay format_version"));
    }

    /// Regression: the version gate must accept the additive format-2 keys.
    #[test]
    fn regression_format_version_2_accepts_additive_keys() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(META_SCHEMA).unwrap();
        OverlayMeta::set_many(
            &conn,
            &[
                ("format_version", "2"),
                ("base_digest_kind", "weak"),
                ("base_weak_digest", "weak:size=1,x"),
                ("base_weak_excludes", "[]"),
                ("base_digest_source", "computed"),
                ("import_in_progress", "1:2"),
            ],
        )
        .unwrap();
        let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
        assert_eq!(meta.format_version().unwrap(), Some(2));
        assert_eq!(meta.get("import_in_progress"), Some("1:2"));
    }

    /// Build `dir/HIDDEN_DB` with a hot rollback journal: a table-less
    /// database (no `files`) copied together with its `-journal` while a
    /// writer's spilled transaction is open.
    fn table_less_db_with_hot_journal(dir: &Path) {
        let scratch = tempfile::tempdir().unwrap();
        let src = scratch.path().join("src.sqlite");
        let conn = Connection::open(&src).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE; CREATE TABLE t(x BLOB); \
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 64) \
             INSERT INTO t SELECT zeroblob(4096) FROM n;",
        )
        .unwrap();
        // A tiny cache spills the open transaction: journal synced, pages
        // written into the database file.
        conn.execute_batch(
            "PRAGMA cache_size=1; BEGIN; UPDATE t SET x = zeroblob(4000); \
             INSERT INTO t SELECT x FROM t;",
        )
        .unwrap();
        let journal = PathBuf::from(format!("{}-journal", src.display()));
        assert!(fs::metadata(&journal).unwrap().len() > 0, "spilled journal");
        let db = dir.join(HIDDEN_DB);
        fs::copy(&src, &db).unwrap();
        fs::copy(&journal, format!("{}-journal", db.display())).unwrap();
        drop(conn);
    }

    /// Regression: (S3 skeptic #2): the required-record latch is kept across
    /// the hot-journal recovery and the retry. A marker present when the
    /// first read's open classified the database (after the caller's own
    /// marker check) and removed after the acquisition made that attempt
    /// required; the read hit `SQLITE_READONLY_ROLLBACK`, recovery rolled
    /// the journal back, and the retry used the caller's original `false`,
    /// so a table-less record read as "unrecorded" (`Ok(None)`).
    #[test]
    fn regression_required_latch_survives_hot_journal_retry() {
        let dir = tempfile::tempdir().unwrap();
        table_less_db_with_hot_journal(dir.path());
        let marker = dir.path().join(crate::write_overlay::OVERLAY_MARKER);
        fs::write(&marker, b"").unwrap();
        let journal = PathBuf::from(format!("{}-journal", dir.path().join(HIDDEN_DB).display()));

        let opens = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let counted = opens.clone();
        let removed = marker.clone();
        crate::overlay_db::AFTER_ACQUIRE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_| {
                counted.set(counted.get() + 1);
                if counted.get() == 1 {
                    fs::remove_file(&removed).unwrap();
                }
            }))
        });
        // The caller's own marker check ran before the marker appeared.
        let result = OverlayMeta::read_with_required(dir.path(), true, false, false);
        crate::overlay_db::AFTER_ACQUIRE.with(|hook| *hook.borrow_mut() = None);

        assert_eq!(opens.get(), 3, "read, recovery, retry");
        assert!(!journal.exists(), "the hot journal was rolled back");
        match result {
            Err(OverlayError::Msg(msg)) => assert_eq!(msg, NO_FILES_TABLE),
            other => panic!("a required table-less record must refuse: {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // R11-S7 (#151): base hashing reads through managed readers.
    // ---------------------------------------------------------------------

    #[cfg(unix)]
    use ratarmount_index::managed_read::lock_probe::other_process_sees_lock;

    /// An SQLite database (an SQLAR or an index) at `path`; its bytes.
    #[cfg(unix)]
    fn s7_database(path: &Path) -> Vec<u8> {
        let c = Connection::open(path).unwrap();
        c.execute_batch(
            "CREATE TABLE sqlar(name TEXT PRIMARY KEY, mode INT, mtime INT, sz INT, data BLOB);
             INSERT INTO sqlar VALUES ('a', 33188, 0, 3, randomblob(150000));",
        )
        .unwrap();
        drop(c);
        fs::read(path).unwrap()
    }

    /// A connection of this process holding SHARED on `path`.
    #[cfg(unix)]
    fn s7_holder(path: &Path) -> Connection {
        let c = Connection::open(path).unwrap();
        c.execute_batch("BEGIN").unwrap();
        let _: i64 = c
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .unwrap();
        assert!(other_process_sees_lock(path));
        c
    }

    /// A file base with a supplied strong digest of `bytes`.
    #[cfg(unix)]
    fn s7_strong_overlay(root: &Path, archive: &Path, bytes: &[u8]) -> PathBuf {
        let overlay = root.join("strong-overlay");
        let mut request = info(archive);
        request.base_digest =
            BaseDigestRequest::Supplied(format!("sha256:{:x}", Sha256::digest(bytes)));
        drop(WriteOverlay::new_with_create_info_for_tests(base(root), &overlay, &request).unwrap());
        overlay
    }

    /// Regression: the strong directory digest hashed every file with a raw
    /// `File`, releasing the lock of a connection of this process on an SQLAR
    /// inside the base directory.
    #[cfg(unix)]
    #[test]
    fn regression_directory_strong_digest_keeps_sqlar_lock() {
        let root = tempfile::tempdir().unwrap();
        let basedir = root.path().canonicalize().unwrap().join("base");
        fs::create_dir(&basedir).unwrap();
        let db = basedir.join("a.sqlar");
        s7_database(&db);
        let h = s7_holder(&db);
        directory_digest(&basedir).unwrap();
        assert!(other_process_sees_lock(&db), "lock kept");
        drop(fs::File::open(&db).unwrap());
        assert!(!other_process_sees_lock(&db), "oracle check");
        drop(h);
    }

    /// Regression: resolving a pending archive digest (the mount's background
    /// hasher and `resolve_pending_base_digest`) hashed the archive raw while
    /// a connection of this process had it open (the archive here is an
    /// ordinary index with a `files` table).
    #[cfg(unix)]
    #[test]
    fn regression_pending_base_hash_keeps_index_lock() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let archive = root.join("a.tar");
        {
            let mut idx = ratarmount_index::SqliteIndex::create_writable(Some(&archive)).unwrap();
            idx.publish_tmp().unwrap();
        }
        let (overlay, pending) = pending_overlay(&root, &archive, "overlay");
        let h = {
            let c = Connection::open(&archive).unwrap();
            c.execute_batch("BEGIN").unwrap();
            let _: i64 = c
                .query_row("SELECT count(*) FROM files", [], |r| r.get(0))
                .unwrap();
            c
        };
        assert!(other_process_sees_lock(&archive));
        let digest = pending.hash(&|| Ok(())).unwrap();
        assert!(digest.starts_with("sha256:"));
        assert!(
            other_process_sees_lock(&archive),
            "PendingBase::hash kept it"
        );
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        resolve_pending_base_digest(&conn).unwrap();
        assert!(other_process_sees_lock(&archive), "resolution kept it");
        drop(h);
    }

    /// Regression: `overlay verify`'s strong base check hashed the base raw
    /// (an SQLAR another connection of this process has open).
    #[cfg(unix)]
    #[test]
    fn regression_strong_base_verification_keeps_sqlar_lock() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let archive = root.join("a.sqlar");
        let bytes = s7_database(&archive);
        let overlay = s7_strong_overlay(&root, &archive, &bytes);
        let h = s7_holder(&archive);
        assert!(matches!(
            verify_base_path(&overlay, &archive),
            BaseCheck::Matches {
                strength: BaseStrength::Strong,
                ..
            }
        ));
        assert!(other_process_sees_lock(&archive), "lock kept");
        drop(h);
    }

    /// Regression: a failed strong base hash must stay `Skipped` (the CLI
    /// keeps its exit status and reports `base_ok: null`), never `Matches`.
    #[cfg(unix)]
    #[test]
    fn regression_verify_base_hash_failure_stays_skipped() {
        use ratarmount_index::managed_read::{seams, Seam};
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let archive = root.join("a.sqlar");
        let bytes = s7_database(&archive);
        let overlay = s7_strong_overlay(&root, &archive, &bytes);
        for seam in [Seam::AfterOpen, Seam::BeforeRead] {
            let got = seams::with(
                move |s| {
                    if s == seam {
                        Err(io::Error::other("injected"))
                    } else {
                        Ok(())
                    }
                },
                || verify_base_path(&overlay, &archive),
            );
            match got {
                BaseCheck::Skipped { reason } => assert!(reason.contains("injected"), "{reason}"),
                other => panic!("{seam:?}: {other:?}"),
            }
        }
    }

    /// Regression: (live caller of the digest refresh, `refresh_archive_digest`
    /// through `refresh_committed_base`): refreshing the committed base's
    /// digest hashed an archive that is an SQLAR open in this process raw.
    #[cfg(unix)]
    #[test]
    fn regression_archive_digest_and_refresh_keep_sqlar_lock_live_caller() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let archive = root.join("a.sqlar");
        let bytes = s7_database(&archive);
        let overlay = s7_strong_overlay(&root, &archive, &bytes);
        let h = s7_holder(&archive);
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        refresh_committed_base(&conn, None, &archive).unwrap();
        assert!(other_process_sees_lock(&archive), "refresh kept the lock");
        drop(h);
    }

    /// Set by the creation-mode test for its child.
    #[cfg(unix)]
    const S7_MODE_CHILD_ENV: &str = "RATARMOUNT_TEST_S7_MODE_CHILD";

    /// The child half of the creation-mode test (a no-op unless spawned):
    /// under the given umask, a real overlay creation and an index build and
    /// publication; reports every mode.
    #[cfg(unix)]
    #[test]
    fn s7_mode_child() {
        use std::os::unix::fs::PermissionsExt;
        let Some(arg) = std::env::var_os(S7_MODE_CHILD_ENV) else {
            return;
        };
        let arg = arg.to_string_lossy().into_owned();
        let (umask, dir) = arg.split_once(':').unwrap();
        let umask = u32::from_str_radix(umask, 8).unwrap();
        // SAFETY: a single-threaded child.
        unsafe { libc::umask(umask as libc::mode_t) };
        let dir = PathBuf::from(dir);
        let mode_of = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let want = 0o644 & !umask;
        let mut report = Vec::new();
        // Overlay creation (SQLite creates the database).
        let archive = dir.join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let overlay = dir.join("overlay");
        let ov =
            WriteOverlay::new_with_create_info_for_tests(base(&dir), &overlay, &info(&archive))
                .unwrap();
        let db = overlay.join(HIDDEN_DB);
        assert_eq!(mode_of(&db), want, "overlay database");
        for side in ["-wal", "-shm", "-journal"] {
            let p = PathBuf::from(format!("{}{side}", db.display()));
            if p.exists() {
                assert_eq!(mode_of(&p), mode_of(&db), "overlay {side}");
                report.push(side.to_owned());
            }
        }
        drop(ov);
        // Cold index: temporary database, publication, companions.
        let dest = dir.join("idx").join("a.tar.index.sqlite");
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        let mut idx = ratarmount_index::SqliteIndex::create_writable(Some(&dest)).unwrap();
        let tmp = fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p != &dest && p.is_file() && !p.to_string_lossy().ends_with("-journal"))
            .expect("temporary index");
        assert_eq!(mode_of(&tmp), want, "temporary index");
        idx.publish_tmp().unwrap();
        assert_eq!(
            mode_of(&dest),
            want,
            "published index (rename keeps the mode)"
        );
        for side in ["-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{side}", dest.display()));
            if p.exists() {
                assert_eq!(mode_of(&p), want, "index {side}");
                report.push(format!("index{side}"));
            }
        }
        drop(idx);
        fs::write(dir.join("result"), format!("ok {}", report.join(","))).unwrap();
    }

    /// Regression: (R11-S7 §7): the overlay database and the cold index keep
    /// SQLite's `0644 & !umask` creation mode; publication's rename keeps the
    /// temporary database's mode; companions take the database's mode.
    /// Umasks 002, 022, 077, each in a fresh child.
    #[cfg(unix)]
    #[test]
    fn regression_exclusive_create_preserves_overlay_and_published_index_modes() {
        for umask in ["002", "022", "077"] {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().canonicalize().unwrap();
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "overlay_meta::tests::s7_mode_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(S7_MODE_CHILD_ENV, format!("{umask}:{}", dir.display()))
                .output()
                .unwrap();
            let got = fs::read_to_string(dir.join("result")).unwrap_or_default();
            assert!(
                out.status.success() && got.starts_with("ok"),
                "umask {umask}: {got:?}\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
