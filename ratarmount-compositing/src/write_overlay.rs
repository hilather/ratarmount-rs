//! Write overlay: redirect creates/writes/deletes to a host folder.
//! Mirrors Python `WritableFolderMountSource` (subset) + `commit_overlay`.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions as FsOpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime};

use bzip2::write::BzEncoder;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use ratarmount_compress::{
    body_looks_like_tar, decode_zstd_frames_to, detect_compression, export_zstd_blocks,
    materialize, open_seekable_zstd, open_seekable_zstd_with_threads, scan_zstd_frames_path,
    CompressionFormat, SpliceStats, ZstdFrameMap, DEFAULT_MEMORY_CAP,
};
use ratarmount_core::{
    create_root_file_info, metadata_gid, metadata_mode, metadata_mtime_secs, metadata_uid,
    normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
    OpenOptions, UserData,
};
use ratarmount_formats_tar::{
    find_last_tar_eof, rewrite_tar_suffix, window_has_member_boundary, RewriteTarSuffix,
    SqliteIndexedTar, UstarMember, UstarPayload,
};
use ratarmount_index::{
    fill_content_hashes, locate_pattern_matches, resolve_index_location, IndexLocation,
    SqliteIndex, DEFAULT_SEARCH_LIMIT, MEMORY_INDEX,
};
#[cfg(test)]
use ratarmount_index::{index_pointer_to_json, IndexPointer};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use thiserror::Error;
use xz2::write::XzEncoder;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub const HIDDEN_DB: &str = ".ratarmount.overlay.sqlite";

/// Marker written next to [`HIDDEN_DB`] once an overlay database exists (#96).
/// A marked folder whose database is missing, or whose database lost its
/// `files` table, is refused instead of silently recreated (that would drop
/// every tombstone and unlinked archive members would reappear).
///
/// Not prefixed with [`HIDDEN_DB`], so `rm .ratarmount.overlay.sqlite*` does not
/// take it along with the database.
pub const OVERLAY_MARKER: &str = ".ratarmount-overlay.used";

/// Marker name used before the rename; still accepted (never created).
pub const LEGACY_OVERLAY_MARKER: &str = ".ratarmount.overlay.sqlite.used";

/// Copy-on-write staging files. Not the final member name: a crash mid-copy
/// leaves this prefix, which list, lookup, and commit ignore. ASCII case is
/// ignored, same as [`HIDDEN_DB`].
const COW_STAGING_PREFIX: &str = ".ratarmount.overlay.cow-";

fn has_ascii_prefix(name: &str, prefix: &str) -> bool {
    let n = name.as_bytes();
    let p = prefix.as_bytes();
    n.len() >= p.len() && n[..p.len()].eq_ignore_ascii_case(p)
}

/// Overlay bookkeeping names that never show up as overlay content.
/// ASCII case is ignored: on a case-insensitive overlay folder (macOS,
/// Windows shares) `/.RATARMOUNT.OVERLAY.SQLITE` is the real database.
fn is_overlay_internal_name(name: &str) -> bool {
    has_ascii_prefix(name, HIDDEN_DB)
        || has_ascii_prefix(name, COW_STAGING_PREFIX)
        || name.eq_ignore_ascii_case(".ratarmount-sealed")
        || name.eq_ignore_ascii_case(OVERLAY_MARKER)
}

/// Mount path with any component that is overlay bookkeeping (database, its
/// SQLite sidecars, either marker name). Hidden and immutable through the
/// mount at every depth, including anything beneath such a name, so a
/// full-path frontend (SMB, SFTP) cannot `create_dir_all` one into being.
pub fn is_overlay_internal_path(path: &str) -> bool {
    path.split('/').any(is_overlay_internal_name)
}

/// The virtual control folder served by `--control-interface`. Matches the
/// normalized path (`./`, `//`, `..` collapsed): the folder itself and
/// everything under it, at the mount root only.
pub fn is_control_reserved_path(path: &str) -> bool {
    let n = normpath(path);
    n == "/.ratarmount-control" || n.starts_with("/.ratarmount-control/")
}

fn control_name_refused(path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{path} is the reserved control folder (--control-interface)"),
    )
}

/// Refusal for a mount-side create/delete/rename/write of an internal name.
fn internal_name_refused(path: &str) -> OverlayError {
    OverlayError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{path} is reserved for the write overlay's bookkeeping"),
    ))
}

/// Every regular overlay marker present (current name first, then legacy).
/// A non-regular entry under either marker name fails closed.
fn overlay_markers(root: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut bad: Option<PathBuf> = None;
    for name in [OVERLAY_MARKER, LEGACY_OVERLAY_MARKER] {
        let p = root.join(name);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_file() => found.push(p),
            Ok(_) => {
                bad.get_or_insert(p);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(OverlayError::Io(e)),
        }
    }
    if let Some(p) = bad {
        return Err(OverlayError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("overlay marker {} is not a regular file", p.display()),
        )));
    }
    Ok(found)
}

/// The first regular overlay marker (see [`overlay_markers`]).
fn overlay_marker(root: &Path) -> Result<Option<PathBuf>> {
    Ok(overlay_markers(root)?.into_iter().next())
}

/// Reset hint appended to every #96 refusal.
fn discard_hint(paths: &[&Path]) -> String {
    let list: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
    format!(
        "; or, to discard this overlay's deletions on purpose, remove {}",
        list.join(" and ")
    )
}

/// The database path exists but is a directory (Robo-Ilya, #96 review).
fn db_is_directory_error(db_path: &Path) -> OverlayError {
    OverlayError::Msg(format!(
        "overlay database path {} is a directory, not a database file; move it aside",
        db_path.display()
    ))
}

/// Overlay-relative names with this prefix are not commit members.
const SPOOL_NAME_PREFIX: &str = ".ratarmount-spool-";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS "files" (
    "path"    VARCHAR(65535) NOT NULL,
    "name"    VARCHAR(65535) NOT NULL,
    "mtime"   REAL,
    "mode"    INTEGER,
    "uid"     INTEGER,
    "gid"     INTEGER,
    "deleted" BOOL,
    PRIMARY KEY (path, name)
);
CREATE TABLE IF NOT EXISTS overlay_metadata (
    path TEXT PRIMARY KEY,
    mode INTEGER,
    atime REAL,
    mtime REAL
);
CREATE TABLE IF NOT EXISTS xattrs (
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    value BLOB,
    PRIMARY KEY (path, name)
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

/// Optional metadata changes. Missing times mean UTIME_OMIT; frontends resolve
/// UTIME_NOW once per request. Ownership changes are refused with EPERM.
#[derive(Clone, Debug, Default)]
pub struct OverlayMetadata {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<f64>,
    pub mtime: Option<f64>,
}

impl OverlayMetadata {
    pub fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.atime.is_none()
            && self.mtime.is_none()
    }
}

/// Access time carried separately because archive FileInfo only has mtime.
pub fn overlay_atime(fi: &FileInfo) -> f64 {
    fi.userdata
        .iter()
        .find_map(|data| match data {
            UserData::Other(s) => s
                .strip_prefix("overlay-atime:")
                .and_then(|s| s.parse().ok()),
            _ => None,
        })
        .unwrap_or(fi.mtime)
}

pub(crate) fn set_info_atime(fi: &mut FileInfo, atime: f64) {
    fi.userdata
        .retain(|data| !matches!(data, UserData::Other(s) if s.starts_with("overlay-atime:")));
    let index = fi.userdata.len().saturating_sub(1);
    fi.userdata
        .insert(index, UserData::Other(format!("overlay-atime:{atime}")));
}

#[derive(Debug, Error)]
pub enum OverlayError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Msg(String),
    /// A journaled append wrote the new bytes but its journal is still
    /// pending (the baseline rows could not be updated). Never answered with
    /// a copy fallback: the archive already holds the commit.
    #[error("{0}")]
    Committed(String),
    /// A journaled append failed and its journal (old or torn bytes) is still
    /// on disk where recovery must find it. Never answered with a copy: the
    /// mount must be recovered (remounted) first.
    #[error("{0}")]
    JournalPending(String),
}

pub type Result<T> = std::result::Result<T, OverlayError>;

/// `cfg(test)` hook invoked once after `rename(2)` and before the tombstone
/// transaction. Taken on the first attempt and not restored. `Err` fails that
/// attempt only; later attempts still run.
///
/// Runs while [`WriteOverlay`]'s pending-row queue is held. Must not lock that
/// queue (lookup and the database are fine).
#[cfg(test)]
type RenameBeforeTxHook = Box<dyn FnMut() -> Result<()> + Send>;

/// `cfg(test)` hook invoked once during a pending-row replay, after the batch
/// is taken and before SQL, while the pending-row queue is held.
///
/// Must not lock that queue. `Err` fails that attempt; the batch is restored
/// in front of anything appended under the same lock.
#[cfg(test)]
type ReplayHoldHook = Box<dyn FnMut() -> Result<()> + Send>;

/// `cfg(test)` hook invoked once at the start of a direct-write retry wait,
/// while `pending_rows` is held, before the backoff sleep.
///
/// Must not lock that queue. The contender samples the lock from another
/// thread and only then continues; waiting for that contender's own
/// `files` write deadlocks, because this hook still holds the queue.
#[cfg(test)]
type DirectRetryWaitHook = Box<dyn FnMut() + Send>;

/// `cfg(test)` hook consulted when a parked open is about to run.
///
/// `Err` becomes the open result (`EMFILE` / `ENFILE`). `Ok(())` continues
/// with the real `open`. Plain [`WriteOverlay::rename`] / [`WriteOverlay::unlink`]
/// never call it.
#[cfg(test)]
type ParkOpenHook = Box<dyn FnMut() -> io::Result<()> + Send>;

/// Host inode snapshotted before [`WriteOverlay::rename_parked`] or
/// [`WriteOverlay::unlink_parked`] replaces or removes it (#88).
///
/// `fd` is set when the park open succeeded. On Linux that open is
/// `O_PATH|O_NOFOLLOW|O_CLOEXEC` (mode `000` does not block it). Elsewhere it
/// is `O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC`. Symlinks are not opened. Any
/// other open error leaves `fd` empty and keeps [`FileInfo`], including `linkname`.
pub struct Parked {
    #[cfg(unix)]
    fd: Option<std::os::unix::io::OwnedFd>,
    last_fi: FileInfo,
}

impl Parked {
    /// Attributes of the parked inode, taken before the name moved or was removed.
    pub fn file_info(&self) -> &FileInfo {
        &self.last_fi
    }

    /// Parked descriptor, when the open succeeded.
    ///
    /// `fstat` on this fd is the old inode (Linux `O_PATH` included).
    #[cfg(unix)]
    pub fn fd(&self) -> Option<&std::os::unix::io::OwnedFd> {
        self.fd.as_ref()
    }

    /// Split the snapshot into the [`FileInfo`] and the parked descriptor.
    ///
    /// FUSE stores both on the detached inode. Dropping the owned descriptor closes it.
    #[cfg(unix)]
    pub fn into_parts(self) -> (FileInfo, Option<std::os::unix::io::OwnedFd>) {
        (self.last_fi, self.fd)
    }
}

impl std::fmt::Debug for Parked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Parked");
        #[cfg(unix)]
        d.field("has_fd", &self.fd.is_some());
        #[cfg(not(unix))]
        d.field("has_fd", &false);
        d.field("mode", &self.last_fi.mode)
            .field("size", &self.last_fi.size)
            .field("linkname", &self.last_fi.linkname)
            .finish()
    }
}

/// Live overlay persist job (V-4). Interval and on-exit only.
///
/// CLI [`commit_overlay`] is the prefix-rewrite escape hatch and must **not**
/// go through this queue. F-7 S3 write-through reuses this queue via
/// [`WriteOverlay::install_remote_live_commit`]. `None` (no install) keeps
/// local rename-only persist. Direct [`WriteOverlay::commit_live`] is not the
/// remote path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitKind {
    /// Interval tick: persist overlay files idle for at least this long.
    IntervalIdle(Duration),
    /// SIGTERM/unmount: wait for an in-flight persist, then [`WriteOverlay::commit_atomic`]
    /// remaining files (no reopen).
    OnExit,
}

/// Result of [`WriteOverlay::enqueue_commit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    DidWork,
    /// A live persist is already in flight; this tick did not start another splice.
    Coalesced,
    Nothing,
    /// [`WriteOverlay::interval_disabled`] — remount required; no persist.
    Disabled,
}

/// Where an archive mutation invalidated the 0.7.x file table.
///
/// Persist stashes this on [`WriteOverlay`]; interval closures already capture
/// `Arc<WriteOverlay>` and can read it. The `commit_live` reopen callback stays
/// `FnOnce(&Path)` (K20).
#[derive(Clone, Debug)]
pub struct IndexPatchWindow {
    /// Uncompressed TAR byte offset; delete + reparse from here.
    pub window_start: u64,
    /// First zstd frame index rewritten (`None` = uncompressed TAR).
    pub from_frame: Option<usize>,
    /// `true` when GNU tar `--delete` may have shifted later members.
    pub offsets_shifted: bool,
}

/// Prefix cut from the splice that just ran.
///
/// `prefix_compressed_bytes` is [`SpliceStats::prefix_compressed_bytes`]
/// (pre-splice `frames[from_idx].compressed_offset`). Uncompressed TAR stores `0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LivePublishPlan {
    prefix_compressed_bytes: u64,
}

/// Bytes match the remote object at this ETag. Safe to splice once.
#[derive(Clone, Debug)]
struct SpoolDownloaded {
    etag: Option<String>,
    len: u64,
}

/// `persist_by_format` already replaced this file. Do not splice it again.
#[derive(Clone, Debug)]
struct SpoolSpliced {
    prefix_compressed_bytes: u64,
    etag_at_download: Option<String>,
    committed: Box<OverlayCommitPlan>,
    /// Length, full SHA-256, and edge hashes of the spool **before** `persist_by_format`.
    presplice_len: u64,
    presplice_sha256: String,
    presplice_prefix512_sha256: String,
    presplice_suffix512_sha256: String,
}

enum SpoolState {
    Downloaded(SpoolDownloaded),
    Spliced(SpoolSpliced),
}

struct SpoolHold {
    file: tempfile::NamedTempFile,
    state: SpoolState,
}

/// HEAD of the remote object before a live tick decides to splice or retry PUT.
#[derive(Clone, Debug)]
pub struct RemoteObjectHead {
    pub etag: Option<String>,
    pub len: u64,
}

/// Prefer-range download. The file must live outside the overlay directory.
pub struct RemoteDownload {
    pub file: tempfile::NamedTempFile,
    pub len: u64,
}

/// Arguments for one publish attempt (object PUT, then index). Owned so the
/// hook can run without borrowing the spool lock.
#[derive(Clone, Debug)]
pub struct RemotePublishRequest {
    pub staged: PathBuf,
    pub prefix_compressed_bytes: u64,
    pub etag_at_download: Option<String>,
    pub window: IndexPatchWindow,
    /// The object already matches this spool. Do not PUT it again.
    pub skip_object_put: bool,
    /// SHA-256, edge hashes, and length of the downloaded object before splice.
    pub presplice_len: u64,
    pub presplice_sha256: String,
    pub presplice_prefix512_sha256: String,
    pub presplice_suffix512_sha256: String,
    /// `commit_generation` sampled before this attempt's success bump.
    /// Azure block ids use it. A failed attempt does not bump, so a retry
    /// reuses the same ids.
    pub commit_generation: u64,
}

/// Publish failed before a successful object replace, or the object already
/// stands and the pointer must not be published.
#[derive(Debug)]
pub enum RemotePublishError {
    /// HTTP 412. Drop `Spliced`; the next tick downloads again.
    EtagMismatch(String),
    /// 500 / timeout, or the file table does not describe this spool and the
    /// object was not replaced. Keep `Spliced` and retry the PUT only.
    Retryable(String),
    /// The object already contains the splice. Do not PUT a pointer. The caller
    /// forgets only the stashed plan so a remount does not append it again.
    PointerRefused(String),
}

impl std::fmt::Display for RemotePublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EtagMismatch(m) | Self::Retryable(m) | Self::PointerRefused(m) => f.write_str(m),
        }
    }
}

type RemotePublishHook =
    Box<dyn FnMut(&RemotePublishRequest) -> std::result::Result<(), RemotePublishError> + Send>;
type RemoteReopenHook = Box<dyn Fn() -> Result<Arc<dyn MountSource>> + Send>;

struct RemoteLive {
    head: Box<dyn FnMut() -> Result<RemoteObjectHead> + Send>,
    download: Box<dyn FnMut() -> Result<RemoteDownload> + Send>,
    publish: RemotePublishHook,
    reopen: Option<RemoteReopenHook>,
    on_exit_extra_wait: Duration,
    /// `s3://…` or `gs://…`. Failure text uses the scheme, not a hard-coded `s3`.
    archive_url: String,
}

/// Pointer JSON from [`IndexPointer::for_blob`] after the sidecar is patched.
#[cfg(test)]
#[derive(Clone, Debug)]
struct IndexPointerPlan {
    pointer: IndexPointer,
    /// Pretty JSON plus a trailing newline.
    json: String,
}

/// Attempts for the post-rename tombstone transaction, and the same budget
/// when those rows are replayed. Transient lock or disk errors usually clear
/// on a retry. A database that is still failing keeps the rows in memory and
/// live commit refuses until they land.
const RENAME_TX_ATTEMPTS: u32 = 3;
const RENAME_TX_BACKOFF: Duration = Duration::from_millis(5);

/// One `files` change whose host effect already happened.
///
/// Lock order when these rows are applied: `pending_rows`, then `db`, then
/// `tombstones`. Replay holds `pending_rows` across take, SQL, and restore.
/// A direct writer holds it across every attempt, the backoff, and the push
/// onto the queue. Releasing it during that wait lets a newer writer commit
/// first; this retry then undoes that writer and an archive member reappears.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingFilesOp {
    /// Host rename finished: `to` present, `from` tombstoned iff `hides_from`.
    Rename {
        from: String,
        to: String,
        mode: u32,
        hides_from: bool,
        xattrs: BTreeMap<String, Vec<u8>>,
    },
    /// Host unlink or rmdir finished.
    Deleted { path: String, hides_base: bool },
    /// Host create finished (file, directory, or symlink).
    Present { path: String, mode: u32 },
    /// Open cleared `deleted` without inserting a row.
    ClearDeleted { path: String },
}

impl PendingFilesOp {
    fn is_rename(&self) -> bool {
        matches!(self, Self::Rename { .. })
    }
}

impl std::fmt::Display for PendingFilesOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rename { from, to, .. } => write!(f, "rename {from} -> {to}"),
            Self::Deleted { path, .. } => write!(f, "delete {path}"),
            Self::Present { path, .. } => write!(f, "present {path}"),
            Self::ClearDeleted { path } => write!(f, "clear tombstone {path}"),
        }
    }
}

/// Put `batch` back in front of `queued`. `batch` is the older snapshot.
fn restore_pending_front(queued: &mut Vec<PendingFilesOp>, mut batch: Vec<PendingFilesOp>) {
    if queued.is_empty() {
        *queued = batch;
        return;
    }
    batch.append(queued);
    *queued = batch;
}

/// `Strict` panics if the mutex was poisoned. `Recover` is for [`Drop`],
/// which must finish the last replay without aborting the process.
#[derive(Clone, Copy)]
enum LockPoison {
    Strict,
    Recover,
}

fn lock_mutex<'a, T>(
    mutex: &'a Mutex<T>,
    poison: LockPoison,
    what: &'static str,
) -> std::sync::MutexGuard<'a, T> {
    match poison {
        LockPoison::Recover => mutex.lock().unwrap_or_else(PoisonError::into_inner),
        LockPoison::Strict => mutex.lock().expect(what),
    }
}

/// Mutation being authorized. Rename supplies both source and destination paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayMutation {
    CopyOnWrite,
    Create,
    OpenWrite,
    Write,
    Mkdir,
    Unlink,
    Rmdir,
    Truncate,
    Symlink,
    Rename,
    Reset,
}

/// Optional authorization and accounting for overlay content.
///
/// Paths are normalized mount paths. Callbacks must not call back into the
/// overlay. Checks and accounting are serialized within this overlay.
/// `check_write` authorizes the prospective extent (including sparse growth),
/// with the current host file length, not the archive member's size. A truncate
/// checks `(offset = new_size, len = 0)`. COW reserves the final extent before
/// copying outside the policy lock; on Unix the staging file's mode, times, and
/// file fsync also run outside that lock. Accounting releases unused reservations.
///
/// Accounting counts logical host file lengths, including symlinks and COW
/// copies, but excludes directories and overlay bookkeeping. Removal releases
/// the named file's charge. Subsequent growth of unlinked open inodes remains
/// charged until their last registered overlay descriptor closes. The original
/// unlinked extent is excluded; this conservative growth accounting is not a
/// disk-block quota. Callers must close descriptors via `close_overlay_fd` or
/// `finish_owned_write_fd`, and duplicate them via `clone_overlay_fd`.
/// Initialize usage from the overlay folder before installing a policy on an
/// existing overlay. External host writes are outside this interface.
pub trait OverlayPolicy: Send + Sync {
    fn check_mutation(&self, op: OverlayMutation, paths: &[&str]) -> io::Result<()>;
    fn check_write(&self, path: &str, offset: u64, len: u64, current_size: u64) -> io::Result<()>;
    fn bytes_changed(&self, _path: &str, _added: u64, _removed: u64) {}
    fn file_created(&self, _path: &str) {}
    fn file_removed(&self, _path: &str) {}
}

// Snapshot around a host mutation, including failed/partial operations. This
// guard is only constructed with a policy; the default path does no extra stat.
struct PolicyAccounting<'a> {
    overlay: &'a WriteOverlay,
    path: String,
    before: Option<u64>,
}

impl Drop for PolicyAccounting<'_> {
    fn drop(&mut self) {
        let after = self.overlay.policy_file_size(&self.path);
        let policy = self.overlay.policy.as_ref().expect("policy accounting");
        if self.before.is_none() && after.is_some() {
            policy.file_created(&self.path);
        }
        let old = self.before.unwrap_or(0);
        let new = after.unwrap_or(0);
        if old != new {
            policy.bytes_changed(&self.path, new.saturating_sub(old), old.saturating_sub(new));
        }
        if self.before.is_some() && after.is_none() {
            policy.file_removed(&self.path);
        }
    }
}

#[cfg(unix)]
#[derive(Default)]
struct PolicyFds {
    fds: HashMap<i32, (u64, u64)>,
    growth: HashMap<(u64, u64), (String, u64)>,
}

// A COW reservation is charged before reading, then settled after publishing.
// Drop also refunds on an open/read failure or panic.
struct CowReservation<'a> {
    overlay: &'a WriteOverlay,
    path: &'a str,
    bytes: u64,
}

impl Drop for CowReservation<'_> {
    fn drop(&mut self) {
        let _policy = self.overlay.policy_lock();
        self.overlay
            .policy
            .as_ref()
            .expect("COW policy")
            .bytes_changed(self.path, 0, self.bytes);
    }
}

/// Union of a read-only base with a writable overlay folder + deletion DB.
pub struct WriteOverlay {
    policy: Option<Arc<dyn OverlayPolicy>>,
    policy_gate: Mutex<()>,
    #[cfg(unix)]
    policy_fds: Mutex<PolicyFds>,
    #[cfg(test)]
    account_reset_failure: AtomicBool,
    #[cfg(test)]
    cow_before_read_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Test-only: taken once and run from `publish_cow_staging` after staging
    /// metadata and the file fsync, before `persist_noclobber`.
    #[cfg(test)]
    cow_before_persist_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    base: Arc<dyn MountSource>,
    /// The classified base this overlay was opened with (`None` for the
    /// legacy constructors). A commit re-points it at the archive it wrote.
    identity: Mutex<Option<crate::ClassifiedBase>>,
    /// `--force-base-mismatch`: a commit over a changed base proceeds.
    force_base_mismatch: bool,
    rolling: Option<Arc<crate::RollingMountSource>>,
    /// After a live TAR commit, the reopened archive.
    replacement: RwLock<Option<Arc<dyn MountSource>>>,
    root: PathBuf,
    db: Mutex<Connection>,
    /// Mount paths with `deleted = 1` (for example `/dir/file`).
    ///
    /// `is_deleted` checks this set. The `files` table remains the durable
    /// copy; every insert or clear of a tombstone updates both.
    tombstones: Mutex<HashSet<String>>,
    /// `files` rows saved after the host change when the transaction still
    /// failed. Replayed at the start of the next `files` write, on drop, and
    /// before a commit plan is built. Live, interval, and on-exit commits
    /// refuse while this is non-empty after a replay attempt.
    ///
    /// Lock order: this queue, then [`Self::db`], then [`Self::tombstones`].
    /// Held across take / apply / restore, and across a direct write's
    /// attempts, backoff, and the push onto the queue. See [`PendingFilesOp`].
    pending_rows: Mutex<Vec<PendingFilesOp>>,
    /// Writers take a read lock; live commit takes the write lock.
    commit_gate: RwLock<()>,
    commit_mode: CommitMode,
    manifest_hashes: Option<String>,
    /// Set when persist succeeded but reopen failed (K11). Further interval
    /// ticks must not persist again (overlay still holds the committed names).
    interval_disabled: AtomicBool,
    /// Bumped after every successful commit persist. Cached FileInfos /
    /// reader handles keyed to pre-commit base offsets are invalid after a
    /// commit (delete/replace shift TAR member offsets), so read caches
    /// (NFS reader LRU, inode FileInfo) watch this counter.
    commit_generation: std::sync::atomic::AtomicU64,
    /// Overlay FDs still open for write (FUSE keeps the fd until release).
    /// Interval settle must not persist/unlink these: later pwrite would hit
    /// an unlinked inode and the extra bytes would never reach the archive.
    /// Busy matching uses `fstat` `(dev, ino)` so a rename of the open file
    /// still skips the same host inode.
    write_fds: Mutex<HashMap<i32, String>>,
    /// TAR member-name encoding (`-e`); live `.tar.zst` persist. Default utf-8.
    encoding: String,
    /// `--control-interface` is serving a virtual `/.ratarmount-control`:
    /// the name is reserved and every mutation of it is refused.
    control_reserved: bool,
    /// Last successful persist window for incremental sidecar patch (F-2).
    last_patch_window: Mutex<Option<IndexPatchWindow>>,
    /// Live commit coordinator (V-4). Separate from `commit_gate` (writers vs
    /// persist). Interval/on-exit set this before `commit_live_inner`.
    commit_inflight: AtomicBool,
    commit_wait: Mutex<()>,
    commit_cv: Condvar,
    last_persist_duration: Mutex<Duration>,
    /// Floor for on-exit wait (`ON_EXIT_WAIT_MIN` unless a test shortens it).
    on_exit_wait_min: Mutex<Duration>,
    /// Test-only: sleep after taking the inflight flag (injected long persist).
    persist_delay: Mutex<Option<Duration>>,
    /// Prefix from the splice that just ran (`0` for uncompressed TAR).
    last_publish_plan: Mutex<Option<LivePublishPlan>>,
    /// F-7 live queue. `None` keeps local rename and the unbounded on-exit wait.
    remote: Mutex<Option<RemoteLive>>,
    /// Downloaded or spliced spool. Not in the overlay directory.
    spool: Mutex<Option<SpoolHold>>,
    /// Times [`Self::persist_by_format`] ran (tests assert a `Spliced` retry skips it).
    persist_count: AtomicU64,
    /// Set for the duration of remote on-exit so the interval thread cannot start
    /// another PUT while on-exit is waiting.
    interval_suppressed: AtomicBool,
    /// Test-only: after the host rename, before one tombstone attempt (#88).
    /// `Err` fails that attempt. Later attempts still run. The rename returns
    /// success either way, and the in-memory tombstones match the completed
    /// rename. One-shot: taken on the first attempt and not restored.
    #[cfg(test)]
    rename_before_tx_hook: Mutex<Option<RenameBeforeTxHook>>,
    /// Test-only: fail the next N `files` writes inside
    /// [`apply_pending_ops_sql`], including direct retries and pending-row
    /// replays. `0` means the fault is off. The one-shot before-tx hook does
    /// not consume a count.
    #[cfg(test)]
    rename_tx_fail_remaining: AtomicU64,
    /// Test-only: one-shot hook inside replay, while `pending_rows` is held.
    #[cfg(test)]
    replay_hold_hook: Mutex<Option<ReplayHoldHook>>,
    /// Test-only: one-shot hook while a direct writer waits to retry, still
    /// holding `pending_rows`.
    #[cfg(test)]
    direct_retry_wait_hook: Mutex<Option<DirectRetryWaitHook>>,
    /// Test-only: injected park-open result. Stays installed until replaced.
    /// Plain `rename` / `unlink` never consult it.
    #[cfg(test)]
    park_open_hook: Mutex<Option<ParkOpenHook>>,
    /// Times a parked open was attempted (injected or real). Plain rename and
    /// unlink leave this at 0.
    #[cfg(test)]
    park_open_count: AtomicU64,
}

impl OverlayError {
    fn sqlite_code(&self) -> Option<rusqlite::ErrorCode> {
        match self {
            OverlayError::Sqlite(rusqlite::Error::SqliteFailure(f, _)) => Some(f.code),
            _ => None,
        }
    }

    /// SQLITE_BUSY / SQLITE_LOCKED: another process holds the overlay database.
    pub fn is_locked(&self) -> bool {
        matches!(
            self.sqlite_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        )
    }

    /// SQLITE_READONLY / SQLITE_CANTOPEN / SQLITE_PERM: an access problem,
    /// not a corrupt database.
    pub fn is_access_error(&self) -> bool {
        matches!(
            self.sqlite_code(),
            Some(
                rusqlite::ErrorCode::ReadOnly
                    | rusqlite::ErrorCode::CannotOpen
                    | rusqlite::ErrorCode::PermissionDenied
            )
        )
    }
}

impl WriteOverlay {
    /// Install before sharing the overlay with frontends. `None` disables hooks.
    pub fn set_policy(&mut self, policy: Option<Arc<dyn OverlayPolicy>>) {
        self.policy = policy;
    }

    fn policy_lock(&self) -> Option<std::sync::MutexGuard<'_, ()>> {
        self.policy
            .as_ref()
            .map(|_| self.policy_gate.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Reserved control name (only while the control folder is served).
    fn is_control_path(&self, path: &str) -> bool {
        self.control_reserved && is_control_reserved_path(path)
    }

    fn refuse_control_path(&self, path: &str) -> io::Result<()> {
        if self.is_control_path(path) {
            return Err(control_name_refused(path));
        }
        Ok(())
    }

    fn check_mutation(&self, op: OverlayMutation, paths: &[&str]) -> io::Result<()> {
        for p in paths {
            self.refuse_control_path(p)?;
        }
        if let Some(policy) = &self.policy {
            let paths: Vec<String> = paths.iter().map(|p| normpath(p)).collect();
            let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
            policy.check_mutation(op, &refs)?;
        }
        Ok(())
    }

    fn policy_file_size(&self, path: &str) -> Option<u64> {
        fs::symlink_metadata(self.realpath(path))
            .ok()
            .filter(|m| !m.is_dir())
            .map(|m| m.len())
    }

    fn account_path(&self, path: &str) -> Option<PolicyAccounting<'_>> {
        self.policy.as_ref().map(|_| PolicyAccounting {
            overlay: self,
            path: normpath(path),
            before: self.policy_file_size(path),
        })
    }

    /// Write bytes through the policy to a borrowed overlay file (never closes it).
    /// The file may refer to an inode detached by rename/unlink. Callers retain
    /// ownership and the write-open pin until their normal release path.
    #[cfg(unix)]
    pub fn write_at(&self, file: &File, path: &str, offset: u64, buf: &[u8]) -> io::Result<usize> {
        let _gate = self
            .policy
            .as_ref()
            .map(|_| self.commit_gate.read().expect("overlay commit gate"));
        let _policy = self.policy_lock();
        self.write_at_inner(file, path, offset, buf)
    }

    #[cfg(unix)]
    fn write_at_inner(
        &self,
        file: &File,
        path: &str,
        offset: u64,
        buf: &[u8],
    ) -> io::Result<usize> {
        use std::os::unix::fs::{FileExt, MetadataExt};
        if is_overlay_internal_path(path) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "overlay internal path",
            ));
        }
        self.check_mutation(OverlayMutation::Write, &[path])?;
        let before = if let Some(policy) = &self.policy {
            use std::os::fd::AsRawFd;
            let meta = file.metadata()?;
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            // Linux pwrite honors O_APPEND despite the positional offset.
            let effective_offset = if cfg!(target_os = "linux") && flags & libc::O_APPEND != 0 {
                meta.len()
            } else {
                offset
            };
            policy.check_write(
                &normpath(path),
                effective_offset,
                buf.len() as u64,
                meta.len(),
            )?;
            Some((meta, effective_offset))
        } else {
            None
        };
        let written = file.write_at(buf, offset)?;
        if let (Some(policy), Some((before, effective_offset))) = (&self.policy, before) {
            let added = if written == 0 {
                0
            } else {
                effective_offset
                    .saturating_add(written as u64)
                    .saturating_sub(before.len())
            };
            if before.nlink() == 0 {
                self.account_orphan(&before, path, added, 0);
            } else if added != 0 {
                policy.bytes_changed(&normpath(path), added, 0);
            }
        }
        Ok(written)
    }

    /// Fill a positional write, preserving short-write and EINTR semantics.
    #[cfg(unix)]
    pub fn write_all_at(
        &self,
        file: &File,
        path: &str,
        mut offset: u64,
        mut buf: &[u8],
    ) -> io::Result<()> {
        while !buf.is_empty() {
            match self.write_at(file, path, offset, buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "overlay write returned zero",
                    ))
                }
                Ok(n) => {
                    offset = offset.checked_add(n as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "overlay write offset overflow")
                    })?;
                    buf = &buf[n..];
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Truncate an already-open inode, including a detached FUSE writer.
    pub fn truncate_file(&self, file: &File, path: &str, size: u64) -> io::Result<()> {
        let _gate = self
            .policy
            .as_ref()
            .map(|_| self.commit_gate.read().expect("overlay commit gate"));
        let _policy = self.policy_lock();
        self.truncate_file_inner(file, path, size)
    }

    fn truncate_file_inner(&self, file: &File, path: &str, size: u64) -> io::Result<()> {
        if is_overlay_internal_path(path) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "overlay internal path",
            ));
        }
        self.check_mutation(OverlayMutation::Truncate, &[path])?;
        let before = if let Some(policy) = &self.policy {
            let meta = file.metadata()?;
            policy.check_write(&normpath(path), size, 0, meta.len())?;
            Some(meta)
        } else {
            None
        };
        file.set_len(size)?;
        if let (Some(policy), Some(before)) = (&self.policy, before) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if before.nlink() == 0 {
                    self.account_orphan(
                        &before,
                        path,
                        size.saturating_sub(before.len()),
                        before.len().saturating_sub(size),
                    );
                    return Ok(());
                }
            }
            policy.bytes_changed(
                &normpath(path),
                size.saturating_sub(before.len()),
                before.len().saturating_sub(size),
            );
        }
        Ok(())
    }

    /// In-crate tests only: an overlay that records no base at all. A real
    /// overlay is opened with [`Self::open`] over a classified base.
    #[cfg(test)]
    pub(crate) fn new_for_tests(
        base: Arc<dyn MountSource>,
        overlay: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::open_with_create_info(base, overlay.as_ref(), None, None)
    }

    /// Open (or create) the overlay over a classified base. `composed` is the
    /// view that is served (lower layers over `base.source()`); the token is
    /// what was opened and is compared with what the overlay recorded.
    pub fn open(
        base: &crate::ClassifiedBase,
        composed: Arc<dyn MountSource>,
        overlay: impl AsRef<Path>,
        options: &crate::CreateOptions,
    ) -> Result<Self> {
        let info = base.actual().create_info(options);
        Self::open_with_create_info(composed, overlay.as_ref(), Some(&info), Some(base))
    }

    /// In-crate tests only: open with a hand-built creation record.
    #[cfg(test)]
    pub(crate) fn new_with_create_info_for_tests(
        base: Arc<dyn MountSource>,
        overlay: impl AsRef<Path>,
        info: &crate::overlay_meta::OverlayCreateInfo,
    ) -> Result<Self> {
        Self::open_with_create_info(base, overlay.as_ref(), Some(info), None)
    }

    fn open_with_create_info(
        base: Arc<dyn MountSource>,
        overlay: &Path,
        info: Option<&crate::overlay_meta::OverlayCreateInfo>,
        identity: Option<&crate::ClassifiedBase>,
    ) -> Result<Self> {
        // Before the directory is created: the topmost-new exclusion rule
        // depends on which parents of the overlay exist right now.
        let exclude_plan = info
            .map(|info| crate::overlay_meta::plan_excludes(info, overlay))
            .transpose()?
            .flatten();
        let root = overlay.to_path_buf();
        if root.exists() {
            if !root.is_dir() {
                return Err(OverlayError::Msg(format!(
                    "overlay path must be a folder: {}",
                    root.display()
                )));
            }
        } else {
            fs::create_dir_all(&root)?;
        }
        // Canonical root so confinement checks use a stable absolute prefix.
        let root = root.canonicalize().map_err(OverlayError::Io)?;
        let db_path = root.join(HIDDEN_DB);
        let found_marker = overlay_marker(&root)?;
        let marker = found_marker.is_some();
        let marker_path = found_marker.unwrap_or_else(|| root.join(OVERLAY_MARKER));
        // Follows a symlinked database exactly like `Connection::open` does.
        let db_len = match fs::metadata(&db_path) {
            Ok(m) if m.is_dir() => return Err(db_is_directory_error(&db_path)),
            Ok(m) => Some(m.len()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(OverlayError::Io(e)),
        };
        if marker && db_len.unwrap_or(0) == 0 {
            return Err(OverlayError::Msg(format!(
                "write overlay {} was used before but its database {} is missing or empty; \
                 its deletions would be lost (unlinked archive members reappear). \
                 Restore the database, or use a new empty folder{}",
                root.display(),
                db_path.display(),
                discard_hint(
                    &overlay_markers(&root)?
                        .iter()
                        .map(|p| p.as_path())
                        .collect::<Vec<_>>()
                )
            )));
        }
        let mut conn = Connection::open(&db_path)?;
        let had_files = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'files'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !had_files && (marker || db_len.is_some_and(|n| n > 0)) {
            drop(conn);
            return Err(OverlayError::Msg(format!(
                "overlay database {} has no files table; its deletions would be lost \
                 (unlinked archive members reappear). Restore it, or use a new empty folder{}",
                db_path.display(),
                // Removing only the marker would still leave a non-empty,
                // table-less database that is refused.
                discard_hint(
                    &overlay_markers(&root)?
                        .iter()
                        .map(|p| p.as_path())
                        .chain([db_path.as_path()])
                        .collect::<Vec<_>>()
                )
            )));
        }
        // Marker before SCHEMA: a brand-new overlay whose marker cannot be
        // written must not leave a `files` table behind (the next open would
        // take the backfill path and run unmarked).
        // Remove a database file this call created, so a failed first open
        // leaves the folder as it was (not "non-empty DB without files").
        let undo_new_db = |conn: Connection| {
            drop(conn);
            match db_len {
                None => {
                    for suf in ["", "-journal", "-shm", "-wal"] {
                        let _ = fs::remove_file(root.join(format!("{HIDDEN_DB}{suf}")));
                    }
                }
                // It was 0 bytes: put it back that way.
                Some(0) => {
                    let _ = fs::OpenOptions::new()
                        .write(true)
                        .open(&db_path)
                        .and_then(|f| f.set_len(0));
                }
                Some(_) => {}
            }
        };
        // A legacy-named marker is migrated: `rm .ratarmount.overlay.sqlite*`
        // deletes the old name together with the database.
        let new_marker_path = root.join(OVERLAY_MARKER);
        let mut created_marker = false;
        if marker && marker_path != new_marker_path {
            if let Err(e) = create_overlay_marker(&new_marker_path) {
                log::warn!(
                    "could not create overlay marker {}: {e}",
                    new_marker_path.display()
                );
            }
        }
        if !marker {
            match create_overlay_marker(&marker_path) {
                Ok(created) => created_marker = created,
                Err(e) if had_files => log::warn!(
                    "could not create overlay marker {}: {e}",
                    marker_path.display()
                ),
                Err(e) => {
                    undo_new_db(conn);
                    return Err(OverlayError::Io(e));
                }
            }
        }
        let opened = (|| -> Result<HashSet<String>> {
            conn.execute_batch("PRAGMA LOCKING_MODE = EXCLUSIVE;")?;
            let transaction = conn.transaction()?;
            transaction.execute_batch(SCHEMA)?;
            if crate::OverlayMeta::from_connection(&transaction)?
                .as_ref()
                .is_some_and(crate::OverlayMeta::layer_sealed)
            {
                return Err(OverlayError::Msg(
                    "overlay is sealed; mount it with --lower, or `overlay unseal`".into(),
                ));
            }
            crate::overlay_meta::initialize(
                &transaction,
                had_files,
                info,
                exclude_plan.as_ref(),
                identity,
            )?;
            let tombstones = tombstone_set_from_conn(&transaction)?;
            transaction.commit()?;
            Ok(tombstones)
        })();
        let mut tombstones = match opened {
            Ok(t) => t,
            Err(e) => {
                // A folder that never opened successfully must not stay marked
                // (it would then be refused as "used").
                if created_marker && !had_files {
                    let _ = fs::remove_file(&marker_path);
                }
                if !had_files {
                    undo_new_db(conn);
                }
                return Err(e);
            }
        };
        // #88: a crash between host rename/create and the tombstone clear leaves
        // the new bytes under a deleted=1 name. Clear those rows. A tombstone
        // with no host file stays. Do not delete the host file.
        if let Err(e) = clear_tombstones_with_host_files(&mut conn, &root, &mut tombstones) {
            if created_marker && !had_files {
                let _ = fs::remove_file(&marker_path);
            }
            if !had_files {
                undo_new_db(conn);
            }
            return Err(e);
        }
        // Once the current marker is in place the legacy one is redundant;
        // removing it keeps a reset to one file (also cleans folders that an
        // earlier build migrated but left both names in).
        // The folder is fsynced first so a crash cannot leave neither marker;
        // skipped when there is no legacy marker to remove.
        let legacy_present = fs::symlink_metadata(root.join(LEGACY_OVERLAY_MARKER)).is_ok();
        let marker_durable = legacy_present
            && fs::symlink_metadata(&new_marker_path).is_ok_and(|m| m.file_type().is_file())
            && match fs::File::open(&root).and_then(|d| d.sync_all()) {
                Ok(()) => true,
                Err(e) => {
                    log::warn!(
                        "could not sync overlay folder {}; keeping legacy marker: {e}",
                        root.display()
                    );
                    false
                }
            };
        if marker_durable {
            let legacy = root.join(LEGACY_OVERLAY_MARKER);
            if let Err(e) = fs::remove_file(&legacy) {
                if e.kind() != io::ErrorKind::NotFound {
                    log::warn!(
                        "could not remove legacy overlay marker {}: {e}",
                        legacy.display()
                    );
                }
            }
        }
        // LOCKING_MODE=EXCLUSIVE keeps only a shared lock until the first
        // write. Schema creation is that write on a new folder, but a later
        // open does not write, so the sweep would otherwise run under a
        // shared lock and a second open could delete this process's staging
        // file. COMMIT does not drop the lock while locking mode is exclusive.
        // A failed open above returns before this, including SQLITE_BUSY.
        conn.execute_batch("BEGIN EXCLUSIVE; COMMIT;")?;
        // Best-effort. An unreadable directory must not fail the open.
        sweep_cow_staging(&root);
        Ok(Self {
            policy: None,
            policy_gate: Mutex::new(()),
            #[cfg(unix)]
            policy_fds: Mutex::new(PolicyFds::default()),
            #[cfg(test)]
            account_reset_failure: AtomicBool::new(false),
            #[cfg(test)]
            cow_before_read_hook: Mutex::new(None),
            #[cfg(test)]
            cow_before_persist_hook: Mutex::new(None),
            base,
            identity: Mutex::new(identity.cloned()),
            force_base_mismatch: info.is_some_and(|info| info.force_base_mismatch),
            rolling: None,
            replacement: RwLock::new(None),
            root,
            db: Mutex::new(conn),
            tombstones: Mutex::new(tombstones),
            pending_rows: Mutex::new(Vec::new()),
            commit_gate: RwLock::new(()),
            interval_disabled: AtomicBool::new(false),
            commit_generation: std::sync::atomic::AtomicU64::new(0),
            write_fds: Mutex::new(HashMap::new()),
            encoding: "utf-8".into(),
            control_reserved: false,
            last_patch_window: Mutex::new(None),
            commit_mode: CommitMode::Copy,
            manifest_hashes: None,
            commit_inflight: AtomicBool::new(false),
            commit_wait: Mutex::new(()),
            commit_cv: Condvar::new(),
            last_persist_duration: Mutex::new(Duration::ZERO),
            on_exit_wait_min: Mutex::new(ON_EXIT_WAIT_MIN),
            persist_delay: Mutex::new(None),
            last_publish_plan: Mutex::new(None),
            remote: Mutex::new(None),
            spool: Mutex::new(None),
            persist_count: AtomicU64::new(0),
            interval_suppressed: AtomicBool::new(false),
            #[cfg(test)]
            rename_before_tx_hook: Mutex::new(None),
            #[cfg(test)]
            rename_tx_fail_remaining: AtomicU64::new(0),
            #[cfg(test)]
            replay_hold_hook: Mutex::new(None),
            #[cfg(test)]
            direct_retry_wait_hook: Mutex::new(None),
            #[cfg(test)]
            park_open_hook: Mutex::new(None),
            #[cfg(test)]
            park_open_count: AtomicU64::new(0),
        })
    }

    /// Install the F-7 publish hook. Local commits leave this unset.
    ///
    /// `on_exit_extra_wait` bounds the remote on-exit wait after the 2× floor
    /// (object-store I/O timeout, 120s). Direct [`Self::commit_live`] does not
    /// call the hook.
    pub fn install_remote_live_commit(
        &self,
        head: Box<dyn FnMut() -> Result<RemoteObjectHead> + Send>,
        download: Box<dyn FnMut() -> Result<RemoteDownload> + Send>,
        publish: RemotePublishHook,
        on_exit_extra_wait: Duration,
    ) {
        self.install_remote_live_commit_for("s3://", head, download, publish, on_exit_extra_wait);
    }

    /// Same as [`Self::install_remote_live_commit`], with the archive URL used
    /// in publish errors (`gs publish failed`, not `s3 publish failed`).
    pub fn install_remote_live_commit_for(
        &self,
        archive_url: &str,
        head: Box<dyn FnMut() -> Result<RemoteObjectHead> + Send>,
        download: Box<dyn FnMut() -> Result<RemoteDownload> + Send>,
        publish: RemotePublishHook,
        on_exit_extra_wait: Duration,
    ) {
        *self.remote.lock().expect("overlay remote") = Some(RemoteLive {
            head,
            download,
            publish,
            reopen: None,
            on_exit_extra_wait,
            archive_url: archive_url.to_string(),
        });
    }

    /// Reopen at the exact identity returned by an atomic remote publication.
    pub fn install_remote_reopen(&self, reopen: RemoteReopenHook) {
        if let Some(remote) = self.remote.lock().expect("overlay remote").as_mut() {
            remote.reopen = Some(reopen);
        }
    }

    /// Invoke the installed callback after publication, before forgetting committed overlay files.
    pub fn reopen_remote_live_commit(&self) -> Result<Arc<dyn MountSource>> {
        self.with_remote_mut(|remote| match &remote.reopen {
            Some(reopen) => reopen(),
            None => Err(OverlayError::Msg("remote reopen is not installed".into())),
        })?
    }

    fn remote_scheme_label(&self) -> String {
        let guard = self.remote.lock().expect("overlay remote");
        let url = guard
            .as_ref()
            .map(|r| r.archive_url.as_str())
            .unwrap_or("s3://");
        url.split("://")
            .next()
            .filter(|s| !s.is_empty() && !s.contains('/'))
            .unwrap_or("s3")
            .to_string()
    }

    fn remote_enabled(&self) -> bool {
        self.remote.lock().expect("overlay remote").is_some()
    }

    fn remote_on_exit_extra(&self) -> Option<Duration> {
        self.remote
            .lock()
            .expect("overlay remote")
            .as_ref()
            .map(|r| r.on_exit_extra_wait)
    }

    /// Successful live commits (not counting a base source's own generation).
    pub fn commit_generation(&self) -> u64 {
        self.commit_generation.load(Ordering::SeqCst)
    }

    /// How many times [`Self::persist_by_format`] has run.
    #[doc(hidden)]
    pub fn persist_count_for_test(&self) -> u64 {
        self.persist_count.load(Ordering::SeqCst)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Mount `-e` / `--encoding` for live `.tar.zst` persist (ustar/PAX names).
    /// Defaults to `"utf-8"` inside [`Self::new`]; fuse/nfs tests need not call this.
    pub fn set_encoding(&mut self, encoding: &str) {
        self.encoding = encoding.to_string();
    }

    /// Reserve `/.ratarmount-control` (call when the virtual control folder is
    /// mounted, before sharing the overlay). Off: the name is ordinary.
    pub fn set_control_reserved(&mut self, on: bool) {
        self.control_reserved = on;
    }

    /// True after persist-ok + reopen-err; further interval ticks must remount.
    pub fn interval_disabled(&self) -> bool {
        self.interval_disabled.load(Ordering::SeqCst)
    }

    /// Uncompressed rewrite window from the last successful persist (F-2).
    pub fn last_patch_window(&self) -> Option<IndexPatchWindow> {
        self.last_patch_window
            .lock()
            .expect("overlay patch window")
            .clone()
    }

    fn stash_patch_window(&self, window: IndexPatchWindow) {
        *self.last_patch_window.lock().expect("overlay patch window") = Some(window);
    }

    /// Prefix recorded by the last successful live persist.
    fn last_publish_plan(&self) -> Option<LivePublishPlan> {
        *self.last_publish_plan.lock().expect("overlay publish plan")
    }

    fn stash_publish_plan(&self, plan: LivePublishPlan) {
        *self.last_publish_plan.lock().expect("overlay publish plan") = Some(plan);
    }

    fn current_base(&self) -> Arc<dyn MountSource> {
        self.replacement
            .read()
            .expect("overlay replacement")
            .clone()
            .unwrap_or_else(|| Arc::clone(&self.base))
    }

    /// Swap the archive view after a successful live commit (interval).
    pub fn replace_base(&self, new_base: Arc<dyn MountSource>) {
        *self.replacement.write().expect("overlay replacement") = Some(new_base);
    }

    fn realpath(&self, path: &str) -> PathBuf {
        let path = normpath(path);
        if path == "/" {
            return self.root.clone();
        }
        self.root.join(path.trim_start_matches('/'))
    }

    /// Ensure a host path under the overlay cannot escape the overlay root via
    /// intermediate or final-component symlinks (`libc::open` follows by default).
    ///
    /// - Final component that is a symlink → PermissionDenied (O_NOFOLLOW policy).
    /// - Resolved parent/path must stay under the canonical overlay root.
    fn ensure_under_root(&self, host_path: &Path) -> io::Result<()> {
        ensure_overlay_under_root(&self.root, host_path)
    }

    fn split(path: &str) -> (String, String) {
        let path = normpath(path);
        if path == "/" {
            return (String::new(), String::new());
        }
        match path.rsplit_once('/') {
            Some(("", name)) => (String::new(), name.to_string()),
            Some((dir, name)) => (dir.to_string(), name.to_string()),
            None => (String::new(), path),
        }
    }

    pub fn is_deleted(&self, path: &str) -> bool {
        let path = normpath(path);
        if path == "/" {
            return false;
        }
        self.tombstones
            .lock()
            .expect("overlay tombstones")
            .contains(&path)
    }

    pub fn list_deleted(&self, path: &str) -> Vec<String> {
        let path = normpath(path);
        let folder = path.trim_end_matches('/');
        let folder = if folder.is_empty() || folder == "/" {
            ""
        } else {
            folder
        };
        let mut out = Vec::new();
        {
            let set = self.tombstones.lock().expect("overlay tombstones");
            for full in set.iter() {
                if tombstone_parent(full) == folder {
                    out.push(tombstone_name(full).to_string());
                }
            }
        }
        // Hide overlay DB and SQLite sidecars
        for suf in ["", "-journal", "-shm", "-wal", ".used"] {
            out.push(format!("{HIDDEN_DB}{suf}"));
        }
        out.push(OVERLAY_MARKER.to_string());
        out
    }

    fn tombstone_remember(&self, path: &str) {
        self.tombstones
            .lock()
            .expect("overlay tombstones")
            .insert(normpath(path));
    }

    fn tombstone_forget(&self, path: &str) {
        self.tombstones
            .lock()
            .expect("overlay tombstones")
            .remove(&normpath(path));
    }

    fn tombstone_forget_many(&self, paths: &[String]) {
        let mut set = self.tombstones.lock().expect("overlay tombstones");
        for path in paths {
            set.remove(&normpath(path));
        }
    }

    fn tombstone_clear(&self) {
        self.tombstones.lock().expect("overlay tombstones").clear();
    }

    fn mark_deleted(&self, path: &str) -> Result<()> {
        let hides_base = self.current_base().exists(path);
        let path = normpath(path);
        // The host entry is already gone. Queue instead of returning an error
        // when older rows are still unsaved or this write fails.
        self.persist_files_op(PendingFilesOp::Deleted {
            path: path.clone(),
            hides_base,
        })?;
        if hides_base {
            self.tombstone_remember(&path);
        } else {
            self.tombstone_forget(&path);
        }
        Ok(())
    }

    fn mark_present(&self, path: &str, mode: u32) -> Result<()> {
        let path = normpath(path);
        self.persist_files_op(PendingFilesOp::Present {
            path: path.clone(),
            mode,
        })?;
        self.tombstone_forget(&path);
        Ok(())
    }

    fn ensure_parent(&self, path: &str) -> Result<()> {
        let (parent, _) = Self::split(path);
        if parent.is_empty() || parent == "/" {
            return Ok(());
        }
        let real_parent = self.realpath(&parent);
        self.ensure_under_root(&real_parent)?;
        if !real_parent.exists() && self.current_base().is_dir(&parent) {
            fs::create_dir_all(&real_parent)?;
        }
        Ok(())
    }

    /// Copy base file into overlay (COW) if not already present.
    pub fn ensure_modifiable(&self, path: &str) -> Result<()> {
        let _gate = self
            .policy
            .as_ref()
            .map(|_| self.commit_gate.read().expect("overlay commit gate"));
        self.ensure_modifiable_inner(path, None)
    }

    fn remember_base_xattrs(
        &self,
        path: &str,
        base: &dyn MountSource,
        fi: &FileInfo,
    ) -> Result<()> {
        let attrs = source_xattrs(base, fi);
        if !attrs.is_empty() {
            let db = self.db.lock().expect("overlay db");
            let reset: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM xattrs WHERE path=?1 AND name='')",
                [normpath(path)],
                |r| r.get(0),
            )?;
            if !reset {
                for (name, value) in attrs {
                    db.execute(
                        "INSERT OR IGNORE INTO xattrs(path,name,value) VALUES (?1,?2,?3)",
                        params![normpath(path), name, value],
                    )?;
                }
            }
        }
        Ok(())
    }

    fn ensure_modifiable_inner(&self, path: &str, size: Option<u64>) -> Result<()> {
        if self.policy.is_some() {
            return self.copy_with_reservation(path, size);
        }
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        // Use symlink_metadata so a planted escape symlink is not treated as "present".
        if fs::symlink_metadata(&real).is_ok() {
            // Existing entry must stay under root (final symlink already rejected).
            return Ok(());
        }
        self.check_mutation(OverlayMutation::CopyOnWrite, &[path])?;
        self.ensure_parent(path)?;
        let Some(mut fi) = self.current_base().lookup(path, 0) else {
            // New file: just ensure parent
            return Ok(());
        };
        self.apply_metadata(path, &mut fi);
        self.remember_base_xattrs(path, self.current_base().as_ref(), &fi)?;
        if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            fs::create_dir_all(&real)?;
            set_host_metadata(&real, &metadata_from_info(&fi))?;
            return Ok(());
        }
        if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK {
            let _account = self.account_path(path);
            // COW a symlink as a symlink: archive symlinks carry no content,
            // so copying the body would materialize an empty regular file and
            // a later commit would drop the link member entirely.
            if let Some(parent) = real.parent() {
                fs::create_dir_all(parent)?;
            }
            overlay_symlink(Path::new(&fi.linkname), &real)?;
            set_host_metadata(
                &real,
                &OverlayMetadata {
                    mode: None,
                    ..metadata_from_info(&fi)
                },
            )?;
            return Ok(());
        }
        let mut src = self.current_base().open(&without_overlay_meta(&fi), 0)?;
        let parent = real
            .parent()
            .ok_or_else(|| io::Error::other("copy-on-write target has no parent directory"))?;
        let mut dst = create_cow_staging(parent)?;
        // This path ignores the truncate hint. `O_TRUNC` and `truncate` copy
        // the whole member, then the caller shortens the published file.
        // Expected length is the archive `FileInfo` size, so a real empty
        // member (size 0) still publishes. Symlinks and directories return
        // above and never reach this copy.
        let copied = io::copy(&mut src, &mut dst)?;
        if copied != fi.size {
            drop(dst);
            return Err(cow_length_mismatch(copied, fi.size).into());
        }
        publish_cow_staging(
            dst,
            &real,
            Some(&metadata_from_info(&fi)),
            take_cow_before_persist(self),
            |_| Ok(()),
        )?;
        Ok(())
    }

    fn copy_with_reservation(&self, path: &str, truncate: Option<u64>) -> Result<()> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        let path = normpath(path);
        let real = self.realpath(&path);
        let policy = self.policy.as_ref().expect("COW policy");
        let base = self.current_base();
        let (fi, mut reservation) = {
            let _policy = self.policy_lock();
            self.ensure_under_root(&real)?;
            if fs::symlink_metadata(&real).is_ok() {
                return Ok(());
            }
            self.check_mutation(OverlayMutation::CopyOnWrite, &[&path])?;
            self.ensure_parent(&path)?;
            let Some(mut fi) = base.lookup(&path, 0) else {
                return Ok(());
            };
            self.apply_metadata(&path, &mut fi);
            self.remember_base_xattrs(&path, base.as_ref(), &fi)?;
            if ratarmount_core::is_dir_mode(fi.mode) {
                fs::create_dir_all(&real)?;
                set_host_metadata(&real, &metadata_from_info(&fi))?;
                return Ok(());
            }
            if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK {
                policy.check_write(&path, 0, fi.linkname.len() as u64, 0)?;
                let _account = self.account_path(&path);
                overlay_symlink(Path::new(&fi.linkname), &real)?;
                set_host_metadata(
                    &real,
                    &OverlayMetadata {
                        mode: None,
                        ..metadata_from_info(&fi)
                    },
                )?;
                return Ok(());
            }
            self.check_mutation(OverlayMutation::Write, &[&path])?;
            let bytes = truncate.unwrap_or(fi.size);
            policy.check_write(&path, 0, bytes, 0)?;
            policy.bytes_changed(&path, bytes, 0);
            (
                fi,
                CowReservation {
                    overlay: self,
                    path: &path,
                    bytes,
                },
            )
        };
        // Hidden staging keeps other writers from observing a partial copy.
        // No policy lock is held during archive open/decompression, host copy,
        // or (on Unix) staging-fd metadata and the file fsync.
        // `take(limit)` stops a truncate hint early. The read must yield
        // `min(member size, limit)` before publish: a shorter hint copies
        // that prefix, a longer hint still needs the whole member before
        // `set_len` extends it, and `O_TRUNC` (`limit == 0`) copies nothing.
        // Compare bytes read, not the length after `set_len`.
        let limit = truncate.unwrap_or(u64::MAX);
        let expected = fi.size.min(limit);
        let mut src = if limit == 0 {
            None
        } else {
            #[cfg(test)]
            {
                let hook = self.cow_before_read_hook.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            Some(base.open(&without_overlay_meta(&fi), 0)?.take(limit))
        };
        let parent = real
            .parent()
            .ok_or_else(|| io::Error::other("copy-on-write target has no parent directory"))?;
        let mut dst = create_cow_staging(parent)?;
        let copied: io::Result<()> = (|| {
            let mut offset = 0u64;
            if let Some(src) = &mut src {
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = match src.read(&mut buf) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        other => other?,
                    };
                    if n == 0 {
                        break;
                    }
                    let end = offset + n as u64;
                    if end > reservation.bytes {
                        let _policy = self.policy_lock();
                        policy.check_write(&path, 0, end, reservation.bytes)?;
                        policy.bytes_changed(&path, end - reservation.bytes, 0);
                        reservation.bytes = end;
                    }
                    dst.write_all(&buf[..n])?;
                    offset = end;
                }
            }
            if offset != expected {
                return Err(cow_length_mismatch(offset, expected));
            }
            if let Some(size) = truncate {
                dst.as_file().set_len(size)?;
            }
            Ok(())
        })();
        // A short or failed copy must not be renamed into place. Leave
        // `reservation.bytes` charged, including any in-loop top-up, so Drop
        // refunds it. Drop of `dst` removes the staging file.
        copied.map_err(OverlayError::Io)?;
        let actual = dst.as_file().metadata()?.len();
        let attrs = metadata_from_info(&fi);
        // Fd metadata and the file fsync do not publish the final name and do
        // not change quota counters. They use the open staging descriptor, so
        // a concurrent path rename cannot retarget them, and they stay outside
        // the second lock. Path metadata is not applied again on this Unix
        // path. Settlement, persist, and the parent fsync stay inside the lock
        // below. `_policy` is declared after `reservation` so it drops first:
        // Drop of the reservation takes the same lock.
        #[cfg(unix)]
        {
            set_host_metadata_file(dst.as_file(), &attrs)?;
            dst.as_file().sync_all()?;
        }
        let _policy = self.policy_lock();
        self.ensure_under_root(&real)?;
        // Take the test hook only after ensure succeeds, so a rejected path
        // leaves the one-shot hook in place. It still runs inside publish,
        // after this check and before `persist_noclobber`.
        let before_persist = take_cow_before_persist(self);
        publish_cow_staging(
            dst,
            &real,
            #[cfg(unix)]
            None,
            #[cfg(not(unix))]
            Some(&attrs),
            before_persist,
            |_| {
                // Settle to the published length. A short read never reaches here.
                // Zero `bytes` before `file_created` so Drop cannot refund a file
                // that already exists. `AlreadyExists` and any other persist
                // error skip this closure and Drop refunds the whole charge.
                policy.bytes_changed(&path, 0, reservation.bytes - actual);
                reservation.bytes = 0;
                policy.file_created(&path);
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Last-wins overlay merge onto catalog locate hits (no [`FileInfo`]).
    ///
    /// Starts from **all** base rows (every `offsetheader` / GNU incremental
    /// version). Drops tombstoned paths. An overlay host file at a path
    /// replaces every base row for that path with one last-wins hit (COW /
    /// replace / create). `fts:` only overrides or drops existing hit rows
    /// (no host glob of the `fts:` prefix).
    pub fn merge_search_hits(
        &self,
        base: Vec<CheapSearchHit>,
        pattern: &str,
    ) -> Vec<CheapSearchHit> {
        let fts = pattern.starts_with("fts:");
        let tombstones = self.load_tombstone_paths();
        let mut out: Vec<CheapSearchHit> = base
            .into_iter()
            .filter(|hit| !tombstones.contains(&hit.path) && !is_overlay_internal_path(&hit.path))
            .collect();
        if fts {
            let mut seen_path: HashSet<String> = HashSet::new();
            let mut fts_out = Vec::new();
            for hit in out {
                if let Some(ov) = self.overlay_cheap_hit(&hit.path) {
                    if seen_path.insert(hit.path.clone()) {
                        fts_out.push(ov);
                    }
                    continue;
                }
                fts_out.push(hit);
            }
            fts_out.truncate(DEFAULT_SEARCH_LIMIT);
            return fts_out;
        }
        let mut overlay_by_path: BTreeMap<String, CheapSearchHit> = BTreeMap::new();
        self.walk_overlay_host("/", &self.root, pattern, &tombstones, &mut overlay_by_path);
        if !overlay_by_path.is_empty() {
            let overlay_paths: HashSet<String> = overlay_by_path.keys().cloned().collect();
            out.retain(|h| !overlay_paths.contains(&h.path));
            out.extend(overlay_by_path.into_values());
        }
        out.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.offsetheader.cmp(&b.offsetheader))
        });
        out.truncate(DEFAULT_SEARCH_LIMIT);
        out
    }

    /// Snapshot live deletions without opening the exclusively locked overlay DB.
    pub fn load_tombstone_paths(&self) -> HashSet<String> {
        self.tombstones.lock().expect("overlay tombstones").clone()
    }

    /// `symlink_metadata` size/mtime on an overlay host path — never [`FileInfo`].
    fn overlay_cheap_hit(&self, mount_path: &str) -> Option<CheapSearchHit> {
        let real = self.realpath(mount_path);
        self.ensure_under_root(&real).ok()?;
        let name = mount_path.rsplit('/').next().unwrap_or("").to_string();
        if name.is_empty() || is_overlay_internal_name(&name) {
            return None;
        }
        let meta = fs::symlink_metadata(&real).ok()?;
        Some(CheapSearchHit {
            path: if mount_path.starts_with('/') {
                mount_path.to_string()
            } else {
                format!("/{mount_path}")
            },
            name,
            size: meta.len() as i64,
            mtime: metadata_mtime_secs(&meta) as f64,
            offsetheader: None,
        })
    }

    fn walk_overlay_host(
        &self,
        mount_dir: &str,
        host_dir: &Path,
        pattern: &str,
        tombstones: &HashSet<String>,
        by_path: &mut BTreeMap<String, CheapSearchHit>,
    ) {
        for_each_overlay_host_non_dir(
            self,
            mount_dir,
            host_dir,
            tombstones,
            &mut |child_mount, name, child_meta| {
                if locate_pattern_matches(pattern, &child_mount, &name) {
                    by_path.insert(
                        child_mount.clone(),
                        CheapSearchHit {
                            path: child_mount,
                            name,
                            size: child_meta.len() as i64,
                            mtime: metadata_mtime_secs(&child_meta) as f64,
                            offsetheader: None,
                        },
                    );
                }
            },
        );
    }

    /// True when the overlay root has a real file (or symlink) for this path.
    pub fn has_file(&self, path: &str) -> bool {
        if is_overlay_internal_path(path) {
            return false;
        }
        let real = self.realpath(path);
        real.is_file() || real.is_symlink()
    }

    /// See [`overlay_only_names()`].
    pub fn overlay_only_names(&self) -> Vec<String> {
        overlay_only_names(self)
    }

    pub fn create_file(&self, path: &str, mode: u32) -> Result<i32> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        let fd = self.create_file_inner(path, mode)?;
        self.register_write_fd(fd, path);
        Ok(fd)
    }

    #[cfg(unix)]
    fn account_orphan(&self, meta: &fs::Metadata, path: &str, added: u64, removed: u64) {
        use std::os::unix::fs::MetadataExt;
        let mut state = self
            .policy_fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let entry = state
            .growth
            .entry((meta.dev(), meta.ino()))
            .or_insert_with(|| (normpath(path), 0));
        let removed = removed.min(entry.1);
        entry.1 = entry.1 + added - removed;
        self.policy
            .as_ref()
            .expect("orphan policy")
            .bytes_changed(&entry.0, added, removed);
    }

    /// Duplicate a live overlay handle while its owner's handle table is locked.
    /// The returned file must be released with `finish_owned_write_fd`.
    #[cfg(unix)]
    pub fn clone_overlay_fd(&self, fd: i32, path: &str) -> io::Result<File> {
        use std::os::fd::FromRawFd;
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        self.register_write_fd(duplicate, path);
        Ok(unsafe { File::from_raw_fd(duplicate) })
    }

    /// Track a read-only or parked descriptor for unlinked-inode accounting.
    /// Call `release_write_fd` before its owner closes it. This does not pin commits.
    pub fn track_overlay_fd(&self, fd: i32) {
        #[cfg(not(unix))]
        let _ = fd;
        #[cfg(unix)]
        if self.policy.is_some() {
            let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(fd, &mut st) } == 0 {
                self.policy_fds
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .fds
                    .insert(fd, (st.st_dev as u64, st.st_ino as u64));
            }
        }
    }

    fn register_write_fd(&self, fd: i32, path: &str) {
        self.track_overlay_fd(fd);
        self.write_fds
            .lock()
            .expect("overlay write fds")
            .insert(fd, normpath(path));
    }

    /// Drop the write-open pin without closing `fd` (caller already closed it).
    pub fn release_write_fd(&self, fd: i32) {
        let _policy = self.policy_lock();
        #[cfg(unix)]
        if let Some(policy) = &self.policy {
            let mut state = self
                .policy_fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(key) = state.fds.remove(&fd) {
                if !state.fds.values().any(|k| *k == key) {
                    if let Some((path, bytes)) = state.growth.remove(&key) {
                        policy.bytes_changed(&path, 0, bytes);
                    }
                }
            }
        }
        self.write_fds
            .lock()
            .expect("overlay write fds")
            .remove(&fd);
    }

    /// Unregister a write-open pin and close `fd` (FUSE release / NFS create).
    pub fn close_overlay_fd(&self, fd: i32) {
        self.release_write_fd(fd);
        #[cfg(unix)]
        {
            use std::os::unix::io::FromRawFd;
            let _ = unsafe { File::from_raw_fd(fd) };
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
        }
    }

    /// Unregister the write pin, then drop `file` (closes the fd).
    ///
    /// Protocol WRITE helpers that wrap [`Self::open_overlay_fd`] /
    /// [`Self::create_file`] in `File::from_raw_fd` must use this instead of
    /// `drop(file)` then [`Self::release_write_fd`]. The pin map is keyed by
    /// fd number. Closing first lets the kernel reuse that number for another
    /// still-open overlay writer (FUSE create, a second WRITE). Unpinning the
    /// stale number then drops the new pin; `--commit-overlay-interval` can
    /// persist/unlink the still-open file and later pwrite bytes hit a
    /// detached inode.
    pub fn finish_owned_write_fd(&self, file: File) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            self.release_write_fd(file.as_raw_fd());
        }
        drop(file);
    }

    /// Host `(dev, ino)` for each pinned write fd. `None` if any `fstat`
    /// fails — caller must skip the idle tick (fail-closed).
    ///
    /// `fstat` while holding `write_fds` so a concurrent
    /// [`Self::finish_owned_write_fd`] cannot close/reuse the number mid-scan.
    /// Do not wrap the fd in `File` (that can close a still-pinned writer).
    fn write_open_inodes(&self) -> Option<HashSet<(u64, u64)>> {
        let guard = self.write_fds.lock().expect("overlay write fds");
        #[cfg(not(unix))]
        {
            let _ = guard;
            return Some(HashSet::new());
        }
        #[cfg(unix)]
        {
            let mut out = HashSet::new();
            for &fd in guard.keys() {
                let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
                if unsafe { libc::fstat(fd, &mut st) } != 0 {
                    return None;
                }
                out.insert((st.st_dev as u64, st.st_ino as u64));
            }
            Some(out)
        }
    }

    fn create_file_inner(&self, path: &str, mode: u32) -> Result<i32> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        self.refuse_control_path(path)?;
        self.check_mutation(OverlayMutation::Create, &[path])?;
        #[cfg(not(unix))]
        {
            let _ = (self, path, mode);
            return Err(overlay_fd_unsupported());
        }
        #[cfg(unix)]
        {
            self.ensure_parent(path)?;
            let real = self.realpath(path);
            self.ensure_under_root(&real)?;
            if let Some(parent) = real.parent() {
                self.ensure_under_root(parent)?;
                fs::create_dir_all(parent)?;
            }
            let mut opts = open_options_nofollow();
            opts.read(true).write(true).create(true).truncate(true);
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(mode & 0o7777);
            }
            if let Some(policy) = &self.policy {
                policy.check_write(
                    &normpath(path),
                    0,
                    0,
                    self.policy_file_size(path).unwrap_or(0),
                )?;
            }
            let _account = self.account_path(path);
            let f = opts.open(&real)?;
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
            }
            let fd = {
                use std::os::unix::io::IntoRawFd;
                f.into_raw_fd()
            };
            self.mark_present(path, mode | ratarmount_core::S_IFREG)?;
            Ok(fd)
        }
    }

    pub fn open_overlay_fd(&self, path: &str, flags: i32) -> Result<i32> {
        self.open_overlay_fd_with_mode(path, flags, 0o644)
    }

    /// `mode` has already been masked by the client's umask.
    pub fn open_overlay_fd_with_mode(&self, path: &str, flags: i32, mode: u32) -> Result<i32> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        #[cfg(not(unix))]
        {
            let _ = (self, path, flags, mode);
            return Err(overlay_fd_unsupported());
        }
        #[cfg(unix)]
        {
            let _gate = self.commit_gate.read().expect("overlay commit gate");
            let _policy = self.policy_lock();
            if flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) != 0 {
                self.refuse_control_path(path)?;
                self.check_mutation(OverlayMutation::OpenWrite, &[path])?;
            }
            drop(_policy);
            if flags & (libc::O_CREAT | libc::O_EXCL) == (libc::O_CREAT | libc::O_EXCL)
                && self.lookup(path, 0).is_some()
            {
                return Err(io::Error::from_raw_os_error(libc::EEXIST).into());
            }
            let truncate = (flags & libc::O_TRUNC != 0 && flags & libc::O_EXCL == 0).then_some(0);
            self.ensure_modifiable_inner(path, truncate)?;
            let _policy = self.policy_lock();
            let real = self.realpath(path);
            self.ensure_under_root(&real)?;
            // If still missing and write flags, create empty. `create_file_inner`
            // returns an owned raw fd (`into_raw_fd`); discarding it leaked one
            // descriptor per call. Interval persist wipes the overlay host file,
            // so the next FUSE/NFS/9P/SMB/SFTP rewrite hits this every time.
            let mut flags = flags;
            if fs::symlink_metadata(&real).is_err()
                && (flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT)) != 0
            {
                let leftover = self.create_file_inner(path, mode)?;
                flags &= !(libc::O_CREAT | libc::O_EXCL);
                // This temporary descriptor has never been registered.
                unsafe {
                    libc::close(leftover);
                }
            }
            if fs::symlink_metadata(&real).is_err() {
                return Err(OverlayError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no overlay file at {}", real.display()),
                )));
            }
            // Never follow host symlinks out of the overlay folder.
            let flags = flags | libc::O_NOFOLLOW;
            if flags & libc::O_TRUNC != 0 {
                if let Some(policy) = &self.policy {
                    self.check_mutation(OverlayMutation::Truncate, &[path])?;
                    policy.check_write(
                        &normpath(path),
                        0,
                        0,
                        self.policy_file_size(path).unwrap_or(0),
                    )?;
                }
            }
            // Keep O_TRUNC on open: Linux permits it with O_RDONLY, and open
            // must perform permission and O_EXCL checks before changing data.
            let fd = {
                let _account = self.account_path(path);
                unsafe { libc::open(c_path(&real)?.as_ptr(), flags, mode & 0o7777) }
            };
            if fd < 0 {
                return Err(OverlayError::Io(io::Error::last_os_error()));
            }
            // Double-check the opened path still resolves under the overlay root.
            if let Ok(canon) = fs::canonicalize(&real) {
                if !path_is_under(&self.root, &canon) {
                    let _ = unsafe { libc::close(fd) };
                    return Err(OverlayError::Io(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "overlay open resolved outside overlay root",
                    )));
                }
            }
            if (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0 {
                self.register_write_fd(fd, path);
            } else {
                self.track_overlay_fd(fd);
            }
            // Same queue as unlink and rename: a direct UPDATE while older
            // rows are unsaved would be undone when those rows replay.
            self.persist_files_op(PendingFilesOp::ClearDeleted {
                path: normpath(path),
            })?;
            self.tombstone_forget(path);
            Ok(fd)
        }
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> Result<()> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        self.check_mutation(OverlayMutation::Mkdir, &[path])?;
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        fs::create_dir_all(&real)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&real, fs::Permissions::from_mode(mode & 0o7777))?;
        }
        self.mark_present(path, mode | ratarmount_core::S_IFDIR)?;
        Ok(())
    }

    /// Remove `path` from the overlay. Does not open the host inode.
    ///
    /// 9P, SFTP, SMB, NFS, and export-core use this. FUSE uses [`Self::unlink_parked`].
    pub fn unlink(&self, path: &str) -> Result<()> {
        self.unlink_inner(path, false).map(|_| ())
    }

    /// FUSE-only unlink. Parks the host inode when one exists, then removes `path` (#88).
    ///
    /// Other frontends call [`Self::unlink`], which never opens the old file.
    /// Reserved names are refused before the park open. `EMFILE` / `ENFILE`
    /// from that open fails the unlink with nothing removed. The park open is
    /// a raw `open`, not [`Self::open_overlay_fd`]: this method already holds
    /// `commit_gate`'s read lock, and `RwLock` is not reentrant.
    pub fn unlink_parked(&self, path: &str) -> Result<Option<Parked>> {
        self.unlink_inner(path, true)
    }

    fn unlink_inner(&self, path: &str, park: bool) -> Result<Option<Parked>> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        self.check_mutation(OverlayMutation::Unlink, &[path])?;
        self.refuse_sealed_delete(path)?;
        let path = normpath(path);
        let real = self.realpath(&path);
        // unlink of a symlink removes the link itself (safe); refuse only when the
        // joined path is not under the overlay root by construction.
        if !path_is_under(&self.root, &real) {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "overlay unlink path escapes overlay root",
            )));
        }
        let parked = if park {
            self.park_host(&path, &real)?
        } else {
            None
        };
        let _account = self.account_path(&path);
        // remove_file unlinks symlinks without following them.
        if fs::symlink_metadata(&real).is_ok() {
            fs::remove_file(&real)?;
        }
        self.mark_deleted(&path)?;
        Ok(parked)
    }

    pub fn rmdir(&self, path: &str) -> Result<()> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        self.check_mutation(OverlayMutation::Rmdir, &[path])?;
        self.refuse_sealed_delete(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        // POSIX: refuse non-directories and non-empty dirs in the union view.
        // Committing a bare dir tombstone would recursively delete base
        // children (GNU tar --delete) or orphan them (zstd splice drops only
        // the dir member) — the two paths also disagree with each other.
        match self.lookup(path, 0) {
            Some(fi) if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR => {}
            Some(_) => {
                return Err(OverlayError::Io(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("rmdir: not a directory: {path}"),
                )));
            }
            None => {
                return Err(OverlayError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("rmdir: no such directory: {path}"),
                )));
            }
        }
        let has_children = match self.list(path) {
            Some(ListResult::Infos(m)) => !m.is_empty(),
            Some(ListResult::Names(n)) => !n.is_empty(),
            None => false,
        };
        if has_children {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::DirectoryNotEmpty,
                format!("rmdir: directory not empty: {path}"),
            )));
        }
        if real.exists() {
            fs::remove_dir(&real)?;
        }
        self.mark_deleted(path)?;
        Ok(())
    }

    pub fn truncate(&self, path: &str, size: u64) -> Result<()> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        self.check_mutation(OverlayMutation::Truncate, &[path])?;
        drop(_policy);
        self.ensure_modifiable_inner(path, Some(size))?;
        let _policy = self.policy_lock();
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        let mut opts = open_options_nofollow();
        opts.write(true);
        let f = opts.open(&real)?;
        self.truncate_file_inner(&f, path, size)?;
        Ok(())
    }

    /// Create a symlink in the overlay folder (`O_NOFOLLOW` / no escape).
    pub fn create_symlink(&self, path: &str, target: &str) -> Result<()> {
        if is_overlay_internal_path(path) {
            return Err(internal_name_refused(path));
        }
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        self.check_mutation(OverlayMutation::Symlink, &[path])?;
        if target.is_empty() {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty symlink target",
            )));
        }
        self.ensure_parent(path)?;
        let real = self.realpath(path);
        self.ensure_under_root(&real)?;
        if fs::symlink_metadata(&real).is_ok() || self.lookup(path, 0).is_some() {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("symlink destination exists: {path}"),
            )));
        }
        if let Some(parent) = real.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(policy) = &self.policy {
            policy.check_write(&normpath(path), 0, target.len() as u64, 0)?;
        }
        let _account = self.account_path(path);
        overlay_symlink(Path::new(target), &real)?;
        self.mark_present(path, ratarmount_core::S_IFLNK | 0o777)?;
        Ok(())
    }

    /// Rename `from` onto `to` inside the overlay. Does not open either inode.
    ///
    /// 9P, SFTP, SMB, NFS, and export-core use this. FUSE uses [`Self::rename_parked`].
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.rename_inner(from, to, false).map(|_| ())
    }

    /// FUSE-only rename of `from` onto `to` in one `rename(2)` (#88).
    ///
    /// Parks `to`'s host inode when it exists, then renames directly over `to`.
    /// Other frontends call [`Self::rename`], which never opens the old file.
    ///
    /// For a non-directory: COW `from`, reject a directory `to`, park `to`,
    /// `rename(2)` over `to`, then one SQLite transaction that marks `to` present
    /// and tombstones `from` only when the base has `from`. The in-memory
    /// tombstone set is updated after that transaction (`to` out, `from` in only
    /// if the base has `from`). Lock order is `pending_rows`, then `db`, then
    /// tombstones.
    ///
    /// The transaction is tried [`RENAME_TX_ATTEMPTS`] times. The queue lock is
    /// held across those attempts, the backoff, and the push that records a
    /// failure. Releasing it during the backoff lets another writer commit a
    /// later rename that this retry then undoes. If it still fails, or if older
    /// rows are still queued after a replay attempt, this rename is appended to
    /// `pending_rows` and this returns success: the host rename cannot be
    /// undone, and writing it first would let the older replay undo it. The
    /// queue is replayed at the start of the next `files` write, on drop, and
    /// before a commit plan. Live, interval, and on-exit commits refuse while
    /// it is still non-empty after a replay attempt, so a plan cannot publish
    /// an archive member that the mount already hides.
    ///
    /// Reserved names are refused before the park open. The park open is a raw
    /// `open`, not [`Self::open_overlay_fd`] (`commit_gate` is not reentrant).
    /// `EMFILE` / `ENFILE` fails the rename before `to` is modified (the source
    /// copy-up may already exist).
    pub fn rename_parked(&self, from: &str, to: &str) -> Result<Option<Parked>> {
        self.rename_inner(from, to, true)
    }

    fn rename_inner(&self, from: &str, to: &str, park: bool) -> Result<Option<Parked>> {
        for p in [from, to] {
            if is_overlay_internal_path(p) {
                return Err(internal_name_refused(p));
            }
        }
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        self.check_mutation(OverlayMutation::Rename, &[from, to])?;
        self.refuse_sealed_delete(from)?;
        let from = normpath(from);
        let to = normpath(to);
        if from == "/" || to == "/" || from == to {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid rename paths",
            )));
        }
        self.ensure_parent(&to)?;
        let from_real_meta = fs::symlink_metadata(self.realpath(&from));
        let from_is_dir = from_real_meta
            .as_ref()
            .map(|m| m.file_type().is_dir())
            .unwrap_or_else(|_| self.current_base().is_dir(&from));
        if from_is_dir {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::IsADirectory,
                "directory rename is not supported on the write overlay",
            )));
        }
        // COW the source before touching the destination: if the copy fails
        // (read error, ENOSPC), the destination must stay as it was.
        drop(_policy);
        self.ensure_modifiable_inner(&from, None)?;
        let _policy = self.policy_lock();
        let from_real = self.realpath(&from);
        let to_real = self.realpath(&to);
        self.ensure_rename_confined(&from_real)?;
        self.ensure_rename_confined(&to_real)?;
        if fs::symlink_metadata(&from_real).is_err() {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("rename source missing: {from}"),
            )));
        }
        if fs::symlink_metadata(&to_real).is_ok_and(|m| m.file_type().is_dir())
            || self
                .lookup(&to, 0)
                .is_some_and(|fi| ratarmount_core::is_dir_mode(fi.mode))
        {
            return Err(OverlayError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "rename destination is a directory",
            )));
        }
        let parked = if park {
            self.park_host(&to, &to_real)?
        } else {
            None
        };
        if let Some(parent) = to_real.parent() {
            fs::create_dir_all(parent)?;
        }
        let xattrs = self.xattrs_for_path(&from)?;
        {
            let _from_account = self.account_path(&from);
            let _to_account = self.account_path(&to);
            fs::rename(&from_real, &to_real)?;
        }
        let hides_from = self.current_base().exists(&from);
        // Host rename already happened. `persist_files_op` queues on failure
        // and returns success so the client sees the completed rename.
        drop(_policy);
        self.commit_rename_rows(&from, &to, &to_real, hides_from, xattrs)?;
        self.apply_rename_tombstone_memory(&from, &to, hides_from);
        Ok(parked)
    }

    /// Snapshot `host` when it exists, before `rename(2)` or `remove_file`.
    ///
    /// Does not take `commit_gate` and does not call [`Self::open_overlay_fd`].
    fn park_host(&self, mount_path: &str, host: &Path) -> Result<Option<Parked>> {
        let meta = match fs::symlink_metadata(host) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(OverlayError::Io(e)),
        };
        if meta.file_type().is_dir() {
            return Ok(None);
        }
        let last_fi = file_info_from_overlay_meta(mount_path, host, &meta);
        if meta.file_type().is_symlink() {
            return Ok(Some(parked_meta(last_fi)));
        }
        #[cfg(unix)]
        {
            match try_park_open(self, host) {
                Ok(fd) => Ok(Some(parked_fd(last_fi, fd))),
                Err(e) if is_fd_exhaustion(&e) => Err(OverlayError::Io(e)),
                Err(_) => Ok(Some(parked_meta(last_fi))),
            }
        }
        #[cfg(not(unix))]
        {
            Ok(Some(parked_meta(last_fi)))
        }
    }

    /// One transaction: `to` present, and `from` tombstoned iff `hides_from`.
    ///
    /// Replays any older queued rows first. When those rows are still queued,
    /// or when this rename's own attempts fail, the rename is appended and
    /// this returns success. The host rename cannot be undone.
    fn commit_rename_rows(
        &self,
        from: &str,
        to: &str,
        to_real: &Path,
        hides_from: bool,
        xattrs: BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        let mode = match fs::symlink_metadata(to_real) {
            Ok(meta) => metadata_mode(&meta),
            Err(e) => {
                log::error!(
                    "overlay rename could not stat {} after the host rename: {e}",
                    to_real.display()
                );
                ratarmount_core::S_IFREG | 0o644
            }
        };
        self.persist_files_op(PendingFilesOp::Rename {
            from: from.to_string(),
            to: to.to_string(),
            mode,
            hides_from,
            xattrs,
        })
    }

    /// Replay queued rows, then write `op` or append it.
    ///
    /// The host change has already happened. A failure here queues `op` and
    /// returns success so the caller does not report an error for a change
    /// that cannot be undone. Appending keeps order: a later direct write
    /// would be undone when the older rows replay.
    ///
    /// Lock order: `pending_rows`, then `db`. Tombstones are updated by the
    /// caller after this returns. The queue guard stays held across every
    /// direct attempt, the backoff sleep, and the final push. Dropping it to
    /// sleep lets another writer see an empty queue and commit a later rename
    /// that this retry then marks present again.
    fn persist_files_op(&self, op: PendingFilesOp) -> Result<()> {
        if let Err(e) = self.replay_pending_rows() {
            log::warn!(
                "overlay could not replay earlier files rows: {e}; queueing the next update behind them"
            );
        }
        let attempts = if op.is_rename() {
            RENAME_TX_ATTEMPTS
        } else {
            1
        };
        let mut pending_op = Some(op);
        let mut last_err = None;
        let mut queued = self.pending_rows.lock().expect("overlay pending rows");
        for attempt in 1..=attempts {
            if !queued.is_empty() {
                let op = pending_op.take().expect("files op");
                log::error!(
                    "overlay {op} appended behind {} unsaved files update(s); \
                     writing it now would let a later replay undo it",
                    queued.len()
                );
                queued.push(op);
                return Ok(());
            }
            if attempt > 1 {
                // Still holding `pending_rows`. The sleep is the window another
                // writer used to slip a later rename in ahead of this retry.
                #[cfg(test)]
                {
                    let hook = self
                        .direct_retry_wait_hook
                        .lock()
                        .expect("direct retry wait hook")
                        .take();
                    if let Some(mut hook) = hook {
                        hook();
                    }
                }
                std::thread::sleep(RENAME_TX_BACKOFF);
            }
            let op_ref = pending_op.as_ref().expect("files op");
            let ctx = FilesWriteCtx {
                db: &self.db,
                #[cfg(test)]
                fail: &self.rename_tx_fail_remaining,
                #[cfg(test)]
                before_tx: &self.rename_before_tx_hook,
            };
            match write_files_op_direct(&ctx, op_ref) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    log::warn!(
                        "overlay {op_ref} files update attempt {attempt}/{attempts} failed: {e}"
                    );
                    last_err = Some(e);
                }
            }
        }
        let op = pending_op.take().expect("files op");
        let why = last_err
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        log::error!(
            "overlay {op} failed ({why}); queued it behind {} unsaved files update(s)",
            queued.len()
        );
        queued.push(op);
        Ok(())
    }

    /// Write queued rows, retrying a few times. Empty queue is success.
    fn replay_pending_rows(&self) -> Result<()> {
        self.replay_pending_rows_with(LockPoison::Strict)
    }

    /// Each attempt holds `pending_rows` across take, SQL, and restore
    /// (lock order: queue, then `db`). The backoff between attempts is
    /// outside that lock. A failed attempt restores the batch before
    /// releasing the lock, so the queue stays non-empty and another writer
    /// cannot commit directly. On failure the batch is put back in front of
    /// rows appended under that same lock.
    fn replay_pending_rows_with(&self, poison: LockPoison) -> Result<()> {
        if self.pending_rows_is_empty_with(poison) {
            return Ok(());
        }
        let mut last_err = None;
        for attempt in 1..=RENAME_TX_ATTEMPTS {
            if attempt > 1 {
                std::thread::sleep(RENAME_TX_BACKOFF);
            }
            match self.try_replay_pending_once_with(poison) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    log::warn!(
                        "overlay pending files replay attempt {attempt}/{RENAME_TX_ATTEMPTS} \
                         failed: {e}"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("pending replay loop records an error"))
    }

    fn try_replay_pending_once_with(&self, poison: LockPoison) -> Result<()> {
        let mut queued = lock_mutex(&self.pending_rows, poison, "overlay pending rows");
        if queued.is_empty() {
            return Ok(());
        }
        let batch = std::mem::take(&mut *queued);
        #[cfg(test)]
        {
            let hook = lock_mutex(&self.replay_hold_hook, poison, "replay hold hook").take();
            if let Some(mut hook) = hook {
                if let Err(e) = hook() {
                    restore_pending_front(&mut queued, batch);
                    return Err(e);
                }
            }
        }
        // A failure here is the real restore path. The injected fault is raised
        // inside `apply_pending_ops_sql` after the first statement, so the
        // transaction rolls back and this `Err` arm puts the batch back.
        // Dropping `batch` on this error loses the rows.
        if let Err(e) = apply_pending_ops_sql(
            &self.db,
            &batch,
            poison,
            #[cfg(test)]
            Some(&self.rename_tx_fail_remaining),
        ) {
            restore_pending_front(&mut queued, batch);
            return Err(e);
        }
        Ok(())
    }

    fn pending_rows_is_empty(&self) -> bool {
        self.pending_rows_is_empty_with(LockPoison::Strict)
    }

    fn pending_rows_is_empty_with(&self, poison: LockPoison) -> bool {
        lock_mutex(&self.pending_rows, poison, "overlay pending rows").is_empty()
    }

    /// Paths an unsaved queue would hide that SQL does not already tombstone.
    ///
    /// After remount the in-memory queue is gone. Those archive members show
    /// up again, and an offline `--commit-overlay` publishes them because it
    /// reads SQL only.
    fn pending_reappear_paths(&self) -> Vec<String> {
        self.pending_reappear_paths_with(LockPoison::Strict)
    }

    fn pending_reappear_paths_with(&self, poison: LockPoison) -> Vec<String> {
        let ops = lock_mutex(&self.pending_rows, poison, "overlay pending rows").clone();
        let mut hide: HashSet<String> = HashSet::new();
        for op in &ops {
            match op {
                PendingFilesOp::Rename {
                    from,
                    to,
                    hides_from,
                    ..
                } => {
                    hide.remove(to);
                    if *hides_from {
                        hide.insert(from.clone());
                    } else {
                        hide.remove(from);
                    }
                }
                PendingFilesOp::Deleted { path, hides_base } => {
                    if *hides_base {
                        hide.insert(path.clone());
                    } else {
                        hide.remove(path);
                    }
                }
                PendingFilesOp::Present { path, .. } | PendingFilesOp::ClearDeleted { path } => {
                    hide.remove(path);
                }
            }
        }
        let mut out: Vec<String> = hide
            .into_iter()
            .filter(|path| !matches!(self.files_deleted_flag_with(path, poison), Ok(Some(1))))
            .collect();
        out.sort();
        out
    }

    /// Replay queued rows, then refuse when any remain.
    ///
    /// A commit plan reads `deleted = 1` from SQL. Publishing while the mount
    /// already hides a name would leave that archive member in place and, after
    /// the overlay reset, show it again.
    fn replay_pending_or_refuse_commit(&self) -> Result<()> {
        let replay_err = self.replay_pending_rows().err();
        if self.pending_rows_is_empty() {
            return match replay_err {
                Some(e) => Err(e),
                None => Ok(()),
            };
        }
        let n = self.pending_row_count_locked_with(LockPoison::Strict);
        let why = replay_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "replay left rows queued".to_string());
        let paths = self.pending_reappear_paths();
        let listed = if paths.is_empty() {
            "unlinked archive members would reappear".to_string()
        } else {
            format!(
                "unlinked archive members would reappear: {}",
                paths.join(", ")
            )
        };
        Err(OverlayError::Msg(format!(
            "write overlay {} has {n} files update(s) that could not be saved ({why}); \
             refusing to commit because the archive would not match the mount \
             ({listed}). An offline --commit-overlay will publish them",
            self.root.display()
        )))
    }

    fn pending_row_count_locked_with(&self, poison: LockPoison) -> usize {
        lock_mutex(&self.pending_rows, poison, "overlay pending rows").len()
    }

    /// Final replay when the mount goes away. Rows that still cannot be saved
    /// are logged with the archive paths that will show up again.
    ///
    /// A poisoned `pending_rows` or `db` lock must not panic: this runs from
    /// [`Drop`], and a panic while unwinding aborts the process. The guard is
    /// recovered with [`PoisonError::into_inner`]. `std::process::exit` skips
    /// this replay; the mount path drops the overlay before it exits.
    fn replay_pending_on_drop(&self) {
        let poison = LockPoison::Recover;
        if self.pending_rows_is_empty_with(poison) {
            return;
        }
        if self.replay_pending_rows_with(poison).is_ok() && self.pending_rows_is_empty_with(poison)
        {
            return;
        }
        let n = self.pending_row_count_locked_with(poison);
        let paths = self.pending_reappear_paths_with(poison);
        let listed = if paths.is_empty() {
            "(none)".to_string()
        } else {
            paths.join(", ")
        };
        log::error!(
            "overlay {}: {n} pending files update(s) were not saved on unmount; \
             these paths will reappear on remount: {listed}. \
             An offline --commit-overlay will publish them",
            self.root.display()
        );
    }

    fn plan_for_commit(
        &self,
        idle_cutoff: Option<SystemTime>,
        busy_inodes: &HashSet<(u64, u64)>,
    ) -> Result<OverlayCommitPlan> {
        self.replay_pending_or_refuse_commit()?;
        let db = self.db.lock().expect("overlay db");
        collect_overlay_commit_plan_from_conn(&self.root, Some(&db), idle_cutoff, busy_inodes)
    }

    /// `to` leaves the tombstone set; `from` enters it only when the base has `from`.
    fn apply_rename_tombstone_memory(&self, from: &str, to: &str, hides_from: bool) {
        let mut set = self.tombstones.lock().expect("overlay tombstones");
        set.remove(&normpath(to));
        if hides_from {
            set.insert(normpath(from));
        } else {
            set.remove(&normpath(from));
        }
    }

    #[cfg(test)]
    fn set_rename_before_tx_hook(&self, hook: Option<RenameBeforeTxHook>) {
        *self
            .rename_before_tx_hook
            .lock()
            .expect("overlay rename hook") = hook;
    }

    /// Fail the next `n` `files` writes (direct attempts and replays). `0` clears it.
    #[cfg(test)]
    fn set_rename_tx_failures(&self, n: u64) {
        self.rename_tx_fail_remaining.store(n, Ordering::SeqCst);
    }

    /// One-shot replay hook. Runs while `pending_rows` is held. Must not lock it.
    #[cfg(test)]
    fn set_replay_hold_hook(&self, hook: Option<ReplayHoldHook>) {
        *self.replay_hold_hook.lock().expect("replay hold hook") = hook;
    }

    /// One-shot hook at the start of a direct-write retry wait. Runs while
    /// `pending_rows` is held. Must not lock it, and must not wait for another
    /// thread's `files` write.
    #[cfg(test)]
    fn set_direct_retry_wait_hook(&self, hook: Option<DirectRetryWaitHook>) {
        *self
            .direct_retry_wait_hook
            .lock()
            .expect("direct retry wait hook") = hook;
    }

    #[cfg(test)]
    fn pending_row_count(&self) -> usize {
        self.pending_rows
            .lock()
            .expect("overlay pending rows")
            .len()
    }

    #[cfg(test)]
    fn set_park_open_hook(&self, hook: Option<ParkOpenHook>) {
        *self.park_open_hook.lock().expect("park open hook") = hook;
    }

    #[cfg(test)]
    fn park_open_count(&self) -> u64 {
        self.park_open_count.load(Ordering::SeqCst)
    }

    /// `deleted` column for `path`: `Some(1)` tombstone, `Some(0)` present, `None` no row.
    #[cfg(test)]
    fn files_deleted_flag(&self, path: &str) -> Result<Option<i64>> {
        self.files_deleted_flag_with(path, LockPoison::Strict)
    }

    fn files_deleted_flag_with(&self, path: &str, poison: LockPoison) -> Result<Option<i64>> {
        let (folder, name) = Self::split(path);
        let db = lock_mutex(&self.db, poison, "overlay db");
        let flag = db
            .query_row(
                r#"SELECT deleted FROM "files" WHERE path = ?1 AND name = ?2"#,
                params![folder, name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(flag)
    }

    /// Apply a protocol SETATTR request. Explicit times are applied after the
    /// truncate, which itself changes mtime. Refused ownership must not truncate.
    pub fn set_attributes(
        &self,
        path: &str,
        size: Option<u64>,
        attrs: &OverlayMetadata,
    ) -> Result<()> {
        if !attrs.is_empty() {
            let _policy = self.policy_lock();
            self.check_mutation(OverlayMutation::Write, &[path])?;
            validate_metadata(attrs)?;
        }
        if let Some(size) = size {
            self.truncate(path, size)?;
        }
        if !attrs.is_empty() {
            self.set_metadata(path, attrs)?;
        }
        Ok(())
    }

    /// Read overlay-level metadata through the held connection, including on a mounted overlay.
    pub fn meta_value(&self, key: &str) -> Result<Option<String>> {
        let db = self.db.lock().expect("overlay db");
        Ok(crate::overlay_meta::OverlayMeta::from_connection(&db)?
            .and_then(|meta| meta.get(key).map(str::to_owned)))
    }

    /// Provenance in the composed base, before this writable layer.
    pub fn base_serving_layer(&self, path: &str) -> Option<crate::LayerIndex> {
        crate::serving_layer(self.current_base().as_ref(), path)
    }

    /// The archive base whose digest is still `pending`, if any.
    pub fn pending_base(&self) -> Result<Option<crate::PendingBase>> {
        let db = self.db.lock().expect("overlay db");
        match crate::OverlayMeta::from_connection(&db)? {
            Some(meta) => crate::PendingBase::from_meta(&meta),
            None => Ok(None),
        }
    }

    /// Record a lazily computed base digest through the mount's own connection
    /// (a live mount holds it exclusively). Compare-and-set: `false` when the
    /// digest is no longer `pending` for `pending`'s stamp.
    pub fn record_base_digest(&self, pending: &crate::PendingBase, digest: &str) -> Result<bool> {
        let db = self.db.lock().expect("overlay db");
        crate::record_base_digest(&db, pending, digest)
    }

    /// Record one overlay-level `meta` key (for example `readonly_rules`).
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let db = self.db.lock().expect("overlay db");
        crate::overlay_meta::OverlayMeta::set(&db, key, value)
    }

    /// Remove one overlay-level `meta` key (no error when absent).
    pub fn clear_meta(&self, key: &str) -> Result<()> {
        let db = self.db.lock().expect("overlay db");
        crate::overlay_meta::OverlayMeta::remove(&db, key)
    }

    /// Test seam (`test-hooks` feature or unit tests): when
    /// `RATARMOUNT_TEST_JOURNAL_HOLD` names a file, open a write transaction
    /// that dirties more pages than the page cache holds (so SQLite writes
    /// the rollback journal and the database), create that file as the ready
    /// signal and block holding the transaction. The test then SIGKILLs the
    /// process, which leaves a hot `-journal`. No-op in release builds.
    pub fn test_hold_open_transaction(&self) {
        #[cfg(any(test, feature = "test-hooks"))]
        if let Some(ready) = std::env::var_os("RATARMOUNT_TEST_JOURNAL_HOLD") {
            let db = self.db.lock().expect("overlay db");
            db.execute_batch(
                "BEGIN IMMEDIATE; \
                 INSERT OR REPLACE INTO meta(key, value) VALUES('test_scratch', hex(randomblob(6000000)));",
            )
            .expect("hold transaction");
            std::fs::write(ready, b"ready").expect("ready file");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let _ = db.execute_batch("ROLLBACK");
        }
    }

    /// Change metadata through the same policy gate as data writes. Archive-only
    /// members retain their original read cookie and never copy payload data.
    pub fn set_metadata(&self, path: &str, attrs: &OverlayMetadata) -> Result<()> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        let path = normpath(path);
        self.check_mutation(OverlayMutation::Write, &[&path])?;
        if is_overlay_internal_path(&path) {
            return Err(internal_name_refused(&path));
        }
        if self.rolling.is_some() && !self.has_file(&path) {
            self.refuse_sealed_delete(&path)?;
        }
        let fi = self
            .lookup(&path, 0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        validate_metadata(attrs)?;
        if attrs.mode.is_some() && ratarmount_core::is_lnk_mode(fi.mode) {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP).into());
        }
        if attrs.is_empty() {
            return Ok(());
        }
        self.replay_pending_rows()?;
        let pending = self.pending_rows.lock().expect("overlay pending rows");
        if !pending.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::WouldBlock, "overlay name updates pending").into(),
            );
        }
        let real = self.realpath(&path);
        self.ensure_under_root(if path == "/" {
            &real
        } else {
            real.parent().expect("overlay parent")
        })?;
        if fs::symlink_metadata(&real).is_ok() {
            set_host_metadata(&real, attrs)?;
        }
        let db = self.db.lock().expect("overlay db");
        let tx = db.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO overlay_metadata(path,mode,atime,mtime) VALUES (?1,?2,?3,?4)
             ON CONFLICT(path) DO UPDATE SET mode=COALESCE(excluded.mode,mode),
             atime=COALESCE(excluded.atime,atime), mtime=COALESCE(excluded.mtime,mtime)",
            params![
                path,
                attrs.mode.map(|m| m & 0o7777),
                attrs.atime,
                attrs.mtime
            ],
        )?;
        let (folder, name) = Self::split(&path);
        tx.execute(
            "INSERT INTO files(path,name,mode,mtime,uid,gid,deleted) VALUES (?1,?2,?3,?4,?5,?6,0)
             ON CONFLICT(path,name) DO UPDATE SET mode=excluded.mode,mtime=excluded.mtime",
            params![
                folder,
                name,
                (fi.mode & !0o7777) | attrs.mode.unwrap_or(fi.mode) & 0o7777,
                attrs.mtime.unwrap_or(fi.mtime),
                fi.uid,
                fi.gid
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Descriptor metadata changes for detached FUSE inodes. No path rows are
    /// changed: that name may already refer to an entirely different inode.
    #[cfg(unix)]
    pub fn set_metadata_file(
        &self,
        file: &File,
        path: &str,
        attrs: &OverlayMetadata,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        self.check_mutation(OverlayMutation::Write, &[path])?;
        validate_metadata(attrs)?;
        if let Some(mode) = attrs.mode {
            file.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
        }
        if attrs.atime.is_some() || attrs.mtime.is_some() {
            let times = metadata_times(attrs);
            if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn metadata_for_path(&self, path: &str) -> Option<OverlayMetadata> {
        self.db
            .lock()
            .expect("overlay db")
            .query_row(
                "SELECT mode,atime,mtime FROM overlay_metadata WHERE path=?1",
                [normpath(path)],
                |r| {
                    Ok(OverlayMetadata {
                        mode: r.get(0)?,
                        atime: r.get(1)?,
                        mtime: r.get(2)?,
                        ..Default::default()
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    fn apply_metadata(&self, path: &str, fi: &mut FileInfo) {
        if let Some(attrs) = self.metadata_for_path(path) {
            if let Some(mode) = attrs.mode {
                fi.mode = (fi.mode & !0o7777) | (mode & 0o7777);
            }
            if let Some(mtime) = attrs.mtime {
                fi.mtime = mtime;
            }
            if let Some(atime) = attrs.atime {
                set_info_atime(fi, atime);
            }
        }
    }

    /// Set before sharing the overlay with frontends. Copy is the default.
    /// Xattr metadata is separate from host files: setting it never copies payload data.
    /// NULL values mask archive attributes. Xattr bytes have their own caps and are
    /// excluded from the host-file quota.
    pub fn set_xattr(&self, path: &str, name: &str, value: &[u8], flags: i32) -> Result<()> {
        self.change_xattr(path, name, Some(value), flags)
    }

    pub fn remove_xattr(&self, path: &str, name: &str) -> Result<()> {
        self.change_xattr(path, name, None, 2)
    }

    fn change_xattr(&self, path: &str, name: &str, value: Option<&[u8]>, flags: i32) -> Result<()> {
        let _gate = self.commit_gate.read().expect("overlay commit gate");
        let _policy = self.policy_lock();
        let path = normpath(path);
        self.refuse_control_path(&path)?;
        self.check_mutation(OverlayMutation::Write, &[&path])?;
        if self.rolling.is_some() && !self.has_file(&path) {
            self.refuse_sealed_delete(&path)?;
        }
        if path == "/" {
            return Err(io::Error::from_raw_os_error(libc::EPERM).into());
        }
        if !name.starts_with("user.") {
            return Err(io::Error::from_raw_os_error(libc::EPERM).into());
        }
        if name.len() <= 5
            || name.len() > 255
            || name.contains(['=', '\0', '\n'])
            || !matches!(flags, 0..=2)
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL).into());
        }
        if value.is_some_and(|v| v.len() > 65536) {
            return Err(io::Error::from_raw_os_error(libc::E2BIG).into());
        }
        self.lookup(&path, 0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        self.replay_pending_or_refuse_commit()?;
        let mut attrs = self.base_xattrs(&path);
        let mut db = self.db.lock().expect("overlay db");
        merge_xattr_rows(&db, &path, &mut attrs)?;
        let exists = attrs.contains_key(name);
        if flags == 1 && exists {
            return Err(io::Error::from_raw_os_error(libc::EEXIST).into());
        }
        if flags == 2 && !exists {
            return Err(io::Error::from_raw_os_error(missing_xattr_errno()).into());
        }
        attrs.remove(name);
        let total = attrs.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
            + value.map_or(0, |v| name.len() + v.len());
        let stored: usize = db.query_row(
            "SELECT COALESCE(SUM(length(CAST(name AS BLOB)) + COALESCE(length(value),0)),0) FROM xattrs WHERE path=?1 AND name<>?2",
            params![path, name], |r| r.get(0))?;
        let stored_names: HashSet<String> = db
            .prepare("SELECT name FROM xattrs WHERE path=?1")?
            .query_map([&path], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let inherited = attrs
            .iter()
            .filter(|(key, _)| !stored_names.contains(*key))
            .map(|(key, data)| key.len() + data.len())
            .sum::<usize>();
        if total > 256 * 1024
            || stored + inherited + name.len() + value.map_or(0, <[u8]>::len) > 256 * 1024
        {
            return Err(io::Error::from_raw_os_error(libc::E2BIG).into());
        }
        let tx = db.transaction()?;
        // Keep index-only inherited metadata (notably user.hash.*) when the
        // replacement header is built from a fresh TAR scan during commit.
        for (key, data) in &attrs {
            tx.execute(
                "INSERT OR IGNORE INTO xattrs(path,name,value) VALUES (?1,?2,?3)",
                params![path, key, data],
            )?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO xattrs(path,name,value) VALUES (?1,?2,?3)",
            params![path, name, value],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn base_xattrs(&self, path: &str) -> BTreeMap<String, Vec<u8>> {
        let base = self.current_base();
        base.lookup(path, 0)
            .map(|fi| source_xattrs(base.as_ref(), &fi))
            .unwrap_or_default()
    }

    pub fn xattrs_for_path(&self, path: &str) -> Result<BTreeMap<String, Vec<u8>>> {
        let path = normpath(path);
        self.lookup(&path, 0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        let mut attrs = self.base_xattrs(&path);
        // Rename SQL can be queued after the host rename. Observe its metadata
        // snapshot too, in the same queue-before-database order used by replay.
        let pending = self.pending_rows.lock().expect("overlay pending rows");
        merge_xattr_rows(&self.db.lock().expect("overlay db"), &path, &mut attrs)?;
        for op in pending.iter() {
            match op {
                PendingFilesOp::Rename { to, xattrs, .. } if to == &path => attrs = xattrs.clone(),
                PendingFilesOp::Rename { from, .. } if from == &path => attrs.clear(),
                PendingFilesOp::Deleted { path: deleted, .. } if deleted == &path => attrs.clear(),
                _ => {}
            }
        }
        Ok(attrs)
    }

    /// Enable local TAR commit manifests with all/new/none hash coverage.
    pub fn set_manifest_hashes(&mut self, hashes: Option<String>) {
        self.manifest_hashes = hashes;
    }

    pub fn set_commit_mode(&mut self, mode: CommitMode) {
        self.commit_mode = mode;
    }

    /// Install the series used as this overlay's base before serving requests.
    pub fn set_rolling(&mut self, rolling: Arc<crate::RollingMountSource>) {
        self.rolling = Some(rolling);
    }

    /// Actual active path (the CLI keeps the original generation as its label).
    pub fn commit_archive_path(&self, archive: &Path) -> PathBuf {
        self.rolling
            .as_ref()
            .map_or_else(|| archive.to_path_buf(), |series| series.active_path())
    }

    fn refuse_sealed_delete(&self, path: &str) -> Result<()> {
        if self
            .rolling
            .as_ref()
            .is_some_and(|series| series.sealed_contains(path))
        {
            return Err(io::Error::from_raw_os_error(libc::EROFS).into());
        }
        Ok(())
    }

    fn rolling_commit_target(&self, archive: &Path, plan: &OverlayCommitPlan) -> Result<PathBuf> {
        let Some(series) = &self.rolling else {
            return Ok(archive.to_path_buf());
        };
        let mut defer = false;
        for path in &plan.deleted_paths {
            if !plan.append_entries.iter().any(|(p, _)| p == path) {
                self.refuse_sealed_delete(path)?;
                defer |= series.active_source().exists(&archive_lookup_path(path));
            }
        }
        for path in plan.xattrs.keys().chain(plan.metadata.keys()) {
            if !plan.append_entries.iter().any(|(p, _)| p == path) {
                self.refuse_sealed_delete(path)?;
                defer = true;
            }
        }
        series.prepare_commit(defer)
    }

    fn rolling_persist_plan<'a>(&self, plan: &'a OverlayCommitPlan) -> Cow<'a, OverlayCommitPlan> {
        let Some(series) = &self.rolling else {
            return Cow::Borrowed(plan);
        };
        let mut plan = plan.clone();
        // Offsets and deletion names belong to the active archive only.
        // Overlay cleanup still consumes the original, unfiltered plan.
        let active = series.active_source();
        plan.deleted_paths
            .retain(|p| active.exists(&archive_lookup_path(p)));
        plan.deletions_nul.clear();
        for path in &plan.deleted_paths {
            add_deletion_variants(&mut plan.deletions_nul, path);
        }
        Cow::Owned(plan)
    }

    /// True when `archive` can be live-committed (uncompressed TAR or `.tar.zst`).
    pub fn live_commit_supported(archive: &Path) -> Result<()> {
        live_commit_is_supported(archive)
    }

    /// Persist only (on-exit). No reopen/reset.
    pub fn commit_atomic(&self, archive: &Path) -> Result<bool> {
        if self.remote_enabled() {
            return self.commit_atomic_remote();
        }
        let _gate = self.commit_gate.write().expect("overlay commit gate");
        let archive_path = self.commit_archive_path(archive);
        let archive = archive_path.as_path();
        self.recover_journal(archive)?;
        live_commit_is_supported(archive)?;
        let format = detect_live_commit_format(archive)?;
        if self.interval_disabled() {
            return Err(interval_disabled_err());
        }
        // Refuse unsaved rows before looking for GNU tar, so on-exit names the
        // paths that would reappear even when tar is not installed.
        let plan = self.plan_for_commit(None, &HashSet::new())?;
        if format != CompressionFormat::Zstd && self.commit_mode == CommitMode::Copy {
            ensure_gnu_tar()?;
        }
        if plan.is_empty() {
            return Ok(false);
        }
        // After `recover` on purpose: recovery only rolls a torn earlier append
        // back to the archive the rows describe, and the identity check then
        // judges that restored file; nothing of this commit is written before it.
        self.check_commit_identity(archive, false)?;
        let target = self.rolling_commit_target(archive, &plan)?;
        let archive = target.as_path();
        let persist_plan = self.rolling_persist_plan(&plan);
        let window = self.persist_by_format(archive, format, &persist_plan)?;
        if let Some(series) = &self.rolling {
            series.committed(None);
        }
        self.stash_patch_window(window);
        self.commit_generation.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    /// Dispatcher: uncompressed TAR (GNU tar) or `.tar.zst` (last-frame splice).
    ///
    /// Commits every overlay change, then wipes the overlay folder. Interval
    /// ticks use [`Self::commit_live_idle`] so recently modified files stay
    /// in the overlay until they settle.
    ///
    /// Not coalesced: NFS / compositing tests call this directly. Live interval
    /// and on-exit go through [`Self::enqueue_commit`].
    pub fn commit_live(
        &self,
        archive: &Path,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        self.commit_live_inner(archive, None, reopen)
    }

    /// Interval persist: only overlay files whose host mtime is at least
    /// `idle_for` in the past **and** that have no open write fd. Still-hot
    /// files (and parent dirs they need) stay in the overlay. Delete
    /// tombstones are already settled and go out on the same tick.
    ///
    /// Not coalesced: tests call this directly. Production interval ticks use
    /// [`Self::enqueue_commit`] (`CommitKind::IntervalIdle`).
    pub fn commit_live_idle(
        &self,
        archive: &Path,
        idle_for: Duration,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        // Shared lock so a 1 Hz empty poll does not stall overlay writers.
        {
            let _gate = self.commit_gate.read().expect("overlay commit gate");
            if self.interval_disabled() {
                return Err(interval_disabled_err());
            }
            let cutoff = SystemTime::now()
                .checked_sub(idle_for)
                .unwrap_or(SystemTime::UNIX_EPOCH);
            self.replay_pending_or_refuse_commit()?;
            let Some(busy) = self.write_open_inodes() else {
                return Ok(false);
            };
            let plan = self.plan_for_commit(Some(cutoff), &busy)?;
            if plan.is_empty() {
                return Ok(false);
            }
        }
        self.commit_live_inner(archive, Some(idle_for), reopen)
    }

    /// Enqueue a **live** persist (V-4). `CommitKind::{IntervalIdle, OnExit}` only.
    ///
    /// Overlay `create`/`write` stay on `commit_gate.read()`. Inflight is a
    /// separate flag — do not hold the writer-visible gate from enqueue until
    /// unmount. CLI [`commit_overlay`] stays off this path. F-7 will reuse
    /// this live queue later.
    pub fn enqueue_commit(
        &self,
        archive: &Path,
        kind: CommitKind,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<CommitOutcome> {
        match kind {
            CommitKind::IntervalIdle(idle_for) => {
                self.enqueue_interval_idle(archive, idle_for, reopen)
            }
            CommitKind::OnExit => {
                // On-exit is persist-only (`commit_atomic`); interval owns reopen.
                drop(reopen);
                self.enqueue_on_exit(archive)
            }
        }
    }

    fn enqueue_interval_idle(
        &self,
        archive: &Path,
        idle_for: Duration,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<CommitOutcome> {
        if self.interval_disabled() {
            return Ok(CommitOutcome::Disabled);
        }
        if self.interval_suppressed.load(Ordering::SeqCst) {
            log::debug!("interval overlay commit skipped (on-exit in progress)");
            return Ok(CommitOutcome::Nothing);
        }
        let Some(_guard) = InFlightGuard::try_begin(self) else {
            log::debug!("interval overlay commit coalesced (persist already in flight)");
            return Ok(CommitOutcome::Coalesced);
        };
        if self.interval_suppressed.load(Ordering::SeqCst) {
            log::debug!("interval overlay commit skipped (on-exit in progress)");
            return Ok(CommitOutcome::Nothing);
        }
        self.apply_test_persist_delay();
        let start = Instant::now();
        let result = if self.remote_enabled() {
            // Remote mounts enter here. Direct `commit_live` does not.
            self.commit_remote_interval(idle_for, reopen)
        } else {
            self.commit_live_idle(archive, idle_for, reopen)
        };
        match result {
            Ok(true) => {
                // Empty/error ticks must not shrink the on-exit wait (2× last splice).
                self.record_persist_duration(start.elapsed());
                Ok(CommitOutcome::DidWork)
            }
            Ok(false) => Ok(CommitOutcome::Nothing),
            Err(e) => Err(e),
        }
    }

    fn enqueue_on_exit(&self, archive: &Path) -> Result<CommitOutcome> {
        if self.interval_disabled() {
            return Err(interval_disabled_err());
        }
        let remote = self.remote_enabled();
        if remote {
            // The interval thread must not start another PUT during this wait.
            self.interval_suppressed.store(true, Ordering::SeqCst);
        }
        let timeout = self.on_exit_wait_timeout();
        if !self.wait_inflight_cleared(Some(timeout)) {
            if let Some(extra) = self.remote_on_exit_extra() {
                log::error!(
                    "on-exit overlay commit timed out waiting for in-flight persist; \
                     waiting at most {extra:?} more (object-store I/O timeout)"
                );
                if !self.wait_inflight_cleared(Some(extra)) {
                    log::error!(
                        "remote on-exit still in flight after object-store timeout; \
                         not splicing"
                    );
                    return Err(remote_on_exit_timeout_err());
                }
            } else {
                log::error!(
                    "on-exit overlay commit timed out waiting for in-flight persist; \
                     waiting for it to finish before final flush"
                );
                self.wait_inflight_cleared(None);
            }
        }
        if self.interval_disabled() {
            return Err(interval_disabled_err());
        }
        // Own inflight before `commit_atomic`. `commit_gate` serializes splice
        // I/O but on-exit persist does not forget overlay files; overlapping
        // interval would append the same names again.
        let _guard = if remote {
            let extra = self
                .remote_on_exit_extra()
                .unwrap_or(REMOTE_ON_EXIT_EXTRA_DEFAULT);
            match InFlightGuard::try_begin(self) {
                Some(g) => g,
                None => {
                    if !self.wait_inflight_cleared(Some(extra)) {
                        log::error!(
                            "remote on-exit still in flight after object-store timeout; \
                             not splicing"
                        );
                        return Err(remote_on_exit_timeout_err());
                    }
                    match InFlightGuard::try_begin(self) {
                        Some(g) => g,
                        None => {
                            log::error!(
                                "remote on-exit could not start after the bounded wait; \
                                 not splicing"
                            );
                            return Err(remote_on_exit_timeout_err());
                        }
                    }
                }
            }
        } else {
            loop {
                if let Some(g) = InFlightGuard::try_begin(self) {
                    break g;
                }
                self.wait_inflight_cleared(None);
            }
        };
        match self.commit_atomic(archive) {
            Ok(true) => Ok(CommitOutcome::DidWork),
            Ok(false) => Ok(CommitOutcome::Nothing),
            Err(e) => Err(e),
        }
    }

    fn last_persist_duration(&self) -> Duration {
        *self
            .last_persist_duration
            .lock()
            .expect("overlay persist duration")
    }

    fn record_persist_duration(&self, elapsed: Duration) {
        *self
            .last_persist_duration
            .lock()
            .expect("overlay persist duration") = elapsed;
    }

    fn on_exit_wait_timeout(&self) -> Duration {
        self.last_persist_duration()
            .saturating_mul(2)
            .max(*self.on_exit_wait_min.lock().expect("on-exit wait min"))
    }

    fn apply_test_persist_delay(&self) {
        let delay = *self.persist_delay.lock().expect("overlay persist delay");
        if let Some(d) = delay {
            if !d.is_zero() {
                std::thread::sleep(d);
            }
        }
    }

    /// `None` timeout waits until inflight clears (on-exit after the 2× wait).
    fn wait_inflight_cleared(&self, timeout: Option<Duration>) -> bool {
        let mut g = self.commit_wait.lock().expect("overlay commit wait");
        let deadline = timeout.map(|t| Instant::now() + t);
        while self.commit_inflight.load(Ordering::SeqCst) {
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                let (guard, wait_res) = self
                    .commit_cv
                    .wait_timeout(g, deadline.saturating_duration_since(now))
                    .expect("overlay commit wait");
                g = guard;
                if wait_res.timed_out() && self.commit_inflight.load(Ordering::SeqCst) {
                    return false;
                }
            } else {
                g = self.commit_cv.wait(g).expect("overlay commit wait");
            }
        }
        true
    }

    /// Injected long persist for V-4 coalesce tests.
    #[doc(hidden)]
    pub fn set_persist_delay_for_test(&self, delay: Duration) {
        *self.persist_delay.lock().expect("overlay persist delay") = Some(delay);
    }

    /// Shorten the on-exit wait floor (production default 60s).
    #[doc(hidden)]
    pub fn set_on_exit_wait_min_for_test(&self, min: Duration) {
        *self.on_exit_wait_min.lock().expect("on-exit wait min") = min;
    }

    /// Last `DidWork` persist duration (empty/error ticks do not update it).
    #[doc(hidden)]
    pub fn last_persist_duration_for_test(&self) -> Duration {
        self.last_persist_duration()
    }

    /// Whether a live persist currently holds the V-4 inflight flag.
    #[doc(hidden)]
    pub fn persist_inflight_for_test(&self) -> bool {
        self.commit_inflight.load(Ordering::SeqCst)
    }

    fn with_remote_mut<T>(&self, f: impl FnOnce(&mut RemoteLive) -> T) -> Result<T> {
        let mut guard = self.remote.lock().expect("overlay remote");
        let hooks = guard
            .as_mut()
            .ok_or_else(|| OverlayError::Msg("remote live commit is not installed".into()))?;
        Ok(f(hooks))
    }

    fn remote_head(&self) -> Result<RemoteObjectHead> {
        self.with_remote_mut(|h| (h.head)())?
    }

    fn remote_download(&self) -> Result<RemoteDownload> {
        self.with_remote_mut(|h| (h.download)())?
    }

    fn remote_publish(
        &self,
        req: &RemotePublishRequest,
    ) -> std::result::Result<(), RemotePublishError> {
        match self.with_remote_mut(|h| (h.publish)(req)) {
            Ok(inner) => inner,
            Err(e) => Err(RemotePublishError::Retryable(e.to_string())),
        }
    }

    fn drop_spool(&self) {
        *self.spool.lock().expect("overlay spool") = None;
    }

    fn spool_path_and_downloaded_etag(&self) -> Option<(PathBuf, Option<String>, bool)> {
        let guard = self.spool.lock().expect("overlay spool");
        let hold = guard.as_ref()?;
        let path = hold.file.path().to_path_buf();
        let (etag, spliced) = match &hold.state {
            SpoolState::Downloaded(d) => (d.etag.clone(), false),
            SpoolState::Spliced(s) => (s.etag_at_download.clone(), true),
        };
        Some((path, etag, spliced))
    }

    /// `true` when HEAD's ETag is the one stored for this spool.
    fn spool_etag_matches(&self, head_etag: Option<&str>) -> bool {
        let guard = self.spool.lock().expect("overlay spool");
        let Some(hold) = guard.as_ref() else {
            return false;
        };
        let stored = match &hold.state {
            SpoolState::Downloaded(d) => d.etag.as_deref(),
            SpoolState::Spliced(s) => s.etag_at_download.as_deref(),
        };
        match (stored, head_etag) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            _ => false,
        }
    }

    fn spool_is_spliced(&self) -> bool {
        let guard = self.spool.lock().expect("overlay spool");
        matches!(
            guard.as_ref().map(|h| &h.state),
            Some(SpoolState::Spliced(_))
        )
    }

    fn accept_download(&self, dl: RemoteDownload, etag: Option<String>) -> Result<PathBuf> {
        self.ensure_spool_outside_overlay(dl.file.path())?;
        set_spool_mode_0600(dl.file.path())?;
        if dl.len > REMOTE_SPOOL_WARN_BYTES {
            log::warn!(
                "remote live commit downloaded {len} bytes; v1 still splices a local spool",
                len = dl.len
            );
        }
        log::info!(
            "remote spool downloaded {len} bytes (etag {etag})",
            len = dl.len,
            etag = etag.as_deref().unwrap_or("-")
        );
        let path = dl.file.path().to_path_buf();
        *self.spool.lock().expect("overlay spool") = Some(SpoolHold {
            file: dl.file,
            state: SpoolState::Downloaded(SpoolDownloaded { etag, len: dl.len }),
        });
        Ok(path)
    }

    fn ensure_spool_outside_overlay(&self, path: &Path) -> Result<()> {
        let parent = path.parent().unwrap_or(path);
        let parent_canon = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        if parent_canon.starts_with(&self.root) || path.starts_with(&self.root) {
            return Err(OverlayError::Msg(
                "s3 spool must not be created inside the overlay directory".into(),
            ));
        }
        Ok(())
    }

    fn mark_spool_spliced(&self, plan: &OverlayCommitPlan, fp: PrespliceFingerprint) {
        let prefix = self
            .last_publish_plan()
            .map(|p| p.prefix_compressed_bytes)
            .unwrap_or(0);
        let mut guard = self.spool.lock().expect("overlay spool");
        let Some(hold) = guard.as_mut() else {
            return;
        };
        let etag = match &hold.state {
            SpoolState::Downloaded(d) => d.etag.clone(),
            SpoolState::Spliced(s) => s.etag_at_download.clone(),
        };
        hold.state = SpoolState::Spliced(SpoolSpliced {
            prefix_compressed_bytes: prefix,
            etag_at_download: etag,
            committed: Box::new(plan.clone()),
            presplice_len: fp.len,
            presplice_sha256: fp.sha256,
            presplice_prefix512_sha256: fp.prefix512_sha256,
            presplice_suffix512_sha256: fp.suffix512_sha256,
        });
    }

    fn spliced_publish_request(&self) -> Result<RemotePublishRequest> {
        let scheme = self.remote_scheme_label();
        let guard = self.spool.lock().expect("overlay spool");
        let hold = guard.as_ref().ok_or_else(|| {
            OverlayError::Msg(format!("{scheme} publish requested without a spool"))
        })?;
        let SpoolState::Spliced(s) = &hold.state else {
            return Err(OverlayError::Msg(format!(
                "{scheme} publish requested before splice"
            )));
        };
        let window = self.last_patch_window().ok_or_else(|| {
            OverlayError::Msg(format!("{scheme} publish missing the splice patch window"))
        })?;
        Ok(RemotePublishRequest {
            staged: hold.file.path().to_path_buf(),
            prefix_compressed_bytes: s.prefix_compressed_bytes,
            etag_at_download: s.etag_at_download.clone(),
            window,
            skip_object_put: false,
            presplice_len: s.presplice_len,
            presplice_sha256: s.presplice_sha256.clone(),
            presplice_prefix512_sha256: s.presplice_prefix512_sha256.clone(),
            presplice_suffix512_sha256: s.presplice_suffix512_sha256.clone(),
            commit_generation: self.commit_generation(),
        })
    }

    fn take_stashed_plan(&self) -> Result<OverlayCommitPlan> {
        let guard = self.spool.lock().expect("overlay spool");
        match guard.as_ref().map(|h| &h.state) {
            Some(SpoolState::Spliced(s)) => Ok((*s.committed).clone()),
            _ => Err(OverlayError::Msg(
                "s3 commit has no stashed overlay plan".into(),
            )),
        }
    }

    /// Download or keep the spool, splice at most once, leave state `Spliced`
    /// when there is something to upload. `Ok(None)` is an empty plan.
    fn prepare_remote_spool(
        &self,
        idle_for: Option<Duration>,
    ) -> Result<Option<RemotePublishRequest>> {
        let head = self.remote_head()?;
        let same = self.spool_etag_matches(head.etag.as_deref());
        if self.spool_is_spliced() && same {
            log::info!(
                "remote spool still spliced at etag {}; retrying PUT without persist",
                head.etag.as_deref().unwrap_or("-")
            );
            return Ok(Some(self.spliced_publish_request()?));
        }
        if self.spool_is_spliced() {
            // ETag moved after a spliced PUT. The body may already be this spool
            // (client timed out after the server stored it) or a concurrent writer.
            let spool_path = self
                .spool_path_and_downloaded_etag()
                .map(|(p, _, _)| p)
                .ok_or_else(|| OverlayError::Msg("s3 spliced spool missing".into()))?;
            let dl = self.remote_download()?;
            let already = files_same_len_and_hash(dl.file.path(), &spool_path)?;
            if already {
                log::info!(
                    "remote object already matches the spliced spool; skipping persist and object PUT"
                );
                drop(dl);
                let mut req = self.spliced_publish_request()?;
                req.skip_object_put = true;
                return Ok(Some(req));
            }
            log::info!("remote object changed under a spliced spool; splicing onto the new bytes");
            self.drop_spool();
            self.accept_download(dl, head.etag.clone())?;
        } else if !(same && self.spool_path_and_downloaded_etag().is_some()) {
            self.drop_spool();
            let dl = self.remote_download()?;
            self.accept_download(dl, head.etag.clone())?;
        }
        let spool_len = {
            let guard = self.spool.lock().expect("overlay spool");
            match guard.as_ref().map(|h| &h.state) {
                Some(SpoolState::Downloaded(d)) => d.len,
                _ => 0,
            }
        };
        log::debug!("remote spool ready ({spool_len} bytes) before splice");
        let cutoff = idle_for.map(|d| {
            SystemTime::now()
                .checked_sub(d)
                .unwrap_or(SystemTime::UNIX_EPOCH)
        });
        self.replay_pending_or_refuse_commit()?;
        let busy = if cutoff.is_some() {
            match self.write_open_inodes() {
                Some(b) => b,
                None => return Ok(None),
            }
        } else {
            HashSet::new()
        };
        let plan = self.plan_for_commit(cutoff, &busy)?;
        if plan.is_empty() {
            return Ok(None);
        }
        let spool_path = self
            .spool_path_and_downloaded_etag()
            .map(|(p, _, _)| p)
            .ok_or_else(|| OverlayError::Msg("s3 spool missing after download".into()))?;
        let format = detect_live_commit_format(&spool_path)?;
        if format != CompressionFormat::Zstd {
            ensure_gnu_tar()?;
        }
        // Snapshot the downloaded object before splice. Publish compares this
        // to the sidecar so a partial window is not stamped onto a different re-GET.
        let presplice = presplice_fingerprint(&spool_path)?;
        // `earlier_frame_err` returns here. State stays `Downloaded`. No PUT.
        let window = self.persist_by_format(&spool_path, format, &plan)?;
        self.stash_patch_window(window);
        self.mark_spool_spliced(&plan, presplice);
        Ok(Some(self.spliced_publish_request()?))
    }

    fn publish_prepared(&self, req: &RemotePublishRequest) -> Result<()> {
        let scheme = self.remote_scheme_label();
        match self.remote_publish(req) {
            Ok(()) => Ok(()),
            Err(RemotePublishError::EtagMismatch(msg)) => {
                // Do not resplice the old spool. The next tick downloads.
                self.drop_spool();
                Err(OverlayError::Msg(format!(
                    "{scheme} publish precondition failed: {msg}"
                )))
            }
            Err(RemotePublishError::Retryable(msg)) => {
                Err(OverlayError::Msg(format!("{scheme} publish failed: {msg}")))
            }
            Err(RemotePublishError::PointerRefused(msg)) => {
                // The object already contains this splice. Leave the previous
                // pointer. The Ok arm forgets only the stashed plan.
                log::warn!(
                    "{scheme} pointer refused after the object already contained the splice: {msg}"
                );
                Ok(())
            }
        }
    }

    fn commit_remote_interval(
        &self,
        idle_for: Duration,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        let _gate = self.commit_gate.write().expect("overlay commit gate");
        if self.interval_disabled() {
            return Err(interval_disabled_err());
        }
        let Some(req) = self.prepare_remote_spool(Some(idle_for))? else {
            return Ok(false);
        };
        // Publish is a separate `?` before reopen. A 500 must not disable.
        self.publish_prepared(&req)?;
        let staged = req.staged.clone();
        match reopen(&staged) {
            Ok(src) => {
                *self.replacement.write().expect("overlay replacement") = Some(src);
                let plan = self.take_stashed_plan()?;
                // Bump only in this arm, then forget only the stashed plan.
                self.commit_generation.fetch_add(1, Ordering::SeqCst);
                if let Err(e) = self.forget_committed_overlay(&plan) {
                    self.interval_disabled.store(true, Ordering::SeqCst);
                    return Err(OverlayError::Msg(format!(
                        "persist succeeded; overlay cleanup failed (remount required): {e}"
                    )));
                }
                self.drop_spool();
                Ok(true)
            }
            Err(e) => {
                // Object replace already happened. Do not bump or forget.
                self.interval_disabled.store(true, Ordering::SeqCst);
                Err(OverlayError::Msg(format!(
                    "persist succeeded; reopen failed (remount required): {e}"
                )))
            }
        }
    }

    fn commit_atomic_remote(&self) -> Result<bool> {
        let _gate = self.commit_gate.write().expect("overlay commit gate");
        if self.interval_disabled() {
            return Err(interval_disabled_err());
        }
        let Some(req) = self.prepare_remote_spool(None)? else {
            return Ok(false);
        };
        // No reopen. Bump only after the object PUT succeeds. A failure leaves
        // the counter unchanged and does not set `interval_disabled`.
        self.publish_prepared(&req)?;
        let plan = self.take_stashed_plan()?;
        self.commit_generation.fetch_add(1, Ordering::SeqCst);
        self.forget_committed_overlay(&plan)?;
        self.drop_spool();
        Ok(true)
    }

    fn commit_live_inner(
        &self,
        archive: &Path,
        idle_for: Option<Duration>,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        let _gate = self.commit_gate.write().expect("overlay commit gate");
        let archive_path = self.commit_archive_path(archive);
        let archive = archive_path.as_path();
        self.gate_pending_journal(archive)?;
        if let Err(e) = self.recover_journal_after_gate(archive) {
            self.refuse_base_after_commit_failure();
            return Err(e);
        }
        live_commit_is_supported(archive)?;
        let format = detect_live_commit_format(archive)?;
        if format != CompressionFormat::Zstd && self.commit_mode == CommitMode::Copy {
            ensure_gnu_tar()?;
        }
        if self.interval_disabled() {
            return Err(interval_disabled_err());
        }
        let cutoff = idle_for.map(|d| {
            SystemTime::now()
                .checked_sub(d)
                .unwrap_or(SystemTime::UNIX_EPOCH)
        });
        self.replay_pending_or_refuse_commit()?;
        let busy = if cutoff.is_some() {
            match self.write_open_inodes() {
                Some(b) => b,
                None => return Ok(false),
            }
        } else {
            HashSet::new()
        };
        let plan = self.plan_for_commit(cutoff, &busy)?;
        if plan.is_empty() {
            return Ok(false);
        }
        // After `recover` on purpose: recovery only rolls a torn earlier append
        // back to the archive the rows describe, and the identity check then
        // judges that restored file; nothing of this commit is written before it.
        self.check_commit_identity(archive, false)?;
        let target = self.rolling_commit_target(archive, &plan)?;
        let archive = target.as_path();
        let persist_plan = self.rolling_persist_plan(&plan);
        let window = self.persist_by_format(archive, format, &persist_plan)?;
        self.stash_patch_window(window);
        match reopen(archive) {
            Ok(src) => {
                if let Some(series) = &self.rolling {
                    // The existing base wrappers already refer to this mutable series.
                    series.committed(Some(src));
                } else {
                    *self.replacement.write().expect("overlay replacement") = Some(src);
                }
                // Bump before overlay cleanup: readers must drop pre-commit
                // offsets even if forget/reset fails.
                self.commit_generation.fetch_add(1, Ordering::SeqCst);
                let cleanup = if idle_for.is_some() {
                    self.forget_committed_overlay(&plan)
                } else {
                    (|| {
                        let _policy = self.policy_lock();
                        let _account = self.account_reset()?;
                        let wiped = reset_overlay_dir(&self.root).and_then(|_| {
                            self.db
                                .lock()
                                .expect("overlay db")
                                .execute_batch("DELETE FROM files; DELETE FROM xattrs; DELETE FROM overlay_metadata;")?;
                            Ok(())
                        });
                        if wiped.is_ok() {
                            self.tombstone_clear();
                        }
                        wiped
                    })()
                };
                if let Err(e) = cleanup {
                    self.interval_disabled.store(true, Ordering::SeqCst);
                    return Err(OverlayError::Msg(format!(
                        "persist succeeded; overlay cleanup failed (remount required): {e}"
                    )));
                }
                Ok(true)
            }
            Err(e) => {
                if self.commit_mode == CommitMode::Copy {
                    // Copy/rename leaves the old source's inode intact.
                    self.interval_disabled.store(true, Ordering::SeqCst);
                } else {
                    self.refuse_base_after_commit_failure();
                }
                Err(OverlayError::Msg(format!(
                    "persist succeeded; reopen failed (remount required): {e}"
                )))
            }
        }
    }

    /// Drop only the overlay files / tombstones that this idle tick persisted.
    /// Unsettled siblings stay so the next tick can pick them up.
    fn forget_committed_overlay(&self, plan: &OverlayCommitPlan) -> Result<()> {
        let _policy = self.policy_lock();
        let mut dropped_rows = Vec::new();
        // Rows already deleted are forgotten even when a later remove or prune
        // returns. The db lock ends with `cleaned`.
        let cleaned = {
            let db = self.db.lock().expect("overlay db");
            self.forget_committed_overlay_rows(&db, plan, &mut dropped_rows)
        };
        self.tombstone_forget_many(&dropped_rows);
        cleaned
    }

    /// Remove committed overlay files and SQL rows.
    ///
    /// Returns `Err` from a failed remove or from [`prune_empty_overlay_ancestors`]
    /// without skipping rows already pushed onto `dropped_rows`. The caller
    /// forgets those tombstones after dropping the db lock.
    fn forget_committed_overlay_rows(
        &self,
        db: &Connection,
        plan: &OverlayCommitPlan,
        dropped_rows: &mut Vec<String>,
    ) -> Result<()> {
        for path in plan.xattrs.keys().chain(plan.metadata.keys()) {
            db.execute("DELETE FROM xattrs WHERE path=?1", [normpath(path)])?;
            db.execute(
                "DELETE FROM overlay_metadata WHERE path=?1",
                [normpath(path)],
            )?;
        }
        let mut dirs: Vec<&str> = Vec::new();
        for (rel, is_dir) in &plan.append_entries {
            if *is_dir {
                dirs.push(rel.as_str());
                continue;
            }
            let host = self.realpath(rel);
            let _account = self.account_path(rel);
            match fs::remove_file(&host) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            delete_overlay_files_row(db, rel)?;
            dropped_rows.push(rel.clone());
        }
        dirs.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
        for rel in dirs {
            let host = self.realpath(rel);
            // Not empty: a hot child appeared or was skipped. Leave the dir.
            match fs::remove_dir(&host) {
                Ok(()) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::NotFound
                        || e.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                Err(e) => return Err(e.into()),
            }
            delete_overlay_files_row(db, rel)?;
            dropped_rows.push(rel.to_string());
        }
        for rel in &plan.deleted_paths {
            if plan.append_entries.iter().any(|(p, _)| p == rel) {
                continue;
            }
            delete_overlay_files_row(db, rel)?;
            dropped_rows.push(rel.clone());
        }
        // Drop leftover empty parents so a later tick does not persist them
        // as extra TAR directory members. Stop at a dir that still has a
        // hot sibling.
        let mut parents: Vec<String> = plan
            .append_entries
            .iter()
            .filter_map(|(rel, is_dir)| {
                if *is_dir {
                    None
                } else {
                    rel.rsplit_once('/').map(|(p, _)| p.to_string())
                }
            })
            .collect();
        parents.sort();
        parents.dedup();
        parents.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
        for parent in parents {
            prune_empty_overlay_ancestors(&self.root, db, &parent, dropped_rows)?;
        }
        Ok(())
    }

    /// Persist only (on-exit). Thin wrapper over [`Self::commit_atomic`].
    pub fn commit_uncompressed_tar_atomic(&self, archive: &Path) -> Result<bool> {
        self.commit_atomic(archive)
    }

    /// Persist, swap base, and wipe overlay under **one** write lock (interval).
    pub fn commit_live_uncompressed_tar(
        &self,
        archive: &Path,
        reopen: impl FnOnce(&Path) -> Result<Arc<dyn MountSource>>,
    ) -> Result<bool> {
        self.commit_live(archive, reopen)
    }

    fn persist_by_format(
        &self,
        archive: &Path,
        format: CompressionFormat,
        plan: &OverlayCommitPlan,
    ) -> Result<IndexPatchWindow> {
        self.recover_journal(archive)?;
        // The one snapshot every write of this commit compares against: the
        // file the gate accepted (after recovery), never a later stat.
        let original = self.check_commit_identity(archive, true)?;
        self.persist_count.fetch_add(1, Ordering::SeqCst);
        let mut manifest_plan = if self.manifest_hashes.is_some() && !self.remote_enabled() {
            let mut snapshot = plan.clone();
            snapshot.known_hashes = known_manifest_hashes(archive)?;
            Some(snapshot)
        } else {
            None
        };
        let hash_payloads =
            manifest_plan.is_some() && self.manifest_hashes.as_deref() != Some("none");
        let (window, prefix) = if plan.has_metadata_changes() || hash_payloads {
            let window = persist_provenance_plan(
                archive,
                &self.root,
                plan,
                &self.encoding,
                self.commit_mode,
                if hash_payloads {
                    manifest_plan.as_mut().map(|p| &mut p.written_hashes)
                } else {
                    None
                },
                &self.commit_rows(),
                &original,
            );
            // Exactly the ordinary append branches: a splice that landed but
            // could not finish, or left its journal, refuses the stale frame
            // map and stops intervals; any other error wrote nothing.
            match window {
                Ok(window) => (window, 0),
                Err(e @ (OverlayError::Committed(_) | OverlayError::JournalPending(_))) => {
                    self.refuse_base_after_commit_failure();
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        } else {
            match format {
                CompressionFormat::Zstd => {
                    let (window, stats) = self.persist_tar_zst_plan(archive, plan, &original)?;
                    (window, stats.prefix_compressed_bytes)
                }
                // Uncompressed TAR stores 0.
                _ => (
                    self.persist_uncompressed_tar_plan(archive, plan, &original)?,
                    0,
                ),
            }
        };
        if !self.remote_enabled() {
            let identity = self.identity.lock().expect("overlay identity").clone();
            match crate::overlay_meta::refresh_committed_base(
                &self.db.lock().expect("overlay db"),
                identity.as_ref(),
                archive,
            ) {
                // The next commit starts from the re-pointed token.
                Ok(Some(moved)) => *self.identity.lock().expect("overlay identity") = Some(moved),
                Ok(None) => {}
                Err(error) => {
                    self.refuse_base_after_commit_failure();
                    return Err(OverlayError::Msg(format!(
                        "archive committed; baseline refresh failed (remount required): {error}"
                    )));
                }
            }
            if let Some(hashes) = &self.manifest_hashes {
                if let Err(e) = write_commit_manifest(
                    archive,
                    manifest_plan.as_ref().expect("manifest plan"),
                    &self.encoding,
                    hashes,
                ) {
                    self.refuse_base_after_commit_failure();
                    return Err(OverlayError::Msg(format!(
                        "archive committed; manifest failed (remount required): {e}"
                    )));
                }
            }
        }
        self.stash_publish_plan(LivePublishPlan {
            prefix_compressed_bytes: prefix,
        });
        Ok(window)
    }

    #[cfg(test)]
    pub(crate) fn meta_for_tests(&self) -> crate::OverlayMeta {
        crate::OverlayMeta::from_connection(&self.db.lock().expect("overlay db"))
            .expect("read meta")
            .expect("meta table")
    }

    #[cfg(test)]
    pub(crate) fn identity_for_tests(&self) -> Option<crate::ClassifiedBase> {
        self.identity.lock().expect("overlay identity").clone()
    }

    /// Refuse THIS commit, before it writes anything, when the archive is no
    /// longer the base the last create, commit or refresh recorded (under the
    /// commit gate). The mount keeps serving and the interval stays on: unlike
    /// a failed commit, nothing was written. `--force-base-mismatch` commits
    /// anyway (the refresh after the write records the new baseline).
    ///
    /// Returns the gate's one snapshot of the archive (or, when the gate judged
    /// no local archive or was forced, one stat taken right after it): every
    /// write of the commit compares against it. `quiet`: a repeated check that
    /// does not log the forced refusal again.
    fn check_commit_identity(&self, archive: &Path, quiet: bool) -> Result<fs::Metadata> {
        if self.remote_enabled() {
            return Ok(fs::metadata(archive)?);
        }
        let Some(base) = self.identity.lock().expect("overlay identity").clone() else {
            return Ok(fs::metadata(archive)?);
        };
        let checked = crate::overlay_gate::check_commit_base(
            &self.db.lock().expect("overlay db"),
            &base,
            archive,
        );
        match checked {
            Ok(Some(snapshot)) => Ok(snapshot),
            Ok(None) => Ok(fs::metadata(archive)?),
            Err(refusal) if self.force_base_mismatch => {
                if !quiet {
                    log::warn!("{refusal} (--force-base-mismatch: committing anyway)");
                }
                Ok(fs::metadata(archive)?)
            }
            Err(refusal) => Err(OverlayError::Msg(refusal.0)),
        }
    }

    /// Before recovery touches the archive: a pending commit journal may only be
    /// rolled back when the archive is still the base this overlay recorded.
    /// A foreign archive that carries its own interrupted journal (a replacement
    /// moved over the mounted base) is refused here, byte-identical, instead of
    /// being restored or truncated and only then rejected. Recovery still runs
    /// first for the overlay's own torn append: its journal describes the
    /// recorded state. `--force-base-mismatch` accepts the foreign archive.
    fn gate_pending_journal(&self, archive: &Path) -> Result<()> {
        match ratarmount_compress::commit_journal::pending(archive) {
            Ok(None) => Ok(()),
            Ok(Some(_)) | Err(_) => self.check_commit_identity(archive, false).map(drop),
        }
    }

    /// The one recovery entry for this overlay: the gate first (for its
    /// message), then recovery whose authorizer re-takes the same decision on
    /// the LOCKED file. A complete journal is rolled forward and the rows
    /// restamped (a strong digest `pending`) BEFORE the journal is unlinked.
    /// Recover `archive`'s pending journal AFTER every gate accepted the mount
    /// (a member whose journal the mount-time classifier deferred). Runs
    /// through this overlay's own connection: it holds its database exclusively.
    pub fn recover_member_journal(&self, archive: &Path) -> Result<()> {
        self.recover_journal(archive).map(|_| ())
    }

    fn recover_journal(
        &self,
        archive: &Path,
    ) -> Result<Option<ratarmount_compress::commit_journal::Applied>> {
        self.gate_pending_journal(archive)?;
        self.recover_journal_after_gate(archive)
    }

    /// Where a fresh replacement restamps the recorded base before it unlinks
    /// its journal: this mount's own connection.
    fn commit_rows(&self) -> crate::journal_recovery::Rows<'_> {
        if self.remote_enabled() {
            crate::journal_recovery::Rows::None
        } else {
            crate::journal_recovery::Rows::Shared(&self.db)
        }
    }

    fn recover_journal_raw(
        &self,
        archive: &Path,
    ) -> std::result::Result<
        Option<ratarmount_compress::commit_journal::Applied>,
        ratarmount_compress::commit_journal::RecoverError,
    > {
        use crate::journal_recovery::{Owner, Record};
        let identity = if self.remote_enabled() {
            None
        } else {
            self.identity.lock().expect("overlay identity").clone()
        };
        let owner = match &identity {
            _ if self.force_base_mismatch => Owner::Forced,
            Some(base) => Owner::Recorded {
                base,
                archive,
                record: Record::Live(&self.db),
            },
            None => Owner::Inode,
        };
        crate::journal_recovery::recover_journal(archive, self.commit_rows(), owner)
    }

    fn recover_journal_after_gate(
        &self,
        archive: &Path,
    ) -> Result<Option<ratarmount_compress::commit_journal::Applied>> {
        use ratarmount_compress::commit_journal::RecoverError;
        self.recover_journal_raw(archive)
            .map_err(|error| match error {
                RecoverError::Committed(e) => {
                    self.refuse_base_after_commit_failure();
                    OverlayError::Msg(format!(
                        "{e}; the archive holds the committed bytes but the recorded baseline \
                     could not be updated (remount required)"
                    ))
                }
                other => OverlayError::Io(other.into_io()),
            })
    }

    /// The recorded base digest kind and digest, read through the mount's own
    /// connection.
    #[cfg(test)]
    pub(crate) fn recorded_digest_for_tests(&self) -> (Option<String>, Option<String>) {
        let conn = self.db.lock().expect("overlay db");
        let meta = crate::OverlayMeta::from_connection(&conn)
            .expect("overlay meta")
            .expect("overlay meta present");
        (
            meta.base_digest_kind().map(str::to_owned),
            meta.base_digest().map(str::to_owned),
        )
    }

    /// The recorded base stamp rows, read through the mount's own connection.
    #[cfg(test)]
    pub(crate) fn recorded_stamp_for_tests(&self) -> (Option<String>, Option<String>) {
        let conn = self.db.lock().expect("overlay db");
        let meta = crate::OverlayMeta::from_connection(&conn)
            .expect("overlay meta")
            .expect("overlay meta present");
        (
            meta.get("base_size").map(str::to_owned),
            meta.get("base_mtime_ns").map(str::to_owned),
        )
    }

    fn refuse_base_after_commit_failure(&self) {
        self.interval_disabled.store(true, Ordering::SeqCst);
        *self.replacement.write().expect("overlay replacement") =
            Some(Arc::new(FailedCommitSource));
        self.commit_generation.fetch_add(1, Ordering::SeqCst);
    }

    /// The one reaction to a failed journaled replacement on a live mount.
    /// `Ok(from)`: nothing of the attempt remains and the mode allows a copy,
    /// which the caller then reads by the rule `from` names and publishes
    /// through the copy guard. Committed bytes or a pending journal stop
    /// interval commits until a remount.
    fn after_failed_replace(
        &self,
        failed: crate::journal_recovery::FailedReplace,
    ) -> Result<crate::journal_recovery::CopyFrom> {
        if failed.base_unusable {
            self.refuse_base_after_commit_failure();
            return Err(failed.error);
        }
        if failed.may_copy && self.commit_mode == CommitMode::Auto {
            log::warn!(
                "commit: append failed: {}; falling back to copy",
                failed.error
            );
            return Ok(failed.copy_from());
        }
        Err(failed.error)
    }

    /// Last-N zstd frame rewrite. Never calls GNU tar (K3).
    ///
    /// Returns [`SpliceStats`] from this splice. `prefix_compressed_bytes` is
    /// the pre-splice `frames[from_idx].compressed_offset`, not a rescan.
    fn persist_tar_zst_plan(
        &self,
        archive: &Path,
        plan: &OverlayCommitPlan,
        original: &fs::Metadata,
    ) -> Result<(IndexPatchWindow, SpliceStats)> {
        let map = scan_zstd_frames_path(archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
        let (from_idx, rewrite_window_start_uncomp) =
            find_last_n_tar_window(archive, &map, "live")?;
        // Do not classify against `current_base()`: a remount without `-i`
        // hides later complete-TAR frames, so those tombstones look
        // overlay-only, the splice skips them, and interval cleanup
        // forgets the delete (same class as offline #32).
        let mut last_window_deletes = HashSet::new();
        let mut append = !self.remote_enabled()
            && self.commit_mode.may_append(archive)?
            && map.seek_table.is_some();
        if !plan.deleted_paths.is_empty() || append {
            let classify_base = tar_zst_full_frame_index(archive, self.encoding.as_str())?;
            append &= plan
                .append_entries
                .iter()
                .all(|(p, _)| classify_base.lookup(&archive_lookup_path(p), 0).is_none());
            for path in &plan.deleted_paths {
                match classify_tar_zst_path(&classify_base, path, rewrite_window_start_uncomp)? {
                    TarZstPathClass::OverlayOnly => {}
                    TarZstPathClass::LastWindow => {
                        last_window_deletes.insert(path.clone());
                    }
                }
            }
        }
        let pending = self.collect_ustar_pending(&plan.append_entries)?;
        // Captured during the splice (pre-write map). Do not rescan `archive`.
        let transform = |mut suffix: &mut dyn ratarmount_compress::SeekRead,
                         stream_offset,
                         mut out: &mut dyn Write| {
            let members: Vec<UstarMember<'_>> =
                pending.iter().map(PendingUstar::as_member).collect();
            let opts = RewriteTarSuffix {
                deleted_paths: &last_window_deletes,
                append: &members,
                encoding: self.encoding.as_str(),
            };
            rewrite_tar_suffix(&mut suffix, stream_offset, &opts, &mut out).map(|_| ())
        };
        let stats = if append && last_window_deletes.is_empty() {
            match crate::journal_recovery::splice_append_committing(
                archive,
                from_idx,
                transform,
                original,
                &self.commit_rows(),
            ) {
                Ok(stats) => stats,
                Err(failed) => {
                    let from = self.after_failed_replace(failed)?;
                    crate::journal_recovery::splice_replace_over(
                        archive, from_idx, transform, original, from,
                    )?
                }
            }
        } else {
            crate::journal_recovery::splice_replace_over(
                archive,
                from_idx,
                transform,
                original,
                crate::journal_recovery::CopyFrom::Gate,
            )?
        };
        Ok((
            IndexPatchWindow {
                window_start: rewrite_window_start_uncomp,
                from_frame: Some(from_idx),
                offsets_shifted: false,
            },
            stats,
        ))
    }

    fn collect_ustar_pending(
        &self,
        append_entries: &[(String, bool)],
    ) -> Result<Vec<PendingUstar>> {
        collect_ustar_pending_at(&self.root, append_entries)
    }

    /// Confinement for rename endpoints: `rename(2)` never follows symlinks,
    /// so a symlink final component only needs a confined parent (the plain
    /// `ensure_under_root` rejects final symlinks — an anti-escape policy for
    /// open/read/write that does not apply here).
    fn ensure_rename_confined(&self, host_path: &Path) -> Result<()> {
        match fs::symlink_metadata(host_path) {
            Ok(meta) if meta.file_type().is_symlink() => self
                .ensure_parent_confined(host_path)
                .map_err(OverlayError::Io),
            _ => self.ensure_under_root(host_path).map_err(OverlayError::Io),
        }
    }

    /// Confine a symlink's parent without following the final component.
    fn ensure_parent_confined(&self, host_path: &Path) -> io::Result<()> {
        ensure_overlay_parent_confined(&self.root, host_path)
    }

    fn persist_uncompressed_tar_plan(
        &self,
        archive: &Path,
        plan: &OverlayCommitPlan,
        original: &fs::Metadata,
    ) -> Result<IndexPatchWindow> {
        let mut copy_from = crate::journal_recovery::CopyFrom::Gate;
        if self.commit_mode.may_append(archive)? {
            match append_uncompressed_tar_plan(
                archive,
                &self.root,
                plan,
                &self.encoding,
                &self.commit_rows(),
                original,
            ) {
                Ok(Some(window)) => return Ok(window),
                Ok(None) => {}
                Err(failed) => copy_from = self.after_failed_replace(failed)?,
            }
        }
        ensure_gnu_tar()?;
        // Record GNU `--append` window from the two-zero EOF **before** tar runs.
        // `metadata().len()` includes EOF padding; parse would start after the
        // appended members.
        let classify_base = self
            .rolling
            .as_ref()
            .map_or_else(|| self.current_base(), |series| series.active_source());
        let window = uncompressed_patch_window(archive, classify_base.as_ref(), plan)?;
        let parent = archive
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let (mut src, source) =
            crate::journal_recovery::open_copy_source(archive, original, copy_from)?;
        let (tmp, method) = ratarmount_compress::fastcopy::copy_to_temp(&mut src, parent)?;
        ratarmount_compress::fastcopy::log_commit_copy(source.len(), method);
        tmp.as_file().sync_all()?;
        let work_tar = tmp.path().to_path_buf();
        let list_dir = tempfile::tempdir()?;
        let deletion_list = list_dir.path().join("deletions.lst");
        let append_list = list_dir.path().join("append.lst");
        fs::write(&deletion_list, &plan.deletions_nul)?;
        fs::write(&append_list, &plan.appends_nul)?;
        if !plan.deletions_nul.is_empty() {
            let output = tar_env_command()
                .args([
                    "--delete",
                    "--ignore-zeros",
                    "--null",
                    &format!("--files-from={}", deletion_list.display()),
                    "--file",
                ])
                .arg(&work_tar)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            let unfiltered: Vec<&str> = stderr
                .lines()
                .filter(|line| {
                    let line = line.trim();
                    !line.is_empty()
                        && !line.contains("tar: Exiting with failure")
                        && !line.contains("Not found in archive")
                })
                .collect();
            if !unfiltered.is_empty() {
                for line in &unfiltered {
                    eprintln!("{line}");
                }
                return Err(gnu_tar_delete_problems_err(&unfiltered));
            }
        }
        if !plan.appends_nul.is_empty() {
            let status = tar_env_command()
                .args(["--append", "--ignore-zeros", "-C"])
                .arg(&self.root)
                .args([
                    "--null",
                    &format!("--files-from={}", append_list.display()),
                    "--file",
                ])
                .arg(&work_tar)
                .status()?;
            if !status.success() {
                return Err(OverlayError::Msg(format!(
                    "tar --append failed with {status}"
                )));
            }
        }
        tmp.as_file().sync_all()?;
        crate::journal_recovery::publish_over(archive, &source, || {
            tmp.persist(archive).map(drop).map_err(|e| e.error)
        })
        .map_err(|e| {
            OverlayError::Msg(format!(
                "Failed to replace '{}' after live TAR commit: {e}",
                archive.display(),
            ))
        })?;
        Ok(window)
    }

    fn account_reset(&self) -> Result<Vec<PolicyAccounting<'_>>> {
        if self.policy.is_none() {
            return Ok(Vec::new());
        }
        #[cfg(test)]
        if self.account_reset_failure.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected read_dir failure").into());
        }
        let mut accounts = Vec::new();
        let mut dirs = vec![("/".to_string(), self.root.clone())];
        while let Some((path, host)) = dirs.pop() {
            for entry in fs::read_dir(host)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if is_overlay_internal_name(&name) {
                    continue;
                }
                let child = join(&path, &name);
                if entry.file_type()?.is_dir() {
                    dirs.push((child.clone(), entry.path()));
                }
                if let Some(account) = self.account_path(&child) {
                    accounts.push(account);
                }
            }
        }
        Ok(accounts)
    }

    /// Remove overlay files (except the hidden DB) and clear deletion/present rows.
    pub fn reset_overlay_contents(&self) -> Result<()> {
        let _gate = self.commit_gate.write().expect("overlay commit gate");
        let _policy = self.policy_lock();
        self.check_mutation(OverlayMutation::Reset, &["/"])?;
        let _account = self.account_reset()?;
        for account in &_account {
            self.check_mutation(OverlayMutation::Unlink, &[&account.path])?;
        }
        reset_overlay_dir(&self.root)?;
        {
            // Queue then database. A later replay must not resurrect rows
            // this reset just deleted.
            let mut pending = self.pending_rows.lock().expect("overlay pending rows");
            pending.clear();
            let db = self.db.lock().expect("overlay db");
            db.execute_batch(
                "DELETE FROM files; DELETE FROM xattrs; DELETE FROM overlay_metadata;",
            )?;
        }
        self.tombstone_clear();
        Ok(())
    }

    fn overlay_file_info(&self, path: &str) -> Option<FileInfo> {
        let real = self.realpath(path);
        // symlink_metadata so a dangling overlay symlink is still visible.
        let meta = fs::symlink_metadata(&real).ok()?;
        let mut fi = file_info_from_overlay_meta(path, &real, &meta);
        // Seal preserves visible permissions here before chmod removes host write bits.
        if let Some(mode) = self.metadata_for_path(path).and_then(|m| m.mode) {
            fi.mode = (fi.mode & !0o7777) | (mode & 0o7777);
        }
        Some(fi)
    }
}

impl Drop for WriteOverlay {
    fn drop(&mut self) {
        // Recover poisoned locks. A panic here aborts the process.
        // `std::process::exit` skips this; callers drop the overlay first.
        self.replay_pending_on_drop();
    }
}

fn validate_metadata(attrs: &OverlayMetadata) -> io::Result<()> {
    if attrs.uid.is_some() || attrs.gid.is_some() {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    for time in [attrs.atime, attrs.mtime].into_iter().flatten() {
        if !time.is_finite() || !(-9e15..9e15).contains(&time) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
    }
    Ok(())
}

fn metadata_from_info(fi: &FileInfo) -> OverlayMetadata {
    OverlayMetadata {
        mode: Some(fi.mode),
        atime: Some(overlay_atime(fi)),
        mtime: Some(fi.mtime),
        ..Default::default()
    }
}

#[cfg(unix)]
fn metadata_times(attrs: &OverlayMetadata) -> [libc::timespec; 2] {
    [attrs.atime, attrs.mtime].map(|t| match t {
        Some(t) => libc::timespec {
            tv_sec: t.floor() as libc::time_t,
            tv_nsec: ((t - t.floor()) * 1e9) as libc::c_long,
        },
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    })
}

fn set_host_metadata(path: &Path, attrs: &OverlayMetadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        // Never chmod through a symlink, even one pointing back into the overlay.
        if let Some(mode) = attrs.mode {
            if fs::symlink_metadata(path)?.file_type().is_symlink() {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            let path = c_path(path)?;
            if unsafe {
                libc::fchmodat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    (mode & 0o7777) as libc::mode_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        if attrs.atime.is_some() || attrs.mtime.is_some() {
            let times = metadata_times(attrs);
            let path = c_path(path)?;
            if unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, attrs);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "overlay metadata requires Unix",
        ))
    }
}

/// Mode and times on an open staging file. No owner or xattr changes.
/// The descriptor is the inode, so a concurrent path rename cannot retarget it.
#[cfg(unix)]
fn set_host_metadata_file(file: &File, attrs: &OverlayMetadata) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if let Some(mode) = attrs.mode {
        // SAFETY: `fchmod` only changes permission bits on this open file.
        if unsafe { libc::fchmod(file.as_raw_fd(), (mode & 0o7777) as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        let times = metadata_times(attrs);
        // SAFETY: `futimens` writes two timespecs for this open file.
        if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn file_info_from_overlay_meta(
    path: &str,
    host: &Path,
    meta: &fs::Metadata,
) -> FileInfo {
    let linkname = if meta.file_type().is_symlink() {
        fs::read_link(host)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let mut fi = FileInfo {
        size: meta.len(),
        mtime: metadata_mtime_secs(meta) as f64,
        mode: metadata_mode(meta),
        linkname,
        uid: metadata_uid(meta),
        gid: metadata_gid(meta),
        userdata: vec![UserData::Other(format!("overlay:{path}"))],
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fi.mtime = meta.mtime() as f64 + meta.mtime_nsec() as f64 / 1e9;
        set_info_atime(
            &mut fi,
            meta.atime() as f64 + meta.atime_nsec() as f64 / 1e9,
        );
    }
    fi
}

fn parked_meta(last_fi: FileInfo) -> Parked {
    Parked {
        #[cfg(unix)]
        fd: None,
        last_fi,
    }
}

#[cfg(unix)]
fn parked_fd(last_fi: FileInfo, fd: std::os::unix::io::OwnedFd) -> Parked {
    Parked {
        fd: Some(fd),
        last_fi,
    }
}

/// Overlay host regular files that are not catalog flatten payloads.
///
/// Concatenate after [`ratarmount_index::SqliteIndex::list_visible_files_by_offset`]
/// and open via [`WriteOverlay::has_file`] / overlay fd. No archive offset.
pub fn overlay_only_names(ov: &WriteOverlay) -> Vec<String> {
    let tombstones = ov.load_tombstone_paths();
    let mut names = Vec::new();
    for_each_overlay_host_non_dir(
        ov,
        "/",
        &ov.root,
        &tombstones,
        &mut |child_mount, _, meta| {
            if !meta.file_type().is_file() {
                return;
            }
            // Only flatten payloads (S_IFREG, empty linkname, not generated) already
            // have an archive offset. A regular overlay file that replaces a
            // symlink / hardlink / generated dir is overlay-only.
            if base_is_flatten_payload(ov, &child_mount) {
                return;
            }
            names.push(child_mount);
        },
    );
    names.sort();
    names
}

/// Same host walk as live search: confinement, no symlink-dir recurse, skip DB / tombstones.
fn for_each_overlay_host_non_dir(
    ov: &WriteOverlay,
    mount_dir: &str,
    host_dir: &Path,
    tombstones: &HashSet<String>,
    visit: &mut dyn FnMut(String, String, fs::Metadata),
) {
    if ov.ensure_under_root(host_dir).is_err() {
        return;
    }
    let meta = match fs::symlink_metadata(host_dir) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return;
    }
    let rd = match fs::read_dir(host_dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if is_overlay_internal_name(&name) {
            continue;
        }
        let child_mount = join(mount_dir, &name);
        if tombstones.contains(&child_mount) {
            continue;
        }
        let child_host = host_dir.join(&name);
        if ov.ensure_under_root(&child_host).is_err() {
            continue;
        }
        let child_meta = match fs::symlink_metadata(&child_host) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if child_meta.file_type().is_dir() && !child_meta.file_type().is_symlink() {
            for_each_overlay_host_non_dir(ov, &child_mount, &child_host, tombstones, visit);
            continue;
        }
        visit(child_mount, name, child_meta);
    }
}

/// Flatten payload: `S_IFREG`, empty `linkname`, not generated. Matches
/// `list_visible_files_by_offset` membership without using `SqliteIndex`.
fn base_is_flatten_payload(ov: &WriteOverlay, path: &str) -> bool {
    let Some(fi) = ov.current_base().lookup(path, 0) else {
        return false;
    };
    if fi.mode & ratarmount_core::S_IFMT != ratarmount_core::S_IFREG || !fi.linkname.is_empty() {
        return false;
    }
    // `userdata.last()` is the current layer (FileVersionLayer / AutoMount tag),
    // not Tar — same scan as automount / union / live-commit (K1).
    let generated = fi
        .userdata
        .iter()
        .rev()
        .find_map(|u| match u {
            UserData::Tar(t) => Some(t.isgenerated),
            _ => None,
        })
        .unwrap_or(false);
    !generated
}

/// Existing on-disk sidecar persist may patch. Never created here (`:memory:` → `None`).
pub fn sidecar_path_for_patch(archive: &Path, opts: &OpenOptions) -> Option<PathBuf> {
    if opts.index_in_memory {
        return None;
    }
    let explicit = opts
        .index_file_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    if explicit
        .as_deref()
        .is_some_and(|s| s.trim() == MEMORY_INDEX)
    {
        return None;
    }
    match resolve_index_location(archive, explicit.as_deref(), &opts.index_folders, false) {
        IndexLocation::Memory => None,
        IndexLocation::Path(p) if p.is_file() => Some(p),
        IndexLocation::Path(_) => None,
    }
}

/// Patch `{archive}.index.sqlite` (or `--index-file`) after persist. No-op when missing.
///
/// One `BEGIN IMMEDIATE` around delete + suffix parse + tarstats + `set_zstd_blocks`.
/// Never [`SqliteIndex::create_writable`]. Parse-time zstd is a fresh frame scan
/// ([`open_seekable_zstd_with_threads`]), never pre-splice `zstdblocks`.
pub fn patch_sidecar_if_present(
    archive: &Path,
    window: &IndexPatchWindow,
    opts: &OpenOptions,
) -> Result<()> {
    let Some(sidecar) = sidecar_path_for_patch(archive, opts) else {
        log::info!("incremental reindex skipped (no sidecar); rebuilding");
        return Ok(());
    };
    let idx = SqliteIndex::open_writable(&sidecar).map_err(|e| OverlayError::Msg(e.to_string()))?;
    idx.begin_write()
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    let format = detect_live_commit_format(archive)?;
    // Live persist can rewrite a window that still contains an interior TAR
    // EOF (concatenated complete TARs, or one zstd frame holding them).
    // `parse_tar_from` with the mount's `ignore_zeros: false` stops there and
    // drops later members — including newly appended overlay files. Offline
    // splice already forces `ignore_zeros: true`; live must match for every
    // format that patches a sidecar (zstd and uncompressed TAR).
    let mut patch_opts = opts.clone();
    patch_opts.ignore_zeros = true;
    let stats = match format {
        CompressionFormat::Zstd => {
            let threads = patch_opts.threads_for("zstd");
            let body = open_seekable_zstd_with_threads(archive, threads)
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            let mut reader = body
                .open_reader()
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            SqliteIndexedTar::patch_index_from(
                &mut reader,
                &idx,
                &patch_opts,
                window.window_start,
                env!("CARGO_PKG_VERSION"),
            )
            .map_err(|e| OverlayError::Msg(e.to_string()))?
        }
        _ => {
            let mut file = File::open(archive)?;
            SqliteIndexedTar::patch_index_from(
                &mut file,
                &idx,
                &patch_opts,
                window.window_start,
                env!("CARGO_PKG_VERSION"),
            )
            .map_err(|e| OverlayError::Msg(e.to_string()))?
        }
    };
    idx.store_tarstats_for_path(archive)
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    if format == CompressionFormat::Zstd {
        let blocks = export_zstd_blocks(archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
        let i64_blocks: Vec<(i64, i64)> =
            blocks.iter().map(|&(c, d)| (c as i64, d as i64)).collect();
        idx.set_zstd_blocks(&i64_blocks)
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
    }
    if !opts.hashes.is_empty() && format == CompressionFormat::None {
        fill_content_hashes(&idx, archive, &opts.hashes)
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
    }
    idx.commit_write()
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    // The mount holds a read-only connection. Checkpoint until the main file
    // has the patched rows, then drop the writer before the caller hashes it.
    idx.wal_checkpoint_truncate()
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    drop(idx);
    log::info!(
        "incremental reindex {} window_start={} deleted={} inserted={} parse_start={}",
        archive.display(),
        window.window_start,
        stats.rows_deleted,
        stats.rows_inserted,
        stats.parse_start
    );
    Ok(())
}

/// Pointer JSON for a sidecar the caller has already patched.
///
/// Uses [`IndexPointer::for_blob`]. Call after [`patch_sidecar_if_present`]:
/// the id is SHA-256 of the sidecar bytes, so an unpatched file is a different id.
#[cfg(test)]
fn index_pointer_plan_after_patch(
    sidecar: &Path,
    archive: Option<&Path>,
) -> Result<IndexPointerPlan> {
    let pointer =
        IndexPointer::for_blob(sidecar, archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
    let json = index_pointer_to_json(&pointer).map_err(|e| OverlayError::Msg(e.to_string()))?;
    Ok(IndexPointerPlan { pointer, json })
}

fn uncompressed_patch_window(
    archive: &Path,
    base: &dyn MountSource,
    plan: &OverlayCommitPlan,
) -> Result<IndexPatchWindow> {
    let mut window_start = 0u64;
    let mut offsets_shifted = false;
    if !plan.deleted_paths.is_empty() {
        match classify_deleted_offsetheaders(base, &plan.deleted_paths) {
            DeletedOffsetClass::From(min_oh) => {
                window_start = min_oh;
                offsets_shifted = true;
            }
            // AutoMount (and similar wrappers) can hide TAR userdata, so a real
            // archive delete looks unclassifiable. GNU tar --delete still
            // removes the member. Patching from EOF would keep the stale
            // sidecar row (ghost file / wrong bytes on warm remount).
            DeletedOffsetClass::Unclassified => {
                window_start = 0;
                offsets_shifted = true;
            }
            DeletedOffsetClass::None => {}
        }
    }
    let eof = {
        let mut old = File::open(archive)?;
        find_last_tar_eof(&mut old, 0)?.unwrap_or(0)
    };
    if !plan.append_entries.is_empty() {
        if offsets_shifted {
            window_start = window_start.min(eof);
        } else {
            window_start = eof;
        }
    }
    Ok(IndexPatchWindow {
        window_start,
        from_frame: None,
        offsets_shifted,
    })
}

/// How deleted overlay paths map onto TAR `offsetheader`s in `base`.
enum DeletedOffsetClass {
    /// Overlay-only names (replace of a file that is not in the archive).
    None,
    /// Earliest classified archive `offsetheader`.
    From(u64),
    /// At least one path exists in `base` but has no TAR `offsetheader`.
    Unclassified,
}

fn classify_deleted_offsetheaders(
    base: &dyn MountSource,
    deleted: &HashSet<String>,
) -> DeletedOffsetClass {
    let mut min_oh: Option<u64> = None;
    let mut unclassified = false;
    for path in deleted {
        match all_tar_offsetheaders(base, path) {
            Ok(ohs) => {
                for oh in ohs {
                    min_oh = Some(match min_oh {
                        Some(m) => m.min(oh),
                        None => oh,
                    });
                }
            }
            Err(_) => unclassified = true,
        }
    }
    if unclassified {
        DeletedOffsetClass::Unclassified
    } else if let Some(oh) = min_oh {
        DeletedOffsetClass::From(oh)
    } else {
        DeletedOffsetClass::None
    }
}

impl MountSource for WriteOverlay {
    fn list(&self, path: &str) -> Option<ListResult> {
        if is_overlay_internal_path(path) {
            return None;
        }
        let path = normpath(path);
        if self.is_deleted(&path) && path != "/" {
            return None;
        }
        let deleted: std::collections::HashSet<String> =
            self.list_deleted(&path).into_iter().collect();

        let mut map = std::collections::BTreeMap::new();

        if let Some(base_list) = self.current_base().list(&path) {
            match base_list {
                ListResult::Infos(m) => {
                    for (k, v) in m {
                        if !deleted.contains(&k) && !is_overlay_internal_name(&k) {
                            map.insert(k, v);
                        }
                    }
                }
                ListResult::Names(names) => {
                    for name in names {
                        if deleted.contains(&name) || is_overlay_internal_name(&name) {
                            continue;
                        }
                        let full = join(&path, &name);
                        if let Some(fi) = self.current_base().lookup(&full, 0) {
                            map.insert(name, fi);
                        }
                    }
                }
            }
        }

        // Overlay folder entries
        let real = self.realpath(&path);
        if let Ok(rd) = fs::read_dir(&real) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if is_overlay_internal_name(&name) || deleted.contains(&name) {
                    continue;
                }
                let full = join(&path, &name);
                if let Some(fi) = self.overlay_file_info(&full) {
                    map.insert(name, fi);
                }
            }
        }

        if path == "/" || !map.is_empty() || self.current_base().is_dir(&path) {
            for (name, fi) in &mut map {
                if overlay_info_path(fi).is_none() {
                    self.apply_metadata(&join(&path, name), fi);
                    fi.userdata.push(UserData::Other(format!(
                        "overlay-meta:{}",
                        join(&path, name)
                    )));
                }
            }
            Some(ListResult::Infos(map))
        } else {
            None
        }
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        if is_overlay_internal_path(path) {
            return None;
        }
        let path = normpath(path);
        if self.is_deleted(&path) && path != "/" {
            return None;
        }
        let deleted: HashSet<String> = self.list_deleted(&path).into_iter().collect();
        let mut by_name: BTreeMap<String, CheapDirent> = BTreeMap::new();

        if let Some(base_dents) = self.current_base().list_dirents(&path) {
            for mut d in base_dents {
                if !deleted.contains(&d.name) && !is_overlay_internal_name(&d.name) {
                    if let Some(attrs) = self.metadata_for_path(&join(&path, &d.name)) {
                        if let Some(mode) = attrs.mode {
                            d.mode = (d.mode & !0o7777) | (mode & 0o7777);
                        }
                    }
                    by_name.insert(d.name.clone(), d);
                }
            }
        }

        let real = self.realpath(&path);
        if let Ok(rd) = fs::read_dir(&real) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if is_overlay_internal_name(&name) || deleted.contains(&name) {
                    continue;
                }
                let full = join(&path, &name);
                if let Some(fi) = self.overlay_file_info(&full) {
                    by_name.insert(
                        name.clone(),
                        CheapDirent {
                            name,
                            mode: fi.mode,
                            size: fi.size,
                        },
                    );
                }
            }
        }

        if path == "/" || !by_name.is_empty() || self.current_base().is_dir(&path) {
            Some(by_name.into_values().collect())
        } else {
            None
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        if is_overlay_internal_path(path) {
            return None;
        }
        let dents = self.list_dirents(path)?;
        Some(ListModeResult::Modes(
            dents.into_iter().map(|d| (d.name, d.mode)).collect(),
        ))
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return None;
        }
        let base_hits = self.current_base().search_cheap(pattern)?;
        Some(self.merge_search_hits(base_hits, pattern))
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        if is_overlay_internal_path(path) {
            return None;
        }
        let path = normpath(path);
        if path == "/" {
            let mut fi = create_root_file_info();
            fi.userdata.push(UserData::Other("overlay-meta:/".into()));
            self.apply_metadata(&path, &mut fi);
            return Some(fi);
        }
        if self.is_deleted(&path) {
            return None;
        }
        if let Some(fi) = self.overlay_file_info(&path) {
            return Some(fi);
        }
        self.current_base()
            .lookup(&path, file_version)
            .map(|mut fi| {
                self.apply_metadata(&path, &mut fi);
                fi.userdata
                    .push(UserData::Other(format!("overlay-meta:{path}")));
                fi
            })
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        // Prefer overlay path if tagged
        if let Some(UserData::Other(s)) = file_info.userdata.last() {
            if let Some(path) = s.strip_prefix("overlay:") {
                let real = self.realpath(path);
                self.ensure_under_root(&real)?;
                let mut opts = open_options_nofollow();
                opts.read(true);
                match opts.open(&real) {
                    Ok(f) => return Ok(Box::new(f)),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        // Live commit wiped the overlay file; serve from the new base.
                        if let Some(fi) = self.current_base().lookup(path, 0) {
                            return self.current_base().open(&fi, buffering);
                        }
                        return Err(e);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        self.current_base()
            .open(&without_overlay_meta(file_info), buffering)
    }

    fn is_immutable(&self) -> bool {
        false
    }

    fn content_generation(&self) -> u64 {
        // Own commit counter dominates; forward the base in case an inner
        // mutable source (stacked overlay) also changes under us.
        self.commit_generation
            .load(Ordering::SeqCst)
            .saturating_add(self.base.content_generation())
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        if let Some(UserData::Other(s)) = file_info.userdata.last() {
            if s.starts_with("overlay:") {
                return true;
            }
        }
        self.current_base()
            .member_seek_is_cheap(&without_overlay_meta(file_info))
    }

    fn list_xattr(&self, file_info: &FileInfo) -> Vec<String> {
        if let Some(path) = overlay_info_path(file_info) {
            return self
                .xattrs_for_path(path)
                .unwrap_or_default()
                .into_keys()
                .collect();
        }
        self.current_base().list_xattr(file_info)
    }

    fn get_xattr(&self, file_info: &FileInfo, key: &str) -> Option<Vec<u8>> {
        if let Some(path) = overlay_info_path(file_info) {
            return self.xattrs_for_path(path).ok()?.remove(key);
        }
        self.current_base().get_xattr(file_info, key)
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_MANIFEST_PUBLISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, not(windows)))]
thread_local! {
    static FAIL_COW_DIR_FSYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Capture reusable hashes before suffix patching removes their old offset rows.
fn known_manifest_hashes(archive: &Path) -> Result<BTreeMap<String, String>> {
    let sidecar = ratarmount_index::default_index_path(archive);
    if !sidecar.is_file() {
        return Ok(BTreeMap::new());
    }
    let idx =
        SqliteIndex::open_read_only(&sidecar).map_err(|e| OverlayError::Msg(e.to_string()))?;
    if idx.check_tarstats_matches_archive(archive).is_err() {
        return Ok(BTreeMap::new());
    }
    let mut out = BTreeMap::new();
    let mut cursor: Option<(String, Option<i64>)> = None;
    loop {
        let query = ratarmount_index::SearchQuery {
            include_hashes: true,
            after: cursor
                .as_ref()
                .map(|(path, offset)| ratarmount_index::FindAfter {
                    fullpath: path,
                    offsetheader: *offset,
                }),
            ..ratarmount_index::SearchQuery::glob("*")
        };
        let hits = idx
            .search_query(&query)
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
        let done = hits.len() < DEFAULT_SEARCH_LIMIT;
        if let Some(last) = hits.last() {
            cursor = Some((last.path.clone(), last.offsetheader));
        }
        for hit in hits {
            let current = idx
                .lookup(&hit.path, 0)
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
            if !current.is_some_and(|fi| {
                hit.offsetheader
                    .is_some_and(|oh| tar_offsetheaders_in(&fi).any(|offset| offset == oh as u64))
            }) {
                continue;
            }
            if let Some((_, hash)) = hit.hashes.into_iter().find(|(name, value)| {
                name == "user.hash.sha256"
                    && value.len() == 64
                    && value.bytes().all(|c| c.is_ascii_hexdigit())
            }) {
                out.insert(hit.path, hash);
            }
        }
        if done {
            break;
        }
    }
    Ok(out)
}

fn write_commit_manifest(
    archive: &Path,
    plan: &OverlayCommitPlan,
    encoding: &str,
    hashes: &str,
) -> Result<()> {
    if !matches!(hashes, "all" | "new" | "none") {
        return Err(OverlayError::Msg(
            "manifest hashes must be all, new, or none".into(),
        ));
    }
    let source = provenance_base(archive, encoding)?;
    let mut name = archive.as_os_str().to_os_string();
    name.push(crate::base_sidecars::MANIFEST_SIDECAR_SUFFIX);
    let dest = PathBuf::from(name);
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_micros() as u64;
    let previous = match File::open(&dest) {
        Ok(file) => {
            use std::io::BufRead;
            let line = BufReader::new(file).lines().next().transpose()?;
            line.map(|line| {
                serde_json::from_str::<serde_json::Value>(&line).map_err(io::Error::other)
            })
            .transpose()?
            .and_then(|v| v["commit_id"].as_u64())
            .unwrap_or(0)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e.into()),
    };
    let commit_id = now.max(previous.saturating_add(1));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    let mut dirs = vec!["/".to_string()];
    while let Some(dir) = dirs.pop() {
        let mut entries = source.list_dirents(&dir).unwrap_or_default();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for entry in entries {
            let path = join(&dir, &entry.name);
            let fi = source
                .lookup(&path, 0)
                .ok_or_else(|| io::Error::other("manifest member disappeared"))?;
            let mut attrs = source_xattrs(&source, &fi);
            attrs.retain(|k, _| k.starts_with("user."));
            let changed = plan
                .append_entries
                .iter()
                .any(|(p, _)| p == path.trim_start_matches('/'));
            let sha256 = if (fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFREG)
                && hashes != "none"
            {
                if let Some(hash) = plan.written_hashes.get(&path) {
                    Some(hash.clone())
                } else if hashes == "all" || changed {
                    Some(
                        ratarmount_index::sha256_hex_stream(&mut source.open(&fi, 0)?)
                            .map_err(|e| OverlayError::Msg(e.to_string()))?,
                    )
                } else {
                    attrs
                        .get("user.hash.sha256")
                        .and_then(|v| std::str::from_utf8(v).ok())
                        .filter(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
                        .map(str::to_owned)
                        .or_else(|| plan.known_hashes.get(&path).cloned())
                }
            } else {
                None
            };
            // JSON arrays preserve arbitrary bytes, including NUL and invalid UTF-8.
            let row = serde_json::json!({ "path": path.trim_start_matches('/'), "size": fi.size,
                "sha256": sha256, "xattrs": attrs, "commit_id": commit_id });
            serde_json::to_writer(tmp.as_file_mut(), &row).map_err(io::Error::other)?;
            tmp.write_all(b"\n")?;
            if ratarmount_core::is_dir_mode(fi.mode) {
                dirs.push(path);
            }
        }
    }
    tmp.as_file().sync_all()?;
    #[cfg(test)]
    if FAIL_MANIFEST_PUBLISH.replace(false) {
        return Err(io::Error::other("injected manifest publication failure").into());
    }
    tmp.persist(&dest).map_err(|e| OverlayError::Io(e.error))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Linux and Windows libc spell a missing xattr `ENODATA`. Other targets spell
/// it `ENOATTR` (absent from the Windows libc). Windows has the constant, not
/// working xattrs; host metadata stays Unix-only.
fn missing_xattr_errno() -> i32 {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        libc::ENODATA
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        libc::ENOATTR
    }
}

fn overlay_info_path(fi: &FileInfo) -> Option<&str> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) => s
            .strip_prefix("overlay:")
            .or_else(|| s.strip_prefix("overlay-meta:")),
        _ => None,
    })
}

fn without_overlay_meta(fi: &FileInfo) -> FileInfo {
    let mut fi = fi.clone();
    fi.userdata
        .retain(|d| !matches!(d, UserData::Other(s) if s.starts_with("overlay-atime:")));
    if matches!(fi.userdata.last(), Some(UserData::Other(s)) if s.starts_with("overlay-meta:")) {
        fi.userdata.pop();
    }
    fi
}

fn source_xattrs(source: &dyn MountSource, fi: &FileInfo) -> BTreeMap<String, Vec<u8>> {
    source
        .list_xattr(fi)
        .into_iter()
        .filter_map(|name| source.get_xattr(fi, &name).map(|value| (name, value)))
        .collect()
}

fn merge_xattr_rows(
    db: &Connection,
    path: &str,
    attrs: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let mut stmt = db.prepare("SELECT name,value FROM xattrs WHERE path=?1 ORDER BY name")?;
    for row in stmt.query_map([path], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<Vec<u8>>>(1)?))
    })? {
        let (name, value) = row?;
        if name.is_empty() {
            attrs.clear();
        } else if let Some(value) = value {
            attrs.insert(name, value);
        } else {
            attrs.remove(&name);
        }
    }
    Ok(())
}

fn provenance_base(archive: &Path, encoding: &str) -> Result<SqliteIndexedTar> {
    if detect_compression(archive).map_err(|e| OverlayError::Msg(e.to_string()))?
        == CompressionFormat::Zstd
    {
        return tar_zst_full_frame_index(archive, encoding);
    }
    let opts = OpenOptions {
        index_in_memory: true,
        write_index: false,
        ignore_zeros: true,
        gnu_incremental: Some(false),
        encoding: encoding.into(),
        ..OpenOptions::default()
    };
    SqliteIndexedTar::create_index(
        archive,
        archive,
        None,
        &opts,
        env!("CARGO_PKG_VERSION"),
        &mut None,
    )
    .map_err(|e| OverlayError::Msg(e.to_string()))
}

/// Shared replacement path for metadata-only changes. Payload copies live only
/// for the commit, never in the writable overlay. Unchanged TAR records remain raw.
#[allow(clippy::too_many_arguments)]
fn persist_provenance_plan(
    archive: &Path,
    root: &Path,
    plan: &OverlayCommitPlan,
    encoding: &str,
    mode: CommitMode,
    hash_output: Option<&mut BTreeMap<String, String>>,
    rows: &crate::journal_recovery::Rows<'_>,
    original: &fs::Metadata,
) -> Result<IndexPatchWindow> {
    live_commit_is_supported(archive)?;
    let base = provenance_base(archive, encoding)?;
    // Offline commits do not pass through WriteOverlay::new's canonical root.
    // macOS /var (and other symlinked parents) must compare in the same form.
    let root = root.canonicalize()?;
    let mut pending = collect_ustar_pending_at(&root, &plan.append_entries)?;
    let mut spools = Vec::new();
    for path in plan.xattrs.keys().chain(plan.metadata.keys()) {
        if pending.iter().any(|p| &p.path == path) {
            continue;
        }
        let host = root.join(path);
        if let Ok(meta) = fs::symlink_metadata(&host) {
            pending.extend(collect_ustar_pending_at(
                &root,
                &[(path.clone(), meta.is_dir())],
            )?);
            continue;
        }
        let fi = base
            .lookup(&archive_lookup_path(path), 0)
            .ok_or_else(|| OverlayError::Msg(format!("metadata member disappeared: {path}")))?;
        let (host, kind) = if ratarmount_core::is_dir_mode(fi.mode) {
            (PathBuf::new(), PendingKind::Directory)
        } else if ratarmount_core::is_lnk_mode(fi.mode) {
            (
                PathBuf::new(),
                PendingKind::Symlink {
                    target: fi.linkname.clone(),
                },
            )
        } else if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFREG {
            let mut tmp = tempfile::NamedTempFile::new()?;
            let mut reader = base.open(&fi, 0)?;
            if io::copy(&mut reader, tmp.as_file_mut())? != fi.size {
                return Err(
                    io::Error::new(io::ErrorKind::UnexpectedEof, "short metadata member").into(),
                );
            }
            let host = tmp.path().to_path_buf();
            spools.push(tmp);
            (host, PendingKind::FileOnDisk { size: fi.size })
        } else {
            return Err(OverlayError::Msg(format!(
                "metadata commit unsupported member type: {path}"
            )));
        };
        pending.push(PendingUstar {
            path: path.clone(),
            host,
            kind,
            mode: fi.mode & 0o7777,
            uid: fi.uid,
            gid: fi.gid,
            mtime: fi.mtime.max(0.0) as u64,
            xattrs: Vec::new(),
            sha256: None,
        });
    }
    for p in &mut pending {
        if fs::symlink_metadata(root.join(&p.path)).is_err() {
            if let Some(metadata) = plan.metadata.get(&p.path) {
                if let Some(mode) = metadata.mode {
                    p.mode = mode & 0o7777;
                }
                if let Some(mtime) = metadata.mtime {
                    p.mtime = mtime.max(0.0) as u64;
                }
            }
        }
        let mut attrs = base
            .lookup(&archive_lookup_path(&p.path), 0)
            .map(|fi| source_xattrs(&base, &fi))
            .unwrap_or_default();
        if let Some(changes) = plan.xattrs.get(&p.path) {
            for (name, value) in changes {
                if name.is_empty() {
                    attrs.clear();
                    continue;
                }
                if let Some(value) = value {
                    attrs.insert(name.clone(), value.clone());
                } else {
                    attrs.remove(name);
                }
            }
        }
        // Data replacements invalidate cached content hashes.
        if plan.append_entries.iter().any(|(path, _)| path == &p.path) {
            attrs.retain(|k, _| !k.starts_with("user.hash."));
        }
        p.xattrs = attrs.into_iter().collect();
    }
    let mut deleted = HashSet::new();
    let mut offsets = Vec::new();
    for path in plan
        .deleted_paths
        .iter()
        .chain(plan.xattrs.keys())
        .chain(plan.metadata.keys())
    {
        let ohs = match all_tar_offsetheaders(&base, path) {
            Ok(ohs) => ohs,
            Err(_)
                if base
                    .lookup(&archive_lookup_path(path), 0)
                    .is_some_and(|fi| {
                        ratarmount_core::is_dir_mode(fi.mode)
                            && tar_offsetheaders_in(&fi).next().is_none()
                    }) =>
            {
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        if !ohs.is_empty() {
            deleted.insert(path.clone());
            offsets.extend(ohs);
        }
    }
    let patch_opts = OpenOptions {
        encoding: encoding.into(),
        ignore_zeros: true,
        index_folders: vec![PathBuf::new()],
        ..OpenOptions::default()
    };
    invalidate_stale_commit_sidecar(archive, &patch_opts)?;
    if hash_output.is_some() {
        for member in &mut pending {
            if plan
                .append_entries
                .iter()
                .any(|(path, _)| path == &member.path)
            {
                member.sha256 = Some(Mutex::new(None));
            }
        }
    }
    let members: Vec<_> = pending.iter().map(PendingUstar::as_member).collect();
    let rewrite = RewriteTarSuffix {
        deleted_paths: &deleted,
        append: &members,
        encoding,
    };
    let persist = || -> Result<IndexPatchWindow> {
        #[cfg(test)]
        append_prepare_seams(archive, original)?;
        let format = detect_compression(archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
        if format == CompressionFormat::Zstd {
            let map =
                scan_zstd_frames_path(archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
            let from = match offsets.iter().min() {
                Some(offset) => offline_tar_zst_from_idx(archive, &map, *offset)?,
                None => find_last_n_tar_window(archive, &map, "provenance")?.0,
            };
            let transform = |mut input: &mut dyn ratarmount_compress::SeekRead,
                             offset,
                             mut out: &mut dyn Write| {
                rewrite_tar_suffix(&mut input, offset, &rewrite, &mut out).map(|_| ())
            };
            if deleted.is_empty() && map.seek_table.is_some() && mode.may_append(archive)? {
                if let Err(failed) = crate::journal_recovery::splice_append_committing(
                    archive, from, transform, original, rows,
                ) {
                    let copy_from = copy_after_failed_replace(failed, mode)?;
                    crate::journal_recovery::splice_replace_over(
                        archive, from, transform, original, copy_from,
                    )?;
                }
            } else {
                crate::journal_recovery::splice_replace_over(
                    archive,
                    from,
                    transform,
                    original,
                    crate::journal_recovery::CopyFrom::Gate,
                )?;
            }
            return Ok(IndexPatchWindow {
                window_start: map.frames[from].uncompressed_offset,
                from_frame: Some(from),
                offsets_shifted: false,
            });
        }
        let parent = archive
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        let (mut src, _) = crate::journal_recovery::open_copy_source(
            archive,
            original,
            crate::journal_recovery::CopyFrom::Gate,
        )?;
        let append_offset = if deleted.is_empty() && mode.may_append(archive)? {
            uncompressed_append_offset(archive, plan, encoding)?
        } else {
            None
        };
        if let Some(offset) = append_offset {
            ratarmount_formats_tar::write_ustar_members(tmp.as_file_mut(), &members)?;
            ratarmount_formats_tar::write_tar_eof(tmp.as_file_mut())?;
            if let Err(failed) = crate::journal_recovery::replace_committing(
                archive,
                offset,
                tmp.as_file_mut(),
                original,
                rows,
            ) {
                let copy_from = copy_after_failed_replace(failed, mode)?;
                // The stamp after the attempt (a rollback may have left a new
                // mtime), read from the very file the copy reads; it must
                // still be the gate's file by the rule the failure names.
                let source = src.metadata()?;
                if !crate::journal_recovery::copy_source_matches(original, &source, copy_from) {
                    return Err(crate::journal_recovery::copy_source_changed(archive).into());
                }
                tmp.as_file_mut().set_len(0)?;
                tmp.as_file_mut().rewind()?;
                src.rewind()?;
                rewrite_tar_suffix(&mut src, 0, &rewrite, tmp.as_file_mut())?;
                tmp.as_file().sync_all()?;
                crate::journal_recovery::publish_over(archive, &source, || {
                    tmp.persist(archive).map(drop).map_err(|e| e.error)
                })
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
                return Ok(IndexPatchWindow {
                    window_start: 0,
                    from_frame: None,
                    offsets_shifted: true,
                });
            }
            Ok(IndexPatchWindow {
                window_start: offset,
                from_frame: None,
                offsets_shifted: false,
            })
        } else {
            let source = src.metadata()?;
            rewrite_tar_suffix(&mut src, 0, &rewrite, tmp.as_file_mut())?;
            tmp.as_file().sync_all()?;
            crate::journal_recovery::publish_over(archive, &source, || {
                tmp.persist(archive).map(drop).map_err(|e| e.error)
            })
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
            Ok(IndexPatchWindow {
                window_start: 0,
                from_frame: None,
                offsets_shifted: true,
            })
        }
    };
    let window = persist()?;
    if let Some(output) = hash_output {
        for member in &pending {
            if let Some(digest) = member
                .sha256
                .as_ref()
                .and_then(|hash| hash.lock().expect("TAR payload digest").clone())
            {
                output.insert(archive_lookup_path(&member.path), digest);
            }
        }
    }
    Ok(window)
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Component-wise path prefix check (safe vs string prefix `/tmp/ov` vs `/tmp/ov-evil`).
fn path_is_under(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

fn overlay_host_path(overlay_root: &Path, rel: &str) -> PathBuf {
    let path = normpath(rel);
    if path == "/" {
        overlay_root.to_path_buf()
    } else {
        overlay_root.join(path.trim_start_matches('/'))
    }
}

fn ensure_overlay_under_root(root: &Path, host_path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(host_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "overlay refuses to follow symlink at {}",
                    host_path.display()
                ),
            ));
        }
        Ok(_) => {
            let canon = fs::canonicalize(host_path)?;
            if !path_is_under(root, &canon) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "overlay path escapes overlay root: {} not under {}",
                        canon.display(),
                        root.display()
                    ),
                ));
            }
            return Ok(());
        }
        Err(_) => {
            // Path missing: walk up to an existing ancestor and verify it.
        }
    }

    let mut ancestor = host_path.to_path_buf();
    while ancestor.pop() {
        match fs::symlink_metadata(&ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let canon = fs::canonicalize(&ancestor).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "overlay parent symlink not confinable ({}): {e}",
                            ancestor.display()
                        ),
                    )
                })?;
                if !path_is_under(root, &canon) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "overlay parent symlink escapes overlay root: {} → {}",
                            ancestor.display(),
                            canon.display()
                        ),
                    ));
                }
                return Ok(());
            }
            Ok(_) => {
                let canon = fs::canonicalize(&ancestor)?;
                if !path_is_under(root, &canon) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "overlay path escapes overlay root: {} not under {}",
                            canon.display(),
                            root.display()
                        ),
                    ));
                }
                return Ok(());
            }
            Err(_) => continue,
        }
    }

    if path_is_under(root, host_path) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "overlay path escapes overlay root: {} not under {}",
                host_path.display(),
                root.display()
            ),
        ))
    }
}

fn ensure_overlay_parent_confined(root: &Path, host_path: &Path) -> io::Result<()> {
    let parent = host_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "overlay symlink has no parent",
        )
    })?;
    let canon = fs::canonicalize(parent)?;
    if !path_is_under(root, &canon) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "overlay symlink parent escapes overlay root: {} not under {}",
                canon.display(),
                root.display()
            ),
        ));
    }
    Ok(())
}

fn collect_ustar_pending_at(
    overlay_root: &Path,
    append_entries: &[(String, bool)],
) -> Result<Vec<PendingUstar>> {
    let mut out = Vec::with_capacity(append_entries.len());
    for (rel, is_dir) in append_entries {
        let host = overlay_host_path(overlay_root, rel);
        let meta = fs::symlink_metadata(&host)?;
        let mode = metadata_mode(&meta) & 0o7777;
        let uid = metadata_uid(&meta);
        let gid = metadata_gid(&meta);
        let mtime = metadata_mtime_secs(&meta).max(0) as u64;
        let kind = if meta.file_type().is_symlink() {
            ensure_overlay_parent_confined(overlay_root, &host)?;
            let target = fs::read_link(&host)?;
            PendingKind::Symlink {
                target: target.to_string_lossy().into_owned(),
            }
        } else if *is_dir || meta.file_type().is_dir() {
            ensure_overlay_under_root(overlay_root, &host)?;
            PendingKind::Directory
        } else {
            ensure_overlay_under_root(overlay_root, &host)?;
            PendingKind::FileOnDisk { size: meta.len() }
        };
        out.push(PendingUstar {
            path: rel.clone(),
            host,
            kind,
            mode,
            uid,
            gid,
            mtime,
            xattrs: Vec::new(),
            sha256: None,
        });
    }
    Ok(out)
}

fn is_fd_exhaustion(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(err.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

/// Park open. Not [`WriteOverlay::open_overlay_fd`]: callers already hold
/// `commit_gate`, and that helper would take the lock again.
#[cfg(unix)]
fn open_park_fd(host: &Path) -> io::Result<std::os::unix::io::OwnedFd> {
    use std::os::unix::io::{FromRawFd, OwnedFd};
    let c = c_path(host)?;
    // Safety: `c` is NUL-terminated. Flags never include `O_CREAT`.
    let fd = unsafe { libc::open(c.as_ptr(), park_open_flags(), 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // Safety: `fd` is a new descriptor owned by this process.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn park_open_flags() -> i32 {
    #[cfg(target_os = "linux")]
    {
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
}

/// Park open used by [`WriteOverlay::park_host`].
///
/// The `cfg(test)` hook and counter live here so a plain rename or unlink,
/// which never calls [`WriteOverlay::park_host`], cannot bump either.
#[cfg(unix)]
fn try_park_open(overlay: &WriteOverlay, host: &Path) -> io::Result<std::os::unix::io::OwnedFd> {
    #[cfg(test)]
    {
        overlay.park_open_count.fetch_add(1, Ordering::SeqCst);
        let mut guard = overlay.park_open_hook.lock().expect("park open hook");
        if let Some(hook) = guard.as_mut() {
            hook()?;
        }
    }
    #[cfg(not(test))]
    {
        let _ = overlay;
    }
    open_park_fd(host)
}

#[cfg(unix)]
fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Create the empty [`OVERLAY_MARKER`] without following a symlink. An existing
/// entry is accepted only if it is a regular file.
/// Returns whether this call created it.
fn create_overlay_marker(path: &Path) -> io::Result<bool> {
    match open_options_nofollow()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(path)?.file_type().is_file() {
                Ok(false)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("overlay marker {} is not a regular file", path.display()),
                ))
            }
        }
        Err(e) => Err(e),
    }
}

/// WHY: O_NOFOLLOW is Unix-only; Windows OpenOptions has no equivalent bit.
pub(crate) fn open_options_nofollow() -> FsOpenOptions {
    let mut opts = FsOpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts
}

/// Early EOF (or a longer body than `FileInfo` declares) must not be published.
/// `UnexpectedEof` maps to `EIO` in the protocol errno helpers.
fn cow_length_mismatch(copied: u64, expected: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("copy-on-write read {copied} bytes, expected {expected}"),
    )
}

fn create_cow_staging(parent: &Path) -> io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(COW_STAGING_PREFIX)
        .make_in(parent, |path| {
            let mut opts = open_options_nofollow();
            opts.write(true).create_new(true).open(path)
        })
}

/// Rename `dst` onto `real`, then fsync `real`'s parent.
///
/// `attrs == Some` applies path metadata and fsyncs the staging file first
/// (no-policy caller, and the non-Unix policy caller). `None` means the Unix
/// policy path already did that on the staging fd, outside the policy lock.
/// `before_persist` runs after that metadata and before `persist_noclobber`.
///
/// `after_publish` runs once the final name exists and before the parent
/// fsync. A parent-fsync error is returned after that, so settlement is not
/// undone for a file that was already renamed into place. `AlreadyExists`
/// leaves `real` untouched and does not call `after_publish`. Any other
/// persist error is returned the same way, so `Drop` refunds the reservation.
/// Any error before the rename drops the temp.
fn publish_cow_staging(
    dst: tempfile::NamedTempFile,
    real: &Path,
    attrs: Option<&OverlayMetadata>,
    before_persist: impl FnOnce(),
    after_publish: impl FnOnce(&File) -> Result<()>,
) -> Result<()> {
    if let Some(attrs) = attrs {
        set_host_metadata(dst.path(), attrs)?;
        dst.as_file().sync_all()?;
    }
    before_persist();
    match dst.persist_noclobber(real) {
        Ok(published) => {
            after_publish(&published)?;
            // Windows cannot open a directory as a File to fsync it.
            #[cfg(not(windows))]
            if let Some(parent) = real.parent() {
                let r = {
                    #[cfg(test)]
                    {
                        if FAIL_COW_DIR_FSYNC.replace(false) {
                            Err(io::Error::other("injected directory fsync failure"))
                        } else {
                            File::open(parent).and_then(|d| d.sync_all())
                        }
                    }
                    #[cfg(not(test))]
                    {
                        File::open(parent).and_then(|d| d.sync_all())
                    }
                };
                r?;
            }
            Ok(())
        }
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.error.into()),
    }
}

fn take_cow_before_persist(overlay: &WriteOverlay) -> impl FnOnce() {
    #[cfg(test)]
    let hook = overlay.cow_before_persist_hook.lock().unwrap().take();
    #[cfg(test)]
    {
        move || {
            if let Some(hook) = hook {
                hook();
            }
        }
    }
    #[cfg(not(test))]
    {
        let _ = overlay;
        || {}
    }
}

/// Remove crash leftovers named [`COW_STAGING_PREFIX`]. Regular files only.
/// Does not follow symlinks. `NotFound` is ignored. Bookkeeping that does not
/// have this prefix (the database, its sidecars, both markers) is left alone.
///
/// Best-effort: a directory read, metadata, or unlink error is logged and that
/// directory or entry is skipped. The sweep never fails the open.
fn sweep_cow_staging(root: &Path) {
    sweep_cow_staging_dir(root, root);
}

fn sweep_cow_staging_dir(root: &Path, dir: &Path) {
    if let Err(e) = ensure_overlay_under_root(root, dir) {
        log::warn!(
            "skipping copy-on-write staging sweep of {}: {e}",
            dir.display()
        );
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(e) => {
            log::warn!(
                "could not read overlay directory {} while sweeping copy-on-write staging: {e}",
                dir.display()
            );
            return;
        }
    };
    for ent in entries {
        let ent = match ent {
            Ok(ent) => ent,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                log::warn!(
                    "could not read an overlay directory entry in {} while sweeping copy-on-write staging: {e}",
                    dir.display()
                );
                continue;
            }
        };
        let path = ent.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                log::warn!(
                    "could not stat {} while sweeping copy-on-write staging: {e}",
                    path.display()
                );
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            sweep_cow_staging_dir(root, &path);
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !has_ascii_prefix(&name, COW_STAGING_PREFIX) {
            continue;
        }
        if let Err(e) = ensure_overlay_under_root(root, &path) {
            log::warn!(
                "skipping copy-on-write staging file {}: {e}",
                path.display()
            );
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                log::warn!(
                    "could not remove copy-on-write staging file {}: {e}",
                    path.display()
                );
            }
        }
    }
}

fn overlay_symlink(target: &Path, dest: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, dest)
    }
    #[cfg(not(unix))]
    {
        let _ = (target, dest);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "overlay symlinks require Unix",
        ))
    }
}

#[cfg(not(unix))]
fn overlay_fd_unsupported() -> OverlayError {
    OverlayError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "overlay raw fds require Unix",
    ))
}

// A successful in-place persist invalidates the old source even if reopen fails.
struct FailedCommitSource;
impl MountSource for FailedCommitSource {
    fn is_immutable(&self) -> bool {
        false
    }
    fn list(&self, _: &str) -> Option<ListResult> {
        None
    }
    fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
        None
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(io::Error::other(
            "archive unavailable after commit failure; remount required",
        ))
    }
}

// Validate before mutation, while tarstats still describes the old archive.
// Stamping a stale prefix index with fresh tarstats would bless wrong offsets.
fn invalidate_stale_commit_sidecar(archive: &Path, opts: &OpenOptions) -> Result<()> {
    let Some(path) = sidecar_path_for_patch(archive, opts) else {
        return Ok(());
    };
    let valid = SqliteIndex::open_read_only(&path).is_ok_and(|idx| {
        idx.tarstats().is_ok_and(|stats| stats.is_some())
            && idx.check_tarstats_matches_archive(archive).is_ok()
    });
    if !valid {
        fs::remove_file(&path)?;
        log::info!(
            "commit: removed stale sidecar {} before mutation",
            path.display()
        );
    }
    Ok(())
}

fn uncompressed_append_offset(
    archive: &Path,
    plan: &OverlayCommitPlan,
    encoding: &str,
) -> Result<Option<u64>> {
    let mut touched = plan.deleted_paths.clone();
    touched.extend(plan.append_entries.iter().map(|(p, _)| p.clone()));
    let mut file = File::open(archive)?;
    Ok(ratarmount_formats_tar::tar_append_offset(
        &mut file, &touched, encoding,
    )?)
}

#[cfg(test)]
thread_local! {
    static APPEND_PREPARE_TOUCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When set, renamed over the archive after the suffix is staged (another
    /// file takes the name between preparation and the journaled replacement).
    pub(crate) static APPEND_PREPARE_SWAP: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// The test seams of an append, run before the commit reads the archive: a
/// touch (the archive is no longer the gate's snapshot) or a swap (another
/// file takes the name).
#[cfg(test)]
fn append_prepare_seams(archive: &Path, original: &fs::Metadata) -> io::Result<()> {
    if APPEND_PREPARE_TOUCH.replace(false) {
        File::options().write(true).open(archive)?.set_times(
            fs::FileTimes::new().set_modified(original.modified()? + Duration::from_secs(2)),
        )?;
    }
    if let Some(other) = APPEND_PREPARE_SWAP.take() {
        fs::rename(other, archive)?;
    }
    Ok(())
}

/// The reaction to a failed journaled replacement without a live mount (and
/// inside the provenance persist): `Ok(from)` when a copy may run, reading
/// its source by the rule `from` names.
fn copy_after_failed_replace(
    failed: crate::journal_recovery::FailedReplace,
    mode: CommitMode,
) -> Result<crate::journal_recovery::CopyFrom> {
    if failed.may_copy && mode == CommitMode::Auto {
        log::warn!(
            "commit: append failed: {}; falling back to copy",
            failed.error
        );
        return Ok(failed.copy_from());
    }
    Err(failed.error)
}

/// A failed journaled replacement: `Committed` keeps its own variant so no
/// caller answers it with a copy fallback.
fn recover_error_to_overlay(
    error: ratarmount_compress::commit_journal::RecoverError,
) -> OverlayError {
    use ratarmount_compress::commit_journal::RecoverError;
    match error {
        RecoverError::Committed(e) => OverlayError::Committed(format!(
            "{e}; the archive holds the committed bytes but the recorded baseline could not be \
             updated (remount required)"
        )),
        other => OverlayError::Io(other.into_io()),
    }
}

/// Offline recovery before a commit: restamps the overlay database beside
/// `root` (when it exists) from the locked descriptor before the journal is
/// unlinked. `authorize` decides under the archive lock. The only offline
/// recovery: a failed replacement cleans up after itself.
fn recover_offline(
    archive: &Path,
    root: &Path,
    owner: crate::journal_recovery::Owner<'_>,
) -> Result<()> {
    crate::journal_recovery::recover_journal_at(archive, Some(&root.join(HIDDEN_DB)), owner)
        .map(|_| ())
        .map_err(recover_error_to_overlay)
}

fn append_uncompressed_tar_plan(
    archive: &Path,
    root: &Path,
    plan: &OverlayCommitPlan,
    encoding: &str,
    rows: &crate::journal_recovery::Rows<'_>,
    original: &fs::Metadata,
) -> std::result::Result<Option<IndexPatchWindow>, crate::journal_recovery::FailedReplace> {
    #[cfg(test)]
    append_prepare_seams(archive, original)?;
    let Some(offset) = uncompressed_append_offset(archive, plan, encoding)? else {
        return Ok(None);
    };
    let root = root.canonicalize()?;
    let pending = collect_ustar_pending_at(&root, &plan.append_entries)?;
    let members: Vec<_> = pending.iter().map(PendingUstar::as_member).collect();
    let parent = archive
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tail = tempfile::NamedTempFile::new_in(parent)?;
    ratarmount_formats_tar::write_ustar_members(tail.as_file_mut(), &members)?;
    ratarmount_formats_tar::write_tar_eof(tail.as_file_mut())?;
    crate::journal_recovery::replace_committing(
        archive,
        offset,
        tail.as_file_mut(),
        original,
        rows,
    )?;
    log::info!(
        "commit: prefix {:.1} GiB retained via append",
        offset as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    Ok(Some(IndexPatchWindow {
        window_start: offset,
        from_frame: None,
        offsets_shifted: false,
    }))
}

/// Archive persistence policy. Append is limited to adds-only TAR plans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CommitMode {
    #[default]
    Copy,
    Append,
    Auto,
}

impl std::str::FromStr for CommitMode {
    type Err = String;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "copy" => Ok(Self::Copy),
            "append" => Ok(Self::Append),
            "auto" => Ok(Self::Auto),
            _ => Err("commit mode must be append, copy, or auto".into()),
        }
    }
}

impl CommitMode {
    fn may_append(self, archive: &Path) -> io::Result<bool> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(match self {
                Self::Copy => false,
                Self::Append => true,
                Self::Auto => fs::metadata(archive)?.nlink() == 1,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = archive;
            Ok(false)
        }
    }
}

/// Options for [`commit_overlay`].
#[derive(Clone, Debug)]
pub struct CommitOverlayOptions {
    pub mode: CommitMode,
    pub manifest_hashes: Option<String>,
    /// When true, skip interactive "commit" confirmation (for harness / automation).
    pub yes: bool,
    /// Verbosity: 0 = quiet, 1+ = print plan (Python `printDebug`).
    pub debug: u8,
    /// TAR member-name encoding (`-e` / `--encoding`). Default `"utf-8"`.
    pub encoding: String,
    /// Concatenated TAR (`-i` / `--ignore-zeros`) for mount reopen.
    /// Offline/live GNU tar `--delete`/`--append`, `.tar.zst` delete
    /// classification, and sidecar patch always walk past per-frame TAR EOF
    /// so later concatenated members survive even when this is false.
    pub ignore_zeros: bool,
    /// `--force-base-mismatch`: commit although the archive is no longer the
    /// base the overlay recorded.
    pub force_base_mismatch: bool,
}

impl Default for CommitOverlayOptions {
    fn default() -> Self {
        Self {
            mode: CommitMode::Copy,
            manifest_hashes: None,
            yes: false,
            debug: 1,
            encoding: "utf-8".into(),
            ignore_zeros: false,
            force_base_mismatch: false,
        }
    }
}

/// Apply overlay folder modifications to a TAR or ZIP archive.
///
/// **TAR**: uncompressed TAR and gzip / bzip2 / xz compressed TAR via GNU tar
/// (decompress → `tar --delete` / `tar --append` → recompress). `.tar.zst` uses
/// in-tree last-window / earlier-frame zstd splice (no GNU tar).
///
/// **ZIP** (full rebuild, not in-place): rebuilds a new ZIP from the base archive plus
/// overlay adds/deletes. Unchanged members are raw-copied (preserves store/deflate and
/// other methods). Overlay file bodies are written as **deflate** (directories as empty
/// directory entries). Atomic replace of the original path. Runtime scales with archive
/// size (full rewrite). Encrypted / multi-part / spanned ZIPs are not supported for commit.
///
/// Shared plan:
/// 1. Collect deleted paths from `.ratarmount.overlay.sqlite`
/// 2. Walk overlay files → delete-then-append list
/// 3. Apply format-specific commit
///
/// Returns `Ok(true)` if changes were committed, `Ok(false)` if nothing to do or canceled.
///
/// Offline prefix-rewrite escape hatch (including earlier-frame `.tar.zst`
/// delete). **Not** a V-4 live-queue job — do not route this through
/// [`WriteOverlay::enqueue_commit`].
///
/// The overlay has a database: the archive about to be
/// rewritten must still be the base the last create, commit or refresh
/// recorded (checked with `stat` only, before anything is written; the
/// classified base is the opener's report for `archive_file`). The refresh
/// afterwards re-points the recorded location at the committed archive.
/// `--force-base-mismatch` (`opts`) commits anyway.
pub fn commit_overlay(
    write_overlay: impl AsRef<Path>,
    archive_file: impl AsRef<Path>,
    base: &crate::ClassifiedBase,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    let write_overlay = write_overlay.as_ref();
    let archive_file = archive_file.as_ref();
    if !write_overlay.join(HIDDEN_DB).exists() {
        return Err(OverlayError::Msg(format!(
            "overlay {} has no database; use commit_overlay_raw_dir for a raw directory",
            write_overlay.display()
        )));
    }
    if let Err(refusal) =
        crate::overlay_gate::check_commit_base_offline(write_overlay, base, archive_file)
    {
        if !opts.force_base_mismatch {
            return Err(OverlayError::Msg(refusal.0));
        }
        log::warn!("{refusal} (--force-base-mismatch: committing anyway)");
    }
    commit_overlay_inner(write_overlay, archive_file, Some(base), opts)
}

/// What [`commit_overlay_raw_dir`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawDirCommit {
    pub committed: bool,
    /// Always `false`: a raw overlay directory records no base identity, so
    /// none was checked. The CLI says so.
    pub identity_checked: bool,
}

/// Commit a raw overlay DIRECTORY of files (no database) to an archive. It
/// takes no token and checks no identity; it refuses once the directory has
/// an overlay database, because then the base identity must be checked
/// through [`commit_overlay`].
pub fn commit_overlay_raw_dir(
    write_overlay: impl AsRef<Path>,
    archive_file: impl AsRef<Path>,
    opts: &CommitOverlayOptions,
) -> Result<RawDirCommit> {
    let write_overlay = write_overlay.as_ref();
    let db = write_overlay.join(HIDDEN_DB);
    if db.exists() {
        return Err(OverlayError::Msg(format!(
            "overlay database {} exists; its base identity must be checked, so commit it \
             with a classified base (commit_overlay), not as a raw directory",
            db.display()
        )));
    }
    if !opts.force_base_mismatch {
        crate::overlay_gate::ensure_journal_is_for_archive(archive_file.as_ref())
            .map_err(OverlayError::Msg)?;
    }
    let committed = commit_overlay_inner(write_overlay, archive_file.as_ref(), None, opts)?;
    Ok(RawDirCommit {
        committed,
        identity_checked: false,
    })
}

fn commit_overlay_inner(
    write_overlay: &Path,
    archive_file: &Path,
    identity: Option<&crate::ClassifiedBase>,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    if !write_overlay.is_dir() {
        return Err(OverlayError::Msg(
            "Need an existing write overlay folder for committing changes.".into(),
        ));
    }
    if !archive_file.is_file() {
        return Err(OverlayError::Msg(format!(
            "Specified archive '{}' to commit to does not exist or is not a file!",
            archive_file.display()
        )));
    }

    {
        use crate::journal_recovery::{Owner, Record};
        // The gate ran before this call (unlocked); the owner re-takes the
        // decision on the LOCKED file, and recovery restamps the rows from it.
        let owner = match identity {
            _ if opts.force_base_mismatch => Owner::Forced,
            Some(base) if write_overlay.join(HIDDEN_DB).exists() => Owner::Recorded {
                base,
                archive: archive_file,
                record: Record::Offline(write_overlay),
            },
            _ => Owner::Inode,
        };
        recover_offline(archive_file, write_overlay, owner)?;
    }
    // The one snapshot every write of this commit compares against: the file
    // the gate accepts after recovery (one stat when no identity applies).
    let original = match identity {
        Some(base) if write_overlay.join(HIDDEN_DB).exists() => {
            match crate::overlay_gate::check_commit_base_offline(write_overlay, base, archive_file)
            {
                Ok(Some(snapshot)) => snapshot,
                Ok(None) => fs::metadata(archive_file)?,
                Err(_) if opts.force_base_mismatch => fs::metadata(archive_file)?,
                Err(refusal) => return Err(OverlayError::Msg(refusal.0)),
            }
        }
        _ => fs::metadata(archive_file)?,
    };
    let mut plan = collect_overlay_commit_plan(write_overlay)?;
    if opts.manifest_hashes.is_some() {
        plan.known_hashes = known_manifest_hashes(archive_file)?;
    }
    if opts.manifest_hashes.is_some() {
        live_commit_is_supported(archive_file)?;
    }
    let hash_payloads = opts
        .manifest_hashes
        .as_deref()
        .is_some_and(|mode| mode != "none");
    if plan.has_metadata_changes() || hash_payloads {
        if plan.is_empty() {
            return Ok(false);
        }
        live_commit_is_supported(archive_file)?;
        if !confirm_commit(opts)? {
            return Ok(false);
        }
        let mut written_hashes = BTreeMap::new();
        let db = write_overlay.join(HIDDEN_DB);
        let window = persist_provenance_plan(
            archive_file,
            write_overlay,
            &plan,
            &opts.encoding,
            opts.mode,
            hash_payloads.then_some(&mut written_hashes),
            &crate::journal_recovery::Rows::Path(&db),
            &original,
        )?;
        crate::overlay_meta::refresh_committed_base_offline(write_overlay, identity, archive_file)?;
        plan.written_hashes = written_hashes;
        let patch_opts = OpenOptions {
            encoding: opts.encoding.clone(),
            ignore_zeros: true,
            index_folders: vec![PathBuf::new()],
            ..OpenOptions::default()
        };
        patch_sidecar_if_present(archive_file, &window, &patch_opts)?;
        if let Some(hashes) = &opts.manifest_hashes {
            write_commit_manifest(archive_file, &plan, &opts.encoding, hashes)?;
        }
        return Ok(true);
    }
    let committed = if is_zip_archive(archive_file)? {
        commit_overlay_zip(write_overlay, archive_file, opts)?
    } else {
        commit_overlay_tar(write_overlay, archive_file, opts, &original)?
    };
    if committed {
        crate::overlay_meta::refresh_committed_base_offline(write_overlay, identity, archive_file)?;
        if let Some(hashes) = &opts.manifest_hashes {
            write_commit_manifest(archive_file, &plan, &opts.encoding, hashes)?;
        }
    }
    Ok(committed)
}

/// Overlay changes collected for commit (paths relative to archive root, `/`-separated).
#[derive(Clone, Debug)]
struct OverlayCommitPlan {
    /// Null-terminated path variants for GNU tar `--files-from`.
    deletions_nul: Vec<u8>,
    /// Null-terminated paths for GNU tar `--append --files-from`.
    appends_nul: Vec<u8>,
    /// Normalized relative paths marked deleted (DB + files being replaced).
    deleted_paths: HashSet<String>,
    /// Overlay entries to add: `(relative path, is_directory)`.
    append_entries: Vec<(String, bool)>,
    xattrs: BTreeMap<String, BTreeMap<String, Option<Vec<u8>>>>,
    metadata: BTreeMap<String, OverlayMetadata>,
    known_hashes: BTreeMap<String, String>,
    written_hashes: BTreeMap<String, String>,
}

impl OverlayCommitPlan {
    fn has_metadata_changes(&self) -> bool {
        !self.metadata.is_empty()
            || self
                .xattrs
                .values()
                .any(|attrs| attrs.keys().any(|name| !name.is_empty()))
    }

    fn is_empty(&self) -> bool {
        self.deleted_paths.is_empty()
            && self.append_entries.is_empty()
            && self.xattrs.is_empty()
            && self.metadata.is_empty()
    }
}

/// Offline commit reads SQL only. In-memory [`PendingFilesOp`] rows belong to a
/// live [`WriteOverlay`], which replays them in [`WriteOverlay::plan_for_commit`]
/// before it builds a plan. This function has no overlay object, so it cannot
/// see rows that never reached the database. An unsaved queue is logged on
/// unmount: an offline `--commit-overlay` will publish those archive members.
fn collect_overlay_commit_plan(write_overlay: &Path) -> Result<OverlayCommitPlan> {
    let db_path = write_overlay.join(HIDDEN_DB);
    let markers = overlay_markers(write_overlay)?;
    let marker = markers.first().cloned();
    let db_regular = match fs::metadata(&db_path) {
        Ok(m) if m.is_dir() => {
            let canon = write_overlay
                .canonicalize()
                .unwrap_or_else(|_| write_overlay.to_path_buf());
            return Err(db_is_directory_error(&canon.join(HIDDEN_DB)));
        }
        // A 0-byte file in a marked folder is as gone as a missing one.
        Ok(m) => m.is_file() && (marker.is_none() || m.len() > 0),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(OverlayError::Io(e)),
    };
    if marker.is_some() && !db_regular {
        // #96: committing without the tombstones would write the unlinked
        // members back into the archive. Same wording and canonical paths as
        // the mount refusal.
        let canon = write_overlay
            .canonicalize()
            .unwrap_or_else(|_| write_overlay.to_path_buf());
        let canon_markers: Vec<PathBuf> = markers
            .iter()
            .map(|m| canon.join(m.file_name().unwrap_or_default()))
            .collect();
        return Err(OverlayError::Msg(format!(
            "write overlay {} was used before but its database {} is missing or empty; \
             refusing to commit without its deletions{}",
            canon.display(),
            canon.join(HIDDEN_DB).display(),
            discard_hint(
                &canon_markers
                    .iter()
                    .map(|p| p.as_path())
                    .collect::<Vec<_>>()
            )
        )));
    }
    let conn = if db_regular {
        Some(Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?)
    } else {
        None
    };
    collect_overlay_commit_plan_from_conn(write_overlay, conn.as_ref(), None, &HashSet::new())
}

fn collect_overlay_commit_plan_from_conn(
    write_overlay: &Path,
    conn: Option<&Connection>,
    idle_cutoff: Option<SystemTime>,
    busy_inodes: &HashSet<(u64, u64)>,
) -> Result<OverlayCommitPlan> {
    let mut deletions_nul: Vec<u8> = Vec::new();
    let mut appends_nul: Vec<u8> = Vec::new();
    let mut deleted_paths: HashSet<String> = HashSet::new();
    let mut append_entries: Vec<(String, bool)> = Vec::new();
    let mut skipped: HashSet<String> = HashSet::new();

    if let Some(conn) = conn {
        let mut stmt = conn.prepare(r#"SELECT path, name FROM "files" WHERE deleted = 1"#)?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (path, name) = row?;
            let rel = join_rel(&path, &name);
            let norm = normalize_archive_rel_path(&rel);
            if norm.starts_with(SPOOL_NAME_PREFIX)
                || norm == OVERLAY_MARKER
                || norm == LEGACY_OVERLAY_MARKER
            {
                continue;
            }
            if !norm.is_empty() {
                deleted_paths.insert(norm);
            }
            add_deletion_variants(&mut deletions_nul, &rel);
        }
    }

    // Overlay walk: files to append (and replace = delete + append)
    let suffixes = ["", "-journal", "-shm", "-wal", ".used"];
    let mut ignored: Vec<String> = suffixes.iter().map(|s| format!("{HIDDEN_DB}{s}")).collect();
    ignored.push(OVERLAY_MARKER.to_string());

    let overlay_str = write_overlay.to_string_lossy();
    let overlay_prefix = if overlay_str.ends_with('/') {
        overlay_str.to_string()
    } else {
        format!("{overlay_str}/")
    };

    for entry in walkdir_files_and_empty_dirs(write_overlay)? {
        let full = entry.path;
        let is_dir = entry.is_dir;
        let rel = if full == write_overlay {
            continue;
        } else if let Ok(r) = full.strip_prefix(write_overlay) {
            r.to_string_lossy().replace('\\', "/")
        } else if let Some(rest) = full.to_string_lossy().strip_prefix(&overlay_prefix) {
            rest.to_string()
        } else {
            continue;
        };
        let rel = rel.trim_start_matches('/').to_string();
        if rel.is_empty() {
            continue;
        }
        // Planted `.ratarmount-spool-*` is not an append member.
        if rel.starts_with(SPOOL_NAME_PREFIX) {
            continue;
        }
        if ignored.iter().any(|i| rel == *i || rel.ends_with(i)) || is_overlay_internal_path(&rel) {
            continue;
        }
        // Only top-level DB name
        if ignored.contains(&rel) {
            continue;
        }
        let norm = normalize_archive_rel_path(&rel);
        if let Some(cutoff) = idle_cutoff {
            if !overlay_entry_is_idle(&full, cutoff, busy_inodes) {
                skipped.insert(norm);
                continue;
            }
        }
        if is_dir {
            // Empty dirs only (walkdir_files_and_empty_dirs already filters)
            appends_nul.extend(rel.as_bytes());
            appends_nul.push(0);
            append_entries.push((norm, true));
        } else {
            add_deletion_variants(&mut deletions_nul, &rel);
            deleted_paths.insert(norm.clone());
            appends_nul.extend(rel.as_bytes());
            appends_nul.push(0);
            append_entries.push((norm, false));
        }
    }

    if idle_cutoff.is_some() && !skipped.is_empty() {
        // A hot file under dir/ must not persist dir/ as an empty member
        // (and must not wipe that parent from the overlay).
        append_entries.retain(|(p, is_dir)| {
            if !is_dir {
                return true;
            }
            !skipped.iter().any(|s| s == p || path_is_under_rel(p, s))
        });
        appends_nul.clear();
        for (rel, _) in &append_entries {
            appends_nul.extend(rel.as_bytes());
            appends_nul.push(0);
        }
    }

    let mut metadata = BTreeMap::new();
    let mut xattrs = BTreeMap::<String, BTreeMap<String, Option<Vec<u8>>>>::new();
    if let Some(conn) = conn {
        let has_metadata: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='overlay_metadata')", [], |r| r.get(0),
        )?;
        if has_metadata {
            let mut stmt = conn.prepare("SELECT path,mode,atime,mtime FROM overlay_metadata")?;
            for row in stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    OverlayMetadata {
                        mode: r.get(1)?,
                        atime: r.get(2)?,
                        mtime: r.get(3)?,
                        ..Default::default()
                    },
                ))
            })? {
                let (path, attrs) = row?;
                let rel = normalize_archive_rel_path(&path);
                let removed =
                    deleted_paths.contains(&rel) && !append_entries.iter().any(|(p, _)| p == &rel);
                if !removed
                    && !skipped.contains(&rel)
                    && !rel.is_empty()
                    && !is_overlay_internal_path(&rel)
                {
                    metadata.insert(rel, attrs);
                }
            }
        }
        let has_xattrs: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='xattrs')",
            [],
            |r| r.get(0),
        )?;
        if has_xattrs {
            let mut stmt = conn.prepare("SELECT path,name,value FROM xattrs ORDER BY path,name")?;
            for row in stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })? {
                let (path, name, value) = row?;
                let rel = normalize_archive_rel_path(&path);
                let removed =
                    deleted_paths.contains(&rel) && !append_entries.iter().any(|(p, _)| p == &rel);
                if !removed && !skipped.contains(&rel) && !is_overlay_internal_path(&rel) {
                    xattrs.entry(rel).or_default().insert(name, value);
                }
            }
        }
    }
    Ok(OverlayCommitPlan {
        known_hashes: BTreeMap::new(),
        written_hashes: BTreeMap::new(),
        metadata,
        xattrs,
        deletions_nul,
        appends_nul,
        deleted_paths,
        append_entries,
    })
}

fn overlay_entry_is_idle(
    path: &Path,
    cutoff: SystemTime,
    busy_inodes: &HashSet<(u64, u64)>,
) -> bool {
    // Identify open writers by (dev, ino), not overlay path. Rename of an
    // open fd keeps the same inode; a path pin would miss the new name and
    // persist/unlink a still-open file.
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if busy_inodes.contains(&(meta.dev(), meta.ino())) {
                    return false;
                }
            }
            #[cfg(not(unix))]
            {
                let _ = busy_inodes;
            }
            match meta.modified() {
                Ok(mtime) => mtime <= cutoff,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

fn path_is_under_rel(parent: &str, child: &str) -> bool {
    child.starts_with(parent) && child.as_bytes().get(parent.len()) == Some(&b'/')
}

fn tombstone_key(folder: &str, name: &str) -> String {
    if folder.is_empty() || folder == "/" {
        format!("/{name}")
    } else {
        format!("{folder}/{name}")
    }
}

fn tombstone_parent(full: &str) -> &str {
    match full.rsplit_once('/') {
        Some(("", _)) => "",
        Some((dir, _)) => dir,
        None => "",
    }
}

fn tombstone_name(full: &str) -> &str {
    full.rsplit_once('/').map(|(_, name)| name).unwrap_or(full)
}

/// Borrows of fields other than `pending_rows`, so a direct write can run
/// while that queue is held (lock order: queue, then `db`).
struct FilesWriteCtx<'a> {
    db: &'a Mutex<Connection>,
    #[cfg(test)]
    fail: &'a AtomicU64,
    #[cfg(test)]
    before_tx: &'a Mutex<Option<RenameBeforeTxHook>>,
}

#[cfg(test)]
fn consume_rename_tx_failure_flag(flag: &AtomicU64) -> Option<OverlayError> {
    loop {
        let cur = flag.load(Ordering::SeqCst);
        if cur == 0 {
            return None;
        }
        if flag
            .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Some(OverlayError::Msg("injected rename tx failure".into()));
        }
    }
}

/// Direct `files` write. Rename attempts run the one-shot before-tx hook
/// before SQL. The injected failure counter lives in [`apply_pending_ops_sql`]
/// so a failed replay restores through that function's error. The caller
/// holds `pending_rows`.
fn write_files_op_direct(ctx: &FilesWriteCtx<'_>, op: &PendingFilesOp) -> Result<()> {
    // Drop the hook mutex before calling it. The hook may lock `db`.
    // It must not lock `pending_rows`: the caller already holds that queue.
    #[cfg(test)]
    if op.is_rename() {
        let hook = ctx.before_tx.lock().expect("overlay rename hook").take();
        if let Some(mut hook) = hook {
            hook()?;
        }
    }
    apply_pending_ops_sql(
        ctx.db,
        std::slice::from_ref(op),
        LockPoison::Strict,
        #[cfg(test)]
        Some(ctx.fail),
    )
}

fn apply_pending_ops_sql(
    db: &Mutex<Connection>,
    ops: &[PendingFilesOp],
    poison: LockPoison,
    #[cfg(test)] fail: Option<&AtomicU64>,
) -> Result<()> {
    let db = lock_mutex(db, poison, "overlay db");
    let tx = db.unchecked_transaction()?;
    #[cfg(test)]
    let mut injected = false;
    for op in ops {
        apply_files_op_sql(&tx, op)?;
        // After the first statement, before commit. Returning here rolls the
        // transaction back. Callers that replay a batch restore it on this
        // error; dropping the batch loses those rows.
        #[cfg(test)]
        if !injected {
            injected = true;
            if let Some(flag) = fail {
                if let Some(e) = consume_rename_tx_failure_flag(flag) {
                    return Err(e);
                }
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// SQL for one queued `files` update.
fn apply_files_op_sql(conn: &Connection, op: &PendingFilesOp) -> Result<()> {
    match op {
        PendingFilesOp::Rename {
            from,
            to,
            mode,
            hides_from,
            xattrs,
        } => {
            conn.execute("DELETE FROM overlay_metadata WHERE path=?1", [to])?;
            conn.execute(
                "UPDATE overlay_metadata SET path=?1 WHERE path=?2",
                params![to, from],
            )?;
            conn.execute("DELETE FROM xattrs WHERE path=?1", [to])?;
            conn.execute("DELETE FROM xattrs WHERE path=?1", [from])?;
            conn.execute(
                "INSERT INTO xattrs(path,name,value) VALUES (?1,'',NULL)",
                [to],
            )?;
            for (name, value) in xattrs {
                conn.execute(
                    "INSERT INTO xattrs(path,name,value) VALUES (?1,?2,?3)",
                    params![to, name, value],
                )?;
            }
            let (to_folder, to_name) = WriteOverlay::split(to);
            let (from_folder, from_name) = WriteOverlay::split(from);
            conn.execute(
                r#"INSERT OR IGNORE INTO "files" (path,name,mode,deleted) VALUES (?1,?2,?3,0)"#,
                params![to_folder, to_name, *mode as i64],
            )?;
            conn.execute(
                r#"UPDATE "files" SET deleted = 0, mode = ?3 WHERE path = ?1 AND name = ?2"#,
                params![to_folder, to_name, *mode as i64],
            )?;
            if *hides_from {
                conn.execute(
                    r#"INSERT OR REPLACE INTO "files" (path,name,deleted) VALUES (?1,?2,1)"#,
                    params![from_folder, from_name],
                )?;
            } else {
                conn.execute(
                    r#"DELETE FROM "files" WHERE path = ?1 AND name = ?2"#,
                    params![from_folder, from_name],
                )?;
            }
        }
        PendingFilesOp::Deleted { path, hides_base } => {
            conn.execute("DELETE FROM overlay_metadata WHERE path=?1", [path])?;
            conn.execute("DELETE FROM xattrs WHERE path=?1", [path])?;
            conn.execute(
                "INSERT INTO xattrs(path,name,value) VALUES (?1,'',NULL)",
                [path],
            )?;
            let (folder, name) = WriteOverlay::split(path);
            if *hides_base {
                conn.execute(
                    r#"INSERT OR REPLACE INTO "files" (path,name,deleted) VALUES (?1,?2,1)"#,
                    params![folder, name],
                )?;
            } else {
                conn.execute(
                    r#"DELETE FROM "files" WHERE path = ?1 AND name = ?2"#,
                    params![folder, name],
                )?;
            }
        }
        PendingFilesOp::Present { path, mode } => {
            conn.execute("DELETE FROM overlay_metadata WHERE path=?1", [path])?;
            let (folder, name) = WriteOverlay::split(path);
            conn.execute(
                r#"INSERT OR IGNORE INTO "files" (path,name,mode,deleted) VALUES (?1,?2,?3,0)"#,
                params![folder, name, *mode as i64],
            )?;
            conn.execute(
                r#"UPDATE "files" SET deleted = 0, mode = ?3 WHERE path = ?1 AND name = ?2"#,
                params![folder, name, *mode as i64],
            )?;
        }
        PendingFilesOp::ClearDeleted { path } => {
            let (folder, name) = WriteOverlay::split(path);
            conn.execute(
                r#"UPDATE "files" SET deleted = 0 WHERE path = ?1 AND name = ?2"#,
                params![folder, name],
            )?;
        }
    }
    Ok(())
}

/// Clear tombstones whose name already has a host file or symlink (#88).
///
/// One transaction, then the in-memory set. A tombstone with no host file
/// stays. A host directory does not count: see [`tombstone_has_host_file`].
/// This does not delete the host file. The duplicate-only crash row
/// (an archive member with neither a tombstone nor a host file) is left alone.
fn clear_tombstones_with_host_files(
    conn: &mut Connection,
    root: &Path,
    tombstones: &mut HashSet<String>,
) -> Result<()> {
    let shadowed: Vec<String> = tombstones
        .iter()
        .filter(|path| tombstone_has_host_file(root, path))
        .cloned()
        .collect();
    if shadowed.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    for path in &shadowed {
        let (folder, name) = WriteOverlay::split(path);
        tx.execute(
            r#"UPDATE "files" SET deleted = 0 WHERE path = ?1 AND name = ?2"#,
            params![folder, name],
        )?;
    }
    tx.commit()?;
    for path in &shadowed {
        tombstones.remove(path);
    }
    log::warn!(
        "overlay {}: cleared {} tombstone(s) that had a host file under the same name",
        root.display(),
        shadowed.len()
    );
    Ok(())
}

/// True when `mount_path` has a non-directory host entry (regular file or symlink).
///
/// A host directory does not count. `ensure_parent` and nested creates call
/// `create_dir_all` for parent folders while a directory tombstone stays set.
/// Treating that directory as "the name was replaced" would clear the tombstone
/// and resurrect the archive directory and its children. The crash window this
/// cleanup repairs is a file or symlink written under a still-deleted name
/// (host rename or create committed the bytes, then lost the `deleted = 0` update).
fn tombstone_has_host_file(root: &Path, mount_path: &str) -> bool {
    if is_overlay_internal_path(mount_path) {
        return false;
    }
    let host = overlay_host_path(root, mount_path);
    match fs::symlink_metadata(&host) {
        Ok(meta) => !meta.file_type().is_dir(),
        Err(_) => false,
    }
}

/// Load every `deleted = 1` row. Any SQL error (prepare, step, or a row that
/// does not decode) fails the overlay open: an empty or partial set would
/// make unlinked archive members reappear.
fn tombstone_set_from_conn(conn: &Connection) -> rusqlite::Result<HashSet<String>> {
    let mut stmt = conn.prepare(r#"SELECT path, name FROM "files" WHERE deleted = 1"#)?;
    let rows = stmt.query_map([], |row| {
        let folder: String = row.get(0)?;
        let name: String = row.get(1)?;
        Ok((folder, name))
    })?;
    let mut out = HashSet::new();
    for row in rows {
        let (folder, name) = row?;
        out.insert(tombstone_key(&folder, &name));
    }
    Ok(out)
}

fn delete_overlay_files_row(db: &Connection, rel: &str) -> Result<()> {
    db.execute(
        "DELETE FROM overlay_metadata WHERE path=?1",
        [normpath(rel)],
    )?;
    db.execute("DELETE FROM xattrs WHERE path=?1", [normpath(rel)])?;
    let (folder, name) = WriteOverlay::split(rel);
    db.execute(
        r#"DELETE FROM "files" WHERE path = ?1 AND name = ?2"#,
        params![folder, name],
    )?;
    Ok(())
}

fn prune_empty_overlay_ancestors(
    root: &Path,
    db: &Connection,
    start: &str,
    dropped_rows: &mut Vec<String>,
) -> Result<()> {
    let mut cur = Some(start.to_string());
    while let Some(rel) = cur {
        if rel.is_empty() || rel == "/" {
            break;
        }
        let host = if rel == "/" {
            root.to_path_buf()
        } else {
            root.join(rel.trim_start_matches('/'))
        };
        if host == root {
            break;
        }
        match fs::remove_dir(&host) {
            Ok(()) => {
                delete_overlay_files_row(db, &rel)?;
                dropped_rows.push(rel.clone());
                cur = rel.rsplit_once('/').map(|(p, _)| p.to_string());
            }
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.kind() == io::ErrorKind::DirectoryNotEmpty =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn confirm_commit(opts: &CommitOverlayOptions) -> Result<bool> {
    if opts.yes {
        return Ok(true);
    }
    print!("Please confirm by entering \"commit\". Any other input will cancel.\n> ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim() == "commit")
}

/// Strip leading `./` / `/` and trailing `/` for stable path matching.
fn normalize_archive_rel_path(path: &str) -> String {
    let p = path
        .trim_start_matches('/')
        .trim_start_matches("./")
        .trim_end_matches('/');
    p.to_string()
}

/// True if path looks like a ZIP local/central/EOCD signature (`PK…`).
fn is_zip_archive(path: &Path) -> Result<bool> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    if n >= 4 && magic[0] == b'P' && magic[1] == b'K' {
        // Local header, central directory, EOCD, or spanned data descriptor.
        return Ok(matches!(
            (magic[2], magic[3]),
            (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08) | (0x01, 0x02) | (0x06, 0x06) | (0x06, 0x07)
        ));
    }
    // Extension fallback (empty / exotic zips that don't open as files we can magic).
    Ok(path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip") || e.eq_ignore_ascii_case("jar")))
}

/// True when a ZIP member should be dropped (explicit delete or replaced by overlay).
fn zip_member_dropped(member_name: &str, plan: &OverlayCommitPlan) -> bool {
    let norm = normalize_archive_rel_path(member_name);
    if norm.is_empty() {
        return false;
    }
    if plan.deleted_paths.contains(&norm) {
        return true;
    }
    // Overlay replace / add with same path (dirs may only be in append_entries).
    plan.append_entries.iter().any(|(p, _)| p == &norm)
}

/// Rebuild ZIP from base + overlay (full archive rewrite, atomic replace).
///
/// Unchanged members are **raw-copied** (preserves store/deflate/etc.). Overlay files are
/// written with **deflate**. Not in-place append; cost is O(archive size).
fn commit_overlay_zip(
    write_overlay: &Path,
    zip_file: &Path,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    let plan = collect_overlay_commit_plan(write_overlay)?;

    if plan.is_empty() {
        if opts.debug >= 1 {
            println!("Nothing to commit.");
        }
        return Ok(false);
    }

    if opts.debug >= 1 {
        println!(
            "To commit the overlay folder to the ZIP archive, the archive will be fully rebuilt:"
        );
        println!();
        println!(
            "    # full rebuild (not in-place) of {}",
            zip_file.display()
        );
        if !plan.deleted_paths.is_empty() {
            println!(
                "    # drop {} deleted/replaced path(s)",
                plan.deleted_paths.len()
            );
        }
        if !plan.append_entries.is_empty() {
            println!(
                "    # add/replace {} overlay path(s) from {}",
                plan.append_entries.len(),
                write_overlay.display()
            );
            for (p, is_dir) in &plan.append_entries {
                if *is_dir {
                    println!("    #   dir  {p}/");
                } else {
                    println!("    #   file {p}  (deflate)");
                }
            }
        }
        println!();
        println!(
            "ZIP commit-overlay rewrites the entire archive (store/deflate members preserved \
             via raw copy; overlay files stored with deflate). Performance scales with size."
        );
        println!("Committing is an experimental feature!");
    }

    if !confirm_commit(opts)? {
        if opts.debug >= 1 {
            println!("Canceled");
        }
        return Ok(false);
    }

    rebuild_zip_with_overlay(write_overlay, zip_file, &plan)?;

    if opts.debug >= 1 {
        println!(
            "Committed successfully. You can now remove the overlay folder at {}.",
            write_overlay.display()
        );
    }
    Ok(true)
}

fn rebuild_zip_with_overlay(
    write_overlay: &Path,
    zip_file: &Path,
    plan: &OverlayCommitPlan,
) -> Result<()> {
    let src = File::open(zip_file).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to open ZIP '{}' for commit: {e}",
            zip_file.display()
        ))
    })?;
    let mut archive = ZipArchive::new(src).map_err(|e| {
        OverlayError::Msg(format!("Failed to read ZIP '{}': {e}", zip_file.display()))
    })?;

    let parent = zip_file.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(dir) => tempfile::NamedTempFile::new_in(dir)?,
        None => tempfile::NamedTempFile::new()?,
    };

    {
        let mut writer = ZipWriter::new(tmp.as_file_mut());

        // Preserve archive comment when present.
        let comment = archive.comment().to_vec();
        if !comment.is_empty() {
            writer.set_raw_comment(comment.into_boxed_slice());
        }

        let n = archive.len();
        for i in 0..n {
            let name = archive
                .name_for_index(i)
                .ok_or_else(|| OverlayError::Msg(format!("ZIP member index {i} has no name")))?
                .to_string();
            if zip_member_dropped(&name, plan) {
                continue;
            }
            // Raw copy preserves compression method and encrypted payload bytes without decrypt.
            let file = archive.by_index_raw(i).map_err(|e| {
                OverlayError::Msg(format!("Failed to read ZIP member '{name}' for copy: {e}"))
            })?;
            writer.raw_copy_file(file).map_err(|e| {
                OverlayError::Msg(format!("Failed to copy ZIP member '{name}': {e}"))
            })?;
        }

        let file_opts =
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let dir_opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

        for (rel, is_dir) in &plan.append_entries {
            if *is_dir {
                // ZIP directory entries conventionally end with '/'.
                let dir_name = if rel.ends_with('/') {
                    rel.clone()
                } else {
                    format!("{rel}/")
                };
                writer.add_directory(&dir_name, dir_opts).map_err(|e| {
                    OverlayError::Msg(format!("Failed to add directory '{dir_name}' to ZIP: {e}"))
                })?;
            } else {
                let src_path = write_overlay.join(rel);
                let mut src_file = File::open(&src_path).map_err(|e| {
                    OverlayError::Msg(format!(
                        "Failed to open overlay file '{}': {e}",
                        src_path.display()
                    ))
                })?;
                writer.start_file(rel.as_str(), file_opts).map_err(|e| {
                    OverlayError::Msg(format!("Failed to start ZIP file '{rel}': {e}"))
                })?;
                io::copy(&mut src_file, &mut writer).map_err(|e| {
                    OverlayError::Msg(format!(
                        "Failed to write overlay file '{rel}' into ZIP: {e}"
                    ))
                })?;
            }
        }

        writer.finish().map_err(|e| {
            OverlayError::Msg(format!(
                "Failed to finalize rebuilt ZIP for '{}': {e}",
                zip_file.display()
            ))
        })?;
    }
    tmp.as_file().sync_all()?;

    tmp.persist(zip_file).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to replace '{}' with rebuilt ZIP: {}",
            zip_file.display(),
            e.error
        ))
    })?;
    Ok(())
}

/// Apply overlay to TAR — `.tar.zst` splice, else GNU tar (uncompressed / gzip / bzip2 / xz).
fn commit_overlay_tar(
    write_overlay: &Path,
    tar_file: &Path,
    opts: &CommitOverlayOptions,
    original: &fs::Metadata,
) -> Result<bool> {
    let format = detect_compression(tar_file).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to detect compression for '{}': {e}",
            tar_file.display()
        ))
    })?;

    if format == CompressionFormat::Zstd {
        if !looks_like_tar_zst(tar_file)? {
            return Err(OverlayError::Msg(
                "Currently, commit-overlay supports ZIP, uncompressed TAR, gzip/bzip2/xz \
                 compressed TAR, and .tar.zst (got Zstd; plain .zst is not a TAR)."
                    .into(),
            ));
        }
        return commit_overlay_tar_zst(write_overlay, tar_file, opts, original);
    }

    let mut copy_from = crate::journal_recovery::CopyFrom::Gate;
    if format == CompressionFormat::None && opts.mode.may_append(tar_file)? {
        let plan = collect_overlay_commit_plan(write_overlay)?;
        if plan.is_empty() {
            return Ok(false);
        }
        let patch_opts = OpenOptions {
            encoding: opts.encoding.clone(),
            index_folders: vec![PathBuf::new()],
            ..OpenOptions::default()
        };
        let mut canceled = false;
        let attempt = (|| -> std::result::Result<
            Option<IndexPatchWindow>,
            crate::journal_recovery::FailedReplace,
        > {
            if uncompressed_append_offset(tar_file, &plan, &opts.encoding)?.is_none() {
                return Ok(None);
            }
            if opts.debug >= 1 {
                println!(
                    "Append {} new members to '{}' in place (journaled tail replacement).",
                    plan.append_entries.len(),
                    tar_file.display()
                );
                for (path, _) in &plan.append_entries {
                    println!("    add {path}");
                }
            }
            if !confirm_commit(opts)? {
                canceled = true;
                return Ok(None);
            }
            invalidate_stale_commit_sidecar(tar_file, &patch_opts)?;
            let db = write_overlay.join(HIDDEN_DB);
            append_uncompressed_tar_plan(
                tar_file,
                write_overlay,
                &plan,
                &opts.encoding,
                &crate::journal_recovery::Rows::Path(&db),
                original,
            )
        })();
        if canceled {
            return Ok(false);
        }
        match attempt {
            Ok(Some(window)) => {
                patch_sidecar_if_present(tar_file, &window, &patch_opts)?;
                return Ok(true);
            }
            Ok(None) => {}
            Err(failed) => copy_from = copy_after_failed_replace(failed, opts.mode)?,
        }
    }
    ensure_gnu_tar()?;

    // Keep work temp alive through delete/append (and recompress for compressed).
    // Uncompressed offline matches live: sibling copy; replace only on success.
    let mut copy_source = None;
    let (work_tar, work_holder): (PathBuf, Option<tempfile::NamedTempFile>) = match format {
        CompressionFormat::None => {
            if !is_uncompressed_tar(tar_file)? {
                return Err(OverlayError::Msg(
                    "Archive does not look like an uncompressed TAR or ZIP \
                     (ustar/GNU magic missing; ZIP uses PK signature)."
                        .into(),
                ));
            }
            let parent = tar_file
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let (mut src, source) =
                crate::journal_recovery::open_copy_source(tar_file, original, copy_from)?;
            let (tmp, method) = ratarmount_compress::fastcopy::copy_to_temp(&mut src, parent)?;
            ratarmount_compress::fastcopy::log_commit_copy(source.len(), method);
            copy_source = Some(source);
            tmp.as_file().sync_all()?;
            let path = tmp.path().to_path_buf();
            (path, Some(tmp))
        }
        CompressionFormat::Gzip | CompressionFormat::Bzip2 | CompressionFormat::Xz => {
            let (tmp, _) = materialize(tar_file, format).map_err(|e| {
                OverlayError::Msg(format!(
                    "Failed to decompress '{}' for commit: {e}",
                    tar_file.display()
                ))
            })?;
            if !is_uncompressed_tar(tmp.path())? {
                return Err(OverlayError::Msg(format!(
                    "Decompressed content of '{}' does not look like a TAR archive.",
                    tar_file.display()
                )));
            }
            let path = tmp.path().to_path_buf();
            (path, Some(tmp))
        }
        other => {
            return Err(OverlayError::Msg(format!(
                "Currently, commit-overlay supports ZIP, uncompressed TAR, gzip/bzip2/xz \
                 compressed TAR, and .tar.zst (got {other:?})."
            )));
        }
    };

    let plan = collect_overlay_commit_plan(write_overlay)?;

    let tmp = tempfile::tempdir()?;
    let deletion_list = tmp.path().join("deletions.lst");
    let append_list = tmp.path().join("append.lst");

    fs::write(&deletion_list, &plan.deletions_nul)?;
    fs::write(&append_list, &plan.appends_nul)?;

    if plan.is_empty() {
        if opts.debug >= 1 {
            println!("Nothing to commit.");
        }
        return Ok(false);
    }

    if opts.debug >= 1 {
        println!(
            "To commit the overlay folder to the archive, these commands have to be executed:"
        );
        println!();
        if format != CompressionFormat::None {
            println!("    # decompress {} -> temp TAR, then:", tar_file.display());
        }
        if !plan.deletions_nul.is_empty() {
            println!(
                "    tar --delete --ignore-zeros --null --files-from='{}' --file '{}' 2>&1 |",
                deletion_list.display(),
                work_tar.display()
            );
            println!("       sed '/^tar: Exiting with failure/d; /^tar.*Not found in archive/d'");
        }
        if !plan.appends_nul.is_empty() {
            println!(
                "    tar --append --ignore-zeros -C '{}' --null --files-from='{}' --file '{}'",
                write_overlay.display(),
                append_list.display(),
                work_tar.display()
            );
        }
        if format != CompressionFormat::None {
            println!(
                "    # recompress temp TAR -> {} ({format:?})",
                tar_file.display()
            );
        }
        println!();
        println!("Committing is an experimental feature!");
    }

    if !confirm_commit(opts)? {
        if opts.debug >= 1 {
            println!("Canceled");
        }
        return Ok(false);
    }

    if !plan.deletions_nul.is_empty() {
        let output = tar_env_command()
            .args([
                "--delete",
                "--ignore-zeros",
                "--null",
                &format!("--files-from={}", deletion_list.display()),
                "--file",
            ])
            .arg(&work_tar)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let unfiltered: Vec<&str> = stderr
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty()
                    && !line.contains("tar: Exiting with failure")
                    && !line.contains("Not found in archive")
            })
            .collect();
        if !unfiltered.is_empty() {
            for line in &unfiltered {
                eprintln!("{line}");
            }
            return Err(gnu_tar_delete_problems_err(&unfiltered));
        }
    }

    if !plan.appends_nul.is_empty() {
        let status = tar_env_command()
            .args(["--append", "--ignore-zeros", "-C"])
            .arg(write_overlay)
            .args([
                "--null",
                &format!("--files-from={}", append_list.display()),
                "--file",
            ])
            .arg(&work_tar)
            .status()?;
        if !status.success() {
            return Err(OverlayError::Msg(format!(
                "tar --append failed with {status}"
            )));
        }
    }

    if format != CompressionFormat::None {
        recompress_replace(&work_tar, tar_file, format)?;
        // Keep materialized temp alive until recompress finishes.
        drop(work_holder);
    } else {
        let tmp = work_holder.ok_or_else(|| {
            OverlayError::Msg(
                "internal error: missing work temp for uncompressed offline commit".into(),
            )
        })?;
        tmp.as_file().sync_all()?;
        let source = copy_source.ok_or_else(|| {
            OverlayError::Msg("internal error: missing copy source for offline commit".into())
        })?;
        crate::journal_recovery::publish_over(tar_file, &source, || {
            tmp.persist(tar_file).map(drop).map_err(|e| e.error)
        })
        .map_err(|e| {
            OverlayError::Msg(format!(
                "Failed to replace '{}' after offline TAR commit: {e}",
                tar_file.display(),
            ))
        })?;
    }

    if opts.debug >= 1 {
        println!(
            "Committed successfully. You can now remove the overlay folder at {}.",
            write_overlay.display()
        );
    }
    Ok(true)
}

/// Offline `.tar.zst`: splice from the affected frame (append-only uses last-N).
/// Never GNU tar / materialize / recompress. Splice already persists atomically.
fn commit_overlay_tar_zst(
    write_overlay: &Path,
    tar_file: &Path,
    opts: &CommitOverlayOptions,
    original: &fs::Metadata,
) -> Result<bool> {
    let plan = collect_overlay_commit_plan(write_overlay)?;
    if plan.is_empty() {
        if opts.debug >= 1 {
            println!("Nothing to commit.");
        }
        return Ok(false);
    }

    if opts.debug >= 1 {
        println!(
            "To commit the overlay folder to '{}', ratarmount will splice zstd frames \
             (rewrite from the affected frame, requested persistence mode {:?}; no GNU tar).",
            tar_file.display(),
            opts.mode
        );
        for (path, _) in &plan.append_entries {
            println!("    add/replace {path}");
        }
        println!();
        println!("Committing is an experimental feature!");
    }

    if !confirm_commit(opts)? {
        if opts.debug >= 1 {
            println!("Canceled");
        }
        return Ok(false);
    }

    let map = scan_zstd_frames_path(tar_file).map_err(|e| OverlayError::Msg(e.to_string()))?;
    // Always walk past per-frame TAR EOF. Mount `-i` only controls listing
    // visibility; a tombstone for a later complete-TAR frame must still map
    // to offsetheaders. With `ignore_zeros: false` those names look like
    // overlay-only adds, the delete is skipped, and commit still returns
    // success — then removing the overlay (as the success text suggests)
    // undeletes the member. Pin GNU incremental off so a later-frame
    // dumpdir does not flip classification.
    let base = tar_zst_full_frame_index(tar_file, opts.encoding.as_str())?;

    let mut rewrite_deletes = HashSet::new();
    let mut ohs = Vec::new();
    for path in &plan.deleted_paths {
        let path_ohs = all_tar_offsetheaders(&base, path)?;
        if path_ohs.is_empty() {
            // Overlay-only add: walk marks replace=delete+append, but the name
            // is not in the archive. rewrite_tar_suffix errors on a missing delete.
            continue;
        }
        rewrite_deletes.insert(path.clone());
        ohs.extend(path_ohs);
    }
    ohs.sort_unstable();
    ohs.dedup();

    let from_idx = if ohs.is_empty() {
        find_last_n_tar_window(tar_file, &map, "offline --commit-overlay")?.0
    } else {
        offline_tar_zst_from_idx(tar_file, &map, ohs[0])?
    };

    let window_plain: u64 = map.frames[from_idx..]
        .iter()
        .map(|f| f.uncompressed_size)
        .sum();
    warn_large_zstd_window("offline --commit-overlay", window_plain);

    let overlay_root = write_overlay.canonicalize().map_err(OverlayError::Io)?;
    let pending = collect_ustar_pending_at(&overlay_root, &plan.append_entries)?;
    let encoding = opts.encoding.clone();

    let append = opts.mode.may_append(tar_file)?
        && map.seek_table.is_some()
        && rewrite_deletes.is_empty()
        && plan
            .append_entries
            .iter()
            .all(|(p, _)| base.lookup(&archive_lookup_path(p), 0).is_none());
    let transform = |mut suffix: &mut dyn ratarmount_compress::SeekRead,
                     stream_offset,
                     mut out: &mut dyn Write| {
        let members: Vec<UstarMember<'_>> = pending.iter().map(PendingUstar::as_member).collect();
        let rewrite = RewriteTarSuffix {
            deleted_paths: &rewrite_deletes,
            append: &members,
            encoding: encoding.as_str(),
        };
        rewrite_tar_suffix(&mut suffix, stream_offset, &rewrite, &mut out).map(|_| ())
    };
    let patch_opts = OpenOptions {
        encoding: opts.encoding.clone(),
        ignore_zeros: true,
        write_index: false,
        index_folders: vec![PathBuf::new()],
        ..OpenOptions::default()
    };
    invalidate_stale_commit_sidecar(tar_file, &patch_opts)?;
    if append {
        let db = write_overlay.join(HIDDEN_DB);
        let rows = crate::journal_recovery::Rows::Path(&db);
        match crate::journal_recovery::splice_append_committing(
            tar_file, from_idx, transform, original, &rows,
        ) {
            Ok(stats) => stats,
            Err(failed) => {
                let copy_from = copy_after_failed_replace(failed, opts.mode)?;
                crate::journal_recovery::splice_replace_over(
                    tar_file, from_idx, transform, original, copy_from,
                )?
            }
        }
    } else {
        crate::journal_recovery::splice_replace_over(
            tar_file,
            from_idx,
            transform,
            original,
            crate::journal_recovery::CopyFrom::Gate,
        )?
    };

    let window = IndexPatchWindow {
        window_start: map.frames[from_idx].uncompressed_offset,
        from_frame: Some(from_idx),
        offsets_shifted: false,
    };
    // Sibling only: do not create a sidecar; do not hunt XDG (K3 / offline).
    patch_sidecar_if_present(tar_file, &window, &patch_opts)?;

    if opts.debug >= 1 {
        let prefix = map.frames[from_idx].compressed_offset;
        println!(
            "Committed .tar.zst ({} frames, from_idx={from_idx}, prefix {prefix} bytes preserved).",
            map.frames.len()
        );
        println!(
            "Committed successfully. You can now remove the overlay folder at {}.",
            write_overlay.display()
        );
    }
    Ok(true)
}

/// Compress `plain` with `format` and atomically replace `dest`.
fn recompress_replace(plain: &Path, dest: &Path, format: CompressionFormat) -> Result<()> {
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match parent {
        Some(dir) => tempfile::NamedTempFile::new_in(dir)?,
        None => tempfile::NamedTempFile::new()?,
    };

    {
        let mut src = BufReader::new(File::open(plain)?);
        let mut out = BufWriter::new(tmp.as_file_mut());
        match format {
            CompressionFormat::Gzip => {
                let mut enc = GzEncoder::new(&mut out, GzCompression::default());
                io::copy(&mut src, &mut enc)?;
                enc.finish()?;
            }
            CompressionFormat::Bzip2 => {
                let mut enc = BzEncoder::new(&mut out, bzip2::Compression::default());
                io::copy(&mut src, &mut enc)?;
                enc.finish()?;
            }
            CompressionFormat::Xz => {
                let mut enc = XzEncoder::new(&mut out, 6);
                io::copy(&mut src, &mut enc)?;
                enc.finish()?;
            }
            other => {
                return Err(OverlayError::Msg(format!(
                    "internal: recompress_replace called with unsupported format {other:?}"
                )));
            }
        }
        out.flush()?;
    }
    tmp.as_file().sync_all()?;

    // Atomic replace on the same filesystem (parent chosen to match dest).
    tmp.persist(dest).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to replace '{}' with recompressed archive: {}",
            dest.display(),
            e.error
        ))
    })?;
    Ok(())
}

fn join_rel(path: &str, name: &str) -> String {
    let path = path.trim_start_matches('/').trim_end_matches('/');
    if path.is_empty() {
        name.trim_start_matches('/').to_string()
    } else {
        format!("{path}/{}", name.trim_start_matches('/'))
    }
}

fn add_deletion_variants(buf: &mut Vec<u8>, path_relative_to_root: &str) {
    let p = path_relative_to_root.trim_start_matches('/');
    for variant in [p.to_string(), format!("/{p}"), format!("./{p}")] {
        buf.extend(variant.as_bytes());
        buf.push(0);
    }
}

/// Uncompressed TAR or `.tar.zst` — gzip/bzip2/xz TAR and ZIP stay rejected.
pub fn live_commit_is_supported(archive: &Path) -> Result<()> {
    if is_zip_archive(archive)? {
        return Err(OverlayError::Msg(
            "live overlay commit supports uncompressed TAR only (not ZIP)".into(),
        ));
    }
    let format = detect_live_commit_format(archive)?;
    match format {
        CompressionFormat::None => {
            if !is_uncompressed_tar(archive)? {
                return Err(OverlayError::Msg(format!(
                    "'{}' is not an uncompressed TAR",
                    archive.display()
                )));
            }
            Ok(())
        }
        CompressionFormat::Zstd => {
            if !looks_like_tar_zst(archive)? {
                return Err(OverlayError::Msg(
                    "plain .zst is not a TAR; live commit not supported".into(),
                ));
            }
            Ok(())
        }
        CompressionFormat::Gzip | CompressionFormat::Bzip2 | CompressionFormat::Xz => {
            Err(OverlayError::Msg(format!(
                "live overlay commit supports uncompressed TAR and .tar.zst only \
                 (got {format:?}; gzip/bzip2/xz stay offline --commit-overlay)"
            )))
        }
        other => Err(OverlayError::Msg(format!(
            "live overlay commit supports uncompressed TAR and .tar.zst only (got {other:?})"
        ))),
    }
}

fn detect_live_commit_format(archive: &Path) -> Result<CompressionFormat> {
    detect_compression(archive).map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to detect compression for '{}': {e}",
            archive.display()
        ))
    })
}

fn interval_disabled_err() -> OverlayError {
    OverlayError::Msg("live overlay commit disabled after reopen failure; remount required".into())
}

/// On-exit wait: 2× last persist duration, at least 60s (fail-closed flush, not skip).
const ON_EXIT_WAIT_MIN: Duration = Duration::from_secs(60);

/// v1 still downloads the whole object. Warn above this; do not refuse.
const REMOTE_SPOOL_WARN_BYTES: u64 = 1024 * 1024 * 1024;

fn remote_on_exit_timeout_err() -> OverlayError {
    OverlayError::Msg("remote on-exit timed out waiting for in-flight persist".into())
}

const REMOTE_ON_EXIT_EXTRA_DEFAULT: Duration = Duration::from_secs(120);

fn file_sha256(path: &Path) -> Result<String> {
    let mut f = File::open(path)?;
    ratarmount_index::sha256_hex_stream(&mut f).map_err(|e| OverlayError::Msg(e.to_string()))
}

/// Bytes of the downloaded object before `persist_by_format`.
struct PrespliceFingerprint {
    len: u64,
    sha256: String,
    prefix512_sha256: String,
    suffix512_sha256: String,
}

fn presplice_fingerprint(path: &Path) -> Result<PrespliceFingerprint> {
    let (prefix512_sha256, suffix512_sha256) = ratarmount_index::archive_edge_hashes(path)
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    Ok(PrespliceFingerprint {
        len: fs::metadata(path)?.len(),
        sha256: file_sha256(path)?,
        prefix512_sha256,
        suffix512_sha256,
    })
}

fn files_same_len_and_hash(a: &Path, b: &Path) -> Result<bool> {
    let la = fs::metadata(a)?.len();
    let lb = fs::metadata(b)?.len();
    if la != lb {
        return Ok(false);
    }
    Ok(file_sha256(a)? == file_sha256(b)?)
}

fn set_spool_mode_0600(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Sets `commit_inflight` for the lifetime of a live persist; clears + notifies on drop.
struct InFlightGuard<'a> {
    overlay: &'a WriteOverlay,
}

impl<'a> InFlightGuard<'a> {
    fn try_begin(overlay: &'a WriteOverlay) -> Option<Self> {
        overlay
            .commit_inflight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self { overlay })
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.overlay.commit_inflight.store(false, Ordering::SeqCst);
        let _g = self
            .overlay
            .commit_wait
            .lock()
            .expect("overlay commit wait");
        self.overlay.commit_cv.notify_all();
    }
}

/// `.tar.zst` / `.tzst` / `.tar.zstd` only — not `.taz`.
pub fn name_suggests_tar_zst(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let l = name.to_ascii_lowercase();
    l.ends_with(".tar.zst") || l.ends_with(".tzst") || l.ends_with(".tar.zstd")
}

fn looks_like_tar_zst(archive: &Path) -> Result<bool> {
    if name_suggests_tar_zst(archive) {
        return Ok(true);
    }
    let body = open_seekable_zstd(archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
    body_looks_like_tar(&body).map_err(|e| OverlayError::Msg(e.to_string()))
}

const LAST_FRAME_WARN_BYTES: u64 = 64 * 1024 * 1024;

fn last_zstd_plain_needs_warn(plain: u64) -> bool {
    plain > LAST_FRAME_WARN_BYTES
}

fn warn_large_zstd_window(kind: &str, window_plain: u64) {
    if last_zstd_plain_needs_warn(window_plain) {
        log::warn!(
            "{kind} .tar.zst commit will rewrite {window_plain} uncompressed \
             (large last frame); persist still copies the compressed file"
        );
    }
}

/// Grow last-N until the decoded suffix contains a TAR EOF (K6). Never refuse on size.
fn find_last_n_tar_window(archive: &Path, map: &ZstdFrameMap, kind: &str) -> Result<(usize, u64)> {
    if map.frames.is_empty() {
        return Err(OverlayError::Msg("TAR EOF not found (truncated?)".into()));
    }
    let last_plain = map.frames.last().map(|f| f.uncompressed_size).unwrap_or(0);
    warn_large_zstd_window(kind, last_plain);
    let mut src = File::open(archive)?;
    for n in 1..=map.frames.len() {
        let from_idx = map.frames.len() - n;
        let window_plain: u64 = map.frames[from_idx..]
            .iter()
            .map(|f| f.uncompressed_size)
            .sum();
        if n > 1 {
            warn_large_zstd_window(kind, window_plain);
        }
        let mut suffix = tempfile::spooled_tempfile(DEFAULT_MEMORY_CAP as usize);
        decode_zstd_frames_to(&mut src, map, from_idx, &mut suffix)
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
        suffix.seek(SeekFrom::Start(0))?;
        let stream_offset = map.frames[from_idx].uncompressed_offset;
        // The window must both contain the TAR EOF and start at a parseable
        // member boundary (or be pure padding). A member spanning the whole
        // window has no findable data end — grow the window instead of
        // risking a miscut.
        let has_eof = find_last_tar_eof(&mut suffix, stream_offset)?.is_some();
        let has_boundary = window_has_member_boundary(&mut suffix, stream_offset)
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
        if has_eof && has_boundary {
            return Ok((from_idx, stream_offset));
        }
    }
    Err(OverlayError::Msg(
        "TAR EOF / member boundary not found (truncated?)".into(),
    ))
}

enum TarZstPathClass {
    OverlayOnly,
    LastWindow,
}

fn tar_offsetheaders_in(fi: &FileInfo) -> impl Iterator<Item = u64> + '_ {
    fi.userdata.iter().filter_map(|u| match u {
        UserData::Tar(t) => t.offsetheader,
        _ => None,
    })
}

fn lookup_version(base: &dyn MountSource, path: &str, i: i32) -> Option<FileInfo> {
    // Always probe `.versions/{i}` first. `FileVersionLayer(AutoMount)` reports
    // `versions() == 1` (AutoMount uses the trait default) while older copies
    // only exist at `{path}.versions/{i}`.
    if i >= 1 {
        if let Some(fi) = base.lookup(&format!("{path}.versions/{i}"), 0) {
            return Some(fi);
        }
    }
    base.lookup(path, i)
}

fn archive_lookup_path(rel: &str) -> String {
    let n = normalize_archive_rel_path(rel);
    if n.is_empty() {
        "/".into()
    } else {
        format!("/{n}")
    }
}

fn all_tar_offsetheaders(base: &dyn MountSource, path: &str) -> Result<Vec<u64>> {
    let path = archive_lookup_path(path);
    let mut out = Vec::new();
    // Walk `.versions/{i}` until miss. Do not stop at `versions()` — AutoMount
    // (and similar wrappers) report 1 even when FileVersionLayer exposes more.
    const MAX_VERSION_WALK: i32 = 1024;
    for i in 1..=MAX_VERSION_WALK {
        match base.lookup(&format!("{path}.versions/{i}"), 0) {
            Some(fi) => out.extend(tar_offsetheaders_in(&fi)),
            None => break,
        }
    }
    let nver = base.versions(&path);
    if nver == 0 && out.is_empty() {
        if let Some(fi) = base.lookup(&path, 0) {
            out.extend(tar_offsetheaders_in(&fi));
            if out.is_empty() {
                return Err(cannot_classify_err(&path));
            }
        }
        return Ok(out);
    }
    for i in 1..=nver {
        if let Some(fi) = lookup_version(base, &path, i as i32) {
            out.extend(tar_offsetheaders_in(&fi));
        }
    }
    if let Some(fi) = base.lookup(&path, 0) {
        out.extend(tar_offsetheaders_in(&fi));
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err(cannot_classify_err(&path));
    }
    Ok(out)
}

fn cannot_classify_err(path: &str) -> OverlayError {
    OverlayError::Msg(format!(
        ".tar.zst overlay commit cannot classify '{path}' (no TAR offsetheader)"
    ))
}

fn earlier_frame_err(path: &str) -> OverlayError {
    let shown = archive_lookup_path(path);
    OverlayError::Msg(format!(
        "error: live overlay commit for .tar.zst is append-only (and last-frame replace/delete);\n\
               '{shown}' has a version in an earlier zstd frame\n\
               (delete would undelete that copy). The whole commit was skipped\n\
               (including pending appends). Undo the delete, omit\n\
               --commit-overlay-interval / --commit-overlay-on-exit, or use offline\n\
               --commit-overlay (rewrites from the affected frame)."
    ))
}

fn frame_covering_uncomp(map: &ZstdFrameMap, uncomp: u64) -> Result<usize> {
    map.frames
        .iter()
        .enumerate()
        .find_map(|(i, f)| {
            let start = f.uncompressed_offset;
            let end = start.saturating_add(f.uncompressed_size);
            (uncomp >= start && uncomp < end).then_some(i)
        })
        .ok_or_else(|| {
            OverlayError::Msg(format!(
                "offline .tar.zst commit: offsetheader {uncomp} is not inside any zstd frame"
            ))
        })
}

fn suffix_window_has_member_boundary(
    src: &mut File,
    map: &ZstdFrameMap,
    from_idx: usize,
) -> Result<bool> {
    let mut suffix = tempfile::spooled_tempfile(DEFAULT_MEMORY_CAP as usize);
    decode_zstd_frames_to(src, map, from_idx, &mut suffix)
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    suffix.seek(SeekFrom::Start(0))?;
    let stream_offset = map.frames[from_idx].uncompressed_offset;
    window_has_member_boundary(&mut suffix, stream_offset)
        .map_err(|e| OverlayError::Msg(e.to_string()))
}

/// Ceiling `from_idx`: never start rewrite after the affected member; grow the
/// window backward until the suffix has a TAR member boundary.
fn offline_tar_zst_from_idx(archive: &Path, map: &ZstdFrameMap, min_oh: u64) -> Result<usize> {
    if map.frames.is_empty() {
        return Err(OverlayError::Msg("TAR EOF not found (truncated?)".into()));
    }
    let from_idx0 = frame_covering_uncomp(map, min_oh)?;
    let mut from_idx = from_idx0;
    let mut src = File::open(archive)?;
    while from_idx > 0 {
        if suffix_window_has_member_boundary(&mut src, map, from_idx)? {
            break;
        }
        from_idx -= 1;
    }
    debug_assert!(from_idx <= from_idx0);
    Ok(from_idx)
}

/// In-memory index that walks past per-frame TAR EOF.
///
/// Mount `-i` only controls listing visibility. Delete classification must
/// still see later complete-TAR frames, or a tombstone looks overlay-only,
/// the splice skips it, and a successful commit undeletes the member.
fn tar_zst_full_frame_index(archive: &Path, encoding: &str) -> Result<SqliteIndexedTar> {
    let body = open_seekable_zstd(archive).map_err(|e| OverlayError::Msg(e.to_string()))?;
    let index_opts = OpenOptions {
        write_index: false,
        index_in_memory: true,
        encoding: encoding.to_string(),
        ignore_zeros: true,
        gnu_incremental: Some(false),
        ..OpenOptions::default()
    };
    SqliteIndexedTar::create_index_body(archive, body, None, &index_opts, env!("CARGO_PKG_VERSION"))
        .map_err(|e| OverlayError::Msg(e.to_string()))
}

fn classify_tar_zst_path(
    base: &dyn MountSource,
    path: &str,
    rewrite_window_start_uncomp: u64,
) -> Result<TarZstPathClass> {
    let ohs = all_tar_offsetheaders(base, path)?;
    if ohs.is_empty() {
        return Ok(TarZstPathClass::OverlayOnly);
    }
    if ohs.iter().any(|&oh| oh < rewrite_window_start_uncomp) {
        return Err(earlier_frame_err(path));
    }
    Ok(TarZstPathClass::LastWindow)
}

struct PendingUstar {
    path: String,
    host: PathBuf,
    kind: PendingKind,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
    xattrs: Vec<(String, Vec<u8>)>,
    sha256: Option<Mutex<Option<String>>>,
}

enum PendingKind {
    FileOnDisk { size: u64 },
    Directory,
    Symlink { target: String },
}

impl PendingUstar {
    fn as_member(&self) -> UstarMember<'_> {
        UstarMember {
            xattrs: &self.xattrs,
            path: &self.path,
            payload: match &self.kind {
                PendingKind::FileOnDisk { size } => UstarPayload::FileOnDisk {
                    path: &self.host,
                    size: *size,
                    sha256: self.sha256.as_ref(),
                },
                PendingKind::Directory => UstarPayload::Directory,
                PendingKind::Symlink { target } => UstarPayload::Symlink { target },
            },
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime: self.mtime,
        }
    }
}

fn reset_overlay_dir(root: &Path) -> Result<()> {
    let rd = match fs::read_dir(root) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name_s = name.to_string_lossy();
        // Same (ASCII case-insensitive) rule the mount uses to hide them.
        if is_overlay_internal_name(&name_s) {
            continue;
        }
        let p = ent.path();
        let meta = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_dir() {
            fs::remove_dir_all(&p)?;
        } else {
            fs::remove_file(&p)?;
        }
    }
    Ok(())
}

fn is_uncompressed_tar(path: &Path) -> Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(path)?;
    // Reject common compression magics
    let mut magic = [0u8; 6];
    let n = f.read(&mut magic)?;
    if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return Ok(false); // gzip
    }
    if n >= 3 && &magic[..3] == b"BZh" {
        return Ok(false);
    }
    if n >= 6 && &magic[..6] == b"\xFD7zXZ\0" {
        return Ok(false);
    }
    if n >= 4 && &magic[..4] == b"\x28\xb5\x2f\xfd" {
        return Ok(false);
    }
    // ustar at 257
    f.seek(SeekFrom::Start(257))?;
    let mut ustar = [0u8; 5];
    let n = f.read(&mut ustar)?;
    if n == 5 && (&ustar == b"ustar" || ustar.starts_with(b"ustar") || &ustar == b"GNU  ") {
        return Ok(true);
    }
    Ok(is_posix_or_gnu_empty_tar(&mut f)?)
}

/// POSIX/GNU empty TAR: 1024..=10240, 512-aligned, all-zero. Reads at most 10 KiB.
fn is_posix_or_gnu_empty_tar(f: &mut File) -> io::Result<bool> {
    let n = f.metadata()?.len();
    if !(1024..=10240).contains(&n) || n % 512 != 0 {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; 10240];
    let len = n as usize;
    f.read_exact(&mut buf[..len])?;
    Ok(buf[..len].iter().all(|&b| b == 0))
}

/// Resolve a GNU tar binary (`tar` on Linux, often `gtar` via Homebrew on macOS).
fn find_gnu_tar() -> Option<PathBuf> {
    for name in ["gtar", "gnutar", "tar"] {
        let Ok(out) = Command::new(name).arg("--version").output() else {
            continue;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("GNU tar") {
            return Some(PathBuf::from(name));
        }
    }
    None
}

fn ensure_gnu_tar() -> Result<()> {
    if find_gnu_tar().is_some() {
        return Ok(());
    }
    Err(OverlayError::Msg(
        "Currently, GNU tar is required for --commit-overlay \
         (install `gtar` via Homebrew on macOS, or use Linux GNU tar)."
            .into(),
    ))
}

fn tar_env_command() -> Command {
    let bin = find_gnu_tar().unwrap_or_else(|| PathBuf::from("tar"));
    let mut cmd = Command::new(bin);
    // Locale C for reproducible/stable messages (Python run_without_locale)
    cmd.env("LC_ALL", "C");
    cmd.env("LC_LANG", "C");
    cmd.env("LANGUAGE", "C");
    // Clear LC_* that might already be set by clearing via env_clear is too aggressive;
    // setting LC_ALL=C is enough for most systems.
    cmd
}

/// Map unfiltered GNU tar `--delete` stderr lines into the overlay error.
///
/// Includes the stderr text so callers/tests can detect known broken builds
/// (e.g. Debian tar 1.35 `lseek: … Value too large for defined data type`) —
/// the historical fixed string alone did not contain `"GNU tar"` / `lseek`.
fn gnu_tar_delete_problems_err(unfiltered: &[&str]) -> OverlayError {
    OverlayError::Msg(format!(
        "There were problems when trying to delete files: {}",
        unfiltered.join("; ")
    ))
}

struct WalkEntry {
    path: PathBuf,
    is_dir: bool,
}

/// Files + empty directories under `root` (topdown=False equivalent for empty dirs).
fn walkdir_files_and_empty_dirs(root: &Path) -> Result<Vec<WalkEntry>> {
    let mut out = Vec::new();
    fn walk(dir: &Path, root: &Path, out: &mut Vec<WalkEntry>) -> Result<()> {
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let rd = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let ft = ent.file_type()?;
            if ft.is_dir() {
                dirs.push(p);
            } else if ft.is_file() || ft.is_symlink() {
                files.push(p);
            }
        }
        for d in &dirs {
            walk(d, root, out)?;
        }
        for f in files {
            out.push(WalkEntry {
                path: f,
                is_dir: false,
            });
        }
        // Empty directory (no files; may still have subdirs already walked)
        if dirs.is_empty() {
            // re-check: empty of files and dirs
            let empty = fs::read_dir(dir)?.next().is_none();
            if empty && dir != root {
                out.push(WalkEntry {
                    path: dir.to_path_buf(),
                    is_dir: true,
                });
            }
        } else {
            // Python: if not filenames and dirpath: append empty folder
            // Only when this dir has no filenames (even if it has subdirs that had content)
            let has_file = fs::read_dir(dir)?.any(|e| {
                e.ok()
                    .map(|e| {
                        e.file_type()
                            .map(|t| t.is_file() || t.is_symlink())
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            });
            if !has_file && dir != root {
                // Still append dirpath if no files directly — matches Python "not filenames"
                out.push(WalkEntry {
                    path: dir.to_path_buf(),
                    is_dir: true,
                });
            }
        }
        Ok(())
    }
    walk(root, root, &mut out)?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
pub(crate) mod tests {
    use super::*;

    /// Offline commit without a classified base: the in-crate fixtures open
    /// overlays with `new_for_tests`, which record no base to check.
    fn commit_overlay(
        write_overlay: impl AsRef<Path>,
        archive_file: impl AsRef<Path>,
        opts: &CommitOverlayOptions,
    ) -> Result<bool> {
        commit_overlay_inner(write_overlay.as_ref(), archive_file.as_ref(), None, opts)
    }

    use ratarmount_compress::{open_seekable_bzip2, open_seekable_xz};
    use std::process::Command as StdCommand;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipArchive, ZipWriter};

    /// Regression: a panicking policy must not poison every subsequent mutation.
    #[test]
    fn regression_policy_panic_does_not_poison_mutations() {
        struct PanicOnce(AtomicBool);
        impl OverlayPolicy for PanicOnce {
            fn check_mutation(&self, _: OverlayMutation, _: &[&str]) -> io::Result<()> {
                assert!(
                    !self.0.swap(false, Ordering::SeqCst),
                    "injected policy panic"
                );
                Ok(())
            }
            fn check_write(&self, _: &str, _: u64, _: u64, _: u64) -> io::Result<()> {
                Ok(())
            }
        }
        let td = tempfile::tempdir().unwrap();
        let mut ov = WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), td.path()).unwrap();
        ov.set_policy(Some(Arc::new(PanicOnce(AtomicBool::new(true)))));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || ov.mkdir("/first", 0o755)
        ))
        .is_err());
        ov.mkdir("/second", 0o755).unwrap();
    }

    /// Regression: truncating a large archive member charges/copies only the final extent.
    #[cfg(unix)]
    #[test]
    fn regression_truncate_large_member_under_small_quota() {
        let (td, ov, policy) = policy_overlay(
            Arc::new(MemBase::with(&[
                ("/zero", b"large member"),
                ("/prefix", b"large member"),
                ("/open", b"large member"),
            ])),
            3,
        );
        ov.truncate("/zero", 0).unwrap();
        ov.truncate("/prefix", 3).unwrap();
        let fd = ov
            .open_overlay_fd("/open", libc::O_WRONLY | libc::O_TRUNC)
            .unwrap();
        ov.close_overlay_fd(fd);
        assert_eq!(fs::read(td.path().join("prefix")).unwrap(), b"lar");
        assert_eq!(fs::metadata(td.path().join("zero")).unwrap().len(), 0);
        assert_eq!(fs::metadata(td.path().join("open")).unwrap().len(), 0);
        assert_eq!(policy.usage(), (3, 3));
    }

    /// Regression: Linux O_RDONLY|O_TRUNC must truncate under a policy too.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_readonly_trunc_open_matches_kernel() {
        let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 8);
        let file = policy_file(&ov, "/file");
        ov.write_at(&file, "/file", 0, b"data").unwrap();
        let fd = ov
            .open_overlay_fd("/file", libc::O_RDONLY | libc::O_TRUNC)
            .unwrap();
        ov.close_overlay_fd(fd);
        assert_eq!(file.metadata().unwrap().len(), 0);
        assert_eq!(policy.usage(), (0, 1));
        ov.finish_owned_write_fd(file);
    }

    /// Regression: repeated create/unlink/write cannot evade quota via open inodes.
    #[cfg(unix)]
    #[test]
    fn regression_unlinked_writers_retain_growth_until_last_close() {
        use std::os::fd::AsRawFd;
        let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 8);
        let first = policy_file(&ov, "/file");
        ov.unlink("/file").unwrap();
        ov.write_at(&first, "/file", 0, b"1234").unwrap();
        let alias = ov.clone_overlay_fd(first.as_raw_fd(), "/file").unwrap();
        let second = policy_file(&ov, "/file");
        ov.unlink("/file").unwrap();
        ov.truncate_file(&second, "/file", 4).unwrap();
        let third = policy_file(&ov, "/file");
        ov.unlink("/file").unwrap();
        assert_eq!(
            ov.write_at(&third, "/file", 0, b"x").unwrap_err().kind(),
            io::ErrorKind::QuotaExceeded
        );
        ov.finish_owned_write_fd(first);
        assert_eq!(policy.usage().0, 8, "duplicate still owns the charge");
        ov.finish_owned_write_fd(alias);
        assert_eq!(policy.usage().0, 4);
        ov.write_at(&third, "/file", 0, b"x").unwrap();
        ov.finish_owned_write_fd(second);
        ov.finish_owned_write_fd(third);
        assert_eq!(policy.usage(), (0, 0));
    }

    /// Regression: slow COW decompression must not hold the global policy lock.
    #[cfg(unix)]
    #[test]
    fn regression_slow_cow_does_not_block_small_write() {
        let (_td, ov, policy) =
            policy_overlay(Arc::new(MemBase::with(&[("/large", b"abcdef")])), 8);
        let small = policy_file(&ov, "/small");
        let ov = Arc::new(ov);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        *ov.cow_before_read_hook.lock().unwrap() = Some(Box::new(move || {
            started_tx.send(()).unwrap();
            resume_rx.recv().unwrap();
        }));
        let copy_ov = ov.clone();
        let copy = std::thread::spawn(move || copy_ov.ensure_modifiable("/large"));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(policy.usage().0, 6, "COW extent reserved before reading");
        let write_ov = ov.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let write = std::thread::spawn(move || {
            let result = write_ov.write_at(&small, "/small", 0, b"xy");
            write_ov.finish_owned_write_fd(small);
            done_tx.send(result).unwrap();
        });
        let result = done_rx.recv_timeout(Duration::from_secs(5));
        resume_tx.send(()).unwrap();
        copy.join().unwrap().unwrap();
        write.join().unwrap();
        assert_eq!(result.unwrap().unwrap(), 2);
        assert_eq!(policy.usage(), (8, 2));
    }

    /// Regression: rename's SQL retry/backoff must not monopolize policy checks.
    #[test]
    fn regression_rename_retry_releases_policy_gate() {
        let (_td, ov, _) = policy_overlay(Arc::new(MemBase::with(&[("/source", b"x")])), 8);
        let ov = Arc::new(ov);
        let weak = Arc::downgrade(&ov);
        ov.set_rename_before_tx_hook(Some(Box::new(move || {
            assert!(weak.upgrade().unwrap().policy_gate.try_lock().is_ok());
            Err(OverlayError::Msg("injected retry".into()))
        })));
        ov.rename("/source", "/dest").unwrap();
    }

    /// Regression: post-persist read_dir failure disables further commits rather than duplicating members.
    #[test]
    fn regression_commit_cleanup_read_dir_failure_disables_interval() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", b"seed")]);
        let (_td, ov, _) = policy_overlay(open_tar_zst_base(&archive, false), 8);
        let fd = ov.create_file("/new", 0o644).unwrap();
        ov.close_overlay_fd(fd);
        ov.account_reset_failure.store(true, Ordering::SeqCst);
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("persist succeeded; overlay cleanup failed"),
            "{err}"
        );
        assert!(ov.interval_disabled());
        let persisted = fs::read(&archive).unwrap();
        assert!(ov
            .commit_live(&archive, |_| panic!("disabled commit reopened"))
            .is_err());
        assert_eq!(fs::read(&archive).unwrap(), persisted);
        assert!(open_tar_zst_base(&archive, false)
            .lookup("/new", 0)
            .is_some());
    }

    /// Regression: append-mode descriptors must charge growth even with offset zero.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_overlay_policy_append_cannot_bypass_quota() {
        use std::os::fd::FromRawFd;
        let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 4);
        let file = unsafe {
            File::from_raw_fd(
                ov.open_overlay_fd("/append", libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND)
                    .unwrap(),
            )
        };
        ov.write_at(&file, "/append", 0, b"ab").unwrap();
        ov.write_at(&file, "/append", 0, b"cd").unwrap();
        assert_eq!(policy.usage(), (4, 1));
        assert_eq!(
            ov.write_at(&file, "/append", 0, b"e").unwrap_err().kind(),
            io::ErrorKind::QuotaExceeded
        );
        assert_eq!(file.metadata().unwrap().len(), 4);
        ov.finish_owned_write_fd(file);
    }

    /// Regression: a failed COW must not publish the short prefix or keep its quota (#126).
    #[test]
    fn regression_overlay_policy_accounts_partial_cow_failure() {
        struct PartialReader(io::Cursor<Vec<u8>>);
        impl Read for PartialReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.position() >= 3 {
                    return Err(io::Error::other("injected read failure"));
                }
                self.0.read(buf)
            }
        }
        impl Seek for PartialReader {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.0.seek(pos)
            }
        }
        struct PartialBase;
        impl MountSource for PartialBase {
            fn list(&self, _: &str) -> Option<ListResult> {
                None
            }
            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                (path == "/partial").then(|| mem_file_info(path, 6))
            }
            fn open(
                &self,
                _: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                Ok(Box::new(PartialReader(io::Cursor::new(b"abc".to_vec()))))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }
        let (td, ov, policy) = policy_overlay(Arc::new(PartialBase), 8);
        let host = td.path().join("partial");
        let err = ov.ensure_modifiable("/partial");
        let bytes = fs::read(&host).ok();
        assert!(
            err.is_err() && bytes.is_none() && policy.usage() == (0, 0),
            "failed COW must drop the partial and refund; err={err:?} bytes={bytes:?} usage={:?}",
            policy.usage()
        );
    }

    /// Regression: a 6-byte member whose read returns 3 bytes then EOF is not
    /// published, and the quota charge is refunded to the pre-COW usage (#126).
    #[test]
    fn regression_overlay_policy_accounts_short_cow_eof_slack() {
        struct EofAfter3(io::Cursor<Vec<u8>>);
        impl Read for EofAfter3 {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.position() >= 3 {
                    return Ok(0);
                }
                let room = (3 - self.0.position()) as usize;
                let n = room.min(buf.len());
                self.0.read(&mut buf[..n])
            }
        }
        impl Seek for EofAfter3 {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.0.seek(pos)
            }
        }
        struct ShortBase;
        impl MountSource for ShortBase {
            fn list(&self, _: &str) -> Option<ListResult> {
                None
            }
            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                (path == "/short").then(|| mem_file_info(path, 6))
            }
            fn open(
                &self,
                _: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                Ok(Box::new(EofAfter3(io::Cursor::new(b"abcdef".to_vec()))))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }
        let (td, ov, policy) = policy_overlay(Arc::new(ShortBase), 8);
        let before = policy.usage();
        let host = td.path().join("short");
        let err = ov.ensure_modifiable("/short");
        let bytes = fs::read(&host).ok();
        assert!(
            matches!(
                &err,
                Err(OverlayError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
            ) && bytes.is_none()
                && policy.usage() == before,
            "short EOF must not publish and must refund the quota charge; err={err:?} bytes={bytes:?} before={before:?} usage={:?}",
            policy.usage()
        );
    }

    /// Regression: without a quota policy, a 6-byte member whose read returns 3
    /// bytes then EOF is not published and leaves no staging file (#126).
    #[test]
    fn regression_cow_short_eof_default_path_not_published() {
        struct EofAfter3(io::Cursor<Vec<u8>>);
        impl Read for EofAfter3 {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.position() >= 3 {
                    return Ok(0);
                }
                let room = (3 - self.0.position()) as usize;
                let n = room.min(buf.len());
                self.0.read(&mut buf[..n])
            }
        }
        impl Seek for EofAfter3 {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.0.seek(pos)
            }
        }
        struct ShortBase;
        impl MountSource for ShortBase {
            fn list(&self, _: &str) -> Option<ListResult> {
                None
            }
            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                (path == "/short").then(|| mem_file_info(path, 6))
            }
            fn open(
                &self,
                _: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                Ok(Box::new(EofAfter3(io::Cursor::new(b"abcdef".to_vec()))))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }
        let td = tempfile::tempdir().unwrap();
        let ov = WriteOverlay::new_for_tests(Arc::new(ShortBase), td.path()).unwrap();
        let host = td.path().join("short");
        let err = ov.ensure_modifiable("/short");
        let bytes = fs::read(&host).ok();
        let staged = fs::read_dir(td.path())
            .unwrap()
            .flatten()
            .any(|ent| name_has_cow_prefix(&ent.file_name().to_string_lossy()));
        assert!(
            matches!(
                &err,
                Err(OverlayError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
            ) && bytes.is_none()
                && !staged,
            "short EOF must not publish the final name or leave staging; err={err:?} bytes={bytes:?} staged={staged}"
        );
    }

    fn name_has_cow_prefix(name: &str) -> bool {
        has_ascii_prefix(name, COW_STAGING_PREFIX)
    }

    /// Regression: a reader that dies mid-copy must not leave the short bytes at
    /// the final name, and a crashed `.ratarmount.overlay.cow-` temp must not be
    /// committed (#126).
    #[test]
    fn regression_cow_crash_mid_copy_hides_partial_and_skips_commit() {
        let original = b"abcdef";
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let mount_tar = dir.path().join("mount.tar");
        let one_tar = dir.path().join("one.tar");
        {
            let mut f = File::create(&mount_tar).unwrap();
            ratarmount_formats_tar::write_ustar_members(
                &mut f,
                &[
                    ustar_file("big.bin", original),
                    ustar_file("keep.txt", b"keep"),
                ],
            )
            .unwrap();
            ratarmount_formats_tar::write_tar_eof(&mut f).unwrap();
        }
        {
            let mut f = File::create(&one_tar).unwrap();
            ratarmount_formats_tar::write_ustar_members(&mut f, &[ustar_file("big.bin", original)])
                .unwrap();
            ratarmount_formats_tar::write_tar_eof(&mut f).unwrap();
        }

        struct CrashReader {
            overlay: PathBuf,
            data: Vec<u8>,
            pos: usize,
        }
        impl Read for CrashReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos >= 3 {
                    let host = self.overlay.join("big.bin");
                    let staged = fs::read_dir(&self.overlay)
                        .map(|rd| {
                            rd.flatten()
                                .any(|ent| name_has_cow_prefix(&ent.file_name().to_string_lossy()))
                        })
                        .unwrap_or(false);
                    let bytes = fs::read(&host).ok();
                    assert!(
                        staged && !host.exists(),
                        "mid-copy must stage a .ratarmount.overlay.cow- file and leave big.bin absent; staged={staged} big.bin={bytes:?}"
                    );
                    return Err(io::Error::other("injected read failure"));
                }
                let n = (3 - self.pos)
                    .min(buf.len())
                    .min(self.data.len() - self.pos);
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }
        impl Seek for CrashReader {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                let len = self.data.len() as i64;
                let cur = self.pos as i64;
                let next = match pos {
                    SeekFrom::Start(n) => n as i64,
                    SeekFrom::Current(n) => cur + n,
                    SeekFrom::End(n) => len + n,
                };
                if next < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek before start",
                    ));
                }
                self.pos = next as usize;
                Ok(self.pos as u64)
            }
        }
        struct CrashBase {
            overlay: PathBuf,
            big: Vec<u8>,
        }
        impl MountSource for CrashBase {
            fn list(&self, path: &str) -> Option<ListResult> {
                if path != "/" {
                    return None;
                }
                let mut map = BTreeMap::new();
                map.insert(
                    "big.bin".into(),
                    mem_file_info("/big.bin", self.big.len() as u64),
                );
                map.insert("keep.txt".into(), mem_file_info("/keep.txt", 4));
                Some(ListResult::Infos(map))
            }
            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                match path {
                    "/" => Some(create_root_file_info()),
                    "/big.bin" => Some(mem_file_info(path, self.big.len() as u64)),
                    "/keep.txt" => Some(mem_file_info(path, 4)),
                    _ => None,
                }
            }
            fn open(
                &self,
                file_info: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                let path = file_info.userdata.iter().rev().find_map(|u| match u {
                    UserData::Other(s) => s.strip_prefix("mem:"),
                    _ => None,
                });
                if path == Some("/big.bin") {
                    return Ok(Box::new(CrashReader {
                        overlay: self.overlay.clone(),
                        data: self.big.clone(),
                        pos: 0,
                    }));
                }
                Ok(Box::new(io::Cursor::new(b"keep".to_vec())))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }

        let ov = WriteOverlay::new_for_tests(
            Arc::new(CrashBase {
                overlay: overlay.clone(),
                big: original.to_vec(),
            }),
            &overlay,
        )
        .unwrap();
        ov.unlink("/keep.txt").unwrap();
        assert!(ov.lookup("/keep.txt", 0).is_none());
        let err = ov.ensure_modifiable("/big.bin");
        assert!(err.is_err(), "{err:?}");
        assert!(
            !overlay.join("big.bin").exists(),
            "host big.bin must be absent, got {:?}",
            fs::read(overlay.join("big.bin")).ok()
        );
        assert!(
            fs::read_dir(&overlay)
                .unwrap()
                .flatten()
                .all(|ent| { !name_has_cow_prefix(&ent.file_name().to_string_lossy()) }),
            "failed COW must drop its staging temp"
        );
        drop(ov);

        fs::create_dir_all(overlay.join("sub")).unwrap();
        fs::write(overlay.join(".ratarmount.overlay.cow-Ab12Cd"), b"short").unwrap();
        fs::write(
            overlay.join("sub").join(".ratarmount.overlay.cow-Ab12Cd"),
            b"short",
        )
        .unwrap();
        fs::write(
            overlay.join("sub").join(".RATARMOUNT.OVERLAY.COW-Xy"),
            b"short",
        )
        .unwrap();
        let plan = collect_overlay_commit_plan(&overlay).unwrap();
        assert!(
            plan.append_entries
                .iter()
                .all(|(p, _)| { p != "big.bin" && !p.split('/').any(name_has_cow_prefix) }),
            "commit plan must omit the partial and cow temps: {:?}",
            plan.append_entries
        );
        match commit_overlay(&overlay, &one_tar, &yes_commit_opts()) {
            Ok(_) => {
                let src = open_uncompressed_tar_base(&one_tar, false);
                assert_eq!(read_member(src.as_ref(), "/big.bin"), original);
            }
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: commit_overlay needs GNU tar: {e}");
            }
            Err(e) => panic!("{e}"),
        }

        let ov =
            WriteOverlay::new_for_tests(open_uncompressed_tar_base(&mount_tar, false), &overlay)
                .unwrap();
        assert!(!overlay.join(".ratarmount.overlay.cow-Ab12Cd").exists());
        assert!(!overlay
            .join("sub")
            .join(".ratarmount.overlay.cow-Ab12Cd")
            .exists());
        assert!(!overlay
            .join("sub")
            .join(".RATARMOUNT.OVERLAY.COW-Xy")
            .exists());
        assert!(overlay.join(HIDDEN_DB).is_file());
        assert!(overlay.join(OVERLAY_MARKER).is_file());
        assert!(ov.is_deleted("/keep.txt"));
        assert!(ov.lookup("/keep.txt", 0).is_none());
        let fi = ov.lookup("/big.bin", 0).unwrap();
        assert_eq!(fi.size, original.len() as u64);
        assert_eq!(ov.read(&fi, original.len(), 0).unwrap(), original);
    }

    /// Regression: an unreadable overlay directory must not fail reopen (#126 v3).
    ///
    /// Symptom: the copy-on-write staging sweep returned the directory error,
    /// so `WriteOverlay::new` failed when a subdirectory was mode 000.
    #[cfg(unix)]
    #[test]
    fn regression_cow_v3_unreadable_dir_reopen() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip: euid 0 ignores mode 000");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        drop(WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay).unwrap());
        let locked = overlay.join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(
            locked.join(format!("{COW_STAGING_PREFIX}Ab12Cd")),
            b"leftover",
        )
        .unwrap();
        struct RestoreMode {
            path: PathBuf,
        }
        impl Drop for RestoreMode {
            fn drop(&mut self) {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755));
            }
        }
        let _restore = RestoreMode {
            path: locked.clone(),
        };
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        }
        let err = WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay).err();
        assert!(
            err.is_none(),
            "unreadable dir must not fail reopen: {err:?}"
        );
    }

    /// Regression: a second open must not sweep another holder's staging file (#126 v3).
    ///
    /// Symptom: `PRAGMA LOCKING_MODE = EXCLUSIVE` keeps only a shared lock until
    /// the first write. After schema creation, a reopen does not write, so a
    /// second `WriteOverlay::new` succeeded and deleted the in-progress temp.
    #[test]
    fn regression_cow_v3_second_open_keeps_staging() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        drop(WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay).unwrap());
        let first = WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay).unwrap();
        let staging = overlay.join(format!("{COW_STAGING_PREFIX}Ab12Cd"));
        fs::write(&staging, b"in-progress").unwrap();
        match WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay) {
            Ok(_) => panic!("second open must be refused while the first holds the lock"),
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                assert!(
                    msg.contains("locked") || msg.contains("busy"),
                    "second open must be refused with the database lock, got {e}"
                );
            }
        }
        assert_eq!(fs::read(&staging).unwrap(), b"in-progress");
        drop(first);
    }

    /// Regression: `persist_noclobber` AlreadyExists refunds the reservation (#126 v3).
    ///
    /// Symptom: a final name created after the reservation and before publish
    /// was counted or replaced. The existing bytes must stay, the reservation
    /// must be refunded by Drop, and the staging temp must be removed.
    #[test]
    fn regression_cow_v3_already_exists_refunds() {
        let (td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/race", b"abcdef")])), 64);
        let host = td.path().join("race");
        let existing = b"keep-me";
        let ov = Arc::new(ov);
        let host_for_hook = host.clone();
        *ov.cow_before_read_hook.lock().unwrap() = Some(Box::new(move || {
            fs::write(&host_for_hook, existing).unwrap();
        }));
        let before = policy.usage();
        ov.ensure_modifiable("/race").unwrap();
        assert_eq!(
            policy.usage(),
            before,
            "AlreadyExists must skip file_created and let Drop refund the reservation"
        );
        assert_eq!(fs::read(&host).unwrap(), existing);
        assert!(
            fs::read_dir(td.path())
                .unwrap()
                .flatten()
                .all(|ent| { !name_has_cow_prefix(&ent.file_name().to_string_lossy()) }),
            "staging temp must be removed"
        );
    }

    /// Regression: a persist error other than `AlreadyExists` refunds the reservation (#126 v3).
    ///
    /// Symptom: replacing the parent directory with a regular file makes
    /// `persist_noclobber` return `ENOTDIR` (`NotADirectory`, not `ENOENT`:
    /// the path component exists and is not a directory). That must not
    /// publish `/d/race`, must not run `file_created`, and Drop must refund.
    #[cfg(unix)]
    #[test]
    fn regression_cow_v3_persist_error_refunds() {
        let (td, ov, policy) =
            policy_overlay(Arc::new(MemBase::with(&[("/d/race", b"abcdef")])), 64);
        fs::create_dir(td.path().join("d")).unwrap();
        let overlay = td.path().to_path_buf();
        *ov.cow_before_persist_hook.lock().unwrap() = Some(Box::new(move || {
            let parent = overlay.join("d");
            fs::rename(&parent, overlay.join("d.held")).unwrap();
            fs::write(&parent, b"not-a-directory").unwrap();
        }));
        let before = policy.usage();
        let err = match ov.ensure_modifiable("/d/race").unwrap_err() {
            OverlayError::Io(err) => err,
            other => panic!("persist error must be io, got {other}"),
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::NotADirectory,
            "non-AlreadyExists persist error must surface, got {err}"
        );
        assert_eq!(
            policy.usage(),
            before,
            "persist error must skip file_created and let Drop refund the reservation"
        );
        assert!(
            !td.path().join("d").join("race").exists(),
            "final name must not be published"
        );
    }

    /// Regression: a directory fsync error after publish keeps the charge (#126 v3).
    ///
    /// Symptom: ignoring the parent `sync_all` error would report success, and
    /// refunding after `file_created` would drop a file that is already named.
    #[cfg(unix)]
    #[test]
    fn regression_cow_v3_dir_fsync_error_keeps_charge() {
        let (td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/m", b"abcdef")])), 64);
        FAIL_COW_DIR_FSYNC.set(true);
        let err = match ov.ensure_modifiable("/m").unwrap_err() {
            OverlayError::Io(err) => err,
            other => panic!("directory fsync error must be io, got {other}"),
        };
        assert!(
            err.to_string().contains("injected directory fsync failure"),
            "{err}"
        );
        assert_eq!(fs::read(td.path().join("m")).unwrap(), b"abcdef");
        assert_eq!(
            policy.usage(),
            (6, 1),
            "published file must stay charged after a parent fsync error"
        );
    }

    /// Regression: read-only opens of an existing host file must not invoke a write policy.
    #[cfg(unix)]
    #[test]
    fn regression_overlay_policy_read_open_still_allowed() {
        let td = tempfile::tempdir().unwrap();
        let mut ov = WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), td.path()).unwrap();
        ov.mkdir("/locked", 0o755).unwrap();
        let file = policy_file(&ov, "/locked/file");
        ov.write_at(&file, "/locked/file", 0, b"base").unwrap();
        ov.finish_owned_write_fd(file);
        ov.set_policy(Some(Arc::new(CountingPolicy::new(0))));
        let fd = ov.open_overlay_fd("/locked/file", libc::O_RDONLY).unwrap();
        ov.close_overlay_fd(fd);
        assert!(
            matches!(ov.reset_overlay_contents(), Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::ReadOnlyFilesystem)
        );
        assert_eq!(fs::read(td.path().join("locked/file")).unwrap(), b"base");
    }

    struct CountingPolicy {
        limit: u64,
        usage: Mutex<(u64, u64)>,
    }

    impl CountingPolicy {
        fn new(limit: u64) -> Self {
            Self {
                limit,
                usage: Mutex::new((0, 0)),
            }
        }
        fn usage(&self) -> (u64, u64) {
            *self.usage.lock().unwrap()
        }
    }

    impl OverlayPolicy for CountingPolicy {
        fn check_mutation(&self, _: OverlayMutation, paths: &[&str]) -> io::Result<()> {
            if paths
                .iter()
                .any(|p| *p == "/locked" || p.starts_with("/locked/"))
            {
                return Err(io::Error::new(io::ErrorKind::ReadOnlyFilesystem, "locked"));
            }
            Ok(())
        }
        fn check_write(&self, _: &str, offset: u64, len: u64, current_size: u64) -> io::Result<()> {
            let growth = offset.saturating_add(len).saturating_sub(current_size);
            if self.usage().0.saturating_add(growth) > self.limit {
                return Err(io::Error::new(io::ErrorKind::QuotaExceeded, "quota"));
            }
            Ok(())
        }
        fn bytes_changed(&self, _: &str, added: u64, removed: u64) {
            let mut usage = self.usage.lock().unwrap();
            usage.0 = usage
                .0
                .checked_add(added)
                .unwrap()
                .checked_sub(removed)
                .unwrap();
        }
        fn file_created(&self, _: &str) {
            self.usage.lock().unwrap().1 += 1;
        }
        fn file_removed(&self, _: &str) {
            self.usage.lock().unwrap().1 -= 1;
        }
    }

    /// Regression: policy-path COW applies the member's mode and mtime on the
    /// staging fd before publish (#126 v3, Keystone).
    ///
    /// Symptom: dropping the fd `fchmod`/`futimens` step on the Unix policy
    /// path publishes the copy with the umask mode and the current time.
    #[cfg(unix)]
    #[test]
    fn regression_cow_policy_applies_member_mode_and_mtime() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut base = MemBase::with(&[("/m", b"abcdef")]);
        let info = base.files.get_mut("/m").unwrap();
        info.mode = ratarmount_core::S_IFREG | 0o751;
        info.mtime = 1_000_000_000.0;
        let (td, ov, _policy) = policy_overlay(Arc::new(base), 64);
        ov.ensure_modifiable("/m").unwrap();
        let md = fs::symlink_metadata(td.path().join("m")).unwrap();
        assert_eq!(
            md.permissions().mode() & 0o7777,
            0o751,
            "member mode must be applied"
        );
        assert_eq!(md.mtime(), 1_000_000_000, "member mtime must be applied");
        assert_eq!(fs::read(td.path().join("m")).unwrap(), b"abcdef");
    }

    fn policy_overlay(
        base: Arc<dyn MountSource>,
        limit: u64,
    ) -> (tempfile::TempDir, WriteOverlay, Arc<CountingPolicy>) {
        let td = tempfile::tempdir().unwrap();
        let mut ov = WriteOverlay::new_for_tests(base, td.path()).unwrap();
        let policy = Arc::new(CountingPolicy::new(limit));
        ov.set_policy(Some(policy.clone()));
        (td, ov, policy)
    }

    #[cfg(unix)]
    fn policy_file(ov: &WriteOverlay, path: &str) -> File {
        use std::os::fd::FromRawFd;
        unsafe {
            File::from_raw_fd(
                ov.open_overlay_fd(path, libc::O_RDWR | libc::O_CREAT)
                    .unwrap(),
            )
        }
    }

    /// Regression: readonly paths reject COW, both rename endpoints, and all mutations before side effects.
    #[test]
    fn regression_overlay_policy_denials_leave_names_unchanged() {
        let (td, ov, policy) = policy_overlay(
            Arc::new(MemBase::with(&[
                ("/locked/file", b"base"),
                ("/outside", b"source"),
            ])),
            64,
        );
        let results = [
            ov.ensure_modifiable("/locked/file"),
            ov.create_file("/locked/new", 0o644)
                .map(|fd| ov.close_overlay_fd(fd)),
            ov.mkdir("/locked/dir", 0o755),
            ov.unlink("/locked/file"),
            ov.unlink_parked("/locked/file").map(|_| ()),
            ov.rmdir("/locked/empty"),
            ov.truncate("/locked/file", 0),
            ov.create_symlink("/locked/link", "target"),
            ov.rename("/locked/file", "/moved"),
            ov.rename("/outside", "/locked/file"),
            ov.rename_parked("/outside", "/locked/file").map(|_| ()),
        ];
        for result in results {
            assert!(
                matches!(result, Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::ReadOnlyFilesystem)
            );
        }
        assert!(!td.path().join("locked").exists());
        assert!(!td.path().join("outside").exists());
        assert_eq!(policy.usage(), (0, 0));
        assert_eq!(ov.lookup("/locked/file", 0).unwrap().size, 4);
    }

    /// Regression: COW, sparse writes, overwrite, truncate, symlink and rename-over account actual host growth once.
    #[cfg(unix)]
    #[test]
    fn regression_overlay_policy_accounts_cow_truncate_rename_and_reset() {
        let (_td, ov, policy) =
            policy_overlay(Arc::new(MemBase::with(&[("/base", b"abcdef")])), 64);
        ov.ensure_modifiable("/base").unwrap();
        ov.ensure_modifiable("/base").unwrap();
        assert_eq!(policy.usage(), (6, 1));
        let file = policy_file(&ov, "/base");
        ov.write_at(&file, "/base", 8, b"xy").unwrap();
        assert_eq!(policy.usage(), (10, 1));
        ov.write_at(&file, "/base", 0, b"xy").unwrap();
        assert_eq!(policy.usage(), (10, 1));
        ov.truncate("/base", 3).unwrap();
        assert_eq!(policy.usage(), (3, 1));
        let fd = ov.create_file("/base", 0o644).unwrap();
        ov.close_overlay_fd(fd);
        assert_eq!(policy.usage(), (0, 1));
        ov.create_symlink("/link", "foo").unwrap();
        assert_eq!(policy.usage(), (3, 2));
        ov.unlink("/link").unwrap();
        assert_eq!(policy.usage(), (0, 1));
        ov.write_at(&file, "/base", 0, b"abc").unwrap();
        let dst = policy_file(&ov, "/dest");
        ov.write_at(&dst, "/dest", 0, b"1234").unwrap();
        assert_eq!(policy.usage(), (7, 2));
        ov.rename("/base", "/dest").unwrap();
        assert_eq!(policy.usage(), (3, 1));
        // Detached growth remains charged; shrinking releases only that growth.
        ov.write_at(&dst, "/dest", 8, b"orphan").unwrap();
        ov.truncate_file(&dst, "/dest", 1).unwrap();
        assert_eq!(policy.usage(), (3, 1));
        ov.finish_owned_write_fd(file);
        ov.finish_owned_write_fd(dst);
        ov.create_symlink("/dangling", "/missing/target").unwrap();
        ov.reset_overlay_contents().unwrap();
        assert_eq!(policy.usage(), (0, 0));
    }

    /// Regression: quota refusal cannot leave a full COW copy or enlarge a truncated file.
    #[cfg(unix)]
    #[test]
    fn regression_overlay_policy_quota_cow_and_truncate() {
        let (td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/large", b"abcdef")])), 4);
        assert!(
            matches!(ov.ensure_modifiable("/large"), Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::QuotaExceeded)
        );
        assert!(!td.path().join("large").exists());
        let file = policy_file(&ov, "/small");
        ov.write_at(&file, "/small", 0, b"abcd").unwrap();
        assert_eq!(
            ov.write_at(&file, "/small", 4, b"x").unwrap_err().kind(),
            io::ErrorKind::QuotaExceeded
        );
        assert!(
            matches!(ov.truncate("/small", 5), Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::QuotaExceeded)
        );
        assert_eq!(file.metadata().unwrap().len(), 4);
        let refused = ov.open_overlay_fd(
            "/small",
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC,
        );
        assert!(
            matches!(refused, Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(file.metadata().unwrap().len(), 4);
        assert_eq!(policy.usage(), (4, 1));
        let fd = ov
            .open_overlay_fd("/small", libc::O_RDWR | libc::O_TRUNC)
            .unwrap();
        ov.close_overlay_fd(fd);
        assert_eq!(policy.usage(), (0, 1));
        ov.finish_owned_write_fd(file);
    }

    /// Regression: concurrent checks cannot both spend the same quota allowance.
    #[cfg(unix)]
    #[test]
    fn regression_overlay_policy_concurrent_writes_do_not_overspend() {
        let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 8);
        let ov = Arc::new(ov);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = ["/a", "/b"]
            .into_iter()
            .map(|path| {
                let ov = ov.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let file = policy_file(&ov, path);
                    barrier.wait();
                    let result = ov.write_at(&file, path, 0, b"12345678");
                    ov.finish_owned_write_fd(file);
                    result
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .find_map(|r| r.as_ref().err())
                .unwrap()
                .kind(),
            io::ErrorKind::QuotaExceeded
        );
        assert_eq!(policy.usage(), (8, 2));
    }

    /// Regression: commit cleanup must release quota for removed host files.
    #[cfg(unix)]
    #[test]
    fn regression_overlay_policy_commit_cleanup_releases_usage() {
        let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 8);
        let file = policy_file(&ov, "/file");
        ov.write_at(&file, "/file", 0, b"abcd").unwrap();
        ov.finish_owned_write_fd(file);
        let plan = OverlayCommitPlan {
            known_hashes: BTreeMap::new(),
            written_hashes: BTreeMap::new(),
            metadata: BTreeMap::new(),
            xattrs: BTreeMap::new(),
            deletions_nul: Vec::new(),
            appends_nul: Vec::new(),
            deleted_paths: HashSet::new(),
            append_entries: vec![("file".into(), false)],
        };
        ov.forget_committed_overlay(&plan).unwrap();
        assert_eq!(policy.usage(), (0, 0));
    }

    fn write_zero_file(path: &Path, n: usize) {
        fs::write(path, vec![0u8; n]).unwrap();
    }

    /// Regression: POSIX empty TAR is recognized as uncompressed TAR.
    #[test]
    fn is_uncompressed_tar_posix_empty_1024_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.tar");
        {
            let mut f = File::create(&path).unwrap();
            ratarmount_formats_tar::write_tar_eof(&mut f).unwrap();
        }
        assert!(
            is_uncompressed_tar(&path).unwrap(),
            "1024-zero POSIX empty TAR"
        );
        assert!(
            !ratarmount_compress::looks_like_tar(&path).unwrap(),
            "looks_like_tar must stay false on 1024 zeros"
        );
    }

    #[test]
    fn is_uncompressed_tar_gnu_empty_10240_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.tar");
        write_zero_file(&path, 10240);
        assert!(is_uncompressed_tar(&path).unwrap());
    }

    #[test]
    fn is_uncompressed_tar_rejects_too_short_or_unaligned() {
        let dir = tempfile::tempdir().unwrap();
        for n in [0usize, 512, 1025] {
            let path = dir.path().join(format!("z{n}.tar"));
            write_zero_file(&path, n);
            assert!(
                !is_uncompressed_tar(&path).unwrap(),
                "{n}-byte zeros must not be an empty TAR"
            );
        }
    }

    #[test]
    fn is_uncompressed_tar_rejects_over_10240_zero_head_tail_dirty_middle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dirty.tar");
        let mut buf = vec![0u8; 20 * 1024];
        buf[12 * 1024] = 1;
        fs::write(&path, &buf).unwrap();
        assert!(!is_uncompressed_tar(&path).unwrap());
    }

    #[test]
    fn warn_large_zstd_window_1024_one_frame_does_not_warn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.tar.zst");
        let mut eof = Vec::new();
        ratarmount_formats_tar::write_tar_eof(&mut eof).unwrap();
        let zst = ratarmount_compress::encode_zstd_frame(&eof, 3).unwrap();
        fs::write(&path, zst).unwrap();
        let map = scan_zstd_frames_path(&path).unwrap();
        assert_eq!(map.frames.len(), 1);
        assert_eq!(map.frames[0].uncompressed_size, 1024);
        assert!(!last_zstd_plain_needs_warn(map.frames[0].uncompressed_size));
    }

    #[test]
    fn warn_large_zstd_window_last_frame_over_64mib_warns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.tar.zst");
        let plain = vec![0u8; (LAST_FRAME_WARN_BYTES as usize) + 1];
        let zst = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
        fs::write(&path, zst).unwrap();
        let map = scan_zstd_frames_path(&path).unwrap();
        assert_eq!(map.frames.len(), 1);
        assert!(map.frames[0].uncompressed_size > LAST_FRAME_WARN_BYTES);
        assert!(last_zstd_plain_needs_warn(map.frames[0].uncompressed_size));
    }

    fn write_sample_zip(path: &Path, members: &[(&str, &[u8], CompressionMethod)]) {
        let file = File::create(path).unwrap();
        let mut zw = ZipWriter::new(file);
        for (name, data, method) in members {
            let opts = SimpleFileOptions::default().compression_method(*method);
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }

    fn assert_committed_baseline(
        overlay: &Path,
        archive: &Path,
        info: &crate::overlay_meta::OverlayCreateInfo,
    ) {
        let meta = crate::OverlayMeta::read(overlay).unwrap().unwrap();
        let stamp = ratarmount_index::ArchiveDigestStamp::read(archive).unwrap();
        let digest = format!(
            "sha256:{}",
            ratarmount_index::sha256_hex(&fs::read(archive).unwrap())
        );
        assert_eq!(meta.base_digest(), Some(digest.as_str()));
        assert_eq!(meta.base_digest_kind(), Some("strong"));
        assert_eq!(meta.get("base_size"), Some(stamp.size.to_string().as_str()));
        assert_eq!(
            meta.get("base_mtime_ns"),
            Some(stamp.mtime_ns.to_string().as_str())
        );
        assert_eq!(
            meta.stack_digest(),
            Some(crate::overlay_meta::stack_digest(&digest, &[]).as_str())
        );
        assert!(meta.get("base_committed_at").is_some());
        assert!(meta.get("base_mismatch_forced_at").is_none());
        let conn = Connection::open(info.index_path.as_ref().unwrap()).unwrap();
        let cached: (String, String, String, String) = conn
            .query_row(
                "SELECT size, mtime_ns, inode, sha256 FROM overlay_base_digests",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            cached,
            (
                stamp.size.to_string(),
                stamp.mtime_ns.to_string(),
                stamp.inode.to_string(),
                digest[7..].to_owned()
            )
        );
        // Use the same default creation context as mount startup, with no override.
        drop(
            WriteOverlay::new_with_create_info_for_tests(Arc::new(NullBase), overlay, info)
                .unwrap(),
        );
        fs::OpenOptions::new()
            .append(true)
            .open(archive)
            .unwrap()
            .write_all(b"external change")
            .unwrap();
        let error = WriteOverlay::new_with_create_info_for_tests(Arc::new(NullBase), overlay, info)
            .err()
            .expect("external archive change must be refused");
        assert!(error.to_string().contains("base mismatch"), "{error}");
    }

    fn commit_baseline_case(
        extension: &str,
        mode: CommitMode,
        live: bool,
        atomic: bool,
        manifest: bool,
    ) {
        if extension == "tar" && mode == CommitMode::Copy {
            if let Err(error) = ensure_gnu_tar() {
                eprintln!("skip: {error}");
                return;
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(format!("base.{extension}"));
        let members = [ustar_file("old", b"original")];
        match extension {
            "zip" => write_sample_zip(&archive, &[("old", b"original", CompressionMethod::Stored)]),
            "tar.zst" => {
                fs::write(&archive, concat_zstd_frames(&[&pack_tar(&members)], true)).unwrap()
            }
            _ => fs::write(&archive, pack_tar(&members)).unwrap(),
        }
        let overlay = dir.path().join("overlay");
        let index = dir.path().join("custom-index.sqlite");
        Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        let info = crate::overlay_meta::OverlayCreateInfo {
            base_url: archive.to_str().unwrap().to_owned(),
            index_path: Some(index),
            ..Default::default()
        };
        let base = match extension {
            "tar" => open_uncompressed_tar_base(&archive, false),
            "tar.zst" => open_tar_zst_base(&archive, false),
            _ => Arc::new(NullBase) as Arc<dyn MountSource>,
        };
        let mut ov = WriteOverlay::new_with_create_info_for_tests(base, &overlay, &info).unwrap();
        ov.set_commit_mode(mode);
        fs::write(overlay.join("new"), b"new payload").unwrap();
        if live {
            assert!(ov
                .commit_live_idle(&archive, Duration::ZERO, |path| {
                    Ok(if extension == "tar" {
                        open_uncompressed_tar_base(path, false)
                    } else {
                        open_tar_zst_base(path, false)
                    })
                })
                .unwrap());
            assert!(!overlay.join("new").exists());
        } else if atomic {
            assert!(ov.commit_atomic(&archive).unwrap());
        } else {
            drop(ov);
            let opts = CommitOverlayOptions {
                mode,
                manifest_hashes: manifest.then(|| "all".to_owned()),
                ..yes_commit_opts()
            };
            assert!(commit_overlay(&overlay, &archive, &opts).unwrap());
            assert_committed_baseline(&overlay, &archive, &info);
            return;
        }
        drop(ov);
        assert_committed_baseline(&overlay, &archive, &info);
    }

    /// Regression: offline TAR commits left the overlay bound to the old archive bytes.
    #[test]
    fn regression_commit_overlay_tar_refreshes_baseline() {
        for mode in [CommitMode::Copy, CommitMode::Append] {
            commit_baseline_case("tar", mode, false, false, false);
        }
        commit_baseline_case("tar", CommitMode::Copy, false, false, true);
    }

    /// Regression: zstd splice and append commits caused a mismatch on remount.
    #[test]
    fn regression_commit_overlay_tar_zst_refreshes_baseline() {
        for mode in [CommitMode::Copy, CommitMode::Append] {
            commit_baseline_case("tar.zst", mode, false, false, false);
        }
    }

    /// Regression: rebuilding ZIP left its recorded digest and size stale.
    #[test]
    fn regression_commit_overlay_zip_refreshes_baseline() {
        commit_baseline_case("zip", CommitMode::Copy, false, false, false);
    }

    /// Regression: interval and on-exit commits required force-base-mismatch afterward.
    #[test]
    fn regression_live_commit_refreshes_baseline() {
        for extension in ["tar", "tar.zst"] {
            for mode in [CommitMode::Copy, CommitMode::Append] {
                commit_baseline_case(extension, mode, true, false, false);
                commit_baseline_case(extension, mode, false, true, false);
            }
        }
    }

    /// Regression: ZIP --commit-overlay add file (full rebuild) → reopen list/read.
    /// Symptom: commit-overlay rejected non-TAR archives (upstream #154).
    #[test]
    fn commit_overlay_zip_add_file() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("a.zip");
        write_sample_zip(
            &zip_path,
            &[
                ("old.txt", b"old zip\n", CompressionMethod::Stored),
                ("nested/keep.txt", b"keep me\n", CompressionMethod::Deflated),
            ],
        );

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        {
            let _ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
            fs::write(overlay.join("new.txt"), b"hello zip commit\n").unwrap();
        }

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
            ..Default::default()
        };
        commit_overlay(&overlay, &zip_path, &opts).expect("commit_overlay zip");

        // Still a ZIP after commit
        let magic = fs::read(&zip_path).unwrap();
        assert!(
            magic.len() >= 4 && &magic[..2] == b"PK",
            "archive should remain ZIP after commit"
        );

        let file = File::open(&zip_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.name_for_index(i).map(|s| s.to_string()))
            .collect();
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "old.txt"),
            "zip listing: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "nested/keep.txt"),
            "zip listing: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "new.txt"),
            "zip listing: {names:?}"
        );

        // Read overlay-added content
        {
            let mut f = archive.by_name("new.txt").unwrap();
            let mut body = String::new();
            f.read_to_string(&mut body).unwrap();
            assert_eq!(body, "hello zip commit\n");
        }
        // Unchanged stored member still readable
        {
            let mut f = archive.by_name("old.txt").unwrap();
            let mut body = String::new();
            f.read_to_string(&mut body).unwrap();
            assert_eq!(body, "old zip\n");
        }
        // Unchanged deflated member still readable
        {
            let mut f = archive.by_name("nested/keep.txt").unwrap();
            let mut body = String::new();
            f.read_to_string(&mut body).unwrap();
            assert_eq!(body, "keep me\n");
        }
    }

    /// Regression: ZIP commit replaces existing member and honors DB delete.
    #[test]
    fn commit_overlay_zip_replace_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("b.zip");
        write_sample_zip(
            &zip_path,
            &[
                ("keep.txt", b"keep\n", CompressionMethod::Stored),
                ("gone.txt", b"remove me\n", CompressionMethod::Stored),
                ("mut.txt", b"old mut\n", CompressionMethod::Deflated),
            ],
        );

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        {
            let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
            // Replace mut.txt via overlay file (also marks delete+append on commit walk)
            fs::write(overlay.join("mut.txt"), b"new mut\n").unwrap();
            // Delete gone.txt in overlay DB (base would have had it)
            // NullBase has no files; insert deleted row directly to simulate unlink of base path.
            {
                let db = ov.db.lock().expect("db");
                db.execute(
                    r#"INSERT OR REPLACE INTO "files" (path,name,deleted) VALUES ('','gone.txt',1)"#,
                    [],
                )
                .unwrap();
            }
            // Drop overlay so exclusive SQLite lock is released before commit.
            drop(ov);
        }

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
            ..Default::default()
        };
        commit_overlay(&overlay, &zip_path, &opts).expect("commit_overlay zip replace/delete");

        let file = File::open(&zip_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.name_for_index(i).map(|s| s.to_string()))
            .collect();
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "keep.txt"),
            "{names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "gone.txt"),
            "gone.txt should be deleted: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| normalize_archive_rel_path(n) == "mut.txt"),
            "{names:?}"
        );
        let mut f = archive.by_name("mut.txt").unwrap();
        let mut body = String::new();
        f.read_to_string(&mut body).unwrap();
        assert_eq!(body, "new mut\n");
    }

    #[test]
    fn is_zip_archive_detects_pk_magic() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("c.zip");
        write_sample_zip(&zip_path, &[("x", b"y", CompressionMethod::Stored)]);
        assert!(is_zip_archive(&zip_path).unwrap());

        let tarish = dir.path().join("not-a-zip.bin");
        fs::write(&tarish, b"ustar is not here but also not PK").unwrap();
        assert!(!is_zip_archive(&tarish).unwrap());
    }

    #[test]
    fn commit_overlay_add_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("data");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("old.txt"), b"old\n").unwrap();
        let tar = dir.path().join("a.tar");
        let st = StdCommand::new("tar")
            .args(["-cf"])
            .arg(&tar)
            .arg("-C")
            .arg(&src)
            .arg("old.txt")
            .status()
            .unwrap();
        assert!(st.success());

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        // Create hidden DB so schema exists (optional for append-only)
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        {
            let _ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
            fs::write(overlay.join("new.txt"), b"hello commit\n").unwrap();
            // Drop overlay so exclusive SQLite lock is released before commit.
        }

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
            ..Default::default()
        };
        match commit_overlay(&overlay, &tar, &opts) {
            Ok(_) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            Err(e) => panic!("commit_overlay: {e}"),
        }

        let list = StdCommand::new("tar")
            .args(["-tf"])
            .arg(&tar)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&list.stdout);
        assert!(text.contains("new.txt"), "tar listing: {text}");
        assert!(text.contains("old.txt"), "tar listing: {text}");
    }

    #[test]
    fn commit_overlay_add_file_tar_gz() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("data");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("old.txt"), b"old gz\n").unwrap();
        let tgz = dir.path().join("a.tar.gz");
        let st = StdCommand::new("tar")
            .args(["-czf"])
            .arg(&tgz)
            .arg("-C")
            .arg(&src)
            .arg("old.txt")
            .status()
            .unwrap();
        assert!(st.success());

        // Sanity: starts with gzip magic
        let magic = fs::read(&tgz).unwrap();
        assert!(magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b);

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        {
            let _ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
            fs::write(overlay.join("new.txt"), b"hello gzip commit\n").unwrap();
        }

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
            ..Default::default()
        };
        match commit_overlay(&overlay, &tgz, &opts) {
            Ok(_) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            Err(e) => panic!("commit_overlay tar.gz: {e}"),
        }

        // Still gzip-compressed after commit
        let magic = fs::read(&tgz).unwrap();
        assert!(
            magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b,
            "archive should remain gzip after commit"
        );

        // List via tar -tzf (or gunzip | tar if needed)
        let list = StdCommand::new("tar")
            .args(["-tzf"])
            .arg(&tgz)
            .output()
            .unwrap();
        assert!(
            list.status.success(),
            "tar -tzf failed: {}",
            String::from_utf8_lossy(&list.stderr)
        );
        let text = String::from_utf8_lossy(&list.stdout);
        assert!(text.contains("new.txt"), "tar.gz listing: {text}");
        assert!(text.contains("old.txt"), "tar.gz listing: {text}");

        // Extract new.txt and verify content
        let extract = dir.path().join("out");
        fs::create_dir_all(&extract).unwrap();
        let st = StdCommand::new("tar")
            .args(["-xzf"])
            .arg(&tgz)
            .arg("-C")
            .arg(&extract)
            .arg("new.txt")
            .status()
            .unwrap();
        assert!(st.success());
        let body = fs::read_to_string(extract.join("new.txt")).unwrap();
        assert_eq!(body, "hello gzip commit\n");
    }

    /// Regression: offline append must not bless a stale prefix index with fresh tarstats.
    #[test]
    fn commit_overlay_append_invalidates_stale_sidecar() {
        for zstd in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join(if zstd { "a.tar.zst" } else { "a.tar" });
            append_fixture(&archive, zstd);
            let sidecar = append_index(&archive, zstd);
            if zstd {
                write_split_tar_zst(
                    &archive,
                    &[ustar_file("prefix", b"changed")],
                    &[ustar_file("last", b"last")],
                    true,
                );
            } else {
                fs::write(
                    &archive,
                    pack_tar(&[
                        ustar_file("prefix", b"changed"),
                        ustar_file("last", b"last"),
                    ]),
                )
                .unwrap();
            }
            let root = dir.path().join("ov");
            fs::create_dir(&root).unwrap();
            fs::write(root.join("new"), b"new contents").unwrap();
            assert!(commit_overlay(
                &root,
                &archive,
                &CommitOverlayOptions {
                    mode: CommitMode::Append,
                    ..yes_commit_opts()
                }
            )
            .unwrap());
            assert!(
                !sidecar.exists(),
                "stale index must be invalidated before patching"
            );
            let base = if zstd {
                open_tar_zst_base(&archive, false)
            } else {
                open_uncompressed_tar_base(&archive, false)
            };
            assert_eq!(read_member(base.as_ref(), "/prefix"), b"changed");
            assert_eq!(read_member(base.as_ref(), "/last"), b"last");
            assert_eq!(read_member(base.as_ref(), "/new"), b"new contents");
        }
    }

    /// Regression: successful append followed by reopen failure must refuse stale reads.
    #[test]
    fn live_commit_append_reopen_failure_refuses_base_reads() {
        for zstd in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join(if zstd { "a.tar.zst" } else { "a.tar" });
            append_fixture(&archive, zstd);
            let base = if zstd {
                open_tar_zst_base(&archive, false)
            } else {
                open_uncompressed_tar_base(&archive, false)
            };
            let old = base.lookup("/last", 0).unwrap();
            let mut ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
            ov.set_commit_mode(CommitMode::Append);
            fs::write(ov.root().join("new"), b"new").unwrap();
            assert!(ov
                .commit_live(&archive, |_| Err(OverlayError::Msg("reopen failed".into())))
                .is_err());
            assert!(ov.interval_disabled());
            assert!(ov.content_generation() > 0);
            assert!(ov.open(&old, 0).is_err());
            assert!(ov.root().join("new").exists());
        }
    }

    /// Regression (R7-B3): a `--commit-manifest` (provenance) append whose
    /// baseline restamp fails after the splice returned `Committed` without the
    /// ordinary append branches' handling: the interval stayed on and the
    /// mounted source kept serving the pre-splice frame map over the new bytes.
    #[cfg(unix)]
    #[test]
    fn regression_provenance_append_committed_refuses_stale_frame_map() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar.zst");
        append_fixture(&archive, true);
        let base = open_tar_zst_base(&archive, false);
        let old = base.lookup("/last", 0).unwrap();
        let mut ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
        ov.set_commit_mode(CommitMode::Append);
        ov.set_manifest_hashes(Some("new".into()));
        fs::write(ov.root().join("new"), b"new").unwrap();
        // An open transaction on the mount's connection makes the restamp's
        // BEGIN IMMEDIATE fail after the splice.
        ov.db.lock().unwrap().execute_batch("BEGIN").unwrap();
        let err = ov
            .commit_live(&archive, |_| panic!("a committed splice must not reopen"))
            .unwrap_err();
        assert!(matches!(err, OverlayError::Committed(_)), "{err}");
        assert!(ov.interval_disabled(), "interval commits stay enabled");
        assert!(
            ov.open(&old, 0).is_err(),
            "stale pre-splice frame map still served"
        );
    }

    /// Regression: recovery of a failed append keeps the old live index readable.
    #[cfg(unix)]
    #[test]
    fn live_commit_append_failure_recovers_before_next_tick() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let (_, last) = append_fixture(&archive, false);
        let base = open_uncompressed_tar_base(&archive, false);
        let ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
        let offset = fs::metadata(&archive).unwrap().len() - 1024;
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"partial new member").unwrap();
        assert!(
            ratarmount_compress::commit_journal::replace_suffix_with_hook(
                &archive,
                offset,
                &mut suffix,
                &mut |step| {
                    if step == "archive write" {
                        Err(io::Error::from_raw_os_error(libc::ENOSPC))
                    } else {
                        Ok(())
                    }
                },
            )
            .is_err()
        );
        ov.recover_member_journal(&archive).unwrap();
        assert!(!ov.interval_disabled());
        assert_eq!(read_member(&ov, "/last"), last);
    }

    /// Regression: failed rollback must refuse base reads instead of serving torn bytes.
    #[cfg(unix)]
    #[test]
    fn live_commit_append_recovery_failure_refuses_base_reads() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        append_fixture(&archive, false);
        let base = open_uncompressed_tar_base(&archive, false);
        let old = base.lookup("/last", 0).unwrap();
        let ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new").unwrap();
        assert!(
            ratarmount_compress::commit_journal::replace_suffix_with_hook(
                &archive,
                512,
                &mut suffix,
                &mut |step| {
                    if step == "archive truncate" {
                        Err(io::Error::other("crash"))
                    } else {
                        Ok(())
                    }
                },
            )
            .is_err()
        );
        File::options()
            .append(true)
            .open(&archive)
            .unwrap()
            .write_all(b"unrelated bytes")
            .unwrap();
        assert!(ov
            .commit_live(&archive, |_| panic!("must refuse recovery"))
            .is_err());
        assert!(ov.interval_disabled());
        assert!(ov.open(&old, 0).is_err());
    }

    /// Regression: a touch during suffix staging must refuse and retry, in
    /// `append` and in `auto` alike. R7-D1: `auto` used to copy the touched
    /// file, a file the commit gate never judged; the archive changed since
    /// the gate, so no copy runs and the next commit appends in place.
    #[cfg(unix)]
    #[test]
    fn live_commit_append_stale_preparation_retries_without_a_copy() {
        use std::os::unix::fs::MetadataExt;
        for mode in [CommitMode::Append, CommitMode::Auto] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("a.tar");
            append_fixture(&archive, false);
            let before = fs::metadata(&archive).unwrap().ino();
            let mut ov = WriteOverlay::new_for_tests(
                open_uncompressed_tar_base(&archive, false),
                dir.path().join("ov"),
            )
            .unwrap();
            ov.set_commit_mode(mode);
            fs::write(ov.root().join("new"), b"new").unwrap();
            APPEND_PREPARE_TOUCH.set(true);
            let result = ov.commit_live(&archive, |p| Ok(open_uncompressed_tar_base(p, false)));
            assert!(!ov.interval_disabled(), "{mode:?}");
            assert!(result.is_err(), "{mode:?}");
            assert_eq!(before, fs::metadata(&archive).unwrap().ino(), "{mode:?}");
            assert!(ov
                .commit_live(&archive, |p| Ok(open_uncompressed_tar_base(p, false)))
                .unwrap());
            assert_eq!(before, fs::metadata(&archive).unwrap().ino(), "{mode:?}");
            assert_eq!(read_member(&ov, "/new"), b"new");
        }
    }

    /// Regression: trailing garbage rejected during append preparation must not disable ticks.
    #[test]
    fn live_commit_append_checksum_error_keeps_interval_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        append_fixture(&archive, false);
        let good = fs::read(&archive).unwrap();
        let mut ov = WriteOverlay::new_for_tests(
            open_uncompressed_tar_base(&archive, false),
            dir.path().join("ov"),
        )
        .unwrap();
        ov.set_commit_mode(CommitMode::Append);
        fs::write(ov.root().join("new"), b"new").unwrap();
        File::options()
            .append(true)
            .open(&archive)
            .unwrap()
            .write_all(&[0x37; 512])
            .unwrap();
        assert!(ov
            .commit_live(&archive, |_| panic!("invalid append must not reopen"))
            .is_err());
        assert!(!ov.interval_disabled());
        fs::write(&archive, good).unwrap();
        assert!(ov
            .commit_live(&archive, |p| Ok(open_uncompressed_tar_base(p, false)))
            .unwrap());
        assert_eq!(read_member(&ov, "/new"), b"new");
    }

    fn append_fixture(path: &Path, zstd: bool) -> (Vec<u8>, Vec<u8>) {
        let mut seed = 42u32;
        let prefix: Vec<_> = (0..2 * 1024 * 1024)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        let last = vec![0; 8192];
        if zstd {
            write_split_tar_zst(
                path,
                &[ustar_file("prefix", &prefix)],
                &[ustar_file("last", &last)],
                true,
            );
        } else {
            fs::write(
                path,
                pack_tar(&[ustar_file("prefix", &prefix), ustar_file("last", &last)]),
            )
            .unwrap();
        }
        (prefix, last)
    }

    fn append_index(path: &Path, zstd: bool) -> PathBuf {
        let sidecar = ratarmount_index::default_index_path(path);
        let opts = OpenOptions {
            write_index: true,
            index_minimum_file_count: 0,
            ..OpenOptions::default()
        };
        if zstd {
            SqliteIndexedTar::create_index_body(
                path,
                open_seekable_zstd(path).unwrap(),
                Some(&sidecar),
                &opts,
                "test",
            )
            .unwrap();
        } else {
            SqliteIndexedTar::create_index(path, path, Some(&sidecar), &opts, "test", &mut None)
                .unwrap();
        }
        sidecar
    }

    fn append_warm_open(path: &Path, zstd: bool, sidecar: &Path) -> Arc<dyn MountSource> {
        SqliteIndex::open_read_only(sidecar)
            .unwrap()
            .check_tarstats_matches_archive(path)
            .unwrap();
        if zstd {
            Arc::new(
                SqliteIndexedTar::open_with_existing_index_body(
                    path,
                    open_seekable_zstd(path).unwrap(),
                    sidecar,
                    OpenOptions::default(),
                )
                .unwrap(),
            )
        } else {
            Arc::new(
                SqliteIndexedTar::open_with_existing_index(
                    path,
                    path,
                    sidecar,
                    OpenOptions::default(),
                    &mut None,
                )
                .unwrap(),
            )
        }
    }

    /// Regression: adds-only interval commits copied the entire archive and inode.
    #[test]
    fn live_commit_append_inode_space_sidecar_and_copy_content() {
        use std::os::unix::fs::MetadataExt;
        if let Err(e) = ensure_gnu_tar() {
            eprintln!("skip: {e}");
            return;
        }
        for zstd in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join(if zstd { "a.tar.zst" } else { "a.tar" });
            let (prefix, last) = append_fixture(&archive, zstd);
            let copy = dir
                .path()
                .join(if zstd { "copy.tar.zst" } else { "copy.tar" });
            fs::copy(&archive, &copy).unwrap();
            let sidecar = append_index(&archive, zstd);
            let base = append_warm_open(&archive, zstd, &sidecar);
            let root = dir.path().join("overlay");
            let mut ov = overlay_with_base(base, &root);
            ov.set_commit_mode(CommitMode::Append);
            let added = vec![0x91; 150_000];
            fs::write(root.join("new"), &added).unwrap();
            set_mtime_age(&root.join("new"), Duration::from_secs(30));
            // The offline path needs its own folder: a mounted overlay holds
            // its deletion database exclusively.
            let copy_root = dir.path().join("copy-overlay");
            fs::create_dir(&copy_root).unwrap();
            fs::copy(root.join("new"), copy_root.join("new")).unwrap();
            assert!(commit_overlay(&copy_root, &copy, &yes_commit_opts()).unwrap());
            let before = fs::metadata(&archive).unwrap();
            assert!(ov
                .commit_live_idle(&archive, Duration::from_secs(1), |path| {
                    patch_sidecar_if_present(
                        path,
                        &ov.last_patch_window().unwrap(),
                        &OpenOptions {
                            index_file_path: Some(sidecar.clone()),
                            ..OpenOptions::default()
                        },
                    )?;
                    Ok(append_warm_open(path, zstd, &sidecar))
                })
                .unwrap());
            let after = fs::metadata(&archive).unwrap();
            assert_eq!(before.ino(), after.ino());
            assert!(
                after.blocks() * 512 <= before.blocks() * 512 + added.len() as u64 + 64 * 1024,
                "append allocated the prefix again"
            );
            let copied = if zstd {
                open_tar_zst_base(&copy, false)
            } else {
                open_uncompressed_tar_base(&copy, false)
            };
            let mut got_names: Vec<_> = ov
                .list_dirents("/")
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
            let mut copy_names: Vec<_> = copied
                .list_dirents("/")
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
            got_names.sort();
            copy_names.sort();
            assert_eq!(got_names, copy_names);
            for (name, expected) in [("/prefix", &prefix), ("/last", &last), ("/new", &added)] {
                assert_eq!(read_member(&ov, name), *expected);
                assert_eq!(read_member(copied.as_ref(), name), *expected);
            }
            assert!(!root.join("new").exists());
            assert!(!ratarmount_compress::commit_journal::journal_path(&archive).exists());
            fs::write(root.join("second"), b"second tick").unwrap();
            assert!(ov
                .commit_live(&archive, |path| {
                    patch_sidecar_if_present(
                        path,
                        &ov.last_patch_window().unwrap(),
                        &OpenOptions {
                            index_file_path: Some(sidecar.clone()),
                            ..OpenOptions::default()
                        },
                    )?;
                    Ok(append_warm_open(path, zstd, &sidecar))
                })
                .unwrap());
            assert_eq!(read_member(&ov, "/second"), b"second tick");
            assert_eq!(read_member(&ov, "/new"), added);
        }
    }

    /// Regression: uncompressed append must work without GNU tar and keep zero-tail bytes.
    #[test]
    fn commit_overlay_append_uncompressed_zero_tail_without_tools() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let old = vec![0; 8192];
        fs::write(&archive, pack_tar(&[ustar_file("old", &old)])).unwrap();
        let sidecar = append_index(&archive, false);
        let before = fs::metadata(&archive).unwrap().ino();
        let root = dir.path().join("ov");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("new"), b"new bytes").unwrap();
        assert!(commit_overlay(
            &root,
            &archive,
            &CommitOverlayOptions {
                mode: CommitMode::Append,
                ..yes_commit_opts()
            }
        )
        .unwrap());
        assert_eq!(before, fs::metadata(&archive).unwrap().ino());
        let base = append_warm_open(&archive, false, &sidecar);
        assert_eq!(read_member(base.as_ref(), "/old"), old);
        assert_eq!(read_member(base.as_ref(), "/new"), b"new bytes");
    }

    /// Regression: auto must not mutate another hard link, or append replacements.
    #[test]
    fn commit_overlay_append_auto_hardlink_and_replacement_fallback() {
        use std::os::unix::fs::MetadataExt;
        for hardlink in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("a.tar.zst");
            append_fixture(&archive, true);
            let old = fs::read(&archive).unwrap();
            let alias = dir.path().join("alias.tar.zst");
            if hardlink {
                fs::hard_link(&archive, &alias).unwrap();
            }
            let root = dir.path().join("ov");
            fs::create_dir(&root).unwrap();
            fs::write(
                root.join(if hardlink { "new" } else { "last" }),
                b"new bytes",
            )
            .unwrap();
            let before = fs::metadata(&archive).unwrap().ino();
            assert!(commit_overlay(
                &root,
                &archive,
                &CommitOverlayOptions {
                    mode: CommitMode::Auto,
                    ..yes_commit_opts()
                }
            )
            .unwrap());
            assert_ne!(before, fs::metadata(&archive).unwrap().ino());
            if hardlink {
                assert_eq!(fs::read(alias).unwrap(), old);
            }
            let base = open_tar_zst_base(&archive, false);
            assert_eq!(
                read_member(base.as_ref(), if hardlink { "/new" } else { "/last" }),
                b"new bytes"
            );
        }
    }

    /// Regression: auto should append eligible seekable files, but never a table-less zstd.
    #[test]
    fn commit_overlay_append_auto_requires_seek_table() {
        use std::os::unix::fs::MetadataExt;
        for seek_table in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("a.tar.zst");
            write_split_tar_zst(
                &archive,
                &[ustar_file("prefix", b"prefix")],
                &[ustar_file("last", b"last")],
                seek_table,
            );
            let root = dir.path().join("ov");
            fs::create_dir(&root).unwrap();
            fs::write(root.join("new"), b"new bytes").unwrap();
            let before = fs::metadata(&archive).unwrap().ino();
            assert!(commit_overlay(
                &root,
                &archive,
                &CommitOverlayOptions {
                    mode: CommitMode::Auto,
                    ..yes_commit_opts()
                }
            )
            .unwrap());
            assert_eq!(before == fs::metadata(&archive).unwrap().ino(), seek_table);
            assert_eq!(
                read_member(open_tar_zst_base(&archive, false).as_ref(), "/new"),
                b"new bytes"
            );
        }
    }

    /// Regression: crash during append must recover full contents and matching sidecar.
    #[test]
    fn commit_overlay_append_crash_listing_hashes_and_sidecar() {
        use ratarmount_compress::commit_journal::{recover, replace_suffix_with_hook};
        for zstd in [false, true] {
            for stop in 1..=19 {
                let dir = tempfile::tempdir().unwrap();
                let archive = dir.path().join(if zstd { "a.tar.zst" } else { "a.tar" });
                let (prefix, last) = append_fixture(&archive, zstd);
                let old = fs::read(&archive).unwrap();
                let sidecar = append_index(&archive, zstd);
                let mut tail = tempfile::tempfile().unwrap();
                let added = vec![0x93; 150_000];
                let (offset, window) = if zstd {
                    let map = scan_zstd_frames_path(&archive).unwrap();
                    let from = find_last_n_tar_window(&archive, &map, "test").unwrap().0;
                    ratarmount_compress::write_zstd_splice_suffix(
                        &mut File::open(&archive).unwrap(),
                        &map,
                        from,
                        |mut input, start, mut out| {
                            rewrite_tar_suffix(
                                &mut input,
                                start,
                                &RewriteTarSuffix {
                                    deleted_paths: &HashSet::new(),
                                    append: &[ustar_file("new", &added)],
                                    encoding: "utf-8",
                                },
                                &mut out,
                            )
                            .map(|_| ())
                        },
                        &mut tail,
                    )
                    .unwrap();
                    (
                        map.frames[from].compressed_offset,
                        IndexPatchWindow {
                            window_start: map.frames[from].uncompressed_offset,
                            from_frame: Some(from),
                            offsets_shifted: false,
                        },
                    )
                } else {
                    ratarmount_formats_tar::write_ustar_members(
                        &mut tail,
                        &[ustar_file("new", &added)],
                    )
                    .unwrap();
                    ratarmount_formats_tar::write_tar_eof(&mut tail).unwrap();
                    let offset = old.len() as u64 - 1024;
                    (
                        offset,
                        IndexPatchWindow {
                            window_start: offset,
                            from_frame: None,
                            offsets_shifted: false,
                        },
                    )
                };
                tail.rewind().unwrap();
                let mut expected = old[..offset as usize].to_vec();
                tail.read_to_end(&mut expected).unwrap();
                let mut step = 0;
                let _ = replace_suffix_with_hook(&archive, offset, &mut tail, &mut |_| {
                    step += 1;
                    if step == stop {
                        Err(io::Error::other("injected crash"))
                    } else {
                        Ok(())
                    }
                });
                recover(&archive).unwrap();
                let actual = fs::read(&archive).unwrap();
                assert!(
                    actual == old || actual == expected,
                    "third state: zstd={zstd} step={stop}"
                );
                let committed = actual == expected;
                if committed {
                    patch_sidecar_if_present(
                        &archive,
                        &window,
                        &OpenOptions {
                            index_file_path: Some(sidecar.clone()),
                            ..OpenOptions::default()
                        },
                    )
                    .unwrap();
                }
                let warm = append_warm_open(&archive, zstd, &sidecar);
                let full = if zstd {
                    open_tar_zst_base(&archive, false)
                } else {
                    open_uncompressed_tar_base(&archive, false)
                };
                let names: HashSet<_> = full
                    .list_dirents("/")
                    .unwrap()
                    .into_iter()
                    .map(|e| e.name)
                    .collect();
                assert_eq!(
                    names,
                    if committed {
                        HashSet::from(["prefix".into(), "last".into(), "new".into()])
                    } else {
                        HashSet::from(["prefix".into(), "last".into()])
                    }
                );
                assert_eq!(warm.lookup("/new", 0).is_some(), committed);
                for (name, bytes) in [("/prefix", &prefix), ("/last", &last), ("/new", &added)] {
                    if name == "/new" && !committed {
                        continue;
                    }
                    let hash = |data: &[u8]| {
                        ratarmount_index::sha256_hex_stream(&mut std::io::Cursor::new(data))
                            .unwrap()
                    };
                    assert_eq!(hash(&read_member(warm.as_ref(), name)), hash(bytes));
                    assert_eq!(hash(&read_member(full.as_ref(), name)), hash(bytes));
                }
            }
        }
    }

    fn yes_commit_opts() -> CommitOverlayOptions {
        CommitOverlayOptions {
            yes: true,
            debug: 0,
            ..Default::default()
        }
    }

    /// Soft-skip GNU tar commit tests when the host tar is missing/wrong, or when
    /// `--delete --ignore-zeros` hits the known Debian 1.35 lseek EOVERFLOW bug
    /// (stderr/`Err` carry `lseek` / `Value too large for defined data type`).
    fn soft_skip_gnu_tar_commit(err: &impl std::fmt::Display) -> bool {
        let s = err.to_string();
        s.contains("GNU tar")
            || s.contains("lseek")
            || s.contains("Value too large for defined data type")
    }

    fn sibling_index_sqlite_paths(dir: &Path) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(".index.sqlite"))
            })
            .collect();
        out.sort();
        out
    }

    fn padded_ustar_span(payload_len: usize) -> usize {
        512 + payload_len.div_ceil(512) * 512
    }

    /// Regression: offline --commit-overlay appends into multi-frame .tar.zst
    /// without rewriting prefix frames.
    #[test]
    fn commit_overlay_tar_zst_multi_frame_append() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("off-mf-prefix");
        let last = generated_payload("off-mf-last");
        let extra = generated_payload("off-mf-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        let rewrite_start = map.frames.last().unwrap().compressed_offset as usize;
        let prefix_bytes = before[..rewrite_start].to_vec();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("new.txt"), &extra).unwrap();

        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..rewrite_start],
            prefix_bytes.as_slice(),
            "prefix frames must stay byte-identical"
        );
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    /// Regression: offline --commit-overlay last-window replace keeps one name.
    #[test]
    fn commit_overlay_tar_zst_last_window_replace() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("off-rw-prefix");
        let old = generated_payload("off-rw-old");
        let new = generated_payload("off-rw-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &old)],
            false,
        );
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("last.txt"), &new).unwrap();

        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/last.txt"), new);
        let names = src.list("/").expect("list");
        let n = match names {
            ListResult::Infos(m) => m.keys().filter(|k| *k == "last.txt").count(),
            ListResult::Names(v) => v.iter().filter(|k| *k == "last.txt").count(),
        };
        assert_eq!(n, 1, "replaced name must appear once");
    }

    /// Regression: prefix-frame delete via offline --commit-overlay.
    #[test]
    fn commit_overlay_tar_zst_earlier_frame_delete() {
        let dir = tempfile::tempdir().unwrap();
        let keep = generated_payload("off-ef-keep");
        let old = generated_payload("off-ef-old");
        let last = generated_payload("off-ef-last");
        let archive = dir.path().join("a.tar.zst");
        let f0 = pack_tar_no_eof(&[ustar_file("keep.txt", &keep)]);
        let f1 = pack_tar_no_eof(&[ustar_file("old.txt", &old)]);
        let mut f2 = pack_tar_no_eof(&[ustar_file("last.txt", &last)]);
        ratarmount_formats_tar::write_tar_eof(&mut f2).unwrap();
        fs::write(&archive, concat_zstd_frames(&[&f0, &f1, &f2], false)).unwrap();

        let before = fs::read(&archive).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        assert!(map.frames.len() >= 3);
        let prefix_end = map.frames[1].compressed_offset as usize;
        let prefix_bytes = before[..prefix_end].to_vec();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/old.txt").expect("unlink prefix-frame member");
        drop(ov);

        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..prefix_end],
            prefix_bytes.as_slice(),
            "prefix before rewrite start must stay byte-identical"
        );
        let src = open_tar_zst_base(&archive, false);
        assert!(
            src.lookup("/old.txt", 0).is_none(),
            "deleted name must be gone"
        );
        assert_eq!(read_member(src.as_ref(), "/keep.txt"), keep);
        assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
    }

    /// Regression: offsetheader in frame k but frame k starts mid-member.
    /// Ceiling stays at k when the suffix still has a later header; opaque
    /// prefix of `big.bin` is copied. Floor-skip coverage is
    /// `commit_overlay_tar_zst_earlier_frame_delete`.
    #[test]
    fn commit_overlay_tar_zst_header_straddle_delete() {
        let dir = tempfile::tempdir().unwrap();
        let keep = generated_payload("off-hs-keep");
        let big = generated_payload("off-hs-big").repeat(200);
        let gone = generated_payload("off-hs-gone");
        let last = generated_payload("off-hs-last");
        let tar = pack_tar(&[
            ustar_file("keep.txt", &keep),
            ustar_file("big.bin", &big),
            ustar_file("gone.txt", &gone),
            ustar_file("last.txt", &last),
        ]);
        let keep_end = padded_ustar_span(keep.len());
        let mid_big = keep_end + 512 + big.len() / 2;
        assert!(mid_big < keep_end + padded_ustar_span(big.len()));
        let archive = dir.path().join("a.tar.zst");
        fs::write(
            &archive,
            concat_zstd_frames(
                &[&tar[..keep_end], &tar[keep_end..mid_big], &tar[mid_big..]],
                false,
            ),
        )
        .unwrap();

        let map = scan_zstd_frames_path(&archive).unwrap();
        assert_eq!(map.frames.len(), 3);
        let base = open_tar_zst_base(&archive, false);
        let ohs = all_tar_offsetheaders(base.as_ref(), "gone.txt").expect("ohs");
        let min_oh = *ohs.iter().min().expect("oh");
        let k = frame_covering_uncomp(&map, min_oh).expect("frame k");
        assert_eq!(k, 2, "gone.txt header must live in frame 2");

        let before = fs::read(&archive).unwrap();
        let prefix_km1 = map.frames[k - 1].compressed_offset as usize;
        let prefix_bytes = before[..prefix_km1].to_vec();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(Arc::clone(&base), &overlay);
        ov.unlink("/gone.txt")
            .expect("unlink straddling-window name");
        drop(ov);

        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..prefix_km1],
            prefix_bytes.as_slice(),
            "prefix before k-1 must stay byte-identical"
        );
        let src = open_tar_zst_base(&archive, false);
        assert!(src.lookup("/gone.txt", 0).is_none());
        assert_eq!(read_member(src.as_ref(), "/keep.txt"), keep);
        assert_eq!(read_member(src.as_ref(), "/big.bin"), big);
        assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
    }

    /// Regression: concatenated complete-TAR later-frame delete must apply
    /// even when the caller omits `--ignore-zeros` (default offline CLI).
    #[test]
    fn commit_overlay_tar_zst_concatenated_delete_without_ignore_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("off-i0-prefix");
        let last = generated_payload("off-i0-last");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("prefix.txt", &prefix)]),
                pack_tar(&[ustar_file("last.txt", &last)]),
            ],
        );
        let before = fs::read(&archive).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        assert!(map.frames.len() >= 2);
        let prefix_end = map.frames[1].compressed_offset as usize;
        let prefix_bytes = before[..prefix_end].to_vec();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        ov.unlink("/last.txt")
            .expect("unlink later complete-TAR frame");
        drop(ov);

        assert!(
            commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"),
            "offline commit without -i must still persist the later-frame delete"
        );
        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..prefix_end],
            prefix_bytes.as_slice(),
            "prefix complete-TAR frame must stay byte-identical"
        );
        let src = open_tar_zst_base(&archive, true);
        assert!(
            src.lookup("/last.txt", 0).is_none(),
            "later-frame name must be gone after offline commit without -i"
        );
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    }

    /// Regression: concatenated complete-TAR later-frame delete needs --ignore-zeros
    /// only for the mount that created the tombstone, not for offline classification.
    #[test]
    fn commit_overlay_tar_zst_concatenated_delete_ignore_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("off-i-prefix");
        let last = generated_payload("off-i-last");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("prefix.txt", &prefix)]),
                pack_tar(&[ustar_file("last.txt", &last)]),
            ],
        );
        let before = fs::read(&archive).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        assert!(map.frames.len() >= 2);
        let prefix_end = map.frames[1].compressed_offset as usize;
        let prefix_bytes = before[..prefix_end].to_vec();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        ov.unlink("/last.txt")
            .expect("unlink later complete-TAR frame");
        drop(ov);

        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
            ignore_zeros: true,
            ..Default::default()
        };
        assert!(commit_overlay(&overlay, &archive, &opts).expect("commit"));
        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..prefix_end],
            prefix_bytes.as_slice(),
            "prefix complete-TAR frame must stay byte-identical"
        );
        let src = open_tar_zst_base(&archive, true);
        assert!(
            src.lookup("/last.txt", 0).is_none(),
            "later-frame name must be gone when classified with ignore_zeros"
        );
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    }

    /// Regression: live persist of a single-frame concatenated `.tar.zst`
    /// must reinsert members after the first interior TAR EOF when patching
    /// the sibling sidecar. `window_start` is 0 for a one-frame archive, so
    /// `ignore_zeros: false` (default live CLI opts) used to wipe the suffix
    /// and stop at the first EOF — the appended overlay file vanished on
    /// warm remount.
    #[test]
    fn live_commit_tar_zst_single_frame_concatenated_patches_sidecar_after_interior_eof() {
        let dir = tempfile::tempdir().unwrap();
        let first = generated_payload("live-1f-first");
        let second = generated_payload("live-1f-second");
        let extra = generated_payload("live-1f-new");
        let archive = dir.path().join("a.tar.zst");
        let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
        combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
        fs::write(&archive, concat_zstd_frames(&[&combined], false)).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        assert_eq!(map.frames.len(), 1, "fixture must be one zstd frame");

        let sidecar = ratarmount_index::default_index_path(&archive);
        {
            let body = open_seekable_zstd(&archive).expect("open zstd");
            let opts = OpenOptions {
                ignore_zeros: true,
                gnu_incremental: Some(false),
                ..OpenOptions::default()
            };
            let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
                &archive,
                body,
                Some(&sidecar),
                &opts,
                "test",
            )
            .expect("create sidecar");
        }
        assert!(sidecar.is_file(), "pre-existing sidecar");

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, true))
            .expect("live commit append"));
        let window = ov.last_patch_window().expect("stashed window");
        assert_eq!(
            window.window_start, 0,
            "single-frame persist rewrites from uncompressed offset 0"
        );

        // Live CLI passes the mount OpenOptions (ignore_zeros: false).
        let mount_opts = OpenOptions {
            ignore_zeros: false,
            gnu_incremental: Some(false),
            ..OpenOptions::default()
        };
        patch_sidecar_if_present(&archive, &window, &mount_opts).expect("patch sidecar");

        let body = open_seekable_zstd(&archive).expect("fresh zstd");
        let src = ratarmount_formats_tar::SqliteIndexedTar::open_with_existing_index_body(
            &archive,
            body,
            &sidecar,
            OpenOptions {
                ignore_zeros: true,
                ..OpenOptions::default()
            },
        )
        .expect("warm-open patched sidecar");
        assert_eq!(read_member(&src, "/first.txt"), first);
        assert_eq!(
            read_member(&src, "/second.txt"),
            second,
            "second complete TAR after the interior EOF must stay in the sidecar"
        );
        assert_eq!(
            read_member(&src, "/new.txt"),
            extra,
            "appended overlay file after the interior EOF must be reinserted \
             (ignore_zeros: false on the patch would stop after first.txt)"
        );
    }

    /// Regression: uncompressed concatenated TAR sidecar patch from
    /// `window_start` 0 (unclassified delete / first-frame rewrite) must
    /// reinsert members after the interior TAR EOF. Mount CLI opts default
    /// to `ignore_zeros: false` and used to wipe the suffix.
    #[test]
    fn patch_sidecar_uncompressed_concatenated_keeps_later_members() {
        let dir = tempfile::tempdir().unwrap();
        let first = generated_payload("patch-tar-first");
        let second = generated_payload("patch-tar-second");
        let archive = dir.path().join("a.tar");
        let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
        combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
        fs::write(&archive, &combined).unwrap();

        let sidecar = ratarmount_index::default_index_path(&archive);
        {
            let opts = OpenOptions {
                ignore_zeros: true,
                gnu_incremental: Some(false),
                ..OpenOptions::default()
            };
            let mut materialised = None;
            let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index(
                &archive,
                &archive,
                Some(&sidecar),
                &opts,
                "test",
                &mut materialised,
            )
            .expect("create sidecar");
        }
        assert!(sidecar.is_file(), "pre-existing sidecar");

        let mount_opts = OpenOptions {
            ignore_zeros: false,
            gnu_incremental: Some(false),
            ..OpenOptions::default()
        };
        patch_sidecar_if_present(
            &archive,
            &IndexPatchWindow {
                window_start: 0,
                from_frame: None,
                offsets_shifted: true,
            },
            &mount_opts,
        )
        .expect("patch sidecar");

        let mut materialised = None;
        let src = ratarmount_formats_tar::SqliteIndexedTar::open_with_existing_index(
            &archive,
            &archive,
            &sidecar,
            OpenOptions {
                ignore_zeros: true,
                ..OpenOptions::default()
            },
            &mut materialised,
        )
        .expect("warm-open patched sidecar");
        assert_eq!(read_member(&src, "/first.txt"), first);
        assert_eq!(
            read_member(&src, "/second.txt"),
            second,
            "second complete TAR after the interior EOF must stay in the sidecar"
        );
    }

    /// Regression: offline later-frame delete must reinsert later complete-TAR
    /// frames when patching a sibling sidecar (not stop at the first TAR EOF).
    #[test]
    fn commit_overlay_tar_zst_concatenated_delete_patches_sidecar_later_frame() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("off-i0-sc-prefix");
        let mid = generated_payload("off-i0-sc-mid");
        let last = generated_payload("off-i0-sc-last");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("prefix.txt", &prefix)]),
                pack_tar(&[ustar_file("mid.txt", &mid)]),
                pack_tar(&[ustar_file("last.txt", &last)]),
            ],
        );
        let sidecar = ratarmount_index::default_index_path(&archive);
        {
            let body = open_seekable_zstd(&archive).expect("open zstd");
            let opts = OpenOptions {
                ignore_zeros: true,
                gnu_incremental: Some(false),
                ..OpenOptions::default()
            };
            let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
                &archive,
                body,
                Some(&sidecar),
                &opts,
                "test",
            )
            .expect("create sidecar");
        }
        assert!(sidecar.is_file(), "pre-existing sidecar");

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        ov.unlink("/prefix.txt")
            .expect("unlink first complete-TAR frame");
        drop(ov);

        assert!(
            commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"),
            "offline commit without -i must persist the first-frame delete"
        );

        let idx = ratarmount_index::SqliteIndex::open_read_only(&sidecar).expect("open patched");
        idx.check_tarstats_matches_archive(&archive)
            .expect("patched tarstats must match spliced archive");

        let body = open_seekable_zstd(&archive).expect("fresh zstd");
        let src = ratarmount_formats_tar::SqliteIndexedTar::open_with_existing_index_body(
            &archive,
            body,
            &sidecar,
            OpenOptions {
                ignore_zeros: true,
                ..OpenOptions::default()
            },
        )
        .expect("warm-open patched sidecar");
        assert!(
            src.lookup("/prefix.txt", 0).is_none(),
            "first-frame name must be gone from the patched sidecar"
        );
        assert_eq!(
            read_member(&src, "/mid.txt"),
            mid,
            "next complete-TAR frame must be reinserted when patching with ignore_zeros"
        );
        assert_eq!(
            read_member(&src, "/last.txt"),
            last,
            "later complete-TAR frame after another kept EOF must be reinserted \
             (ignore_zeros: false on the patch would stop after mid.txt)"
        );
    }

    /// Regression: offline --commit-overlay must not create a sibling *.index.sqlite.
    #[test]
    fn commit_overlay_tar_zst_no_durable_index() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("off-idx-seed");
        let extra = generated_payload("off-idx-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let preexisting = dir.path().join("preexisting.index.sqlite");
        fs::write(&preexisting, b"leave-me").unwrap();
        let before_sidecars = sibling_index_sqlite_paths(dir.path());
        let before_pre = fs::read(&preexisting).unwrap();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));

        let after_sidecars = sibling_index_sqlite_paths(dir.path());
        assert_eq!(
            after_sidecars, before_sidecars,
            "commit must not create or rename index sidecars: {after_sidecars:?}"
        );
        assert_eq!(fs::read(&preexisting).unwrap(), before_pre);
        let archive_name = archive.file_name().unwrap().to_string_lossy();
        let next_to = archive.with_file_name(format!("{archive_name}.index.sqlite"));
        assert!(!next_to.exists(), "must not write {}", next_to.display());
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    /// Regression: offline --commit-overlay patches an existing sibling sidecar
    /// (does not create one when missing).
    #[test]
    fn commit_overlay_tar_zst_patches_existing_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("off-patch-prefix");
        let last = generated_payload("off-patch-last");
        let extra = generated_payload("off-patch-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        let prefix_end = map.frames.last().unwrap().compressed_offset as usize;
        let prefix_bytes = before[..prefix_end].to_vec();

        let sidecar = ratarmount_index::default_index_path(&archive);
        {
            let body = open_seekable_zstd(&archive).expect("open zstd");
            let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
                &archive,
                body,
                Some(&sidecar),
                &OpenOptions::default(),
                "test",
            )
            .expect("create sidecar");
        }
        assert!(sidecar.is_file(), "pre-existing sidecar");
        let idx_before = fs::metadata(&sidecar).unwrap();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));

        assert!(
            sidecar.is_file(),
            "must patch existing sidecar, not delete it"
        );
        let idx_after = fs::metadata(&sidecar).unwrap();
        assert!(
            idx_after.len() > 0,
            "sidecar must remain a real SQLite file"
        );
        let _ = idx_before;

        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..prefix_end],
            prefix_bytes.as_slice(),
            "prefix frames must stay byte-identical"
        );

        let idx = ratarmount_index::SqliteIndex::open_read_only(&sidecar).expect("open patched");
        idx.check_tarstats_matches_archive(&archive)
            .expect("patched tarstats must match spliced archive");

        let body = open_seekable_zstd(&archive).expect("fresh zstd");
        let src = ratarmount_formats_tar::SqliteIndexedTar::open_with_existing_index_body(
            &archive,
            body,
            &sidecar,
            OpenOptions::default(),
        )
        .expect("warm-open patched sidecar");
        assert_eq!(read_member(&src, "/prefix.txt"), prefix);
        assert_eq!(read_member(&src, "/last.txt"), last);
        assert_eq!(read_member(&src, "/new.txt"), extra);
    }

    #[test]
    fn commit_overlay_tar_zst_single_frame_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("off-sf-seed");
        let extra = generated_payload("off-sf-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn commit_overlay_tar_zst_seek_table_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("off-st-prefix");
        let last = generated_payload("off-st-last");
        let extra = generated_payload("off-st-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            true,
        );
        let before = fs::read(&archive).unwrap();
        assert!(seek_table_footer_present(&before));
        let map = scan_zstd_frames_path(&archive).unwrap();
        let rewrite_start = map.frames.last().unwrap().compressed_offset as usize;
        let prefix_bytes = before[..rewrite_start].to_vec();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));

        let after = fs::read(&archive).unwrap();
        assert_eq!(&after[..rewrite_start], prefix_bytes.as_slice());
        assert!(
            seek_table_footer_present(&after),
            "seek-table footer must be rewritten"
        );
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn commit_overlay_tar_zst_empty() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("off-empty");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let committed = commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit");
        assert!(!committed);
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    #[test]
    fn commit_overlay_plain_zst_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("plain.zst");
        let zst = ratarmount_compress::encode_zstd_frame(b"not-a-tar-body", 3).unwrap();
        fs::write(&archive, zst).unwrap();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("x.txt"), b"x").unwrap();
        let err = commit_overlay(&overlay, &archive, &yes_commit_opts())
            .unwrap_err()
            .to_string();
        assert!(err.contains("got Zstd"), "{err}");
        assert!(err.contains("not a TAR"), "{err}");
    }

    /// Minimal immutable empty base for WriteOverlay construction in tests.
    struct NullBase;
    impl MountSource for NullBase {
        fn list(&self, _path: &str) -> Option<ListResult> {
            Some(ListResult::Infos(Default::default()))
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "null base"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: unlinking an archive member must hide it without a per-lookup
    /// SQL probe, including after the overlay is reopened from the same folder.
    #[test]
    fn tombstone_cache_hides_unlinked_base_across_remount() {
        struct OneFile;
        impl MountSource for OneFile {
            fn list(&self, path: &str) -> Option<ListResult> {
                if path == "/" {
                    let mut map = BTreeMap::new();
                    map.insert("keep.txt".into(), keep_info());
                    map.insert("other.txt".into(), other_info());
                    Some(ListResult::Infos(map))
                } else {
                    None
                }
            }
            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                match path {
                    "/" => Some(create_root_file_info()),
                    "/keep.txt" => Some(keep_info()),
                    "/other.txt" => Some(other_info()),
                    _ => None,
                }
            }
            fn open(
                &self,
                _: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                Err(io::Error::new(io::ErrorKind::NotFound, "one file"))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }
        fn keep_info() -> FileInfo {
            FileInfo {
                size: 4,
                mtime: 0.0,
                mode: ratarmount_core::S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                    offset: 0,
                    offsetheader: Some(0),
                    istar: true,
                    issparse: false,
                    isgenerated: false,
                    recursiondepth: 0,
                })],
            }
        }
        fn other_info() -> FileInfo {
            let mut fi = keep_info();
            fi.size = 5;
            fi
        }

        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(OneFile) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
        assert!(!ov.is_deleted("/keep.txt"));
        assert!(ov.lookup("/keep.txt", 0).is_some());
        for _ in 0..64 {
            assert!(!ov.is_deleted("/other.txt"));
        }
        ov.unlink("/keep.txt").unwrap();
        assert!(ov.is_deleted("/keep.txt"));
        assert!(ov.lookup("/keep.txt", 0).is_none());
        assert!(ov.lookup("/other.txt", 0).is_some());
        assert!(
            ov.list_deleted("/").iter().any(|name| name == "keep.txt"),
            "root listing must still hide the tombstone"
        );
        drop(ov);

        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert!(
            ov.is_deleted("/keep.txt"),
            "reopen must load tombstones from the overlay database"
        );
        assert!(ov.lookup("/keep.txt", 0).is_none());
        assert!(!ov.is_deleted("/other.txt"));
        let fd = ov.create_file("/keep.txt", 0o644).unwrap();
        drop(unsafe {
            use std::os::unix::io::FromRawFd;
            std::fs::File::from_raw_fd(fd)
        });
        assert!(!ov.is_deleted("/keep.txt"));
        let restored = ov.lookup("/keep.txt", 0).expect("recreated overlay file");
        assert!(
            matches!(restored.userdata.last(), Some(UserData::Other(s)) if s.starts_with("overlay:")),
            "create after unlink must clear the tombstone and serve the overlay file"
        );
    }

    /// Archive base with one member, `/keep.txt` (lookup `Some`, so unlink
    /// writes a `deleted = 1` tombstone row).
    struct KeepBase;
    impl MountSource for KeepBase {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                let mut map = BTreeMap::new();
                map.insert("keep.txt".into(), keep_base_info());
                Some(ListResult::Infos(map))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            match path {
                "/" => Some(create_root_file_info()),
                "/keep.txt" => Some(keep_base_info()),
                _ => None,
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "keep base"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }
    fn keep_base_info() -> FileInfo {
        FileInfo {
            size: 4,
            mtime: 0.0,
            mode: ratarmount_core::S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                offset: 0,
                offsetheader: Some(0),
                istar: true,
                issparse: false,
                isgenerated: false,
                recursiondepth: 0,
            })],
        }
    }

    /// Overlay folder whose database holds a `/keep.txt` tombstone.
    fn overlay_with_keep_tombstone() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(KeepBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        ov.unlink("/keep.txt").unwrap();
        assert!(ov.lookup("/keep.txt", 0).is_none());
        drop(ov);
        (dir, overlay)
    }

    fn reopen_keep_overlay(overlay: &Path) -> Result<WriteOverlay> {
        WriteOverlay::new_for_tests(Arc::new(KeepBase) as Arc<dyn MountSource>, overlay)
    }

    /// Remove the overlay database by exact name (plus SQLite sidecars), never
    /// a `sqlite*` glob, which would also take the marker.
    fn remove_overlay_db(overlay: &Path) {
        for suf in ["", "-journal", "-shm", "-wal"] {
            let _ = fs::remove_file(overlay.join(format!("{HIDDEN_DB}{suf}")));
        }
    }

    fn msg_of(r: Result<WriteOverlay>) -> String {
        match r {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected the overlay open to be refused"),
        }
    }

    fn has_files_table(db: &Path) -> bool {
        let c = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        c.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'files'",
            [],
            |_| Ok(()),
        )
        .optional()
        .unwrap()
        .is_some()
    }

    /// Regression: #96, a deleted overlay database was silently recreated, so
    /// every tombstone was lost and unlinked archive members reappeared.
    #[test]
    fn overlay_open_refuses_missing_db_after_use() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        assert!(overlay.join(OVERLAY_MARKER).is_file());
        remove_overlay_db(&overlay);
        let msg = msg_of(reopen_keep_overlay(&overlay));
        assert!(
            msg.contains("database") && msg.contains("is missing"),
            "{msg}"
        );
        assert!(
            !overlay.join(HIDDEN_DB).exists(),
            "refusal must not create the DB"
        );
        let msg2 = msg_of(reopen_keep_overlay(&overlay));
        assert_eq!(msg, msg2);
    }

    /// Regression: #96, a dropped `files` table was recreated empty by SCHEMA.
    #[test]
    fn overlay_open_refuses_db_without_files_table() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        let db = overlay.join(HIDDEN_DB);
        Connection::open(&db)
            .unwrap()
            .execute_batch(r#"DROP TABLE "files";"#)
            .unwrap();
        let msg = msg_of(reopen_keep_overlay(&overlay));
        assert!(msg.contains("has no files table"), "{msg}");
        assert!(!has_files_table(&db), "refusal must not run SCHEMA");
        assert!(msg.contains("on purpose, remove"), "{msg}");
        assert!(msg.contains(" and "), "marker and DB both named: {msg}");
        assert_eq!(msg, msg_of(reopen_keep_overlay(&overlay)));
        // Without the marker (overlay from an older build) a non-empty DB
        // without the table is still refused.
        fs::remove_file(overlay.join(OVERLAY_MARKER)).unwrap();
        assert!(msg_of(reopen_keep_overlay(&overlay)).contains("has no files table"));
        assert!(!has_files_table(&db));
    }

    /// Regression: #96, a truncated (0-byte) database in a marked folder.
    #[test]
    fn overlay_open_refuses_zero_byte_db_in_used_folder() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        remove_overlay_db(&overlay);
        fs::write(overlay.join(HIDDEN_DB), b"").unwrap();
        let msg = msg_of(reopen_keep_overlay(&overlay));
        assert!(msg.contains("is missing or empty"), "{msg}");
        assert_eq!(
            fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len(),
            0,
            "refusal must not initialize the file"
        );
    }

    /// Regression: #96, offline `--commit-overlay` on a used folder whose
    /// database is gone committed without the tombstones.
    #[test]
    fn overlay_commit_plan_refuses_missing_db_after_use() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        assert!(collect_overlay_commit_plan(&overlay).is_ok());
        remove_overlay_db(&overlay);
        let msg = match collect_overlay_commit_plan(&overlay) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("commit plan must be refused"),
        };
        assert!(msg.contains("refusing to commit"), "{msg}");
        assert!(
            msg.contains(OVERLAY_MARKER) && msg.contains("on purpose"),
            "{msg}"
        );
    }

    /// Regression: #97 review, the old marker name started with the DB name,
    /// so `rm ov/.ratarmount.overlay.sqlite*` deleted it too.
    #[test]
    fn overlay_open_refuses_after_db_glob_rm() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        for ent in fs::read_dir(&overlay).unwrap().flatten() {
            if ent.file_name().to_string_lossy().starts_with(HIDDEN_DB) {
                fs::remove_file(ent.path()).unwrap();
            }
        }
        assert!(overlay.join(OVERLAY_MARKER).is_file());
        let msg = msg_of(reopen_keep_overlay(&overlay));
        assert!(msg.contains("is missing"), "{msg}");
        let hint = format!(
            "to discard this overlay's deletions on purpose, remove {}",
            overlay
                .canonicalize()
                .unwrap()
                .join(OVERLAY_MARKER)
                .display()
        );
        assert!(msg.contains(&hint), "{msg}");
    }

    /// The pre-rename marker name still guards the folder; it is migrated to
    /// the new name and then deleted, so a reset is one file.
    #[test]
    fn overlay_open_accepts_legacy_marker() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        fs::rename(
            overlay.join(OVERLAY_MARKER),
            overlay.join(LEGACY_OVERLAY_MARKER),
        )
        .unwrap();
        let ov = reopen_keep_overlay(&overlay).unwrap();
        assert!(ov.lookup("/keep.txt", 0).is_none());
        drop(ov);
        assert!(
            overlay.join(OVERLAY_MARKER).is_file(),
            "legacy marker is migrated to the new name"
        );
        assert!(
            !overlay.join(LEGACY_OVERLAY_MARKER).exists(),
            "legacy removed"
        );
        // The old glob takes the DB; the new marker stays.
        for ent in fs::read_dir(&overlay).unwrap().flatten() {
            if ent.file_name().to_string_lossy().starts_with(HIDDEN_DB) {
                fs::remove_file(ent.path()).unwrap();
            }
        }
        let msg = msg_of(reopen_keep_overlay(&overlay));
        assert!(msg.contains(OVERLAY_MARKER), "{msg}");
    }

    /// Regression: folders an earlier build migrated kept both markers, so a
    /// reset needed two removals. The next open drops the legacy one.
    #[test]
    fn overlay_open_removes_legacy_marker_when_both_present() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        fs::write(overlay.join(LEGACY_OVERLAY_MARKER), b"").unwrap();
        let ov = reopen_keep_overlay(&overlay).unwrap();
        assert!(ov.lookup("/keep.txt", 0).is_none(), "tombstone kept");
        drop(ov);
        assert!(overlay.join(OVERLAY_MARKER).is_file());
        assert!(!overlay.join(LEGACY_OVERLAY_MARKER).exists());
    }

    /// Every marker present is named in the reset hint (here: legacy could
    /// not be cleaned because the DB was already gone).
    #[test]
    fn overlay_refusal_lists_every_marker() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        fs::write(overlay.join(LEGACY_OVERLAY_MARKER), b"").unwrap();
        remove_overlay_db(&overlay);
        let msg = msg_of(reopen_keep_overlay(&overlay));
        assert!(
            msg.contains(OVERLAY_MARKER) && msg.contains(LEGACY_OVERLAY_MARKER),
            "{msg}"
        );
        let msg = match collect_overlay_commit_plan(&overlay) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("commit must be refused"),
        };
        assert!(
            msg.contains(OVERLAY_MARKER) && msg.contains(LEGACY_OVERLAY_MARKER),
            "{msg}"
        );
    }

    /// Regression (Keystone, #97): the commit refusal said only "missing" and
    /// printed the overlay path as given.
    #[test]
    fn overlay_commit_refusal_missing_or_empty_canonical() {
        let (dir, overlay) = overlay_with_keep_tombstone();
        remove_overlay_db(&overlay);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&overlay, &link).unwrap();
        let msg = match collect_overlay_commit_plan(&link) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("commit must be refused"),
        };
        let canon = overlay.canonicalize().unwrap();
        assert!(msg.contains("is missing or empty"), "{msg}");
        assert!(
            msg.contains(&canon.join(HIDDEN_DB).display().to_string()),
            "{msg}"
        );
        assert!(!msg.contains(&format!("{}/", link.display())), "{msg}");
    }

    /// Regression (Robo-Ilya, #97): the database and markers were visible to
    /// lookup through the mount.
    #[test]
    fn overlay_internal_names_hidden_from_lookup() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        let ov = reopen_keep_overlay(&overlay).unwrap();
        for p in [
            format!("/{HIDDEN_DB}"),
            format!("/{HIDDEN_DB}-journal"),
            format!("/{OVERLAY_MARKER}"),
            format!("/{LEGACY_OVERLAY_MARKER}"),
            format!("/sub/{OVERLAY_MARKER}"),
            format!("/{COW_STAGING_PREFIX}Ab12Cd"),
        ] {
            assert!(ov.lookup(&p, 0).is_none(), "{p}");
            assert!(!ov.has_file(&p), "{p}");
        }
        // Planted after open, so startup sweep cannot remove it. Lookup and
        // has_file still have to treat the staging prefix as bookkeeping.
        let planted_name = format!("{COW_STAGING_PREFIX}Ab12Cd");
        fs::write(overlay.join(&planted_name), b"short").unwrap();
        let planted = format!("/{planted_name}");
        assert!(ov.lookup(&planted, 0).is_none(), "{planted}");
        assert!(!ov.has_file(&planted), "{planted}");
        // A base-archive member with the database name is hidden too.
        struct DbNamedBase;
        impl MountSource for DbNamedBase {
            fn list(&self, _: &str) -> Option<ListResult> {
                None
            }
            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                (path == "/.ratarmount.overlay.sqlite").then(keep_base_info)
            }
            fn open(
                &self,
                _: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                Err(io::Error::from(io::ErrorKind::Unsupported))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let ov2 = WriteOverlay::new_for_tests(Arc::new(DbNamedBase), dir.path().join("o")).unwrap();
        // Remove the host DB so only the base member could answer.
        fs::remove_file(dir.path().join("o").join(HIDDEN_DB)).unwrap();
        assert!(ov2.lookup("/.ratarmount.overlay.sqlite", 0).is_none());
    }

    /// Regression (Robo-Ilya, #97): create/delete/rename/truncate of the
    /// database or a marker through the mount could destroy the tombstones.
    #[test]
    fn overlay_internal_names_refuse_mutation() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        let db_len = fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len();
        let ov = reopen_keep_overlay(&overlay).unwrap();
        let denied = |r: Result<()>| match r {
            Err(OverlayError::Io(e)) => e.kind() == io::ErrorKind::PermissionDenied,
            _ => false,
        };
        for p in [
            format!("/{HIDDEN_DB}"),
            format!("/{HIDDEN_DB}-journal"),
            format!("/{OVERLAY_MARKER}"),
            format!("/{LEGACY_OVERLAY_MARKER}"),
            format!("/sub/{OVERLAY_MARKER}"),
        ] {
            assert!(denied(ov.create_file(&p, 0o644).map(|_| ())), "create {p}");
            assert!(
                denied(ov.open_overlay_fd(&p, libc::O_RDONLY).map(|_| ())),
                "open {p}"
            );
            assert!(
                denied(ov.open_overlay_fd(&p, libc::O_WRONLY).map(|_| ())),
                "open w {p}"
            );
            assert!(denied(ov.unlink(&p)), "unlink {p}");
            assert!(denied(ov.mkdir(&p, 0o755)), "mkdir {p}");
            assert!(denied(ov.rmdir(&p)), "rmdir {p}");
            assert!(denied(ov.truncate(&p, 0)), "truncate {p}");
            assert!(denied(ov.create_symlink(&p, "x")), "symlink {p}");
            assert!(denied(ov.rename(&p, "/x")), "rename from {p}");
            assert!(denied(ov.rename("/keep.txt", &p)), "rename to {p}");
            assert!(denied(ov.ensure_modifiable(&p)), "cow {p}");
        }
        drop(ov);
        assert_eq!(fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len(), db_len);
        assert!(overlay.join(OVERLAY_MARKER).is_file());
        let ov = reopen_keep_overlay(&overlay).unwrap();
        assert!(ov.lookup("/keep.txt", 0).is_none(), "tombstone kept");
    }

    /// Keystone (#99): on a case-insensitive overlay folder a case variant
    /// of the database or marker name is the real file, so it is refused and
    /// hidden like the exact name.
    #[test]
    fn overlay_internal_names_ignore_ascii_case() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        let db_len = fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len();
        let ov = reopen_keep_overlay(&overlay).unwrap();
        let denied = |r: Result<()>| match r {
            Err(OverlayError::Io(e)) => e.kind() == io::ErrorKind::PermissionDenied,
            _ => false,
        };
        for p in [
            "/.RATARMOUNT.OVERLAY.SQLITE",
            "/.Ratarmount-Overlay.Used",
            "/.Ratarmount.Overlay.Sqlite-journal",
            "/sub/.RATARMOUNT-OVERLAY.USED/foo",
        ] {
            assert!(denied(ov.create_file(p, 0o644).map(|_| ())), "create {p}");
            assert!(denied(ov.unlink(p)), "unlink {p}");
            assert!(denied(ov.mkdir(p, 0o755)), "mkdir {p}");
            assert!(denied(ov.truncate(p, 0)), "truncate {p}");
            assert!(denied(ov.rename("/keep.txt", p)), "rename to {p}");
            assert!(ov.lookup(p, 0).is_none(), "lookup {p}");
        }
        drop(ov);
        assert_eq!(fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len(), db_len);
        if cfg!(target_os = "linux") {
            assert!(!overlay.join(".RATARMOUNT.OVERLAY.SQLITE").exists());
        }
    }

    /// Plan skeptic (round 2): SMB/SFTP pass full paths, so a path *beneath*
    /// a bookkeeping name must be refused before `create_dir_all`, hidden from
    /// lookup/listing, and skipped by the commit walk.
    #[test]
    fn overlay_internal_names_refused_beneath_any_component() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        let ov = reopen_keep_overlay(&overlay).unwrap();
        let denied = |r: Result<()>| match r {
            Err(OverlayError::Io(e)) => e.kind() == io::ErrorKind::PermissionDenied,
            _ => false,
        };
        let p = format!("/sub/{OVERLAY_MARKER}/foo");
        assert!(denied(ov.create_file(&p, 0o644).map(|_| ())), "create {p}");
        assert!(denied(ov.mkdir(&p, 0o755)), "mkdir {p}");
        assert!(denied(ov.rename("/keep.txt", &p)), "rename to {p}");
        assert!(!overlay.join("sub").join(OVERLAY_MARKER).exists());
        assert!(ov.lookup(&format!("/{HIDDEN_DB}/."), 0).is_none());
        // A child planted on the host under that name is invisible and
        // never appended by commit.
        fs::create_dir_all(overlay.join("sub").join(OVERLAY_MARKER)).unwrap();
        fs::write(overlay.join("sub").join(OVERLAY_MARKER).join("foo"), b"x").unwrap();
        assert!(ov.lookup(&p, 0).is_none());
        assert!(ov.list(&format!("/sub/{OVERLAY_MARKER}")).is_none());
        drop(ov);
        let plan =
            collect_overlay_commit_plan_from_conn(&overlay, None, None, &HashSet::new()).unwrap();
        assert!(
            !plan.append_entries.is_empty()
                && plan
                    .append_entries
                    .iter()
                    .all(|(e, _)| !e.split('/').any(is_overlay_internal_name)),
            "{:?}",
            plan.append_entries
        );
    }

    /// Plan skeptic (round 2): a non-regular entry under either marker name
    /// fails closed even when the other marker is a regular file.
    #[test]
    fn overlay_markers_fail_closed_on_non_regular_sibling() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(LEGACY_OVERLAY_MARKER), b"").unwrap();
        fs::create_dir(dir.path().join(OVERLAY_MARKER)).unwrap();
        let e = overlay_markers(dir.path()).unwrap_err().to_string();
        assert!(e.contains("not a regular file"), "{e}");
        assert!(e.contains(OVERLAY_MARKER), "{e}");
    }

    /// Regression: a first open that fails after the marker was created
    /// (SCHEMA on a read-only 0-byte database) must not leave the marker.
    #[test]
    fn overlay_first_open_failure_removes_marker() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        fs::create_dir(&overlay).unwrap();
        let db = overlay.join(HIDDEN_DB);
        fs::write(&db, b"").unwrap();
        fs::set_permissions(&db, fs::Permissions::from_mode(0o444)).unwrap();
        if fs::OpenOptions::new().write(true).open(&db).is_ok() {
            eprintln!("skip: read-only file is writable (running as root?)");
            return;
        }
        let r = reopen_keep_overlay(&overlay);
        assert!(r.is_err(), "SCHEMA on a read-only DB must fail");
        assert!(
            !overlay.join(OVERLAY_MARKER).exists(),
            "marker must be removed"
        );
        fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(fs::metadata(&db).unwrap().len(), 0);
        reopen_keep_overlay(&overlay).expect("folder still opens as new");
    }

    /// Robo-Ilya: a directory at the database path is named as such.
    #[test]
    fn overlay_open_db_path_directory_is_named() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        remove_overlay_db(&overlay);
        fs::create_dir(overlay.join(HIDDEN_DB)).unwrap();
        let msg = msg_of(reopen_keep_overlay(&overlay));
        assert!(msg.contains("is a directory, not a database file"), "{msg}");
        let msg = match collect_overlay_commit_plan(&overlay) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("commit must be refused"),
        };
        assert!(msg.contains("is a directory"), "{msg}");
    }

    #[test]
    fn overlay_open_accepts_new_empty_and_zero_byte() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        let zero = dir.path().join("zero");
        fs::create_dir(&zero).unwrap();
        fs::write(zero.join(HIDDEN_DB), b"").unwrap();
        for ov in [&missing, &empty, &zero] {
            let o = reopen_keep_overlay(ov).unwrap_or_else(|e| panic!("{}: {e}", ov.display()));
            drop(o);
            assert!(ov.join(OVERLAY_MARKER).is_file(), "{}", ov.display());
            assert!(has_files_table(&ov.join(HIDDEN_DB)));
        }
    }

    /// Overlays created before the marker existed get it on their next open.
    #[test]
    fn overlay_open_backfills_marker() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        fs::remove_file(overlay.join(OVERLAY_MARKER)).unwrap();
        let ov = reopen_keep_overlay(&overlay).unwrap();
        assert!(ov.lookup("/keep.txt", 0).is_none(), "tombstone kept");
        assert!(overlay.join(OVERLAY_MARKER).is_file());
    }

    /// A symlinked database keeps working across opens (followed like
    /// `Connection::open` does), and the tombstone survives.
    #[test]
    fn overlay_open_follows_symlinked_db_across_opens() {
        let (dir, overlay) = overlay_with_keep_tombstone();
        let real = dir.path().join("real.sqlite");
        fs::rename(overlay.join(HIDDEN_DB), &real).unwrap();
        std::os::unix::fs::symlink(&real, overlay.join(HIDDEN_DB)).unwrap();
        for _ in 0..2 {
            let ov = reopen_keep_overlay(&overlay).unwrap();
            assert!(ov.lookup("/keep.txt", 0).is_none(), "tombstone kept");
        }
        fs::remove_file(&real).unwrap();
        assert!(msg_of(reopen_keep_overlay(&overlay)).contains("is missing"));
    }

    /// Regression: the marker must not be created through a planted symlink.
    #[test]
    fn overlay_marker_symlink_is_refused_and_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, b"secret").unwrap();
        let dangling_target = dir.path().join("created-outside");
        for (name, target) in [("a", &outside), ("b", &dangling_target)] {
            let overlay = dir.path().join(name);
            fs::create_dir(&overlay).unwrap();
            std::os::unix::fs::symlink(target, overlay.join(OVERLAY_MARKER)).unwrap();
            let r =
                WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay);
            assert!(r.is_err(), "symlinked marker must be refused");
        }
        assert_eq!(fs::read(&outside).unwrap(), b"secret");
        assert!(!dangling_target.exists());
    }

    #[test]
    fn overlay_marker_is_hidden_kept_on_reset_and_not_committed() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        let ov = reopen_keep_overlay(&overlay).unwrap();
        let names: Vec<String> = ov
            .list_dirents("/")
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert!(!names.iter().any(|n| n == OVERLAY_MARKER), "{names:?}");
        assert!(ov.list_deleted("/").iter().any(|n| n == OVERLAY_MARKER));
        reset_overlay_dir(&overlay).unwrap();
        assert!(overlay.join(OVERLAY_MARKER).is_file());
        assert!(overlay.join(HIDDEN_DB).is_file());
        drop(ov);
        let plan =
            collect_overlay_commit_plan_from_conn(&overlay, None, None, &HashSet::new()).unwrap();
        assert!(
            plan.append_entries.iter().all(|(p, _)| p != OVERLAY_MARKER),
            "{:?}",
            plan.append_entries
        );
        assert!(!plan.deleted_paths.contains(OVERLAY_MARKER));
    }

    /// Regression: a failing tombstone SELECT at open became an empty set, so
    /// every unlinked archive member reappeared. Opening must fail instead.
    #[test]
    fn overlay_open_fails_when_tombstone_query_errors() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        {
            let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
            conn.execute_batch(r#"ALTER TABLE "files" RENAME COLUMN "deleted" TO "deleted_x";"#)
                .unwrap();
        } // EXCLUSIVE locking: drop before reopening.
        match reopen_keep_overlay(&overlay) {
            Ok(ov) => panic!(
                "overlay opened with an unreadable tombstone table; /keep.txt visible: {}",
                ov.lookup("/keep.txt", 0).is_some()
            ),
            Err(e) => assert!(
                matches!(e, OverlayError::Sqlite(_)) && e.to_string().contains("no such column"),
                "want the tombstone SELECT error, got {e}"
            ),
        }
    }

    /// Regression: an unreadable tombstone row was dropped by
    /// `filter_map(ok)`, opening with a partial set (that member reappears).
    #[test]
    fn overlay_open_fails_when_a_tombstone_row_is_unreadable() {
        let (_dir, overlay) = overlay_with_keep_tombstone();
        {
            let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
            conn.execute(
                r#"INSERT INTO "files" (path, name, deleted) VALUES ('', X'FF', 1)"#,
                [],
            )
            .unwrap();
            let kind: String = conn
                .query_row(
                    r#"SELECT typeof(name) FROM "files" WHERE path = '' AND deleted = 1 AND typeof(name) = 'blob'"#,
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(kind, "blob", "TEXT affinity keeps blobs as blobs");
        }
        match reopen_keep_overlay(&overlay) {
            Ok(_) => panic!("overlay opened with a partial tombstone set"),
            Err(e) => assert!(
                matches!(
                    e,
                    OverlayError::Sqlite(rusqlite::Error::InvalidColumnType(..))
                ),
                "want InvalidColumnType from the tombstone row, got {e}"
            ),
        }
    }

    /// Regression: prune EACCES after a committed delete left `is_deleted` true.
    ///
    /// Symptom: `forget_committed_overlay` deleted the `gone` row, then
    /// `prune_empty_overlay_ancestors` returned before `tombstone_forget_many`,
    /// so the in-memory set still hid `gone`.
    #[test]
    fn forget_committed_overlay_forgets_tombstone_when_prune_fails() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip: euid 0 ignores mode 0o555");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();

        let sub = ov.root.join("sub");
        fs::create_dir_all(sub.join("nested")).unwrap();
        fs::write(sub.join("nested").join("f"), b"payload").unwrap();
        {
            let db = ov.db.lock().expect("overlay db");
            db.execute(
                r#"INSERT OR REPLACE INTO "files" (path,name,deleted) VALUES ('','gone',1)"#,
                [],
            )
            .unwrap();
        }
        ov.tombstone_remember("gone");
        assert!(
            ov.is_deleted("gone"),
            "fixture must seed the in-memory tombstone"
        );

        // `sub` at 0o555 blocks removing `nested`. Restore before TempDir drops.
        struct RestoreMode {
            path: PathBuf,
            mode: u32,
        }
        impl Drop for RestoreMode {
            fn drop(&mut self) {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
            }
        }
        let original_mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&sub).unwrap().permissions().mode()
        };
        let _restore = RestoreMode {
            path: sub.clone(),
            mode: original_mode,
        };
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sub, fs::Permissions::from_mode(0o555)).unwrap();
        }

        let plan = OverlayCommitPlan {
            known_hashes: BTreeMap::new(),
            written_hashes: BTreeMap::new(),
            metadata: BTreeMap::new(),
            xattrs: BTreeMap::new(),
            deletions_nul: Vec::new(),
            appends_nul: Vec::new(),
            deleted_paths: ["gone".into()].into_iter().collect(),
            append_entries: vec![("sub/nested/f".into(), false)],
        };
        let err = ov
            .forget_committed_overlay(&plan)
            .expect_err("prune remove_dir(sub/nested) must fail");
        let OverlayError::Io(ioe) = &err else {
            panic!("expected io::PermissionDenied from prune, got {err}");
        };
        assert_eq!(
            ioe.kind(),
            io::ErrorKind::PermissionDenied,
            "expected EACCES from prune, got {err}"
        );
        {
            let db = ov.db.lock().expect("overlay db");
            let n: i64 = db
                .query_row(
                    r#"SELECT COUNT(*) FROM "files" WHERE path = '' AND name = 'gone'"#,
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(n, 0, "gone row must be deleted before prune fails");
        }
        assert!(
            !ov.is_deleted("gone"),
            "committed tombstone must leave the cache when prune fails"
        );
    }

    /// Regression: overlay open/create must not follow host symlinks outside root.
    ///
    /// Symptom: `realpath` is join+normpath only; `libc::open` / `File::create`
    /// follow symlinks, so a pre-seeded symlink under the overlay folder can
    /// redirect writes to arbitrary host paths.
    #[test]
    fn overlay_rejects_symlink_escape_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let outside_file = outside.join("secret.txt");
        fs::write(&outside_file, b"secret-data").unwrap();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        // Plant a file symlink and a directory symlink pointing outside the overlay.
        std::os::unix::fs::symlink(&outside_file, overlay.join("escape")).unwrap();
        std::os::unix::fs::symlink(&outside, overlay.join("outdir")).unwrap();

        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();

        // create_file through file symlink must fail and not clobber outside content.
        let err = ov.create_file("/escape", 0o644);
        assert!(
            err.is_err(),
            "create_file through escape symlink must fail, got Ok"
        );
        assert_eq!(
            fs::read(&outside_file).unwrap(),
            b"secret-data",
            "outside file must remain untouched after create_file"
        );

        // open_overlay_fd must not follow the escape symlink either.
        let err = ov.open_overlay_fd("/escape", libc::O_RDWR | libc::O_CREAT);
        assert!(
            err.is_err(),
            "open_overlay_fd through escape symlink must fail, got Ok"
        );
        assert_eq!(
            fs::read(&outside_file).unwrap(),
            b"secret-data",
            "outside file must remain untouched after open_overlay_fd"
        );

        // create under a directory symlink must not write outside the overlay.
        let err = ov.create_file("/outdir/pwned.txt", 0o644);
        assert!(
            err.is_err(),
            "create_file under dir symlink must fail, got Ok"
        );
        assert!(
            !outside.join("pwned.txt").exists(),
            "must not create files outside overlay via dir symlink"
        );

        // mkdir via escape dir symlink must fail.
        let err = ov.mkdir("/outdir/evil-dir", 0o755);
        assert!(err.is_err(), "mkdir under dir symlink must fail, got Ok");
        assert!(
            !outside.join("evil-dir").exists(),
            "must not mkdir outside overlay via dir symlink"
        );

        // Normal create inside overlay still works.
        let fd = ov.create_file("/safe.txt", 0o644).expect("safe create");
        assert!(fd >= 0);
        unsafe {
            libc::close(fd);
        }
        assert!(overlay.join("safe.txt").exists() || ov.root().join("safe.txt").exists());
    }

    /// Counts `list()` so we can prove WriteOverlay uses `base.list_dirents`.
    struct ListCallCounter {
        inner: ratarmount_formats_zip::ZipMountSource,
        list_calls: std::sync::atomic::AtomicUsize,
    }

    impl MountSource for ListCallCounter {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.list_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.list(path)
        }

        fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
            self.inner.list_dirents(path)
        }

        fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
            self.inner.lookup(path, file_version)
        }

        fn versions(&self, path: &str) -> u32 {
            self.inner.versions(path)
        }

        fn open(
            &self,
            file_info: &FileInfo,
            buffering: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.inner.open(file_info, buffering)
        }

        fn is_immutable(&self) -> bool {
            self.inner.is_immutable()
        }
    }

    fn zip_counted_base() -> (
        tempfile::TempDir,
        Arc<ListCallCounter>,
        &'static [u8],
        &'static [u8],
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overlay-base.zip");
        let a: &'static [u8] = b"alpha-payload\n";
        let b: &'static [u8] = b"bravo-bytes-here\n";
        write_sample_zip(
            &path,
            &[
                ("a.txt", a, CompressionMethod::Stored),
                ("b.bin", b, CompressionMethod::Stored),
            ],
        );
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let zip = ratarmount_formats_zip::ZipMountSource::open(&path, None, &opts, "test", true)
            .expect("open zip");
        let counted = Arc::new(ListCallCounter {
            inner: zip,
            list_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        (dir, counted, a, b)
    }

    /// Regression: `-w` readdir called `base.list()`.
    #[test]
    fn overlay_list_dirents_base_plus_overlay_minus_deletes_without_base_list() {
        let (dir, counted, _a, b) = zip_counted_base();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov =
            WriteOverlay::new_for_tests(Arc::clone(&counted) as Arc<dyn MountSource>, &overlay)
                .expect("overlay");

        ov.unlink("/a.txt").expect("delete base a.txt");
        let fd = ov.create_file("/c.txt", 0o644).expect("overlay create");
        unsafe {
            libc::close(fd);
        }
        fs::write(ov.root().join("c.txt"), b"overlay-only\n").unwrap();

        let dents = ov.list_dirents("/").expect("cheap overlay dirents");
        assert_eq!(
            counted.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "WriteOverlay::list_dirents must not call base.list() (fat FileInfo map)"
        );
        let by_name: BTreeMap<_, _> = dents.into_iter().map(|d| (d.name, d.size)).collect();
        assert!(
            !by_name.contains_key("a.txt"),
            "deleted base name must be gone: {by_name:?}"
        );
        assert_eq!(by_name.get("b.bin").copied(), Some(b.len() as u64));
        assert_eq!(
            by_name.get("c.txt").copied(),
            Some(b"overlay-only\n".len() as u64)
        );
        assert!(
            !by_name.keys().any(|n| n.starts_with(HIDDEN_DB)),
            "overlay DB must stay hidden: {by_name:?}"
        );
    }

    /// Regression: create-then-list reported leftover base size.
    #[test]
    fn overlay_list_dirents_create_empty_has_size_zero() {
        let (dir, counted, a, _b) = zip_counted_base();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov =
            WriteOverlay::new_for_tests(Arc::clone(&counted) as Arc<dyn MountSource>, &overlay)
                .expect("overlay");

        assert!(
            !a.is_empty(),
            "base member must have a leftover size to regress against"
        );
        let fd = ov
            .create_file("/a.txt", 0o644)
            .expect("create empty overlay");
        unsafe {
            libc::close(fd);
        }

        let dents = ov.list_dirents("/").expect("cheap overlay dirents");
        assert_eq!(
            counted.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "WriteOverlay::list_dirents must not call base.list()"
        );
        let a_dent = dents
            .iter()
            .find(|d| d.name == "a.txt")
            .expect("overlay-created a.txt");
        assert_eq!(
            a_dent.size,
            0,
            "create-then-list must not report leftover base size {}",
            a.len()
        );
    }

    fn catalog_member_path(m: &ratarmount_index::VisibleMember) -> String {
        if m.path.is_empty() || m.path == "/" {
            format!("/{}", m.name)
        } else {
            format!("{}/{}", m.path, m.name)
        }
    }

    fn overlay_write_bytes(ov: &WriteOverlay, path: &str, bytes: &[u8]) {
        let fd = ov.create_file(path, 0o644).expect("create");
        {
            use std::os::unix::io::FromRawFd;
            let mut f = unsafe { File::from_raw_fd(fd) };
            f.write_all(bytes).unwrap();
        }
        ov.release_write_fd(fd);
    }

    /// Documented extract order: catalog flatten, then overlay-only names.
    fn concat_catalog_then_overlay(catalog: &[String], overlay: &[String]) -> Vec<String> {
        let mut out = catalog.to_vec();
        out.extend(overlay.iter().cloned());
        out
    }

    /// Forwards to `inner` except `/gen.txt`, a generated `S_IFREG` (not a flatten payload).
    struct WithGeneratedReg {
        inner: Arc<dyn MountSource>,
    }

    impl MountSource for WithGeneratedReg {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.inner.list(path)
        }
        fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
            if normpath(path) == "/gen.txt" {
                return Some(FileInfo {
                    size: 1,
                    mtime: 0.0,
                    mode: ratarmount_core::S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                        offset: 0,
                        offsetheader: Some(0),
                        istar: true,
                        issparse: false,
                        isgenerated: true,
                        recursiondepth: 0,
                    })],
                });
            }
            self.inner.lookup(path, file_version)
        }
        fn open(
            &self,
            file_info: &FileInfo,
            buffering: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.inner.open(file_info, buffering)
        }
        fn is_immutable(&self) -> bool {
            self.inner.is_immutable()
        }
    }

    /// Regression: overlay create is visible after catalog flatten members.
    /// Catalog flatten stays overlay-free; COW of a catalog path is not overlay-only.
    #[test]
    fn regression_overlay_only_names_listed_after_catalog_flatten() {
        let dir = tempfile::tempdir().unwrap();
        let z = b"z-payload\n";
        let a = b"a-payload\n";
        let bytes = pack_tar(&[
            ustar_file("z.txt", z),
            ustar_file("a.txt", a),
            ustar_symlink("link.txt", "a.txt"),
        ]);
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let tar = SqliteIndexedTar::create_index_from_reader(
            std::io::Cursor::new(bytes),
            Path::new("overlay-extract.tar"),
            None,
            &opts,
            "test",
        )
        .expect("index tar");
        let catalog = tar
            .index()
            .list_visible_files_by_offset()
            .expect("flatten stays overlay-free");
        let catalog_paths: Vec<String> = catalog.iter().map(catalog_member_path).collect();
        assert_eq!(
            catalog_paths,
            vec!["/z.txt".to_string(), "/a.txt".to_string()],
            "offset flatten is archive order, not name order; symlink is not a payload"
        );

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        // Default CLI stack is FileVersionLayer then WriteOverlay; last userdata
        // is `versionlayer:file`, not Tar.
        let stacked = crate::FileVersionLayer::new(Arc::new(WithGeneratedReg {
            inner: Arc::new(tar) as Arc<dyn MountSource>,
        }));
        let ov = WriteOverlay::new_for_tests(Arc::new(stacked) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        let z_fi = ov.current_base().lookup("/z.txt", 0).expect("z.txt");
        assert!(
            matches!(z_fi.userdata.last(), Some(UserData::Other(s)) if s == "versionlayer:file"),
            "FileVersionLayer must own last userdata: {:?}",
            z_fi.userdata.last()
        );
        overlay_write_bytes(&ov, "/new.txt", b"overlay-create\n");
        overlay_write_bytes(&ov, "/ov/nested.bin", b"nested-only\n");
        overlay_write_bytes(&ov, "/z.txt", b"cow-replace\n");
        overlay_write_bytes(&ov, "/link.txt", b"was-symlink\n");
        overlay_write_bytes(&ov, "/gen.txt", b"was-generated\n");

        let ov_names = overlay_only_names(&ov);
        assert_eq!(
            ov_names,
            vec![
                "/gen.txt".to_string(),
                "/link.txt".to_string(),
                "/new.txt".to_string(),
                "/ov/nested.bin".to_string()
            ],
            "creates + symlink replace + generated S_IFREG; COW of /z.txt excluded: {ov_names:?}"
        );
        assert!(
            !ov_names.iter().any(|p| p == "/z.txt" || p == "/a.txt"),
            "catalog flatten payloads must not appear in overlay_only_names: {ov_names:?}"
        );
        assert!(
            !catalog_paths
                .iter()
                .any(|p| { p == "/new.txt" || p == "/ov/nested.bin" || p == "/link.txt" }),
            "catalog flatten must stay overlay-free: {catalog_paths:?}"
        );

        assert_eq!(
            concat_catalog_then_overlay(&catalog_paths, &ov_names),
            vec![
                "/z.txt".to_string(),
                "/a.txt".to_string(),
                "/gen.txt".to_string(),
                "/link.txt".to_string(),
                "/new.txt".to_string(),
                "/ov/nested.bin".to_string(),
            ],
            "overlay-only host paths listed last"
        );
        assert!(ov.has_file("/new.txt"));
        assert!(ov.has_file("/ov/nested.bin"));
        assert!(ov.has_file("/link.txt"));
        assert!(ov.has_file("/gen.txt"));
    }

    /// Regression: restore loop must not SeekFrom::Start to cookie.offset on overlay names.
    /// Dummy CompactOpenCookie (offsetheader = -1) would seek the base at garbage.
    #[test]
    fn regression_overlay_only_restore_does_not_seek_cookie_offset() {
        let dir = tempfile::tempdir().unwrap();
        let z = b"z-payload\n";
        let a = b"a-payload\n";
        let bytes = pack_tar(&[ustar_file("z.txt", z), ustar_file("a.txt", a)]);
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let tar = SqliteIndexedTar::create_index_from_reader(
            std::io::Cursor::new(bytes.clone()),
            Path::new("overlay-restore.tar"),
            None,
            &opts,
            "test",
        )
        .expect("index tar");
        let catalog = tar.index().list_visible_files_by_offset().expect("flatten");

        struct StartLog {
            inner: std::io::Cursor<Vec<u8>>,
            starts: Vec<u64>,
        }
        impl Read for StartLog {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.inner.read(buf)
            }
        }
        impl Seek for StartLog {
            fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
                if let SeekFrom::Start(n) = from {
                    self.starts.push(n);
                }
                self.inner.seek(from)
            }
        }

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov =
            WriteOverlay::new_for_tests(Arc::new(tar) as Arc<dyn MountSource>, &overlay).unwrap();
        overlay_write_bytes(&ov, "/new.txt", b"overlay-create\n");
        let ov_names = overlay_only_names(&ov);
        assert_eq!(ov_names, vec!["/new.txt".to_string()]);

        let mut reader = StartLog {
            inner: std::io::Cursor::new(bytes),
            starts: Vec::new(),
        };
        for mem in &catalog {
            reader.seek(SeekFrom::Start(mem.cookie.offset)).unwrap();
            let mut buf = vec![0u8; mem.cookie.size as usize];
            reader.read_exact(&mut buf).unwrap();
        }
        let catalog_starts = reader.starts.len();
        assert!(
            catalog_starts >= 2,
            "catalog restore seeks: {:?}",
            reader.starts
        );

        for virt in ov_names {
            assert!(
                ov.has_file(&virt),
                "overlay-only {virt} must open via has_file / overlay fd"
            );
            let fi = ov.lookup(&virt, 0).expect("overlay lookup");
            match fi.userdata.last() {
                Some(UserData::Other(s)) if s.starts_with("overlay:") => {}
                other => {
                    panic!("overlay-only must not carry a catalog CompactOpenCookie: {other:?}")
                }
            }
            let mut r = ov.open(&fi, 0).expect("overlay fd");
            let mut body = Vec::new();
            r.read_to_end(&mut body).unwrap();
            assert_eq!(body, b"overlay-create\n");
        }
        assert_eq!(
            reader.starts.len(),
            catalog_starts,
            "overlay names must not SeekFrom::Start cookie.offset, starts={:?}",
            reader.starts
        );
    }

    fn make_tiny_tar(dir: &Path, members: &[(&str, &[u8])]) -> PathBuf {
        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        for (name, body) in members {
            let p = tree.join(name);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, body).unwrap();
        }
        let tar = dir.join("a.tar");
        let mut cmd = StdCommand::new("tar");
        cmd.arg("-cf").arg(&tar).arg("-C").arg(&tree);
        for (name, _) in members {
            cmd.arg(name);
        }
        assert!(cmd.status().unwrap().success());
        tar
    }

    #[test]
    fn overlay_rename_and_symlink_persist() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        let fd = ov.create_file("/src.txt", 0o644).unwrap();
        unsafe {
            libc::close(fd);
        }
        fs::write(overlay.join("src.txt"), b"renamed-bytes\n").unwrap();
        ov.rename("/src.txt", "/dst.txt").expect("rename");
        assert!(ov.lookup("/src.txt", 0).is_none());
        let fi = ov.lookup("/dst.txt", 0).expect("dst");
        assert_eq!(fi.size, b"renamed-bytes\n".len() as u64);

        ov.create_symlink("/link", "dst.txt").expect("symlink");
        let link = ov.lookup("/link", 0).expect("link info");
        assert!(ratarmount_core::is_lnk_mode(link.mode));
        assert_eq!(link.linkname, "dst.txt");
        let dents = ov.list_dirents("/").unwrap();
        let names: Vec<_> = dents.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"dst.txt"), "{names:?}");
        assert!(names.contains(&"link"), "{names:?}");
    }

    /// Regression: renaming (or COW-ing) a base symlink must materialize a
    /// symlink in the overlay — copying its "content" yielded an empty
    /// regular file, and a later commit dropped the link member entirely.
    #[test]
    fn rename_base_symlink_stays_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("base");
        fs::create_dir_all(&base_dir).unwrap();
        fs::write(base_dir.join("target.txt"), b"payload\n").unwrap();
        std::os::unix::fs::symlink("target.txt", base_dir.join("link")).unwrap();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = crate::folder::FolderMountSource::new(&base_dir).unwrap();
        let ov =
            WriteOverlay::new_for_tests(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();

        ov.rename("/link", "/link2").expect("rename symlink");
        let meta = fs::symlink_metadata(overlay.join("link2")).expect("overlay link2");
        assert!(
            meta.file_type().is_symlink(),
            "rename must COW a symlink as a symlink, got {:?}",
            meta.file_type()
        );
        assert_eq!(
            fs::read_link(overlay.join("link2")).unwrap(),
            std::path::PathBuf::from("target.txt")
        );
        let fi = ov.lookup("/link2", 0).expect("lookup link2");
        assert!(ratarmount_core::is_lnk_mode(fi.mode));
        assert_eq!(fi.linkname, "target.txt");
        assert!(ov.lookup("/link", 0).is_none(), "old name must be gone");
    }

    /// Regression: rmdir must refuse non-empty union dirs (base children
    /// included) and non-directories — committing a bare dir tombstone would
    /// recursively delete or orphan the children depending on commit format.
    #[test]
    fn rmdir_refuses_nonempty_and_non_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("base");
        fs::create_dir_all(base_dir.join("full")).unwrap();
        fs::write(base_dir.join("full").join("a.txt"), b"a\n").unwrap();
        fs::create_dir_all(base_dir.join("empty")).unwrap();
        fs::write(base_dir.join("file.txt"), b"f\n").unwrap();

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let base = crate::folder::FolderMountSource::new(&base_dir).unwrap();
        let ov =
            WriteOverlay::new_for_tests(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();

        let err = ov.rmdir("/full").expect_err("non-empty base dir");
        assert!(
            err.to_string().contains("not empty"),
            "unexpected error: {err}"
        );
        let err = ov.rmdir("/file.txt").expect_err("file is not a dir");
        assert!(
            err.to_string().contains("not a directory"),
            "unexpected error: {err}"
        );
        let err = ov.rmdir("/missing").expect_err("missing path");
        assert!(
            err.to_string().contains("no such directory"),
            "unexpected error: {err}"
        );
        ov.rmdir("/empty").expect("empty dir rmdir");
        assert!(
            ov.lookup("/empty", 0).is_none(),
            "empty dir must be gone from the union view"
        );
        // Children of the refused dir are untouched.
        let fi = ov.lookup("/full/a.txt", 0).expect("child survives");
        assert_eq!(fi.size, 2);
    }

    /// Regression: rename must not modify the destination when the source
    /// COW fails — copy the source first.
    #[test]
    fn rename_keeps_destination_when_source_cow_fails() {
        struct FailOpenBase;
        impl MountSource for FailOpenBase {
            fn list(&self, _path: &str) -> Option<ListResult> {
                Some(ListResult::Infos(Default::default()))
            }
            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                if path == "/" {
                    return Some(create_root_file_info());
                }
                if path == "/src" {
                    return Some(FileInfo {
                        size: 5,
                        mtime: 0.0,
                        mode: ratarmount_core::S_IFREG | 0o644,
                        linkname: String::new(),
                        uid: 0,
                        gid: 0,
                        userdata: vec![],
                    });
                }
                None
            }
            fn open(
                &self,
                _: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "boom"))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov =
            WriteOverlay::new_for_tests(Arc::new(FailOpenBase) as Arc<dyn MountSource>, &overlay)
                .unwrap();
        let fd = ov.create_file("/dst", 0o644).unwrap();
        unsafe {
            libc::close(fd);
        }
        fs::write(overlay.join("dst"), b"precious\n").unwrap();

        let err = ov.rename("/src", "/dst").expect_err("source COW must fail");
        assert!(
            err.to_string().contains("boom"),
            "expected the COW error, got: {err}"
        );
        assert_eq!(
            fs::read(overlay.join("dst")).unwrap(),
            b"precious\n",
            "destination must survive a failed rename"
        );
        assert!(ov.lookup("/dst", 0).is_some(), "dst still listed");
    }

    #[test]
    fn live_commit_uncompressed_tar_add_replace_delete_no_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let old_payload = dir.path().join("old-expected.bin");
        fs::write(&old_payload, b"old-body\n").unwrap();
        let new_payload = dir.path().join("new-expected.bin");
        fs::write(&new_payload, b"new-body-unique\n").unwrap();
        let replaced_payload = dir.path().join("replaced-expected.bin");
        fs::write(&replaced_payload, b"replaced-body\n").unwrap();

        let tar = make_tiny_tar(
            dir.path(),
            &[
                ("old.txt", &fs::read(&old_payload).unwrap()),
                ("gone.txt", b"delete-me\n"),
                ("keep.txt", b"orig-keep\n"),
            ],
        );
        let _ = replaced_payload;

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let mut materialised = None;
        let base = ratarmount_formats_tar::SqliteIndexedTar::create_index(
            &tar,
            &tar,
            None,
            &opts,
            "test",
            &mut materialised,
        )
        .expect("index tar");
        let ov =
            WriteOverlay::new_for_tests(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();
        fs::write(overlay.join("new.txt"), fs::read(&new_payload).unwrap()).unwrap();
        fs::write(overlay.join("keep.txt"), b"replaced-body\n").unwrap();
        ov.unlink("/gone.txt").expect("mark gone deleted");

        match ov.commit_uncompressed_tar_atomic(&tar) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("commit_uncompressed_tar_atomic: {other:?}"),
        }

        let list = StdCommand::new("tar")
            .args(["-tf"])
            .arg(&tar)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&list.stdout);
        assert!(text.contains("new.txt"), "{text}");
        assert!(text.contains("old.txt"), "{text}");
        assert!(text.contains("keep.txt"), "{text}");
        assert!(
            !text.contains("gone.txt"),
            "deleted member still listed: {text}"
        );
        let new_count = text
            .lines()
            .filter(|l| l.trim_end_matches('/') == "new.txt")
            .count();
        assert_eq!(new_count, 1, "first commit must not duplicate: {text}");

        let extracted = dir.path().join("ex");
        fs::create_dir_all(&extracted).unwrap();
        assert!(StdCommand::new("tar")
            .args(["-xf"])
            .arg(&tar)
            .arg("-C")
            .arg(&extracted)
            .status()
            .unwrap()
            .success());
        assert!(
            fs::read(extracted.join("new.txt")).unwrap() == fs::read(&new_payload).unwrap(),
            "new.txt must cmp to overlay source file"
        );
        assert_eq!(
            fs::read(extracted.join("keep.txt")).unwrap(),
            b"replaced-body\n"
        );

        ov.reset_overlay_contents().expect("reset");
        assert!(!overlay.join("new.txt").exists());
        match ov.commit_uncompressed_tar_atomic(&tar) {
            Ok(false) => {}
            Ok(true) => panic!("second commit with empty overlay must be a no-op"),
            Err(e) => panic!("second commit: {e}"),
        }
        let list2 = StdCommand::new("tar")
            .args(["-tf"])
            .arg(&tar)
            .output()
            .unwrap();
        let text2 = String::from_utf8_lossy(&list2.stdout);
        let new_count2 = text2
            .lines()
            .filter(|l| l.trim_end_matches('/') == "new.txt")
            .count();
        assert_eq!(new_count2, 1, "second tick must not duplicate: {text2}");
    }

    /// Regression: GNU tar `--delete` without `--ignore-zeros` stops at the
    /// first TAR EOF and rewrites only the first complete archive, destroying
    /// later concatenated members (symptom: `second.txt` gone after deleting
    /// `first.txt` from `cat a.tar b.tar`).
    #[test]
    fn live_commit_uncompressed_tar_concatenated_delete_keeps_later_archive() {
        let dir = tempfile::tempdir().unwrap();
        let first = generated_payload("live-tar-first");
        let second = generated_payload("live-tar-second");
        let archive = dir.path().join("a.tar");
        let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
        combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
        fs::write(&archive, &combined).unwrap();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_uncompressed_tar_base(&archive, true), &overlay);
        ov.unlink("/first.txt")
            .expect("unlink first complete-TAR member");
        match ov.commit_live(&archive, |p| Ok(open_uncompressed_tar_base(p, true))) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("live commit concatenated delete: {other:?}"),
        }

        let src = open_uncompressed_tar_base(&archive, true);
        assert!(
            src.lookup("/first.txt", 0).is_none(),
            "deleted first-frame name must be gone"
        );
        assert_eq!(
            read_member(src.as_ref(), "/second.txt"),
            second,
            "later complete TAR must survive GNU tar --delete"
        );
    }

    /// Regression: offline `--commit-overlay` used the same GNU tar `--delete`
    /// without `--ignore-zeros`, so a first-frame delete dropped later
    /// concatenated archives (and later-frame deletes were "Not found").
    #[test]
    fn commit_overlay_uncompressed_tar_concatenated_delete_keeps_later_archive() {
        let dir = tempfile::tempdir().unwrap();
        let first = generated_payload("off-tar-first");
        let second = generated_payload("off-tar-second");
        let archive = dir.path().join("a.tar");
        let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
        combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
        fs::write(&archive, &combined).unwrap();
        let before = fs::read(&archive).unwrap();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_uncompressed_tar_base(&archive, true), &overlay);
        ov.unlink("/first.txt")
            .expect("unlink first complete-TAR member");
        drop(ov);

        match commit_overlay(&overlay, &archive, &yes_commit_opts()) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                // #73: offline uncompressed must not mutate the archive when GNU
                // tar `--delete` fails (Debian lseek EOVERFLOW). Soft-skip the
                // member asserts on broken hosts after checking fail-closed.
                assert_eq!(
                    fs::read(&archive).unwrap(),
                    before,
                    "offline uncompressed commit must leave archive unchanged on GNU tar delete failure"
                );
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("offline concatenated delete: {other:?}"),
        }

        let src = open_uncompressed_tar_base(&archive, true);
        assert!(
            src.lookup("/first.txt", 0).is_none(),
            "deleted first-frame name must be gone"
        );
        assert_eq!(
            read_member(src.as_ref(), "/second.txt"),
            second,
            "later complete TAR must survive offline GNU tar --delete"
        );
    }

    /// Regression: later-frame delete on a concatenated uncompressed TAR must
    /// apply (GNU tar without `--ignore-zeros` reported "Not found in archive",
    /// which persist filtered as success, and the member stayed on disk).
    #[test]
    fn commit_overlay_uncompressed_tar_concatenated_later_frame_delete() {
        let dir = tempfile::tempdir().unwrap();
        let first = generated_payload("off-tar-later-first");
        let second = generated_payload("off-tar-later-second");
        let archive = dir.path().join("a.tar");
        let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
        combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
        fs::write(&archive, &combined).unwrap();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_uncompressed_tar_base(&archive, true), &overlay);
        ov.unlink("/second.txt")
            .expect("unlink later complete-TAR member");
        drop(ov);

        match commit_overlay(&overlay, &archive, &yes_commit_opts()) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("offline later-frame delete: {other:?}"),
        }

        let src = open_uncompressed_tar_base(&archive, true);
        assert!(
            src.lookup("/second.txt", 0).is_none(),
            "later-frame name must be gone after offline commit"
        );
        assert_eq!(read_member(src.as_ref(), "/first.txt"), first);
    }

    /// Regression: `BzDecoder` (not multi) dropped later bzip2 streams
    /// during `--commit-overlay` materialize. Symptom: `second.txt` gone
    /// after deleting `first.txt` from `cat a.tar.bz2 b.tar.bz2`.
    #[test]
    fn commit_overlay_tar_bz2_concatenated_delete_keeps_later_archive() {
        let dir = tempfile::tempdir().unwrap();
        let first = generated_payload("off-bz2-del-first");
        let second = generated_payload("off-bz2-del-second");
        let archive = dir.path().join("a.tar.bz2");
        write_concatenated_tar_bz2(
            &archive,
            &[ustar_file("first.txt", &first)],
            &[ustar_file("second.txt", &second)],
        );

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_bz2_base(&archive, true), &overlay);
        ov.unlink("/first.txt")
            .expect("unlink first complete-TAR member");
        drop(ov);

        match commit_overlay(&overlay, &archive, &yes_commit_opts()) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("offline concatenated tar.bz2 delete: {other:?}"),
        }

        let src = open_tar_bz2_base(&archive, true);
        assert!(
            src.lookup("/first.txt", 0).is_none(),
            "deleted first-stream name must be gone"
        );
        assert_eq!(
            read_member(src.as_ref(), "/second.txt"),
            second,
            "later bzip2 stream must survive offline GNU tar --delete"
        );
    }

    /// Regression: `XzDecoder::new` (not multi) dropped later xz streams
    /// during `--commit-overlay` materialize. Symptom: `second.txt` gone
    /// after deleting `first.txt` from `cat a.tar.xz b.tar.xz`.
    #[test]
    fn commit_overlay_tar_xz_concatenated_delete_keeps_later_archive() {
        let dir = tempfile::tempdir().unwrap();
        let first = generated_payload("off-xz-del-first");
        let second = generated_payload("off-xz-del-second");
        let archive = dir.path().join("a.tar.xz");
        write_concatenated_tar_xz(
            &archive,
            &[ustar_file("first.txt", &first)],
            &[ustar_file("second.txt", &second)],
        );

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_xz_base(&archive, true), &overlay);
        ov.unlink("/first.txt")
            .expect("unlink first complete-TAR member");
        drop(ov);

        match commit_overlay(&overlay, &archive, &yes_commit_opts()) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("offline concatenated tar.xz delete: {other:?}"),
        }

        let src = open_tar_xz_base(&archive, true);
        assert!(
            src.lookup("/first.txt", 0).is_none(),
            "deleted first-stream name must be gone"
        );
        assert_eq!(
            read_member(src.as_ref(), "/second.txt"),
            second,
            "later xz stream must survive offline GNU tar --delete"
        );
    }

    /// Base that lists `gone.txt` but strips TAR userdata (AutoMount nested
    /// archive, foreign sidecar, or any wrapper that hides `offsetheader`).
    struct NoTarOffsetheaderBase;

    impl MountSource for NoTarOffsetheaderBase {
        fn list(&self, _path: &str) -> Option<ListResult> {
            Some(ListResult::Infos(Default::default()))
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(create_root_file_info());
            }
            if path == "/gone.txt" || path == "gone.txt" {
                return Some(FileInfo {
                    size: 9,
                    mtime: 0.0,
                    mode: ratarmount_core::S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                });
            }
            None
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "no-tar-oh base"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    struct TarOffsetheaderBase {
        gone_oh: u64,
    }

    impl MountSource for TarOffsetheaderBase {
        fn list(&self, _path: &str) -> Option<ListResult> {
            Some(ListResult::Infos(Default::default()))
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(create_root_file_info());
            }
            if path == "/gone.txt" || path == "gone.txt" {
                return Some(tar_fi_at(self.gone_oh));
            }
            None
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "tar-oh base"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    fn two_member_tar(dir: &Path) -> (PathBuf, u64, u64) {
        let keep = b"keep-body";
        let gone = b"gone-body";
        let bytes = pack_tar(&[ustar_file("keep.txt", keep), ustar_file("gone.txt", gone)]);
        let archive = dir.join("a.tar");
        fs::write(&archive, &bytes).unwrap();
        let eof = {
            let mut f = File::open(&archive).unwrap();
            find_last_tar_eof(&mut f, 0).unwrap().unwrap_or(0)
        };
        let gone_oh = 512 + pad512_for_test(keep.len() as u64);
        (archive, eof, gone_oh)
    }

    fn pad512_for_test(n: u64) -> u64 {
        n.div_ceil(512) * 512
    }

    /// Regression: unclassified delete + append must not patch from EOF only.
    ///
    /// Symptom: AutoMount (or any wrapper that hides TAR userdata) made
    /// `min_deleted_offsetheader` skip a real archive delete; the append
    /// branch then set `window_start = EOF`. GNU tar `--delete` still
    /// removed the member, so the sidecar kept a ghost row.
    #[test]
    fn regression_unclassified_delete_plus_append_does_not_patch_from_eof() {
        let dir = tempfile::tempdir().unwrap();
        let (archive, eof, gone_oh) = two_member_tar(dir.path());
        assert!(gone_oh > 0 && gone_oh < eof, "gone_oh={gone_oh} eof={eof}");

        let plan = OverlayCommitPlan {
            known_hashes: BTreeMap::new(),
            written_hashes: BTreeMap::new(),
            metadata: BTreeMap::new(),
            xattrs: BTreeMap::new(),
            deletions_nul: Vec::new(),
            appends_nul: Vec::new(),
            deleted_paths: ["gone.txt".into()].into_iter().collect(),
            append_entries: vec![("new.txt".into(), false)],
        };
        let window =
            uncompressed_patch_window(&archive, &NoTarOffsetheaderBase, &plan).expect("window");
        assert!(
            window.offsets_shifted,
            "unclassified archive delete must force a suffix rewrite"
        );
        assert_eq!(
            window.window_start, 0,
            "must full-reparse, not EOF {eof} (gone lived at {gone_oh})"
        );
        assert_ne!(
            window.window_start, eof,
            "EOF-only patch would leave gone.txt in the sidecar"
        );
    }

    #[test]
    fn classified_delete_plus_append_still_starts_at_min_offsetheader() {
        let dir = tempfile::tempdir().unwrap();
        let (archive, eof, gone_oh) = two_member_tar(dir.path());
        let plan = OverlayCommitPlan {
            known_hashes: BTreeMap::new(),
            written_hashes: BTreeMap::new(),
            metadata: BTreeMap::new(),
            xattrs: BTreeMap::new(),
            deletions_nul: Vec::new(),
            appends_nul: Vec::new(),
            deleted_paths: ["gone.txt".into()].into_iter().collect(),
            append_entries: vec![("new.txt".into(), false)],
        };
        let window = uncompressed_patch_window(&archive, &TarOffsetheaderBase { gone_oh }, &plan)
            .expect("window");
        assert!(window.offsets_shifted);
        assert_eq!(window.window_start, gone_oh);
        assert_ne!(window.window_start, eof);
        assert_ne!(window.window_start, 0);
    }

    #[test]
    fn overlay_only_replace_plus_append_still_starts_at_eof() {
        let dir = tempfile::tempdir().unwrap();
        let (archive, eof, _) = two_member_tar(dir.path());
        let plan = OverlayCommitPlan {
            known_hashes: BTreeMap::new(),
            written_hashes: BTreeMap::new(),
            metadata: BTreeMap::new(),
            xattrs: BTreeMap::new(),
            deletions_nul: Vec::new(),
            appends_nul: Vec::new(),
            deleted_paths: ["brand-new.txt".into()].into_iter().collect(),
            append_entries: vec![("brand-new.txt".into(), false)],
        };
        let window =
            uncompressed_patch_window(&archive, &NoTarOffsetheaderBase, &plan).expect("window");
        assert!(!window.offsets_shifted);
        assert_eq!(
            window.window_start, eof,
            "overlay-only add must still patch from pre-append EOF"
        );
    }

    /// Regression: GNU `tar --append` patch window is `find_last_tar_eof`, not
    /// `metadata().len()` (EOF padding would skip the new members).
    #[test]
    fn live_commit_gnu_append_window_is_eof_not_len() {
        let dir = tempfile::tempdir().unwrap();
        let tar = make_tiny_tar(dir.path(), &[("old.txt", b"keep\n")]);
        let file_len = fs::metadata(&tar).unwrap().len();
        let eof = {
            let mut f = File::open(&tar).unwrap();
            find_last_tar_eof(&mut f, 0).unwrap().unwrap_or(0)
        };
        assert!(
            eof < file_len,
            "GNU tar pads past the two-zero EOF: eof={eof} len={file_len}"
        );

        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let mut materialised = None;
        let base = ratarmount_formats_tar::SqliteIndexedTar::create_index(
            &tar,
            &tar,
            None,
            &opts,
            "test",
            &mut materialised,
        )
        .expect("index tar");
        let ov =
            WriteOverlay::new_for_tests(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();
        fs::write(overlay.join("new.txt"), b"appended\n").unwrap();
        match ov.commit_atomic(&tar) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("commit_atomic: {other:?}"),
        }
        let window = ov.last_patch_window().expect("stashed window");
        assert_eq!(
            window.window_start, eof,
            "window_start must be last TAR EOF, not file len {file_len}"
        );
        assert!(!window.offsets_shifted);
        assert!(window.from_frame.is_none());
    }

    #[test]
    fn live_commit_rejects_gzip_and_zip() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("t");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a"), b"x").unwrap();
        let tgz = dir.path().join("a.tar.gz");
        let st = StdCommand::new("tar")
            .args(["-czf"])
            .arg(&tgz)
            .arg("-C")
            .arg(&src)
            .arg("a")
            .status()
            .unwrap();
        assert!(st.success());
        let err = live_commit_is_supported(&tgz).unwrap_err().to_string();
        assert!(err.contains("uncompressed"), "{err}");
        assert!(err.contains("gzip"), "{err}");

        let zip = dir.path().join("a.zip");
        write_sample_zip(&zip, &[("a", b"x", CompressionMethod::Stored)]);
        let err = live_commit_is_supported(&zip).unwrap_err().to_string();
        assert!(
            err.contains("ZIP") || err.contains("uncompressed TAR"),
            "{err}"
        );
    }

    pub(crate) fn generated_payload(tag: &str) -> Vec<u8> {
        format!("p-{tag}-{}\n", std::process::id()).into_bytes()
    }

    /// Regression: add-only xattrs must use append and manifests must retain
    /// pre-patch index hashes while hashing newly committed payloads.
    #[test]
    fn regression_provenance_append_manifest_reuses_index_hash() {
        for compressed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join(if compressed {
                "base.tar.zst"
            } else {
                "base.tar"
            });
            let (prefix, _) = append_fixture(&archive, compressed);
            let sidecar = append_index(&archive, compressed);
            let expected = ratarmount_index::sha256_hex_stream(&mut &prefix[..]).unwrap();
            {
                let idx = SqliteIndex::open_writable(&sidecar).unwrap();
                let fi = idx.lookup("/prefix", 0).unwrap().unwrap();
                idx.insert_xattr(
                    tar_offsetheaders_in(&fi).next().unwrap() as i64,
                    "user.hash.sha256",
                    expected.as_bytes(),
                )
                .unwrap();
            }
            let root = dir.path().join("ov");
            let ov = WriteOverlay::new_for_tests(
                Arc::new(provenance_base(&archive, "utf-8").unwrap()),
                &root,
            )
            .unwrap();
            let fd = ov.create_file("/new", 0o644).unwrap();
            ov.close_overlay_fd(fd);
            fs::write(root.join("new"), b"new payload").unwrap();
            ov.set_xattr("/new", "user.teacher", b"teacher", 0).unwrap();
            drop(ov);
            #[cfg(unix)]
            let inode = {
                use std::os::unix::fs::MetadataExt;
                fs::metadata(&archive).unwrap().ino()
            };
            let opts = CommitOverlayOptions {
                yes: true,
                debug: 0,
                mode: CommitMode::Append,
                manifest_hashes: Some("new".into()),
                ..Default::default()
            };
            assert!(commit_overlay(&root, &archive, &opts).unwrap());
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(fs::metadata(&archive).unwrap().ino(), inode);
            }
            let manifest =
                fs::read_to_string(format!("{}.manifest.jsonl", archive.display())).unwrap();
            let rows: BTreeMap<String, serde_json::Value> = manifest
                .lines()
                .map(|line| {
                    let row: serde_json::Value = serde_json::from_str(line).unwrap();
                    (row["path"].as_str().unwrap().into(), row)
                })
                .collect();
            assert_eq!(rows["prefix"]["sha256"], expected);
            assert_eq!(
                rows["new"]["sha256"],
                ratarmount_index::sha256_hex_stream(&mut &b"new payload"[..]).unwrap()
            );
            assert!(rows["last"]["sha256"].is_null());
            let base = append_warm_open(&archive, compressed, &sidecar);
            let fi = base.lookup("/new", 0).unwrap();
            assert_eq!(
                base.get_xattr(&fi, "user.teacher"),
                Some(b"teacher".to_vec())
            );
        }
    }

    /// Regression: offline manifest commits rejected overlays below symlinked parents (/var on macOS).
    #[cfg(unix)]
    #[test]
    fn regression_provenance_manifest_symlinked_overlay_parent() {
        for compressed in [false, true] {
            for mode in [CommitMode::Copy, CommitMode::Append] {
                for xattrs in [false, true] {
                    let dir = tempfile::tempdir().unwrap();
                    let real = dir.path().join("real");
                    fs::create_dir(&real).unwrap();
                    let alias = dir.path().join("alias");
                    std::os::unix::fs::symlink(&real, &alias).unwrap();
                    let archive = dir.path().join(if compressed {
                        "base.tar.zst"
                    } else {
                        "base.tar"
                    });
                    append_fixture(&archive, compressed);
                    let root = alias.join("ov");
                    let ov = WriteOverlay::new_for_tests(
                        Arc::new(provenance_base(&archive, "utf-8").unwrap()),
                        &root,
                    )
                    .unwrap();
                    assert_eq!(ov.root, real.join("ov").canonicalize().unwrap());
                    put_overlay_bytes(&ov, "/new", b"new payload");
                    if xattrs {
                        ov.set_xattr("/new", "user.teacher", b"teacher", 0).unwrap();
                    }
                    drop(ov);
                    assert!(commit_overlay(
                        &root,
                        &archive,
                        &CommitOverlayOptions {
                            yes: true,
                            mode,
                            manifest_hashes: Some("new".into()),
                            ..Default::default()
                        }
                    )
                    .unwrap());
                    let base = provenance_base(&archive, "utf-8").unwrap();
                    let fi = base.lookup("/new", 0).unwrap();
                    assert_eq!(base.read(&fi, 100, 0).unwrap(), b"new payload");
                    assert_eq!(
                        base.get_xattr(&fi, "user.teacher"),
                        xattrs.then(|| b"teacher".to_vec())
                    );
                    let manifest =
                        fs::read_to_string(format!("{}.manifest.jsonl", archive.display()))
                            .unwrap();
                    assert!(manifest.contains(
                        &ratarmount_index::sha256_hex_stream(&mut &b"new payload"[..]).unwrap()
                    ));
                }
            }
        }
    }

    /// Regression: queued renames must carry provenance through intermediate names
    /// even while the host rename has completed and SQLite replay still fails.
    #[test]
    fn regression_provenance_queued_rename_keeps_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        provenance_fixture(&archive, false);
        let ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            dir.path().join("ov"),
        )
        .unwrap();
        ov.set_xattr("/trace", "user.train_ok", b"false", 0)
            .unwrap();
        ov.set_rename_tx_failures(100);
        ov.rename("/trace", "/x").unwrap();
        assert_eq!(ov.xattrs_for_path("/x").unwrap()["user.train_ok"], b"false");
        ov.rename("/x", "/y").unwrap();
        assert_eq!(ov.xattrs_for_path("/y").unwrap()["user.teacher"], b"old");
        ov.set_rename_tx_failures(0);
        ov.replay_pending_rows().unwrap();
        assert_eq!(ov.xattrs_for_path("/y").unwrap()["user.train_ok"], b"false");
        assert!(ov.lookup("/x", 0).is_none());
    }

    /// Regression: manifest-only commits must hash payloads in the shared writer
    /// even when there are no xattrs to trigger the provenance replacement path.
    #[test]
    fn regression_provenance_manifest_without_xattrs() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        fs::write(&archive, pack_tar(&[ustar_file("old", b"old")])).unwrap();
        let root = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        put_overlay_bytes(&ov, "/new", b"new payload");
        drop(ov);
        let mut plan = collect_overlay_commit_plan(&root).unwrap();
        assert!(!plan.has_metadata_changes());
        let mut hashes = BTreeMap::new();
        persist_provenance_plan(
            &archive,
            &root,
            &plan,
            "utf-8",
            CommitMode::Copy,
            Some(&mut hashes),
            &crate::journal_recovery::Rows::None,
            &fs::metadata(&archive).unwrap(),
        )
        .unwrap();
        let expected = ratarmount_index::sha256_hex_stream(&mut &b"new payload"[..]).unwrap();
        assert_eq!(hashes.get("/new"), Some(&expected));
        plan.written_hashes = hashes;
        write_commit_manifest(&archive, &plan, "utf-8", "new").unwrap();
        let manifest = fs::read_to_string(format!("{}.manifest.jsonl", archive.display())).unwrap();
        assert!(manifest.contains(&expected));
        let reopened = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        reopened.set_xattr("/new", "user.empty", b"", 1).unwrap();
        assert_eq!(reopened.xattrs_for_path("/new").unwrap()["user.empty"], b"");
    }

    fn provenance_fixture(path: &Path, compressed: bool) {
        let attrs = vec![
            ("user.teacher".into(), b"old".to_vec()),
            ("user.binary".into(), vec![0xff, 0, b'\n', b'=']),
        ];
        let mut member = ustar_file("trace", b"training payload");
        member.xattrs = &attrs;
        if compressed {
            write_single_frame_tar_zst(path, &[member]);
        } else {
            fs::write(path, pack_tar(&[member])).unwrap();
        }
    }

    /// Regression: chmod/utimens must not copy archive bytes, and mode/mtime
    /// must survive reopen and TAR commit for both archive and overlay files.
    #[test]
    fn regression_overlay_chmod_metadata_only_reopen_commit() {
        for compressed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join(if compressed {
                "base.tar.zst"
            } else {
                "base.tar"
            });
            provenance_fixture(&archive, compressed);
            let root = dir.path().join("overlay");
            let base = Arc::new(provenance_base(&archive, "utf-8").unwrap());
            let ov = WriteOverlay::new_for_tests(base.clone(), &root).unwrap();
            let fd = ov.create_file("/built", 0o600).unwrap();
            ov.close_overlay_fd(fd);
            let attrs = OverlayMetadata {
                mode: Some(0o751),
                atime: Some(1234.25),
                mtime: Some(5678.5),
                ..Default::default()
            };
            for path in ["/trace", "/built"] {
                ov.set_metadata(path, &attrs).unwrap();
                let fi = ov.lookup(path, 0).unwrap();
                assert_eq!(fi.mode & 0o7777, 0o751);
                assert_eq!(fi.mtime, 5678.5);
                assert_eq!(overlay_atime(&fi), 1234.25);
            }
            assert!(!root.join("trace").exists(), "chmod copied archive payload");
            assert_eq!(read_member(&ov, "/trace"), b"training payload");
            let modes: Vec<_> = ov
                .list_dirents("/")
                .unwrap()
                .into_iter()
                .map(|d| d.mode & 0o7777)
                .collect();
            assert_eq!(modes, [0o751, 0o751]);
            drop(ov);
            let ov = WriteOverlay::new_for_tests(base, &root).unwrap();
            assert_eq!(ov.lookup("/trace", 0).unwrap().mode & 0o7777, 0o751);
            assert_eq!(overlay_atime(&ov.lookup("/trace", 0).unwrap()), 1234.25);
            // Omitted timestamps are unchanged by a later chmod.
            ov.set_metadata(
                "/trace",
                &OverlayMetadata {
                    mode: Some(0o755),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(ov.lookup("/trace", 0).unwrap().mtime, 5678.5);
            assert!(ov
                .commit_live(&archive, |p| Ok(Arc::new(provenance_base(p, "utf-8")?)))
                .unwrap());
            assert!(ov.metadata_for_path("/trace").is_none());
            let committed = provenance_base(&archive, "utf-8").unwrap();
            assert_eq!(committed.lookup("/trace", 0).unwrap().mode & 0o7777, 0o755);
            assert_eq!(committed.lookup("/built", 0).unwrap().mode & 0o7777, 0o751);
            assert_eq!(committed.lookup("/trace", 0).unwrap().mtime, 5678.0);
            assert_eq!(read_member(&committed, "/trace"), b"training payload");
        }
    }

    /// Regression: a nested archive-only chmod must not require materialized
    /// parent directories; creation modes must not be masked by the daemon.
    #[test]
    fn regression_overlay_chmod_nested_and_create_modes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        fs::write(&archive, pack_tar(&[ustar_file("sub/script", b"payload")])).unwrap();
        let root = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        ov.set_metadata(
            "/sub/script",
            &OverlayMetadata {
                mode: Some(0o755),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!root.join("sub").exists());
        assert_eq!(read_member(&ov, "/sub/script"), b"payload");
        ov.set_metadata(
            "/",
            &OverlayMetadata {
                mode: Some(0o751),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(ov.lookup("/", 0).unwrap().mode & 0o7777, 0o751);
        let fd = ov
            .open_overlay_fd_with_mode("/built", libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o777)
            .unwrap();
        ov.close_overlay_fd(fd);
        assert_eq!(ov.lookup("/built", 0).unwrap().mode & 0o7777, 0o777);
        assert!(ov
            .open_overlay_fd_with_mode("/built", libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600)
            .is_err());
        ov.mkdir("/dir", 0o777).unwrap();
        let fd = ov.create_file("/dir/child", 0o751).unwrap();
        ov.close_overlay_fd(fd);
        ov.set_metadata(
            "/dir",
            &OverlayMetadata {
                mode: Some(0o750),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(ov
            .commit_live(&archive, |p| Ok(Arc::new(provenance_base(p, "utf-8")?)))
            .unwrap());
        assert_eq!(ov.lookup("/sub/script", 0).unwrap().mode & 0o7777, 0o755);
        assert_eq!(ov.lookup("/dir", 0).unwrap().mode & 0o7777, 0o750);
    }

    /// Regression: a combined truncate/touch must keep the requested mtime;
    /// failed chown must not truncate and chmod must never follow a host symlink.
    #[test]
    fn regression_overlay_chmod_setattr_order_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        fs::write(
            &archive,
            pack_tar(&[
                ustar_file("trace", b"training payload"),
                ustar_symlink("archive-link", "trace"),
            ]),
        )
        .unwrap();
        let root = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        ov.set_metadata(
            "/archive-link",
            &OverlayMetadata {
                mtime: Some(1234.5),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!root.join("archive-link").exists());
        ov.rename("/archive-link", "/moved-link").unwrap();
        assert_eq!(ov.lookup("/moved-link", 0).unwrap().mtime, 1234.5);
        assert!(ov
            .set_attributes(
                "/trace",
                Some(0),
                &OverlayMetadata {
                    uid: Some(123),
                    ..Default::default()
                }
            )
            .is_err());
        assert_eq!(ov.lookup("/trace", 0).unwrap().size, 16);
        ov.set_attributes(
            "/trace",
            Some(3),
            &OverlayMetadata {
                mode: Some(0o755),
                mtime: Some(42.5),
                ..Default::default()
            },
        )
        .unwrap();
        let fi = ov.lookup("/trace", 0).unwrap();
        assert_eq!(fi.size, 3);
        assert_eq!(fi.mtime, 42.5);
        assert_eq!(fi.mode & 0o7777, 0o755);
        ov.create_symlink("/link", "trace").unwrap();
        assert!(ov
            .set_metadata(
                "/link",
                &OverlayMetadata {
                    mode: Some(0o600),
                    ..Default::default()
                }
            )
            .is_err());
        assert_eq!(ov.lookup("/trace", 0).unwrap().mode & 0o7777, 0o755);
    }

    /// Regression: metadata-only chmod is included in offline commit plans.
    #[test]
    fn regression_overlay_chmod_offline_commit() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        provenance_fixture(&archive, false);
        let root = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        ov.set_metadata(
            "/trace",
            &OverlayMetadata {
                mode: Some(0o755),
                ..Default::default()
            },
        )
        .unwrap();
        drop(ov);
        assert!(commit_overlay(
            &root,
            &archive,
            &CommitOverlayOptions {
                yes: true,
                ..Default::default()
            }
        )
        .unwrap());
        assert_eq!(
            provenance_base(&archive, "utf-8")
                .unwrap()
                .lookup("/trace", 0)
                .unwrap()
                .mode
                & 0o7777,
            0o755
        );
    }

    /// Regression: COW, rename and recreation must preserve or discard the
    /// correct inode's mode rather than resurrect metadata from an old name.
    #[test]
    fn regression_overlay_chmod_copy_up_rename_recreate() {
        for policy in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("base.tar");
            provenance_fixture(&archive, false);
            let root = dir.path().join("ov");
            let mut ov = WriteOverlay::new_for_tests(
                Arc::new(provenance_base(&archive, "utf-8").unwrap()),
                &root,
            )
            .unwrap();
            if policy {
                ov.set_policy(Some(Arc::new(CountingPolicy::new(u64::MAX))));
            }
            ov.set_metadata(
                "/trace",
                &OverlayMetadata {
                    mode: Some(0o751),
                    mtime: Some(1234.0),
                    ..Default::default()
                },
            )
            .unwrap();
            let fd = ov.open_overlay_fd("/trace", libc::O_RDWR).unwrap();
            ov.close_overlay_fd(fd);
            assert_eq!(ov.lookup("/trace", 0).unwrap().mode & 0o7777, 0o751);
            assert_eq!(ov.lookup("/trace", 0).unwrap().mtime, 1234.0);
            let fd = ov.create_file("/moved", 0o600).unwrap();
            ov.close_overlay_fd(fd);
            ov.rename("/trace", "/moved").unwrap();
            let mode: u32 = ov
                .db
                .lock()
                .unwrap()
                .query_row("SELECT mode FROM files WHERE name='moved'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(mode & 0o7777, 0o751);
            assert_eq!(ov.lookup("/moved", 0).unwrap().mode & 0o7777, 0o751);
            ov.unlink("/moved").unwrap();
            let fd = ov.create_file("/moved", 0o640).unwrap();
            ov.close_overlay_fd(fd);
            assert_eq!(ov.lookup("/moved", 0).unwrap().mode & 0o7777, 0o640);
            assert!(ov.metadata_for_path("/moved").is_none());
        }
    }

    /// Regression: chmod and utimens must obey read-only globs; chown and
    /// invalid times fail explicitly instead of reporting a successful no-op.
    #[test]
    fn regression_overlay_chmod_readonly_and_chown() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        provenance_fixture(&archive, false);
        let mut ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            dir.path().join("ov"),
        )
        .unwrap();
        let fd = ov.create_file("/host", 0o644).unwrap();
        ov.close_overlay_fd(fd);
        let err = ov
            .set_metadata(
                "/host",
                &OverlayMetadata {
                    uid: Some(123),
                    mode: Some(0o777),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, OverlayError::Io(e) if e.raw_os_error() == Some(libc::EPERM)));
        assert_eq!(ov.lookup("/host", 0).unwrap().mode & 0o7777, 0o644);
        assert!(ov
            .set_metadata(
                "/host",
                &OverlayMetadata {
                    mtime: Some(f64::NAN),
                    ..Default::default()
                }
            )
            .is_err());
        ov.set_policy(Some(Arc::new(
            crate::overlay_policy::ReadOnlyGlobs::new(["trace", "host"]).unwrap(),
        )));
        for path in ["/trace", "/host"] {
            for attrs in [
                OverlayMetadata {
                    mode: Some(0o755),
                    ..Default::default()
                },
                OverlayMetadata {
                    mtime: Some(10.0),
                    ..Default::default()
                },
            ] {
                let err = ov.set_metadata(path, &attrs).unwrap_err();
                assert!(
                    matches!(err, OverlayError::Io(e) if e.kind() == io::ErrorKind::ReadOnlyFilesystem)
                );
            }
        }
    }

    /// Regression: xattr-only edits must not copy archive payloads, lose binary
    /// values, ignore create/replace flags, or bypass read-only policy.
    #[test]
    fn regression_provenance_metadata_only_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        provenance_fixture(&archive, false);
        let base = Arc::new(provenance_base(&archive, "utf-8").unwrap());
        let mut ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
        let error = |r: Result<()>| match r.unwrap_err() {
            OverlayError::Io(e) => e.raw_os_error().unwrap_or_else(|| {
                assert_eq!(e.kind(), io::ErrorKind::ReadOnlyFilesystem);
                libc::EROFS
            }),
            e => panic!("{e}"),
        };
        assert_eq!(
            error(ov.set_xattr("/trace", "user.teacher", b"x", 1)),
            libc::EEXIST
        );
        assert_eq!(
            error(ov.set_xattr("/trace", "user.absent", b"x", 2)),
            missing_xattr_errno()
        );
        assert_eq!(
            error(ov.set_xattr("/trace", "security.label", b"x", 0)),
            libc::EPERM
        );
        assert_eq!(
            error(ov.set_xattr("/trace", "user.x", b"x", 3)),
            libc::EINVAL
        );
        assert_eq!(
            error(ov.set_xattr("/trace", "user.x", &vec![0; 65537], 0)),
            libc::E2BIG
        );
        ov.set_xattr("/trace", "user.teacher", b"new", 2).unwrap();
        ov.set_xattr("/trace", "user.train_ok", b"false", 1)
            .unwrap();
        ov.remove_xattr("/trace", "user.binary").unwrap();
        assert_eq!(
            error(ov.remove_xattr("/trace", "user.binary")),
            missing_xattr_errno()
        );
        let fi = ov.lookup("/trace", 0).unwrap();
        assert_eq!(ov.get_xattr(&fi, "user.teacher"), Some(b"new".to_vec()));
        assert_eq!(ov.list_xattr(&fi), ["user.teacher", "user.train_ok"]);
        assert_eq!(read_member(&ov, "/trace"), b"training payload");
        assert!(!ov.has_file("/trace"));
        for name in ["a", "b", "c"] {
            ov.set_xattr("/trace", &format!("user.{name}"), &vec![0; 65536], 0)
                .unwrap();
        }
        assert_eq!(
            error(ov.set_xattr("/trace", "user.d", &vec![0; 65536], 0)),
            libc::E2BIG
        );
        ov.set_policy(Some(Arc::new(
            crate::ReadOnlyGlobs::new(["trace"]).unwrap(),
        )));
        assert_eq!(
            error(ov.set_xattr("/trace", "user.teacher", b"blocked", 0)),
            libc::EROFS
        );
        assert_eq!(
            error(ov.remove_xattr("/trace", "user.teacher")),
            libc::EROFS
        );
    }

    /// Regression: opening a legacy overlay adds xattrs without losing deletion rows.
    #[test]
    fn regression_provenance_migration_preserves_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        provenance_fixture(&archive, false);
        let root = dir.path().join("ov");
        let base = Arc::new(provenance_base(&archive, "utf-8").unwrap());
        {
            let ov = WriteOverlay::new_for_tests(base.clone(), &root).unwrap();
            ov.unlink("/trace").unwrap();
        }
        {
            let db = Connection::open(root.join(HIDDEN_DB)).unwrap();
            db.execute("DROP TABLE xattrs", []).unwrap();
        }
        let ov = WriteOverlay::new_for_tests(base, &root).unwrap();
        assert!(ov.lookup("/trace", 0).is_none());
        assert!(root.join(OVERLAY_MARKER).exists());
        let fd = ov.create_file("/new", 0o644).unwrap();
        ov.close_overlay_fd(fd);
        ov.set_xattr("/new", "user.test", b"yes", 0).unwrap();
        drop(ov);
        let ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        assert_eq!(ov.xattrs_for_path("/new").unwrap()["user.test"], b"yes");
        assert!(ov.is_deleted("/trace"));
    }

    /// Regression: metadata-only replacement must survive copy/append-fallback,
    /// suffix reindex, remount, and binary PAX decoding for TAR and tar.zst.
    #[test]
    fn regression_provenance_commit_roundtrip_and_manifest() {
        for compressed in [false, true] {
            for mode in [CommitMode::Copy, CommitMode::Append] {
                let dir = tempfile::tempdir().unwrap();
                let archive = dir.path().join(if compressed {
                    "base.tar.zst"
                } else {
                    "base.tar"
                });
                provenance_fixture(&archive, compressed);
                let sidecar = append_index(&archive, compressed);
                let root = dir.path().join("ov");
                let ov = WriteOverlay::new_for_tests(
                    Arc::new(provenance_base(&archive, "utf-8").unwrap()),
                    &root,
                )
                .unwrap();
                ov.set_xattr("/trace", "user.train_ok", b"false", 0)
                    .unwrap();
                ov.remove_xattr("/trace", "user.teacher").unwrap();
                assert!(!root.join("trace").exists());
                drop(ov);
                let opts = CommitOverlayOptions {
                    mode,
                    yes: true,
                    debug: 0,
                    manifest_hashes: Some("all".into()),
                    ..Default::default()
                };
                assert!(commit_overlay(&root, &archive, &opts).unwrap());
                let base = append_warm_open(&archive, compressed, &sidecar);
                let fi = base.lookup("/trace", 0).unwrap();
                assert_eq!(
                    base.get_xattr(&fi, "user.train_ok"),
                    Some(b"false".to_vec())
                );
                assert_eq!(
                    base.get_xattr(&fi, "user.binary"),
                    Some(vec![0xff, 0, b'\n', b'='])
                );
                assert_eq!(base.get_xattr(&fi, "user.teacher"), None);
                assert_eq!(read_member(base.as_ref(), "/trace"), b"training payload");
                let manifest = PathBuf::from(format!("{}.manifest.jsonl", archive.display()));
                let rows: Vec<serde_json::Value> = fs::read_to_string(&manifest)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["path"], "trace");
                assert_eq!(rows[0]["size"], 16);
                assert_eq!(
                    rows[0]["sha256"],
                    ratarmount_index::sha256_hex_stream(&mut &b"training payload"[..]).unwrap()
                );
                assert_eq!(
                    rows[0]["xattrs"]["user.binary"],
                    serde_json::json!([255, 0, 10, 61])
                );
                let old = fs::read(&manifest).unwrap();
                let plan = collect_overlay_commit_plan(&root).unwrap();
                assert!(write_commit_manifest(&archive, &plan, "utf-8", "invalid").is_err());
                assert_eq!(fs::read(&manifest).unwrap(), old);
                FAIL_MANIFEST_PUBLISH.set(true);
                assert!(write_commit_manifest(&archive, &plan, "utf-8", "all").is_err());
                assert_eq!(fs::read(&manifest).unwrap(), old);
                write_commit_manifest(&archive, &plan, "utf-8", "none").unwrap();
                let next: serde_json::Value =
                    serde_json::from_str(fs::read_to_string(&manifest).unwrap().trim()).unwrap();
                assert!(next["sha256"].is_null());
                assert!(next["commit_id"].as_u64() > rows[0]["commit_id"].as_u64());
            }
        }
    }

    /// Regression: live cleanup must forget only committed xattr rows and leave
    /// the archive serving the new metadata and unchanged payload bytes.
    #[test]
    fn regression_provenance_live_cleanup_and_rename() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar.zst");
        provenance_fixture(&archive, true);
        let root = dir.path().join("ov");
        let mut ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        ov.set_manifest_hashes(Some("new".into()));
        ov.set_xattr("/trace", "user.train_ok", b"false", 0)
            .unwrap();
        assert!(ov
            .commit_live(&archive, |p| Ok(Arc::new(provenance_base(p, "utf-8")?)))
            .unwrap());
        assert!(collect_overlay_commit_plan_from_conn(
            &root,
            Some(&ov.db.lock().unwrap()),
            None,
            &HashSet::new()
        )
        .unwrap()
        .is_empty());
        assert_eq!(
            ov.xattrs_for_path("/trace").unwrap()["user.train_ok"],
            b"false"
        );
        ov.rename("/trace", "/moved").unwrap();
        assert_eq!(
            ov.xattrs_for_path("/moved").unwrap()["user.teacher"],
            b"old"
        );
        ov.unlink("/moved").unwrap();
        let fd = ov.create_file("/moved", 0o644).unwrap();
        ov.close_overlay_fd(fd);
        assert!(ov.xattrs_for_path("/moved").unwrap().is_empty());
    }

    pub(crate) fn ustar_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            xattrs: &[],
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn ustar_symlink<'a>(path: &'a str, target: &'a str) -> UstarMember<'a> {
        UstarMember {
            xattrs: &[],
            path,
            payload: UstarPayload::Symlink { target },
            mode: 0o777,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn pack_tar(members: &[UstarMember<'_>]) -> Vec<u8> {
        let mut buf = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut buf, members).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut buf).unwrap();
        buf
    }

    fn pack_tar_no_eof(members: &[UstarMember<'_>]) -> Vec<u8> {
        let mut buf = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut buf, members).unwrap();
        buf
    }

    pub(crate) fn concat_zstd_frames(plains: &[&[u8]], with_seek_table: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut entries = Vec::new();
        for p in plains {
            let f = ratarmount_compress::encode_zstd_frame(p, 3).unwrap();
            entries.push((f.len() as u32, p.len() as u32));
            out.extend_from_slice(&f);
        }
        if with_seek_table {
            out.extend_from_slice(&ratarmount_compress::build_seek_table_skippable(&entries));
        }
        out
    }

    /// One uncompressed TAR split across two zstd frames (EOF only in the last frame).
    pub(crate) fn write_split_tar_zst(
        path: &Path,
        first: &[UstarMember<'_>],
        last: &[UstarMember<'_>],
        with_seek_table: bool,
    ) {
        let f0 = pack_tar_no_eof(first);
        let mut f1 = pack_tar_no_eof(last);
        ratarmount_formats_tar::write_tar_eof(&mut f1).unwrap();
        fs::write(path, concat_zstd_frames(&[&f0, &f1], with_seek_table)).unwrap();
    }

    fn write_single_frame_tar_zst(path: &Path, members: &[UstarMember<'_>]) {
        let tar = pack_tar(members);
        fs::write(path, concat_zstd_frames(&[&tar], false)).unwrap();
    }

    fn write_complete_tar_frames_zst(path: &Path, frames: &[Vec<u8>]) {
        let refs: Vec<&[u8]> = frames.iter().map(|v| v.as_slice()).collect();
        fs::write(path, concat_zstd_frames(&refs, false)).unwrap();
    }

    pub(crate) fn reopen_tar_zst(
        path: &Path,
        ignore_zeros: bool,
    ) -> std::result::Result<Arc<dyn MountSource>, OverlayError> {
        let body = open_seekable_zstd(path).map_err(|e| OverlayError::Msg(e.to_string()))?;
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ignore_zeros,
            ..ratarmount_core::OpenOptions::default()
        };
        ratarmount_formats_tar::SqliteIndexedTar::create_index_body(path, body, None, &opts, "test")
            .map(|t| Arc::new(t) as Arc<dyn MountSource>)
            .map_err(|e| OverlayError::Msg(e.to_string()))
    }

    fn open_tar_zst_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
        reopen_tar_zst(path, ignore_zeros).expect("index tar.zst")
    }

    fn bz2_compress(plain: &[u8]) -> Vec<u8> {
        let mut enc = BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        enc.write_all(plain).unwrap();
        enc.finish().unwrap()
    }

    fn xz_compress(plain: &[u8]) -> Vec<u8> {
        let mut enc = XzEncoder::new(Vec::new(), 0);
        enc.write_all(plain).unwrap();
        enc.finish().unwrap()
    }

    fn write_concatenated_tar_bz2(
        path: &Path,
        first: &[UstarMember<'_>],
        second: &[UstarMember<'_>],
    ) {
        let mut out = bz2_compress(&pack_tar(first));
        out.extend(bz2_compress(&pack_tar(second)));
        fs::write(path, out).unwrap();
    }

    fn write_concatenated_tar_xz(
        path: &Path,
        first: &[UstarMember<'_>],
        second: &[UstarMember<'_>],
    ) {
        let mut out = xz_compress(&pack_tar(first));
        out.extend(xz_compress(&pack_tar(second)));
        fs::write(path, out).unwrap();
    }

    fn open_compressed_tar_base(
        path: &Path,
        body: Arc<dyn ratarmount_compress::SeekableBody>,
        ignore_zeros: bool,
        label: &str,
    ) -> Arc<dyn MountSource> {
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ignore_zeros,
            ..ratarmount_core::OpenOptions::default()
        };
        ratarmount_formats_tar::SqliteIndexedTar::create_index_body(path, body, None, &opts, "test")
            .map(|t| Arc::new(t) as Arc<dyn MountSource>)
            .unwrap_or_else(|e| panic!("index {label}: {e}"))
    }

    fn open_tar_bz2_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
        let body = open_seekable_bzip2(path).expect("open seekable bzip2");
        open_compressed_tar_base(path, body, ignore_zeros, "tar.bz2")
    }

    fn open_tar_xz_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
        let body = open_seekable_xz(path).expect("open seekable xz");
        open_compressed_tar_base(path, body, ignore_zeros, "tar.xz")
    }

    fn open_uncompressed_tar_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ignore_zeros,
            ..ratarmount_core::OpenOptions::default()
        };
        let mut materialised = None;
        Arc::new(
            ratarmount_formats_tar::SqliteIndexedTar::create_index(
                path,
                path,
                None,
                &opts,
                "test",
                &mut materialised,
            )
            .expect("index uncompressed tar"),
        )
    }

    fn read_member(src: &dyn MountSource, path: &str) -> Vec<u8> {
        let fi = src
            .lookup(path, 0)
            .unwrap_or_else(|| panic!("missing {path}"));
        src.read(&fi, fi.size as usize, 0).expect("read member")
    }

    fn overlay_with_base(base: Arc<dyn MountSource>, overlay: &Path) -> WriteOverlay {
        fs::create_dir_all(overlay).unwrap();
        WriteOverlay::new_for_tests(base, overlay).unwrap()
    }

    fn seek_table_footer_present(bytes: &[u8]) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        let n = bytes.len();
        u32::from_le_bytes(bytes[n - 4..].try_into().unwrap()) == 0x8F92_EAB1
    }

    #[test]
    fn live_commit_accepts_tar_zst() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("accept");
        let path = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&path, &[ustar_file("seed.txt", &seed)]);
        live_commit_is_supported(&path).expect(".tar.zst must be accepted");

        let tzst = dir.path().join("b.tzst");
        write_single_frame_tar_zst(&tzst, &[ustar_file("seed.txt", &seed)]);
        live_commit_is_supported(&tzst).expect(".tzst must be accepted");

        let zstd = dir.path().join("c.tar.zstd");
        write_single_frame_tar_zst(&zstd, &[ustar_file("seed.txt", &seed)]);
        live_commit_is_supported(&zstd).expect(".tar.zstd must be accepted");

        let plain = dir.path().join("plain.zst");
        let not_tar = ratarmount_compress::encode_zstd_frame(b"not-a-tar-body", 3).unwrap();
        fs::write(&plain, not_tar).unwrap();
        let err = live_commit_is_supported(&plain).unwrap_err().to_string();
        assert!(
            err.contains("plain .zst") && err.contains("not a TAR"),
            "{err}"
        );
    }

    #[test]
    fn live_commit_tar_zst_multi_frame_append() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("mf-prefix");
        let last = generated_payload("mf-last");
        let extra = generated_payload("mf-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let map_before = scan_zstd_frames_path(&archive).unwrap();
        let expected_start = map_before.frames.last().unwrap().uncompressed_offset;
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();

        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
        let window = ov.last_patch_window().expect("stashed zstd window");
        assert_eq!(window.from_frame, Some(map_before.frames.len() - 1));
        assert!(!window.offsets_shifted);
        assert_eq!(
            window.window_start, expected_start,
            "last-N window must start at the last frame's uncompressed offset"
        );
    }

    #[test]
    fn live_commit_tar_zst_single_frame_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("sf-seed");
        let extra = generated_payload("sf-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();

        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_seek_table_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("st-prefix");
        let last = generated_payload("st-last");
        let extra = generated_payload("st-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            true,
        );
        let before = fs::read(&archive).unwrap();
        assert!(seek_table_footer_present(&before));
        let map = scan_zstd_frames_path(&archive).unwrap();
        assert!(map.seek_table.is_some());
        let rewrite_start = map.frames.last().unwrap().compressed_offset as usize;
        let prefix_bytes = before[..rewrite_start].to_vec();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));

        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..rewrite_start],
            prefix_bytes.as_slice(),
            "prefix frames must stay byte-identical"
        );
        assert!(
            seek_table_footer_present(&after),
            "seek-table footer must be rewritten"
        );
        let out_map = scan_zstd_frames_path(&archive).unwrap();
        assert!(out_map.seek_table.is_some());
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_last_frame_starts_mid_member() {
        let dir = tempfile::tempdir().unwrap();
        let big = generated_payload("mid-big").repeat(200);
        let after = generated_payload("mid-after");
        let extra = generated_payload("mid-new");
        let tar = pack_tar(&[ustar_file("big.bin", &big), ustar_file("after.txt", &after)]);
        // First member: 512-byte header + payload. Split inside the payload.
        let mid = 512 + big.len() / 2;
        assert!(mid < 512 + big.len(), "split must be mid-payload");
        let archive = dir.path().join("a.tar.zst");
        fs::write(
            &archive,
            concat_zstd_frames(&[&tar[..mid], &tar[mid..]], false),
        )
        .unwrap();

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/big.bin"), big);
        assert_eq!(read_member(src.as_ref(), "/after.txt"), after);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_last_window_replace_two_ticks() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("rw-seed");
        let tick1 = generated_payload("rw-t1");
        let tick2 = generated_payload("rw-t2");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("seed.txt", &seed)],
            &[ustar_file("keep.txt", b"keep\n")],
            false,
        );
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("tick.bin"), &tick1).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("tick 1"));
        assert!(!overlay.join("tick.bin").exists());

        fs::write(overlay.join("tick.bin"), &tick2).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("tick 2"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/tick.bin"), tick2);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    }

    #[test]
    fn live_commit_tar_zst_earlier_frame_delete_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("ef-prefix");
        let last = generated_payload("ef-last");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("old.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/old.txt").expect("unlink prefix member");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/old.txt"), "{err}");
        assert_eq!(
            fs::read(&archive).unwrap(),
            before,
            "archive must be unchanged"
        );
    }

    /// Regression: same name in frame 0 and last frame; unlink must fail the tick.
    #[test]
    fn live_commit_tar_zst_same_name_both_frames_unlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = generated_payload("dup-v1");
        let v2 = generated_payload("dup-v2");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("dup.txt", &v1)],
            &[ustar_file("dup.txt", &v2)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        // ignore_zeros so both versions are indexed (split-suffix still one stream).
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/dup.txt").expect("unlink newest");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/dup.txt"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    #[test]
    fn live_commit_tar_zst_mixed_plan_skips_pending_appends() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("mix-old");
        let last = generated_payload("mix-last");
        let extra = generated_payload("mix-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("old.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        ov.unlink("/old.txt").expect("unlink earlier-frame name");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("pending appends"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
        let src = open_tar_zst_base(&archive, false);
        assert!(
            src.lookup("/new.txt", 0).is_none(),
            "new name must not be persisted when the tick fails"
        );
        assert!(overlay.join("new.txt").exists());
    }

    #[test]
    fn live_commit_tar_zst_reopen_fail_keeps_overlay_and_disables() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("rf-seed");
        let extra = generated_payload("rf-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();

        let err = ov
            .commit_live(&archive, |_| {
                Err(OverlayError::Msg("stub reopen fail".into()))
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("remount required"), "{err}");
        assert!(
            overlay.join("new.txt").exists(),
            "overlay must be kept after reopen failure"
        );
        assert!(ov.interval_disabled());
        assert_eq!(read_member(&ov, "/seed.txt"), seed);

        let second = ov
            .commit_live(&archive, |_| {
                panic!("second tick must not persist after interval_disabled")
            })
            .unwrap_err()
            .to_string();
        assert!(
            second.contains("remount required"),
            "second tick skipped via interval_disabled, not Ok(false): {second}"
        );
        assert!(overlay.join("new.txt").exists());
        // Persist did run on the first tick — remount should see the new member.
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_empty_second_tick() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("es-seed");
        let extra = generated_payload("es-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("first tick"));
        assert!(!overlay.join("new.txt").exists());
        match ov.commit_live(&archive, |p| reopen_tar_zst(p, false)) {
            Ok(false) => {}
            other => panic!("empty second tick must be Ok(false), got {other:?}"),
        }
    }

    fn set_mtime_age(path: &Path, age: Duration) {
        use std::os::unix::ffi::OsStrExt;
        let ts = SystemTime::now()
            .checked_sub(age)
            .expect("mtime age within epoch");
        let d = ts
            .duration_since(std::time::UNIX_EPOCH)
            .expect("mtime after epoch");
        let spec = libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        };
        let times = [spec, spec];
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let rc = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        assert_eq!(rc, 0, "utimensat {}", path.display());
    }

    /// Regression: interval settle time skips files still being written.
    #[test]
    fn live_commit_idle_skips_recent_keeps_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-seed");
        let settled = generated_payload("idle-settled");
        let hot = generated_payload("idle-hot");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("settled.txt"), &settled).unwrap();
        fs::write(overlay.join("hot.txt"), &hot).unwrap();
        set_mtime_age(&overlay.join("settled.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle tick"));
        assert!(
            !overlay.join("settled.txt").exists(),
            "settled file must leave the overlay"
        );
        assert!(
            overlay.join("hot.txt").exists(),
            "recently modified file must stay in the overlay"
        );
        assert_eq!(fs::read(overlay.join("hot.txt")).unwrap(), hot);

        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
        assert_eq!(read_member(src.as_ref(), "/settled.txt"), settled);
        assert!(
            src.lookup("/hot.txt", 0).is_none(),
            "hot file must not be in the archive yet"
        );
        assert_eq!(
            read_member(&ov as &dyn MountSource, "/hot.txt"),
            hot,
            "mount view still serves the overlay copy"
        );
    }

    /// Descriptors whose target is under `root`, including unlinked files
    /// (`readlink` appends ` (deleted)`). Ignores the rest of the process so
    /// the leak check stays valid when other tests hold fds.
    #[cfg(unix)]
    fn count_fds_under(root: &Path) -> Option<usize> {
        let prefix = root.to_string_lossy();
        let rd = std::fs::read_dir("/proc/self/fd").ok()?;
        Some(
            rd.flatten()
                .filter(|ent| {
                    std::fs::read_link(ent.path())
                        .ok()
                        .is_some_and(|target| target.to_string_lossy().starts_with(prefix.as_ref()))
                })
                .count(),
        )
    }

    /// Regression: `open_overlay_fd` materialized a missing host file via
    /// `create_file_inner` and discarded the raw fd (`into_raw_fd` is not
    /// Drop-closed). Interval persist wipes the overlay copy, so the next
    /// FUSE/NFS/9P rewrite leaked one descriptor each time — long-lived
    /// `--commit-overlay-interval` mounts hit EMFILE.
    #[cfg(unix)]
    #[test]
    fn open_overlay_fd_create_does_not_leak_materialize_fd() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay);
        let Some(before) = count_fds_under(&overlay) else {
            eprintln!("skip: /proc/self/fd not available");
            return;
        };
        const N: usize = 32;
        for i in 0..N {
            let path = format!("/rewrite-{i}.txt");
            let fd = ov
                .open_overlay_fd(&path, libc::O_RDWR | libc::O_CREAT)
                .expect("first O_CREAT open");
            ov.close_overlay_fd(fd);
            // Same as interval `forget_committed_overlay`: host file is gone.
            fs::remove_file(overlay.join(format!("rewrite-{i}.txt"))).expect("wipe overlay host");
            let fd = ov
                .open_overlay_fd(&path, libc::O_RDWR | libc::O_CREAT)
                .expect("post-wipe O_CREAT open");
            ov.close_overlay_fd(fd);
        }
        let after = count_fds_under(&overlay).expect("/proc/self/fd after loop");
        assert_eq!(
            after, before,
            "Regression: discarded create_file_inner fd leaked on missing-file \
             O_CREAT (overlay fds before={before} after={after}; 32×2 opens would leak 64)"
        );
    }

    /// Regression: interval settle must not persist a file that still has an
    /// open write fd. FUSE keeps that fd across pauses; unlinking would send
    /// later pwrite bytes to a detached inode (silent truncation).
    #[test]
    fn live_commit_idle_skips_open_write_fd() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-open-seed");
        let first = generated_payload("idle-open-first");
        let second = generated_payload("idle-open-second");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        let fd = ov.create_file("/open.txt", 0o644).expect("create");
        let n = unsafe { libc::write(fd, first.as_ptr() as *const _, first.len()) };
        assert_eq!(n as usize, first.len(), "first write");
        set_mtime_age(&overlay.join("open.txt"), Duration::from_secs(30));

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(false) => {}
            other => panic!("open write fd must skip idle persist, got {other:?}"),
        }
        assert!(
            overlay.join("open.txt").exists(),
            "open write fd must keep the overlay file"
        );

        let n = unsafe {
            libc::pwrite(
                fd,
                second.as_ptr() as *const _,
                second.len(),
                first.len() as i64,
            )
        };
        assert_eq!(n as usize, second.len(), "second write after skipped tick");
        ov.close_overlay_fd(fd);
        set_mtime_age(&overlay.join("open.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle tick after close"));
        assert!(!overlay.join("open.txt").exists());

        let mut want = first.clone();
        want.extend_from_slice(&second);
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/open.txt"), want);
    }

    /// Regression: NFS WRITE used to `drop(File)` (close) and then
    /// `release_write_fd`. The pin map is keyed by fd number; the kernel can
    /// reuse that number for a still-open FUSE writer. Interval settle would
    /// persist/unlink the still-open file (later pwrite → detached inode).
    #[test]
    fn live_commit_idle_skips_open_write_fd_after_fd_reuse() {
        use std::os::unix::io::FromRawFd;

        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-reuse-seed");
        let keep = generated_payload("idle-reuse-keep");
        let nfs_bytes = generated_payload("idle-reuse-nfs");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);

        let nfs_fd = ov
            .open_overlay_fd("/nfs.txt", libc::O_RDWR | libc::O_CREAT)
            .expect("nfs open");
        let n = unsafe { libc::write(nfs_fd, nfs_bytes.as_ptr() as *const _, nfs_bytes.len()) };
        assert_eq!(n as usize, nfs_bytes.len(), "nfs write");
        let nfs_file = unsafe { std::fs::File::from_raw_fd(nfs_fd) };
        ov.finish_owned_write_fd(nfs_file);

        // Long-lived FUSE-style writer. If the OS reused `nfs_fd`, the pin
        // must now belong to this file — not a stale closed number.
        let keep_fd = ov.create_file("/keep.txt", 0o644).expect("keep create");
        let n = unsafe { libc::write(keep_fd, keep.as_ptr() as *const _, keep.len()) };
        assert_eq!(n as usize, keep.len(), "keep write");
        set_mtime_age(&overlay.join("keep.txt"), Duration::from_secs(30));
        set_mtime_age(&overlay.join("nfs.txt"), Duration::from_secs(30));

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(_) => {}
            Err(e) => panic!("idle tick after fd reuse: {e}"),
        }
        assert!(
            overlay.join("keep.txt").exists(),
            "still-open writer must stay in the overlay after a finished NFS \
             WRITE reuses/closes another fd (keep_fd={keep_fd}, nfs_fd={nfs_fd})"
        );

        let extra = generated_payload("idle-reuse-extra");
        let n = unsafe {
            libc::pwrite(
                keep_fd,
                extra.as_ptr() as *const _,
                extra.len(),
                keep.len() as i64,
            )
        };
        assert_eq!(n as usize, extra.len(), "pwrite after skipped tick");
        ov.close_overlay_fd(keep_fd);
        set_mtime_age(&overlay.join("keep.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle tick after keep close"));
        assert!(!overlay.join("keep.txt").exists());

        let mut want = keep.clone();
        want.extend_from_slice(&extra);
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/keep.txt"), want);
        assert_eq!(read_member(src.as_ref(), "/nfs.txt"), nfs_bytes);
    }

    /// Regression: SMB/SFTP/9P/WebDAV WRITE used to `drop(File)` (close) and
    /// then `release_write_fd`. Same pin-map / fd-reuse class as NFS.
    #[test]
    fn live_commit_idle_skips_open_write_fd_after_protocol_write_fd_reuse() {
        use std::os::unix::io::FromRawFd;

        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-proto-seed");
        let keep = generated_payload("idle-proto-keep");
        let proto_bytes = generated_payload("idle-proto-write");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);

        // Fixed sequence: unpin while the fd is still open, then close.
        let proto_fd = ov
            .open_overlay_fd("/proto.txt", libc::O_RDWR | libc::O_CREAT)
            .expect("proto open");
        let n = unsafe {
            libc::write(
                proto_fd,
                proto_bytes.as_ptr() as *const _,
                proto_bytes.len(),
            )
        };
        assert_eq!(n as usize, proto_bytes.len(), "proto write");
        let proto_file = unsafe { std::fs::File::from_raw_fd(proto_fd) };
        ov.finish_owned_write_fd(proto_file);

        let keep_fd = ov.create_file("/keep.txt", 0o644).expect("keep create");
        let n = unsafe { libc::write(keep_fd, keep.as_ptr() as *const _, keep.len()) };
        assert_eq!(n as usize, keep.len(), "keep write");
        set_mtime_age(&overlay.join("keep.txt"), Duration::from_secs(30));
        set_mtime_age(&overlay.join("proto.txt"), Duration::from_secs(30));

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(_) => {}
            Err(e) => panic!("idle tick after protocol fd reuse: {e}"),
        }
        assert!(
            overlay.join("keep.txt").exists(),
            "still-open writer must stay in the overlay after a finished protocol \
             WRITE reuses/closes another fd (keep_fd={keep_fd}, proto_fd={proto_fd})"
        );

        let extra = generated_payload("idle-proto-extra");
        let n = unsafe {
            libc::pwrite(
                keep_fd,
                extra.as_ptr() as *const _,
                extra.len(),
                keep.len() as i64,
            )
        };
        assert_eq!(n as usize, extra.len(), "pwrite after skipped tick");
        ov.close_overlay_fd(keep_fd);
        set_mtime_age(&overlay.join("keep.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle tick after keep close"));
        assert!(!overlay.join("keep.txt").exists());

        let mut want = keep.clone();
        want.extend_from_slice(&extra);
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/keep.txt"), want);
        assert_eq!(read_member(src.as_ref(), "/proto.txt"), proto_bytes);
    }

    /// Regression: interval settle keyed the write-open pin by overlay path.
    /// After `rename`, the host file moved but the pin still named the old
    /// path, so a tick persisted and unlinked the renamed inode. Later
    /// `pwrite` bytes hit the detached inode and never reached the archive.
    ///
    /// Overlay-only create plus an unpinned sibling: same tick persists the
    /// sibling (`Ok(true)`) and leaves the renamed writer on disk.
    #[test]
    fn live_commit_idle_skips_open_write_fd_after_rename() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-rename-seed");
        let first = generated_payload("idle-rename-first");
        let second = generated_payload("idle-rename-second");
        let sibling = generated_payload("idle-rename-sibling");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        let fd = ov.create_file("/open.txt", 0o644).expect("create");
        let n = unsafe { libc::write(fd, first.as_ptr() as *const _, first.len()) };
        assert_eq!(n as usize, first.len(), "first write");
        ov.rename("/open.txt", "/renamed.txt")
            .expect("rename open write fd");
        fs::write(overlay.join("sibling.txt"), &sibling).unwrap();
        set_mtime_age(&overlay.join("renamed.txt"), Duration::from_secs(30));
        set_mtime_age(&overlay.join("sibling.txt"), Duration::from_secs(30));

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(true) => {}
            other => panic!(
                "idle tick must persist the unpinned sibling and skip the renamed writer, got {other:?}"
            ),
        }
        assert!(
            overlay.join("renamed.txt").exists(),
            "renamed open write fd must keep the overlay file"
        );
        assert!(
            !overlay.join("sibling.txt").exists(),
            "unpinned idle sibling must leave the overlay (proves we did not fail-closed the whole tick)"
        );
        assert!(
            !overlay.join("open.txt").exists(),
            "rename must have left the old overlay name"
        );

        let n = unsafe {
            libc::pwrite(
                fd,
                second.as_ptr() as *const _,
                second.len(),
                first.len() as i64,
            )
        };
        assert_eq!(n as usize, second.len(), "second write after rename+tick");
        ov.close_overlay_fd(fd);
        set_mtime_age(&overlay.join("renamed.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle tick after close"));
        assert!(!overlay.join("renamed.txt").exists());

        let mut want = first.clone();
        want.extend_from_slice(&second);
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/renamed.txt"), want);
        assert_eq!(read_member(src.as_ref(), "/sibling.txt"), sibling);
        assert!(
            src.lookup("/open.txt", 0).is_none(),
            "old name must not remain in the archive"
        );
    }

    /// Regression: after the hot file settles, a later tick persists it once.
    #[test]
    fn live_commit_idle_second_tick_after_settle() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle2-seed");
        let settled = generated_payload("idle2-settled");
        let later = generated_payload("idle2-later");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("settled.txt"), &settled).unwrap();
        fs::write(overlay.join("later.txt"), &later).unwrap();
        set_mtime_age(&overlay.join("settled.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("first idle tick"));
        assert!(overlay.join("later.txt").exists());

        set_mtime_age(&overlay.join("later.txt"), Duration::from_secs(30));
        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("second idle tick"));
        assert!(!overlay.join("later.txt").exists());

        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/settled.txt"), settled);
        assert_eq!(read_member(src.as_ref(), "/later.txt"), later);
        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(false) => {}
            other => panic!("third tick must be empty, got {other:?}"),
        }
    }

    /// Regression: a hot replace must not delete the base member without appending.
    #[test]
    fn live_commit_idle_hot_replace_leaves_base_member() {
        let dir = tempfile::tempdir().unwrap();
        let orig = generated_payload("idle-rep-orig");
        let newer = generated_payload("idle-rep-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("keep.txt", &orig)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("keep.txt"), &newer).unwrap();

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(false) => {}
            other => panic!("hot replace must not persist, got {other:?}"),
        }
        assert!(overlay.join("keep.txt").exists());
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(
            read_member(src.as_ref(), "/keep.txt"),
            orig,
            "base member must survive a skipped hot replace"
        );
        assert_eq!(read_member(&ov as &dyn MountSource, "/keep.txt"), newer);
    }

    /// Regression: live interval must persist a later complete-TAR-frame
    /// delete after remount without `-i`.
    ///
    /// Tombstones survive in the overlay DB. `current_base()` after a default
    /// remount does not see later-frame names, so classification used to skip
    /// the delete, return success, and `forget_committed_overlay` dropped the
    /// tombstone — the member reappeared on the next `-i` remount.
    #[test]
    fn live_commit_idle_tar_zst_concatenated_delete_without_ignore_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("live-i0-prefix");
        let last = generated_payload("live-i0-last");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("prefix.txt", &prefix)]),
                pack_tar(&[ustar_file("last.txt", &last)]),
            ],
        );
        let before = fs::read(&archive).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        assert!(map.frames.len() >= 2);
        let prefix_end = map.frames[1].compressed_offset as usize;
        let prefix_bytes = before[..prefix_end].to_vec();

        let overlay = dir.path().join("ov");
        {
            let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
            ov.unlink("/last.txt")
                .expect("unlink later complete-TAR frame");
        }

        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        assert!(
            ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
                reopen_tar_zst(p, false)
            })
            .expect("live idle commit without -i must persist later-frame delete"),
            "interval tick must persist the remounted tombstone"
        );
        let after = fs::read(&archive).unwrap();
        assert_eq!(
            &after[..prefix_end],
            prefix_bytes.as_slice(),
            "prefix complete-TAR frame must stay byte-identical"
        );
        let src = open_tar_zst_base(&archive, true);
        assert!(
            src.lookup("/last.txt", 0).is_none(),
            "later-frame name must be gone after live commit without -i"
        );
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert!(
            ov.lookup("/last.txt", 0).is_none(),
            "interval cleanup must not resurrect the forgotten tombstone"
        );
    }

    /// Regression: delete tombstones are already settled and commit on an idle tick.
    #[test]
    fn live_commit_idle_commits_delete_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let keep = generated_payload("idle-del-keep");
        let gone = generated_payload("idle-del-gone");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(
            &archive,
            &[ustar_file("keep.txt", &keep), ustar_file("gone.txt", &gone)],
        );
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/gone.txt").expect("tombstone");

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle delete tick"));
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/keep.txt"), keep);
        assert!(
            src.lookup("/gone.txt", 0).is_none(),
            "deleted member must leave the archive"
        );
        assert!(ov.lookup("/gone.txt", 0).is_none());
    }

    /// Regression: a hot nested sibling must keep its parent dir in the overlay.
    #[test]
    fn live_commit_idle_nested_hot_sibling_keeps_parent() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-nest-seed");
        let settled = generated_payload("idle-nest-settled");
        let hot = generated_payload("idle-nest-hot");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::create_dir_all(overlay.join("dir")).unwrap();
        fs::write(overlay.join("dir/settled.txt"), &settled).unwrap();
        fs::write(overlay.join("dir/hot.txt"), &hot).unwrap();
        set_mtime_age(&overlay.join("dir/settled.txt"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle nested tick"));
        assert!(!overlay.join("dir/settled.txt").exists());
        assert!(
            overlay.join("dir/hot.txt").exists(),
            "hot sibling must keep the parent dir"
        );
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/dir/settled.txt"), settled);
        assert!(src.lookup("/dir/hot.txt", 0).is_none());
        assert_eq!(read_member(&ov as &dyn MountSource, "/dir/hot.txt"), hot);
    }

    /// Regression: after the last file in a new dir settles, prune the empty
    /// parent so a later tick does not persist a bare directory member.
    #[test]
    fn live_commit_idle_prunes_empty_parent_after_last_file() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("idle-prune-seed");
        let only = generated_payload("idle-prune-only");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::create_dir_all(overlay.join("dir")).unwrap();
        fs::write(overlay.join("dir/only.txt"), &only).unwrap();
        set_mtime_age(&overlay.join("dir/only.txt"), Duration::from_secs(30));
        // Dir mtime is refreshed by the file write; backdate so a leftover
        // empty dir would look idle on the next tick if it were not pruned.
        set_mtime_age(&overlay.join("dir"), Duration::from_secs(30));

        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
                p, false
            ))
            .expect("idle prune tick"));
        assert!(
            !overlay.join("dir").exists(),
            "empty parent must be pruned from the overlay"
        );
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/dir/only.txt"), only);

        match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        }) {
            Ok(false) => {}
            other => panic!("second tick must not persist leftover dir, got {other:?}"),
        }
    }

    fn wait_inflight(ov: &WriteOverlay, timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if ov.persist_inflight_for_test() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("inflight flag never set within {timeout:?}");
    }

    fn zstd_magic_ok(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[..4] == [0x28, 0xB5, 0x2F, 0xFD]
    }

    /// Count ustar names after decoding every zstd frame (`tar -tf`).
    fn tar_zst_member_count(archive: &Path, name: &str) -> usize {
        let map = scan_zstd_frames_path(archive).unwrap();
        let mut src = File::open(archive).unwrap();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        ratarmount_compress::decode_zstd_frames_to(&mut src, &map, 0, tmp.as_file_mut()).unwrap();
        let out = StdCommand::new("tar")
            .args(["-tf"])
            .arg(tmp.path())
            .output()
            .expect("tar -tf");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.trim_end_matches('/') == name)
            .count()
    }

    /// Regression: two interval fires during injected long persist → second Coalesced.
    #[test]
    fn overlay_commit_queue_second_interval_coalesced() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("q-coal-seed");
        let extra = generated_payload("q-coal-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = Arc::new(overlay_with_base(
            open_tar_zst_base(&archive, false),
            &overlay,
        ));
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        set_mtime_age(&overlay.join("new.txt"), Duration::from_secs(30));
        ov.set_persist_delay_for_test(Duration::from_millis(400));

        let archive_t = archive.clone();
        let ov_t = Arc::clone(&ov);
        let first = std::thread::spawn(move || {
            ov_t.enqueue_commit(
                &archive_t,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |p| reopen_tar_zst(p, false),
            )
        });
        wait_inflight(&ov, Duration::from_secs(2));
        // Inflight is set before persist delay; splice has not started yet.
        // Sibling-tmp + atomic replace is what keeps readers off a truncated file.
        let during = fs::read(&archive).unwrap();
        assert!(
            zstd_magic_ok(&during),
            "archive path must still be a zstd file while inflight"
        );

        let second = ov
            .enqueue_commit(
                &archive,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |_| panic!("second interval tick must not start persist"),
            )
            .expect("coalesce");
        assert_eq!(second, CommitOutcome::Coalesced);

        let first = first
            .join()
            .expect("first tick thread")
            .expect("first tick");
        assert_eq!(first, CommitOutcome::DidWork);
        assert!(!ov.persist_inflight_for_test());
        assert!(!overlay.join("new.txt").exists());
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
        let after = fs::read(&archive).unwrap();
        assert!(zstd_magic_ok(&after));
    }

    /// Regression: on-exit waits for inflight interval then one commit_atomic
    /// of remaining files (same plan is not spliced twice).
    #[test]
    fn overlay_commit_queue_on_exit_waits_then_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("q-wait-seed");
        let extra = generated_payload("q-wait-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = Arc::new(overlay_with_base(
            open_tar_zst_base(&archive, false),
            &overlay,
        ));
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        set_mtime_age(&overlay.join("new.txt"), Duration::from_secs(30));
        ov.set_persist_delay_for_test(Duration::from_millis(300));

        let archive_t = archive.clone();
        let ov_t = Arc::clone(&ov);
        let interval = std::thread::spawn(move || {
            ov_t.enqueue_commit(
                &archive_t,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |p| reopen_tar_zst(p, false),
            )
        });
        wait_inflight(&ov, Duration::from_secs(2));

        let on_exit = ov
            .enqueue_commit(&archive, CommitKind::OnExit, |_| {
                panic!("on-exit must not reopen")
            })
            .expect("on-exit");
        assert_eq!(
            on_exit,
            CommitOutcome::Nothing,
            "interval already committed the idle plan; on-exit must not splice again"
        );
        let interval = interval.join().expect("interval thread").expect("interval");
        assert_eq!(interval, CommitOutcome::DidWork);

        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
        assert_eq!(tar_zst_member_count(&archive, "new.txt"), 1);
    }

    /// Regression: empty interval polls must not shrink the on-exit wait
    /// (2× last DidWork persist).
    #[test]
    fn overlay_commit_queue_empty_tick_does_not_shrink_persist_duration() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("q-dur-seed");
        let extra = generated_payload("q-dur-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        set_mtime_age(&overlay.join("new.txt"), Duration::from_secs(30));

        assert_eq!(
            ov.enqueue_commit(
                &archive,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |p| reopen_tar_zst(p, false),
            )
            .expect("did work"),
            CommitOutcome::DidWork
        );
        let after_work = ov.last_persist_duration_for_test();
        assert!(
            after_work > Duration::ZERO,
            "DidWork must record a persist duration, got {after_work:?}"
        );

        assert_eq!(
            ov.enqueue_commit(
                &archive,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |p| reopen_tar_zst(p, false),
            )
            .expect("empty"),
            CommitOutcome::Nothing
        );
        assert_eq!(
            ov.last_persist_duration_for_test(),
            after_work,
            "empty poll must not overwrite last DidWork duration"
        );
    }

    /// Regression: on-exit waits then commit_atomic remaining (idle A by
    /// interval, still-hot B by on-exit); each name once.
    #[test]
    fn overlay_commit_queue_on_exit_commits_remaining_hot() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("q-hot-seed");
        let idle = generated_payload("q-hot-idle");
        let hot = generated_payload("q-hot-hot");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = Arc::new(overlay_with_base(
            open_tar_zst_base(&archive, false),
            &overlay,
        ));
        fs::write(overlay.join("idle.txt"), &idle).unwrap();
        fs::write(overlay.join("hot.txt"), &hot).unwrap();
        set_mtime_age(&overlay.join("idle.txt"), Duration::from_secs(30));
        ov.set_persist_delay_for_test(Duration::from_millis(300));

        let archive_t = archive.clone();
        let ov_t = Arc::clone(&ov);
        let interval = std::thread::spawn(move || {
            ov_t.enqueue_commit(
                &archive_t,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |p| reopen_tar_zst(p, false),
            )
        });
        wait_inflight(&ov, Duration::from_secs(2));

        let on_exit = ov
            .enqueue_commit(&archive, CommitKind::OnExit, |_| {
                panic!("on-exit must not reopen")
            })
            .expect("on-exit");
        let interval = interval.join().expect("interval thread").expect("interval");
        assert_eq!(interval, CommitOutcome::DidWork);
        assert_eq!(on_exit, CommitOutcome::DidWork);
        assert!(!overlay.join("idle.txt").exists());
        // On-exit persist does not reset the overlay folder.
        assert!(overlay.join("hot.txt").exists());

        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/idle.txt"), idle);
        assert_eq!(read_member(src.as_ref(), "/hot.txt"), hot);
        assert_eq!(tar_zst_member_count(&archive, "idle.txt"), 1);
        assert_eq!(tar_zst_member_count(&archive, "hot.txt"), 1);
    }

    /// Regression: on-exit wait timeout during persist delay must not splice
    /// until inflight clears (commit_atomic does not forget overlay files).
    #[test]
    fn overlay_commit_queue_on_exit_timeout_waits_inflight() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("q-to-seed");
        let idle = generated_payload("q-to-idle");
        let hot = generated_payload("q-to-hot");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = Arc::new(overlay_with_base(
            open_tar_zst_base(&archive, false),
            &overlay,
        ));
        fs::write(overlay.join("idle.txt"), &idle).unwrap();
        fs::write(overlay.join("hot.txt"), &hot).unwrap();
        set_mtime_age(&overlay.join("idle.txt"), Duration::from_secs(30));
        ov.set_persist_delay_for_test(Duration::from_millis(400));
        ov.set_on_exit_wait_min_for_test(Duration::from_millis(1));

        let archive_t = archive.clone();
        let ov_t = Arc::clone(&ov);
        let interval = std::thread::spawn(move || {
            ov_t.enqueue_commit(
                &archive_t,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |p| reopen_tar_zst(p, false),
            )
        });
        wait_inflight(&ov, Duration::from_secs(2));

        let on_exit = ov
            .enqueue_commit(&archive, CommitKind::OnExit, |_| {
                panic!("on-exit must not reopen")
            })
            .expect("on-exit");
        let interval = interval.join().expect("interval thread").expect("interval");
        assert_eq!(interval, CommitOutcome::DidWork);
        assert_eq!(on_exit, CommitOutcome::DidWork);
        assert_eq!(tar_zst_member_count(&archive, "idle.txt"), 1);
        assert_eq!(tar_zst_member_count(&archive, "hot.txt"), 1);
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/idle.txt"), idle);
        assert_eq!(read_member(src.as_ref(), "/hot.txt"), hot);
    }

    /// Regression: live prefix-frame delete still fail-closed via enqueue.
    #[test]
    fn overlay_commit_queue_prefix_frame_delete_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("q-ef-prefix");
        let last = generated_payload("q-ef-last");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("old.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/old.txt").expect("unlink prefix member");
        let err = ov
            .enqueue_commit(
                &archive,
                CommitKind::IntervalIdle(Duration::from_secs(10)),
                |p| reopen_tar_zst(p, false),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/old.txt"), "{err}");
        assert!(err.contains("--commit-overlay"), "{err}");
        assert_eq!(
            fs::read(&archive).unwrap(),
            before,
            "archive must be unchanged"
        );
    }

    /// Regression: FileVersionLayer wrap (factory default); same name in both frames.
    #[test]
    fn live_commit_tar_zst_file_version_layer_same_name_unlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = generated_payload("fvl-v1");
        let v2 = generated_payload("fvl-v2");
        let archive = dir.path().join("a.tar.zst");
        // Two complete-TAR frames so both versions exist only with ignore_zeros.
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("dup.txt", &v1)]),
                pack_tar(&[ustar_file("dup.txt", &v2)]),
            ],
        );
        let before = fs::read(&archive).unwrap();
        let tar = open_tar_zst_base(&archive, true);
        let layered = crate::FileVersionLayer::new(tar);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(Arc::new(layered) as Arc<dyn MountSource>, &overlay);
        assert!(ov.current_base().versions("/dup.txt") > 1);
        ov.unlink("/dup.txt").expect("unlink newest");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/dup.txt"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    /// Regression: overlay symlink must persist as a symlink (`linkname` remounts).
    #[test]
    fn live_commit_tar_zst_overlay_symlink_persists_linkname() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("sy-seed");
        let target = format!("tgt-{}", std::process::id());
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.create_symlink("/link", &target)
            .expect("overlay symlink");
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit symlink"));
        let src = open_tar_zst_base(&archive, false);
        let fi = src.lookup("/link", 0).expect("symlink remounted");
        assert!(
            ratarmount_core::is_lnk_mode(fi.mode),
            "expected symlink mode, got {:o}",
            fi.mode
        );
        assert_eq!(fi.linkname, target);
        assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    }

    /// Regression: FileVersionLayer(AutoMount) reports versions()==1; unlink still rejects.
    #[test]
    fn live_commit_tar_zst_file_version_layer_automount_same_name_unlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = generated_payload("am-v1");
        let v2 = generated_payload("am-v2");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("dup.txt", &v1)]),
                pack_tar(&[ustar_file("dup.txt", &v2)]),
            ],
        );
        let before = fs::read(&archive).unwrap();
        let tar = open_tar_zst_base(&archive, true);
        let open_nested: crate::OpenNestedFn =
            Arc::new(|_p| Err(io::Error::other("no nested open in live-commit test")));
        let automount = crate::AutoMountLayer::new(tar, 1, open_nested);
        assert_eq!(
            automount.versions("/dup.txt"),
            1,
            "AutoMount default versions() is 1 if exists"
        );
        let layered = crate::FileVersionLayer::new(Arc::new(automount) as Arc<dyn MountSource>);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(Arc::new(layered) as Arc<dyn MountSource>, &overlay);
        ov.unlink("/dup.txt").expect("unlink newest");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/dup.txt"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    /// Regression: versions()==1 still walks .versions/{i} until miss.
    #[test]
    fn live_commit_tar_zst_versions_undercount_still_probes_version_paths() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = generated_payload("uc-v1");
        let v2 = generated_payload("uc-v2");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("dup.txt", &v1)],
            &[ustar_file("dup.txt", &v2)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let map = scan_zstd_frames_path(&archive).unwrap();
        let last_start = map.frames.last().unwrap().uncompressed_offset;
        let base = Arc::new(VersionsUndercount {
            oldest: tar_fi_at(0),
            newest: tar_fi_at(last_start),
        }) as Arc<dyn MountSource>;
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(base, &overlay);
        assert_eq!(ov.current_base().versions("/dup.txt"), 1);
        assert!(ov.current_base().lookup("/dup.txt.versions/1", 0).is_some());
        ov.unlink("/dup.txt").expect("unlink newest");
        let err = ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert!(err.contains("/dup.txt"), "{err}");
        assert_eq!(fs::read(&archive).unwrap(), before);
    }

    fn tar_fi_at(offsetheader: u64) -> FileInfo {
        FileInfo {
            size: 1,
            mtime: 0.0,
            mode: ratarmount_core::S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                offset: offsetheader.saturating_add(512),
                offsetheader: Some(offsetheader),
                istar: false,
                issparse: false,
                isgenerated: false,
                recursiondepth: 0,
            })],
        }
    }

    /// `versions()` lies (always 1) but `.versions/{i}` serves every copy.
    struct VersionsUndercount {
        oldest: FileInfo,
        newest: FileInfo,
    }

    impl MountSource for VersionsUndercount {
        fn list(&self, _path: &str) -> Option<ListResult> {
            Some(ListResult::Infos(Default::default()))
        }
        fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
            let path = normpath(path);
            if path == "/dup.txt.versions/1" {
                return Some(self.oldest.clone());
            }
            if path == "/dup.txt.versions/2" || path == "/dup.txt" {
                let _ = file_version;
                return Some(self.newest.clone());
            }
            if path == "/" {
                return Some(create_root_file_info());
            }
            None
        }
        fn versions(&self, path: &str) -> u32 {
            if normpath(path) == "/dup.txt" {
                1
            } else {
                0
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "versions-undercount stub",
            ))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: complete-TAR multi-frame remount with ignore_zeros sees prefix + new.
    #[test]
    fn live_commit_tar_zst_complete_frames_ignore_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("cf-prefix");
        let last = generated_payload("cf-last");
        let extra = generated_payload("cf-new");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("prefix.txt", &prefix)]),
                pack_tar(&[ustar_file("last.txt", &last)]),
            ],
        );
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, true))
            .expect("commit"));
        let src = open_tar_zst_base(&archive, true);
        assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
        assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    #[test]
    fn live_commit_tar_zst_complete_frames_without_ignore_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("cf0-prefix");
        let last = generated_payload("cf0-last");
        let extra = generated_payload("cf0-new");
        let archive = dir.path().join("a.tar.zst");
        write_complete_tar_frames_zst(
            &archive,
            &[
                pack_tar(&[ustar_file("prefix.txt", &prefix)]),
                pack_tar(&[ustar_file("last.txt", &last)]),
            ],
        );
        let overlay = dir.path().join("ov");
        // Base indexed with -i so last-frame names exist for classification; reopen without.
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));

        // Default parse stops at the first 512-zero block (end of frame 0).
        let default = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(default.as_ref(), "/prefix.txt"), prefix);
        assert!(
            default.lookup("/last.txt", 0).is_none(),
            "without ignore_zeros, last-frame names stay invisible"
        );
        assert!(
            default.lookup("/new.txt", 0).is_none(),
            "new members live after the first frame EOF"
        );

        // The rewritten last complete TAR frame itself contains last + new, not prefix.
        let map = scan_zstd_frames_path(&archive).unwrap();
        let last_idx = map.frames.len() - 1;
        let mut src = File::open(&archive).unwrap();
        let mut last_plain = Vec::new();
        decode_zstd_frames_to(&mut src, &map, last_idx, &mut last_plain).unwrap();
        let last_tar = ratarmount_formats_tar::SqliteIndexedTar::open_from_reader(
            std::io::Cursor::new(last_plain),
            "last-frame.tar",
            None,
            &ratarmount_core::OpenOptions {
                index_in_memory: true,
                ..ratarmount_core::OpenOptions::default()
            },
            "test",
        )
        .expect("index last frame");
        assert!(last_tar.lookup("/prefix.txt", 0).is_none());
        assert_eq!(read_member(&last_tar, "/last.txt"), last);
        assert_eq!(read_member(&last_tar, "/new.txt"), extra);
    }

    /// Multi-frame live splice records the pre-splice cut, not the new length.
    #[test]
    fn prefix_compressed_bytes_matches_splice_stats() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("plan-prefix");
        let last = generated_payload("plan-last");
        let extra = generated_payload("plan-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let map = scan_zstd_frames_path(&archive).unwrap();
        assert!(map.frames.len() >= 2, "fixture must be multi-frame");
        let (from_idx, _) = find_last_n_tar_window(&archive, &map, "test").unwrap();
        let pre_cut = map.frames[from_idx].compressed_offset;
        assert!(pre_cut > 0, "prefix frames must occupy compressed bytes");

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        assert!(ov.last_publish_plan().is_none());
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));
        let plan = ov.last_publish_plan().expect("publish plan");
        assert_eq!(
            plan.prefix_compressed_bytes, pre_cut,
            "prefix must equal SpliceStats.prefix_compressed_bytes / pre-splice frames[from_idx].compressed_offset"
        );
        let post_len = fs::metadata(&archive).unwrap().len();
        assert_ne!(
            plan.prefix_compressed_bytes, post_len,
            "prefix cut is not the post-splice file length"
        );
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
        assert!(
            !fs::read_dir(&overlay).unwrap().flatten().any(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with(".ratarmount-spool-")),
            "real spool must not be created inside the overlay"
        );
    }

    /// Regression: uncompressed TAR publish plan stores prefix 0.
    #[test]
    fn uncompressed_tar_publish_plan_has_zero_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let tar = make_tiny_tar(dir.path(), &[("old.txt", b"keep\n")]);
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        let ov =
            WriteOverlay::new_for_tests(open_uncompressed_tar_base(&tar, false), &overlay).unwrap();
        fs::write(overlay.join("new.txt"), b"appended\n").unwrap();
        match ov.commit_atomic(&tar) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("commit_atomic: {other:?}"),
        }
        let plan = ov.last_publish_plan().expect("publish plan");
        assert_eq!(plan.prefix_compressed_bytes, 0);
    }

    /// Schema and 64-hex id match `IndexPointer::for_blob` only after the patch.
    #[test]
    fn pointer_plan_matches_index_pointer_for_blob() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("ptr-seed");
        let extra = generated_payload("ptr-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let sidecar = ratarmount_index::default_index_path(&archive);
        {
            let body = open_seekable_zstd(&archive).expect("open zstd");
            let opts = OpenOptions {
                ignore_zeros: true,
                gnu_incremental: Some(false),
                ..OpenOptions::default()
            };
            let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
                &archive,
                body,
                Some(&sidecar),
                &opts,
                "test",
            )
            .expect("create sidecar");
        }

        let unpatched =
            index_pointer_plan_after_patch(&sidecar, Some(&archive)).expect("unpatched plan");
        assert_eq!(
            unpatched.pointer.schema,
            ratarmount_index::INDEX_POINTER_SCHEMA
        );
        assert_eq!(
            unpatched.pointer.index_id.len(),
            ratarmount_index::INDEX_ID_HEX_LEN
        );
        assert!(unpatched
            .pointer
            .index_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(unpatched.pointer.etag_sha256, unpatched.pointer.index_id);
        let parsed = ratarmount_index::parse_index_pointer_json(&unpatched.json).expect("json");
        assert_eq!(parsed.index_id, unpatched.pointer.index_id);
        assert_eq!(parsed.schema, unpatched.pointer.schema);

        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("commit"));
        let window = ov.last_patch_window().expect("window");
        // Helper does not patch. Hashing here would still be the pre-commit id.
        let still_unpatched =
            index_pointer_plan_after_patch(&sidecar, Some(&archive)).expect("pre-patch plan");
        assert_eq!(still_unpatched.pointer.index_id, unpatched.pointer.index_id);

        patch_sidecar_if_present(
            &archive,
            &window,
            &OpenOptions {
                ignore_zeros: true,
                gnu_incremental: Some(false),
                ..OpenOptions::default()
            },
        )
        .expect("patch sidecar");

        let patched = index_pointer_plan_after_patch(&sidecar, Some(&archive)).expect("patched");
        let direct = IndexPointer::for_blob(&sidecar, Some(&archive)).expect("for_blob");
        assert_eq!(patched.pointer.schema, direct.schema);
        assert_eq!(patched.pointer.index_id, direct.index_id);
        assert_eq!(patched.pointer.etag_sha256, direct.etag_sha256);
        assert_eq!(
            patched.pointer.index_id.len(),
            ratarmount_index::INDEX_ID_HEX_LEN
        );
        assert_ne!(
            patched.pointer.index_id, unpatched.pointer.index_id,
            "hash changes if the helper runs on the unpatched sidecar"
        );
        let parsed = ratarmount_index::parse_index_pointer_json(&patched.json).expect("json");
        assert_eq!(parsed.index_id, direct.index_id);
        assert_eq!(parsed.schema, ratarmount_index::INDEX_POINTER_SCHEMA);
        assert!(!ratarmount_index::index_pointer_path(&archive).exists());
    }

    #[test]
    fn collect_overlay_commit_plan_from_conn_skips_planted_spool_name() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join(".ratarmount-spool-x"), b"planted").unwrap();
        fs::write(overlay.join("real.txt"), b"keep").unwrap();
        let names_before = overlay_entry_names(&overlay);
        let plan =
            collect_overlay_commit_plan_from_conn(&overlay, None, None, &HashSet::new()).unwrap();
        assert!(
            plan.append_entries
                .iter()
                .all(|(p, _)| !p.starts_with(".ratarmount-spool-")),
            "planted spool name must not be an append entry: {:?}",
            plan.append_entries
        );
        assert!(plan
            .append_entries
            .iter()
            .any(|(p, is_dir)| p == "real.txt" && !*is_dir));
        assert!(!plan
            .deleted_paths
            .iter()
            .any(|p| p.starts_with(".ratarmount-spool-")));
        assert_eq!(
            overlay_entry_names(&overlay),
            names_before,
            "real spool must not be created in the overlay"
        );
        assert!(overlay.join(".ratarmount-spool-x").is_file());
    }

    /// Offline `commit_overlay` must not take the live inflight flag.
    #[test]
    fn commit_overlay_is_not_enqueued() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("off-q-seed");
        let extra = generated_payload("off-q-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        // The live connection holds LOCKING_MODE=EXCLUSIVE. Drop that file
        // handle so offline commit can open the sqlite, without dropping `ov`.
        {
            let mut db = ov.db.lock().expect("overlay db");
            *db = Connection::open_in_memory().expect("release overlay db");
        }
        assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
        assert!(
            !ov.persist_inflight_for_test(),
            "offline commit_overlay must not enqueue"
        );
        let src = open_tar_zst_base(&archive, false);
        assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    }

    fn fresh_spool(src: &Path) -> RemoteDownload {
        use std::io::Write;
        let mut file = tempfile::Builder::new()
            .prefix(".ratarmount-spool-")
            .tempfile()
            .unwrap();
        std::io::copy(&mut fs::File::open(src).unwrap(), &mut file).unwrap();
        file.flush().unwrap();
        let len = file.as_file().metadata().unwrap().len();
        RemoteDownload { file, len }
    }

    /// Local `commit_live` does not call the publish hook, even if one is installed.
    #[test]
    fn remote_publish_not_called_for_local() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("loc-seed");
        let extra = generated_payload("loc-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let calls_p = Arc::clone(&calls);
        let archive_dl = archive.clone();
        ov.install_remote_live_commit(
            Box::new(|| {
                Ok(RemoteObjectHead {
                    etag: Some("\"e\"".into()),
                    len: 1,
                })
            }),
            Box::new(move || Ok(fresh_spool(&archive_dl))),
            Box::new(move |_| {
                calls_p.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Duration::from_secs(120),
        );
        assert!(ov
            .commit_live(&archive, |p| reopen_tar_zst(p, false))
            .expect("local commit"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "direct commit_live must not publish"
        );
    }

    /// Regression: prefix-frame delete does not call the publish callback.
    #[test]
    fn earlier_frame_skips_publish() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("efp-prefix");
        let last = generated_payload("efp-last");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("old.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.unlink("/old.txt").expect("unlink prefix member");
        let calls = Arc::new(AtomicU64::new(0));
        let calls_p = Arc::clone(&calls);
        let archive_dl = archive.clone();
        let len = before.len() as u64;
        ov.install_remote_live_commit(
            Box::new(move || {
                Ok(RemoteObjectHead {
                    etag: Some("\"ef\"".into()),
                    len,
                })
            }),
            Box::new(move || Ok(fresh_spool(&archive_dl))),
            Box::new(move |_| {
                calls_p.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Duration::from_secs(120),
        );
        let err = ov
            .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
                panic!("publish/reopen must not run on earlier-frame error")
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("append-only"), "{err}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "prefix-frame delete must not PUT"
        );
        assert!(!ov.interval_disabled());
        assert_eq!(ov.commit_generation(), 0);
        assert_eq!(fs::read(&archive).unwrap(), before);
        assert_eq!(ov.persist_count_for_test(), 1, "splice was attempted once");
    }

    /// Regression: retry forgets only overlay bytes that were uploaded.
    #[test]
    fn publish_500_does_not_disable_interval() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("p500-seed");
        let extra = generated_payload("p500-new");
        let during = generated_payload("p500-during");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        let len = fs::metadata(&archive).unwrap().len();
        let fail_once = Arc::new(AtomicU64::new(1));
        let fail_pub = Arc::clone(&fail_once);
        let archive_dl = archive.clone();
        ov.install_remote_live_commit(
            Box::new(move || {
                Ok(RemoteObjectHead {
                    etag: Some("\"e1\"".into()),
                    len,
                })
            }),
            Box::new(move || Ok(fresh_spool(&archive_dl))),
            Box::new(move |_| {
                if fail_pub.swap(0, Ordering::SeqCst) == 1 {
                    Err(RemotePublishError::Retryable("HTTP 500".into()))
                } else {
                    Ok(())
                }
            }),
            Duration::from_secs(120),
        );
        let gen = ov.commit_generation();
        let err = ov
            .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
                panic!("500 must not reopen")
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("500"), "{err}");
        assert!(!ov.interval_disabled());
        assert_eq!(ov.commit_generation(), gen);
        assert!(
            overlay.join("new.txt").is_file(),
            "original overlay file stays"
        );
        assert_eq!(ov.persist_count_for_test(), 1);

        fs::write(overlay.join("during.txt"), &during).unwrap();
        assert_eq!(
            ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
                reopen_tar_zst(p, false)
            })
            .expect("retry"),
            CommitOutcome::DidWork
        );
        assert_eq!(
            ov.persist_count_for_test(),
            1,
            "Spliced retry with a matching ETag must not persist again"
        );
        assert!(
            !overlay.join("new.txt").exists(),
            "stashed plan file is gone"
        );
        assert!(
            overlay.join("during.txt").is_file(),
            "file created during the failed PUT stays"
        );
        assert_eq!(ov.commit_generation(), gen + 1);
        assert!(!ov.interval_disabled());
    }

    /// Regression: a GCS publish failure is not logged as an S3 publish.
    #[test]
    fn gs_publish_failure_is_not_labeled_s3() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("gs-fail-seed");
        let extra = generated_payload("gs-fail-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        let len = fs::metadata(&archive).unwrap().len();
        let archive_dl = archive.clone();
        ov.install_remote_live_commit_for(
            "gs://bkt/data/a.tar.zst",
            Box::new(move || {
                Ok(RemoteObjectHead {
                    etag: Some("\"e1\"".into()),
                    len,
                })
            }),
            Box::new(move || Ok(fresh_spool(&archive_dl))),
            Box::new(|_| Err(RemotePublishError::Retryable("HTTP 500".into()))),
            Duration::from_secs(120),
        );
        let err = ov
            .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
                panic!("500 must not reopen")
            })
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("gs publish failed:"),
            "GCS failure must name gs, not s3: {err}"
        );
        assert!(!err.contains("s3 publish"), "{err}");
        assert!(overlay.join("new.txt").is_file(), "overlay file stays");
    }

    /// 412 drops `Spliced` and the next tick downloads instead of resplicing.
    #[test]
    fn etag_mismatch_regets_instead_of_resplicing() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("etag-seed");
        let extra = generated_payload("etag-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        let len = fs::metadata(&archive).unwrap().len();
        let downloads = Arc::new(AtomicU64::new(0));
        let downloads_d = Arc::clone(&downloads);
        let archive_dl = archive.clone();
        let fail_once = Arc::new(AtomicU64::new(1));
        let fail_pub = Arc::clone(&fail_once);
        let paths = Arc::new(std::sync::Mutex::new(Vec::<PathBuf>::new()));
        let paths_p = Arc::clone(&paths);
        ov.install_remote_live_commit(
            Box::new(move || {
                Ok(RemoteObjectHead {
                    etag: Some("\"e1\"".into()),
                    len,
                })
            }),
            Box::new(move || {
                downloads_d.fetch_add(1, Ordering::SeqCst);
                Ok(fresh_spool(&archive_dl))
            }),
            Box::new(move |req| {
                paths_p.lock().expect("paths").push(req.staged.clone());
                if fail_pub.swap(0, Ordering::SeqCst) == 1 {
                    Err(RemotePublishError::EtagMismatch("HTTP 412".into()))
                } else {
                    Ok(())
                }
            }),
            Duration::from_secs(120),
        );
        let err = ov
            .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
                panic!("412 must not reopen")
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("412"), "{err}");
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
        assert_eq!(ov.persist_count_for_test(), 1);
        assert_eq!(ov.commit_generation(), 0);
        assert!(overlay.join("new.txt").is_file());
        let first = paths.lock().expect("paths")[0].clone();
        assert!(!first.exists(), "412 must drop the spliced spool");

        assert_eq!(
            ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
                reopen_tar_zst(p, false)
            })
            .expect("redownload tick"),
            CommitOutcome::DidWork
        );
        assert_eq!(downloads.load(Ordering::SeqCst), 2, "next tick downloads");
        assert_eq!(ov.persist_count_for_test(), 2);
        let second = paths.lock().expect("paths")[1].clone();
        assert_ne!(first, second, "must not resplice the old spool");
        assert!(!overlay.join("new.txt").exists());
    }

    fn spool_from_bytes(bytes: &[u8]) -> RemoteDownload {
        use std::io::Write;
        let mut file = tempfile::Builder::new()
            .prefix(".ratarmount-spool-")
            .tempfile()
            .unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
        RemoteDownload {
            file,
            len: bytes.len() as u64,
        }
    }

    fn count_member(bytes: &[u8], dir: &Path, name: &str) -> u32 {
        let stored = dir.join(format!(
            "stored-{}.tar.zst",
            name.trim_start_matches('/').replace('/', "_")
        ));
        fs::write(&stored, bytes).unwrap();
        open_tar_zst_base(&stored, false).versions(name)
    }

    /// Regression: a PUT that lands and then times out must not splice again.
    #[test]
    fn remote_publish_timeout_after_landed_put_keeps_one_member() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("land-seed");
        let extra = generated_payload("land-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        let remote = Arc::new(Mutex::new((
            "\"e1\"".to_string(),
            fs::read(&archive).unwrap(),
        )));
        let remote_h = Arc::clone(&remote);
        let remote_dl = Arc::clone(&remote);
        let remote_pub = Arc::clone(&remote);
        let puts = Arc::new(AtomicU64::new(0));
        let puts_p = Arc::clone(&puts);
        ov.install_remote_live_commit(
            Box::new(move || {
                let g = remote_h.lock().expect("remote");
                Ok(RemoteObjectHead {
                    etag: Some(g.0.clone()),
                    len: g.1.len() as u64,
                })
            }),
            Box::new(move || {
                let bytes = remote_dl.lock().expect("remote").1.clone();
                Ok(spool_from_bytes(&bytes))
            }),
            Box::new(move |req| {
                let n = puts_p.fetch_add(1, Ordering::SeqCst);
                if !req.skip_object_put {
                    let bytes = fs::read(&req.staged).expect("staged");
                    let mut g = remote_pub.lock().expect("remote");
                    g.1 = bytes;
                    g.0 = format!("\"put-{n}\"");
                }
                if n == 0 {
                    Err(RemotePublishError::Retryable(
                        "timeout after the body was stored".into(),
                    ))
                } else {
                    Ok(())
                }
            }),
            Duration::from_millis(200),
        );
        let err = ov
            .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
                panic!("timeout must not reopen")
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("timeout"), "{err}");
        assert_eq!(ov.persist_count_for_test(), 1);
        assert!(!ov.interval_disabled());
        assert_eq!(ov.commit_generation(), 0);
        assert!(overlay.join("new.txt").is_file());

        assert_eq!(
            ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
                reopen_tar_zst(p, false)
            })
            .expect("byte-match retry"),
            CommitOutcome::DidWork
        );
        assert_eq!(
            ov.persist_count_for_test(),
            1,
            "object that already contains the splice must not be persisted again"
        );
        assert!(
            !overlay.join("new.txt").exists(),
            "success path forgets only the stashed plan"
        );
        assert_eq!(ov.commit_generation(), 1);
        assert!(!ov.interval_disabled());
        let stored = remote.lock().expect("remote").1.clone();
        assert_eq!(
            count_member(&stored, dir.path(), "/new.txt"),
            1,
            "one copy of the member"
        );
        assert_eq!(count_member(&stored, dir.path(), "/seed.txt"), 1);
    }

    /// A moved ETag whose bytes differ is a concurrent writer: splice onto that object once.
    #[test]
    fn remote_publish_concurrent_object_is_spliced_once() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("conc-seed");
        let other_seed = generated_payload("conc-other");
        let extra = generated_payload("conc-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let other = dir.path().join("other.tar.zst");
        write_single_frame_tar_zst(&other, &[ustar_file("other.txt", &other_seed)]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        let remote = Arc::new(Mutex::new((
            "\"e1\"".to_string(),
            fs::read(&archive).unwrap(),
        )));
        let remote_h = Arc::clone(&remote);
        let remote_dl = Arc::clone(&remote);
        let remote_pub = Arc::clone(&remote);
        let puts = Arc::new(AtomicU64::new(0));
        let puts_p = Arc::clone(&puts);
        ov.install_remote_live_commit(
            Box::new(move || {
                let g = remote_h.lock().expect("remote");
                Ok(RemoteObjectHead {
                    etag: Some(g.0.clone()),
                    len: g.1.len() as u64,
                })
            }),
            Box::new(move || {
                let bytes = remote_dl.lock().expect("remote").1.clone();
                Ok(spool_from_bytes(&bytes))
            }),
            Box::new(move |req| {
                let n = puts_p.fetch_add(1, Ordering::SeqCst);
                if !req.skip_object_put {
                    let bytes = fs::read(&req.staged).expect("staged");
                    let mut g = remote_pub.lock().expect("remote");
                    g.1 = bytes;
                    g.0 = format!("\"put-{n}\"");
                }
                if n == 0 {
                    Err(RemotePublishError::Retryable(
                        "timeout after the body was stored".into(),
                    ))
                } else {
                    Ok(())
                }
            }),
            Duration::from_millis(200),
        );
        let err = ov
            .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
                panic!("timeout must not reopen")
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("timeout"), "{err}");
        {
            let mut g = remote.lock().expect("remote");
            g.0 = "\"concurrent\"".into();
            g.1 = fs::read(&other).unwrap();
        }
        assert_eq!(
            ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
                reopen_tar_zst(p, false)
            })
            .expect("splice onto concurrent object"),
            CommitOutcome::DidWork
        );
        assert_eq!(ov.persist_count_for_test(), 2);
        let stored = remote.lock().expect("remote").1.clone();
        assert_eq!(count_member(&stored, dir.path(), "/new.txt"), 1);
        assert_eq!(count_member(&stored, dir.path(), "/other.txt"), 1);
        assert_eq!(count_member(&stored, dir.path(), "/seed.txt"), 0);
    }

    /// Regression: a refused partial window forgets the overlay once the object
    /// body already matches the spool, so a remount does not append again.
    #[test]
    fn publish_refuses_partial_window_forgets_matching_object() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = generated_payload("pref-keep");
        let last = generated_payload("last-keep");
        let extra = generated_payload("partial-new");
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("old.txt", &prefix)],
            &[ustar_file("last.txt", &last)],
            false,
        );
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        let remote = Arc::new(Mutex::new((
            "\"e1\"".to_string(),
            fs::read(&archive).unwrap(),
        )));
        let remote_h = Arc::clone(&remote);
        let remote_dl = Arc::clone(&remote);
        let remote_pub = Arc::clone(&remote);
        let puts = Arc::new(AtomicU64::new(0));
        let puts_p = Arc::clone(&puts);
        ov.install_remote_live_commit(
            Box::new(move || {
                let g = remote_h.lock().expect("remote");
                Ok(RemoteObjectHead {
                    etag: Some(g.0.clone()),
                    len: g.1.len() as u64,
                })
            }),
            Box::new(move || {
                let bytes = remote_dl.lock().expect("remote").1.clone();
                Ok(spool_from_bytes(&bytes))
            }),
            Box::new(move |req| {
                let n = puts_p.fetch_add(1, Ordering::SeqCst);
                if !req.skip_object_put {
                    let bytes = fs::read(&req.staged).expect("staged");
                    let mut g = remote_pub.lock().expect("remote");
                    g.1 = bytes;
                    g.0 = format!("\"put-{n}\"");
                }
                if n == 0 {
                    return Err(RemotePublishError::Retryable(
                        "timeout after the body was stored".into(),
                    ));
                }
                assert!(
                    req.skip_object_put,
                    "second publish must see the object that already matches the spool"
                );
                assert!(
                    req.window.window_start > 0,
                    "last-frame splice must keep a partial window"
                );
                Err(RemotePublishError::PointerRefused(
                    "sidecar file table was not rebuilt from the uploaded spool; leaving the previous pointer"
                        .into(),
                ))
            }),
            Duration::from_millis(200),
        );
        let err = ov
            .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
                panic!("timeout must not reopen")
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("timeout"), "{err}");
        assert!(overlay.join("new.txt").is_file());
        assert_eq!(ov.persist_count_for_test(), 1);

        assert_eq!(
            ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
                reopen_tar_zst(p, false)
            })
            .expect("pointer refusal forgets the stashed plan"),
            CommitOutcome::DidWork
        );
        assert!(
            !overlay.join("new.txt").exists(),
            "refused partial window must not leave the overlay file in place"
        );
        assert_eq!(ov.persist_count_for_test(), 1);
        assert!(!ov.interval_disabled());
        let stored = remote.lock().expect("remote").1.clone();
        assert_eq!(count_member(&stored, dir.path(), "/new.txt"), 1);
        assert_eq!(count_member(&stored, dir.path(), "/old.txt"), 1);
        assert_eq!(
            ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
                panic!("empty overlay must not publish")
            })
            .expect("nothing left to splice"),
            CommitOutcome::Nothing
        );
        assert_eq!(ov.persist_count_for_test(), 1);
    }

    /// Regression: remote on-exit must not wait forever for a new interval PUT.
    #[test]
    fn remote_on_exit_bounds_wait_without_disabling() {
        let dir = tempfile::tempdir().unwrap();
        let seed = generated_payload("exit-seed");
        let extra = generated_payload("exit-new");
        let archive = dir.path().join("a.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
        let overlay = dir.path().join("ov");
        let ov = Arc::new(overlay_with_base(
            open_tar_zst_base(&archive, false),
            &overlay,
        ));
        fs::write(overlay.join("new.txt"), &extra).unwrap();
        let puts = Arc::new(AtomicU64::new(0));
        let puts_p = Arc::clone(&puts);
        let archive_dl = archive.clone();
        ov.set_persist_delay_for_test(Duration::from_secs(5));
        ov.set_on_exit_wait_min_for_test(Duration::from_millis(50));
        ov.install_remote_live_commit(
            Box::new(|| {
                Ok(RemoteObjectHead {
                    etag: Some("\"e\"".into()),
                    len: 1,
                })
            }),
            Box::new(move || Ok(fresh_spool(&archive_dl))),
            Box::new(move |_| {
                puts_p.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Duration::from_millis(200),
        );
        let ov_i = Arc::clone(&ov);
        let archive_i = archive.clone();
        let worker = std::thread::spawn(move || {
            ov_i.enqueue_commit(&archive_i, CommitKind::IntervalIdle(Duration::ZERO), |p| {
                reopen_tar_zst(p, false)
            })
        });
        let started = Instant::now();
        while !ov.persist_inflight_for_test() && started.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            ov.persist_inflight_for_test(),
            "interval thread did not take the inflight flag"
        );
        let t0 = Instant::now();
        let err = ov
            .enqueue_commit(&archive, CommitKind::OnExit, |_| unreachable!())
            .unwrap_err();
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "remote on-exit waited {elapsed:?}"
        );
        assert!(
            err.to_string().contains("timed out"),
            "expected timeout, got {err}"
        );
        assert!(!ov.interval_disabled());
        assert_eq!(ov.persist_count_for_test(), 0, "timeout must not splice");
        assert_eq!(ov.commit_generation(), 0);
        assert_eq!(
            puts.load(Ordering::SeqCst),
            0,
            "interval must not start a PUT during the on-exit wait"
        );
        assert!(overlay.join("new.txt").is_file());
        let _ = worker.join().expect("interval thread");
    }

    /// In-memory archive: each path has a body the COW path can read.
    struct MemBase {
        files: BTreeMap<String, FileInfo>,
        bodies: BTreeMap<String, Vec<u8>>,
    }

    impl MemBase {
        fn with(entries: &[(&str, &[u8])]) -> Self {
            let mut files = BTreeMap::new();
            let mut bodies = BTreeMap::new();
            for (path, body) in entries {
                bodies.insert((*path).to_string(), body.to_vec());
                files.insert((*path).to_string(), mem_file_info(path, body.len() as u64));
            }
            Self { files, bodies }
        }

        fn with_dir(path: &str) -> Self {
            let mut files = BTreeMap::new();
            files.insert(
                path.to_string(),
                FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: ratarmount_core::S_IFDIR | 0o755,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                },
            );
            Self {
                files,
                bodies: BTreeMap::new(),
            }
        }
    }

    fn mem_file_info(path: &str, size: u64) -> FileInfo {
        FileInfo {
            size,
            mtime: 0.0,
            mode: ratarmount_core::S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![
                UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                    offset: 0,
                    offsetheader: Some(0),
                    istar: true,
                    issparse: false,
                    isgenerated: false,
                    recursiondepth: 0,
                }),
                UserData::Other(format!("mem:{path}")),
            ],
        }
    }

    impl MountSource for MemBase {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path != "/" {
                return None;
            }
            let mut map = BTreeMap::new();
            for (path, fi) in &self.files {
                let name = path.trim_start_matches('/');
                if !name.is_empty() && !name.contains('/') {
                    map.insert(name.to_string(), fi.clone());
                }
            }
            Some(ListResult::Infos(map))
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(create_root_file_info())
            } else {
                self.files.get(path).cloned()
            }
        }

        fn open(
            &self,
            file_info: &FileInfo,
            _: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            let path = file_info.userdata.iter().rev().find_map(|u| match u {
                UserData::Other(s) => s.strip_prefix("mem:"),
                _ => None,
            });
            let Some(path) = path else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "mem base"));
            };
            let body = self.bodies.get(path).cloned().unwrap_or_default();
            Ok(Box::new(std::io::Cursor::new(body)))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    fn put_overlay_bytes(ov: &WriteOverlay, path: &str, bytes: &[u8]) {
        let fd = ov.create_file(path, 0o644).unwrap();
        let n = unsafe { libc::write(fd, bytes.as_ptr() as *const _, bytes.len()) };
        assert_eq!(n as usize, bytes.len(), "write {path}");
        unsafe { libc::close(fd) };
    }

    fn is_overlay_fi(fi: &FileInfo) -> bool {
        matches!(fi.userdata.last(), Some(UserData::Other(s)) if s.starts_with("overlay:"))
    }

    fn deleted_flag(ov: &WriteOverlay, path: &str) -> Option<i64> {
        ov.files_deleted_flag(path).expect("files row")
    }

    fn host_ino(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(path).unwrap().ino()
    }

    fn fd_ino(fd: &impl std::os::unix::io::AsRawFd) -> u64 {
        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
        assert_eq!(rc, 0, "fstat: {}", io::Error::last_os_error());
        st.st_ino as u64
    }

    /// Regression: rename-over must not unlink first (#88). Overlay-backed,
    /// archive-only, and tombstoned targets each end on the new bytes.
    #[test]
    fn rename_over_overlay_archive_and_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        put_overlay_bytes(&ov, "/final", b"old-dest");
        put_overlay_bytes(&ov, "/swap", b"new-src");
        let parked = ov
            .rename_parked("/swap", "/final")
            .expect("overlay rename")
            .expect("overlay-backed target is parked");
        let (fi, fd) = parked.into_parts();
        assert!(fd.is_some(), "regular file park keeps an fd");
        assert_eq!(fi.size, b"old-dest".len() as u64);
        drop(fd);
        assert_eq!(fs::read(overlay.join("final")).unwrap(), b"new-src");
        assert!(ov.lookup("/swap", 0).is_none());
        assert!(!ov.is_deleted("/swap"));
        assert!(!ov.is_deleted("/final"));
        let fi = ov.lookup("/final", 0).expect("final");
        assert!(is_overlay_fi(&fi));
        assert_eq!(deleted_flag(&ov, "/final"), Some(0));
        assert_eq!(deleted_flag(&ov, "/swap"), None);
        ov.mkdir("/dir", 0o755).unwrap();
        put_overlay_bytes(&ov, "/file", b"keep");
        let err = ov.rename("/file", "/dir").expect_err("directory target");
        match err {
            OverlayError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::AlreadyExists, "{e}");
            }
            other => panic!("expected Io, got {other}"),
        }
        assert_eq!(fs::read(overlay.join("file")).unwrap(), b"keep");
        assert!(ratarmount_core::is_dir_mode(
            ov.lookup("/dir", 0).expect("dir").mode
        ));

        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[
            ("/src", b"archive-src"),
            ("/final", b"archive-final"),
        ])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
        assert!(!is_overlay_fi(&ov.lookup("/final", 0).unwrap()));
        let parked = ov.rename_parked("/src", "/final").expect("archive rename");
        assert!(parked.is_none(), "archive-only target has no host inode");
        assert_eq!(fs::read(overlay.join("final")).unwrap(), b"archive-src");
        assert!(is_overlay_fi(&ov.lookup("/final", 0).unwrap()));
        assert!(
            ov.lookup("/src", 0).is_none(),
            "archive source is tombstoned"
        );
        assert!(ov.is_deleted("/src"));
        assert!(!ov.is_deleted("/final"));
        assert_eq!(deleted_flag(&ov, "/src"), Some(1));
        assert_eq!(deleted_flag(&ov, "/final"), Some(0));
        drop(ov);
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert!(
            ov.is_deleted("/src"),
            "persisted tombstone hides the archive source"
        );
        assert_eq!(fs::read(overlay.join("final")).unwrap(), b"archive-src");
        assert!(is_overlay_fi(&ov.lookup("/final", 0).unwrap()));

        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/final", b"archived")])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        ov.unlink("/final").unwrap();
        assert!(ov.lookup("/final", 0).is_none());
        assert!(ov.is_deleted("/final"));
        assert!(!overlay.join("final").exists());
        put_overlay_bytes(&ov, "/swap", b"replacement");
        let parked = ov
            .rename_parked("/swap", "/final")
            .expect("rename over tombstone");
        assert!(parked.is_none(), "tombstoned target has no host inode yet");
        assert!(!ov.is_deleted("/final"));
        assert!(is_overlay_fi(&ov.lookup("/final", 0).expect("visible")));
        assert_eq!(fs::read(overlay.join("final")).unwrap(), b"replacement");
        assert_eq!(deleted_flag(&ov, "/final"), Some(0));
        assert!(ov.lookup("/swap", 0).is_none());
    }

    /// Lookup oracles must fail instead of spinning when the in-memory rename
    /// update disappears. `thread::scope` joins every child, so a parent assert
    /// that never sets `stop` would hang the child until the job is killed.
    const LOOKUP_ORACLE_DEADLINE: Duration = Duration::from_secs(10);

    struct StopLookupOnDrop<'a>(&'a AtomicBool);

    impl Drop for StopLookupOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn assert_lookup_oracle_deadline(deadline: Instant, waiting_for: &str) {
        assert!(
            Instant::now() < deadline,
            "lookup loop exceeded 10s waiting for {waiting_for}; a missing in-memory rename update must fail the test, not hang"
        );
    }

    /// Regression: a visible rename-over target never resolves as missing (#88).
    #[test]
    fn rename_visible_lookup_never_none() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        put_overlay_bytes(&ov, "/final", b"seed");
        let nones = AtomicU64::new(0);
        let samples = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        let some_to_none = std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let deadline = Instant::now() + LOOKUP_ORACLE_DEADLINE;
                let mut prev = true;
                let mut flips = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    assert_lookup_oracle_deadline(deadline, "the rename loop to stop");
                    let some = ov.lookup("/final", 0).is_some();
                    samples.fetch_add(1, Ordering::SeqCst);
                    if !some {
                        nones.fetch_add(1, Ordering::SeqCst);
                    }
                    if prev && !some {
                        flips += 1;
                    }
                    prev = some;
                }
                flips
            });
            // Drop sets `stop` before `handle` joins, including when an assert
            // panics. Declared after `handle` so it runs first.
            let _stop_on_unwind = StopLookupOnDrop(&stop);
            let start = Instant::now();
            while samples.load(Ordering::SeqCst) == 0 {
                assert!(
                    start.elapsed() < Duration::from_secs(2),
                    "lookup loop did not start"
                );
                std::thread::yield_now();
            }
            for i in 0..80 {
                put_overlay_bytes(&ov, "/swap", format!("n{i:04}").as_bytes());
                ov.rename("/swap", "/final").expect("rename");
            }
            stop.store(true, Ordering::SeqCst);
            handle.join().expect("lookup thread")
        });
        assert!(samples.load(Ordering::SeqCst) > 0);
        assert_eq!(
            nones.load(Ordering::SeqCst),
            0,
            "visible target was None in {} lookups",
            samples.load(Ordering::SeqCst)
        );
        assert_eq!(some_to_none, 0);
        assert_eq!(fs::read(overlay.join("final")).unwrap(), b"n0079");
        assert!(ov.lookup("/swap", 0).is_none());
    }

    /// Regression: a tombstoned target stays missing until the rename commits,
    /// then becomes visible once (#88).
    #[test]
    fn rename_tombstone_lookup_none_to_some_once() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(
            Arc::new(MemBase::with(&[("/final", b"archived")])) as Arc<dyn MountSource>,
            &overlay,
        )
        .unwrap();
        ov.unlink("/final").unwrap();
        assert!(ov.lookup("/final", 0).is_none());
        let seen_none = AtomicBool::new(false);
        let none_to_some = AtomicU64::new(0);
        let some_to_none = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let deadline = Instant::now() + LOOKUP_ORACLE_DEADLINE;
                let mut prev = false;
                let mut saw_none = false;
                while !stop.load(Ordering::SeqCst) {
                    assert_lookup_oracle_deadline(deadline, "stop after None->Some");
                    let some = ov.lookup("/final", 0).is_some();
                    if !some {
                        saw_none = true;
                        seen_none.store(true, Ordering::SeqCst);
                    }
                    if !prev && some && saw_none {
                        none_to_some.fetch_add(1, Ordering::SeqCst);
                    }
                    if prev && !some {
                        some_to_none.fetch_add(1, Ordering::SeqCst);
                    }
                    prev = some;
                    std::thread::yield_now();
                }
            });
            // Drop sets `stop` before `handle` joins, including when an assert
            // panics. Declared after `handle` so it runs first.
            let _stop_on_unwind = StopLookupOnDrop(&stop);
            let start = Instant::now();
            while !seen_none.load(Ordering::SeqCst) {
                assert!(
                    start.elapsed() < Duration::from_secs(2),
                    "lookup loop did not observe the tombstone"
                );
                std::thread::yield_now();
            }
            put_overlay_bytes(&ov, "/swap", b"replacement");
            ov.rename("/swap", "/final").unwrap();
            let start = Instant::now();
            while none_to_some.load(Ordering::SeqCst) == 0 {
                assert!(
                    start.elapsed() < LOOKUP_ORACLE_DEADLINE,
                    "lookup loop exceeded 10s waiting for None->Some; a missing in-memory rename update must fail the test, not hang (some_to_none={})",
                    some_to_none.load(Ordering::SeqCst)
                );
                std::thread::yield_now();
            }
            stop.store(true, Ordering::SeqCst);
            handle.join().expect("lookup thread");
        });
        assert_eq!(none_to_some.load(Ordering::SeqCst), 1);
        assert_eq!(some_to_none.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(overlay.join("final")).unwrap(), b"replacement");
    }

    /// Regression: a failed tombstone transaction after the host rename still
    /// returns success. When every retry fails, durable state matches the #88
    /// crash table and the rows sit in `pending_rows`. Drop tries one last
    /// replay; when that also fails, the queue is lost the same way a process
    /// crash loses it. This session's tombstones match the completed rename.
    /// Same-session replay is covered by the commit test.
    #[test]
    fn rename_tx_failure_matches_crash_table() {
        // Visible `to`, archive `from`: `from` reappears from the archive.
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/src", b"archive-src")])) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap());
        put_overlay_bytes(&ov, "/dst", b"old-dest");
        let probe = Arc::downgrade(&ov);
        let host = overlay.clone();
        // The one-shot hook fails only the first attempt and does not consume a
        // failure. Two retries consume 2. Drop's replay gets three more attempts;
        // 8 leaves those failing so the queue is lost like a crash.
        ov.set_rename_tx_failures(8);
        ov.set_rename_before_tx_hook(Some(Box::new(move || {
            let probe = probe.upgrade().expect("overlay");
            assert_eq!(fs::read(host.join("dst")).unwrap(), b"archive-src");
            assert!(!host.join("src").exists());
            let src = probe.lookup("/src", 0).expect("archive from reappears");
            assert!(
                !is_overlay_fi(&src),
                "crash window serves the archive member"
            );
            assert!(is_overlay_fi(&probe.lookup("/dst", 0).unwrap()));
            assert_eq!(deleted_flag(&probe, "/src"), None);
            assert_eq!(deleted_flag(&probe, "/dst"), Some(0));
            Err(OverlayError::Msg("injected rename tx failure".into()))
        })));
        ov.rename_parked("/src", "/dst")
            .expect("tx failure still returns success");
        assert!(ov.pending_row_count() >= 1, "queued the failed rename");
        assert!(ov.is_deleted("/src"), "in-memory tombstone applied");
        assert!(ov.lookup("/src", 0).is_none());
        assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));
        assert_eq!(
            deleted_flag(&ov, "/src"),
            None,
            "db still has no from tombstone"
        );
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"archive-src");
        drop(ov);
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        let src = ov
            .lookup("/src", 0)
            .expect("duplicate archive member accepted");
        assert!(!is_overlay_fi(&src));
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"archive-src");
        assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));

        // Overlay-only `from`: lookup is None and a stale deleted=0 row remains.
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = Arc::new(
            WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
                .unwrap(),
        );
        put_overlay_bytes(&ov, "/dst", b"old-dest");
        put_overlay_bytes(&ov, "/src", b"new-src");
        let probe = Arc::downgrade(&ov);
        let host = overlay.clone();
        // Same budget as the archive-from case: Drop's replay must also fail.
        ov.set_rename_tx_failures(8);
        ov.set_rename_before_tx_hook(Some(Box::new(move || {
            let probe = probe.upgrade().expect("overlay");
            assert_eq!(fs::read(host.join("dst")).unwrap(), b"new-src");
            assert!(!host.join("src").exists());
            assert!(probe.lookup("/src", 0).is_none());
            assert!(is_overlay_fi(&probe.lookup("/dst", 0).unwrap()));
            assert_eq!(deleted_flag(&probe, "/src"), Some(0));
            Err(OverlayError::Msg("injected rename tx failure".into()))
        })));
        ov.rename("/src", "/dst").expect("success");
        assert!(ov.pending_row_count() >= 1, "queued the failed rename");
        assert!(!ov.is_deleted("/src"));
        assert!(ov.lookup("/src", 0).is_none());
        assert_eq!(deleted_flag(&ov, "/src"), Some(0), "stale present row kept");
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new-src");
        drop(ov);
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        assert!(ov.lookup("/src", 0).is_none());
        assert_eq!(deleted_flag(&ov, "/src"), Some(0));
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new-src");

        // Tombstoned `to`: hidden until open recovery, which must keep the bytes.
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/dst", b"archived")])) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap());
        ov.unlink("/dst").unwrap();
        put_overlay_bytes(&ov, "/src", b"replacement");
        let probe = Arc::downgrade(&ov);
        let host = overlay.clone();
        // Same budget as the archive-from case: Drop's replay must also fail.
        ov.set_rename_tx_failures(8);
        ov.set_rename_before_tx_hook(Some(Box::new(move || {
            let probe = probe.upgrade().expect("overlay");
            assert_eq!(fs::read(host.join("dst")).unwrap(), b"replacement");
            assert!(probe.lookup("/dst", 0).is_none(), "still tombstoned");
            assert!(probe.is_deleted("/dst"));
            assert_eq!(deleted_flag(&probe, "/dst"), Some(1));
            Err(OverlayError::Msg("injected rename tx failure".into()))
        })));
        ov.rename("/src", "/dst").expect("success");
        assert!(ov.pending_row_count() >= 1, "queued the failed rename");
        assert!(!ov.is_deleted("/dst"), "in-memory clear");
        assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));
        assert_eq!(deleted_flag(&ov, "/dst"), Some(1), "db row still deleted");
        drop(ov);
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert!(!ov.is_deleted("/dst"), "open clears the tombstone");
        assert_eq!(deleted_flag(&ov, "/dst"), Some(0));
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"replacement");
        assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));
    }

    /// Regression: opening the overlay clears a tombstone that has a host file
    /// and leaves a tombstone with no host file (#88). Recovery does not
    /// delete the host file.
    #[test]
    fn clear_tombstone_with_host_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[
            ("/keep.txt", b"archived-keep"),
            ("/other.txt", b"archived-other"),
        ])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
        ov.unlink("/keep.txt").unwrap();
        ov.unlink("/other.txt").unwrap();
        assert!(ov.is_deleted("/keep.txt"));
        assert!(ov.is_deleted("/other.txt"));
        fs::write(overlay.join("keep.txt"), b"hidden-but-committed").unwrap();
        drop(ov);

        let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
        assert!(!ov.is_deleted("/keep.txt"));
        assert!(is_overlay_fi(&ov.lookup("/keep.txt", 0).expect("visible")));
        assert_eq!(
            fs::read(overlay.join("keep.txt")).unwrap(),
            b"hidden-but-committed"
        );
        assert_eq!(deleted_flag(&ov, "/keep.txt"), Some(0));
        assert!(ov.is_deleted("/other.txt"));
        assert!(ov.lookup("/other.txt", 0).is_none());
        assert_eq!(deleted_flag(&ov, "/other.txt"), Some(1));
        assert!(overlay.join(HIDDEN_DB).is_file());
        assert!(overlay.join(OVERLAY_MARKER).is_file());
        drop(ov);

        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert!(!ov.is_deleted("/keep.txt"), "clear was persisted");
        assert!(ov.is_deleted("/other.txt"));
        assert_eq!(
            fs::read(overlay.join("keep.txt")).unwrap(),
            b"hidden-but-committed"
        );
    }

    /// Regression: a host directory with the same name as a tombstone does not
    /// clear that tombstone on open (#88).
    ///
    /// Parent directories are created for nested overlay files (`ensure_parent`
    /// / `create_dir_all`) while a directory tombstone stays set. That directory
    /// is not evidence the archive directory was replaced. Clearing it would
    /// resurrect the archive directory and its children. Only a non-directory
    /// host entry (file or symlink) is the crash window that should become visible.
    #[test]
    fn clear_tombstone_keeps_host_directory() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with_dir("/sub")) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
        ov.rmdir("/sub").expect("tombstone the archive directory");
        assert!(ov.is_deleted("/sub"));
        assert_eq!(deleted_flag(&ov, "/sub"), Some(1));
        assert!(!overlay.join("sub").exists());
        fs::create_dir(overlay.join("sub")).unwrap();
        drop(ov);

        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert!(
            overlay.join("sub").is_dir(),
            "open must not delete the host directory"
        );
        assert!(
            ov.is_deleted("/sub"),
            "a host directory must not clear the tombstone"
        );
        assert_eq!(deleted_flag(&ov, "/sub"), Some(1));
        assert!(ov.lookup("/sub", 0).is_none());
    }

    /// Regression: one injected tombstone failure is retried and the rename
    /// commits. The caller sees success and nothing is queued (#88).
    #[test]
    fn rename_tx_retry_transient() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/src", b"archive-src")])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        ov.set_rename_tx_failures(1);
        ov.rename_parked("/src", "/dst")
            .expect("a single transient failure is retried");
        assert_eq!(ov.pending_row_count(), 0, "retry committed; nothing queued");
        assert_eq!(deleted_flag(&ov, "/src"), Some(1));
        assert_eq!(deleted_flag(&ov, "/dst"), Some(0));
        assert!(ov.is_deleted("/src"));
        assert!(ov.lookup("/src", 0).is_none());
        assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"archive-src");
    }

    /// Regression: queued rename rows are written at the start of the next
    /// `files` update (`mark_present`), not only at commit time (#88).
    #[test]
    fn rename_tx_pending_replays_on_next_db_write() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/src", b"archive-src")])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
        ov.rename("/src", "/dst").expect("rename returns success");
        assert_eq!(ov.pending_row_count(), 1);
        assert_eq!(deleted_flag(&ov, "/src"), None, "sql missed the tombstone");
        assert!(ov.is_deleted("/src"), "memory already hides from");
        ov.set_rename_tx_failures(0);
        put_overlay_bytes(&ov, "/other", b"trigger-replay");
        assert_eq!(
            ov.pending_row_count(),
            0,
            "mark_present replayed the queued rename"
        );
        assert_eq!(deleted_flag(&ov, "/src"), Some(1));
        assert_eq!(deleted_flag(&ov, "/dst"), Some(0));
        assert!(ov.is_deleted("/src"));
        assert!(ov.lookup("/src", 0).is_none());
        assert_eq!(fs::read(overlay.join("other")).unwrap(), b"trigger-replay");
    }

    /// Regression: a persistent tombstone-tx failure must not let `commit_live`
    /// publish an archive `from` that the mount already hides (#88).
    ///
    /// While the fault is installed, commit refuses (the plan would omit the
    /// `from` delete, then the overlay reset would show `from` again). After
    /// the fault is cleared, the next commit replays the queued rows and
    /// deletes `from` from the archive.
    #[test]
    fn rename_tx_pending_commit_refuses_then_replays() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"pending-src-payload\n";
        let tar = make_tiny_tar(dir.path(), &[("src.txt", payload), ("keep.txt", b"keep\n")]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_uncompressed_tar_base(&tar, true), &overlay);
        // Rename retries plus the commit's replay retries.
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 2);
        ov.rename("/src.txt", "/dst.txt")
            .expect("rename returns success");
        assert!(ov.pending_row_count() >= 1);
        assert!(ov.is_deleted("/src.txt"));
        assert!(
            ov.lookup("/src.txt", 0).is_none(),
            "mount hides archive from"
        );
        assert_eq!(
            deleted_flag(&ov, "/src.txt"),
            None,
            "sql has no from tombstone yet"
        );
        assert_eq!(fs::read(overlay.join("dst.txt")).unwrap(), payload);

        match ov.commit_live(&tar, |p| Ok(open_uncompressed_tar_base(p, true))) {
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("refusing to commit") && msg.contains("reappear"),
                    "{msg}"
                );
            }
            Ok(published) => {
                panic!("commit published while rename rows were pending: {published}")
            }
        }
        assert!(
            ov.lookup("/src.txt", 0).is_none(),
            "refused commit must keep from hidden"
        );
        assert!(ov.is_deleted("/src.txt"));
        assert!(
            ov.pending_row_count() >= 1,
            "rows stay queued after the refusal"
        );
        let mid = open_uncompressed_tar_base(&tar, true);
        assert!(
            mid.lookup("/src.txt", 0).is_some(),
            "refused commit must leave the archive member in place"
        );
        assert!(
            mid.lookup("/dst.txt", 0).is_none(),
            "refused commit must not append dst"
        );

        ov.set_rename_tx_failures(0);
        match ov.commit_live(&tar, |p| Ok(open_uncompressed_tar_base(p, true))) {
            Ok(true) => {}
            Err(e) if soft_skip_gnu_tar_commit(&e) => {
                eprintln!("skip: {e}");
                return;
            }
            other => panic!("replay commit: {other:?}"),
        }
        assert_eq!(ov.pending_row_count(), 0, "replay drained the queue");
        let after = open_uncompressed_tar_base(&tar, true);
        assert!(
            after.lookup("/src.txt", 0).is_none(),
            "replayed tombstone deleted archive from; it must not stay as a duplicate"
        );
        assert_eq!(read_member(after.as_ref(), "/dst.txt"), payload);
        assert!(
            ov.lookup("/src.txt", 0).is_none(),
            "mount must not show a duplicate from"
        );
        assert!(after.lookup("/keep.txt", 0).is_some());
        let dst = ov.lookup("/dst.txt", 0).expect("dst visible after commit");
        assert_eq!(dst.size, payload.len() as u64);
    }

    /// Regression: archive `/a` and `/x`, rename `a`→`x` queued, then `x`→`y`
    /// while replay still fails. The second rename must stay behind the first.
    /// After the fault clears, remount must hide `/a` and `/x` and show `/y`
    /// (#88). Replaying `a`→`x` after `x`→`y` would mark `/x` present again.
    #[test]
    fn rename_tx_pending_second_rename_keeps_intermediate_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")]))
            as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
        // First rename's direct attempts, then the second rename's replay.
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 2);
        ov.rename("/a", "/x").expect("a->x returns success");
        assert_eq!(ov.pending_row_count(), 1, "a->x queued");
        assert_eq!(deleted_flag(&ov, "/a"), None, "sql has no a tombstone yet");
        ov.rename("/x", "/y").expect("x->y returns success");
        assert_eq!(ov.pending_row_count(), 2, "x->y appended behind a->x");
        assert_eq!(deleted_flag(&ov, "/a"), None);
        assert_eq!(
            deleted_flag(&ov, "/x"),
            None,
            "x->y must not tombstone x while a->x is still queued"
        );
        assert_eq!(deleted_flag(&ov, "/y"), None);
        assert!(ov.lookup("/a", 0).is_none(), "mount hides a");
        assert!(ov.lookup("/x", 0).is_none(), "mount hides x");
        assert!(is_overlay_fi(&ov.lookup("/y", 0).expect("y visible")));
        assert_eq!(fs::read(overlay.join("y")).unwrap(), b"from-a");

        ov.set_rename_tx_failures(0);
        drop(ov);
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert_eq!(deleted_flag(&ov, "/a"), Some(1));
        assert_eq!(deleted_flag(&ov, "/x"), Some(1), "/x must stay deleted");
        assert_eq!(deleted_flag(&ov, "/y"), Some(0));
        assert!(ov.lookup("/a", 0).is_none(), "remount must not show /a");
        assert!(
            ov.lookup("/x", 0).is_none(),
            "remount must not show /x; a later a->x replay would resurrect it"
        );
        let y = ov.lookup("/y", 0).expect("/y present");
        assert!(is_overlay_fi(&y));
        assert_eq!(fs::read(overlay.join("y")).unwrap(), b"from-a");
    }

    /// Regression: replay holds `pending_rows` across take, the failure path,
    /// and restore. A contending rename must not write `/x` while `a`→`x` is
    /// off the queue (#88).
    #[test]
    fn rename_tx_pending_replay_holds_queue_lock() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")]))
            as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new_for_tests(base, &overlay).unwrap());
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
        ov.rename("/a", "/x").expect("a->x queued");
        assert_eq!(ov.pending_row_count(), 1);
        ov.set_rename_tx_failures(0);

        let in_replay = Arc::new(AtomicBool::new(false));
        let t2_tried = Arc::new(AtomicBool::new(false));
        let lock_was_held = Arc::new(AtomicBool::new(false));
        let in_replay_hook = Arc::clone(&in_replay);
        let t2_tried_hook = Arc::clone(&t2_tried);
        ov.set_replay_hold_hook(Some(Box::new(move || {
            in_replay_hook.store(true, Ordering::SeqCst);
            let start = std::time::Instant::now();
            while !t2_tried_hook.load(Ordering::SeqCst) {
                if start.elapsed() > Duration::from_secs(5) {
                    return Err(OverlayError::Msg(
                        "replay hook timed out waiting for contender".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            // Fail this attempt so the batch is restored while the lock is held.
            Err(OverlayError::Msg("injected replay hold failure".into()))
        })));

        let ov_t2 = Arc::clone(&ov);
        let in_replay_t2 = Arc::clone(&in_replay);
        let t2_tried_t2 = Arc::clone(&t2_tried);
        let lock_was_held_t2 = Arc::clone(&lock_was_held);
        let t2 = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !in_replay_t2.load(Ordering::SeqCst) {
                if start.elapsed() > Duration::from_secs(5) {
                    panic!("replay hook did not run");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            match ov_t2.pending_rows.try_lock() {
                Ok(guard) => {
                    drop(guard);
                    lock_was_held_t2.store(false, Ordering::SeqCst);
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    lock_was_held_t2.store(true, Ordering::SeqCst);
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    panic!("pending queue poisoned");
                }
            }
            t2_tried_t2.store(true, Ordering::SeqCst);
            ov_t2.rename("/x", "/y").expect("contending rename");
        });

        ov.mkdir("/trigger", 0o755).expect("trigger replay");
        t2.join().expect("contender");
        assert!(
            lock_was_held.load(Ordering::SeqCst),
            "replay dropped the queue lock before apply/restore"
        );
        assert_eq!(ov.pending_row_count(), 0, "both renames reached sql");
        assert_eq!(deleted_flag(&ov, "/a"), Some(1));
        assert_eq!(deleted_flag(&ov, "/x"), Some(1));
        assert_eq!(deleted_flag(&ov, "/y"), Some(0));
        assert!(ov.lookup("/a", 0).is_none());
        assert!(ov.lookup("/x", 0).is_none());
        assert!(is_overlay_fi(&ov.lookup("/y", 0).expect("y")));
        assert_eq!(fs::read(overlay.join("y")).unwrap(), b"from-a");
    }

    /// Regression: an unlink tombstone write replays queued rows first (#88).
    /// Skipping that replay would leave archive `/a` visible in SQL.
    #[test]
    fn rename_tx_pending_unlink_replays_before_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base =
            Arc::new(MemBase::with(&[("/a", b"from-a"), ("/z", b"zzz")])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
        ov.rename("/a", "/b").expect("queued");
        assert_eq!(ov.pending_row_count(), 1);
        assert_eq!(deleted_flag(&ov, "/a"), None);
        ov.set_rename_tx_failures(0);
        ov.unlink("/z").expect("unlink replays, then tombstones z");
        assert_eq!(ov.pending_row_count(), 0, "unlink drained the queue");
        assert_eq!(deleted_flag(&ov, "/a"), Some(1));
        assert_eq!(deleted_flag(&ov, "/b"), Some(0));
        assert_eq!(deleted_flag(&ov, "/z"), Some(1));
        assert!(ov.lookup("/a", 0).is_none());
        assert!(ov.lookup("/z", 0).is_none());
        assert!(is_overlay_fi(&ov.lookup("/b", 0).expect("b")));
        assert_eq!(fs::read(overlay.join("b")).unwrap(), b"from-a");
    }

    /// Regression: when replay fails, unlink queues behind the rename instead
    /// of tombstoning `/x` in SQL. A later `a`→`x` replay would otherwise
    /// mark `/x` present and the unlinked name would come back (#88).
    #[test]
    fn rename_tx_pending_unlink_queues_behind_failed_replay() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")]))
            as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 2);
        ov.rename("/a", "/x").expect("queued");
        ov.unlink("/x").expect("unlink returns success");
        assert_eq!(ov.pending_row_count(), 2, "unlink appended");
        assert_eq!(
            deleted_flag(&ov, "/x"),
            None,
            "unlink must not write the tombstone ahead of a->x"
        );
        assert!(ov.lookup("/x", 0).is_none(), "memory already hides x");
        ov.set_rename_tx_failures(0);
        drop(ov);
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert_eq!(ov.pending_row_count(), 0);
        assert_eq!(deleted_flag(&ov, "/a"), Some(1));
        assert_eq!(deleted_flag(&ov, "/x"), Some(1));
        assert!(ov.lookup("/a", 0).is_none());
        assert!(ov.lookup("/x", 0).is_none());
    }

    /// Regression: a failed replay puts the batch back. The next present-mark
    /// stays behind those rows, and a later successful replay still tombstones
    /// `/a` (#88).
    ///
    /// The fault is raised inside `apply_pending_ops_sql` after the first
    /// statement. The transaction rolls back, and
    /// `try_replay_pending_once_with` restores the batch on that error.
    /// Removing that restore drops `a`→`b` and this test's pending count is
    /// no longer 2.
    #[test]
    fn rename_tx_failed_replay_keeps_rows() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/a", b"from-a")])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
        ov.rename("/a", "/b").expect("queued");
        assert_eq!(ov.pending_row_count(), 1);
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
        ov.mkdir("/c", 0o755)
            .expect("present queues behind the failed replay");
        assert_eq!(
            ov.pending_row_count(),
            2,
            "failed replay must keep a->b and queue present /c"
        );
        assert_eq!(deleted_flag(&ov, "/a"), None, "a->b still unsaved");
        assert_eq!(deleted_flag(&ov, "/c"), None, "present /c still unsaved");
        ov.set_rename_tx_failures(0);
        ov.mkdir("/d", 0o755)
            .expect("later present replays the queue");
        assert_eq!(ov.pending_row_count(), 0);
        assert_eq!(deleted_flag(&ov, "/a"), Some(1));
        assert_eq!(deleted_flag(&ov, "/b"), Some(0));
        assert_eq!(deleted_flag(&ov, "/c"), Some(0));
        assert_eq!(deleted_flag(&ov, "/d"), Some(0));
        assert!(ov.lookup("/a", 0).is_none());
    }

    /// Regression: restoring a failed batch keeps those rows ahead of anything
    /// already queued. Appending them would apply `x`→`y` before `a`→`x` and
    /// resurrect `/x` (#88).
    #[test]
    fn restore_pending_front_keeps_older_rows_ahead() {
        let older = vec![PendingFilesOp::Rename {
            from: "/a".to_string(),
            to: "/x".to_string(),
            mode: ratarmount_core::S_IFREG | 0o644,
            hides_from: true,
            xattrs: BTreeMap::new(),
        }];
        let newer = PendingFilesOp::Rename {
            from: "/x".to_string(),
            to: "/y".to_string(),
            mode: ratarmount_core::S_IFREG | 0o644,
            hides_from: true,
            xattrs: BTreeMap::new(),
        };
        let mut queued = vec![newer.clone()];
        restore_pending_front(&mut queued, older.clone());
        assert_eq!(
            queued.first().map(|op| op.to_string()),
            Some(older[0].to_string())
        );
        assert_eq!(queued, vec![older[0].clone(), newer]);

        let mut empty = Vec::new();
        restore_pending_front(&mut empty, older.clone());
        assert_eq!(empty, older);
    }

    /// Regression: on-exit `commit_atomic` is the plan-builder call site that
    /// does not refuse on its own. The plan must still refuse, name `/a` and
    /// `/x`, and warn that an offline `--commit-overlay` would publish them
    /// (#88). `commit_live` refuses before `plan_for_commit`, so it does not
    /// cover deleting the check inside the plan builder.
    #[test]
    fn rename_tx_pending_on_exit_names_reappear_paths() {
        let dir = tempfile::tempdir().unwrap();
        let tar = make_tiny_tar(dir.path(), &[("a", b"from-a"), ("x", b"orig-x")]);
        let overlay = dir.path().join("ov");
        let ov = overlay_with_base(open_uncompressed_tar_base(&tar, true), &overlay);
        // a->x direct attempts, x->y replay, and commit_atomic's replay.
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 3);
        ov.rename("/a", "/x").expect("a->x queued");
        ov.rename("/x", "/y").expect("x->y queued");
        assert_eq!(ov.pending_row_count(), 2);
        assert_eq!(deleted_flag(&ov, "/x"), None);
        let err = ov
            .commit_atomic(&tar)
            .expect_err("on-exit commit must refuse while rows are queued");
        let msg = err.to_string();
        assert!(
            msg.contains("refusing to commit")
                && msg.contains("reappear")
                && msg.contains("/a")
                && msg.contains("/x")
                && msg.contains("offline --commit-overlay"),
            "{msg}"
        );
        assert_eq!(ov.pending_row_count(), 2, "refusal must keep the queue");
        let archive = open_uncompressed_tar_base(&tar, true);
        assert!(
            archive.lookup("/a", 0).is_some(),
            "refused commit must leave /a in the archive"
        );
        assert!(
            archive.lookup("/x", 0).is_some(),
            "refused commit must leave /x in the archive"
        );
        assert!(
            archive.lookup("/y", 0).is_none(),
            "refused commit must not publish /y"
        );
    }

    struct DropCaptureLog;

    static DROP_CAPTURED_LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    impl log::Log for DropCaptureLog {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.level() <= log::Level::Error
        }

        fn log(&self, record: &log::Record<'_>) {
            if !self.enabled(record.metadata()) {
                return;
            }
            if let Ok(mut lines) = DROP_CAPTURED_LOGS.lock() {
                lines.push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    fn install_drop_capture_log() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            log::set_logger(&DropCaptureLog).expect("install overlay drop log capture");
            log::set_max_level(log::LevelFilter::Error);
        });
    }

    /// Regression: drop replays once more, then logs the archive paths that
    /// will reappear and warns that an offline `--commit-overlay` publishes
    /// them (#88).
    #[test]
    fn rename_tx_pending_drop_logs_reappear_paths() {
        install_drop_capture_log();
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")]))
            as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        // Direct attempts plus Drop's three replay attempts.
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 2);
        ov.rename("/a", "/x").expect("queued");
        assert_eq!(ov.pending_row_count(), 1);
        let root = overlay.display().to_string();
        drop(ov);
        let lines = DROP_CAPTURED_LOGS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let hit = lines.iter().any(|line| {
            line.contains(&root)
                && line.contains("/a")
                && line.contains("will reappear")
                && line.contains("offline --commit-overlay")
        });
        assert!(hit, "drop log missing reappear paths for {root}: {lines:?}");
    }

    fn drop_log_reappear_list(root: &str) -> String {
        let lines = DROP_CAPTURED_LOGS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let line = lines
            .iter()
            .rev()
            .find(|line| {
                line.contains(root) && line.contains("these paths will reappear on remount:")
            })
            .unwrap_or_else(|| panic!("drop log missing for {root}: {lines:?}"));
        line.split_once("these paths will reappear on remount: ")
            .and_then(|(_, rest)| rest.split_once('.'))
            .map(|(paths, _)| paths.to_string())
            .unwrap_or_else(|| panic!("could not parse drop log: {line}"))
    }

    /// Regression: a direct writer's retry holds `pending_rows` across the
    /// backoff. Thread B (`x`→`y`) runs in that window. If the lock is free,
    /// B tombstones `/x` and A's retry then marks `/x` present (#88).
    #[test]
    fn rename_tx_retry_window_second_thread_cannot_resurrect_x() {
        for trial in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            let overlay = dir.path().join("ov");
            let base = Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")]))
                as Arc<dyn MountSource>;
            let ov = Arc::new(WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap());
            let entered = Arc::new(AtomicBool::new(false));
            let sampled = Arc::new(AtomicBool::new(false));
            let lock_was_held = Arc::new(AtomicBool::new(false));
            ov.set_rename_before_tx_hook(Some(Box::new(|| {
                Err(OverlayError::Msg(
                    "injected first attempt, before the retry wait".into(),
                ))
            })));
            let entered_hook = Arc::clone(&entered);
            let sampled_hook = Arc::clone(&sampled);
            ov.set_direct_retry_wait_hook(Some(Box::new(move || {
                entered_hook.store(true, Ordering::SeqCst);
                let start = Instant::now();
                while !sampled_hook.load(Ordering::SeqCst) {
                    assert!(
                        start.elapsed() < Duration::from_secs(5),
                        "trial {trial}: contender did not sample the retry window"
                    );
                    std::thread::yield_now();
                }
            })));
            let ov_b = Arc::clone(&ov);
            let entered_b = Arc::clone(&entered);
            let sampled_b = Arc::clone(&sampled);
            let lock_b = Arc::clone(&lock_was_held);
            let contender = std::thread::spawn(move || {
                let start = Instant::now();
                while !entered_b.load(Ordering::SeqCst) {
                    assert!(
                        start.elapsed() < Duration::from_secs(5),
                        "trial {trial}: retry window did not open"
                    );
                    std::thread::yield_now();
                }
                match ov_b.pending_rows.try_lock() {
                    Ok(guard) => {
                        drop(guard);
                        lock_b.store(false, Ordering::SeqCst);
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {
                        lock_b.store(true, Ordering::SeqCst);
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        panic!("trial {trial}: pending queue poisoned");
                    }
                }
                sampled_b.store(true, Ordering::SeqCst);
                ov_b.rename("/x", "/y").expect("x->y");
            });
            ov.rename("/a", "/x").expect("a->x");
            contender.join().expect("contender");
            assert!(
                lock_was_held.load(Ordering::SeqCst),
                "trial {trial}: queue lock was free during the retry wait"
            );
            assert_eq!(
                ov.pending_row_count(),
                0,
                "trial {trial}: both renames committed"
            );
            assert_eq!(deleted_flag(&ov, "/a"), Some(1), "trial {trial}");
            assert_eq!(
                deleted_flag(&ov, "/x"),
                Some(1),
                "trial {trial}: /x resurrected before reopen"
            );
            assert_eq!(deleted_flag(&ov, "/y"), Some(0), "trial {trial}");
            drop(ov);
            let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
            assert_eq!(deleted_flag(&ov, "/a"), Some(1), "trial {trial}");
            assert_eq!(
                deleted_flag(&ov, "/x"),
                Some(1),
                "trial {trial}: /x resurrected on reopen"
            );
            assert_eq!(deleted_flag(&ov, "/y"), Some(0), "trial {trial}");
            assert!(
                ov.lookup("/x", 0).is_none(),
                "trial {trial}: remount shows /x"
            );
            let y = ov.lookup("/y", 0).expect("trial {trial}: /y");
            assert!(is_overlay_fi(&y), "trial {trial}");
            assert_eq!(fs::read(overlay.join("y")).unwrap(), b"from-a");
        }
    }

    /// Regression: `Drop` recovers a poisoned `pending_rows` or `db` lock and
    /// still replays. `expect` on those locks aborts the process (#88).
    #[test]
    fn drop_recovers_poisoned_pending_and_db_locks() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/a", b"from-a")])) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap());
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
        ov.rename("/a", "/b").expect("queued");
        assert_eq!(ov.pending_row_count(), 1);
        ov.set_rename_tx_failures(0);
        {
            let ov_poison = Arc::clone(&ov);
            let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = ov_poison.pending_rows.lock().expect("pending");
                panic!("poison pending rows");
            }));
            assert!(poisoned.is_err(), "pending poison panic was swallowed");
        }
        {
            let ov_poison = Arc::clone(&ov);
            let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = ov_poison.db.lock().expect("db");
                panic!("poison db");
            }));
            assert!(poisoned.is_err(), "db poison panic was swallowed");
        }
        assert!(
            ov.pending_rows.lock().is_err(),
            "pending lock must stay poisoned"
        );
        assert!(ov.db.lock().is_err(), "db lock must stay poisoned");
        let ov = Arc::try_unwrap(ov).unwrap_or_else(|_| panic!("only the test holds the overlay"));
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(ov)));
        assert!(dropped.is_ok(), "drop panicked on a poisoned overlay lock");
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert_eq!(deleted_flag(&ov, "/a"), Some(1), "drop replay must land");
        assert_eq!(deleted_flag(&ov, "/b"), Some(0));
        assert!(ov.lookup("/a", 0).is_none());
    }

    /// Regression: resetting the overlay clears `pending_rows`. A later `files`
    /// write must not replay rows the reset just wiped (#88).
    #[test]
    fn reset_overlay_contents_clears_pending_rows() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/a", b"archive-a")])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
        ov.rename("/a", "/b").expect("queued");
        assert_eq!(ov.pending_row_count(), 1);
        // Clear the fault first. A leftover queue whose replay still fails
        // would leave `/a` without a SQL tombstone, and the lookup below would
        // pass even if the queue survived the reset.
        ov.set_rename_tx_failures(0);
        ov.reset_overlay_contents().expect("reset");
        assert_eq!(
            ov.pending_row_count(),
            0,
            "reset must drop queued files updates"
        );
        ov.mkdir("/c", 0o755).expect("later write");
        assert_eq!(
            ov.pending_row_count(),
            0,
            "later write must not replay wiped rows"
        );
        assert_eq!(
            deleted_flag(&ov, "/a"),
            None,
            "queued a->b must not be rewritten after reset"
        );
        assert!(ov.lookup("/a", 0).is_some(), "archive /a stays visible");
    }

    /// Regression: the drop log lists only names that are still hidden. A later
    /// rename that re-exposes an earlier hidden name must not be listed (#88).
    /// Keeping `hide.remove(to)` out of the fold lists `/reexposed` as well.
    #[test]
    fn rename_tx_pending_drop_log_omits_reexposed_name() {
        install_drop_capture_log();
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[
            ("/still-hidden", b"stay"),
            ("/reexposed", b"old"),
        ])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        put_overlay_bytes(&ov, "/fresh", b"new-bytes");
        ov.set_rename_tx_failures(20);
        ov.unlink("/still-hidden").expect("queue still-hidden");
        ov.unlink("/reexposed").expect("queue reexposed behind it");
        ov.rename("/fresh", "/reexposed")
            .expect("re-expose /reexposed");
        assert_eq!(
            ov.pending_reappear_paths(),
            vec!["/still-hidden".to_string()],
            "fold must drop the re-exposed name"
        );
        let root = overlay.display().to_string();
        drop(ov);
        assert_eq!(
            drop_log_reappear_list(&root),
            "/still-hidden",
            "drop log must not list /reexposed"
        );
    }

    /// Regression: a path SQL already tombstones is not logged as reappearing.
    /// Dropping the `deleted = 1` filter lists `/already` (#88).
    #[test]
    fn rename_tx_pending_drop_log_omits_sql_tombstone() {
        install_drop_capture_log();
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[
            ("/already", b"gone"),
            ("/still-hidden", b"stay"),
        ])) as Arc<dyn MountSource>;
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        ov.unlink("/already").expect("sql tombstone");
        assert_eq!(deleted_flag(&ov, "/already"), Some(1));
        ov.set_rename_tx_failures(20);
        ov.unlink("/still-hidden").expect("queue still-hidden");
        ov.unlink("/already")
            .expect("queue a path sql already hides");
        assert_eq!(
            ov.pending_reappear_paths(),
            vec!["/still-hidden".to_string()],
            "sql tombstone must be filtered out"
        );
        let root = overlay.display().to_string();
        drop(ov);
        assert_eq!(drop_log_reappear_list(&root), "/still-hidden");
    }

    /// Regression: mode 000 must not block rename or unlink (#88). Linux parks
    /// with `O_PATH`; elsewhere a refused open is metadata-only.
    #[test]
    fn park_mode000_rename_and_unlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        put_overlay_bytes(&ov, "/dst", b"old-mode");
        fs::set_permissions(overlay.join("dst"), fs::Permissions::from_mode(0o000)).unwrap();
        let old_ino = host_ino(&overlay.join("dst"));
        put_overlay_bytes(&ov, "/src", b"kept");
        let parked = ov
            .rename_parked("/src", "/dst")
            .expect("mode 000 rename")
            .expect("parked");
        match parked.fd() {
            Some(fd) => assert_eq!(fd_ino(fd), old_ino),
            None => assert_eq!(parked.file_info().size, b"old-mode".len() as u64),
        }
        #[cfg(target_os = "linux")]
        assert!(parked.fd().is_some(), "Linux O_PATH parks a mode-000 file");
        drop(parked);
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"kept");
        assert!(ov.lookup("/src", 0).is_none());

        put_overlay_bytes(&ov, "/locked", b"secret");
        fs::set_permissions(overlay.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
        let old_ino = host_ino(&overlay.join("locked"));
        let parked = ov.unlink_parked("/locked").expect("mode 000 unlink");
        let parked = parked.expect("host file was parked");
        match parked.fd() {
            Some(fd) => assert_eq!(fd_ino(fd), old_ino),
            None => assert_eq!(parked.file_info().size, b"secret".len() as u64),
        }
        #[cfg(target_os = "linux")]
        assert!(
            parked.fd().is_some(),
            "Linux O_PATH parks a mode-000 unlink"
        );
        drop(parked);
        assert!(!overlay.join("locked").exists());
        assert!(ov.lookup("/locked", 0).is_none());
    }

    /// Regression: the parked fd is the pre-rename inode (#88).
    #[test]
    fn park_fstat_old_inode() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        put_overlay_bytes(&ov, "/dst", b"old-inode");
        put_overlay_bytes(&ov, "/src", b"new-inode");
        let old_ino = host_ino(&overlay.join("dst"));
        let src_ino = host_ino(&overlay.join("src"));
        assert_ne!(old_ino, src_ino);
        let parked = ov.rename_parked("/src", "/dst").unwrap().expect("parked");
        let fd = parked.fd().expect("park open");
        assert_eq!(fd_ino(fd), old_ino);
        assert_eq!(host_ino(&overlay.join("dst")), src_ino);
        assert_ne!(host_ino(&overlay.join("dst")), old_ino);
    }

    /// Regression: a symlink target is snapshotted, not opened (#88).
    #[test]
    fn park_symlink_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        ov.create_symlink("/link", "old-target").unwrap();
        put_overlay_bytes(&ov, "/src", b"file");
        let parked = ov
            .rename_parked("/src", "/link")
            .unwrap()
            .expect("symlink parked");
        assert!(parked.fd().is_none(), "symlinks are not opened");
        assert_eq!(parked.file_info().linkname, "old-target");
        assert!(ratarmount_core::is_lnk_mode(parked.file_info().mode));
        let now = ov.lookup("/link", 0).unwrap();
        assert!(!ratarmount_core::is_lnk_mode(now.mode));
        assert!(now.linkname.is_empty());
        assert_eq!(fs::read(overlay.join("link")).unwrap(), b"file");
        assert!(ov.lookup("/src", 0).is_none());
    }

    /// Regression: plain rename and unlink never open the target (#88).
    /// An installed EMFILE park hook must not run, and the park-open counter stays 0.
    #[test]
    fn plain_rename_and_unlink_do_not_park() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        put_overlay_bytes(&ov, "/dst", b"old-dst");
        put_overlay_bytes(&ov, "/src", b"new-src");
        let hook_calls = Arc::new(AtomicU64::new(0));
        let hook_calls2 = Arc::clone(&hook_calls);
        ov.set_park_open_hook(Some(Box::new(move || {
            hook_calls2.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(libc::EMFILE))
        })));
        ov.rename("/src", "/dst")
            .expect("plain rename over a target");
        assert_eq!(ov.park_open_count(), 0);
        assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new-src");
        assert!(!overlay.join("src").exists());
        assert!(ov.lookup("/src", 0).is_none());

        put_overlay_bytes(&ov, "/gone", b"bye");
        ov.unlink("/gone").expect("plain unlink of a target");
        assert_eq!(ov.park_open_count(), 0);
        assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
        assert!(!overlay.join("gone").exists());
        assert!(ov.lookup("/gone", 0).is_none());
    }

    /// Regression: park open EMFILE/ENFILE fails rename with `to` unchanged
    /// and fails unlink with nothing removed (#88).
    #[test]
    fn park_open_emfile_leaves_names_unchanged() {
        for code in [libc::EMFILE, libc::ENFILE] {
            let dir = tempfile::tempdir().unwrap();
            let overlay = dir.path().join("ov");
            let ov =
                WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
                    .unwrap();
            put_overlay_bytes(&ov, "/dst", b"keep-dst");
            put_overlay_bytes(&ov, "/src", b"keep-src");
            ov.set_park_open_hook(Some(Box::new(move || {
                Err(io::Error::from_raw_os_error(code))
            })));
            let err = ov
                .rename_parked("/src", "/dst")
                .expect_err("park open must fail the rename");
            let OverlayError::Io(err) = err else {
                panic!("expected Io, got {err}");
            };
            assert_eq!(err.raw_os_error(), Some(code), "errno {code}");
            assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"keep-dst");
            assert_eq!(fs::read(overlay.join("src")).unwrap(), b"keep-src");
            assert!(ov.lookup("/dst", 0).is_some());
            assert!(ov.lookup("/src", 0).is_some());
            assert!(!ov.is_deleted("/dst"));
            assert_eq!(ov.park_open_count(), 1, "errno {code}");

            put_overlay_bytes(&ov, "/victim", b"stay");
            let err = ov
                .unlink_parked("/victim")
                .expect_err("park open must fail the unlink");
            let OverlayError::Io(err) = err else {
                panic!("expected Io, got {err}");
            };
            assert_eq!(err.raw_os_error(), Some(code), "errno {code}");
            assert_eq!(fs::read(overlay.join("victim")).unwrap(), b"stay");
            assert!(ov.lookup("/victim", 0).is_some());
            assert!(!ov.is_deleted("/victim"));
            assert_eq!(deleted_flag(&ov, "/victim"), Some(0));
            assert_eq!(ov.park_open_count(), 2, "errno {code}");
        }
    }

    /// Regression: the before-tx hook fires once and is not restored (#88).
    /// A single `Err` fails only that attempt; the retry commits the rename.
    #[test]
    fn rename_before_tx_hook_is_one_shot() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        put_overlay_bytes(&ov, "/dst", b"old");
        put_overlay_bytes(&ov, "/src", b"new");
        let calls = Arc::new(AtomicU64::new(0));
        let calls2 = Arc::clone(&calls);
        ov.set_rename_before_tx_hook(Some(Box::new(move || {
            calls2.fetch_add(1, Ordering::SeqCst);
            Err(OverlayError::Msg("injected rename tx failure".into()))
        })));
        ov.rename("/src", "/dst")
            .expect("tx failure still returns success");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            deleted_flag(&ov, "/src"),
            None,
            "retry committed the overlay-only delete"
        );
        assert_eq!(ov.pending_row_count(), 0, "retry did not queue the rename");

        put_overlay_bytes(&ov, "/src2", b"second");
        put_overlay_bytes(&ov, "/dst2", b"old2");
        ov.rename("/src2", "/dst2").expect("second rename");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "hook was not restored");
        assert_eq!(deleted_flag(&ov, "/src2"), None, "second tx committed");
        assert_eq!(fs::read(overlay.join("dst2")).unwrap(), b"second");
    }

    /// Regression: non-Linux park opens add O_NONBLOCK so a FIFO cannot block (#88).
    ///
    /// `#[cfg]` rather than `cfg!`: macOS libc has no `O_PATH`, so that name
    /// must not be compiled off Linux.
    #[cfg(unix)]
    #[test]
    fn park_open_flags_set_nonblock_off_linux() {
        let flags = park_open_flags();
        assert_ne!(flags & libc::O_NOFOLLOW, 0);
        assert_ne!(flags & libc::O_CLOEXEC, 0);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(flags, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            assert_eq!(flags & libc::O_NONBLOCK, 0);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                flags,
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
            );
        }
    }

    /// Regression: park-open EACCES is metadata-only (#88).
    /// `rename_parked` and `unlink_parked` still change the names; `fd` is
    /// `None` and `last_fi` keeps the pre-change attributes.
    #[test]
    fn park_open_eacces_is_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        put_overlay_bytes(&ov, "/dst", b"old-dst");
        put_overlay_bytes(&ov, "/src", b"new-src");
        let dst_before = ov.lookup("/dst", 0).expect("dst metadata");
        ov.set_park_open_hook(Some(Box::new(|| {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        })));
        let parked = ov
            .rename_parked("/src", "/dst")
            .expect("EACCES park open still renames")
            .expect("destination parked");
        assert!(parked.fd().is_none(), "metadata-only park");
        assert_eq!(parked.file_info().size, dst_before.size);
        assert_eq!(parked.file_info().mode, dst_before.mode);
        assert_eq!(parked.file_info().linkname, dst_before.linkname);
        assert_eq!(parked.file_info().size, b"old-dst".len() as u64);
        drop(parked);
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new-src");
        assert!(!overlay.join("src").exists());
        assert!(ov.lookup("/src", 0).is_none());
        assert!(ov.lookup("/dst", 0).is_some());
        assert_eq!(ov.park_open_count(), 1);

        put_overlay_bytes(&ov, "/victim", b"stay-bytes");
        let victim_before = ov.lookup("/victim", 0).expect("victim metadata");
        let parked = ov
            .unlink_parked("/victim")
            .expect("EACCES park open still unlinks")
            .expect("victim parked");
        assert!(parked.fd().is_none(), "metadata-only park");
        assert_eq!(parked.file_info().size, victim_before.size);
        assert_eq!(parked.file_info().mode, victim_before.mode);
        assert_eq!(parked.file_info().linkname, victim_before.linkname);
        assert_eq!(parked.file_info().size, b"stay-bytes".len() as u64);
        drop(parked);
        assert!(!overlay.join("victim").exists());
        assert!(ov.lookup("/victim", 0).is_none());
        assert_eq!(ov.park_open_count(), 2);
    }

    /// Regression: the before-tx hook runs after its mutex guard is dropped (#88).
    #[test]
    fn rename_before_tx_hook_runs_after_mutex_drop() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = Arc::new(
            WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
                .unwrap(),
        );
        put_overlay_bytes(&ov, "/dst", b"old");
        put_overlay_bytes(&ov, "/src", b"new");
        let probe = Arc::downgrade(&ov);
        ov.set_rename_before_tx_hook(Some(Box::new(move || {
            let probe = probe.upgrade().expect("overlay");
            assert!(
                probe.rename_before_tx_hook.try_lock().is_ok(),
                "hook ran while its mutex was still held"
            );
            Ok(())
        })));
        ov.rename("/src", "/dst").expect("rename");
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new");
        assert!(!overlay.join("src").exists());
    }

    fn overlay_entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
    #[test]
    fn regression_oplog_meta_value_reads_the_exclusively_held_connection() {
        let dir = tempfile::tempdir().unwrap();
        let overlay =
            WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[("/base", b"data")])), dir.path())
                .unwrap();
        assert!(overlay.meta_value("journal_path").unwrap().is_none());
        overlay.set_meta("journal_path", "/trace.jsonl").unwrap();
        assert_eq!(
            overlay.meta_value("journal_path").unwrap().as_deref(),
            Some("/trace.jsonl")
        );
        assert_eq!(
            overlay.base_serving_layer("/base"),
            Some(crate::LayerIndex::Base)
        );
        assert_eq!(overlay.base_serving_layer("/missing"), None);
    }

    /// Regression (Ilya #2): writes under the virtual `/.ratarmount-control`
    /// folder landed in the overlay. Reserved only while the control folder is
    /// served; every entry point refuses with `PermissionDenied`.
    #[cfg(unix)]
    #[test]
    fn regression_control_name_reserved_at_every_entry_point() {
        type Op = fn(&WriteOverlay, &str) -> io::Result<()>;
        let ops: Vec<(&str, Op)> = vec![
            ("create_file", |o, p| {
                o.create_file(p, 0o644).map(close_fd).map_err(into_io)
            }),
            ("open O_CREAT", |o, p| {
                o.open_overlay_fd_with_mode(p, libc::O_CREAT | libc::O_WRONLY, 0o644)
                    .map(close_fd)
                    .map_err(into_io)
            }),
            ("open O_TRUNC", |o, p| {
                o.open_overlay_fd_with_mode(p, libc::O_TRUNC | libc::O_WRONLY, 0o644)
                    .map(close_fd)
                    .map_err(into_io)
            }),
            ("mkdir", |o, p| o.mkdir(p, 0o755).map_err(into_io)),
            ("symlink", |o, p| o.create_symlink(p, "t").map_err(into_io)),
            ("unlink", |o, p| o.unlink(p).map_err(into_io)),
            ("rmdir", |o, p| o.rmdir(p).map_err(into_io)),
            ("truncate", |o, p| o.truncate(p, 0).map_err(into_io)),
            ("rename source", |o, p| {
                o.rename(p, "/dest").map_err(into_io)
            }),
            ("rename dest", |o, p| o.rename("/a", p).map_err(into_io)),
            ("set_xattr", |o, p| {
                o.set_xattr(p, "user.k", b"v", 0).map_err(into_io)
            }),
            ("remove_xattr", |o, p| {
                o.remove_xattr(p, "user.k").map_err(into_io)
            }),
            ("chmod", |o, p| {
                let m = OverlayMetadata {
                    mode: Some(0o600),
                    ..Default::default()
                };
                o.set_attributes(p, None, &m).map_err(into_io)
            }),
            ("utimens", |o, p| {
                let m = OverlayMetadata {
                    mtime: Some(5.0),
                    ..Default::default()
                };
                o.set_attributes(p, None, &m).map_err(into_io)
            }),
            ("set_metadata", |o, p| {
                let m = OverlayMetadata {
                    mode: Some(0o600),
                    ..Default::default()
                };
                o.set_metadata(p, &m).map_err(into_io)
            }),
            ("set_attributes size", |o, p| {
                o.set_attributes(p, Some(0), &OverlayMetadata::default())
                    .map_err(into_io)
            }),
        ];
        fn close_fd(fd: i32) {
            unsafe { libc::close(fd) };
        }
        fn into_io(e: OverlayError) -> io::Error {
            match e {
                OverlayError::Io(e) => e,
                other => io::Error::other(other.to_string()),
            }
        }
        let spellings = [
            "/.ratarmount-control/x",
            "./.ratarmount-control/x",
            "//.ratarmount-control/x",
            "/a/../.ratarmount-control/x",
            "/.ratarmount-control",
        ];
        // The base already holds the reserved name, for unlink/xattr/chmod/rename-from.
        let base = || {
            Arc::new(MemBase::with(&[
                ("/a", b"a"),
                ("/.ratarmount-control/x", b"x"),
                ("/sub/.ratarmount-control/x", b"x"),
            ])) as Arc<dyn MountSource>
        };
        let td = tempfile::tempdir().unwrap();
        let mut on = WriteOverlay::new_for_tests(base(), td.path()).unwrap();
        on.set_control_reserved(true);
        for (name, op) in &ops {
            for path in spellings {
                let err = op(&on, path).expect_err(&format!("{name} {path}"));
                assert_eq!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied,
                    "{name} {path}: {err}"
                );
            }
            // Names that only look similar stay ordinary (the error, if any, is not the refusal).
            for path in ["/sub/.ratarmount-control/x", "/.ratarmount-controlx"] {
                if let Err(e) = op(&on, path) {
                    assert!(
                        !e.to_string().contains("reserved control folder"),
                        "{name} {path}: {e}"
                    );
                }
            }
        }
        assert!(!td.path().join(".ratarmount-control").exists());
        // Off (no --control-interface, or --control-socket-only): ordinary names.
        let td = tempfile::tempdir().unwrap();
        let off = WriteOverlay::new_for_tests(base(), td.path()).unwrap();
        off.create_file("/.ratarmount-control/new", 0o644)
            .map(close_fd)
            .unwrap();
        off.mkdir("/.ratarmount-control/d", 0o755).unwrap();
        off.set_xattr("/.ratarmount-control/x", "user.k", b"v", 0)
            .unwrap();
        for path in spellings {
            assert!(is_control_reserved_path(path), "{path}");
        }
        assert!(!is_control_reserved_path("/sub/.ratarmount-control/x"));
        assert!(!is_control_reserved_path("/.ratarmount-controlx"));
    }
}
