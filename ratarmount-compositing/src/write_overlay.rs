//! Write overlay: redirect creates/writes/deletes to a host folder.
//! Mirrors Python `WritableFolderMountSource` (subset) + `commit_overlay`.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
#[expect(
    clippy::disallowed_types,
    reason = r###"internal-read:v1 {"id":"IR-E0005-T01","item":"ratarmount_compositing::write_overlay","disposition":"support","category":"builder-type-support","reason":"Builder type support: Import the FsOpenOptions alias used by overlay output and no-follow builder helpers.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
)]
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
    materialize_open, open_seekable_zstd, open_seekable_zstd_with_threads, scan_zstd_frames_path,
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

/// Persistent overlay-scoped coordination, never a payload or bundle member.
pub(crate) const SEAL_COMMIT_LOCK: &str = ".ratarmount.overlay.seal-commit.lock";

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
        || name.eq_ignore_ascii_case(SEAL_COMMIT_LOCK)
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
pub(crate) fn overlay_markers(root: &Path) -> Result<Vec<PathBuf>> {
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
            Err(e) => return Err(io_with_path(e, "cannot stat the overlay marker", &p)),
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

/// What is at an overlay directory's database path (R10-B, #150).
///
/// One classifier for every caller that must tell "no record" from "a lost
/// record" from "a record to open". It never opens anything: `lstat` of the
/// entry, `stat` through it (the way `Connection::open` follows a symlink),
/// `lstat` of the two marker names.
#[derive(Debug)]
pub enum DbEntry {
    /// Nothing at the database path and no marker: a raw directory, or an
    /// overlay about to be created. The only "no record".
    Absent,
    /// A marker remains (the overlay was used) but the database is gone:
    /// missing, a dangling symlink, or (`empty`) a 0-byte file. A LOST
    /// record, never "no record".
    Lost { markers: Vec<PathBuf>, empty: bool },
    /// A regular file (directly or through a symlink) that may be a record;
    /// `metadata` is the followed `stat` (`is_file()` always holds, so its
    /// `(dev, ino)` is the file SQLite would open). It does not certify the
    /// contents or that the file is readable: the validated open decides.
    Present {
        marked: bool,
        metadata: fs::Metadata,
    },
}

/// Classify `dir`'s overlay database entry; see [`DbEntry`]. Errors: a marker
/// that is not a regular file; a database entry that is a directory, FIFO,
/// device or socket (directly or through a symlink); an unmarked dangling
/// symlink; and EVERY other `lstat` or followed-`stat` error (`ENOTDIR`,
/// `EACCES`, `ELOOP`, `EIO`, ...), which is never read as "present" or
/// "absent": an unresolved target proves nothing about the record.
pub fn overlay_db_entry(dir: &Path) -> Result<DbEntry> {
    let markers = overlay_markers(dir)?;
    let marked = !markers.is_empty();
    Ok(match overlay_db_regular(&dir.join(HIDDEN_DB), marked)? {
        None if marked => DbEntry::Lost {
            markers,
            empty: false,
        },
        None => DbEntry::Absent,
        Some(metadata) if marked && metadata.len() == 0 => DbEntry::Lost {
            markers,
            empty: true,
        },
        Some(metadata) => DbEntry::Present { marked, metadata },
    })
}

/// [`overlay_db_entry`] of the database file `db` itself (Fable r11 N2): the
/// overlay directory's classification when `db` is named [`HIDDEN_DB`] (its
/// markers count), else the type of `db` alone, never marked (a staging copy,
/// a test's `real.sqlite`).
pub(crate) fn overlay_db_entry_for(db: &Path) -> Result<DbEntry> {
    if db.file_name() == Some(std::ffi::OsStr::new(HIDDEN_DB)) {
        return overlay_db_entry(db.parent().unwrap_or(Path::new("")));
    }
    Ok(match overlay_db_regular(db, false)? {
        None => DbEntry::Absent,
        Some(metadata) => DbEntry::Present {
            marked: false,
            metadata,
        },
    })
}

/// Nothing at all is at `dir`'s overlay database path and no marker says the
/// overlay was used ([`DbEntry::Absent`]). A symlink (dangling or not), a
/// directory, a FIFO, an entry that cannot be statted (R7-E2, R10-B) or a lost
/// record is not absent, so the caller takes the database path, which opens
/// it or refuses. Never `exists()`, `is_file()` or `metadata()`: they follow a
/// dangling symlink to "missing".
pub fn overlay_db_absent(dir: &Path) -> bool {
    matches!(overlay_db_entry(dir), Ok(DbEntry::Absent))
}

/// The #96 refusal for a [`DbEntry::Lost`] record in `dir`.
pub fn lost_record_error(dir: &Path, markers: &[PathBuf]) -> OverlayError {
    OverlayError::Msg(format!(
        "write overlay {} was used before but its database {} is missing or empty; \
         its deletions would be lost (unlinked archive members reappear). \
         Restore the database, or use a new empty folder{}",
        dir.display(),
        dir.join(HIDDEN_DB).display(),
        discard_hint(&markers.iter().map(|p| p.as_path()).collect::<Vec<_>>())
    ))
}

#[cfg(test)]
thread_local! {
    /// Test seam (R10-B): while set, every followed `stat` of an overlay
    /// database in [`overlay_db_regular`] on this thread fails with this errno.
    pub(crate) static FOLLOWED_STAT_ERRNO: std::cell::Cell<Option<i32>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Test seam (#160 fix round): when set, a `-w` open runs it once in its
    /// schema step and then fails there, taking the failed-open cleanup.
    pub(crate) static FAIL_SCHEMA_STEP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// The `stat` through the database entry ([`FOLLOWED_STAT_ERRNO`] in tests).
fn followed_db_stat(db_path: &Path) -> io::Result<fs::Metadata> {
    #[cfg(test)]
    if let Some(errno) = FOLLOWED_STAT_ERRNO.with(|seam| seam.get()) {
        return Err(io::Error::from_raw_os_error(errno));
    }
    fs::metadata(db_path)
}

/// `e` (its kind kept) with what failed on which path in its text.
fn io_with_path(e: io::Error, what: &str, path: &Path) -> OverlayError {
    OverlayError::Io(io::Error::new(
        e.kind(),
        format!("{what} {}: {e}", path.display()),
    ))
}

/// The overlay database at `db_path` as `Connection::open` would see it:
/// `None` when nothing is there (an `lstat` NotFound), else the metadata of
/// the regular file it is (or a symlink points to). A directory, a dangling
/// symlink or any other non-regular file is refused; any other error of the
/// followed `stat` propagates with the path (R10-B). `marked`: the overlay
/// was used before (#96); a dangling symlink then reads as a missing database,
/// which the caller refuses with the #96 wording.
fn overlay_db_regular(db_path: &Path, marked: bool) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(db_path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_with_path(e, "cannot stat the overlay database", db_path)),
        Ok(_) => {}
    }
    match followed_db_stat(db_path) {
        Ok(m) if m.is_file() => Ok(Some(m)),
        // A directory or any other non-regular file: the shared open's text.
        Ok(m) => Err(OverlayError::Msg(crate::overlay_db::not_regular_message(
            db_path, &m,
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound && marked => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(OverlayError::Msg(format!(
            "overlay database {} is a symlink to a file that does not exist; it is not \
             created through the symlink: restore its target or remove the symlink",
            db_path.display()
        ))),
        Err(e) => Err(OverlayError::Io(io::Error::new(
            e.kind(),
            format!(
                "cannot resolve the overlay database {} (it is neither proved present nor \
                 missing): {e}",
                db_path.display()
            ),
        ))),
    }
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
    /// `(dev, ino)` of the database file this mount opened (the validated
    /// open's post-open path stat). Recovery refuses when the database path
    /// no longer names it (R10-B).
    db_id: Option<(u64, u64)>,
    /// The database inode stays registered as open while the mount lives
    /// (R10-C). After `db`: dropped once the connection is closed.
    _db_registration: Option<ratarmount_core::db_inodes::DbInodeRegistration>,
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0006-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::write_at_inner","disposition":"out-of-family","category":"descriptor-control","reason":"Read existing overlay output descriptor flags before choosing the append/write path.","creation":{"policy":"none","basis":"F_GETFL queries an already-open file; it creates and duplicates no descriptor."}}"###
            )]
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0007-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::open_with_create_info","disposition":"output-owner","category":"overlay-directory","reason":"Create a missing overlay root after planning exclusions and rejecting an existing non-directory.","creation":{"policy":"recursive-directory","basis":"The overlay owner creates the requested tree with std directory defaults and umask, then canonicalizes the root."}}"###
            )]
            fs::create_dir_all(&root)?;
        }
        // Canonical root so confinement checks use a stable absolute prefix.
        let root = root.canonicalize().map_err(OverlayError::Io)?;
        let db_path = root.join(HIDDEN_DB);
        let found_marker = overlay_marker(&root)?;
        let marker = found_marker.is_some();
        let marker_path = found_marker.unwrap_or_else(|| root.join(OVERLAY_MARKER));
        // Classify without treating a dangling symlink as "no database"
        // (R7-E2), nor an unresolvable one as anything (R10-B). The checked
        // NOFOLLOW open below refuses symlinks, including a same-inode swap.
        let db_len = match overlay_db_entry(&root)? {
            DbEntry::Absent => None,
            DbEntry::Lost { markers, .. } => return Err(lost_record_error(&root, &markers)),
            DbEntry::Present { metadata, .. } => Some(metadata.len()),
        };
        let opened = crate::overlay_db::open_overlay_db_required(
            &db_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            crate::DbName::Path,
            marker,
        )
        .map_err(|error| match error {
            crate::OverlayDbError::NotRegular(message) => {
                OverlayError::Msg(format!("{message}; then retry the writable mount"))
            }
            other => other.into(),
        })?;
        let required = marker || opened.required_record();
        let db_id = opened.id();
        let (mut conn, db_registration) = opened.into_parts();
        let had_files = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'files'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !had_files && (required || db_len.is_some_and(|n| n > 0)) {
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
        // Remove a database file that was absent before this call (a stat
        // before SQLite's open; an empty file planted between that stat and
        // the open is indistinguishable, see `Expect::Fresh`), so a failed
        // first open leaves the folder as it was (not "non-empty DB without
        // files"); only while the name still holds the inode SQLite opened.
        // A database that existed (0 bytes included) is left to SQLite's own
        // rollback: truncating it through a descriptor of our own would close
        // that descriptor, which releases every fcntl lock this process holds
        // on the file, another connection's included (#160). If that rollback
        // itself fails, the database is left non-empty without `files`, and
        // the next open refuses it (#96) instead of starting over.
        let undo_new_db = |conn: Connection| {
            drop(conn);
            let still_ours = || match (db_id, fs::symlink_metadata(&db_path)) {
                (Some(id), Ok(m)) => crate::overlay_db::file_id(&m) == Some(id),
                // Off Unix there is no identity to compare.
                (None, Ok(_)) => true,
                (_, Err(_)) => false,
            };
            if db_len.is_none() && still_ours() {
                for suf in ["", "-journal", "-shm", "-wal"] {
                    let _ = fs::remove_file(root.join(format!("{HIDDEN_DB}{suf}")));
                }
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
            #[cfg(test)]
            if let Some(hook) = FAIL_SCHEMA_STEP.with(|seam| seam.borrow_mut().take()) {
                hook();
                return Err(OverlayError::Msg("test: schema step failed".into()));
            }
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0162-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::open_with_create_info","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"directory handle opened only to fsync a directory entry","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
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
            db_id,
            _db_registration: db_registration,
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0008-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::ensure_parent","disposition":"output-owner","category":"overlay-directory","reason":"Materialize an archive parent directory inside the checked overlay root before a mutation.","creation":{"policy":"recursive-directory","basis":"Only a missing parent represented as a base directory is materialized; host directory creation keeps existing default/umask behavior."}}"###
            )]
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0009-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::ensure_modifiable_inner","disposition":"output-owner","category":"overlay-directory","reason":"Materialize a base directory during copy-on-write and then apply the archived directory metadata.","creation":{"policy":"recursive-directory","basis":"The path passes overlay confinement checks; set_host_metadata restores the base directory metadata after creation."}}"###
            )]
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
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0010-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::ensure_modifiable_inner","disposition":"output-owner","category":"overlay-directory","reason":"Create the confined parent before publishing a base symlink as a symlink during copy-on-write.","creation":{"policy":"recursive-directory","basis":"Parent creation uses existing std defaults; the symlink operation and its metadata are handled separately."}}"###
                )]
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
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0011-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::copy_with_reservation","disposition":"output-owner","category":"overlay-directory","reason":"Materialize a directory in the reservation-aware copy-on-write branch before applying its base metadata.","creation":{"policy":"recursive-directory","basis":"Confinement and mutation checks precede creation; archived directory metadata is restored afterward."}}"###
                )]
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0163-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::clone_overlay_fd","disposition":"residual","reason":"duplicates a live overlay handle (no pathname open); overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        self.register_write_fd(duplicate, path);
        Ok(unsafe {
            {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0164-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::clone_overlay_fd","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )]
                let __inventory_value_0 = File::from_raw_fd(duplicate);
                __inventory_value_0
            }
        })
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0165-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::close_overlay_fd","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )]
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
            drop(guard);
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
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0012-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::create_file_inner","disposition":"output-owner","category":"overlay-directory","reason":"Ensure the confined parent exists before creating the caller-requested overlay file.","creation":{"policy":"recursive-directory","basis":"The parent is checked under the overlay root and keeps ordinary directory defaults; file mode is reviewed on the admitted open."}}"###
                )]
                fs::create_dir_all(parent)?;
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
            // Admitted before `O_TRUNC` and the chmod (R10-C): never a
            // descriptor of an open overlay database.
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0013-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::create_file_inner","disposition":"output-owner","category":"overlay-content","reason":"Open the new overlay payload through admitted acquisition before truncation and permission application.","creation":{"policy":"create-or-truncate","basis":"The admitted O_CREAT/O_TRUNC open uses caller mode masked to 07777, then sets the requested permission bits on the acquired descriptor."}}"###
            )]
            let f = open_admitted_file(
                &real,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
                mode & 0o7777,
            )?;
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
            }
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0166-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::create_file_inner","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )]
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
            // The admitted open applies it only to an inode that is not an
            // open overlay database (R10-C): another name of one is refused
            // without closing a descriptor of it.
            let fd = {
                use std::os::unix::io::IntoRawFd;
                let _account = self.account_path(path);
                {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0167-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::open_overlay_fd_with_mode","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                    )]
                    let __inventory_value_0 =
                        ratarmount_core::db_inodes::open_admitted(&real, flags, mode & 0o7777);
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0168-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::open_overlay_fd_with_mode","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                    )]
                    let __inventory_value_1 = __inventory_value_0?.into_raw_fd();
                    __inventory_value_1
                }
            };
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0014-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::mkdir","disposition":"output-owner","category":"overlay-directory","reason":"Create the directory requested by the overlay mkdir operation and mark it present.","creation":{"policy":"recursive-directory","basis":"Confinement/mutation checks precede creation; Unix permissions are explicitly set to caller mode masked to 07777."}}"###
        )]
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
        #[cfg(unix)]
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0015-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::truncate","disposition":"out-of-family","category":"overlay-content","reason":"Acquire the existing overlay payload through the admitted helper before truncating it.","creation":{"policy":"none","basis":"This O_WRONLY/O_NOFOLLOW acquisition has no create flag and cannot invent a missing payload."}}"###
        )]
        let f = open_admitted_file(&real, libc::O_WRONLY | libc::O_NOFOLLOW, 0)?;
        #[cfg(not(unix))]
        let f = {
            let mut options = open_options_nofollow();
            options.write(true);
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0169-I01","disposition":"residual","family":"payload-admitted-readers","issue":"#196","reason":"non-Unix overlay payload open for truncate (no admitted open off Unix); payload ownership needs the excluded coordinator","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::truncate","native_observed":false,"creation":{"policy":"none","basis":"Existing non-Unix overlay payload opened write-only before explicit truncation; no create flag."},"category":"overlay-payload"}"###
            )]
            let opened = options.open(&real)?;
            opened
        };
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0016-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::create_symlink","disposition":"output-owner","category":"overlay-directory","reason":"Create the confined parent before creating a caller-requested overlay symlink.","creation":{"policy":"recursive-directory","basis":"The destination absence/confinement checks run first; parent directory creation preserves current defaults."}}"###
            )]
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0017-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::rename_inner","disposition":"output-owner","category":"overlay-directory","reason":"Create the rename destination parent inside the checked overlay root before the host rename.","creation":{"policy":"recursive-directory","basis":"Only the destination parent is created; payload ownership and tombstone publication remain in the rename transaction path."}}"###
            )]
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
        crate::overlay_meta::record_base_digest_required(&db, pending, digest, true)
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0018-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::test_hold_open_transaction","disposition":"out-of-family","category":"feature-test-hook","reason":"Publish the explicit readiness file for the test-hooks open-transaction hold.","creation":{"policy":"create-or-truncate","basis":"This hook-only readiness output uses fs::write and existing umask behavior; it is not an archive input."}}"###
            )]
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

    /// Join the same overlay-scoped operation as offline commit and seal.
    /// Read through this mount's connection: opening another connection would
    /// conflict with its lifetime exclusive SQLite ownership.
    fn commit_operation(&self) -> Result<SealCommitGuard> {
        let lock = SealCommitGuard::acquire(&self.root)?;
        if crate::OverlayMeta::from_connection_required(&self.db.lock().expect("overlay db"), true)?
            .as_ref()
            .is_some_and(crate::OverlayMeta::layer_sealed)
        {
            return Err(OverlayError::Msg(format!(
                "overlay {} is sealed; mount it with --lower, or `overlay unseal`",
                self.root.display()
            )));
        }
        Ok(lock)
    }

    /// Persist only (on-exit). No reopen/reset.
    pub fn commit_atomic(&self, archive: &Path) -> Result<bool> {
        let _seal_commit = self.commit_operation()?;
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
        let _seal_commit = self.commit_operation()?;
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
        let _seal_commit = self.commit_operation()?;
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
                &mut || Ok(()),
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
        let _seal_commit = self.commit_operation()?;
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
            crate::journal_recovery::Rows::Shared {
                db: &self.db,
                dir: &self.root,
                id: self.db_id,
            }
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
                &mut || Ok(()),
            ) {
                Ok(stats) => stats,
                Err(failed) => {
                    let from = self.after_failed_replace(failed)?;
                    crate::journal_recovery::splice_replace_over(
                        archive,
                        from_idx,
                        transform,
                        original,
                        &from,
                        &mut || Ok(()),
                    )?
                }
            }
        } else {
            crate::journal_recovery::splice_replace_over(
                archive,
                from_idx,
                transform,
                original,
                &crate::journal_recovery::CopyFrom::Gate,
                &mut || Ok(()),
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
                &mut || Ok(()),
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
            crate::journal_recovery::open_copy_source(archive, original, &copy_from)?;
        let (tmp, method) = ratarmount_compress::fastcopy::copy_to_temp(&mut src, parent)?;
        ratarmount_compress::fastcopy::log_commit_copy(source.len(), method);
        tmp.as_file().sync_all()?;
        let work_tar = tmp.path().to_path_buf();
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0170-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::persist_uncompressed_tar_plan","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )]
        let list_dir = tempfile::tempdir()?;
        let deletion_list = list_dir.path().join("deletions.lst");
        let append_list = list_dir.path().join("append.lst");
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0171-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::persist_uncompressed_tar_plan","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )]
        fs::write(&deletion_list, &plan.deletions_nul)?;
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0172-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay>::persist_uncompressed_tar_plan","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )]
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
        ratarmount_compress::fastcopy::preserve_archive_metadata(archive, &source, tmp.as_file())
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
        tmp.as_file().sync_all()?;
        crate::journal_recovery::publish_over(
            archive,
            &source,
            || tmp.persist(archive).map(drop).map_err(|e| e.error),
            &mut || Ok(()),
        )
        .map_err(|failed| {
            OverlayError::Msg(format!(
                "Failed to replace '{}' after live TAR commit: {}",
                archive.display(),
                failed.error,
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0173-M01","item":"ratarmount_compositing::write_overlay::patch_sidecar_if_present","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )]
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0174-M01","item":"ratarmount_compositing::write_overlay::uncompressed_patch_window","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
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
                #[cfg(unix)]
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0019-M01","item":"<ratarmount_compositing::write_overlay::WriteOverlay as ratarmount_core::MountSource<ratarmount_compositing::write_overlay::WriteOverlay>>::open","disposition":"out-of-family","category":"overlay-content","reason":"Acquire an existing overlay member through the admitted read-only helper for an overlay open.","creation":{"policy":"none","basis":"O_RDONLY/O_NOFOLLOW opens an existing payload; descriptor admission prevents borrowing an open database inode."}}"###
                )]
                let opened = open_admitted_file(&real, libc::O_RDONLY | libc::O_NOFOLLOW, 0);
                #[cfg(not(unix))]
                let opened = {
                    let mut options = open_options_nofollow();
                    options.read(true);
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0175-I01","disposition":"residual","family":"payload-admitted-readers","issue":"#196","reason":"non-Unix overlay payload open (no admitted open off Unix); payload ownership needs the excluded coordinator","item":"<ratarmount_compositing::write_overlay::WriteOverlay as ratarmount_core::MountSource<ratarmount_compositing::write_overlay::WriteOverlay>>::open","native_observed":false,"creation":{"policy":"none","basis":"Existing non-Unix overlay payload opened read-only; missing content stays missing."},"category":"overlay-payload"}"###
                    )]
                    let opened = options.open(&real);
                    opened
                };
                match opened {
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
    // Admitted (R10-FIX3): a manifest name that is a hard link of an open
    // overlay database is refused without a descriptor of it being closed.
    #[cfg(unix)]
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0020-M01","item":"ratarmount_compositing::write_overlay::write_commit_manifest","disposition":"out-of-family","category":"structured-control-record","reason":"Read the previous commit manifest id through admitted acquisition before writing its replacement manifest.","creation":{"policy":"none","basis":"The previous sidecar is opened read-only/nonblocking; NotFound starts at id zero and no input is created."}}"###
    )]
    let opened = open_admitted_file(&dest, libc::O_RDONLY | libc::O_NONBLOCK, 0);
    #[cfg(not(unix))]
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0176-I01","disposition":"out-of-family","category":"structured-control-record","reason":"commit manifest JSON read back before rewrite","item":"ratarmount_compositing::write_overlay::write_commit_manifest","native_observed":false,"creation":{"policy":"none","basis":"Existing manifest input is read before a separately created replacement is published."}}"###
    )]
    let opened = File::open(&dest);
    let previous = match opened {
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0177-M01","item":"ratarmount_compositing::write_overlay::write_commit_manifest","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0178-M01","item":"ratarmount_compositing::write_overlay::write_commit_manifest","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"directory handle opened only to fsync a directory entry","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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
    before_write: &mut dyn FnMut() -> Result<()>,
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
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0179-M01","item":"ratarmount_compositing::write_overlay::persist_provenance_plan","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )]
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
    let mut persist = || -> Result<IndexPatchWindow> {
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
                    archive,
                    from,
                    transform,
                    original,
                    rows,
                    before_write,
                ) {
                    let copy_from = copy_after_failed_replace(failed, mode)?;
                    crate::journal_recovery::splice_replace_over(
                        archive,
                        from,
                        transform,
                        original,
                        &copy_from,
                        before_write,
                    )?;
                }
            } else {
                crate::journal_recovery::splice_replace_over(
                    archive,
                    from,
                    transform,
                    original,
                    &crate::journal_recovery::CopyFrom::Gate,
                    before_write,
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0180-M01","item":"ratarmount_compositing::write_overlay::persist_provenance_plan","disposition":"output-owner","mode_policy":"private-staging-then-source-archive-metadata","category":"output-owner","reason":"Stage the replacement privately; restore accepted archive metadata by fd before publication (#235).","creation":{"policy":"private-named-temporary-file","basis":"NamedTempFile retains private staging defaults; the finished replacement inherits accepted source permission bits and permitted ownership by fd before rename."}}"###
        )]
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        // The stamp checked against the gate is the one the copy publishes
        // with (R7-E1): another writer's change after this open refuses it.
        let (mut src, opened) = crate::journal_recovery::open_copy_source(
            archive,
            original,
            &crate::journal_recovery::CopyFrom::Gate,
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
                before_write,
            ) {
                let copy_from = copy_after_failed_replace(failed, mode)?;
                // The stamp after the attempt (a rollback left a new ctime),
                // read from the very file the copy reads; it must still be
                // exactly the stamp the failure names.
                ratarmount_compress::commit_journal::fault::point("copy source open")?;
                let source = crate::journal_recovery::recheck_copy_source(
                    archive, &src, original, &copy_from,
                )?;
                ratarmount_compress::commit_journal::fault::point("copy source opened")?;
                tmp.as_file_mut().set_len(0)?;
                tmp.as_file_mut().rewind()?;
                src.rewind()?;
                rewrite_tar_suffix(&mut src, 0, &rewrite, tmp.as_file_mut())?;
                ratarmount_compress::fastcopy::preserve_archive_metadata(
                    archive,
                    &source,
                    tmp.as_file(),
                )
                .map_err(|e| OverlayError::Msg(e.to_string()))?;
                tmp.as_file().sync_all()?;
                crate::journal_recovery::publish_over(
                    archive,
                    &source,
                    || tmp.persist(archive).map(drop).map_err(|e| e.error),
                    before_write,
                )
                .map_err(|failed| failed.error)?;
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
            let source = opened;
            rewrite_tar_suffix(&mut src, 0, &rewrite, tmp.as_file_mut())?;
            ratarmount_compress::fastcopy::preserve_archive_metadata(
                archive,
                &source,
                tmp.as_file(),
            )
            .map_err(|e| OverlayError::Msg(e.to_string()))?;
            tmp.as_file().sync_all()?;
            crate::journal_recovery::publish_over(
                archive,
                &source,
                || tmp.persist(archive).map(drop).map_err(|e| e.error),
                before_write,
            )
            .map_err(|failed| failed.error)?;
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
    // Linux parks an `O_PATH` descriptor: closing it releases no fcntl lock.
    // Elsewhere the parked descriptor is readable, so it is admitted first
    // (R10-C): another name of an open overlay database is never parked.
    #[cfg(not(target_os = "linux"))]
    {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0181-I01","disposition":"residual","family":"payload-admitted-readers","issue":"#196","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","item":"ratarmount_compositing::write_overlay::open_park_fd","native_observed":false,"creation":{"policy":"none","basis":"The non-Linux Unix path parks an admitted existing payload descriptor; no create flags are used."},"category":"overlay-payload"}"###
        )]
        let fd = ratarmount_core::db_inodes::open_admitted(host, park_open_flags(), 0);
        fd
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::{FromRawFd, OwnedFd};
        let c = c_path(host)?;
        // Safety: `c` is NUL-terminated. Flags never include `O_CREAT`.
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0182-M01","item":"ratarmount_compositing::write_overlay::open_park_fd","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let fd = unsafe { libc::open(c.as_ptr(), park_open_flags(), 0) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // Safety: `fd` is a new descriptor owned by this process.
            Ok(unsafe {
                {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0183-M01","item":"ratarmount_compositing::write_overlay::open_park_fd","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                    )]
                    let __inventory_value_0 = OwnedFd::from_raw_fd(fd);
                    __inventory_value_0
                }
            })
        }
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
    {
        let __inventory_condition_278275 = {
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0184-M01","item":"ratarmount_compositing::write_overlay::create_overlay_marker","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###
            )]
            let mut __inventory_value_0 = open_options_nofollow();
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0021-M01","item":"ratarmount_compositing::write_overlay::create_overlay_marker","disposition":"output-owner","category":"overlay-control-record","reason":"Configure exclusive creation of the no-follow overlay ownership marker.","creation":{"policy":"exclusive-new-file","basis":"An existing name is accepted only when symlink_metadata reports a regular file; creation uses ordinary file permissions."}}"###
            )]
            let __inventory_value_1 = __inventory_value_0.write(true).create_new(true);
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0184-M02","item":"ratarmount_compositing::write_overlay::create_overlay_marker","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )]
            let __inventory_value_2 = __inventory_value_1.open(path);
            __inventory_value_2
        };
        match __inventory_condition_278275 {
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
}

/// `open(2)` of a payload, sentinel or commit source that never returns (and
/// never closes) a descriptor of an open overlay database (R10-C, see
/// [`ratarmount_core::db_inodes`]); `O_CLOEXEC` is added.
#[cfg(unix)]
pub(crate) fn open_admitted_file(path: &Path, flags: libc::c_int, mode: u32) -> io::Result<File> {
    {
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0185-M01","item":"ratarmount_compositing::write_overlay::open_admitted_file","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###)]
let __inventory_value_0 = ratarmount_core::db_inodes::open_admitted(path, flags | libc::O_CLOEXEC, mode);
__inventory_value_0
}.map(File::from)
}

/// WHY: O_NOFOLLOW is Unix-only; Windows OpenOptions has no equivalent bit.
#[expect(
    clippy::disallowed_types,
    reason = r###"internal-read:v1 {"id":"IR-E0022-T01","item":"ratarmount_compositing::write_overlay::HostOpenOptions","disposition":"support","category":"builder-type-support","reason":"Builder type support: Return the no-follow OpenOptions builder from the shared overlay helper.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
)]
type HostOpenOptions = FsOpenOptions;

pub(crate) fn open_options_nofollow() -> HostOpenOptions {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0186-M01","item":"ratarmount_compositing::write_overlay::open_options_nofollow","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"out-of-family","baseline_reason":"builder constructor: returns an O_NOFOLLOW OpenOptions and opens nothing; each call site is its own OpenOptions entry"}"###
    )]
    #[expect(
        clippy::disallowed_types,
        reason = r###"internal-read:v1 {"id":"IR-B0186-T01","item":"ratarmount_compositing::write_overlay::open_options_nofollow","disposition":"support","category":"builder-type-support","reason":"Builder type support: builder constructor: returns an O_NOFOLLOW OpenOptions and opens nothing; each call site is its own OpenOptions entry","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
    )]
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
    {
        #[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-E0023-M01","item":"ratarmount_compositing::write_overlay::create_cow_staging","disposition":"output-owner","category":"overlay-staging","reason":"Allocate the named sibling COW staging file through tempfile Builder::make_in.","creation":{"policy":"exclusive-new-file","basis":"The supplied creation closure uses no-follow options and create_new; tempfile owns cleanup until publication."}}"###)]
let __inventory_value_0 = tempfile::Builder::new()
        .prefix(COW_STAGING_PREFIX)
        .make_in(parent, |path| {
            #[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0187-M01","item":"ratarmount_compositing::write_overlay::create_cow_staging","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###)]
let mut opts = open_options_nofollow();
            {
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-E0024-M01","item":"ratarmount_compositing::write_overlay::create_cow_staging","disposition":"output-owner","category":"overlay-staging","reason":"Set exclusive creation on the no-follow COW staging file builder.","creation":{"policy":"exclusive-new-file","basis":"The staging closure uses create_new so a collision cannot truncate an existing path; file permissions retain existing default/umask behavior."}}"###)]
let __inventory_value_0 = opts.write(true).create_new(true);
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0187-M02","item":"ratarmount_compositing::write_overlay::create_cow_staging","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###)]
let __inventory_value_1 = __inventory_value_0.open(path);
__inventory_value_1
}
        });
        __inventory_value_0
    }
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
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0188-M01","item":"ratarmount_compositing::write_overlay::publish_cow_staging","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"parent directory handle for the post-rename fsync; reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )]
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0189-M01","item":"ratarmount_compositing::write_overlay::uncompressed_append_offset","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut file = File::open(archive)?;
    Ok(ratarmount_formats_tar::tar_append_offset(
        &mut file, &touched, encoding,
    )?)
}

#[cfg(test)]
thread_local! {
    static APPEND_PREPARE_TOUCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Run by an offline commit after the caller's gate, right before it
    /// picks the recovery owner (the overlay or the archive changes there).
    pub(crate) static BEFORE_OFFLINE_RECOVERY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
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
    before_write: &mut dyn FnMut() -> Result<()>,
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0190-M01","item":"ratarmount_compositing::write_overlay::append_uncompressed_tar_plan","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut tail = tempfile::NamedTempFile::new_in(parent)?;
    ratarmount_formats_tar::write_ustar_members(tail.as_file_mut(), &members)?;
    ratarmount_formats_tar::write_tar_eof(tail.as_file_mut())?;
    crate::journal_recovery::replace_committing(
        archive,
        offset,
        tail.as_file_mut(),
        original,
        rows,
        before_write,
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
    OverlayCommitGuard::acquire(write_overlay)?.commit(archive_file, base, opts)
}

/// One offline commit operation, including caller-side archive creation or
/// recovery. Keep this owner alive until publication and baseline refresh end.
/// It always acquires the overlay lock before any archive guard.
pub struct OverlayCommitGuard {
    dir: PathBuf,
    _lock: SealCommitGuard,
}

impl OverlayCommitGuard {
    pub fn acquire(write_overlay: impl AsRef<Path>) -> Result<Self> {
        let dir = write_overlay.as_ref().canonicalize()?;
        ensure_overlay_unsealed(&dir)?;
        let lock = SealCommitGuard::acquire(&dir)?;
        ensure_overlay_unsealed(&dir)?;
        Ok(Self { dir, _lock: lock })
    }

    pub fn commit(
        self,
        archive_file: impl AsRef<Path>,
        base: &crate::ClassifiedBase,
        opts: &CommitOverlayOptions,
    ) -> Result<bool> {
        commit_overlay_locked(&self.dir, archive_file.as_ref(), base, opts)
    }

    pub fn commit_raw_dir(
        self,
        archive_file: impl AsRef<Path>,
        opts: &CommitOverlayOptions,
    ) -> Result<RawDirCommit> {
        commit_overlay_raw_dir_locked(&self.dir, archive_file.as_ref(), opts)
    }
}

fn commit_overlay_locked(
    write_overlay: &Path,
    archive_file: &Path,
    base: &crate::ClassifiedBase,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    match overlay_db_entry(write_overlay)? {
        DbEntry::Absent => {
            return Err(OverlayError::Msg(format!(
                "overlay {} has no database; use commit_overlay_raw_dir for a raw directory",
                write_overlay.display()
            )))
        }
        DbEntry::Lost { markers, .. } => return Err(lost_record_error(write_overlay, &markers)),
        DbEntry::Present { marked, .. } => {
            ensure_overlay_unsealed_required(write_overlay, marked)?;
        }
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

/// Serializes seal and offline commit for one overlay, including when callers
/// name different copies of its base. Always acquire before an archive guard.
/// The lock file is persistent bookkeeping: never unlink it on guard disposal.
pub(crate) struct SealCommitGuard {
    #[cfg(unix)]
    _fd: std::os::fd::OwnedFd,
}

impl SealCommitGuard {
    pub(crate) fn acquire(dir: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-V4-SEAL-COMMIT-LOCK","item":"<ratarmount_compositing::write_overlay::SealCommitGuard>::acquire","disposition":"output-owner","category":"overlay-control-record","reason":"Open the persistent overlay-scoped seal/commit lock without opening the archive; registered database aliases are refused before a lock-dropping close.","creation":{"policy":"create-if-missing","basis":"O_RDWR/O_CREAT with mode 0600, CLOEXEC, NONBLOCK and NOFOLLOW; no truncation, and the acquired entry must be regular."}}"###
            )]
            let fd = ratarmount_core::db_inodes::open_admitted(
                &dir.join(SEAL_COMMIT_LOCK),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK,
                0o600,
            )?;
            if rustix::fs::fstat(&fd)?.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(io::Error::other("seal/commit lock must be a regular file"));
            }
            loop {
                // SAFETY: the guard owns fd until the entire operation ends.
                if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    return Ok(Self { _fd: fd });
                }
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != io::ErrorKind::WouldBlock {
                    return Err(error);
                }
                #[cfg(any(test, feature = "test-hooks"))]
                if let Some(marker) = std::env::var_os("RATARMOUNT_TEST_OVERLAY_CONTENDED") {
                    create_overlay_marker(Path::new(&marker))?;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = dir;
            // Sealing is Unix-only. Preserve the existing non-Unix copy-commit
            // path, which has no seal operation to serialize against.
            Ok(Self {})
        }
    }
}

#[cfg(all(test, not(unix)))]
#[test]
fn regression_nonunix_commit_guard_accepts_unsealed_overlay() {
    // Regression: adding the Unix seal/commit lock disabled non-Unix commits
    // before they could reach the supported copy-publication path.
    let overlay = tempfile::tempdir().unwrap();
    let _guard = OverlayCommitGuard::acquire(overlay.path()).unwrap();
}

/// Refuse a sealed database overlay without recovery or a writable connection.
/// Each call reads fresh metadata, including when the database is a symlink.
/// Raw directories retain their existing commit behavior.
pub fn ensure_overlay_unsealed(write_overlay: &Path) -> Result<()> {
    let marked = match overlay_db_entry(write_overlay)? {
        DbEntry::Absent => return Ok(()),
        DbEntry::Lost { markers, .. } => return Err(lost_record_error(write_overlay, &markers)),
        DbEntry::Present { marked, .. } => marked,
    };
    ensure_overlay_unsealed_required(write_overlay, marked)
}

fn ensure_overlay_unsealed_required(write_overlay: &Path, marked: bool) -> Result<()> {
    if crate::OverlayMeta::read_no_recovery_required_followed(write_overlay, marked)?
        .as_ref()
        .is_some_and(crate::OverlayMeta::layer_sealed)
    {
        return Err(OverlayError::Msg(format!(
            "overlay {} is sealed; mount it with --lower, or `overlay unseal`",
            write_overlay.display()
        )));
    }
    Ok(())
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
    OverlayCommitGuard::acquire(write_overlay)?.commit_raw_dir(archive_file, opts)
}

fn commit_overlay_raw_dir_locked(
    write_overlay: &Path,
    archive_file: &Path,
    opts: &CommitOverlayOptions,
) -> Result<RawDirCommit> {
    let db = write_overlay.join(HIDDEN_DB);
    if let DbEntry::Lost { markers, .. } = overlay_db_entry(write_overlay)? {
        return Err(lost_record_error(write_overlay, &markers));
    }
    if !overlay_db_absent(write_overlay) {
        return Err(OverlayError::Msg(format!(
            "overlay database {} exists (or something else is at its path); its base \
             identity must be checked, so commit it with a classified base \
             (commit_overlay), not as a raw directory",
            db.display()
        )));
    }
    if !opts.force_base_mismatch {
        crate::overlay_gate::ensure_journal_is_for_archive(archive_file)
            .map_err(OverlayError::Msg)?;
    }
    let committed = commit_overlay_inner(write_overlay, archive_file, None, opts)?;
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

    #[cfg(test)]
    if let Some(hook) = BEFORE_OFFLINE_RECOVERY.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
    {
        use crate::journal_recovery::{Owner, Record};
        // The gate ran before this call (unlocked); the owner re-takes the
        // decision on the LOCKED file, and recovery restamps the rows from it.
        // A recorded identity stays `Recorded` even if the database vanished
        // since the gate: the missing record refuses, it never downgrades to
        // the inode rule (R7-F2).
        let owner = match identity {
            _ if opts.force_base_mismatch => Owner::Forced,
            Some(base) => Owner::Recorded {
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
        Some(base) => {
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
            &crate::journal_recovery::Rows::path(&db),
            &original,
            &mut || ensure_overlay_unsealed(write_overlay),
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
        commit_overlay_zip(write_overlay, archive_file, opts, &original)?
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
    // Canonical paths in every refusal, same as the mount's.
    let canon = write_overlay
        .canonicalize()
        .unwrap_or_else(|_| write_overlay.to_path_buf());
    let db_path = canon.join(HIDDEN_DB);
    let markers = overlay_markers(write_overlay)?;
    let marker = markers.first().cloned();
    // Only a missing entry is "no database" (R7-E2): a dangling symlink in an
    // unmarked folder is refused, never planned without its tombstones; a
    // directory or another non-regular file is refused with the shared text.
    let db_regular = match overlay_db_regular(&db_path, marker.is_some())? {
        // A 0-byte file in a marked folder is as gone as a missing one.
        Some(m) => marker.is_none() || m.len() > 0,
        None => false,
    };
    if marker.is_some() && !db_regular {
        // #96: committing without the tombstones would write the unlinked
        // members back into the archive. Same wording and canonical paths as
        // the mount refusal.
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
        let conn = crate::overlay_db::open_overlay_db_required(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            crate::DbName::Path,
            marker.is_some(),
        )?;
        // A used overlay's database without its `files` table is a lost
        // record (R10-B): refuse with its path, never plan without deletions.
        if (marker.is_some() || conn.required_record())
            && !crate::overlay_meta::has_files_table(&conn)?
        {
            return Err(OverlayError::Msg(format!(
                "{}: {}; refusing to commit without its deletions",
                db_path.display(),
                crate::overlay_meta::NO_FILES_TABLE
            )));
        }
        Some(conn)
    } else {
        None
    };
    collect_overlay_commit_plan_from_conn(write_overlay, conn.as_deref(), None, &HashSet::new())
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
    let confirmed = if opts.yes {
        true
    } else {
        print!("Please confirm by entering \"commit\". Any other input will cancel.\n> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim() == "commit"
    };
    if confirmed {
        test_commit_hold()?;
    }
    Ok(confirmed)
}

/// Explicit confirmation-time synchronization for subprocess regression tests.
/// The existing exclusive no-follow marker helper avoids another file opener.
fn test_commit_hold() -> Result<()> {
    test_operation_hold(
        "RATARMOUNT_TEST_COMMIT_READY",
        "RATARMOUNT_TEST_COMMIT_RELEASE",
    )
}

/// Bounded, explicit synchronization for subprocess regressions only.
pub(crate) fn test_operation_hold(ready_env: &str, release_env: &str) -> Result<()> {
    let _ = (ready_env, release_env);
    #[cfg(any(test, feature = "test-hooks"))]
    if let (Some(ready), Some(release)) =
        (std::env::var_os(ready_env), std::env::var_os(release_env))
    {
        create_overlay_marker(Path::new(&ready))?;
        let deadline = Instant::now() + Duration::from_secs(60);
        while !Path::new(&release).is_file() {
            if Instant::now() >= deadline {
                return Err(OverlayError::Msg(format!(
                    "timed out waiting for {release_env}"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(())
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0191-M01","item":"ratarmount_compositing::write_overlay::is_zip_archive","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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

    rebuild_zip_with_overlay(write_overlay, zip_file, &plan, original)?;

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
    original: &fs::Metadata,
) -> Result<()> {
    // Read the descriptor checked against the gate; publish only over that
    // stamp, under the copy guard (R7-E1).
    let (src, source) = crate::journal_recovery::open_copy_source(
        zip_file,
        original,
        &crate::journal_recovery::CopyFrom::Gate,
    )
    .map_err(|e| {
        OverlayError::Msg(format!(
            "Failed to open ZIP '{}' for commit: {e}",
            zip_file.display()
        ))
    })?;
    let mut archive = ZipArchive::new(src).map_err(|e| {
        OverlayError::Msg(format!("Failed to read ZIP '{}': {e}", zip_file.display()))
    })?;

    let parent = zip_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0192-M01","item":"ratarmount_compositing::write_overlay::rebuild_zip_with_overlay","disposition":"output-owner","mode_policy":"private-staging-then-source-archive-metadata","category":"output-owner","reason":"Stage the replacement privately; restore accepted archive metadata by fd before publication (#235).","creation":{"policy":"private-named-temporary-file","basis":"NamedTempFile retains private staging defaults; the finished replacement inherits accepted source permission bits and permitted ownership by fd before rename."}}"###
    )]
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;

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
                #[cfg(unix)]
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0025-M01","item":"ratarmount_compositing::write_overlay::rebuild_zip_with_overlay","disposition":"out-of-family","category":"overlay-content","reason":"Acquire an existing overlay file through admission while rebuilding a ZIP member.","creation":{"policy":"none","basis":"The helper opens the source O_RDONLY; the ZIP writer owns the separate output file."}}"###
                )]
                let opened = open_admitted_file(&src_path, libc::O_RDONLY, 0);
                #[cfg(not(unix))]
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0193-I01","disposition":"residual","family":"archive-and-member-io","issue":"#196","reason":"commit rebuild input (overlay member or plain temp); payload ownership excluded","item":"ratarmount_compositing::write_overlay::rebuild_zip_with_overlay","native_observed":false,"creation":{"policy":"none","basis":"Existing overlay member input for ZIP reconstruction; output is independently owned."},"category":"archive-input"}"###
                )]
                let opened = File::open(&src_path);
                let mut src_file = opened.map_err(|e| {
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
    ratarmount_compress::fastcopy::preserve_archive_metadata(zip_file, &source, tmp.as_file())
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    tmp.as_file().sync_all()?;

    crate::journal_recovery::publish_over(
        zip_file,
        &source,
        || tmp.persist(zip_file).map(drop).map_err(|e| e.error),
        &mut || ensure_overlay_unsealed(write_overlay),
    )
    .map_err(|failed| {
        if !failed.may_copy {
            return failed.error;
        }
        OverlayError::Msg(format!(
            "Failed to replace '{}' with rebuilt ZIP: {}",
            zip_file.display(),
            failed.error,
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
                &crate::journal_recovery::Rows::path(&db),
                original,
                &mut || ensure_overlay_unsealed(write_overlay),
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
    // The stamp checked against the gate; the publish compares exactly it.
    let copy_source: fs::Metadata;
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
                crate::journal_recovery::open_copy_source(tar_file, original, &copy_from)?;
            let (tmp, method) = ratarmount_compress::fastcopy::copy_to_temp(&mut src, parent)?;
            ratarmount_compress::fastcopy::log_commit_copy(source.len(), method);
            copy_source = source;
            tmp.as_file().sync_all()?;
            let path = tmp.path().to_path_buf();
            (path, Some(tmp))
        }
        CompressionFormat::Gzip | CompressionFormat::Bzip2 | CompressionFormat::Xz => {
            // Decompress the descriptor checked against the gate; the
            // recompressed copy publishes only over that stamp (R7-E1).
            let (src, source) =
                crate::journal_recovery::open_copy_source(tar_file, original, &copy_from)?;
            copy_source = source;
            let (tmp, _) = materialize_open(src, tar_file, format).map_err(|e| {
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

    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0194-M01","item":"ratarmount_compositing::write_overlay::commit_overlay_tar","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let tmp = tempfile::tempdir()?;
    let deletion_list = tmp.path().join("deletions.lst");
    let append_list = tmp.path().join("append.lst");

    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0195-M01","item":"ratarmount_compositing::write_overlay::commit_overlay_tar","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    fs::write(&deletion_list, &plan.deletions_nul)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0196-M01","item":"ratarmount_compositing::write_overlay::commit_overlay_tar","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
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
        recompress_replace(&work_tar, tar_file, format, &copy_source, &mut || {
            ensure_overlay_unsealed(write_overlay)
        })?;
        // Keep materialized temp alive until recompress finishes.
        drop(work_holder);
    } else {
        let tmp = work_holder.ok_or_else(|| {
            OverlayError::Msg(
                "internal error: missing work temp for uncompressed offline commit".into(),
            )
        })?;
        ratarmount_compress::fastcopy::preserve_archive_metadata(
            tar_file,
            &copy_source,
            tmp.as_file(),
        )
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
        tmp.as_file().sync_all()?;
        crate::journal_recovery::publish_over(
            tar_file,
            &copy_source,
            || tmp.persist(tar_file).map(drop).map_err(|e| e.error),
            &mut || ensure_overlay_unsealed(write_overlay),
        )
        .map_err(|failed| {
            if !failed.may_copy {
                return failed.error;
            }
            OverlayError::Msg(format!(
                "Failed to replace '{}' after offline TAR commit: {}",
                tar_file.display(),
                failed.error,
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
        let rows = crate::journal_recovery::Rows::path(&db);
        match crate::journal_recovery::splice_append_committing(
            tar_file,
            from_idx,
            transform,
            original,
            &rows,
            &mut || ensure_overlay_unsealed(write_overlay),
        ) {
            Ok(stats) => stats,
            Err(failed) => {
                let copy_from = copy_after_failed_replace(failed, opts.mode)?;
                crate::journal_recovery::splice_replace_over(
                    tar_file,
                    from_idx,
                    transform,
                    original,
                    &copy_from,
                    &mut || ensure_overlay_unsealed(write_overlay),
                )?
            }
        }
    } else {
        crate::journal_recovery::splice_replace_over(
            tar_file,
            from_idx,
            transform,
            original,
            &crate::journal_recovery::CopyFrom::Gate,
            &mut || ensure_overlay_unsealed(write_overlay),
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

/// Compress `plain` with `format` and atomically replace `dest`, only while
/// `dest` is still exactly `source` (the stamp checked against the gate),
/// under the copy guard.
fn recompress_replace(
    plain: &Path,
    dest: &Path,
    format: CompressionFormat,
    source: &fs::Metadata,
    before_write: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0197-M01","item":"ratarmount_compositing::write_overlay::recompress_replace","disposition":"output-owner","mode_policy":"private-staging-then-source-archive-metadata","category":"output-owner","reason":"Stage the replacement privately; restore accepted archive metadata by fd before publication (#235).","creation":{"policy":"private-named-temporary-file","basis":"NamedTempFile retains private staging defaults; the finished replacement inherits accepted source permission bits and permitted ownership by fd before rename."}}"###
    )]
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;

    {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0198-M01","item":"ratarmount_compositing::write_overlay::recompress_replace","disposition":"residual","reason":"commit rebuild input (overlay member or plain temp); payload ownership excluded","family":"archive-and-member-io","issue":"#196","category":"archive-and-member-io","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
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
    ratarmount_compress::fastcopy::preserve_archive_metadata(dest, source, tmp.as_file())
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
    tmp.as_file().sync_all()?;

    // Atomic replace on the same filesystem (parent chosen to match dest).
    crate::journal_recovery::publish_over(
        dest,
        source,
        || tmp.persist(dest).map(drop).map_err(|e| e.error),
        before_write,
    )
    .map_err(|failed| {
        if !failed.may_copy {
            return failed.error;
        }
        OverlayError::Msg(format!(
            "Failed to replace '{}' with recompressed archive: {}",
            dest.display(),
            failed.error,
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
    // Managed (#151): a remote spool may be another name of a database open
    // in this process.
    {
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0199-M01","item":"ratarmount_compositing::write_overlay::file_sha256","disposition":"managed-read","regression":"regression_remote_spool_hash_keeps_aliased_database_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###)]
let __inventory_value_0 = ratarmount_index::managed_read::sha256_hex(path);
__inventory_value_0
}.map_err(|e| OverlayError::Msg(e.to_string()))
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0200-M01","item":"ratarmount_compositing::write_overlay::find_last_n_tar_window","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0026-M01","item":"ratarmount_compositing::write_overlay::find_last_n_tar_window","disposition":"output-owner","category":"compression-staging","reason":"Buffer a decoded candidate TAR suffix while finding a safe zstd rewrite window.","creation":{"policy":"spill-private-temporary","basis":"The bounded spool starts in memory and may roll to tempfile storage using tempfile private temporary-file defaults."}}"###
        )]
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0027-M01","item":"ratarmount_compositing::write_overlay::suffix_window_has_member_boundary","disposition":"output-owner","category":"compression-staging","reason":"Buffer a decoded suffix to validate that its starting point is a TAR member boundary.","creation":{"policy":"spill-private-temporary","basis":"The existing memory cap controls rollover to a private tempfile; the spool is temporary analysis output."}}"###
    )]
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0201-M01","item":"ratarmount_compositing::write_overlay::offline_tar_zst_from_idx","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0202-M01","item":"ratarmount_compositing::write_overlay::is_uncompressed_tar","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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
pub(crate) mod tests;
