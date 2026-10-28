//! Managed byte readers for internal reads (#151, R11-S7).
//!
//! POSIX drops every `fcntl` lock a process holds on an inode when ANY
//! descriptor of that inode is closed. An internal read of a file that is
//! also open as an SQLite database in this process (an index read through a
//! pointer, a hash of an archive that is an SQLAR, a copy of a cached index
//! blob, the HTTP index sidecar) therefore released that connection's locks
//! when its `File` was dropped.
//!
//! [`ManagedReadCursor`] reads through the bundled SQLite's own VFS byte-file
//! interface instead: the file is opened as a read-only `SQLITE_OPEN_MAIN_DB`
//! file of the `"unix"` VFS (`"unix-posix"` on macOS), so SQLite registers the
//! descriptor in its per-inode bookkeeping and, on close, parks it (instead of
//! closing it) while any connection of this SQLite instance holds a lock on
//! that inode. A later managed open of the inode reuses a parked descriptor.
//! The read cursor creates no SQL connection, takes no lock and touches no
//! `-shm`/`-wal` file; it never reads the bytes as a database.
//!
//! The guarantee covers successfully acquired managed readers and this
//! SQLite instance's main-file lock bookkeeping only: not descriptors of
//! other code or other SQLite instances, not SQLite's auxiliary files, and
//! raw managed reads are not transactional snapshots.
//!
//! [`ArchiveReservation`] uses the same VFS owner with an exclusive lock to
//! exclude SQLite transactions before commit/recovery opens any raw archive
//! descriptors. Its owner closes after those descriptors; it is never used
//! for ordinary read-only acquisition or overlay sealing.
//!
//! Before every Unix byte open the standard descriptors 0-2 are filled with
//! `/dev/null` when vacant (SQLite's `robust_open` closes a new descriptor
//! below 3, which would release a lock); if that fails the open is refused
//! before SQLite's `xOpen`. No acquisition or read failure falls back to a
//! raw `File` read. On Windows the cursor reads an ordinary `File`.
//!
//! macOS FAT/exFAT: SQLite writes an `S` byte into a zero-length database file
//! when it registers it; on this read-only descriptor that fails, so a managed
//! open of an empty file on such a volume is an acquisition error (inherited
//! limitation; no fallback).

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

/// Largest single `xRead` (SQLite's `seekAndRead` asserts reads below
/// 128 KiB).
pub const MAX_READ_CHUNK: usize = 0x1ffff;

/// A read cursor over a privately owned byte file. Independent cursors made
/// with [`ManagedReadCursor::independent_cursor`] share the owner (no second
/// descriptor) and have their own offsets. The cursor exposes no `File`,
/// descriptor or path reopen.
pub struct ManagedReadCursor {
    owner: Arc<Owner>,
    pos: u64,
}

struct Owner {
    file: std::mem::ManuallyDrop<Mutex<imp::ByteFile>>,
    /// The path as given (for test seams at close).
    #[cfg_attr(not(any(test, feature = "test-hooks")), allow(dead_code))]
    path: std::path::PathBuf,
}

impl ManagedReadCursor {
    /// Open `path` for reading. Symlinks are resolved first (the VFS opens
    /// with `O_NOFOLLOW`); a missing file is `NotFound`.
    pub fn open(path: &Path) -> io::Result<Self> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0067-M01","item":"<ratarmount_index::managed_read::ManagedReadCursor>::open","disposition":"managed-read","category":"managed-reader-backend","reason":"Open the managed cursor through its SQLite-backed ByteFile implementation.","creation":{"policy":"none","basis":"The cursor reads an existing path through the managed backend; no file creation is requested."}}"###
        )]
        let file = imp::ByteFile::open(path, false)?;
        Ok(Self {
            owner: Arc::new(Owner {
                file: std::mem::ManuallyDrop::new(Mutex::new(file)),
                path: seams::opened_path_or(path),
            }),
            pos: 0,
        })
    }

    /// Another cursor over the same owner, at offset 0.
    pub fn independent_cursor(&self) -> Self {
        Self {
            owner: Arc::clone(&self.owner),
            pos: 0,
        }
    }

    /// The current file length.
    pub fn len(&self) -> io::Result<u64> {
        self.lock().len()
    }

    /// `len() == 0`.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// `fsync` the file (through the owner; no reopen).
    pub fn sync_all(&self) -> io::Result<()> {
        seams::fire(Seam::BeforeSync)?;
        self.lock().sync()
    }

    /// Whether the opened file was renamed away from or unlinked at its path
    /// (SQLite's moved-file check; `false` where unsupported).
    pub fn has_moved(&self) -> io::Result<bool> {
        self.lock().has_moved()
    }

    /// Read at `offset` without moving the cursor. `Ok(0)` at or past EOF.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let mut file = self.lock();
        let len = file.len()?;
        if offset >= len || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(MAX_READ_CHUNK)
            .min(usize::try_from(len - offset).unwrap_or(usize::MAX));
        seams::fire(Seam::BeforeRead)?;
        file.read_exact_at(&mut buf[..want], offset)?;
        Ok(want)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, imp::ByteFile> {
        // A panic while holding the lock leaves the file usable.
        self.owner.file.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Protect raw archive descriptors from releasing another connection's POSIX
/// locks when they close. Acquire this before opening those descriptors and
/// drop it after all of them close. A live SQLite reader causes refusal before
/// any raw descriptor opens; new readers are excluded while it is held.
///
/// This reservation requires write access, including for a copy publication
/// that could otherwise replace a read-only file using directory permissions.
/// Empty archives are refused before SQLite opens them: on macOS FAT/exFAT,
/// a writable MAIN_DB open would initialize an empty file with an `S` byte.
/// Ordinary managed readers and seals do not take this reservation.
#[cfg(unix)]
pub struct ArchiveReservation {
    _file: imp::ByteFile,
}

#[cfg(unix)]
impl ArchiveReservation {
    pub fn exclusive(path: &Path) -> io::Result<Self> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-240-V4-RESERVE","item":"<ratarmount_index::managed_read::ArchiveReservation>::exclusive","disposition":"residual","category":"commit-journal-recovery","family":"commit-journal-recovery","issue":"#240","reason":"Reserve the archive through SQLite's VFS before any raw commit descriptor opens, refusing live SQLite readers without a lock-dropping close.","creation":{"policy":"none","basis":"Open an existing archive read-write as a VFS MAIN_DB byte file, with no CREATE flag; the reservation owns no SQL connection and changes no content."}}"###
        )]
        let mut file = imp::ByteFile::open(path, true)?;
        file.lock_exclusive()?;
        Ok(Self { _file: file })
    }
}

impl std::fmt::Debug for ManagedReadCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedReadCursor")
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl Read for ManagedReadCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ManagedReadCursor {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let base = match to {
            SeekFrom::Start(n) => {
                self.pos = n;
                return Ok(n);
            }
            SeekFrom::Current(d) => (self.pos, d),
            SeekFrom::End(d) => (self.len()?, d),
        };
        let next = base
            .0
            .checked_add_signed(base.1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek out of range"))?;
        self.pos = next;
        Ok(next)
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        seams::set_path(&self.path);
        let _ = seams::fire(Seam::BeforeClose);
        // SAFETY: dropped exactly once, here.
        unsafe { std::mem::ManuallyDrop::drop(&mut self.file) };
        seams::set_path(&self.path);
        let _ = seams::fire(Seam::AfterClose);
    }
}

// --------------------------------------------------------------------------
// Whole-file helpers.
// --------------------------------------------------------------------------

/// The error payload of a managed open refused because the path is not a
/// regular file (a directory, FIFO, socket or device). Callers that treat
/// such a name as absent tell it apart with [`is_not_regular_file`]; any
/// other `InvalidInput` (an `EINVAL` from a read) is a real I/O error.
#[derive(Debug)]
struct NotRegularFile(String);

impl std::fmt::Display for NotRegularFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not a regular file", self.0)
    }
}

impl std::error::Error for NotRegularFile {}

fn not_regular_file(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        NotRegularFile(path.display().to_string()),
    )
}

/// Whether `e` is a managed open's refusal of a path that is not a regular
/// file (not any other `InvalidInput`).
pub fn is_not_regular_file(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.downcast_ref::<NotRegularFile>().is_some())
}

/// Read the whole file. The buffer is reserved fallibly: a file larger than
/// the memory this process may allocate is an `OutOfMemory` error, not an
/// abort.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0444-M01","item":"ratarmount_index::managed_read::read","disposition":"managed-read","regression":"regression_internal_cursor_close_keeps_posix_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut c = ManagedReadCursor::open(path)?;
    let len = c.len()?;
    let oom = || {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("cannot allocate {len} bytes to read {}", path.display()),
        )
    };
    let mut out = Vec::new();
    out.try_reserve_exact(usize::try_from(len).map_err(|_| oom())?)
        .map_err(|_| oom())?;
    c.read_to_end(&mut out)?;
    Ok(out)
}

/// Read the whole file as UTF-8.
pub fn read_to_string(path: &Path) -> io::Result<String> {
    String::from_utf8({
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-E0068-M01","item":"ratarmount_index::managed_read::read_to_string","disposition":"managed-read","category":"managed-reader-delegation","reason":"Delegate UTF-8 text loading to the managed byte reader before validating UTF-8.","creation":{"policy":"none","basis":"The nested managed_read::read reads existing content; UTF-8 conversion creates no pathname resource."}}"###)]
let __inventory_value_0 = read(path);
__inventory_value_0
}?).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Read at most `max` bytes from the start of the file (fewer at EOF).
pub fn read_prefix(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0445-M01","item":"ratarmount_index::managed_read::read_prefix","disposition":"managed-read","regression":"regression_internal_cursor_close_keeps_posix_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut c = ManagedReadCursor::open(path)?;
    let mut out = Vec::with_capacity(max.min(1 << 20));
    (&mut c).take(max as u64).read_to_end(&mut out)?;
    Ok(out)
}

/// Lowercase hex SHA-256 of the whole file. An I/O error is an error, never a
/// digest of partial bytes.
pub fn sha256_hex(path: &Path) -> io::Result<String> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0446-M01","item":"ratarmount_index::managed_read::sha256_hex","disposition":"managed-read","regression":"regression_internal_cursor_close_keeps_posix_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut c = ManagedReadCursor::open(path)?;
    sha256_hex_cursor(&mut c)
}

/// Lowercase hex SHA-256 of what is left in `c`.
pub fn sha256_hex_cursor(c: &mut ManagedReadCursor) -> io::Result<String> {
    crate::hashing::sha256_hex_stream(c)
}

/// Stream the whole file into `out`; returns the byte count.
pub fn copy_into<W: Write + ?Sized>(src: &Path, out: &mut W) -> io::Result<u64> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0447-M01","item":"ratarmount_index::managed_read::copy_into","disposition":"managed-read","regression":"regression_internal_cursor_close_keeps_posix_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut c = ManagedReadCursor::open(src)?;
    copy_cursor(&mut c, out, None)
}

fn copy_cursor<W: Write + ?Sized>(
    c: &mut ManagedReadCursor,
    out: &mut W,
    mut hash: Option<&mut Sha256>,
) -> io::Result<u64> {
    let mut buf = vec![0u8; MAX_READ_CHUNK];
    let mut total = 0u64;
    loop {
        let n = c.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        if let Some(h) = hash.as_deref_mut() {
            h.update(&buf[..n]);
        }
        out.write_all(&buf[..n])?;
        total += n as u64;
    }
}

/// How a copy's destination gets its permissions. The only policy is the
/// source's exact permissions: the destination is created with the source
/// mode (the umask applies), and the exact source permissions are applied
/// through the destination handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopySourcePermissions {
    /// The source's exact permissions.
    Exact,
}

/// Whether [`copy_exclusive_new`] computes a SHA-256 of the copied bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyDigest {
    None,
    Sha256,
}

/// A finished exclusive copy: the destination handle (for a later sync), the
/// byte count and the digest when asked for.
#[derive(Debug)]
pub struct ExclusiveCopy {
    pub file: File,
    pub len: u64,
    pub sha256: Option<String>,
}

/// Copy `src` to a NEW file `dest` (`create_new`: an existing `dest` is
/// `AlreadyExists` and is left untouched). The destination is created with the
/// source mode (umask applied); after every byte is copied the source is
/// checked unchanged (length, SQLite's moved-file check) and the exact source
/// permissions are applied through the handle. On any error after creation,
/// `dest` is removed by name. The caller must own the destination namespace:
/// cleanup does not protect against a concurrent replacement at that name.
pub fn copy_exclusive_new(
    src: &Path,
    dest: &Path,
    perms: CopySourcePermissions,
    digest: CopyDigest,
) -> io::Result<ExclusiveCopy> {
    let CopySourcePermissions::Exact = perms;
    let meta = fs::metadata(src)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0448-M01","item":"ratarmount_index::managed_read::copy_exclusive_new","disposition":"managed-read","regression":"regression_internal_cursor_close_keeps_posix_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut c = ManagedReadCursor::open(src)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0449-M01","item":"ratarmount_index::managed_read::copy_exclusive_new","disposition":"support","regression":"regression_exclusive_create_mode_table","mode_policy":"create_new with the source mode & !umask; exact source permissions through the handle after the copy","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###
    )]
    #[expect(
        clippy::disallowed_types,
        reason = r###"internal-read:v1 {"id":"IR-B0449-T01","item":"ratarmount_index::managed_read::copy_exclusive_new","disposition":"support","regression":"regression_exclusive_create_mode_table","mode_policy":"create_new with the source mode & !umask; exact source permissions through the handle after the copy","category":"builder-type-support","reason":"Builder type support: Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
    )]
    let mut opts = fs::OpenOptions::new();
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0069-M01","item":"ratarmount_index::managed_read::copy_exclusive_new","disposition":"output-owner","category":"managed-copy-output","reason":"Configure exclusive creation of the managed copy destination.","creation":{"policy":"exclusive-new-file","basis":"create_new refuses existing destinations; Unix source permission bits are applied by the copy helper before bytes are written."}}"###
    )]
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(meta.permissions().mode() & 0o7777);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0449-M02","item":"ratarmount_index::managed_read::copy_exclusive_new","disposition":"output-owner","regression":"regression_exclusive_create_mode_table","mode_policy":"create_new with the source mode & !umask; exact source permissions through the handle after the copy","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"create_new with the source mode & !umask; exact source permissions through the handle after the copy","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut file = opts.open(dest)?;
    let result = (|| {
        let mut hash = (digest == CopyDigest::Sha256).then(Sha256::new);
        let len = copy_cursor(&mut c, &mut file, hash.as_mut())?;
        file.flush()?;
        if len != meta.len() || c.len()? != len || c.has_moved()? {
            return Err(io::Error::other(format!(
                "{} changed while it was copied",
                src.display()
            )));
        }
        seams::fire(Seam::BeforePermissions)?;
        file.set_permissions(meta.permissions())?;
        seams::fire(Seam::BeforePublish)?;
        Ok((len, hash.map(|h| format!("{:x}", h.finalize()))))
    })();
    match result {
        Ok((len, sha256)) => Ok(ExclusiveCopy { file, len, sha256 }),
        Err(e) => {
            drop(file);
            let _ = fs::remove_file(dest);
            Err(e)
        }
    }
}

/// Copy `src` over `dest`, creating or truncating it (an existing file is not
/// an error, as with `std::fs::copy`). The destination is opened with the
/// source mode (umask applied) and gets the exact source permissions through
/// its handle BEFORE any byte is written, so it never has a umask-derived
/// mode. On error the destination may be truncated or partially written; it is
/// not removed (it may have existed before).
pub fn copy_create_or_truncate(src: &Path, dest: &Path) -> io::Result<u64> {
    let meta = fs::metadata(src)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0450-M01","item":"ratarmount_index::managed_read::copy_create_or_truncate","disposition":"managed-read","regression":"regression_internal_cursor_close_keeps_posix_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut c = ManagedReadCursor::open(src)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0451-M01","item":"ratarmount_index::managed_read::copy_create_or_truncate","disposition":"support","regression":"regression_exclusive_create_mode_table","mode_policy":"create-or-truncate with the source mode & !umask; exact source permissions through the handle before any write","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###
    )]
    #[expect(
        clippy::disallowed_types,
        reason = r###"internal-read:v1 {"id":"IR-B0451-T01","item":"ratarmount_index::managed_read::copy_create_or_truncate","disposition":"support","regression":"regression_exclusive_create_mode_table","mode_policy":"create-or-truncate with the source mode & !umask; exact source permissions through the handle before any write","category":"builder-type-support","reason":"Builder type support: Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
    )]
    let mut opts = fs::OpenOptions::new();
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0070-M01","item":"ratarmount_index::managed_read::copy_create_or_truncate","disposition":"output-owner","category":"managed-copy-output","reason":"Configure create-or-truncate output for a managed-source copy.","creation":{"policy":"create-or-truncate","basis":"The helper intentionally permits a zero-length/existing destination and applies source permissions before copying."}}"###
    )]
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(meta.permissions().mode() & 0o7777);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0451-M02","item":"ratarmount_index::managed_read::copy_create_or_truncate","disposition":"output-owner","regression":"regression_exclusive_create_mode_table","mode_policy":"create-or-truncate with the source mode & !umask; exact source permissions through the handle before any write","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"create-or-truncate with the source mode & !umask; exact source permissions through the handle before any write","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut file = opts.open(dest)?;
    seams::fire(Seam::BeforePermissions)?;
    file.set_permissions(meta.permissions())?;
    seams::fire(Seam::BeforeFirstWrite)?;
    let len = copy_cursor(&mut c, &mut file, None)?;
    file.flush()?;
    if len != meta.len() || c.has_moved()? {
        return Err(io::Error::other(format!(
            "{} changed while it was copied",
            src.display()
        )));
    }
    Ok(len)
}

// --------------------------------------------------------------------------
// Test seams.
// --------------------------------------------------------------------------

/// Points where a test may observe or fail a managed read (thread-local;
/// `test-hooks` builds and this crate's tests only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seam {
    /// Before the standard descriptors are filled.
    BeforeLowFdFill,
    /// Before SQLite's `xOpen` (after the standard descriptors are filled).
    BeforeOpen,
    /// After a successful acquisition.
    AfterOpen,
    /// Before each read.
    BeforeRead,
    /// Before the owner's `fsync` (`xSync`); an error stands for its failure.
    BeforeSync,
    /// Before the owner is closed (`xClose`).
    BeforeClose,
    /// After the owner was closed.
    AfterClose,
    /// Copy: before the source permissions are applied.
    BeforePermissions,
    /// Copy: before the exclusive copy is handed back.
    BeforePublish,
    /// Create-or-truncate copy: after the permissions are applied, before
    /// the first write.
    BeforeFirstWrite,
}

#[cfg(any(test, feature = "test-hooks"))]
pub mod seams {
    //! Thread-local seam callbacks (marker: `RATARMOUNT_TEST_MANAGED_READ_SEAMS`).
    use super::Seam;
    use std::cell::RefCell;
    use std::io;

    /// Present only in builds with seams; the release check looks for it.
    pub const MARKER: &str = "RATARMOUNT_TEST_MANAGED_READ_SEAMS";

    type Hook = Box<dyn FnMut(Seam) -> io::Result<()>>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static PATH: RefCell<Option<std::path::PathBuf>> = const { RefCell::new(None) };
    }

    /// The (resolved) path of the managed open in progress or last done on
    /// this thread, for a hook that must tell files apart.
    pub fn opened_path() -> Option<std::path::PathBuf> {
        PATH.with(|p| p.borrow().clone())
    }

    pub(crate) fn set_path(path: &std::path::Path) {
        PATH.with(|p| *p.borrow_mut() = Some(path.to_path_buf()));
    }

    /// The resolved path of the open just done (else `path`).
    pub(crate) fn opened_path_or(path: &std::path::Path) -> std::path::PathBuf {
        opened_path().unwrap_or_else(|| path.to_path_buf())
    }

    /// Run `f` with `hook` installed on this thread.
    pub fn with<R>(hook: impl FnMut(Seam) -> io::Result<()> + 'static, f: impl FnOnce() -> R) -> R {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                HOOK.with(|h| h.borrow_mut().take());
            }
        }
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        let _reset = Reset;
        std::hint::black_box(MARKER);
        f()
    }

    pub(crate) fn fire(seam: Seam) -> io::Result<()> {
        // Take the hook while it runs (a hook may itself read managed files).
        let Some(mut hook) = HOOK.with(|h| h.borrow_mut().take()) else {
            return Ok(());
        };
        let r = hook(seam);
        HOOK.with(|h| {
            let mut slot = h.borrow_mut();
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
        r
    }
}

#[cfg(not(any(test, feature = "test-hooks")))]
mod seams {
    use super::Seam;
    #[inline(always)]
    pub(crate) fn set_path(_: &std::path::Path) {}
    #[inline(always)]
    pub(crate) fn opened_path_or(_: &std::path::Path) -> std::path::PathBuf {
        std::path::PathBuf::new()
    }
    #[inline(always)]
    pub(crate) fn fire(_: Seam) -> std::io::Result<()> {
        Ok(())
    }
}

// --------------------------------------------------------------------------
// Standard descriptors (all Unix targets).
// --------------------------------------------------------------------------

/// Fill vacant descriptors 0-2 with `/dev/null` (never replacing an occupied
/// slot, no `dup2`) and verify all three are open; refuse on failure.
#[cfg(unix)]
pub(crate) fn ensure_standard_descriptors() -> io::Result<()> {
    fn occupied(fd: libc::c_int) -> bool {
        // SAFETY: F_GETFD on any number is harmless.
        unsafe {
            ({
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0071-M01","item":"ratarmount_index::managed_read::ensure_standard_descriptors::occupied","disposition":"out-of-family","category":"standard-descriptor-control","reason":"Check whether a standard descriptor slot is occupied before filling vacant slots.","creation":{"policy":"none","basis":"F_GETFD is a harmless query on the numeric slot; the later /dev/null opens have independent approvals."}}"###
                )]
                let __inventory_value_0 = libc::fcntl(fd, libc::F_GETFD);
                __inventory_value_0
            }) >= 0
        }
    }
    seams::fire(Seam::BeforeLowFdFill)?;
    if (0..3).all(occupied) {
        return Ok(());
    }
    #[cfg(any(test, feature = "test-hooks"))]
    if FAIL_LOW_FD_FILL.with(|f| f.get()) {
        return Err(io::Error::other(
            "cannot fill a vacant standard descriptor with /dev/null (injected)",
        ));
    }
    loop {
        // No O_CLOEXEC: the placeholder stays a standard descriptor.
        // SAFETY: a constant C string; the descriptor is ours.
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0452-M01","item":"ratarmount_index::managed_read::ensure_standard_descriptors","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"/dev/null placeholder for a vacant standard descriptor 0-2 before the byte VFS opens; reads no file content","non_mandatory_callers":["ByteFile::open"],"creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                e.kind(),
                format!("cannot fill a vacant standard descriptor with /dev/null: {e}"),
            ));
        }
        if fd >= 3 {
            // SAFETY: our own descriptor, never shared.
            unsafe { libc::close(fd) };
            break;
        }
    }
    if (0..3).all(occupied) {
        Ok(())
    } else {
        Err(io::Error::other(
            "a standard descriptor is still vacant after filling",
        ))
    }
}

#[cfg(all(unix, any(test, feature = "test-hooks")))]
thread_local! {
    /// Tests: make filling a vacant standard descriptor fail.
    pub static FAIL_LOW_FD_FILL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// How many times this process called the byte VFS's `xOpen` (tests).
#[cfg(any(test, feature = "test-hooks"))]
pub static XOPEN_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// --------------------------------------------------------------------------
// Unix: SQLite VFS byte file.
// --------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use std::ffi::{CStr, CString};
    use std::io;
    use std::os::raw::{c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use rusqlite::ffi;

    use super::{seams, Seam};

    /// The byte VFS: the one whose descriptors share SQLite's inode
    /// bookkeeping with ordinary connections.
    const VFS: &CStr = if cfg!(target_os = "macos") {
        c"unix-posix"
    } else {
        c"unix"
    };

    pub(super) struct ByteFile {
        vfs: *mut ffi::sqlite3_vfs,
        file: *mut ffi::sqlite3_file,
        name: ffi::sqlite3_filename,
        open: bool,
    }

    // SAFETY: the file object is used under the owner's mutex only; the unix
    // VFS methods are thread-safe for distinct calls on one file object.
    unsafe impl Send for ByteFile {}

    /// Map an SQLite result to an `io::Error`. `errno` is consulted only for
    /// results that come from a system call (`SQLITE_CANTOPEN` and the
    /// `SQLITE_IOERR` family other than `SQLITE_IOERR_NOMEM`): any other
    /// result leaves a stale `errno` behind, and an allocation failure read
    /// as a stale `ENOENT` would be taken for a missing file (a metadata
    /// cache entry dropped and refetched).
    pub(super) fn sqlite_err(rc: c_int, what: &str, errno: c_int) -> io::Error {
        if rc == ffi::SQLITE_NOMEM || rc == ffi::SQLITE_IOERR_NOMEM {
            return io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("{what}: SQLite out of memory (SQLite code {rc})"),
            );
        }
        let primary = rc & 0xff;
        if errno != 0 && (primary == ffi::SQLITE_CANTOPEN || primary == ffi::SQLITE_IOERR) {
            let os = io::Error::from_raw_os_error(errno);
            return io::Error::new(os.kind(), format!("{what}: {os} (SQLite code {rc})"));
        }
        io::Error::other(format!("{what}: SQLite code {rc}"))
    }

    /// `SQLITE_SYNC_FULL`: on macOS SQLite's unix VFS then issues
    /// `F_FULLFSYNC`, as `File::sync_all` (which this replaced) did; on
    /// other systems it is a plain `fsync`.
    pub(super) const SYNC_FLAGS: c_int = ffi::SQLITE_SYNC_FULL;

    impl ByteFile {
        pub(super) fn open(path: &Path, writable: bool) -> io::Result<Self> {
            // The VFS opens with O_NOFOLLOW: resolve symlinks first (an
            // absolute, existing path; a missing file is NotFound here).
            let real = std::fs::canonicalize(path)?;
            // Only regular files (a FIFO would block in `open`).
            let metadata = std::fs::metadata(&real)?;
            if !metadata.is_file() {
                return Err(super::not_regular_file(&real));
            }
            // SQLite's macOS FAT/exFAT inode workaround writes an `S` byte
            // during a writable MAIN_DB xOpen, before we can take any lock.
            // Refuse empty archives during the non-mutating preflight.
            if writable && metadata.len() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot reserve an empty archive for publication",
                ));
            }
            if crate::checked_open::thread_is_acquiring() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "managed read inside a checked SQLite acquisition",
                ));
            }
            let c = CString::new(real.as_os_str().as_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            // SAFETY: plain C calls; every pointer is checked before use and
            // freed exactly once (Drop, or the error paths below).
            unsafe {
                let vfs = ffi::sqlite3_vfs_find(VFS.as_ptr());
                if vfs.is_null() {
                    return Err(io::Error::other(format!(
                        "SQLite VFS {VFS:?} is not available"
                    )));
                }
                let size = (*vfs).szOsFile;
                let Ok(size) = u64::try_from(size) else {
                    return Err(io::Error::other("SQLite VFS file size is negative"));
                };
                let Some(xopen) = (*vfs).xOpen else {
                    return Err(io::Error::other("SQLite VFS has no xOpen"));
                };
                let file = ffi::sqlite3_malloc64(size).cast::<ffi::sqlite3_file>();
                if file.is_null() {
                    return Err(io::Error::from(io::ErrorKind::OutOfMemory));
                }
                std::ptr::write_bytes(file.cast::<u8>(), 0, size as usize);
                let name = ffi::sqlite3_create_filename(
                    c.as_ptr(),
                    c"".as_ptr(),
                    c"".as_ptr(),
                    0,
                    std::ptr::null_mut(),
                );
                if name.is_null() {
                    ffi::sqlite3_free(file.cast());
                    return Err(io::Error::from(io::ErrorKind::OutOfMemory));
                }
                let mut me = Self {
                    vfs,
                    file,
                    name,
                    open: false,
                };
                // Read lifecycle probes must not inject a reader into the
                // write reservation itself. Its exclusive acquisition and
                // disposal have separate journal regression coverage.
                if !writable {
                    seams::set_path(&real);
                }
                super::ensure_standard_descriptors()?;
                if !writable {
                    seams::fire(Seam::BeforeOpen)?;
                }
                #[cfg(any(test, feature = "test-hooks"))]
                super::XOPEN_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut out_flags: c_int = 0;
                let rc = xopen(
                    vfs,
                    name,
                    file,
                    (if writable {
                        ffi::SQLITE_OPEN_READWRITE
                    } else {
                        ffi::SQLITE_OPEN_READONLY
                    }) | ffi::SQLITE_OPEN_MAIN_DB,
                    &mut out_flags,
                );
                let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                // A failed xOpen may still have set pMethods; then it must be
                // closed (SQLite's contract), otherwise not.
                me.open = !(*file).pMethods.is_null();
                if rc != ffi::SQLITE_OK {
                    return Err(sqlite_err(
                        rc,
                        &format!("cannot open {}", real.display()),
                        errno,
                    ));
                }
                if !me.open {
                    return Err(io::Error::other("SQLite xOpen left no methods"));
                }
                if writable && out_flags & ffi::SQLITE_OPEN_READWRITE == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "archive publication requires a writable SQLite VFS reservation",
                    ));
                }
                if !writable {
                    seams::fire(Seam::AfterOpen)?;
                }
                Ok(me)
            }
        }

        fn methods(&self) -> &ffi::sqlite3_io_methods {
            // SAFETY: `open` implies a non-null methods pointer that lives as
            // long as the VFS.
            unsafe { &*(*self.file).pMethods }
        }

        fn last_errno(&self) -> c_int {
            let mut e: c_int = 0;
            if let Some(fc) = self.methods().xFileControl {
                // SAFETY: SQLITE_FCNTL_LAST_ERRNO writes one int.
                unsafe {
                    fc(
                        self.file,
                        ffi::SQLITE_FCNTL_LAST_ERRNO,
                        (&mut e as *mut c_int).cast::<c_void>(),
                    )
                };
            }
            e
        }

        pub(super) fn len(&mut self) -> io::Result<u64> {
            let Some(size) = self.methods().xFileSize else {
                return Err(io::Error::other("SQLite VFS has no xFileSize"));
            };
            let mut n: ffi::sqlite3_int64 = 0;
            // SAFETY: an open file object.
            let rc = unsafe { size(self.file, &mut n) };
            if rc != ffi::SQLITE_OK {
                return Err(sqlite_err(rc, "file size", self.last_errno()));
            }
            if n == 0 {
                // SQLite reports a 1-byte file as 0 bytes (its macOS msdos
                // workaround, ticket #3260): probe one byte to tell them apart.
                let Some(read) = self.methods().xRead else {
                    return Err(io::Error::other("SQLite VFS has no xRead"));
                };
                let mut b = 0u8;
                // SAFETY: one byte of valid memory.
                let rc = unsafe { read(self.file, (&mut b as *mut u8).cast::<c_void>(), 1, 0) };
                return match rc {
                    ffi::SQLITE_OK => Ok(1),
                    ffi::SQLITE_IOERR_SHORT_READ => Ok(0),
                    _ => Err(sqlite_err(rc, "read", self.last_errno())),
                };
            }
            u64::try_from(n).map_err(|_| io::Error::other("negative file size"))
        }

        /// Read exactly `buf.len()` bytes (at most [`MAX_READ_CHUNK`]) at
        /// `offset`; a short read is an error (the zero-filled tail SQLite
        /// returns for it is never handed out).
        pub(super) fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
            debug_assert!(buf.len() <= super::MAX_READ_CHUNK);
            let Some(read) = self.methods().xRead else {
                return Err(io::Error::other("SQLite VFS has no xRead"));
            };
            let amt = c_int::try_from(buf.len()).map_err(|_| io::Error::other("read too large"))?;
            let off = ffi::sqlite3_int64::try_from(offset)
                .map_err(|_| io::Error::other("offset too large"))?;
            // SAFETY: `buf` is valid for `amt` bytes.
            let rc = unsafe { read(self.file, buf.as_mut_ptr().cast::<c_void>(), amt, off) };
            match rc {
                ffi::SQLITE_OK => Ok(()),
                ffi::SQLITE_IOERR_SHORT_READ => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short read (the file shrank while it was read)",
                )),
                _ => Err(sqlite_err(rc, "read", self.last_errno())),
            }
        }

        pub(super) fn sync(&mut self) -> io::Result<()> {
            let Some(sync) = self.methods().xSync else {
                return Err(io::Error::other("SQLite VFS has no xSync"));
            };
            // SAFETY: an open file object.
            let rc = unsafe { sync(self.file, SYNC_FLAGS) };
            if rc != ffi::SQLITE_OK {
                return Err(sqlite_err(rc, "fsync", self.last_errno()));
            }
            Ok(())
        }

        pub(super) fn lock_exclusive(&mut self) -> io::Result<()> {
            let Some(lock) = self.methods().xLock else {
                return Err(io::Error::other("SQLite VFS has no xLock"));
            };
            for level in [
                ffi::SQLITE_LOCK_SHARED,
                ffi::SQLITE_LOCK_RESERVED,
                ffi::SQLITE_LOCK_EXCLUSIVE,
            ] {
                // SAFETY: an open MAIN_DB byte file; no pager or SQL connection
                // uses this object. xClose releases any partial reservation.
                let rc = unsafe { lock(self.file, level) };
                if rc == ffi::SQLITE_BUSY || rc == ffi::SQLITE_LOCKED {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "archive is in use by a SQLite transaction; publication was refused",
                    ));
                }
                if rc != ffi::SQLITE_OK {
                    return Err(sqlite_err(rc, "reserve archive", self.last_errno()));
                }
            }
            Ok(())
        }

        #[cfg(any(test, feature = "test-hooks"))]
        pub(super) fn lock_shared(&mut self) -> io::Result<()> {
            let lock = self.methods().xLock.expect("xLock");
            // SAFETY: an open file object.
            let rc = unsafe { lock(self.file, ffi::SQLITE_LOCK_SHARED) };
            if rc != ffi::SQLITE_OK {
                return Err(sqlite_err(rc, "lock", self.last_errno()));
            }
            Ok(())
        }

        #[cfg(any(test, feature = "test-hooks"))]
        pub(super) fn unlock(&mut self) {
            if let Some(unlock) = self.methods().xUnlock {
                // SAFETY: an open file object.
                unsafe { unlock(self.file, ffi::SQLITE_LOCK_NONE) };
            }
        }

        pub(super) fn has_moved(&mut self) -> io::Result<bool> {
            let Some(fc) = self.methods().xFileControl else {
                return Ok(false);
            };
            let mut moved: c_int = 0;
            // SAFETY: SQLITE_FCNTL_HAS_MOVED writes one int.
            let rc = unsafe {
                fc(
                    self.file,
                    ffi::SQLITE_FCNTL_HAS_MOVED,
                    (&mut moved as *mut c_int).cast::<c_void>(),
                )
            };
            Ok(rc == ffi::SQLITE_OK && moved != 0)
        }
    }

    impl Drop for ByteFile {
        fn drop(&mut self) {
            // SAFETY: closed at most once; memory freed exactly once.
            unsafe {
                if self.open {
                    if let Some(close) = self.methods().xClose {
                        // An error is not retried: SQLite has already
                        // retired (or parked) the descriptor.
                        close(self.file);
                    }
                }
                let _ = self.vfs;
                ffi::sqlite3_free(self.file.cast());
                ffi::sqlite3_free_filename(self.name);
            }
        }
    }
}

// --------------------------------------------------------------------------
// Other targets: an ordinary private file.
// --------------------------------------------------------------------------

#[cfg(not(unix))]
#[path = "managed_read/nonunix.rs"]
mod imp;

#[cfg(all(unix, any(test, feature = "test-hooks")))]
pub mod lock_probe {
    //! Does ANOTHER process see a lock this process holds on a file? A forked
    //! child (only async-signal-safe calls: `open`, `fcntl`, `_exit`) asks
    //! `F_GETLK` for a write lock over SQLite's lock bytes (PENDING, RESERVED
    //! and the SHARED range at `0x40000000`), so SHARED counts and a
    //! read-only file can be probed.
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub fn other_process_sees_lock(path: &Path) -> bool {
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the child only calls async-signal-safe functions.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0072-M01","item":"ratarmount_index::managed_read::lock_probe::other_process_sees_lock","disposition":"out-of-family","category":"feature-test-hook","reason":"Open the explicit lock-probe file read-only in the forked child process.","creation":{"policy":"none","basis":"The child uses O_RDONLY/CLOEXEC only, asks the kernel about locks and exits; no file is created or content read."}}"###
                )]
                let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    libc::_exit(3);
                }
                let mut lk: libc::flock = std::mem::zeroed();
                lk.l_type = libc::F_WRLCK as _;
                lk.l_whence = libc::SEEK_SET as _;
                lk.l_start = 0x4000_0000;
                lk.l_len = 512;
                if {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-E0073-M01","item":"ratarmount_index::managed_read::lock_probe::other_process_sees_lock","disposition":"out-of-family","category":"feature-test-hook","reason":"Ask F_GETLK whether the child observes the parent SQLite shared lock.","creation":{"policy":"none","basis":"This query uses the child-held descriptor and neither duplicates nor creates a resource."}}"###
                    )]
                    let __inventory_value_0 = libc::fcntl(fd, libc::F_GETLK, &mut lk);
                    __inventory_value_0
                } != 0
                {
                    libc::_exit(4);
                }
                #[allow(clippy::unnecessary_cast)]
                let unlocked = lk.l_type as i32 == libc::F_UNLCK as i32;
                libc::_exit(if unlocked { 0 } else { 1 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status), "probe child died");
            match libc::WEXITSTATUS(status) {
                0 => false,
                1 => true,
                n => panic!("probe child failed ({n})"),
            }
        }
    }
}

/// Run `f`; for every managed read on this thread of a path `want` accepts,
/// hold a SHARED lock of this SQLite instance on that file from the open to
/// the close, and record whether another process still sees it right after
/// the managed close (the close must not release it). Tests only.
#[cfg(all(unix, any(test, feature = "test-hooks")))]
pub fn with_close_probes<R>(
    want: impl Fn(&Path) -> bool + 'static,
    f: impl FnOnce() -> R,
) -> (R, Vec<(std::path::PathBuf, bool)>) {
    use std::cell::RefCell;
    use std::rc::Rc;
    let held: Rc<RefCell<Vec<(std::path::PathBuf, VfsLockHolder)>>> = Rc::default();
    let seen: Rc<RefCell<Vec<(std::path::PathBuf, bool)>>> = Rc::default();
    let (h2, s2) = (Rc::clone(&held), Rc::clone(&seen));
    let r = seams::with(
        move |s| {
            let Some(path) = seams::opened_path() else {
                return Ok(());
            };
            if !want(&path) {
                return Ok(());
            }
            match s {
                Seam::AfterOpen => {
                    if let Ok(lock) = {
                        #[expect(
                            clippy::disallowed_methods,
                            reason = r###"internal-read:v1 {"id":"IR-E0074-M01","item":"ratarmount_index::managed_read::with_close_probes","disposition":"out-of-family","category":"feature-test-hook","reason":"Acquire a managed shared-lock holder at the AfterOpen test seam to verify that managed closes retain locks.","creation":{"policy":"none","basis":"VfsLockHolder opens an existing path through ByteFile; this all-features test-hooks instrumentation requests no creation."}}"###
                        )]
                        let __inventory_value_0 = VfsLockHolder::shared(&path);
                        __inventory_value_0
                    } {
                        h2.borrow_mut().push((path, lock));
                    }
                }
                Seam::AfterClose => {
                    let mut held = h2.borrow_mut();
                    if let Some(i) = held.iter().rposition(|(p, _)| *p == path) {
                        let (p, lock) = held.remove(i);
                        #[expect(
                            clippy::disallowed_methods,
                            reason = r###"internal-read:v1 {"id":"IR-E0075-M01","item":"ratarmount_index::managed_read::with_close_probes","disposition":"out-of-family","category":"feature-test-hook","reason":"Run the child lock-observation probe after a managed close before releasing the test-held lock.","creation":{"policy":"none","basis":"The probe only queries an existing file/lock relationship and has separately reviewed child acquisition."}}"###
                        )]
                        let kept = lock_probe::other_process_sees_lock(&p);
                        s2.borrow_mut().push((p, kept));
                        drop(lock);
                    }
                }
                _ => {}
            }
            Ok(())
        },
        f,
    );
    held.borrow_mut().clear();
    let seen = seen.borrow().clone();
    (r, seen)
}

/// The VFS SQLite actually opened `conn`'s main database with
/// (`SQLITE_FCNTL_VFSNAME`). Tests only.
#[cfg(any(test, feature = "test-hooks"))]
pub fn connection_vfs_name(conn: &rusqlite::Connection) -> String {
    use rusqlite::ffi;
    let mut name: *mut std::os::raw::c_char = std::ptr::null_mut();
    // SAFETY: SQLITE_FCNTL_VFSNAME writes a sqlite3_malloc'd string.
    unsafe {
        let rc = ffi::sqlite3_file_control(
            conn.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_VFSNAME,
            (&mut name as *mut *mut std::os::raw::c_char).cast(),
        );
        assert_eq!(rc, ffi::SQLITE_OK, "SQLITE_FCNTL_VFSNAME");
        let s = std::ffi::CStr::from_ptr(name)
            .to_string_lossy()
            .into_owned();
        ffi::sqlite3_free(name.cast());
        s
    }
}

/// Holds a SHARED lock on any file through this SQLite instance's own VFS
/// (a stand-in for a connection on a file that is not a database, e.g. a
/// compressed index or an archive). Tests only.
#[cfg(all(unix, any(test, feature = "test-hooks")))]
pub struct VfsLockHolder {
    file: imp::ByteFile,
}

#[cfg(all(unix, any(test, feature = "test-hooks")))]
#[path = "managed_read/vfs_lock_holder.rs"]
mod vfs_lock_holder;

#[cfg(test)]
#[path = "managed_read_tests.rs"]
mod tests;
