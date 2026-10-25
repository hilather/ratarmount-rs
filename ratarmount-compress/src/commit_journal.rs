//! Durable, content-checked rollback for an in-place archive suffix replacement.
//!
//! The immutable, checksummed journal holds both tails. An inode xattr locates
//! it through hard links and bind mounts. Atomic xattr updates distinguish
//! preparation (`P`), active replacement (`A`), a fully synced completed
//! replacement whose `before_unlink` hook has not been confirmed (`C`), and a
//! completed replacement whose hook returned `Ok` (`D`: only the journal
//! unlink, its directory sync and the clear are owed).
//!
//! A replacement that fails is cleaned up by the attempt itself, under the
//! archive lock it never released, from its own record of what it published
//! ([`ReplaceError`]). Crash recovery finds a journal through the locator, or
//! beside the archive's current name when the directory was renamed; a complete
//! locator (`C`/`D`) whose journal cannot be found is never cleared.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// Suffix of the commit journal written beside an archive.
pub const COMMIT_JOURNAL_SUFFIX: &str = ".ratarmount-commit-journal";

pub fn journal_path(archive: &Path) -> PathBuf {
    let canonical = archive
        .canonicalize()
        .unwrap_or_else(|_| archive.to_path_buf());
    let mut name = canonical.into_os_string();
    name.push(COMMIT_JOURNAL_SUFFIX);
    PathBuf::from(name)
}

fn recovery_error(path: &Path, reason: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!(
        "commit journal '{}': {reason}; archive left untouched where possible. \
         Retry recovery with write access; if the archive was externally replaced, \
         restore the matching archive and journal from backup, or verify the replacement \
         before removing this journal and its user.ratarmount.commit-journal xattr",
        path.display()
    ))
}

// Crash matrix (what a later recovery finds and does; "rows" are the
// overlay's recorded base stamp, restamped by the `before_unlink` hook):
// (a) rollback restamped the rows, crash before the unlink: journal + `P`,
//     rows = the rolled-back stamp -> agrees (disjunct 3); old bytes in place:
//     nothing written; the hook sees a journal not started on the rows and
//     leaves them; unlink.
// (b) rollback with an unrestorable mtime (EPERM) whose hook failed: journal +
//     `P`, rows = the pre stamp -> agrees (disjunct 1); nothing written; the
//     hook moves the rows to the current mtime; unlink.
// (c) `A`, crash before the truncate: agrees; nothing written; exact restore
//     leaves the rows; unlink.
// (d) equal-stamp roll-forward, crash before the unlink: rows = final = pre ->
//     agrees; the hook re-invalidates a strong digest (idempotent); unlink.
// (e) the attempt unlinked its journal, crash before the directory sync:
//     `D` kept; a resurrected journal rolls forward (the hook is idempotent);
//     none: `D` stays until recovered through a name beside its journal or
//     removed by hand (Astra v4 F1: its absence is ambiguous).
// (f) crash between `C` and the hook, directory renamed: the journal beside
//     the archive's new name is found and rolled forward; a base that left its
//     recorded place is left to the gate (rows unchanged). Recovered through a
//     hard link in a third directory: `C` is refused, nothing is dropped.
// (g) `C` whose journal was deleted by hand: refused, the error names the
//     manual escape.
// No ordering leaves "journal gone, rows stale" for a journal on the recorded
// base, "rows moved, bytes not", or "bytes new, digest old".

/// Test-only fault injection, consulted at every step of a replacement and of
/// a rollback. A step is either a checkpoint (consulted after the step
/// succeeded) or an instead-of seam (an `Err` replaces the system call). Without
/// `cfg(test)` or the `test-hooks` feature every check is `Ok(())`.
#[doc(hidden)]
pub mod fault {
    use std::io;

    #[cfg(any(test, feature = "test-hooks"))]
    type Fault = Box<dyn FnMut(&'static str) -> io::Result<()>>;

    #[cfg(any(test, feature = "test-hooks"))]
    thread_local! {
        static FAULT: std::cell::RefCell<Option<Fault>> = const { std::cell::RefCell::new(None) };
    }

    /// Install the fault for this thread (replacing any earlier one).
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn install(fault: impl FnMut(&'static str) -> io::Result<()> + 'static) {
        FAULT.with(|slot| *slot.borrow_mut() = Some(Box::new(fault)));
    }

    /// Remove this thread's fault.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn clear() {
        FAULT.with(|slot| *slot.borrow_mut() = None);
    }

    /// Consult the fault at `step`. The fault is taken out while it runs, so a
    /// replacement or recovery it starts itself sees no fault.
    pub(crate) fn check(step: &'static str) -> io::Result<()> {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            let Some(mut fault) = FAULT.with(|slot| slot.borrow_mut().take()) else {
                return Ok(());
            };
            let result = fault(step);
            FAULT.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_none() {
                    *slot = Some(fault);
                }
            });
            result
        }
        #[cfg(not(any(test, feature = "test-hooks")))]
        {
            let _ = step;
            Ok(())
        }
    }

    /// [`check`] for a step another crate's copy fallback runs ("copy source
    /// open" before it opens and compares its source, "copy source opened"
    /// after): every copy path shares the step names.
    pub fn point(step: &'static str) -> io::Result<()> {
        check(step)
    }

    /// An instead-of seam: a fault's `Err` replaces `op`.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    pub(crate) fn instead<T>(
        step: &'static str,
        op: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        check(step)?;
        op()
    }
}

/// What recovery applied, read from the LOCKED descriptor right before the
/// journal is unlinked: the only stamp a caller may record for the archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The journal was complete: the archive keeps the new bytes. `false` is a
    /// rollback to the state `pre_len`/`pre_mtime_ns` describe.
    pub rolled_forward: bool,
    pub pre_len: u64,
    pub pre_mtime_ns: i128,
    pub new_len: u64,
    /// `fstat` of the locked descriptor, taken after the final sync and the
    /// completion marker, immediately before `before_unlink` runs.
    pub dev: u64,
    pub ino: u64,
    pub final_len: u64,
    pub final_mtime_ns: i128,
}

/// Why a recovery or a journaled replacement did not finish.
#[derive(Debug)]
pub enum RecoverError {
    /// The authorizer said no; nothing was written.
    Refused(io::Error),
    /// The journal could not be applied or cleaned up and the archive does not
    /// hold the new bytes (it is untouched or rolled back).
    Journal(io::Error),
    /// The archive holds the new bytes but the journal is still pending
    /// because the `before_unlink` hook (or the cleanup) failed. Never answer
    /// this with a copy fallback.
    Committed(io::Error),
}

impl RecoverError {
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Refused(e) | Self::Journal(e) | Self::Committed(e) => e,
        }
    }
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(e) | Self::Journal(e) | Self::Committed(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RecoverError {}

impl From<RecoverError> for io::Error {
    fn from(error: RecoverError) -> Self {
        error.into_io()
    }
}

/// Runs under the archive lock with the header read there and the LOCKED
/// descriptor's metadata (never a path stat), after the journal was validated
/// and before the first write. `Err` refuses the recovery.
pub type Authorize<'a> = &'a mut dyn FnMut(&PendingJournal, &fs::Metadata) -> io::Result<()>;

/// Runs under the archive lock after the final sync and completion marker and
/// before the journal is unlinked. An error keeps the journal and the marker,
/// so the next recovery runs the hook again (it must be idempotent).
pub type BeforeUnlink<'a> = &'a mut dyn FnMut(&Applied) -> io::Result<()>;

/// Runs under the archive lock, after the locator was re-read there, before
/// the FIRST write of a recovery: before a stale `P` locator is cleared and
/// before a journal is rolled back or forward. `Err` refuses the recovery
/// ([`RecoverError::Refused`]) with nothing written, the locator included.
pub type BeforeWrite<'a> = &'a mut dyn FnMut() -> io::Result<()>;

/// Ownership only: the journal was started for the very file locked.
pub fn authorize_owned(journal: &PendingJournal, file: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if journal.ino != file.ino() {
            return Err(io::Error::other(format!(
                "the archive carries a commit journal that was started for another file \
                 (journal inode {}, archive inode {}); the journal was not applied",
                journal.ino,
                file.ino()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = (journal, file);
    Ok(())
}

/// The journal and the locked file are the one a replacement attempt started
/// for (`dev`/`ino` of the file it locked): the cleanup of a failed replacement
/// must never touch another file's journal.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn authorize_started(
    journal: &PendingJournal,
    file: &fs::Metadata,
    started: (u64, u64),
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if journal.ino != started.1 || (file.dev(), file.ino()) != started {
        return Err(io::Error::other(format!(
            "the archive carries a commit journal that this replacement did not start \
             (journal inode {}, archive {}:{}, attempt {}:{}); the journal was not applied",
            journal.ino,
            file.dev(),
            file.ino(),
            started.0,
            started.1
        )));
    }
    Ok(())
}

/// Accept any journal: only behind an explicit `--force-*` flag (or in tests).
pub fn authorize_forced(_: &PendingJournal, _: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

/// Forced recovery for tests: it neither authorizes nor restamps. Production
/// callers go through the compositing crate's `recover_journal_at` (or
/// `WriteOverlay::recover_journal`).
#[doc(hidden)]
pub fn recover(archive: &Path) -> io::Result<bool> {
    #[expect(
        clippy::disallowed_methods,
        reason = "The documented test recovery helper explicitly selects forced authorization"
    )]
    let mut authorize = authorize_forced;
    #[expect(
        clippy::disallowed_methods,
        reason = "The test recovery helper delegates to the journal recovery implementation"
    )]
    let recovered = recover_with(archive, &mut authorize, &mut |_| Ok(()));
    recovered
        .map(|applied| applied.is_some())
        .map_err(RecoverError::into_io)
}

/// THE recovery entry. An unlocked probe (marker or sibling journal present?
/// else `Ok(None)` without locking) → open read-write → flock → `(state, path)`
/// both re-derived from the locked descriptor's marker; the journal is the
/// locator's path, else the sibling [`journal_path`] of `archive` when its
/// header names the locked inode (a directory renamed under the journal) → a
/// missing journal: `P` is cleared after a parent sync, `A` is an error, `C` is
/// refused with the locator kept, `D` is kept (its absence is ambiguous: the
/// journal may sit beside another name of the file) → the header is validated →
/// `authorize(header, fstat)` → writes → marker → `before_unlink(&Applied)` →
/// `D` → unlink → clear.
pub fn recover_with(
    archive: &Path,
    authorize: Authorize,
    before_unlink: BeforeUnlink,
) -> std::result::Result<Option<Applied>, RecoverError> {
    #[expect(
        clippy::disallowed_methods,
        reason = "The recovery API delegates to its guarded implementation with an empty extra guard"
    )]
    let recovered = recover_guarded(archive, &mut || Ok(()), authorize, before_unlink);
    recovered
}

/// [`recover_with`] with a `before_write` guard (R10-B): it runs under the
/// lock inside the stale-`P` branch (before the parent sync and the locator
/// clear) and immediately before the rollback, never on the paths that write
/// nothing (`None`, `D`) or that refuse a missing complete journal (`C`), so
/// their outcomes keep their error variants.
pub fn recover_guarded(
    archive: &Path,
    before_write: BeforeWrite,
    authorize: Authorize,
    before_unlink: BeforeUnlink,
) -> std::result::Result<Option<Applied>, RecoverError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::recover(archive, before_write, authorize, before_unlink)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (before_write, authorize, before_unlink);
        if journal_path(archive)
            .try_exists()
            .map_err(RecoverError::Journal)?
        {
            return Err(RecoverError::Journal(recovery_error(
                &journal_path(archive),
                "recovery requires Linux/macOS inode xattrs",
            )));
        }
        Ok(None)
    }
}

/// What a pending journal says about the archive it was started for. Read
/// without a lock and without writing, so a caller can decide whether the
/// journal is its own BEFORE [`recover`] rolls anything back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingJournal {
    /// Device and inode of the archive when the journal started (hints: device
    /// numbers may change on reboot).
    pub dev: u64,
    pub ino: u64,
    /// Size and mtime (nanoseconds since the epoch) of the archive BEFORE the
    /// replacement began: what a rollback restores.
    pub len: u64,
    pub mtime_ns: i128,
    /// Where the replaced suffix starts and the length the replacement ends at.
    pub offset: u64,
    pub new_len: u64,
    /// The replacement finished (the locator says `C` or `D`): recovery rolls
    /// FORWARD and leaves the new bytes.
    pub complete: bool,
}

/// The journal pending for `archive`, found the way [`recover_with`] finds it
/// (the inode locator first, then the sibling path). `Ok(None)` when there is
/// none or the platform has no journals. Never writes.
pub fn pending(archive: &Path) -> io::Result<Option<PendingJournal>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::pending(archive)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = archive;
        Ok(None)
    }
}

/// Why a journaled replacement did not finish. Every variant after
/// `Refused` is decided by the attempt from its own record, under the archive
/// lock it took, before the lock is released.
#[derive(Debug)]
pub enum ReplaceError {
    /// Before the attempt started (open, lock busy, a pending journal or
    /// locator, the archive changed since the caller's snapshot): nothing of
    /// this attempt exists.
    Refused(io::Error),
    /// Started and failed; nothing of this attempt remains: the bytes were
    /// never touched or were rolled back under the same lock, no journal of
    /// this attempt is on disk, and the hook saw the rollback whenever a
    /// journal was published. A copy fallback may run (behind
    /// [`guard_copy`]). The second field is the locked descriptor's stamp
    /// after the cleanup, read before the lock was released (`None` when it
    /// could not be read): the only file a copy fallback may read is one
    /// still exactly at that stamp.
    RolledBack(io::Error, Option<Box<fs::Metadata>>),
    /// Started and failed; this attempt's journal (old or torn bytes) is on
    /// disk or no longer where the attempt put it. Recover through the gate.
    /// Never answer with a copy.
    Pending(io::Error),
    /// The archive holds the new bytes; the journal and its `C`/`D` locator
    /// stay (the hook, the unlink or the directory sync failed, or the journal
    /// is no longer where the attempt put it). Never answer with a copy and
    /// never report success.
    Committed(io::Error),
}

impl ReplaceError {
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Refused(e) | Self::RolledBack(e, _) | Self::Pending(e) | Self::Committed(e) => e,
        }
    }
}

impl std::fmt::Display for ReplaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(e) | Self::RolledBack(e, _) | Self::Pending(e) | Self::Committed(e) => {
                e.fmt(f)
            }
        }
    }
}

impl std::error::Error for ReplaceError {}

impl From<ReplaceError> for io::Error {
    fn from(error: ReplaceError) -> Self {
        error.into_io()
    }
}

/// Replace the archive's suffix from `offset` with `suffix`, journaled, when
/// the archive is still the file `original` describes. `before_unlink` runs
/// under the archive lock with the final stamp, before the journal is
/// unlinked; it may run twice (it must be idempotent). A failure is cleaned up
/// under the same lock from the attempt's own record ([`ReplaceError`]).
pub fn replace_suffix_if_unchanged_with(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    original: &fs::Metadata,
    before_unlink: BeforeUnlink,
) -> std::result::Result<(), ReplaceError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::replace(
            archive,
            offset,
            suffix,
            Some(original),
            true,
            &mut |_| Ok(()),
            before_unlink,
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (archive, offset, suffix, original, before_unlink);
        Err(ReplaceError::Refused(io::Error::new(
            io::ErrorKind::Unsupported,
            "append requires Linux/macOS inode xattrs",
        )))
    }
}

/// Simulate process death: unlike the production entry point, leave recovery
/// to the caller after an injected error.
#[doc(hidden)]
pub fn replace_suffix_with_hook(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    hook: &mut dyn FnMut(&'static str) -> io::Result<()>,
) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::replace(archive, offset, suffix, None, false, hook, &mut |_| Ok(()))
            .map_err(ReplaceError::into_io)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (archive, offset, suffix, hook);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "append requires Linux/macOS inode xattrs",
        ))
    }
}

/// The full stamp a replacement or a copy compares: device, inode, length,
/// mtime and ctime (seconds and nanoseconds).
pub fn same_stamp(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            a.dev(),
            a.ino(),
            a.len(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.dev(),
            b.ino(),
            b.len(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}

/// Held while a copy fallback publishes over an archive: the archive's flock.
pub struct CopyGuard {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    _lock: unix::Lock,
}

/// Lock `archive` for a copy fallback that read the file `source` describes.
/// Refused when the lock is busy, a journal or locator is pending, or the
/// locked file is not exactly `source` (device, inode, length, mtime, ctime).
/// Hold the guard until the copy has been renamed over the archive.
pub fn guard_copy(archive: &Path, source: &fs::Metadata) -> io::Result<CopyGuard> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::guard_copy(archive, source)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (archive, source);
        Ok(CopyGuard {})
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, UNIX_EPOCH};

    const MAGIC: &[u8; 8] = b"RMCJ0002";
    pub(super) const HEADER_LEN: u64 = 96;
    const XATTR: &std::ffi::CStr = c"user.ratarmount.commit-journal";

    pub(crate) struct Lock(File);
    impl Drop for Lock {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
    fn lock(file: &File) -> io::Result<Lock> {
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0212-M01","item":"ratarmount_compress::commit_journal::unix::lock","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        let owned = file.try_clone()?;
        if unsafe { libc::flock(owned.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Lock(owned))
    }
    fn parent(path: &Path) -> &Path {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
    }
    fn sync_parent(path: &Path) -> io::Result<()> {
        {
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0213-M01","item":"ratarmount_compress::commit_journal::unix::sync_parent","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"directory handle opened only to fsync a directory entry","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###))]
let __inventory_value_0 = File::open(parent(path));
__inventory_value_0
}?.sync_all()
    }
    /// [`sync_parent`] where a parent that no longer exists has nothing to sync.
    fn sync_parent_if_present(path: &Path) -> io::Result<()> {
        match sync_parent(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    fn get_marker(file: &File) -> io::Result<Option<(u8, PathBuf)>> {
        let mut bytes = vec![0u8; 8192];
        #[cfg(target_os = "linux")]
        let n = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                XATTR.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        #[cfg(target_os = "macos")]
        let n = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                XATTR.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                0,
                0,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            #[cfg(target_os = "macos")]
            let missing = e.raw_os_error() == Some(libc::ENOATTR);
            #[cfg(not(target_os = "macos"))]
            let missing = e.raw_os_error() == Some(libc::ENODATA);
            if missing || e.raw_os_error() == Some(libc::ENOTSUP) {
                return Ok(None);
            }
            return Err(e);
        }
        bytes.truncate(n as usize);
        decode_marker(&bytes)
    }

    fn decode_marker(bytes: &[u8]) -> io::Result<Option<(u8, PathBuf)>> {
        if bytes.len() < 6
            || !matches!(bytes[4], b'P' | b'A' | b'C' | b'D')
            || crc32fast::hash(&bytes[4..]) != u32::from_le_bytes(bytes[..4].try_into().unwrap())
        {
            return Err(io::Error::other("invalid commit journal locator checksum"));
        }
        Ok(Some((
            bytes[4],
            PathBuf::from(std::ffi::OsString::from_vec(bytes[5..].to_vec())),
        )))
    }

    fn marker(file: &File, path: &Path, state: u8) -> io::Result<()> {
        let mut bytes = vec![0; 4];
        bytes.push(state);
        bytes.extend_from_slice(path.as_os_str().as_bytes());
        let crc = crc32fast::hash(&bytes[4..]);
        bytes[..4].copy_from_slice(&crc.to_le_bytes());
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                XATTR.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        };
        #[cfg(target_os = "macos")]
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                XATTR.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        file.sync_all()
    }
    fn clear_marker(file: &File) -> io::Result<()> {
        if get_marker(file)?.is_none() {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        let rc = unsafe { libc::fremovexattr(file.as_raw_fd(), XATTR.as_ptr()) };
        #[cfg(target_os = "macos")]
        let rc = unsafe { libc::fremovexattr(file.as_raw_fd(), XATTR.as_ptr(), 0) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        file.sync_all()
    }

    // Boundary fingerprints avoid rereading a multi-hundred-GB preserved prefix.
    fn fingerprint(file: &mut File, offset: u64) -> io::Result<[u8; 32]> {
        let mut hash = Sha256::new();
        let mut bytes = [0; 65536];
        for start in [0, offset.saturating_sub(bytes.len() as u64)] {
            let len = (offset - start).min(bytes.len() as u64) as usize;
            file.seek(SeekFrom::Start(start))?;
            file.read_exact(&mut bytes[..len])?;
            hash.update(&bytes[..len]);
        }
        Ok(hash.finalize().into())
    }
    fn checksum(file: &mut File, len: u64) -> io::Result<u32> {
        file.rewind()?;
        let mut hash = crc32fast::Hasher::new();
        let mut remaining = len;
        let mut bytes = [0; 65536];
        while remaining > 0 {
            let n = remaining.min(bytes.len() as u64) as usize;
            file.read_exact(&mut bytes[..n])?;
            hash.update(&bytes[..n]);
            remaining -= n as u64;
        }
        Ok(hash.finalize())
    }
    fn copy_exact(src: &mut File, dst: &mut File, len: u64) -> io::Result<()> {
        if io::copy(&mut src.take(len), dst)? != len {
            return Err(io::Error::other("short archive or suffix while journaling"));
        }
        Ok(())
    }

    /// What the attempt did, each field set right after its step returned
    /// `Ok` and before that step's checkpoint, so a fault leaves the record
    /// equal to the disk.
    #[derive(Default)]
    struct Attempt {
        /// `(dev, ino)` of the journal file this attempt published.
        published: Option<(u64, u64)>,
        /// The `C` locator was installed and synced.
        completed: bool,
        /// This attempt unlinked its journal (after the hook and `D`).
        unlinked: bool,
        /// The unlink's directory sync returned `Ok`.
        synced: bool,
    }

    pub(super) fn replace(
        archive: &Path,
        offset: u64,
        suffix: &mut File,
        original: Option<&fs::Metadata>,
        cleanup: bool,
        hook: &mut dyn FnMut(&'static str) -> io::Result<()>,
        before_unlink: BeforeUnlink,
    ) -> std::result::Result<(), ReplaceError> {
        // Every checkpoint consults the death seam, then the fault.
        let mut hook = |step: &'static str| -> io::Result<()> {
            hook(step)?;
            fault::check(step)
        };
        let refused = ReplaceError::Refused;
        fault::check("before replace").map_err(refused)?;
        let archive = archive.canonicalize().map_err(refused)?;
        let path = journal_path(&archive);
        let mut file = {
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_types, reason = r###"internal-read:v1 {"id":"IR-B0214-T01","item":"ratarmount_compress::commit_journal::unix::replace","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-type-support","reason":"Builder type support: Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###))]
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0214-M01","item":"ratarmount_compress::commit_journal::unix::replace","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###))]
let mut __inventory_value_0 = fs::OpenOptions::new();
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0214-M02","item":"ratarmount_compress::commit_journal::unix::replace","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###))]
let __inventory_value_1 = __inventory_value_0
            .read(true)
            .write(true)
            .open(&archive);
__inventory_value_1
}
            .map_err(refused)?;
        // Held until this function returns: the cleanup of a failed attempt
        // runs under the same lock.
        let _lock = lock(&file).map_err(refused)?;
        if let Some(e) =
            pending_refusal(&path, &file, "recover before preparing a commit").map_err(refused)?
        {
            return Err(refused(e));
        }
        let meta = file.metadata().map_err(refused)?;
        if original.is_some_and(|old| !same_stamp(old, &meta)) {
            return Err(refused(io::Error::other(
                "archive changed while preparing append; retry with a fresh plan",
            )));
        }
        let mut attempt = Attempt::default();
        let error = match run(
            &mut file,
            &path,
            &archive,
            offset,
            suffix,
            &meta,
            &mut attempt,
            &mut hook,
            &mut *before_unlink,
        ) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        let unresolved = |e: io::Error| {
            if attempt.completed {
                ReplaceError::Committed(e)
            } else {
                ReplaceError::Pending(e)
            }
        };
        if !cleanup {
            // The death seam: the process "died"; the disk is left as it is.
            return Err(unresolved(error));
        }
        if let Err(x) = fault::check("before cleanup") {
            return Err(unresolved(join(error, x)));
        }
        match finish_failed(&mut file, &path, &attempt, error, before_unlink) {
            // The stamp a copy fallback compares against, taken under the
            // lock after the last write of the cleanup (the locator xattr).
            Err(ReplaceError::RolledBack(e, _)) => Err(ReplaceError::RolledBack(
                e,
                file.metadata().ok().map(Box::new),
            )),
            other => other,
        }
    }

    fn join(error: io::Error, other: impl std::fmt::Display) -> io::Error {
        io::Error::new(error.kind(), format!("{error}; {other}"))
    }

    /// Steps of a replacement after the lock and the staleness check.
    #[allow(clippy::too_many_arguments)]
    fn run(
        file: &mut File,
        path: &Path,
        archive: &Path,
        offset: u64,
        suffix: &mut File,
        meta: &fs::Metadata,
        attempt: &mut Attempt,
        hook: &mut dyn FnMut(&'static str) -> io::Result<()>,
        before_unlink: BeforeUnlink,
    ) -> io::Result<()> {
        if offset > meta.len() {
            return Err(io::Error::other("append offset past archive EOF"));
        }
        let new_len = offset
            .checked_add(suffix.metadata()?.len())
            .ok_or_else(|| io::Error::other("suffix length overflow"))?;
        let prefix = fingerprint(file, offset)?;
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0215-M01","item":"ratarmount_compress::commit_journal::unix::run","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )
        )]
        let mut journal = tempfile::NamedTempFile::new_in(parent(archive))?;
        journal.write_all(MAGIC)?;
        for value in [
            meta.dev(),
            meta.ino(),
            meta.len(),
            offset,
            meta.mtime() as u64,
            meta.mtime_nsec() as u64,
            new_len,
        ] {
            journal.write_all(&value.to_le_bytes())?;
        }
        journal.write_all(&prefix)?;
        hook("journal header")?;
        file.seek(SeekFrom::Start(offset))?;
        copy_exact(file, journal.as_file_mut(), meta.len() - offset)?;
        suffix.rewind()?;
        copy_exact(suffix, journal.as_file_mut(), new_len - offset)?;
        let size = journal.as_file().metadata()?.len();
        let crc = checksum(journal.as_file_mut(), size)?;
        journal.write_all(&crc.to_le_bytes())?;
        hook("journal tail")?;
        journal.as_file().sync_all()?;
        hook("journal fsync")?;
        marker(file, path, b'P')?;
        hook("locator prepare")?;
        // On `Err` tempfile deletes the temporary journal: nothing of this
        // attempt is at `path`.
        let published = journal.persist_noclobber(path).map_err(|e| e.error)?;
        let id = published.metadata()?;
        attempt.published = Some((id.dev(), id.ino()));
        drop(published);
        hook("journal publish")?;
        sync_parent(path)?;
        hook("journal directory fsync")?;
        marker(file, path, b'A')?;
        hook("locator active")?;
        file.set_len(offset)?;
        file.sync_all()?;
        hook("archive truncate")?;
        file.seek(SeekFrom::Start(offset))?;
        suffix.rewind()?;
        let mut buf = [0; 65536];
        loop {
            let n = suffix.read(&mut buf)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            hook("archive write")?;
        }
        file.sync_all()?;
        hook("archive fsync")?;
        marker(file, path, b'C')?;
        attempt.completed = true;
        hook("locator complete")?;
        before_unlink(&applied_of(
            file,
            true,
            meta.len(),
            mtime_ns(meta),
            new_len,
        )?)?;
        marker(file, path, b'D')?;
        hook("locator done")?;
        fault::instead("commit unlink", || fs::remove_file(path))?;
        attempt.unlinked = true;
        hook("journal unlink")?;
        fault::instead("commit directory sync", || sync_parent(path))?;
        attempt.synced = true;
        hook("commit directory fsync")?;
        clear_marker(file)?;
        hook("locator clear")?;
        Ok(())
    }

    /// The cleanup of a failed attempt, under the lock the attempt still
    /// holds, from its own record. It never re-derives the attempt's state
    /// from the pathname and never adopts a journal it did not publish.
    fn finish_failed(
        file: &mut File,
        path: &Path,
        attempt: &Attempt,
        error: io::Error,
        before_unlink: BeforeUnlink,
    ) -> std::result::Result<(), ReplaceError> {
        let complete = attempt.completed
            || (attempt.published.is_some()
                && match get_marker(file) {
                    // An installed `C` whose fsync failed is still complete.
                    Ok(m) => m.is_some_and(|(s, _)| matches!(s, b'C' | b'D')),
                    Err(x) => return Err(ReplaceError::Pending(join(error, x))),
                });
        let Some(ours) = attempt.published else {
            // Nothing of this attempt is at `path`; whatever is there was
            // published for another file and is never read.
            if let Err(x) = clear_marker(file) {
                log::warn!("commit: stale prepare locator left: {x}");
            }
            return Err(ReplaceError::RolledBack(error, None));
        };
        if attempt.unlinked {
            // The hook ran and THIS attempt removed its journal (`D` is on the
            // inode). Owed: a durable unlink, then the locator.
            if !attempt.synced {
                if let Err(x) = fault::instead("cleanup directory sync", || sync_parent(path)) {
                    return Err(ReplaceError::Committed(join(error, x)));
                }
            }
            if let Err(x) = clear_marker(file) {
                log::warn!("commit: journal unlinked durably; stale locator left: {x}");
            }
            return Ok(());
        }
        let unresolved = |x: io::Error| {
            if complete {
                ReplaceError::Committed(x)
            } else {
                ReplaceError::Pending(x)
            }
        };
        // Published, not unlinked by this attempt. Absent at `path` (a renamed
        // directory): nothing is touched and the locator stays.
        if !fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) {
            return Err(unresolved(join(
                error,
                format!(
                    "commit journal {} is missing or moved; recover through the archive's \
                     current name",
                    path.display()
                ),
            )));
        }
        let locked = match file.metadata() {
            Ok(m) => (m.dev(), m.ino()),
            Err(x) => return Err(unresolved(join(error, x))),
        };
        let mut authorize = |j: &PendingJournal, m: &fs::Metadata| authorize_started(j, m, locked);
        match rollback(
            path,
            file,
            complete,
            Some(ours),
            &mut authorize,
            before_unlink,
        ) {
            Ok(_) if complete => Ok(()),
            Ok(_) => Err(ReplaceError::RolledBack(error, None)),
            Err(x) => Err(unresolved(join(error, x))),
        }
    }

    /// The refusal when a journal or locator is pending on the archive. A done
    /// (`D`) locator with no journal at `path` is what a process killed after
    /// the journal unlink leaves: recovery keeps it (the journal may sit beside
    /// another name of the file), so the refusal names the manual escape.
    fn pending_refusal(path: &Path, file: &File, what: &str) -> io::Result<Option<io::Error>> {
        let journal = path.try_exists()?;
        let marker = get_marker(file)?;
        if !journal && marker.as_ref().is_some_and(|(state, _)| *state == b'D') {
            return Ok(Some(recovery_error(
                path,
                format!(
                    "pending journal; {what}: a done (D) commit-journal locator is left on the \
                     archive with no journal beside this name (the commit finished; only its \
                     cleanup was interrupted). If the journal moved with a renamed directory, \
                     recover through the archive's current name; otherwise verify the archive \
                     and remove its user.ratarmount.commit-journal xattr (setfattr -x on \
                     Linux, xattr -d on macOS)"
                ),
            )));
        }
        if journal || marker.is_some() {
            return Ok(Some(recovery_error(
                path,
                format!("pending journal; {what}"),
            )));
        }
        Ok(None)
    }

    /// Lock for a copy fallback (see [`super::guard_copy`]).
    pub(super) fn guard_copy(archive: &Path, source: &fs::Metadata) -> io::Result<CopyGuard> {
        fault::check("copy publish")?;
        let archive = archive.canonicalize()?;
        // Read-only: flock needs no write permission.
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0216-M01","item":"ratarmount_compress::commit_journal::unix::guard_copy","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        let file = File::open(&archive)?;
        let lock = lock(&file).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "{} is locked by another commit; the copy was not published: {e}",
                    archive.display()
                ),
            )
        })?;
        if let Some(e) =
            pending_refusal(&journal_path(&archive), &file, "the copy was not published")?
        {
            return Err(e);
        }
        if !same_stamp(source, &file.metadata()?) {
            return Err(io::Error::other(
                "archive changed during the copy fallback; retry",
            ));
        }
        Ok(CopyGuard { _lock: lock })
    }

    fn mtime_ns(meta: &fs::Metadata) -> i128 {
        i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec())
    }

    /// The locked descriptor's final stamp (`fstat`, never a path stat).
    fn applied_of(
        file: &File,
        rolled_forward: bool,
        pre_len: u64,
        pre_mtime_ns: i128,
        new_len: u64,
    ) -> io::Result<Applied> {
        let now = file.metadata()?;
        Ok(Applied {
            rolled_forward,
            pre_len,
            pre_mtime_ns,
            new_len,
            dev: now.dev(),
            ino: now.ino(),
            final_len: now.len(),
            final_mtime_ns: mtime_ns(&now),
        })
    }

    #[cfg(test)]
    thread_local! {
        /// Runs between the unlocked probe and the flock.
        pub(super) static AFTER_PROBE: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn recover(
        archive: &Path,
        before_write: BeforeWrite,
        authorize: Authorize,
        before_unlink: BeforeUnlink,
    ) -> std::result::Result<Option<Applied>, RecoverError> {
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0217-M01","item":"ratarmount_compress::commit_journal::unix::recover","disposition":"residual","reason":"base-archive bytes read by journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        let probe = match File::open(archive) {
            Ok(f) if f.metadata().map_err(RecoverError::Journal)?.is_file() => f,
            Ok(_) => return Ok(None),
            // With no visible journal, leave ordinary open errors to the
            // caller (Session's NotFound/NotWritable/index-policy contract).
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) && fs::symlink_metadata(journal_path(archive)).is_err() =>
            {
                return Ok(None)
            }
            Err(e) => {
                return Err(RecoverError::Journal(recovery_error(
                    &journal_path(archive),
                    e,
                )))
            }
        };
        let journal_error =
            |path: &Path, e: io::Error| RecoverError::Journal(recovery_error(path, e));
        let locator = get_marker(&probe).map_err(|e| journal_error(&journal_path(archive), e))?;
        let probed = locator
            .as_ref()
            .map(|(_, p)| p.clone())
            .unwrap_or_else(|| journal_path(archive));
        if locator.is_none() && !probed.try_exists().map_err(RecoverError::Journal)? {
            return Ok(None);
        }
        #[cfg(test)]
        {
            let hook = AFTER_PROBE.with(|hook| hook.borrow_mut().take());
            if let Some(mut hook) = hook {
                hook();
            }
        }
        let mut file = {
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_types, reason = r###"internal-read:v1 {"id":"IR-B0218-T01","item":"ratarmount_compress::commit_journal::unix::recover","disposition":"support","reason":"Builder type support: base archive opened read-write by journal recovery to lock it and roll back or forward; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"builder-type-support","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###))]
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0218-M01","item":"ratarmount_compress::commit_journal::unix::recover","disposition":"support","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","family":"commit-journal-recovery","issue":"#196","category":"builder-setup","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"residual","baseline_reason":"base archive opened read-write by journal recovery to lock it and roll back or forward; recovery and mutation ownership belong to the excluded broader machinery"}"###))]
let mut __inventory_value_0 = fs::OpenOptions::new();
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0218-M02","item":"ratarmount_compress::commit_journal::unix::recover","disposition":"residual","reason":"base archive opened read-write by journal recovery to lock it and roll back or forward; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###))]
let __inventory_value_1 = __inventory_value_0
            .read(true)
            .write(true)
            .open(archive);
__inventory_value_1
}
            .map_err(|e| journal_error(&probed, e))?;
        let _lock = lock(&file).map_err(|e| journal_error(&probed, e))?;
        // Another recovering opener may have won, or another opener (through a
        // hard link) may have started a different journal: BOTH the state and
        // the journal path come from the locked descriptor's marker.
        let locator = get_marker(&file).map_err(|e| journal_error(&probed, e))?;
        let state = locator.as_ref().map(|(s, _)| *s);
        let (path, present) = locate(archive, &file, locator.map(|(_, p)| p))
            .map_err(|e| journal_error(&probed, e))?;
        if !present {
            match state {
                // A winner cleared it under the lock, or nothing was pending.
                None => return Ok(None),
                // No byte changed (or a rollback was made durable): clear it
                // once an unsynced unlink can no longer resurrect a journal.
                Some(b'P') => {
                    before_write().map_err(RecoverError::Refused)?;
                    fault::instead("stale marker directory sync", || {
                        sync_parent_if_present(&path)
                    })
                    .map_err(|e| journal_error(&path, e))?;
                    clear_marker(&file).map_err(|e| journal_error(&path, e))?;
                    return Ok(None);
                }
                // The hook ran (`D` is written only after it returned `Ok`),
                // but the journal may have moved with a renamed directory and
                // sit beside another name of this file: clearing the locator
                // would make that journal look torn and roll the commit back.
                Some(b'D') => {
                    log::warn!(
                        "commit journal '{}': the commit finished but its journal is not \
                         beside this name and the locator was kept; recover through the \
                         archive's current directory name, or verify the archive and remove \
                         its user.ratarmount.commit-journal xattr (setfattr -x on Linux, \
                         xattr -d on macOS)",
                        path.display()
                    );
                    return Ok(None);
                }
                Some(b'C') => {
                    return Err(RecoverError::Committed(io::Error::new(
                        io::ErrorKind::NotFound,
                        recovery_error(
                            &path,
                            "complete commit journal is missing or moved; recover through \
                             the archive's current directory name; a journal removed by hand \
                             needs the archive verified and its user.ratarmount.commit-journal \
                             xattr removed (setfattr -x on Linux, xattr -d on macOS)",
                        )
                        .to_string(),
                    )))
                }
                _ => {
                    return Err(journal_error(
                        &path,
                        io::Error::other("active journal is missing or moved"),
                    ))
                }
            }
        }
        before_write().map_err(RecoverError::Refused)?;
        rollback(
            &path,
            &mut file,
            matches!(state, Some(b'C' | b'D')),
            None,
            authorize,
            before_unlink,
        )
        .map(Some)
        .map_err(|e| match e {
            RecoverError::Journal(e) => RecoverError::Journal(recovery_error(&path, e)),
            RecoverError::Committed(e) => RecoverError::Committed(recovery_error(&path, e)),
            refused => refused,
        })
    }

    pub(super) fn pending(archive: &Path) -> io::Result<Option<PendingJournal>> {
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0219-M01","item":"ratarmount_compress::commit_journal::unix::pending","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        let probe = match File::open(archive) {
            Ok(f) if f.metadata()?.is_file() => f,
            Ok(_) => return Ok(None),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        let marker = get_marker(&probe)?;
        let complete = marker
            .as_ref()
            .is_some_and(|(state, _)| matches!(state, b'C' | b'D'));
        let (path, present) = locate(archive, &probe, marker.map(|(_, p)| p))?;
        if !present {
            return Ok(None);
        }
        let mut journal = match open_journal(&path) {
            Ok(f) if f.metadata()?.is_file() => f,
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut header = [0; HEADER_LEN as usize];
        journal.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(io::Error::other("journal header/length mismatch"));
        }
        Ok(Some(parse_pending(&header, complete)))
    }

    /// Where the journal of the file `file` (opened through the name
    /// `archive`) is: the locator's path when it exists; else, with a locator,
    /// the sibling [`journal_path`] of `archive` when its header names this
    /// file's inode (the journal moved with a renamed directory); else the
    /// locator's path, absent. Without a locator: the sibling.
    fn locate(
        archive: &Path,
        file: &File,
        locator: Option<PathBuf>,
    ) -> io::Result<(PathBuf, bool)> {
        let sibling = journal_path(archive);
        let Some(path) = locator else {
            let present = sibling.try_exists()?;
            return Ok((sibling, present));
        };
        if path.try_exists()? {
            return Ok((path, true));
        }
        if sibling != path && header_names(&sibling, file.metadata()?.ino()) {
            return Ok((sibling, true));
        }
        Ok((path, false))
    }

    /// A regular file at `path` whose journal header names inode `ino` (the
    /// device is a hint only, as in [`validate`]).
    fn header_names(path: &Path, ino: u64) -> bool {
        let Ok(mut journal) = open_journal(path) else {
            return false;
        };
        if !journal.metadata().is_ok_and(|m| m.is_file()) {
            return false;
        }
        let mut header = [0; HEADER_LEN as usize];
        if journal.read_exact(&mut header).is_err() || &header[..8] != MAGIC {
            return false;
        }
        parse_pending(&header, false).ino == ino
    }

    /// Open a journal for reading through the admitted open (R10-FIX3): a
    /// journal name that is another name (a hard link) of an open overlay
    /// database is refused (`PermissionDenied`) without opening, and so
    /// without closing, a descriptor of the database, which would release
    /// this process's SQLite locks on it.
    fn open_journal(path: &Path) -> io::Result<File> {
        {
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0220-M01","item":"ratarmount_compress::commit_journal::unix::open_journal","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###))]
let __inventory_value_0 = ratarmount_core::db_inodes::open_admitted(
            path,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        );
__inventory_value_0
}
        .map(File::from)
    }

    fn parse_pending(header: &[u8; HEADER_LEN as usize], complete: bool) -> PendingJournal {
        let get = |i: usize| u64::from_le_bytes(header[i..i + 8].try_into().unwrap());
        PendingJournal {
            dev: get(8),
            ino: get(16),
            len: get(24),
            offset: get(32),
            mtime_ns: i128::from(get(40) as i64) * 1_000_000_000 + i128::from(get(48)),
            new_len: get(56),
            complete,
        }
    }

    fn matches_tail(
        file: &mut File,
        journal: &mut File,
        offset: u64,
        start: u64,
        max_len: u64,
    ) -> io::Result<bool> {
        let len = file.metadata()?.len();
        if len < offset || len - offset > max_len {
            return Ok(false);
        }
        file.seek(SeekFrom::Start(offset))?;
        journal.seek(SeekFrom::Start(start))?;
        let mut remaining = len - offset;
        let mut actual = [0; 65536];
        let mut expected = [0; 65536];
        while remaining > 0 {
            let n = remaining.min(actual.len() as u64) as usize;
            file.read_exact(&mut actual[..n])?;
            journal.read_exact(&mut expected[..n])?;
            if actual[..n] != expected[..n] {
                return Ok(false);
            }
            remaining -= n as u64;
        }
        Ok(true)
    }
    pub(super) fn restore_mtime(result: io::Result<()>) -> io::Result<()> {
        match result {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                log::info!(
                    "commit: cannot restore mtime as non-owner; sidecar validation will rebuild"
                );
                Ok(())
            }
            result => result,
        }
    }
    /// Validated journal header fields.
    struct Header {
        pending: PendingJournal,
        seconds: i64,
        nanos: u64,
        /// The archive already holds exactly the old bytes (a rollback that
        /// finished its writes, or an attempt stopped before it truncated).
        old_in_place: bool,
    }

    /// `expected`: the `(dev, ino)` of the journal file a failed attempt
    /// published, compared on the descriptor the tail is read from; crash
    /// recovery passes `None`.
    fn validate(
        path: &Path,
        file: &mut File,
        complete: bool,
        expected: Option<(u64, u64)>,
    ) -> io::Result<(Header, File)> {
        if !fs::symlink_metadata(path)?.is_file() {
            return Err(io::Error::other("commit journal is not a regular file"));
        }
        let mut journal = open_journal(path)?;
        if let Some(expected) = expected {
            let opened = journal.metadata()?;
            if (opened.dev(), opened.ino()) != expected {
                return Err(io::Error::other(
                    "commit journal is not the journal this attempt published",
                ));
            }
        }
        let mut header = [0; HEADER_LEN as usize];
        journal.read_exact(&mut header)?;
        let get = |i: usize| u64::from_le_bytes(header[i..i + 8].try_into().unwrap());
        let len = get(24);
        let offset = get(32);
        let seconds = get(40) as i64;
        let nanos = get(48);
        let new_len = get(56);
        let size = len
            .checked_sub(offset)
            .and_then(|old| {
                new_len
                    .checked_sub(offset)
                    .and_then(|new| old.checked_add(new))
            })
            .and_then(|n| n.checked_add(HEADER_LEN + 4));
        if &header[..8] != MAGIC
            || nanos >= 1_000_000_000
            || size != Some(journal.metadata()?.len())
        {
            return Err(io::Error::other("journal header/length mismatch"));
        }
        let size = size.unwrap();
        let crc = checksum(&mut journal, size - 4)?;
        let mut stored = [0; 4];
        journal.read_exact(&mut stored)?;
        if crc != u32::from_le_bytes(stored) {
            return Err(io::Error::other("journal CRC mismatch"));
        }
        if file.metadata()?.len() < offset || fingerprint(file, offset)? != header[64..96] {
            return Err(io::Error::other("archive prefix fingerprint mismatch"));
        }
        let new_matches = matches_tail(
            file,
            &mut journal,
            offset,
            HEADER_LEN + len - offset,
            new_len - offset,
        )?;
        let old_matches = matches_tail(file, &mut journal, offset, HEADER_LEN, len - offset)?;
        if (complete && (!new_matches || file.metadata()?.len() != new_len))
            || (!complete && !old_matches && !new_matches)
        {
            return Err(io::Error::other(
                "archive tail fingerprint mismatch (external modification)",
            ));
        }
        // dev/ino are diagnostic hints only: device numbers may change on reboot.
        if file.metadata()?.dev() != get(8) || file.metadata()?.ino() != get(16) {
            log::info!("commit: journal identity changed; validated archive content instead");
        }
        let old_in_place = old_matches && file.metadata()?.len() == len;
        Ok((
            Header {
                pending: parse_pending(&header, complete),
                seconds,
                nanos,
                old_in_place,
            },
            journal,
        ))
    }

    fn rollback(
        path: &Path,
        file: &mut File,
        complete: bool,
        expected: Option<(u64, u64)>,
        authorize: Authorize,
        before_unlink: BeforeUnlink,
    ) -> std::result::Result<Applied, RecoverError> {
        let (header, mut journal) =
            validate(path, file, complete, expected).map_err(RecoverError::Journal)?;
        // The journal is valid for the locked content; whether it is THIS
        // caller's to apply is decided on the locked descriptor, before any write.
        let locked = file.metadata().map_err(RecoverError::Journal)?;
        authorize(&header.pending, &locked).map_err(RecoverError::Refused)?;
        // After the roll-forward decision the archive holds the new bytes: any
        // later failure leaves a pending journal over committed content.
        let late = |e: io::Error| {
            if complete {
                RecoverError::Committed(e)
            } else {
                RecoverError::Journal(e)
            }
        };
        let PendingJournal {
            len,
            offset,
            mtime_ns: pre_mtime_ns,
            new_len,
            ..
        } = header.pending;
        let (seconds, nanos) = (header.seconds, header.nanos);
        // Idempotent: when the old bytes are already in place nothing is
        // written (no truncate, copy or mtime), so a second recovery of a
        // rolled-back file keeps the stamp the first one's hook recorded.
        if !complete && !header.old_in_place {
            // Persist truncation before rollback writes so another crash leaves
            // a prefix of the old tail, never a mixture of old and new tails.
            let rolled = (|| -> io::Result<()> {
                fault::instead("rollback truncate", || file.set_len(offset))?;
                file.sync_all()?;
                file.seek(SeekFrom::Start(offset))?;
                journal.seek(SeekFrom::Start(HEADER_LEN))?;
                copy_exact(&mut journal, file, len - offset)?;
                let mtime = if seconds >= 0 {
                    UNIX_EPOCH.checked_add(Duration::new(seconds as u64, nanos as u32))
                } else {
                    UNIX_EPOCH
                        .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
                        .and_then(|t| t.checked_add(Duration::from_nanos(nanos)))
                }
                .ok_or_else(|| io::Error::other("commit journal mtime overflow"))?;
                restore_mtime(fault::instead("rollback mtime", || {
                    file.set_times(fs::FileTimes::new().set_modified(mtime))
                }))?;
                file.sync_all()
            })();
            rolled.map_err(RecoverError::Journal)?;
        }
        // P with no journal means no mutation. The restored old archive is now
        // durable, so this also makes cleanup idempotent after an unlink crash.
        marker(file, path, if complete { b'C' } else { b'P' }).map_err(late)?;
        let applied = applied_of(file, complete, len, pre_mtime_ns, new_len).map_err(late)?;
        before_unlink(&applied).map_err(late)?;
        if complete {
            // The hook returned `Ok`: only the unlink is owed.
            marker(file, path, b'D').map_err(late)?;
        }
        fault::instead("rollback unlink", || fs::remove_file(path)).map_err(late)?;
        fault::instead("rollback directory sync", || sync_parent(path)).map_err(late)?;
        // The unlink is durable: a stale `P`/`D` locator is metadata-only for
        // the next recovery.
        if let Err(e) = clear_marker(file) {
            log::warn!(
                "commit: journal {} removed; stale locator left: {e}",
                path.display()
            );
        }
        log::info!("commit: recovered journal {}", path.display());
        Ok(applied)
    }
}
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[allow(
    clippy::disallowed_methods,
    reason = "Journal regression fixtures directly exercise the restricted implementation APIs"
)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Regression: ENOSPC must roll back before returning to a live reader.
    #[test]
    fn append_journal_write_error_rolls_back_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"prefix:old contents").unwrap();
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(&vec![0x82; 150_000]).unwrap();
        fault::install(|step| {
            if step == "archive write" {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            } else {
                Ok(())
            }
        });
        let result =
            replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| Ok(()));
        fault::clear();
        assert!(
            matches!(result, Err(ReplaceError::RolledBack(..))),
            "{result:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
        assert!(!journal_path(&path).exists());
        assert_eq!(marker_state(&path), None);
    }

    /// Regression (R6-K6): `recover_owned` refuses a journal started for another
    /// file (a new-inode copy) untouched, and recovers the file's own journal.
    #[cfg(unix)]
    #[test]
    fn append_journal_recover_owned_refuses_foreign_journal() {
        let crash = |path: &Path| {
            fs::write(path, b"prefix:old contents").unwrap();
            let mut suffix = tempfile::tempfile().unwrap();
            suffix.write_all(b"new contents").unwrap();
            let crashed = replace_suffix_with_hook(path, 7, &mut suffix, &mut |step| {
                if step == "archive truncate" {
                    Err(io::Error::other("crash"))
                } else {
                    Ok(())
                }
            });
            assert!(crashed.is_err());
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        crash(&path);
        let crashed = fs::read(&path).unwrap();
        let journal = fs::read(journal_path(&path)).unwrap();
        let copy = dir.path().join("copy");
        fs::write(&copy, &crashed).unwrap();
        fs::rename(&copy, &path).unwrap();
        let err = recover_with(&path, &mut authorize_owned, &mut |_| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("another file"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), crashed);
        assert_eq!(fs::read(journal_path(&path)).unwrap(), journal);

        let own = dir.path().join("own");
        crash(&own);
        assert!(recover_with(&own, &mut authorize_owned, &mut |_| Ok(()))
            .unwrap()
            .is_some());
        assert_eq!(fs::read(&own).unwrap(), b"prefix:old contents");
        assert!(!journal_path(&own).exists());
    }

    /// Regression: a cleanup failure after completion must not append the same plan twice.
    #[test]
    fn append_journal_completed_cleanup_error_is_success() {
        for stop in [
            "locator complete",
            "locator done",
            "journal unlink",
            "locator clear",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            fs::write(&path, b"prefix:old contents").unwrap();
            let original = fs::metadata(&path).unwrap();
            let mut suffix = tempfile::tempfile().unwrap();
            suffix.write_all(b"new contents").unwrap();
            fault::install(move |step| {
                if step == stop {
                    Err(io::Error::other("cleanup failed"))
                } else {
                    Ok(())
                }
            });
            let result =
                replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| Ok(()));
            fault::clear();
            result.unwrap_or_else(|e| panic!("{stop}: {e:?}"));
            assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
            assert_eq!(marker_state(&path), None, "{stop}");
            assert!(!recover(&path).unwrap());
        }
    }

    /// Regression: absent journals must not replace ordinary Session open errors.
    #[test]
    fn append_journal_absent_preserves_open_errors() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        assert!(!recover(&path).unwrap());
        fs::write(&path, b"ordinary file").unwrap();
        assert!(!recover(&path.join("not-a-directory")).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(!recover(&path).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn interrupted(path: &Path, step: &str) {
        fs::write(path, b"prefix:old contents").unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents are longer").unwrap();
        assert!(replace_suffix_with_hook(path, 7, &mut suffix, &mut |at| {
            if at == step {
                Err(io::Error::other("crash"))
            } else {
                Ok(())
            }
        })
        .is_err());
    }

    /// Regression (r16 nit, R7-D3): a process killed between the journal
    /// unlink and the locator clear leaves a done (`D`) locator with no
    /// journal; recovery keeps it (the journal may sit beside another name),
    /// so every later commit was refused with "pending journal; recover
    /// before preparing a commit" although recovery had nothing to do. The
    /// refusal (append and copy guard) names the documented escape; a real
    /// pending journal does not get that advice.
    #[test]
    fn append_journal_done_locator_without_journal_names_the_escape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "journal unlink");
        assert!(!journal_path(&path).exists());
        assert_eq!(marker_state(&path), Some(b'D'));
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"more").unwrap();
        let refused =
            replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| Ok(()));
        let Err(ReplaceError::Refused(e)) = refused else {
            panic!("{refused:?}");
        };
        let text = e.to_string();
        assert!(text.contains("recover before preparing a commit"), "{text}");
        assert!(text.contains("setfattr -x"), "{text}");
        assert!(text.contains("xattr -d"), "{text}");
        let guarded = guard_copy(&path, &original).map(drop).unwrap_err();
        assert!(guarded.to_string().contains("setfattr -x"), "{guarded}");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator active");
        assert!(journal_path(&path).exists());
        let original = fs::metadata(&path).unwrap();
        let refused =
            replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| Ok(()));
        let Err(ReplaceError::Refused(e)) = refused else {
            panic!("{refused:?}");
        };
        assert!(!e.to_string().contains("setfattr"), "{e}");
    }

    /// Regression: symlinks and hard links must find the same pending journal.
    #[test]
    fn append_journal_alias_recovery() {
        for symlink in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            interrupted(&path, "archive truncate");
            let alias_dir = dir.path().join("other");
            fs::create_dir(&alias_dir).unwrap();
            let alias = alias_dir.join("alias");
            if symlink {
                std::os::unix::fs::symlink(&path, &alias).unwrap();
            } else {
                fs::hard_link(&path, &alias).unwrap();
            }
            if symlink {
                assert_eq!(journal_path(&path), journal_path(&alias));
            }
            assert!(recover(&alias).unwrap());
            assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
            assert!(!recover(&path).unwrap());
        }
    }

    /// Regression: cp/rsync --inplace reuse the inode but must not trigger rollback.
    #[test]
    fn append_journal_reused_inode_refuses_external_bytes() {
        for bytes in [
            b"prefix:unrelated archive".as_slice(),
            b"WRONG!:new",
            b"prefix:new contents are longer and newer",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            interrupted(&path, "archive truncate");
            fs::write(&path, bytes).unwrap();
            let error = recover(&path).unwrap_err().to_string();
            assert!(
                error.contains(journal_path(&path).to_str().unwrap()),
                "{error}"
            );
            assert!(error.contains("backup"), "{error}");
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    /// Regression: changed device numbers are hints, not a permanent recovery block.
    #[test]
    fn append_journal_device_change_uses_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        let journal = journal_path(&path);
        let mut bytes = fs::read(&journal).unwrap();
        bytes[8..24].fill(0xa7);
        let end = bytes.len() - 4;
        let crc = crc32fast::hash(&bytes[..end]);
        bytes[end..].copy_from_slice(&crc.to_le_bytes());
        fs::write(journal, bytes).unwrap();
        assert!(recover(&path).unwrap());
        assert_eq!(fs::read(path).unwrap(), b"prefix:old contents");
    }

    /// Regression: a corrupted journal must never be copied into an archive.
    #[test]
    fn append_journal_crc_refuses_corrupt_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        let journal = journal_path(&path);
        let mut bytes = fs::read(&journal).unwrap();
        bytes[unix::HEADER_LEN as usize] ^= 1;
        fs::write(&journal, bytes).unwrap();
        assert!(recover(&path).unwrap_err().to_string().contains("CRC"));
        assert_eq!(fs::read(path).unwrap(), b"prefix:");
    }

    /// Regression: non-owner writers can recover even when restoring mtime is EPERM.
    #[test]
    fn append_journal_mtime_eperm_is_nonfatal() {
        assert!(unix::restore_mtime(Err(io::Error::from_raw_os_error(libc::EPERM))).is_ok());
        assert!(unix::restore_mtime(Err(io::Error::from_raw_os_error(libc::EIO))).is_err());
    }

    /// Regression: a read-only opener must refuse a torn archive it cannot repair.
    #[test]
    fn append_journal_readonly_recovery_refuses_unwritable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            eprintln!(
                "skip: root bypasses write permissions; content refusal is tested separately"
            );
        } else {
            let error = recover(&path).unwrap_err().to_string();
            assert!(error.contains(journal_path(&path).to_str().unwrap()));
            assert!(error.contains("write access"));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(recover(&path).unwrap());
    }

    /// Regression: a crash during tail replacement must recover byte-for-byte.
    #[test]
    fn append_journal_crash_every_step_old_or_new() {
        let old: Vec<_> = (0..180_000).map(|i| (i % 251) as u8).collect();
        let tail = vec![0xb1; 150_000];
        let offset = 100_003;
        let mut new = old[..offset].to_vec();
        new.extend_from_slice(&tail);
        for stop in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            fs::write(&path, &old).unwrap();
            let mtime = fs::metadata(&path).unwrap().modified().unwrap();
            let mut suffix = tempfile::tempfile().unwrap();
            suffix.write_all(&tail).unwrap();
            let mut step = 0;
            let result = replace_suffix_with_hook(&path, offset as u64, &mut suffix, &mut |_| {
                step += 1;
                if step == stop {
                    Err(io::Error::other("injected crash"))
                } else {
                    Ok(())
                }
            });
            recover(&path).unwrap();
            assert!(!recover(&path).unwrap(), "recovery is idempotent");
            let actual = fs::read(&path).unwrap();
            assert!(actual == old || actual == new, "third state at step {stop}");
            if stop > 0 && stop < 13 {
                assert!(result.is_err());
                assert_eq!(actual, old, "must roll back before unlink");
                assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
            }
        }
    }

    /// Regression (R7-E1): a rolled-back replacement reports the locked
    /// descriptor's stamp after its cleanup (the only stamp a copy fallback
    /// may read), whether its journal was published or not: it equals the
    /// archive's stamp afterwards, the old bytes are in place, and a write
    /// after the lock was released no longer matches it.
    #[test]
    fn append_journal_rolled_back_reports_the_locked_stamp() {
        for step in ["journal header", "locator prepare", "archive write"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            fs::write(&path, b"prefix:old contents").unwrap();
            let original = fs::metadata(&path).unwrap();
            let mut suffix = tempfile::tempfile().unwrap();
            suffix.write_all(b"new contents").unwrap();
            fault::install(move |seen| {
                if seen == step {
                    return Err(io::Error::from_raw_os_error(libc::ENOSPC));
                }
                Ok(())
            });
            let result =
                replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| Ok(()));
            fault::clear();
            let Err(ReplaceError::RolledBack(_, Some(stamp))) = result else {
                panic!("{step}: {result:?}");
            };
            assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents", "{step}");
            assert!(same_stamp(&stamp, &fs::metadata(&path).unwrap()), "{step}");
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"x")
                .unwrap();
            assert!(!same_stamp(&stamp, &fs::metadata(&path).unwrap()), "{step}");
        }
    }

    /// The fault seam is consulted at every step of a production replacement,
    /// in order, and an instead-of seam's `Err` replaces the step.
    #[test]
    fn fault_seam_sees_every_replace_step() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"prefix:old contents").unwrap();
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents").unwrap();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let log = seen.clone();
        fault::install(move |step| {
            log.borrow_mut().push(step);
            Ok(())
        });
        replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| Ok(()))
            .unwrap();
        fault::clear();
        assert_eq!(
            *seen.borrow(),
            [
                "before replace",
                "journal header",
                "journal tail",
                "journal fsync",
                "locator prepare",
                "journal publish",
                "journal directory fsync",
                "locator active",
                "archive truncate",
                "archive write",
                "archive fsync",
                "locator complete",
                "locator done",
                "commit unlink",
                "journal unlink",
                "commit directory sync",
                "commit directory fsync",
                "locator clear",
            ]
        );
        assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");

        // `rollback mtime` replaces `set_times`; EPERM is tolerated as before.
        fs::write(&path, b"prefix:old contents").unwrap();
        let original = fs::metadata(&path).unwrap();
        fault::install(|step| match step {
            "archive write" => Err(io::Error::from_raw_os_error(libc::ENOSPC)),
            "rollback mtime" => Err(io::Error::from_raw_os_error(libc::EPERM)),
            _ => Ok(()),
        });
        let error =
            replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| Ok(()));
        fault::clear();
        assert!(
            matches!(error, Err(ReplaceError::RolledBack(..))),
            "{error:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
        assert!(!journal_path(&path).exists());
    }

    /// Regression: a second crash during rollback must leave a reusable journal.
    #[test]
    fn append_journal_interrupted_rollback_retries() {
        use std::io::{Read, Seek, SeekFrom};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        let old = vec![0x52; 80_000];
        fs::write(&path, &old).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new").unwrap();
        assert!(
            replace_suffix_with_hook(&path, 1024, &mut suffix, &mut |step| {
                if step == "archive truncate" {
                    Err(io::Error::other("crash"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        // Model a rollback interrupted after a partial tail write.
        let mut journal = File::open(journal_path(&path)).unwrap();
        journal.seek(SeekFrom::Start(unix::HEADER_LEN)).unwrap();
        let mut partial = [0; 2000];
        journal.read_exact(&mut partial).unwrap();
        let mut archive = fs::OpenOptions::new().write(true).open(&path).unwrap();
        archive.seek(SeekFrom::Start(1024)).unwrap();
        archive.write_all(&partial).unwrap();
        archive.sync_all().unwrap();
        assert!(recover(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), old);
        assert!(!recover(&path).unwrap());
    }

    /// Regression: a stale prepared suffix must not overwrite a newer commit.
    #[test]
    fn append_journal_stale_preparation_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"old").unwrap();
        let original = fs::metadata(&path).unwrap();
        fs::write(&path, b"another commit").unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"stale").unwrap();
        let result =
            replace_suffix_if_unchanged_with(&path, 0, &mut suffix, &original, &mut |_| Ok(()));
        assert!(
            matches!(result, Err(ReplaceError::Refused(_))),
            "{result:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"another commit");
        assert!(!journal_path(&path).exists());
    }

    /// Regression: a journal from a replaced archive must never clobber its successor.
    #[test]
    fn append_journal_wrong_inode_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"old archive").unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new").unwrap();
        assert!(
            replace_suffix_with_hook(&path, 3, &mut suffix, &mut |step| {
                if step == "archive truncate" {
                    Err(io::Error::other("crash"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, b"unrelated archive").unwrap();
        fs::rename(replacement, &path).unwrap();
        assert!(recover(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), b"unrelated archive");
    }

    /// Regression (R6-G2): `pending` reads the header a recovery would act on
    /// without writing: the archive, its journal and the locator are unchanged.
    #[test]
    fn append_journal_pending_reads_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        assert_eq!(pending(&path).unwrap(), None);
        fs::write(&path, b"plain").unwrap();
        assert_eq!(pending(&path).unwrap(), None);
        interrupted(&path, "archive truncate");
        let journal = journal_path(&path);
        let (archive_before, journal_before) =
            (fs::read(&path).unwrap(), fs::read(&journal).unwrap());
        let found = pending(&path).unwrap().expect("a journal is pending");
        assert_eq!(found.len, b"prefix:old contents".len() as u64);
        assert_eq!(found.offset, 7);
        assert_eq!(found.new_len, 7 + b"new contents are longer".len() as u64);
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(found.ino, std::os::unix::fs::MetadataExt::ino(&meta));
        assert_eq!(fs::read(&path).unwrap(), archive_before);
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        assert!(recover(&path).unwrap());
        assert_eq!(pending(&path).unwrap(), None);
    }

    fn marker_present(path: &Path) -> bool {
        // A pending marker refuses the next replacement.
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"x").unwrap();
        replace_suffix_with_hook(path, 0, &mut suffix, &mut |_| Ok(())).is_err()
    }

    /// Regression (R7): the authorizer runs under the lock, after validation and
    /// before any write, and sees the LOCKED file's metadata.
    #[test]
    fn append_journal_authorize_runs_under_the_lock_before_any_write() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        let journal = journal_path(&path);
        let (archive_before, journal_before) =
            (fs::read(&path).unwrap(), fs::read(&journal).unwrap());
        let ino = fs::metadata(&path).unwrap().ino();
        let mut seen = None;
        let error = recover_with(
            &path,
            &mut |j, m| {
                seen = Some((*j, m.ino()));
                Err(io::Error::other("not mine"))
            },
            &mut |_| panic!("the hook must not run after a refusal"),
        )
        .unwrap_err();
        assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
        let (header, seen_ino) = seen.expect("authorize ran");
        assert_eq!(seen_ino, ino);
        assert!(!header.complete);
        assert_eq!(fs::read(&path).unwrap(), archive_before);
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        assert!(pending(&path).unwrap().is_some());

        // A file swapped in after the unlocked probe is judged by the locked
        // descriptor, not by the earlier stat.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        let crashed = fs::read(&path).unwrap();
        let journal = fs::read(journal_path(&path)).unwrap();
        let swap = path.clone();
        let copy = dir.path().join("copy");
        unix::AFTER_PROBE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::write(&copy, fs::read(&swap).unwrap()).unwrap();
                fs::rename(&copy, &swap).unwrap();
            }));
        });
        let error = recover_with(&path, &mut authorize_owned, &mut |_| Ok(())).unwrap_err();
        unix::AFTER_PROBE.with(|hook| *hook.borrow_mut() = None);
        assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
        assert!(error.to_string().contains("another file"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), crashed);
        assert_eq!(fs::read(journal_path(&path)).unwrap(), journal);
    }

    /// Regression (R7): a failing `before_unlink` keeps the journal and the
    /// marker; the error is `Committed` exactly when the archive holds the new
    /// bytes; a second call with a succeeding hook finishes with the locked
    /// descriptor's final stamp.
    #[test]
    fn append_journal_before_unlink_error_keeps_journal_and_marker() {
        use std::os::unix::fs::MetadataExt;
        // A fresh replacement.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"prefix:old contents").unwrap();
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents").unwrap();
        let mut stamps = Vec::new();
        let error = replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |a| {
            stamps.push(*a);
            Err(io::Error::other("rows busy"))
        })
        .unwrap_err();
        assert!(matches!(error, ReplaceError::Committed(_)), "{error:?}");
        // The hook ran for the replacement and again for its cleanup.
        assert_eq!(stamps.len(), 2);
        assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
        assert!(journal_path(&path).exists());
        assert!(pending(&path).unwrap().expect("journal pending").complete);
        let mut finished = None;
        let applied = recover_with(&path, &mut authorize_forced, &mut |a| {
            finished = Some(*a);
            Ok(())
        })
        .unwrap()
        .expect("applied");
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(finished, Some(applied));
        assert!(applied.rolled_forward);
        assert_eq!(applied.pre_len, b"prefix:old contents".len() as u64);
        assert_eq!(applied.new_len, b"prefix:new contents".len() as u64);
        assert_eq!(applied.final_len, meta.len());
        assert_eq!(applied.ino, meta.ino());
        assert!(!journal_path(&path).exists());
        assert!(!marker_present(&path));

        // A crash after the completion marker: recovery hook fails, then works.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator complete");
        let error = recover_with(&path, &mut authorize_forced, &mut |_| {
            Err(io::Error::other("rows busy"))
        })
        .unwrap_err();
        assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
        assert!(journal_path(&path).exists());
        assert!(recover_with(&path, &mut authorize_forced, &mut |_| Ok(()))
            .unwrap()
            .is_some());
        assert!(!journal_path(&path).exists());

        // A rollback whose hook fails is a journal error, not a commit.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        let error = recover_with(&path, &mut authorize_forced, &mut |a| {
            assert!(!a.rolled_forward);
            Err(io::Error::other("rows busy"))
        })
        .unwrap_err();
        assert!(matches!(error, RecoverError::Journal(_)), "{error:?}");
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
        assert!(journal_path(&path).exists());
        assert!(recover_with(&path, &mut authorize_forced, &mut |_| Ok(()))
            .unwrap()
            .is_some());
    }

    /// Regression (R7): the journal path comes from the LOCKED marker. A is
    /// probed (J0 beside A), then another opener finishes J0 and starts J1
    /// through the hard link B: the locked marker names J1, which the
    /// authorizer judges. Before: the stale J0 name did not exist, so the `C`
    /// marker was cleared and J1 dropped without being applied.
    #[test]
    fn append_journal_hardlink_second_journal_is_authorized_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (one, two) = (dir.path().join("one"), dir.path().join("two"));
        fs::create_dir(&one).unwrap();
        fs::create_dir(&two).unwrap();
        let (a, b) = (one.join("A"), two.join("B"));
        interrupted(&a, "archive truncate");
        fs::hard_link(&a, &b).unwrap();
        assert_ne!(journal_path(&a), journal_path(&b));
        let (seam_a, seam_b) = (a.clone(), b.clone());
        unix::AFTER_PROBE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                assert!(recover(&seam_a).unwrap());
                let mut suffix = tempfile::tempfile().unwrap();
                suffix.write_all(b"second journal").unwrap();
                assert!(
                    replace_suffix_with_hook(&seam_b, 7, &mut suffix, &mut |step| {
                        if step == "locator complete" {
                            Err(io::Error::other("crash"))
                        } else {
                            Ok(())
                        }
                    })
                    .is_err()
                );
            }));
        });
        let mut seen = None;
        let error = recover_with(
            &b,
            &mut |j, _| {
                seen = Some(*j);
                Err(io::Error::other("pre-stamp does not match the rows"))
            },
            &mut |_| panic!("refused"),
        )
        .unwrap_err();
        unix::AFTER_PROBE.with(|hook| *hook.borrow_mut() = None);
        assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
        assert!(seen.expect("authorizer saw J1").complete);
        assert!(journal_path(&b).exists(), "J1 stays");
        assert_eq!(fs::read(&a).unwrap(), b"prefix:second journal");
        assert!(pending(&a).unwrap().is_some());
        // Authorized (forced), J1 rolls forward through either name.
        let applied = recover_with(&a, &mut authorize_forced, &mut |_| Ok(()))
            .unwrap()
            .expect("J1 applied");
        assert!(applied.rolled_forward);
        assert!(!journal_path(&b).exists());
        assert_eq!(fs::read(&a).unwrap(), b"prefix:second journal");
    }

    /// Regression (R7, R7-C2): a stale prepare locator without a journal is
    /// cleared without touching the archive; a done locator is kept (the
    /// journal may sit beside another name); a complete one is refused with
    /// the locator kept; an active one is an error.
    #[test]
    fn append_journal_stale_marker_without_journal_is_cleared() {
        for (step, bytes, kept) in [
            ("locator prepare", b"prefix:old contents".as_slice(), None),
            (
                "journal unlink",
                b"prefix:new contents are longer".as_slice(),
                Some(b'D'),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            interrupted(&path, step);
            let _ = fs::remove_file(journal_path(&path));
            assert!(marker_present(&path), "{step}: a marker is left");
            assert_eq!(fs::read(&path).unwrap(), bytes);
            let applied = recover_with(&path, &mut authorize_owned, &mut |_| {
                panic!("nothing to restamp")
            })
            .unwrap();
            assert!(applied.is_none());
            assert_eq!(fs::read(&path).unwrap(), bytes, "{step}");
            assert_eq!(marker_state(&path), kept, "{step}");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator complete");
        fs::remove_file(journal_path(&path)).unwrap();
        let error = recover_with(&path, &mut authorize_owned, &mut |_| Ok(())).unwrap_err();
        assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
        assert_eq!(marker_state(&path), Some(b'C'));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator active");
        fs::remove_file(journal_path(&path)).unwrap();
        let error = recover_with(&path, &mut authorize_forced, &mut |_| Ok(())).unwrap_err();
        assert!(matches!(error, RecoverError::Journal(_)), "{error:?}");
        assert!(error.to_string().contains("missing or moved"), "{error}");
    }

    /// Regression (R10-B, #150): the `before_write` guard runs under the lock
    /// before the stale-`P` locator is cleared and before a rollback; a refusal
    /// writes nothing (locator, archive and journal stay). It never runs on the
    /// write-free `D` path or the `C` refusal, so `C` stays `Committed`.
    #[test]
    fn regression_recover_guard_runs_before_stale_clear_and_rollback() {
        let refuse = || io::Error::other("lost record");
        // Stale `P` without a journal: kept on a refusal, cleared after an Ok.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator prepare");
        let _ = fs::remove_file(journal_path(&path));
        let before = fs::read(&path).unwrap();
        let mut calls = 0;
        let error = recover_guarded(
            &path,
            &mut || {
                calls += 1;
                Err(refuse())
            },
            &mut authorize_owned,
            &mut |_| panic!("nothing to restamp"),
        )
        .unwrap_err();
        assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
        assert_eq!(calls, 1);
        assert_eq!(marker_state(&path), Some(b'P'), "stale locator kept");
        assert_eq!(fs::read(&path).unwrap(), before);
        recover_guarded(&path, &mut || Ok(()), &mut authorize_owned, &mut |_| {
            panic!("nothing to restamp")
        })
        .unwrap();
        assert_eq!(marker_state(&path), None);
        // A torn journal: the guard refuses before the rollback.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator active");
        let before = fs::read(&path).unwrap();
        let journal = fs::read(journal_path(&path)).unwrap();
        let error = recover_guarded(
            &path,
            &mut || Err(refuse()),
            &mut |_, _| panic!("authorize runs after the guard"),
            &mut |_| panic!("nothing applied"),
        )
        .unwrap_err();
        assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::read(journal_path(&path)).unwrap(), journal);
        assert_eq!(marker_state(&path), Some(b'A'));
        // A missing complete journal stays `Committed`; a `D` locator without
        // a journal writes nothing: neither consults the guard.
        for (step, expect_committed) in [("locator complete", true), ("journal unlink", false)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            interrupted(&path, step);
            let _ = fs::remove_file(journal_path(&path));
            let result = recover_guarded(
                &path,
                &mut || panic!("{step}: no write, no guard"),
                &mut authorize_owned,
                &mut |_| Ok(()),
            );
            if expect_committed {
                assert!(
                    matches!(result, Err(RecoverError::Committed(_))),
                    "{result:?}"
                );
            } else {
                assert!(matches!(result, Ok(None)), "{step}: {result:?}");
            }
        }
    }

    /// The locator state on `path`'s inode (`None` without a marker).
    fn marker_state(path: &Path) -> Option<u8> {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let attr = c"user.ratarmount.commit-journal";
        let mut bytes = vec![0u8; 8192];
        #[cfg(target_os = "linux")]
        let n = unsafe {
            libc::getxattr(
                name.as_ptr(),
                attr.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        #[cfg(target_os = "macos")]
        let n = unsafe {
            libc::getxattr(
                name.as_ptr(),
                attr.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                0,
                0,
            )
        };
        (n > 4).then(|| bytes[4])
    }

    fn remove_marker(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let attr = c"user.ratarmount.commit-journal";
        #[cfg(target_os = "linux")]
        let rc = unsafe { libc::removexattr(name.as_ptr(), attr.as_ptr()) };
        #[cfg(target_os = "macos")]
        let rc = unsafe { libc::removexattr(name.as_ptr(), attr.as_ptr(), 0) };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
    }

    fn sibling(path: &Path) -> PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(COMMIT_JOURNAL_SUFFIX);
        PathBuf::from(name)
    }

    /// Regression (r15 #1, design test 1c): an attempt that never published a
    /// journal must not adopt the journal another file left at the name. B (a
    /// complete journal J2, `C` on B) is renamed over A's name after A's `P`
    /// and before A's publish; A's attempt fails EEXIST, rolls back nothing,
    /// clears only its own `P`, and leaves B, its `C` and J2 alone.
    #[test]
    fn append_journal_unpublished_attempt_never_adopts_a_sibling_journal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (d, x) = (root.join("d"), root.join("x"));
        fs::create_dir(&d).unwrap();
        fs::create_dir(&x).unwrap();
        let a = d.join("A");
        fs::write(&a, b"prefix:a old").unwrap();
        let keep = d.join("keep");
        fs::hard_link(&a, &keep).unwrap();
        let a_mtime = fs::metadata(&keep).unwrap().modified().unwrap();
        let xb = x.join("A");
        interrupted(&xb, "locator complete");
        let b_bytes = fs::read(&xb).unwrap();
        let j2_bytes = fs::read(sibling(&xb)).unwrap();
        let original = fs::metadata(&a).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"a new").unwrap();
        let (seam_b, seam_a) = (xb.clone(), a.clone());
        fault::install(move |step| {
            if step == "locator prepare" {
                fs::rename(sibling(&seam_b), sibling(&seam_a))?;
                fs::rename(&seam_b, &seam_a)?;
            }
            Ok(())
        });
        let mut hooks = 0;
        let result = replace_suffix_if_unchanged_with(&a, 7, &mut suffix, &original, &mut |_| {
            hooks += 1;
            Ok(())
        });
        fault::clear();
        assert!(
            matches!(result, Err(ReplaceError::RolledBack(..))),
            "{result:?}"
        );
        assert_eq!(marker_state(&a), Some(b'C'), "B keeps its complete locator");
        assert_eq!(fs::read(&a).unwrap(), b_bytes, "B untouched");
        assert_eq!(fs::read(sibling(&a)).unwrap(), j2_bytes, "J2 untouched");
        assert_eq!(fs::read(&keep).unwrap(), b"prefix:a old");
        assert_eq!(fs::metadata(&keep).unwrap().modified().unwrap(), a_mtime);
        assert_eq!(marker_state(&keep), None, "A's own prepare locator cleared");
        assert_eq!(hooks, 0);
    }

    /// Regression (r15 #3, design test 7): a commit whose journal unlink or
    /// directory sync failed is retried under the attempt's lock; when the
    /// retry fails too the result is an error with the completion kept,
    /// never success.
    #[test]
    fn append_journal_commit_cleanup_retries_then_stays_committed() {
        let run = |faults: &'static [&'static str]| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            fs::write(&path, b"prefix:old contents").unwrap();
            let original = fs::metadata(&path).unwrap();
            let mut suffix = tempfile::tempfile().unwrap();
            suffix.write_all(b"new contents").unwrap();
            fault::install(move |step| {
                if faults.contains(&step) {
                    Err(io::Error::other(format!("injected {step}")))
                } else {
                    Ok(())
                }
            });
            let mut hooks = 0;
            let result =
                replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| {
                    hooks += 1;
                    Ok(())
                });
            fault::clear();
            (dir, path, result, hooks)
        };
        // (i) the directory sync fails once and the retry succeeds.
        let (_d, path, result, hooks) = run(&["commit directory sync"]);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(hooks, 1);
        assert_eq!(marker_state(&path), None);
        assert!(!journal_path(&path).exists());
        // (ii) the retry fails too: an error, the journal gone, `D` kept.
        let (_d, path, result, hooks) = run(&["commit directory sync", "cleanup directory sync"]);
        assert!(
            matches!(result, Err(ReplaceError::Committed(_))),
            "a failed cleanup is not a success: {result:?}"
        );
        assert_eq!(hooks, 1);
        assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
        assert!(!journal_path(&path).exists());
        assert_eq!(marker_state(&path), Some(b'D'));
        // A later recovery cannot tell where the journal went: `D` stays
        // until the manual escape (Astra v4 F1).
        assert!(!recover(&path).unwrap());
        assert_eq!(marker_state(&path), Some(b'D'));
        remove_marker(&path);
        assert!(!recover(&path).unwrap());
        assert!(!marker_present(&path));
        // (iii) the unlink fails once: rollback re-runs the hook and unlinks.
        let (_d, path, result, hooks) = run(&["commit unlink"]);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(hooks, 2);
        assert_eq!(marker_state(&path), None);
        assert!(!journal_path(&path).exists());
        // (iv) the retry's unlink fails too: committed, journal and `D` kept.
        let (_d, path, result, hooks) = run(&["commit unlink", "rollback unlink"]);
        assert!(
            matches!(result, Err(ReplaceError::Committed(_))),
            "{result:?}"
        );
        assert_eq!(hooks, 2);
        assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
        assert!(journal_path(&path).exists());
        assert_eq!(marker_state(&path), Some(b'D'));
    }

    /// Regression (Astra v4 F1): the completion is kept when the journal's
    /// absence is ambiguous. `/d/a` has a hard link `/third/a`; the commit is
    /// interrupted after its completion marker; `/d` is renamed to `/saved`.
    /// Recovering through `/third/a` cannot see the journal (it moved with
    /// `/d`) and must not clear the locator; recovering through `/saved/a`
    /// then finds the journal beside the archive and rolls FORWARD.
    #[test]
    fn append_journal_completion_kept_when_the_journal_moved_with_its_directory() {
        for (step, state) in [("locator done", b'D'), ("locator complete", b'C')] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let (d, third, saved) = (root.join("d"), root.join("third"), root.join("saved"));
            fs::create_dir(&d).unwrap();
            fs::create_dir(&third).unwrap();
            interrupted(&d.join("a"), step);
            fs::hard_link(d.join("a"), third.join("a")).unwrap();
            fs::rename(&d, &saved).unwrap();
            let new = b"prefix:new contents are longer".to_vec();
            let first = recover(&third.join("a"));
            // `C` (the hook may not have run) is refused; `D` is a no-op.
            assert_eq!(first.is_ok(), state == b'D', "{step}: {first:?}");
            assert_eq!(
                marker_state(&third.join("a")),
                Some(state),
                "{step}: completion kept"
            );
            assert_eq!(
                pending(&saved.join("a")).unwrap().map(|j| j.complete),
                Some(true)
            );
            assert!(recover(&saved.join("a")).unwrap(), "{step}");
            assert_eq!(
                fs::read(saved.join("a")).unwrap(),
                new,
                "{step}: rolled forward"
            );
            assert_eq!(fs::read(third.join("a")).unwrap(), new);
            assert!(!sibling(&saved.join("a")).exists());
            assert_eq!(marker_state(&third.join("a")), None);
            assert!(!recover(&third.join("a")).unwrap());
            assert_eq!(
                fs::read(third.join("a")).unwrap(),
                new,
                "{step}: idempotent"
            );
        }
    }

    /// Regression (Astra v3 #1): a journal moves with its renamed directory;
    /// `pending` and `recover` find it beside the archive's current name.
    #[test]
    fn append_journal_moved_directory_journal_is_found_beside_the_archive() {
        for step in ["locator active", "locator complete", "locator done"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let (d, saved) = (root.join("d"), root.join("saved"));
            fs::create_dir(&d).unwrap();
            interrupted(&d.join("a"), step);
            fs::rename(&d, &saved).unwrap();
            let a = saved.join("a");
            let found = pending(&a).unwrap();
            assert_eq!(
                found.map(|j| j.complete),
                Some(step != "locator active"),
                "{step}"
            );
            assert!(recover(&a).unwrap(), "{step}");
            let expected: &[u8] = if step == "locator active" {
                b"prefix:old contents"
            } else {
                b"prefix:new contents are longer"
            };
            assert_eq!(fs::read(&a).unwrap(), expected, "{step}");
            assert!(!sibling(&a).exists());
            assert_eq!(marker_state(&a), None);
            assert!(!recover(&a).unwrap(), "{step}: idempotent");
            // The renamed directory's old name now holds journal-free B.
            fs::create_dir(&d).unwrap();
            fs::write(d.join("a"), b"B bytes").unwrap();
            assert!(!recover(&d.join("a")).unwrap());
            assert_eq!(fs::read(d.join("a")).unwrap(), b"B bytes");
        }
        // A sibling carrying another inode's journal is never adopted.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (d, saved, other) = (root.join("d"), root.join("saved"), root.join("other"));
        fs::create_dir(&d).unwrap();
        fs::create_dir(&other).unwrap();
        interrupted(&d.join("a"), "locator complete");
        interrupted(&other.join("b"), "locator complete");
        fs::rename(&d, &saved).unwrap();
        let a = saved.join("a");
        fs::rename(sibling(&a), root.join("moved-away")).unwrap();
        fs::copy(sibling(&other.join("b")), sibling(&a)).unwrap();
        let foreign = fs::read(sibling(&a)).unwrap();
        assert_eq!(pending(&a).unwrap(), None);
        let error = recover(&a).unwrap_err();
        assert!(error.to_string().contains("missing or moved"), "{error}");
        assert_eq!(fs::read(sibling(&a)).unwrap(), foreign);
        assert_eq!(fs::read(&a).unwrap(), b"prefix:new contents are longer");
        assert_eq!(marker_state(&a), Some(b'C'));
    }

    /// Regression: a complete locator whose journal is gone is refused with
    /// the manual escape named, never cleared (the hook may not have run).
    #[test]
    fn append_journal_complete_locator_without_journal_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator complete");
        fs::remove_file(journal_path(&path)).unwrap();
        let error = recover_with(&path, &mut authorize_owned, &mut |_| Ok(()))
            .expect_err("a complete locator without journal is refused");
        assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
        let error = error.into_io();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let text = error.to_string();
        assert!(text.contains("missing or moved"), "{text}");
        assert!(text.contains("user.ratarmount.commit-journal"), "{text}");
        assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents are longer");
        assert_eq!(marker_state(&path), Some(b'C'));
        remove_marker(&path);
        assert!(!recover(&path).unwrap());
    }

    /// Regression (Astra v2 #1): the attempt recovers only the journal file it
    /// published. A byte-identical copy renamed over the journal path is
    /// another file: nothing is written and the copy stays.
    #[test]
    fn append_journal_published_journal_replaced_at_the_path_is_unresolved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"prefix:old contents").unwrap();
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents").unwrap();
        let journal = journal_path(&path);
        let copy = dir.path().join("copy");
        let (seam_journal, seam_copy) = (journal.clone(), copy.clone());
        fault::install(move |step| {
            if step == "locator active" {
                fs::copy(&seam_journal, &seam_copy)?;
                fs::rename(&seam_copy, &seam_journal)?;
                return Err(io::Error::other("injected after the journal was replaced"));
            }
            Ok(())
        });
        let result =
            replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| Ok(()));
        fault::clear();
        let error = result.unwrap_err();
        assert!(matches!(error, ReplaceError::Pending(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .contains("not the journal this attempt published"),
            "{error}"
        );
        assert!(
            journal.exists(),
            "the foreign file at the journal path stays"
        );
        assert_eq!(marker_state(&path), Some(b'A'));
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
    }

    /// Regression: a stale prepare locator is cleared only after the parent
    /// directory sync; a stale done locator (the journal unlinked, the clear
    /// lost) is kept (Astra v4 F1: absence is ambiguous).
    #[test]
    fn append_journal_stale_locators_sync_before_clear_and_keep_done() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator prepare");
        assert_eq!(marker_state(&path), Some(b'P'));
        fault::install(|step| {
            if step == "stale marker directory sync" {
                Err(io::Error::other("injected sync"))
            } else {
                Ok(())
            }
        });
        let synced = recover(&path);
        fault::clear();
        assert!(synced.is_err(), "the clear waits for the directory sync");
        assert_eq!(marker_state(&path), Some(b'P'));
        assert!(!recover(&path).unwrap());
        assert_eq!(marker_state(&path), None);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "journal unlink");
        assert!(!journal_path(&path).exists());
        assert!(!recover(&path).unwrap());
        assert!(marker_state(&path).is_some(), "the completion is kept");
        assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents are longer");
    }

    /// Regression: a rollback whose old bytes are already in place writes
    /// nothing (no truncate, copy or mtime), so a second recovery of a
    /// rolled-back file keeps the stamp the first one's hook recorded.
    #[test]
    fn append_journal_rollback_skips_writes_when_old_bytes_are_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator active");
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        fault::install(|step| match step {
            "rollback truncate" | "rollback mtime" => {
                Err(io::Error::other(format!("{step}: no write expected")))
            }
            _ => Ok(()),
        });
        let recovered = recover(&path);
        fault::clear();
        assert!(recovered.unwrap(), "recovered without writing");
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
        assert!(!journal_path(&path).exists());
        assert_eq!(marker_state(&path), None);
    }

    /// The contract of a failed attempt, one case per stop (design §5 cj
    /// table): the variant, the bytes, whether the journal is on disk, the
    /// locator and how often the hook ran.
    #[test]
    fn append_journal_failed_attempt_table() {
        #[derive(Debug, PartialEq)]
        enum V {
            Ok,
            Refused,
            RolledBack,
            Pending,
            Committed,
        }
        const OLD: &[u8] = b"prefix:old contents";
        const NEW: &[u8] = b"prefix:new contents";
        // (faults, variant, bytes, journal on disk, locator, hook count)
        type Case = (
            &'static [&'static str],
            V,
            &'static [u8],
            bool,
            Option<u8>,
            usize,
        );
        let table: &[Case] = &[
            (&["journal header"], V::RolledBack, OLD, false, None, 0),
            (&["journal tail"], V::RolledBack, OLD, false, None, 0),
            (&["journal fsync"], V::RolledBack, OLD, false, None, 0),
            (&["locator prepare"], V::RolledBack, OLD, false, None, 0),
            (&["journal publish"], V::RolledBack, OLD, false, None, 1),
            (
                &["journal directory fsync"],
                V::RolledBack,
                OLD,
                false,
                None,
                1,
            ),
            (&["locator active"], V::RolledBack, OLD, false, None, 1),
            (&["archive truncate"], V::RolledBack, OLD, false, None, 1),
            (&["archive write"], V::RolledBack, OLD, false, None, 1),
            (&["archive fsync"], V::RolledBack, OLD, false, None, 1),
            (&["locator complete"], V::Ok, NEW, false, None, 1),
            (&["locator done"], V::Ok, NEW, false, None, 2),
            (&["journal unlink"], V::Ok, NEW, false, None, 1),
            (&["commit directory fsync"], V::Ok, NEW, false, None, 1),
            (&["locator clear"], V::Ok, NEW, false, None, 1),
            (&["before replace"], V::Refused, OLD, false, None, 0),
            (
                &["archive write", "rollback truncate"],
                V::Pending,
                b"prefix:new contents",
                true,
                Some(b'A'),
                0,
            ),
            (
                &["archive write", "rollback unlink"],
                V::Pending,
                OLD,
                true,
                Some(b'P'),
                1,
            ),
            (
                &["locator complete", "rollback unlink"],
                V::Committed,
                NEW,
                true,
                Some(b'D'),
                1,
            ),
            (
                &["archive write", "rollback directory sync"],
                V::Pending,
                OLD,
                false,
                Some(b'P'),
                1,
            ),
        ];
        for (faults, variant, bytes, journal, locator, hooks) in table {
            let faults: &'static [&'static str] = faults;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            fs::write(&path, OLD).unwrap();
            let original = fs::metadata(&path).unwrap();
            let mut suffix = tempfile::tempfile().unwrap();
            suffix.write_all(b"new contents").unwrap();
            fault::install(move |step| {
                if faults.contains(&step) {
                    Err(io::Error::other(format!("injected {step}")))
                } else {
                    Ok(())
                }
            });
            let mut count = 0;
            let result =
                replace_suffix_if_unchanged_with(&path, 7, &mut suffix, &original, &mut |_| {
                    count += 1;
                    Ok(())
                });
            fault::clear();
            let got = match result {
                Ok(()) => V::Ok,
                Err(ReplaceError::Refused(_)) => V::Refused,
                Err(ReplaceError::RolledBack(..)) => V::RolledBack,
                Err(ReplaceError::Pending(_)) => V::Pending,
                Err(ReplaceError::Committed(_)) => V::Committed,
            };
            let case = format!("{faults:?}");
            assert_eq!(&got, variant, "{case}");
            assert_eq!(fs::read(&path).unwrap(), *bytes, "{case}");
            assert_eq!(journal_path(&path).exists(), *journal, "{case}");
            assert_eq!(marker_state(&path), *locator, "{case}");
            assert_eq!(count, *hooks, "{case}");
            if faults == ["archive write", "rollback directory sync"] {
                assert!(!recover(&path).unwrap());
                assert_eq!(marker_state(&path), None);
            }
        }
    }
}
