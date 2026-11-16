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

/// Publish an explicit test-hooks readiness marker. Ordinary builds do nothing.
#[cfg(any(test, feature = "test-hooks"))]
fn test_marker(variable: &str) -> io::Result<()> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(path) = std::env::var_os(variable) {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-238-V2-M01","item":"ratarmount_compress::commit_journal::test_marker","disposition":"out-of-family","category":"feature-test-hook","reason":"Publish explicit readiness output for the prewrite regression hold.","creation":{"policy":"create-or-truncate","basis":"The test-hooks marker is explicit instrumentation output written with fs::write and ordinary umask permissions."}}"###
        )]
        fs::write(path, b"ready")?;
    }
    #[cfg(not(any(test, feature = "test-hooks")))]
    let _ = variable;
    Ok(())
}

/// Explicit test-only hold after the sealed check and before archive mutation.
/// Copy publishers call this while holding their archive guard too.
#[doc(hidden)]
pub fn test_prewrite_hold() -> io::Result<()> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let (Some(_), Some(release)) = (
        std::env::var_os("RATARMOUNT_TEST_PREWRITE_READY"),
        std::env::var_os("RATARMOUNT_TEST_PREWRITE_RELEASE"),
    ) {
        test_marker("RATARMOUNT_TEST_PREWRITE_READY")?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !Path::new(&release).is_file() {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::other(
                    "timed out waiting for prewrite test release",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    Ok(())
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
/// before a journal is rolled back or forward. It also runs before the first
/// write of a replacement or publication. `Err` refuses with nothing written,
/// the locator included.
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

/// [`recover_with`] with a `before_write` guard under the archive lock.
/// Stale-`P` cleanup checks before the parent sync and again before clearing
/// the locator. Present-journal recovery checks before validation, after
/// authorization, and before archive, row, journal and locator mutations,
/// including after their fault seams (#239).
///
/// A guard failure before recovery writes is [`RecoverError::Refused`], even
/// beside a complete journal. Later failures retain the journal or locator
/// and use [`RecoverError::Committed`] for complete content, or
/// [`RecoverError::Journal`] for incomplete content. The `before_unlink` hook
/// revalidates and restamps rows before the journal is removed. These checks
/// do not provide lifetime isolation against concurrent pathname replacement.
///
/// Paths that write nothing (`None`, `D`) and a missing complete journal (`C`)
/// do not call the guard and keep their existing outcomes. The stale-`P`
/// branch never calls `before_unlink`.
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

/// What the shared read-only probe found at `archive`. Private: the only
/// cross-crate view is [`offline_journal_probe`]'s tuple.
// The non-`None` variants are constructed only where journals exist.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
enum JournalProbe {
    /// Neither a locator nor a journal file is present.
    None,
    /// A journal file is present; the header says whose it is.
    Pending(PendingJournal),
    /// A locator in the recorded phase (`P`, `A`, `C` or `D`) names a journal
    /// that cannot be found. Phases `A` and `C` are the ones recovery refuses
    /// (a torn or committed archive with nothing to recover from).
    Missing(u8, PathBuf),
    /// The located journal entry is not a regular file: an error for a caller
    /// reproducing recovery's refusals, tolerated as `Ok(None)` by
    /// [`pending`] (its long-standing contract).
    NotRegular,
}

/// The journal state of `archive`, found the way [`recover_with`] finds it
/// (the inode locator first, then the sibling path). Never writes; never
/// locks.
fn journal_probe(archive: &Path) -> io::Result<JournalProbe> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::probe(archive)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = archive;
        Ok(JournalProbe::None)
    }
}

/// The journal pending for `archive`, found the way [`recover_with`] finds it
/// (the inode locator first, then the sibling path). `Ok(None)` when there is
/// none or the platform has no journals. Never writes.
pub fn pending(archive: &Path) -> io::Result<Option<PendingJournal>> {
    match journal_probe(archive)? {
        JournalProbe::Pending(journal) => Ok(Some(journal)),
        _ => Ok(None),
    }
}

/// Read-only journal probe backing
/// `ratarmount_compositing::journal_recovery::check_offline_journal` — one
/// pass over [`journal_probe`], exposing no new types: the pending journal's
/// header when a journal file is present, else the locator's phase word and
/// the journal path it names when a locator in the active or complete phase
/// cannot find its journal — the states a recovery would refuse. Hidden
/// cross-crate seam; not public API.
#[doc(hidden)]
#[allow(clippy::type_complexity)]
pub fn offline_journal_probe(
    archive: &Path,
) -> io::Result<(Option<PendingJournal>, Option<(&'static str, PathBuf)>)> {
    Ok(match journal_probe(archive)? {
        JournalProbe::Pending(journal) => (Some(journal), None),
        JournalProbe::Missing(phase @ (b'A' | b'C'), path) => (
            None,
            Some((
                match phase {
                    b'A' => "active",
                    _ => "complete",
                },
                path,
            )),
        ),
        JournalProbe::NotRegular => {
            return Err(io::Error::other("commit journal is not a regular file"));
        }
        _ => (None, None),
    })
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
/// `before_write` runs after the lock and stamp checks, before any mutation.
pub fn replace_suffix_if_unchanged_with(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    original: &fs::Metadata,
    before_write: BeforeWrite,
    before_unlink: BeforeUnlink,
) -> std::result::Result<(), ReplaceError> {
    #[expect(
        clippy::disallowed_methods,
        reason = "The replacement convenience API delegates with the caller pre-write guard"
    )]
    replace_suffix_if_unchanged_guarded(
        archive,
        offset,
        suffix,
        original,
        before_write,
        before_unlink,
    )
}

/// Checked replacement with an additional guard under the archive lock, after
/// preparation seams and before any locator, journal or archive mutation.
pub fn replace_suffix_if_unchanged_guarded(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    original: &fs::Metadata,
    before_write: BeforeWrite,
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
            (before_write, before_unlink),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            archive,
            offset,
            suffix,
            original,
            before_write,
            before_unlink,
        );
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
        unix::replace(
            archive,
            offset,
            suffix,
            None,
            false,
            hook,
            (&mut || Ok(()), &mut |_| Ok(())),
        )
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0212-M01","item":"ratarmount_compress::commit_journal::unix::lock","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
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
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0213-M01","item":"ratarmount_compress::commit_journal::unix::sync_parent","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"directory handle opened only to fsync a directory entry","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###)]
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
        /// The first locator was installed; later guard errors retain recovery state.
        prepared: bool,
        /// The `C` locator was installed and synced.
        completed: bool,
        /// This attempt unlinked its journal (after the hook and `D`).
        unlinked: bool,
        /// The unlink's directory sync returned `Ok`.
        synced: bool,
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn replace(
        archive: &Path,
        offset: u64,
        suffix: &mut File,
        original: Option<&fs::Metadata>,
        cleanup: bool,
        hook: &mut dyn FnMut(&'static str) -> io::Result<()>,
        guards: (BeforeWrite<'_>, BeforeUnlink<'_>),
    ) -> std::result::Result<(), ReplaceError> {
        let (before_write, before_unlink) = guards;
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
#[expect(clippy::disallowed_types, reason = r###"internal-read:v1 {"id":"IR-B0214-T01","item":"ratarmount_compress::commit_journal::unix::replace","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-type-support","reason":"Builder type support: Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###)]
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0214-M01","item":"ratarmount_compress::commit_journal::unix::replace","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###)]
let mut __inventory_value_0 = fs::OpenOptions::new();
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0214-M02","item":"ratarmount_compress::commit_journal::unix::replace","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###)]
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
        before_write().map_err(refused)?;
        test_prewrite_hold().map_err(refused)?;
        let mut attempt = Attempt::default();
        let guard_refused = std::cell::Cell::new(false);
        let mut guard = || before_write().inspect_err(|_| guard_refused.set(true));
        let error = match run(
            &mut file,
            &path,
            &archive,
            offset,
            suffix,
            &meta,
            &mut attempt,
            &mut hook,
            (&mut guard, &mut *before_unlink),
        ) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        if guard_refused.get() && !attempt.prepared {
            // The guard runs before the first locator write. Refuse without
            // cleanup: there is no published state belonging to this attempt.
            return Err(ReplaceError::Refused(error));
        }
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
        match finish_failed(
            &mut file,
            &path,
            &attempt,
            error,
            (before_write, before_unlink),
        ) {
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
        io::Error::new(
            error.kind(),
            RecoveryIoError {
                message: format!("{error}; {other}"),
                cause: error,
            },
        )
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
        guards: (BeforeWrite<'_>, BeforeUnlink<'_>),
    ) -> io::Result<()> {
        let (before_write, before_unlink) = guards;
        if offset > meta.len() {
            return Err(io::Error::other("append offset past archive EOF"));
        }
        let new_len = offset
            .checked_add(suffix.metadata()?.len())
            .ok_or_else(|| io::Error::other("suffix length overflow"))?;
        let prefix = fingerprint(file, offset)?;
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0215-M01","item":"ratarmount_compress::commit_journal::unix::run","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
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
        before_write()?;
        marker(file, path, b'P')?;
        attempt.prepared = true;
        hook("locator prepare")?;
        before_write()?;
        // On `Err` tempfile deletes the temporary journal: nothing of this
        // attempt is at `path`.
        let published = journal.persist_noclobber(path).map_err(|e| e.error)?;
        let id = published.metadata()?;
        attempt.published = Some((id.dev(), id.ino()));
        drop(published);
        hook("journal publish")?;
        sync_parent(path)?;
        hook("journal directory fsync")?;
        before_write()?;
        marker(file, path, b'A')?;
        hook("locator active")?;
        before_write()?;
        file.set_len(offset)?;
        file.sync_all()?;
        hook("archive truncate")?;
        before_write()?;
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
        before_write()?;
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
        before_write()?;
        marker(file, path, b'D')?;
        hook("locator done")?;
        fault::instead("commit unlink", || {
            before_write()?;
            fs::remove_file(path)
        })?;
        attempt.unlinked = true;
        hook("journal unlink")?;
        fault::instead("commit directory sync", || sync_parent(path))?;
        attempt.synced = true;
        hook("commit directory fsync")?;
        before_write()?;
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
        guards: (BeforeWrite<'_>, BeforeUnlink<'_>),
    ) -> std::result::Result<(), ReplaceError> {
        let (before_write, before_unlink) = guards;
        let complete = attempt.completed
            || (attempt.published.is_some()
                && match get_marker(file) {
                    // An installed `C` whose fsync failed is still complete.
                    Ok(m) => m.is_some_and(|(s, _)| matches!(s, b'C' | b'D')),
                    Err(x) => return Err(ReplaceError::Pending(join(error, x))),
                });
        if let Err(error) = before_write() {
            return Err(if complete {
                ReplaceError::Committed(error)
            } else {
                ReplaceError::Pending(error)
            });
        }
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
            before_write().map_err(ReplaceError::Committed)?;
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
            (before_write, before_unlink),
        ) {
            Ok(_) if complete => Ok(()),
            Ok(_) => Err(ReplaceError::RolledBack(error, None)),
            Err(x) => {
                let message = format!("{error}; {x}");
                let cause = x.into_io();
                Err(unresolved(io::Error::new(
                    cause.kind(),
                    RecoveryIoError { message, cause },
                )))
            }
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0216-M01","item":"ratarmount_compress::commit_journal::unix::guard_copy","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0217-M01","item":"ratarmount_compress::commit_journal::unix::recover","disposition":"residual","reason":"base-archive bytes read by journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
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
            |path: &Path, e: io::Error| RecoverError::Journal(recovery_io_error(path, e));
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
#[expect(clippy::disallowed_types, reason = r###"internal-read:v1 {"id":"IR-B0218-T01","item":"ratarmount_compress::commit_journal::unix::recover","disposition":"support","reason":"Builder type support: base archive opened read-write by journal recovery to lock it and roll back or forward; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"builder-type-support","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###)]
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0218-M01","item":"ratarmount_compress::commit_journal::unix::recover","disposition":"support","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","family":"commit-journal-recovery","issue":"#196","category":"builder-setup","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"residual","baseline_reason":"base archive opened read-write by journal recovery to lock it and roll back or forward; recovery and mutation ownership belong to the excluded broader machinery"}"###)]
let mut __inventory_value_0 = fs::OpenOptions::new();
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0218-M02","item":"ratarmount_compress::commit_journal::unix::recover","disposition":"residual","reason":"base archive opened read-write by journal recovery to lock it and roll back or forward; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###)]
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
                    before_write().map_err(RecoverError::Refused)?;
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
            (before_write, before_unlink),
        )
        .map(Some)
        .map_err(|e| match e {
            RecoverError::Journal(e) => RecoverError::Journal(recovery_io_error(&path, e)),
            RecoverError::Committed(e) => RecoverError::Committed(recovery_io_error(&path, e)),
            refused => refused,
        })
    }

    pub(super) fn probe(archive: &Path) -> io::Result<JournalProbe> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0219-M01","item":"ratarmount_compress::commit_journal::unix::probe","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let file = match File::open(archive) {
            Ok(f) if f.metadata()?.is_file() => f,
            Ok(_) => return Ok(JournalProbe::None),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(JournalProbe::None)
            }
            Err(e) => return Err(e),
        };
        let marker = get_marker(&file)?;
        let phase = marker.as_ref().map(|(state, _)| *state);
        let complete = phase.is_some_and(|state| matches!(state, b'C' | b'D'));
        let (path, present) = locate(archive, &file, marker.map(|(_, p)| p))?;
        let missing = |phase: Option<u8>| match phase {
            Some(p) => JournalProbe::Missing(p, path.clone()),
            None => JournalProbe::None,
        };
        if !present {
            return Ok(missing(phase));
        }
        let mut journal = match open_journal(&path) {
            Ok(f) if f.metadata()?.is_file() => f,
            Ok(_) => return Ok(JournalProbe::NotRegular),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(missing(phase)),
            Err(e) => return Err(e),
        };
        let mut header = [0; HEADER_LEN as usize];
        journal.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(io::Error::other("journal header/length mismatch"));
        }
        Ok(JournalProbe::Pending(parse_pending(&header, complete)))
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
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0220-M01","item":"ratarmount_compress::commit_journal::unix::open_journal","disposition":"residual","reason":"base-archive bytes read by commit, splice or journal recovery; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###)]
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

    #[derive(Debug)]
    struct RecoveryIoError {
        message: String,
        cause: io::Error,
    }

    impl std::fmt::Display for RecoveryIoError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl std::error::Error for RecoveryIoError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.cause)
        }
    }

    fn recovery_io_error(path: &Path, cause: io::Error) -> io::Error {
        io::Error::new(
            cause.kind(),
            RecoveryIoError {
                message: recovery_error(path, &cause).to_string(),
                cause,
            },
        )
    }

    fn rollback(
        path: &Path,
        file: &mut File,
        complete: bool,
        expected: Option<(u64, u64)>,
        authorize: Authorize,
        guards: (BeforeWrite<'_>, BeforeUnlink<'_>),
    ) -> std::result::Result<Applied, RecoverError> {
        let (before_write, before_unlink) = guards;
        let (header, mut journal) =
            validate(path, file, complete, expected).map_err(RecoverError::Journal)?;
        // The journal is valid for the locked content; whether it is THIS
        // caller's to apply is decided on the locked descriptor, before any write.
        let locked = file.metadata().map_err(RecoverError::Journal)?;
        authorize(&header.pending, &locked).map_err(RecoverError::Refused)?;
        before_write().map_err(RecoverError::Refused)?;
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
                fault::instead("rollback truncate", || {
                    before_write()?;
                    file.set_len(offset)
                })?;
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
                    before_write()?;
                    file.set_times(fs::FileTimes::new().set_modified(mtime))
                }))?;
                file.sync_all()
            })();
            rolled.map_err(RecoverError::Journal)?;
        }
        // P with no journal means no mutation. The restored old archive is now
        // durable, so this also makes cleanup idempotent after an unlink crash.
        before_write().map_err(late)?;
        marker(file, path, if complete { b'C' } else { b'P' }).map_err(late)?;
        let applied = applied_of(file, complete, len, pre_mtime_ns, new_len).map_err(late)?;
        before_unlink(&applied).map_err(late)?;
        if complete {
            // The hook returned `Ok`: only the unlink is owed.
            before_write().map_err(late)?;
            marker(file, path, b'D').map_err(late)?;
        }
        fault::instead("rollback unlink", || {
            before_write()?;
            fs::remove_file(path)
        })
        .map_err(late)?;
        fault::instead("rollback directory sync", || sync_parent(path)).map_err(late)?;
        // The unlink is durable: a stale `P`/`D` locator is metadata-only for
        // the next recovery.
        before_write().map_err(late)?;
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
#[path = "commit_journal_tests.rs"]
mod tests;
