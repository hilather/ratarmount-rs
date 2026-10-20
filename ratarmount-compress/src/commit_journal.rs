//! Durable, content-checked rollback for an in-place archive suffix replacement.
//!
//! The immutable, checksummed journal holds both tails. An inode xattr locates
//! it through hard links and bind mounts. Atomic xattr updates distinguish
//! preparation, active replacement, and a fully synced completed replacement.

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
/// for (`dev`/`ino` of the file it locked): a fallback cleanup after a failed
/// replacement must never touch another file's journal.
fn authorize_started(journal: &PendingJournal, file: &fs::Metadata, ino: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if journal.ino != ino || file.ino() != ino {
            return Err(io::Error::other(format!(
                "the archive carries a commit journal that this replacement did not start \
                 (journal inode {}, archive inode {}, attempt inode {}); the journal was not applied",
                journal.ino,
                file.ino(),
                ino
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = (journal, file, ino);
    Ok(())
}

/// Accept any journal (a forced recovery, or in-crate tests).
pub fn authorize_any(_: &PendingJournal, _: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

/// Recover before probing an archive or consulting its sidecar, even for a
/// read-only mount. A pending journal that cannot be recovered refuses the open.
///
/// Callers that own an overlay must use the compositing crate's
/// `recover_journal_at` (or `WriteOverlay::recover_journal`): this entry
/// neither authorizes nor restamps.
pub fn recover(archive: &Path) -> io::Result<bool> {
    recover_with(archive, &mut authorize_any, &mut |_| Ok(()))
        .map(|applied| applied.is_some())
        .map_err(RecoverError::into_io)
}

/// THE recovery entry. An unlocked probe (marker or sibling journal present?
/// else `Ok(None)` without locking) → open read-write → flock → `(state, path)`
/// both re-derived from the locked descriptor's marker (the sibling
/// [`journal_path`] only when there is no marker) → a missing journal is
/// metadata-only cleanup (`P`/`C` clear the marker, `A` is an error) → the
/// header is validated → `authorize(header, fstat)` → writes → marker →
/// `before_unlink(&Applied)` → unlink → clear.
pub fn recover_with(
    archive: &Path,
    authorize: Authorize,
    before_unlink: BeforeUnlink,
) -> std::result::Result<Option<Applied>, RecoverError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::recover(archive, authorize, before_unlink)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (authorize, before_unlink);
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
    /// The replacement finished (the locator says `complete`): recovery rolls
    /// FORWARD and leaves the new bytes.
    pub complete: bool,
}

/// The journal pending for `archive`, found the way [`recover`] finds it (the
/// inode locator first, then the sibling path). `Ok(None)` when there is none
/// or the platform has no journals. Never writes.
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

/// Replace a staged suffix. On an ordinary failure, recover before returning.
pub fn replace_suffix(archive: &Path, offset: u64, suffix: &mut File) -> io::Result<()> {
    replace_suffix_if_original(archive, offset, suffix, None, &mut |_| Ok(()))
        .map_err(RecoverError::into_io)
}

pub fn replace_suffix_if_unchanged(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    original: &fs::Metadata,
) -> io::Result<()> {
    replace_suffix_if_original(archive, offset, suffix, Some(original), &mut |_| Ok(()))
        .map_err(RecoverError::into_io)
}

/// [`replace_suffix_if_unchanged`] with a `before_unlink` hook that runs under
/// the archive lock with the final stamp, before the journal is unlinked. A
/// hook that keeps failing leaves the journal pending and returns
/// [`RecoverError::Committed`]; the next recovery runs the hook again.
pub fn replace_suffix_if_unchanged_with(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    original: &fs::Metadata,
    before_unlink: BeforeUnlink,
) -> std::result::Result<(), RecoverError> {
    replace_suffix_if_original(archive, offset, suffix, Some(original), before_unlink)
}

fn replace_suffix_if_original(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    original: Option<&fs::Metadata>,
    before_unlink: BeforeUnlink,
) -> std::result::Result<(), RecoverError> {
    #[allow(unused_mut)]
    let mut committed = false;
    // The (dev, ino) of the file THIS attempt took the lock on, set once the
    // staleness check passed and before the first marker or journal is written.
    #[allow(unused_mut)]
    let mut started: Option<(u64, u64)> = None;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let result = unix::replace(
        archive,
        offset,
        suffix,
        original,
        &mut committed,
        &mut started,
        &mut |_| Ok(()),
        &mut *before_unlink,
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let result = {
        let _ = (archive, offset, suffix, original);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "append requires Linux/macOS inode xattrs",
        ))
    };
    finish_replace(archive, result, committed, started, before_unlink)
}

fn finish_replace(
    archive: &Path,
    result: io::Result<()>,
    committed: bool,
    started: Option<(u64, u64)>,
    before_unlink: BeforeUnlink,
) -> std::result::Result<(), RecoverError> {
    if let Err(error) = result {
        // Only the journal this attempt started may be cleaned up here. A
        // failure before it was written (another file took the name, a pending
        // journal of someone else) leaves every journal alone, and the
        // `before_unlink` hook never restamps for a file this call did not lock.
        let Some((_dev, ino)) = started else {
            return Err(RecoverError::Journal(error));
        };
        fault::check("before cleanup").map_err(RecoverError::Journal)?;
        let mut authorize =
            |journal: &PendingJournal, file: &fs::Metadata| authorize_started(journal, file, ino);
        match recover_with(archive, &mut authorize, before_unlink) {
            Ok(_) if committed => return Ok(()),
            Ok(_) => return Err(RecoverError::Journal(error)),
            Err(RecoverError::Committed(recovery)) => {
                return Err(RecoverError::Committed(io::Error::other(format!(
                    "{error}; {recovery}"
                ))))
            }
            Err(recovery) => {
                return Err(RecoverError::Journal(io::Error::other(format!(
                    "{error}; {recovery}"
                ))))
            }
        }
    }
    Ok(())
}

/// Simulate process death: unlike the production entry points, leave recovery
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
            &mut false,
            &mut None,
            hook,
            &mut |_| Ok(()),
        )
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::{Duration, UNIX_EPOCH};

    const MAGIC: &[u8; 8] = b"RMCJ0002";
    pub(super) const HEADER_LEN: u64 = 96;
    const XATTR: &std::ffi::CStr = c"user.ratarmount.commit-journal";

    struct Lock(File);
    impl Drop for Lock {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
    fn lock(file: &File) -> io::Result<Lock> {
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
        File::open(parent(path))?.sync_all()
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
            || !matches!(bytes[4], b'P' | b'A' | b'C')
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn replace(
        archive: &Path,
        offset: u64,
        suffix: &mut File,
        original: Option<&fs::Metadata>,
        committed: &mut bool,
        started: &mut Option<(u64, u64)>,
        hook: &mut dyn FnMut(&'static str) -> io::Result<()>,
        before_unlink: BeforeUnlink,
    ) -> io::Result<()> {
        // Every checkpoint consults the death seam, then the fault.
        let mut hook = |step: &'static str| -> io::Result<()> {
            hook(step)?;
            fault::check(step)
        };
        fault::check("before replace")?;
        let archive = archive.canonicalize()?;
        let path = journal_path(&archive);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)?;
        let _lock = lock(&file)?;
        if path.try_exists()? || get_marker(&file)?.is_some() {
            return Err(recovery_error(
                &path,
                "pending journal; recover before preparing a commit",
            ));
        }
        let meta = file.metadata()?;
        if original.is_some_and(|old| {
            old.dev() != meta.dev()
                || old.ino() != meta.ino()
                || old.len() != meta.len()
                || old.mtime() != meta.mtime()
                || old.mtime_nsec() != meta.mtime_nsec()
                || old.ctime() != meta.ctime()
                || old.ctime_nsec() != meta.ctime_nsec()
        }) {
            return Err(io::Error::other(
                "archive changed while preparing append; retry with a fresh plan",
            ));
        }
        *started = Some((meta.dev(), meta.ino()));
        if offset > meta.len() {
            return Err(io::Error::other("append offset past archive EOF"));
        }
        let new_len = offset
            .checked_add(suffix.metadata()?.len())
            .ok_or_else(|| io::Error::other("suffix length overflow"))?;
        let prefix = fingerprint(&mut file, offset)?;
        let mut journal = tempfile::NamedTempFile::new_in(parent(&archive))?;
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
        copy_exact(&mut file, journal.as_file_mut(), meta.len() - offset)?;
        suffix.rewind()?;
        copy_exact(suffix, journal.as_file_mut(), new_len - offset)?;
        let size = journal.as_file().metadata()?.len();
        let crc = checksum(journal.as_file_mut(), size)?;
        journal.write_all(&crc.to_le_bytes())?;
        hook("journal tail")?;
        journal.as_file().sync_all()?;
        hook("journal fsync")?;
        marker(&file, &path, b'P')?;
        hook("locator prepare")?;
        journal.persist_noclobber(&path).map_err(|e| e.error)?;
        hook("journal publish")?;
        sync_parent(&path)?;
        hook("journal directory fsync")?;
        marker(&file, &path, b'A')?;
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
        let completion = marker(&file, &path, b'C');
        *committed = get_marker(&file)?.is_some_and(|(state, _)| state == b'C');
        completion?;
        hook("locator complete")?;
        before_unlink(&applied_of(
            &file,
            true,
            meta.len(),
            mtime_ns(&meta),
            new_len,
        )?)?;
        fault::instead("commit unlink", || fs::remove_file(&path))?;
        hook("journal unlink")?;
        fault::instead("commit directory sync", || sync_parent(&path))?;
        hook("commit directory fsync")?;
        clear_marker(&file)?;
        hook("locator clear")?;
        Ok(())
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
        authorize: Authorize,
        before_unlink: BeforeUnlink,
    ) -> std::result::Result<Option<Applied>, RecoverError> {
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
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(archive)
            .map_err(|e| journal_error(&probed, e))?;
        let _lock = lock(&file).map_err(|e| journal_error(&probed, e))?;
        // Another recovering opener may have won, or another opener (through a
        // hard link) may have started a different journal: BOTH the state and
        // the journal path come from the locked descriptor's marker.
        let locator = get_marker(&file).map_err(|e| journal_error(&probed, e))?;
        let state = locator.as_ref().map(|(s, _)| *s);
        let path = locator
            .map(|(_, p)| p)
            .unwrap_or_else(|| journal_path(archive));
        if !path.try_exists().map_err(RecoverError::Journal)? {
            // Metadata-only cleanup: `P` means no byte changed, `C` is only
            // reachable after the hook ran; neither writes archive bytes.
            if state == Some(b'A') {
                return Err(journal_error(
                    &path,
                    io::Error::other("active journal is missing or moved"),
                ));
            }
            clear_marker(&file).map_err(|e| journal_error(&path, e))?;
            return Ok(None);
        }
        rollback(
            &path,
            &mut file,
            state == Some(b'C'),
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
        let complete = marker.as_ref().is_some_and(|(state, _)| *state == b'C');
        let path = marker
            .map(|(_, p)| p)
            .unwrap_or_else(|| journal_path(archive));
        let mut journal = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
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
    }

    fn validate(path: &Path, file: &mut File, complete: bool) -> io::Result<(Header, File)> {
        if !fs::symlink_metadata(path)?.is_file() {
            return Err(io::Error::other("commit journal is not a regular file"));
        }
        let mut journal = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
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
        Ok((
            Header {
                pending: parse_pending(&header, complete),
                seconds,
                nanos,
            },
            journal,
        ))
    }

    fn rollback(
        path: &Path,
        file: &mut File,
        complete: bool,
        authorize: Authorize,
        before_unlink: BeforeUnlink,
    ) -> std::result::Result<Applied, RecoverError> {
        let (header, mut journal) =
            validate(path, file, complete).map_err(RecoverError::Journal)?;
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
        if !complete {
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
        fault::instead("rollback unlink", || fs::remove_file(path)).map_err(late)?;
        fault::instead("rollback directory sync", || sync_parent(path)).map_err(late)?;
        clear_marker(file).map_err(late)?;
        log::info!("commit: recovered journal {}", path.display());
        Ok(applied)
    }
}
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::io::Write;

    /// Regression: ENOSPC must roll back before returning to a live reader.
    #[test]
    fn append_journal_write_error_rolls_back_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"prefix:old contents").unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(&vec![0x82; 150_000]).unwrap();
        let result = replace_suffix_with_hook(&path, 7, &mut suffix, &mut |step| {
            if step == "archive write" {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            } else {
                Ok(())
            }
        });
        let started = Some({
            use std::os::unix::fs::MetadataExt;
            let m = fs::metadata(&path).unwrap();
            (m.dev(), m.ino())
        });
        assert!(finish_replace(&path, result, false, started, &mut |_| Ok(())).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
        assert!(!journal_path(&path).exists());
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
        for stop in ["locator complete", "journal unlink", "locator clear"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("archive");
            fs::write(&path, b"prefix:old contents").unwrap();
            let mut suffix = tempfile::tempfile().unwrap();
            suffix.write_all(b"new contents").unwrap();
            let mut committed = false;
            let started = {
                use std::os::unix::fs::MetadataExt;
                let m = fs::metadata(&path).unwrap();
                Some((m.dev(), m.ino()))
            };
            let result = unix::replace(
                &path,
                7,
                &mut suffix,
                None,
                &mut committed,
                &mut None,
                &mut |step| {
                    if step == stop {
                        Err(io::Error::other("cleanup failed"))
                    } else {
                        Ok(())
                    }
                },
                &mut |_| Ok(()),
            );
            assert!(committed);
            finish_replace(&path, result, committed, started, &mut |_| Ok(())).unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
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
        assert!(matches!(error, Err(RecoverError::Journal(_))), "{error:?}");
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
        assert!(replace_suffix_if_unchanged(&path, 0, &mut suffix, &original).is_err());
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
        assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
        // The hook ran for the replacement and again for its recovery attempt.
        assert_eq!(stamps.len(), 2);
        assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
        assert!(journal_path(&path).exists());
        assert!(pending(&path).unwrap().expect("journal pending").complete);
        let mut finished = None;
        let applied = recover_with(&path, &mut authorize_any, &mut |a| {
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
        let error = recover_with(&path, &mut authorize_any, &mut |_| {
            Err(io::Error::other("rows busy"))
        })
        .unwrap_err();
        assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
        assert!(journal_path(&path).exists());
        assert!(recover_with(&path, &mut authorize_any, &mut |_| Ok(()))
            .unwrap()
            .is_some());
        assert!(!journal_path(&path).exists());

        // A rollback whose hook fails is a journal error, not a commit.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        let error = recover_with(&path, &mut authorize_any, &mut |a| {
            assert!(!a.rolled_forward);
            Err(io::Error::other("rows busy"))
        })
        .unwrap_err();
        assert!(matches!(error, RecoverError::Journal(_)), "{error:?}");
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
        assert!(journal_path(&path).exists());
        assert!(recover_with(&path, &mut authorize_any, &mut |_| Ok(()))
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
        let applied = recover_with(&a, &mut authorize_any, &mut |_| Ok(()))
            .unwrap()
            .expect("J1 applied");
        assert!(applied.rolled_forward);
        assert!(!journal_path(&b).exists());
        assert_eq!(fs::read(&a).unwrap(), b"prefix:second journal");
    }

    /// Regression (R7): a stale locator without a journal is cleared (`P`, `C`)
    /// without touching the archive; an active one is an error.
    #[test]
    fn append_journal_stale_marker_without_journal_is_cleared() {
        for (step, bytes) in [
            ("locator prepare", b"prefix:old contents".as_slice()),
            (
                "locator complete",
                b"prefix:new contents are longer".as_slice(),
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
            assert!(!marker_present(&path), "{step}: marker cleared");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "locator active");
        fs::remove_file(journal_path(&path)).unwrap();
        let error = recover_with(&path, &mut authorize_any, &mut |_| Ok(())).unwrap_err();
        assert!(matches!(error, RecoverError::Journal(_)), "{error:?}");
        assert!(error.to_string().contains("missing or moved"), "{error}");
    }
}
