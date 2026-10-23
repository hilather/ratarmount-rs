//! Open overlay-database inodes, and payload opens that refuse them (R10-C).
//!
//! On POSIX, closing ANY descriptor of an inode releases every fcntl lock the
//! process holds on that inode, SQLite's included. SQLite's own descriptors
//! are safe (its unix VFS defers their close while the inode is locked), but a
//! payload open through another name of the database (a hard link made on the
//! host, or a hard-link-preserving copy such as `cp -al` or `rsync -H`) gets
//! an ordinary descriptor of the database inode, and closing it after a read
//! hands another process the write lock while the mount still believes it
//! holds it (#148).
//!
//! Two halves:
//!
//! * The validated overlay-database open registers the `(dev, ino)` it
//!   opened ([`register_db_inode`]) for as long as its connection lives.
//! * Every payload, sentinel, pack and commit open goes through
//!   [`openat_admitted`] (or [`admit_fd`] for a descriptor it already holds),
//!   which checks the inode of the descriptor it actually obtained against
//!   that set and refuses an open database without closing a descriptor of
//!   it. On Linux the check runs on an `O_PATH` descriptor (closing one does
//!   not release fcntl locks) and the file is then reopened through
//!   `/proc/self/fd` with the caller's flags, so the refused path leaks
//!   nothing and `O_TRUNC` only ever applies to an admitted inode. That path
//!   does not count an external-alias epoch. Elsewhere (or without `/proc`)
//!   the file is opened without `O_TRUNC`, checked, and the first refused
//!   descriptor of an inode is quarantined: kept open for the life of the
//!   process ([`quarantined`] counts them). Further generic opens of that
//!   inode, including after its registration is dropped and created again,
//!   are refused before `open` once the external-alias epoch cap (one) is reached
//!   and quarantine nothing. An unidentified descriptor is still quarantined
//!   and does not count. Two opens that both pass the pre-check before either
//!   is recorded can each quarantine one descriptor. The registry and epoch
//!   locks are never held across `open`. Descriptors are not pooled: pooling
//!   would change what a later open is allowed to do with the file.
//!
//! The registry lock is only ever held to look up, insert or remove an entry:
//! never across `open(2)`, `fstat(2)` or a SQLite open, so a payload FIFO that
//! blocks its opener cannot stall a database open elsewhere in the process
//! (R10-D). Lock order: innermost (no other lock is taken while it is held).
//!
//! Residual (documented in docs/sandbox.md): a payload descriptor opened
//! BEFORE its inode is first opened as a database in this process (the
//! reverse ordering), and descriptors obtained by generic folder sources and
//! backing extents, are not tracked.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg_attr(not(unix), allow(dead_code))]
struct Entry {
    count: usize,
    db: PathBuf,
    warned: bool,
}

static OPEN_DBS: Mutex<BTreeMap<(u64, u64), Entry>> = Mutex::new(BTreeMap::new());

fn open_dbs() -> std::sync::MutexGuard<'static, BTreeMap<(u64, u64), Entry>> {
    OPEN_DBS.lock().unwrap_or_else(|e| e.into_inner())
}

/// One open overlay-database connection's entry in the registry; dropping it
/// removes the entry (the set counts connections per inode).
#[derive(Debug)]
pub struct DbInodeRegistration {
    id: (u64, u64),
}

impl Drop for DbInodeRegistration {
    fn drop(&mut self) {
        let mut dbs = open_dbs();
        if let Some(entry) = dbs.get_mut(&self.id) {
            entry.count -= 1;
            if entry.count == 0 {
                dbs.remove(&self.id);
            }
        }
    }
}

/// Register the overlay database `db` (its `(dev, ino)` as `id`) as open
/// until the returned value is dropped.
pub fn register_db_inode(id: (u64, u64), db: &Path) -> DbInodeRegistration {
    let mut dbs = open_dbs();
    dbs.entry(id)
        .and_modify(|e| e.count += 1)
        .or_insert_with(|| Entry {
            count: 1,
            db: db.to_path_buf(),
            warned: false,
        });
    DbInodeRegistration { id }
}

/// The open overlay database `id` is, if any (logs once per inode).
#[cfg_attr(not(unix), allow(dead_code))]
fn open_db_named(id: (u64, u64), path: &Path) -> Option<PathBuf> {
    let mut dbs = open_dbs();
    let entry = dbs.get_mut(&id)?;
    let db = entry.db.clone();
    let warn = !std::mem::replace(&mut entry.warned, true);
    drop(dbs);
    if warn {
        log::warn!(
            "{} is another name (a hard link) of the open overlay database {}; payload \
             opens of it are refused (further refusals of this inode are not logged)",
            path.display(),
            db.display()
        );
    }
    Some(db)
}

/// Is `id` an open overlay database's inode?
pub fn is_db_inode(id: (u64, u64)) -> bool {
    open_dbs().contains_key(&id)
}

/// The refusal for a payload open of an open database's inode.
#[cfg_attr(not(unix), allow(dead_code))]
fn refused(path: &Path, db: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} is another name (a hard link) of the open overlay database {}; it is not \
             opened as a file, because closing that descriptor would release the \
             database's locks. Remove the extra link",
            path.display(),
            db.display()
        ),
    )
}

#[cfg(unix)]
pub use unix::{admit_fd, open_admitted, openat_admitted, quarantined};

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::Mutex;

    /// Descriptors of open databases obtained by a refused open where no
    /// lock-safe close exists: never closed (see the module docs).
    static QUARANTINE: Mutex<Vec<OwnedFd>> = Mutex::new(Vec::new());

    /// Generic-path opens that obtained a descriptor of one registered
    /// overlay-database inode. Never reset when the registration is dropped:
    /// ordinary unmount/remount churn must not start a new quarantine.
    ///
    /// #196's addendum did not give a number. One is the bound that refuses
    /// the next open without pooling the quarantined descriptor.
    pub(super) const EXTERNAL_ALIAS_EPOCH_CAP: u32 = 1;

    static ALIAS_EPOCHS: Mutex<std::collections::BTreeMap<(u64, u64), u32>> =
        Mutex::new(std::collections::BTreeMap::new());

    fn alias_epochs(id: (u64, u64)) -> u32 {
        ALIAS_EPOCHS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .copied()
            .unwrap_or(0)
    }

    fn note_alias_epoch(id: (u64, u64)) {
        let mut epochs = ALIAS_EPOCHS.lock().unwrap_or_else(|e| e.into_inner());
        let entry = epochs.entry(id).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// `fstatat` with the same final-component follow rule as the open that
    /// would follow. Does not take the registry lock.
    fn fstatat_name(dir: RawFd, name: &CString, flags: libc::c_int) -> io::Result<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let at_flags = if flags & libc::O_NOFOLLOW != 0 {
            libc::AT_SYMLINK_NOFOLLOW
        } else {
            0
        };
        // Safety: `name` is NUL-terminated and outlives the call; `st` is a
        // valid out pointer.
        if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, at_flags) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    }

    /// The epoch is already spent and the name is still a registered database.
    /// No descriptor is opened. A missing name, a non-regular file, or an
    /// unregistered inode returns `None` so the open proceeds.
    fn refuse_capped_alias(
        dir: RawFd,
        c: &CString,
        name: &Path,
        flags: libc::c_int,
    ) -> Option<io::Error> {
        let st = fstatat_name(dir, c, flags).ok()?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return None;
        }
        let id = id(&st);
        if alias_epochs(id) < EXTERNAL_ALIAS_EPOCH_CAP {
            return None;
        }
        let db = super::open_db_named(id, name)?;
        Some(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is another name (a hard link) of the open overlay database {}; further \
                 opens are refused before open (external-alias epoch cap \
                 {EXTERNAL_ALIAS_EPOCH_CAP} reached). Remove the extra link",
                name.display(),
                db.display()
            ),
        ))
    }

    /// How many descriptors refused opens have quarantined so far.
    pub fn quarantined() -> usize {
        QUARANTINE.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn quarantine(fd: OwnedFd) {
        QUARANTINE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(fd);
    }

    #[cfg(test)]
    thread_local! {
        /// Take the generic (open, check, quarantine) path on Linux too.
        pub(super) static FORCE_GENERIC: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
        /// Make every `fstat` fail with `EIO`.
        pub(super) static FAIL_FSTAT: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    fn fstat(fd: RawFd) -> io::Result<libc::stat> {
        #[cfg(test)]
        if FAIL_FSTAT.with(|f| f.get()) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // Safety: `st` is a valid out pointer; `fd` is open.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    }

    fn id(st: &libc::stat) -> (u64, u64) {
        #[allow(clippy::unnecessary_cast)]
        (st.st_dev as u64, st.st_ino as u64)
    }

    fn openat_raw(
        dir: RawFd,
        name: &CString,
        flags: libc::c_int,
        mode: u32,
    ) -> io::Result<OwnedFd> {
        // Safety: `name` is NUL-terminated and outlives the call.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags, mode as libc::c_uint) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // Safety: a new descriptor owned by this process.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    /// Refuse `fd` (opened through `path`) when it is an open database's
    /// inode, WITHOUT closing it: the caller must not close a refused
    /// descriptor either. For a descriptor the caller already holds (a parked
    /// `O_PATH` descriptor about to be reopened, a dup source).
    pub fn admit_fd(fd: BorrowedFd<'_>, path: &Path) -> io::Result<()> {
        let st = fstat(fd.as_raw_fd())?;
        match super::open_db_named(id(&st), path) {
            Some(db) => Err(super::refused(path, &db)),
            None => Ok(()),
        }
    }

    /// [`openat_admitted`] relative to the current directory.
    pub fn open_admitted(path: &Path, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
        openat_admitted(None, path, flags, mode)
    }

    /// `openat(dir, name, flags, mode)` that never returns (and never closes)
    /// a descriptor of an open overlay database; see the module docs. A
    /// refusal is `PermissionDenied` (`EACCES`). With `O_CREAT` a missing file
    /// is created exclusively (a new inode cannot be a database); with
    /// `O_CREAT | O_EXCL` an existing file is `EEXIST`, untouched.
    pub fn openat_admitted(
        dir: Option<BorrowedFd<'_>>,
        name: &Path,
        flags: libc::c_int,
        mode: u32,
    ) -> io::Result<OwnedFd> {
        let dir = dir.map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
        let c = CString::new(name.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        for _ in 0..16 {
            match open_once(dir, &c, name, flags, mode)? {
                Some(fd) => return Ok(fd),
                None => continue,
            }
        }
        Err(io::Error::other(format!(
            "{} kept appearing and disappearing while it was opened",
            name.display()
        )))
    }

    /// One attempt; `None`: a create raced with another creator, retry.
    fn open_once(
        dir: RawFd,
        c: &CString,
        name: &Path,
        flags: libc::c_int,
        mode: u32,
    ) -> io::Result<Option<OwnedFd>> {
        #[cfg(all(target_os = "linux", test))]
        let linux = !FORCE_GENERIC.with(|f| f.get());
        #[cfg(all(target_os = "linux", not(test)))]
        let linux = true;
        #[cfg(target_os = "linux")]
        if linux {
            let create = flags & libc::O_CREAT != 0;
            let exclusive = create && flags & libc::O_EXCL != 0;
            let probe =
                libc::O_PATH | libc::O_CLOEXEC | (flags & (libc::O_NOFOLLOW | libc::O_DIRECTORY));
            match openat_raw(dir, c, probe, 0) {
                Ok(path_fd) => {
                    if exclusive {
                        return Err(io::Error::from_raw_os_error(libc::EEXIST));
                    }
                    let st = fstat(path_fd.as_raw_fd())?;
                    if let Some(db) = super::open_db_named(id(&st), name) {
                        // An `O_PATH` descriptor: closing it releases no lock.
                        drop(path_fd);
                        return Err(super::refused(name, &db));
                    }
                    if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                        // Only with `O_NOFOLLOW`: what `open(2)` reports.
                        return Err(io::Error::from_raw_os_error(libc::ELOOP));
                    }
                    let proc = CString::new(format!("/proc/self/fd/{}", path_fd.as_raw_fd()))
                        .expect("no NUL");
                    let reopen = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW);
                    match openat_raw(libc::AT_FDCWD, &proc, reopen, 0) {
                        Ok(fd) => return Ok(Some(fd)),
                        // No `/proc`: the generic path below.
                        Err(e)
                            if e.kind() == io::ErrorKind::NotFound
                                && !Path::new("/proc/self/fd").is_dir() => {}
                        Err(e) => return Err(e),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                    return create_fresh(dir, c, flags, mode);
                }
                Err(e) => return Err(e),
            }
        }
        generic(dir, c, name, flags, mode)
    }

    /// Exclusive creation of a missing file: a new inode is never a database.
    #[cfg(target_os = "linux")]
    fn create_fresh(
        dir: RawFd,
        c: &CString,
        flags: libc::c_int,
        mode: u32,
    ) -> io::Result<Option<OwnedFd>> {
        match openat_raw(dir, c, (flags | libc::O_EXCL) & !libc::O_TRUNC, mode) {
            Ok(fd) => Ok(Some(fd)),
            // Another creator won: look at what it created.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && flags & libc::O_EXCL == 0 => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Open without `O_TRUNC`, check the descriptor obtained, quarantine a
    /// refused one, truncate only an admitted file. A registered inode whose
    /// external-alias epoch is already spent is refused before this open.
    fn generic(
        dir: RawFd,
        c: &CString,
        name: &Path,
        flags: libc::c_int,
        mode: u32,
    ) -> io::Result<Option<OwnedFd>> {
        if let Some(error) = refuse_capped_alias(dir, c, name, flags) {
            return Err(error);
        }
        let fd = openat_raw(dir, c, flags & !libc::O_TRUNC, mode)?;
        // A descriptor whose identity cannot be established may be the
        // database's: quarantined, never closed.
        let st = match fstat(fd.as_raw_fd()) {
            Ok(st) => st,
            Err(e) => {
                quarantine(fd);
                return Err(e);
            }
        };
        if let Some(db) = super::open_db_named(id(&st), name) {
            // Count only a descriptor proved to be a registered database.
            // An unidentified `fstat` above is quarantined and is not an epoch.
            note_alias_epoch(id(&st));
            quarantine(fd);
            return Err(super::refused(name, &db));
        }
        if flags & libc::O_TRUNC != 0 && st.st_mode & libc::S_IFMT == libc::S_IFREG {
            if flags & libc::O_ACCMODE != libc::O_RDONLY {
                truncate(&fd)?;
            } else if st.st_size != 0 {
                // An empty read-only open (a fresh creation included) has
                // nothing to truncate: no writable reopen, which a new
                // mode-`000` file would refuse (R10-FIX9).
                // `O_RDONLY | O_TRUNC`: truncate through a writable handle on
                // the same, admitted inode (write permission is required, as
                // for the kernel's own `O_TRUNC`).
                let writer = openat_raw(
                    dir,
                    c,
                    libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    0,
                )?;
                let wst = match fstat(writer.as_raw_fd()) {
                    Ok(st) => st,
                    Err(e) => {
                        quarantine(writer);
                        return Err(e);
                    }
                };
                if id(&wst) != id(&st) {
                    if let Some(db) = super::open_db_named(id(&wst), name) {
                        note_alias_epoch(id(&wst));
                        quarantine(writer);
                        return Err(super::refused(name, &db));
                    }
                    return Err(io::Error::other(format!(
                        "{} changed while it was opened",
                        name.display()
                    )));
                }
                truncate(&writer)?;
            }
        }
        Ok(Some(fd))
    }

    fn truncate(fd: &OwnedFd) -> io::Result<()> {
        // Safety: `fd` is open.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    /// The quarantine count is process-wide: tests that read it run one at a
    /// time.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn id_of(path: &Path) -> (u64, u64) {
        let m = fs::metadata(path).unwrap();
        (m.dev(), m.ino())
    }

    /// Regression (R10-C, #148): the admitted open refuses every other name
    /// of a registered inode (read, write, `O_TRUNC`, `O_CREAT`, relative to a
    /// directory descriptor) with `PermissionDenied` naming the database,
    /// truncates nothing, and on Linux leaks no descriptor; other files and
    /// fresh creations open normally, and the registration counts.
    #[test]
    fn regression_admitted_open_refuses_a_registered_inode() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let db = dir.join("db.sqlite");
        fs::write(&db, b"database bytes").unwrap();
        let alias = dir.join("payload");
        fs::hard_link(&db, &alias).unwrap();
        let before = quarantined();
        let first = register_db_inode(id_of(&db), &db);
        let second = register_db_inode(id_of(&db), &db);
        assert!(is_db_inode(id_of(&alias)));
        let parent = fs::File::open(dir).unwrap();
        for flags in [
            libc::O_RDONLY,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            libc::O_WRONLY | libc::O_TRUNC,
            libc::O_RDONLY | libc::O_TRUNC,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        ] {
            let error = open_admitted(&alias, flags, 0o644).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{flags:#x}");
            assert!(
                error.to_string().contains(&db.display().to_string()),
                "{error}"
            );
            use std::os::fd::AsFd;
            let error =
                openat_admitted(Some(parent.as_fd()), Path::new("payload"), flags, 0).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{flags:#x}");
        }
        assert_eq!(fs::metadata(&db).unwrap().len(), 14, "nothing truncated");
        if cfg!(target_os = "linux") {
            assert_eq!(quarantined(), before, "O_PATH refusals leak nothing");
        }
        // `O_CREAT | O_EXCL` over the alias: EEXIST, untouched.
        let error =
            open_admitted(&alias, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o644).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        // Another file, a fresh creation, a truncation of an admitted file.
        let other = dir.join("other");
        fs::write(&other, b"other").unwrap();
        open_admitted(&other, libc::O_RDONLY, 0).unwrap();
        open_admitted(&other, libc::O_RDONLY | libc::O_TRUNC, 0).unwrap();
        assert_eq!(fs::metadata(&other).unwrap().len(), 0, "O_TRUNC applied");
        let fresh = dir.join("fresh");
        open_admitted(&fresh, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600).unwrap();
        assert!(fresh.is_file());
        // A symlink under `O_NOFOLLOW` is ELOOP, as `open(2)` reports.
        std::os::unix::fs::symlink(&other, dir.join("link")).unwrap();
        let error =
            open_admitted(&dir.join("link"), libc::O_RDONLY | libc::O_NOFOLLOW, 0).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
        // The registration counts connections per inode.
        drop(first);
        assert!(is_db_inode(id_of(&db)));
        drop(second);
        assert!(!is_db_inode(id_of(&db)));
        open_admitted(&alias, libc::O_RDONLY, 0).unwrap();
        // `admit_fd` refuses a descriptor it is handed, without closing it.
        let held = fs::File::open(&db).unwrap();
        let _again = register_db_inode(id_of(&db), &db);
        use std::os::fd::AsFd;
        assert_eq!(
            admit_fd(held.as_fd(), &alias).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    /// Regression (R10-FIX4, r10 skeptic #6): on the generic path (macOS, or
    /// Linux without `/proc`) a failed `fstat` returned through `?`, which
    /// closed a descriptor that was never identified and may be an open
    /// database's (releasing this process's locks on it). It is quarantined
    /// now, the error is returned, and nothing is truncated; the generic path
    /// otherwise refuses and admits as the Linux one does.
    #[test]
    fn regression_generic_open_quarantines_an_unidentified_descriptor() {
        use super::unix::{FAIL_FSTAT, FORCE_GENERIC};
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file");
        fs::write(&file, b"bytes").unwrap();
        FORCE_GENERIC.with(|f| f.set(true));
        let before = quarantined();
        FAIL_FSTAT.with(|f| f.set(true));
        let error = open_admitted(&file, libc::O_RDWR | libc::O_TRUNC, 0).unwrap_err();
        FAIL_FSTAT.with(|f| f.set(false));
        assert_eq!(error.raw_os_error(), Some(libc::EIO), "{error}");
        assert_eq!(quarantined(), before + 1, "the descriptor was closed");
        assert_eq!(fs::metadata(&file).unwrap().len(), 5, "nothing truncated");
        // The generic path's ordinary behaviour: a registered inode is
        // refused (quarantined), another file opens and truncates.
        let alias = tmp.path().join("alias");
        fs::hard_link(&file, &alias).unwrap();
        let registration = register_db_inode(id_of(&file), &file);
        let error = open_admitted(&alias, libc::O_RDONLY, 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(quarantined(), before + 2);
        drop(registration);
        open_admitted(&alias, libc::O_WRONLY | libc::O_TRUNC, 0).unwrap();
        assert_eq!(fs::metadata(&file).unwrap().len(), 0);
        FORCE_GENERIC.with(|f| f.set(false));
    }

    /// Regression (R10-FIX9, r10 skeptic P3): the generic path reopened a
    /// fresh `O_RDONLY | O_CREAT | O_TRUNC` creation for writing to truncate
    /// it; with mode `000` that reopen failed (`EACCES`) and the new file was
    /// left behind. An empty read-only open is not reopened; a non-empty one
    /// opened `O_RDONLY | O_TRUNC` is still truncated.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_generic_open_creates_read_only_mode_000_file() {
        use super::unix::FORCE_GENERIC;
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let fresh = tmp.path().join("fresh");
        FORCE_GENERIC.with(|f| f.set(true));
        let opened = open_admitted(&fresh, libc::O_RDONLY | libc::O_CREAT | libc::O_TRUNC, 0);
        let existing = tmp.path().join("existing");
        fs::write(&existing, b"bytes").unwrap();
        let truncated = open_admitted(&existing, libc::O_RDONLY | libc::O_TRUNC, 0);
        FORCE_GENERIC.with(|f| f.set(false));
        opened.expect("a fresh read-only creation opens");
        assert_eq!(fs::metadata(&fresh).unwrap().mode() & 0o7777, 0);
        truncated.unwrap();
        assert_eq!(fs::metadata(&existing).unwrap().len(), 0);
    }

    /// Regression (#196): on the generic path the first open of a registered
    /// overlay-database inode is quarantined. The next open, and an open after
    /// the registration is dropped and created again, is refused before `open`
    /// (external-alias epoch cap) and quarantines nothing. Between
    /// registrations the name is not a database and opens normally. On Linux
    /// the `O_PATH` refusal that runs first quarantines nothing and does not
    /// spend the epoch.
    #[test]
    fn regression_external_alias_epoch_cap_refuses_reopen_churn() {
        use super::unix::FORCE_GENERIC;
        struct ForceGeneric;
        impl ForceGeneric {
            fn arm() -> Self {
                FORCE_GENERIC.with(|f| f.set(true));
                Self
            }
        }
        impl Drop for ForceGeneric {
            fn drop(&mut self) {
                FORCE_GENERIC.with(|f| f.set(false));
            }
        }
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db.sqlite");
        fs::write(&db, b"database bytes").unwrap();
        let alias = tmp.path().join("payload");
        fs::hard_link(&db, &alias).unwrap();
        let before = quarantined();
        let registration = register_db_inode(id_of(&db), &db);

        // Linux checks on an `O_PATH` descriptor and drops it. That refusal
        // must not spend the epoch, or the first generic open below would
        // already be the cap.
        #[cfg(target_os = "linux")]
        {
            let opath = open_admitted(&alias, libc::O_RDONLY, 0).unwrap_err();
            assert_eq!(opath.kind(), io::ErrorKind::PermissionDenied);
            assert!(
                !opath.to_string().contains("epoch cap"),
                "O_PATH does not count an epoch: {opath}"
            );
            assert_eq!(quarantined(), before, "O_PATH refusals quarantine nothing");
        }

        let _force = ForceGeneric::arm();
        let first = open_admitted(&alias, libc::O_RDONLY, 0).unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            first.to_string().contains(&db.display().to_string()),
            "{first}"
        );
        assert!(
            !first.to_string().contains("epoch cap"),
            "the first refusal quarantines: {first}"
        );
        assert_eq!(quarantined(), before + 1);

        let second = open_admitted(&alias, libc::O_WRONLY | libc::O_TRUNC, 0).unwrap_err();
        assert_eq!(second.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            second.to_string().contains("external-alias epoch cap"),
            "{second}"
        );
        assert_eq!(quarantined(), before + 1, "the cap opens nothing");
        assert_eq!(fs::metadata(&db).unwrap().len(), 14, "nothing truncated");

        drop(registration);
        open_admitted(&alias, libc::O_RDONLY, 0).expect("unregistered name opens");
        assert_eq!(quarantined(), before + 1);

        let _again = register_db_inode(id_of(&db), &db);
        let remount = open_admitted(&alias, libc::O_RDONLY, 0).unwrap_err();
        assert!(
            remount.to_string().contains("external-alias epoch cap"),
            "{remount}"
        );
        assert_eq!(
            quarantined(),
            before + 1,
            "ordinary reopen churn does not quarantine another descriptor"
        );
        assert_eq!(fs::metadata(&db).unwrap().len(), 14);
    }
}
