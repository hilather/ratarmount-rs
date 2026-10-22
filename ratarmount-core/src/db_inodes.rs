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
//!   nothing and `O_TRUNC` only ever applies to an admitted inode. Elsewhere
//!   (or without `/proc`) the file is opened without `O_TRUNC`, checked, and a
//!   refused descriptor is quarantined: kept open for the life of the process
//!   (one descriptor per refused open; [`quarantined`] counts them).
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
    /// refused one, truncate only an admitted file. With `O_CREAT`, an
    /// exclusive attempt first learns whether THIS call created the file:
    /// only a new inode may skip the writable reopen a read-only `O_TRUNC`
    /// needs; an existing file (an empty one included) may not, so its
    /// write permission is still checked.
    fn generic(
        dir: RawFd,
        c: &CString,
        name: &Path,
        flags: libc::c_int,
        mode: u32,
    ) -> io::Result<Option<OwnedFd>> {
        let mut created = false;
        let fd = if flags & libc::O_CREAT != 0 {
            match openat_raw(dir, c, (flags | libc::O_EXCL) & !libc::O_TRUNC, mode) {
                Ok(fd) => {
                    created = true;
                    fd
                }
                // The name exists: open it (`O_CREAT` is kept so a file
                // removed meanwhile, or a dangling symlink's target, is
                // created as `open(2)` would); it counts as existing.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && flags & libc::O_EXCL == 0 => {
                    openat_raw(dir, c, flags & !libc::O_TRUNC, mode)?
                }
                Err(e) => return Err(e),
            }
        } else {
            openat_raw(dir, c, flags & !libc::O_TRUNC, mode)?
        };
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
            quarantine(fd);
            return Err(super::refused(name, &db));
        }
        if flags & libc::O_TRUNC != 0 && st.st_mode & libc::S_IFMT == libc::S_IFREG {
            if flags & libc::O_ACCMODE != libc::O_RDONLY {
                truncate(&fd)?;
            } else if !created {
                // Only a file THIS call created skips the writable reopen
                // (a fresh mode-`000` file would refuse it — R10-FIX9).
                // `O_RDONLY | O_TRUNC` on an existing file (empty included):
                // truncate through a writable handle on the same, admitted
                // inode (write permission is required, as for the kernel's
                // own `O_TRUNC`).
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

    fn timestamp_ns(seconds: i64, nanos: i64) -> i128 {
        i128::from(seconds) * 1_000_000_000 + i128::from(nanos)
    }

    fn mtime_ns(meta: &fs::Metadata) -> i128 {
        timestamp_ns(meta.mtime(), meta.mtime_nsec())
    }

    fn ctime_ns(meta: &fs::Metadata) -> i128 {
        timestamp_ns(meta.ctime(), meta.ctime_nsec())
    }

    /// Wait until realtime is strictly after `ctime_ns` and in a later Unix
    /// second, so a 1-second timestamp filesystem still shows an `ftruncate`
    /// update. Panics if that has not happened within 3 seconds.
    fn wait_until_next_second(ctime_ns: i128) {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let ctime_sec = ctime_ns / 1_000_000_000;
        loop {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let now_ns = i128::from(now.as_secs()) * 1_000_000_000 + i128::from(now.subsec_nanos());
            if now_ns > ctime_ns && i128::from(now.as_secs()) > ctime_sec {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "realtime did not pass the recorded ctime"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Selects `generic()` on Linux for this thread. macOS always uses it;
    /// setting the cell there does not change the path.
    #[must_use]
    struct ForceGenericGuard;

    impl ForceGenericGuard {
        fn enter() -> Self {
            super::unix::FORCE_GENERIC.with(|cell| cell.set(true));
            Self
        }
    }

    impl Drop for ForceGenericGuard {
        fn drop(&mut self) {
            super::unix::FORCE_GENERIC.with(|cell| cell.set(false));
        }
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

    /// Regression (sweep 1): on the generic path an `O_RDONLY | O_TRUNC`
    /// open of an EXISTING empty file skipped the writable reopen because
    /// `st_size == 0`, conflating it with a fresh creation — a mode-`444`
    /// file opened `Ok` where `open(2)` returns `EACCES`. Only an inode
    /// this call created may skip the reopen; an existing file goes through
    /// the writable handle, so its write permission is checked.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_generic_open_read_only_trunc_of_an_existing_empty_file() {
        use super::unix::FORCE_GENERIC;
        use std::os::unix::fs::PermissionsExt;
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // Safety: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip: root bypasses the mode-444 write-permission check");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let empty = tmp.path().join("empty");
        fs::write(&empty, b"").unwrap();
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o444)).unwrap();
        let writable = tmp.path().join("writable");
        fs::write(&writable, b"").unwrap();
        FORCE_GENERIC.with(|f| f.set(true));
        let error = open_admitted(&empty, libc::O_RDONLY | libc::O_TRUNC, 0).unwrap_err();
        let opened = open_admitted(&writable, libc::O_RDONLY | libc::O_TRUNC, 0);
        FORCE_GENERIC.with(|f| f.set(false));
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(empty.is_file());
        // R10-FIX10: a writable existing empty file still opens (and is
        // truncated through the writable handle).
        opened.unwrap();
    }

    /// Regression: empty writable `O_TRUNC` on the generic path left ctime and
    /// mtime unchanged (R10-FIX10). The read-only `O_TRUNC` case is
    /// `regression_generic_open_read_only_trunc_of_an_existing_empty_file`.
    #[test]
    fn regression_generic_open_truncates_empty_writable_file() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, UNIX_EPOCH};

        let _generic = ForceGenericGuard::enter();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let parent = fs::File::open(dir).unwrap();
        let past = UNIX_EPOCH + Duration::from_secs(1_000_000_000);

        // FIX9 skipped ftruncate whenever size was 0, so mtime stayed at the
        // stamped past value. ftruncate(0) updates both timestamps even though
        // the size stays 0 (R10-FIX10).
        let writable = dir.join("empty-w");
        fs::write(&writable, b"").unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o644)).unwrap();
        fs::File::options()
            .write(true)
            .open(&writable)
            .unwrap()
            .set_modified(past)
            .unwrap();
        let before_w = fs::metadata(&writable).unwrap();
        wait_until_next_second(ctime_ns(&before_w));
        let fd = openat_admitted(
            Some(parent.as_fd()),
            Path::new("empty-w"),
            libc::O_WRONLY | libc::O_TRUNC,
            0,
        )
        .unwrap();
        let after_w = fs::metadata(&writable).unwrap();
        drop(fd);
        assert_eq!(after_w.len(), 0);
        assert!(
            mtime_ns(&after_w) > mtime_ns(&before_w),
            "empty writable O_TRUNC did not update mtime ({} -> {})",
            mtime_ns(&before_w),
            mtime_ns(&after_w)
        );
        assert!(
            ctime_ns(&after_w) > ctime_ns(&before_w),
            "empty writable O_TRUNC did not update ctime ({} -> {})",
            ctime_ns(&before_w),
            ctime_ns(&after_w)
        );
    }
}
