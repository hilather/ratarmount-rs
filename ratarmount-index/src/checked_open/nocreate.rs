//! Process-wide no-create latch for one overlay database (R11-S8, #151).
//!
//! A successful [`super::open_checked`] of an overlay database registers that
//! database for the rest of the process. The registration is not dropped with
//! the connection. Index, SQLAR, digest-cache and other managed readers must
//! not call [`latch_overlay_nocreate`].
//!
//! The identity is the parent directory's `(st_dev, st_ino)` (`lstat` of the
//! directory, not the database file) plus the database's file name, and also
//! the absolute and canonical path spellings. Renaming the directory keeps
//! the directory inode, so a later checked open at the new path still strips
//! `SQLITE_OPEN_CREATE`. The database file's own inode is not the key: it is
//! gone once the file is removed, which is the create this latch forbids.
//!
//! While a database is latched, a checked open strips `SQLITE_OPEN_CREATE`
//! (an `Expect::Fresh` retry included). On a verified Unix target the
//! installed `open` slot also refuses an `O_CREAT` that would bring the
//! database, `-wal` or `-shm` into existence, which is the path
//! `unixOpenSharedMemory` uses (`robust_open` calls the `open` syscall and
//! does not go through VFS `xOpen`). The slot is the one the installer
//! published; nothing installs a second wrapper later. The hook matches the
//! stored path spellings and, with no heap allocation, an `lstat` of the
//! parent directory plus the file name. On macOS those compares are
//! ASCII-case-insensitive and nothing else: `é` and `É` stay different, and
//! NFC and NFD stay different, so a name that differs only by non-ASCII case
//! or by Unicode normalization can still be created. Folding on every macOS
//! volume, including a case-sensitive one, fails closed.
//!
//! **Deliberate S8 carve-out:** `-journal` is recorded with the latch and
//! every open of it still passes through that slot, but the create is
//! allowed. Overlay databases use SQLite's DELETE journal mode, which creates
//! and unlinks `-journal` on every transaction, including the schema write
//! that follows the first successful open. Refusing that create would make
//! the overlay unwritable.
//!
//! The registry mutex is registered with `pthread_atfork` on the first latch.
//! The prepare handler locks it and the parent and child handlers unlock it,
//! so a child does not inherit the mutex held by another thread (that would
//! deadlock the child's `open`). The forking thread must not already hold the
//! mutex; this module does not fork while it holds the lock.
//!
//! The bundled SQLite has no `openat` syscall. When the slot exists it is
//! hooked in the same installation as `open`; a slot that was absent and
//! appears later fails the installation snapshot. A relative `openat` path is
//! not matched to a parent inode. There is no companion or directory-inode
//! guarantee on Windows or an unverified ABI: those hosts still strip
//! `SQLITE_OPEN_CREATE` on a latched path spelling, and nothing else.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

static LATCHES: AtomicUsize = AtomicUsize::new(0);

struct Entry {
    /// Parent directory `(st_dev, st_ino)` from `lstat`. `None` off Unix, or
    /// when the directory could not be statted. Matched with [`Entry::base`].
    #[cfg_attr(not(unix), allow(dead_code))]
    parent: Option<(u64, u64)>,
    db: Vec<u8>,
    /// Matched by the Unix `open` hook. Unused where that hook is not compiled.
    #[cfg_attr(not(unix), allow(dead_code))]
    wal: Vec<u8>,
    /// Matched by the Unix `open` hook. Unused where that hook is not compiled.
    #[cfg_attr(not(unix), allow(dead_code))]
    shm: Vec<u8>,
    /// Recorded so the latch names the companion. DELETE mode may still create
    /// this file (deliberate S8 carve-out); see the module docs.
    #[allow(dead_code)]
    journal: Vec<u8>,
    /// Holds the parent open so its inode cannot be reused after the directory
    /// is removed. Dropped only with the process. Not read otherwise.
    #[cfg(unix)]
    #[allow(dead_code)]
    pin: Option<std::os::fd::OwnedFd>,
    /// Database file name (not the directory). Matched with [`Entry::parent`].
    #[cfg_attr(not(unix), allow(dead_code))]
    base: Vec<u8>,
    #[cfg_attr(not(unix), allow(dead_code))]
    base_wal: Vec<u8>,
    #[cfg_attr(not(unix), allow(dead_code))]
    base_shm: Vec<u8>,
    /// Recorded with the carve-out. Not a name [`basename_is_refused`] hits.
    #[allow(dead_code)]
    base_journal: Vec<u8>,
}

/// Byte equality. On macOS, also ASCII case-insensitivity (same length, no
/// heap). Non-ASCII case and NFC versus NFD are not the same name. Windows
/// and Linux stay exact. `-journal` is not passed here.
fn names_equal(stored: &[u8], got: &[u8]) -> bool {
    if stored == got {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        stored.len() == got.len()
            && stored
                .iter()
                .zip(got)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(unix)]
fn basename_is_refused(entry: &Entry, name: &[u8]) -> bool {
    names_equal(&entry.base, name)
        || names_equal(&entry.base_wal, name)
        || names_equal(&entry.base_shm, name)
}

fn suffixed(path: &[u8], suffix: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len() + suffix.len());
    out.extend_from_slice(path);
    out.extend_from_slice(suffix.as_bytes());
    out
}

/// `lstat` of the parent directory, plus an fd that keeps that inode
/// allocated for the process. A symlink at the parent is the symlink's inode
/// (not the target); the canonical spelling is latched separately and carries
/// the real directory. Without the fd, Linux recycles the inode of a removed
/// temp directory and a later database of the same name is refused.
#[cfg(unix)]
fn pin_parent(path: &Path) -> (Option<(u64, u64)>, Option<std::os::fd::OwnedFd>) {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let Some(parent) = path.parent() else {
        return (None, None);
    };
    let id = std::fs::symlink_metadata(parent)
        .ok()
        .map(|meta| (meta.dev(), meta.ino()));
    let Some(id) = id else {
        return (None, None);
    };
    let Ok(c_path) = std::ffi::CString::new(parent.as_os_str().as_bytes()) else {
        return (Some(id), None);
    };
    let fd = open_parent(c_path.as_ptr());
    if fd < 0 {
        return (Some(id), None);
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let same = unsafe { libc::fstat(fd, &mut st) } == 0;
    #[allow(clippy::unnecessary_cast)]
    let pinned = (st.st_dev as u64, st.st_ino as u64);
    if !same || pinned != id {
        unsafe { libc::close(fd) };
        return (Some(id), None);
    }
    // SAFETY: `fd` is open and not owned elsewhere.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    (Some(id), Some(owned))
}

/// Open the parent the way `lstat` sees it: do not follow a final symlink.
#[cfg(target_os = "linux")]
fn open_parent(path: *const libc::c_char) -> libc::c_int {
    unsafe { libc::open(path, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) }
}

/// Open the parent the way `lstat` sees it. A directory uses `O_NOFOLLOW`;
/// a symlink (that open fails) is opened with `O_SYMLINK` so `fstat` matches
/// `lstat`. [`pin_parent`] drops the fd when `fstat` does not match.
/// `O_SYMLINK` is Darwin-only.
#[cfg(target_os = "macos")]
fn open_parent(path: *const libc::c_char) -> libc::c_int {
    let fd = unsafe {
        libc::open(
            path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        return fd;
    }
    unsafe { libc::open(path, libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC) }
}

/// Other Unix has no `O_PATH` and no `O_SYMLINK`. A directory is pinned;
/// a symlink parent is recorded by `lstat` without an fd.
#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn open_parent(path: *const libc::c_char) -> libc::c_int {
    unsafe {
        libc::open(
            path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    }
}

#[cfg(not(unix))]
fn pin_parent(path: &Path) -> (Option<(u64, u64)>, Option<()>) {
    let _ = path;
    (None, None)
}

#[cfg(unix)]
mod lock {
    use super::Entry;
    use std::cell::UnsafeCell;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::Once;

    struct Entries(UnsafeCell<Vec<Entry>>);
    // The pthread mutex below is the synchronization.
    unsafe impl Sync for Entries {}

    static ENTRIES: Entries = Entries(UnsafeCell::new(Vec::new()));
    static READY: AtomicPtr<libc::pthread_mutex_t> = AtomicPtr::new(std::ptr::null_mut());
    static INIT: Once = Once::new();

    struct MutexCell(UnsafeCell<libc::pthread_mutex_t>);
    unsafe impl Sync for MutexCell {}

    static MU: MutexCell = MutexCell(UnsafeCell::new(unsafe { std::mem::zeroed() }));

    fn init() {
        INIT.call_once(|| unsafe {
            let rc = libc::pthread_mutex_init(MU.0.get(), std::ptr::null());
            assert_eq!(rc, 0, "overlay no-create latch mutex");
            READY.store(MU.0.get(), Ordering::Release);
            let rc = libc::pthread_atfork(
                Some(atfork_prepare),
                Some(atfork_parent),
                Some(atfork_child),
            );
            assert_eq!(rc, 0, "overlay no-create latch atfork");
        });
    }

    unsafe extern "C" fn atfork_prepare() {
        let mu = READY.load(Ordering::Acquire);
        if !mu.is_null() {
            unsafe { libc::pthread_mutex_lock(mu) };
        }
    }

    unsafe extern "C" fn atfork_parent() {
        let mu = READY.load(Ordering::Acquire);
        if !mu.is_null() {
            unsafe { libc::pthread_mutex_unlock(mu) };
        }
    }

    unsafe extern "C" fn atfork_child() {
        let mu = READY.load(Ordering::Acquire);
        if !mu.is_null() {
            unsafe { libc::pthread_mutex_unlock(mu) };
        }
    }

    pub(super) struct Guard;

    impl Guard {
        pub(super) fn entries(&mut self) -> &mut Vec<Entry> {
            // SAFETY: the mutex is held. One guard exists.
            unsafe { &mut *ENTRIES.0.get() }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            let mu = READY.load(Ordering::Acquire);
            if !mu.is_null() {
                unsafe { libc::pthread_mutex_unlock(mu) };
            }
        }
    }

    /// `None` when the mutex cannot be locked. Callers in the `open` hook must
    /// fail closed instead of panicking through SQLite.
    pub(super) fn try_lock() -> Option<Guard> {
        init();
        let mu = READY.load(Ordering::Acquire);
        if mu.is_null() {
            return None;
        }
        // SAFETY: `init` stored the initialized mutex before returning.
        let rc = unsafe { libc::pthread_mutex_lock(mu) };
        if rc != 0 {
            return None;
        }
        Some(Guard)
    }

    pub(super) fn lock() -> Guard {
        try_lock().expect("overlay no-create latch lock")
    }
}

#[cfg(not(unix))]
mod lock {
    use super::Entry;
    use std::sync::Mutex;

    static REGISTRY: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

    pub(super) struct Guard(std::sync::MutexGuard<'static, Vec<Entry>>);

    impl Guard {
        pub(super) fn entries(&mut self) -> &mut Vec<Entry> {
            &mut self.0
        }
    }

    pub(super) fn lock() -> Guard {
        Guard(match REGISTRY.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        })
    }
}

/// Latch `path` (and its `-wal` / `-shm` / `-journal` names) for the rest of
/// this process. A second latch of the same path spelling is a no-op.
///
/// Two spellings are stored. The absolute path is what a later checked open
/// passes to SQLite (`SQLITE_OPEN_CREATE` is stripped on that spelling). The
/// canonical path is what the Unix VFS uses for `-wal` and `-shm` after it
/// resolves a symlink in the directory (`/tmp` → `/private/tmp` on macOS).
/// Each spelling also records `lstat` of its parent directory and the database
/// file name, so renaming that directory does not open a create.
pub fn latch_overlay_nocreate(path: &Path) {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let canonical = std::fs::canonicalize(&absolute).ok();
    let extra = canonical.filter(|spelling| spelling != &absolute);
    // Stat outside the registry lock. The lock must not be held across a
    // call that can fork; `pthread_atfork`'s prepare handler locks it.
    let (absolute_parent, absolute_pin) = pin_parent(&absolute);
    let (extra_parent, extra_pin) = match extra.as_deref() {
        Some(extra) => pin_parent(extra),
        None => (None, None),
    };
    let mut guard = lock::lock();
    push_entry(guard.entries(), &absolute, absolute_parent, absolute_pin);
    if let Some(extra) = extra.as_ref() {
        push_entry(guard.entries(), extra, extra_parent, extra_pin);
    }
    // Published after the entries are in the vec, under the same mutex the
    // hook takes after it observes a non-zero count.
    LATCHES.store(guard.entries().len(), Ordering::Release);
}

fn push_entry(
    entries: &mut Vec<Entry>,
    path: &Path,
    parent: Option<(u64, u64)>,
    #[cfg(unix)] pin: Option<std::os::fd::OwnedFd>,
    #[cfg(not(unix))] pin: Option<()>,
) {
    #[cfg(not(unix))]
    let _ = pin;
    let db = path.as_os_str().as_encoded_bytes().to_vec();
    if entries.iter().any(|entry| entry.db == db) {
        return;
    }
    let base = path
        .file_name()
        .map(|name| name.as_encoded_bytes().to_vec())
        .unwrap_or_default();
    entries.push(Entry {
        parent,
        #[cfg(unix)]
        pin,
        db: db.clone(),
        wal: suffixed(&db, "-wal"),
        shm: suffixed(&db, "-shm"),
        journal: suffixed(&db, "-journal"),
        base: base.clone(),
        base_wal: suffixed(&base, "-wal"),
        base_shm: suffixed(&base, "-shm"),
        base_journal: suffixed(&base, "-journal"),
    });
}

/// The database path is latched, by the stored spelling or by the parent
/// directory's identity plus the file name. Companions are not a match here;
/// the `open` hook judges those.
pub(crate) fn db_path_is_latched(path: &Path) -> bool {
    if LATCHES.load(Ordering::Acquire) == 0 {
        return false;
    }
    let db = path.as_os_str().as_encoded_bytes();
    #[cfg(unix)]
    let parent = {
        use std::os::unix::fs::MetadataExt;
        path.parent()
            .and_then(|parent| std::fs::symlink_metadata(parent).ok())
            .map(|meta| (meta.dev(), meta.ino()))
    };
    let mut guard = lock::lock();
    guard.entries().iter().any(|entry| {
        if names_equal(&entry.db, db) {
            return true;
        }
        #[cfg(unix)]
        {
            let Some(id) = parent else {
                return false;
            };
            let Some(name) = path.file_name() else {
                return false;
            };
            entry.parent == Some(id) && names_equal(&entry.base, name.as_encoded_bytes())
        }
        #[cfg(not(unix))]
        {
            false
        }
    })
}

/// What the `open` / `openat` wrapper should do with this call.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenPrep {
    /// Not a latched create. Forward the flags unchanged.
    Forward,
    /// `O_CREAT` would create a latched database, `-wal` or `-shm`. Do not
    /// call the real open.
    Refuse,
    /// The name is latched and already exists. Drop `O_CREAT` so a file
    /// unlinked before the real open cannot be recreated.
    StripCreate,
}

/// `lstat` of the parent of an absolute path, plus the file name. No heap
/// allocation. A path that does not fit in the stack buffer is not given a
/// parent identity (the stored path spellings still match).
#[cfg(unix)]
fn parent_of_bytes(path: &[u8]) -> Option<((u64, u64), &[u8])> {
    if path.first() != Some(&b'/') {
        return None;
    }
    let slash = path.iter().rposition(|b| *b == b'/')?;
    let base = &path[slash + 1..];
    if base.is_empty() {
        return None;
    }
    const MAX: usize = 4096;
    let mut buf = [0u8; MAX];
    let parent_len = if slash == 0 { 1 } else { slash };
    if parent_len >= MAX {
        return None;
    }
    if slash == 0 {
        buf[0] = b'/';
    } else {
        buf[..slash].copy_from_slice(&path[..slash]);
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `buf` is NUL-terminated (`MAX` bytes, parent_len < MAX, the rest
    // is zero). `st` is written by `lstat` before it is read.
    let rc = unsafe { libc::lstat(buf.as_ptr().cast(), &mut st) };
    if rc != 0 {
        return None;
    }
    // `st_dev` is `i32` on macOS and `u64` on Linux. Same cast as
    // `MetadataExt::dev` / `ino`.
    #[allow(clippy::unnecessary_cast)]
    Some(((st.st_dev as u64, st.st_ino as u64), base))
}

/// Decide a latched create without allocating. No registry lock when nothing
/// has been latched. The lock is a pthread mutex released across `fork`.
///
/// # Safety
///
/// `path` is null or a NUL-terminated path, as SQLite passes to `open`.
#[cfg(unix)]
pub(crate) unsafe fn prepare_open(path: *const libc::c_char, flags: libc::c_int) -> OpenPrep {
    if LATCHES.load(Ordering::Acquire) == 0 || flags & libc::O_CREAT == 0 || path.is_null() {
        return OpenPrep::Forward;
    }
    // SAFETY: the caller upholds the NUL-terminated contract.
    let bytes = unsafe { std::ffi::CStr::from_ptr(path) }.to_bytes();
    let parent = parent_of_bytes(bytes);
    let Some(mut guard) = lock::try_lock() else {
        return OpenPrep::Refuse;
    };
    let matched = guard.entries().iter().any(|entry| {
        names_equal(&entry.db, bytes)
            || names_equal(&entry.wal, bytes)
            || names_equal(&entry.shm, bytes)
            || parent.is_some_and(|(id, base)| {
                entry.parent == Some(id) && basename_is_refused(entry, base)
            })
    });
    drop(guard);
    if !matched {
        return OpenPrep::Forward;
    }
    // The name exists: opening it is not a create. `lstat` does not follow a
    // final symlink and is not SQLite's hooked `stat`.
    // SAFETY: `path` is the same C string; `st` is not read.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let exists = unsafe { libc::lstat(path, &mut st) } == 0;
    if exists {
        OpenPrep::StripCreate
    } else {
        OpenPrep::Refuse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_companion_is_stored_and_not_a_refused_name() {
        let base = b"db".to_vec();
        let entry = Entry {
            parent: Some((1, 2)),
            #[cfg(unix)]
            pin: None,
            db: b"/overlay/db".to_vec(),
            wal: suffixed(b"/overlay/db", "-wal"),
            shm: suffixed(b"/overlay/db", "-shm"),
            journal: suffixed(b"/overlay/db", "-journal"),
            base: base.clone(),
            base_wal: suffixed(&base, "-wal"),
            base_shm: suffixed(&base, "-shm"),
            base_journal: suffixed(&base, "-journal"),
        };
        assert_eq!(entry.journal, b"/overlay/db-journal");
        assert_eq!(entry.base_journal, b"db-journal");
        assert_ne!(entry.journal, entry.wal);
        assert_ne!(entry.journal, entry.shm);
        assert_ne!(entry.base_journal, entry.base_wal);
        assert_ne!(entry.base_journal, entry.base_shm);
        assert_eq!(entry.parent, Some((1, 2)));
        #[cfg(unix)]
        {
            assert!(
                !basename_is_refused(&entry, &entry.base_journal),
                "DELETE-mode -journal is the S8 carve-out"
            );
            assert!(basename_is_refused(&entry, &entry.base));
            assert!(basename_is_refused(&entry, &entry.base_wal));
            assert!(basename_is_refused(&entry, &entry.base_shm));
            #[cfg(target_os = "macos")]
            {
                assert!(basename_is_refused(&entry, b"DB"));
                assert!(basename_is_refused(&entry, b"DB-WAL"));
                assert!(basename_is_refused(&entry, b"db-SHM"));
                assert!(
                    !basename_is_refused(&entry, b"DB-JOURNAL"),
                    "a case variant of -journal stays the carve-out"
                );
            }
            #[cfg(not(target_os = "macos"))]
            assert!(
                !basename_is_refused(&entry, b"DB"),
                "case-sensitive hosts keep a different case as a different name"
            );
        }
    }
}
