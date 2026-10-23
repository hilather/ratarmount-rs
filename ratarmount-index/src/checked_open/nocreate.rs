//! Process-wide no-create latch for one overlay database (R11-S8, #151).
//!
//! A successful [`super::open_checked`] of an overlay database registers the
//! acquired `(st_dev, st_ino)` and that database's `-wal`, `-shm` and
//! `-journal` companion names for the rest of the process. The registration
//! is not dropped with the connection. Index, SQLAR, digest-cache and other
//! managed readers must not call [`latch_overlay_nocreate`].
//!
//! While a path is latched, a checked open of that database strips
//! `SQLITE_OPEN_CREATE` (an `Expect::Fresh` retry included). On a verified
//! Unix target the installed `open` slot also refuses an `O_CREAT` that would
//! bring the database, `-wal` or `-shm` into existence, which is the path
//! `unixOpenSharedMemory` uses (`robust_open` calls the `open` syscall and
//! does not go through VFS `xOpen`). The slot is the one the installer
//! published; nothing installs a second wrapper later.
//!
//! `-journal` is recorded with the latch and every open of it still passes
//! through that slot, but the create is allowed. Overlay databases use
//! SQLite's DELETE journal mode, which creates and unlinks `-journal` on
//! every transaction, including the schema write that follows the first
//! successful open. Refusing that create would make the overlay unwritable.
//!
//! The bundled SQLite has no `openat` syscall. When the slot exists it is
//! hooked in the same installation as `open`; a slot that was absent and
//! appears later fails the installation snapshot. There is no companion
//! guarantee on Windows or an unverified ABI: those hosts still strip
//! `SQLITE_OPEN_CREATE` on a latched checked open, and nothing else.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use super::DbId;

struct Entry {
    /// The inode SQLite acquired, when this host has one. The hook matches
    /// companion names; the inode is the latch's identity.
    #[allow(dead_code)]
    id: Option<DbId>,
    db: Vec<u8>,
    /// Matched by the Unix `open` hook. Unused where that hook is not compiled.
    #[cfg_attr(not(unix), allow(dead_code))]
    wal: Vec<u8>,
    /// Matched by the Unix `open` hook. Unused where that hook is not compiled.
    #[cfg_attr(not(unix), allow(dead_code))]
    shm: Vec<u8>,
    /// Recorded so the latch key names the companion. DELETE mode may still
    /// create this file; see the module docs.
    #[allow(dead_code)]
    journal: Vec<u8>,
}

static LATCHES: AtomicUsize = AtomicUsize::new(0);
static REGISTRY: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

fn lock() -> std::sync::MutexGuard<'static, Vec<Entry>> {
    match REGISTRY.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn suffixed(path: &[u8], suffix: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len() + suffix.len());
    out.extend_from_slice(path);
    out.extend_from_slice(suffix.as_bytes());
    out
}

/// Latch `path` (and its `-wal` / `-shm` / `-journal` names) for the rest of
/// this process. `id` is the inode SQLite acquired, when this host has one.
/// A second latch of the same path is a no-op.
///
/// Two spellings are stored. The absolute path is what a later checked open
/// passes to SQLite (`SQLITE_OPEN_CREATE` is stripped on that spelling). The
/// canonical path is what the Unix VFS uses for `-wal` and `-shm` after it
/// resolves a symlink in the directory (`/tmp` → `/private/tmp` on macOS).
/// Both are required: latching only one of them leaves a create path open.
pub fn latch_overlay_nocreate(id: Option<DbId>, path: &Path) {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut guard = lock();
    push_entry(&mut guard, id, &absolute);
    if let Ok(canonical) = std::fs::canonicalize(&absolute) {
        if canonical != absolute {
            push_entry(&mut guard, id, &canonical);
        }
    }
    // Published after the entries are in the vec, under the same mutex the
    // hook takes after it observes a non-zero count.
    LATCHES.store(guard.len(), Ordering::Release);
}

fn push_entry(guard: &mut Vec<Entry>, id: Option<DbId>, path: &Path) {
    let db = path.as_os_str().as_encoded_bytes().to_vec();
    if guard.iter().any(|entry| entry.db == db) {
        return;
    }
    guard.push(Entry {
        id,
        db: db.clone(),
        wal: suffixed(&db, "-wal"),
        shm: suffixed(&db, "-shm"),
        journal: suffixed(&db, "-journal"),
    });
}

/// The absolute database path (not a companion) is latched.
pub(crate) fn db_path_is_latched(path: &Path) -> bool {
    if LATCHES.load(Ordering::Acquire) == 0 {
        return false;
    }
    let db = path.as_os_str().as_encoded_bytes();
    lock().iter().any(|entry| entry.db == db)
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

/// Decide a latched create without allocating. No registry lock when nothing
/// has been latched. A poisoned lock is recovered.
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
    let matched = lock().iter().any(|entry| {
        entry.db.as_slice() == bytes
            || entry.wal.as_slice() == bytes
            || entry.shm.as_slice() == bytes
    });
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
        let entry = Entry {
            id: Some((1, 2)),
            db: b"/overlay/db".to_vec(),
            wal: suffixed(b"/overlay/db", "-wal"),
            shm: suffixed(b"/overlay/db", "-shm"),
            journal: suffixed(b"/overlay/db", "-journal"),
        };
        assert_eq!(entry.journal, b"/overlay/db-journal");
        assert_ne!(entry.journal, entry.wal);
        assert_ne!(entry.journal, entry.shm);
        let _ = entry.id;
    }
}
