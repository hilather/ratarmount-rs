//! Test fixture (#151): a shared object that links ratarmount-index and its
//! bundled SQLite privately, as the Python `_native` module does. Its
//! constructor runs at `dlopen`; `tests/dso.rs` loads it into a process that
//! already has several threads, so the constructor abstains and
//! [`fixture_install`] takes the real private-instance path.

use std::ffi::{c_char, c_int, CStr};

use ratarmount_index::checked_open;

/// Copy `text` into `buf` (truncated, NUL-terminated); return its full length.
///
/// # Safety
///
/// `buf` is null or points to `len` writable bytes.
unsafe fn put(text: &str, buf: *mut u8, len: usize) -> usize {
    if !buf.is_null() && len > 0 {
        let n = text.len().min(len - 1);
        // SAFETY: the caller passes `len` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(text.as_ptr(), buf, n);
            *buf.add(n) = 0;
        }
    }
    text.len()
}

/// `{:?}` of `install_private_instance`, anchored at `anchor` (0: this
/// function, the real module anchor).
///
/// # Safety
///
/// `buf` is null or points to `len` writable bytes. The caller calls this
/// before anything else in this object uses SQLite, from one thread.
#[no_mangle]
pub unsafe extern "C" fn fixture_install(anchor: usize, buf: *mut u8, len: usize) -> usize {
    let anchor = match anchor {
        0 => fixture_install as *const std::ffi::c_void,
        other => other as *const std::ffi::c_void,
    };
    // SAFETY: the test calls this before anything else in this object uses
    // SQLite, from one thread; nothing else replaces the hooks.
    let result = unsafe { checked_open::install_private_instance(anchor) };
    // SAFETY: the caller's buffer contract.
    unsafe { put(&format!("{result:?}"), buf, len) }
}

/// `{:?}` of `(constructor_observation(), installed())`.
///
/// # Safety
///
/// `buf` is null or points to `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn fixture_status(buf: *mut u8, len: usize) -> usize {
    let status = (
        checked_open::constructor_observation(),
        checked_open::installed(),
    );
    // SAFETY: the caller's buffer contract.
    unsafe { put(&format!("{status:?}"), buf, len) }
}

/// The current `"open"` slot of this object's `"unix"` VFS (0: none, or the
/// VFS is older than version 3).
#[no_mangle]
pub extern "C" fn fixture_open_slot() -> usize {
    // SAFETY: SQLite is initialized here; a registered VFS lives for the
    // process and is at least the version-1 prefix, so only `iVersion` is
    // read before the version-3 fields are borrowed.
    unsafe {
        rusqlite::ffi::sqlite3_initialize();
        let vfs = rusqlite::ffi::sqlite3_vfs_find(c"unix".as_ptr());
        if vfs.is_null() || std::ptr::addr_of!((*vfs).iVersion).read() < 3 {
            return 0;
        }
        match (*vfs).xGetSystemCall {
            Some(get) => get(vfs, c"open".as_ptr()).map_or(0, |f| f as usize),
            None => 0,
        }
    }
}

/// Create a database at `path`, write a row, reopen it and read it back.
/// Returns 0 on success.
///
/// # Safety
///
/// `path` is a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn fixture_db_roundtrip(path: *const c_char) -> c_int {
    // SAFETY: the caller passes a NUL-terminated path.
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    let run = || -> rusqlite::Result<i64> {
        let conn = rusqlite::Connection::open(&path)?;
        conn.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (7);")?;
        drop(conn);
        let conn = rusqlite::Connection::open(&path)?;
        conn.query_row("SELECT x FROM t", [], |r| r.get(0))
    };
    match run() {
        Ok(7) => 0,
        _ => 1,
    }
}
