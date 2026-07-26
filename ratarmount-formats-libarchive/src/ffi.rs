//! Minimal unsafe FFI to system libarchive (read path).

#![allow(non_camel_case_types, dead_code)]

use std::os::raw::{c_char, c_int, c_void};

pub const ARCHIVE_EOF: c_int = 1;
pub const ARCHIVE_OK: c_int = 0;
pub const ARCHIVE_RETRY: c_int = -10;
pub const ARCHIVE_WARN: c_int = -20;
pub const ARCHIVE_FAILED: c_int = -25;
pub const ARCHIVE_FATAL: c_int = -30;

// Filetype constants from archive_entry.h
pub const AE_IFMT: u32 = 0o170000;
pub const AE_IFREG: u32 = 0o100000;
pub const AE_IFLNK: u32 = 0o120000;
pub const AE_IFDIR: u32 = 0o040000;

pub enum archive {}
pub enum archive_entry {}

extern "C" {
    pub fn archive_read_new() -> *mut archive;
    pub fn archive_read_free(a: *mut archive) -> c_int;
    pub fn archive_read_support_filter_all(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_7zip(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_ar(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_cab(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_cpio(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_iso9660(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_lha(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_rar(a: *mut archive) -> c_int;
    #[cfg(libarchive_has_rar5)]
    pub fn archive_read_support_format_rar5(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_tar(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_warc(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_xar(a: *mut archive) -> c_int;
    pub fn archive_read_support_format_zip(a: *mut archive) -> c_int;
    // Avoid mtree (matches random text)

    pub fn archive_read_open_filename(
        a: *mut archive,
        filename: *const c_char,
        block_size: usize,
    ) -> c_int;

    pub fn archive_read_next_header(a: *mut archive, entry: *mut *mut archive_entry) -> c_int;
    pub fn archive_read_data(a: *mut archive, buff: *mut c_void, size: usize) -> isize;
    pub fn archive_error_string(a: *mut archive) -> *const c_char;
    pub fn archive_format_name(a: *mut archive) -> *const c_char;

    pub fn archive_entry_pathname(entry: *mut archive_entry) -> *const c_char;
    pub fn archive_entry_pathname_w(entry: *mut archive_entry) -> *const libc::wchar_t;
    pub fn archive_entry_size(entry: *mut archive_entry) -> i64;
    pub fn archive_entry_size_is_set(entry: *mut archive_entry) -> c_int;
    pub fn archive_entry_mode(entry: *mut archive_entry) -> c_int;
    pub fn archive_entry_filetype(entry: *mut archive_entry) -> c_int;
    pub fn archive_entry_mtime(entry: *mut archive_entry) -> libc::time_t;
    pub fn archive_entry_mtime_is_set(entry: *mut archive_entry) -> c_int;
    pub fn archive_entry_symlink(entry: *mut archive_entry) -> *const c_char;
    pub fn archive_entry_uid(entry: *mut archive_entry) -> i64;
    pub fn archive_entry_gid(entry: *mut archive_entry) -> i64;
}

pub fn cstr_to_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

pub fn error_string(a: *mut archive) -> String {
    unsafe {
        let p = archive_error_string(a);
        cstr_to_string(p).unwrap_or_else(|| "libarchive error".into())
    }
}
