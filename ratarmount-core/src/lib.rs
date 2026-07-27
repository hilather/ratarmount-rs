//! Core types and the `MountSource` trait (mirrors Python `ratarmountcore.mountsource`).

use std::collections::BTreeMap;
use std::io::{self, Read, Seek};
use std::path::PathBuf;

/// Portable `S_IF*` bits for [`FileInfo::mode`] (`u32`).
///
/// libc `mode_t` is `u32` on Linux but `u16` on macOS; mixing raw `libc::S_IFMT`
/// with `u32` modes fails to compile on Darwin (`u32 & u16`). Always use these.
#[allow(clippy::unnecessary_cast)] // mode_t width differs by OS
pub const S_IFMT: u32 = libc::S_IFMT as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFDIR: u32 = libc::S_IFDIR as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFREG: u32 = libc::S_IFREG as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFLNK: u32 = libc::S_IFLNK as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFIFO: u32 = libc::S_IFIFO as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFCHR: u32 = libc::S_IFCHR as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFBLK: u32 = libc::S_IFBLK as u32;
#[allow(clippy::unnecessary_cast)]
pub const S_IFSOCK: u32 = libc::S_IFSOCK as u32;

#[inline]
pub fn is_dir_mode(mode: u32) -> bool {
    mode & S_IFMT == S_IFDIR
}

#[inline]
pub fn is_lnk_mode(mode: u32) -> bool {
    mode & S_IFMT == S_IFLNK
}

/// Mirrors `MountSource.py::FileInfo`.
#[derive(Clone, Debug)]
pub struct FileInfo {
    pub size: u64,
    pub mtime: f64,
    pub mode: u32,
    pub linkname: String,
    pub uid: u32,
    pub gid: u32,
    /// Stack: only the last element belongs to the current MountSource.
    pub userdata: Vec<UserData>,
}

/// Keep SQL field names for TAR userdata (`SQLiteIndexedTarUserData`).
#[derive(Clone, Debug)]
pub struct SQLiteIndexedTarUserData {
    pub offset: u64,
    pub offsetheader: Option<u64>,
    pub istar: bool,
    pub issparse: bool,
    pub isgenerated: bool,
    pub recursiondepth: u32,
}

#[derive(Clone, Debug)]
pub enum UserData {
    Tar(SQLiteIndexedTarUserData),
    /// Opaque payload for other backends until typed.
    Other(String),
}

#[derive(Clone, Debug)]
pub enum ListResult {
    Names(Vec<String>),
    Infos(BTreeMap<String, FileInfo>),
}

#[derive(Clone, Debug)]
pub enum ListModeResult {
    Names(Vec<String>),
    Modes(BTreeMap<String, u32>),
}

/// Subset of POSIX `statvfs` fields used by FUSE.
#[derive(Clone, Debug, Default)]
pub struct StatFs {
    pub bsize: u64,
    pub namemax: u64,
}

/// Options for opening archives (subset of Python `open_mount_source` kwargs).
#[derive(Clone, Debug)]
pub struct OpenOptions {
    pub write_index: bool,
    pub clear_index_cache: bool,
    /// Explicit `--index-file` path, or `None` to resolve via `index_folders`.
    /// The special value `:memory:` is represented by `index_in_memory = true`.
    pub index_file_path: Option<PathBuf>,
    /// When true, keep the SQLite index purely in memory (`--index-file :memory:`).
    pub index_in_memory: bool,
    /// Folders to try for index storage (empty entry = next to archive).
    /// Empty vec means use Python-compatible defaults at resolve time.
    pub index_folders: Vec<PathBuf>,
    pub verify_modification_time: bool,
    pub index_minimum_file_count: u64,
    pub recursive: bool,
    pub recursion_depth: Option<i32>,
    pub ignore_zeros: bool,
    pub gnu_incremental: Option<bool>,
    pub parallelization: u32,
    /// Character encoding for TAR (and similar) member names (`-e` / `--encoding`).
    pub encoding: String,
    pub gzip_seek_point_spacing: u64,
    /// Passwords for encrypted archives (7z AES, ZIP, …). Tried in order.
    pub passwords: Vec<String>,
    /// Preferred backends (Python `--use-backend`); last has highest priority.
    pub use_backends: Vec<String>,
    /// Never create/modify indexes (`--no-recreate-index`).
    pub read_only_index: bool,
    /// Force folder index usage (`--force-folder-index`); folders still bind-mount live.
    pub force_folder_index: bool,
    /// Content hash algorithms to compute and store as index xattrs (`--hashes`).
    /// Values match Python CLI names, e.g. `crc32`, `md5`, `sha1`, `sha256`.
    pub hashes: Vec<String>,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            write_index: true,
            clear_index_cache: false,
            index_file_path: None,
            index_in_memory: false,
            index_folders: Vec::new(),
            verify_modification_time: false,
            // Harness always forces 0 via CLI; default matches common interactive use later.
            index_minimum_file_count: 0,
            recursive: false,
            recursion_depth: None,
            ignore_zeros: false,
            gnu_incremental: None,
            parallelization: 1,
            encoding: "utf-8".into(),
            gzip_seek_point_spacing: 16 * 1024 * 1024,
            passwords: Vec::new(),
            use_backends: Vec::new(),
            read_only_index: false,
            force_folder_index: false,
            hashes: Vec::new(),
        }
    }
}

/// Readable, seekable archive member handle.
pub trait ArchiveRead: Read + Seek + Send {}

impl<T: Read + Seek + Send> ArchiveRead for T {}

/// Generic mount point API (sync, FUSE-friendly). Paths use a leading `/`.
pub trait MountSource: Send + Sync {
    fn list(&self, path: &str) -> Option<ListResult>;

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match self.list(path)? {
            ListResult::Names(names) => Some(ListModeResult::Names(names)),
            ListResult::Infos(map) => Some(ListModeResult::Modes(
                map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
        }
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo>;

    fn open(&self, file_info: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>>;

    fn read(&self, file_info: &FileInfo, size: usize, offset: u64) -> io::Result<Vec<u8>> {
        let mut file = self.open(file_info, 0)?;
        file.seek(io::SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size];
        let n = read_exact_or_short(&mut file, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn versions(&self, path: &str) -> u32 {
        if self.exists(path) {
            1
        } else {
            0
        }
    }

    fn statfs(&self) -> StatFs {
        StatFs {
            bsize: 512,
            namemax: 255,
        }
    }

    fn is_immutable(&self) -> bool;

    fn list_xattr(&self, _file_info: &FileInfo) -> Vec<String> {
        Vec::new()
    }

    fn get_xattr(&self, _file_info: &FileInfo, _key: &str) -> Option<Vec<u8>> {
        None
    }

    fn exists(&self, path: &str) -> bool {
        self.lookup(path, 0).is_some()
    }

    fn is_dir(&self, path: &str) -> bool {
        self.lookup(path, 0)
            .map(|fi| fi.mode & S_IFMT == S_IFDIR)
            .unwrap_or(false)
    }

    /// Close FDs / join pools. Prefer also implementing `Drop`.
    fn close(&mut self) {}
}

fn read_exact_or_short(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Root directory `FileInfo` for `/`.
pub fn create_root_file_info() -> FileInfo {
    FileInfo {
        size: 0,
        mtime: 0.0,
        mode: S_IFDIR | 0o777,
        linkname: String::new(),
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        userdata: vec![UserData::Tar(SQLiteIndexedTarUserData {
            offset: 0,
            offsetheader: Some(0),
            istar: false,
            issparse: false,
            isgenerated: true,
            recursiondepth: 0,
        })],
    }
}

/// Normalize archive path like Python `SQLiteIndex.normpath`.
pub fn normpath(path: &str) -> String {
    let with_slash = format!("/{}", path.trim_start_matches('/'));
    let collapsed = collapse_path(&with_slash);
    if collapsed.is_empty() {
        "/".into()
    } else {
        collapsed
    }
}

/// Query path normalization (Python `_query_normpath`).
pub fn query_normpath(path: &str) -> String {
    let input = if path.starts_with("../") {
        path.to_string()
    } else {
        format!("/{}", path.trim_start_matches('/'))
    };
    let collapsed = collapse_path(&input);
    if collapsed.is_empty() {
        "/".into()
    } else if collapsed.starts_with('/') {
        collapsed
    } else {
        format!("/{collapsed}")
    }
}

fn collapse_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        "/".into()
    } else {
        format!("/{}", parts.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_basics() {
        assert_eq!(normpath("foo"), "/foo");
        assert_eq!(normpath("/foo/"), "/foo");
        assert_eq!(normpath("/foo/./bar"), "/foo/bar");
        assert_eq!(normpath("/"), "/");
        assert_eq!(normpath(""), "/");
    }
}
