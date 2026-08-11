//! Core types and the `MountSource` trait (mirrors Python `ratarmountcore.mountsource`).

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Seek};
use std::path::PathBuf;

/// Per-backend decompression thread matrix (Python `-P` / `--parallelization`).
///
/// Accepts the same string forms as Python `parse_parallelization`:
/// * `"0"` / `"1"` / `"8"` — default threads for all backends (`0` → CPU count)
/// * `"bzip2:4,gzip:2"` — per-backend overrides; missing default → CPU count
/// * `":1,bzip2:0"` — explicit default (`:N`) plus overrides (`0` → CPU count)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelizationSpec {
    /// Default thread count when a backend is not listed in [`Self::by_backend`].
    pub default: u32,
    /// Backend name → thread count (already resolved; never 0).
    pub by_backend: HashMap<String, u32>,
}

impl Default for ParallelizationSpec {
    fn default() -> Self {
        Self {
            default: 1,
            by_backend: HashMap::new(),
        }
    }
}

impl From<u32> for ParallelizationSpec {
    fn from(n: u32) -> Self {
        Self {
            default: Self::resolve_zero(n),
            by_backend: HashMap::new(),
        }
    }
}

impl ParallelizationSpec {
    /// Build a matrix with only a default thread count (`0` → CPU count).
    pub fn new(default: u32) -> Self {
        Self {
            default: Self::resolve_zero(default),
            by_backend: HashMap::new(),
        }
    }

    /// Available parallelism (at least 1). Used when a value is `0`.
    pub fn cpu_count() -> u32 {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
            .max(1)
    }

    /// Map Python/`0` “use all cores” to a concrete thread count.
    pub fn resolve_zero(n: u32) -> u32 {
        if n == 0 {
            Self::cpu_count()
        } else {
            n
        }
    }

    /// Parse a Python-style parallelization string.
    ///
    /// # Errors
    /// Returns a message when a token is not `digits` or `backend:digits`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self::default());
        }

        // Whole string is a non-negative integer → default only.
        if s.bytes().all(|b| b.is_ascii_digit()) {
            let n: u32 = s
                .parse()
                .map_err(|_| format!("invalid parallelization count: {s}"))?;
            return Ok(Self::new(n));
        }

        let mut by_backend = HashMap::new();
        let mut default: Option<u32> = None;

        for token in s.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let (backend, count_str) = if let Some((b, c)) = token.split_once(':') {
                (b.trim(), c.trim())
            } else {
                return Err(format!(
                    "parallelization entry must be 'N' or 'backend:N', got '{token}'"
                ));
            };
            if count_str.is_empty() || !count_str.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!(
                    "Parallelization must be non-negative number but got {count_str} for {backend}"
                ));
            }
            let n: u32 = count_str.parse().map_err(|_| {
                format!("invalid parallelization count '{count_str}' for {backend}")
            })?;
            let resolved = Self::resolve_zero(n);
            if backend.is_empty() {
                default = Some(resolved);
            } else {
                by_backend.insert(backend.to_ascii_lowercase(), resolved);
            }
        }

        // Python: if '' not in result, default = CPU count.
        Ok(Self {
            default: default.unwrap_or_else(Self::cpu_count),
            by_backend,
        })
    }

    /// Thread count for `backend` (case-insensitive), falling back to [`Self::default`].
    pub fn threads_for(&self, backend: &str) -> u32 {
        let key = backend.to_ascii_lowercase();
        self.by_backend
            .get(&key)
            .copied()
            .unwrap_or(self.default)
            .max(1)
    }

    /// Alias for [`Self::default`] (default backend / empty key).
    pub fn default_threads(&self) -> u32 {
        self.default.max(1)
    }
}

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
    /// When `> 0`, do not keep an on-disk SQLite index if the archive has strictly
    /// fewer than this many indexed members (`files` rows). `0` always allows
    /// creating indexes (harness default). Applies even with an explicit `--index-file`
    /// path (B-119 / upstream #119). In-memory (`:memory:`) is unchanged.
    pub index_minimum_file_count: u64,
    pub recursive: bool,
    pub recursion_depth: Option<i32>,
    pub ignore_zeros: bool,
    pub gnu_incremental: Option<bool>,
    /// Decompression parallelization matrix (Python `-P backend:n` / integer default).
    pub parallelization: ParallelizationSpec,
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
            parallelization: ParallelizationSpec::default(),
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

impl OpenOptions {
    /// Thread count for a compression backend (`bzip2`, `gzip`, `zstd`, …).
    pub fn threads_for(&self, backend: &str) -> u32 {
        self.parallelization.threads_for(backend)
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

    #[test]
    fn parallelization_plain_int() {
        let p = ParallelizationSpec::parse("8").unwrap();
        assert_eq!(p.default, 8);
        assert_eq!(p.threads_for("bzip2"), 8);
        assert_eq!(p.threads_for("gzip"), 8);

        let z = ParallelizationSpec::parse("0").unwrap();
        assert_eq!(z.default, ParallelizationSpec::cpu_count());
        assert!(z.default >= 1);

        let one = ParallelizationSpec::parse("1").unwrap();
        assert_eq!(one.default, 1);
    }

    #[test]
    fn parallelization_backend_matrix() {
        let p = ParallelizationSpec::parse("bzip2:4,gzip:2").unwrap();
        assert_eq!(p.threads_for("bzip2"), 4);
        assert_eq!(p.threads_for("GZIP"), 2); // case-insensitive
                                              // No explicit default → CPU count (Python semantics)
        assert_eq!(p.default, ParallelizationSpec::cpu_count());
        assert_eq!(p.threads_for("xz"), ParallelizationSpec::cpu_count());

        let p2 = ParallelizationSpec::parse(":1,bzip2:0,rapidgzip-gzip:2").unwrap();
        assert_eq!(p2.default, 1);
        assert_eq!(p2.threads_for("bzip2"), ParallelizationSpec::cpu_count());
        assert_eq!(p2.threads_for("rapidgzip-gzip"), 2);
        assert_eq!(p2.threads_for("unknown"), 1);
    }

    #[test]
    fn parallelization_from_u32() {
        let p: ParallelizationSpec = 4u32.into();
        assert_eq!(p.default_threads(), 4);
        let z: ParallelizationSpec = 0u32.into();
        assert_eq!(z.default_threads(), ParallelizationSpec::cpu_count());
    }

    #[test]
    fn parallelization_invalid() {
        assert!(ParallelizationSpec::parse("bzip2").is_err());
        assert!(ParallelizationSpec::parse("bzip2:x").is_err());
        assert!(ParallelizationSpec::parse("gzip:-1").is_err());
    }

    #[test]
    fn open_options_threads_for() {
        let opts = OpenOptions {
            parallelization: ParallelizationSpec::parse("bzip2:3,:2").unwrap(),
            ..OpenOptions::default()
        };
        assert_eq!(opts.threads_for("bzip2"), 3);
        assert_eq!(opts.threads_for("zstd"), 2);
    }
}
