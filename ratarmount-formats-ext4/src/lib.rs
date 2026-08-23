//! EXT2/3/4 filesystem image mount source.
//!
//! # Status
//!
//! Python uses the `ext4` package (`python-ext4`) for random-access reads.
//! This crate prefers the pure-Rust [`ext4_view`] crate for in-process
//! list / lookup / open of regular files and directories (no loop mount).
//!
//! `ext4_view::Ext4` is not `Send`/`Sync` (internal `Rc`), so like the FAT
//! backend we reopen the image per operation. That is still far cheaper than
//! a full-tree materialize for random access.
//!
//! When `ext4-view` cannot load a **path** image (corrupt, unsupported feature
//! set, or other incompatibilities), we fall back to materializing the tree with
//! `debugfs -R 'rdump / OUT'` (e2fsprogs) into a temp dir served by
//! [`FolderMountSource`].
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested EXT members can be opened without `/tmp` when the outer archive yields
//! a seekable stream and **ext4-view** can load the image:
//! [`Ext4MountSource::open_from_reader`] (and
//! [`Ext4MountSource::open_from_reader_with_offset`]) validate the superblock
//! magic, retain a mutex-shared `Read + Seek` body, and reopen ext4-view per
//! operation. No `NamedTempFile` spool on the success path; the image is **not**
//! fully copied into a second buffer by this method (the parent may already hold
//! a `Cursor` or stencil).
//!
//! **Residual:** if pure load fails for a stream open, `open_from_reader*`
//! returns a clear [`Ext4Error`] and does **not** invoke debugfs (which needs a
//! host path and writes under `/tmp`). Factory / AutoMount should then temp-spool
//! the member and call path [`Ext4MountSource::open`] (which may use the
//! debugfs materialize fallback). Wire nested detection via
//! [`looks_like_ext4_reader`] (or name `*.ext2`/`*.ext3`/`*.ext4`).
//!
//! ## Partitioned images
//!
//! Use [`Ext4MountSource::open_with_offset`] /
//! [`Ext4MountSource::open_from_reader_with_offset`] with the byte offset of the
//! filesystem partition. Offset is supported on the pure path via a custom
//! [`ext4_view::Ext4Read`] wrapper. The debugfs fallback only runs for path
//! opens with `offset == 0` (partition must be extracted first for materialize).
//!
//! Superblock detection ([`looks_like_ext4`] / [`looks_like_ext4_at`] /
//! [`looks_like_ext4_reader`] / [`looks_like_ext4_reader_at`]) remains
//! independent of the reader backend (magic `0xEF53` at offset+1080).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use ext4_view::{Ext4, Ext4Read, FileType, Metadata};
use ratarmount_compositing::FolderMountSource;
use ratarmount_core::{CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData};
use tempfile::TempDir;
use thiserror::Error;

pub const BACKEND_NAME: &str = "Ext4MountSource";

#[derive(Debug, Error)]
pub enum Ext4Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Ext4Error>;

/// Linux EXT superblock magic (little-endian) at offset 1024 + 0x38.
const EXT_MAGIC: u16 = 0xEF53;
const SUPERBLOCK_OFFSET: u64 = 1024;
const MAGIC_OFFSET_IN_SB: u64 = 0x38;

/// Object-safe `Read + Seek + Send` for the shared nested backend.
trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

/// File-backed reader with an optional partition byte offset.
struct OffsetReader {
    file: File,
    offset: u64,
}

impl Ext4Read for OffsetReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let pos = self
            .offset
            .checked_add(start_byte)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        self.file.seek(SeekFrom::Start(pos))?;
        self.file.read_exact(dst)?;
        Ok(())
    }
}

/// Shared stream reader with optional partition byte offset (nested no-tmp).
struct SharedOffsetReader {
    shared: Arc<Mutex<Box<dyn SeekRead>>>,
    offset: u64,
}

impl Ext4Read for SharedOffsetReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let pos = self
            .offset
            .checked_add(start_byte)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| io::Error::other("shared EXT4 reader poisoned"))?;
        guard.seek(SeekFrom::Start(pos))?;
        guard.read_exact(dst)?;
        Ok(())
    }
}

/// Pure path: reopen image per call (ext4-view is !Send/!Sync).
/// Pure shared: nested stream, same reopen pattern, no `/tmp`.
/// Materialized: full-tree extract via debugfs when pure path load fails.
enum Backend {
    Pure {
        path: PathBuf,
        partition_offset: u64,
    },
    /// Nested / stream open: mutex-shared `Read + Seek` (no temp spool).
    PureShared {
        shared: Arc<Mutex<Box<dyn SeekRead>>>,
        partition_offset: u64,
        /// Diagnostic label (nested member name / virtual path).
        #[allow(dead_code)]
        archive_label: PathBuf,
    },
    Materialized {
        inner: FolderMountSource,
        _extract: TempDir,
    },
}

pub struct Ext4MountSource {
    backend: Backend,
}

impl Ext4MountSource {
    /// Open an EXT image at partition offset 0.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_offset(path, 0)
    }

    /// Open an EXT image; `partition_offset` is the byte start of the FS
    /// (useful for whole-disk images with a partition table).
    pub fn open_with_offset(path: impl AsRef<Path>, partition_offset: u64) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_ext4_at(path, partition_offset) {
            return Err(Ext4Error::Msg(format!(
                "{} is not an EXT2/3/4 image (superblock magic 0xEF53 not found at offset {})",
                path.display(),
                partition_offset.saturating_add(SUPERBLOCK_OFFSET + MAGIC_OFFSET_IN_SB)
            )));
        }

        match try_open_pure(path, partition_offset) {
            Ok(_fs) => {
                // Validate load, then drop; reopen per op (Ext4 is !Send/!Sync).
                log::debug!(
                    "EXT4: pure ext4-view backend for {} (offset={partition_offset})",
                    path.display()
                );
                Ok(Self {
                    backend: Backend::Pure {
                        path: path.to_path_buf(),
                        partition_offset,
                    },
                })
            }
            Err(pure_err) => {
                if partition_offset != 0 {
                    return Err(Ext4Error::Msg(format!(
                        "failed to open EXT image {} at offset {partition_offset} with \
                         in-process reader ({pure_err}); debugfs fallback requires offset 0 \
                         (extract the partition first, or fix the offset)",
                        path.display()
                    )));
                }
                log::warn!(
                    "EXT4: pure reader failed for {} ({pure_err}); trying debugfs rdump",
                    path.display()
                );
                let backend = open_debugfs_materialized(path)?;
                Ok(Self { backend })
            }
        }
    }

    /// Open an EXT image from any `Read + Seek` source without `/tmp`.
    ///
    /// For nested AutoMount / in-memory / remote images. The reader is retained
    /// under a mutex; each list/lookup/open reopens ext4-view over that shared
    /// body. The full image is **not** copied into a second buffer by this
    /// method (the parent may already hold a `Cursor` or stencil).
    ///
    /// `archive_label` is used for diagnostics only (may be a nested member name).
    ///
    /// # Residual / factory
    ///
    /// Pure load only — no debugfs materialize (that needs a host path and
    /// writes under `/tmp`). On pure failure, returns [`Ext4Error`] so
    /// AutoMount can temp-spool and call path [`Self::open`]. Wire from
    /// `open_nested_reader_fn` via [`looks_like_ext4_reader`] or name
    /// (`*.ext2` / `*.ext3` / `*.ext4`).
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::open_from_reader_with_offset(reader, archive_label, 0)
    }

    /// Like [`Self::open_from_reader`], with a filesystem partition byte offset.
    ///
    /// Success path never writes `/tmp`. Pure-load failure is a hard error
    /// (debugfs residual is path-only).
    pub fn open_from_reader_with_offset<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
        partition_offset: u64,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_label = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_ext4_reader_at(&mut reader, partition_offset) {
            return Err(Ext4Error::Msg(format!(
                "{} is not an EXT2/3/4 image (superblock magic 0xEF53 not found at offset {})",
                archive_label.display(),
                partition_offset.saturating_add(SUPERBLOCK_OFFSET + MAGIC_OFFSET_IN_SB)
            )));
        }
        reader.seek(SeekFrom::Start(0))?;

        let shared: Arc<Mutex<Box<dyn SeekRead>>> =
            Arc::new(Mutex::new(Box::new(reader) as Box<dyn SeekRead>));

        match try_open_pure_shared(Arc::clone(&shared), partition_offset) {
            Ok(_fs) => {
                log::debug!(
                    "EXT4: pure ext4-view shared backend for {} (offset={partition_offset})",
                    archive_label.display()
                );
                Ok(Self {
                    backend: Backend::PureShared {
                        shared,
                        partition_offset,
                        archive_label,
                    },
                })
            }
            Err(pure_err) => Err(Ext4Error::Msg(format!(
                "failed to open EXT image {} at offset {partition_offset} with in-process \
                 ext4-view ({pure_err}); open_from_reader does not fall back to debugfs \
                 (requires a host path and /tmp). Nested AutoMount may temp-spool and use \
                 path open instead.",
                archive_label.display()
            ))),
        }
    }

    /// Which backend is active (`"ext4-view"` or `"debugfs"`).
    pub fn backend_kind(&self) -> &'static str {
        match self.backend {
            Backend::Pure { .. } | Backend::PureShared { .. } => "ext4-view",
            Backend::Materialized { .. } => "debugfs",
        }
    }

    /// Open a fresh `Ext4` for this call (`Ext4` is not `Sync`).
    fn with_fs<R>(&self, f: impl FnOnce(&Ext4) -> Result<R>) -> Result<R> {
        match &self.backend {
            Backend::Pure {
                path,
                partition_offset,
            } => {
                let fs = try_open_pure(path, *partition_offset)?;
                f(&fs)
            }
            Backend::PureShared {
                shared,
                partition_offset,
                ..
            } => {
                let fs = try_open_pure_shared(Arc::clone(shared), *partition_offset)?;
                f(&fs)
            }
            Backend::Materialized { .. } => Err(Ext4Error::Msg(
                "internal: with_fs called on materialized backend".into(),
            )),
        }
    }

    fn find_entry_info(&self, path: &str) -> Option<FileInfo> {
        let abs = abs_path(path);
        self.with_fs(|fs| {
            let meta = fs
                .symlink_metadata(abs.as_str())
                .map_err(|e| Ext4Error::Msg(e.to_string()))?;
            let linkname = if meta.is_symlink() {
                fs.read_link(abs.as_str())
                    .ok()
                    .map(|p| {
                        p.to_str()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|_| format!("{}", p.display()))
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };
            Ok(metadata_to_file_info(&abs, &meta, linkname))
        })
        .ok()
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        let abs = abs_path(path);
        self.with_fs(|fs| {
            let mut map = BTreeMap::new();
            let iter = fs
                .read_dir(abs.as_str())
                .map_err(|e| Ext4Error::Msg(e.to_string()))?;
            for entry in iter {
                let entry = entry.map_err(|e| Ext4Error::Msg(e.to_string()))?;
                let name = entry.file_name();
                let name_str = match name.as_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => format!("{}", name.display()),
                };
                if name_str == "." || name_str == ".." {
                    continue;
                }
                let child_path = if abs == "/" {
                    format!("/{name_str}")
                } else {
                    format!("{abs}/{name_str}")
                };
                let meta = entry
                    .metadata()
                    .map_err(|e| Ext4Error::Msg(e.to_string()))?;
                let linkname = if meta.is_symlink() {
                    fs.read_link(child_path.as_str())
                        .ok()
                        .map(|p| {
                            p.to_str()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|_| format!("{}", p.display()))
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                map.insert(
                    name_str,
                    metadata_to_file_info(&child_path, &meta, linkname),
                );
            }
            Ok(map)
        })
        .ok()
    }

    fn list_dirents_pure(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let abs = abs_path(path);
        self.with_fs(|fs| {
            let mut dents = Vec::new();
            let iter = fs
                .read_dir(abs.as_str())
                .map_err(|e| Ext4Error::Msg(e.to_string()))?;
            for entry in iter {
                let entry = entry.map_err(|e| Ext4Error::Msg(e.to_string()))?;
                let name = entry.file_name();
                let name_str = match name.as_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => format!("{}", name.display()),
                };
                if name_str == "." || name_str == ".." {
                    continue;
                }
                let meta = entry
                    .metadata()
                    .map_err(|e| Ext4Error::Msg(e.to_string()))?;
                dents.push(CheapDirent {
                    name: name_str,
                    mode: metadata_mode(&meta),
                    size: metadata_size(&meta),
                });
            }
            Ok(dents)
        })
        .ok()
    }

    fn read_file_pure(&self, path: &str) -> io::Result<Vec<u8>> {
        let abs = abs_path(path);
        self.with_fs(|fs| {
            fs.read(abs.as_str())
                .map_err(|e| Ext4Error::Msg(format!("ext4-view read {abs}: {e}")))
        })
        .map_err(|e| io::Error::other(e.to_string()))
    }
}

impl MountSource for Ext4MountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        match &self.backend {
            Backend::Pure { .. } | Backend::PureShared { .. } => {
                let map = self.list_dir(path)?;
                Some(ListResult::Infos(map))
            }
            Backend::Materialized { inner, .. } => inner.list(path),
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match &self.backend {
            Backend::Pure { .. } | Backend::PureShared { .. } => {
                let map = self.list_dir(path)?;
                Some(ListModeResult::Modes(
                    map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
                ))
            }
            Backend::Materialized { inner, .. } => inner.list_mode(path),
        }
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        match &self.backend {
            Backend::Pure { .. } | Backend::PureShared { .. } => self.list_dirents_pure(path),
            Backend::Materialized { inner, .. } => inner.list_dirents(path),
        }
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        match &self.backend {
            Backend::Pure { .. } | Backend::PureShared { .. } => self.find_entry_info(path),
            Backend::Materialized { inner, .. } => inner.lookup(path, file_version),
        }
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        match &self.backend {
            Backend::Pure { .. } | Backend::PureShared { .. } => {
                if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
                    return Err(io::Error::new(
                        io::ErrorKind::IsADirectory,
                        "is a directory",
                    ));
                }
                if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "cannot open symlink as file",
                    ));
                }
                let path = path_from_userdata(file_info).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing EXT4 path userdata")
                })?;
                // ext4_view::File is !Send; ArchiveRead requires Send, so buffer.
                let data = self.read_file_pure(&path)?;
                Ok(Box::new(Cursor::new(data)))
            }
            Backend::Materialized { inner, .. } => inner.open(file_info, buffering),
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn try_open_pure(path: &Path, partition_offset: u64) -> Result<Ext4> {
    let file = File::open(path)?;
    let reader = OffsetReader {
        file,
        offset: partition_offset,
    };
    Ext4::load(Box::new(reader)).map_err(|e| {
        Ext4Error::Msg(format!(
            "ext4-view load failed for {} (offset={partition_offset}): {e}",
            path.display()
        ))
    })
}

fn try_open_pure_shared(
    shared: Arc<Mutex<Box<dyn SeekRead>>>,
    partition_offset: u64,
) -> Result<Ext4> {
    let reader = SharedOffsetReader {
        shared,
        offset: partition_offset,
    };
    Ext4::load(Box::new(reader)).map_err(|e| {
        Ext4Error::Msg(format!(
            "ext4-view load failed for shared stream (offset={partition_offset}): {e}"
        ))
    })
}

fn open_debugfs_materialized(path: &Path) -> Result<Backend> {
    let debugfs = which_debugfs().ok_or_else(|| {
        Ext4Error::Msg(format!(
            "EXT image {} could not be opened with in-process ext4-view, and `debugfs` \
             was not found on PATH (install e2fsprogs for rdump fallback)",
            path.display()
        ))
    })?;

    let extract = TempDir::with_prefix("ratarmount-ext4.")?;
    let out = extract.path().to_path_buf();
    // debugfs -R 'rdump / OUT' IMAGE
    // Ownership change warnings are non-fatal for unprivileged users.
    let status = Command::new(&debugfs)
        .arg("-R")
        .arg(format!("rdump / {}", out.display()))
        .arg(path)
        .status()
        .map_err(|e| Ext4Error::Msg(format!("debugfs spawn ({}): {e}", debugfs.display())))?;
    if !status.success() {
        // rdump may return non-zero solely due to chown failures; check content.
        if out
            .read_dir()
            .map(|mut d| d.next().is_none())
            .unwrap_or(true)
        {
            return Err(Ext4Error::Msg(format!(
                "debugfs rdump failed for {} (exit {:?}); pure reader was also unavailable",
                path.display(),
                status.code()
            )));
        }
    }

    let inner = FolderMountSource::new(&out).map_err(|e| Ext4Error::Msg(e.to_string()))?;
    Ok(Backend::Materialized {
        inner,
        _extract: extract,
    })
}

fn metadata_mode(meta: &Metadata) -> u32 {
    let type_bits = match meta.file_type() {
        FileType::Directory => ratarmount_core::S_IFDIR,
        FileType::Regular => ratarmount_core::S_IFREG,
        FileType::Symlink => ratarmount_core::S_IFLNK,
        FileType::Fifo => ratarmount_core::S_IFIFO,
        FileType::CharacterDevice => ratarmount_core::S_IFCHR,
        FileType::BlockDevice => ratarmount_core::S_IFBLK,
        FileType::Socket => ratarmount_core::S_IFSOCK,
    };
    type_bits | (u32::from(meta.mode()) & 0o7777)
}

fn metadata_size(meta: &Metadata) -> u64 {
    if meta.is_dir() {
        0
    } else {
        meta.len()
    }
}

fn metadata_to_file_info(path: &str, meta: &Metadata, linkname: String) -> FileInfo {
    FileInfo {
        size: metadata_size(meta),
        // ext4-view Metadata does not expose mtime yet.
        mtime: 0.0,
        mode: metadata_mode(meta),
        linkname,
        uid: meta.uid(),
        gid: meta.gid(),
        userdata: vec![ext4_path_userdata(path)],
    }
}

fn ext4_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("ext4:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("ext4:") => Some(s[5..].to_string()),
        _ => None,
    })
}

/// Normalize to absolute path with a leading `/` (required by ext4-view).
fn abs_path(path: &str) -> String {
    let t = path.trim();
    if t.is_empty() || t == "/" {
        "/".into()
    } else if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
}

/// Detect EXT2/3/4 superblock magic at the standard offset (partition offset 0).
pub fn looks_like_ext4(path: &Path) -> bool {
    looks_like_ext4_at(path, 0)
}

/// Detect EXT superblock magic at `partition_offset + 1024 + 0x38`.
///
/// Also returns true if the path extension is `.ext2` / `.ext3` / `.ext4`
/// (extension fallback preserved for convenience when magic is not yet
/// readable, matching the previous detector behavior).
pub fn looks_like_ext4_at(path: &Path, partition_offset: u64) -> bool {
    if magic_at(path, partition_offset).is_some_and(|m| m == EXT_MAGIC) {
        return true;
    }
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        e.eq_ignore_ascii_case("ext4")
            || e.eq_ignore_ascii_case("ext3")
            || e.eq_ignore_ascii_case("ext2")
    })
}

/// Superblock magic probe for nested streams (does not use filename).
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_ext4_reader<R: Read + Seek>(reader: &mut R) -> bool {
    looks_like_ext4_reader_at(reader, 0)
}

/// Superblock magic at `partition_offset + 1024 + 0x38` on a seekable stream.
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_ext4_reader_at<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> bool {
    magic_at_reader(reader, partition_offset).is_some_and(|m| m == EXT_MAGIC)
}

fn magic_at(path: &Path, partition_offset: u64) -> Option<u16> {
    let mut f = File::open(path).ok()?;
    magic_at_reader(&mut f, partition_offset)
}

fn magic_at_reader<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> Option<u16> {
    let pos = partition_offset
        .checked_add(SUPERBLOCK_OFFSET)?
        .checked_add(MAGIC_OFFSET_IN_SB)?;
    reader.seek(SeekFrom::Start(pos)).ok()?;
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf).ok()?;
    Some(u16::from_le_bytes(buf))
}

fn which_debugfs() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join("debugfs");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    // Common absolute path on Debian/Ubuntu (often not in non-root PATH)
    let p = PathBuf::from("/usr/sbin/debugfs");
    if p.is_file() {
        return Some(p);
    }
    None
}

pub fn open_as_mount_source(path: &Path) -> Result<Arc<dyn MountSource>> {
    Ok(Arc::new(Ext4MountSource::open(path)?) as Arc<dyn MountSource>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn decompress_fixture(name: &str) -> Option<(tempfile::TempDir, PathBuf)> {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let bz2 = PathBuf::from(&root).join("tests").join(name);
        if !bz2.exists() {
            eprintln!("skip: fixture not found: {}", bz2.display());
            return None;
        }
        let dir = tempfile::tempdir().ok()?;
        let img = dir.path().join("x.ext4");
        let status = Command::new("bzip2")
            .args(["-dc"])
            .arg(&bz2)
            .stdout(File::create(&img).ok()?)
            .status()
            .ok()?;
        if !status.success() {
            eprintln!("skip: bzip2 failed for {}", bz2.display());
            return None;
        }
        if !img.exists() || img.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            eprintln!("skip: empty image after decompress");
            return None;
        }
        Some((dir, img))
    }

    fn load_fixture_bytes(name: &str) -> Option<Vec<u8>> {
        let (_dir, img) = decompress_fixture(name)?;
        std::fs::read(&img).ok()
    }

    /// Minimal EXT4 via mke2fs when the Python fixture tree is unavailable.
    fn mke2fs_minimal_bytes() -> Option<Vec<u8>> {
        let mke2fs = which_mke2fs()?;
        let dir = tempfile::tempdir().ok()?;
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(seed.join("foo/fighter")).ok()?;
        std::fs::write(seed.join("foo/fighter/ufo"), b"iriya\n").ok()?;
        let img = dir.path().join("min.ext4");
        // Sparse 1MiB image is enough for a tiny FS with one file.
        {
            let f = File::create(&img).ok()?;
            f.set_len(1024 * 1024).ok()?;
        }
        let status = Command::new(&mke2fs)
            .args(["-t", "ext4", "-F", "-q", "-d"])
            .arg(&seed)
            .arg(&img)
            .status()
            .ok()?;
        if !status.success() {
            eprintln!("skip: mke2fs failed");
            return None;
        }
        std::fs::read(&img).ok()
    }

    fn which_mke2fs() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                let p = dir.join("mke2fs");
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        let p = PathBuf::from("/usr/sbin/mke2fs");
        if p.is_file() {
            return Some(p);
        }
        None
    }

    fn any_ext4_bytes() -> Option<Vec<u8>> {
        load_fixture_bytes("nested-tar-1M.ext4.bz2").or_else(mke2fs_minimal_bytes)
    }

    #[test]
    fn detect_magic_and_extension() {
        // Empty / random file: no magic, no ext extension → false.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope.bin");
        File::create(&p).unwrap().write_all(&[0u8; 2048]).unwrap();
        assert!(!looks_like_ext4(&p));

        // Extension fallback.
        let p2 = dir.path().join("disk.ext4");
        File::create(&p2).unwrap().write_all(&[0u8; 64]).unwrap();
        assert!(looks_like_ext4(&p2));
    }

    #[test]
    fn detect_and_mount_fixture_pure() {
        let Some((_dir, img)) = decompress_fixture("nested-tar-1M.ext4.bz2") else {
            return;
        };
        assert!(looks_like_ext4(&img));
        assert_eq!(
            magic_at(&img, 0),
            Some(EXT_MAGIC),
            "fixture should have real superblock magic"
        );

        let m = Ext4MountSource::open(&img).expect("open ext4");
        assert_eq!(
            m.backend_kind(),
            "ext4-view",
            "fixture should open with pure reader"
        );

        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFREG);

        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");

        let list = m.list("/foo").expect("list /foo");
        match list {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("fighter"),
                    "expected fighter in /foo, got {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            ListResult::Names(names) => {
                assert!(names.iter().any(|n| n == "fighter"));
            }
        }

        let root = m.list("/").expect("list /");
        match root {
            ListResult::Infos(map) => assert!(map.contains_key("foo")),
            ListResult::Names(names) => assert!(names.iter().any(|n| n == "foo")),
        }
    }

    #[test]
    fn open_with_offset_rejects_bad_offset() {
        let Some((_dir, img)) = decompress_fixture("nested-tar-1M.ext4.bz2") else {
            return;
        };
        // Wrong offset: magic not found (rename away from .ext4 extension so
        // extension fallback does not mask a bad partition offset).
        let dir = tempfile::tempdir().unwrap();
        let renamed = dir.path().join("disk.img");
        std::fs::copy(&img, &renamed).unwrap();
        let err = Ext4MountSource::open_with_offset(&renamed, 4096)
            .err()
            .expect("expected open failure at bad offset");
        let msg = err.to_string();
        assert!(
            msg.contains("not an EXT") || msg.contains("failed to open"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn open_with_offset_zero_matches_open() {
        let Some((_dir, img)) = decompress_fixture("nested-tar-1M.ext4.bz2") else {
            return;
        };
        let m = Ext4MountSource::open_with_offset(&img, 0).unwrap();
        assert!(m.lookup("/foo/fighter/ufo", 0).is_some());
    }

    #[test]
    fn looks_like_ext4_at_respects_offset() {
        let Some((_dir, img)) = decompress_fixture("nested-tar-1M.ext4.bz2") else {
            return;
        };
        // Build a padded image: 8192 zero bytes + real FS.
        let dir = tempfile::tempdir().unwrap();
        let padded = dir.path().join("padded.img");
        {
            let mut out = File::create(&padded).unwrap();
            out.write_all(&vec![0u8; 8192]).unwrap();
            let mut src = File::open(&img).unwrap();
            io::copy(&mut src, &mut out).unwrap();
        }
        assert!(!looks_like_ext4_at(&padded, 0));
        assert!(looks_like_ext4_at(&padded, 8192));

        let m = Ext4MountSource::open_with_offset(&padded, 8192).expect("open at offset");
        assert_eq!(m.backend_kind(), "ext4-view");
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo via offset");
        assert_eq!(fi.size, 6);
    }

    #[test]
    fn clear_error_when_not_ext() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.bin");
        File::create(&p)
            .unwrap()
            .write_all(b"not an ext image")
            .unwrap();
        let err = Ext4MountSource::open(&p)
            .err()
            .expect("expected open failure for non-EXT file");
        assert!(err.to_string().contains("not an EXT"), "got: {err}");
    }

    #[test]
    fn looks_like_ext4_reader_magic() {
        let Some(bytes) = any_ext4_bytes() else {
            eprintln!("skip: no EXT4 fixture and mke2fs unavailable");
            return;
        };
        assert!(looks_like_ext4_reader(&mut Cursor::new(&bytes)));
        assert!(!looks_like_ext4_reader(&mut Cursor::new(vec![0u8; 4096])));
        assert!(!looks_like_ext4_reader(&mut Cursor::new(
            b"not ext".to_vec()
        )));
    }

    #[test]
    fn open_from_reader_cursor_list_and_read() {
        // Nested no-tmp path: image bytes via Cursor → open_from_reader (no host file
        // retained by the mount source; pure ext4-view backend only).
        let Some(bytes) = any_ext4_bytes() else {
            eprintln!("skip: no EXT4 fixture and mke2fs unavailable");
            return;
        };
        assert!(looks_like_ext4_reader(&mut Cursor::new(&bytes)));

        let m = Ext4MountSource::open_from_reader(Cursor::new(bytes), "nested.ext4")
            .expect("open_from_reader");
        assert_eq!(
            m.backend_kind(),
            "ext4-view",
            "open_from_reader success path must use pure backend (no debugfs /tmp)"
        );

        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFREG);

        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");

        let list = m.list("/foo").expect("list /foo");
        match list {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("fighter"),
                    "expected fighter in /foo, got {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            ListResult::Names(names) => {
                assert!(names.iter().any(|n| n == "fighter"));
            }
        }
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = Ext4MountSource::open_from_reader(Cursor::new(vec![0u8; 4096]), "fake.img")
            .err()
            .expect("expected open_from_reader failure for non-EXT bytes");
        assert!(
            err.to_string().contains("not an EXT"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn open_from_reader_with_offset_padded() {
        let Some(bytes) = any_ext4_bytes() else {
            eprintln!("skip: no EXT4 fixture and mke2fs unavailable");
            return;
        };
        let mut padded = vec![0u8; 8192];
        padded.extend_from_slice(&bytes);

        assert!(!looks_like_ext4_reader_at(&mut Cursor::new(&padded), 0));
        assert!(looks_like_ext4_reader_at(&mut Cursor::new(&padded), 8192));

        let m = Ext4MountSource::open_from_reader_with_offset(
            Cursor::new(padded),
            "padded-nested.img",
            8192,
        )
        .expect("open_from_reader_with_offset");
        assert_eq!(m.backend_kind(), "ext4-view");
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo via offset");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
    }

    #[test]
    fn open_from_reader_equals_path_when_fixture_present() {
        let Some((_dir, img)) = decompress_fixture("nested-tar-1M.ext4.bz2") else {
            return;
        };
        let bytes = std::fs::read(&img).expect("read fixture");
        let from_path = Ext4MountSource::open(&img).expect("path open");
        let from_reader = Ext4MountSource::open_from_reader(Cursor::new(bytes), "nested.ext4")
            .expect("open_from_reader");
        assert_eq!(from_path.backend_kind(), "ext4-view");
        assert_eq!(from_reader.backend_kind(), "ext4-view");

        let fi_p = from_path.lookup("/foo/fighter/ufo", 0).expect("path ufo");
        let fi_r = from_reader
            .lookup("/foo/fighter/ufo", 0)
            .expect("reader ufo");
        assert_eq!(fi_p.size, fi_r.size);

        let mut sp = String::new();
        from_path
            .open(&fi_p, 0)
            .unwrap()
            .read_to_string(&mut sp)
            .unwrap();
        let mut sr = String::new();
        from_reader
            .open(&fi_r, 0)
            .unwrap()
            .read_to_string(&mut sr)
            .unwrap();
        assert_eq!(sp, sr);
        assert_eq!(sp, "iriya\n");
    }

    /// Regression: cheap readdirplus sizes.
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let Some(bytes) = any_ext4_bytes() else {
            eprintln!("skip: no EXT4 fixture and mke2fs unavailable");
            return;
        };
        let src = Ext4MountSource::open_from_reader(Cursor::new(bytes), "dirents.ext4")
            .expect("open_from_reader");
        let dents = src.list_dirents("/foo/fighter").expect("dirents");
        let d = dents.iter().find(|e| e.name == "ufo").expect("ufo dirent");
        let fi = src.lookup("/foo/fighter/ufo", 0).expect("lookup");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, 6);
        assert_ne!(d.size, 0);
    }
}
