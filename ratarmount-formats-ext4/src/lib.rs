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
//! When `ext4-view` cannot load the image (corrupt, unsupported feature set,
//! or other incompatibilities), we fall back to materializing the tree with
//! `debugfs -R 'rdump / OUT'` (e2fsprogs) into a temp dir served by
//! [`FolderMountSource`].
//!
//! ## Partitioned images
//!
//! Use [`Ext4MountSource::open_with_offset`] with the byte offset of the
//! filesystem partition. Offset is supported on the pure path via a custom
//! [`ext4_view::Ext4Read`] wrapper. The debugfs fallback only runs for
//! `offset == 0` (partition must be extracted first for materialize).
//!
//! Superblock detection ([`looks_like_ext4`] / [`looks_like_ext4_at`]) remains
//! independent of the reader backend (magic `0xEF53` at offset+1080).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ext4_view::{Ext4, Ext4Read, FileType, Metadata};
use ratarmount_compositing::FolderMountSource;
use ratarmount_core::{FileInfo, ListModeResult, ListResult, MountSource, UserData};
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

/// Pure path: reopen image per call (ext4-view is !Send/!Sync).
/// Materialized: full-tree extract via debugfs when pure load fails.
enum Backend {
    Pure {
        path: PathBuf,
        partition_offset: u64,
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

    /// Which backend is active (`"ext4-view"` or `"debugfs"`).
    pub fn backend_kind(&self) -> &'static str {
        match self.backend {
            Backend::Pure { .. } => "ext4-view",
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
            Backend::Pure { .. } => {
                let map = self.list_dir(path)?;
                Some(ListResult::Infos(map))
            }
            Backend::Materialized { inner, .. } => inner.list(path),
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match &self.backend {
            Backend::Pure { .. } => {
                let map = self.list_dir(path)?;
                Some(ListModeResult::Modes(
                    map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
                ))
            }
            Backend::Materialized { inner, .. } => inner.list_mode(path),
        }
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        match &self.backend {
            Backend::Pure { .. } => self.find_entry_info(path),
            Backend::Materialized { inner, .. } => inner.lookup(path, file_version),
        }
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        match &self.backend {
            Backend::Pure { .. } => {
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

fn metadata_to_file_info(path: &str, meta: &Metadata, linkname: String) -> FileInfo {
    let type_bits = match meta.file_type() {
        FileType::Directory => ratarmount_core::S_IFDIR,
        FileType::Regular => ratarmount_core::S_IFREG,
        FileType::Symlink => ratarmount_core::S_IFLNK,
        FileType::Fifo => ratarmount_core::S_IFIFO,
        FileType::CharacterDevice => ratarmount_core::S_IFCHR,
        FileType::BlockDevice => ratarmount_core::S_IFBLK,
        FileType::Socket => ratarmount_core::S_IFSOCK,
    };
    let mode = type_bits | (u32::from(meta.mode()) & 0o7777);
    FileInfo {
        size: if meta.is_dir() { 0 } else { meta.len() },
        // ext4-view Metadata does not expose mtime yet.
        mtime: 0.0,
        mode,
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

fn magic_at(path: &Path, partition_offset: u64) -> Option<u16> {
    let mut f = File::open(path).ok()?;
    let pos = partition_offset
        .checked_add(SUPERBLOCK_OFFSET)?
        .checked_add(MAGIC_OFFSET_IN_SB)?;
    f.seek(SeekFrom::Start(pos)).ok()?;
    let mut buf = [0u8; 2];
    f.read_exact(&mut buf).ok()?;
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
}
