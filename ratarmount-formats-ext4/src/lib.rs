//! EXT2/3/4 filesystem image mount source (MVP).
//!
//! Python uses the `ext4` package for random access. This MVP:
//! 1. Detects EXT superblock magic `0xEF53` at offset 1080.
//! 2. Uses `debugfs -R 'rdump / OUT'` (e2fsprogs) to extract into a temp dir.
//! 3. Serves via [`FolderMountSource`].
//!
//! A pure in-process reader can replace this later.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ratarmount_compositing::FolderMountSource;
use ratarmount_core::MountSource;
use tempfile::TempDir;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Ext4Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Ext4Error>;

/// Linux EXT superblock magic (little-endian) at offset 1024 + 0x38.
const EXT_MAGIC: u16 = 0xEF53;
const SUPERBLOCK_OFFSET: u64 = 1024;
const MAGIC_OFFSET_IN_SB: u64 = 0x38;

pub struct Ext4MountSource {
    inner: FolderMountSource,
    _extract: TempDir,
    #[allow(dead_code)]
    archive_path: PathBuf,
}

impl Ext4MountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_ext4(path) {
            return Err(Ext4Error::Msg(format!(
                "{} is not an EXT2/3/4 image",
                path.display()
            )));
        }
        if which_debugfs().is_none() {
            return Err(Ext4Error::Msg(
                "EXT image detected but `debugfs` not found on PATH; install e2fsprogs \
                 (true in-process reader is not implemented yet)"
                    .into(),
            ));
        }

        let extract = TempDir::with_prefix("ratarmount-ext4.")?;
        let out = extract.path().to_path_buf();
        // debugfs -R 'rdump / OUT' IMAGE
        // Ownership change warnings are non-fatal for unprivileged users.
        let status = Command::new("debugfs")
            .arg("-R")
            .arg(format!("rdump / {}", out.display()))
            .arg(path)
            .status()
            .map_err(|e| Ext4Error::Msg(format!("debugfs spawn: {e}")))?;
        if !status.success() {
            // rdump may return non-zero solely due to chown failures; check content.
            if out
                .read_dir()
                .map(|mut d| d.next().is_none())
                .unwrap_or(true)
            {
                return Err(Ext4Error::Msg(format!(
                    "debugfs rdump failed for {}",
                    path.display()
                )));
            }
        }

        let inner = FolderMountSource::new(&out).map_err(|e| Ext4Error::Msg(e.to_string()))?;
        Ok(Self {
            inner,
            _extract: extract,
            archive_path: path.to_path_buf(),
        })
    }
}

impl MountSource for Ext4MountSource {
    fn list(&self, path: &str) -> Option<ratarmount_core::ListResult> {
        self.inner.list(path)
    }

    fn list_mode(&self, path: &str) -> Option<ratarmount_core::ListModeResult> {
        self.inner.list_mode(path)
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<ratarmount_core::FileInfo> {
        self.inner.lookup(path, file_version)
    }

    fn open(
        &self,
        file_info: &ratarmount_core::FileInfo,
        buffering: i32,
    ) -> std::io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(file_info, buffering)
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

/// Detect EXT2/3/4 superblock magic at the standard offset.
pub fn looks_like_ext4(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    if f.seek(SeekFrom::Start(SUPERBLOCK_OFFSET + MAGIC_OFFSET_IN_SB))
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 2];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    u16::from_le_bytes(buf) == EXT_MAGIC
        || path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
            e.eq_ignore_ascii_case("ext4")
                || e.eq_ignore_ascii_case("ext3")
                || e.eq_ignore_ascii_case("ext2")
        })
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
    use std::io::Read;
    use std::process::Command;

    #[test]
    fn detect_and_mount_fixture() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let bz2 = PathBuf::from(&root).join("tests/nested-tar-1M.ext4.bz2");
        if !bz2.exists() {
            return;
        }
        if which_debugfs().is_none() {
            eprintln!("skip: no debugfs");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("x.ext4");
        let status = Command::new("bunzip2")
            .args(["-k", "-c"])
            .arg(&bz2)
            .stdout(std::fs::File::create(&img).unwrap())
            .status()
            .unwrap();
        // Alternative: bzip2 -dc
        if !status.success() {
            let _ = Command::new("bzip2")
                .args(["-dc"])
                .arg(&bz2)
                .stdout(std::fs::File::create(&img).unwrap())
                .status();
        }
        if !img.exists() || img.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            eprintln!("skip: could not decompress fixture");
            return;
        }
        assert!(looks_like_ext4(&img));
        let m = Ext4MountSource::open(&img).unwrap();
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
    }
}
