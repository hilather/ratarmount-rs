//! SquashFS mount source (MVP).
//!
//! Full random-access SquashFS (Python `PySquashfsImage`) is deferred. This MVP:
//! 1. Detects SquashFS superblock magic (`hsqs` / `sqsh`) including AppImage offset.
//! 2. When `unsquashfs` is on `PATH`, extracts once into a temp dir and serves via
//!    [`FolderMountSource`] (same pattern as Python materialize for unsupported paths).
//!
//! True in-process block maps are a follow-up (crate such as `backhand` or pure port).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ratarmount_compositing::FolderMountSource;
use ratarmount_core::MountSource;
use tempfile::TempDir;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SquashFsError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, SquashFsError>;

const MAGIC_LE: &[u8; 4] = b"hsqs";
const MAGIC_BE: &[u8; 4] = b"sqsh";

/// SquashFS opened by materializing with `unsquashfs` into a kept temp dir.
pub struct SquashFsMountSource {
    inner: FolderMountSource,
    /// Keep extract tree alive for the mount lifetime.
    _extract: TempDir,
    #[allow(dead_code)]
    archive_path: PathBuf,
}

impl SquashFsMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let offset = find_squashfs_offset(path)?.ok_or_else(|| {
            SquashFsError::Msg(format!("{} is not a SquashFS image", path.display()))
        })?;

        if which_unsquashfs().is_none() {
            return Err(SquashFsError::Msg(
                "SquashFS detected but `unsquashfs` not found on PATH; install squashfs-tools \
                 (true in-process reader is not implemented yet)"
                    .into(),
            ));
        }

        let extract = TempDir::with_prefix("ratarmount-squashfs.")?;
        let out = extract.path().to_path_buf();
        // unsquashfs -f -d OUT [-o OFFSET] IMAGE
        let mut cmd = Command::new("unsquashfs");
        cmd.arg("-f").arg("-d").arg(&out);
        if offset > 0 {
            cmd.arg("-o").arg(offset.to_string());
        }
        cmd.arg(path);
        let status = cmd
            .status()
            .map_err(|e| SquashFsError::Msg(format!("unsquashfs spawn: {e}")))?;
        if !status.success() {
            return Err(SquashFsError::Msg(format!(
                "unsquashfs failed for {} (offset={offset})",
                path.display()
            )));
        }

        // unsquashfs may create OUT/ or OUT/squashfs-root depending on version/flags.
        let root = if out.join("squashfs-root").is_dir() {
            out.join("squashfs-root")
        } else {
            out.clone()
        };
        // If -d OUT worked, contents are directly in OUT.
        let serve = if root.read_dir()?.next().is_some() {
            root
        } else {
            out.clone()
        };

        let inner = FolderMountSource::new(&serve)
            .map_err(|e| SquashFsError::Msg(e.to_string()))?;
        Ok(Self {
            inner,
            _extract: extract,
            archive_path: path.to_path_buf(),
        })
    }
}

impl MountSource for SquashFsMountSource {
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

/// Detect SquashFS; returns superblock offset if found (0..1 MiB scan for AppImage).
pub fn find_squashfs_offset(path: &Path) -> Result<Option<u64>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 4];
    // Check offset 0 first.
    f.read_exact(&mut buf)?;
    if &buf == MAGIC_LE || &buf == MAGIC_BE {
        return Ok(Some(0));
    }
    // Scan first 1 MiB at 4K strides (AppImage payload).
    const MAX: u64 = 1024 * 1024;
    const STRIDE: u64 = 4096;
    let mut off = STRIDE;
    while off < MAX {
        f.seek(SeekFrom::Start(off))?;
        if f.read(&mut buf)? < 4 {
            break;
        }
        if &buf == MAGIC_LE || &buf == MAGIC_BE {
            return Ok(Some(off));
        }
        off += STRIDE;
    }
    Ok(None)
}

pub fn looks_like_squashfs(path: &Path) -> bool {
    find_squashfs_offset(path)
        .ok()
        .flatten()
        .is_some()
}

fn which_unsquashfs() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join("unsquashfs");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Open as Arc dyn MountSource for factory convenience.
pub fn open_as_mount_source(path: &Path) -> Result<Arc<dyn MountSource>> {
    Ok(Arc::new(SquashFsMountSource::open(path)?) as Arc<dyn MountSource>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_and_mount_fixture() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/folder-symlink.no-compression.squashfs");
        if !path.exists() {
            return;
        }
        assert!(looks_like_squashfs(&path));
        if which_unsquashfs().is_none() {
            eprintln!("skip: no unsquashfs");
            return;
        }
        let m = SquashFsMountSource::open(&path).unwrap();
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        use std::io::Read;
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
    }
}
