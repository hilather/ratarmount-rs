//! FAT12/16/32 filesystem image mount source.
//!
//! Python uses `pyfatfs` for random access. This crate uses the pure-Rust [`fatfs`]
//! library for in-process cluster reads (no loop mount / mtools required).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fatfs::{Dir, FileSystem, FsOptions};
use ratarmount_core::{FileInfo, ListModeResult, ListResult, MountSource, UserData};
use thiserror::Error;

pub const BACKEND_NAME: &str = "FATMountSource";

#[derive(Debug, Error)]
pub enum FatError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, FatError>;

/// Read-only file wrapper that satisfies fatfs's `Read + Write + Seek` bound
/// without mutating the image (writes are discarded).
struct RoDisk {
    file: File,
}

impl Read for RoDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}
impl Write for RoDisk {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for RoDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

/// Absolute path stored in FileInfo userdata for reopen.
fn fat_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("fat:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("fat:") => Some(s[4..].to_string()),
        _ => None,
    })
}

/// Normalize to fatfs path without leading `/` (fatfs uses `/` separators internally).
fn fatfs_rel(path: &str) -> String {
    path.trim_matches('/').to_string()
}

fn dos_datetime_to_unix(dt: fatfs::DateTime) -> f64 {
    // Best-effort: fatfs DateTime fields are DOS calendar.
    // Convert via approximate civil date if chrono not available.
    let d = dt.date;
    let t = dt.time;
    // days since 1970-01-01 via simple algorithm (ignoring leap edge cases is OK for mtime).
    let y = d.year as i64;
    let m = d.month as i64;
    let day = d.day as i64;
    // Algorithm from Howard Hinnant (civil_from_days inverse).
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    let days = (era * 146097 + doe as i64 - 719468) as f64;
    days * 86400.0 + f64::from(t.hour) * 3600.0 + f64::from(t.min) * 60.0 + f64::from(t.sec)
}

fn entry_to_file_info(name_path: &str, is_dir: bool, size: u64, mtime: f64) -> FileInfo {
    let mode = if is_dir {
        libc::S_IFDIR | 0o777
    } else {
        libc::S_IFREG | 0o777
    };
    FileInfo {
        size: if is_dir { 0 } else { size },
        mtime,
        mode,
        linkname: String::new(),
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        userdata: vec![fat_path_userdata(name_path)],
    }
}

pub struct FatMountSource {
    archive_path: PathBuf,
}

impl FatMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_fat(path) {
            return Err(FatError::Msg(format!(
                "{} is not a FAT12/16/32 image",
                path.display()
            )));
        }
        // Validate we can open with fatfs (FileSystem is !Sync, so we reopen per op).
        {
            let file = File::open(path)?;
            let _fs = FileSystem::new(RoDisk { file }, FsOptions::new()).map_err(|e| {
                FatError::Msg(format!("failed to open FAT image {}: {e}", path.display()))
            })?;
        }
        Ok(Self {
            archive_path: path.to_path_buf(),
        })
    }

    /// Open a fresh FileSystem for this call (fatfs FileSystem is not Sync).
    fn with_fs<R>(&self, f: impl FnOnce(&FileSystem<RoDisk>) -> Result<R>) -> Result<R> {
        let file = File::open(&self.archive_path)?;
        let fs = FileSystem::new(RoDisk { file }, FsOptions::new()).map_err(|e| {
            FatError::Msg(format!(
                "failed to open FAT image {}: {e}",
                self.archive_path.display()
            ))
        })?;
        f(&fs)
    }

    /// Look up a path under root; returns (is_dir, size, mtime).
    fn resolve(root: &Dir<'_, RoDisk>, rel: &str) -> Result<(bool, u64, f64)> {
        if rel.is_empty() {
            return Ok((true, 0, 0.0));
        }
        let (parent, name) = match rel.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", rel),
        };
        let dir = if parent.is_empty() {
            root.clone()
        } else {
            root.open_dir(parent).map_err(FatError::Io)?
        };
        for e in dir.iter() {
            let e = e.map_err(FatError::Io)?;
            let n = e.file_name();
            if n == "." || n == ".." {
                continue;
            }
            if e.attributes().contains(fatfs::FileAttributes::VOLUME_ID) {
                continue;
            }
            if n.eq_ignore_ascii_case(name) {
                let is_dir = e.is_dir();
                let size = if is_dir { 0 } else { e.len() };
                let mtime = dos_datetime_to_unix(e.modified());
                return Ok((is_dir, size, mtime));
            }
        }
        Err(FatError::Msg("not found".into()))
    }

    fn find_entry_info(&self, path: &str) -> Option<FileInfo> {
        let rel = fatfs_rel(path);
        self.with_fs(|fs| {
            let root = fs.root_dir();
            let (is_dir, size, mtime) = Self::resolve(&root, &rel)?;
            Ok(entry_to_file_info(path, is_dir, size, mtime))
        })
        .ok()
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        let rel = fatfs_rel(path);
        self.with_fs(|fs| {
            let root = fs.root_dir();
            let dir = if rel.is_empty() {
                root
            } else {
                root.open_dir(&rel).map_err(FatError::Io)?
            };
            let mut map = BTreeMap::new();
            for e in dir.iter() {
                let e = e.map_err(FatError::Io)?;
                let name = e.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                if e.attributes().contains(fatfs::FileAttributes::VOLUME_ID) {
                    continue;
                }
                let child_path = if path == "/" || path.is_empty() {
                    format!("/{name}")
                } else {
                    format!("{}/{}", path.trim_end_matches('/'), name)
                };
                let is_dir = e.is_dir();
                let size = if is_dir { 0 } else { e.len() };
                let mtime = dos_datetime_to_unix(e.modified());
                map.insert(name, entry_to_file_info(&child_path, is_dir, size, mtime));
            }
            Ok(map)
        })
        .ok()
    }

    fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        let rel = fatfs_rel(path);
        if rel.is_empty() {
            return Err(io::Error::new(io::ErrorKind::IsADirectory, "root"));
        }
        self.with_fs(|fs| {
            let mut file = fs.root_dir().open_file(&rel).map_err(FatError::Io)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).map_err(FatError::Io)?;
            Ok(buf)
        })
        .map_err(|e| io::Error::other(e.to_string()))
    }
}

impl MountSource for FatMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let map = self.list_dir(path)?;
        Some(ListResult::Infos(map))
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let map = self.list_dir(path)?;
        Some(ListModeResult::Modes(
            map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
        ))
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        self.find_entry_info(path)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if file_info.mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let path = path_from_userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing FAT path userdata")
        })?;
        let data = self.read_file(&path)?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

/// Detect FAT via boot-sector 0x55AA signature + "FAT" type string or fat* extension.
pub fn looks_like_fat(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut boot = [0u8; 512];
        if f.read_exact(&mut boot).is_ok() && boot[510] == 0x55 && boot[511] == 0xAA {
            // FAT12/16 type string at 54, FAT32 at 82
            let s16 = &boot[54..62];
            let s32 = &boot[82..90];
            if s16.starts_with(b"FAT") || s32.starts_with(b"FAT") {
                return true;
            }
            // Fallback BPB heuristic (jump + valid sector size)
            let bps = u16::from_le_bytes([boot[11], boot[12]]);
            let spc = boot[13];
            if (boot[0] == 0xEB || boot[0] == 0xE9) && bps >= 512 && spc > 0 && boot[16] >= 1 {
                return true;
            }
        }
    }
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        let e = e.to_ascii_lowercase();
        e == "fat" || e == "fat12" || e == "fat16" || e == "fat32" || e == "vfat"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn fat12_fixture_list_and_read() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let bz2 = PathBuf::from(&root).join("tests/folder-symlink.fat12.bz2");
        if !bz2.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("x.fat");
        let status = Command::new("bzip2")
            .args(["-dc"])
            .arg(&bz2)
            .stdout(File::create(&img).unwrap())
            .status()
            .unwrap();
        if !status.success() {
            return;
        }
        assert!(looks_like_fat(&img));
        let m = FatMountSource::open(&img).unwrap();
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");

        let list = m.list("/foo").expect("list foo");
        match list {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("fighter")
                        || map.keys().any(|k| k.eq_ignore_ascii_case("fighter"))
                );
            }
            _ => panic!("expected infos"),
        }
    }
}
