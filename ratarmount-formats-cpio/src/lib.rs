//! CPIO "newc" (070701) archive support — Phase 9 subset of libarchive formats.
//! `backendName=LibarchiveMountSource` is used when we want broader interop later;
//! for pure newc we use `CpioMountSource`.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
    SQLiteIndexedTarUserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "CpioMountSource";
const NEWC_MAGIC: &[u8; 6] = b"070701";
const CRC_MAGIC: &[u8; 6] = b"070702";

#[derive(Debug, Error)]
pub enum CpioError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, CpioError>;

pub struct CpioMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl CpioMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let default_index = default_index_path(&archive_path);
        let index_path = index_path.unwrap_or(&default_index);

        if !recreate && index_path.exists() {
            let meta_ok = std::fs::metadata(index_path)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
            if meta_ok {
                match Self::open_existing(&archive_path, index_path, options) {
                    Ok(s) => return Ok(s),
                    Err(e) => eprintln!("info: could not load cpio index ({e}); rebuilding"),
                }
            }
        }
        Self::create_index(&archive_path, index_path, options, product_version)
    }

    fn open_existing(archive_path: &Path, index_path: &Path, options: &OpenOptions) -> Result<Self> {
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            index,
            options: options.clone(),
        })
    }

    fn create_index(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let mut file = File::open(archive_path)?;
        let index = SqliteIndex::create_writable(Some(index_path))?;
        index.begin_write()?;
        let mut generated = std::collections::BTreeSet::new();

        loop {
            let header_offset = file.stream_position()?;
            let mut magic = [0u8; 6];
            match file.read(&mut magic)? {
                0 => break,
                n if n < 6 => return Err(CpioError::Msg("truncated cpio magic".into())),
                _ => {}
            }
            if &magic != NEWC_MAGIC && &magic != CRC_MAGIC {
                return Err(CpioError::Msg(format!("unsupported cpio magic {magic:?}")));
            }

            // newc header after magic: 13 * 8 hex fields = 104 bytes
            let mut fields = [0u8; 104];
            file.read_exact(&mut fields)?;
            let ino = hex_u32(&fields[0..8])?;
            let mode = hex_u32(&fields[8..16])?;
            let uid = hex_u32(&fields[16..24])?;
            let gid = hex_u32(&fields[24..32])?;
            let _nlink = hex_u32(&fields[32..40])?;
            let mtime = hex_u32(&fields[40..48])? as f64;
            let filesize = hex_u32(&fields[48..56])? as u64;
            let _devmajor = hex_u32(&fields[56..64])?;
            let _devminor = hex_u32(&fields[64..72])?;
            let _rdevmajor = hex_u32(&fields[72..80])?;
            let _rdevminor = hex_u32(&fields[80..88])?;
            let namesize = hex_u32(&fields[88..96])? as usize;
            let _check = hex_u32(&fields[96..104])?;
            let _ = ino;

            let mut name_buf = vec![0u8; namesize];
            file.read_exact(&mut name_buf)?;
            // name includes trailing NUL
            while name_buf.last() == Some(&0) {
                name_buf.pop();
            }
            let name = String::from_utf8_lossy(&name_buf).into_owned();

            // header+name padded to 4-byte boundary from start of header
            // header is 110 bytes (6+104), + namesize, pad so (110+namesize) % 4 == 0
            let header_and_name = 110 + namesize;
            let name_pad = (4 - (header_and_name % 4)) % 4;
            if name_pad > 0 {
                file.seek(SeekFrom::Current(name_pad as i64))?;
            }

            let data_offset = file.stream_position()?;

            if name == "TRAILER!!!" {
                break;
            }

            let is_dir = mode & libc::S_IFMT == libc::S_IFDIR;
            let is_lnk = mode & libc::S_IFMT == libc::S_IFLNK;
            let mut linkname = String::new();
            if is_lnk && filesize > 0 && filesize < 4096 {
                let mut buf = vec![0u8; filesize as usize];
                file.read_exact(&mut buf)?;
                linkname = String::from_utf8_lossy(&buf).into_owned();
                // already consumed data; still need pad
                let data_pad = (4 - (filesize as usize % 4)) % 4;
                if data_pad > 0 {
                    file.seek(SeekFrom::Current(data_pad as i64))?;
                }
            } else {
                // skip file data + pad
                let data_pad = (4 - (filesize as usize % 4)) % 4;
                file.seek(SeekFrom::Current((filesize + data_pad as u64) as i64))?;
            }

            if name.is_empty() || name == "." {
                continue;
            }

            let full = normpath(&name);
            let (path, base) = match full.rsplit_once('/') {
                Some(("", n)) => (String::new(), n.to_string()),
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (String::new(), full.clone()),
            };
            ensure_parents(&index, &path, &mut generated, mtime)?;

            let ifmt = if is_dir {
                libc::S_IFDIR
            } else if is_lnk {
                libc::S_IFLNK
            } else {
                libc::S_IFREG
            };
            let fmode = (mode & 0o7777) | ifmt as u32;

            index.insert_file(
                &path,
                &base,
                header_offset as i64,
                data_offset as i64,
                if is_dir { 0 } else { filesize as i64 },
                mtime,
                fmode as i64,
                0,
                &linkname,
                uid as i64,
                gid as i64,
                false,
                false,
                false,
                0,
            )?;
        }

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats(&index, archive_path)?;
        index.commit_write()?;
        index.finalize_build()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        drop(index);
        let index = SqliteIndex::open_read_only(index_path)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            index,
            options: options.clone(),
        })
    }
}

impl MountSource for CpioMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index
            .list(path)
            .ok()
            .flatten()
            .map(ListResult::Infos)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        self.index
            .list_mode(path)
            .ok()
            .flatten()
            .map(ListModeResult::Modes)
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.index.lookup(path, file_version).ok().flatten()
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
        let ud = userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing cpio userdata")
        })?;
        let file = File::open(&self.archive_path)?;
        Ok(Box::new(StenciledFile::new(
            file,
            vec![(ud.offset, file_info.size)],
        )))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

pub fn looks_like_cpio_newc(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 6];
        if f.read(&mut magic).ok() == Some(6) && (&magic == NEWC_MAGIC || &magic == CRC_MAGIC) {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("cpio"))
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

fn hex_u32(bytes: &[u8]) -> Result<u32> {
    let s = std::str::from_utf8(bytes).map_err(|e| CpioError::Msg(e.to_string()))?;
    u32::from_str_radix(s, 16).map_err(|e| CpioError::Msg(e.to_string()))
}

fn ensure_parents(
    index: &SqliteIndex,
    path: &str,
    generated: &mut std::collections::BTreeSet<String>,
    mtime: f64,
) -> Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    let mut cur = String::new();
    for (i, part) in parts.iter().enumerate() {
        let parent = if i == 0 {
            String::new()
        } else {
            cur.clone()
        };
        cur = if parent.is_empty() {
            format!("/{part}")
        } else {
            format!("{parent}/{part}")
        };
        if generated.contains(&cur) {
            continue;
        }
        generated.insert(cur.clone());
        let mode = (libc::S_IFDIR | 0o755) as i64;
        index.insert_file(
            &parent, part, 0, 0, 0, mtime, mode, 0, "", 0, 0, false, false, true, 0,
        )?;
    }
    Ok(())
}

fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    let json = format!(
        "{{\"st_size\":{},\"st_mtime\":{},\"st_mtime_ns\":{}}}",
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec()
    );
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_newc_cpio() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/single-file.newc.cpio");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("c.index.sqlite");
        let m = CpioMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m.lookup("/bar", 0).expect("bar");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }
}
