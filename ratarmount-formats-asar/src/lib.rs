//! Electron ASAR MountSource (`backendName=ASARMountSource`).
//!
//! Format: pickled JSON header + concatenated file payloads. Members open via
//! absolute data offsets (stencil), matching Python `ASARMountSource`.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
};
use ratarmount_index::{FileRow, IndexError, SqliteIndex};
use serde_json::Value;
use thiserror::Error;

pub const BACKEND_NAME: &str = "ASARMountSource";

#[derive(Debug, Error)]
pub enum AsarError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, AsarError>;

/// (json_start, json_size, data_start)
pub fn find_asar_header(file: &mut File) -> Result<(u64, u64, u64)> {
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 16];
    file.read_exact(&mut magic)?;
    let size_of_pickled_size = u32::from_le_bytes(magic[0..4].try_into().unwrap());
    let size_of_pickled_pickled_pickled_header =
        u32::from_le_bytes(magic[4..8].try_into().unwrap());
    let size_of_pickled_pickled_header = u32::from_le_bytes(magic[8..12].try_into().unwrap());
    let size_of_pickled_header = u32::from_le_bytes(magic[12..16].try_into().unwrap());

    if size_of_pickled_size != 4 {
        return Err(AsarError::Msg(
            "First magic bytes quadruplet does not match ASAR".into(),
        ));
    }
    if size_of_pickled_pickled_pickled_header != size_of_pickled_pickled_header + 4 {
        return Err(AsarError::Msg(
            "Second magic bytes quadruplet does not match ASAR".into(),
        ));
    }
    let padding = (4 - (size_of_pickled_header % 4)) % 4;
    if size_of_pickled_pickled_header != size_of_pickled_header + padding + 4 {
        return Err(AsarError::Msg(
            "Third magic bytes quadruplet does not match ASAR".into(),
        ));
    }
    let header_start = 16u64;
    let header_size = u64::from(size_of_pickled_header);
    let data_offset = header_start + header_size + u64::from(padding);
    Ok((header_start, header_size, data_offset))
}

pub fn looks_like_asar(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    find_asar_header(&mut f).is_ok()
        || path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("asar"))
}

pub struct AsarMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl AsarMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let index_path_buf: Option<PathBuf> = if options.index_in_memory {
            None
        } else {
            Some(index_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
                let mut s = archive_path.as_os_str().to_os_string();
                s.push(".index.sqlite");
                PathBuf::from(s)
            }))
        };

        if let Some(ref ip) = index_path_buf {
            if !recreate && ip.exists() {
                let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
                if meta_ok {
                    if let Ok(s) = Self::open_existing(&archive_path, ip, options) {
                        return Ok(s);
                    }
                }
            }
        }
        Self::create_index(
            &archive_path,
            index_path_buf.as_deref(),
            options,
            product_version,
        )
    }

    fn open_existing(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
    ) -> Result<Self> {
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
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let _ = options;
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let mut file = File::open(archive_path)?;
        let (header_start, header_size, data_offset) = find_asar_header(&mut file)?;
        file.seek(SeekFrom::Start(header_start))?;
        let mut header_bytes = vec![0u8; header_size as usize];
        file.read_exact(&mut header_bytes)?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AsarError::Msg(format!("ASAR JSON header: {e}")))?;

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;

        let mut batch = Vec::new();
        // BFS/DFS stack of (full_path, entry)
        let mut stack: Vec<(String, Value)> = vec![("/".into(), header)];
        while let Some((full_path, entry)) = stack.pop() {
            if let Some(row) = entry_to_row(&full_path, &entry, data_offset) {
                batch.push(row);
            }
            if let Some(files) = entry.get("files").and_then(|v| v.as_object()) {
                for (name, nested) in files {
                    let child = if full_path == "/" {
                        format!("/{name}")
                    } else {
                        format!("{full_path}/{name}")
                    };
                    stack.push((child, nested.clone()));
                }
            }
            if batch.len() > 1000 {
                index.insert_files_batch(&batch)?;
                batch.clear();
            }
        }
        if !batch.is_empty() {
            index.insert_files_batch(&batch)?;
        }

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        index.commit_write()?;
        println!(
            "Creating offset dictionary for {} took {:.2}s",
            archive_path.display(),
            t0.elapsed().as_secs_f64()
        );

        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            index: index.into_read_only()?,
            options: options.clone(),
        })
    }
}

fn entry_to_row(full_path: &str, entry: &Value, data_offset: u64) -> Option<FileRow> {
    let is_file = entry.get("offset").is_some() && entry.get("size").is_some();
    let is_dir = entry.get("files").is_some();
    if !is_file && !is_dir {
        return None;
    }
    // Root "/" as directory
    let full = if full_path == "/" {
        "/".to_string()
    } else {
        normpath(full_path)
    };
    let (path, name) = if full == "/" {
        // synthetic root — skip empty name root row if needed
        (String::new(), String::new())
    } else {
        match full.rsplit_once('/') {
            Some(("", n)) => (String::new(), n.to_string()),
            Some((p, n)) => (p.to_string(), n.to_string()),
            None => (String::new(), full.clone()),
        }
    };
    if name.is_empty() && full != "/" {
        return None;
    }
    // Skip indexing bare root (Python still adds it but FUSE uses synthetic root)
    if name.is_empty() {
        return None;
    }

    let mode = if is_dir {
        (libc::S_IFDIR | 0o777) as i64
    } else {
        let mut m = (libc::S_IFREG | 0o777) as i64;
        if entry
            .get("executable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            m |= 0o111;
        }
        m
    };
    let size = if is_file {
        entry
            .get("size")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0) as i64
    } else {
        0
    };
    let offset = if is_file {
        let off: u64 = entry
            .get("offset")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0);
        (data_offset + off) as i64
    } else {
        0
    };

    Some(FileRow::new(
        path, name, 0, offset, size, 0.0, mode, 0, "", 0, 0, false, false, false, 0,
    ))
}

impl MountSource for AsarMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index.list(path).ok().flatten().map(ListResult::Infos)
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
        if file_info.size == 0 {
            return Ok(Box::new(std::io::Cursor::new(Vec::new())));
        }
        let offset = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Tar(t) => Some(t.offset),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("missing ASAR offset userdata"))?;
        let file = File::open(&self.archive_path)?;
        let stencil = StenciledFile::new(file, vec![(offset, file_info.size)]);
        Ok(Box::new(stencil))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

// Ensure FileRow userdata path works: index stores offset in data offset column
// which becomes Tar userdata.offset on lookup — already how other stencil formats work.

#[cfg(test)]
mod tests {
    use super::*;

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn nested_tar_asar() {
        let path = py_fixture("nested-tar.asar");
        if !path.exists() {
            return;
        }
        assert!(looks_like_asar(&path));
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let m = AsarMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
    }

    #[test]
    fn empty_asar() {
        let path = py_fixture("empty.asar");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let m = AsarMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        // empty root is fine
        let _ = m.list("/");
    }
}
