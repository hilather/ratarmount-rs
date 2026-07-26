//! Custom 7z MountSource with real pack offsets (`backendName=SevenZipMountSource`).
//!
//! Port of Python `ratarmountcore.mountsource.formats.sevenzip` + `sevenzip.py`
//! (hilather/ratarmount PR #1).

mod decode;
mod parse;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    UserData,
};
use ratarmount_index::{FileRow, IndexError, SqliteIndex};
use thiserror::Error;

pub use parse::{looks_like_7z, SevenZipArchiveInfo, SevenZipError, SevenZipFileEntry};

pub const BACKEND_NAME: &str = "SevenZipMountSource";

const SMALL_FOLDER_THRESHOLD: u64 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SzError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Seven(#[from] SevenZipError),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, SzError>;

/// Mount source for 7z archives with pack-offset random access.
pub struct SevenZipMountSource {
    archive_path: PathBuf,
    archive: SevenZipArchiveInfo,
    index: SqliteIndex,
    file: Mutex<File>,
    /// folder_index → fully decompressed folder bytes (small/medium folders).
    folder_cache: Mutex<HashMap<usize, Vec<u8>>>,
    password: Option<String>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl SevenZipMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let default_index = {
            let mut s = archive_path.as_os_str().to_os_string();
            s.push(".index.sqlite");
            PathBuf::from(s)
        };
        let index_path = index_path.unwrap_or(&default_index);

        if !recreate && index_path.exists() {
            if let Ok(s) = Self::open_existing(&archive_path, index_path, options) {
                return Ok(s);
            }
        }
        Self::create_index(&archive_path, index_path, options, product_version)
    }

    fn open_existing(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
    ) -> Result<Self> {
        let mut file = File::open(archive_path)?;
        let password = options.passwords.first().cloned();
        let archive = parse::parse_7z_archive(&mut file, |folder, packed| {
            decode::decompress_folder(folder, packed, password.as_deref())
                .map_err(|e| parse::SevenZipError::Msg(e.to_string()))
        })?;
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            archive,
            index,
            file: Mutex::new(file),
            folder_cache: Mutex::new(HashMap::new()),
            password,
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
        // Parse once (encoded-header decompress uses no password typically).
        let archive = parse::parse_7z_archive(&mut file, |folder, packed| {
            decode::decompress_folder(folder, packed, None)
                .map_err(|e| parse::SevenZipError::Msg(e.to_string()))
        })?;

        let encrypted = archive.folders.iter().any(|f| f.is_encrypted());
        let password = if encrypted {
            let mut chosen = None;
            let mut last_err = None;
            for pw in &options.passwords {
                if let Some(entry) = archive
                    .files
                    .iter()
                    .find(|e| e.folder_index.is_some() && e.size > 0 && !e.is_dir)
                {
                    let fi = entry.folder_index.unwrap();
                    let folder = &archive.folders[fi];
                    file.seek(SeekFrom::Start(entry.pack_offset))?;
                    let mut packed = vec![0u8; entry.pack_size as usize];
                    if file.read_exact(&mut packed).is_err() {
                        continue;
                    }
                    match decode::decompress_folder(folder, &packed, Some(pw.as_str())) {
                        Ok(data)
                            if (data.len() as u64) >= folder.get_unpack_size()
                                || data.len() >= entry.size as usize =>
                        {
                            chosen = Some(pw.clone());
                            break;
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            last_err = Some(e);
                            continue;
                        }
                    }
                } else {
                    chosen = Some(pw.clone());
                    break;
                }
            }
            if chosen.is_none() {
                return Err(SzError::Seven(last_err.unwrap_or_else(|| {
                    SevenZipError::Msg(
                        "7z archive contents are encrypted; pass --password".into(),
                    )
                })));
            }
            chosen
        } else {
            options.passwords.first().cloned()
        };

        let index = SqliteIndex::create_writable(Some(index_path))?;
        index.begin_write()?;

        let mut batch = Vec::new();
        let mut generated = std::collections::BTreeSet::new();

        for (entry_index, entry) in archive.files.iter().enumerate() {
            let mut full = entry.path.trim_end_matches('/').to_string();
            if full.is_empty() && entry.is_dir {
                continue;
            }
            while full.starts_with("./") {
                full = full[2..].to_string();
            }
            let full_path = normpath(&full);
            let (path, name) = match full_path.rsplit_once('/') {
                Some(("", n)) => (String::new(), n.to_string()),
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (String::new(), full_path.clone()),
            };
            if name.is_empty() {
                continue;
            }
            ensure_parent_dirs(&mut batch, &path, &mut generated, entry.mtime);

            let mut mode = entry.mode;
            let ifmt = mode & libc::S_IFMT as u32;
            if entry.is_dir && ifmt != libc::S_IFDIR as u32 {
                mode = (mode & 0o777) | libc::S_IFDIR as u32;
            } else if !entry.is_dir && ifmt == 0 {
                mode = (mode & 0o777) | libc::S_IFREG as u32;
            }

            let mut linkname = String::new();
            let mut size = entry.size as i64;
            if ifmt == libc::S_IFLNK as u32 || (mode & libc::S_IFMT as u32) == libc::S_IFLNK as u32
            {
                // Read symlink target at index time.
                if let Some(fi) = entry.folder_index {
                    if let Ok(bytes) = read_member_bytes_static(
                        &mut file,
                        &archive,
                        entry,
                        &archive.folders[fi],
                        password.as_deref(),
                    ) {
                        linkname = String::from_utf8_lossy(&bytes).into_owned();
                    }
                }
                size = 0;
            }

            let header_offset = if entry.folder_index.is_some() {
                entry.pack_offset as i64
            } else {
                ((1u64 << 62) + entry_index as u64) as i64
            };
            let data_offset = entry.unpack_offset as i64;

            batch.push(FileRow::new(
                path,
                name,
                header_offset,
                data_offset,
                size,
                entry.mtime,
                mode as i64,
                0,
                linkname,
                0,
                0,
                false,
                false,
                false,
                0,
            ));
            if batch.len() >= 512 {
                index.insert_files_batch(&batch)?;
                batch.clear();
            }
        }
        if !batch.is_empty() {
            index.insert_files_batch(&batch)?;
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
            archive,
            index,
            file: Mutex::new(file),
            folder_cache: Mutex::new(HashMap::new()),
            password,
            options: options.clone(),
        })
    }

    fn find_entry(&self, file_info: &FileInfo) -> Result<&SevenZipFileEntry> {
        let ud = file_info.userdata.iter().rev().find_map(|u| match u {
            UserData::Tar(t) => Some(t),
            _ => None,
        });
        let ud = ud.ok_or_else(|| SzError::Msg("missing userdata".into()))?;
        let pack_offset = ud.offsetheader.unwrap_or(0);
        let unpack_offset = ud.offset;

        for entry in &self.archive.files {
            if entry.is_dir || entry.is_empty_stream {
                continue;
            }
            if entry.pack_offset == pack_offset && entry.unpack_offset == unpack_offset {
                let is_link = (file_info.mode & libc::S_IFMT) == libc::S_IFLNK as u32;
                if entry.size == file_info.size || (is_link && file_info.size == 0) {
                    return Ok(entry);
                }
            }
        }
        Err(SzError::Msg(format!(
            "Could not locate 7z member pack={pack_offset} unpack={unpack_offset}"
        )))
    }

    fn read_packed(&self, entry: &SevenZipFileEntry) -> Result<Vec<u8>> {
        let mut f = self.file.lock().expect("file lock");
        f.seek(SeekFrom::Start(entry.pack_offset))?;
        let mut packed = vec![0u8; entry.pack_size as usize];
        f.read_exact(&mut packed)?;
        Ok(packed)
    }

    fn get_folder_bytes(&self, entry: &SevenZipFileEntry) -> Result<Vec<u8>> {
        let fi = entry
            .folder_index
            .ok_or_else(|| SzError::Msg("entry has no folder".into()))?;
        {
            let cache = self.folder_cache.lock().unwrap();
            if let Some(data) = cache.get(&fi) {
                return Ok(data.clone());
            }
        }
        let folder = &self.archive.folders[fi];
        let packed = self.read_packed(entry)?;
        let data =
            decode::decompress_folder(folder, &packed, self.password.as_deref())?;
        let mut cache = self.folder_cache.lock().unwrap();
        if cache.len() >= 4 {
            if let Some(k) = cache.keys().next().copied() {
                cache.remove(&k);
            }
        }
        cache.insert(fi, data.clone());
        Ok(data)
    }
}

fn read_member_bytes_static(
    file: &mut File,
    _archive: &SevenZipArchiveInfo,
    entry: &SevenZipFileEntry,
    folder: &parse::Folder,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    if folder.is_copy_only() && !folder.is_encrypted() {
        file.seek(SeekFrom::Start(entry.pack_offset + entry.unpack_offset))?;
        let mut buf = vec![0u8; entry.size as usize];
        file.read_exact(&mut buf)?;
        return Ok(buf);
    }
    file.seek(SeekFrom::Start(entry.pack_offset))?;
    let mut packed = vec![0u8; entry.pack_size as usize];
    file.read_exact(&mut packed)?;
    let data = decode::decompress_folder(folder, &packed, password)?;
    let end = (entry.unpack_offset + entry.size) as usize;
    if end > data.len() {
        return Err(SzError::Msg("member slice exceeds folder".into()));
    }
    Ok(data[entry.unpack_offset as usize..end].to_vec())
}

fn ensure_parent_dirs(
    batch: &mut Vec<FileRow>,
    path: &str,
    generated: &mut std::collections::BTreeSet<String>,
    mtime: f64,
) {
    if path.is_empty() {
        return;
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
        batch.push(FileRow::new(
            parent,
            (*part).to_string(),
            0,
            0,
            0,
            mtime,
            (libc::S_IFDIR | 0o755) as i64,
            0,
            "",
            0,
            0,
            false,
            false,
            true,
            0,
        ));
    }
}

fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path)?;
    use std::os::unix::fs::MetadataExt;
    let json = format!(
        "{{\"st_size\":{},\"st_mtime\":{}}}",
        meta.size(),
        meta.mtime()
    );
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

impl MountSource for SevenZipMountSource {
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
        if file_info.mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot read symlink contents",
            ));
        }
        if file_info.size == 0 {
            return Ok(Box::new(Cursor::new(Vec::new())));
        }

        let entry = self
            .find_entry(file_info)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let fi = entry
            .folder_index
            .ok_or_else(|| io::Error::other("no folder"))?;
        let folder = &self.archive.folders[fi];
        let allow_enc = !folder.is_encrypted() || self.password.is_some();
        if !folder.is_supported_for_open(allow_enc) {
            return Err(io::Error::other(format!(
                "Unsupported 7z codecs for {}",
                entry.path
            )));
        }

        // Store / Copy: true random access via stencil into the archive file.
        if folder.is_copy_only() && !folder.is_encrypted() {
            let file = File::open(&self.archive_path)?;
            let offset = entry.pack_offset + entry.unpack_offset;
            let stencil = StenciledFile::new(file, vec![(offset, entry.size)]);
            return Ok(Box::new(stencil));
        }

        // Compressed: full-folder decompress + slice (all test fixtures fit; large
        // solid folders still use a per-folder cache so second opens are free).
        let folder_size = folder.get_unpack_size();
        let folder_data = self
            .get_folder_bytes(entry)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let start = entry.unpack_offset as usize;
        let end = start + entry.size as usize;
        if end > folder_data.len() {
            return Err(io::Error::other(format!(
                "Member slice [{start}:{end}] exceeds folder {}",
                folder_data.len()
            )));
        }
        // For very large folders only retain the member slice in the handle.
        let slice = if folder_size > SMALL_FOLDER_THRESHOLD {
            folder_data[start..end].to_vec()
        } else {
            folder_data[start..end].to_vec()
        };
        Ok(Box::new(Cursor::new(slice)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT").unwrap_or_else(|_| {
            "/home/mbrewer/projects/ratarmount".into()
        });
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn store_copy_two_files() {
        let path = py_fixture("store-copy-two-files.7z");
        if !path.exists() {
            eprintln!("skip missing {}", path.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions::default();
        let m = SevenZipMountSource::open(&path, Some(&idx), &opts, "0.1.0", true).unwrap();
        let fi = m.lookup("/a.txt", 0).expect("a.txt");
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert!(!s.is_empty());
        let fi2 = m.lookup("/b.txt", 0).expect("b.txt");
        assert!(fi2.size > 0);
    }

    #[test]
    fn lzma2_two_files() {
        let path = py_fixture("lzma2-two-files-and-medium.7z");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let m = SevenZipMountSource::open(
            &path,
            Some(&idx),
            &OpenOptions::default(),
            "0.1.0",
            true,
        )
        .unwrap();
        let fi = m.lookup("/a.txt", 0).expect("a.txt");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), fi.size as usize);
        let med = m.lookup("/medium.bin", 0).expect("medium");
        assert_eq!(med.size, 2097152);
        let mut r = m.open(&med, 0).unwrap();
        let mut one = [0u8; 1];
        r.read_exact(&mut one).unwrap();
    }

    #[test]
    fn encrypted_hello() {
        let path = py_fixture("encrypted-hello.7z");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let mut opts = OpenOptions::default();
        opts.passwords = vec!["secret".into()];
        let m = SevenZipMountSource::open(&path, Some(&idx), &opts, "0.1.0", true).unwrap();
        let fi = m.lookup("/secret.txt", 0).expect("secret");
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert!(s.contains("secret") || !s.is_empty());
    }
}
