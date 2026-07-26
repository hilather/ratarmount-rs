//! ZIP archive mount source (`backendName=ZipMountSource`).
//!
//! Hot path avoids holding a process-wide `ZipArchive` lock and fully decompressing
//! on every open: **Stored** members use `StenciledFile` random access; **Deflate**
//! members are decoded once per open into a `Cursor` (no global mutex).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratarmount_compress::SharedArchiveFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;
use zip::CompressionMethod;
use zip::ZipArchive;

/// Exact metadata string for Python interop.
pub const BACKEND_NAME: &str = "ZipMountSource";

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

#[derive(Debug, Error)]
pub enum ZipError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, ZipError>;

#[derive(Clone, Debug)]
struct ZipMemberMeta {
    #[allow(dead_code)]
    name: String,
    data_start: u64,
    compressed_size: u64,
    method: u16,
}

/// ZIP backed by SQLite index for metadata; content open uses direct archive I/O.
pub struct ZipMountSource {
    #[allow(dead_code)]
    archive_path: PathBuf,
    /// Shared archive fd (region views for Stored; clone for Deflate).
    archive_file: Arc<SharedArchiveFile>,
    raw_file: File,
    index: SqliteIndex,
    /// local header offset → member layout for open
    members: HashMap<u64, ZipMemberMeta>,
    /// Decompressed member cache (header_offset → bytes). Avoids re-inflate on random cat.
    inflate_cache: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl ZipMountSource {
    /// `index_path`: `Some(path)` for on-disk index, `None` for in-memory (`:memory:`).
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
            Some(
                index_path
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| default_index_path(&archive_path)),
            )
        };

        if let Some(ref ip) = index_path_buf {
            if !recreate && ip.exists() {
                let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
                if meta_ok {
                    match Self::open_existing(&archive_path, ip, options) {
                        Ok(s) => return Ok(s),
                        Err(e) => eprintln!("info: could not load zip index ({e}); rebuilding"),
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
        let file = File::open(archive_path)?;
        let mut archive = ZipArchive::new(file.try_clone()?)?;
        let members = member_meta_map(&mut archive)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            archive_file: Arc::new(SharedArchiveFile::new(file.try_clone()?)),
            raw_file: file,
            index,
            members,
            inflate_cache: Mutex::new(HashMap::new()),
            options: options.clone(),
        })
    }

    fn create_index(
        archive_path: &Path,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let file = File::open(archive_path)?;
        let mut archive = ZipArchive::new(file)?;
        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut members = HashMap::new();
        let mut generated_dirs: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();

        for i in 0..archive.len() {
            let zf = archive.by_index(i)?;
            let name = zf.name().to_string();
            let header_offset = zf.header_start();
            let data_start = zf.data_start();
            let size = zf.size();
            let compressed_size = zf.compressed_size();
            let method = match zf.compression() {
                CompressionMethod::Stored => METHOD_STORED,
                CompressionMethod::Deflated => METHOD_DEFLATE,
                other => {
                    // Encode as high bit set + raw id when possible.
                    let _ = other;
                    0xffff
                }
            };
            let is_dir = zf.is_dir() || name.ends_with('/');
            let mtime = zf
                .last_modified()
                .map(|dt| {
                    msdos_to_unix(
                        dt.year(),
                        dt.month(),
                        dt.day(),
                        dt.hour(),
                        dt.minute(),
                        dt.second(),
                    )
                })
                .unwrap_or(0.0);

            let unix_mode = zf.unix_mode().unwrap_or(if is_dir { 0o755 } else { 0o644 });
            let is_symlink = (unix_mode & libc::S_IFMT) == libc::S_IFLNK;
            drop(zf);

            let mut linkname = String::new();
            if is_symlink {
                if let Ok(mut zf) = archive.by_index(i) {
                    let mut buf = String::new();
                    if zf.read_to_string(&mut buf).is_ok() {
                        linkname = buf;
                    }
                }
            }

            let mode = if is_dir {
                (unix_mode & 0o7777) | libc::S_IFDIR
            } else if is_symlink {
                (unix_mode & 0o7777) | libc::S_IFLNK
            } else {
                (unix_mode & 0o7777) | libc::S_IFREG
            };

            let full = name.trim_end_matches('/');
            if full.is_empty() {
                continue;
            }
            let full_path = normpath(full);
            let (path, base) = match full_path.rsplit_once('/') {
                Some(("", n)) => (String::new(), n.to_string()),
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (String::new(), full_path.clone()),
            };

            ensure_parent_dirs(&index, &path, &mut generated_dirs, mtime)?;

            // offset = data_start; type = compression method
            index.insert_file(
                &path,
                &base,
                header_offset as i64,
                data_start as i64,
                if is_dir { 0 } else { size as i64 },
                mtime,
                mode as i64,
                method as i64,
                &linkname,
                0,
                0,
                false,
                false,
                false,
                0,
            )?;
            members.insert(
                header_offset,
                ZipMemberMeta {
                    name: name.clone(),
                    data_start,
                    compressed_size,
                    method,
                },
            );
        }

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats(&index, archive_path)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        let index = index.into_read_only()?;
        let raw_file = File::open(archive_path)?;

        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            archive_file: Arc::new(SharedArchiveFile::new(raw_file.try_clone()?)),
            raw_file,
            index,
            members,
            inflate_cache: Mutex::new(HashMap::new()),
            options: options.clone(),
        })
    }
}

impl MountSource for ZipMountSource {
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
            return Ok(Box::new(io::Cursor::new(Vec::new())));
        }
        let header = userdata(file_info)
            .and_then(|u| u.offsetheader)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing zip header offset")
            })?;

        let meta = self
            .members
            .get(&header)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "zip member meta not found"))?;

        // Prefer data_start from index userdata.offset when present (new indexes).
        let data_start = userdata(file_info)
            .map(|u| u.offset)
            .filter(|&o| o > 0)
            .unwrap_or(meta.data_start);

        match meta.method {
            METHOD_STORED => Ok(Box::new(
                self.archive_file.region(data_start, file_info.size),
            )),
            METHOD_DEFLATE => {
                {
                    let cache = self.inflate_cache.lock().expect("zip cache");
                    if let Some(bytes) = cache.get(&header) {
                        return Ok(Box::new(ArcBytes::new(Arc::clone(bytes))));
                    }
                }
                let mut file = self.raw_file.try_clone()?;
                file.seek(SeekFrom::Start(data_start))?;
                let limited = file.take(meta.compressed_size);
                let mut dec = flate2::read::DeflateDecoder::new(limited);
                let mut data = Vec::with_capacity(file_info.size as usize);
                dec.read_to_end(&mut data)
                    .map_err(|e| io::Error::other(format!("zip deflate: {e}")))?;
                if data.len() as u64 > file_info.size {
                    data.truncate(file_info.size as usize);
                }
                let arc = Arc::new(data);
                {
                    let mut cache = self.inflate_cache.lock().expect("zip cache");
                    if cache.len() > 256 {
                        cache.clear();
                    }
                    cache.insert(header, Arc::clone(&arc));
                }
                Ok(Box::new(ArcBytes::new(arc)))
            }
            _ => {
                let file = self.raw_file.try_clone()?;
                let mut archive = ZipArchive::new(file).map_err(io::Error::other)?;
                let mut zf = archive
                    .by_name(&meta.name)
                    .map_err(|e| io::Error::other(format!("zip open: {e}")))?;
                let mut data = Vec::with_capacity(zf.size() as usize);
                zf.read_to_end(&mut data)?;
                Ok(Box::new(io::Cursor::new(data)))
            }
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

/// Zero-copy view of cached inflated ZIP member bytes.
struct ArcBytes {
    data: Arc<Vec<u8>>,
    pos: u64,
}

impl ArcBytes {
    fn new(data: Arc<Vec<u8>>) -> Self {
        Self { data, pos: 0 }
    }
}

impl Read for ArcBytes {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.data.as_slice();
        if self.pos as usize >= data.len() {
            return Ok(0);
        }
        let start = self.pos as usize;
        let n = (data.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&data[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ArcBytes {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.data.len() as i64;
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => len + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

fn member_meta_map(archive: &mut ZipArchive<File>) -> Result<HashMap<u64, ZipMemberMeta>> {
    let mut members = HashMap::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let method = match file.compression() {
            CompressionMethod::Stored => METHOD_STORED,
            CompressionMethod::Deflated => METHOD_DEFLATE,
            _ => 0xffff,
        };
        members.insert(
            file.header_start(),
            ZipMemberMeta {
                name: file.name().to_string(),
                data_start: file.data_start(),
                compressed_size: file.compressed_size(),
                method,
            },
        );
    }
    Ok(members)
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

/// True if path looks like a ZIP archive.
pub fn looks_like_zip(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 4];
        if std::io::Read::read(&mut f, &mut magic).ok() == Some(4)
            && magic[0] == b'P'
            && magic[1] == b'K'
        {
            return true;
        }
    }
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        e.eq_ignore_ascii_case("zip")
            || e.eq_ignore_ascii_case("jar")
            || e.eq_ignore_ascii_case("war")
    })
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

fn ensure_parent_dirs(
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
        let parent = if i == 0 { String::new() } else { cur.clone() };
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

fn msdos_to_unix(year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Approximate via chrono-less conversion: use libc mktime
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = year as i32 - 1900;
        tm.tm_mon = month as i32 - 1;
        tm.tm_mday = day as i32;
        tm.tm_hour = hour as i32;
        tm.tm_min = min as i32;
        tm.tm_sec = sec as i32;
        tm.tm_isdst = -1;
        let t = libc::mktime(&mut tm);
        if t < 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        } else {
            t as f64
        }
    }
}
