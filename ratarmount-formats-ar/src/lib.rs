//! Unix `ar` archive format (`backendName=ARMountSource`).
//!
//! Path-based open and [`ArMountSource::open_from_reader`] (shared `Read + Seek`)
//! both stencil member ranges for random access — nested AutoMount without temp spool
//! once the factory sniffs `!<arch>\n`.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratarmount_compress::{SeekRead, StenciledFile};
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "ARMountSource";
const MAGIC: &[u8; 8] = b"!<arch>\n";
const HEADER_SIZE: usize = 60;

#[derive(Debug, Error)]
pub enum ArError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, ArError>;

/// Mutex-backed `Read + Seek` for concurrent stencil opens (Cursor / nested / remote).
struct SharedSeekReader {
    inner: Mutex<Box<dyn SeekRead>>,
}

impl SharedSeekReader {
    fn new<R: SeekRead + 'static>(reader: R) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Box::new(reader)),
        })
    }

    fn open_reader(self: &Arc<Self>) -> PositionedSeekReader {
        PositionedSeekReader {
            shared: Arc::clone(self),
            pos: 0,
        }
    }
}

/// Independent logical cursor over a [`SharedSeekReader`].
struct PositionedSeekReader {
    shared: Arc<SharedSeekReader>,
    pos: u64,
}

impl Read for PositionedSeekReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .shared
            .inner
            .lock()
            .map_err(|_| io::Error::other("shared AR reader poisoned"))?;
        guard.seek(SeekFrom::Start(self.pos))?;
        let n = guard.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for PositionedSeekReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.pos as i64 + o,
            SeekFrom::End(o) => {
                let mut guard = self
                    .shared
                    .inner
                    .lock()
                    .map_err(|_| io::Error::other("shared AR reader poisoned"))?;
                let end = guard.seek(SeekFrom::End(0))? as i64;
                end + o
            }
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

/// Where AR bytes live for member open.
enum ArBackend {
    /// On-disk archive: open a fresh [`File`] per member.
    Path(PathBuf),
    /// Any `Read + Seek` shared under a mutex (nested / in-memory / remote).
    Shared(Arc<SharedSeekReader>),
}

pub struct ArMountSource {
    /// Host path or virtual label (URL / nested name).
    #[allow(dead_code)]
    archive_path: PathBuf,
    backend: ArBackend,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl ArMountSource {
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
                        Err(e) => eprintln!("info: could not load ar index ({e}); rebuilding"),
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

    /// Index and open an AR archive from any `Read + Seek` source.
    ///
    /// Intended for nested AutoMount / in-memory archives: no on-disk archive path is
    /// required. `archive_label` is used for logs and index metadata (may be a nested
    /// member name). The reader is retained under a mutex for concurrent stencil opens.
    ///
    /// `index_path`: `Some(path)` for on-disk index, `None` for `:memory:` (also when
    /// `options.index_in_memory` is set).
    pub fn open_from_reader<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let index_path_buf: Option<PathBuf> = if options.index_in_memory {
            None
        } else {
            index_path.map(|p| p.to_path_buf())
        };

        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let mut reader = reader;
        let size = reader.seek(SeekFrom::End(0)).unwrap_or(0);
        reader.seek(SeekFrom::Start(0))?;

        let index = SqliteIndex::create_writable_for_open(index_path_buf.as_deref(), options)?;
        index.begin_write()?;
        parse_ar_into_index(&mut reader, &index)?;
        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats_for_label(&index, &archive_path, size)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        reader.seek(SeekFrom::Start(0))?;
        let index = index.into_read_only()?;
        Ok(Self {
            archive_path,
            backend: ArBackend::Shared(SharedSeekReader::new(reader)),
            index,
            options: options.clone(),
        })
    }

    /// Open AR using an imported durable nested index (skip cold file-table rebuild).
    pub fn open_from_reader_with_durable<R>(
        mut reader: R,
        archive_label: impl AsRef<Path>,
        blob: &ratarmount_index::DurableNestedBlob,
        options: OpenOptions,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        use ratarmount_index::NESTED_FORMAT_AR;
        if blob.format != NESTED_FORMAT_AR {
            return Err(ArError::Msg(format!(
                "durable nested blob format {} is not ar",
                blob.format
            )));
        }
        let archive_path = archive_label.as_ref().to_path_buf();
        reader.seek(SeekFrom::Start(0))?;
        let index = SqliteIndex::create_compact_from_nested_blob(blob)?;
        eprintln!(
            "nested durable index: imported AR file table for {} ({} rows)",
            archive_path.display(),
            index.file_count().unwrap_or(0)
        );
        Ok(Self {
            archive_path,
            backend: ArBackend::Shared(SharedSeekReader::new(reader)),
            index,
            options,
        })
    }

    /// Export compact nested durable blob.
    pub fn export_nested_durable(
        &self,
        fingerprint: ratarmount_index::NestedBodyFingerprint,
    ) -> Result<Vec<u8>> {
        use ratarmount_index::NESTED_FORMAT_AR;
        self.index
            .export_nested_blob(NESTED_FORMAT_AR, fingerprint, vec![])
            .map_err(Into::into)
    }

    pub fn index_is_compact_only(&self) -> bool {
        self.index.is_compact_only()
    }

    fn open_existing(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
    ) -> Result<Self> {
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        // Reject sibling indexes for a replaced archive (size/mtime/edge hash).
        // Missing tarstats still Ok (legacy indexes).
        index.check_tarstats_matches_archive(archive_path)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            backend: ArBackend::Path(archive_path.to_path_buf()),
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
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let mut file = File::open(archive_path)?;
        let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
        file.seek(SeekFrom::Start(0))?;

        let index = SqliteIndex::create_writable_for_open(index_path, options)?;
        index.begin_write()?;
        parse_ar_into_index(&mut file, &index)?;
        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats_for_label(&index, archive_path, size)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        let index = index.into_read_only()?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            backend: ArBackend::Path(archive_path.to_path_buf()),
            index,
            options: options.clone(),
        })
    }
}

/// Parse AR members from a seekable stream into the writable index.
fn parse_ar_into_index<R: Read + Seek>(reader: &mut R, index: &SqliteIndex) -> Result<()> {
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(ArError::Msg(format!("invalid AR magic: {magic:?}")));
    }

    let mut header = [0u8; HEADER_SIZE];
    loop {
        let header_offset = reader.stream_position()?;
        match reader.read(&mut header)? {
            0 => break,
            n if n < HEADER_SIZE => {
                return Err(ArError::Msg("truncated AR header".into()));
            }
            _ => {}
        }
        if &header[58..60] != b"`\n" {
            return Err(ArError::Msg(format!(
                "invalid AR header end: {:?}",
                &header[58..60]
            )));
        }

        let name_raw = &header[0..16];
        let name = String::from_utf8_lossy(name_raw)
            .trim_end_matches([' ', '\0', '/'])
            .to_string();
        let mtime = parse_dec(&header[16..28]).unwrap_or(0) as f64;
        let uid = parse_dec(&header[28..34]).unwrap_or(0);
        let gid = parse_dec(&header[34..40]).unwrap_or(0);
        let mode_bits = parse_oct(&header[40..48]).unwrap_or(0o644);
        let size = parse_dec(&header[48..58]).unwrap_or(0);
        let data_offset = reader.stream_position()?;

        // Skip special GNU/BSD tables for index of regular files only
        let is_special = name.is_empty() || name == "/" || name == "//" || name.starts_with("#1/");

        if !is_special && !name.is_empty() {
            let full = normpath(&name);
            let (path, base) = split_name(&full);
            let mode = (mode_bits & 0o7777) | ratarmount_core::S_IFREG;
            index.insert_file(
                &path,
                &base,
                header_offset as i64,
                data_offset as i64,
                size as i64,
                mtime,
                mode as i64,
                0,
                "",
                uid as i64,
                gid as i64,
                false,
                false,
                false,
                0,
            )?;
        }

        // Advance past data + even padding
        let mut skip = size;
        if size % 2 == 1 {
            skip += 1;
        }
        reader.seek(SeekFrom::Current(skip as i64))?;
    }
    Ok(())
}

impl MountSource for ArMountSource {
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
        let ud = userdata(file_info)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing AR userdata"))?;
        let regions = vec![(ud.offset, file_info.size)];
        match &self.backend {
            ArBackend::Path(path) => {
                let file = File::open(path)?;
                Ok(Box::new(StenciledFile::new(file, regions)))
            }
            ArBackend::Shared(shared) => {
                let reader = shared.open_reader();
                Ok(Box::new(StenciledFile::new(reader, regions)))
            }
        }
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

pub fn looks_like_ar(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 8];
        if f.read(&mut magic).ok() == Some(8) && &magic == MAGIC {
            return true;
        }
    }
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        e.eq_ignore_ascii_case("ar") || e.eq_ignore_ascii_case("a") || e.eq_ignore_ascii_case("deb")
    })
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

fn parse_dec(bytes: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if s.is_empty() {
        return Some(0);
    }
    s.parse().ok()
}

fn parse_oct(bytes: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if s.is_empty() {
        return Some(0o644);
    }
    u32::from_str_radix(s, 8).ok()
}

fn split_name(full: &str) -> (String, String) {
    match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.to_string()),
    }
}

/// Store tarstats from path metadata + edge hashes when available; otherwise synthetic size-only.
///
/// Real on-disk archives use the shared helper so warm reopen fails closed after in-place
/// replace (size/mtime + first/last 512 SHA-256). Nested / virtual labels get size-only.
fn store_stats_for_label(index: &SqliteIndex, path: &Path, size: u64) -> Result<()> {
    if path.is_file() && index.store_tarstats_for_path(path).is_ok() {
        return Ok(());
    }
    let json = format!("{{\"st_size\":{size},\"st_mtime\":0,\"st_mtime_ns\":0}}");
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Minimal SVR4/GNU `ar` with one regular member (name ends with `/`).
    fn synthetic_ar(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        let mut hdr = [b' '; HEADER_SIZE];
        let name_field = format!("{name}/");
        let nb = name_field.as_bytes();
        assert!(nb.len() <= 16, "name too long for short AR header");
        hdr[..nb.len()].copy_from_slice(nb);
        hdr[16] = b'0'; // mtime
        hdr[28] = b'0'; // uid
        hdr[34] = b'0'; // gid
        let mode = b"100644";
        hdr[40..40 + mode.len()].copy_from_slice(mode);
        let size_s = payload.len().to_string();
        hdr[48..48 + size_s.len()].copy_from_slice(size_s.as_bytes());
        hdr[58..60].copy_from_slice(b"`\n");
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn open_from_reader_list_and_random_read() {
        let payload = b"hello world!";
        let bytes = synthetic_ar("hello.txt", payload);
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let ar = ArMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("memory://synthetic.a"),
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader");

        let root = ar.list("/").expect("list root");
        match root {
            ListResult::Infos(map) => {
                assert!(map.contains_key("hello.txt"), "keys: {:?}", map.keys());
            }
            other => panic!("unexpected list: {other:?}"),
        }

        let fi = ar.lookup("/hello.txt", 0).expect("lookup");
        assert_eq!(fi.size, payload.len() as u64);

        let mut r = ar.open(&fi, 0).unwrap();
        // Random access: seek mid-member then read rest.
        r.seek(SeekFrom::Start(6)).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"world!");

        r.seek(SeekFrom::Start(0)).unwrap();
        let mut full = Vec::new();
        r.read_to_end(&mut full).unwrap();
        assert_eq!(full, payload);
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let err = ArMountSource::open_from_reader(
            Cursor::new(b"not-an-ar!!!!"),
            Path::new("memory://bad.a"),
            None,
            &opts,
            "0.1.0",
        );
        assert!(err.is_err());
    }

    #[test]
    fn open_single_file_ar() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/single-file.ar");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("a.index.sqlite");
        let ar =
            ArMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true).unwrap();
        let fi = ar.lookup("/bar", 0).expect("bar");
        assert_eq!(fi.size, 4);
        let mut r = ar.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }

    /// Regression: open_existing rejects when archive size/mtime no longer match tarstats.
    #[test]
    fn warm_index_rejects_when_archive_size_or_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.a");
        std::fs::write(&archive, synthetic_ar("hello.txt", b"ar-v1\n")).unwrap();
        let index = dir.path().join("swap.a.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src =
            ArMountSource::open(&archive, Some(&index), &opts, "test", true).expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "ar-v1\n");
        drop(src);
        assert!(index.exists());

        // Matching archive still opens warm.
        ArMountSource::open_existing(&archive, &index, &opts).expect("warm match must succeed");

        // Replace archive content (size change) while reusing the sibling index path.
        std::fs::write(&archive, synthetic_ar("hello.txt", b"ar-v2-longer\n")).unwrap();

        match ArMountSource::open_existing(&archive, &index, &opts) {
            Ok(_) => panic!("stale index must fail open_existing after archive replace"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("size")
                        || msg.contains("mtime")
                        || msg.contains("mismatch")
                        || msg.contains("fingerprint"),
                    "unexpected error (expected tarstats mismatch): {msg}"
                );
            }
        }
    }

    /// Regression: warm AR open rebuilds when archive content no longer matches tarstats.
    #[test]
    fn warm_index_rebuilds_when_archive_content_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.a");
        std::fs::write(&archive, synthetic_ar("hello.txt", b"ar-v1\n")).unwrap();
        let index = dir.path().join("swap.a.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src =
            ArMountSource::open(&archive, Some(&index), &opts, "test", true).expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "ar-v1\n");
        drop(src);
        assert!(index.exists());

        std::fs::write(&archive, synthetic_ar("hello.txt", b"ar-v2-longer\n")).unwrap();

        // recreate=false: tarstats mismatch must rebuild, not serve stale member rows.
        let src2 = ArMountSource::open(&archive, Some(&index), &opts, "test", false).expect("warm");
        let fi2 = src2.lookup("/hello.txt", 0).expect("lookup v2");
        let mut buf2 = String::new();
        src2.open(&fi2, 0)
            .unwrap()
            .read_to_string(&mut buf2)
            .unwrap();
        assert_eq!(
            buf2, "ar-v2-longer\n",
            "must serve new AR data after tarstats mismatch rebuild"
        );
    }
}
