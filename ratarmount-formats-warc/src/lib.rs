//! WARC MountSource with random access via record payload offsets (`backendName=WARCMountSource`).
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Path-based mounts reopen the archive file per member open. Nested / remote /
//! in-memory WARC is opened via [`WarcMountSource::open_from_reader`], which keeps a
//! mutex-shared `Read + Seek` backend and serves payloads as stenciled regions —
//! no host temp spool.

use std::collections::HashMap;
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
use url::Url;

pub const BACKEND_NAME: &str = "WARCMountSource";

#[derive(Debug, Error)]
pub enum WarcError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, WarcError>;

/// Mutex-backed `Read + Seek` for concurrent stencil opens (Cursor / nested stream).
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
            .map_err(|_| io::Error::other("shared warc reader poisoned"))?;
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
                    .map_err(|_| io::Error::other("shared warc reader poisoned"))?;
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

/// Where WARC bytes live for member open / stencil.
enum WarcBackend {
    /// Path-based: reopen [`WarcMountSource::archive_path`] on each open.
    Path,
    /// Shared `Read + Seek` (nested no-tmp / Cursor / remote).
    Shared(Arc<SharedSeekReader>),
}

pub struct WarcMountSource {
    archive_path: PathBuf,
    backend: WarcBackend,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl WarcMountSource {
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
                        Err(e) => eprintln!("info: could not load warc index ({e}); rebuilding"),
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

    /// Index and open a WARC from any `Read + Seek` source.
    ///
    /// For nested AutoMount / in-memory archives without a host path. Content is served
    /// via stenciled regions over a shared reader — no temp spool.
    ///
    /// `archive_label` is used for logs and index metadata (may be a virtual name).
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
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        if !data.starts_with(b"WARC/") {
            return Err(WarcError::Msg(
                "Not a WARC file (missing WARC/ version line)".into(),
            ));
        }

        let index = SqliteIndex::create_writable_for_open(index_path_buf.as_deref(), options)?;
        index.begin_write()?;
        fill_index_from_data(&index, &data)?;
        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats_synthetic(&index, size)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        // Rewind and retain for member open (shared stencil backend).
        reader.seek(SeekFrom::Start(0))?;
        let index = index.into_read_only()?;
        Ok(Self {
            archive_path,
            backend: WarcBackend::Shared(SharedSeekReader::new(reader)),
            index,
            options: options.clone(),
        })
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
            backend: WarcBackend::Path,
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
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        if !data.starts_with(b"WARC/") {
            return Err(WarcError::Msg(
                "Not a WARC file (missing WARC/ version line)".into(),
            ));
        }

        let index = SqliteIndex::create_writable_for_open(index_path, options)?;
        index.begin_write()?;
        fill_index_from_data(&index, &data)?;
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
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            backend: WarcBackend::Path,
            index,
            options: options.clone(),
        })
    }
}

impl MountSource for WarcMountSource {
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
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let ud = userdata(file_info)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing warc userdata"))?;
        let regions = vec![(ud.offset, file_info.size)];
        match &self.backend {
            WarcBackend::Path => {
                let file = File::open(&self.archive_path)?;
                Ok(Box::new(StenciledFile::new(file, regions)))
            }
            WarcBackend::Shared(shared) => {
                let reader = shared.open_reader();
                Ok(Box::new(StenciledFile::new(reader, regions)))
            }
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

/// Parse WARC records from an in-memory buffer and insert file rows into `index`.
fn fill_index_from_data(index: &SqliteIndex, data: &[u8]) -> Result<()> {
    let mut generated = std::collections::BTreeSet::new();
    let mut used_names: HashMap<String, u32> = HashMap::new();
    let mut pos = 0usize;
    let mut record_index = 0usize;

    while pos < data.len() {
        // Skip blank lines between records.
        while pos < data.len() && (data[pos] == b'\r' || data[pos] == b'\n') {
            if data[pos..].starts_with(b"\r\n") {
                pos += 2;
            } else {
                pos += 1;
            }
        }
        if pos >= data.len() {
            break;
        }
        if !data[pos..].starts_with(b"WARC/") {
            break;
        }

        let header_start = pos;
        let (header_blob, payload_offset) =
            if let Some(rel) = find_subslice(&data[pos..], b"\r\n\r\n") {
                let sep = pos + rel;
                (&data[pos..sep], sep + 4)
            } else if let Some(rel) = find_subslice(&data[pos..], b"\n\n") {
                let sep = pos + rel;
                (&data[pos..sep], sep + 2)
            } else {
                return Err(WarcError::Msg(format!(
                    "WARC record at {pos} missing header terminator"
                )));
            };

        let content_length = header_field(header_blob, b"Content-Length")
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|s| s.trim().parse::<usize>().ok())
            .ok_or_else(|| {
                WarcError::Msg(format!(
                    "WARC record at {header_start} missing Content-Length"
                ))
            })?;

        let warc_type = header_field(header_blob, b"WARC-Type")
            .map(|v| String::from_utf8_lossy(v).trim().to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".into());

        let mut display = if let Some(uri) = header_field(header_blob, b"WARC-Target-URI") {
            uri_to_path(&String::from_utf8_lossy(uri))
        } else if let Some(rid) = header_field(header_blob, b"WARC-Record-ID") {
            let s = String::from_utf8_lossy(rid)
                .trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .replace(':', "_");
            s
        } else {
            format!("record-{record_index}")
        };

        if matches!(
            warc_type.as_str(),
            "warcinfo" | "request" | "metadata" | "revisit" | "conversion"
        ) {
            display = format!("_warc/{warc_type}/{display}");
        }
        display = sanitize_name(&display, &mut used_names);

        if payload_offset + content_length > data.len() {
            return Err(WarcError::Msg(format!(
                "WARC record at {header_start} truncated payload"
            )));
        }

        let nfull = normpath(&display);
        let (path, base) = split_name(&nfull);
        ensure_parents(index, &path, &mut generated, 0.0)?;
        let mode = (ratarmount_core::S_IFREG | 0o644) as i64;
        index.insert_file(
            &path,
            &base,
            header_start as i64,
            payload_offset as i64,
            content_length as i64,
            0.0,
            mode,
            0,
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        )?;

        pos = payload_offset + content_length;
        record_index += 1;
    }

    if record_index == 0 {
        return Err(WarcError::Msg("WARC file contains no records".into()));
    }
    Ok(())
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn header_field<'a>(header: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    // Case-insensitive field match; value is rest of line after ':'
    let mut pos = 0usize;
    while pos < header.len() {
        let line_end = header[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i)
            .unwrap_or(header.len());
        let mut line = &header[pos..line_end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let key = &line[..colon];
            if key.eq_ignore_ascii_case(name) {
                let mut val = &line[colon + 1..];
                while val.first() == Some(&b' ') || val.first() == Some(&b'\t') {
                    val = &val[1..];
                }
                return Some(val);
            }
        }
        pos = line_end + 1;
    }
    None
}

fn uri_to_path(uri: &str) -> String {
    let uri = uri.trim().replace('\\', "/");
    if uri.contains("://") {
        if let Ok(parsed) = Url::parse(&uri) {
            let host = parsed.host_str().unwrap_or("unknown-host");
            let mut path = parsed.path().to_string();
            if path.is_empty() {
                path = "/".into();
            }
            if let Some(q) = parsed.query() {
                path = format!("{path}?{q}");
            }
            return format!("{host}{path}").trim_start_matches('/').to_string();
        }
    }
    let s = uri.trim_start_matches('/');
    if s.is_empty() {
        "index".into()
    } else {
        s.to_string()
    }
}

fn sanitize_name(name: &str, used: &mut HashMap<String, u32>) -> String {
    let mut name = uri_to_path(name);
    if name.is_empty() || name.ends_with('/') {
        name = format!(
            "{}index.html",
            if name.is_empty() { "record" } else { &name }
        );
    }
    let key = name.clone();
    if let Some(n) = used.get_mut(&key) {
        *n += 1;
        let count = *n;
        if let Some((stem, ext)) = name.rsplit_once('.') {
            if !stem.is_empty() {
                return format!("{stem}-{count}.{ext}");
            }
        }
        format!("{name}-{count}")
    } else {
        used.insert(key, 0);
        name
    }
}

fn split_name(full: &str) -> (String, String) {
    match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.to_string()),
    }
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
        let mode = (ratarmount_core::S_IFDIR | 0o755) as i64;
        index.insert_file(
            &parent, part, 0, 0, 0, mtime, mode, 0, "", 0, 0, false, false, true, 0,
        )?;
    }
    Ok(())
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

pub fn looks_like_warc(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut head = [0u8; 5];
        if f.read(&mut head).ok() == Some(5) && &head == b"WARC/" {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("warc"))
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

/// Store tarstats from path metadata + edge hashes (shared helper for warm-open fingerprint).
fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    index.store_tarstats_for_path(path)?;
    Ok(())
}

/// Synthetic size-only tarstats for nested / virtual labels without a host path.
fn store_stats_synthetic(index: &SqliteIndex, size: u64) -> Result<()> {
    let json = format!("{{\"st_size\":{size},\"st_mtime\":0,\"st_mtime_ns\":0}}");
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

/// Build a minimal WARC/1.0 with one `response` record (synthetic unit-test fixture).
#[cfg(test)]
fn synthetic_response_warc(uri: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"WARC/1.0\r\n");
    out.extend_from_slice(b"WARC-Type: response\r\n");
    out.extend_from_slice(format!("WARC-Target-URI: {uri}\r\n").as_bytes());
    out.extend_from_slice(b"WARC-Date: 2020-01-01T00:00:00Z\r\n");
    out.extend_from_slice(b"WARC-Record-ID: <urn:uuid:00000000-0000-0000-0000-000000000001>\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", payload.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn open_hello_world_warc() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/hello-world.warc");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("w.index.sqlite");
        let m = WarcMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m
            .lookup(
                "/iipc.github.io/warc-specifications/primers/web-archive-formats/hello-world.txt",
                0,
            )
            .expect("response payload");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(buf.windows(11).any(|w| w == b"Hello World"), "{buf:?}");
    }

    #[test]
    fn open_simple_response_warc() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/simple-response.warc");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("w.index.sqlite");
        let m = WarcMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m.lookup("/example.com/hello.txt", 0).expect("hello");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(buf.ends_with(b"hello warc\n"), "{buf:?}");
    }

    #[test]
    fn open_from_reader_synthetic_response() {
        let payload = b"Hello World";
        let warc = synthetic_response_warc("http://example.com/hello.txt", payload);
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = WarcMountSource::open_from_reader(
            Cursor::new(warc),
            "nested.warc",
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader");

        let fi = m
            .lookup("/example.com/hello.txt", 0)
            .expect("response path");
        assert_eq!(fi.size, payload.len() as u64);
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, payload);

        // Random access: seek into stencil mid-payload.
        r.seek(SeekFrom::Start(6)).unwrap();
        let mut tail = Vec::new();
        r.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, b"World");
    }

    #[test]
    fn open_from_reader_matches_path_open() {
        let payload = b"path-vs-reader";
        let warc = synthetic_response_warc("http://example.org/a.txt", payload);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.warc");
        std::fs::write(&path, &warc).unwrap();

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };

        let from_path =
            WarcMountSource::open(&path, None, &opts, "0.1.0", true).expect("path open");
        let from_reader = WarcMountSource::open_from_reader(
            Cursor::new(warc.clone()),
            "sample.warc",
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader");

        let fi_p = from_path.lookup("/example.org/a.txt", 0).expect("path fi");
        let fi_r = from_reader
            .lookup("/example.org/a.txt", 0)
            .expect("reader fi");
        assert_eq!(fi_p.size, fi_r.size);

        let mut bp = Vec::new();
        from_path
            .open(&fi_p, 0)
            .unwrap()
            .read_to_end(&mut bp)
            .unwrap();
        let mut br = Vec::new();
        from_reader
            .open(&fi_r, 0)
            .unwrap()
            .read_to_end(&mut br)
            .unwrap();
        assert_eq!(bp, payload);
        assert_eq!(br, payload);
    }

    /// Regression: open_existing rejects when archive size/mtime no longer match tarstats.
    #[test]
    fn warm_index_rejects_when_archive_size_or_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.warc");
        std::fs::write(
            &archive,
            synthetic_response_warc("http://example.com/hello.txt", b"warc-v1\n"),
        )
        .unwrap();
        let index = dir.path().join("swap.warc.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src = WarcMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/example.com/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "warc-v1\n");
        drop(src);
        assert!(index.exists());

        // Matching archive still opens warm.
        WarcMountSource::open_existing(&archive, &index, &opts).expect("warm match must succeed");

        // Replace archive content (size change) while reusing the sibling index path.
        std::fs::write(
            &archive,
            synthetic_response_warc("http://example.com/hello.txt", b"warc-v2-longer\n"),
        )
        .unwrap();

        match WarcMountSource::open_existing(&archive, &index, &opts) {
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

    /// Regression: warm WARC open rebuilds when archive content no longer matches tarstats.
    #[test]
    fn warm_index_rebuilds_when_archive_content_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.warc");
        std::fs::write(
            &archive,
            synthetic_response_warc("http://example.com/hello.txt", b"warc-v1\n"),
        )
        .unwrap();
        let index = dir.path().join("swap.warc.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src = WarcMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/example.com/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "warc-v1\n");
        drop(src);
        assert!(index.exists());

        std::fs::write(
            &archive,
            synthetic_response_warc("http://example.com/hello.txt", b"warc-v2-longer\n"),
        )
        .unwrap();

        // recreate=false: tarstats mismatch must rebuild, not serve stale member rows.
        let src2 =
            WarcMountSource::open(&archive, Some(&index), &opts, "test", false).expect("warm");
        let fi2 = src2.lookup("/example.com/hello.txt", 0).expect("lookup v2");
        let mut buf2 = String::new();
        src2.open(&fi2, 0)
            .unwrap()
            .read_to_string(&mut buf2)
            .unwrap();
        assert_eq!(
            buf2, "warc-v2-longer\n",
            "must serve new WARC data after tarstats mismatch rebuild"
        );
    }
}
