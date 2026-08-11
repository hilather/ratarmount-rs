//! Electron ASAR MountSource (`backendName=ASARMountSource`).
//!
//! Format: pickled JSON header + concatenated file payloads. Members open via
//! absolute data offsets (stencil), matching Python `ASARMountSource`.
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! [`AsarMountSource::open_from_reader`] indexes any seekable stream without a
//! host path, so nested ASAR can open without a `/tmp` spool when the parent
//! member body is seekable.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratarmount_compress::{SeekRead, StenciledFile};
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
};
use ratarmount_index::{FileRow, IndexError, SqliteIndex};
use serde_json::Value;
use thiserror::Error;

pub const BACKEND_NAME: &str = "ASARMountSource";

/// Mutex-shared seekable archive body for concurrent stencil opens.
type SharedArchiveIo = Arc<Mutex<Box<dyn SeekRead>>>;

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

/// Independent logical cursor over a shared `Read + Seek` archive body.
struct SharedSeekHandle {
    shared: SharedArchiveIo,
    pos: u64,
}

impl SharedSeekHandle {
    fn new(shared: SharedArchiveIo) -> Self {
        Self { shared, pos: 0 }
    }
}

impl Read for SharedSeekHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| io::Error::other("shared asar reader poisoned"))?;
        guard.seek(SeekFrom::Start(self.pos))?;
        let n = guard.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SharedSeekHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.pos as i64 + o,
            SeekFrom::End(o) => {
                let mut guard = self
                    .shared
                    .lock()
                    .map_err(|_| io::Error::other("shared asar reader poisoned"))?;
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

/// (json_start, json_size, data_start)
pub fn find_asar_header<R: Read + Seek>(file: &mut R) -> Result<(u64, u64, u64)> {
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

/// Walk the ASAR JSON header tree and emit index rows with absolute data offsets.
fn walk_asar_entries(header: &Value, data_offset: u64) -> Vec<FileRow> {
    let mut batch = Vec::new();
    let mut stack: Vec<(String, Value)> = vec![("/".into(), header.clone())];
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
    }
    batch
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
    /// Path or virtual label (logs / index metadata).
    #[allow(dead_code)]
    archive_path: PathBuf,
    archive_io: SharedArchiveIo,
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
        let file = File::open(&archive_path)?;
        Self::open_from_reader(
            file,
            &archive_path,
            index_path,
            options,
            product_version,
            recreate,
        )
    }

    /// Open an ASAR archive from any seekable reader (nested AutoMount without temp spool).
    ///
    /// `archive_label` is used for logs / index metadata (may be a nested member name).
    /// Prefer `index_path: None` or `options.index_in_memory` for nested mounts.
    pub fn open_from_reader<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let index_path_buf: Option<PathBuf> = if options.index_in_memory {
            None
        } else {
            index_path.map(|p| p.to_path_buf()).or_else(|| {
                // Only invent a sibling index path when the label is a real file.
                if archive_path.is_file() {
                    let mut s = archive_path.as_os_str().to_os_string();
                    s.push(".index.sqlite");
                    Some(PathBuf::from(s))
                } else {
                    None
                }
            })
        };

        if let Some(ref ip) = index_path_buf {
            if !recreate && ip.exists() && archive_path.is_file() {
                let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
                if meta_ok {
                    match Self::open_existing_path(&archive_path, ip, options) {
                        Ok(s) => return Ok(s),
                        Err(e) => {
                            eprintln!("info: could not load asar index ({e}); rebuilding")
                        }
                    }
                }
            }
        }

        Self::create_index_from_reader(
            reader,
            &archive_path,
            index_path_buf.as_deref(),
            options,
            product_version,
        )
    }

    fn open_existing_path(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
    ) -> Result<Self> {
        // Index + fingerprint first: reject a sibling index for a replaced archive
        // before trusting files rows / stencil opens.
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        // Reject sibling indexes for a replaced archive (size/mtime/edge hash).
        // Missing tarstats still Ok (legacy indexes).
        index.check_tarstats_matches_archive(archive_path)?;
        let file = File::open(archive_path)?;
        let archive_io: SharedArchiveIo = Arc::new(Mutex::new(Box::new(file)));
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            archive_io,
            index,
            options: options.clone(),
        })
    }

    fn create_index_from_reader<R>(
        mut reader: R,
        archive_path: &Path,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let _ = options;
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let (header_start, header_size, data_offset) = find_asar_header(&mut reader)?;
        reader.seek(SeekFrom::Start(header_start))?;
        let mut header_bytes = vec![0u8; header_size as usize];
        reader.read_exact(&mut header_bytes)?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AsarError::Msg(format!("ASAR JSON header: {e}")))?;

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;

        let rows = walk_asar_entries(&header, data_offset);
        for chunk in rows.chunks(1000) {
            index.insert_files_batch(chunk)?;
        }

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        // Real on-disk archives: store size/mtime + edge hashes so warm reopen
        // fails closed after in-place replace. Nested/virtual labels skip.
        store_stats_for_label(&index, archive_path)?;
        index.commit_write()?;
        println!(
            "Creating offset dictionary for {} took {:.2}s",
            archive_path.display(),
            t0.elapsed().as_secs_f64()
        );

        reader.seek(SeekFrom::Start(0))?;
        let archive_io: SharedArchiveIo = Arc::new(Mutex::new(Box::new(reader)));
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            archive_io,
            index: index.into_read_only()?,
            options: options.clone(),
        })
    }
}

/// Store tarstats from path metadata + edge hashes when the label is a real file.
///
/// Nested / virtual labels leave tarstats absent (legacy-compatible warm check allows).
fn store_stats_for_label(index: &SqliteIndex, path: &Path) -> Result<()> {
    if path.is_file() {
        index.store_tarstats_for_path(path)?;
    }
    Ok(())
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
        (ratarmount_core::S_IFDIR | 0o777) as i64
    } else {
        let mut m = (ratarmount_core::S_IFREG | 0o777) as i64;
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
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
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
        let handle = SharedSeekHandle::new(Arc::clone(&self.archive_io));
        let stencil = StenciledFile::new(handle, vec![(offset, file_info.size)]);
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
    use std::io::Cursor;

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    /// Build a minimal Electron ASAR with flat files (concatenated payload).
    fn build_minimal_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
        use serde_json::{json, Map};
        let mut map = Map::new();
        let mut offset: u64 = 0;
        let mut payload = Vec::new();
        for (name, data) in files {
            map.insert(
                (*name).to_string(),
                json!({
                    "size": data.len(),
                    "offset": offset.to_string(),
                }),
            );
            payload.extend_from_slice(data);
            offset += data.len() as u64;
        }
        let header = json!({ "files": map });
        let header_bytes = serde_json::to_vec(&header).expect("json");
        let size_of_pickled_header = header_bytes.len() as u32;
        let padding = (4 - (size_of_pickled_header % 4)) % 4;
        let size_of_pickled_pickled_header = size_of_pickled_header + padding + 4;
        let size_of_pickled_pickled_pickled_header = size_of_pickled_pickled_header + 4;

        let mut out = Vec::new();
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_pickled_pickled_header.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_pickled_header.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_header.to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend(std::iter::repeat_n(0u8, padding as usize));
        out.extend_from_slice(&payload);
        out
    }

    /// Nested-directory ASAR: `/foo/fighter/ufo` with payload `iriya\n`.
    fn build_nested_ufo_asar() -> Vec<u8> {
        let header = serde_json::json!({
            "files": {
                "foo": {
                    "files": {
                        "fighter": {
                            "files": {
                                "ufo": {
                                    "size": 6,
                                    "offset": "0",
                                    "executable": true
                                }
                            }
                        }
                    }
                }
            }
        });
        let header_bytes = serde_json::to_vec(&header).expect("json");
        let size_of_pickled_header = header_bytes.len() as u32;
        let padding = (4 - (size_of_pickled_header % 4)) % 4;
        let size_of_pickled_pickled_header = size_of_pickled_header + padding + 4;
        let size_of_pickled_pickled_pickled_header = size_of_pickled_pickled_header + 4;
        let mut out = Vec::new();
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_pickled_pickled_header.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_pickled_header.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_header.to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend(std::iter::repeat_n(0u8, padding as usize));
        out.extend_from_slice(b"iriya\n");
        out
    }

    #[test]
    fn find_asar_header_on_cursor() {
        let bytes = build_minimal_asar(&[("a.txt", b"hello\n")]);
        let mut cur = Cursor::new(bytes.as_slice());
        let (hs, hsz, data) = find_asar_header(&mut cur).expect("header");
        assert_eq!(hs, 16);
        assert!(hsz > 0);
        assert_eq!(data, 16 + hsz + ((4 - (hsz % 4)) % 4));
    }

    #[test]
    fn open_from_reader_cursor_minimal() {
        let bytes = build_minimal_asar(&[("hello.txt", b"world\n"), ("b.bin", b"xyz")]);
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = AsarMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("virtual/minimal.asar"),
            None,
            &opts,
            "0.1.0",
            true,
        )
        .expect("open_from_reader");
        let fi = m.lookup("/hello.txt", 0).expect("hello.txt");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "world\n");

        let fi2 = m.lookup("/b.bin", 0).expect("b.bin");
        let mut r2 = m.open(&fi2, 0).unwrap();
        let mut buf = Vec::new();
        r2.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"xyz");

        // Mid-member seek on shared reader backend.
        let mut r3 = m.open(&fi, 0).unwrap();
        r3.seek(SeekFrom::Start(1)).unwrap();
        let mut mid = String::new();
        r3.read_to_string(&mut mid).unwrap();
        assert_eq!(mid, "orld\n");
    }

    #[test]
    fn open_from_reader_nested_ufo_cursor() {
        let bytes = build_nested_ufo_asar();
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = AsarMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("virtual/nested-ufo.asar"),
            None,
            &opts,
            "0.1.0",
            true,
        )
        .expect("open_from_reader nested");
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
    }

    #[test]
    fn open_from_reader_fixture_cursor_if_present() {
        let path = py_fixture("nested-tar.asar");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = AsarMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("virtual/nested-tar.asar"),
            None,
            &opts,
            "0.1.0",
            true,
        )
        .expect("fixture open_from_reader");
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
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

    #[test]
    fn open_from_reader_equals_path_when_fixture_present() {
        let path = py_fixture("nested-tar.asar");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let from_path =
            AsarMountSource::open(&path, None, &opts, "0.1.0", true).expect("path open");
        let from_reader = AsarMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("virtual/nested-tar.asar"),
            None,
            &opts,
            "0.1.0",
            true,
        )
        .expect("reader open");
        let fi_p = from_path.lookup("/foo/fighter/ufo", 0).expect("path ufo");
        let fi_r = from_reader
            .lookup("/foo/fighter/ufo", 0)
            .expect("reader ufo");
        assert_eq!(fi_p.size, fi_r.size);
        let mut bp = Vec::new();
        let mut br = Vec::new();
        from_path
            .open(&fi_p, 0)
            .unwrap()
            .read_to_end(&mut bp)
            .unwrap();
        from_reader
            .open(&fi_r, 0)
            .unwrap()
            .read_to_end(&mut br)
            .unwrap();
        assert_eq!(bp, br);
    }

    /// Regression: open_existing rejects when archive size/mtime no longer match tarstats.
    #[test]
    fn warm_index_rejects_when_archive_size_or_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.asar");
        std::fs::write(&archive, build_minimal_asar(&[("hello.txt", b"asar-v1\n")])).unwrap();
        let index = dir.path().join("swap.asar.index.sqlite");
        let opts = OpenOptions::default();

        let src = AsarMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "asar-v1\n");
        drop(src);
        assert!(index.exists());

        // Matching archive still opens warm.
        AsarMountSource::open_existing_path(&archive, &index, &opts)
            .expect("warm match must succeed");

        // Replace archive content (size change) while reusing the sibling index path.
        std::fs::write(
            &archive,
            build_minimal_asar(&[("hello.txt", b"asar-v2-longer\n")]),
        )
        .unwrap();

        match AsarMountSource::open_existing_path(&archive, &index, &opts) {
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

    /// Regression: warm ASAR open rebuilds when archive content no longer matches tarstats.
    #[test]
    fn warm_index_rebuilds_when_archive_content_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.asar");
        std::fs::write(&archive, build_minimal_asar(&[("hello.txt", b"asar-v1\n")])).unwrap();
        let index = dir.path().join("swap.asar.index.sqlite");
        let opts = OpenOptions::default();

        let src = AsarMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "asar-v1\n");
        drop(src);
        assert!(index.exists());

        std::fs::write(
            &archive,
            build_minimal_asar(&[("hello.txt", b"asar-v2-longer\n")]),
        )
        .unwrap();

        // recreate=false: tarstats mismatch must rebuild, not serve stale member rows.
        let src2 =
            AsarMountSource::open(&archive, Some(&index), &opts, "test", false).expect("warm");
        let fi2 = src2.lookup("/hello.txt", 0).expect("lookup v2");
        let mut buf2 = String::new();
        src2.open(&fi2, 0)
            .unwrap()
            .read_to_string(&mut buf2)
            .unwrap();
        assert_eq!(
            buf2, "asar-v2-longer\n",
            "must serve new ASAR data after tarstats mismatch rebuild"
        );
    }
}
