//! XAR archive MountSource with TOC heap offsets (`backendName=XARMountSource`).
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! [`XarMountSource::open_from_reader`] indexes any seekable stream without a host path,
//! so nested XAR can open without a `/tmp` spool when the parent member body is seekable
//! and the factory sniffs `xar!` magic.

use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use flate2::read::{GzDecoder, ZlibDecoder};
use quick_xml::events::Event;
use quick_xml::Reader;
use ratarmount_compress::{SeekRead, StenciledFile};
use ratarmount_core::{
    normpath, CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "XARMountSource";

#[derive(Debug, Error)]
pub enum XarError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, XarError>;

/// Mutex-backed `Read + Seek` for concurrent stencil / heap opens (Cursor / nested / remote).
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
            .map_err(|_| io::Error::other("shared XAR reader poisoned"))?;
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
                    .map_err(|_| io::Error::other("shared XAR reader poisoned"))?;
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

/// Where XAR bytes live for member open.
enum XarBackend {
    /// On-disk archive: open a fresh [`File`] per member.
    Path(PathBuf),
    /// Any `Read + Seek` shared under a mutex (nested / in-memory / remote).
    Shared(Arc<SharedSeekReader>),
}

pub struct XarMountSource {
    /// Path or virtual label (logs / index metadata).
    #[allow(dead_code)]
    archive_path: PathBuf,
    backend: XarBackend,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl XarMountSource {
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
                        Err(e) => eprintln!("info: could not load xar index ({e}); rebuilding"),
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

    /// Index and open a XAR archive from any `Read + Seek` source.
    ///
    /// Intended for nested AutoMount / in-memory archives: no on-disk archive path is
    /// required. `archive_label` is used for logs and index metadata (may be a nested
    /// member name). The reader is retained under a mutex for concurrent stencil opens
    /// and compressed heap reads (inflate into RAM; no disk spool).
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

        let (toc_xml, heap_offset) = read_header_and_toc(&mut reader)?;
        let rows = parse_toc_xml(&toc_xml, heap_offset)?;
        if rows.is_empty() {
            return Err(XarError::Msg("XAR archive contains no files".into()));
        }

        let index = SqliteIndex::create_writable_for_open(index_path_buf.as_deref(), options)?;
        index.begin_write()?;
        insert_rows(&index, &rows)?;
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
            backend: XarBackend::Shared(SharedSeekReader::new(reader)),
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
            backend: XarBackend::Path(archive_path.to_path_buf()),
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
        let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
        file.seek(SeekFrom::Start(0))?;

        let (toc_xml, heap_offset) = read_header_and_toc(&mut file)?;
        let rows = parse_toc_xml(&toc_xml, heap_offset)?;
        if rows.is_empty() {
            return Err(XarError::Msg("XAR archive contains no files".into()));
        }

        let index = SqliteIndex::create_writable_for_open(index_path, options)?;
        index.begin_write()?;
        insert_rows(&index, &rows)?;
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
            backend: XarBackend::Path(archive_path.to_path_buf()),
            index,
            options: options.clone(),
        })
    }
}

/// Parse XAR header + zlib TOC; return decompressed TOC XML and absolute heap start.
fn read_header_and_toc<R: Read + Seek>(reader: &mut R) -> Result<(Vec<u8>, u64)> {
    let mut header = [0u8; 28];
    reader.read_exact(&mut header)?;
    if &header[..4] != b"xar!" {
        return Err(XarError::Msg("Not a XAR archive".into()));
    }
    let header_size = u16::from_be_bytes([header[4], header[5]]) as u64;
    let toc_comp_len = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let header_size = if header_size < 28 { 28 } else { header_size };

    reader.seek(SeekFrom::Start(header_size))?;
    let mut toc_compressed = vec![0u8; toc_comp_len as usize];
    reader.read_exact(&mut toc_compressed)?;
    let mut decoder = ZlibDecoder::new(&toc_compressed[..]);
    let mut toc_xml = Vec::new();
    decoder
        .read_to_end(&mut toc_xml)
        .map_err(|e| XarError::Msg(format!("Failed to decompress XAR TOC: {e}")))?;

    let heap_offset = header_size + toc_comp_len;
    Ok((toc_xml, heap_offset))
}

fn insert_rows(index: &SqliteIndex, rows: &[XarRow]) -> Result<()> {
    let mut generated = std::collections::BTreeSet::new();
    for row in rows {
        ensure_parents(index, &row.path, &mut generated, row.mtime)?;
        index.insert_file(
            &row.path,
            &row.name,
            row.header_offset,
            row.data_offset,
            row.size,
            row.mtime,
            row.mode,
            0,
            &row.linkname,
            0,
            0,
            false,
            false,
            false,
            0,
        )?;
    }
    Ok(())
}

struct XarRow {
    path: String,
    name: String,
    header_offset: i64,
    data_offset: i64,
    size: i64,
    mtime: f64,
    mode: i64,
    linkname: String,
}

fn parse_toc_xml(toc_xml: &[u8], heap_offset: u64) -> Result<Vec<XarRow>> {
    let mut reader = Reader::from_reader(toc_xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut rows = Vec::new();

    #[derive(Default)]
    struct St {
        name: String,
        file_type: String,
        length: u64,
        offset: u64,
        size: u64,
        encoding: String,
        in_data: bool,
        cur_field: Option<String>,
        pushed_dir: bool,
    }

    let mut stack: Vec<St> = Vec::new();
    let mut dir_stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = local_name(e.name().as_ref());
                if local == "file" {
                    stack.push(St {
                        file_type: "file".into(),
                        encoding: "application/octet-stream".into(),
                        ..St::default()
                    });
                } else if let Some(st) = stack.last_mut() {
                    if local == "data" {
                        st.in_data = true;
                    } else if st.in_data {
                        if matches!(local.as_str(), "length" | "offset" | "size") {
                            st.cur_field = Some(local);
                        } else if local == "encoding" {
                            for a in e.attributes().flatten() {
                                let key = local_name(a.key.as_ref());
                                if key == "style" || key == "name" {
                                    st.encoding = String::from_utf8_lossy(&a.value).into_owned();
                                }
                            }
                        }
                    } else if matches!(local.as_str(), "name" | "type") {
                        st.cur_field = Some(local);
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if local_name(e.name().as_ref()) == "encoding" {
                    if let Some(st) = stack.last_mut() {
                        for a in e.attributes().flatten() {
                            let key = local_name(a.key.as_ref());
                            if key == "style" || key == "name" {
                                st.encoding = String::from_utf8_lossy(&a.value).into_owned();
                            }
                        }
                    }
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(st) = stack.last_mut() {
                    if let Some(field) = st.cur_field.take() {
                        let text = t.unescape().unwrap_or_default().into_owned();
                        match field.as_str() {
                            "name" if !st.in_data => {
                                st.name = text;
                                if st.file_type == "directory"
                                    && !st.name.is_empty()
                                    && !st.pushed_dir
                                {
                                    dir_stack.push(st.name.clone());
                                    st.pushed_dir = true;
                                }
                            }
                            "type" if !st.in_data => {
                                st.file_type = text;
                                if st.file_type == "directory"
                                    && !st.name.is_empty()
                                    && !st.pushed_dir
                                {
                                    dir_stack.push(st.name.clone());
                                    st.pushed_dir = true;
                                }
                            }
                            "length" => st.length = text.trim().parse().unwrap_or(0),
                            "offset" => st.offset = text.trim().parse().unwrap_or(0),
                            "size" => st.size = text.trim().parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name(e.name().as_ref());
                if local == "data" {
                    if let Some(st) = stack.last_mut() {
                        st.in_data = false;
                    }
                } else if local == "file" {
                    if let Some(st) = stack.pop() {
                        let name = if st.name.is_empty() {
                            "unnamed".into()
                        } else {
                            st.name
                        };
                        let parent_parts: Vec<String> =
                            if st.file_type == "directory" && st.pushed_dir {
                                dir_stack[..dir_stack.len().saturating_sub(1)].to_vec()
                            } else {
                                dir_stack.clone()
                            };
                        let full = if parent_parts.is_empty() {
                            name.clone()
                        } else {
                            format!("{}/{}", parent_parts.join("/"), name)
                        };
                        if st.file_type == "directory" {
                            let nfull = normpath(&full);
                            let (path, base) = split_name(&nfull);
                            rows.push(XarRow {
                                path,
                                name: base,
                                header_offset: 0,
                                data_offset: 0,
                                size: 0,
                                mtime: 0.0,
                                mode: (ratarmount_core::S_IFDIR | 0o755) as i64,
                                linkname: String::new(),
                            });
                            if st.pushed_dir {
                                dir_stack.pop();
                            }
                        } else {
                            let data_offset = heap_offset + st.offset;
                            let size = if st.size != 0 { st.size } else { st.length };
                            let nfull = normpath(&full);
                            let (path, base) = split_name(&nfull);
                            let linkname = format!("xar-enc:{}|packed:{}", st.encoding, st.length);
                            rows.push(XarRow {
                                path,
                                name: base,
                                header_offset: data_offset as i64,
                                data_offset: data_offset as i64,
                                size: size as i64,
                                mtime: 0.0,
                                mode: (ratarmount_core::S_IFREG | 0o644) as i64,
                                linkname,
                            });
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(XarError::Msg(format!("Invalid XAR TOC XML: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    Ok(rows)
}

fn local_name(qname: &[u8]) -> String {
    let s = String::from_utf8_lossy(qname);
    s.rsplit('}').next().unwrap_or(&s).to_string()
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

impl MountSource for XarMountSource {
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

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.index.list_dirents(path).ok().flatten().map(|rows| {
            rows.into_iter()
                .map(|d| CheapDirent {
                    name: d.name,
                    mode: d.mode,
                    size: d.size,
                })
                .collect()
        })
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
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing xar userdata"))?;
        let offset = ud.offset;
        let link = file_info.linkname.as_str();

        match &self.backend {
            XarBackend::Path(path) => {
                let file = File::open(path)?;
                open_member_from_reader(file, offset, file_info.size, link)
            }
            XarBackend::Shared(shared) => {
                let reader = shared.open_reader();
                open_member_from_reader(reader, offset, file_info.size, link)
            }
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

/// Open a XAR member: store/none → stencil; gzip/zlib/bzip2/xz → inflate into RAM cursor.
fn open_member_from_reader<R: Read + Seek + Send + 'static>(
    mut reader: R,
    offset: u64,
    logical_size: u64,
    link: &str,
) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
    if !link.starts_with("xar-enc:") {
        return Ok(Box::new(StenciledFile::new(
            reader,
            vec![(offset, logical_size)],
        )));
    }

    let rest = &link["xar-enc:".len()..];
    let (style, packed_meta) = rest.split_once("|packed:").unwrap_or((rest, ""));
    let packed_size = packed_meta.parse::<u64>().unwrap_or(logical_size);

    if style == "application/octet-stream" || style.is_empty() {
        return Ok(Box::new(StenciledFile::new(
            reader,
            vec![(offset, packed_size)],
        )));
    }

    reader.seek(SeekFrom::Start(offset))?;
    let mut packed = vec![0u8; packed_size as usize];
    reader.read_exact(&mut packed)?;

    let data = if style == "application/x-bzip2" {
        let mut d = bzip2::read::BzDecoder::new(&packed[..]);
        let mut out = Vec::new();
        d.read_to_end(&mut out)?;
        out
    } else if style == "application/x-xz" || style == "application/xz" {
        let mut d = xz2::read::XzDecoder::new(&packed[..]);
        let mut out = Vec::new();
        d.read_to_end(&mut out)?;
        out
    } else if style == "application/x-gzip" || style == "application/gzip" || style.contains("gzip")
    {
        decompress_zlib_or_gzip(&packed)?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("XAR member encoding not supported for random access: {style}"),
        ));
    };

    Ok(Box::new(Cursor::new(data)))
}

fn decompress_zlib_or_gzip(packed: &[u8]) -> io::Result<Vec<u8>> {
    {
        let mut d = ZlibDecoder::new(packed);
        let mut out = Vec::new();
        if d.read_to_end(&mut out).is_ok() && !out.is_empty() {
            return Ok(out);
        }
    }
    {
        let mut d = GzDecoder::new(packed);
        let mut out = Vec::new();
        if d.read_to_end(&mut out).is_ok() {
            return Ok(out);
        }
    }
    let mut d = flate2::Decompress::new(false);
    let mut out = vec![0u8; packed.len() * 4 + 64];
    loop {
        let before_in = d.total_in() as usize;
        let before_out = d.total_out() as usize;
        match d.decompress(
            &packed[before_in..],
            &mut out[before_out..],
            flate2::FlushDecompress::Finish,
        ) {
            Ok(flate2::Status::Ok) => {
                if d.total_out() as usize == out.len() {
                    out.resize(out.len() * 2, 0);
                }
            }
            Ok(flate2::Status::StreamEnd) => {
                out.truncate(d.total_out() as usize);
                return Ok(out);
            }
            Ok(flate2::Status::BufError) => out.resize(out.len() * 2, 0),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("gzip/zlib decompress failed: {e}"),
                ));
            }
        }
    }
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

pub fn looks_like_xar(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 4];
        if f.read(&mut magic).ok() == Some(4) && &magic == b"xar!" {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("xar"))
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
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
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    /// Minimal synthetic XAR: one store-encoded member (no disk needed).
    fn build_store_xar(name: &str, payload: &[u8]) -> Vec<u8> {
        let toc = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <file id="1">
   <type>file</type>
   <name>{name}</name>
   <data>
    <length>{len}</length>
    <offset>0</offset>
    <size>{len}</size>
    <encoding style="application/octet-stream"/>
   </data>
  </file>
 </toc>
</xar>"#,
            name = name,
            len = payload.len()
        );
        wrap_xar(toc.as_bytes(), payload)
    }

    /// Minimal synthetic XAR: one gzip/zlib-encoded member.
    fn build_gzip_xar(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let packed = enc.finish().unwrap();
        let toc = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <file id="1">
   <type>file</type>
   <name>{name}</name>
   <data>
    <length>{plen}</length>
    <offset>0</offset>
    <size>{ulen}</size>
    <encoding style="application/x-gzip"/>
   </data>
  </file>
 </toc>
</xar>"#,
            name = name,
            plen = packed.len(),
            ulen = payload.len()
        );
        wrap_xar(toc.as_bytes(), &packed)
    }

    fn wrap_xar(toc_xml: &[u8], heap: &[u8]) -> Vec<u8> {
        let mut toc_comp = ZlibEncoder::new(Vec::new(), Compression::default());
        toc_comp.write_all(toc_xml).unwrap();
        let toc_comp = toc_comp.finish().unwrap();

        let header_size: u16 = 28;
        let mut out = Vec::with_capacity(28 + toc_comp.len() + heap.len());
        out.extend_from_slice(b"xar!");
        out.extend_from_slice(&header_size.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // version
        out.extend_from_slice(&(toc_comp.len() as u64).to_be_bytes());
        out.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // checksum algo none
        out.extend_from_slice(&toc_comp);
        out.extend_from_slice(heap);
        out
    }

    fn read_member(m: &XarMountSource, path: &str) -> Vec<u8> {
        let fi = m.lookup(path, 0).unwrap_or_else(|| panic!("lookup {path}"));
        let mut r = m.open(&fi, 0).expect("open member");
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).expect("read member");
        buf
    }

    #[test]
    fn open_from_reader_store_synthetic() {
        let bytes = build_store_xar("hello.txt", b"hello");
        let m = XarMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("nested.xar"),
            None,
            &OpenOptions::default(),
            "0.1.0",
        )
        .expect("open_from_reader");
        assert_eq!(read_member(&m, "/hello.txt"), b"hello");
    }

    /// Regression: cheap list_dirents must expose index sizes (readdirplus TTL).
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let payload = b"hello";
        let bytes = build_store_xar("hello.txt", payload);
        let src = XarMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("nested.xar"),
            None,
            &OpenOptions::default(),
            "0.1.0",
        )
        .expect("open_from_reader");
        let dents = src.list_dirents("/").expect("dirents");
        let d = dents.iter().find(|e| e.name == "hello.txt").unwrap();
        assert_eq!(d.size, payload.len() as u64);
        assert_eq!(src.lookup("/hello.txt", 0).unwrap().size, d.size);
    }

    #[test]
    fn open_from_reader_gzip_synthetic() {
        let payload = b"foo\n";
        let bytes = build_gzip_xar("bar", payload);
        let m = XarMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("nested-gz.xar"),
            None,
            &OpenOptions::default(),
            "0.1.0",
        )
        .expect("open_from_reader gzip");
        assert_eq!(read_member(&m, "/bar"), payload);
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = XarMountSource::open_from_reader(
            Cursor::new(b"not a xar"),
            Path::new("bad.xar"),
            None,
            &OpenOptions::default(),
            "0.1.0",
        );
        assert!(err.is_err());
    }

    #[test]
    fn open_single_file_xar() {
        let path = py_fixture("single-file.xar");
        if !path.exists() {
            return;
        }
        assert!(looks_like_xar(&path));
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("x.index.sqlite");
        let m = XarMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        assert_eq!(read_member(&m, "/bar"), b"foo\n");
    }

    #[test]
    fn open_from_reader_matches_path_open() {
        let path = py_fixture("single-file.xar");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("x.index.sqlite");
        let from_path =
            XarMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
                .expect("path open");
        let bytes = std::fs::read(&path).expect("read fixture");
        let from_reader = XarMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("single-file.xar"),
            None,
            &OpenOptions::default(),
            "0.1.0",
        )
        .expect("open_from_reader");
        assert_eq!(
            read_member(&from_path, "/bar"),
            read_member(&from_reader, "/bar")
        );
        assert_eq!(read_member(&from_reader, "/bar"), b"foo\n");
    }

    /// Regression: open_existing rejects when archive size/mtime no longer match tarstats.
    #[test]
    fn warm_index_rejects_when_archive_size_or_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.xar");
        std::fs::write(&archive, build_store_xar("hello.txt", b"xar-v1\n")).unwrap();
        let index = dir.path().join("swap.xar.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src =
            XarMountSource::open(&archive, Some(&index), &opts, "test", true).expect("cold create");
        assert_eq!(read_member(&src, "/hello.txt"), b"xar-v1\n");
        drop(src);
        assert!(index.exists());

        // Matching archive still opens warm.
        XarMountSource::open_existing(&archive, &index, &opts).expect("warm match must succeed");

        // Replace archive content (size change) while reusing the sibling index path.
        std::fs::write(&archive, build_store_xar("hello.txt", b"xar-v2-longer\n")).unwrap();

        match XarMountSource::open_existing(&archive, &index, &opts) {
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

    /// Regression: warm XAR open rebuilds when archive content no longer matches tarstats.
    #[test]
    fn warm_index_rebuilds_when_archive_content_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.xar");
        std::fs::write(&archive, build_store_xar("hello.txt", b"xar-v1\n")).unwrap();
        let index = dir.path().join("swap.xar.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src =
            XarMountSource::open(&archive, Some(&index), &opts, "test", true).expect("cold create");
        assert_eq!(read_member(&src, "/hello.txt"), b"xar-v1\n");
        drop(src);
        assert!(index.exists());

        std::fs::write(&archive, build_store_xar("hello.txt", b"xar-v2-longer\n")).unwrap();

        // recreate=false: tarstats mismatch must rebuild, not serve stale member rows.
        let src2 =
            XarMountSource::open(&archive, Some(&index), &opts, "test", false).expect("warm");
        assert_eq!(
            read_member(&src2, "/hello.txt"),
            b"xar-v2-longer\n",
            "must serve new XAR data after tarstats mismatch rebuild"
        );
    }
}
