//! TAR indexing and open-by-offset (Phase 1–3).
//!
//! `backendName` must be exactly `SQLiteIndexedTar` for Python interop.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use std::sync::Arc;

use ratarmount_compress::{
    FileSegment, SeekRead, SeekableBody, SegmentedFile, SharedSeekableGzip, StenciledFile,
};
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{FileRow, IndexError, SqliteIndex};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Exact string stored in index metadata (Python `SQLiteIndexedTar`).
pub const BACKEND_NAME: &str = "SQLiteIndexedTar";

const BLOCK_SIZE: u64 = 512;

#[derive(Debug, Error)]
pub enum TarError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, TarError>;

/// Where uncompressed TAR bytes live for open/read.
enum ContentBackend {
    /// Plain file (uncompressed archive or materialised temp body).
    File {
        file: File,
        _keep: Option<NamedTempFile>,
    },
    /// Seekable gzip (checkpoint decoder).
    Gzip(Arc<SharedSeekableGzip>),
    /// Generic seekable body (bzip2/xz/zstd DecodedBody or multi-frame zstd).
    Body(Arc<dyn SeekableBody>),
}

impl ContentBackend {
    fn open_reader(&self) -> io::Result<ContentReader> {
        match self {
            Self::File { file, .. } => Ok(ContentReader::File(file.try_clone()?)),
            Self::Gzip(g) => Ok(ContentReader::Gzip(g.reader()?)),
            Self::Body(b) => Ok(ContentReader::Dyn(b.open_reader()?)),
        }
    }
}

/// Concrete reader used by open paths.
enum ContentReader {
    File(File),
    Gzip(ratarmount_compress::SeekableGzipReader),
    Dyn(Box<dyn SeekRead>),
}

impl Read for ContentReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(f) => f.read(buf),
            Self::Gzip(g) => g.read(buf),
            Self::Dyn(r) => r.read(buf),
        }
    }
}

impl Seek for ContentReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(f) => f.seek(pos),
            Self::Gzip(g) => g.seek(pos),
            Self::Dyn(r) => r.seek(pos),
        }
    }
}

/// TAR archive backed by a SQLite index (read path + optional build).
pub struct SqliteIndexedTar {
    /// Original archive path (for logs / tarstats).
    archive_path: PathBuf,
    /// Path used for content reads (uncompressed body; may be a temp file).
    #[allow(dead_code)]
    data_path: PathBuf,
    backend: ContentBackend,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl SqliteIndexedTar {
    /// Open existing index; `data_path` is the uncompressed content source.
    /// On success, takes ownership of `materialised` (if any).
    pub fn open_with_existing_index(
        archive_path: impl AsRef<Path>,
        data_path: impl AsRef<Path>,
        index_path: impl AsRef<Path>,
        options: OpenOptions,
        materialised: &mut Option<NamedTempFile>,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = data_path.as_ref().to_path_buf();
        let index = SqliteIndex::open_read_only(index_path.as_ref())?;
        index.check_backend_name(BACKEND_NAME)?;
        let data_file = File::open(&data_path)?;
        Ok(Self {
            archive_path,
            data_path,
            backend: ContentBackend::File {
                file: data_file,
                _keep: materialised.take(),
            },
            index,
            options,
        })
    }

    /// Open existing index with a seekable-gzip body (no materialize).
    pub fn open_with_existing_index_gzip(
        archive_path: impl AsRef<Path>,
        gzip: Arc<SharedSeekableGzip>,
        index_path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = gzip.path().to_path_buf();
        let index = SqliteIndex::open_read_only(index_path.as_ref())?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path,
            data_path,
            backend: ContentBackend::Gzip(gzip),
            index,
            options,
        })
    }

    /// Build a new index by parsing TAR data at `data_path` (uncompressed).
    /// Logs use `archive_path` (original user-facing path).
    /// `index_path`: `Some(path)` for on-disk index, `None` for `:memory:`.
    /// On success, takes ownership of `materialised` (if any).
    pub fn create_index(
        archive_path: impl AsRef<Path>,
        data_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        materialised: &mut Option<NamedTempFile>,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = data_path.as_ref().to_path_buf();
        let mut file = File::open(&data_path)?;
        let backend = ContentBackend::File {
            file: file.try_clone()?,
            _keep: materialised.take(),
        };
        Self::create_index_from_reader(
            archive_path,
            data_path,
            &mut file,
            index_path,
            options,
            product_version,
            backend,
        )
    }

    /// Build index from a seekable-gzip body (G3 Tier B — no materialize).
    pub fn create_index_gzip(
        archive_path: impl AsRef<Path>,
        gzip: Arc<SharedSeekableGzip>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = gzip.path().to_path_buf();
        let mut reader = gzip.reader()?;
        let backend = ContentBackend::Gzip(Arc::clone(&gzip));
        Self::create_index_from_reader(
            archive_path,
            data_path,
            &mut reader,
            index_path,
            options,
            product_version,
            backend,
        )
    }

    /// Open existing index with a generic seekable body (bzip2/xz/zstd).
    pub fn open_with_existing_index_body(
        archive_path: impl AsRef<Path>,
        body: Arc<dyn SeekableBody>,
        index_path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = body.path().to_path_buf();
        let index = SqliteIndex::open_read_only(index_path.as_ref())?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path,
            data_path,
            backend: ContentBackend::Body(body),
            index,
            options,
        })
    }

    /// Build index from a generic seekable body (bzip2/xz/zstd).
    pub fn create_index_body(
        archive_path: impl AsRef<Path>,
        body: Arc<dyn SeekableBody>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = body.path().to_path_buf();
        let mut reader = body.open_reader().map_err(TarError::Io)?;
        let backend = ContentBackend::Body(body);
        Self::create_index_from_reader(
            archive_path,
            data_path,
            &mut reader,
            index_path,
            options,
            product_version,
            backend,
        )
    }

    fn create_index_from_reader<R: Read + Seek>(
        archive_path: PathBuf,
        data_path: PathBuf,
        reader: &mut R,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        backend: ContentBackend,
    ) -> Result<Self> {
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let is_gnu_incremental = parse_tar_into_index(reader, &index, options)?;

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        index.store_metadata_key_value(
            "isGnuIncremental",
            if is_gnu_incremental { "1" } else { "0" },
        )?;
        store_tarstats(&index, &archive_path)?;
        store_arguments(&index, options)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        let index = index.into_read_only()?;
        Ok(Self {
            archive_path,
            data_path,
            backend,
            index,
            options: options.clone(),
        })
    }

    pub fn index(&self) -> &SqliteIndex {
        &self.index
    }

    pub fn archive_path(&self) -> &Path {
        &self.archive_path
    }
}

impl MountSource for SqliteIndexedTar {
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

    fn versions(&self, path: &str) -> u32 {
        self.index.version_count(path).unwrap_or(0)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        let ud = tar_userdata(file_info)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing TAR userdata"))?;
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        if file_info.size == 0 && !ud.issparse {
            return Ok(Box::new(std::io::Cursor::new(Vec::new())));
        }
        let reader = self.backend.open_reader()?;
        if ud.issparse {
            let header_off = ud
                .offsetheader
                .unwrap_or(ud.offset.saturating_sub(BLOCK_SIZE));
            return open_sparse_member(reader, header_off, ud.offset, file_info.size);
        }
        Ok(Box::new(StenciledFile::new(
            reader,
            vec![(ud.offset, file_info.size)],
        )))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn tar_userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

fn store_tarstats(index: &SqliteIndex, path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path)?;
    let json = serde_json_tarstats(&meta);
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

fn serde_json_tarstats(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "{{\"st_size\":{},\"st_mtime\":{},\"st_mtime_ns\":{}}}",
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec()
    )
}

fn store_arguments(index: &SqliteIndex, options: &OpenOptions) -> Result<()> {
    let json = format!(
        "{{\"ignoreZeros\":{},\"gnuIncremental\":{},\"recursive\":{}}}",
        options.ignore_zeros,
        match options.gnu_incremental {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        },
        options.recursive
    );
    index.store_metadata_key_value("arguments", &json)?;
    Ok(())
}

/// Flush threshold for batched SQLite inserts during TAR parse.
const BATCH_FLUSH: usize = 512;

fn pad512(n: u64) -> u64 {
    n.div_ceil(BLOCK_SIZE) * BLOCK_SIZE
}

/// Parsed pax records plus accumulated GNU sparse 0.0 offset/numbytes pairs.
struct PaxParsed {
    map: std::collections::HashMap<String, String>,
    /// Ordered sparse pairs from repeated `GNU.sparse.offset` / `numbytes` (format 0.0).
    sparse_pairs: Vec<(u64, u64)>,
}

/// Parse pax extended header records (`LEN key=value\n` …).
fn parse_pax_records(data: &[u8]) -> PaxParsed {
    let mut map = std::collections::HashMap::new();
    let mut sparse_pairs = Vec::new();
    let mut pending_offset: Option<u64> = None;
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == 0 {
            break;
        }
        let rest = &data[i..];
        let Some(sp) = rest.iter().position(|&b| b == b' ') else {
            break;
        };
        let Ok(len_str) = std::str::from_utf8(&rest[..sp]) else {
            break;
        };
        let Ok(rec_len) = len_str.parse::<usize>() else {
            break;
        };
        if rec_len == 0 || i + rec_len > data.len() {
            break;
        }
        let record = &data[i..i + rec_len];
        if let Some(eq) = record.iter().position(|&b| b == b'=') {
            let key_start = sp + 1;
            if key_start < eq {
                let key = String::from_utf8_lossy(&record[key_start..eq]).into_owned();
                let mut val_end = rec_len;
                if val_end > 0 && record[val_end - 1] == b'\n' {
                    val_end -= 1;
                }
                let val = String::from_utf8_lossy(&record[eq + 1..val_end]).into_owned();
                if key == "GNU.sparse.offset" {
                    pending_offset = val.parse().ok();
                } else if key == "GNU.sparse.numbytes" {
                    if let (Some(off), Ok(len)) = (pending_offset.take(), val.parse::<u64>()) {
                        sparse_pairs.push((off, len));
                    }
                }
                map.insert(key, val);
            }
        }
        i += rec_len;
    }
    PaxParsed { map, sparse_pairs }
}

/// GNU sparse 1.0 map at the start of the data blocks: `N\noff\nlen\n…` then 512-pad.
/// Returns `(map pairs, absolute offset of first content byte)`.
fn parse_sparse_1_0_map<R: Read + Seek>(
    reader: &mut R,
    data_start: u64,
) -> Result<(Vec<(u64, u64)>, u64)> {
    reader.seek(SeekFrom::Start(data_start))?;
    let mut buf = vec![0u8; 512 * 64];
    let n = reader.read(&mut buf)?;
    buf.truncate(n);
    let bytes = buf.as_slice();
    let Some(nl0) = bytes.iter().position(|&b| b == b'\n') else {
        return Err(TarError::Msg("sparse 1.0 map missing count".into()));
    };
    let count: usize = std::str::from_utf8(&bytes[..nl0])
        .unwrap_or("0")
        .trim()
        .parse()
        .unwrap_or(0);
    let mut pos_in_buf = nl0 + 1;
    let mut map = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(nl1) = bytes[pos_in_buf..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let off_s = std::str::from_utf8(&bytes[pos_in_buf..pos_in_buf + nl1]).unwrap_or("0");
        pos_in_buf += nl1 + 1;
        let Some(nl2) = bytes[pos_in_buf..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let len_s = std::str::from_utf8(&bytes[pos_in_buf..pos_in_buf + nl2]).unwrap_or("0");
        pos_in_buf += nl2 + 1;
        let off: u64 = off_s.trim().parse().unwrap_or(0);
        let len: u64 = len_s.trim().parse().unwrap_or(0);
        if off != 0 || len != 0 {
            map.push((off, len));
        }
    }
    let content_off = data_start + pad512(pos_in_buf as u64);
    Ok((map, content_off))
}

fn sparse_map_from_pax(pax: &PaxParsed) -> Vec<(u64, u64)> {
    // 0.1: GNU.sparse.map = "off,len,off,len,..."
    if let Some(m) = pax.map.get("GNU.sparse.map") {
        let nums: Vec<u64> = m.split(',').filter_map(|s| s.trim().parse().ok()).collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i + 1 < nums.len() {
            let off = nums[i];
            let len = nums[i + 1];
            if off != 0 || len != 0 {
                out.push((off, len));
            }
            i += 2;
        }
        return out;
    }
    // 0.0: accumulated pairs
    if !pax.sparse_pairs.is_empty() {
        return pax.sparse_pairs.clone();
    }
    Vec::new()
}

/// Scan headers for GNU dumpdir typeflag `D` (Python `_detect_gnu_incremental`).
fn detect_gnu_incremental<R: Read + Seek>(reader: &mut R, ignore_zeros: bool) -> Result<bool> {
    let old_pos = reader.stream_position()?;
    let result = (|| -> Result<bool> {
        reader.seek(SeekFrom::Start(0))?;
        let mut pos: u64 = 0;
        let mut header = [0u8; 512];
        let mut remaining: u32 = 10_000;
        let t0 = Instant::now();

        loop {
            if remaining == 0 || t0.elapsed().as_secs_f64() > 3.0 {
                return Ok(false);
            }
            reader.seek(SeekFrom::Start(pos))?;
            let n = reader.read(&mut header)?;
            if n < 512 {
                return Ok(false);
            }

            if header.iter().all(|&b| b == 0) {
                pos += BLOCK_SIZE;
                reader.seek(SeekFrom::Start(pos))?;
                let mut next = [0u8; 512];
                let n2 = reader.read(&mut next)?;
                if n2 < 512 || next.iter().all(|&b| b == 0) {
                    if ignore_zeros {
                        continue;
                    }
                    return Ok(false);
                }
                // Zero block then non-zero without ignore_zeros → end of archive.
                return Ok(false);
            }

            let typeflag = header[156];
            if typeflag == b'D' {
                return Ok(true);
            }
            remaining -= 1;

            let size = parse_octal(&header[124..136]).unwrap_or(0);
            pos = pos + BLOCK_SIZE + pad512(size);
        }
    })();
    reader.seek(SeekFrom::Start(old_pos))?;
    result
}

/// Strip GNU incremental octal-timestamp prefix when it matches the raw ustar prefix field.
///
/// Python: `_fix_incremental_backup_name_prefixes`. Also requires the first path component
/// to look like an octal timestamp (digits 0–7 only).
fn fix_incremental_backup_name_prefixes(name: &str, header: &[u8; 512]) -> String {
    let Some((prefix, rest)) = name.split_once('/') else {
        return name.to_string();
    };
    if prefix.is_empty() {
        return name.to_string();
    }
    // Incremental timestamp prefixes are octal digit strings.
    if !prefix.bytes().all(|b| b.is_ascii_digit() && b <= b'7') {
        return name.to_string();
    }
    let encoded = prefix.as_bytes();
    let raw_prefix = &header[345..500];
    // Match first C-string in the 155-byte prefix field (may hold two timestamps).
    if raw_prefix.starts_with(encoded) && raw_prefix.get(encoded.len()) == Some(&0) {
        return rest.to_string();
    }
    name.to_string()
}

/// Returns whether the archive was treated as GNU incremental (`isGnuIncremental`).
fn parse_tar_into_index<R: Read + Seek>(
    reader: &mut R,
    index: &SqliteIndex,
    options: &OpenOptions,
) -> Result<bool> {
    let mut pos: u64 = 0;
    let mut header = [0u8; 512];
    let mut generated_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut batch: Vec<FileRow> = Vec::with_capacity(BATCH_FLUSH);
    let mut pax_global: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut pax_pending: PaxParsed = PaxParsed {
        map: std::collections::HashMap::new(),
        sparse_pairs: Vec::new(),
    };
    let mut pax_header_start: Option<u64> = None;

    let mut is_gnu_incremental = match options.gnu_incremental {
        Some(v) => v,
        None => detect_gnu_incremental(reader, options.ignore_zeros)?,
    };

    let flush = |batch: &mut Vec<FileRow>| -> Result<()> {
        if !batch.is_empty() {
            index.insert_files_batch(batch)?;
            batch.clear();
        }
        Ok(())
    };

    loop {
        reader.seek(SeekFrom::Start(pos))?;
        let n = reader.read(&mut header)?;
        if n == 0 {
            break;
        }
        if n < 512 {
            break;
        }

        if header.iter().all(|&b| b == 0) {
            if options.ignore_zeros {
                pos += BLOCK_SIZE;
                continue;
            }
            pos += BLOCK_SIZE;
            reader.seek(SeekFrom::Start(pos))?;
            let mut next = [0u8; 512];
            let n2 = reader.read(&mut next)?;
            if n2 < 512 || next.iter().all(|&b| b == 0) {
                break;
            }
            break;
        }

        let size = parse_octal(&header[124..136]).unwrap_or(0);
        let mtime = parse_octal(&header[136..148]).unwrap_or(0) as f64;
        let mode_bits = parse_octal(&header[100..108]).unwrap_or(0o644) as u32;
        let uid = parse_octal(&header[108..116]).unwrap_or(0) as i64;
        let gid = parse_octal(&header[116..124]).unwrap_or(0) as i64;
        let typeflag = header[156];
        let linkname = cstr_field_encoded(&header[157..257], &options.encoding);

        // PAX extended / global headers — apply to next file (or global).
        if typeflag == b'x' || typeflag == b'g' {
            let body_off = pos + BLOCK_SIZE;
            let mut body = vec![0u8; size as usize];
            reader.seek(SeekFrom::Start(body_off))?;
            if size > 0 {
                reader.read_exact(&mut body)?;
            }
            let recs = parse_pax_records(&body);
            if typeflag == b'g' {
                pax_global.extend(recs.map);
            } else {
                pax_pending = recs;
                pax_header_start = Some(pos);
            }
            pos = body_off + pad512(size);
            continue;
        }

        // GNU long name / long link
        if typeflag == b'L' || typeflag == b'K' {
            let data_off_long = pos + BLOCK_SIZE;
            let mut long = vec![0u8; size as usize];
            reader.seek(SeekFrom::Start(data_off_long))?;
            if size > 0 {
                reader.read_exact(&mut long)?;
            }
            while long.last() == Some(&0) {
                long.pop();
            }
            let long_str = decode_bytes(&long, &options.encoding);
            pos = data_off_long + pad512(size);
            if typeflag == b'L' {
                pax_pending.map.insert("path".into(), long_str);
            } else {
                pax_pending.map.insert("linkpath".into(), long_str);
            }
            continue;
        }

        // Merge pax for this member.
        let mut pax_map = pax_global.clone();
        let pending = std::mem::replace(
            &mut pax_pending,
            PaxParsed {
                map: std::collections::HashMap::new(),
                sparse_pairs: Vec::new(),
            },
        );
        pax_map.extend(pending.map.iter().map(|(k, v)| (k.clone(), v.clone())));
        let pax_for_sparse = PaxParsed {
            map: pax_map.clone(),
            sparse_pairs: pending.sparse_pairs,
        };
        let member_header_start = pax_header_start.take().unwrap_or(pos);

        let mut name = if let Some(p) = pax_map.get("path") {
            p.clone()
        } else if let Some(p) = pax_map.get("GNU.sparse.name") {
            p.clone()
        } else {
            parse_name(&header, &options.encoding)
        };
        let linkname = pax_map.get("linkpath").cloned().unwrap_or(linkname);
        let mtime = pax_map
            .get("mtime")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(mtime);

        // Dumpdir members mark GNU incremental archives (Python `_process_tar_info`).
        if typeflag == b'D' && !is_gnu_incremental {
            is_gnu_incremental = true;
        }

        if is_gnu_incremental {
            name = fix_incremental_backup_name_prefixes(&name, &header);
        }

        let mut issparse = false;
        let mut logical_size = size;
        let mut data_off = pos + BLOCK_SIZE;
        let mut on_tape = size; // bytes to skip after ustar header (size field)

        // Old GNU sparse typeflag 'S'
        if typeflag == b'S' {
            issparse = true;
            logical_size = parse_octal(&header[483..495]).unwrap_or(size);
            let mut is_extended = header[482] != 0;
            while is_extended {
                let mut ext = [0u8; 512];
                reader.seek(SeekFrom::Start(data_off))?;
                reader.read_exact(&mut ext)?;
                is_extended = ext[504] != 0;
                data_off += BLOCK_SIZE;
            }
            on_tape = size;
        }

        // PAX GNU sparse 0.0 / 0.1 / 1.0
        let is_pax_sparse = pax_map.contains_key("GNU.sparse.size")
            || pax_map.contains_key("GNU.sparse.realsize")
            || pax_map.contains_key("GNU.sparse.map")
            || pax_map.get("GNU.sparse.major").map(|s| s.as_str()) == Some("1")
            || !pax_for_sparse.sparse_pairs.is_empty();
        if is_pax_sparse {
            issparse = true;
            if let Some(n) = pax_map.get("GNU.sparse.name") {
                name = n.clone();
            }
            logical_size = pax_map
                .get("GNU.sparse.realsize")
                .or_else(|| pax_map.get("GNU.sparse.size"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(size);
            if pax_map.get("GNU.sparse.major").map(|s| s.as_str()) == Some("1") {
                let (_map, content_off) = parse_sparse_1_0_map(reader, data_off)?;
                data_off = content_off;
                on_tape = size;
            } else {
                let _ = sparse_map_from_pax(&pax_for_sparse);
                on_tape = size;
            }
        }

        // Skip junk placeholder paths if any slipped through.
        if name.contains("PaxHeaders/") || name.starts_with("./PaxHeaders/") {
            pos = pos + BLOCK_SIZE + pad512(on_tape);
            continue;
        }

        if typeflag == b'D' {
            // Dumpdir: regular meta entry (S_IFREG, dumpdir size) + directory entry (size 0).
            push_dumpdir_entries(
                &mut batch,
                &name,
                member_header_start,
                data_off,
                logical_size,
                mtime,
                mode_bits,
                &linkname,
                uid,
                gid,
                &mut generated_dirs,
            )?;
        } else {
            push_entry(
                &mut batch,
                &name,
                member_header_start,
                data_off,
                if typeflag == b'5' || name.ends_with('/') {
                    0
                } else {
                    logical_size
                },
                mtime,
                mode_bits,
                typeflag,
                &linkname,
                uid,
                gid,
                issparse,
                &mut generated_dirs,
            )?;
        }
        if batch.len() >= BATCH_FLUSH {
            flush(&mut batch)?;
        }

        pos = if typeflag == b'5' || typeflag == b'1' || typeflag == b'2' {
            if on_tape == 0 {
                pos + BLOCK_SIZE
            } else {
                // rare: dir with data
                pos + BLOCK_SIZE + pad512(on_tape)
            }
        } else {
            // Always advance by ustar header + padded size field (includes sparse map for 1.0).
            pos + BLOCK_SIZE + pad512(on_tape)
        };
        let _ = mtime; // used
    }

    flush(&mut batch)?;
    Ok(is_gnu_incremental)
}

#[allow(clippy::too_many_arguments)]
fn push_entry(
    batch: &mut Vec<FileRow>,
    full_name: &str,
    offsetheader: u64,
    offset: u64,
    size: u64,
    mtime: f64,
    mode_bits: u32,
    typeflag: u8,
    linkname: &str,
    uid: i64,
    gid: i64,
    issparse: bool,
    generated_dirs: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let is_dir = typeflag == b'5' || full_name.ends_with('/');
    let mut full = full_name.trim_end_matches('/').to_string();
    if full.is_empty() {
        return Ok(());
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

    ensure_parent_dirs(batch, &path, generated_dirs, mtime, uid, gid);

    let ifmt = if is_dir {
        ratarmount_core::S_IFDIR
    } else if typeflag == b'2' {
        ratarmount_core::S_IFLNK
    } else {
        ratarmount_core::S_IFREG
    };
    let mode = (mode_bits & 0o7777) | ifmt;

    // typeflag 'S' is not a digit — store as 0 like Python/sqlite silent conversion, or as byte value.
    // Keep raw byte for diagnostics; Python notes it becomes 0 for non-digit typeflags in some paths.
    let type_store = if typeflag == b'S' {
        b'S' as i64
    } else {
        typeflag as i64
    };

    batch.push(FileRow::new(
        path,
        name,
        offsetheader as i64,
        offset as i64,
        if is_dir { 0 } else { size as i64 },
        mtime,
        mode as i64,
        type_store,
        linkname,
        uid,
        gid,
        false,
        issparse,
        false,
        0,
    ));
    Ok(())
}

/// GNU dumpdir (typeflag `D`): store as regular-file meta plus a directory entry.
///
/// Python `_process_tar_info` adds the dumpdir payload as `S_IFREG` and a second
/// row with `offsetheader + 1`, size 0, and `mode | S_IFDIR` so the name is listable
/// as a directory (newest version wins by higher `offsetheader`).
#[allow(clippy::too_many_arguments)]
fn push_dumpdir_entries(
    batch: &mut Vec<FileRow>,
    full_name: &str,
    offsetheader: u64,
    offset: u64,
    size: u64,
    mtime: f64,
    mode_bits: u32,
    linkname: &str,
    uid: i64,
    gid: i64,
    generated_dirs: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let mut full = full_name.trim_end_matches('/').to_string();
    if full.is_empty() {
        return Ok(());
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

    ensure_parent_dirs(batch, &path, generated_dirs, mtime, uid, gid);

    let mode_reg = ((mode_bits & 0o7777) | ratarmount_core::S_IFREG) as i64;
    let mode_dir = ((mode_bits & 0o7777) | ratarmount_core::S_IFDIR) as i64;
    let type_store = b'D' as i64;

    // Dumpdir metadata (regular file with dumpdir payload size).
    batch.push(FileRow::new(
        path.clone(),
        name.clone(),
        offsetheader as i64,
        offset as i64,
        size as i64,
        mtime,
        mode_reg,
        type_store,
        linkname,
        uid,
        gid,
        false,
        false,
        false,
        0,
    ));

    // Directory side so children can be listed; unique PK via offsetheader+1.
    batch.push(FileRow::new(
        path.clone(),
        name.clone(),
        offsetheader as i64 + 1,
        offset as i64,
        0,
        mtime,
        mode_dir,
        type_store,
        linkname,
        uid,
        gid,
        false,
        false,
        false,
        0,
    ));

    // Prevent `ensure_parent_dirs` from synthesizing a generated parent later.
    let dir_key = if path.is_empty() {
        format!("/{name}")
    } else {
        format!("{path}/{name}")
    };
    generated_dirs.insert(dir_key);

    Ok(())
}

fn ensure_parent_dirs(
    batch: &mut Vec<FileRow>,
    path: &str,
    generated: &mut std::collections::BTreeSet<String>,
    mtime: f64,
    uid: i64,
    gid: i64,
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
        batch.push(FileRow::new(
            parent,
            (*part).to_string(),
            0,
            0,
            0,
            mtime,
            mode,
            b'5' as i64,
            "",
            uid,
            gid,
            false,
            false,
            true,
            0,
        ));
    }
}

/// Build a segmented view from a sparse map + on-tape data cursor.
fn segments_from_map(
    map: &[(u64, u64)],
    mut tar_cursor: u64,
    logical_size: u64,
) -> io::Result<Vec<FileSegment>> {
    let mut segments: Vec<FileSegment> = Vec::new();
    let mut last_end: u64 = 0;
    for &(off, num) in map {
        if off == 0 && num == 0 {
            continue;
        }
        if off < last_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sparse map not sorted / overlapping",
            ));
        }
        if off > last_end {
            segments.push(FileSegment::Zero {
                len: off - last_end,
            });
        }
        if num > 0 {
            segments.push(FileSegment::Data {
                file_offset: tar_cursor,
                len: num,
            });
            tar_cursor += num;
        }
        last_end = off + num;
    }
    if last_end < logical_size {
        segments.push(FileSegment::Zero {
            len: logical_size - last_end,
        });
    }
    Ok(segments)
}

/// Open a sparse member: re-read map from old GNU `S` or PAX 0.0/0.1/1.0 headers.
fn open_sparse_member<R: Read + Seek + Send + 'static>(
    mut file: R,
    header_offset: u64,
    data_offset: u64,
    logical_size: u64,
) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
    let mut pos = header_offset;
    let mut header = [0u8; 512];
    file.seek(SeekFrom::Start(pos))?;
    file.read_exact(&mut header)?;
    let mut pax = PaxParsed {
        map: std::collections::HashMap::new(),
        sparse_pairs: Vec::new(),
    };

    // Optional PAX 'x' header before the file header.
    if header[156] == b'x' {
        let size = parse_octal(&header[124..136]).unwrap_or(0);
        let body_off = pos + BLOCK_SIZE;
        let mut body = vec![0u8; size as usize];
        file.seek(SeekFrom::Start(body_off))?;
        if size > 0 {
            file.read_exact(&mut body)?;
        }
        pax = parse_pax_records(&body);
        pos = body_off + pad512(size);
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(&mut header)?;
    }

    let typeflag = header[156];
    let mut real_size = logical_size;
    for key in ["GNU.sparse.realsize", "GNU.sparse.size"] {
        if let Some(v) = pax.map.get(key) {
            if let Ok(n) = v.parse::<u64>() {
                real_size = n;
            }
        }
    }
    if typeflag == b'S' {
        real_size = parse_octal(&header[483..495]).unwrap_or(real_size);
    }

    let mut map: Vec<(u64, u64)> = Vec::new();
    let mut content_off = pos + BLOCK_SIZE;

    if typeflag == b'S' {
        for i in 0..4 {
            let base = 386 + i * 24;
            let off = parse_octal(&header[base..base + 12]).unwrap_or(0);
            let num = parse_octal(&header[base + 12..base + 24]).unwrap_or(0);
            if num > 0 || off > 0 {
                map.push((off, num));
            }
        }
        let mut is_extended = header[482] != 0;
        while is_extended {
            let mut ext = [0u8; 512];
            file.seek(SeekFrom::Start(content_off))?;
            file.read_exact(&mut ext)?;
            for i in 0..21 {
                let base = i * 24;
                if base + 24 > 504 {
                    break;
                }
                let off = parse_octal(&ext[base..base + 12]).unwrap_or(0);
                let num = parse_octal(&ext[base + 12..base + 24]).unwrap_or(0);
                if off != 0 || num != 0 {
                    map.push((off, num));
                }
            }
            is_extended = ext[504] != 0;
            content_off += BLOCK_SIZE;
        }
    } else if pax.map.get("GNU.sparse.major").map(|s| s.as_str()) == Some("1") {
        let (m, c) = parse_sparse_1_0_map(&mut file, content_off)
            .map_err(|e| io::Error::other(e.to_string()))?;
        map = m;
        content_off = c;
    } else {
        map = sparse_map_from_pax(&pax);
        if data_offset > 0 {
            content_off = data_offset;
        }
    }

    // If reparse found no map, fall back to contiguous slice of logical size.
    if map.is_empty() {
        let stencil = StenciledFile::new(file, vec![(data_offset.max(content_off), real_size)]);
        return Ok(Box::new(stencil));
    }

    let segments = segments_from_map(&map, content_off, real_size)?;
    Ok(Box::new(SegmentedFile::new(file, segments)))
}

fn parse_name(header: &[u8; 512], encoding: &str) -> String {
    let prefix = cstr_field_encoded(&header[345..500], encoding);
    let name = cstr_field_encoded(&header[0..100], encoding);
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

/// NUL-terminated header field as UTF-8 (for octal / binary-safe numeric fields).
fn cstr_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// NUL-terminated field decoded with the configured archive encoding (`-e`).
fn cstr_field_encoded(bytes: &[u8], encoding: &str) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    decode_bytes(&bytes[..end], encoding)
}

/// Decode archive path/name bytes using Python-compatible encoding labels.
fn decode_bytes(bytes: &[u8], encoding: &str) -> String {
    let enc = encoding.trim();
    if enc.is_empty()
        || enc.eq_ignore_ascii_case("utf-8")
        || enc.eq_ignore_ascii_case("utf8")
        || enc.eq_ignore_ascii_case("ascii")
    {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    // Common aliases Python accepts
    let lowered = enc.to_ascii_lowercase();
    let label: &str = match lowered.as_str() {
        "latin1" | "latin-1" | "iso-8859-1" | "iso8859-1" => "iso-8859-1",
        "cp1252" | "windows-1252" => "windows-1252",
        "cp437" => "ibm437",
        other => other,
    };
    if let Some(enc) = encoding_rs::Encoding::for_label(label.as_bytes()) {
        let (cow, _, _) = enc.decode(bytes);
        cow.into_owned()
    } else {
        // Unknown label: fall back to lossy UTF-8 rather than failing the whole archive.
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn parse_octal(bytes: &[u8]) -> Option<u64> {
    let s = cstr_field(bytes);
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
        return parse_base256(bytes);
    }
    u64::from_str_radix(s, 8).ok()
}

fn parse_base256(bytes: &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let b = if i == 0 { b & 0x7f } else { b };
        v = (v << 8) | u64::from(b);
    }
    Some(v)
}

/// Single decompressed file presented as a mount (Python SingleFileMountSource).
pub struct SingleFileMountSource {
    name: String,
    size: u64,
    data_path: PathBuf,
    _materialised: Option<NamedTempFile>,
    mtime: f64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl SingleFileMountSource {
    pub fn new(
        name: String,
        data_path: PathBuf,
        size: u64,
        materialised: Option<NamedTempFile>,
    ) -> io::Result<Self> {
        let meta = std::fs::metadata(&data_path)?;
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            name,
            size,
            data_path,
            _materialised: materialised,
            mtime: meta.mtime() as f64,
            mode: ratarmount_core::S_IFREG | 0o644,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        })
    }

    fn file_info(&self) -> FileInfo {
        FileInfo {
            size: self.size,
            mtime: self.mtime,
            mode: self.mode,
            linkname: String::new(),
            uid: self.uid,
            gid: self.gid,
            userdata: vec![UserData::Tar(SQLiteIndexedTarUserData {
                offset: 0,
                offsetheader: None,
                istar: false,
                issparse: false,
                isgenerated: false,
                recursiondepth: 0,
            })],
        }
    }
}

impl MountSource for SingleFileMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if path != "/" {
            return None;
        }
        let mut map = std::collections::BTreeMap::new();
        map.insert(self.name.clone(), self.file_info());
        Some(ListResult::Infos(map))
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(ratarmount_core::create_root_file_info());
        }
        if path == format!("/{}", self.name) || path.trim_start_matches('/') == self.name {
            return Some(self.file_info());
        }
        None
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
        let file = File::open(&self.data_path)?;
        Ok(Box::new(StenciledFile::new(file, vec![(0, self.size)])))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn multi_version_count_updated_file() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = Path::new(&root).join("tests/updated-file.tar");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &path,
            &path,
            Some(&idx),
            &OpenOptions::default(),
            "0.1.0",
            &mut mat,
        )
        .unwrap();
        assert_eq!(m.versions("/foo/fighter/ufo"), 3);
        let latest = m.lookup("/foo/fighter/ufo", 0).unwrap();
        let oldest = m.lookup("/foo/fighter/ufo", 1).unwrap();
        assert_ne!(latest.size, oldest.size);
    }

    #[test]
    fn index_simple_tar_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("t.tar");
        let src = dir.path().join("data");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("hello.txt"), b"hello world\n").unwrap();
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&src)
            .arg("hello.txt")
            .status()
            .expect("tar");
        assert!(status.success());

        let idx_path = dir.path().join("t.tar.index.sqlite");
        let opts = OpenOptions::default();
        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &tar_path,
            &tar_path,
            Some(&idx_path),
            &opts,
            "0.1.0",
            &mut mat,
        )
        .expect("create index");
        let fi = m.lookup("/hello.txt", 0).expect("lookup hello");
        assert_eq!(fi.size, 12);
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world\n");
    }

    #[test]
    fn sparse_fixtures_pax_and_gnu() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        for name in [
            "sparse.gnu.tar",
            "sparse.pax.sparse-0.0.tar",
            "sparse.pax.sparse-0.1.tar",
            "sparse.pax.sparse-1.0.tar",
        ] {
            let path = std::path::PathBuf::from(&root).join("tests").join(name);
            if !path.exists() {
                eprintln!("skip missing {name}");
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let idx = dir.path().join("i.sqlite");
            let mut mat = None;
            let m = SqliteIndexedTar::create_index(
                &path,
                &path,
                Some(&idx),
                &OpenOptions::default(),
                "0.1.0",
                &mut mat,
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Must not expose PaxHeaders / GNUSparseFile placeholders as real content names.
            let root_list = m.list("/").expect("root");
            if let ListResult::Infos(map) = root_list {
                for k in map.keys() {
                    assert!(
                        !k.contains("PaxHeaders") && !k.starts_with("GNUSparseFile"),
                        "{name}: unexpected entry {k}"
                    );
                }
            }
            let fi = m
                .lookup("/sparse-512B", 0)
                .unwrap_or_else(|| panic!("{name}: missing sparse-512B"));
            assert_eq!(fi.size, 512, "{name} logical size");
            let ud = tar_userdata(&fi).unwrap();
            assert!(ud.issparse, "{name} should be sparse");
            let mut r = m.open(&fi, 0).unwrap();
            let mut buf = vec![0u8; 512];
            r.read_exact(&mut buf).unwrap();
            assert!(buf.iter().all(|&b| b == 0), "{name}: 512B should be holes");

            let fi2 = m.lookup("/sparse-513B", 0).expect("sparse-513B");
            assert_eq!(fi2.size, 513);
            let mut r = m.open(&fi2, 0).unwrap();
            let mut buf = vec![0u8; 513];
            r.read_exact(&mut buf).unwrap();
            assert!(buf[..512].iter().all(|&b| b == 0));
            // one data byte at offset 512
            assert_ne!(buf[512], 0, "{name}: expected data byte at 512");
        }
    }

    #[test]
    fn index_gnu_sparse_tar() {
        // GNU tar --sparse stores typeflag 'S' members with hole maps.
        let dir = tempfile::tempdir().unwrap();
        let sparse_path = dir.path().join("holey.bin");
        // 1 MiB hole + 8 bytes data + 1 MiB hole → logical ~2MiB+8, tiny on disk.
        let status = Command::new("truncate")
            .args(["-s", "1048576"])
            .arg(&sparse_path)
            .status();
        if status.map(|s| !s.success()).unwrap_or(true) {
            eprintln!("skip: truncate not available");
            return;
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&sparse_path)
                .unwrap();
            f.write_all(b"SPARSE!!").unwrap();
        }
        let status = Command::new("truncate")
            .args(["-s", "2097160"]) // 2*1MiB + 8
            .arg(&sparse_path)
            .status()
            .expect("truncate grow");
        assert!(status.success());

        let tar_path = dir.path().join("sparse.tar");
        let status = Command::new("tar")
            .args(["--sparse", "-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(dir.path())
            .arg("holey.bin")
            .status()
            .expect("tar --sparse");
        if !status.success() {
            eprintln!("skip: tar --sparse failed");
            return;
        }

        let idx_path = dir.path().join("sparse.tar.index.sqlite");
        let opts = OpenOptions::default();
        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &tar_path,
            &tar_path,
            Some(&idx_path),
            &opts,
            "0.1.0",
            &mut mat,
        )
        .expect("create index");
        let fi = m.lookup("/holey.bin", 0).expect("lookup sparse");
        assert!(
            fi.size >= 2_097_160,
            "expected logical sparse size, got {}",
            fi.size
        );
        let ud = tar_userdata(&fi).expect("userdata");
        // If tar used sparse format, issparse should be set; some tars may store non-sparse.
        let mut r = m.open(&fi, 0).unwrap();
        r.seek(SeekFrom::Start(1_048_576)).unwrap();
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, b"SPARSE!!", "data at hole boundary");
        if ud.issparse {
            r.seek(SeekFrom::Start(0)).unwrap();
            let mut z = [0u8; 16];
            r.read_exact(&mut z).unwrap();
            assert!(z.iter().all(|&b| b == 0), "leading hole should be zeros");
        }
    }

    fn py_test_root() -> PathBuf {
        PathBuf::from(
            std::env::var("RATARMOUNT_PY_ROOT")
                .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into()),
        )
    }

    fn open_fixture(name: &str, gnu: Option<bool>) -> Option<SqliteIndexedTar> {
        let path = py_test_root().join("tests").join(name);
        if !path.exists() {
            eprintln!("skip missing fixture {name}");
            return None;
        }
        let opts = OpenOptions {
            gnu_incremental: gnu,
            ..OpenOptions::default()
        };
        let mut mat = None;
        Some(
            SqliteIndexedTar::create_index(&path, &path, None, &opts, "0.1.0", &mut mat)
                .unwrap_or_else(|e| panic!("{name}: {e}")),
        )
    }

    #[test]
    fn gnu_incremental_detect_dumpdir_strips_prefix() {
        // incremental-backup.level.0.tar has typeflag 'D' → auto-detect strips octal prefixes.
        let Some(m) = open_fixture("incremental-backup.level.0.tar", None) else {
            return;
        };
        let meta = m.index().metadata().unwrap();
        assert_eq!(
            meta.get("isGnuIncremental").map(String::as_str),
            Some("1"),
            "metadata isGnuIncremental"
        );

        let root = m.list("/").expect("root list");
        if let ListResult::Infos(map) = root {
            assert!(map.contains_key("foo"), "dir foo from dumpdir: {:?}", map.keys());
            assert!(
                map.contains_key("root-file.txt"),
                "root-file.txt: {:?}",
                map.keys()
            );
            assert!(
                !map.keys().any(|k| k.chars().all(|c| c.is_ascii_digit())),
                "octal timestamp dirs should be stripped: {:?}",
                map.keys()
            );
            let foo = map.get("foo").unwrap();
            assert_eq!(
                foo.mode & ratarmount_core::S_IFMT,
                ratarmount_core::S_IFDIR,
                "lookup /foo is directory"
            );
            assert_eq!(foo.size, 0);
        } else {
            panic!("expected Infos");
        }

        // Dumpdir also creates a regular-file version (size > 0).
        assert_eq!(m.versions("/foo"), 2);
        let dump_meta = m.lookup("/foo", 1).expect("older dumpdir version");
        assert_eq!(
            dump_meta.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFREG
        );
        assert!(dump_meta.size > 0);

        for child in ["1", "2", "3"] {
            let fi = m
                .lookup(&format!("/foo/{child}"), 0)
                .unwrap_or_else(|| panic!("missing /foo/{child}"));
            assert!(fi.size > 0);
        }

        let fi = m.lookup("/root-file.txt", 0).expect("root-file.txt");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    #[test]
    fn gnu_incremental_force_strips_single_file() {
        // No typeflag D — only forced gnu_incremental=Some(true) strips the prefix.
        let Some(m) = open_fixture("single-file-incremental.tar", Some(true)) else {
            return;
        };
        let meta = m.index().metadata().unwrap();
        assert_eq!(meta.get("isGnuIncremental").map(String::as_str), Some("1"));

        assert!(m.lookup("/foo", 0).is_some(), "stripped path /foo");
        assert!(
            m.lookup("/14130613451/foo", 0).is_none(),
            "prefixed path should not exist when forced"
        );
        let fi = m.lookup("/foo", 0).unwrap();
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"bar\n");
    }

    #[test]
    fn gnu_incremental_off_keeps_prefix_without_dumpdir() {
        let Some(m) = open_fixture("single-file-incremental.tar", Some(false)) else {
            return;
        };
        let meta = m.index().metadata().unwrap();
        assert_eq!(meta.get("isGnuIncremental").map(String::as_str), Some("0"));
        assert!(m.lookup("/14130613451/foo", 0).is_some());
        assert!(m.lookup("/foo", 0).is_none());
    }

    #[test]
    fn gnu_incremental_detect_without_dumpdir_keeps_prefix() {
        // Auto-detect finds no 'D' → leave names as tarfile-joined prefix/name.
        let Some(m) = open_fixture("single-file-incremental.tar", None) else {
            return;
        };
        let meta = m.index().metadata().unwrap();
        assert_eq!(meta.get("isGnuIncremental").map(String::as_str), Some("0"));
        assert!(m.lookup("/14130613451/foo", 0).is_some());
    }

    #[test]
    fn gnu_incremental_force_absolute_path() {
        let Some(m) = open_fixture("absolute-file-incremental.tar", Some(true)) else {
            return;
        };
        assert!(m.lookup("/tmp/foo", 0).is_some());
        assert!(m.lookup("/14130612002/tmp/foo", 0).is_none());
    }

    #[test]
    fn gnu_incremental_mockup_does_not_strip_without_raw_prefix() {
        // Mockup stores the timestamp in the name field with empty ustar prefix → do not strip.
        let Some(m) = open_fixture("single-file-incremental-mockup.tar", Some(true)) else {
            return;
        };
        assert!(
            m.lookup("/14130613451/foo", 0).is_some(),
            "mockup must keep embedded prefix path"
        );
        assert!(m.lookup("/foo", 0).is_none());
    }

    #[test]
    fn gnu_incremental_level1_moved_file() {
        let Some(m) = open_fixture("incremental-backup.level.1.tar", None) else {
            return;
        };
        assert_eq!(
            m.index()
                .metadata()
                .unwrap()
                .get("isGnuIncremental")
                .map(String::as_str),
            Some("1")
        );
        assert!(m.lookup("/foo/3", 0).is_some());
        assert!(m.lookup("/foo/moved", 0).is_some());
        let fi = m.lookup("/foo", 0).expect("foo dir");
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);
    }

    #[test]
    fn fix_incremental_name_helpers() {
        let mut header = [0u8; 512];
        let prefix = b"14130613451";
        header[345..345 + prefix.len()].copy_from_slice(prefix);
        // second timestamp + NULs already zero
        assert_eq!(
            fix_incremental_backup_name_prefixes("14130613451/foo", &header),
            "foo"
        );
        assert_eq!(
            fix_incremental_backup_name_prefixes("14130613451//tmp/foo", &header),
            "/tmp/foo"
        );
        // non-octal first component
        assert_eq!(
            fix_incremental_backup_name_prefixes("notoctal/foo", &header),
            "notoctal/foo"
        );
        // mismatch vs raw prefix
        assert_eq!(
            fix_incremental_backup_name_prefixes("99999999999/foo", &header),
            "99999999999/foo"
        );
        // empty raw prefix (mockup style)
        let empty = [0u8; 512];
        assert_eq!(
            fix_incremental_backup_name_prefixes("14130613451/foo", &empty),
            "14130613451/foo"
        );
    }
}
