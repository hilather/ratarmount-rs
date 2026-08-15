//! CPIO archive support: newc/crc (070701/070702), portable ASCII odc (070707),
//! and old binary (0x71c7 LE/BE). Random access via [`StenciledFile`].
//!
//! Nested archives can open from any seekable stream via
//! [`CpioMountSource::open_from_reader`] (no temp spool).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratarmount_compress::{SeekRead, StenciledFile};
use ratarmount_core::{
    normpath, CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "CpioMountSource";
const NEWC_MAGIC: &[u8; 6] = b"070701";
const CRC_MAGIC: &[u8; 6] = b"070702";
const ODC_MAGIC: &[u8; 6] = b"070707";
const BIN_MAGIC_LE: &[u8; 2] = b"\xc7\x71";
const BIN_MAGIC_BE: &[u8; 2] = b"\x71\xc7";

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

enum CpioKind {
    Newc,
    Odc,
    BinLe,
    BinBe,
}

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
            .map_err(|_| io::Error::other("shared cpio reader poisoned"))?;
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
                    .map_err(|_| io::Error::other("shared cpio reader poisoned"))?;
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

/// Where CPIO archive bytes live for open/read.
enum ContentBackend {
    /// On-disk path: `File::open` per member open (current path-based behavior).
    Path(PathBuf),
    /// Any `Read + Seek` shared under a mutex (nested / in-memory / remote).
    Shared(Arc<SharedSeekReader>),
}

impl ContentBackend {
    fn open_reader(&self) -> io::Result<ContentReader> {
        match self {
            Self::Path(p) => Ok(ContentReader::File(File::open(p)?)),
            Self::Shared(s) => Ok(ContentReader::Shared(s.open_reader())),
        }
    }
}

enum ContentReader {
    File(File),
    Shared(PositionedSeekReader),
}

impl Read for ContentReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(f) => f.read(buf),
            Self::Shared(r) => r.read(buf),
        }
    }
}

impl Seek for ContentReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(f) => f.seek(pos),
            Self::Shared(r) => r.seek(pos),
        }
    }
}

pub struct CpioMountSource {
    /// User-facing path or virtual label (logs / tarstats).
    #[allow(dead_code)]
    archive_path: PathBuf,
    backend: ContentBackend,
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
                        Err(e) => eprintln!("info: could not load cpio index ({e}); rebuilding"),
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

    /// Index and open a CPIO archive from any `Read + Seek` source.
    ///
    /// Intended for nested AutoMount / in-memory archives: no on-disk archive path is
    /// required. `archive_label` is used for logs and index metadata (may be a virtual
    /// name). The reader is retained under a mutex for concurrent stencil opens.
    ///
    /// `index_path`: `Some(path)` for on-disk index, `None` for `:memory:` (also when
    /// `options.index_in_memory` is set).
    pub fn open_from_reader<R>(
        mut reader: R,
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

        let size = reader.seek(SeekFrom::End(0)).unwrap_or(0);
        reader.seek(SeekFrom::Start(0))?;

        let kind = detect_kind(&mut reader)?;
        reader.seek(SeekFrom::Start(0))?;

        let index = SqliteIndex::create_writable_for_open(index_path_buf.as_deref(), options)?;
        index.begin_write()?;
        let mut generated = std::collections::BTreeSet::new();

        match kind {
            CpioKind::Newc => parse_newc(&mut reader, &index, &mut generated)?,
            CpioKind::Odc => parse_odc(&mut reader, &index, &mut generated)?,
            CpioKind::BinLe => parse_bin(&mut reader, &index, &mut generated, true)?,
            CpioKind::BinBe => parse_bin(&mut reader, &index, &mut generated, false)?,
        }

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
            backend: ContentBackend::Shared(SharedSeekReader::new(reader)),
            index,
            options: options.clone(),
        })
    }

    /// Open CPIO using an imported durable nested index (skip cold file-table rebuild).
    pub fn open_from_reader_with_durable<R>(
        mut reader: R,
        archive_label: impl AsRef<Path>,
        blob: &ratarmount_index::DurableNestedBlob,
        options: OpenOptions,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        use ratarmount_index::NESTED_FORMAT_CPIO;
        if blob.format != NESTED_FORMAT_CPIO {
            return Err(CpioError::Msg(format!(
                "durable nested blob format {} is not cpio",
                blob.format
            )));
        }
        let archive_path = archive_label.as_ref().to_path_buf();
        reader.seek(SeekFrom::Start(0))?;
        let index = SqliteIndex::create_compact_from_nested_blob(blob)?;
        eprintln!(
            "nested durable index: imported CPIO file table for {} ({} rows)",
            archive_path.display(),
            index.file_count().unwrap_or(0)
        );
        Ok(Self {
            archive_path,
            backend: ContentBackend::Shared(SharedSeekReader::new(reader)),
            index,
            options,
        })
    }

    /// Export compact nested durable blob.
    pub fn export_nested_durable(
        &self,
        fingerprint: ratarmount_index::NestedBodyFingerprint,
    ) -> Result<Vec<u8>> {
        use ratarmount_index::NESTED_FORMAT_CPIO;
        self.index
            .export_nested_blob(NESTED_FORMAT_CPIO, fingerprint, vec![])
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
            backend: ContentBackend::Path(archive_path.to_path_buf()),
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
        let kind = detect_kind(&mut file)?;
        file.seek(SeekFrom::Start(0))?;

        let index = SqliteIndex::create_writable_for_open(index_path, options)?;
        index.begin_write()?;
        let mut generated = std::collections::BTreeSet::new();

        match kind {
            CpioKind::Newc => parse_newc(&mut file, &index, &mut generated)?,
            CpioKind::Odc => parse_odc(&mut file, &index, &mut generated)?,
            CpioKind::BinLe => parse_bin(&mut file, &index, &mut generated, true)?,
            CpioKind::BinBe => parse_bin(&mut file, &index, &mut generated, false)?,
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
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            backend: ContentBackend::Path(archive_path.to_path_buf()),
            index,
            options: options.clone(),
        })
    }
}

impl MountSource for CpioMountSource {
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
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing cpio userdata"))?;
        let reader = self.backend.open_reader()?;
        Ok(Box::new(StenciledFile::new(
            reader,
            vec![(ud.offset, file_info.size)],
        )))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn detect_kind<R: Read + Seek>(file: &mut R) -> Result<CpioKind> {
    let mut magic = [0u8; 6];
    let n = file.read(&mut magic)?;
    if n >= 6 {
        if &magic == NEWC_MAGIC || &magic == CRC_MAGIC {
            return Ok(CpioKind::Newc);
        }
        if &magic == ODC_MAGIC {
            return Ok(CpioKind::Odc);
        }
    }
    if n >= 2 {
        if &magic[..2] == BIN_MAGIC_LE {
            return Ok(CpioKind::BinLe);
        }
        if &magic[..2] == BIN_MAGIC_BE {
            return Ok(CpioKind::BinBe);
        }
    }
    Err(CpioError::Msg(format!("unrecognized cpio magic {magic:?}")))
}

fn parse_newc<R: Read + Seek>(
    file: &mut R,
    index: &SqliteIndex,
    generated: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    loop {
        let header_offset = file.stream_position()?;
        let mut magic = [0u8; 6];
        match file.read(&mut magic)? {
            0 => break,
            n if n < 6 => return Err(CpioError::Msg("truncated cpio magic".into())),
            _ => {}
        }
        if magic.iter().all(|&b| b == 0) {
            break;
        }
        if &magic != NEWC_MAGIC && &magic != CRC_MAGIC {
            return Err(CpioError::Msg(format!("unsupported cpio magic {magic:?}")));
        }

        let mut fields = [0u8; 104];
        file.read_exact(&mut fields)?;
        let mode = hex_u32(&fields[8..16])?;
        let uid = hex_u32(&fields[16..24])?;
        let gid = hex_u32(&fields[24..32])?;
        let mtime = hex_u32(&fields[40..48])? as f64;
        let filesize = hex_u32(&fields[48..56])? as u64;
        let namesize = hex_u32(&fields[88..96])? as usize;

        let mut name_buf = vec![0u8; namesize];
        file.read_exact(&mut name_buf)?;
        while name_buf.last() == Some(&0) {
            name_buf.pop();
        }
        let name = String::from_utf8_lossy(&name_buf).into_owned();

        let header_and_name = 110 + namesize;
        let name_pad = (4 - (header_and_name % 4)) % 4;
        if name_pad > 0 {
            file.seek(SeekFrom::Current(name_pad as i64))?;
        }
        let data_offset = file.stream_position()?;

        if name == "TRAILER!!!" {
            break;
        }

        insert_entry(
            index,
            generated,
            &name,
            mode,
            mtime,
            filesize,
            header_offset,
            data_offset,
            uid,
            gid,
            file,
            4,
        )?;
    }
    Ok(())
}

fn parse_odc<R: Read + Seek>(
    file: &mut R,
    index: &SqliteIndex,
    generated: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    // Portable ASCII odc: 76-byte header (magic 6 + 70 octal fields).
    loop {
        let header_offset = file.stream_position()?;
        let mut magic = [0u8; 6];
        match file.read(&mut magic)? {
            0 => break,
            n if n < 6 => return Err(CpioError::Msg("truncated odc magic".into())),
            _ => {}
        }
        if magic.iter().all(|&b| b == 0) {
            break;
        }
        if &magic != ODC_MAGIC {
            return Err(CpioError::Msg(format!("invalid odc magic {magic:?}")));
        }
        let mut rest = [0u8; 70];
        file.read_exact(&mut rest)?;
        let s = std::str::from_utf8(&rest).map_err(|e| CpioError::Msg(e.to_string()))?;
        // after magic: dev6 ino6 mode6 uid6 gid6 nlink6 rdev6 mtime11 namesize6 filesize11
        let mode = oct_u32(&s[12..18])?;
        let uid = oct_u32(&s[18..24])?;
        let gid = oct_u32(&s[24..30])?;
        let mtime = oct_u64(&s[42..53])? as f64;
        let namesize = oct_u32(&s[53..59])? as usize;
        let filesize = oct_u64(&s[59..70])?;

        let mut name_buf = vec![0u8; namesize];
        file.read_exact(&mut name_buf)?;
        while name_buf.last() == Some(&0) {
            name_buf.pop();
        }
        let name = String::from_utf8_lossy(&name_buf).into_owned();
        let data_offset = file.stream_position()?;

        if name == "TRAILER!!!" {
            break;
        }

        // odc: no padding on name or data
        insert_entry(
            index,
            generated,
            &name,
            mode,
            mtime,
            filesize,
            header_offset,
            data_offset,
            uid,
            gid,
            file,
            1,
        )?;
    }
    Ok(())
}

fn parse_bin<R: Read + Seek>(
    file: &mut R,
    index: &SqliteIndex,
    generated: &mut std::collections::BTreeSet<String>,
    little_endian: bool,
) -> Result<()> {
    loop {
        let header_offset = file.stream_position()?;
        let mut magic = [0u8; 2];
        match file.read(&mut magic)? {
            0 => break,
            n if n < 2 => return Err(CpioError::Msg("truncated binary magic".into())),
            _ => {}
        }
        if magic == [0, 0] {
            break;
        }
        let ok = if little_endian {
            &magic == BIN_MAGIC_LE
        } else {
            &magic == BIN_MAGIC_BE
        };
        if !ok {
            return Err(CpioError::Msg(format!(
                "invalid binary cpio magic {magic:?}"
            )));
        }
        let mut rest = [0u8; 24];
        file.read_exact(&mut rest)?;
        // 12 u16 fields after magic
        let fields: [u16; 12] = if little_endian {
            let mut out = [0u16; 12];
            for i in 0..12 {
                out[i] = u16::from_le_bytes([rest[i * 2], rest[i * 2 + 1]]);
            }
            out
        } else {
            let mut out = [0u16; 12];
            for i in 0..12 {
                out[i] = u16::from_be_bytes([rest[i * 2], rest[i * 2 + 1]]);
            }
            out
        };
        let mode = fields[2] as u32;
        let uid = fields[3] as u32;
        let gid = fields[4] as u32;
        let mtime = (((fields[7] as u32) << 16) | fields[8] as u32) as f64;
        let namesize = fields[9] as usize;
        let filesize = (((fields[10] as u32) << 16) | fields[11] as u32) as u64;

        let mut name_buf = vec![0u8; namesize];
        file.read_exact(&mut name_buf)?;
        while name_buf.last() == Some(&0) {
            name_buf.pop();
        }
        let name = String::from_utf8_lossy(&name_buf).into_owned();
        // Align to even after name
        if file.stream_position()? % 2 == 1 {
            file.seek(SeekFrom::Current(1))?;
        }
        let data_offset = file.stream_position()?;

        if name == "TRAILER!!!" {
            break;
        }

        insert_entry(
            index,
            generated,
            &name,
            mode,
            mtime,
            filesize,
            header_offset,
            data_offset,
            uid,
            gid,
            file,
            2,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_entry<R: Read + Seek>(
    index: &SqliteIndex,
    generated: &mut std::collections::BTreeSet<String>,
    name: &str,
    mode: u32,
    mtime: f64,
    filesize: u64,
    header_offset: u64,
    data_offset: u64,
    uid: u32,
    gid: u32,
    file: &mut R,
    data_align: u64,
) -> Result<()> {
    let is_dir = mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR;
    let is_lnk = mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK;
    let mut linkname = String::new();
    let mut size = filesize;

    if is_lnk && filesize > 0 && filesize < 4096 {
        let mut buf = vec![0u8; filesize as usize];
        file.read_exact(&mut buf)?;
        linkname = String::from_utf8_lossy(&buf).into_owned();
        size = 0;
        let pad = if data_align > 1 {
            (data_align - (filesize % data_align)) % data_align
        } else {
            0
        };
        if pad > 0 {
            file.seek(SeekFrom::Current(pad as i64))?;
        }
    } else {
        let pad = if data_align > 1 {
            (data_align - (filesize % data_align)) % data_align
        } else {
            0
        };
        file.seek(SeekFrom::Current((filesize + pad) as i64))?;
        if is_dir {
            size = 0;
        }
    }

    if name.is_empty() || name == "." {
        return Ok(());
    }

    let full = normpath(name);
    let (path, base) = match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.clone()),
    };
    ensure_parents(index, &path, generated, mtime)?;

    let ifmt = if is_dir {
        ratarmount_core::S_IFDIR
    } else if is_lnk {
        ratarmount_core::S_IFLNK
    } else {
        ratarmount_core::S_IFREG
    };
    let fmode = (mode & 0o7777) | ifmt;

    index.insert_file(
        &path,
        &base,
        header_offset as i64,
        data_offset as i64,
        size as i64,
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
    Ok(())
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

/// Detect any supported CPIO variant (newc/crc/odc/binary) by magic or extension.
pub fn looks_like_cpio(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 6];
        if let Ok(n) = f.read(&mut magic) {
            if n >= 6 && (&magic == NEWC_MAGIC || &magic == CRC_MAGIC || &magic == ODC_MAGIC) {
                return true;
            }
            if n >= 2 && (&magic[..2] == BIN_MAGIC_LE || &magic[..2] == BIN_MAGIC_BE) {
                return true;
            }
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("cpio"))
}

/// Backward-compatible alias.
pub fn looks_like_cpio_newc(path: &Path) -> bool {
    looks_like_cpio(path)
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

fn oct_u32(s: &str) -> Result<u32> {
    u32::from_str_radix(s.trim(), 8).map_err(|e| CpioError::Msg(e.to_string()))
}

fn oct_u64(s: &str) -> Result<u64> {
    u64::from_str_radix(s.trim(), 8).map_err(|e| CpioError::Msg(e.to_string()))
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

fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    // Shared helper: size/mtime + first/last 512 SHA-256 for warm-open fingerprint.
    index.store_tarstats_for_path(path)?;
    Ok(())
}

/// Store tarstats for a path label; if not a real file, use synthetic stats from `size`.
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

    fn py_root() -> PathBuf {
        PathBuf::from(
            std::env::var("RATARMOUNT_PY_ROOT")
                .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into()),
        )
    }

    fn open_and_read_bar(path: &Path) {
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("c.index.sqlite");
        let m = CpioMountSource::open(path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m.lookup("/bar", 0).expect("bar");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }

    /// Build a minimal newc CPIO with one regular file and TRAILER.
    fn build_newc_cpio(name: &str, data: &[u8], mode: u32) -> Vec<u8> {
        fn push_entry(out: &mut Vec<u8>, name: &str, data: &[u8], mode: u32) {
            let namesize = name.len() + 1;
            let filesize = data.len() as u32;
            out.extend_from_slice(b"070701");
            for val in [
                1u32, // ino
                mode,
                0, // uid
                0, // gid
                1, // nlink
                0, // mtime
                filesize,
                0, // devmajor
                0, // devminor
                0, // rdevmajor
                0, // rdevminor
                namesize as u32,
                0, // check
            ] {
                out.extend_from_slice(format!("{val:08X}").as_bytes());
            }
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            let header_and_name = 110 + namesize;
            let name_pad = (4 - (header_and_name % 4)) % 4;
            out.extend(std::iter::repeat_n(0u8, name_pad));
            out.extend_from_slice(data);
            let data_pad = (4 - (data.len() % 4)) % 4;
            out.extend(std::iter::repeat_n(0u8, data_pad));
        }

        let mut out = Vec::new();
        push_entry(&mut out, name, data, mode);
        push_entry(&mut out, "TRAILER!!!", &[], 0);
        out
    }

    #[test]
    fn open_newc_cpio() {
        open_and_read_bar(&py_root().join("tests/single-file.newc.cpio"));
    }

    #[test]
    fn open_odc_cpio() {
        open_and_read_bar(&py_root().join("tests/single-file.odc.cpio"));
    }

    #[test]
    fn open_bin_cpio() {
        open_and_read_bar(&py_root().join("tests/single-file.bin.cpio"));
    }

    #[test]
    fn looks_like_detects_variants() {
        let root = py_root();
        for name in [
            "tests/single-file.newc.cpio",
            "tests/single-file.odc.cpio",
            "tests/single-file.bin.cpio",
            "tests/single-file.crc.cpio",
        ] {
            let p = root.join(name);
            if p.exists() {
                assert!(looks_like_cpio(&p), "{name}");
            }
        }
    }

    #[test]
    fn open_from_reader_newc_list_lookup_seek() {
        // S_IFREG | 0644
        let mode = ratarmount_core::S_IFREG | 0o644;
        let payload = b"hello-cpio-world";
        let bytes = build_newc_cpio("nested/hello.txt", payload, mode);
        let size = bytes.len() as u64;

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let src = CpioMountSource::open_from_reader(
            Cursor::new(bytes),
            "virtual://nested.cpio",
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader");

        // list root / nested
        let root = src.list("/").expect("list /");
        match root {
            ListResult::Infos(infos) => {
                assert!(
                    infos.contains_key("nested"),
                    "root should contain nested dir: {:?}",
                    infos.keys().collect::<Vec<_>>()
                );
            }
            other => panic!("unexpected list result: {other:?}"),
        }

        let fi = src.lookup("/nested/hello.txt", 0).expect("lookup hello");
        assert_eq!(fi.size, payload.len() as u64);

        // full read
        let mut r = src.open(&fi, 0).expect("open member");
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, payload);

        // mid-seek read (no temp files — pure Cursor backend)
        let mut r2 = src.open(&fi, 0).expect("reopen");
        r2.seek(SeekFrom::Start(6)).unwrap();
        let mut mid = [0u8; 4];
        r2.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, b"cpio");

        // seek to end then back
        r2.seek(SeekFrom::End(-5)).unwrap();
        let mut tail = [0u8; 5];
        r2.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, b"world");

        // synthetic label is not a real path; size was recorded for indexing
        let _ = size;
    }

    /// Regression: cheap list_dirents must expose index sizes (readdirplus TTL).
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let mode = ratarmount_core::S_IFREG | 0o644;
        let payload = b"hello-cpio-dirents";
        let bytes = build_newc_cpio("hello.txt", payload, mode);
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let src = CpioMountSource::open_from_reader(
            Cursor::new(bytes),
            "virtual://dirents.cpio",
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader");

        let dents = src.list_dirents("/").expect("dirents");
        let d = dents.iter().find(|e| e.name == "hello.txt").unwrap();
        assert_eq!(d.size, payload.len() as u64);
        assert_eq!(src.lookup("/hello.txt", 0).unwrap().size, d.size);
    }

    fn write_sample_cpio(path: &Path, name: &str, data: &[u8]) {
        let mode = ratarmount_core::S_IFREG | 0o644;
        let bytes = build_newc_cpio(name, data, mode);
        std::fs::write(path, bytes).unwrap();
    }

    /// Regression: open_existing rejects when archive size/mtime no longer match tarstats.
    #[test]
    fn warm_index_rejects_when_archive_size_or_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.cpio");
        write_sample_cpio(&archive, "hello.txt", b"cpio-v1\n");
        let index = dir.path().join("swap.cpio.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src = CpioMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "cpio-v1\n");
        drop(src);
        assert!(index.exists());

        // Matching archive still opens warm.
        CpioMountSource::open_existing(&archive, &index, &opts).expect("warm match must succeed");

        // Replace archive content (size change) while reusing the sibling index path.
        write_sample_cpio(&archive, "hello.txt", b"cpio-v2-longer\n");

        match CpioMountSource::open_existing(&archive, &index, &opts) {
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

    /// Regression: warm CPIO open rebuilds when archive content no longer matches tarstats.
    #[test]
    fn warm_index_rebuilds_when_archive_content_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.cpio");
        write_sample_cpio(&archive, "hello.txt", b"cpio-v1\n");
        let index = dir.path().join("swap.cpio.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src = CpioMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "cpio-v1\n");
        drop(src);
        assert!(index.exists());

        write_sample_cpio(&archive, "hello.txt", b"cpio-v2-longer\n");

        // recreate=false: tarstats mismatch must rebuild, not serve stale member rows.
        let src2 =
            CpioMountSource::open(&archive, Some(&index), &opts, "test", false).expect("warm");
        let fi2 = src2.lookup("/hello.txt", 0).expect("lookup v2");
        let mut buf2 = String::new();
        src2.open(&fi2, 0)
            .unwrap()
            .read_to_string(&mut buf2)
            .unwrap();
        assert_eq!(
            buf2, "cpio-v2-longer\n",
            "must serve new CPIO data after tarstats mismatch rebuild"
        );
    }
}
