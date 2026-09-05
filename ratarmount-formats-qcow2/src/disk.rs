//! QCOW2 v2/v3 header parse and guest-cluster mapping (`Read + Seek` of the
//! virtual disk). Partitioning is the block crate's job.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use flate2::{Decompress, FlushDecompress, Status};
use thiserror::Error;

/// Object-safe `Read + Seek + Send` for the shared image / backing file.
pub(crate) trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

pub const MAGIC: &[u8; 4] = b"QFI\xfb";

const QCOW_OFLAG_COPIED: u64 = 1 << 63;
const QCOW_OFLAG_COMPRESSED: u64 = 1 << 62;
const QCOW_OFLAG_ZERO: u64 = 1;
/// L1/L2 host offset: bits 9–55.
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;

const INCOMPAT_DIRTY: u64 = 1 << 0;
const INCOMPAT_CORRUPT: u64 = 1 << 1;
const INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
const INCOMPAT_COMPRESSION_TYPE: u64 = 1 << 3;
const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;
const INCOMPAT_KNOWN: u64 = INCOMPAT_DIRTY
    | INCOMPAT_CORRUPT
    | INCOMPAT_EXTERNAL_DATA
    | INCOMPAT_COMPRESSION_TYPE
    | INCOMPAT_EXTENDED_L2;

const MIN_HEADER: usize = 72;
const V3_HEADER_MIN: usize = 104;
const MAX_L1_ENTRIES: u32 = 2_097_152;
const MAX_BACKING_NAME: usize = 1024;
const MAX_BACKING_DEPTH: u32 = 16;
const MIN_CLUSTER_BITS: u32 = 9;
const MAX_CLUSTER_BITS: u32 = 21;

#[derive(Debug, Error)]
pub enum Qcow2Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Qcow2Error>;

/// QCOW2 cluster compression (v3 `compression_type`; v2 is always zlib).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Qcow2Compression {
    /// Raw deflate (RFC 1951), called "zlib" in QEMU — **no** zlib wrapper.
    Zlib,
    /// Residual: v1 does not decompress zstd clusters.
    Zstd,
}

/// Parsed QCOW2 header (active L1; snapshots ignored).
#[derive(Clone, Debug)]
pub struct Qcow2Header {
    pub version: u32,
    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    pub backing_file: Option<String>,
    pub compression: Qcow2Compression,
    pub incompatible_features: u64,
}

impl Qcow2Header {
    pub fn cluster_size(&self) -> u64 {
        1u64 << self.cluster_bits
    }

    pub fn l2_entries(&self) -> u64 {
        self.cluster_size() / 8
    }
}

/// Guest-byte view of a QCOW2 image (`Read + Seek` of the virtual disk).
///
/// Clone shares the image mutex and L1; each clone has its own seek cursor.
pub struct Qcow2VirtualDisk {
    inner: Arc<Qcow2Inner>,
    pos: u64,
}

struct Qcow2Inner {
    file: Mutex<Box<dyn SeekRead>>,
    header: Qcow2Header,
    l1: Vec<u64>,
    backing: Option<Backing>,
    l2_cache: Mutex<L2Cache>,
    decode_cache: Mutex<DecodeCache>,
}

struct L2Cache {
    offset: Option<u64>,
    entries: Vec<u64>,
}

struct DecodeCache {
    cluster_idx: Option<u64>,
    data: Vec<u8>,
}

enum Backing {
    Qcow2(Arc<Qcow2Inner>),
    Raw {
        file: Arc<Mutex<Box<dyn SeekRead>>>,
        size: u64,
    },
}

enum Cluster {
    Unallocated,
    Zero,
    Standard { host_offset: u64 },
    Compressed { host_offset: u64, packed_size: u64 },
}

impl Clone for Qcow2VirtualDisk {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            pos: 0,
        }
    }
}

impl Qcow2VirtualDisk {
    pub fn header(&self) -> &Qcow2Header {
        &self.inner.header
    }

    /// Open a QCOW2 image from a host path (resolves relative backing files).
    pub fn open_path(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        Self::open_from_reader(file, path, path.parent())
    }

    /// Open a QCOW2 image from any `Read + Seek` without `/tmp`.
    ///
    /// `backing_dir` is the directory used to resolve a relative backing file
    /// (typically `archive_label.parent()`). Nested virtual labels without a
    /// real parent cannot open relative backing files.
    pub fn open_from_reader<R>(
        mut reader: R,
        archive_label: &Path,
        backing_dir: Option<&Path>,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        reader.seek(SeekFrom::Start(0))?;
        let inner = Qcow2Inner::from_reader(reader, archive_label, backing_dir, 0)?;
        Ok(Self { inner, pos: 0 })
    }
}

impl Qcow2Inner {
    fn from_reader<R>(
        mut reader: R,
        archive_label: &Path,
        backing_dir: Option<&Path>,
        depth: u32,
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        reader.seek(SeekFrom::Start(0))?;
        let header = parse_qcow2_header(&mut reader)?;
        validate_open(&header, archive_label)?;
        // Fail closed on HTTP/NBD before reading L1 so a truncated probe still
        // reports the residual instead of UnexpectedEof.
        if let Some(name) = header.backing_file.as_deref() {
            if is_remote_backing(name) {
                return Err(Qcow2Error::Msg(format!(
                    "qcow2 backing {name:?} is not a local path (HTTP/NBD backing is residual)"
                )));
            }
        }

        reader.seek(SeekFrom::Start(header.l1_table_offset))?;
        let mut l1_bytes = vec![0u8; (header.l1_size as usize).saturating_mul(8)];
        if !l1_bytes.is_empty() {
            reader.read_exact(&mut l1_bytes)?;
        }
        let l1 = l1_bytes
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().expect("chunks_exact 8")))
            .collect();

        let backing = match header.backing_file.as_deref() {
            Some(name) => Some(open_backing(name, backing_dir, depth)?),
            None => None,
        };

        reader.seek(SeekFrom::Start(0))?;
        Ok(Arc::new(Self {
            file: Mutex::new(Box::new(reader) as Box<dyn SeekRead>),
            header,
            l1,
            backing,
            l2_cache: Mutex::new(L2Cache {
                offset: None,
                entries: Vec::new(),
            }),
            decode_cache: Mutex::new(DecodeCache {
                cluster_idx: None,
                data: Vec::new(),
            }),
        }))
    }

    fn lock_file(&self) -> io::Result<std::sync::MutexGuard<'_, Box<dyn SeekRead>>> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("shared qcow2 reader poisoned"))
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut guard = self.lock_file()?;
        guard.seek(SeekFrom::Start(offset))?;
        guard.read_exact(buf)
    }

    fn l2_table(&self, l2_offset: u64) -> io::Result<Vec<u64>> {
        let mut cache = self
            .l2_cache
            .lock()
            .map_err(|_| io::Error::other("qcow2 L2 cache poisoned"))?;
        if cache.offset == Some(l2_offset) {
            return Ok(cache.entries.clone());
        }
        let cs = self.header.cluster_size() as usize;
        let mut buf = vec![0u8; cs];
        self.read_exact_at(l2_offset, &mut buf)?;
        let entries = buf
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().expect("chunks_exact 8")))
            .collect();
        cache.offset = Some(l2_offset);
        cache.entries = entries;
        Ok(cache.entries.clone())
    }

    fn map_cluster(&self, cluster_idx: u64) -> io::Result<Cluster> {
        let l2_entries = self.header.l2_entries();
        if l2_entries == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "qcow2 cluster_bits too small",
            ));
        }
        let l1_index = cluster_idx / l2_entries;
        let l2_index = cluster_idx % l2_entries;
        let l1_entry = match self.l1.get(l1_index as usize) {
            Some(e) => *e,
            None => return Ok(Cluster::Unallocated),
        };
        let l2_offset = l1_entry & OFFSET_MASK;
        if l2_offset == 0 {
            return Ok(Cluster::Unallocated);
        }
        let table = self.l2_table(l2_offset)?;
        let Some(&entry) = table.get(l2_index as usize) else {
            return Ok(Cluster::Unallocated);
        };
        if entry & QCOW_OFLAG_COMPRESSED != 0 {
            let x = 62u32.saturating_sub(self.header.cluster_bits.saturating_sub(8));
            if x == 0 || x >= 62 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "qcow2 compressed-cluster descriptor width",
                ));
            }
            let desc = entry & !QCOW_OFLAG_COPIED & !QCOW_OFLAG_COMPRESSED;
            let host_offset = desc & ((1u64 << x) - 1);
            let additional = desc >> x;
            let packed_size = additional
                .saturating_add(1)
                .saturating_mul(512)
                .min(self.header.cluster_size().saturating_mul(2));
            return Ok(Cluster::Compressed {
                host_offset,
                packed_size,
            });
        }
        if entry & QCOW_OFLAG_ZERO != 0 {
            return Ok(Cluster::Zero);
        }
        let host_offset = entry & OFFSET_MASK;
        if host_offset == 0 {
            Ok(Cluster::Unallocated)
        } else {
            Ok(Cluster::Standard { host_offset })
        }
    }

    fn decompress_cluster(
        &self,
        cluster_idx: u64,
        host_offset: u64,
        packed_size: u64,
    ) -> io::Result<Vec<u8>> {
        if self.header.compression == Qcow2Compression::Zstd {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "qcow2 zstd compressed clusters are residual",
            ));
        }
        {
            let cache = self
                .decode_cache
                .lock()
                .map_err(|_| io::Error::other("qcow2 decode cache poisoned"))?;
            if cache.cluster_idx == Some(cluster_idx) {
                return Ok(cache.data.clone());
            }
        }
        let mut packed = vec![0u8; packed_size as usize];
        self.read_exact_at(host_offset, &mut packed)?;
        let cs = self.header.cluster_size() as usize;
        let mut dest = vec![0u8; cs];
        inflate_qcow2_cluster(&packed, &mut dest)?;
        let mut cache = self
            .decode_cache
            .lock()
            .map_err(|_| io::Error::other("qcow2 decode cache poisoned"))?;
        cache.cluster_idx = Some(cluster_idx);
        cache.data = dest.clone();
        Ok(dest)
    }

    fn read_backing(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        match &self.backing {
            None => {
                buf.fill(0);
                Ok(buf.len())
            }
            Some(Backing::Qcow2(inner)) => {
                // Overlay may be larger than the backing image; short reads
                // must read as zeros, not leave dest uninitialized.
                let n = inner.read_guest(offset, buf)?;
                if n < buf.len() {
                    buf[n..].fill(0);
                }
                Ok(buf.len())
            }
            Some(Backing::Raw { file, size }) => {
                if offset >= *size {
                    buf.fill(0);
                    return Ok(buf.len());
                }
                let avail = (*size - offset) as usize;
                let n = buf.len().min(avail);
                {
                    let mut guard = file
                        .lock()
                        .map_err(|_| io::Error::other("qcow2 raw backing poisoned"))?;
                    guard.seek(SeekFrom::Start(offset))?;
                    guard.read_exact(&mut buf[..n])?;
                }
                if n < buf.len() {
                    buf[n..].fill(0);
                }
                Ok(buf.len())
            }
        }
    }

    /// Fill `buf` from guest `offset` (zeros past EOF). Returns bytes of `buf`
    /// filled (always `buf.len()` unless `offset >= size`, then 0).
    fn read_guest(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.header.size || buf.is_empty() {
            return Ok(0);
        }
        let remaining = (self.header.size - offset) as usize;
        let to_fill = buf.len().min(remaining);
        let cs = self.header.cluster_size();
        let mut done = 0usize;
        while done < to_fill {
            let pos = offset + done as u64;
            let cluster_idx = pos / cs;
            let in_cluster = (pos % cs) as usize;
            let n = (cs as usize - in_cluster).min(to_fill - done);
            let dest = &mut buf[done..done + n];
            match self.map_cluster(cluster_idx)? {
                Cluster::Unallocated => {
                    self.read_backing(pos, dest)?;
                }
                Cluster::Zero => dest.fill(0),
                Cluster::Standard { host_offset } => {
                    let host = host_offset.checked_add(in_cluster as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "qcow2 host offset overflow")
                    })?;
                    self.read_exact_at(host, dest)?;
                }
                Cluster::Compressed {
                    host_offset,
                    packed_size,
                } => {
                    let data = self.decompress_cluster(cluster_idx, host_offset, packed_size)?;
                    dest.copy_from_slice(&data[in_cluster..in_cluster + n]);
                }
            }
            done += n;
        }
        Ok(to_fill)
    }
}

impl Read for Qcow2VirtualDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read_guest(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Qcow2VirtualDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.pos as i64 + o,
            SeekFrom::End(o) => self.inner.header.size as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start of qcow2 virtual disk",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

fn inflate_qcow2_cluster(src: &[u8], dest: &mut [u8]) -> io::Result<()> {
    // QEMU inflateInit2(strm, -12): raw deflate, no zlib wrapper.
    let mut d = Decompress::new(false);
    let status = d
        .decompress(src, dest, FlushDecompress::Finish)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // Packed size is sector-rounded; QEMU accepts Z_BUF_ERROR when dest is full.
    let filled = d.total_out() as usize;
    if filled == dest.len() && matches!(status, Status::Ok | Status::BufError | Status::StreamEnd) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "qcow2 zlib cluster decompressed {filled} bytes (wanted {}); {status:?}",
            dest.len()
        ),
    ))
}

fn validate_open(header: &Qcow2Header, label: &Path) -> Result<()> {
    if header.version != 2 && header.version != 3 {
        return Err(Qcow2Error::Msg(format!(
            "{} is qcow version {} (v1 residual; need v2/v3)",
            label.display(),
            header.version
        )));
    }
    if header.crypt_method != 0 {
        return Err(Qcow2Error::Msg(format!(
            "{} is encrypted QCOW2 (crypt_method {}); AES/LUKS residual",
            label.display(),
            header.crypt_method
        )));
    }
    let incompat = header.incompatible_features;
    if incompat & !INCOMPAT_KNOWN != 0 {
        return Err(Qcow2Error::Msg(format!(
            "{} has unknown qcow2 incompatible features 0x{incompat:x}",
            label.display()
        )));
    }
    if incompat & INCOMPAT_CORRUPT != 0 {
        return Err(Qcow2Error::Msg(format!(
            "{} is marked corrupt",
            label.display()
        )));
    }
    if incompat & INCOMPAT_EXTERNAL_DATA != 0 {
        return Err(Qcow2Error::Msg(format!(
            "{} uses an external data file (residual)",
            label.display()
        )));
    }
    if incompat & INCOMPAT_EXTENDED_L2 != 0 {
        return Err(Qcow2Error::Msg(format!(
            "{} uses extended L2 subclusters (residual)",
            label.display()
        )));
    }
    if incompat & INCOMPAT_DIRTY != 0 {
        log::debug!(
            "qcow2 {} has dirty bit set; mounting read-only anyway",
            label.display()
        );
    }
    Ok(())
}

fn is_remote_backing(name: &str) -> bool {
    let n = name.trim();
    if n.contains("://") {
        return true;
    }
    let lower = n.to_ascii_lowercase();
    lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("nbd:")
        || lower.starts_with("nbd+")
        || lower.starts_with("json:")
        || lower.starts_with("gluster:")
        || lower.starts_with("iscsi:")
        || lower.starts_with("rbd:")
}

fn resolve_backing_path(name: &str, backing_dir: Option<&Path>) -> Result<PathBuf> {
    let name = name.strip_prefix("file:").unwrap_or(name);
    let p = Path::new(name);
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    match backing_dir {
        Some(dir) if !dir.as_os_str().is_empty() => Ok(dir.join(p)),
        _ => Err(Qcow2Error::Msg(format!(
            "qcow2 relative backing {name:?} needs a local parent path \
             (HTTP/NBD backing is residual)"
        ))),
    }
}

fn open_backing(name: &str, backing_dir: Option<&Path>, depth: u32) -> Result<Backing> {
    if depth >= MAX_BACKING_DEPTH {
        return Err(Qcow2Error::Msg(
            "qcow2 backing chain exceeds depth 16".into(),
        ));
    }
    if is_remote_backing(name) {
        return Err(Qcow2Error::Msg(format!(
            "qcow2 backing {name:?} is not a local path (HTTP/NBD backing is residual)"
        )));
    }
    let path = resolve_backing_path(name, backing_dir)?;
    if !path.is_file() {
        return Err(Qcow2Error::Msg(format!(
            "qcow2 backing file {} not found",
            path.display()
        )));
    }
    let mut file = File::open(&path)?;
    if looks_like_qcow2_reader(&mut file) {
        file.seek(SeekFrom::Start(0))?;
        let inner = Qcow2Inner::from_reader(file, &path, path.parent(), depth + 1)?;
        Ok(Backing::Qcow2(inner))
    } else {
        let size = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(0))?;
        Ok(Backing::Raw {
            file: Arc::new(Mutex::new(Box::new(file) as Box<dyn SeekRead>)),
            size,
        })
    }
}

fn u32_be(buf: &[u8], off: usize) -> Result<u32> {
    let slice = buf
        .get(off..off + 4)
        .ok_or_else(|| Qcow2Error::Msg("truncated qcow2 header".into()))?;
    let b: [u8; 4] = slice
        .try_into()
        .map_err(|_| Qcow2Error::Msg("truncated qcow2 header".into()))?;
    Ok(u32::from_be_bytes(b))
}

fn u64_be(buf: &[u8], off: usize) -> Result<u64> {
    let slice = buf
        .get(off..off + 8)
        .ok_or_else(|| Qcow2Error::Msg("truncated qcow2 header".into()))?;
    let b: [u8; 8] = slice
        .try_into()
        .map_err(|_| Qcow2Error::Msg("truncated qcow2 header".into()))?;
    Ok(u64::from_be_bytes(b))
}

/// Parse a QCOW2 v2/v3 header. Leaves the reader at an unspecified position.
pub fn parse_qcow2_header<R: Read + Seek>(reader: &mut R) -> Result<Qcow2Header> {
    reader.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; 112];
    let n = reader.read(&mut buf)?;
    if n < MIN_HEADER || buf[0..4] != MAGIC[..] {
        return Err(Qcow2Error::Msg(
            "not a QCOW2 image (missing QFI\\xfb)".into(),
        ));
    }
    let version = u32_be(&buf, 4)?;
    if version != 2 && version != 3 {
        return Err(Qcow2Error::Msg(format!(
            "unsupported qcow version {version} (need 2 or 3)"
        )));
    }
    let backing_file_offset = u64_be(&buf, 8)?;
    let backing_file_size = u32_be(&buf, 16)?;
    let cluster_bits = u32_be(&buf, 20)?;
    if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
        return Err(Qcow2Error::Msg(format!(
            "qcow2 cluster_bits {cluster_bits} out of range {MIN_CLUSTER_BITS}..={MAX_CLUSTER_BITS}"
        )));
    }
    let size = u64_be(&buf, 24)?;
    let crypt_method = u32_be(&buf, 32)?;
    let l1_size = u32_be(&buf, 36)?;
    if l1_size > MAX_L1_ENTRIES {
        return Err(Qcow2Error::Msg(format!(
            "qcow2 l1_size {l1_size} exceeds {MAX_L1_ENTRIES}"
        )));
    }
    let l1_table_offset = u64_be(&buf, 40)?;

    let mut incompatible_features = 0u64;
    let mut compression = Qcow2Compression::Zlib;
    if version >= 3 {
        if n < V3_HEADER_MIN {
            return Err(Qcow2Error::Msg("truncated qcow2 v3 header".into()));
        }
        incompatible_features = u64_be(&buf, 72)?;
        let header_length = u32_be(&buf, 100)?;
        if header_length < V3_HEADER_MIN as u32 {
            return Err(Qcow2Error::Msg(format!(
                "qcow2 v3 header_length {header_length} < {V3_HEADER_MIN}"
            )));
        }
        if incompatible_features & INCOMPAT_COMPRESSION_TYPE != 0 {
            if n < 108 && header_length < 108 {
                return Err(Qcow2Error::Msg(
                    "qcow2 compression_type field missing".into(),
                ));
            }
            let ct = u32_be(&buf, 104)?;
            compression = match ct {
                0 => Qcow2Compression::Zlib,
                1 => Qcow2Compression::Zstd,
                other => {
                    return Err(Qcow2Error::Msg(format!(
                        "unknown qcow2 compression_type {other}"
                    )));
                }
            };
        }
    }

    let backing_file = if backing_file_offset != 0 && backing_file_size != 0 {
        let len = backing_file_size as usize;
        if len > MAX_BACKING_NAME {
            return Err(Qcow2Error::Msg(format!(
                "qcow2 backing file name length {len} exceeds {MAX_BACKING_NAME}"
            )));
        }
        let mut name = vec![0u8; len];
        reader.seek(SeekFrom::Start(backing_file_offset))?;
        reader.read_exact(&mut name)?;
        let s = String::from_utf8(name)
            .map_err(|_| Qcow2Error::Msg("qcow2 backing file name is not UTF-8".into()))?;
        Some(s)
    } else {
        None
    };

    Ok(Qcow2Header {
        version,
        cluster_bits,
        size,
        crypt_method,
        l1_size,
        l1_table_offset,
        backing_file,
        compression,
        incompatible_features,
    })
}

/// Detect QCOW2 (`QFI\xfb` + version 2 or 3). No extension fallback.
pub fn looks_like_qcow2(path: &Path) -> bool {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    looks_like_qcow2_reader(&mut f)
}

/// Stream probe (does not use filename). Leaves the reader at an unspecified position.
pub fn looks_like_qcow2_reader<R: Read + Seek>(reader: &mut R) -> bool {
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    let mut buf = [0u8; 8];
    if reader.read_exact(&mut buf).is_err() {
        return false;
    }
    if buf[0..4] != MAGIC[..] {
        return false;
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    version == 2 || version == 3
}

#[cfg(test)]
pub(crate) fn write_qcow2_v2_header(
    cluster_bits: u32,
    size: u64,
    l1_size: u32,
    l1_table_offset: u64,
    backing: Option<&str>,
) -> Vec<u8> {
    let mut hdr = vec![0u8; MIN_HEADER];
    hdr[0..4].copy_from_slice(MAGIC);
    hdr[4..8].copy_from_slice(&2u32.to_be_bytes());
    hdr[20..24].copy_from_slice(&cluster_bits.to_be_bytes());
    hdr[24..32].copy_from_slice(&size.to_be_bytes());
    hdr[36..40].copy_from_slice(&l1_size.to_be_bytes());
    hdr[40..48].copy_from_slice(&l1_table_offset.to_be_bytes());
    if let Some(name) = backing {
        hdr[8..16].copy_from_slice(&(MIN_HEADER as u64).to_be_bytes());
        hdr[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
        hdr.extend_from_slice(name.as_bytes());
    }
    hdr
}
