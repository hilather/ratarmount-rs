//! WIM header, blob table, and first-image metadata (dentry tree).

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

#[cfg(test)]
use sha1::{Digest, Sha1};

use crate::xpress;
use crate::{Result, WimError};

pub const MAGIC: &[u8; 8] = b"MSWIM\0\0\0";
pub const HEADER_DISK_SIZE: usize = 208;
#[cfg(test)]
pub const WIM_VERSION_DEFAULT: u32 = 0x10d00;

#[cfg(test)]
pub const HDR_COMPRESSION: u32 = 0x0000_0002;
pub const HDR_COMPRESS_XPRESS: u32 = 0x0002_0000;
pub const HDR_COMPRESS_LZX: u32 = 0x0004_0000;
pub const HDR_COMPRESS_LZMS: u32 = 0x0008_0000;
pub const HDR_COMPRESS_XPRESS_2: u32 = 0x0020_0000;

const RES_FREE: u8 = 0x01;
const RES_METADATA: u8 = 0x02;
const RES_COMPRESSED: u8 = 0x04;
const RES_SOLID: u8 = 0x10;

const ATTR_DIRECTORY: u32 = 0x0000_0010;
const ATTR_REPARSE: u32 = 0x0000_0400;
const ATTR_ENCRYPTED: u32 = 0x0000_4000;

const BLOB_ENTRY_SIZE: usize = 50;
const DENTRY_BASE: usize = 102;
const MAX_RESOURCE: u64 = 64 * 1024 * 1024;
const MAX_DEPTH: usize = 256;

pub const FILETIME_UNIX_DELTA: u64 = 116_444_736_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Xpress,
    Lzx,
    Lzms,
}

impl Compression {
    fn from_header_flags(flags: u32) -> Self {
        if flags & HDR_COMPRESS_LZMS != 0 {
            Compression::Lzms
        } else if flags & HDR_COMPRESS_LZX != 0 {
            Compression::Lzx
        } else if flags & (HDR_COMPRESS_XPRESS | HDR_COMPRESS_XPRESS_2) != 0 {
            Compression::Xpress
        } else {
            Compression::None
        }
    }

    fn residual_name(self) -> Option<&'static str> {
        match self {
            Compression::Lzx => Some("LZX"),
            Compression::Lzms => Some("LZMS"),
            Compression::None | Compression::Xpress => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ResHdr {
    pub size_in_wim: u64,
    pub flags: u8,
    pub offset: u64,
    pub uncompressed_size: u64,
}

impl ResHdr {
    fn is_empty(&self) -> bool {
        self.size_in_wim == 0 && self.uncompressed_size == 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Blob {
    pub res: ResHdr,
}

#[derive(Clone, Debug)]
pub struct CatalogEntry {
    pub is_dir: bool,
    pub encrypted: bool,
    pub size: u64,
    pub mtime: f64,
    pub hash: [u8; 20],
}

#[derive(Clone, Debug)]
pub struct ParsedWim {
    pub compression: Compression,
    pub chunk_size: u32,
    pub blobs: HashMap<[u8; 20], Blob>,
    /// Full path (`/` + UTF-8 names) → entry for the first image.
    pub entries: HashMap<String, CatalogEntry>,
    /// Directory path → child basenames (insertion order).
    pub children: HashMap<String, Vec<String>>,
}

pub fn header_looks_like_wim(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return false;
    }
    if buf[..8] != *MAGIC {
        return false;
    }
    let hdr_size = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    hdr_size == HEADER_DISK_SIZE as u32
}

pub fn parse_wim<R: Read + Seek>(reader: &mut R) -> Result<ParsedWim> {
    let mut hdr = [0u8; HEADER_DISK_SIZE];
    reader.seek(SeekFrom::Start(0))?;
    reader.read_exact(&mut hdr)?;
    if !header_looks_like_wim(&hdr) {
        return Err(WimError::Msg("not a WIM image (MSWIM magic)".into()));
    }
    let flags = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
    let chunk_size = u32::from_le_bytes(hdr[20..24].try_into().unwrap());
    let image_count = u32::from_le_bytes(hdr[44..48].try_into().unwrap());
    let blob_table = read_reshdr(&hdr[48..72]);
    let compression = Compression::from_header_flags(flags);
    if let Some(name) = compression.residual_name() {
        return Err(WimError::Msg(format!(
            "WIM {name} compression is residual (v1 is uncompressed + XPRESS)"
        )));
    }
    if image_count == 0 {
        return Err(WimError::Msg("WIM has no images".into()));
    }
    if blob_table.is_empty() {
        return Err(WimError::Msg("WIM blob table is empty".into()));
    }
    let table_bytes = read_resource(reader, &blob_table, compression, chunk_size)?;
    let (blobs, metadata) = parse_blob_table(&table_bytes)?;
    let meta_blob = metadata
        .first()
        .ok_or_else(|| WimError::Msg("WIM first image has no metadata resource".into()))?;
    let meta = read_resource(reader, meta_blob, compression, chunk_size)?;
    let (entries, children) = parse_metadata(&meta, &blobs)?;
    Ok(ParsedWim {
        compression,
        chunk_size,
        blobs,
        entries,
        children,
    })
}

pub fn read_blob<R: Read + Seek + ?Sized>(
    reader: &mut R,
    parsed: &ParsedWim,
    hash: &[u8; 20],
) -> Result<Vec<u8>> {
    if hash.iter().all(|&b| b == 0) {
        return Ok(Vec::new());
    }
    let blob = parsed
        .blobs
        .get(hash)
        .ok_or_else(|| WimError::Msg("WIM blob hash not in lookup table".into()))?;
    read_resource(reader, &blob.res, parsed.compression, parsed.chunk_size)
}

fn read_reshdr(buf: &[u8]) -> ResHdr {
    ResHdr {
        size_in_wim: read_u56(&buf[0..7]),
        flags: buf[7],
        offset: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        uncompressed_size: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
    }
}

#[cfg(test)]
pub fn write_reshdr(buf: &mut [u8], res: &ResHdr) {
    let size = res.size_in_wim.to_le_bytes();
    buf[0..7].copy_from_slice(&size[..7]);
    buf[7] = res.flags;
    buf[8..16].copy_from_slice(&res.offset.to_le_bytes());
    buf[16..24].copy_from_slice(&res.uncompressed_size.to_le_bytes());
}

#[cfg(test)]
pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

pub fn filetime_to_unix(filetime: u64) -> f64 {
    if filetime == 0 {
        return 0.0;
    }
    if filetime >= FILETIME_UNIX_DELTA {
        (filetime - FILETIME_UNIX_DELTA) as f64 / 10_000_000.0
    } else {
        -((FILETIME_UNIX_DELTA - filetime) as f64) / 10_000_000.0
    }
}

fn read_u56(buf: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b[..7].copy_from_slice(buf);
    u64::from_le_bytes(b)
}

fn read_resource<R: Read + Seek + ?Sized>(
    reader: &mut R,
    res: &ResHdr,
    compression: Compression,
    chunk_size: u32,
) -> Result<Vec<u8>> {
    if res.flags & RES_SOLID != 0 {
        return Err(WimError::Msg(
            "WIM solid resources are residual (WIMBoot / delta)".into(),
        ));
    }
    if res.uncompressed_size > MAX_RESOURCE {
        return Err(WimError::Msg("WIM resource exceeds 64 MiB v1 cap".into()));
    }
    if res.size_in_wim > MAX_RESOURCE {
        return Err(WimError::Msg(
            "WIM compressed resource exceeds 64 MiB v1 cap".into(),
        ));
    }
    let usize_ = res.uncompressed_size as usize;
    if res.flags & RES_COMPRESSED == 0 {
        let mut buf = vec![0u8; usize_];
        if usize_ > 0 {
            reader.seek(SeekFrom::Start(res.offset))?;
            reader.read_exact(&mut buf)?;
        }
        return Ok(buf);
    }
    if let Some(name) = compression.residual_name() {
        return Err(WimError::Msg(format!(
            "WIM {name} compression is residual (v1 is uncompressed + XPRESS)"
        )));
    }
    if compression != Compression::Xpress {
        return Err(WimError::Msg(
            "WIM compressed resource without XPRESS header flag".into(),
        ));
    }
    let chunk = if chunk_size == 0 { 32768 } else { chunk_size };
    read_xpress_resource(reader, res, chunk)
}

fn read_xpress_resource<R: Read + Seek + ?Sized>(
    reader: &mut R,
    res: &ResHdr,
    chunk_size: u32,
) -> Result<Vec<u8>> {
    let mut packed = vec![0u8; res.size_in_wim as usize];
    if !packed.is_empty() {
        reader.seek(SeekFrom::Start(res.offset))?;
        reader.read_exact(&mut packed)?;
    }
    let uncomp = res.uncompressed_size;
    if uncomp == 0 {
        return Ok(Vec::new());
    }
    let chunk_size = u64::from(chunk_size.max(1));
    let num_chunks = uncomp.div_ceil(chunk_size);
    let entry_size: usize = if uncomp > u64::from(u32::MAX) { 8 } else { 4 };
    let table_entries = num_chunks.saturating_sub(1) as usize;
    let table_size = table_entries.saturating_mul(entry_size);
    if packed.len() < table_size {
        return Err(WimError::Msg("WIM chunk table truncated".into()));
    }
    let mut ends = Vec::with_capacity(num_chunks as usize);
    for i in 0..table_entries {
        let off = i * entry_size;
        let end = if entry_size == 4 {
            u64::from(u32::from_le_bytes(packed[off..off + 4].try_into().unwrap()))
        } else {
            u64::from_le_bytes(packed[off..off + 8].try_into().unwrap())
        };
        ends.push(end);
    }
    let payload = packed.len() - table_size;
    ends.push(payload as u64);
    let mut out = Vec::with_capacity(uncomp as usize);
    let mut prev = 0u64;
    for &end in &ends {
        if end < prev || end as usize > payload {
            return Err(WimError::Msg("WIM chunk table offsets invalid".into()));
        }
        let cstart = table_size + prev as usize;
        let cend = table_size + end as usize;
        let remaining = uncomp - out.len() as u64;
        let this_uncomp = remaining.min(chunk_size) as usize;
        let chunk = &packed[cstart..cend];
        if chunk.len() >= this_uncomp {
            out.extend_from_slice(&chunk[..this_uncomp]);
        } else {
            let decoded = xpress::decompress(chunk, this_uncomp)?;
            if decoded.len() != this_uncomp {
                return Err(WimError::Msg("XPRESS chunk size mismatch".into()));
            }
            out.extend_from_slice(&decoded);
        }
        prev = end;
    }
    if out.len() as u64 != uncomp {
        return Err(WimError::Msg("WIM decompressed size mismatch".into()));
    }
    Ok(out)
}

type BlobTable = (HashMap<[u8; 20], Blob>, Vec<ResHdr>);

fn parse_blob_table(bytes: &[u8]) -> Result<BlobTable> {
    let mut blobs = HashMap::new();
    let mut metadata = Vec::new();
    let n = bytes.len() / BLOB_ENTRY_SIZE;
    for i in 0..n {
        let e = &bytes[i * BLOB_ENTRY_SIZE..(i + 1) * BLOB_ENTRY_SIZE];
        let res = read_reshdr(&e[0..24]);
        if res.flags & RES_FREE != 0 {
            continue;
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&e[30..50]);
        if res.flags & RES_METADATA != 0 {
            metadata.push(res);
        } else if !hash.iter().all(|&b| b == 0) {
            blobs.insert(hash, Blob { res });
        }
    }
    Ok((blobs, metadata))
}

type Catalog = (HashMap<String, CatalogEntry>, HashMap<String, Vec<String>>);

fn parse_metadata(meta: &[u8], blobs: &HashMap<[u8; 20], Blob>) -> Result<Catalog> {
    if meta.len() < 8 {
        return Err(WimError::Msg("WIM metadata too small".into()));
    }
    let total_length = u32::from_le_bytes(meta[0..4].try_into().unwrap()) as u64;
    let root_off = total_length.next_multiple_of(8);
    let mut entries = HashMap::new();
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    entries.insert(
        "/".into(),
        CatalogEntry {
            is_dir: true,
            encrypted: false,
            size: 0,
            mtime: 0.0,
            hash: [0u8; 20],
        },
    );
    children.insert("/".into(), Vec::new());
    let (root, _) = read_dentry(meta, root_off)?;
    let Some(root) = root else {
        return Ok((entries, children));
    };
    if root.subdir_offset != 0 {
        walk_dir(
            meta,
            root.subdir_offset,
            "/",
            blobs,
            &mut entries,
            &mut children,
            0,
        )?;
    }
    Ok((entries, children))
}

struct DiskDentry {
    attributes: u32,
    subdir_offset: u64,
    mtime: f64,
    hash: [u8; 20],
    name: String,
}

fn read_dentry(meta: &[u8], offset: u64) -> Result<(Option<DiskDentry>, u64)> {
    let off = offset as usize;
    match off.checked_add(8) {
        Some(e) if e <= meta.len() => {}
        _ => return Err(WimError::Msg("WIM dentry length truncated".into())),
    }
    let raw_len = u64::from_le_bytes(meta[off..off + 8].try_into().unwrap());
    let length = raw_len.next_multiple_of(8);
    if length <= 8 {
        return Ok((None, offset + 8));
    }
    if length < DENTRY_BASE as u64 {
        return Err(WimError::Msg("WIM dentry shorter than 102 bytes".into()));
    }
    let end = off
        .checked_add(length as usize)
        .ok_or_else(|| WimError::Msg("WIM dentry overflow".into()))?;
    if end > meta.len() {
        return Err(WimError::Msg("WIM dentry overruns metadata".into()));
    }
    let d = &meta[off..end];
    let attributes = u32::from_le_bytes(d[8..12].try_into().unwrap());
    let subdir_offset = u64::from_le_bytes(d[16..24].try_into().unwrap());
    let last_write = u64::from_le_bytes(d[56..64].try_into().unwrap());
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&d[64..84]);
    let num_extra = u16::from_le_bytes(d[96..98].try_into().unwrap());
    let short_nbytes = u16::from_le_bytes(d[98..100].try_into().unwrap()) as usize;
    let name_nbytes = u16::from_le_bytes(d[100..102].try_into().unwrap()) as usize;
    if (short_nbytes | name_nbytes) & 1 != 0 {
        return Err(WimError::Msg("WIM dentry name length is odd".into()));
    }
    let mut p = DENTRY_BASE;
    let name = if name_nbytes > 0 {
        if p + name_nbytes + 2 > d.len() {
            return Err(WimError::Msg("WIM dentry name truncated".into()));
        }
        let units: Vec<u16> = d[p..p + name_nbytes]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        p += name_nbytes + 2;
        String::from_utf16(&units).unwrap_or_else(|_| String::from('\u{FFFD}'))
    } else {
        String::new()
    };
    if short_nbytes > 0 {
        p = p.saturating_add(short_nbytes + 2);
    }
    let _ = p;
    // Extra streams follow the dentry (not included in `length`).
    let mut next = offset + length;
    for _ in 0..num_extra {
        let ns = next as usize;
        if ns + 8 > meta.len() {
            return Err(WimError::Msg("WIM extra stream truncated".into()));
        }
        let slen = u64::from_le_bytes(meta[ns..ns + 8].try_into().unwrap()).next_multiple_of(8);
        if slen < 8 {
            return Err(WimError::Msg("WIM extra stream length invalid".into()));
        }
        next = next
            .checked_add(slen)
            .ok_or_else(|| WimError::Msg("WIM extra stream overflow".into()))?;
        if next as usize > meta.len() {
            return Err(WimError::Msg("WIM extra stream overruns metadata".into()));
        }
    }
    Ok((
        Some(DiskDentry {
            attributes,
            subdir_offset,
            mtime: filetime_to_unix(last_write),
            hash,
            name,
        }),
        next,
    ))
}

fn walk_dir(
    meta: &[u8],
    offset: u64,
    parent: &str,
    blobs: &HashMap<[u8; 20], Blob>,
    entries: &mut HashMap<String, CatalogEntry>,
    children: &mut HashMap<String, Vec<String>>,
    depth: usize,
) -> Result<()> {
    if depth >= MAX_DEPTH {
        return Err(WimError::Msg("WIM directory tree too deep".into()));
    }
    let mut cur = offset;
    loop {
        let (dentry, next) = read_dentry(meta, cur)?;
        let Some(d) = dentry else {
            break;
        };
        cur = next;
        if d.name.is_empty() || d.name == "." || d.name == ".." || d.name.contains('\0') {
            continue;
        }
        let path = if parent == "/" {
            format!("/{}", d.name)
        } else {
            format!("{parent}/{}", d.name)
        };
        let is_dir = d.attributes & ATTR_DIRECTORY != 0 && d.attributes & ATTR_REPARSE == 0;
        let encrypted = d.attributes & ATTR_ENCRYPTED != 0;
        let size = if is_dir {
            0
        } else {
            blobs
                .get(&d.hash)
                .map(|b| b.res.uncompressed_size)
                .unwrap_or(0)
        };
        entries.insert(
            path.clone(),
            CatalogEntry {
                is_dir,
                encrypted,
                size,
                mtime: d.mtime,
                hash: d.hash,
            },
        );
        children
            .entry(parent.to_string())
            .or_default()
            .push(d.name.clone());
        if is_dir {
            children.entry(path.clone()).or_default();
            if d.subdir_offset != 0 {
                walk_dir(
                    meta,
                    d.subdir_offset,
                    &path,
                    blobs,
                    entries,
                    children,
                    depth + 1,
                )?;
            }
        }
    }
    Ok(())
}

/// Flags used by the synthetic uncompressed fixture builder (tests / XPRESS blob).
#[cfg(test)]
pub const RES_FLAG_METADATA: u8 = RES_METADATA;
#[cfg(test)]
pub const RES_FLAG_COMPRESSED: u8 = RES_COMPRESSED;
#[cfg(test)]
pub const ATTR_FLAG_DIRECTORY: u32 = ATTR_DIRECTORY;
#[cfg(test)]
pub const ATTR_FLAG_ARCHIVE: u32 = 0x20;
