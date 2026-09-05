//! UDIF `koly` trailer, XML `blkx` plist, and `mish` chunk tables.

use std::io::{Read, Seek, SeekFrom};

use crate::{DmgError, Result};

pub const KOLY_SIZE: u64 = 512;
pub const SECTOR_SIZE: u64 = 512;
const KOLY_MAGIC: &[u8; 4] = b"koly";
const MISH_MAGIC: &[u8; 4] = b"mish";
const MISH_HEADER: usize = 204;
const CHUNK_ENTRY: usize = 40;
const MAX_XML: u64 = 32 * 1024 * 1024;
const MAX_CHUNKS: u32 = 1_000_000;

pub const CHUNK_ZERO: u32 = 0x0000_0000;
pub const CHUNK_RAW: u32 = 0x0000_0001;
pub const CHUNK_IGNORE: u32 = 0x0000_0002;
pub const CHUNK_ADC: u32 = 0x8000_0004;
pub const CHUNK_ZLIB: u32 = 0x8000_0005;
pub const CHUNK_BZIP2: u32 = 0x8000_0006;
pub const CHUNK_LZFSE: u32 = 0x8000_0007;
pub const CHUNK_LZMA: u32 = 0x8000_0008;
pub const CHUNK_COMMENT: u32 = 0x7FFF_FFFE;
pub const CHUNK_TERM: u32 = 0xFFFF_FFFF;

const ENCRDSA: &[u8; 7] = b"encrdsa";
const CDSAENCR: &[u8; 8] = b"cdsaencr";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    Zero,
    Raw,
    Adc,
    Zlib,
    Bzip2,
    Lzfse,
    Lzma,
}

#[derive(Debug, Clone)]
pub struct KolyTrailer {
    pub version: u32,
    pub flags: u32,
    pub data_fork_offset: u64,
    pub data_fork_length: u64,
    pub rsrc_fork_offset: u64,
    pub rsrc_fork_length: u64,
    pub xml_offset: u64,
    pub xml_length: u64,
    pub sector_count: u64,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub kind: ChunkKind,
    pub start_byte: u64,
    pub length: u64,
    pub file_offset: u64,
    pub compressed_length: u64,
}

pub fn parse_koly(buf: &[u8; KOLY_SIZE as usize]) -> Result<KolyTrailer> {
    if &buf[0..4] != KOLY_MAGIC {
        return Err(DmgError::Msg("not a UDIF koly trailer".into()));
    }
    let version = u32_be(buf, 4);
    let header_size = u32_be(buf, 8);
    if header_size != KOLY_SIZE as u32 {
        return Err(DmgError::Msg(format!(
            "koly header size {header_size} (expected 512)"
        )));
    }
    if !(1..=4).contains(&version) {
        return Err(DmgError::Msg(format!("unsupported UDIF version {version}")));
    }
    Ok(KolyTrailer {
        version,
        flags: u32_be(buf, 12),
        data_fork_offset: u64_be(buf, 24),
        data_fork_length: u64_be(buf, 32),
        rsrc_fork_offset: u64_be(buf, 40),
        rsrc_fork_length: u64_be(buf, 48),
        xml_offset: u64_be(buf, 216),
        xml_length: u64_be(buf, 224),
        sector_count: u64_be(buf, 492),
    })
}

pub fn read_koly<R: Read + Seek>(reader: &mut R) -> Result<KolyTrailer> {
    reader.seek(SeekFrom::End(-(KOLY_SIZE as i64)))?;
    let mut buf = [0u8; KOLY_SIZE as usize];
    reader.read_exact(&mut buf)?;
    parse_koly(&buf)
}

/// True when the last 512 bytes are a parseable `koly` trailer.
///
/// Leaves the reader at an unspecified position.
pub fn looks_like_udif_reader<R: Read + Seek>(reader: &mut R) -> bool {
    match reader.seek(SeekFrom::End(-(KOLY_SIZE as i64))) {
        Ok(_) => {}
        Err(_) => return false,
    }
    let mut buf = [0u8; KOLY_SIZE as usize];
    if reader.read_exact(&mut buf).is_err() {
        return false;
    }
    parse_koly(&buf).is_ok()
}

pub fn looks_like_encrypted_reader<R: Read + Seek>(reader: &mut R) -> bool {
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    let mut mag = [0u8; 8];
    if reader.read_exact(&mut mag).is_err() {
        return false;
    }
    mag.starts_with(ENCRDSA) || mag == *CDSAENCR
}

pub fn load_chunks<R: Read + Seek>(reader: &mut R, koly: &KolyTrailer) -> Result<Vec<Chunk>> {
    if looks_like_encrypted_reader(reader) {
        return Err(DmgError::Msg(
            "encrypted UDIF is residual (no AES passphrase path in this crate)".into(),
        ));
    }
    if koly.xml_length == 0 {
        if koly.rsrc_fork_length > 0 {
            return Err(DmgError::Msg(
                "resource-fork-only UDIF is residual (XML blkx plist required)".into(),
            ));
        }
        return Err(DmgError::Msg(
            "UDIF has no XML plist (encrypted DMG residual)".into(),
        ));
    }
    if koly.xml_length > MAX_XML {
        return Err(DmgError::Msg(format!(
            "UDIF XML plist {} bytes exceeds {MAX_XML} cap",
            koly.xml_length
        )));
    }
    reader.seek(SeekFrom::Start(koly.xml_offset))?;
    let mut xml = vec![0u8; koly.xml_length as usize];
    reader.read_exact(&mut xml)?;
    if !xml_looks_like_plist(&xml) {
        return Err(DmgError::Msg(
            "UDIF XML is not a plist (encrypted DMG residual)".into(),
        ));
    }
    let xml_str = std::str::from_utf8(&xml)
        .map_err(|_| DmgError::Msg("UDIF XML plist is not UTF-8".into()))?;
    let blobs = extract_blkx_mish(xml_str)?;
    if blobs.is_empty() {
        return Err(DmgError::Msg("UDIF plist has no blkx mish blobs".into()));
    }
    let mut chunks = Vec::new();
    for blob in blobs {
        parse_mish(&blob, koly.data_fork_offset, &mut chunks)?;
    }
    chunks.sort_by_key(|c| c.start_byte);
    for pair in chunks.windows(2) {
        let a_end = pair[0].start_byte.saturating_add(pair[0].length);
        if pair[1].start_byte < a_end {
            return Err(DmgError::Msg("overlapping UDIF blkx chunks".into()));
        }
    }
    Ok(chunks)
}

fn xml_looks_like_plist(xml: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(xml) else {
        return false;
    };
    let t = s.trim_start();
    t.starts_with("<?xml") || t.starts_with("<plist") || t.contains("<key>blkx</key>")
}

fn extract_blkx_mish(xml: &str) -> Result<Vec<Vec<u8>>> {
    const KEY: &str = "<key>blkx</key>";
    let start = xml
        .find(KEY)
        .ok_or_else(|| DmgError::Msg("UDIF plist missing blkx key".into()))?;
    let after = &xml[start + KEY.len()..];
    let array_at = after
        .find("<array>")
        .ok_or_else(|| DmgError::Msg("UDIF blkx is not an array".into()))?;
    let body_start = array_at + "<array>".len();
    let mut depth = 1i32;
    let mut i = body_start;
    let mut body_end = None;
    while i < after.len() {
        if after[i..].starts_with("<array>") {
            depth += 1;
            i += 7;
        } else if after[i..].starts_with("</array>") {
            depth -= 1;
            if depth == 0 {
                body_end = Some(i);
                break;
            }
            i += 8;
        } else {
            i += 1;
        }
    }
    let body_end = body_end.ok_or_else(|| DmgError::Msg("unterminated UDIF blkx array".into()))?;
    let body = &after[body_start..body_end];
    let mut blobs = Vec::new();
    let mut rest = body;
    while let Some(ds) = rest.find("<data>") {
        rest = &rest[ds + 6..];
        let Some(de) = rest.find("</data>") else {
            return Err(DmgError::Msg("unterminated UDIF <data>".into()));
        };
        let decoded = decode_base64(&rest[..de])?;
        if decoded.len() >= 4 && decoded.starts_with(MISH_MAGIC) {
            blobs.push(decoded);
        }
        rest = &rest[de + 7..];
    }
    Ok(blobs)
}

fn parse_mish(blob: &[u8], data_fork_offset: u64, out: &mut Vec<Chunk>) -> Result<()> {
    if blob.len() < MISH_HEADER {
        return Err(DmgError::Msg(
            "mish blob shorter than 204-byte header".into(),
        ));
    }
    if &blob[0..4] != MISH_MAGIC {
        return Err(DmgError::Msg("blkx blob is not mish".into()));
    }
    let first_sector = u64_be(blob, 8);
    let mish_data_offset = u64_be(blob, 24);
    let nchunks = u32_be(blob, 200);
    if nchunks > MAX_CHUNKS {
        return Err(DmgError::Msg(format!(
            "mish chunk count {nchunks} too large"
        )));
    }
    let need = MISH_HEADER
        .checked_add(nchunks as usize * CHUNK_ENTRY)
        .ok_or_else(|| DmgError::Msg("mish size overflow".into()))?;
    if blob.len() < need {
        return Err(DmgError::Msg("mish truncated before chunk table".into()));
    }
    for i in 0..nchunks as usize {
        let o = MISH_HEADER + i * CHUNK_ENTRY;
        let ty = u32_be(blob, o);
        if ty == CHUNK_TERM || ty == CHUNK_COMMENT {
            continue;
        }
        let sector = u64_be(blob, o + 8);
        let sector_count = u64_be(blob, o + 16);
        if sector_count == 0 {
            continue;
        }
        let comp_off = u64_be(blob, o + 24);
        let comp_len = u64_be(blob, o + 32);
        let kind = match ty {
            CHUNK_ZERO | CHUNK_IGNORE => ChunkKind::Zero,
            CHUNK_RAW => ChunkKind::Raw,
            CHUNK_ADC => ChunkKind::Adc,
            CHUNK_ZLIB => ChunkKind::Zlib,
            CHUNK_BZIP2 => ChunkKind::Bzip2,
            CHUNK_LZFSE => ChunkKind::Lzfse,
            CHUNK_LZMA => ChunkKind::Lzma,
            other => {
                return Err(DmgError::Msg(format!(
                    "unsupported UDIF chunk type 0x{other:08x} (LZFSE/LZMA residual)"
                )));
            }
        };
        let start_byte = first_sector
            .saturating_add(sector)
            .saturating_mul(SECTOR_SIZE);
        let length = sector_count.saturating_mul(SECTOR_SIZE);
        let file_offset = data_fork_offset
            .saturating_add(mish_data_offset)
            .saturating_add(comp_off);
        out.push(Chunk {
            kind,
            start_byte,
            length,
            file_offset,
            compressed_length: comp_len,
        });
    }
    Ok(())
}

fn u32_be(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().expect("u32 slice"))
}

fn u64_be(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(buf[off..off + 8].try_into().expect("u64 slice"))
}

fn decode_base64(s: &str) -> Result<Vec<u8>> {
    let filtered: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if filtered.is_empty() {
        return Ok(Vec::new());
    }
    // `% 4` not `is_multiple_of` — that method is rustc 1.87+ (MSRV 1.74).
    #[allow(clippy::manual_is_multiple_of)]
    if filtered.len() % 4 != 0 {
        return Err(DmgError::Msg("invalid base64 length in UDIF plist".into()));
    }
    let mut out = Vec::with_capacity(filtered.len() / 4 * 3);
    for chunk in filtered.chunks_exact(4) {
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let (c, pad_c) = if chunk[2] == b'=' {
            (0, true)
        } else {
            (b64_val(chunk[2])?, false)
        };
        let (d, pad_d) = if chunk[3] == b'=' {
            (0, true)
        } else {
            (b64_val(chunk[3])?, false)
        };
        out.push((a << 2) | (b >> 4));
        if !pad_c {
            out.push((b << 4) | (c >> 2));
        }
        if !pad_d {
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

fn b64_val(b: u8) -> Result<u8> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(DmgError::Msg("invalid base64 byte in UDIF plist".into())),
    }
}

#[cfg(test)]
pub(crate) fn encode_base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = data.get(i + 1).copied();
        let b2 = data.get(i + 2).copied();
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)) as usize] as char);
        match (b1, b2) {
            (Some(b1), Some(b2)) => {
                out.push(T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
                out.push(T[(b2 & 0x3f) as usize] as char);
            }
            (Some(b1), None) => {
                out.push(T[((b1 & 0x0f) << 2) as usize] as char);
                out.push('=');
            }
            (None, _) => {
                out.push('=');
                out.push('=');
            }
        }
        i += 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_koly_synthetic_fields() {
        let mut buf = [0u8; 512];
        buf[0..4].copy_from_slice(b"koly");
        buf[4..8].copy_from_slice(&4u32.to_be_bytes());
        buf[8..12].copy_from_slice(&512u32.to_be_bytes());
        buf[12..16].copy_from_slice(&1u32.to_be_bytes());
        buf[24..32].copy_from_slice(&0u64.to_be_bytes());
        buf[32..40].copy_from_slice(&0x1234u64.to_be_bytes());
        buf[216..224].copy_from_slice(&0x2000u64.to_be_bytes());
        buf[224..232].copy_from_slice(&0x100u64.to_be_bytes());
        buf[492..500].copy_from_slice(&2048u64.to_be_bytes());
        let k = parse_koly(&buf).expect("koly");
        assert_eq!(k.version, 4);
        assert_eq!(k.flags, 1);
        assert_eq!(k.data_fork_length, 0x1234);
        assert_eq!(k.xml_offset, 0x2000);
        assert_eq!(k.xml_length, 0x100);
        assert_eq!(k.sector_count, 2048);
    }

    #[test]
    fn parse_koly_rejects_bad_magic() {
        let buf = [0u8; 512];
        assert!(parse_koly(&buf).is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let src = b"mish\x00\x01\x02\xff";
        let enc = encode_base64(src);
        let dec = decode_base64(&enc).unwrap();
        assert_eq!(dec, src);
    }
}
