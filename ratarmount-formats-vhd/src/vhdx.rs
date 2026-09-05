//! Microsoft VHDX (fixed and sparse, no parent). Differencing / encrypted residual.

use std::io::{Read, Seek, SeekFrom};

use crate::disk::{DiskMap, VirtualDisk};
use crate::{Result, VhdError, VhdKind};

pub(crate) const VHDX_SIG: &[u8; 8] = b"vhdxfile";
const HEADER_SIG: &[u8; 4] = b"head";
const REGION_SIG: &[u8; 4] = b"regi";
const META_SIG: &[u8; 8] = b"metadata";
const HEADER1_OFF: u64 = 64 * 1024;
const HEADER2_OFF: u64 = 128 * 1024;
const REGION1_OFF: u64 = 192 * 1024;
const REGION2_OFF: u64 = 256 * 1024;
const HEADER_LEN: usize = 4096;
const REGION_LEN: usize = 64 * 1024;
const MIB: u64 = 1024 * 1024;
const MAX_VIRT_SIZE: u64 = 64 * 1024 * 1024 * 1024 * 1024;
const MAX_BAT_ENTRIES: usize = 8 * 1024 * 1024;
#[cfg(test)]
const VHDX_STATE_FULLY_PRESENT: u64 = 6;

/// Mixed-endian GUID (same layout as GPT).
fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&data1.to_le_bytes());
    g[4..6].copy_from_slice(&data2.to_le_bytes());
    g[6..8].copy_from_slice(&data3.to_le_bytes());
    g[8..16].copy_from_slice(&data4);
    g
}

fn guid_bat() -> [u8; 16] {
    guid(
        0x2DC2_7766,
        0xF623,
        0x4200,
        [0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08],
    )
}

fn guid_metadata() -> [u8; 16] {
    guid(
        0x8B7C_A206,
        0x4790,
        0x4B9A,
        [0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E],
    )
}

fn guid_file_params() -> [u8; 16] {
    guid(
        0xCAA1_6737,
        0xFA36,
        0x4D43,
        [0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6F],
    )
}

fn guid_virt_size() -> [u8; 16] {
    guid(
        0x2FA5_4224,
        0xCD1B,
        0x4876,
        [0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8],
    )
}

fn guid_logical_sector() -> [u8; 16] {
    guid(
        0x8141_BF1D,
        0xA96F,
        0x4709,
        [0x99, 0x07, 0x94, 0xC8, 0x1A, 0xDE, 0x76, 0x1B],
    )
}

#[cfg(test)]
fn guid_physical_sector() -> [u8; 16] {
    guid(
        0xCDA3_48C7,
        0x445D,
        0x4471,
        [0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56],
    )
}

fn guid_parent_locator() -> [u8; 16] {
    guid(
        0xA8D3_5F2D,
        0xB30B,
        0x454D,
        [0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C],
    )
}

/// Castagnoli CRC-32C (reflected poly 0x82F63B78). VHDX headers use this, not IEEE CRC-32.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

pub(crate) fn looks_like_vhdx_reader<R: Read + Seek>(reader: &mut R) -> bool {
    let mut mag = [0u8; 8];
    reader.seek(SeekFrom::Start(0)).is_ok()
        && reader.read_exact(&mut mag).is_ok()
        && mag == *VHDX_SIG
}

struct Header {
    sequence: u64,
}

fn read_header<R: Read + Seek>(reader: &mut R, off: u64) -> Result<Option<Header>> {
    let mut raw = vec![0u8; HEADER_LEN];
    reader.seek(SeekFrom::Start(off))?;
    match reader.read_exact(&mut raw) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if raw[0..4] != *HEADER_SIG {
        return Ok(None);
    }
    let stored = le_u32(&raw, 4);
    raw[4..8].fill(0);
    let calc = crc32c(&raw);
    if stored != calc {
        log::debug!("VHDX header at {off:#x} CRC32C mismatch");
        return Ok(None);
    }
    let version = le_u16(&raw, 66);
    if version != 1 {
        return Err(VhdError::Msg(format!(
            "VHDX header version {version} is not 1"
        )));
    }
    Ok(Some(Header {
        sequence: le_u64(&raw, 8),
    }))
}

struct Region {
    guid: [u8; 16],
    file_offset: u64,
    length: u32,
    required: bool,
}

fn parse_region_table<R: Read + Seek>(reader: &mut R, off: u64) -> Result<Option<Vec<Region>>> {
    let mut raw = vec![0u8; REGION_LEN];
    reader.seek(SeekFrom::Start(off))?;
    match reader.read_exact(&mut raw) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if raw[0..4] != *REGION_SIG {
        return Ok(None);
    }
    let stored = le_u32(&raw, 4);
    raw[4..8].fill(0);
    if stored != crc32c(&raw) {
        return Ok(None);
    }
    let count = le_u32(&raw, 8) as usize;
    if count > 2047 {
        return Err(VhdError::Msg(format!(
            "VHDX region table entry count {count} is too large"
        )));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let e = 16 + i * 32;
        if e + 32 > raw.len() {
            break;
        }
        let mut guid_b = [0u8; 16];
        guid_b.copy_from_slice(&raw[e..e + 16]);
        let file_offset = le_u64(&raw, e + 16);
        let length = le_u32(&raw, e + 24);
        let required = le_u32(&raw, e + 28) & 1 != 0;
        out.push(Region {
            guid: guid_b,
            file_offset,
            length,
            required,
        });
    }
    Ok(Some(out))
}

struct FileParams {
    block_size: u32,
    has_parent: bool,
}

struct Metadata {
    file_params: FileParams,
    virt_size: u64,
    logical_sector: u32,
}

fn parse_metadata<R: Read + Seek>(reader: &mut R, off: u64, len: u32) -> Result<Metadata> {
    if len < 64 * 1024 {
        return Err(VhdError::Msg(format!(
            "VHDX metadata region length {len} is < 64 KiB"
        )));
    }
    let read_len = (len as usize).min(1024 * 1024);
    let mut raw = vec![0u8; read_len];
    reader.seek(SeekFrom::Start(off))?;
    reader.read_exact(&mut raw)?;
    if raw.len() < 32 || raw[0..8] != *META_SIG {
        return Err(VhdError::Msg("VHDX metadata signature missing".into()));
    }
    let count = le_u16(&raw, 10) as usize;
    if count > 2047 {
        return Err(VhdError::Msg(format!(
            "VHDX metadata entry count {count} is too large"
        )));
    }
    let mut file_params = None;
    let mut virt_size = None;
    let mut logical_sector = None;
    let mut saw_parent = false;
    for i in 0..count {
        let e = 32 + i * 32;
        if e + 32 > raw.len() {
            break;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&raw[e..e + 16]);
        let item_off = le_u32(&raw, e + 16) as usize;
        let item_len = le_u32(&raw, e + 20) as usize;
        // Spec: Offset MUST be ≥ 64 KiB and a multiple of 64 KiB.
        #[allow(clippy::manual_is_multiple_of)]
        if item_off < 64 * 1024 || item_off % (64 * 1024) != 0 {
            return Err(VhdError::Msg(format!(
                "VHDX metadata item offset {item_off} is not 64 KiB-aligned"
            )));
        }
        match item_off.checked_add(item_len) {
            Some(end) if end <= raw.len() => {}
            _ => {
                return Err(VhdError::Msg(
                    "VHDX metadata item is outside the region buffer".into(),
                ))
            }
        }
        let item = &raw[item_off..item_off + item_len];
        if id == guid_file_params() {
            if item.len() < 8 {
                return Err(VhdError::Msg(
                    "VHDX File Parameters item is truncated".into(),
                ));
            }
            let block_size = le_u32(item, 0);
            let flags = le_u32(item, 4);
            file_params = Some(FileParams {
                block_size,
                has_parent: flags & 2 != 0,
            });
        } else if id == guid_virt_size() {
            if item.len() < 8 {
                return Err(VhdError::Msg(
                    "VHDX Virtual Disk Size item is truncated".into(),
                ));
            }
            virt_size = Some(le_u64(item, 0));
        } else if id == guid_logical_sector() {
            if item.len() < 4 {
                return Err(VhdError::Msg(
                    "VHDX Logical Sector Size item is truncated".into(),
                ));
            }
            logical_sector = Some(le_u32(item, 0));
        } else if id == guid_parent_locator() {
            saw_parent = true;
        }
    }
    let file_params = file_params
        .ok_or_else(|| VhdError::Msg("VHDX metadata is missing File Parameters".into()))?;
    let virt_size = virt_size
        .ok_or_else(|| VhdError::Msg("VHDX metadata is missing Virtual Disk Size".into()))?;
    let logical_sector = logical_sector.unwrap_or(512);
    if file_params.has_parent || saw_parent {
        return Err(VhdError::Msg(
            "differencing VHDX is residual (no parent chain)".into(),
        ));
    }
    Ok(Metadata {
        file_params,
        virt_size,
        logical_sector,
    })
}

pub(crate) fn open_vhdx<R>(mut reader: R) -> Result<(VirtualDisk, VhdKind)>
where
    R: Read + Seek + Send + 'static,
{
    let mut mag = [0u8; 8];
    reader.seek(SeekFrom::Start(0))?;
    reader.read_exact(&mut mag)?;
    if mag != *VHDX_SIG {
        return Err(VhdError::Msg(
            "VHDX file identifier is not 'vhdxfile'".into(),
        ));
    }

    let h1 = read_header(&mut reader, HEADER1_OFF)?;
    let h2 = read_header(&mut reader, HEADER2_OFF)?;
    let header = match (h1, h2) {
        (Some(a), Some(b)) => {
            if a.sequence >= b.sequence {
                a
            } else {
                b
            }
        }
        (Some(h), None) | (None, Some(h)) => h,
        (None, None) => {
            return Err(VhdError::Msg(
                "no valid VHDX header (CRC32C / signature)".into(),
            ))
        }
    };
    let _ = header;

    let r1 = parse_region_table(&mut reader, REGION1_OFF)?;
    let r2 = parse_region_table(&mut reader, REGION2_OFF)?;
    let regions = r1
        .or(r2)
        .ok_or_else(|| VhdError::Msg("no valid VHDX region table (CRC32C / signature)".into()))?;

    let mut bat_reg = None;
    let mut meta_reg = None;
    for r in &regions {
        if r.guid == guid_bat() {
            bat_reg = Some(r);
        } else if r.guid == guid_metadata() {
            meta_reg = Some(r);
        } else if r.required {
            return Err(VhdError::Msg(
                "VHDX required region GUID is unknown (encrypted / extension residual)".into(),
            ));
        }
    }
    let bat_reg = bat_reg.ok_or_else(|| VhdError::Msg("VHDX BAT region is missing".into()))?;
    let meta_reg =
        meta_reg.ok_or_else(|| VhdError::Msg("VHDX metadata region is missing".into()))?;

    let meta = parse_metadata(&mut reader, meta_reg.file_offset, meta_reg.length)?;
    let block_size = u64::from(meta.file_params.block_size);
    if !(MIB..=256 * MIB).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(VhdError::Msg(format!(
            "VHDX block size {block_size} is not a power of two in 1 MiB..=256 MiB"
        )));
    }
    if meta.virt_size == 0 || meta.virt_size > MAX_VIRT_SIZE {
        return Err(VhdError::Msg(format!(
            "VHDX virtual size {} is not in 1..={MAX_VIRT_SIZE}",
            meta.virt_size
        )));
    }
    let logical = u64::from(meta.logical_sector);
    if logical != 512 && logical != 4096 {
        return Err(VhdError::Msg(format!(
            "VHDX logical sector size {logical} is not 512 or 4096"
        )));
    }
    // chunk_ratio = (2^23 * logical_sector_size) / block_size
    let chunk_ratio = (8 * MIB)
        .checked_mul(logical)
        .and_then(|n| n.checked_div(block_size))
        .filter(|&n| n > 0)
        .ok_or_else(|| VhdError::Msg("VHDX chunk ratio overflow".into()))?;

    let payload_blocks = meta.virt_size.div_ceil(block_size);
    if payload_blocks > MAX_BAT_ENTRIES as u64 {
        return Err(VhdError::Msg(format!(
            "VHDX payload BAT would have {payload_blocks} entries (cap {MAX_BAT_ENTRIES})"
        )));
    }
    let bat_len = bat_reg.length as usize;
    if bat_len > MAX_BAT_ENTRIES * 8 {
        return Err(VhdError::Msg(format!(
            "VHDX BAT region length {bat_len} exceeds cap"
        )));
    }
    let mut bat_raw = vec![0u8; bat_len];
    reader.seek(SeekFrom::Start(bat_reg.file_offset))?;
    reader.read_exact(&mut bat_raw)?;

    let mut payload_bat = Vec::with_capacity(payload_blocks as usize);
    for i in 0..payload_blocks {
        let chunk = i / chunk_ratio;
        let off = i % chunk_ratio;
        let bat_index = chunk
            .saturating_mul(chunk_ratio.saturating_add(1))
            .saturating_add(off);
        let byte = (bat_index as usize).saturating_mul(8);
        if byte + 8 > bat_raw.len() {
            payload_bat.push(0);
            continue;
        }
        payload_bat.push(le_u64(&bat_raw, byte));
    }

    Ok((
        VirtualDisk::new(
            reader,
            DiskMap::Vhdx {
                payload_bat,
                block_size,
            },
            meta.virt_size,
        ),
        VhdKind::Vhdx,
    ))
}

/// Build a minimal fixed VHDX (1 MiB block, payload starting at 3 MiB). Tests only.
#[cfg(test)]
pub(crate) fn encode_fixed_vhdx(payload: &[u8], virt_size: u64) -> Result<Vec<u8>> {
    const BLOCK: u64 = MIB;
    // `% 512` not `is_multiple_of` — that method is rustc 1.87+ (MSRV 1.74).
    #[allow(clippy::manual_is_multiple_of)]
    if virt_size == 0 || virt_size % 512 != 0 {
        return Err(VhdError::Msg(
            "fixture virtual size must be a non-zero multiple of 512".into(),
        ));
    }
    let payload_blocks = virt_size.div_ceil(BLOCK).max(1);
    let payload_off = 3 * MIB;
    let file_len = payload_off + payload_blocks * BLOCK;
    let mut img = vec![0u8; file_len as usize];

    img[0..8].copy_from_slice(VHDX_SIG);
    // UTF-16LE creator "ratarmount"
    let creator = "ratarmount";
    for (i, c) in creator.encode_utf16().enumerate() {
        let o = 8 + i * 2;
        img[o..o + 2].copy_from_slice(&c.to_le_bytes());
    }

    write_header(&mut img, HEADER1_OFF as usize, 1);
    write_header(&mut img, HEADER2_OFF as usize, 1);

    let mut regions = vec![0u8; REGION_LEN];
    regions[0..4].copy_from_slice(REGION_SIG);
    regions[8..12].copy_from_slice(&2u32.to_le_bytes());
    // BAT at 2 MiB, 1 MiB long
    write_region_entry(&mut regions, 0, guid_bat(), 2 * MIB, MIB as u32, true);
    // Metadata at 1 MiB, 1 MiB long
    write_region_entry(&mut regions, 1, guid_metadata(), MIB, MIB as u32, true);
    let stored = {
        let mut tmp = regions.clone();
        tmp[4..8].fill(0);
        crc32c(&tmp)
    };
    regions[4..8].copy_from_slice(&stored.to_le_bytes());
    img[REGION1_OFF as usize..REGION1_OFF as usize + REGION_LEN].copy_from_slice(&regions);
    img[REGION2_OFF as usize..REGION2_OFF as usize + REGION_LEN].copy_from_slice(&regions);

    write_metadata_region(&mut img, MIB as usize, virt_size, BLOCK as u32);

    // BAT: one FULLY_PRESENT payload entry per block, FileOffsetMB = 3+i
    let bat_off = (2 * MIB) as usize;
    for i in 0..payload_blocks {
        let entry = ((3 + i) << 20) | VHDX_STATE_FULLY_PRESENT;
        let o = bat_off + (i as usize) * 8;
        img[o..o + 8].copy_from_slice(&entry.to_le_bytes());
    }

    let dest = payload_off as usize;
    let n = payload.len().min(img.len() - dest);
    img[dest..dest + n].copy_from_slice(&payload[..n]);
    Ok(img)
}

#[cfg(test)]
fn write_header(img: &mut [u8], off: usize, seq: u64) {
    let mut h = vec![0u8; HEADER_LEN];
    h[0..4].copy_from_slice(HEADER_SIG);
    h[8..16].copy_from_slice(&seq.to_le_bytes());
    h[66..68].copy_from_slice(&1u16.to_le_bytes()); // Version = 1
                                                    // LogGuid stays zero (log unused).
    let sum = crc32c(&h);
    h[4..8].copy_from_slice(&sum.to_le_bytes());
    img[off..off + HEADER_LEN].copy_from_slice(&h);
}

#[cfg(test)]
fn write_region_entry(
    table: &mut [u8],
    index: usize,
    guid: [u8; 16],
    file_offset: u64,
    length: u32,
    required: bool,
) {
    let e = 16 + index * 32;
    table[e..e + 16].copy_from_slice(&guid);
    table[e + 16..e + 24].copy_from_slice(&file_offset.to_le_bytes());
    table[e + 24..e + 28].copy_from_slice(&length.to_le_bytes());
    table[e + 28..e + 32].copy_from_slice(&(u32::from(required)).to_le_bytes());
}

#[cfg(test)]
fn write_metadata_region(img: &mut [u8], off: usize, virt_size: u64, block_size: u32) {
    // Item data starts at 64 KiB into the metadata region (spec minimum).
    const ITEMS: usize = 64 * 1024;
    img[off..off + 8].copy_from_slice(META_SIG);
    img[off + 10..off + 12].copy_from_slice(&5u16.to_le_bytes());

    // Each item Offset MUST be a multiple of 64 KiB (MS-VHDX).
    let mut put_item = |id: [u8; 16], data: &[u8], flags: u32, entry: usize| {
        let e = off + 32 + entry * 32;
        let item_rel = ITEMS * (entry + 1);
        img[e..e + 16].copy_from_slice(&id);
        img[e + 16..e + 20].copy_from_slice(&(item_rel as u32).to_le_bytes());
        img[e + 20..e + 24].copy_from_slice(&(data.len() as u32).to_le_bytes());
        img[e + 28..e + 32].copy_from_slice(&flags.to_le_bytes());
        img[off + item_rel..off + item_rel + data.len()].copy_from_slice(data);
    };

    // flags: IsVirtualDisk (bit 1) | IsRequired (bit 2) = 6; File Parameters is required only (4)
    let mut fp = [0u8; 8];
    fp[0..4].copy_from_slice(&block_size.to_le_bytes());
    fp[4..8].copy_from_slice(&1u32.to_le_bytes()); // LeaveBlockAllocated
    put_item(guid_file_params(), &fp, 4, 0);
    put_item(guid_virt_size(), &virt_size.to_le_bytes(), 6, 1);
    put_item(guid_logical_sector(), &512u32.to_le_bytes(), 6, 2);
    put_item(guid_physical_sector(), &512u32.to_le_bytes(), 6, 3);
    put_item(guid_disk_id(), &[0xABu8; 16], 6, 4);
}

#[cfg(test)]
fn guid_disk_id() -> [u8; 16] {
    guid(
        0xBECA_12AB,
        0xB2E6,
        0x4523,
        [0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7, 0x46],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn crc32c_known_vector() {
        // RFC 3720 / common CRC-32C vector.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn looks_like_false_on_vhd_cookie() {
        assert!(!looks_like_vhdx_reader(&mut Cursor::new(
            b"conectixxxxxxxxx"
        )));
    }

    #[test]
    fn encode_roundtrip_zeros() {
        let img = encode_fixed_vhdx(&[0x11, 0x22, 0x33], 1024 * 1024).unwrap();
        assert_eq!(&img[0..8], VHDX_SIG);
        let (mut disk, kind) = open_vhdx(Cursor::new(img)).unwrap();
        assert_eq!(kind, VhdKind::Vhdx);
        assert_eq!(disk.virt_size(), 1024 * 1024);
        let mut buf = [0u8; 3];
        disk.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0x11, 0x22, 0x33]);
    }
}
