//! Microsoft VHDX (fixed and sparse, no parent). Differencing / encrypted residual.

use std::collections::HashSet;
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
        [0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B],
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
        [0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F],
    )
}

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

fn guid_disk_id() -> [u8; 16] {
    guid(
        0xBECA_12AB,
        0xB2E6,
        0x4523,
        [0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7, 0x46],
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
    log_guid: [u8; 16],
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
        // Skip this copy; the sibling 4 KiB header may still be v1.
        log::debug!("VHDX header at {off:#x} version {version} is not 1");
        return Ok(None);
    }
    let mut log_guid = [0u8; 16];
    log_guid.copy_from_slice(&raw[48..64]);
    Ok(Some(Header {
        sequence: le_u64(&raw, 8),
        log_guid,
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
    let region_end = off
        .checked_add(u64::from(len))
        .ok_or_else(|| VhdError::Msg("VHDX metadata region offset overflow".into()))?;
    if region_end > reader.seek(SeekFrom::End(0))? {
        return Err(VhdError::Msg(
            "VHDX metadata region is outside the file".into(),
        ));
    }
    // Only the table has a fixed size. Items may be unaligned and anywhere
    // after it, including beyond the first MiB (MS-VHDX 2.6 / 2.6.1.2).
    let mut raw = vec![0u8; 64 * 1024];
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
    let mut item_ids = HashSet::new();
    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        let e = 32 + i * 32;
        if e + 32 > raw.len() {
            break;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&raw[e..e + 16]);
        let item_off = le_u32(&raw, e + 16);
        let item_len = le_u32(&raw, e + 20);
        let flags = le_u32(&raw, e + 24);
        let is_user = flags & 1 != 0;
        if !item_ids.insert((id, is_user)) {
            return Err(VhdError::Msg("VHDX duplicate metadata item".into()));
        }
        if item_len > MIB as u32 {
            return Err(VhdError::Msg("VHDX metadata item exceeds 1 MiB".into()));
        }
        // Empty items use Offset=Length=0. Nonempty items must not overlap
        // the table or run past the declared region; there is no alignment rule.
        if (item_len == 0 && item_off != 0) || (item_len != 0 && item_off < 64 * 1024) {
            return Err(VhdError::Msg(format!(
                "VHDX metadata item offset {item_off} is invalid for length {item_len}"
            )));
        }
        match item_off.checked_add(item_len) {
            Some(end) if end <= len => {
                if item_len != 0 {
                    ranges.push((item_off, end));
                }
            }
            _ => {
                return Err(VhdError::Msg(
                    "VHDX metadata item is outside the region".into(),
                ))
            }
        }
        let known = !is_user
            && (id == guid_file_params()
                || id == guid_virt_size()
                || id == guid_logical_sector()
                || id == guid_physical_sector()
                || id == guid_disk_id()
                || id == guid_parent_locator());
        if !known && flags & 4 != 0 {
            return Err(VhdError::Msg(format!(
                "VHDX required metadata item is unknown: {id:02x?}"
            )));
        }
        if !known {
            continue;
        }
        let mut item = vec![0u8; item_len as usize];
        reader.seek(SeekFrom::Start(off + u64::from(item_off)))?;
        reader.read_exact(&mut item)?;
        if id == guid_file_params() {
            if item.len() < 8 {
                return Err(VhdError::Msg(
                    "VHDX File Parameters item is truncated".into(),
                ));
            }
            let block_size = le_u32(&item, 0);
            let flags = le_u32(&item, 4);
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
            virt_size = Some(le_u64(&item, 0));
        } else if id == guid_logical_sector() {
            if item.len() < 4 {
                return Err(VhdError::Msg(
                    "VHDX Logical Sector Size item is truncated".into(),
                ));
            }
            logical_sector = Some(le_u32(&item, 0));
        } else if id == guid_parent_locator() {
            saw_parent = true;
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(VhdError::Msg("VHDX metadata items overlap".into()));
    }
    let file_params = file_params
        .ok_or_else(|| VhdError::Msg("VHDX metadata is missing File Parameters".into()))?;
    let virt_size = virt_size
        .ok_or_else(|| VhdError::Msg("VHDX metadata is missing Virtual Disk Size".into()))?;
    let logical_sector = logical_sector
        .ok_or_else(|| VhdError::Msg("VHDX metadata is missing Logical Sector Size".into()))?;
    if file_params.has_parent || saw_parent {
        return Err(VhdError::Msg(
            "differencing VHDX is residual (no parent chain)".into(),
        ));
    }
    if logical_sector != 512 && logical_sector != 4096 {
        return Err(VhdError::Msg(format!(
            "VHDX logical sector size {logical_sector} is not 512 or 4096"
        )));
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
    if header.log_guid.iter().any(|&b| b != 0) {
        return Err(VhdError::Msg(
            "VHDX log replay is residual (LogGuid is non-zero)".into(),
        ));
    }

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
    // `% 512` not `is_multiple_of` — that method is rustc 1.87+ (written for the former 1.74 MSRV).
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

    write_header(&mut img, HEADER1_OFF as usize, 1, [0u8; 16]);
    write_header(&mut img, HEADER2_OFF as usize, 1, [0u8; 16]);

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
fn write_header(img: &mut [u8], off: usize, seq: u64, log_guid: [u8; 16]) {
    let mut h = vec![0u8; HEADER_LEN];
    h[0..4].copy_from_slice(HEADER_SIG);
    h[8..16].copy_from_slice(&seq.to_le_bytes());
    h[48..64].copy_from_slice(&log_guid);
    h[66..68].copy_from_slice(&1u16.to_le_bytes()); // Version = 1
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

    // qemu-img 11 packs items consecutively after the 64 KiB metadata table.
    let mut item_rel = ITEMS;
    let mut put_item = |id: [u8; 16], data: &[u8], flags: u32, entry: usize| {
        let e = off + 32 + entry * 32;
        img[e..e + 16].copy_from_slice(&id);
        img[e + 16..e + 20].copy_from_slice(&(item_rel as u32).to_le_bytes());
        img[e + 20..e + 24].copy_from_slice(&(data.len() as u32).to_le_bytes());
        img[e + 24..e + 28].copy_from_slice(&flags.to_le_bytes());
        img[off + item_rel..off + item_rel + data.len()].copy_from_slice(data);
        item_rel += data.len();
    };

    // flags: IsVirtualDisk (bit 1) | IsRequired (bit 2) = 6; File Parameters is required only (4)
    let mut fp = [0u8; 8];
    fp[0..4].copy_from_slice(&block_size.to_le_bytes());
    fp[4..8].copy_from_slice(&1u32.to_le_bytes()); // LeaveBlockAllocated
                                                   // Literal GUIDs keep the fixture independent of the parser's identifiers.
    put_item(
        [
            0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44,
            0xE7, 0x6B,
        ],
        &fp,
        4,
        0,
    );
    put_item(guid_virt_size(), &virt_size.to_le_bytes(), 6, 1);
    put_item(guid_disk_id(), &[0xABu8; 16], 6, 2);
    // Literal on-disk GUID from MS-VHDX 2.6.2 / qemu-img, independent of the parser.
    put_item(
        [
            0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA,
            0xAB, 0x5F,
        ],
        &512u32.to_le_bytes(),
        6,
        3,
    );
    put_item(guid_physical_sector(), &512u32.to_le_bytes(), 6, 4);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Regression: qemu-img 11 fixed VHDX fails on its packed metadata offsets.
    #[test]
    fn regression_qemu11_vhdx_packed_metadata() {
        let img = encode_fixed_vhdx(b"qemu11 payload", MIB).unwrap();
        let meta = MIB as usize;
        for (entry, offset) in [0x10000, 0x10008, 0x10010, 0x10020, 0x10024]
            .into_iter()
            .enumerate()
        {
            assert_eq!(le_u32(&img, meta + 32 + entry * 32 + 16), offset);
        }
        let (mut disk, kind) = open_vhdx(Cursor::new(img)).expect("qemu11 packed metadata");
        assert_eq!(kind, VhdKind::Vhdx);
        let mut got = [0u8; 14];
        disk.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"qemu11 payload");
    }

    /// Regression: the qemu/MS-VHDX logical-sector GUID must not default to 512.
    #[test]
    fn regression_qemu11_vhdx_logical_sector_guid() {
        let mut img = encode_fixed_vhdx(&[], MIB).unwrap();
        let sector = MIB as usize + 0x10020;
        img[sector..sector + 4].copy_from_slice(&4096u32.to_le_bytes());
        let meta = parse_metadata(&mut Cursor::new(img), MIB, MIB as u32).unwrap();
        assert_eq!(meta.logical_sector, 4096);
    }

    fn metadata_image() -> Vec<u8> {
        let mut img = vec![0u8; MIB as usize];
        write_metadata_region(&mut img, 0, MIB, MIB as u32);
        img
    }

    /// Regression: valid unaligned, unordered items beyond 1 MiB must open.
    #[test]
    fn regression_vhdx_metadata_unaligned_unordered_beyond_first_mib() {
        let mut img = metadata_image();
        img.resize(2 * MIB as usize, 0);
        for (i, relative) in [47, 31, 1, 19, 25].into_iter().enumerate() {
            let e = 32 + i * 32;
            let old = le_u32(&img, e + 16) as usize;
            let len = le_u32(&img, e + 20) as usize;
            let new = MIB as usize + relative;
            img.copy_within(old..old + len, new);
            img[e + 16..e + 20].copy_from_slice(&(new as u32).to_le_bytes());
        }
        // The table itself is unsorted too.
        for i in 0..32 {
            img.swap(32 + i, 32 + 4 * 32 + i);
        }
        let meta = parse_metadata(&mut Cursor::new(img), 0, 2 * MIB as u32).unwrap();
        assert_eq!(meta.virt_size, MIB);
        assert_eq!(meta.file_params.block_size, MIB as u32);
        assert_eq!(meta.logical_sector, 512);
    }

    /// Regression: relaxing item alignment must retain metadata bounds checks.
    #[test]
    fn regression_vhdx_metadata_invalid_ranges_rejected() {
        for (offset, len, expected) in [
            (65535, 8, "offset"),
            (MIB as u32 - 4, 8, "outside the region"),
            (u32::MAX - 3, 8, "outside the region"),
            (65536, MIB as u32 + 1, "exceeds 1 MiB"),
            (0, 8, "offset"),
            (65536, 0, "offset"),
        ] {
            let mut img = metadata_image();
            img[48..52].copy_from_slice(&offset.to_le_bytes());
            img[52..56].copy_from_slice(&len.to_le_bytes());
            let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
                .err()
                .expect("invalid metadata range must fail");
            assert!(err.to_string().contains(expected), "unexpected: {err}");
        }
        let mut img = metadata_image();
        img.pop();
        let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
            .err()
            .expect("truncated region must fail");
        assert!(err.to_string().contains("outside the file"), "{err}");
    }

    /// Regression: packed metadata must not allow overlapping or duplicate items.
    #[test]
    fn regression_vhdx_metadata_overlap_and_duplicate_rejected() {
        let mut img = metadata_image();
        // Disk ID is not used to interpret guest bytes, but its span still counts.
        let disk_id = 32 + 2 * 32;
        img[disk_id + 16..disk_id + 20].copy_from_slice(&65536u32.to_le_bytes());
        let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
            .err()
            .expect("overlapping item must fail");
        assert!(err.to_string().contains("overlap"), "{err}");

        let mut img = metadata_image();
        img.copy_within(32..48, disk_id);
        let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
            .err()
            .expect("duplicate item must fail");
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    /// Regression: unknown required metadata fails; optional empty items are valid.
    #[test]
    fn regression_vhdx_metadata_unknown_required_and_empty_optional() {
        let mut img = metadata_image();
        let e = 32 + 5 * 32;
        img[10..12].copy_from_slice(&6u16.to_le_bytes());
        img[e..e + 16].fill(0x77);
        // Offset=Length=0 is valid for this unknown optional item.
        parse_metadata(&mut Cursor::new(&img), 0, MIB as u32).unwrap();
        img[e + 24..e + 28].copy_from_slice(&4u32.to_le_bytes());
        let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
            .err()
            .expect("unknown required item must fail");
        assert!(err.to_string().contains("required metadata"), "{err}");
    }

    /// Regression: missing/truncated core metadata cannot silently use defaults.
    #[test]
    fn regression_vhdx_metadata_missing_and_truncated_items_rejected() {
        for (entry, len) in [(0, 0u32), (1, 4), (3, 2)] {
            let mut img = metadata_image();
            let e = 32 + entry * 32;
            img[e + 20..e + 24].copy_from_slice(&len.to_le_bytes());
            if len == 0 {
                img[e + 16..e + 20].fill(0);
            }
            let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
                .err()
                .expect("truncated core item must fail");
            assert!(err.to_string().contains("truncated"), "{err}");
        }
        let mut img = metadata_image();
        let e = 32 + 3 * 32;
        img[e..e + 16].fill(0x77);
        img[e + 24..e + 28].fill(0);
        let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
            .err()
            .expect("missing Logical Sector Size must fail");
        assert!(
            err.to_string().contains("missing Logical Sector Size"),
            "{err}"
        );
    }

    /// Regression: MS-VHDX GUID helpers must match the spec's on-disk bytes.
    #[test]
    fn regression_vhdx_metadata_guid_bytes() {
        assert_eq!(
            guid_bat(),
            [
                0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD,
                0x4A, 0x08,
            ]
        );
        assert_eq!(
            guid_metadata(),
            [
                0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F,
                0x88, 0x6E,
            ]
        );
        assert_eq!(
            guid_file_params(),
            [
                0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44,
                0xE7, 0x6B,
            ]
        );
        assert_eq!(
            guid_virt_size(),
            [
                0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B,
                0xF4, 0xB8,
            ]
        );
        assert_eq!(
            guid_logical_sector(),
            [
                0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA,
                0xAB, 0x5F,
            ]
        );
        assert_eq!(
            guid_physical_sector(),
            [
                0xC7, 0x48, 0xA3, 0xCD, 0x5D, 0x44, 0x71, 0x44, 0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51,
                0xC5, 0x56,
            ]
        );
        assert_eq!(
            guid_parent_locator(),
            [
                0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45, 0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34,
                0xAB, 0x0C,
            ]
        );
        assert_eq!(
            guid_disk_id(),
            [
                0xAB, 0x12, 0xCA, 0xBE, 0xE6, 0xB2, 0x23, 0x45, 0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00,
                0xC7, 0x46,
            ]
        );
    }

    /// Regression: region length 65536 is not "< 64 KiB"; 65535 is.
    #[test]
    fn regression_vhdx_metadata_region_len_64kib_edge() {
        let mut img = vec![0u8; 65536];
        img[0..8].copy_from_slice(b"metadata");
        let err = parse_metadata(&mut Cursor::new(img), 0, 65536)
            .err()
            .expect("64 KiB region with no items");
        let msg = err.to_string();
        assert!(msg.contains("missing File Parameters"), "{msg}");
        assert!(!msg.contains("< 64 KiB"), "{msg}");

        let err = parse_metadata(&mut Cursor::new(Vec::<u8>::new()), 0, 65535)
            .err()
            .expect("65535-byte region must fail the minimum");
        assert!(err.to_string().contains("< 64 KiB"), "{err}");
    }

    /// Regression: entry count 2047 is accepted; 2048 is too large.
    #[test]
    fn regression_vhdx_metadata_entry_count_2047_edge() {
        let mut img = metadata_image();
        // Index 2046 sits at byte 65504, so e + 32 == raw.len() and `>` must keep it.
        let logical = 32 + 3 * 32;
        img.copy_within(logical..logical + 32, 32 + 2046 * 32);
        // Whole 32-byte filler, not just the id. id[0] = 0xEE and the index is a
        // little-endian u16 at bytes 1..3. A single id byte collides past 255.
        for i in 0..2047 {
            if matches!(i, 0 | 1 | 2 | 4 | 2046) {
                continue;
            }
            let e = 32 + i * 32;
            img[e..e + 32].fill(0);
            img[e] = 0xEE;
            img[e + 1..e + 3].copy_from_slice(&(i as u16).to_le_bytes());
        }
        img[10..12].copy_from_slice(&2047u16.to_le_bytes());
        let meta = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
            .expect("2047 entries at the table end");
        assert_eq!(meta.logical_sector, 512);
        assert_eq!(meta.virt_size, MIB);
        assert_eq!(meta.file_params.block_size, MIB as u32);

        // Leave the 2048-count image unfilled. Removing the cap yields
        // "VHDX duplicate metadata item" (the zero tail shares one id),
        // so the "entry count 2048" assertion still fails.
        let mut img = metadata_image();
        img[10..12].copy_from_slice(&2048u16.to_le_bytes());
        let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
            .err()
            .expect("entry count 2048 must fail");
        assert!(err.to_string().contains("entry count 2048"), "{err}");
    }

    /// Regression: a metadata item of exactly 1 MiB is accepted; one byte over is not.
    #[test]
    fn regression_vhdx_metadata_item_len_1mib_edge() {
        // Physical Sector Size (entry 4): offset 0x10024, length field at byte 180.
        const PHYS_LEN_AT: usize = 32 + 4 * 32 + 20;
        let accept_end = 0x10024 + 1_048_576;
        let mut img = metadata_image();
        img.resize(accept_end, 0);
        img[PHYS_LEN_AT..PHYS_LEN_AT + 4].copy_from_slice(&1_048_576u32.to_le_bytes());
        let meta = parse_metadata(&mut Cursor::new(img), 0, accept_end as u32)
            .expect("item length of exactly 1 MiB");
        assert_eq!(meta.logical_sector, 512);

        let mut img = metadata_image();
        img[PHYS_LEN_AT..PHYS_LEN_AT + 4].copy_from_slice(&1_048_577u32.to_le_bytes());
        let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
            .err()
            .expect("item length of 1 MiB + 1 must fail");
        assert!(err.to_string().contains("exceeds 1 MiB"), "{err}");
    }

    /// Regression: logical sector sizes other than 512 and 4096 fail in parse_metadata.
    #[test]
    fn regression_vhdx_metadata_logical_sector_rejected() {
        for sector in [512u32, 4096] {
            let mut img = metadata_image();
            img[0x10020..0x10024].copy_from_slice(&sector.to_le_bytes());
            let meta = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
                .expect("512 and 4096 are valid logical sectors");
            assert_eq!(meta.logical_sector, sector);
        }
        for sector in [0u32, 511, 513, 1024, 4095, 4097, 8192] {
            let mut img = metadata_image();
            img[0x10020..0x10024].copy_from_slice(&sector.to_le_bytes());
            let err = parse_metadata(&mut Cursor::new(img), 0, MIB as u32)
                .err()
                .expect("logical sector other than 512 or 4096 must fail");
            assert!(
                err.to_string().contains("not 512 or 4096"),
                "sector {sector}: {err}"
            );
        }
    }

    /// Regression: open_vhdx accepts logical sector 4096 and rejects 1024.
    #[test]
    fn regression_vhdx_metadata_logical_sector_open() {
        let patch = MIB as usize + 0x10020;
        let mut img = encode_fixed_vhdx(b"x", MIB).unwrap();
        img[patch..patch + 4].copy_from_slice(&4096u32.to_le_bytes());
        let (mut disk, kind) = open_vhdx(Cursor::new(img)).expect("4096 logical sector opens");
        assert_eq!(kind, VhdKind::Vhdx);
        let mut byte = [0u8; 1];
        disk.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], b'x');

        let mut img = encode_fixed_vhdx(b"x", MIB).unwrap();
        img[patch..patch + 4].copy_from_slice(&1024u32.to_le_bytes());
        let err = open_vhdx(Cursor::new(img))
            .err()
            .expect("logical sector 1024 must fail");
        assert!(err.to_string().contains("not 512 or 4096"), "{err}");
    }

    /// Regression: even an all-zero log cannot bypass the non-zero LogGuid refusal.
    #[test]
    fn regression_vhdx_nonzero_log_guid_with_empty_log_rejected() {
        let mut img = encode_fixed_vhdx(b"payload", MIB).unwrap();
        let log_offset = img.len();
        img.resize(log_offset + MIB as usize, 0);
        write_header(&mut img, HEADER2_OFF as usize, 2, [0xAA; 16]);
        for off in [HEADER1_OFF as usize, HEADER2_OFF as usize] {
            let header = &mut img[off..off + HEADER_LEN];
            header[68..72].copy_from_slice(&(MIB as u32).to_le_bytes());
            header[72..80].copy_from_slice(&(log_offset as u64).to_le_bytes());
            header[4..8].fill(0);
            let sum = crc32c(header);
            header[4..8].copy_from_slice(&sum.to_le_bytes());
        }
        let err = open_vhdx(Cursor::new(img))
            .err()
            .expect("non-zero LogGuid with empty log must fail closed");
        assert!(err.to_string().contains("log replay"), "{err}");
    }

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

    /// Regression: non-zero LogGuid is fail-closed (replay residual).
    #[test]
    fn log_guid_nonzero_is_residual() {
        let mut img = encode_fixed_vhdx(&[0x11, 0x22, 0x33], 1024 * 1024).unwrap();
        write_header(&mut img, HEADER1_OFF as usize, 2, [0xAAu8; 16]);
        write_header(&mut img, HEADER2_OFF as usize, 1, [0u8; 16]);
        let err = match open_vhdx(Cursor::new(img)) {
            Err(e) => e,
            Ok(_) => panic!("active VHDX log must fail closed"),
        };
        assert!(err.to_string().contains("log replay"), "unexpected: {err}");
    }

    /// Regression: CRC-valid version≠1 header is skipped; sibling v1 still opens.
    #[test]
    fn header_version_not_1_tries_sibling() {
        let mut img = encode_fixed_vhdx(&[0x11], 1024 * 1024).unwrap();
        let mut h = vec![0u8; HEADER_LEN];
        h[0..4].copy_from_slice(HEADER_SIG);
        h[8..16].copy_from_slice(&3u64.to_le_bytes());
        h[66..68].copy_from_slice(&2u16.to_le_bytes());
        let sum = crc32c(&h);
        h[4..8].copy_from_slice(&sum.to_le_bytes());
        img[HEADER1_OFF as usize..HEADER1_OFF as usize + HEADER_LEN].copy_from_slice(&h);
        let (disk, kind) = open_vhdx(Cursor::new(img)).expect("sibling v1 header");
        assert_eq!(kind, VhdKind::Vhdx);
        assert_eq!(disk.virt_size(), 1024 * 1024);
    }
}
