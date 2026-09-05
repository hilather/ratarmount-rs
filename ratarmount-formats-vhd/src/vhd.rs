//! Connectix VHD footer + dynamic BAT (big-endian). Differencing is residual.

use std::io::{self, Read, Seek, SeekFrom};

use crate::disk::{vhd_bitmap_size, DiskMap, VirtualDisk};
use crate::{Result, VhdError, VhdKind};

pub(crate) const VHD_COOKIE: &[u8; 8] = b"conectix";
const VHD_SPARSE_COOKIE: &[u8; 8] = b"cxsparse";
const VHD_FOOTER_LEN: u64 = 512;
const VHD_DYNAMIC_HEADER_LEN: u64 = 1024;
const VHD_TYPE_FIXED: u32 = 2;
const VHD_TYPE_DYNAMIC: u32 = 3;
const VHD_TYPE_DIFFERENCING: u32 = 4;
/// 4 Mi entries × 4 bytes = 16 MiB BAT; 2 MiB blocks → 8 TiB virtual.
const MAX_BAT_ENTRIES: u32 = 4 * 1024 * 1024;
const MAX_VIRT_SIZE: u64 = 64 * 1024 * 1024 * 1024 * 1024; // 64 TiB

#[derive(Clone, Debug)]
pub(crate) struct VhdFooter {
    pub data_offset: u64,
    pub current_size: u64,
    pub disk_type: u32,
}

pub(crate) fn looks_like_vhd_reader<R: Read + Seek>(reader: &mut R) -> bool {
    let mut mag = [0u8; 8];
    if reader.seek(SeekFrom::Start(0)).is_ok()
        && reader.read_exact(&mut mag).is_ok()
        && mag == *VHD_COOKIE
    {
        return true;
    }
    let Ok(end) = reader.seek(SeekFrom::End(0)) else {
        return false;
    };
    if end < VHD_FOOTER_LEN {
        return false;
    }
    reader.seek(SeekFrom::Start(end - VHD_FOOTER_LEN)).is_ok()
        && reader.read_exact(&mut mag).is_ok()
        && mag == *VHD_COOKIE
}

pub(crate) fn open_vhd<R>(mut reader: R) -> Result<(VirtualDisk, VhdKind)>
where
    R: Read + Seek + Send + 'static,
{
    let file_len = reader.seek(SeekFrom::End(0))?;
    if file_len < VHD_FOOTER_LEN {
        return Err(VhdError::Msg(
            "VHD is shorter than a 512-byte footer".into(),
        ));
    }
    let mut footer_raw = [0u8; 512];
    reader.seek(SeekFrom::Start(file_len - VHD_FOOTER_LEN))?;
    reader.read_exact(&mut footer_raw)?;
    let footer = parse_footer(&footer_raw)?;
    if footer.current_size == 0 || footer.current_size > MAX_VIRT_SIZE {
        return Err(VhdError::Msg(format!(
            "VHD virtual size {} is not in 1..={MAX_VIRT_SIZE}",
            footer.current_size
        )));
    }
    match footer.disk_type {
        VHD_TYPE_FIXED => {
            let data_end = file_len - VHD_FOOTER_LEN;
            if footer.current_size > data_end {
                return Err(VhdError::Msg(format!(
                    "fixed VHD current_size {} exceeds file data {}",
                    footer.current_size, data_end
                )));
            }
            Ok((
                VirtualDisk::new(reader, DiskMap::Fixed, footer.current_size),
                VhdKind::FixedVhd,
            ))
        }
        VHD_TYPE_DYNAMIC => {
            let disk = open_dynamic(reader, &footer, file_len)?;
            Ok((disk, VhdKind::DynamicVhd))
        }
        VHD_TYPE_DIFFERENCING => Err(VhdError::Msg(
            "differencing VHD is residual (no parent chain)".into(),
        )),
        t => Err(VhdError::Msg(format!("unsupported VHD disk type {t}"))),
    }
}

/// Connectix/MS VHD footer (big-endian). Offsets match qemu-img / VirtualBox
/// (`CurrentSize` @ 48, `DiskType` @ 60, checksum @ 64) — not a +4 shift.
const FOOTER_DATA_OFFSET: usize = 16;
#[cfg(test)]
const FOOTER_ORIGINAL_SIZE: usize = 40;
const FOOTER_CURRENT_SIZE: usize = 48;
#[cfg(test)]
const FOOTER_GEOMETRY: usize = 56;
const FOOTER_DISK_TYPE: usize = 60;
const FOOTER_CHECKSUM: usize = 64;
#[cfg(test)]
const FOOTER_UNIQUE_ID: usize = 68;

fn parse_footer(raw: &[u8; 512]) -> Result<VhdFooter> {
    if raw[0..8] != *VHD_COOKIE {
        return Err(VhdError::Msg("VHD footer cookie is not 'conectix'".into()));
    }
    let stored = be_u32(raw, FOOTER_CHECKSUM);
    let calc = vhd_checksum(raw, FOOTER_CHECKSUM);
    if stored != calc {
        log::warn!(
            "VHD footer checksum mismatch (stored {stored:#08x}, calc {calc:#08x}); parsing anyway"
        );
    }
    Ok(VhdFooter {
        data_offset: be_u64(raw, FOOTER_DATA_OFFSET),
        current_size: be_u64(raw, FOOTER_CURRENT_SIZE),
        disk_type: be_u32(raw, FOOTER_DISK_TYPE),
    })
}

fn open_dynamic<R>(mut reader: R, footer: &VhdFooter, file_len: u64) -> Result<VirtualDisk>
where
    R: Read + Seek + Send + 'static,
{
    let hdr_off = footer.data_offset;
    match hdr_off.checked_add(VHD_DYNAMIC_HEADER_LEN) {
        Some(end) if hdr_off != u64::MAX && end <= file_len => {}
        _ => {
            return Err(VhdError::Msg(format!(
                "dynamic VHD header offset {hdr_off} is out of range"
            )))
        }
    }
    let mut hdr = [0u8; 1024];
    reader.seek(SeekFrom::Start(hdr_off))?;
    reader.read_exact(&mut hdr)?;
    if hdr[0..8] != *VHD_SPARSE_COOKIE {
        return Err(VhdError::Msg(
            "dynamic VHD header cookie is not 'cxsparse'".into(),
        ));
    }
    let stored = be_u32(&hdr, 36);
    let calc = vhd_checksum(&hdr, 36);
    if stored != calc {
        log::warn!(
            "dynamic VHD header checksum mismatch (stored {stored:#08x}, calc {calc:#08x}); parsing anyway"
        );
    }
    let table_offset = be_u64(&hdr, 16);
    let max_entries = be_u32(&hdr, 28);
    let block_size = u64::from(be_u32(&hdr, 32));
    if block_size < 512 || !block_size.is_power_of_two() {
        return Err(VhdError::Msg(format!(
            "dynamic VHD block size {block_size} is not a power of two ≥ 512"
        )));
    }
    if max_entries == 0 || max_entries > MAX_BAT_ENTRIES {
        return Err(VhdError::Msg(format!(
            "dynamic VHD BAT entries {max_entries} is not in 1..={MAX_BAT_ENTRIES}"
        )));
    }
    let needed = footer.current_size.div_ceil(block_size);
    if u64::from(max_entries) < needed {
        return Err(VhdError::Msg(format!(
            "dynamic VHD BAT has {max_entries} entries but virtual size needs {needed}"
        )));
    }
    let bat_bytes = (max_entries as usize)
        .checked_mul(4)
        .ok_or_else(|| VhdError::Msg("dynamic VHD BAT size overflow".into()))?;
    match table_offset.checked_add(bat_bytes as u64) {
        Some(end) if end <= file_len => {}
        _ => {
            return Err(VhdError::Msg(format!(
                "dynamic VHD BAT at {table_offset} is out of range"
            )))
        }
    }
    let mut raw = vec![0u8; bat_bytes];
    reader.seek(SeekFrom::Start(table_offset))?;
    reader.read_exact(&mut raw)?;
    let mut bat = Vec::with_capacity(max_entries as usize);
    for chunk in raw.chunks_exact(4) {
        bat.push(u32::from_be_bytes(chunk.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "BAT entry")
        })?));
    }
    let bitmap_size = vhd_bitmap_size(block_size);
    Ok(VirtualDisk::new(
        reader,
        DiskMap::DynamicVhd {
            bat,
            block_size,
            bitmap_size,
        },
        footer.current_size,
    ))
}

fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn be_u64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
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

/// One's complement of the sum of all bytes except the 4-byte checksum field.
fn vhd_checksum(raw: &[u8], checksum_off: usize) -> u32 {
    let mut sum = 0u32;
    for (i, &b) in raw.iter().enumerate() {
        if (checksum_off..checksum_off + 4).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(b));
    }
    !sum
}

/// CHS for a virtual size (Connectix algorithm). Used by the fixture encoder.
#[cfg(test)]
pub(crate) fn vhd_geometry(size: u64) -> (u16, u8, u8) {
    let mut total_sectors = (size / 512) as u32;
    let max = 65535u32 * 16 * 255;
    if total_sectors > max {
        total_sectors = max;
    }
    let (cylinders, heads, spt);
    if total_sectors >= 65535 * 16 * 63 {
        spt = 255u8;
        heads = 16u8;
        cylinders = (total_sectors / (u32::from(heads) * u32::from(spt))) as u16;
    } else {
        let mut s = 17u8;
        let mut cth = total_sectors / u32::from(s);
        let mut h = cth.div_ceil(1024).max(4);
        if cth >= h * 1024 || h > 16 {
            s = 31;
            h = 16;
            cth = total_sectors / u32::from(s);
        }
        if cth >= h * 1024 {
            s = 63;
            h = 16;
            cth = total_sectors / u32::from(s);
        }
        spt = s;
        heads = h as u8;
        cylinders = (cth / h) as u16;
    }
    (cylinders, heads, spt)
}

/// Encode a 512-byte VHD footer (tests + fixture builders).
#[cfg(test)]
pub(crate) fn encode_footer(current_size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
    let mut raw = [0u8; 512];
    raw[0..8].copy_from_slice(VHD_COOKIE);
    raw[8..12].copy_from_slice(&0x0000_0002u32.to_be_bytes()); // reserved feature bit
    raw[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    raw[FOOTER_DATA_OFFSET..FOOTER_DATA_OFFSET + 8].copy_from_slice(&data_offset.to_be_bytes());
    raw[28..32].copy_from_slice(b"rtr ");
    raw[32..36].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // creator version
    raw[36..40].copy_from_slice(b"Wi2k");
    raw[FOOTER_ORIGINAL_SIZE..FOOTER_ORIGINAL_SIZE + 8]
        .copy_from_slice(&current_size.to_be_bytes());
    raw[FOOTER_CURRENT_SIZE..FOOTER_CURRENT_SIZE + 8].copy_from_slice(&current_size.to_be_bytes());
    let (cyl, heads, spt) = vhd_geometry(current_size);
    raw[FOOTER_GEOMETRY..FOOTER_GEOMETRY + 2].copy_from_slice(&cyl.to_be_bytes());
    raw[FOOTER_GEOMETRY + 2] = heads;
    raw[FOOTER_GEOMETRY + 3] = spt;
    raw[FOOTER_DISK_TYPE..FOOTER_DISK_TYPE + 4].copy_from_slice(&disk_type.to_be_bytes());
    raw[FOOTER_UNIQUE_ID..FOOTER_UNIQUE_ID + 16].fill(0x11);
    let sum = vhd_checksum(&raw, FOOTER_CHECKSUM);
    raw[FOOTER_CHECKSUM..FOOTER_CHECKSUM + 4].copy_from_slice(&sum.to_be_bytes());
    raw
}

#[cfg(test)]
pub(crate) fn encode_dynamic_header(
    table_offset: u64,
    max_entries: u32,
    block_size: u32,
) -> [u8; 1024] {
    let mut hdr = [0u8; 1024];
    hdr[0..8].copy_from_slice(VHD_SPARSE_COOKIE);
    hdr[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    hdr[16..24].copy_from_slice(&table_offset.to_be_bytes());
    hdr[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    hdr[28..32].copy_from_slice(&max_entries.to_be_bytes());
    hdr[32..36].copy_from_slice(&block_size.to_be_bytes());
    let sum = vhd_checksum(&hdr, 36);
    hdr[36..40].copy_from_slice(&sum.to_be_bytes());
    hdr
}

#[cfg(test)]
pub(crate) const DISK_TYPE_FIXED: u32 = VHD_TYPE_FIXED;
#[cfg(test)]
pub(crate) const DISK_TYPE_DYNAMIC: u32 = VHD_TYPE_DYNAMIC;
#[cfg(test)]
pub(crate) const DISK_TYPE_DIFFERENCING: u32 = VHD_TYPE_DIFFERENCING;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn footer_checksum_roundtrip() {
        let raw = encode_footer(1024 * 1024, VHD_TYPE_FIXED, u64::MAX);
        let f = parse_footer(&raw).unwrap();
        assert_eq!(f.current_size, 1024 * 1024);
        assert_eq!(f.disk_type, VHD_TYPE_FIXED);
        assert_eq!(
            vhd_checksum(&raw, FOOTER_CHECKSUM),
            be_u32(&raw, FOOTER_CHECKSUM)
        );
    }

    /// Regression: Connectix layout is Current Size @ 48, Disk Type @ 60
    /// (not the +4 shift that only round-trips `encode_footer`).
    #[test]
    fn parse_footer_spec_offsets_not_encoder_relative() {
        let mut raw = [0u8; 512];
        raw[0..8].copy_from_slice(VHD_COOKIE);
        raw[8..12].copy_from_slice(&0x0000_0002u32.to_be_bytes());
        raw[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        raw[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        let current = 2u64 * 1024 * 1024;
        raw[40..48].copy_from_slice(&current.to_be_bytes());
        raw[48..56].copy_from_slice(&current.to_be_bytes());
        raw[56..58].copy_from_slice(&1u16.to_be_bytes());
        raw[58] = 16;
        raw[59] = 63;
        raw[60..64].copy_from_slice(&2u32.to_be_bytes());
        let sum = vhd_checksum(&raw, 64);
        raw[64..68].copy_from_slice(&sum.to_be_bytes());
        let f = parse_footer(&raw).expect("spec-layout footer");
        assert_eq!(f.current_size, current);
        assert_eq!(f.disk_type, VHD_TYPE_FIXED);
        assert_eq!(f.data_offset, u64::MAX);
    }

    #[test]
    fn looks_like_false_on_short() {
        assert!(!looks_like_vhd_reader(&mut Cursor::new(b"conect")));
    }

    #[test]
    fn differencing_is_residual() {
        let mut img = vec![0u8; 1024];
        let footer = encode_footer(512, VHD_TYPE_DIFFERENCING, u64::MAX);
        img[512..].copy_from_slice(&footer);
        let err = match open_vhd(Cursor::new(img)) {
            Err(e) => e,
            Ok(_) => panic!("differencing VHD must fail"),
        };
        assert!(
            err.to_string().contains("differencing"),
            "unexpected: {err}"
        );
    }
}
