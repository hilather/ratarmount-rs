//! GPT and MBR partition-table parse (no filesystem open).
//!
//! QCOW2/VHD/VMDK crates can feed a raw virtual disk [`Read`] + [`Seek`] here,
//! then open the resulting partitions with FAT/EXT4 `open_*_with_offset`.

use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom};

use crate::{BlockError, Result};

/// Assumed MBR sector size (512e). GPT also tries 4096-byte native.
pub const DEFAULT_SECTOR_SIZE: u32 = 512;

const MBR_SIG_OFF: usize = 510;
const MBR_TABLE_OFF: usize = 446;
const MBR_ENTRY_LEN: usize = 16;
const MBR_ENTRY_COUNT: usize = 4;
const GPT_SIG: &[u8; 8] = b"EFI PART";
const GPT_HEADER_MIN: u32 = 92;
const MAX_GPT_ENTRIES: u32 = 256;
/// UEFI: `SizeOfPartitionEntry` is `128 × 2^n`; 128 is typical, 4096 is a hard cap.
const MAX_GPT_ENTRY_SIZE: u32 = 4096;
/// 256 × 128 — reject crafted headers before `vec![0; array_len]`.
const MAX_GPT_ARRAY_BYTES: usize = 32 * 1024;
const MAX_EBR_LOGICAL: usize = 64;

/// Protective MBR partition type (`0xEE`).
pub const MBR_TYPE_GPT_PROTECTIVE: u8 = 0xEE;
/// Extended CHS (`0x05`) / LBA (`0x0F`).
pub const MBR_TYPE_EXTENDED: u8 = 0x05;
pub const MBR_TYPE_EXTENDED_LBA: u8 = 0x0F;
/// Linux LVM (`0x8E`) — residual (not mounted).
pub const MBR_TYPE_LINUX_LVM: u8 = 0x8E;

/// On-disk partition scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionScheme {
    Mbr,
    Gpt,
}

/// Best-effort type classification for skip vs filesystem probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionKind {
    Unknown,
    /// FAT12/16/32 (MBR 0x01/0x04/0x06/0x0B/0x0C/0x0E).
    Fat,
    /// Linux filesystem (MBR 0x83 / GPT Linux FS) — typically EXT4.
    LinuxFs,
    /// NTFS / exFAT (MBR 0x07 / GPT Microsoft basic data). Try FAT until those crates exist.
    NtfsExfat,
    /// EFI System Partition (often FAT).
    Efi,
    /// Linux LVM — **residual** (not mounted).
    LinuxLvm,
    /// Linux RAID — **residual**.
    LinuxRaid,
    Swap,
    /// Extended container (EBR chain, not a filesystem).
    Extended,
    /// Microsoft reserved / BIOS boot / similar — no filesystem.
    Reserved,
}

impl PartitionKind {
    /// True when this crate will not attempt a filesystem open (LVM/RAID/swap/…).
    pub fn is_mount_residual(self) -> bool {
        matches!(
            self,
            Self::LinuxLvm | Self::LinuxRaid | Self::Swap | Self::Extended | Self::Reserved
        )
    }
}

/// One MBR slot, GPT entry, or logical (EBR) partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    /// 1-based `pN` name: encounter order of non-empty table slots (including
    /// residual LVM/RAID/swap/MSR). Empty (all-zero GPT type) is not numbered.
    /// Only mounted filesystems appear under `/pN/` in the tree.
    pub number: u32,
    pub start_lba: u64,
    pub lba_count: u64,
    pub sector_size: u32,
    pub scheme: PartitionScheme,
    pub kind: PartitionKind,
}

impl Partition {
    /// Byte offset of the first sector (FAT/EXT4 `open_*_with_offset`).
    pub fn start_byte(&self) -> u64 {
        self.start_lba.saturating_mul(u64::from(self.sector_size))
    }

    pub fn size_bytes(&self) -> u64 {
        self.lba_count.saturating_mul(u64::from(self.sector_size))
    }

    /// Mount directory name (`p1`, `p2`, …).
    pub fn dir_name(&self) -> String {
        format!("p{}", self.number)
    }
}

/// Parse a GPT (preferred) or MBR table from a raw disk image.
///
/// Leaves the reader at an unspecified position.
pub fn parse_partition_table<R: Read + Seek>(reader: &mut R) -> Result<Vec<Partition>> {
    for ss in [512u32, 4096] {
        if gpt_signature_at(reader, ss)? {
            return parse_gpt(reader, ss);
        }
    }
    parse_mbr(reader, DEFAULT_SECTOR_SIZE)
}

/// `EFI PART` at LBA 1 for `sector_size`.
pub fn gpt_signature_at<R: Read + Seek>(reader: &mut R, sector_size: u32) -> Result<bool> {
    let mut sig = [0u8; 8];
    let off = u64::from(sector_size);
    match reader.seek(SeekFrom::Start(off)) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    match reader.read_exact(&mut sig) {
        Ok(()) => Ok(&sig == GPT_SIG),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// True when sector 0 is an MBR with at least one usable (non-empty, non-EE) entry.
pub fn mbr_has_usable_partition<R: Read + Seek>(reader: &mut R) -> Result<bool> {
    let Some(boot) = read_mbr_sector(reader)? else {
        return Ok(false);
    };
    let has = mbr_usable_entries(&boot).next().is_some();
    Ok(has)
}

/// Protective GPT MBR (`0xEE` in slot 0) with the 0x55AA signature.
pub fn mbr_is_protective_gpt<R: Read + Seek>(reader: &mut R) -> Result<bool> {
    let Some(boot) = read_mbr_sector(reader)? else {
        return Ok(false);
    };
    Ok(boot[MBR_TABLE_OFF + 4] == MBR_TYPE_GPT_PROTECTIVE)
}

fn read_mbr_sector<R: Read + Seek>(reader: &mut R) -> Result<Option<[u8; 512]>> {
    let mut boot = [0u8; 512];
    reader.seek(SeekFrom::Start(0))?;
    match reader.read_exact(&mut boot) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if boot[MBR_SIG_OFF] != 0x55 || boot[MBR_SIG_OFF + 1] != 0xAA {
        return Ok(None);
    }
    Ok(Some(boot))
}

struct MbrEntry {
    ptype: u8,
    start_lba: u32,
    lba_count: u32,
}

fn parse_mbr_entry(raw: &[u8]) -> Option<MbrEntry> {
    if raw.len() < MBR_ENTRY_LEN {
        return None;
    }
    let ptype = raw[4];
    if ptype == 0 {
        return None;
    }
    let start_lba = u32::from_le_bytes(raw[8..12].try_into().ok()?);
    let lba_count = u32::from_le_bytes(raw[12..16].try_into().ok()?);
    if lba_count == 0 {
        return None;
    }
    Some(MbrEntry {
        ptype,
        start_lba,
        lba_count,
    })
}

fn mbr_usable_entries(boot: &[u8; 512]) -> impl Iterator<Item = MbrEntry> + '_ {
    (0..MBR_ENTRY_COUNT).filter_map(move |i| {
        let off = MBR_TABLE_OFF + i * MBR_ENTRY_LEN;
        let e = parse_mbr_entry(&boot[off..off + MBR_ENTRY_LEN])?;
        if e.ptype == MBR_TYPE_GPT_PROTECTIVE {
            return None;
        }
        // Superfloppy / overlapping MBR: require the payload to start after sector 0.
        if e.start_lba == 0 {
            return None;
        }
        Some(e)
    })
}

fn kind_from_mbr_type(t: u8) -> PartitionKind {
    match t {
        0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E => PartitionKind::Fat,
        0x07 => PartitionKind::NtfsExfat,
        0x05 | 0x0F => PartitionKind::Extended,
        0x82 => PartitionKind::Swap,
        0x83 => PartitionKind::LinuxFs,
        MBR_TYPE_LINUX_LVM => PartitionKind::LinuxLvm,
        0xFD => PartitionKind::LinuxRaid,
        0xEF => PartitionKind::Efi,
        MBR_TYPE_GPT_PROTECTIVE => PartitionKind::Reserved,
        _ => PartitionKind::Unknown,
    }
}

fn parse_mbr<R: Read + Seek>(reader: &mut R, sector_size: u32) -> Result<Vec<Partition>> {
    let boot = read_mbr_sector(reader)?.ok_or_else(|| {
        BlockError::Msg("no MBR signature (0x55AA) and no GPT header (EFI PART)".into())
    })?;

    let mut out = Vec::new();
    let mut number = 1u32;
    for i in 0..MBR_ENTRY_COUNT {
        let off = MBR_TABLE_OFF + i * MBR_ENTRY_LEN;
        let Some(e) = parse_mbr_entry(&boot[off..off + MBR_ENTRY_LEN]) else {
            continue;
        };
        if e.ptype == MBR_TYPE_GPT_PROTECTIVE {
            continue;
        }
        if e.start_lba == 0 {
            continue;
        }
        let kind = kind_from_mbr_type(e.ptype);
        if kind == PartitionKind::Extended {
            let logical = parse_ebr_chain(reader, u64::from(e.start_lba), sector_size)?;
            for p in logical {
                let mut p = p;
                p.number = number;
                number = number.saturating_add(1);
                out.push(p);
            }
            continue;
        }
        out.push(Partition {
            number,
            start_lba: u64::from(e.start_lba),
            lba_count: u64::from(e.lba_count),
            sector_size,
            scheme: PartitionScheme::Mbr,
            kind,
        });
        number = number.saturating_add(1);
    }
    if out.is_empty() {
        return Err(BlockError::Msg(
            "MBR has no usable partitions (empty, protective-GPT-only, or start LBA 0)".into(),
        ));
    }
    Ok(out)
}

fn parse_ebr_chain<R: Read + Seek>(
    reader: &mut R,
    extended_start: u64,
    sector_size: u32,
) -> Result<Vec<Partition>> {
    let mut out = Vec::new();
    let mut ebr_lba = extended_start;
    let mut seen = HashSet::new();
    for _ in 0..MAX_EBR_LOGICAL {
        if !seen.insert(ebr_lba) {
            break;
        }
        let off = ebr_lba.saturating_mul(u64::from(sector_size));
        let mut boot = [0u8; 512];
        reader.seek(SeekFrom::Start(off))?;
        match reader.read_exact(&mut boot) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        if boot[MBR_SIG_OFF] != 0x55 || boot[MBR_SIG_OFF + 1] != 0xAA {
            break;
        }
        // First entry: this logical partition (LBA relative to this EBR).
        if let Some(e) = parse_mbr_entry(&boot[MBR_TABLE_OFF..MBR_TABLE_OFF + MBR_ENTRY_LEN]) {
            if e.ptype != 0 && e.lba_count > 0 && !matches!(e.ptype, 0x05 | 0x0F) {
                let start = ebr_lba.saturating_add(u64::from(e.start_lba));
                out.push(Partition {
                    number: 0, // assigned by caller
                    start_lba: start,
                    lba_count: u64::from(e.lba_count),
                    sector_size,
                    scheme: PartitionScheme::Mbr,
                    kind: kind_from_mbr_type(e.ptype),
                });
            }
        }
        // Second entry: next EBR (LBA relative to the extended partition start).
        let next_raw = &boot[MBR_TABLE_OFF + MBR_ENTRY_LEN..MBR_TABLE_OFF + 2 * MBR_ENTRY_LEN];
        match parse_mbr_entry(next_raw) {
            Some(n) if n.ptype == 0x05 || n.ptype == 0x0F => {
                ebr_lba = extended_start.saturating_add(u64::from(n.start_lba));
            }
            _ => break,
        }
    }
    Ok(out)
}

/// Mixed-endian GPT type GUID as stored on disk.
pub fn gpt_guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&data1.to_le_bytes());
    g[4..6].copy_from_slice(&data2.to_le_bytes());
    g[6..8].copy_from_slice(&data3.to_le_bytes());
    g[8..16].copy_from_slice(&data4);
    g
}

/// EFI System (`C12A7328-F81F-11D2-BA4B-00A0C93EC93B`).
pub fn gpt_type_efi() -> [u8; 16] {
    gpt_guid(
        0xC12A_7328,
        0xF81F,
        0x11D2,
        [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    )
}

/// Microsoft basic data (`EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`).
pub fn gpt_type_microsoft_basic() -> [u8; 16] {
    gpt_guid(
        0xEBD0_A0A2,
        0xB9E5,
        0x4433,
        [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
    )
}

/// Linux filesystem (`0FC63DAF-8483-4772-8E79-3D69D8477DE4`).
pub fn gpt_type_linux_fs() -> [u8; 16] {
    gpt_guid(
        0x0FC6_3DAF,
        0x8483,
        0x4772,
        [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
    )
}

/// Linux LVM (`E6D6D379-373D-4F05-AE2C-FA5F46BDCBBE`).
pub fn gpt_type_linux_lvm() -> [u8; 16] {
    gpt_guid(
        0xE6D6_D379,
        0x373D,
        0x4F05,
        [0xAE, 0x2C, 0xFA, 0x5F, 0x46, 0xBD, 0xCB, 0xBE],
    )
}

fn gpt_type_linux_raid() -> [u8; 16] {
    gpt_guid(
        0xA19D_880F,
        0x05FC,
        0x4D3B,
        [0xA0, 0x06, 0x74, 0x3F, 0x0F, 0x84, 0x91, 0x1E],
    )
}

fn gpt_type_linux_swap() -> [u8; 16] {
    gpt_guid(
        0x0657_FD6D,
        0xA4AB,
        0x43C4,
        [0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F],
    )
}

/// Microsoft reserved (`E3C9E316-0B5C-4DB8-817D-F92DF00215AE`).
pub fn gpt_type_ms_reserved() -> [u8; 16] {
    gpt_guid(
        0xE3C9_E316,
        0x0B5C,
        0x4DB8,
        [0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE],
    )
}

fn gpt_type_bios_boot() -> [u8; 16] {
    gpt_guid(
        0x2168_6148,
        0x6449,
        0x6E6F,
        [0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49],
    )
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

fn kind_from_gpt_type(guid: &[u8; 16]) -> PartitionKind {
    if guid.iter().all(|&b| b == 0) {
        return PartitionKind::Reserved;
    }
    if guid == &gpt_type_efi() {
        return PartitionKind::Efi;
    }
    if guid == &gpt_type_microsoft_basic() {
        return PartitionKind::NtfsExfat;
    }
    if guid == &gpt_type_linux_fs() {
        return PartitionKind::LinuxFs;
    }
    if guid == &gpt_type_linux_lvm() {
        return PartitionKind::LinuxLvm;
    }
    if guid == &gpt_type_linux_raid() {
        return PartitionKind::LinuxRaid;
    }
    if guid == &gpt_type_linux_swap() {
        return PartitionKind::Swap;
    }
    if guid == &gpt_type_ms_reserved() || guid == &gpt_type_bios_boot() {
        return PartitionKind::Reserved;
    }
    PartitionKind::Unknown
}

fn parse_gpt<R: Read + Seek>(reader: &mut R, sector_size: u32) -> Result<Vec<Partition>> {
    let ss = u64::from(sector_size);
    let mut hdr = vec![0u8; sector_size as usize];
    reader.seek(SeekFrom::Start(ss))?;
    reader.read_exact(&mut hdr)?;
    if hdr.len() < GPT_HEADER_MIN as usize || &hdr[0..8] != GPT_SIG {
        return Err(BlockError::Msg(
            "GPT header signature missing at LBA 1".into(),
        ));
    }
    let header_size = le_u32(&hdr, 12);
    if header_size < GPT_HEADER_MIN || header_size as usize > hdr.len() {
        return Err(BlockError::Msg(format!(
            "GPT header size {header_size} is not in {GPT_HEADER_MIN}..={}",
            hdr.len()
        )));
    }
    let stored_crc = le_u32(&hdr, 16);
    let mut crc_buf = hdr[..header_size as usize].to_vec();
    crc_buf[16..20].fill(0);
    let calc = crc32fast::hash(&crc_buf);
    if calc != stored_crc {
        log::warn!(
            "GPT header CRC mismatch (stored {stored_crc:#08x}, calc {calc:#08x}); parsing anyway"
        );
    }

    let part_lba = le_u64(&hdr, 72);
    let part_count = le_u32(&hdr, 80);
    let part_entry_size = le_u32(&hdr, 84);
    // Cap before multiply: a crafted SizeOfPartitionEntry of ~4 GiB × 256 entries
    // would OOM (or panic on 32-bit saturating_mul + slice) the FUSE/NFS process.
    // `% 128` not `is_multiple_of` — that method is rustc 1.87+ (MSRV 1.74).
    #[allow(clippy::manual_is_multiple_of)]
    if !(128..=MAX_GPT_ENTRY_SIZE).contains(&part_entry_size) || part_entry_size % 128 != 0 {
        return Err(BlockError::Msg(format!(
            "GPT partition entry size {part_entry_size} is not 128..={MAX_GPT_ENTRY_SIZE} \
             and a multiple of 128"
        )));
    }
    let entry_size = part_entry_size as usize;
    let max_by_bytes = MAX_GPT_ARRAY_BYTES / entry_size;
    let count = (part_count as usize)
        .min(MAX_GPT_ENTRIES as usize)
        .min(max_by_bytes);
    let array_len = count
        .checked_mul(entry_size)
        .filter(|&n| n > 0 && n <= MAX_GPT_ARRAY_BYTES)
        .ok_or_else(|| {
            BlockError::Msg(format!(
                "GPT partition array too large (count={part_count} entry_size={part_entry_size})"
            ))
        })?;
    let mut array = vec![0u8; array_len];
    let array_off = part_lba.saturating_mul(ss);
    reader.seek(SeekFrom::Start(array_off))?;
    reader.read_exact(&mut array)?;

    let stored_array_crc = le_u32(&hdr, 88);
    let array_crc = crc32fast::hash(&array);
    if array_crc != stored_array_crc {
        log::warn!(
            "GPT partition-array CRC mismatch (stored {stored_array_crc:#08x}, calc {array_crc:#08x}); parsing anyway"
        );
    }

    let mut out = Vec::new();
    let mut number = 1u32;
    for i in 0..count as usize {
        let off = i * part_entry_size as usize;
        let entry = &array[off..off + part_entry_size as usize];
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&entry[0..16]);
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }
        let start_lba = le_u64(entry, 32);
        let end_lba = le_u64(entry, 40);
        if end_lba < start_lba {
            continue;
        }
        let lba_count = end_lba.saturating_sub(start_lba).saturating_add(1);
        if lba_count == 0 || start_lba == 0 {
            continue;
        }
        let kind = kind_from_gpt_type(&type_guid);
        out.push(Partition {
            number,
            start_lba,
            lba_count,
            sector_size,
            scheme: PartitionScheme::Gpt,
            kind,
        });
        number = number.saturating_add(1);
    }
    if out.is_empty() {
        return Err(BlockError::Msg(
            "GPT has no usable partitions (empty, reserved-only, or LBA 0)".into(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn mbr_bytes(entries: &[(u8, u32, u32)]) -> Vec<u8> {
        let mut boot = vec![0u8; 512];
        boot[510] = 0x55;
        boot[511] = 0xAA;
        for (i, &(ptype, start, count)) in entries.iter().enumerate() {
            let off = MBR_TABLE_OFF + i * MBR_ENTRY_LEN;
            boot[off + 4] = ptype;
            boot[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
            boot[off + 12..off + 16].copy_from_slice(&count.to_le_bytes());
        }
        boot
    }

    #[test]
    fn parse_mbr_fat_and_lvm() {
        let img = mbr_bytes(&[(0x0C, 2048, 1024), (MBR_TYPE_LINUX_LVM, 4096, 2048)]);
        let parts = parse_partition_table(&mut Cursor::new(&img)).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].number, 1);
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[0].start_byte(), 2048 * 512);
        assert_eq!(parts[0].kind, PartitionKind::Fat);
        assert_eq!(parts[0].dir_name(), "p1");
        assert_eq!(parts[1].kind, PartitionKind::LinuxLvm);
        assert!(parts[1].kind.is_mount_residual());
        assert_eq!(parts[1].dir_name(), "p2");
    }

    #[test]
    fn parse_mbr_rejects_empty() {
        let img = mbr_bytes(&[]);
        let err = parse_partition_table(&mut Cursor::new(&img)).unwrap_err();
        assert!(err.to_string().contains("no usable"));
    }

    #[test]
    fn parse_gpt_microsoft_basic() {
        let start_lba = 34u64;
        let last_lba = 100u64;
        let img = gpt_fixture(start_lba, last_lba, gpt_type_microsoft_basic());
        let parts = parse_partition_table(&mut Cursor::new(&img)).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].scheme, PartitionScheme::Gpt);
        assert_eq!(parts[0].start_lba, start_lba);
        assert_eq!(parts[0].lba_count, last_lba - start_lba + 1);
        assert_eq!(parts[0].kind, PartitionKind::NtfsExfat);
    }

    #[test]
    fn parse_gpt_lvm_is_residual() {
        let img = gpt_fixture(34, 80, gpt_type_linux_lvm());
        let parts = parse_partition_table(&mut Cursor::new(&img)).unwrap();
        assert_eq!(parts[0].kind, PartitionKind::LinuxLvm);
        assert!(parts[0].kind.is_mount_residual());
    }

    /// Regression: MSR is numbered like LVM (Windows GPT data is p3, not p2).
    #[test]
    fn parse_gpt_msr_then_data_numbers_p2() {
        let img = gpt_fixture_entries(&[
            (gpt_type_ms_reserved(), 34, 40),
            (gpt_type_microsoft_basic(), 41, 100),
        ]);
        let parts = parse_partition_table(&mut Cursor::new(&img)).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].kind, PartitionKind::Reserved);
        assert_eq!(parts[0].dir_name(), "p1");
        assert!(parts[0].kind.is_mount_residual());
        assert_eq!(parts[1].kind, PartitionKind::NtfsExfat);
        assert_eq!(parts[1].dir_name(), "p2");
    }

    /// Regression: crafted SizeOfPartitionEntry must Err, not OOM/panic.
    #[test]
    fn parse_gpt_rejects_huge_entry_size() {
        let mut img = vec![0u8; 1024];
        img[510] = 0x55;
        img[511] = 0xAA;
        img[446 + 4] = MBR_TYPE_GPT_PROTECTIVE;
        img[512..520].copy_from_slice(GPT_SIG);
        img[512 + 12..512 + 16].copy_from_slice(&92u32.to_le_bytes());
        img[512 + 80..512 + 84].copy_from_slice(&128u32.to_le_bytes());
        img[512 + 84..512 + 88].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        let err = parse_partition_table(&mut Cursor::new(&img))
            .expect_err("huge SizeOfPartitionEntry must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("entry size") || msg.contains("array"),
            "unexpected: {msg}"
        );
    }

    /// Regression: EBR logical partition LBA is EBR LBA + relative start.
    #[test]
    fn parse_ebr_logical_start_lba() {
        let mut img = vec![0u8; 20 * 512];
        img[510] = 0x55;
        img[511] = 0xAA;
        // Primary slot 0: extended LBA starting at 8.
        img[446 + 4] = MBR_TYPE_EXTENDED_LBA;
        img[446 + 8..446 + 12].copy_from_slice(&8u32.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&10u32.to_le_bytes());
        // EBR at LBA 8: logical FAT, start relative +1 → absolute LBA 9.
        let ebr = 8 * 512;
        img[ebr + 510] = 0x55;
        img[ebr + 511] = 0xAA;
        img[ebr + 446 + 4] = 0x0C;
        img[ebr + 446 + 8..ebr + 446 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[ebr + 446 + 12..ebr + 446 + 16].copy_from_slice(&4u32.to_le_bytes());
        let parts = parse_partition_table(&mut Cursor::new(&img)).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].start_lba, 9);
        assert_eq!(parts[0].lba_count, 4);
        assert_eq!(parts[0].kind, PartitionKind::Fat);
        assert_eq!(parts[0].dir_name(), "p1");
    }

    fn gpt_fixture(start_lba: u64, last_lba: u64, type_guid: [u8; 16]) -> Vec<u8> {
        gpt_fixture_entries(&[(type_guid, start_lba, last_lba)])
    }

    fn gpt_fixture_entries(entries: &[([u8; 16], u64, u64)]) -> Vec<u8> {
        const SS: usize = 512;
        let last_used = entries.iter().map(|e| e.2).max().unwrap_or(34);
        let backup_lba = last_used + 33;
        let mut img = vec![0u8; (backup_lba as usize + 1) * SS];
        img[510] = 0x55;
        img[511] = 0xAA;
        img[446 + 4] = MBR_TYPE_GPT_PROTECTIVE;
        img[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[446 + 12..446 + 16]
            .copy_from_slice(&(backup_lba as u32).saturating_sub(1).to_le_bytes());

        let entry_off = 2 * SS;
        for (i, &(type_guid, start_lba, last_lba)) in entries.iter().enumerate() {
            let off = entry_off + i * 128;
            img[off..off + 16].copy_from_slice(&type_guid);
            img[off + 16..off + 32].copy_from_slice(&[1u8; 16]);
            img[off + 32..off + 40].copy_from_slice(&start_lba.to_le_bytes());
            img[off + 40..off + 48].copy_from_slice(&last_lba.to_le_bytes());
        }
        let array_crc = crc32fast::hash(&img[entry_off..entry_off + 128 * 128]);

        let mut hdr = [0u8; 92];
        hdr[0..8].copy_from_slice(GPT_SIG);
        hdr[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        hdr[12..16].copy_from_slice(&92u32.to_le_bytes());
        hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
        hdr[32..40].copy_from_slice(&backup_lba.to_le_bytes());
        hdr[40..48].copy_from_slice(&34u64.to_le_bytes());
        hdr[48..56].copy_from_slice(&(backup_lba - 33).to_le_bytes());
        hdr[56..72].copy_from_slice(&[2u8; 16]);
        hdr[72..80].copy_from_slice(&2u64.to_le_bytes());
        hdr[80..84].copy_from_slice(&128u32.to_le_bytes());
        hdr[84..88].copy_from_slice(&128u32.to_le_bytes());
        hdr[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let hdr_crc = crc32fast::hash(&hdr);
        hdr[16..20].copy_from_slice(&hdr_crc.to_le_bytes());
        img[SS..SS + 92].copy_from_slice(&hdr);
        img
    }
}
