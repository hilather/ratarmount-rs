//! Read-only UDF (ECMA-167 / UDF 2.01) filesystem image mount source.
//!
//! In-process extent reads (no loop mount). Detection is a Volume Recognition
//! Sequence **NSR02** or **NSR03** identifier in the 32 KiB recognition space
//! — ISO 9660 `CD001`-only images do not match.
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested UDF members can be opened without `/tmp` when the outer archive
//! yields a seekable stream: [`UdfMountSource::open_from_reader`] validates
//! the VRS and retains a mutex-shared `Read + Seek` body. Each list/lookup/open
//! re-seeks that shared handle. No `NamedTempFile` spool.
//!
//! ## Partitioned images
//!
//! Use [`UdfMountSource::open_with_offset`] /
//! [`UdfMountSource::open_from_reader_with_offset`] with the byte offset of
//! the filesystem partition (GPT/MBR wrapper lands in the block crate).
//!
//! # Residual / factory
//!
//! This crate does not edit session `factory.rs` or `formats-all`. Mixed
//! ISO+UDF discs match UDF magic here; **UDF-primary probe order** (Udf
//! immediately before Iso) is factory-PR behavior. UDF 2.50 metadata
//! partitions and extended (20-byte) allocation descriptors are residual.
//! Type-3 AD continuations are followed.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratarmount_core::{CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData};
use thiserror::Error;

pub const BACKEND_NAME: &str = "UdfMountSource";

/// ECMA-167 volume recognition space starts at byte 32768 regardless of block size.
const VRS_OFFSET: u64 = 32_768;
const VSD_SIZE: u64 = 2048;
const MAX_VSD: u32 = 16;
const TAG_LEN: usize = 16;
const MAX_SLURP: u64 = 256 * 1024 * 1024;
const MAX_DIR: u64 = 16 * 1024 * 1024;
const MAX_INDIRECT: u32 = 8;
const MAX_AD_HOPS: u32 = 128;

const TAG_AVDP: u16 = 2;
const TAG_PD: u16 = 5;
const TAG_LVD: u16 = 6;
const TAG_TD: u16 = 8;
const TAG_FSD: u16 = 256;
const TAG_FID: u16 = 257;
const TAG_INDIRECT: u16 = 259;
const TAG_FE: u16 = 261;
const TAG_EFE: u16 = 266;

const AD_SHORT: u16 = 0;
const AD_LONG: u16 = 1;
const AD_EXT: u16 = 2;
const AD_IN_ICB: u16 = 3;

const FID_DELETED: u8 = 0x04;
const FID_PARENT: u8 = 0x08;

const FILE_TYPE_DIR: u8 = 4;

#[derive(Debug, Error)]
pub enum UdfError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, UdfError>;

trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

#[derive(Clone, Copy, Debug)]
struct LongAd {
    lba: u32,
    partition: u16,
}

#[derive(Clone, Copy, Debug)]
struct Extent {
    /// Partition-relative LBA; ignored when [`Self::zeros`].
    lba: u32,
    length: u32,
    zeros: bool,
}

#[derive(Clone, Debug)]
struct FileEntry {
    is_dir: bool,
    size: u64,
    mtime: f64,
    ad_type: u16,
    in_icb: Vec<u8>,
    extents: Vec<Extent>,
}

#[derive(Clone, Debug)]
struct Dirent {
    name: String,
    icb: LongAd,
}

#[derive(Clone, Copy, Debug)]
struct Geometry {
    partition_offset: u64,
    block_size: u32,
    partition_start: u32,
    partition_len: u32,
    root_icb: LongAd,
}

pub struct UdfMountSource {
    #[allow(dead_code)]
    archive_path: PathBuf,
    shared: Arc<Mutex<Box<dyn SeekRead>>>,
    geo: Geometry,
}

impl UdfMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_offset(path, 0)
    }

    /// Open a UDF image; `partition_offset` is the byte start of the FS.
    pub fn open_with_offset(path: impl AsRef<Path>, partition_offset: u64) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_udf_at(path, partition_offset) {
            return Err(UdfError::Msg(format!(
                "{} is not a UDF image",
                path.display()
            )));
        }
        let file = File::open(path)?;
        Self::from_reader(file, path.to_path_buf(), partition_offset)
            .map_err(|e| UdfError::Msg(format!("failed to open UDF image {}: {e}", path.display())))
    }

    /// Open a UDF image from any `Read + Seek` source without `/tmp`.
    ///
    /// For nested AutoMount / in-memory / remote images. The reader is retained
    /// under a mutex; each list/lookup/open re-seeks that shared body.
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::open_from_reader_with_offset(reader, archive_label, 0)
    }

    /// Like [`Self::open_from_reader`], with a filesystem partition byte offset.
    ///
    /// Success path never writes `/tmp`.
    pub fn open_from_reader_with_offset<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
        partition_offset: u64,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_udf_reader_at(&mut reader, partition_offset) {
            return Err(UdfError::Msg(format!(
                "{} is not a UDF image",
                archive_path.display()
            )));
        }
        reader.seek(SeekFrom::Start(0))?;
        Self::from_reader(reader, archive_path, partition_offset)
    }

    fn from_reader<R>(mut reader: R, archive_path: PathBuf, partition_offset: u64) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let geo = probe_geometry(&mut reader, partition_offset)?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> =
            Arc::new(Mutex::new(Box::new(reader) as Box<dyn SeekRead>));
        Ok(Self {
            archive_path,
            shared,
            geo,
        })
    }

    fn with_reader<T>(&self, f: impl FnOnce(&mut dyn SeekRead) -> Result<T>) -> Result<T> {
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| UdfError::Msg("shared UDF reader poisoned".into()))?;
        f(&mut **guard)
    }

    fn read_exact_abs(&self, abs: u64, buf: &mut [u8]) -> Result<()> {
        self.with_reader(|r| {
            r.seek(SeekFrom::Start(abs))?;
            r.read_exact(buf)?;
            Ok(())
        })
    }

    fn read_part_block(&self, lba: u32) -> Result<Vec<u8>> {
        let abs = part_lba_abs(&self.geo, lba)?;
        let mut buf = vec![0u8; self.geo.block_size as usize];
        self.read_exact_abs(abs, &mut buf)?;
        Ok(buf)
    }

    fn load_icb(&self, icb: LongAd) -> Result<FileEntry> {
        load_icb_with(icb, |lba| self.read_part_block(lba))
    }

    fn read_entry_bytes(&self, fe: &FileEntry, cap: u64) -> Result<Vec<u8>> {
        let want = fe.size.min(cap);
        if fe.ad_type == AD_IN_ICB {
            let n = (want as usize).min(fe.in_icb.len());
            return Ok(fe.in_icb[..n].to_vec());
        }
        let mut out = Vec::new();
        let mut remaining = want;
        for ext in &fe.extents {
            if remaining == 0 {
                break;
            }
            let n = u64::from(ext.length).min(remaining);
            if ext.zeros {
                out.resize(out.len() + n as usize, 0);
                remaining -= n;
                continue;
            }
            let abs = part_lba_abs(&self.geo, ext.lba)?;
            let start = out.len();
            out.resize(start + n as usize, 0);
            self.read_exact_abs(abs, &mut out[start..])?;
            remaining -= n;
        }
        Ok(out)
    }

    fn list_entries(&self, fe: &FileEntry) -> Result<Vec<Dirent>> {
        if !fe.is_dir {
            return Err(UdfError::Msg("not a directory".into()));
        }
        let bytes = self.read_entry_bytes(fe, MAX_DIR)?;
        // In-ICB directories are a packed FID stream (no per-block padding).
        let block_size = if fe.ad_type == AD_IN_ICB {
            bytes.len().max(1)
        } else {
            self.geo.block_size.max(1) as usize
        };
        parse_directory(&bytes, block_size)
    }

    fn resolve(&self, path: &str) -> Result<Resolved> {
        let rel = trim_rel(path);
        let root = self.load_icb(self.geo.root_icb)?;
        if rel.is_empty() {
            return Ok(Resolved::Root(root));
        }
        let mut cur = root;
        let parts: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        for (i, part) in parts.iter().enumerate() {
            if !cur.is_dir {
                return Err(UdfError::Msg("not found".into()));
            }
            let ents = self.list_entries(&cur)?;
            let ent = ents
                .iter()
                .find(|e| e.name == *part)
                .cloned()
                .ok_or_else(|| UdfError::Msg("not found".into()))?;
            let fe = self.load_icb(ent.icb)?;
            if i + 1 == parts.len() {
                return Ok(Resolved::Entry(fe));
            }
            if !fe.is_dir {
                return Err(UdfError::Msg("not found".into()));
            }
            cur = fe;
        }
        Err(UdfError::Msg("not found".into()))
    }

    fn find_entry_info(&self, path: &str) -> Option<FileInfo> {
        match self.resolve(path) {
            Ok(Resolved::Root(fe)) => Some(entry_to_file_info(path, true, 0, fe.mtime)),
            Ok(Resolved::Entry(fe)) => Some(entry_to_file_info(path, fe.is_dir, fe.size, fe.mtime)),
            Err(_) => None,
        }
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        let fe = match self.resolve(path) {
            Ok(Resolved::Root(fe)) => fe,
            Ok(Resolved::Entry(fe)) if fe.is_dir => fe,
            _ => return None,
        };
        let ents = self.list_entries(&fe).ok()?;
        let mut map = BTreeMap::new();
        for e in ents {
            let child_fe = match self.load_icb(e.icb) {
                Ok(fe) => fe,
                Err(_) => continue,
            };
            let child = child_path(path, &e.name);
            map.insert(
                e.name.clone(),
                entry_to_file_info(&child, child_fe.is_dir, child_fe.size, child_fe.mtime),
            );
        }
        Some(map)
    }

    fn list_dirents_dir(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let fe = match self.resolve(path) {
            Ok(Resolved::Root(fe)) => fe,
            Ok(Resolved::Entry(fe)) if fe.is_dir => fe,
            _ => return None,
        };
        let ents = self.list_entries(&fe).ok()?;
        let mut out = Vec::with_capacity(ents.len());
        for e in ents {
            let child_fe = match self.load_icb(e.icb) {
                Ok(fe) => fe,
                Err(_) => continue,
            };
            let (mode, size) = entry_mode_size(child_fe.is_dir, child_fe.size);
            out.push(CheapDirent {
                name: e.name,
                mode,
                size,
            });
        }
        Some(out)
    }

    fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        match self.resolve(path) {
            Ok(Resolved::Root(_)) => Err(io::Error::new(io::ErrorKind::IsADirectory, "root")),
            Ok(Resolved::Entry(fe)) if fe.is_dir => Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            )),
            Ok(Resolved::Entry(fe)) => {
                if fe.size > MAX_SLURP {
                    return Err(io::Error::other("UDF file too large to buffer"));
                }
                self.read_entry_bytes(&fe, fe.size)
                    .map_err(|e| io::Error::other(e.to_string()))
            }
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}

enum Resolved {
    Root(FileEntry),
    Entry(FileEntry),
}

impl MountSource for UdfMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let map = self.list_dir(path)?;
        Some(ListResult::Infos(map))
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let map = self.list_dir(path)?;
        Some(ListModeResult::Modes(
            map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
        ))
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.list_dirents_dir(path)
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        self.find_entry_info(path)
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
        let path = path_from_userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing UDF path userdata")
        })?;
        let data = self.read_file(&path)?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn udf_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("udf:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("udf:") => Some(s[4..].to_string()),
        _ => None,
    })
}

fn trim_rel(path: &str) -> String {
    path.trim_matches('/').to_string()
}

fn child_path(parent: &str, name: &str) -> String {
    if parent == "/" || parent.is_empty() {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

fn entry_mode_size(is_dir: bool, size: u64) -> (u32, u64) {
    if is_dir {
        (ratarmount_core::S_IFDIR | 0o777, 0)
    } else {
        (ratarmount_core::S_IFREG | 0o777, size)
    }
}

fn entry_to_file_info(name_path: &str, is_dir: bool, size: u64, mtime: f64) -> FileInfo {
    let (mode, size) = entry_mode_size(is_dir, size);
    FileInfo {
        size,
        mtime,
        mode,
        linkname: String::new(),
        uid: ratarmount_core::effective_uid(),
        gid: ratarmount_core::effective_gid(),
        userdata: vec![udf_path_userdata(name_path)],
    }
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]))
}

/// ITU-T CRC-16 (poly 0x1021, init 0) used by UDF descriptor tags.
fn udf_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn tag_checksum(tag: &[u8]) -> u8 {
    tag.iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .fold(0u8, |a, (_, b)| a.wrapping_add(*b))
}

struct Tag {
    ident: u16,
    location: u32,
}

fn parse_tag(buf: &[u8]) -> Result<Tag> {
    if buf.len() < TAG_LEN {
        return Err(UdfError::Msg("truncated UDF tag".into()));
    }
    if tag_checksum(&buf[..TAG_LEN]) != buf[4] {
        return Err(UdfError::Msg("UDF tag checksum mismatch".into()));
    }
    let ident = read_u16(buf, 0);
    let crc = read_u16(buf, 8);
    let crc_len = read_u16(buf, 10) as usize;
    let location = read_u32(buf, 12);
    if crc_len > buf.len().saturating_sub(TAG_LEN) {
        return Err(UdfError::Msg("UDF tag CRC length past buffer".into()));
    }
    if crc_len > 0 && udf_crc(&buf[TAG_LEN..TAG_LEN + crc_len]) != crc {
        return Err(UdfError::Msg("UDF tag CRC mismatch".into()));
    }
    Ok(Tag { ident, location })
}

fn parse_long_ad(buf: &[u8]) -> Result<LongAd> {
    if buf.len() < 16 {
        return Err(UdfError::Msg("truncated long_ad".into()));
    }
    Ok(LongAd {
        lba: read_u32(buf, 4),
        partition: read_u16(buf, 8),
    })
}

fn parse_extent_len(raw: u32) -> (u32, u8) {
    (raw & 0x3FFF_FFFF, (raw >> 30) as u8)
}

fn vol_lba_abs(geo: &Geometry, vol_lba: u32) -> Result<u64> {
    geo.partition_offset
        .checked_add(u64::from(vol_lba).saturating_mul(u64::from(geo.block_size)))
        .ok_or_else(|| UdfError::Msg("volume LBA overflow".into()))
}

fn part_lba_abs(geo: &Geometry, lba: u32) -> Result<u64> {
    if lba >= geo.partition_len {
        return Err(UdfError::Msg(format!(
            "partition LBA {lba} past length {}",
            geo.partition_len
        )));
    }
    let vol = geo
        .partition_start
        .checked_add(lba)
        .ok_or_else(|| UdfError::Msg("partition LBA overflow".into()))?;
    vol_lba_abs(geo, vol)
}

/// Scan the ECMA-167 recognition space for NSR02/NSR03.
fn vrs_has_nsr<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> bool {
    for i in 0..MAX_VSD {
        let off = match partition_offset
            .checked_add(VRS_OFFSET)
            .and_then(|b| b.checked_add(u64::from(i).checked_mul(VSD_SIZE)?))
        {
            Some(o) => o,
            None => return false,
        };
        if reader.seek(SeekFrom::Start(off)).is_err() {
            return false;
        }
        let mut vsd = [0u8; 7];
        if reader.read_exact(&mut vsd).is_err() {
            return false;
        }
        let ident = &vsd[1..6];
        if ident == b"NSR02" || ident == b"NSR03" {
            return true;
        }
        if ident == b"TEA01" || ident == b"\0\0\0\0\0" {
            return false;
        }
    }
    false
}

fn udf_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("udf"))
}

/// Detect UDF via NSR02/NSR03 in the 32 KiB VRS, or `*.udf` extension.
pub fn looks_like_udf(path: &Path) -> bool {
    looks_like_udf_at(path, 0)
}

/// Detect UDF VRS at `partition_offset`.
///
/// Extension fallback (`*.udf`) applies only at offset 0 so a partitioned
/// disk named `*.udf` is not reported as a superfloppy.
pub fn looks_like_udf_at(path: &Path, partition_offset: u64) -> bool {
    if let Ok(mut f) = File::open(path) {
        if looks_like_udf_reader_at(&mut f, partition_offset) {
            return true;
        }
    }
    partition_offset == 0 && udf_extension(path)
}

/// VRS probe for nested streams (does not use filename).
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_udf_reader<R: Read + Seek>(reader: &mut R) -> bool {
    looks_like_udf_reader_at(reader, 0)
}

/// VRS probe at `partition_offset` on a seekable stream.
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_udf_reader_at<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> bool {
    vrs_has_nsr(reader, partition_offset)
}

fn read_at<R: Read + Seek>(reader: &mut R, abs: u64, buf: &mut [u8]) -> Result<()> {
    reader.seek(SeekFrom::Start(abs))?;
    reader.read_exact(buf)?;
    Ok(())
}

fn image_len<R: Read + Seek>(reader: &mut R) -> Result<u64> {
    let len = reader.seek(SeekFrom::End(0))?;
    Ok(len)
}

fn try_avdp_at<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    block_size: u32,
    vol_lba: u32,
) -> Result<Option<(u32, u32)>> {
    let abs = partition_offset
        .checked_add(u64::from(vol_lba).saturating_mul(u64::from(block_size)))
        .ok_or_else(|| UdfError::Msg("AVDP offset overflow".into()))?;
    let mut buf = vec![0u8; block_size as usize];
    if read_at(reader, abs, &mut buf).is_err() {
        return Ok(None);
    }
    let tag = match parse_tag(&buf) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    if tag.ident != TAG_AVDP || tag.location != vol_lba {
        return Ok(None);
    }
    let main_len = read_u32(&buf, 16);
    let main_loc = read_u32(&buf, 20);
    if main_len < block_size || main_loc == 0 {
        return Ok(None);
    }
    Ok(Some((main_loc, main_len)))
}

fn find_avdp<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    block_size: u32,
    image_size: u64,
) -> Result<(u32, u32)> {
    let mut candidates = vec![256u32];
    let n = image_size.saturating_sub(partition_offset) / u64::from(block_size);
    if n > 256 {
        let last = (n - 1) as u32;
        candidates.push(last.saturating_sub(256));
        candidates.push(last);
    }
    candidates.push(512);
    let mut seen = Vec::new();
    for loc in candidates {
        if seen.contains(&loc) {
            continue;
        }
        seen.push(loc);
        if let Some(vds) = try_avdp_at(reader, partition_offset, block_size, loc)? {
            return Ok(vds);
        }
    }
    Err(UdfError::Msg(format!(
        "no UDF AVDP for block size {block_size}"
    )))
}

struct VolumeDesc {
    partitions: BTreeMap<u16, (u32, u32)>,
    lvd: Option<Lvd>,
}

struct Lvd {
    block_size: u32,
    fileset: LongAd,
    type1_parts: Vec<u16>,
    saw_metadata_map: bool,
}

fn parse_lvd(buf: &[u8]) -> Result<Lvd> {
    if buf.len() < 440 {
        return Err(UdfError::Msg("truncated Logical Volume Descriptor".into()));
    }
    let block_size = read_u32(buf, 212);
    if ![512, 1024, 2048, 4096, 8192].contains(&block_size) {
        return Err(UdfError::Msg(format!(
            "unsupported UDF logical block size {block_size}"
        )));
    }
    let fileset = parse_long_ad(&buf[248..264])?;
    let map_len = read_u32(buf, 264) as usize;
    let nmaps = read_u32(buf, 268);
    if 440 + map_len > buf.len() {
        return Err(UdfError::Msg("UDF partition maps past descriptor".into()));
    }
    let maps = &buf[440..440 + map_len];
    let mut type1_parts = Vec::new();
    let mut saw_metadata_map = false;
    let mut off = 0usize;
    for _ in 0..nmaps {
        if off + 2 > maps.len() {
            break;
        }
        let ptype = maps[off];
        let plen = maps[off + 1] as usize;
        if plen < 2 || off + plen > maps.len() {
            return Err(UdfError::Msg("corrupt UDF partition map".into()));
        }
        let body = &maps[off..off + plen];
        match ptype {
            1 if plen >= 6 => {
                type1_parts.push(read_u16(body, 4));
            }
            2 => {
                let ident = body.get(4..27).unwrap_or(&[]);
                if ident.windows(8).any(|w| w == b"Metadata") {
                    saw_metadata_map = true;
                }
            }
            _ => {}
        }
        off += plen;
    }
    Ok(Lvd {
        block_size,
        fileset,
        type1_parts,
        saw_metadata_map,
    })
}

fn parse_vds<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    block_size: u32,
    vds_loc: u32,
    vds_len: u32,
) -> Result<VolumeDesc> {
    let nblocks = vds_len.div_ceil(block_size).min(64);
    let mut partitions = BTreeMap::new();
    let mut lvd = None;
    for i in 0..nblocks {
        let vol = vds_loc.saturating_add(i);
        let abs = partition_offset
            .checked_add(u64::from(vol).saturating_mul(u64::from(block_size)))
            .ok_or_else(|| UdfError::Msg("VDS offset overflow".into()))?;
        let mut buf = vec![0u8; block_size as usize];
        read_at(reader, abs, &mut buf)?;
        let tag = match parse_tag(&buf) {
            Ok(t) => t,
            Err(_) => continue,
        };
        match tag.ident {
            TAG_TD => break,
            TAG_PD if buf.len() >= 196 => {
                let pnum = read_u16(&buf, 22);
                let start = read_u32(&buf, 188);
                let len = read_u32(&buf, 192);
                partitions.insert(pnum, (start, len));
            }
            TAG_LVD => {
                lvd = Some(parse_lvd(&buf)?);
            }
            _ => {}
        }
    }
    Ok(VolumeDesc { partitions, lvd })
}

fn probe_geometry<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> Result<Geometry> {
    if !vrs_has_nsr(reader, partition_offset) {
        return Err(UdfError::Msg(
            "no NSR02/NSR03 Volume Recognition Sequence".into(),
        ));
    }
    let size = image_len(reader)?;
    let mut last_err = UdfError::Msg("no UDF AVDP".into());
    for &bs in &[2048u32, 512, 4096, 1024] {
        let (vds_loc, vds_len) = match find_avdp(reader, partition_offset, bs, size) {
            Ok(v) => v,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        let vds = parse_vds(reader, partition_offset, bs, vds_loc, vds_len)?;
        let lvd = vds
            .lvd
            .ok_or_else(|| UdfError::Msg("UDF Logical Volume Descriptor missing".into()))?;
        let block_size = if [512, 1024, 2048, 4096, 8192].contains(&lvd.block_size) {
            lvd.block_size
        } else {
            bs
        };
        let part_ref = lvd.fileset.partition;
        if !lvd.type1_parts.is_empty() && !lvd.type1_parts.contains(&part_ref) {
            if lvd.saw_metadata_map {
                return Err(UdfError::Msg(
                    "UDF 2.50 metadata partition is residual".into(),
                ));
            }
            return Err(UdfError::Msg(
                "UDF fileset partition is not a type-1 map".into(),
            ));
        }
        if lvd.type1_parts.is_empty() && lvd.saw_metadata_map {
            return Err(UdfError::Msg(
                "UDF 2.50 metadata partition is residual".into(),
            ));
        }
        let (pstart, plen) = vds.partitions.get(&part_ref).copied().ok_or_else(|| {
            if lvd.saw_metadata_map {
                UdfError::Msg("UDF 2.50 metadata partition is residual".into())
            } else {
                UdfError::Msg(format!("UDF partition {part_ref} not found"))
            }
        })?;
        let root_icb = read_root_icb(
            reader,
            partition_offset,
            block_size,
            pstart,
            plen,
            lvd.fileset,
        )?;
        return Ok(Geometry {
            partition_offset,
            block_size,
            partition_start: pstart,
            partition_len: plen,
            root_icb,
        });
    }
    Err(last_err)
}

fn read_root_icb<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    block_size: u32,
    pstart: u32,
    plen: u32,
    fileset: LongAd,
) -> Result<LongAd> {
    let geo = Geometry {
        partition_offset,
        block_size,
        partition_start: pstart,
        partition_len: plen,
        root_icb: fileset,
    };
    let abs = part_lba_abs(&geo, fileset.lba)?;
    let mut buf = vec![0u8; block_size as usize];
    read_at(reader, abs, &mut buf)?;
    let tag = parse_tag(&buf)?;
    if tag.ident != TAG_FSD {
        return Err(UdfError::Msg("UDF File Set Descriptor missing".into()));
    }
    if buf.len() < 416 {
        return Err(UdfError::Msg("truncated File Set Descriptor".into()));
    }
    parse_long_ad(&buf[400..416])
}

fn load_icb_with(
    icb: LongAd,
    mut read_part: impl FnMut(u32) -> Result<Vec<u8>>,
) -> Result<FileEntry> {
    let mut loc = icb.lba;
    for _ in 0..MAX_INDIRECT {
        let buf = read_part(loc)?;
        let tag = parse_tag(&buf)?;
        match tag.ident {
            TAG_INDIRECT => {
                if buf.len() < 52 {
                    return Err(UdfError::Msg("truncated indirect ICB".into()));
                }
                let next = parse_long_ad(&buf[36..52])?;
                loc = next.lba;
            }
            TAG_FE | TAG_EFE => return parse_file_entry(&buf, tag.ident, &mut read_part),
            other => {
                return Err(UdfError::Msg(format!(
                    "unexpected UDF ICB tag {other} at LBA {loc}"
                )));
            }
        }
    }
    Err(UdfError::Msg("UDF ICB indirection too deep".into()))
}

fn parse_file_entry(
    buf: &[u8],
    ident: u16,
    read_part: &mut impl FnMut(u32) -> Result<Vec<u8>>,
) -> Result<FileEntry> {
    let (info_off, ea_off, ad_off) = if ident == TAG_EFE {
        (56, 208, 212)
    } else {
        (56, 168, 172)
    };
    let need = ad_off + 4;
    if buf.len() < need {
        return Err(UdfError::Msg("truncated File Entry".into()));
    }
    let file_type = buf[27];
    let flags = read_u16(buf, 34);
    let ad_type = flags & 0x7;
    let size = read_u64(buf, info_off);
    let mtime_off = if ident == TAG_EFE { 92 } else { 84 };
    let mtime = udf_timestamp_to_unix(buf.get(mtime_off..mtime_off + 12).unwrap_or(&[]));
    let l_ea = read_u32(buf, ea_off) as usize;
    let l_ad = read_u32(buf, ad_off) as usize;
    let data_off: usize = if ident == TAG_EFE { 216 } else { 176 };
    let start = data_off
        .checked_add(l_ea)
        .ok_or_else(|| UdfError::Msg("UDF EA length overflow".into()))?;
    if start + l_ad > buf.len() {
        return Err(UdfError::Msg(
            "UDF allocation descriptors past File Entry".into(),
        ));
    }
    let is_dir = file_type == FILE_TYPE_DIR;
    if ad_type == AD_IN_ICB {
        let n = (size as usize).min(l_ad);
        return Ok(FileEntry {
            is_dir,
            size,
            mtime,
            ad_type,
            in_icb: buf[start..start + n].to_vec(),
            extents: Vec::new(),
        });
    }
    if ad_type == AD_EXT {
        return Err(UdfError::Msg(
            "UDF extended allocation descriptors residual".into(),
        ));
    }
    let extents = collect_alloc_descs(&buf[start..start + l_ad], ad_type, read_part)?;
    Ok(FileEntry {
        is_dir,
        size,
        mtime,
        ad_type,
        in_icb: Vec::new(),
        extents,
    })
}

/// Type-3 continuation: partition LBA and byte length of the next AD list.
type AdContinuation = (u32, u32);

fn parse_alloc_descs(bytes: &[u8], ad_type: u16) -> Result<(Vec<Extent>, Option<AdContinuation>)> {
    let step = match ad_type {
        AD_SHORT => 8,
        AD_LONG => 16,
        _ => {
            return Err(UdfError::Msg(
                "unsupported UDF allocation descriptor type".into(),
            ))
        }
    };
    let mut extents = Vec::new();
    let mut off = 0;
    while off + step <= bytes.len() {
        let (len, ty) = parse_extent_len(read_u32(bytes, off));
        if len == 0 && ty == 0 {
            break;
        }
        let lba = read_u32(bytes, off + 4);
        if ty == 3 {
            return Ok((extents, Some((lba, len))));
        }
        extents.push(Extent {
            lba,
            length: len,
            zeros: ty != 0,
        });
        off += step;
        if extents.len() > 4096 {
            return Err(UdfError::Msg("too many UDF extents".into()));
        }
    }
    Ok((extents, None))
}

fn read_ad_bytes(
    read_part: &mut impl FnMut(u32) -> Result<Vec<u8>>,
    start_lba: u32,
    len: u32,
) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut got = 0u32;
    let mut lba = start_lba;
    while got < len {
        let block = read_part(lba)?;
        if block.is_empty() {
            return Err(UdfError::Msg("empty UDF AD continuation block".into()));
        }
        let take = ((len - got) as usize).min(block.len());
        out.extend_from_slice(&block[..take]);
        got += take as u32;
        lba = lba
            .checked_add(1)
            .ok_or_else(|| UdfError::Msg("UDF AD continuation LBA overflow".into()))?;
    }
    Ok(out)
}

fn collect_alloc_descs(
    initial: &[u8],
    ad_type: u16,
    read_part: &mut impl FnMut(u32) -> Result<Vec<u8>>,
) -> Result<Vec<Extent>> {
    let mut extents = Vec::new();
    let mut cur = initial.to_vec();
    for _ in 0..MAX_AD_HOPS {
        let (more, cont) = parse_alloc_descs(&cur, ad_type)?;
        extents.extend(more);
        if extents.len() > 4096 {
            return Err(UdfError::Msg("too many UDF extents".into()));
        }
        match cont {
            None => return Ok(extents),
            Some((lba, len)) => {
                cur = read_ad_bytes(read_part, lba, len)?;
            }
        }
    }
    Err(UdfError::Msg(
        "UDF allocation descriptor continuation too deep".into(),
    ))
}

fn decode_cs0(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    match bytes[0] {
        8 => String::from_utf8_lossy(&bytes[1..]).into_owned(),
        16 => {
            let mut rest = &bytes[1..];
            if rest.len() % 2 == 1 {
                rest = &rest[..rest.len() - 1];
            }
            let units: Vec<u16> = rest
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .filter(|&u| u != 0)
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn parse_directory(bytes: &[u8], block_size: usize) -> Result<Vec<Dirent>> {
    let block_size = block_size.max(1);
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 38 <= bytes.len() {
        let block_end = ((off / block_size) + 1)
            .saturating_mul(block_size)
            .min(bytes.len());
        if off >= block_end {
            break;
        }
        if bytes[off..block_end].iter().all(|&b| b == 0) {
            off = block_end;
            continue;
        }
        let tag = match parse_tag(&bytes[off..]) {
            Ok(t) if t.ident == TAG_FID => t,
            _ => {
                off = block_end;
                continue;
            }
        };
        let _ = tag;
        let l_fi = bytes[off + 19] as usize;
        let l_iu = read_u16(bytes, off + 36) as usize;
        let mut total = 38 + l_iu + l_fi;
        total = (total + 3) & !3;
        if off + total > block_end {
            off = block_end;
            continue;
        }
        let ch = bytes[off + 18];
        if ch & FID_DELETED == 0 && ch & FID_PARENT == 0 && l_fi > 0 {
            let name_off = off + 38 + l_iu;
            let name = decode_cs0(&bytes[name_off..name_off + l_fi]);
            if !name.is_empty() {
                let icb = parse_long_ad(&bytes[off + 20..off + 36])?;
                out.push(Dirent { name, icb });
            }
        }
        off += total;
        if out.len() > 65_536 {
            return Err(UdfError::Msg("UDF directory too large".into()));
        }
    }
    Ok(out)
}

fn udf_timezone_minutes(type_and_tz: u16) -> i32 {
    let tz = type_and_tz & 0x0FFF;
    if tz == 0x800 {
        0
    } else {
        let n = i32::from(tz);
        if n & 0x800 != 0 {
            n | !0x0FFF
        } else {
            n
        }
    }
}

fn udf_timestamp_to_unix(buf: &[u8]) -> f64 {
    if buf.len() < 12 {
        return 0.0;
    }
    let year = read_u16(buf, 2) as i32;
    let month = buf[4];
    let day = buf[5];
    let hour = buf[6];
    let min = buf[7];
    let sec = buf[8];
    let centi = buf[9];
    if year < 1970 || !(1..=12).contains(&month) || day == 0 {
        return 0.0;
    }
    let offset_min = udf_timezone_minutes(read_u16(buf, 0));
    civil_to_unix(year, month, day, hour, min, sec, centi) - f64::from(offset_min) * 60.0
}

fn civil_to_unix(year: i32, month: u8, day: u8, hour: u8, min: u8, sec: u8, centi: u8) -> f64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 {
        i32::from(month) + 9
    } else {
        i32::from(month) - 3
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * m + 2) / 5 + i32::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    let days = (i64::from(era) * 146097 + doe as i64 - 719468) as f64;
    days * 86400.0
        + f64::from(hour) * 3600.0
        + f64::from(min) * 60.0
        + f64::from(sec)
        + f64::from(centi) * 0.01
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;

    fn write_u16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn write_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn write_u64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn finish_tag(buf: &mut [u8], ident: u16, location: u32) {
        write_u16(buf, 0, ident);
        write_u16(buf, 2, 2);
        buf[4] = 0;
        buf[5] = 0;
        write_u16(buf, 6, 0);
        let crc_len = u16::try_from(buf.len().saturating_sub(TAG_LEN)).unwrap_or(0);
        write_u16(buf, 10, crc_len);
        let crc = udf_crc(&buf[TAG_LEN..]);
        write_u16(buf, 8, crc);
        write_u32(buf, 12, location);
        buf[4] = tag_checksum(&buf[..TAG_LEN]);
    }

    fn put_vsd(img: &mut [u8], sector: u32, ident: &[u8; 5]) {
        let off = sector as usize * 2048;
        img[off] = 0;
        img[off + 1..off + 6].copy_from_slice(ident);
        img[off + 6] = 1;
    }

    fn encode_fid(
        name: &str,
        icb_lba: u32,
        part: u16,
        is_dir: bool,
        is_parent: bool,
        tag_loc: u32,
        block_size: u32,
    ) -> Vec<u8> {
        let mut ident = Vec::new();
        if !is_parent {
            ident.push(8u8);
            ident.extend(name.as_bytes());
        }
        let l_fi = ident.len();
        let mut total = 38 + l_fi;
        total = (total + 3) & !3;
        let mut buf = vec![0u8; total];
        write_u16(&mut buf, 16, 1);
        let mut ch = 0u8;
        if is_dir {
            ch |= 0x02;
        }
        if is_parent {
            ch |= FID_PARENT;
        }
        buf[18] = ch;
        buf[19] = l_fi as u8;
        write_u32(&mut buf, 20, block_size);
        write_u32(&mut buf, 24, icb_lba);
        write_u16(&mut buf, 28, part);
        buf[38..38 + ident.len()].copy_from_slice(&ident);
        finish_tag(&mut buf, TAG_FID, tag_loc);
        buf
    }

    fn encode_fid_cs2(
        name: &str,
        icb_lba: u32,
        part: u16,
        tag_loc: u32,
        block_size: u32,
        trailing_pad: bool,
    ) -> Vec<u8> {
        let mut ident = vec![16u8];
        for u in name.encode_utf16() {
            ident.extend_from_slice(&u.to_be_bytes());
        }
        if trailing_pad {
            ident.push(0);
        }
        let l_fi = ident.len();
        let mut total = 38 + l_fi;
        total = (total + 3) & !3;
        let mut buf = vec![0u8; total];
        write_u16(&mut buf, 16, 1);
        buf[19] = l_fi as u8;
        write_u32(&mut buf, 20, block_size);
        write_u32(&mut buf, 24, icb_lba);
        write_u16(&mut buf, 28, part);
        buf[38..38 + ident.len()].copy_from_slice(&ident);
        finish_tag(&mut buf, TAG_FID, tag_loc);
        buf
    }

    fn encode_fe_in_icb(
        is_dir: bool,
        data: &[u8],
        tag_loc: u32,
        parent_lba: u32,
        block_size: usize,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; block_size];
        write_u16(&mut buf, 20, 4);
        write_u16(&mut buf, 24, 1);
        buf[27] = if is_dir { FILE_TYPE_DIR } else { 5 };
        write_u32(&mut buf, 28, parent_lba);
        write_u16(&mut buf, 34, AD_IN_ICB);
        write_u32(&mut buf, 44, 0x7FFF);
        write_u16(&mut buf, 48, 1);
        write_u64(&mut buf, 56, data.len() as u64);
        write_u32(&mut buf, 172, data.len() as u32);
        buf[176..176 + data.len()].copy_from_slice(data);
        finish_tag(&mut buf, TAG_FE, tag_loc);
        buf
    }

    fn encode_fe_short_ad(
        size: u64,
        data_lba: u32,
        tag_loc: u32,
        parent_lba: u32,
        block_size: usize,
    ) -> Vec<u8> {
        encode_fe_short_ads(
            false,
            size,
            &[(size as u32, 0, data_lba)],
            tag_loc,
            parent_lba,
            block_size,
        )
    }

    fn encode_fe_short_ads(
        is_dir: bool,
        info_len: u64,
        ads: &[(u32, u8, u32)],
        tag_loc: u32,
        parent_lba: u32,
        block_size: usize,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; block_size];
        write_u16(&mut buf, 20, 4);
        write_u16(&mut buf, 24, 1);
        buf[27] = if is_dir { FILE_TYPE_DIR } else { 5 };
        write_u32(&mut buf, 28, parent_lba);
        write_u16(&mut buf, 34, AD_SHORT);
        write_u32(&mut buf, 44, 0x7FFF);
        write_u16(&mut buf, 48, 1);
        write_u64(&mut buf, 56, info_len);
        let l_ad = ads.len() * 8;
        write_u32(&mut buf, 172, l_ad as u32);
        for (i, &(len, ty, lba)) in ads.iter().enumerate() {
            let raw = (len & 0x3FFF_FFFF) | (u32::from(ty) << 30);
            let off = 176 + i * 8;
            write_u32(&mut buf, off, raw);
            write_u32(&mut buf, off + 4, lba);
        }
        finish_tag(&mut buf, TAG_FE, tag_loc);
        buf
    }

    /// Minimal UDF 2.01 volume: hello.txt, foo/ufo, short_ad big.bin,
    /// two-block `wide/` directory, CS2 names, type-3 AD continuation.
    fn synthetic_udf_image() -> Vec<u8> {
        const BS: usize = 2048;
        const BS_U: u32 = 2048;
        let nsectors = 280u32;
        let mut img = vec![0u8; nsectors as usize * BS];

        put_vsd(&mut img, 16, b"BEA01");
        put_vsd(&mut img, 17, b"NSR02");
        put_vsd(&mut img, 18, b"TEA01");

        let put_desc = |img: &mut [u8], sector: u32, ident: u16, fill: &dyn Fn(&mut [u8])| {
            let off = sector as usize * BS;
            let mut desc = vec![0u8; 512];
            fill(&mut desc);
            finish_tag(&mut desc, ident, sector);
            img[off..off + 512].copy_from_slice(&desc);
        };

        put_desc(&mut img, 32, 1, &|d| {
            d[16..].fill(0);
            write_u32(d, 16, 1);
        });
        put_desc(&mut img, 33, TAG_PD, &|d| {
            write_u16(d, 22, 0);
            d[24..30].copy_from_slice(b"+NSR02");
            write_u32(d, 184, 1);
            write_u32(d, 188, 64);
            write_u32(d, 192, 180);
        });
        put_desc(&mut img, 34, TAG_LVD, &|d| {
            write_u32(d, 212, BS_U);
            write_u32(d, 248, BS_U);
            write_u32(d, 252, 0);
            write_u16(d, 256, 0);
            write_u32(d, 264, 6);
            write_u32(d, 268, 1);
            d[440] = 1;
            d[441] = 6;
            write_u16(d, 442, 1);
            write_u16(d, 444, 0);
        });
        put_desc(&mut img, 35, TAG_TD, &|_| {});

        let put_block = |img: &mut [u8], part_lba: u32, data: &[u8]| {
            let vol = 64 + part_lba;
            let off = vol as usize * BS;
            img[off..off + data.len()].copy_from_slice(data);
        };

        let mut fsd = vec![0u8; BS];
        write_u32(&mut fsd, 248, BS_U);
        write_u32(&mut fsd, 400, BS_U);
        write_u32(&mut fsd, 404, 1);
        write_u16(&mut fsd, 408, 0);
        finish_tag(&mut fsd, TAG_FSD, 0);
        put_block(&mut img, 0, &fsd);

        let hello = b"hello-udf\n";
        let ufo = b"iriya\n";
        let big: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let first = b"first-block\n";
        let second = b"second-block\n";
        let cs2 = b"cs2-utf16\n";
        let pad = b"pad-cs2\n";
        let cont = b"type3-continued\n";

        let hello_fe = encode_fe_in_icb(false, hello, 2, 1, BS);
        let ufo_fe = encode_fe_in_icb(false, ufo, 4, 3, BS);
        // Data at LBA 5..6; File Entry at LBA 7 so the payload cannot clobber the FE.
        let big_fe = encode_fe_short_ad(big.len() as u64, 5, 7, 1, BS);
        let first_fe = encode_fe_in_icb(false, first, 10, 12, BS);
        let second_fe = encode_fe_in_icb(false, second, 11, 12, BS);
        let wide_fe = encode_fe_short_ads(true, (2 * BS) as u64, &[(2 * BS_U, 0, 8)], 12, 1, BS);
        let cs2_fe = encode_fe_in_icb(false, cs2, 13, 1, BS);
        let pad_fe = encode_fe_in_icb(false, pad, 14, 1, BS);
        let cont_fe = encode_fe_short_ads(false, cont.len() as u64, &[(8, 3, 15)], 17, 1, BS);

        let mut foo_dir = Vec::new();
        foo_dir.extend(encode_fid("", 1, 0, true, true, 3, BS_U));
        foo_dir.extend(encode_fid("ufo", 4, 0, false, false, 3, BS_U));
        let foo_fe = encode_fe_in_icb(true, &foo_dir, 3, 1, BS);

        let mut wide0 = vec![0u8; BS];
        let parent = encode_fid("", 1, 0, true, true, 8, BS_U);
        let first_fid = encode_fid("first.txt", 10, 0, false, false, 8, BS_U);
        wide0[..parent.len()].copy_from_slice(&parent);
        wide0[parent.len()..parent.len() + first_fid.len()].copy_from_slice(&first_fid);
        let mut wide1 = vec![0u8; BS];
        let second_fid = encode_fid("second.txt", 11, 0, false, false, 9, BS_U);
        wide1[..second_fid.len()].copy_from_slice(&second_fid);

        let mut root_dir = Vec::new();
        root_dir.extend(encode_fid("", 1, 0, true, true, 1, BS_U));
        root_dir.extend(encode_fid("hello.txt", 2, 0, false, false, 1, BS_U));
        root_dir.extend(encode_fid("foo", 3, 0, true, false, 1, BS_U));
        root_dir.extend(encode_fid("big.bin", 7, 0, false, false, 1, BS_U));
        root_dir.extend(encode_fid("wide", 12, 0, true, false, 1, BS_U));
        root_dir.extend(encode_fid_cs2("cs2.txt", 13, 0, 1, BS_U, false));
        root_dir.extend(encode_fid_cs2("P", 14, 0, 1, BS_U, true));
        root_dir.extend(encode_fid("cont.bin", 17, 0, false, false, 1, BS_U));
        // Unreadable child: ICB at empty LBA 99. list/list_dirents must skip it.
        root_dir.extend(encode_fid("bad", 99, 0, false, false, 1, BS_U));
        let root_fe = encode_fe_in_icb(true, &root_dir, 1, 1, BS);

        put_block(&mut img, 1, &root_fe);
        put_block(&mut img, 2, &hello_fe);
        put_block(&mut img, 3, &foo_fe);
        put_block(&mut img, 4, &ufo_fe);
        put_block(&mut img, 7, &big_fe);
        put_block(&mut img, 5, &big[..BS]);
        let data_off = (64 + 5) as usize * BS + BS;
        img[data_off..data_off + (big.len() - BS)].copy_from_slice(&big[BS..]);
        put_block(&mut img, 8, &wide0);
        put_block(&mut img, 9, &wide1);
        put_block(&mut img, 10, &first_fe);
        put_block(&mut img, 11, &second_fe);
        put_block(&mut img, 12, &wide_fe);
        put_block(&mut img, 13, &cs2_fe);
        put_block(&mut img, 14, &pad_fe);
        let mut ad_cont = [0u8; 8];
        write_u32(&mut ad_cont, 0, cont.len() as u32);
        write_u32(&mut ad_cont, 4, 16);
        put_block(&mut img, 15, &ad_cont);
        put_block(&mut img, 16, cont);
        put_block(&mut img, 17, &cont_fe);

        let mut avdp = vec![0u8; 512];
        write_u32(&mut avdp, 16, 16 * BS_U);
        write_u32(&mut avdp, 20, 32);
        finish_tag(&mut avdp, TAG_AVDP, 256);
        let aoff = 256 * BS;
        img[aoff..aoff + 512].copy_from_slice(&avdp);

        img
    }

    fn iso9660_cd001_only() -> Vec<u8> {
        let mut img = vec![0u8; 18 * 2048];
        let pvd = 16 * 2048;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1;
        let td = 17 * 2048;
        img[td] = 255;
        img[td + 1..td + 6].copy_from_slice(b"CD001");
        img[td + 6] = 1;
        img
    }

    fn mixed_iso_udf_vrs() -> Vec<u8> {
        let mut img = vec![0u8; 22 * 2048];
        let pvd = 16 * 2048;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1;
        let iso_td = 17 * 2048;
        img[iso_td] = 255;
        img[iso_td + 1..iso_td + 6].copy_from_slice(b"CD001");
        put_vsd(&mut img, 18, b"BEA01");
        put_vsd(&mut img, 19, b"NSR02");
        put_vsd(&mut img, 20, b"TEA01");
        img
    }

    fn nsr03_vrs() -> Vec<u8> {
        let mut img = vec![0u8; 20 * 2048];
        put_vsd(&mut img, 16, b"BEA01");
        put_vsd(&mut img, 17, b"NSR03");
        put_vsd(&mut img, 18, b"TEA01");
        img
    }

    fn which_cmd(name: &str) -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                let p = dir.join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        for prefix in ["/usr/sbin", "/sbin", "/usr/bin"] {
            let p = PathBuf::from(prefix).join(name);
            if p.is_file() {
                return Some(p);
            }
        }
        None
    }

    struct ToolImage {
        _dir: tempfile::TempDir,
        path: PathBuf,
        has_hello: bool,
    }

    fn mkudffs_or_mkisofs_image() -> Option<ToolImage> {
        let dir = tempfile::tempdir().ok()?;
        if let Some(mkudffs) = which_cmd("mkudffs") {
            let img = dir.path().join("vol.udf");
            {
                let f = File::create(&img).ok()?;
                f.set_len(8 * 1024 * 1024).ok()?;
            }
            let status = Command::new(&mkudffs)
                .args(["--media-type=hd", "--udfrev=0x0201"])
                .arg(&img)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok()?;
            if status.success() {
                return Some(ToolImage {
                    _dir: dir,
                    path: img,
                    has_hello: false,
                });
            }
            eprintln!("skip: mkudffs failed ({})", mkudffs.display());
        }
        let src = dir.path().join("src");
        std::fs::create_dir(&src).ok()?;
        std::fs::write(src.join("hello.txt"), b"hello-udf\n").ok()?;
        let img = dir.path().join("vol.iso");
        for (bin, extra) in [
            ("mkisofs", vec!["-udf", "-o"]),
            ("genisoimage", vec!["-udf", "-o"]),
        ] {
            let Some(cmd) = which_cmd(bin) else {
                continue;
            };
            let status = Command::new(&cmd)
                .args(&extra)
                .arg(&img)
                .arg(&src)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok()?;
            if status.success() {
                return Some(ToolImage {
                    _dir: dir,
                    path: img,
                    has_hello: true,
                });
            }
            eprintln!("skip: {bin} failed ({})", cmd.display());
        }
        if let Some(xorriso) = which_cmd("xorriso") {
            let status = Command::new(&xorriso)
                .args(["-as", "mkisofs", "-udf", "-o"])
                .arg(&img)
                .arg(&src)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok()?;
            if status.success() {
                return Some(ToolImage {
                    _dir: dir,
                    path: img,
                    has_hello: true,
                });
            }
            eprintln!("skip: xorriso failed ({})", xorriso.display());
        }
        None
    }

    /// Always-on: ITU-T CRC-16 vector used by UDF tags.
    #[test]
    fn udf_crc_matches_itu_t_vector() {
        assert_eq!(udf_crc(b"123456789"), 0x31C3);
        assert_eq!(udf_crc(b""), 0);
    }

    /// Always-on: NSR02 / NSR03 at 32 KiB is enough for the probe.
    #[test]
    fn looks_like_udf_nsr_magic() {
        let nsr02 = {
            let mut img = vec![0u8; 20 * 2048];
            put_vsd(&mut img, 16, b"BEA01");
            put_vsd(&mut img, 17, b"NSR02");
            put_vsd(&mut img, 18, b"TEA01");
            img
        };
        assert!(looks_like_udf_reader(&mut Cursor::new(&nsr02)));
        assert!(looks_like_udf_reader(&mut Cursor::new(nsr03_vrs())));
        let mut short = vec![0u8; 100];
        short.extend_from_slice(b"NSR02");
        assert!(!looks_like_udf_reader(&mut Cursor::new(short)));
    }

    /// Regression: ISO 9660 `CD001` at sector 16 without NSR is not UDF.
    #[test]
    fn looks_like_udf_false_on_iso9660_cd001_only() {
        let iso = iso9660_cd001_only();
        assert!(!looks_like_udf_reader(&mut Cursor::new(&iso)));
        let err = UdfMountSource::open_from_reader(Cursor::new(iso), "disk.iso")
            .err()
            .expect("ISO-only is not UDF");
        assert!(
            err.to_string().contains("not a UDF"),
            "unexpected error: {err}"
        );
    }

    /// Mixed ISO+UDF VRS matches UDF magic; factory-PR inserts Udf before Iso.
    #[test]
    fn looks_like_udf_true_on_mixed_iso_udf_vrs() {
        let mixed = mixed_iso_udf_vrs();
        assert!(looks_like_udf_reader(&mut Cursor::new(&mixed)));
        let pvd = 16 * 2048 + 1;
        assert_eq!(&mixed[pvd..pvd + 5], b"CD001");
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = UdfMountSource::open_from_reader(Cursor::new(b"not-a-udf-image!!!!"), "bad")
            .err()
            .expect("expected open_from_reader failure");
        assert!(
            err.to_string().contains("not a UDF"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn open_from_reader_nsr_without_avdp_fails() {
        let vrs = nsr03_vrs();
        assert!(looks_like_udf_reader(&mut Cursor::new(&vrs)));
        let err = UdfMountSource::open_from_reader(Cursor::new(vrs), "nsr-only.udf")
            .err()
            .expect("NSR without AVDP must fail open");
        let msg = err.to_string();
        assert!(
            msg.contains("AVDP") || msg.contains("failed to open"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn open_from_reader_list_and_read() {
        let bytes = synthetic_udf_image();
        assert!(looks_like_udf_reader(&mut Cursor::new(&bytes)));
        let m = UdfMountSource::open_from_reader(Cursor::new(bytes), "nested.udf")
            .expect("open_from_reader");

        let fi = m.lookup("/hello.txt", 0).expect("hello.txt");
        assert_eq!(fi.size, 10);
        let mut s = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello-udf\n");

        let ufo = m.lookup("/foo/ufo", 0).expect("ufo");
        assert_eq!(ufo.size, 6);
        let mut s = String::new();
        m.open(&ufo, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");

        match m.list("/").expect("list /") {
            ListResult::Infos(map) => {
                assert!(map.contains_key("hello.txt"));
                assert!(map.contains_key("foo"));
                assert!(map.contains_key("big.bin"));
            }
            other => panic!("expected infos, got {other:?}"),
        }
        match m.list("/foo").expect("list /foo") {
            ListResult::Infos(map) => assert!(map.contains_key("ufo")),
            other => panic!("expected infos, got {other:?}"),
        }
    }

    #[test]
    fn open_from_reader_short_ad_spans_blocks() {
        let bytes = synthetic_udf_image();
        let m = UdfMountSource::open_from_reader(Cursor::new(bytes), "chain.udf")
            .expect("open_from_reader");
        let fi = m.lookup("/big.bin", 0).expect("big.bin");
        assert_eq!(fi.size, 3000);
        let mut data = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut data).unwrap();
        let expect: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        assert_eq!(data, expect);
    }

    #[test]
    fn open_from_reader_matches_path_open() {
        let bytes = synthetic_udf_image();
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("match.udf");
        std::fs::write(&img, &bytes).unwrap();

        let path_src = UdfMountSource::open(&img).expect("path open");
        let reader_src = UdfMountSource::open_from_reader(Cursor::new(bytes), "match.udf")
            .expect("open_from_reader");

        let path_fi = path_src.lookup("/foo/ufo", 0).expect("path ufo");
        let reader_fi = reader_src.lookup("/foo/ufo", 0).expect("reader ufo");
        assert_eq!(path_fi.size, reader_fi.size);
        assert_eq!(path_fi.mode, reader_fi.mode);

        let mut path_data = Vec::new();
        path_src
            .open(&path_fi, 0)
            .unwrap()
            .read_to_end(&mut path_data)
            .unwrap();
        let mut reader_data = Vec::new();
        reader_src
            .open(&reader_fi, 0)
            .unwrap()
            .read_to_end(&mut reader_data)
            .unwrap();
        assert_eq!(path_data, reader_data);
        assert_eq!(path_data, b"iriya\n");
    }

    /// Regression: cheap readdirplus sizes.
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let bytes = synthetic_udf_image();
        let src = UdfMountSource::open_from_reader(Cursor::new(bytes), "dirents.udf")
            .expect("open_from_reader");
        let dents = src.list_dirents("/").expect("dirents");
        let d = dents
            .iter()
            .find(|e| e.name == "hello.txt")
            .expect("hello.txt dirent");
        let fi = src.lookup("/hello.txt", 0).expect("lookup hello.txt");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, 10);
        assert_ne!(d.size, 0);
        let foo = dents.iter().find(|e| e.name == "foo").expect("foo dirent");
        assert_eq!(foo.size, 0);
        assert_eq!(foo.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);
    }

    #[test]
    fn open_from_reader_with_offset_padded() {
        let bytes = synthetic_udf_image();
        let offset = 1024 * 1024;
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(&bytes);

        assert!(!looks_like_udf_reader_at(&mut Cursor::new(&padded), 0));
        assert!(looks_like_udf_reader_at(
            &mut Cursor::new(&padded),
            offset as u64
        ));

        let m = UdfMountSource::open_from_reader_with_offset(
            Cursor::new(padded),
            "padded-nested.img",
            offset as u64,
        )
        .expect("open_from_reader_with_offset");
        let fi = m.lookup("/hello.txt", 0).expect("hello via offset");
        assert_eq!(fi.size, 10);
        let mut s = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello-udf\n");
    }

    #[test]
    fn open_with_offset_path_padded() {
        let bytes = synthetic_udf_image();
        let offset = 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let padded = dir.path().join("disk.img");
        {
            let mut out = File::create(&padded).unwrap();
            out.write_all(&vec![0u8; offset]).unwrap();
            out.write_all(&bytes).unwrap();
        }
        assert!(!looks_like_udf_at(&padded, 0));
        assert!(looks_like_udf_at(&padded, offset as u64));
        let m = UdfMountSource::open_with_offset(&padded, offset as u64).expect("open at 1 MiB");
        assert!(m.lookup("/foo/ufo", 0).is_some());
    }

    #[test]
    fn looks_like_udf_extension_fallback_offset_zero_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("disk.udf");
        File::create(&p).unwrap().write_all(&[0u8; 64]).unwrap();
        assert!(looks_like_udf(&p), "extension fallback");
        assert!(
            !looks_like_udf_at(&p, 4096),
            "extension must not mask a bad partition offset"
        );
    }

    /// Always-on: CS0 compression 16 pad is the last byte, not the first unit.
    #[test]
    fn decode_cs0_utf16_trims_trailing_pad() {
        // Odd rest after compression ID: trailing pad. First unit is 'A' (U+0041).
        assert_eq!(decode_cs0(&[16, 0x00, 0x41, 0x00]), "A");
        // Even rest, no pad: "cs2".
        assert_eq!(decode_cs0(&[16, 0x00, b'c', 0x00, b's', 0x00, b'2']), "cs2");
    }

    /// Regression: 12-bit timezone offset is minutes from UTC (0x800 = unspecified).
    #[test]
    fn udf_timestamp_applies_timezone_offset() {
        let mut ts = [0u8; 12];
        write_u16(&mut ts, 0, 60);
        write_u16(&mut ts, 2, 2020);
        ts[4] = 1;
        ts[5] = 15;
        ts[6] = 12;
        let with_tz = udf_timestamp_to_unix(&ts);
        write_u16(&mut ts, 0, 0x0800);
        ts[6] = 11;
        let unspecified_utc = udf_timestamp_to_unix(&ts);
        assert_eq!(with_tz, unspecified_utc);
        write_u16(&mut ts, 0, 0x0800);
        ts[6] = 12;
        let unspecified_noon = udf_timestamp_to_unix(&ts);
        assert_eq!(unspecified_noon, with_tz + 3600.0);
    }

    /// Regression: directory FIDs after block-0 zero padding must still be listed.
    #[test]
    fn list_dirents_reads_second_directory_block() {
        let bytes = synthetic_udf_image();
        let m = UdfMountSource::open_from_reader(Cursor::new(bytes), "wide.udf")
            .expect("open_from_reader");
        let dents = m.list_dirents("/wide").expect("wide dirents");
        assert!(
            dents.iter().any(|e| e.name == "first.txt"),
            "first-block FID missing: {dents:?}"
        );
        let second = dents
            .iter()
            .find(|e| e.name == "second.txt")
            .expect("second-block FID dropped");
        let fi = m.lookup("/wide/second.txt", 0).expect("lookup second.txt");
        assert_eq!(second.size, fi.size);
        let mut s = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "second-block\n");
    }

    #[test]
    fn open_from_reader_cs2_names_and_type3_continuation() {
        let bytes = synthetic_udf_image();
        let m = UdfMountSource::open_from_reader(Cursor::new(bytes), "cs2.udf")
            .expect("open_from_reader");

        let cs2 = m.lookup("/cs2.txt", 0).expect("cs2.txt UTF-16 name");
        let mut s = String::new();
        m.open(&cs2, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "cs2-utf16\n");

        let pad = m.lookup("/P", 0).expect("padded UTF-16 name P");
        let mut s = String::new();
        m.open(&pad, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "pad-cs2\n");

        let cont = m.lookup("/cont.bin", 0).expect("cont.bin");
        let mut data = Vec::new();
        m.open(&cont, 0).unwrap().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"type3-continued\n");
    }

    /// Regression: one bad child ICB must not turn list() into None.
    #[test]
    fn list_skips_unreadable_child_icb() {
        let bytes = synthetic_udf_image();
        let m = UdfMountSource::open_from_reader(Cursor::new(bytes), "skip-bad.udf")
            .expect("open_from_reader");
        match m.list("/").expect("list / with bad child") {
            ListResult::Infos(map) => {
                assert!(map.contains_key("hello.txt"));
                assert!(!map.contains_key("bad"));
            }
            other => panic!("expected infos, got {other:?}"),
        }
        let dents = m.list_dirents("/").expect("dirents with bad child");
        assert!(dents.iter().any(|e| e.name == "hello.txt"));
        assert!(dents.iter().all(|e| e.name != "bad"));
    }

    #[test]
    fn mkudffs_or_mkisofs_open_and_list_root() {
        let Some(img) = mkudffs_or_mkisofs_image() else {
            eprintln!("skip: mkudffs/mkisofs not available");
            return;
        };
        assert!(
            looks_like_udf(&img.path),
            "tool-built image should have NSR02/NSR03"
        );
        let m = UdfMountSource::open(&img.path).expect("open tool-built UDF image");
        let _root = m.list("/").expect("list root of mkudffs/mkisofs image");
        assert!(m.lookup("/", 0).is_some());
        if img.has_hello {
            let fi = m
                .lookup("/hello.txt", 0)
                .or_else(|| m.lookup("/HELLO.TXT", 0))
                .expect("hello.txt from mkisofs src tree");
            let mut body = Vec::new();
            m.open(&fi, 0).unwrap().read_to_end(&mut body).unwrap();
            assert!(
                body == b"hello-udf\n" || body.starts_with(b"hello"),
                "unexpected hello.txt bytes: {body:?}"
            );
        }
    }
}
