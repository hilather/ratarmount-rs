//! Read-only exFAT filesystem image mount source.
//!
//! In-process cluster reads (no loop mount / `exfat-fuse`). Detection is OEM
//! `"EXFAT   "` at byte 3 plus boot signature `0x55AA` — FAT12/16/32 boot
//! sectors do not match.
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested exFAT members can be opened without `/tmp` when the outer archive
//! yields a seekable stream: [`ExfatMountSource::open_from_reader`] validates
//! the boot sector and retains a mutex-shared `Read + Seek` body. Each
//! list/lookup/open re-seeks that shared handle. No `NamedTempFile` spool.
//!
//! The image is **not** fully loaded into RAM — only the outer member body
//! (if any) remains whatever the parent archive already produced (Cursor /
//! stencil / etc.).
//!
//! ## Partitioned images
//!
//! Use [`ExfatMountSource::open_with_offset`] /
//! [`ExfatMountSource::open_from_reader_with_offset`] with the byte offset of
//! the filesystem partition (GPT/MBR wrapper lands in the block crate).
//!
//! # Residual / factory
//!
//! This crate does not edit session `factory.rs` or `formats-all`. Wire nested
//! detection via [`looks_like_exfat_reader`] or name (`*.exfat`). Bitmap /
//! up-case-table Unicode casefold is residual (v1 is ASCII case-insensitive).

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratarmount_core::{CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData};
use thiserror::Error;

pub const BACKEND_NAME: &str = "ExfatMountSource";

const OEM_NAME: &[u8; 8] = b"EXFAT   ";
const ENTRY_SIZE: usize = 32;
const ENTRY_END: u8 = 0x00;
const ENTRY_FILE: u8 = 0x85;
const ENTRY_STREAM: u8 = 0xC0;
const ENTRY_NAME: u8 = 0xC1;
const IN_USE: u8 = 0x80;
const ATTR_DIRECTORY: u16 = 0x10;
const FLAG_NO_FAT_CHAIN: u8 = 0x02;
const FAT_EOC: u32 = 0xFFFF_FFF8;
const FAT_BAD: u32 = 0xFFFF_FFF7;

#[derive(Debug, Error)]
pub enum ExfatError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, ExfatError>;

/// Object-safe `Read + Seek + Send` for the shared nested backend.
trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

#[derive(Clone, Copy, Debug)]
struct Boot {
    cluster_size: u64,
    fat_offset_bytes: u64,
    cluster_heap_offset_bytes: u64,
    cluster_count: u32,
    root_cluster: u32,
}

#[derive(Clone, Debug)]
struct DirEntry {
    name: String,
    is_dir: bool,
    size: u64,
    data_length: u64,
    first_cluster: u32,
    no_fat_chain: bool,
    mtime: f64,
}

pub struct ExfatMountSource {
    /// Host path or virtual label (nested member name / URL).
    #[allow(dead_code)]
    archive_path: PathBuf,
    shared: Arc<Mutex<Box<dyn SeekRead>>>,
    partition_offset: u64,
    boot: Boot,
}

impl ExfatMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_offset(path, 0)
    }

    /// Open an exFAT image; `partition_offset` is the byte start of the FS
    /// (useful for whole-disk images with a partition table).
    pub fn open_with_offset(path: impl AsRef<Path>, partition_offset: u64) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_exfat_at(path, partition_offset) {
            return Err(ExfatError::Msg(format!(
                "{} is not an exFAT image",
                path.display()
            )));
        }
        // One fd for the mount lifetime (list/open must not reopen per cluster).
        let file = File::open(path)?;
        Self::from_reader(file, path.to_path_buf(), partition_offset).map_err(|e| {
            ExfatError::Msg(format!(
                "failed to open exFAT image {}: {e}",
                path.display()
            ))
        })
    }

    /// Open an exFAT image from any `Read + Seek` source without `/tmp`.
    ///
    /// For nested AutoMount / in-memory / remote images. The reader is retained
    /// under a mutex; each list/lookup/open re-seeks that shared body. The full
    /// image is **not** copied into a second buffer by this method (the parent
    /// may already hold a `Cursor` or stencil).
    ///
    /// `archive_label` is used for diagnostics only (may be a nested member name).
    ///
    /// # Residual / factory
    ///
    /// Wire this from `open_nested_reader_fn` via boot-sector probe
    /// ([`looks_like_exfat_reader`]) or name (`*.exfat`). Path-based compressed
    /// exFAT still materializes via existing factory keep-temp paths until that
    /// glue lands.
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
        if !looks_like_exfat_reader_at(&mut reader, partition_offset) {
            return Err(ExfatError::Msg(format!(
                "{} is not an exFAT image",
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
        let boot = read_boot(&mut reader, partition_offset)?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> =
            Arc::new(Mutex::new(Box::new(reader) as Box<dyn SeekRead>));
        Ok(Self {
            archive_path,
            shared,
            partition_offset,
            boot,
        })
    }

    fn with_reader<T>(&self, f: impl FnOnce(&mut dyn SeekRead) -> Result<T>) -> Result<T> {
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| ExfatError::Msg("shared exFAT reader poisoned".into()))?;
        f(&mut **guard)
    }

    fn read_exact_at(&self, rel: u64, buf: &mut [u8]) -> Result<()> {
        let abs = self
            .partition_offset
            .checked_add(rel)
            .ok_or_else(|| ExfatError::Msg("offset overflow".into()))?;
        self.with_reader(|r| {
            r.seek(SeekFrom::Start(abs))?;
            r.read_exact(buf)?;
            Ok(())
        })
    }

    fn fat_entry(&self, cluster: u32) -> Result<u32> {
        let off = self
            .boot
            .fat_offset_bytes
            .checked_add(u64::from(cluster).saturating_mul(4))
            .ok_or_else(|| ExfatError::Msg("FAT offset overflow".into()))?;
        let mut buf = [0u8; 4];
        self.read_exact_at(off, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Last valid cluster number (`cluster_count + 1`; heap is clusters 2..=last).
    fn last_cluster(&self) -> u32 {
        self.boot.cluster_count.saturating_add(1)
    }

    fn cluster_in_heap(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster <= self.last_cluster()
    }

    fn cluster_rel_offset(&self, cluster: u32) -> Result<u64> {
        if !self.cluster_in_heap(cluster) {
            return Err(ExfatError::Msg(format!("cluster {cluster} past heap")));
        }
        let idx = u64::from(cluster - 2);
        let rel = idx
            .checked_mul(self.boot.cluster_size)
            .and_then(|b| self.boot.cluster_heap_offset_bytes.checked_add(b))
            .ok_or_else(|| ExfatError::Msg("cluster offset overflow".into()))?;
        Ok(rel)
    }

    fn follow_fat(&self, first: u32) -> Result<Vec<u32>> {
        let mut clusters = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = first;
        while (2..FAT_EOC).contains(&cur) {
            if cur == FAT_BAD {
                return Err(ExfatError::Msg("bad cluster in FAT chain".into()));
            }
            if !self.cluster_in_heap(cur) {
                return Err(ExfatError::Msg(format!("cluster {cur} past heap")));
            }
            if !seen.insert(cur) {
                return Err(ExfatError::Msg("FAT chain loop".into()));
            }
            if clusters.len() > self.boot.cluster_count as usize {
                return Err(ExfatError::Msg("FAT chain too long".into()));
            }
            clusters.push(cur);
            cur = self.fat_entry(cur)?;
            if cur == 0 || cur == 1 {
                break;
            }
        }
        Ok(clusters)
    }

    /// Contiguous (`NoFatChain`) or FAT-chained cluster list.
    ///
    /// `data_length` is the on-disk Stream Extension length (must fit in the
    /// heap). `bytes_to_read` sizes the returned vec (`min` with `data_length`)
    /// so a 12-byte `open` cannot allocate a terabyte-scale cluster list.
    fn cluster_list(
        &self,
        first: u32,
        no_fat_chain: bool,
        data_length: Option<u64>,
        bytes_to_read: Option<u64>,
    ) -> Result<Vec<u32>> {
        if first < 2 {
            return Ok(Vec::new());
        }
        if !no_fat_chain {
            return self.follow_fat(first);
        }
        if !self.cluster_in_heap(first) {
            return Err(ExfatError::Msg(format!("cluster {first} past heap")));
        }
        let declared = data_length.unwrap_or(self.boot.cluster_size);
        let remaining = u64::from(self.last_cluster().saturating_sub(first).saturating_add(1));
        let n_declared = declared.div_ceil(self.boot.cluster_size).max(1);
        if n_declared > remaining {
            return Err(ExfatError::Msg(format!(
                "NoFatChain cluster walk past heap (first={first}, data_length={declared})"
            )));
        }
        let to_read = bytes_to_read.unwrap_or(declared).min(declared);
        let n_read = to_read
            .div_ceil(self.boot.cluster_size)
            .max(1)
            .min(n_declared);
        let n = usize::try_from(n_read)
            .map_err(|_| ExfatError::Msg("cluster count overflow".into()))?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let i = u32::try_from(i).map_err(|_| ExfatError::Msg("cluster overflow".into()))?;
            let c = first
                .checked_add(i)
                .ok_or_else(|| ExfatError::Msg("cluster overflow".into()))?;
            if !self.cluster_in_heap(c) {
                return Err(ExfatError::Msg(format!("cluster {c} past heap")));
            }
            out.push(c);
        }
        Ok(out)
    }

    fn read_clusters(&self, clusters: &[u32], max_bytes: u64) -> Result<Vec<u8>> {
        let want = usize::try_from(max_bytes)
            .map_err(|_| ExfatError::Msg("file too large to buffer".into()))?;
        let mut out = Vec::new();
        let mut remaining = want;
        let cluster_size = usize::try_from(self.boot.cluster_size)
            .map_err(|_| ExfatError::Msg("cluster size overflow".into()))?;
        for &c in clusters {
            if remaining == 0 {
                break;
            }
            let rel = self.cluster_rel_offset(c)?;
            let n = remaining.min(cluster_size);
            let start = out.len();
            out.resize(start + n, 0);
            self.read_exact_at(rel, &mut out[start..])?;
            remaining -= n;
        }
        Ok(out)
    }

    fn read_dir_bytes(
        &self,
        first: u32,
        no_fat_chain: bool,
        data_length: Option<u64>,
    ) -> Result<Vec<u8>> {
        let clusters = self.cluster_list(first, no_fat_chain, data_length, data_length)?;
        if clusters.is_empty() {
            return Ok(Vec::new());
        }
        let cap = data_length
            .unwrap_or_else(|| (clusters.len() as u64).saturating_mul(self.boot.cluster_size));
        self.read_clusters(&clusters, cap)
    }

    fn list_entries(
        &self,
        first: u32,
        no_fat_chain: bool,
        data_length: Option<u64>,
    ) -> Result<Vec<DirEntry>> {
        let bytes = self.read_dir_bytes(first, no_fat_chain, data_length)?;
        parse_directory(&bytes)
    }

    fn resolve(&self, path: &str) -> Result<Resolved> {
        let rel = trim_rel(path);
        if rel.is_empty() {
            return Ok(Resolved::Root);
        }
        let mut cluster = self.boot.root_cluster;
        let mut no_fat = false;
        let mut data_len: Option<u64> = None;
        let parts: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        for (i, part) in parts.iter().enumerate() {
            let ents = self.list_entries(cluster, no_fat, data_len)?;
            let ent = ents
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case(part))
                .cloned()
                .ok_or_else(|| ExfatError::Msg("not found".into()))?;
            if i + 1 == parts.len() {
                return Ok(Resolved::Entry(ent));
            }
            if !ent.is_dir {
                return Err(ExfatError::Msg("not found".into()));
            }
            cluster = ent.first_cluster;
            no_fat = ent.no_fat_chain;
            data_len = Some(ent.data_length);
        }
        Err(ExfatError::Msg("not found".into()))
    }

    fn find_entry_info(&self, path: &str) -> Option<FileInfo> {
        match self.resolve(path) {
            Ok(Resolved::Root) => Some(entry_to_file_info(path, true, 0, 0.0)),
            Ok(Resolved::Entry(e)) => Some(entry_to_file_info(path, e.is_dir, e.size, e.mtime)),
            Err(_) => None,
        }
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        let ents = match self.resolve(path) {
            Ok(Resolved::Root) => self
                .list_entries(self.boot.root_cluster, false, None)
                .ok()?,
            Ok(Resolved::Entry(e)) if e.is_dir => self
                .list_entries(e.first_cluster, e.no_fat_chain, Some(e.data_length))
                .ok()?,
            _ => return None,
        };
        let mut map = BTreeMap::new();
        for e in ents {
            let child_path = if path == "/" || path.is_empty() {
                format!("/{}", e.name)
            } else {
                format!("{}/{}", path.trim_end_matches('/'), e.name)
            };
            map.insert(
                e.name.clone(),
                entry_to_file_info(&child_path, e.is_dir, e.size, e.mtime),
            );
        }
        Some(map)
    }

    fn list_dirents_dir(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let ents = match self.resolve(path) {
            Ok(Resolved::Root) => self
                .list_entries(self.boot.root_cluster, false, None)
                .ok()?,
            Ok(Resolved::Entry(e)) if e.is_dir => self
                .list_entries(e.first_cluster, e.no_fat_chain, Some(e.data_length))
                .ok()?,
            _ => return None,
        };
        Some(
            ents.into_iter()
                .map(|e| {
                    let (mode, size) = entry_mode_size(e.is_dir, e.size);
                    CheapDirent {
                        name: e.name,
                        mode,
                        size,
                    }
                })
                .collect(),
        )
    }

    fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        match self.resolve(path) {
            Ok(Resolved::Root) => Err(io::Error::new(io::ErrorKind::IsADirectory, "root")),
            Ok(Resolved::Entry(e)) if e.is_dir => Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            )),
            Ok(Resolved::Entry(e)) => {
                if e.first_cluster < 2 || e.size == 0 {
                    return Ok(Vec::new());
                }
                let clusters = self
                    .cluster_list(
                        e.first_cluster,
                        e.no_fat_chain,
                        Some(e.data_length),
                        Some(e.size),
                    )
                    .map_err(|err| io::Error::other(err.to_string()))?;
                self.read_clusters(&clusters, e.size)
                    .map_err(|err| io::Error::other(err.to_string()))
            }
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}

enum Resolved {
    Root,
    Entry(DirEntry),
}

impl MountSource for ExfatMountSource {
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
            io::Error::new(io::ErrorKind::InvalidInput, "missing exFAT path userdata")
        })?;
        let data = self.read_file(&path)?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn exfat_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("exfat:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("exfat:") => Some(s[6..].to_string()),
        _ => None,
    })
}

fn trim_rel(path: &str) -> String {
    path.trim_matches('/').to_string()
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
        userdata: vec![exfat_path_userdata(name_path)],
    }
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    b.copy_from_slice(&buf[off..off + 2]);
    u16::from_le_bytes(b)
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(b)
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Boot-sector heuristics shared by path and stream probes.
fn boot_sector_looks_like_exfat(boot: &[u8; 512]) -> bool {
    if boot[3..11] != *OEM_NAME {
        return false;
    }
    if boot[510] != 0x55 || boot[511] != 0xAA {
        return false;
    }
    // Bytes 11..64 are MustBeZero on exFAT and hold the FAT BPB on FAT12/16/32.
    if boot[11..64].iter().any(|&b| b != 0) {
        return false;
    }
    let bps_shift = boot[0x6C];
    (9..=12).contains(&bps_shift)
}

fn parse_boot(boot: &[u8; 512]) -> Result<Boot> {
    if !boot_sector_looks_like_exfat(boot) {
        return Err(ExfatError::Msg("not an exFAT boot sector".into()));
    }
    let bps_shift = boot[0x6C];
    let spc_shift = boot[0x6D];
    if spc_shift > 25 {
        return Err(ExfatError::Msg("invalid SectorsPerClusterShift".into()));
    }
    let bytes_per_sector = 1u32 << bps_shift;
    let cluster_size = u64::from(bytes_per_sector) << spc_shift;
    if cluster_size == 0 || cluster_size > 32 * 1024 * 1024 {
        return Err(ExfatError::Msg("invalid cluster size".into()));
    }
    let fat_offset_sectors = read_u32(boot, 0x50);
    let fat_length_sectors = read_u32(boot, 0x54);
    let heap_offset_sectors = read_u32(boot, 0x58);
    let cluster_count = read_u32(boot, 0x5C);
    let root_cluster = read_u32(boot, 0x60);
    let number_of_fats = boot[0x6E];
    let volume_flags = read_u16(boot, 0x6A);
    let active_fat = volume_flags & 1;
    if fat_offset_sectors == 0 || fat_length_sectors == 0 || heap_offset_sectors == 0 {
        return Err(ExfatError::Msg("exFAT FAT/heap offsets are zero".into()));
    }
    if cluster_count < 1 || root_cluster < 2 {
        return Err(ExfatError::Msg(
            "exFAT cluster count / root cluster invalid".into(),
        ));
    }
    let bps = u64::from(bytes_per_sector);
    let mut fat_offset_bytes = u64::from(fat_offset_sectors)
        .checked_mul(bps)
        .ok_or_else(|| ExfatError::Msg("FAT offset overflow".into()))?;
    if number_of_fats >= 2 && active_fat == 1 {
        let fat_len = u64::from(fat_length_sectors)
            .checked_mul(bps)
            .ok_or_else(|| ExfatError::Msg("FAT length overflow".into()))?;
        fat_offset_bytes = fat_offset_bytes
            .checked_add(fat_len)
            .ok_or_else(|| ExfatError::Msg("active FAT offset overflow".into()))?;
    }
    let cluster_heap_offset_bytes = u64::from(heap_offset_sectors)
        .checked_mul(bps)
        .ok_or_else(|| ExfatError::Msg("cluster heap offset overflow".into()))?;
    Ok(Boot {
        cluster_size,
        fat_offset_bytes,
        cluster_heap_offset_bytes,
        cluster_count,
        root_cluster,
    })
}

fn read_boot<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> Result<Boot> {
    let mut boot = [0u8; 512];
    reader.seek(SeekFrom::Start(partition_offset))?;
    reader.read_exact(&mut boot)?;
    parse_boot(&boot)
}

fn parse_directory(bytes: &[u8]) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + ENTRY_SIZE <= bytes.len() {
        let ent = &bytes[i..i + ENTRY_SIZE];
        let et = ent[0];
        if et == ENTRY_END {
            break;
        }
        if et & IN_USE == 0 {
            i += ENTRY_SIZE;
            continue;
        }
        if et != ENTRY_FILE {
            i += ENTRY_SIZE;
            continue;
        }
        let secondary = ent[1] as usize;
        let set_end = i + ENTRY_SIZE * (1 + secondary);
        if set_end > bytes.len() {
            break;
        }
        if let Some(parsed) = parse_file_set(&bytes[i..set_end]) {
            out.push(parsed);
        }
        i = set_end;
    }
    Ok(out)
}

fn parse_file_set(set: &[u8]) -> Option<DirEntry> {
    if set.len() < ENTRY_SIZE * 2 {
        return None;
    }
    let file = &set[0..ENTRY_SIZE];
    let attr = read_u16(file, 4);
    let is_dir = attr & ATTR_DIRECTORY != 0;
    let mtime = dos_datetime_to_unix(read_u32(file, 12), file[21]);

    let mut stream = None;
    let mut name_units = Vec::new();
    let mut off = ENTRY_SIZE;
    while off + ENTRY_SIZE <= set.len() {
        let ent = &set[off..off + ENTRY_SIZE];
        let et = ent[0];
        if et == ENTRY_STREAM {
            stream = Some(ent);
        } else if et == ENTRY_NAME {
            for n in 0..15 {
                let cu = read_u16(ent, 2 + n * 2);
                name_units.push(cu);
            }
        }
        off += ENTRY_SIZE;
    }
    let stream = stream?;
    let flags = stream[1];
    let name_len = stream[3] as usize;
    let valid_len = read_u64(stream, 8);
    let first_cluster = read_u32(stream, 20);
    let data_length = read_u64(stream, 24);
    name_units.truncate(name_len);
    let name = String::from_utf16_lossy(&name_units);
    if name.is_empty() {
        return None;
    }
    Some(DirEntry {
        name,
        is_dir,
        size: if is_dir { 0 } else { valid_len },
        data_length,
        first_cluster,
        no_fat_chain: flags & FLAG_NO_FAT_CHAIN != 0,
        mtime,
    })
}

fn dos_datetime_to_unix(ts: u32, ten_ms: u8) -> f64 {
    let time = (ts & 0xFFFF) as u16;
    let date = (ts >> 16) as u16;
    let day = (date & 0x1F) as i64;
    let month = ((date >> 5) & 0xF) as i64;
    let year = 1980 + ((date >> 9) & 0x7F) as i64;
    if day == 0 || !(1..=12).contains(&month) {
        return 0.0;
    }
    let sec = i64::from((time & 0x1F) * 2);
    let min = i64::from((time >> 5) & 0x3F);
    let hour = i64::from((time >> 11) & 0x1F);
    // Howard Hinnant civil_from_days inverse (same as the FAT crate).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    let days = (era * 146097 + doe as i64 - 719468) as f64;
    days * 86400.0
        + hour as f64 * 3600.0
        + min as f64 * 60.0
        + sec as f64
        + f64::from(ten_ms) * 0.01
}

fn exfat_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("exfat"))
}

/// Detect exFAT via OEM `"EXFAT   "` @ 3 + `0x55AA`, or `*.exfat` extension.
pub fn looks_like_exfat(path: &Path) -> bool {
    looks_like_exfat_at(path, 0)
}

/// Detect exFAT boot sector at `partition_offset`.
///
/// Extension fallback (`*.exfat`) applies only at offset 0 so a partitioned
/// disk named `*.exfat` is not reported as a superfloppy.
pub fn looks_like_exfat_at(path: &Path, partition_offset: u64) -> bool {
    if let Ok(mut f) = File::open(path) {
        if looks_like_exfat_reader_at(&mut f, partition_offset) {
            return true;
        }
    }
    partition_offset == 0 && exfat_extension(path)
}

/// Boot-sector probe for nested streams (does not use filename).
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_exfat_reader<R: Read + Seek>(reader: &mut R) -> bool {
    looks_like_exfat_reader_at(reader, 0)
}

/// Boot-sector probe at `partition_offset` on a seekable stream.
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_exfat_reader_at<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> bool {
    let mut boot = [0u8; 512];
    if reader.seek(SeekFrom::Start(partition_offset)).is_err() {
        return false;
    }
    if reader.read_exact(&mut boot).is_err() {
        return false;
    }
    boot_sector_looks_like_exfat(&boot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;

    const EOC: u32 = 0xFFFF_FFFF;

    fn write_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn write_u64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn synthetic_boot_sector() -> [u8; 512] {
        let mut boot = [0u8; 512];
        boot[0] = 0xEB;
        boot[1] = 0x76;
        boot[2] = 0x90;
        boot[3..11].copy_from_slice(OEM_NAME);
        boot[0x6C] = 9;
        boot[0x6D] = 0;
        boot[510] = 0x55;
        boot[511] = 0xAA;
        boot
    }

    fn fat32_boot_sector() -> [u8; 512] {
        let mut boot = [0u8; 512];
        boot[0] = 0xEB;
        boot[1] = 0x58;
        boot[2] = 0x90;
        boot[3..11].copy_from_slice(b"MSDOS5.0");
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 8;
        boot[16] = 2;
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510] = 0x55;
        boot[511] = 0xAA;
        boot
    }

    fn file_set(
        name: &str,
        is_dir: bool,
        first_cluster: u32,
        data_len: u64,
        no_fat_chain: bool,
    ) -> Vec<[u8; 32]> {
        file_set_lens(
            name,
            is_dir,
            first_cluster,
            data_len,
            data_len,
            no_fat_chain,
        )
    }

    fn file_set_lens(
        name: &str,
        is_dir: bool,
        first_cluster: u32,
        valid_len: u64,
        data_len: u64,
        no_fat_chain: bool,
    ) -> Vec<[u8; 32]> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let mut name_ents = Vec::new();
        for chunk in utf16.chunks(15) {
            let mut e = [0u8; 32];
            e[0] = ENTRY_NAME;
            for (i, &cu) in chunk.iter().enumerate() {
                e[2 + i * 2..4 + i * 2].copy_from_slice(&cu.to_le_bytes());
            }
            name_ents.push(e);
        }
        let secondary = 1 + name_ents.len();
        let mut file = [0u8; 32];
        file[0] = ENTRY_FILE;
        file[1] = secondary as u8;
        let attr: u16 = if is_dir { ATTR_DIRECTORY } else { 0x20 };
        file[4..6].copy_from_slice(&attr.to_le_bytes());
        // 2020-01-15 12:00:00 DOS timestamp in both date/time halves.
        let date: u16 = 15 | (1 << 5) | (40 << 9);
        let time: u16 = 12 << 11;
        let ts = u32::from(time) | (u32::from(date) << 16);
        file[8..12].copy_from_slice(&ts.to_le_bytes());
        file[12..16].copy_from_slice(&ts.to_le_bytes());
        file[16..20].copy_from_slice(&ts.to_le_bytes());

        let mut stream = [0u8; 32];
        stream[0] = ENTRY_STREAM;
        stream[1] = 0x01 | if no_fat_chain { FLAG_NO_FAT_CHAIN } else { 0 };
        stream[3] = utf16.len() as u8;
        write_u64(&mut stream, 8, valid_len);
        write_u32(&mut stream, 20, first_cluster);
        write_u64(&mut stream, 24, data_len);

        let mut out = vec![file, stream];
        out.extend(name_ents);
        out
    }

    const SYNTH_BPS: u32 = 512;
    const SYNTH_VOLUME_SECTORS: u32 = 2048;
    const SYNTH_CLUSTER_COUNT: u32 = 2008;
    const SYNTH_PAD_BYTE: u8 = 0xAB;
    const SYNTH_PAD_LEN: usize = 8192;

    /// Minimal valid-enough volume: hello.txt, foo/ufo, FAT-chained big.bin,
    /// plus crafted NoFatChain overflow entries. Distinctive pad after the heap
    /// so a past-heap cluster walk would leak `SYNTH_PAD_BYTE`s.
    fn synthetic_exfat_image() -> Vec<u8> {
        const FAT_OFFSET: u32 = 24;
        const FAT_LENGTH: u32 = 16;
        const HEAP_OFFSET: u32 = 40;
        const ROOT: u32 = 4;
        let bps = SYNTH_BPS;
        let volume_sectors = SYNTH_VOLUME_SECTORS;
        let cluster_count = SYNTH_CLUSTER_COUNT;

        let mut img = vec![0u8; (volume_sectors * bps) as usize];
        let mut boot = synthetic_boot_sector();
        write_u64(&mut boot, 0x48, u64::from(volume_sectors));
        write_u32(&mut boot, 0x50, FAT_OFFSET);
        write_u32(&mut boot, 0x54, FAT_LENGTH);
        write_u32(&mut boot, 0x58, HEAP_OFFSET);
        write_u32(&mut boot, 0x5C, cluster_count);
        write_u32(&mut boot, 0x60, ROOT);
        write_u32(&mut boot, 0x64, 0x1234_5678);
        boot[0x68] = 0x00;
        boot[0x69] = 0x01;
        boot[0x6E] = 1;
        boot[0x6F] = 0x80;
        img[..512].copy_from_slice(&boot);
        img[12 * 512..13 * 512].copy_from_slice(&boot);

        let fat_off = (FAT_OFFSET * bps) as usize;
        let put_fat = |img: &mut [u8], cluster: u32, val: u32| {
            let o = fat_off + cluster as usize * 4;
            img[o..o + 4].copy_from_slice(&val.to_le_bytes());
        };
        put_fat(&mut img, 0, 0xFFFF_FFF8);
        put_fat(&mut img, 1, EOC);
        for c in 2..=9u32 {
            let next = if c == 8 { 9 } else { EOC };
            put_fat(&mut img, c, next);
        }

        let cluster_off = |c: u32| (HEAP_OFFSET * bps) as usize + (c as usize - 2) * bps as usize;
        img[cluster_off(2)] = 0xFF;

        let hello = b"hello-exfat\n";
        let ufo = b"iriya\n";
        let big: Vec<u8> = (0..612).map(|i| (i % 256) as u8).collect();

        let mut root = Vec::new();
        root.extend(file_set("hello.txt", false, 6, hello.len() as u64, true));
        root.extend(file_set("foo", true, 5, u64::from(bps), true));
        root.extend(file_set("big.bin", false, 8, big.len() as u64, false));
        // Last heap cluster; DataLength covers two clusters → past cluster_count.
        let last = cluster_count + 1;
        root.extend(file_set(
            "overflow.bin",
            false,
            last,
            u64::from(bps) * 2,
            true,
        ));
        // Declared DataLength would allocate ~2^31 cluster ids without a cap.
        root.extend(file_set_lens("huge.bin", false, 6, 12, 1 << 40, true));
        let mut off = cluster_off(4);
        for e in &root {
            img[off..off + 32].copy_from_slice(e);
            off += 32;
        }

        let foo = file_set("ufo", false, 7, ufo.len() as u64, true);
        off = cluster_off(5);
        for e in &foo {
            img[off..off + 32].copy_from_slice(e);
            off += 32;
        }

        img[cluster_off(6)..cluster_off(6) + hello.len()].copy_from_slice(hello);
        img[cluster_off(7)..cluster_off(7) + ufo.len()].copy_from_slice(ufo);
        img[cluster_off(8)..cluster_off(8) + 512].copy_from_slice(&big[..512]);
        img[cluster_off(9)..cluster_off(9) + 100].copy_from_slice(&big[512..]);
        img.extend(vec![SYNTH_PAD_BYTE; SYNTH_PAD_LEN]);
        img
    }

    fn which_mkfs_exfat() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                let p = dir.join("mkfs.exfat");
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        let p = PathBuf::from("/usr/sbin/mkfs.exfat");
        if p.is_file() {
            Some(p)
        } else {
            None
        }
    }

    fn mkfs_exfat_image() -> Option<(tempfile::TempDir, PathBuf)> {
        let mkfs = which_mkfs_exfat()?;
        let dir = tempfile::tempdir().ok()?;
        let img = dir.path().join("vol.exfat");
        {
            let f = File::create(&img).ok()?;
            f.set_len(2 * 1024 * 1024).ok()?;
        }
        let status = Command::new(&mkfs)
            .args(["-n", "Ratar"])
            .arg(&img)
            .status()
            .ok()?;
        if !status.success() {
            eprintln!("skip: mkfs.exfat failed ({})", mkfs.display());
            return None;
        }
        Some((dir, img))
    }

    /// Always-on: OEM `"EXFAT   "` @ 3 is enough for the probe.
    #[test]
    fn looks_like_exfat_oem_magic() {
        let boot = synthetic_boot_sector();
        assert!(looks_like_exfat_reader(&mut Cursor::new(boot)));
        assert!(boot_sector_looks_like_exfat(&boot));
        let mut short = boot.to_vec();
        short.truncate(64);
        assert!(!looks_like_exfat_reader(&mut Cursor::new(short)));
    }

    /// Always-on: FAT32 boot (type string at 82) must not match exFAT.
    #[test]
    fn looks_like_exfat_false_on_fat32() {
        let boot = fat32_boot_sector();
        assert!(!looks_like_exfat_reader(&mut Cursor::new(boot)));
        assert!(!boot_sector_looks_like_exfat(&boot));
        let err = ExfatMountSource::open_from_reader(Cursor::new(boot), "disk.fat")
            .err()
            .expect("FAT32 boot is not exFAT");
        assert!(
            err.to_string().contains("not an exFAT"),
            "unexpected error: {err}"
        );
    }

    /// MustBeZero at 11..64 is the discriminator when OEM is spoofed as `"EXFAT   "`.
    #[test]
    fn looks_like_exfat_false_on_exfat_oem_with_fat_bpb() {
        let mut boot = synthetic_boot_sector();
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 8;
        boot[16] = 2;
        assert!(!boot_sector_looks_like_exfat(&boot));
        assert!(!looks_like_exfat_reader(&mut Cursor::new(boot)));
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = ExfatMountSource::open_from_reader(Cursor::new(b"not-an-exfat-image!!!!"), "bad")
            .err()
            .expect("expected open_from_reader failure");
        assert!(
            err.to_string().contains("not an exFAT"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn open_from_reader_list_and_read() {
        let bytes = synthetic_exfat_image();
        assert!(looks_like_exfat_reader(&mut Cursor::new(&bytes)));
        let m = ExfatMountSource::open_from_reader(Cursor::new(bytes), "nested.exfat")
            .expect("open_from_reader");

        let fi = m.lookup("/hello.txt", 0).expect("hello.txt");
        assert_eq!(fi.size, 12);
        let mut s = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello-exfat\n");

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
    fn open_from_reader_fat_chain_spans_clusters() {
        let bytes = synthetic_exfat_image();
        let m = ExfatMountSource::open_from_reader(Cursor::new(bytes), "chain.exfat")
            .expect("open_from_reader");
        let fi = m.lookup("/big.bin", 0).expect("big.bin");
        assert_eq!(fi.size, 612);
        let mut data = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut data).unwrap();
        let expect: Vec<u8> = (0..612).map(|i| (i % 256) as u8).collect();
        assert_eq!(data, expect);
    }

    fn open_must_not_leak_pad(m: &ExfatMountSource, path: &str) {
        let fi = m.lookup(path, 0).expect("dirent present");
        match m.open(&fi, 0) {
            Ok(mut r) => {
                let mut data = Vec::new();
                r.read_to_end(&mut data).unwrap();
                panic!(
                    "{path} should error on past-heap NoFatChain; got {} bytes (pad leaked: {})",
                    data.len(),
                    data.contains(&SYNTH_PAD_BYTE)
                );
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("past heap") || msg.contains("NoFatChain"),
                    "unexpected error for {path}: {msg}"
                );
            }
        }
    }

    /// Regression: NoFatChain DataLength past cluster_count must not read heap pad.
    #[test]
    fn no_fat_chain_over_length_errors_without_reading_pad() {
        let bytes = synthetic_exfat_image();
        assert!(bytes[bytes.len() - SYNTH_PAD_LEN..]
            .iter()
            .all(|&b| b == SYNTH_PAD_BYTE));
        let m = ExfatMountSource::open_from_reader(Cursor::new(bytes), "overflow.exfat")
            .expect("open_from_reader");
        open_must_not_leak_pad(&m, "/overflow.bin");
    }

    /// Regression: huge declared DataLength must not allocate a terabyte-scale cluster vec.
    #[test]
    fn no_fat_chain_huge_data_length_does_not_allocate() {
        let bytes = synthetic_exfat_image();
        let m = ExfatMountSource::open_from_reader(Cursor::new(bytes), "huge.exfat")
            .expect("open_from_reader");
        open_must_not_leak_pad(&m, "/huge.bin");
    }

    #[test]
    fn open_from_reader_matches_path_open() {
        let bytes = synthetic_exfat_image();
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("match.exfat");
        std::fs::write(&img, &bytes).unwrap();

        let path_src = ExfatMountSource::open(&img).expect("path open");
        let reader_src = ExfatMountSource::open_from_reader(Cursor::new(bytes), "match.exfat")
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

        // Path open keeps one fd for the mount (two-cluster FAT chain).
        let path_big = path_src.lookup("/big.bin", 0).expect("path big.bin");
        let mut big_data = Vec::new();
        path_src
            .open(&path_big, 0)
            .unwrap()
            .read_to_end(&mut big_data)
            .unwrap();
        assert_eq!(big_data.len(), 612);
    }

    /// Regression: cheap readdirplus sizes.
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let bytes = synthetic_exfat_image();
        let src = ExfatMountSource::open_from_reader(Cursor::new(bytes), "dirents.exfat")
            .expect("open_from_reader");
        let dents = src.list_dirents("/").expect("dirents");
        let d = dents
            .iter()
            .find(|e| e.name == "hello.txt")
            .expect("hello.txt dirent");
        let fi = src.lookup("/hello.txt", 0).expect("lookup hello.txt");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, 12);
        assert_ne!(d.size, 0);
        let foo = dents.iter().find(|e| e.name == "foo").expect("foo dirent");
        assert_eq!(foo.size, 0);
        assert_eq!(foo.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);
    }

    #[test]
    fn open_from_reader_with_offset_padded() {
        let bytes = synthetic_exfat_image();
        let offset = 1024 * 1024;
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(&bytes);

        assert!(!looks_like_exfat_reader_at(&mut Cursor::new(&padded), 0));
        assert!(looks_like_exfat_reader_at(
            &mut Cursor::new(&padded),
            offset as u64
        ));

        let m = ExfatMountSource::open_from_reader_with_offset(
            Cursor::new(padded),
            "padded-nested.img",
            offset as u64,
        )
        .expect("open_from_reader_with_offset");
        let fi = m.lookup("/hello.txt", 0).expect("hello via offset");
        assert_eq!(fi.size, 12);
        let mut s = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello-exfat\n");
    }

    #[test]
    fn open_with_offset_path_padded() {
        let bytes = synthetic_exfat_image();
        let offset = 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let padded = dir.path().join("disk.img");
        {
            let mut out = File::create(&padded).unwrap();
            out.write_all(&vec![0u8; offset]).unwrap();
            out.write_all(&bytes).unwrap();
        }
        assert!(!looks_like_exfat_at(&padded, 0));
        assert!(looks_like_exfat_at(&padded, offset as u64));
        let m = ExfatMountSource::open_with_offset(&padded, offset as u64).expect("open at 1 MiB");
        assert!(m.lookup("/foo/ufo", 0).is_some());
    }

    #[test]
    fn mkfs_exfat_open_and_list_root() {
        let Some((_dir, img)) = mkfs_exfat_image() else {
            eprintln!("skip: mkfs.exfat not available");
            return;
        };
        assert!(looks_like_exfat(&img));
        let m = ExfatMountSource::open(&img).expect("open mkfs.exfat image");
        let _root = m.list("/").expect("list root of mkfs.exfat image");
        assert!(m.lookup("/", 0).is_some());
    }
}
