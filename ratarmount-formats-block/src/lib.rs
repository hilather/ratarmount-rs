//! GPT/MBR partition-table mount source.
//!
//! Whole-disk images with a partition table are presented as `/pN/` directories
//! named by **table-slot encounter order** (including residual LVM/RAID/MSR
//! numbers). Only partitions that open as FAT/EXT4 appear in the tree:
//!
//! ```text
//! /p1/   # first numbered slot that mounted (may skip residual p1)
//! /p3/   # e.g. Windows GPT: EFI p1 + MSR p2 skipped + data p3
//! ```
//!
//! Superfloppy FAT/EXT4 at offset **0** stays in those crates (factory probe
//! order will try `Fat` / `Ext4` before `Block`). This crate only claims GPT
//! (`EFI PART` at LBA 1) or an MBR with partitions that start after sector 0.
//! Protective MBR (`0xEE`) without a GPT header is **not** claimed.
//!
//! Each mounted `pN/` is FAT or EXT4 [`open_from_reader_with_offset`] /
//! [`open_with_offset`]. Nested no-tmp uses a mutex-shared `Read + Seek` body —
//! no `NamedTempFile` spool. A small in-crate tree presents `pN/` (not a
//! compositing union) so a two-partition `disk.img` is not noisy.
//!
//! # Residual
//!
//! LVM, Linux RAID, Btrfs, swap, and unknown types that are not FAT/EXT4 are
//! **not** mounted (they still consume `pN` numbers). exFAT/NTFS offset opens
//! land when those crates exist. QCOW2/VHD/VMDK wrap this crate's
//! [`BlockMountSource::open_from_reader`] on the raw virtual disk (no factory
//! edits here).
//!
//! [`open_from_reader_with_offset`]: ratarmount_formats_fat::FatMountSource::open_from_reader_with_offset
//! [`open_with_offset`]: ratarmount_formats_fat::FatMountSource::open_with_offset

mod table;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratarmount_core::{
    create_root_file_info, normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult,
    ListResult, MountSource,
};
use ratarmount_formats_ext4::{looks_like_ext4_at, looks_like_ext4_reader_at, Ext4MountSource};
use ratarmount_formats_fat::{looks_like_fat_at, looks_like_fat_reader_at, FatMountSource};
use thiserror::Error;

pub use table::{
    gpt_guid, gpt_signature_at, gpt_type_efi, gpt_type_linux_fs, gpt_type_linux_lvm,
    gpt_type_microsoft_basic, gpt_type_ms_reserved, mbr_has_usable_partition,
    mbr_is_protective_gpt, parse_partition_table, Partition, PartitionKind, PartitionScheme,
    DEFAULT_SECTOR_SIZE, MBR_TYPE_EXTENDED, MBR_TYPE_EXTENDED_LBA, MBR_TYPE_GPT_PROTECTIVE,
    MBR_TYPE_LINUX_LVM,
};

pub const BACKEND_NAME: &str = "BlockMountSource";

#[derive(Debug, Error)]
pub enum BlockError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, BlockError>;

/// Object-safe `Read + Seek + Send` for the nested shared backend.
trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

/// Cloneable view of a mutex-shared disk image (seek+read under one lock).
struct SharedSeekReader {
    inner: Arc<Mutex<Box<dyn SeekRead>>>,
    pos: u64,
}

impl Clone for SharedSeekReader {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            pos: 0,
        }
    }
}

impl SharedSeekReader {
    fn new(inner: Arc<Mutex<Box<dyn SeekRead>>>) -> Self {
        Self { inner, pos: 0 }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Box<dyn SeekRead>>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("shared block reader poisoned"))
    }
}

impl Read for SharedSeekReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = {
            let mut guard = self.lock()?;
            guard.seek(SeekFrom::Start(self.pos))?;
            guard.read(buf)?
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SharedSeekReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.pos as i64 + o,
            SeekFrom::End(o) => {
                let mut guard = self.lock()?;
                let end = guard.seek(SeekFrom::End(0))?;
                end as i64 + o
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

fn part_dir_info() -> FileInfo {
    FileInfo {
        size: 0,
        mtime: 0.0,
        mode: ratarmount_core::S_IFDIR | 0o755,
        linkname: String::new(),
        uid: ratarmount_core::effective_uid(),
        gid: ratarmount_core::effective_gid(),
        userdata: vec![],
    }
}

/// `/pN` → (`pN`, `/`); `/pN/foo` → (`pN`, `/foo`).
fn split_part(path: &str) -> Option<(String, String)> {
    let path = normpath(path);
    if path == "/" {
        return None;
    }
    let rest = path.trim_start_matches('/');
    match rest.split_once('/') {
        Some((name, tail)) => Some((name.to_string(), format!("/{tail}"))),
        None => Some((rest.to_string(), "/".into())),
    }
}

/// In-crate `pN/` tree (avoids compositing union folder-cache `warn!`).
struct PartitionTree {
    mounts: Vec<(String, Arc<dyn MountSource>)>,
}

impl PartitionTree {
    fn find(&self, name: &str) -> Option<&Arc<dyn MountSource>> {
        self.mounts.iter().find(|(n, _)| n == name).map(|(_, s)| s)
    }
}

impl MountSource for PartitionTree {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if path == "/" {
            let mut map = BTreeMap::new();
            for (name, _) in &self.mounts {
                map.insert(name.clone(), part_dir_info());
            }
            return Some(ListResult::Infos(map));
        }
        let (name, inner) = split_part(&path)?;
        self.find(&name)?.list(&inner)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let path = normpath(path);
        if path == "/" {
            return Some(
                self.mounts
                    .iter()
                    .map(|(name, _)| CheapDirent {
                        name: name.clone(),
                        mode: ratarmount_core::S_IFDIR | 0o755,
                        size: 0,
                    })
                    .collect(),
            );
        }
        let (name, inner) = split_part(&path)?;
        self.find(&name)?.list_dirents(&inner)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let dents = self.list_dirents(path)?;
        Some(ListModeResult::Modes(
            dents.into_iter().map(|d| (d.name, d.mode)).collect(),
        ))
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        let (name, inner) = split_part(&path)?;
        if inner == "/" {
            return self.find(&name).map(|_| part_dir_info());
        }
        self.find(&name)?.lookup(&inner, file_version)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no partition source could open");
        for (_, src) in &self.mounts {
            match src.open(file_info, buffering) {
                Ok(r) => return Ok(r),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn versions(&self, path: &str) -> u32 {
        let path = normpath(path);
        if path == "/" {
            return 1;
        }
        let Some((name, inner)) = split_part(&path) else {
            return 0;
        };
        self.find(&name).map(|s| s.versions(&inner)).unwrap_or(0)
    }

    fn is_immutable(&self) -> bool {
        self.mounts.iter().all(|(_, s)| s.is_immutable())
    }

    fn content_generation(&self) -> u64 {
        self.mounts.iter().fold(0u64, |acc, (_, s)| {
            acc.saturating_add(s.content_generation())
        })
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        self.mounts
            .iter()
            .all(|(_, s)| s.member_seek_is_cheap(file_info))
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return None;
        }
        let mut out = Vec::new();
        for (_, src) in &self.mounts {
            out.extend(src.search_cheap(pattern)?);
        }
        Some(out)
    }
}

/// Partitioned disk image as a tree of `pN/` filesystem mounts.
pub struct BlockMountSource {
    inner: PartitionTree,
    partitions: Vec<Partition>,
    /// Diagnostic label (path or nested member name).
    #[allow(dead_code)]
    archive_label: PathBuf,
}

impl BlockMountSource {
    /// Open a partitioned raw disk image from a host path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_block(path) {
            return Err(BlockError::Msg(format!(
                "{} is not a GPT/MBR partitioned disk image",
                path.display()
            )));
        }
        let mut file = File::open(path)?;
        let partitions = parse_partition_table(&mut file)?;
        drop(file);

        let mut mounts: Vec<(String, Arc<dyn MountSource>)> = Vec::new();
        for part in &partitions {
            if let Some(fs) = try_open_fs_path(path, part) {
                mounts.push((part.dir_name(), fs));
            }
        }
        if mounts.is_empty() {
            return Err(no_fs_error(&partitions, path.display()));
        }
        Ok(Self {
            inner: PartitionTree { mounts },
            partitions,
            archive_label: path.to_path_buf(),
        })
    }

    /// Open a partitioned raw disk from any `Read + Seek` without `/tmp`.
    ///
    /// The reader is retained under a mutex and cloned as a positioned view for
    /// each partition's FAT/EXT4 `open_from_reader_with_offset`. The image is
    /// **not** copied into a second buffer by this method.
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_label = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_block_reader(&mut reader) {
            return Err(BlockError::Msg(format!(
                "{} is not a GPT/MBR partitioned disk image",
                archive_label.display()
            )));
        }
        reader.seek(SeekFrom::Start(0))?;
        let partitions = parse_partition_table(&mut reader)?;
        reader.seek(SeekFrom::Start(0))?;

        let shared: Arc<Mutex<Box<dyn SeekRead>>> =
            Arc::new(Mutex::new(Box::new(reader) as Box<dyn SeekRead>));

        let mut mounts: Vec<(String, Arc<dyn MountSource>)> = Vec::new();
        for part in &partitions {
            if let Some(fs) = try_open_fs_shared(SharedSeekReader::new(Arc::clone(&shared)), part) {
                mounts.push((part.dir_name(), fs));
            }
        }
        if mounts.is_empty() {
            return Err(no_fs_error(&partitions, archive_label.display()));
        }
        Ok(Self {
            inner: PartitionTree { mounts },
            partitions,
            archive_label,
        })
    }

    pub fn partitions(&self) -> &[Partition] {
        &self.partitions
    }
}

fn no_fs_error(parts: &[Partition], label: impl std::fmt::Display) -> BlockError {
    let kinds: Vec<_> = parts
        .iter()
        .map(|p| format!("p{}={:?}", p.number, p.kind))
        .collect();
    BlockError::Msg(format!(
        "no supported filesystems in GPT/MBR image {label} (opened 0 of {} partitions: {}). \
         LVM, RAID, and Btrfs are residual; exFAT/NTFS wait on those crates",
        parts.len(),
        kinds.join(", ")
    ))
}

fn try_open_fs_path(path: &Path, part: &Partition) -> Option<Arc<dyn MountSource>> {
    if part.kind.is_mount_residual() {
        log::debug!(
            "block: skip {} ({:?}) — residual",
            part.dir_name(),
            part.kind
        );
        return None;
    }
    let off = part.start_byte();
    if looks_like_fat_at(path, off) {
        match FatMountSource::open_with_offset(path, off) {
            Ok(m) => return Some(Arc::new(m)),
            Err(e) => log::debug!("block: FAT open {} at {off} failed: {e}", path.display()),
        }
    }
    if looks_like_ext4_at(path, off) {
        match Ext4MountSource::open_with_offset(path, off) {
            Ok(m) => return Some(Arc::new(m)),
            Err(e) => log::debug!("block: EXT4 open {} at {off} failed: {e}", path.display()),
        }
    }
    None
}

fn try_open_fs_shared(shared: SharedSeekReader, part: &Partition) -> Option<Arc<dyn MountSource>> {
    if part.kind.is_mount_residual() {
        log::debug!(
            "block: skip {} ({:?}) — residual",
            part.dir_name(),
            part.kind
        );
        return None;
    }
    let off = part.start_byte();
    let label = part.dir_name();
    {
        let mut probe = shared.clone();
        if looks_like_fat_reader_at(&mut probe, off) {
            match FatMountSource::open_from_reader_with_offset(shared.clone(), &label, off) {
                Ok(m) => return Some(Arc::new(m)),
                Err(e) => log::debug!("block: FAT reader open {label} at {off} failed: {e}"),
            }
        }
    }
    {
        let mut probe = shared.clone();
        if looks_like_ext4_reader_at(&mut probe, off) {
            match Ext4MountSource::open_from_reader_with_offset(shared, &label, off) {
                Ok(m) => return Some(Arc::new(m)),
                Err(e) => log::debug!("block: EXT4 reader open {label} at {off} failed: {e}"),
            }
        }
    }
    None
}

/// Detect GPT (`EFI PART` at LBA 1) or an MBR with partitions starting after LBA 0.
///
/// Superfloppy FAT/EXT4 at offset 0 returns **false** so those crates keep the
/// image. No `.img` extension fallback (too generic).
pub fn looks_like_block(path: &Path) -> bool {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    looks_like_block_reader(&mut f)
}

/// Stream probe (does not use filename). Leaves the reader at an unspecified position.
pub fn looks_like_block_reader<R: Read + Seek>(reader: &mut R) -> bool {
    match gpt_signature_at(reader, 512) {
        Ok(true) => return true,
        Ok(false) => {}
        Err(_) => return false,
    }
    match gpt_signature_at(reader, 4096) {
        Ok(true) => return true,
        Ok(false) => {}
        Err(_) => return false,
    }
    // Superfloppy wins: factory (later) probes Fat/Ext4 first; this crate must
    // not claim offset-0 filesystems even if bytes 446–510 look like an MBR.
    if looks_like_fat_reader_at(reader, 0) || looks_like_ext4_reader_at(reader, 0) {
        return false;
    }
    mbr_has_usable_partition(reader).unwrap_or(false)
}

impl MountSource for BlockMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.inner.list(path)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        self.inner.list_mode(path)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.inner.list_dirents(path)
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        self.inner.search_cheap(pattern)
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.inner.lookup(path, file_version)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(file_info, buffering)
    }

    fn versions(&self, path: &str) -> u32 {
        self.inner.versions(path)
    }

    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }

    fn content_generation(&self) -> u64 {
        self.inner.content_generation()
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        self.inner.member_seek_is_cheap(file_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    use fatfs::{FileSystem, FsOptions};

    const FAT_BYTES: usize = 256 * 1024;

    fn fat_volume(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut storage = vec![0u8; FAT_BYTES];
        {
            let mut cur = Cursor::new(&mut storage[..]);
            fatfs::format_volume(&mut cur, fatfs::FormatVolumeOptions::new())
                .expect("format FAT volume");
        }
        {
            let mut cur = Cursor::new(&mut storage[..]);
            let fs = FileSystem::new(&mut cur, FsOptions::new()).expect("mount formatted FAT");
            {
                let mut f = fs.root_dir().create_file(name).expect("create file");
                f.write_all(payload).expect("write payload");
                f.flush().ok();
            }
        }
        storage
    }

    fn mbr_wrap(fat: &[u8], start_lba: u32) -> Vec<u8> {
        let start_off = start_lba as usize * 512;
        let fat_sectors = fat.len().div_ceil(512) as u32;
        let mut img = vec![0u8; start_off + fat.len()];
        img[510] = 0x55;
        img[511] = 0xAA;
        let ent = 446;
        img[ent + 4] = 0x0C;
        img[ent + 8..ent + 12].copy_from_slice(&start_lba.to_le_bytes());
        img[ent + 12..ent + 16].copy_from_slice(&fat_sectors.to_le_bytes());
        img[start_off..start_off + fat.len()].copy_from_slice(fat);
        img
    }

    fn gpt_wrap(fat: &[u8], start_lba: u64) -> Vec<u8> {
        const SS: u64 = 512;
        let fat_sectors = (fat.len() as u64).div_ceil(512).max(1);
        let last_lba = start_lba + fat_sectors - 1;
        let backup_lba = last_lba + 33;
        let mut img = vec![0u8; ((backup_lba + 1) * SS) as usize];

        img[510] = 0x55;
        img[511] = 0xAA;
        img[446 + 4] = MBR_TYPE_GPT_PROTECTIVE;
        img[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[446 + 12..446 + 16]
            .copy_from_slice(&(backup_lba as u32).saturating_sub(1).to_le_bytes());

        let entry_off = (2 * SS) as usize;
        let type_guid = gpt_type_microsoft_basic();
        img[entry_off..entry_off + 16].copy_from_slice(&type_guid);
        img[entry_off + 16..entry_off + 32].copy_from_slice(&[1u8; 16]);
        img[entry_off + 32..entry_off + 40].copy_from_slice(&start_lba.to_le_bytes());
        img[entry_off + 40..entry_off + 48].copy_from_slice(&last_lba.to_le_bytes());
        let array_crc = crc32fast::hash(&img[entry_off..entry_off + 128 * 128]);

        let mut hdr = [0u8; 92];
        hdr[0..8].copy_from_slice(b"EFI PART");
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
        img[512..512 + 92].copy_from_slice(&hdr);

        let fat_off = (start_lba * SS) as usize;
        img[fat_off..fat_off + fat.len()].copy_from_slice(fat);
        img
    }

    fn find_name<'a>(dents: &'a [CheapDirent], want: &str) -> &'a CheapDirent {
        dents
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(want))
            .unwrap_or_else(|| {
                panic!(
                    "missing {want} in {:?}",
                    dents.iter().map(|d| &d.name).collect::<Vec<_>>()
                )
            })
    }

    /// Regression: superfloppy FAT at offset 0 is not a partition table.
    #[test]
    fn looks_like_block_false_on_fat_superfloppy() {
        let bytes = fat_volume("hello.txt", b"superfloppy");
        assert!(!looks_like_block_reader(&mut Cursor::new(&bytes)));
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("superfloppy.img");
        std::fs::write(&img, &bytes).unwrap();
        assert!(!looks_like_block(&img));
        let err = BlockMountSource::open(&img)
            .err()
            .expect("superfloppy must not open as GPT/MBR");
        assert!(
            err.to_string().contains("not a GPT/MBR"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn looks_like_block_false_on_random() {
        assert!(!looks_like_block_reader(&mut Cursor::new(b"not-a-disk")));
        let mut ext = vec![0u8; 2048];
        ext[1024 + 0x38..1024 + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        assert!(
            !looks_like_block_reader(&mut Cursor::new(&ext)),
            "EXT superblock at offset 0 must not look like GPT/MBR"
        );
    }

    /// Regression: synthetic MBR + FAT offset fixture lists `p1/` and reads the file.
    #[test]
    fn mbr_fat_p1_listing_and_read() {
        let payload = b"hello-mbr-fat";
        let fat = fat_volume("hello.txt", payload);
        let img = mbr_wrap(&fat, 8); // 4 KiB prefix
        assert!(looks_like_block_reader(&mut Cursor::new(&img)));
        assert!(!looks_like_fat_reader_at(&mut Cursor::new(&img), 0));
        assert!(looks_like_fat_reader_at(&mut Cursor::new(&img), 8 * 512));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        std::fs::write(&path, &img).unwrap();

        let m = BlockMountSource::open(&path).expect("open MBR+FAT");
        assert_eq!(m.partitions().len(), 1);
        assert_eq!(m.partitions()[0].dir_name(), "p1");

        let root = m.list_dirents("/").expect("list /");
        find_name(&root, "p1");
        assert!(m.lookup("/p1", 0).is_some());

        let p1 = m.list_dirents("/p1").expect("list /p1");
        let d = find_name(&p1, "hello.txt");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup p1/hello.txt");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.size, payload.len() as u64);
        assert_ne!(d.size, 0);

        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: nested no-tmp `open_from_reader` on MBR+FAT (Cursor, no /tmp).
    #[test]
    fn mbr_fat_open_from_reader_no_tmp() {
        let payload = b"nested-mbr-fat";
        let img = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let m = BlockMountSource::open_from_reader(Cursor::new(img), "nested.img")
            .expect("open_from_reader");
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got.as_bytes(), payload);
    }

    /// Regression: partition at 1 MiB still lists `p1/`.
    #[test]
    fn mbr_fat_partition_at_1mib() {
        let payload = b"one-mebibyte-offset";
        let start_lba = 2048u32; // 1 MiB
        let img = mbr_wrap(&fat_volume("hello.txt", payload), start_lba);
        assert_eq!(img.len(), 1024 * 1024 + FAT_BYTES);
        let m = BlockMountSource::open_from_reader(Cursor::new(img), "1mib.img").expect("open");
        assert_eq!(m.partitions()[0].start_byte(), 1024 * 1024);
        let dents = m.list_dirents("/p1").expect("p1 dirents");
        find_name(&dents, "hello.txt");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: GPT + FAT offset fixture lists `p1/`.
    #[test]
    fn gpt_fat_p1_listing() {
        let payload = b"hello-gpt-fat";
        let img = gpt_wrap(&fat_volume("hello.txt", payload), 34);
        assert!(looks_like_block_reader(&mut Cursor::new(&img)));
        let m = BlockMountSource::open_from_reader(Cursor::new(img), "gpt.img").expect("gpt open");
        assert_eq!(m.partitions()[0].scheme, PartitionScheme::Gpt);
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: LVM-only MBR is parsed but not mounted (residual).
    #[test]
    fn lvm_partition_skipped() {
        let mut img = vec![0u8; 512];
        img[510] = 0x55;
        img[511] = 0xAA;
        img[446 + 4] = MBR_TYPE_LINUX_LVM;
        img[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&1024u32.to_le_bytes());
        assert!(looks_like_block_reader(&mut Cursor::new(&img)));
        let parts = parse_partition_table(&mut Cursor::new(&img)).unwrap();
        assert_eq!(parts[0].kind, PartitionKind::LinuxLvm);
        let err = BlockMountSource::open_from_reader(Cursor::new(img), "lvm.img")
            .err()
            .expect("LVM-only image must not mount a filesystem");
        let msg = err.to_string();
        assert!(
            msg.contains("LVM") || msg.contains("residual") || msg.contains("no supported"),
            "unexpected: {msg}"
        );
    }

    /// Regression: LVM + FAT → only the FAT partition is listed (`p2/` when LVM is p1).
    #[test]
    fn mbr_lvm_then_fat_lists_p2() {
        let payload = b"second-part";
        let fat = fat_volume("hello.txt", payload);
        let fat_lba = 4096u32;
        let mut img = mbr_wrap(&fat, fat_lba);
        // Slot 0 = LVM, slot 1 = FAT (rewrite table; keep FAT payload at fat_lba).
        img[446 + 4] = MBR_TYPE_LINUX_LVM;
        img[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&1024u32.to_le_bytes());
        let fat_sectors = (FAT_BYTES / 512) as u32;
        img[446 + 16 + 4] = 0x0C;
        img[446 + 16 + 8..446 + 16 + 12].copy_from_slice(&fat_lba.to_le_bytes());
        img[446 + 16 + 12..446 + 16 + 16].copy_from_slice(&fat_sectors.to_le_bytes());

        let m = BlockMountSource::open_from_reader(Cursor::new(img), "mixed.img").expect("open");
        assert_eq!(m.partitions().len(), 2);
        assert_eq!(m.partitions()[0].kind, PartitionKind::LinuxLvm);
        assert_eq!(m.partitions()[1].kind, PartitionKind::Fat);
        let root = m.list_dirents("/").expect("root");
        assert!(root.iter().any(|d| d.name == "p2"));
        assert!(!root.iter().any(|d| d.name == "p1"));
        let fi = m.lookup("/p2/hello.txt", 0).expect("p2 file");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = BlockMountSource::open_from_reader(Cursor::new(b"nope"), "bad.img")
            .err()
            .expect("non-disk bytes must fail");
        assert!(
            err.to_string().contains("not a GPT/MBR"),
            "unexpected: {err}"
        );
    }

    /// Regression: cheap readdirplus sizes under `p1/`.
    #[test]
    fn list_dirents_sizes_match_lookup() {
        let payload = b"hello-block-dirents";
        let img = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let m = BlockMountSource::open_from_reader(Cursor::new(img), "dirents.img").unwrap();
        let dents = m.list_dirents("/p1").expect("p1 dirents");
        let d = find_name(&dents, "hello.txt");
        let fi = m.lookup("/p1/hello.txt", 0).unwrap();
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, payload.len() as u64);
    }

    /// Regression: protective MBR without `EFI PART` must not steal later backends.
    #[test]
    fn looks_like_block_false_on_protective_mbr_without_gpt() {
        let mut img = vec![0u8; 512];
        img[510] = 0x55;
        img[511] = 0xAA;
        img[446 + 4] = MBR_TYPE_GPT_PROTECTIVE;
        img[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(mbr_is_protective_gpt(&mut Cursor::new(&img)).unwrap());
        assert!(!looks_like_block_reader(&mut Cursor::new(&img)));
    }

    fn mbr_two_fat(fat1: &[u8], lba1: u32, fat2: &[u8], lba2: u32) -> Vec<u8> {
        let s1 = fat1.len().div_ceil(512) as u32;
        let s2 = fat2.len().div_ceil(512) as u32;
        let end = (lba2 as usize + fat2.len().div_ceil(512)) * 512;
        let mut img = vec![0u8; end.max(lba1 as usize * 512 + fat1.len())];
        img[510] = 0x55;
        img[511] = 0xAA;
        img[446 + 4] = 0x0C;
        img[446 + 8..446 + 12].copy_from_slice(&lba1.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&s1.to_le_bytes());
        img[446 + 16 + 4] = 0x0C;
        img[446 + 16 + 8..446 + 16 + 12].copy_from_slice(&lba2.to_le_bytes());
        img[446 + 16 + 12..446 + 16 + 16].copy_from_slice(&s2.to_le_bytes());
        let o1 = lba1 as usize * 512;
        img[o1..o1 + fat1.len()].copy_from_slice(fat1);
        let o2 = lba2 as usize * 512;
        img[o2..o2 + fat2.len()].copy_from_slice(fat2);
        img
    }

    /// Regression: two mountable FAT partitions list `/p1` and `/p2` with distinct payloads.
    #[test]
    fn mbr_two_fat_p1_p2_open_from_reader() {
        let a = b"payload-one";
        let b = b"payload-two";
        let fat1 = fat_volume("a.txt", a);
        let fat2 = fat_volume("b.txt", b);
        let lba1 = 8u32;
        let lba2 = lba1 + fat1.len().div_ceil(512) as u32;
        let img = mbr_two_fat(&fat1, lba1, &fat2, lba2);
        let m = BlockMountSource::open_from_reader(Cursor::new(img), "two.img").expect("open");
        let root = m.list_dirents("/").expect("root");
        find_name(&root, "p1");
        find_name(&root, "p2");
        let fi1 = m.lookup("/p1/a.txt", 0).expect("p1/a.txt");
        let fi2 = m.lookup("/p2/b.txt", 0).expect("p2/b.txt");
        let mut g1 = Vec::new();
        m.open(&fi1, 0).unwrap().read_to_end(&mut g1).unwrap();
        let mut g2 = Vec::new();
        m.open(&fi2, 0).unwrap().read_to_end(&mut g2).unwrap();
        assert_eq!(g1, a);
        assert_eq!(g2, b);
        assert!(m.lookup("/p1/b.txt", 0).is_none());
        assert!(m.lookup("/p2/a.txt", 0).is_none());
    }

    /// Regression: EBR logical FAT is mounted as sequential `p1/`.
    #[test]
    fn ebr_logical_fat_p1_listing() {
        let payload = b"logical-fat";
        let fat = fat_volume("hello.txt", payload);
        let ext_start = 8u32;
        let fat_lba = ext_start + 1;
        let fat_sectors = fat.len().div_ceil(512) as u32;
        let mut img = vec![0u8; (fat_lba as usize + fat_sectors as usize) * 512];
        img[510] = 0x55;
        img[511] = 0xAA;
        img[446 + 4] = MBR_TYPE_EXTENDED_LBA;
        img[446 + 8..446 + 12].copy_from_slice(&ext_start.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&(fat_sectors + 1).to_le_bytes());
        let ebr = ext_start as usize * 512;
        img[ebr + 510] = 0x55;
        img[ebr + 511] = 0xAA;
        img[ebr + 446 + 4] = 0x0C;
        img[ebr + 446 + 8..ebr + 446 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[ebr + 446 + 12..ebr + 446 + 16].copy_from_slice(&fat_sectors.to_le_bytes());
        let fat_off = fat_lba as usize * 512;
        img[fat_off..fat_off + fat.len()].copy_from_slice(&fat);

        let m = BlockMountSource::open_from_reader(Cursor::new(img), "ebr.img").expect("ebr open");
        assert_eq!(m.partitions()[0].start_lba, u64::from(fat_lba));
        let fi = m.lookup("/p1/hello.txt", 0).expect("logical p1 file");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    fn any_ext4_bytes() -> Option<Vec<u8>> {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let bz2 = PathBuf::from(&root).join("tests/nested-tar-1M.ext4.bz2");
        if bz2.exists() {
            let dir = tempfile::tempdir().ok()?;
            let img = dir.path().join("x.ext4");
            let status = std::process::Command::new("bzip2")
                .args(["-dc"])
                .arg(&bz2)
                .stdout(File::create(&img).ok()?)
                .status()
                .ok()?;
            if status.success() {
                return std::fs::read(&img).ok();
            }
        }
        let mke2fs = ["/usr/sbin/mke2fs", "/sbin/mke2fs"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .or_else(|| {
                std::env::var_os("PATH").and_then(|path| {
                    std::env::split_paths(&path)
                        .map(|d| d.join("mke2fs"))
                        .find(|p| p.is_file())
                })
            })?;
        let dir = tempfile::tempdir().ok()?;
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(seed.join("foo")).ok()?;
        std::fs::write(seed.join("foo/hello.txt"), b"ext4-in-mbr").ok()?;
        let img = dir.path().join("min.ext4");
        File::create(&img).ok()?.set_len(1024 * 1024).ok()?;
        let status = std::process::Command::new(mke2fs)
            .args(["-t", "ext4", "-F", "-q", "-d"])
            .arg(&seed)
            .arg(&img)
            .status()
            .ok()?;
        if !status.success() {
            eprintln!("skip: mke2fs failed");
            return None;
        }
        std::fs::read(&img).ok()
    }

    /// EXT4 `open_*_with_offset` via MBR `p1/` when a fixture or mke2fs exists.
    #[test]
    fn mbr_ext4_p1_skip_if_missing() {
        let Some(ext) = any_ext4_bytes() else {
            eprintln!("skip: no EXT4 fixture / mke2fs");
            return;
        };
        let start_lba = 8u32;
        let start_off = start_lba as usize * 512;
        let sectors = ext.len().div_ceil(512) as u32;
        let mut img = vec![0u8; start_off + ext.len()];
        img[510] = 0x55;
        img[511] = 0xAA;
        img[446 + 4] = 0x83;
        img[446 + 8..446 + 12].copy_from_slice(&start_lba.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&sectors.to_le_bytes());
        img[start_off..start_off + ext.len()].copy_from_slice(&ext);
        let m = BlockMountSource::open_from_reader(Cursor::new(img), "ext4.img")
            .expect("MBR+EXT4 open");
        assert_eq!(m.partitions()[0].kind, PartitionKind::LinuxFs);
        assert!(m.lookup("/p1", 0).is_some());
        let root = m.list_dirents("/p1").expect("ext4 p1");
        assert!(!root.is_empty(), "EXT4 p1 should list at least one dirent");
    }
}
