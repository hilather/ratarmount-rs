//! GPT/MBR partition-table mount source.
//!
//! Whole-disk images with a partition table are presented as:
//!
//! ```text
//! /p1/   # first filesystem partition
//! /p2/
//! ```
//!
//! Superfloppy FAT/EXT4 at offset **0** stays in those crates (factory probe
//! order will try `Fat` / `Ext4` before `Block`). This crate only claims GPT
//! (`EFI PART` at LBA 1) or an MBR with partitions that start after sector 0.
//!
//! Each `pN/` is a [`PrefixMountSource`] over FAT or EXT4
//! [`open_from_reader_with_offset`] / [`open_with_offset`]. Nested no-tmp uses a
//! mutex-shared `Read + Seek` body — no `NamedTempFile` spool.
//!
//! # Residual
//!
//! LVM, Linux RAID, Btrfs, swap, and unknown types that are not FAT/EXT4 are
//! **not** mounted. exFAT/NTFS offset opens land when those crates exist.
//! QCOW2/VHD/VMDK wrap this crate's [`BlockMountSource::open_from_reader`] on
//! the raw virtual disk (no factory edits here).
//!
//! [`open_from_reader_with_offset`]: ratarmount_formats_fat::FatMountSource::open_from_reader_with_offset
//! [`open_with_offset`]: ratarmount_formats_fat::FatMountSource::open_with_offset

mod table;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratarmount_compositing::{PrefixMountSource, UnionMountSource};
use ratarmount_core::{
    CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
};
use ratarmount_formats_ext4::{looks_like_ext4_at, looks_like_ext4_reader_at, Ext4MountSource};
use ratarmount_formats_fat::{looks_like_fat_at, looks_like_fat_reader_at, FatMountSource};
use thiserror::Error;

pub use table::{
    gpt_guid, gpt_signature_at, gpt_type_efi, gpt_type_linux_fs, gpt_type_linux_lvm,
    gpt_type_microsoft_basic, mbr_has_usable_partition, mbr_is_protective_gpt,
    parse_partition_table, Partition, PartitionKind, PartitionScheme, DEFAULT_SECTOR_SIZE,
    MBR_TYPE_EXTENDED, MBR_TYPE_EXTENDED_LBA, MBR_TYPE_GPT_PROTECTIVE, MBR_TYPE_LINUX_LVM,
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

/// Partitioned disk image as a union of `pN/` filesystem mounts.
pub struct BlockMountSource {
    inner: UnionMountSource,
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

        let mut sources: Vec<Arc<dyn MountSource>> = Vec::new();
        for part in &partitions {
            if let Some(fs) = try_open_fs_path(path, part) {
                sources.push(Arc::new(PrefixMountSource::new(&part.dir_name(), fs)));
            }
        }
        if sources.is_empty() {
            return Err(no_fs_error(&partitions, path.display()));
        }
        Ok(Self {
            inner: UnionMountSource::new(sources),
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

        let mut sources: Vec<Arc<dyn MountSource>> = Vec::new();
        for part in &partitions {
            if let Some(fs) = try_open_fs_shared(SharedSeekReader::new(Arc::clone(&shared)), part) {
                sources.push(Arc::new(PrefixMountSource::new(&part.dir_name(), fs)));
            }
        }
        if sources.is_empty() {
            return Err(no_fs_error(&partitions, archive_label.display()));
        }
        Ok(Self {
            inner: UnionMountSource::new(sources),
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
    match mbr_has_usable_partition(reader) {
        Ok(true) => return true,
        Ok(false) => {}
        Err(_) => return false,
    }
    mbr_is_protective_gpt(reader).unwrap_or(false)
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
}
