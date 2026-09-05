//! VHD / VHDX virtual-disk mount source.
//!
//! Translates guest LBA bytes through a Connectix VHD footer (fixed or dynamic
//! BAT) or a VHDX BAT, then wraps [`BlockMountSource::open_from_reader`] so
//! GPT/MBR partitions appear as `/pN/`. Superfloppy FAT/EXT4 at virtual offset
//! 0 is mounted at `/` (same as the factory probe order Fat/Ext4-before-Block).
//! Nested no-tmp uses the caller's `Read + Seek` — no `NamedTempFile`.
//!
//! # Residual
//!
//! Differencing (parent) VHD/VHDX, encrypted VHDX, and a non-zero VHDX
//! `LogGuid` (journal replay) are **not** opened. Dynamic VHDX without a
//! parent is the same BAT path as fixed (holes read as zeros). Sector-bitmap
//! partial blocks are treated as fully present. This crate does **not** edit
//! session `factory.rs` / `formats-all`.
//!
//! [`BlockMountSource::open_from_reader`]: ratarmount_formats_block::BlockMountSource::open_from_reader

mod disk;
mod vhd;
mod vhdx;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use ratarmount_core::{
    CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
};
use ratarmount_formats_block::{looks_like_block_reader, BlockMountSource};
use ratarmount_formats_ext4::{looks_like_ext4_reader_at, Ext4MountSource};
use ratarmount_formats_fat::{looks_like_fat_reader_at, FatMountSource};
use thiserror::Error;

use crate::disk::VirtualDisk;
use crate::vhd::{looks_like_vhd_reader as vhd_magic, open_vhd};
use crate::vhdx::{looks_like_vhdx_reader as vhdx_magic, open_vhdx};

pub const BACKEND_NAME: &str = "VhdMountSource";

/// Object-safe `Read + Seek + Send` for the container file / nested body.
trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

#[derive(Debug, Error)]
pub enum VhdError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, VhdError>;

/// Container kind after a successful open (tests / diagnostics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VhdKind {
    FixedVhd,
    DynamicVhd,
    Vhdx,
}

/// VHD or VHDX image presented as the inner disk's filesystems.
pub struct VhdMountSource {
    inner: Box<dyn MountSource>,
    kind: VhdKind,
    virtual_size: u64,
}

impl VhdMountSource {
    /// Open a host-path `.vhd` / `.vhdx`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_vhd(path) && !looks_like_vhdx(path) {
            return Err(VhdError::Msg(format!(
                "{} is not a VHD/VHDX virtual disk",
                path.display()
            )));
        }
        let file = File::open(path)?;
        Self::from_reader(file, path.to_path_buf())
    }

    /// Open a VHD/VHDX from any `Read + Seek` without `/tmp`.
    ///
    /// The container is **not** copied into a second buffer. Guest reads go
    /// through the BAT / fixed map onto the same stream (mutex-shared by the
    /// inner FAT/EXT4/block mount).
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_label = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_vhd_or_vhdx_reader(&mut reader) {
            return Err(VhdError::Msg(format!(
                "{} is not a VHD/VHDX virtual disk",
                archive_label.display()
            )));
        }
        reader.seek(SeekFrom::Start(0))?;
        Self::from_reader(reader, archive_label)
    }

    pub fn kind(&self) -> VhdKind {
        self.kind
    }

    pub fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    fn from_reader<R>(mut reader: R, archive_label: PathBuf) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        reader.seek(SeekFrom::Start(0))?;
        let (disk, kind) = if vhdx_magic(&mut reader) {
            reader.seek(SeekFrom::Start(0))?;
            open_vhdx(reader)?
        } else {
            reader.seek(SeekFrom::Start(0))?;
            open_vhd(reader)?
        };
        let virtual_size = disk.virt_size();
        let inner = mount_virtual_disk(disk, &archive_label)?;
        Ok(Self {
            inner,
            kind,
            virtual_size,
        })
    }
}

fn mount_virtual_disk(mut disk: VirtualDisk, label: &Path) -> Result<Box<dyn MountSource>> {
    disk.seek(SeekFrom::Start(0))?;
    if looks_like_block_reader(&mut disk) {
        disk.seek(SeekFrom::Start(0))?;
        return BlockMountSource::open_from_reader(disk, label)
            .map(|m| Box::new(m) as Box<dyn MountSource>)
            .map_err(|e| VhdError::Msg(e.to_string()));
    }
    disk.seek(SeekFrom::Start(0))?;
    if looks_like_fat_reader_at(&mut disk, 0) {
        disk.seek(SeekFrom::Start(0))?;
        return FatMountSource::open_from_reader(disk, label)
            .map(|m| Box::new(m) as Box<dyn MountSource>)
            .map_err(|e| VhdError::Msg(e.to_string()));
    }
    disk.seek(SeekFrom::Start(0))?;
    if looks_like_ext4_reader_at(&mut disk, 0) {
        disk.seek(SeekFrom::Start(0))?;
        return Ext4MountSource::open_from_reader(disk, label)
            .map(|m| Box::new(m) as Box<dyn MountSource>)
            .map_err(|e| VhdError::Msg(e.to_string()));
    }
    Err(VhdError::Msg(format!(
        "no GPT/MBR, FAT, or EXT4 filesystem in virtual disk {} ({} bytes). \
         Differencing VHD/VHDX and encrypted images are residual",
        label.display(),
        disk.virt_size()
    )))
}

/// Footer cookie `conectix` at EOF (fixed) or offset 0 (dynamic copy).
pub fn looks_like_vhd(path: &Path) -> bool {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    vhd_magic(&mut f)
}

/// File identifier `vhdxfile` at offset 0.
pub fn looks_like_vhdx(path: &Path) -> bool {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    vhdx_magic(&mut f)
}

pub fn looks_like_vhd_reader<R: Read + Seek>(reader: &mut R) -> bool {
    vhd_magic(reader)
}

pub fn looks_like_vhdx_reader<R: Read + Seek>(reader: &mut R) -> bool {
    vhdx_magic(reader)
}

/// Stream probe (VHDX start magic, else VHD footer). Leaves the reader unspecified.
pub fn looks_like_vhd_or_vhdx_reader<R: Read + Seek>(reader: &mut R) -> bool {
    vhdx_magic(reader) || vhd_magic(reader)
}

impl MountSource for VhdMountSource {
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
    use std::process::Command;

    use fatfs::{FileSystem, FsOptions};

    use crate::disk::vhd_bitmap_size;
    use crate::vhd::{
        encode_dynamic_header, encode_footer, DISK_TYPE_DIFFERENCING, DISK_TYPE_DYNAMIC,
        DISK_TYPE_FIXED,
    };
    use crate::vhdx::encode_fixed_vhdx;

    const FAT_BYTES: usize = 256 * 1024;
    const VHD_BLOCK: u32 = 2 * 1024 * 1024;

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

    fn pad_to_sector(mut img: Vec<u8>) -> Vec<u8> {
        let rem = img.len() % 512;
        if rem != 0 {
            img.resize(img.len() + (512 - rem), 0);
        }
        img
    }

    fn wrap_fixed_vhd(disk: &[u8]) -> Vec<u8> {
        let disk = pad_to_sector(disk.to_vec());
        let mut out = disk.clone();
        out.extend_from_slice(&encode_footer(disk.len() as u64, DISK_TYPE_FIXED, u64::MAX));
        out
    }

    /// Dynamic VHD: one 2 MiB block holding `disk` at guest offset 0; extra
    /// unallocated block so hole reads are testable.
    fn wrap_dynamic_vhd(disk: &[u8]) -> Vec<u8> {
        let disk = pad_to_sector(disk.to_vec());
        let block = u64::from(VHD_BLOCK);
        let virt = block * 2;
        let bitmap = vhd_bitmap_size(block);
        let footer = encode_footer(virt, DISK_TYPE_DYNAMIC, 512);
        let header = encode_dynamic_header(1536, 2, VHD_BLOCK);
        // BAT at 1536 (3 sectors). Block 0 at sector 4 (offset 2048).
        let block0_off = 2048u64;
        let bat_entry0 = (block0_off / 512) as u32;
        let mut bat = vec![0u8; 512];
        bat[0..4].copy_from_slice(&bat_entry0.to_be_bytes());
        bat[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        let data_end = block0_off + bitmap + block;
        let mut out = vec![0u8; data_end as usize + 512];
        out[0..512].copy_from_slice(&footer);
        out[512..1536].copy_from_slice(&header);
        out[1536..2048].copy_from_slice(&bat);
        let payload = (block0_off + bitmap) as usize;
        out[payload..payload + disk.len()].copy_from_slice(&disk);
        let end = out.len() - 512;
        out[end..].copy_from_slice(&footer);
        out
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

    /// Regression: random / FAT / TAR bytes are not a VHD.
    #[test]
    fn looks_like_vhd_false_on_fat_and_random() {
        let fat = fat_volume("hello.txt", b"nope");
        assert!(!looks_like_vhd_reader(&mut Cursor::new(&fat)));
        assert!(!looks_like_vhdx_reader(&mut Cursor::new(&fat)));
        assert!(!looks_like_vhd_or_vhdx_reader(&mut Cursor::new(
            b"not-a-disk"
        )));
        assert!(!looks_like_vhd_reader(&mut Cursor::new(b"conecti")));
    }

    /// Regression: fixed VHD fixture (MBR+FAT) always lists `p1/` and reads the file.
    #[test]
    fn fixed_vhd_mbr_fat_p1_listing_and_read() {
        let payload = b"hello-fixed-vhd";
        let vhd = wrap_fixed_vhd(&mbr_wrap(&fat_volume("hello.txt", payload), 8));
        assert!(looks_like_vhd_reader(&mut Cursor::new(&vhd)));
        assert!(!looks_like_vhdx_reader(&mut Cursor::new(&vhd)));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.vhd");
        std::fs::write(&path, &vhd).unwrap();
        assert!(looks_like_vhd(&path));

        let m = VhdMountSource::open(&path).expect("open fixed VHD");
        assert_eq!(m.kind(), VhdKind::FixedVhd);
        let root = m.list_dirents("/").expect("list /");
        find_name(&root, "p1");
        let dents = m.list_dirents("/p1").expect("p1");
        let d = find_name(&dents, "hello.txt");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.size, payload.len() as u64);
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: nested no-tmp `open_from_reader` on a fixed VHD (Cursor, no /tmp).
    #[test]
    fn fixed_vhd_open_from_reader_no_tmp() {
        let payload = b"nested-fixed-vhd";
        let vhd = wrap_fixed_vhd(&mbr_wrap(&fat_volume("hello.txt", payload), 8));
        let m = VhdMountSource::open_from_reader(Cursor::new(vhd), "nested.vhd")
            .expect("open_from_reader");
        assert_eq!(m.kind(), VhdKind::FixedVhd);
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got.as_bytes(), payload);
    }

    /// Regression: dynamic VHD BAT maps guest offset 0 through an allocated
    /// block (MBR+FAT `p1/`) and unallocated blocks read as zeros.
    #[test]
    fn dynamic_vhd_bat_maps_virtual_offset() {
        let payload = b"hello-dynamic-vhd";
        let vhd = wrap_dynamic_vhd(&mbr_wrap(&fat_volume("hello.txt", payload), 8));
        assert!(looks_like_vhd_reader(&mut Cursor::new(&vhd)));

        let m = VhdMountSource::open_from_reader(Cursor::new(vhd.clone()), "dyn.vhd")
            .expect("open dynamic VHD");
        assert_eq!(m.kind(), VhdKind::DynamicVhd);
        assert_eq!(m.virtual_size(), u64::from(VHD_BLOCK) * 2);
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);

        // Hole at the second 2 MiB block (unit: BAT unused → zeros).
        let (mut disk, kind) = open_vhd(Cursor::new(vhd)).expect("re-parse");
        assert_eq!(kind, VhdKind::DynamicVhd);
        disk.seek(SeekFrom::Start(u64::from(VHD_BLOCK))).unwrap();
        let mut hole = [0xFFu8; 16];
        disk.read_exact(&mut hole).unwrap();
        assert_eq!(hole, [0; 16]);
    }

    /// Regression: differencing VHD is rejected (parent chain residual).
    #[test]
    fn differencing_vhd_rejected() {
        let mut img = vec![0u8; 1024];
        let footer = encode_footer(512, DISK_TYPE_DIFFERENCING, u64::MAX);
        img[512..].copy_from_slice(&footer);
        let err = VhdMountSource::open_from_reader(Cursor::new(img), "diff.vhd")
            .err()
            .expect("differencing must fail");
        assert!(
            err.to_string().contains("differencing"),
            "unexpected: {err}"
        );
    }

    /// Regression: fixed VHDX fixture lists `p1/` through the BAT.
    #[test]
    fn fixed_vhdx_mbr_fat_p1_listing() {
        let payload = b"hello-fixed-vhdx";
        let disk = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let virt = 1024 * 1024u64;
        let vhdx = encode_fixed_vhdx(&disk, virt).expect("encode vhdx");
        assert!(looks_like_vhdx_reader(&mut Cursor::new(&vhdx)));
        assert!(!looks_like_vhd_reader(&mut Cursor::new(&vhdx)));

        let m = VhdMountSource::open_from_reader(Cursor::new(vhdx), "disk.vhdx")
            .expect("open fixed VHDX");
        assert_eq!(m.kind(), VhdKind::Vhdx);
        assert_eq!(m.virtual_size(), virt);
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: cheap readdirplus sizes under `p1/` of a fixed VHD.
    #[test]
    fn list_dirents_sizes_match_lookup() {
        let payload = b"hello-vhd-dirents";
        let vhd = wrap_fixed_vhd(&mbr_wrap(&fat_volume("hello.txt", payload), 8));
        let m = VhdMountSource::open_from_reader(Cursor::new(vhd), "dirents.vhd").unwrap();
        let dents = m.list_dirents("/p1").expect("p1 dirents");
        let d = find_name(&dents, "hello.txt");
        let fi = m.lookup("/p1/hello.txt", 0).unwrap();
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, payload.len() as u64);
    }

    /// Regression: superfloppy FAT inside a fixed VHD mounts at `/` (no `p1/`).
    #[test]
    fn fixed_vhd_superfloppy_fat_at_root() {
        let payload = b"superfloppy-vhd";
        let vhd = wrap_fixed_vhd(&fat_volume("hello.txt", payload));
        let m = VhdMountSource::open_from_reader(Cursor::new(vhd), "floppy.vhd").expect("open");
        assert!(m.lookup("/p1", 0).is_none());
        let fi = m.lookup("/hello.txt", 0).expect("root file");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = VhdMountSource::open_from_reader(Cursor::new(b"nope"), "bad.vhd")
            .err()
            .expect("non-vhd bytes must fail");
        assert!(
            err.to_string().contains("not a VHD/VHDX"),
            "unexpected: {err}"
        );
    }

    /// Regression: VHDX File Parameters HasParent is residual (not encoder-only).
    #[test]
    fn differencing_vhdx_rejected() {
        let disk = mbr_wrap(&fat_volume("hello.txt", b"x"), 8);
        let mut img = encode_fixed_vhdx(&disk, 1024 * 1024).expect("encode");
        // File Parameters flags sit at metadata region (1 MiB) + 64 KiB + 4.
        let fp_flags = 1024 * 1024 + 64 * 1024 + 4;
        img[fp_flags..fp_flags + 4].copy_from_slice(&2u32.to_le_bytes());
        let err = VhdMountSource::open_from_reader(Cursor::new(img), "diff.vhdx")
            .err()
            .expect("HasParent must fail");
        assert!(
            err.to_string().contains("differencing"),
            "unexpected: {err}"
        );
    }

    fn qemu_img_bin() -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join("qemu-img"))
                .find(|p| p.is_file())
        })
    }

    fn qemu_convert_open(fmt: &str, extra: &[&str], payload: &[u8]) {
        let Some(qemu) = qemu_img_bin() else {
            eprintln!("skip: qemu-img not available");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("disk.img");
        let out = dir.path().join(format!("disk.{fmt}"));
        let mut img = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        img.resize(1024 * 1024, 0);
        std::fs::write(&raw, &img).unwrap();
        let status = Command::new(&qemu)
            .args(["convert", "-f", "raw", "-O", fmt])
            .args(extra)
            .arg(&raw)
            .arg(&out)
            .status()
            .expect("spawn qemu-img");
        if !status.success() {
            eprintln!("skip: qemu-img convert -O {fmt} failed ({status})");
            return;
        }
        let m = match VhdMountSource::open(&out) {
            Ok(m) => m,
            Err(e) if e.to_string().contains("log replay") => {
                eprintln!("skip: qemu-img {fmt} LogGuid is non-zero ({e})");
                return;
            }
            Err(e) => panic!("qemu-img {fmt} must open with spec-layout parser: {e}"),
        };
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Optional: real Connectix VHD from qemu-img (skip if missing). Always-on
    /// spec-offset unit test is `parse_footer_spec_offsets_not_encoder_relative`.
    #[test]
    fn qemu_img_fixed_vhd_skip_if_missing() {
        qemu_convert_open("vpc", &["-o", "subformat=fixed"], b"qemu-fixed-vhd");
    }

    #[test]
    fn qemu_img_fixed_vhdx_skip_if_missing() {
        qemu_convert_open("vhdx", &["-o", "subformat=fixed"], b"qemu-fixed-vhdx");
    }
}
