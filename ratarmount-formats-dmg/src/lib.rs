//! UDIF DMG block reader (inner FAT/ISO/exFAT/NTFS; HFS+/APFS residual).
//!
//! Parses the 512-byte `koly` trailer, XML `blkx` / `mish` maps, and reconstructs
//! a `Read + Seek` inner disk from raw / ADC / zlib / bzip2 runs. When that disk
//! is FAT, ISO 9660, exFAT, NTFS, EXT4, or GPT/MBR, the matching crate's public
//! `open_from_reader` (or offset) API is used. **HFS+ and APFS are residual** —
//! there is no HFS crate; this backend does not claim those volumes.
//!
//! Nested members use [`DmgMountSource::open_from_reader`] (mutex-shared body,
//! no `NamedTempFile`). This crate does not edit session `factory.rs`.

mod adc;
mod disk;
mod udif;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::{
    CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
};
use ratarmount_formats_block::{looks_like_block_reader, BlockMountSource};
use ratarmount_formats_exfat::{looks_like_exfat_reader_at, ExfatMountSource};
use ratarmount_formats_ext4::{looks_like_ext4_reader_at, Ext4MountSource};
use ratarmount_formats_fat::{looks_like_fat_reader_at, FatMountSource};
use ratarmount_formats_iso9660::{looks_like_iso9660_reader, Iso9660MountSource};
use ratarmount_formats_ntfs::{looks_like_ntfs_reader_at, NtfsMountSource};
use thiserror::Error;

pub use disk::DmgDisk;
pub use udif::{parse_koly, ChunkKind, KolyTrailer, KOLY_SIZE, SECTOR_SIZE};

pub const BACKEND_NAME: &str = "DmgMountSource";

#[derive(Debug, Error)]
pub enum DmgError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, DmgError>;

trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

/// UDIF image whose inner disk opened as a supported filesystem.
pub struct DmgMountSource {
    inner: Arc<dyn MountSource>,
    koly: KolyTrailer,
    #[allow(dead_code)]
    archive_label: PathBuf,
}

impl DmgMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_dmg(path) {
            return Err(DmgError::Msg(format!(
                "{} is not a UDIF image (no koly trailer)",
                path.display()
            )));
        }
        let file = File::open(path)?;
        Self::from_reader(file, path.to_path_buf())
    }

    /// Open a UDIF image from any `Read + Seek` without `/tmp`.
    ///
    /// The reader is retained under a mutex for chunk I/O. Inner FAT/ISO/exFAT/
    /// NTFS/EXT4/GPT-MBR opens clone that view. Success never writes a host temp.
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_label = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_dmg_reader(&mut reader) {
            return Err(DmgError::Msg(format!(
                "{} is not a UDIF image (no koly trailer)",
                archive_label.display()
            )));
        }
        reader.seek(SeekFrom::Start(0))?;
        Self::from_reader(reader, archive_label)
    }

    pub fn koly(&self) -> &KolyTrailer {
        &self.koly
    }

    fn from_reader<R>(reader: R, archive_label: PathBuf) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let (disk, koly) = DmgDisk::open(reader)?;
        let inner = try_open_inner_fs(disk, &archive_label)?;
        Ok(Self {
            inner,
            koly,
            archive_label,
        })
    }
}

fn try_open_inner_fs(disk: DmgDisk, label: &Path) -> Result<Arc<dyn MountSource>> {
    {
        let mut probe = disk.clone();
        if looks_like_fat_reader_at(&mut probe, 0) {
            match FatMountSource::open_from_reader_with_offset(disk.clone(), label, 0) {
                Ok(m) => return Ok(Arc::new(m)),
                Err(e) => log::debug!("dmg: FAT open {} failed: {e}", label.display()),
            }
        }
    }
    {
        let mut probe = disk.clone();
        if looks_like_exfat_reader_at(&mut probe, 0) {
            match ExfatMountSource::open_from_reader_with_offset(disk.clone(), label, 0) {
                Ok(m) => return Ok(Arc::new(m)),
                Err(e) => log::debug!("dmg: exFAT open {} failed: {e}", label.display()),
            }
        }
    }
    {
        let mut probe = disk.clone();
        if looks_like_ntfs_reader_at(&mut probe, 0) {
            match NtfsMountSource::open_from_reader_with_offset(disk.clone(), label, 0) {
                Ok(m) => return Ok(Arc::new(m)),
                Err(e) => log::debug!("dmg: NTFS open {} failed: {e}", label.display()),
            }
        }
    }
    {
        let mut probe = disk.clone();
        if looks_like_ext4_reader_at(&mut probe, 0) {
            match Ext4MountSource::open_from_reader_with_offset(disk.clone(), label, 0) {
                Ok(m) => return Ok(Arc::new(m)),
                Err(e) => log::debug!("dmg: EXT4 open {} failed: {e}", label.display()),
            }
        }
    }
    {
        let mut probe = disk.clone();
        if looks_like_iso9660_reader(&mut probe) {
            let opts = OpenOptions {
                index_in_memory: true,
                write_index: false,
                ..OpenOptions::default()
            };
            match Iso9660MountSource::open_from_reader(
                disk.clone(),
                label,
                None,
                &opts,
                env!("CARGO_PKG_VERSION"),
            ) {
                Ok(m) => return Ok(Arc::new(m)),
                Err(e) => log::debug!("dmg: ISO open {} failed: {e}", label.display()),
            }
        }
    }
    {
        let mut probe = disk.clone();
        if looks_like_block_reader(&mut probe) {
            match BlockMountSource::open_from_reader(disk, label) {
                Ok(m) => return Ok(Arc::new(m)),
                Err(e) => log::debug!("dmg: GPT/MBR open {} failed: {e}", label.display()),
            }
        }
    }
    Err(DmgError::Msg(format!(
        "UDIF inner disk in {} has no supported filesystem (FAT/ISO/exFAT/NTFS/EXT4/GPT-MBR). \
         HFS+ and APFS volumes are residual; encrypted DMG is residual",
        label.display()
    )))
}

/// Detect UDIF via a parseable `koly` trailer at EOF. No `.dmg` extension fallback
/// (raw HFS+ files named `*.dmg` must not be claimed).
pub fn looks_like_dmg(path: &Path) -> bool {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    looks_like_dmg_reader(&mut f)
}

/// Stream probe (does not use filename). Leaves the reader at an unspecified position.
pub fn looks_like_dmg_reader<R: Read + Seek>(reader: &mut R) -> bool {
    udif::looks_like_udif_reader(reader)
}

impl MountSource for DmgMountSource {
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
    use flate2::write::ZlibEncoder;
    use flate2::Compression;

    use crate::adc::adc_decompress;
    use crate::udif::{
        encode_base64, parse_koly, CHUNK_ADC, CHUNK_BZIP2, CHUNK_RAW, CHUNK_TERM, CHUNK_ZERO,
        CHUNK_ZLIB,
    };

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

    fn mish_blob(chunks: &[(u32, u64, u64, u64, u64)]) -> Vec<u8> {
        let n = (chunks.len() + 1) as u32;
        let mut v = vec![0u8; 204 + n as usize * 40];
        v[0..4].copy_from_slice(b"mish");
        v[4..8].copy_from_slice(&1u32.to_be_bytes());
        let total_sectors: u64 = chunks.iter().map(|c| c.2).sum();
        v[16..24].copy_from_slice(&total_sectors.to_be_bytes());
        v[200..204].copy_from_slice(&n.to_be_bytes());
        for (i, &(ty, sec, sc, off, len)) in chunks.iter().enumerate() {
            let o = 204 + i * 40;
            v[o..o + 4].copy_from_slice(&ty.to_be_bytes());
            v[o + 8..o + 16].copy_from_slice(&sec.to_be_bytes());
            v[o + 16..o + 24].copy_from_slice(&sc.to_be_bytes());
            v[o + 24..o + 32].copy_from_slice(&off.to_be_bytes());
            v[o + 32..o + 40].copy_from_slice(&len.to_be_bytes());
        }
        let o = 204 + chunks.len() * 40;
        v[o..o + 4].copy_from_slice(&CHUNK_TERM.to_be_bytes());
        v[o + 8..o + 16].copy_from_slice(&total_sectors.to_be_bytes());
        v
    }

    fn koly_bytes(xml_off: u64, xml_len: u64, data_len: u64, sectors: u64) -> [u8; 512] {
        let mut k = [0u8; 512];
        k[0..4].copy_from_slice(b"koly");
        k[4..8].copy_from_slice(&4u32.to_be_bytes());
        k[8..12].copy_from_slice(&512u32.to_be_bytes());
        k[12..16].copy_from_slice(&1u32.to_be_bytes());
        k[32..40].copy_from_slice(&data_len.to_be_bytes());
        k[56..60].copy_from_slice(&1u32.to_be_bytes());
        k[60..64].copy_from_slice(&1u32.to_be_bytes());
        k[216..224].copy_from_slice(&xml_off.to_be_bytes());
        k[224..232].copy_from_slice(&xml_len.to_be_bytes());
        k[488..492].copy_from_slice(&1u32.to_be_bytes());
        k[492..500].copy_from_slice(&sectors.to_be_bytes());
        k
    }

    fn wrap_udif(data_fork: &[u8], chunks: &[(u32, u64, u64, u64, u64)], sectors: u64) -> Vec<u8> {
        let mish = mish_blob(chunks);
        let b64 = encode_base64(&mish);
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
<key>resource-fork</key>
<dict>
<key>blkx</key>
<array>
<dict>
<key>Name</key>
<string>disk</string>
<key>Data</key>
<data>
{b64}
</data>
</dict>
</array>
</dict>
</dict>
</plist>
"#
        );
        let xml_bytes = xml.into_bytes();
        let xml_off = data_fork.len() as u64;
        let mut out = Vec::with_capacity(data_fork.len() + xml_bytes.len() + 512);
        out.extend_from_slice(data_fork);
        out.extend_from_slice(&xml_bytes);
        out.extend_from_slice(&koly_bytes(
            xml_off,
            xml_bytes.len() as u64,
            data_fork.len() as u64,
            sectors,
        ));
        out
    }

    fn raw_udif(inner: &[u8]) -> Vec<u8> {
        let sectors = (inner.len() as u64).div_ceil(512);
        let mut padded = inner.to_vec();
        padded.resize((sectors * 512) as usize, 0);
        wrap_udif(
            &padded,
            &[(CHUNK_RAW, 0, sectors, 0, padded.len() as u64)],
            sectors,
        )
    }

    fn adc_encode_plain(src: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in src.chunks(128) {
            out.push(0x80 | (chunk.len() as u8 - 1));
            out.extend_from_slice(chunk);
        }
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

    /// Regression: synthetic koly trailer parses version / xml / sector count.
    #[test]
    fn koly_parse_always_on() {
        let mut buf = [0u8; 512];
        buf[0..4].copy_from_slice(b"koly");
        buf[4..8].copy_from_slice(&4u32.to_be_bytes());
        buf[8..12].copy_from_slice(&512u32.to_be_bytes());
        buf[216..224].copy_from_slice(&100u64.to_be_bytes());
        buf[224..232].copy_from_slice(&50u64.to_be_bytes());
        buf[492..500].copy_from_slice(&8u64.to_be_bytes());
        let k = parse_koly(&buf).expect("koly");
        assert_eq!(k.xml_offset, 100);
        assert_eq!(k.xml_length, 50);
        assert_eq!(k.sector_count, 8);
        let mut bytes = vec![0u8; 100];
        bytes.extend_from_slice(&buf);
        assert!(looks_like_dmg_reader(&mut Cursor::new(bytes)));
    }

    #[test]
    fn looks_like_dmg_false_on_fat_iso_random() {
        let fat = fat_volume("x.txt", b"nope");
        assert!(!looks_like_dmg_reader(&mut Cursor::new(&fat)));
        assert!(!looks_like_dmg_reader(&mut Cursor::new(b"not-a-dmg")));
        let mut isoish = vec![0u8; 0x8010];
        isoish[0x8001..0x8006].copy_from_slice(b"CD001");
        assert!(!looks_like_dmg_reader(&mut Cursor::new(&isoish)));
        let err = DmgMountSource::open_from_reader(Cursor::new(b"nope"), "bad.dmg")
            .err()
            .expect("non-UDIF must fail");
        assert!(err.to_string().contains("koly"), "unexpected: {err}");
    }

    /// Regression: raw UDIF chunk round-trips inner disk bytes (no FS).
    #[test]
    fn dmg_disk_raw_chunk_roundtrip() {
        let inner = b"hello-udif-raw-disk".to_vec();
        let dmg = raw_udif(&inner);
        assert!(looks_like_dmg_reader(&mut Cursor::new(&dmg)));
        let (mut disk, koly) = DmgDisk::open(Cursor::new(dmg)).expect("open disk");
        assert!(koly.sector_count >= 1);
        let mut got = vec![0u8; inner.len()];
        disk.read_exact(&mut got).unwrap();
        assert_eq!(got, inner);
        disk.seek(SeekFrom::Start(6)).unwrap();
        let mut mid = [0u8; 4];
        disk.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, b"udif");
    }

    /// Regression: zlib (UDZO) chunk reconstructs inner bytes.
    #[test]
    fn dmg_disk_zlib_chunk() {
        let inner = {
            let mut v = b"zlib-payload-".to_vec();
            v.extend_from_slice(&[b'Z'; 4000]);
            v
        };
        let sectors = (inner.len() as u64).div_ceil(512);
        let mut padded = inner.clone();
        padded.resize((sectors * 512) as usize, 0);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(&padded).unwrap();
        let packed = enc.finish().unwrap();
        let dmg = wrap_udif(
            &packed,
            &[(CHUNK_ZLIB, 0, sectors, 0, packed.len() as u64)],
            sectors,
        );
        let (mut disk, _) = DmgDisk::open(Cursor::new(dmg)).unwrap();
        let mut got = vec![0u8; inner.len()];
        disk.read_exact(&mut got).unwrap();
        assert_eq!(got, inner);
    }

    /// Regression: bzip2 chunk reconstructs inner bytes.
    #[test]
    fn dmg_disk_bzip2_chunk() {
        let inner = b"bzip2-udif-payload".to_vec();
        let sectors = (inner.len() as u64).div_ceil(512);
        let mut padded = inner.clone();
        padded.resize((sectors * 512) as usize, 0);
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        enc.write_all(&padded).unwrap();
        let packed = enc.finish().unwrap();
        let dmg = wrap_udif(
            &packed,
            &[(CHUNK_BZIP2, 0, sectors, 0, packed.len() as u64)],
            sectors,
        );
        let (mut disk, _) = DmgDisk::open(Cursor::new(dmg)).unwrap();
        let mut got = vec![0u8; inner.len()];
        disk.read_exact(&mut got).unwrap();
        assert_eq!(got, inner);
    }

    /// Regression: ADC chunk reconstructs inner bytes.
    #[test]
    fn dmg_disk_adc_chunk() {
        let inner = b"adc-udif-plain-lits".to_vec();
        let sectors = (inner.len() as u64).div_ceil(512);
        let mut padded = inner.clone();
        padded.resize((sectors * 512) as usize, 0);
        let packed = adc_encode_plain(&padded);
        let dmg = wrap_udif(
            &packed,
            &[(CHUNK_ADC, 0, sectors, 0, packed.len() as u64)],
            sectors,
        );
        let (mut disk, _) = DmgDisk::open(Cursor::new(dmg)).unwrap();
        let mut got = vec![0u8; inner.len()];
        disk.read_exact(&mut got).unwrap();
        assert_eq!(got, inner);
        let mut round = vec![0u8; padded.len()];
        assert_eq!(adc_decompress(&packed, &mut round).unwrap(), padded.len());
        assert_eq!(round, padded);
    }

    /// Regression: ZERO run reads as zeros; raw run still serves payload.
    #[test]
    fn dmg_disk_zero_then_raw() {
        let raw = vec![0xABu8; 512];
        let dmg = wrap_udif(
            &raw,
            &[(CHUNK_ZERO, 0, 1, 0, 0), (CHUNK_RAW, 1, 1, 0, 512)],
            2,
        );
        let (mut disk, _) = DmgDisk::open(Cursor::new(dmg)).unwrap();
        let mut head = [0u8; 512];
        disk.read_exact(&mut head).unwrap();
        assert!(head.iter().all(|&b| b == 0));
        let mut tail = [0u8; 512];
        disk.read_exact(&mut tail).unwrap();
        assert_eq!(tail, [0xAB; 512]);
    }

    /// Regression: inner FAT superfloppy lists and reads through UDIF (no /tmp).
    #[test]
    fn fat_superfloppy_inside_raw_udif() {
        let payload = b"hello-dmg-fat";
        let fat = fat_volume("hello.txt", payload);
        let dmg = raw_udif(&fat);
        let m = DmgMountSource::open_from_reader(Cursor::new(dmg), "fat.dmg")
            .expect("open FAT-in-UDIF");
        let dents = m.list_dirents("/").expect("root");
        let d = find_name(&dents, "hello.txt");
        let fi = m.lookup("/hello.txt", 0).expect("lookup");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.size, payload.len() as u64);
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: path open matches reader open for inner FAT.
    #[test]
    fn fat_udif_path_open() {
        let payload = b"path-open-fat";
        let dmg = raw_udif(&fat_volume("hello.txt", payload));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.dmg");
        std::fs::write(&path, &dmg).unwrap();
        assert!(looks_like_dmg(&path));
        let m = DmgMountSource::open(&path).expect("path open");
        let fi = m.lookup("/hello.txt", 0).unwrap();
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: zlib-compressed FAT-in-UDIF still lists (UDZO-style).
    #[test]
    fn fat_inside_zlib_udif() {
        let payload = b"zlib-fat-hello";
        let fat = fat_volume("hello.txt", payload);
        let sectors = (fat.len() as u64).div_ceil(512);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(&fat).unwrap();
        let packed = enc.finish().unwrap();
        let dmg = wrap_udif(
            &packed,
            &[(CHUNK_ZLIB, 0, sectors, 0, packed.len() as u64)],
            sectors,
        );
        let m = DmgMountSource::open_from_reader(Cursor::new(dmg), "udzo.dmg").expect("udzo");
        let fi = m.lookup("/hello.txt", 0).unwrap();
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: partitioned MBR+FAT inner disk mounts as `p1/` via the block crate.
    #[test]
    fn mbr_fat_inside_udif_lists_p1() {
        let payload = b"part-in-dmg";
        let img = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let dmg = raw_udif(&img);
        let m = DmgMountSource::open_from_reader(Cursor::new(dmg), "part.dmg").expect("open");
        let root = m.list_dirents("/").expect("root");
        find_name(&root, "p1");
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1 file");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: cheap readdirplus sizes match lookup for inner FAT.
    #[test]
    fn list_dirents_sizes_match_lookup() {
        let payload = b"hello-dmg-dirents";
        let m = DmgMountSource::open_from_reader(
            Cursor::new(raw_udif(&fat_volume("hello.txt", payload))),
            "dirents.dmg",
        )
        .unwrap();
        let dents = m.list_dirents("/").expect("dirents");
        let d = find_name(&dents, "hello.txt");
        let fi = m.lookup("/hello.txt", 0).unwrap();
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, payload.len() as u64);
    }

    /// Regression: inner zeros / non-FS disk is HFS+/APFS residual (no HFS+ claim).
    #[test]
    fn inner_non_fs_is_hfs_residual() {
        let inner = vec![0u8; 64 * 1024];
        let err = DmgMountSource::open_from_reader(Cursor::new(raw_udif(&inner)), "hfs.dmg")
            .err()
            .expect("HFS-like zeros must not mount");
        let msg = err.to_string();
        assert!(
            msg.contains("HFS+") && msg.contains("residual"),
            "unexpected: {msg}"
        );
        assert!(
            !msg.to_ascii_lowercase().contains("via existing"),
            "must not claim HFS+ via existing path: {msg}"
        );
    }

    /// Regression: non-plist XML is encrypted residual.
    #[test]
    fn encrypted_xml_is_residual() {
        let data = vec![0u8; 512];
        let xml = b"not-a-plist-encrypted-blob";
        let mut dmg = data.clone();
        dmg.extend_from_slice(xml);
        dmg.extend_from_slice(&koly_bytes(
            data.len() as u64,
            xml.len() as u64,
            data.len() as u64,
            1,
        ));
        let err = DmgDisk::open(Cursor::new(dmg))
            .err()
            .expect("encrypted xml must fail");
        assert!(
            err.to_string().to_ascii_lowercase().contains("encrypted"),
            "unexpected: {err}"
        );
    }

    /// Regression: `encrdsa` header is encrypted residual.
    #[test]
    fn encrdsa_header_is_residual() {
        let mut dmg = b"encrdsa\0".to_vec();
        dmg.resize(1024, 0);
        let koly = koly_bytes(512, 10, 512, 1);
        dmg.splice(512..1024, koly);
        // koly at EOF: file is 1024 bytes, trailer is last 512.
        let err = DmgDisk::open(Cursor::new(dmg))
            .err()
            .expect("encrdsa must fail");
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("encrypted") || msg.contains("koly") || msg.contains("plist"),
            "unexpected: {err}"
        );
    }

    /// Skip: `hdiutil` is not on Linux CI; synthetic koly tests always run.
    #[test]
    fn hdiutil_convert_skipped_without_binary() {
        if Command::new("hdiutil")
            .arg("help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            // Real macOS images are almost always HFS+/APFS — residual here.
            eprintln!("skip: hdiutil present but HFS+/APFS inner volumes are residual");
            return;
        }
        eprintln!("skip: hdiutil not available");
    }
}
