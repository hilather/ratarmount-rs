//! QCOW2 virtual-disk mount source.
//!
//! Guest clusters are mapped in-process (QCOW2 v2/v3, uncompressed + zlib
//! deflate). The resulting raw virtual disk is handed to
//! [`BlockMountSource::open_from_reader`] so partitioned images appear as
//! `/p1/`… via FAT/EXT4 offset opens. Unpartitioned superfloppy FAT/EXT4
//! mounts at `/`.
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested QCOW2 members can be opened without `/tmp` when the outer archive
//! yields a seekable stream: [`Qcow2MountSource::open_from_reader`] validates
//! `QFI\xfb` + version 2/3, retains a mutex-shared image body, and maps guest
//! offsets through L1/L2. No `NamedTempFile` spool. Relative backing files
//! need a real parent directory ([`Qcow2MountSource::open`]); a virtual nested
//! label cannot resolve `backing_file`.
//!
//! # Residual
//!
//! zstd compressed clusters, HTTP/NBD/`json:` backing, AES/LUKS, external data
//! file, extended L2, qcow v1. Factory `FormatBackend::Qcow2` is a later
//! orchestrator PR (this crate does not edit `factory.rs`).
//!
//! [`BlockMountSource::open_from_reader`]: ratarmount_formats_block::BlockMountSource::open_from_reader

mod disk;

use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::{
    CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
};
use ratarmount_formats_block::{looks_like_block_reader, BlockMountSource};
use ratarmount_formats_ext4::{looks_like_ext4_reader, Ext4MountSource};
use ratarmount_formats_fat::{looks_like_fat_reader, FatMountSource};

pub use disk::{
    looks_like_qcow2, looks_like_qcow2_reader, parse_qcow2_header, Qcow2Compression, Qcow2Error,
    Qcow2Header, Qcow2VirtualDisk, Result, MAGIC,
};

pub const BACKEND_NAME: &str = "Qcow2MountSource";

/// QCOW2 image presented as a partitioned (`pN/`) or superfloppy filesystem tree.
pub struct Qcow2MountSource {
    inner: Arc<dyn MountSource>,
    header: Qcow2Header,
    /// Diagnostic label (path or nested member name).
    #[allow(dead_code)]
    archive_label: PathBuf,
}

impl Qcow2MountSource {
    /// Open a QCOW2 image from a host path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_qcow2(path) {
            return Err(Qcow2Error::Msg(format!(
                "{} is not a QCOW2 v2/v3 image",
                path.display()
            )));
        }
        let disk = Qcow2VirtualDisk::open_path(path)?;
        mount_virtual_disk(disk, path)
    }

    /// Open a QCOW2 image from any `Read + Seek` without `/tmp`.
    ///
    /// The image is **not** copied into a second buffer by this method. Relative
    /// backing files resolve against `archive_label.parent()` when that directory
    /// exists.
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_label = archive_label.as_ref();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_qcow2_reader(&mut reader) {
            return Err(Qcow2Error::Msg(format!(
                "{} is not a QCOW2 v2/v3 image",
                archive_label.display()
            )));
        }
        reader.seek(SeekFrom::Start(0))?;
        let backing_dir = archive_label.parent().filter(|p| !p.as_os_str().is_empty());
        let disk = Qcow2VirtualDisk::open_from_reader(reader, archive_label, backing_dir)?;
        mount_virtual_disk(disk, archive_label)
    }

    pub fn header(&self) -> &Qcow2Header {
        &self.header
    }
}

fn mount_virtual_disk(disk: Qcow2VirtualDisk, label: &Path) -> Result<Qcow2MountSource> {
    let header = disk.header().clone();
    let inner = open_guest_fs(disk, label)?;
    Ok(Qcow2MountSource {
        inner,
        header,
        archive_label: label.to_path_buf(),
    })
}

fn open_guest_fs(disk: Qcow2VirtualDisk, label: &Path) -> Result<Arc<dyn MountSource>> {
    {
        let mut probe = disk.clone();
        if looks_like_block_reader(&mut probe) {
            return BlockMountSource::open_from_reader(disk, label)
                .map(|m| Arc::new(m) as Arc<dyn MountSource>)
                .map_err(|e| Qcow2Error::Msg(e.to_string()));
        }
    }
    {
        let mut probe = disk.clone();
        if looks_like_fat_reader(&mut probe) {
            return FatMountSource::open_from_reader(disk, label)
                .map(|m| Arc::new(m) as Arc<dyn MountSource>)
                .map_err(|e| Qcow2Error::Msg(e.to_string()));
        }
    }
    {
        let mut probe = disk.clone();
        if looks_like_ext4_reader(&mut probe) {
            return Ext4MountSource::open_from_reader(disk, label)
                .map(|m| Arc::new(m) as Arc<dyn MountSource>)
                .map_err(|e| Qcow2Error::Msg(e.to_string()));
        }
    }
    Err(Qcow2Error::Msg(format!(
        "no supported filesystems in QCOW2 virtual disk {} \
         (need GPT/MBR + FAT/EXT4, or superfloppy FAT/EXT4). \
         zstd clusters and HTTP backing are residual",
        label.display()
    )))
}

impl MountSource for Qcow2MountSource {
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
    use std::path::PathBuf;
    use std::process::Command;

    use fatfs::{FileSystem, FsOptions};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;

    const FAT_BYTES: usize = 256 * 1024;
    const CLUSTER_BITS: u32 = 12;
    const QCOW_OFLAG_COPIED: u64 = 1 << 63;
    const QCOW_OFLAG_COMPRESSED: u64 = 1 << 62;
    const QCOW_OFLAG_ZERO: u64 = 1;

    /// Nested/HTTP-style reader: each `read` yields at most one byte.
    struct OneByteReader<R> {
        inner: R,
    }
    impl<R: Read> Read for OneByteReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.inner.read(&mut buf[..1])
        }
    }
    impl<R: Seek> Seek for OneByteReader<R> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

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

    /// Build a minimal QCOW2 v2 wrapping `guest` bytes (optional zlib clusters).
    fn build_qcow2(guest: &[u8], backing: Option<&str>, compress: bool) -> Vec<u8> {
        let cs = 1usize << CLUSTER_BITS;
        let virtual_size = guest.len() as u64;
        let n_clusters = guest.len().div_ceil(cs).max(1);
        let l2_entries = cs / 8;
        let n_l2 = n_clusters.div_ceil(l2_entries).max(1);
        let l1_off = cs as u64;
        let first_l2 = 2 * cs as u64;

        let mut l1 = vec![0u64; n_l2];
        let mut l2_tables = vec![vec![0u64; l2_entries]; n_l2];
        let mut host_blobs: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut cursor = first_l2 + (n_l2 as u64) * cs as u64;

        for i in 0..n_clusters {
            let start = i * cs;
            if start >= guest.len() {
                break;
            }
            let end = (start + cs).min(guest.len());
            let mut cluster = vec![0u8; cs];
            cluster[..end - start].copy_from_slice(&guest[start..end]);
            if cluster.iter().all(|&b| b == 0) {
                continue;
            }
            let l2i = i / l2_entries;
            let l2j = i % l2_entries;
            l1[l2i] = (first_l2 + (l2i as u64) * cs as u64) | QCOW_OFLAG_COPIED;
            if compress {
                let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
                enc.write_all(&cluster).expect("deflate");
                let packed = enc.finish().expect("deflate finish");
                cursor = (cursor + 511) & !511;
                let sectors = packed.len().div_ceil(512).max(1);
                let additional = (sectors - 1) as u64;
                let x = 62 - (CLUSTER_BITS - 8);
                let entry = cursor | (additional << x) | QCOW_OFLAG_COMPRESSED | QCOW_OFLAG_COPIED;
                l2_tables[l2i][l2j] = entry;
                let mut padded = packed;
                padded.resize(sectors * 512, 0);
                let n = padded.len() as u64;
                host_blobs.push((cursor, padded));
                cursor += n;
            } else {
                cursor = cursor.div_ceil(cs as u64) * cs as u64;
                l2_tables[l2i][l2j] = cursor | QCOW_OFLAG_COPIED;
                let n = cluster.len() as u64;
                host_blobs.push((cursor, cluster));
                cursor += n;
            }
        }

        let file_size = cursor
            .max(first_l2 + n_l2 as u64 * cs as u64)
            .max(cs as u64);
        let mut img = vec![0u8; file_size as usize];
        img[0..4].copy_from_slice(MAGIC);
        img[4..8].copy_from_slice(&2u32.to_be_bytes());
        if let Some(name) = backing {
            img[8..16].copy_from_slice(&72u64.to_be_bytes());
            img[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
            img[72..72 + name.len()].copy_from_slice(name.as_bytes());
        }
        img[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
        img[24..32].copy_from_slice(&virtual_size.to_be_bytes());
        img[36..40].copy_from_slice(&(n_l2 as u32).to_be_bytes());
        img[40..48].copy_from_slice(&l1_off.to_be_bytes());

        for (i, e) in l1.iter().enumerate() {
            let o = l1_off as usize + i * 8;
            img[o..o + 8].copy_from_slice(&e.to_be_bytes());
        }
        for (t, table) in l2_tables.iter().enumerate() {
            if l1[t] == 0 {
                continue;
            }
            let base = first_l2 as usize + t * cs;
            for (j, e) in table.iter().enumerate() {
                img[base + j * 8..base + j * 8 + 8].copy_from_slice(&e.to_be_bytes());
            }
        }
        for (off, blob) in host_blobs {
            img[off as usize..off as usize + blob.len()].copy_from_slice(&blob);
        }
        img
    }

    fn stamp_v3(img: &mut [u8]) {
        img[4..8].copy_from_slice(&3u32.to_be_bytes());
        img[100..104].copy_from_slice(&104u32.to_be_bytes());
    }

    /// QCOW2 v3 with `header_length` 104 wrapping the same guest as v2.
    fn build_qcow2_v3(guest: &[u8]) -> Vec<u8> {
        let mut img = build_qcow2(guest, None, false);
        stamp_v3(&mut img);
        img
    }

    /// One zlib cluster at an unaligned host offset; file ends at the last
    /// occupied 512-byte sector (QEMU `qcow2_alloc_bytes` layout).
    fn build_qcow2_unaligned_zlib(guest: &[u8]) -> Vec<u8> {
        let cs = 1usize << CLUSTER_BITS;
        assert_eq!(guest.len(), cs, "one guest cluster");
        let l1_off = cs as u64;
        let l2_off = 2 * cs as u64;
        let host_offset = 3 * cs as u64 + 100; // 100 bytes into a sector
        assert_ne!(host_offset & 511, 0);

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(guest).expect("deflate");
        let packed = enc.finish().expect("deflate finish");
        let last_byte = host_offset + packed.len() as u64 - 1;
        let last_sector_end = (last_byte & !511) + 512;
        let additional = (last_sector_end - (host_offset & !511)) / 512 - 1;
        let x = 62 - (CLUSTER_BITS - 8);
        let l2_entry = host_offset | (additional << x) | QCOW_OFLAG_COMPRESSED | QCOW_OFLAG_COPIED;

        let mut img = vec![0u8; last_sector_end as usize];
        img[0..4].copy_from_slice(MAGIC);
        img[4..8].copy_from_slice(&2u32.to_be_bytes());
        img[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
        img[24..32].copy_from_slice(&(guest.len() as u64).to_be_bytes());
        img[36..40].copy_from_slice(&1u32.to_be_bytes());
        img[40..48].copy_from_slice(&l1_off.to_be_bytes());
        img[l1_off as usize..l1_off as usize + 8]
            .copy_from_slice(&(l2_off | QCOW_OFLAG_COPIED).to_be_bytes());
        img[l2_off as usize..l2_off as usize + 8].copy_from_slice(&l2_entry.to_be_bytes());
        img[host_offset as usize..host_offset as usize + packed.len()].copy_from_slice(&packed);
        img
    }

    /// Overlay whose L2 entries are explicit `QCOW_OFLAG_ZERO` (must not read backing).
    fn build_qcow2_zero_clusters(guest_size: usize, backing: Option<&str>) -> Vec<u8> {
        let cs = 1usize << CLUSTER_BITS;
        let n_clusters = guest_size.div_ceil(cs).max(1);
        let l2_entries = cs / 8;
        let n_l2 = n_clusters.div_ceil(l2_entries).max(1);
        let l1_off = cs as u64;
        let first_l2 = 2 * cs as u64;
        let file_size = first_l2 + n_l2 as u64 * cs as u64;
        let mut img = vec![0u8; file_size as usize];
        img[0..4].copy_from_slice(MAGIC);
        img[4..8].copy_from_slice(&2u32.to_be_bytes());
        if let Some(name) = backing {
            img[8..16].copy_from_slice(&72u64.to_be_bytes());
            img[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
            img[72..72 + name.len()].copy_from_slice(name.as_bytes());
        }
        img[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
        img[24..32].copy_from_slice(&(guest_size as u64).to_be_bytes());
        img[36..40].copy_from_slice(&(n_l2 as u32).to_be_bytes());
        img[40..48].copy_from_slice(&l1_off.to_be_bytes());
        for i in 0..n_clusters {
            let l2i = i / l2_entries;
            let l2j = i % l2_entries;
            let l2_off = first_l2 + l2i as u64 * cs as u64;
            img[l1_off as usize + l2i * 8..l1_off as usize + l2i * 8 + 8]
                .copy_from_slice(&(l2_off | QCOW_OFLAG_COPIED).to_be_bytes());
            let e = QCOW_OFLAG_ZERO | QCOW_OFLAG_COPIED;
            let o = l2_off as usize + l2j * 8;
            img[o..o + 8].copy_from_slice(&e.to_be_bytes());
        }
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

    fn qemu_img_bin() -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join("qemu-img"))
                .find(|p| p.is_file())
        })
    }

    /// Regression: synthetic QCOW2 v2 header is detected; random/TAR bytes are not.
    #[test]
    fn looks_like_qcow2_synthetic_header() {
        let hdr = disk::write_qcow2_v2_header(16, 1 << 20, 1, 65536, None);
        assert!(looks_like_qcow2_reader(&mut Cursor::new(&hdr)));
        let parsed = parse_qcow2_header(&mut Cursor::new(&hdr)).expect("parse header");
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.cluster_bits, 16);
        assert_eq!(parsed.size, 1 << 20);
        assert_eq!(parsed.compression, Qcow2Compression::Zlib);
        assert!(!looks_like_qcow2_reader(&mut Cursor::new(b"not-qcow2")));
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        assert!(!looks_like_qcow2_reader(&mut Cursor::new(&tar)));
    }

    /// Regression: QCOW2 v3 header_length + features parse.
    #[test]
    fn looks_like_qcow2_v3_header() {
        let mut hdr = vec![0u8; 104];
        hdr[0..4].copy_from_slice(MAGIC);
        hdr[4..8].copy_from_slice(&3u32.to_be_bytes());
        hdr[20..24].copy_from_slice(&16u32.to_be_bytes());
        hdr[24..32].copy_from_slice(&(1u64 << 20).to_be_bytes());
        hdr[36..40].copy_from_slice(&1u32.to_be_bytes());
        hdr[40..48].copy_from_slice(&65536u64.to_be_bytes());
        hdr[100..104].copy_from_slice(&104u32.to_be_bytes());
        assert!(looks_like_qcow2_reader(&mut Cursor::new(&hdr)));
        let parsed = parse_qcow2_header(&mut Cursor::new(&hdr)).expect("v3 parse");
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.size, 1 << 20);
    }

    /// Regression: HTTP backing is rejected (local path only).
    #[test]
    fn backing_http_is_residual() {
        let hdr = disk::write_qcow2_v2_header(
            16,
            1 << 20,
            1,
            65536,
            Some("https://example.com/base.qcow2"),
        );
        let err =
            Qcow2VirtualDisk::open_from_reader(Cursor::new(hdr), Path::new("http.qcow2"), None)
                .err()
                .expect("HTTP backing must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("HTTP") || msg.contains("residual") || msg.contains("not a local"),
            "unexpected: {msg}"
        );
    }

    /// Regression: encrypted crypt_method is rejected.
    #[test]
    fn encrypted_qcow2_rejected() {
        let mut hdr = disk::write_qcow2_v2_header(16, 1 << 20, 1, 65536, None);
        hdr[32..36].copy_from_slice(&1u32.to_be_bytes());
        let err =
            Qcow2VirtualDisk::open_from_reader(Cursor::new(hdr), Path::new("enc.qcow2"), None)
                .err()
                .expect("encrypted must fail");
        assert!(
            err.to_string().contains("encrypted") || err.to_string().contains("crypt"),
            "unexpected: {err}"
        );
    }

    /// Regression: synthetic QCOW2 + MBR + FAT lists `p1/` and reads the file.
    #[test]
    fn qcow2_mbr_fat_p1_listing_and_read() {
        let payload = b"hello-qcow2-fat";
        let guest = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let img = build_qcow2(&guest, None, false);
        assert!(looks_like_qcow2_reader(&mut Cursor::new(&img)));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.qcow2");
        std::fs::write(&path, &img).unwrap();

        let m = Qcow2MountSource::open(&path).expect("open qcow2");
        assert_eq!(m.header().version, 2);
        let root = m.list_dirents("/").expect("list /");
        find_name(&root, "p1");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: nested no-tmp `open_from_reader` on QCOW2+MBR+FAT (Cursor, no /tmp).
    #[test]
    fn open_from_reader_no_tmp() {
        let payload = b"nested-qcow2-fat";
        let img = build_qcow2(&mbr_wrap(&fat_volume("hello.txt", payload), 8), None, false);
        let m = Qcow2MountSource::open_from_reader(Cursor::new(img), "nested.qcow2")
            .expect("open_from_reader");
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got.as_bytes(), payload);
    }

    /// Regression: short `Read::read` is not EOF; fill-loop still lists `p1/`.
    #[test]
    fn open_from_reader_one_byte_reads() {
        let payload = b"one-byte-qcow2";
        let img = build_qcow2(&mbr_wrap(&fat_volume("hello.txt", payload), 8), None, false);
        let r = OneByteReader {
            inner: Cursor::new(img),
        };
        let m = Qcow2MountSource::open_from_reader(r, "onebyte.qcow2")
            .expect("open_from_reader one-byte");
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: always-on synthetic v3 (header_length 104) MBR+FAT lists `p1/`.
    #[test]
    fn qcow2_v3_mbr_fat_p1_listing_and_read() {
        let payload = b"hello-qcow2-v3";
        let img = build_qcow2_v3(&mbr_wrap(&fat_volume("hello.txt", payload), 8));
        assert!(looks_like_qcow2_reader(&mut Cursor::new(&img)));
        let m = Qcow2MountSource::open_from_reader(Cursor::new(img), "v3.qcow2").expect("open v3");
        assert_eq!(m.header().version, 3);
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: zlib (raw deflate) compressed clusters round-trip.
    #[test]
    fn zlib_compressed_clusters_read() {
        let payload = b"hello-zlib-qcow2";
        let img = build_qcow2(&mbr_wrap(&fat_volume("hello.txt", payload), 8), None, true);
        let m = Qcow2MountSource::open_from_reader(Cursor::new(img), "zlib.qcow2")
            .expect("open compressed");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: unaligned zlib host offset; file ends at last occupied sector.
    #[test]
    fn zlib_compressed_unaligned_host_offset() {
        let guest = vec![b'Q'; 1 << CLUSTER_BITS];
        let img = build_qcow2_unaligned_zlib(&guest);
        assert_eq!(img.len() % 512, 0, "file ends on a sector boundary");
        let mut disk = Qcow2VirtualDisk::open_from_reader(
            Cursor::new(img),
            Path::new("unaligned.qcow2"),
            None,
        )
        .expect("open unaligned zlib");
        let mut got = vec![0u8; guest.len()];
        disk.read_exact(&mut got).expect("read_guest unaligned");
        assert_eq!(got, guest);
    }

    /// Regression: v3 zstd `compression_type` fails at open, not as "no filesystem".
    #[test]
    fn zstd_rejected_at_open() {
        let mut hdr = vec![0u8; 112];
        hdr[0..4].copy_from_slice(MAGIC);
        hdr[4..8].copy_from_slice(&3u32.to_be_bytes());
        hdr[20..24].copy_from_slice(&16u32.to_be_bytes());
        hdr[24..32].copy_from_slice(&(1u64 << 20).to_be_bytes());
        hdr[36..40].copy_from_slice(&1u32.to_be_bytes());
        hdr[40..48].copy_from_slice(&65536u64.to_be_bytes());
        hdr[72..80].copy_from_slice(&(1u64 << 3).to_be_bytes()); // INCOMPAT_COMPRESSION_TYPE
        hdr[100..104].copy_from_slice(&108u32.to_be_bytes());
        hdr[104..108].copy_from_slice(&1u32.to_be_bytes()); // zstd
        let err =
            Qcow2VirtualDisk::open_from_reader(Cursor::new(hdr), Path::new("zstd.qcow2"), None)
                .err()
                .expect("zstd must fail at open");
        let msg = err.to_string();
        assert!(
            msg.to_ascii_lowercase().contains("zstd"),
            "unexpected: {msg}"
        );
    }

    /// Regression: superfloppy FAT at guest offset 0 mounts at `/` (not `p1/`).
    #[test]
    fn superfloppy_fat_at_root() {
        let payload = b"superfloppy-qcow2";
        let img = build_qcow2(&fat_volume("hello.txt", payload), None, false);
        let m = Qcow2MountSource::open_from_reader(Cursor::new(img), "sf.qcow2").expect("open");
        assert!(m.lookup("/p1", 0).is_none());
        let fi = m.lookup("/hello.txt", 0).expect("root file");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: unallocated overlay past backing EOF reads as zeros (not
    /// leftover dest bytes).
    #[test]
    fn unallocated_past_backing_is_zero() {
        let base_guest = vec![0xAAu8; 4096];
        let base_img = build_qcow2(&base_guest, None, false);
        let overlay = build_qcow2(&vec![0u8; 8192], Some("base.qcow2"), false);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("base.qcow2"), &base_img).unwrap();
        let overlay_path = dir.path().join("overlay.qcow2");
        std::fs::write(&overlay_path, &overlay).unwrap();

        let mut disk = Qcow2VirtualDisk::open_path(&overlay_path).expect("open overlay");
        let mut buf = vec![0xFFu8; 8192];
        disk.read_exact(&mut buf).expect("read 8k");
        assert!(buf[..4096].iter().all(|&b| b == 0xAA), "backing payload");
        assert!(
            buf[4096..].iter().all(|&b| b == 0),
            "bytes past backing must be zero, got {:x?}",
            &buf[4096..4112]
        );
    }

    /// Regression: `QCOW_OFLAG_ZERO` must not fall through to backing bytes.
    #[test]
    fn zero_flag_cluster_ignores_backing() {
        let base_guest = vec![0xAAu8; 4096];
        let base_img = build_qcow2(&base_guest, None, false);
        let overlay = build_qcow2_zero_clusters(4096, Some("base.qcow2"));

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("base.qcow2"), &base_img).unwrap();
        let overlay_path = dir.path().join("overlay.qcow2");
        std::fs::write(&overlay_path, &overlay).unwrap();

        let mut disk = Qcow2VirtualDisk::open_path(&overlay_path).expect("open zero overlay");
        let mut buf = vec![0xFFu8; 4096];
        disk.read_exact(&mut buf).expect("read zero cluster");
        assert!(
            buf.iter().all(|&b| b == 0),
            "ZERO cluster must be zeros, not backing 0xAA"
        );
    }

    /// Regression: qcow v1 backing is residual (not raw guest bytes).
    #[test]
    fn qcow_v1_backing_is_residual() {
        let mut v1 = vec![0u8; 512];
        v1[0..4].copy_from_slice(MAGIC);
        v1[4..8].copy_from_slice(&1u32.to_be_bytes());
        let overlay = build_qcow2(&vec![0u8; 4096], Some("base.qcow2"), false);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("base.qcow2"), &v1).unwrap();
        let overlay_path = dir.path().join("overlay.qcow2");
        std::fs::write(&overlay_path, &overlay).unwrap();

        let err = Qcow2VirtualDisk::open_path(&overlay_path)
            .err()
            .expect("v1 backing must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("v1") || msg.contains("version 1"),
            "unexpected: {msg}"
        );
    }

    /// Regression: local backing file supplies unallocated overlay clusters.
    #[test]
    fn local_backing_file_reads_base() {
        let payload = b"from-backing";
        let base_guest = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let base_img = build_qcow2(&base_guest, None, false);
        let overlay = build_qcow2(&vec![0u8; base_guest.len()], Some("base.qcow2"), false);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("base.qcow2"), &base_img).unwrap();
        let overlay_path = dir.path().join("overlay.qcow2");
        std::fs::write(&overlay_path, &overlay).unwrap();

        let m = Qcow2MountSource::open(&overlay_path).expect("open overlay");
        let fi = m.lookup("/p1/hello.txt", 0).expect("backing file");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: cheap readdirplus sizes under `p1/`.
    #[test]
    fn list_dirents_sizes_match_lookup() {
        let payload = b"hello-qcow2-dirents";
        let img = build_qcow2(&mbr_wrap(&fat_volume("hello.txt", payload), 8), None, false);
        let m = Qcow2MountSource::open_from_reader(Cursor::new(img), "dirents.qcow2").unwrap();
        let dents = m.list_dirents("/p1").expect("p1 dirents");
        let d = find_name(&dents, "hello.txt");
        let fi = m.lookup("/p1/hello.txt", 0).unwrap();
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, payload.len() as u64);
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = Qcow2MountSource::open_from_reader(Cursor::new(b"nope"), "bad.qcow2")
            .err()
            .expect("non-qcow2 bytes must fail");
        assert!(err.to_string().contains("not a QCOW2"), "unexpected: {err}");
    }

    /// Regression: `qemu-img create` produces a header we detect (skip if missing).
    #[test]
    fn qemu_img_create_looks_like() {
        let Some(qemu) = qemu_img_bin() else {
            eprintln!("skip: qemu-img not available");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("empty.qcow2");
        let status = Command::new(&qemu)
            .args(["create", "-f", "qcow2"])
            .arg(&img)
            .arg("1M")
            .status()
            .expect("run qemu-img create");
        if !status.success() {
            eprintln!("skip: qemu-img create failed");
            return;
        }
        assert!(looks_like_qcow2(&img));
        let parsed = parse_qcow2_header(&mut std::fs::File::open(&img).unwrap()).expect("parse");
        assert!(parsed.version == 2 || parsed.version == 3);
        assert_eq!(parsed.size, 1024 * 1024);
        let err = Qcow2MountSource::open(&img)
            .err()
            .expect("empty qcow2 has no filesystem");
        assert!(
            err.to_string().contains("no supported") || err.to_string().contains("not a QCOW2"),
            "unexpected: {err}"
        );
    }

    /// Regression: `qemu-img convert` of MBR+FAT still lists `p1/` (skip if missing).
    #[test]
    fn qemu_img_convert_mbr_fat() {
        let Some(qemu) = qemu_img_bin() else {
            eprintln!("skip: qemu-img not available");
            return;
        };
        let payload = b"qemu-img-qcow2";
        let raw = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let dir = tempfile::tempdir().unwrap();
        let raw_path = dir.path().join("disk.img");
        let qcow = dir.path().join("disk.qcow2");
        std::fs::write(&raw_path, &raw).unwrap();
        let status = Command::new(&qemu)
            .args(["convert", "-f", "raw", "-O", "qcow2"])
            .arg(&raw_path)
            .arg(&qcow)
            .status()
            .expect("run qemu-img convert");
        if !status.success() {
            eprintln!("skip: qemu-img convert failed");
            return;
        }
        let m = Qcow2MountSource::open(&qcow).expect("open qemu-img qcow2");
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: `qemu-img convert -c` zlib clusters (skip if missing).
    #[test]
    fn qemu_img_convert_compressed() {
        let Some(qemu) = qemu_img_bin() else {
            eprintln!("skip: qemu-img not available");
            return;
        };
        let payload = b"qemu-img-zlib";
        let raw = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let dir = tempfile::tempdir().unwrap();
        let raw_path = dir.path().join("disk.img");
        let qcow = dir.path().join("disk.qcow2");
        std::fs::write(&raw_path, &raw).unwrap();
        let status = Command::new(&qemu)
            .args(["convert", "-c", "-f", "raw", "-O", "qcow2"])
            .arg(&raw_path)
            .arg(&qcow)
            .status()
            .expect("run qemu-img convert -c");
        if !status.success() {
            eprintln!("skip: qemu-img convert -c failed");
            return;
        }
        let m = Qcow2MountSource::open(&qcow).expect("open compressed qemu-img");
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }
}
