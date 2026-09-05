//! VMDK virtual-disk mount source (hosted KDMV sparse).
//!
//! Parses a VMware disk descriptor and hosted sparse extents (`KDMV` magic),
//! presents a `Read + Seek` virtual disk, then wraps
//! [`BlockMountSource::open_from_reader`] so GPT/MBR partitions appear as
//! `/p1/`… (FAT/EXT4). Superfloppy FAT/EXT4 at virtual LBA 0 is mounted at `/`
//! (Block refuses offset-0 filesystems by design).
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested **monolithicSparse** members open from any `Read + Seek` stream via
//! [`VmdkMountSource::open_from_reader`]: grain translation stays on the shared
//! body. No `NamedTempFile` spool. Descriptor-only files that name **sibling**
//! extent files need a host path ([`VmdkMountSource::open`]).
//!
//! This crate does **not** edit session `factory.rs` or `formats-all`.
//!
//! # Residual
//!
//! Compressed grains (`streamOptimized` / `FLAG_COMPRESS`), ESXi COWD /
//! VMFSSPARSE / SESparse, delta disks (`parentCID` ≠ `ffffffff`), and
//! absolute / `..` extent filenames are rejected with a clear error.
//! Factory probe order is a later orchestrator PR.

mod descriptor;
mod sparse;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::{
    CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
};
use ratarmount_formats_block::{looks_like_block_reader, BlockMountSource};
use ratarmount_formats_ext4::{looks_like_ext4_reader, Ext4MountSource};
use ratarmount_formats_fat::{looks_like_fat_reader, FatMountSource};
use thiserror::Error;

pub use descriptor::{parse_vmdk_descriptor, DescriptorExtent, ExtentKind, VmdkDescriptor};
pub use sparse::{FLAG_COMPRESS, FLAG_MARKER, FLAG_ZERO_GRAIN, SECTOR, SPARSE_MAGIC};

pub const BACKEND_NAME: &str = "VmdkMountSource";

/// qemu-style cap for a **text** sidecar descriptor (not the KDMV file).
/// Embedded descriptors are capped separately in `read_embedded_descriptor`.
const MAX_SIDECAR_DESCRIPTOR_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum VmdkError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, VmdkError>;

/// Object-safe `Read + Seek + Send` for sparse/flat backends.
trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

/// Read-only VMDK wrapping a GPT/MBR (or superfloppy FAT/EXT4) mount.
pub struct VmdkMountSource {
    inner: Arc<dyn MountSource>,
    #[allow(dead_code)]
    archive_label: PathBuf,
}

impl VmdkMountSource {
    /// Open a hosted VMDK from a host path (KDMV file or text descriptor).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_vmdk(path) {
            return Err(VmdkError::Msg(format!(
                "{} is not a KDMV sparse VMDK or disk descriptor",
                path.display()
            )));
        }
        let disk = open_disk_from_path(path)?;
        wrap_virtual_disk(disk, path)
    }

    /// Open a **monolithicSparse** VMDK from any `Read + Seek` without `/tmp`.
    ///
    /// Descriptor-only streams that name sibling extent files are rejected
    /// (those need [`Self::open`]). The image is **not** copied into a second
    /// buffer by this method.
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_label = archive_label.as_ref().to_path_buf();
        let disk = open_disk_from_reader(reader, &archive_label)?;
        wrap_virtual_disk(disk, &archive_label)
    }
}

fn wrap_virtual_disk(disk: sparse::VmdkDisk, label: &Path) -> Result<VmdkMountSource> {
    let inner = mount_virtual_disk(disk, label)?;
    Ok(VmdkMountSource {
        inner,
        archive_label: label.to_path_buf(),
    })
}

fn mount_virtual_disk(disk: sparse::VmdkDisk, label: &Path) -> Result<Arc<dyn MountSource>> {
    if looks_like_block_reader(&mut disk.clone()) {
        return BlockMountSource::open_from_reader(disk, label)
            .map(|m| Arc::new(m) as Arc<dyn MountSource>)
            .map_err(|e| VmdkError::Msg(e.to_string()));
    }
    if looks_like_fat_reader(&mut disk.clone()) {
        return FatMountSource::open_from_reader(disk, label)
            .map(|m| Arc::new(m) as Arc<dyn MountSource>)
            .map_err(|e| VmdkError::Msg(e.to_string()));
    }
    if looks_like_ext4_reader(&mut disk.clone()) {
        return Ext4MountSource::open_from_reader(disk, label)
            .map(|m| Arc::new(m) as Arc<dyn MountSource>)
            .map_err(|e| VmdkError::Msg(e.to_string()));
    }
    Err(VmdkError::Msg(format!(
        "{} has no GPT/MBR partition table or FAT/EXT4 filesystem in the virtual disk \
         (LVM/RAID/Btrfs residual; factory wire later)",
        label.display()
    )))
}

fn open_disk_from_reader<R>(reader: R, label: &Path) -> Result<sparse::VmdkDisk>
where
    R: Read + Seek + Send + 'static,
{
    let mut reader = reader;
    reader.seek(SeekFrom::Start(0))?;
    let mut probe = [0u8; 512];
    let n = read_prefix(&mut reader, &mut probe)?;
    reader.seek(SeekFrom::Start(0))?;
    if sparse::looks_like_cowd(&probe[..n]) {
        return Err(VmdkError::Msg(
            "ESXi COWD/vmfsSparse grain residual (v1 is hosted KDMV sparse only)".into(),
        ));
    }
    if !sparse::looks_like_kdmv(&probe[..n]) {
        if descriptor::looks_like_descriptor_text(&probe[..n]) {
            return Err(VmdkError::Msg(format!(
                "{} is a VMDK descriptor that names sibling extent files; \
                 open_from_reader only accepts monolithicSparse KDMV streams",
                label.display()
            )));
        }
        return Err(VmdkError::Msg(format!(
            "{} is not a KDMV sparse VMDK",
            label.display()
        )));
    }
    let backend = sparse::share_reader(reader);
    let (extent, desc) = sparse::open_sparse_extent(backend)?;
    if let Some(d) = desc.as_ref() {
        reject_residual_descriptor(d)?;
        reject_reader_sibling_extents(d, label)?;
    }
    let mut extents = vec![sparse::DiskExtent::Sparse(extent)];
    if let Some(d) = desc {
        append_trailing_zero_extents(&mut extents, &d);
    }
    sparse::VmdkDisk::new(extents)
}

fn open_disk_from_path(path: &Path) -> Result<sparse::VmdkDisk> {
    let mut file = File::open(path)?;
    let mut probe = [0u8; 4096];
    let n = read_prefix(&mut file, &mut probe)?;
    drop(file);
    if sparse::looks_like_cowd(&probe[..n]) {
        return Err(VmdkError::Msg(
            "ESXi COWD/vmfsSparse grain residual (v1 is hosted KDMV sparse only)".into(),
        ));
    }
    if sparse::looks_like_kdmv(&probe[..n]) {
        return open_kdmv_path(path);
    }
    if descriptor::looks_like_descriptor_text(&probe[..n]) {
        let text = read_sidecar_descriptor(path)?;
        let desc = parse_vmdk_descriptor(&text)?;
        return open_descriptor_path(path, &desc);
    }
    Err(VmdkError::Msg(format!(
        "{} is not a KDMV sparse VMDK or disk descriptor",
        path.display()
    )))
}

fn open_kdmv_path(path: &Path) -> Result<sparse::VmdkDisk> {
    let file = File::open(path)?;
    let backend = sparse::share_reader(file);
    let (extent, desc) = sparse::open_sparse_extent(backend)?;
    if let Some(d) = desc.as_ref() {
        reject_residual_descriptor(d)?;
    }
    let Some(desc) = desc else {
        return sparse::VmdkDisk::new(vec![sparse::DiskExtent::Sparse(extent)]);
    };
    // Embedded descriptor: this file is the first SPARSE extent; extra SPARSE/FLAT
    // names are siblings next to `path`.
    let mut extents = Vec::with_capacity(desc.extents.len().max(1));
    let mut used_self = false;
    for ext in &desc.extents {
        match ext.kind {
            ExtentKind::Zero => {
                extents.push(sparse::DiskExtent::Zero {
                    size_bytes: ext.sectors.saturating_mul(SECTOR),
                });
            }
            ExtentKind::Sparse => {
                if !used_self {
                    extents.push(sparse::DiskExtent::Sparse(extent.clone()));
                    used_self = true;
                } else {
                    let sib = sibling_path(path, ext.filename.as_deref())?;
                    extents.push(open_sparse_file(&sib)?);
                }
            }
            ExtentKind::Flat | ExtentKind::Vmfs => {
                let sib = sibling_path(path, ext.filename.as_deref())?;
                extents.push(open_flat_file(&sib, ext)?);
            }
            ExtentKind::EsxiSparse | ExtentKind::Other => {
                return Err(esxi_or_other_extent_err(ext));
            }
        }
    }
    if !used_self && extents.is_empty() {
        extents.push(sparse::DiskExtent::Sparse(extent));
    }
    sparse::VmdkDisk::new(extents)
}

fn open_descriptor_path(desc_path: &Path, desc: &VmdkDescriptor) -> Result<sparse::VmdkDisk> {
    reject_residual_descriptor(desc)?;
    let mut extents = Vec::with_capacity(desc.extents.len());
    for ext in &desc.extents {
        match ext.kind {
            ExtentKind::Zero => extents.push(sparse::DiskExtent::Zero {
                size_bytes: ext.sectors.saturating_mul(SECTOR),
            }),
            ExtentKind::Sparse => {
                let sib = sibling_path(desc_path, ext.filename.as_deref())?;
                extents.push(open_sparse_file(&sib)?);
            }
            ExtentKind::Flat | ExtentKind::Vmfs => {
                let sib = sibling_path(desc_path, ext.filename.as_deref())?;
                extents.push(open_flat_file(&sib, ext)?);
            }
            ExtentKind::EsxiSparse | ExtentKind::Other => {
                return Err(esxi_or_other_extent_err(ext));
            }
        }
    }
    sparse::VmdkDisk::new(extents)
}

fn open_sparse_file(path: &Path) -> Result<sparse::DiskExtent> {
    let file = File::open(path)?;
    let backend = sparse::share_reader(file);
    let (extent, desc) = sparse::open_sparse_extent(backend)?;
    if let Some(d) = desc.as_ref() {
        reject_residual_descriptor(d)?;
    }
    Ok(sparse::DiskExtent::Sparse(extent))
}

fn open_flat_file(path: &Path, ext: &DescriptorExtent) -> Result<sparse::DiskExtent> {
    let file = File::open(path)?;
    let backend = sparse::share_reader(file);
    let size_bytes = ext.sectors.saturating_mul(SECTOR);
    let offset_bytes = ext.offset_sectors.saturating_mul(SECTOR);
    Ok(sparse::DiskExtent::Flat(sparse::FlatExtent::new(
        backend,
        offset_bytes,
        size_bytes,
    )))
}

/// Cap sidecar text so a crafted `# Disk DescriptorFile` prefix cannot slurp GiB.
fn read_sidecar_descriptor(path: &Path) -> Result<String> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_SIDECAR_DESCRIPTOR_BYTES {
        return Err(VmdkError::Msg(format!(
            "{} is larger than {MAX_SIDECAR_DESCRIPTOR_BYTES} bytes; \
             text VMDK descriptors are capped (refusing unbounded read)",
            path.display()
        )));
    }
    let file = File::open(path)?;
    let mut buf = Vec::new();
    file.take(MAX_SIDECAR_DESCRIPTOR_BYTES)
        .read_to_end(&mut buf)?;
    String::from_utf8(buf).map_err(|e| {
        VmdkError::Msg(format!(
            "{} is not UTF-8 VMDK descriptor text: {e}",
            path.display()
        ))
    })
}

/// v1: extent names are siblings under the descriptor directory.
/// Absolute Unix/Windows paths and `..` are rejected (not trusted host paths).
fn sibling_path(base: &Path, filename: Option<&str>) -> Result<PathBuf> {
    let name =
        filename.ok_or_else(|| VmdkError::Msg("VMDK extent is missing a filename".into()))?;
    if extent_name_escapes(name) {
        return Err(VmdkError::Msg(format!(
            "VMDK extent path {name:?} must be a relative sibling (absolute / '..' residual)"
        )));
    }
    let p = Path::new(name);
    if p.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(VmdkError::Msg(format!(
            "VMDK extent path {name:?} must be a relative sibling (absolute / '..' residual)"
        )));
    }
    let dir = base.parent().unwrap_or(Path::new("."));
    Ok(dir.join(p))
}

fn extent_name_escapes(name: &str) -> bool {
    let p = Path::new(name);
    p.is_absolute() || looks_like_windows_absolute(name)
}

fn looks_like_windows_absolute(name: &str) -> bool {
    let b = name.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || name.starts_with("\\\\")
        || name.starts_with("//")
}

fn reject_residual_descriptor(d: &VmdkDescriptor) -> Result<()> {
    if d.is_stream_optimized() {
        return Err(VmdkError::Msg(
            "compressed VMDK grains residual (createType=streamOptimized)".into(),
        ));
    }
    if d.is_esxi_create_type() {
        return Err(VmdkError::Msg(format!(
            "ESXi grain residual (createType={})",
            d.create_type
        )));
    }
    if !d.parent_cid_is_none() {
        return Err(VmdkError::Msg(format!(
            "VMDK delta/snapshot residual (parentCID={})",
            d.parent_cid
        )));
    }
    if d.extents.iter().any(|e| e.kind.is_esxi_grain()) {
        return Err(VmdkError::Msg(
            "ESXi VMFSSPARSE/SESparse grain residual".into(),
        ));
    }
    Ok(())
}

fn reject_reader_sibling_extents(d: &VmdkDescriptor, label: &Path) -> Result<()> {
    let files = d
        .extents
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                ExtentKind::Sparse | ExtentKind::Flat | ExtentKind::Vmfs
            )
        })
        .count();
    if files > 1 {
        return Err(VmdkError::Msg(format!(
            "{} names sibling VMDK extents; open_from_reader is monolithicSparse only",
            label.display()
        )));
    }
    Ok(())
}

fn append_trailing_zero_extents(extents: &mut Vec<sparse::DiskExtent>, d: &VmdkDescriptor) {
    // Reader path already has the first SPARSE from this stream; extra ZERO
    // extents still contribute to virtual capacity.
    let mut seen_sparse = false;
    for ext in &d.extents {
        if ext.kind == ExtentKind::Sparse {
            seen_sparse = true;
            continue;
        }
        if ext.kind == ExtentKind::Zero && seen_sparse {
            extents.push(sparse::DiskExtent::Zero {
                size_bytes: ext.sectors.saturating_mul(SECTOR),
            });
        }
    }
}

fn esxi_or_other_extent_err(ext: &DescriptorExtent) -> VmdkError {
    if ext.kind.is_esxi_grain() {
        VmdkError::Msg("ESXi VMFSSPARSE/SESparse grain residual".into())
    } else {
        VmdkError::Msg(format!("unsupported VMDK extent type {:?}", ext.kind))
    }
}

fn read_prefix<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0usize;
    while n < buf.len() {
        match reader.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Detect KDMV sparse magic or a text disk descriptor. COWD is **not** claimed
/// (ESXi residual). No `.vmdk` extension fallback.
pub fn looks_like_vmdk(path: &Path) -> bool {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    looks_like_vmdk_reader(&mut f)
}

/// Stream probe (does not use filename). Leaves the reader at an unspecified position.
pub fn looks_like_vmdk_reader<R: Read + Seek>(reader: &mut R) -> bool {
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    let mut buf = [0u8; 4096];
    let n = match read_prefix(reader, &mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    if n < 4 {
        return false;
    }
    if sparse::looks_like_cowd(&buf[..n]) {
        return false;
    }
    sparse::looks_like_kdmv(&buf[..n]) || descriptor::looks_like_descriptor_text(&buf[..n])
}

impl MountSource for VmdkMountSource {
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

    use crate::sparse::build_monolithic_sparse;

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

    /// Regression: KDMV magic is detected; FAT/QCOW/COWD/random are not.
    #[test]
    fn looks_like_vmdk_kdmv_magic() {
        let raw = mbr_wrap(&fat_volume("hello.txt", b"x"), 8);
        let vmdk = build_monolithic_sparse(&raw, 8);
        assert!(vmdk.starts_with(b"KDMV"));
        assert!(looks_like_vmdk_reader(&mut Cursor::new(&vmdk)));
        assert!(!looks_like_vmdk_reader(&mut Cursor::new(b"not-a-vmdk")));
        assert!(!looks_like_vmdk_reader(&mut Cursor::new(&raw)));
        let mut qcow = vec![0u8; 512];
        qcow[..4].copy_from_slice(b"QFI\xfb");
        assert!(!looks_like_vmdk_reader(&mut Cursor::new(&qcow)));
        let mut cowd = vec![0u8; 512];
        cowd[..4].copy_from_slice(b"COWD");
        assert!(
            !looks_like_vmdk_reader(&mut Cursor::new(&cowd)),
            "COWD is ESXi residual — do not claim it"
        );
        assert!(!looks_like_vmdk_reader(&mut Cursor::new(&fat_volume(
            "a.txt", b"a"
        ))));
    }

    /// Regression: text descriptor (no KDMV) is still a VMDK probe hit.
    #[test]
    fn looks_like_vmdk_descriptor_text() {
        let text = b"# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicSparse\"\nRW 8 SPARSE \"d.vmdk\"\n";
        assert!(looks_like_vmdk_reader(&mut Cursor::new(&text[..])));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("disk.vmdk");
        std::fs::write(&p, text).unwrap();
        assert!(looks_like_vmdk(&p));
    }

    /// Regression: synthetic KDMV sparse wrapping MBR+FAT lists `p1/` and reads.
    #[test]
    fn sparse_extent_fixture_lists_p1() {
        let payload = b"hello-vmdk-sparse";
        let raw = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let vmdk = build_monolithic_sparse(&raw, 8);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.vmdk");
        std::fs::write(&path, &vmdk).unwrap();

        let m = VmdkMountSource::open(&path).expect("open KDMV path");
        let root = m.list_dirents("/").expect("list /");
        find_name(&root, "p1");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: nested no-tmp `open_from_reader` on a Cursor (no `/tmp`).
    #[test]
    fn open_from_reader_sparse_no_tmp() {
        let payload = b"nested-vmdk-sparse";
        let vmdk = build_monolithic_sparse(&mbr_wrap(&fat_volume("hello.txt", payload), 8), 8);
        let m = VmdkMountSource::open_from_reader(Cursor::new(vmdk), "nested.vmdk")
            .expect("open_from_reader");
        let fi = m.lookup("/p1/hello.txt", 0).expect("p1/hello.txt");
        let mut got = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got.as_bytes(), payload);
    }

    /// Regression: cheap readdirplus sizes under `p1/`.
    #[test]
    fn list_dirents_sizes_match_lookup() {
        let payload = b"hello-vmdk-dirents";
        let vmdk = build_monolithic_sparse(&mbr_wrap(&fat_volume("hello.txt", payload), 8), 8);
        let m = VmdkMountSource::open_from_reader(Cursor::new(vmdk), "dirents.vmdk").unwrap();
        let dents = m.list_dirents("/p1").expect("p1 dirents");
        let d = find_name(&dents, "hello.txt");
        let fi = m.lookup("/p1/hello.txt", 0).unwrap();
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, payload.len() as u64);
        assert_ne!(d.size, 0);
    }

    /// Regression: partition at 1 MiB inside the virtual disk still lists.
    #[test]
    fn sparse_partition_at_1mib() {
        let payload = b"one-mebibyte-vmdk";
        let start_lba = 2048u32;
        let raw = mbr_wrap(&fat_volume("hello.txt", payload), start_lba);
        assert!(raw.len() >= 1024 * 1024 + FAT_BYTES);
        let vmdk = build_monolithic_sparse(&raw, 128);
        let m = VmdkMountSource::open_from_reader(Cursor::new(vmdk), "1mib.vmdk").expect("open");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: superfloppy FAT inside VMDK mounts at `/` (not Block `p1/`).
    #[test]
    fn sparse_superfloppy_fat_at_root() {
        let payload = b"superfloppy-vmdk";
        let fat = fat_volume("hello.txt", payload);
        let vmdk = build_monolithic_sparse(&fat, 8);
        let m = VmdkMountSource::open_from_reader(Cursor::new(vmdk), "floppy.vmdk").expect("open");
        assert!(m.lookup("/p1", 0).is_none());
        let fi = m.lookup("/hello.txt", 0).expect("root file");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = VmdkMountSource::open_from_reader(Cursor::new(b"nope"), "bad.vmdk")
            .err()
            .expect("non-vmdk bytes must fail");
        assert!(err.to_string().contains("not a KDMV"), "unexpected: {err}");
    }

    /// Regression: compressed FLAG_COMPRESS is residual (not silent zeros).
    #[test]
    fn residual_compressed_flags() {
        let mut vmdk = build_monolithic_sparse(&mbr_wrap(&fat_volume("a.txt", b"a"), 8), 8);
        let flags = u32::from_le_bytes(vmdk[8..12].try_into().unwrap()) | sparse::FLAG_COMPRESS;
        vmdk[8..12].copy_from_slice(&flags.to_le_bytes());
        assert!(looks_like_vmdk_reader(&mut Cursor::new(&vmdk)));
        let err = VmdkMountSource::open_from_reader(Cursor::new(vmdk), "comp.vmdk")
            .err()
            .expect("compressed must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("compressed") && msg.contains("residual"),
            "unexpected: {msg}"
        );
    }

    /// Regression: FLAG_MARKER alone is not compression (qemu treats it separately).
    #[test]
    fn residual_flag_marker_is_not_compressed() {
        let payload = b"marker-not-compress";
        let mut vmdk = build_monolithic_sparse(&mbr_wrap(&fat_volume("hello.txt", payload), 8), 8);
        let flags = u32::from_le_bytes(vmdk[8..12].try_into().unwrap()) | sparse::FLAG_MARKER;
        vmdk[8..12].copy_from_slice(&flags.to_le_bytes());
        let m = VmdkMountSource::open_from_reader(Cursor::new(vmdk), "marker.vmdk")
            .expect("FLAG_MARKER alone must not fail as compressed");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: COWD magic is ESXi residual, not a successful open.
    #[test]
    fn residual_esxi_cowd() {
        let mut cowd = vec![0u8; 512];
        cowd[..4].copy_from_slice(b"COWD");
        let err = VmdkMountSource::open_from_reader(Cursor::new(cowd), "esxi.vmdk")
            .err()
            .expect("COWD must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("ESXi") || msg.contains("COWD") || msg.contains("residual"),
            "unexpected: {msg}"
        );
    }

    /// Regression: parentCID delta disks are residual.
    #[test]
    fn residual_delta_parent_cid() {
        let mut vmdk = build_monolithic_sparse(&mbr_wrap(&fat_volume("a.txt", b"a"), 8), 8);
        let desc_off = 512;
        let desc = std::str::from_utf8(&vmdk[desc_off..desc_off + 400]).unwrap();
        let patched = desc.replace("parentCID=ffffffff", "parentCID=12345678");
        vmdk[desc_off..desc_off + patched.len()].copy_from_slice(patched.as_bytes());
        let err = VmdkMountSource::open_from_reader(Cursor::new(vmdk), "delta.vmdk")
            .err()
            .expect("delta must fail");
        assert!(err.to_string().contains("residual"), "unexpected: {err}");
    }

    /// Regression: descriptor + sibling KDMV extent (path open, not reader).
    #[test]
    fn path_open_descriptor_plus_sibling_sparse() {
        let payload = b"descriptor-sibling";
        let raw = mbr_wrap(&fat_volume("hello.txt", payload), 8);
        let extent = build_monolithic_sparse(&raw, 8);
        let cap = {
            let mut b = [0u8; 8];
            b.copy_from_slice(&extent[0x0C..0x14]);
            u64::from_le_bytes(b)
        };
        let dir = tempfile::tempdir().unwrap();
        let ext_path = dir.path().join("disk-s001.vmdk");
        std::fs::write(&ext_path, &extent).unwrap();
        let desc = format!(
            "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n\
             createType=\"twoGbMaxExtentSparse\"\nRW {cap} SPARSE \"disk-s001.vmdk\"\n"
        );
        let desc_path = dir.path().join("disk.vmdk");
        std::fs::write(&desc_path, desc).unwrap();
        assert!(looks_like_vmdk(&desc_path));
        let m = VmdkMountSource::open(&desc_path).expect("descriptor + sibling");
        let fi = m.lookup("/p1/hello.txt", 0).expect("lookup");
        let mut got = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    /// Regression: `open_from_reader` of a descriptor-only stream fails closed.
    #[test]
    fn open_from_reader_descriptor_only_needs_path() {
        let text = b"# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicSparse\"\nRW 8 SPARSE \"d.vmdk\"\n";
        let err = VmdkMountSource::open_from_reader(Cursor::new(&text[..]), "desc.vmdk")
            .err()
            .expect("descriptor-only reader must fail");
        assert!(
            err.to_string().contains("sibling") || err.to_string().contains("monolithicSparse"),
            "unexpected: {err}"
        );
    }

    fn open_descriptor_naming(name: &str) -> Result<VmdkMountSource> {
        let dir = tempfile::tempdir().unwrap();
        let desc = format!(
            "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n\
             createType=\"monolithicSparse\"\nRW 8 SPARSE \"{name}\"\n"
        );
        let desc_path = dir.path().join("disk.vmdk");
        std::fs::write(&desc_path, desc).unwrap();
        VmdkMountSource::open(&desc_path)
    }

    /// Regression: path-open of a text descriptor must not unbounded-slurp a huge file.
    #[test]
    fn descriptor_rejects_oversized_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.vmdk");
        let mut f = File::create(&path).unwrap();
        f.write_all(
            b"# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicSparse\"\nRW 8 SPARSE \"d.vmdk\"\n",
        )
        .unwrap();
        // Sparse hole: size is over the cap; body is not materialized.
        f.set_len(MAX_SIDECAR_DESCRIPTOR_BYTES + 1).unwrap();
        drop(f);
        assert!(looks_like_vmdk(&path));
        let err = VmdkMountSource::open(&path)
            .err()
            .expect("oversized sidecar must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("larger") || msg.contains("capped"),
            "unexpected: {msg}"
        );
    }

    /// Regression: `..` in an extent name is rejected (not joined as a host path).
    #[test]
    fn sibling_path_rejects_dotdot() {
        let err = open_descriptor_naming("../secret.vmdk")
            .err()
            .expect(".. must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("..") || msg.contains("sibling") || msg.contains("residual"),
            "unexpected: {msg}"
        );
    }

    /// Regression: Unix absolute extent names are not opened (`/etc/passwd`).
    #[test]
    fn sibling_path_rejects_absolute_unix() {
        let err = open_descriptor_naming("/etc/passwd")
            .err()
            .expect("absolute must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("absolute") || msg.contains("sibling") || msg.contains("residual"),
            "unexpected: {msg}"
        );
    }

    /// Regression: Windows absolute / UNC extent names are rejected on Unix too.
    #[test]
    fn sibling_path_rejects_windows_absolute() {
        for name in [
            r"C:\Windows\x.vmdk",
            r"C:/Windows/x.vmdk",
            r"\\server\share\x.vmdk",
        ] {
            let err = open_descriptor_naming(name)
                .err()
                .unwrap_or_else(|| panic!("{name} must fail"));
            let msg = err.to_string();
            assert!(
                msg.contains("absolute") || msg.contains("sibling") || msg.contains("residual"),
                "{name}: {msg}"
            );
        }
    }

    /// Regression: unallocated grains read as zeros (true sparse hole).
    #[test]
    fn sparse_unallocated_grain_is_zero() {
        // Tiny raw: only the first sector is non-zero; later grains stay sparse.
        let mut raw = vec![0u8; 64 * 512];
        raw[0] = 0xAA;
        raw[511] = 0x55;
        let vmdk = build_monolithic_sparse(&raw, 8);
        let backend = sparse::share_reader(Cursor::new(vmdk));
        let (extent, _) = sparse::open_sparse_extent(backend).unwrap();
        let mut hole = [0xFFu8; 16];
        extent
            .read_at(8 * 512, &mut hole)
            .expect("read unallocated grain");
        assert!(hole.iter().all(|&b| b == 0), "sparse hole must be zeros");
        let mut head = [0u8; 1];
        extent.read_at(0, &mut head).unwrap();
        assert_eq!(head[0], 0xAA);
    }
}
