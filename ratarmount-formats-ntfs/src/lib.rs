//! NTFS filesystem image mount source (read-only).
//!
//! Uses the pure-Rust [`ntfs`] crate for in-process MFT / index / `$DATA` reads
//! (no loop mount, no `ntfs-3g`). The volume journal (`$LogFile`) is **not**
//! replayed.
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested NTFS members can be opened without `/tmp` when the outer archive
//! yields a seekable stream: [`NtfsMountSource::open_from_reader`] (and
//! [`NtfsMountSource::open_from_reader_with_offset`]) validate the OEM
//! `"NTFS    "` boot-sector magic, retain a mutex-shared `Read + Seek` body,
//! and reopen the volume per operation. No `NamedTempFile` spool.
//!
//! # Residuals
//!
//! Encrypted EFS files list but `open` returns [`io::ErrorKind::PermissionDenied`].
//! LZNT1-compressed `$DATA` lists but `open` returns [`io::ErrorKind::Unsupported`]
//! (`ntfs` 0.4 does not decompress; returning raw compression units would be
//! silent corruption). Alternate data streams are not presented as files
//! (unnamed `$DATA` only). WOF / Compact OS reparse is unresolved (often an
//! empty unnamed `$DATA`).
//!
//! # Partitioned images
//!
//! Use [`NtfsMountSource::open_with_offset`] /
//! [`NtfsMountSource::open_from_reader_with_offset`] with the byte offset of
//! the filesystem partition.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{NtfsFileAttributeFlags, NtfsFileNamespace};
use ntfs::{Ntfs, NtfsReadSeek, NtfsTime};
use ratarmount_core::{CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData};
use thiserror::Error;

pub const BACKEND_NAME: &str = "NtfsMountSource";

/// OEM ID at boot-sector offset 3 (8 bytes, space-padded).
const NTFS_OEM: &[u8; 8] = b"NTFS    ";

/// Windows FILETIME → Unix: 100-nanosecond ticks between 1601-01-01 and 1970-01-01.
/// Same constant as 7z (`FILETIME_UNIX_DELTA`); do not use a nanosecond-scale gap.
const FILETIME_UNIX_DELTA: u64 = 116_444_736_000_000_000;

#[derive(Debug, Error)]
pub enum NtfsError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, NtfsError>;

trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

enum NtfsBackend {
    Path {
        path: PathBuf,
        partition_offset: u64,
    },
    Shared {
        shared: Arc<Mutex<Box<dyn SeekRead>>>,
        partition_offset: u64,
        #[allow(dead_code)]
        archive_label: PathBuf,
    },
}

/// Read-only disk that presents the NTFS volume starting at byte 0
/// (`partition_offset` is added to every on-disk seek).
struct OffsetDisk {
    inner: OffsetDiskInner,
    partition_offset: u64,
    pos: u64,
}

enum OffsetDiskInner {
    File(File),
    Shared(Arc<Mutex<Box<dyn SeekRead>>>),
}

impl OffsetDisk {
    fn from_file(file: File, partition_offset: u64) -> Self {
        Self {
            inner: OffsetDiskInner::File(file),
            partition_offset,
            pos: 0,
        }
    }

    fn from_shared(shared: Arc<Mutex<Box<dyn SeekRead>>>, partition_offset: u64) -> Self {
        Self {
            inner: OffsetDiskInner::Shared(shared),
            partition_offset,
            pos: 0,
        }
    }

    fn abs_pos(&self) -> io::Result<u64> {
        self.partition_offset
            .checked_add(self.pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))
    }
}

impl Read for OffsetDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let abs = self.abs_pos()?;
        let n = match &mut self.inner {
            OffsetDiskInner::File(f) => {
                f.seek(SeekFrom::Start(abs))?;
                f.read(buf)?
            }
            OffsetDiskInner::Shared(shared) => {
                let mut guard = shared
                    .lock()
                    .map_err(|_| io::Error::other("shared NTFS reader poisoned"))?;
                guard.seek(SeekFrom::Start(abs))?;
                guard.read(buf)?
            }
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for OffsetDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.pos as i64 + o,
            SeekFrom::End(o) => {
                let end = match &mut self.inner {
                    OffsetDiskInner::File(f) => f.seek(SeekFrom::End(0))?,
                    OffsetDiskInner::Shared(shared) => {
                        let mut guard = shared
                            .lock()
                            .map_err(|_| io::Error::other("shared NTFS reader poisoned"))?;
                        guard.seek(SeekFrom::End(0))?
                    }
                };
                let vol_end = end.saturating_sub(self.partition_offset);
                vol_end as i64 + o
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

fn ntfs_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("ntfs:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("ntfs:") => Some(s[5..].to_string()),
        _ => None,
    })
}

fn abs_path(path: &str) -> String {
    let t = path.trim();
    if t.is_empty() || t == "/" {
        "/".into()
    } else if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
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
        userdata: vec![ntfs_path_userdata(name_path)],
    }
}

/// Convert NT FILETIME (100ns since 1601-01-01) to Unix seconds as `f64`.
fn filetime_to_unix(filetime: u64) -> f64 {
    if filetime == 0 {
        return 0.0;
    }
    if filetime >= FILETIME_UNIX_DELTA {
        (filetime - FILETIME_UNIX_DELTA) as f64 / 10_000_000.0
    } else {
        -((FILETIME_UNIX_DELTA - filetime) as f64) / 10_000_000.0
    }
}

fn ntfs_time_to_unix(t: NtfsTime) -> f64 {
    filetime_to_unix(t.nt_timestamp())
}

fn map_ntfs<E: std::fmt::Display>(e: E) -> NtfsError {
    NtfsError::Msg(e.to_string())
}

/// Map crate errors from `open` / `read_file` to `io::ErrorKind`.
/// LZNT1 is fail-closed (`Unsupported`); EFS is `PermissionDenied`.
fn kind_for_read_msg(m: &str) -> io::ErrorKind {
    if m.contains("LZNT1") || m.contains("compressed $DATA") {
        io::ErrorKind::Unsupported
    } else if m.contains("EFS") || m.contains("encrypted") {
        io::ErrorKind::PermissionDenied
    } else if m.contains("not found") {
        io::ErrorKind::NotFound
    } else if m.contains("directory") {
        io::ErrorKind::IsADirectory
    } else {
        io::ErrorKind::Other
    }
}

fn map_read_error(e: NtfsError) -> io::Error {
    match e {
        NtfsError::Io(io) => io,
        NtfsError::Msg(m) => io::Error::new(kind_for_read_msg(&m), m),
    }
}

fn ntfs_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ntfs"))
}

/// Boot-sector probe: OEM `"NTFS    "` at offset 3.
fn boot_sector_looks_like_ntfs(boot: &[u8]) -> bool {
    boot.len() >= 11 && &boot[3..11] == NTFS_OEM
}

struct ListedEntry {
    name: String,
    is_dir: bool,
    size: u64,
    mtime: f64,
}

pub struct NtfsMountSource {
    backend: NtfsBackend,
}

impl NtfsMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_offset(path, 0)
    }

    /// Open an NTFS image; `partition_offset` is the byte start of the FS.
    pub fn open_with_offset(path: impl AsRef<Path>, partition_offset: u64) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_ntfs_at(path, partition_offset) {
            return Err(NtfsError::Msg(format!(
                "{} is not an NTFS image (OEM \"NTFS    \" not found at offset {})",
                path.display(),
                partition_offset.saturating_add(3)
            )));
        }
        {
            let file = File::open(path)?;
            let mut disk = OffsetDisk::from_file(file, partition_offset);
            validate_ntfs(&mut disk, &path.display().to_string())?;
        }
        log::debug!(
            "NTFS: path backend for {} (offset={partition_offset})",
            path.display()
        );
        Ok(Self {
            backend: NtfsBackend::Path {
                path: path.to_path_buf(),
                partition_offset,
            },
        })
    }

    /// Open an NTFS image from any `Read + Seek` source without `/tmp`.
    ///
    /// `archive_label` is diagnostics only (may be a nested member name).
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
        let archive_label = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_ntfs_reader_at(&mut reader, partition_offset) {
            return Err(NtfsError::Msg(format!(
                "{} is not an NTFS image (OEM \"NTFS    \" not found at offset {})",
                archive_label.display(),
                partition_offset.saturating_add(3)
            )));
        }
        reader.seek(SeekFrom::Start(0))?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> =
            Arc::new(Mutex::new(Box::new(reader) as Box<dyn SeekRead>));
        {
            let mut disk = OffsetDisk::from_shared(Arc::clone(&shared), partition_offset);
            validate_ntfs(&mut disk, &archive_label.display().to_string())?;
        }
        log::debug!(
            "NTFS: shared backend for {} (offset={partition_offset})",
            archive_label.display()
        );
        Ok(Self {
            backend: NtfsBackend::Shared {
                shared,
                partition_offset,
                archive_label,
            },
        })
    }

    fn with_disk<R>(&self, f: impl FnOnce(&mut OffsetDisk) -> Result<R>) -> Result<R> {
        match &self.backend {
            NtfsBackend::Path {
                path,
                partition_offset,
            } => {
                let file = File::open(path)?;
                let mut disk = OffsetDisk::from_file(file, *partition_offset);
                f(&mut disk)
            }
            NtfsBackend::Shared {
                shared,
                partition_offset,
                ..
            } => {
                let mut disk = OffsetDisk::from_shared(Arc::clone(shared), *partition_offset);
                f(&mut disk)
            }
        }
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        let abs = abs_path(path);
        self.with_disk(|disk| list_entries(disk, &abs))
            .ok()
            .map(|entries| {
                let mut map = BTreeMap::new();
                for e in entries {
                    let child = child_path(&abs, &e.name);
                    map.insert(
                        e.name,
                        entry_to_file_info(&child, e.is_dir, e.size, e.mtime),
                    );
                }
                map
            })
    }

    fn list_dirents_dir(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let abs = abs_path(path);
        self.with_disk(|disk| list_entries(disk, &abs))
            .ok()
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|e| {
                        let (mode, size) = entry_mode_size(e.is_dir, e.size);
                        CheapDirent {
                            name: e.name,
                            mode,
                            size,
                        }
                    })
                    .collect()
            })
    }

    fn find_entry_info(&self, path: &str) -> Option<FileInfo> {
        let abs = abs_path(path);
        self.with_disk(|disk| lookup_entry(disk, &abs)).ok()
    }

    fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        let abs = abs_path(path);
        self.with_disk(|disk| read_unnamed_data(disk, &abs))
            .map_err(map_read_error)
    }
}

impl MountSource for NtfsMountSource {
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
            io::Error::new(io::ErrorKind::InvalidInput, "missing NTFS path userdata")
        })?;
        let data = self.read_file(&path)?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn validate_ntfs(disk: &mut OffsetDisk, label: &str) -> Result<()> {
    let mut ntfs = Ntfs::new(disk).map_err(map_ntfs)?;
    ntfs.read_upcase_table(disk).map_err(map_ntfs)?;
    let _root = ntfs.root_directory(disk).map_err(map_ntfs)?;
    log::debug!("NTFS: validated {label}");
    Ok(())
}

fn open_ntfs(disk: &mut OffsetDisk) -> Result<Ntfs> {
    let mut ntfs = Ntfs::new(disk).map_err(map_ntfs)?;
    ntfs.read_upcase_table(disk).map_err(map_ntfs)?;
    Ok(ntfs)
}

fn list_entries(disk: &mut OffsetDisk, abs: &str) -> Result<Vec<ListedEntry>> {
    let ntfs = open_ntfs(disk)?;
    let dir = resolve_file(&ntfs, disk, abs)?;
    if !dir.is_directory() {
        return Err(NtfsError::Msg(format!("{abs} is not a directory")));
    }
    let index = dir.directory_index(disk).map_err(map_ntfs)?;
    let mut iter = index.entries();
    let mut out = Vec::new();
    while let Some(entry) = iter.next(disk) {
        let entry = entry.map_err(map_ntfs)?;
        let Some(key) = entry.key() else {
            continue;
        };
        let name = key.map_err(map_ntfs)?;
        if name.namespace() == NtfsFileNamespace::Dos {
            continue;
        }
        let n = name.name().to_string_lossy();
        if n.is_empty() || n == "." || n == ".." {
            continue;
        }
        let is_dir = name.is_directory();
        let size = if is_dir { 0 } else { name.data_size() };
        let mtime = ntfs_time_to_unix(name.modification_time());
        out.push(ListedEntry {
            name: n,
            is_dir,
            size,
            mtime,
        });
    }
    Ok(out)
}

fn lookup_entry(disk: &mut OffsetDisk, abs: &str) -> Result<FileInfo> {
    let ntfs = open_ntfs(disk)?;
    if abs == "/" {
        return Ok(entry_to_file_info("/", true, 0, 0.0));
    }
    let (parent, name) = match abs.rsplit_once('/') {
        Some(("", n)) => ("/", n),
        Some((p, n)) => (p, n),
        None => ("/", abs.trim_start_matches('/')),
    };
    if name.is_empty() {
        return Ok(entry_to_file_info("/", true, 0, 0.0));
    }
    let parent_file = resolve_file(&ntfs, disk, parent)?;
    if !parent_file.is_directory() {
        return Err(NtfsError::Msg("not found".into()));
    }
    let index = parent_file.directory_index(disk).map_err(map_ntfs)?;
    let mut finder = index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, disk, name)
        .ok_or_else(|| NtfsError::Msg("not found".into()))?
        .map_err(map_ntfs)?;
    let key = entry
        .key()
        .ok_or_else(|| NtfsError::Msg("not found".into()))?
        .map_err(map_ntfs)?;
    let is_dir = key.is_directory();
    let size = if is_dir { 0 } else { key.data_size() };
    let mtime = ntfs_time_to_unix(key.modification_time());
    Ok(entry_to_file_info(abs, is_dir, size, mtime))
}

fn resolve_file<'n>(
    ntfs: &'n Ntfs,
    disk: &mut OffsetDisk,
    abs: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    let mut file = ntfs.root_directory(disk).map_err(map_ntfs)?;
    let rel = abs.trim_matches('/');
    if rel.is_empty() {
        return Ok(file);
    }
    for component in rel.split('/') {
        if component.is_empty() {
            continue;
        }
        if !file.is_directory() {
            return Err(NtfsError::Msg("not found".into()));
        }
        let index = file.directory_index(disk).map_err(map_ntfs)?;
        let mut finder = index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, ntfs, disk, component)
            .ok_or_else(|| NtfsError::Msg("not found".into()))?
            .map_err(map_ntfs)?;
        file = entry.to_file(ntfs, disk).map_err(map_ntfs)?;
    }
    Ok(file)
}

fn read_unnamed_data(disk: &mut OffsetDisk, abs: &str) -> Result<Vec<u8>> {
    let ntfs = open_ntfs(disk)?;
    let file = resolve_file(&ntfs, disk, abs)?;
    if file.is_directory() {
        return Err(NtfsError::Msg(format!("{abs} is a directory")));
    }
    if let Ok(info) = file.info() {
        let attrs = info.file_attributes();
        if attrs.contains(NtfsFileAttributeFlags::ENCRYPTED) {
            return Err(NtfsError::Msg(format!(
                "NTFS EFS encrypted file {abs} (decrypt residual)"
            )));
        }
        // File-level COMPRESSED on a non-directory: ntfs 0.4 has no LZNT1.
        if attrs.contains(NtfsFileAttributeFlags::COMPRESSED) {
            return Err(NtfsError::Msg(format!(
                "NTFS LZNT1 compressed $DATA on {abs} (decompress residual)"
            )));
        }
    }
    let data_item = file
        .data(disk, "")
        .ok_or_else(|| NtfsError::Msg(format!("no unnamed $DATA on {abs}")))?
        .map_err(map_ntfs)?;
    let attr = data_item.to_attribute().map_err(map_ntfs)?;
    if attr.flags().contains(ntfs::NtfsAttributeFlags::ENCRYPTED) {
        return Err(NtfsError::Msg(format!(
            "NTFS EFS encrypted $DATA on {abs} (decrypt residual)"
        )));
    }
    // ntfs 0.4 concatenates compression units without LZNT1 — fail-closed
    // rather than return raw bytes whose lookup size is uncompressed.
    if attr.flags().contains(ntfs::NtfsAttributeFlags::COMPRESSED) {
        return Err(NtfsError::Msg(format!(
            "NTFS LZNT1 compressed $DATA on {abs} (decompress residual)"
        )));
    }
    let mut value = attr.value(disk).map_err(map_ntfs)?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = value.read(disk, &mut tmp).map_err(map_ntfs)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}

/// Detect NTFS via OEM `"NTFS    "` at offset 3, or a `.ntfs` extension.
pub fn looks_like_ntfs(path: &Path) -> bool {
    looks_like_ntfs_at(path, 0)
}

/// Detect NTFS OEM at `partition_offset + 3`.
///
/// Extension fallback (`.ntfs`) is only applied at offset 0 so a bad partition
/// offset on a `*.ntfs` file is not masked.
pub fn looks_like_ntfs_at(path: &Path, partition_offset: u64) -> bool {
    if let Ok(mut f) = File::open(path) {
        if looks_like_ntfs_reader_at(&mut f, partition_offset) {
            return true;
        }
    }
    partition_offset == 0 && ntfs_extension(path)
}

/// Boot-sector probe for nested streams (does not use filename).
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_ntfs_reader<R: Read + Seek>(reader: &mut R) -> bool {
    looks_like_ntfs_reader_at(reader, 0)
}

/// OEM `"NTFS    "` at `partition_offset + 3` on a seekable stream.
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_ntfs_reader_at<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> bool {
    let mut boot = [0u8; 512];
    if reader.seek(SeekFrom::Start(partition_offset)).is_err() {
        return false;
    }
    if reader.read_exact(&mut boot).is_err() {
        return false;
    }
    boot_sector_looks_like_ntfs(&boot)
}

pub fn open_as_mount_source(path: &Path) -> Result<Arc<dyn MountSource>> {
    Ok(Arc::new(NtfsMountSource::open(path)?) as Arc<dyn MountSource>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;

    fn synthetic_ntfs_boot() -> [u8; 512] {
        let mut b = [0u8; 512];
        b[0] = 0xEB;
        b[1] = 0x52;
        b[2] = 0x90;
        b[3..11].copy_from_slice(NTFS_OEM);
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 8;
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    fn synthetic_fat32_boot() -> [u8; 512] {
        let mut b = [0u8; 512];
        b[0] = 0xEB;
        b[1] = 0x58;
        b[2] = 0x90;
        b[3..11].copy_from_slice(b"MSDOS5.0");
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 8;
        b[16] = 2;
        b[82..90].copy_from_slice(b"FAT32   ");
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    fn synthetic_exfat_boot() -> [u8; 512] {
        let mut b = [0u8; 512];
        b[0] = 0xEB;
        b[1] = 0x76;
        b[2] = 0x90;
        b[3..11].copy_from_slice(b"EXFAT   ");
        b[510] = 0x55;
        b[511] = 0xAA;
        b
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

    fn mkfs_ntfs_image() -> Option<(tempfile::TempDir, PathBuf)> {
        let mkfs = which_cmd("mkfs.ntfs").or_else(|| which_cmd("mkntfs"))?;
        let dir = tempfile::tempdir().ok()?;
        let img = dir.path().join("disk.ntfs");
        {
            let f = File::create(&img).ok()?;
            f.set_len(8 * 1024 * 1024).ok()?;
        }
        let status = Command::new(&mkfs)
            .args(["-F", "-Q", "-L", "ratar-ntfs"])
            .arg(&img)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        if !status.success() {
            eprintln!("skip: mkfs.ntfs failed ({})", mkfs.display());
            return None;
        }
        Some((dir, img))
    }

    fn maybe_ntfscp_hello(img: &Path, payload: &[u8]) -> bool {
        let Some(ntfscp) = which_cmd("ntfscp") else {
            eprintln!("skip: ntfscp not on PATH (system files only)");
            return false;
        };
        let dir = match img.parent() {
            Some(p) => p.to_path_buf(),
            None => return false,
        };
        let src = dir.join("hello.txt");
        if std::fs::write(&src, payload).is_err() {
            return false;
        }
        let status = Command::new(&ntfscp)
            .arg(img)
            .arg(&src)
            .arg("hello.txt")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        matches!(status, Ok(s) if s.success())
    }

    /// Always-on: OEM `"NTFS    "` vs FAT32 / exFAT / empty.
    #[test]
    fn looks_like_ntfs_boot_sector_not_fat_or_exfat() {
        assert!(boot_sector_looks_like_ntfs(&synthetic_ntfs_boot()));
        assert!(!boot_sector_looks_like_ntfs(&synthetic_fat32_boot()));
        assert!(!boot_sector_looks_like_ntfs(&synthetic_exfat_boot()));
        assert!(!boot_sector_looks_like_ntfs(&[0u8; 512]));
        assert!(!boot_sector_looks_like_ntfs(b"short"));

        assert!(looks_like_ntfs_reader(&mut Cursor::new(
            synthetic_ntfs_boot()
        )));
        assert!(!looks_like_ntfs_reader(&mut Cursor::new(
            synthetic_fat32_boot()
        )));
        assert!(!looks_like_ntfs_reader(&mut Cursor::new(
            synthetic_exfat_boot()
        )));

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope.bin");
        File::create(&p).unwrap().write_all(&[0u8; 512]).unwrap();
        assert!(!looks_like_ntfs(&p));

        let p2 = dir.path().join("disk.ntfs");
        File::create(&p2).unwrap().write_all(&[0u8; 64]).unwrap();
        assert!(looks_like_ntfs(&p2), "extension fallback");
        assert!(
            !looks_like_ntfs_at(&p2, 4096),
            "extension must not mask a bad partition offset"
        );
    }

    #[test]
    fn looks_like_ntfs_reader_at_respects_offset() {
        let mut padded = vec![0u8; 1024];
        padded.extend_from_slice(&synthetic_ntfs_boot());
        assert!(!looks_like_ntfs_reader_at(&mut Cursor::new(&padded), 0));
        assert!(looks_like_ntfs_reader_at(&mut Cursor::new(&padded), 1024));
    }

    /// Regression: FILETIME 1601→1970 delta must be 100ns ticks, not nanoseconds.
    #[test]
    fn filetime_unix_epoch_is_zero() {
        assert_eq!(filetime_to_unix(0), 0.0);
        let ft = FILETIME_UNIX_DELTA;
        assert!((filetime_to_unix(ft) - 0.0).abs() < 1e-6);
        let unix = 1_592_222_400u64;
        let ft = unix * 10_000_000 + FILETIME_UNIX_DELTA;
        let got = filetime_to_unix(ft);
        assert!((got - unix as f64).abs() < 1.0, "got {got} expected {unix}");
        assert!(got > 0.0);
        assert!(
            got < 2.0e9,
            "must not be a multi-millennium offset, got {got}"
        );
    }

    /// Regression: LZNT1 must fail-closed as Unsupported, not PermissionDenied / Other.
    #[test]
    fn compressed_data_maps_to_unsupported_not_permission_denied() {
        let lz = map_read_error(NtfsError::Msg(
            "NTFS LZNT1 compressed $DATA on /x (decompress residual)".into(),
        ));
        assert_eq!(lz.kind(), io::ErrorKind::Unsupported);
        let efs = map_read_error(NtfsError::Msg(
            "NTFS EFS encrypted file /x (decrypt residual)".into(),
        ));
        assert_eq!(efs.kind(), io::ErrorKind::PermissionDenied);
        assert_ne!(
            lz.kind(),
            efs.kind(),
            "compression must not share the EFS PermissionDenied mapping"
        );
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = NtfsMountSource::open_from_reader(Cursor::new(vec![0u8; 4096]), "fake.img")
            .err()
            .expect("expected open_from_reader failure for non-NTFS bytes");
        assert!(
            err.to_string().contains("not an NTFS"),
            "unexpected error: {err}"
        );

        let err = NtfsMountSource::open_from_reader(
            Cursor::new(synthetic_fat32_boot().to_vec()),
            "fat32.img",
        )
        .err()
        .expect("FAT32 must not open as NTFS");
        assert!(err.to_string().contains("not an NTFS"), "got: {err}");
    }

    #[test]
    fn open_rejects_non_ntfs_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.bin");
        File::create(&p)
            .unwrap()
            .write_all(b"not an ntfs image")
            .unwrap();
        let err = NtfsMountSource::open(&p)
            .err()
            .expect("expected open failure for non-NTFS file");
        assert!(err.to_string().contains("not an NTFS"), "got: {err}");
    }

    #[test]
    fn mkfs_ntfs_list_and_read() {
        let Some((_dir, img)) = mkfs_ntfs_image() else {
            eprintln!("skip: mkfs.ntfs not available");
            return;
        };
        assert!(looks_like_ntfs(&img));
        let m = NtfsMountSource::open(&img).expect("open mkfs.ntfs image");
        let root = m.list("/").expect("list /");
        let names: Vec<String> = match root {
            ListResult::Infos(map) => map.keys().cloned().collect(),
            ListResult::Names(n) => n,
        };
        assert!(
            names
                .iter()
                .any(|n| n == "$MFT" || n == "$Volume" || n == "$Boot"),
            "expected NTFS metadata in root, got {names:?}"
        );
        let boot = m
            .lookup("/$Boot", 0)
            .or_else(|| m.lookup("/$Volume", 0))
            .expect("$Boot or $Volume");
        assert_eq!(
            boot.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFREG
        );

        let payload = b"hello-ntfs\n";
        if maybe_ntfscp_hello(&img, payload) {
            let m = NtfsMountSource::open(&img).expect("reopen after ntfscp");
            let fi = m.lookup("/hello.txt", 0).expect("hello.txt");
            assert_eq!(fi.size, payload.len() as u64);
            let mut r = m.open(&fi, 0).unwrap();
            let mut s = Vec::new();
            r.read_to_end(&mut s).unwrap();
            assert_eq!(s, payload);
        }
    }

    #[test]
    fn open_from_reader_mkfs_matches_path() {
        let Some((_dir, img)) = mkfs_ntfs_image() else {
            eprintln!("skip: mkfs.ntfs not available");
            return;
        };
        let bytes = std::fs::read(&img).expect("read image");
        assert!(looks_like_ntfs_reader(&mut Cursor::new(&bytes)));
        let from_path = NtfsMountSource::open(&img).expect("path open");
        let from_reader = NtfsMountSource::open_from_reader(Cursor::new(bytes), "nested.ntfs")
            .expect("open_from_reader");

        let path_root = from_path.list("/").expect("path list");
        let reader_root = from_reader.list("/").expect("reader list");
        let path_names: Vec<String> = match path_root {
            ListResult::Infos(map) => map.keys().cloned().collect(),
            ListResult::Names(n) => n,
        };
        let reader_names: Vec<String> = match reader_root {
            ListResult::Infos(map) => map.keys().cloned().collect(),
            ListResult::Names(n) => n,
        };
        assert_eq!(path_names, reader_names);
    }

    #[test]
    fn open_from_reader_with_offset_padded() {
        let Some((_dir, img)) = mkfs_ntfs_image() else {
            eprintln!("skip: mkfs.ntfs not available");
            return;
        };
        let bytes = std::fs::read(&img).expect("read image");
        let pad = 1024 * 1024u64;
        let mut padded = vec![0u8; pad as usize];
        padded.extend_from_slice(&bytes);

        assert!(!looks_like_ntfs_reader_at(&mut Cursor::new(&padded), 0));
        assert!(looks_like_ntfs_reader_at(&mut Cursor::new(&padded), pad));

        let m = NtfsMountSource::open_from_reader_with_offset(
            Cursor::new(padded),
            "padded-nested.img",
            pad,
        )
        .expect("open_from_reader_with_offset");
        let root = m.list("/").expect("list / at offset");
        match root {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("$MFT") || map.contains_key("$Volume"),
                    "expected metadata at 1 MiB offset, got {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            ListResult::Names(names) => {
                assert!(names.iter().any(|n| n == "$MFT" || n == "$Volume"));
            }
        }
    }

    #[test]
    fn open_with_offset_padded_path() {
        let Some((_dir, img)) = mkfs_ntfs_image() else {
            eprintln!("skip: mkfs.ntfs not available");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        // `.img` so extension fallback cannot mask offset 0.
        let padded = dir.path().join("padded.img");
        let pad = 1024 * 1024usize;
        {
            let mut out = File::create(&padded).unwrap();
            out.write_all(&vec![0u8; pad]).unwrap();
            let mut src = File::open(&img).unwrap();
            io::copy(&mut src, &mut out).unwrap();
        }
        assert!(!looks_like_ntfs_at(&padded, 0));
        assert!(looks_like_ntfs_at(&padded, pad as u64));
        let m = NtfsMountSource::open_with_offset(&padded, pad as u64)
            .expect("open_with_offset at 1 MiB");
        let root = m.list("/").expect("list / at path offset");
        match root {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("$MFT") || map.contains_key("$Volume"),
                    "expected metadata at 1 MiB path offset, got {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            ListResult::Names(names) => {
                assert!(names.iter().any(|n| n == "$MFT" || n == "$Volume"));
            }
        }
    }

    #[test]
    fn open_with_offset_rejects_bad_offset() {
        let Some((_dir, img)) = mkfs_ntfs_image() else {
            eprintln!("skip: mkfs.ntfs not available");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let renamed = dir.path().join("disk.img");
        std::fs::copy(&img, &renamed).unwrap();
        let err = NtfsMountSource::open_with_offset(&renamed, 4096)
            .err()
            .expect("expected open failure at bad offset");
        let msg = err.to_string();
        assert!(
            msg.contains("not an NTFS") || msg.contains("failed to open"),
            "unexpected error: {msg}"
        );
    }

    /// Regression: cheap readdirplus sizes.
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let Some((_dir, img)) = mkfs_ntfs_image() else {
            eprintln!("skip: mkfs.ntfs not available");
            return;
        };
        let payload = b"hello-ntfs-dirents";
        let bytes = std::fs::read(&img).expect("read image");
        let src = if maybe_ntfscp_hello(&img, payload) {
            NtfsMountSource::open(&img).expect("open after ntfscp")
        } else {
            NtfsMountSource::open_from_reader(Cursor::new(bytes), "dirents.ntfs")
                .expect("open_from_reader")
        };
        let dents = src.list_dirents("/").expect("dirents");
        let target = if dents.iter().any(|e| e.name == "hello.txt") {
            "hello.txt"
        } else {
            dents
                .iter()
                .find(|e| e.name == "$Boot" || e.name == "$Volume")
                .map(|e| e.name.as_str())
                .expect("hello.txt or $Boot/$Volume dirent")
        };
        let d = dents.iter().find(|e| e.name == target).unwrap();
        let fi = src
            .lookup(&format!("/{target}"), 0)
            .unwrap_or_else(|| panic!("lookup {target}"));
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        if target == "hello.txt" {
            assert_eq!(d.size, payload.len() as u64);
            assert_ne!(d.size, 0);
        }
    }
}
