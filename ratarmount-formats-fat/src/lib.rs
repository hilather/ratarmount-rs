//! FAT12/16/32 filesystem image mount source.
//!
//! Python uses `pyfatfs` for random access. This crate uses the pure-Rust [`fatfs`]
//! library for in-process cluster reads (no loop mount / mtools required).
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested FAT members can be opened without `/tmp` when the outer archive yields a
//! seekable stream: [`FatMountSource::open_from_reader`] validates the image and
//! retains a mutex-shared `Read + Seek` body. Each list/lookup/open reopens fatfs
//! over that shared handle (`FileSystem` is not `Sync`). No `NamedTempFile` spool.
//!
//! The image is **not** fully loaded into RAM — only the outer member body (if any)
//! remains whatever the parent archive already produced (Cursor / stencil / etc.).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fatfs::{Dir, FileSystem, FsOptions};
use ratarmount_core::{CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData};
use thiserror::Error;

pub const BACKEND_NAME: &str = "FATMountSource";

#[derive(Debug, Error)]
pub enum FatError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, FatError>;

/// Object-safe `Read + Seek + Send` for the shared nested backend.
trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

/// Where FAT image bytes live (path re-open vs nested shared stream).
enum FatBackend {
    /// On-disk image: `File::open` per fatfs session.
    Path(PathBuf),
    /// Nested / stream open: mutex-shared `Read + Seek` (no temp spool, no full RAM copy).
    Shared(Arc<Mutex<Box<dyn SeekRead>>>),
}

/// Read-only disk wrapper that satisfies fatfs's `Read + Write + Seek` bound
/// without mutating the image (writes are discarded).
struct RoDisk {
    inner: RoDiskInner,
}

enum RoDiskInner {
    File(File),
    Shared {
        shared: Arc<Mutex<Box<dyn SeekRead>>>,
        pos: u64,
    },
}

impl RoDisk {
    fn from_file(file: File) -> Self {
        Self {
            inner: RoDiskInner::File(file),
        }
    }

    fn from_shared(shared: Arc<Mutex<Box<dyn SeekRead>>>) -> Self {
        Self {
            inner: RoDiskInner::Shared { shared, pos: 0 },
        }
    }
}

impl Read for RoDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            RoDiskInner::File(f) => f.read(buf),
            RoDiskInner::Shared { shared, pos } => {
                let mut guard = shared
                    .lock()
                    .map_err(|_| io::Error::other("shared FAT reader poisoned"))?;
                guard.seek(SeekFrom::Start(*pos))?;
                let n = guard.read(buf)?;
                *pos += n as u64;
                Ok(n)
            }
        }
    }
}

impl Write for RoDisk {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for RoDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            RoDiskInner::File(f) => f.seek(pos),
            RoDiskInner::Shared {
                shared,
                pos: cur_pos,
            } => {
                let new = match pos {
                    SeekFrom::Start(o) => o as i64,
                    SeekFrom::Current(o) => *cur_pos as i64 + o,
                    SeekFrom::End(o) => {
                        let mut guard = shared
                            .lock()
                            .map_err(|_| io::Error::other("shared FAT reader poisoned"))?;
                        let end = guard.seek(SeekFrom::End(0))? as i64;
                        end + o
                    }
                };
                if new < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek before start",
                    ));
                }
                *cur_pos = new as u64;
                Ok(*cur_pos)
            }
        }
    }
}

/// Absolute path stored in FileInfo userdata for reopen.
fn fat_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("fat:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("fat:") => Some(s[4..].to_string()),
        _ => None,
    })
}

/// Normalize to fatfs path without leading `/` (fatfs uses `/` separators internally).
fn fatfs_rel(path: &str) -> String {
    path.trim_matches('/').to_string()
}

fn dos_datetime_to_unix(dt: fatfs::DateTime) -> f64 {
    // Best-effort: fatfs DateTime fields are DOS calendar.
    // Convert via approximate civil date if chrono not available.
    let d = dt.date;
    let t = dt.time;
    // days since 1970-01-01 via simple algorithm (ignoring leap edge cases is OK for mtime).
    let y = d.year as i64;
    let m = d.month as i64;
    let day = d.day as i64;
    // Algorithm from Howard Hinnant (civil_from_days inverse).
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    let days = (era * 146097 + doe as i64 - 719468) as f64;
    days * 86400.0 + f64::from(t.hour) * 3600.0 + f64::from(t.min) * 60.0 + f64::from(t.sec)
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
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        userdata: vec![fat_path_userdata(name_path)],
    }
}

/// Boot-sector / BPB heuristics shared by path and stream probes.
fn boot_sector_looks_like_fat(boot: &[u8; 512]) -> bool {
    if boot[510] != 0x55 || boot[511] != 0xAA {
        return false;
    }
    // FAT12/16 type string at 54, FAT32 at 82
    let s16 = &boot[54..62];
    let s32 = &boot[82..90];
    if s16.starts_with(b"FAT") || s32.starts_with(b"FAT") {
        return true;
    }
    // Fallback BPB heuristic (jump + valid sector size)
    let bps = u16::from_le_bytes([boot[11], boot[12]]);
    let spc = boot[13];
    (boot[0] == 0xEB || boot[0] == 0xE9) && bps >= 512 && spc > 0 && boot[16] >= 1
}

fn fat_extension(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        let e = e.to_ascii_lowercase();
        e == "fat" || e == "fat12" || e == "fat16" || e == "fat32" || e == "vfat"
    })
}

pub struct FatMountSource {
    /// Host path or virtual label (nested member name / URL).
    #[allow(dead_code)]
    archive_path: PathBuf,
    backend: FatBackend,
}

impl FatMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_fat(path) {
            return Err(FatError::Msg(format!(
                "{} is not a FAT12/16/32 image",
                path.display()
            )));
        }
        // Validate we can open with fatfs (FileSystem is !Sync, so we reopen per op).
        {
            let file = File::open(path)?;
            let _fs = FileSystem::new(RoDisk::from_file(file), FsOptions::new()).map_err(|e| {
                FatError::Msg(format!("failed to open FAT image {}: {e}", path.display()))
            })?;
        }
        Ok(Self {
            archive_path: path.to_path_buf(),
            backend: FatBackend::Path(path.to_path_buf()),
        })
    }

    /// Open a FAT12/16/32 image from any `Read + Seek` source without `/tmp`.
    ///
    /// For nested AutoMount / in-memory / remote images. The reader is retained under
    /// a mutex; each list/lookup/open reopens fatfs over a positioned view of that
    /// shared body. The full image is **not** copied into a second buffer by this
    /// method (the parent may already hold a `Cursor` or stencil).
    ///
    /// `archive_label` is used for diagnostics only (may be a nested member name).
    ///
    /// # Residual / factory
    ///
    /// Wire this from `open_nested_reader_fn` via boot-sector probe
    /// ([`looks_like_fat_reader`]) or name (`*.fat` / `*.vfat` / …). Path-based
    /// compressed FAT still materializes via existing factory keep-temp paths until
    /// that glue lands.
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_fat_reader(&mut reader) {
            return Err(FatError::Msg(format!(
                "{} is not a FAT12/16/32 image",
                archive_path.display()
            )));
        }
        reader.seek(SeekFrom::Start(0))?;

        // Own the stream under a mutex, validate fatfs can parse BPB/FSInfo, then
        // retain the same body for per-op reopens (FileSystem is !Sync).
        let shared: Arc<Mutex<Box<dyn SeekRead>>> =
            Arc::new(Mutex::new(Box::new(reader) as Box<dyn SeekRead>));
        {
            let disk = RoDisk::from_shared(Arc::clone(&shared));
            let _fs = FileSystem::new(disk, FsOptions::new()).map_err(|e| {
                FatError::Msg(format!(
                    "failed to open FAT image {}: {e}",
                    archive_path.display()
                ))
            })?;
        }
        shared
            .lock()
            .map_err(|_| FatError::Msg("shared FAT reader poisoned".into()))?
            .seek(SeekFrom::Start(0))?;

        Ok(Self {
            archive_path,
            backend: FatBackend::Shared(shared),
        })
    }

    /// Open a fresh FileSystem for this call (fatfs FileSystem is not Sync).
    fn with_fs<R>(&self, f: impl FnOnce(&FileSystem<RoDisk>) -> Result<R>) -> Result<R> {
        let disk = match &self.backend {
            FatBackend::Path(path) => {
                let file = File::open(path)?;
                RoDisk::from_file(file)
            }
            FatBackend::Shared(shared) => RoDisk::from_shared(Arc::clone(shared)),
        };
        let label = match &self.backend {
            FatBackend::Path(p) => p.display().to_string(),
            FatBackend::Shared(_) => self.archive_path.display().to_string(),
        };
        let fs = FileSystem::new(disk, FsOptions::new())
            .map_err(|e| FatError::Msg(format!("failed to open FAT image {label}: {e}")))?;
        f(&fs)
    }

    /// Look up a path under root; returns (is_dir, size, mtime).
    fn resolve(root: &Dir<'_, RoDisk>, rel: &str) -> Result<(bool, u64, f64)> {
        if rel.is_empty() {
            return Ok((true, 0, 0.0));
        }
        let (parent, name) = match rel.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", rel),
        };
        let dir = if parent.is_empty() {
            root.clone()
        } else {
            root.open_dir(parent).map_err(FatError::Io)?
        };
        for e in dir.iter() {
            let e = e.map_err(FatError::Io)?;
            let n = e.file_name();
            if n == "." || n == ".." {
                continue;
            }
            if e.attributes().contains(fatfs::FileAttributes::VOLUME_ID) {
                continue;
            }
            if n.eq_ignore_ascii_case(name) {
                let is_dir = e.is_dir();
                let size = if is_dir { 0 } else { e.len() };
                let mtime = dos_datetime_to_unix(e.modified());
                return Ok((is_dir, size, mtime));
            }
        }
        Err(FatError::Msg("not found".into()))
    }

    fn find_entry_info(&self, path: &str) -> Option<FileInfo> {
        let rel = fatfs_rel(path);
        self.with_fs(|fs| {
            let root = fs.root_dir();
            let (is_dir, size, mtime) = Self::resolve(&root, &rel)?;
            Ok(entry_to_file_info(path, is_dir, size, mtime))
        })
        .ok()
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        let rel = fatfs_rel(path);
        self.with_fs(|fs| {
            let root = fs.root_dir();
            let dir = if rel.is_empty() {
                root
            } else {
                root.open_dir(&rel).map_err(FatError::Io)?
            };
            let mut map = BTreeMap::new();
            for e in dir.iter() {
                let e = e.map_err(FatError::Io)?;
                let name = e.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                if e.attributes().contains(fatfs::FileAttributes::VOLUME_ID) {
                    continue;
                }
                let child_path = if path == "/" || path.is_empty() {
                    format!("/{name}")
                } else {
                    format!("{}/{}", path.trim_end_matches('/'), name)
                };
                let is_dir = e.is_dir();
                let size = if is_dir { 0 } else { e.len() };
                let mtime = dos_datetime_to_unix(e.modified());
                map.insert(name, entry_to_file_info(&child_path, is_dir, size, mtime));
            }
            Ok(map)
        })
        .ok()
    }

    fn list_dirents_dir(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let rel = fatfs_rel(path);
        self.with_fs(|fs| {
            let root = fs.root_dir();
            let dir = if rel.is_empty() {
                root
            } else {
                root.open_dir(&rel).map_err(FatError::Io)?
            };
            let mut dents = Vec::new();
            for e in dir.iter() {
                let e = e.map_err(FatError::Io)?;
                let name = e.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                if e.attributes().contains(fatfs::FileAttributes::VOLUME_ID) {
                    continue;
                }
                let is_dir = e.is_dir();
                let (mode, size) = entry_mode_size(is_dir, e.len());
                dents.push(CheapDirent { name, mode, size });
            }
            Ok(dents)
        })
        .ok()
    }

    fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        let rel = fatfs_rel(path);
        if rel.is_empty() {
            return Err(io::Error::new(io::ErrorKind::IsADirectory, "root"));
        }
        self.with_fs(|fs| {
            let mut file = fs.root_dir().open_file(&rel).map_err(FatError::Io)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).map_err(FatError::Io)?;
            Ok(buf)
        })
        .map_err(|e| io::Error::other(e.to_string()))
    }
}

impl MountSource for FatMountSource {
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
            io::Error::new(io::ErrorKind::InvalidInput, "missing FAT path userdata")
        })?;
        let data = self.read_file(&path)?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

/// Detect FAT via boot-sector 0x55AA signature + "FAT" type string or fat* extension.
pub fn looks_like_fat(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        if looks_like_fat_reader(&mut f) {
            return true;
        }
    }
    fat_extension(path)
}

/// Boot-sector probe for nested streams (does not use filename).
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_fat_reader<R: Read + Seek>(reader: &mut R) -> bool {
    let mut boot = [0u8; 512];
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    if reader.read_exact(&mut boot).is_err() {
        return false;
    }
    boot_sector_looks_like_fat(&boot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn load_fat12_fixture_bytes() -> Option<Vec<u8>> {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let bz2 = PathBuf::from(&root).join("tests/folder-symlink.fat12.bz2");
        if !bz2.exists() {
            eprintln!(
                "skip: missing FAT fixture at {} (set RATARMOUNT_PY_ROOT)",
                bz2.display()
            );
            return None;
        }
        let dir = tempfile::tempdir().ok()?;
        let img = dir.path().join("x.fat");
        let status = Command::new("bzip2")
            .args(["-dc"])
            .arg(&bz2)
            .stdout(File::create(&img).ok()?)
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        std::fs::read(&img).ok()
    }

    #[test]
    fn fat12_fixture_list_and_read() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let bz2 = PathBuf::from(&root).join("tests/folder-symlink.fat12.bz2");
        if !bz2.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("x.fat");
        let status = Command::new("bzip2")
            .args(["-dc"])
            .arg(&bz2)
            .stdout(File::create(&img).unwrap())
            .status()
            .unwrap();
        if !status.success() {
            return;
        }
        assert!(looks_like_fat(&img));
        let m = FatMountSource::open(&img).unwrap();
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");

        let list = m.list("/foo").expect("list foo");
        match list {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("fighter")
                        || map.keys().any(|k| k.eq_ignore_ascii_case("fighter"))
                );
            }
            _ => panic!("expected infos"),
        }
    }

    #[test]
    fn open_from_reader_fat12_list_and_read() {
        let Some(bytes) = load_fat12_fixture_bytes() else {
            return;
        };
        assert!(looks_like_fat_reader(&mut Cursor::new(&bytes)));
        let m = FatMountSource::open_from_reader(Cursor::new(bytes), "nested.fat12")
            .expect("open_from_reader");
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");

        let list = m.list("/foo").expect("list foo");
        match list {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("fighter")
                        || map.keys().any(|k| k.eq_ignore_ascii_case("fighter"))
                );
            }
            _ => panic!("expected infos"),
        }
    }

    #[test]
    fn open_from_reader_matches_path_open() {
        let Some(bytes) = load_fat12_fixture_bytes() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("match.fat");
        std::fs::write(&img, &bytes).unwrap();

        let path_src = FatMountSource::open(&img).expect("path open");
        let reader_src = FatMountSource::open_from_reader(Cursor::new(bytes), "match.fat")
            .expect("open_from_reader");

        let path_fi = path_src.lookup("/foo/fighter/ufo", 0).expect("path ufo");
        let reader_fi = reader_src
            .lookup("/foo/fighter/ufo", 0)
            .expect("reader ufo");
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

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let result =
            FatMountSource::open_from_reader(Cursor::new(b"not-a-fat-image!!!!"), "bad.fat");
        assert!(result.is_err(), "should reject non-FAT stream");
        let err = result.err().unwrap();
        assert!(
            err.to_string().contains("not a FAT") || err.to_string().contains("failed to open"),
            "unexpected error: {err}"
        );
    }

    fn fat_image_with_file(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut storage = vec![0u8; 256 * 1024];
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

    /// Regression: cheap readdirplus sizes.
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let payload = b"hello-fat-dirents";
        let bytes = fat_image_with_file("hello.txt", payload);
        let src = FatMountSource::open_from_reader(Cursor::new(bytes), "dirents.fat")
            .expect("open_from_reader");
        let dents = src.list_dirents("/").expect("dirents");
        let d = dents
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case("hello.txt"))
            .expect("hello.txt dirent");
        let fi = src.lookup("/hello.txt", 0).expect("lookup hello.txt");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, payload.len() as u64);
        assert_ne!(d.size, 0);
    }
}
