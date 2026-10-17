//! ISO 9660 MountSource with random access via extent LBAs (`backendName=ISO9660MountSource`).
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Nested ISO members can be opened without `/tmp` when the outer archive yields a
//! seekable stream: [`Iso9660MountSource::open_from_reader`] indexes from any
//! `Read + Seek` and retains a mutex-shared handle for extent stencil opens.
//! Large images are never loaded fully into RAM.
//!
//! # Names and file types
//!
//! The file type comes from the ISO 9660 directory record (the directory flag),
//! not from Rock Ridge PX `S_IFMT`. PX contributes only permission bits
//! (`mode & 0o7777`). `SL` is a symlink only on a non-directory record; a
//! directory `SL` is ignored (empty link name, size 0) and its children stay.
//! Character and block devices, FIFOs, sockets, and `PN` are regular files:
//! `FileInfo` has no device number, and a device type would ask FUSE for a
//! kernel device node. The ISO data length is kept. Joliet names are used when
//! that tree parses and no Rock Ridge `NM` exists. A damaged Joliet tree logs
//! one warning and the index keeps the primary tree. Sidecar
//! `isoMetadataVersion` is `rock-ridge-joliet-v3`.
// #102: shadow std print macros so a closed pipe does not panic (exit 101).
#[macro_use]
extern crate ratarmount_core;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratarmount_compress::{SeekRead, StenciledFile};
use ratarmount_core::{
    normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
    OpenOptions, SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "ISO9660MountSource";
const SECTOR: u64 = 2048;
mod iso;

// Reject old sidecars that contain only ISO aliases and default metadata.
const ISO_METADATA_VERSION: &str = "rock-ridge-joliet-v3";

#[derive(Debug, Error)]
pub enum IsoError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, IsoError>;

/// Where ISO bytes live for member open (path re-open vs shared seekable stream).
enum IsoBackend {
    /// Path-based: `File::open` + [`StenciledFile`] on extent offsets.
    Path(PathBuf),
    /// Nested / stream open: mutex-shared `Read + Seek` (no full-image RAM load).
    Shared(Arc<Mutex<Box<dyn SeekRead>>>),
}

/// Random-access slice of a shared ISO reader (one file extent).
struct SharedSeekRegion {
    shared: Arc<Mutex<Box<dyn SeekRead>>>,
    file_offset: u64,
    len: u64,
    pos: u64,
}

impl SharedSeekRegion {
    fn new(shared: Arc<Mutex<Box<dyn SeekRead>>>, file_offset: u64, len: u64) -> Self {
        Self {
            shared,
            file_offset,
            len,
            pos: 0,
        }
    }
}

impl Read for SharedSeekRegion {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let max = ((self.len - self.pos) as usize).min(buf.len());
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| io::Error::other("shared iso reader poisoned"))?;
        guard.seek(SeekFrom::Start(self.file_offset + self.pos))?;
        let n = guard.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SharedSeekRegion {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.len as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
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

pub struct Iso9660MountSource {
    /// Path or virtual label (logs / index metadata).
    #[allow(dead_code)]
    archive_path: PathBuf,
    backend: IsoBackend,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl Iso9660MountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let index_path_buf: Option<PathBuf> = if options.index_in_memory {
            None
        } else {
            Some(
                index_path
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| default_index_path(&archive_path)),
            )
        };

        if let Some(ref ip) = index_path_buf {
            if !recreate && ip.exists() {
                let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
                if meta_ok {
                    match Self::open_existing(&archive_path, ip, options) {
                        Ok(s) => return Ok(s),
                        Err(e) => eprintln!("info: could not load iso9660 index ({e}); rebuilding"),
                    }
                }
            }
        }
        Self::create_index(
            &archive_path,
            index_path_buf.as_deref(),
            options,
            product_version,
        )
    }

    /// Index and open an ISO 9660 image from any `Read + Seek` source.
    ///
    /// For nested AutoMount / HTTP Range / in-memory images without materializing to
    /// `/tmp`. The reader is retained under a mutex for extent stencil opens — the
    /// full image is **not** loaded into RAM.
    ///
    /// `archive_label` is used for logs and index metadata (may be a nested member
    /// name). Prefer `index_path: None` or `options.index_in_memory` for nested mounts.
    pub fn open_from_reader<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let index_path_buf: Option<PathBuf> = if options.index_in_memory {
            None
        } else {
            index_path.map(|p| p.to_path_buf())
        };

        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let mut reader = reader;
        let size = reader.seek(SeekFrom::End(0)).unwrap_or(0);
        reader.seek(SeekFrom::Start(0))?;

        // Index while owning the reader, then wrap for shared open() I/O.
        // (Cannot share under mutex during walk without an independent handle.)
        let index = build_iso_index(
            &mut reader,
            index_path_buf.as_deref(),
            options,
            product_version,
            StatsSource::Synthetic(size),
        )?;
        reader.seek(SeekFrom::Start(0))?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> = Arc::new(Mutex::new(Box::new(reader)));

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        Ok(Self {
            archive_path,
            backend: IsoBackend::Shared(shared),
            index,
            options: options.clone(),
        })
    }

    fn open_existing(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
    ) -> Result<Self> {
        // Index + fingerprint first (same order as TAR/ZIP/7z): reject a sibling
        // index for a replaced archive before trusting files rows / extent opens.
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        if index
            .metadata()?
            .get("isoMetadataVersion")
            .map(String::as_str)
            != Some(ISO_METADATA_VERSION)
        {
            return Err(IsoError::Msg("ISO name/metadata parser changed".into()));
        }
        // Reject sibling indexes for a replaced archive (size/mtime/edge hash).
        // Missing tarstats still Ok (legacy indexes).
        index.check_tarstats_matches_archive(archive_path)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            backend: IsoBackend::Path(archive_path.to_path_buf()),
            index,
            options: options.clone(),
        })
    }

    fn create_index(
        archive_path: &Path,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let _ = options;
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let mut file = File::open(archive_path)?;
        let index = build_iso_index(
            &mut file,
            index_path,
            options,
            product_version,
            StatsSource::Path(archive_path),
        )?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            backend: IsoBackend::Path(archive_path.to_path_buf()),
            index,
            options: options.clone(),
        })
    }
}

impl MountSource for Iso9660MountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index.list(path).ok().flatten().map(ListResult::Infos)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        self.index
            .list_mode(path)
            .ok()
            .flatten()
            .map(ListModeResult::Modes)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.index.list_dirents(path).ok().flatten().map(|rows| {
            rows.into_iter()
                .map(|d| CheapDirent {
                    name: d.name,
                    mode: d.mode,
                    size: d.size,
                })
                .collect()
        })
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return None;
        }
        self.index.search_cheap(pattern).ok()
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.index.lookup(path, file_version).ok().flatten()
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
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot open an ISO symlink as file data",
            ));
        }
        let ud = userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing iso9660 userdata")
        })?;
        match &self.backend {
            IsoBackend::Path(path) => {
                let file = File::open(path)?;
                Ok(Box::new(StenciledFile::new(
                    file,
                    vec![(ud.offset, file_info.size)],
                )))
            }
            IsoBackend::Shared(shared) => Ok(Box::new(SharedSeekRegion::new(
                Arc::clone(shared),
                ud.offset,
                file_info.size,
            ))),
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

enum StatsSource<'a> {
    Path(&'a Path),
    Synthetic(u64),
}

/// Parse PVD + walk directory tree into a SQLite index (any `Read + Seek`).
fn build_iso_index<R: Read + Seek>(
    file: &mut R,
    index_path: Option<&Path>,
    options: &OpenOptions,
    product_version: &str,
    stats: StatsSource<'_>,
) -> Result<SqliteIndex> {
    let entries = iso::read_entries(file)?;
    let index = SqliteIndex::create_writable_for_open(index_path, options)?;
    index.begin_write()?;
    let mut paths = vec![String::new(); entries.len()];
    for (id, node) in entries.iter().enumerate().skip(1) {
        let rec = &node.record;
        let Some(name) = rec.rr.name.as_ref().or(rec.name.as_ref()) else {
            continue;
        };
        let full = format!("{}/{name}", paths[node.parent]);
        let (path, base) = split_name(&normpath(&full));
        let data_off = i64::from(rec.extent) * SECTOR as i64;
        let link = rec.rr.link.as_deref().unwrap_or("");
        let size = if rec.rr.link.is_some() {
            link.len() as i64
        } else if rec.is_dir {
            0
        } else {
            i64::from(rec.size)
        };
        index.insert_file(
            &path,
            &base,
            data_off,
            data_off,
            size,
            rec.rr.mtime.unwrap_or(rec.mtime),
            i64::from(rec.mode()),
            0,
            link,
            i64::from(rec.rr.uid),
            i64::from(rec.rr.gid),
            false,
            false,
            false,
            0,
        )?;
        paths[id] = full;
    }
    index.store_metadata_key_value("isoMetadataVersion", ISO_METADATA_VERSION)?;

    index.store_versions(product_version)?;
    index.store_metadata_key_value("backendName", BACKEND_NAME)?;
    match stats {
        StatsSource::Path(path) => store_stats(&index, path)?,
        StatsSource::Synthetic(size) => store_stats_size(&index, size)?,
    }
    index.commit_write()?;
    Ok(index.into_read_only()?)
}

fn split_name(full: &str) -> (String, String) {
    match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.to_string()),
    }
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

pub fn looks_like_iso9660(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        if f.seek(SeekFrom::Start(0x8001)).is_ok() {
            let mut cd = [0u8; 5];
            if f.read(&mut cd).ok() == Some(5) && &cd == b"CD001" {
                return true;
            }
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("iso"))
}

/// True when `reader` has a primary volume descriptor at sector 16 (`CD001`).
pub fn looks_like_iso9660_reader<R: Read + Seek>(reader: &mut R) -> bool {
    if reader.seek(SeekFrom::Start(0x8001)).is_err() {
        return false;
    }
    let mut cd = [0u8; 5];
    matches!(reader.read(&mut cd), Ok(5) if &cd == b"CD001")
}

pub fn looks_like_iso(path: &Path) -> bool {
    looks_like_iso9660(path)
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    // Shared helper: size/mtime + first/last 512 SHA-256 for warm-open fingerprint.
    // Path-backed cold create always has a real archive file (see create_index).
    index.store_tarstats_for_path(path)?;
    Ok(())
}

fn store_stats_size(index: &SqliteIndex, size: u64) -> Result<()> {
    let json = format!("{{\"st_size\":{size},\"st_mtime\":0,\"st_mtime_ns\":0}}");
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

#[cfg(test)]
mod regression_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    /// Minimal single-file ISO 9660 (PVD + root dir + one data extent). Always-on.
    fn synthetic_iso(name: &str, payload: &[u8]) -> Vec<u8> {
        const SECTOR: usize = 2048;
        let file_extent = 19u32;
        let root_extent = 18u32;
        let mut img = vec![0u8; 20 * SECTOR];

        fn dir_rec(extent: u32, size: u32, is_dir: bool, name: &[u8]) -> Vec<u8> {
            let name_len = name.len();
            let mut len = 33 + name_len;
            if len % 2 == 1 {
                len += 1;
            }
            let mut rec = vec![0u8; len];
            rec[0] = len as u8;
            rec[2..6].copy_from_slice(&extent.to_le_bytes());
            rec[6..10].copy_from_slice(&extent.to_be_bytes());
            rec[10..14].copy_from_slice(&size.to_le_bytes());
            rec[14..18].copy_from_slice(&size.to_be_bytes());
            rec[25] = if is_dir { 0x02 } else { 0 };
            rec[28..30].copy_from_slice(&1u16.to_le_bytes());
            rec[30..32].copy_from_slice(&1u16.to_be_bytes());
            rec[32] = name_len as u8;
            rec[33..33 + name_len].copy_from_slice(name);
            rec
        }

        let pvd = 16 * SECTOR;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1;
        let root_rec = dir_rec(root_extent, SECTOR as u32, true, &[0]);
        img[pvd + 156..pvd + 156 + root_rec.len()].copy_from_slice(&root_rec);

        let root = 18 * SECTOR;
        let r1 = dir_rec(root_extent, SECTOR as u32, true, &[0]);
        let r2 = dir_rec(root_extent, SECTOR as u32, true, &[1]);
        let r3 = dir_rec(file_extent, payload.len() as u32, false, name.as_bytes());
        let mut off = root;
        for r in [r1, r2, r3] {
            img[off..off + r.len()].copy_from_slice(&r);
            off += r.len();
        }

        let data = 19 * SECTOR;
        img[data..data + payload.len()].copy_from_slice(payload);
        img
    }

    fn load_single_file_iso() -> Option<Vec<u8>> {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let bz = PathBuf::from(&root).join("tests/single-file.iso.bz2");
        if !bz.exists() {
            eprintln!(
                "skip: missing ISO fixture at {} (set RATARMOUNT_PY_ROOT)",
                bz.display()
            );
            return None;
        }
        let compressed = std::fs::read(&bz).ok()?;
        let mut decoder = bzip2::read::BzDecoder::new(&compressed[..]);
        let mut plain = Vec::new();
        decoder.read_to_end(&mut plain).ok()?;
        Some(plain)
    }

    #[test]
    fn open_single_file_iso_bz2() {
        let Some(plain) = load_single_file_iso() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let iso = dir.path().join("single-file.iso");
        std::fs::File::create(&iso)
            .unwrap()
            .write_all(&plain)
            .unwrap();
        assert!(looks_like_iso(&iso));
        let idx = dir.path().join("i.index.sqlite");
        let m = Iso9660MountSource::open(&iso, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        // ISO Level 1 names are uppercase
        let fi = m
            .lookup("/BAR", 0)
            .or_else(|| m.lookup("/bar", 0))
            .expect("BAR");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }

    #[test]
    fn open_from_reader_single_file_iso() {
        let Some(plain) = load_single_file_iso() else {
            return;
        };
        assert!(looks_like_iso9660_reader(&mut Cursor::new(&plain)));
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = Iso9660MountSource::open_from_reader(
            Cursor::new(plain),
            "single-file.iso",
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader");
        let fi = m
            .lookup("/BAR", 0)
            .or_else(|| m.lookup("/bar", 0))
            .expect("BAR");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }

    /// Regression: cheap list_dirents must expose index sizes (readdirplus TTL).
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let payload = b"hello-iso-dirents";
        let iso = synthetic_iso("hello.txt", payload);
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let src = Iso9660MountSource::open_from_reader(
            Cursor::new(iso),
            "dirents.iso",
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader");

        let dents = src.list_dirents("/").expect("dirents");
        let d = dents.iter().find(|e| e.name == "hello.txt").unwrap();
        assert_eq!(d.size, payload.len() as u64);
        assert_eq!(src.lookup("/hello.txt", 0).unwrap().size, d.size);
    }

    #[test]
    fn open_from_reader_matches_path_open() {
        let Some(plain) = load_single_file_iso() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let iso = dir.path().join("single-file.iso");
        std::fs::File::create(&iso)
            .unwrap()
            .write_all(&plain)
            .unwrap();

        let path_src =
            Iso9660MountSource::open(&iso, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let reader_src = Iso9660MountSource::open_from_reader(
            Cursor::new(plain),
            "single-file.iso",
            None,
            &opts,
            "0.1.0",
        )
        .unwrap();

        let path_fi = path_src
            .lookup("/BAR", 0)
            .or_else(|| path_src.lookup("/bar", 0))
            .expect("path BAR");
        let reader_fi = reader_src
            .lookup("/BAR", 0)
            .or_else(|| reader_src.lookup("/bar", 0))
            .expect("reader BAR");
        assert_eq!(path_fi.size, reader_fi.size);

        let mut a = Vec::new();
        let mut b = Vec::new();
        path_src
            .open(&path_fi, 0)
            .unwrap()
            .read_to_end(&mut a)
            .unwrap();
        reader_src
            .open(&reader_fi, 0)
            .unwrap()
            .read_to_end(&mut b)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a, b"foo\n");
    }

    /// Write `plain` ISO bytes to `path`, optionally patching the BAR payload
    /// (`foo\n` at extent 31 in the Python single-file fixture) for a second variant.
    fn write_iso_variant(path: &Path, plain: &[u8], payload: &[u8; 4]) {
        let mut bytes = plain.to_vec();
        // Fixture: BAR.;1 extent=31, size=4, payload "foo\n" at sector 31.
        let off = 31 * 2048;
        assert!(
            plain.len() > off + 4,
            "fixture too small to patch BAR payload"
        );
        assert_eq!(&plain[off..off + 4], b"foo\n", "unexpected fixture payload");
        bytes[off..off + 4].copy_from_slice(payload);
        std::fs::write(path, &bytes).unwrap();
    }

    /// Regression: open_existing rejects when archive size/mtime no longer match tarstats.
    #[test]
    fn warm_index_rejects_when_archive_size_or_mtime_changes() {
        let Some(plain) = load_single_file_iso() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.iso");
        write_iso_variant(&archive, &plain, b"foo\n");
        let index = dir.path().join("swap.iso.index.sqlite");
        let opts = OpenOptions::default();

        let src = Iso9660MountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src
            .lookup("/BAR", 0)
            .or_else(|| src.lookup("/bar", 0))
            .expect("lookup v1");
        let mut buf = Vec::new();
        src.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
        drop(src);
        assert!(index.exists());

        // Matching archive still opens warm.
        Iso9660MountSource::open_existing(&archive, &index, &opts)
            .expect("warm match must succeed");

        // Replace archive content (size change) while reusing the sibling index path.
        std::fs::write(&archive, b"not-an-iso-but-different-size").unwrap();

        match Iso9660MountSource::open_existing(&archive, &index, &opts) {
            Ok(_) => panic!("stale index must fail open_existing after archive replace"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("size")
                        || msg.contains("mtime")
                        || msg.contains("mismatch")
                        || msg.contains("fingerprint"),
                    "unexpected error (expected tarstats mismatch): {msg}"
                );
            }
        }
    }

    /// Regression: warm ISO open rebuilds when archive content no longer matches tarstats.
    #[test]
    fn warm_index_rebuilds_when_archive_content_replaced() {
        let Some(plain) = load_single_file_iso() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.iso");
        write_iso_variant(&archive, &plain, b"foo\n");
        let index = dir.path().join("swap.iso.index.sqlite");
        let opts = OpenOptions::default();

        let src = Iso9660MountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src
            .lookup("/BAR", 0)
            .or_else(|| src.lookup("/bar", 0))
            .expect("lookup v1");
        let mut buf = Vec::new();
        src.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
        drop(src);
        assert!(index.exists());

        // Same-size payload swap (edge/full hash fingerprint catches replace).
        write_iso_variant(&archive, &plain, b"bar\n");

        // recreate=false: tarstats mismatch must rebuild, not serve stale extent rows.
        let src2 = Iso9660MountSource::open(&archive, Some(&index), &opts, "test", false)
            .expect("warm rebuild");
        let fi2 = src2
            .lookup("/BAR", 0)
            .or_else(|| src2.lookup("/bar", 0))
            .expect("lookup v2");
        let mut buf2 = Vec::new();
        src2.open(&fi2, 0).unwrap().read_to_end(&mut buf2).unwrap();
        assert_eq!(
            buf2, b"bar\n",
            "must serve new ISO data after tarstats mismatch rebuild"
        );
    }
}
