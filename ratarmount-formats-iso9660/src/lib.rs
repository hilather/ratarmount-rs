//! ISO 9660 MountSource with random access via extent LBAs (`backendName=ISO9660MountSource`).

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "ISO9660MountSource";
const SECTOR: u64 = 2048;
const PVD_OFFSET: u64 = 16 * SECTOR;

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

pub struct Iso9660MountSource {
    archive_path: PathBuf,
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

    fn open_existing(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
    ) -> Result<Self> {
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
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
        file.seek(SeekFrom::Start(PVD_OFFSET))?;
        let mut pvd = vec![0u8; SECTOR as usize];
        file.read_exact(&mut pvd)?;
        if pvd.first() != Some(&1) || pvd.get(1..6) != Some(b"CD001") {
            return Err(IsoError::Msg(
                "Not a valid ISO 9660 image (missing primary volume descriptor)".into(),
            ));
        }

        let root = parse_directory_record(&pvd, 156)
            .ok_or_else(|| IsoError::Msg("ISO 9660 PVD has no root directory".into()))?;

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut seen = HashSet::new();
        walk_directory(&mut file, root.extent, root.size, "", &index, &mut seen)?;

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats(&index, archive_path)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        let index = index.into_read_only()?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
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
        let ud = userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing iso9660 userdata")
        })?;
        let file = File::open(&self.archive_path)?;
        Ok(Box::new(StenciledFile::new(
            file,
            vec![(ud.offset, file_info.size)],
        )))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

struct DirRec {
    length: usize,
    extent: u32,
    size: u32,
    is_dir: bool,
    name: Option<String>,
}

fn read_both_endian_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn parse_directory_record(data: &[u8], offset: usize) -> Option<DirRec> {
    if offset >= data.len() {
        return None;
    }
    let length = data[offset] as usize;
    if length == 0 {
        return None;
    }
    if offset + length > data.len() {
        return None;
    }
    let rec = &data[offset..offset + length];
    let extent = read_both_endian_u32(rec, 2);
    let size = read_both_endian_u32(rec, 10);
    let flags = rec[25];
    let name_len = rec[32] as usize;
    let name_bytes = &rec[33..33 + name_len.min(rec.len().saturating_sub(33))];
    let name = if name_bytes == b"\x00" || name_bytes == b"\x01" {
        None
    } else {
        let raw = String::from_utf8_lossy(name_bytes);
        // Strip ISO version suffix ";1"
        let stripped = raw.split(';').next().unwrap_or(&raw).trim_end_matches('.');
        Some(stripped.to_string())
    };
    Some(DirRec {
        length,
        extent,
        size,
        is_dir: flags & 0x02 != 0,
        name,
    })
}

fn read_sector(file: &mut File, sector: u32) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(u64::from(sector) * SECTOR))?;
    let mut data = vec![0u8; SECTOR as usize];
    file.read_exact(&mut data)?;
    Ok(data)
}

fn walk_directory(
    file: &mut File,
    extent: u32,
    size: u32,
    path_prefix: &str,
    index: &SqliteIndex,
    seen: &mut HashSet<u32>,
) -> Result<()> {
    if !seen.insert(extent) {
        return Ok(());
    }
    let mut remaining = size as i64;
    let mut sector = extent;
    while remaining > 0 {
        let data = read_sector(file, sector)?;
        let to_parse = (SECTOR as i64).min(remaining) as usize;
        let mut offset = 0usize;
        while offset < to_parse {
            if data[offset] == 0 {
                break;
            }
            let Some(rec) = parse_directory_record(&data, offset) else {
                break;
            };
            offset += rec.length;
            let Some(name) = rec.name else {
                continue;
            };
            let full = if path_prefix.is_empty() {
                name.clone()
            } else {
                format!("{path_prefix}/{name}")
            };
            let full = full.trim_start_matches('/').to_string();
            let nfull = normpath(&full);
            let (path, base) = split_name(&nfull);
            let data_off = u64::from(rec.extent) * SECTOR;
            if rec.is_dir {
                let mode = (ratarmount_core::S_IFDIR | 0o755) as i64;
                index.insert_file(
                    &path,
                    &base,
                    data_off as i64,
                    data_off as i64,
                    0,
                    0.0,
                    mode,
                    0,
                    "",
                    0,
                    0,
                    false,
                    false,
                    false,
                    0,
                )?;
                walk_directory(file, rec.extent, rec.size, &full, index, seen)?;
            } else {
                let mode = (ratarmount_core::S_IFREG | 0o644) as i64;
                index.insert_file(
                    &path,
                    &base,
                    data_off as i64,
                    data_off as i64,
                    rec.size as i64,
                    0.0,
                    mode,
                    0,
                    "",
                    0,
                    0,
                    false,
                    false,
                    false,
                    0,
                )?;
            }
        }
        remaining -= SECTOR as i64;
        sector += 1;
    }
    Ok(())
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

pub fn looks_like_iso(path: &Path) -> bool {
    looks_like_iso9660(path)
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    let json = format!(
        "{{\"st_size\":{},\"st_mtime\":{},\"st_mtime_ns\":{}}}",
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec()
    );
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn open_single_file_iso_bz2() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let bz = PathBuf::from(&root).join("tests/single-file.iso.bz2");
        if !bz.exists() {
            return;
        }
        let compressed = std::fs::read(&bz).unwrap();
        let mut decoder = bzip2::read::BzDecoder::new(&compressed[..]);
        let mut plain = Vec::new();
        decoder.read_to_end(&mut plain).unwrap();
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
}
