//! Unix `ar` archive format (`backendName=ARMountSource`).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
    SQLiteIndexedTarUserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "ARMountSource";
const MAGIC: &[u8; 8] = b"!<arch>\n";
const HEADER_SIZE: usize = 60;

#[derive(Debug, Error)]
pub enum ArError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, ArError>;

pub struct ArMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl ArMountSource {
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
                let meta_ok = std::fs::metadata(ip)
                    .map(|m| m.len() > 0)
                    .unwrap_or(false);
                if meta_ok {
                    match Self::open_existing(&archive_path, ip, options) {
                        Ok(s) => return Ok(s),
                        Err(e) => eprintln!("info: could not load ar index ({e}); rebuilding"),
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

    fn open_existing(archive_path: &Path, index_path: &Path, options: &OpenOptions) -> Result<Self> {
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
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let mut file = File::open(archive_path)?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(ArError::Msg(format!("invalid AR magic: {magic:?}")));
        }

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut header = [0u8; HEADER_SIZE];

        loop {
            let header_offset = file.stream_position()?;
            match file.read(&mut header)? {
                0 => break,
                n if n < HEADER_SIZE => {
                    return Err(ArError::Msg("truncated AR header".into()));
                }
                _ => {}
            }
            if &header[58..60] != b"`\n" {
                return Err(ArError::Msg(format!(
                    "invalid AR header end: {:?}",
                    &header[58..60]
                )));
            }

            let name_raw = &header[0..16];
            let name = String::from_utf8_lossy(name_raw)
                .trim_end_matches([' ', '\0', '/'])
                .to_string();
            let mtime = parse_dec(&header[16..28]).unwrap_or(0) as f64;
            let uid = parse_dec(&header[28..34]).unwrap_or(0);
            let gid = parse_dec(&header[34..40]).unwrap_or(0);
            let mode_bits = parse_oct(&header[40..48]).unwrap_or(0o644);
            let size = parse_dec(&header[48..58]).unwrap_or(0);
            let data_offset = file.stream_position()?;

            // Skip special GNU/BSD tables for index of regular files only
            let is_special = name.is_empty()
                || name == "/"
                || name == "//"
                || name.starts_with("#1/");

            if !is_special && !name.is_empty() {
                let full = normpath(&name);
                let (path, base) = split_name(&full);
                let mode = (mode_bits & 0o7777) | libc::S_IFREG as u32;
                index.insert_file(
                    &path,
                    &base,
                    header_offset as i64,
                    data_offset as i64,
                    size as i64,
                    mtime,
                    mode as i64,
                    0,
                    "",
                    uid as i64,
                    gid as i64,
                    false,
                    false,
                    false,
                    0,
                )?;
            }

            // Advance past data + even padding
            let mut skip = size;
            if size % 2 == 1 {
                skip += 1;
            }
            file.seek(SeekFrom::Current(skip as i64))?;
        }

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

impl MountSource for ArMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index
            .list(path)
            .ok()
            .flatten()
            .map(ListResult::Infos)
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
        let ud = userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing AR userdata")
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

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

pub fn looks_like_ar(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 8];
        if f.read(&mut magic).ok() == Some(8) && &magic == MAGIC {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ar") || e.eq_ignore_ascii_case("a") || e.eq_ignore_ascii_case("deb"))
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

fn parse_dec(bytes: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if s.is_empty() {
        return Some(0);
    }
    s.parse().ok()
}

fn parse_oct(bytes: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if s.is_empty() {
        return Some(0o644);
    }
    u32::from_str_radix(s, 8).ok()
}

fn split_name(full: &str) -> (String, String) {
    match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.to_string()),
    }
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

    #[test]
    fn open_single_file_ar() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/single-file.ar");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("a.index.sqlite");
        let ar = ArMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = ar.lookup("/bar", 0).expect("bar");
        assert_eq!(fi.size, 4);
        let mut r = ar.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }
}
