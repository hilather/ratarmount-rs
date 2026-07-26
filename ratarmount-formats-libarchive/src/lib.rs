//! libarchive-backed archive mount (`backendName=LibarchiveMountSource`).
//!
//! Matches Python `LibarchiveMountSource` strategy: index entries with a sequential
//! `entry_index` as `offsetheader`, re-scan on open to extract file data.

mod ffi;

use std::collections::BTreeSet;
use std::ffi::CString;
use std::io::{self, Cursor, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;
use std::time::Instant;

use log::info;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

use crate::ffi::{
    archive_entry_filetype, archive_entry_gid, archive_entry_mode, archive_entry_mtime,
    archive_entry_mtime_is_set, archive_entry_pathname, archive_entry_size,
    archive_entry_size_is_set, archive_entry_symlink, archive_entry_uid, archive_format_name,
    archive_read_data, archive_read_free, archive_read_new, archive_read_next_header,
    archive_read_open_filename, archive_read_support_filter_all, archive_read_support_format_7zip,
    archive_read_support_format_ar, archive_read_support_format_cab,
    archive_read_support_format_cpio, archive_read_support_format_iso9660,
    archive_read_support_format_lha, archive_read_support_format_rar,
    archive_read_support_format_rar5, archive_read_support_format_tar,
    archive_read_support_format_warc, archive_read_support_format_xar,
    archive_read_support_format_zip, cstr_to_string, error_string, AE_IFDIR, AE_IFLNK, AE_IFMT,
    ARCHIVE_EOF, ARCHIVE_OK, ARCHIVE_WARN,
};

/// Exact Python interop string.
pub const BACKEND_NAME: &str = "LibarchiveMountSource";

#[derive(Debug, Error)]
pub enum LaError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("libarchive: {0}")]
    Lib(String),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, LaError>;

struct ArchiveHandle {
    ptr: *mut ffi::archive,
}

// libarchive archive is used under a mutex; mark Send.
unsafe impl Send for ArchiveHandle {}

impl ArchiveHandle {
    fn open_path(path: &Path) -> Result<Self> {
        unsafe {
            let a = archive_read_new();
            if a.is_null() {
                return Err(LaError::Lib("archive_read_new failed".into()));
            }
            let h = Self { ptr: a };
            support_formats(h.ptr)?;
            use std::os::unix::ffi::OsStrExt;
            let cpath = CString::new(path.as_os_str().as_bytes())
                .map_err(|e| LaError::Msg(e.to_string()))?;
            // block size 10k as python often uses st_blksize; 10240 is fine
            let r = archive_read_open_filename(h.ptr, cpath.as_ptr(), 10240);
            if r != ARCHIVE_OK && r != ARCHIVE_WARN {
                let err = error_string(h.ptr);
                return Err(LaError::Lib(err));
            }
            Ok(h)
        }
    }
}

impl Drop for ArchiveHandle {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                archive_read_free(self.ptr);
            }
            self.ptr = ptr::null_mut();
        }
    }
}

unsafe fn support_formats(a: *mut ffi::archive) -> Result<()> {
    // Filters (decompress)
    let r = archive_read_support_filter_all(a);
    if r != ARCHIVE_OK && r != ARCHIVE_WARN {
        return Err(LaError::Lib(error_string(a)));
    }
    // Formats — skip mtree (false positives). Ignore per-format enable failures.
    let _ = archive_read_support_format_7zip(a);
    let _ = archive_read_support_format_ar(a);
    let _ = archive_read_support_format_cab(a);
    let _ = archive_read_support_format_cpio(a);
    let _ = archive_read_support_format_iso9660(a);
    let _ = archive_read_support_format_lha(a);
    let _ = archive_read_support_format_rar(a);
    let _ = archive_read_support_format_rar5(a);
    let _ = archive_read_support_format_tar(a);
    let _ = archive_read_support_format_warc(a);
    let _ = archive_read_support_format_xar(a);
    let _ = archive_read_support_format_zip(a);
    Ok(())
}

/// Read all entry data for current header into a Vec.
unsafe fn read_entry_data(a: *mut ffi::archive, expected: Option<u64>) -> Result<Vec<u8>> {
    let mut out = if let Some(sz) = expected {
        Vec::with_capacity(sz.min(64 * 1024 * 1024) as usize)
    } else {
        Vec::new()
    };
    let mut buf = [0u8; 1024 * 64];
    loop {
        let n = archive_read_data(a, buf.as_mut_ptr() as *mut _, buf.len());
        if n == 0 {
            break;
        }
        if n < 0 {
            return Err(LaError::Lib(error_string(a)));
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    Ok(out)
}

pub struct LibarchiveMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    /// Guards re-open/scan for extract
    path_lock: Mutex<()>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl LibarchiveMountSource {
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
                        Err(e) => {
                            eprintln!("info: could not load libarchive index ({e}); rebuilding")
                        }
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
            path_lock: Mutex::new(()),
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

        let handle = ArchiveHandle::open_path(archive_path)?;
        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut generated = BTreeSet::new();
        let mut entry_index: i64 = 0;

        unsafe {
            let fmt = cstr_to_string(archive_format_name(handle.ptr));
            if let Some(f) = fmt {
                if f != "none" {
                    info!("libarchive format: {f}");
                }
            }

            loop {
                let mut entry: *mut ffi::archive_entry = ptr::null_mut();
                let r = archive_read_next_header(handle.ptr, &mut entry);
                if r == ARCHIVE_EOF {
                    break;
                }
                if r != ARCHIVE_OK && r != ARCHIVE_WARN {
                    return Err(LaError::Lib(error_string(handle.ptr)));
                }

                let path_c = archive_entry_pathname(entry);
                let path = cstr_to_string(path_c).unwrap_or_default();
                // Skip empty
                if path.is_empty() {
                    let _ = read_entry_data(handle.ptr, None);
                    entry_index += 1;
                    continue;
                }

                let filetype = archive_entry_filetype(entry) as u32;
                let is_dir = (filetype & AE_IFMT) == AE_IFDIR || path.ends_with('/');
                let is_lnk = (filetype & AE_IFMT) == AE_IFLNK;
                let mode_bits = (archive_entry_mode(entry) as u32) & 0o7777;
                let mtime = if archive_entry_mtime_is_set(entry) != 0 {
                    archive_entry_mtime(entry) as f64
                } else {
                    0.0
                };
                let uid = archive_entry_uid(entry);
                let gid = archive_entry_gid(entry);

                let size_set = archive_entry_size_is_set(entry) != 0;
                let declared_size = if size_set {
                    archive_entry_size(entry).max(0) as u64
                } else {
                    0
                };

                let mut linkname = String::new();
                if is_lnk {
                    if let Some(s) = cstr_to_string(archive_entry_symlink(entry)) {
                        linkname = s;
                    }
                }

                // Always consume body (and measure size when unset).
                let data = read_entry_data(
                    handle.ptr,
                    if size_set { Some(declared_size) } else { None },
                )?;
                let size = if size_set {
                    declared_size.max(data.len() as u64)
                } else {
                    data.len() as u64
                };
                if is_lnk && linkname.is_empty() && !data.is_empty() {
                    linkname = String::from_utf8_lossy(&data).into_owned();
                }

                insert_entry(
                    &index,
                    &path,
                    entry_index,
                    if is_dir { 0 } else { size },
                    mtime,
                    mode_bits,
                    is_dir,
                    is_lnk,
                    &linkname,
                    uid,
                    gid,
                    &mut generated,
                )?;
                entry_index += 1;
            }
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
            path_lock: Mutex::new(()),
            options: options.clone(),
        })
    }

    fn extract_entry(&self, entry_index: i64, expected_size: u64) -> Result<Vec<u8>> {
        let _guard = self.path_lock.lock().expect("libarchive lock");
        let handle = ArchiveHandle::open_path(&self.archive_path)?;
        unsafe {
            let mut idx: i64 = 0;
            loop {
                let mut entry: *mut ffi::archive_entry = ptr::null_mut();
                let r = archive_read_next_header(handle.ptr, &mut entry);
                if r == ARCHIVE_EOF {
                    break;
                }
                if r != ARCHIVE_OK && r != ARCHIVE_WARN {
                    return Err(LaError::Lib(error_string(handle.ptr)));
                }
                if idx == entry_index {
                    let data = read_entry_data(handle.ptr, Some(expected_size))?;
                    return Ok(data);
                }
                // skip body
                let _ = read_entry_data(handle.ptr, None)?;
                idx += 1;
            }
        }
        Err(LaError::Msg(format!(
            "failed to find archive entry {entry_index}"
        )))
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_entry(
    index: &SqliteIndex,
    raw_path: &str,
    entry_index: i64,
    size: u64,
    mtime: f64,
    mode_bits: u32,
    is_dir: bool,
    is_lnk: bool,
    linkname: &str,
    uid: i64,
    gid: i64,
    generated: &mut BTreeSet<String>,
) -> Result<()> {
    let full = normpath(raw_path.trim_end_matches('/'));
    if full == "/" || full.is_empty() {
        return Ok(());
    }
    let (path, name) = match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.clone()),
    };
    ensure_parents(index, &path, generated, mtime)?;

    let ifmt = if is_dir {
        libc::S_IFDIR
    } else if is_lnk {
        libc::S_IFLNK
    } else {
        libc::S_IFREG
    };
    let mode = (mode_bits & 0o7777) | ifmt;

    index.insert_file(
        &path,
        &name,
        entry_index, // unique header offset substitute
        0,
        if is_dir { 0 } else { size as i64 },
        mtime,
        mode as i64,
        0,
        linkname,
        uid,
        gid,
        false,
        false,
        false,
        0,
    )?;
    Ok(())
}

fn ensure_parents(
    index: &SqliteIndex,
    path: &str,
    generated: &mut BTreeSet<String>,
    mtime: f64,
) -> Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    let mut cur = String::new();
    for (i, part) in parts.iter().enumerate() {
        let parent = if i == 0 { String::new() } else { cur.clone() };
        cur = if parent.is_empty() {
            format!("/{part}")
        } else {
            format!("{parent}/{part}")
        };
        if generated.contains(&cur) {
            continue;
        }
        generated.insert(cur.clone());
        let mode = (libc::S_IFDIR | 0o755) as i64;
        index.insert_file(
            &parent,
            part,
            -1 - i as i64,
            0,
            0,
            mtime,
            mode,
            0,
            "",
            0,
            0,
            false,
            false,
            true,
            0,
        )?;
    }
    Ok(())
}

impl MountSource for LibarchiveMountSource {
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
        if file_info.mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let ud = userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing libarchive userdata")
        })?;
        let entry_index = ud.offsetheader.unwrap_or(ud.offset) as i64;
        // generated parents use negative header offsets
        if entry_index < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot open generated folder",
            ));
        }
        let data = self
            .extract_entry(entry_index, file_info.size)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Box::new(Cursor::new(data)))
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

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

/// Heuristic: extension/magic suggests a libarchive-handled format not covered by pure backends.
pub fn looks_like_libarchive(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "cab" | "iso" | "xar" | "warc" | "7z" | "rar" | "lha" | "lzh" | "rpm" | "deb"
    ) || {
        // Magic probes
        if let Ok(mut f) = std::fs::File::open(path) {
            let mut magic = [0u8; 8];
            if std::io::Read::read(&mut f, &mut magic).ok() == Some(8) {
                // CAB: MSCF
                if &magic[0..4] == b"MSCF" {
                    return true;
                }
                // 7z
                if &magic[0..6] == b"7z\xBC\xAF\x27\x1C" {
                    return true;
                }
                // RAR
                if &magic[0..4] == b"Rar!" {
                    return true;
                }
                // ISO often starts with zeros; CD001 at 0x8001
            }
            // WARC
            let _ = f.seek(SeekFrom::Start(0));
            let mut head = [0u8; 5];
            if std::io::Read::read(&mut f, &mut head).ok() == Some(5) && &head == b"WARC/" {
                return true;
            }
            // XAR
            let _ = f.seek(SeekFrom::Start(0));
            let mut xar = [0u8; 4];
            if std::io::Read::read(&mut f, &mut xar).ok() == Some(4) && &xar == b"xar!" {
                return true;
            }
            // ISO9660 primary volume descriptor
            if f.seek(SeekFrom::Start(0x8001)).is_ok() {
                let mut cd = [0u8; 5];
                if std::io::Read::read(&mut f, &mut cd).ok() == Some(5) && &cd == b"CD001" {
                    return true;
                }
            }
        }
        false
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
    fn open_cab() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(&root).join("tests/single-file.cab");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("c.index.sqlite");
        let m =
            LibarchiveMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
                .expect("open cab");
        let fi = m.lookup("/bar", 0).expect("bar");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }
}
