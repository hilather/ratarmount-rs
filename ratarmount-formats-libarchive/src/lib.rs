//! libarchive-backed archive mount (`backendName=LibarchiveMountSource`).
//!
//! Matches Python `LibarchiveMountSource` strategy: index entries with a sequential
//! `entry_index` as `offsetheader`, re-scan on open to extract file data.
//!
//! ## Compression filters (including lrzip)
//!
//! Opens enable [`archive_read_support_filter_all`](ffi::archive_read_support_filter_all),
//! which includes the **lrzip** filter when the system libarchive was built with it
//! ([`archive_read_support_filter_lrzip`](ffi::archive_read_support_filter_lrzip)).
//! That filter typically shells out to the external `lrzip -d` program at read time.
//!
//! Python keeps pure random-access for lrzip on this backend only (no custom CLI
//! materialize). Single-stream `.lrz` files use a second open with the **raw** format
//! handler after archive formats fail to bid (same as Python's two-phase open).

mod ffi;

use std::collections::BTreeSet;
use std::ffi::CString;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;
use std::time::Instant;

use log::info;
use ratarmount_core::{
    normpath, CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

#[cfg(libarchive_has_rar5)]
use crate::ffi::archive_read_support_format_rar5;
use crate::ffi::{
    archive_entry_filetype, archive_entry_gid, archive_entry_mode, archive_entry_mtime,
    archive_entry_mtime_is_set, archive_entry_pathname, archive_entry_size,
    archive_entry_size_is_set, archive_entry_symlink, archive_entry_uid, archive_filter_count,
    archive_filter_name, archive_format_name, archive_read_data, archive_read_free,
    archive_read_new, archive_read_next_header, archive_read_open_filename,
    archive_read_support_filter_all, archive_read_support_filter_lrzip,
    archive_read_support_format_7zip, archive_read_support_format_ar,
    archive_read_support_format_cab, archive_read_support_format_cpio,
    archive_read_support_format_iso9660, archive_read_support_format_lha,
    archive_read_support_format_rar, archive_read_support_format_raw,
    archive_read_support_format_tar, archive_read_support_format_warc,
    archive_read_support_format_xar, archive_read_support_format_zip, cstr_to_string, error_string,
    AE_IFDIR, AE_IFLNK, AE_IFMT, ARCHIVE_EOF, ARCHIVE_OK, ARCHIVE_WARN,
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
    /// True when opened with the raw format handler only (compressed single stream).
    raw: bool,
}

// libarchive archive is used under a mutex; mark Send.
unsafe impl Send for ArchiveHandle {}

impl ArchiveHandle {
    /// Python-style two-phase open: archive formats first, then raw + filters.
    fn open_path(path: &Path) -> Result<Self> {
        match Self::open_path_inner(path, /*allow_archives*/ true) {
            Ok(h) => Ok(h),
            Err(archive_err) => match Self::open_path_inner(path, /*allow_archives*/ false) {
                Ok(h) => Ok(h),
                Err(raw_err) => Err(LaError::Lib(format!(
                    "archive open failed ({archive_err}); raw/filter open failed ({raw_err})"
                ))),
            },
        }
    }

    fn open_path_inner(path: &Path, allow_archives: bool) -> Result<Self> {
        unsafe {
            let a = archive_read_new();
            if a.is_null() {
                return Err(LaError::Lib("archive_read_new failed".into()));
            }
            let h = Self {
                ptr: a,
                raw: !allow_archives,
            };
            support_formats(h.ptr, allow_archives)?;
            use std::os::unix::ffi::OsStrExt;
            let cpath = CString::new(path.as_os_str().as_bytes())
                .map_err(|e| LaError::Msg(e.to_string()))?;
            // block size 10k as python often uses st_blksize; 10240 is fine
            let r = archive_read_open_filename(h.ptr, cpath.as_ptr(), 10240);
            if r != ARCHIVE_OK && r != ARCHIVE_WARN {
                let err = error_string(h.ptr);
                return Err(LaError::Lib(err));
            }
            // Raw open must have at least one non-none filter (Python check).
            if !allow_archives && !has_non_none_filter(h.ptr) {
                return Err(LaError::Lib(
                    "raw open had no compression filter (not a filtered stream)".into(),
                ));
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

/// Enable decompress filters + formats.
///
/// `allow_archives`: when true, enable container formats (tar/zip/…); when false,
/// enable **only** the raw handler so filters (gzip/lrzip/…) can expose a single stream.
/// Do not mix raw with other format handlers (libarchive caveat).
unsafe fn support_formats(a: *mut ffi::archive, allow_archives: bool) -> Result<()> {
    // Filters (decompress). Includes lrzip when built into system libarchive.
    let r = archive_read_support_filter_all(a);
    if r != ARCHIVE_OK && r != ARCHIVE_WARN {
        return Err(LaError::Lib(error_string(a)));
    }
    if !allow_archives {
        let r = archive_read_support_format_raw(a);
        if r != ARCHIVE_OK && r != ARCHIVE_WARN {
            return Err(LaError::Lib(error_string(a)));
        }
        return Ok(());
    }
    // Formats — skip mtree (false positives). Ignore per-format enable failures.
    let _ = archive_read_support_format_7zip(a);
    let _ = archive_read_support_format_ar(a);
    let _ = archive_read_support_format_cab(a);
    let _ = archive_read_support_format_cpio(a);
    let _ = archive_read_support_format_iso9660(a);
    let _ = archive_read_support_format_lha(a);
    let _ = archive_read_support_format_rar(a);
    // RAR5 requires libarchive ≥ 3.4; older EL/Rocky 8 only have classic RAR.
    #[cfg(libarchive_has_rar5)]
    let _ = archive_read_support_format_rar5(a);
    let _ = archive_read_support_format_tar(a);
    let _ = archive_read_support_format_warc(a);
    let _ = archive_read_support_format_xar(a);
    let _ = archive_read_support_format_zip(a);
    Ok(())
}

unsafe fn has_non_none_filter(a: *mut ffi::archive) -> bool {
    let n = archive_filter_count(a);
    for i in 0..n {
        if let Some(name) = cstr_to_string(archive_filter_name(a, i)) {
            if name != "none" {
                return true;
            }
        }
    }
    false
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
        // Reject sibling indexes for a replaced archive (size/mtime/edge hash).
        // Missing tarstats still Ok (legacy indexes).
        index.check_tarstats_matches_archive(archive_path)?;
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
        let index = SqliteIndex::create_writable_for_open(index_path, options)?;
        index.begin_write()?;
        let mut generated = BTreeSet::new();
        let mut entry_index: i64 = 0;
        let raw_stream = handle.raw;
        let raw_display_name = if raw_stream {
            Some(raw_entry_name_from_path(archive_path))
        } else {
            None
        };

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
                let mut path = cstr_to_string(path_c).unwrap_or_default();
                // Raw single-stream: invent a stable basename (Python tarFileName strip).
                if entry_index == 0 {
                    if let Some(ref name) = raw_display_name {
                        path = name.clone();
                    }
                }
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
        ratarmount_core::S_IFDIR
    } else if is_lnk {
        ratarmount_core::S_IFLNK
    } else {
        ratarmount_core::S_IFREG
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
        let mode = (ratarmount_core::S_IFDIR | 0o755) as i64;
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

/// lrzip magic: `LRZI` + version major `0x00` (Python `FID.LRZIP`).
pub const LRZIP_MAGIC: &[u8; 5] = b"LRZI\x00";

/// True if `magic` starts with the lrzip file magic.
pub fn looks_like_lrzip_magic(magic: &[u8]) -> bool {
    magic.len() >= LRZIP_MAGIC.len() && &magic[..LRZIP_MAGIC.len()] == LRZIP_MAGIC
}

/// True if path extension or magic suggests lrzip (`.lrz` / `.lrzip` / `LRZI\0`).
pub fn looks_like_lrzip(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with(".lrz") || name.ends_with(".lrzip") {
        return true;
    }
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut magic = [0u8; 5];
        if f.read(&mut magic).ok() == Some(5) {
            return looks_like_lrzip_magic(&magic);
        }
    }
    false
}

/// Whether the linked libarchive exposes the lrzip **filter API**.
///
/// This only checks that `archive_read_support_filter_lrzip` accepts enablement.
/// Runtime decompression still typically requires the external `lrzip` program
/// (libarchive shells out to `lrzip -d`).
pub fn libarchive_has_lrzip_filter() -> bool {
    unsafe {
        let a = archive_read_new();
        if a.is_null() {
            return false;
        }
        let r = archive_read_support_filter_lrzip(a);
        archive_read_free(a);
        r == ARCHIVE_OK || r == ARCHIVE_WARN
    }
}

/// Open an lrzip path via libarchive (Python-style pure libarchive path).
///
/// Handles both multi-member archives (e.g. `.tar.lrz` after filter+tar bid) and
/// single-stream `.lrz` via the raw format fallback. Returns a clear error when
/// the filter cannot run (missing external `lrzip`, or filter not built in).
pub fn try_open_lrzip_via_libarchive(
    path: impl AsRef<Path>,
    index_path: Option<&Path>,
    options: &OpenOptions,
    product_version: &str,
    recreate: bool,
) -> Result<LibarchiveMountSource> {
    let path = path.as_ref();
    if !looks_like_lrzip(path) {
        return Err(LaError::Msg(format!(
            "not an lrzip input: {}",
            path.display()
        )));
    }
    if !libarchive_has_lrzip_filter() {
        return Err(LaError::Msg(
            "libarchive has no lrzip filter (not built with archive_read_support_filter_lrzip)"
                .into(),
        ));
    }
    LibarchiveMountSource::open(path, index_path, options, product_version, recreate).map_err(
        |e| {
            LaError::Msg(format!(
                "libarchive lrzip open failed for {}: {e} \
                 (install `lrzip`/`lrunzip` if the filter shells out, or use a libarchive built with lrzip)",
                path.display()
            ))
        },
    )
}

/// Basename for a raw compressed stream entry: strip known compression suffixes.
fn raw_entry_name_from_path(archive_path: &Path) -> String {
    let mut fname = archive_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("data")
        .to_string();
    // Match Python: strip one known compression suffix (incl. libarchive-only codecs).
    const SUFFIXES: &[&str] = &[
        ".gz", ".gzip", ".bz2", ".bzip2", ".xz", ".zst", ".zstd", ".lz4", ".lzip", ".lzma", ".lzo",
        ".lzop", ".Z", ".lrz", ".lrzip", ".grz", ".grzip", ".zz", ".zlib",
    ];
    let lower = fname.to_ascii_lowercase();
    for suf in SUFFIXES {
        let s = suf.to_ascii_lowercase();
        if lower.ends_with(&s) && fname.len() > s.len() {
            fname.truncate(fname.len() - s.len());
            break;
        }
    }
    if fname.is_empty() {
        "data".into()
    } else {
        fname
    }
}

/// Heuristic: extension/magic suggests a libarchive-handled format not covered by pure backends.
pub fn looks_like_libarchive(path: &Path) -> bool {
    if looks_like_lrzip(path) {
        return true;
    }
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
            if f.read(&mut magic).ok() == Some(8) {
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
                // lrzip
                if looks_like_lrzip_magic(&magic) {
                    return true;
                }
                // ISO often starts with zeros; CD001 at 0x8001
            }
            // WARC
            let _ = f.seek(SeekFrom::Start(0));
            let mut head = [0u8; 5];
            if f.read(&mut head).ok() == Some(5) && &head == b"WARC/" {
                return true;
            }
            // XAR
            let _ = f.seek(SeekFrom::Start(0));
            let mut xar = [0u8; 4];
            if f.read(&mut xar).ok() == Some(4) && &xar == b"xar!" {
                return true;
            }
            // ISO9660 primary volume descriptor
            if f.seek(SeekFrom::Start(0x8001)).is_ok() {
                let mut cd = [0u8; 5];
                if f.read(&mut cd).ok() == Some(5) && &cd == b"CD001" {
                    return true;
                }
            }
        }
        false
    }
}

/// Store tarstats from path metadata + edge hashes when available; otherwise synthetic size-only.
///
/// Real on-disk archives use the shared helper so warm reopen fails closed after in-place
/// replace (size/mtime + first/last 512 SHA-256). Nested / virtual labels get size-only.
fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    if path.is_file() && index.store_tarstats_for_path(path).is_ok() {
        return Ok(());
    }
    use std::os::unix::fs::MetadataExt;
    let (size, mtime, mtime_ns) = match std::fs::metadata(path) {
        Ok(meta) => (meta.size(), meta.mtime(), meta.mtime_nsec()),
        Err(_) => (0, 0, 0),
    };
    let json = format!("{{\"st_size\":{size},\"st_mtime\":{mtime},\"st_mtime_ns\":{mtime_ns}}}");
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn open_cab() {
        let path = py_test("single-file.cab");
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

    #[test]
    fn lrzip_magic_and_extension_detection() {
        assert!(looks_like_lrzip_magic(b"LRZI\x00\x06"));
        assert!(!looks_like_lrzip_magic(b"LRZI"));
        assert!(!looks_like_lrzip_magic(b"LZIP\x01"));
        assert!(looks_like_lrzip(Path::new("archive.lrz")));
        assert!(looks_like_lrzip(Path::new("archive.lrzip")));
        assert!(!looks_like_lrzip(Path::new("archive.tar")));
        assert!(looks_like_libarchive(Path::new("foo.lrz")));
    }

    #[test]
    fn lrzip_magic_from_fixture_when_present() {
        let path = py_test("simple.lrz");
        if !path.exists() {
            return;
        }
        assert!(looks_like_lrzip(&path));
        assert!(looks_like_libarchive(&path));
        let mut magic = [0u8; 5];
        let mut f = std::fs::File::open(&path).unwrap();
        f.read_exact(&mut magic).unwrap();
        assert!(looks_like_lrzip_magic(&magic));
    }

    #[test]
    fn libarchive_lrzip_filter_api_present() {
        // Host libarchive is expected to expose the filter (even if runtime needs `lrzip` binary).
        assert!(
            libarchive_has_lrzip_filter(),
            "system libarchive missing archive_read_support_filter_lrzip"
        );
    }

    #[test]
    fn open_simple_lrz_skips_if_unsupported() {
        let path = py_test("simple.lrz");
        if !path.exists() {
            eprintln!("skip: missing {}", path.display());
            return;
        }
        if !libarchive_has_lrzip_filter() {
            eprintln!("skip: libarchive has no lrzip filter");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("lrz.index.sqlite");
        match try_open_lrzip_via_libarchive(
            &path,
            Some(&idx),
            &OpenOptions::default(),
            "0.1.0",
            true,
        ) {
            Ok(m) => {
                let fi = m.lookup("/simple", 0).expect("simple entry");
                let mut r = m.open(&fi, 0).unwrap();
                let mut buf = Vec::new();
                r.read_to_end(&mut buf).unwrap();
                assert_eq!(buf, b"foo fighter\n");
            }
            Err(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                // Runtime needs external lrzip for most builds of the filter.
                let skip = msg.contains("lrzip")
                    || msg.contains("unable to run")
                    || msg.contains("filter")
                    || msg.contains("program");
                assert!(
                    skip,
                    "unexpected libarchive lrzip error (not a skippable support gap): {e}"
                );
                eprintln!("skip: lrzip runtime unavailable via libarchive: {e}");
            }
        }
    }

    #[test]
    fn raw_entry_name_strips_lrz() {
        assert_eq!(
            raw_entry_name_from_path(Path::new("/tmp/simple.lrz")),
            "simple"
        );
        assert_eq!(
            raw_entry_name_from_path(Path::new("archive.tar.lrzip")),
            "archive.tar"
        );
    }

    #[test]
    fn try_open_rejects_non_lrzip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("not.lrz");
        {
            let mut f = std::fs::File::create(&p).unwrap();
            f.write_all(b"not lrzip").unwrap();
        }
        // Extension says lrz but magic does not — still treated as lrzip by extension.
        // Use a non-lrz name:
        let p2 = dir.path().join("plain.txt");
        std::fs::write(&p2, b"hi").unwrap();
        let err = match try_open_lrzip_via_libarchive(
            &p2,
            None,
            &OpenOptions::default(),
            "0.1.0",
            true,
        ) {
            Ok(_) => panic!("expected non-lrzip rejection"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("not an lrzip"), "got: {err}");
    }

    /// Minimal BSD/GNU AR for libarchive path opens (no external tools).
    fn synthetic_ar(name: &str, payload: &[u8]) -> Vec<u8> {
        const MAGIC: &[u8] = b"!<arch>\n";
        const HEADER_SIZE: usize = 60;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        let mut hdr = [b' '; HEADER_SIZE];
        let name_field = format!("{name}/");
        let nb = name_field.as_bytes();
        assert!(nb.len() <= 16, "name too long for short AR header");
        hdr[..nb.len()].copy_from_slice(nb);
        hdr[16] = b'0'; // mtime
        hdr[28] = b'0'; // uid
        hdr[34] = b'0'; // gid
        let mode = b"100644";
        hdr[40..40 + mode.len()].copy_from_slice(mode);
        let size_s = payload.len().to_string();
        hdr[48..48 + size_s.len()].copy_from_slice(size_s.as_bytes());
        hdr[58..60].copy_from_slice(b"`\n");
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    /// Regression: cheap list_dirents must expose index sizes (readdirplus TTL).
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("hello.a");
        let payload = b"hello-libarchive";
        std::fs::write(&archive, synthetic_ar("hello.txt", payload)).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let src =
            LibarchiveMountSource::open(&archive, None, &opts, "0.1.0", true).expect("open ar");
        let dents = src.list_dirents("/").expect("dirents");
        let d = dents.iter().find(|e| e.name == "hello.txt").unwrap();
        assert_eq!(d.size, payload.len() as u64);
        assert_eq!(src.lookup("/hello.txt", 0).unwrap().size, d.size);
    }

    /// Regression: open_existing rejects when archive size/mtime no longer match tarstats.
    #[test]
    fn warm_index_rejects_when_archive_size_or_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.a");
        std::fs::write(&archive, synthetic_ar("hello.txt", b"la-v1\n")).unwrap();
        let index = dir.path().join("swap.a.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src = LibarchiveMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "la-v1\n");
        drop(src);
        assert!(index.exists());

        // Matching archive still opens warm.
        LibarchiveMountSource::open_existing(&archive, &index, &opts)
            .expect("warm match must succeed");

        // Replace archive content (size change) while reusing the sibling index path.
        std::fs::write(&archive, synthetic_ar("hello.txt", b"la-v2-longer\n")).unwrap();

        match LibarchiveMountSource::open_existing(&archive, &index, &opts) {
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

    /// Regression: warm libarchive open rebuilds when archive content no longer matches tarstats.
    #[test]
    fn warm_index_rebuilds_when_archive_content_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.a");
        std::fs::write(&archive, synthetic_ar("hello.txt", b"la-v1\n")).unwrap();
        let index = dir.path().join("swap.a.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src = LibarchiveMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "la-v1\n");
        drop(src);
        assert!(index.exists());

        std::fs::write(&archive, synthetic_ar("hello.txt", b"la-v2-longer\n")).unwrap();

        // recreate=false: tarstats mismatch must rebuild, not serve stale member rows.
        let src2 = LibarchiveMountSource::open(&archive, Some(&index), &opts, "test", false)
            .expect("warm");
        let fi2 = src2.lookup("/hello.txt", 0).expect("lookup v2");
        let mut buf2 = String::new();
        src2.open(&fi2, 0)
            .unwrap()
            .read_to_string(&mut buf2)
            .unwrap();
        assert_eq!(
            buf2, "la-v2-longer\n",
            "must serve new libarchive data after tarstats mismatch rebuild"
        );
    }
}
