//! ZIP archive mount source (`backendName=ZipMountSource`).
//!
//! Hot path avoids holding a process-wide `ZipArchive` lock and fully decompressing
//! on every open: **Stored** members use `StenciledFile` random access; **Deflate**
//! members are decoded once per open into a `Cursor` (no global mutex).
//!
//! # Multi-disk / multi-part ZIP
//!
//! The underlying [`zip`] crate does **not** implement true multi-disk archives
//! (EOCD `disk_number != disk_with_central_directory` is rejected). This backend
//! recovers the common practical case by **concatenating consecutive on-disk parts**
//! before open:
//!
//! * PKZIP-style volumes: `archive.z01`, `archive.z02`, …, `archive.zip`
//! * Generic split suffixes: `archive.zip.001` + `archive.zip.002` + … (and other
//!   patterns handled by [`ratarmount_compress::check_for_split_file_in_folder`])
//!
//! Parts must form a single continuous byte stream of a normal (single-disk) ZIP.
//! Archives whose central-directory / local offsets are **per-disk** (true spanned
//! multi-disk with non-remapped offsets) remain unsupported even after concatenation.
//!
//! # Encryption
//!
//! Password-protected members (ZipCrypto and AES, via the `zip` crate defaults) are
//! supported when a matching password is supplied in [`OpenOptions::passwords`]
//! (`--password` / `--password-file`). Passwords are tried in order against the first
//! encrypted non-empty member (Python `ZipMountSource._find_password` parity).
//!
//! Limitations:
//!
//! * Encrypted members always go through the `zip` crate decrypt path (no STORE stencil).
//! * Wrong/missing password fails at mount open (not metadata-only).
//! * Crypto has not been independently audited; treat as best-effort interoperability.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratarmount_compress::{
    check_for_split_file_in_folder, materialize_joined_parts, SharedArchiveFile,
};
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use tempfile::NamedTempFile;
use thiserror::Error;
use zip::CompressionMethod;
use zip::ZipArchive;

/// Exact metadata string for Python interop.
pub const BACKEND_NAME: &str = "ZipMountSource";

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

#[derive(Debug, Error)]
pub enum ZipError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, ZipError>;

#[derive(Clone, Debug)]
struct ZipMemberMeta {
    /// Member path inside the archive (debug / future by-name open).
    #[allow(dead_code)]
    name: String,
    data_start: u64,
    compressed_size: u64,
    method: u16,
    encrypted: bool,
    /// Central-directory index for `by_index_decrypt`.
    index: usize,
}

/// Resolved on-disk archive: original path plus optional joined multi-part temp file.
struct OpenedArchive {
    /// Path the user passed (for index naming / display).
    user_path: PathBuf,
    /// Path actually opened (temp joined file or original).
    open_path: PathBuf,
    file: File,
    /// Keeps multi-part join materialization alive for the mount lifetime.
    _joined: Option<NamedTempFile>,
    /// Ordered part paths when multi-part was joined (for diagnostics / tests).
    multipart_parts: Option<Vec<PathBuf>>,
}

/// ZIP backed by SQLite index for metadata; content open uses direct archive I/O.
pub struct ZipMountSource {
    #[allow(dead_code)]
    archive_path: PathBuf,
    /// Shared archive fd (region views for Stored; clone for Deflate).
    archive_file: Arc<SharedArchiveFile>,
    raw_file: File,
    /// Keep multi-part join temp file from being deleted.
    _joined: Option<NamedTempFile>,
    index: SqliteIndex,
    /// local header offset → member layout for open
    members: HashMap<u64, ZipMemberMeta>,
    /// Decompressed member cache (header_offset → bytes). Avoids re-inflate on random cat.
    inflate_cache: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
    /// Working password for encrypted members (`None` if archive is unencrypted).
    password: Option<String>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl ZipMountSource {
    /// `index_path`: `Some(path)` for on-disk index, `None` for in-memory (`:memory:`).
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
                        Err(e) => eprintln!("info: could not load zip index ({e}); rebuilding"),
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
        let opened = open_archive_file(archive_path)?;
        let mut archive = ZipArchive::new(opened.file.try_clone()?)?;
        let password = find_password(&mut archive, &options.passwords)?;
        let members = member_meta_map(&mut archive, password.as_deref())?;
        Ok(Self {
            archive_path: opened.user_path,
            archive_file: Arc::new(SharedArchiveFile::new(opened.file.try_clone()?)),
            raw_file: opened.file,
            _joined: opened._joined,
            index,
            members,
            inflate_cache: Mutex::new(HashMap::new()),
            password,
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

        let opened = open_archive_file(archive_path)?;
        if let Some(ref parts) = opened.multipart_parts {
            println!(
                "Joined {} multi-part ZIP volumes for {}",
                parts.len(),
                archive_path.display()
            );
        }

        let mut archive = match ZipArchive::new(opened.file.try_clone()?) {
            Ok(a) => a,
            Err(e) => {
                return Err(map_zip_open_error(e, archive_path, opened.multipart_parts.as_ref()));
            }
        };
        let password = find_password(&mut archive, &options.passwords)?;

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut members = HashMap::new();
        let mut generated_dirs: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();

        for i in 0..archive.len() {
            let zf = open_member(&mut archive, i, password.as_deref())?;
            let name = zf.name().to_string();
            let header_offset = zf.header_start();
            let data_start = zf.data_start();
            let size = zf.size();
            let compressed_size = zf.compressed_size();
            let encrypted = zf.encrypted();
            let method = match zf.compression() {
                CompressionMethod::Stored => METHOD_STORED,
                CompressionMethod::Deflated => METHOD_DEFLATE,
                other => {
                    let _ = other;
                    0xffff
                }
            };
            let is_dir = zf.is_dir() || name.ends_with('/');
            let mtime = zf
                .last_modified()
                .map(|dt| {
                    msdos_to_unix(
                        dt.year(),
                        dt.month(),
                        dt.day(),
                        dt.hour(),
                        dt.minute(),
                        dt.second(),
                    )
                })
                .unwrap_or(0.0);

            let unix_mode = zf.unix_mode().unwrap_or(if is_dir { 0o755 } else { 0o644 });
            let is_symlink = (unix_mode & ratarmount_core::S_IFMT) == ratarmount_core::S_IFLNK;
            drop(zf);

            let mut linkname = String::new();
            if is_symlink {
                if let Ok(mut zf) = open_member(&mut archive, i, password.as_deref()) {
                    let mut buf = String::new();
                    if zf.read_to_string(&mut buf).is_ok() {
                        linkname = buf;
                    }
                }
            }

            let mode = if is_dir {
                (unix_mode & 0o7777) | ratarmount_core::S_IFDIR
            } else if is_symlink {
                (unix_mode & 0o7777) | ratarmount_core::S_IFLNK
            } else {
                (unix_mode & 0o7777) | ratarmount_core::S_IFREG
            };

            let full = name.trim_end_matches('/');
            if full.is_empty() {
                continue;
            }
            let full_path = normpath(full);
            let (path, base) = match full_path.rsplit_once('/') {
                Some(("", n)) => (String::new(), n.to_string()),
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (String::new(), full_path.clone()),
            };

            ensure_parent_dirs(&index, &path, &mut generated_dirs, mtime)?;

            // offset = data_start; type = compression method
            index.insert_file(
                &path,
                &base,
                header_offset as i64,
                data_start as i64,
                if is_dir { 0 } else { size as i64 },
                mtime,
                mode as i64,
                method as i64,
                &linkname,
                0,
                0,
                false,
                false,
                false,
                0,
            )?;
            members.insert(
                header_offset,
                ZipMemberMeta {
                    name: name.clone(),
                    data_start,
                    compressed_size,
                    method,
                    encrypted,
                    index: i,
                },
            );
        }

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        if let Some(ref parts) = opened.multipart_parts {
            index.store_metadata_key_value("zipMultipartParts", &parts.len().to_string())?;
        }
        store_stats(&index, &opened.open_path)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        let index = index.into_read_only()?;

        Ok(Self {
            archive_path: opened.user_path,
            archive_file: Arc::new(SharedArchiveFile::new(opened.file.try_clone()?)),
            raw_file: opened.file,
            _joined: opened._joined,
            index,
            members,
            inflate_cache: Mutex::new(HashMap::new()),
            password,
            options: options.clone(),
        })
    }
}

impl MountSource for ZipMountSource {
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
        if file_info.size == 0 {
            return Ok(Box::new(io::Cursor::new(Vec::new())));
        }
        let header = userdata(file_info)
            .and_then(|u| u.offsetheader)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing zip header offset")
            })?;

        let meta = self
            .members
            .get(&header)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "zip member meta not found"))?;

        // Encrypted members always go through zip crate decrypt (password required).
        if meta.encrypted {
            return self.open_via_zip_crate(meta);
        }

        // Prefer data_start from index userdata.offset when present (new indexes).
        let data_start = userdata(file_info)
            .map(|u| u.offset)
            .filter(|&o| o > 0)
            .unwrap_or(meta.data_start);

        match meta.method {
            METHOD_STORED => Ok(Box::new(
                self.archive_file.region(data_start, file_info.size),
            )),
            METHOD_DEFLATE => {
                {
                    let cache = self.inflate_cache.lock().expect("zip cache");
                    if let Some(bytes) = cache.get(&header) {
                        return Ok(Box::new(ArcBytes::new(Arc::clone(bytes))));
                    }
                }
                let mut file = self.raw_file.try_clone()?;
                file.seek(SeekFrom::Start(data_start))?;
                let limited = file.take(meta.compressed_size);
                let mut dec = flate2::read::DeflateDecoder::new(limited);
                let mut data = Vec::with_capacity(file_info.size as usize);
                dec.read_to_end(&mut data)
                    .map_err(|e| io::Error::other(format!("zip deflate: {e}")))?;
                if data.len() as u64 > file_info.size {
                    data.truncate(file_info.size as usize);
                }
                let arc = Arc::new(data);
                {
                    let mut cache = self.inflate_cache.lock().expect("zip cache");
                    if cache.len() > 256 {
                        cache.clear();
                    }
                    cache.insert(header, Arc::clone(&arc));
                }
                Ok(Box::new(ArcBytes::new(arc)))
            }
            _ => self.open_via_zip_crate(meta),
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

impl ZipMountSource {
    fn open_via_zip_crate(
        &self,
        meta: &ZipMemberMeta,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        let file = self.raw_file.try_clone()?;
        let mut archive = ZipArchive::new(file).map_err(io::Error::other)?;
        let mut zf = if meta.encrypted {
            let pw = self.password.as_deref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "password required to decrypt encrypted ZIP member; pass --password",
                )
            })?;
            archive
                .by_index_decrypt(meta.index, pw.as_bytes())
                .map_err(|e| io::Error::other(format!("zip decrypt: {e}")))?
        } else {
            archive
                .by_index(meta.index)
                .map_err(|e| io::Error::other(format!("zip open: {e}")))?
        };
        let mut data = Vec::with_capacity(zf.size() as usize);
        zf.read_to_end(&mut data)?;
        Ok(Box::new(io::Cursor::new(data)))
    }
}

/// Zero-copy view of cached inflated ZIP member bytes.
struct ArcBytes {
    data: Arc<Vec<u8>>,
    pos: u64,
}

impl ArcBytes {
    fn new(data: Arc<Vec<u8>>) -> Self {
        Self { data, pos: 0 }
    }
}

impl Read for ArcBytes {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.data.as_slice();
        if self.pos as usize >= data.len() {
            return Ok(0);
        }
        let start = self.pos as usize;
        let n = (data.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&data[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ArcBytes {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.data.len() as i64;
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => len + o,
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

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

fn open_member<'a>(
    archive: &'a mut ZipArchive<File>,
    index: usize,
    password: Option<&str>,
) -> Result<zip::read::ZipFile<'a>> {
    // Peek encryption without requiring a password.
    let encrypted = {
        let zf = archive.by_index_raw(index)?;
        zf.encrypted()
    };
    if encrypted {
        let pw = password.ok_or_else(|| {
            ZipError::Msg("password required to decrypt encrypted ZIP; pass --password".into())
        })?;
        Ok(archive.by_index_decrypt(index, pw.as_bytes())?)
    } else {
        Ok(archive.by_index(index)?)
    }
}

/// Try passwords against the first encrypted non-empty member (Python parity).
fn find_password(
    archive: &mut ZipArchive<File>,
    passwords: &[String],
) -> Result<Option<String>> {
    let mut first_encrypted: Option<usize> = None;
    let mut any_encrypted = false;
    for i in 0..archive.len() {
        // by_index_raw does not require a password for metadata / raw stream setup.
        let zf = archive.by_index_raw(i)?;
        if zf.encrypted() {
            any_encrypted = true;
            if !zf.is_dir() && zf.size() > 0 {
                first_encrypted = Some(i);
                break;
            }
        }
    }
    if !any_encrypted {
        return Ok(None);
    }
    let idx = first_encrypted.ok_or_else(|| {
        ZipError::Msg("encrypted ZIP has no non-empty members to verify password".into())
    })?;

    // Try empty password first (some tools encrypt with empty), then provided list.
    let mut candidates: Vec<String> = Vec::with_capacity(passwords.len() + 1);
    candidates.push(String::new());
    for p in passwords {
        if !candidates.iter().any(|c| c == p) {
            candidates.push(p.clone());
        }
    }

    for pw in &candidates {
        match archive.by_index_decrypt(idx, pw.as_bytes()) {
            Ok(mut zf) => {
                let mut buf = [0u8; 1];
                // Any successful read (incl. EOF) means the password was accepted for this trial.
                // ZipCrypto may also accept wrong passwords (1/256); AES rejects more reliably.
                match zf.read(&mut buf) {
                    Ok(n) => {
                        let _ = n;
                        return Ok(Some(pw.clone()));
                    }
                    Err(_) => continue,
                }
            }
            Err(zip::result::ZipError::InvalidPassword) => continue,
            // ZipCrypto often reports other errors for wrong password.
            Err(zip::result::ZipError::UnsupportedArchive(_)) => continue,
            Err(zip::result::ZipError::Io(_)) => continue,
            Err(_) => continue,
        }
    }

    if passwords.is_empty() {
        Err(ZipError::Msg(
            "password required to decrypt encrypted ZIP; pass --password".into(),
        ))
    } else {
        Err(ZipError::Msg(
            "could not find a matching password for encrypted ZIP".into(),
        ))
    }
}

fn member_meta_map(
    archive: &mut ZipArchive<File>,
    password: Option<&str>,
) -> Result<HashMap<u64, ZipMemberMeta>> {
    let mut members = HashMap::new();
    for i in 0..archive.len() {
        let file = open_member(archive, i, password)?;
        let method = match file.compression() {
            CompressionMethod::Stored => METHOD_STORED,
            CompressionMethod::Deflated => METHOD_DEFLATE,
            _ => 0xffff,
        };
        members.insert(
            file.header_start(),
            ZipMemberMeta {
                name: file.name().to_string(),
                data_start: file.data_start(),
                compressed_size: file.compressed_size(),
                method,
                encrypted: file.encrypted(),
                index: i,
            },
        );
    }
    Ok(members)
}

fn map_zip_open_error(
    e: zip::result::ZipError,
    path: &Path,
    multipart: Option<&Vec<PathBuf>>,
) -> ZipError {
    let msg = e.to_string();
    if msg.contains("multi-disk") || msg.contains("multi disk") {
        ZipError::Msg(format!(
            "true multi-disk ZIP is not supported by the zip crate for {}{}",
            path.display(),
            if multipart.is_some() {
                " (parts were concatenated; archive still has multi-disk EOCD markers / per-disk offsets)"
            } else {
                " (if you have archive.z01+archive.zip or archive.zip.001 parts, place them together)"
            }
        ))
    } else {
        ZipError::Zip(e)
    }
}

/// Open a ZIP path, joining multi-part volumes when present.
fn open_archive_file(path: &Path) -> Result<OpenedArchive> {
    if let Some(parts) = detect_multipart_zip_parts(path) {
        if parts.len() > 1 {
            let (tmp, _) = materialize_joined_parts(&parts)?;
            let file = File::open(tmp.path())?;
            let open_path = tmp.path().to_path_buf();
            return Ok(OpenedArchive {
                user_path: path.to_path_buf(),
                open_path,
                file,
                _joined: Some(tmp),
                multipart_parts: Some(parts),
            });
        }
    }
    let file = File::open(path)?;
    Ok(OpenedArchive {
        user_path: path.to_path_buf(),
        open_path: path.to_path_buf(),
        file,
        _joined: None,
        multipart_parts: None,
    })
}

/// Detect consecutive multi-part ZIP volumes on disk.
///
/// Supports:
/// * `name.z01` … `name.zNN` + final `name.zip`
/// * Generic split extensions via [`check_for_split_file_in_folder`] (`.001`, `.aa`, …)
pub fn detect_multipart_zip_parts(path: &Path) -> Option<Vec<PathBuf>> {
    if let Some(parts) = detect_z_series_parts(path) {
        if parts.len() > 1 {
            return Some(parts);
        }
    }
    if let Some(set) = check_for_split_file_in_folder(path) {
        if set.paths.len() > 1 {
            return Some(set.paths);
        }
    }
    None
}

/// PKZIP multi-volume naming: `base.z01`, `base.z02`, …, `base.zip`.
fn detect_z_series_parts(path: &Path) -> Option<Vec<PathBuf>> {
    let name = path.file_name()?.to_str()?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let lower = name.to_ascii_lowercase();
    let base = if lower.ends_with(".zip") {
        // Opening the final volume (or a lone .zip): look for sibling .z01 …
        &name[..name.len() - 4]
    } else if let Some((b, ext)) = name.rsplit_once('.') {
        let ext_l = ext.to_ascii_lowercase();
        // .z01 … .z99 (exactly one letter 'z' + two digits is traditional; also accept z1)
        if is_z_volume_ext(&ext_l) {
            b
        } else {
            return None;
        }
    } else {
        return None;
    };

    if base.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    // Volumes .z01, .z02, … until a gap (try both lower and upper extension case).
    for i in 1..1000 {
        let candidates = [
            parent.join(format!("{base}.z{i:02}")),
            parent.join(format!("{base}.Z{i:02}")),
        ];
        let found = candidates.into_iter().find(|p| p.is_file());
        if let Some(p) = found {
            parts.push(p);
        } else if i == 1 {
            // No .z01 → not a multi-volume set (plain .zip).
            break;
        } else {
            break;
        }
    }

    // Final volume is base.zip / base.ZIP
    let zip_candidates = [parent.join(format!("{base}.zip")), parent.join(format!("{base}.ZIP"))];
    if let Some(p) = zip_candidates.into_iter().find(|p| p.is_file()) {
        // Avoid duplicating if the user named something oddly.
        if !parts.iter().any(|x| x == &p) {
            parts.push(p);
        }
    }

    if parts.len() > 1 {
        Some(parts)
    } else {
        None
    }
}

fn is_z_volume_ext(ext: &str) -> bool {
    // z01, z02, … or z1, z2 (case already lowered)
    let bytes = ext.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'z' {
        return false;
    }
    bytes[1..].iter().all(|b| b.is_ascii_digit())
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

/// True if path looks like a ZIP archive (including first multi-part volume).
pub fn looks_like_zip(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 4];
        if std::io::Read::read(&mut f, &mut magic).ok() == Some(4)
            && magic[0] == b'P'
            && magic[1] == b'K'
        {
            return true;
        }
    }
    // Multi-part first volume may not start with local header if split mid-stream;
    // recognize common extensions.
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".zip")
            || lower.ends_with(".jar")
            || lower.ends_with(".war")
            || lower.ends_with(".ear")
        {
            return true;
        }
        if let Some((_, ext)) = lower.rsplit_once('.') {
            if is_z_volume_ext(ext) {
                return true;
            }
            // archive.zip.001 style — first part of a split zip
            if ext.chars().all(|c| c.is_ascii_digit()) && lower.contains(".zip.") {
                return true;
            }
        }
    }
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        e.eq_ignore_ascii_case("zip")
            || e.eq_ignore_ascii_case("jar")
            || e.eq_ignore_ascii_case("war")
    })
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

fn ensure_parent_dirs(
    index: &SqliteIndex,
    path: &str,
    generated: &mut std::collections::BTreeSet<String>,
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
            &parent, part, 0, 0, 0, mtime, mode, 0, "", 0, 0, false, false, true, 0,
        )?;
    }
    Ok(())
}

fn msdos_to_unix(year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Approximate via chrono-less conversion: use libc mktime
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = year as i32 - 1900;
        tm.tm_mon = month as i32 - 1;
        tm.tm_mday = day as i32;
        tm.tm_hour = hour as i32;
        tm.tm_min = min as i32;
        tm.tm_sec = sec as i32;
        tm.tm_isdst = -1;
        let t = libc::mktime(&mut tm);
        if t < 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        } else {
            t as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::{AesMode, ZipWriter};

    fn write_sample_zip(path: &Path, name: &str, data: &[u8]) {
        let file = File::create(path).unwrap();
        let mut zw = ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zw.start_file(name, opts).unwrap();
        zw.write_all(data).unwrap();
        zw.finish().unwrap();
    }

    fn write_encrypted_zip(path: &Path, name: &str, data: &[u8], password: &str) {
        let file = File::create(path).unwrap();
        let mut zw = ZipWriter::new(file);
        let opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .with_aes_encryption(AesMode::Aes256, password);
        zw.start_file(name, opts).unwrap();
        zw.write_all(data).unwrap();
        zw.finish().unwrap();
    }

    #[test]
    fn detect_z_series_from_z01_and_zip() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("vol.zip");
        write_sample_zip(&zip_path, "hello.txt", b"hello multi-part\n");
        let full = std::fs::read(&zip_path).unwrap();
        let mid = full.len() / 2;
        assert!(mid > 0 && mid < full.len());
        std::fs::write(dir.path().join("vol.z01"), &full[..mid]).unwrap();
        std::fs::write(&zip_path, &full[mid..]).unwrap();

        let parts = detect_multipart_zip_parts(&dir.path().join("vol.z01")).expect("parts");
        assert_eq!(parts.len(), 2);
        assert!(parts[0].ends_with("vol.z01"));
        assert!(parts[1].ends_with("vol.zip"));

        // Opening via final .zip also discovers parts.
        let parts2 = detect_multipart_zip_parts(&zip_path).expect("parts from zip");
        assert_eq!(parts2.len(), 2);
    }

    #[test]
    fn open_concatenated_z01_zip() {
        let dir = tempfile::tempdir().unwrap();
        let complete = dir.path().join("complete.zip");
        write_sample_zip(&complete, "hello.txt", b"hello multi-part\n");
        let full = std::fs::read(&complete).unwrap();
        let mid = full.len() / 2;
        let z01 = dir.path().join("archive.z01");
        let zlast = dir.path().join("archive.zip");
        std::fs::write(&z01, &full[..mid]).unwrap();
        std::fs::write(&zlast, &full[mid..]).unwrap();

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        // Open via first volume
        let src = ZipMountSource::open(&z01, None, &opts, "test", true).expect("open z01");
        let fi = src.lookup("/hello.txt", 0).expect("lookup");
        let mut r = src.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello multi-part\n");

        // Open via final volume
        let src2 = ZipMountSource::open(&zlast, None, &opts, "test", true).expect("open zip");
        let fi2 = src2.lookup("/hello.txt", 0).expect("lookup2");
        let mut r2 = src2.open(&fi2, 0).unwrap();
        let mut buf2 = String::new();
        r2.read_to_string(&mut buf2).unwrap();
        assert_eq!(buf2, "hello multi-part\n");
    }

    #[test]
    fn open_split_zip_001_002() {
        let dir = tempfile::tempdir().unwrap();
        let complete = dir.path().join("blob.zip");
        write_sample_zip(&complete, "data.bin", b"abcdefghij");
        let full = std::fs::read(&complete).unwrap();
        let mid = full.len() / 2;
        let p1 = dir.path().join("blob.zip.001");
        let p2 = dir.path().join("blob.zip.002");
        std::fs::write(&p1, &full[..mid]).unwrap();
        std::fs::write(&p2, &full[mid..]).unwrap();

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let src = ZipMountSource::open(&p1, None, &opts, "test", true).expect("open 001");
        let fi = src.lookup("/data.bin", 0).expect("lookup");
        let mut r = src.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"abcdefghij");
    }

    #[test]
    fn encrypted_zip_with_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.zip");
        write_encrypted_zip(&path, "secret.txt", b"top secret payload\n", "s3cret");

        let opts = OpenOptions {
            index_in_memory: true,
            passwords: vec!["wrong".into(), "s3cret".into()],
            ..OpenOptions::default()
        };
        let src = ZipMountSource::open(&path, None, &opts, "test", true).expect("open encrypted");
        let fi = src.lookup("/secret.txt", 0).expect("lookup");
        let mut r = src.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "top secret payload\n");
    }

    #[test]
    fn encrypted_zip_missing_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.zip");
        write_encrypted_zip(&path, "secret.txt", b"nope\n", "s3cret");

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        match ZipMountSource::open(&path, None, &opts, "test", true) {
            Ok(_) => panic!("expected password error"),
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("password") || s.contains("Password"),
                    "unexpected error: {s}"
                );
            }
        }
    }

    #[test]
    fn plain_zip_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.zip");
        write_sample_zip(&path, "a.txt", b"aaa");
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let src = ZipMountSource::open(&path, None, &opts, "test", true).unwrap();
        let fi = src.lookup("/a.txt", 0).unwrap();
        let mut r = src.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "aaa");
    }

    #[test]
    fn looks_like_zip_recognizes_z01() {
        assert!(looks_like_zip(Path::new("archive.z01")));
        assert!(looks_like_zip(Path::new("archive.zip.001")));
        assert!(looks_like_zip(Path::new("foo.jar")));
    }

    #[test]
    fn py_fixture_encrypted_nested_tar() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "../ratarmount".into());
        let path = PathBuf::from(root).join("tests/encrypted-nested-tar.zip");
        if !path.is_file() {
            eprintln!("skip: missing fixture {}", path.display());
            return;
        }
        let opts = OpenOptions {
            index_in_memory: true,
            passwords: vec!["foo".into()],
            ..OpenOptions::default()
        };
        let src = ZipMountSource::open(&path, None, &opts, "test", true).expect("open fixture");
        let fi = src.lookup("/foo/fighter/ufo", 0).expect("lookup ufo");
        let mut r = src.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "iriya\n");
    }

    #[test]
    fn is_z_volume_ext_cases() {
        assert!(is_z_volume_ext("z01"));
        assert!(is_z_volume_ext("z99"));
        assert!(is_z_volume_ext("z1"));
        assert!(!is_z_volume_ext("zip"));
        assert!(!is_z_volume_ext("001"));
        assert!(!is_z_volume_ext("za1"));
    }
}
