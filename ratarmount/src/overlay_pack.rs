//! Portable sealed layers: deterministic seekable bundles and confined extraction.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_compositing::{
    overlay_changes, overlay_seal::check_hash_format, OverlayMeta, HIDDEN_DB,
};
use ratarmount_core::MountSource;
use rustix::fs::{self as host, AtFlags, Dir, Mode, OFlags};

/// Bundle permission bits as the host mode_t (u16 on macOS, u32 on Linux).
#[allow(clippy::unnecessary_cast)]
fn raw_mode(mode: u32) -> host::RawMode {
    (mode & 0o7777) as host::RawMode
}

const SENTINEL: &str = ".ratarmount-sealed";
const FRAME_SIZE: u64 = 4 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct PackOptions {
    pub include_journal: Option<PathBuf>,
    pub include_index: bool,
    /// Local base override for locating its adjacent index sidecar.
    pub base: Option<PathBuf>,
}

#[derive(Debug)]
pub struct UnpackOutcome {
    pub layer_digest: String,
    pub ok: bool,
    /// False when the recorded base or one of its lower layers is unavailable.
    pub verified: bool,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_root(path: &Path) -> io::Result<OwnedFd> {
    Ok(host::open(path, directory_flags(), Mode::empty())?)
}

fn regular_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}

// Each component is opened relative to the previous directory, never via a
// host path that can traverse a symlink. Used for both packing and extraction.
fn parent(root: &OwnedFd, path: &str, create: bool) -> io::Result<(OwnedFd, String)> {
    let mut parts: Vec<_> = path.split('/').collect();
    let name = parts.pop().ok_or_else(|| invalid("empty member path"))?;
    let mut fd = host::openat(root, ".", directory_flags(), Mode::empty())?;
    for part in parts {
        if create {
            match host::mkdirat(&fd, part, Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        fd = host::openat(&fd, part, directory_flags(), Mode::empty())?;
    }
    Ok((fd, name.into()))
}

fn omitted(path: &str) -> bool {
    path.split('/').any(|name| {
        let name = name.to_ascii_lowercase();
        name == ".ratarmount-overlay.used"
            || name == ".ratarmount.overlay.sqlite.used"
            || name.starts_with(".ratarmount.overlay.cow-")
            || name.starts_with(".ratarmount-spool-")
            || (name.starts_with(HIDDEN_DB) && name != HIDDEN_DB)
    })
}

fn collect(fd: &OwnedFd, prefix: &str, paths: &mut BTreeSet<String>) -> io::Result<()> {
    for entry in Dir::read_from(fd)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = std::str::from_utf8(name).map_err(|_| invalid("non-UTF-8 layer path"))?;
        let path = if prefix.is_empty() {
            name.into()
        } else {
            format!("{prefix}/{name}")
        };
        if omitted(&path) {
            continue;
        }
        let stat = ratarmount_compositing::host_stat::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child = host::openat(fd, name, directory_flags(), Mode::empty())?;
            collect(&child, &path, paths)?;
        }
        paths.insert(path);
    }
    Ok(())
}

fn header(mode: u32, mtime: i64, size: u64, kind: tar::EntryType) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_mode(mode & 0o7777);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(mtime.max(0) as u64);
    h.set_size(size);
    h.set_entry_type(kind);
    h
}

fn append_host<W: Write>(tar: &mut tar::Builder<W>, root: &OwnedFd, path: &str) -> io::Result<()> {
    let (fd, name) = if path.is_empty() {
        (
            host::openat(root, ".", directory_flags(), Mode::empty())?,
            ".".into(),
        )
    } else {
        parent(root, path, false)?
    };
    let stat =
        ratarmount_compositing::host_stat::statat(&fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
    let archive_path = if path.is_empty() {
        "layer".into()
    } else {
        format!("layer/{path}")
    };
    // Preserve negative and sub-second mtimes through a local PAX header.
    let nanos = i128::from(stat.st_mtime) * 1_000_000_000 + i128::from(stat.st_mtime_nsec);
    let mtime = format!(
        "{}{}.{:09}",
        if nanos < 0 { "-" } else { "" },
        nanos.abs() / 1_000_000_000,
        nanos.abs() % 1_000_000_000
    );
    tar.append_pax_extensions([("mtime", mtime.as_bytes())])?;
    #[allow(clippy::unnecessary_cast)]
    let mode = stat.st_mode as u32;
    let kind = mode & 0o170000;
    let mut h = header(mode, stat.st_mtime, 0, tar::EntryType::Directory);
    match kind {
        0o040000 => tar.append_data(&mut h, archive_path, io::empty()),
        0o120000 => {
            let target = host::readlinkat(&fd, name.as_str(), Vec::new())?;
            h.set_entry_type(tar::EntryType::Symlink);
            tar.append_link(
                &mut h,
                archive_path,
                Path::new(std::ffi::OsStr::from_bytes(target.to_bytes())),
            )
        }
        0o100000 => {
            let file = host::openat(&fd, name.as_str(), regular_flags(), Mode::empty())?;
            let mut file = File::from(file);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(file.metadata()?.len());
            tar.append_data(&mut h, archive_path, &mut file)
        }
        _ => Err(invalid(format!("unsupported layer entry {path}"))),
    }
}

fn append_bytes<W: Write>(tar: &mut tar::Builder<W>, name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut h = header(0o444, 0, bytes.len() as u64, tar::EntryType::Regular);
    tar.append_data(&mut h, name, bytes)
}

/// Pack after dropping all writers. `lower_view` must be the same composed
/// base/lower stack used to seal the directory. Returns its recorded digest.
pub fn pack(
    directory: &Path,
    bundle: &Path,
    lower_view: Arc<dyn MountSource>,
    options: &PackOptions,
) -> io::Result<String> {
    let root = open_root(directory)?;
    let meta = checked_meta(directory)?;
    let digest = meta.get("layer_digest").expect("checked digest").to_owned();
    let output_parent = bundle
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if output_parent
        .canonicalize()?
        .starts_with(directory.canonicalize()?)
    {
        return Err(invalid("bundle output must be outside the layer"));
    }
    let opts = overlay_changes::ChangeOptions {
        include_git_dir: true,
        ..Default::default()
    };
    let changes = overlay_changes::change_set(directory, lower_view, &opts)?;
    let mut manifest = tempfile::tempfile()?;
    overlay_changes::write_manifest(&changes, &mut manifest)?;
    let mut paths = BTreeSet::new();
    collect(&root, "", &mut paths)?;
    let mut plain = tempfile::tempfile()?;
    {
        let mut tar = tar::Builder::new(BufWriter::new(&mut plain));
        // Top-level members and all layer entries use bytewise sorted paths.
        if options.include_index {
            let base = options
                .base
                .as_deref()
                .or_else(|| meta.base_url().map(Path::new));
            if let Some(base) = base.filter(|p| p.is_file()) {
                let index = ratarmount_index::default_index_path(base);
                if index.is_file() {
                    let file = File::from(host::open(&index, regular_flags(), Mode::empty())?);
                    let name = format!(
                        "index/{}",
                        index
                            .file_name()
                            .ok_or_else(|| invalid("index name"))?
                            .to_string_lossy()
                    );
                    let mut h = header(0o444, 0, file.metadata()?.len(), tar::EntryType::Regular);
                    tar.append_data(&mut h, name, file)?;
                }
            }
        }
        if let Some(journal) = &options.include_journal {
            let mut file = File::from(host::open(journal, regular_flags(), Mode::empty())?);
            let summary = crate::journal_cmd::summarize(BufReader::new(&mut file), None, None)?;
            append_bytes(
                &mut tar,
                "journal-summary.json",
                &serde_json::to_vec(&summary)?,
            )?;
            file.rewind()?;
            let mut h = header(0o444, 0, file.metadata()?.len(), tar::EntryType::Regular);
            tar.append_data(&mut h, "journal.jsonl", file)?;
        }
        append_host(&mut tar, &root, "")?;
        for path in paths {
            append_host(&mut tar, &root, &path)?;
        }
        manifest.rewind()?;
        let mut h = header(
            0o444,
            0,
            manifest.metadata()?.len(),
            tar::EntryType::Regular,
        );
        tar.append_data(&mut h, "manifest.jsonl", &mut manifest)?;
        append_bytes(&mut tar, "meta.json", &serde_json::to_vec(meta.values())?)?;
        tar.into_inner()?.flush()?;
    }
    plain.rewind()?;
    let mut remaining = plain.metadata()?.len();
    let mut encoded = tempfile::NamedTempFile::new_in(output_parent)?;
    {
        let mut writer =
            ratarmount_compress::ZstdFrameWriter::new(BufWriter::new(encoded.as_file_mut()), 3);
        while remaining > 0 {
            let size = remaining.min(FRAME_SIZE);
            writer
                .write_frame((&mut plain).take(size))
                .map_err(io::Error::other)?;
            remaining -= size;
        }
        writer.finish().map_err(io::Error::other)?;
    }
    encoded.as_file().sync_all()?;
    encoded.persist_noclobber(bundle).map_err(|e| e.error)?;
    Ok(digest)
}

fn valid_digest(digest: &str) -> io::Result<&str> {
    digest
        .strip_prefix("sha256:")
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| invalid("invalid layer_digest"))
}

/// Read metadata via the regular session API; no bundle payload is extracted.
fn bundle_meta(bundle: &Path) -> io::Result<BTreeMap<String, String>> {
    let options = ratarmount_core::OpenOptions {
        write_index: false,
        index_in_memory: true,
        ..Default::default()
    };
    let source = ratarmount_session::factory::open_path(bundle, &options, false)
        .map_err(io::Error::other)?;
    let info = source
        .lookup("/meta.json", 0)
        .ok_or_else(|| invalid("bundle missing meta.json"))?;
    let meta: BTreeMap<String, String> = serde_json::from_reader(source.open(&info, 0)?)?;
    valid_digest(
        meta.get("layer_digest")
            .ok_or_else(|| invalid("bundle missing layer_digest"))?,
    )?;
    if !meta.contains_key("sealed_at") {
        return Err(invalid("bundle layer is unsealed"));
    }
    check_hash_format(|key| meta.get(key).map(String::as_str))?;
    Ok(meta)
}

fn checked_meta(directory: &Path) -> io::Result<OverlayMeta> {
    let meta = immutable_meta(directory)?;
    if !sentinel_matches(directory, meta.get("layer_digest").expect("checked digest"))? {
        return Err(invalid("sentinel digest does not match metadata"));
    }
    Ok(meta)
}

fn immutable_meta(directory: &Path) -> io::Result<OverlayMeta> {
    let root = open_root(directory)?;
    let db = host::openat(&root, HIDDEN_DB, regular_flags(), Mode::empty())?;
    if !File::from(db).metadata()?.is_file() {
        return Err(invalid("layer database is not a regular file"));
    }
    // URL encoding prevents SQLite URI syntax in a host filename from changing
    // the immutable/read-only parameters.
    let db = directory.join(HIDDEN_DB).canonicalize()?;
    let mut uri = url::Url::from_file_path(db).map_err(|()| invalid("invalid database path"))?;
    uri.set_query(Some("mode=ro&immutable=1"));
    let conn = rusqlite::Connection::open_with_flags(
        uri.as_str(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(io::Error::other)?;
    let meta = OverlayMeta::from_connection(&conn)
        .map_err(io::Error::other)?
        .filter(OverlayMeta::layer_sealed)
        .ok_or_else(|| invalid("overlay is not sealed"))?;
    let digest = meta
        .get("layer_digest")
        .ok_or_else(|| invalid("missing layer_digest"))?;
    valid_digest(digest)?;
    check_hash_format(|key| meta.get(key))?;
    Ok(meta)
}

fn sentinel_matches(directory: &Path, digest: &str) -> io::Result<bool> {
    let root = open_root(directory)?;
    let fd = match host::openat(&root, SENTINEL, regular_flags(), Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let mut file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Ok(false);
    }
    let mut sentinel = String::new();
    (&mut file).take(128).read_to_string(&mut sentinel)?;
    Ok(sentinel == digest || sentinel == format!("{digest}\n"))
}

fn entry_mtime<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<std::time::SystemTime> {
    let mut time = i128::from(entry.header().mtime()?) * 1_000_000_000;
    if let Some(extensions) = entry.pax_extensions()? {
        for extension in extensions {
            let extension = extension?;
            if extension.key_bytes() == b"mtime" {
                let value = std::str::from_utf8(extension.value_bytes())
                    .map_err(|_| invalid("invalid mtime"))?;
                let negative = value.starts_with('-');
                let value = value.trim_start_matches('-');
                let (secs, frac) = value.split_once('.').unwrap_or((value, ""));
                if frac.len() > 9 || !frac.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid("invalid mtime"));
                }
                let secs = secs.parse::<i64>().map_err(|_| invalid("invalid mtime"))?;
                let fraction = format!("{frac:0<9}")
                    .parse::<u32>()
                    .map_err(|_| invalid("invalid mtime"))?;
                time = (i128::from(secs) * 1_000_000_000 + i128::from(fraction))
                    * if negative { -1 } else { 1 };
            }
        }
    }
    let duration = std::time::Duration::new(
        u64::try_from(time.abs() / 1_000_000_000).map_err(|_| invalid("mtime out of range"))?,
        (time.abs() % 1_000_000_000) as u32,
    );
    (if time < 0 {
        std::time::UNIX_EPOCH.checked_sub(duration)
    } else {
        std::time::UNIX_EPOCH.checked_add(duration)
    })
    .ok_or_else(|| invalid("mtime out of range"))
}

fn safe_path(bytes: &[u8]) -> io::Result<String> {
    let path = std::str::from_utf8(bytes).map_err(|_| invalid("non-UTF-8 bundle path"))?;
    let path = path.trim_end_matches('/');
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\0')
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(invalid(format!("unsafe bundle path: {path:?}")));
    }
    Ok(path.into())
}

// The staging tree may already contain read-only directories when an error
// occurs. Make only directories writable for TempDir cleanup, without links.
fn cleanup_dirs(fd: &OwnedFd) {
    let _ = host::fchmod(fd, Mode::from_raw_mode(0o700));
    if let Ok(entries) = Dir::read_from(fd) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            if let Ok(child) = host::openat(fd, name, directory_flags(), Mode::empty()) {
                cleanup_dirs(&child);
            }
        }
    }
}

struct Stage(tempfile::TempDir);
impl Drop for Stage {
    fn drop(&mut self) {
        if let Ok(root) = open_root(self.0.path()) {
            cleanup_dirs(&root);
        }
    }
}

fn seal_directories(fd: &OwnedFd) -> io::Result<()> {
    for entry in Dir::read_from(fd)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let stat = ratarmount_compositing::host_stat::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child = host::openat(fd, name, directory_flags(), Mode::empty())?;
            seal_directories(&child)?;
        }
    }
    host::fchmod(
        fd,
        Mode::from_raw_mode(ratarmount_compositing::host_stat::fstat(fd)?.st_mode & !0o222),
    )?;
    Ok(())
}

fn extract(bundle: &Path, directory: &Path) -> io::Result<()> {
    let root = open_root(directory)?;
    let body = ratarmount_compress::open_seekable_zstd(bundle).map_err(io::Error::other)?;
    let mut archive = tar::Archive::new(body.open_reader()?);
    let mut seen = BTreeSet::new();
    let mut directories = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = safe_path(&entry.path_bytes())?;
        if !seen.insert(path.clone()) {
            return Err(invalid(format!("duplicate bundle entry {path}")));
        }
        if path != "layer" && !path.starts_with("layer/") {
            continue;
        }
        let mode = entry.header().mode()? & 0o7777 & !0o222;
        let kind = entry.header().entry_type();
        let mtime = entry_mtime(&mut entry)?;
        let relative = path.strip_prefix("layer/").unwrap_or("");
        if relative.is_empty() {
            if !kind.is_dir() {
                return Err(invalid("layer must be a directory"));
            }
            directories.insert(String::new(), (mode, mtime));
            continue;
        }
        if omitted(relative) {
            return Err(invalid("bundle contains temporary overlay state"));
        }
        let (fd, name) = parent(&root, relative, true)?;
        if kind.is_dir() {
            match host::mkdirat(&fd, name.as_str(), Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
            host::openat(&fd, name.as_str(), directory_flags(), Mode::empty())?;
            directories.insert(relative.into(), (mode, mtime));
        } else if kind.is_file() {
            let child = host::openat(
                &fd,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            let mut file = File::from(child);
            let expected = entry.size();
            if io::copy(&mut entry, &mut file)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated bundle member",
                ));
            }
            file.set_times(fs::FileTimes::new().set_modified(mtime))?;
            host::fchmod(&file, Mode::from_raw_mode(raw_mode(mode)))?;
        } else if kind.is_symlink() {
            let target = entry
                .link_name_bytes()
                .ok_or_else(|| invalid("symlink has no target"))?;
            let target = std::ffi::OsString::from_vec(target.into_owned());
            host::symlinkat(&target, &fd, name.as_str())?;
            let nanos = match mtime.duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_nanos() as i128,
                Err(e) => -(e.duration().as_nanos() as i128),
            };
            let times = host::Timestamps {
                last_access: rustix::fs::Timespec {
                    tv_sec: 0,
                    tv_nsec: host::UTIME_OMIT,
                },
                last_modification: rustix::fs::Timespec {
                    tv_sec: i64::try_from(nanos.div_euclid(1_000_000_000))
                        .map_err(|_| invalid("mtime out of range"))?,
                    tv_nsec: nanos.rem_euclid(1_000_000_000) as _,
                },
            };
            host::utimensat(&fd, name.as_str(), &times, AtFlags::SYMLINK_NOFOLLOW)?;
        } else {
            return Err(invalid(format!("unsupported bundle entry {path}")));
        }
    }
    // Children first, so sealed parent permissions never obstruct extraction.
    for (path, (mode, mtime)) in directories.into_iter().rev() {
        let fd = if path.is_empty() {
            host::openat(&root, ".", directory_flags(), Mode::empty())?
        } else {
            let (fd, name) = parent(&root, &path, false)?;
            host::openat(&fd, name.as_str(), directory_flags(), Mode::empty())?
        };
        let file = File::from(fd);
        file.set_times(fs::FileTimes::new().set_modified(mtime))?;
        host::fchmod(&file, Mode::from_raw_mode(raw_mode(mode)))?;
    }
    seal_directories(&root)
}

fn verify_recorded(directory: &Path, meta: &OverlayMeta) -> io::Result<Option<bool>> {
    let Some(base) = meta.base_url().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let local = ratarmount_formats_git::parse_git_url(base)
        .map_err(io::Error::other)?
        .map(|(p, _)| p)
        .or_else(|| ratarmount_formats_git::split_inline_reference(Path::new(base)).map(|(p, _)| p))
        .unwrap_or_else(|| PathBuf::from(base));
    if !base.contains("://") && !local.exists() {
        return Ok(None);
    }
    if base.starts_with("git://") && !local.exists() {
        return Ok(None);
    }
    let lowers = meta.lower_layers().map_err(io::Error::other)?;
    if lowers.iter().any(|l| !l.path.exists()) {
        return Ok(None);
    }
    let lower = crate::overlay_cmd::lower_view(&crate::overlay_cmd::SealArgs {
        directory: directory.into(),
        base: None,
        lower: Vec::new(),
        json: false,
    });
    let lower = match lower {
        Ok(lower) => lower,
        Err(_) if base.contains("://") && !base.starts_with("git://") => return Ok(None),
        Err(e) => return Err(io::Error::other(e)),
    };
    Ok(Some(
        ratarmount_compositing::overlay_seal::verify(directory, lower)?.ok,
    ))
}

/// Restore into a nonexistent or empty directory. Always checks immutable DB
/// metadata and the sentinel; verifies changes when the recorded stack exists.
pub fn unpack(bundle: &Path, directory: &Path) -> io::Result<UnpackOutcome> {
    unpack_impl(bundle, directory, false)
}

fn unpack_impl(bundle: &Path, directory: &Path, require_match: bool) -> io::Result<UnpackOutcome> {
    let metadata = bundle_meta(bundle)?;
    match fs::symlink_metadata(directory) {
        Ok(m) if m.is_dir() && fs::read_dir(directory)?.next().is_none() => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(invalid(
                "unpack directory must not exist or must be empty (no symlinks)",
            ))
        }
        Err(e) => return Err(e),
    }
    let output_parent = directory
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let stage = Stage(tempfile::tempdir_in(output_parent)?);
    // Stage beside the destination, so publishing a read-only directory does
    // not need write permission to update its `..` across different parents.
    let layer = stage.0.path();
    extract(bundle, layer).map_err(|e| io::Error::new(e.kind(), format!("extract layer: {e}")))?;
    let meta = immutable_meta(layer)
        .map_err(|e| io::Error::new(e.kind(), format!("read layer database: {e}")))?;
    let metadata_ok = meta.values() == &metadata;
    let sentinel_ok = sentinel_matches(layer, meta.get("layer_digest").expect("checked digest"))?;
    let verified = verify_recorded(layer, &meta)
        .map_err(|e| io::Error::new(e.kind(), format!("verify layer: {e}")))?;
    let outcome = UnpackOutcome {
        layer_digest: meta.get("layer_digest").expect("checked digest").into(),
        ok: verified.unwrap_or(true) && metadata_ok && sentinel_ok,
        verified: verified.is_some(),
    };
    if require_match && !outcome.ok {
        return Err(invalid("bundle seal verification failed"));
    }
    // macOS (like the BSDs) needs write permission on a directory to rename
    // it, even within one parent, and the sealed layer root is read-only.
    // Hold the root by fd so the permission change follows the renamed inode.
    let root = host::open(layer, directory_flags(), Mode::empty())?;
    let sealed = ratarmount_compositing::host_stat::fstat(&root)?.st_mode;
    host::fchmod(&root, Mode::from_raw_mode(sealed | 0o200))?;
    fs::rename(layer, directory)
        .map_err(|e| io::Error::new(e.kind(), format!("publish layer: {e}")))?;
    host::fchmod(&root, Mode::from_raw_mode(sealed))?;
    Ok(outcome)
}

pub fn cached_lower(bundle: &Path) -> io::Result<PathBuf> {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cache")))
        .ok_or_else(|| invalid("neither XDG_CACHE_HOME nor HOME is set"))?;
    cached_lower_in(bundle, &cache.join("ratarmount/layers"))
}

fn cached_lower_in(bundle: &Path, cache: &Path) -> io::Result<PathBuf> {
    let meta = bundle_meta(bundle)?;
    let digest = meta.get("layer_digest").expect("checked digest");
    fs::create_dir_all(cache)?;
    let destination = cache.join(valid_digest(digest)?);
    if destination.try_exists()? {
        if checked_meta(&destination)?.get("layer_digest") != Some(digest.as_str()) {
            return Err(invalid("cached layer digest mismatch"));
        }
        return Ok(destination);
    }
    match unpack_impl(bundle, &destination, true) {
        Ok(_) => {}
        Err(e) if destination.is_dir() => {
            if checked_meta(&destination)?.get("layer_digest") != Some(digest.as_str()) {
                return Err(e);
            }
        }
        Err(e) => return Err(e),
    }
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_compositing::{FolderMountSource, OverlayCreateInfo, WriteOverlay};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct Fixture {
        tmp: tempfile::TempDir,
        base: Arc<dyn MountSource>,
        dir: PathBuf,
    }
    impl Fixture {
        fn new(sealed: bool) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let base_dir = tmp.path().join("base");
            fs::create_dir(&base_dir).unwrap();
            fs::write(base_dir.join("deleted"), b"old").unwrap();
            fs::write(tmp.path().join("outside"), b"secret").unwrap();
            let base: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base_dir).unwrap());
            let dir = tmp.path().join("overlay");
            let ov = WriteOverlay::new_with_create_info(
                base.clone(),
                &dir,
                &OverlayCreateInfo {
                    base_url: base_dir.to_str().unwrap().into(),
                    ..Default::default()
                },
            )
            .unwrap();
            ov.unlink("/deleted").unwrap();
            ov.mkdir("/sub", 0o755).unwrap();
            let fd = ov.create_file("/sub/file", 0o751).unwrap();
            ov.close_overlay_fd(fd);
            fs::write(dir.join("sub/file"), b"payload\n").unwrap();
            File::options()
                .write(true)
                .open(dir.join("sub/file"))
                .unwrap()
                .set_times(
                    // Regression: within (-1 s, 0) macOS reports {0 s, negative
                    // ns}, which rustix 1.1's stat panicked on (host_stat).
                    fs::FileTimes::new().set_modified(
                        std::time::UNIX_EPOCH - std::time::Duration::from_millis(250),
                    ),
                )
                .unwrap();
            ov.create_symlink("/link", "../outside").unwrap();
            drop(ov);
            if sealed {
                ratarmount_compositing::overlay_seal::seal(&dir, base.clone()).unwrap();
            }
            Self { tmp, base, dir }
        }
        fn bundle(&self, name: &str) -> PathBuf {
            let bundle = self.tmp.path().join(name);
            pack(
                &self.dir,
                &bundle,
                self.base.clone(),
                &PackOptions::default(),
            )
            .unwrap();
            bundle
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            cleanup_dirs(&open_root(self.tmp.path()).unwrap());
        }
    }

    /// Regression: pack must refuse a layer sealed under canonical hash
    /// format 1 (symlink modes hashed) instead of shipping a digest that this
    /// build's unpack/verify cannot reproduce.
    #[test]
    fn regression_pack_refuses_old_canonical_hash_format() {
        let f = Fixture::new(true);
        let db = f.dir.join(HIDDEN_DB);
        let mode = |path: &Path, mode| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        mode(&f.dir, 0o755);
        mode(&db, 0o644);
        let conn = rusqlite::Connection::open(&db).unwrap();
        OverlayMeta::set(&conn, "canonical_hash_format", "1").unwrap();
        drop(conn);
        mode(&db, 0o444);
        mode(&f.dir, 0o555);
        let bundle = f.tmp.path().join("old.tar.zst");
        let error = pack(&f.dir, &bundle, f.base.clone(), &PackOptions::default()).unwrap_err();
        assert!(
            error.to_string().contains("canonical hash format 1"),
            "{error}"
        );
        assert!(!bundle.exists());
    }

    /// Regression: pack must refuse unsealed overlays without publishing output.
    #[test]
    fn regression_pack_refuses_unsealed() {
        let f = Fixture::new(false);
        let bundle = f.tmp.path().join("refused.tar.zst");
        assert!(
            pack(&f.dir, &bundle, f.base.clone(), &PackOptions::default())
                .unwrap_err()
                .to_string()
                .contains("not sealed")
        );
        assert!(!bundle.exists());
    }

    /// Regression: a packed top must use the recorded composed lower stack,
    /// including deletions of members supplied by a sealed lower layer.
    #[test]
    fn regression_pack_roundtrip_recorded_lower_stack() {
        use ratarmount_compositing::{compose_stack, Immutability, LowerLayerRecord};
        let f = Fixture::new(true);
        let lower_meta = checked_meta(&f.dir).unwrap();
        let lower =
            compose_stack(f.base.clone(), &[(f.dir.clone(), Immutability::Immutable)]).unwrap();
        let top = f.tmp.path().join("top");
        let writer = WriteOverlay::new_with_create_info(
            lower.clone(),
            &top,
            &OverlayCreateInfo {
                base_url: lower_meta.base_url().unwrap().into(),
                lower_layers: vec![LowerLayerRecord {
                    path: f.dir.clone(),
                    layer_digest: lower_meta.get("layer_digest").unwrap().into(),
                    sealed_at: lower_meta.get("sealed_at").unwrap().into(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
        writer.unlink("/sub/file").unwrap();
        let fd = writer.create_file("/new", 0o640).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(top.join("new"), b"new bytes").unwrap();
        drop(writer);
        ratarmount_compositing::overlay_fsck::fsck(&top, true).unwrap();
        ratarmount_compositing::overlay_seal::seal(&top, lower.clone()).unwrap();
        let bundle = f.tmp.path().join("stack.tar.zst");
        pack(&top, &bundle, lower.clone(), &PackOptions::default()).unwrap();
        let restored = f.tmp.path().join("stack-restored");
        let report = unpack(&bundle, &restored).unwrap();
        assert!(report.ok && report.verified);
        let view = compose_stack(lower, &[(restored, Immutability::Immutable)]).unwrap();
        assert!(view.lookup("/sub/file", 0).is_none());
        assert!(view.lookup("/deleted", 0).is_none());
        assert!(view.lookup("/new", 0).is_some());
    }

    /// Regression: a portable layer must retain tombstones, modes, symlinks,
    /// metadata and its exact seal, with deterministic bytes and session reads.
    #[test]
    fn regression_pack_roundtrip_deterministic_and_session_mount() {
        let f = Fixture::new(true);
        let first = f.bundle("first.tar.zst");
        let second = f.bundle("second.tar.zst");
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        let source = ratarmount_session::factory::open_path(
            &first,
            &ratarmount_core::OpenOptions {
                write_index: false,
                index_in_memory: true,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        for path in ["/layer/sub/file", "/manifest.jsonl", "/meta.json"] {
            assert!(source.lookup(path, 0).is_some(), "{path}");
        }
        let info = source.lookup("/layer/sub/file", 0).unwrap();
        assert_eq!(
            info.mode & 0o7777,
            fs::metadata(f.dir.join("sub/file")).unwrap().mode() & 0o7777
        );
        let mut bytes = Vec::new();
        source
            .open(&info, 0)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"payload\n");
        let restored = f.tmp.path().join("restored");
        let report = unpack(&first, &restored).unwrap();
        assert!(report.ok && report.verified);
        assert!(
            ratarmount_compositing::overlay_seal::verify(&restored, f.base.clone())
                .unwrap()
                .ok
        );
        assert_eq!(
            fs::read_link(restored.join("link")).unwrap(),
            Path::new("../outside")
        );
        assert_eq!(
            fs::read(restored.join(HIDDEN_DB)).unwrap(),
            fs::read(f.dir.join(HIDDEN_DB)).unwrap()
        );
        assert_eq!(
            fs::metadata(restored.join("sub/file"))
                .unwrap()
                .modified()
                .unwrap(),
            fs::metadata(f.dir.join("sub/file"))
                .unwrap()
                .modified()
                .unwrap()
        );
        assert_eq!(
            fs::metadata(restored.join("sub/file")).unwrap().mode(),
            fs::metadata(f.dir.join("sub/file")).unwrap().mode()
        );
        assert!(pack(&f.dir, &first, f.base.clone(), &PackOptions::default()).is_err());
        assert!(unpack(&first, &restored).is_err());
        assert_eq!(fs::read(f.tmp.path().join("outside")).unwrap(), b"secret");
    }

    /// Regression: bundle lower cache must be content addressed and reused;
    /// missing bases still allow sentinel/immutable-DB validation offline.
    #[test]
    fn regression_pack_bundle_lower_cache_reused_and_offline_unpack() {
        let f = Fixture::new(true);
        let bundle = f.bundle("bundle.tar.zst");
        let cache = f.tmp.path().join("cache");
        let first = cached_lower_in(&bundle, &cache).unwrap();
        let inode = fs::metadata(&first).unwrap().ino();
        let second = cached_lower_in(&bundle, &cache).unwrap();
        assert_eq!(first, second);
        assert_eq!(inode, fs::metadata(&second).unwrap().ino());
        let concurrent_cache = f.tmp.path().join("concurrent-cache");
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| cached_lower_in(&bundle, &concurrent_cache).unwrap()))
                .collect();
            let paths: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(paths.iter().all(|p| p == &paths[0]));
            assert_eq!(fs::read_dir(&concurrent_cache).unwrap().count(), 1);
        });
        let digest = checked_meta(&first)
            .unwrap()
            .get("layer_digest")
            .unwrap()
            .to_owned();
        assert_eq!(first.file_name().unwrap(), valid_digest(&digest).unwrap());
        let stack = crate::MountLowerStack::read(std::slice::from_ref(&first), false).unwrap();
        let view = ratarmount_compositing::compose_stack(f.base.clone(), &stack.layers).unwrap();
        assert!(view.lookup("/deleted", 0).is_none());
        assert!(view.lookup("/sub/file", 0).is_some());
        fs::rename(f.tmp.path().join("base"), f.tmp.path().join("base-away")).unwrap();
        let report = unpack(&bundle, &f.tmp.path().join("offline")).unwrap();
        assert!(report.ok && !report.verified);
        fs::set_permissions(first.join(SENTINEL), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(first.join(SENTINEL), b"wrong").unwrap();
        assert!(cached_lower_in(&bundle, &cache).is_err());
    }

    /// Regression: unpack must report a seal mismatch rather than accepting a
    /// bundled payload that was changed after sealing; sentinel-only checks
    /// still detect mismatches without the base.
    #[test]
    fn regression_unpack_reports_content_and_sentinel_mismatch() {
        let f = Fixture::new(true);
        fs::set_permissions(f.dir.join("sub/file"), fs::Permissions::from_mode(0o751)).unwrap();
        fs::write(f.dir.join("sub/file"), b"tampered").unwrap();
        let bundle = f.bundle("tampered.tar.zst");
        let restored = f.tmp.path().join("tampered");
        fs::create_dir(&restored).unwrap();
        let report = unpack(&bundle, &restored).unwrap();
        assert!(report.verified && !report.ok);
        fs::set_permissions(restored.join(SENTINEL), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(restored.join(SENTINEL), b"different\n").unwrap();
        assert!(!sentinel_matches(&restored, &report.layer_digest).unwrap());
        let meta = immutable_meta(&restored).unwrap();
        let root = open_root(&restored).unwrap();
        let mut paths = BTreeSet::new();
        collect(&root, "", &mut paths).unwrap();
        let mut tar = tar::Builder::new(Vec::new());
        append_host(&mut tar, &root, "").unwrap();
        for path in paths {
            append_host(&mut tar, &root, &path).unwrap();
        }
        append_bytes(
            &mut tar,
            "meta.json",
            &serde_json::to_vec(meta.values()).unwrap(),
        )
        .unwrap();
        let bytes = tar.into_inner().unwrap();
        let wrong_sentinel = f.tmp.path().join("sentinel.tar.zst");
        let mut writer =
            ratarmount_compress::ZstdFrameWriter::new(File::create(&wrong_sentinel).unwrap(), 3);
        writer.write_frame(&bytes[..]).unwrap();
        writer.finish().unwrap();
        fs::rename(f.tmp.path().join("base"), f.tmp.path().join("base-away")).unwrap();
        let report = unpack(&wrong_sentinel, &f.tmp.path().join("offline-bad-sentinel")).unwrap();
        assert!(!report.ok && !report.verified);
    }

    /// Regression: journal and base index shipping must be visible in a normal
    /// TAR listing, while in-use markers and spool/COW temps stay out.
    #[test]
    fn regression_pack_includes_journal_index_and_excludes_temps() {
        let f = Fixture::new(true);
        // Sidecar discovery uses only local archives and never follows links.
        let base = f.tmp.path().join("base.tar");
        let mut tar = tar::Builder::new(File::create(&base).unwrap());
        append_bytes(&mut tar, "hello", b"base").unwrap();
        tar.finish().unwrap();
        let index = ratarmount_index::default_index_path(&base);
        ratarmount_session::IndexJob::run(
            crate::shard::index_request(&base, &index),
            Default::default(),
        )
        .unwrap();
        let source = ratarmount_session::factory::open_path(
            &base,
            &ratarmount_core::OpenOptions {
                write_index: false,
                index_in_memory: true,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        let directory = f.tmp.path().join("indexed-overlay");
        let writer = WriteOverlay::new_with_create_info(
            source.clone(),
            &directory,
            &OverlayCreateInfo {
                base_url: base.to_str().unwrap().into(),
                ..Default::default()
            },
        )
        .unwrap();
        let fd = writer.create_file("/added", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(directory.join("added"), b"new bytes").unwrap();
        drop(writer);
        ratarmount_compositing::overlay_seal::seal(&directory, source.clone()).unwrap();
        let journal = f.tmp.path().join("journal");
        fs::write(
            &journal,
            b"{\"journal\":1}\n{\"op\":\"read\",\"path\":\"/hello\",\"ts\":1,\"bytes\":4}\n",
        )
        .unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        for name in [
            ".ratarmount-overlay.used",
            ".ratarmount.overlay.cow-test",
            ".ratarmount-spool-test",
        ] {
            if !directory.join(name).exists() {
                fs::write(directory.join(name), b"temporary").unwrap();
            }
        }
        let bundle = f.tmp.path().join("extras.tar.zst");
        pack(
            &directory,
            &bundle,
            source,
            &PackOptions {
                include_journal: Some(journal),
                include_index: true,
                base: None,
            },
        )
        .unwrap();
        let body = ratarmount_compress::open_seekable_zstd(&bundle).unwrap();
        let mut archive = tar::Archive::new(body.open_reader().unwrap());
        let paths: Vec<_> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        for name in [
            "journal.jsonl",
            "journal-summary.json",
            "index/base.tar.index.sqlite",
        ] {
            assert!(paths.iter().any(|p| p == name), "{paths:?}");
        }
        assert!(!paths.iter().any(|p| omitted(p)));
    }

    fn write_crafted(f: &Fixture, name: &str, paths: &[(&str, Option<&str>)]) -> PathBuf {
        let mut tar = tar::Builder::new(Vec::new());
        let meta = checked_meta(&f.dir).unwrap();
        append_bytes(
            &mut tar,
            "meta.json",
            &serde_json::to_vec(meta.values()).unwrap(),
        )
        .unwrap();
        for (path, link) in paths {
            let mut h = header(
                0o644,
                0,
                if link.is_some() { 0 } else { 1 },
                if link.is_some() {
                    tar::EntryType::Symlink
                } else {
                    tar::EntryType::Regular
                },
            );
            h.as_mut_bytes()[..100].fill(0);
            h.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            if let Some(link) = link {
                h.set_link_name(link).unwrap();
            }
            h.set_cksum();
            tar.append(&h, if link.is_some() { &b""[..] } else { &b"x"[..] })
                .unwrap();
        }
        let bytes = tar.into_inner().unwrap();
        let bundle = f.tmp.path().join(name);
        let mut writer =
            ratarmount_compress::ZstdFrameWriter::new(File::create(&bundle).unwrap(), 3);
        writer.write_frame(&bytes[..]).unwrap();
        writer.finish().unwrap();
        bundle
    }

    /// Regression: malicious TAR paths and writes through symlink components
    /// must never escape the private staging directory.
    #[test]
    fn regression_unpack_refuses_traversal_absolute_and_symlink_components() {
        let f = Fixture::new(true);
        for (i, paths) in [
            vec![("layer/../escaped", None)],
            vec![("/absolute", None)],
            vec![
                ("layer/link", Some("../../outside")),
                ("layer/link/payload", None),
            ],
            vec![("layer/duplicate", None), ("layer/duplicate", None)],
        ]
        .iter()
        .enumerate()
        {
            let bundle = write_crafted(&f, &format!("bad-{i}.tar.zst"), paths);
            let destination = f.tmp.path().join(format!("bad-{i}"));
            assert!(unpack(&bundle, &destination).is_err(), "{paths:?}");
            assert!(!destination.exists());
            assert!(!f.tmp.path().join("escaped").exists());
            assert_eq!(fs::read(f.tmp.path().join("outside")).unwrap(), b"secret");
        }
        let bad_db = write_crafted(
            &f,
            "bad-db.tar.zst",
            &[
                ("layer/.ratarmount.overlay.sqlite", None),
                ("layer/.ratarmount-sealed", None),
            ],
        );
        assert!(unpack(&bad_db, &f.tmp.path().join("bad-db")).is_err());
        for path in ["layer/a/../b", "../outside", "/absolute", "layer/a\0b"] {
            assert!(safe_path(path.as_bytes()).is_err());
        }
        for digest in ["sha256:../escape", "sha256:A", "blake3:abcdef"] {
            assert!(valid_digest(digest).is_err());
        }
    }

    /// Regression: extraction must refuse truncated payloads and special nodes
    /// even before a recorded base is available to check the content digest.
    #[test]
    fn regression_unpack_refuses_truncated_payload_and_special_nodes() {
        let f = Fixture::new(true);
        for (i, kind) in [
            tar::EntryType::Regular,
            tar::EntryType::Link,
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
        ]
        .into_iter()
        .enumerate()
        {
            let mut tar = tar::Builder::new(Vec::new());
            let body = if kind.is_file() {
                vec![0; 4096]
            } else {
                Vec::new()
            };
            let mut h = header(0o644, 0, body.len() as u64, kind);
            if kind.is_hard_link() {
                h.set_link_name("layer/target").unwrap();
            }
            tar.append_data(&mut h, "layer/payload", &body[..]).unwrap();
            let mut bytes = tar.into_inner().unwrap();
            if kind.is_file() {
                bytes.truncate(513);
            }
            let bundle = f.tmp.path().join(format!("node-{i}.tar.zst"));
            let mut writer =
                ratarmount_compress::ZstdFrameWriter::new(File::create(&bundle).unwrap(), 3);
            writer.write_frame(&bytes[..]).unwrap();
            writer.finish().unwrap();
            let dir = f.tmp.path().join(format!("node-{i}"));
            fs::create_dir(&dir).unwrap();
            assert!(extract(&bundle, &dir).is_err(), "{kind:?}");
        }
    }

    /// Regression: the overlay CLI must keep both bundle operands and its
    /// optional base, without consuming them as ordinary mount paths.
    #[test]
    fn regression_pack_unpack_cli_positionals() {
        let args = crate::parse_args_from([
            "ratarmount",
            "overlay",
            "pack",
            "DIR",
            "OUT.tar.zst",
            "--lower",
            "LOWER",
            "--include-index",
            "--include-journal",
            "JOURNAL",
            "BASE",
        ])
        .unwrap();
        let crate::overlay_cmd::OverlayCommand::Pack(args) = args.overlay.unwrap().command else {
            panic!("pack")
        };
        assert_eq!(args.directory, Path::new("DIR"));
        assert_eq!(args.bundle, Path::new("OUT.tar.zst"));
        assert_eq!(args.base.as_deref(), Some(Path::new("BASE")));
        assert_eq!(args.lower, vec![Path::new("LOWER")]);
        assert!(args.include_index);
        let args = crate::parse_args_from(["ratarmount", "overlay", "unpack", "IN.tar.zst", "DIR"])
            .unwrap();
        assert!(matches!(
            args.overlay.unwrap().command,
            crate::overlay_cmd::OverlayCommand::Unpack { .. }
        ));
    }
}
