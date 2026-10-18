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
    unpack_impl(bundle, directory)
}

fn unpack_impl(bundle: &Path, directory: &Path) -> io::Result<UnpackOutcome> {
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
    publish_layer(layer, directory)?;
    Ok(outcome)
}

/// Move a staged layer into place. macOS (like the BSDs) needs write
/// permission on a directory to rename it, even within one parent, and the
/// sealed layer root is read-only. Hold the root by fd so the permission
/// change follows the renamed inode.
fn publish_layer(layer: &Path, directory: &Path) -> io::Result<()> {
    let root = host::open(layer, directory_flags(), Mode::empty())?;
    let sealed = ratarmount_compositing::host_stat::fstat(&root)?.st_mode;
    host::fchmod(&root, Mode::from_raw_mode(sealed | 0o200))?;
    fs::rename(layer, directory)
        .map_err(|e| io::Error::new(e.kind(), format!("publish layer: {e}")))?;
    host::fchmod(&root, Mode::from_raw_mode(sealed))?;
    Ok(())
}

/// Resolve a `--lower` bundle to a verified, immutable cache directory.
///
/// `view` is the composed view the bundle sits on (base plus the lowers
/// beneath it). `marker_key` is `Some` only when a previous verification
/// against exactly this view may be trusted (a strong base digest and a
/// sealed immutable stack beneath); otherwise every use re-verifies.
pub fn cached_lower(
    bundle: &Path,
    view: Arc<dyn MountSource>,
    marker_key: Option<&str>,
) -> io::Result<PathBuf> {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cache")))
        .ok_or_else(|| invalid("neither XDG_CACHE_HOME nor HOME is set"))?;
    cached_lower_in(bundle, &cache.join("ratarmount/layers"), view, marker_key)
}

#[cfg(test)]
thread_local! {
    static VERIFY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static AFTER_COPY: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Copy the bundle into a private file inside the cache while hashing it, so
/// everything after reads exactly the hashed bytes and never the original path.
fn private_copy(bundle: &Path, cache: &Path) -> io::Result<(tempfile::NamedTempFile, String)> {
    use sha2::{Digest, Sha256};
    let mut source = File::open(bundle)?;
    let mut copy = tempfile::Builder::new()
        .prefix(".copy-")
        .suffix(".tar.zst")
        .tempfile_in(cache)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buffer[..n]);
        copy.write_all(&buffer[..n])?;
    }
    copy.flush()?;
    Ok((copy, format!("{:x}", hasher.finalize())))
}

/// Check a layer directory against the view it sits on; error names the paths.
fn verify_against_view(layer: &Path, view: &Arc<dyn MountSource>) -> io::Result<()> {
    #[cfg(test)]
    VERIFY_CALLS.with(|c| c.set(c.get() + 1));
    let report = ratarmount_compositing::overlay_seal::verify(layer, view.clone())?;
    if report.ok {
        return Ok(());
    }
    let mut paths = report.mismatched.join(", ");
    if paths.is_empty() {
        paths = if report.sentinel_ok {
            format!("digest {} != recorded {}", report.computed, report.recorded)
        } else {
            "seal sentinel".into()
        };
    }
    Err(invalid(format!(
        "lower bundle does not match the base and lowers it is mounted on: {paths}"
    )))
}

fn marker_dir(cache: &Path, hex: &str) -> PathBuf {
    cache.join(format!("{hex}.verified"))
}

fn write_marker(cache: &Path, hex: &str, key: &str) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = marker_dir(cache, hex);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    match File::options()
        .write(true)
        .create_new(true)
        .open(dir.join(key))
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

pub(crate) fn cached_lower_in(
    bundle: &Path,
    cache: &Path,
    view: Arc<dyn MountSource>,
    marker_key: Option<&str>,
) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(cache)?;
    let (copy, hex) = private_copy(bundle, cache)?;
    #[cfg(test)]
    AFTER_COPY.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook();
        }
    });
    let metadata = bundle_meta(copy.path())?;
    let digest = metadata
        .get("layer_digest")
        .expect("checked digest")
        .clone();
    let destination = cache.join(&hex);
    let hit = |destination: &Path| -> io::Result<PathBuf> {
        let meta = checked_meta(destination)?;
        if meta.get("layer_digest") != Some(digest.as_str()) || meta.values() != &metadata {
            return Err(invalid("cached layer does not match the bundle"));
        }
        if let Some(key) = marker_key {
            if marker_dir(cache, &hex).join(key).try_exists()? {
                return Ok(destination.into());
            }
        }
        verify_against_view(destination, &view)?;
        if let Some(key) = marker_key {
            write_marker(cache, &hex, key)?;
        }
        Ok(destination.into())
    };
    if destination.try_exists()? {
        return hit(&destination);
    }
    // Stage beside the destination; nothing is published before it verifies.
    let stage = Stage(
        tempfile::Builder::new()
            .prefix(".ratarmount-layer-")
            .tempdir_in(cache)?,
    );
    let layer = stage.0.path();
    extract(copy.path(), layer)
        .map_err(|e| io::Error::new(e.kind(), format!("extract layer: {e}")))?;
    let meta = immutable_meta(layer)
        .map_err(|e| io::Error::new(e.kind(), format!("read layer database: {e}")))?;
    if meta.values() != &metadata {
        return Err(invalid(
            "bundle meta.json does not match its layer database",
        ));
    }
    if !sentinel_matches(layer, &digest)? {
        return Err(invalid("sentinel digest does not match metadata"));
    }
    verify_against_view(layer, &view)?;
    match publish_layer(layer, &destination) {
        Ok(()) => {}
        // Lost a concurrent fill (renaming onto a non-empty directory fails):
        // verify the published directory, never our staging copy.
        Err(_) if destination.is_dir() => return hit(&destination),
        Err(e) => return Err(e),
    }
    if let Some(key) = marker_key {
        write_marker(cache, &hex, key)?;
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
        let first = cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        let inode = fs::metadata(&first).unwrap().ino();
        let second = cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        assert_eq!(first, second);
        assert_eq!(inode, fs::metadata(&second).unwrap().ino());
        let concurrent_cache = f.tmp.path().join("concurrent-cache");
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        cached_lower_in(&bundle, &concurrent_cache, f.base.clone(), None).unwrap()
                    })
                })
                .collect();
            let paths: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(paths.iter().all(|p| p == &paths[0]));
            assert_eq!(fs::read_dir(&concurrent_cache).unwrap().count(), 1);
        });
        // The entry is named by the SHA-256 of the bundle bytes, not by the
        // layer digest the bundle claims.
        let bundle_hex =
            ratarmount_index::sha256_hex_stream(&mut File::open(&bundle).unwrap()).unwrap();
        assert_eq!(first.file_name().unwrap().to_str().unwrap(), bundle_hex);
        let (_, view) =
            crate::MountLowerStack::open(f.base.clone(), None, std::slice::from_ref(&first), false)
                .unwrap();
        assert!(view.lookup("/deleted", 0).is_none());
        assert!(view.lookup("/sub/file", 0).is_some());
        fs::rename(f.tmp.path().join("base"), f.tmp.path().join("base-away")).unwrap();
        let report = unpack(&bundle, &f.tmp.path().join("offline")).unwrap();
        assert!(report.ok && !report.verified);
        fs::set_permissions(first.join(SENTINEL), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(first.join(SENTINEL), b"wrong").unwrap();
        assert!(cached_lower_in(&bundle, &cache, f.base.clone(), None).is_err());
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

    /// Re-tar `bundle` with the payload of one member replaced (same seal
    /// metadata, so the bundle stays self-consistent but lies about content).
    fn retar_with(bundle: &Path, out: &Path, member: &str, payload: &[u8]) {
        let body = ratarmount_compress::open_seekable_zstd(bundle).unwrap();
        let mut archive = tar::Archive::new(body.open_reader().unwrap());
        let mut builder = tar::Builder::new(Vec::new());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut header = entry.header().clone();
            let pax: Vec<(String, Vec<u8>)> = entry
                .pax_extensions()
                .unwrap()
                .map(|exts| {
                    exts.map(|e| {
                        let e = e.unwrap();
                        (e.key().unwrap().to_owned(), e.value_bytes().to_vec())
                    })
                    .collect()
                })
                .unwrap_or_default();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            if path == member {
                data = payload.to_vec();
                header.set_size(data.len() as u64);
            }
            if !pax.is_empty() {
                builder
                    .append_pax_extensions(pax.iter().map(|(k, v)| (k.as_str(), v.as_slice())))
                    .unwrap();
            }
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
        }
        let bytes = builder.into_inner().unwrap();
        let mut writer = ratarmount_compress::ZstdFrameWriter::new(File::create(out).unwrap(), 3);
        writer.write_frame(&bytes[..]).unwrap();
        writer.finish().unwrap();
    }

    fn cache_entries(cache: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(cache)
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| !n.starts_with('.') && !n.ends_with(".verified"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn verify_calls() -> usize {
        VERIFY_CALLS.with(|c| c.get())
    }

    fn folder(path: PathBuf) -> Arc<dyn MountSource> {
        Arc::new(FolderMountSource::new(path).unwrap())
    }

    /// A top sealed over the fixture layer (`f.dir`): deletes `/sub/file`, adds `/new`.
    fn stacked_bundle(f: &Fixture, name: &str) -> PathBuf {
        use ratarmount_compositing::{compose_stack, Immutability, LowerLayerRecord};
        let lower_meta = checked_meta(&f.dir).unwrap();
        let lower =
            compose_stack(f.base.clone(), &[(f.dir.clone(), Immutability::Immutable)]).unwrap();
        let top = f.tmp.path().join(format!("{name}-top"));
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
        ratarmount_compositing::overlay_seal::seal(&top, lower.clone()).unwrap();
        let bundle = f.tmp.path().join(name);
        pack(&top, &bundle, lower, &PackOptions::default()).unwrap();
        bundle
    }

    /// Regression (Keystone blocker 1): a tampered bundle that claims a valid
    /// `layer_digest` must not be cached or served when the base it was sealed
    /// against is only available as the mounted view (not at its recorded path).
    #[test]
    fn regression_lower_cache_evil_bundle_fails_closed_then_good_serves_good() {
        let f = Fixture::new(true);
        let good = f.bundle("good.tar.zst");
        let evil = f.tmp.path().join("evil.tar.zst");
        retar_with(&good, &evil, "layer/sub/file", b"EVIL!!!\n");
        fs::rename(f.tmp.path().join("base"), f.tmp.path().join("base-away")).unwrap();
        let view = folder(f.tmp.path().join("base-away"));
        for order in [0, 1] {
            let cache = f.tmp.path().join(format!("cache{order}"));
            if order == 1 {
                let served = cached_lower_in(&good, &cache, view.clone(), None).unwrap();
                assert_eq!(fs::read(served.join("sub/file")).unwrap(), b"payload\n");
            }
            let error = cached_lower_in(&evil, &cache, view.clone(), None).unwrap_err();
            assert!(error.to_string().contains("sub/file"), "{error}");
            if order == 0 {
                assert!(
                    cache_entries(&cache).is_empty(),
                    "{:?}",
                    cache_entries(&cache)
                );
                let served = cached_lower_in(&good, &cache, view.clone(), None).unwrap();
                assert_eq!(fs::read(served.join("sub/file")).unwrap(), b"payload\n");
            }
            assert_eq!(cache_entries(&cache).len(), 1);
            let entry = cache.join(&cache_entries(&cache)[0]);
            assert_eq!(fs::read(entry.join("sub/file")).unwrap(), b"payload\n");
        }
    }

    /// Regression: a cache hit is checked again; an entry altered in place
    /// after it was published (same length) fails closed.
    #[test]
    fn regression_lower_cache_hit_reverifies_altered_entry() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let cache = f.tmp.path().join("cache");
        let entry = cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        let file = entry.join("sub/file");
        let dir = entry.join("sub");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&file, b"PAYLOAD\n").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let error = cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap_err();
        assert!(error.to_string().contains("sub/file"), "{error}");
        // A marker for this view must not let an altered entry through either
        // when the marker is absent.
        assert!(cached_lower_in(&bundle, &cache, f.base.clone(), Some("view-a")).is_err());
    }

    /// Regression: with a marker key the second use of an unchanged view skips
    /// verification; a different view key verifies once and gets its own marker.
    #[test]
    fn regression_lower_cache_marker_hit_skips_verify() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let cache = f.tmp.path().join("cache");
        let before = verify_calls();
        cached_lower_in(&bundle, &cache, f.base.clone(), Some("view-a")).unwrap();
        assert_eq!(verify_calls() - before, 1);
        cached_lower_in(&bundle, &cache, f.base.clone(), Some("view-a")).unwrap();
        assert_eq!(verify_calls() - before, 1, "marker hit must not re-verify");
        cached_lower_in(&bundle, &cache, f.base.clone(), Some("view-b")).unwrap();
        assert_eq!(verify_calls() - before, 2);
        let hex = cache_entries(&cache).remove(0);
        let markers = fs::read_dir(marker_dir(&cache, &hex)).unwrap().count();
        assert_eq!(markers, 2);
        // Without a key every use verifies.
        cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        assert_eq!(verify_calls() - before, 4);
    }

    /// Regression: the entry is named by the bytes of the bundle, and the bytes
    /// that are hashed are the bytes that are extracted even when the original
    /// path is swapped (or modified in place) after the copy.
    #[test]
    fn regression_lower_cache_keyed_on_bundle_bytes() {
        let f = Fixture::new(true);
        let good = f.bundle("good.tar.zst");
        let evil = f.tmp.path().join("evil.tar.zst");
        retar_with(&good, &evil, "layer/sub/file", b"EVIL!!!\n");
        let good_hex =
            ratarmount_index::sha256_hex_stream(&mut File::open(&good).unwrap()).unwrap();
        for variant in ["swap", "in-place"] {
            let target = f.tmp.path().join(format!("target-{variant}.tar.zst"));
            fs::copy(&good, &target).unwrap();
            let (t, e) = (target.clone(), evil.clone());
            let variant_owned = variant.to_string();
            AFTER_COPY.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    if variant_owned == "swap" {
                        fs::rename(&e, &t).unwrap();
                    } else {
                        fs::copy(&e, &t).unwrap();
                    }
                }))
            });
            let cache = f.tmp.path().join(format!("cache-{variant}"));
            let entry = cached_lower_in(&target, &cache, f.base.clone(), None).unwrap();
            AFTER_COPY.with(|hook| *hook.borrow_mut() = None);
            assert_eq!(entry.file_name().unwrap().to_str().unwrap(), good_hex);
            assert_eq!(fs::read(entry.join("sub/file")).unwrap(), b"payload\n");
            fs::copy(&good, &evil).ok();
            retar_with(&good, &evil, "layer/sub/file", b"EVIL!!!\n");
        }
    }

    /// Regression: concurrent fills of one bundle publish one entry, one marker
    /// per view, and leave no copy or staging directories behind.
    #[test]
    fn regression_lower_cache_concurrent_fill_with_markers() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let cache = f.tmp.path().join("cache");
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        cached_lower_in(&bundle, &cache, f.base.clone(), Some("view-a")).unwrap()
                    })
                })
                .collect();
            let paths: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(paths.iter().all(|p| p == &paths[0]));
        });
        let all: Vec<String> = fs::read_dir(&cache)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(all.iter().any(|n| n.ends_with(".verified")), "{all:?}");
        assert!(!all
            .iter()
            .any(|n| n.starts_with('.') && !n.ends_with(".verified")));
        let hex = cache_entries(&cache).remove(0);
        assert_eq!(fs::read_dir(marker_dir(&cache, &hex)).unwrap().count(), 1);
    }

    /// Regression: a stacked bundle is verified against the lowers beneath it:
    /// the right stack resolves, a tampered top fails, and the top alone
    /// (without the lower it was sealed on) fails.
    #[test]
    fn regression_lower_bundle_stack_verified_against_lowers_beneath() {
        let f = Fixture::new(true);
        let top = stacked_bundle(&f, "top.tar.zst");
        let evil = f.tmp.path().join("evil-top.tar.zst");
        retar_with(&top, &evil, "layer/new", b"EVIL bytes");
        let base_only = f.base.clone();
        let cache = f.tmp.path().join("cache");
        let lower_view = ratarmount_compositing::compose_stack(
            f.base.clone(),
            &[(
                f.dir.clone(),
                ratarmount_compositing::Immutability::Immutable,
            )],
        )
        .unwrap();
        assert!(cached_lower_in(&top, &cache, lower_view.clone(), None).is_ok());
        assert!(cached_lower_in(&evil, &cache, lower_view, None).is_err());
        let cache2 = f.tmp.path().join("cache2");
        assert!(cached_lower_in(&top, &cache2, base_only, None).is_err());
        assert!(cache_entries(&cache2).is_empty());
    }

    struct Recording {
        inner: Arc<dyn MountSource>,
        seen: std::sync::Mutex<Vec<String>>,
        opens: std::sync::atomic::AtomicUsize,
    }
    impl MountSource for Recording {
        fn list(&self, path: &str) -> Option<ratarmount_core::ListResult> {
            self.seen.lock().unwrap().push(format!("list {path}"));
            self.inner.list(path)
        }
        fn lookup(&self, path: &str, v: i32) -> Option<ratarmount_core::FileInfo> {
            self.seen.lock().unwrap().push(format!("lookup {path}"));
            self.inner.lookup(path, v)
        }
        fn open(
            &self,
            fi: &ratarmount_core::FileInfo,
            b: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.open(fi, b)
        }
        fn is_immutable(&self) -> bool {
            self.inner.is_immutable()
        }
    }

    /// Keystone (g): verifying a bundle on a first fill reads only the paths
    /// the layer mentions, never an untouched base file.
    #[test]
    fn regression_lower_bundle_verify_reads_only_mentioned_paths() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let untouched = f.tmp.path().join("base/untouched");
        fs::write(&untouched, b"do not read").unwrap();
        let recording = Arc::new(Recording {
            inner: f.base.clone(),
            seen: Default::default(),
            opens: Default::default(),
        });
        let cache = f.tmp.path().join("cache");
        cached_lower_in(&bundle, &cache, recording.clone(), None).unwrap();
        let seen = recording.seen.lock().unwrap().clone();
        assert!(seen.iter().any(|s| s == "lookup /deleted"), "{seen:?}");
        assert!(!seen.iter().any(|s| s.contains("untouched")), "{seen:?}");
        assert_eq!(
            recording.opens.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only the deleted base file's preimage is read: {seen:?}"
        );
        // Behavioural half: an unreadable untouched file does not matter.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip: root reads mode 000 files");
            return;
        }
        fs::set_permissions(&untouched, fs::Permissions::from_mode(0o000)).unwrap();
        let cache2 = f.tmp.path().join("cache2");
        cached_lower_in(&bundle, &cache2, f.base.clone(), None).unwrap();
        // A marker hit opens nothing on the base at all.
        let again = Arc::new(Recording {
            inner: f.base.clone(),
            seen: Default::default(),
            opens: Default::default(),
        });
        cached_lower_in(&bundle, &cache2, again.clone(), Some("k")).unwrap();
        let opens_after_fill = again.opens.load(std::sync::atomic::Ordering::SeqCst);
        cached_lower_in(&bundle, &cache2, again.clone(), Some("k")).unwrap();
        assert_eq!(
            again.opens.load(std::sync::atomic::Ordering::SeqCst),
            opens_after_fill
        );
        fs::set_permissions(&untouched, fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// A stack over an unsealed (editable) directory lower never gets a marker:
    /// a second use re-verifies and an edit that breaks the preimage fails closed.
    #[test]
    fn regression_lower_cache_unsealed_lower_edit_reverifies() {
        use ratarmount_compositing::{compose_stack, Immutability, LowerLayerRecord};
        let f = Fixture::new(true);
        let unsealed = f.tmp.path().join("unsealed");
        let writer = WriteOverlay::new(f.base.clone(), &unsealed).unwrap();
        let fd = writer.create_file("/lf", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        drop(writer);
        fs::write(unsealed.join("lf"), b"aaaa").unwrap();
        let lower =
            compose_stack(f.base.clone(), &[(unsealed.clone(), Immutability::Shared)]).unwrap();
        let top = f.tmp.path().join("top");
        let writer = WriteOverlay::new_with_create_info(
            lower.clone(),
            &top,
            &OverlayCreateInfo {
                base_url: f.tmp.path().join("base").to_str().unwrap().into(),
                lower_layers: vec![LowerLayerRecord {
                    path: unsealed.clone(),
                    layer_digest: String::new(),
                    sealed_at: String::new(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
        // Replace the lower's file: the row depends on the lower still holding
        // different bytes (an edit to the new bytes would make it a no-op).
        writer.unlink("/lf").unwrap();
        let fd = writer.create_file("/lf", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(top.join("lf"), b"bbbb").unwrap();
        drop(writer);
        ratarmount_compositing::overlay_seal::seal(&top, lower.clone()).unwrap();
        let bundle = f.tmp.path().join("top.tar.zst");
        pack(&top, &bundle, lower, &PackOptions::default()).unwrap();
        let cache = f.tmp.path().join("cache");
        let paths = [unsealed.clone(), bundle.clone()];
        let before = verify_calls();
        for _ in 0..2 {
            crate::MountLowerStack::open_in(
                f.base.clone(),
                Some("strong"),
                &paths,
                true,
                Some(&cache),
            )
            .unwrap();
        }
        assert_eq!(
            verify_calls() - before,
            2,
            "no marker over an unsealed lower"
        );
        let hex = cache_entries(&cache).remove(0);
        assert!(!marker_dir(&cache, &hex).exists());
        fs::write(unsealed.join("lf"), b"bbbb").unwrap();
        let error = crate::MountLowerStack::open_in(
            f.base.clone(),
            Some("strong"),
            &paths,
            true,
            Some(&cache),
        )
        .err()
        .expect("edited unsealed lower must fail closed");
        assert!(error.contains("lf"), "{error}");
    }

    /// A directory base without `--base-digest` has only a weak identity, so no
    /// marker is trusted: a same-size edit with the mtime restored is caught.
    #[test]
    fn regression_lower_cache_weak_directory_base_always_reverifies() {
        let f = Fixture::new(true);
        let base_dir = f.tmp.path().join("base");
        // Replace the base's `deleted` ("old") with same-length "new" bytes.
        let replace = f.tmp.path().join("replace");
        let writer = WriteOverlay::new_with_create_info(
            f.base.clone(),
            &replace,
            &OverlayCreateInfo {
                base_url: base_dir.to_str().unwrap().into(),
                ..Default::default()
            },
        )
        .unwrap();
        writer.unlink("/deleted").unwrap();
        let fd = writer.create_file("/deleted", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(replace.join("deleted"), b"new").unwrap();
        drop(writer);
        ratarmount_compositing::overlay_seal::seal(&replace, f.base.clone()).unwrap();
        let bundle = f.tmp.path().join("replace.tar.zst");
        pack(&replace, &bundle, f.base.clone(), &PackOptions::default()).unwrap();
        let key = crate::lower_base_key(None, Some(&base_dir), None, std::slice::from_ref(&bundle));
        assert_eq!(key, None);
        let cache = f.tmp.path().join("cache");
        let paths = [bundle.clone()];
        let before = verify_calls();
        for _ in 0..2 {
            crate::MountLowerStack::open_in(
                f.base.clone(),
                key.as_deref(),
                &paths,
                false,
                Some(&cache),
            )
            .unwrap();
        }
        assert_eq!(verify_calls() - before, 2);
        let target = base_dir.join("deleted");
        let mtime = fs::metadata(&target).unwrap().modified().unwrap();
        fs::write(&target, b"new").unwrap();
        File::options()
            .write(true)
            .open(&target)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(mtime))
            .unwrap();
        let error = crate::MountLowerStack::open_in(
            f.base.clone(),
            key.as_deref(),
            &paths,
            false,
            Some(&cache),
        )
        .err()
        .expect("edited base must fail closed");
        assert!(error.contains("deleted"), "{error}");
        // With a supplied strong digest the weak manifest is folded in, so the
        // key exists and differs per base state.
        let supplied = format!("sha256:{}", "a".repeat(64));
        let strong = crate::lower_base_key(Some(&supplied), Some(&base_dir), None, &paths);
        assert!(strong.is_some_and(|k| k.starts_with(&supplied)));
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
