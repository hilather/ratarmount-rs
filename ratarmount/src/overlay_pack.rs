//! Portable sealed layers: deterministic seekable bundles and confined extraction.
//!
//! Unix-only by design (`std::os::unix`, `flock`, `openat`); `main.rs` builds it
//! unconditionally, as the binary is not built for Windows.

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
    /// Rows describing the base actually used, written over the bundle's
    /// metadata (`meta.json` and the packed database) by a forced pack.
    pub base_rows: Option<std::collections::BTreeMap<String, String>>,
    /// The base is not at the place the seal recorded (forced, or confirmed by
    /// a strong digest): the change set on it must still be the sealed one, or
    /// the manifest would describe another layer than the seal does.
    pub check_change_set: bool,
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

/// `openat(dir, name, flags)` that refuses another name of an open overlay
/// database without closing a descriptor of it (R10-C).
fn openat_admitted(dir: &OwnedFd, name: &str, flags: OFlags) -> io::Result<OwnedFd> {
    use std::os::fd::AsFd;
    ratarmount_core::db_inodes::openat_admitted(
        Some(dir.as_fd()),
        Path::new(name),
        flags.bits() as libc::c_int,
        0,
    )
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

/// Copy of the layer database, with credentials removed from its URL-bearing
/// `meta` values. The bundle's database member is always this copy, made by
/// SQLite (`VACUUM INTO`) in `staging`, never the live file read through a
/// descriptor of our own: closing that would release every fcntl lock this
/// process holds on the database (#156). The source is only read (immutable,
/// read-only); the copy is opened again without `SQLITE_OPEN_CREATE`.
fn staged_db(
    directory: &Path,
    staging: &Path,
    meta: &OverlayMeta,
    packed: &OverlayMeta,
    previously_required: bool,
) -> io::Result<PathBuf> {
    // The overlay's own name (the open classifies it with its markers); the
    // checked open resolves the directory and builds the immutable URI.
    let source = directory.join(HIDDEN_DB);
    #[cfg(test)]
    run_pack_record_hook(&BEFORE_STAGED_DB_ACQUIRE);
    let conn = ratarmount_compositing::open_overlay_db_with_required_record(
        &source,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ratarmount_compositing::DbName::Immutable,
        previously_required,
    )?;
    let required = previously_required || conn.required_record();
    // VACUUM INTO opens its target with this connection's flags, so NOFOLLOW
    // rejects a symlink in any component of the staging path (every macOS temp
    // dir lives under /var -> /private/var): hand SQLite the resolved path.
    let copy = staging.canonicalize()?.join(HIDDEN_DB);
    ratarmount_index::vacuum_into(&conn, &copy).map_err(io::Error::other)?;
    drop(conn);
    // VACUUM INTO cannot run inside a transaction. Validate the snapshot it
    // actually made before redaction or publication, retaining the operation's
    // requirement even when the source's markers disappeared between opens.
    let validation = (|| {
        let snapshot = rusqlite::Connection::open_with_flags(
            &copy,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(io::Error::other)?;
        OverlayMeta::from_connection_required(&snapshot, required)
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("overlay snapshot has no metadata"))?;
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = validation {
        let _ = fs::remove_file(&copy);
        return Err(error);
    }
    let clean = packed.redacted_values();
    if &clean == meta.values() {
        return Ok(copy);
    }
    let conn = rusqlite::Connection::open_with_flags(
        &copy,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(io::Error::other)?;
    // Overwrite freed pages and compact, so the old text is not left behind.
    conn.execute_batch("PRAGMA secure_delete=ON;")
        .map_err(io::Error::other)?;
    for (key, value) in &clean {
        if meta.values().get(key) != Some(value) {
            conn.execute(
                "INSERT INTO meta (key,value) VALUES (?2,?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [value, key],
            )
            .map_err(io::Error::other)?;
        }
    }
    // Rows the packed metadata no longer has (a forced pack drops the old
    // base's comparison rows) must not survive in the copy.
    for key in meta.values().keys().filter(|k| !clean.contains_key(*k)) {
        conn.execute("DELETE FROM meta WHERE key=?1", [key])
            .map_err(io::Error::other)?;
    }
    conn.execute_batch("VACUUM;").map_err(io::Error::other)?;
    drop(conn);
    Ok(copy)
}

fn append_host<W: Write>(
    tar: &mut tar::Builder<W>,
    root: &OwnedFd,
    path: &str,
    replacement: Option<&Path>,
) -> io::Result<()> {
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
            h.set_entry_type(tar::EntryType::Regular);
            match replacement {
                // The layer database's SQLite snapshot, read through a managed
                // reader (#151): its close keeps this process's locks.
                Some(copy) => {
                    let mut file = ratarmount_index::managed_read::ManagedReadCursor::open(copy)?;
                    h.set_size(file.len()?);
                    tar.append_data(&mut h, archive_path, &mut file)
                }
                None => {
                    let mut file =
                        File::from(openat_admitted(&fd, name.as_str(), regular_flags())?);
                    h.set_size(file.metadata()?.len());
                    tar.append_data(&mut h, archive_path, &mut file)
                }
            }
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
    let (meta, required) = checked_meta_with_requirement(directory)?;
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
    let changes = overlay_changes::change_set(directory, lower_view.clone(), &opts)?;
    if (options.base_rows.is_some() || options.check_change_set)
        && ratarmount_compositing::overlay_seal::current_layer_digest(
            directory,
            lower_view.clone(),
        )? != digest
    {
        // The sealed digest covers the change set on the base the layer was
        // sealed on. Replacing only the base rows would make a bundle whose
        // unpack / verify fails against the base it names; recomputing the
        // digest would make the layer claim a seal it never had.
        return Err(invalid(
            "the layer's change set on the base as it is now differs from the one it was sealed with; \
             run `overlay unseal --i-know`, then `overlay seal --force-base-mismatch` against this base, then pack",
        ));
    }
    let mut manifest = tempfile::tempfile()?;
    overlay_changes::write_manifest(&changes, &mut manifest)?;
    let mut paths = BTreeSet::new();
    collect(&root, "", &mut paths)?;
    let mut plain = tempfile::tempfile()?;
    // An overlay from an earlier build may hold a credentialed base URL: export
    // a redacted copy of its database; the source is never modified.
    sweep_pack_temps(output_parent);
    let staging = Stage::new_in(output_parent, PACK_STAGE_PREFIX, false)?;
    let packed = match &options.base_rows {
        Some(rows) => meta.with_rows(rows),
        None => meta.clone(),
    };
    let staged = staged_db(directory, staging.path(), &meta, &packed, required)?;
    {
        let mut tar = tar::Builder::new(BufWriter::new(&mut plain));
        // Top-level members and all layer entries use bytewise sorted paths.
        if options.include_index {
            // The local archive the classified base is (None for any other kind).
            if let Some(base) = options.base.as_deref().filter(|p| p.is_file()) {
                let index = ratarmount_index::default_index_path(base);
                // `symlink_metadata`: a symlinked (or dangling) index reaches
                // the snapshot, which refuses it by name, instead of being
                // followed here or skipped silently.
                if std::fs::symlink_metadata(&index).is_ok() {
                    // A SQLite copy, never the live file read through a
                    // descriptor of our own: a session of this process may
                    // hold the index open, and that close would release its
                    // locks (#156). The snapshot refuses a symlink (also one
                    // substituted after this check) and an index it could
                    // not copy without a raw read of the live files.
                    let copy = staging.path().canonicalize()?.join("index.sqlite");
                    ratarmount_index::snapshot_index_into(&index, &copy)?;
                    // Its bytes through a managed reader (#151).
                    let file = ratarmount_index::managed_read::ManagedReadCursor::open(&copy)?;
                    let name = format!(
                        "index/{}",
                        index
                            .file_name()
                            .ok_or_else(|| invalid("index name"))?
                            .to_string_lossy()
                    );
                    let mut h = header(0o444, 0, file.len()?, tar::EntryType::Regular);
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
        append_host(&mut tar, &root, "", None)?;
        for path in paths {
            let replacement = (path == HIDDEN_DB).then_some(staged.as_path());
            append_host(&mut tar, &root, &path, replacement)?;
        }
        manifest.rewind()?;
        let mut h = header(
            0o444,
            0,
            manifest.metadata()?.len(),
            tar::EntryType::Regular,
        );
        tar.append_data(&mut h, "manifest.jsonl", &mut manifest)?;
        append_bytes(
            &mut tar,
            "meta.json",
            &serde_json::to_vec(&packed.redacted_values())?,
        )?;
        append_bytes(
            &mut tar,
            "bundle.json",
            &serde_json::to_vec(&serde_json::json!({ "bundle_format": BUNDLE_FORMAT }))?,
        )?;
        tar.into_inner()?.flush()?;
    }
    plain.rewind()?;
    let mut remaining = plain.metadata()?.len();
    let mut encoded = tempfile::Builder::new()
        .prefix(PACK_TEMP_PREFIX)
        .suffix(PACK_TEMP_SUFFIX)
        .tempfile_in(output_parent)?;
    // Held while the file is written, so a concurrent pack's sweep never
    // removes a live temp file; released when the process exits or is killed.
    if !try_flock(encoded.as_file()) {
        return Err(io::Error::other(
            "pack temp file is locked by another process",
        ));
    }
    ratarmount_compositing::overlay_meta::test_pack_hold();
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

/// Bundle layout version written to `bundle.json`; a bundle without the member
/// is layout 1.
const BUNDLE_FORMAT: u64 = 1;

/// Largest `meta.json` / `bundle.json` read from a bundle; real ones are a few KiB.
const MAX_META_BYTES: u64 = 1 << 20;

// Decoded bytes read so far by the capped decoders of this thread (tests assert
// that a hostile bundle stops the decode early).
#[cfg(test)]
thread_local! {
    static DECODED_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Streaming zstd decoder that fails once it has produced more than the
/// bundle's limits allow: `max_bytes` of payload plus tar framing (a header and
/// padding per entry and a small constant for PAX records). Nothing is spooled
/// to disk, so `--max-bytes` stops the work, not only the extraction.
struct CappedDecode<R> {
    inner: R,
    decoded: u64,
    max_bytes: u64,
    entries: std::rc::Rc<std::cell::Cell<u64>>,
}

impl<R: Read> Read for CappedDecode<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let allowed = self
            .max_bytes
            .saturating_add(self.entries.get().saturating_add(2).saturating_mul(2048))
            .saturating_add(1 << 20);
        let room = allowed.saturating_sub(self.decoded);
        if room == 0 {
            return Err(invalid(format!(
                "bundle decodes to more than {} bytes",
                self.max_bytes
            )));
        }
        let want = buf.len().min(usize::try_from(room).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        self.decoded += n as u64;
        #[cfg(test)]
        DECODED_BYTES.with(|c| c.set(c.get() + n as u64));
        Ok(n)
    }
}

type BundleTar = tar::Archive<CappedDecode<zstd::stream::read::Decoder<'static, BufReader<File>>>>;

/// Open `bundle` as a tar read through the capped streaming decoder. The
/// returned counter is the number of entries seen, kept by the caller.
fn open_bundle_tar(
    bundle: &Path,
    limits: Limits,
) -> io::Result<(BundleTar, std::rc::Rc<std::cell::Cell<u64>>)> {
    let entries = std::rc::Rc::new(std::cell::Cell::new(0));
    let decoder = zstd::stream::read::Decoder::new(File::open(bundle)?)?;
    let archive = tar::Archive::new(CappedDecode {
        inner: decoder,
        decoded: 0,
        max_bytes: limits.max_bytes,
        entries: entries.clone(),
    });
    Ok((archive, entries))
}

fn read_capped_member(entry: &mut impl Read, what: &str) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    entry.take(MAX_META_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_META_BYTES {
        return Err(invalid(format!(
            "bundle {what} is larger than {MAX_META_BYTES} bytes"
        )));
    }
    Ok(data)
}

/// Read metadata by a sequential, size-capped scan of the bundle: `meta.json`
/// and `bundle.json` are read (each at most 1 MiB) and every other payload is
/// skipped, never extracted or spooled. The scan is bounded by `limits`, like
/// extraction, so a hostile bundle cannot make this step do unbounded work.
fn bundle_meta(bundle: &Path, limits: Limits) -> io::Result<BTreeMap<String, String>> {
    let (mut archive, seen) = open_bundle_tar(bundle, limits)?;
    let mut layout = None;
    let mut meta_json = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        seen.set(seen.get() + 1);
        if seen.get() > limits.max_entries {
            return Err(invalid(format!(
                "bundle extracts more than {} entries",
                limits.max_entries
            )));
        }
        let name = entry.path_bytes().into_owned();
        match name.as_slice() {
            b"bundle.json" => layout = Some(read_capped_member(&mut entry, "bundle.json")?),
            b"meta.json" => meta_json = Some(read_capped_member(&mut entry, "meta.json")?),
            _ => {}
        }
    }
    if let Some(layout) = layout {
        let layout: serde_json::Value = serde_json::from_slice(&layout)
            .map_err(|_| invalid("bundle.json is not valid JSON"))?;
        let format = layout
            .get("bundle_format")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| invalid("bundle.json bundle_format is not an integer"))?;
        if format > BUNDLE_FORMAT {
            return Err(invalid(format!(
                "bundle layout {format} is newer than this ratarmount supports ({BUNDLE_FORMAT})"
            )));
        }
    }
    let meta_json = meta_json.ok_or_else(|| invalid("bundle missing meta.json"))?;
    let meta: BTreeMap<String, String> = serde_json::from_slice(&meta_json)?;
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
    checked_meta_with_requirement(directory).map(|(meta, _)| meta)
}

fn checked_meta_with_requirement(directory: &Path) -> io::Result<(OverlayMeta, bool)> {
    let (meta, required) = immutable_meta_with_requirement(directory)?;
    if !sentinel_matches(directory, meta.get("layer_digest").expect("checked digest"))? {
        return Err(invalid("sentinel digest does not match metadata"));
    }
    Ok((meta, required))
}

fn immutable_meta(directory: &Path) -> io::Result<OverlayMeta> {
    immutable_meta_with_requirement(directory).map(|(meta, _)| meta)
}

fn immutable_meta_with_requirement(directory: &Path) -> io::Result<(OverlayMeta, bool)> {
    let root = open_root(directory)?;
    // A stat, never an open: closing a descriptor of the database would
    // release this process's fcntl locks on it (R7-H1, R10-FIX9).
    let stat =
        ratarmount_compositing::host_stat::statat(&root, HIDDEN_DB, AtFlags::SYMLINK_NOFOLLOW)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(invalid("layer database is not a regular file"));
    }
    // The checked open percent-encodes the path into the immutable URI, so
    // SQLite URI syntax in a host filename cannot change its parameters.
    let conn = ratarmount_compositing::open_overlay_db(
        &directory.join(HIDDEN_DB),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ratarmount_compositing::DbName::Immutable,
    )?;
    #[cfg(test)]
    run_pack_record_hook(&AFTER_IMMUTABLE_META_ACQUIRE);
    let meta = OverlayMeta::from_opened(&conn)
        .map_err(io::Error::other)?
        .filter(OverlayMeta::layer_sealed)
        .ok_or_else(|| invalid("overlay is not sealed"))?;
    let digest = meta
        .get("layer_digest")
        .ok_or_else(|| invalid("missing layer_digest"))?;
    valid_digest(digest)?;
    check_hash_format(|key| meta.get(key))?;
    Ok((meta, conn.required_record()))
}

#[cfg(test)]
type PackRecordHook = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

#[cfg(test)]
thread_local! {
    static AFTER_IMMUTABLE_META_ACQUIRE: PackRecordHook = const { std::cell::RefCell::new(None) };
    static BEFORE_STAGED_DB_ACQUIRE: PackRecordHook = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_pack_record_hook(hook: &'static std::thread::LocalKey<PackRecordHook>) {
    // Take before calling: the callback may open another database itself.
    let callback = hook.with(|slot| slot.borrow_mut().take());
    if let Some(callback) = callback {
        callback();
    }
}

fn sentinel_matches(directory: &Path, digest: &str) -> io::Result<bool> {
    let root = open_root(directory)?;
    let fd = match openat_admitted(&root, SENTINEL, regular_flags()) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ELOOP) => {
            return Ok(false)
        }
        Err(e) => return Err(e),
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

/// Exclusive advisory lock held for the life of a stage (or `.ratarmount-copy-` file).
/// The stage's lock file lives beside it as `<stage>.lock`, never inside the
/// layer, where it would be published, hashed and packed as content.
struct StageLock {
    _file: File,
    path: PathBuf,
}

fn try_flock(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

impl StageLock {
    fn beside(stage: &Path) -> io::Result<Self> {
        let path = lock_path(stage);
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        if !try_flock(&file) {
            return Err(io::Error::other("staging lock is held by another process"));
        }
        let lock = Self { _file: file, path };
        // A sweeper that locked first may have removed the lock file (and the
        // stage) and released: the lock we hold is then on an unlinked inode.
        lock_names_current_inode(&lock)?;
        Ok(lock)
    }
}

/// Whether the lock file's path still names the inode the lock was taken on.
fn lock_names_current_inode(lock: &StageLock) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let held = lock._file.metadata()?;
    match fs::symlink_metadata(&lock.path) {
        Ok(now) if now.dev() == held.dev() && now.ino() == held.ino() => Ok(()),
        _ => Err(io::Error::other(
            "staging lock file was removed by a concurrent sweep",
        )),
    }
}

impl Drop for StageLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path(stage: &Path) -> PathBuf {
    let mut name = stage.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

// Field order matters: the directory is removed before the lock file.
struct Stage {
    dir: tempfile::TempDir,
    _lock: StageLock,
}

impl Stage {
    /// `sweep_copies` is true only for ratarmount's private cache; the user's
    /// destination parent is never searched for copy files.
    fn new_in(parent: &Path, prefix: &str, sweep_copies: bool) -> io::Result<Self> {
        Self::new_in_with(parent, prefix, sweep_copies, StageLock::beside)
    }

    /// A concurrent sweeper can take a fresh stage's lock before the stage does
    /// and then remove the stage; make a new one rather than fail.
    fn new_in_with(
        parent: &Path,
        prefix: &str,
        sweep_copies: bool,
        lock_for: impl Fn(&Path) -> io::Result<StageLock>,
    ) -> io::Result<Self> {
        const ATTEMPTS: usize = 4;
        sweep_stale_stages(parent, sweep_copies);
        let mut last = None;
        for _ in 0..ATTEMPTS {
            let dir = tempfile::Builder::new().prefix(prefix).tempdir_in(parent)?;
            match lock_for(dir.path()) {
                // The sweeper may also have removed the stage itself.
                Ok(lock) if fs::symlink_metadata(dir.path()).is_ok() => {
                    return Ok(Self { dir, _lock: lock })
                }
                Ok(_) => {
                    last = Some(io::Error::other(
                        "staging was removed by a concurrent sweep",
                    ))
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("cannot lock staging")))
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if let Ok(root) = open_root(self.dir.path()) {
            cleanup_dirs(&root);
        }
    }
}

const PACK_STAGE_PREFIX: &str = ".ratarmount-pack-stage-";
const STAGE_PREFIXES: [&str; 3] = [
    ".ratarmount-unpack-",
    ".ratarmount-layer-",
    PACK_STAGE_PREFIX,
];
/// `overlay pack` writes the bundle to `.ratarmount-pack-` + six random
/// alphanumerics + `.tmp` beside the output and renames it into place.
const PACK_TEMP_PREFIX: &str = ".ratarmount-pack-";
const PACK_TEMP_SUFFIX: &str = ".tmp";
/// A file younger than this may be a pack that has not taken its lock yet.
const PACK_TEMP_MIN_AGE: std::time::Duration = std::time::Duration::from_secs(60);

fn is_pack_temp_name(name: &str) -> bool {
    name.strip_prefix(PACK_TEMP_PREFIX)
        .and_then(|rest| rest.strip_suffix(PACK_TEMP_SUFFIX))
        .is_some_and(|random| {
            random.len() == 6 && random.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

/// Remove temp files of killed packs from the output directory: exact name
/// shape, regular file (never a symlink), ours, at least a minute old and not
/// locked (a live pack holds an exclusive flock on its file). Staging
/// directories are swept with the other stages. The anonymous `.tmpXXXXXX`
/// names of earlier builds cannot be told from other programs' temp files and
/// are left alone. Best effort.
fn sweep_pack_temps(parent: &Path) {
    // Resolve the caller's path once, then work only relative to the opened
    // directory: replacing `parent` with a symlink afterwards redirects nothing.
    let Ok(canonical) = parent.canonicalize() else {
        return;
    };
    let Ok(dir) = open_root(&canonical) else {
        return;
    };
    sweep_pack_temps_in(&dir);
}

fn sweep_pack_temps_in(dir: &OwnedFd) {
    let Ok(entries) = Dir::read_from(dir) else {
        return;
    };
    let euid = unsafe { libc::geteuid() };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_str().ok().is_some_and(is_pack_temp_name) {
            continue;
        }
        let Ok(stat) =
            ratarmount_compositing::host_stat::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
        else {
            continue;
        };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_uid != euid {
            continue;
        }
        let old_enough = stat_age(&stat) >= PACK_TEMP_MIN_AGE;
        if !old_enough {
            continue;
        }
        // Admitted (R10-FIX3): an old temp name that is a hard link of an open
        // overlay database is skipped without a descriptor of it being
        // opened and closed (its flock says nothing about SQLite's locks).
        let Ok(fd) = name
            .to_str()
            .map_err(io::Error::other)
            .and_then(|name| openat_admitted(dir, name, regular_flags()))
        else {
            continue;
        };
        let file = File::from(fd);
        if !try_flock(&file) {
            continue;
        }
        // Still the file that was checked, not one swapped in under the name.
        let same = ratarmount_compositing::host_stat::fstat(&file)
            .is_ok_and(|now| now.st_dev == stat.st_dev && now.st_ino == stat.st_ino);
        if same {
            if let Ok(name) = name.to_str() {
                unlink_if_same(dir, name, &file);
            }
        }
    }
}

static QUARANTINE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Remove the directory entry `name` only if it still names the inode behind
/// `locked`. `unlinkat` acts on the *name*, so checking the opened inode first
/// leaves a window in which the entry can be replaced by another file (and a
/// different live pack's locked temp deleted). The entry is renamed to a unique
/// quarantine name in the same directory, the quarantine name is checked
/// (`fstatat` without following) against the locked inode, and only then
/// unlinked; a mismatch puts the entry back (`linkat` never replaces a file
/// created in the meantime) and removes nothing. Same-uid attackers only: the
/// directories swept are the caller's own. Returns whether the entry was removed.
fn unlink_if_same(dir: &OwnedFd, name: &str, locked: &File) -> bool {
    use std::sync::atomic::Ordering;
    unlink_if_same_named(dir, name, locked, &mut || {
        format!(
            ".ratarmount-quarantine-{}-{}",
            std::process::id(),
            QUARANTINE_COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    })
}

/// `renameat` that fails with `EEXIST` instead of replacing `to`.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rename_no_replace(dir: &OwnedFd, from: &str, to: &str) -> rustix::io::Result<()> {
    host::renameat_with(dir, from, dir, to, host::RenameFlags::NOREPLACE)
}

/// No atomic no-replace rename on this platform (e.g. BSD). `linkat` followed
/// by `unlinkat` is not a substitute: the old name can be replaced by a live
/// file between the two calls and then be deleted. So nothing is quarantined
/// and stale temps are left for manual deletion; see
/// [`no_replace_rename_available`].
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn rename_no_replace(_: &OwnedFd, _: &str, _: &str) -> rustix::io::Result<()> {
    Err(rustix::io::Errno::NOSYS)
}

#[cfg(test)]
thread_local! {
    /// Test hook: pretend this platform has no no-replace rename.
    static FORCE_NO_REPLACE_FALLBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether [`rename_no_replace`] is atomic here. Without it the sweep never
/// unlinks a temp.
fn no_replace_rename_available() -> bool {
    #[cfg(test)]
    if FORCE_NO_REPLACE_FALLBACK.with(std::cell::Cell::get) {
        return false;
    }
    cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))
}

/// How many quarantine names are tried before the entry is left alone.
const QUARANTINE_ATTEMPTS: usize = 8;

/// [`unlink_if_same`] with the quarantine names supplied by `next_name`.
fn unlink_if_same_named(
    dir: &OwnedFd,
    name: &str,
    locked: &File,
    next_name: &mut dyn FnMut() -> String,
) -> bool {
    // No atomic no-replace rename: leave the stale file for manual deletion.
    if !no_replace_rename_available() {
        return false;
    }
    let Ok(held) = ratarmount_compositing::host_stat::fstat(locked) else {
        return false;
    };
    let mut quarantine = None;
    for _ in 0..QUARANTINE_ATTEMPTS {
        let candidate = next_name();
        match rename_no_replace(dir, name, &candidate) {
            Ok(()) => {
                quarantine = Some(candidate);
                break;
            }
            // Taken (an orphan that outlived a pid, a planted file): leave it
            // alone and try another name.
            Err(e) if e == rustix::io::Errno::EXIST => {}
            Err(_) => return false,
        }
    }
    let Some(quarantine) = quarantine else {
        return false;
    };
    let same = ratarmount_compositing::host_stat::statat(
        dir,
        quarantine.as_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .is_ok_and(|now| now.st_dev == held.st_dev && now.st_ino == held.st_ino);
    if same {
        return host::unlinkat(dir, quarantine.as_str(), AtFlags::empty()).is_ok();
    }
    if host::linkat(dir, quarantine.as_str(), dir, name, AtFlags::empty()).is_ok() {
        let _ = host::unlinkat(dir, quarantine.as_str(), AtFlags::empty());
    }
    false
}

/// Age of a stat'ed entry by its mtime (zero for an mtime in the future).
fn stat_age(stat: &rustix::fs::Stat) -> std::time::Duration {
    #[allow(clippy::unnecessary_cast)]
    let modified = std::time::UNIX_EPOCH
        + std::time::Duration::new(
            u64::try_from(stat.st_mtime).unwrap_or(0),
            u32::try_from(stat.st_mtime_nsec).unwrap_or(0),
        );
    std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default()
}

/// Open a regular lock/temp file relative to `dir` for the sweeper's flock,
/// never following a symlink planted under the name.
fn open_lock_at(dir: &OwnedFd, name: &str) -> io::Result<File> {
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    Ok(File::from(openat_admitted(dir, name, flags)?))
}

/// Delete everything below `fd` through descriptors only: each child is opened
/// relative to its parent with `O_NOFOLLOW`, so no pathname (and no symlink
/// swapped in for an ancestor) is ever resolved. Read-only directories are made
/// writable first. Best effort.
fn remove_contents(fd: &OwnedFd) {
    let _ = host::fchmod(fd, Mode::from_raw_mode(0o700));
    let Ok(entries) = Dir::read_from(fd) else {
        return;
    };
    let names: Vec<_> = entries
        .flatten()
        .map(|e| e.file_name().to_owned())
        .filter(|n| n.to_bytes() != b"." && n.to_bytes() != b"..")
        .collect();
    for name in names {
        let is_dir = ratarmount_compositing::host_stat::statat(
            fd,
            name.as_c_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .is_ok_and(|s| s.st_mode & libc::S_IFMT == libc::S_IFDIR);
        if is_dir {
            if let Ok(child) = host::openat(fd, name.as_c_str(), directory_flags(), Mode::empty()) {
                remove_contents(&child);
            }
            let _ = host::unlinkat(fd, name.as_c_str(), AtFlags::REMOVEDIR);
        } else {
            let _ = host::unlinkat(fd, name.as_c_str(), AtFlags::empty());
        }
    }
}

/// Whether `name` is a stage directory ratarmount generated: a stage prefix and
/// the six random alphanumerics `tempfile` appends. `.ratarmount-pack-stage-notes`
/// is somebody's directory, not ours.
fn is_stage_name(name: &str) -> bool {
    STAGE_PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|random| {
            random.len() == 6 && random.bytes().all(|b| b.is_ascii_alphanumeric())
        })
    })
}

const COPY_PREFIX: &str = ".ratarmount-copy-";

/// Builds before the `.ratarmount-copy-` rename staged bundle copies as
/// `.copy-` + tempfile's six random alphanumerics + `.tar.zst`. Only that exact
/// shape is swept, and only inside the layer cache, so a user's own `.copy-*`
/// files never match.
fn is_legacy_copy_name(name: &str) -> bool {
    name.strip_prefix(".copy-")
        .and_then(|rest| rest.strip_suffix(".tar.zst"))
        .is_some_and(|random| {
            random.len() == 6 && random.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

/// Remove staging left by killed processes. Only our own prefixes, owned by
/// us, never symlinks. A stage is abandoned when its sibling lock can be
/// taken; no mtime heuristic is used for stages with a lock (the root mtime
/// is a restored archive value). Best effort: errors are ignored.
fn sweep_stale_stages(parent: &Path, sweep_copies: bool) {
    // Resolve the caller's path once and work only relative to the opened
    // directory: replacing `parent` (or an ancestor) with a symlink after a
    // lock is taken redirects nothing.
    let Ok(canonical) = parent.canonicalize() else {
        return;
    };
    let Ok(dir) = open_root(&canonical) else {
        return;
    };
    sweep_stale_stages_in(&dir, sweep_copies);
}

fn sweep_stale_stages_in(dir: &OwnedFd, sweep_copies: bool) {
    use ratarmount_compositing::host_stat::{fstat, statat};
    let Ok(entries) = Dir::read_from(dir) else {
        return;
    };
    let euid = unsafe { libc::geteuid() };
    let day = std::time::Duration::from_secs(24 * 3600);
    let minute = std::time::Duration::from_secs(60);
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(stat) = statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        let kind = stat.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK || stat.st_uid != euid {
            continue;
        }
        if sweep_copies
            && (name.starts_with(COPY_PREFIX) || is_legacy_copy_name(&name))
            && kind == libc::S_IFREG
        {
            // A copy being written has a fresh mtime; the age check closes the
            // gap between its creation and its flock.
            if stat_age(&stat) < minute {
                continue;
            }
            let Ok(file) = open_lock_at(dir, &name) else {
                continue;
            };
            if try_flock(&file) {
                unlink_if_same(dir, &name, &file);
            }
        } else if name.strip_suffix(".lock").is_some_and(is_stage_name) && kind == libc::S_IFREG {
            // Orphan lock whose stage is gone.
            let stage = name.trim_end_matches(".lock");
            if statat(dir, stage, AtFlags::SYMLINK_NOFOLLOW).is_err() {
                if let Ok(file) = open_lock_at(dir, &name) {
                    if try_flock(&file) {
                        unlink_if_same(dir, &name, &file);
                    }
                }
            }
        } else if is_stage_name(&name) && kind == libc::S_IFDIR {
            let lock = format!("{name}.lock");
            let held = match open_lock_at(dir, &lock) {
                Ok(file) => {
                    if !try_flock(&file) {
                        continue;
                    }
                    Some(file)
                }
                // No lock: the stage predates locks or is foreign.
                Err(_) if stat_age(&stat) > day => None,
                Err(_) => continue,
            };
            let Ok(child) = host::openat(dir, name.as_str(), directory_flags(), Mode::empty())
            else {
                continue;
            };
            // Still the directory that was checked, not one renamed in under
            // the name; the contents are removed through this descriptor.
            if !fstat(&child)
                .is_ok_and(|now| now.st_dev == stat.st_dev && now.st_ino == stat.st_ino)
            {
                continue;
            }
            remove_contents(&child);
            drop(child);
            // Non-recursive: only an empty directory goes.
            let _ = host::unlinkat(dir, name.as_str(), AtFlags::REMOVEDIR);
            if let Some(file) = held {
                unlink_if_same(dir, &lock, &file);
            }
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

/// Modes and mtimes the archive asks for. Extraction creates everything
/// writable (a killed unpack must leave a tree `rm -rf` can remove) and
/// `finalize_stage` applies these once every check has passed.
#[derive(Debug)]
struct Recorded {
    files: Vec<(String, u32)>,
    directories: BTreeMap<String, (u32, std::time::SystemTime)>,
}

/// Bounds on what one bundle may extract. A layer is a patch of agent edits,
/// so the defaults are generous but still stop a compression bomb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_entries: u64,
}

pub const DEFAULT_MAX_BYTES: u64 = 32 << 30;
pub const DEFAULT_MAX_ENTRIES: u64 = 1_000_000;
const MAX_BYTES_ENV: &str = "RATARMOUNT_BUNDLE_MAX_BYTES";
const MAX_ENTRIES_ENV: &str = "RATARMOUNT_BUNDLE_MAX_ENTRIES";

impl Limits {
    /// Explicit values win over the environment, which wins over the defaults.
    pub fn resolve(max_bytes: Option<u64>, max_entries: Option<u64>) -> io::Result<Self> {
        let from_env = |name: &str| -> io::Result<Option<u64>> {
            match std::env::var(name) {
                Ok(v) if !v.trim().is_empty() => ratarmount_compositing::parse_overlay_size(&v)
                    .map(Some)
                    .map_err(|e| invalid(format!("{name}: {e}"))),
                _ => Ok(None),
            }
        };
        Ok(Self {
            max_bytes: match max_bytes {
                Some(n) => n,
                None => from_env(MAX_BYTES_ENV)?.unwrap_or(DEFAULT_MAX_BYTES),
            },
            max_entries: match max_entries {
                Some(n) => n,
                None => from_env(MAX_ENTRIES_ENV)?.unwrap_or(DEFAULT_MAX_ENTRIES),
            },
        })
    }
}

fn extract(bundle: &Path, directory: &Path) -> io::Result<Recorded> {
    extract_with_limits(bundle, directory, Limits::resolve(None, None)?)
}

fn extract_with_limits(bundle: &Path, directory: &Path, limits: Limits) -> io::Result<Recorded> {
    let root = open_root(directory)?;
    let mut entries_seen = 0u64;
    let mut remaining = limits.max_bytes;
    let mut files = Vec::new();
    let (mut archive, entry_counter) = open_bundle_tar(bundle, limits)?;
    let mut seen = BTreeSet::new();
    let mut directories = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        entries_seen += 1;
        entry_counter.set(entries_seen);
        if entries_seen > limits.max_entries {
            return Err(invalid(format!(
                "bundle extracts more than {} entries",
                limits.max_entries
            )));
        }
        let path = safe_path(&entry.path_bytes())?;
        if !seen.insert(path.clone()) {
            return Err(invalid(format!("duplicate bundle entry {path}")));
        }
        if path != "layer" && !path.starts_with("layer/") {
            continue;
        }
        let mode = entry.header().mode()? & 0o7777;
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
            let too_big = || {
                invalid(format!(
                    "bundle extracts more than {} bytes",
                    limits.max_bytes
                ))
            };
            if expected > remaining {
                return Err(too_big());
            }
            let written = io::copy(
                &mut (&mut entry).take(remaining.saturating_add(1)),
                &mut file,
            )?;
            if written > remaining {
                return Err(too_big());
            }
            if written != expected {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated bundle member",
                ));
            }
            remaining -= written;
            file.set_times(fs::FileTimes::new().set_modified(mtime))?;
            files.push((relative.to_string(), mode));
            #[cfg(test)]
            run_extract_hook(&MID_EXTRACT, directory);
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
    #[cfg(test)]
    run_extract_hook(&AFTER_EXTRACT, directory);
    Ok(Recorded { files, directories })
}

/// Apply the archived modes and mtimes and make the tree read-only. Runs after
/// all checks, immediately before the publishing rename.
fn finalize_stage(directory: &Path, recorded: Recorded) -> io::Result<()> {
    let root = open_root(directory)?;
    for (path, mode) in &recorded.files {
        let (fd, name) = parent(&root, path, false)?;
        let name = std::ffi::CString::new(name).map_err(|_| invalid("NUL in member path"))?;
        let stat = ratarmount_compositing::host_stat::statat(
            &fd,
            name.as_c_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        // Never a data descriptor (#149): its close would release this
        // process's locks on a database open in it.
        ratarmount_compositing::host_stat::chmod_entry_at(&fd, &name, &stat, |_| {
            raw_mode(mode & !0o222)
        })?;
    }
    // Children first, so sealed parent permissions never obstruct this walk.
    for (path, (mode, mtime)) in recorded.directories.into_iter().rev() {
        let fd = if path.is_empty() {
            host::openat(&root, ".", directory_flags(), Mode::empty())?
        } else {
            let (fd, name) = parent(&root, &path, false)?;
            host::openat(&fd, name.as_str(), directory_flags(), Mode::empty())?
        };
        let file = File::from(fd);
        file.set_times(fs::FileTimes::new().set_modified(mtime))?;
        host::fchmod(&file, Mode::from_raw_mode(raw_mode(mode & !0o222)))?;
    }
    seal_directories(&root)
}

fn verify_recorded(directory: &Path, meta: &OverlayMeta) -> io::Result<Option<bool>> {
    verify_recorded_with(directory, meta, &|meta| {
        crate::overlay_cmd::classify_base(
            None,
            Some(meta),
            None,
            &crate::base_identity::OverlayRunContext::default(),
        )
    })
}

/// Whether a recorded base URL names a remote object: unpack never opens one
/// (it would touch the network on a path that only verifies a bundle).
fn recorded_base_is_remote(base: &str) -> bool {
    base.contains("://") && !base.starts_with("file://") && !base.starts_with("git://")
}

/// [`verify_recorded`] with the classifier injected, so a test can prove the
/// opener is not reached for a recorded remote base.
fn verify_recorded_with(
    directory: &Path,
    meta: &OverlayMeta,
    classify: &dyn Fn(&OverlayMeta) -> Result<ratarmount_compositing::ClassifiedBase, String>,
) -> io::Result<Option<bool>> {
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
    // Decided BEFORE the opener is called: catching its error afterwards would
    // already have made the request.
    let recorded_remote_place = meta
        .get("base_location")
        .is_some_and(|row| row.starts_with("remote:"));
    if recorded_base_is_remote(base) || recorded_remote_place {
        return Ok(None);
    }
    let lowers = meta.lower_layers().map_err(io::Error::other)?;
    if lowers.iter().any(|l| !l.path.exists()) {
        return Ok(None);
    }
    let lower =
        classify(meta).and_then(|base| crate::overlay_cmd::lower_view(&base, &[], Some(meta)));
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
#[cfg(test)]
fn unpack(bundle: &Path, directory: &Path) -> io::Result<UnpackOutcome> {
    unpack_with_limits(bundle, directory, Limits::resolve(None, None)?)
}

pub fn unpack_with_limits(
    bundle: &Path,
    directory: &Path,
    limits: Limits,
) -> io::Result<UnpackOutcome> {
    unpack_impl(bundle, directory, limits)
}

fn unpack_impl(bundle: &Path, directory: &Path, limits: Limits) -> io::Result<UnpackOutcome> {
    let metadata = bundle_meta(bundle, limits)?;
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
    // Stage beside the destination, so publishing a read-only directory does
    // not need write permission to update its `..` across different parents.
    let stage = Stage::new_in(output_parent, ".ratarmount-unpack-", false)?;
    let layer = stage.path();
    let recorded = extract_with_limits(bundle, layer, limits)
        .map_err(|e| io::Error::new(e.kind(), format!("extract layer: {e}")))?;
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
    finalize_stage(layer, recorded)?;
    publish_layer(layer, directory)?;
    Ok(outcome)
}

/// Move a staged layer into place. macOS (like the BSDs) needs write
/// permission on a directory to rename it, even within one parent, and the
/// sealed layer root is read-only. Hold the root by fd so the permission
/// change follows the renamed inode.
fn publish_layer(layer: &Path, directory: &Path) -> io::Result<()> {
    let root = host::open(layer, directory_flags(), Mode::empty())?;
    let sealed = ratarmount_compositing::host_stat::fstat_named(&root, layer)?.st_mode;
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
type ExtractHook = std::cell::RefCell<Option<Box<dyn Fn(&Path)>>>;

#[cfg(test)]
thread_local! {
    static VERIFY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static AFTER_COPY: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
    static MID_EXTRACT: ExtractHook =
        const { std::cell::RefCell::new(None) };
    static AFTER_EXTRACT: ExtractHook =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_extract_hook(hook: &'static std::thread::LocalKey<ExtractHook>, stage: &Path) {
    hook.with(|h| {
        if let Some(h) = h.borrow().as_ref() {
            h(stage);
        }
    });
}

/// Copy the bundle into a private file inside the cache while hashing it, so
/// everything after reads exactly the hashed bytes and never the original path.
fn private_copy(bundle: &Path, cache: &Path) -> io::Result<(tempfile::NamedTempFile, String)> {
    use sha2::{Digest, Sha256};
    let mut source = File::open(bundle)?;
    let mut copy = tempfile::Builder::new()
        .prefix(COPY_PREFIX)
        .suffix(".tar.zst")
        .tempfile_in(cache)?;
    // The flock lives as long as the copy's descriptor, i.e. until it is dropped.
    if !try_flock(copy.as_file()) {
        return Err(io::Error::other("staging file is locked"));
    }
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
    let metadata = bundle_meta(copy.path(), Limits::resolve(None, None)?)?;
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
    let stage = Stage::new_in(cache, ".ratarmount-layer-", true)?;
    let layer = stage.path();
    let recorded = extract(copy.path(), layer)
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
    finalize_stage(layer, recorded)?;
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
pub(crate) mod tests {
    use super::*;
    use ratarmount_compositing::FolderMountSource;
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
            let ov = crate::base_identity::fixtures::overlay_over(
                base.clone(),
                &dir,
                base_dir.to_str().unwrap(),
                Vec::new(),
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
                crate::base_identity::fixtures::seal(&dir, base.clone()).unwrap();
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

    /// Regression: the sanitized database copy was written through the staging
    /// path as given; with NOFOLLOW inherited from the source connection,
    /// `VACUUM INTO` failed with "unable to open database" when any staging
    /// component is a symlink (macOS `/var`). Credentials must still be gone.
    #[test]
    fn regression_sanitized_db_staging_below_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir_all(real.join("stage")).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let dir = tmp.path().join("layer");
        fs::create_dir(&dir).unwrap();
        let raw = "https://user:s3cr3t@h.example/b.tar?X-Amz-Signature=deadbeef";
        let conn = rusqlite::Connection::open(dir.join(HIDDEN_DB)).unwrap();
        conn.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
            .unwrap();
        conn.execute("INSERT INTO meta VALUES('base_url', ?1)", [raw])
            .unwrap();
        let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
        drop(conn);
        let copy = staged_db(&dir, &link.join("stage"), &meta, &meta, false).unwrap();
        let bytes = fs::read(copy).unwrap();
        assert!(!bytes.windows(6).any(|w| w == b"s3cr3t"));
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
        let writer = crate::base_identity::fixtures::overlay_over(
            lower.clone(),
            &top,
            lower_meta.base_url().unwrap(),
            vec![LowerLayerRecord {
                path: f.dir.clone(),
                layer_digest: lower_meta.get("layer_digest").unwrap().into(),
                sealed_at: lower_meta.get("sealed_at").unwrap().into(),
            }],
        )
        .unwrap();
        writer.unlink("/sub/file").unwrap();
        let fd = writer.create_file("/new", 0o640).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(top.join("new"), b"new bytes").unwrap();
        drop(writer);
        ratarmount_compositing::overlay_fsck::fsck(&top, true).unwrap();
        crate::base_identity::fixtures::seal(&top, lower.clone()).unwrap();
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
        // The member is a copy SQLite made (#156): the same rows, not
        // necessarily the same bytes.
        assert_eq!(
            db_rows(&restored.join(HIDDEN_DB)),
            db_rows(&f.dir.join(HIDDEN_DB))
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
        let (_, view) = crate::MountLowerStack::open(
            f.base.clone(),
            None,
            std::slice::from_ref(&first),
            false,
            &crate::lower_stack_services(),
        )
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

    /// Regression (Keystone mutant `!= || !=` -> `&&` on the cache-hit meta
    /// check): a cached layer whose `layer_digest` still matches but whose other
    /// meta rows differ from the bundle's is refused, not served.
    #[test]
    fn regression_cache_hit_refused_when_only_other_meta_rows_differ() {
        let f = Fixture::new(true);
        let bundle = f.bundle("bundle.tar.zst");
        let cache = f.tmp.path().join("cache");
        let entry = cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        // A hit still works untouched.
        assert!(cached_lower_in(&bundle, &cache, f.base.clone(), None).is_ok());
        for dir in [&entry, &entry.join("layer")] {
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
        }
        let db = entry.join(HIDDEN_DB);
        fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute("UPDATE meta SET value='elsewhere' WHERE key='base_url'", [])
            .unwrap();
        drop(conn);
        let error = cached_lower_in(&bundle, &cache, f.base.clone(), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match the bundle"), "{error}");
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
        append_host(&mut tar, &root, "", None).unwrap();
        for path in paths {
            append_host(&mut tar, &root, &path, None).unwrap();
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
        let writer = crate::base_identity::fixtures::overlay_over(
            source.clone(),
            &directory,
            base.to_str().unwrap(),
            Vec::new(),
        )
        .unwrap();
        let fd = writer.create_file("/added", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(directory.join("added"), b"new bytes").unwrap();
        drop(writer);
        crate::base_identity::fixtures::seal(&directory, source.clone()).unwrap();
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
                // The local archive the classified base is (what `overlay pack`
                // takes from the token).
                base: Some(base.clone()),
                base_rows: None,
                check_change_set: false,
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

    /// Every row of every table of the database at `path` (read-only), by
    /// table name, rows sorted.
    fn db_rows(path: &Path) -> BTreeMap<String, Vec<Vec<String>>> {
        let conn =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        tables
            .into_iter()
            .map(|table| {
                let mut statement = conn
                    .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
                    .unwrap();
                let columns = statement.column_count();
                let mut rows: Vec<Vec<String>> = statement
                    .query_map([], |r| {
                        (0..columns)
                            .map(|i| r.get_ref(i).map(|v| format!("{v:?}")))
                            .collect()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                rows.sort();
                (table, rows)
            })
            .collect()
    }

    fn with_pack_record_hook<T>(
        hook: &'static std::thread::LocalKey<PackRecordHook>,
        callback: impl FnOnce() + 'static,
        run: impl FnOnce() -> T,
    ) -> T {
        struct Restore {
            hook: &'static std::thread::LocalKey<PackRecordHook>,
            previous: Option<Box<dyn FnOnce()>>,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                self.hook.with(|slot| {
                    *slot.borrow_mut() = self.previous.take();
                });
            }
        }
        let _restore = Restore {
            hook,
            previous: hook.with(|slot| slot.replace(Some(Box::new(callback)))),
        };
        run()
    }

    const PACK_NO_FILES_TABLE: &str =
        "the overlay database has no files table (the record of a used overlay is lost)";
    const PACK_USED_MARKERS: [&str; 2] = [
        ".ratarmount-overlay.used",
        ".ratarmount.overlay.sqlite.used",
    ];

    fn prepare_record_loss(f: &Fixture) {
        // Corruption must work without root, and production must leave these
        // deliberately prepared modes unchanged after refusing.
        fs::set_permissions(&f.dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(f.dir.join(HIDDEN_DB), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(PACK_USED_MARKERS
            .iter()
            .any(|name| f.dir.join(name).exists()));
    }

    fn lose_pack_record(directory: &Path, remove_markers: bool, table: &str) {
        if remove_markers {
            for name in PACK_USED_MARKERS {
                match fs::remove_file(directory.join(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => panic!("remove marker {name}: {error}"),
                }
            }
        }
        // An independent connection to the same nonempty inode.
        let other = rusqlite::Connection::open(directory.join(HIDDEN_DB)).unwrap();
        other
            .execute_batch(match table {
                "files" => "DROP TABLE files",
                "meta" => "DROP TABLE meta",
                _ => unreachable!("only record tables are corrupted"),
            })
            .unwrap();
    }

    fn record_modes(directory: &Path) -> BTreeMap<PathBuf, u32> {
        fn collect(root: &Path, path: &Path, modes: &mut BTreeMap<PathBuf, u32>) {
            let metadata = fs::symlink_metadata(path).unwrap();
            modes.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                metadata.mode() & 0o7777,
            );
            if metadata.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    collect(root, &entry.unwrap().path(), modes);
                }
            }
        }
        let mut modes = BTreeMap::new();
        collect(directory, directory, &mut modes);
        modes
    }

    fn assert_pack_record_loss_preserved(
        f: &Fixture,
        mut rows: BTreeMap<String, Vec<Vec<String>>>,
        mut modes: BTreeMap<PathBuf, u32>,
        sentinel: &[u8],
        remove_markers: bool,
        lost_table: &str,
    ) {
        rows.remove(lost_table);
        assert_eq!(db_rows(&f.dir.join(HIDDEN_DB)), rows);
        if remove_markers {
            for name in PACK_USED_MARKERS {
                modes.remove(Path::new(name));
            }
        }
        assert_eq!(record_modes(&f.dir), modes);
        assert_eq!(fs::read(f.dir.join(SENTINEL)).unwrap(), sentinel);
    }

    /// Regression: removing markers after the immutable metadata acquisition
    /// weakened pack's required-record read, accepting a lost files table.
    #[test]
    fn regression_pack_required_record_marker_removal_refuses() {
        for public_pack in [false, true] {
            let f = Fixture::new(true);
            prepare_record_loss(&f);
            let rows = db_rows(&f.dir.join(HIDDEN_DB));
            let modes = record_modes(&f.dir);
            let sentinel = fs::read(f.dir.join(SENTINEL)).unwrap();
            let output = f.tmp.path().join("output");
            fs::create_dir(&output).unwrap();
            let bundle = output.join("refused.tar.zst");
            let fired = std::rc::Rc::new(std::cell::Cell::new(0));
            let count = fired.clone();
            let directory = f.dir.clone();
            let error = with_pack_record_hook(
                &AFTER_IMMUTABLE_META_ACQUIRE,
                move || {
                    count.set(count.get() + 1);
                    lose_pack_record(&directory, true, "files");
                },
                || {
                    if public_pack {
                        pack(&f.dir, &bundle, f.base.clone(), &PackOptions::default()).map(|_| ())
                    } else {
                        immutable_meta(&f.dir).map(|_| ())
                    }
                },
            )
            .unwrap_err();
            assert_eq!(fired.get(), 1, "the caller acquisition hook ran once");
            assert_eq!(error.to_string(), PACK_NO_FILES_TABLE);
            assert_pack_record_loss_preserved(&f, rows, modes, &sentinel, true, "files");
            assert!(!bundle.exists());
            assert_eq!(fs::read_dir(&output).unwrap().count(), 0, "no staging");
        }
    }

    /// Regression: pack's later source acquisition/snapshot forgot the
    /// earlier required record, publishing a snapshot without files.
    /// A snapshot with a lost metadata table must also refuse publication.
    #[test]
    fn regression_pack_required_record_lost_before_snapshot_refuses() {
        for (remove_markers, table) in [(false, "files"), (true, "files"), (false, "meta")] {
            let f = Fixture::new(true);
            prepare_record_loss(&f);
            let rows = db_rows(&f.dir.join(HIDDEN_DB));
            let modes = record_modes(&f.dir);
            let sentinel = fs::read(f.dir.join(SENTINEL)).unwrap();
            let output = f.tmp.path().join("output");
            fs::create_dir(&output).unwrap();
            let bundle = output.join("refused.tar.zst");
            let fired = std::rc::Rc::new(std::cell::Cell::new(0));
            let count = fired.clone();
            let directory = f.dir.clone();
            let error = with_pack_record_hook(
                &BEFORE_STAGED_DB_ACQUIRE,
                move || {
                    count.set(count.get() + 1);
                    lose_pack_record(&directory, remove_markers, table);
                },
                || pack(&f.dir, &bundle, f.base.clone(), &PackOptions::default()),
            )
            .unwrap_err();
            assert_eq!(fired.get(), 1, "the later source acquisition was reached");
            assert_eq!(
                error.to_string(),
                if table == "files" {
                    PACK_NO_FILES_TABLE
                } else {
                    "overlay snapshot has no metadata"
                }
            );
            assert_pack_record_loss_preserved(&f, rows, modes, &sentinel, remove_markers, table);
            assert!(!bundle.exists());
            assert_eq!(fs::read_dir(&output).unwrap().count(), 0, "stage cleaned");
        }
    }

    /// Regression: append_host's ordinary payload path must retain admission
    /// of a registered database alias before any data descriptor is opened.
    #[test]
    fn regression_pack_payload_db_alias_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let layer = temp.path().join("layer");
        fs::create_dir(&layer).unwrap();
        let database = temp.path().join("held.sqlite");
        rusqlite::Connection::open(&database)
            .unwrap()
            .execute_batch("CREATE TABLE files (x); INSERT INTO files VALUES (1)")
            .unwrap();
        fs::hard_link(&database, layer.join("payload")).unwrap();
        let holder = ratarmount_compositing::open_overlay_db(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            ratarmount_compositing::DbName::Path,
        )
        .unwrap();
        holder.execute_batch("BEGIN; SELECT * FROM files").unwrap();
        assert!(other_process_sees_lock(&database));
        let root = open_root(&layer).unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let error = append_host(&mut builder, &root, "payload", None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(other_process_sees_lock(&database), "holder lock retained");
        holder.execute_batch("COMMIT").unwrap();
    }

    /// Regression: finalization opened a data descriptor just to chmod a
    /// staged alias, releasing an independently held database's SHARED lock.
    #[test]
    fn regression_finalize_stage_chmod_keeps_db_alias_lock() {
        let temp = tempfile::tempdir().unwrap();
        let stage = temp.path().join("stage");
        fs::create_dir(&stage).unwrap();
        let database = temp.path().join("held.sqlite");
        rusqlite::Connection::open(&database)
            .unwrap()
            .execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1)")
            .unwrap();
        let alias = stage.join("alias");
        fs::hard_link(&database, &alias).unwrap();
        let before = fs::metadata(&alias).unwrap();
        let holder = rusqlite::Connection::open(&database).unwrap();
        holder.execute_batch("BEGIN; SELECT * FROM t").unwrap();
        assert!(other_process_sees_lock(&database));
        finalize_stage(
            &stage,
            Recorded {
                files: [("alias".into(), 0o666)].into(),
                directories: BTreeMap::new(),
            },
        )
        .unwrap();
        let after = fs::metadata(&alias).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.mode() & 0o777, 0o444);
        assert!(other_process_sees_lock(&database), "chmod kept the lock");
        drop(holder);
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// Set by [`other_process_sees_lock`] for the child it spawns.
    const GETLK_PROBE_ENV: &str = "RATARMOUNT_TEST_PACK_GETLK_PROBE";

    /// The child half of [`other_process_sees_lock`]: `F_GETLK` for a write
    /// lock over SQLite's lock bytes (PENDING, RESERVED and the SHARED range
    /// at `0x40000000`) on a read-only descriptor. A no-op unless spawned.
    #[test]
    fn pack_getlk_probe_child() {
        use std::os::fd::AsRawFd;
        let Some(db) = std::env::var_os(GETLK_PROBE_ENV) else {
            return;
        };
        let file = File::open(db).unwrap();
        // SAFETY: a zeroed `flock` is a valid argument; F_GETLK only fills it.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        lock.l_start = 0x4000_0000;
        lock.l_len = 512;
        // SAFETY: `file` is open and `lock` lives across the call.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) },
            0,
            "F_GETLK: {}",
            io::Error::last_os_error()
        );
        // `F_UNLCK` is a `c_short` on Apple platforms, a `c_int` on Linux.
        #[allow(clippy::unnecessary_cast)]
        let unlocked = i32::from(lock.l_type) == libc::F_UNLCK as i32;
        println!("GETLK:{}", if unlocked { "unlocked" } else { "locked" });
    }

    /// Does another process see any SQLite lock this process holds on `db`
    /// (SHARED included, which `BEGIN IMMEDIATE` cannot see; read-only files
    /// too)? The child must exit successfully.
    fn other_process_sees_lock(db: &Path) -> bool {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "overlay_pack::tests::pack_getlk_probe_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(GETLK_PROBE_ENV, db)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "probe child failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if stdout.contains("GETLK:locked") {
            return true;
        }
        assert!(stdout.contains("GETLK:unlocked"), "probe child: {stdout}");
        false
    }

    /// Regression: (#156): `overlay pack` read the layer database through a
    /// descriptor of its own whenever no credential had to be redacted;
    /// closing it released every fcntl lock this process held on the database
    /// (here a plain read transaction of another connection, so another
    /// process could write under it). The database member is now always a
    /// copy SQLite makes in the staging directory, and the bundle still
    /// unpacks and verifies.
    #[test]
    fn regression_pack_keeps_in_process_db_lock() {
        let f = Fixture::new(true);
        let db = f.dir.join(HIDDEN_DB);
        // A sealed layer (database and directory) is read-only, so the holder
        // only reads; the index test below has a holder that writes after.
        let holder =
            rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        holder
            .execute_batch("BEGIN; SELECT count(*) FROM files;")
            .unwrap();
        assert!(other_process_sees_lock(&db), "the holder's SHARED lock");
        let bundle = f.tmp.path().join("held.tar.zst");
        pack(&f.dir, &bundle, f.base.clone(), &PackOptions::default()).unwrap();
        assert!(
            other_process_sees_lock(&db),
            "pack's read of the database released the holder's lock"
        );
        holder
            .execute_batch("SELECT count(*) FROM files; COMMIT;")
            .unwrap();
        drop(holder);
        let report = unpack(&bundle, &f.tmp.path().join("held-restored")).unwrap();
        assert!(report.ok && report.verified);
    }

    /// Regression: (#156): `overlay pack --include-index` read the base's
    /// index through a descriptor of its own; closing it released every
    /// fcntl lock this process held on the index, a session's included (a
    /// WAL connection keeps SHARED on the file for its whole life, which is
    /// what stops another process from checkpointing and deleting the WAL
    /// under it). The member is now a `VACUUM INTO` copy with the same rows.
    #[test]
    fn regression_pack_include_index_keeps_session_lock() {
        let f = Fixture::new(true);
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
        let holder = rusqlite::Connection::open(&index).unwrap();
        let rows: i64 = holder
            .query_row("SELECT count(*) FROM files", [], |r| r.get(0))
            .unwrap();
        assert!(other_process_sees_lock(&index), "the session's SHARED lock");
        let bundle = f.tmp.path().join("indexed.tar.zst");
        pack(
            &f.dir,
            &bundle,
            f.base.clone(),
            &PackOptions {
                include_index: true,
                base: Some(base.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            other_process_sees_lock(&index),
            "pack's read of the index released the session's lock"
        );
        holder
            .execute_batch("CREATE TABLE after_pack (x); DROP TABLE after_pack;")
            .unwrap();
        let body = ratarmount_compress::open_seekable_zstd(&bundle).unwrap();
        let mut archive = tar::Archive::new(body.open_reader().unwrap());
        let shipped = f.tmp.path().join("shipped.sqlite");
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == "index/base.tar.index.sqlite" {
                io::copy(&mut entry, &mut File::create(&shipped).unwrap()).unwrap();
            }
        }
        let copy = rusqlite::Connection::open(&shipped).unwrap();
        let copied: i64 = copy
            .query_row("SELECT count(*) FROM files", [], |r| r.get(0))
            .unwrap();
        assert_eq!(copied, rows);
    }

    /// Regression: (R11-S5-FIX7): `--include-index` tested the index with
    /// `is_file()`, which follows a symlink, so a dangling symlinked index was
    /// skipped without a word. A symlink at the index name (dangling or not)
    /// now reaches the snapshot, which refuses it by name.
    #[cfg(unix)]
    #[test]
    fn regression_pack_include_index_refuses_symlinked_index() {
        let f = Fixture::new(true);
        let base = f.tmp.path().join("base.tar");
        let mut tar = tar::Builder::new(File::create(&base).unwrap());
        append_bytes(&mut tar, "hello", b"base").unwrap();
        tar.finish().unwrap();
        let index = ratarmount_index::default_index_path(&base);
        let real = f.tmp.path().join("real.index.sqlite");
        rusqlite::Connection::open(&real)
            .unwrap()
            .execute_batch("CREATE TABLE t (x);")
            .unwrap();
        for target in [real.clone(), f.tmp.path().join("missing.sqlite")] {
            let _ = std::fs::remove_file(&index);
            std::os::unix::fs::symlink(&target, &index).unwrap();
            let bundle = f.tmp.path().join("symlinked.tar.zst");
            let err = pack(
                &f.dir,
                &bundle,
                f.base.clone(),
                &PackOptions {
                    include_index: true,
                    base: Some(base.clone()),
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("not a regular file"),
                "{}: {err:#}",
                target.display()
            );
            assert!(!bundle.exists());
        }
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

    fn bundle_members(bundle: &Path) -> Vec<String> {
        let body = ratarmount_compress::open_seekable_zstd(bundle).unwrap();
        let mut archive = tar::Archive::new(body.open_reader().unwrap());
        archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    /// Regression: bundles carried no layout version, so a future layout was
    /// unpacked as layout 1. `pack` writes `bundle.json`; a newer layout is
    /// refused by unpack and by the `--lower` cache; layout 1 and a bundle with
    /// no member both work.
    #[test]
    fn regression_bundle_json_layout_version_gate() {
        let f = Fixture::new(true);
        let bundle = f.bundle("good.tar.zst");
        assert!(bundle_members(&bundle).iter().any(|m| m == "bundle.json"));
        let out = f.tmp.path().join("ok1");
        assert!(unpack(&bundle, &out).unwrap().ok);

        let newer = f.tmp.path().join("newer.tar.zst");
        retar_with(&bundle, &newer, "bundle.json", br#"{"bundle_format":2}"#);
        let error = unpack(&newer, &f.tmp.path().join("no"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("bundle layout 2 is newer than this ratarmount supports (1)"),
            "{error}"
        );
        let cache = f.tmp.path().join("cache");
        let error = cached_lower_in(&newer, &cache, f.base.clone(), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("bundle layout 2 is newer"), "{error}");
        assert!(cache_entries(&cache).is_empty());

        for bad in [&br#"{"bundle_format":"1"}"#[..], b"[]", b"not json"] {
            let broken = f.tmp.path().join("broken.tar.zst");
            let _ = fs::remove_file(&broken);
            retar_with(&bundle, &broken, "bundle.json", bad);
            assert!(unpack(&broken, &f.tmp.path().join("nob")).is_err());
        }

        let v1 = f.tmp.path().join("v1.tar.zst");
        retar_with(&bundle, &v1, "bundle.json", br#"{"bundle_format":1}"#);
        assert!(unpack(&v1, &f.tmp.path().join("ok2")).unwrap().ok);
    }

    /// A bundle from before `bundle.json` (no member) is layout 1.
    #[test]
    fn regression_bundle_without_bundle_json_is_layout_1() {
        let f = Fixture::new(true);
        let bundle = f.bundle("good.tar.zst");
        let body = ratarmount_compress::open_seekable_zstd(&bundle).unwrap();
        let mut archive = tar::Archive::new(body.open_reader().unwrap());
        let mut builder = tar::Builder::new(Vec::new());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == "bundle.json" {
                continue;
            }
            let mut header = entry.header().clone();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
        }
        let bytes = builder.into_inner().unwrap();
        let old = f.tmp.path().join("old.tar.zst");
        let mut writer = ratarmount_compress::ZstdFrameWriter::new(File::create(&old).unwrap(), 3);
        writer.write_frame(&bytes[..]).unwrap();
        writer.finish().unwrap();
        assert!(!bundle_members(&old).iter().any(|m| m == "bundle.json"));
        assert!(unpack(&old, &f.tmp.path().join("restored")).unwrap().ok);
    }

    type Seen = Arc<std::sync::Mutex<Vec<(&'static str, Vec<String>)>>>;

    fn missing_user_write(root: &Path) -> Vec<String> {
        let mut bad = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let meta = fs::symlink_metadata(&dir).unwrap();
            if meta.permissions().mode() & 0o200 == 0 {
                bad.push(dir.display().to_string());
            }
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let meta = fs::symlink_metadata(&path).unwrap();
                    if meta.is_dir() {
                        stack.push(path);
                    } else if !meta.file_type().is_symlink()
                        && meta.permissions().mode() & 0o200 == 0
                    {
                        bad.push(path.display().to_string());
                    }
                }
            }
        }
        bad
    }

    /// A read-only staging tree as a SIGKILLed unpack leaves it.
    fn make_stale(parent: &Path, name: &str, with_lock: bool) -> PathBuf {
        let stage = parent.join(name);
        fs::create_dir_all(stage.join("sub/deeper")).unwrap();
        fs::write(stage.join("sub/deeper/file"), b"x").unwrap();
        for dir in ["sub/deeper", "sub", ""] {
            fs::set_permissions(stage.join(dir), fs::Permissions::from_mode(0o500)).unwrap();
        }
        fs::set_permissions(
            stage.join("sub/deeper/file"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        File::open(&stage)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(
                std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 365 * 86400),
            ))
            .unwrap();
        if with_lock {
            fs::write(parent.join(format!("{name}.lock")), b"").unwrap();
        }
        stage
    }

    fn hold_lock(path: &Path) -> File {
        use std::os::fd::AsRawFd;
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        file
    }

    /// Regression (Ilya QA2 N4): extraction stripped write bits as it went, so
    /// a SIGKILL mid-unpack left a tree `rm -rf` cannot remove.
    #[test]
    fn regression_unpack_staging_is_writable_during_extract() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let seen: Seen = Arc::default();
        for (name, key) in [("mid", 0), ("after", 1)] {
            let seen = seen.clone();
            let hook: Box<dyn Fn(&Path)> = Box::new(move |stage| {
                seen.lock().unwrap().push((name, missing_user_write(stage)));
            });
            if key == 0 {
                MID_EXTRACT.with(|h| *h.borrow_mut() = Some(hook));
            } else {
                AFTER_EXTRACT.with(|h| *h.borrow_mut() = Some(hook));
            }
        }
        let out = f.tmp.path().join("out");
        let report = unpack(&bundle, &out).unwrap();
        MID_EXTRACT.with(|h| *h.borrow_mut() = None);
        AFTER_EXTRACT.with(|h| *h.borrow_mut() = None);
        assert!(report.ok);
        let seen = seen.lock().unwrap();
        assert!(seen.iter().any(|(n, _)| *n == "mid"));
        assert!(seen.iter().any(|(n, _)| *n == "after"));
        for (name, bad) in seen.iter() {
            assert!(
                bad.is_empty(),
                "{name}: not writable during extract: {bad:?}"
            );
        }
        // Published layers are read-only as before.
        assert_eq!(fs::metadata(&out).unwrap().permissions().mode() & 0o222, 0);
        assert_eq!(
            fs::metadata(out.join("sub/file"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o551 & !0o222
        );
    }

    /// Regression (fold-in 4): the stage lock lives beside the stage and is
    /// never layer content.
    #[test]
    fn regression_stage_lock_is_not_layer_content() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let out = f.tmp.path().join("out");
        unpack(&bundle, &out).unwrap();
        let locks = |dir: &Path| -> Vec<String> {
            fs::read_dir(dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".lock"))
                .collect()
        };
        assert!(locks(&out).is_empty(), "{:?}", locks(&out));
        assert!(locks(f.tmp.path()).is_empty(), "{:?}", locks(f.tmp.path()));
        let cache = f.tmp.path().join("cache");
        let layer = cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        assert!(locks(&layer).is_empty());
        assert!(locks(&cache).is_empty(), "{:?}", locks(&cache));
        assert!(
            ratarmount_compositing::overlay_seal::verify(&layer, f.base.clone())
                .unwrap()
                .ok
        );
    }

    /// Regression (Ilya QA2 N4): abandoned read-only staging dirs are swept.
    #[test]
    fn regression_unpack_sweeps_stale_read_only_staging() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let parent = f.tmp.path().join("work");
        fs::create_dir(&parent).unwrap();
        let stale = make_stale(&parent, ".ratarmount-unpack-Stale1", true);
        let foreign = make_stale(&parent, "other-stale", false);
        let target = parent.join("target");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, parent.join(".ratarmount-unpack-link")).unwrap();
        unpack(&bundle, &parent.join("out")).unwrap();
        assert!(!stale.exists(), "stale stage survived");
        assert!(!parent.join(".ratarmount-unpack-Stale1.lock").exists());
        assert!(foreign.exists(), "foreign prefix must survive");
        assert!(target.exists());
        assert!(fs::symlink_metadata(parent.join(".ratarmount-unpack-link")).is_ok());
    }

    /// Regression (R4-S5): the sweep matched stage names by prefix only and
    /// recursively deleted a user's `.ratarmount-pack-stage-notes/` once it was
    /// a day old. Only the generated shape (prefix + six alphanumerics) matches.
    #[test]
    fn regression_stage_sweep_requires_exact_generated_name() {
        let tmp = tempfile::tempdir().unwrap();
        let day = std::time::Duration::from_secs(3 * 24 * 3600);
        let old = std::time::SystemTime::now() - day;
        let mut foreign = Vec::new();
        for name in [
            ".ratarmount-pack-stage-notes",
            ".ratarmount-pack-stage-",
            ".ratarmount-pack-stage-abc12345",
            ".ratarmount-unpack-keep",
            ".ratarmount-layer-a_b123",
        ] {
            let dir = tmp.path().join(name);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("precious"), b"mine").unwrap();
            File::open(&dir)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(old))
                .unwrap();
            foreign.push(dir);
        }
        let ours = tmp.path().join(".ratarmount-pack-stage-Ab3xY9");
        fs::create_dir(&ours).unwrap();
        File::open(&ours)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
        sweep_stale_stages(tmp.path(), false);
        assert!(!ours.exists(), "generated stale stage survived");
        for dir in foreign {
            assert!(dir.join("precious").exists(), "{dir:?} was swept");
        }
    }

    /// Set by [`pack_db_lock_busy_in_child`] for the child it spawns.
    const PACK_DB_PROBE_ENV: &str = "RATARMOUNT_TEST_PACK_DB_PROBE";

    /// The child half of [`pack_db_lock_busy_in_child`]: `BEGIN IMMEDIATE`
    /// alone, busy timeout 0.
    #[test]
    fn pack_db_lock_probe_child() {
        let Some(db) = std::env::var_os(PACK_DB_PROBE_ENV) else {
            return;
        };
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        match conn.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => println!("PROBE:acquired"),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                println!("PROBE:busy")
            }
            Err(e) => panic!("probe: {e}"),
        }
    }

    /// Another process's `BEGIN IMMEDIATE` on `db` is busy (the child must
    /// exit successfully).
    pub(crate) fn pack_db_lock_busy_in_child(db: &Path) -> bool {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "overlay_pack::tests::pack_db_lock_probe_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PACK_DB_PROBE_ENV, db)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "probe child failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if stdout.contains("PROBE:busy") {
            return true;
        }
        assert!(stdout.contains("PROBE:acquired"), "probe child: {stdout}");
        false
    }

    /// Regression (R10-FIX3, r10 skeptic #3): an old pack-temp name that is a
    /// hard link of an open overlay database. The sweeper opened it, took a
    /// flock and closed it, releasing every fcntl lock this process held on
    /// the database (another process's `BEGIN IMMEDIATE` then succeeded
    /// while the holder still wrote). The admitted open skips it: the name
    /// stays, the child is still busy and the holder still commits.
    /// Regression (R10-FIX9, r10 review N1): `immutable_meta` opened the
    /// layer database by its own name to check its type and closed that
    /// descriptor, which released every fcntl lock this process held on the
    /// database (another process's `BEGIN IMMEDIATE` then succeeded while
    /// the holder still wrote). It stats the name now.
    #[test]
    fn regression_immutable_meta_keeps_the_holders_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let db = dir.join(HIDDEN_DB);
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute_batch("CREATE TABLE files (x)")
            .unwrap();
        let holder = ratarmount_compositing::open_overlay_db(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            ratarmount_compositing::DbName::Path,
        )
        .unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(pack_db_lock_busy_in_child(&db), "the holder's lock");
        let error = immutable_meta(&dir).expect_err("not a sealed layer");
        assert!(error.to_string().contains("not sealed"), "{error}");
        assert!(
            pack_db_lock_busy_in_child(&db),
            "immutable_meta released the holder's lock"
        );
        holder
            .execute_batch("INSERT INTO files VALUES (1); COMMIT")
            .unwrap();
        drop(holder);
        assert!(!pack_db_lock_busy_in_child(&db), "probe control");
        // A database entry that is not a regular file is still refused.
        fs::remove_file(&db).unwrap();
        fs::create_dir(&db).unwrap();
        let error = immutable_meta(&dir).expect_err("a directory");
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[test]
    fn regression_pack_temp_sweep_skips_a_db_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let db = dir.join(".ratarmount.overlay.sqlite");
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute_batch("CREATE TABLE files (x)")
            .unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        File::options()
            .write(true)
            .open(&db)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
        let alias = dir.join(".ratarmount-pack-Ab3xY9.tmp");
        fs::hard_link(&db, &alias).unwrap();
        let holder = ratarmount_compositing::open_overlay_db(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            ratarmount_compositing::DbName::Path,
        )
        .unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(pack_db_lock_busy_in_child(&db), "the holder's lock");
        sweep_pack_temps_in(&open_root(&dir).unwrap());
        assert!(alias.exists(), "a database alias is never swept");
        assert!(
            pack_db_lock_busy_in_child(&db),
            "the sweep released the holder's lock"
        );
        holder
            .execute_batch("INSERT INTO files VALUES (1); COMMIT")
            .unwrap();
        drop(holder);
        assert!(!pack_db_lock_busy_in_child(&db), "probe control");
    }

    /// Regression (R4-S5): the pack-temp sweep unlinked through the parent
    /// pathname after taking the flock; replacing the parent with a symlink
    /// then deleted a same-named file in another directory. Cleanup is relative
    /// to the directory opened once.
    #[test]
    fn regression_pack_temp_sweep_is_directory_relative() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        let decoy = tmp.path().join("decoy");
        fs::create_dir(&out).unwrap();
        fs::create_dir(&decoy).unwrap();
        let name = ".ratarmount-pack-Ab3xY9.tmp";
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for dir in [&out, &decoy] {
            let file = File::create(dir.join(name)).unwrap();
            file.set_times(fs::FileTimes::new().set_modified(old))
                .unwrap();
        }
        let pinned = open_root(&out).unwrap();
        // The parent path now names the decoy.
        fs::rename(&out, tmp.path().join("moved")).unwrap();
        std::os::unix::fs::symlink(&decoy, &out).unwrap();
        sweep_pack_temps_in(&pinned);
        assert!(
            decoy.join(name).exists(),
            "deleted through the swapped path"
        );
        assert!(!tmp.path().join("moved").join(name).exists());
    }

    /// Regression (R5-2, round-4 skeptic G2): where no atomic no-replace rename
    /// exists (BSD), the `linkat` + `unlinkat` fallback could delete a live file
    /// that replaced the stale one between the two calls. The sweep now skips
    /// quarantine entirely there and leaves the stale temps (forced on Linux by
    /// the test hook; a control run proves the sweep removes them otherwise).
    #[test]
    fn regression_sweep_without_no_replace_rename_unlinks_nothing() {
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let names = [
            ".ratarmount-pack-Ab3xY9.tmp".to_owned(),
            format!("{COPY_PREFIX}Ab3xY9"),
            ".ratarmount-pack-stage-Zz9Zz9.lock".to_owned(),
        ];
        for forced in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            for name in &names {
                let file = File::create(tmp.path().join(name)).unwrap();
                file.set_times(fs::FileTimes::new().set_modified(old))
                    .unwrap();
            }
            FORCE_NO_REPLACE_FALLBACK.with(|f| f.set(forced));
            let dir = open_root(tmp.path()).unwrap();
            sweep_pack_temps_in(&dir);
            sweep_stale_stages_in(&dir, true);
            FORCE_NO_REPLACE_FALLBACK.with(|f| f.set(false));
            // The control run removes the stale temps only where an atomic
            // no-replace rename exists; on a platform without one (BSD) the
            // unforced sweep skips quarantine too, so everything stays.
            let left_in_place = forced || !no_replace_rename_available();
            for name in &names {
                assert_eq!(
                    tmp.path().join(name).exists(),
                    left_in_place,
                    "forced={forced}: {name}"
                );
            }
            // Nothing was quarantined or left under a quarantine name either.
            let stray = fs::read_dir(tmp.path())
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains("quarantine"))
                .count();
            assert_eq!(stray, 0);
        }
    }

    /// Regression (R4-S13): the quarantine rename replaced an existing
    /// destination (an orphan after PID reuse, or any file under that name)
    /// before the inode was verified. An occupied name is never overwritten:
    /// the next name is tried, and the occupant keeps its content.
    #[test]
    fn regression_quarantine_never_replaces_an_occupied_name() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim.tmp");
        let occupied = tmp.path().join(".ratarmount-quarantine-1-0");
        let spare = tmp.path().join(".ratarmount-quarantine-1-1");
        fs::write(&occupied, b"someone else's orphan").unwrap();
        fs::write(&victim, b"pack temp").unwrap();
        let locked = File::open(&victim).unwrap();
        let dir = open_root(tmp.path()).unwrap();
        let mut names = [
            ".ratarmount-quarantine-1-0".to_owned(),
            ".ratarmount-quarantine-1-1".to_owned(),
        ]
        .into_iter();
        let removed = unlink_if_same_named(&dir, "victim.tmp", &locked, &mut || {
            names.next().expect("only two attempts expected")
        });
        assert!(removed);
        assert_eq!(fs::read(&occupied).unwrap(), b"someone else's orphan");
        assert!(!victim.exists() && !spare.exists());
        // Every name taken: nothing is removed and nothing replaced.
        let victim = tmp.path().join("victim2.tmp");
        fs::write(&victim, b"pack temp 2").unwrap();
        let locked = File::open(&victim).unwrap();
        let removed = unlink_if_same_named(&dir, "victim2.tmp", &locked, &mut || {
            ".ratarmount-quarantine-1-0".to_owned()
        });
        assert!(!removed);
        assert!(victim.exists());
        assert_eq!(fs::read(&occupied).unwrap(), b"someone else's orphan");
    }

    /// Regression (R4-S9a): the stage sweep deleted recursively through the
    /// parent pathname after taking the stage lock; replacing the parent with a
    /// symlink then removed another directory's same-named live stage. The whole
    /// removal is relative to the directory opened once, and a symlink inside a
    /// stage is unlinked, never followed. (Pre-fix the sweep took a path, so
    /// there was no way to swap it after the lock: no separate red run.)
    #[test]
    fn regression_stage_sweep_is_directory_relative_and_never_follows() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        let decoy = tmp.path().join("decoy");
        let outside = tmp.path().join("outside");
        for dir in [&out, &decoy, &outside] {
            fs::create_dir(dir).unwrap();
        }
        fs::write(outside.join("precious"), b"mine").unwrap();
        let name = ".ratarmount-pack-stage-Ab3xY9";
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3 * 24 * 3600);
        for dir in [&out, &decoy] {
            let stage = dir.join(name);
            fs::create_dir_all(stage.join("ro/deeper")).unwrap();
            fs::write(stage.join("ro/deeper/file"), b"x").unwrap();
            std::os::unix::fs::symlink(&outside, stage.join("link")).unwrap();
            fs::set_permissions(stage.join("ro"), fs::Permissions::from_mode(0o500)).unwrap();
            File::open(&stage)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(old))
                .unwrap();
        }
        let pinned = open_root(&out).unwrap();
        // The parent path now names the decoy.
        fs::rename(&out, tmp.path().join("moved")).unwrap();
        std::os::unix::fs::symlink(&decoy, &out).unwrap();
        sweep_stale_stages_in(&pinned, false);
        assert!(decoy.join(name).join("ro/deeper/file").exists());
        assert!(!tmp.path().join("moved").join(name).exists());
        assert!(outside.join("precious").exists(), "followed a symlink");
    }

    /// Regression (R4-S9b): the sweeper checked the opened inode and then
    /// unlinked the *name*; replacing the entry in between deleted a different
    /// (live, locked) file. The entry is quarantined, verified and only then
    /// unlinked; a swapped entry is put back.
    #[test]
    fn regression_unlink_if_same_leaves_a_swapped_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = open_root(tmp.path()).unwrap();
        let name = ".ratarmount-pack-Ab3xY9.tmp";
        fs::write(tmp.path().join(name), b"stale").unwrap();
        let locked = File::options()
            .read(true)
            .write(true)
            .open(tmp.path().join(name))
            .unwrap();
        // Another pack's live temp file takes the name after the open.
        fs::write(tmp.path().join("live"), b"live pack").unwrap();
        fs::rename(tmp.path().join("live"), tmp.path().join(name)).unwrap();
        assert!(!unlink_if_same(&dir, name, &locked));
        assert_eq!(fs::read(tmp.path().join(name)).unwrap(), b"live pack");
        let leftovers: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("quarantine"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        // The matching inode is removed, with no quarantine name left behind.
        let locked = File::options()
            .read(true)
            .write(true)
            .open(tmp.path().join(name))
            .unwrap();
        assert!(unlink_if_same(&dir, name, &locked));
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    /// Regression: a stage whose lock another process holds is never swept,
    /// whatever its (restored archive) root mtime says.
    #[test]
    fn regression_unpack_active_stage_is_not_swept() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let parent = f.tmp.path().join("work");
        fs::create_dir(&parent).unwrap();
        let active = make_stale(&parent, ".ratarmount-unpack-active", true);
        let _held = hold_lock(&parent.join(".ratarmount-unpack-active.lock"));
        unpack(&bundle, &parent.join("out")).unwrap();
        assert!(
            active.join("sub/deeper/file").exists(),
            "active stage swept"
        );
        assert!(parent.join(".ratarmount-unpack-active.lock").exists());
    }

    /// Regression: the cache fill sweeps stale `.ratarmount-layer-*` stages and
    /// unlocked `.ratarmount-copy-*` files, never a locked one.
    #[test]
    fn regression_cache_fill_sweeps_stale_staging() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let cache = f.tmp.path().join("cache");
        fs::create_dir(&cache).unwrap();
        let stale = make_stale(&cache, ".ratarmount-layer-Stale1", true);
        let active = make_stale(&cache, ".ratarmount-layer-active", true);
        let _held = hold_lock(&cache.join(".ratarmount-layer-active.lock"));
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let copy = |name: &str| {
            let path = cache.join(name);
            fs::write(&path, b"partial").unwrap();
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(old))
                .unwrap();
            path
        };
        let dead_copy = copy(".ratarmount-copy-dead.tar.zst");
        let live_copy = copy(".ratarmount-copy-live.tar.zst");
        let _live = hold_lock(&live_copy);
        cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        assert!(!stale.exists());
        assert!(!cache.join(".ratarmount-layer-Stale1.lock").exists());
        assert!(!dead_copy.exists());
        assert!(active.exists());
        assert!(live_copy.exists());
    }

    /// Regression: bundle copies staged by builds before the
    /// `.ratarmount-copy-` rename (`.copy-XXXXXX.tar.zst`) were never swept
    /// from the layer cache. Only that exact shape is swept, and only there,
    /// under the same lock, owner and age rules.
    #[test]
    fn regression_cache_fill_sweeps_legacy_copy_files() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let cache = f.tmp.path().join("cache");
        fs::create_dir(&cache).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let make = |name: &str, age: std::time::SystemTime| {
            let path = cache.join(name);
            fs::write(&path, b"partial").unwrap();
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(age))
                .unwrap();
            path
        };
        let dead = make(".copy-aB3xY9.tar.zst", old);
        let live = make(".copy-Zz9Aa0.tar.zst", old);
        let _live = hold_lock(&live);
        let young = make(".copy-Qw3Er4.tar.zst", std::time::SystemTime::now());
        let keep: Vec<_> = [
            ".copy-notes",
            ".copy-dead.tar.zst",
            ".copy-aB3xY.tar.zst",
            ".copy-aB3xY99.tar.zst",
            ".copy-aB3x_9.tar.zst",
            ".copy-aB3xY9.tar.zst.bak",
            "x.copy-aB3xY9.tar.zst",
        ]
        .iter()
        .map(|name| make(name, old))
        .collect();
        cached_lower_in(&bundle, &cache, f.base.clone(), None).unwrap();
        assert!(!dead.exists(), "legacy copy not swept");
        assert!(live.exists() && young.exists());
        for path in keep {
            assert!(path.exists(), "swept {}", path.display());
        }
        // Outside the layer cache (unpack destination parent) nothing is swept.
        let parent = f.tmp.path().join("work");
        fs::create_dir(&parent).unwrap();
        let mine = parent.join(".copy-aB3xY9.tar.zst");
        fs::write(&mine, b"mine").unwrap();
        File::options()
            .write(true)
            .open(&mine)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
        unpack(&bundle, &parent.join("out")).unwrap();
        assert!(mine.exists());
    }

    /// Regression: `overlay unpack bundle work/out` swept `work` and deleted the
    /// user's own old `.copy-notes`; only ratarmount's private cache is swept
    /// for copy files, and only by a ratarmount-specific prefix.
    #[test]
    fn regression_unpack_does_not_delete_user_copy_files() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let parent = f.tmp.path().join("work");
        fs::create_dir(&parent).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let mut mine = Vec::new();
        for name in [
            ".copy-notes",
            ".copy-dead.tar.zst",
            ".ratarmount-copy-notes",
        ] {
            let path = parent.join(name);
            fs::write(&path, b"mine").unwrap();
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(old))
                .unwrap();
            mine.push(path);
        }
        unpack(&bundle, &parent.join("out")).unwrap();
        for path in mine {
            assert!(path.exists(), "unpack deleted {}", path.display());
        }
    }

    /// Regression: the sweeper can lock a stage's lock file between its
    /// creation and the stage's own flock (and then removes the stage); the
    /// stage retries instead of failing "staging lock is held".
    #[test]
    fn regression_stage_new_in_retries_when_sweeper_wins_lock_race() {
        let tmp = tempfile::tempdir().unwrap();
        let attempts = std::cell::Cell::new(0);
        let stage = Stage::new_in_with(tmp.path(), ".ratarmount-unpack-", false, |dir| {
            attempts.set(attempts.get() + 1);
            if attempts.get() == 1 {
                // The sweeper removed the stage after taking its lock.
                fs::remove_dir_all(dir).unwrap();
                return Err(io::Error::other("staging lock is held by another process"));
            }
            StageLock::beside(dir)
        })
        .unwrap();
        assert_eq!(attempts.get(), 2);
        assert!(stage.path().is_dir());
    }

    /// Regression: a sweeper that took the lock first and finished (stage and
    /// lock file removed) before the stage's own flock succeeded left a lock on
    /// an unlinked inode and a missing stage dir; the first write was ENOENT.
    #[test]
    fn regression_stage_new_in_retries_when_sweeper_removed_stage_before_our_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let attempts = std::cell::Cell::new(0);
        let stage = Stage::new_in_with(tmp.path(), ".ratarmount-unpack-", false, |dir| {
            attempts.set(attempts.get() + 1);
            let lock = StageLock::beside(dir)?;
            if attempts.get() == 1 {
                // The sweeper locked, removed stage and lock file, and released
                // before our flock ran against the old inode.
                fs::remove_dir_all(dir).unwrap();
                fs::remove_file(lock_path(dir)).unwrap();
            }
            Ok(lock)
        })
        .unwrap();
        assert_eq!(attempts.get(), 2);
        assert!(stage.path().is_dir());
        fs::write(stage.path().join("f"), b"x").unwrap();
    }

    /// Regression: a lock taken on an inode the sweeper already unlinked is
    /// refused, so the stage cannot run unprotected.
    #[test]
    fn regression_stage_lock_refuses_unlinked_inode() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join(".ratarmount-unpack-x");
        fs::create_dir(&stage).unwrap();
        let first = StageLock::beside(&stage).unwrap();
        fs::remove_file(lock_path(&stage)).unwrap();
        assert!(lock_names_current_inode(&first).is_err());
        fs::write(lock_path(&stage), b"").unwrap();
        assert!(lock_names_current_inode(&first).is_err());
    }

    /// Regression: a failed fill leaves no staging directory or lock behind.
    #[test]
    fn regression_unpack_failure_leaves_removable_staging() {
        let f = Fixture::new(true);
        let good = f.bundle("good.tar.zst");
        let evil = f.tmp.path().join("evil.tar.zst");
        retar_with(&good, &evil, "layer/sub/file", b"EVIL!!!\n");
        fs::rename(f.tmp.path().join("base"), f.tmp.path().join("base-away")).unwrap();
        let view = folder(f.tmp.path().join("base-away"));
        let cache = f.tmp.path().join("cache");
        cached_lower_in(&evil, &cache, view, None).unwrap_err();
        let left: Vec<_> = fs::read_dir(&cache)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".ratarmount-") || n.ends_with(".lock"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// The published root is read-only and was renamed from a staged one.
    #[test]
    fn regression_unpack_publish_keeps_macos_rename_workaround() {
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let out = f.tmp.path().join("out");
        unpack(&bundle, &out).unwrap();
        assert_eq!(fs::metadata(&out).unwrap().permissions().mode() & 0o222, 0);
        assert!(fs::read_dir(&out).unwrap().next().is_some());
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
        let writer = crate::base_identity::fixtures::overlay_over(
            lower.clone(),
            &top,
            lower_meta.base_url().unwrap(),
            vec![LowerLayerRecord {
                path: f.dir.clone(),
                layer_digest: lower_meta.get("layer_digest").unwrap().into(),
                sealed_at: lower_meta.get("sealed_at").unwrap().into(),
            }],
        )
        .unwrap();
        writer.unlink("/sub/file").unwrap();
        let fd = writer.create_file("/new", 0o640).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(top.join("new"), b"new bytes").unwrap();
        drop(writer);
        crate::base_identity::fixtures::seal(&top, lower.clone()).unwrap();
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

    /// Regression (K1 e2e): a bundle verified under `--no-file-versions` left a
    /// marker that a plain remount trusted, although the plain view lists
    /// `f.versions/N`. Drives the real key derivation (`lower_key_for`) from
    /// parsed CLI args into the cache: the plain remount must verify again, and
    /// each view then hits its own marker.
    #[test]
    fn regression_marker_no_file_versions_then_plain_remount_reverifies() {
        use clap::Parser;
        let f = Fixture::new(true);
        let bundle = f.bundle("b.tar.zst");
        let cache = f.tmp.path().join("cache");
        let archive = f.tmp.path().join("a.tar");
        fs::write(&archive, b"aaaa").unwrap();
        let index = f.tmp.path().join("a.tar.index.sqlite");
        rusqlite::Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        ratarmount_index::cached_archive_digest(&archive, Some(&index)).unwrap();
        let mount = |extra: &[&str]| {
            let mut argv = vec!["ratarmount", "--lower", bundle.to_str().unwrap()];
            argv.extend_from_slice(extra);
            argv.push("a.tar");
            let args = crate::Args::try_parse_from(argv).unwrap();
            let key =
                crate::lower_key_for(&args, false, std::slice::from_ref(&archive), Some(&index));
            assert!(key.is_some());
            let before = verify_calls();
            crate::MountLowerStack::open_in(
                f.base.clone(),
                key.as_deref(),
                &args.lower,
                false,
                Some(&cache),
                &crate::lower_stack_services(),
            )
            .unwrap();
            verify_calls() - before
        };
        assert_eq!(mount(&["--no-file-versions"]), 1, "first use verifies");
        assert_eq!(mount(&["--no-file-versions"]), 0, "same view hits");
        assert_eq!(mount(&[]), 1, "plain remount must re-verify");
        assert_eq!(mount(&[]), 0, "plain view then hits its own marker");
        let hex = cache_entries(&cache).remove(0);
        assert_eq!(fs::read_dir(marker_dir(&cache, &hex)).unwrap().count(), 2);
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
        let writer =
            crate::base_identity::fixtures::new_overlay(f.base.clone(), &unsealed).unwrap();
        let fd = writer.create_file("/lf", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        drop(writer);
        fs::write(unsealed.join("lf"), b"aaaa").unwrap();
        let lower =
            compose_stack(f.base.clone(), &[(unsealed.clone(), Immutability::Shared)]).unwrap();
        let top = f.tmp.path().join("top");
        let writer = crate::base_identity::fixtures::overlay_over(
            lower.clone(),
            &top,
            f.tmp.path().join("base").to_str().unwrap(),
            vec![LowerLayerRecord {
                path: unsealed.clone(),
                layer_digest: String::new(),
                sealed_at: String::new(),
            }],
        )
        .unwrap();
        // Replace the lower's file: the row depends on the lower still holding
        // different bytes (an edit to the new bytes would make it a no-op).
        writer.unlink("/lf").unwrap();
        let fd = writer.create_file("/lf", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(top.join("lf"), b"bbbb").unwrap();
        drop(writer);
        crate::base_identity::fixtures::seal(&top, lower.clone()).unwrap();
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
                &crate::lower_stack_services(),
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
            &crate::lower_stack_services(),
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
        let writer = crate::base_identity::fixtures::overlay_over(
            f.base.clone(),
            &replace,
            base_dir.to_str().unwrap(),
            Vec::new(),
        )
        .unwrap();
        writer.unlink("/deleted").unwrap();
        let fd = writer.create_file("/deleted", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        fs::write(replace.join("deleted"), b"new").unwrap();
        drop(writer);
        crate::base_identity::fixtures::seal(&replace, f.base.clone()).unwrap();
        let bundle = f.tmp.path().join("replace.tar.zst");
        pack(&replace, &bundle, f.base.clone(), &PackOptions::default()).unwrap();
        let key = crate::lower_base_key(
            std::slice::from_ref(&base_dir),
            None,
            std::slice::from_ref(&bundle),
            "v",
        );
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
                &crate::lower_stack_services(),
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
            &crate::lower_stack_services(),
        )
        .err()
        .expect("edited base must fail closed");
        assert!(error.contains("deleted"), "{error}");
        // A directory has no computed strong digest, and a supplied
        // `--base-digest` is only a claim: still no marker.
        let strong = crate::lower_base_key(std::slice::from_ref(&base_dir), None, &paths, "v");
        assert_eq!(strong, None);
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

    /// Bundle of `layer/` plus the named regular files, each of the given size.
    fn sized_bundle(f: &Fixture, name: &str, files: &[(&str, usize)]) -> PathBuf {
        let mut tar = tar::Builder::new(Vec::new());
        let meta = checked_meta(&f.dir).unwrap();
        append_bytes(
            &mut tar,
            "meta.json",
            &serde_json::to_vec(meta.values()).unwrap(),
        )
        .unwrap();
        let mut dir = header(0o755, 0, 0, tar::EntryType::Directory);
        tar.append_data(&mut dir, "layer/", &[][..]).unwrap();
        for (path, size) in files {
            let body = vec![7u8; *size];
            let mut h = header(0o644, 0, *size as u64, tar::EntryType::Regular);
            tar.append_data(&mut h, format!("layer/{path}"), &body[..])
                .unwrap();
        }
        let bundle = f.tmp.path().join(name);
        let mut writer =
            ratarmount_compress::ZstdFrameWriter::new(File::create(&bundle).unwrap(), 3);
        writer.write_frame(&tar.into_inner().unwrap()[..]).unwrap();
        writer.finish().unwrap();
        bundle
    }

    fn leftovers(parent: &Path) -> Vec<String> {
        fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".ratarmount-unpack-"))
            .collect()
    }

    /// Regression: a bundle with more tar entries than the cap (a zip-bomb
    /// style entry flood) must fail, leave no destination and no staging.
    #[test]
    fn regression_extract_refuses_entry_count_over_cap() {
        let f = Fixture::new(true);
        let files: Vec<(String, usize)> = (0..6).map(|i| (format!("f{i}"), 1)).collect();
        let refs: Vec<(&str, usize)> = files.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        let bundle = sized_bundle(&f, "many.tar.zst", &refs);
        let limits = |n| Limits {
            max_bytes: u64::MAX,
            max_entries: n,
        };
        let dir = f.tmp.path().join("ex");
        fs::create_dir(&dir).unwrap();
        let err = extract_with_limits(&bundle, &dir, limits(3)).unwrap_err();
        assert!(err.to_string().contains("more than 3 entries"), "{err}");
        // Exactly at the cap (meta.json, layer/, six files) succeeds.
        let ok = f.tmp.path().join("ex-ok");
        fs::create_dir(&ok).unwrap();
        extract_with_limits(&bundle, &ok, limits(8)).unwrap();
        let dest = f.tmp.path().join("dest");
        let err = unpack_with_limits(&bundle, &dest, limits(3)).unwrap_err();
        assert!(err.to_string().contains("more than 3 entries"), "{err}");
        assert!(!dest.exists());
        assert!(leftovers(f.tmp.path()).is_empty());
    }

    /// Regression: members individually under the byte cap whose sum is over
    /// it must fail; exactly at the cap succeeds.
    #[test]
    fn regression_extract_refuses_total_bytes_over_cap() {
        let f = Fixture::new(true);
        let bundle = sized_bundle(&f, "big.tar.zst", &[("a", 600), ("b", 600)]);
        let limits = |n| Limits {
            max_bytes: n,
            max_entries: u64::MAX,
        };
        let dir = f.tmp.path().join("ex");
        fs::create_dir(&dir).unwrap();
        let err = extract_with_limits(&bundle, &dir, limits(1000)).unwrap_err();
        assert!(err.to_string().contains("more than 1000 bytes"), "{err}");
        let ok = f.tmp.path().join("ex-ok");
        fs::create_dir(&ok).unwrap();
        extract_with_limits(&bundle, &ok, limits(1200)).unwrap();
        let dest = f.tmp.path().join("dest");
        let err = unpack_with_limits(&bundle, &dest, limits(1000)).unwrap_err();
        assert!(err.to_string().contains("more than 1000 bytes"), "{err}");
        assert!(!dest.exists());
        assert!(leftovers(f.tmp.path()).is_empty());
    }

    /// A single-frame bundle (what a hostile producer writes: no seek table, so
    /// the old path decoded all of it to temporary storage) of a valid
    /// `meta.json`, `junk` non-layer bytes and a `layer/` holding `layer_bytes`.
    fn bomb_bundle(
        f: &Fixture,
        name: &str,
        junk: usize,
        layer_bytes: usize,
        meta_last: bool,
    ) -> PathBuf {
        let meta = checked_meta(&f.dir).unwrap();
        let meta_json = serde_json::to_vec(meta.values()).unwrap();
        let mut tar = tar::Builder::new(Vec::new());
        if !meta_last {
            append_bytes(&mut tar, "meta.json", &meta_json).unwrap();
        }
        let mut dir = header(0o755, 0, 0, tar::EntryType::Directory);
        tar.append_data(&mut dir, "layer/", &[][..]).unwrap();
        for (path, size) in [("junk", junk), ("layer/big", layer_bytes)] {
            let mut h = header(0o644, 0, size as u64, tar::EntryType::Regular);
            tar.append_data(&mut h, path, std::io::repeat(0).take(size as u64))
                .unwrap();
        }
        if meta_last {
            append_bytes(&mut tar, "meta.json", &meta_json).unwrap();
        }
        let bundle = f.tmp.path().join(name);
        let mut writer =
            ratarmount_compress::ZstdFrameWriter::new(File::create(&bundle).unwrap(), 3);
        writer.write_frame(&tar.into_inner().unwrap()[..]).unwrap();
        writer.finish().unwrap();
        bundle
    }

    /// Regression: `--max-bytes 100` still decoded a whole single-frame bundle
    /// to temporary storage before any counter ran, and read `meta.json`
    /// through the session factory with no cap. Decoding must stop near the cap.
    #[test]
    fn regression_unpack_caps_bound_decompression() {
        let f = Fixture::new(true);
        let limits = Limits {
            max_bytes: 100,
            max_entries: 1_000_000,
        };
        // 48 MiB of zeros in a non-layer member, then the layer, meta last.
        for (name, junk, layer, meta_last) in [
            ("junk-last.tar.zst", 48 << 20, 1 << 10, true),
            ("layer-big.tar.zst", 0, 48 << 20, false),
        ] {
            let bundle = bomb_bundle(&f, name, junk, layer, meta_last);
            DECODED_BYTES.with(|c| c.set(0));
            let dest = f.tmp.path().join(format!("dest-{name}"));
            let err = unpack_with_limits(&bundle, &dest, limits).unwrap_err();
            let decoded = DECODED_BYTES.with(|c| c.get());
            assert!(
                err.to_string().contains("more than 100 bytes"),
                "{name}: {err}"
            );
            assert!(
                decoded < (4 << 20),
                "{name}: decoded {decoded} bytes before refusing"
            );
            assert!(!dest.exists());
            assert!(leftovers(f.tmp.path()).is_empty());
        }
    }

    /// Regression: an oversized `meta.json` is refused at 1 MiB, not read whole.
    #[test]
    fn regression_unpack_caps_meta_json_read() {
        let f = Fixture::new(true);
        let mut tar = tar::Builder::new(Vec::new());
        append_bytes(&mut tar, "meta.json", &vec![b' '; 32 << 20]).unwrap();
        let bundle = f.tmp.path().join("meta-bomb.tar.zst");
        let mut writer =
            ratarmount_compress::ZstdFrameWriter::new(File::create(&bundle).unwrap(), 3);
        writer.write_frame(&tar.into_inner().unwrap()[..]).unwrap();
        writer.finish().unwrap();
        DECODED_BYTES.with(|c| c.set(0));
        let err = bundle_meta(&bundle, Limits::resolve(None, None).unwrap()).unwrap_err();
        assert!(err.to_string().contains("meta.json is larger"), "{err}");
        assert!(DECODED_BYTES.with(|c| c.get()) < (4 << 20));
    }

    /// Mutant gaps: path components that alias another path are unsafe.
    #[test]
    fn regression_safe_path_rejects_aliasing_components() {
        for bad in ["", ".", "a//b", "a/./b", "/abs", "a/../b"] {
            assert!(safe_path(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert_eq!(safe_path(b"a/b/").unwrap(), "a/b");
    }

    /// Mutant gaps: unpack refuses a non-empty, symlink or file destination
    /// and leaves each untouched.
    #[test]
    fn regression_unpack_refuses_non_directory_destinations() {
        let f = Fixture::new(true);
        let bundle = sized_bundle(&f, "ok.tar.zst", &[("a", 1)]);
        let full = f.tmp.path().join("full");
        fs::create_dir(&full).unwrap();
        fs::write(full.join("keep"), b"x").unwrap();
        let file = f.tmp.path().join("file");
        fs::write(&file, b"x").unwrap();
        let target = f.tmp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = f.tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        for dest in [&full, &file, &link] {
            assert!(unpack(&bundle, dest).is_err(), "{dest:?}");
        }
        assert_eq!(fs::read(full.join("keep")).unwrap(), b"x");
        assert_eq!(fs::read(&file).unwrap(), b"x");
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
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

    /// A `meta` table with the given rows, for the classifier-injection tests.
    fn meta_of(rows: &[(&str, &str)]) -> OverlayMeta {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(ratarmount_compositing::overlay_meta::META_SCHEMA)
            .unwrap();
        OverlayMeta::set_many(&conn, rows).unwrap();
        OverlayMeta::from_connection(&conn).unwrap().unwrap()
    }

    /// Regression: `overlay unpack` of a bundle whose recorded base is a remote
    /// URL opened the base (a network request) before it noticed the error.
    /// The opener must not be reached for a recorded remote scheme.
    #[test]
    fn regression_unpack_recorded_remote_base_opens_no_network() {
        let dir = tempfile::tempdir().unwrap();
        for base in [
            "http://127.0.0.1:9/never.tar",
            "https://user:s3cr3t@example.invalid/x.tar?sig=1",
            "s3://bucket/key.tar",
            "ssh://host/path.tar",
        ] {
            let meta = meta_of(&[("format_version", "2"), ("base_url", base)]);
            let verified = verify_recorded_with(dir.path(), &meta, &|_| {
                panic!("the opener was called for a recorded remote base: {base}")
            })
            .unwrap();
            assert_eq!(verified, None, "{base}");
        }
        // Regression (R6-F6): an existing local `.torrent` path has no `://`,
        // but the recorded (classified) location is remote.
        let torrent = dir.path().join("base.torrent");
        fs::write(&torrent, b"d4:infod4:name1:xee").unwrap();
        let meta = meta_of(&[
            ("format_version", "2"),
            ("base_url", torrent.to_str().unwrap()),
            ("base_kind", "archive"),
            ("base_location", "remote:magnet-or-torrent"),
        ]);
        let verified = verify_recorded_with(dir.path(), &meta, &|_| {
            panic!("the opener was called for a recorded remote location")
        })
        .unwrap();
        assert_eq!(verified, None);
        // A local recorded base still reaches the classifier.
        let local = dir.path().join("base");
        fs::create_dir(&local).unwrap();
        let meta = meta_of(&[
            ("format_version", "2"),
            ("base_url", local.to_str().unwrap()),
        ]);
        let reached = std::cell::Cell::new(false);
        let _ = verify_recorded_with(dir.path(), &meta, &|_| {
            reached.set(true);
            Err("stop".into())
        });
        assert!(reached.get(), "a local recorded base must be classified");
    }

    /// Regression: (R11-S7, #151): the bundle's database member (the layer
    /// database's `VACUUM INTO` copy) and the `--include-index` member (the
    /// index's checked snapshot) were read through raw `File`s; a lock taken
    /// on those output inodes before the read was released by its close.
    /// Here a lock of this SQLite instance is taken on each snapshot output at
    /// the managed open (the consumption seam) and checked right after the
    /// managed close.
    #[cfg(unix)]
    #[test]
    fn regression_pack_snapshot_output_readers_keep_database_lock() {
        use ratarmount_index::managed_read::with_close_probes;
        let f = Fixture::new(true);
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
        let bundle = f.tmp.path().join("snap.tar.zst");
        let staging = |p: &Path| {
            let name = p.file_name().unwrap_or_default();
            name == HIDDEN_DB || name == "index.sqlite"
        };
        let (got, probes) = with_close_probes(staging, || {
            pack(
                &f.dir,
                &bundle,
                f.base.clone(),
                &PackOptions {
                    include_index: true,
                    base: Some(base.clone()),
                    ..Default::default()
                },
            )
        });
        got.unwrap();
        assert!(
            probes
                .iter()
                .any(|(p, _)| p.file_name().unwrap() == HIDDEN_DB),
            "database snapshot read through a managed reader: {probes:?}"
        );
        assert!(
            probes
                .iter()
                .any(|(p, _)| p.file_name().unwrap() == "index.sqlite"),
            "included index snapshot read through a managed reader: {probes:?}"
        );
        assert!(probes.iter().all(|(_, kept)| *kept), "{probes:?}");
    }
}
