//! Offline sealing: exact change hashes, preserved visible modes, and verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

use ratarmount_core::MountSource;
use rusqlite::{params, Connection, OpenFlags};
use rustix::fs::{self as host, AtFlags, Dir, Mode, OFlags};

use crate::overlay_changes::{self as changes, ChangeOptions};
use crate::{Immutability, OverlayError, OverlayMeta, ReadOnlyOverlayLayer, HIDDEN_DB};

pub(crate) const SENTINEL: &str = ".ratarmount-sealed";
const SEAL_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS seal_rows (path TEXT PRIMARY KEY, row_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS overlay_metadata (path TEXT PRIMARY KEY, mode INTEGER, atime REAL, mtime REAL);";

#[derive(Debug)]
pub struct SealOutcome {
    pub layer_digest: String,
    pub sealed_at: String,
    pub already_sealed: bool,
}

#[derive(Debug)]
pub struct VerifyReport {
    pub ok: bool,
    pub recorded: String,
    pub computed: String,
    pub sentinel_ok: bool,
    pub mismatched: Vec<String>,
}

fn overlay_error(error: OverlayError) -> io::Error {
    if error.is_locked() {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "overlay is in use by another ratarmount process",
        )
    } else {
        io::Error::other(error)
    }
}

fn sql_error(error: rusqlite::Error) -> io::Error {
    overlay_error(error.into())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn root(dir: &Path) -> io::Result<OwnedFd> {
    Ok(host::open(dir, directory_flags(), Mode::empty())?)
}

fn connection(dir: &Path, immutable: bool) -> io::Result<Connection> {
    let path = dir.join(HIDDEN_DB);
    if !fs::symlink_metadata(&path)?.is_file() {
        return Err(io::Error::other("overlay database must be a regular file"));
    }
    let conn = if immutable {
        Connection::open_with_flags(
            crate::overlay_layer::immutable_uri(&path.canonicalize()?),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
    } else {
        // NOFOLLOW rejects a symlink in any component, so resolve the directory.
        Connection::open_with_flags(
            dir.canonicalize()?.join(HIDDEN_DB),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
    }
    .map_err(sql_error)?;
    conn.busy_timeout(std::time::Duration::ZERO)
        .map_err(sql_error)?;
    Ok(conn)
}

// The directory FDs and no-follow opens keep chmod confined to the tree, even
// for dangling links or links to a directory outside it. No symlink is chmodded.
fn walk_modes(fd: &OwnedFd, parent: &str, modes: &mut BTreeMap<String, u32>) -> io::Result<()> {
    let mut hosts = BTreeMap::new();
    changes::walk_host_entries(fd, parent, &mut hosts)?;
    for (path, stat) in hosts {
        // mode_t is u16 on macOS, u32 on Linux.
        #[allow(clippy::unnecessary_cast)]
        modes.insert(path, stat.st_mode as u32);
    }
    Ok(())
}

fn chmod_tree(fd: &OwnedFd, writable: bool) -> io::Result<()> {
    let mode = crate::host_stat::fstat(fd)?.st_mode;
    let change = |mode: host::RawMode| {
        Mode::from_raw_mode(if writable {
            mode | 0o200
        } else {
            mode & !0o222
        })
    };
    if writable {
        host::fchmod(fd, change(mode))?;
    }
    for entry in Dir::read_from(fd)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let stat = crate::host_stat::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = stat.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            continue;
        }
        let flags = if kind == libc::S_IFDIR {
            directory_flags()
        } else {
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
        };
        let child = host::openat(fd, name, flags, Mode::empty())?;
        if kind == libc::S_IFDIR {
            chmod_tree(&child, writable)?;
        } else {
            host::fchmod(
                &child,
                change(
                    crate::host_stat::fstat_named(&child, name.to_string_lossy().as_ref())?.st_mode,
                ),
            )?;
        }
    }
    if !writable {
        host::fchmod(fd, change(mode))?;
    }
    Ok(())
}

fn options() -> ChangeOptions {
    ChangeOptions {
        include_git_dir: true,
        ..Default::default()
    }
}

fn digest_rows(
    dir: &Path,
    lower: Arc<dyn MountSource>,
    immutable: bool,
) -> io::Result<(String, BTreeMap<String, String>)> {
    let paths = changes::mentioned_paths_with_immutability(
        dir,
        if immutable {
            Immutability::Immutable
        } else {
            Immutability::Shared
        },
    )?;
    let top = Arc::new(ReadOnlyOverlayLayer::new(
        lower.clone(),
        dir,
        if immutable {
            Immutability::Immutable
        } else {
            Immutability::Shared
        },
    )?);
    let opts = options();
    let changes = changes::compare_paths(paths, top, Some(lower), &opts)?;
    let digest = changes::canonical_hash(&changes, &opts)?;
    let rows = changes
        .iter()
        .map(|c| {
            let path = String::from_utf8(c.path.clone()).map_err(io::Error::other)?;
            Ok((path, c.row_hash(&opts)?))
        })
        .collect::<io::Result<_>>()?;
    Ok((digest, rows))
}

/// Seal against the supplied composed lower view. Legacy overlays get minimal
/// metadata; callers must supply their base explicitly when none is recorded.
/// A writer reservation covers fsck, hashing, and the atomic metadata update.
/// Seal an overlay that is not sealed yet, over the base the opener served
/// (`composed` is that base under the `--lower` layers: what the rows hash
/// against). An overlay that recorded no kind (made by a released build)
/// gets the kind and place of this base recorded with the seal. An overlay
/// that is already sealed is [`reseal`]ed, never sealed again.
pub fn seal(
    dir: &Path,
    base: &crate::ClassifiedBase,
    composed: Arc<dyn MountSource>,
) -> io::Result<SealOutcome> {
    seal_impl(dir, Some(base), composed)
}

/// Finish an interrupted seal of an already sealed overlay, from the record
/// read off the overlay itself. It opens no base and writes no row: it
/// re-checks that the overlay is still sealed with the same digest, then
/// restores the sentinel and the read-only modes. It cannot start a seal.
pub fn reseal(record: &crate::SealedRecord) -> io::Result<SealOutcome> {
    let dir = record.dir();
    let root = root(dir)?;
    let meta = OverlayMeta::read(dir)
        .map_err(overlay_error)?
        .filter(OverlayMeta::layer_sealed)
        .ok_or_else(|| io::Error::other("overlay is no longer sealed"))?;
    check_hash_format(|key| meta.get(key))?;
    let layer_digest: String = meta
        .get("layer_digest")
        .ok_or_else(|| io::Error::other("sealed overlay has no layer_digest"))?
        .into();
    if layer_digest != record.layer_digest() {
        return Err(io::Error::other(
            "overlay was sealed again since it was read; retry",
        ));
    }
    finish_sealed(dir, &root, &layer_digest)?;
    Ok(SealOutcome {
        layer_digest,
        sealed_at: meta.get("sealed_at").unwrap_or_default().into(),
        already_sealed: true,
    })
}

pub(crate) fn seal_impl(
    dir: &Path,
    identity: Option<&crate::ClassifiedBase>,
    lower_view: Arc<dyn MountSource>,
) -> io::Result<SealOutcome> {
    let root = root(dir)?;
    let meta = OverlayMeta::read(dir).map_err(overlay_error)?;
    if let Some(meta) = meta.filter(OverlayMeta::layer_sealed) {
        check_hash_format(|key| meta.get(key))?;
        let layer_digest: String = meta
            .get("layer_digest")
            .ok_or_else(|| io::Error::other("sealed overlay has no layer_digest"))?
            .into();
        finish_sealed(dir, &root, &layer_digest)?;
        return Ok(SealOutcome {
            layer_digest,
            sealed_at: meta.get("sealed_at").unwrap().into(),
            already_sealed: true,
        });
    }
    let conn = connection(dir, false)?;
    // A sealed layer is never `pending`: hash the base first, outside the
    // write transaction (a cache hit is free).
    crate::resolve_pending_base_digest(&conn).map_err(overlay_error)?;
    // Readers can still take snapshots for canonical hashing. Competing writers,
    // including mounts in exclusive locking mode, cannot enter this interval.
    conn.execute_batch("BEGIN IMMEDIATE").map_err(sql_error)?;
    if OverlayMeta::from_connection(&conn)
        .map_err(overlay_error)?
        .is_some_and(|m| m.layer_sealed())
    {
        return Err(io::Error::other("overlay was sealed while starting; retry"));
    }
    let report = crate::overlay_fsck::check_connection(&conn, &root, false, false)?;
    if report.import_incomplete > 0 {
        return Err(io::Error::other(
            "overlay import did not finish (import_in_progress is set); \
             delete the directory and import again",
        ));
    }
    if !report.is_clean() {
        return Err(io::Error::other(format!(
            "overlay has {} inconsistencies; run overlay fsck --repair",
            report.errors()
        )));
    }
    let mut modes = BTreeMap::new();
    walk_modes(&root, "", &mut modes)?;
    let (layer_digest, rows) = digest_rows(dir, lower_view, false)?;
    if let Some(base) = identity {
        // The caller's gate already accepted (or forced) this base. A released
        // overlay recorded no kind: the seal writes it now (no digest). An
        // accepted move to another place (a local copy of a remote archive)
        // is recorded too, so the sealed layer names the base it was sealed on.
        let meta = OverlayMeta::from_connection(&conn).map_err(overlay_error)?;
        if !matches!(
            crate::overlay_gate::Recorded::from_meta(meta.as_ref()),
            crate::overlay_gate::Recorded::Nothing | crate::overlay_gate::Recorded::Unknown
        ) {
            crate::overlay_gate::write_accepted_identity(&conn, meta.as_ref(), base)
                .map_err(overlay_error)?;
        }
    }
    let sealed_at = chrono::Utc::now().to_rfc3339();
    conn.execute_batch(SEAL_SCHEMA).map_err(sql_error)?;
    for (path, mode) in &modes {
        conn.execute(
            "INSERT INTO overlay_metadata(path,mode) VALUES (?1,?2)
            ON CONFLICT(path) DO UPDATE SET mode=COALESCE(overlay_metadata.mode,excluded.mode)",
            params![format!("/{path}"), mode & 0o7777],
        )
        .map_err(sql_error)?;
    }
    conn.execute("DELETE FROM seal_rows", [])
        .map_err(sql_error)?;
    for (path, hash) in rows {
        conn.execute(
            "INSERT INTO seal_rows(path,row_hash) VALUES (?1,?2)",
            params![path, hash],
        )
        .map_err(sql_error)?;
    }
    if OverlayMeta::from_connection(&conn)
        .map_err(overlay_error)?
        .is_none_or(|m| m.format_version().ok().flatten().is_none())
    {
        OverlayMeta::set(&conn, "format_version", "1").map_err(overlay_error)?;
    }
    OverlayMeta::set_many(
        &conn,
        &[
            ("sealed_at", &sealed_at),
            ("layer_digest", &layer_digest),
            ("canonical_hash_format", changes::CANONICAL_HASH_FORMAT),
        ],
    )
    .map_err(overlay_error)?;
    conn.execute_batch("COMMIT").map_err(sql_error)?;
    // Publish without following an existing sentinel symlink. Keep the DB open
    // until its commit is durable, then close before changing host permissions.
    drop(conn);
    write_sentinel(dir, &layer_digest)?;
    chmod_tree(&root, false)?;
    Ok(SealOutcome {
        layer_digest,
        sealed_at,
        already_sealed: false,
    })
}

fn write_sentinel(dir: &Path, layer_digest: &str) -> io::Result<()> {
    let mut sentinel = tempfile::Builder::new()
        .prefix(".ratarmount.overlay.cow-seal-")
        .tempfile_in(dir)?;
    writeln!(sentinel, "{layer_digest}")?;
    sentinel.as_file().sync_all()?;
    sentinel.persist(dir.join(SENTINEL)).map_err(|e| e.error)?;
    Ok(())
}

/// Finish a seal that was interrupted after its metadata commit: write the
/// missing sentinel (a present one must match exactly and is never replaced)
/// and re-apply the read-only modes. Writes nothing to the sealed database.
fn finish_sealed(dir: &Path, root: &OwnedFd, layer_digest: &str) -> io::Result<()> {
    match host::openat(
        root,
        SENTINEL,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd)
            if crate::host_stat::fstat_named(&fd, dir.join(SENTINEL))?.st_mode & libc::S_IFMT
                == libc::S_IFREG =>
        {
            use std::io::Read;
            let mut bytes = Vec::new();
            fs::File::from(fd)
                .take((layer_digest.len() + 2) as u64)
                .read_to_end(&mut bytes)?;
            if bytes != layer_digest.as_bytes() && bytes != format!("{layer_digest}\n").as_bytes() {
                return Err(io::Error::other(
                    "sealed overlay sentinel does not match its layer digest; refusing to overwrite it",
                ));
            }
        }
        Ok(_) => {
            return Err(io::Error::other(
                "sealed overlay sentinel is not a regular file; refusing to replace it",
            ))
        }
        Err(rustix::io::Errno::NOENT) => write_sentinel(dir, layer_digest)?,
        Err(e) => {
            return Err(io::Error::other(format!(
                "sealed overlay sentinel is not a regular file ({e}); refusing to replace it"
            )))
        }
    }
    chmod_tree(root, false)
}

/// Remove seal metadata and restore owner write permission. Mode overrides stay.
pub fn unseal(dir: &Path) -> io::Result<()> {
    let root = root(dir)?;
    // Probe before touching permissions, so a mounted overlay is never changed.
    OverlayMeta::read(dir).map_err(overlay_error)?;
    chmod_tree(&root, true)?;
    let conn = connection(dir, false)?;
    conn.execute_batch("BEGIN EXCLUSIVE").map_err(sql_error)?;
    conn.execute_batch(crate::overlay_meta::META_SCHEMA)
        .map_err(sql_error)?;
    conn.execute_batch(SEAL_SCHEMA).map_err(sql_error)?;
    conn.execute_batch(
        "DELETE FROM meta WHERE key IN ('sealed_at','layer_digest'); DELETE FROM seal_rows;",
    )
    .map_err(sql_error)?;
    OverlayMeta::set(&conn, "unsealed_at", &chrono::Utc::now().to_rfc3339())
        .map_err(overlay_error)?;
    match host::unlinkat(&root, SENTINEL, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(e.into()),
    }
    conn.execute_batch("COMMIT").map_err(sql_error)?;
    Ok(())
}

/// Verify without writing or changing permissions, including per-path differences
/// and the sentinel. A missing seal is an error; mismatches are a successful report.
/// Refuse a layer sealed under another canonical hash definition: its digest
/// cannot be recomputed by this build, so a mismatch would be a false alarm
/// and a match would be luck. `get` reads the recorded metadata.
pub fn check_hash_format<'a>(get: impl Fn(&str) -> Option<&'a str>) -> io::Result<()> {
    let recorded = get("canonical_hash_format").unwrap_or("1");
    if recorded == changes::CANONICAL_HASH_FORMAT {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "layer was sealed with canonical hash format {recorded}; this ratarmount computes format {} \
             (symlink rows carry no mode). Unseal with --i-know and seal again to re-record the digest",
            changes::CANONICAL_HASH_FORMAT
        ),
    ))
}

/// Verify a layer against the view it sits on. Read-only: it writes nothing
/// and cannot authorize a seal or a create, so it needs no classified base.
pub fn verify(dir: &Path, lower_view: Arc<dyn MountSource>) -> io::Result<VerifyReport> {
    let root = root(dir)?;
    let conn = connection(dir, true)?;
    let meta = OverlayMeta::from_connection(&conn)
        .map_err(overlay_error)?
        .filter(OverlayMeta::layer_sealed)
        .ok_or_else(|| io::Error::other("overlay is not sealed"))?;
    check_hash_format(|key| meta.get(key))?;
    let recorded = meta
        .get("layer_digest")
        .ok_or_else(|| io::Error::other("sealed overlay has no layer_digest"))?
        .to_owned();
    let rows = conn
        .prepare("SELECT path,row_hash FROM seal_rows")
        .map_err(sql_error)?
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(sql_error)?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()
        .map_err(sql_error)?;
    let (computed, current) = digest_rows(dir, lower_view, true)?;
    let paths: BTreeSet<_> = rows.keys().chain(current.keys()).collect();
    let mismatched: Vec<_> = paths
        .into_iter()
        .filter(|p| rows.get(*p) != current.get(*p))
        .cloned()
        .collect();
    let sentinel_ok = match host::openat(
        &root,
        SENTINEL,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd)
            if crate::host_stat::fstat_named(&fd, dir.join(SENTINEL))?.st_mode & libc::S_IFMT
                == libc::S_IFREG =>
        {
            use std::io::Read;
            let mut bytes = Vec::new();
            fs::File::from(fd)
                .take((recorded.len() + 2) as u64)
                .read_to_end(&mut bytes)?;
            bytes == recorded.as_bytes() || bytes == format!("{recorded}\n").as_bytes()
        }
        Ok(_) => false,
        Err(e) if e == rustix::io::Errno::NOENT || e == rustix::io::Errno::LOOP => false,
        Err(e) => return Err(e.into()),
    };
    Ok(VerifyReport {
        ok: recorded == computed && sentinel_ok && mismatched.is_empty(),
        recorded,
        computed,
        sentinel_ok,
        mismatched,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FolderMountSource, OverlayMetadata, WriteOverlay};

    /// Seal without a classified base: the in-crate fixtures open overlays
    /// with `new_for_tests`, which record no base.
    fn seal(dir: &Path, lower_view: Arc<dyn MountSource>) -> io::Result<SealOutcome> {
        seal_impl(dir, None, lower_view)
    }

    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct Fixture {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
        base: Arc<dyn MountSource>,
    }
    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().join("base");
            fs::create_dir(&base).unwrap();
            fs::write(base.join("inherited"), b"base bytes").unwrap();
            let base: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base).unwrap());
            let dir = tmp.path().join("overlay");
            let overlay = WriteOverlay::new_for_tests(base.clone(), &dir).unwrap();
            overlay.mkdir("/sub", 0o775).unwrap();
            for path in ["/sub/file", "/plain"] {
                let fd = overlay.create_file(path, 0o664).unwrap();
                overlay.close_overlay_fd(fd);
                fs::write(dir.join(path.trim_start_matches('/')), b"payload").unwrap();
            }
            overlay
                .set_metadata(
                    "/sub/file",
                    &OverlayMetadata {
                        mode: Some(0o751),
                        ..Default::default()
                    },
                )
                .unwrap();
            overlay
                .set_metadata(
                    "/inherited",
                    &OverlayMetadata {
                        mode: Some(0o600),
                        ..Default::default()
                    },
                )
                .unwrap();
            overlay.create_symlink("/link", "../../outside").unwrap();
            drop(overlay);
            Self {
                _tmp: tmp,
                dir,
                base,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Ok(root) = root(&self.dir) {
                let _ = chmod_tree(&root, true);
            }
        }
    }

    fn visible(source: &dyn MountSource) -> Vec<(String, u32)> {
        let mut result = Vec::new();
        for parent in ["/", "/sub"] {
            for entry in source.list_dirents(parent).unwrap() {
                let path = format!("{}/{}", parent.trim_end_matches('/'), entry.name);
                assert_eq!(source.lookup(&path, 0).unwrap().mode, entry.mode, "{path}");
                result.push((path, entry.mode));
            }
            result.push((parent.into(), source.lookup(parent, 0).unwrap().mode));
        }
        result.sort();
        result
    }

    /// Regression: seal refused COW payloads, lost their modes, or failed to detect tampering.
    #[test]
    fn regression_cow_seal_pins_modes_and_detects_tampering() {
        let f = Fixture::new();
        let base_dir = f._tmp.path().join("base/sub");
        fs::create_dir(&base_dir).unwrap();
        fs::write(base_dir.join("cow"), b"base bytes").unwrap();
        fs::set_permissions(base_dir.join("cow"), fs::Permissions::from_mode(0o751)).unwrap();
        let writer = WriteOverlay::new_for_tests(f.base.clone(), &f.dir).unwrap();
        changes::cow_write(&writer, "/sub/cow", b"changed\n");
        let before = visible(&writer);
        drop(writer);
        assert_eq!(
            connection(&f.dir, false)
                .unwrap()
                .query_row("SELECT count(*) FROM files WHERE name='cow'", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(crate::overlay_fsck::fsck(&f.dir, false).unwrap().is_clean());
        let expected = changes::canonical_hash(
            &changes::change_set(&f.dir, f.base.clone(), &options()).unwrap(),
            &options(),
        )
        .unwrap();
        // Staging payloads must not acquire pinned modes or enter the seal hash.
        fs::write(f.dir.join("sub/.ratarmount-spool-test"), b"partial").unwrap();
        let sealed = seal(&f.dir, f.base.clone()).unwrap();
        assert_eq!(sealed.layer_digest, expected);
        let layer =
            ReadOnlyOverlayLayer::new(f.base.clone(), &f.dir, Immutability::Immutable).unwrap();
        assert_eq!(layer.lookup("/sub/cow", 0).unwrap().mode, 0o100751);
        // The staging name is outside the public change set; omit it from this listing comparison.
        let mut after = visible(&layer);
        after.retain(|(path, _)| !path.ends_with(".ratarmount-spool-test"));
        assert_eq!(after, before);
        let conn = connection(&f.dir, true).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT mode FROM overlay_metadata WHERE path='/sub/cow'",
                [],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
            0o751
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM overlay_metadata WHERE path LIKE '%spool%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM seal_rows WHERE path='sub/cow'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        drop(conn);
        assert!(verify(&f.dir, f.base.clone()).unwrap().ok);
        fs::set_permissions(f.dir.join("sub/cow"), fs::Permissions::from_mode(0o751)).unwrap();
        fs::write(f.dir.join("sub/cow"), b"tampered\n").unwrap();
        let report = verify(&f.dir, f.base.clone()).unwrap();
        assert!(!report.ok);
        assert_eq!(report.mismatched, ["sub/cow"]);
    }

    fn writable_entries(dir: &Path) -> Vec<String> {
        let mut modes = BTreeMap::new();
        walk_modes(&root(dir).unwrap(), "", &mut modes).unwrap();
        modes
            .into_iter()
            .filter(|(_, m)| m & ratarmount_core::S_IFMT != ratarmount_core::S_IFLNK)
            .filter(|(_, m)| m & 0o222 != 0)
            .map(|(p, _)| p)
            .collect()
    }

    /// Regression: a seal killed after the DB commit left no sentinel, and a re-run was a silent no-op.
    #[test]
    fn regression_seal_rerun_writes_missing_sentinel() {
        let f = Fixture::new();
        seal(&f.dir, f.base.clone()).unwrap();
        chmod_tree(&root(&f.dir).unwrap(), true).unwrap();
        fs::remove_file(f.dir.join(SENTINEL)).unwrap();
        assert!(!verify(&f.dir, f.base.clone()).unwrap().ok);
        assert!(seal(&f.dir, f.base.clone()).unwrap().already_sealed);
        assert!(f.dir.join(SENTINEL).exists());
        assert!(verify(&f.dir, f.base.clone()).unwrap().ok);
    }

    /// Regression: a seal killed during chmod left writable entries that `verify` accepted.
    #[test]
    fn regression_seal_rerun_reapplies_read_only_modes() {
        let f = Fixture::new();
        seal(&f.dir, f.base.clone()).unwrap();
        let sub = root(&f.dir).unwrap();
        chmod_tree(&sub, true).unwrap();
        // Leave only part of the tree sealed, like a kill mid-walk.
        let sentinel = f.dir.join(SENTINEL);
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(!writable_entries(&f.dir).is_empty());
        assert!(seal(&f.dir, f.base.clone()).unwrap().already_sealed);
        assert_eq!(writable_entries(&f.dir), Vec::<String>::new());
        assert_eq!(
            fs::metadata(&f.dir).unwrap().permissions().mode() & 0o222,
            0
        );
        assert!(verify(&f.dir, f.base.clone()).unwrap().ok);
    }

    /// Regression: a re-run must never overwrite a sentinel that names another digest.
    #[test]
    fn regression_seal_rerun_refuses_wrong_sentinel() {
        let f = Fixture::new();
        seal(&f.dir, f.base.clone()).unwrap();
        let sentinel = f.dir.join(SENTINEL);
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&sentinel, b"wrong digest\n").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(seal(&f.dir, f.base.clone()).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"wrong digest\n");
    }

    /// Regression: chmod -w changed lookup and readdir modes, and leaked the sentinel.
    #[test]
    fn regression_seal_preserves_lookup_and_listing_modes() {
        let f = Fixture::new();
        let source =
            ReadOnlyOverlayLayer::new(f.base.clone(), &f.dir, Immutability::Shared).unwrap();
        let before = visible(&source);
        let writer = WriteOverlay::new_for_tests(f.base.clone(), &f.dir).unwrap();
        assert_eq!(visible(&writer), before);
        drop(writer);
        let digest = changes::canonical_hash(
            &changes::change_set(&f.dir, f.base.clone(), &options()).unwrap(),
            &options(),
        )
        .unwrap();
        let outcome = seal(&f.dir, f.base.clone()).unwrap();
        assert_eq!(outcome.layer_digest, digest);
        assert!(!outcome.already_sealed);
        let source = Arc::new(
            ReadOnlyOverlayLayer::new(f.base.clone(), &f.dir, Immutability::Immutable).unwrap(),
        );
        assert_eq!(visible(source.as_ref()), before);
        assert!(source.lookup("/.ratarmount-sealed", 0).is_none());
        // A fresh writable top over the sealed layer must retain the same modes.
        let writer = WriteOverlay::new_for_tests(source, f._tmp.path().join("top")).unwrap();
        assert_eq!(visible(&writer), before);
        drop(writer);
        let mut modes = BTreeMap::new();
        walk_modes(&root(&f.dir).unwrap(), "", &mut modes).unwrap();
        assert_eq!(
            fs::metadata(&f.dir).unwrap().permissions().mode() & 0o222,
            0
        );
        for (path, mode) in modes {
            if mode & ratarmount_core::S_IFMT != ratarmount_core::S_IFLNK {
                assert_eq!(mode & 0o222, 0, "{path}");
            }
        }
        let db = fs::read(f.dir.join(HIDDEN_DB)).unwrap();
        assert!(verify(&f.dir, f.base.clone()).unwrap().ok);
        assert!(seal(&f.dir, f.base.clone()).unwrap().already_sealed);
        assert_eq!(fs::read(f.dir.join(HIDDEN_DB)).unwrap(), db);
        unseal(&f.dir).unwrap();
        let writer = WriteOverlay::new_for_tests(f.base.clone(), &f.dir).unwrap();
        assert_eq!(visible(&writer), before);
        drop(writer);
        let meta = OverlayMeta::read(&f.dir).unwrap().unwrap();
        assert!(!meta.layer_sealed());
        assert!(meta.get("layer_digest").is_none());
        assert!(meta.get("unsealed_at").is_some());
        assert!(verify(&f.dir, f.base.clone()).is_err());
        assert_eq!(
            connection(&f.dir, false)
                .unwrap()
                .query_row("SELECT count(*) FROM seal_rows", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    /// Regression: altered bytes, unindexed additions, removed rows and sentinel tampering went unnoticed.
    #[test]
    fn regression_seal_verify_names_modified_added_removed_paths() {
        let f = Fixture::new();
        seal(&f.dir, f.base.clone()).unwrap();
        chmod_tree(&root(&f.dir).unwrap(), true).unwrap();
        fs::write(f.dir.join("plain"), b"tampered").unwrap();
        fs::write(f.dir.join("added"), b"new").unwrap();
        fs::remove_file(f.dir.join("sub/file")).unwrap();
        chmod_tree(&root(&f.dir).unwrap(), false).unwrap();
        let report = verify(&f.dir, f.base.clone()).unwrap();
        assert!(!report.ok);
        assert!(report.sentinel_ok);
        assert_eq!(report.mismatched, ["added", "plain", "sub/file"]);
        unseal(&f.dir).unwrap();
        crate::overlay_fsck::fsck(&f.dir, true).unwrap();
        seal(&f.dir, f.base.clone()).unwrap();
        let sentinel = f.dir.join(SENTINEL);
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&sentinel, b"wrong digest").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o400)).unwrap();
        let report = verify(&f.dir, f.base.clone()).unwrap();
        assert!(!report.ok && !report.sentinel_ok);
        assert_eq!(report.recorded, report.computed);
        assert!(report.mismatched.is_empty());
    }

    /// Regression: sealing an active writer or inconsistent overlay must fail before chmod.
    #[test]
    fn regression_seal_refuses_mounted_and_inconsistent_overlay() {
        let f = Fixture::new();
        let writer = WriteOverlay::new_for_tests(f.base.clone(), &f.dir).unwrap();
        for error in [
            seal(&f.dir, f.base.clone()).unwrap_err(),
            unseal(&f.dir).unwrap_err(),
        ] {
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(error
                .to_string()
                .contains("in use by another ratarmount process"));
        }
        drop(writer);
        fs::remove_file(f.dir.join("plain")).unwrap();
        assert!(seal(&f.dir, f.base.clone())
            .unwrap_err()
            .to_string()
            .contains("overlay fsck --repair"));
        assert!(!OverlayMeta::read(&f.dir).unwrap().unwrap().layer_sealed());
        assert_ne!(
            fs::metadata(&f.dir).unwrap().permissions().mode() & 0o200,
            0
        );
        crate::overlay_fsck::fsck(&f.dir, true).unwrap();
        seal(&f.dir, f.base.clone()).unwrap();
        assert!(WriteOverlay::new_for_tests(f.base.clone(), &f.dir)
            .err()
            .unwrap()
            .to_string()
            .contains("sealed"));
    }

    /// Regression: seal/unseal chmod must never follow host links, including the sentinel.
    #[test]
    fn regression_seal_symlinks_never_chmod_external_targets() {
        let f = Fixture::new();
        let outside = f._tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"safe").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o750)).unwrap();
        let writer = WriteOverlay::new_for_tests(f.base.clone(), &f.dir).unwrap();
        writer
            .create_symlink("/external", outside.to_str().unwrap())
            .unwrap();
        drop(writer);
        symlink(outside.join("keep"), f.dir.join(SENTINEL)).unwrap();
        seal(&f.dir, f.base.clone()).unwrap();
        assert!(verify(&f.dir, f.base.clone()).unwrap().ok);
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"safe");
        unseal(&f.dir).unwrap();
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }

    /// Regression: format 2 dropped symlink modes from the canonical hash; a
    /// layer sealed under format 1 must be refused by name, not reported as a
    /// content mismatch (or pass by luck), until it is resealed.
    #[test]
    fn regression_seal_records_and_checks_canonical_hash_format() {
        let f = Fixture::new();
        seal(&f.dir, f.base.clone()).unwrap();
        let format = |dir: &Path| {
            OverlayMeta::read(dir)
                .unwrap()
                .unwrap()
                .get("canonical_hash_format")
                .map(str::to_owned)
        };
        assert_eq!(
            format(&f.dir).as_deref(),
            Some(changes::CANONICAL_HASH_FORMAT)
        );
        for old in [Some("1"), None] {
            chmod_tree(&root(&f.dir).unwrap(), true).unwrap();
            let conn = connection(&f.dir, false).unwrap();
            match old {
                Some(v) => OverlayMeta::set(&conn, "canonical_hash_format", v).unwrap(),
                None => {
                    conn.execute("DELETE FROM meta WHERE key='canonical_hash_format'", [])
                        .unwrap();
                }
            }
            drop(conn);
            chmod_tree(&root(&f.dir).unwrap(), false).unwrap();
            for error in [
                verify(&f.dir, f.base.clone()).unwrap_err(),
                seal(&f.dir, f.base.clone()).unwrap_err(),
            ] {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(
                    error.to_string().contains("canonical hash format 1"),
                    "{error}"
                );
            }
        }
        unseal(&f.dir).unwrap();
        seal(&f.dir, f.base.clone()).unwrap();
        assert_eq!(
            format(&f.dir).as_deref(),
            Some(changes::CANONICAL_HASH_FORMAT)
        );
        assert!(verify(&f.dir, f.base.clone()).unwrap().ok);
    }

    /// Regression: legacy databases and .git changes must be sealable without losing exact bytes.
    #[test]
    fn regression_seal_legacy_metadata_and_git_content() {
        let f = Fixture::new();
        let writer = WriteOverlay::new_for_tests(f.base.clone(), &f.dir).unwrap();
        writer.mkdir("/.git", 0o755).unwrap();
        let fd = writer.create_file("/.git/config", 0o644).unwrap();
        writer.close_overlay_fd(fd);
        drop(writer);
        connection(&f.dir, false)
            .unwrap()
            .execute_batch("DROP TABLE meta")
            .unwrap();
        seal(&f.dir, f.base.clone()).unwrap();
        assert!(OverlayMeta::read(&f.dir).unwrap().unwrap().legacy());
        assert!(verify(&f.dir, f.base.clone()).unwrap().ok);
        let path = f.dir.join(".git/config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"changed").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            verify(&f.dir, f.base.clone()).unwrap().mismatched,
            [".git/config"]
        );
    }
}
