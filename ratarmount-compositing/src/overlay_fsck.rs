//! Offline consistency checking and confined repair of overlay bookkeeping.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rusqlite::{params, Connection, OpenFlags};
use rustix::fs::{self, AtFlags, Mode, OFlags, Stat};
use serde::Serialize;

use crate::overlay_changes::{internal_path, walk_host_entries};
use crate::{OverlayError, OverlayMeta, HIDDEN_DB};

/// Counts describe the initial check; `repaired` counts resolved findings, not
/// SQL statements. Unrowed host entries are normal COW content, not errors.
#[derive(Debug, Default, Serialize)]
pub struct FsckReport {
    pub missing_content: usize,
    /// Compatibility field; always zero. See `unrowed` for host-only entries.
    pub orphan_content: usize,
    /// Host entries without files rows, including implicit COW parent directories.
    pub unrowed: usize,
    pub tombstone_content: usize,
    pub type_mismatch: usize,
    pub invalid_path: usize,
    pub missing_parent: usize,
    /// 1 when an `overlay import` was killed before it finished (`import_in_progress`
    /// meta row). Never repaired: fsck cannot know the import is complete.
    pub import_incomplete: usize,
    pub repaired: usize,
}

impl FsckReport {
    pub fn errors(&self) -> usize {
        self.missing_content
            + self.tombstone_content
            + self.type_mismatch
            + self.invalid_path
            + self.missing_parent
            + self.import_incomplete
    }

    pub fn is_clean(&self) -> bool {
        self.errors() == self.repaired
    }

    pub fn result(&self) -> String {
        if !self.is_clean() {
            format!("errors:{}", self.errors() - self.repaired)
        } else if self.repaired > 0 {
            format!("repaired:{}", self.repaired)
        } else {
            "ok".into()
        }
    }
}

struct Row {
    parent: String,
    name: String,
    mode: Option<u32>,
    deleted: bool,
    metadata_only: bool,
}

// `files.path` is a mount-root parent: "" at root, "/a/b" below it.
// The leading slash is part of the existing schema, never a host absolute path.
fn relative_path(parent: &str, name: &str, metadata_only: bool) -> Option<String> {
    fn component(s: &str) -> bool {
        !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\0'])
    }
    if parent.is_empty() && name.is_empty() && metadata_only {
        return Some(String::new()); // chmod/utime on the overlay root
    }
    if !component(name) {
        return None;
    }
    let path = if parent.is_empty() {
        name.to_owned()
    } else {
        let parent = parent.strip_prefix('/')?;
        if !parent.split('/').all(component) {
            return None;
        }
        format!("{parent}/{name}")
    };
    (!internal_path(&path)).then_some(path)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn file_type(stat: &Stat) -> u32 {
    // mode_t is u16 on macOS and u32 on Linux.
    #[allow(clippy::unnecessary_cast)]
    let mode = stat.st_mode as u32;
    mode & 0o170000
}

fn open_directory(root: &OwnedFd, path: &str) -> io::Result<OwnedFd> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0146-M01","item":"ratarmount_compositing::overlay_fsck::open_directory","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"O_DIRECTORY descriptor of an overlay directory for the no-follow fsck walk; reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut fd = fs::openat(root, ".", directory_flags(), Mode::empty())?;
    if !path.is_empty() {
        for part in path.split('/') {
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0147-M01","item":"ratarmount_compositing::overlay_fsck::open_directory","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"O_DIRECTORY descriptor of an overlay directory for the no-follow fsck walk; reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )]
            let __inventory_assigned = fs::openat(&fd, part, directory_flags(), Mode::empty())?;
            fd = __inventory_assigned;
        }
    }
    Ok(fd)
}

fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn store_host(conn: &Connection, path: &str, stat: &Stat) -> io::Result<()> {
    let (parent, name) = split(path);
    let parent = if parent.is_empty() {
        String::new()
    } else {
        format!("/{parent}")
    };
    conn.execute(
        "INSERT INTO files(path,name,mode,mtime,uid,gid,deleted) VALUES (?1,?2,?3,?4,?5,?6,0)
         ON CONFLICT(path,name) DO UPDATE SET mode=excluded.mode,mtime=excluded.mtime,
         uid=excluded.uid,gid=excluded.gid,deleted=0",
        params![
            parent,
            name,
            stat.st_mode,
            stat.st_mtime as f64 + stat.st_mtime_nsec as f64 / 1e9,
            stat.st_uid,
            stat.st_gid
        ],
    )
    .map_err(io::Error::other)?;
    Ok(())
}

fn overlay_error(error: OverlayError) -> io::Error {
    if error.is_locked() {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "overlay is in use (database locked)",
        )
    } else {
        io::Error::other(error)
    }
}

/// Check with one directory walk and one `files` scan. Repair holds a SQLite
/// exclusive transaction throughout; host removals use no-follow parent FDs.
/// Sealed overlays are checked read-only, without updating their metadata.
/// A missing/unreadable database is an error and is never created.
pub fn fsck(dir: &Path, repair: bool) -> io::Result<FsckReport> {
    let meta = OverlayMeta::read(dir).map_err(overlay_error)?;
    let sealed = meta.as_ref().is_some_and(OverlayMeta::layer_sealed);
    if repair && sealed {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "overlay is sealed; fsck --repair is refused",
        ));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0148-M01","item":"ratarmount_compositing::overlay_fsck::fsck","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"O_DIRECTORY descriptor of the overlay folder (walk root); reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let root = fs::open(dir, directory_flags(), Mode::empty())?;
    let flags = if sealed {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    // NOFOLLOW makes SQLite reject a symlink in any path component (macOS
    // temp dirs live under /var -> /private/var); the shared open resolves the
    // directory, so only the DB file must not be one.
    let conn = crate::open_overlay_db(
        &dir.join(HIDDEN_DB),
        flags | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        crate::DbName::Path,
    )?;
    conn.busy_timeout(std::time::Duration::ZERO)
        .map_err(io::Error::other)?;
    conn.execute_batch(if sealed { "BEGIN" } else { "BEGIN EXCLUSIVE" })
        .map_err(|e| overlay_error(e.into()))?;
    // Recheck after acquiring the transaction: a seal may have won the race.
    if !sealed
        && OverlayMeta::from_opened(&conn)
            .map_err(overlay_error)?
            .as_ref()
            .is_some_and(OverlayMeta::layer_sealed)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "overlay was sealed while fsck started; retry read-only",
        ));
    }
    let report = check_connection(&conn, &root, repair, sealed)?;
    conn.execute_batch("COMMIT").map_err(io::Error::other)?;
    Ok(report)
}

/// The `import_in_progress` meta row, if the `meta` table exists and has one.
fn import_marker(conn: &Connection) -> io::Result<Option<String>> {
    let has_meta: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
            [],
            |r| r.get(0),
        )
        .map_err(io::Error::other)?;
    if !has_meta {
        return Ok(None);
    }
    match conn.query_row(
        "SELECT value FROM meta WHERE key='import_in_progress'",
        [],
        |r| r.get(0),
    ) {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(io::Error::other(e)),
    }
}

// Seal holds its writer reservation across the check, hash and metadata update.
pub(crate) fn check_connection(
    conn: &Connection,
    root: &OwnedFd,
    repair: bool,
    sealed: bool,
) -> io::Result<FsckReport> {
    let has_metadata: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='overlay_metadata')", [], |r| r.get(0),
    ).map_err(io::Error::other)?;
    // chmod/utime rows can intentionally refer to inherited content. Preserve
    // them without requiring the base (including a metadata row for '/').
    let sql = if has_metadata {
        "SELECT f.path,f.name,f.mode,f.deleted,EXISTS(SELECT 1 FROM overlay_metadata m WHERE m.path=f.path || '/' || f.name) FROM files f"
    } else {
        "SELECT path,name,mode,deleted,0 FROM files"
    };
    let rows = conn
        .prepare(sql)
        .map_err(io::Error::other)?
        .query_map([], |r| {
            Ok(Row {
                parent: r.get(0)?,
                name: r.get(1)?,
                mode: r.get(2)?,
                deleted: r.get::<_, Option<bool>>(3)?.unwrap_or(false),
                metadata_only: r.get(4)?,
            })
        })
        .map_err(io::Error::other)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(io::Error::other)?;
    let mut hosts = BTreeMap::new();
    walk_host_entries(root, "", &mut hosts)?;
    let mut report = FsckReport {
        import_incomplete: usize::from(import_marker(conn)?.is_some()),
        ..Default::default()
    };
    let mut valid = BTreeMap::new();
    for row in &rows {
        if let Some(path) = relative_path(&row.parent, &row.name, row.metadata_only) {
            valid.insert(path, row);
        } else {
            report.invalid_path += 1;
            if repair {
                conn.execute(
                    "DELETE FROM files WHERE path=?1 AND name=?2",
                    params![row.parent, row.name],
                )
                .map_err(io::Error::other)?;
            }
        }
    }
    let tombstones: HashSet<&str> = valid
        .iter()
        .filter(|(_, row)| row.deleted)
        .map(|(p, _)| p.as_str())
        .collect();
    let hidden = |path: &str| {
        let mut p = path;
        loop {
            if tombstones.contains(p) {
                return true;
            }
            let Some((parent, _)) = p.rsplit_once('/') else {
                return false;
            };
            p = parent;
        }
    };
    for (path, row) in &valid {
        if path.is_empty() {
            continue;
        }
        let host = hosts.get(path);
        if row.deleted {
            if host.is_some() {
                report.tombstone_content += 1;
            }
        } else if host.is_none() || hidden(path) {
            if !row.metadata_only || hidden(path) {
                report.missing_content += 1;
                if repair {
                    conn.execute(
                        "DELETE FROM files WHERE path=?1 AND name=?2",
                        params![row.parent, row.name],
                    )
                    .map_err(io::Error::other)?;
                }
            }
        } else if row.mode.map(|m| m & 0o170000) != host.map(file_type) {
            report.type_mismatch += 1;
            if repair {
                store_host(conn, path, host.expect("host checked"))?;
            }
        }
        // Only present rows need a host parent directory. A tombstone hides a
        // base path and never needs one: deleting `a/b/c` inside an untouched
        // base directory creates no host `a/b`, and `rm -rf d; echo x > d`
        // leaves `d/...` tombstones under what is now a file or symlink.
        let parent = split(path).0;
        if !row.deleted
            && !parent.is_empty()
            && !hidden(parent)
            && !row.metadata_only
            && !hosts
                .get(parent)
                .is_some_and(|s| s.st_mode & libc::S_IFMT == libc::S_IFDIR)
        {
            report.missing_parent += 1;
        }
    }
    report.unrowed = hosts
        .keys()
        .filter(|path| !valid.contains_key(*path) && !hidden(path))
        .count();
    if repair {
        // Reverse lexical order puts descendants before their parents. Never
        // join a DB path to a host path or follow a symlink during removal.
        for (path, stat) in hosts.iter().rev().filter(|(path, _)| hidden(path)) {
            let (parent, name) = split(path);
            let fd = open_directory(root, parent)?;
            let flags = if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            };
            fs::unlinkat(&fd, name, flags)?;
        }
        // The import marker is never repaired.
        report.repaired = report.errors() - report.import_incomplete;
    }
    if !sealed {
        conn.execute_batch(crate::overlay_meta::META_SCHEMA)
            .map_err(io::Error::other)?;
        OverlayMeta::set_many(
            conn,
            &[
                ("fsck_at", &chrono::Utc::now().to_rfc3339()),
                ("fsck_result", &report.result()),
            ],
        )
        .map_err(overlay_error)?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FolderMountSource, OverlayMetadata, WriteOverlay};
    use ratarmount_core::MountSource;
    use std::fs as host;
    use std::sync::Arc;

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        Arc<FolderMountSource>,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        host::create_dir(&base).unwrap();
        let source = Arc::new(FolderMountSource::new(&base).unwrap());
        let overlay = tmp.path().join("overlay");
        drop(WriteOverlay::new_for_tests(source.clone(), &overlay).unwrap());
        (tmp, overlay, source)
    }

    fn db(dir: &Path) -> Connection {
        Connection::open(dir.join(HIDDEN_DB)).unwrap()
    }

    /// Regression: normal COW content was an orphan error and repair invented files rows.
    #[test]
    fn regression_cow_fsck_clean_and_repair_preserves_unrowed_content() {
        let (tmp, dir, source) = fixture();
        host::create_dir(tmp.path().join("base/lib")).unwrap();
        host::write(tmp.path().join("base/lib/f"), b"base").unwrap();
        let ov = WriteOverlay::new_for_tests(source.clone(), &dir).unwrap();
        crate::overlay_changes::cow_write(&ov, "/lib/f", b"changed");
        drop(ov);
        for repair in [false, true] {
            let report = fsck(&dir, repair).unwrap();
            assert!(report.is_clean());
            assert_eq!(report.result(), "ok");
            assert_eq!(
                (report.unrowed, report.orphan_content, report.repaired),
                (2, 0, 0)
            );
            assert_eq!(
                db(&dir)
                    .query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        host::write(dir.join("lib/.ratarmount.overlay.cow-killed"), b"partial").unwrap();
        assert!(fsck(&dir, true).unwrap().is_clean());
        drop(WriteOverlay::new_for_tests(source, &dir).unwrap());
        assert!(!dir.join("lib/.ratarmount.overlay.cow-killed").exists());
        assert_eq!(host::read(dir.join("lib/f")).unwrap(), b"changed");
    }

    /// Regression: killed writers leave stale rows and tombstone content; host-only COW is valid.
    #[test]
    fn regression_fsck_killed_writer_reports_and_repairs_each_category() {
        let (tmp, dir, source) = fixture();
        host::write(tmp.path().join("base/cow"), b"base").unwrap();
        let ov = WriteOverlay::new_for_tests(source, &dir).unwrap();
        crate::overlay_changes::cow_write(&ov, "/cow", b"changed");
        drop(ov);
        let conn = db(&dir);
        conn.execute_batch(
            "INSERT INTO files(path,name,mode,deleted) VALUES
            ('','missing',33188,0), ('','deleted',NULL,1),
            ('','wrong-type',16877,0), ('/..','escape',33188,0);",
        )
        .unwrap();
        drop(conn);
        // A crash during copy-up can leave staging files, which remain internal.
        host::write(dir.join(".ratarmount.overlay.cow-killed"), b"partial").unwrap();
        host::write(dir.join("deleted"), b"must go").unwrap();
        host::write(dir.join("wrong-type"), b"file, not directory").unwrap();
        let report = fsck(&dir, false).unwrap();
        assert_eq!(
            (
                report.missing_content,
                report.orphan_content,
                report.tombstone_content,
                report.type_mismatch,
                report.invalid_path,
                report.missing_parent
            ),
            (1, 0, 1, 1, 1, 0)
        );
        assert_eq!(report.result(), "errors:4");
        assert_eq!(
            OverlayMeta::read(&dir).unwrap().unwrap().get("fsck_result"),
            Some("errors:4")
        );
        let report = fsck(&dir, true).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.result(), "repaired:4");
        assert!(!dir.join("deleted").exists());
        assert_eq!(report.unrowed, 1);
        assert_eq!(host::read(dir.join("cow")).unwrap(), b"changed");
        assert_eq!(
            db(&dir)
                .query_row("SELECT count(*) FROM files WHERE name='cow'", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(fsck(&dir, false).unwrap().errors(), 0);
    }

    /// Regression: repair must refuse mounted and sealed overlays; checks cannot alter seals.
    #[test]
    fn regression_fsck_locked_or_sealed_overlay_is_not_repaired() {
        let (_tmp, dir, source) = fixture();
        let mounted = WriteOverlay::new_for_tests(source.clone(), &dir).unwrap();
        assert_eq!(
            fsck(&dir, true).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            fsck(&dir, false).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(mounted);
        OverlayMeta::set(&db(&dir), "sealed_at", "2026-10-17T00:00:00Z").unwrap();
        host::write(dir.join(".ratarmount-sealed"), b"digest").unwrap();
        let before = host::read(dir.join(HIDDEN_DB)).unwrap();
        assert!(WriteOverlay::new_for_tests(source, &dir)
            .err()
            .unwrap()
            .to_string()
            .contains("sealed"));
        assert_eq!(
            fsck(&dir, true).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(fsck(&dir, false).unwrap().is_clean());
        assert_eq!(host::read(dir.join(HIDDEN_DB)).unwrap(), before);
        assert!(OverlayMeta::read(&dir)
            .unwrap()
            .unwrap()
            .get("fsck_at")
            .is_none());
    }

    /// Regression: malformed rows and symlink parents must never delete outside the overlay.
    #[test]
    fn regression_fsck_traversal_and_symlink_never_remove_external_content() {
        let (tmp, dir, _source) = fixture();
        let outside = tmp.path().join("outside");
        host::create_dir(&outside).unwrap();
        host::write(outside.join("keep"), b"safe").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
        let conn = db(&dir);
        for (parent, name) in [
            ("/..", "outside"),
            ("//absolute", "x"),
            ("", "/absolute"),
            ("/a//b", "x"),
            ("", ""),
            ("", "nul\0name"),
            ("/a/./b", "x"),
            ("", "../outside"),
        ] {
            conn.execute(
                "INSERT INTO files(path,name,deleted) VALUES (?1,?2,1)",
                params![parent, name],
            )
            .unwrap();
        }
        conn.execute_batch(
            "INSERT INTO files(path,name,deleted) VALUES ('','link',1),('/link','keep',0)",
        )
        .unwrap();
        drop(conn);
        let report = fsck(&dir, true).unwrap();
        assert_eq!(report.invalid_path, 8);
        assert_eq!(host::read(outside.join("keep")).unwrap(), b"safe");
        assert!(host::symlink_metadata(dir.join("link")).is_err());
        assert!(fsck(&dir, false).unwrap().is_clean());
    }

    /// Regression: a tombstone below a live symlink must not unlink its external
    /// target, and is not an inconsistency (`rm -rf d; ln -s x d`).
    #[test]
    fn regression_fsck_tombstone_below_symlink_is_harmless() {
        let (tmp, dir, _source) = fixture();
        let outside = tmp.path().join("outside");
        host::create_dir(&outside).unwrap();
        host::write(outside.join("keep"), b"safe").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
        db(&dir)
            .execute_batch("INSERT INTO files(path,name,deleted) VALUES ('/link','keep',1)")
            .unwrap();
        // A tombstone below what is now a symlink is stale but harmless; it is
        // not an error, and repair never traverses the link.
        // The link has no row, just like a normal COW host entry.
        let report = fsck(&dir, false).unwrap();
        assert_eq!((report.missing_parent, report.tombstone_content), (0, 0));
        assert_eq!(report.orphan_content, 0);
        assert_eq!(report.unrowed, 1);
        fsck(&dir, true).unwrap();
        assert!(fsck(&dir, false).unwrap().is_clean());
        assert_eq!(host::read(outside.join("keep")).unwrap(), b"safe");
        assert!(host::symlink_metadata(dir.join("link"))
            .unwrap()
            .is_symlink());
    }

    /// Regression: fsck reported `missing_parent` for ordinary agent edits, so
    /// `overlay seal` refused them: deleting a file inside an untouched base
    /// directory (no host parent), and replacing a base directory with a file
    /// or a symlink (tombstones left under a non-directory).
    #[test]
    fn regression_fsck_tombstones_need_no_host_parent() {
        let (tmp, dir, _) = fixture();
        let base = tmp.path().join("base");
        for sub in ["a/b", "d/sub", "l/x"] {
            host::create_dir_all(base.join(sub)).unwrap();
        }
        for file in ["a/b/c", "d/sub/old", "l/x/k"] {
            host::write(base.join(file), b"base").unwrap();
        }
        let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base).unwrap());
        let overlay = WriteOverlay::new_for_tests(source.clone(), &dir).unwrap();
        overlay.unlink("/a/b/c").unwrap();
        for (file, sub, top) in [("/d/sub/old", "/d/sub", "/d"), ("/l/x/k", "/l/x", "/l")] {
            overlay.unlink(file).unwrap();
            overlay.rmdir(sub).unwrap();
            overlay.rmdir(top).unwrap();
        }
        use std::io::Write as _;
        use std::os::fd::FromRawFd as _;
        let fd = overlay.create_file("/d", 0o644).unwrap();
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(b"now a file").unwrap();
        overlay.finish_owned_write_fd(file);
        overlay.create_symlink("/l", "/etc").unwrap();
        drop(overlay);
        let report = fsck(&dir, false).unwrap();
        assert!(report.is_clean(), "{}", report.result());
        assert!(!dir.join("a").exists(), "fsck must not create host parents");
        crate::overlay_seal::seal_impl(&dir, None, source).unwrap();
    }

    /// Regression: tombstoned directories leave descendants and missing parents inconsistent.
    #[test]
    fn regression_fsck_nested_tombstones_and_missing_parents() {
        let (_tmp, dir, _source) = fixture();
        host::create_dir_all(dir.join("gone/sub")).unwrap();
        host::write(dir.join("gone/sub/file"), b"old").unwrap();
        db(&dir)
            .execute_batch(
                "INSERT INTO files(path,name,mode,deleted) VALUES
            ('','gone',NULL,1), ('/gone/sub','file',33188,0),
            ('/missing','child',33188,0), ('/deleted-parent','child',NULL,1);",
            )
            .unwrap();
        let report = fsck(&dir, true).unwrap();
        // Only the present `/missing/child` row lacks its parent; the tombstone
        // `/deleted-parent/child` needs none and repair must not invent one.
        assert_eq!(report.missing_parent, 1);
        assert!(!dir.join("gone").exists());
        assert!(!dir.join("deleted-parent").exists());
        assert!(fsck(&dir, false).unwrap().is_clean());
    }

    /// Regression: inherited chmod rows and internal staging files are not orphan payloads.
    #[test]
    fn regression_fsck_metadata_only_and_internal_names_are_preserved() {
        let (tmp, dir, source) = fixture();
        host::create_dir(tmp.path().join("base/sub")).unwrap();
        host::write(tmp.path().join("base/sub/file"), b"base").unwrap();
        let overlay = WriteOverlay::new_for_tests(source, &dir).unwrap();
        for path in ["/", "/sub/file"] {
            overlay
                .set_metadata(
                    path,
                    &OverlayMetadata {
                        mode: Some(0o700),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        drop(overlay);
        for name in [
            ".ratarmount.overlay.cow-1",
            ".ratarmount-spool-1",
            ".ratarmount-sealed",
        ] {
            host::write(dir.join(name), b"internal").unwrap();
        }
        assert_eq!(fsck(&dir, true).unwrap().errors(), 0);
        assert_eq!(
            db(&dir)
                .query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    /// Regression: 10k host-only files need no invented rows or repeated directory walks.
    #[test]
    fn regression_fsck_ten_thousand_rows_single_scan() {
        let (_tmp, dir, _source) = fixture();
        for i in 0..10_000 {
            host::write(dir.join(format!("file-{i}")), []).unwrap();
        }
        let start = std::time::Instant::now();
        let report = fsck(&dir, true).unwrap();
        assert_eq!(report.repaired, 0);
        assert_eq!(report.unrowed, 10_000);
        assert_eq!(
            db(&dir)
                .query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(fsck(&dir, false).unwrap().is_clean());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(15),
            "fsck took {:?}",
            start.elapsed()
        );
    }

    /// Regression: checking a missing directory/database must not create an overlay.
    #[test]
    fn regression_fsck_missing_database_is_not_created() {
        let tmp = tempfile::tempdir().unwrap();
        for repair in [false, true] {
            assert!(fsck(tmp.path(), repair).is_err());
        }
        assert!(!tmp.path().join(HIDDEN_DB).exists());
    }

    /// Child half of [`regression_fsck_reports_incomplete_import`]: marks an
    /// import in progress, opens a write transaction and blocks until killed.
    /// Ignored, so it only runs when the parent re-executes the test binary.
    #[test]
    #[ignore = "child process of regression_fsck_reports_incomplete_import"]
    fn hot_journal_child() {
        let dir = std::env::var_os("RATARMOUNT_TEST_CHILD_OVERLAY").expect("child overlay dir");
        let base = std::path::PathBuf::from(dir.clone()).with_file_name("base");
        let source = Arc::new(FolderMountSource::new(&base).unwrap());
        let overlay = WriteOverlay::new_for_tests(source, std::path::Path::new(&dir)).unwrap();
        overlay
            .set_meta("import_in_progress", "123:2026-10-18T00:00:00Z")
            .unwrap();
        overlay.test_hold_open_transaction();
    }

    /// Regression: a killed `overlay import --no-seal` left a partial overlay
    /// that fsck reported clean, and (I1) its hot `-journal` made `fsck` fail
    /// with a readonly error. The writer is a real child process, SIGKILLed
    /// while its write transaction is open.
    #[cfg(unix)]
    #[test]
    fn regression_fsck_reports_incomplete_import() {
        let _process_guard = ratarmount_index::test_process::spawning();
        let (tmp, dir, source) = fixture();
        let ready = tmp.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "overlay_fsck::tests::hot_journal_child",
            ])
            .env("RATARMOUNT_TEST_CHILD_OVERLAY", &dir)
            .env("RATARMOUNT_TEST_JOURNAL_HOLD", &ready)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !ready.exists() {
            assert!(std::time::Instant::now() < deadline, "child never held");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let journal = dir.join(format!("{HIDDEN_DB}-journal"));
        assert!(journal.exists(), "no hot journal after SIGKILL");
        for repair in [false, true] {
            let report = fsck(&dir, repair).unwrap();
            assert!(!report.is_clean(), "repair={repair}: {}", report.result());
            assert_eq!(report.import_incomplete, 1);
            assert!(report.result().starts_with("errors:"));
        }
        // --repair cannot know the import finished: the marker stays.
        assert_eq!(
            OverlayMeta::read(&dir)
                .unwrap()
                .unwrap()
                .get("import_in_progress"),
            Some("123:2026-10-18T00:00:00Z")
        );
        // Seal refuses, naming the import rather than suggesting fsck --repair.
        let err = crate::overlay_seal::seal_impl(&dir, None, source)
            .unwrap_err()
            .to_string();
        assert!(err.contains("import"), "{err}");
        assert!(!err.contains("fsck --repair"), "{err}");
    }

    /// Compatibility: no marker (or a cleared one) is clean.
    #[test]
    fn regression_fsck_cleared_import_marker_is_clean() {
        let (_tmp, dir, _source) = fixture();
        db(&dir)
            .execute("DELETE FROM meta WHERE key='import_in_progress'", [])
            .unwrap();
        assert!(fsck(&dir, false).unwrap().is_clean());
    }
}
