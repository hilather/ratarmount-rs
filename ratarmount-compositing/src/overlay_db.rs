//! The one validated open of an overlay database (R7-F1).
//!
//! SQLite opens whatever is at a path: a symlink to `/dev/null` reads as an
//! empty database (an offline gate then sees no record and accepts), and a
//! FIFO blocks the open until a writer appears. Every overlay-database open
//! goes through [`open_overlay_db`]:
//!
//! 1. the path is classified BEFORE anything opens it (`lstat` when the
//!    caller's flags carry `SQLITE_OPEN_NOFOLLOW`, else `stat`): a directory,
//!    a FIFO, a device or a socket is refused without an `open(2)`, so a FIFO
//!    never blocks;
//! 2. SQLite opens the path;
//! 3. the path is classified again under the same rule: it must be a regular
//!    file with the `(dev, ino)` step 1 saw (or, when step 1 found nothing
//!    and SQLite created the file, the one the path names now).
//!
//! Step 3 is a `stat`, never an `open(2)` (R7-H1): on POSIX, closing ANY
//! descriptor of an inode releases every fcntl lock this process holds on
//! it, including SQLite's (this connection's and any other connection's in
//! the process), so a descriptor of our own would hand another process the
//! write lock as soon as it was dropped. SQLite's own descriptors are safe:
//! its unix VFS defers their close while the inode is locked.
//!
//! rusqlite does not expose the descriptor SQLite itself opened, so step 3
//! proves the identity of the file at the path right after SQLite's open, not
//! of SQLite's descriptor: an entry swapped away and back between steps 2 and
//! 3 is not detected (a known follow-up). Every swap that stays in place is.
//!
//! An error is returned before the caller reads or writes anything, so a
//! caller that authorizes or recovers on the record refuses (or defers)
//! first.

use std::fs;
use std::io;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::OverlayError;

/// Why an overlay database was not opened.
#[derive(Debug, thiserror::Error)]
pub enum OverlayDbError {
    /// The path is not a regular file (or changed while it was opened).
    #[error("{0}")]
    NotRegular(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

impl OverlayDbError {
    /// An `io::Error`, with SQLite's errors mapped by the caller's `sql`.
    pub fn into_io_with(self, sql: impl FnOnce(rusqlite::Error) -> io::Error) -> io::Error {
        match self {
            OverlayDbError::Sqlite(e) => sql(e),
            other => other.into(),
        }
    }
}

impl From<OverlayDbError> for OverlayError {
    fn from(error: OverlayDbError) -> Self {
        match error {
            OverlayDbError::NotRegular(msg) => OverlayError::Msg(msg),
            OverlayDbError::Io(e) => OverlayError::Io(e),
            OverlayDbError::Sqlite(e) => OverlayError::Sqlite(e),
        }
    }
}

impl From<OverlayDbError> for io::Error {
    fn from(error: OverlayDbError) -> Self {
        match error {
            OverlayDbError::NotRegular(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            OverlayDbError::Io(e) => e,
            OverlayDbError::Sqlite(e) => io::Error::other(e),
        }
    }
}

/// The text for an overlay database entry of the wrong type.
pub(crate) fn not_regular_message(db: &Path, metadata: &fs::Metadata) -> String {
    if metadata.is_dir() {
        format!(
            "overlay database path {} is a directory, not a database file; move it aside",
            db.display()
        )
    } else if metadata.file_type().is_symlink() {
        format!(
            "overlay database {} is a symlink; it must be a regular file",
            db.display()
        )
    } else {
        format!(
            "overlay database {} is not a regular file; move it aside",
            db.display()
        )
    }
}

/// How SQLite is pointed at the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbName<'a> {
    /// The path itself.
    Path,
    /// `file:<canonical path>?mode=ro&immutable=1` (adds `SQLITE_OPEN_URI`).
    Immutable,
    /// A caller-built URI for the same file (adds `SQLITE_OPEN_URI`).
    Uri(&'a str),
}

/// A connection [`open_overlay_db`] validated. Dereferences to the
/// [`Connection`], so callers use it as one.
#[derive(Debug)]
pub struct OverlayDb {
    conn: Connection,
    id: Option<(u64, u64)>,
}

impl OverlayDb {
    /// `(dev, ino)` of the database file, from the post-open path stat (see
    /// the module docs: the file at the path right after SQLite's open, not
    /// SQLite's own descriptor). `None` off Unix.
    pub fn id(&self) -> Option<(u64, u64)> {
        self.id
    }

    /// The connection, for a caller that keeps it in its own structure.
    pub fn into_connection(self) -> Connection {
        self.conn
    }
}

impl std::ops::Deref for OverlayDb {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}

impl std::ops::DerefMut for OverlayDb {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// Open the overlay database at `db` with `flags`; see the module docs.
/// `SQLITE_OPEN_NOFOLLOW` also makes the type checks refuse a symlink at
/// `db`; SQLite then refuses a symlink in any component, so the directory is
/// resolved first.
pub fn open_overlay_db(
    db: &Path,
    flags: OpenFlags,
    name: DbName<'_>,
) -> Result<OverlayDb, OverlayDbError> {
    let nofollow = flags.contains(OpenFlags::SQLITE_OPEN_NOFOLLOW);
    let resolved;
    let db = if nofollow || name == DbName::Immutable {
        resolved = match (db.parent(), db.file_name()) {
            (Some(dir), Some(file)) if !dir.as_os_str().is_empty() => {
                dir.canonicalize()?.join(file)
            }
            _ => db.to_path_buf(),
        };
        resolved.as_path()
    } else {
        db
    };
    let stat = |path: &Path| {
        if nofollow {
            fs::symlink_metadata(path)
        } else {
            fs::metadata(path)
        }
    };
    let before = match stat(db) {
        Ok(m) if m.is_file() => Some(m),
        Ok(m) => return Err(OverlayDbError::NotRegular(not_regular_message(db, &m))),
        // A dangling symlink: never created (or read) through it.
        Err(e)
            if e.kind() == io::ErrorKind::NotFound
                && !nofollow
                && fs::symlink_metadata(db).is_ok() =>
        {
            return Err(OverlayDbError::NotRegular(format!(
                "overlay database {} is a symlink to a file that does not exist; it is not \
                 created through the symlink: restore its target or remove the symlink",
                db.display()
            )))
        }
        // Nothing (or nothing reachable) is there: SQLite creates it when the
        // flags allow, else fails with its own error.
        Err(_) => None,
    };
    let conn = match name {
        DbName::Path => Connection::open_with_flags(db, flags)?,
        DbName::Immutable => Connection::open_with_flags(
            crate::overlay_layer::immutable_uri(db),
            flags | OpenFlags::SQLITE_OPEN_URI,
        )?,
        DbName::Uri(uri) => Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI)?,
    };
    // A stat, not an open: see the module docs (R7-H1).
    let opened = stat(db).map_err(|e| {
        OverlayDbError::NotRegular(format!(
            "overlay database {} changed while it was opened: {e}",
            db.display()
        ))
    })?;
    if !opened.is_file() {
        return Err(OverlayDbError::NotRegular(not_regular_message(db, &opened)));
    }
    if before.is_some_and(|before| !same_file(&before, &opened)) {
        return Err(OverlayDbError::NotRegular(format!(
            "overlay database {} changed while it was opened",
            db.display()
        )));
    }
    Ok(OverlayDb {
        conn,
        id: file_id(&opened),
    })
}

/// `(dev, ino)` of `metadata` (`None` off Unix).
pub(crate) fn file_id(metadata: &fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Without `(dev, ino)` the type checks are all there is.
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    file_id(a) == file_id(b)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const RO: OpenFlags = OpenFlags::SQLITE_OPEN_READ_ONLY;

    fn real_db(path: &Path) {
        Connection::open(path)
            .unwrap()
            .execute_batch("CREATE TABLE t (x)")
            .unwrap();
    }

    /// Regression (R7-F1): what the one validated open accepts and refuses.
    /// A directory, a FIFO (without blocking), a symlink to `/dev/null` and a
    /// dangling symlink are refused; a symlink to a regular database is
    /// followed unless the flags carry `SQLITE_OPEN_NOFOLLOW`; a missing path
    /// is created only when the flags allow it.
    #[test]
    fn regression_open_overlay_db_validates_the_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let not_regular = |path: &Path, flags: OpenFlags| {
            matches!(
                open_overlay_db(path, flags, DbName::Path),
                Err(OverlayDbError::NotRegular(_))
            )
        };
        let directory = dir.join("dir.sqlite");
        fs::create_dir(&directory).unwrap();
        assert!(not_regular(&directory, RO));
        let error = open_overlay_db(&directory, RO, DbName::Path)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("is a directory, not a database file"),
            "{error}"
        );

        let fifo = dir.join("fifo.sqlite");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // Would block forever if anything opened the FIFO.
        assert!(not_regular(&fifo, RO));
        assert!(not_regular(&fifo, RO | OpenFlags::SQLITE_OPEN_NOFOLLOW));

        let null = dir.join("null.sqlite");
        std::os::unix::fs::symlink("/dev/null", &null).unwrap();
        assert!(not_regular(&null, RO));
        assert!(not_regular(&null, OpenFlags::default()));

        let dangling = dir.join("dangling.sqlite");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();
        assert!(not_regular(&dangling, OpenFlags::default()));
        assert!(!dir.join("nowhere").exists(), "nothing created through it");

        let db = dir.join("real.sqlite");
        real_db(&db);
        let link = dir.join("link.sqlite");
        std::os::unix::fs::symlink(&db, &link).unwrap();
        open_overlay_db(&db, RO, DbName::Path).unwrap();
        open_overlay_db(&db, RO, DbName::Immutable).unwrap();
        open_overlay_db(&link, RO, DbName::Path).unwrap();
        assert!(not_regular(&link, RO | OpenFlags::SQLITE_OPEN_NOFOLLOW));

        let missing = dir.join("missing.sqlite");
        assert!(matches!(
            open_overlay_db(&missing, RO, DbName::Path),
            Err(OverlayDbError::Sqlite(_))
        ));
        assert!(!missing.exists());
        open_overlay_db(&missing, OpenFlags::default(), DbName::Path).unwrap();
        assert!(missing.is_file());
    }

    /// Set by [`regression_open_overlay_db_keeps_other_connections_locks`]
    /// for the child it spawns.
    const PROBE_DB_ENV: &str = "RATARMOUNT_TEST_OVERLAY_DB_LOCK_PROBE";

    /// The child half of the lock regression: try to take the write lock
    /// without waiting and print what happened. A no-op unless spawned.
    #[test]
    fn overlay_db_lock_probe_child() {
        let Some(db) = std::env::var_os(PROBE_DB_ENV) else {
            return;
        };
        let conn = Connection::open(db).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        match conn.execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (2); COMMIT") {
            Ok(()) => println!("PROBE:acquired"),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseBusy =>
            {
                println!("PROBE:busy")
            }
            Err(e) => println!("PROBE:error {e}"),
        }
    }

    /// Regression (R7-H1): another connection of this process keeps its
    /// write lock across an `open_overlay_db` of the same file. POSIX drops
    /// every fcntl lock a process holds on an inode when ANY descriptor of
    /// that inode is closed; the validated open used to open (and close) a
    /// descriptor of its own, so a second process could then write while the
    /// first still held RESERVED.
    #[test]
    fn regression_open_overlay_db_keeps_other_connections_locks() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().canonicalize().unwrap().join("overlay.sqlite");
        real_db(&db);
        let holder = Connection::open(&db).unwrap();
        holder
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (1)")
            .unwrap();
        for flags in [
            RO,
            OpenFlags::default(),
            RO | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ] {
            drop(open_overlay_db(&db, flags, DbName::Path).unwrap());
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "overlay_db::tests::overlay_db_lock_probe_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PROBE_DB_ENV, &db)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("PROBE:busy"),
            "a second process must still see the holder's write lock after \
             open_overlay_db; child stdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        holder.execute_batch("COMMIT").unwrap();
    }
}
