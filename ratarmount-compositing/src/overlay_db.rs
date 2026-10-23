//! The one validated open of an overlay database (R7-F1, #151).
//!
//! SQLite opens whatever is at a path: a symlink to `/dev/null` reads as an
//! empty database (an offline gate then sees no record and accepts), and a
//! FIFO blocks the open until a writer appears. Every overlay-database open
//! goes through [`open_overlay_db`]:
//!
//! 1. the path is classified BEFORE anything opens it, by the r10 classifier
//!    ([`crate::write_overlay::overlay_db_entry`] for an overlay directory's
//!    database, the type of the file alone for any other name): a directory,
//!    a FIFO, a device, a socket, a dangling symlink, any unresolved `stat`
//!    and a lost record (#96) are refused without an `open(2)`. Only an
//!    `lstat` NotFound is "nothing there". With `SQLITE_OPEN_NOFOLLOW` a
//!    symlink at the name is refused too;
//! 2. the classification becomes the expectation of a checked acquisition
//!    ([`ratarmount_index::checked_open`]): the regular file with that
//!    `(dev, ino)` (non-empty when the record is required: a marked overlay
//!    or one the caller saw required earlier), or, when nothing was there,
//!    the empty file SQLite creates. The acquisition judges SQLite's OWN
//!    descriptor (or every `stat` that selected a reused one) inside
//!    SQLite's open, so a name swapped to another file and back around the
//!    open (A→X→A) is refused, and a refused descriptor is never handed to
//!    SQLite or closed;
//! 3. that acquired `(dev, ino)` is registered as an open database inode
//!    ([`ratarmount_core::db_inodes`]) for the connection's life, and the
//!    database path plus its `-wal` / `-shm` / `-journal` names are latched
//!    for the rest of the process ([`ratarmount_index::checked_open::latch_overlay_nocreate`],
//!    R11-S8): a later checked open of that path cannot create the file, and
//!    on a verified Unix host neither can an `open` of a missing `-wal` or
//!    `-shm`. `-journal` stays creatable (DELETE journal mode). Index and
//!    other checked opens are not latched.
//!
//! Nothing here opens a descriptor of its own (R7-H1): on POSIX, closing ANY
//! descriptor of an inode releases every fcntl lock this process holds on
//! it, including SQLite's. SQLite's own descriptors are safe: its unix VFS
//! defers their close while the inode is locked.
//!
//! An error is returned before the caller reads or writes anything, so a
//! caller that authorizes or recovers on the record refuses (or defers)
//! first.

use std::fs;
use std::io;
use std::path::Path;

use ratarmount_index::checked_open::{self, AcquireError, Expect, NameMode, Verification};
use rusqlite::{Connection, OpenFlags};

use crate::write_overlay::DbEntry;
use crate::OverlayError;

/// Why an overlay database was not opened.
#[derive(Debug, thiserror::Error)]
pub enum OverlayDbError {
    /// The path is not a regular file.
    #[error("{0}")]
    NotRegular(String),
    /// The record is lost, or the checked acquisition refused (SQLite
    /// acquired another file than the one classified, an empty record, no
    /// checked open on this host, ...).
    #[error("{0}")]
    Refused(String),
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
            OverlayDbError::NotRegular(msg) | OverlayDbError::Refused(msg) => {
                OverlayError::Msg(msg)
            }
            OverlayDbError::Io(e) => OverlayError::Io(e),
            OverlayDbError::Sqlite(e) => OverlayError::Sqlite(e),
        }
    }
}

impl From<OverlayDbError> for io::Error {
    fn from(error: OverlayDbError) -> Self {
        match error {
            OverlayDbError::NotRegular(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            OverlayDbError::Refused(msg) => io::Error::other(msg),
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
    /// `file:<path>?mode=ro&immutable=1`, built by the checked open from the
    /// absolute path (its parent directory resolved, the final component
    /// kept as given); read-only flags without `SQLITE_OPEN_CREATE`.
    Immutable,
    /// Deprecated (#153): a caller-built URI could carry `vfs=` or `modeof=`.
    /// Always refused, before anything is opened; use [`DbName::Immutable`].
    Uri(&'a str),
}

/// A connection [`open_overlay_db`] validated. Dereferences to the
/// [`Connection`], so callers use it as one. While it lives, its database
/// inode is registered as open (R10-C,
/// [`ratarmount_core::db_inodes`]): payload opens of another name of that
/// inode are refused, so they can never close a descriptor of it.
#[derive(Debug)]
pub struct OverlayDb {
    // Declared first: the connection closes before the registration drops.
    conn: Connection,
    id: Option<(u64, u64)>,
    registration: Option<ratarmount_core::db_inodes::DbInodeRegistration>,
    required_record: bool,
    verification: Verification,
}

impl OverlayDb {
    /// `(dev, ino)` SQLite acquired (its own descriptor, or the inode every
    /// reuse-selection `stat` reported). `None` off Unix.
    pub fn id(&self) -> Option<(u64, u64)> {
        self.id
    }

    /// The record must hold the `files` table: the overlay is marked, or the
    /// caller already required it (a latch: never cleared by a later look).
    pub fn required_record(&self) -> bool {
        self.required_record
    }

    /// What the identity rests on.
    pub fn verification(&self) -> Verification {
        self.verification
    }

    /// The connection and its registration, for a caller that keeps them in
    /// its own structure (drop the connection first).
    pub(crate) fn into_parts(
        self,
    ) -> (
        Connection,
        Option<ratarmount_core::db_inodes::DbInodeRegistration>,
    ) {
        (self.conn, self.registration)
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

/// A test seam: called with the database path on every open of this thread.
#[cfg(test)]
pub(crate) type Seam = std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>>;

#[cfg(test)]
thread_local! {
    /// After the classification, before the checked acquisition.
    pub(crate) static AFTER_CLASSIFY: Seam = const { std::cell::RefCell::new(None) };
    /// After the acquisition, before the caller reads anything.
    pub(crate) static AFTER_ACQUIRE: Seam = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn fire(seam: &'static std::thread::LocalKey<Seam>, db: &Path) {
    seam.with(|hook| {
        if let Some(f) = hook.borrow_mut().as_mut() {
            f(db)
        }
    })
}

/// Open the overlay database at `db` with `flags`; see the module docs.
/// `SQLITE_OPEN_NOFOLLOW` also refuses a symlink at `db`; SQLite then refuses
/// a symlink in any component, so the directory is resolved first.
pub fn open_overlay_db(
    db: &Path,
    flags: OpenFlags,
    name: DbName<'_>,
) -> Result<OverlayDb, OverlayDbError> {
    open_overlay_db_required(db, flags, name, false)
}

/// [`open_overlay_db`] of a record the caller already saw required
/// (`previously_required`: a marker it observed earlier, a `files` table it
/// required before): the record must exist and be non-empty even if its
/// marker is gone now. [`OverlayDb::required_record`] is that latch OR'ed
/// with this classification's marker.
pub(crate) fn open_overlay_db_required(
    db: &Path,
    flags: OpenFlags,
    name: DbName<'_>,
    previously_required: bool,
) -> Result<OverlayDb, OverlayDbError> {
    let mode = match name {
        DbName::Path => NameMode::Path,
        DbName::Immutable => NameMode::Immutable,
        DbName::Uri(_) => {
            return Err(OverlayDbError::Refused(format!(
                "overlay database {}: caller-built SQLite URIs are not accepted",
                db.display()
            )))
        }
    };
    let nofollow = flags.contains(OpenFlags::SQLITE_OPEN_NOFOLLOW);
    let resolved;
    let db = if nofollow || mode == NameMode::Immutable {
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
    let entry = crate::write_overlay::overlay_db_entry_for(db).map_err(|e| match e {
        OverlayError::Io(e) => OverlayDbError::Io(e),
        OverlayError::Msg(msg) => OverlayDbError::NotRegular(msg),
        other => OverlayDbError::Refused(other.to_string()),
    })?;
    if nofollow {
        if let Ok(m) = fs::symlink_metadata(db) {
            if m.file_type().is_symlink() {
                return Err(OverlayDbError::NotRegular(not_regular_message(db, &m)));
            }
        }
    }
    let (expect, required) = match entry {
        DbEntry::Absent if previously_required => {
            return Err(OverlayDbError::Refused(format!(
                "overlay database {} is missing, but its record was required earlier (the \
                 overlay was used); it is not created anew",
                db.display()
            )))
        }
        DbEntry::Absent => (Expect::Fresh, false),
        DbEntry::Lost { markers, .. } => {
            let dir = db.parent().unwrap_or(Path::new(""));
            return Err(OverlayDbError::Refused(
                crate::write_overlay::lost_record_error(dir, &markers).to_string(),
            ));
        }
        DbEntry::Present { marked, metadata } => {
            let required = previously_required || marked;
            (
                Expect::Existing {
                    // Off Unix there is no identity (`WindowsPathTypeOnly`).
                    id: file_id(&metadata).unwrap_or_default(),
                    require_nonempty: required,
                },
                required,
            )
        }
    };
    #[cfg(test)]
    fire(&AFTER_CLASSIFY, db);
    let acquired = checked_open::open_checked(db, flags, mode, expect).map_err(|refusal| {
        match refusal.error {
            AcquireError::Sqlite(e) => OverlayDbError::Sqlite(e),
            _ => OverlayDbError::Refused(format!("overlay database {}: {refusal}", db.display())),
        }
    })?;
    // Only the acquired identity is registered, after SQLite's open: the
    // registry lock is never held across an open (R10-D). The no-create
    // latch is the same moment: the open has succeeded, and the hook is not
    // on the stack (it must not run while this lock is held).
    checked_open::latch_overlay_nocreate(acquired.id, db);
    let registration = acquired
        .id
        .map(|id| ratarmount_core::db_inodes::register_db_inode(id, db));
    #[cfg(test)]
    fire(&AFTER_ACQUIRE, db);
    Ok(OverlayDb {
        conn: acquired.conn,
        id: acquired.id,
        registration,
        required_record: required,
        verification: acquired.verification,
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

/// Set by [`lock_probe_is_busy`] for the child it spawns.
#[cfg(all(test, unix))]
pub(crate) const BEGIN_IMMEDIATE_PROBE_ENV: &str = "RATARMOUNT_TEST_BEGIN_IMMEDIATE_PROBE";

/// Does ANOTHER process see this process's lock on `db`? A child of this test
/// binary runs `BEGIN IMMEDIATE` as its own statement (busy timeout 0): `true`
/// when that statement itself reports busy. The child must exit successfully.
#[cfg(all(test, unix))]
pub(crate) fn lock_probe_is_busy(db: &Path) -> bool {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "overlay_db::tests::begin_immediate_probe_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(BEGIN_IMMEDIATE_PROBE_ENV, db)
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

/// Set by [`other_process_sees_lock`] for the child it spawns.
#[cfg(all(test, unix))]
pub(crate) const GETLK_PROBE_ENV: &str = "RATARMOUNT_TEST_GETLK_PROBE";

/// Does ANOTHER process see any SQLite lock this process holds on `db`? A
/// child of this test binary asks `F_GETLK` for a write lock over SQLite's
/// lock bytes (PENDING, RESERVED and the SHARED range at `0x40000000`), so a
/// SHARED lock (which `BEGIN IMMEDIATE` cannot see) counts, and a read-only
/// file can be probed. The child opens the file read-only and writes nothing.
#[cfg(all(test, unix))]
pub(crate) fn other_process_sees_lock(db: &Path) -> bool {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "overlay_db::tests::getlk_probe_child",
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

    /// Regression (Fable r11 N2): the open classifies the path it is given.
    /// A database under another name than the overlay's (a staging copy, a
    /// test's `real.sqlite`) is the file itself, never marked, even in a
    /// marked directory; the overlay's own name in that directory is a
    /// required record, refused when lost or (if required earlier) missing.
    #[test]
    fn regression_open_overlay_db_classifies_the_given_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        fs::write(dir.join(crate::OVERLAY_MARKER), b"").unwrap();
        let real = dir.join("real.sqlite");
        real_db(&real);
        let link = dir.join("link.sqlite");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let empty = dir.join("empty.sqlite");
        fs::write(&empty, b"").unwrap();
        for path in [&real, &link, &empty] {
            let opened = open_overlay_db(path, OpenFlags::default(), DbName::Path)
                .unwrap_or_else(|e| panic!("{path:?}: {e}"));
            assert!(!opened.required_record(), "{path:?}");
            assert_eq!(opened.id(), file_id(&fs::metadata(path).unwrap()));
        }
        assert_eq!(fs::metadata(&empty).unwrap().len(), 0, "not created anew");

        // The overlay's own name: marked, so required.
        let hidden = dir.join(crate::HIDDEN_DB);
        let lost = |flags| match open_overlay_db(&hidden, flags, DbName::Path) {
            Err(OverlayDbError::Refused(e)) => e,
            other => panic!("{other:?}"),
        };
        assert!(lost(OpenFlags::default()).contains("missing or empty"));
        assert!(!hidden.exists(), "a lost record is never created");
        fs::write(&hidden, b"").unwrap();
        assert!(lost(RO).contains("missing or empty"));
        fs::remove_file(&hidden).unwrap();
        real_db(&hidden);
        let opened = open_overlay_db(&hidden, RO, DbName::Path).unwrap();
        assert!(opened.required_record());
        // The latched requirement reaches the reader: no `files` table is a
        // lost record, never "unrecorded".
        let error = crate::OverlayMeta::from_opened(&opened).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(crate::overlay_meta::NO_FILES_TABLE),
            "{error}"
        );
        drop(opened);
        Connection::open(&hidden)
            .unwrap()
            .execute_batch("CREATE TABLE files (x)")
            .unwrap();
        let opened = open_overlay_db(&hidden, RO, DbName::Path).unwrap();
        assert!(crate::OverlayMeta::from_opened(&opened).unwrap().is_none());
        drop(opened);

        // Required earlier, unmarked now: a missing record is not created.
        fs::remove_file(dir.join(crate::OVERLAY_MARKER)).unwrap();
        fs::remove_file(&hidden).unwrap();
        match open_overlay_db_required(&hidden, OpenFlags::default(), DbName::Path, true) {
            // The message is one sentence (S3 review nit: a missing line
            // continuation put a run of spaces in it).
            Err(OverlayDbError::Refused(msg)) => assert_eq!(
                msg,
                format!(
                    "overlay database {} is missing, but its record was required earlier \
                     (the overlay was used); it is not created anew",
                    hidden.display()
                )
            ),
            other => panic!("a required missing record must refuse: {other:?}"),
        }
        assert!(!hidden.exists());
        // The successful opens above latched this path for the process
        // (R11-S8). Dropping the marker does not make a later Fresh open
        // create it again.
        let error = open_overlay_db(&hidden, OpenFlags::default(), DbName::Path).unwrap_err();
        assert!(
            !hidden.exists(),
            "a latched overlay database was created again: {error}"
        );
    }

    /// Regression (#153): a caller-built URI is refused before anything is
    /// opened (its `vfs=` or `modeof=` would escape the checked open).
    #[test]
    fn regression_open_overlay_db_refuses_caller_uri() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().canonicalize().unwrap().join("x.sqlite");
        real_db(&db);
        let uri = format!("file:{}?vfs=unix-none", db.display());
        assert!(matches!(
            open_overlay_db(&db, RO, DbName::Uri(&uri)),
            Err(OverlayDbError::Refused(_))
        ));
    }

    /// Regression (#151, r9 T1 × R10-C): the registration is the inode SQLite
    /// acquired. The overlay database A is swapped to another database X
    /// after the classification and back right after SQLite's real `open`
    /// (A→X→A, invisible to any look at the name before or after): the open
    /// is refused and neither inode is registered. A normal open registers
    /// the acquired inode for exactly the connection's life.
    // The acquisition seams exist only where the wrappers are installed.
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
    ))]
    #[test]
    fn regression_checked_open_registration_uses_acquired_inode() {
        use ratarmount_core::db_inodes::is_db_inode;
        use ratarmount_index::checked_open::test_seams::{Seam, Seams};
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let a = dir.join(crate::HIDDEN_DB);
        let x = dir.join("x.sqlite");
        let saved = dir.join("a.saved");
        real_db(&a);
        real_db(&x);
        let id_a = file_id(&fs::metadata(&a).unwrap()).unwrap();
        let id_x = file_id(&fs::metadata(&x).unwrap()).unwrap();
        {
            let (a, x, saved) = (a.clone(), x.clone(), saved.clone());
            AFTER_CLASSIFY.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |_| {
                    fs::rename(&a, &saved).unwrap();
                    fs::rename(&x, &a).unwrap();
                }))
            });
        }
        let restore = {
            let (a, x, saved) = (a.clone(), x.clone(), saved.clone());
            Seams::set(move |seam| {
                if seam == Seam::AfterRealOpen {
                    fs::rename(&a, &x).unwrap();
                    fs::rename(&saved, &a).unwrap();
                }
            })
        };
        let error = open_overlay_db(&a, RO, DbName::Path).unwrap_err();
        AFTER_CLASSIFY.with(|hook| *hook.borrow_mut() = None);
        drop(restore);
        // Another test's open connection makes SQLite's reuse-selection
        // `stat` see X first, which refuses before any `open` (no restore).
        if saved.exists() {
            fs::rename(&a, &x).unwrap();
            fs::rename(&saved, &a).unwrap();
        }
        assert!(
            matches!(&error, OverlayDbError::Refused(e) if e.contains("another file")),
            "{error}"
        );
        assert_eq!(file_id(&fs::metadata(&a).unwrap()), Some(id_a), "A is back");
        assert!(
            !is_db_inode(id_a) && !is_db_inode(id_x),
            "nothing registered"
        );

        let opened = open_overlay_db(&a, RO, DbName::Path).unwrap();
        assert_eq!(opened.id(), Some(id_a));
        assert!(is_db_inode(id_a));
        drop(opened);
        assert!(!is_db_inode(id_a), "deregistered with the connection");
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

    /// The child half of [`lock_probe_is_busy`]: `BEGIN IMMEDIATE` alone, so
    /// a busy result is the lock statement's own. A no-op unless spawned.
    #[test]
    fn begin_immediate_probe_child() {
        let Some(db) = std::env::var_os(BEGIN_IMMEDIATE_PROBE_ENV) else {
            return;
        };
        let conn = Connection::open(db).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        match conn.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => {
                conn.execute_batch("ROLLBACK").unwrap();
                println!("PROBE:acquired")
            }
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

    /// The child half of [`other_process_sees_lock`]. A no-op unless spawned.
    #[test]
    fn getlk_probe_child() {
        use std::os::fd::AsRawFd;
        let Some(db) = std::env::var_os(GETLK_PROBE_ENV) else {
            return;
        };
        let file = fs::File::open(db).unwrap();
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
        if unlocked {
            println!("GETLK:unlocked");
        } else {
            println!("GETLK:locked");
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
        assert!(lock_probe_is_busy(&db), "BEGIN IMMEDIATE alone is busy");
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

    /// Regression (R11-S8): the first `Expect::Fresh` overlay open creates the
    /// database (and can write; DELETE mode creates `-journal`). After that
    /// open succeeds the path is latched, so deleting the file and opening
    /// again does not create another one.
    #[test]
    fn regression_fresh_creates_once_then_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let db = dir.join("fresh.sqlite");
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
        let opened = open_overlay_db(&db, flags, DbName::Path).unwrap();
        opened
            .execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1);")
            .unwrap();
        assert!(opened.id().is_some());
        drop(opened);
        fs::remove_file(&db).unwrap();
        let error = open_overlay_db(&db, flags, DbName::Path).unwrap_err();
        assert!(
            !db.exists(),
            "a second Fresh open created the database: {error}"
        );
        for suffix in ["-shm", "-wal"] {
            let mut name = db.file_name().unwrap().to_os_string();
            name.push(suffix);
            assert!(
                !dir.join(&name).exists(),
                "{name:?} appeared on the refused open"
            );
        }
    }

    /// Regression (R11-S8): `Expect::Existing` never creates. The file is
    /// removed after classification and before SQLite's open (the marker
    /// stays); no 0-byte database is left beside it.
    #[test]
    fn regression_existing_never_creates() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let db = dir.join(crate::HIDDEN_DB);
        let marker = dir.join(crate::OVERLAY_MARKER);
        real_db(&db);
        fs::write(&marker, b"").unwrap();
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                AFTER_CLASSIFY.with(|hook| *hook.borrow_mut() = None);
            }
        }
        let _clear = Clear;
        AFTER_CLASSIFY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|db| {
                fs::remove_file(db).unwrap();
            }))
        });
        let error = open_overlay_db(&db, OpenFlags::default(), DbName::Path).unwrap_err();
        assert!(
            !db.exists(),
            "Existing created a database beside the marker: {error}"
        );
        assert!(marker.is_file(), "marker removed");
        for suffix in ["-shm", "-wal", "-journal"] {
            let mut name = db.file_name().unwrap().to_os_string();
            name.push(suffix);
            let path = dir.join(&name);
            assert!(
                !path.exists(),
                "created {} beside the marker",
                path.display()
            );
        }
    }
}
