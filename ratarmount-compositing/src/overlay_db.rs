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
//! 3. a stat-only post-open path check remains as an additional defense;
//!    that acquired `(dev, ino)` is registered as an open database inode
//!    ([`ratarmount_core::db_inodes`]) for the connection's life.
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
            error @ OverlayDbError::NotRegular(_) => OverlayError::Io(error.into()),
            OverlayDbError::Refused(msg) => OverlayError::Msg(msg),
            OverlayDbError::Io(e) => OverlayError::Io(e),
            OverlayDbError::Sqlite(e) => OverlayError::Sqlite(e),
        }
    }
}

impl From<OverlayDbError> for io::Error {
    fn from(error: OverlayDbError) -> Self {
        match error {
            error @ OverlayDbError::NotRegular(_) => {
                io::Error::new(io::ErrorKind::InvalidData, error)
            }
            OverlayDbError::Refused(msg) => io::Error::other(msg),
            OverlayDbError::Io(e) => e,
            OverlayDbError::Sqlite(e) => io::Error::other(e),
        }
    }
}

/// A strict overlay-state policy refusal, retained through I/O wrappers so
/// offline callers can distinguish it from a lost record or journal error.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct OverlayStateError(pub(crate) String);

/// Whether an error reports a strict overlay-state policy refusal.
///
/// Several journal error types intentionally do not expose a source, and
/// transparent I/O wrappers can skip their inner error's own identity.
pub fn is_overlay_state_error(error: &(dyn std::error::Error + 'static)) -> bool {
    if error.is::<OverlayStateError>() {
        return true;
    }
    if let Some(error) = error.downcast_ref::<io::Error>() {
        return error
            .get_ref()
            .is_some_and(|error| is_overlay_state_error(error));
    }
    if let Some(OverlayError::Io(error)) = error.downcast_ref::<OverlayError>() {
        return is_overlay_state_error(error);
    }
    if let Some(error) = error.downcast_ref::<OverlayDbError>() {
        match error {
            OverlayDbError::NotRegular(_) => return true,
            OverlayDbError::Io(error) => return is_overlay_state_error(error),
            _ => {}
        }
    }
    use ratarmount_compress::commit_journal::{RecoverError, ReplaceError};
    if let Some(error) = error.downcast_ref::<RecoverError>() {
        let (RecoverError::Refused(error)
        | RecoverError::Journal(error)
        | RecoverError::Committed(error)) = error;
        return is_overlay_state_error(error);
    }
    if let Some(error) = error.downcast_ref::<ReplaceError>() {
        let (ReplaceError::Refused(error)
        | ReplaceError::RolledBack(error, _)
        | ReplaceError::Pending(error)
        | ReplaceError::Committed(error)) = error;
        return is_overlay_state_error(error);
    }
    if let Some(error) = error.downcast_ref::<ratarmount_compress::CompressError>() {
        return match error {
            ratarmount_compress::CompressError::Io(error) => is_overlay_state_error(error),
            ratarmount_compress::CompressError::Replace(error) => is_overlay_state_error(error),
            _ => false,
        };
    }
    error.source().is_some_and(is_overlay_state_error)
}

/// Refuse symlinks and other nonregular entries at an overlay database's
/// final component and its literal SQLite companion names. Missing entries
/// are allowed; the caller retains its required-record checks.
///
/// This is stat-only: opening and closing an alias could release SQLite's
/// POSIX locks. Parent symlinks remain supported; the final component is
/// never canonicalized.
pub fn validate_overlay_state(db: &Path) -> io::Result<()> {
    inspect_overlay_entry(db, false)?;
    for suffix in ["-wal", "-journal", "-shm"] {
        let mut companion = db.as_os_str().to_os_string();
        companion.push(suffix);
        inspect_overlay_entry(Path::new(&companion), true)?;
    }
    Ok(())
}

fn inspect_overlay_entry(path: &Path, companion: bool) -> io::Result<()> {
    let label = if companion {
        "overlay database companion"
    } else {
        "overlay database"
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                OverlayStateError(format!(
                    "cannot inspect {label} {}: {error}",
                    path.display()
                )),
            ))
        }
    };
    if metadata.is_file() {
        return Ok(());
    }
    let message = if !companion {
        not_regular_message(path, &metadata)
    } else if metadata.file_type().is_symlink() {
        format!(
            "{label} {} is a symlink; it must be a regular file (move the companion file into place of the link)",
            path.display()
        )
    } else if metadata.is_dir() {
        format!(
            "{label} {} is a directory, not a regular file; move it aside",
            path.display()
        )
    } else {
        format!(
            "{label} {} is not a regular file; move it aside",
            path.display()
        )
    };
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        OverlayStateError(message),
    ))
}

/// The text for an overlay database entry of the wrong type.
pub(crate) fn not_regular_message(db: &Path, metadata: &fs::Metadata) -> String {
    if metadata.is_dir() {
        format!(
            "overlay database path {} is a directory, not a database file; move it aside",
            db.display()
        )
    } else if metadata.file_type().is_symlink() {
        symlink_message(db)
    } else {
        format!(
            "overlay database {} is not a regular file; move it aside",
            db.display()
        )
    }
}

fn symlink_message(db: &Path) -> String {
    format!(
        "overlay database {} is a symlink; it must be a regular file \
         (move the database file into place of the link)",
        db.display()
    )
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

/// Open an overlay database while preserving a previously observed requirement.
///
/// Once `previously_required` is true, missing or empty records are refused
/// even when the overlay markers have disappeared. The returned handle also
/// latches any requirement observed by this acquisition.
pub fn open_overlay_db_with_required_record(
    db: &Path,
    flags: OpenFlags,
    name: DbName<'_>,
    previously_required: bool,
) -> Result<OverlayDb, OverlayDbError> {
    open_overlay_db_required(db, flags, name, previously_required)
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
    if nofollow {
        if let Ok(m) = fs::symlink_metadata(db) {
            if m.file_type().is_symlink() {
                return Err(OverlayDbError::NotRegular(not_regular_message(db, &m)));
            }
        }
    }
    let entry = crate::write_overlay::overlay_db_entry_for(db).map_err(|e| match e {
        OverlayError::Io(e) => OverlayDbError::Io(e),
        OverlayError::Msg(msg) => OverlayDbError::NotRegular(msg),
        other => OverlayDbError::Refused(other.to_string()),
    })?;
    let before = match &entry {
        DbEntry::Present { metadata, .. } => Some(metadata.clone()),
        _ => None,
    };
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
    // SQLite NOFOLLOW protects the database name, but not its companions.
    // Recheck after the classification seam, immediately before acquisition.
    if nofollow {
        validate_overlay_state(db)?;
    }
    let acquired = checked_open::open_checked(db, flags, mode, expect)
        .map_err(|refusal| acquired_error(db, refusal))?;
    // Main's additional post-open path defense remains stat-only. The
    // acquired identity, rather than this path observation, is registered.
    let opened = if nofollow {
        fs::symlink_metadata(db)
    } else {
        fs::metadata(db)
    }
    .map_err(|e| {
        OverlayDbError::NotRegular(format!(
            "overlay database {} changed while it was opened: {e}",
            db.display()
        ))
    })?;
    if !opened.is_file() {
        if nofollow {
            return Err(OverlayDbError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                OverlayStateError(not_regular_message(db, &opened)),
            )));
        }
        return Err(OverlayDbError::NotRegular(not_regular_message(db, &opened)));
    }
    if before.is_some_and(|before| !same_file(&before, &opened))
        || acquired.id.is_some_and(|id| Some(id) != file_id(&opened))
    {
        return Err(OverlayDbError::NotRegular(format!(
            "overlay database {} changed while it was opened",
            db.display()
        )));
    }
    // Only the acquired identity is registered, after SQLite's open: the
    // registry lock is never held across an open (R10-D).
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

/// Without `(dev, ino)` the type checks are all there is.
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    file_id(a) == file_id(b)
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

fn acquired_error(db: &Path, refusal: checked_open::Refusal) -> OverlayDbError {
    match refusal.error {
        AcquireError::NotRegular { .. } => {
            // Windows can observe a substituted final component in its
            // post-open pathname check. Preserve policy identity even if
            // that substitution has already been restored.
            if let Err(error) = validate_overlay_state(db) {
                return OverlayDbError::Io(error);
            }
            OverlayDbError::NotRegular(format!("overlay database {}: {refusal}", db.display()))
        }
        AcquireError::Sqlite(e)
            if e.sqlite_error().is_some_and(|error| {
                error.extended_code == rusqlite::ffi::SQLITE_CANTOPEN_SYMLINK
            }) =>
        {
            OverlayDbError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                OverlayStateError(symlink_message(db)),
            ))
        }
        AcquireError::Sqlite(e) => OverlayDbError::Sqlite(e),
        _ => OverlayDbError::Refused(format!("overlay database {}: {refusal}", db.display())),
    }
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

    /// Regression: #239 the Windows acquired-path type refusal must retain
    /// its policy cause through recovery wrappers, even if a swap is restored.
    #[test]
    fn regression_overlay_acquired_type_refusal_preserves_policy_cause() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("overlay.sqlite");
        let target = tmp.path().join("target.sqlite");
        real_db(&target);
        let before = fs::read(&target).unwrap();
        for linked in [true, false] {
            if linked {
                std::os::unix::fs::symlink(&target, &db).unwrap();
            } else {
                fs::remove_file(&db).unwrap();
                fs::copy(&target, &db).unwrap();
            }
            let error = acquired_error(
                &db,
                checked_open::Refusal {
                    error: AcquireError::NotRegular { mode: 0 },
                    retained_fd: None,
                },
            );
            let error = ratarmount_compress::commit_journal::RecoverError::Refused(error.into());
            assert!(is_overlay_state_error(&error), "{error}");
            assert!(
                error.to_string().contains(&db.display().to_string()),
                "{error}"
            );
            if linked {
                assert!(
                    error
                        .to_string()
                        .contains("is a symlink; it must be a regular file"),
                    "{error}"
                );
                assert!(fs::symlink_metadata(&db).unwrap().is_symlink());
            } else {
                assert!(error.to_string().contains("not a regular file"), "{error}");
            }
            assert_eq!(fs::read(&target).unwrap(), before);
            assert_eq!(fs::read(&db).unwrap(), before);
        }
    }

    /// Regression: #239 NOFOLLOW acquisitions refuse companion links and
    /// nonregular entries without opening aliases or changing the database.
    #[test]
    fn regression_overlay_companion_path_classification() {
        use std::os::unix::fs::symlink;
        for suffix in ["-wal", "-journal", "-shm"] {
            for shape in [
                "missing",
                "regular",
                "link",
                "empty-link",
                "dangling",
                "loop",
                "fifo",
                "directory",
            ] {
                let tmp = tempfile::tempdir().unwrap();
                let dir = tmp.path().canonicalize().unwrap();
                let db = dir.join("overlay.sqlite");
                real_db(&db);
                let before = fs::read(&db).unwrap();
                let companion = dir.join(format!("overlay.sqlite{suffix}"));
                let target = dir.join("target");
                match shape {
                    "missing" => (),
                    "regular" => fs::write(&companion, b"").unwrap(),
                    "link" | "empty-link" => {
                        fs::write(
                            &target,
                            if shape == "link" {
                                b"target bytes".as_slice()
                            } else {
                                b""
                            },
                        )
                        .unwrap();
                        symlink(&target, &companion).unwrap();
                    }
                    "dangling" => symlink(&target, &companion).unwrap(),
                    "loop" => symlink(&companion, &companion).unwrap(),
                    "fifo" => {
                        let c = std::ffi::CString::new(companion.to_str().unwrap()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                    }
                    "directory" => fs::create_dir(&companion).unwrap(),
                    _ => unreachable!(),
                }
                let target_before = fs::read(&target).ok();
                let result =
                    open_overlay_db(&db, RO | OpenFlags::SQLITE_OPEN_NOFOLLOW, DbName::Path);
                if matches!(shape, "missing" | "regular") {
                    result.unwrap();
                } else {
                    let error = result.unwrap_err();
                    assert!(is_overlay_state_error(&error), "typed acquisition refusal");
                    let error =
                        ratarmount_compress::commit_journal::RecoverError::Refused(error.into());
                    assert!(is_overlay_state_error(&error), "typed recovery refusal");
                    let error = error.to_string();
                    assert!(
                        error.contains(&companion.display().to_string()),
                        "{shape} {suffix}: {error}"
                    );
                    if matches!(shape, "link" | "empty-link" | "dangling" | "loop") {
                        assert!(
                            error.contains("is a symlink; it must be a regular file"),
                            "{shape} {suffix}: {error}"
                        );
                        assert!(fs::symlink_metadata(&companion)
                            .unwrap()
                            .file_type()
                            .is_symlink());
                    } else {
                        assert!(
                            error.contains("not a regular file"),
                            "{shape} {suffix}: {error}"
                        );
                    }
                }
                assert_eq!(
                    fs::read(&db).unwrap(),
                    before,
                    "{shape} {suffix}: database unchanged"
                );
                assert_eq!(
                    fs::read(&target).ok(),
                    target_before,
                    "{shape} {suffix}: target unchanged"
                );
                fs::remove_file(&db).unwrap();
                // Companion policy also applies to raw, unmarked directories
                // with no database, before an early-return or fresh creation.
                let validation = validate_overlay_state(&db);
                if matches!(shape, "missing" | "regular") {
                    validation.unwrap();
                } else {
                    let error = validation.unwrap_err();
                    assert!(is_overlay_state_error(&error));
                    assert!(
                        error.to_string().contains(&companion.display().to_string()),
                        "{error}"
                    );
                }
                assert!(!db.exists());
            }
        }
        // ENOTDIR is an inspection failure, never absence.
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("file");
        fs::write(&parent, b"parent").unwrap();
        let db = parent.join("overlay.sqlite");
        let error = validate_overlay_state(&db).unwrap_err();
        assert!(is_overlay_state_error(&error));
        assert!(
            error.to_string().contains(&db.display().to_string()),
            "{error}"
        );
        assert!(error.to_string().contains("Not a directory"), "{error}");
        assert_eq!(fs::read(parent).unwrap(), b"parent");
    }

    /// Regression: #239 initial NOFOLLOW and post-open type refusals must keep
    /// their policy identity through wrappers, so force cannot waive them.
    #[test]
    fn regression_overlay_nofollow_type_refusal_preserves_policy_cause() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("real.sqlite");
        real_db(&db);
        for shape in ["regular", "dangling", "loop"] {
            let link = tmp.path().join(format!("{shape}.sqlite"));
            let target = match shape {
                "regular" => db.clone(),
                "dangling" => tmp.path().join("missing.sqlite"),
                "loop" => link.clone(),
                _ => unreachable!(),
            };
            std::os::unix::fs::symlink(target, &link).unwrap();
            let error = open_overlay_db(&link, RO | OpenFlags::SQLITE_OPEN_NOFOLLOW, DbName::Path)
                .unwrap_err();
            assert!(
                matches!(&error, OverlayDbError::NotRegular(_)),
                "generic error shape retained"
            );
            assert!(
                error
                    .to_string()
                    .contains("is a symlink; it must be a regular file"),
                "{error}"
            );
            assert!(
                is_overlay_state_error(&error),
                "direct refusal must remain policy"
            );
            let error = io::Error::from(error);
            assert!(
                is_overlay_state_error(&error),
                "I/O conversion must retain policy"
            );
        }
        let error = OverlayError::from(OverlayDbError::NotRegular("type changed".into()));
        assert!(
            is_overlay_state_error(&error),
            "overlay conversion must retain policy"
        );
        // The generic caller's opt-in contract remains unchanged.
        open_overlay_db(&tmp.path().join("regular.sqlite"), RO, DbName::Path).unwrap();
    }

    /// Regression: #239 regular WAL/SHM and rollback journals remain usable;
    /// validation cannot close an alias and release a held SQLite lock.
    #[test]
    fn regression_overlay_companions_preserve_hot_journal_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().canonicalize().unwrap().join("overlay.sqlite");
        real_db(&db);
        let holder = Connection::open(&db).unwrap();
        holder
            .execute_batch("PRAGMA journal_mode=WAL; INSERT INTO t VALUES (7)")
            .unwrap();
        let companion = |suffix: &str| {
            let mut path = db.as_os_str().to_os_string();
            path.push(suffix);
            std::path::PathBuf::from(path)
        };
        assert!(fs::metadata(companion("-wal")).unwrap().len() > 0);
        assert!(fs::metadata(companion("-shm")).unwrap().len() > 0);
        let opened =
            open_overlay_db(&db, RO | OpenFlags::SQLITE_OPEN_NOFOLLOW, DbName::Path).unwrap();
        assert_eq!(
            opened
                .query_row("SELECT x FROM t", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            7
        );
        drop(opened);
        drop(holder);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "overlay_db::tests::hot_journal_writer_child",
                "--nocapture",
            ])
            .env("RATARMOUNT_TEST_HOT_JOURNAL", &db)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(fs::metadata(companion("-journal")).unwrap().len() > 0);
        let opened = open_overlay_db(
            &db,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            DbName::Path,
        )
        .unwrap();
        assert_eq!(
            opened
                .query_row("SELECT count(*) FROM t", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(!companion("-journal").exists(), "hot journal recovered");
    }

    #[test]
    fn hot_journal_writer_child() {
        let Some(db) = std::env::var_os("RATARMOUNT_TEST_HOT_JOURNAL") else {
            return;
        };
        let conn = Connection::open(db).unwrap();
        conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA cache_size=1; BEGIN IMMEDIATE; INSERT INTO t SELECT zeroblob(1000000)").unwrap();
        // Simulate a crashed writer without dropping its SQLite connection.
        std::process::exit(0);
    }

    /// Regression: the established three-argument API keeps its optional
    /// incoming requirement; the explicit required wrapper refuses creation.
    #[test]
    fn regression_open_overlay_db_default_requirement_is_optional() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let default = dir.join("default.sqlite");
        let explicit_optional = dir.join("optional.sqlite");
        let explicit_required = dir.join("required.sqlite");
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
        for (path, opened) in [
            (&default, open_overlay_db(&default, flags, DbName::Path)),
            (
                &explicit_optional,
                open_overlay_db_with_required_record(
                    &explicit_optional,
                    flags,
                    DbName::Path,
                    false,
                ),
            ),
        ] {
            let opened = opened.unwrap();
            assert!(!opened.required_record(), "{}", path.display());
            assert_eq!(opened.id(), file_id(&fs::metadata(path).unwrap()));
            assert_eq!(fs::metadata(path).unwrap().len(), 0);
        }
        let error =
            open_overlay_db_with_required_record(&explicit_required, flags, DbName::Path, true)
                .unwrap_err();
        assert!(error.to_string().contains("required earlier"), "{error}");
        assert!(
            !explicit_required.exists(),
            "required acquisition must not create a record"
        );

        // An optional incoming default still raises a requirement observed
        // from the overlay's current marker.
        let marked = dir.join(crate::HIDDEN_DB);
        real_db(&marked);
        fs::write(dir.join(crate::OVERLAY_MARKER), b"").unwrap();
        assert!(open_overlay_db(&marked, RO, DbName::Path)
            .unwrap()
            .required_record());
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
        // Unmarked and never required: created fresh.
        let fresh = open_overlay_db(&hidden, OpenFlags::default(), DbName::Path).unwrap();
        assert!(!fresh.required_record());
        assert_eq!(fresh.id(), file_id(&fs::metadata(&hidden).unwrap()));
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
}
