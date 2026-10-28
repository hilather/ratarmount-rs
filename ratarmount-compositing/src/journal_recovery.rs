//! One roll-forward for every commit-journal recovery.
//!
//! A COMPLETE commit journal means the archive already holds the new bytes. The
//! overlay's recorded base stamp then describes the pre-commit bytes and the
//! next identity gate would refuse the archive recovery just produced. Every
//! recovery (offline, mount, live and on-exit commits, and a fresh replacement
//! about to unlink its own journal) therefore goes through the functions here:
//! the `before_unlink` hook restamps the rows from the LOCKED descriptor's final
//! stamp, and marks a strong digest `pending`, BEFORE the journal is unlinked.
//! A hook that fails keeps the journal, so no ordering leaves "journal gone,
//! rows stale".
//!
//! This is the only module that names the commit journal's recovery,
//! replacement and copy-guard entry points (`clippy.toml` forbids them
//! elsewhere): every caller says WHO may apply a journal ([`Owner`]) and a
//! replacement or copy goes through the wrappers below.

use std::cell::Cell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use ratarmount_compress::commit_journal::{
    self, Applied, PendingJournal, RecoverError, ReplaceError,
};
use rusqlite::Connection;

use crate::write_overlay::{DbEntry, OverlayError, Result};

use crate::overlay_gate::{kind_only, Recorded};
use crate::overlay_meta::OverlayMeta;
use crate::ClassifiedBase;

/// Who may apply a pending journal. Decided under the archive lock, on the
/// header read there and the locked descriptor's metadata.
pub enum Owner<'a> {
    /// A `-w` overlay committing to (or recovering) the base it recorded: the
    /// journal must be the locked file's own AND agree with the record (the
    /// commit gate on the locked file).
    Recorded {
        base: &'a ClassifiedBase,
        archive: &'a Path,
        record: Record<'a>,
    },
    /// A mount: every readable overlay record votes (R7-A1).
    Mount {
        records: &'a MountRecords,
        member: &'a Path,
    },
    /// No overlay record applies (a raw overlay directory, the library and
    /// factory openers, rolling members, `--lower`-only mounts): the journal
    /// must have been started for the locked inode.
    Inode,
    /// Mount identity gates already admitted these records; retain their named
    /// state policy while applying only the locked inode's own journal.
    AdmittedMount { records: &'a MountRecords },
    /// The user's explicit `--force-*` flag: any journal.
    Forced,
    /// A test authorizer.
    #[cfg(test)]
    Test(commit_journal::Authorize<'a>),
}

/// Where a [`Owner::Recorded`] overlay's record is read.
pub enum Record<'a> {
    /// The mount's own connection (it holds its database exclusively).
    Live(&'a Mutex<Connection>),
    /// The overlay directory, read-only.
    Offline(&'a Path),
}

impl Owner<'_> {
    fn authorize(&mut self, header: &PendingJournal, locked: &fs::Metadata) -> io::Result<()> {
        let refusal = |r: crate::overlay_gate::CommitBaseRefusal| r.into_io();
        match self {
            Owner::Recorded {
                base,
                archive,
                record: Record::Live(db),
            } => crate::overlay_gate::check_commit_base_with(
                &db.lock().unwrap_or_else(|e| e.into_inner()),
                base,
                archive,
                Some((header, locked)),
                true,
            )
            .map(drop)
            .map_err(refusal),
            Owner::Recorded {
                base,
                archive,
                record: Record::Offline(dir),
            } => crate::overlay_gate::check_commit_base_offline_with(
                dir,
                base,
                archive,
                Some((header, locked)),
            )
            .map(drop)
            .map_err(refusal),
            Owner::Mount { records, member } => {
                authorize_mount_recovery(records, member, header, locked)
            }
            Owner::Inode | Owner::AdmittedMount { .. } => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "Owner::Inode is the reviewed authority for applying the locked inode's own journal"
                )]
                let result = commit_journal::authorize_owned(header, locked);
                result
            }
            Owner::Forced => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "Owner::Forced represents the caller's explicit force flag"
                )]
                let result = commit_journal::authorize_forced(header, locked);
                result
            }
            #[cfg(test)]
            Owner::Test(authorize) => authorize(header, locked),
        }
    }
}

/// Which restamp rule applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Restamp {
    /// A recovery: only a journal started on the recorded stamp moves the
    /// baseline; a journal started on another state never does.
    Recovery,
    /// The commit that wrote the journal: the new stamp is the new baseline.
    Commit,
}

/// Where the rows live.
pub(crate) enum Rows<'a> {
    None,
    /// A mount's own connection, on the database file `id` in `dir`.
    Shared {
        db: &'a Mutex<Connection>,
        dir: &'a Path,
        id: Option<(u64, u64)>,
    },
    /// An overlay database opened (read-write, never created) when the hook
    /// runs. A raw overlay directory has none: nothing to restamp. Two
    /// monotonic flags (R10-B), set from every classification of the
    /// directory and never cleared: `must_exist` once a database was seen,
    /// `required_files` once a marker was seen (the record must then have a
    /// `files` table).
    Path {
        db: &'a Path,
        must_exist: Cell<bool>,
        required_files: Cell<bool>,
    },
}

/// The database `db`'s overlay directory.
fn db_dir(db: &Path) -> &Path {
    db.parent().unwrap_or(Path::new("."))
}

/// A classification of an overlay directory that is not a usable record, as
/// the `io::Error` recovery refuses with.
fn usable_entry(dir: &Path) -> io::Result<DbEntry> {
    match classify(dir) {
        Err(error) if crate::overlay_db::is_overlay_state_error(&error) => Err(error),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("the overlay record in {} cannot be classified: {error}; no recovery write was made", dir.display()),
        )),
        Ok(DbEntry::Lost { markers, .. }) => Err(io::Error::other(
            crate::write_overlay::lost_record_error(dir, &markers).to_string(),
        )),
        Ok(entry) => Ok(entry),
    }
}

/// The refusal of a database seen earlier in this recovery and gone now.
fn vanished(db: &Path) -> io::Error {
    io::Error::other(format!(
        "overlay database {} disappeared while a journal was being recovered (it existed \
         when recovery was authorized); no recovery write was made after that and the \
         journal is kept",
        db.display()
    ))
}

/// A used overlay's database `db` still has its `files` table (read-only).
fn require_files(db: &Path) -> io::Result<()> {
    let result = (|| {
        let conn = crate::overlay_db::open_overlay_db_required(
            db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            crate::DbName::Path,
            true,
        )
        .map_err(io::Error::from)?;
        // Under the archive lock: never wait on another holder of the database
        // (as `read_with`).
        conn.busy_timeout(Duration::ZERO)
            .map_err(|e| io::Error::other(format!("cannot read {}: {e}", db.display())))?;
        match crate::overlay_meta::has_files_table(&conn) {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::other(format!(
                "{}: {}; no recovery write was made",
                db.display(),
                crate::overlay_meta::NO_FILES_TABLE
            ))),
            Err(error) if crate::overlay_db::is_overlay_state_error(&error) => {
                Err(io::Error::other(error))
            }
            Err(e) => Err(io::Error::other(format!(
                "cannot read {}: {e}",
                db.display()
            ))),
        }
    })();
    result.or_else(|error| {
        ratarmount_index::checked_open::refuse_symlink(
            db,
            rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(io::Error::other)?;
        Err(error)
    })
}

/// Strict named-state admission before the generic followed classification.
fn classify(dir: &Path) -> io::Result<DbEntry> {
    crate::overlay_db::validate_overlay_state(&dir.join(crate::HIDDEN_DB))?;
    crate::write_overlay::overlay_db_entry(dir).map_err(|e| match e {
        OverlayError::Io(e) => e,
        other => io::Error::other(other.to_string()),
    })
}

/// A live record (a mount's own database `id` in `dir`) is still that file.
fn check_live(dir: &Path, id: Option<(u64, u64)>) -> io::Result<()> {
    match usable_entry(dir)? {
        DbEntry::Present { metadata, .. } => {
            if id.is_some() && crate::overlay_db::file_id(&metadata) != id {
                return Err(io::Error::other(format!(
                    "the overlay database in {} was replaced while the overlay is mounted; \
                     no recovery write was made",
                    dir.display()
                )));
            }
            Ok(())
        }
        _ => Err(io::Error::other(format!(
            "the overlay database in {} disappeared while the overlay is mounted; no \
             recovery write was made",
            dir.display()
        ))),
    }
}

#[cfg(test)]
thread_local! {
    /// After Rows' outer classification, immediately before its inner open.
    static BEFORE_INNER_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

impl<'a> Rows<'a> {
    /// [`Rows::Path`] for `db`, its flags seeded from a classification now.
    pub(crate) fn path(db: &'a Path) -> Self {
        let rows = Rows::Path {
            db,
            must_exist: Cell::new(false),
            required_files: Cell::new(false),
        };
        if let Ok(entry) = classify(db_dir(db)) {
            rows.observe(&entry);
        }
        rows
    }

    /// Raise [`Rows::Path`]'s flags from a classification.
    fn observe(&self, entry: &DbEntry) {
        if let Rows::Path {
            must_exist,
            required_files,
            ..
        } = self
        {
            match entry {
                DbEntry::Present { marked, .. } => {
                    must_exist.set(true);
                    if *marked {
                        required_files.set(true);
                    }
                }
                DbEntry::Lost { .. } => required_files.set(true),
                DbEntry::Absent => {}
            }
        }
    }

    /// Check named state without acquiring a second descriptor or SQLite lock.
    fn validate_state(&self) -> io::Result<()> {
        match self {
            Rows::None => Ok(()),
            Rows::Shared { dir, .. } => {
                crate::overlay_db::validate_overlay_state(&dir.join(crate::HIDDEN_DB))
            }
            Rows::Path { db, .. } => crate::overlay_db::validate_overlay_state(db),
        }
    }

    /// The guard half for the rows (under the archive lock, before any
    /// recovery write): the rows' directory must not be a lost or
    /// unclassifiable record, and a mount's own database must still be the
    /// file it opened.
    pub(crate) fn guard(&self) -> io::Result<()> {
        self.validate_state()?;
        match self {
            Rows::None => Ok(()),
            Rows::Shared { dir, id, .. } => check_live(dir, *id),
            Rows::Path {
                db,
                must_exist,
                required_files,
            } => {
                let dir = db_dir(db);
                let entry = usable_entry(dir)?;
                self.observe(&entry);
                match entry {
                    // Seen before, gone now (database and marker both
                    // removed): refuse here, before the first recovery write,
                    // not only in `with` after it.
                    DbEntry::Absent if must_exist.get() || required_files.get() => {
                        Err(vanished(db))
                    }
                    DbEntry::Present { .. } if required_files.get() => require_files(db),
                    _ => Ok(()),
                }
            }
        }
    }

    /// Run `f` on the rows' connection with whether the record must have a
    /// `files` table. The rows are re-classified first (R10-B): a record lost,
    /// replaced or unclassifiable since the guard fails the hook, which keeps
    /// the journal.
    pub(crate) fn with(
        &self,
        f: impl FnOnce(&Connection, bool) -> io::Result<()>,
    ) -> io::Result<()> {
        let result = (|| {
            self.validate_state()?;
            match self {
                Rows::None => Ok(()),
                Rows::Shared { db, dir, id } => {
                    check_live(dir, *id)?;
                    f(&db.lock().unwrap_or_else(|e| e.into_inner()), true)
                }
                Rows::Path {
                    db,
                    must_exist,
                    required_files,
                } => {
                    let dir = db_dir(db);
                    let entry = usable_entry(dir)?;
                    self.observe(&entry);
                    if let DbEntry::Absent = entry {
                        if must_exist.get() || required_files.get() {
                            return Err(vanished(db));
                        }
                        // A raw overlay directory: nothing to restamp.
                        return Ok(());
                    }
                    // The latch goes into the acquisition (a required record
                    // must be the non-empty file classified) and comes back.
                    #[cfg(test)]
                    {
                        let hook = BEFORE_INNER_OPEN.with(|h| h.borrow_mut().take());
                        if let Some(hook) = hook {
                            hook();
                        }
                    }
                    crate::overlay_db::validate_overlay_state(db)?;
                    let conn = crate::overlay_db::open_overlay_db_required(
                        db,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
                        crate::DbName::Path,
                        required_files.get(),
                    )
                    .map_err(io::Error::from)?;
                    if conn.required_record() {
                        required_files.set(true);
                    }
                    f(&conn, required_files.get())
                }
            }
        })();
        result.or_else(|error| {
            let db = match self {
                Rows::None => return Err(error),
                Rows::Shared { dir, .. } => dir.join(crate::HIDDEN_DB),
                Rows::Path { db, .. } => db.to_path_buf(),
            };
            ratarmount_index::checked_open::refuse_symlink(
                &db,
                rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(io::Error::other)?;
            Err(error)
        })
    }

    /// The `before_unlink` hook of the commit that wrote the journal
    /// (`Restamp::Commit`): the new stamp is the new baseline.
    pub(crate) fn commit_hook<'h>(
        &'h self,
        archive: &'h Path,
    ) -> impl FnMut(&Applied) -> io::Result<()> + 'h {
        move |applied| {
            self.with(|conn, required| {
                restamp_rows(conn, archive, applied, Restamp::Commit, required)
            })
        }
    }
}

/// The journal's pre-commit stamp is the recorded one, or the rows already
/// describe the file recovery will leave and only the unlink is owed: the
/// committed bytes (a complete journal) or the rolled-back bytes whose mtime
/// could not be restored (a torn journal whose old bytes are in place).
pub fn journal_agrees(
    recorded: (u64, i128),
    current: (u64, i128),
    journal: &PendingJournal,
) -> bool {
    (journal.len, journal.mtime_ns) == recorded
        || (journal.complete && current.0 == journal.new_len && current == recorded)
        || (!journal.complete && current.0 == journal.len && current == recorded)
}

fn busy(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

/// Does the record name `canonical` as its base archive?
fn names(meta: &OverlayMeta, canonical: &Path) -> bool {
    let local = meta.get("base_local_path").map(Path::new) == Some(canonical);
    let located = meta.get("base_location") == Some(&format!("local:{}", canonical.display()));
    (local || located) && meta.get("base_kind").is_none_or(|kind| kind == "archive")
}

/// THE target rule: a journal on the file `file` (its CURRENT `(dev, ino)`:
/// the locked descriptor's, or a stat of the member) opened through
/// `canonical` is the recorded base's journal when the record names
/// `canonical`, or when the recorded base's local path resolves to that very
/// file (a hard link or another name of it; device AND inode, never the inode
/// alone). Ownership is never inferred from stamps: a base that left its
/// recorded place (a renamed directory, a replaced name) is not the target,
/// and its journal is left to the gate (Astra v4 F2, F3).
pub(crate) fn journal_targets_record(
    meta: &OverlayMeta,
    canonical: &Path,
    file: (u64, u64),
) -> bool {
    if names(meta, canonical) {
        return true;
    }
    if !meta.get("base_kind").is_none_or(|kind| kind == "archive") {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.get("base_local_path")
            .and_then(|path| fs::metadata(path).ok())
            .is_some_and(|base| (base.dev(), base.ino()) == file)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        false
    }
}

/// Write the stamp recovery (or the commit) produced into the overlay's rows.
///
/// The rows are never derived from a path: `applied` carries the LOCKED
/// descriptor's final `(len, mtime_ns, dev, ino)`. The archive name (symlinks
/// followed: the RESOLVED target) must still resolve to that inode, else the
/// rows are left as they were and the hook fails, which keeps the journal.
pub(crate) fn restamp_rows(
    conn: &Connection,
    archive: &Path,
    applied: &Applied,
    mode: Restamp,
    required: bool,
) -> io::Result<()> {
    let target = fs::metadata(archive)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (target.dev(), target.ino()) != (applied.dev, applied.ino) {
            return Err(io::Error::other(format!(
                "{} no longer names the file recovery locked; rows left as they were",
                archive.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = target;
    let canonical = archive.canonicalize()?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(io::Error::other)?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        match restamp_once(conn, &canonical, applied, mode, required) {
            Err(RestampError::Busy(_)) if attempt < 3 => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(RestampError::Busy(e) | RestampError::Other(e)) => return Err(e),
            Ok(()) => return Ok(()),
        }
    }
}

enum RestampError {
    Busy(io::Error),
    Other(io::Error),
}

fn restamp_once(
    conn: &Connection,
    canonical: &Path,
    applied: &Applied,
    mode: Restamp,
    required: bool,
) -> std::result::Result<(), RestampError> {
    let classify = |e: rusqlite::Error| {
        if busy(&e) {
            RestampError::Busy(io::Error::other(e))
        } else {
            RestampError::Other(io::Error::other(e))
        }
    };
    conn.execute_batch("BEGIN IMMEDIATE").map_err(classify)?;
    let result = (|| -> std::result::Result<(), RestampError> {
        // A used overlay's record must be there (R10-B): an emptied or
        // replaced database would otherwise read as "unrecorded" and the
        // journal would be unlinked with the rows never restamped. Plain SQL
        // inside this transaction: no nested BEGIN.
        if required && !crate::overlay_meta::has_files_table(conn).map_err(classify)? {
            return Err(RestampError::Other(io::Error::other(format!(
                "{}; the rows were not restamped and the journal is kept",
                crate::overlay_meta::NO_FILES_TABLE
            ))));
        }
        let meta = OverlayMeta::from_connection(conn)
            .map_err(|e| RestampError::Other(io::Error::other(e)))?;
        // A journal whose target is not the recorded base (a union member, a
        // base that left its recorded place), a kind-only record and a record
        // without a stamp leave the rows alone.
        let Some(meta) = meta else {
            return Ok(());
        };
        if !journal_targets_record(&meta, canonical, (applied.dev, applied.ino)) || kind_only(&meta)
        {
            return Ok(());
        }
        let (Some(size), Some(mtime)) = (meta.get("base_size"), meta.get("base_mtime_ns")) else {
            return Ok(());
        };
        let other = |e: OverlayError| RestampError::Other(io::Error::other(e.to_string()));
        let final_size = applied.final_len.to_string();
        let final_mtime = applied.final_mtime_ns.to_string();
        // The journal was started on the recorded state.
        let started =
            applied.pre_len.to_string() == size && applied.pre_mtime_ns.to_string() == mtime;
        let stamp = [
            ("base_size", final_size.as_str()),
            ("base_mtime_ns", final_mtime.as_str()),
        ];
        let weak = format!("weak:size={final_size},mtime_ns={final_mtime}");
        if !applied.rolled_forward {
            // A rollback restored the recorded bytes under a lock never
            // released; only an mtime it could not restore (EPERM for a
            // non-owner) can differ. The rows follow it only when the journal
            // was started on the recorded state (a forced attempt over another
            // file never moves the baseline); a strong digest still names the
            // restored bytes.
            if applied.final_len != applied.pre_len {
                return Err(RestampError::Other(io::Error::other(format!(
                    "a rollback ended at {} bytes, not the {} it restores; rows left as they were",
                    applied.final_len, applied.pre_len
                ))));
            }
            if applied.final_mtime_ns == applied.pre_mtime_ns || !started {
                return Ok(());
            }
            OverlayMeta::set_many(conn, &stamp).map_err(other)?;
            if meta.base_digest_kind() == Some("weak") {
                OverlayMeta::set_many(conn, &[("base_digest", weak.as_str())]).map_err(other)?;
            }
            return Ok(());
        }
        // A roll-forward. A recovery of a journal started on another state
        // leaves the rows (unless they already describe the committed bytes).
        if mode == Restamp::Recovery && !started && (size != final_size || mtime != final_mtime) {
            return Ok(());
        }
        OverlayMeta::set_many(conn, &stamp).map_err(other)?;
        // The recorded digest names the PRE-commit bytes, also when the stamp
        // did not change (an equal-length, equal-mtime commit, or relocation
        // rows written before this recovery). A weak one is the stamp itself;
        // a strong one is marked `pending` (never cleared) and resolved lazily
        // by seal, diff, pack or grading, so mounting stays fast.
        let digest = match meta.base_digest_kind() {
            Some("weak") => OverlayMeta::set_many(conn, &[("base_digest", weak.as_str())]),
            Some("strong") => OverlayMeta::set_many(
                conn,
                &[("base_digest", ""), ("base_digest_kind", "pending")],
            )
            .and_then(|()| OverlayMeta::remove(conn, "stack_digest")),
            _ => Ok(()),
        };
        digest.map_err(|e| RestampError::Other(io::Error::other(e.to_string())))
    })();
    match result {
        Ok(()) => conn.execute_batch("COMMIT").map_err(classify),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Recover the journal pending for `archive` and restamp `rows` from the locked
/// descriptor before the journal is unlinked (`Restamp::Recovery`).
pub(crate) fn recover_journal(
    archive: &Path,
    rows: Rows<'_>,
    owner: Owner<'_>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    recover_journal_with_records(archive, rows, owner, None)
}

/// A live mount also retains the named policy of already-admitted directory
/// lowers, independently of its held connection and recovery authorization.
pub(crate) fn recover_journal_with_records(
    archive: &Path,
    rows: Rows<'_>,
    mut owner: Owner<'_>,
    admitted: Option<&MountRecords>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    let mut records: Vec<PathBuf> = match &owner {
        Owner::Mount { records, .. } | Owner::AdmittedMount { records } => records
            .top
            .iter()
            .chain(records.lowers.iter())
            .cloned()
            .collect(),
        Owner::Recorded {
            record: Record::Offline(dir),
            ..
        } => vec![dir.to_path_buf()],
        _ => Vec::new(),
    };
    if let Some(admitted) = admitted {
        records.extend(admitted.lowers.iter().cloned());
    }
    // A held connection must never be re-opened through an alias as a probe:
    // closing that alias could release this process's SQLite POSIX locks.
    let live_path = match &owner {
        Owner::Recorded {
            record: Record::Live(db),
            ..
        } => db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .path()
            .map(PathBuf::from),
        _ => None,
    };
    let validate = || -> io::Result<()> {
        for dir in &records {
            crate::overlay_db::validate_overlay_state(&dir.join(crate::HIDDEN_DB))?;
        }
        if let Some(path) = &live_path {
            crate::overlay_db::validate_overlay_state(path)?;
        }
        if let Some(top) = admitted.and_then(|records| records.top.as_ref()) {
            crate::overlay_db::validate_overlay_state(&top.join(crate::HIDDEN_DB))?;
        }
        rows.validate_state()
    };
    // Even no-journal recovery returns only after every supplied named state
    // has been checked; force and inode ownership cannot bypass this policy.
    validate().map_err(RecoverError::Refused)?;
    let mut before_write = || {
        validate()?;
        for dir in &records {
            read_record(dir)?;
        }
        rows.guard()
    };
    let mut authorize =
        |header: &PendingJournal, locked: &fs::Metadata| owner.authorize(header, locked);
    #[expect(
        clippy::disallowed_methods,
        reason = "The compositing recovery owner supplies authorization, row guards and the before-unlink restamp"
    )]
    let recovered = commit_journal::recover_guarded(
        archive,
        &mut before_write,
        &mut authorize,
        &mut |applied| {
            validate()?;
            rows.with(|conn, required| {
                restamp_rows(conn, archive, applied, Restamp::Recovery, required)
            })
        },
    );
    recovered
}

/// [`recover_journal`] for callers that hold no overlay: the library and mount
/// openers, offline commits. Every supplied database and companion name is
/// checked before journal classification, including when no journal is pending.
/// A database is acquired read-write, without creation, only for restamping.
pub fn recover_journal_at(
    archive: &Path,
    overlay_db: Option<&Path>,
    owner: Owner<'_>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    if let Some(db) = overlay_db {
        crate::overlay_db::validate_overlay_state(db).map_err(RecoverError::Refused)?;
    }
    // Opened only when a roll-forward needs to restamp: a mount with no pending
    // journal never touches the overlay database here.
    let rows = overlay_db.map_or(Rows::None, Rows::path);
    recover_journal(archive, rows, owner)
}

/// The journal rule an offline open owes a base. Journals are never applied
/// here — recovery is a mount's or a commit's write — but the states a
/// recovery would refuse stay refused, read-only: a pending journal that was
/// started for the file `member` resolves to now, or an active/complete
/// locator whose journal is missing or moved. A prepare/done locator without
/// its journal (nothing was replaced / the commit finished; mounts clear or
/// tolerate those) and a journal naming another inode are not refused.
#[doc(hidden)] // cross-crate seam for ratarmount's offline classification; not public API
pub fn check_offline_journal(member: &Path) -> io::Result<()> {
    let (pending, missing) = commit_journal::offline_journal_probe(member)?;
    if let Some(journal) = pending {
        if owns(&journal, member) {
            return Err(io::Error::other(format!(
                "{} carries a pending commit journal from an interrupted commit; recover it \
                     first (`ratarmount --no-mount {}` rolls the interrupted append back or \
                     forward)",
                member.display(),
                member.display()
            )));
        }
    }
    if let Some((phase, path)) = missing {
        return Err(io::Error::other(format!(
            "{} carries a {phase} commit-journal locator but its journal {} is missing or \
                 moved; recover it through the archive's current directory name, or verify the \
                 archive and remove its user.ratarmount.commit-journal xattr (setfattr -x on \
                 Linux, xattr -d on macOS)",
            member.display(),
            path.display()
        )));
    }
    Ok(())
}

/// `verify`'s journal rule: the archive at `path` carries its OWN pending
/// journal (started for this very inode) that agrees with the record, which
/// names `path`. The stamp then differs only because recovery has not run yet.
/// Never applies to a base at another place: the record must name `path`.
pub(crate) fn own_pending_journal_agrees(
    meta: &OverlayMeta,
    path: &Path,
    current: (u64, i128),
) -> bool {
    let (Ok(canonical), Some(size), Some(mtime)) = (
        path.canonicalize(),
        meta.get("base_size").and_then(|v| v.parse::<u64>().ok()),
        meta.get("base_mtime_ns")
            .and_then(|v| v.parse::<i128>().ok()),
    ) else {
        return false;
    };
    if !fs::metadata(&canonical)
        .is_ok_and(|m| journal_targets_record(meta, &canonical, file_id(&m)))
    {
        return false;
    }
    let Ok(Some(journal)) = commit_journal::pending(&canonical) else {
        return false;
    };
    owns(&journal, &canonical) && journal_agrees((size, mtime), current, &journal)
}

/// The journal was started for the file `path` resolves to, by inode only:
/// the journal's device number is a hint (it changes across reboots, see
/// `regression_journal_dev_change_is_not_a_refusal`). Read-only; only `verify`
/// uses it, after its own device and inode check of the recorded target.
fn owns(journal: &PendingJournal, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).is_ok_and(|m| m.ino() == journal.ino)
    }
    #[cfg(not(unix))]
    {
        let _ = (journal, path);
        false
    }
}

// ---- mount-time classification (R7-A1) -------------------------------------

/// What a mount knows about the overlay records that vote on a member's journal.
#[derive(Clone, Debug, Default)]
pub struct MountRecords {
    /// The `-w` overlay directory (its database is the top record).
    pub top: Option<std::path::PathBuf>,
    /// Every `--lower` that is a directory (each holds a sealed record).
    pub lowers: Vec<std::path::PathBuf>,
    /// A `--lower` is a bundle file: its record is readable only after the
    /// mount unpacks it, so it cannot vote yet.
    pub bundles: bool,
}

/// The decision for one member's pending journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountJournal {
    /// No journal is pending (a stale locator may still be cleared).
    None,
    /// Every readable record abstains or agrees: recover before any gate.
    Own,
    /// Some record does not own it: no write until every gate has decided.
    Deferred {
        complete: bool,
        why: String,
        force_flag: &'static str,
    },
}

/// Read a record only after its database and every companion passed the
/// strict named-state policy, including an otherwise unmarked raw directory.
fn read_record(dir: &Path) -> io::Result<Option<OverlayMeta>> {
    crate::overlay_db::validate_overlay_state(&dir.join(crate::HIDDEN_DB))?;
    let marked = match usable_entry(dir)? {
        DbEntry::Absent => return Ok(None),
        DbEntry::Present { marked, .. } => marked,
        _ => true,
    };
    OverlayMeta::read_no_recovery_required(dir, marked).map_err(|error| match error {
        OverlayError::Io(error) => error,
        other => io::Error::other(other),
    })
}

/// The decision table on the journal header and the file's current identity.
/// `current` is `((dev, ino), len, mtime_ns)`.
fn decide(
    records: &MountRecords,
    canonical: &Path,
    journal: &PendingJournal,
    current: ((u64, u64), u64, i128),
) -> io::Result<MountJournal> {
    if journal.ino != current.0 .1 {
        return Err(io::Error::other(format!(
            "{} carries a commit journal that was started for another file \
             (journal inode {}, archive inode {}); the journal was not applied",
            canonical.display(),
            journal.ino,
            current.0 .1
        )));
    }
    let defer = |why: String, flag: &'static str| MountJournal::Deferred {
        complete: journal.complete,
        why,
        force_flag: flag,
    };
    if records.bundles {
        return Ok(defer(
            "a --lower bundle's record is read after unpacking".into(),
            "--force-stack-mismatch",
        ));
    }
    let voters = records
        .top
        .iter()
        .map(|d| (d, true))
        .chain(records.lowers.iter().map(|d| (d, false)));
    for (dir, is_top) in voters {
        let flag = if is_top {
            "--force-base-mismatch"
        } else {
            "--force-stack-mismatch"
        };
        let meta = match read_record(dir) {
            Ok(meta) => meta,
            Err(e) => {
                // Path policy outranks journal deferral: force cannot turn a
                // typed acquisition/metadata refusal into recovery authority.
                if crate::overlay_db::is_overlay_state_error(&e) {
                    return Err(e);
                }
                return Ok(defer(
                    format!(
                        "has an overlay record ({}) that cannot be read: {e}",
                        dir.display()
                    ),
                    flag,
                ));
            }
        };
        let Some(meta) = meta else { continue };
        if is_top && meta.layer_sealed() {
            return Ok(defer("is guarded by a sealed overlay".into(), flag));
        }
        match Recorded::from_meta(Some(&meta)) {
            Recorded::Unrecorded | Recorded::Nothing => continue,
            Recorded::Unknown => {
                return Ok(defer(
                    "has an overlay record with no usable base kind".into(),
                    flag,
                ))
            }
            Recorded::Kind { .. } => {}
        }
        if !journal_targets_record(&meta, canonical, current.0) {
            return Ok(defer("is not the base this overlay recorded".into(), flag));
        }
        if kind_only(&meta) {
            continue;
        }
        let (Some(size), Some(mtime)) = (
            meta.get("base_size").and_then(|v| v.parse::<u64>().ok()),
            meta.get("base_mtime_ns")
                .and_then(|v| v.parse::<i128>().ok()),
        ) else {
            continue;
        };
        if !journal_agrees((size, mtime), (current.1, current.2), journal) {
            return Ok(defer(
                format!(
                    "carries a commit journal that was not started for the recorded base \
                     (it rolls back to size={},mtime_ns={}; size={size},mtime_ns={mtime} recorded)",
                    journal.len, journal.mtime_ns
                ),
                flag,
            ));
        }
    }
    Ok(MountJournal::Own)
}

fn file_id(meta: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        (0, 0)
    }
}

fn current_identity(meta: &fs::Metadata) -> ((u64, u64), u64, i128) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            file_id(meta),
            meta.len(),
            i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        )
    }
    #[cfg(not(unix))]
    {
        (file_id(meta), meta.len(), 0)
    }
}

/// Read-only: the pending journal of `member` and every readable record. Never
/// recovers and never rolls an overlay database's own journal back.
pub fn classify_mount_journal(records: &MountRecords, member: &Path) -> io::Result<MountJournal> {
    let Some(journal) = commit_journal::pending(member)? else {
        return Ok(MountJournal::None);
    };
    let canonical = member.canonicalize()?;
    let metadata = fs::metadata(member)?;
    decide(records, &canonical, &journal, current_identity(&metadata))
}

/// The same table on the header read under the archive lock and the locked
/// descriptor's metadata: `Ok(())` only for [`MountJournal::Own`].
pub fn authorize_mount_recovery(
    records: &MountRecords,
    member: &Path,
    locked: &PendingJournal,
    file: &fs::Metadata,
) -> io::Result<()> {
    let canonical = member.canonicalize()?;
    match decide(records, &canonical, locked, current_identity(file))? {
        MountJournal::None | MountJournal::Own => Ok(()),
        MountJournal::Deferred { why, .. } => Err(io::Error::other(format!(
            "{} {why}; its commit journal changed while the mount classified it, retry",
            member.display()
        ))),
    }
}

// ---- a failed replacement, and the copy fallback (R7-C3) ------------------

/// What a failed journaled replacement leaves its caller to do. Decided once,
/// here, from the attempt's own [`ReplaceError`]: no caller re-runs recovery.
#[derive(Debug)]
pub(crate) struct FailedReplace {
    pub(crate) error: OverlayError,
    /// Nothing of the attempt remains: in `Auto` mode a copy fallback may run
    /// (through [`open_copy_source`] and [`publish_over`]).
    pub(crate) may_copy: bool,
    /// This attempt itself rolled back under its lock (its ctime, and
    /// possibly its mtime, moved): the stamp the locked descriptor had after
    /// the cleanup, which the copy source must then still be exactly.
    /// Otherwise (`None`) the archive must still be exactly the gate's
    /// snapshot ([`CopyFrom`]).
    pub(crate) rolled_back: Option<Box<fs::Metadata>>,
    /// The archive holds the new bytes, or this attempt's journal is still on
    /// disk: a live mount stops committing until it is remounted.
    pub(crate) base_unusable: bool,
}

impl From<OverlayError> for FailedReplace {
    /// An error before the replacement started (staging, scanning): nothing
    /// was written.
    fn from(error: OverlayError) -> Self {
        let may_copy = !crate::overlay_db::is_overlay_state_error(&error);
        Self {
            error,
            may_copy,
            rolled_back: None,
            base_unusable: false,
        }
    }
}

impl From<io::Error> for FailedReplace {
    fn from(error: io::Error) -> Self {
        OverlayError::Io(error).into()
    }
}

pub(crate) fn failed_replace(error: ReplaceError) -> FailedReplace {
    // A refusal (the archive changed since the gate, its lock was busy, a
    // journal was pending) may copy only while the archive is still exactly
    // the gate's snapshot: `rolled_back` is `None`, so the copy source is
    // compared with that snapshot ([`CopyFrom::Gate`]). A rollback whose
    // final stamp could not be read has no reference: no copy.
    let mut rolled_back = None;
    let (error, may_copy, base_unusable) = match error {
        ReplaceError::Refused(e) => {
            let may_copy = !crate::overlay_db::is_overlay_state_error(&e);
            (OverlayError::Io(e), may_copy, false)
        }
        ReplaceError::RolledBack(e, Some(stamp)) => {
            rolled_back = Some(stamp);
            let may_copy = !crate::overlay_db::is_overlay_state_error(&e);
            (OverlayError::Io(e), may_copy, false)
        }
        ReplaceError::RolledBack(e, None) if crate::overlay_db::is_overlay_state_error(&e) => {
            (OverlayError::Io(e), false, false)
        }
        ReplaceError::RolledBack(e, None) => (
            OverlayError::Msg(format!(
                "{e}; the archive's stamp after the rollback could not be read, so no copy \
                 fallback runs"
            )),
            false,
            false,
        ),
        ReplaceError::Pending(e) => (
            OverlayError::JournalPending(format!(
                "{e}; the archive's commit journal is still pending (remount required)"
            )),
            false,
            true,
        ),
        ReplaceError::Committed(e) => (
            OverlayError::Committed(format!(
                "{e}; the archive holds the committed bytes but the recorded baseline could \
                 not be updated (remount required)"
            )),
            false,
            true,
        ),
    };
    FailedReplace {
        error,
        may_copy,
        rolled_back,
        base_unusable,
    }
}

impl FailedReplace {
    /// What the copy fallback after this failure compares its source with.
    pub(crate) fn copy_from(&self) -> CopyFrom {
        match &self.rolled_back {
            Some(stamp) => CopyFrom::AfterRollback((**stamp).clone()),
            None => CopyFrom::Gate,
        }
    }
}

/// What a copy fallback's source must still be exactly (R7-D1, R7-E1): one
/// rule, [`commit_journal::same_stamp`] (device, inode, length, mtime,
/// ctime), against the stamp [`CopyFrom::reference`] names. Never a stamp the
/// copy took itself.
#[derive(Clone, Debug)]
pub(crate) enum CopyFrom {
    /// Nothing of this commit wrote the archive since the gate took its
    /// snapshot: the source must be exactly that snapshot. Any other writer
    /// since the gate refuses the copy: it would publish a file the gate never
    /// judged.
    Gate,
    /// This commit's own journaled attempt rolled back under its lock: the
    /// stamp its locked descriptor had after the cleanup. Another writer that
    /// took the lock after the rollback refuses the copy. (Only Linux and
    /// macOS have the journal, so only they ever produce this.)
    AfterRollback(fs::Metadata),
}

impl CopyFrom {
    /// The stamp the copy source must still be exactly (`gate`: the commit
    /// gate's snapshot).
    pub(crate) fn reference<'a>(&'a self, gate: &'a fs::Metadata) -> &'a fs::Metadata {
        match self {
            CopyFrom::Gate => gate,
            CopyFrom::AfterRollback(stamp) => stamp,
        }
    }
}

/// The file a copy fallback opened (`source`) is still exactly the stamp
/// `from` names (`original`: the gate's snapshot).
pub(crate) fn copy_source_matches(
    original: &fs::Metadata,
    source: &fs::Metadata,
    from: &CopyFrom,
) -> bool {
    commit_journal::same_stamp(from.reference(original), source)
}

/// The refusal when [`copy_source_matches`] fails.
pub(crate) fn copy_source_changed(archive: &Path) -> io::Error {
    io::Error::other(format!(
        "{} changed before the copy fallback (it is no longer the file the commit \
         gate accepted); nothing was published, retry",
        archive.display()
    ))
}

/// [`failed_replace`] for the zstd append splice; its other errors (scan,
/// staging) happen before anything is written.
pub(crate) fn failed_splice(error: ratarmount_compress::CompressError) -> FailedReplace {
    match error {
        ratarmount_compress::CompressError::Replace(e) => failed_replace(e),
        ratarmount_compress::CompressError::Io(error)
            if crate::overlay_db::is_overlay_state_error(&error) =>
        {
            error.into()
        }
        ratarmount_compress::CompressError::ArchiveMetadata(error) => FailedReplace {
            error: OverlayError::Io(error),
            may_copy: false,
            rolled_back: None,
            base_unusable: false,
        },
        other => OverlayError::Msg(other.to_string()).into(),
    }
}

/// The commit's journaled suffix replacement: the `Restamp::Commit` hook and
/// the gate's snapshot cannot be forgotten, and a failure is answered once.
pub(crate) fn replace_committing(
    archive: &Path,
    offset: u64,
    suffix: &mut fs::File,
    original: &fs::Metadata,
    rows: &Rows<'_>,
    before_write: &mut dyn FnMut() -> Result<()>,
) -> std::result::Result<(), FailedReplace> {
    let mut refusal = None;
    let mut checked_write = || {
        rows.guard()?;
        before_write().map_err(|error| {
            let message = error.to_string();
            refusal = Some(error);
            io::Error::other(message)
        })
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "The compositing replacement wrapper supplies the checked base and commit restamp hook"
    )]
    let replaced = commit_journal::replace_suffix_if_unchanged_guarded(
        archive,
        offset,
        suffix,
        original,
        &mut checked_write,
        &mut rows.commit_hook(archive),
    );
    if let Some(error) = refusal {
        return Err(FailedReplace {
            error,
            may_copy: false,
            rolled_back: None,
            base_unusable: false,
        });
    }
    replaced.map_err(failed_replace)
}

/// The commit's journaled zstd append splice (see [`replace_committing`]).
pub(crate) fn splice_append_committing<F>(
    archive: &Path,
    from_idx: usize,
    transform: F,
    original: &fs::Metadata,
    rows: &Rows<'_>,
    before_write: &mut dyn FnMut() -> Result<()>,
) -> std::result::Result<ratarmount_compress::SpliceStats, FailedReplace>
where
    F: FnOnce(&mut dyn ratarmount_compress::SeekRead, u64, &mut dyn io::Write) -> io::Result<()>,
{
    let mut refusal = None;
    let mut checked_write = || {
        rows.guard()?;
        before_write().map_err(|error| {
            let message = error.to_string();
            refusal = Some(error);
            io::Error::other(message)
        })
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "The compositing append wrapper supplies the checked base and commit restamp hook"
    )]
    let appended = ratarmount_compress::splice_zstd_last_frames_append_guarded(
        archive,
        from_idx,
        transform,
        original,
        &mut checked_write,
        &mut rows.commit_hook(archive),
    );
    if let Some(error) = refusal {
        return Err(FailedReplace {
            error,
            may_copy: false,
            rolled_back: None,
            base_unusable: false,
        });
    }
    appended.map_err(failed_splice)
}

/// Open the file a copy fallback reads, refusing unless it is still exactly
/// the stamp `from` names (`original`: the gate's snapshot). Returns the open
/// file and that checked stamp: the copy publishes through [`publish_over`]
/// with it (never with a stamp taken later, which would accept another
/// writer's change since the check).
pub(crate) fn open_copy_source(
    archive: &Path,
    original: &fs::Metadata,
    from: &CopyFrom,
) -> io::Result<(fs::File, fs::Metadata)> {
    commit_journal::fault::point("copy source open")?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0143-M01","item":"ratarmount_compositing::journal_recovery::open_copy_source","disposition":"residual","reason":"open_copy_source: source of every commit copy fallback; recovery and mutation ownership belong to the excluded broader machinery","family":"commit-journal-recovery","issue":"#196","category":"commit-journal-recovery","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let file = fs::File::open(archive)?;
    let source = recheck_copy_source(archive, &file, original, from)?;
    commit_journal::fault::point("copy source opened")?;
    Ok((file, source))
}

/// The stamp of an already open copy source (`file`), refusing unless it is
/// still exactly the stamp `from` names (see [`open_copy_source`]).
pub(crate) fn recheck_copy_source(
    archive: &Path,
    file: &fs::File,
    original: &fs::Metadata,
    from: &CopyFrom,
) -> io::Result<fs::Metadata> {
    let source = file.metadata()?;
    if !copy_source_matches(original, &source, from) {
        return Err(copy_source_changed(archive));
    }
    Ok(source)
}

/// Publish a copy over `archive` only while it is still exactly the file the
/// copy was read from (`source`) and no journal is pending on it, under its
/// lock (held until `publish` returned). A before-write refusal retains its
/// original error and is terminal, including in Auto mode.
pub(crate) fn publish_over(
    archive: &Path,
    source: &fs::Metadata,
    rows: &Rows<'_>,
    publish: impl FnOnce() -> io::Result<()>,
    before_write: &mut dyn FnMut() -> Result<()>,
) -> std::result::Result<(), FailedReplace> {
    #[expect(
        clippy::disallowed_methods,
        reason = "The compositing publisher holds the checked-source guard across the publication callback"
    )]
    let _guard = commit_journal::guard_copy(archive, source)?;
    rows.guard()?;
    if let Err(error) = before_write() {
        return Err(FailedReplace {
            error,
            may_copy: false,
            rolled_back: None,
            base_unusable: false,
        });
    }
    commit_journal::test_prewrite_hold()?;
    rows.guard()?;
    if let Err(error) = before_write() {
        return Err(FailedReplace {
            error,
            may_copy: false,
            rolled_back: None,
            base_unusable: false,
        });
    }
    publish().map_err(FailedReplace::from)
}

/// The zstd copy splice, read only from a file still exactly the stamp `from`
/// names and published under the same guard.
pub(crate) fn splice_replace_over<F>(
    archive: &Path,
    from_idx: usize,
    transform: F,
    original: &fs::Metadata,
    from: &CopyFrom,
    rows: &Rows<'_>,
    before_write: &mut dyn FnMut() -> Result<()>,
) -> std::result::Result<ratarmount_compress::SpliceStats, OverlayError>
where
    F: FnOnce(&mut dyn ratarmount_compress::SeekRead, u64, &mut dyn io::Write) -> io::Result<()>,
{
    let mut refusal = None;
    let mut checked_write = || {
        rows.guard()?;
        before_write().map_err(|error| {
            let message = error.to_string();
            refusal = Some(error);
            io::Error::other(message)
        })
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "The compositing copy-splice wrapper provides the previously accepted source stamp"
    )]
    let replaced = ratarmount_compress::splice_zstd_last_frames_replace_guarded(
        archive,
        from_idx,
        transform,
        from.reference(original),
        &mut checked_write,
    );
    if let Some(error) = refusal {
        return Err(error);
    }
    replaced.map_err(|e| match e {
        ratarmount_compress::CompressError::Io(error) => OverlayError::Io(error),
        other => OverlayError::Msg(other.to_string()),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn assert_archive_locked(archive: &Path) {
        use std::os::fd::AsRawFd;
        let competitor = fs::File::open(archive).unwrap();
        let result = unsafe { libc::flock(competitor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(
            result, -1,
            "before-write guard must run under the archive lock"
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
    }

    /// Regression: #238 ordinary copy publication checks sealing under the
    /// archive lock and refuses before publishing any bytes.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn regression_238_publish_guard_runs_under_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("base.tar");
        fs::write(&archive, b"before").unwrap();
        let source = fs::metadata(&archive).unwrap();
        let published = Cell::new(false);
        let error = publish_over(
            &archive,
            &source,
            &Rows::None,
            || {
                published.set(true);
                fs::write(&archive, b"after")
            },
            &mut || {
                assert_archive_locked(&archive);
                Err(OverlayError::Msg("sealed refusal".into()))
            },
        )
        .unwrap_err();
        assert!(!error.may_copy);
        assert!(
            matches!(error.error, OverlayError::Msg(ref message) if message == "sealed refusal")
        );
        assert!(!published.get());
        assert_eq!(fs::read(&archive).unwrap(), b"before");
        assert!(!commit_journal::journal_path(&archive).exists());
    }

    /// Regression: #238 a prewrite refusal stays the original overlay error
    /// and cannot trigger Auto mode's copy fallback.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn regression_238_replace_guard_refusal_is_terminal() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("base.tar");
        fs::write(&archive, b"before").unwrap();
        let original = fs::metadata(&archive).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"after").unwrap();
        let failed = replace_committing(
            &archive,
            0,
            &mut suffix,
            &original,
            &Rows::None,
            &mut || {
                assert_archive_locked(&archive);
                Err(OverlayError::Msg("sealed refusal".into()))
            },
        )
        .unwrap_err();
        assert!(
            matches!(failed.error, OverlayError::Msg(ref message) if message == "sealed refusal")
        );
        assert!(
            !failed.may_copy,
            "Auto must not fall back after a guard refusal"
        );
        assert!(!failed.base_unusable);
        assert!(failed.rolled_back.is_none());
        assert_eq!(fs::read(&archive).unwrap(), b"before");
        assert!(!commit_journal::journal_path(&archive).exists());
        assert!(commit_journal::pending(&archive).unwrap().is_none());
    }

    /// Regression: #238 both zstd persistence wrappers preserve the sealed
    /// refusal, and an append refusal cannot trigger Auto's copy fallback.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn regression_238_splice_guard_refusal_is_terminal() {
        for append in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let archive = tmp.path().join("base.tar.zst");
            let mut before = ratarmount_compress::encode_zstd_frame(b"before", 3).unwrap();
            before.extend(ratarmount_compress::build_seek_table_skippable(&[(
                before.len() as u32,
                6,
            )]));
            fs::write(&archive, &before).unwrap();
            let original = fs::metadata(&archive).unwrap();
            let mut guard = || {
                assert_archive_locked(&archive);
                Err(OverlayError::Msg("sealed refusal".into()))
            };
            let transform =
                |_source: &mut dyn ratarmount_compress::SeekRead,
                 _offset: u64,
                 dest: &mut dyn io::Write| dest.write_all(b"after");
            let error = if append {
                let failed = splice_append_committing(
                    &archive,
                    0,
                    transform,
                    &original,
                    &Rows::None,
                    &mut guard,
                )
                .unwrap_err();
                assert!(
                    !failed.may_copy,
                    "Auto must not fall back after a guard refusal"
                );
                failed.error
            } else {
                splice_replace_over(
                    &archive,
                    0,
                    transform,
                    &original,
                    &CopyFrom::Gate,
                    &Rows::None,
                    &mut guard,
                )
                .unwrap_err()
            };
            assert!(matches!(error, OverlayError::Msg(ref message) if message == "sealed refusal"));
            assert_eq!(fs::read(&archive).unwrap(), before);
            assert!(!commit_journal::journal_path(&archive).exists());
            assert!(commit_journal::pending(&archive).unwrap().is_none());
        }
    }

    /// Regression: archive metadata failures must not trigger Auto's copy fallback
    /// or disable a live commit's still-unchanged base.
    #[test]
    fn regression_235_archive_metadata_failure_forbids_copy() {
        let failed = failed_splice(ratarmount_compress::CompressError::ArchiveMetadata(
            io::Error::from_raw_os_error(libc::EIO),
        ));
        assert!(!failed.may_copy);
        assert!(failed.rolled_back.is_none());
        assert!(!failed.base_unusable);
        let OverlayError::Io(cause) = failed.error else {
            panic!("archive metadata failure lost its I/O cause");
        };
        assert_eq!(cause.raw_os_error(), Some(libc::EIO));
    }

    struct BeforeOpenGuard(Option<Box<dyn FnOnce()>>);
    impl Drop for BeforeOpenGuard {
        fn drop(&mut self) {
            BEFORE_INNER_OPEN.with(|h| *h.borrow_mut() = self.0.take());
        }
    }
    type AfterAcquireCallback = Box<dyn FnMut(&Path)>;
    struct AfterAcquireGuard(Option<AfterAcquireCallback>);
    impl Drop for AfterAcquireGuard {
        fn drop(&mut self) {
            crate::overlay_db::AFTER_ACQUIRE.with(|h| *h.borrow_mut() = self.0.take());
        }
    }

    /// Regression: only the inner acquisition observes a newly planted marker.
    /// Rows retains that requirement after marker removal, including retries
    /// with missing, empty, and nonempty files-less records.
    #[test]
    fn regression_rows_required_latch_raised_by_acquisition() {
        for loss in ["filesless", "empty", "missing"] {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().canonicalize().unwrap();
            let db = dir.join(crate::HIDDEN_DB);
            Connection::open(&db)
                .unwrap()
                .execute_batch(
                    "CREATE TABLE files (x); CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO meta VALUES ('sentinel', 'unchanged');",
                )
                .unwrap();
            let rows = Rows::path(&db);
            let Rows::Path { required_files, .. } = &rows else {
                unreachable!()
            };
            assert!(!required_files.get(), "Rows::path initially sees no marker");
            let planted = Rc::new(Cell::new(false));
            let planted_hook = planted.clone();
            let marker = dir.join(crate::OVERLAY_MARKER);
            let previous = BEFORE_INNER_OPEN.with(|h| {
                h.borrow_mut().replace(Box::new(move || {
                    fs::write(&marker, b"").unwrap();
                    planted_hook.set(true);
                }))
            });
            let _before = BeforeOpenGuard(previous);
            let removed = Rc::new(Cell::new(false));
            let removed_hook = removed.clone();
            let hook_dir = dir.clone();
            let mut remove_once = Some(move || {
                for name in [crate::OVERLAY_MARKER, crate::LEGACY_OVERLAY_MARKER] {
                    let path = hook_dir.join(name);
                    if path.exists() {
                        fs::remove_file(path).unwrap();
                    }
                }
                removed_hook.set(true);
            });
            let previous = crate::overlay_db::AFTER_ACQUIRE.with(|h| {
                h.borrow_mut().replace(Box::new(move |_| {
                    if let Some(remove) = remove_once.take() {
                        remove();
                    }
                }))
            });
            let _after = AfterAcquireGuard(previous);
            let called = Cell::new(false);
            rows.with(|conn, required| {
                assert!(planted.get() && removed.get());
                assert!(required, "only the acquisition saw the marker");
                OverlayMeta::from_connection_required(conn, required).map_err(io::Error::other)?;
                called.set(true);
                Ok(())
            })
            .unwrap();
            assert!(called.get());
            assert!(
                required_files.get(),
                "acquired requirement must raise Rows' latch"
            );
            assert!(crate::write_overlay::overlay_markers(&dir)
                .unwrap()
                .is_empty());

            match loss {
                "filesless" => Connection::open(&db)
                    .unwrap()
                    .execute_batch("DROP TABLE files")
                    .unwrap(),
                "empty" => fs::write(&db, b"").unwrap(),
                "missing" => fs::remove_file(&db).unwrap(),
                _ => unreachable!(),
            }
            let mutated = Cell::new(false);
            let received_required = Cell::new(false);
            let error = rows
                .with(|conn, required| {
                    received_required.set(required);
                    assert!(required);
                    OverlayMeta::from_connection_required(conn, required)
                        .map_err(io::Error::other)?;
                    conn.execute("UPDATE meta SET value='mutated'", [])
                        .map_err(io::Error::other)?;
                    mutated.set(true);
                    Ok(())
                })
                .unwrap_err();
            assert!(!mutated.get(), "{loss}: no record-driven write");
            if loss == "filesless" {
                assert!(received_required.get());
                assert_eq!(error.to_string(), crate::overlay_meta::NO_FILES_TABLE);
                let c = Connection::open(&db).unwrap();
                assert_eq!(
                    c.query_row("SELECT value FROM meta WHERE key='sentinel'", [], |r| {
                        r.get::<_, String>(0)
                    })
                    .unwrap(),
                    "unchanged"
                );
            } else {
                assert!(!received_required.get(), "{loss}: callback must not run");
                if loss == "missing" {
                    assert!(!db.exists(), "record was not recreated");
                } else {
                    assert_eq!(fs::metadata(&db).unwrap().len(), 0);
                }
            }
        }
    }
}
