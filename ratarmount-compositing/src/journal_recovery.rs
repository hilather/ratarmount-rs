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

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use ratarmount_compress::commit_journal::{self, Applied, Authorize, PendingJournal, RecoverError};
use rusqlite::Connection;

use crate::overlay_gate::kind_only;
use crate::overlay_meta::OverlayMeta;

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
    Shared(&'a Mutex<Connection>),
    Owned(&'a Connection),
    /// An overlay database opened (read-write, never created) when the hook
    /// runs. A raw overlay directory has none: nothing to restamp.
    Path(&'a Path),
}

impl Rows<'_> {
    fn with(&self, f: impl FnOnce(&Connection) -> io::Result<()>) -> io::Result<()> {
        match self {
            Rows::None => Ok(()),
            Rows::Shared(db) => f(&db.lock().unwrap_or_else(|e| e.into_inner())),
            Rows::Owned(conn) => f(conn),
            Rows::Path(db) => {
                if !db.exists() {
                    return Ok(());
                }
                let conn = Connection::open_with_flags(
                    db,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .map_err(|e| {
                    io::Error::other(format!(
                        "cannot open the overlay database {} to restamp the base: {e}",
                        db.display()
                    ))
                })?;
                f(&conn)
            }
        }
    }

    /// The `before_unlink` hook of the commit that wrote the journal
    /// (`Restamp::Commit`): the new stamp is the new baseline.
    pub(crate) fn commit_hook<'h>(
        &'h self,
        archive: &'h Path,
    ) -> impl FnMut(&Applied) -> io::Result<()> + 'h {
        move |applied| self.with(|conn| restamp_rows(conn, archive, applied, Restamp::Commit))
    }
}

/// The journal's pre-commit stamp is the recorded one, or the rows already
/// describe the committed bytes and only the unlink is owed.
pub fn journal_agrees(
    recorded: (u64, i128),
    current: (u64, i128),
    journal: &PendingJournal,
) -> bool {
    (journal.len, journal.mtime_ns) == recorded
        || (journal.complete && current.0 == journal.new_len && current == recorded)
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
        match restamp_once(conn, &canonical, applied, mode) {
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
        let meta = OverlayMeta::from_connection(conn)
            .map_err(|e| RestampError::Other(io::Error::other(e.to_string())))?;
        // A union member's journal, a record aimed at another place, a
        // kind-only record and a record without a stamp leave the rows alone.
        let Some(meta) = meta else {
            return Ok(());
        };
        if !names(&meta, canonical) || kind_only(&meta) {
            return Ok(());
        }
        let (Some(size), Some(mtime)) = (meta.get("base_size"), meta.get("base_mtime_ns")) else {
            return Ok(());
        };
        let final_size = applied.final_len.to_string();
        let final_mtime = applied.final_mtime_ns.to_string();
        if mode == Restamp::Recovery {
            let started_on_rows =
                applied.pre_len.to_string() == size && applied.pre_mtime_ns.to_string() == mtime;
            let already_final = size == final_size && mtime == final_mtime;
            if already_final {
                return Ok(());
            }
            if !(applied.rolled_forward && started_on_rows) {
                return Ok(());
            }
        }
        OverlayMeta::set_many(
            conn,
            &[
                ("base_size", final_size.as_str()),
                ("base_mtime_ns", final_mtime.as_str()),
            ],
        )
        .map_err(|e| RestampError::Other(io::Error::other(e.to_string())))?;
        // The recorded digest names the PRE-crash bytes. A weak one is the
        // stamp itself; a strong one is marked `pending` (never cleared) and
        // resolved lazily by seal, diff, pack or grading, so mounting stays
        // fast.
        let digest = match meta.base_digest_kind() {
            Some("weak") => {
                let weak = format!("weak:size={final_size},mtime_ns={final_mtime}");
                OverlayMeta::set_many(conn, &[("base_digest", weak.as_str())])
            }
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
    authorize: Authorize<'_>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    commit_journal::recover_with(archive, authorize, &mut |applied| {
        rows.with(|conn| restamp_rows(conn, archive, applied, Restamp::Recovery))
    })
}

/// [`recover_journal`] for callers that hold no overlay: the library and mount
/// openers, offline commits. `overlay_db`, when it exists, is opened read-write
/// (it is never created) BEFORE recovery starts; a database that cannot be
/// opened fails the call with the journal untouched.
pub fn recover_journal_at(
    archive: &Path,
    overlay_db: Option<&Path>,
    authorize: Authorize<'_>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    let conn = match overlay_db.filter(|db| db.exists()) {
        Some(db) => {
            let conn = Connection::open_with_flags(
                db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .and_then(|conn| conn.busy_timeout(Duration::from_secs(5)).map(|()| conn))
            .map_err(|e| {
                RecoverError::Journal(io::Error::other(format!(
                    "cannot open the overlay database {} to restamp the recovered base: {e}",
                    db.display()
                )))
            })?;
            Some(conn)
        }
        None => None,
    };
    let rows = conn.as_ref().map_or(Rows::None, Rows::Owned);
    recover_journal(archive, rows, authorize)
}
