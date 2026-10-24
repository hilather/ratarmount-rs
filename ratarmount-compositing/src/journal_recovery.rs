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
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use ratarmount_compress::commit_journal::{
    self, Applied, PendingJournal, RecoverError, ReplaceError,
};
use rusqlite::Connection;

use crate::write_overlay::OverlayError;

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
        let refusal = |r: crate::overlay_gate::CommitBaseRefusal| io::Error::other(r.0);
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
            Owner::Inode => commit_journal::authorize_owned(header, locked),
            Owner::Forced => commit_journal::authorize_forced(header, locked),
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
    Shared(&'a Mutex<Connection>),
    /// An overlay database opened (read-write, never created) when the hook
    /// runs. A raw overlay directory has none: nothing to restamp.
    Path(&'a Path),
}

impl Rows<'_> {
    pub(crate) fn with(&self, f: impl FnOnce(&Connection) -> io::Result<()>) -> io::Result<()> {
        match self {
            Rows::None => Ok(()),
            Rows::Shared(db) => f(&db.lock().unwrap_or_else(|e| e.into_inner())),
            Rows::Path(db) => {
                // Only a missing entry is "no database" (R7-E2); anything
                // else is opened (never created) and fails if unreadable.
                if crate::write_overlay::db_entry_absent(db) {
                    return Ok(());
                }
                let conn = crate::open_overlay_db(
                    db,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                    crate::DbName::Path,
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
    mut owner: Owner<'_>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    let mut authorize =
        |header: &PendingJournal, locked: &fs::Metadata| owner.authorize(header, locked);
    commit_journal::recover_with(archive, &mut authorize, &mut |applied| {
        rows.with(|conn| restamp_rows(conn, archive, applied, Restamp::Recovery))
    })
}

/// Recover one archive and restamp every top database before the journal is
/// unlinked. An incomplete header, or an Own that the under-lock recheck
/// classifies as Deferred, refuses with no recovery write (the authorizer
/// returns before `recover_with` applies the journal). A restamp error keeps
/// the journal.
pub fn recover_journal_cohort(
    archive: &Path,
    tops: &[std::path::PathBuf],
    records: &MountRecords,
) -> std::result::Result<Option<Applied>, RecoverError> {
    // A dangling symlink or other non-file is not an absent database. Refuse
    // before `recover_with` so the journal is not applied.
    refuse_nonregular_top_dbs(archive, tops).map_err(RecoverError::Refused)?;
    let conns = open_regular_top_dbs(tops).map_err(RecoverError::Refused)?;
    let mut authorize = |header: &PendingJournal, locked: &fs::Metadata| {
        if !header.complete {
            return Err(io::Error::other(format!(
                "fork-n refuses {}: commit journal changed while the mount classified it, retry",
                archive.display()
            )));
        }
        let canonical = archive.canonicalize()?;
        let current = current_identity(locked);
        // Every top votes on this pass. Deferred under the lock aborts the
        // run (the error does not start with `fork-n defers journal`, so the
        // caller does not queue this member for step 6).
        for top in tops {
            let one = MountRecords {
                top: Some(top.clone()),
                lowers: records.lowers.clone(),
                bundles: records.bundles,
            };
            match decide(&one, &canonical, header, current)? {
                MountJournal::None | MountJournal::Own => {}
                MountJournal::Deferred { .. } => {
                    return Err(io::Error::other(format!(
                        "fork-n refuses {}: commit journal changed while the mount classified it, retry",
                        archive.display()
                    )));
                }
            }
        }
        Ok(())
    };
    commit_journal::recover_with(archive, &mut authorize, &mut |applied| {
        for conn in &conns {
            restamp_rows(conn, archive, applied, Restamp::Recovery)?;
        }
        Ok(())
    })
}

/// Locator rules for a member classified [`MountJournal::None`], and the same
/// cohort authorization if a journal appears before the lock. A journal that
/// is Deferred and complete is not applied here: the error text starts with
/// `fork-n defers journal` and the caller queues it for the post-open pass.
/// An incomplete journal refuses with no write.
pub fn recover_journal_locator(
    archive: &Path,
    tops: &[std::path::PathBuf],
    records: &MountRecords,
) -> std::result::Result<Option<Applied>, RecoverError> {
    let mut owner = Owner::Mount {
        records,
        member: archive,
    };
    let mut authorize = |header: &PendingJournal, locked: &fs::Metadata| {
        if !header.complete {
            return Err(io::Error::other(format!(
                "fork-n refuses {}: commit journal changed while the mount classified it, retry",
                archive.display()
            )));
        }
        let canonical = archive.canonicalize()?;
        match decide(records, &canonical, header, current_identity(locked))? {
            MountJournal::Deferred { complete: true, .. } => Err(io::Error::other(format!(
                "fork-n defers journal {}",
                archive.display()
            ))),
            MountJournal::Deferred { .. } => Err(io::Error::other(format!(
                "fork-n refuses {}: commit journal is incomplete; recover it on a single mount or with --no-mount",
                archive.display()
            ))),
            MountJournal::None | MountJournal::Own => owner.authorize(header, locked),
        }
    };
    commit_journal::recover_with(archive, &mut authorize, &mut |applied| {
        restamp_cohort_dbs(archive, tops, applied)
    })
}

/// Post-open Deferred recovery. Every top votes under the archive lock.
/// Incomplete, or an Own that became Deferred-incomplete, refuses with no
/// write. `restamp` is the live overlay connections; this function does not
/// open a second database.
pub fn recover_journal_deferred(
    archive: &Path,
    tops: &[std::path::PathBuf],
    lowers: &[std::path::PathBuf],
    bundles: bool,
    restamp: &mut dyn FnMut(&Applied) -> io::Result<()>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    let mut authorize = |header: &PendingJournal, locked: &fs::Metadata| {
        if !header.complete {
            return Err(io::Error::other(format!(
                "fork-n refuses {}: commit journal changed while the mount classified it, retry",
                archive.display()
            )));
        }
        let canonical = archive.canonicalize()?;
        let current = current_identity(locked);
        for top in tops {
            let records = MountRecords {
                top: Some(top.clone()),
                lowers: lowers.to_vec(),
                bundles,
            };
            match decide(&records, &canonical, header, current)? {
                MountJournal::None | MountJournal::Own => {}
                MountJournal::Deferred { complete: true, .. } => {}
                MountJournal::Deferred { why, .. } => {
                    return Err(io::Error::other(format!(
                        "{} {why}; its commit journal changed while the mount classified it, retry",
                        archive.display()
                    )));
                }
            }
        }
        Ok(())
    };
    commit_journal::recover_with(archive, &mut authorize, restamp)
}

fn refuse_nonregular_top_dbs(archive: &Path, tops: &[std::path::PathBuf]) -> io::Result<()> {
    for top in tops {
        let db = top.join(crate::HIDDEN_DB);
        match fs::symlink_metadata(&db) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
            Ok(meta) if meta.is_file() => {}
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "fork-n refuses {}: top database {} is not a regular file",
                    archive.display(),
                    db.display()
                )));
            }
        }
    }
    Ok(())
}

fn open_regular_top_dbs(tops: &[std::path::PathBuf]) -> io::Result<Vec<rusqlite::Connection>> {
    let mut conns = Vec::new();
    for top in tops {
        let db = top.join(crate::HIDDEN_DB);
        match fs::symlink_metadata(&db) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
            Ok(meta) if !meta.is_file() => continue,
            Ok(_) => {}
        }
        let conn = crate::open_overlay_db(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            crate::DbName::Path,
        )
        .map_err(|e| io::Error::other(e.to_string()))?;
        conns.push(conn);
    }
    Ok(conns)
}

fn restamp_cohort_dbs(
    archive: &Path,
    tops: &[std::path::PathBuf],
    applied: &Applied,
) -> io::Result<()> {
    refuse_nonregular_top_dbs(archive, tops)?;
    for conn in open_regular_top_dbs(tops)? {
        restamp_rows(&conn, archive, applied, Restamp::Recovery)?;
    }
    Ok(())
}

/// [`recover_journal`] for callers that hold no overlay: the library and mount
/// openers, offline commits. `overlay_db`, when it exists, is opened read-write
/// (it is never created) BEFORE recovery starts; a database that cannot be
/// opened fails the call with the journal untouched.
pub fn recover_journal_at(
    archive: &Path,
    overlay_db: Option<&Path>,
    owner: Owner<'_>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    // Opened only when a roll-forward needs to restamp: a mount with no pending
    // journal never touches the overlay database here.
    let rows = overlay_db.map_or(Rows::None, Rows::Path);
    recover_journal(archive, rows, owner)
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

fn read_record(dir: &Path) -> io::Result<Option<OverlayMeta>> {
    // Only a missing database is "no record". A directory, a symlink or
    // anything else that is not a regular file, or that cannot be statted, is
    // an unreadable record: it must defer, never abstain.
    match fs::symlink_metadata(dir.join(crate::HIDDEN_DB)) {
        Ok(m) if m.is_file() => {}
        Ok(_) => {
            return Err(io::Error::other(
                "the overlay database is not a regular file".to_string(),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    OverlayMeta::read_no_recovery(dir).map_err(|e| io::Error::other(e.to_string()))
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
                return Ok(defer(
                    format!(
                        "has an overlay record ({}) that cannot be read: {e}",
                        dir.display()
                    ),
                    flag,
                ))
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
        Self {
            error,
            may_copy: true,
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
        ReplaceError::Refused(e) => (OverlayError::Msg(e.to_string()), true, false),
        ReplaceError::RolledBack(e, Some(stamp)) => {
            rolled_back = Some(stamp);
            (OverlayError::Io(e), true, false)
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
) -> std::result::Result<(), FailedReplace> {
    commit_journal::replace_suffix_if_unchanged_with(
        archive,
        offset,
        suffix,
        original,
        &mut rows.commit_hook(archive),
    )
    .map_err(failed_replace)
}

/// The commit's journaled zstd append splice (see [`replace_committing`]).
pub(crate) fn splice_append_committing<F>(
    archive: &Path,
    from_idx: usize,
    transform: F,
    original: &fs::Metadata,
    rows: &Rows<'_>,
) -> std::result::Result<ratarmount_compress::SpliceStats, FailedReplace>
where
    F: FnOnce(&mut dyn ratarmount_compress::SeekRead, u64, &mut dyn io::Write) -> io::Result<()>,
{
    ratarmount_compress::splice_zstd_last_frames_append_with(
        archive,
        from_idx,
        transform,
        original,
        &mut rows.commit_hook(archive),
    )
    .map_err(failed_splice)
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
/// lock (held until `publish` returned).
pub(crate) fn publish_over(
    archive: &Path,
    source: &fs::Metadata,
    publish: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let _guard = commit_journal::guard_copy(archive, source)?;
    publish()
}

/// The zstd copy splice, read only from a file still exactly the stamp `from`
/// names and published under the same guard.
pub(crate) fn splice_replace_over<F>(
    archive: &Path,
    from_idx: usize,
    transform: F,
    original: &fs::Metadata,
    from: &CopyFrom,
) -> std::result::Result<ratarmount_compress::SpliceStats, OverlayError>
where
    F: FnOnce(&mut dyn ratarmount_compress::SeekRead, u64, &mut dyn io::Write) -> io::Result<()>,
{
    ratarmount_compress::splice_zstd_last_frames_replace(
        archive,
        from_idx,
        transform,
        from.reference(original),
    )
    .map_err(|e| OverlayError::Msg(e.to_string()))
}

#[cfg(test)]
mod fork_n_journal_tests {
    use super::{recover_journal_cohort, MountRecords};
    use std::os::unix::fs::symlink;

    /// Regression: a dangling top database is not treated as absent, and
    /// recovery does not start.
    #[test]
    fn fork_n_journal_dangling_top_db_refuses_before_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"not a journal").unwrap();
        let top = dir.path().join("top");
        std::fs::create_dir(&top).unwrap();
        symlink("/no/such/overlay-db", top.join(crate::HIDDEN_DB)).unwrap();
        let records = MountRecords {
            top: Some(top.clone()),
            lowers: Vec::new(),
            bundles: false,
        };
        let err = recover_journal_cohort(&archive, std::slice::from_ref(&top), &records)
            .expect_err("dangling database");
        let text = err.to_string();
        assert!(text.contains("not a regular file"), "{text}");
        assert_eq!(std::fs::read(&archive).unwrap(), b"not a journal");
    }
}
