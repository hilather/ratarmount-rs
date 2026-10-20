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
    fn with(&self, f: impl FnOnce(&Connection) -> io::Result<()>) -> io::Result<()> {
        match self {
            Rows::None => Ok(()),
            Rows::Shared(db) => f(&db.lock().unwrap_or_else(|e| e.into_inner())),
            Rows::Path(db) => {
                if !db.is_file() {
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
    // A rollback restored the recorded state: the commit's baseline (and a
    // strong digest) already describe it, so there is nothing to move.
    if mode == Restamp::Commit && !applied.rolled_forward {
        return Ok(());
    }
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
    mut owner: Owner<'_>,
) -> std::result::Result<Option<Applied>, RecoverError> {
    let mut authorize =
        |header: &PendingJournal, locked: &fs::Metadata| owner.authorize(header, locked);
    commit_journal::recover_with(archive, &mut authorize, &mut |applied| {
        // A rollback restores the recorded state: nothing to restamp.
        if !applied.rolled_forward {
            return Ok(());
        }
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
    if !names(meta, &canonical) {
        return false;
    }
    let Ok(Some(journal)) = commit_journal::pending(&canonical) else {
        return false;
    };
    owns(&journal, &canonical) && journal_agrees((size, mtime), current, &journal)
}

/// The journal was started for the file `path` resolves to.
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
    // Only a missing database is "no record". A symlink or anything that cannot
    // be statted is an unreadable record: it must defer, never abstain.
    match fs::symlink_metadata(dir.join(crate::HIDDEN_DB)) {
        Ok(m) if m.is_file() => {}
        Ok(m) if m.is_dir() => return Ok(None),
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
/// `current` is `(ino, len, mtime_ns)`.
fn decide(
    records: &MountRecords,
    canonical: &Path,
    journal: &PendingJournal,
    current: (u64, u64, i128),
) -> io::Result<MountJournal> {
    if journal.ino != current.0 {
        return Err(io::Error::other(format!(
            "{} carries a commit journal that was started for another file \
             (journal inode {}, archive inode {}); the journal was not applied",
            canonical.display(),
            journal.ino,
            current.0
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
        if !names(&meta, canonical) {
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

fn current_identity(meta: &fs::Metadata) -> (u64, u64, i128) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            meta.ino(),
            meta.len(),
            i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        )
    }
    #[cfg(not(unix))]
    {
        (0, meta.len(), 0)
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
    let (error, may_copy, base_unusable) = match error {
        ReplaceError::Refused(e) => (OverlayError::Msg(e.to_string()), true, false),
        ReplaceError::RolledBack(e) => (OverlayError::Io(e), true, false),
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
        base_unusable,
    }
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

/// Open the file a copy fallback reads, refusing unless it is the file the
/// commit gate accepted (`original`'s device and inode). Returns the open
/// file and its stamp; [`publish_over`] compares that stamp under the lock.
pub(crate) fn open_copy_source(
    archive: &Path,
    original: &fs::Metadata,
) -> io::Result<(fs::File, fs::Metadata)> {
    let file = fs::File::open(archive)?;
    let source = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (source.dev(), source.ino()) != (original.dev(), original.ino()) {
            return Err(io::Error::other(format!(
                "{} changed before the copy fallback (it is no longer the file the commit \
                 gate accepted); nothing was published, retry",
                archive.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = original;
    Ok((file, source))
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

/// The zstd copy splice, read from the gate's file and published under the
/// same guard.
pub(crate) fn splice_replace_over<F>(
    archive: &Path,
    from_idx: usize,
    transform: F,
    original: &fs::Metadata,
) -> std::result::Result<ratarmount_compress::SpliceStats, OverlayError>
where
    F: FnOnce(&mut dyn ratarmount_compress::SeekRead, u64, &mut dyn io::Write) -> io::Result<()>,
{
    ratarmount_compress::splice_zstd_last_frames_replace(archive, from_idx, transform, original)
        .map_err(|e| OverlayError::Msg(e.to_string()))
}
