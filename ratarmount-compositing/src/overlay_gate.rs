//! The one base-identity rule, on what the opener reported.
//!
//! **Experimental.** A creator or gate compares the base it holds a
//! [`ClassifiedBase`] for with what the overlay recorded:
//!
//! 1. an overlay with no recorded kind (made by a released build) or no named
//!    base agrees with anything;
//! 2. a record from an unreleased build that has no usable kind is refused
//!    until `--force-base-mismatch` records the base now in use;
//! 3. a different kind (Git, directory, archive) is a different base;
//! 4. the same kind with digest `none` agrees (kind-only, nothing is read);
//! 5. the same kind at the same place compares content as before (tree id,
//!    directory manifest, archive stamp);
//! 6. a base that moved between local and remote agrees only when the record
//!    is strong and a supplied or already cached SHA-256 equals it.
//!
//! Nothing here hashes, walks or reads a base on its own.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ratarmount_index::{peek_archive_digest, ArchiveDigestStamp};
use rusqlite::Connection;

use crate::overlay_identity::{ActualBase, BaseKind, BaseLocation, ClassifiedBase};
use crate::overlay_meta::{
    self, stack_digest, BaseCheck, BaseComparison, BaseExcludes, BaseStrength, OverlayMeta,
};
use crate::write_overlay::Result;
use crate::{OverlayError, HIDDEN_DB};

/// What a caller knows about a base besides what the opener served.
pub struct BaseProbe<'a> {
    /// A supplied `--base-digest`.
    pub supplied: Option<&'a str>,
    /// Base-relative paths of the caller's own overlay, journal and mount
    /// point, left out of the walk in addition to the recorded set.
    pub extra_excludes: &'a [PathBuf],
}

/// What an overlay says its base is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// Made by a released build (no kind row): agrees with any base, and the
    /// first `-w` open writes the kind.
    Unrecorded,
    /// Made without naming a base.
    Nothing,
    /// Written by an unreleased build with no usable kind.
    Unknown,
    Kind {
        kind: BaseKind,
        location: Option<BaseLocation>,
    },
}

impl Recorded {
    pub fn from_meta(meta: Option<&OverlayMeta>) -> Self {
        let Some(meta) = meta else {
            return Self::Unrecorded;
        };
        let kind = meta
            .get("base_kind")
            .and_then(BaseKind::parse)
            .map(|kind| Self::Kind {
                kind,
                location: meta.get("base_location").and_then(BaseLocation::from_row),
            });
        match meta.get("format_version") {
            None | Some("1") => kind.unwrap_or(Self::Unrecorded),
            Some("2") => kind.unwrap_or_else(|| {
                if meta.get("base_url") == Some("") {
                    Self::Nothing
                } else {
                    Self::Unknown
                }
            }),
            Some(_) => Self::Unknown,
        }
    }
}

/// The kind-and-place half of the comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Agrees; nothing more to read.
    Same,
    /// Same kind at the same place (or a local move): compare content.
    Content,
    Refuse(String),
}

fn kind_only(meta: &OverlayMeta) -> bool {
    matches!(meta.base_digest_kind(), None | Some("none"))
}

fn describe(location: Option<&BaseLocation>) -> String {
    match location {
        Some(BaseLocation::Local(path)) => format!("local {}", path.display()),
        Some(BaseLocation::Remote(url)) => format!("remote {url}"),
        None => "an unknown place".to_owned(),
    }
}

/// Compare kind and place, reading nothing but the cached digest of a local
/// archive when a record moved between local and remote.
pub fn shape_verdict(
    meta: Option<&OverlayMeta>,
    actual: &ActualBase,
    probe: &BaseProbe,
) -> Verdict {
    let (kind, location) =
        match Recorded::from_meta(meta) {
            Recorded::Unrecorded | Recorded::Nothing => return Verdict::Same,
            Recorded::Unknown => return Verdict::Refuse(
                "the overlay recorded no usable base kind (it was written by a pre-release build)"
                    .to_owned(),
            ),
            Recorded::Kind { kind, location } => (kind, location),
        };
    let meta = meta.expect("a recorded kind comes from metadata");
    if kind != actual.kind() {
        return Verdict::Refuse(format!(
            "a {} base (the overlay recorded a {} base)",
            actual.kind().as_str(),
            kind.as_str()
        ));
    }
    if kind_only(meta) {
        return Verdict::Same;
    }
    let pair = match (&location, actual.location()) {
        (_, None) => false,
        (None, Some(BaseLocation::Local(_))) => false,
        (Some(recorded), Some(now)) if recorded == now => false,
        (Some(BaseLocation::Local(_)), Some(BaseLocation::Local(_))) => false,
        _ => true,
    };
    if !pair {
        return Verdict::Content;
    }
    // A base that moved between local and remote: only a strong record that a
    // SHA-256 from elsewhere confirms. `pending` and `weak` never rescue.
    let recorded_digest = meta.known_base_digest();
    let strong = kind == BaseKind::Archive
        && meta.base_digest_kind() == Some("strong")
        && recorded_digest.is_some();
    // A supplied digest decides alone; the cache answers only when nothing was
    // supplied, so a wrong `--base-digest` is never rescued by a cached one.
    let confirmed = strong
        && match probe.supplied {
            Some(supplied) => Some(supplied) == recorded_digest,
            None => match actual.location() {
                Some(BaseLocation::Local(path)) => {
                    peek_archive_digest(path, actual.index_for_peek())
                        .ok()
                        .flatten()
                        .as_deref()
                        == recorded_digest
                }
                _ => false,
            },
        };
    if confirmed {
        Verdict::Same
    } else {
        Verdict::Refuse(format!(
            "the base moved from {} to {}, and no strong digest confirms it",
            describe(location.as_ref()),
            describe(actual.location())
        ))
    }
}

fn content_probe<'a>(
    actual: &'a ActualBase,
    probe: &BaseProbe<'a>,
) -> overlay_meta::ContentProbe<'a> {
    overlay_meta::ContentProbe {
        path: match (actual.kind(), actual.location()) {
            (BaseKind::Archive | BaseKind::Dir, Some(BaseLocation::Local(path))) => {
                Some(path.as_path())
            }
            _ => None,
        },
        git_tree: actual.git_tree(),
        supplied: probe.supplied,
        index: actual.index_for_peek(),
        extra_excludes: probe.extra_excludes,
    }
}

/// Reopen, `overlay seal`/`pack`, `diff` and the `--lower` mount all compare
/// a base with what the overlay recorded through this. Metadata only.
pub fn compare_base_identity(
    meta: Option<&OverlayMeta>,
    base: &ClassifiedBase,
    probe: &BaseProbe,
) -> std::result::Result<BaseComparison, String> {
    let actual = base.actual();
    let identity = probe.supplied.unwrap_or_default().to_owned();
    match shape_verdict(meta, actual, probe) {
        Verdict::Same => Ok(BaseComparison {
            identity,
            ..Default::default()
        }),
        Verdict::Refuse(reason) => Ok(BaseComparison {
            identity,
            mismatch: Some(reason),
            ..Default::default()
        }),
        Verdict::Content => overlay_meta::compare_content(meta, &content_probe(actual, probe)),
    }
}

/// The rows that make an overlay describe the base the opener served:
/// `base_kind`, `base_location`, and `base_url` when it names one. `None`
/// when the overlay already says exactly this.
pub fn identity_rows(
    meta: Option<&OverlayMeta>,
    base: &ClassifiedBase,
) -> Option<BTreeMap<String, String>> {
    let actual = base.actual();
    let mut rows = BTreeMap::new();
    rows.insert("base_kind".to_owned(), actual.kind().as_str().to_owned());
    if let Some(location) = actual.location() {
        rows.insert("base_location".to_owned(), location.row());
    }
    if !actual.base_url().is_empty() {
        rows.insert("base_url".to_owned(), actual.base_url().to_owned());
    }
    let unchanged =
        meta.is_some_and(|meta| rows.iter().all(|(key, value)| meta.get(key) == Some(value)));
    (!unchanged).then_some(rows)
}

/// Rows describing the base now in use after a forced or accepted change of
/// place: identity rows plus, for a local archive, its current stamp.
fn relocation_rows(
    meta: Option<&OverlayMeta>,
    base: &ClassifiedBase,
) -> Result<BTreeMap<String, String>> {
    let actual = base.actual();
    let mut rows = identity_rows(None, base).unwrap_or_default();
    // A directory keeps its comparison baseline: the weak manifest of the
    // place now read, measured with the exclusions the overlay recorded.
    // (It equals the recorded one, or the move would not have been accepted.)
    if let (BaseKind::Dir, Some(BaseLocation::Local(path))) = (actual.kind(), actual.location()) {
        if meta.is_some_and(|m| m.get("base_weak_digest").is_some()) {
            let excludes = match meta.and_then(|m| m.get("base_weak_excludes")) {
                Some(text) => BaseExcludes::from_json(text)?,
                None => BaseExcludes::default(),
            };
            rows.insert(
                "base_weak_digest".into(),
                overlay_meta::directory_weak_digest(path, &excludes)?,
            );
        }
    }
    if let (BaseKind::Archive, Some(BaseLocation::Local(path))) = (actual.kind(), actual.location())
    {
        if path.is_file() {
            let stamp = ArchiveDigestStamp::read(path)?;
            rows.insert("base_size".into(), stamp.size.to_string());
            rows.insert("base_mtime_ns".into(), stamp.mtime_ns.to_string());
            rows.insert(
                "base_local_path".into(),
                path.to_string_lossy().into_owned(),
            );
        }
    }
    Ok(rows)
}

/// Write the rows an accepted (not forced) change of place needs, through the
/// caller's connection: a Local archive also moves its stamp so the next
/// content comparison measures the new place.
pub(crate) fn write_accepted_identity(
    conn: &Connection,
    meta: Option<&OverlayMeta>,
    base: &ClassifiedBase,
) -> Result<()> {
    let Some(identity) = identity_rows(meta, base) else {
        return Ok(());
    };
    let moved = meta
        .and_then(|m| m.get("base_location"))
        .is_some_and(|row| Some(row) != identity.get("base_location").map(String::as_str));
    let rows = if moved {
        relocation_rows(meta, base)?
    } else {
        identity
    };
    if moved {
        // The stamp, path and manifest of the place left behind describe a
        // base that is no longer read; the next reopen would compare them.
        for key in [
            "base_size",
            "base_mtime_ns",
            "base_local_path",
            "base_weak_digest",
        ] {
            if !rows.contains_key(key) {
                OverlayMeta::remove(conn, key)?;
            }
        }
    }
    OverlayMeta::set_many(
        conn,
        &rows
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
    )
}

/// The rows a forced seal, pack, diff or reopen records so the overlay
/// describes the base actually used. A supplied digest is recorded as strong
/// (with the directory manifest or archive stamp measured now); with nothing
/// supplied a directory or archive drops to kind-only (`none`): later runs
/// compare kind, not content, until a digest is supplied. A Git tree keeps
/// its tree id (it costs nothing). Nothing is hashed.
pub fn forced_base_record(
    meta: &OverlayMeta,
    base: &ClassifiedBase,
    probe: &BaseProbe,
) -> std::result::Result<BTreeMap<String, String>, String> {
    let actual = base.actual();
    let mut rows: BTreeMap<String, String> = identity_rows(None, base).unwrap_or_default();
    let mut set = |key: &str, value: String| {
        rows.insert(key.to_owned(), value);
    };
    let (digest, kind, source) = if let Some(tree) = actual.git_tree() {
        set("base_git_tree", tree.to_owned());
        (format!("git-tree:{tree}"), "git-tree", Some("computed"))
    } else {
        // What is measured about a local base is only useful next to a
        // supplied digest; nothing is measured for a remote one.
        if probe.supplied.is_some() {
            match (actual.kind(), actual.location()) {
                (BaseKind::Dir, Some(BaseLocation::Local(path))) => {
                    let recorded = match meta.get("base_weak_excludes") {
                        Some(text) => BaseExcludes::from_json(text).map_err(|e| e.to_string())?,
                        None => BaseExcludes::default(),
                    };
                    let excludes = BaseExcludes::new(
                        recorded.paths().iter().chain(probe.extra_excludes).cloned(),
                    );
                    set(
                        "base_weak_digest",
                        overlay_meta::directory_weak_digest(path, &excludes)
                            .map_err(|e| format!("cannot measure base {}: {e}", path.display()))?,
                    );
                }
                (BaseKind::Archive, Some(BaseLocation::Local(path))) => {
                    let stamp = ArchiveDigestStamp::read(path)
                        .map_err(|e| format!("cannot stat base {}: {e}", path.display()))?;
                    set("base_size", stamp.size.to_string());
                    set("base_mtime_ns", stamp.mtime_ns.to_string());
                    set("base_local_path", path.to_string_lossy().into_owned());
                }
                _ => {}
            }
        }
        match probe.supplied {
            Some(supplied) => (supplied.to_owned(), "strong", Some("supplied")),
            None => ("none".to_owned(), "none", None),
        }
    };
    let layers = meta.lower_layers().map_err(|e| e.to_string())?;
    let stack = stack_digest(
        &digest,
        &layers
            .iter()
            .map(|l| l.layer_digest.as_str())
            .collect::<Vec<_>>(),
    );
    rows.insert("base_digest".into(), digest);
    rows.insert("base_digest_kind".into(), kind.to_owned());
    if let Some(source) = source {
        rows.insert("base_digest_source".into(), source.to_owned());
    }
    rows.insert("stack_digest".into(), stack);
    rows.insert("base_mismatch_forced_at".into(), overlay_meta::timestamp());
    Ok(rows)
}

/// Write `rows` (from [`forced_base_record`]) into an unsealed overlay's
/// `meta` table. The token must describe the base the rows name.
pub fn record_forced_base_rows(
    overlay: &Path,
    base: &ClassifiedBase,
    rows: &BTreeMap<String, String>,
) -> Result<()> {
    if rows.get("base_kind").map(String::as_str) != Some(base.actual().kind().as_str()) {
        return Err(OverlayError::Msg(
            "forced base rows do not describe the classified base".into(),
        ));
    }
    overlay_meta::record_base_rows_offline(overlay, rows)
}

/// Compare `base` with the digest the overlay recorded: the kind rule first,
/// then the digest check on a local archive or directory.
pub fn verify_base(dir: &Path, base: &ClassifiedBase) -> BaseCheck {
    let actual = base.actual();
    let meta = match OverlayMeta::read(dir) {
        Ok(meta) => meta,
        Err(error) => {
            return BaseCheck::Skipped {
                reason: format!("cannot read overlay metadata: {error}"),
            }
        }
    };
    let probe = BaseProbe {
        supplied: None,
        extra_excludes: &[],
    };
    if let Verdict::Refuse(current) = shape_verdict(meta.as_ref(), actual, &probe) {
        return BaseCheck::Mismatch {
            recorded: meta
                .as_ref()
                .and_then(|m| m.get("base_kind"))
                .unwrap_or("unknown")
                .to_owned(),
            current,
            strength: BaseStrength::Strong,
        };
    }
    match (actual.kind(), actual.location()) {
        (BaseKind::Git, _) => BaseCheck::Skipped {
            reason: "git-tree base".to_owned(),
        },
        (_, Some(BaseLocation::Local(path))) => overlay_meta::verify_base_path(dir, path),
        _ => BaseCheck::Skipped {
            reason: "base is not a local path".to_owned(),
        },
    }
}

/// Why a commit was refused before it wrote anything.
#[derive(Debug)]
pub(crate) struct CommitBaseRefusal(pub String);

impl std::fmt::Display for CommitBaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The identity check a live or on-exit commit runs BEFORE it writes: the
/// archive about to be rewritten must still be the base the last create,
/// commit or refresh recorded. Only the recorded rows count (never the
/// mount's supplied digest, never a cached one), and only `stat` is used:
///
/// 1. the commit target is still a regular file (a directory swapped in at
///    the same path is refused under every digest kind);
/// 2. digest `none` is kind-only: nothing more;
/// 3. otherwise the stamp (size, mtime) must equal the recorded stamp.
///
/// A token that is not a local archive, or an archive other than the one the
/// token describes (a union whose commit target is not the overlay's base),
/// has no recorded stamp to compare and passes.
pub(crate) fn check_commit_base(
    conn: &Connection,
    base: &ClassifiedBase,
    archive: &Path,
) -> std::result::Result<(), CommitBaseRefusal> {
    let refuse = |why: String| {
        CommitBaseRefusal(format!(
            "base mismatch: {why}; the commit was not written. Restore the archive, \
             or use --force-base-mismatch to accept the new base"
        ))
    };
    let actual = base.actual();
    // The recorded kind and the Unknown gate come first, under every digest
    // kind: a `none` directory overlay must not commit into an unrelated
    // archive, and a record with no usable kind never commits without force.
    let meta = OverlayMeta::from_connection(conn)
        .map_err(|e| refuse(format!("cannot read overlay metadata: {e}")))?;
    match Recorded::from_meta(meta.as_ref()) {
        Recorded::Unknown => {
            return Err(refuse(
                "the overlay recorded no usable base kind (it was written by a pre-release \
                 build)"
                    .to_owned(),
            ))
        }
        Recorded::Kind { kind, .. } if kind != actual.kind() => {
            return Err(refuse(format!(
                "the commit target is of kind {} (the overlay recorded kind {})",
                actual.kind().as_str(),
                kind.as_str()
            )))
        }
        _ => {}
    }
    let (BaseKind::Archive, Some(BaseLocation::Local(path))) = (actual.kind(), actual.location())
    else {
        return Ok(());
    };
    let canonical = archive
        .canonicalize()
        .map_err(|e| refuse(format!("cannot resolve {}: {e}", archive.display())))?;
    // The commit names the mounted base when it resolves to the token's path,
    // or when the name it gives (parent resolved, the last component left as
    // named) is the token's path or the name the user typed: the file behind
    // that name may have been replaced or a symlink retargeted since.
    let named = crate::overlay_identity::named_path(archive);
    let names_base = &canonical == path
        || named.as_deref() == Some(path.as_path())
        || (named.is_some() && named == actual.typed_named);
    if !names_base {
        // An archive the token does not describe (a union's other member).
        return Ok(());
    }
    let metadata = std::fs::metadata(&canonical)
        .map_err(|e| refuse(format!("cannot stat {}: {e}", canonical.display())))?;
    if !metadata.is_file() {
        return Err(refuse(format!(
            "{} is no longer a regular file",
            canonical.display()
        )));
    }
    let same_file = match actual.file_id {
        Some(id) => crate::overlay_identity::FileId::of(&canonical) == Some(id),
        None => &canonical == path,
    };
    if !same_file {
        return Err(refuse(format!(
            "{} no longer is the archive that was recorded (it now resolves to {})",
            archive.display(),
            canonical.display()
        )));
    }
    let Some(meta) = meta else {
        return Ok(());
    };
    if kind_only(&meta) {
        return Ok(());
    }
    let (Some(size), Some(mtime)) = (meta.get("base_size"), meta.get("base_mtime_ns")) else {
        return Ok(());
    };
    // A commit journal is pending: recovery rolls the archive back to the state
    // the journal recorded BEFORE this commit writes, so that state is what the
    // recorded stamp must describe. A journal that describes another state
    // belongs to another archive; it is left unread by recovery and refused.
    match ratarmount_compress::commit_journal::pending(&canonical) {
        Ok(None) => {}
        Ok(Some(journal)) => {
            // The journal was started for one inode. A successor (a copy of
            // the interrupted bytes, a restored backup) has another, and
            // recovery would roll it back on content alone: refuse it.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if journal.ino != metadata.ino() || journal.dev != metadata.dev() {
                    return Err(refuse(format!(
                        "{} carries a commit journal that was started for another file \
                         (journal inode {}:{}, archive inode {}:{}); the journal was not applied",
                        canonical.display(),
                        journal.dev,
                        journal.ino,
                        metadata.dev(),
                        metadata.ino()
                    )));
                }
            }
            return if journal.len.to_string() == size && journal.mtime_ns.to_string() == mtime {
                Ok(())
            } else {
                Err(refuse(format!(
                    "{} carries a commit journal that was not started for the recorded base \
                     (it rolls back to size={},mtime_ns={}, size={size},mtime_ns={mtime} recorded); \
                     the journal was not applied",
                    canonical.display(),
                    journal.len,
                    journal.mtime_ns
                )))
            };
        }
        Err(e) => {
            return Err(refuse(format!(
                "cannot read the commit journal of {}: {e}",
                canonical.display()
            )))
        }
    }
    let now = ArchiveDigestStamp::read(&canonical)
        .map_err(|e| refuse(format!("cannot stat {}: {e}", canonical.display())))?;
    if now.size.to_string() != size || now.mtime_ns.to_string() != mtime {
        return Err(refuse(format!(
            "{} changed since it was recorded (size={},mtime_ns={} now, size={size},mtime_ns={mtime} recorded)",
            canonical.display(),
            now.size,
            now.mtime_ns
        )));
    }
    Ok(())
}

/// Offline `--commit-overlay` gate for a DB-backed overlay: the archive about
/// to be rewritten must still be the base recorded by the last create, commit
/// or refresh. Reads the overlay database read-only.
pub(crate) fn check_commit_base_offline(
    overlay: &Path,
    base: &ClassifiedBase,
    archive: &Path,
) -> std::result::Result<(), CommitBaseRefusal> {
    let db = overlay.join(HIDDEN_DB);
    let conn = Connection::open_with_flags(
        &db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| CommitBaseRefusal(format!("cannot open {}: {e}", db.display())))?;
    check_commit_base(&conn, base, archive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay_identity::BaseKind;
    use crate::{IndexProvenance, Opened, ServedKind, ServedLocation};
    use std::fs;
    use std::sync::Arc;

    fn meta_with(rows: &[(&str, &str)]) -> OverlayMeta {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::overlay_meta::META_SCHEMA)
            .unwrap();
        OverlayMeta::set_many(&conn, rows).unwrap();
        OverlayMeta::from_connection(&conn).unwrap().unwrap()
    }

    #[test]
    fn recorded_from_meta_cases() {
        assert_eq!(Recorded::from_meta(None), Recorded::Unrecorded);
        // A released overlay: format 1 with or without a kind.
        let m = meta_with(&[("format_version", "1")]);
        assert_eq!(Recorded::from_meta(Some(&m)), Recorded::Unrecorded);
        let m = meta_with(&[("format_version", "1"), ("base_kind", "archive")]);
        assert_eq!(
            Recorded::from_meta(Some(&m)),
            Recorded::Kind {
                kind: BaseKind::Archive,
                location: None
            }
        );
        // An unreleased build: format 2 needs a usable kind.
        let m = meta_with(&[("format_version", "2"), ("base_url", "")]);
        assert_eq!(Recorded::from_meta(Some(&m)), Recorded::Nothing);
        for kind in [None, Some("remote"), Some("junk")] {
            let mut rows = vec![("format_version", "2"), ("base_url", "/x.tar")];
            rows.extend(kind.map(|k| ("base_kind", k)));
            assert_eq!(
                Recorded::from_meta(Some(&meta_with(&rows))),
                Recorded::Unknown,
                "{kind:?}"
            );
        }
        let m = meta_with(&[
            ("format_version", "2"),
            ("base_kind", "git"),
            ("base_location", "local:/g"),
        ]);
        assert_eq!(
            Recorded::from_meta(Some(&m)),
            Recorded::Kind {
                kind: BaseKind::Git,
                location: Some(BaseLocation::Local("/g".into()))
            }
        );
    }

    /// One recorded or served base of the all-pairs table.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Shape {
        Git,
        DirL,
        DirL2,
        DirR,
        ArchL,
        ArchL2,
        ArchR,
    }

    struct Place {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
        dir2: PathBuf,
        archive: PathBuf,
        archive2: PathBuf,
    }

    impl Place {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().canonicalize().unwrap();
            let (dir, dir2) = (root.join("d"), root.join("d2"));
            for d in [&dir, &dir2] {
                fs::create_dir(d).unwrap();
                fs::write(d.join("f"), b"x").unwrap();
            }
            let (archive, archive2) = (root.join("a.tar"), root.join("a2.tar"));
            fs::write(&archive, b"bytes").unwrap();
            fs::write(&archive2, b"bytes").unwrap();
            Self {
                _tmp: tmp,
                dir,
                dir2,
                archive,
                archive2,
            }
        }

        fn kind_and_location(&self, shape: Shape) -> (BaseKind, BaseLocation) {
            match shape {
                Shape::Git => (BaseKind::Git, BaseLocation::Local(self.dir.clone())),
                Shape::DirL => (BaseKind::Dir, BaseLocation::Local(self.dir.clone())),
                Shape::DirL2 => (BaseKind::Dir, BaseLocation::Local(self.dir2.clone())),
                Shape::DirR => (BaseKind::Dir, BaseLocation::Remote("https://h/d".into())),
                Shape::ArchL => (BaseKind::Archive, BaseLocation::Local(self.archive.clone())),
                Shape::ArchL2 => (
                    BaseKind::Archive,
                    BaseLocation::Local(self.archive2.clone()),
                ),
                Shape::ArchR => (
                    BaseKind::Archive,
                    BaseLocation::Remote("https://h/a.tar".into()),
                ),
            }
        }

        fn token(&self, shape: Shape) -> ClassifiedBase {
            let (kind, location) = self.kind_and_location(shape);
            let (served, location) = match (kind, location) {
                (BaseKind::Git, BaseLocation::Local(p)) => (
                    ServedKind::Git {
                        tree: "tree1".into(),
                    },
                    ServedLocation::Local(p),
                ),
                (BaseKind::Dir, BaseLocation::Local(p)) => {
                    (ServedKind::Folder, ServedLocation::Local(p))
                }
                (BaseKind::Dir, BaseLocation::Remote(u)) => {
                    (ServedKind::Folder, ServedLocation::Remote(u))
                }
                (BaseKind::Archive, BaseLocation::Local(p)) => {
                    (ServedKind::Archive, ServedLocation::Local(p))
                }
                (BaseKind::Archive, BaseLocation::Remote(u)) => {
                    (ServedKind::Archive, ServedLocation::Remote(u))
                }
                (BaseKind::Git, BaseLocation::Remote(_)) => unreachable!(),
            };
            let source: Arc<dyn ratarmount_core::MountSource> =
                Arc::new(crate::FolderMountSource::new(&self.dir).unwrap());
            ClassifiedBase::for_tests(source, served, Some(location))
        }

        fn record(&self, shape: Shape, digest_kind: &str, digest: &str) -> OverlayMeta {
            let (kind, location) = self.kind_and_location(shape);
            let mut rows = vec![
                ("format_version", "2"),
                ("base_url", "x"),
                ("base_kind", kind.as_str()),
                ("base_digest_kind", digest_kind),
                ("base_digest", digest),
            ];
            let location = location.row();
            rows.push(("base_location", location.as_str()));
            meta_with(&rows)
        }
    }

    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    /// R6-2: the one rule over EVERY (recorded, served, digest kind, supplied)
    /// combination, written as an independent oracle: Unrecorded and Nothing
    /// agree; Unknown refuses; another kind refuses; `none` is kind-only;
    /// the same place (or any local move) compares content; a move between
    /// local and remote (or between two remotes) agrees only for a strong
    /// record that a supplied digest equals. Forced records are re-read and
    /// a second run passes.
    #[test]
    fn regression_base_shape_table_every_pair() {
        let place = Place::new();
        let shapes = [
            Shape::Git,
            Shape::DirL,
            Shape::DirL2,
            Shape::DirR,
            Shape::ArchL,
            Shape::ArchL2,
            Shape::ArchR,
        ];
        // Exhaustive: a new shape breaks this match until the table covers it.
        for shape in shapes {
            match shape {
                Shape::Git
                | Shape::DirL
                | Shape::DirL2
                | Shape::DirR
                | Shape::ArchL
                | Shape::ArchL2
                | Shape::ArchR => {}
            }
        }
        let is_local = |s: Shape| !matches!(s, Shape::DirR | Shape::ArchR);
        let mut refused = 0;
        for recorded in shapes {
            for served in shapes {
                if served == Shape::Git && recorded != Shape::Git {
                    // exercised below as a kind mismatch too
                }
                for digest_kind in ["none", "weak", "strong", "pending"] {
                    for supplied in [None, Some(D1), Some(D2)] {
                        let digest = match digest_kind {
                            "strong" => D1,
                            "pending" => "",
                            "none" => "none",
                            _ => "weak:x",
                        };
                        let meta = place.record(recorded, digest_kind, digest);
                        let token = place.token(served);
                        let probe = BaseProbe {
                            supplied,
                            extra_excludes: &[],
                        };
                        let got = shape_verdict(Some(&meta), token.actual(), &probe);
                        let (rk, _) = place.kind_and_location(recorded);
                        let (sk, _) = place.kind_and_location(served);
                        let want = if rk != sk {
                            Verdict::Refuse(String::new())
                        } else if digest_kind == "none" {
                            Verdict::Same
                        } else if recorded == served || (is_local(recorded) && is_local(served)) {
                            Verdict::Content
                        } else if digest_kind == "strong"
                            && supplied == Some(D1)
                            && rk == BaseKind::Archive
                        {
                            Verdict::Same
                        } else {
                            Verdict::Refuse(String::new())
                        };
                        let same_class = matches!(
                            (&got, &want),
                            (Verdict::Same, Verdict::Same)
                                | (Verdict::Content, Verdict::Content)
                                | (Verdict::Refuse(_), Verdict::Refuse(_))
                        );
                        assert!(
                            same_class,
                            "recorded {recorded:?} served {served:?} {digest_kind} {supplied:?}: got {got:?}, want {want:?}"
                        );
                        if let Verdict::Refuse(reason) = got {
                            refused += 1;
                            assert!(!reason.is_empty());
                            // Forced: the rows describe the served base, and a
                            // second run over them agrees.
                            let rows = forced_base_record(&meta, &token, &probe).unwrap();
                            let forced = meta.with_rows(&rows);
                            let again = shape_verdict(Some(&forced), token.actual(), &probe);
                            assert!(
                                !matches!(again, Verdict::Refuse(_)),
                                "recorded {recorded:?} served {served:?} {digest_kind} {supplied:?}: forced rows still refuse: {again:?}"
                            );
                            assert_eq!(
                                forced.get("base_kind"),
                                Some(token.actual().kind().as_str())
                            );
                        }
                    }
                }
            }
        }
        assert!(refused > 100, "the table exercised {refused} refusals");
        // Rows that need no digest kind.
        let token = place.token(Shape::ArchL);
        let probe = BaseProbe {
            supplied: None,
            extra_excludes: &[],
        };
        assert_eq!(shape_verdict(None, token.actual(), &probe), Verdict::Same);
        let nothing = meta_with(&[("format_version", "2"), ("base_url", "")]);
        assert_eq!(
            shape_verdict(Some(&nothing), token.actual(), &probe),
            Verdict::Same
        );
        let unknown = meta_with(&[
            ("format_version", "2"),
            ("base_url", "/x"),
            ("base_kind", "remote"),
        ]);
        assert!(matches!(
            shape_verdict(Some(&unknown), token.actual(), &probe),
            Verdict::Refuse(_)
        ));
    }

    /// Regression (R5 record, no `base_location` row): a strong archive record
    /// without a place compares content as before when the base is local, and
    /// needs the matching strong digest when the base is remote.
    #[test]
    fn regression_r5_absent_location_remote_needs_digest() {
        let place = Place::new();
        let r5 = meta_with(&[
            ("format_version", "2"),
            ("base_url", "x"),
            ("base_kind", "archive"),
            ("base_digest_kind", "strong"),
            ("base_digest", D1),
        ]);
        let probe = |supplied| BaseProbe {
            supplied,
            extra_excludes: &[],
        };
        let local = place.token(Shape::ArchL);
        assert_eq!(
            shape_verdict(Some(&r5), local.actual(), &probe(None)),
            Verdict::Content
        );
        let remote = place.token(Shape::ArchR);
        for (supplied, same) in [(None, false), (Some(D2), false), (Some(D1), true)] {
            let got = shape_verdict(Some(&r5), remote.actual(), &probe(supplied));
            assert_eq!(got == Verdict::Same, same, "supplied {supplied:?}: {got:?}");
            if !same {
                assert!(matches!(got, Verdict::Refuse(_)), "{got:?}");
            }
        }
    }

    /// Regression (R6-F5): a remote strong record D1 reopened over a local copy
    /// whose index CACHES D1 accepted an explicitly wrong `--base-digest D2`,
    /// because the cached digest was consulted next to the supplied one. A
    /// supplied digest now decides alone; the cache answers only when nothing
    /// was supplied.
    #[test]
    fn regression_supplied_digest_is_not_overridden_by_cache() {
        let place = Place::new();
        let index = place.archive.with_extension("tar.index.sqlite");
        Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        ratarmount_index::cached_archive_digest_with(&place.archive, Some(&index), |_| {
            Ok("1".repeat(64))
        })
        .unwrap();
        let recorded = place.record(Shape::ArchR, "strong", D1);
        let local = ClassifiedBase::mint(Opened {
            source: Arc::new(crate::FolderMountSource::new(&place.dir).unwrap()),
            kind: ServedKind::Archive,
            inputs: Vec::new(),
            location: Some(ServedLocation::Local(place.archive.clone())),
            index: IndexProvenance::None,
            sidecar_candidate: Some(index),
            fetched: false,
            keep_alive: Box::new(()),
        })
        .unwrap();
        let verdict = |supplied| {
            shape_verdict(
                Some(&recorded),
                local.actual(),
                &BaseProbe {
                    supplied,
                    extra_excludes: &[],
                },
            )
        };
        assert_eq!(verdict(None), Verdict::Same, "the cache confirms D1");
        assert_eq!(verdict(Some(D1)), Verdict::Same);
        assert!(
            matches!(verdict(Some(D2)), Verdict::Refuse(_)),
            "a wrong supplied digest must not be rescued by the cache: {:?}",
            verdict(Some(D2))
        );
    }

    /// Regression (R6-F5, review nit): only an archive moved between local and
    /// remote is rescued by a matching strong digest; a directory is not.
    #[test]
    fn regression_digest_rescue_is_archive_only() {
        let place = Place::new();
        let recorded = place.record(Shape::DirR, "strong", D1);
        let local = place.token(Shape::DirL);
        let got = shape_verdict(
            Some(&recorded),
            local.actual(),
            &BaseProbe {
                supplied: Some(D1),
                extra_excludes: &[],
            },
        );
        assert!(matches!(got, Verdict::Refuse(_)), "{got:?}");
    }

    /// Regression: a forced change with nothing supplied drops a directory or
    /// archive to kind-only (`none`) with no weak digest, no stamp and no
    /// "cannot measure base" error; a supplied digest records strong/supplied.
    #[test]
    fn regression_forced_none_records_kind_only_dir_and_archive() {
        let place = Place::new();
        for (recorded, served) in [
            (Shape::ArchL, Shape::DirL),
            (Shape::DirL, Shape::ArchL),
            (Shape::ArchR, Shape::DirR),
        ] {
            let meta = place.record(recorded, "strong", D1);
            let token = place.token(served);
            let rows = forced_base_record(
                &meta,
                &token,
                &BaseProbe {
                    supplied: None,
                    extra_excludes: &[],
                },
            )
            .unwrap();
            assert_eq!(rows["base_digest_kind"], "none");
            assert_eq!(rows["base_digest"], "none");
            for key in [
                "base_weak_digest",
                "base_size",
                "base_mtime_ns",
                "base_digest_source",
            ] {
                assert!(!rows.contains_key(key), "{recorded:?}->{served:?}: {key}");
            }
            assert!(rows.contains_key("base_mismatch_forced_at"));
            let supplied = forced_base_record(
                &meta,
                &token,
                &BaseProbe {
                    supplied: Some(D2),
                    extra_excludes: &[],
                },
            )
            .unwrap();
            assert_eq!(supplied["base_digest_kind"], "strong");
            assert_eq!(supplied["base_digest"], D2);
            assert_eq!(supplied["base_digest_source"], "supplied");
        }
    }

    /// The file-type check of the commit gate: a directory at the archive
    /// path is refused, a foreign archive or a non-archive token passes.
    #[test]
    fn check_commit_base_file_type_and_scope() {
        let place = Place::new();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::overlay_meta::META_SCHEMA)
            .unwrap();
        OverlayMeta::set_many(
            &conn,
            &[
                ("format_version", "2"),
                ("base_digest_kind", "none"),
                ("base_kind", "archive"),
            ],
        )
        .unwrap();
        let token = place.token(Shape::ArchL);
        check_commit_base(&conn, &token, &place.archive).unwrap();
        // A different archive than the one the token describes: not this base.
        check_commit_base(&conn, &token, &place.archive2).unwrap();
        // A directory swapped in at the same path, even under `none`.
        let moved = place.archive.with_extension("kept");
        fs::rename(&place.archive, &moved).unwrap();
        fs::create_dir(&place.archive).unwrap();
        let err = check_commit_base(&conn, &token, &place.archive).unwrap_err();
        assert!(err.0.contains("no longer a regular file"), "{err}");
        assert!(err.0.contains("--force-base-mismatch"), "{err}");
        // A token of another kind than the record is the kind gate's to refuse
        // (R6-G4); with a matching record a non-archive token has no stamp.
        let err = check_commit_base(&conn, &place.token(Shape::DirL), &place.archive).unwrap_err();
        assert!(err.0.contains("kind"), "{err}");
    }

    /// Regression (R6-G4, #2): the commit gate compares the recorded KIND under
    /// every digest kind (a `none` directory overlay does not commit into an
    /// archive) and refuses an Unknown record; a recorded archive passes.
    #[test]
    fn check_commit_base_kind_and_unknown_gate() {
        let place = Place::new();
        let token = place.token(Shape::ArchL);
        let conn_with = |rows: &[(&str, &str)]| {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(crate::overlay_meta::META_SCHEMA)
                .unwrap();
            OverlayMeta::set_many(&conn, rows).unwrap();
            conn
        };
        for kind in ["directory", "git"] {
            let conn = conn_with(&[
                ("format_version", "2"),
                ("base_digest_kind", "none"),
                ("base_kind", kind),
            ]);
            let err = check_commit_base(&conn, &token, &place.archive).unwrap_err();
            assert!(err.0.contains(kind) && err.0.contains("archive"), "{err}");
            assert!(err.0.contains("--force-base-mismatch"), "{err}");
        }
        let unknown = conn_with(&[("format_version", "2"), ("base_url", "/x.tar")]);
        let err = check_commit_base(&unknown, &token, &place.archive).unwrap_err();
        assert!(err.0.contains("no usable base kind"), "{err}");
        let archive = conn_with(&[
            ("format_version", "2"),
            ("base_digest_kind", "none"),
            ("base_kind", "archive"),
        ]);
        check_commit_base(&archive, &token, &place.archive).unwrap();
    }
}
