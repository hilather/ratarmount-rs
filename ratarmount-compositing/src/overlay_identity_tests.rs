//! R6-2: the token-based create/reopen/commit rules, driven through
//! `WriteOverlay::open` and the commit paths with a real tar on disk.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::MountSource;
use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};

use crate::overlay_identity::BaseLocation;
use crate::{
    BaseDigestRequest, ClassifiedBase, CommitOverlayOptions, CreateOptions, OverlayMeta,
    ServedKind, ServedLocation, WriteOverlay, HIDDEN_DB,
};

fn have_gnu_tar() -> bool {
    std::process::Command::new("tar")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("GNU tar"))
}

fn write_tar(path: &Path, members: &[(&str, &[u8])]) {
    let members: Vec<_> = members
        .iter()
        .map(|(name, bytes)| UstarMember {
            path: name,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        })
        .collect();
    let mut file = fs::File::create(path).unwrap();
    write_ustar_members(&mut file, &members).unwrap();
    write_tar_eof(&mut file).unwrap();
}

fn open_tar(path: &Path) -> Arc<dyn MountSource> {
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..Default::default()
    };
    Arc::new(
        ratarmount_formats_tar::SqliteIndexedTar::create_index(
            path, path, None, &opts, "test", &mut None,
        )
        .expect("index tar"),
    )
}

fn archive_token(archive: &Path) -> ClassifiedBase {
    ClassifiedBase::for_tests(
        open_tar(archive),
        ServedKind::Archive,
        Some(ServedLocation::Local(archive.to_path_buf())),
    )
}

struct Fixture {
    _tmp: tempfile::TempDir,
    archive: PathBuf,
    overlay: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let archive = root.join("base.tar");
        write_tar(&archive, &[("first", b"first member")]);
        Self {
            overlay: root.join("overlay"),
            archive,
            _tmp: tmp,
        }
    }

    fn open(&self, digest: BaseDigestRequest, force: bool) -> WriteOverlay {
        let token = archive_token(&self.archive);
        WriteOverlay::open(
            &token,
            token.source(),
            &self.overlay,
            &CreateOptions {
                base_digest: digest,
                force_base_mismatch: force,
                ..Default::default()
            },
        )
        .unwrap()
    }

    /// A different valid tar at the same path (another size and content).
    fn swap_for_other_tar(&self) -> Vec<u8> {
        write_tar(
            &self.archive,
            &[("other", b"a different base"), ("more", b"x")],
        );
        fs::read(&self.archive).unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
enum Path_ {
    /// `commit_live` (interval / explicit).
    Live,
    /// `commit_atomic` (on-exit).
    OnExit,
}

fn commit(ov: &WriteOverlay, archive: &Path, path: Path_) -> crate::write_overlay::Result<bool> {
    match path {
        Path_::Live => ov.commit_live(archive, |p| Ok(open_tar(p))),
        Path_::OnExit => ov.commit_atomic(archive),
    }
}

fn read_member(src: &dyn MountSource, path: &str) -> Vec<u8> {
    let fi = src
        .lookup(path, 0)
        .unwrap_or_else(|| panic!("missing {path}"));
    src.read(&fi, fi.size as usize, 0).expect("read member")
}

/// Regression: a base replaced by a DIFFERENT VALID TAR between two commits
/// was rewritten and then re-baselined (commit two persisted before any
/// check). Refused BEFORE persisting on the live and on-exit paths: the
/// archive bytes, the overlay data and the mount's reads are untouched, the
/// refusal names the flag, no new baseline is recorded, and the mount is not
/// failed closed (the interval stays on).
#[test]
fn regression_base_swapped_between_commits_refused_by_next_gate() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let ov = fx.open(BaseDigestRequest::Compute, false);
        fs::write(ov.root().join("one"), b"one").unwrap();
        assert!(commit(&ov, &fx.archive, path).unwrap(), "{path:?}");
        let recorded = ov.meta_for_tests();
        let swapped = fx.swap_for_other_tar();
        fs::write(ov.root().join("two"), b"two").unwrap();
        let err = commit(&ov, &fx.archive, path).unwrap_err().to_string();
        assert!(err.contains("--force-base-mismatch"), "{path:?}: {err}");
        assert!(err.contains("not written"), "{path:?}: {err}");
        assert_eq!(fs::read(&fx.archive).unwrap(), swapped, "{path:?}");
        assert!(
            ov.root().join("two").exists(),
            "{path:?}: overlay data kept"
        );
        assert!(!ov.interval_disabled(), "{path:?}: not failed closed");
        // The mount still answers (the file under it was swapped, so only the
        // absence of an error is meaningful, not the bytes).
        assert!(ov.lookup("/one", 0).is_some(), "{path:?}");
        let after = ov.meta_for_tests();
        for key in ["base_size", "base_mtime_ns", "base_digest", "base_location"] {
            assert_eq!(recorded.get(key), after.get(key), "{path:?}: {key}");
        }
    }
}

/// A directory swapped in at the archive path is refused under every digest
/// kind, `none` included (the token's kind is static, so only a fresh file
/// type check can see it); a different valid tar under `none` is accepted
/// (kind-only by definition).
#[test]
fn regression_swapped_directory_refused_and_none_accepts_a_valid_tar() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for digest in [BaseDigestRequest::Compute, BaseDigestRequest::None] {
        let fx = Fixture::new();
        let ov = fx.open(digest.clone(), false);
        fs::write(ov.root().join("one"), b"one").unwrap();
        assert!(ov.commit_atomic(&fx.archive).unwrap());
        let copy = fx.archive.with_extension("kept");
        fs::rename(&fx.archive, &copy).unwrap();
        fs::create_dir(&fx.archive).unwrap();
        fs::write(ov.root().join("two"), b"two").unwrap();
        // Refused before anything is written (format detection fails first
        // for a directory; the identity check's own file-type refusal is
        // unit-tested in `overlay_gate`).
        assert!(ov.commit_atomic(&fx.archive).is_err(), "{digest:?}");
        fs::remove_dir(&fx.archive).unwrap();
        fs::rename(&copy, &fx.archive).unwrap();
        if digest == BaseDigestRequest::None {
            fx.swap_for_other_tar();
            assert!(
                ov.commit_atomic(&fx.archive).unwrap(),
                "none is kind-only: a different valid tar is accepted"
            );
        }
    }
}

/// `--force-base-mismatch` commits over a swapped base and records the new
/// baseline (the refresh after the write).
#[test]
fn forced_commit_over_swapped_base_records_new_baseline() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, true);
    fs::write(ov.root().join("one"), b"one").unwrap();
    assert!(ov.commit_atomic(&fx.archive).unwrap());
    fx.swap_for_other_tar();
    fs::write(ov.root().join("two"), b"two").unwrap();
    assert!(ov.commit_atomic(&fx.archive).unwrap());
    let stamp = ratarmount_index::ArchiveDigestStamp::read(&fx.archive).unwrap();
    assert_eq!(
        ov.meta_for_tests().get("base_size"),
        Some(stamp.size.to_string().as_str())
    );
}

/// Regression: the commit check compares only the rows the last create,
/// commit or refresh wrote. A `--base-digest D0` given at the mount never
/// overrides a changed stamp later.
#[test]
fn regression_commit_check_ignores_mount_supplied_digest() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let d0 = format!(
        "sha256:{}",
        ratarmount_index::sha256_hex(&fs::read(&fx.archive).unwrap())
    );
    let ov = fx.open(BaseDigestRequest::Supplied(d0), false);
    fx.swap_for_other_tar();
    fs::write(ov.root().join("one"), b"one").unwrap();
    let err = ov.commit_atomic(&fx.archive).unwrap_err().to_string();
    assert!(err.contains("--force-base-mismatch"), "{err}");
}

/// Regression: after commit one records D1, an UNCHANGED commit two is
/// compared with D1's stamp rows, not the retained mount digest D0.
#[test]
fn regression_two_unchanged_commits_both_pass() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let d0 = format!(
            "sha256:{}",
            ratarmount_index::sha256_hex(&fs::read(&fx.archive).unwrap())
        );
        let ov = fx.open(BaseDigestRequest::Supplied(d0.clone()), false);
        fs::write(ov.root().join("one"), b"one").unwrap();
        assert!(commit(&ov, &fx.archive, path).unwrap());
        assert_ne!(
            ov.meta_for_tests().base_digest(),
            Some(d0.as_str()),
            "D1 recorded"
        );
        fs::write(ov.root().join("two"), b"two").unwrap();
        assert!(commit(&ov, &fx.archive, path).unwrap(), "{path:?}");
    }
}

/// Regression: the FIRST commit after create checks against the creation
/// rows, not only later ones.
#[test]
fn regression_first_commit_after_create_checks_creation_rows() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let ov = fx.open(BaseDigestRequest::Compute, false);
        assert!(
            ov.meta_for_tests().get("base_size").is_some(),
            "creation stamp rows"
        );
        let swapped = fx.swap_for_other_tar();
        fs::write(ov.root().join("one"), b"one").unwrap();
        assert!(commit(&ov, &fx.archive, path).is_err(), "{path:?}");
        assert_eq!(fs::read(&fx.archive).unwrap(), swapped);
    }
}

/// Regression: a refused commit does not fail the mount closed. After the
/// original archive is restored (same bytes, same mtime) the next commit
/// goes through.
#[test]
fn regression_commit_check_refusal_does_not_fail_closed_mount() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    let original = fs::read(&fx.archive).unwrap();
    let mtime = fs::metadata(&fx.archive).unwrap().modified().unwrap();
    fx.swap_for_other_tar();
    fs::write(ov.root().join("one"), b"one").unwrap();
    assert!(ov.commit_live(&fx.archive, |p| Ok(open_tar(p))).is_err());
    assert!(!ov.interval_disabled());
    assert!(ov.lookup("/first", 0).is_some());
    fs::write(&fx.archive, &original).unwrap();
    fs::File::options()
        .write(true)
        .open(&fx.archive)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert!(ov.commit_live(&fx.archive, |p| Ok(open_tar(p))).unwrap());
    assert_eq!(read_member(&ov, "/one"), b"one");
}

/// Regression: the commit refresh re-points the mount's token and the
/// `base_location` row at the archive that was written (no second open).
#[test]
fn regression_commit_refresh_reuses_mount_token() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    let before = ov.identity_for_tests().unwrap();
    fs::write(ov.root().join("one"), b"one").unwrap();
    assert!(ov.commit_atomic(&fx.archive).unwrap());
    let after = ov.identity_for_tests().unwrap();
    assert!(
        Arc::ptr_eq(&before.source(), &after.source()),
        "same source"
    );
    assert_eq!(
        after.actual().location(),
        Some(&BaseLocation::Local(fx.archive.clone()))
    );
    assert_eq!(
        ov.meta_for_tests().get("base_location"),
        Some(format!("local:{}", fx.archive.display()).as_str())
    );
    assert_eq!(ov.meta_for_tests().get("base_kind"), Some("archive"));
}

/// Regression: a Folder-first union commits to an archive that is NOT the
/// overlay's base; refresh writes no base rows and does not fail the commit,
/// and the swap check passes for it (the token describes a directory).
#[test]
fn regression_commit_refresh_non_archive_token_leaves_base_rows() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let folder = fx.overlay.parent().unwrap().join("folder");
    fs::create_dir(&folder).unwrap();
    let token = ClassifiedBase::for_tests(
        Arc::new(crate::FolderMountSource::new(&folder).unwrap()),
        ServedKind::Folder,
        Some(ServedLocation::Local(folder.clone())),
    );
    let ov = WriteOverlay::open(
        &token,
        token.source(),
        &fx.overlay,
        &CreateOptions::default(),
    )
    .unwrap();
    let rows: Vec<_> = ["base_kind", "base_location", "base_url", "base_size"]
        .iter()
        .map(|k| ov.meta_for_tests().get(k).map(str::to_owned))
        .collect();
    fs::write(ov.root().join("one"), b"one").unwrap();
    assert!(ov.commit_atomic(&fx.archive).unwrap());
    let after: Vec<_> = ["base_kind", "base_location", "base_url", "base_size"]
        .iter()
        .map(|k| ov.meta_for_tests().get(k).map(str::to_owned))
        .collect();
    assert_eq!(rows, after);
    assert_eq!(after[0].as_deref(), Some("directory"));
}

/// Regression: a released (format 1) overlay that already gained a
/// `base_kind` row is refreshed like any other and keeps `format_version=1`.
#[test]
fn regression_commit_refresh_repoints_legacy_overlay_with_kind() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::None, false));
    {
        let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
        for key in ["base_location", "base_digest_kind", "base_digest"] {
            OverlayMeta::remove(&conn, key).unwrap();
        }
        OverlayMeta::set(&conn, "format_version", "1").unwrap();
    }
    let ov = fx.open(BaseDigestRequest::None, false);
    fs::write(ov.root().join("one"), b"one").unwrap();
    assert!(ov.commit_atomic(&fx.archive).unwrap());
    let meta = ov.meta_for_tests();
    assert_eq!(meta.get("format_version"), Some("1"));
    assert_eq!(
        meta.get("base_location"),
        Some(format!("local:{}", fx.archive.display()).as_str())
    );
}

/// Offline `--commit-overlay` over a DB-backed overlay: the same check runs
/// before the splice; a forced commit goes through.
#[test]
fn regression_offline_commit_checks_the_recorded_base() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    fs::write(ov.root().join("one"), b"one").unwrap();
    drop(ov);
    let swapped = fx.swap_for_other_tar();
    let token = archive_token(&fx.archive);
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    let err = crate::commit_overlay_checked(&fx.overlay, &fx.archive, &token, &opts)
        .unwrap_err()
        .to_string();
    assert!(err.contains("--force-base-mismatch"), "{err}");
    assert_eq!(fs::read(&fx.archive).unwrap(), swapped);
    let forced = CommitOverlayOptions {
        force_base_mismatch: true,
        ..opts
    };
    assert!(crate::commit_overlay_checked(&fx.overlay, &fx.archive, &token, &forced).unwrap());
}

/// A raw overlay DIRECTORY (no database) commits through its own entry, which
/// says no identity was checked; with a database it refuses.
#[test]
fn regression_raw_dir_commit_refuses_when_overlay_db_exists() {
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::None, false));
    let err = crate::commit_overlay_raw_dir(&fx.overlay, &fx.archive, &Default::default())
        .unwrap_err()
        .to_string();
    assert!(err.contains(HIDDEN_DB), "{err}");
}

#[test]
fn regression_raw_dir_commit_succeeds_and_reports_no_identity_check() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    fs::create_dir(&fx.overlay).unwrap();
    fs::write(fx.overlay.join("added"), b"raw").unwrap();
    let done = crate::commit_overlay_raw_dir(
        &fx.overlay,
        &fx.archive,
        &CommitOverlayOptions {
            yes: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(done.committed);
    assert!(!done.identity_checked);
    assert_eq!(
        read_member(open_tar(&fx.archive).as_ref(), "/added"),
        b"raw"
    );
    // And the checked entry refuses a raw directory.
    let token = archive_token(&fx.archive);
    assert!(
        crate::commit_overlay_checked(&fx.overlay, &fx.archive, &token, &Default::default())
            .is_err()
    );
}

fn folder_token(dir: &Path) -> ClassifiedBase {
    ClassifiedBase::for_tests(
        Arc::new(crate::FolderMountSource::new(dir).unwrap()),
        ServedKind::Folder,
        Some(ServedLocation::Local(dir.to_path_buf())),
    )
}

fn open_with(
    token: &ClassifiedBase,
    overlay: &Path,
    digest: BaseDigestRequest,
    force: bool,
) -> crate::write_overlay::Result<WriteOverlay> {
    WriteOverlay::open(
        token,
        token.source(),
        overlay,
        &CreateOptions {
            base_digest: digest,
            force_base_mismatch: force,
            ..Default::default()
        },
    )
}

fn read_rows(overlay: &Path, keys: &[&str]) -> Vec<Option<String>> {
    let meta = OverlayMeta::read(overlay).unwrap().unwrap();
    keys.iter()
        .map(|k| meta.get(k).map(str::to_owned))
        .collect()
}

/// Regression: a `--base-digest none` overlay compared nothing, so a base of
/// another kind (a directory where an archive was recorded) reopened without
/// force. The kind is compared under every digest kind; one force records
/// the base now in use, kind-only.
#[test]
fn regression_none_overlay_refuses_kind_swap_in_reopen() {
    for digest in [BaseDigestRequest::None, BaseDigestRequest::Compute] {
        let fx = Fixture::new();
        drop(fx.open(digest.clone(), false));
        let folder = fx.overlay.parent().unwrap().join("folder");
        fs::create_dir(&folder).unwrap();
        let token = folder_token(&folder);
        let err = open_with(&token, &fx.overlay, digest.clone(), false)
            .err()
            .expect("kind swap must refuse")
            .to_string();
        assert!(err.contains("--force-base-mismatch"), "{digest:?}: {err}");
        assert!(err.contains("directory base"), "{digest:?}: {err}");
        drop(open_with(&token, &fx.overlay, digest.clone(), true).unwrap());
        let rows = read_rows(&fx.overlay, &["base_kind", "base_digest_kind"]);
        assert_eq!(rows[0].as_deref(), Some("directory"));
        assert_eq!(
            rows[1].as_deref(),
            Some("none"),
            "forced drops to kind-only"
        );
        // The next unforced open agrees.
        drop(open_with(&token, &fx.overlay, digest, false).unwrap());
    }
}

/// An overlay from a released build (no `meta` table at all) opens without
/// force, gains the kind, place and url on that first `-w` open (no digest),
/// and from then on refuses another kind.
#[test]
fn released_overlay_gains_kind_on_first_open_then_refuses_swap() {
    let fx = Fixture::new();
    drop(WriteOverlay::new(open_tar(&fx.archive), &fx.overlay).unwrap());
    {
        let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
        conn.execute_batch("DROP TABLE meta").unwrap();
    }
    assert!(OverlayMeta::read(&fx.overlay).unwrap().is_none());
    let token = archive_token(&fx.archive);
    drop(open_with(&token, &fx.overlay, BaseDigestRequest::Compute, false).unwrap());
    let rows = read_rows(
        &fx.overlay,
        &[
            "format_version",
            "base_kind",
            "base_location",
            "base_url",
            "base_digest_kind",
        ],
    );
    assert_eq!(rows[0].as_deref(), Some("1"));
    assert_eq!(rows[1].as_deref(), Some("archive"));
    assert_eq!(
        rows[2].as_deref(),
        Some(format!("local:{}", fx.archive.display()).as_str())
    );
    assert_eq!(rows[3], None, "for_tests names no url");
    assert_eq!(rows[4], None, "no digest is written for a released overlay");
    let folder = fx.overlay.parent().unwrap().join("folder");
    fs::create_dir(&folder).unwrap();
    let err = open_with(
        &folder_token(&folder),
        &fx.overlay,
        BaseDigestRequest::Compute,
        false,
    )
    .err()
    .expect("kind swap on a released overlay that gained a kind")
    .to_string();
    assert!(err.contains("--force-base-mismatch"), "{err}");
}

/// Regression: an overlay from an unreleased build with format_version 2 and
/// no usable kind (absent, or the old `remote`) is Unknown: refused naming
/// the flag; one force records the base and later opens pass.
#[test]
fn regression_format2_without_base_kind_is_unknown() {
    for old_kind in [None, Some("remote")] {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::None, false));
        {
            let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
            for key in ["base_kind", "base_location"] {
                OverlayMeta::remove(&conn, key).unwrap();
            }
            OverlayMeta::set(&conn, "base_url", "/some/base.tar").unwrap();
            if let Some(kind) = old_kind {
                OverlayMeta::set(&conn, "base_kind", kind).unwrap();
            }
        }
        let token = archive_token(&fx.archive);
        let err = open_with(&token, &fx.overlay, BaseDigestRequest::None, false)
            .err()
            .expect("Unknown must refuse")
            .to_string();
        assert!(err.contains("--force-base-mismatch"), "{old_kind:?}: {err}");
        assert!(err.contains("no usable base kind"), "{old_kind:?}: {err}");
        drop(open_with(&token, &fx.overlay, BaseDigestRequest::None, true).unwrap());
        drop(open_with(&token, &fx.overlay, BaseDigestRequest::None, false).unwrap());
        assert_eq!(
            read_rows(&fx.overlay, &["base_kind"])[0].as_deref(),
            Some("archive")
        );
    }
}

/// An archive recorded with a strong supplied digest at a remote location
/// reopens over a local copy only when the same SHA-256 is supplied; the
/// accepted reopen moves the recorded place (and stamp) to the local copy.
#[test]
fn remote_strong_record_reopens_over_local_copy_only_with_matching_digest() {
    let fx = Fixture::new();
    let digest = format!(
        "sha256:{}",
        ratarmount_index::sha256_hex(&fs::read(&fx.archive).unwrap())
    );
    let remote = ClassifiedBase::for_tests(
        open_tar(&fx.archive),
        ServedKind::Archive,
        Some(ServedLocation::Remote("https://h.example/a.tar".into())),
    );
    drop(
        open_with(
            &remote,
            &fx.overlay,
            BaseDigestRequest::Supplied(digest.clone()),
            false,
        )
        .unwrap(),
    );
    let local = archive_token(&fx.archive);
    let wrong = format!("sha256:{}", "2".repeat(64));
    for (request, label) in [
        (BaseDigestRequest::Compute, "nothing supplied"),
        (BaseDigestRequest::Supplied(wrong), "wrong digest"),
        (BaseDigestRequest::None, "none requested"),
    ] {
        assert!(
            open_with(&local, &fx.overlay, request, false).is_err(),
            "{label}"
        );
    }
    drop(
        open_with(
            &local,
            &fx.overlay,
            BaseDigestRequest::Supplied(digest.clone()),
            false,
        )
        .unwrap(),
    );
    let rows = read_rows(
        &fx.overlay,
        &[
            "base_location",
            "base_size",
            "base_digest",
            "base_digest_kind",
        ],
    );
    assert_eq!(
        rows[0].as_deref(),
        Some(format!("local:{}", fx.archive.display()).as_str())
    );
    assert!(rows[1].is_some(), "the local stamp is recorded");
    assert_eq!(rows[2].as_deref(), Some(digest.as_str()), "digest kept");
    assert_eq!(rows[3].as_deref(), Some("strong"));
    // And it stays reopenable at the new place.
    drop(
        open_with(
            &local,
            &fx.overlay,
            BaseDigestRequest::Supplied(digest),
            false,
        )
        .unwrap(),
    );
}

/// Regression: `repo@stable` accepted over a recorded `repo@main` (equal tree
/// and repository path) updates `base_url`; a later reopen with the new
/// selector is unchanged. The rewrite happens when the redacted URL OR the
/// place differs.
#[test]
fn regression_repo_stable_over_main_updates_base_url() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let repo = root.join("repo");
    fs::create_dir(&repo).unwrap();
    let git = |selector: &str| {
        ClassifiedBase::mint(crate::Opened {
            source: Arc::new(crate::FolderMountSource::new(&repo).unwrap()),
            kind: ServedKind::Git {
                tree: "tree-one".into(),
            },
            inputs: vec![format!("{}@{selector}", repo.display())],
            location: Some(ServedLocation::Local(repo.clone())),
            index: crate::IndexProvenance::None,
            sidecar_candidate: None,
            fetched: false,
            keep_alive: Box::new(()),
        })
        .unwrap()
    };
    let overlay = root.join("overlay");
    let url = |selector: &str| format!("{}@{selector}", repo.display());
    drop(open_with(&git("main"), &overlay, BaseDigestRequest::Compute, false).unwrap());
    assert_eq!(
        read_rows(&overlay, &["base_url"])[0].as_deref(),
        Some(url("main").as_str())
    );
    drop(open_with(&git("stable"), &overlay, BaseDigestRequest::Compute, false).unwrap());
    assert_eq!(
        read_rows(&overlay, &["base_url"])[0].as_deref(),
        Some(url("stable").as_str())
    );
    // A different tree is still a different base.
    let other = ClassifiedBase::mint(crate::Opened {
        source: Arc::new(crate::FolderMountSource::new(&repo).unwrap()),
        kind: ServedKind::Git {
            tree: "tree-two".into(),
        },
        inputs: vec![url("main")],
        location: Some(ServedLocation::Local(repo.clone())),
        index: crate::IndexProvenance::None,
        sidecar_candidate: None,
        fetched: false,
        keep_alive: Box::new(()),
    })
    .unwrap();
    assert!(open_with(&other, &overlay, BaseDigestRequest::Compute, false).is_err());
}
