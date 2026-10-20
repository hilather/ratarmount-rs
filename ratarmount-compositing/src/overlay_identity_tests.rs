#![allow(clippy::disallowed_methods)]
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

/// Regression (R6-F2): the mounted `base.tar` replaced by a SYMLINK to another
/// valid tar made the canonical path differ from the token's, so the commit
/// guard passed and committed against the replacement. Refused on the live and
/// on-exit paths, with the archive untouched.
#[cfg(unix)]
#[test]
fn regression_base_replaced_by_symlink_refused() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let ov = fx.open(BaseDigestRequest::Compute, false);
        fs::write(ov.root().join("one"), b"one").unwrap();
        let other = fx.archive.with_file_name("other.tar");
        write_tar(&other, &[("other", b"a different base"), ("more", b"x")]);
        fs::remove_file(&fx.archive).unwrap();
        std::os::unix::fs::symlink(&other, &fx.archive).unwrap();
        let before = fs::read(&other).unwrap();
        let err = commit(&ov, &fx.archive, path).unwrap_err().to_string();
        assert!(err.contains("--force-base-mismatch"), "{path:?}: {err}");
        assert_eq!(fs::read(&other).unwrap(), before, "{path:?}: untouched");
    }
}

fn sha(path: &Path) -> String {
    format!(
        "sha256:{}",
        ratarmount_index::sha256_hex(&fs::read(path).unwrap())
    )
}

/// Regression (R6-F3): reopen used the old stamp verifier, so a byte-identical
/// local copy of a strong-digest archive (another path, another mtime) failed
/// even though the supplied SHA-256 matched. Every gate shares one comparator.
#[test]
fn regression_reopen_byte_identical_copy_with_other_mtime_accepted_by_digest() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let digest = sha(&fx.archive);
    drop(
        open_with(
            &archive_token(&fx.archive),
            &fx.overlay,
            BaseDigestRequest::Supplied(digest.clone()),
            false,
        )
        .unwrap(),
    );
    let copy = fx.archive.with_file_name("copy.tar");
    fs::copy(&fx.archive, &copy).unwrap();
    fs::File::options()
        .write(true)
        .open(&copy)
        .unwrap()
        .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000))
        .unwrap();
    open_with(
        &archive_token(&copy),
        &fx.overlay,
        BaseDigestRequest::Supplied(digest.clone()),
        false,
    )
    .expect("a byte-identical copy confirmed by the supplied digest reopens");
    // A wrong supplied digest still refuses.
    let wrong = format!("sha256:{}", "2".repeat(64));
    assert!(open_with(
        &archive_token(&copy),
        &fx.overlay,
        BaseDigestRequest::Supplied(wrong),
        false
    )
    .is_err());
}

/// Regression (R6-F3): an accepted local -> remote relocation kept the local
/// stamp rows, so the NEXT remote reopen compared a stamp that cannot be read
/// and failed with "unavailable (local archive missing)".
#[test]
fn regression_accepted_remote_relocation_drops_local_stamp() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let digest = sha(&fx.archive);
    drop(
        open_with(
            &archive_token(&fx.archive),
            &fx.overlay,
            BaseDigestRequest::Supplied(digest.clone()),
            false,
        )
        .unwrap(),
    );
    let remote = || {
        ClassifiedBase::for_tests(
            open_tar(&fx.archive),
            ServedKind::Archive,
            Some(ServedLocation::Remote("https://h.example/base.tar".into())),
        )
    };
    drop(
        open_with(
            &remote(),
            &fx.overlay,
            BaseDigestRequest::Supplied(digest.clone()),
            false,
        )
        .expect("accepted by the strong digest"),
    );
    drop(
        open_with(
            &remote(),
            &fx.overlay,
            BaseDigestRequest::Supplied(digest.clone()),
            false,
        )
        .expect("the next remote reopen agrees"),
    );
    let meta = crate::OverlayMeta::read(&fx.overlay).unwrap().unwrap();
    for key in ["base_size", "base_mtime_ns", "base_local_path"] {
        assert_eq!(meta.get(key), None, "{key}");
    }
}

/// Regression (R6-F6): a sole-bind `rclone+remote:path` / `restic:/repo` base
/// has no `://`, so creation took its typed text for a local path, looked for
/// a cached digest of a file that does not exist and failed. The classified
/// (remote) location decides, not the shape of the text.
#[test]
fn regression_remote_base_without_scheme_creates_without_digest_lookup() {
    for typed in ["rclone+remote:path/base.tar", "restic:/repo"] {
        let fx = Fixture::new();
        let token = ClassifiedBase::mint(crate::Opened {
            source: open_tar(&fx.archive),
            kind: ServedKind::Archive,
            inputs: vec![typed.to_owned()],
            location: Some(ServedLocation::Remote(typed.to_owned())),
            index: crate::IndexProvenance::None,
            sidecar_candidate: None,
            fetched: false,
            keep_alive: Box::new(()),
        })
        .unwrap();
        for digest in [BaseDigestRequest::Compute, BaseDigestRequest::None] {
            let overlay = fx.overlay.with_file_name(format!("o-{}", typed.len()));
            let ov = WriteOverlay::open(
                &token,
                token.source(),
                &overlay,
                &CreateOptions {
                    base_digest: digest.clone(),
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("{typed} {digest:?}: {e}"));
            drop(ov);
            fs::remove_dir_all(&overlay).unwrap();
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
    let err = crate::commit_overlay(&fx.overlay, &fx.archive, &token, &opts)
        .unwrap_err()
        .to_string();
    assert!(err.contains("--force-base-mismatch"), "{err}");
    assert_eq!(fs::read(&fx.archive).unwrap(), swapped);
    let forced = CommitOverlayOptions {
        force_base_mismatch: true,
        ..opts
    };
    assert!(crate::commit_overlay(&fx.overlay, &fx.archive, &token, &forced).unwrap());
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
    assert!(crate::commit_overlay(&fx.overlay, &fx.archive, &token, &Default::default()).is_err());
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
    drop(WriteOverlay::new_for_tests(open_tar(&fx.archive), &fx.overlay).unwrap());
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

/// Leave `archive` mid-commit the way a crash does: the journal and the locator
/// exist, the archive is truncated at the replaced suffix.
fn interrupt_append(archive: &Path) {
    use std::io::Write;
    let len = fs::metadata(archive).unwrap().len();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[0u8; 1536]).unwrap();
    let crashed = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        archive,
        len - 1024,
        &mut suffix,
        &mut |step| {
            if step == "archive truncate" {
                Err(std::io::Error::other("crash"))
            } else {
                Ok(())
            }
        },
    );
    assert!(crashed.is_err());
}

/// Regression (R6-G2): the mounted base replaced by ANOTHER archive that carries
/// its own interrupted-append journal was restored (rolled back or truncated)
/// by `recover` before the identity guard rejected it. The commit is refused
/// first: the foreign archive and its journal stay byte-identical. Live and
/// on-exit paths, every digest kind (`none` is caught by the inode).
#[test]
fn regression_foreign_archive_with_own_journal_refused_untouched() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        for digest in [BaseDigestRequest::Compute, BaseDigestRequest::None] {
            let fx = Fixture::new();
            let ov = fx.open(digest.clone(), false);
            fs::write(ov.root().join("one"), b"one").unwrap();
            let foreign = fx.archive.with_file_name("foreign.tar");
            write_tar(&foreign, &[("other", b"a different base"), ("more", b"x")]);
            interrupt_append(&foreign);
            let crashed_bytes = fs::read(&foreign).unwrap();
            let journal = ratarmount_compress::commit_journal::journal_path(&foreign);
            let journal_bytes = fs::read(&journal).unwrap();
            fs::rename(&foreign, &fx.archive).unwrap();
            let err = commit(&ov, &fx.archive, path).unwrap_err().to_string();
            assert!(err.contains("--force-base-mismatch"), "{path:?}: {err}");
            assert!(
                fs::read(&fx.archive).unwrap() == crashed_bytes,
                "{path:?}: the foreign archive was modified"
            );
            assert!(
                fs::read(&journal).unwrap() == journal_bytes,
                "{path:?}: the foreign journal was modified"
            );
            assert!(!ov.interval_disabled(), "{path:?}: not failed closed");
        }
    }
}

/// One real crash: kill this very process with SIGKILL at journal step
/// `RATARMOUNT_TEST_CRASH_STEP` while it replaces the suffix of the archive
/// named by `RATARMOUNT_TEST_CRASH_ARCHIVE`. A no-op unless both are set (the
/// parent test below runs it as a child). Unix only: `libc::kill`/`SIGKILL`
/// do not exist on Windows.
#[cfg(unix)]
#[test]
fn journal_crash_child() {
    use std::io::Write;
    let (Some(archive), Ok(step)) = (
        std::env::var_os("RATARMOUNT_TEST_CRASH_ARCHIVE"),
        std::env::var("RATARMOUNT_TEST_CRASH_STEP"),
    ) else {
        return;
    };
    let archive = PathBuf::from(archive);
    let len = fs::metadata(&archive).unwrap().len();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[0u8; 1536]).unwrap();
    let _ = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        &archive,
        len - 1024,
        &mut suffix,
        &mut |at| {
            if at == step {
                unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
            Ok(())
        },
    );
}

const JOURNAL_STEPS: [&str; 15] = [
    "journal header",
    "journal tail",
    "journal fsync",
    "locator prepare",
    "journal publish",
    "journal directory fsync",
    "locator active",
    "archive truncate",
    "archive write",
    "archive fsync",
    "locator complete",
    "locator done",
    "journal unlink",
    "commit directory fsync",
    "locator clear",
];

/// Regression (R6-G2, R6-J2): the guard runs BEFORE recovery for a foreign
/// journal, but the overlay's OWN torn append must still recover. A real
/// SIGKILL at every journal phase: until the replacement is complete the
/// archive rolls back to the recorded base and the next commit succeeds; at
/// `locator complete` and `locator done` the journal is still there, consistent
/// with the recorded base, and recovery rolls FORWARD: the commit is accepted and
/// the stamp rows re-baselined. Once the journal is gone (`journal unlink` and later) nothing
/// ties the changed archive to the crash, so that commit is refused as a
/// changed base - never a torn archive, and no journal is left either way.
#[cfg(unix)]
#[test]
fn regression_real_sigkill_at_every_journal_phase_still_recovers() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for step in JOURNAL_STEPS {
        for path in [Path_::Live, Path_::OnExit] {
            let fx = Fixture::new();
            let ov = fx.open(BaseDigestRequest::Compute, false);
            let original = fs::read(&fx.archive).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "overlay_identity_tests::journal_crash_child"])
                .args(["--test-threads=1", "--nocapture"])
                .env("RATARMOUNT_TEST_CRASH_ARCHIVE", &fx.archive)
                .env("RATARMOUNT_TEST_CRASH_STEP", step)
                .status()
                .unwrap();
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(libc::SIGKILL), "{step}: {status:?}");
            }
            fs::write(ov.root().join("one"), b"one").unwrap();
            let result = commit(&ov, &fx.archive, path);
            let journal = ratarmount_compress::commit_journal::journal_path(&fx.archive);
            assert!(!journal.exists(), "{step} {path:?}: journal recovered");
            let position = |name: &str| JOURNAL_STEPS.iter().position(|s| *s == name).unwrap();
            let refused = position(step) > position("locator done");
            if refused {
                let err = result.unwrap_err().to_string();
                assert!(err.contains("--force-base-mismatch"), "{step}: {err}");
            } else {
                assert!(result.unwrap_or_else(|e| panic!("{step} {path:?}: {e}")));
                let served = fs::read(&fx.archive).unwrap();
                assert!(served.len() >= original.len(), "{step}");
            }
        }
    }
}

/// Regression (R6-G2): an archive replaced (new inode) after a crash is
/// refused: a journal started for the old file never rolls back its successor.
#[test]
fn regression_archive_replaced_after_crash_is_refused() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let ov = fx.open(BaseDigestRequest::Compute, false);
        fs::write(ov.root().join("one"), b"one").unwrap();
        interrupt_append(&fx.archive);
        let journal = ratarmount_compress::commit_journal::journal_path(&fx.archive);
        let journal_bytes = fs::read(&journal).unwrap();
        let replacement = fx.archive.with_file_name("replacement.tar");
        write_tar(&replacement, &[("other", b"a different base")]);
        let replaced = fs::read(&replacement).unwrap();
        fs::rename(&replacement, &fx.archive).unwrap();
        let err = commit(&ov, &fx.archive, path).unwrap_err().to_string();
        assert!(err.contains("--force-base-mismatch"), "{path:?}: {err}");
        assert!(
            fs::read(&fx.archive).unwrap() == replaced,
            "{path:?}: the replacement was modified"
        );
        assert!(
            fs::read(&journal).unwrap() == journal_bytes,
            "{path:?}: the journal was modified"
        );
    }
}

/// Regression (R6-G3, #1): the base was mounted as `alias.tar -> base.tar` and
/// the link was retargeted to another valid tar while mounted. Neither the
/// canonical path nor the named path equalled the token's, so the commit guard
/// returned success without any check and rewrote the other archive. The guard
/// recognises the typed name and compares device and inode: refused on the live
/// and on-exit paths with the retarget target untouched; the unchanged link
/// still commits.
#[cfg(unix)]
#[test]
fn regression_retargeted_symlink_refused() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        for retarget in [false, true] {
            let fx = Fixture::new();
            let alias = fx.archive.with_file_name("alias.tar");
            std::os::unix::fs::symlink(&fx.archive, &alias).unwrap();
            let token = ClassifiedBase::for_tests_typed(
                open_tar(&fx.archive),
                ServedKind::Archive,
                Some(ServedLocation::Local(fx.archive.clone())),
                &alias,
            );
            let ov = open_with(&token, &fx.overlay, BaseDigestRequest::Compute, false).unwrap();
            fs::write(ov.root().join("one"), b"one").unwrap();
            let other = fx.archive.with_file_name("other.tar");
            write_tar(&other, &[("other", b"a different base"), ("more", b"x")]);
            let before = fs::read(&other).unwrap();
            if retarget {
                fs::remove_file(&alias).unwrap();
                std::os::unix::fs::symlink(&other, &alias).unwrap();
            }
            let result = commit(&ov, &alias, path);
            if retarget {
                let err = result.unwrap_err().to_string();
                assert!(err.contains("--force-base-mismatch"), "{path:?}: {err}");
                assert!(fs::read(&other).unwrap() == before, "{path:?}: touched");
            } else {
                assert!(result.unwrap(), "{path:?}: the unchanged link commits");
            }
        }
    }
}

/// Pinning (R6-H7 nit): a record that is not `none` but has lost its stamp rows
/// (`base_size`, `base_mtime_ns`; a database edited by hand, or written by a
/// build that did not record them) has nothing to compare the archive's stamp
/// or a pending journal against. An offline commit then rests on the kind and
/// place checks alone and goes through, even over a swapped archive at the
/// same place. This documents that limit so a change to it is deliberate; with
/// the rows present the same swap is refused (the sibling test above).
#[test]
fn regression_missing_stamp_rows_on_a_digest_record_skip_only_the_stamp_check() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    fs::write(ov.root().join("one"), b"one").unwrap();
    drop(ov);
    {
        let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
        for key in ["base_size", "base_mtime_ns"] {
            OverlayMeta::remove(&conn, key).unwrap();
        }
    }
    let swapped = fx.swap_for_other_tar();
    let token = archive_token(&fx.archive);
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    assert!(
        crate::commit_overlay(&fx.overlay, &fx.archive, &token, &opts).is_ok(),
        "a record without stamp rows commits on kind and place alone"
    );
    assert_ne!(
        fs::read(&fx.archive).unwrap(),
        swapped,
        "the commit spliced into the swapped archive"
    );
}

/// Crash an append into `archive`, then replace it by a copy with the same
/// bytes and mtime on a new inode: the sibling journal stays behind and now
/// describes another file. Returns what must stay byte-identical.
#[cfg(unix)]
fn crashed_new_inode_copy(archive: &Path) -> (Vec<u8>, PathBuf, Vec<u8>) {
    interrupt_append(archive);
    let bytes = fs::read(archive).unwrap();
    let journal = ratarmount_compress::commit_journal::journal_path(archive);
    let journal_bytes = fs::read(&journal).unwrap();
    let mtime = fs::metadata(archive).unwrap().modified().unwrap();
    let copy = archive.with_file_name("inode-copy.tmp");
    fs::write(&copy, &bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(&copy)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    fs::rename(&copy, archive).unwrap();
    (bytes, journal, journal_bytes)
}

#[cfg(unix)]
fn assert_refused_untouched(
    result: crate::write_overlay::Result<bool>,
    archive: &Path,
    kept: &(Vec<u8>, PathBuf, Vec<u8>),
    what: &str,
) {
    let err = result.unwrap_err().to_string();
    assert!(err.contains("--force-base-mismatch"), "{what}: {err}");
    assert!(
        fs::read(archive).unwrap() == kept.0,
        "{what}: archive modified"
    );
    assert!(
        fs::read(&kept.1).unwrap() == kept.2,
        "{what}: journal modified"
    );
}

/// Regression (R6-J2, audit A8; Codex r10 #1): a `none` record returned before
/// the journal ownership check. With a FRESH token (an in-process reopen over
/// the copy, or offline `--commit-overlay`) recovery rolled the old journal
/// into a new-inode copy of the crashed archive and committed into it.
#[cfg(unix)]
#[test]
fn regression_none_record_refuses_foreign_journal_with_fresh_token() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let ov = fx.open(BaseDigestRequest::None, false);
        fs::write(ov.root().join("one"), b"one").unwrap();
        drop(ov);
        let kept = crashed_new_inode_copy(&fx.archive);
        // Reopen over the copy: a fresh token, kind-only record.
        let ov = fx.open(BaseDigestRequest::None, false);
        assert_refused_untouched(
            commit(&ov, &fx.archive, path),
            &fx.archive,
            &kept,
            &format!("{path:?}"),
        );
    }
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::None, false);
    fs::write(ov.root().join("one"), b"one").unwrap();
    drop(ov);
    let kept = crashed_new_inode_copy(&fx.archive);
    let token = archive_token(&fx.archive);
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    let result = crate::commit_overlay(&fx.overlay, &fx.archive, &token, &opts);
    assert_refused_untouched(result, &fx.archive, &kept, "offline");
}

/// Regression (R6-J2, audit A9): a digest record that lost its stamp rows
/// returned before the ownership check too.
#[cfg(unix)]
#[test]
fn regression_missing_stamp_rows_still_refuse_foreign_journal() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    fs::write(ov.root().join("one"), b"one").unwrap();
    drop(ov);
    {
        let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
        for key in ["base_size", "base_mtime_ns"] {
            OverlayMeta::remove(&conn, key).unwrap();
        }
    }
    let kept = crashed_new_inode_copy(&fx.archive);
    let token = archive_token(&fx.archive);
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    let result = crate::commit_overlay(&fx.overlay, &fx.archive, &token, &opts);
    assert_refused_untouched(result, &fx.archive, &kept, "no stamp rows");
}

/// Regression (R6-J2, audit A3/A4): a commit target the token does not
/// describe (a Folder-first union, or another member of the union) returned
/// before the ownership check, so recovery rolled a foreign journal into it.
/// The target's OWN journal still recovers.
#[cfg(unix)]
#[test]
fn regression_union_commit_target_with_foreign_journal_refused() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        for folder_first in [true, false] {
            for foreign in [true, false] {
                let fx = Fixture::new();
                let ov = if folder_first {
                    let folder = fx.overlay.parent().unwrap().join("folder");
                    fs::create_dir(&folder).unwrap();
                    open_with(
                        &folder_token(&folder),
                        &fx.overlay,
                        BaseDigestRequest::None,
                        false,
                    )
                    .unwrap()
                } else {
                    fx.open(BaseDigestRequest::Compute, false)
                };
                let target = fx.archive.with_file_name("member.tar");
                write_tar(&target, &[("m", b"member")]);
                fs::write(ov.root().join("one"), b"one").unwrap();
                let what = format!("{path:?} folder_first={folder_first} foreign={foreign}");
                if foreign {
                    let kept = crashed_new_inode_copy(&target);
                    assert_refused_untouched(commit(&ov, &target, path), &target, &kept, &what);
                } else {
                    interrupt_append(&target);
                    let done = commit(&ov, &target, path);
                    assert!(done.unwrap_or_else(|e| panic!("{what}: {e}")), "{what}");
                    assert!(
                        !ratarmount_compress::commit_journal::journal_path(&target).exists(),
                        "{what}: own journal recovered"
                    );
                }
            }
        }
    }
}

/// Leave `archive` crashed right after the replacement was fully written: the
/// journal is still there and marked complete.
#[cfg(unix)]
fn interrupt_complete(archive: &Path) {
    use std::io::Write;
    let len = fs::metadata(archive).unwrap().len();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[0u8; 1536]).unwrap();
    let crashed = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        archive,
        len - 1024,
        &mut suffix,
        &mut |step| {
            if step == "locator complete" {
                Err(std::io::Error::other("crash"))
            } else {
                Ok(())
            }
        },
    );
    assert!(crashed.is_err());
}

/// Regression (R6-K1, r11 skeptic #4): a journal touches the overlay's rows
/// only when its target is the recorded base. The overlay records A; the
/// commit goes to union member B, which carries its OWN complete journal.
/// Recovery rolled B forward and then wrote B's stamp into A's rows, so the
/// next commit to the unchanged A was refused. Both directions, live and
/// on-exit; a later commit to A succeeds (empty plan: nothing refreshes the
/// token, so the rows are the only thing recovery could corrupt).
#[cfg(unix)]
#[test]
fn regression_union_member_complete_journal_leaves_recorded_stamp() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        for record_a in [true, false] {
            let fx = Fixture::new();
            let other = fx.archive.with_file_name("member.tar");
            write_tar(&other, &[("m", b"member")]);
            let (recorded, target) = if record_a {
                (fx.archive.clone(), other.clone())
            } else {
                (other.clone(), fx.archive.clone())
            };
            let token = archive_token(&recorded);
            let ov = WriteOverlay::open(
                &token,
                token.source(),
                &fx.overlay,
                &CreateOptions {
                    base_digest: BaseDigestRequest::Compute,
                    ..Default::default()
                },
            )
            .unwrap();
            let before = ov.recorded_stamp_for_tests();
            assert!(before.0.is_some() && before.1.is_some());
            interrupt_complete(&target);
            let what = format!("{path:?} record_a={record_a}");
            // An empty plan: recovery runs, nothing is committed or refreshed.
            let done = commit(&ov, &target, path);
            done.unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(
                !ratarmount_compress::commit_journal::journal_path(&target).exists(),
                "{what}: own journal recovered"
            );
            assert_eq!(ov.recorded_stamp_for_tests(), before, "{what}: stamp moved");
            fs::write(ov.root().join("two"), b"two").unwrap();
            let again = commit(&ov, &recorded, path);
            assert!(
                again.unwrap_or_else(|e| panic!("{what}: later commit to base: {e}")),
                "{what}"
            );
        }
    }
}

/// Regression (R6-K7, r11 review nit 2): a complete journal rolled forward
/// moved the stamp rows but left the strong digest naming the PRE-crash bytes,
/// so a retry that ended before the refresh left stamp and digest disagreeing.
/// The digest is now marked `pending` (resolved lazily by seal, diff, pack or
/// grading; mounting stays fast) and resolves to the digest of the archive as
/// it is now.
#[cfg(unix)]
#[test]
fn regression_roll_forward_marks_base_digest_pending() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let before = sha(&fx.archive);
        let ov = fx.open(BaseDigestRequest::Supplied(before.clone()), false);
        let (kind, digest) = ov.recorded_digest_for_tests();
        assert_eq!(kind.as_deref(), Some("strong"));
        assert_eq!(digest.as_deref(), Some(before.as_str()));
        interrupt_complete(&fx.archive);
        // An empty plan: recovery rolls forward and the commit ends before any refresh.
        commit(&ov, &fx.archive, path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        let (kind, digest) = ov.recorded_digest_for_tests();
        assert_eq!(kind.as_deref(), Some("pending"), "{path:?}");
        assert_eq!(digest.as_deref(), Some(""), "{path:?}");
        drop(ov);
        let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
        assert!(crate::overlay_meta::resolve_pending_base_digest(&conn).unwrap());
        let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
        let after = meta.base_digest().unwrap().to_owned();
        assert_eq!(meta.base_digest_kind(), Some("strong"), "{path:?}");
        assert_ne!(
            after, before,
            "{path:?}: digest still names the pre-crash bytes"
        );
    }
}

/// Regression (R6-J2, audit A10 + #9): the journal check compares the inode
/// only. `commit_journal` calls the device number a hint (it changes on
/// reboot), so a device change with the same inode is the overlay's own journal.
#[cfg(unix)]
#[test]
fn regression_journal_dev_change_is_not_a_refusal() {
    use ratarmount_compress::commit_journal::PendingJournal;
    let journal = |dev, ino| PendingJournal {
        dev,
        ino,
        len: 1,
        mtime_ns: 1,
        offset: 0,
        new_len: 1,
        complete: false,
    };
    assert!(crate::overlay_gate::journal_started_for(
        &journal(7, 42),
        42
    ));
    assert!(crate::overlay_gate::journal_started_for(
        &journal(8, 42),
        42
    ));
    assert!(!crate::overlay_gate::journal_started_for(
        &journal(7, 42),
        43
    ));
}

/// Pin (R6-J2, audit A13): a journal that cannot be read refuses the commit.
#[cfg(unix)]
#[test]
fn regression_corrupt_journal_locator_refuses_commit() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let ov = fx.open(BaseDigestRequest::Compute, false);
        fs::write(ov.root().join("one"), b"one").unwrap();
        interrupt_append(&fx.archive);
        let journal = ratarmount_compress::commit_journal::journal_path(&fx.archive);
        let mut bytes = fs::read(&journal).unwrap();
        bytes[..8].copy_from_slice(b"GARBAGE!");
        fs::write(&journal, &bytes).unwrap();
        let archive_bytes = fs::read(&fx.archive).unwrap();
        let err = commit(&ov, &fx.archive, path).unwrap_err().to_string();
        assert!(err.contains("journal"), "{path:?}: {err}");
        assert!(fs::read(&fx.archive).unwrap() == archive_bytes, "{path:?}");
    }
}

/// Regression (R6-J2, audit A17): the raw-directory entry recovered whatever
/// journal the target carried, twice, with no ownership evidence at all.
#[cfg(unix)]
#[test]
fn regression_raw_dir_commit_refuses_foreign_journal() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    fs::create_dir(&fx.overlay).unwrap();
    fs::write(fx.overlay.join("added"), b"raw").unwrap();
    let kept = crashed_new_inode_copy(&fx.archive);
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    let result =
        crate::commit_overlay_raw_dir(&fx.overlay, &fx.archive, &opts).map(|d| d.committed);
    assert_refused_untouched(result, &fx.archive, &kept, "raw dir");
    // Its own journal still recovers.
    let fx = Fixture::new();
    fs::create_dir(&fx.overlay).unwrap();
    fs::write(fx.overlay.join("added"), b"raw").unwrap();
    interrupt_append(&fx.archive);
    let done = crate::commit_overlay_raw_dir(&fx.overlay, &fx.archive, &opts).unwrap();
    assert!(done.committed);
    assert!(!ratarmount_compress::commit_journal::journal_path(&fx.archive).exists());
}

/// Regression (R6-J7, audit C9): a FORCED reopen over an edited copy at another
/// local place overrides that open only ("the recorded digest stays"), but the
/// accepted-move writer then re-measured the stamp (archive) or weak manifest
/// (directory) FROM THE EDITED COPY, silently re-pointing the baseline, so a
/// later unforced open or gate accepted the edit. The record is left as it was:
/// the next unforced reopen over the copy is still refused.
#[test]
fn regression_forced_reopen_at_other_place_does_not_rebaseline() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let keys = [
        "base_location",
        "base_size",
        "base_mtime_ns",
        "base_local_path",
        "base_weak_digest",
        "base_digest",
    ];
    // Archive, strong.
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    let before = read_rows(&fx.overlay, &keys);
    let copy = fx.archive.with_file_name("copy.tar");
    write_tar(&copy, &[("other", b"a different base"), ("more", b"x")]);
    let edited = archive_token(&copy);
    drop(open_with(&edited, &fx.overlay, BaseDigestRequest::Compute, true).unwrap());
    assert_eq!(read_rows(&fx.overlay, &keys), before, "archive: re-pointed");
    assert!(
        open_with(&edited, &fx.overlay, BaseDigestRequest::Compute, false).is_err(),
        "archive: the edited copy was accepted after one forced open"
    );
    // Directory, weak.
    let fx = Fixture::new();
    let dir = fx.overlay.parent().unwrap().join("basedir");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("f"), b"base").unwrap();
    drop(
        open_with(
            &folder_token(&dir),
            &fx.overlay,
            BaseDigestRequest::Compute,
            false,
        )
        .unwrap(),
    );
    let before = read_rows(&fx.overlay, &keys);
    assert!(before[4].is_some(), "a directory record has a weak digest");
    let copy = fx.overlay.parent().unwrap().join("copydir");
    fs::create_dir(&copy).unwrap();
    fs::write(copy.join("f"), b"edited").unwrap();
    let edited = folder_token(&copy);
    drop(open_with(&edited, &fx.overlay, BaseDigestRequest::Compute, true).unwrap());
    assert_eq!(
        read_rows(&fx.overlay, &keys),
        before,
        "directory: re-pointed"
    );
    assert!(
        open_with(&edited, &fx.overlay, BaseDigestRequest::Compute, false).is_err(),
        "directory: the edited copy was accepted after one forced open"
    );
}

/// Regression (R6-J8, audit C1): an accepted move of an archive base to another
/// local place rewrote the stamp and path rows but left `base_index_path`
/// naming the OLD place's sidecar, which a commit refresh and a pending-digest
/// resolution read as the index of the base. The row follows the move: the new
/// place's sidecar when one exists, else it is dropped.
#[test]
fn regression_accepted_archive_move_repoints_base_index_path() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for copy_has_sidecar in [true, false] {
        let fx = Fixture::new();
        let digest = sha(&fx.archive);
        let token_at = |archive: &Path, index: Option<&Path>| {
            ClassifiedBase::mint(crate::Opened {
                source: open_tar(archive),
                kind: ServedKind::Archive,
                inputs: Vec::new(),
                location: Some(ServedLocation::Local(archive.to_path_buf())),
                index: index.map_or(crate::IndexProvenance::None, |path| {
                    crate::IndexProvenance::Local(path.to_path_buf())
                }),
                sidecar_candidate: None,
                fetched: false,
                keep_alive: Box::new(()),
            })
            .unwrap()
        };
        let old_index = fx.archive.with_file_name("base.tar.index.sqlite");
        fs::write(&old_index, b"sidecar").unwrap();
        let open_writable = |token: &ClassifiedBase| {
            WriteOverlay::open(
                token,
                token.source(),
                &fx.overlay,
                &CreateOptions {
                    base_digest: BaseDigestRequest::Supplied(digest.clone()),
                    index_writable: true,
                    ..Default::default()
                },
            )
        };
        drop(open_writable(&token_at(&fx.archive, Some(&old_index))).unwrap());
        assert_eq!(
            read_rows(&fx.overlay, &["base_index_path"])[0].as_deref(),
            Some(old_index.to_str().unwrap())
        );
        let copy = fx.archive.with_file_name("copy.tar");
        fs::copy(&fx.archive, &copy).unwrap();
        let new_index = fx.archive.with_file_name("copy.tar.index.sqlite");
        if copy_has_sidecar {
            fs::write(&new_index, b"sidecar").unwrap();
        }
        drop(
            open_writable(&token_at(
                &copy,
                copy_has_sidecar.then_some(new_index.as_path()),
            ))
            .expect("a byte-identical copy confirmed by the digest reopens"),
        );
        let row = read_rows(&fx.overlay, &["base_index_path"])[0].clone();
        if copy_has_sidecar {
            assert_eq!(row.as_deref(), Some(new_index.to_str().unwrap()));
        } else {
            assert_eq!(row, None, "the old place's sidecar is still named");
        }
    }
}

// ---- R7-A2: one roll-forward -------------------------------------------------

/// The rows recorded in the overlay database at `overlay`.
fn recorded_rows(overlay: &Path) -> Vec<Option<String>> {
    read_rows(overlay, &["base_size", "base_mtime_ns", "base_digest_kind"])
}

/// The stamp rows `archive` would be recorded with now.
#[cfg(unix)]
fn stamp_rows(archive: &Path) -> (Option<String>, Option<String>) {
    let now = ratarmount_index::ArchiveDigestStamp::read(archive).unwrap();
    (Some(now.size.to_string()), Some(now.mtime_ns.to_string()))
}

/// Regression (R7-A2): `recover_journal_at` (the entry the mount, the library
/// openers and the offline verbs share) rolls a COMPLETE journal forward and
/// restamps the rows before it unlinks the journal, so the NEXT gate accepts
/// the archive recovery just produced: the offline commit gate, a `-w` remount,
/// and a live and an on-exit commit. A strong digest is marked `pending`.
#[cfg(unix)]
#[test]
fn regression_recover_journal_at_restamps_and_the_next_gate_accepts() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for supplied in [false, true] {
        let fx = Fixture::new();
        let digest = if supplied {
            BaseDigestRequest::Supplied(sha(&fx.archive))
        } else {
            BaseDigestRequest::Compute
        };
        drop(fx.open(digest, false));
        interrupt_complete(&fx.archive);
        let db = fx.overlay.join(HIDDEN_DB);
        let applied = crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Inode)
            .unwrap()
            .expect("a journal was applied");
        assert!(applied.rolled_forward);
        assert!(!ratarmount_compress::commit_journal::journal_path(&fx.archive).exists());
        let rows = recorded_rows(&fx.overlay);
        let (size, mtime) = stamp_rows(&fx.archive);
        assert_eq!(
            (rows[0].clone(), rows[1].clone()),
            (size, mtime),
            "{supplied}"
        );
        if supplied {
            assert_eq!(rows[2].as_deref(), Some("pending"));
        }
        let token = archive_token(&fx.archive);
        crate::overlay_gate::check_commit_base_offline(&fx.overlay, &token, &fx.archive)
            .unwrap_or_else(|e| panic!("{supplied}: offline gate: {e}"));
        drop(fx.open(BaseDigestRequest::Compute, false));
        for path in [Path_::Live, Path_::OnExit] {
            let ov = fx.open(BaseDigestRequest::Compute, false);
            fs::write(ov.root().join(format!("two-{path:?}")), b"two").unwrap();
            assert!(
                commit(&ov, &fx.archive, path)
                    .unwrap_or_else(|e| panic!("{supplied} {path:?}: {e}")),
                "{supplied} {path:?}"
            );
        }
    }
}

/// Regression (R7-A2): offline `commit_overlay` recovered a complete journal
/// and ended on an EMPTY plan without restamping, so the next offline commit
/// failed with "changed since it was recorded".
#[cfg(unix)]
#[test]
fn regression_offline_commit_roll_forward_with_empty_plan_restamps() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    interrupt_complete(&fx.archive);
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    let token = archive_token(&fx.archive);
    assert!(!crate::commit_overlay(&fx.overlay, &fx.archive, &token, &opts).unwrap());
    assert!(!ratarmount_compress::commit_journal::journal_path(&fx.archive).exists());
    fs::write(fx.overlay.join("one"), b"one").unwrap();
    let token = archive_token(&fx.archive);
    assert!(
        crate::commit_overlay(&fx.overlay, &fx.archive, &token, &opts).unwrap(),
        "the second commit is accepted by the gate"
    );
}

/// Regression (R7-A2): the rows already describe the committed bytes but the
/// complete journal is still on disk (the unlink failed after the rows were
/// written). Every gate accepts that state: the journal's pre-stamp is not the
/// recorded stamp any more, but the rows equal the archive and `new_len`.
#[cfg(unix)]
#[test]
fn regression_rows_committed_then_unlink_failed_is_accepted_by_every_gate() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for gate in ["live", "on-exit", "offline", "remount"] {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::Compute, false));
        interrupt_complete(&fx.archive);
        {
            let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
            let (size, mtime) = stamp_rows(&fx.archive);
            OverlayMeta::set_many(
                &conn,
                &[
                    ("base_size", size.as_deref().unwrap()),
                    ("base_mtime_ns", mtime.as_deref().unwrap()),
                ],
            )
            .unwrap();
        }
        let before = recorded_rows(&fx.overlay);
        match gate {
            "live" | "on-exit" => {
                let ov = fx.open(BaseDigestRequest::Compute, false);
                let path = if gate == "live" {
                    Path_::Live
                } else {
                    Path_::OnExit
                };
                commit(&ov, &fx.archive, path).unwrap_or_else(|e| panic!("{gate}: {e}"));
            }
            "offline" => {
                let token = archive_token(&fx.archive);
                let opts = CommitOverlayOptions {
                    yes: true,
                    ..Default::default()
                };
                crate::commit_overlay(&fx.overlay, &fx.archive, &token, &opts)
                    .unwrap_or_else(|e| panic!("{gate}: {e}"));
            }
            _ => drop(fx.open(BaseDigestRequest::Compute, false)),
        }
        // Recovery finds the rows already final and writes nothing.
        let after = recorded_rows(&fx.overlay);
        assert_eq!(&after[..2], &before[..2], "{gate}");
        if gate != "remount" {
            assert!(
                !ratarmount_compress::commit_journal::journal_path(&fx.archive).exists(),
                "{gate}: journal recovered"
            );
        }
    }
}

/// Regression (R7-A2, finding 2): the rows are written from the LOCKED
/// descriptor's final stamp, never from whatever the name resolves to later. An
/// unrelated archive renamed over the name under the lock leaves the rows as
/// they were, keeps the journal and marker (`Committed`), and recovery finishes
/// once the name is A again.
#[cfg(unix)]
#[test]
fn regression_restamp_writes_the_locked_descriptor_not_the_name() {
    use ratarmount_compress::commit_journal::RecoverError;
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    let keep = fx.archive.with_file_name("keep.tar");
    fs::hard_link(&fx.archive, &keep).unwrap();
    interrupt_complete(&fx.archive);
    let other = fx.archive.with_file_name("b.tar");
    write_tar(&other, &[("other", b"a different base"), ("more", b"x")]);
    let before = recorded_rows(&fx.overlay);
    let db = fx.overlay.join(HIDDEN_DB);
    let (swap_to, swap_from) = (fx.archive.clone(), other.clone());
    let mut swap = move |_: &ratarmount_compress::commit_journal::PendingJournal,
                         _: &fs::Metadata| {
        fs::rename(&swap_from, &swap_to).unwrap();
        Ok(())
    };
    let error = crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Test(&mut swap))
        .unwrap_err();
    assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
    assert_eq!(recorded_rows(&fx.overlay), before, "rows moved");
    assert!(
        ratarmount_compress::commit_journal::journal_path(&fx.archive).exists(),
        "journal kept"
    );
    // The name is now an unrelated file: its journal belongs to another inode.
    let refused = crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Inode);
    assert!(refused.is_err());
    assert_eq!(recorded_rows(&fx.overlay), before, "rows moved");
    // Restore A's name: recovery finishes with A's final stamp.
    fs::rename(&keep, &fx.archive).unwrap();
    crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Inode)
        .unwrap()
        .expect("finished");
    let rows = recorded_rows(&fx.overlay);
    let (size, mtime) = stamp_rows(&fx.archive);
    assert_eq!((rows[0].clone(), rows[1].clone()), (size, mtime));
    assert!(!ratarmount_compress::commit_journal::journal_path(&fx.archive).exists());
}

/// Regression (R7-A2, finding 3): the locked authorizer is `check_commit_base`
/// itself, so a union member's OWN complete journal is recovered without
/// moving the recorded base's rows, and a member journal started for another
/// inode is refused.
#[cfg(unix)]
#[test]
fn regression_locked_authorizer_accepts_union_member_journal() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let member = fx.archive.with_file_name("member.tar");
        write_tar(&member, &[("m", b"member")]);
        let ov = fx.open(BaseDigestRequest::Compute, false);
        let before = ov.recorded_stamp_for_tests();
        interrupt_complete(&member);
        commit(&ov, &member, path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        assert!(
            !ratarmount_compress::commit_journal::journal_path(&member).exists(),
            "{path:?}"
        );
        assert_eq!(ov.recorded_stamp_for_tests(), before, "{path:?}: base rows");
        // A journal started for another inode is refused.
        let crashed = fx.archive.with_file_name("crashed.tar");
        write_tar(&crashed, &[("c", b"crashed")]);
        let (bytes, journal, journal_bytes) = {
            interrupt_append(&crashed);
            let journal = ratarmount_compress::commit_journal::journal_path(&crashed);
            (
                fs::read(&crashed).unwrap(),
                journal.clone(),
                fs::read(&journal).unwrap(),
            )
        };
        let copy = fx.archive.with_file_name("crashed-copy.tmp");
        fs::write(&copy, &bytes).unwrap();
        fs::rename(&copy, &crashed).unwrap();
        let err = commit(&ov, &crashed, path).unwrap_err().to_string();
        assert!(err.contains("another file"), "{path:?}: {err}");
        assert_eq!(fs::read(&journal).unwrap(), journal_bytes, "{path:?}");
    }
}

// ---- R7-A3: symlinked bases --------------------------------------------------

/// Regression (R7-A3, Astra v4 #4): the base is mounted as `alias.tar ->
/// base.tar`. A COMPLETE journal on the unchanged target recovers THROUGH THE
/// LINK and restamps the rows from the resolved target (canonical path + the
/// locked inode); the user's path is only for display.
#[cfg(unix)]
#[test]
fn regression_symlink_unchanged_complete_recovery_restamps() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let alias = fx.archive.with_file_name("alias.tar");
        std::os::unix::fs::symlink(&fx.archive, &alias).unwrap();
        let token = ClassifiedBase::for_tests_typed(
            open_tar(&fx.archive),
            ServedKind::Archive,
            Some(ServedLocation::Local(fx.archive.clone())),
            &alias,
        );
        let ov = open_with(&token, &fx.overlay, BaseDigestRequest::Compute, false).unwrap();
        interrupt_complete(&fx.archive);
        commit(&ov, &alias, path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        assert!(
            !ratarmount_compress::commit_journal::journal_path(&fx.archive).exists(),
            "{path:?}: recovered through the link"
        );
        let (size, mtime) = stamp_rows(&fx.archive);
        assert_eq!(ov.recorded_stamp_for_tests(), (size, mtime), "{path:?}");
        // The next gate accepts, through the link.
        fs::write(ov.root().join("one"), b"one").unwrap();
        assert!(commit(&ov, &alias, path).unwrap(), "{path:?}: next commit");
    }
    // The shared entry too (mount, offline and library openers pass the typed path).
    let fx = Fixture::new();
    let alias = fx.archive.with_file_name("alias.tar");
    std::os::unix::fs::symlink(&fx.archive, &alias).unwrap();
    drop(fx.open(BaseDigestRequest::Compute, false));
    interrupt_complete(&fx.archive);
    let db = fx.overlay.join(HIDDEN_DB);
    crate::recover_journal_at(&alias, Some(&db), crate::Owner::Inode)
        .unwrap()
        .expect("recovered through the link");
    let rows = recorded_rows(&fx.overlay);
    let (size, mtime) = stamp_rows(&fx.archive);
    assert_eq!((rows[0].clone(), rows[1].clone()), (size, mtime));
}

/// Regression (R7-B5): the base is mounted as `alias.tar -> base.tar` and the
/// TARGET file is replaced by a different inode while the link itself is
/// unchanged. The restamp compares the resolved target with the locked
/// descriptor (a stat of the link would never match and would also refuse the
/// unchanged case): the replacement leaves the rows alone and keeps the
/// journal, and once the original target is back recovery finishes through the
/// link with the target's final stamp.
#[cfg(unix)]
#[test]
fn regression_symlink_replaced_target_uses_resolved_identity() {
    use ratarmount_compress::commit_journal::RecoverError;
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let alias = fx.archive.with_file_name("alias.tar");
    std::os::unix::fs::symlink(&fx.archive, &alias).unwrap();
    drop(fx.open(BaseDigestRequest::Compute, false));
    let keep = fx.archive.with_file_name("keep.tar");
    fs::hard_link(&fx.archive, &keep).unwrap();
    interrupt_complete(&fx.archive);
    let other = fx.archive.with_file_name("b.tar");
    write_tar(&other, &[("other", b"a different base"), ("more", b"x")]);
    let before = recorded_rows(&fx.overlay);
    let db = fx.overlay.join(HIDDEN_DB);
    let (swap_to, swap_from) = (fx.archive.clone(), other.clone());
    let mut swap = move |_: &ratarmount_compress::commit_journal::PendingJournal,
                         _: &fs::Metadata| {
        fs::rename(&swap_from, &swap_to).unwrap();
        Ok(())
    };
    let error =
        crate::recover_journal_at(&alias, Some(&db), crate::Owner::Test(&mut swap)).unwrap_err();
    assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
    assert_eq!(recorded_rows(&fx.overlay), before, "rows moved");
    assert!(fs::symlink_metadata(&alias).unwrap().is_symlink());
    // The original target is back under the link's target name.
    fs::rename(&keep, &fx.archive).unwrap();
    crate::recover_journal_at(&alias, Some(&db), crate::Owner::Inode)
        .unwrap()
        .expect("finished through the link");
    let rows = recorded_rows(&fx.overlay);
    let (size, mtime) = stamp_rows(&fx.archive);
    assert_eq!((rows[0].clone(), rows[1].clone()), (size, mtime));
}

/// Regression (R7-A3): a link retargeted to another archive that carries its
/// own COMPLETE journal, and a target replaced by such an archive, are refused
/// with the other file, its journal and the rows untouched.
#[cfg(unix)]
#[test]
fn regression_symlink_retargeted_or_replaced_target_is_refused() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        for replace_target in [false, true] {
            let fx = Fixture::new();
            let alias = fx.archive.with_file_name("alias.tar");
            std::os::unix::fs::symlink(&fx.archive, &alias).unwrap();
            let token = ClassifiedBase::for_tests_typed(
                open_tar(&fx.archive),
                ServedKind::Archive,
                Some(ServedLocation::Local(fx.archive.clone())),
                &alias,
            );
            let ov = open_with(&token, &fx.overlay, BaseDigestRequest::Compute, false).unwrap();
            fs::write(ov.root().join("one"), b"one").unwrap();
            let other = fx.archive.with_file_name("other.tar");
            write_tar(&other, &[("other", b"a different base"), ("more", b"x")]);
            interrupt_complete(&other);
            let (bytes, journal) = (
                fs::read(&other).unwrap(),
                ratarmount_compress::commit_journal::journal_path(&other),
            );
            let journal_bytes = fs::read(&journal).unwrap();
            let rows = ov.recorded_stamp_for_tests();
            let what = format!("{path:?} replace_target={replace_target}");
            if replace_target {
                // The journal beside `other` moves with its inode: rename it over the base.
                fs::rename(&other, &fx.archive).unwrap();
            } else {
                fs::remove_file(&alias).unwrap();
                std::os::unix::fs::symlink(&other, &alias).unwrap();
            }
            let err = commit(&ov, &alias, path).unwrap_err().to_string();
            assert!(err.contains("--force-base-mismatch"), "{what}: {err}");
            let target = if replace_target { &fx.archive } else { &other };
            assert!(
                fs::read(target).unwrap() == bytes,
                "{what}: archive touched"
            );
            let journal = if replace_target {
                ratarmount_compress::commit_journal::journal_path(&fx.archive)
            } else {
                journal
            };
            if !replace_target {
                assert!(
                    fs::read(&journal).unwrap() == journal_bytes,
                    "{what}: journal"
                );
            }
            assert_eq!(ov.recorded_stamp_for_tests(), rows, "{what}: rows moved");
        }
    }
}

// ---- R7-A1: mount-time journal -------------------------------------------------

use crate::{authorize_mount_recovery, classify_mount_journal, MountJournal, MountRecords};

fn records_of(fx: &Fixture) -> MountRecords {
    MountRecords {
        top: Some(fx.overlay.clone()),
        ..Default::default()
    }
}

/// `foreign.tar` with an interrupted append (torn or complete), renamed over
/// `fx.archive`: the name now has ANOTHER file's inode and journal.
#[cfg(unix)]
fn rename_b_over_a(fx: &Fixture, complete: bool) -> (Vec<u8>, PathBuf, Vec<u8>) {
    let foreign = fx.archive.with_file_name("foreign.tar");
    write_tar(&foreign, &[("b", b"bb"), ("c", b"c")]);
    if complete {
        interrupt_complete(&foreign);
    } else {
        interrupt_append(&foreign);
    }
    let journal = ratarmount_compress::commit_journal::journal_path(&foreign);
    let journal_bytes = fs::read(&journal).unwrap();
    let bytes = fs::read(&foreign).unwrap();
    fs::rename(&foreign, &fx.archive).unwrap();
    (bytes, journal, journal_bytes)
}

/// Regression (R7-A1, Keystone 1): `mv B A` where B carries its own interrupted
/// journal. The journal's inode matches the file at A's name, so the unlocked
/// ownership check passed and recovery rolled B back BEFORE the gate refused
/// the stamp. The classifier compares the journal's pre-commit stamp with the
/// recorded base first: Deferred, and the locked authorizer refuses too, with
/// the archive and the journal byte-identical.
#[cfg(unix)]
#[test]
fn regression_mount_rename_b_over_a_is_deferred_and_untouched() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for complete in [false, true] {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::Compute, false));
        let (bytes, journal, journal_bytes) = rename_b_over_a(&fx, complete);
        let records = records_of(&fx);
        let decision = classify_mount_journal(&records, &fx.archive).unwrap();
        match &decision {
            MountJournal::Deferred {
                complete: c,
                force_flag,
                why,
            } => {
                assert_eq!(*c, complete);
                assert_eq!(*force_flag, "--force-base-mismatch");
                assert!(why.contains("not started for the recorded base"), "{why}");
            }
            other => panic!("complete={complete}: {other:?}"),
        }
        let db = fx.overlay.join(HIDDEN_DB);
        let archive = fx.archive.clone();
        let mut authorize = |h: &ratarmount_compress::commit_journal::PendingJournal,
                             m: &fs::Metadata| {
            authorize_mount_recovery(&records, &archive, h, m)
        };
        let refused =
            crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Test(&mut authorize));
        assert!(
            matches!(
                refused,
                Err(ratarmount_compress::commit_journal::RecoverError::Refused(
                    _
                ))
            ),
            "complete={complete}: {refused:?}"
        );
        assert_eq!(fs::read(&fx.archive).unwrap(), bytes, "complete={complete}");
        assert_eq!(
            fs::read(&journal).unwrap(),
            journal_bytes,
            "complete={complete}"
        );
    }
}

/// Regression (R7-B1): the top record's database is a symlink (a supported
/// layout). `read_record` treated a non-regular file as "no record", so the
/// record abstained, `mv B A` with B's own torn journal classified `Own` and
/// recovery rolled B back. A symlinked or unstatable database is an unreadable
/// record: Deferred in the classifier and refused by the locked authorizer.
#[cfg(unix)]
#[test]
fn regression_mount_symlinked_overlay_db_defers_recovery() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    let real = fx.archive.with_file_name("real-overlay.sqlite");
    let db = fx.overlay.join(HIDDEN_DB);
    fs::rename(&db, &real).unwrap();
    std::os::unix::fs::symlink(&real, &db).unwrap();
    let (bytes, journal, journal_bytes) = rename_b_over_a(&fx, false);
    let records = records_of(&fx);
    match classify_mount_journal(&records, &fx.archive).unwrap() {
        MountJournal::Deferred {
            force_flag, why, ..
        } => {
            assert_eq!(force_flag, "--force-base-mismatch");
            assert!(why.contains("cannot be read"), "{why}");
        }
        other => panic!("symlinked record must defer: {other:?}"),
    }
    let archive = fx.archive.clone();
    let mut authorize = |h: &ratarmount_compress::commit_journal::PendingJournal,
                         m: &fs::Metadata| {
        authorize_mount_recovery(&records, &archive, h, m)
    };
    let refused =
        crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Test(&mut authorize));
    assert!(
        matches!(
            refused,
            Err(ratarmount_compress::commit_journal::RecoverError::Refused(
                _
            ))
        ),
        "{refused:?}"
    );
    assert_eq!(fs::read(&fx.archive).unwrap(), bytes);
    assert_eq!(fs::read(&journal).unwrap(), journal_bytes);
}

/// Regression (r16 skeptic, R7-D2): A's overlay database is replaced by a
/// directory, then B with its own torn journal is renamed over A.
/// `read_record` treated a directory at the database path as "no record", so
/// the top record abstained, the mount classified B's journal `Own` and
/// recovery rolled B back before `WriteOverlay::open` refused the directory.
/// Any non-regular file at the database path is an unreadable record: the
/// classifier defers, the locked authorizer refuses, B and its journal stay
/// byte-identical and the gate refuses.
#[cfg(unix)]
#[test]
fn regression_mount_directory_at_overlay_db_defers_recovery() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    let db = fx.overlay.join(HIDDEN_DB);
    fs::remove_file(&db).unwrap();
    fs::create_dir(&db).unwrap();
    let (bytes, journal, journal_bytes) = rename_b_over_a(&fx, false);
    let records = records_of(&fx);
    match classify_mount_journal(&records, &fx.archive).unwrap() {
        MountJournal::Deferred {
            force_flag, why, ..
        } => {
            assert_eq!(force_flag, "--force-base-mismatch");
            assert!(why.contains("cannot be read"), "{why}");
        }
        other => panic!("a directory at the database path must defer: {other:?}"),
    }
    let archive = fx.archive.clone();
    let mut authorize = |h: &ratarmount_compress::commit_journal::PendingJournal,
                         m: &fs::Metadata| {
        authorize_mount_recovery(&records, &archive, h, m)
    };
    let refused =
        crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Test(&mut authorize));
    assert!(
        matches!(
            refused,
            Err(ratarmount_compress::commit_journal::RecoverError::Refused(
                _
            ))
        ),
        "{refused:?}"
    );
    assert!(fs::read(&fx.archive).unwrap() == bytes, "B untouched");
    assert_eq!(
        fs::read(&journal).unwrap(),
        journal_bytes,
        "B's journal kept"
    );
    assert!(
        crate::overlay_gate::check_commit_base_offline(
            &fx.overlay,
            &archive_token(&fx.archive),
            &fx.archive
        )
        .is_err(),
        "the gate refuses"
    );
}

/// Regression (R7-B2): a journal-bearing file B takes A's name AFTER the
/// append's suffix was staged and BEFORE the journaled replacement. The
/// replacement fails ("pending journal") and the fallback cleanup recovered
/// whatever journal sat at the name with `authorize_forced`: B was rolled back and
/// B's stamp became A's recorded baseline (`Restamp::Commit`). Only the journal
/// THIS attempt started may be recovered.
#[cfg(unix)]
#[test]
fn regression_replacement_error_fallback_leaves_foreign_journal() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for complete in [false, true] {
        let fx = Fixture::new();
        let mut ov = fx.open(BaseDigestRequest::Compute, false);
        ov.set_commit_mode(crate::CommitMode::Append);
        let before = ov.recorded_stamp_for_tests();
        fs::write(ov.root().join("new"), b"new").unwrap();
        let foreign = fx.archive.with_file_name("foreign.tar");
        write_tar(&foreign, &[("b", b"bb"), ("c", b"c")]);
        if complete {
            interrupt_complete(&foreign);
        } else {
            interrupt_append(&foreign);
        }
        let journal = ratarmount_compress::commit_journal::journal_path(&foreign);
        let journal_bytes = fs::read(&journal).unwrap();
        let bytes = fs::read(&foreign).unwrap();
        crate::write_overlay::APPEND_PREPARE_SWAP.set(Some(foreign));
        let result = commit(&ov, &fx.archive, Path_::Live);
        assert!(result.is_err(), "complete={complete}: {result:?}");
        assert!(
            fs::read(&fx.archive).unwrap() == bytes,
            "complete={complete}: B touched"
        );
        assert!(
            fs::read(&journal).unwrap() == journal_bytes,
            "complete={complete}: journal"
        );
        assert_eq!(
            ov.recorded_stamp_for_tests(),
            before,
            "complete={complete}: baseline moved"
        );
    }
}

/// Regression (R7-A1): the table's other rows. The overlay's own torn and
/// complete journals are `Own`; a record naming another file (a union member),
/// a bundle `--lower`, a sealed or unreadable top and a lower that disagrees
/// all defer; a journal from another inode is an error; no journal is `None`.
#[cfg(unix)]
#[test]
fn regression_mount_journal_table() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for complete in [false, true] {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::Compute, false));
        let records = records_of(&fx);
        assert_eq!(
            classify_mount_journal(&records, &fx.archive).unwrap(),
            MountJournal::None
        );
        if complete {
            interrupt_complete(&fx.archive);
        } else {
            interrupt_append(&fx.archive);
        }
        assert_eq!(
            classify_mount_journal(&records, &fx.archive).unwrap(),
            MountJournal::Own,
            "complete={complete}"
        );
        // No overlay at all: nothing votes.
        assert_eq!(
            classify_mount_journal(&MountRecords::default(), &fx.archive).unwrap(),
            MountJournal::Own
        );
        // A bundle lower cannot vote yet: everything waits.
        let bundles = MountRecords {
            bundles: true,
            ..records.clone()
        };
        assert!(matches!(
            classify_mount_journal(&bundles, &fx.archive).unwrap(),
            MountJournal::Deferred {
                force_flag: "--force-stack-mismatch",
                ..
            }
        ));
        // A record that names another file: this member is not the base.
        let member = fx.archive.with_file_name("member.tar");
        write_tar(&member, &[("m", b"member")]);
        if complete {
            interrupt_complete(&member);
        } else {
            interrupt_append(&member);
        }
        match classify_mount_journal(&records, &member).unwrap() {
            MountJournal::Deferred {
                why, complete: c, ..
            } => {
                assert_eq!(c, complete);
                assert!(why.contains("not the base this overlay recorded"), "{why}");
            }
            other => panic!("complete={complete}: {other:?}"),
        }
        // A lower record that disagrees votes too.
        let lower = fx.archive.with_file_name("lower");
        fs::create_dir(&lower).unwrap();
        {
            let conn = rusqlite::Connection::open(lower.join(HIDDEN_DB)).unwrap();
            conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
                .unwrap();
            let path = fx.archive.canonicalize().unwrap();
            OverlayMeta::set_many(
                &conn,
                &[
                    ("format_version", "2"),
                    ("base_kind", "archive"),
                    ("base_local_path", path.to_str().unwrap()),
                    ("base_digest_kind", "weak"),
                    ("base_size", "1"),
                    ("base_mtime_ns", "1"),
                ],
            )
            .unwrap();
        }
        let with_lower = MountRecords {
            lowers: vec![lower],
            ..records.clone()
        };
        assert!(matches!(
            classify_mount_journal(&with_lower, &fx.archive).unwrap(),
            MountJournal::Deferred {
                force_flag: "--force-stack-mismatch",
                ..
            }
        ));
        // A journal started for another inode is refused outright.
        let copy = fx.archive.with_file_name("inode-copy.tmp");
        fs::write(&copy, fs::read(&fx.archive).unwrap()).unwrap();
        fs::rename(&copy, &fx.archive).unwrap();
        assert!(classify_mount_journal(&records, &fx.archive)
            .unwrap_err()
            .to_string()
            .contains("another file"));
    }
}

/// Regression (R7-A1): `verify` accepts an archive whose stamp differs from the
/// record ONLY because its own pending journal is not recovered yet, and never
/// for a base at another place or a journal that was not started for the rows.
#[cfg(unix)]
#[test]
fn regression_verify_accepts_own_pending_journal() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    let meta = || OverlayMeta::read(&fx.overlay).unwrap().unwrap();
    let now = |p: &Path| {
        let s = ratarmount_index::ArchiveDigestStamp::read(p).unwrap();
        (s.size, s.mtime_ns)
    };
    interrupt_complete(&fx.archive);
    assert!(crate::journal_recovery::own_pending_journal_agrees(
        &meta(),
        &fx.archive,
        now(&fx.archive)
    ));
    // Another place: the record does not name it.
    let copy = fx.archive.with_file_name("copy.tar");
    fs::copy(&fx.archive, &copy).unwrap();
    assert!(!crate::journal_recovery::own_pending_journal_agrees(
        &meta(),
        &copy,
        now(&copy)
    ));
    // A foreign journal under the same name.
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    rename_b_over_a(&fx, true);
    assert!(!crate::journal_recovery::own_pending_journal_agrees(
        &OverlayMeta::read(&fx.overlay).unwrap().unwrap(),
        &fx.archive,
        now(&fx.archive)
    ));
}

// ---- R7-C3: a failed replacement's reaction, the gate's snapshot, the copy guard ----

use crate::write_overlay::tests::{reopen_tar_zst, ustar_file, write_split_tar_zst};
use ratarmount_compress::commit_journal::{fault, journal_path};

/// Incompressible bytes (a zstd frame of them is larger than the data).
fn noise(tag: u64, len: usize) -> Vec<u8> {
    let mut x = tag.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Way {
    Live,
    Provenance,
    Offline,
}

/// A recorded base (`.tar` or a seekable two-frame `.tar.zst`) and its overlay.
struct Place {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    archive: PathBuf,
    overlay: PathBuf,
    zst: bool,
}

impl Place {
    fn new(zst: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let archive = root.join(if zst { "base.tar.zst" } else { "base.tar" });
        Self::write_base(&archive, zst);
        Self {
            overlay: root.join("overlay"),
            archive,
            root,
            zst,
            _tmp: tmp,
        }
    }

    fn write_base(archive: &Path, zst: bool) {
        if zst {
            write_split_tar_zst(
                archive,
                &[ustar_file("prefix.txt", b"prefix member")],
                &[ustar_file("last.txt", b"last member")],
                true,
            );
        } else {
            write_tar(archive, &[("first", b"first member")]);
        }
    }

    fn source(&self, path: &Path) -> Arc<dyn MountSource> {
        if self.zst {
            reopen_tar_zst(path, false).unwrap()
        } else {
            open_tar(path)
        }
    }

    fn token(&self) -> ClassifiedBase {
        ClassifiedBase::for_tests(
            self.source(&self.archive),
            ServedKind::Archive,
            Some(ServedLocation::Local(self.archive.clone())),
        )
    }

    fn open(&self, overlay: &Path, way: Way, mode: crate::CommitMode) -> WriteOverlay {
        let mut ov = open_with(&self.token(), overlay, BaseDigestRequest::Compute, false).unwrap();
        ov.set_commit_mode(mode);
        if way == Way::Provenance {
            ov.set_manifest_hashes(Some("sha256".into()));
        }
        ov
    }

    /// Commit `ov` the given way (offline drops it first).
    fn commit(
        &self,
        ov: WriteOverlay,
        way: Way,
        mode: crate::CommitMode,
    ) -> (Option<WriteOverlay>, crate::write_overlay::Result<bool>) {
        match way {
            Way::Live | Way::Provenance => {
                let result = ov.commit_live(&self.archive, |p| Ok(self.source(p)));
                (Some(ov), result)
            }
            Way::Offline => {
                drop(ov);
                let opts = CommitOverlayOptions {
                    yes: true,
                    mode,
                    ..Default::default()
                };
                let token = self.token();
                (
                    None,
                    crate::commit_overlay(&self.overlay, &self.archive, &token, &opts),
                )
            }
        }
    }
}

#[cfg(unix)]
fn ino(path: &Path) -> u64 {
    std::os::unix::fs::MetadataExt::ino(&fs::metadata(path).unwrap())
}

/// Regression (r15 #1): a failed replacement never recovers or copies over
/// a journal another file left at the name. Journal-bearing B (torn or
/// complete) is renamed over A right before the replacement locks the name;
/// the replacement is refused, a copy fallback finds another inode at the
/// name, and B, its journal and the overlay's rows stay as they were (a live
/// mount keeps committing). Before: the fallback's `recover_offline(
/// authorize_any)` recovered B's journal (offline/provenance), or the gated
/// re-recovery refused it and stopped interval commits (live).
#[cfg(unix)]
#[test]
fn regression_foreign_journal_at_the_name_is_never_recovered_or_overwritten() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for (way, zst) in [
        (Way::Live, false),
        (Way::Live, true),
        (Way::Provenance, false),
        (Way::Provenance, true),
        (Way::Offline, false),
        (Way::Offline, true),
    ] {
        for complete in [false, true] {
            for mode in [crate::CommitMode::Append, crate::CommitMode::Auto] {
                let case = format!("{way:?} zst={zst} complete={complete} {mode:?}");
                let place = Place::new(zst);
                let ov = place.open(&place.overlay, way, mode);
                fs::write(ov.root().join("new"), b"new member").unwrap();
                let rows = recorded_rows_live(&ov);
                let other = place.root.join("other");
                fs::create_dir(&other).unwrap();
                let b = other.join(place.archive.file_name().unwrap());
                write_tar(&b, &[("b", &noise(7, 4096))]);
                if complete {
                    interrupt_complete(&b);
                } else {
                    interrupt_append(&b);
                }
                let (b_bytes, j_bytes) =
                    (fs::read(&b).unwrap(), fs::read(journal_path(&b)).unwrap());
                let (from, to) = (b.clone(), place.archive.clone());
                let (jfrom, jto) = (journal_path(&b), journal_path(&place.archive));
                fault::install(move |step| {
                    if step == "before replace" && from.exists() {
                        fs::rename(&jfrom, &jto)?;
                        fs::rename(&from, &to)?;
                    }
                    Ok(())
                });
                let b_ino = ino(&b);
                let (ov, result) = place.commit(ov, way, mode);
                fault::clear();
                assert!(result.is_err(), "{case}: {result:?}");
                assert!(
                    fs::read(&place.archive).unwrap() == b_bytes,
                    "{case}: B touched"
                );
                assert!(
                    fs::read(journal_path(&place.archive)).unwrap() == j_bytes,
                    "{case}: B's journal touched"
                );
                assert_eq!(ino(&place.archive), b_ino, "{case}: B replaced");
                match ov {
                    Some(ov) => {
                        assert!(!ov.interval_disabled(), "{case}: interval stopped");
                        assert_eq!(recorded_rows_live(&ov), rows, "{case}: rows moved");
                    }
                    None => assert_eq!(recorded_rows(&place.overlay), rows, "{case}: rows moved"),
                }
            }
        }
    }
}

fn recorded_rows_live(ov: &WriteOverlay) -> Vec<Option<String>> {
    let meta = ov.meta_for_tests();
    ["base_size", "base_mtime_ns", "base_digest_kind"]
        .iter()
        .map(|k| meta.get(k).map(str::to_owned))
        .collect()
}

/// Regression (Astra v2 #3): a file swapped over the name before the append
/// stages its suffix is never appended into or copied over. zstd B without a
/// seek table (with a complete journal) and zstd B with a seek table are
/// swapped in before the splice scans the archive; a TAR B with trailing
/// garbage before the append offset is computed. Auto mode, live and
/// offline: an error, B (and its journal) untouched, interval commits on.
#[cfg(unix)]
#[test]
fn regression_swapped_archive_before_staging_is_refused() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for way in [Way::Live, Way::Offline] {
        for variant in ["zst_no_seek_table", "zst_seek_table", "tar_bad_eof"] {
            let case = format!("{way:?} {variant}");
            let zst = variant != "tar_bad_eof";
            let place = Place::new(zst);
            let ov = place.open(&place.overlay, way, crate::CommitMode::Auto);
            fs::write(ov.root().join("new"), b"new member").unwrap();
            let other = place.root.join("other");
            fs::create_dir(&other).unwrap();
            let b = other.join(place.archive.file_name().unwrap());
            let payload = noise(11, 4096);
            match variant {
                "zst_no_seek_table" | "zst_seek_table" => {
                    write_split_tar_zst(
                        &b,
                        &[ustar_file("b1", &payload)],
                        &[ustar_file("b2", &payload)],
                        variant == "zst_seek_table",
                    );
                }
                _ => {
                    write_tar(&b, &[("b", &payload)]);
                    let mut bytes = fs::read(&b).unwrap();
                    bytes.extend_from_slice(&noise(12, 700));
                    fs::write(&b, bytes).unwrap();
                }
            }
            if variant == "zst_no_seek_table" {
                interrupt_complete(&b);
            }
            let b_bytes = fs::read(&b).unwrap();
            let journal = fs::read(journal_path(&b)).ok();
            let (from, to) = (b.clone(), place.archive.clone());
            let (jfrom, jto) = (journal_path(&b), journal_path(&place.archive));
            if zst {
                fault::install(move |step| {
                    if step == "before splice scan" && from.exists() {
                        if jfrom.exists() {
                            fs::rename(&jfrom, &jto)?;
                        }
                        fs::rename(&from, &to)?;
                    }
                    Ok(())
                });
            } else {
                crate::write_overlay::APPEND_PREPARE_SWAP.set(Some(b.clone()));
            }
            let (ov, result) = place.commit(ov, way, crate::CommitMode::Auto);
            fault::clear();
            crate::write_overlay::APPEND_PREPARE_SWAP.set(None);
            assert!(result.is_err(), "{case}: {result:?}");
            assert!(
                fs::read(&place.archive).unwrap() == b_bytes,
                "{case}: B touched"
            );
            assert_eq!(
                fs::read(journal_path(&place.archive)).ok(),
                journal,
                "{case}: B's journal"
            );
            if let Some(ov) = ov {
                assert!(!ov.interval_disabled(), "{case}: interval stopped");
            }
        }
    }
}

/// Regression (r15 #1, design test 1c): an attempt that never published its
/// journal never adopts another file's. B (complete journal J2, `C` on B) is
/// renamed over A's name after A's prepare locator and before A publishes;
/// A's attempt fails (EEXIST), rolls nothing back, and the Auto copy finds
/// another inode at the name: an error, A unchanged (read through an fd
/// opened before), B and J2 untouched and B still complete, rows unchanged,
/// interval commits on.
#[cfg(unix)]
#[test]
fn regression_unpublished_attempt_collision_refuses_copy() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    use std::io::{Read, Seek};
    let place = Place::new(false);
    let ov = place.open(&place.overlay, Way::Live, crate::CommitMode::Auto);
    fs::write(ov.root().join("new"), b"new member").unwrap();
    let rows = recorded_rows_live(&ov);
    let mut a = fs::File::open(&place.archive).unwrap();
    let (a_bytes, a_mtime) = (
        fs::read(&place.archive).unwrap(),
        a.metadata().unwrap().modified().unwrap(),
    );
    let x = place.root.join("x");
    fs::create_dir(&x).unwrap();
    let b = x.join("base.tar");
    write_tar(&b, &[("b", &noise(3, 4096))]);
    interrupt_complete(&b);
    let (b_bytes, j2) = (fs::read(&b).unwrap(), fs::read(journal_path(&b)).unwrap());
    let (from, to) = (b.clone(), place.archive.clone());
    let (jfrom, jto) = (journal_path(&b), journal_path(&place.archive));
    fault::install(move |step| {
        if step == "locator prepare" && from.exists() {
            fs::rename(&jfrom, &jto)?;
            fs::rename(&from, &to)?;
        }
        Ok(())
    });
    let result = ov.commit_live(&place.archive, |p| Ok(open_tar(p)));
    fault::clear();
    assert!(result.is_err(), "{result:?}");
    let mut now = Vec::new();
    a.rewind().unwrap();
    a.read_to_end(&mut now).unwrap();
    assert!(now == a_bytes, "A changed");
    assert_eq!(a.metadata().unwrap().modified().unwrap(), a_mtime);
    assert!(fs::read(&place.archive).unwrap() == b_bytes, "B touched");
    assert!(
        fs::read(journal_path(&place.archive)).unwrap() == j2,
        "J2 touched"
    );
    assert!(
        ratarmount_compress::commit_journal::pending(&place.archive)
            .unwrap()
            .expect("B's journal")
            .complete,
        "B keeps its complete locator"
    );
    assert!(!ov.interval_disabled());
    assert_eq!(recorded_rows_live(&ov), rows);
}

/// Regression (r15 skeptic #2): the cleanup of a failed attempt runs under
/// the attempt's own lock. ENOSPC while the archive is written; while the
/// attempt is about to clean up, another thread tries to recover the archive
/// and to start its own (complete) replacement: both fail on the lock. The
/// attempt then rolls back: the archive is the old bytes, no journal, no
/// locator, rows unchanged, and the next commit succeeds.
#[cfg(unix)]
#[test]
fn regression_failed_attempt_cleanup_holds_the_archive_lock() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let place = Place::new(false);
    let ov = place.open(&place.overlay, Way::Live, crate::CommitMode::Append);
    fs::write(ov.root().join("new"), b"new member").unwrap();
    let rows = recorded_rows_live(&ov);
    let before = fs::read(&place.archive).unwrap();
    let archive = place.archive.clone();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    fault::install(move |step| {
        match step {
            "archive write" => return Err(std::io::Error::from_raw_os_error(libc::ENOSPC)),
            "before cleanup" => {
                let archive = archive.clone();
                let log = log.clone();
                std::thread::spawn(move || {
                    let recovered = crate::recover_journal_at(&archive, None, crate::Owner::Inode);
                    log.lock().unwrap().push(format!("recover: {recovered:?}"));
                    use std::io::Write;
                    let mut suffix = tempfile::tempfile().unwrap();
                    suffix.write_all(&[0u8; 1536]).unwrap();
                    let len = fs::metadata(&archive).unwrap().len();
                    let started = ratarmount_compress::commit_journal::replace_suffix_with_hook(
                        &archive,
                        len.saturating_sub(1024),
                        &mut suffix,
                        &mut |step| {
                            if step == "locator complete" {
                                Err(std::io::Error::other("crash"))
                            } else {
                                Ok(())
                            }
                        },
                    );
                    log.lock().unwrap().push(format!("replace: {started:?}"));
                })
                .join()
                .unwrap();
            }
            _ => {}
        }
        Ok(())
    });
    let result = ov.commit_live(&place.archive, |p| Ok(open_tar(p)));
    fault::clear();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    for line in &seen {
        assert!(
            line.contains("Resource temporarily unavailable") || line.contains("WouldBlock"),
            "the other committer must hit the lock: {line}"
        );
    }
    assert!(result.is_err(), "{result:?}");
    assert!(fs::read(&place.archive).unwrap() == before, "rolled back");
    assert!(!journal_path(&place.archive).exists());
    assert!(ratarmount_compress::commit_journal::pending(&place.archive)
        .unwrap()
        .is_none());
    assert_eq!(recorded_rows_live(&ov), rows);
    assert!(!ov.interval_disabled());
    assert!(ov.commit_live(&place.archive, |p| Ok(open_tar(p))).unwrap());
}

/// Regression (r15 #3): the commit goes through `alias -> A` and, after the
/// completion marker, `alias` is retargeted to journal-free B. The hook
/// (resolved name != locked inode) fails, so the commit is NOT a success:
/// `Committed`, A holds the new bytes with its complete journal, the rows
/// still describe A's old stamp, the overlay file stays, interval commits
/// stop. Recovering A then restamps and the gate accepts it. Before: the
/// cleanup probed `alias` (B: no journal), counted `Ok(None)` as done and
/// reported success; the refresh then recorded B and the cleanup pruned the
/// overlay file.
#[cfg(unix)]
#[test]
fn regression_committed_hook_failure_after_link_retarget_stays_committed() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for path in [Path_::Live, Path_::OnExit] {
        let fx = Fixture::new();
        let alias = fx.archive.with_file_name("alias.tar");
        std::os::unix::fs::symlink(&fx.archive, &alias).unwrap();
        let token = ClassifiedBase::for_tests_typed(
            open_tar(&fx.archive),
            ServedKind::Archive,
            Some(ServedLocation::Local(fx.archive.clone())),
            &alias,
        );
        let mut ov = open_with(&token, &fx.overlay, BaseDigestRequest::Compute, false).unwrap();
        ov.set_commit_mode(crate::CommitMode::Append);
        fs::write(ov.root().join("one"), b"one").unwrap();
        let rows = recorded_rows_live(&ov);
        let b = fx.archive.with_file_name("b.tar");
        write_tar(&b, &[("other", b"a different base")]);
        let b_bytes = fs::read(&b).unwrap();
        let (link, target) = (alias.clone(), b.clone());
        fault::install(move |step| {
            if step == "locator complete" {
                fs::remove_file(&link)?;
                std::os::unix::fs::symlink(&target, &link)?;
            }
            Ok(())
        });
        let result = commit(&ov, &alias, path);
        fault::clear();
        let error = result.expect_err("a commit whose hook failed is not a success");
        assert!(
            matches!(error, crate::OverlayError::Committed(_)),
            "{path:?}: {error}"
        );
        let journal = ratarmount_compress::commit_journal::pending(&fx.archive)
            .unwrap()
            .expect("A keeps its journal");
        assert!(journal.complete, "{path:?}");
        assert_eq!(recorded_rows_live(&ov), rows, "{path:?}: rows moved");
        assert!(ov.root().join("one").exists(), "{path:?}: overlay pruned");
        assert!(ov.interval_disabled(), "{path:?}");
        assert_eq!(fs::read(&b).unwrap(), b_bytes);
        drop(ov);
        crate::recover_journal_at(
            &fx.archive,
            Some(&fx.overlay.join(HIDDEN_DB)),
            crate::Owner::Inode,
        )
        .unwrap()
        .expect("A recovered");
        let (size, mtime) = stamp_rows(&fx.archive);
        let now = recorded_rows(&fx.overlay);
        assert_eq!((now[0].clone(), now[1].clone()), (size, mtime), "{path:?}");
        crate::overlay_gate::check_commit_base_offline(
            &fx.overlay,
            &archive_token(&fx.archive),
            &fx.archive,
        )
        .unwrap_or_else(|e| panic!("{path:?}: {e:?}"));
    }
}

/// Regression (r15 #3, renamed directory): the base `/d/a`; after the
/// completion marker `/d` is renamed to `/saved` and journal-free B is
/// written at `/d/a`. The hook fails (the name is B): `Committed`; A (now
/// `/saved/a`) holds the new bytes with its journal byte-identical and `C`;
/// B untouched; rows unchanged; the overlay file stays; interval commits
/// stop. With the directory restored, recovery rolls forward, restamps, and
/// the gate accepts.
#[cfg(unix)]
#[test]
fn regression_committed_hook_failure_after_directory_rename_stays_committed() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let (d, saved) = (root.join("d"), root.join("saved"));
    fs::create_dir(&d).unwrap();
    let a = d.join("a.tar");
    write_tar(&a, &[("first", b"first member")]);
    let overlay = root.join("overlay");
    let mut ov = open_with(
        &archive_token(&a),
        &overlay,
        BaseDigestRequest::Compute,
        false,
    )
    .unwrap();
    ov.set_commit_mode(crate::CommitMode::Append);
    fs::write(ov.root().join("one"), b"one").unwrap();
    let rows = recorded_rows_live(&ov);
    let (seam_d, seam_saved) = (d.clone(), saved.clone());
    fault::install(move |step| {
        if step == "locator complete" {
            fs::rename(&seam_d, &seam_saved)?;
            fs::create_dir(&seam_d)?;
            write_tar(&seam_d.join("a.tar"), &[("other", b"journal-free B")]);
        }
        Ok(())
    });
    let result = ov.commit_live(&a, |p| Ok(open_tar(p)));
    fault::clear();
    let error = result.expect_err("not a success");
    assert!(
        matches!(error, crate::OverlayError::Committed(_)),
        "{error}"
    );
    let moved = saved.join("a.tar");
    let journal = fs::read(journal_path(&moved)).expect("J1 beside the moved archive");
    assert!(
        ratarmount_compress::commit_journal::pending(&moved)
            .unwrap()
            .expect("pending through the new name")
            .complete
    );
    let b_bytes = fs::read(&a).unwrap();
    assert_eq!(recorded_rows_live(&ov), rows);
    assert!(ov.root().join("one").exists());
    assert!(ov.interval_disabled());
    drop(ov);
    assert_eq!(fs::read(&a).unwrap(), b_bytes, "B untouched");
    assert_eq!(fs::read(journal_path(&moved)).unwrap(), journal);
    fs::remove_file(&a).unwrap();
    fs::remove_dir(&d).unwrap();
    fs::rename(&saved, &d).unwrap();
    crate::recover_journal_at(&a, Some(&overlay.join(HIDDEN_DB)), crate::Owner::Inode)
        .unwrap()
        .expect("rolled forward");
    let (size, mtime) = stamp_rows(&a);
    let now = recorded_rows(&overlay);
    assert_eq!((now[0].clone(), now[1].clone()), (size, mtime));
    crate::overlay_gate::check_commit_base_offline(&overlay, &archive_token(&a), &a).unwrap();
}

/// Regression (Astra v2 #5): the gate resolves and stats the archive once
/// and returns that snapshot; every later write compares against it. B (same
/// size, another inode) is swapped over the name right after the snapshot:
/// the gate still judges and returns A; the replacement and the copy source
/// then refuse B. Mutation-red: judging the identity by a second stat of the
/// name (the old `FileId::of(&canonical)`) returns B or a mixed judgement.
#[cfg(unix)]
#[test]
fn regression_commit_gate_judges_and_returns_one_snapshot() {
    use std::os::unix::fs::MetadataExt;
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    let a_ino = ino(&fx.archive);
    let mut b_bytes = fs::read(&fx.archive).unwrap();
    b_bytes[600] ^= 1;
    let b = fx.archive.with_file_name("b.tar");
    fs::write(&b, &b_bytes).unwrap();
    let (from, to) = (b.clone(), fx.archive.clone());
    crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || fs::rename(&from, &to).unwrap()));
    });
    let token = archive_token(&fx.archive);
    let snapshot = crate::overlay_gate::check_commit_base_offline(&fx.overlay, &token, &fx.archive)
        .expect("the gate judged A")
        .expect("an archive snapshot");
    assert_eq!(snapshot.ino(), a_ino);
    assert_ne!(ino(&fx.archive), a_ino, "B is at the name");
    let mut suffix = tempfile::tempfile().unwrap();
    std::io::Write::write_all(&mut suffix, &[0u8; 1024]).unwrap();
    let replaced = ratarmount_compress::commit_journal::replace_suffix_if_unchanged_with(
        &fx.archive,
        512,
        &mut suffix,
        &snapshot,
        &mut |_| Ok(()),
    );
    assert!(
        matches!(
            replaced,
            Err(ratarmount_compress::commit_journal::ReplaceError::Refused(
                _
            ))
        ),
        "{replaced:?}"
    );
    assert_eq!(fs::read(&fx.archive).unwrap(), b_bytes);
    for from in [
        crate::journal_recovery::CopyFrom::Gate,
        crate::journal_recovery::CopyFrom::AfterRollback(snapshot.clone()),
    ] {
        assert!(crate::journal_recovery::open_copy_source(&fx.archive, &snapshot, &from).is_err());
    }
}

/// Regression (Astra v3 #2): a copy fallback publishes only over the file it
/// read, unchanged. P1's append fails (ENOSPC) and rolls back; while P1 is
/// about to publish its copy, P2 (another overlay on the same archive)
/// appends its own member to the same inode. P1's copy is refused
/// ("archive changed during the copy fallback"), P2's member stays readable,
/// the inode is unchanged, interval commits stay on, and P1's next commit is
/// refused too (its rows still describe the archive before P2's commit).
/// Mutation-red: a guard comparing only (dev, ino) publishes P1's copy over
/// P2's append.
#[cfg(unix)]
#[test]
fn regression_auto_copy_refuses_an_archive_that_changed_since_it_was_staged() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for (way, zst) in [
        (Way::Live, false),
        (Way::Live, true),
        (Way::Provenance, false),
        (Way::Offline, false),
        (Way::Offline, true),
    ] {
        let case = format!("{way:?} zst={zst}");
        let place = Place::new(zst);
        let p1 = place.open(&place.overlay, way, crate::CommitMode::Auto);
        fs::write(p1.root().join("from-p1"), b"p1 member").unwrap();
        let p2 = place.open(
            &place.root.join("overlay2"),
            Way::Live,
            crate::CommitMode::Append,
        );
        fs::write(p2.root().join("from-p2"), b"p2 member").unwrap();
        let a_ino = ino(&place.archive);
        let archive = place.archive.clone();
        let zst_reopen = zst;
        let mut p2 = Some(p2);
        fault::install(move |step| {
            match step {
                "archive write" => return Err(std::io::Error::from_raw_os_error(libc::ENOSPC)),
                "copy publish" => {
                    if let Some(p2) = p2.take() {
                        let committed = p2.commit_live(&archive, |p| {
                            Ok(if zst_reopen {
                                reopen_tar_zst(p, false).unwrap()
                            } else {
                                open_tar(p)
                            })
                        });
                        assert!(committed.unwrap(), "P2 commits");
                    }
                }
                _ => {}
            }
            Ok(())
        });
        let (p1, result) = place.commit(p1, way, crate::CommitMode::Auto);
        fault::clear();
        let error = result.expect_err(&case).to_string();
        assert!(
            error.contains("changed during the copy fallback"),
            "{case}: {error}"
        );
        assert_eq!(ino(&place.archive), a_ino, "{case}: P1 published a copy");
        let served = place.source(&place.archive);
        assert_eq!(
            read_member(served.as_ref(), "/from-p2"),
            b"p2 member",
            "{case}"
        );
        assert!(served.lookup("/from-p1", 0).is_none(), "{case}");
        if let Some(p1) = p1 {
            assert!(!p1.interval_disabled(), "{case}");
            let next = p1.commit_live(&place.archive, |p| Ok(place.source(p)));
            assert!(
                next.unwrap_err()
                    .to_string()
                    .contains("--force-base-mismatch"),
                "{case}: P1's rows describe the archive before P2's commit"
            );
        }
    }
}

// ---- R7-D1: no copy over an archive that changed since the gate ----

/// When P2 commits inside P1's commit, after P1's gate took its snapshot.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum AfterGate {
    /// Auto mode: right before the journaled replacement takes the archive
    /// lock (`before replace`, `before splice scan`); P1's replacement is
    /// refused because the stamp changed.
    BeforeLock,
    /// Copy mode: right after the gate's snapshot; no replacement is tried.
    Snapshot,
}

/// Regression (r16 review, R7-D1): a commit whose archive changed between its
/// gate and its write must not fall back to a copy. P2 (another `-w` overlay
/// on the same archive) appends its member in place after P1's gate accepted
/// snapshot S0. Before: P1's replacement was refused ("archive changed while
/// preparing append"), every refusal allowed the Auto copy fallback, and the
/// copy (checked against the gate only by device and inode) read P2's file
/// and published it as a new inode the gate never judged (a `tar --delete` in
/// that copy would drop P2's member); P2's next commit was then refused. In
/// Copy mode the same change between the gate and opening the copy was
/// published too. Now the copy source must be exactly the gate's snapshot
/// (unless this attempt itself rolled back): P1 is refused, P2's member stays,
/// the inode is unchanged and P2's next commit is accepted.
#[cfg(unix)]
#[test]
fn regression_no_copy_over_an_archive_changed_after_the_gate() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let mut failed = Vec::new();
    for when in [AfterGate::BeforeLock, AfterGate::Snapshot] {
        for (way, zst) in [
            (Way::Live, false),
            (Way::Live, true),
            (Way::Provenance, false),
            (Way::Provenance, true),
            (Way::Offline, false),
            (Way::Offline, true),
        ] {
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                no_copy_case(when, way, zst)
            }));
            fault::clear();
            crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| *hook.borrow_mut() = None);
            if run.is_err() {
                failed.push(format!("{when:?} {way:?} zst={zst}"));
            }
        }
    }
    assert!(failed.is_empty(), "failed cases: {failed:?}");
}

#[cfg(unix)]
fn no_copy_case(when: AfterGate, way: Way, zst: bool) {
    use std::rc::Rc;
    let case = format!("{when:?} {way:?} zst={zst}");
    let mode = match when {
        AfterGate::BeforeLock => crate::CommitMode::Auto,
        AfterGate::Snapshot => crate::CommitMode::Copy,
    };
    let place = Rc::new(Place::new(zst));
    let mut p1 = place.open(&place.overlay, way, mode);
    if way == Way::Provenance {
        p1.set_manifest_hashes(Some("all".into()));
    }
    fs::write(p1.root().join("from-p1"), b"p1 member").unwrap();
    let p2 = place.open(
        &place.root.join("overlay2"),
        Way::Live,
        crate::CommitMode::Append,
    );
    fs::write(p2.root().join("from-p2"), b"p2 member").unwrap();
    let a_ino = ino(&place.archive);
    let p2_commit = {
        let place = place.clone();
        move || {
            let committed = p2.commit_live(&place.archive, |p| Ok(place.source(p)));
            assert!(committed.unwrap(), "P2 commits");
            P2_BACK.with(|slot| *slot.borrow_mut() = Some(p2));
        }
    };
    P2_BACK.with(|slot| *slot.borrow_mut() = None);
    match when {
        AfterGate::BeforeLock => {
            let mut p2_commit = Some(p2_commit);
            fault::install(move |step| {
                if matches!(step, "before replace" | "before splice scan") {
                    if let Some(run) = p2_commit.take() {
                        run();
                    }
                }
                Ok(())
            });
        }
        AfterGate::Snapshot => {
            // Every commit judges the archive twice (an early identity check,
            // then the one snapshot its writes compare against): P2 commits
            // right after the second.
            let fire: Box<dyn FnOnce()> = Box::new(move || {
                crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(p2_commit));
                });
            });
            crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| *hook.borrow_mut() = Some(fire));
        }
    }
    let (_p1, result) = place.commit(p1, way, mode);
    fault::clear();
    crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| *hook.borrow_mut() = None);
    let p2 = P2_BACK
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_else(|| panic!("{case}: P2 never committed inside P1's commit"));
    let error = result.expect_err(&format!("{case}: P1 must be refused"));
    assert!(error.to_string().contains("changed"), "{case}: {error}");
    assert_eq!(ino(&place.archive), a_ino, "{case}: P1 published a copy");
    let served = place.source(&place.archive);
    assert_eq!(
        read_member(served.as_ref(), "/from-p2"),
        b"p2 member",
        "{case}"
    );
    assert!(served.lookup("/from-p1", 0).is_none(), "{case}");
    fs::write(p2.root().join("again-p2"), b"p2 again").unwrap();
    let next = p2.commit_live(&place.archive, |p| Ok(place.source(p)));
    assert!(
        next.unwrap_or_else(|e| panic!("{case}: P2's next commit: {e}")),
        "{case}"
    );
}

thread_local! {
    /// P2, handed back after it committed inside P1's commit.
    static P2_BACK: std::cell::RefCell<Option<WriteOverlay>> =
        const { std::cell::RefCell::new(None) };
}

// ---- R7-E1: every copy path compares the gate's stamp ----

/// When the other writer changes the archive inside P1's copy fallback.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum CopyWindow {
    /// Right after the copy source was opened and compared ("copy source
    /// opened"): the copy must still publish only the gate's file.
    Opened,
    /// P1's in-place append failed (ENOSPC) and rolled back; the writer acts
    /// right before the copy source is opened ("copy source open"), after P1
    /// released the lock.
    AfterRollback,
    /// P1's in-place append failed and rolled back; the writer acts right
    /// after the copy source was opened and re-checked ("copy source
    /// opened"): the publish guard must still refuse.
    OpenedAfterRollback,
    /// Right after the gate's snapshot (offline gzip/bzip2/xz and ZIP, which
    /// had no copy-source check at all).
    AfterGate,
}

/// The archive format of a copy-path row.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum CopyFmt {
    Tar,
    Zst,
    Gz,
    Bz2,
    Xz,
    Zip,
}

/// One copy/publish call site (R7-E1 inventory, PROGRESS "R6 fix round 7E").
#[cfg(unix)]
struct CopyRow {
    site: &'static str,
    fmt: CopyFmt,
    way: Way,
    mode: crate::CommitMode,
    window: CopyWindow,
    /// P1 also deletes the base member (Auto with deletions takes the copy).
    delete: bool,
}

/// Regression (r17 skeptic #1, R7-E1): every copy/publish path carries the
/// stamp its gate checked and compares against it. Before: the plain-TAR
/// provenance copy dropped the stamp `open_copy_source` had matched and took a
/// fresh one, so another writer's in-place append between the open and that
/// stat was copied and published (Copy mode, Auto with deletions); a copy after
/// a rollback compared only device and inode, so an append after P1 released
/// its lock was published; the offline gzip/bzip2/xz recompress and the ZIP
/// rebuild compared nothing and published without the copy guard. Now P1 is
/// refused, the archive keeps its inode and the other writer's bytes, and the
/// other writer's next commit is accepted. Rows marked control already passed.
#[cfg(unix)]
#[test]
fn regression_copy_paths_compare_the_gate_stamp() {
    use crate::CommitMode::{Auto, Copy};
    use CopyFmt::*;
    use CopyWindow::*;
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let row = |site, fmt, way, mode, window, delete| CopyRow {
        site,
        fmt,
        way,
        mode,
        window,
        delete,
    };
    let rows = [
        row(
            "A1 provenance tar copy",
            Tar,
            Way::Provenance,
            Copy,
            Opened,
            false,
        ),
        row(
            "A1 provenance tar auto+delete",
            Tar,
            Way::Provenance,
            Auto,
            Opened,
            true,
        ),
        row(
            "A2 provenance tar after rollback",
            Tar,
            Way::Provenance,
            Auto,
            AfterRollback,
            false,
        ),
        row(
            "A2 provenance tar opened after rollback",
            Tar,
            Way::Provenance,
            Auto,
            OpenedAfterRollback,
            false,
        ),
        row(
            "A3 live tar copy (control)",
            Tar,
            Way::Live,
            Copy,
            Opened,
            false,
        ),
        row(
            "A3 live tar after rollback",
            Tar,
            Way::Live,
            Auto,
            AfterRollback,
            false,
        ),
        row(
            "A4 offline tar copy (control)",
            Tar,
            Way::Offline,
            Copy,
            Opened,
            false,
        ),
        row(
            "A4 offline tar after rollback",
            Tar,
            Way::Offline,
            Auto,
            AfterRollback,
            false,
        ),
        row(
            "A5 live zst copy (control)",
            Zst,
            Way::Live,
            Copy,
            Opened,
            false,
        ),
        row(
            "A5 provenance zst copy (control)",
            Zst,
            Way::Provenance,
            Copy,
            Opened,
            false,
        ),
        row(
            "A5 offline zst copy (control)",
            Zst,
            Way::Offline,
            Copy,
            Opened,
            false,
        ),
        row(
            "A5 live zst after rollback",
            Zst,
            Way::Live,
            Auto,
            AfterRollback,
            false,
        ),
        row(
            "A5 provenance zst after rollback",
            Zst,
            Way::Provenance,
            Auto,
            AfterRollback,
            false,
        ),
        row(
            "A5 offline zst after rollback",
            Zst,
            Way::Offline,
            Auto,
            AfterRollback,
            false,
        ),
        row(
            "A6 offline tar.gz after gate",
            Gz,
            Way::Offline,
            Auto,
            AfterGate,
            false,
        ),
        row(
            "A6 offline tar.gz opened",
            Gz,
            Way::Offline,
            Auto,
            Opened,
            false,
        ),
        row(
            "A6 offline tar.bz2 after gate",
            Bz2,
            Way::Offline,
            Auto,
            AfterGate,
            false,
        ),
        row(
            "A6 offline tar.bz2 opened",
            Bz2,
            Way::Offline,
            Auto,
            Opened,
            false,
        ),
        row(
            "A6 offline tar.xz after gate",
            Xz,
            Way::Offline,
            Auto,
            AfterGate,
            false,
        ),
        row(
            "A6 offline tar.xz opened",
            Xz,
            Way::Offline,
            Auto,
            Opened,
            false,
        ),
        row(
            "A7 offline zip after gate",
            Zip,
            Way::Offline,
            Auto,
            AfterGate,
            false,
        ),
        row(
            "A7 offline zip opened",
            Zip,
            Way::Offline,
            Auto,
            Opened,
            false,
        ),
    ];
    let mut failed = Vec::new();
    for r in &rows {
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if matches!(r.fmt, Tar | Zst) {
                copy_row_with_p2(r)
            } else {
                copy_row_in_place(r)
            }
        }));
        fault::clear();
        crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| *hook.borrow_mut() = None);
        if run.is_err() {
            failed.push(r.site);
        }
    }
    assert!(failed.is_empty(), "failed rows: {failed:?}");
}

/// A `.tar`/`.tar.zst` row: P2 (another `-w` overlay) appends its member in
/// place inside P1's copy fallback.
#[cfg(unix)]
fn copy_row_with_p2(r: &CopyRow) {
    use std::rc::Rc;
    let case = r.site;
    let place = Rc::new(Place::new(r.fmt == CopyFmt::Zst));
    let mut p1 = place.open(&place.overlay, r.way, r.mode);
    if r.way == Way::Provenance {
        p1.set_manifest_hashes(Some("all".into()));
    }
    fs::write(p1.root().join("from-p1"), b"p1 member").unwrap();
    if r.delete {
        p1.unlink("/first").unwrap();
    }
    let p2 = place.open(
        &place.root.join("overlay2"),
        Way::Live,
        crate::CommitMode::Append,
    );
    fs::write(p2.root().join("from-p2"), b"p2 member").unwrap();
    let a_ino = ino(&place.archive);
    let mut p2_commit = Some({
        let place = place.clone();
        move || {
            let committed = p2.commit_live(&place.archive, |p| Ok(place.source(p)));
            assert!(committed.unwrap(), "P2 commits");
            P2_BACK.with(|slot| *slot.borrow_mut() = Some(p2));
        }
    });
    P2_BACK.with(|slot| *slot.borrow_mut() = None);
    let window = r.window;
    let mut wrote = false;
    fault::install(move |step| {
        match (window, step) {
            (CopyWindow::AfterRollback | CopyWindow::OpenedAfterRollback, "archive write")
                if !wrote =>
            {
                wrote = true;
                return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
            }
            (CopyWindow::AfterRollback, "copy source open") if wrote => {
                if let Some(run) = p2_commit.take() {
                    run();
                }
            }
            (CopyWindow::Opened, "copy source opened") => {
                if let Some(run) = p2_commit.take() {
                    run();
                }
            }
            (CopyWindow::OpenedAfterRollback, "copy source opened") if wrote => {
                if let Some(run) = p2_commit.take() {
                    run();
                }
            }
            _ => {}
        }
        Ok(())
    });
    let (_p1, result) = place.commit(p1, r.way, r.mode);
    fault::clear();
    let p2 = P2_BACK
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_else(|| panic!("{case}: P2 never committed inside P1's commit"));
    let error = match result {
        Ok(done) => panic!("{case}: P1 must be refused, got Ok({done})"),
        Err(e) => e.to_string(),
    };
    assert!(error.contains("changed"), "{case}: {error}");
    assert_eq!(ino(&place.archive), a_ino, "{case}: P1 published a copy");
    let served = place.source(&place.archive);
    assert_eq!(
        read_member(served.as_ref(), "/from-p2"),
        b"p2 member",
        "{case}"
    );
    assert!(served.lookup("/from-p1", 0).is_none(), "{case}");
    fs::write(p2.root().join("again-p2"), b"p2 again").unwrap();
    let next = p2.commit_live(&place.archive, |p| Ok(place.source(p)));
    assert!(
        next.unwrap_or_else(|e| panic!("{case}: P2's next commit: {e}")),
        "{case}"
    );
}

/// The bytes of a one-member archive `x` in `fmt`.
#[cfg(unix)]
fn copy_row_archive(fmt: CopyFmt, name: &str, payload: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let tar = dir.path().join("x.tar");
    write_tar(&tar, &[(name, payload)]);
    let plain = fs::read(&tar).unwrap();
    match fmt {
        CopyFmt::Gz => {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(&plain).unwrap();
            enc.finish().unwrap()
        }
        CopyFmt::Bz2 => {
            let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            enc.write_all(&plain).unwrap();
            enc.finish().unwrap()
        }
        CopyFmt::Xz => {
            let mut enc = xz2::write::XzEncoder::new(Vec::new(), 6);
            enc.write_all(&plain).unwrap();
            enc.finish().unwrap()
        }
        CopyFmt::Zip => {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            zip.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(payload).unwrap();
            zip.finish().unwrap().into_inner()
        }
        CopyFmt::Tar | CopyFmt::Zst => unreachable!("in-place rows are gzip/bzip2/xz/zip"),
    }
}

/// An offline gzip/bzip2/xz/ZIP row: another writer rewrites the archive in
/// place (same inode, a valid archive holding `x`) inside P1's commit.
#[cfg(unix)]
fn copy_row_in_place(r: &CopyRow) {
    use std::io::Write;
    let case = r.site;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let ext = match r.fmt {
        CopyFmt::Gz => "tar.gz",
        CopyFmt::Bz2 => "tar.bz2",
        CopyFmt::Xz => "tar.xz",
        _ => "zip",
    };
    let archive = root.join(format!("base.{ext}"));
    fs::write(&archive, copy_row_archive(r.fmt, "first", b"first member")).unwrap();
    let plain = root.join("plain.tar");
    write_tar(&plain, &[("first", b"first member")]);
    let token = || {
        ClassifiedBase::for_tests(
            open_tar(&plain),
            ServedKind::Archive,
            Some(ServedLocation::Local(archive.clone())),
        )
    };
    let overlay = root.join("overlay");
    let p1 = open_with(&token(), &overlay, BaseDigestRequest::Compute, false).unwrap();
    fs::write(p1.root().join("from-p1"), b"p1 member").unwrap();
    drop(p1);
    let theirs = copy_row_archive(r.fmt, "x", b"the other writer's x");
    let a_ino = ino(&archive);
    let rewrite = {
        let (archive, theirs) = (archive.clone(), theirs.clone());
        move || {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&archive)
                .unwrap();
            f.write_all(&theirs).unwrap();
            f.sync_all().unwrap();
        }
    };
    match r.window {
        CopyWindow::AfterGate => {
            // The offline commit judges the archive twice; rewrite right
            // after the second (the snapshot every write compares against).
            let fire: Box<dyn FnOnce()> = Box::new(move || {
                crate::overlay_gate::AFTER_SNAPSHOT
                    .with(|hook| *hook.borrow_mut() = Some(Box::new(rewrite)));
            });
            crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| *hook.borrow_mut() = Some(fire));
        }
        _ => {
            let mut rewrite = Some(rewrite);
            fault::install(move |step| {
                if step == "copy source opened" {
                    if let Some(run) = rewrite.take() {
                        run();
                    }
                }
                Ok(())
            });
        }
    }
    let opts = CommitOverlayOptions {
        yes: true,
        mode: r.mode,
        ..Default::default()
    };
    let result = crate::commit_overlay(&overlay, &archive, &token(), &opts);
    fault::clear();
    crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| *hook.borrow_mut() = None);
    let error = match result {
        Ok(done) => panic!("{case}: P1 must be refused, got Ok({done})"),
        Err(e) => e.to_string(),
    };
    assert!(error.contains("changed"), "{case}: {error}");
    assert_eq!(ino(&archive), a_ino, "{case}: P1 published a copy");
    assert_eq!(
        fs::read(&archive).unwrap(),
        theirs,
        "{case}: the other writer's archive"
    );
}

// ---- R7-E2: an overlay database path that is not a regular file ----

/// Replace `fx`'s overlay database with a symlink to a file that does not
/// exist; returns the symlink target.
#[cfg(unix)]
fn dangle_db(overlay: &Path) -> PathBuf {
    let db = overlay.join(HIDDEN_DB);
    let target = overlay.with_file_name("nowhere.sqlite");
    fs::rename(&db, overlay.with_file_name("saved.sqlite")).unwrap();
    std::os::unix::fs::symlink(&target, &db).unwrap();
    target
}

/// Regression (r17 skeptic #2, R7-E2): every overlay-database existence check
/// `lstat`s the path; only a missing entry is "no database". A dangling
/// symlink (or a directory, a FIFO) was read as absent by `exists()` /
/// `is_file()` / `metadata()`, so the raw-directory commit and the
/// unrecorded-recovery owner recovered B (another archive with its own
/// journal, renamed over A) before any gate, `commit_overlay` advised the
/// raw-directory API, a restamp or a baseline refresh silently skipped the
/// rows, and `--base-digest none` treated the overlay as new. Each row is one
/// call site of the R7-E2 inventory (PROGRESS "R6 fix round 7E").
#[cfg(unix)]
#[test]
fn regression_overlay_db_entry_not_a_regular_file() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    let mut failed = Vec::new();
    let mut row = |site: &str, run: &dyn Fn()| {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).is_err() {
            failed.push(site.to_owned());
        }
        crate::overlay_gate::AFTER_SNAPSHOT.with(|hook| *hook.borrow_mut() = None);
        crate::write_overlay::BEFORE_OFFLINE_RECOVERY.with(|hook| *hook.borrow_mut() = None);
    };
    // B3: `commit_overlay` must not call a dangling database "no database"
    // (and point at the raw-directory API); B is untouched.
    row("B3 commit_overlay", &|| {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::Compute, false));
        let target = dangle_db(&fx.overlay);
        let (bytes, journal, journal_bytes) = rename_b_over_a(&fx, false);
        let error =
            crate::commit_overlay(&fx.overlay, &fx.archive, &archive_token(&fx.archive), &opts)
                .expect_err("refused")
                .to_string();
        assert!(!error.contains("has no database"), "{error}");
        assert!(fs::read(&fx.archive).unwrap() == bytes, "B untouched");
        assert!(
            fs::read(&journal).is_ok_and(|j| j == journal_bytes),
            "journal kept"
        );
        assert!(!target.exists(), "nothing created through the symlink");
    });
    // B4: the raw-directory commit refuses a dangling database instead of
    // recovering B's journal by inode and committing.
    row("B4 commit_overlay_raw_dir", &|| {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::Compute, false));
        let target = dangle_db(&fx.overlay);
        let (bytes, journal, journal_bytes) = rename_b_over_a(&fx, false);
        let result = crate::commit_overlay_raw_dir(&fx.overlay, &fx.archive, &opts);
        assert!(
            result.is_err(),
            "refused: {:?}",
            result.map(|r| r.committed)
        );
        assert!(fs::read(&fx.archive).unwrap() == bytes, "B untouched");
        assert!(
            fs::read(&journal).is_ok_and(|j| j == journal_bytes),
            "journal kept"
        );
        assert!(!target.exists(), "nothing created through the symlink");
    });
    // B5/B6: the database becomes a dangling symlink and B is renamed over A
    // after the caller's gate accepted A, right before the commit picks its
    // recovery owner: the owner and the snapshot gate inside the commit must
    // treat the record as unreadable.
    row("B5/B6 commit_overlay_inner owner + snapshot", &|| {
        let fx = Fixture::new();
        let ov = fx.open(BaseDigestRequest::Compute, false);
        fs::write(ov.root().join("new"), b"new").unwrap();
        drop(ov);
        let foreign = fx.archive.with_file_name("foreign.tar");
        write_tar(&foreign, &[("b", b"bb"), ("c", b"c")]);
        interrupt_append(&foreign);
        let journal = ratarmount_compress::commit_journal::journal_path(&foreign);
        let journal_bytes = fs::read(&journal).unwrap();
        let bytes = fs::read(&foreign).unwrap();
        let (overlay, archive) = (fx.overlay.clone(), fx.archive.clone());
        crate::write_overlay::BEFORE_OFFLINE_RECOVERY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                dangle_db(&overlay);
                fs::rename(&foreign, &archive).unwrap();
            }));
        });
        let result =
            crate::commit_overlay(&fx.overlay, &fx.archive, &archive_token(&fx.archive), &opts);
        assert!(result.is_err(), "refused: {result:?}");
        assert!(fs::read(&fx.archive).unwrap() == bytes, "B untouched");
        assert!(
            fs::read(&journal).is_ok_and(|j| j == journal_bytes),
            "journal kept"
        );
    });
    // B9: a restamp through a dangling database fails instead of silently
    // skipping the rows.
    row("B9 Rows::Path", &|| {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::Compute, false));
        let target = dangle_db(&fx.overlay);
        let db = fx.overlay.join(HIDDEN_DB);
        let rows = crate::journal_recovery::Rows::path(&db);
        assert!(
            rows.with(|_, _| Ok(())).is_err(),
            "restamp must not be skipped"
        );
        assert!(!target.exists(), "nothing created through the symlink");
    });
    // B10: `--base-digest none` treats an overlay with a dangling database as
    // a reopen (the recorded identity is compared), not as a new overlay.
    row("B10 plan_excludes", &|| {
        let fx = Fixture::new();
        let base = fx.archive.with_file_name("basedir");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("f"), b"f").unwrap();
        drop(fx.open(BaseDigestRequest::Compute, false));
        dangle_db(&fx.overlay);
        let info = crate::overlay_meta::OverlayCreateInfo {
            base_url: base.to_str().unwrap().to_owned(),
            base_digest: BaseDigestRequest::None,
            local_path: Some(base.clone()),
            ..Default::default()
        };
        let plan = crate::overlay_meta::plan_excludes(&info, &fx.overlay).unwrap();
        assert!(plan.is_some(), "a dangling database is not a new overlay");
    });
    // B11: the committed-baseline refresh fails instead of skipping.
    row("B11 refresh_committed_base_offline", &|| {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::Compute, false));
        let target = dangle_db(&fx.overlay);
        let refreshed =
            crate::overlay_meta::refresh_committed_base_offline(&fx.overlay, None, &fx.archive);
        assert!(refreshed.is_err(), "refresh must not be skipped");
        assert!(!target.exists(), "nothing created through the symlink");
    });
    assert!(failed.is_empty(), "failed rows: {failed:?}");
}

/// Regression (r18 skeptic #2, R7-F2): an offline commit whose overlay
/// database is DELETED after the caller's gate accepted A, with B (another
/// archive carrying its own journal) renamed over A, downgraded the recovery
/// owner (and the snapshot gate) to `Owner::Inode` because the database was
/// now "absent". B's journal matched B's inode, so recovery rewrote B and
/// removed its journal before the #96 marker refused the commit. A commit
/// that has a recorded identity keeps `Owner::Recorded`: the vanished record
/// refuses.
#[test]
fn regression_offline_db_deleted_after_gate_keeps_recorded_owner() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    fs::write(ov.root().join("new"), b"new").unwrap();
    drop(ov);
    let foreign = fx.archive.with_file_name("foreign.tar");
    write_tar(&foreign, &[("b", b"bb"), ("c", b"c")]);
    interrupt_append(&foreign);
    let journal = ratarmount_compress::commit_journal::journal_path(&foreign);
    let journal_bytes = fs::read(&journal).unwrap();
    let bytes = fs::read(&foreign).unwrap();
    let (overlay, archive) = (fx.overlay.clone(), fx.archive.clone());
    crate::write_overlay::BEFORE_OFFLINE_RECOVERY.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            fs::remove_file(overlay.join(HIDDEN_DB)).unwrap();
            fs::rename(&foreign, &archive).unwrap();
        }));
    });
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    let result =
        crate::commit_overlay(&fx.overlay, &fx.archive, &archive_token(&fx.archive), &opts);
    crate::write_overlay::BEFORE_OFFLINE_RECOVERY.with(|hook| *hook.borrow_mut() = None);
    assert!(result.is_err(), "refused: {result:?}");
    assert!(fs::read(&fx.archive).unwrap() == bytes, "B untouched");
    assert!(
        fs::read(&journal).is_ok_and(|j| j == journal_bytes),
        "B's journal kept"
    );
}

/// What replaces the overlay database in [`regression_offline_gates_refuse_non_regular_db`].
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum NotADb {
    /// A symlink to `/dev/null` (SQLite reads it as an empty database).
    DevNull,
    /// A FIFO (an `O_RDONLY` open blocks until a writer appears).
    Fifo,
}

#[cfg(unix)]
fn replace_db(overlay: &Path, with: NotADb) {
    let db = overlay.join(HIDDEN_DB);
    fs::rename(&db, overlay.with_file_name("saved.sqlite")).unwrap();
    match with {
        NotADb::DevNull => std::os::unix::fs::symlink("/dev/null", &db).unwrap(),
        NotADb::Fifo => {
            use std::os::unix::ffi::OsStrExt;
            let c = std::ffi::CString::new(db.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
        }
    }
}

/// An archive's bytes and its journal's bytes.
#[cfg(unix)]
type ArchiveAndJournal = (Vec<u8>, Vec<u8>);

/// Regression (r18 skeptic #1, R7-F1): the offline gates opened the overlay
/// database without checking what it is. A symlink to `/dev/null` there read
/// as an empty database (no record), so a gate accepted any journal that was
/// the file's own; a FIFO there blocked the gate's open forever. Every row
/// must refuse promptly, with the archive and its journal untouched:
/// - `entry`: A's database is replaced and B (another archive carrying its own
///   journal) is renamed over A before `commit_overlay`; its entry gate
///   accepted and recovery rewrote B before the plan's regular-file check
///   refused.
/// - `inside`: after the entry gate accepted A, the database is replaced and A
///   gets a journal started on a state that is not the recorded one (another
///   writer appended and crashed); the recovery owner's gate under the archive
///   lock saw no record and rolled A back.
#[cfg(unix)]
#[test]
fn regression_offline_gates_refuse_non_regular_db() {
    use std::sync::{Arc, Mutex};
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let mut failed = Vec::new();
    for with in [NotADb::DevNull, NotADb::Fifo] {
        for inside in [false, true] {
            let case = format!("{with:?} {}", if inside { "inside" } else { "entry" });
            let fx = Fixture::new();
            let ov = fx.open(BaseDigestRequest::Compute, false);
            fs::write(ov.root().join("new"), b"new").unwrap();
            drop(ov);
            // B's journal keeps the name it was started under.
            let foreign = fx.archive.with_file_name("foreign.tar");
            let journal = ratarmount_compress::commit_journal::journal_path(if inside {
                &fx.archive
            } else {
                &foreign
            });
            // The archive and journal bytes recovery must leave alone.
            let expected: Arc<Mutex<Option<ArchiveAndJournal>>> = Arc::default();
            if !inside {
                write_tar(&foreign, &[("b", b"bb"), ("c", b"c")]);
                interrupt_append(&foreign);
                *expected.lock().unwrap() =
                    Some((fs::read(&foreign).unwrap(), fs::read(&journal).unwrap()));
                replace_db(&fx.overlay, with);
                fs::rename(&foreign, &fx.archive).unwrap();
            }
            let (overlay, archive) = (fx.overlay.clone(), fx.archive.clone());
            let (tx, rx) = std::sync::mpsc::channel();
            let seen = expected.clone();
            // The hook is thread-local: install it in the committing thread.
            std::thread::spawn(move || {
                let token = archive_token(&archive);
                if inside {
                    let (overlay, archive) = (overlay.clone(), archive.clone());
                    crate::write_overlay::BEFORE_OFFLINE_RECOVERY.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            replace_db(&overlay, with);
                            use std::io::Write;
                            fs::File::options()
                                .append(true)
                                .open(&archive)
                                .unwrap()
                                .write_all(&[0u8; 512])
                                .unwrap();
                            interrupt_append(&archive);
                            let journal =
                                ratarmount_compress::commit_journal::journal_path(&archive);
                            *seen.lock().unwrap() =
                                Some((fs::read(&archive).unwrap(), fs::read(journal).unwrap()));
                        }));
                    });
                }
                let opts = CommitOverlayOptions {
                    yes: true,
                    ..Default::default()
                };
                let result = crate::commit_overlay(&overlay, &archive, &token, &opts)
                    .map_err(|e| e.to_string());
                let _ = tx.send(result);
            });
            let outcome = rx.recv_timeout(std::time::Duration::from_secs(20));
            if outcome.is_err() {
                // Unblock an open stuck on the FIFO, then let it finish.
                use std::os::unix::fs::OpenOptionsExt;
                let _ = fs::File::options()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(fx.overlay.join(HIDDEN_DB));
                let _ = rx.recv_timeout(std::time::Duration::from_secs(20));
                failed.push(format!("{case}: blocked on the database open"));
                continue;
            }
            let (bytes, journal_bytes) = expected.lock().unwrap().clone().expect("seam ran");
            match outcome.unwrap() {
                Ok(done) => failed.push(format!("{case}: committed ({done})")),
                Err(_) if fs::read(&fx.archive).unwrap() != bytes => {
                    failed.push(format!("{case}: the archive was rewritten"))
                }
                Err(_) if !fs::read(&journal).is_ok_and(|j| j == journal_bytes) => {
                    failed.push(format!("{case}: the archive's journal was removed"))
                }
                Err(_) => {}
            }
        }
    }
    assert!(failed.is_empty(), "failed rows: {failed:?}");
}

// ---- R7-C5: one target rule, one restamp rule, disjunct 3, idempotent rollback ----

fn strong_fixture() -> Fixture {
    let fx = Fixture::new();
    // An old mtime, so any write this test makes moves it.
    fs::File::options()
        .write(true)
        .open(&fx.archive)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000),
            ),
        )
        .unwrap();
    fx
}

fn strong_digest() -> BaseDigestRequest {
    BaseDigestRequest::Supplied(format!("sha256:{}", "0".repeat(64)))
}

fn digest_rows(overlay: &Path) -> Vec<Option<String>> {
    read_rows(
        overlay,
        &["base_digest_kind", "base_digest", "stack_digest"],
    )
}

/// Regression (r15 #4): a rollback that could not restore the mtime (EPERM
/// for a non-owner) left the rows on the old mtime, so the next commit was
/// refused as a changed base. The rows follow the restored file (the journal
/// was started on the recorded state); a strong digest is kept (the bytes are
/// the recorded bytes); the error is a plain failure and the next commit
/// succeeds.
#[cfg(unix)]
#[test]
fn regression_rollback_with_unrestored_mtime_restamps_and_the_next_commit_accepts() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = strong_fixture();
    let mut ov = fx.open(strong_digest(), false);
    ov.set_commit_mode(crate::CommitMode::Append);
    fs::write(ov.root().join("one"), b"one").unwrap();
    let bytes = fs::read(&fx.archive).unwrap();
    let pre = fs::metadata(&fx.archive).unwrap().modified().unwrap();
    let digest = ov.recorded_digest_for_tests();
    ratarmount_compress::commit_journal::fault::install(|step| match step {
        "archive write" => Err(std::io::Error::from_raw_os_error(libc::ENOSPC)),
        "rollback mtime" => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        _ => Ok(()),
    });
    let result = commit(&ov, &fx.archive, Path_::Live);
    ratarmount_compress::commit_journal::fault::clear();
    let error = result.unwrap_err();
    assert!(
        !matches!(
            error,
            crate::OverlayError::Committed(_) | crate::OverlayError::JournalPending(_)
        ),
        "{error}"
    );
    assert!(!ov.interval_disabled());
    assert_ne!(fs::metadata(&fx.archive).unwrap().modified().unwrap(), pre);
    assert_eq!(fs::read(&fx.archive).unwrap(), bytes, "rolled back");
    assert!(!journal_path(&fx.archive).exists());
    assert_eq!(ov.recorded_stamp_for_tests(), stamp_rows(&fx.archive));
    assert_eq!(ov.recorded_digest_for_tests(), digest, "strong digest kept");
    assert!(
        commit(&ov, &fx.archive, Path_::Live).unwrap(),
        "next commit"
    );
}

/// Regression (r15 #4, crash recovery): a torn append rolled back by recovery
/// whose mtime cannot be restored restamps the rows (the journal was started
/// on the recorded state), so a reopen and the commit gate accept the file.
#[cfg(unix)]
#[test]
fn regression_recovery_rollback_with_unrestored_mtime_restamps_and_reopen_accepts() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = strong_fixture();
    drop(fx.open(strong_digest(), false));
    let bytes = fs::read(&fx.archive).unwrap();
    interrupt_append(&fx.archive);
    ratarmount_compress::commit_journal::fault::install(|step| match step {
        "rollback mtime" => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        _ => Ok(()),
    });
    let applied = crate::recover_journal_at(
        &fx.archive,
        Some(&fx.overlay.join(HIDDEN_DB)),
        crate::Owner::Inode,
    );
    ratarmount_compress::commit_journal::fault::clear();
    assert!(!applied.unwrap().expect("rolled back").rolled_forward);
    assert_eq!(fs::read(&fx.archive).unwrap(), bytes);
    let rows = recorded_rows(&fx.overlay);
    assert_eq!((rows[0].clone(), rows[1].clone()), stamp_rows(&fx.archive));
    crate::overlay_gate::check_commit_base_offline(
        &fx.overlay,
        &archive_token(&fx.archive),
        &fx.archive,
    )
    .unwrap();
    drop(fx.open(BaseDigestRequest::Compute, false));
}

/// Regression (r15 #4 + crash): the rollback restamped the rows (unrestored
/// mtime) and then its unlink failed: the journal stays (`P`), the rows
/// describe the rolled-back file. Every gate accepts the file (disjunct 3:
/// the torn journal's rows already describe the old bytes), and the later
/// recovery writes nothing (the old bytes are in place) and only unlinks.
#[cfg(unix)]
#[test]
fn regression_rows_rolled_back_then_unlink_failed_is_accepted_by_every_gate() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = strong_fixture();
    let mut ov = fx.open(strong_digest(), false);
    ov.set_commit_mode(crate::CommitMode::Append);
    fs::write(ov.root().join("one"), b"one").unwrap();
    ratarmount_compress::commit_journal::fault::install(|step| match step {
        "archive write" => Err(std::io::Error::from_raw_os_error(libc::ENOSPC)),
        "rollback mtime" => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        "rollback unlink" => Err(std::io::Error::other("injected unlink failure")),
        _ => Ok(()),
    });
    let result = commit(&ov, &fx.archive, Path_::Live);
    ratarmount_compress::commit_journal::fault::clear();
    let error = result.unwrap_err();
    assert!(
        matches!(error, crate::OverlayError::JournalPending(_)),
        "{error}"
    );
    let journal = ratarmount_compress::commit_journal::pending(&fx.archive)
        .unwrap()
        .expect("journal kept");
    assert!(!journal.complete);
    assert_eq!(ov.recorded_stamp_for_tests(), stamp_rows(&fx.archive));
    drop(ov);
    assert_eq!(
        classify_mount_journal(&records_of(&fx), &fx.archive).unwrap(),
        MountJournal::Own
    );
    crate::overlay_gate::check_commit_base_offline(
        &fx.overlay,
        &archive_token(&fx.archive),
        &fx.archive,
    )
    .unwrap();
    let (rows, mtime) = (
        recorded_rows(&fx.overlay),
        fs::metadata(&fx.archive).unwrap().modified().unwrap(),
    );
    crate::recover_journal_at(
        &fx.archive,
        Some(&fx.overlay.join(HIDDEN_DB)),
        crate::Owner::Inode,
    )
    .unwrap()
    .expect("unlinked");
    assert!(!journal_path(&fx.archive).exists());
    assert_eq!(
        fs::metadata(&fx.archive).unwrap().modified().unwrap(),
        mtime
    );
    assert_eq!(recorded_rows(&fx.overlay), rows);
    drop(fx.open(BaseDigestRequest::Compute, false));
}

/// Regression: a roll-forward always invalidates a strong digest, also when
/// the rows already equal the final stamp (an equal-length, equal-mtime
/// commit, or relocation rows written before a deferred recovery). A
/// recovery of a journal started on another state still leaves the rows.
#[cfg(unix)]
#[test]
fn regression_equal_stamp_roll_forward_invalidates_the_strong_digest() {
    use crate::journal_recovery::{restamp_rows, Restamp};
    use std::os::unix::fs::MetadataExt;
    for mode in [Restamp::Recovery, Restamp::Commit] {
        let fx = Fixture::new();
        drop(fx.open(strong_digest(), false));
        let rows = recorded_rows(&fx.overlay);
        let (size, mtime): (u64, i128) = (
            rows[0].as_ref().unwrap().parse().unwrap(),
            rows[1].as_ref().unwrap().parse().unwrap(),
        );
        let meta = fs::metadata(&fx.archive).unwrap();
        let applied = |pre: (u64, i128)| ratarmount_compress::commit_journal::Applied {
            rolled_forward: true,
            pre_len: pre.0,
            pre_mtime_ns: pre.1,
            new_len: size,
            dev: meta.dev(),
            ino: meta.ino(),
            final_len: size,
            final_mtime_ns: mtime,
        };
        let db = fx.overlay.join(HIDDEN_DB);
        // pre == final == rows.
        let conn = rusqlite::Connection::open(&db).unwrap();
        restamp_rows(&conn, &fx.archive, &applied((size, mtime)), mode, true).unwrap();
        drop(conn);
        assert_eq!(
            recorded_rows(&fx.overlay)[2].as_deref(),
            Some("pending"),
            "{mode:?}"
        );
        assert_eq!(digest_rows(&fx.overlay)[2], None, "{mode:?}: stack digest");
        if mode == Restamp::Recovery {
            // pre != final == rows (relocation rows): rows unchanged, digest pending.
            let fx = Fixture::new();
            drop(fx.open(strong_digest(), false));
            let meta = fs::metadata(&fx.archive).unwrap();
            let rows = recorded_rows(&fx.overlay);
            let (size, mtime): (u64, i128) = (
                rows[0].as_ref().unwrap().parse().unwrap(),
                rows[1].as_ref().unwrap().parse().unwrap(),
            );
            let other = ratarmount_compress::commit_journal::Applied {
                rolled_forward: true,
                pre_len: size - 512,
                pre_mtime_ns: 5,
                new_len: size,
                dev: meta.dev(),
                ino: meta.ino(),
                final_len: size,
                final_mtime_ns: mtime,
            };
            let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
            restamp_rows(&conn, &fx.archive, &other, mode, true).unwrap();
            drop(conn);
            let now = recorded_rows(&fx.overlay);
            assert_eq!(
                (now[0].clone(), now[1].clone()),
                (rows[0].clone(), rows[1].clone())
            );
            assert_eq!(now[2].as_deref(), Some("pending"));
            // pre != final != rows: nothing.
            let fx = Fixture::new();
            drop(fx.open(strong_digest(), false));
            let before = (recorded_rows(&fx.overlay), digest_rows(&fx.overlay));
            let meta = fs::metadata(&fx.archive).unwrap();
            let foreign = ratarmount_compress::commit_journal::Applied {
                rolled_forward: true,
                pre_len: 1,
                pre_mtime_ns: 5,
                new_len: 9,
                dev: meta.dev(),
                ino: meta.ino(),
                final_len: 9,
                final_mtime_ns: 7,
            };
            let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
            restamp_rows(&conn, &fx.archive, &foreign, mode, true).unwrap();
            drop(conn);
            assert_eq!(
                (recorded_rows(&fx.overlay), digest_rows(&fx.overlay)),
                before
            );
        }
    }
}

/// Pin (R7-B6): a forced commit over a swapped base whose append rolls back
/// with an unrestored mtime keeps the record (the journal was started on
/// another state): the next unforced commit is still refused.
#[cfg(unix)]
#[test]
fn regression_forced_rollback_over_a_swapped_base_keeps_the_record() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = strong_fixture();
    // Opened (forced) while the base is still the recorded one.
    let mut ov = fx.open(strong_digest(), true);
    fx.swap_for_other_tar();
    fs::File::options()
        .write(true)
        .open(&fx.archive)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_500),
            ),
        )
        .unwrap();
    ov.set_commit_mode(crate::CommitMode::Append);
    fs::write(ov.root().join("one"), b"one").unwrap();
    let rows_now = (recorded_rows_live(&ov), ov.recorded_digest_for_tests());
    ratarmount_compress::commit_journal::fault::install(|step| match step {
        "archive write" => Err(std::io::Error::from_raw_os_error(libc::ENOSPC)),
        "rollback mtime" => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        _ => Ok(()),
    });
    let result = commit(&ov, &fx.archive, Path_::Live);
    ratarmount_compress::commit_journal::fault::clear();
    assert!(result.is_err());
    assert_eq!(
        (recorded_rows_live(&ov), ov.recorded_digest_for_tests()),
        rows_now,
        "a forced rollback moved the record"
    );
    drop(ov);
    let refused = open_with(
        &archive_token(&fx.archive),
        &fx.overlay,
        BaseDigestRequest::Compute,
        false,
    )
    .err()
    .expect("the next unforced open is refused")
    .to_string();
    assert!(refused.contains("--force-base-mismatch"), "{refused}");
}

/// Regression (B6 rewritten): the commit hook after a rollback moves the
/// rows only when the journal was started on the recorded stamp and the
/// mtime could not be restored; a strong digest is kept; a rollback that
/// ended at another length is an error (impossible by construction).
#[cfg(unix)]
#[test]
fn regression_commit_restamp_after_rollback_moves_only_a_started_unrestored_stamp() {
    use crate::journal_recovery::{restamp_rows, Restamp};
    use std::os::unix::fs::MetadataExt;
    for case in ["exact", "started", "not started", "other length"] {
        let fx = Fixture::new();
        drop(fx.open(strong_digest(), false));
        let rows = recorded_rows(&fx.overlay);
        let digest = digest_rows(&fx.overlay);
        let (size, mtime): (u64, i128) = (
            rows[0].as_ref().unwrap().parse().unwrap(),
            rows[1].as_ref().unwrap().parse().unwrap(),
        );
        let meta = fs::metadata(&fx.archive).unwrap();
        let (pre_mtime, final_len, final_mtime) = match case {
            "exact" => (mtime, size, mtime),
            "started" => (mtime, size, mtime + 99),
            "not started" => (mtime - 5, size, mtime + 99),
            _ => (mtime, size + 7, mtime + 99),
        };
        let applied = ratarmount_compress::commit_journal::Applied {
            rolled_forward: false,
            pre_len: size,
            pre_mtime_ns: pre_mtime,
            new_len: size + 512,
            dev: meta.dev(),
            ino: meta.ino(),
            final_len,
            final_mtime_ns: final_mtime,
        };
        let conn = rusqlite::Connection::open(fx.overlay.join(HIDDEN_DB)).unwrap();
        let result = restamp_rows(&conn, &fx.archive, &applied, Restamp::Commit, true);
        drop(conn);
        let now = recorded_rows(&fx.overlay);
        match case {
            "started" => {
                result.unwrap();
                assert_eq!(
                    now[1].as_deref(),
                    Some((mtime + 99).to_string().as_str()),
                    "{case}"
                );
                assert_eq!(now[0], rows[0], "{case}");
            }
            "other length" => {
                assert!(result.is_err(), "{case}");
                assert_eq!(now, rows, "{case}");
            }
            _ => {
                result.unwrap();
                assert_eq!(now, rows, "{case}");
            }
        }
        assert_eq!(
            digest_rows(&fx.overlay),
            digest,
            "{case}: strong digest kept"
        );
    }
}

/// Pins (Astra v4 F2): a journal's target is never inferred from matching
/// stamps. Union member B is a timestamp-preserving copy of the recorded
/// base A and carries its own complete journal (started on A's recorded
/// stamp). With A in place, and again with A's name replaced by C carrying
/// B's final stamp: the mount defers B, recovering B leaves A's rows and
/// strong digest alone, and a reopen over C is refused.
#[cfg(unix)]
#[test]
fn regression_union_member_journal_is_never_adopted_from_matching_stamps() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for replaced in [false, true] {
        let fx = strong_fixture();
        drop(fx.open(strong_digest(), false));
        let before = (recorded_rows(&fx.overlay), digest_rows(&fx.overlay));
        let other = fx.archive.parent().unwrap().join("member");
        fs::create_dir(&other).unwrap();
        let b = other.join("base.tar");
        fs::copy(&fx.archive, &b).unwrap();
        let a_mtime = fs::metadata(&fx.archive).unwrap().modified().unwrap();
        fs::File::options()
            .write(true)
            .open(&b)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(a_mtime))
            .unwrap();
        interrupt_complete(&b);
        if replaced {
            let c = fx.archive.with_file_name("c.tar");
            fs::copy(&b, &c).unwrap();
            let b_mtime = fs::metadata(&b).unwrap().modified().unwrap();
            fs::File::options()
                .write(true)
                .open(&c)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(b_mtime))
                .unwrap();
            fs::rename(&c, &fx.archive).unwrap();
        }
        assert!(
            matches!(
                classify_mount_journal(&records_of(&fx), &b).unwrap(),
                MountJournal::Deferred { .. }
            ),
            "replaced={replaced}: the member's journal is not the base's"
        );
        crate::recover_journal_at(&b, Some(&fx.overlay.join(HIDDEN_DB)), crate::Owner::Inode)
            .unwrap()
            .expect("B rolled forward");
        assert_eq!(
            (recorded_rows(&fx.overlay), digest_rows(&fx.overlay)),
            before,
            "replaced={replaced}: A's rows moved"
        );
        if replaced {
            let refused = open_with(
                &archive_token(&fx.archive),
                &fx.overlay,
                BaseDigestRequest::Compute,
                false,
            )
            .err()
            .expect("C at A's name is refused")
            .to_string();
            assert!(refused.contains("--force-base-mismatch"), "{refused}");
        }
    }
}

/// Regression (Astra v4 F3): the target rule compares the CURRENT device
/// and inode of the recorded base with the locked file, never the inode
/// alone. Another name of the base (a hard link in another directory)
/// recovers and restamps like the base; the same inode number on another
/// device is not the base.
#[cfg(unix)]
#[test]
fn regression_journal_target_compares_device_and_inode() {
    use std::os::unix::fs::MetadataExt;
    let fx = Fixture::new();
    drop(fx.open(strong_digest(), false));
    let meta = OverlayMeta::read(&fx.overlay).unwrap().unwrap();
    let base = fs::metadata(&fx.archive).unwrap();
    let elsewhere = fx.archive.with_file_name("elsewhere.tar");
    assert!(crate::journal_recovery::journal_targets_record(
        &meta,
        &elsewhere,
        (base.dev(), base.ino())
    ));
    assert!(!crate::journal_recovery::journal_targets_record(
        &meta,
        &elsewhere,
        (base.dev().wrapping_add(1), base.ino())
    ));
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    // Recovered through a hard link in another directory: restamped.
    let other = fx.archive.parent().unwrap().join("links");
    fs::create_dir(&other).unwrap();
    let link = other.join("link.tar");
    fs::hard_link(&fx.archive, &link).unwrap();
    interrupt_complete(&fx.archive);
    crate::recover_journal_at(
        &link,
        Some(&fx.overlay.join(HIDDEN_DB)),
        crate::Owner::Inode,
    )
    .unwrap()
    .expect("rolled forward");
    let rows = recorded_rows(&fx.overlay);
    assert_eq!((rows[0].clone(), rows[1].clone()), stamp_rows(&fx.archive));
    assert_eq!(rows[2].as_deref(), Some("pending"));
}

/// Regression (Astra v3 #1, F2): a complete journal that moved with its
/// renamed directory is recovered through the archive's new name: rolled
/// forward (never back), the journal and locator gone. The base left its
/// recorded place, so ownership is ambiguous: the rows are left for the gate
/// (the mount defers; a reopen needs --force-base-mismatch).
#[cfg(unix)]
#[test]
fn regression_moved_base_complete_journal_is_recovered_through_its_new_name_and_defers() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let (d, saved) = (root.join("d"), root.join("saved"));
    fs::create_dir(&d).unwrap();
    let a = d.join("a.tar");
    write_tar(&a, &[("first", b"first member")]);
    let overlay = root.join("overlay");
    drop(open_with(&archive_token(&a), &overlay, strong_digest(), false).unwrap());
    let before = (recorded_rows(&overlay), digest_rows(&overlay));
    interrupt_complete(&a);
    let new = fs::read(&a).unwrap();
    fs::rename(&d, &saved).unwrap();
    fs::create_dir(&d).unwrap();
    write_tar(&d.join("a.tar"), &[("other", b"journal-free B")]);
    let b_bytes = fs::read(d.join("a.tar")).unwrap();
    let moved = saved.join("a.tar");
    let records = MountRecords {
        top: Some(overlay.clone()),
        ..Default::default()
    };
    assert!(matches!(
        classify_mount_journal(&records, &moved).unwrap(),
        MountJournal::Deferred { complete: true, .. }
    ));
    let applied =
        crate::recover_journal_at(&moved, Some(&overlay.join(HIDDEN_DB)), crate::Owner::Inode)
            .unwrap()
            .expect("found beside the new name");
    assert!(applied.rolled_forward);
    assert_eq!(fs::read(&moved).unwrap(), new, "never rolled back");
    assert!(ratarmount_compress::commit_journal::pending(&moved)
        .unwrap()
        .is_none());
    assert!(!journal_path(&moved).exists());
    assert_eq!((recorded_rows(&overlay), digest_rows(&overlay)), before);
    assert_eq!(fs::read(d.join("a.tar")).unwrap(), b_bytes);
    let refused = open_with(
        &archive_token(&moved),
        &overlay,
        BaseDigestRequest::Compute,
        false,
    )
    .err()
    .expect("an ambiguous move is left to the gate")
    .to_string();
    assert!(refused.contains("--force-base-mismatch"), "{refused}");
}

/// Regression: disjunct 3 of `journal_agrees`: a torn journal whose rows
/// already describe the rolled-back file (only its unlink is owed) agrees;
/// a complete one, or a file of another length, does not.
#[test]
fn regression_journal_agrees_disjunct_three() {
    let journal = ratarmount_compress::commit_journal::PendingJournal {
        dev: 1,
        ino: 2,
        len: 100,
        mtime_ns: 5,
        offset: 50,
        new_len: 150,
        complete: false,
    };
    assert!(crate::journal_agrees((100, 9), (100, 9), &journal));
    assert!(!crate::journal_agrees((100, 9), (150, 9), &journal));
    assert!(!crate::journal_agrees((100, 9), (100, 8), &journal));
    let complete = ratarmount_compress::commit_journal::PendingJournal {
        complete: true,
        ..journal
    };
    assert!(!crate::journal_agrees((100, 9), (100, 9), &complete));
}

// ---- R10-B (#150): followed-stat errors never classify a record ----------

/// Sets [`crate::write_overlay::FOLLOWED_STAT_ERRNO`] for this thread until
/// dropped.
struct FollowedStatErrno;

impl FollowedStatErrno {
    fn set(errno: i32) -> Self {
        crate::write_overlay::FOLLOWED_STAT_ERRNO.with(|seam| seam.set(Some(errno)));
        Self
    }
}

impl Drop for FollowedStatErrno {
    fn drop(&mut self) {
        crate::write_overlay::FOLLOWED_STAT_ERRNO.with(|seam| seam.set(None));
    }
}

/// The helper entry [`Unresolved::plant`] creates beside `dir`.
#[cfg(unix)]
fn side_of(dir: &Path, how: Unresolved) -> PathBuf {
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    dir.with_file_name(format!("side-{name}-{how:?}"))
}

/// How the database entry of an overlay is made unresolvable.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum Unresolved {
    /// A symlink through a regular file: `ENOTDIR`.
    NotDir,
    /// A symlink into a directory without search permission: `EACCES`.
    Access,
    /// A symlink loop: `ELOOP`.
    Loop,
    /// The followed `stat` fails with `EIO` (test seam).
    Io,
}

#[cfg(unix)]
impl Unresolved {
    const ALL: [Unresolved; 4] = [Self::NotDir, Self::Access, Self::Loop, Self::Io];

    /// Replace `dir`'s database by the unresolvable entry. `None` when the row
    /// cannot run here (EACCES as root). The guard keeps the seam set.
    fn plant(self, dir: &Path) -> Option<Option<FollowedStatErrno>> {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let db = dir.join(HIDDEN_DB);
        if fs::symlink_metadata(&db).is_ok() {
            fs::rename(&db, side_of(dir, self).with_extension("saved")).unwrap();
        }
        let side = side_of(dir, self);
        match self {
            Self::NotDir => {
                fs::write(&side, b"plain file").unwrap();
                symlink(side.join("missing.sqlite"), &db).unwrap();
            }
            Self::Access => {
                if unsafe { libc::geteuid() } == 0 {
                    eprintln!("skip: EACCES row runs as root");
                    return None;
                }
                fs::create_dir(&side).unwrap();
                fs::write(side.join("db.sqlite"), b"x").unwrap();
                fs::set_permissions(&side, fs::Permissions::from_mode(0o000)).unwrap();
                symlink(side.join("db.sqlite"), &db).unwrap();
            }
            Self::Loop => symlink(HIDDEN_DB, &db).unwrap(),
            Self::Io => {
                fs::write(&db, b"not consulted").unwrap();
                return Some(Some(FollowedStatErrno::set(libc::EIO)));
            }
        }
        Some(None)
    }

    fn kind(self) -> std::io::ErrorKind {
        let errno = match self {
            Self::NotDir => libc::ENOTDIR,
            Self::Access => libc::EACCES,
            Self::Loop => libc::ELOOP,
            Self::Io => libc::EIO,
        };
        std::io::Error::from_raw_os_error(errno).kind()
    }

    /// Undo [`Unresolved::Access`]'s permission change so the tempdir can be
    /// removed.
    fn cleanup(self, dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let side = side_of(dir, self);
        if side.is_dir() || fs::symlink_metadata(&side).is_ok_and(|m| m.is_dir()) {
            let _ = fs::set_permissions(&side, fs::Permissions::from_mode(0o700));
        }
    }
}

/// Regression (R10-B, #150): the shared classifier. A followed-`stat` error
/// (`ENOTDIR`, `EACCES`, `ELOOP`, `EIO`) is an error, marked or not: never
/// `Present` (which would let recovery act on the record) and never `Absent` /
/// `Lost`. The v4 T9 table with its rows updated: a directory, a FIFO and an
/// unmarked dangling symlink are errors; there is no identity-less `Present`.
#[cfg(unix)]
#[test]
fn regression_overlay_db_followed_stat_errors_are_not_present() {
    use crate::{overlay_db_absent, overlay_db_entry, DbEntry, OVERLAY_MARKER};
    use std::os::unix::fs::{symlink, MetadataExt};
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let mut n = 0;
    let mut dir = |marked: bool| {
        n += 1;
        let d = root.join(format!("ov{n}"));
        fs::create_dir(&d).unwrap();
        if marked {
            fs::write(d.join(OVERLAY_MARKER), b"").unwrap();
        }
        d
    };
    let real_db = |path: &Path| {
        rusqlite::Connection::open(path)
            .unwrap()
            .execute_batch("CREATE TABLE files (x)")
            .unwrap();
    };
    // Absent / Lost.
    let d = dir(false);
    assert!(matches!(overlay_db_entry(&d), Ok(DbEntry::Absent)));
    assert!(overlay_db_absent(&d));
    let d = dir(true);
    assert!(matches!(
        overlay_db_entry(&d),
        Ok(DbEntry::Lost { empty: false, .. })
    ));
    assert!(!overlay_db_absent(&d), "a lost record is not absent");
    let d = dir(true);
    fs::write(d.join(HIDDEN_DB), b"").unwrap();
    assert!(matches!(
        overlay_db_entry(&d),
        Ok(DbEntry::Lost { empty: true, .. })
    ));
    // Present: identity is the followed stat's.
    let d = dir(false);
    fs::write(d.join(HIDDEN_DB), b"").unwrap();
    assert!(matches!(
        overlay_db_entry(&d),
        Ok(DbEntry::Present { marked: false, .. })
    ));
    let d = dir(true);
    real_db(&d.join(HIDDEN_DB));
    let id = fs::metadata(d.join(HIDDEN_DB)).unwrap().ino();
    assert!(matches!(
        overlay_db_entry(&d),
        Ok(DbEntry::Present { marked: true, ref metadata }) if metadata.ino() == id
    ));
    let d = dir(false);
    let target = root.join("target.sqlite");
    real_db(&target);
    symlink(&target, d.join(HIDDEN_DB)).unwrap();
    let id = fs::metadata(&target).unwrap().ino();
    assert!(matches!(
        overlay_db_entry(&d),
        Ok(DbEntry::Present { ref metadata, .. }) if metadata.ino() == id && metadata.is_file()
    ));
    let d = dir(true);
    let empty = root.join("empty.sqlite");
    fs::write(&empty, b"").unwrap();
    symlink(&empty, d.join(HIDDEN_DB)).unwrap();
    assert!(matches!(
        overlay_db_entry(&d),
        Ok(DbEntry::Lost { empty: true, .. })
    ));
    let d = dir(true);
    symlink(root.join("nowhere"), d.join(HIDDEN_DB)).unwrap();
    assert!(matches!(
        overlay_db_entry(&d),
        Ok(DbEntry::Lost { empty: false, .. })
    ));
    // Errors: unmarked dangling symlink, directory, FIFO, non-regular marker.
    let d = dir(false);
    symlink(root.join("nowhere"), d.join(HIDDEN_DB)).unwrap();
    assert!(overlay_db_entry(&d).is_err());
    assert!(!overlay_db_absent(&d));
    for marked in [false, true] {
        let d = dir(marked);
        fs::create_dir(d.join(HIDDEN_DB)).unwrap();
        assert!(overlay_db_entry(&d).is_err(), "directory, marked={marked}");
        let d = dir(marked);
        let c = std::ffi::CString::new(d.join(HIDDEN_DB).to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(overlay_db_entry(&d).is_err(), "FIFO, marked={marked}");
    }
    let d = dir(false);
    fs::create_dir(d.join(OVERLAY_MARKER)).unwrap();
    assert!(overlay_db_entry(&d).is_err(), "non-regular marker");
    // Followed-stat errors: an error with its kind and the path, marked or
    // not, and never absent.
    for how in Unresolved::ALL {
        for marked in [false, true] {
            let d = dir(marked);
            let Some(_seam) = how.plant(&d) else {
                continue;
            };
            let error = match overlay_db_entry(&d) {
                Err(crate::OverlayError::Io(e)) => e,
                other => panic!("{how:?} marked={marked}: {other:?}"),
            };
            assert_eq!(error.kind(), how.kind(), "{how:?}: {error}");
            assert!(
                error
                    .to_string()
                    .contains(&d.join(HIDDEN_DB).display().to_string()),
                "{error}"
            );
            assert!(!overlay_db_absent(&d), "{how:?} marked={marked}");
            how.cleanup(&d);
        }
    }
}

/// Leave `archive` with a stale prepare (`P`) locator and no journal: the
/// crash came before the journal was written (or after it was removed).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stale_prepare(archive: &Path) {
    use std::io::Write;
    let len = fs::metadata(archive).unwrap().len();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[0u8; 1536]).unwrap();
    let crashed = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        archive,
        len - 1024,
        &mut suffix,
        &mut |step| {
            if step == "locator prepare" {
                Err(std::io::Error::other("crash"))
            } else {
                Ok(())
            }
        },
    );
    assert!(crashed.is_err());
    let _ = fs::remove_file(ratarmount_compress::commit_journal::journal_path(archive));
    assert_eq!(locator(archive).get(4), Some(&b'P'), "stale P left");
}

/// The raw commit-journal locator xattr of `archive` (empty without one):
/// CRC32 (4 bytes), the state byte, the journal path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn locator(archive: &Path) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    match rustix::fs::getxattr(archive, "user.ratarmount.commit-journal", &mut buf) {
        Ok(n) => buf[..n].to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Regression (R10-B, #150, r9 Astra v4 #2): a marked overlay whose database
/// is replaced by a symlink that cannot be resolved (`plain-file/missing.sqlite`
/// gives `ENOTDIR`; also `EACCES`, `ELOOP`, injected `EIO`) next to an archive
/// with a stale prepare locator and no journal. The followed-`stat` error was
/// read as a present record, so recovery cleared the locator before anything
/// refused. Every owner refuses under the lock now (the mount's top, a
/// `--lower`-only mount, the offline path rows, the live mount's own
/// connection), and the archive and its locator stay byte-identical.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_stale_prepare_locator_unresolved_target_is_kept() {
    use ratarmount_compress::commit_journal::RecoverError;
    for how in Unresolved::ALL {
        for row in ["mount top", "lower only", "offline path", "live"] {
            let fx = Fixture::new();
            let live = fx.open(BaseDigestRequest::Compute, false);
            let live = if row == "live" {
                Some(live)
            } else {
                drop(live);
                None
            };
            stale_prepare(&fx.archive);
            let bytes = fs::read(&fx.archive).unwrap();
            let before = locator(&fx.archive);
            let Some(seam) = how.plant(&fx.overlay) else {
                continue;
            };
            let db = fx.overlay.join(HIDDEN_DB);
            let error = match row {
                "mount top" => {
                    let records = records_of(&fx);
                    crate::recover_journal_at(
                        &fx.archive,
                        Some(&db),
                        crate::Owner::Mount {
                            records: &records,
                            member: &fx.archive,
                        },
                    )
                    .map(drop)
                    .unwrap_err()
                }
                "lower only" => {
                    let records = MountRecords {
                        lowers: vec![fx.overlay.clone()],
                        ..Default::default()
                    };
                    crate::recover_journal_at(
                        &fx.archive,
                        None,
                        crate::Owner::Mount {
                            records: &records,
                            member: &fx.archive,
                        },
                    )
                    .map(drop)
                    .unwrap_err()
                }
                "offline path" => {
                    crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Inode)
                        .map(drop)
                        .unwrap_err()
                }
                _ => {
                    let error = live
                        .as_ref()
                        .unwrap()
                        .recover_member_journal(&fx.archive)
                        .unwrap_err();
                    RecoverError::Refused(std::io::Error::other(error.to_string()))
                }
            };
            assert!(
                matches!(error, RecoverError::Refused(_)),
                "{how:?} {row}: {error:?}"
            );
            drop(seam);
            assert_eq!(locator(&fx.archive), before, "{how:?} {row}: locator kept");
            assert_eq!(fs::read(&fx.archive).unwrap(), bytes, "{how:?} {row}");
            assert!(
                !ratarmount_compress::commit_journal::journal_path(&fx.archive).exists(),
                "{how:?} {row}: no journal appears"
            );
            how.cleanup(&fx.overlay);
        }
    }
}

/// Regression (R10-B, v4 T7 live rows): a mounted overlay's own database
/// replaced at its path by another database (a new inode), or removed while
/// its marker stays, next to a stale prepare locator: the live recovery
/// cleared the locator through the mount's connection without looking at the
/// path. The guard compares the path with the inode the mount opened.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_live_recovery_refuses_a_replaced_or_lost_database() {
    for replaced in [true, false] {
        let fx = Fixture::new();
        let ov = fx.open(BaseDigestRequest::Compute, false);
        stale_prepare(&fx.archive);
        let before = locator(&fx.archive);
        let db = fx.overlay.join(HIDDEN_DB);
        fs::rename(&db, fx.overlay.with_file_name("held.sqlite")).unwrap();
        if replaced {
            rusqlite::Connection::open(&db)
                .unwrap()
                .execute_batch("CREATE TABLE files (x)")
                .unwrap();
        }
        let error = ov
            .recover_member_journal(&fx.archive)
            .unwrap_err()
            .to_string();
        let expect = if replaced {
            "replaced while the overlay is mounted"
        } else {
            "missing or empty"
        };
        assert!(error.contains(expect), "replaced={replaced}: {error}");
        assert_eq!(locator(&fx.archive), before, "replaced={replaced}");
    }
}

/// Regression (R10-B, v4 T8/T13b): a complete journal of A's own commit is
/// rolled forward, then the restamp finds the record lost after
/// authorization: the database emptied, replaced by one without a `files`
/// table (the plain-SQL check inside the restamp transaction), or removed
/// with its marker. The restamp skipped (an empty record read as
/// "unrecorded") and the journal was unlinked with the rows naming the
/// pre-commit stamp. Now `Committed`, the journal is kept, and once the
/// database is restored recovery finishes and the gate accepts.
#[cfg(unix)]
#[test]
fn regression_restamp_refuses_when_the_record_vanishes_after_authorization() {
    use ratarmount_compress::commit_journal::{PendingJournal, RecoverError};
    for row in ["emptied", "no files table", "removed with marker"] {
        let fx = Fixture::new();
        drop(fx.open(BaseDigestRequest::Compute, false));
        let db = fx.overlay.join(HIDDEN_DB);
        let saved = fx.overlay.with_file_name("saved-db.sqlite");
        fs::copy(&db, &saved).unwrap();
        interrupt_complete(&fx.archive);
        let journal = ratarmount_compress::commit_journal::journal_path(&fx.archive);
        let records = records_of(&fx);
        let archive = fx.archive.clone();
        let overlay = fx.overlay.clone();
        let db2 = db.clone();
        let mut authorize = |h: &PendingJournal, m: &fs::Metadata| {
            authorize_mount_recovery(&records, &archive, h, m)?;
            match row {
                "emptied" => fs::write(&db2, b"")?,
                "no files table" => {
                    fs::remove_file(&db2)?;
                    rusqlite::Connection::open(&db2)
                        .and_then(|c| c.execute_batch("CREATE TABLE other (x)"))
                        .map_err(std::io::Error::other)?;
                }
                _ => {
                    fs::remove_file(&db2)?;
                    fs::remove_file(overlay.join(crate::OVERLAY_MARKER))?;
                }
            }
            Ok(())
        };
        let error =
            crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Test(&mut authorize))
                .unwrap_err();
        assert!(
            matches!(error, RecoverError::Committed(_)),
            "{row}: {error:?}"
        );
        assert!(journal.exists(), "{row}: journal kept");
        assert!(
            ratarmount_compress::commit_journal::pending(&fx.archive)
                .unwrap()
                .is_some_and(|j| j.complete),
            "{row}"
        );
        let _ = fs::remove_file(&db);
        fs::copy(&saved, &db).unwrap();
        fs::write(fx.overlay.join(crate::OVERLAY_MARKER), b"").unwrap();
        let applied = crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Inode)
            .unwrap()
            .expect("recovered");
        assert!(applied.rolled_forward, "{row}");
        assert!(!journal.exists(), "{row}");
        assert_eq!(
            stamp_rows(&fx.archive),
            (
                read_rows(&fx.overlay, &["base_size"])[0].clone(),
                read_rows(&fx.overlay, &["base_mtime_ns"])[0].clone()
            ),
            "{row}: rows name the recovered archive"
        );
    }
}

/// Replace `overlay`'s database with another SQLite file that has no `files`
/// table (the marker stays): the record of a used overlay is lost.
#[cfg(unix)]
fn replace_db_without_files(overlay: &Path) {
    let db = overlay.join(HIDDEN_DB);
    fs::remove_file(&db).unwrap();
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch("CREATE TABLE other (x); INSERT INTO other VALUES (1)")
        .unwrap();
    assert!(overlay.join(crate::OVERLAY_MARKER).is_file(), "marker kept");
}

/// Regression (R10-FIX1, r10 review B1 / skeptic #2, v4 T13a): a marked
/// overlay whose database is replaced by a non-empty SQLite file without a
/// `files` table read as an unrecorded overlay. With B (and its own torn or
/// complete journal) renamed over A, the mount classified the journal `Own`
/// and rolled B back before `WriteOverlay::open` refused; the offline gate
/// accepted `Unrecorded` and recovery rewrote B; a stale `P` locator was
/// cleared. The required-record reader refuses before any recovery write
/// (mount top, `--lower`-only, offline `commit_overlay`): B, its journal and
/// the locator stay byte-identical.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_marked_record_without_files_table_refuses_before_recovery() {
    use ratarmount_compress::commit_journal::RecoverError;
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    for journal in ["torn", "complete", "stale P"] {
        for row in ["mount top", "lower only", "offline commit"] {
            let what = format!("{journal} / {row}");
            let fx = Fixture::new();
            drop(fx.open(BaseDigestRequest::Compute, false));
            replace_db_without_files(&fx.overlay);
            let kept = if journal == "stale P" {
                stale_prepare(&fx.archive);
                None
            } else {
                Some(rename_b_over_a(&fx, journal == "complete"))
            };
            let bytes = fs::read(&fx.archive).unwrap();
            let before = locator(&fx.archive);
            let db = fx.overlay.join(HIDDEN_DB);
            let records = match row {
                "lower only" => MountRecords {
                    lowers: vec![fx.overlay.clone()],
                    ..Default::default()
                },
                _ => records_of(&fx),
            };
            let error = match row {
                "offline commit" => crate::commit_overlay(
                    &fx.overlay,
                    &fx.archive,
                    &archive_token(&fx.archive),
                    &opts,
                )
                .expect_err(&what)
                .to_string(),
                _ => {
                    match classify_mount_journal(&records, &fx.archive).unwrap() {
                        MountJournal::Deferred { why, .. } => {
                            assert!(why.contains("no files table"), "{what}: {why}")
                        }
                        MountJournal::None if kept.is_none() => {}
                        other => panic!("{what}: {other:?}"),
                    }
                    let top = (row == "mount top").then_some(db.as_path());
                    let error = crate::recover_journal_at(
                        &fx.archive,
                        top,
                        crate::Owner::Mount {
                            records: &records,
                            member: &fx.archive,
                        },
                    )
                    .map(drop)
                    .expect_err(&what);
                    assert!(
                        matches!(error, RecoverError::Refused(_)),
                        "{what}: {error:?}"
                    );
                    error.to_string()
                }
            };
            assert!(error.contains("no files table"), "{what}: {error}");
            assert_eq!(fs::read(&fx.archive).unwrap(), bytes, "{what}: archive");
            assert_eq!(locator(&fx.archive), before, "{what}: locator");
            if let Some((_, journal_path, journal_bytes)) = &kept {
                assert_eq!(
                    &fs::read(journal_path).unwrap(),
                    journal_bytes,
                    "{what}: journal"
                );
            }
        }
    }
}

/// Regression (R10-FIX1, r10 skeptic #1): the database and the marker were
/// both seen when recovery started, then both removed before the guard ran
/// under the lock. `Rows::Path`'s guard accepted `Absent` despite its latched
/// flags (only the restamp hook refused, after the rollback had written).
/// The guard refuses before the first recovery write: the archive and its
/// torn journal stay byte-identical.
#[cfg(unix)]
#[test]
fn regression_rows_guard_refuses_a_record_removed_after_it_was_seen() {
    use ratarmount_compress::commit_journal::RecoverError;
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    interrupt_append(&fx.archive);
    let journal = ratarmount_compress::commit_journal::journal_path(&fx.archive);
    let journal_bytes = fs::read(&journal).unwrap();
    let bytes = fs::read(&fx.archive).unwrap();
    let db = fx.overlay.join(HIDDEN_DB);
    // Seen (the flags latch), then both removed before the locked guard.
    let rows = crate::journal_recovery::Rows::path(&db);
    fs::remove_file(&db).unwrap();
    fs::remove_file(fx.overlay.join(crate::OVERLAY_MARKER)).unwrap();
    let error = crate::journal_recovery::recover_journal(&fx.archive, rows, crate::Owner::Inode)
        .map(drop)
        .unwrap_err();
    assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
    assert!(error.to_string().contains("disappeared"), "{error}");
    assert!(fs::read(&fx.archive).unwrap() == bytes, "no rollback");
    assert!(fs::read(&journal).unwrap() == journal_bytes, "journal kept");
}

/// The four ways a used overlay's database is lost (its marker kept).
#[cfg(unix)]
const LOST_SHAPES: [&str; 4] = [
    "deleted",
    "0-byte",
    "symlink to 0-byte",
    "symlink to missing",
];

/// Lose `overlay`'s database in the way `shape` names.
#[cfg(unix)]
fn lose_db(overlay: &Path, shape: &str) {
    let db = overlay.join(HIDDEN_DB);
    fs::remove_file(&db).unwrap();
    match shape {
        "deleted" => {}
        "0-byte" => fs::write(&db, b"").unwrap(),
        "symlink to 0-byte" => {
            let empty = overlay.with_file_name("empty.sqlite");
            fs::write(&empty, b"").unwrap();
            std::os::unix::fs::symlink(&empty, &db).unwrap();
        }
        _ => std::os::unix::fs::symlink(overlay.with_file_name("nowhere.sqlite"), &db).unwrap(),
    }
    assert!(overlay.join(crate::OVERLAY_MARKER).is_file(), "marker kept");
}

/// Regression (R10-FIX2, r10 review B2, v4 T5): a mount whose top or
/// `--lower`-only record is lost (database deleted, 0-byte, a symlink to a
/// 0-byte file or to nothing; marker kept) next to B renamed over A with its
/// own torn or complete journal, or next to a stale prepare locator.
/// `read_record` read a deleted or empty database as "no record", so the
/// journal classified `Own` and was recovered; the stale locator was cleared.
/// The classifier defers (or reports no journal for the stale locator), the
/// locked recovery refuses, and B, its journal and the locator stay
/// byte-identical.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_mount_lost_overlay_db_defers_recovery() {
    use ratarmount_compress::commit_journal::RecoverError;
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for shape in LOST_SHAPES {
        for journal in ["torn", "complete", "stale P"] {
            for top in [true, false] {
                let what = format!("{shape} / {journal} / top={top}");
                let fx = Fixture::new();
                drop(fx.open(BaseDigestRequest::Compute, false));
                lose_db(&fx.overlay, shape);
                let kept = if journal == "stale P" {
                    stale_prepare(&fx.archive);
                    None
                } else {
                    Some(rename_b_over_a(&fx, journal == "complete"))
                };
                let bytes = fs::read(&fx.archive).unwrap();
                let before = locator(&fx.archive);
                let records = if top {
                    records_of(&fx)
                } else {
                    MountRecords {
                        lowers: vec![fx.overlay.clone()],
                        ..Default::default()
                    }
                };
                let flag = if top {
                    "--force-base-mismatch"
                } else {
                    "--force-stack-mismatch"
                };
                match classify_mount_journal(&records, &fx.archive).unwrap() {
                    MountJournal::Deferred {
                        why, force_flag, ..
                    } => {
                        assert_eq!(force_flag, flag, "{what}");
                        assert!(why.contains("missing or empty"), "{what}: {why}");
                    }
                    MountJournal::None if kept.is_none() => {}
                    other => panic!("{what}: {other:?}"),
                }
                let db = fx.overlay.join(HIDDEN_DB);
                let error = crate::recover_journal_at(
                    &fx.archive,
                    top.then_some(db.as_path()),
                    crate::Owner::Mount {
                        records: &records,
                        member: &fx.archive,
                    },
                )
                .map(drop)
                .expect_err(&what);
                assert!(
                    matches!(error, RecoverError::Refused(_)),
                    "{what}: {error:?}"
                );
                assert!(
                    error.to_string().contains("missing or empty"),
                    "{what}: {error}"
                );
                assert!(fs::read(&fx.archive).unwrap() == bytes, "{what}: archive");
                assert_eq!(locator(&fx.archive), before, "{what}: locator");
                if let Some((_, path, journal_bytes)) = &kept {
                    assert!(fs::read(path).unwrap() == *journal_bytes, "{what}: journal");
                }
            }
        }
    }
}

/// Regression (R10-FIX2, r10 review B2, v4 T7): the offline entry points with
/// a lost record (the four shapes, marker kept). `commit_overlay` said "has no
/// database" for a deleted one or read an empty one through the symlink;
/// `commit_overlay_raw_dir` recovered B by inode and then refused;
/// `recover_journal_at(.., Some(db), Owner::Inode)` rolled A's own torn
/// journal back or cleared a stale prepare locator. Each refuses before any
/// recovery write: the archive, its journal and the locator stay
/// byte-identical.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_lost_record_refuses_before_recovery() {
    use ratarmount_compress::commit_journal::RecoverError;
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let opts = CommitOverlayOptions {
        yes: true,
        ..Default::default()
    };
    for shape in LOST_SHAPES {
        for row in [
            "commit_overlay",
            "commit_overlay_raw_dir",
            "recover torn",
            "recover stale P",
        ] {
            let what = format!("{shape} / {row}");
            let fx = Fixture::new();
            drop(fx.open(BaseDigestRequest::Compute, false));
            lose_db(&fx.overlay, shape);
            let journal = match row {
                "recover torn" => {
                    interrupt_append(&fx.archive);
                    let path = ratarmount_compress::commit_journal::journal_path(&fx.archive);
                    let bytes = fs::read(&path).unwrap();
                    Some((path, bytes))
                }
                "recover stale P" => {
                    stale_prepare(&fx.archive);
                    None
                }
                _ => {
                    let (_, path, bytes) = rename_b_over_a(&fx, false);
                    Some((path, bytes))
                }
            };
            let bytes = fs::read(&fx.archive).unwrap();
            let before = locator(&fx.archive);
            let db = fx.overlay.join(HIDDEN_DB);
            let error = match row {
                "commit_overlay" => crate::commit_overlay(
                    &fx.overlay,
                    &fx.archive,
                    &archive_token(&fx.archive),
                    &opts,
                )
                .expect_err(&what)
                .to_string(),
                "commit_overlay_raw_dir" => {
                    crate::commit_overlay_raw_dir(&fx.overlay, &fx.archive, &opts)
                        .map(drop)
                        .expect_err(&what)
                        .to_string()
                }
                _ => {
                    let error =
                        crate::recover_journal_at(&fx.archive, Some(&db), crate::Owner::Inode)
                            .map(drop)
                            .expect_err(&what);
                    assert!(
                        matches!(error, RecoverError::Refused(_)),
                        "{what}: {error:?}"
                    );
                    error.to_string()
                }
            };
            assert!(error.contains("missing or empty"), "{what}: {error}");
            assert!(fs::read(&fx.archive).unwrap() == bytes, "{what}: archive");
            assert_eq!(locator(&fx.archive), before, "{what}: locator");
            if let Some((path, journal_bytes)) = &journal {
                assert!(fs::read(path).unwrap() == *journal_bytes, "{what}: journal");
            }
        }
    }
}

// ---- R10-C (#148): payload opens of another name of an open database ------

/// The overlay call was refused with `PermissionDenied` (an admission
/// refusal), not some other error.
#[cfg(unix)]
fn denied<T: std::fmt::Debug>(result: crate::write_overlay::Result<T>) -> bool {
    matches!(
        result,
        Err(crate::OverlayError::Io(ref e)) if e.kind() == std::io::ErrorKind::PermissionDenied
    )
}

/// A hard link of `db` named `name` in the overlay root `dir`.
#[cfg(unix)]
fn link_db(db: &Path, dir: &Path, name: &str) -> PathBuf {
    let alias = dir.join(name);
    fs::hard_link(db, &alias).unwrap();
    alias
}

/// Regression (R10-C, #148, r20 skeptic #1): the overlay database hard-linked
/// under a payload name. FUSE/NFS-style `open_overlay_fd` and
/// `MountSource::open` opened an unmanaged descriptor of the database inode
/// and closed it after the read, releasing every fcntl lock this process held
/// on it while SQLite still believed it held EXCLUSIVE: another process could
/// then write beneath the mount. Both refuse with EACCES; a child's
/// `BEGIN IMMEDIATE` is still busy afterwards and the holder still writes.
#[cfg(unix)]
#[test]
fn regression_payload_db_alias_preserves_process_locks() {
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    let db = fx.overlay.join(HIDDEN_DB);
    link_db(&db, &fx.overlay, "payload");
    fs::write(fx.overlay.join("plain"), b"plain bytes").unwrap();
    let error = ov.open_overlay_fd("/payload", libc::O_RDONLY).unwrap_err();
    assert!(
        error.to_string().contains("open overlay database"),
        "{error}"
    );
    let fi = ov.lookup("/payload", 0).expect("payload listed");
    let error = ov.open(&fi, 0).map(drop).unwrap_err();
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{error}"
    );
    // An ordinary payload still opens, reads and closes.
    let fi = ov.lookup("/plain", 0).expect("plain");
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut ov.open(&fi, 0).unwrap(), &mut bytes).unwrap();
    assert_eq!(bytes, b"plain bytes");
    let fd = ov.open_overlay_fd("/plain", libc::O_RDONLY).unwrap();
    ov.close_overlay_fd(fd);
    assert!(
        crate::overlay_db::lock_probe_is_busy(&db),
        "another process must still see the mount's lock"
    );
    ov.set_meta("r10_probe", "still writes").unwrap();
    assert!(crate::overlay_db::lock_probe_is_busy(&db));
    // The probe itself: without the mount, the child takes the lock.
    drop(ov);
    assert!(!crate::overlay_db::lock_probe_is_busy(&db));
}

/// Regression (R10-C, #148): no write path truncates or changes the
/// database through an alias: create over it, a writable `O_TRUNC` open, a
/// read-only `O_TRUNC` open and an explicit truncate are refused; the
/// database keeps its size (a `stat`, never a read: a read in this process
/// would itself close a descriptor) and its lock.
#[cfg(unix)]
#[test]
fn regression_payload_db_alias_write_never_truncates() {
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    let db = fx.overlay.join(HIDDEN_DB);
    link_db(&db, &fx.overlay, "payload");
    let size = fs::metadata(&db).unwrap().len();
    assert!(size > 0);
    assert!(denied(ov.create_file("/payload", 0o644)), "create over");
    for flags in [
        libc::O_WRONLY | libc::O_TRUNC,
        libc::O_RDWR,
        libc::O_RDONLY | libc::O_TRUNC,
    ] {
        assert!(
            denied(ov.open_overlay_fd("/payload", flags)),
            "{flags:#x} refused"
        );
    }
    assert!(denied(ov.truncate("/payload", 0)), "truncate");
    assert_eq!(fs::metadata(&db).unwrap().len(), size, "database unchanged");
    assert!(crate::overlay_db::lock_probe_is_busy(&db));
    ov.set_meta("r10_probe", "still writes").unwrap();
}

/// Regression (R10-C, #148): a payload of overlay A that is a hard link of
/// overlay B's database (B mounted in the same process, holding its lock) is
/// refused through A, naming B's database; B keeps its lock.
#[cfg(unix)]
#[test]
fn regression_payload_alias_other_overlay() {
    let a = Fixture::new();
    let b = Fixture::new();
    let ov_a = a.open(BaseDigestRequest::Compute, false);
    let ov_b = b.open(BaseDigestRequest::Compute, false);
    let b_db = b.overlay.join(HIDDEN_DB);
    link_db(&b_db, &a.overlay, "theirs");
    let error = ov_a.open_overlay_fd("/theirs", libc::O_RDONLY).unwrap_err();
    assert!(
        error.to_string().contains(&b_db.display().to_string()),
        "names B's database: {error}"
    );
    let fi = ov_a.lookup("/theirs", 0).expect("listed");
    assert_eq!(
        ov_a.open(&fi, 0).map(drop).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(crate::overlay_db::lock_probe_is_busy(&b_db));
    ov_b.set_meta("r10_probe", "still writes").unwrap();
    // Once B is unmounted, the name is an ordinary file of A.
    drop(ov_b);
    let fd = ov_a.open_overlay_fd("/theirs", libc::O_RDONLY).unwrap();
    ov_a.close_overlay_fd(fd);
}

/// Regression (R10-FIX3, r10 skeptic #5): the commit-journal name of a
/// member is a hard link of the mount's open database. `pending()` (reached
/// by live recovery before the guard) and the rollback's journal read opened
/// it, rejected the header and closed the descriptor, releasing the mount's
/// locks. Both refuse with `PermissionDenied` now; another process is still
/// busy and the holder still writes.
#[cfg(unix)]
#[test]
fn regression_journal_reads_refuse_a_db_alias() {
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    let db = fx.overlay.join(HIDDEN_DB);
    let journal = ratarmount_compress::commit_journal::journal_path(&fx.archive);
    fs::hard_link(&db, &journal).unwrap();
    let error = ratarmount_compress::commit_journal::pending(&fx.archive).unwrap_err();
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{error}"
    );
    assert!(ov.recover_member_journal(&fx.archive).is_err());
    assert!(
        crate::overlay_db::lock_probe_is_busy(&db),
        "a journal read released the mount's lock"
    );
    ov.set_meta("r10_probe", "still writes").unwrap();
    assert!(crate::overlay_db::lock_probe_is_busy(&db));
}

/// Regression (R10-FIX3, r10 skeptic #4): a commit writing the provenance
/// manifest read the previous `<archive>.manifest.jsonl` through a plain
/// open. When that name is a hard link of another overlay's open database
/// (B, mounted in this process), the close after the (failed) parse released
/// B's locks. The read is admitted: refused with `PermissionDenied`, B's
/// lock survives and B still writes.
#[cfg(unix)]
#[test]
fn regression_manifest_read_refuses_a_db_alias() {
    let a = Fixture::new();
    let b = Fixture::new();
    drop(a.open(BaseDigestRequest::Compute, false));
    fs::write(a.overlay.join("new"), b"new member").unwrap();
    let ov_b = b.open(BaseDigestRequest::Compute, false);
    let b_db = b.overlay.join(HIDDEN_DB);
    let mut manifest = a.archive.as_os_str().to_os_string();
    manifest.push(crate::base_sidecars::MANIFEST_SIDECAR_SUFFIX);
    fs::hard_link(&b_db, PathBuf::from(&manifest)).unwrap();
    let opts = CommitOverlayOptions {
        yes: true,
        manifest_hashes: Some("all".into()),
        ..Default::default()
    };
    let error = crate::commit_overlay(&a.overlay, &a.archive, &archive_token(&a.archive), &opts)
        .unwrap_err()
        .to_string();
    assert!(error.contains("open overlay database"), "{error}");
    assert!(
        crate::overlay_db::lock_probe_is_busy(&b_db),
        "the manifest read released B's lock"
    );
    ov_b.set_meta("r10_probe", "still writes").unwrap();
}

// ---- R10-D: the inode registry is never held across an open --------------

/// Regression (R10-D, Fable r10 blocker 2): a FIFO planted under a payload
/// name blocks its opener in `open(2)` (FUSE has always given that request
/// thread to the FIFO). The database-inode registry must not be held across
/// that open: while one thread is blocked opening the FIFO through
/// `open_overlay_fd`, another thread's overlay-database open (which
/// registers its inode) and an admitted payload open still return at once.
#[cfg(unix)]
#[test]
fn regression_fifo_payload_does_not_stall_db_opens() {
    use std::time::{Duration, Instant};
    let fx = Fixture::new();
    let ov = fx.open(BaseDigestRequest::Compute, false);
    let fifo = fx.overlay.join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    fs::write(fx.overlay.join("plain"), b"plain").unwrap();
    let other = Fixture::new();
    drop(other.open(BaseDigestRequest::Compute, false));
    let other_db = other.overlay.join(HIDDEN_DB);
    std::thread::scope(|scope| {
        let (started, blocked) = std::sync::mpsc::channel();
        let ov = &ov;
        let reader = scope.spawn(move || {
            started.send(()).unwrap();
            ov.open_overlay_fd("/fifo", libc::O_RDONLY)
        });
        blocked.recv().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(!reader.is_finished(), "the FIFO open blocks until a writer");
        // The opens under test run on a helper thread with a watchdog: a
        // regression fails the test instead of hanging it (on timeout a
        // writer releases the FIFO reader first, so the scope can join).
        let (done, finished) = std::sync::mpsc::channel();
        let other_db = &other_db;
        let helper = scope.spawn(move || {
            let start = Instant::now();
            let conn = crate::open_overlay_db(
                other_db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                crate::DbName::Path,
            )
            .unwrap();
            let fd = ov.open_overlay_fd("/plain", libc::O_RDONLY).unwrap();
            ov.close_overlay_fd(fd);
            drop(conn);
            let _ = done.send(start.elapsed());
        });
        let waited = finished.recv_timeout(Duration::from_secs(5));
        // Unblock the reader: a writer appears.
        let writer = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        let fd = reader
            .join()
            .unwrap()
            .expect("FIFO opened once a writer came");
        ov.close_overlay_fd(fd);
        drop(writer);
        helper.join().unwrap();
        let elapsed = waited.expect("database and payload opens waited on the blocked FIFO open");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    });
}

/// Regression (R10-FIX6, r10 skeptic #1): the required-record reader checked
/// `files` and read `meta` as two autocommit reads. Another connection that
/// committed `DROP TABLE files; DROP TABLE meta` between them made a lost
/// record read as "unrecorded" (`Ok(None)`), so the offline gate passed a
/// base that no longer matches the record. Both reads are now one read
/// transaction: the concurrent DROP cannot commit while it is open, and the
/// gate judges the record it found (the changed base is refused).
#[test]
fn regression_required_record_read_is_one_snapshot() {
    use std::cell::Cell;
    use std::rc::Rc;
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    write_tar(
        &fx.archive,
        &[("first", b"first member"), ("second", b"the base changed")],
    );
    let db = fx.overlay.join(HIDDEN_DB);
    let arm = |dropped: Rc<Cell<Option<bool>>>| {
        let db = db.clone();
        crate::overlay_meta::BETWEEN_REQUIRED_READS.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let other = rusqlite::Connection::open(&db).unwrap();
                other.busy_timeout(std::time::Duration::ZERO).unwrap();
                let committed = other
                    .execute_batch("BEGIN IMMEDIATE; DROP TABLE files; DROP TABLE meta; COMMIT")
                    .is_ok();
                dropped.set(Some(committed));
            }))
        });
    };
    // The offline gate (an autocommit connection of its own).
    let dropped = Rc::new(Cell::new(None));
    arm(dropped.clone());
    let refusal = crate::overlay_gate::check_commit_base_offline(
        &fx.overlay,
        &archive_token(&fx.archive),
        &fx.archive,
    )
    .expect_err("the gate judged the record it read");
    assert!(refusal.0.contains("base mismatch"), "{}", refusal.0);
    assert_eq!(dropped.get(), Some(false), "the DROP committed mid-read");
    // The reader itself, on an autocommit connection.
    let dropped = Rc::new(Cell::new(None));
    arm(dropped.clone());
    let conn = rusqlite::Connection::open(&db).unwrap();
    let meta = crate::OverlayMeta::from_connection_required(&conn, true)
        .unwrap()
        .expect("one snapshot: the record is there");
    assert!(meta.get("base_size").is_some());
    assert_eq!(dropped.get(), Some(false), "the DROP committed mid-read");
    assert!(conn.is_autocommit(), "the reader's transaction ended");
    // Inside a caller's transaction the reader opens none of its own.
    let tx = conn.unchecked_transaction().unwrap();
    assert!(crate::OverlayMeta::from_connection_required(&tx, true)
        .unwrap()
        .is_some());
    drop(tx);
    // Control: without a reader the DROP commits.
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch("DROP TABLE files; DROP TABLE meta")
        .unwrap();
}

/// Regression (R10-FIX7, r10 skeptic #2): offline recovery read its record
/// with the mount's strict rule, which refuses a database entry that is a
/// symlink, although the offline gate (and the classifier) accept a symlink
/// to a regular database file. An offline commit of such an overlay next to a
/// stale prepare locator was refused. The offline owner now reads the record
/// through the symlink: the stale locator is cleared and the commit goes on;
/// a mount's records keep the strict rule (it still defers).
#[cfg(unix)]
#[test]
fn regression_offline_recovery_follows_a_symlinked_database() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let fx = Fixture::new();
    drop(fx.open(BaseDigestRequest::Compute, false));
    let db = fx.overlay.join(HIDDEN_DB);
    let elsewhere = fx.overlay.parent().unwrap().join("db-elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let target = elsewhere.join("overlay.sqlite");
    fs::rename(&db, &target).unwrap();
    std::os::unix::fs::symlink(&target, &db).unwrap();
    stale_prepare(&fx.archive);
    assert!(!locator(&fx.archive).is_empty(), "a stale locator");
    // A mount's records keep the strict rule.
    let records = records_of(&fx);
    match classify_mount_journal(&records, &fx.archive).unwrap() {
        MountJournal::None => {}
        other => panic!("no journal is pending: {other:?}"),
    }
    let rows = || {
        let conn = rusqlite::Connection::open(&target).unwrap();
        OverlayMeta::from_connection(&conn)
            .unwrap()
            .unwrap()
            .values()
            .clone()
    };
    let before = rows();
    crate::commit_overlay(
        &fx.overlay,
        &fx.archive,
        &archive_token(&fx.archive),
        &CommitOverlayOptions {
            yes: true,
            ..Default::default()
        },
    )
    .expect("the offline commit reads its record through the symlink");
    assert!(
        locator(&fx.archive).is_empty(),
        "the stale locator is cleared"
    );
    assert!(
        fs::symlink_metadata(&db).unwrap().file_type().is_symlink(),
        "the database entry is still the symlink"
    );
    assert_eq!(rows(), before, "the record is unchanged");
    crate::overlay_gate::check_commit_base_offline(
        &fx.overlay,
        &archive_token(&fx.archive),
        &fx.archive,
    )
    .unwrap();
}
