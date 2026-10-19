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

const JOURNAL_STEPS: [&str; 14] = [
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
    "journal unlink",
    "commit directory fsync",
    "locator clear",
];

/// Regression (R6-G2, R6-J2): the guard runs BEFORE recovery for a foreign
/// journal, but the overlay's OWN torn append must still recover. A real
/// SIGKILL at every journal phase: until the replacement is complete the
/// archive rolls back to the recorded base and the next commit succeeds; at
/// `locator complete` the journal is still there, consistent with the recorded
/// base, and recovery rolls FORWARD: the commit is accepted and the stamp rows
/// re-baselined. Once the journal is gone (`journal unlink` and later) nothing
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
            let refused = position(step) > position("locator complete");
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
