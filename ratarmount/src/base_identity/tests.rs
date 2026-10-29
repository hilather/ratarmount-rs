use super::*;

/// Child-side oracle: a different process must not get an exclusive SQLite
/// transaction while the parent still owns a read transaction.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[allow(clippy::disallowed_methods)]
fn regression_240_external_exclusive_probe() {
    let Some(path) = std::env::var_os("RATARMOUNT_TEST_SQLITE_LOCK_PATH") else {
        return;
    };
    let blocked = std::env::var_os("RATARMOUNT_TEST_SQLITE_LOCK_BLOCKED").is_some();
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.busy_timeout(std::time::Duration::ZERO).unwrap();
    match conn.execute_batch("BEGIN EXCLUSIVE; ROLLBACK;") {
        Ok(()) => assert!(
            !blocked,
            "outside BEGIN EXCLUSIVE succeeded during the reader transaction"
        ),
        Err(error) => {
            assert!(
                blocked,
                "outside BEGIN EXCLUSIVE failed without the reader: {error}"
            );
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy),
                "{error}"
            );
        }
    }
}

/// Regression: #240 raw archive descriptors retained by source construction or
/// opened during seal released an independent SQLAR reader's locks on disposal.
/// Keep one read transaction live across seal, a real commit and source disposal;
/// the outside BEGIN EXCLUSIVE oracle must fail at every operation boundary.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[allow(clippy::disallowed_methods)]
fn regression_240_reader_transaction_survives_seal_and_commit() {
    let _processes = ratarmount_index::test_process::spawning();
    use ratarmount_compositing::{
        commit_overlay, BaseDigestRequest, CommitMode, CommitOverlayOptions, CreateOptions,
        WriteOverlay,
    };
    use std::io::Read;

    let tmp = tempfile::tempdir().unwrap();
    let sqlar = tmp.path().join("base.sqlar");
    {
        let conn = rusqlite::Connection::open(&sqlar).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE;
             CREATE TABLE sqlar(name TEXT PRIMARY KEY, mode INT, mtime INT, sz INT, data BLOB);
             INSERT INTO sqlar VALUES ('base.txt',33188,0,4,X'62617365');",
        )
        .unwrap();
    }
    // Construct the source before the independent transaction: generic format
    // probes are a separate reader inventory (#196). The transaction below
    // must remain live across seal, commit and this source's later disposal.
    let sqlar_base = fixtures::classify(&sqlar);
    let reader = rusqlite::Connection::open(&sqlar).unwrap();
    reader.execute_batch("BEGIN; SELECT * FROM sqlar;").unwrap();
    let mut failures = Vec::new();
    let mut probe = |stage: &str, blocked: bool| {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "base_identity::tests::regression_240_external_exclusive_probe",
                "--nocapture",
            ])
            .env("RATARMOUNT_TEST_SQLITE_LOCK_PATH", &sqlar);
        if blocked {
            command.env("RATARMOUNT_TEST_SQLITE_LOCK_BLOCKED", "1");
        }
        let out = command.output().unwrap();
        if !out.status.success() || !String::from_utf8_lossy(&out.stdout).contains("running 1 test")
        {
            failures.push(format!(
                "{stage}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    };
    probe("before seal setup", true);
    let overlay = tmp.path().join("sealed-overlay");
    let create = CreateOptions {
        base_digest: BaseDigestRequest::None,
        ..Default::default()
    };
    drop(WriteOverlay::open(&sqlar_base, sqlar_base.source(), &overlay, &create).unwrap());
    std::fs::write(overlay.join("new.txt"), b"overlay").unwrap();
    probe("before seal", true);
    ratarmount_compositing::overlay_seal::seal(&overlay, &sqlar_base, sqlar_base.source()).unwrap();
    probe("after seal", true);

    let tar = tmp.path().join("commit.tar");
    write_tar_file(&tar);
    let tar_base = fixtures::classify(&tar);
    let writable = tmp.path().join("commit-overlay");
    drop(WriteOverlay::open(&tar_base, tar_base.source(), &writable, &create).unwrap());
    std::fs::write(writable.join("committed.txt"), b"committed").unwrap();
    assert!(commit_overlay(
        &writable,
        &tar,
        &tar_base,
        &CommitOverlayOptions {
            mode: CommitMode::Append,
            yes: true,
            debug: 0,
            ..Default::default()
        }
    )
    .unwrap());
    probe("after commit in the same process", true);
    let reopened = fixtures::classify(&tar);
    let source = reopened.source();
    let info = source.lookup("/committed.txt", 0).unwrap();
    let mut payload = Vec::new();
    source
        .open(&info, 0)
        .unwrap()
        .read_to_end(&mut payload)
        .unwrap();
    assert_eq!(payload, b"committed", "exercise a completed archive commit");

    drop(sqlar_base);
    probe("after SQLAR source disposal", true);
    reader.execute_batch("COMMIT;").unwrap();
    probe("after reader COMMIT (negative control)", false);
    ratarmount_compositing::overlay_seal::unseal(&overlay).unwrap();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Regression: classification is the factory open a verb already needs and
/// nothing else: no directory walk, no digest, and (for an archive) no
/// hashing or stamp comparison. A big directory and a plain archive are
/// classified without any content work.
#[test]
fn regression_classifier_does_no_content_work() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let folder = root.join("folder");
    std::fs::create_dir(&folder).unwrap();
    for i in 0..50 {
        std::fs::write(folder.join(format!("f{i}")), vec![b'x'; 1024]).unwrap();
    }
    let archive = root.join("a.tar");
    let members = [ratarmount_formats_tar::UstarMember {
        path: "f",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: &[],
    }];
    let mut file = std::fs::File::create(&archive).unwrap();
    ratarmount_formats_tar::write_ustar_members(&mut file, &members).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut file).unwrap();
    drop(file);
    let walks = ratarmount_compositing::directory_weak_walks_this_thread();
    let digests = ratarmount_compositing::directory_digest_calls_this_thread();
    for base in [&folder, &archive] {
        classify_offline(base, GitIntent::Replay(None), &OverlayRunContext::default()).unwrap();
    }
    assert_eq!(
        ratarmount_compositing::directory_weak_walks_this_thread(),
        walks
    );
    assert_eq!(
        ratarmount_compositing::directory_digest_calls_this_thread(),
        digests
    );
    // No sidecar was created next to the archive, either.
    assert!(!root.join("a.tar.index.sqlite").exists());
}

/// Regression (R6-G4, offline-commit cost): offline `--commit-overlay`
/// classified the archive with an in-memory index (R6 review), then by
/// loading its sidecar (R6-F7), so a multi-GB archive paid an index
/// build or load just to learn it is an archive. The commit's classifier
/// opens nothing: the token's source holds no member of the archive, no
/// file appears beside it and its sidecar is untouched; the sidecar is
/// still the peek target for a cached digest.
#[test]
fn regression_offline_commit_classification_builds_no_index() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let archive = root.join("a.tar");
    let members = [ratarmount_formats_tar::UstarMember {
        path: "f",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: &[],
    }];
    let mut file = std::fs::File::create(&archive).unwrap();
    ratarmount_formats_tar::write_ustar_members(&mut file, &members).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut file).unwrap();
    drop(file);
    let sidecar = root.join("a.tar.index.sqlite");
    drop(
        ratarmount_formats_tar::SqliteIndexedTar::create_index(
            &archive,
            &archive,
            Some(&sidecar),
            &ratarmount_core::OpenOptions::default(),
            "test",
            &mut None,
        )
        .unwrap(),
    );
    let names = |dir: &Path| {
        let mut all: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        all.sort();
        all
    };
    let (listing, before) = (names(&root), std::fs::read(&sidecar).unwrap());
    let context = OverlayRunContext::default();
    let token = classify_offline_commit(&archive, &context).unwrap();
    assert_eq!(token.actual().kind(), BaseKind::Archive);
    assert!(
        token.source().lookup("/f", 0).is_none(),
        "no index of the archive may be built or loaded"
    );
    assert_eq!(token.actual().index_for_peek(), Some(sidecar.as_path()));
    assert_eq!(names(&root), listing, "nothing created beside the archive");
    assert!(
        std::fs::read(&sidecar).unwrap() == before,
        "sidecar written"
    );
    // The other offline verbs keep the factory's in-memory open.
    let fresh = classify_offline(&archive, GitIntent::Replay(None), &context).unwrap();
    assert!(fresh.source().lookup("/f", 0).is_some());
}

fn write_tar_file(path: &Path) {
    let members = [ratarmount_formats_tar::UstarMember {
        path: "f",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: &[],
    }];
    let mut file = std::fs::File::create(path).unwrap();
    ratarmount_formats_tar::write_ustar_members(&mut file, &members).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut file).unwrap();
}

/// Leave `archive` mid-commit the way a crash does: `step` names the hook
/// the attempt dies at (`archive truncate`: torn, marker `A`; `locator
/// complete`: rolled forward on recovery, marker `C`; `journal unlink`:
/// finished, marker `D`, journal already gone).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::disallowed_methods)]
fn crash_commit(archive: &Path, step: &'static str) {
    use std::io::Write;
    let len = std::fs::metadata(archive).unwrap().len();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[0u8; 1536]).unwrap();
    let crashed = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        archive,
        len - 1024,
        &mut suffix,
        &mut |s| {
            if s == step {
                Err(std::io::Error::other("crash"))
            } else {
                Ok(())
            }
        },
    );
    assert!(crashed.is_err());
}

/// Regression (#174): offline classification opened the base through the
/// factory with `recover_journals` on, so a pending commit journal was
/// rolled back or forward under `Owner::Inode` before any identity gate —
/// a write a mount or an offline commit would refuse for a foreign journal
/// (B renamed over A; the journal's inode matches the renamed file). The
/// classify open now refuses a pending journal started for the file and
/// never recovers: archive and journal stay byte-identical.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_classify_refuses_pending_commit_journal() {
    use ratarmount_compress::commit_journal::{journal_path, pending};
    for complete in [false, true] {
        for renamed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("base.tar");
            write_tar_file(&base);
            let (crashed, journal) = if renamed {
                let foreign = dir.path().join("foreign.tar");
                write_tar_file(&foreign);
                crash_commit(
                    &foreign,
                    if complete {
                        "locator complete"
                    } else {
                        "archive truncate"
                    },
                );
                let journal = journal_path(&foreign);
                let bytes = std::fs::read(&foreign).unwrap();
                std::fs::rename(&foreign, &base).unwrap();
                (bytes, journal)
            } else {
                crash_commit(
                    &base,
                    if complete {
                        "locator complete"
                    } else {
                        "archive truncate"
                    },
                );
                (std::fs::read(&base).unwrap(), journal_path(&base))
            };
            let journal_bytes = std::fs::read(&journal).unwrap();
            let context = OverlayRunContext::default();
            let error = match classify_offline(&base, GitIntent::Replay(None), &context) {
                Err(error) => error,
                Ok(_) => panic!("a pending commit journal must refuse classification"),
            };
            assert!(
                error.contains("commit journal"),
                "complete={complete} renamed={renamed}: {error}"
            );
            assert_eq!(
                std::fs::read(&base).unwrap(),
                crashed,
                "complete={complete} renamed={renamed}: archive"
            );
            assert_eq!(
                std::fs::read(&journal).unwrap(),
                journal_bytes,
                "complete={complete} renamed={renamed}: journal"
            );
            assert!(
                pending(&base).unwrap().is_some(),
                "complete={complete} renamed={renamed}: journal still pending"
            );
        }
    }
}

/// The `user.ratarmount.commit-journal` locator bytes on `path`, if set.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn commit_locator(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = c"user.ratarmount.commit-journal";
    let mut buf = vec![0u8; 8192];
    #[cfg(target_os = "linux")]
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    #[cfg(target_os = "macos")]
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// Regression (#174): a locator whose journal is missing refuses the way
/// recovery would — an `A` or `C` phase means the archive sits mid-crash
/// (a torn TAR that ends on a header boundary parses, so the factory open
/// alone is no guard). A `D` locator with its journal already unlinked is
/// what a finished commit leaves: classification proceeds. Either way the
/// locator itself is left for a mount or `--no-mount` to act on.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_classify_missing_commit_journal() {
    use ratarmount_compress::commit_journal::journal_path;
    for step in ["archive truncate", "locator complete"] {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.tar");
        write_tar_file(&base);
        crash_commit(&base, step);
        let bytes = std::fs::read(&base).unwrap();
        let locator = commit_locator(&base);
        assert!(locator.is_some(), "{step}: the crash left a locator");
        let journal = journal_path(&base);
        std::fs::remove_file(&journal).unwrap();
        let context = OverlayRunContext::default();
        let error = match classify_offline(&base, GitIntent::Replay(None), &context) {
            Err(error) => error,
            Ok(_) => panic!("a missing journal must refuse classification"),
        };
        assert!(error.contains("commit-journal locator"), "{step}: {error}");
        assert_eq!(std::fs::read(&base).unwrap(), bytes, "{step}: archive");
        assert!(!journal.exists(), "{step}: journal");
        assert_eq!(commit_locator(&base), locator, "{step}: locator");
    }
    // Finished commit (`D` locator, journal already unlinked): allowed.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    write_tar_file(&base);
    crash_commit(&base, "journal unlink");
    let locator = commit_locator(&base);
    let context = OverlayRunContext::default();
    classify_offline(&base, GitIntent::Replay(None), &context)
        .expect("a finished commit's stale locator does not refuse");
    assert!(!journal_path(&base).exists());
    assert_eq!(commit_locator(&base), locator, "stale D locator left alone");
}

/// Regression (#174): a sibling journal whose header names ANOTHER inode
/// (a copy of a crashed archive's journal left beside a fresh base) is not
/// this file's journal: the refusal does not fire, but
/// `recover_journals: false` is what keeps the factory from recovering it.
/// Under the old default the factory's `Owner::Inode` recovery refused the
/// inode mismatch and the open failed — this test fails if the flag is
/// dropped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_classify_ignores_foreign_sibling_journal() {
    use ratarmount_compress::commit_journal::journal_path;
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    write_tar_file(&base);
    let victim = dir.path().join("victim.tar");
    write_tar_file(&victim);
    crash_commit(&victim, "archive truncate");
    let bytes = std::fs::read(&base).unwrap();
    let journal = journal_path(&base);
    let journal_bytes = std::fs::read(journal_path(&victim)).unwrap();
    std::fs::copy(journal_path(&victim), &journal).unwrap();
    let context = OverlayRunContext::default();
    let token = classify_offline(&base, GitIntent::Replay(None), &context)
        .expect("a journal naming another inode does not refuse");
    assert!(token.source().lookup("/f", 0).is_some());
    assert_eq!(std::fs::read(&base).unwrap(), bytes, "archive");
    assert_eq!(std::fs::read(&journal).unwrap(), journal_bytes, "journal");
}
