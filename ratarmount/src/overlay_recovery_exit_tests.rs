use super::*;
use ratarmount_compositing::{classify_mount_journal, MountRecords, OVERLAY_MARKER};
use ratarmount_compress::commit_journal;
use ratarmount_index::checked_open::test_seams::{Seam, Seams};
use std::cell::Cell;
use std::fs;
use std::rc::Rc;

/// Regression: #239 a DB symlink planted after SQLite's pathname check
/// must exit 1 with a typed policy refusal, rather than defer a torn
/// journal and exit 2. The archive and all recovery state stay intact.
#[test]
fn regression_after_low_fd_fill_symlink_recovery_exits_one() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let archive = root.join("base.tar");
    fs::write(&archive, [0u8; 4096]).unwrap();
    let overlay = root.join("overlay");
    fs::create_dir(&overlay).unwrap();
    let db = overlay.join(HIDDEN_DB);
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch("CREATE TABLE files (path, name, deleted)")
        .unwrap();
    let marker = overlay.join(OVERLAY_MARKER);
    fs::write(&marker, b"used overlay").unwrap();
    let payload = overlay.join("new");
    fs::write(&payload, b"overlay addition").unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[1u8; 1536]).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "The test death seam leaves a real torn journal for recovery classification"
    )]
    let interrupted =
        commit_journal::replace_suffix_with_hook(&archive, 3072, &mut suffix, &mut |step| {
            if step == "archive truncate" {
                Err(std::io::Error::other("crash"))
            } else {
                Ok(())
            }
        });
    assert!(interrupted.is_err());
    assert!(!commit_journal::pending(&archive).unwrap().unwrap().complete);
    let journal = commit_journal::journal_path(&archive);
    let locator = || {
        let mut bytes = vec![0u8; 4096];
        let n =
            rustix::fs::getxattr(&archive, "user.ratarmount.commit-journal", &mut bytes).unwrap();
        bytes.truncate(n);
        bytes
    };
    let before = (
        fs::read(&archive).unwrap(),
        fs::read(&db).unwrap(),
        fs::read(&marker).unwrap(),
        fs::read(&payload).unwrap(),
        fs::read(&journal).unwrap(),
        locator(),
    );
    let target = root.join("saved.sqlite");
    let planted = Rc::new(Cell::new(false));
    let seams = {
        let (db, target, planted) = (db.clone(), target.clone(), planted.clone());
        Seams::set(move |seam| {
            if seam == Seam::AfterLowFdFill && !planted.replace(true) {
                fs::rename(&db, &target).unwrap();
                std::os::unix::fs::symlink(&target, &db).unwrap();
            }
        })
    };
    let result = classify_mount_journal(
        &MountRecords {
            top: Some(overlay),
            ..Default::default()
        },
        &archive,
    );
    drop(seams);
    assert!(planted.get(), "AfterLowFdFill seam ran");
    assert_eq!(fs::read_link(&db).unwrap(), target);
    assert_eq!(fs::read(&target).unwrap(), before.1);
    assert_eq!(
        (
            fs::read(&archive).unwrap(),
            fs::read(&db).unwrap(),
            fs::read(&marker).unwrap(),
            fs::read(&payload).unwrap(),
            fs::read(&journal).unwrap(),
            locator(),
        ),
        before
    );
    let error = result.expect_err("policy refusal must not become Deferred");
    assert!(
        ratarmount_compositing::overlay_db::is_overlay_state_error(&error),
        "typed policy refusal: {error}"
    );
    assert!(
        error
            .to_string()
            .contains("is a symlink; it must be a regular file"),
        "{error}"
    );
    assert!(error.to_string().contains(&db.display().to_string()));
    assert_eq!(overlay_recovery_exit_code(&error), 1, "{error}");
}
