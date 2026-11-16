use super::*;
use ratarmount_compositing::{classify_mount_journal, MountRecords, OVERLAY_MARKER};
use ratarmount_compress::commit_journal;
use ratarmount_index::checked_open::test_seams::{Seam, Seams};
use std::cell::Cell;
use std::fs;
use std::rc::Rc;

struct LateCompanionFixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    archive: PathBuf,
    overlay: PathBuf,
    db: PathBuf,
    target: PathBuf,
    linked: PathBuf,
    before: Vec<Vec<u8>>,
}

impl LateCompanionFixture {
    fn new(suffix: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let archive = root.join("base.tar");
        fs::write(&archive, [0u8; 4096]).unwrap();
        let overlay = root.join("overlay");
        fs::create_dir(&overlay).unwrap();
        let db = overlay.join(HIDDEN_DB);
        let conn = rusqlite::Connection::open(&db).unwrap();
        let mode = if suffix == "-journal" {
            "DELETE"
        } else {
            "WAL"
        };
        conn.execute_batch(&format!(
            "PRAGMA journal_mode={mode}; CREATE TABLE files(path, name, deleted)"
        ))
        .unwrap();
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap(),
            mode.to_ascii_lowercase()
        );
        drop(conn);
        fs::write(overlay.join(OVERLAY_MARKER), b"used overlay").unwrap();
        fs::write(overlay.join("new"), b"overlay addition").unwrap();
        let target = root.join("companion-target");
        fs::write(&target, b"nonempty external target").unwrap();
        let mut tail = tempfile::tempfile().unwrap();
        tail.write_all(&[1u8; 1536]).unwrap();
        #[expect(
            clippy::disallowed_methods,
            reason = "The test death seam leaves a real torn journal for recovery classification"
        )]
        let interrupted =
            commit_journal::replace_suffix_with_hook(&archive, 3072, &mut tail, &mut |step| {
                if step == "archive truncate" {
                    Err(std::io::Error::other("crash"))
                } else {
                    Ok(())
                }
            });
        assert!(interrupted.is_err());
        assert!(!commit_journal::pending(&archive).unwrap().unwrap().complete);
        let mut linked = db.as_os_str().to_os_string();
        linked.push(suffix);
        let mut fixture = Self {
            _tmp: tmp,
            root,
            archive,
            overlay,
            db,
            target,
            linked: linked.into(),
            before: Vec::new(),
        };
        assert!(!fixture.linked.exists());
        fixture.before = fixture.bytes();
        fixture
    }

    fn bytes(&self) -> Vec<Vec<u8>> {
        let mut bytes: Vec<_> = [
            self.archive.clone(),
            self.db.clone(),
            self.target.clone(),
            self.overlay.join(OVERLAY_MARKER),
            self.overlay.join("new"),
            commit_journal::journal_path(&self.archive),
        ]
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect();
        let mut locator = vec![0u8; 4096];
        let n = rustix::fs::getxattr(
            &self.archive,
            "user.ratarmount.commit-journal",
            &mut locator,
        )
        .unwrap();
        locator.truncate(n);
        bytes.push(locator);
        bytes
    }

    fn assert_unchanged(&self) {
        assert!(fs::symlink_metadata(&self.linked).unwrap().is_symlink());
        assert_eq!(fs::read_link(&self.linked).unwrap(), self.target);
        assert_eq!(
            self.bytes(),
            self.before,
            "archive/target/DB/recovery bytes"
        );
    }
}

fn plant_late_companion(linked: PathBuf, target: PathBuf) -> Seams {
    let planted = Cell::new(false);
    Seams::set(move |seam| {
        if seam == Seam::AfterLowFdFill && !planted.replace(true) {
            std::os::unix::fs::symlink(&target, &linked).unwrap();
        }
    })
}

fn late_companion_recovery(suffix: &str) {
    let mut failures = Vec::new();
    for subprocess in [false, true] {
        let result = std::panic::catch_unwind(|| {
            let fx = LateCompanionFixture::new(suffix);
            let error = if subprocess {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "overlay_recovery_exit_tests::late_companion_cli_child",
                        "--nocapture",
                    ])
                    .env("RATARMOUNT_TEST_LATE_COMPANION_ROOT", &fx.root)
                    .env("RATARMOUNT_TEST_LATE_COMPANION_SUFFIX", suffix)
                    .output()
                    .unwrap();
                fx.assert_unchanged();
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(output.status.code(), Some(1), "{text}");
                assert!(
                    !text.contains("--force"),
                    "force cannot bypass policy: {text}"
                );
                text
            } else {
                let seams = plant_late_companion(fx.linked.clone(), fx.target.clone());
                let result = classify_mount_journal(
                    &MountRecords {
                        top: Some(fx.overlay.clone()),
                        ..Default::default()
                    },
                    &fx.archive,
                );
                drop(seams);
                fx.assert_unchanged();
                let error = result.expect_err("policy refusal must not become Deferred");
                assert!(
                    ratarmount_compositing::overlay_db::is_overlay_state_error(&error),
                    "typed policy refusal: {error}"
                );
                assert_eq!(overlay_recovery_exit_code(&error), 1, "{error}");
                error.to_string()
            };
            assert!(error.contains(&fx.linked.display().to_string()), "{error}");
            assert!(
                error.contains("is a symlink; it must be a regular file"),
                "{error}"
            );
        });
        if result.is_err() {
            failures.push(if subprocess { "CLI" } else { "library" });
        }
    }
    assert!(failures.is_empty(), "{suffix}: {failures:?}");
}

// A subprocess runs the actual CLI recovery branch because it calls process::exit.
#[test]
fn late_companion_cli_child() {
    let Some(root) = std::env::var_os("RATARMOUNT_TEST_LATE_COMPANION_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let suffix = std::env::var_os("RATARMOUNT_TEST_LATE_COMPANION_SUFFIX").unwrap();
    let overlay = root.join("overlay");
    let archive = root.join("base.tar");
    let mut linked = overlay.join(HIDDEN_DB).into_os_string();
    linked.push(suffix);
    let _seams = plant_late_companion(linked.into(), root.join("companion-target"));
    let args = Args::try_parse_from([
        std::ffi::OsStr::new("ratarmount"),
        std::ffi::OsStr::new("--no-mount"),
        std::ffi::OsStr::new("-w"),
        overlay.as_os_str(),
        archive.as_os_str(),
    ])
    .unwrap();
    recover_mount_journals(&args, &[archive]);
    panic!("late companion policy must refuse recovery");
}

/// Regression: #239 a late journal symlink must stay typed and exit 1 without force advice.
#[test]
fn regression_after_low_fd_fill_journal_symlink_recovery_exits_one() {
    let _spawning = ratarmount_index::test_process::spawning();
    late_companion_recovery("-journal");
}

/// Regression: #239 a late WAL symlink on a WAL-mode DB must preserve policy and all bytes.
#[test]
fn regression_after_low_fd_fill_wal_symlink_recovery_exits_one() {
    let _spawning = ratarmount_index::test_process::spawning();
    late_companion_recovery("-wal");
}

/// Regression: #239 a late SHM symlink on a WAL-mode DB must preserve policy and all bytes.
#[test]
fn regression_after_low_fd_fill_shm_symlink_recovery_exits_one() {
    let _spawning = ratarmount_index::test_process::spawning();
    late_companion_recovery("-shm");
}

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
