//! Offline diff exit codes and clean patch output, without /dev/fuse.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use ratarmount_compositing::{FolderMountSource, WriteOverlay, HIDDEN_DB};
use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};

#[path = "diff/cow.rs"]
mod cow;

fn run(overlay: &Path, base: Option<&Path>, flags: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    cmd.arg("diff").arg(overlay);
    if let Some(base) = base {
        cmd.arg("--base").arg(base);
    }
    cmd.args(flags).output().unwrap()
}

/// Regression: an existing file edited through the real COW path vanished from every diff mode.
#[test]
fn regression_cow_diff_name_manifest_hash_and_between() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), b"base\n").unwrap();
    let source = Arc::new(FolderMountSource::new(&base).unwrap());
    let dir = tmp.path().join("cow");
    let ov = WriteOverlay::new(source.clone(), &dir).unwrap();
    cow::cow_write(&ov, "/f", b"changed\n");
    drop(ov);
    let conn = rusqlite::Connection::open(dir.join(HIDDEN_DB)).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(conn);
    let names = run(&dir, Some(&base), &["--name-status"]);
    assert_eq!(names.status.code(), Some(1));
    assert_eq!(names.stdout, b"M\tf\n");
    let manifest = run(&dir, Some(&base), &["--manifest"]);
    assert!(manifest.status.success());
    let row: serde_json::Value = serde_json::from_slice(&manifest.stdout).unwrap();
    assert_eq!(row["status"], "modified");
    assert_eq!(row["path"], "f");
    assert!(row["base_hash"].as_str().unwrap().starts_with("sha256:"));
    let hash = run(&dir, Some(&base), &["--hash"]);
    assert!(hash.status.success());
    assert_ne!(
        String::from_utf8_lossy(&hash.stdout).trim(),
        ratarmount_compositing::overlay_changes::EMPTY_SHA256
    );
    let rowed = tmp.path().join("rowed");
    let ov = WriteOverlay::new(source, &rowed).unwrap();
    use std::io::Write;
    use std::os::fd::FromRawFd;
    let mut file = unsafe { fs::File::from_raw_fd(ov.create_file("/f", 0o644).unwrap()) };
    file.write_all(b"changed\n").unwrap();
    ov.finish_owned_write_fd(file);
    drop(ov);
    assert_eq!(hash.stdout, run(&rowed, Some(&base), &["--hash"]).stdout);
    let between = run(
        &dir,
        Some(&base),
        &["--hash", "--between", rowed.to_str().unwrap()],
    );
    assert!(
        between.status.success(),
        "{}",
        String::from_utf8_lossy(&between.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&between.stdout).trim(),
        ratarmount_compositing::overlay_changes::EMPTY_SHA256
    );
    let manifest = run(&dir, None, &["--manifest"]);
    assert!(manifest.status.success());
    let row: serde_json::Value = serde_json::from_slice(&manifest.stdout).unwrap();
    assert_eq!(row["status"], "written");
    assert_eq!(row["path"], "f");
}

/// Regression: diff returns 0/1/2, does not create missing databases, and emits no progress on stdout.
#[test]
fn regression_diff_exit_codes_and_clean_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("a"), b"before\n").unwrap();
    let overlay_dir = tmp.path().join("overlay");
    let overlay = WriteOverlay::new(
        Arc::new(FolderMountSource::new(&base).unwrap()),
        &overlay_dir,
    )
    .unwrap();
    drop(overlay);
    let result = run(&overlay_dir, Some(&base), &[]);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let overlay = WriteOverlay::new(
        Arc::new(FolderMountSource::new(&base).unwrap()),
        &overlay_dir,
    )
    .unwrap();
    overlay.ensure_modifiable("/a").unwrap();
    overlay
        .set_metadata(
            "/a",
            &ratarmount_compositing::OverlayMetadata {
                mode: Some(0o644),
                ..Default::default()
            },
        )
        .unwrap();
    drop(overlay);
    let before_db = fs::read(overlay_dir.join(HIDDEN_DB)).unwrap();
    fs::write(overlay_dir.join("a"), b"after\n").unwrap();
    let result = run(&overlay_dir, Some(&base), &[]);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-before\n+after\n"
    );
    assert_eq!(fs::read(overlay_dir.join(HIDDEN_DB)).unwrap(), before_db);
    let result = run(&overlay_dir, None, &[]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--base"));
    let missing = tmp.path().join("missing");
    fs::create_dir(&missing).unwrap();
    assert_eq!(run(&missing, Some(&base), &[]).status.code(), Some(2));
    assert_eq!(fs::read_dir(missing).unwrap().count(), 0);
    assert_eq!(
        run(&overlay_dir, Some(&base), &["--unknown"]).status.code(),
        Some(2)
    );
    let archive = tmp.path().join("base.tar");
    let mut tar = fs::File::create(&archive).unwrap();
    write_ustar_members(
        &mut tar,
        &[UstarMember {
            xattrs: &[],
            path: "a",
            payload: UstarPayload::File { bytes: b"before\n" },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }],
    )
    .unwrap();
    write_tar_eof(&mut tar).unwrap();
    drop(tar);
    let result = run(&overlay_dir, Some(&archive), &["--git"]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.stdout.starts_with(b"diff --git a/a b/a\n"),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(!archive.with_extension("tar.index.sqlite").exists());
}

/// Regression: --base REPO reads the committed snapshot, even with a dirty working tree.
#[test]
fn regression_diff_git_base_uses_committed_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_dir = tmp.path().join("repo");
    let repo = git2::Repository::init(&repo_dir).unwrap();
    fs::write(repo_dir.join("a"), b"committed\n").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("a")).unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = git2::Signature::now("Test", "test@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "base", &tree, &[])
        .unwrap();
    fs::write(repo_dir.join("a"), b"dirty\n").unwrap();
    let overlay_dir = tmp.path().join("overlay");
    let overlay = WriteOverlay::new(
        Arc::new(FolderMountSource::new(&repo_dir).unwrap()),
        &overlay_dir,
    )
    .unwrap();
    overlay.ensure_modifiable("/a").unwrap();
    overlay
        .set_metadata(
            "/a",
            &ratarmount_compositing::OverlayMetadata {
                mode: Some(0o644),
                ..Default::default()
            },
        )
        .unwrap();
    drop(overlay);
    fs::write(overlay_dir.join("a"), b"attempt\n").unwrap();
    let result = run(&overlay_dir, Some(&repo_dir), &[]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let patch = String::from_utf8(result.stdout).unwrap();
    assert!(patch.contains("-committed\n+attempt\n"), "{patch}");
    assert_eq!(fs::read(repo_dir.join("a")).unwrap(), b"dirty\n");
}

/// Regression: legacy/unsealed and loose warnings stay on stderr; --hash remains machine-readable.
#[test]
fn regression_diff_warnings_hash_and_limits() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    let dir = tmp.path().join("overlay");
    let overlay =
        WriteOverlay::new(Arc::new(FolderMountSource::new(&base).unwrap()), &dir).unwrap();
    use std::io::Write;
    use std::os::fd::FromRawFd;
    let mut file = unsafe { fs::File::from_raw_fd(overlay.create_file("/a", 0o644).unwrap()) };
    file.write_all(b"new \r\n").unwrap();
    overlay.finish_owned_write_fd(file);
    drop(overlay);
    let result = run(
        &dir,
        Some(&base),
        &["--hash", "--normalize", "loose", "--json"],
    );
    assert_eq!(result.status.code(), Some(0));
    let row: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(row["files"], 1);
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("unsealed overlay"));
    assert_eq!(stderr.matches("analysis only").count(), 1);
    let result = run(&dir, Some(&base), &["--max-patch-bytes", "1"]);
    assert_eq!(result.status.code(), Some(3));
    assert!(result.stdout.is_empty());
    let result = run(&dir, Some(&base), &["--manifest", "--max-files", "0"]);
    assert_eq!(result.status.code(), Some(3));
    assert!(result.stdout.is_empty());
    rusqlite::Connection::open(dir.join(HIDDEN_DB))
        .unwrap()
        .execute("DROP TABLE meta", [])
        .unwrap();
    let result = run(&dir, None, &["--manifest"]);
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .contains("legacy overlay"));
}
