//! #89 follow-up: an overlay database that cannot be opened names the file
//! and the way out. `--no-mount` exits after opening the overlay, before FUSE.

use std::path::Path;
use std::process::{Command, Output};

fn run_w(overlay: &Path, src: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .arg("--no-mount")
        .arg("-w")
        .arg(overlay)
        .arg(src)
        .output()
        .unwrap()
}

/// Regression: an unopenable overlay database printed a bare SQLite error
/// with no path or recovery hint.
#[test]
fn corrupt_overlay_db_names_file_and_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("a"), b"a").unwrap();
    let ov = tmp.path().join("ov");
    std::fs::create_dir(&ov).unwrap();
    let db = ov.join(".ratarmount.overlay.sqlite");
    std::fs::write(&db, vec![0x5a; 4096]).unwrap();
    let out = run_w(&ov, &src);
    assert_eq!(out.status.code(), Some(1));
    let want = format!(
        "error opening write overlay database {}: file is not a database; \
         move it aside to start a fresh overlay, or mount without -w",
        db.display()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.lines().any(|l| l == want), "{stderr}");
}

#[test]
fn overlay_path_that_is_a_file_keeps_generic_message() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let ov = tmp.path().join("ov");
    std::fs::write(&ov, b"x").unwrap();
    let out = run_w(&ov, &src);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr
            .lines()
            .any(|l| l.starts_with("error creating write overlay: overlay path must be a folder")),
        "{stderr}"
    );
    assert!(!stderr.contains("move it aside"), "{stderr}");
}
