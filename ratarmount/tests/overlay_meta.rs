//! Overlay identity and CLI inspection stop at --no-mount; no /dev/fuse needed.

use std::path::Path;
use std::process::{Command, Output};

use ratarmount_compositing::{OverlayMeta, HIDDEN_DB};
use sha2::{Digest, Sha256};

fn open(overlay: &Path, base: &Path, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["--no-mount", "--index-file", ":memory:", "-w"])
        .arg(overlay)
        .args(flags)
        .arg(base)
        .output()
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Regression: mount startup did not record the base URL or digest for offline info.
#[test]
fn regression_overlay_meta_cli_creation_info_and_remount() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("base.tar");
    std::fs::write(&archive, [0u8; 1024]).unwrap();
    let overlay = root.path().join("overlay");
    assert_success(&open(&overlay, &archive, &[]));
    let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "info"])
        .arg(&overlay)
        .arg("--json")
        .output()
        .unwrap();
    assert_success(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["base_url"], archive.to_str().unwrap());
    assert_eq!(
        value["base_digest"],
        format!("sha256:{:x}", Sha256::digest([0u8; 1024]))
    );
    assert_eq!(value["format_version"], "2");
    assert_eq!(value["legacy"], false);
    assert_eq!(value["files_present"], 0);
    assert_eq!(value["db_opens_read_only"], true);
    assert_success(&open(&overlay, &archive, &[]));
    std::fs::write(&archive, [0u8; 2048]).unwrap();
    let refused = open(&overlay, &archive, &[]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("base mismatch"));
    assert_success(&open(&overlay, &archive, &["--force-base-mismatch"]));
    assert!(OverlayMeta::read(&overlay)
        .unwrap()
        .unwrap()
        .get("base_mismatch_forced_at")
        .is_some());
}

/// Regression: --base-digest none silently omitted the disabled-verification warning.
#[test]
fn regression_overlay_meta_cli_none_warns_and_supplied_is_recorded() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let overlay = root.path().join("none");
    let output = open(&overlay, &source, &["--base-digest", "none"]);
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("warning: --base-digest none"));
    assert_eq!(
        OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .base_digest_kind(),
        Some("none")
    );
    let supplied = format!("sha256:{}", "a".repeat(64));
    let overlay = root.path().join("supplied");
    assert_success(&open(&overlay, &source, &["--base-digest", &supplied]));
    assert_eq!(
        OverlayMeta::read(&overlay).unwrap().unwrap().base_digest(),
        Some(supplied.as_str())
    );
}

/// Regression: info on an old overlay must stay legacy after a writable mount migrates it.
#[test]
fn regression_overlay_meta_cli_legacy_info_after_migration() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let overlay = root.path().join("overlay");
    std::fs::create_dir(&overlay).unwrap();
    let conn = rusqlite::Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    conn.execute_batch("CREATE TABLE files (path TEXT, name TEXT, mtime REAL, mode INTEGER, uid INTEGER, gid INTEGER, deleted BOOL, PRIMARY KEY(path,name));").unwrap();
    drop(conn);
    assert_success(&open(&overlay, &source, &[]));
    let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "info"])
        .arg(&overlay)
        .arg("--json")
        .output()
        .unwrap();
    assert_success(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["legacy"], true);
    assert_eq!(value["format_version"], "1");
    assert!(value.get("base_digest").is_none());
}
