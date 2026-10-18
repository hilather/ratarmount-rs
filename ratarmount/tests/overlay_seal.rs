//! Regression: real sealed overlays through the offline CLI, without /dev/fuse.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use ratarmount_compositing::{FolderMountSource, OverlayCreateInfo, WriteOverlay, HIDDEN_DB};

#[path = "diff/cow.rs"]
mod cow;

fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(args)
        .output()
        .unwrap()
}
fn expect(out: Output, code: i32) -> String {
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn fixture(root: &Path) -> (String, String) {
    let base = root.join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("file"), b"base\n").unwrap();
    let dir = root.join("overlay");
    let writer = WriteOverlay::new_with_create_info(
        Arc::new(FolderMountSource::new(&base).unwrap()),
        &dir,
        &OverlayCreateInfo {
            base_url: base.to_str().unwrap().into(),
            ..Default::default()
        },
    )
    .unwrap();
    cow::cow_write(&writer, "/file", b"change\n");
    drop(writer);
    (base.to_str().unwrap().into(), dir.to_str().unwrap().into())
}

/// Regression: sealing must work through strict diff and the existing -w/--lower mount checks.
#[test]
fn regression_cow_seal_cli_strict_diff_and_real_lower() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, dir) = fixture(tmp.path());
    let text = expect(command(&["overlay", "seal", &dir, "--json"]), 0);
    let meta: serde_json::Value = serde_json::from_str(&text).unwrap();
    let digest = meta["layer_digest"].as_str().unwrap();
    assert!(digest.starts_with("sha256:"));
    assert!(meta["sealed_at"].as_str().unwrap().contains('T'));
    assert_eq!(
        expect(command(&["overlay", "seal", &dir]), 0).trim(),
        digest
    );
    assert_eq!(
        expect(command(&["overlay", "verify", &dir]), 0).trim(),
        digest
    );
    assert_eq!(
        expect(command(&["diff", &dir, "--strict", "--hash"]), 0).trim(),
        digest
    );
    let top = tmp.path().join("top");
    let top = top.to_str().unwrap();
    expect(
        command(&["--no-mount", "--lower", &dir, "-w", top, &base]),
        0,
    );
    expect(command(&["--no-mount", "--lower", &dir, &base]), 0);
    let refused = command(&["--no-mount", "-w", &dir, &base]);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("sealed"));
    assert!(!refused.status.success());
    expect(command(&["overlay", "unseal", &dir]), 2);
    expect(command(&["overlay", "unseal", &dir, "--i-know"]), 0);
    expect(command(&["overlay", "verify", &dir]), 2);
    expect(command(&["--no-mount", "-w", &dir, &base]), 0);
    assert!(!Path::new(&dir).join(".ratarmount-sealed").exists());
    assert_ne!(fs::metadata(&dir).unwrap().permissions().mode() & 0o200, 0);
}

/// Regression: verify must exit 1 naming altered content or the sentinel, without DB writes.
#[test]
fn regression_cow_seal_cli_tamper_exit_one_names_path() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, dir) = fixture(tmp.path());
    expect(command(&["overlay", "seal", &dir]), 0);
    let db = fs::read(Path::new(&dir).join(HIDDEN_DB)).unwrap();
    let file = Path::new(&dir).join("file");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&file, b"tamper\n").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(expect(command(&["overlay", "verify", &dir]), 1)
        .lines()
        .any(|l| l == "file"));
    assert_eq!(fs::read(Path::new(&dir).join(HIDDEN_DB)).unwrap(), db);
    let sentinel = Path::new(&dir).join(".ratarmount-sealed");
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&sentinel, b"bad digest").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(expect(command(&["overlay", "verify", &dir]), 1).contains("sentinel mismatch"));
    expect(command(&["overlay", "unseal", &dir, "--i-know"]), 0);
}

/// Regression: BASE/--lower positionals and recorded lower defaults must compose the same view.
#[test]
fn regression_seal_cli_recorded_lowers_and_legacy_explicit_base() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, lower) = fixture(tmp.path());
    expect(command(&["overlay", "seal", &lower]), 0);
    let top = tmp.path().join("top");
    let top = top.to_str().unwrap();
    expect(
        command(&["--no-mount", "-w", top, "--lower", &lower, &base]),
        0,
    );
    expect(
        command(&["overlay", "seal", top, "--lower", &lower, &base]),
        0,
    );
    expect(command(&["overlay", "verify", top]), 0);
    expect(command(&["overlay", "unseal", top, "--i-know"]), 0);
    expect(command(&["overlay", "unseal", &lower, "--i-know"]), 0);
    rusqlite::Connection::open(Path::new(&lower).join(HIDDEN_DB))
        .unwrap()
        .execute_batch("DROP TABLE meta")
        .unwrap();
    let missing = command(&["overlay", "seal", &lower]);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("pass BASE"));
    expect(missing, 2);
    expect(command(&["overlay", "seal", &lower, &base]), 0);
    expect(command(&["overlay", "verify", &lower, &base]), 0);
    expect(command(&["overlay", "unseal", &lower, "--i-know"]), 0);
}
