//! Import CLI contracts, stdin, lower metadata and exit codes without FUSE.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use ratarmount_compositing::{FolderMountSource, OverlayCreateInfo, OverlayMeta, WriteOverlay};

fn import(base: &Path, dest: &Path, patch: &[u8], flags: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "import", "--json"])
        .args(flags)
        .arg("-")
        .arg(dest)
        .arg(base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(patch).unwrap();
    child.wait_with_output().unwrap()
}

/// Regression: stdin must remain byte-oriented and JSON must be the only stdout.
#[test]
fn regression_import_stdin_seal_json_and_exit_codes() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("a"), b"caf\xe9\n").unwrap();
    let dest = root.path().join("overlay");
    let patch = b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-caf\xe9\n+d\xe9j\xe0\n";
    let output = import(&base, &dest, patch, &["--mtime", "42"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["files"], 1);
    assert_eq!(json["rejected"], 0);
    assert!(json["layer_digest"].is_string());
    assert!(OverlayMeta::read(&dest).unwrap().unwrap().layer_sealed());
    assert_eq!(fs::read(dest.join("a")).unwrap(), b"d\xe9j\xe0\n");
    let verify = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "verify", "--json"])
        .arg(&dest)
        .arg(&base)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let error = import(&base, &dest, patch, &[]);
    assert_eq!(error.status.code(), Some(2));
    assert_eq!(fs::read(dest.join("a")).unwrap(), b"d\xe9j\xe0\n");
    ratarmount_compositing::overlay_seal::unseal(&dest).unwrap();

    let patch_file = root.path().join("edit.patch");
    fs::write(&patch_file, patch).unwrap();
    let file_dest = root.path().join("from-file");
    let result = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "import", "--no-seal", "--json"])
        .arg(&patch_file)
        .arg(&file_dest)
        .arg(&base)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(file_dest.join("a")).unwrap(), b"d\xe9j\xe0\n");

    let reject = root.path().join("reject");
    let bad = b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-missing\n+changed\n";
    let result = import(&base, &reject, bad, &["--reject", "--no-seal"]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["rejected"], 1);
    assert!(json["layer_digest"].is_null());
    assert_eq!(fs::read(reject.join("a")).unwrap(), b"caf\xe9\n");
    assert!(reject.join("a.rej").is_file());
    let abort = root.path().join("abort");
    assert_eq!(import(&base, &abort, bad, &[]).status.code(), Some(2));
    assert!(!abort.exists());
}

/// Regression: import must apply against sealed lowers and record the mount's stack identity.
#[test]
fn regression_import_lower_stack_identity_and_unsealed_opt_in() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("a"), b"base\n").unwrap();
    let source = Arc::new(FolderMountSource::new(&base).unwrap());
    let lower = root.path().join("lower");
    let ov = WriteOverlay::new_with_create_info(
        source.clone(),
        &lower,
        &OverlayCreateInfo {
            base_url: base.to_str().unwrap().into(),
            ..Default::default()
        },
    )
    .unwrap();
    let fd = ov.create_file("/a", 0o644).unwrap();
    use std::os::fd::FromRawFd;
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(b"prepared\n").unwrap();
    ov.finish_owned_write_fd(file);
    drop(ov);
    let patch = b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-prepared\n+attempt\n";
    let fail = root.path().join("fail");
    assert_eq!(
        import(&base, &fail, patch, &["--lower", lower.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    assert!(!fail.exists());
    let shared = root.path().join("shared");
    let result = import(
        &base,
        &shared,
        patch,
        &[
            "--lower",
            lower.to_str().unwrap(),
            "--allow-unsealed-lower",
            "--no-seal",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let seal = ratarmount_compositing::overlay_seal::seal(&lower, source).unwrap();
    let dest = root.path().join("sealed-lower");
    let result = import(&base, &dest, patch, &["--lower", lower.to_str().unwrap()]);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(dest.join("a")).unwrap(), b"attempt\n");
    let meta = OverlayMeta::read(&dest).unwrap().unwrap();
    let records = meta.lower_layers().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].path, lower.canonicalize().unwrap());
    assert_eq!(records[0].layer_digest, seal.layer_digest);
    assert_eq!(
        meta.stack_digest(),
        Some(
            ratarmount_compositing::stack_digest(
                meta.base_digest().unwrap(),
                &[&seal.layer_digest]
            )
            .as_str()
        )
    );
    ratarmount_compositing::overlay_seal::unseal(&dest).unwrap();
    ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
}
