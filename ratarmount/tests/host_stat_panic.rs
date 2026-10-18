//! Regression: a panic inside a host stat call (rustix 1.1 on macOS, pre-epoch
//! mtimes) must become an error that names the path, never a 101 abort.
//! The panic is forced with `RATARMOUNT_TEST_STAT_PANIC=<path suffix>`, which
//! only exists when `ratarmount-compositing/test-hooks` is on (dev-dependency).

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use ratarmount_compositing::{FolderMountSource, OverlayCreateInfo, WriteOverlay};

#[path = "diff/cow.rs"]
mod cow;

const POISON: &str = "poison.txt";

fn fixture(root: &Path) -> (String, String) {
    let base = root.join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join(POISON), b"base\n").unwrap();
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
    cow::cow_write(&writer, &format!("/{POISON}"), b"change\n");
    drop(writer);
    (base.to_str().unwrap().into(), dir.to_str().unwrap().into())
}

fn run(root: &Path, args: &[&str], poison: bool) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    cmd.env("HOME", root.join("home"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .args(args);
    if poison {
        cmd.env("RATARMOUNT_TEST_STAT_PANIC", POISON);
    }
    cmd.output().unwrap()
}

fn assert_named_error(out: &Output, code: i32, what: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(code), "{what}: stderr: {stderr}");
    assert!(
        stderr.contains("internal error reading file metadata") && stderr.contains(POISON),
        "{what}: stderr must name the path: {stderr}"
    );
}

/// Regression: a forced stat panic aborted fsck/seal/verify/diff/pack with
/// status 101; each verb must exit 2 (the error code the
/// verb already uses for an I/O failure) and name
/// the path.
#[test]
fn regression_fsck_seal_verify_diff_pack_stat_panic_exit_2_names_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (base, dir) = fixture(root);
    let bundle = root.join("bundle.tar.zst");
    let bundle = bundle.to_str().unwrap();

    // Control: without the hook everything works (and seal leaves a sealed
    // overlay for verify/pack below).
    assert_eq!(
        run(root, &["overlay", "fsck", &dir], false).status.code(),
        Some(0)
    );
    assert_named_error(&run(root, &["overlay", "fsck", &dir], true), 2, "fsck");
    assert_named_error(&run(root, &["overlay", "seal", &dir], true), 2, "seal");
    assert_named_error(
        &run(root, &["diff", &dir, "--base", &base, "--hash"], true),
        2,
        "diff",
    );
    let seal = run(root, &["overlay", "seal", &dir], false);
    assert_eq!(seal.status.code(), Some(0), "{seal:?}");
    assert_named_error(&run(root, &["overlay", "verify", &dir], true), 2, "verify");
    assert_named_error(
        &run(root, &["overlay", "pack", &dir, bundle], true),
        2,
        "pack",
    );
}
