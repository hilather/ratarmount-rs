//! R6-5: overlays written by released builds. The fixture under
//! `test-harness/fixtures/overlay-v0.1.35/` was created by a REAL v0.1.35
//! binary (`test-harness/make-overlay-v0.1.35.sh`): a `-w` mount over a small
//! tar with one created file. It has a `files` table and NO `meta` table. A
//! released overlay must keep remounting without a flag; only overlays written
//! by unreleased builds with a missing or conflicting kind need one force.
//! CLI-level, offline (no FUSE needed to run these), private HOME / cache.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ratarmount_compositing::{OverlayMeta, HIDDEN_DB};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-harness/fixtures/overlay-v0.1.35")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

struct Env {
    root: tempfile::TempDir,
    overlay: PathBuf,
    base: PathBuf,
}

impl Env {
    /// A private copy of the released overlay and its base tar.
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let overlay = root.path().join("overlay");
        copy_tree(&fixture_dir().join("overlay"), &overlay);
        let base = root.path().join("base.tar");
        fs::copy(fixture_dir().join("base.tar"), &base).unwrap();
        Self {
            root,
            overlay,
            base,
        }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .env("HOME", self.root.path())
            .env("XDG_CACHE_HOME", self.root.path().join(".cache"))
            .env_remove("RATARMOUNT_FORCE_GIT")
            .args(args)
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {}", text(&out));
        String::from_utf8(out.stdout).unwrap()
    }
    /// `--no-mount -w OVERLAY BASE`: the open every `-w` mount starts with.
    fn open(&self, base: &Path, extra: &[&str]) -> Output {
        let mut args = vec![
            "--no-mount",
            "--index-file",
            ":memory:",
            "-w",
            self.overlay.to_str().unwrap(),
        ];
        args.extend(extra);
        args.push(base.to_str().unwrap());
        self.run(&args)
    }
    fn meta(&self) -> OverlayMeta {
        OverlayMeta::read(&self.overlay).unwrap().unwrap()
    }
}

fn text(out: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// The fixture really is a released overlay: no `meta` table at all.
#[test]
fn v035_fixture_has_no_meta_table() {
    let env = Env::new();
    assert!(env.overlay.join(HIDDEN_DB).is_file());
    assert!(
        OverlayMeta::read(&env.overlay).unwrap().is_none(),
        "a v0.1.35 overlay has no meta table"
    );
    assert!(env.overlay.join("created.txt").is_file());
}

/// Regression: a v0.1.35 overlay remounts with no flag, and that first `-w`
/// open records the kind, place and URL of what was opened (no digest). Only
/// unreleased #133 records without a kind are Unknown.
#[test]
fn regression_v035_overlay_remounts_unforced_and_gains_kind() {
    let env = Env::new();
    let out = env.open(&env.base, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let meta = env.meta();
    assert_eq!(meta.get("format_version"), Some("1"), "stays legacy");
    assert_eq!(meta.get("base_kind"), Some("archive"));
    assert_eq!(
        meta.get("base_location"),
        Some(format!("local:{}", env.base.canonicalize().unwrap().display()).as_str())
    );
    assert_eq!(meta.get("base_url"), Some(s(&env.base)));
    assert!(meta.get("base_digest").is_none(), "no digest is invented");
    assert!(meta.get("base_digest_kind").is_none());
    assert!(env.overlay.join("created.txt").is_file());
    // And it keeps remounting.
    let again = env.open(&env.base, &[]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again));
}

/// Regression: before any `-w` open a released overlay is Unrecorded for every
/// verb: seal, verify, diff and pack all run unforced, even with a BASE the
/// overlay never saw; the seal records the kind (no digest).
#[test]
fn regression_v035_overlay_is_unrecorded_for_every_verb() {
    let env = Env::new();
    let other = env.root.path().join("other.tar");
    fs::copy(&env.base, &other).unwrap();
    env.ok(&["diff", s(&env.overlay), s(&other), "--hash"]);
    env.ok(&["overlay", "seal", s(&env.overlay), s(&other)]);
    let meta = env.meta();
    assert!(meta.layer_sealed());
    assert_eq!(
        meta.get("base_kind"),
        Some("archive"),
        "the seal recorded the kind"
    );
    assert!(
        meta.get("base_digest").is_none(),
        "no digest for a released overlay"
    );
    env.ok(&["overlay", "verify", s(&env.overlay), s(&other)]);
    let bundle = env.root.path().join("bundle.tar.zst");
    env.ok(&["overlay", "pack", s(&env.overlay), s(&bundle), s(&other)]);
    assert!(bundle.is_file());
}

/// Regression: once the first `-w` open recorded the kind, an overlay that was
/// made over an archive refuses a directory, naming the flag; one force
/// records the directory.
#[test]
fn regression_v035_then_directory_reopen_refuses() {
    let env = Env::new();
    assert_eq!(env.open(&env.base, &[]).status.code(), Some(0));
    let folder = env.root.path().join("folder");
    fs::create_dir(&folder).unwrap();
    let refused = env.open(&folder, &[]);
    assert_ne!(refused.status.code(), Some(0), "{}", text(&refused));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--force-base-mismatch"),
        "{}",
        text(&refused)
    );
    let forced = env.open(&folder, &["--force-base-mismatch"]);
    assert_eq!(forced.status.code(), Some(0), "{}", text(&forced));
    assert_eq!(env.meta().get("base_kind"), Some("directory"));
}

/// Regression: an overlay from an unreleased #133 build (`format_version` 2)
/// with no usable `base_kind` (absent, or R5's `remote`) is Unknown: refused
/// naming the flag; one force records the base and later opens pass.
#[test]
fn regression_format2_without_base_kind_is_unknown() {
    for old_kind in [None, Some("remote")] {
        let env = Env::new();
        let base = env.base.clone();
        // Made by the current build, then rewritten into the R4/R5 shape.
        let fresh = env.root.path().join("r5-overlay");
        assert_eq!(
            env.run(&[
                "--no-mount",
                "--index-file",
                ":memory:",
                "-w",
                s(&fresh),
                "--base-digest",
                "none",
                s(&base),
            ])
            .status
            .code(),
            Some(0)
        );
        {
            let conn = rusqlite::Connection::open(fresh.join(HIDDEN_DB)).unwrap();
            for key in ["base_kind", "base_location"] {
                OverlayMeta::remove(&conn, key).unwrap();
            }
            if let Some(kind) = old_kind {
                OverlayMeta::set(&conn, "base_kind", kind).unwrap();
            }
        }
        let open = |extra: &[&str]| {
            let mut args = vec!["--no-mount", "--index-file", ":memory:", "-w", s(&fresh)];
            args.extend(extra);
            args.push(s(&base));
            env.run(&args)
        };
        let refused = open(&[]);
        assert_ne!(
            refused.status.code(),
            Some(0),
            "{old_kind:?}: {}",
            text(&refused)
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("--force-base-mismatch"),
            "{old_kind:?}: {stderr}"
        );
        assert_eq!(open(&["--force-base-mismatch"]).status.code(), Some(0));
        assert_eq!(open(&[]).status.code(), Some(0), "one force is enough");
        assert_eq!(
            OverlayMeta::read(&fresh).unwrap().unwrap().get("base_kind"),
            Some("archive")
        );
    }
}
