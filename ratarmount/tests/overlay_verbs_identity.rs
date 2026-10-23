//! R6-4: the offline verbs (`seal`, `pack`, `diff`, `verify`, `import`) open
//! the base through the factory and compare what it served with what the
//! overlay recorded. CLI-level, offline (no FUSE), private HOME / cache.

#[path = "support/token.rs"]
mod token;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use ratarmount_compositing::{FolderMountSource, OverlayMeta, HIDDEN_DB};
use ratarmount_core::MountSource;

#[path = "diff/cow.rs"]
mod cow;

struct Env {
    root: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .env("HOME", self.root.path())
            .env("XDG_CACHE_HOME", self.path(".cache"))
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

fn tar_of(env: &Env, name: &str) -> PathBuf {
    let dir = env.path(&format!("{name}-src"));
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("f.txt"), "a").unwrap();
    let archive = env.path(name);
    assert!(Command::new("tar")
        .args(["cf", s(&archive), "-C", s(&dir), "f.txt"])
        .status()
        .unwrap()
        .success());
    archive
}

fn refused(out: &Output, flag: &str, what: &str) {
    assert_ne!(out.status.code(), Some(0), "{what}: {}", text(out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(flag),
        "{what}: {}",
        text(out)
    );
}

/// Regression: a `--base-digest none` overlay compared nothing, so every verb
/// accepted a base of another kind. Reopen, `seal`, `pack`, `diff` and
/// `verify` refuse a directory where an archive was recorded (and the other
/// way round); the kind is compared under every digest kind.
#[test]
fn regression_none_overlay_refuses_kind_swap_in_every_verb() {
    let env = Env::new();
    let archive = tar_of(&env, "a.tar");
    let folder = env.path("folder");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("f.txt"), "a").unwrap();
    let overlay = env.path("ov");
    env.ok(&[
        "--no-mount",
        "--index-file",
        ":memory:",
        "-w",
        s(&overlay),
        "--base-digest",
        "none",
        s(&archive),
    ]);
    // Unsealed overlay: seal and diff.
    refused(
        &env.run(&["overlay", "seal", s(&overlay), s(&folder)]),
        "--force-base-mismatch",
        "seal",
    );
    assert!(!OverlayMeta::read(&overlay).unwrap().unwrap().layer_sealed());
    refused(
        &env.run(&["diff", s(&overlay), s(&folder), "--hash"]),
        "--force-base-mismatch",
        "diff",
    );
    // Sealed overlay: pack and verify.
    env.ok(&["overlay", "seal", s(&overlay), s(&archive)]);
    let bundle = env.path("bundle.tar.zst");
    refused(
        &env.run(&["overlay", "pack", s(&overlay), s(&bundle), s(&folder)]),
        "--force-base-mismatch",
        "pack",
    );
    assert!(!bundle.exists());
    let verify = env.run(&["overlay", "verify", s(&overlay), s(&folder), "--json"]);
    assert_eq!(verify.status.code(), Some(1), "{}", text(&verify));
    let report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(report["base_ok"], false, "{report}");
    // The matching base still passes every verb.
    env.ok(&["overlay", "verify", s(&overlay), s(&archive)]);
    env.ok(&["diff", s(&overlay), s(&archive), "--hash"]);
}

/// Regression: a directory base that happens to be a Git working tree was
/// reopened by `seal`/`diff`/`pack` as Git (`.git exists`), so the layer was
/// measured against HEAD instead of the working tree that was mounted. The
/// recorded kind decides: a directory overlay is replayed as a directory.
#[test]
fn regression_dir_overlay_over_worktree_seals_the_working_tree() {
    let env = Env::new();
    let base = env.path("work");
    fs::create_dir(&base).unwrap();
    let repo = git2::Repository::init(&base).unwrap();
    fs::write(base.join("f"), b"committed\n").unwrap();
    {
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("f")).unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "first", &tree, &[])
            .unwrap();
    }
    // The working tree differs from HEAD.
    fs::write(base.join("f"), b"worktree\n").unwrap();
    let overlay = env.path("ov");
    let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base).unwrap());
    let token = token::ClassifiedBaseOver::folder(source.clone(), &base);
    let ov = ratarmount_compositing::WriteOverlay::open(
        &token,
        source,
        &overlay,
        &ratarmount_compositing::CreateOptions::default(),
    )
    .unwrap();
    cow::cow_write(&ov, "/f", b"changed\n");
    drop(ov);
    assert_eq!(
        OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .get("base_kind"),
        Some("directory")
    );
    // `ratarmount diff` exits 1 when there are changes.
    let out = env.run(&["diff", s(&overlay), "--patch"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let patch = String::from_utf8_lossy(&out.stdout);
    assert!(
        patch.contains("-worktree"),
        "measured against the working tree: {patch}"
    );
    assert!(
        !patch.contains("-committed"),
        "measured against HEAD: {patch}"
    );
    env.ok(&["overlay", "seal", s(&overlay)]);
    env.ok(&["overlay", "verify", s(&overlay)]);
}

/// Regression: an already sealed overlay is finished from its own record. The
/// base is not opened (a BASE that cannot be opened does not matter), nothing
/// is written, and a sealed record cannot start a seal of anything else.
#[test]
fn regression_sealed_record_cannot_authorize() {
    let env = Env::new();
    let archive = tar_of(&env, "a.tar");
    let overlay = env.path("ov");
    env.ok(&[
        "--no-mount",
        "--index-file",
        ":memory:",
        "-w",
        s(&overlay),
        s(&archive),
    ]);
    let digest = env.ok(&["overlay", "seal", s(&overlay), s(&archive)]);
    let before = fs::read(overlay.join(HIDDEN_DB)).unwrap();
    let missing = env.path("does-not-exist.tar");
    let again = env.ok(&["overlay", "seal", s(&overlay), s(&missing)]);
    assert_eq!(again, digest);
    assert_eq!(
        fs::read(overlay.join(HIDDEN_DB)).unwrap(),
        before,
        "no row written"
    );
    // `pack` classifies and gates: a swapped base is still refused.
    let other = tar_of(&env, "other.tar");
    fs::write(&other, b"different bytes").unwrap();
    let bundle = env.path("bundle.tar.zst");
    let out = env.run(&["overlay", "pack", s(&overlay), s(&bundle), s(&other)]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!bundle.exists());
}

/// A released (v0.1.35-shaped, `meta` table-less) overlay gains its kind when
/// it is sealed: the seal records `base_kind`, `base_location` and `base_url`
/// from the classified base, and no digest.
#[test]
fn regression_seal_of_unrecorded_overlay_records_kind() {
    let env = Env::new();
    let base = env.path("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), b"x").unwrap();
    let overlay = env.path("ov");
    let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base).unwrap());
    drop(token::new_overlay(source, &overlay).unwrap());
    {
        let conn = rusqlite::Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        conn.execute_batch("DROP TABLE meta").unwrap();
    }
    env.ok(&["overlay", "seal", s(&overlay), s(&base)]);
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    assert!(meta.layer_sealed());
    assert_eq!(meta.get("format_version"), Some("1"));
    assert_eq!(meta.get("base_kind"), Some("directory"));
    assert_eq!(
        meta.get("base_location"),
        Some(format!("local:{}", base.canonicalize().unwrap().display()).as_str())
    );
    assert!(
        meta.get("base_digest").is_none(),
        "no digest for a released overlay"
    );
}

fn have_gnu_tar() -> bool {
    Command::new("tar")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("GNU tar"))
}

/// Offline `--commit-overlay` of an overlay with a database checks the archive
/// against the recorded base BEFORE the splice: a swapped base is refused
/// naming the flag (nothing written), `--force-base-mismatch` commits; a raw
/// directory of files has no identity and says so.
#[test]
fn regression_offline_commit_overlay_gates_the_base() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let archive = tar_of(&env, "a.tar");
    let overlay = env.path("ov");
    env.ok(&[
        "--no-mount",
        "--index-file",
        ":memory:",
        "-w",
        s(&overlay),
        s(&archive),
    ]);
    fs::write(overlay.join("new.txt"), b"new").unwrap();
    // The base is swapped for a different valid tar.
    let other = tar_of(&env, "swap.tar");
    fs::write(&other, {
        let mut bytes = fs::read(&other).unwrap();
        bytes.extend_from_slice(&[0u8; 1024]);
        bytes
    })
    .unwrap();
    fs::copy(&other, &archive).unwrap();
    let before = fs::read(&archive).unwrap();
    let refused = env.run(&["--commit-overlay", "-w", s(&overlay), s(&archive), "--yes"]);
    refused_with(&refused, "--force-base-mismatch");
    assert_eq!(fs::read(&archive).unwrap(), before, "nothing was written");
    let forced = env.run(&[
        "--commit-overlay",
        "-w",
        s(&overlay),
        s(&archive),
        "--yes",
        "--force-base-mismatch",
    ]);
    assert_eq!(forced.status.code(), Some(0), "{}", text(&forced));
    assert_ne!(
        fs::read(&archive).unwrap(),
        before,
        "the forced commit wrote"
    );

    // A raw directory (no overlay database): committed, with the note.
    let raw = env.path("raw");
    fs::create_dir(&raw).unwrap();
    fs::write(raw.join("added"), b"raw").unwrap();
    let target = tar_of(&env, "raw-target.tar");
    let out = env.run(&["--commit-overlay", "-w", s(&raw), s(&target), "--yes"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no base identity was checked"),
        "{}",
        text(&out)
    );
}

fn refused_with(out: &Output, flag: &str) {
    assert_ne!(out.status.code(), Some(0), "{}", text(out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(flag),
        "{}",
        text(out)
    );
}
