//! Regression (Keystone 5564615409, blocker 1): `overlay seal`, `overlay pack`
//! and `diff` compared nothing against the identity the overlay recorded, so a
//! base edited after creation was sealed, packed and diffed silently (and the
//! layer then failed its own `overlay verify`). They now run the cheap identity
//! check that reopen uses and refuse naming `--force-base-mismatch`.
//!
//! CLI-level, offline (no FUSE), private HOME / XDG_CACHE_HOME per test.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ratarmount_compositing::{directory_weak_digest, BaseExcludes, OverlayMeta};

#[path = "support/http_tar.rs"]
mod http_tar;

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
        self.run_env(args, &[])
    }
    fn run_env(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.env("HOME", self.root.path())
            .env("XDG_CACHE_HOME", self.path(".cache"))
            .args(args);
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.output().unwrap()
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Dir,
    Archive,
}

#[derive(Clone, Copy, Debug)]
enum Verb {
    Seal,
    Pack,
    Diff,
}

/// A base of the given kind, and an overlay over it. `seal` seals the overlay
/// first (pack and diff are exercised on sealed layers).
fn fixture(env: &Env, kind: Kind, seal: bool) -> (PathBuf, PathBuf) {
    let dir = env.path("basedir");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("x.txt"), b"base content\n").unwrap();
    fs::write(dir.join("y.txt"), b"other\n").unwrap();
    let base = match kind {
        Kind::Dir => dir,
        Kind::Archive => {
            let archive = env.path("base.tar");
            assert!(Command::new("tar")
                .args(["cf", s(&archive), "-C", s(&dir), "x.txt", "y.txt"])
                .status()
                .unwrap()
                .success());
            archive
        }
    };
    let overlay = env.path("overlay");
    env.ok(&[
        "--no-mount",
        "--index-file",
        ":memory:",
        "-w",
        s(&overlay),
        s(&base),
    ]);
    if seal {
        env.ok(&["overlay", "seal", s(&overlay)]);
    }
    (base, overlay)
}

/// Edit the base the way a user would: a directory gains bytes; an archive
/// keeps its size and gets a new mtime (the review's `tar rf` shape).
fn edit(base: &Path, kind: Kind) {
    match kind {
        Kind::Dir => {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(base.join("x.txt"))
                .unwrap();
            file.write_all(b"edit\n").unwrap();
        }
        Kind::Archive => {
            let old = fs::metadata(base).unwrap().modified().unwrap();
            let mut bytes = fs::read(base).unwrap();
            bytes[512] ^= 1;
            fs::write(base, &bytes).unwrap();
            fs::File::options()
                .write(true)
                .open(base)
                .unwrap()
                .set_modified(old + std::time::Duration::from_secs(10))
                .unwrap();
        }
    }
}

fn verb(env: &Env, v: Verb, overlay: &Path, base: &Path, extra: &[&str]) -> Output {
    let bundle = env.path("bundle.tar.zst");
    let mut args: Vec<&str> = match v {
        Verb::Seal => vec!["overlay", "seal", s(overlay), s(base)],
        Verb::Pack => vec!["overlay", "pack", s(overlay), s(&bundle), s(base)],
        Verb::Diff => vec!["diff", s(overlay), s(base), "--hash", "--json"],
    };
    args.extend_from_slice(extra);
    env.run(&args)
}

fn meta_of(overlay: &Path) -> OverlayMeta {
    OverlayMeta::read(overlay).unwrap().unwrap()
}

fn mtime_ns(path: &Path) -> String {
    let m = fs::metadata(path).unwrap();
    (i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec())).to_string()
}

fn weak_now(base: &Path) -> String {
    directory_weak_digest(base, &BaseExcludes::default()).unwrap()
}

const VERBS: [Verb; 3] = [Verb::Seal, Verb::Pack, Verb::Diff];

fn refused(out: &Output) {
    assert!(!out.status.success(), "must refuse: {}", text(out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force-base-mismatch"), "{err}");
    assert!(err.contains("recorded"), "{err}");
}

/// (a) + (b): an edited directory or archive base is refused by every verb,
/// and nothing is written (no seal, no bundle).
#[test]
fn regression_edited_base_is_refused_by_seal_pack_and_diff() {
    for kind in [Kind::Dir, Kind::Archive] {
        for v in VERBS {
            let env = Env::new();
            let (base, overlay) = fixture(&env, kind, !matches!(v, Verb::Seal));
            edit(&base, kind);
            let out = verb(&env, v, &overlay, &base, &[]);
            refused(&out);
            assert!(
                !env.path("bundle.tar.zst").exists(),
                "{kind:?} {v:?} wrote a bundle"
            );
            if matches!(v, Verb::Seal) {
                assert!(!meta_of(&overlay).layer_sealed(), "{kind:?} sealed anyway");
            }
        }
    }
}

/// (c): forced, the verbs succeed and record or report the base that was
/// actually used; `overlay verify` against that base passes after a forced seal.
#[test]
fn regression_forced_seal_records_actual_base_and_verifies() {
    for kind in [Kind::Dir, Kind::Archive] {
        let env = Env::new();
        let (base, overlay) = fixture(&env, kind, false);
        let old = meta_of(&overlay).base_digest().unwrap().to_owned();
        edit(&base, kind);
        let out = verb(
            &env,
            Verb::Seal,
            &overlay,
            &base,
            &["--force-base-mismatch"],
        );
        assert_eq!(out.status.code(), Some(0), "{kind:?}: {}", text(&out));
        let meta = meta_of(&overlay);
        assert!(meta.layer_sealed());
        assert!(meta.get("base_mismatch_forced_at").is_some());
        assert_ne!(
            meta.base_digest().unwrap(),
            old,
            "{kind:?} kept the stale identity"
        );
        match kind {
            Kind::Dir => assert_eq!(meta.get("base_weak_digest"), Some(weak_now(&base).as_str())),
            Kind::Archive => assert_eq!(meta.get("base_mtime_ns"), Some(mtime_ns(&base).as_str())),
        }
        // The stack digest follows the recorded base.
        assert_eq!(
            meta.stack_digest().unwrap(),
            ratarmount_compositing::stack_digest(meta.base_digest().unwrap(), &[])
        );
        let json = env.ok(&["overlay", "verify", s(&overlay), s(&base), "--json"]);
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(json["ok"], true, "{kind:?}: {json}");
        assert_ne!(json["base_ok"], false, "{kind:?}: {json}");
    }
}

#[test]
fn regression_forced_pack_records_actual_base_in_bundle() {
    for kind in [Kind::Dir, Kind::Archive] {
        let env = Env::new();
        let (base, overlay) = fixture(&env, kind, true);
        let old = meta_of(&overlay).base_digest().unwrap().to_owned();
        edit(&base, kind);
        let out = verb(
            &env,
            Verb::Pack,
            &overlay,
            &base,
            &["--force-base-mismatch"],
        );
        assert_eq!(out.status.code(), Some(0), "{kind:?}: {}", text(&out));
        // The sealed source layer is never modified.
        assert_eq!(meta_of(&overlay).base_digest().unwrap(), old);
        assert!(meta_of(&overlay).get("base_mismatch_forced_at").is_none());
        let restored = env.path("restored");
        env.ok(&[
            "overlay",
            "unpack",
            s(&env.path("bundle.tar.zst")),
            s(&restored),
        ]);
        let meta = meta_of(&restored);
        assert!(meta.get("base_mismatch_forced_at").is_some());
        assert_ne!(meta.base_digest().unwrap(), old);
        match kind {
            Kind::Dir => assert_eq!(meta.get("base_weak_digest"), Some(weak_now(&base).as_str())),
            Kind::Archive => assert_eq!(meta.get("base_mtime_ns"), Some(mtime_ns(&base).as_str())),
        }
        // The restored layer verifies against the base it was packed on.
        env.ok(&["overlay", "verify", s(&restored), s(&base)]);
    }
}

#[test]
fn regression_forced_diff_reports_the_base_actually_diffed() {
    for kind in [Kind::Dir, Kind::Archive] {
        let env = Env::new();
        let (base, overlay) = fixture(&env, kind, true);
        let old = meta_of(&overlay).base_digest().unwrap().to_owned();
        edit(&base, kind);
        let out = verb(
            &env,
            Verb::Diff,
            &overlay,
            &base,
            &["--force-base-mismatch"],
        );
        assert_eq!(out.status.code(), Some(0), "{kind:?}: {}", text(&out));
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(json["base_forced"], true, "{json}");
        assert_eq!(json["base_recorded"], old, "{json}");
        assert_ne!(
            json["base"],
            old.as_str(),
            "stale recorded base reported: {json}"
        );
        assert!(json["base"].is_string(), "{json}");
        if kind == Kind::Dir {
            assert_eq!(json["base"], weak_now(&base).as_str());
        }
    }
}

/// (d): an unchanged base succeeds, reports the confirmed identity, and no
/// base file is opened for hashing (the sealed overlay already knows its digest).
#[test]
fn regression_unchanged_base_passes_without_hashing() {
    for kind in [Kind::Dir, Kind::Archive] {
        for v in VERBS {
            // Sealing an archive overlay resolves its pending digest by hashing,
            // which is existing behaviour; only the sealed paths are zero-hash.
            if matches!((v, kind), (Verb::Seal, Kind::Archive)) {
                continue;
            }
            let env = Env::new();
            let (base, overlay) = fixture(&env, kind, !matches!(v, Verb::Seal));
            let recorded = meta_of(&overlay).base_digest().unwrap().to_owned();
            let log = env.path("hash.log");
            let bundle = env.path("bundle.tar.zst");
            let args: Vec<&str> = match v {
                Verb::Seal => vec!["overlay", "seal", s(&overlay), s(&base)],
                Verb::Pack => vec!["overlay", "pack", s(&overlay), s(&bundle), s(&base)],
                Verb::Diff => vec!["diff", s(&overlay), s(&base), "--hash", "--json"],
            };
            let out = env.run_env(&args, &[("RATARMOUNT_TEST_HASH_LOG", &log)]);
            assert_eq!(out.status.code(), Some(0), "{kind:?} {v:?}: {}", text(&out));
            assert!(
                !log.exists() || fs::read_to_string(&log).unwrap().is_empty(),
                "{kind:?} {v:?} hashed a base: {}",
                fs::read_to_string(&log).unwrap_or_default()
            );
            if matches!(v, Verb::Diff) {
                let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(json["base"], recorded.as_str(), "{json}");
                assert!(json["base_forced"].is_null() || json["base_forced"] == false);
            }
        }
    }
}

/// A strong directory overlay edited after creation is refused with a hint for
/// `--base-digest`; the supplied digest of the edited tree confirms identity.
#[test]
fn regression_strong_directory_base_confirmed_by_supplied_digest() {
    let env = Env::new();
    let base = env.path("basedir");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("x.txt"), b"base\n").unwrap();
    let digest = env
        .ok(&["overlay", "digest-base", s(&base)])
        .trim()
        .to_owned();
    let overlay = env.path("overlay");
    env.ok(&[
        "--no-mount",
        "-w",
        s(&overlay),
        "--base-digest",
        &digest,
        s(&base),
    ]);
    // A byte-identical copy at another path: the walk can differ (mtimes), the
    // supplied strong digest confirms it without reading any file.
    let copy = env.path("copy");
    assert!(Command::new("cp")
        .args(["-r", s(&base), s(&copy)])
        .status()
        .unwrap()
        .success());
    let out = env.run(&["diff", s(&overlay), s(&copy), "--hash", "--json"]);
    refused(&out);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--base-digest"),
        "{}",
        text(&out)
    );
    let out = env.run(&[
        "diff",
        s(&overlay),
        s(&copy),
        "--hash",
        "--json",
        "--base-digest",
        &digest,
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["base"], digest.as_str());
}

/// A sealed overlay that changes `x.txt` from the base's bytes to `new`.
fn non_empty_sealed(env: &Env) -> (PathBuf, PathBuf) {
    let (base, overlay) = fixture(env, Kind::Dir, false);
    fs::write(overlay.join("x.txt"), b"new\n").unwrap();
    env.ok(&["overlay", "seal", s(&overlay)]);
    (base, overlay)
}

/// Regression (R4-S1): a forced pack kept the sealed layer digest while
/// replacing the base rows, so a non-empty layer whose change set differs on
/// the base as it is now (`x` A->B, base `x` became B) produced a bundle that
/// failed its own unpack / verify. It now refuses that case.
#[test]
fn regression_forced_pack_refuses_when_change_set_differs_on_actual_base() {
    let env = Env::new();
    let (base, overlay) = non_empty_sealed(&env);
    fs::write(base.join("x.txt"), b"new\n").unwrap();
    let out = verb(
        &env,
        Verb::Pack,
        &overlay,
        &base,
        &["--force-base-mismatch"],
    );
    assert!(!out.status.success(), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("change set") && err.contains("unseal"),
        "{err}"
    );
    assert!(!env.path("bundle.tar.zst").exists());
}

/// A forced pack of a non-empty layer whose change set is unchanged on the
/// edited base still bundles, and the bundle unpacks and verifies on that base.
#[test]
fn regression_forced_pack_non_empty_unrelated_edit_round_trips() {
    let env = Env::new();
    let (base, overlay) = non_empty_sealed(&env);
    fs::write(base.join("y.txt"), b"other edited\n").unwrap();
    let out = verb(
        &env,
        Verb::Pack,
        &overlay,
        &base,
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let restored = env.path("restored");
    env.ok(&[
        "overlay",
        "unpack",
        s(&env.path("bundle.tar.zst")),
        s(&restored),
    ]);
    env.ok(&["overlay", "verify", s(&restored), s(&base)]);
}

fn tar_of(env: &Env, dir: &Path, name: &str) -> PathBuf {
    let archive = env.path(name);
    assert!(Command::new("tar")
        .args(["cf", s(&archive), "-C", s(dir), "x.txt", "y.txt"])
        .status()
        .unwrap()
        .success());
    archive
}

/// Regression (R4-S7): a forced seal onto a base of another kind kept the old
/// kind's comparison rows (A.tar's size/mtime stamp, the old directory's weak
/// walk), so `--lower O <old base>` later matched the stale stamp and accepted
/// the wrong base.
#[test]
fn regression_forced_seal_clears_obsolete_identity_rows() {
    // archive -> directory
    let env = Env::new();
    let (archive, overlay) = fixture(&env, Kind::Archive, false);
    let other = env.path("otherdir");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("x.txt"), b"different\n").unwrap();
    let out = verb(
        &env,
        Verb::Seal,
        &overlay,
        &other,
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let meta = meta_of(&overlay);
    for key in ["base_size", "base_mtime_ns", "base_local_path"] {
        assert!(
            meta.get(key).is_none(),
            "{key} survived: {:?}",
            meta.get(key)
        );
    }
    assert!(meta.get("base_weak_digest").is_some());
    let out = env.run(&["--no-mount", "--lower", s(&overlay), s(&archive)]);
    assert!(
        !out.status.success(),
        "old archive accepted: {}",
        text(&out)
    );
    let out = env.run(&["--no-mount", "--lower", s(&overlay), s(&other)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // directory -> archive
    let env = Env::new();
    let (dir, overlay) = fixture(&env, Kind::Dir, false);
    let archive = tar_of(&env, &dir, "other.tar");
    let out = verb(
        &env,
        Verb::Seal,
        &overlay,
        &archive,
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let meta = meta_of(&overlay);
    assert!(meta.get("base_weak_digest").is_none());
    assert!(meta.get("base_mtime_ns").is_some());
    let out = env.run(&["--no-mount", "--lower", s(&overlay), s(&dir)]);
    assert!(
        !out.status.success(),
        "old directory accepted: {}",
        text(&out)
    );
}

/// Same for a forced pack: the bundle's metadata must not keep the old rows.
#[test]
fn regression_forced_pack_clears_obsolete_identity_rows() {
    let env = Env::new();
    let (archive, overlay) = fixture(&env, Kind::Archive, true);
    let other = env.path("otherdir");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("x.txt"), b"base content\n").unwrap();
    let out = verb(
        &env,
        Verb::Pack,
        &overlay,
        &other,
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let restored = env.path("restored");
    env.ok(&[
        "overlay",
        "unpack",
        s(&env.path("bundle.tar.zst")),
        s(&restored),
    ]);
    let meta = meta_of(&restored);
    for key in ["base_size", "base_mtime_ns", "base_local_path"] {
        assert!(meta.get(key).is_none(), "{key} survived");
    }
    let out = env.run(&["--no-mount", "--lower", s(&restored), s(&archive)]);
    assert!(
        !out.status.success(),
        "old archive accepted: {}",
        text(&out)
    );
}

/// Regression (R4-S11): a forced seal opened the overlay database with
/// `SQLITE_OPEN_NOFOLLOW` without resolving the parent, so an overlay reached
/// through a symlinked directory (`/link/overlay`, macOS `/tmp/...`) failed
/// with `SQLITE_CANTOPEN_SYMLINK`.
#[test]
fn regression_forced_seal_under_symlinked_parent() {
    let env = Env::new();
    let (base, overlay) = fixture(&env, Kind::Dir, false);
    edit(&base, Kind::Dir);
    let link = env.path("link");
    std::os::unix::fs::symlink(env.path(""), &link).unwrap();
    let through = link.join("overlay");
    let out = verb(
        &env,
        Verb::Seal,
        &through,
        &base,
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(meta_of(&overlay).layer_sealed());
    assert!(meta_of(&overlay).get("base_mismatch_forced_at").is_some());
}

/// A one-commit repository; returns `git://<repo>#<commit>` and the tree id.
fn git_base(env: &Env, name: &str) -> (String, String) {
    let dir = env.path(name);
    let repo = git2::Repository::init(&dir).unwrap();
    let sig = git2::Signature::new("t", "t@t", &git2::Time::new(0, 0)).unwrap();
    let blob = repo.blob(b"git content\n").unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder.insert("a.txt", blob, 0o100644).unwrap();
    let tree_id = builder.write().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let commit = repo
        .commit(Some("HEAD"), &sig, &sig, "c", &tree, &[])
        .unwrap();
    (
        format!("git://{}#{commit}", dir.display()),
        tree_id.to_string(),
    )
}

/// Regression (R4-S12): the Git tree was resolved only when the overlay had
/// recorded a Git base, so an overlay made over a directory sealed, packed and
/// diffed against `git:///repo#rev` found no mismatch (seal kept the
/// directory's identity, `--force-base-mismatch` did nothing). A kind change is
/// a mismatch; forced, the Git tree is recorded and the directory rows go.
#[test]
fn regression_directory_overlay_against_git_base_is_refused_then_forced() {
    for v in VERBS {
        let env = Env::new();
        let (_dir, overlay) = fixture(&env, Kind::Dir, !matches!(v, Verb::Seal));
        let (url, tree) = git_base(&env, "repo");
        let out = verb(&env, v, &overlay, Path::new(&url), &[]);
        refused(&out);
        assert!(!env.path("bundle.tar.zst").exists(), "{v:?} wrote a bundle");
        if matches!(v, Verb::Seal) {
            assert!(!meta_of(&overlay).layer_sealed());
            let out = verb(
                &env,
                v,
                &overlay,
                Path::new(&url),
                &["--force-base-mismatch"],
            );
            assert_eq!(out.status.code(), Some(0), "{}", text(&out));
            let meta = meta_of(&overlay);
            assert_eq!(meta.get("base_git_tree"), Some(tree.as_str()));
            assert_eq!(
                meta.base_digest(),
                Some(format!("git-tree:{tree}").as_str())
            );
            assert!(meta.get("base_weak_digest").is_none());
        }
    }
    // `--lower` mount path.
    let env = Env::new();
    let (_dir, overlay) = fixture(&env, Kind::Dir, true);
    let (url, _) = git_base(&env, "repo");
    let out = env.run(&["--no-mount", "--lower", s(&overlay), &url]);
    assert!(!out.status.success(), "git accepted: {}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--force-stack-mismatch"),
        "{}",
        text(&out)
    );
}

/// The reverse: a Git-recorded overlay against a directory is refused.
#[test]
fn regression_git_overlay_against_directory_base_is_refused() {
    for v in VERBS {
        let env = Env::new();
        let (url, _) = git_base(&env, "repo");
        let overlay = env.path("overlay");
        env.ok(&["--no-mount", "-w", s(&overlay), &url]);
        if !matches!(v, Verb::Seal) {
            env.ok(&["overlay", "seal", s(&overlay)]);
        }
        let dir = env.path("plain");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"git content\n").unwrap();
        refused(&verb(&env, v, &overlay, &dir, &[]));
    }
    let env = Env::new();
    let (url, _) = git_base(&env, "repo");
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), &url]);
    env.ok(&["overlay", "seal", s(&overlay)]);
    let dir = env.path("plain");
    fs::create_dir(&dir).unwrap();
    let out = env.run(&["--no-mount", "--lower", s(&overlay), s(&dir)]);
    assert!(!out.status.success(), "dir accepted: {}", text(&out));
}

/// Regression (R4-S12): an archive-recorded overlay against `git:///repo#rev`
/// is a base switch, refused by seal, pack and diff.
#[test]
fn regression_archive_overlay_against_git_base_is_refused() {
    for v in VERBS {
        let env = Env::new();
        let (_archive, overlay) = fixture(&env, Kind::Archive, !matches!(v, Verb::Seal));
        let (url, _) = git_base(&env, "repo");
        refused(&verb(&env, v, &overlay, Path::new(&url), &[]));
        assert!(!env.path("bundle.tar.zst").exists(), "{v:?} wrote a bundle");
        if matches!(v, Verb::Seal) {
            assert!(!meta_of(&overlay).layer_sealed());
        }
    }
}

/// Regression (R4-S12): a Git-recorded overlay against an archive is refused
/// by seal, pack and diff.
#[test]
fn regression_git_overlay_against_archive_base_is_refused() {
    for v in VERBS {
        let env = Env::new();
        let (url, _) = git_base(&env, "repo");
        let overlay = env.path("overlay");
        env.ok(&["--no-mount", "-w", s(&overlay), &url]);
        if !matches!(v, Verb::Seal) {
            env.ok(&["overlay", "seal", s(&overlay)]);
        }
        let dir = env.path("plain");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"git content\n").unwrap();
        let archive = env.path("plain.tar");
        assert!(Command::new("tar")
            .args(["cf", s(&archive), "-C", s(&dir), "a.txt"])
            .status()
            .unwrap()
            .success());
        refused(&verb(&env, v, &overlay, &archive, &[]));
        assert!(!env.path("bundle.tar.zst").exists(), "{v:?} wrote a bundle");
    }
}

const REMOTE_STRONG: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Regression (R5-1, round-4 skeptic G1): a remote-recorded overlay against a
/// `git://` base (and the reverse) matched nothing locally, so seal, pack and
/// diff found no mismatch. One rule: any change of base kind is refused unless
/// `--force-base-mismatch`.
#[test]
fn regression_git_and_remote_kind_switch_is_refused_by_every_verb() {
    let stub = http_tar::serve_tar_stub();
    let url = format!("{stub}/base.tar");
    for v in VERBS {
        // remote -> Git
        let env = Env::new();
        let overlay = env.path("overlay");
        env.ok(&[
            "--no-mount",
            "--index-file",
            ":memory:",
            "-w",
            s(&overlay),
            "--base-digest",
            REMOTE_STRONG,
            &url,
        ]);
        if !matches!(v, Verb::Seal) {
            env.ok(&["overlay", "seal", s(&overlay)]);
        }
        let (git, _) = git_base(&env, "repo");
        refused(&verb(&env, v, &overlay, Path::new(&git), &[]));
        assert!(!env.path("bundle.tar.zst").exists(), "{v:?} wrote a bundle");
        if matches!(v, Verb::Seal) {
            assert!(!meta_of(&overlay).layer_sealed());
        }
        // Git -> remote
        let env = Env::new();
        let (git, _) = git_base(&env, "repo");
        let overlay = env.path("overlay");
        env.ok(&["--no-mount", "-w", s(&overlay), &git]);
        if !matches!(v, Verb::Seal) {
            env.ok(&["overlay", "seal", s(&overlay)]);
        }
        refused(&verb(&env, v, &overlay, Path::new(&url), &[]));
        assert!(!env.path("bundle.tar.zst").exists(), "{v:?} wrote a bundle");
        if matches!(v, Verb::Seal) {
            assert!(!meta_of(&overlay).layer_sealed());
        }
    }
}
