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
        // Nothing supplied: the forced base drops to kind-only (`none`) with no
        // weak digest and no stamp. With the digest of the base as it is now
        // supplied, it is recorded strong with the measured rows.
        for supplied in [false, true] {
            let env = Env::new();
            let (base, overlay) = fixture(&env, kind, false);
            let old = meta_of(&overlay).base_digest().unwrap().to_owned();
            edit(&base, kind);
            let digest = env.ok(&["overlay", "digest-base", s(&base)]);
            let digest = digest.trim().to_owned();
            let mut extra = vec!["--force-base-mismatch"];
            if supplied {
                extra.extend(["--base-digest", digest.as_str()]);
            }
            let out = verb(&env, Verb::Seal, &overlay, &base, &extra);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{kind:?} supplied={supplied}: {}",
                text(&out)
            );
            let meta = meta_of(&overlay);
            assert!(meta.layer_sealed());
            assert!(meta.get("base_mismatch_forced_at").is_some());
            assert_ne!(
                meta.base_digest().unwrap(),
                old,
                "{kind:?} kept the stale identity"
            );
            if supplied {
                assert_eq!(meta.base_digest_kind(), Some("strong"));
                assert_eq!(meta.base_digest(), Some(digest.as_str()));
                assert_eq!(meta.get("base_digest_source"), Some("supplied"));
                match kind {
                    Kind::Dir => {
                        assert_eq!(meta.get("base_weak_digest"), Some(weak_now(&base).as_str()))
                    }
                    Kind::Archive => {
                        assert_eq!(meta.get("base_mtime_ns"), Some(mtime_ns(&base).as_str()))
                    }
                }
            } else {
                assert_eq!(meta.base_digest_kind(), Some("none"), "{kind:?}");
                assert_eq!(meta.base_digest(), Some("none"));
                for key in [
                    "base_weak_digest",
                    "base_size",
                    "base_mtime_ns",
                    "base_digest_source",
                ] {
                    assert!(meta.get(key).is_none(), "{kind:?}: {key} recorded");
                }
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
}

#[test]
fn regression_forced_pack_records_actual_base_in_bundle() {
    for kind in [Kind::Dir, Kind::Archive] {
        for supplied in [false, true] {
            let env = Env::new();
            let (base, overlay) = fixture(&env, kind, true);
            let old = meta_of(&overlay).base_digest().unwrap().to_owned();
            edit(&base, kind);
            let digest = env.ok(&["overlay", "digest-base", s(&base)]);
            let digest = digest.trim().to_owned();
            let mut extra = vec!["--force-base-mismatch"];
            if supplied {
                extra.extend(["--base-digest", digest.as_str()]);
            }
            let out = verb(&env, Verb::Pack, &overlay, &base, &extra);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{kind:?} supplied={supplied}: {}",
                text(&out)
            );
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
            if supplied {
                assert_eq!(meta.base_digest(), Some(digest.as_str()));
                match kind {
                    Kind::Dir => {
                        assert_eq!(meta.get("base_weak_digest"), Some(weak_now(&base).as_str()))
                    }
                    Kind::Archive => {
                        assert_eq!(meta.get("base_mtime_ns"), Some(mtime_ns(&base).as_str()))
                    }
                }
            } else {
                assert_eq!(meta.base_digest_kind(), Some("none"), "{kind:?}");
                assert!(meta.get("base_weak_digest").is_none());
                assert!(meta.get("base_mtime_ns").is_none());
            }
            // The restored layer verifies against the base it was packed on.
            env.ok(&["overlay", "verify", s(&restored), s(&base)]);
        }
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
        // Nothing supplied: the base actually diffed is kind-only.
        assert_eq!(json["base"], "none", "{json}");
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
    assert!(meta.get("base_weak_digest").is_none(), "kind-only: no walk");
    assert_eq!(meta.get("base_kind"), Some("directory"));
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
    assert!(meta.get("base_mtime_ns").is_none(), "kind-only: no stamp");
    assert_eq!(meta.get("base_kind"), Some("archive"));
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

/// `meta.json` of a packed bundle (`.tar.zst`).
fn bundle_meta_json(bundle: &Path) -> serde_json::Value {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(fs::File::open(bundle).unwrap()).unwrap();
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().ends_with("meta.json") {
            let mut text = String::new();
            entry.read_to_string(&mut text).unwrap();
            return serde_json::from_str(&text).unwrap();
        }
    }
    panic!("no meta.json in {bundle:?}");
}

const STALE_ROWS: [&str; 4] = [
    "base_size",
    "base_mtime_ns",
    "base_local_path",
    "base_weak_digest",
];

/// The overlay's `(base_kind, base_digest, base_digest_kind)` for assertions.
fn identity_of(meta: &OverlayMeta) -> (String, String) {
    (
        meta.get("base_kind").unwrap_or("").to_owned(),
        meta.base_digest().unwrap_or("").to_owned(),
    )
}

/// Review nit (R5-4): a forced pack across kinds records the ACTUAL base in
/// both the bundle's `meta.json` and the packed database rows, and the stale
/// rows of the old kind are gone from both.
#[test]
fn regression_forced_pack_across_kinds_records_actual_base_in_bundle_and_db() {
    // archive -> Git, then Git -> directory.
    for case in ["archive_to_git", "git_to_dir"] {
        let env = Env::new();
        let (url, tree) = git_base(&env, "repo");
        let dir = env.path("plain");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"git content\n").unwrap();
        let (overlay, actual, want_kind, want_digest) = if case == "archive_to_git" {
            let (_archive, overlay) = fixture(&env, Kind::Archive, true);
            let want = format!("git-tree:{tree}");
            (overlay, PathBuf::from(&url), "git", want)
        } else {
            let overlay = env.path("overlay");
            env.ok(&["--no-mount", "-w", s(&overlay), &url]);
            env.ok(&["overlay", "seal", s(&overlay)]);
            // A directory with nothing supplied is kind-only.
            (overlay, dir.clone(), "directory", "none".to_owned())
        };
        let old = meta_of(&overlay);
        let out = verb(
            &env,
            Verb::Pack,
            &overlay,
            &actual,
            &["--force-base-mismatch"],
        );
        assert_eq!(out.status.code(), Some(0), "{case}: {}", text(&out));
        // The sealed source layer is not modified.
        assert_eq!(identity_of(&meta_of(&overlay)), identity_of(&old), "{case}");
        let bundle = env.path("bundle.tar.zst");
        let json = bundle_meta_json(&bundle);
        assert_eq!(json["base_kind"], want_kind, "{case}: {json}");
        assert_eq!(json["base_digest"], want_digest.as_str(), "{case}: {json}");
        assert!(
            json["base_mismatch_forced_at"].is_string(),
            "{case}: {json}"
        );
        let restored = env.path("restored");
        env.ok(&["overlay", "unpack", s(&bundle), s(&restored)]);
        let meta = meta_of(&restored);
        assert_eq!(
            identity_of(&meta),
            (want_kind.to_owned(), want_digest.clone()),
            "{case}"
        );
        let stale: &[&str] = if case == "archive_to_git" {
            &[
                "base_size",
                "base_mtime_ns",
                "base_local_path",
                "base_weak_digest",
            ]
        } else {
            &[
                "base_git_tree",
                "base_size",
                "base_mtime_ns",
                "base_local_path",
            ]
        };
        for key in stale {
            assert!(
                json.get(*key).is_none(),
                "{case}: bundle meta.json kept {key}"
            );
            assert!(meta.get(key).is_none(), "{case}: packed DB kept {key}");
        }
        if case == "archive_to_git" {
            assert_eq!(json["base_git_tree"], tree.as_str(), "{json}");
            assert_eq!(meta.get("base_git_tree"), Some(tree.as_str()));
        } else {
            assert!(meta.get("base_weak_digest").is_none());
            assert_eq!(meta.base_digest_kind(), Some("none"));
        }
    }
}

/// Review nit (R5-4): a forced diff reports the base actually diffed
/// (`base`, `base_forced`, `base_identity: "forced"`, `base_recorded`) when the
/// kind changed, not only when the same kind was edited.
#[test]
fn regression_forced_diff_across_kinds_reports_actual_base() {
    let env = Env::new();
    let (url, tree) = git_base(&env, "repo");
    let (_archive, overlay) = fixture(&env, Kind::Archive, true);
    let old = meta_of(&overlay).base_digest().unwrap().to_owned();
    let out = verb(
        &env,
        Verb::Diff,
        &overlay,
        Path::new(&url),
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["base_forced"], true, "{json}");
    assert_eq!(json["base_identity"], "forced", "{json}");
    assert_eq!(json["base_recorded"], old.as_str(), "{json}");
    assert_eq!(json["base"], format!("git-tree:{tree}").as_str(), "{json}");

    // Git -> directory.
    let env = Env::new();
    let (git, _) = git_base(&env, "repo");
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), &git]);
    env.ok(&["overlay", "seal", s(&overlay)]);
    let old = meta_of(&overlay).base_digest().unwrap().to_owned();
    let dir = env.path("plain");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("a.txt"), b"git content\n").unwrap();
    let out = verb(&env, Verb::Diff, &overlay, &dir, &["--force-base-mismatch"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["base_forced"], true, "{json}");
    assert_eq!(json["base_identity"], "forced", "{json}");
    assert_eq!(json["base_recorded"], old.as_str(), "{json}");
    assert_eq!(json["base"], "none", "{json}");
}

/// Review nit (R5-4): forced Git -> directory and forced archive -> Git seals
/// keep none of the old kind's rows, and `--lower` then accepts only the new
/// base.
#[test]
fn regression_forced_seal_git_to_dir_and_archive_to_git_clear_stale_rows() {
    // Git -> directory.
    let env = Env::new();
    let (git, _) = git_base(&env, "repo");
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), &git]);
    let dir = env.path("plain");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("a.txt"), b"git content\n").unwrap();
    let out = verb(&env, Verb::Seal, &overlay, &dir, &["--force-base-mismatch"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let meta = meta_of(&overlay);
    assert_eq!(meta.get("base_kind"), Some("directory"));
    assert!(meta.get("base_git_tree").is_none(), "git tree survived");
    assert_eq!(meta.base_digest_kind(), Some("none"));
    assert!(meta.get("base_weak_digest").is_none());
    let out = env.run(&["--no-mount", "--lower", s(&overlay), &git]);
    assert!(
        !out.status.success(),
        "old git base accepted: {}",
        text(&out)
    );
    let out = env.run(&["--no-mount", "--lower", s(&overlay), s(&dir)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // archive -> Git.
    let env = Env::new();
    let (archive, overlay) = fixture(&env, Kind::Archive, false);
    assert!(meta_of(&overlay).get("base_size").is_some());
    let (git, tree) = git_base(&env, "repo");
    let out = verb(
        &env,
        Verb::Seal,
        &overlay,
        Path::new(&git),
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let meta = meta_of(&overlay);
    assert_eq!(meta.get("base_kind"), Some("git"));
    assert_eq!(meta.get("base_git_tree"), Some(tree.as_str()));
    for key in STALE_ROWS.into_iter().chain(["base_index_path"]) {
        assert!(
            meta.get(key).is_none(),
            "{key} survived: {:?}",
            meta.get(key)
        );
    }
    let out = env.run(&["--no-mount", "--lower", s(&overlay), s(&archive)]);
    assert!(
        !out.status.success(),
        "old archive accepted: {}",
        text(&out)
    );
    let out = env.run(&["--no-mount", "--lower", s(&overlay), &git]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

/// A tar of the given members, built the same way for every caller.
fn tar_with_members(env: &Env, name: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let dir = env.path(&format!("{name}.dir"));
    fs::create_dir(&dir).unwrap();
    let mut args = vec!["cf".to_owned(), s(&env.path(name)).to_owned()];
    args.extend(["-C".to_owned(), s(&dir).to_owned()]);
    for (file, bytes) in files {
        fs::write(dir.join(file), bytes).unwrap();
        args.push((*file).to_owned());
    }
    assert!(Command::new("tar").args(&args).status().unwrap().success());
    env.path(name)
}

/// The member listing of a bundle's `manifest.jsonl`, whole.
fn bundle_manifest(bundle: &Path) -> String {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(fs::File::open(bundle).unwrap()).unwrap();
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().ends_with("manifest.jsonl") {
            let mut text = String::new();
            entry.read_to_string(&mut text).unwrap();
            return text;
        }
    }
    panic!("no manifest.jsonl in {bundle:?}");
}

/// A sealed `none` overlay over `base.tar` whose layer modifies `x.txt`.
fn sealed_none_overlay(env: &Env) -> (PathBuf, PathBuf) {
    let (base, _) = fixture(env, Kind::Archive, false);
    fs::remove_dir_all(env.path("overlay")).unwrap();
    let overlay = env.path("overlay");
    env.ok(&[
        "--no-mount",
        "--index-file",
        ":memory:",
        "-w",
        s(&overlay),
        "--base-digest",
        "none",
        s(&base),
    ]);
    fs::write(overlay.join("x.txt"), b"new\n").unwrap();
    env.ok(&["overlay", "seal", s(&overlay)]);
    (base, overlay)
}

/// Regression (R6-H4, B4; supersedes R6-G1's accepted `none` pack): a `none`
/// pack against another archive was ACCEPTED without any content confirmation
/// and exported `manifest.jsonl` measured against that archive (`/x.txt` Added)
/// next to A's seal (Modified) and A's rows. It is refused without
/// `--force-base-mismatch`, names the flag and writes no bundle. A forced pack
/// re-checks the seal against the base it is given: a byte-identical copy
/// packs and its manifest agrees; an archive that makes the layer an add is
/// refused even forced, because it is not the base the layer was sealed on.
#[test]
fn regression_none_pack_against_other_archive_needs_force_and_agrees() {
    let env = Env::new();
    let (base, overlay) = sealed_none_overlay(&env);
    let recorded = meta_of(&overlay);
    let bundle = env.path("bundle.tar.zst");
    // B has no x.txt: the layer would be an add over it.
    let other = tar_with_members(&env, "other.tar", &[("z.txt", b"z\n")]);
    let out = verb(&env, Verb::Pack, &overlay, &other, &[]);
    refused(&out);
    assert!(!bundle.exists(), "wrote a bundle");
    let out = verb(
        &env,
        Verb::Pack,
        &overlay,
        &other,
        &["--force-base-mismatch"],
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        !bundle.exists(),
        "wrote a bundle for a different change set"
    );
    // A byte-identical copy at another path: refused unforced (nothing
    // confirms it), packs forced, and the manifest agrees with the seal.
    let copy = env.path("copy.tar");
    fs::copy(&base, &copy).unwrap();
    let out = verb(&env, Verb::Pack, &overlay, &copy, &[]);
    refused(&out);
    assert!(!bundle.exists(), "wrote a bundle");
    let out = verb(
        &env,
        Verb::Pack,
        &overlay,
        &copy,
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let manifest = bundle_manifest(&bundle);
    assert!(
        manifest.contains("x.txt") && !manifest.contains("\"added\""),
        "{manifest}"
    );
    // R6-J6 (audit C5): the forced pack measured the manifest against the copy,
    // so the bundle must describe the copy, not the place it was sealed on.
    let copy_location = format!("local:{}", copy.canonicalize().unwrap().display());
    assert_eq!(
        bundle_meta_json(&bundle)["base_location"].as_str(),
        Some(copy_location.as_str()),
        "the bundle still names the old base"
    );
    let restored = env.path("restored");
    env.ok(&["overlay", "unpack", s(&bundle), s(&restored)]);
    let unpacked = meta_of(&restored);
    assert_eq!(unpacked.get("base_location"), Some(copy_location.as_str()));
    assert_eq!(unpacked.get("base_url"), Some(s(&copy)));
    env.ok(&["overlay", "verify", s(&restored), s(&copy)]);
    // The sealed source layer keeps its own record.
    assert_eq!(
        meta_of(&overlay).get("base_location"),
        recorded.get("base_location")
    );
}

/// Regression (R6-H4, B4 carve-out): a copy confirmed by the recorded STRONG
/// digest (supplied) packs without force, keeps the recorded rows, and its
/// manifest agrees with the seal.
#[test]
fn regression_strong_confirmed_copy_packs_and_manifest_agrees() {
    let env = Env::new();
    let (base, _) = fixture(&env, Kind::Archive, false);
    fs::remove_dir_all(env.path("overlay")).unwrap();
    let digest = env
        .ok(&["overlay", "digest-base", s(&base)])
        .trim()
        .to_owned();
    let overlay = env.path("overlay");
    env.ok(&[
        "--no-mount",
        "--index-file",
        ":memory:",
        "-w",
        s(&overlay),
        "--base-digest",
        &digest,
        s(&base),
    ]);
    fs::write(overlay.join("x.txt"), b"new\n").unwrap();
    env.ok(&["overlay", "seal", s(&overlay)]);
    let recorded = meta_of(&overlay);
    let copy = env.path("copy.tar");
    fs::copy(&base, &copy).unwrap();
    // Without the digest nothing confirms the copy.
    let out = verb(&env, Verb::Pack, &overlay, &copy, &[]);
    refused(&out);
    let out = verb(
        &env,
        Verb::Pack,
        &overlay,
        &copy,
        &["--base-digest", &digest],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let bundle = env.path("bundle.tar.zst");
    let manifest = bundle_manifest(&bundle);
    assert!(
        manifest.contains("x.txt") && !manifest.contains("\"added\""),
        "{manifest}"
    );
    let restored = env.path("restored");
    env.ok(&["overlay", "unpack", s(&bundle), s(&restored)]);
    let meta = meta_of(&restored);
    for key in ["base_location", "base_digest", "base_size", "base_mtime_ns"] {
        assert_eq!(meta.get(key), recorded.get(key), "{key}");
    }
    env.ok(&["overlay", "verify", s(&restored), s(&copy)]);
}

/// A repository whose branches `main` and `stable` both point at one commit.
fn repo_with_two_refs(env: &Env, name: &str, body: &[u8]) -> PathBuf {
    let dir = env.path(name);
    let repo = git2::Repository::init(&dir).unwrap();
    let sig = git2::Signature::new("t", "t@t", &git2::Time::new(0, 0)).unwrap();
    let blob = repo.blob(body).unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder.insert("a.txt", blob, 0o100644).unwrap();
    let tree = repo.find_tree(builder.write().unwrap()).unwrap();
    let id = repo
        .commit(Some("HEAD"), &sig, &sig, "c", &tree, &[])
        .unwrap();
    let commit = repo.find_commit(id).unwrap();
    for branch in ["main", "stable"] {
        repo.branch(branch, &commit, true).unwrap();
    }
    dir
}

/// Regression (R6-G7, #5): a selector-only change (`repo@stable` over a record
/// of `repo@main`, same repository and tree) kept `main` in the rows. An
/// accepted seal writes the new selector; a forced pack against another
/// repository's `@stable` records that selector in the bundle and the packed
/// database.
#[test]
fn regression_repo_stable_over_main_updates_base_url_in_seal_and_forced_pack() {
    let env = Env::new();
    let repo = repo_with_two_refs(&env, "repo", b"git content\n");
    let main = format!("{}@main", repo.display());
    let stable = format!("{}@stable", repo.display());
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), &main]);
    assert!(meta_of(&overlay).base_url().unwrap().ends_with("@main"));
    env.ok(&["overlay", "seal", s(&overlay), &stable]);
    let sealed = meta_of(&overlay);
    assert_eq!(sealed.base_url(), Some(stable.as_str()), "accepted seal");
    // An ACCEPTED pack leaves the rows as recorded (the sealed record decides;
    // only a forced relocation rewrites them, R6-G1).
    let accepted_overlay = env.path("accepted-overlay");
    env.ok(&["--no-mount", "-w", s(&accepted_overlay), &main]);
    env.ok(&["overlay", "seal", s(&accepted_overlay)]);
    let accepted = env.path("accepted.tar.zst");
    let out = env.run(&[
        "overlay",
        "pack",
        s(&accepted_overlay),
        s(&accepted),
        &stable,
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        bundle_meta_json(&accepted)["base_url"],
        main.as_str(),
        "accepted pack leaves the recorded rows"
    );
    // A different repository (another tree), selector @stable: forced pack.
    let other = repo_with_two_refs(&env, "other", b"other content\n");
    let other_stable = format!("{}@stable", other.display());
    let bundle = env.path("bundle.tar.zst");
    let out = env.run(&[
        "overlay",
        "pack",
        s(&overlay),
        s(&bundle),
        &other_stable,
        "--force-base-mismatch",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let json = bundle_meta_json(&bundle);
    assert_eq!(json["base_url"], other_stable.as_str(), "{json}");
    let restored = env.path("restored");
    env.ok(&["overlay", "unpack", s(&bundle), s(&restored)]);
    assert_eq!(
        meta_of(&restored).base_url(),
        Some(other_stable.as_str()),
        "packed database"
    );
    // The sealed source layer keeps its own record.
    assert_eq!(meta_of(&overlay).base_url(), Some(stable.as_str()));
}

/// Regression (R6-G1, directory copy case; R6-H4 decision): packing a sealed
/// WEAK directory overlay against a copy of the base at another path matched
/// only the weak manifest. That is no content confirmation, so the pack is
/// refused without `--force-base-mismatch` (it used to be accepted and then
/// rewrote the rows and dropped `base_weak_digest`). Forced, the manifest is
/// re-checked against the seal and agrees for an identical copy.
#[test]
fn regression_accepted_pack_against_directory_copy_keeps_weak_digest() {
    let env = Env::new();
    let (base, overlay) = fixture(&env, Kind::Dir, true);
    let recorded = meta_of(&overlay);
    let copy = env.path("copy");
    assert!(Command::new("cp")
        .args(["-a", s(&base), s(&copy)])
        .status()
        .unwrap()
        .success());
    let out = verb(&env, Verb::Pack, &overlay, &copy, &[]);
    refused(&out);
    assert!(!env.path("bundle.tar.zst").exists(), "wrote a bundle");
    let out = verb(
        &env,
        Verb::Pack,
        &overlay,
        &copy,
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    // The sealed source layer keeps its own record.
    let after = meta_of(&overlay);
    for key in ["base_weak_digest", "base_url", "base_location", "base_kind"] {
        assert_eq!(after.get(key), recorded.get(key), "{key}");
    }
    // R6-J6 (audit C5): the bundle describes the copy it was measured on, with
    // a weak digest measured from it.
    let copy_location = format!("local:{}", copy.canonicalize().unwrap().display());
    let bundle = env.path("bundle.tar.zst");
    assert_eq!(
        bundle_meta_json(&bundle)["base_location"].as_str(),
        Some(copy_location.as_str()),
        "the bundle still names the old base"
    );
    let restored = env.path("restored");
    env.ok(&["overlay", "unpack", s(&bundle), s(&restored)]);
    let unpacked = meta_of(&restored);
    assert_eq!(unpacked.get("base_location"), Some(copy_location.as_str()));
    assert_eq!(
        unpacked.get("base_weak_digest"),
        Some(weak_now(&copy).as_str())
    );
}

/// Regression (R6-H3, B3): an accepted `overlay seal` against a metadata-
/// preserving copy of a directory base moved the recorded place and deleted
/// `base_weak_digest` without writing a replacement, so editing that copy
/// afterwards was accepted by every later gate (nothing left to compare). The
/// seal writes a weak digest measured from the copy; an edit of the copy is
/// refused by `diff` and `pack`.
#[test]
fn regression_accepted_seal_against_directory_copy_keeps_a_baseline() {
    let env = Env::new();
    let (base, overlay) = fixture(&env, Kind::Dir, false);
    let copy = env.path("copy");
    assert!(Command::new("cp")
        .args(["-a", s(&base), s(&copy)])
        .status()
        .unwrap()
        .success());
    let out = verb(&env, Verb::Seal, &overlay, &copy, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let meta = meta_of(&overlay);
    assert_eq!(
        meta.get("base_weak_digest"),
        Some(weak_now(&copy).as_str()),
        "the seal measured the copy"
    );
    edit(&copy, Kind::Dir);
    for v in [Verb::Diff, Verb::Pack] {
        let out = verb(&env, v, &overlay, &copy, &[]);
        refused(&out);
    }
}

/// Regression (R6-K2, r11 skeptic #2): `overlay seal` resolved a `pending` base
/// digest from the OLD recorded location before the accepted move was applied.
/// Rename A -> B and seal against B: A has vanished (hash failed), or A was
/// recreated with other bytes carrying the recorded size and mtime (the seal
/// hashed A and recorded A's digest for B). The digest is resolved from the
/// classified base, so it is B's.
#[cfg(unix)]
#[test]
fn regression_pending_seal_hashes_the_moved_base_not_the_old_place() {
    use sha2::{Digest, Sha256};
    for recreate_old in [false, true] {
        let env = Env::new();
        let (base, overlay) = fixture(&env, Kind::Archive, false);
        assert_eq!(
            meta_of(&overlay).base_digest_kind(),
            Some("pending"),
            "fixture must leave the digest pending"
        );
        let stamp = fs::metadata(&base).unwrap().modified().unwrap();
        let moved = env.path("moved.tar");
        fs::rename(&base, &moved).unwrap();
        if recreate_old {
            let mut bytes = fs::read(&moved).unwrap();
            bytes[512] ^= 1;
            fs::write(&base, &bytes).unwrap();
            fs::File::options()
                .write(true)
                .open(&base)
                .unwrap()
                .set_modified(stamp)
                .unwrap();
        }
        let out = verb(&env, Verb::Seal, &overlay, &moved, &[]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "recreate_old={recreate_old}: {}",
            text(&out)
        );
        let expected = format!("sha256:{:x}", Sha256::digest(fs::read(&moved).unwrap()));
        let meta = meta_of(&overlay);
        assert_eq!(meta.base_digest_kind(), Some("strong"));
        assert_eq!(
            meta.base_digest(),
            Some(expected.as_str()),
            "recreate_old={recreate_old}: the seal hashed the old place"
        );
    }
}

/// Regression (R6-K3, r11 skeptic #3): a forced `overlay pack` against
/// repository B holding the SAME tree as the recorded repository A wrote
/// relocation rows without `base_git_tree`, so the bundle kept
/// `base_digest_kind=git-tree` but no comparison row and a later changed tree
/// in B was accepted by `--lower`. The tree actually opened is written.
#[test]
fn regression_forced_pack_to_same_tree_repo_keeps_git_tree_row() {
    let env = Env::new();
    let (url_a, tree) = git_base(&env, "repo-a");
    let (url_b, tree_b) = git_base(&env, "repo-b");
    assert_eq!(tree, tree_b, "the fixture repositories share a tree");
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), &url_a]);
    env.ok(&["overlay", "seal", s(&overlay)]);
    let out = verb(
        &env,
        Verb::Pack,
        &overlay,
        Path::new(&url_b),
        &["--force-base-mismatch"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let bundle = env.path("bundle.tar.zst");
    let json = bundle_meta_json(&bundle);
    assert_eq!(json["base_git_tree"], tree.as_str(), "{json}");
    let restored = env.path("restored");
    env.ok(&["overlay", "unpack", s(&bundle), s(&restored)]);
    assert_eq!(
        meta_of(&restored).get("base_git_tree"),
        Some(tree.as_str()),
        "the unpacked database lost its comparison row"
    );
    // A tree change in B is refused.
    let repo = git2::Repository::open(env.path("repo-b")).unwrap();
    let sig = git2::Signature::new("t", "t@t", &git2::Time::new(1, 0)).unwrap();
    let blob = repo.blob(b"changed\n").unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder.insert("a.txt", blob, 0o100644).unwrap();
    let changed = repo.find_tree(builder.write().unwrap()).unwrap();
    let parent = repo.head().unwrap().peel_to_commit().unwrap();
    let commit = repo
        .commit(Some("HEAD"), &sig, &sig, "d", &changed, &[&parent])
        .unwrap();
    let url_changed = format!("git://{}#{commit}", env.path("repo-b").display());
    let out = env.run(&["--no-mount", "--lower", s(&restored), &url_changed]);
    assert!(
        !out.status.success(),
        "a changed tree was accepted: {}",
        text(&out)
    );
}
