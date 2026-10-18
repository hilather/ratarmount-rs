//! Regression (Keystone 5564615409, blocker 2): the `--lower` base check ignored
//! strong identity, so a bundle sealed against a strong digest was refused over
//! a byte-identical copy of its base even with a matching `--base-digest` (a
//! directory) or a matching digest already cached in the mounted archive's index.
//! The mount never hashes: it only compares what was supplied or already cached.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
    fn run(&self, args: &[&str], hash_log: Option<&Path>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.env("HOME", self.root.path())
            .env("XDG_CACHE_HOME", self.path(".cache"))
            .args(args);
        if let Some(log) = hash_log {
            cmd.env("RATARMOUNT_TEST_HASH_LOG", log);
        }
        cmd.output().unwrap()
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args, None);
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

fn copy_tree(from: &Path, to: &Path) {
    assert!(Command::new("cp")
        .args(["-r", s(from), s(to)])
        .status()
        .unwrap()
        .success());
}

/// A directory bundle sealed against a strong `--base-digest`, and a copy of
/// the base (new mtimes, so the weak walk differs).
fn dir_bundle(env: &Env) -> (PathBuf, PathBuf, String) {
    let base = env.path("dA");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("a.txt"), b"alpha\n").unwrap();
    let digest = env
        .ok(&["overlay", "digest-base", s(&base)])
        .trim()
        .to_owned();
    let overlay = env.path("L");
    env.ok(&[
        "--no-mount",
        "-w",
        s(&overlay),
        "--base-digest",
        &digest,
        s(&base),
    ]);
    env.ok(&["overlay", "seal", s(&overlay)]);
    let bundle = env.path("L.tar.zst");
    env.ok(&["overlay", "pack", s(&overlay), s(&bundle)]);
    let copy = env.path("dB");
    copy_tree(&base, &copy);
    (bundle, copy, digest)
}

#[test]
fn regression_lower_strong_directory_copy_needs_matching_base_digest() {
    let env = Env::new();
    let (bundle, copy, digest) = dir_bundle(&env);
    let mount = |extra: &[&str]| {
        let mut args = vec!["--no-mount", "--lower", s(&bundle)];
        args.extend_from_slice(extra);
        args.push(s(&copy));
        env.run(&args, None)
    };
    let out = mount(&["--base-digest", &digest]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    for extra in [
        &[][..],
        &["--base-digest", &format!("sha256:{}", "0".repeat(64))][..],
    ] {
        let out = mount(extra);
        assert!(!out.status.success(), "{extra:?}: {}", text(&out));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("could not be confirmed cheaply"), "{err}");
        assert!(err.contains("--base-digest"), "{err}");
        assert!(err.contains("--force-stack-mismatch"), "{err}");
    }
    // The last resort still works.
    let out = mount(&["--force-stack-mismatch"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

/// An archive bundle sealed against `based/base.tar`; the mounted
/// `elsewhere/base.tar` is a byte-identical copy (new mtime and inode). Its
/// index already caches the SHA-256 when it was sealed or mounted before.
#[test]
fn regression_lower_strong_archive_copy_accepted_by_cached_digest_without_hashing() {
    let env = Env::new();
    let src = env.path("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("a.txt"), b"alpha\n").unwrap();
    fs::create_dir(env.path("based")).unwrap();
    let based = env.path("based/base.tar");
    assert!(Command::new("tar")
        .args(["cf", s(&based), "-C", s(&src), "a.txt"])
        .status()
        .unwrap()
        .success());
    let cached = env.path("elsewhere");
    let uncached = env.path("uncached");
    for dir in [&cached, &uncached] {
        fs::create_dir(dir).unwrap();
        fs::copy(&based, dir.join("base.tar")).unwrap();
        // Distinct mtime from the original.
        let file = fs::File::options()
            .write(true)
            .open(dir.join("base.tar"))
            .unwrap();
        file.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(30))
            .unwrap();
    }
    let overlay = env.path("L");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&based)]);
    env.ok(&["overlay", "seal", s(&overlay)]);
    let bundle = env.path("L.tar.zst");
    env.ok(&["overlay", "pack", s(&overlay), s(&bundle)]);
    // Cache the digest in the copy's own index: build the index, then seal a
    // scratch overlay on it (sealing resolves and caches the digest).
    let copy = cached.join("base.tar");
    env.ok(&["--no-mount", s(&copy)]);
    let scratch = env.path("scratch");
    env.ok(&["--no-mount", "-w", s(&scratch), s(&copy)]);
    env.ok(&["overlay", "seal", s(&scratch)]);
    let log = env.path("hash.log");
    let out = env.run(&["--no-mount", "--lower", s(&bundle), s(&copy)], Some(&log));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        !log.exists() || fs::read_to_string(&log).unwrap().is_empty(),
        "the mount hashed: {}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    // A copy whose index holds no digest cannot be confirmed without hashing.
    let log = env.path("hash2.log");
    let out = env.run(
        &[
            "--no-mount",
            "--lower",
            s(&bundle),
            s(&uncached.join("base.tar")),
        ],
        Some(&log),
    );
    assert!(!out.status.success(), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("could not be confirmed cheaply"), "{err}");
    assert!(!log.exists() || fs::read_to_string(&log).unwrap().is_empty());
}

/// Regression (R4-S8): a read-only `--lower` mount resolved the Git tree id
/// only with `-w`, so the comparator got no tree and a lower sealed against
/// `git:///repo#A` was accepted on `git:///repo#B`.
#[test]
fn regression_lower_read_only_git_lower_compares_tree() {
    let env = Env::new();
    let repo_dir = env.path("repo");
    let repo = git2::Repository::init(&repo_dir).unwrap();
    let sig = git2::Signature::new("t", "t@t", &git2::Time::new(0, 0)).unwrap();
    let mut commits = Vec::new();
    let mut parent: Option<git2::Oid> = None;
    for content in [&b"one\n"[..], &b"two\n"[..]] {
        let blob = repo.blob(content).unwrap();
        let mut builder = repo.treebuilder(None).unwrap();
        builder.insert("a.txt", blob, 0o100644).unwrap();
        let tree = repo.find_tree(builder.write().unwrap()).unwrap();
        let parents: Vec<git2::Commit> = parent
            .map(|p| repo.find_commit(p).unwrap())
            .into_iter()
            .collect();
        let parents: Vec<&git2::Commit> = parents.iter().collect();
        let id = repo
            .commit(Some("HEAD"), &sig, &sig, "c", &tree, &parents)
            .unwrap();
        parent = Some(id);
        commits.push(id);
    }
    let url = |c: git2::Oid| format!("git://{}#{c}", repo_dir.display());
    let overlay = env.path("L");
    env.ok(&["--no-mount", "-w", s(&overlay), &url(commits[0])]);
    env.ok(&["overlay", "seal", s(&overlay)]);
    let out = env.run(
        &["--no-mount", "--lower", s(&overlay), &url(commits[1])],
        None,
    );
    assert!(!out.status.success(), "wrong tree accepted: {}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--force-stack-mismatch"),
        "{}",
        text(&out)
    );
    let out = env.run(
        &["--no-mount", "--lower", s(&overlay), &url(commits[0])],
        None,
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}
