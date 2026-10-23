//! R6-3: an overlay records the kind and place the factory ACTUALLY served,
//! and every reopen compares them. CLI-level, offline (`--no-mount`, no
//! FUSE), private HOME / XDG_CACHE_HOME per test.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ratarmount_compositing::OverlayMeta;

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
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.env("HOME", self.root.path())
            .env("XDG_CACHE_HOME", self.path(".cache"))
            .env_remove("RATARMOUNT_FORCE_GIT")
            .args(args);
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.output().unwrap()
    }
    fn create(
        &self,
        overlay: &Path,
        base_args: &[&str],
        extra: &[&str],
        env: &[(&str, &str)],
    ) -> Output {
        let mut args = vec!["--no-mount", "--index-file", ":memory:", "-w", s(overlay)];
        args.extend(extra);
        args.extend(base_args);
        self.run(&args, env)
    }
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn tar_of(env: &Env, name: &str, content: &str) -> PathBuf {
    let dir = env.path(&format!("{name}-src"));
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("f.txt"), content).unwrap();
    let archive = env.path(name);
    assert!(Command::new("tar")
        .args(["cf", s(&archive), "-C", s(&dir), "f.txt"])
        .status()
        .unwrap()
        .success());
    archive
}

fn rows(overlay: &Path, keys: &[&str]) -> Vec<Option<String>> {
    let meta = OverlayMeta::read(overlay).unwrap().unwrap();
    keys.iter()
        .map(|k| meta.get(k).map(str::to_owned))
        .collect()
}

fn git_repo(path: &Path, bare: bool) -> String {
    let repo = if bare {
        git2::Repository::init_bare(path)
    } else {
        git2::Repository::init(path)
    }
    .unwrap();
    let signature = git2::Signature::now("Test", "test@example.com").unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder
        .insert("file", repo.blob(b"original").unwrap(), 0o100644)
        .unwrap();
    let tree = repo.find_tree(builder.write().unwrap()).unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "first", &tree, &[])
        .unwrap();
    tree.id().to_string()
}

/// R6-3: the recorded kind and place come from what the factory served, for
/// every shape of input: archive, directory, `file://`, bare repository,
/// `RATARMOUNT_FORCE_GIT`, composite (first element) and bind-only.
#[test]
fn regression_bind_only_and_composite_record_served_kind() {
    let env = Env::new();
    let archive = tar_of(&env, "a.tar", "a");
    let folder = env.path("folder");
    fs::create_dir(&folder).unwrap();
    let local = |p: &Path| format!("local:{}", p.canonicalize().unwrap().display());
    let keys = ["base_kind", "base_location"];
    let check = |name: &str,
                 base_args: &[&str],
                 extra: &[&str],
                 env_vars: &[(&str, &str)],
                 kind: &str,
                 location: Option<String>| {
        let overlay = env.path(&format!("ov-{name}"));
        let out = env.create(&overlay, base_args, extra, env_vars);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", text(&out));
        let got = rows(&overlay, &keys);
        assert_eq!(got[0].as_deref(), Some(kind), "{name}: {got:?}");
        if let Some(location) = location {
            assert_eq!(got[1].as_deref(), Some(location.as_str()), "{name}");
        }
        overlay
    };
    check(
        "tar",
        &[s(&archive)],
        &[],
        &[],
        "archive",
        Some(local(&archive)),
    );
    check(
        "dir",
        &[s(&folder)],
        &[],
        &[],
        "directory",
        Some(local(&folder)),
    );
    let url = |p: &Path| format!("file://{}", p.canonicalize().unwrap().display());
    check(
        "file-url",
        &[&url(&archive)],
        &[],
        &[],
        "archive",
        Some(local(&archive)),
    );
    check(
        "file-url-dir",
        &[&url(&folder)],
        &[],
        &[],
        "directory",
        Some(local(&folder)),
    );
    // The first element of a composite is what is recorded; the others
    // become the redacted remote token.
    let composite = check(
        "composite-a",
        &[s(&archive), s(&folder)],
        &[],
        &[],
        "archive",
        Some(local(&archive)),
    );
    assert!(rows(&composite, &["base_remote_token"])[0].is_some());
    check(
        "composite-b",
        &[s(&folder), s(&archive)],
        &[],
        &[],
        "directory",
        Some(local(&folder)),
    );
    // Bind-only: the bind source is the whole base.
    let bind = format!("/b={}", archive.display());
    check(
        "bind",
        &[],
        &["--bind", &bind],
        &[],
        "archive",
        Some(local(&archive)),
    );
    // Git: a bare repository without a flag, a working tree with
    // RATARMOUNT_FORCE_GIT, and the same bare repository as `file://`.
    let bare = env.path("bare.git");
    let work = env.path("work");
    let bare_tree = git_repo(&bare, true);
    git_repo(&work, false);
    let overlay = check("bare", &[s(&bare)], &[], &[], "git", Some(local(&bare)));
    assert_eq!(
        rows(&overlay, &["base_git_tree"])[0].as_deref(),
        Some(bare_tree.as_str())
    );
    check(
        "force-git",
        &[s(&work)],
        &[],
        &[("RATARMOUNT_FORCE_GIT", "1")],
        "git",
        Some(local(&work)),
    );
    check(
        "work-plain",
        &[s(&work)],
        &[],
        &[],
        "directory",
        Some(local(&work)),
    );
    check(
        "file-url-bare",
        &[&url(&bare)],
        &[],
        &[],
        "git",
        Some(local(&bare)),
    );
}

/// Regression: a `--base-digest none` overlay compared nothing, so a base of
/// another kind reopened. Reopen, and a `--lower` mount over a lower sealed
/// against another kind, are refused naming their flag; one force passes.
#[test]
fn regression_none_overlay_refuses_kind_swap_in_every_verb() {
    let env = Env::new();
    let archive = tar_of(&env, "a.tar", "a");
    let folder = env.path("folder");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("f.txt"), "a").unwrap();
    let overlay = env.path("ov");
    let out = env.create(&overlay, &[s(&archive)], &["--base-digest", "none"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let refused = env.create(&overlay, &[s(&folder)], &["--base-digest", "none"], &[]);
    assert_ne!(refused.status.code(), Some(0), "{}", text(&refused));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--force-base-mismatch"),
        "{}",
        text(&refused)
    );
    let forced = env.create(
        &overlay,
        &[s(&folder)],
        &["--base-digest", "none", "--force-base-mismatch"],
        &[],
    );
    assert_eq!(forced.status.code(), Some(0), "{}", text(&forced));
    assert_eq!(
        rows(&overlay, &["base_kind"])[0].as_deref(),
        Some("directory")
    );

    // A lower sealed over the archive, mounted over the directory.
    let lower = env.path("lower");
    let made = env.create(&lower, &[s(&archive)], &["--base-digest", "none"], &[]);
    assert_eq!(made.status.code(), Some(0), "{}", text(&made));
    let sealed = env.run(&["overlay", "seal", s(&lower)], &[]);
    assert_eq!(sealed.status.code(), Some(0), "{}", text(&sealed));
    let top = env.path("top");
    let swap = env.run(
        &[
            "--no-mount",
            "--index-file",
            ":memory:",
            "-w",
            s(&top),
            "--lower",
            s(&lower),
            s(&folder),
        ],
        &[],
    );
    assert_ne!(swap.status.code(), Some(0), "{}", text(&swap));
    assert!(
        String::from_utf8_lossy(&swap.stderr).contains("--force-stack-mismatch"),
        "{}",
        text(&swap)
    );
}

/// A credential in the typed URL never reaches the overlay database: the base
/// URL and place rows hold the redacted form.
#[test]
fn regression_credentialed_url_recorded_redacted() {
    let env = Env::new();
    let stub = http_tar::serve_tar_stub();
    let credentialed = stub.replacen("http://", "http://user:s3cr3t@", 1) + "/a.tar";
    let overlay = env.path("ov");
    let out = env.create(&overlay, &[&credentialed], &[], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    for (key, value) in meta.values() {
        assert!(!value.contains("s3cr3t"), "{key} leaked: {value}");
    }
    assert_eq!(meta.get("base_kind"), Some("archive"));
    let plain = format!("{stub}/a.tar");
    assert_eq!(
        meta.get("base_location"),
        Some(format!("remote:{plain}").as_str())
    );
}

/// A strong record made over an HTTP archive reopens over a byte-identical
/// local copy only with the matching digest (no hashing by the mount).
#[test]
fn regression_remote_strong_reopen_over_local_requires_digest() {
    let env = Env::new();
    let stub = http_tar::serve_tar_stub();
    let url = format!("{stub}/a.tar");
    let host = stub.trim_start_matches("http://");
    // Fetch the served bytes once to know their digest and keep a local copy.
    let copy = env.path("copy.tar");
    {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(host).unwrap();
        write!(stream, "GET /a.tar HTTP/1.0\r\nHost: {host}\r\n\r\n").unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        fs::write(&copy, &response[split..]).unwrap();
    }
    let sum = Command::new("sha256sum").arg(&copy).output();
    let Ok(sum) = sum else {
        eprintln!("skip: sha256sum unavailable");
        return;
    };
    let digest = format!(
        "sha256:{}",
        String::from_utf8_lossy(&sum.stdout)
            .split_whitespace()
            .next()
            .unwrap()
    );
    let overlay = env.path("ov");
    let made = env.create(&overlay, &[&url], &["--base-digest", &digest], &[]);
    assert_eq!(made.status.code(), Some(0), "{}", text(&made));
    assert_eq!(
        rows(&overlay, &["base_digest_kind"])[0].as_deref(),
        Some("strong")
    );
    let wrong = format!("sha256:{}", "2".repeat(64));
    for (label, extra) in [
        ("nothing supplied", vec![]),
        ("wrong digest", vec!["--base-digest", wrong.as_str()]),
    ] {
        let out = env.create(&overlay, &[s(&copy)], &extra, &[]);
        assert_ne!(out.status.code(), Some(0), "{label}: {}", text(&out));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--force-base-mismatch"),
            "{label}: {}",
            text(&out)
        );
    }
    let ok = env.create(&overlay, &[s(&copy)], &["--base-digest", &digest], &[]);
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok));
    let location = rows(&overlay, &["base_location"])[0].clone().unwrap();
    assert!(location.starts_with("local:"), "{location}");
}
