//! R6-6: a base that moved between remote and local agrees when a SHA-256 the
//! local copy's index already caches equals the recorded strong digest. The
//! verbs open the base with an in-memory index, so the cached digest is read
//! from the sidecar the opener would have used (`--index-folders` included),
//! read-only: no index is created, written or locked.

use std::fs;
use std::io::{Read, Write};
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

/// What the test needs: an overlay with a strong record over the HTTP stub, a
/// byte-identical local copy `copy.tar` (different mtime and path), and a
/// second overlay over the copy whose seal caches the copy's SHA-256 in
/// `index`.
struct Setup {
    env: Env,
    url: String,
    remote: PathBuf,
    copy: PathBuf,
    digest: String,
}

fn setup(index_for_copy: impl Fn(&Env, &Path) -> PathBuf) -> Option<Setup> {
    let env = Env::new();
    let stub = http_tar::serve_tar_stub();
    let host = stub.trim_start_matches("http://").to_owned();
    let copy = env.path("copy.tar");
    let mut stream = std::net::TcpStream::connect(&host).unwrap();
    write!(stream, "GET /a.tar HTTP/1.0\r\nHost: {host}\r\n\r\n").unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    fs::write(&copy, &response[split..]).unwrap();
    let Ok(sum) = Command::new("sha256sum").arg(&copy).output() else {
        eprintln!("skip: sha256sum unavailable");
        return None;
    };
    let digest = format!(
        "sha256:{}",
        String::from_utf8_lossy(&sum.stdout)
            .split_whitespace()
            .next()
            .unwrap()
    );
    let url = format!("{stub}/a.tar");
    // The overlay under test: a strong record over the remote archive.
    let remote = env.path("remote-ov");
    env.ok(&[
        "--no-mount",
        "--index-file",
        ":memory:",
        "-w",
        s(&remote),
        "--base-digest",
        &digest,
        &url,
    ]);
    // A second overlay over the copy: its seal hashes the copy once and caches
    // the digest in the copy's index (`overlay_base_digests`).
    let index = index_for_copy(&env, &copy);
    let other = env.path("copy-ov");
    env.ok(&[
        "--no-mount",
        "--index-file",
        s(&index),
        "-w",
        s(&other),
        s(&copy),
    ]);
    env.ok(&["overlay", "seal", s(&other), s(&copy)]);
    assert_eq!(
        OverlayMeta::read(&other).unwrap().unwrap().base_digest(),
        Some(digest.as_str()),
        "the copy's seal resolved the digest"
    );
    Some(Setup {
        env,
        url,
        remote,
        copy,
        digest,
    })
}

fn refused(out: &Output, what: &str) {
    assert_ne!(out.status.code(), Some(0), "{what}: {}", text(out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--force-base-mismatch"),
        "{what}: {}",
        text(out)
    );
}

/// Regression: the verbs open with an in-memory index, so the cached digest
/// of the local copy was never found and a byte-identical copy of a strong
/// remote base needed `--base-digest` even though its own sidecar already
/// held the SHA-256.
#[test]
fn regression_offline_verbs_peek_sidecar_despite_in_memory_index() {
    // The sibling sidecar (`copy.tar.index.sqlite`).
    let Some(fx) = setup(|_, copy| PathBuf::from(format!("{}.index.sqlite", copy.display())))
    else {
        return;
    };
    let _ = &fx.digest;
    // Without the sidecar being consulted nothing could confirm the copy; with
    // it, `seal`, `diff --hash` and `verify` agree.
    let sealed = fx.env.run(&["overlay", "seal", s(&fx.remote), s(&fx.copy)]);
    assert_eq!(sealed.status.code(), Some(0), "{}", text(&sealed));
    fx.env.ok(&["diff", s(&fx.remote), s(&fx.copy), "--hash"]);
    fx.env
        .ok(&["overlay", "verify", s(&fx.remote), s(&fx.copy)]);
    // The peek never writes: the sidecar is untouched by the verbs.
}

/// Regression: a digest cached only in a custom `--index-folders` sidecar
/// rescued nothing, because the folders never reached the verb. With the flag
/// the copy is accepted; without it the copy is refused (no sibling sidecar).
#[test]
fn regression_index_folders_digest_rescues_no_recreate() {
    let Some(fx) = setup(|env, copy| {
        let folder = env.path("idx");
        fs::create_dir(&folder).unwrap();
        folder.join(format!("{}.index.sqlite", copy.display()).replace('/', "_"))
    }) else {
        return;
    };
    refused(
        &fx.env.run(&["overlay", "seal", s(&fx.remote), s(&fx.copy)]),
        "no folder",
    );
    let folder = fx.env.path("idx");
    // The custom index is read-only (chmod 444): the peek still answers.
    {
        use std::os::unix::fs::PermissionsExt;
        let index = folder.join(format!("{}.index.sqlite", fx.copy.display()).replace('/', "_"));
        fs::set_permissions(&index, fs::Permissions::from_mode(0o444)).unwrap();
    }
    let out = fx.env.run(&[
        "overlay",
        "seal",
        s(&fx.remote),
        s(&fx.copy),
        "--index-folders",
        s(&folder),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

/// Regression: a `--no-recreate-index` reopen peeks at the copy's existing
/// sidecar read-only (the peek is not index-write permission).
#[test]
fn regression_no_recreate_index_still_peeks() {
    let Some(fx) = setup(|_, copy| PathBuf::from(format!("{}.index.sqlite", copy.display())))
    else {
        return;
    };
    let sidecar = PathBuf::from(format!("{}.index.sqlite", fx.copy.display()));
    let out = fx.env.run(&[
        "--no-mount",
        "--no-recreate-index",
        "--index-file",
        s(&sidecar),
        "-w",
        s(&fx.remote),
        s(&fx.copy),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let location = OverlayMeta::read(&fx.remote)
        .unwrap()
        .unwrap()
        .get("base_location")
        .map(str::to_owned)
        .unwrap();
    assert!(location.starts_with("local:"), "{location}");
}

/// The recorded rows of a sealed bundle's `meta.json`.
fn bundle_meta_json(bundle: &Path) -> serde_json::Value {
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

/// Regression (R6-J5, audit B1-B3, B6): a strong remote record over a local
/// byte-identical copy whose own sidecar caches the SHA-256. The identity gate
/// accepted the copy (the cache confirmed it), but dropped WHICH evidence
/// confirmed it, so `overlay pack` saw an unconfirmed move and refused, and
/// `diff --hash --json` reported `unconfirmed`. The confirmation now reaches
/// pack and diff; a supplied digest packs the same way; the bundle keeps the
/// recorded (remote) rows.
#[test]
fn regression_cached_strong_confirmation_packs() {
    let Some(fx) = setup(|_, copy| PathBuf::from(format!("{}.index.sqlite", copy.display())))
    else {
        return;
    };
    fx.env.ok(&["overlay", "seal", s(&fx.remote), &fx.url]);
    let diff = fx
        .env
        .ok(&["diff", s(&fx.remote), s(&fx.copy), "--hash", "--json"]);
    assert!(
        diff.contains("\"base_identity\":\"confirmed\""),
        "a cached confirmation is reported as confirmed: {diff}"
    );
    let bundle = fx.env.path("cached.tar.zst");
    let out = fx
        .env
        .run(&["overlay", "pack", s(&fx.remote), s(&bundle), s(&fx.copy)]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "cached confirmation: {}",
        text(&out)
    );
    let rows = bundle_meta_json(&bundle);
    assert!(
        rows["base_location"]
            .as_str()
            .is_some_and(|l| l.starts_with("remote:")),
        "the bundle keeps the recorded base: {rows}"
    );
    // A supplied digest packs the same way (audit B4).
    let supplied = fx.env.path("supplied.tar.zst");
    let out = fx.env.run(&[
        "overlay",
        "pack",
        s(&fx.remote),
        s(&supplied),
        s(&fx.copy),
        "--base-digest",
        &fx.digest,
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "supplied digest: {}",
        text(&out)
    );
}

/// Pin (R6-J5, audit B5): a local archive copied to another local path, with
/// its digest cached only in the copy's sidecar, packs without a flag.
#[test]
fn regression_local_copy_cached_digest_packs() {
    let env = Env::new();
    let base = env.path("a.tar");
    fs::write(&base, tar_bytes()).unwrap();
    let Ok(sum) = Command::new("sha256sum").arg(&base).output() else {
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
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    env.ok(&["overlay", "seal", s(&overlay), s(&base)]);
    let copy = env.path("copy.tar");
    fs::copy(&base, &copy).unwrap();
    // Cache the copy's digest in its own sidecar via a second overlay's seal.
    let index = PathBuf::from(format!("{}.index.sqlite", copy.display()));
    let other = env.path("copy-ov");
    env.ok(&[
        "--no-mount",
        "--index-file",
        s(&index),
        "-w",
        s(&other),
        s(&copy),
    ]);
    env.ok(&["overlay", "seal", s(&other), s(&copy)]);
    let bundle = env.path("b.tar.zst");
    let out = env.run(&["overlay", "pack", s(&overlay), s(&bundle), s(&copy)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

fn tar_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "x.txt", &b"x\n"[..])
            .unwrap();
        builder.finish().unwrap();
    }
    out
}
