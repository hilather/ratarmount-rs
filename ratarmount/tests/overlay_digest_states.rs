//! Gate-2b digest states: write-back of a resolved archive digest, the
//! `base_digest_state` contract, and concurrent resolution on a read-only base.
//! Offline CLI only; no /dev/fuse needed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

fn bin(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    let home = home.join("home");
    fs::create_dir_all(&home).unwrap();
    cmd.env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join(".cache"));
    cmd
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

fn archive(root: &Path) -> PathBuf {
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("member.txt"), b"member bytes\n").unwrap();
    let archive = root.join("base.tar");
    assert!(Command::new("tar")
        .arg("cf")
        .arg(&archive)
        .arg("-C")
        .arg(&src)
        .arg("member.txt")
        .status()
        .unwrap()
        .success());
    archive
}

fn sha(path: &Path) -> String {
    format!("sha256:{:x}", Sha256::digest(fs::read(path).unwrap()))
}

/// `--no-mount -w overlay archive` (creates the overlay; never hashes).
fn create(root: &Path, overlay: &str, archive: &Path, index: &Path) {
    expect(
        bin(root)
            .args(["--no-mount", "--index-file"])
            .arg(index)
            .arg("-w")
            .arg(root.join(overlay))
            .arg(archive)
            .output()
            .unwrap(),
        0,
    );
}

fn info(root: &Path, overlay: &str) -> serde_json::Value {
    let text = expect(
        bin(root)
            .args(["overlay", "info", "--json"])
            .arg(root.join(overlay))
            .output()
            .unwrap(),
        0,
    );
    serde_json::from_str(&text).unwrap()
}

fn seal(root: &Path, overlay: &str, log: &Path) -> Output {
    bin(root)
        .env("RATARMOUNT_TEST_HASH_LOG", log)
        .args(["overlay", "seal"])
        .arg(root.join(overlay))
        .output()
        .unwrap()
}

fn lines(log: &Path) -> usize {
    fs::read_to_string(log).map_or(0, |s| s.lines().count())
}

fn cached_rows(index: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(index).unwrap();
    // A missing table is simply an empty cache.
    let Ok(mut stmt) = conn.prepare("SELECT sha256 FROM overlay_base_digests") else {
        return Vec::new();
    };
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Item 1: sealing resolves a pending archive digest, writes it to the writable
/// index cache, and neither a later seal of another overlay nor a later mount
/// creation hashes the archive again.
#[test]
fn regression_seal_writes_digest_back_to_writable_index() {
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let index = root.path().join("base.index.sqlite");
    let log = root.path().join("hash.log");
    // Two overlays created while the digest is uncached: both pending.
    create(root.path(), "ov1", &archive, &index);
    create(root.path(), "ov2", &archive, &index);
    assert_eq!(info(root.path(), "ov1")["base_digest_kind"], "pending");
    assert_eq!(info(root.path(), "ov2")["base_digest_kind"], "pending");
    assert!(cached_rows(&index).is_empty());

    expect(seal(root.path(), "ov1", &log), 0);
    assert_eq!(lines(&log), 1);
    let expected = sha(&archive);
    assert_eq!(
        cached_rows(&index),
        [expected.trim_start_matches("sha256:")]
    );
    assert_eq!(info(root.path(), "ov1")["base_digest"], expected);

    // A later seal of the other overlay reads the cache.
    expect(seal(root.path(), "ov2", &log), 0);
    assert_eq!(lines(&log), 1, "second seal must not hash");
    assert_eq!(info(root.path(), "ov2")["base_digest"], expected);

    // verify rehashes the bytes even though the digest is cached (it must
    // catch a same-stamp edit the cache would hide): +1 per run.
    expect(
        bin(root.path())
            .env("RATARMOUNT_TEST_HASH_LOG", &log)
            .args(["overlay", "verify"])
            .arg(root.path().join("ov2"))
            .arg(&archive)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(lines(&log), 2, "verify hashes the base itself");
    expect(
        bin(root.path())
            .env("RATARMOUNT_TEST_HASH_LOG", &log)
            .args(["overlay", "verify"])
            .arg(root.path().join("ov2"))
            .arg(&archive)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(lines(&log), 3);
    // A later mount creation sees the digest present at once.
    create(root.path(), "ov3", &archive, &index);
    let ov3 = info(root.path(), "ov3");
    assert_eq!(ov3["base_digest_kind"], "strong");
    assert_eq!(ov3["base_digest"], expected);
    assert_eq!(lines(&log), 3, "creation hashed nothing");
}

/// Item 1: with no writable index the digest is recorded in the overlay DB
/// only, and a read-only index file is left byte-for-byte untouched.
#[test]
fn regression_seal_without_writable_index_records_in_overlay_only() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let index = root.path().join("base.index.sqlite");
    create(root.path(), "warm", &archive, &index);
    let before = fs::read(&index).unwrap();
    fs::set_permissions(&index, fs::Permissions::from_mode(0o444)).unwrap();
    let mtime = fs::metadata(&index).unwrap().modified().unwrap();
    let log = root.path().join("hash.log");

    // Read-only index: overlay created against it stays pending.
    create(root.path(), "ro", &archive, &index);
    assert_eq!(info(root.path(), "ro")["base_digest_kind"], "pending");
    expect(seal(root.path(), "ro", &log), 0);
    assert_eq!(lines(&log), 1);
    assert_eq!(info(root.path(), "ro")["base_digest"], sha(&archive));
    assert_eq!(fs::read(&index).unwrap(), before, "index must be untouched");
    assert_eq!(fs::metadata(&index).unwrap().modified().unwrap(), mtime);

    // `:memory:` index: same, nothing is written anywhere but the overlay.
    expect(
        bin(root.path())
            .args(["--no-mount", "--index-file", ":memory:", "-w"])
            .arg(root.path().join("mem"))
            .arg(&archive)
            .output()
            .unwrap(),
        0,
    );
    expect(seal(root.path(), "mem", &log), 0);
    assert_eq!(lines(&log), 2);
    assert_eq!(info(root.path(), "mem")["base_digest"], sha(&archive));
    fs::set_permissions(&index, fs::Permissions::from_mode(0o644)).unwrap();
}

/// Item 2: `overlay info` carries `base_digest_state` (JSON and text) for
/// every kind: pending, strong (present), weak (present), none.
#[test]
fn regression_overlay_info_base_digest_state_each_value() {
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let index = root.path().join("base.index.sqlite");
    let log = root.path().join("hash.log");
    create(root.path(), "pending", &archive, &index);
    let pending = info(root.path(), "pending");
    assert_eq!(pending["base_digest_state"], "pending");
    assert_eq!(pending["base_digest_kind"], "pending");
    let text = expect(
        bin(root.path())
            .args(["overlay", "info"])
            .arg(root.path().join("pending"))
            .output()
            .unwrap(),
        0,
    );
    assert!(text.contains("base_digest_state: pending\n"), "{text}");

    expect(seal(root.path(), "pending", &log), 0);
    let strong = info(root.path(), "pending");
    assert_eq!(strong["base_digest_kind"], "strong");
    assert_eq!(strong["base_digest_state"], "present");

    // Directory base: weak digest is present.
    let dir_base = root.path().join("dirbase");
    fs::create_dir(&dir_base).unwrap();
    fs::write(dir_base.join("f"), b"x").unwrap();
    expect(
        bin(root.path())
            .args(["--no-mount", "--index-file", ":memory:", "-w"])
            .arg(root.path().join("weak"))
            .arg(&dir_base)
            .output()
            .unwrap(),
        0,
    );
    let weak = info(root.path(), "weak");
    assert_eq!(weak["base_digest_kind"], "weak");
    assert_eq!(weak["base_digest_state"], "present");

    // --base-digest none.
    expect(
        bin(root.path())
            .args([
                "--no-mount",
                "--index-file",
                ":memory:",
                "--base-digest",
                "none",
                "-w",
            ])
            .arg(root.path().join("none"))
            .arg(&archive)
            .output()
            .unwrap(),
        0,
    );
    let none = info(root.path(), "none");
    assert_eq!(none["base_digest_kind"], "none");
    assert_eq!(none["base_digest_state"], "none");
}

/// Item 3: eight concurrent seals of eight overlays over one archive with no
/// writable index. Without a writable index there is no lock to coordinate
/// on (and no user-level digest cache is allowed), so each seal hashes: the
/// count is exactly N. Every seal records the correct digest and no overlay is
/// damaged. Concurrent verifies of the sealed results rehash the base each
/// (verify's strong base check deliberately never trusts a cache).
#[test]
fn regression_concurrent_seals_on_read_only_base_hash_per_verb() {
    const N: usize = 8;
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let expected = sha(&archive);
    for n in 0..N {
        expect(
            bin(root.path())
                .args(["--no-mount", "--index-file", ":memory:", "-w"])
                .arg(root.path().join(format!("ov{n}")))
                .arg(&archive)
                .output()
                .unwrap(),
            0,
        );
        assert_eq!(
            info(root.path(), &format!("ov{n}"))["base_digest_state"],
            "pending"
        );
    }
    let log = root.path().join("hash.log");
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..N)
            .map(|n| {
                let (root, log) = (root.path(), &log);
                s.spawn(move || seal(root, &format!("ov{n}"), log))
            })
            .collect();
        for h in handles {
            expect(h.join().unwrap(), 0);
        }
    });
    assert_eq!(
        lines(&log),
        N,
        "one hash per seal (no coordination possible)"
    );
    for n in 0..N {
        let i = info(root.path(), &format!("ov{n}"));
        assert_eq!(i["base_digest"], expected);
        assert_eq!(i["base_digest_state"], "present");
        assert_eq!(i["fsck_result"], "ok");
    }
    // Verify rehashes the uncached bytes once per run, by design.
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..N)
            .map(|n| {
                let (root, log) = (root.path(), &log);
                s.spawn(move || {
                    bin(root)
                        .env("RATARMOUNT_TEST_HASH_LOG", log)
                        .args(["overlay", "verify", "--json"])
                        .arg(root.join(format!("ov{n}")))
                        .arg(archive_path(root))
                        .output()
                        .unwrap()
                })
            })
            .collect();
        for h in handles {
            let out = expect(h.join().unwrap(), 0);
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["ok"], true);
            assert_eq!(v["base_ok"], true);
            assert_eq!(v["base_check"], "strong");
        }
    });
    assert_eq!(lines(&log), 2 * N, "each verify rehashes the base");
    for n in 0..N {
        let out = expect(
            bin(root.path())
                .args(["overlay", "fsck"])
                .arg(root.path().join(format!("ov{n}")))
                .output()
                .unwrap(),
            0,
        );
        assert!(out.contains("ok"), "{out}");
    }
}

fn archive_path(root: &Path) -> PathBuf {
    root.join("base.tar")
}
