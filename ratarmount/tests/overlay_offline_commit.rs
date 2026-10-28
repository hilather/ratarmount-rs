//! Offline `--commit-overlay` identity: the recorded kind and the Unknown gate
//! run before anything is written, the archive is classified without building
//! an index, no sidecar is written or rewritten, and a stale sidecar cannot
//! stand in the way of `--force-base-mismatch`.
//!
//! CLI-level, offline (no FUSE), private HOME / XDG_CACHE_HOME per test.
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

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
            .args(args)
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) {
        let out = self.run(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {}", text(&out));
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

fn tar_with(env: &Env, name: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let dir = env.path(&format!("{name}.src"));
    fs::create_dir(&dir).unwrap();
    for (file, bytes) in files {
        fs::write(dir.join(file), bytes).unwrap();
    }
    let archive = env.path(name);
    let mut cmd = Command::new("tar");
    cmd.args(["cf", s(&archive), "-C", s(&dir)]);
    cmd.args(files.iter().map(|(f, _)| *f));
    assert!(cmd.status().unwrap().success());
    archive
}

fn members(archive: &Path) -> String {
    let out = Command::new("tar")
        .args(["tf", s(archive)])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn have_gnu_tar() -> bool {
    Command::new("tar")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("GNU tar"))
}

/// A `--base-digest none` overlay over a directory, holding `new.txt`.
fn directory_overlay(env: &Env) -> PathBuf {
    let base = env.path("basedir");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("x.txt"), b"base\n").unwrap();
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
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    overlay
}

/// Regression (R6-G4, #2): offline `--commit-overlay` never compared the
/// recorded kind, so a `--base-digest none` DIRECTORY overlay committed into an
/// unrelated TAR without force. Refused (naming the flag) with the archive
/// byte-identical; `--force-base-mismatch` commits.
#[test]
fn regression_directory_none_overlay_into_unrelated_tar_refused() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let overlay = directory_overlay(&env);
    let archive = tar_with(&env, "other.tar", &[("z.txt", b"z\n")]);
    let before = fs::read(&archive).unwrap();
    let out = env.run(&["--commit-overlay", "-w", s(&overlay), s(&archive)]);
    assert!(!out.status.success(), "must refuse: {}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force-base-mismatch"), "{err}");
    assert!(err.contains("directory"), "{err}");
    assert!(fs::read(&archive).unwrap() == before, "archive modified");
    assert!(overlay.join("new.txt").exists(), "overlay data kept");
    let out = env.run(&[
        "--commit-overlay",
        "-w",
        s(&overlay),
        "--force-base-mismatch",
        "--yes",
        s(&archive),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(members(&archive).contains("new.txt"));
}

/// Regression (R6-G4, #2): an overlay whose record names no usable base kind
/// (written by an unreleased build) is Unknown, and Unknown refuses a commit
/// like it refuses every other verb.
#[test]
fn regression_unknown_record_refuses_offline_commit() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let overlay = directory_overlay(&env);
    let db = overlay.join(".ratarmount-overlay.sqlite");
    let db = if db.exists() {
        db
    } else {
        fs::read_dir(&overlay)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "sqlite"))
            .expect("overlay database")
    };
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute("DELETE FROM meta WHERE key = 'base_kind'", [])
        .unwrap();
    drop(conn);
    let archive = tar_with(&env, "other.tar", &[("z.txt", b"z\n")]);
    let before = fs::read(&archive).unwrap();
    let out = env.run(&["--commit-overlay", "-w", s(&overlay), s(&archive)]);
    assert!(!out.status.success(), "must refuse: {}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force-base-mismatch"), "{err}");
    assert!(fs::read(&archive).unwrap() == before, "archive modified");
}

/// Everything beside the archive: names and bytes.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut all: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(&p).unwrap_or_default(),
            )
        })
        .collect();
    all.sort();
    all
}

/// A `.tar.zst` of `files` with an indexed sidecar in DELETE journal mode.
fn zst_with_sidecar(env: &Env, dir: &Path) -> PathBuf {
    let tar = tar_with(env, "a.tar", &[("f.txt", b"f\n")]);
    let archive = dir.join("a.tar.zst");
    fs::write(
        &archive,
        zstd::stream::encode_all(&fs::read(&tar).unwrap()[..], 3).unwrap(),
    )
    .unwrap();
    env.ok(&["--no-mount", s(&archive)]);
    let sidecar = dir.join("a.tar.zst.index.sqlite");
    assert!(sidecar.exists(), "indexing wrote no sidecar");
    let conn = rusqlite::Connection::open(&sidecar).unwrap();
    conn.query_row("PRAGMA journal_mode=DELETE", [], |_| Ok(()))
        .unwrap();
    drop(conn);
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", sidecar.display()));
    }
    archive
}

/// Regression (R6-G5, #6): the "read-only" classification of a `.tar.zst` loaded
/// its sidecar through writable loaders, so a DELETE-mode sidecar gained WAL
/// files and schema changes before a later identity refusal. The refused
/// commit leaves the archive, the sidecar and the directory byte-identical and
/// creates nothing (no `-wal`, no `-shm`).
#[test]
fn regression_refused_offline_commit_writes_no_sidecar_files() {
    let env = Env::new();
    let overlay = directory_overlay(&env);
    let dir = env.path("zst");
    fs::create_dir(&dir).unwrap();
    let archive = zst_with_sidecar(&env, &dir);
    let before = snapshot(&dir);
    let out = env.run(&["--commit-overlay", "-w", s(&overlay), s(&archive)]);
    assert!(!out.status.success(), "must refuse: {}", text(&out));
    assert!(
        snapshot(&dir) == before,
        "the refused commit created or modified files: {:?}",
        snapshot(&dir).iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
}

/// Regression (R6-G6, #7): replacing an indexed TAR left a stale sidecar, and
/// `--commit-overlay --force-base-mismatch` died loading it before the override
/// gate. Without force the replacement is refused naming the flag; with force
/// the commit goes through and never needs the sidecar.
#[test]
fn regression_stale_sidecar_does_not_block_force() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    env.ok(&["--no-mount", s(&archive)]);
    assert!(env.path("base.tar.index.sqlite").exists());
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    // Replace the archive: the sidecar now describes the old one.
    let replacement = tar_with(
        &env,
        "replacement.tar",
        &[("b.txt", b"bb\n"), ("c.txt", b"c\n")],
    );
    fs::rename(&replacement, &archive).unwrap();
    let before = fs::read(&archive).unwrap();
    let out = env.run(&["--commit-overlay", "-w", s(&overlay), s(&archive)]);
    assert!(!out.status.success(), "must refuse: {}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force-base-mismatch"), "{err}");
    assert!(fs::read(&archive).unwrap() == before, "archive modified");
    let out = env.run(&[
        "--commit-overlay",
        "-w",
        s(&overlay),
        "--force-base-mismatch",
        "--yes",
        s(&archive),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let listing = members(&archive);
    assert!(
        listing.contains("new.txt") && listing.contains("b.txt"),
        "{listing}"
    );
}

/// Leave `archive` mid-commit the way a crash does (journal and locator on
/// disk, the archive truncated at the replaced suffix).
fn interrupt_append(archive: &Path) {
    use std::io::Write;
    let len = fs::metadata(archive).unwrap().len();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[0u8; 1536]).unwrap();
    let crashed = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        archive,
        len - 1024,
        &mut suffix,
        &mut |step| {
            if step == "archive truncate" {
                Err(std::io::Error::other("crash"))
            } else {
                Ok(())
            }
        },
    );
    assert!(crashed.is_err());
}

/// Regression (R6-G4, #8 offline half): `--commit-overlay` recovered the
/// archive's pending journal before it classified anything, so a foreign
/// archive carrying its own interrupted append (a replacement of the recorded
/// base) was rolled back before the identity gate refused it. The overlay's
/// own torn append still recovers and commits.
#[test]
fn regression_offline_commit_recovers_only_its_own_journal() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    // Foreign: refused, archive and journal byte-identical.
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    let foreign = tar_with(
        &env,
        "foreign.tar",
        &[("b.txt", b"bb\n"), ("c.txt", b"c\n")],
    );
    interrupt_append(&foreign);
    let crashed = fs::read(&foreign).unwrap();
    let journal = ratarmount_compress::commit_journal::journal_path(&foreign);
    let journal_bytes = fs::read(&journal).unwrap();
    fs::rename(&foreign, &archive).unwrap();
    let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
    assert!(!out.status.success(), "must refuse: {}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force-base-mismatch"), "{err}");
    assert!(fs::read(&archive).unwrap() == crashed, "archive modified");
    assert!(
        fs::read(&journal).unwrap() == journal_bytes,
        "journal modified"
    );

    // Own: the torn append rolls back to the recorded base and the commit goes through.
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    interrupt_append(&archive);
    let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let listing = members(&archive);
    assert!(
        listing.contains("a.txt") && listing.contains("new.txt"),
        "{listing}"
    );
    assert!(!ratarmount_compress::commit_journal::journal_path(&archive).exists());
}

/// Regression (R6-H1, B1): after a crash the interrupted archive was replaced
/// by a new-inode copy of the same bytes (same mtime), and the commit ran as a
/// fresh process. The fresh token matched the copy, and recovery, which checks
/// only content, rolled the copy back and committed into it. The journal
/// records the inode it was started for; a successor with another inode is
/// refused with archive and journal untouched.
#[cfg(unix)]
#[test]
fn regression_new_inode_copy_of_interrupted_archive_is_refused() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    interrupt_append(&archive);
    let crashed = fs::read(&archive).unwrap();
    let journal = ratarmount_compress::commit_journal::journal_path(&archive);
    let journal_bytes = fs::read(&journal).unwrap();
    let copy = env.path("copy.tar");
    fs::write(&copy, &crashed).unwrap();
    fs::File::options()
        .write(true)
        .open(&copy)
        .unwrap()
        .set_modified(fs::metadata(&archive).unwrap().modified().unwrap())
        .unwrap();
    fs::rename(&copy, &archive).unwrap();
    let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
    assert!(
        !out.status.success(),
        "must refuse a new-inode successor: {}",
        text(&out)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force-base-mismatch"), "{err}");
    assert!(fs::read(&archive).unwrap() == crashed, "archive modified");
    assert!(
        fs::read(&journal).unwrap() == journal_bytes,
        "journal modified"
    );
}

/// Regression (R6-J2, audit A17): a RAW overlay directory (no database) has no
/// recorded base, yet `main.rs` and the commit both recovered whatever journal
/// the archive carried. A new-inode copy of a crashed archive is refused, and
/// the archive's own torn append still recovers.
#[cfg(unix)]
#[test]
fn regression_raw_dir_commit_refuses_foreign_journal() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    fs::create_dir(&overlay).unwrap();
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    interrupt_append(&archive);
    let crashed = fs::read(&archive).unwrap();
    let journal = ratarmount_compress::commit_journal::journal_path(&archive);
    let journal_bytes = fs::read(&journal).unwrap();
    let copy = env.path("copy.tar");
    fs::write(&copy, &crashed).unwrap();
    fs::File::options()
        .write(true)
        .open(&copy)
        .unwrap()
        .set_modified(fs::metadata(&archive).unwrap().modified().unwrap())
        .unwrap();
    fs::rename(&copy, &archive).unwrap();
    let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
    assert!(!out.status.success(), "must refuse: {}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--force-base-mismatch"),
        "{}",
        text(&out)
    );
    assert!(fs::read(&archive).unwrap() == crashed, "archive modified");
    assert!(
        fs::read(&journal).unwrap() == journal_bytes,
        "journal modified"
    );

    // Its own torn append still recovers and commits.
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    fs::create_dir(&overlay).unwrap();
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    interrupt_append(&archive);
    let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(members(&archive).contains("new.txt"));
}

/// Regression (R6-K6, audit A-ext1): the mount path recovered whatever journal
/// each input carried BEFORE any gate, so a `-w` remount over a new-inode copy
/// of a crashed archive rolled the copy back. The journal belongs to the file
/// it was started for: a foreign one is refused with archive and journal
/// untouched; the archive's own crash still recovers at mount. (`--no-mount`
/// runs the same recovery and needs no FUSE.)
#[cfg(unix)]
#[test]
fn regression_mount_recovery_refuses_foreign_journal() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    interrupt_append(&archive);
    let crashed = fs::read(&archive).unwrap();
    let journal = ratarmount_compress::commit_journal::journal_path(&archive);
    let journal_bytes = fs::read(&journal).unwrap();
    let copy = env.path("copy.tar");
    fs::write(&copy, &crashed).unwrap();
    fs::File::options()
        .write(true)
        .open(&copy)
        .unwrap()
        .set_modified(fs::metadata(&archive).unwrap().modified().unwrap())
        .unwrap();
    fs::rename(&copy, &archive).unwrap();
    let out = env.run(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    assert!(!out.status.success(), "must refuse: {}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("another file"), "{err}");
    assert!(fs::read(&archive).unwrap() == crashed, "archive modified");
    assert!(
        fs::read(&journal).unwrap() == journal_bytes,
        "journal modified"
    );

    // Its own crash still recovers at mount.
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    let original = fs::read(&archive).unwrap();
    interrupt_append(&archive);
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    assert!(fs::read(&archive).unwrap() == original, "not rolled back");
    assert!(!ratarmount_compress::commit_journal::journal_path(&archive).exists());
}

/// Regression (R6-K8, r11 review nit 8): the classifier maps a `file://` base
/// to its local path, but the commit gate canonicalised the typed URL and
/// refused with "cannot resolve file:///...". The URL is resolved to its path
/// first, so the commit goes through (and is gated like the path).
#[cfg(unix)]
#[test]
fn regression_offline_commit_accepts_file_url() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    let url = format!("file://{}", archive.display());
    let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), &url]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let listing = members(&archive);
    assert!(
        listing.contains("a.txt") && listing.contains("new.txt"),
        "{listing}"
    );
}

/// Regression (R6-L1, r12 skeptic 5): R6-K8 resolved EVERY remote input to a
/// local file before the commit, so `--commit-overlay http://...` downloaded
/// the archive (and ssh/sftp/ftp/webdav would connect). Only `file://` is
/// resolved; every other remote scheme is refused with no network contact.
#[cfg(unix)]
#[test]
fn regression_offline_commit_makes_no_network_fetch() {
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let env = Env::new();
    let overlay = env.path("overlay");
    fs::create_dir_all(&overlay).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicUsize::new(0));
    let (h, st) = (hits.clone(), stop.clone());
    let server = std::thread::spawn(move || {
        while st.load(Ordering::SeqCst) == 0 {
            if listener.accept().is_ok() {
                h.fetch_add(1, Ordering::SeqCst);
            } else {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    });
    for url in [
        format!("http://127.0.0.1:{port}/a.tar"),
        format!("https://127.0.0.1:{port}/a.tar"),
        format!("ssh://127.0.0.1:{port}/a.tar"),
        format!("sftp://127.0.0.1:{port}/a.tar"),
        format!("ftp://127.0.0.1:{port}/a.tar"),
        format!("webdav://127.0.0.1:{port}/a.tar"),
    ] {
        let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), &url]);
        assert!(!out.status.success(), "{url}: must refuse: {}", text(&out));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("only a local path or file:// URL"),
            "{url}: unclear refusal: {err}"
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    stop.store(1, Ordering::SeqCst);
    server.join().unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 0, "network contacted");
}

/// Leave `archive` crashed right after the replacement was fully written: the
/// journal is on disk and marked complete, so recovery rolls it FORWARD.
fn interrupt_complete(archive: &Path) {
    use std::io::Write;
    let len = fs::metadata(archive).unwrap().len();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[0u8; 1536]).unwrap();
    let crashed = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        archive,
        len - 1024,
        &mut suffix,
        &mut |step| {
            if step == "locator complete" {
                Err(std::io::Error::other("crash"))
            } else {
                Ok(())
            }
        },
    );
    assert!(crashed.is_err());
}

fn info(env: &Env, overlay: &Path) -> serde_json::Value {
    let out = env.run(&["overlay", "info", "--json", s(overlay)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Regression (R7-A2): mount-time recovery rolled a COMPLETE journal forward
/// and unlinked it without restamping the `-w` overlay's recorded base, so the
/// identity gate that followed (or the next mount) refused the archive recovery
/// itself had just produced. The rows are restamped from the locked descriptor
/// before the journal is unlinked (a strong digest is marked `pending`), and
/// the next mount accepts.
#[cfg(unix)]
#[test]
fn regression_mount_roll_forward_restamps_then_remount_accepts() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for supplied in [false, true] {
        let env = Env::new();
        let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
        let overlay = env.path("overlay");
        let old = if supplied {
            use sha2::{Digest, Sha256};
            Some(format!(
                "sha256:{:x}",
                Sha256::digest(fs::read(&archive).unwrap())
            ))
        } else {
            None
        };
        let mut args = vec!["--no-mount"];
        if let Some(digest) = &old {
            args.extend(["--base-digest", digest]);
        }
        args.extend(["-w", s(&overlay), s(&archive)]);
        env.ok(&args);
        interrupt_complete(&archive);
        let rolled = fs::read(&archive).unwrap();
        env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
        assert!(
            !ratarmount_compress::commit_journal::journal_path(&archive).exists(),
            "supplied={supplied}: journal recovered"
        );
        assert!(fs::read(&archive).unwrap() == rolled, "rolled forward");
        let record = info(&env, &overlay);
        // A strong digest of the pre-crash bytes is never kept: it is `pending`
        // (or already re-resolved against the archive as it is now).
        if let Some(old) = &old {
            assert_ne!(
                record["base_digest"].as_str(),
                Some(old.as_str()),
                "{record}"
            );
        }
        // The next gate accepts the archive recovery produced.
        env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    }
}

/// Regression (R7-A2): offline `--commit-overlay` recovered a complete journal
/// at the start of the commit and then ended on an empty plan (or a declined
/// confirmation) without restamping, so the next commit failed with "changed
/// since it was recorded". Recovery restamps before the journal is unlinked.
#[cfg(unix)]
#[test]
fn regression_offline_commit_roll_forward_with_empty_plan_restamps() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    interrupt_complete(&archive);
    // An empty overlay: recovery rolls forward and the commit has nothing to do.
    env.ok(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
    assert!(
        !ratarmount_compress::commit_journal::journal_path(&archive).exists(),
        "journal recovered"
    );
    // The next commit is accepted by the gate.
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    env.ok(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
    assert!(members(&archive).contains("new.txt"));
}

/// `foreign.tar` carrying an interrupted append (torn or complete), renamed
/// over `archive`. Returns the archive bytes and the journal path and bytes.
#[cfg(unix)]
fn rename_b_over_a(env: &Env, archive: &Path, complete: bool) -> (Vec<u8>, PathBuf, Vec<u8>) {
    let foreign = tar_with(env, "foreign.tar", &[("b.txt", b"bb\n"), ("c.txt", b"c\n")]);
    if complete {
        interrupt_complete(&foreign);
    } else {
        interrupt_append(&foreign);
    }
    let bytes = fs::read(&foreign).unwrap();
    let journal = ratarmount_compress::commit_journal::journal_path(&foreign);
    let journal_bytes = fs::read(&journal).unwrap();
    fs::rename(&foreign, archive).unwrap();
    (bytes, journal, journal_bytes)
}

/// Regression (R7-A1, Keystone 1): `mv B A` where B carries its own interrupted
/// journal. The journal's inode matches the file at A's name, so mount-time
/// recovery rolled B back BEFORE the gate refused the stamp. Now the journal's
/// pre-commit stamp is compared with the recorded base first: exit 2, the
/// archive and the journal byte-identical (torn and complete).
#[cfg(unix)]
#[test]
fn regression_mount_rename_b_over_a_leaves_b_and_its_journal_untouched() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for complete in [false, true] {
        let env = Env::new();
        let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
        let overlay = env.path("overlay");
        env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
        let (bytes, journal, journal_bytes) = rename_b_over_a(&env, &archive, complete);
        let out = env.run(&["--no-mount", "-w", s(&overlay), s(&archive)]);
        let err = String::from_utf8_lossy(&out.stderr);
        if complete {
            // A complete journal waits for the gate, which refuses the stamp.
            assert_eq!(out.status.code(), Some(1), "{}", text(&out));
            assert!(err.contains("base mismatch"), "{err}");
        } else {
            // A torn one can be neither opened nor applied: refused up front.
            assert_eq!(out.status.code(), Some(2), "{}", text(&out));
            assert!(err.contains("not started for the recorded base"), "{err}");
        }
        assert!(err.contains("--force-base-mismatch"), "{err}");
        assert!(
            fs::read(&archive).unwrap() == bytes,
            "complete={complete}: archive"
        );
        assert!(
            fs::read(&journal).unwrap() == journal_bytes,
            "complete={complete}: journal"
        );
    }
}

/// Regression (R7-A1): a COMPLETE foreign journal under `--force-base-mismatch`
/// is recovered only AFTER the gates accepted, and the overlay keeps A's
/// baseline: a second unforced open still refuses B.
#[cfg(unix)]
#[test]
fn regression_forced_rename_b_over_a_keeps_a_baseline() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    let (bytes, journal, _) = rename_b_over_a(&env, &archive, true);
    let before = info(&env, &overlay);
    let out = env.run(&[
        "--no-mount",
        "--force-base-mismatch",
        "-w",
        s(&overlay),
        s(&archive),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!journal.exists(), "journal recovered after the gate");
    assert!(
        fs::read(&archive).unwrap() == bytes,
        "rolled forward: bytes unchanged"
    );
    let after = info(&env, &overlay);
    assert_eq!(after["base_digest_kind"], before["base_digest_kind"]);
    let again = env.run(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    assert!(
        !again.status.success(),
        "B is still not the recorded base: {}",
        text(&again)
    );
}

/// Regression (R7-A1): a union member (not the recorded base) with a COMPLETE
/// own journal waits for the gate: the mount of `-w ov A B` is refused or
/// accepted by the gate first; a torn member journal is refused with the
/// instruction, untouched.
#[cfg(unix)]
#[test]
fn regression_mount_union_member_journal_waits_for_the_gate() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    let env = Env::new();
    let a = tar_with(&env, "a.tar", &[("a.txt", b"a\n")]);
    let b = tar_with(&env, "b.tar", &[("b.txt", b"b\n")]);
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&a)]);
    interrupt_append(&b);
    let crashed = fs::read(&b).unwrap();
    let journal = ratarmount_compress::commit_journal::journal_path(&b);
    let journal_bytes = fs::read(&journal).unwrap();
    let out = env.run(&["--no-mount", "-w", s(&overlay), s(&a), s(&b)]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not the base this overlay recorded"), "{err}");
    assert!(err.contains("--no-mount"), "{err}");
    assert!(fs::read(&b).unwrap() == crashed, "member untouched");
    assert!(
        fs::read(&journal).unwrap() == journal_bytes,
        "journal untouched"
    );
    // Recovered alone first, the member opens again.
    env.ok(&["--no-mount", s(&b)]);
    assert!(!journal.exists(), "recovered alone");
}

/// Regression: #239 (r17 skeptic #2, R7-E2 B1/B2): A's overlay database is replaced
/// by a dangling symlink, then B with its own journal (torn or complete) is
/// renamed over A. `overlay.join(DB).exists()` read the dangling symlink as
/// "no database", so `--commit-overlay -w ov --yes A` ran the inode-only
/// recovery before any recorded-base gate: B was rolled back (or forward) and
/// its journal removed. Strict admission now `lstat`s the final database
/// component and refuses the link with exit 1 before classification or recovery,
/// with B, its journal and the symlink target untouched.
#[cfg(unix)]
#[test]
fn regression_offline_commit_dangling_db_symlink_leaves_b_untouched() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for complete in [false, true] {
        let env = Env::new();
        let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
        let overlay = env.path("overlay");
        env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
        fs::write(overlay.join("new.txt"), b"new\n").unwrap();
        let db = overlay.join(".ratarmount.overlay.sqlite");
        fs::rename(&db, env.path("saved.sqlite")).unwrap();
        let target = env.path("nowhere.sqlite");
        std::os::unix::fs::symlink(&target, &db).unwrap();
        let (bytes, journal, journal_bytes) = rename_b_over_a(&env, &archive, complete);
        let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "complete={complete}: {}",
            text(&out)
        );
        assert!(
            text(&out).contains("is a symlink; it must be a regular file"),
            "{}",
            text(&out)
        );
        assert!(
            fs::read(&archive).unwrap() == bytes,
            "complete={complete}: B modified: {}",
            text(&out)
        );
        assert!(
            fs::read(&journal).is_ok_and(|j| j == journal_bytes),
            "complete={complete}: journal modified or removed: {}",
            text(&out)
        );
        assert!(
            !target.exists(),
            "complete={complete}: created through the symlink"
        );
    }
}

/// Regression: #239 (R10-B, #150, v4 T6): `--commit-overlay` with the overlay used
/// (marker kept) and its database deleted, replaced by a symlink to a 0-byte
/// file, or by a symlink that cannot be resolved
/// (`plain-file/missing.sqlite`: `ENOTDIR`), with B
/// (its own torn or complete journal) renamed over A. A deleted database read
/// as "no database" and the raw-directory branch ran inode-only recovery on B;
/// the unresolvable one could read as a record. Symlinks exit 1; deleted or
/// empty regular records exit 2. B and its journal stay byte-identical.
#[cfg(unix)]
#[test]
fn regression_offline_commit_lost_or_unresolved_db_leaves_b_untouched() {
    if !have_gnu_tar() {
        eprintln!("skip: GNU tar unavailable");
        return;
    }
    for shape in ["deleted", "empty", "symlink to empty", "unresolved"] {
        for complete in [false, true] {
            let unresolved = shape == "unresolved";
            let env = Env::new();
            let archive = tar_with(&env, "base.tar", &[("a.txt", b"a\n")]);
            let overlay = env.path("overlay");
            env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
            let db = overlay.join(".ratarmount.overlay.sqlite");
            fs::rename(&db, env.path("saved.sqlite")).unwrap();
            if unresolved {
                let plain = env.path("plain-file");
                fs::write(&plain, b"plain").unwrap();
                std::os::unix::fs::symlink(plain.join("missing.sqlite"), &db).unwrap();
            } else if shape == "empty" {
                fs::write(&db, b"").unwrap();
            } else if shape == "symlink to empty" {
                let empty = env.path("empty.sqlite");
                fs::write(&empty, b"").unwrap();
                std::os::unix::fs::symlink(&empty, &db).unwrap();
            }
            let (bytes, journal, journal_bytes) = rename_b_over_a(&env, &archive, complete);
            let out = env.run(&["--commit-overlay", "--yes", "-w", s(&overlay), s(&archive)]);
            let row = format!("{shape} complete={complete}");
            let is_link = unresolved || shape == "symlink to empty";
            assert_eq!(
                out.status.code(),
                Some(if is_link { 1 } else { 2 }),
                "{row}: {}",
                text(&out)
            );
            let expect = if is_link {
                "is a symlink; it must be a regular file"
            } else {
                "was used before but its database"
            };
            assert!(text(&out).contains(expect), "{row}: {}", text(&out));
            assert!(
                !text(&out).contains("no base identity was checked"),
                "{row}: {}",
                text(&out)
            );
            assert!(fs::read(&archive).unwrap() == bytes, "{row}: B modified");
            assert!(
                fs::read(&journal).is_ok_and(|j| j == journal_bytes),
                "{row}: journal modified or removed"
            );
        }
    }
}

/// Regression (#234): `--commit-overlay` on a sealed overlay rewrote the
/// archive and then failed on the read-only database, breaking the seal. It
/// must refuse with the `-w` sealed message before touching the archive, also
/// under `--force-base-mismatch`. The fixture needs no GNU tar: the refusal
/// comes before any commit backend.
#[test]
fn regression_commit_overlay_refuses_sealed_overlay() {
    let env = Env::new();
    let archive = env.path("base.tar");
    {
        let mut builder = tar::Builder::new(fs::File::create(&archive).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "a.txt", &b"a\n"[..])
            .unwrap();
        builder.finish().unwrap();
    }
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(&archive)]);
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    env.ok(&["overlay", "seal", s(&overlay), s(&archive)]);
    let before = fs::read(&archive).unwrap();
    let expected = format!(
        "error: overlay {} is sealed; mount it with --lower, or `overlay unseal`",
        overlay.display()
    );
    for extra in [None, Some("--force-base-mismatch")] {
        let mut args = vec!["--commit-overlay", "-w", s(&overlay), "--yes"];
        args.extend(extra);
        args.push(s(&archive));
        let out = env.run(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", text(&out));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.lines().any(|line| line == expected), "{err}");
        assert!(fs::read(&archive).unwrap() == before, "archive modified");
    }
    env.ok(&["overlay", "verify", s(&overlay), s(&archive)]);
    // Restore write bits so the temporary directory can be removed.
    env.ok(&["overlay", "unseal", s(&overlay), "--i-know"]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn symlink_policy_fixture() -> (Env, PathBuf, PathBuf) {
    let env = Env::new();
    let archive = env.path("base.tar");
    let mut builder = tar::Builder::new(fs::File::create(&archive).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(5);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "base.txt", &b"base\n"[..])
        .unwrap();
    builder.finish().unwrap();
    drop(builder);
    let overlay = env.path("overlay");
    env.ok(&[
        "--no-mount",
        "--index-file",
        ":memory:",
        "--base-digest",
        "none",
        "-w",
        s(&overlay),
        s(&archive),
    ]);
    fs::write(overlay.join("added.txt"), b"addition\n").unwrap();
    (env, archive, overlay)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn policy_locator(archive: &Path) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    match rustix::fs::getxattr(archive, "user.ratarmount.commit-journal", &mut bytes) {
        Ok(n) => bytes[..n].to_vec(),
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOENT) => Vec::new(),
        Err(e) => panic!("locator {}: {e}", archive.display()),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn policy_snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, (String, Vec<u8>)> {
    fn visit(
        root: &Path,
        dir: &Path,
        out: &mut std::collections::BTreeMap<PathBuf, (String, Vec<u8>)>,
    ) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path == root.join(".cache") {
                continue;
            }
            let meta = fs::symlink_metadata(&path).unwrap();
            let (kind, bytes) = if meta.is_symlink() {
                (
                    "link",
                    fs::read_link(&path)
                        .unwrap()
                        .as_os_str()
                        .as_encoded_bytes()
                        .to_vec(),
                )
            } else if meta.is_file() {
                ("file", fs::read(&path).unwrap())
            } else {
                ("dir", Vec::new())
            };
            out.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                (kind.to_owned(), bytes),
            );
            if meta.is_dir() {
                visit(root, &path, out);
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    visit(root, root, &mut out);
    out
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn policy_link(env: &Env, overlay: &Path, suffix: &str, shape: &str) -> PathBuf {
    let db = overlay.join(ratarmount_compositing::HIDDEN_DB);
    let mut name = db.as_os_str().to_owned();
    name.push(suffix);
    let link = PathBuf::from(name);
    let target = env.path("external-target");
    if suffix.is_empty() {
        fs::rename(&db, env.path("saved-db")).unwrap();
    }
    match shape {
        "regular" if suffix.is_empty() => {
            fs::copy(env.path("saved-db"), &target).unwrap();
        }
        "regular" => {
            fs::write(&target, b"external target\n").unwrap();
        }
        "empty" => {
            fs::write(&target, b"").unwrap();
        }
        "dangling" => {}
        "loop" => {
            std::os::unix::fs::symlink(&link, &target).unwrap();
        }
        _ => panic!("unknown link shape"),
    }
    std::os::unix::fs::symlink(&target, &link).unwrap();
    link
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_policy_refusal(env: &Env, archive: &Path, link: &Path, args: &[&str]) {
    let before = policy_snapshot(env.root.path());
    let locator = policy_locator(archive);
    let out = env.run(args);
    assert_eq!(out.status.code(), Some(1), "{args:?}: {}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    let canonical_link = link
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join(link.file_name().unwrap());
    assert!(
        err.contains(&link.display().to_string())
            || err.contains(&canonical_link.display().to_string()),
        "{err}"
    );
    assert!(
        err.contains("is a symlink; it must be a regular file"),
        "{err}"
    );
    assert_eq!(
        policy_snapshot(env.root.path()),
        before,
        "{args:?}: state changed: {}",
        text(&out)
    );
    assert_eq!(policy_locator(archive), locator, "locator changed");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn offline_symlink_cases(suffix: &str) {
    for shape in ["regular", "empty", "dangling", "loop"] {
        for mode in [None, Some("copy"), Some("append"), Some("auto")] {
            for force in [false, true] {
                let (env, archive, overlay) = symlink_policy_fixture();
                let link = policy_link(&env, &overlay, suffix, shape);
                let mut args = vec![
                    "--commit-overlay",
                    "--yes",
                    "--index-file",
                    ":memory:",
                    "-w",
                    s(&overlay),
                ];
                if let Some(mode) = mode {
                    args.extend(["--commit-overlay-mode", mode]);
                }
                if force {
                    args.push("--force-base-mismatch");
                }
                args.push(s(&archive));
                assert_policy_refusal(&env, &archive, &link, &args);
            }
        }
    }
    for missing in [false, true] {
        for force in [false, true] {
            let (env, archive, overlay) = symlink_policy_fixture();
            if missing {
                fs::remove_file(&archive).unwrap();
            }
            let link = policy_link(&env, &overlay, suffix, "regular");
            let file_url = format!("file://{}", archive.display());
            let mut args = vec!["--commit-overlay", "--yes", "-w", s(&overlay)];
            if force {
                args.push("--force-base-mismatch");
            }
            args.push(&file_url);
            assert_policy_refusal(&env, &archive, &link, &args);
        }
    }
}

/// Regression: #239 offline DB links must refuse before any write, including force and missing bases.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_commit_refuses_symlinked_db() {
    offline_symlink_cases("");
}

/// Regression: #239 offline WAL links must refuse before archive publication or SQLite recovery.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_commit_refuses_symlinked_wal() {
    offline_symlink_cases("-wal");
}

/// Regression: #239 offline journal links must refuse before archive publication or SQLite recovery.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_commit_refuses_symlinked_journal() {
    offline_symlink_cases("-journal");
}

/// Regression: #239 offline SHM links must refuse before archive publication or SQLite recovery.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_commit_refuses_symlinked_shm() {
    offline_symlink_cases("-shm");
}

/// Regression: #239 no-mount recovery validates top/lower state before no-journal,
/// stale locator, torn/complete journal and prepared-index early-return paths.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_no_mount_refuses_symlinked_overlay_state() {
    for suffix in ["", "-wal", "-journal", "-shm"] {
        for journal in ["none", "prepare", "torn", "complete", "missing", "prepared"] {
            for lower in [false, true] {
                for force in [false, true] {
                    let (env, archive, overlay) = symlink_policy_fixture();
                    match journal {
                        "prepare" => {
                            let len = fs::metadata(&archive).unwrap().len();
                            let mut suffix = tempfile::tempfile().unwrap();
                            std::io::Write::write_all(&mut suffix, &[0; 1536]).unwrap();
                            let out = ratarmount_compress::commit_journal::replace_suffix_with_hook(
                                &archive,
                                len - 1024,
                                &mut suffix,
                                &mut |step| {
                                    if step == "locator prepare" {
                                        Err(std::io::Error::other("crash"))
                                    } else {
                                        Ok(())
                                    }
                                },
                            );
                            assert!(out.is_err());
                            let _ = fs::remove_file(
                                ratarmount_compress::commit_journal::journal_path(&archive),
                            );
                            assert_eq!(policy_locator(&archive).get(4), Some(&b'P'));
                        }
                        "torn" => interrupt_append(&archive),
                        "complete" => interrupt_complete(&archive),
                        "missing" => fs::remove_file(&archive).unwrap(),
                        _ => {}
                    }
                    let link = policy_link(&env, &overlay, suffix, "regular");
                    let mut args = vec!["--no-mount"];
                    if journal != "prepared" {
                        args.extend(["--index-file", ":memory:"]);
                    }
                    if lower {
                        args.extend(["--lower", s(&overlay), "--allow-unsealed-lower"]);
                    } else {
                        args.extend(["-w", s(&overlay)]);
                    }
                    if force {
                        args.push(if lower {
                            "--force-stack-mismatch"
                        } else {
                            "--force-base-mismatch"
                        });
                    }
                    if journal == "prepared" {
                        args.push("--no-recreate-index");
                    }
                    args.push(s(&archive));
                    assert_policy_refusal(&env, &archive, &link, &args);
                }
            }
        }
    }
}

/// Regression: #239 regular database and raw-directory commits retain their successful behavior.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_commit_regular_and_raw_controls() {
    for raw in [false, true] {
        let (env, archive, overlay) = symlink_policy_fixture();
        let overlay = if raw {
            let dir = env.path("raw");
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("added.txt"), b"addition\n").unwrap();
            dir
        } else {
            overlay
        };
        env.ok(&[
            "--commit-overlay",
            "--commit-overlay-mode",
            "append",
            "--yes",
            "-w",
            s(&overlay),
            s(&archive),
        ]);
        let mut reader = tar::Archive::new(fs::File::open(&archive).unwrap());
        assert!(reader
            .entries()
            .unwrap()
            .any(|entry| entry.unwrap().path().unwrap() == Path::new("added.txt")));
    }
}

fn regression_238_tar(env: &Env) -> PathBuf {
    let archive = env.path("base.tar");
    let mut builder = tar::Builder::new(fs::File::create(&archive).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(2);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "a.txt", &b"a\n"[..])
        .unwrap();
    builder.finish().unwrap();
    archive
}

fn regression_238_overlay(env: &Env, archive: &Path) -> PathBuf {
    let overlay = env.path("overlay");
    env.ok(&["--no-mount", "-w", s(&overlay), s(archive)]);
    fs::write(overlay.join("new.txt"), b"new\n").unwrap();
    overlay
}

fn regression_238_refusal_errors(overlay: &Path, out: &Output) -> Vec<String> {
    let expected = format!(
        "error: overlay {} is sealed; mount it with --lower, or `overlay unseal`",
        overlay.display()
    );
    let mut errors = Vec::new();
    if out.status.code() != Some(1) {
        errors.push(format!("expected exit 1: {}", text(out)));
    }
    if !String::from_utf8_lossy(&out.stderr)
        .lines()
        .any(|line| line == expected)
    {
        errors.push(format!("missing exact sealed refusal: {}", text(out)));
    }
    if [
        "created empty archive",
        "initialized empty archive",
        "Committed successfully",
        "Committed .tar.zst",
    ]
    .iter()
    .any(|message| text(out).contains(message))
    {
        errors.push(format!("unexpected mutation success output: {}", text(out)));
    }
    errors
}

/// Regression: #238 sealed commits created a missing base before refusing,
/// including when --force-base-mismatch was supplied.
#[test]
fn regression_238_sealed_missing_archive_not_created() {
    let env = Env::new();
    let archive = regression_238_tar(&env);
    let overlay = regression_238_overlay(&env, &archive);
    env.ok(&["overlay", "seal", s(&overlay), s(&archive)]);
    let mut errors = Vec::new();
    for extra in [None, Some("--force-base-mismatch")] {
        if archive.exists() {
            fs::remove_file(&archive).unwrap();
        }
        let mut args = vec!["--commit-overlay", "-w", s(&overlay), "--yes"];
        args.extend(extra);
        args.push(s(&archive));
        let out = env.run(&args);
        errors.extend(regression_238_refusal_errors(&overlay, &out));
        if archive.exists() {
            errors.push(format!(
                "{extra:?}: sealed commit created the missing archive"
            ));
        }
    }
    env.ok(&["overlay", "unseal", s(&overlay), "--i-know"]);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Regression: #238 sealed commits initialized a zero-byte base before refusing.
#[test]
fn regression_238_sealed_empty_archive_not_initialized() {
    let env = Env::new();
    let archive = regression_238_tar(&env);
    let overlay = regression_238_overlay(&env, &archive);
    env.ok(&["overlay", "seal", s(&overlay), s(&archive)]);
    let mut errors = Vec::new();
    for extra in [None, Some("--force-base-mismatch")] {
        fs::write(&archive, []).unwrap();
        let mut args = vec!["--commit-overlay", "-w", s(&overlay), "--yes"];
        args.extend(extra);
        args.push(s(&archive));
        let out = env.run(&args);
        errors.extend(regression_238_refusal_errors(&overlay, &out));
        if !archive.is_file() || !fs::read(&archive).unwrap().is_empty() {
            errors.push(format!(
                "{extra:?}: sealed commit initialized the empty archive"
            ));
        }
    }
    env.ok(&["overlay", "unseal", s(&overlay), "--i-know"]);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Reap each owned subprocess even if a readiness assertion or seal fails.
struct Regression238Child(Option<Child>);

impl Drop for Regression238Child {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Regression: #238 a seal starting during confirmation must wait for each
/// persistence route to finish, then seal its new base digest or refuse.
#[test]
fn regression_238_seal_after_confirmation_waits_for_commit() {
    let mut errors = Vec::new();
    for (route, mode, yes) in [
        ("tar-append", "append", false),
        ("tar-auto", "auto", false),
        ("tar-copy", "copy", false),
        ("zip-copy", "copy", false),
        ("zstd-append", "append", false),
        ("zstd-copy", "copy", false),
        ("metadata-append", "append", false),
        ("metadata-copy", "copy", false),
        ("gzip-copy", "copy", false),
        ("tar-yes", "append", true),
    ] {
        if matches!(route, "tar-copy" | "gzip-copy") && !have_gnu_tar() {
            eprintln!("skip: {route} publication requires GNU tar");
            continue;
        }
        if mode != "copy" && !cfg!(any(target_os = "linux", target_os = "macos")) {
            eprintln!("skip: {route} journaled append requires Linux/macOS inode xattrs");
            continue;
        }
        let env = Env::new();
        let tar = regression_238_tar(&env);
        let archive = if route.starts_with("zstd") {
            let plain = fs::read(&tar).unwrap();
            let mut frame = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
            let table = ratarmount_compress::build_seek_table_skippable(&[(
                u32::try_from(frame.len()).unwrap(),
                u32::try_from(plain.len()).unwrap(),
            )]);
            frame.extend(table);
            let archive = env.path("base.tar.zst");
            fs::write(&archive, frame).unwrap();
            let map = ratarmount_compress::scan_zstd_frames_path(&archive).unwrap();
            assert!(
                map.seek_table.is_some(),
                "zstd append fixture must be eligible"
            );
            assert_eq!(map.frames.len(), 1);
            archive
        } else if route.starts_with("gzip") {
            let archive = env.path("base.tar.gz");
            let mut encoder = flate2::write::GzEncoder::new(
                fs::File::create(&archive).unwrap(),
                flate2::Compression::default(),
            );
            encoder.write_all(&fs::read(&tar).unwrap()).unwrap();
            encoder.finish().unwrap();
            archive
        } else if route.starts_with("zip") {
            // The valid empty ZIP EOCD needs no external producer or new dependency.
            let archive = env.path("base.zip");
            let mut eocd = vec![0; 22];
            eocd[..4].copy_from_slice(b"PK\x05\x06");
            fs::write(&archive, eocd).unwrap();
            archive
        } else {
            tar
        };
        let overlay = regression_238_overlay(&env, &archive);
        if route.starts_with("metadata") {
            let metadata_path = if mode == "append" {
                // Metadata on a new member has no base header to delete, so
                // provenance persistence remains eligible for append.
                "/new.txt"
            } else {
                fs::remove_file(overlay.join("new.txt")).unwrap();
                "/a.txt"
            };
            let conn = rusqlite::Connection::open(overlay.join(ratarmount_compositing::HIDDEN_DB))
                .unwrap();
            conn.execute(
                "INSERT INTO overlay_metadata(path,mode) VALUES (?1,384)",
                [metadata_path],
            )
            .unwrap();
            assert_eq!(
                conn.query_row("SELECT count(*) FROM overlay_metadata", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        // Adds-only TAR/zstd plans and a singly linked base make append/Auto
        // eligible. The explicit mode pins copy rows to their publishers.
        assert!(!overlay.join("a.txt").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(&archive).unwrap().nlink(), 1);
        }
        let before = fs::read(&archive).unwrap();
        let ready = env.path("commit-ready");
        let release = env.path("commit-release");
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command
            .env("HOME", env.root.path())
            .env("XDG_CACHE_HOME", env.path(".cache"))
            .env("RATARMOUNT_TEST_COMMIT_READY", &ready)
            .env("RATARMOUNT_TEST_COMMIT_RELEASE", &release)
            .args([
                "--commit-overlay",
                "-w",
                s(&overlay),
                "--commit-overlay-mode",
                mode,
                s(&archive),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if yes {
            command.arg("--yes");
        }
        let mut child = Regression238Child(Some(command.spawn().unwrap()));
        child
            .0
            .as_mut()
            .unwrap()
            .stdin
            .take()
            .unwrap()
            .write_all(b"commit\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "{route}: confirmation hook timed out"
            );
            if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                let out = child.0.take().unwrap().wait_with_output().unwrap();
                panic!("{route}: commit exited before READY: {}", text(&out));
            }
            // File readiness, rather than an elapsed delay, orders the seal.
            std::thread::sleep(Duration::from_millis(10));
        }
        let contended = env.path("seal-contended");
        let mut seal = Regression238Child::spawn(
            &env,
            &["overlay", "seal", s(&overlay), s(&archive)],
            &[("RATARMOUNT_TEST_OVERLAY_CONTENDED", &contended)],
        );
        let blocked = seal.marker_or_exit(&contended);
        fs::write(&release, b"release").unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "{route}: commit did not finish after RELEASE"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = child.0.take().unwrap().wait_with_output().unwrap();
        let sealed = seal.finish();
        if !blocked {
            errors.push(format!(
                "{route}: seal did not wait for commit's overlay lock: {}",
                text(&sealed)
            ));
        }
        if !out.status.success() {
            errors.push(format!("{route}: commit failed: {}", text(&out)));
        }
        let after = fs::read(&archive).unwrap();
        if after == before {
            errors.push(format!("{route}: commit did not change archive bytes"));
        }
        if !sealed.status.success() {
            assert!(
                !ratarmount_compositing::OverlayMeta::read(&overlay)
                    .unwrap()
                    .unwrap()
                    .layer_sealed(),
                "{route}: failed seal published metadata"
            );
            env.ok(&["overlay", "seal", s(&overlay), s(&archive)]);
        }
        assert_eq!(
            regression_238_recorded_archive_digest(&overlay),
            format!("sha256:{}", ratarmount_index::sha256_hex(&after)),
            "{route}: seal must bind the completed commit"
        );
        let verify = env.run(&["overlay", "verify", s(&overlay), s(&archive)]);
        if !verify.status.success() {
            errors.push(format!(
                "{route}: sealed overlay verification failed: {}",
                text(&verify)
            ));
        }
        env.ok(&["overlay", "unseal", s(&overlay), "--i-know"]);
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

impl Regression238Child {
    fn spawn(env: &Env, args: &[&str], hooks: &[(&str, &Path)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command
            .env("HOME", env.root.path())
            .env("XDG_CACHE_HOME", env.path(".cache"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, path) in hooks {
            command.env(key, path);
        }
        Self(Some(command.spawn().unwrap()))
    }

    /// An explicit hook or process exit orders the next action; elapsed time
    /// never establishes that the other process reached the overlay lock.
    fn marker_or_exit(&mut self, marker: &Path) -> bool {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if marker.is_file() {
                return true;
            }
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return false;
            }
            assert!(
                Instant::now() < deadline,
                "waiting for {}",
                marker.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "child did not finish after release"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

fn regression_238_recorded_archive_digest(overlay: &Path) -> String {
    ratarmount_compositing::OverlayMeta::read(overlay)
        .unwrap()
        .unwrap()
        .base_digest()
        .unwrap()
        .to_owned()
}

/// Regression: #238 a seal starting after before_write hashed the old
/// archive while commit wrote it, leaving a stale sealed base digest.
/// Both inode-preserving replacement and copy publication must exclude seal.
#[test]
fn regression_238_seal_during_write_waits_for_overlay_lock() {
    let mut errors = Vec::new();
    for mode in ["append", "copy"] {
        if mode == "copy" && !have_gnu_tar() {
            eprintln!("skip: copy publication requires GNU tar; append still tests the core race");
            continue;
        }
        if mode == "append" && !cfg!(any(target_os = "linux", target_os = "macos")) {
            eprintln!("skip: append requires Linux/macOS inode xattrs");
            continue;
        }
        let env = Env::new();
        let archive = regression_238_tar(&env);
        let overlay = regression_238_overlay(&env, &archive);
        let before = fs::read(&archive).unwrap();
        let ready = env.path("prewrite-ready");
        let release = env.path("prewrite-release");
        let contended = env.path("seal-contended");
        let mut commit = Regression238Child::spawn(
            &env,
            &[
                "--commit-overlay",
                "-w",
                s(&overlay),
                s(&archive),
                "--commit-overlay-mode",
                mode,
                "--yes",
            ],
            &[
                ("RATARMOUNT_TEST_PREWRITE_READY", &ready),
                ("RATARMOUNT_TEST_PREWRITE_RELEASE", &release),
            ],
        );
        assert!(
            commit.marker_or_exit(&ready),
            "{mode}: commit exited before its write hook: {}",
            text(&commit.finish())
        );
        assert_eq!(
            fs::read(&archive).unwrap(),
            before,
            "{mode}: prewrite hook ran after archive mutation"
        );
        let mut seal = Regression238Child::spawn(
            &env,
            &["overlay", "seal", s(&overlay), s(&archive)],
            &[("RATARMOUNT_TEST_OVERLAY_CONTENDED", &contended)],
        );
        let blocked = seal.marker_or_exit(&contended);
        fs::write(&release, b"release").unwrap();
        let committed = commit.finish();
        let sealed = seal.finish();
        let after = fs::read(&archive).unwrap();
        if !blocked {
            errors.push(format!(
                "{mode}: seal finished while commit held its overlay lock: {}",
                text(&sealed)
            ));
        }
        if !committed.status.success() {
            errors.push(format!("{mode}: commit failed: {}", text(&committed)));
        }
        if before == after {
            errors.push(format!(
                "{mode}: commit fixture did not change archive bytes"
            ));
        }
        let expected = format!("sha256:{}", ratarmount_index::sha256_hex(&after));
        if sealed.status.success() {
            let recorded = regression_238_recorded_archive_digest(&overlay);
            if recorded != expected {
                errors.push(format!(
                    "{mode}: seal recorded {recorded}, post-commit archive digest is {expected}"
                ));
            }
        } else {
            assert!(
                !ratarmount_compositing::OverlayMeta::read(&overlay)
                    .unwrap()
                    .unwrap()
                    .layer_sealed(),
                "{mode}: refused seal must not leave seal metadata: {}",
                text(&sealed)
            );
            // A retry against the completed commit must record precisely the
            // post-commit bytes, including after a copy changed the inode.
            env.ok(&["overlay", "seal", s(&overlay), s(&archive)]);
            assert_eq!(regression_238_recorded_archive_digest(&overlay), expected);
        }
        let verified = env.run(&["overlay", "verify", s(&overlay), s(&archive)]);
        if !verified.status.success() {
            errors.push(format!(
                "{mode}: post-commit seal failed verification: {}",
                text(&verified)
            ));
        }
        env.ok(&["overlay", "unseal", s(&overlay), "--i-know"]);
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Regression: #238 a seal's DB reservation did not stop a concurrent commit.
/// Seal owns the overlay lock first; a waiting commit must recheck sealing
/// after taking that lock and preserve every archive byte.
#[test]
fn regression_238_commit_waits_for_seal_then_refuses() {
    let mut errors = Vec::new();
    for mode in ["append", "copy"] {
        if mode == "copy" && !have_gnu_tar() {
            eprintln!("skip: copy publication requires GNU tar; append still tests the core race");
            continue;
        }
        if mode == "append" && !cfg!(any(target_os = "linux", target_os = "macos")) {
            eprintln!("skip: append requires Linux/macOS inode xattrs");
            continue;
        }
        let env = Env::new();
        let archive = regression_238_tar(&env);
        let overlay = regression_238_overlay(&env, &archive);
        let before = fs::read(&archive).unwrap();
        let seal_ready = env.path("seal-lock-ready");
        let seal_release = env.path("seal-lock-release");
        let contended = env.path("commit-contended");
        let mut seal = Regression238Child::spawn(
            &env,
            &["overlay", "seal", s(&overlay), s(&archive)],
            &[
                ("RATARMOUNT_TEST_SEAL_LOCK_READY", &seal_ready),
                ("RATARMOUNT_TEST_SEAL_LOCK_RELEASE", &seal_release),
            ],
        );
        assert!(
            seal.marker_or_exit(&seal_ready),
            "{mode}: seal exited before overlay-lock hook: {}",
            text(&seal.finish())
        );
        let mut commit = Regression238Child::spawn(
            &env,
            &[
                "--commit-overlay",
                "-w",
                s(&overlay),
                s(&archive),
                "--commit-overlay-mode",
                mode,
                "--yes",
            ],
            &[("RATARMOUNT_TEST_OVERLAY_CONTENDED", &contended)],
        );
        let blocked = commit.marker_or_exit(&contended);
        fs::write(&seal_release, b"release").unwrap();
        let sealed = seal.finish();
        let committed = commit.finish();
        if !blocked {
            errors.push(format!(
                "{mode}: commit finished while seal held its overlay lock: {}",
                text(&committed)
            ));
        }
        if !sealed.status.success() {
            errors.push(format!("{mode}: seal failed: {}", text(&sealed)));
        }
        errors.extend(
            regression_238_refusal_errors(&overlay, &committed)
                .into_iter()
                .map(|e| format!("{mode}: {e}")),
        );
        if fs::read(&archive).unwrap() != before {
            errors.push(format!(
                "{mode}: archive changed while sealing won the overlay lock"
            ));
        }
        if sealed.status.success() {
            let expected = format!("sha256:{}", ratarmount_index::sha256_hex(&before));
            let recorded = regression_238_recorded_archive_digest(&overlay);
            if recorded != expected {
                errors.push(format!(
                    "{mode}: seal recorded {recorded}, unchanged archive digest must be {expected}"
                ));
            }
            let verified = env.run(&["overlay", "verify", s(&overlay), s(&archive)]);
            if !verified.status.success() {
                errors.push(format!(
                    "{mode}: seal failed verification: {}",
                    text(&verified)
                ));
            }
            env.ok(&["overlay", "unseal", s(&overlay), "--i-know"]);
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Regression: #240 CLI archive creation/initialization ran before the overlay
/// lock. A seal against an accepted second base copy must block that work, then
/// make the waiting commit refuse without creating or filling its own target.
#[test]
fn regression_240_seal_blocks_cli_archive_initialization() {
    for empty in [false, true] {
        let env = Env::new();
        let archive = regression_238_tar(&env);
        let seal_base = env.path("seal-base.tar");
        fs::copy(&archive, &seal_base).unwrap();
        let overlay = env.path("overlay");
        env.ok(&[
            "--no-mount",
            "-w",
            s(&overlay),
            "--base-digest",
            "none",
            s(&archive),
        ]);
        fs::write(overlay.join("new.txt"), b"new\n").unwrap();
        if empty {
            fs::write(&archive, b"").unwrap();
        } else {
            fs::remove_file(&archive).unwrap();
        }
        let state = || match fs::read(&archive) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read target: {error}"),
        };
        let before = state();
        let seal_ready = env.path("seal-ready");
        let seal_release = env.path("seal-release");
        let contended = env.path("commit-contended");
        let mut seal = Regression238Child::spawn(
            &env,
            &["overlay", "seal", s(&overlay), s(&seal_base)],
            &[
                ("RATARMOUNT_TEST_SEAL_LOCK_READY", &seal_ready),
                ("RATARMOUNT_TEST_SEAL_LOCK_RELEASE", &seal_release),
            ],
        );
        assert!(
            seal.marker_or_exit(&seal_ready),
            "empty={empty}: seal did not reach its overlay lock: {}",
            text(&seal.finish())
        );
        let mut commit = Regression238Child::spawn(
            &env,
            &[
                "--commit-overlay",
                "-w",
                s(&overlay),
                s(&archive),
                "--force-base-mismatch",
                "--yes",
            ],
            &[("RATARMOUNT_TEST_OVERLAY_CONTENDED", &contended)],
        );
        let blocked = commit.marker_or_exit(&contended);
        let while_sealing = state();
        fs::write(&seal_release, b"release").unwrap();
        let sealed = seal.finish();
        let committed = commit.finish();
        assert!(
            blocked,
            "empty={empty}: commit did not wait: {}",
            text(&committed)
        );
        assert!(sealed.status.success(), "empty={empty}: {}", text(&sealed));
        assert_eq!(
            while_sealing, before,
            "empty={empty}: target changed before the overlay lock"
        );
        assert_eq!(
            state(),
            before,
            "empty={empty}: refused commit changed target"
        );
        assert!(
            regression_238_refusal_errors(&overlay, &committed).is_empty(),
            "empty={empty}: {}",
            text(&committed)
        );
        env.ok(&["overlay", "unseal", s(&overlay), "--i-know"]);
    }
}

/// Regression: #239 symlink policy takes precedence over #240 seal refusal,
/// and both checks must run before a missing base can be created.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_239_240_sealed_symlink_policy_precedes_base_creation() {
    use std::os::unix::fs::PermissionsExt;

    for suffix in ["", "-wal"] {
        let (env, archive, overlay) = symlink_policy_fixture();
        env.ok(&["overlay", "seal", s(&overlay), s(&archive)]);
        // Plant the invalid state without changing the recorded seal metadata.
        let mode = fs::metadata(&overlay).unwrap().permissions().mode();
        fs::set_permissions(&overlay, fs::Permissions::from_mode(mode | 0o200)).unwrap();
        let link = policy_link(&env, &overlay, suffix, "regular");
        fs::remove_file(&archive).unwrap();
        let before = policy_snapshot(env.root.path());
        for force in [false, true] {
            let mut args = vec!["--commit-overlay", "--yes", "-w", s(&overlay)];
            if force {
                args.push("--force-base-mismatch");
            }
            args.push(s(&archive));
            let out = env.run(&args);
            assert_eq!(out.status.code(), Some(1), "{args:?}: {}", text(&out));
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(
                err.contains("is a symlink; it must be a regular file"),
                "{err}"
            );
            assert!(!err.contains("is sealed"), "{err}");
            assert!(!err.contains("--force"), "{err}");
            assert!(!archive.exists(), "{args:?}: missing base was created");
            assert_eq!(
                policy_snapshot(env.root.path()),
                before,
                "{args:?}: state changed: {}",
                text(&out)
            );
        }
        fs::remove_file(link).unwrap();
        if suffix.is_empty() {
            fs::rename(
                env.path("saved-db"),
                overlay.join(ratarmount_compositing::HIDDEN_DB),
            )
            .unwrap();
        }
        env.ok(&["overlay", "unseal", s(&overlay), "--i-know"]);
    }
}
