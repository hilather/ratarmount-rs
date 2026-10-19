//! Offline `--commit-overlay` identity: the recorded kind and the Unknown gate
//! run before anything is written, the archive is classified without building
//! an index, no sidecar is written or rewritten, and a stale sidecar cannot
//! stand in the way of `--force-base-mismatch`.
//!
//! CLI-level, offline (no FUSE), private HOME / XDG_CACHE_HOME per test.

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
