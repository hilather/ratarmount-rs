//! Overlay identity and CLI inspection stop at --no-mount; no /dev/fuse needed.

use std::path::Path;
use std::process::{Command, Output};

use ratarmount_compositing::{OverlayMeta, HIDDEN_DB};
use sha2::{Digest, Sha256};

fn open(overlay: &Path, base: &Path, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["--no-mount", "--index-file", ":memory:", "-w"])
        .arg(overlay)
        .args(flags)
        .arg(base)
        .output()
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Regression: mount startup did not record the base URL or digest for offline info.
#[test]
fn regression_overlay_meta_cli_creation_info_and_remount() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("base.tar");
    std::fs::write(&archive, [0u8; 1024]).unwrap();
    let overlay = root.path().join("overlay");
    assert_success(&open(&overlay, &archive, &[]));
    let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "info"])
        .arg(&overlay)
        .arg("--json")
        .output()
        .unwrap();
    assert_success(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["base_url"], archive.to_str().unwrap());
    // `--no-mount` never serves, so nothing hashed the archive: pending (spec
    // 1.2: hashing is lazy). Seal/verbs and the mount's hasher resolve it.
    assert_eq!(value["base_digest"], serde_json::Value::Null);
    assert_eq!(value["base_digest_kind"], "pending");
    assert_eq!(value["format_version"], "2");
    assert_eq!(value["legacy"], false);
    assert_eq!(value["files_present"], 0);
    assert_eq!(value["db_opens_read_only"], true);
    assert_success(&open(&overlay, &archive, &[]));
    std::fs::write(&archive, [0u8; 2048]).unwrap();
    let refused = open(&overlay, &archive, &[]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("base mismatch"));
    assert_success(&open(&overlay, &archive, &["--force-base-mismatch"]));
    assert!(OverlayMeta::read(&overlay)
        .unwrap()
        .unwrap()
        .get("base_mismatch_forced_at")
        .is_some());
}

/// Regression: --base-digest none silently omitted the disabled-verification warning.
#[test]
fn regression_overlay_meta_cli_none_warns_and_supplied_is_recorded() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let overlay = root.path().join("none");
    let output = open(&overlay, &source, &["--base-digest", "none"]);
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("warning: --base-digest none"));
    assert_eq!(
        OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .base_digest_kind(),
        Some("none")
    );
    let supplied = format!("sha256:{}", "a".repeat(64));
    let overlay = root.path().join("supplied");
    assert_success(&open(&overlay, &source, &["--base-digest", &supplied]));
    assert_eq!(
        OverlayMeta::read(&overlay).unwrap().unwrap().base_digest(),
        Some(supplied.as_str())
    );
}

/// Regression: info on an old overlay must stay legacy after a writable mount migrates it.
#[test]
fn regression_overlay_meta_cli_legacy_info_after_migration() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let overlay = root.path().join("overlay");
    std::fs::create_dir(&overlay).unwrap();
    let conn = rusqlite::Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    conn.execute_batch("CREATE TABLE files (path TEXT, name TEXT, mtime REAL, mode INTEGER, uid INTEGER, gid INTEGER, deleted BOOL, PRIMARY KEY(path,name));").unwrap();
    drop(conn);
    assert_success(&open(&overlay, &source, &[]));
    let output = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "info"])
        .arg(&overlay)
        .arg("--json")
        .output()
        .unwrap();
    assert_success(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["legacy"], true);
    assert_eq!(value["format_version"], "1");
    assert!(value.get("base_digest").is_none());
}

/// Regression: a `git:///repo#rev` base was hashed as a missing local file
/// ("cannot hash base git:///…: No such file or directory") instead of
/// recording `git-tree:<sha>`.
#[test]
fn regression_overlay_meta_git_url_base_records_git_tree() {
    let root = tempfile::tempdir().unwrap();
    let repo_dir = root.path().join("repo");
    let repo = git2::Repository::init(&repo_dir).unwrap();
    let blob = repo.blob(b"hi\n").unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder.insert("a.txt", blob, 0o100644).unwrap();
    let tree_id = builder.write().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = git2::Signature::new("t", "t@t", &git2::Time::new(0, 0)).unwrap();
    let commit = repo
        .commit(Some("HEAD"), &sig, &sig, "x", &tree, &[])
        .unwrap();

    for (name, url) in [
        ("pinned", format!("git://{}#{commit}", repo_dir.display())),
        ("head", format!("git://{}", repo_dir.display())),
    ] {
        let overlay = root.path().join(name);
        assert_success(&open(&overlay, Path::new(&url), &[]));
        let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
        assert_eq!(meta.base_url(), Some(url.as_str()));
        assert_eq!(
            meta.base_digest(),
            Some(format!("git-tree:{tree_id}").as_str())
        );
        assert_eq!(meta.base_digest_kind(), Some("git-tree"));
        // Remount verifies the tree cheaply and succeeds.
        assert_success(&open(&overlay, Path::new(&url), &[]));
    }
}

/// Regression: `overlay info` did not show which read-only rules the last
/// writable mount enforced, and a later mount without rules left stale ones.
#[test]
fn regression_overlay_meta_records_readonly_rules() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("base.tar");
    std::fs::write(&archive, [0u8; 1024]).unwrap();
    let overlay = root.path().join("overlay");
    assert_success(&open(
        &overlay,
        &archive,
        &[
            "--overlay-readonly",
            "t/**",
            "--overlay-allow",
            "t/agent/**",
        ],
    ));
    let rules = |overlay: &Path| -> serde_json::Value {
        let meta = OverlayMeta::read(overlay).unwrap().unwrap();
        serde_json::from_str(meta.get("readonly_rules").unwrap()).unwrap()
    };
    assert_eq!(
        rules(&overlay),
        serde_json::json!({"readonly": ["t/**"], "allow": ["t/agent/**"]})
    );
    assert_success(&open(&overlay, &archive, &[]));
    assert_eq!(
        rules(&overlay),
        serde_json::json!({"readonly": [], "allow": []})
    );
}

/// Private `HOME`/`XDG_CACHE_HOME` so no test touches the user's caches.
fn private_env(cmd: &mut Command, dir: &Path) {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    cmd.env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join(".cache"));
}

/// Bytes the process has read so far, from `/proc/<pid>/io` (`rchar`).
#[cfg(target_os = "linux")]
fn rchar(pid: u32) -> Option<u64> {
    let io = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    io.lines()
        .find_map(|l| l.strip_prefix("rchar: "))
        .and_then(|v| v.trim().parse().ok())
}

/// Regression: a writable mount over a 1 GiB directory base hashed every file
/// before it was ready (65-86 s debug, ~4.8 s release). Without `--base-digest`
/// the mount must read no base content (Linux; needs /dev/fuse).
#[cfg(target_os = "linux")]
#[test]
fn regression_mount_1gib_directory_base_reads_no_content_without_base_digest() {
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};
    if !Path::new("/dev/fuse").exists()
        || Command::new("fusermount3")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("skip: /dev/fuse or fusermount3 unavailable");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    std::fs::create_dir_all(base.join("sub")).unwrap();
    let big = std::fs::File::create(base.join("big.bin")).unwrap();
    if big.set_len(1 << 30).is_err() {
        eprintln!("skip: filesystem refuses sparse files");
        return;
    }
    std::fs::write(base.join("small.txt"), b"hello").unwrap();
    std::fs::write(base.join("sub/inner.txt"), b"inner").unwrap();
    let mnt = root.path().join("mnt");
    std::fs::create_dir(&mnt).unwrap();
    let overlay = root.path().join("overlay");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    private_env(&mut cmd, root.path());
    let start = Instant::now();
    let mut child = cmd
        .args([
            "-f",
            "--passthrough",
            "off",
            "--index-file",
            ":memory:",
            "-w",
        ])
        .arg(&overlay)
        .arg(&base)
        .arg(&mnt)
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let parent_dev = std::fs::metadata(root.path()).unwrap().dev();
    let deadline = start + Duration::from_secs(20);
    let ready = loop {
        if std::fs::metadata(&mnt).is_ok_and(|m| m.dev() != parent_dev)
            && std::fs::read_dir(&mnt).is_ok_and(|mut d| d.next().is_some())
        {
            break Some(start.elapsed());
        }
        if Instant::now() > deadline || child.try_wait().unwrap().is_some() {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let read = rchar(child.id());
    let unmount = || {
        let _ = Command::new("fusermount3").arg("-u").arg(&mnt).status();
    };
    let Some(ready_after) = ready else {
        unmount();
        let _ = child.kill();
        let _ = child.wait();
        panic!("not ready within 20 s (the mount hashes the base)");
    };
    unmount();
    let status = child.wait().unwrap();
    let read = read.expect("/proc/<pid>/io readable");
    assert!(
        read < 4 << 20,
        "mount read {read} bytes before it was ready"
    );
    if !cfg!(debug_assertions) {
        assert!(
            ready_after < Duration::from_secs(1),
            "ready after {ready_after:?}"
        );
    }
    let _ = status;
    let mut info = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    private_env(&mut info, root.path());
    let output = info
        .args(["overlay", "info", "--json"])
        .arg(&overlay)
        .output()
        .unwrap();
    assert_success(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["base_digest"].as_str().unwrap().starts_with("weak:"));
    assert_eq!(value["base_digest_kind"], "weak");
    assert_eq!(value["base_weak_digest"], value["base_digest"]);
    assert_eq!(value["base_digest_source"], "computed");
}

fn digest_base(args: &[&std::ffi::OsStr], dir: &Path) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    private_env(&mut cmd, dir);
    cmd.args(["overlay", "digest-base"])
        .args(args)
        .output()
        .unwrap()
}

fn listing(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    out.sort();
    out
}

/// Regression: there was no way to compute a strong directory digest once and
/// supply it; `overlay digest-base` prints exactly `directory_digest`/sha256.
#[test]
fn regression_overlay_digest_base_matches_directory_digest() {
    use std::ffi::OsStr;
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    std::fs::create_dir_all(base.join("sub")).unwrap();
    std::fs::write(base.join("sub/a"), b"alpha").unwrap();
    let before = listing(&base);
    let out = digest_base(&[base.as_os_str()], root.path());
    assert_success(&out);
    let printed = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert_eq!(
        printed,
        ratarmount_compositing::directory_digest(&base).unwrap()
    );
    assert_eq!(listing(&base), before, "digest-base must create nothing");

    let json = digest_base(&[base.as_os_str(), OsStr::new("--json")], root.path());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["kind"], "directory");
    assert_eq!(value["digest"], printed.as_str());

    let archive = root.path().join("a.tar");
    std::fs::write(&archive, [7u8; 100]).unwrap();
    let out = digest_base(&[archive.as_os_str()], root.path());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        format!("sha256:{:x}", Sha256::digest([7u8; 100]))
    );

    // The printed value is accepted by --base-digest and recorded as strong,
    // with the weak companion kept for cheap remount checks.
    let overlay = root.path().join("overlay");
    assert_success(&open(&overlay, &base, &["--base-digest", &printed]));
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    assert_eq!(meta.base_digest(), Some(printed.as_str()));
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    assert_eq!(meta.get("base_digest_source"), Some("supplied"));
    assert!(meta.get("base_weak_digest").unwrap().starts_with("weak:"));

    let missing = digest_base(&[root.path().join("nope").as_os_str()], root.path());
    assert_eq!(missing.status.code(), Some(1));
    let fifo = base.join("pipe");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let refused = digest_base(&[base.as_os_str()], root.path());
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("cannot digest special file"));
}

/// Regression: a strong digest taken while an overlay lives inside the
/// directory would hash its SQLite files; it must be excluded explicitly.
#[test]
fn regression_digest_base_excludes_overlay_and_refuses_unexcluded_overlay() {
    use std::ffi::OsStr;
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    std::fs::create_dir(&base).unwrap();
    std::fs::write(base.join("f"), b"one").unwrap();
    let overlay = base.join(".ov");
    assert_success(&open(&overlay, &base, &[]));
    let refused = digest_base(&[base.as_os_str()], root.path());
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--exclude-overlay"));
    let args = [
        base.as_os_str(),
        OsStr::new("--exclude-overlay"),
        overlay.as_os_str(),
    ];
    let out = digest_base(&args, root.path());
    assert_success(&out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("excluding: .ov"));
    let digest = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert_ne!(digest, "");
    // Writing through the overlay (a fresh mount reopens it) leaves it unchanged.
    assert_success(&open(&overlay, &base, &[]));
    assert_eq!(
        String::from_utf8(digest_base(&args, root.path()).stdout)
            .unwrap()
            .trim(),
        digest
    );
    // A new overlay with that supplied digest records strong + weak companion.
    let second = base.join(".ov2");
    assert_success(&open(&second, &base, &["--base-digest", &digest]));
    assert_eq!(
        OverlayMeta::read(&second).unwrap().unwrap().base_digest(),
        Some(digest.as_str())
    );
}

/// Regression: a directory base edited between sessions was never noticed on
/// remount; it now refuses naming `--force-base-mismatch` (sidecars excepted).
#[test]
fn regression_overlay_meta_cli_directory_remount_refuses_edit() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    std::fs::create_dir(&base).unwrap();
    std::fs::write(base.join("f"), b"one").unwrap();
    let overlay = root.path().join("overlay");
    assert_success(&open(&overlay, &base, &[]));
    std::fs::write(base.join("f.index.sqlite"), b"idx").unwrap();
    assert_success(&open(&overlay, &base, &[]));
    std::fs::write(base.join("f"), b"edited").unwrap();
    let refused = open(&overlay, &base, &[]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--force-base-mismatch"));
    assert_success(&open(&overlay, &base, &["--force-base-mismatch"]));
}

/// A foreground `-w` mount of a tar whose background digest hash is held at a
/// gate file the test creates to release it. Linux with /dev/fuse only.
#[cfg(target_os = "linux")]
struct GatedMount {
    root: tempfile::TempDir,
    archive: std::path::PathBuf,
    overlay: std::path::PathBuf,
    mnt: std::path::PathBuf,
    gate: std::path::PathBuf,
    child: std::process::Child,
}

#[cfg(target_os = "linux")]
impl GatedMount {
    fn start() -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        use std::time::{Duration, Instant};
        if !Path::new("/dev/fuse").exists()
            || Command::new("fusermount3")
                .arg("--version")
                .output()
                .is_err()
        {
            eprintln!("skip: /dev/fuse or fusermount3 unavailable");
            return None;
        }
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("member.txt"), b"member bytes\n").unwrap();
        let archive = root.path().join("base.tar");
        assert!(Command::new("tar")
            .arg("cf")
            .arg(&archive)
            .arg("-C")
            .arg(&src)
            .arg("member.txt")
            .status()
            .unwrap()
            .success());
        let mnt = root.path().join("mnt");
        std::fs::create_dir(&mnt).unwrap();
        let overlay = root.path().join("overlay");
        let gate = root.path().join("gate");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        private_env(&mut cmd, root.path());
        let child = cmd
            .env("RATARMOUNT_TEST_HASH_GATE", &gate)
            .args([
                "-f",
                "--passthrough",
                "off",
                "--index-file",
                ":memory:",
                "-w",
            ])
            .arg(&overlay)
            .arg(&archive)
            .arg(&mnt)
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut mount = Self {
            root,
            archive,
            overlay,
            mnt,
            gate,
            child,
        };
        let parent_dev = std::fs::metadata(mount.root.path()).unwrap().dev();
        let deadline = Instant::now() + Duration::from_secs(20);
        // Ready means a member can be read, not merely that the mount exists.
        while std::fs::read(mount.mnt.join("member.txt")).ok().as_deref()
            != Some(b"member bytes\n".as_slice())
            || std::fs::metadata(&mount.mnt).unwrap().dev() == parent_dev
        {
            if Instant::now() > deadline || mount.child.try_wait().unwrap().is_some() {
                mount.unmount();
                panic!("mount not serving a member read within 20 s");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Some(mount)
    }

    /// The root `user.ratarmount.<name>` xattr.
    fn xattr(&self, name: &str) -> String {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(self.mnt.as_os_str().as_bytes()).unwrap();
        let key = std::ffi::CString::new(format!("user.ratarmount.{name}")).unwrap();
        let mut buf = vec![0u8; 4096];
        let n = unsafe {
            libc::getxattr(
                path.as_ptr(),
                key.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        assert!(
            n >= 0,
            "getxattr {name}: {}",
            std::io::Error::last_os_error()
        );
        String::from_utf8(buf[..n as usize].to_vec()).unwrap()
    }

    fn release(&self) {
        std::fs::write(&self.gate, b"go").unwrap();
    }

    fn unmount(&mut self) {
        let _ = Command::new("fusermount3")
            .arg("-u")
            .arg(&self.mnt)
            .status();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
impl Drop for GatedMount {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("fusermount3")
                .arg("-u")
                .arg(&self.mnt)
                .status();
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Regression: an uncached archive base was hashed before the mount served
/// (spec 1.2: hashing is lazy, after the mount is serving). With the hash held
/// at the gate the mount still serves a member read.
#[cfg(target_os = "linux")]
#[test]
fn regression_uncached_archive_base_mount_ready_before_hashing_finishes() {
    let Some(mut mount) = GatedMount::start() else {
        return;
    };
    // `start` only returns after a member read succeeded with the gate shut.
    assert!(!mount.gate.exists());
    mount.release();
    mount.unmount();
}

/// Regression: while the hash is gated the live digest xattrs are empty (not
/// the digest the old synchronous path had already recorded).
#[cfg(target_os = "linux")]
#[test]
fn regression_pending_xattrs_empty_while_gated() {
    let Some(mut mount) = GatedMount::start() else {
        return;
    };
    assert_eq!(mount.xattr("base_digest"), "");
    assert_eq!(mount.xattr("stack_digest"), "");
    mount.release();
    mount.unmount();
}

/// Regression: after the background hash finishes it records the digest
/// through the mount's own connection: xattrs change, and the overlay ends
/// `strong` with a stack digest.
#[cfg(target_os = "linux")]
#[test]
fn regression_pending_digest_recorded_after_hashing_finishes() {
    use std::time::{Duration, Instant};
    let Some(mut mount) = GatedMount::start() else {
        return;
    };
    let expected = format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(&mount.archive).unwrap())
    );
    mount.release();
    let deadline = Instant::now() + Duration::from_secs(20);
    while mount.xattr("base_digest") != expected {
        assert!(
            Instant::now() < deadline,
            "digest not recorded within 20 s: {:?}",
            mount.xattr("base_digest")
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        mount.xattr("stack_digest"),
        ratarmount_compositing::stack_digest(&expected, &[])
    );
    mount.unmount();
    let meta = OverlayMeta::read(&mount.overlay).unwrap().unwrap();
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    assert_eq!(meta.base_digest(), Some(expected.as_str()));
    assert!(meta.stack_digest().is_some());
}
