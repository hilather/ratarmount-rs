//! Overlay identity and CLI inspection stop at --no-mount; no /dev/fuse needed.

use std::path::Path;
use std::process::{Command, Output};

use ratarmount_compositing::{OverlayMeta, HIDDEN_DB};
use sha2::{Digest, Sha256};

#[path = "support/http_tar.rs"]
mod http_tar;
use http_tar::serve_tar_stub;

#[cfg(target_os = "linux")]
#[path = "support/unmount.rs"]
mod unmount;

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
    let Some(ready_after) = ready else {
        fail_mount_not_ready(&mnt, &mut child);
    };
    stop_mount(&mnt, &mut child, "mount_1gib");
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

/// Regression: #215, observe daemon exit without an unbounded wait, including
/// one final observation at the deadline before declaring a timeout.
#[cfg(target_os = "linux")]
fn poll_child_exit(
    child: &mut std::process::Child,
    limit: std::time::Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return child.try_wait();
        }
        std::thread::sleep(Duration::from_millis(20).min(deadline - now));
    }
}

/// Regression: #215, preserve shutdown failures even if forced cleanup reaps
/// the daemon. Cleanup mechanics return diagnostics and never panic in Drop.
#[cfg(target_os = "linux")]
fn finish_stop_mount(
    child: &mut std::process::Child,
    label: &str,
    unmounted: Result<(), String>,
    exit_limit: std::time::Duration,
) -> Result<(), String> {
    let pid = child.id();
    let mut errors = Vec::new();
    if let Err(error) = &unmounted {
        errors.push(format!("{label}: mount stayed busy: {error}"));
    }
    let exited = match poll_child_exit(child, exit_limit) {
        Ok(Some(_)) => true,
        Ok(None) => {
            if unmounted.is_ok() {
                errors.push(format!(
                    "{label}: daemon did not exit after a successful unmount within {exit_limit:?} (pid {pid})"
                ));
            }
            false
        }
        Err(error) => {
            errors.push(format!("{label}: polling daemon {pid} failed: {error}"));
            false
        }
    };
    if !exited {
        if let Err(error) = child.kill() {
            errors.push(format!("{label}: killing daemon {pid} failed: {error}"));
        }
        match poll_child_exit(child, std::time::Duration::from_secs(1)) {
            Ok(Some(_)) => {}
            Ok(None) => errors.push(format!(
                "{label}: daemon {pid} was not reaped within 1s after kill"
            )),
            Err(error) => errors.push(format!(
                "{label}: reaping daemon {pid} after kill failed: {error}"
            )),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Regression: #215, retry transient busy mounts and fail persistent unmount
/// or daemon-exit problems with a reason after bounded cleanup, rather than hang.
#[cfg(target_os = "linux")]
fn stop_mount(mnt: &Path, child: &mut std::process::Child, label: &str) {
    use std::time::Duration;
    let unmounted = unmount::unmount_within(mnt, Duration::from_secs(5), label);
    if let Err(error) = finish_stop_mount(child, label, unmounted, Duration::from_secs(10)) {
        panic!("{error}");
    }
}

/// Regression: #215, readiness cleanup must retain the original failure reason
/// while bounding reaping even when unmounting fails.
#[cfg(target_os = "linux")]
fn fail_mount_not_ready(mnt: &Path, child: &mut std::process::Child) -> ! {
    use std::time::Duration;
    let _ = unmount::unmount_within(mnt, Duration::from_secs(5), "mount_1gib not ready");
    let _ = child.kill();
    let _ = poll_child_exit(child, Duration::from_secs(1));
    panic!("not ready within 20 s (the mount hashes the base)");
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
            .args(["-f", "--passthrough", "off", "--index-file"])
            .arg(root.path().join("base.index.sqlite"))
            .arg("-w")
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
        stop_mount(&self.mnt, &mut self.child, "GatedMount::unmount");
    }
}

#[cfg(target_os = "linux")]
impl Drop for GatedMount {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let unmounted = unmount::unmount_within(
                &self.mnt,
                std::time::Duration::from_secs(5),
                "GatedMount::drop",
            );
            let _ = finish_stop_mount(
                &mut self.child,
                "GatedMount::drop",
                unmounted,
                std::time::Duration::from_secs(10),
            );
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
    assert_eq!(mount.xattr("base_digest_state"), "pending");
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
    assert_eq!(mount.xattr("base_digest_state"), "present");
    mount.unmount();
    let meta = OverlayMeta::read(&mount.overlay).unwrap().unwrap();
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    assert_eq!(meta.base_digest(), Some(expected.as_str()));
    assert!(meta.stack_digest().is_some());
}

/// Regression: a credentialed base URL (userinfo, presigned query) was stored in the
/// overlay DB and printed by `overlay info`, mount progress and `pack` meta.json.
#[test]
fn regression_credentialed_base_url_is_never_stored_or_printed() {
    let root = tempfile::tempdir().unwrap();
    let stub = serve_tar_stub();
    let port = stub.rsplit(':').next().unwrap();
    let url = format!("http://user:s3cr3t@127.0.0.1:{port}/base.tar?X-Amz-Signature=deadbeef");
    let overlay = root.path().join("overlay");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    private_env(&mut cmd, root.path());
    let mount = cmd
        .args(["--no-mount", "--index-file", ":memory:", "-w"])
        .arg(&overlay)
        .arg(&url)
        .output()
        .unwrap();
    assert_success(&mount);
    let mut seen = String::from_utf8_lossy(&mount.stdout).into_owned();
    seen.push_str(&String::from_utf8_lossy(&mount.stderr));
    let secrets = ["s3cr3t", "deadbeef"];
    for secret in secrets {
        assert!(
            !seen.contains(secret),
            "mount output leaked {secret}: {seen}"
        );
    }
    for json in [true, false] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        private_env(&mut cmd, root.path());
        cmd.args(["overlay", "info"]).arg(&overlay);
        if json {
            cmd.arg("--json");
        }
        let info = cmd.output().unwrap();
        assert_success(&info);
        let text = String::from_utf8_lossy(&info.stdout).into_owned();
        assert!(text.contains("127.0.0.1"), "{text}");
        for secret in secrets {
            assert!(
                !text.contains(secret),
                "overlay info leaked {secret}: {text}"
            );
        }
    }
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    for (key, value) in meta.values() {
        for secret in secrets {
            assert!(
                !value.contains(secret),
                "meta {key} leaked {secret}: {value}"
            );
        }
    }
}

fn set_meta(overlay: &Path, key: &str, value: &str) {
    let conn = rusqlite::Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)",
        [key, value],
    )
    .unwrap();
}

/// Regression: an overlay written by an earlier build holds a credentialed
/// `base_url` and a raw-input `base_remote_token`; `overlay info` printed both.
#[test]
fn regression_overlay_info_redacts_earlier_build_database() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    std::fs::create_dir(&base).unwrap();
    let overlay = root.path().join("overlay");
    assert_success(&open(&overlay, &base, &["--base-digest", "none"]));
    let raw = "https://user:s3cr3t@h.example/b.tar?X-Amz-Signature=deadbeef";
    set_meta(&overlay, "base_url", raw);
    set_meta(
        &overlay,
        "base_remote_token",
        &serde_json::to_string(&[raw, "/plain"]).unwrap(),
    );
    set_meta(
        &overlay,
        "base_index_path",
        "/c/http:__user:s3cr3t@h_b.tar.index",
    );
    for json in [true, false] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        private_env(&mut cmd, root.path());
        cmd.args(["overlay", "info"]).arg(&overlay);
        if json {
            cmd.arg("--json");
        }
        let out = cmd.output().unwrap();
        assert_success(&out);
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(text.contains("https://h.example/b.tar"), "{text}");
        assert!(
            !text.contains("s3cr3t") && !text.contains("deadbeef"),
            "{text}"
        );
    }
}

/// Regression: a recorded remote base is stored without credentials, so an
/// offline verb that cannot reopen it must say to pass BASE explicitly.
#[test]
fn regression_recorded_redacted_remote_base_asks_for_explicit_base() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    std::fs::create_dir(&base).unwrap();
    let overlay = root.path().join("overlay");
    assert_success(&open(&overlay, &base, &["--base-digest", "none"]));
    set_meta(&overlay, "base_url", "http://127.0.0.1:1/b.tar");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    private_env(&mut cmd, root.path());
    let out = cmd
        .args(["overlay", "seal"])
        .arg(&overlay)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("stored without credentials; pass BASE explicitly"),
        "{stderr}"
    );
}

/// One foreground `-w` mount of `archive` with its own overlay and mountpoint,
/// sharing `index`; hashes append a line to `log`. Linux with /dev/fuse only.
#[cfg(target_os = "linux")]
struct LoggedMount {
    mnt: std::path::PathBuf,
    child: std::process::Child,
}

#[cfg(target_os = "linux")]
impl LoggedMount {
    fn spawn(
        root: &Path,
        n: usize,
        archive: &Path,
        index: Option<&Path>,
        log: &Path,
        delay_ms: u64,
    ) -> Self {
        Self::spawn_held(root, n, archive, index, log, delay_ms, None)
    }

    /// [`Self::spawn`] whose archive hash blocks (lock held) until `hold` exists.
    fn spawn_held(
        root: &Path,
        n: usize,
        archive: &Path,
        index: Option<&Path>,
        log: &Path,
        delay_ms: u64,
        hold: Option<&Path>,
    ) -> Self {
        let mnt = root.join(format!("mnt{n}"));
        std::fs::create_dir_all(&mnt).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        private_env(&mut cmd, root);
        cmd.env("RATARMOUNT_TEST_HASH_LOG", log)
            .env("RATARMOUNT_TEST_HASH_DELAY_MS", delay_ms.to_string())
            .envs(hold.map(|h| ("RATARMOUNT_TEST_HASH_HOLD", h)))
            .args(["-f", "--passthrough", "off", "--index-file"])
            .arg(index.unwrap_or(Path::new(":memory:")))
            .arg("-w")
            .arg(root.join(format!("overlay{n}")))
            .arg(archive)
            .arg(&mnt)
            .stdin(std::process::Stdio::null());
        Self {
            mnt,
            child: cmd.spawn().unwrap(),
        }
    }

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
        if n < 0 {
            return String::new();
        }
        String::from_utf8(buf[..n as usize].to_vec()).unwrap()
    }

    fn serving(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
            && std::fs::read(self.mnt.join("member.txt")).ok().as_deref()
                == Some(b"member bytes\n".as_slice())
    }

    fn unmount(&mut self) {
        stop_mount(&self.mnt, &mut self.child, "LoggedMount::unmount");
    }
}

#[cfg(target_os = "linux")]
impl Drop for LoggedMount {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let unmounted = unmount::unmount_within(
                &self.mnt,
                std::time::Duration::from_secs(5),
                "LoggedMount::drop",
            );
            let _ = finish_stop_mount(
                &mut self.child,
                "LoggedMount::drop",
                unmounted,
                std::time::Duration::from_secs(10),
            );
        }
    }
}

/// A tar plus a warm index that has no cached base digest. `None` skips.
#[cfg(target_os = "linux")]
fn logged_fixture(root: &Path) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    if !Path::new("/dev/fuse").exists()
        || Command::new("fusermount3")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("skip: /dev/fuse or fusermount3 unavailable");
        return None;
    }
    let src = root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("member.txt"), b"member bytes\n").unwrap();
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
    let index = root.join("idx").join("base.index.sqlite");
    std::fs::create_dir(root.join("idx")).unwrap();
    // `--no-mount` builds the index and never hashes the archive.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    private_env(&mut cmd, root);
    let out = cmd
        .args(["--no-mount", "--index-file"])
        .arg(&index)
        .arg("-w")
        .arg(root.join("overlay-warm"))
        .arg(&archive)
        .output()
        .unwrap();
    assert_success(&out);
    Some((archive, index))
}

#[cfg(target_os = "linux")]
fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ready() {
        assert!(std::time::Instant::now() < deadline, "not ready: {what}");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
fn hash_lines(log: &Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |s| s.lines().count())
}

/// Regression: C3, a cached archive digest is computed once per archive, not on
/// every mount: eight sequential mounts of one archive hash it exactly once.
#[cfg(target_os = "linux")]
#[test]
fn regression_digest_once_eight_sequential_mounts() {
    let root = tempfile::tempdir().unwrap();
    let Some((archive, index)) = logged_fixture(root.path()) else {
        return;
    };
    let log = root.path().join("hash.log");
    for n in 0..8 {
        let mut m = LoggedMount::spawn(root.path(), n, &archive, Some(&index), &log, 0);
        wait_until("serving", || m.serving());
        wait_until("digest recorded", || !m.xattr("base_digest").is_empty());
        m.unmount();
    }
    assert_eq!(hash_lines(&log), 1, "{:?}", std::fs::read_to_string(&log));
}

/// Regression: C3, eight first mounts of one uncached archive started together
/// (separate processes) all hashed it; the others must wait and read the cache.
#[cfg(target_os = "linux")]
#[test]
fn regression_digest_once_eight_concurrent_mounts() {
    let root = tempfile::tempdir().unwrap();
    let Some((archive, index)) = logged_fixture(root.path()) else {
        return;
    };
    let log = root.path().join("hash.log");
    let mut mounts: Vec<_> = (0..8)
        .map(|n| LoggedMount::spawn(root.path(), n, &archive, Some(&index), &log, 400))
        .collect();
    for m in &mut mounts {
        wait_until("serving", || m.serving());
    }
    for m in &mounts {
        wait_until("digest recorded", || !m.xattr("base_digest").is_empty());
    }
    for m in &mut mounts {
        m.unmount();
    }
    assert_eq!(hash_lines(&log), 1, "{:?}", std::fs::read_to_string(&log));
}

/// Regression: a second mount's cache peek waited for the first mount's hash
/// (it took the same lock), so it was not serving until that hash finished.
/// The first mount's hash is held (lock taken) until the test releases it; the
/// second mount must be serving with a pending digest meanwhile. Afterwards
/// both resolve and the archive was hashed exactly once. No timed delay.
#[cfg(target_os = "linux")]
#[test]
fn regression_second_mount_serves_while_the_first_is_hashing() {
    let root = tempfile::tempdir().unwrap();
    let Some((archive, index)) = logged_fixture(root.path()) else {
        return;
    };
    let log = root.path().join("hash.log");
    let hold = root.path().join("release-hash");
    let mut first =
        LoggedMount::spawn_held(root.path(), 0, &archive, Some(&index), &log, 0, Some(&hold));
    wait_until("first serving", || first.serving());
    wait_until("first started hashing", || hash_lines(&log) == 1);
    let mut second =
        LoggedMount::spawn_held(root.path(), 1, &archive, Some(&index), &log, 0, Some(&hold));
    wait_until("second serving", || second.serving());
    // The first hash is still blocked: nothing can have resolved yet.
    assert_eq!(first.xattr("base_digest"), "", "first digest still pending");
    assert_eq!(second.xattr("base_digest"), "", "digest still pending");
    std::fs::write(&hold, b"").unwrap();
    wait_until("first digest", || !first.xattr("base_digest").is_empty());
    wait_until("second digest", || !second.xattr("base_digest").is_empty());
    assert_eq!(first.xattr("base_digest"), second.xattr("base_digest"));
    first.unmount();
    second.unmount();
    assert_eq!(hash_lines(&log), 1, "{:?}", std::fs::read_to_string(&log));
}

/// Regression: C3 case 3, with no writable index cache (`:memory:`) every
/// mount's background hasher rehashed the archive. The digest stays pending.
#[cfg(target_os = "linux")]
#[test]
fn regression_digest_once_no_writable_cache_stays_pending() {
    let root = tempfile::tempdir().unwrap();
    let Some((archive, _)) = logged_fixture(root.path()) else {
        return;
    };
    let log = root.path().join("hash.log");
    for n in 0..2 {
        let mut m = LoggedMount::spawn(root.path(), n, &archive, None, &log, 0);
        wait_until("serving", || m.serving());
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert_eq!(m.xattr("base_digest"), "");
        m.unmount();
        let meta = OverlayMeta::read(root.path().join(format!("overlay{n}")))
            .unwrap()
            .unwrap();
        assert_eq!(meta.base_digest_kind(), Some("pending"));
    }
    assert_eq!(hash_lines(&log), 0, "{:?}", std::fs::read_to_string(&log));
}
#[cfg(target_os = "linux")]
mod shutdown_regression {
    use super::*;
    use std::fs::File;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::process::Child;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    struct DirectChild(Option<Child>);

    impl DirectChild {
        fn sleep(seconds: &str) -> Self {
            Self(Some(Command::new("sleep").arg(seconds).spawn().unwrap()))
        }

        fn child(&mut self) -> &mut Child {
            self.0.as_mut().unwrap()
        }

        fn into_reaped(mut self) -> Child {
            assert!(poll_child_exit(self.child(), Duration::from_secs(1))
                .unwrap()
                .is_some());
            self.0.take().unwrap()
        }
    }

    impl Drop for DirectChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                if child.try_wait().ok().flatten().is_none() {
                    let _ = child.kill();
                    let _ = poll_child_exit(child, Duration::from_secs(1));
                }
            }
        }
    }

    // Wake the releaser on unwinding too; its only wait has a finite timeout.
    struct RootReleaser {
        release: mpsc::Sender<()>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl RootReleaser {
        fn after(root: File, delay: Duration) -> Self {
            let (release, received) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                let _ = received.recv_timeout(delay);
                drop(root);
            });
            Self {
                release,
                thread: Some(thread),
            }
        }

        fn join_within(&mut self) -> bool {
            let deadline = Instant::now() + Duration::from_secs(1);
            while self
                .thread
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())
            {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            if let Some(thread) = self.thread.take() {
                thread.join().is_ok()
            } else {
                true
            }
        }
    }

    impl Drop for RootReleaser {
        fn drop(&mut self) {
            let _ = self.release.send(());
            let _ = self.join_within();
        }
    }

    fn fuse_available() -> bool {
        if !Path::new("/dev/fuse").exists() {
            eprintln!("skip: #215 real-FUSE regression requires /dev/fuse");
            return false;
        }
        for tool in ["fusermount3", "tar"] {
            if !Command::new(tool)
                .arg("--version")
                .output()
                .is_ok_and(|out| out.status.success())
            {
                eprintln!("skip: #215 real-FUSE regression requires {tool}");
                return false;
            }
        }
        true
    }

    fn logged_mount(root: &Path) -> Option<LoggedMount> {
        if !fuse_available() {
            return None;
        }
        let (archive, index) = logged_fixture(root)?;
        let log = root.join("hash.log");
        let hold = root.join("release-hash");
        let mut mount =
            LoggedMount::spawn_held(root, 0, &archive, Some(&index), &log, 0, Some(&hold));
        wait_until("#215 logged mount serving", || mount.serving());
        wait_until("#215 hash held", || hash_lines(&log) == 1);
        std::fs::write(&hold, b"go").unwrap();
        wait_until("#215 hash released", || {
            !mount.xattr("base_digest").is_empty()
        });
        Some(mount)
    }

    fn assert_detached(mnt: &Path) {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        assert!(
            !mountinfo.lines().any(|line| {
                line.split_whitespace().nth(4).is_some_and(|path| {
                    let path = path
                        .replace("\\040", " ")
                        .replace("\\011", "\t")
                        .replace("\\012", "\n")
                        .replace("\\134", "\\");
                    Path::new(&path) == mnt
                })
            }),
            "exact mountpoint still attached: {}",
            mnt.display()
        );
    }

    fn start_time(pid: u32) -> Option<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (_, fields) = stat.rsplit_once(") ")?;
        fields.split_whitespace().nth(19).map(str::to_owned)
    }

    fn child_identity(child: &Child) -> (u32, String) {
        let pid = child.id();
        (
            pid,
            start_time(pid).expect("live daemon has a process start time"),
        )
    }

    fn assert_reaped((pid, started): (u32, String)) {
        assert_ne!(
            start_time(pid).as_deref(),
            Some(started.as_str()),
            "daemon {pid} still exists (including an unreaped zombie)"
        );
    }

    fn panic_message(result: std::thread::Result<()>) -> String {
        let panic = result.expect_err("shutdown must fail after cleanup");
        if let Some(message) = panic.downcast_ref::<String>() {
            message.clone()
        } else if let Some(message) = panic.downcast_ref::<&str>() {
            (*message).to_owned()
        } else {
            panic!("shutdown panic did not contain a diagnostic");
        }
    }

    /// Regression: #215 transient root-directory holders made one-shot unmount hang.
    #[test]
    fn regression_stop_mount_retries_transient_busy() {
        let root = tempfile::tempdir().unwrap();
        let Some(mut mount) = logged_mount(root.path()) else {
            return;
        };
        let held = File::open(&mount.mnt).unwrap();
        assert!(!Command::new("fusermount3")
            .arg("-u")
            .arg(&mount.mnt)
            .status()
            .unwrap()
            .success());
        let mut releaser = RootReleaser::after(held, Duration::from_millis(250));
        stop_mount(&mount.mnt, &mut mount.child, "transient busy");
        assert!(releaser.join_within(), "root-FD releaser did not finish");
        drop(releaser);
        assert_detached(&mount.mnt);
        assert!(mount.child.try_wait().unwrap().is_some());
    }

    /// Regression: #215 lazy cleanup or child exit must not erase a busy unmount error.
    #[test]
    fn regression_busy_unmount_remains_failure() {
        for seconds in ["0", "60"] {
            let mut child = DirectChild::sleep(seconds);
            if seconds == "0" {
                assert!(poll_child_exit(child.child(), Duration::from_secs(1))
                    .unwrap()
                    .is_some());
            }
            let error = finish_stop_mount(
                child.child(),
                "synthetic busy",
                Err("synthetic EBUSY after lazy detach".to_owned()),
                Duration::from_millis(50),
            )
            .unwrap_err();
            assert!(
                error.contains("synthetic busy: mount stayed busy"),
                "{error}"
            );
            assert!(
                error.contains("synthetic EBUSY after lazy detach"),
                "{error}"
            );
            assert!(child.child().try_wait().unwrap().is_some());
        }
    }

    /// Regression: #215 persistent holders must fail even after lazy detachment.
    #[test]
    fn regression_persistent_busy_unmount_fails_after_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let Some(mut mount) = logged_mount(root.path()) else {
            return;
        };
        let held = File::open(&mount.mnt).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            stop_mount(&mount.mnt, &mut mount.child, "persistent busy");
        }));
        drop(held);
        let message = panic_message(result);
        assert!(
            message.contains("persistent busy: mount stayed busy"),
            "{message}"
        );
        assert_detached(&mount.mnt);
        assert!(mount.child.try_wait().unwrap().is_some());
    }

    /// Regression: #215 a daemon stuck after successful unmount must be killed and reaped.
    #[test]
    fn regression_successful_unmount_kills_stuck_daemon() {
        let root = tempfile::tempdir().unwrap();
        let mut child = DirectChild::sleep("60");
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| {
            stop_mount(root.path(), child.child(), "stuck daemon");
        }));
        let elapsed = started.elapsed();
        let message = panic_message(result);
        assert!(
            message.contains("stuck daemon: daemon did not exit after a successful unmount"),
            "{message}"
        );
        assert!(elapsed >= Duration::from_secs(10), "{elapsed:?}");
        assert!(child.child().try_wait().unwrap().is_some());

        let mut naturally_exiting = DirectChild::sleep("0.05");
        assert!(finish_stop_mount(
            naturally_exiting.child(),
            "naturally exited",
            Ok(()),
            Duration::from_secs(1),
        )
        .is_ok());
        assert!(naturally_exiting
            .child()
            .try_wait()
            .unwrap()
            .is_some_and(|status| status.success()));
    }

    /// Regression: #215 GatedMount Drop must detach a busy mount without panicking.
    #[test]
    fn regression_gated_drop_busy_cleanup_never_panics() {
        if !fuse_available() {
            return;
        }
        let Some(mount) = GatedMount::start() else {
            return;
        };
        mount.release();
        let mnt = mount.mnt.clone();
        let identity = child_identity(&mount.child);
        let held = File::open(&mnt).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| drop(mount)));
        drop(held);
        assert!(
            result.is_ok(),
            "GatedMount Drop panicked during busy cleanup"
        );
        assert_detached(&mnt);
        assert_reaped(identity);
    }

    /// Regression: #215 LoggedMount Drop must detach a busy mount without panicking.
    #[test]
    fn regression_logged_drop_busy_cleanup_never_panics() {
        let root = tempfile::tempdir().unwrap();
        let Some(mount) = logged_mount(root.path()) else {
            return;
        };
        let mnt = mount.mnt.clone();
        let identity = child_identity(&mount.child);
        let held = File::open(&mnt).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| drop(mount)));
        drop(held);
        assert!(
            result.is_ok(),
            "LoggedMount Drop panicked during busy cleanup"
        );
        assert_detached(&mnt);
        assert_reaped(identity);
    }

    /// Regression: #215 an already-reaped guard must not unmount another owned daemon.
    #[test]
    fn regression_drop_reaped_child_is_noop() {
        let root = tempfile::tempdir().unwrap();
        let Some(mut owner) = logged_mount(root.path()) else {
            return;
        };
        let inert_root = tempfile::tempdir().unwrap();
        let inert = GatedMount {
            archive: inert_root.path().join("unused.tar"),
            overlay: inert_root.path().join("unused-overlay"),
            gate: inert_root.path().join("unused-gate"),
            root: inert_root,
            mnt: owner.mnt.clone(),
            child: DirectChild::sleep("0").into_reaped(),
        };
        drop(inert);
        assert!(
            owner.serving(),
            "reaped GatedMount guard unmounted live owner"
        );
        let inert = LoggedMount {
            mnt: owner.mnt.clone(),
            child: DirectChild::sleep("0").into_reaped(),
        };
        drop(inert);
        assert!(
            owner.serving(),
            "reaped LoggedMount guard unmounted live owner"
        );
        owner.unmount();
        assert_detached(&owner.mnt);
        assert!(owner.child.try_wait().unwrap().is_some());
    }

    /// Regression: #215 readiness cleanup must reap its child and retain the startup reason.
    #[test]
    fn regression_readiness_failure_cleanup_preserves_reason() {
        let root = tempfile::tempdir().unwrap();
        let mut child = DirectChild::sleep("60");
        let result = catch_unwind(AssertUnwindSafe(|| {
            fail_mount_not_ready(root.path(), child.child());
        }));
        assert_eq!(
            panic_message(result),
            "not ready within 20 s (the mount hashes the base)"
        );
        assert!(child.child().try_wait().unwrap().is_some());
    }
}
