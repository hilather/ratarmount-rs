//! FUSE `rename(2)` on the write overlay (#86).
#![cfg(target_os = "linux")]

use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const MOUNT_DEADLINE: Duration = Duration::from_secs(10);
/// All rename cases together. Each is a handful of FUSE ops; a hang means a
/// stuck request, and cleanup (lazy unmount + SIGKILL) unblocks the thread.
const CASES_DEADLINE: Duration = Duration::from_secs(60);
const UNMOUNT_DEADLINE: Duration = Duration::from_secs(10);
const DAEMON_EXIT_DEADLINE: Duration = Duration::from_secs(30);
const KILL_REAP: Duration = Duration::from_secs(5);

/// Regression: rename(2) on a FUSE `-w` mount returned ENOSYS because
/// `Filesystem::rename` was not implemented (#86). Covers a plain
/// temp-then-rename, rename over an existing overlay and archive target,
/// copy-up rename of an archive-only member, and the errno cases.
#[test]
fn fuse_rename_write_overlay() {
    if let Some(msg) = skip_reason() {
        eprintln!("{msg}");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("rrs86-fuse-rename-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    let tar = build_fixture(root);
    let ov = root.join("ov");
    fs::create_dir_all(&ov).expect("overlay dir");
    let mnt_raw = root.join("mnt");
    fs::create_dir_all(&mnt_raw).expect("mnt dir");
    let mnt = mnt_raw.canonicalize().expect("canonicalize mnt");
    let daemon_log = root.join("daemon.log");

    let mut guard = MountGuard::spawn(&ratarmount_bin(), &ov, &tar, &mnt, &daemon_log);
    if let Err(e) = guard.wait_mounted() {
        panic!("{e}");
    }

    let d = mnt.join("d");
    let (tx, rx) = mpsc::channel();
    let cases = thread::spawn(move || {
        let r = std::panic::catch_unwind(|| run_cases(&d));
        let _ = tx.send(());
        r
    });
    match rx.recv_timeout(CASES_DEADLINE) {
        Ok(()) => {}
        Err(_) => {
            let pid = guard.daemon_pid;
            guard.force_cleanup();
            let _ = cases.join();
            panic!("rename cases did not finish in {CASES_DEADLINE:?} (daemon pid {pid})");
        }
    }
    if let Err(p) = cases.join().expect("cases thread") {
        // Unmount first (guard drop), then surface the assertion.
        drop(guard);
        std::panic::resume_unwind(p);
    }
    if let Err(e) = guard.graceful_unmount() {
        panic!("{e}");
    }
}

fn run_cases(d: &Path) {
    // 1. Plain temp-then-rename (the Unreal pattern): `echo x > tmp && mv tmp final`.
    fs::write(d.join("tmp"), "x\n").expect("write tmp");
    rename_ok(d, "tmp", "final");
    assert_eq!(read(d, "final"), "x\n");
    assert_enoent(d, "tmp");
    assert_listing(d, &["final"], &["tmp"]);

    // 2. Rename over an existing overlay file.
    fs::write(d.join("t1"), "one").expect("write t1");
    fs::write(d.join("t2"), "two").expect("write t2");
    rename_ok(d, "t1", "t2");
    assert_eq!(read(d, "t2"), "one");
    assert_enoent(d, "t1");

    // 3. Rename over an existing archive member.
    fs::write(d.join("t3"), "three").expect("write t3");
    rename_ok(d, "t3", "a2");
    assert_eq!(read(d, "a2"), "three");
    assert_enoent(d, "t3");
    let n = list(d).iter().filter(|n| n.as_str() == "a2").count();
    assert_eq!(n, 1, "a2 listed once: {:?}", list(d));

    // 4. Archive-only source: copy-up, old name gone.
    rename_ok(d, "a1", "moved");
    assert_eq!(read(d, "moved"), "archive-one\n");
    assert_enoent(d, "a1");
    assert_listing(d, &["moved"], &["a1"]);

    // 5. Missing source.
    assert_rename_errno(d, "nope", "x", libc::ENOENT);

    // 6. renameat2 flags. The VFS answers RENAME_NOREPLACE onto an existing
    // name with EEXIST itself. The negotiated FUSE ABI is below 7.23, so for
    // anything that reaches the filesystem the kernel refuses flags with
    // EINVAL before the daemon sees them (kernel-observed; the handler's own
    // flag check is covered by the ratarmount-fuse lib unit test).
    let cases: [(libc::c_uint, &str, &str, i32); 3] = [
        (
            libc::RENAME_NOREPLACE,
            "moved",
            "RENAME_NOREPLACE existing",
            libc::EEXIST,
        ),
        (
            libc::RENAME_NOREPLACE,
            "fresh",
            "RENAME_NOREPLACE fresh",
            libc::EINVAL,
        ),
        (
            libc::RENAME_EXCHANGE,
            "moved",
            "RENAME_EXCHANGE",
            libc::EINVAL,
        ),
    ];
    for (flags, to, what, want) in cases {
        let err = renameat2(&d.join("final"), &d.join(to), flags).expect_err(what);
        assert_eq!(err.raw_os_error(), Some(want), "{what}: {err}");
        assert_eq!(read(d, "final"), "x\n", "{what} left source");
        assert_eq!(read(d, "moved"), "archive-one\n", "{what} left target");
    }
    assert_enoent(d, "fresh");

    // 7. Directory source: EISDIR like the other frontends; tree untouched.
    assert_rename_errno(d, "sub", "sub2", libc::EISDIR);
    assert_eq!(read(d, "sub/f"), "in-sub\n");
}

fn rename_ok(d: &Path, from: &str, to: &str) {
    if let Err(e) = fs::rename(d.join(from), d.join(to)) {
        panic!("rename {from} -> {to}: {e} (raw {:?})", e.raw_os_error());
    }
}

fn assert_rename_errno(d: &Path, from: &str, to: &str, want: i32) {
    match fs::rename(d.join(from), d.join(to)) {
        Ok(()) => panic!("rename {from} -> {to} succeeded, want errno {want}"),
        Err(e) => assert_eq!(e.raw_os_error(), Some(want), "rename {from} -> {to}: {e}"),
    }
}

fn read(d: &Path, name: &str) -> String {
    fs::read_to_string(d.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn assert_enoent(d: &Path, name: &str) {
    match fs::symlink_metadata(d.join(name)) {
        Ok(_) => panic!("{name} still exists"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound, "stat {name}: {e}"),
    }
}

fn list(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(d)
        .expect("read_dir")
        .map(|e| {
            e.expect("dirent")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    v.sort();
    v
}

fn assert_listing(d: &Path, present: &[&str], absent: &[&str]) {
    let names = list(d);
    for p in present {
        assert!(names.iter().any(|n| n == p), "{p} missing from {names:?}");
    }
    for a in absent {
        assert!(
            !names.iter().any(|n| n == a),
            "{a} still listed in {names:?}"
        );
    }
}

fn renameat2(from: &Path, to: &Path, flags: libc::c_uint) -> io::Result<()> {
    let from = CString::new(from.as_os_str().as_bytes()).expect("from nul");
    let to = CString::new(to.as_os_str().as_bytes()).expect("to nul");
    // SAFETY: valid NUL-terminated paths; AT_FDCWD with absolute paths.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            flags,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn ratarmount_bin() -> PathBuf {
    if let Some(p) = env::var_os("RATARMOUNT_TEST_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(env!("CARGO_BIN_EXE_ratarmount"))
}

fn skip_reason() -> Option<&'static str> {
    if !Path::new("/dev/fuse").exists() {
        return Some("skip: /dev/fuse missing");
    }
    if !on_path("fusermount3") {
        return Some("skip: fusermount3 not on PATH");
    }
    if !on_path("tar") {
        return Some("skip: tar not on PATH");
    }
    None
}

fn on_path(bin: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| env::split_paths(&paths).any(|p| p.join(bin).is_file()))
}

fn build_fixture(root: &Path) -> PathBuf {
    let src = root.join("src").join("d");
    fs::create_dir_all(src.join("sub")).expect("src/d/sub");
    fs::write(src.join("a1"), "archive-one\n").expect("a1");
    fs::write(src.join("a2"), "archive-two\n").expect("a2");
    fs::write(src.join("sub").join("f"), "in-sub\n").expect("sub/f");
    let tar = root.join("a.tar");
    let status = Command::new("tar")
        .args(["-C", root.join("src").to_str().expect("src utf8"), "-cf"])
        .arg(&tar)
        .arg("d")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "tar -cf failed: {status}");
    tar
}

struct MountGuard {
    mnt: PathBuf,
    daemon: Child,
    daemon_pid: u32,
    daemon_log: PathBuf,
    armed: bool,
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        self.force_cleanup();
    }
}

impl MountGuard {
    fn spawn(bin: &Path, ov: &Path, tar: &Path, mnt: &Path, log_path: &Path) -> Self {
        let log = File::create(log_path).expect("daemon log");
        let daemon = Command::new(bin)
            .arg("-f")
            .arg("-w")
            .arg(ov)
            .arg(tar)
            .arg(mnt)
            .env("LC_ALL", "C")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .process_group(0)
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {} -f -w: {e}", bin.display()));
        let daemon_pid = daemon.id();
        MountGuard {
            mnt: mnt.to_path_buf(),
            daemon,
            daemon_pid,
            daemon_log: log_path.to_path_buf(),
            armed: true,
        }
    }

    fn wait_mounted(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + MOUNT_DEADLINE;
        loop {
            if mount_visible(&self.mnt) {
                return Ok(());
            }
            if let Ok(Some(st)) = self.daemon.try_wait() {
                return Err(format!(
                    "daemon pid {} exited before mount: {st}\n{}",
                    self.daemon_pid,
                    tail(&self.daemon_log)
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "mount {} did not appear within {MOUNT_DEADLINE:?} (daemon pid {})\n{}",
                    self.mnt.display(),
                    self.daemon_pid,
                    tail(&self.daemon_log)
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Lazy unmount, then SIGKILL the daemon (its own process group). Bounded.
    fn force_cleanup(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if mount_visible(&self.mnt) {
            let _ = run_fusermount(&["-u", "-z"], &self.mnt, UNMOUNT_DEADLINE);
        }
        if !matches!(self.daemon.try_wait(), Ok(Some(_))) {
            let _ = self.daemon.kill();
        }
        let _ = reap(&mut self.daemon, KILL_REAP);
    }

    fn graceful_unmount(&mut self) -> Result<(), String> {
        if !run_fusermount(&["-u"], &self.mnt, UNMOUNT_DEADLINE) {
            return Err(format!(
                "fusermount3 -u {} failed within {UNMOUNT_DEADLINE:?} (daemon pid {})\n{}",
                self.mnt.display(),
                self.daemon_pid,
                tail(&self.daemon_log)
            ));
        }
        match reap(&mut self.daemon, DAEMON_EXIT_DEADLINE) {
            Some(st) if st.success() => {
                self.armed = false;
                Ok(())
            }
            Some(st) => Err(format!(
                "daemon pid {} exited {st}\n{}",
                self.daemon_pid,
                tail(&self.daemon_log)
            )),
            None => Err(format!(
                "daemon pid {} did not exit within {DAEMON_EXIT_DEADLINE:?} after unmount\n{}",
                self.daemon_pid,
                tail(&self.daemon_log)
            )),
        }
    }
}

fn reap(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => return None,
        }
    }
}

fn run_fusermount(args: &[&str], mnt: &Path, timeout: Duration) -> bool {
    let Ok(mut child) = Command::new("fusermount3")
        .args(args)
        .arg(mnt)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    match reap(&mut child, timeout) {
        Some(st) => st.success(),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            false
        }
    }
}

fn mount_visible(mnt: &Path) -> bool {
    let want = mnt.as_os_str().as_bytes();
    fs::read("/proc/self/mountinfo").is_ok_and(|text| {
        text.split(|&b| b == b'\n')
            .any(|line| line.split(|&b| b == b' ').nth(4) == Some(want))
    })
}

fn tail(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(30);
    lines[start..].join("\n")
}
