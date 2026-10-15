//! Kernel rename-over poller for FUSE `-w` (#88 phase 2).
//!
//! A file replaced or unlinked while the kernel still holds it must not
//! surface `ENOENT`. The harness is duplicated from `ratarmount/tests/fuse_rename.rs`
//! so that file stays untouched.
#![cfg(target_os = "linux")]

use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const MOUNT_DEADLINE: Duration = Duration::from_secs(10);
const UNMOUNT_DEADLINE: Duration = Duration::from_secs(10);
const DAEMON_EXIT_DEADLINE: Duration = Duration::from_secs(30);
const KILL_REAP: Duration = Duration::from_secs(5);
/// Post-reply notifier batch. Same wait as `fuse_rename.rs`.
const NOTIFY_SETTLE: Duration = Duration::from_secs(1);
const SMOKE_DEADLINE: Duration = Duration::from_secs(60);
/// Poll/write phase of one stress run. Not the 60s `fuse_rename` guard.
const STRESS_DEADLINE: Duration = Duration::from_secs(120);

/// Regression (#88): 1 writer × 50 rename-overs of an overlay-backed `d/final`
/// produce 0 ENOENT.
#[test]
fn fuse_rename_over_smoke_overlay_target() {
    mount_and_run(
        "rrs88-smoke-ov-",
        &[("d/base.txt", b"base\n")],
        &[],
        SMOKE_DEADLINE,
        |d, _ov, _tar| {
            fs::write(d.join("final"), b"seed\n").expect("seed overlay final");
            let report = run_poll(d, 1, 50, "smoke overlay 1x50");
            assert_poll_clean(&report);
        },
    );
}

/// Regression (#88): 1 writer × 50 rename-overs of an archive member `d/final`
/// produce 0 ENOENT. The target is not copied up before the writers start.
#[test]
fn fuse_rename_over_smoke_archive_target() {
    mount_and_run(
        "rrs88-smoke-ar-",
        &[("d/final", b"archive-final\n"), ("d/base.txt", b"base\n")],
        &[],
        SMOKE_DEADLINE,
        |d, _ov, _tar| {
            let meta = fs::metadata(d.join("final")).expect("stat archive final");
            assert!(meta.len() > 0, "archive final is empty");
            let report = run_poll(d, 1, 50, "smoke archive 1x50");
            assert_poll_clean(&report);
        },
    );
}

/// Phase 2 stress: 1×400 and 8×100, 3 runs, both targets. Own 120s deadline.
#[test]
#[ignore = "phase 2 stress: 1x400 and 8x100, 3 runs, both targets"]
fn fuse_rename_over_stress() {
    if let Some(msg) = skip_reason() {
        eprintln!("{msg}");
        return;
    }
    let configs = [(1usize, 400usize), (8, 100)];
    for run in 0..3 {
        for (writers, cycles) in configs {
            mount_and_run(
                "rrs88-stress-ov-",
                &[("d/base.txt", b"base\n")],
                &[],
                STRESS_DEADLINE,
                move |d, _ov, _tar| {
                    fs::write(d.join("final"), b"seed\n").expect("seed");
                    let label = format!("stress overlay {writers}x{cycles} run {run}");
                    let report = run_poll(d, writers, cycles, &label);
                    assert_poll_clean(&report);
                },
            );
            mount_and_run(
                "rrs88-stress-ar-",
                &[("d/final", b"archive-final\n"), ("d/base.txt", b"base\n")],
                &[],
                STRESS_DEADLINE,
                move |d, _ov, _tar| {
                    fs::metadata(d.join("final")).expect("stat archive final");
                    let label = format!("stress archive {writers}x{cycles} run {run}");
                    let report = run_poll(d, writers, cycles, &label);
                    assert_poll_clean(&report);
                },
            );
        }
    }
}

/// Regression (#88): 300 distinct archive members held open and replaced once
/// keep their old bytes. A fresh open reads the replacement.
#[test]
fn fuse_rename_over_many_archive_members_keep_old_bytes() {
    let mut files: Vec<(String, Vec<u8>)> = Vec::with_capacity(301);
    files.push(("d/base.txt".into(), b"base\n".to_vec()));
    for i in 0..300 {
        let payload = format!("member-{i:04}\n").repeat(4);
        files.push((format!("d/f{i:03}"), payload.into_bytes()));
    }
    let owned: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    mount_and_run(
        "rrs88-many-",
        &owned,
        &[],
        SMOKE_DEADLINE,
        |d, _ov, _tar| {
            let mut held = Vec::with_capacity(300);
            for i in 0..300 {
                let path = d.join(format!("f{i:03}"));
                held.push(File::open(&path).unwrap_or_else(|e| panic!("open f{i:03}: {e}")));
            }
            for i in 0..300 {
                let tmp = d.join(format!(".tmp-many-{i}"));
                let body = format!("replaced-{i:04}\n");
                fs::write(&tmp, &body).unwrap_or_else(|e| panic!("write temp {i}: {e}"));
                fs::rename(&tmp, d.join(format!("f{i:03}")))
                    .unwrap_or_else(|e| panic!("rename f{i:03}: {e}"));
            }
            thread::sleep(NOTIFY_SETTLE);
            for (i, file) in held.iter_mut().enumerate() {
                let mut buf = String::new();
                file.seek(SeekFrom::Start(0)).expect("seek held");
                file.read_to_string(&mut buf)
                    .unwrap_or_else(|e| panic!("read held f{i:03}: {e}"));
                let want = format!("member-{i:04}\n").repeat(4);
                assert_eq!(buf, want, "held f{i:03} lost its old bytes");
            }
            for i in 0..300 {
                let got = fs::read(d.join(format!("f{i:03}")))
                    .unwrap_or_else(|e| panic!("fresh f{i:03}: {e}"));
                let want = format!("replaced-{i:04}\n");
                assert_eq!(got, want.as_bytes(), "fresh f{i:03}");
            }
        },
    );
}

/// Regression (#88): an archive member held open across rename-over still
/// reads its old bytes after a live `--commit-overlay-interval` commit.
#[test]
fn fuse_rename_over_held_archive_member_survives_live_commit() {
    if skip_no_gnu_tar() {
        eprintln!("skip: GNU tar missing");
        return;
    }
    mount_and_run(
        "rrs88-live-hold-",
        &[
            ("d/final", b"archive-final\n"),
            ("d/other", b"other\n"),
            ("d/base.txt", b"base\n"),
        ],
        &[
            "--commit-overlay-interval",
            "1s",
            "--index-file",
            ":memory:",
        ],
        SMOKE_DEADLINE,
        |d, _ov, tar| {
            let mut held = File::open(d.join("final")).expect("open final");
            fs::rename(d.join("other"), d.join("final")).expect("rename other onto final");
            thread::sleep(NOTIFY_SETTLE);
            fs::write(d.join("tick.bin"), b"tick\n").expect("tick");
            wait_tar_lists(tar, "tick.bin");
            held.seek(SeekFrom::Start(0)).expect("seek held");
            let mut buf = String::new();
            held.read_to_string(&mut buf)
                .expect("read held after commit");
            assert_eq!(buf, "archive-final\n");
            let fresh = fs::read(d.join("final")).expect("fresh final");
            assert_eq!(fresh, b"other\n");
        },
    );
}

/// Regression (#88): bytes written to a pre-unlink fd are absent from the
/// committed archive. The held fd still reads them.
#[test]
fn fuse_rename_over_prerename_writer_discarded_at_commit() {
    if skip_no_gnu_tar() {
        eprintln!("skip: GNU tar missing");
        return;
    }
    mount_and_run(
        "rrs88-orphan-",
        &[("d/base.txt", b"base\n")],
        &[
            "--commit-overlay-interval",
            "1s",
            "--index-file",
            ":memory:",
        ],
        SMOKE_DEADLINE,
        |d, _ov, tar| {
            fs::write(d.join("note"), b"visible\n").expect("create note");
            let mut held = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(d.join("note"))
                .expect("open note");
            fs::remove_file(d.join("note")).expect("unlink note");
            held.write_all(b"ORPHAN\n").expect("write orphan");
            held.flush().expect("flush orphan");
            fs::write(d.join("tick.bin"), b"tick\n").expect("tick");
            wait_tar_lists(tar, "tick.bin");

            let extract = tar.parent().expect("tar parent").join("extracted");
            fs::create_dir_all(&extract).expect("extract dir");
            let status = Command::new("tar")
                .args(["-xf"])
                .arg(tar)
                .arg("-C")
                .arg(&extract)
                .status()
                .expect("tar -x");
            assert!(status.success(), "tar -x failed: {status}");
            assert!(
                !extract.join("d").join("note").exists() && !extract.join("note").exists(),
                "committed archive still has note"
            );
            for ent in walk(&extract) {
                let body = fs::read(&ent).unwrap_or_default();
                assert!(
                    !body.windows(b"ORPHAN".len()).any(|w| w == b"ORPHAN"),
                    "{} contains ORPHAN",
                    ent.display()
                );
            }
            held.seek(SeekFrom::Start(0)).expect("seek orphan");
            let mut buf = String::new();
            held.read_to_string(&mut buf).expect("read orphan fd");
            assert!(buf.contains("ORPHAN"), "held fd lost the orphan: {buf:?}");
        },
    );
}

/// Regression (#88): mode 000 host files can still be renamed and removed
/// through the mount. setattr ignores mode, so the chmod is on the host file.
#[test]
fn fuse_rename_over_mode_000_mv_rm() {
    mount_and_run(
        "rrs88-mode0-",
        &[("d/base.txt", b"base\n")],
        &[],
        SMOKE_DEADLINE,
        |d, ov, _tar| {
            fs::write(d.join("locked"), b"x").expect("create locked");
            fs::set_permissions(
                ov.join("d").join("locked"),
                fs::Permissions::from_mode(0o000),
            )
            .expect("chmod locked");
            fs::rename(d.join("locked"), d.join("locked2")).expect("mv mode 000");
            fs::write(d.join("gone"), b"y").expect("create gone");
            fs::set_permissions(ov.join("d").join("gone"), fs::Permissions::from_mode(0o000))
                .expect("chmod gone");
            fs::remove_file(d.join("gone")).expect("rm mode 000");
        },
    );
}

struct PollReport {
    label: String,
    attempts: u64,
    open_enoent: u64,
    read_enoent: u64,
    other: u64,
    first_other: i32,
    writer_errors: usize,
    leftovers: usize,
    elapsed: Duration,
}

fn assert_poll_clean(r: &PollReport) {
    assert_eq!(
        (r.writer_errors, r.leftovers, r.other, r.open_enoent, r.read_enoent),
        (0, 0, 0, 0, 0),
        "{} writer_errors={} leftovers={} other={} (errno {}) open_enoent={} read_enoent={} attempts={}",
        r.label,
        r.writer_errors,
        r.leftovers,
        r.other,
        r.first_other,
        r.open_enoent,
        r.read_enoent,
        r.attempts
    );
}

fn run_poll(d: &Path, writers: usize, cycles: usize, label: &str) -> PollReport {
    let final_path = d.join("final");
    let c_path = CString::new(final_path.as_os_str().as_bytes()).expect("final path");
    let stop = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);
    let open_enoent = AtomicU64::new(0);
    let read_enoent = AtomicU64::new(0);
    let other = AtomicU64::new(0);
    let first_other = AtomicI32::new(0);
    let writer_errors = AtomicUsize::new(0);

    let poller = thread::scope(|scope| {
        let handle = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                attempts.fetch_add(1, Ordering::Relaxed);
                let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 {
                    note_errno(&open_enoent, &other, &first_other, true);
                    continue;
                }
                let mut buf = [0u8; 64];
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                unsafe { libc::close(fd) };
                if n < 0 {
                    note_errno(&read_enoent, &other, &first_other, false);
                }
            }
        });

        let start = Instant::now();
        thread::scope(|writers_scope| {
            for id in 0..writers {
                let dir = d;
                let errors = &writer_errors;
                writers_scope.spawn(move || writer_loop(dir, id, cycles, errors));
            }
        });
        let elapsed = start.elapsed();
        stop.store(true, Ordering::Relaxed);
        handle.join().expect("poller");
        elapsed
    });

    let leftovers = fs::read_dir(d)
        .map(|rd| {
            rd.flatten()
                .filter(|ent| ent.file_name().to_string_lossy().starts_with(".tmp-"))
                .count()
        })
        .unwrap_or(0);
    let attempts = attempts.load(Ordering::Relaxed);
    let elapsed = poller;
    let secs = elapsed.as_secs_f64().max(1e-9);
    let rate = attempts as f64 / secs;
    let report = PollReport {
        label: label.to_string(),
        attempts,
        open_enoent: open_enoent.load(Ordering::Relaxed),
        read_enoent: read_enoent.load(Ordering::Relaxed),
        other: other.load(Ordering::Relaxed),
        first_other: first_other.load(Ordering::Relaxed),
        writer_errors: writer_errors.load(Ordering::Relaxed),
        leftovers,
        elapsed,
    };
    eprintln!(
        "fuse_rename_over {}: attempts={} open_enoent={} read_enoent={} other={} first_other={} writer_errors={} leftovers={} elapsed={:?} rate={rate:.0}/s",
        report.label,
        report.attempts,
        report.open_enoent,
        report.read_enoent,
        report.other,
        report.first_other,
        report.writer_errors,
        report.leftovers,
        report.elapsed
    );
    report
}

fn note_errno(enoent: &AtomicU64, other: &AtomicU64, first_other: &AtomicI32, open: bool) {
    let raw = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if raw == libc::ENOENT {
        enoent.fetch_add(1, Ordering::Relaxed);
    } else {
        other.fetch_add(1, Ordering::Relaxed);
        let _ = first_other.compare_exchange(0, raw, Ordering::Relaxed, Ordering::Relaxed);
        if open {
            eprintln!("fuse_rename_over poll open errno {raw}");
        } else {
            eprintln!("fuse_rename_over poll read errno {raw}");
        }
    }
}

fn writer_loop(dir: &Path, id: usize, cycles: usize, errors: &AtomicUsize) {
    for n in 0..cycles {
        let tmp = dir.join(format!(".tmp-{id}-{n}"));
        if let Err(e) = fs::write(&tmp, format!("w{id}-{n}\n")) {
            errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("fuse_rename_over writer {id} write: {e}");
            return;
        }
        if let Err(e) = fs::rename(&tmp, dir.join("final")) {
            errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("fuse_rename_over writer {id} rename: {e}");
            return;
        }
    }
}

fn wait_tar_lists(tar: &Path, name: &str) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if tar_list(tar).contains(name) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "interval did not commit {name} within 5s\n{}\n{}",
        tar_list(tar),
        tail(tar.parent().unwrap_or(tar).join("daemon.log").as_path())
    );
}

fn tar_list(tar: &Path) -> String {
    let out = Command::new("tar").args(["-tf"]).arg(tar).output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => format!("tar -tf failed: {e}"),
    }
}

fn skip_no_gnu_tar() -> bool {
    let out = Command::new("tar").arg("--version").output();
    match out {
        Ok(o) => !String::from_utf8_lossy(&o.stdout).contains("GNU tar"),
        Err(_) => true,
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else {
        return out;
    };
    for ent in rd.flatten() {
        let path = ent.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn mount_and_run(
    prefix: &str,
    files: &[(&str, &[u8])],
    extra: &[&str],
    deadline: Duration,
    cases: impl FnOnce(&Path, &Path, &Path) + Send + 'static,
) {
    if let Some(msg) = skip_reason() {
        eprintln!("{msg}");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    let tar = build_tar(root, files);
    let ov = root.join("ov");
    fs::create_dir_all(&ov).expect("overlay dir");
    let mnt_raw = root.join("mnt");
    fs::create_dir_all(&mnt_raw).expect("mnt dir");
    let mnt = mnt_raw.canonicalize().expect("canonicalize mnt");
    let daemon_log = root.join("daemon.log");

    let mut guard = MountGuard::spawn(&ratarmount_bin(), &ov, &tar, &mnt, &daemon_log, extra);
    if let Err(e) = guard.wait_mounted() {
        panic!("{e}");
    }

    let d = mnt.join("d");
    let ov_dir = ov.clone();
    let tar_path = tar.clone();
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cases(&d, &ov_dir, &tar_path);
        }));
        let _ = tx.send(());
        r
    });
    match rx.recv_timeout(deadline) {
        Ok(()) => {}
        Err(_) => {
            let pid = guard.daemon_pid;
            guard.force_cleanup();
            let _ = worker.join();
            panic!("rename-over case did not finish in {deadline:?} (daemon pid {pid})");
        }
    }
    if let Err(p) = worker.join().expect("cases thread") {
        drop(guard);
        std::panic::resume_unwind(p);
    }
    if let Err(e) = guard.graceful_unmount() {
        panic!("{e}");
    }
}

fn build_tar(root: &Path, files: &[(&str, &[u8])]) -> PathBuf {
    let src = root.join("src");
    for (rel, body) in files {
        let path = src.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture dir");
        }
        fs::write(&path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }
    let tar = root.join("a.tar");
    let status = Command::new("tar")
        .args(["-C", src.to_str().expect("src utf8"), "-cf"])
        .arg(&tar)
        .arg("d")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "tar -cf failed: {status}");
    tar
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
    fn spawn(
        bin: &Path,
        ov: &Path,
        tar: &Path,
        mnt: &Path,
        log_path: &Path,
        extra: &[&str],
    ) -> Self {
        let log = File::create(log_path).expect("daemon log");
        let mut cmd = Command::new(bin);
        cmd.arg("-f").arg("-w").arg(ov);
        cmd.args(extra);
        cmd.arg(tar).arg(mnt);
        let daemon = cmd
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

    /// Lazy unmount, then SIGKILL the daemon this guard spawned.
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
        if mount_visible(&self.mnt) {
            let _ = run_fusermount(&["-u", "-z"], &self.mnt, UNMOUNT_DEADLINE);
        }
        if mount_visible(&self.mnt) {
            eprintln!(
                "warning: {} still mounted after cleanup (fusermount3 failed); unmount it by hand",
                self.mnt.display()
            );
        }
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
    let start = lines.len().saturating_sub(40);
    lines[start..].join("\n")
}
