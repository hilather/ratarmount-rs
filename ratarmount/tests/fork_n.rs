//! Fork-N CLI acceptance. Kernel mounts `eprintln!("skip:")` without `/dev/fuse`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
}

fn layout() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    let top = root.path().join("top");
    let mnt = root.path().join("mnt");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("file"), b"base-bytes").unwrap();
    fs::create_dir_all(top.join("sub/dir")).unwrap();
    fs::write(top.join("sub/dir/file"), b"payload").unwrap();
    fs::create_dir(&mnt).unwrap();
    (root, base, top, mnt)
}

fn run(extra: &[&str], base: &Path, top: &Path, mnt: &Path) -> std::process::Output {
    let mut cmd = bin();
    cmd.args(["--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .args(extra)
        .arg(base);
    cmd.output().unwrap()
}

/// Regression: a nested regular file with nlink > 1 is refused before a session.
#[test]
fn fork_n_hardlink_nlink_at_start() {
    let (_root, base, top, mnt) = layout();
    let file = top.join("sub/dir/file");
    fs::hard_link(&file, top.join("sub/dir/file-link")).unwrap();
    let output = run(&[], &base, &top, &mnt);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(&file.display().to_string()), "{stderr}");
    assert!(stderr.contains("hardlinked regular file"), "{stderr}");

    let (_root, base, top, mnt) = layout();
    let outside = base.join("linked");
    fs::write(&outside, b"x").unwrap();
    fs::hard_link(&outside, base.join("linked-2")).unwrap();
    std::os::unix::fs::symlink(&outside, top.join("sub/dir/via")).unwrap();
    let marker = _root.path().join("admitted");
    let output = bin()
        .env("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT", "1")
        .env("RATARMOUNT_TEST_FORK_N_ADMIT_MARKER", &marker)
        .args(["--foreground", "--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .arg(&base)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("hardlinked regular file"),
        "a symlink is not a hardlink hit: {stderr}"
    );
    assert!(output.status.success(), "{stderr}");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "admitted\n");

    // A directory's st_nlink is already > 1 once it has a subdirectory.
    // A symlink to such a directory outside the top is not a regular file.
    let (_root, base, top, mnt) = layout();
    let outside_dir = base.join("outside-dir");
    fs::create_dir_all(outside_dir.join("nested")).unwrap();
    let linked = outside_dir.join("nested/file");
    fs::write(&linked, b"y").unwrap();
    fs::hard_link(&linked, outside_dir.join("nested/file-link")).unwrap();
    std::os::unix::fs::symlink(&outside_dir, top.join("sub/dir/dir-link")).unwrap();
    let marker = _root.path().join("admitted");
    let output = bin()
        .env("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT", "1")
        .env("RATARMOUNT_TEST_FORK_N_ADMIT_MARKER", &marker)
        .args(["--foreground", "--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .arg(&base)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("hardlinked regular file"),
        "a directory symlink is not a hardlink hit: {stderr}"
    );
    assert!(output.status.success(), "{stderr}");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "admitted\n");
}

/// Regression: the extra link is created during the after-locks hold, not the
/// step-4 hold. The refusing pid wrote `locks-held` and is not the launcher.
#[test]
fn fork_n_hardlink_nlink_after_handoff() {
    after_locks(false);
}

/// Regression: foreground (`-f`) uses the same after-locks hold and does not fork.
#[test]
fn fork_n_hardlink_nlink_after_handoff_foreground() {
    after_locks(true);
}

fn after_locks(foreground: bool) {
    let (root, base, top, mnt) = layout();
    let hold = root.path().join("hold");
    let marker = root.path().join("locks");
    fs::write(&hold, b"1").unwrap();
    let file = top.join("sub/dir/file");
    let mut cmd = bin();
    cmd.env("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_LOCKS", &hold)
        .env("RATARMOUNT_TEST_FORK_N_LOCK_MARKER", &marker)
        .args(["--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .arg(&base);
    if foreground {
        cmd.arg("--foreground");
    }
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let text = loop {
        if marker.is_file() {
            break fs::read_to_string(&marker).unwrap();
        }
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!("marker missing\n{}", String::from_utf8_lossy(&out.stderr));
        }
        std::thread::sleep(Duration::from_millis(30));
    };
    assert!(text.starts_with("locks-held\n"), "{text}");
    let pid: u32 = text.lines().nth(1).unwrap().parse().unwrap();
    if foreground {
        assert_eq!(pid, child.id());
    } else {
        assert_ne!(pid, child.id(), "daemon recheck runs in the child");
    }
    let db = top.join(".ratarmount.overlay.sqlite");
    let start = Instant::now();
    while !db.is_file() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let locked =
        rusqlite::Connection::open(&db).and_then(|conn| conn.execute_batch("BEGIN IMMEDIATE;"));
    assert!(
        locked.is_err(),
        "BEGIN IMMEDIATE must fail while locks are held"
    );
    fs::hard_link(&file, top.join("sub/dir/extra")).unwrap();
    fs::remove_file(&hold).unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(&file.display().to_string()), "{stderr}");
    assert!(stderr.contains("hardlinked regular file"), "{stderr}");
}

/// Regression: a non-empty mountpoint exits 2 before a session and does not call fusermount.
#[test]
fn fork_n_cleanup_occupied_target() {
    let (root, base, top, mnt) = layout();
    fs::write(mnt.join("already"), b"keep").unwrap();
    let recorder = root.path().join("fusermount-log");
    let script = root.path().join("fusermount-rec");
    fs::write(
        &script,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$RATARMOUNT_TEST_FUSERMOUNT_LOG\"\nexit 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }
    let output = bin()
        .env("RATARMOUNT_TEST_FUSERMOUNT", &script)
        .env("RATARMOUNT_TEST_FUSERMOUNT_LOG", &recorder)
        .args(["--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .arg(&base)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("not an empty directory"), "{stderr}");
    assert!(fs::read(mnt.join("already")).unwrap() == b"keep");
    assert!(
        !recorder.exists(),
        "fusermount recorder must see zero calls"
    );
}

/// Regression: daemon torrent inputs are refused with `use --foreground`.
/// Foreground gets the coverage diagnostic and does not say `use --foreground`.
#[test]
fn fork_n_daemon_sources_torrent_spelling() {
    let (root, _base, top, mnt) = layout();
    let torrent = root.path().join("disk.torrent");
    fs::write(&torrent, b"d8:announce0:e").unwrap();
    let daemon = bin()
        .args(["--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .arg(&torrent)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&daemon.stderr);
    assert_eq!(daemon.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("use --foreground"), "{stderr}");
    assert!(
        stderr.contains("fork-n daemon refuses torrent input"),
        "{stderr}"
    );

    let foreground = bin()
        .args(["--foreground", "--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .arg(&torrent)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&foreground.stderr);
    assert_eq!(foreground.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("fork-n has no storage coverage for torrent"),
        "{stderr}"
    );
    assert!(!stderr.contains("use --foreground"), "{stderr}");
}

/// Regression: daemon preparation is `Preparing` before the source constructor.
#[test]
fn fork_n_daemon_workers_phase_before_constructor() {
    let (root, base, top, mnt) = layout();
    let log = root.path().join("phase");
    let marker = root.path().join("admitted");
    let output = bin()
        .env("RATARMOUNT_TEST_FORK_N_PHASE_LOG", &log)
        .env("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT", "1")
        .env("RATARMOUNT_TEST_FORK_N_ADMIT_MARKER", &marker)
        .args(["--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .arg(&base)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let phase = fs::read_to_string(&log).unwrap();
    assert!(phase.contains("Preparing"), "{phase}");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "admitted\n");
}

/// Regression: `STOP_AFTER_ADMIT` exits 0 only after the owning database is admitted.
#[test]
fn fork_n_self_reopen_backing_under_mountpoint_stop_after_admit() {
    let (root, base, top, mnt) = layout();
    let marker = root.path().join("admitted");
    let output = bin()
        .env("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT", "1")
        .env("RATARMOUNT_TEST_FORK_N_ADMIT_MARKER", &marker)
        .args(["--foreground", "--top", &format!("A={}", top.display())])
        .args(["--mount", &format!("A={}", mnt.display())])
        .arg(&base)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "admitted\n");
}

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists() && Path::new("/usr/bin/fusermount3").exists()
}

fn recorder(dir: &Path) -> (PathBuf, PathBuf) {
    let log = dir.join("fusermount-log");
    let script = dir.join("fusermount-rec");
    fs::write(
        &script,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$RATARMOUNT_TEST_FUSERMOUNT_LOG\"\nexec fusermount3 \"$@\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }
    (script, log)
}

struct Cohort {
    root: tempfile::TempDir,
    base: PathBuf,
    top_a: PathBuf,
    top_b: PathBuf,
    mnt_a: PathBuf,
    mnt_b: PathBuf,
}

fn two_tops() -> Cohort {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    let top_a = root.path().join("top-a");
    let top_b = root.path().join("top-b");
    let mnt_a = root.path().join("mnt-a");
    let mnt_b = root.path().join("mnt-b");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("file"), b"base-bytes").unwrap();
    for top in [&top_a, &top_b] {
        fs::create_dir_all(top.join("sub/dir")).unwrap();
        fs::write(top.join("sub/dir/file"), b"payload").unwrap();
    }
    fs::create_dir(&mnt_a).unwrap();
    fs::create_dir(&mnt_b).unwrap();
    Cohort {
        root,
        base,
        top_a,
        top_b,
        mnt_a,
        mnt_b,
    }
}

fn spawn_cohort(
    cohort: &Cohort,
    extra_env: &[(&str, &Path)],
    foreground: bool,
) -> std::process::Child {
    let mut cmd = bin();
    cmd.env("RATARMOUNT_TEST_FORK_N_FAIL_MOUNT", "B")
        .args(["--top", &format!("A={}", cohort.top_a.display())])
        .args(["--top", &format!("B={}", cohort.top_b.display())])
        .args(["--mount", &format!("A={}", cohort.mnt_a.display())])
        .args(["--mount", &format!("B={}", cohort.mnt_b.display())])
        .arg(&cohort.base);
    if foreground {
        cmd.arg("--foreground");
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_child(mut child: std::process::Child, bound: Duration) -> std::process::Output {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut output = child.wait_with_output().unwrap();
            output.status = status;
            return output;
        }
        if start.elapsed() > bound {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "fork-n partial start hung\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

fn assert_unmounted_only_a(log: &str, mnt_a: &Path, mnt_b: &Path) {
    assert!(log.contains("-u"), "{log}");
    assert!(!log.contains("-z"), "{log}");
    assert!(log.contains(&mnt_a.display().to_string()), "{log}");
    assert!(
        !log.contains(&mnt_b.display().to_string()),
        "B never gets a session: {log}"
    );
}

/// Regression: a failed second mount unmounts only the session this process
/// reported. Stomp, killed-child, and foreground use the same `FAIL_MOUNT=B`.
#[test]
fn fork_n_cleanup_partial_start() {
    if !fuse_available() {
        eprintln!("skip: /dev/fuse or fusermount3 unavailable");
        return;
    }
    let cohort = two_tops();
    let (script, log) = recorder(cohort.root.path());
    let output = wait_child(
        spawn_cohort(
            &cohort,
            &[
                ("RATARMOUNT_TEST_FUSERMOUNT", script.as_path()),
                ("RATARMOUNT_TEST_FUSERMOUNT_LOG", log.as_path()),
            ],
            false,
        ),
        Duration::from_secs(45),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = fs::read_to_string(&log).unwrap_or_default();
    assert_ne!(output.status.code(), Some(0), "{stderr}");
    assert_unmounted_only_a(&text, &cohort.mnt_a, &cohort.mnt_b);

    let cohort = two_tops();
    let (script, log) = recorder(cohort.root.path());
    let output = wait_child(
        spawn_cohort(
            &cohort,
            &[
                ("RATARMOUNT_TEST_FUSERMOUNT", script.as_path()),
                ("RATARMOUNT_TEST_FUSERMOUNT_LOG", log.as_path()),
            ],
            true,
        ),
        Duration::from_secs(45),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(output.status.code(), Some(0), "{stderr}");
    let text = fs::read_to_string(&log).unwrap_or_default();
    assert_unmounted_only_a(&text, &cohort.mnt_a, &cohort.mnt_b);

    let cohort = two_tops();
    let (script, log) = recorder(cohort.root.path());
    let hold = cohort.root.path().join("report-hold");
    let held = cohort.root.path().join("report-held");
    let child_pid = cohort.root.path().join("child-pid");
    fs::write(&hold, b"1").unwrap();
    let child = spawn_cohort(
        &cohort,
        &[
            ("RATARMOUNT_TEST_FUSERMOUNT", script.as_path()),
            ("RATARMOUNT_TEST_FUSERMOUNT_LOG", log.as_path()),
            ("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT", Path::new("A")),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HOLD", hold.as_path()),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HELD", held.as_path()),
            ("RATARMOUNT_TEST_FORK_N_CHILD_PID", child_pid.as_path()),
        ],
        false,
    );
    let start = Instant::now();
    while !held.is_file() {
        if start.elapsed() > Duration::from_secs(40) {
            let _ = Command::new("kill").arg(child.id().to_string()).status();
            let output = wait_child(child, Duration::from_secs(5));
            panic!(
                "report hold missing\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let pid = fs::read_to_string(&child_pid).unwrap();
    // The report line is already in the pipe. Give the launcher one poll
    // interval to record it before the child disappears.
    std::thread::sleep(Duration::from_millis(500));
    let status = Command::new("kill")
        .args(["-KILL", pid.trim()])
        .status()
        .unwrap();
    assert!(status.success(), "kill {}", pid.trim());
    let output = wait_child(child, Duration::from_secs(20));
    assert_ne!(output.status.code(), Some(0));
    let text = fs::read_to_string(&log).unwrap_or_default();
    assert_unmounted_only_a(&text, &cohort.mnt_a, &cohort.mnt_b);
    for top in [&cohort.top_a, &cohort.top_b] {
        let db = top.join(".ratarmount.overlay.sqlite");
        if db.is_file() {
            rusqlite::Connection::open(&db)
                .and_then(|conn| conn.execute_batch("BEGIN IMMEDIATE;"))
                .expect("BEGIN IMMEDIATE after the child is gone");
        }
    }

    let cohort = two_tops();
    let (script, log) = recorder(cohort.root.path());
    let hold = cohort.root.path().join("report-hold");
    let held = cohort.root.path().join("report-held");
    let cover = cohort.root.path().join("cover");
    fs::create_dir(&cover).unwrap();
    fs::write(&hold, b"1").unwrap();
    let child = spawn_cohort(
        &cohort,
        &[
            ("RATARMOUNT_TEST_FUSERMOUNT", script.as_path()),
            ("RATARMOUNT_TEST_FUSERMOUNT_LOG", log.as_path()),
            ("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT", Path::new("A")),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HOLD", hold.as_path()),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HELD", held.as_path()),
        ],
        true,
    );
    let start = Instant::now();
    while !held.is_file() {
        if start.elapsed() > Duration::from_secs(40) {
            let _ = Command::new("kill").arg(child.id().to_string()).status();
            let output = wait_child(child, Duration::from_secs(5));
            panic!(
                "stomp hold missing\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let bound = Command::new("mount")
        .args([
            "--bind",
            &cover.display().to_string(),
            &cohort.mnt_a.display().to_string(),
        ])
        .status();
    if bound.map(|status| status.success()).unwrap_or(false) {
        fs::remove_file(&hold).unwrap();
        let output = wait_child(child, Duration::from_secs(20));
        assert_ne!(output.status.code(), Some(0));
        assert!(
            !log.exists() || fs::read_to_string(&log).unwrap_or_default().is_empty(),
            "inode mismatch must suppress unmount"
        );
        let _ = Command::new("umount").arg(&cohort.mnt_a).status();
    } else {
        eprintln!("skip: bind mount over A is not permitted");
        fs::remove_file(&hold).unwrap();
        let _ = wait_child(child, Duration::from_secs(20));
        let _ = Command::new("fusermount3")
            .args(["-u", &cohort.mnt_a.display().to_string()])
            .status();
    }
}
