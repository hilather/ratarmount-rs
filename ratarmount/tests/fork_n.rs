//! Fork-N PR2a: identity, hardlinks, self-reopen, and v1 cleanup.
//!
//! Partial-start mounts for real. Missing `/dev/fuse` or `fusermount3` is
//! `skip:`. `fusermount3` returning `Operation not permitted` is a failure.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};

const DB_NAME: &str = ".ratarmount.overlay.sqlite";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ratarmount")
}

fn clear_fork_env(cmd: &mut Command) {
    for key in [
        "RATARMOUNT_TEST_FORK_N_HOLD_AFTER_LOCKS",
        "RATARMOUNT_TEST_FORK_N_LOCK_MARKER",
        "RATARMOUNT_TEST_FORK_N_FAIL_MOUNT",
        "RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT",
        "RATARMOUNT_TEST_FORK_N_REPORT_HOLD",
        "RATARMOUNT_TEST_FORK_N_REPORT_HELD",
        "RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT",
        "RATARMOUNT_TEST_FORK_N_ADMIT_MARKER",
        "RATARMOUNT_TEST_FORK_N_READY_LOG",
        "RATARMOUNT_TEST_FORK_N_SPY_LOG",
        "RATARMOUNT_TEST_FORK_N_CHILD_EXIT",
        "RATARMOUNT_TEST_FUSERMOUNT",
    ] {
        cmd.env_remove(key);
    }
}

fn write_tar(path: &Path) {
    let mut file = File::create(path).unwrap();
    write_ustar_members(
        &mut file,
        &[UstarMember {
            path: "hello.txt",
            payload: UstarPayload::File { bytes: b"hello\n" },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        }],
    )
    .unwrap();
    write_tar_eof(&mut file).unwrap();
}

fn write_qcow(path: &Path, backing: &str) {
    let mut hdr = vec![0u8; 72];
    hdr[0..4].copy_from_slice(b"QFI\xfb");
    hdr[4..8].copy_from_slice(&2u32.to_be_bytes());
    hdr[8..16].copy_from_slice(&72u64.to_be_bytes());
    hdr[16..20].copy_from_slice(&(backing.len() as u32).to_be_bytes());
    hdr[20..24].copy_from_slice(&9u32.to_be_bytes());
    hdr[24..32].copy_from_slice(&4096u64.to_be_bytes());
    hdr.extend_from_slice(backing.as_bytes());
    fs::write(path, hdr).unwrap();
}

fn db_path(top: &Path) -> PathBuf {
    top.join(DB_NAME)
}

fn spawn(args: &[String], env: &[(&str, &str)], stderr: &Path) -> std::process::Child {
    let err = File::create(stderr).unwrap();
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(err);
    clear_fork_env(&mut cmd);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.spawn().expect("spawn ratarmount")
}

fn kill_tree(pid: u32) {
    let children =
        fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap_or_default();
    for child in children.split_whitespace() {
        if let Ok(raw) = child.parse::<i32>() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(raw),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGKILL,
    );
}

fn finish(child: &mut std::process::Child, timeout: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if start.elapsed() > timeout {
            kill_tree(child.id());
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(30));
    }
}

fn wait_contains(path: &Path, needle: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if fs::read_to_string(path)
            .ok()
            .is_some_and(|text| text.contains(needle))
        {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

fn stderr_of(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn spy(path: &Path) -> (u64, u64, u64, u64) {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut admit = None;
    let mut open = None;
    let mut create = None;
    let mut truncate = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("admit=") {
            admit = value.parse().ok();
        } else if let Some(value) = line.strip_prefix("open=") {
            open = value.parse().ok();
        } else if let Some(value) = line.strip_prefix("create=") {
            create = value.parse().ok();
        } else if let Some(value) = line.strip_prefix("truncate=") {
            truncate = value.parse().ok();
        }
    }
    (
        admit.expect(&text),
        open.expect(&text),
        create.expect(&text),
        truncate.expect(&text),
    )
}

fn assert_no_ready(path: &Path) {
    if path.exists() {
        let text = fs::read_to_string(path).unwrap();
        assert!(
            text.lines().all(|line| line != "ready"),
            "ready line was written:\n{text}"
        );
    }
}

fn assert_honored_without_ready(path: &Path) {
    let text = fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    assert!(
        text.lines().any(|line| line == "fusermount-honored"),
        "ready log missing fusermount-honored:\n{text}"
    );
    assert!(
        text.lines().all(|line| line != "ready"),
        "ready line was written:\n{text}"
    );
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

/// Parent pid of `pid`, from `ps` (portable; `/proc` is Linux only).
fn parent_pid(pid: u32) -> Option<u32> {
    let out = Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

fn pid_alive(pid: u32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
}

/// Open fds in `pid` whose target is `db` (lstat of the link, not a follow of `db`).
#[cfg(target_os = "linux")]
fn sqlite_fd_count(pid: u32, db: &Path) -> usize {
    let Ok(want) = fs::canonicalize(db) else {
        return 0;
    };
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| fs::read_link(entry.path()).is_ok_and(|target| target == want))
        .count()
}

fn assert_locked(path: &Path) {
    assert!(
        is_regular_file(path),
        "database is not a regular file: {}",
        path.display()
    );
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.busy_timeout(Duration::ZERO).unwrap();
    let err = conn
        .execute_batch("BEGIN IMMEDIATE")
        .expect_err("BEGIN IMMEDIATE should block on the held lock");
    let text = err.to_string().to_ascii_lowercase();
    assert!(
        text.contains("locked") || text.contains("busy"),
        "{}: {err}",
        path.display()
    );
}

fn assert_immediate_succeeds(path: &Path) {
    assert!(
        path.is_file(),
        "database missing after the killed child: {}",
        path.display()
    );
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.busy_timeout(Duration::from_secs(2)).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE; COMMIT;")
        .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
}

fn script(path: &Path, body: &str) {
    let mut file = File::create(path).unwrap();
    file.write_all(body.as_bytes()).unwrap();
    let mut perms = file.metadata().unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

fn recording_fusermount(path: &Path, log: &Path, exec_real: bool) {
    let body = if exec_real {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexec fusermount3 \"$@\"\n",
            shell_quote(log)
        )
    } else {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexit 0\n",
            shell_quote(log)
        )
    };
    script(path, &body);
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn code_of(status: Option<ExitStatus>, stderr: &Path) -> i32 {
    match status {
        Some(status) => status
            .code()
            .unwrap_or_else(|| panic!("signaled\n{}", stderr_of(stderr))),
        None => panic!("timed out\n{}", stderr_of(stderr)),
    }
}

fn no_database(tops: &[&Path]) {
    for top in tops {
        assert!(
            !db_path(top).exists(),
            "overlay database was created under {}",
            top.display()
        );
    }
}

struct UmountGuard(Vec<PathBuf>);

impl Drop for UmountGuard {
    fn drop(&mut self) {
        for path in &self.0 {
            let text = path.display().to_string();
            let _ = Command::new("fusermount3").args(["-u", &text]).status();
            let _ = Command::new("umount").arg(&text).status();
            let _ = Command::new("umount").args(["-l", &text]).status();
        }
    }
}

fn try_bind(source: &Path, target: &Path) -> bool {
    Command::new("mount")
        .args([
            "--bind",
            &source.display().to_string(),
            &target.display().to_string(),
        ])
        .status()
        .is_ok_and(|status| status.success())
}

fn fork_pair(
    archive: &Path,
    top_a: &Path,
    mnt_a: &Path,
    top_b: &Path,
    mnt_b: &Path,
) -> Vec<String> {
    vec![
        "--top".into(),
        format!("A={}", top_a.display()),
        "--mount".into(),
        format!("A={}", mnt_a.display()),
        "--top".into(),
        format!("B={}", top_b.display()),
        "--mount".into(),
        format!("B={}", mnt_b.display()),
        "--index-file".into(),
        ":memory:".into(),
        archive.display().to_string(),
    ]
}

/// Regression: `--bind` stole the only directory positional, so Fork-N never opened it.
#[test]
fn fork_n_bind_directory_stays_a_source() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"x").unwrap();
    let top = root.path().join("top");
    let mnt = root.path().join("mnt");
    fs::create_dir(&top).unwrap();
    fs::create_dir(&mnt).unwrap();
    let marker = root.path().join("admitted");
    let stderr = root.path().join("err");
    let mut args = vec![
        "--top".into(),
        format!("A={}", top.display()),
        "--mount".into(),
        format!("A={}", mnt.display()),
        "--bind".into(),
        "/missing=/no/such".into(),
        "--index-file".into(),
        ":memory:".into(),
        source.display().to_string(),
    ];
    let _ = &mut args;
    let mut child = spawn(
        &args,
        &[
            ("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT", "1"),
            (
                "RATARMOUNT_TEST_FORK_N_ADMIT_MARKER",
                marker.to_str().unwrap(),
            ),
        ],
        &stderr,
    );
    let status = finish(&mut child, Duration::from_secs(60));
    assert_eq!(code_of(status, &stderr), 0, "{}", stderr_of(&stderr));
    assert_eq!(fs::read_to_string(&marker).unwrap(), "admitted\n");
}

/// Regression: a mount on, inside, or over its top still created the overlay database.
#[test]
fn fork_n_identity_mount_over_top_exits_before_database() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive.tar");
    write_tar(&archive);
    let other_top = root.path().join("other-top");
    let other_mnt = root.path().join("other-mnt");
    fs::create_dir(&other_top).unwrap();
    fs::create_dir(&other_mnt).unwrap();

    let equal = root.path().join("same");
    fs::create_dir(&equal).unwrap();
    let parent = root.path().join("parent");
    let nested_top = parent.join("top");
    fs::create_dir_all(&nested_top).unwrap();
    let covering = root.path().join("covering");
    let child = covering.join("mnt");
    fs::create_dir_all(&child).unwrap();

    for (label, top, mnt, word) in [
        ("equal", equal.as_path(), equal.as_path(), ": on "),
        ("parent", nested_top.as_path(), parent.as_path(), ": over "),
        ("child", covering.as_path(), child.as_path(), ": inside "),
    ] {
        let stderr = root.path().join(format!("{label}.err"));
        let mut args = fork_pair(&archive, top, mnt, &other_top, &other_mnt);
        args.insert(0, "--force-stack-mismatch".into());
        let mut child = spawn(&args, &[], &stderr);
        let status = finish(&mut child, Duration::from_secs(30));
        let text = stderr_of(&stderr);
        assert_eq!(code_of(status, &stderr), 2, "{label}: {text}");
        assert!(text.contains("fork-n refuses mount"), "{label}: {text}");
        assert!(text.contains(word), "{label}: {text}");
        no_database(&[top, &other_top]);
    }
}

/// Regression: a hardlinked regular file under `sub/dir` was mounted, and a
/// directory or symlink with `nlink > 1` was refused.
#[test]
fn fork_n_hardlink_nlink_at_start() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive.tar");
    write_tar(&archive);
    let top_a = root.path().join("top-a");
    let top_b = root.path().join("top-b");
    let mnt_a = root.path().join("mnt-a");
    let mnt_b = root.path().join("mnt-b");
    let nested = top_a.join("sub/dir");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir_all(&top_b).unwrap();
    fs::create_dir_all(&mnt_a).unwrap();
    fs::create_dir_all(&mnt_b).unwrap();
    let file = nested.join("file");
    fs::write(&file, b"payload").unwrap();
    let outside = root.path().join("outside-link");
    fs::hard_link(&file, &outside).unwrap();
    let ready = root.path().join("ready");
    let stderr = root.path().join("err");
    let args = fork_pair(&archive, &top_a, &mnt_a, &top_b, &mnt_b);
    let mut child = spawn(
        &args,
        &[("RATARMOUNT_TEST_FORK_N_READY_LOG", ready.to_str().unwrap())],
        &stderr,
    );
    let status = finish(&mut child, Duration::from_secs(30));
    let text = stderr_of(&stderr);
    assert_eq!(code_of(status, &stderr), 2, "{text}");
    assert!(
        text.contains(&format!(
            "fork-n refuses hardlinked regular file {}",
            file.canonicalize().unwrap().display()
        )),
        "{text}"
    );
    assert_no_ready(&ready);
    assert!(outside.is_file());
    no_database(&[&top_a, &top_b]);

    fs::remove_file(&outside).unwrap();
    fs::remove_file(&file).unwrap();
    let via_target = root.path().join("via-target");
    fs::write(&via_target, b"via").unwrap();
    fs::hard_link(&via_target, root.path().join("via-target-2")).unwrap();
    std::os::unix::fs::symlink(&via_target, nested.join("via")).unwrap();
    admit_control(
        &archive,
        &top_a,
        &mnt_a,
        &top_b,
        &mnt_b,
        &root.path().join("via"),
    );

    let dir_target = root.path().join("dir-target");
    fs::create_dir(&dir_target).unwrap();
    let linked = dir_target.join("linked");
    fs::write(&linked, b"linked").unwrap();
    fs::hard_link(&linked, root.path().join("linked-2")).unwrap();
    std::os::unix::fs::symlink(&dir_target, nested.join("dir-link")).unwrap();
    admit_control(
        &archive,
        &top_a,
        &mnt_a,
        &top_b,
        &mnt_b,
        &root.path().join("dir"),
    );

    fs::write(&file, b"plain").unwrap();
    let meta = fs::metadata(top_a.join("sub")).unwrap();
    assert!(std::os::unix::fs::MetadataExt::nlink(&meta) > 1);
    admit_control(
        &archive,
        &top_a,
        &mnt_a,
        &top_b,
        &mnt_b,
        &root.path().join("sub"),
    );
}

fn admit_control(
    archive: &Path,
    top_a: &Path,
    mnt_a: &Path,
    top_b: &Path,
    mnt_b: &Path,
    marker: &Path,
) {
    let _ = fs::remove_file(marker);
    let stderr = marker.with_extension("err");
    let args = fork_pair(archive, top_a, mnt_a, top_b, mnt_b);
    let mut child = spawn(
        &args,
        &[
            ("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT", "1"),
            (
                "RATARMOUNT_TEST_FORK_N_ADMIT_MARKER",
                marker.to_str().unwrap(),
            ),
        ],
        &stderr,
    );
    let status = finish(&mut child, Duration::from_secs(60));
    let text = stderr_of(&stderr);
    assert_eq!(code_of(status, &stderr), 0, "{text}");
    assert_eq!(fs::read_to_string(marker).unwrap(), "admitted\n");
    assert!(!text.contains("hardlinked regular file"), "{text}");
}

fn handoff(foreground: bool) {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive.tar");
    write_tar(&archive);
    let top_a = root.path().join("top-a");
    let top_b = root.path().join("top-b");
    let mnt_a = root.path().join("mnt-a");
    let mnt_b = root.path().join("mnt-b");
    let nested = top_a.join("sub/dir");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir_all(&top_b).unwrap();
    fs::create_dir_all(&mnt_a).unwrap();
    fs::create_dir_all(&mnt_b).unwrap();
    let file = nested.join("file");
    fs::write(&file, b"payload").unwrap();
    let hold = root.path().join("hold");
    fs::write(&hold, b"1").unwrap();
    let locks = root.path().join("locks");
    let ready = root.path().join("ready");
    let argv_log = root.path().join("fusermount-argv");
    let fusermount = root.path().join("fusermount");
    recording_fusermount(&fusermount, &argv_log, false);
    let stderr = root.path().join("err");
    let child_exit = root.path().join("child-exit");
    let mut args = fork_pair(&archive, &top_a, &mnt_a, &top_b, &mnt_b);
    if foreground {
        args.insert(0, "-f".into());
    }
    let mut env = vec![
        (
            "RATARMOUNT_TEST_FORK_N_HOLD_AFTER_LOCKS",
            hold.to_str().unwrap(),
        ),
        (
            "RATARMOUNT_TEST_FORK_N_LOCK_MARKER",
            locks.to_str().unwrap(),
        ),
        ("RATARMOUNT_TEST_FORK_N_READY_LOG", ready.to_str().unwrap()),
        ("RATARMOUNT_TEST_FUSERMOUNT", fusermount.to_str().unwrap()),
    ];
    if !foreground {
        env.push((
            "RATARMOUNT_TEST_FORK_N_CHILD_EXIT",
            child_exit.to_str().unwrap(),
        ));
    }
    let mut child = spawn(&args, &env, &stderr);
    assert!(
        wait_contains(&locks, "locks-held\n", Duration::from_secs(60)),
        "locks marker missing\n{}",
        stderr_of(&stderr)
    );
    assert!(is_regular_file(&db_path(&top_a)));
    assert!(is_regular_file(&db_path(&top_b)));
    assert_locked(&db_path(&top_a));
    assert_locked(&db_path(&top_b));
    assert_honored_without_ready(&ready);
    assert!(!argv_log.exists(), "fusermount was invoked");
    let marker = fs::read_to_string(&locks).unwrap();
    let pid: u32 = marker
        .lines()
        .nth(1)
        .and_then(|line| line.parse().ok())
        .expect(&marker);
    if foreground {
        assert_eq!(pid, child.id());
    } else {
        #[cfg(target_os = "linux")]
        {
            let kids =
                fs::read_to_string(format!("/proc/{}/task/{}/children", child.id(), child.id()))
                    .unwrap_or_default();
            assert!(
                kids.split_whitespace().any(|kid| kid == pid.to_string()),
                "marker pid {pid} is not the forked child ({kids})"
            );
        }
        // Portable: the marker pid is a direct child of the launcher. The
        // `forwarded` nonce check after exit proves the launcher waited on it.
        assert_eq!(
            parent_pid(pid),
            Some(child.id()),
            "marker pid {pid} is not the forked child"
        );
        // The parent dropped its connections before the fork. The child
        // reopened both databases. A parent that never released still has
        // the fd, and a child that never reopened does not.
        #[cfg(target_os = "linux")]
        for db in [db_path(&top_a), db_path(&top_b)] {
            assert!(
                sqlite_fd_count(pid, &db) >= 1,
                "child {pid} does not hold {}",
                db.display()
            );
            assert_eq!(
                sqlite_fd_count(child.id(), &db),
                0,
                "launcher still holds {}",
                db.display()
            );
        }
    }
    fs::hard_link(&file, root.path().join("extra-name")).unwrap();
    fs::remove_file(&hold).unwrap();
    let status = finish(&mut child, Duration::from_secs(30));
    let text = stderr_of(&stderr);
    assert_eq!(code_of(status, &stderr), 2, "{text}");
    if !foreground {
        let gone = (0..50).any(|_| {
            if !pid_alive(pid) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
            false
        });
        assert!(gone, "marker pid {pid} still alive after exit 2");
        // The child writes a nonce only it chose, then exits 2. The launcher
        // prints `forwarded` only from the waitpid arm, with that nonce.
        // `process::exit(2)` without waitpid leaves the line absent.
        let recorded = fs::read_to_string(&child_exit).unwrap_or_default();
        let mut parts = recorded.split_whitespace();
        let recorded_pid = parts.next().unwrap_or("");
        let nonce = parts.next().unwrap_or("");
        let recorded_code = parts.next().unwrap_or("");
        assert_eq!(
            recorded_pid,
            pid.to_string(),
            "locks-held pid did not write the exit marker\n{recorded}"
        );
        assert_eq!(
            recorded_code, "2",
            "locks-held pid did not exit 2\n{recorded}"
        );
        assert!(
            !nonce.is_empty() && nonce.chars().all(|ch| ch.is_ascii_hexdigit()),
            "child nonce missing\n{recorded}"
        );
        assert!(
            text.contains(&format!("fork-n child-exit {pid} {nonce} 2")),
            "hardlink stderr was not produced by the locks-held pid\n{text}"
        );
        assert!(
            text.contains(&format!("fork-n forwarded {pid} {nonce} 2")),
            "launcher did not forward the locks-held pid's status\n{text}"
        );
    }
    assert!(
        text.contains(&format!(
            "fork-n refuses hardlinked regular file {}",
            file.canonicalize().unwrap().display()
        )),
        "{text}"
    );
    assert_honored_without_ready(&ready);
    assert!(!argv_log.exists());
}

/// Regression: a hard link added after the child held both locks was not seen,
/// or the launcher turned that exit 2 into 1.
#[test]
fn fork_n_hardlink_nlink_after_handoff() {
    handoff(false);
}

/// Regression: foreground Fork-N forked again, or skipped the lock recheck.
#[test]
fn fork_n_hardlink_nlink_after_handoff_foreground() {
    handoff(true);
}

/// Regression: a backing or index path under a mountpoint was opened or created.
#[test]
fn fork_n_self_reopen_backing_under_mountpoint() {
    let root = tempfile::tempdir().unwrap();
    let top = root.path().join("top");
    let mnt = root.path().join("mnt");
    fs::create_dir_all(&top).unwrap();
    fs::create_dir_all(&mnt).unwrap();
    let outside = root.path().join("backing.bin");
    fs::write(&outside, b"raw-backing").unwrap();
    let under = mnt.join("backing.bin");
    fs::write(&under, b"raw-backing").unwrap();

    let under_text = under.display().to_string();
    qcow_case(
        &root,
        &top,
        &mnt,
        &under,
        QcowExpect {
            code: 2,
            needle: &under_text,
            fork_n: true,
            counts: Some((0, 0)),
        },
    );
    qcow_case(
        &root,
        &top,
        &mnt,
        &outside,
        QcowExpect {
            code: 1,
            needle: "no supported filesystems",
            fork_n: false,
            counts: Some((1, 1)),
        },
    );

    let missing = root.path().join("absent-backing");
    qcow_case(
        &root,
        &top,
        &mnt,
        &missing,
        QcowExpect {
            code: 1,
            needle: "not found",
            fork_n: false,
            counts: Some((0, 0)),
        },
    );
    let parent = mnt.join("sub");
    fs::create_dir(&parent).unwrap();
    let missing_under = parent.join("backing");
    qcow_case(
        &root,
        &top,
        &mnt,
        &missing_under,
        QcowExpect {
            code: 2,
            needle: "canonical path is under a cohort mountpoint",
            fork_n: true,
            counts: Some((0, 0)),
        },
    );
    assert!(!missing_under.exists());
    let missing_err = fs::read_to_string(root.path().join(format!(
        "err-{}",
        missing_under.file_name().unwrap().to_string_lossy()
    )))
    .unwrap_or_default();
    assert!(
        missing_err.contains(&missing_under.display().to_string()),
        "{missing_err}"
    );
    assert!(
        !missing_err.contains("not an empty directory"),
        "{missing_err}"
    );

    let loop_path = root.path().join("loop");
    std::os::unix::fs::symlink("loop", &loop_path).unwrap();
    qcow_case(
        &root,
        &top,
        &mnt,
        &loop_path,
        QcowExpect {
            code: 2,
            needle: "fork-n refuses to resolve",
            fork_n: true,
            counts: Some((0, 0)),
        },
    );
    let ancestor = root.path().join("missing-ancestor/backing");
    qcow_case(
        &root,
        &top,
        &mnt,
        &ancestor,
        QcowExpect {
            code: 2,
            needle: "fork-n refuses to resolve",
            fork_n: true,
            counts: Some((0, 0)),
        },
    );

    for suffix in ["-wal", "-shm", "-journal"] {
        let target = mnt.join(format!("payload{suffix}"));
        fs::write(&target, b"x").unwrap();
        let link = top.join(format!("{DB_NAME}{suffix}"));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (code, text, counts) = tar_case(&root, &top, &mnt, &[], true);
        assert_eq!(code, 2, "{suffix}: {text}");
        assert!(text.contains("fork-n"), "{suffix}: {text}");
        assert!(
            text.contains(&link.display().to_string()),
            "{suffix}: {text}"
        );
        assert_eq!(counts.1, 0, "{suffix} open count");
        fs::remove_file(&link).unwrap();
    }

    fs::create_dir_all(mnt.join("idx")).unwrap();
    let index = mnt.join("idx/catalog.sqlite");
    let (code, text, counts) = tar_case(
        &root,
        &top,
        &mnt,
        &["--index-file", index.to_str().unwrap()],
        true,
    );
    assert_eq!(code, 2, "{text}");
    assert!(
        text.contains("canonical path is under a cohort mountpoint"),
        "{text}"
    );
    assert!(text.contains(&index.display().to_string()), "{text}");
    assert!(!text.contains("not an empty directory"), "{text}");
    assert_eq!((counts.2, counts.3), (0, 0), "create/truncate");
    assert!(!index.exists());

    let marker = root.path().join("admitted");
    let early = root.path().join("early-err");
    let early_spy = root.path().join("early.spy");
    let hard = top.join("sub/dir/file");
    fs::create_dir_all(hard.parent().unwrap()).unwrap();
    fs::write(&hard, b"x").unwrap();
    fs::hard_link(&hard, root.path().join("hard-outside")).unwrap();
    let archive = root.path().join("early.tar");
    write_tar(&archive);
    let args = vec![
        "-f".into(),
        "--top".into(),
        format!("A={}", top.display()),
        "--mount".into(),
        format!("A={}", mnt.display()),
        "--index-file".into(),
        ":memory:".into(),
        archive.display().to_string(),
    ];
    let mut child = spawn(
        &args,
        &[
            ("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT", "1"),
            (
                "RATARMOUNT_TEST_FORK_N_ADMIT_MARKER",
                marker.to_str().unwrap(),
            ),
            (
                "RATARMOUNT_TEST_FORK_N_SPY_LOG",
                early_spy.to_str().unwrap(),
            ),
        ],
        &early,
    );
    let status = finish(&mut child, Duration::from_secs(30));
    assert_eq!(code_of(status, &early), 2, "{}", stderr_of(&early));
    assert!(!marker.exists(), "admit marker written before admission");
    assert_eq!(
        spy(&early_spy).0,
        0,
        "hardlink refusal admitted a path before the walk"
    );
    fs::remove_file(root.path().join("hard-outside")).unwrap();
    fs::remove_file(&hard).unwrap();
    // The index subcase left `mnt/idx`, and earlier cases left files under the
    // mountpoint. STOP_AFTER_ADMIT only exits 0 when every target is empty.
    for entry in fs::read_dir(&mnt).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            fs::remove_dir_all(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
    }

    let stderr = root.path().join("admit-err");
    let admit_spy = root.path().join("admit.spy");
    let archive = root.path().join("admit.tar");
    write_tar(&archive);
    let args = vec![
        "-f".into(),
        "--top".into(),
        format!("A={}", top.display()),
        "--mount".into(),
        format!("A={}", mnt.display()),
        "--index-file".into(),
        ":memory:".into(),
        archive.display().to_string(),
    ];
    let mut child = spawn(
        &args,
        &[
            ("RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT", "1"),
            (
                "RATARMOUNT_TEST_FORK_N_ADMIT_MARKER",
                marker.to_str().unwrap(),
            ),
            (
                "RATARMOUNT_TEST_FORK_N_SPY_LOG",
                admit_spy.to_str().unwrap(),
            ),
        ],
        &stderr,
    );
    let status = finish(&mut child, Duration::from_secs(60));
    assert_eq!(code_of(status, &stderr), 0, "{}", stderr_of(&stderr));
    assert_eq!(fs::read_to_string(&marker).unwrap(), "admitted\n");
    // One top: the database plus `-wal`, `-shm`, and `-journal`. A marker
    // written before `admit_overlay_db` still says `admitted` and leaves
    // this count at 0. `:memory:` admits nothing else.
    assert_eq!(
        spy(&admit_spy).0,
        4,
        "owning-top database and three companions were not all admitted"
    );
    assert!(
        is_regular_file(&top.join(DB_NAME)),
        "overlay database was not a regular file when the marker was written"
    );
}

struct QcowExpect<'a> {
    code: i32,
    needle: &'a str,
    fork_n: bool,
    counts: Option<(u64, u64)>,
}

fn qcow_case(
    root: &tempfile::TempDir,
    top: &Path,
    mnt: &Path,
    backing: &Path,
    expect: QcowExpect<'_>,
) {
    let image = root.path().join(format!(
        "image-{}.qcow2",
        backing.file_name().unwrap().to_string_lossy()
    ));
    write_qcow(&image, &backing.display().to_string());
    let spy_path = root.path().join(format!(
        "spy-{}",
        backing.file_name().unwrap().to_string_lossy()
    ));
    let stderr = root.path().join(format!(
        "err-{}",
        backing.file_name().unwrap().to_string_lossy()
    ));
    let args = vec![
        "-f".into(),
        "--top".into(),
        format!("A={}", top.display()),
        "--mount".into(),
        format!("A={}", mnt.display()),
        "--index-file".into(),
        ":memory:".into(),
        image.display().to_string(),
    ];
    let mut child = spawn(
        &args,
        &[("RATARMOUNT_TEST_FORK_N_SPY_LOG", spy_path.to_str().unwrap())],
        &stderr,
    );
    let status = finish(&mut child, Duration::from_secs(30));
    let text = stderr_of(&stderr);
    assert_eq!(code_of(status, &stderr), expect.code, "{text}");
    assert!(text.contains(expect.needle), "{text}");
    if expect.fork_n {
        assert!(text.contains("fork-n"), "{text}");
    } else {
        assert!(!text.contains("fork-n"), "{text}");
    }
    if let Some((admit, open)) = expect.counts {
        let got = spy(&spy_path);
        assert_eq!((got.0, got.1), (admit, open), "{text}\nspy {got:?}");
    }
}

fn tar_case(
    root: &tempfile::TempDir,
    top: &Path,
    mnt: &Path,
    extra: &[&str],
    spy_log: bool,
) -> (i32, String, (u64, u64, u64, u64)) {
    let archive = root.path().join("case.tar");
    write_tar(&archive);
    let stderr = root.path().join("case.err");
    let spy_path = root.path().join("case.spy");
    let mut args = vec![
        "-f".into(),
        "--top".into(),
        format!("A={}", top.display()),
        "--mount".into(),
        format!("A={}", mnt.display()),
    ];
    if extra.is_empty() {
        args.push("--index-file".into());
        args.push(":memory:".into());
    } else {
        args.extend(extra.iter().map(|s| (*s).to_string()));
    }
    args.push(archive.display().to_string());
    let env: Vec<(&str, &str)> = if spy_log {
        vec![("RATARMOUNT_TEST_FORK_N_SPY_LOG", spy_path.to_str().unwrap())]
    } else {
        Vec::new()
    };
    let mut child = spawn(&args, &env, &stderr);
    let status = finish(&mut child, Duration::from_secs(30));
    let text = stderr_of(&stderr);
    let code = code_of(status, &stderr);
    let counts = if spy_log {
        spy(&spy_path)
    } else {
        (0, 0, 0, 0)
    };
    let _ = fs::remove_file(&archive);
    (code, text, counts)
}

/// Regression: a non-empty or already-mounted target was served.
#[test]
fn fork_n_cleanup_occupied_target() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive.tar");
    write_tar(&archive);
    let top = root.path().join("top");
    let mnt = root.path().join("mnt");
    fs::create_dir_all(&top).unwrap();
    fs::create_dir_all(&mnt).unwrap();
    let planted = mnt.join("keep.txt");
    fs::write(&planted, b"stay").unwrap();
    let log = root.path().join("argv");
    let fusermount = root.path().join("fusermount");
    recording_fusermount(&fusermount, &log, false);
    let stderr = root.path().join("err");
    let args = vec![
        "-f".into(),
        "--top".into(),
        format!("A={}", top.display()),
        "--mount".into(),
        format!("A={}", mnt.display()),
        "--index-file".into(),
        ":memory:".into(),
        archive.display().to_string(),
    ];
    let mut child = spawn(
        &args,
        &[("RATARMOUNT_TEST_FUSERMOUNT", fusermount.to_str().unwrap())],
        &stderr,
    );
    let status = finish(&mut child, Duration::from_secs(30));
    let text = stderr_of(&stderr);
    assert_eq!(code_of(status, &stderr), 2, "{text}");
    assert!(text.contains("not an empty directory"), "{text}");
    assert_eq!(fs::read(&planted).unwrap(), b"stay");
    assert!(!log.exists(), "fusermount was invoked");

    fs::remove_file(&planted).unwrap();
    let source = root.path().join("bind-src");
    fs::create_dir(&source).unwrap();
    if !try_bind(&source, &mnt) {
        eprintln!("skip: cannot create a bind mount for the already-mounted subcase");
        return;
    }
    let _guard = UmountGuard(vec![mnt.clone()]);
    let stderr = root.path().join("mounted.err");
    let log = root.path().join("mounted-argv");
    let mut child = spawn(
        &args,
        &[("RATARMOUNT_TEST_FUSERMOUNT", fusermount.to_str().unwrap())],
        &stderr,
    );
    let status = finish(&mut child, Duration::from_secs(30));
    let text = stderr_of(&stderr);
    assert_eq!(code_of(status, &stderr), 2, "{text}");
    assert!(text.contains("already a mountpoint"), "{text}");
    assert!(
        listed_in_mountinfo(&mnt),
        "pre-existing mount was removed\n{text}"
    );
    assert!(
        !log.exists(),
        "fusermount was invoked for an already-mounted target"
    );
}

fn listed_in_mountinfo(path: &Path) -> bool {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let want = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let want = want.to_string_lossy().replace(' ', "\\040");
    text.lines()
        .any(|line| line.split(' ').nth(4) == Some(want.as_str()))
}

fn fuse_or_skip() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse is missing");
        return false;
    }
    let ok = Command::new("fusermount3")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !ok {
        eprintln!("skip: fusermount3 is missing");
        return false;
    }
    true
}

fn partial_layout(root: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let archive = root.join("archive.tar");
    write_tar(&archive);
    let top_a = root.join("top-a");
    let top_b = root.join("top-b");
    let mnt_a = root.join("mnt-a");
    let mnt_b = root.join("mnt-b");
    for path in [&top_a, &top_b, &mnt_a, &mnt_b] {
        fs::create_dir_all(path).unwrap();
    }
    (archive, top_a, mnt_a, top_b, mnt_b)
}

fn partial_args(
    archive: &Path,
    top_a: &Path,
    mnt_a: &Path,
    top_b: &Path,
    mnt_b: &Path,
    foreground: bool,
) -> Vec<String> {
    let mut args = fork_pair(archive, top_a, mnt_a, top_b, mnt_b);
    if foreground {
        args.insert(0, "-f".into());
    }
    args
}

/// Regression: a failed second mount left the first mounted, unmounted with
/// `-z`, or unmounted a mount this process did not own.
#[test]
fn fork_n_cleanup_partial_start() {
    if !fuse_or_skip() {
        return;
    }
    // Each subcase gets its own mountpoints. A stomp bind over A leaves the
    // FUSE mount underneath, and a later subcase on that path would not start
    // a fresh A.
    for case in [
        killed_child as fn(&Path, &Path, &Path, &Path, &Path, &Path),
        stomp,
        normal_partial,
        foreground_partial,
    ] {
        let root = tempfile::tempdir().unwrap();
        let (archive, top_a, mnt_a, top_b, mnt_b) = partial_layout(root.path());
        let _guard = UmountGuard(vec![mnt_a.clone(), mnt_b.clone()]);
        case(root.path(), &archive, &top_a, &mnt_a, &top_b, &mnt_b);
    }
}

fn killed_child(
    root: &Path,
    archive: &Path,
    top_a: &Path,
    mnt_a: &Path,
    top_b: &Path,
    mnt_b: &Path,
) {
    let log = root.join("killed-argv");
    let fusermount = root.join("killed-fusermount");
    recording_fusermount(&fusermount, &log, true);
    let hold = root.join("killed-hold");
    fs::write(&hold, b"1").unwrap();
    let held = root.join("killed-held");
    let stderr = root.join("killed.err");
    let args = partial_args(archive, top_a, mnt_a, top_b, mnt_b, false);
    let mut child = spawn(
        &args,
        &[
            ("RATARMOUNT_TEST_FORK_N_FAIL_MOUNT", "B"),
            ("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT", "A"),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HOLD", hold.to_str().unwrap()),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HELD", held.to_str().unwrap()),
            ("RATARMOUNT_TEST_FUSERMOUNT", fusermount.to_str().unwrap()),
        ],
        &stderr,
    );
    assert!(
        wait_contains(&held, "report-held\n", Duration::from_secs(45)),
        "report hold missing\n{}",
        stderr_of(&stderr)
    );
    let children =
        fs::read_to_string(format!("/proc/{}/task/{}/children", child.id(), child.id())).unwrap();
    let daemon = children
        .split_whitespace()
        .next()
        .and_then(|pid| pid.parse::<i32>().ok())
        .expect("daemon child pid");
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(daemon),
        nix::sys::signal::Signal::SIGKILL,
    );
    let status = finish(&mut child, Duration::from_secs(45));
    let text = stderr_of(&stderr);
    let code = code_of(status, &stderr);
    assert_ne!(code, 0, "{text}");
    let argv = fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        argv.lines()
            .filter(|line| line.contains("-u") && line.contains(&mnt_a.display().to_string()))
            .count(),
        1,
        "{argv}"
    );
    assert!(!argv.contains("-z"), "{argv}");
    assert_immediate_succeeds(&db_path(top_a));
    assert_immediate_succeeds(&db_path(top_b));
}

fn stomp(root: &Path, archive: &Path, top_a: &Path, mnt_a: &Path, top_b: &Path, mnt_b: &Path) {
    let source = root.join("stomp-src");
    fs::create_dir(&source).unwrap();
    let log = root.join("stomp-argv");
    let fusermount = root.join("stomp-fusermount");
    recording_fusermount(&fusermount, &log, true);
    let hold = root.join("stomp-hold");
    fs::write(&hold, b"1").unwrap();
    let held = root.join("stomp-held");
    let stderr = root.join("stomp.err");
    let args = partial_args(archive, top_a, mnt_a, top_b, mnt_b, false);
    let mut child = spawn(
        &args,
        &[
            ("RATARMOUNT_TEST_FORK_N_FAIL_MOUNT", "B"),
            ("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT", "A"),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HOLD", hold.to_str().unwrap()),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HELD", held.to_str().unwrap()),
            ("RATARMOUNT_TEST_FUSERMOUNT", fusermount.to_str().unwrap()),
        ],
        &stderr,
    );
    if !wait_contains(&held, "report-held\n", Duration::from_secs(45)) {
        kill_tree(child.id());
        let _ = child.wait();
        panic!("stomp report hold missing\n{}", stderr_of(&stderr));
    }
    if !try_bind(&source, mnt_a) {
        fs::remove_file(&hold).unwrap();
        let _ = finish(&mut child, Duration::from_secs(45));
        eprintln!("skip: cannot bind-mount over A for the stomp subcase");
        return;
    }
    fs::remove_file(&hold).unwrap();
    let status = finish(&mut child, Duration::from_secs(45));
    let _ = Command::new("umount").arg(mnt_a).status();
    assert!(status.is_some(), "{}", stderr_of(&stderr));
    assert!(!log.exists(), "stomp unmounted a replaced mount");
}

fn normal_partial(
    root: &Path,
    archive: &Path,
    top_a: &Path,
    mnt_a: &Path,
    top_b: &Path,
    mnt_b: &Path,
) {
    let unrelated_src = root.join("unrelated-src");
    let unrelated = root.join("unrelated-mnt");
    fs::create_dir_all(&unrelated_src).unwrap();
    fs::create_dir_all(&unrelated).unwrap();
    let planted = try_bind(&unrelated_src, &unrelated);
    if !planted {
        eprintln!("skip: unrelated mount plant failed; still checking -u of A");
    }
    let log = root.join("normal-argv");
    let fusermount = root.join("normal-fusermount");
    recording_fusermount(&fusermount, &log, true);
    let stderr = root.join("normal.err");
    let args = partial_args(archive, top_a, mnt_a, top_b, mnt_b, false);
    let mut child = spawn(
        &args,
        &[
            ("RATARMOUNT_TEST_FORK_N_FAIL_MOUNT", "B"),
            ("RATARMOUNT_TEST_FUSERMOUNT", fusermount.to_str().unwrap()),
        ],
        &stderr,
    );
    let status = finish(&mut child, Duration::from_secs(45));
    if planted {
        let _ = Command::new("umount").arg(&unrelated).status();
    }
    let text = stderr_of(&stderr);
    assert_ne!(code_of(status, &stderr), 0, "{text}");
    let argv = fs::read_to_string(&log).unwrap_or_else(|_| panic!("no fusermount log\n{text}"));
    assert_eq!(
        argv.lines()
            .filter(|line| line.contains("-u") && line.contains(&mnt_a.display().to_string()))
            .count(),
        1,
        "{argv}\n{text}"
    );
    assert!(!argv.contains("-z"), "{argv}");
    if planted {
        assert!(!argv.contains(&unrelated.display().to_string()), "{argv}");
    }
}

fn foreground_partial(
    root: &Path,
    archive: &Path,
    top_a: &Path,
    mnt_a: &Path,
    top_b: &Path,
    mnt_b: &Path,
) {
    let log = root.join("fg-argv");
    let fusermount = root.join("fg-fusermount");
    recording_fusermount(&fusermount, &log, true);
    let hold = root.join("fg-hold");
    fs::write(&hold, b"1").unwrap();
    let held = root.join("fg-held");
    let stderr = root.join("fg.err");
    let args = partial_args(archive, top_a, mnt_a, top_b, mnt_b, true);
    let mut child = spawn(
        &args,
        &[
            ("RATARMOUNT_TEST_FORK_N_FAIL_MOUNT", "B"),
            ("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT", "A"),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HOLD", hold.to_str().unwrap()),
            ("RATARMOUNT_TEST_FORK_N_REPORT_HELD", held.to_str().unwrap()),
            ("RATARMOUNT_TEST_FUSERMOUNT", fusermount.to_str().unwrap()),
        ],
        &stderr,
    );
    assert!(
        wait_contains(&held, "report-held\n", Duration::from_secs(45)),
        "foreground report hold missing\n{}",
        stderr_of(&stderr)
    );
    let children = fs::read_to_string(format!("/proc/{}/task/{}/children", child.id(), child.id()))
        .unwrap_or_default();
    assert!(children.trim().is_empty(), "foreground forked: {children}");
    fs::remove_file(&hold).unwrap();
    let status = finish(&mut child, Duration::from_secs(45));
    let text = stderr_of(&stderr);
    assert_ne!(code_of(status, &stderr), 0, "{text}");
    let argv = fs::read_to_string(&log).unwrap_or_else(|_| panic!("no fusermount log\n{text}"));
    assert_eq!(
        argv.lines()
            .filter(|line| line.contains("-u") && line.contains(&mnt_a.display().to_string()))
            .count(),
        1,
        "{argv}\n{text}"
    );
    assert!(!argv.contains("-z"), "{argv}");
}
