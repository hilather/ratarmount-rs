//! Regression (#183): a daemonized `-w` mount (no `-f`) must hold the overlay
//! database's exclusive lock in the serving child. `BEGIN IMMEDIATE` from
//! another process used to succeed while that child was serving, because the
//! parent locked the database and then exited.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

const PARENT_DEADLINE: Duration = Duration::from_secs(40);

struct Guard {
    pid: i32,
    mnt: PathBuf,
    parent: Option<Child>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if mount_visible(&self.mnt) {
            let _ = Command::new("fusermount3")
                .args(["-u", "-z"])
                .arg(&self.mnt)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if let Some(parent) = self.parent.as_mut() {
            if matches!(parent.try_wait(), Ok(None)) {
                let _ = parent.kill();
            }
            let _ = parent.wait();
        }
        let pids = if self.pid > 0 {
            vec![self.pid]
        } else {
            find_serving_pids(&self.mnt)
        };
        for pid in pids {
            if !pid_gone(pid) {
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
        }
    }
}

/// Regression (#183): daemonize a `-w` mount, then from this process assert
/// `BEGIN IMMEDIATE` on the overlay database returns `SQLITE_BUSY` while the
/// mount is serving.
#[test]
fn regression_daemonized_write_mount_holds_overlay_lock() {
    if let Some(why) = skip_reason() {
        eprintln!("{why}");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let src = root.join("src");
    let ov = root.join("ov");
    let mnt = root.join("mnt");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&ov).unwrap();
    fs::create_dir_all(&mnt).unwrap();
    fs::create_dir_all(root.join("home")).unwrap();
    fs::create_dir_all(root.join("cache")).unwrap();
    fs::write(src.join("file"), b"hello\n").unwrap();

    let bin = env::var_os("RATARMOUNT_TEST_BIN")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_ratarmount")));
    let mut cmd = Command::new(bin);
    cmd.args(["-d", "3", "-w"])
        .arg(&ov)
        .arg(&src)
        .arg(&mnt)
        .env("HOME", root.join("home"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("TMPDIR", &root)
        .env("LC_ALL", "C")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let parent = cmd.spawn().expect("spawn ratarmount");
    let mut guard = Guard {
        pid: 0,
        mnt: mnt.clone(),
        parent: Some(parent),
    };
    let stderr = guard
        .parent
        .as_mut()
        .unwrap()
        .stderr
        .take()
        .expect("piped stderr");
    let log_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr), &mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });
    let status = wait_child(guard.parent.as_mut().unwrap(), PARENT_DEADLINE);
    if status.is_none() {
        if let Some(parent) = guard.parent.as_mut() {
            let _ = parent.kill();
            let _ = parent.wait();
        }
        for pid in find_serving_pids(&mnt) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
    let log = log_thread.join().unwrap_or_default();
    assert!(
        status.is_some_and(|s| s.success()),
        "daemonizing parent did not exit 0: {status:?}\n{log}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !(mount_visible(&mnt) && mnt.join("file").exists()) {
        assert!(Instant::now() < deadline, "mount did not appear\n{log}");
        thread::sleep(Duration::from_millis(50));
    }
    let pids = find_serving_pids(&mnt);
    assert_eq!(pids.len(), 1, "serving child pids {pids:?}\n{log}");
    guard.pid = pids[0];

    let db = ov.join(".ratarmount.overlay.sqlite");
    let conn = rusqlite::Connection::open(&db)
        .unwrap_or_else(|e| panic!("opening {db:?} while the mount is serving: {e}\n{log}"));
    conn.busy_timeout(Duration::ZERO).unwrap();
    match conn.execute_batch("BEGIN IMMEDIATE") {
        Err(rusqlite::Error::SqliteFailure(err, _))
            if matches!(
                err.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) => {}
        Ok(()) => {
            let _ = conn.execute_batch("ROLLBACK");
            panic!(
                "BEGIN IMMEDIATE acquired the overlay database while the daemonized mount was serving\n{log}"
            );
        }
        Err(e) => panic!("BEGIN IMMEDIATE: {e}\n{log}"),
    }
}

fn skip_reason() -> Option<&'static str> {
    if !Path::new("/dev/fuse").exists() {
        return Some("skip: /dev/fuse missing");
    }
    if !on_path("fusermount3") {
        return Some("skip: fusermount3 not on PATH");
    }
    None
}

fn on_path(bin: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| env::split_paths(&paths).any(|p| p.join(bin).is_file()))
}

fn wait_child(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(st)) = child.try_wait() {
            return Some(st);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn mount_visible(mnt: &Path) -> bool {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let want = mnt.to_string_lossy();
    text.lines()
        .any(|line| line.split_whitespace().nth(4).is_some_and(|mp| mp == want))
}

fn find_serving_pids(mnt: &Path) -> Vec<i32> {
    use std::os::unix::fs::MetadataExt;
    let want = mnt.as_os_str().as_encoded_bytes().to_vec();
    let me = unsafe { libc::getuid() };
    let own = i32::try_from(std::process::id()).unwrap();
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return out;
    };
    for ent in rd.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        if pid == own || ent.metadata().map(|m| m.uid()).ok() != Some(me) {
            continue;
        }
        let Ok(cmd) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        if cmd.split(|b| *b == 0).any(|arg| arg == want.as_slice()) {
            out.push(pid);
        }
    }
    out
}

fn pid_gone(pid: i32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| state == "Z"),
    }
}
