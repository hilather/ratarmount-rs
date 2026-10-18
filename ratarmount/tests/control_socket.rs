//! Regression: the control socket `ratarmount-control-<pid>.sock` is removed
//! when the mount ends, including an external `fusermount -u` (the accept
//! thread blocks in `accept()` and never sees its stop flag then).
#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(30);

fn reap(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let end = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) if Instant::now() < end => thread::sleep(Duration::from_millis(20)),
            _ => return None,
        }
    }
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

fn mounted(mnt: &Path) -> bool {
    let want = mnt.to_string_lossy().into_owned();
    fs::read_to_string("/proc/self/mountinfo").is_ok_and(|t| {
        t.lines()
            .any(|l| l.split(' ').nth(4) == Some(want.as_str()))
    })
}

fn sockets(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("ratarmount-control-") && n.ends_with(".sock"))
        .collect()
}

struct Daemon(Child, PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        if mounted(&self.1) {
            let _ = Command::new("fusermount3")
                .args(["-uz"])
                .arg(&self.1)
                .status();
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Regression: an external `fusermount -u` left `ratarmount-control-<pid>.sock`
/// behind in `TMPDIR` (no Drop guard; the accept thread never saw `stop`).
#[test]
fn regression_control_socket_removed_after_external_unmount() {
    if !Path::new("/dev/fuse").exists() || !on_path("fusermount3") || !on_path("tar") {
        eprintln!("skip: needs /dev/fuse, fusermount3 and tar");
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("rrs-ctl-")
        .tempdir()
        .unwrap();
    let root = root.path().canonicalize().unwrap();
    let tmpdir = root.join("t");
    let mnt = root.join("mnt");
    fs::create_dir_all(&tmpdir).unwrap();
    fs::create_dir_all(&mnt).unwrap();
    fs::set_permissions(&tmpdir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/a"), b"x").unwrap();
    let tar = root.join("a.tar");
    assert!(Command::new("tar")
        .arg("-C")
        .arg(root.join("src"))
        .arg("-cf")
        .arg(&tar)
        .arg("a")
        .status()
        .unwrap()
        .success());
    let log = File::create(root.join("log")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["-f", "--control-interface"])
        .arg(&tar)
        .arg(&mnt)
        .env("TMPDIR", &tmpdir)
        .env("LC_ALL", "C")
        .env("HOME", &root)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .process_group(0)
        .spawn()
        .unwrap();
    let mut d = Daemon(child, mnt.clone());
    let end = Instant::now() + DEADLINE;
    while !mounted(&mnt) {
        assert!(
            Instant::now() < end && d.0.try_wait().unwrap().is_none(),
            "mount did not appear: {}",
            fs::read_to_string(root.join("log")).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(sockets(&tmpdir).len(), 1, "socket while mounted");
    // A socket owned by another pid is never ours to unlink.
    let foreign = tmpdir.join("ratarmount-control-1.sock");
    fs::write(&foreign, b"").unwrap();
    assert!(Command::new("fusermount3")
        .arg("-u")
        .arg(&mnt)
        .status()
        .unwrap()
        .success());
    assert!(reap(&mut d.0, DEADLINE).is_some(), "daemon did not exit");
    assert_eq!(
        sockets(&tmpdir),
        vec!["ratarmount-control-1.sock".to_string()],
        "own socket left behind (or foreign one removed)"
    );
}
