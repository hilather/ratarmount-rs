//! Live overlay commit: real `ratarmount --nfs` + SIGTERM / short interval.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ratarmount"))
}

fn write_tar(dir: &Path, members: &[(&str, &[u8])]) -> PathBuf {
    let tree = dir.join("tree");
    fs::create_dir_all(&tree).unwrap();
    for (name, body) in members {
        fs::write(tree.join(name), body).unwrap();
    }
    let tar = dir.join("a.tar");
    let mut cmd = Command::new("tar");
    cmd.arg("-cf").arg(&tar).arg("-C").arg(&tree);
    for (name, _) in members {
        cmd.arg(name);
    }
    assert!(cmd.status().unwrap().success(), "tar -cf");
    tar
}

fn wait_ready(log: &Path, needle: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(s) = fs::read_to_string(log) {
            if s.contains(needle) {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn tar_list(tar: &Path) -> String {
    let out = Command::new("tar").args(["-tf"]).arg(tar).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn skip_no_gnu_tar() -> bool {
    let out = Command::new("tar").arg("--version").output();
    match out {
        Ok(o) => !String::from_utf8_lossy(&o.stdout).contains("GNU tar"),
        Err(_) => true,
    }
}

#[test]
fn commit_overlay_on_exit_sigterm_cmp_overlay_files() {
    if skip_no_gnu_tar() {
        eprintln!("skip: GNU tar missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let expected_new = dir.path().join("expected-new.bin");
    fs::write(
        &expected_new,
        format!("live-on-exit-{}\n", std::process::id()),
    )
    .unwrap();
    let tar = write_tar(dir.path(), &[("old.txt", b"keep-me\n")]);
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let mut child = Command::new(bin())
        .args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .arg("--commit-overlay-on-exit")
        .arg("--index-file")
        .arg(":memory:")
        .arg(&tar)
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn ratarmount");

    if !wait_ready(&log, "NFSv3", Duration::from_secs(8)) {
        let _ = child.kill();
        panic!(
            "server not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    // Persist the same way the overlay would: file in the overlay folder.
    fs::write(ov.join("new.bin"), fs::read(&expected_new).unwrap()).unwrap();

    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let status = child.wait().expect("wait");
    assert!(
        status.success() || status.code() == Some(0) || status.code().is_none(),
        "SIGTERM exit: {status:?} log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );

    let listing = tar_list(&tar);
    assert!(listing.contains("old.txt"), "{listing}");
    assert!(
        listing.contains("new.bin"),
        "missing new.bin after on-exit: {listing}"
    );
    let extract = dir.path().join("ex");
    fs::create_dir_all(&extract).unwrap();
    assert!(Command::new("tar")
        .args(["-xf"])
        .arg(&tar)
        .arg("-C")
        .arg(&extract)
        .status()
        .unwrap()
        .success());
    assert_eq!(
        fs::read(extract.join("new.bin")).unwrap(),
        fs::read(&expected_new).unwrap()
    );
}

#[test]
fn commit_overlay_on_exit_rejects_temp() {
    let dir = tempfile::tempdir().unwrap();
    let tar = write_tar(dir.path(), &[("a.txt", b"a\n")]);
    let out = Command::new(bin())
        .args([
            "--nfs",
            "-w",
            ":temp:",
            "--commit-overlay-on-exit",
            "--index-file",
            ":memory:",
        ])
        .arg(&tar)
        .output()
        .expect("run");
    assert!(!out.status.success(), "expected nonzero");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(":temp:") || err.contains("temp"), "{err}");
}

#[test]
fn commit_overlay_on_exit_rejects_targz() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("t");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("a"), b"x").unwrap();
    let tgz = dir.path().join("a.tar.gz");
    assert!(Command::new("tar")
        .args(["-czf"])
        .arg(&tgz)
        .arg("-C")
        .arg(&tree)
        .arg("a")
        .status()
        .unwrap()
        .success());
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let out = Command::new(bin())
        .args(["--nfs", "-w"])
        .arg(&ov)
        .arg("--commit-overlay-on-exit")
        .arg("--index-file")
        .arg(":memory:")
        .arg(&tgz)
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("uncompressed TAR") || err.contains("gzip"),
        "{err}"
    );
}

#[test]
fn commit_overlay_interval_writes_once_no_duplicate() {
    if skip_no_gnu_tar() {
        eprintln!("skip: GNU tar missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let expected = dir.path().join("expected.bin");
    fs::write(&expected, format!("interval-{}\n", std::process::id())).unwrap();
    let tar = write_tar(dir.path(), &[("seed.txt", b"seed\n")]);
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let mut child = Command::new(bin())
        .args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .args([
            "--commit-overlay-interval",
            "1s",
            "--index-file",
            ":memory:",
        ])
        .arg(&tar)
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn");

    if !wait_ready(&log, "NFSv3", Duration::from_secs(8)) {
        let _ = child.kill();
        panic!(
            "not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    fs::write(ov.join("tick.bin"), fs::read(&expected).unwrap()).unwrap();

    let start = Instant::now();
    let mut saw = false;
    while start.elapsed() < Duration::from_secs(5) {
        if tar_list(&tar).contains("tick.bin") {
            saw = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(saw, "interval did not commit: {}", tar_list(&tar));

    thread::sleep(Duration::from_millis(1500));
    let listing = tar_list(&tar);
    let n = listing
        .lines()
        .filter(|l| l.trim_end_matches('/') == "tick.bin")
        .count();
    assert_eq!(n, 1, "second interval duplicated members: {listing}");

    let extract = dir.path().join("ex");
    fs::create_dir_all(&extract).unwrap();
    assert!(Command::new("tar")
        .args(["-xf"])
        .arg(&tar)
        .arg("-C")
        .arg(&extract)
        .status()
        .unwrap()
        .success());
    assert_eq!(
        fs::read(extract.join("tick.bin")).unwrap(),
        fs::read(&expected).unwrap()
    );

    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = child.wait();
}

#[test]
fn commit_overlay_interval_zero_never_commits() {
    let dir = tempfile::tempdir().unwrap();
    let tar = write_tar(dir.path(), &[("only.txt", b"x\n")]);
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    fs::write(ov.join("nope.bin"), b"should-not-commit\n").unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let mut child = Command::new(bin())
        .args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .args(["--commit-overlay-interval", "0", "--index-file", ":memory:"])
        .arg(&tar)
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn");
    if !wait_ready(&log, "NFSv3", Duration::from_secs(8)) {
        let _ = child.kill();
        panic!(
            "not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    thread::sleep(Duration::from_millis(400));
    let listing = tar_list(&tar);
    assert!(
        !listing.contains("nope.bin"),
        "interval 0 must not commit: {listing}"
    );
    let _ = child.kill();
    let _ = child.wait();
}
