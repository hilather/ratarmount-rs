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

fn write_split_tar_zst(dir: &Path, first: &[(&str, &[u8])], last: &[(&str, &[u8])]) -> PathBuf {
    fn pack_no_eof(members: &[(&str, &[u8])]) -> Vec<u8> {
        let ustar: Vec<ratarmount_formats_tar::UstarMember<'_>> = members
            .iter()
            .map(|(n, b)| ratarmount_formats_tar::UstarMember {
                path: n,
                payload: ratarmount_formats_tar::UstarPayload::File { bytes: b },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            })
            .collect();
        let mut buf = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut buf, &ustar).unwrap();
        buf
    }
    let f0 = pack_no_eof(first);
    let mut f1 = pack_no_eof(last);
    ratarmount_formats_tar::write_tar_eof(&mut f1).unwrap();
    let mut out = Vec::new();
    out.extend(ratarmount_compress::encode_zstd_frame(&f0, 3).unwrap());
    out.extend(ratarmount_compress::encode_zstd_frame(&f1, 3).unwrap());
    let path = dir.join("a.tar.zst");
    fs::write(&path, out).unwrap();
    path
}

fn decode_tar_zst_to_tar(zst: &Path, dest_tar: &Path) {
    let map = ratarmount_compress::scan_zstd_frames_path(zst).unwrap();
    let mut src = fs::File::open(zst).unwrap();
    let mut out = fs::File::create(dest_tar).unwrap();
    ratarmount_compress::decode_zstd_frames_to(&mut src, &map, 0, &mut out).unwrap();
}

#[test]
fn commit_overlay_on_exit_sigterm_tar_zst_cmp() {
    let dir = tempfile::tempdir().unwrap();
    let expected_new = dir.path().join("expected-new.bin");
    fs::write(&expected_new, format!("p-{}\n", std::process::id())).unwrap();
    let old = b"keep-zst\n";
    let last = b"last-frame\n";
    let zst = write_split_tar_zst(dir.path(), &[("old.txt", old)], &[("last.txt", last)]);
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
        .arg(&zst)
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

    let dest_tar = dir.path().join("decoded.tar");
    decode_tar_zst_to_tar(&zst, &dest_tar);
    let extract = dir.path().join("ex");
    fs::create_dir_all(&extract).unwrap();
    assert!(
        Command::new("tar")
            .args(["-xf"])
            .arg(&dest_tar)
            .arg("-C")
            .arg(&extract)
            .status()
            .unwrap()
            .success(),
        "tar -xf decoded last-frame rewrite"
    );
    assert_eq!(fs::read(extract.join("old.txt")).unwrap(), old);
    assert_eq!(fs::read(extract.join("last.txt")).unwrap(), last);
    assert_eq!(
        fs::read(extract.join("new.bin")).unwrap(),
        fs::read(&expected_new).unwrap()
    );
}

fn write_empty_zip(path: &Path) {
    let mut bytes = vec![0u8; 22];
    bytes[0] = 0x50;
    bytes[1] = 0x4b;
    bytes[2] = 0x05;
    bytes[3] = 0x06;
    fs::write(path, bytes).unwrap();
}

fn write_tiny_targz(dir: &Path) -> Option<PathBuf> {
    let tree = dir.join("gztree");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("a.txt"), b"gz\n").unwrap();
    let path = dir.join("existing.tar.gz");
    let ok = Command::new("tar")
        .args(["-czf"])
        .arg(&path)
        .arg("-C")
        .arg(&tree)
        .arg("a.txt")
        .status()
        .map(|s| s.success() && path.is_file())
        .unwrap_or(false);
    if ok {
        Some(path)
    } else {
        eprintln!("skip: tar -czf missing or failed");
        None
    }
}

/// Regression: missing archive.tar is not found without -w
#[test]
fn create_missing_without_w_does_not_create() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("archive.tar");
    let out = Command::new(bin())
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&archive)
        .output()
        .expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("not found"), "{err}");
    assert!(!archive.exists());
}

/// Regression: missing .tar.gz refused for write create
#[test]
fn create_missing_targz_refused() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar.gz");
    let ov = dir.path().join("ov");
    let out = Command::new(bin())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&archive)
        .output()
        .expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(
        err.contains("cannot create") || err.contains("gzip"),
        "{err}"
    );
    assert!(!archive.exists());
}

/// Regression: existing .tar.gz / .zip still mount under -w
#[test]
fn create_missing_existing_targz_zip_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let zip = dir.path().join("a.zip");
    write_empty_zip(&zip);
    let before_zip = fs::read(&zip).unwrap();
    let ov = dir.path().join("ov");
    let out = Command::new(bin())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&zip)
        .output()
        .expect("run zip");
    assert!(
        out.status.success(),
        "existing zip: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read(&zip).unwrap(), before_zip);

    let Some(gz) = write_tiny_targz(dir.path()) else {
        return;
    };
    let before_gz = fs::read(&gz).unwrap();
    let out = Command::new(bin())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&gz)
        .output()
        .expect("run gzip");
    assert!(
        out.status.success(),
        "existing gzip: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read(&gz).unwrap(), before_gz);
}

/// Regression: missing .iso under -w stays not found
#[test]
fn create_missing_iso_stays_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.iso");
    let ov = dir.path().join("ov");
    let out = Command::new(bin())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&archive)
        .output()
        .expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("not found"), "{err}");
    assert!(!archive.exists());
}

/// Regression: remote URL never creates
#[test]
fn create_missing_remote_url_never_creates() {
    let dir = tempfile::tempdir().unwrap();
    let ov = dir.path().join("ov");
    let out = Command::new(bin())
        .current_dir(dir.path())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg("https://example.com/a.tar")
        .output()
        .expect("run");
    assert!(!dir.path().join("a.tar").exists());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("parent directory does not exist"), "{err}");
    let _ = out;
}

/// Regression: offline --commit-overlay remote URL never creates
#[test]
fn create_missing_offline_remote_url_never_creates() {
    let dir = tempfile::tempdir().unwrap();
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let out = Command::new(bin())
        .current_dir(dir.path())
        .args(["--commit-overlay", "-w"])
        .arg(&ov)
        .args(["--yes", "https://example.com/a.tar"])
        .output()
        .expect("run");
    assert!(!dir.path().join("a.tar").exists());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("parent directory does not exist"), "{err}");
    assert!(!out.status.success(), "{err}");
}

/// Regression: missing archive.tar + -w mounts empty root
#[test]
fn create_missing_tar_is_1024_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("new.tar");
    let ov = dir.path().join("ov");
    let out = Command::new(bin())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&archive)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = fs::read(&archive).unwrap();
    assert_eq!(bytes.len(), 1024);
    assert!(bytes.iter().all(|&b| b == 0));
}

/// Regression: offline --commit-overlay missing .tar.zst does not create
#[test]
fn create_missing_offline_tar_zst_does_not_create() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("new.tar.zst");
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let out = Command::new(bin())
        .args(["--commit-overlay", "-w"])
        .arg(&ov)
        .arg("--yes")
        .arg(&archive)
        .output()
        .expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("on-exit") || err.contains("interval"), "{err}");
    assert!(!archive.exists());
}

/// Regression: offline --commit-overlay missing .tar creates then commits
#[test]
fn create_missing_offline_tar_creates_then_commits() {
    if skip_no_gnu_tar() {
        eprintln!("skip: GNU tar missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("new.tar");
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let expected = b"offline-create\n";
    fs::write(ov.join("hello.txt"), expected).unwrap();
    let out = Command::new(bin())
        .args(["--commit-overlay", "-w"])
        .arg(&ov)
        .arg("--yes")
        .arg(&archive)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(archive.is_file());
    let extract = dir.path().join("ex");
    fs::create_dir_all(&extract).unwrap();
    assert!(Command::new("tar")
        .args(["-xf"])
        .arg(&archive)
        .arg("-C")
        .arg(&extract)
        .status()
        .unwrap()
        .success());
    assert_eq!(fs::read(extract.join("hello.txt")).unwrap(), expected);
}

/// Refuse existing dir named `*.tar`
#[test]
fn create_missing_refuses_dir_named_tar() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("archive.tar");
    fs::create_dir_all(&archive).unwrap();
    let ov = dir.path().join("ov");
    let out = Command::new(bin())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&archive)
        .output()
        .expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("is a directory"), "{err}");
    assert!(archive.is_dir());
}

/// Existing dir without createable name → folder bind as today
#[test]
fn create_missing_folder_bind_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("dest");
    fs::create_dir_all(&dest).unwrap();
    let ov = dir.path().join("ov");
    let out = Command::new(bin())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&dest)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dest.is_dir());
}

/// Refuse clobber: pre-write secret into a.tar
#[test]
fn create_missing_refuses_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar");
    fs::write(&archive, b"secret").unwrap();
    let ov = dir.path().join("ov");
    let _ = Command::new(bin())
        .args(["-w"])
        .arg(&ov)
        .args(["--no-mount", "--index-file", ":memory:"])
        .arg(&archive)
        .output()
        .expect("run");
    assert_eq!(fs::read(&archive).unwrap(), b"secret");
}

/// Missing-path on-exit `.tar`: create then write overlay file; SIGTERM; tar -xf + cmp.
#[test]
fn create_missing_on_exit_tar_cmp_overlay_files() {
    if skip_no_gnu_tar() {
        eprintln!("skip: GNU tar missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let expected_new = dir.path().join("expected-new.bin");
    fs::write(
        &expected_new,
        format!("live-on-exit-create-{}\n", std::process::id()),
    )
    .unwrap();
    let tar = dir.path().join("new.tar");
    assert!(!tar.exists());
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
    assert!(
        tar.is_file(),
        "create-if-missing should have written {tar:?}"
    );
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

/// Missing-path interval `.tar.zst`: write file; wait for commit; scan_zstd_frames; decode + cmp.
#[test]
fn create_missing_interval_tar_zst_cmp() {
    let dir = tempfile::tempdir().unwrap();
    let expected = dir.path().join("expected.bin");
    fs::write(
        &expected,
        format!("interval-create-{}\n", std::process::id()),
    )
    .unwrap();
    let zst = dir.path().join("new.tar.zst");
    assert!(!zst.exists());
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
        .arg(&zst)
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
    assert!(
        zst.is_file(),
        "create-if-missing should have written {zst:?}"
    );
    fs::write(ov.join("tick.bin"), fs::read(&expected).unwrap()).unwrap();

    let dest_tar = dir.path().join("decoded.tar");
    let start = Instant::now();
    let mut saw = false;
    while start.elapsed() < Duration::from_secs(8) {
        if zst.is_file() {
            if let Ok(map) = ratarmount_compress::scan_zstd_frames_path(&zst) {
                if !map.frames.is_empty() {
                    decode_tar_zst_to_tar(&zst, &dest_tar);
                    if dest_tar.is_file() {
                        let extract = dir.path().join("ex-poll");
                        let _ = fs::remove_dir_all(&extract);
                        fs::create_dir_all(&extract).unwrap();
                        if Command::new("tar")
                            .args(["-xf"])
                            .arg(&dest_tar)
                            .arg("-C")
                            .arg(&extract)
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false)
                            && extract.join("tick.bin").is_file()
                        {
                            saw = true;
                            break;
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(150));
    }
    assert!(
        saw,
        "interval did not persist tick.bin: log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );

    let map = ratarmount_compress::scan_zstd_frames_path(&zst).expect("scan frames");
    assert!(!map.frames.is_empty(), "expected at least one zstd frame");
    decode_tar_zst_to_tar(&zst, &dest_tar);
    let extract = dir.path().join("ex");
    fs::create_dir_all(&extract).unwrap();
    assert!(
        Command::new("tar")
            .args(["-xf"])
            .arg(&dest_tar)
            .arg("-C")
            .arg(&extract)
            .status()
            .unwrap()
            .success(),
        "tar -xf decoded created .tar.zst"
    );
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
