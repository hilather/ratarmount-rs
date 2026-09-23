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

/// Regression: interval + on-exit must not splice the same overlay file twice.
#[test]
fn commit_overlay_interval_on_exit_no_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let expected_new = dir.path().join("expected-new.bin");
    fs::write(&expected_new, format!("p-coal-{}\n", std::process::id())).unwrap();
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
        .args([
            "--commit-overlay-interval",
            "1s",
            "--commit-overlay-on-exit",
            "--index-file",
            ":memory:",
        ])
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

    // SIGTERM immediately: on-exit must flush the still-hot file even if the
    // interval tick is in flight or skipped it as unsettled.
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
    let listing = tar_list(&dest_tar);
    let n = listing
        .lines()
        .filter(|l| l.trim_end_matches('/') == "new.bin")
        .count();
    assert_eq!(n, 1, "interval+on-exit duplicated members: {listing}");

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
        "tar -xf decoded"
    );
    assert_eq!(fs::read(extract.join("old.txt")).unwrap(), old);
    assert_eq!(fs::read(extract.join("last.txt")).unwrap(), last);
    assert_eq!(
        fs::read(extract.join("new.bin")).unwrap(),
        fs::read(&expected_new).unwrap()
    );
}

/// Regression: on-exit splice must patch the sibling sidecar so the next
/// remount without `-c` is warm (tarstats match; no prefix-frame decode).
#[test]
fn live_commit_on_exit_remount_tar_zst() {
    let dir = tempfile::tempdir().unwrap();
    let expected_new = dir.path().join("expected-new.bin");
    fs::write(&expected_new, format!("p-{}\n", std::process::id())).unwrap();
    let old = b"keep-zst\n";
    let last = b"last-frame\n";
    let zst = write_split_tar_zst(dir.path(), &[("old.txt", old)], &[("last.txt", last)]);
    let map = ratarmount_compress::scan_zstd_frames_path(&zst).unwrap();
    let prefix_end = map.frames.last().unwrap().compressed_offset as usize;
    let prefix_bytes = fs::read(&zst).unwrap()[..prefix_end].to_vec();

    // Cold-index once so a sibling sidecar exists (default `{archive}.index.sqlite`).
    let index_out = Command::new(bin())
        .args(["--no-mount", "-f"])
        .arg(&zst)
        .output()
        .expect("cold index");
    assert!(
        index_out.status.success(),
        "cold index: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );
    let sidecar = {
        let mut s = zst.as_os_str().to_os_string();
        s.push(".index.sqlite");
        PathBuf::from(s)
    };
    assert!(sidecar.is_file(), "sidecar after --no-mount");
    let cold = String::from_utf8_lossy(&index_out.stdout);
    assert!(
        cold.contains("Creating offset dictionary"),
        "first open is a full parse: {cold}"
    );

    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let mut child = Command::new(bin())
        .args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .arg("--commit-overlay-on-exit")
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

    let after = fs::read(&zst).unwrap();
    assert_eq!(
        &after[..prefix_end],
        prefix_bytes.as_slice(),
        "prefix frames must stay byte-identical after on-exit splice"
    );

    let remount = Command::new(bin())
        .args(["--no-mount", "-f"])
        .arg(&zst)
        .output()
        .expect("remount without -c");
    let remount_out = format!(
        "{}{}",
        String::from_utf8_lossy(&remount.stdout),
        String::from_utf8_lossy(&remount.stderr)
    );
    assert!(
        remount.status.success(),
        "remount without -c: {remount_out}"
    );
    assert!(
        remount_out.contains("Successfully loaded offset dictionary"),
        "remount must warm-open patched sidecar: {remount_out}"
    );
    assert!(
        !remount_out.contains("Creating offset dictionary"),
        "remount without -c must not full-parse: {remount_out}"
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

struct S3Hit {
    method: String,
    key: String,
    body: Vec<u8>,
}

struct S3Live {
    addr: std::net::SocketAddr,
    hits: std::sync::Arc<std::sync::Mutex<Vec<S3Hit>>>,
    objects: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
}

fn spawn_s3_live(objects: std::collections::HashMap<String, Vec<u8>>) -> S3Live {
    spawn_s3_live_ex(objects, false)
}

fn spawn_s3_live_ex(
    objects: std::collections::HashMap<String, Vec<u8>>,
    fail_first_archive_put: bool,
) -> S3Live {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::<S3Hit>::new()));
    let objs = std::sync::Arc::new(std::sync::Mutex::new(objects));
    let etags = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        String,
    >::new()));
    let hits_t = std::sync::Arc::clone(&hits);
    let objs_t = std::sync::Arc::clone(&objs);
    thread::spawn(move || {
        let failed_archive_put = std::sync::atomic::AtomicBool::new(false);
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                continue;
            }
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let target = parts.next().unwrap_or("/").to_string();
            let mut content_length = 0usize;
            let mut if_match: Option<String> = None;
            let mut range_hdr: Option<String> = None;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    break;
                }
                if line == "\r\n" || line == "\n" || line.is_empty() {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = lower.strip_prefix("if-match:") {
                    if_match = Some(v.trim().to_string());
                } else if let Some(v) = lower.strip_prefix("range:") {
                    range_hdr = Some(v.trim().to_string());
                }
            }
            let mut body = vec![0u8; content_length];
            if content_length > 0 && reader.read_exact(&mut body).is_err() {
                continue;
            }
            let path = target.split('?').next().unwrap_or(&target);
            let key = path
                .trim_start_matches('/')
                .split_once('/')
                .map(|(_, k)| k.to_string())
                .unwrap_or_default();
            if method == "HEAD" || method == "GET" {
                let guard = objs_t.lock().unwrap();
                if let Some(obj) = guard.get(&key) {
                    let etag = etags
                        .lock()
                        .unwrap()
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| "\"v1\"".into());
                    let mut start = 0usize;
                    let mut end = obj.len().saturating_sub(1);
                    let mut partial = false;
                    if let Some(r) = range_hdr.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
                        let bits: Vec<&str> = r.splitn(2, '-').collect();
                        if bits.len() == 2 && !bits[0].is_empty() {
                            start = bits[0].parse().unwrap_or(0);
                            if !bits[1].is_empty() {
                                end = bits[1].parse().unwrap_or(end);
                            }
                            if start < obj.len() && start <= end {
                                end = end.min(obj.len() - 1);
                                partial = true;
                            }
                        }
                    }
                    let resp_body = if method == "HEAD" {
                        Vec::new()
                    } else if partial {
                        obj[start..=end].to_vec()
                    } else {
                        obj.clone()
                    };
                    let status = if partial && method == "GET" { 206 } else { 200 };
                    let reason = if status == 206 {
                        "Partial Content"
                    } else {
                        "OK"
                    };
                    let len_hdr = if method == "HEAD" {
                        obj.len()
                    } else {
                        resp_body.len()
                    };
                    let mut extra = format!("ETag: {etag}\r\nAccept-Ranges: bytes\r\n");
                    if partial {
                        extra.push_str(&format!(
                            "Content-Range: bytes {start}-{end}/{}\r\n",
                            obj.len()
                        ));
                    }
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} {reason}\r\n{extra}Content-Length: {len_hdr}\r\nConnection: close\r\n\r\n"
                    );
                    if method != "HEAD" {
                        let _ = stream.write_all(&resp_body);
                    }
                    hits_t.lock().unwrap().push(S3Hit {
                        method,
                        key,
                        body: resp_body,
                    });
                    continue;
                }
                drop(guard);
                let msg = b"NoSuchKey";
                let _ = write!(
                    stream,
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    msg.len()
                );
                let _ = stream.write_all(msg);
                hits_t.lock().unwrap().push(S3Hit {
                    method,
                    key,
                    body: Vec::new(),
                });
            } else if method == "PUT" {
                let current = etags
                    .lock()
                    .unwrap()
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| "\"v1\"".into());
                if let Some(want) = if_match.as_deref() {
                    if want != current {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        hits_t.lock().unwrap().push(S3Hit { method, key, body });
                        continue;
                    }
                }
                objs_t.lock().unwrap().insert(key.clone(), body.clone());
                let n = hits_t.lock().unwrap().len();
                let new_etag = format!("\"put-{n}\"");
                etags.lock().unwrap().insert(key.clone(), new_etag.clone());
                let fail_landed = fail_first_archive_put
                    && !key.contains(".index")
                    && !failed_archive_put.swap(true, std::sync::atomic::Ordering::SeqCst);
                if fail_landed {
                    let msg = b"body mentions HTTP 412";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    let _ = stream.write_all(msg);
                    hits_t.lock().unwrap().push(S3Hit { method, key, body });
                    continue;
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nETag: {new_etag}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                hits_t.lock().unwrap().push(S3Hit { method, key, body });
            } else {
                let _ = write!(
                    stream,
                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        }
    });
    S3Live {
        addr,
        hits,
        objects: objs,
    }
}

/// One interval tick uploads the spliced object, then the meta-v3 blob, then the pointer.
#[test]
fn s3_interval_uploads_once() {
    let dir = tempfile::tempdir().unwrap();
    let member = ratarmount_formats_tar::UstarMember {
        path: "seed.txt",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"seed\n" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    };
    let mut plain = Vec::new();
    ratarmount_formats_tar::write_ustar_members(&mut plain, &[member]).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut plain).unwrap();
    let zst_bytes = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
    let zst = dir.path().join("a.tar.zst");
    fs::write(&zst, &zst_bytes).unwrap();
    let idx = dir.path().join("a.tar.zst.index.sqlite");
    let body = ratarmount_compress::open_seekable_zstd(&zst).unwrap();
    let opts = ratarmount_core::OpenOptions {
        write_index: true,
        index_minimum_file_count: 0,
        ..ratarmount_core::OpenOptions::default()
    };
    ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
        &zst,
        body,
        Some(&idx),
        &opts,
        "test",
    )
    .expect("sidecar");
    let index_bytes = fs::read(&idx).unwrap();
    let pointer = ratarmount_index::IndexPointer::for_blob(&idx, Some(&zst)).unwrap();
    let pointer_bytes = ratarmount_index::index_pointer_to_json(&pointer)
        .unwrap()
        .into_bytes();
    let id = pointer.index_id.clone();
    let key = "data/a.tar.zst";
    let mut objects = std::collections::HashMap::new();
    objects.insert(key.into(), zst_bytes);
    objects.insert(format!("{key}.index.ptr"), pointer_bytes);
    objects.insert(format!("{key}.index.{id}.sqlite"), index_bytes);
    let s3 = spawn_s3_live(objects);
    let cache = tempfile::tempdir().unwrap();
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let payload = format!("s3-interval-{}\n", std::process::id());
    let mut child = Command::new(bin())
        .args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .args(["--commit-overlay-interval", "1s"])
        .arg("s3://bkt/data/a.tar.zst")
        .env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        .env("AWS_SECRET_ACCESS_KEY", secret)
        .env("AWS_REGION", "us-east-1")
        .env("AWS_DEFAULT_REGION", "us-east-1")
        .env("AWS_ENDPOINT_URL", format!("http://{}", s3.addr))
        .env("XDG_CACHE_HOME", cache.path())
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_ANONYMOUS")
        .env_remove("RATARMOUNT_S3_ANONYMOUS")
        .env("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1")
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn");
    if !wait_ready(&log, "NFSv3", Duration::from_secs(15)) {
        let _ = child.kill();
        panic!(
            "server not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    assert!(
        !fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(secret),
        "mount log must not contain the AWS secret"
    );
    fs::write(ov.join("tick.bin"), payload.as_bytes()).unwrap();
    let archive_puts = || {
        s3.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.method == "PUT" && h.key == key)
            .count()
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(12) && archive_puts() == 0 {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        archive_puts() >= 1,
        "no archive PUT: {:?} log={}",
        s3.hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| format!("{} {}", h.method, h.key))
            .collect::<Vec<_>>(),
        fs::read_to_string(&log).unwrap_or_default()
    );
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(8) && ov.join("tick.bin").exists() {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !ov.join("tick.bin").exists(),
        "overlay file should be forgotten after upload: log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    let hits: Vec<(String, String, Vec<u8>)> = s3
        .hits
        .lock()
        .unwrap()
        .iter()
        .map(|h| (h.method.clone(), h.key.clone(), h.body.clone()))
        .collect();
    let puts: Vec<&(String, String, Vec<u8>)> = hits.iter().filter(|h| h.0 == "PUT").collect();
    let put_keys: Vec<&String> = puts.iter().map(|h| &h.1).collect();
    assert!(
        puts.len() >= 3,
        "expected archive, blob, pointer PUTs, got {put_keys:?}"
    );
    assert_eq!(puts[0].1, key, "archive PUT first: {put_keys:?}");
    assert!(
        puts[1].1.starts_with(&format!("{key}.index.")) && puts[1].1.ends_with(".sqlite"),
        "blob PUT second: {}",
        puts[1].1
    );
    assert!(
        puts[1].1 != format!("{key}.index.sqlite"),
        "blob key must include the index id"
    );
    assert_eq!(puts[2].1, format!("{key}.index.ptr"), "pointer PUT third");
    assert!(
        puts.iter().all(|h| h.1 != format!("{key}.index.sqlite")),
        "well-known key must not be written"
    );
    let archive_body = &puts[0].2;
    assert_eq!(
        s3.objects.lock().unwrap().get(key).map(Vec::as_slice),
        Some(archive_body.as_slice()),
        "stored object bytes must match the uploaded spool"
    );
    let uploaded = dir.path().join("uploaded.tar.zst");
    let plain_out = dir.path().join("uploaded.tar");
    fs::write(&uploaded, archive_body).unwrap();
    decode_tar_zst_to_tar(&uploaded, &plain_out);
    let plain_bytes = fs::read(&plain_out).unwrap();
    assert!(
        plain_bytes
            .windows(payload.len())
            .any(|w| w == payload.as_bytes()),
        "uploaded spool must contain the overlay file"
    );
    assert!(
        plain_bytes.windows(5).any(|w| w == b"seed\n"),
        "uploaded spool must keep the seed member"
    );
    let meta = cache.path().join("ratarmount").join("meta-v3");
    let mut matched = false;
    if meta.is_dir() {
        for ent in fs::read_dir(&meta).unwrap().flatten() {
            if ent.file_name().to_string_lossy().ends_with(".hdr") {
                continue;
            }
            if fs::read(ent.path()).ok().as_deref() == Some(puts[1].2.as_slice()) {
                matched = true;
                break;
            }
        }
    }
    assert!(
        matched,
        "blob PUT must equal the meta-v3 sidecar under {}",
        meta.display()
    );
    let blob_sqlite = dir.path().join("uploaded.sqlite");
    fs::write(&blob_sqlite, &puts[1].2).unwrap();
    let uploaded_idx = ratarmount_index::SqliteIndex::open_read_only(&blob_sqlite)
        .expect("uploaded sidecar opens");
    assert!(
        uploaded_idx.version_count("/tick.bin").unwrap() >= 1,
        "uploaded sqlite must list the overlay member"
    );
    let archive_put_at = hits
        .iter()
        .position(|h| h.0 == "PUT" && h.1 == key)
        .unwrap();
    assert!(
        hits.iter()
            .skip(archive_put_at + 1)
            .any(|h| h.0 == "GET" && h.1 == key),
        "reopen must read the listener, not the spool path"
    );
    thread::sleep(Duration::from_secs(2));
    assert_eq!(
        archive_puts(),
        1,
        "second tick must not PUT the archive again"
    );
    assert!(
        !fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(secret),
        "log must not contain the AWS secret"
    );
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = child.wait();
}

/// The in-test listener (not a private `gcs.rs` mock) sees archive, blob, then
/// pointer PUTs. Auth is `GOOGLE_HMAC_*` plus `RATARMOUNT_GCS_ENDPOINT`, not AWS.
#[test]
fn gs_interval_uploads_once() {
    let dir = tempfile::tempdir().unwrap();
    let member = ratarmount_formats_tar::UstarMember {
        path: "seed.txt",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"seed\n" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    };
    let mut plain = Vec::new();
    ratarmount_formats_tar::write_ustar_members(&mut plain, &[member]).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut plain).unwrap();
    let zst_bytes = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
    let zst = dir.path().join("a.tar.zst");
    fs::write(&zst, &zst_bytes).unwrap();
    let idx = dir.path().join("a.tar.zst.index.sqlite");
    let body = ratarmount_compress::open_seekable_zstd(&zst).unwrap();
    let opts = ratarmount_core::OpenOptions {
        write_index: true,
        index_minimum_file_count: 0,
        ..ratarmount_core::OpenOptions::default()
    };
    ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
        &zst,
        body,
        Some(&idx),
        &opts,
        "test",
    )
    .expect("sidecar");
    let index_bytes = fs::read(&idx).unwrap();
    let pointer = ratarmount_index::IndexPointer::for_blob(&idx, Some(&zst)).unwrap();
    let pointer_bytes = ratarmount_index::index_pointer_to_json(&pointer)
        .unwrap()
        .into_bytes();
    let id = pointer.index_id.clone();
    let key = "data/a.tar.zst";
    let mut objects = std::collections::HashMap::new();
    objects.insert(key.into(), zst_bytes);
    objects.insert(format!("{key}.index.ptr"), pointer_bytes);
    objects.insert(format!("{key}.index.{id}.sqlite"), index_bytes);
    let gcs = spawn_s3_live(objects);
    let cache = tempfile::tempdir().unwrap();
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let secret = "gcs-fixture-secret-DO-NOT-LOG";
    let payload = format!("gs-interval-{}\n", std::process::id());
    let mut child = Command::new(bin())
        .args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .args(["--commit-overlay-interval", "1s"])
        .arg("gs://bkt/data/a.tar.zst")
        .env("GOOGLE_HMAC_KEY", "GOOG1ACCESS")
        .env("GOOGLE_HMAC_SECRET", secret)
        .env("RATARMOUNT_GCS_ENDPOINT", format!("http://{}", gcs.addr))
        .env("RATARMOUNT_GCS_IMDS_BASE", "http://127.0.0.1:1")
        .env("XDG_CACHE_HOME", cache.path())
        .env_remove("CLOUDSDK_AUTH_ACCESS_TOKEN")
        .env_remove("GOOGLE_OAUTH_ACCESS_TOKEN")
        .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
        .env_remove("RATARMOUNT_GCS_ANONYMOUS")
        .env_remove("CLOUDSDK_ANONYMOUS")
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_ENDPOINT_URL")
        .env_remove("S3_ENDPOINT_URL")
        .env_remove("AWS_ANONYMOUS")
        .env_remove("RATARMOUNT_S3_ANONYMOUS")
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn");
    if !wait_ready(&log, "NFSv3", Duration::from_secs(15)) {
        let _ = child.kill();
        panic!(
            "server not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    assert!(
        !fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(secret),
        "mount log must not contain the GCS HMAC secret"
    );
    fs::write(ov.join("tick.bin"), payload.as_bytes()).unwrap();
    let archive_puts = || {
        gcs.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.method == "PUT" && h.key == key)
            .count()
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(12) && archive_puts() == 0 {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        archive_puts() >= 1,
        "no archive PUT: {:?} log={}",
        gcs.hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| format!("{} {}", h.method, h.key))
            .collect::<Vec<_>>(),
        fs::read_to_string(&log).unwrap_or_default()
    );
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(8) && ov.join("tick.bin").exists() {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !ov.join("tick.bin").exists(),
        "overlay file should be forgotten after upload: log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    let hits: Vec<(String, String, Vec<u8>)> = gcs
        .hits
        .lock()
        .unwrap()
        .iter()
        .map(|h| (h.method.clone(), h.key.clone(), h.body.clone()))
        .collect();
    let puts: Vec<&(String, String, Vec<u8>)> = hits.iter().filter(|h| h.0 == "PUT").collect();
    let put_keys: Vec<&String> = puts.iter().map(|h| &h.1).collect();
    assert!(
        puts.len() >= 3,
        "expected archive, blob, pointer PUTs, got {put_keys:?}"
    );
    assert_eq!(puts[0].1, key, "archive PUT first: {put_keys:?}");
    assert!(
        puts[1].1.starts_with(&format!("{key}.index.")) && puts[1].1.ends_with(".sqlite"),
        "blob PUT second: {}",
        puts[1].1
    );
    assert!(
        puts[1].1 != format!("{key}.index.sqlite"),
        "blob key must include the index id"
    );
    assert_eq!(puts[2].1, format!("{key}.index.ptr"), "pointer PUT third");
    assert!(
        puts.iter().all(|h| h.1 != format!("{key}.index.sqlite")),
        "well-known key must not be written"
    );
    let archive_body = &puts[0].2;
    assert_eq!(
        gcs.objects.lock().unwrap().get(key).map(Vec::as_slice),
        Some(archive_body.as_slice()),
        "stored object bytes must match the uploaded spool"
    );
    let uploaded = dir.path().join("uploaded.tar.zst");
    let plain_out = dir.path().join("uploaded.tar");
    fs::write(&uploaded, archive_body).unwrap();
    decode_tar_zst_to_tar(&uploaded, &plain_out);
    let plain_bytes = fs::read(&plain_out).unwrap();
    assert!(
        plain_bytes
            .windows(payload.len())
            .any(|w| w == payload.as_bytes()),
        "uploaded spool must contain the overlay file"
    );
    assert!(
        plain_bytes.windows(5).any(|w| w == b"seed\n"),
        "uploaded spool must keep the seed member"
    );
    let meta = cache.path().join("ratarmount").join("meta-v3");
    let mut matched = false;
    if meta.is_dir() {
        for ent in fs::read_dir(&meta).unwrap().flatten() {
            if ent.file_name().to_string_lossy().ends_with(".hdr") {
                continue;
            }
            if fs::read(ent.path()).ok().as_deref() == Some(puts[1].2.as_slice()) {
                matched = true;
                break;
            }
        }
    }
    assert!(
        matched,
        "blob PUT must equal the meta-v3 sidecar under {}",
        meta.display()
    );
    let archive_put_at = hits
        .iter()
        .position(|h| h.0 == "PUT" && h.1 == key)
        .unwrap();
    assert!(
        hits.iter()
            .skip(archive_put_at + 1)
            .any(|h| h.0 == "GET" && h.1 == key),
        "reopen must read the listener, not the spool path"
    );
    thread::sleep(Duration::from_secs(2));
    assert_eq!(
        archive_puts(),
        1,
        "second tick must not PUT the archive again"
    );
    assert!(
        !fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(secret),
        "log must not contain the GCS HMAC secret"
    );
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = child.wait();
}

struct AzHit {
    method: String,
    key: String,
    query: String,
    body: Vec<u8>,
}

struct AzLive {
    addr: std::net::SocketAddr,
    hits: std::sync::Arc<std::sync::Mutex<Vec<AzHit>>>,
    objects: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
}

/// In-test HTTP listener for `az://`. Not the private mock inside `azure.rs`.
/// Put Block does not replace the blob. `fail_block_list` answers Put Block List
/// with HTTP 500 and leaves the committed bytes alone. Put Blob without
/// `x-ms-blob-type: BlockBlob` is HTTP 400. `fail_pointer` answers the
/// `.index.ptr` Put Blob with HTTP 500.
fn spawn_azure_live(
    objects: std::collections::HashMap<String, Vec<u8>>,
    fail_block_list: bool,
    fail_pointer: bool,
) -> AzLive {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::<AzHit>::new()));
    let objs = std::sync::Arc::new(std::sync::Mutex::new(objects));
    let etags = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        String,
    >::new()));
    let hits_t = std::sync::Arc::clone(&hits);
    let objs_t = std::sync::Arc::clone(&objs);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                continue;
            }
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let target = parts.next().unwrap_or("/").to_string();
            let mut content_length = 0usize;
            let mut range_hdr: Option<String> = None;
            let mut blob_type = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    break;
                }
                if line == "\r\n" || line == "\n" || line.is_empty() {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = lower.strip_prefix("range:") {
                    range_hdr = Some(v.trim().to_string());
                } else if lower.starts_with("x-ms-blob-type:") {
                    if let Some((_, v)) = line.split_once(':') {
                        blob_type = v.trim().to_string();
                    }
                }
            }
            let mut body = vec![0u8; content_length];
            if content_length > 0 && reader.read_exact(&mut body).is_err() {
                continue;
            }
            let (path, query) = target.split_once('?').unwrap_or((&target, ""));
            let key = path
                .trim_start_matches('/')
                .split_once('/')
                .map(|(_, k)| k.to_string())
                .unwrap_or_default();
            let query = query.to_string();
            if method == "HEAD" || method == "GET" {
                let guard = objs_t.lock().unwrap();
                if let Some(obj) = guard.get(&key) {
                    let etag = etags
                        .lock()
                        .unwrap()
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| "\"v1\"".into());
                    let mut start = 0usize;
                    let mut end = obj.len().saturating_sub(1);
                    let mut partial = false;
                    if let Some(r) = range_hdr.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
                        let bits: Vec<&str> = r.splitn(2, '-').collect();
                        if bits.len() == 2 && !bits[0].is_empty() {
                            start = bits[0].parse().unwrap_or(0);
                            if !bits[1].is_empty() {
                                end = bits[1].parse().unwrap_or(end);
                            }
                            if start < obj.len() && start <= end {
                                end = end.min(obj.len() - 1);
                                partial = true;
                            }
                        }
                    }
                    let resp_body = if method == "HEAD" {
                        Vec::new()
                    } else if partial {
                        obj[start..=end].to_vec()
                    } else {
                        obj.clone()
                    };
                    let status = if partial && method == "GET" { 206 } else { 200 };
                    let reason = if status == 206 {
                        "Partial Content"
                    } else {
                        "OK"
                    };
                    let len_hdr = if method == "HEAD" {
                        obj.len()
                    } else {
                        resp_body.len()
                    };
                    let mut extra = format!("ETag: {etag}\r\nAccept-Ranges: bytes\r\n");
                    if partial {
                        extra.push_str(&format!(
                            "Content-Range: bytes {start}-{end}/{}\r\n",
                            obj.len()
                        ));
                    }
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} {reason}\r\n{extra}Content-Length: {len_hdr}\r\nConnection: close\r\n\r\n"
                    );
                    if method != "HEAD" {
                        let _ = stream.write_all(&resp_body);
                    }
                    hits_t.lock().unwrap().push(AzHit {
                        method,
                        key,
                        query,
                        body: Vec::new(),
                    });
                    continue;
                }
                drop(guard);
                let msg = b"BlobNotFound";
                let _ = write!(
                    stream,
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    msg.len()
                );
                let _ = stream.write_all(msg);
                hits_t.lock().unwrap().push(AzHit {
                    method,
                    key,
                    query,
                    body: Vec::new(),
                });
            } else if method == "PUT" {
                let comp_block = query.contains("comp=block") && !query.contains("comp=blocklist");
                let comp_list = query.contains("comp=blocklist");
                let put_blob = !comp_block && !comp_list;
                if put_blob && blob_type != "BlockBlob" {
                    let msg = b"MissingRequiredHeader";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    let _ = stream.write_all(msg);
                    hits_t.lock().unwrap().push(AzHit {
                        method,
                        key,
                        query,
                        body: Vec::new(),
                    });
                    continue;
                }
                if put_blob && fail_pointer && key.ends_with(".index.ptr") {
                    let msg = b"pointer failed";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    let _ = stream.write_all(msg);
                    hits_t.lock().unwrap().push(AzHit {
                        method,
                        key,
                        query,
                        body,
                    });
                    continue;
                }
                if comp_list && fail_block_list {
                    let msg = b"block list failed";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    let _ = stream.write_all(msg);
                    hits_t.lock().unwrap().push(AzHit {
                        method,
                        key,
                        query,
                        body: Vec::new(),
                    });
                    continue;
                }
                if !comp_block && !comp_list {
                    objs_t.lock().unwrap().insert(key.clone(), body.clone());
                    let n = hits_t.lock().unwrap().len();
                    etags
                        .lock()
                        .unwrap()
                        .insert(key.clone(), format!("\"put-{n}\""));
                }
                let stored = if body.len() > 2 * 1024 * 1024 {
                    Vec::new()
                } else {
                    body
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                hits_t.lock().unwrap().push(AzHit {
                    method,
                    key,
                    query,
                    body: stored,
                });
            } else {
                let _ = write!(
                    stream,
                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        }
    });
    AzLive {
        addr,
        hits,
        objects: objs,
    }
}

fn az_env(cmd: &mut Command, addr: std::net::SocketAddr, secret_b64: &str, cache: &Path) {
    cmd.env("AZURE_STORAGE_ACCOUNT", "acct")
        .env("AZURE_STORAGE_KEY", secret_b64)
        .env("AZURE_STORAGE_ENDPOINT", format!("http://{addr}"))
        .env("RATARMOUNT_AZURE_IMDS_BASE", "http://127.0.0.1:1")
        .env("XDG_CACHE_HOME", cache)
        .env_remove("AZURE_STORAGE_SAS_TOKEN")
        .env_remove("RATARMOUNT_AZURE_ANONYMOUS")
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_ENDPOINT_URL")
        .env_remove("GOOGLE_HMAC_KEY")
        .env_remove("GOOGLE_HMAC_SECRET")
        .env_remove("RATARMOUNT_GCS_ENDPOINT");
}

/// The in-test listener (not a private `azure.rs` mock) sees archive, blob, then
/// pointer PUTs. The `az://` arm calls `publish_azure`.
#[test]
fn az_interval_uploads_once() {
    let dir = tempfile::tempdir().unwrap();
    let member = ratarmount_formats_tar::UstarMember {
        path: "seed.txt",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"seed\n" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    };
    let mut plain = Vec::new();
    ratarmount_formats_tar::write_ustar_members(&mut plain, &[member]).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut plain).unwrap();
    let zst_bytes = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
    let zst = dir.path().join("a.tar.zst");
    fs::write(&zst, &zst_bytes).unwrap();
    let idx = dir.path().join("a.tar.zst.index.sqlite");
    let body = ratarmount_compress::open_seekable_zstd(&zst).unwrap();
    let opts = ratarmount_core::OpenOptions {
        write_index: true,
        index_minimum_file_count: 0,
        ..ratarmount_core::OpenOptions::default()
    };
    ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
        &zst,
        body,
        Some(&idx),
        &opts,
        "test",
    )
    .expect("sidecar");
    let index_bytes = fs::read(&idx).unwrap();
    let pointer = ratarmount_index::IndexPointer::for_blob(&idx, Some(&zst)).unwrap();
    let pointer_bytes = ratarmount_index::index_pointer_to_json(&pointer)
        .unwrap()
        .into_bytes();
    let id = pointer.index_id.clone();
    let key = "data/a.tar.zst";
    let mut objects = std::collections::HashMap::new();
    objects.insert(key.into(), zst_bytes);
    objects.insert(format!("{key}.index.ptr"), pointer_bytes);
    objects.insert(format!("{key}.index.{id}.sqlite"), index_bytes);
    let az = spawn_azure_live(objects, false, false);
    let cache = tempfile::tempdir().unwrap();
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let secret = "YXp1cmUtc2VjcmV0LWtleS1ET05PVExPRw==";
    let payload = format!("az-interval-{}\n", std::process::id());
    let mut cmd = Command::new(bin());
    cmd.args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .args(["--commit-overlay-interval", "1s"])
        .arg("az://bkt/data/a.tar.zst");
    az_env(&mut cmd, az.addr, secret, cache.path());
    let mut child = cmd
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn");
    if !wait_ready(&log, "NFSv3", Duration::from_secs(20)) {
        let _ = child.kill();
        panic!(
            "server not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    assert!(
        !fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(secret),
        "mount log must not contain the SharedKey secret"
    );
    fs::write(ov.join("tick.bin"), payload.as_bytes()).unwrap();
    let archive_puts = || {
        az.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.method == "PUT" && h.key == key && h.query.is_empty())
            .count()
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) && archive_puts() == 0 {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        archive_puts() >= 1,
        "no archive PUT: {:?} log={}",
        az.hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| format!("{} {} {}", h.method, h.key, h.query))
            .collect::<Vec<_>>(),
        fs::read_to_string(&log).unwrap_or_default()
    );
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) && ov.join("tick.bin").exists() {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !ov.join("tick.bin").exists(),
        "overlay file should be forgotten after upload: log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    let hits: Vec<(String, String, String, Vec<u8>)> = az
        .hits
        .lock()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h.method.clone(),
                h.key.clone(),
                h.query.clone(),
                h.body.clone(),
            )
        })
        .collect();
    let puts: Vec<&(String, String, String, Vec<u8>)> = hits
        .iter()
        .filter(|h| h.0 == "PUT" && h.2.is_empty())
        .collect();
    let put_keys: Vec<&String> = puts.iter().map(|h| &h.1).collect();
    assert!(
        puts.len() >= 3,
        "expected archive, blob, pointer PUTs, got {put_keys:?}"
    );
    assert_eq!(puts[0].1, key, "archive PUT first: {put_keys:?}");
    assert!(
        puts[1].1.starts_with(&format!("{key}.index.")) && puts[1].1.ends_with(".sqlite"),
        "blob PUT second: {}",
        puts[1].1
    );
    assert!(
        puts[1].1 != format!("{key}.index.sqlite"),
        "blob key must include the index id"
    );
    assert_eq!(puts[2].1, format!("{key}.index.ptr"), "pointer PUT third");
    assert!(
        puts.iter().all(|h| h.1 != format!("{key}.index.sqlite")),
        "well-known key must not be written"
    );
    let archive_body = &puts[0].3;
    assert_eq!(
        az.objects.lock().unwrap().get(key).map(Vec::as_slice),
        Some(archive_body.as_slice()),
        "stored object bytes must match the uploaded spool"
    );
    let uploaded = dir.path().join("uploaded.tar.zst");
    let plain_out = dir.path().join("uploaded.tar");
    fs::write(&uploaded, archive_body).unwrap();
    decode_tar_zst_to_tar(&uploaded, &plain_out);
    let plain_bytes = fs::read(&plain_out).unwrap();
    assert!(
        plain_bytes
            .windows(payload.len())
            .any(|w| w == payload.as_bytes()),
        "uploaded spool must contain the overlay file"
    );
    assert!(
        plain_bytes.windows(5).any(|w| w == b"seed\n"),
        "uploaded spool must keep the seed member"
    );
    let archive_put_at = hits
        .iter()
        .position(|h| h.0 == "PUT" && h.1 == key && h.2.is_empty())
        .unwrap();
    assert!(
        hits.iter()
            .skip(archive_put_at + 1)
            .any(|h| h.0 == "GET" && h.1 == key),
        "reopen must read the listener, not the spool path"
    );
    thread::sleep(Duration::from_secs(2));
    assert_eq!(
        archive_puts(),
        1,
        "second tick must not PUT the archive again"
    );
    assert!(
        !fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(secret),
        "log must not contain the SharedKey secret"
    );
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = child.wait();
}

/// Regression: a pointer PUT failure must not forget the overlay.
#[test]
fn az_pointer_put_failure_keeps_overlay() {
    let dir = tempfile::tempdir().unwrap();
    let member = ratarmount_formats_tar::UstarMember {
        path: "seed.txt",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"seed\n" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    };
    let mut plain = Vec::new();
    ratarmount_formats_tar::write_ustar_members(&mut plain, &[member]).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut plain).unwrap();
    let zst_bytes = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
    let zst = dir.path().join("a.tar.zst");
    fs::write(&zst, &zst_bytes).unwrap();
    let idx = dir.path().join("a.tar.zst.index.sqlite");
    let body = ratarmount_compress::open_seekable_zstd(&zst).unwrap();
    let opts = ratarmount_core::OpenOptions {
        write_index: true,
        index_minimum_file_count: 0,
        ..ratarmount_core::OpenOptions::default()
    };
    ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
        &zst,
        body,
        Some(&idx),
        &opts,
        "test",
    )
    .expect("sidecar");
    let index_bytes = fs::read(&idx).unwrap();
    let pointer = ratarmount_index::IndexPointer::for_blob(&idx, Some(&zst)).unwrap();
    let pointer_bytes = ratarmount_index::index_pointer_to_json(&pointer)
        .unwrap()
        .into_bytes();
    let id = pointer.index_id.clone();
    let key = "data/a.tar.zst";
    let mut objects = std::collections::HashMap::new();
    objects.insert(key.into(), zst_bytes);
    objects.insert(format!("{key}.index.ptr"), pointer_bytes);
    objects.insert(format!("{key}.index.{id}.sqlite"), index_bytes);
    let az = spawn_azure_live(objects, false, true);
    let cache = tempfile::tempdir().unwrap();
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let secret = "YXp1cmUtc2VjcmV0LWtleS1ET05PVExPRw==";
    let mut cmd = Command::new(bin());
    cmd.args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .args(["--commit-overlay-interval", "1s"])
        .arg("az://bkt/data/a.tar.zst");
    az_env(&mut cmd, az.addr, secret, cache.path());
    let mut child = cmd
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn");
    if !wait_ready(&log, "NFSv3", Duration::from_secs(20)) {
        let _ = child.kill();
        panic!(
            "server not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    fs::write(ov.join("tick.bin"), b"keep-pointer\n").unwrap();
    let pointer_puts = || {
        az.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.method == "PUT" && h.key.ends_with(".index.ptr"))
            .count()
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) && pointer_puts() == 0 {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        pointer_puts() >= 1,
        "no pointer PUT: {:?} log={}",
        az.hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| format!("{} {}", h.method, h.key))
            .collect::<Vec<_>>(),
        fs::read_to_string(&log).unwrap_or_default()
    );
    assert!(
        ov.join("tick.bin").exists(),
        "pointer failure must not forget the overlay: log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    thread::sleep(Duration::from_secs(3));
    assert!(
        ov.join("tick.bin").exists(),
        "retry after a pointer failure must not forget the overlay"
    );
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = child.wait();
}

/// Regression: a failed Put Block List leaves the overlay file in place.
#[test]
fn az_block_list_failure_keeps_overlay() {
    let dir = tempfile::tempdir().unwrap();
    let mut payload = vec![0u8; 8 * 1024 * 1024 + 64 * 1024];
    let mut state = 0xA5A5_1234u32;
    for b in &mut payload {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        *b = (state >> 24) as u8;
    }
    let member = ratarmount_formats_tar::UstarMember {
        path: "seed.bin",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: &payload },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    };
    let mut plain = Vec::new();
    ratarmount_formats_tar::write_ustar_members(&mut plain, &[member]).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut plain).unwrap();
    let zst_bytes = ratarmount_compress::encode_zstd_frame(&plain, 1).unwrap();
    assert!(
        zst_bytes.len() > 8 * 1024 * 1024,
        "compressed fixture must exceed the single Put Blob limit, got {}",
        zst_bytes.len()
    );
    let zst = dir.path().join("a.tar.zst");
    fs::write(&zst, &zst_bytes).unwrap();
    let idx = dir.path().join("a.tar.zst.index.sqlite");
    let body = ratarmount_compress::open_seekable_zstd(&zst).unwrap();
    let opts = ratarmount_core::OpenOptions {
        write_index: true,
        index_minimum_file_count: 0,
        ..ratarmount_core::OpenOptions::default()
    };
    ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
        &zst,
        body,
        Some(&idx),
        &opts,
        "test",
    )
    .expect("sidecar");
    let index_bytes = fs::read(&idx).unwrap();
    let pointer = ratarmount_index::IndexPointer::for_blob(&idx, Some(&zst)).unwrap();
    let pointer_bytes = ratarmount_index::index_pointer_to_json(&pointer)
        .unwrap()
        .into_bytes();
    let id = pointer.index_id.clone();
    let key = "data/a.tar.zst";
    let original = zst_bytes.clone();
    let mut objects = std::collections::HashMap::new();
    objects.insert(key.into(), zst_bytes);
    objects.insert(format!("{key}.index.ptr"), pointer_bytes);
    objects.insert(format!("{key}.index.{id}.sqlite"), index_bytes);
    let az = spawn_azure_live(objects, true, false);
    let cache = tempfile::tempdir().unwrap();
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let secret = "YXp1cmUtc2VjcmV0LWtleS1ET05PVExPRw==";
    let mut cmd = Command::new(bin());
    cmd.args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .args(["--commit-overlay-interval", "1s"])
        .arg("az://bkt/data/a.tar.zst");
    az_env(&mut cmd, az.addr, secret, cache.path());
    let mut child = cmd
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn");
    if !wait_ready(&log, "NFSv3", Duration::from_secs(30)) {
        let _ = child.kill();
        panic!(
            "server not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    fs::write(ov.join("tick.bin"), b"keep-me\n").unwrap();
    let block_lists = || {
        az.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.method == "PUT" && h.query.contains("comp=blocklist"))
            .count()
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(90) && block_lists() == 0 {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        block_lists() >= 1,
        "no block list PUT: {:?} log={}",
        az.hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| format!("{} {} {}", h.method, h.key, h.query))
            .collect::<Vec<_>>(),
        fs::read_to_string(&log).unwrap_or_default()
    );
    assert!(
        ov.join("tick.bin").exists(),
        "failed block list must not forget the overlay: log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    thread::sleep(Duration::from_secs(3));
    assert!(
        ov.join("tick.bin").exists(),
        "retry after a failed block list must not forget the overlay"
    );
    assert_eq!(
        az.objects.lock().unwrap().get(key).map(Vec::as_slice),
        Some(original.as_slice()),
        "failed block list must not replace the blob"
    );
    assert!(
        az.hits
            .lock()
            .unwrap()
            .iter()
            .all(|h| { h.key != format!("{key}.index.sqlite") || h.method != "PUT" }),
        "well-known key must not be written"
    );
    assert!(
        !fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(secret),
        "log must not contain the SharedKey secret"
    );
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = child.wait();
}

fn ustar_name_count(tar: &[u8], name: &str) -> usize {
    let want = name.as_bytes();
    tar.chunks(512)
        .filter(|block| {
            if block.len() < 512 || block.get(257..262) != Some(b"ustar") {
                return false;
            }
            let raw = &block[..100];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(100);
            &raw[..end] == want
        })
        .count()
}

/// Regression: the first archive PUT is stored, then the client sees HTTP 500
/// whose body mentions HTTP 412. The next tick must not splice that object again.
#[test]
fn etag_mismatch_landed_put_keeps_one_member() {
    let dir = tempfile::tempdir().unwrap();
    let member = ratarmount_formats_tar::UstarMember {
        path: "seed.txt",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"seed\n" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    };
    let mut plain = Vec::new();
    ratarmount_formats_tar::write_ustar_members(&mut plain, &[member]).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut plain).unwrap();
    let zst_bytes = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
    let zst = dir.path().join("a.tar.zst");
    fs::write(&zst, &zst_bytes).unwrap();
    let idx = dir.path().join("a.tar.zst.index.sqlite");
    let body = ratarmount_compress::open_seekable_zstd(&zst).unwrap();
    let opts = ratarmount_core::OpenOptions {
        write_index: true,
        index_minimum_file_count: 0,
        ..ratarmount_core::OpenOptions::default()
    };
    ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
        &zst,
        body,
        Some(&idx),
        &opts,
        "test",
    )
    .expect("sidecar");
    let index_bytes = fs::read(&idx).unwrap();
    let pointer = ratarmount_index::IndexPointer::for_blob(&idx, Some(&zst)).unwrap();
    let pointer_bytes = ratarmount_index::index_pointer_to_json(&pointer)
        .unwrap()
        .into_bytes();
    let id = pointer.index_id.clone();
    let key = "data/a.tar.zst";
    let mut objects = std::collections::HashMap::new();
    objects.insert(key.into(), zst_bytes);
    objects.insert(format!("{key}.index.ptr"), pointer_bytes);
    objects.insert(format!("{key}.index.{id}.sqlite"), index_bytes);
    let s3 = spawn_s3_live_ex(objects, true);
    let cache = tempfile::tempdir().unwrap();
    let ov = dir.path().join("ov");
    fs::create_dir_all(&ov).unwrap();
    let log = dir.path().join("server.log");
    let logf = fs::File::create(&log).unwrap();
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let payload = format!("etag-landed-{}\n", std::process::id());
    let mut child = Command::new(bin())
        .args(["--nfs", "--nfs-bind", "127.0.0.1:0", "-w"])
        .arg(&ov)
        .args(["--commit-overlay-interval", "1s"])
        .arg("s3://bkt/data/a.tar.zst")
        .env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        .env("AWS_SECRET_ACCESS_KEY", secret)
        .env("AWS_REGION", "us-east-1")
        .env("AWS_DEFAULT_REGION", "us-east-1")
        .env("AWS_ENDPOINT_URL", format!("http://{}", s3.addr))
        .env("XDG_CACHE_HOME", cache.path())
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_ANONYMOUS")
        .env_remove("RATARMOUNT_S3_ANONYMOUS")
        .env("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1")
        .stdout(Stdio::from(logf.try_clone().unwrap()))
        .stderr(Stdio::from(logf))
        .spawn()
        .expect("spawn");
    if !wait_ready(&log, "NFSv3", Duration::from_secs(15)) {
        let _ = child.kill();
        panic!(
            "server not ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    fs::write(ov.join("tick.bin"), payload.as_bytes()).unwrap();
    let archive_puts = || {
        s3.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.method == "PUT" && h.key == key)
            .count()
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(12) && archive_puts() == 0 {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        archive_puts() >= 1,
        "no archive PUT: log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) && ov.join("tick.bin").exists() {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !ov.join("tick.bin").exists(),
        "overlay file should be forgotten after the landed object is accepted: log={}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    assert_eq!(
        archive_puts(),
        1,
        "landed PUT must not be uploaded again: {:?}",
        s3.hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| format!("{} {}", h.method, h.key))
            .collect::<Vec<_>>()
    );
    let stored = s3.objects.lock().unwrap().get(key).cloned().unwrap();
    let uploaded = dir.path().join("uploaded.tar.zst");
    let plain_out = dir.path().join("uploaded.tar");
    fs::write(&uploaded, &stored).unwrap();
    decode_tar_zst_to_tar(&uploaded, &plain_out);
    let plain_bytes = fs::read(&plain_out).unwrap();
    assert_eq!(
        ustar_name_count(&plain_bytes, "tick.bin"),
        1,
        "one copy of the member"
    );
    assert_eq!(ustar_name_count(&plain_bytes, "seed.txt"), 1);
    assert!(
        plain_bytes
            .windows(payload.len())
            .any(|w| w == payload.as_bytes()),
        "member bytes must be the overlay payload"
    );
    let hits = s3.hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.method == "PUT" && h.key == format!("{key}.index.ptr")),
        "success path still publishes the pointer"
    );
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = child.wait();
}
