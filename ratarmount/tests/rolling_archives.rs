//! One complete roll through the Linux kernel FUSE client.
#![cfg(target_os = "linux")]

#[path = "support/token.rs"]
mod token;

use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

struct MountGuard {
    daemon: Child,
    mountpoint: PathBuf,
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Ok(mut unmount) = Command::new("fusermount3")
            .arg("-uz")
            .arg(&self.mountpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let deadline = Instant::now() + Duration::from_secs(5);
            while unmount.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(25));
            }
            let _ = unmount.kill();
            let _ = unmount.wait();
        }
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for rolling commit"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

/// Regression: the interval loop must switch its active target and retain the
/// sealed generation in the mounted union after the second settled write.
#[test]
fn fuse_rolling_one_cycle() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse missing");
        return;
    }
    if Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: fusermount3 missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mountpoint = dir.path().join("mnt");
    fs::create_dir(&mountpoint).unwrap();
    let overlay = dir.path().join("overlay");
    let base = dir.path().join("traces.tar.zst");
    let log = dir.path().join("daemon.log");
    let log_file = File::create(&log).unwrap();
    let daemon = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args([
            "-f",
            "--roll-every",
            "1B",
            "--commit-overlay-interval",
            "1s",
            "--commit-overlay-mode",
            "append",
            "--commit-manifest",
            "-w",
        ])
        .arg(&overlay)
        .arg(&base)
        .arg(&mountpoint)
        .stdin(Stdio::null())
        .stdout(log_file.try_clone().unwrap())
        .stderr(log_file)
        .process_group(0)
        .spawn()
        .unwrap();
    let mut guard = MountGuard {
        daemon,
        mountpoint: mountpoint.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mounted = fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| line.split_whitespace().nth(4) == mountpoint.to_str());
        if mounted {
            break;
        }
        assert!(
            guard.daemon.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "mount failed: {}",
            fs::read_to_string(&log).unwrap()
        );
        thread::sleep(Duration::from_millis(50));
    }
    let root = dir.path().to_path_buf();
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = std::panic::catch_unwind(|| {
            fs::write(mountpoint.join("one"), b"generation-one").unwrap();
            wait_until(|| !overlay.join("one").exists());
            let first = root.join("traces.000001.tar.zst");
            let sealed = fs::read(&first).unwrap();
            fs::write(mountpoint.join("two"), b"generation-two").unwrap();
            wait_until(|| {
                root.join("traces.000002.tar.zst").is_file() && !overlay.join("two").exists()
            });
            assert_eq!(fs::read(&first).unwrap(), sealed);
            assert_eq!(fs::read(mountpoint.join("one")).unwrap(), b"generation-one");
            assert_eq!(fs::read(mountpoint.join("two")).unwrap(), b"generation-two");
            let names: Vec<_> = fs::read_dir(&mountpoint)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert!(names.contains(&"one".into()) && names.contains(&"two".into()));
            assert_eq!(
                fs::remove_file(mountpoint.join("one"))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EROFS)
            );
            assert!(root.join("traces.000001.tar.zst.manifest.jsonl").is_file());
            assert!(root.join("traces.000002.tar.zst.manifest.jsonl").is_file());
        });
        let _ = tx.send(result);
    });
    let result = rx.recv_timeout(Duration::from_secs(45));
    let daemon_log = fs::read_to_string(&log).unwrap_or_default();
    drop(guard);
    worker.join().unwrap();
    match result {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(error) => panic!("FUSE roll cycle hung: {error}; log: {daemon_log}"),
    }
}

/// A rolled series with an overlay over it: two commits rolled the active
/// generation to `traces.000002.tar.zst`, and each commit passed the commit
/// check against the rows the previous commit/refresh wrote (the pre-roll
/// rows for the first, the re-pointed ones for the second).
fn rolled_overlay() -> (
    tempfile::TempDir,
    PathBuf,
    PathBuf,
    std::sync::Arc<ratarmount_compositing::RollingMountSource>,
) {
    use ratarmount_compositing::{CommitMode, RollingMountSource, WriteOverlay};
    use ratarmount_core::{MountSource, OpenOptions};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("traces.tar.zst");
    let overlay = dir.path().join("overlay");
    let opener = |path: &Path| {
        ratarmount_session::factory::open_path(
            path,
            &OpenOptions {
                index_in_memory: true,
                ..Default::default()
            },
            false,
        )
        .map_err(|e| ratarmount_compositing::OverlayError::Msg(e.to_string()))
    };
    let series = Arc::new(RollingMountSource::open(&base, "1B".parse().unwrap(), opener).unwrap());
    // The series is built here, so the test names what it is: an archive at
    // its active generation, typed as the series base.
    let token = ratarmount_compositing::ClassifiedBase::open(&mut token::FixtureOpener {
        source: series.clone() as Arc<dyn MountSource>,
        kind: ratarmount_compositing::ServedKind::Archive,
        inputs: vec![base.to_str().unwrap().to_owned()],
        location: Some(ratarmount_compositing::ServedLocation::Local(
            series.active_path(),
        )),
    })
    .unwrap();
    let mut ov = WriteOverlay::open(
        &token,
        series.clone() as Arc<dyn MountSource>,
        &overlay,
        &ratarmount_compositing::CreateOptions::default(),
    )
    .unwrap();
    ov.set_rolling(series.clone());
    ov.set_commit_mode(CommitMode::Append);
    for name in ["one", "two"] {
        fs::write(overlay.join(name), name.as_bytes()).unwrap();
        assert!(ov.commit_live_idle(&base, Duration::ZERO, opener).unwrap());
    }
    assert!(series.active_path().ends_with("traces.000002.tar.zst"));
    drop(ov);
    (dir, base, overlay, series)
}

fn rolling_remount(base: &Path, overlay: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args([
            "--no-mount",
            "--index-file",
            ":memory:",
            "--roll-every",
            "1B",
            "-w",
        ])
        .arg(overlay)
        .arg(base)
        .output()
        .unwrap()
}

/// Regression: a rolling commit recorded the old generation's baseline and
/// refused the next mount of the same series (no kernel mount required).
#[test]
fn regression_rolling_commit_baseline_allows_cli_remount() {
    use ratarmount_compositing::OverlayMeta;

    let (_dir, base, overlay, series) = rolled_overlay();
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    assert!(meta.get("base_committed_at").is_some());
    let out = rolling_remount(&base, &overlay);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let active = series.active_path();
    let modified = fs::metadata(&active).unwrap().modified().unwrap();
    File::open(active)
        .unwrap()
        .set_modified(modified + Duration::from_secs(1))
        .unwrap();
    let out = rolling_remount(&base, &overlay);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("base mismatch"));
}

/// After a roll the active generation is a different path than the one the
/// overlay was created over. The roll's commits passed the commit check, the
/// refresh re-pointed the recorded place (`base_location`) at the new
/// generation, a remount over the series is not refused, and replacing the
/// NEW active generation's bytes is (the check compares the generation that is
/// active now, not the stale creation path).
#[test]
fn regression_rolling_roll_then_remount_not_refused() {
    use ratarmount_compositing::OverlayMeta;

    let (_dir, base, overlay, series) = rolled_overlay();
    let active = series.active_path();
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    assert_eq!(
        meta.get("base_location"),
        Some(format!("local:{}", active.canonicalize().unwrap().display()).as_str()),
        "the refresh followed the roll"
    );
    let out = rolling_remount(&base, &overlay);
    assert!(
        out.status.success(),
        "a remount after a roll was refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Same mtime, different size: only the content gate can notice it.
    let modified = fs::metadata(&active).unwrap().modified().unwrap();
    let mut bytes = fs::read(&active).unwrap();
    // An empty zstd skippable frame: still a valid archive, one size larger.
    bytes.extend_from_slice(&[0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    fs::write(&active, bytes).unwrap();
    File::options()
        .write(true)
        .open(&active)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let out = rolling_remount(&base, &overlay);
    assert!(
        !out.status.success(),
        "a replaced active generation was accepted"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("base mismatch"), "{stderr}");
}
