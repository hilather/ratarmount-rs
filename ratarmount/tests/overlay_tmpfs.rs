//! RAM-overlay startup and exit cleanup without a FUSE device.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

/// Regression: process::exit and ordinary return must remove a RAM overlay.
#[test]
fn regression_overlay_tmpfs_cleanup_on_return_and_error_exit() {
    let source = tempfile::tempdir().unwrap();
    for fail in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command
            .args(["--overlay-tmpfs=1M", "--no-mount"])
            .env("XDG_RUNTIME_DIR", source.path());
        if fail {
            // This error is deliberately checked after opening the overlay.
            command.arg("--http");
        }
        let output = command.arg(source.path()).output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("cannot create RAM overlay") {
            eprintln!("skip: sandbox has no writable tmpfs: {stderr}");
            return;
        }
        assert_eq!(output.status.success(), !fail, "{stderr}");
        let path = stderr
            .lines()
            .find_map(|line| line.strip_prefix("Created temporary overlay directory: "))
            .unwrap_or_else(|| panic!("overlay not created: {stderr}"));
        assert!(!Path::new(path).exists(), "RAM overlay leaked: {path}");
    }
}

/// Regression: SIGINT/SIGTERM must stop serving before removing the RAM overlay.
#[test]
fn regression_overlay_tmpfs_signal_cleanup() {
    use std::fs;
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let source = tempfile::tempdir().unwrap();
    let logs = tempfile::tempdir().unwrap();
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let log_path = logs.path().join(format!("signal-{signal}.log"));
        let log = fs::File::create(&log_path).unwrap();
        let mut child = ChildGuard(
            Command::new(env!("CARGO_BIN_EXE_ratarmount"))
                .args([
                    "serve",
                    "--http",
                    "--http-bind=127.0.0.1:0",
                    "--overlay-tmpfs=1M",
                    "-d",
                    "2",
                ])
                .arg(source.path())
                .env("XDG_RUNTIME_DIR", source.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        let stderr = loop {
            let stderr = fs::read_to_string(&log_path).unwrap();
            if stderr.contains("cannot create RAM overlay") {
                eprintln!("skip: sandbox has no writable tmpfs: {stderr}");
                return;
            }
            if stderr.contains("HTTP listening") {
                break stderr;
            }
            assert!(child.0.try_wait().unwrap().is_none(), "{stderr}");
            assert!(Instant::now() < deadline, "server did not start: {stderr}");
            std::thread::sleep(Duration::from_millis(20));
        };
        let path = stderr
            .lines()
            .find_map(|line| line.strip_prefix("Created temporary overlay directory: "))
            .unwrap();
        assert!(Path::new(path).exists());
        assert_eq!(
            unsafe { libc::kill(child.0.id() as libc::pid_t, signal) },
            0
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "signal {signal}: {status}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "signal {signal} did not stop server"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!Path::new(path).exists(), "RAM overlay leaked: {path}");
    }
}
