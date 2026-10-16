//! Kernel checks for AI-PT. Run outside the sandbox with /dev/fuse.
#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(20);

fn fuse_available() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return false;
    }
    if Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: fusermount3 unavailable");
        return false;
    }
    true
}

fn privileged() -> bool {
    use std::os::unix::fs::MetadataExt;
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let caps = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("CapEff:")
                .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
        })
        .unwrap_or(0);
    caps & (1 << 21) != 0
        && fs::metadata("/proc/self/ns/user").is_ok_and(|ns| ns.ino() == 0xeffffffd)
}

fn available() -> bool {
    if !fuse_available() {
        return false;
    }
    if !privileged() {
        assert!(
            std::env::var_os("RATARMOUNT_TEST_REQUIRE_PASSTHROUGH").is_none(),
            "CAP_SYS_ADMIN in initial user namespace required"
        );
        eprintln!("skip: passthrough on requires CAP_SYS_ADMIN in the initial user namespace");
        return false;
    }
    true
}

struct Mount {
    child: Child,
    path: PathBuf,
    log: PathBuf,
}

impl Mount {
    fn start(
        root: &Path,
        source: &Path,
        mode: &str,
        copy: bool,
        overlay: Option<(&Path, bool)>,
    ) -> Self {
        let path = root.join("mnt");
        fs::create_dir_all(&path).unwrap();
        let log = root.join("daemon.log");
        let output = File::create(&log).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command.args(["-f", "--passthrough", mode, "-d", "3"]);
        if copy {
            command.args(["--passthrough-copy", "--passthrough-copy-max", "1M"]);
        }
        if let Some((dir, readonly)) = overlay {
            command.arg("-w").arg(dir);
            if readonly {
                command.args(["-o", "ro"]);
            }
        }
        let child = command
            .arg(source)
            .arg(&path)
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("RUST_LOG", "ratarmount_fuse=debug")
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        let mut mount = Self { child, path, log };
        let deadline = Instant::now() + DEADLINE;
        loop {
            let log = mount.logs();
            if mount.visible() && log.contains("FUSE I/O mode:") {
                return mount;
            }
            if let Some(status) = mount.child.try_wait().unwrap() {
                panic!("daemon exited {status}: {log}");
            }
            assert!(Instant::now() < deadline, "mount timed out: {log}");
            thread::sleep(Duration::from_millis(30));
        }
    }

    fn logs(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn visible(&self) -> bool {
        fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| line.split_whitespace().nth(4) == self.path.to_str())
    }

    fn unmount(&mut self) {
        let mut child = Command::new("fusermount3")
            .args(["-u", "-z"])
            .arg(&self.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + DEADLINE;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }
        let _ = child.wait();
    }

    fn finish(mut self) {
        self.unmount();
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "daemon exited {status}: {}", self.logs());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not exit: {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(30));
        }
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = self.child.kill();
        if self.visible() {
            self.unmount();
        }
        let _ = self.child.wait();
    }
}

fn assert_bytes(mount: &Mount, expected: &[u8]) {
    let path = mount.path.join("file");
    let expected = expected.to_vec();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = std::panic::catch_unwind(|| {
            let mut first = File::open(&path).unwrap();
            let mut second = File::open(&path).unwrap();
            let mut bytes = Vec::new();
            first.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, expected);
            drop(first);
            second.seek(SeekFrom::Start(17)).unwrap();
            bytes.clear();
            second.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, expected[17..]);
            drop(second);
            assert_eq!(fs::read(&path).unwrap(), expected);
        });
        let _ = tx.send(result);
    });
    rx.recv_timeout(DEADLINE)
        .expect("FUSE read timed out")
        .unwrap();
}

/// Regression: stored members start at byte zero; on/off yield identical bytes,
/// and concurrent opens retain the registration until the last release.
#[test]
fn fuse_passthrough_folder_and_tar_identical_bytes() {
    if !available() {
        return;
    }
    let payload: Vec<u8> = (0..65539).map(|i| (i % 251) as u8).collect();
    for tar in [false, true] {
        for mode in ["off", "on"] {
            let dir = tempfile::tempdir().unwrap();
            let folder = dir.path().join("folder");
            fs::create_dir(&folder).unwrap();
            fs::write(folder.join("file"), &payload).unwrap();
            let source = if tar {
                let path = dir.path().join("stored.tar");
                ratarmount_formats_tar::write_ustar_members(
                    &mut File::create(&path).unwrap(),
                    &[ratarmount_formats_tar::UstarMember {
                        xattrs: &[],
                        path: "file",
                        payload: ratarmount_formats_tar::UstarPayload::File { bytes: &payload },
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    }],
                )
                .unwrap();
                path
            } else {
                folder
            };
            let mount = Mount::start(dir.path(), &source, mode, tar, None);
            assert_bytes(&mount, &payload);
            let logs = mount.logs();
            if mode == "on" {
                assert!(
                    logs.contains("passthrough registration probe succeeded"),
                    "{logs}"
                );
                if std::env::var_os("RATARMOUNT_TEST_REQUIRE_PASSTHROUGH").is_some() {
                    assert!(
                        logs.lines()
                            .any(|line| line.contains("FUSE passthrough open ino=")
                                && !line.contains("using daemon reads")),
                        "no backing registered: {logs}"
                    );
                }
            } else {
                assert!(logs.contains("FUSE I/O mode: daemon"), "{logs}");
                assert!(!logs.contains("FUSE passthrough open ino="), "{logs}");
            }
            mount.finish();
        }
    }
}

/// Regression: writable overlay opens must remain compatible with a concurrent
/// reader; an explicitly RO overlay can pass its whole-file descriptor through.
#[test]
fn fuse_passthrough_overlay_readonly_and_writable_modes() {
    if !available() {
        return;
    }
    for readonly in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("base");
        let overlay = dir.path().join("overlay");
        fs::create_dir(&folder).unwrap();
        fs::create_dir(&overlay).unwrap();
        let payload = vec![0x57; 4096];
        fs::write(overlay.join("file"), &payload).unwrap();
        let mount = Mount::start(dir.path(), &folder, "on", false, Some((&overlay, readonly)));
        assert_bytes(&mount, &payload);
        if readonly {
            assert!(mount
                .logs()
                .contains("passthrough registration probe succeeded"));
        } else {
            assert!(mount
                .logs()
                .contains("FUSE I/O mode: daemon until backing registration"));
            let path = mount.path.join("file");
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                use std::os::unix::fs::FileExt;
                let reader = File::open(&path).unwrap();
                let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
                writer.write_all_at(b"changed", 0).unwrap();
                let mut bytes = [0; 7];
                reader.read_exact_at(&mut bytes, 0).unwrap();
                assert_eq!(&bytes, b"changed");
                let _ = tx.send(());
            });
            rx.recv_timeout(DEADLINE)
                .expect("concurrent overlay opens/read/write failed");
        }
        mount.finish();
    }
}

/// Regression: unprivileged auto mounts retain daemon I/O; forced on fails at startup.
#[test]
fn fuse_passthrough_unprivileged_auto_and_on() {
    if !fuse_available() {
        return;
    }
    if privileged() {
        eprintln!("skip: unprivileged passthrough check requires no initial CAP_SYS_ADMIN");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("folder");
    fs::create_dir(&folder).unwrap();
    let payload = vec![0x61; 4096];
    fs::write(folder.join("file"), &payload).unwrap();
    let mount = Mount::start(dir.path(), &folder, "auto", false, None);
    assert_bytes(&mount, &payload);
    assert!(mount.logs().contains("FUSE I/O mode: daemon"));
    assert!(!mount.logs().contains("passthrough negotiated"));
    mount.finish();

    let log = dir.path().join("forced.log");
    let child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["-f", "--passthrough", "on", "-d", "3"])
        .arg(&folder)
        .arg(dir.path().join("mnt"))
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(&log).unwrap()))
        .spawn()
        .unwrap();
    let mut forced = Mount {
        child,
        path: dir.path().join("mnt"),
        log,
    };
    let deadline = Instant::now() + DEADLINE;
    loop {
        if let Some(status) = forced.child.try_wait().unwrap() {
            let logs = forced.logs();
            assert!(
                !status.success(),
                "forced mount unexpectedly succeeded: {logs}"
            );
            // Older kernels fail negotiation before they reach the permission probe.
            assert!(
                logs.contains("CAP_SYS_ADMIN") || logs.contains("--passthrough on requires"),
                "{logs}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "forced mount did not reject startup: {}",
            forced.logs()
        );
        thread::sleep(Duration::from_millis(30));
    }
}
