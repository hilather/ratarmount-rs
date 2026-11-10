//! Regression: Linux binaries must start without a load-time libfuse dependency.
#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[path = "support/unmount.rs"]
mod unmount;

const PROMPT_EXIT: Duration = Duration::from_secs(10);
const CONTENT: &[u8] = b"runtime-loaded libfuse3\n";

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    mountpoint: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("rrs-libfuse-")
            .tempdir()
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir(root.join("tmp")).unwrap();
        // One small ustar member, without depending on an external tar producer.
        let mut tar = vec![0u8; 2048];
        tar[..10].copy_from_slice(b"member.txt");
        tar[100..108].copy_from_slice(b"0000644\0");
        tar[108..116].copy_from_slice(b"0000000\0");
        tar[116..124].copy_from_slice(b"0000000\0");
        tar[124..136].copy_from_slice(format!("{:011o}\0", CONTENT.len()).as_bytes());
        tar[136..148].copy_from_slice(b"00000000000\0");
        tar[148..156].fill(b' ');
        tar[156] = b'0';
        tar[257..263].copy_from_slice(b"ustar\0");
        tar[263..265].copy_from_slice(b"00");
        let checksum: u32 = tar[..512].iter().map(|&b| u32::from(b)).sum();
        tar[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        tar[512..512 + CONTENT.len()].copy_from_slice(CONTENT);
        fs::write(root.join("x.tar"), tar).unwrap();
        Self {
            mountpoint: root.join("mnt"),
            root,
            _temp: temp,
        }
    }

    fn block_libraries(&self) {
        for soname in ["libfuse3.so.4", "libfuse3.so.3"] {
            fs::write(self.root.join(soname), b"not an ELF library\n").unwrap();
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command
            .env("LD_LIBRARY_PATH", &self.root)
            .env("TMPDIR", self.root.join("tmp"))
            .env("HOME", &self.root)
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("LC_ALL", "C")
            .env("RUST_LOG", "ratarmount_fuse=info")
            .stdout(Stdio::null())
            .stderr(File::create(self.root.join("stderr")).unwrap());
        command
    }

    fn stderr(&self) -> String {
        fs::read_to_string(self.root.join("stderr")).unwrap()
    }
}

struct Running {
    child: Child,
    mountpoint: PathBuf,
}

impl Drop for Running {
    fn drop(&mut self) {
        if unmount::is_mounted(&self.mountpoint) {
            let _ = unmount::unmount_within(
                &self.mountpoint,
                Duration::from_secs(5),
                "libfuse cleanup",
            );
        }
        // Only our unreaped child can be signalled, never a saved/reused pid.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait_within(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_preflight_failure(arguments: &[&str]) {
    let fixture = Fixture::new();
    fixture.block_libraries();
    let start = Instant::now();
    let child = fixture
        .command()
        .args(arguments)
        .arg("--control-interface")
        .arg(fixture.root.join("x.tar"))
        .arg(&fixture.mountpoint)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut running = Running {
        child,
        mountpoint: fixture.mountpoint.clone(),
    };
    let pid = running.child.id();
    // Hold the write end open, including during --sftp-subsystem startup.
    let _stdin = running.child.stdin.take().unwrap();
    let status = wait_within(&mut running.child, PROMPT_EXIT);
    let stderr = fixture.stderr();
    assert!(
        status.is_some(),
        "preflight did not exit within 10s: {stderr}"
    );
    assert_eq!(status.unwrap().code(), Some(1), "{stderr}");
    assert!(start.elapsed() < PROMPT_EXIT, "{stderr}");
    let first = stderr
        .find("cannot load libfuse3 (tried libfuse3.so.4:")
        .expect(&stderr);
    let second = stderr.find("; libfuse3.so.3:").expect(&stderr);
    assert!(first < second, "{stderr}");
    assert!(
        stderr.contains("install the distribution's fuse3 package"),
        "{stderr}"
    );
    assert!(!stderr.contains("timed out waiting for mount"), "{stderr}");
    assert!(!stderr.contains("control interface:"), "{stderr}");
    assert!(!unmount::is_mounted(&fixture.mountpoint));
    // Mirrors main.rs control_socket_path(TMPDIR, pid); --control-interface is opt-in.
    assert!(!fixture
        .root
        .join("tmp")
        .join(format!("ratarmount-control-{pid}.sock"))
        .exists());
    assert!(
        !fixture.root.join("x.tar.index.sqlite").exists(),
        "preflight must precede indexing"
    );
    assert!(
        !fixture.mountpoint.exists(),
        "preflight must precede mountpoint creation"
    );
}

/// Regression: missing libfuse must fail before foreground indexing or socket binding.
#[test]
fn regression_libfuse_missing_foreground() {
    assert_preflight_failure(&["-f"]);
}

/// Regression: the daemon parent must report missing libfuse before its 30s mount wait.
#[test]
fn regression_libfuse_missing_daemon() {
    assert_preflight_failure(&[]);
}

/// Regression: missing libfuse must fail even while SFTP subsystem stdin stays open.
/// With sftp-russh this covers the stdin server; without it preflight must still
/// precede the feature refusal (exit 1 instead of exit 2).
#[test]
fn regression_libfuse_missing_sftp_subsystem() {
    assert_preflight_failure(&["-f", "--sftp-subsystem"]);
}

/// Regression: portable binaries linked to libfuse3.so.3 cannot start on so.4 hosts.
#[test]
fn regression_portable_no_libfuse_needed() {
    let binary = env!("CARGO_BIN_EXE_ratarmount");
    let bytes = fs::read(binary).unwrap();
    for name in [b"libfuse3.so.4", b"libfuse3.so.3"] {
        assert!(
            bytes.windows(name.len()).any(|window| window == name),
            "missing runtime candidate {name:?}"
        );
    }
    let output = match Command::new("readelf").arg("-d").arg(binary).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skip: readelf is missing (runtime candidate strings checked)");
            return;
        }
        Err(error) => panic!("readelf: {error}"),
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dynamic = String::from_utf8(output.stdout).unwrap();
    for line in dynamic.lines().filter(|line| line.contains("(NEEDED)")) {
        assert!(!line.contains("libfuse"), "load-time dependency: {line}");
    }
    assert!(
        dynamic.contains("(NEEDED)"),
        "readelf reported no NEEDED entries"
    );
}

fn host_library() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(output) = Command::new("ldconfig").arg("-p").output() {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if matches!(
                line.split_whitespace().next(),
                Some("libfuse3.so.4" | "libfuse3.so.3")
            ) {
                if let Some((_, path)) = line.split_once(" => ") {
                    candidates.push(PathBuf::from(path));
                }
            }
        }
    }
    for dir in [
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
    ] {
        for soname in ["libfuse3.so.4", "libfuse3.so.3"] {
            candidates.push(Path::new(dir).join(soname));
        }
    }
    candidates.into_iter().find(|path| path.is_file())
}

/// Regression: the so.4 branch must mount through libfuse, even on a so.3-only host.
#[test]
fn regression_libfuse_so4_only_mount() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse missing");
        return;
    }
    if !std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|p| p.join("fusermount3").is_file()))
    {
        eprintln!("skip: fusermount3 not on PATH");
        return;
    }
    let Some(host) = host_library() else {
        eprintln!("skip: no host libfuse3 found by ldconfig or in standard library directories");
        return;
    };
    let fixture = Fixture::new();
    fixture.block_libraries();
    fs::copy(host, fixture.root.join("libfuse3.so.4")).unwrap();
    fs::create_dir(&fixture.mountpoint).unwrap();
    let child = fixture
        .command()
        .arg("-f")
        .arg(fixture.root.join("x.tar"))
        .arg(&fixture.mountpoint)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut running = Running {
        child,
        mountpoint: fixture.mountpoint.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !unmount::is_mounted(&fixture.mountpoint) {
        assert!(
            running.child.try_wait().unwrap().is_none(),
            "mount exited: {}",
            fixture.stderr()
        );
        assert!(
            Instant::now() < deadline,
            "mount timed out: {}",
            fixture.stderr()
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        fs::read(fixture.mountpoint.join("member.txt")).unwrap(),
        CONTENT
    );
    assert!(
        fixture
            .stderr()
            .contains("libfuse: mounted through libfuse3.so.4"),
        "{}",
        fixture.stderr()
    );
    let maps = fs::read_to_string(format!("/proc/{}/maps", running.child.id())).unwrap();
    let loaded = fixture.root.join("libfuse3.so.4");
    assert!(
        maps.contains(loaded.to_str().unwrap()),
        "expected canonical path {} in maps",
        loaded.display()
    );
    unmount::unmount_within(
        &fixture.mountpoint,
        Duration::from_secs(5),
        "libfuse so4 mount",
    )
    .unwrap();
    let status = wait_within(&mut running.child, PROMPT_EXIT)
        .expect("mount process did not exit after unmount");
    assert!(status.success(), "{}", fixture.stderr());
    assert!(!unmount::is_mounted(&fixture.mountpoint));
}
