//! AI-PERF kernel coverage; run outside the sandbox with /dev/fuse.
#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Mount {
    child: Child,
    path: std::path::PathBuf,
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("fusermount3")
            .args(["-uz"])
            .arg(&self.path)
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Regression: parallel multiframe reads, seeks and EOF match with direct I/O on/off.
#[test]
fn regression_fuse_zstd_direct_io_identical_bytes() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return;
    }
    if Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: fusermount3 unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..4 * 1024 * 1024 + 713)
        .map(|i| (i % 251) as u8)
        .collect();
    let mut tar = Vec::new();
    ratarmount_formats_tar::write_ustar_members(
        &mut tar,
        &[ratarmount_formats_tar::UstarMember {
            path: "member",
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: &data },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }],
    )
    .unwrap();
    let mut compressed = Vec::new();
    for part in tar.chunks(128 * 1024) {
        compressed.extend(ratarmount_compress::encode_zstd_frame(part, 1).unwrap());
    }
    let archive = dir.path().join("frames.tar.zst");
    fs::write(&archive, compressed).unwrap();
    for direct in [false, true] {
        let mountpoint = dir.path().join(if direct { "direct" } else { "cached" });
        fs::create_dir(&mountpoint).unwrap();
        let log = dir.path().join("daemon.log");
        let output = File::create(&log).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.args(["-f", "-P", "4", "--readahead", "1M"]);
        if direct {
            // Explicit "on" must also be disabled by the direct-I/O policy.
            cmd.args(["--direct-io", "--passthrough", "on"]);
        } else {
            cmd.args(["--passthrough", "off"]);
        }
        let child = cmd
            .arg(&archive)
            .arg(&mountpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        let mut mount = Mount {
            child,
            path: mountpoint,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if fs::read_to_string("/proc/self/mountinfo")
                .unwrap()
                .lines()
                .any(|line| line.split_whitespace().nth(4) == mount.path.to_str())
            {
                break;
            }
            assert!(
                mount.child.try_wait().unwrap().is_none(),
                "{}",
                fs::read_to_string(&log).unwrap()
            );
            assert!(
                Instant::now() < deadline,
                "mount timeout: {}",
                fs::read_to_string(&log).unwrap()
            );
            std::thread::sleep(Duration::from_millis(30));
        }
        let path = mount.path.join("member");
        let expected = data.clone();
        let (tx, rx) = mpsc::channel();
        let read = std::thread::spawn(move || {
            let mut f = File::open(&path).unwrap();
            let mut got = Vec::new();
            f.read_to_end(&mut got).unwrap();
            assert_eq!(got, expected);
            for offset in [17, 700_003, 33] {
                f.seek(SeekFrom::Start(offset)).unwrap();
                let mut bytes = vec![0; 300_019];
                f.read_exact(&mut bytes).unwrap();
                assert_eq!(
                    bytes,
                    expected[offset as usize..offset as usize + bytes.len()]
                );
            }
            f.seek(SeekFrom::End(0)).unwrap();
            assert_eq!(f.read(&mut [0; 16]).unwrap(), 0);
            tx.send(()).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(30));
        drop(mount); // Lazy unmount also releases a reader if the daemon stalled.
        result.expect("multiframe FUSE read failed or timed out");
        read.join().unwrap();
    }
}
