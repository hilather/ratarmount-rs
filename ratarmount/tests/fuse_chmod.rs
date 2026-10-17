//! Regression: toolchain outputs and scripts inside write mounts are executable.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Mount {
    child: Child,
    path: PathBuf,
}

impl Mount {
    fn start(archive: &Path, mount: &Path, overlay: Option<&Path>) -> Self {
        fs::create_dir_all(mount).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.args(["-f", "--passthrough", "off"]);
        if let Some(overlay) = overlay {
            cmd.arg("-w").arg(overlay);
        }
        let child = cmd
            .arg(archive)
            .arg(mount)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let mut mounted = Self {
            child,
            path: mount.into(),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while !mount.join("trace").exists() {
            assert!(mounted.child.try_wait().unwrap().is_none(), "mount exited");
            assert!(Instant::now() < deadline, "mount timeout");
            std::thread::sleep(Duration::from_millis(50));
        }
        mounted
    }

    fn stop(&mut self) {
        let _ = Command::new("fusermount3")
            .arg("-u")
            .arg(&self.path)
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            self.stop();
        }
    }
}

#[test]
fn regression_fuse_setattr_mode_build_and_execute() {
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
    let archive = dir.path().join("base.tar");
    let overlay = dir.path().join("overlay");
    let mount = dir.path().join("mnt");
    let mut tar = Vec::new();
    ratarmount_formats_tar::write_ustar_members(
        &mut tar,
        &[
            ratarmount_formats_tar::UstarMember {
                path: "trace",
                payload: ratarmount_formats_tar::UstarPayload::File {
                    bytes: b"#!/bin/sh\nprintf base-ok",
                },
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                xattrs: &[],
            },
            ratarmount_formats_tar::UstarMember {
                path: "script.sh",
                payload: ratarmount_formats_tar::UstarPayload::File {
                    bytes: b"#!/bin/sh\nprintf script-ok",
                },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                xattrs: &[],
            },
        ],
    )
    .unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut tar).unwrap();
    fs::write(&archive, tar).unwrap();
    let _mounted = Mount::start(&archive, &mount, Some(&overlay));
    let base = Command::new(mount.join("trace")).output().unwrap();
    assert!(base.status.success());
    assert_eq!(base.stdout, b"base-ok");
    let script = Command::new("sh")
        .current_dir(&mount)
        .args(["-c", "chmod +x script.sh && ./script.sh"])
        .output()
        .unwrap();
    assert!(
        script.status.success(),
        "{}",
        String::from_utf8_lossy(&script.stderr)
    );
    assert_eq!(script.stdout, b"script-ok");
    assert!(
        !overlay.join("script.sh").exists(),
        "chmod copied archive payload"
    );
    fs::write(mount.join("new.sh"), b"#!/bin/sh\nprintf new-ok").unwrap();
    let script = Command::new("sh")
        .current_dir(&mount)
        .args(["-c", "chmod +x new.sh && ./new.sh"])
        .output()
        .unwrap();
    assert!(
        script.status.success(),
        "{}",
        String::from_utf8_lossy(&script.stderr)
    );
    assert_eq!(script.stdout, b"new-ok");
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skip: cc unavailable (script execution passed)");
        return;
    }
    fs::write(
        mount.join("tiny.c"),
        b"#include <stdio.h>\nint main(void) { puts(\"compiled-ok\"); return 0; }\n",
    )
    .unwrap();
    let build = Command::new("cc")
        .current_dir(&mount)
        .args(["tiny.c", "-o", "tiny"])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let run = Command::new(mount.join("tiny")).output().unwrap();
    assert!(run.status.success());
    assert_eq!(run.stdout, b"compiled-ok\n");
}
