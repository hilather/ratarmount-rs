//! Regression: provenance survives FUSE setfattr, commit, and a fresh read-only mount.
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
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if self.child.try_wait().ok().flatten().is_none() {
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
fn regression_provenance_setfattr_commit_remount() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return;
    }
    for tool in ["setfattr", "getfattr", "fusermount3"] {
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!("skip: {tool} unavailable");
            return;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("trace.tar");
    let overlay = dir.path().join("overlay");
    let mount = dir.path().join("mnt");
    let mut tar = Vec::new();
    ratarmount_formats_tar::write_ustar_members(
        &mut tar,
        &[ratarmount_formats_tar::UstarMember {
            path: "trace",
            payload: ratarmount_formats_tar::UstarPayload::File {
                bytes: b"trace payload",
            },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        }],
    )
    .unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut tar).unwrap();
    fs::write(&archive, tar).unwrap();
    let mut mounted = Mount::start(&archive, &mount, Some(&overlay));
    assert!(Command::new("setfattr")
        .args(["-n", "user.train_ok", "-v", "false"])
        .arg(mount.join("trace"))
        .status()
        .unwrap()
        .success());
    assert!(
        !overlay.join("trace").exists(),
        "xattr-only edit copied payload"
    );
    mounted.stop();
    assert!(Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["--commit-overlay", "--yes", "--commit-manifest", "-w"])
        .arg(&overlay)
        .arg(&archive)
        .status()
        .unwrap()
        .success());
    let _mounted = Mount::start(&archive, &mount, None);
    let attr = Command::new("getfattr")
        .args(["--only-values", "-n", "user.train_ok"])
        .arg(mount.join("trace"))
        .output()
        .unwrap();
    assert!(attr.status.success());
    assert_eq!(attr.stdout, b"false");
    assert_eq!(fs::read(mount.join("trace")).unwrap(), b"trace payload");
}
