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
        Self::start_with(archive, mount, overlay, None)
    }

    fn start_with(
        archive: &Path,
        mount: &Path,
        overlay: Option<&Path>,
        options: Option<&str>,
    ) -> Self {
        fs::create_dir_all(mount).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.args(["-f", "--passthrough", "off"]);
        if let Some(overlay) = overlay {
            cmd.arg("-w").arg(overlay);
        }
        if let Some(options) = options {
            cmd.args(["-o", options]);
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

#[test]
fn regression_fuse_setattr_mode_build_and_execute() {
    if !fuse_available() {
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

fn sh(mount: &Path, script: &str) -> std::process::Output {
    Command::new("sh")
        .current_dir(mount)
        .args(["-c", script])
        .output()
        .unwrap()
}

/// Regression (#327): `cp -p` and `sed -i` preserve ownership with a chown
/// to the owner already shown, and copy the POSIX ACL. Both failed with EPERM
/// (`cp -p` as root exited 1; `sed -i` warned "preserving permissions").
/// Every case runs as the caller; a chown from a root `--cap-drop ALL`
/// container takes the same daemon path because the mount has no
/// `default_permissions`, so the "root" presentation stands in for it.
#[test]
fn regression_fuse_same_owner_chown_cp_p_and_sed_i() {
    if !fuse_available() {
        return;
    }
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    for (label, options, shown) in [
        ("caller", format!("uid={uid},gid={gid}"), (uid, gid)),
        ("root", "uid=0,gid=0".to_owned(), (0, 0)),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        let overlay = dir.path().join("overlay");
        let mount = dir.path().join("mnt");
        let mut tar = Vec::new();
        ratarmount_formats_tar::write_ustar_members(
            &mut tar,
            &[ratarmount_formats_tar::UstarMember {
                path: "trace",
                payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"xxx\n" },
                mode: 0o644,
                uid: 1234,
                gid: 1234,
                mtime: 0,
                xattrs: &[],
            }],
        )
        .unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut tar).unwrap();
        fs::write(&archive, tar).unwrap();
        let _mounted = Mount::start_with(&archive, &mount, Some(&overlay), Some(&options));
        // The same chown `cp -p` makes as root, run as the caller.
        let out = sh(&mount, &format!("chown {}:{} trace", shown.0, shown.1));
        assert!(
            out.status.success(),
            "{label}: same-owner chown: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = sh(&mount, "cp -p trace b && cp -p b trace && cat trace");
        assert!(
            out.status.success(),
            "{label}: cp -p round trip: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"xxx\n", "{label}");
        let out = sh(&mount, "sed -i s/x/y/ trace && cat trace");
        assert!(out.status.success(), "{label}: sed -i");
        // The kernel itself refuses an ACL set by a caller that is not the
        // presented owner (no CAP_FOWNER) before FUSE sees it, so the quiet
        // EOPNOTSUPP fallback is only reachable when the caller is shown as owner.
        if shown == (uid, gid) {
            assert_eq!(
                String::from_utf8_lossy(&out.stderr),
                "",
                "{label}: sed -i warned"
            );
        }
        assert_eq!(out.stdout, b"yxx\n", "{label}");
        // A real ownership change is still refused.
        let other = shown.0.wrapping_add(1);
        let out = sh(&mount, &format!("chown {other} trace"));
        assert!(!out.status.success(), "{label}: chown to another uid");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Operation not permitted"),
            "{label}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Regression (#316): mkdir of an existing name inside a `-w` mount must
/// fail with EEXIST and leave the directory's mode alone, for an archive
/// directory, an overlay directory and an archive file. (The kernel usually
/// answers from its own LOOKUP; the daemon path is pinned by the
/// `ratarmount-fuse` unit test `regression_316_mkdir_existing_is_eexist`.)
#[test]
fn regression_316_fuse_mkdir_existing_is_eexist() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !fuse_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    let overlay = dir.path().join("overlay");
    let mount = dir.path().join("mnt");
    let mut tar = Vec::new();
    let member = |path, payload, mode| ratarmount_formats_tar::UstarMember {
        path,
        payload,
        mode,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: &[],
    };
    ratarmount_formats_tar::write_ustar_members(
        &mut tar,
        &[
            member(
                "trace",
                ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
                0o644,
            ),
            member(
                "basedir",
                ratarmount_formats_tar::UstarPayload::Directory,
                0o750,
            ),
        ],
    )
    .unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut tar).unwrap();
    fs::write(&archive, tar).unwrap();
    let _mounted = Mount::start(&archive, &mount, Some(&overlay));
    fs::DirBuilder::new()
        .mode(0o750)
        .create(mount.join("made"))
        .unwrap();
    let mode = |name: &str| fs::metadata(mount.join(name)).unwrap().permissions().mode();
    for name in ["basedir", "made", "trace"] {
        let before = mode(name);
        let err = fs::DirBuilder::new()
            .mode(0o700)
            .create(mount.join(name))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST), "{name}: {err}");
        assert_eq!(mode(name), before, "{name}");
    }
    assert_eq!(mode("basedir") & 0o7777, 0o750);
    assert!(fs::metadata(mount.join("trace")).unwrap().is_file());
}
