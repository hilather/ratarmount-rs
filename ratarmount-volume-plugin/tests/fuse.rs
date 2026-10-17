//! Run outside the worker sandbox with RATARMOUNT_BIN pointing to a built CLI.
#![cfg(target_os = "linux")]

use ratarmount_volume_plugin::{process::ProcessMounter, Driver};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn small_tar() -> Vec<u8> {
    let mut tar = vec![0u8; 2048];
    tar[..11].copy_from_slice(b"payload.txt");
    tar[100..108].copy_from_slice(b"0000644\0");
    tar[108..116].copy_from_slice(b"0000000\0");
    tar[116..124].copy_from_slice(b"0000000\0");
    tar[124..136].copy_from_slice(b"00000000006\0");
    tar[136..148].copy_from_slice(b"00000000000\0");
    tar[148..156].fill(b' ');
    tar[156] = b'0';
    tar[257..263].copy_from_slice(b"ustar\0");
    tar[263..265].copy_from_slice(b"00");
    let checksum: u32 = tar[..512].iter().map(|b| u32::from(*b)).sum();
    tar[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    tar[512..518].copy_from_slice(b"hello\n");
    tar
}

/// Regression: a real mounted tar must remain readable until the final container ID unmounts.
#[test]
fn regression_real_tar_mount_refcounts_and_readonly() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!(
            "skip: /dev/fuse is unavailable; orchestrator must run this test outside the sandbox"
        );
        return;
    }
    if !fs::read_to_string("/etc/fuse.conf")
        .unwrap_or_default()
        .lines()
        .any(|line| line.trim() == "user_allow_other")
    {
        eprintln!("skip: enable user_allow_other in /etc/fuse.conf for container access");
        return;
    }
    let binary = std::env::var_os("RATARMOUNT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug/ratarmount")
        });
    if !binary.is_file() {
        eprintln!("skip: build the ratarmount CLI or set RATARMOUNT_BIN");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("source.tar");
    fs::write(&archive, small_tar()).unwrap();
    let mut driver = Driver::open(
        &dir.path().join("state"),
        ProcessMounter::new(binary, Duration::from_secs(30)),
    )
    .unwrap();
    let create = driver.handle(
        "/VolumeDriver.Create",
        &serde_json::to_vec(&json!({"Name":"data", "Opts":{"source":archive.to_str().unwrap()}}))
            .unwrap(),
    );
    assert_eq!(create["Err"], "", "{create}");
    for id in ["one", "one", "two"] {
        let response = driver.handle(
            "/VolumeDriver.Mount",
            &serde_json::to_vec(&json!({"Name":"data", "ID":id})).unwrap(),
        );
        assert_eq!(response["Err"], "", "{response}");
    }
    let mountpoint = dir.path().join("state/mnt/data");
    assert_eq!(
        fs::read(mountpoint.join("payload.txt")).unwrap(),
        b"hello\n"
    );
    assert_eq!(
        fs::write(mountpoint.join("new.txt"), b"refused")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    for id in ["one", "two"] {
        let response = driver.handle(
            "/VolumeDriver.Unmount",
            &serde_json::to_vec(&json!({"Name":"data", "ID":id})).unwrap(),
        );
        assert_eq!(response["Err"], "", "{response}");
        if id == "one" {
            assert_eq!(
                fs::read(mountpoint.join("payload.txt")).unwrap(),
                b"hello\n"
            );
        }
    }
    assert!(!ratarmount_volume_plugin::process::is_mounted(&mountpoint).unwrap());
}
