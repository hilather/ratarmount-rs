//! Real Linux FUSE checks; run outside the worker sandbox.
#![cfg(target_os = "linux")]
mod common;
use ratarmount_csi::{
    csi::{node_server::Node, volume_capability::access_mode::Mode},
    process::ProcessMounter,
    Driver,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tonic::Request;

fn fixture_tar() -> Vec<u8> {
    let mut tar = vec![0; 2048];
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
    let sum: u32 = tar[..512].iter().map(|b| u32::from(*b)).sum();
    tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    tar[512..518].copy_from_slice(b"hello\n");
    tar
}

/// Regression: two pods must see private writes and preserve the read-only base.
#[tokio::test]
async fn regression_real_fuse_readonly_and_private_overlay_targets() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable; run outside sandbox");
        return;
    }
    if unsafe { libc::geteuid() } != 0
        && !fs::read_to_string("/etc/fuse.conf")
            .unwrap_or_default()
            .lines()
            .any(|s| s.trim() == "user_allow_other")
    {
        eprintln!("skip: enable user_allow_other in /etc/fuse.conf");
        return;
    }
    if std::process::Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: fusermount3 unavailable");
        return;
    }
    let binary = std::env::var_os("RATARMOUNT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug/ratarmount")
        });
    if !binary.is_file() {
        eprintln!("skip: build ratarmount or set RATARMOUNT_BIN");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let overlays = match tempfile::tempdir_in("/dev/shm") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skip: writable /dev/shm required for RAM overlays");
            return;
        }
    };
    let source = dir.path().join("base.tar");
    fs::write(&source, fixture_tar()).unwrap();
    let mounter = Arc::new(ProcessMounter::new(
        binary,
        overlays.path().join("overlays"),
        Duration::from_secs(30),
    ));
    let driver = Driver::open(
        "node".into(),
        &dir.path().join("state"),
        dir.path(),
        mounter,
    )
    .await
    .unwrap();
    let result: Result<(), Box<dyn std::error::Error>> = async {
        for pod in ["ro", "a", "b"] {
            let mut request = common::request(dir.path().join(pod).to_str().unwrap());
            request
                .volume_context
                .insert("source".into(), source.to_str().unwrap().into());
            if pod != "ro" {
                request.readonly = false;
                request
                    .volume_capability
                    .as_mut()
                    .unwrap()
                    .access_mode
                    .as_mut()
                    .unwrap()
                    .mode = Mode::MultiNodeMultiWriter as i32;
                request
                    .volume_context
                    .insert("overlay".into(), "tmpfs:8M".into());
            }
            driver.node_publish_volume(Request::new(request)).await?;
            if fs::read(dir.path().join(pod).join("payload.txt"))? != b"hello\n" {
                return Err("wrong mounted bytes".into());
            }
        }
        if fs::write(dir.path().join("ro/new"), b"refused")
            .err()
            .and_then(|error| error.raw_os_error())
            != Some(libc::EROFS)
        {
            return Err("RO mount did not return EROFS".into());
        }
        fs::write(dir.path().join("a/payload.txt"), b"private")?;
        fs::write(dir.path().join("a/new"), b"private")?;
        if fs::read(dir.path().join("b/payload.txt"))? != b"hello\n"
            || dir.path().join("b/new").exists()
        {
            return Err("overlay leaked between pods".into());
        }
        Ok(())
    }
    .await;
    let cleanup = driver.shutdown().await;
    result.unwrap();
    cleanup.unwrap();
    assert_eq!(fs::read(&source).unwrap(), fixture_tar());
    assert_eq!(
        fs::read_dir(overlays.path().join("overlays"))
            .unwrap()
            .count(),
        0
    );
    assert!(!dir.path().join("a").exists());
}
