#![cfg(target_os = "linux")]
mod common;
use common::*;
use ratarmount_csi::{
    csi::{node_server::Node, *},
    options, Driver,
};
use std::sync::{atomic::Ordering, Arc};
use tonic::{Code, Request};

#[test]
fn regression_invalid_request_cannot_become_cli_arguments() {
    let good = request("/pods/a/mount");
    assert!(options::parse(&good).is_ok());
    for key in [
        "uid",
        "gid",
        "umask",
        "recursive",
        "gitSyntheticHead",
        "passthrough",
        "overlay",
        "quota",
        "AWS_SECRET_ACCESS_KEY",
        "unknown",
    ] {
        let mut bad = good.clone();
        bad.volume_context
            .insert(key.into(), "--password=secret".into());
        assert_eq!(
            options::parse(&bad).unwrap_err().code(),
            Code::InvalidArgument,
            "{key}"
        );
    }
    for target in [
        "",
        "/",
        "relative",
        "/pods/../mount",
        "/pods//mount",
        "/pods/./mount",
        "/pods/mount/",
        "/pods/\0mount",
    ] {
        let mut bad = good.clone();
        bad.target_path = target.into();
        assert_eq!(
            options::parse(&bad).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    for source in [
        "",
        "--foo",
        "https://user:secret@example.org/a",
        "https://example.org/a?token=secret",
    ] {
        let mut bad = good.clone();
        bad.volume_context.insert("source".into(), source.into());
        assert_eq!(
            options::parse(&bad).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    let mut bad = good.clone();
    bad.volume_capability = None;
    assert_eq!(
        options::parse(&bad).unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut bad = good.clone();
    bad.volume_id.clear();
    assert_eq!(
        options::parse(&bad).unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut bad = good;
    bad.volume_capability.as_mut().unwrap().access_type = Some(
        volume_capability::AccessType::Block(volume_capability::BlockVolume {}),
    );
    assert_eq!(
        options::parse(&bad).unwrap_err().code(),
        Code::InvalidArgument
    );
}

#[test]
fn regression_secrets_never_enter_argv_or_serialized_spec() {
    let mut req = request("/pods/a/mount");
    req.secrets.insert("HF_TOKEN".into(), "super-secret".into());
    let spec = options::parse(&req).unwrap();
    assert!(!format!("{spec:?}").contains("super-secret"));
    assert!(!serde_json::to_string(&spec)
        .unwrap()
        .contains("super-secret"));
    assert_eq!(
        options::secret_env(&req.secrets).unwrap()["HF_TOKEN"],
        "super-secret"
    );
    for name in [
        "LD_PRELOAD",
        "PATH",
        "AWS_CONFIG_FILE",
        "RATARMOUNT_LOG_FILE",
        "HF_TOKEN\0",
    ] {
        req.secrets.insert(name.into(), "secret".into());
        assert_eq!(
            options::parse(&req).unwrap_err().code(),
            Code::InvalidArgument
        );
        req.secrets.remove(name);
    }
}

#[test]
fn regression_readonly_and_overlay_policy_are_honored() {
    let mut req = request("/pods/a/mount");
    req.readonly = false;
    assert!(options::parse(&req)
        .unwrap()
        .args
        .contains(&"allow_other,ro".into()));
    req.volume_context
        .insert("overlay".into(), "tmpfs:2G".into());
    assert!(options::parse(&req).is_err());
    req.volume_capability
        .as_mut()
        .unwrap()
        .access_mode
        .as_mut()
        .unwrap()
        .mode = volume_capability::access_mode::Mode::MultiNodeMultiWriter as i32;
    req.volume_context.extend([
        ("quota".into(), "1G".into()),
        ("readonlyGlobs".into(), "tests/**,data/**".into()),
        ("uid".into(), "1000".into()),
        ("gid".into(), "1001".into()),
        ("umask".into(), "022".into()),
        ("recursive".into(), "true".into()),
        ("gitSyntheticHead".into(), "true".into()),
        ("passthrough".into(), "auto".into()),
    ]);
    let args = options::parse(&req).unwrap().args;
    for flag in [
        "--foreground",
        "--overlay-tmpfs=2G",
        "--overlay-quota=1G",
        "--overlay-readonly=tests/**,data/**",
        "allow_other,rw,uid=1000,gid=1001,umask=022",
        "--recursive",
        "--git-synthetic-head",
        "--passthrough=auto",
    ] {
        assert!(args.contains(&flag.into()), "{flag}");
    }
    assert_eq!(
        &args[args.len() - 3..],
        &["--", "/fixtures/data.tar", "/pods/a/mount"]
    );
    req.readonly = true;
    assert!(options::parse(&req)
        .unwrap()
        .args
        .iter()
        .any(|a| a.starts_with("allow_other,ro")));
    for size in ["", "1GB", "-1", "18446744073709551615T", "1KK"] {
        req.volume_context.insert("quota".into(), size.into());
        assert!(options::parse(&req).is_err());
    }
}

#[tokio::test]
async fn regression_idempotent_publish_conflicts_and_per_pod_targets() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(FakeMounter::default());
    let driver = Driver::open(
        "node".into(),
        &dir.path().join("state"),
        dir.path(),
        fake.clone(),
    )
    .await
    .unwrap();
    let target = dir.path().join("pod-a").to_str().unwrap().to_string();
    let req = request(&target);
    driver
        .node_publish_volume(Request::new(req.clone()))
        .await
        .unwrap();
    driver
        .node_publish_volume(Request::new(req.clone()))
        .await
        .unwrap();
    assert_eq!(fake.publishes.load(Ordering::SeqCst), 1);
    let mut changed = req.clone();
    changed
        .volume_context
        .insert("recursive".into(), "true".into());
    assert_eq!(
        driver
            .node_publish_volume(Request::new(changed))
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    let mut other = req.clone();
    other.target_path = dir.path().join("pod-b").to_str().unwrap().into();
    driver
        .node_publish_volume(Request::new(other))
        .await
        .unwrap();
    assert_eq!(fake.publishes.load(Ordering::SeqCst), 2);
    assert_eq!(
        driver
            .node_unpublish_volume(Request::new(NodeUnpublishVolumeRequest {
                volume_id: "wrong".into(),
                target_path: target.clone()
            }))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    for _ in 0..2 {
        driver
            .node_unpublish_volume(Request::new(NodeUnpublishVolumeRequest {
                volume_id: req.volume_id.clone(),
                target_path: target.clone(),
            }))
            .await
            .unwrap();
    }
    assert!(!std::path::Path::new(&target).exists());
    driver.shutdown().await.unwrap();
}

#[tokio::test]
async fn regression_journal_restart_cleans_mounts_without_persisting_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let fake = Arc::new(FakeMounter::default());
    let driver = Driver::open("node".into(), &state, dir.path(), fake.clone())
        .await
        .unwrap();
    let target = dir.path().join("pod").to_str().unwrap().to_string();
    let mut req = request(&target);
    req.secrets
        .insert("HF_TOKEN".into(), "do-not-persist".into());
    driver
        .node_publish_volume(Request::new(req.clone()))
        .await
        .unwrap();
    assert_eq!(fake.env.lock().unwrap()["HF_TOKEN"], "do-not-persist");
    assert!(!std::fs::read_to_string(state.join("journal.json"))
        .unwrap()
        .contains("do-not-persist"));
    assert!(
        Driver::open("node".into(), &state, dir.path(), fake.clone())
            .await
            .is_err()
    );
    drop(driver);
    let recovered = Driver::open("node".into(), &state, dir.path(), fake.clone())
        .await
        .unwrap();
    assert!(fake.mounts.lock().unwrap().is_empty());
    recovered
        .node_publish_volume(Request::new(req))
        .await
        .unwrap();
    assert_eq!(fake.publishes.load(Ordering::SeqCst), 2);
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn regression_failed_publish_and_failed_cleanup_recover_from_intent() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let fake = Arc::new(FakeMounter::default());
    fake.fail_mount.store(true, Ordering::SeqCst);
    fake.fail_unmount.store(true, Ordering::SeqCst);
    let driver = Driver::open("node".into(), &state, dir.path(), fake.clone())
        .await
        .unwrap();
    let req = request(dir.path().join("pod").to_str().unwrap());
    assert!(driver
        .node_publish_volume(Request::new(req.clone()))
        .await
        .is_err());
    let bytes = std::fs::read_to_string(state.join("journal.json")).unwrap();
    assert!(bytes.contains("\"ready\":false"));
    drop(driver);
    assert!(
        Driver::open("node".into(), &state, dir.path(), fake.clone())
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(state.join("journal.json")).unwrap(),
        bytes
    );
    fake.fail_unmount.store(false, Ordering::SeqCst);
    fake.fail_mount.store(false, Ordering::SeqCst);
    let driver = Driver::open("node".into(), &state, dir.path(), fake.clone())
        .await
        .unwrap();
    driver.node_publish_volume(Request::new(req)).await.unwrap();
    driver.shutdown().await.unwrap();
}

#[tokio::test]
async fn regression_child_crash_requires_explicit_republish() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(FakeMounter::default());
    let driver = Driver::open(
        "node".into(),
        &dir.path().join("state"),
        dir.path(),
        fake.clone(),
    )
    .await
    .unwrap();
    let req = request(dir.path().join("pod").to_str().unwrap());
    driver
        .node_publish_volume(Request::new(req.clone()))
        .await
        .unwrap();
    fake.mounts.lock().unwrap().clear();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert_eq!(fake.publishes.load(Ordering::SeqCst), 1);
    driver.node_publish_volume(Request::new(req)).await.unwrap();
    assert_eq!(fake.publishes.load(Ordering::SeqCst), 2);
    driver.shutdown().await.unwrap();
}

#[tokio::test]
async fn regression_unknown_mount_and_symlink_targets_are_not_modified() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(FakeMounter::default());
    let driver = Driver::open(
        "node".into(),
        &dir.path().join("state"),
        dir.path(),
        fake.clone(),
    )
    .await
    .unwrap();
    let target = dir.path().join("unowned").to_str().unwrap().to_string();
    fake.mounts.lock().unwrap().insert(target.clone());
    assert_eq!(
        driver
            .node_publish_volume(Request::new(request(&target)))
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert!(driver
        .node_unpublish_volume(Request::new(NodeUnpublishVolumeRequest {
            volume_id: "fixture".into(),
            target_path: target
        }))
        .await
        .is_err());
    std::os::unix::fs::symlink("/tmp", dir.path().join("link")).unwrap();
    assert!(driver
        .node_publish_volume(Request::new(request(
            dir.path().join("link/mount").to_str().unwrap()
        )))
        .await
        .is_err());
    assert!(driver
        .node_publish_volume(Request::new(request("/elsewhere/mount")))
        .await
        .is_err());
    assert_eq!(fake.unpublishes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn regression_corrupt_journal_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("journal.json"), b"broken").unwrap();
    assert!(Driver::open(
        "node".into(),
        dir.path(),
        dir.path(),
        Arc::new(FakeMounter::default())
    )
    .await
    .is_err());
    assert_eq!(
        std::fs::read(dir.path().join("journal.json")).unwrap(),
        b"broken"
    );
}

#[tokio::test]
async fn regression_shutdown_and_overlapping_targets_cannot_start_new_mounts() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(FakeMounter::default());
    let driver = Driver::open(
        "node".into(),
        &dir.path().join("state"),
        dir.path(),
        fake.clone(),
    )
    .await
    .unwrap();
    let first = request(dir.path().join("pod").to_str().unwrap());
    driver
        .node_publish_volume(Request::new(first.clone()))
        .await
        .unwrap();
    let nested = request(dir.path().join("pod/nested").to_str().unwrap());
    assert_eq!(
        driver
            .node_publish_volume(Request::new(nested))
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    let state = request(dir.path().join("state/mount").to_str().unwrap());
    assert_eq!(
        driver
            .node_publish_volume(Request::new(state))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    driver.shutdown().await.unwrap();
    assert_eq!(
        driver
            .node_publish_volume(Request::new(first))
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert!(fake.mounts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn regression_cancelled_rpc_finishes_journaled_publish() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(FakeMounter::default());
    fake.pause_mount.store(true, Ordering::SeqCst);
    let driver = Driver::open(
        "node".into(),
        &dir.path().join("state"),
        dir.path(),
        fake.clone(),
    )
    .await
    .unwrap();
    let req = request(dir.path().join("pod").to_str().unwrap());
    let cloned = driver.clone();
    let first = req.clone();
    let rpc = tokio::spawn(async move { cloned.node_publish_volume(Request::new(first)).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), fake.entered.notified())
        .await
        .unwrap();
    rpc.abort();
    let _ = rpc.await;
    fake.resume.notify_one();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        driver.node_publish_volume(Request::new(req)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fake.publishes.load(Ordering::SeqCst), 1);
    assert!(
        std::fs::read_to_string(dir.path().join("state/journal.json"))
            .unwrap()
            .contains("\"ready\":true")
    );
    driver.shutdown().await.unwrap();
}

#[tokio::test]
async fn regression_unpublish_preserves_preexisting_directory() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(FakeMounter::default());
    let driver = Driver::open("node".into(), &dir.path().join("state"), dir.path(), fake)
        .await
        .unwrap();
    let target = dir.path().join("pod");
    std::fs::create_dir(&target).unwrap();
    driver
        .node_publish_volume(Request::new(request(target.to_str().unwrap())))
        .await
        .unwrap();
    driver.shutdown().await.unwrap();
    assert!(target.is_dir());
}
