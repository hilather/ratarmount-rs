#![cfg(target_os = "linux")]
mod common;
use ratarmount_csi::{
    options,
    process::{mountinfo_contains, ProcessMounter},
    Mounter,
};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

#[test]
fn regression_mountinfo_escaped_target_is_not_a_prefix_match() {
    let info = b"1 2 0:3 / /pods/a\\040b\\134c rw - fuse.ratarmount ratarmount rw\n2 3 0:4 / /pods/another rw - tmpfs tmpfs rw\n";
    assert!(mountinfo_contains(info, "/pods/a b\\c"));
    assert!(!mountinfo_contains(info, "/pods/a"));
    assert!(!mountinfo_contains(b"1 2 3 4 /pods/\\777", "/pods/x"));
}

#[tokio::test]
async fn regression_child_secret_env_and_exit_are_supervised() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-mounter");
    // The temporary directory path contains no shell metacharacters.
    std::fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}/args'\nprintf '%s' \"$HF_TOKEN\" > '{}/token'\nprintf '%s' \"${{NODE_ID-unset}}\" > '{}/inherited'\nexit 7\n", dir.path().display(), dir.path().display(), dir.path().display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mounter = ProcessMounter::new(script, dir.path().join("overlays"), Duration::from_secs(2));
    let mut req = common::request(dir.path().join("target").to_str().unwrap());
    req.volume_context
        .insert("source".into(), "/dev/null".into());
    let spec = options::parse(&req).unwrap();
    let error = mounter
        .mount(
            &spec,
            BTreeMap::from([("HF_TOKEN".into(), "secret-in-env-only".into())]),
        )
        .await
        .unwrap_err();
    assert!(!error.message().contains("secret-in-env-only"));
    assert!(!std::fs::read_to_string(dir.path().join("args"))
        .unwrap()
        .contains("secret-in-env-only"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("token")).unwrap(),
        "secret-in-env-only"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("inherited")).unwrap(),
        "unset"
    );
    assert!(!mounter.healthy(&spec.target).await.unwrap());
    mounter.unmount(&spec.target).await.unwrap();
}

#[tokio::test]
async fn regression_mount_timeout_stops_the_child() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-mounter");
    std::fs::write(&script, "#!/bin/sh\nexec sleep 60\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mounter = ProcessMounter::new(
        script,
        dir.path().join("overlays"),
        Duration::from_millis(40),
    );
    let mut req = common::request(dir.path().join("target").to_str().unwrap());
    req.volume_context
        .insert("source".into(), "/dev/null".into());
    let spec = options::parse(&req).unwrap();
    assert_eq!(
        mounter
            .mount(&spec, BTreeMap::new())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::DeadlineExceeded
    );
    mounter.unmount(&spec.target).await.unwrap();
    assert!(!mounter.healthy(&spec.target).await.unwrap());
}

/// Helper run in its own process by the parent-death regression below.
#[test]
#[ignore = "subprocess helper; invoked by regression_driver_death_kills_owned_child"]
fn parent_exit_helper() {
    let dir = std::path::PathBuf::from(std::env::var_os("CSI_HELPER_DIR").unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mounter = ProcessMounter::new(
            dir.join("fake-mounter"),
            dir.join("overlays"),
            Duration::from_secs(60),
        );
        let mut req = common::request(dir.join("mount").to_str().unwrap());
        req.volume_context
            .insert("source".into(), "/dev/null".into());
        let _ = mounter
            .mount(&options::parse(&req).unwrap(), BTreeMap::new())
            .await;
    });
}

/// Regression: a killed driver must not leave a credential-bearing daemon alive.
#[test]
fn regression_driver_death_kills_owned_child() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-mounter");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho $$ > '{}/child.pid'\nexec sleep 60\n",
            dir.path().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut driver = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "parent_exit_helper"])
        .env("CSI_HELPER_DIR", dir.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Ok(text) = std::fs::read_to_string(dir.path().join("child.pid")) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                break Some(pid);
            }
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    driver.kill().unwrap();
    driver.wait().unwrap();
    let pid = pid.expect("helper failed to spawn its child");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        if stat.is_err() || stat.unwrap().split_whitespace().nth(2) == Some("Z") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "child survived its driver"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[tokio::test]
async fn regression_missing_local_base_is_not_created_by_write_mount() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("missing.tar");
    let mounter = ProcessMounter::new(
        "/bin/false".into(),
        dir.path().join("overlays"),
        Duration::from_secs(1),
    );
    let mut request = common::request(dir.path().join("target").to_str().unwrap());
    request
        .volume_context
        .insert("source".into(), source.to_str().unwrap().into());
    request
        .volume_context
        .insert("overlay".into(), "tmpfs".into());
    let error = mounter
        .mount(&options::parse(&request).unwrap(), BTreeMap::new())
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    assert!(!source.exists());
}
