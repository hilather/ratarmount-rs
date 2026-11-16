#![cfg(target_os = "linux")]
mod common;
#[path = "../../test-harness/child_process.rs"]
mod test_child;
use ratarmount_csi::{
    options,
    process::{mountinfo_contains, ProcessMounter},
    Mounter,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tonic::Status;

#[test]
fn regression_mountinfo_escaped_target_is_not_a_prefix_match() {
    let info = b"1 2 0:3 / /pods/a\\040b\\134c rw - fuse.ratarmount ratarmount rw\n2 3 0:4 / /pods/another rw - tmpfs tmpfs rw\n";
    assert!(mountinfo_contains(info, "/pods/a b\\c"));
    assert!(!mountinfo_contains(info, "/pods/a"));
    assert!(!mountinfo_contains(b"1 2 3 4 /pods/\\777", "/pods/x"));
}

/// Regression: `mount_retrying_spawn` retries one `cannot spawn ratarmount`
/// Internal error and then returns the later success (`calls == 2`).
#[tokio::test]
async fn regression_mount_spawn_retries_once() {
    struct RetryMounter {
        calls: AtomicUsize,
    }

    #[tonic::async_trait]
    impl Mounter for RetryMounter {
        async fn mounted(&self, _: &str) -> Result<bool, Status> {
            Ok(false)
        }
        async fn healthy(&self, _: &str) -> Result<bool, Status> {
            Ok(true)
        }
        async fn mount(
            &self,
            _: &options::MountSpec,
            _: BTreeMap<String, String>,
        ) -> Result<(), Status> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Err(Status::internal("cannot spawn ratarmount"))
            } else {
                Ok(())
            }
        }
        async fn unmount(&self, _: &str) -> Result<(), Status> {
            Ok(())
        }
    }

    let mounter = RetryMounter {
        calls: AtomicUsize::new(0),
    };
    let spec = options::parse(&common::request("/mnt/vol")).unwrap();
    let result = common::mount_retrying_spawn(&mounter, &spec, BTreeMap::new()).await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(mounter.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn regression_child_secret_env_and_exit_are_supervised() {
    let dir = tempfile::tempdir().unwrap();
    // The temporary directory path contains no shell metacharacters.
    let script = common::write_fake_mounter(
        dir.path(),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}/args'\nprintf '%s' \"$HF_TOKEN\" > '{}/token'\nprintf '%s' \"${{NODE_ID-unset}}\" > '{}/inherited'\nexit 7\n",
            dir.path().display(),
            dir.path().display(),
            dir.path().display()
        ),
    );
    let mounter = ProcessMounter::new(script, dir.path().join("overlays"), Duration::from_secs(2));
    let mut req = common::request(dir.path().join("target").to_str().unwrap());
    req.volume_context
        .insert("source".into(), "/dev/null".into());
    let spec = options::parse(&req).unwrap();
    let error = common::mount_retrying_spawn(
        &mounter,
        &spec,
        BTreeMap::from([("HF_TOKEN".into(), "secret-in-env-only".into())]),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(
        error.message(),
        "ratarmount exited before mounting; check source, credentials and FUSE configuration"
    );
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
    let script = common::write_fake_mounter(dir.path(), "#!/bin/sh\nexec sleep 60\n");
    let mounter = ProcessMounter::new(
        script,
        dir.path().join("overlays"),
        Duration::from_millis(40),
    );
    let mut req = common::request(dir.path().join("target").to_str().unwrap());
    req.volume_context
        .insert("source".into(), "/dev/null".into());
    let spec = options::parse(&req).unwrap();
    let err = common::mount_retrying_spawn(&mounter, &spec, BTreeMap::new())
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::DeadlineExceeded);
    assert_eq!(err.message(), "timed out waiting for FUSE mount");
    mounter.unmount(&spec.target).await.unwrap();
    assert!(!mounter.healthy(&spec.target).await.unwrap());
}

/// Set by [`regression_driver_death_kills_owned_child`] for
/// [`parent_exit_helper`] (#310).
const PARENT_EXIT_HELPER_CHILD: &str = "RATARMOUNT_TEST_CSI_PARENT_EXIT_HELPER_CHILD";

/// Helper run in its own process by the parent-death regression below; it
/// skips unless that parent set [`PARENT_EXIT_HELPER_CHILD`].
#[test]
#[ignore = "subprocess helper; invoked by regression_driver_death_kills_owned_child"]
fn parent_exit_helper() {
    if std::env::var_os(PARENT_EXIT_HELPER_CHILD).as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!(
            "skip: parent_exit_helper runs only as a child of \
             regression_driver_death_kills_owned_child ({PARENT_EXIT_HELPER_CHILD}=1 is not set)"
        );
        return;
    }
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
        let _ =
            common::mount_retrying_spawn(&mounter, &options::parse(&req).unwrap(), BTreeMap::new())
                .await;
    });
}

/// Regression: #310 [`parent_exit_helper`] run directly (`cargo test --
/// --ignored`) started a mount outside its parent. Without
/// [`PARENT_EXIT_HELPER_CHILD`] it skips and never runs the fake mounter,
/// although `CSI_HELPER_DIR` names one.
#[test]
fn regression_310_parent_exit_helper_skips_without_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    common::write_fake_mounter(
        dir.path(),
        &format!(
            "#!/bin/sh\necho $$ > '{}/child.pid'\nexit 0\n",
            dir.path().display()
        ),
    );
    let output = test_child::TestChild::spawn(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "parent_exit_helper", "--nocapture"])
            .env_remove(PARENT_EXIT_HELPER_CHILD)
            .env("CSI_HELPER_DIR", dir.path()),
    )
    .unwrap()
    .output(Duration::from_secs(5))
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    assert!(stderr.contains("skip: parent_exit_helper"), "{stderr}");
    assert!(!dir.path().join("child.pid").exists());
    assert!(!dir.path().join("overlays").exists());
}

/// Regression: a killed driver must not leave a credential-bearing daemon alive.
#[test]
fn regression_driver_death_kills_owned_child() {
    let dir = tempfile::tempdir().unwrap();
    common::write_fake_mounter(
        dir.path(),
        &format!(
            "#!/bin/sh\necho $$ > '{}/child.pid'\nexec sleep 60\n",
            dir.path().display()
        ),
    );
    let mut driver = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "parent_exit_helper"])
        .env("CSI_HELPER_DIR", dir.path())
        .env(PARENT_EXIT_HELPER_CHILD, "1")
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
