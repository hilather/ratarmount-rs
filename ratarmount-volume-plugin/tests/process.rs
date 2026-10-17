#![cfg(target_os = "linux")]

use ratarmount_volume_plugin::{
    options::Options,
    process::{mountpoints, ProcessMounter},
    Mounter,
};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

/// Regression: mount readiness must compare decoded exact mountinfo paths, not substrings.
#[test]
fn regression_mountinfo_escaped_paths_and_sibling_prefixes() {
    let info = b"40 2 0:4 / /state/mnt/a\\040b rw - fuse.ratarmount ratarmount rw\n41 2 0:4 / /state/mnt/ab rw - fuse.ratarmount ratarmount rw\n42 2 0:4 / /state/mnt/c\\134d rw - fuse.ratarmount x rw\n";
    assert_eq!(
        mountpoints(info),
        vec![
            PathBuf::from("/state/mnt/a b"),
            PathBuf::from("/state/mnt/ab"),
            PathBuf::from("/state/mnt/c\\d")
        ]
    );
    assert!(!mountpoints(info).contains(&PathBuf::from("/state/mnt/a")));
}

/// Regression: an exited child and a timed-out indexer must be reaped without a FUSE device.
#[test]
fn regression_real_child_early_exit_and_timeout_are_reaped() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-ratarmount");
    let pid_file = dir.path().join("pid");
    let mountpoint = dir.path().join("mnt");
    fs::create_dir(&mountpoint).unwrap();
    let opts: Options = BTreeMap::from([("source".into(), "a.tar".into())]);
    for body in ["exit 1", "exec sleep 30"] {
        fs::write(
            &script,
            format!("#!/bin/sh\necho $$ > '{}'\n{body}\n", pid_file.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let mut mounter = ProcessMounter::new(script.clone(), Duration::from_millis(200));
        assert!(mounter.mount(&opts, &mountpoint).is_err());
        assert!(!mounter.alive(&mountpoint).unwrap());
        let pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal 0 only probes whether this test's child still exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}
