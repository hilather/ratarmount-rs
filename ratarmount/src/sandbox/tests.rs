use super::*;
use daemon::{SocketGuard, Supervisor};
use process::{MountState, Mounter};
use protocol::{ApiError, Attempt, Base};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};

fn private_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

#[derive(Default)]
struct FakeState {
    mounts: BTreeMap<PathBuf, MountState>,
    fail_spawn: Option<usize>,
    spawns: usize,
    first_poll_spawns: Option<usize>,
    stuck: bool,
    refuse_cleanup: bool,
    inspection: bool,
    cleaned: Vec<PathBuf>,
    policies: Vec<(Option<u64>, Vec<String>)>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<FakeState>>);

impl Mounter for Fake {
    fn prepare(&mut self, _: &Base, _: &Path, _: Duration) -> Result<(), ApiError> {
        Ok(())
    }
    fn spawn(
        &mut self,
        _: &Base,
        _: &Path,
        attempt: &Attempt,
        quota: Option<u64>,
        readonly: &[String],
    ) -> Result<(), ApiError> {
        let mut state = self.0.lock().unwrap();
        state.spawns += 1;
        if state.fail_spawn == Some(state.spawns) {
            return Err(ApiError::new("spawn_failed", "injected"));
        }
        let status = if state.stuck {
            MountState::Starting
        } else {
            MountState::Ready
        };
        state.mounts.insert(attempt.path.clone(), status);
        state.policies.push((quota, readonly.into()));
        Ok(())
    }
    fn poll(&mut self, attempt: &Attempt) -> Result<MountState, ApiError> {
        let mut state = self.0.lock().unwrap();
        if state.first_poll_spawns.is_none() {
            state.first_poll_spawns = Some(state.spawns);
        }
        Ok(state
            .mounts
            .get(&attempt.path)
            .copied()
            .unwrap_or(MountState::Crashed))
    }
    fn deleted_paths(&mut self, attempt: &Attempt) -> Result<Option<Vec<String>>, ApiError> {
        if self.0.lock().unwrap().inspection {
            super::inspection::deleted_paths(attempt)
                .map(Some)
                .map_err(Into::into)
        } else {
            Ok(Some(Vec::new()))
        }
    }

    fn cleanup(&mut self, path: &Path) -> Result<(), ApiError> {
        let mut state = self.0.lock().unwrap();
        if state.refuse_cleanup {
            return Err(ApiError::new("unmount_failed", "injected"));
        }
        state.mounts.remove(path);
        state.cleaned.push(path.into());
        Ok(())
    }
}

fn setup(limit: usize) -> (tempfile::TempDir, Supervisor<Fake>, Fake) {
    let root = private_tempdir();
    let fake = Fake::default();
    let mut supervisor =
        Supervisor::open(root.path(), limit, Duration::from_millis(250), fake.clone()).unwrap();
    supervisor
        .handle(Operation::CreateBase {
            name: "task".into(),
            source: "/fake.tar".into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    (root, supervisor, fake)
}
fn new(count: usize) -> Operation {
    Operation::New {
        base: "task".into(),
        count,
        overlay: Overlay::Disk,
        quota: None,
        readonly_globs: vec![],
    }
}

/// Regression: version negotiation, unknown fields and invalid JSON return structured errors.
#[test]
fn regression_protocol_rejects_unknown_fields_and_versions() {
    for line in [r#"{}"#, r#"{"version":2,"op":"list"}"#] {
        assert_eq!(
            Request::parse(line.as_bytes()).unwrap_err().code,
            "unsupported_version"
        );
    }
    for line in [
        r#"{"version":1,"op":"list","typo":true}"#,
        r#"{"version":1,"op":"unknown"}"#,
        "{",
        r#"{"version":1,"op":"create_base","name":"a","source":"x","options":{"bad":true}}"#,
    ] {
        let response = Response::from_result(Request::parse(line.as_bytes()).map(|_| json!(null)));
        assert!(!response.ok);
        let encoded = serde_json::to_vec(&response).unwrap();
        let decoded: Response = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.error.unwrap().code, "invalid_request");
    }
    for operation in [
        new(8),
        Operation::Shutdown,
        Operation::Destroy {
            id: Some("a".into()),
            base: None,
        },
        Operation::Diff {
            id: "b".into(),
            git: true,
        },
        Operation::Stats { id: "b".into() },
    ] {
        let request = Request {
            version: VERSION,
            operation,
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let parsed = Request::parse(&bytes).unwrap();
        assert_eq!(
            serde_json::to_value(parsed).unwrap(),
            serde_json::to_value(request).unwrap()
        );
    }
}

/// Regression: sandbox verb does not consume the existing --sandbox preset or mount positionals.
#[test]
fn regression_sandbox_verb_preserves_mount_preset() {
    let args = crate::parse_args_from([
        "ratarmount",
        "sandbox",
        "new",
        "--socket",
        "/tmp/api",
        "task",
        "--count",
        "8",
    ])
    .unwrap();
    assert!(matches!(
        args.sandbox_api.unwrap().command,
        Command::New { count: 8, .. }
    ));
    let mount = crate::parse_args_from(["ratarmount", "--sandbox", "source.tar", "mnt"]).unwrap();
    assert!(mount.sandbox && mount.sandbox_api.is_none());
    for tail in [
        vec!["destroy"],
        vec!["destroy", "a", "--base", "b"],
        vec!["daemon", "--state-dir", "state", "--max-attempts", "0"],
    ] {
        assert!(SandboxArgs::try_parse_from(
            ["sandbox", "--socket", "/tmp/sock"].into_iter().chain(tail)
        )
        .is_err());
    }
}

/// Regression: batch mounts start together, use unique overlays, and respect capacity including crashed attempts.
#[test]
fn regression_batch_parallel_start_and_capacity() {
    let (_root, mut supervisor, fake) = setup(8);
    let result = supervisor.handle(new(8)).unwrap();
    assert_eq!(result.as_array().unwrap().len(), 8);
    assert_eq!(fake.0.lock().unwrap().first_poll_spawns, Some(8));
    for attempt in supervisor.attempts.values() {
        assert_eq!(
            fs::metadata(attempt.path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
    }
    let overlays: BTreeSet<_> = supervisor
        .attempts
        .values()
        .map(|a| &a.overlay_dir)
        .collect();
    assert_eq!(overlays.len(), 8);
    assert_eq!(supervisor.handle(new(1)).unwrap_err().code, "capacity");
    assert_eq!(supervisor.handle(new(0)).unwrap_err().code, "capacity");
    supervisor
        .handle(Operation::Destroy {
            base: Some("task".into()),
            id: None,
        })
        .unwrap();
    assert!(supervisor.attempts.is_empty());
    assert_eq!(
        fs::read_dir(supervisor.root.join("attempts"))
            .unwrap()
            .count(),
        0
    );
    supervisor.handle(new(1)).unwrap(); // destroying a base's attempts retains the registered base
    supervisor.handle(Operation::Shutdown).unwrap();
    assert!(supervisor.stopping);
}

/// Regression: one exited mount remains inspectable as crashed while siblings keep serving.
#[test]
fn regression_crashed_attempt_does_not_affect_siblings() {
    let (_root, mut supervisor, fake) = setup(8);
    supervisor.handle(new(3)).unwrap();
    let first = supervisor.attempts.values().next().unwrap().clone();
    fake.0
        .lock()
        .unwrap()
        .mounts
        .insert(first.path.clone(), MountState::Crashed);
    let list = supervisor.handle(Operation::List { base: None }).unwrap();
    assert_eq!(
        list.as_array()
            .unwrap()
            .iter()
            .filter(|a| a["status"] == "ready")
            .count(),
        2
    );
    assert_eq!(supervisor.attempts[&first.id].status, "crashed");
    supervisor.destroy(&first.id).unwrap();
    assert!(!first.path.parent().unwrap().exists());
    assert_eq!(supervisor.attempts.len(), 2);
    supervisor.destroy_all().unwrap();
}

/// Regression: failed or timed-out batches remove all their partial mounts and directories.
#[test]
fn regression_partial_batch_and_timeout_roll_back() {
    for stuck in [false, true] {
        let (_root, mut supervisor, fake) = setup(8);
        {
            let mut state = fake.0.lock().unwrap();
            state.stuck = stuck;
            state.fail_spawn = (!stuck).then_some(3);
        }
        let error = supervisor.handle(new(4)).unwrap_err();
        assert_eq!(error.code, if stuck { "timeout" } else { "spawn_failed" });
        assert!(supervisor.attempts.is_empty());
        assert!(fake.0.lock().unwrap().mounts.is_empty());
        assert_eq!(
            fs::read_dir(supervisor.root.join("attempts"))
                .unwrap()
                .count(),
            0
        );
    }
}

/// Regression: failed unmount must preserve the attempt and overlay for a later cleanup retry.
#[test]
fn regression_cleanup_failure_keeps_attempt_data() {
    let (_root, mut supervisor, fake) = setup(8);
    supervisor.handle(new(1)).unwrap();
    let attempt = supervisor.attempts.values().next().unwrap().clone();
    fs::write(attempt.overlay_dir.join("keep"), "payload").unwrap();
    fake.0.lock().unwrap().refuse_cleanup = true;
    assert_eq!(
        supervisor.destroy(&attempt.id).unwrap_err().code,
        "unmount_failed"
    );
    assert_eq!(
        fs::read_to_string(attempt.overlay_dir.join("keep")).unwrap(),
        "payload"
    );
    fake.0.lock().unwrap().refuse_cleanup = false;
    supervisor.destroy(&attempt.id).unwrap();
}

/// Regression: restart removes stale attempts only after unmount, retains bases, and excludes another daemon.
#[test]
fn regression_restart_reconciles_stale_mounts_and_locks_state() {
    let (root, mut supervisor, fake) = setup(8);
    supervisor.handle(new(2)).unwrap();
    assert!(Supervisor::open(root.path(), 8, Duration::from_secs(1), fake.clone()).is_err());
    let paths: Vec<_> = supervisor
        .attempts
        .values()
        .map(|a| a.path.clone())
        .collect();
    drop(supervisor);
    let mut restarted =
        Supervisor::open(root.path(), 8, Duration::from_secs(1), fake.clone()).unwrap();
    assert!(restarted.attempts.is_empty());
    assert!(paths
        .iter()
        .all(|p| fake.0.lock().unwrap().cleaned.contains(p)));
    assert_eq!(
        fs::read_dir(root.path().join("attempts")).unwrap().count(),
        0
    );
    restarted.handle(new(1)).unwrap();
    restarted.destroy_all().unwrap();
}

/// Regression: a stale mount cleanup error must stop restart without deleting its backing files.
#[test]
fn regression_restart_failed_unmount_preserves_state() {
    let (root, mut supervisor, fake) = setup(8);
    supervisor.handle(new(1)).unwrap();
    let path = supervisor
        .attempts
        .values()
        .next()
        .unwrap()
        .overlay_dir
        .clone();
    fs::write(path.join("keep"), "data").unwrap();
    drop(supervisor);
    fake.0.lock().unwrap().refuse_cleanup = true;
    assert!(Supervisor::open(root.path(), 8, Duration::from_secs(1), fake).is_err());
    assert_eq!(fs::read_to_string(path.join("keep")).unwrap(), "data");
}

/// Regression: socket symlinks, foreign ownership and regular files are never replaced; sockets are 0600.
#[test]
fn regression_socket_permissions_and_unsafe_paths() {
    // Socket creation briefly changes umask before the daemon starts threads.
    // Run that startup code in its own process, away from parallel unit tests.
    if std::env::var_os("RATARMOUNT_SANDBOX_SOCKET_TEST").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::tests::regression_socket_permissions_and_unsafe_paths",
                "--nocapture",
            ])
            .env("RATARMOUNT_SANDBOX_SOCKET_TEST", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = private_tempdir();
    let path = root.path().join("api.sock");
    let target = root.path().join("target");
    fs::write(&target, "keep").unwrap();
    symlink(&target, &path).unwrap();
    assert!(SocketGuard::bind(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::write(&path, "keep").unwrap();
    assert!(SocketGuard::bind(&path).is_err());
    fs::remove_file(&path).unwrap();
    let socket = SocketGuard::bind(&path).unwrap();
    let meta = fs::symlink_metadata(&path).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    assert!(daemon::check_socket_metadata(&meta, meta.uid().wrapping_add(1)).is_err());
    assert!(SocketGuard::bind(&path).is_err());
    drop(socket);
    let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
    assert!(SocketGuard::bind(&path).is_err());
    assert!(path.exists());
    drop(stale);
    drop(SocketGuard::bind(&path).unwrap());
    assert!(!path.exists());
    assert_eq!(fs::read_to_string(target).unwrap(), "keep");
    let unsafe_dir = root.path().join("public");
    fs::create_dir(&unsafe_dir).unwrap();
    fs::set_permissions(&unsafe_dir, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(SocketGuard::bind(&unsafe_dir.join("socket")).is_err());
}

/// Regression: policy overrides cannot weaken base limits; source/bind arguments never become flags.
#[test]
fn regression_base_policy_and_mount_options_forwarded() {
    let (_root, mut supervisor, fake) = setup(8);
    supervisor
        .handle(Operation::CreateBase {
            name: "restricted".into(),
            source: "/repo.git@sha".into(),
            options: BaseOptions {
                git_synthetic_head: true,
                recursive: true,
                uid: Some(123),
                gid: Some(456),
                umask: Some("027".into()),
                quota: Some(10),
                readonly_globs: vec!["tests/**".into()],
                passthrough: Some("off".into()),
                binds: vec!["/data=/srv/data.tar".into()],
                allow_other: true,
            },
        })
        .unwrap();
    supervisor
        .handle(Operation::New {
            base: "restricted".into(),
            count: 1,
            overlay: Overlay::Disk,
            quota: Some(100),
            readonly_globs: vec!["fixtures/**".into()],
        })
        .unwrap();
    assert_eq!(
        fake.0.lock().unwrap().policies[0],
        (Some(10), vec!["tests/**".into(), "fixtures/**".into()])
    );
    let base = Base {
        name: "a".into(),
        source: "--evil".into(),
        options: BaseOptions {
            uid: Some(123),
            gid: Some(456),
            umask: Some("027".into()),
            binds: vec!["/repo=/srv/repo.git@sha".into()],
            ..Default::default()
        },
    };
    let attempt = supervisor.attempts.values().next().unwrap();
    let args = process::mount_args(
        &base,
        Path::new("/index,with-comma"),
        attempt,
        Some(10),
        &["tests/**".into()],
    );
    let parsed =
        crate::parse_args_from(std::iter::once(std::ffi::OsString::from("ratarmount")).chain(args))
            .unwrap();
    assert_eq!(parsed.paths[0], PathBuf::from("--evil"));
    assert_eq!(parsed.source_binds[0].mount_path, "/repo");
    assert!(parsed.fuse.contains("uid=123,gid=456,umask=027"));
    supervisor.destroy_all().unwrap();
}

/// Regression: invalid base definitions and destroy selectors do not mutate persistent state.
#[test]
fn regression_invalid_requests_do_not_modify_state() {
    let (_root, mut supervisor, _) = setup(8);
    for (name, options) in [
        ("../escape", BaseOptions::default()),
        (
            "bad",
            BaseOptions {
                passthrough: Some("bad".into()),
                ..Default::default()
            },
        ),
        (
            "bad",
            BaseOptions {
                readonly_globs: vec!["x/../y".into()],
                ..Default::default()
            },
        ),
    ] {
        assert!(supervisor
            .handle(Operation::CreateBase {
                name: name.into(),
                source: "x".into(),
                options
            })
            .is_err());
    }
    assert_eq!(
        supervisor
            .handle(Operation::Destroy {
                id: None,
                base: None
            })
            .unwrap_err()
            .code,
        "invalid_request"
    );
    assert_eq!(
        supervisor
            .handle(Operation::List {
                base: Some("missing".into())
            })
            .unwrap_err()
            .code,
        "not_found"
    );
    assert_eq!(
        supervisor
            .handle(Operation::CreateBase {
                name: "task".into(),
                source: "x".into(),
                options: BaseOptions::default()
            })
            .unwrap_err()
            .code,
        "already_exists"
    );
}

/// Regression: mountinfo escaped paths and nested mounts must be recognized for safe cleanup.
#[test]
fn regression_mountinfo_decodes_escaped_mount_paths() {
    assert_eq!(process::parse_mountinfo(b"1 2 0:1 / /tmp/a\\040b\\134c rw - fuse x rw\n2 1 0:2 / /tmp/a\\040b\\134c/child rw - fuse x rw\n"),
        vec![PathBuf::from("/tmp/a b\\c"), PathBuf::from("/tmp/a b\\c/child")]);
}

/// Regression: API diffs include composed bind paths and stats read the attempt's real overlay.
#[test]
fn regression_live_diff_and_stats_do_not_reopen_locked_database() {
    use ratarmount_compositing::{FolderMountSource, WriteOverlay};
    let (root, mut supervisor, fake) = setup(8);
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("original"), "base\n").unwrap();
    let empty = root.path().join("empty");
    fs::create_dir(&empty).unwrap();
    supervisor
        .handle(Operation::CreateBase {
            name: "bound".into(),
            source: empty.to_str().unwrap().into(),
            options: BaseOptions {
                binds: vec![format!("/repo={}", source.display())],
                ..Default::default()
            },
        })
        .unwrap();
    supervisor
        .handle(Operation::New {
            base: "bound".into(),
            count: 1,
            overlay: Overlay::Disk,
            quota: None,
            readonly_globs: vec![],
        })
        .unwrap();
    let attempt = supervisor.attempts.values().next().unwrap().clone();
    fs::write(empty.join("gone"), "delete me\n").unwrap();
    let overlay = Arc::new(
        WriteOverlay::new(
            Arc::new(FolderMountSource::new(&empty).unwrap()),
            &attempt.overlay_dir,
        )
        .unwrap(),
    );
    overlay.unlink("/gone").unwrap();
    let inspector =
        super::start_inspection(&super::inspection::socket_path(&attempt), &overlay).unwrap();
    fake.0.lock().unwrap().inspection = true;
    fs::create_dir(attempt.overlay_dir.join("repo")).unwrap();
    fs::write(attempt.overlay_dir.join("repo/original"), "edited\n").unwrap();
    let patch = supervisor
        .handle(Operation::Diff {
            id: attempt.id.clone(),
            git: true,
        })
        .unwrap();
    assert!(patch["patch"]
        .as_str()
        .unwrap()
        .contains("diff --git a/repo/original b/repo/original"));
    assert!(patch["patch"]
        .as_str()
        .unwrap()
        .contains("-base\n+edited\n"));
    let stats = supervisor
        .handle(Operation::Stats {
            id: attempt.id.clone(),
        })
        .unwrap();
    assert_eq!(stats["bytes_in_overlay"], 7);
    assert_eq!(stats["files_present"], 1);
    assert_eq!(stats["files_deleted"], 1);
    assert!(patch["patch"].as_str().unwrap().contains("-delete me\n"));
    drop(inspector);
    drop(overlay);
    supervisor.destroy_all().unwrap();
}

/// Regression: daemon-owned tmpfs overlays survive child failure but are discarded on restart.
#[cfg(target_os = "linux")]
#[test]
fn regression_tmpfs_overlay_path_and_restart_cleanup() {
    use sha2::{Digest, Sha256};
    let root = private_tempdir();
    let ram_parent = private_tempdir();
    // /tmp is tmpfs in the worker sandbox; no /dev/shm write permission is needed.
    let ram = ram_parent.path().join(format!(
        "ratarmount-sandbox-{:x}",
        Sha256::digest(
            fs::canonicalize(root.path())
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
        )
    ));
    fs::write(
        root.path().join("ram-root.json"),
        serde_json::to_vec(&ram).unwrap(),
    )
    .unwrap();
    let fake = Fake::default();
    let mut supervisor =
        Supervisor::open(root.path(), 8, Duration::from_secs(1), fake.clone()).unwrap();
    supervisor
        .handle(Operation::CreateBase {
            name: "task".into(),
            source: "/fake.tar".into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    let result = supervisor.handle(Operation::New {
        base: "task".into(),
        count: 1,
        overlay: Overlay::Tmpfs,
        quota: Some(1024),
        readonly_globs: vec![],
    });
    if let Err(error) = &result {
        if error.code == "unsupported" {
            eprintln!(
                "skip: test temporary directory is not tmpfs: {}",
                error.message
            );
            return;
        }
    }
    result.unwrap();
    let attempt = supervisor.attempts.values().next().unwrap().clone();
    assert_eq!(attempt.overlay_dir, ram.join(&attempt.id));
    fs::write(attempt.overlay_dir.join("payload"), "keep until destroy").unwrap();
    fake.0
        .lock()
        .unwrap()
        .mounts
        .insert(attempt.path.clone(), MountState::Crashed);
    supervisor.supervise();
    assert!(attempt.overlay_dir.join("payload").exists());
    drop(supervisor);
    let restarted = Supervisor::open(root.path(), 8, Duration::from_secs(1), fake).unwrap();
    assert!(restarted.attempts.is_empty());
    assert!(!attempt.overlay_dir.exists());
}

/// Regression: UTF-8 local paths must not panic during URL detection or change meaning on restart.
#[test]
fn regression_unicode_sources_normalized_without_panics() {
    let (_root, mut supervisor, _) = setup(8);
    for (name, source) in [
        ("local", "éééé.tar"),
        ("remote", "s3://aé/base.tar"),
        ("restic", "restic:/srv/backup"),
    ] {
        let result = supervisor
            .handle(Operation::CreateBase {
                name: name.into(),
                source: source.into(),
                options: BaseOptions::default(),
            })
            .unwrap();
        if name == "local" {
            assert_eq!(
                result["source"],
                std::env::current_dir()
                    .unwrap()
                    .join(source)
                    .to_str()
                    .unwrap()
            );
        } else {
            assert_eq!(result["source"], source);
        }
    }
}
