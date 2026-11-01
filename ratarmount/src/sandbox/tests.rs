use super::*;
use daemon::{SocketGuard, Supervisor};
use process::{MountState, Mounter};
use protocol::{ApiError, Attempt, Base};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub(super) fn private_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        // Leave room for attempts/ID/inspect.sock within Darwin's 104-byte sun_path.
        .tempdir_in("/tmp")
        .unwrap()
}

#[derive(Default)]
pub(super) struct FakeState {
    pub(super) mounts: BTreeMap<PathBuf, MountState>,
    pub(super) fail_spawn: Option<usize>,
    pub(super) spawns: usize,
    pub(super) prepares: usize,
    pub(super) first_poll_spawns: Option<usize>,
    pub(super) stuck: bool,
    pub(super) refuse_cleanup: bool,
    pub(super) inspection: bool,
    /// Write a `spawned` marker into each attempt directory on spawn.
    pub(super) marker: bool,
    pub(super) cleaned: Vec<PathBuf>,
    pub(super) policies: Vec<(Option<u64>, Vec<String>)>,
}

#[derive(Clone, Default)]
pub(super) struct Fake(pub(super) Arc<Mutex<FakeState>>);

impl Mounter for Fake {
    fn prepare(&mut self, _: &Base, _: &Path, _: Duration) -> Result<(), ApiError> {
        self.0.lock().unwrap().prepares += 1;
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
        if state.marker {
            fs::write(attempt.path.parent().unwrap().join("spawned"), b"").unwrap();
        }
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

pub(super) fn setup(limit: usize) -> (tempfile::TempDir, Supervisor<Fake>, Fake) {
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
    for line in [r#"{}"#, r#"{"version":3,"op":"list"}"#] {
        assert_eq!(
            Request::parse(line.as_bytes()).unwrap_err().error.code,
            "unsupported_version"
        );
    }
    for line in [
        r#"{"version":1,"op":"list","typo":true}"#,
        r#"{"version":1,"op":"unknown"}"#,
        "{",
        r#"{"version":1,"op":"create_base","name":"a","source":"x","options":{"bad":true}}"#,
    ] {
        let response = Response::from_result(
            VERSION,
            Request::parse(line.as_bytes())
                .map(|_| json!(null))
                .map_err(|rejection| rejection.error),
        );
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
            operation: operation.into(),
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
    // Regression: a parallel child can retain daemon.lock until exec/exit (#242).
    let _processes = ratarmount_index::test_process::exclusive();
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
    let _processes = ratarmount_index::test_process::exclusive();
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
    let _processes = ratarmount_index::test_process::spawning();
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
                allow_globs: vec!["tests/agent/**".into()],
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
            allow_globs: vec!["tests/agent/**".into()],
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
    assert_eq!(parsed.overlay_allow, ["tests/agent/**"]);
    assert!(parsed.fuse.contains("uid=123,gid=456,umask=027"));
    supervisor.destroy_all().unwrap();
}

/// Regression: v1 bases without exceptions still decode; optional exceptions reach
/// child mounts, and invalid exceptions are rejected before persisting a base.
#[test]
fn regression_base_allow_globs_optional_v1() {
    for (options, expected) in [
        (json!({"readonly_globs": ["t/**"]}), vec![]),
        (
            json!({"readonly_globs": ["t/**"], "allow_globs": ["t/agent/**"]}),
            vec!["t/agent/**".to_string()],
        ),
    ] {
        let request = json!({"version": 1, "op": "create_base", "name": "task", "source": "x", "options": options});
        let parsed = Request::parse(&serde_json::to_vec(&request).unwrap()).unwrap();
        let protocol::Op::V1(Operation::CreateBase { options, .. }) = parsed.operation else {
            panic!("create_base");
        };
        assert_eq!(options.allow_globs, expected);
    }
    let (_root, mut supervisor, _) = setup(8);
    for options in [
        BaseOptions {
            allow_globs: vec!["t/agent/**".into()],
            ..Default::default()
        },
        BaseOptions {
            readonly_globs: vec!["t/**".into()],
            allow_globs: vec!["../escape".into()],
            ..Default::default()
        },
    ] {
        assert!(supervisor
            .handle(Operation::CreateBase {
                name: "bad-allow".into(),
                source: "x".into(),
                options
            })
            .is_err());
        assert_eq!(
            supervisor
                .handle(Operation::List {
                    base: Some("bad-allow".into())
                })
                .unwrap_err()
                .code,
            "not_found"
        );
    }
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
    use ratarmount_compositing::FolderMountSource;
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
        crate::base_identity::fixtures::new_overlay(
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
    let _processes = ratarmount_index::test_process::exclusive();
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

/// Regression: long macOS temp paths must report the native Unix socket byte limit.
#[test]
fn regression_sandbox_socket_path_reports_platform_limit() {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: all-zero sockaddr_un is valid; only the path array length is used.
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let limit = address.sun_path.len();
    let valid = "x".repeat(limit - 1);
    super::inspection::validate_socket_path(Path::new(&valid)).unwrap();
    let too_long = PathBuf::from("x".repeat(limit));
    let error = super::inspection::validate_socket_path(&too_long).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error
        .to_string()
        .contains(&format!("shorter than {limit} bytes")));
    assert!(error.to_string().contains("--state-dir"));
    assert!(SocketGuard::bind(&too_long)
        .err()
        .unwrap()
        .message
        .contains(&format!("shorter than {limit} bytes")));
    let nul = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/a\0b"));
    assert!(super::inspection::validate_socket_path(nul).is_err());
}

/// Regression: strict worker policy is a parsed option before the source separator.
#[test]
fn regression_prepared_index_sandbox_worker_argv() {
    let (root, mut supervisor, _) = setup(8);
    supervisor.handle(new(1)).unwrap();
    let base = &Base {
        name: "task".into(),
        source: "/fake.tar".into(),
        options: BaseOptions::default(),
    };
    let attempt = supervisor.attempts.values().next().unwrap();
    let args = process::mount_args(base, root.path(), attempt, None, &[]);
    let policy = args
        .iter()
        .position(|a| a == "--no-recreate-index")
        .unwrap();
    assert!(policy < args.iter().position(|a| a == "--").unwrap());
    let parsed =
        crate::parse_args_from(std::iter::once(OsString::from("ratarmount")).chain(args)).unwrap();
    assert!(parsed.no_recreate_index);
    assert!(!parsed.commit_overlay && !parsed.commit_overlay_on_exit);
    assert_eq!(parsed.commit_overlay_interval, "0");
    let prepare = process::base_args(base, root.path()).into_iter().chain([
        OsString::from("--no-mount"),
        OsString::from("--"),
        OsString::from(&base.source),
    ]);
    let parsed =
        crate::parse_args_from(std::iter::once(OsString::from("ratarmount")).chain(prepare))
            .unwrap();
    assert!(parsed.no_mount);
    assert!(!parsed.no_recreate_index);
    assert!(parsed.write_overlay.is_none());
}

/// Regression: a registered base is prepared once across worker batches and reloads.
#[test]
fn regression_prepared_index_sandbox_prepares_once_across_batches() {
    let _processes = ratarmount_index::test_process::exclusive();
    let (root, mut supervisor, fake) = setup(8);
    assert_eq!(fake.0.lock().unwrap().prepares, 1);
    for _ in 0..2 {
        supervisor.handle(new(3)).unwrap();
        supervisor.destroy_all().unwrap();
    }
    drop(supervisor);
    let mut supervisor =
        Supervisor::open(root.path(), 8, Duration::from_secs(1), fake.clone()).unwrap();
    supervisor.handle(new(3)).unwrap();
    supervisor.destroy_all().unwrap();
    assert_eq!(fake.0.lock().unwrap().prepares, 1);
}

/// Regression: API diff must refuse an invalid selected index without repairing it.
#[test]
fn regression_prepared_index_sandbox_diff_refuses_invalid_cache() {
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let base = root.path().join("base.tar");
    let mut file = fs::File::create(&base).unwrap();
    write_ustar_members(
        &mut file,
        &[UstarMember {
            path: "f",
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
            payload: UstarPayload::File { bytes: b"original" },
        }],
    )
    .unwrap();
    write_tar_eof(&mut file).unwrap();
    drop(file);
    let mut supervisor =
        Supervisor::open(root.path(), 8, Duration::from_secs(1), Fake::default()).unwrap();
    supervisor
        .handle(Operation::CreateBase {
            name: "task".into(),
            source: base.to_string_lossy().into(),
            options: BaseOptions::default(),
        })
        .unwrap();
    let cache = root.path().join("indexes/task");
    let opts = ratarmount_core::OpenOptions {
        index_folders: vec![cache.clone()],
        ..Default::default()
    };
    drop(ratarmount_session::factory::open_path(&base, &opts, false).unwrap());
    let index = fs::read_dir(&cache)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "sqlite"))
        .unwrap();
    fs::write(&index, b"invalid prepared catalog").unwrap();
    let before = fs::read(&index).unwrap();
    supervisor.handle(new(1)).unwrap();
    let id = supervisor.attempts.keys().next().unwrap().clone();
    let error = supervisor
        .handle(Operation::Diff { id, git: true })
        .unwrap_err();
    assert_eq!(error.code, "base_open_failed", "{}", error.message);
    assert!(
        error.message.contains("index") || error.message.contains("prepar"),
        "{}",
        error.message
    );
    assert_eq!(fs::read(index).unwrap(), before);
    supervisor.destroy_all().unwrap();
}

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/sandbox/testdata/v1-golden.jsonl"
);
const CLI_V1_REQUESTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/sandbox/testdata/cli-v1-requests.jsonl"
);

/// The v1 transcript. `request` lines and overlay paths use `$STATE` (the
/// canonical state root) and `$BASE` (the base path as sent). `generated`
/// stands for a line of that many `x` bytes, too large to store. Envelope
/// errors carry no path and are replayed against the real daemon as well
/// (`ratarmount/tests/sandbox.rs`).
fn golden_script() -> Vec<serde_json::Value> {
    let request = |line: &str| json!({ "request": line });
    let envelope = |line: &str| json!({ "request": line, "envelope": true });
    let overlay = "$STATE/attempts/attempt-000001/overlay";
    vec![
        request(r#"{"version":1,"op":"create_base","name":"task","source":"$BASE"}"#),
        request(r#"{"version":1,"op":"create_base","name":"task","source":"$BASE"}"#),
        request(
            r#"{"version":1,"op":"create_base","name":"other","source":"$BASE","options":{"bogus":true}}"#,
        ),
        request(r#"{"version":1,"op":"new","base":"task","count":2}"#),
        request(r#"{"version":1,"op":"new","base":"task","count":0}"#),
        request(r#"{"version":1,"op":"new","base":"task","count":2}"#),
        request(r#"{"version":1,"op":"new","base":"missing"}"#),
        request(r#"{"version":1,"op":"new","base":"task","request_id":"r1"}"#),
        request(r#"{"version":1,"op":"new","base":"task","lowers":["layer"]}"#),
        request(r#"{"version":1,"op":"list"}"#),
        request(r#"{"version":1,"op":"list","base":"task"}"#),
        request(r#"{"version":1,"op":"list","base":"missing"}"#),
        json!({ "mkdir": format!("{overlay}/sub"), "mode": "0755" }),
        json!({ "write": format!("{overlay}/original.txt"), "mode": "0644", "content": "edited\n" }),
        json!({ "write": format!("{overlay}/new.txt"), "mode": "0640", "content": "added\n" }),
        json!({ "write": format!("{overlay}/sub/keep.txt"), "mode": "0755", "content": "keep\n" }),
        request(r#"{"version":1,"op":"diff","id":"attempt-000001","git":false}"#),
        request(r#"{"version":1,"op":"diff","id":"attempt-000001","git":true}"#),
        request(r#"{"version":1,"op":"stats","id":"attempt-000001"}"#),
        request(r#"{"version":1,"op":"destroy","id":"attempt-000002","base":"task"}"#),
        request(r#"{"version":1,"op":"destroy"}"#),
        request(r#"{"version":1,"op":"destroy","id":"attempt-999999"}"#),
        request(r#"{"version":1,"op":"destroy","id":"attempt-000002"}"#),
        request(r#"{"version":1,"op":"destroy","base":"task"}"#),
        request(r#"{"version":1,"op":"list"}"#),
        envelope(r#"{}"#),
        envelope(r#"{"version":3,"op":"list"}"#),
        envelope(r#"{"version":"1","op":"list"}"#),
        envelope(r#"{"version":1.0,"op":"list"}"#),
        envelope("{bad}"),
        json!({ "generated": protocol::MAX_REQUEST, "envelope": true }),
        json!({ "generated": protocol::MAX_REQUEST + 1, "envelope": true }),
        request(r#"{"version":1,"op":"shutdown"}"#),
        // v1 ignores extra keys on its unit `shutdown` and executes it (§4 row 21).
        request(r#"{"version":1,"op":"shutdown","x":1}"#),
    ]
}

/// A fresh supervisor over a fixed directory base, with deterministic IDs.
struct Golden {
    supervisor: Supervisor<Fake>,
    state: String,
    base: String,
    _dirs: [tempfile::TempDir; 2],
}

impl Golden {
    fn new() -> Self {
        let state = private_tempdir();
        let parent = private_tempdir();
        let base = parent.path().join("base");
        // Explicit modes keep the umask out of non-git diff headers.
        for (path, content, mode) in [
            (base.clone(), None, 0o755),
            (base.join("original.txt"), Some("base\n"), 0o644),
            (base.join("sub"), None, 0o755),
            (base.join("sub/keep.txt"), Some("keep\n"), 0o644),
        ] {
            match content {
                Some(content) => fs::write(&path, content).unwrap(),
                None => fs::create_dir(&path).unwrap(),
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut supervisor =
            Supervisor::open(state.path(), 3, Duration::from_secs(30), Fake::default()).unwrap();
        supervisor.test_ids = Some(daemon::TestIds::default());
        Self {
            state: supervisor.root.to_str().unwrap().into(),
            base: base.to_str().unwrap().into(),
            supervisor,
            _dirs: [state, parent],
        }
    }

    fn fill(&self, text: &str) -> String {
        text.replace("$STATE", &self.state)
            .replace("$BASE", &self.base)
    }

    fn template(&self, text: &str) -> String {
        text.replace(&self.state, "$STATE")
            .replace(&self.base, "$BASE")
    }

    /// Runs one entry: a request returns its response line, a file write `None`.
    fn step(
        &mut self,
        entry: &serde_json::Value,
        respond: fn(&mut Supervisor<Fake>, &[u8]) -> Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mode = || u32::from_str_radix(entry["mode"].as_str().unwrap(), 8).unwrap();
        if let Some(path) = entry["mkdir"].as_str() {
            let path = self.fill(path);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode())).unwrap();
            None
        } else if let Some(path) = entry["write"].as_str() {
            let path = self.fill(path);
            fs::write(&path, entry["content"].as_str().unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode())).unwrap();
            None
        } else if let Some(size) = entry["generated"].as_u64() {
            Some(respond(&mut self.supervisor, &vec![b'x'; size as usize]))
        } else {
            let line = self.fill(entry["request"].as_str().unwrap());
            Some(respond(&mut self.supervisor, line.as_bytes()))
        }
    }
}

fn golden_respond(supervisor: &mut Supervisor<Fake>, line: &[u8]) -> Vec<u8> {
    daemon::respond(supervisor, line)
}

/// Writes `testdata/v1-golden.jsonl` through `daemon::respond`. The committed
/// fixture was generated from the baseline per-line path (`serve` and `send`
/// at 2b96837). Regenerate only on purpose, with the reason in the commit
/// message: a serde_json upgrade that changes the pinned parse-error texts is
/// such an intentional regeneration.
#[test]
#[ignore = "fixture generator: cargo test -p ratarmount --bin ratarmount generate_v1_golden -- --ignored"]
fn generate_v1_golden() {
    let mut golden = Golden::new();
    let mut output = String::new();
    for mut entry in golden_script() {
        if let Some(response) = golden.step(&entry, golden_respond) {
            let response = golden.template(std::str::from_utf8(&response).unwrap());
            entry["response"] = json!(response);
        }
        output.push_str(&serde_json::to_string(&entry).unwrap());
        output.push('\n');
    }
    fs::write(GOLDEN, output).unwrap();
}

/// Regression: protocol v1 replies change no byte (Keystone #7). The golden
/// transcript was generated from the baseline per-line path; every reply of
/// the production `respond()` must match after `$STATE`/`$BASE` substitution,
/// with no entry skipped.
#[test]
fn regression_v1_golden_transcript_byte_identical() {
    let mut golden = Golden::new();
    let text = fs::read_to_string(GOLDEN).unwrap();
    let mut replies = 0;
    for (number, line) in text.lines().enumerate() {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(!line.contains(r#"\"version\":2"#), "version 2 is not v1");
        let reply = golden.step(&entry, golden_respond);
        match (reply, entry["response"].as_str()) {
            (Some(reply), Some(expected)) => {
                assert_eq!(
                    String::from_utf8(reply).unwrap(),
                    golden.fill(expected),
                    "golden line {}",
                    number + 1
                );
                replies += 1;
            }
            (None, None) => {}
            other => panic!("golden line {}: {other:?}", number + 1),
        }
    }
    assert_eq!(
        replies,
        golden_script()
            .iter()
            .filter(|e| e.get("request").is_some() || e.get("generated").is_some())
            .count()
    );
    assert!(golden.supervisor.stopping);
}

/// Regression: version 2 is dispatched separately; an answer carries its
/// request's version, and one refused before a version is known is v1. v2
/// refuses unknown fields on every operation, `shutdown` included, and a
/// `request_id` anywhere but `new` (§5.1, §5.2, Codex sweep 4 B1).
#[test]
fn regression_protocol_v2_dispatch_and_envelope_versions() {
    use protocol::{Op, OperationV2, VERSION_2};
    for (line, version, code) in [
        ("{", 1, "invalid_request"),
        ("[]", 1, "unsupported_version"),
        ("{}", 1, "unsupported_version"),
        (r#"{"op":"list"}"#, 1, "unsupported_version"),
        (r#"{"version":"1","op":"list"}"#, 1, "unsupported_version"),
        (r#"{"version":"2","op":"list"}"#, 1, "unsupported_version"),
        (r#"{"version":1.0,"op":"list"}"#, 1, "unsupported_version"),
        (r#"{"version":2.0,"op":"list"}"#, 1, "unsupported_version"),
        (r#"{"version":3,"op":"list"}"#, 1, "unsupported_version"),
        (r#"{"version":-1,"op":"list"}"#, 1, "unsupported_version"),
        (r#"{"version":null,"op":"list"}"#, 1, "unsupported_version"),
        (
            r#"{"version":1,"op":"list","typo":true}"#,
            1,
            "invalid_request",
        ),
        (
            r#"{"version":1,"op":"new","base":"t","request_id":"r"}"#,
            1,
            "invalid_request",
        ),
        (r#"{"version":2}"#, 2, "invalid_request"),
        (
            r#"{"version":2,"op":"list","typo":true}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"finalize","id":"a"}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"new","base":"t","lowers":["l"]}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"new","base":"t","allow_globs":["a"]}"#,
            2,
            "invalid_request",
        ),
        (r#"{"version":2,"op":"diff"}"#, 2, "invalid_request"),
        (
            r#"{"version":2,"op":"new","base":"t","request_id":null}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"new","base":"t","request_id":7}"#,
            2,
            "invalid_request",
        ),
        // Only `new` takes a request ID (N2).
        (
            r#"{"version":2,"op":"create_base","name":"a","source":"x","request_id":"r"}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"destroy","id":"a","request_id":"r"}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"list","request_id":"r"}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"diff","id":"a","request_id":"r"}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"stats","id":"a","request_id":"r"}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"shutdown","request_id":"r"}"#,
            2,
            "invalid_request",
        ),
        (
            r#"{"version":2,"op":"shutdown","extra":1}"#,
            2,
            "invalid_request",
        ),
    ] {
        let rejection = Request::parse(line.as_bytes()).unwrap_err();
        assert_eq!(
            (rejection.version, rejection.error.code.as_str()),
            (version, code),
            "{line}: {}",
            rejection.error.message
        );
    }
    assert_eq!(
        Request::parse(b"{}").unwrap_err().error.message,
        "version must be 1"
    );
    let parsed =
        Request::parse(br#"{"version":2,"op":"new","base":"t","request_id":"r"}"#).unwrap();
    assert_eq!(parsed.version, VERSION_2);
    assert!(matches!(
        parsed.operation,
        Op::V2(OperationV2::New { request_id: Some(ref id), count: 1, .. }) if id == "r"
    ));
    assert!(matches!(
        Request::parse(br#"{"version":1,"op":"list"}"#)
            .unwrap()
            .operation,
        Op::V1(Operation::List { base: None })
    ));
    assert!(matches!(
        Request::parse(br#"{"version":2,"op":"shutdown"}"#)
            .unwrap()
            .operation,
        Op::V2(OperationV2::Shutdown {})
    ));
    assert_eq!(
        serde_json::to_string(&Request::new(OperationV2::Shutdown {})).unwrap(),
        r#"{"version":2,"op":"shutdown"}"#
    );
    // Through respond(): a refused v2 shutdown executes nothing.
    let (_root, mut supervisor, _) = setup(8);
    supervisor.handle(new(2)).unwrap();
    for line in [
        r#"{"version":2,"op":"shutdown","request_id":"r"}"#,
        r#"{"version":2,"op":"shutdown","extra":1}"#,
    ] {
        let reply: serde_json::Value =
            serde_json::from_slice(&daemon::respond(&mut supervisor, line.as_bytes())).unwrap();
        assert_eq!(reply["version"], 2, "{reply}");
        assert_eq!(reply["error"]["code"], "invalid_request");
        assert_eq!(supervisor.attempts.len(), 2);
        assert!(!supervisor.stopping);
    }
    for (line, version, ok) in [
        (r#"{"version":1,"op":"list"}"#, 1, true),
        (r#"{"version":1,"op":"stats","id":"missing"}"#, 1, false),
        (r#"{"version":2,"op":"list"}"#, 2, true),
        (r#"{"version":2,"op":"stats","id":"missing"}"#, 2, false),
        (r#"{"version":2,"op":"bogus"}"#, 2, false),
        (r#"{"version":9,"op":"list"}"#, 1, false),
    ] {
        let reply: serde_json::Value =
            serde_json::from_slice(&daemon::respond(&mut supervisor, line.as_bytes())).unwrap();
        assert_eq!(
            (reply["version"].as_u64(), reply["ok"].as_bool()),
            (Some(version), Some(ok)),
            "{line}"
        );
    }
    let reply = daemon::respond(&mut supervisor, &vec![b'x'; protocol::MAX_REQUEST + 1]);
    assert!(reply.starts_with(b"{\"version\":1,\"ok\":false"));
    supervisor.destroy_all().unwrap();
    // encode() substitutes an oversize reply with the reply's own version.
    for version in [VERSION, VERSION_2] {
        let large = Response::from_result(version, Ok(json!("x".repeat(100))));
        assert_eq!(
            String::from_utf8(daemon::encode(&large, 64)).unwrap(),
            format!("{{\"version\":{version},\"ok\":false,\"error\":{{\"code\":\"response_too_large\",\"message\":\"response exceeds 64 MiB; export the diff locally\"}}}}\n")
        );
        let small = Response::from_result(version, Ok(json!(1)));
        assert_eq!(
            String::from_utf8(daemon::encode(&small, 64)).unwrap(),
            format!("{{\"version\":{version},\"ok\":true,\"result\":1}}\n")
        );
    }
    // v2 list, diff, stats and destroy answer what v1 answers on the same state.
    let mut golden = Golden::new();
    let mut result = |line: String| {
        let reply: serde_json::Value =
            serde_json::from_slice(&daemon::respond(&mut golden.supervisor, line.as_bytes()))
                .unwrap();
        assert_eq!(reply["ok"], true, "{line}: {reply}");
        reply["result"].clone()
    };
    result(format!(
        r#"{{"version":1,"op":"create_base","name":"task","source":"{}"}}"#,
        golden.base
    ));
    result(r#"{"version":1,"op":"new","base":"task","count":2}"#.into());
    fs::write(
        format!(
            "{}/attempts/attempt-000001/overlay/original.txt",
            golden.state
        ),
        "edited\n",
    )
    .unwrap();
    for body in [
        r#""op":"list""#,
        r#""op":"list","base":"task""#,
        r#""op":"diff","id":"attempt-000001""#,
        r#""op":"diff","id":"attempt-000001","git":true"#,
        r#""op":"stats","id":"attempt-000001""#,
    ] {
        let v1 = result(format!(r#"{{"version":1,{body}}}"#));
        let v2 = result(format!(r#"{{"version":2,{body}}}"#));
        assert_eq!(v1, v2, "{body}");
    }
    let v1 = result(r#"{"version":1,"op":"destroy","id":"attempt-000001"}"#.into());
    let v2 = result(r#"{"version":2,"op":"destroy","id":"attempt-000002"}"#.into());
    assert_eq!(v1, v2);
    let v1 = result(r#"{"version":1,"op":"destroy","base":"task"}"#.into());
    let v2 = result(r#"{"version":2,"op":"destroy","base":"task"}"#.into());
    assert_eq!(v1, v2);
    assert_eq!(result(r#"{"version":2,"op":"list"}"#.into()), json!([]));
    // create_base keeps every option through the v2 mapping (sweep 1).
    let options = r#""options":{"recursive":true,"umask":"027","readonly_globs":["sub/**"],"allow_globs":["sub/open/**"],"quota":7,"passthrough":"off"}"#;
    let create = |version: u32, name: &str| {
        format!(
            r#"{{"version":{version},"op":"create_base","name":"{name}","source":"{}",{options}}}"#,
            golden.base
        )
    };
    let (one, two) = (create(1, "one"), create(2, "two"));
    let mut v1 = result(one);
    let v2 = result(two);
    assert_eq!(v1["options"]["allow_globs"], json!(["sub/open/**"]));
    v1["name"] = json!("two");
    assert_eq!(v1, v2);
    result(r#"{"version":2,"op":"list","base":"two"}"#.into());
    // A v2 shutdown executes and answers in a v2 envelope.
    assert!(!golden.supervisor.stopping);
    assert_eq!(
        daemon::respond(&mut golden.supervisor, br#"{"version":2,"op":"shutdown"}"#),
        b"{\"version\":2,\"ok\":true,\"result\":{\"shutdown\":true}}\n"
    );
    assert!(golden.supervisor.stopping);
}

/// v1 CLI subcommands; the socket comes from the recording listener.
const CLI_V1_ARGVS: &[&[&str]] = &[
    &["create-base", "task", "/srv/base.tar"],
    &[
        "create-base",
        "task",
        "/srv/base.tar",
        "--options",
        r#"{"quota":2147483648,"readonly_globs":["tests/**"],"git_synthetic_head":true,"binds":["/data=/srv/data.tar"]}"#,
    ],
    &["new", "task"],
    &[
        "new",
        "task",
        "--count",
        "8",
        "--overlay",
        "tmpfs",
        "--quota",
        "2G",
        "--readonly",
        "a,b",
    ],
    &["new", "task", "--readonly", "a", "--readonly", "b/**"],
    &["list"],
    &["list", "--base", "task"],
    &["diff", "attempt-ABC123"],
    &["diff", "attempt-ABC123", "--git"],
    &["stats", "attempt-ABC123"],
    &["destroy", "attempt-ABC123"],
    &["destroy", "--base", "task"],
    &["shutdown"],
];

/// A listener thread that records one request line per connection and sends
/// the next reply. The listener is owned by its thread: a panic there drops
/// it, so a waiting `call` sees EOF at once instead of its 3600 s timeout.
struct Recorder {
    socket: PathBuf,
    lines: std::sync::mpsc::Receiver<Vec<u8>>,
    thread: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Recorder {
    fn start(replies: Vec<Vec<u8>>) -> Self {
        let dir = private_tempdir();
        let socket = dir.path().join("record.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (sender, lines) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let listener = listener;
            for reply in replies {
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "no client");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = Vec::new();
                reader.read_until(b'\n', &mut line).unwrap();
                sender.send(line).unwrap();
                reader.get_mut().write_all(&reply).unwrap();
            }
        });
        Self {
            socket,
            lines,
            thread: Some(thread),
            _dir: dir,
        }
    }

    fn args(&self, argv: &[&str]) -> SandboxArgs {
        SandboxArgs::try_parse_from(
            ["sandbox", "--socket", self.socket.to_str().unwrap()]
                .into_iter()
                .chain(argv.iter().copied()),
        )
        .unwrap()
    }

    fn line(&self) -> Vec<u8> {
        self.lines.recv_timeout(Duration::from_secs(30)).unwrap()
    }

    /// Joins the listener thread with a bounded wait.
    fn finish(mut self) {
        let thread = self.thread.take().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !thread.is_finished() {
            assert!(std::time::Instant::now() < deadline, "recorder hung");
            std::thread::sleep(Duration::from_millis(5));
        }
        thread.join().unwrap();
    }
}

const RECORDER_OK: &[u8] = b"{\"version\":1,\"ok\":true,\"result\":null}\n";

/// Drives `sandbox::run` for every v1 argv against the recording listener.
fn record_cli_v1_requests() -> Vec<serde_json::Value> {
    let recorder = Recorder::start(vec![RECORDER_OK.to_vec(); CLI_V1_ARGVS.len()]);
    let mut entries = Vec::new();
    for argv in CLI_V1_ARGVS {
        run(&recorder.args(argv)).unwrap();
        let line = String::from_utf8(recorder.line()).unwrap();
        eprintln!("{argv:?} -> {}", line.trim_end());
        entries.push(json!({ "argv": argv, "request": line }));
    }
    recorder.finish();
    entries
}

/// Writes `testdata/cli-v1-requests.jsonl` from the CLI's own requests.
/// Regenerate only on purpose, with the reason in the commit message.
#[test]
#[ignore = "fixture generator: cargo test -p ratarmount --bin ratarmount generate_cli_v1_requests -- --ignored"]
fn generate_cli_v1_requests() {
    let mut output = String::new();
    for entry in record_cli_v1_requests() {
        output.push_str(&serde_json::to_string(&entry).unwrap());
        output.push('\n');
    }
    fs::write(CLI_V1_REQUESTS, output).unwrap();
}

/// Regression: every v1 CLI subcommand still sends the baseline bytes;
/// `new --request-id` sends v2, and `call` accepts only its request's
/// version, or a v1 error answering v2 (how an older daemon refuses v2).
#[test]
fn regression_cli_v1_request_bytes_unchanged() {
    let expected: Vec<serde_json::Value> = fs::read_to_string(CLI_V1_REQUESTS)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(record_cli_v1_requests(), expected);
    let v2_new = ["new", "task", "--count", "2", "--request-id", "r"];
    let recorder = Recorder::start(vec![
        b"{\"version\":2,\"ok\":true,\"result\":null}\n".to_vec()
    ]);
    run(&recorder.args(&v2_new)).unwrap();
    assert_eq!(
        String::from_utf8(recorder.line()).unwrap(),
        "{\"version\":2,\"op\":\"new\",\"base\":\"task\",\"count\":2,\"overlay\":\"disk\",\"quota\":null,\"readonly_globs\":[],\"request_id\":\"r\"}\n"
    );
    recorder.finish();
    const FAILED: &str = "request failed (see JSON error)";
    const VERSION_ERROR: &str = "unsupported response version";
    let v1_error = r#"{"version":1,"ok":false,"error":{"code":"unsupported_version","message":"version must be 1"}}"#;
    let v2_error =
        r#"{"version":2,"ok":false,"error":{"code":"not_found","message":"unknown base"}}"#;
    for (argv, reply, expected) in [
        (
            &v2_new[..],
            r#"{"version":2,"ok":true,"result":null}"#,
            Ok(()),
        ),
        (&v2_new[..], v2_error, Err(FAILED)),
        (&v2_new[..], v1_error, Err(FAILED)),
        (
            &v2_new[..],
            r#"{"version":1,"ok":true,"result":null}"#,
            Err(VERSION_ERROR),
        ),
        (
            &v2_new[..],
            r#"{"version":3,"ok":false,"error":{"code":"x","message":"y"}}"#,
            Err(VERSION_ERROR),
        ),
        (
            &["list"][..],
            r#"{"version":1,"ok":true,"result":[]}"#,
            Ok(()),
        ),
        (&["list"][..], v1_error, Err(FAILED)),
        (
            &["list"][..],
            r#"{"version":2,"ok":true,"result":[]}"#,
            Err(VERSION_ERROR),
        ),
        (&["list"][..], v2_error, Err(VERSION_ERROR)),
    ] {
        let recorder = Recorder::start(vec![format!("{reply}\n").into_bytes()]);
        let outcome = run(&recorder.args(argv));
        assert_eq!(
            outcome,
            expected.map_err(String::from),
            "{argv:?} <- {reply}"
        );
        recorder.line();
        recorder.finish();
    }
    // call() itself returns an older daemon's v1 error answering v2.
    let recorder = Recorder::start(vec![format!("{v1_error}\n").into_bytes()]);
    let response = call(
        &recorder.socket,
        Request::new(protocol::OperationV2::New {
            base: "task".into(),
            count: 1,
            overlay: Overlay::Disk,
            quota: None,
            readonly_globs: vec![],
            request_id: Some("r".into()),
        }),
    )
    .unwrap();
    assert_eq!((response.version, response.ok), (VERSION, false));
    assert_eq!(response.error.unwrap().code, "unsupported_version");
    recorder.line();
    recorder.finish();
}
