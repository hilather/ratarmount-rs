//! Git commands on a writable synthetic repository (requires a real FUSE kernel).
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct MountGuard {
    child: Child,
    mountpoint: PathBuf,
    unmounted: bool,
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if !self.unmounted {
            let _ = Command::new("timeout")
                .args(["10", "fusermount3", "-uz"])
                .arg(&self.mountpoint)
                .status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Regression: Git needs writable index/ref lock paths while source history stays hidden.
#[test]
fn regression_fuse_git_synthetic_overlay_status_diff_log_add_stash() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse missing");
        return;
    }
    for tool in ["git", "fusermount3", "timeout", "bash", "grep", "wc"] {
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!("skip: {tool} missing");
            return;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo_path = root.join("repo");
    let repo = git2::Repository::init(&repo_path).unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder
        .insert("code.txt", repo.blob(b"before\n").unwrap(), 0o100644)
        .unwrap();
    let sig = git2::Signature::new(
        "fixture",
        "fixture@example.test",
        &git2::Time::new(1_600_000_000, 0),
    )
    .unwrap();
    let tree = repo.find_tree(builder.write().unwrap()).unwrap();
    let first = repo
        .commit(Some("HEAD"), &sig, &sig, "base", &tree, &[])
        .unwrap();
    let fix_blob = repo.blob(b"secret future fix\n").unwrap();
    builder.insert("fix", fix_blob, 0o100644).unwrap();
    let tree = repo.find_tree(builder.write().unwrap()).unwrap();
    let second = repo
        .commit(
            Some("HEAD"),
            &sig,
            &sig,
            "fix",
            &tree,
            &[&repo.find_commit(first).unwrap()],
        )
        .unwrap();
    let mnt = root.join("mnt");
    let overlay = root.join("overlay");
    fs::create_dir(&mnt).unwrap();
    fs::create_dir(&overlay).unwrap();
    let log = fs::File::create(root.join("daemon.log")).unwrap();
    let binary = std::env::var_os("RATARMOUNT_TEST_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_ratarmount").into());
    let child = Command::new(binary)
        .args([
            "-f",
            "--git-ref",
            &first.to_string(),
            "--git-synthetic-head",
            "-w",
        ])
        .arg(&overlay)
        .arg(&repo_path)
        .arg(&mnt)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut guard = MountGuard {
        child,
        mountpoint: mnt.clone(),
        unmounted: false,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
        if mounts
            .lines()
            .any(|line| line.split_whitespace().nth(4) == mnt.to_str())
        {
            break;
        }
        assert!(
            guard.child.try_wait().unwrap().is_none(),
            "daemon exited: {}",
            fs::read_to_string(root.join("daemon.log")).unwrap()
        );
        assert!(Instant::now() < deadline, "mount timed out");
        thread::sleep(Duration::from_millis(50));
    }
    // Run every potentially blocking filesystem operation in a bounded child.
    let script = r#"
set -euo pipefail
cd "$1"
test -z "$(git status --porcelain)"
test "$(git log --oneline | wc -l)" -eq 1
test -z "$(git reflog)"
objects=$(git cat-file --batch-all-objects --batch-check)
[[ "$objects" != *"$2"* && "$objects" != *"$3"* ]]
printf 'agent edit\n' > code.txt
git diff | grep -q '+agent edit'
git add code.txt
git diff --cached | grep -q '+agent edit'
printf 'other edit\n' > code.txt
git diff | grep -q '+other edit'
git -c user.name=Agent -c user.email=agent@example.test stash push -m attempt
test -z "$(git status --porcelain)"
git stash pop
git diff | grep -q '+other edit'
test "$(git log --oneline | wc -l)" -eq 1
"#;
    let output = Command::new("timeout")
        .args(["60", "bash", "-c", script, "git-cases"])
        .arg(&mnt)
        .arg(second.to_string())
        .arg(fix_blob.to_string())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Git cases {:?}:\n{}\n{}\ndaemon:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(root.join("daemon.log")).unwrap()
    );
    assert!(overlay.join(".git/index").is_file());
    assert_eq!(repo.head().unwrap().target(), Some(second));
    assert!(Command::new("timeout")
        .args(["10", "fusermount3", "-u"])
        .arg(&mnt)
        .status()
        .unwrap()
        .success());
    guard.unmounted = true;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = guard.child.try_wait().unwrap() {
            assert!(status.success(), "daemon exit: {status}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not exit after unmount"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
