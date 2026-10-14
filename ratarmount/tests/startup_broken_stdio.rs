//! #93: a launcher that hands ratarmount a stdout/stderr pipe with no reader
//! must not make startup die with exit 101 (`println!` panic on EPIPE).
//! Linux only: the dead-pipe probe relies on Linux `poll` reporting POLLERR
//! for a pipe write end without readers.
#![cfg(target_os = "linux")]

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A pipe write end whose read end is already closed (and was CLOEXEC, so the
/// child cannot inherit a reader).
fn widowed_pipe() -> OwnedFd {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(r);
    w
}

fn make_tar(dir: &Path) -> Option<PathBuf> {
    std::fs::create_dir_all(dir.join("d")).unwrap();
    std::fs::write(dir.join("d/a"), b"hello\n").unwrap();
    let tar = dir.join("t.tar");
    match Command::new("tar")
        .arg("-cf")
        .arg(&tar)
        .arg("-C")
        .arg(dir)
        .arg("d")
        .status()
    {
        Ok(st) if st.success() => Some(tar),
        r => {
            eprintln!("skip: cannot build test tar with `tar`: {r:?}");
            None
        }
    }
}

fn run(args: &[&std::ffi::OsStr], stdout: Stdio, stderr: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .output()
        .unwrap()
}

fn no_mount(tmp: &Path, stdout: Stdio, stderr: Stdio) -> Option<(Output, PathBuf)> {
    let tar = make_tar(tmp)?;
    let idx = tmp.join("t.index.sqlite");
    let out = run(
        &[
            "--no-mount".as_ref(),
            "--index-file".as_ref(),
            idx.as_os_str(),
            tar.as_os_str(),
        ],
        stdout,
        stderr,
    );
    Some((out, idx))
}

/// Regression: #93, a widowed stdout pipe made startup exit 101.
#[test]
fn no_mount_with_dead_stdout_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((out, idx)) = no_mount(tmp.path(), Stdio::from(widowed_pipe()), Stdio::piped()) else {
        return;
    };
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(idx.exists());
}

#[test]
fn no_mount_with_dead_stdout_and_stderr_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((out, idx)) = no_mount(
        tmp.path(),
        Stdio::from(widowed_pipe()),
        Stdio::from(widowed_pipe()),
    ) else {
        return;
    };
    assert_eq!(out.status.code(), Some(0));
    assert!(idx.exists());
}

#[test]
fn error_with_dead_stderr_is_not_a_panic() {
    // A missing archive makes main eprintln! an error; with fd 2 dead that
    // must exit with the normal failure code, not 101.
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.tar");
    let out = run(
        &["--no-mount".as_ref(), missing.as_os_str()],
        Stdio::from(widowed_pipe()),
        Stdio::from(widowed_pipe()),
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn no_mount_harness_line_prints_once_on_live_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((out, idx)) = no_mount(tmp.path(), Stdio::piped(), Stdio::piped()) else {
        return;
    };
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let want = format!(
        "Successfully loaded offset dictionary from {}",
        idx.display()
    );
    assert_eq!(stdout.lines().filter(|l| *l == want).count(), 1, "{stdout}");
}
