//! Daemonizing a FUSE mount without losing its SQLite locks (#183).
//!
//! POSIX `fcntl` record locks belong to a process and are not inherited by a
//! `fork()` child. SQLite takes them on the overlay database (exclusive
//! locking mode: held for the connection's life) and on a WAL index (its
//! shared lock). A mount that opened those databases and then forked served
//! from a child that held none of them: once the launcher exited, any other
//! process could lock and write the live overlay database, or treat the
//! serving child's live `-journal` as hot and roll back a write the child had
//! committed. SQLite also documents carrying an open connection across
//! `fork()` as unsupported.
//!
//! So the launcher forks *before* it opens anything: [`fork_launcher`] runs
//! right after the mount point is planned and the FUSE backend is checked.
//! The child does all of the startup (journal recovery, the factory and its
//! index, the overlay and its lock, the control socket) with the caller's
//! stdio and session, so errors and progress are printed as before. The
//! launcher holds no database and only supervises: it relays the child's exit
//! status while the child starts, and once the child [`detach`]es (right
//! before it serves) it waits for the mount exactly as the old forked parent
//! did. No lock is ever handed over, so there is no window between a release
//! and a re-acquire.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, setsid, ForkResult, Pid};

/// The child's end of the readiness pipe, taken by [`detach`].
static READY: Mutex<Option<OwnedFd>> = Mutex::new(None);

/// The child the launcher forwards SIGINT, SIGTERM and SIGHUP to while it
/// starts (0: none).
static CHILD: AtomicI32 = AtomicI32::new(0);

/// How long the launcher waits for the mount once the child detached (the
/// old forked parent's bound).
const MOUNT_WAIT: Duration = Duration::from_secs(30);

/// The byte [`detach`] writes to the readiness pipe.
const READY_BYTE: u8 = b'R';

/// A pipe whose ends are both close-on-exec. `pipe` then `FD_CLOEXEC`
/// (portable; there is no `pipe2` on macOS): the launcher calls this before
/// any thread exists, so nothing can fork or exec in between.
fn cloexec_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for both descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pipe returned two fresh descriptors that nothing else owns.
    let pipe = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&pipe.0, &pipe.1] {
        // SAFETY: sets a flag on an owned descriptor.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(pipe)
}

/// Fork the serving process. Returns only in the child; the launcher exits
/// with the status [`supervise`] decides.
pub(crate) fn fork_launcher(mp: &Path) {
    // O_CLOEXEC keeps the write end out of every program the child runs
    // (fusermount3, git, tar), so a child's exit is always seen as EOF.
    let (read, write) = match cloexec_pipe() {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("error: pipe failed: {e}");
            std::process::exit(1);
        }
    };
    // SAFETY: nothing has been opened or started that the child must not
    // inherit; the child continues startup on its own.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(write);
            // A `:temp:` overlay, should one exist, is the child's.
            crate::relinquish_temp_overlay();
            std::process::exit(supervise(child, read, mp, MOUNT_WAIT, true));
        }
        Ok(ForkResult::Child) => {
            drop(read);
            *READY.lock().unwrap_or_else(|e| e.into_inner()) = Some(write);
        }
        Err(e) => {
            eprintln!("error: fork failed: {e}");
            std::process::exit(1);
        }
    }
}

/// In the forked child, right before serving: leave the caller's session,
/// drop its stdio (unless a log file holds it) and tell the launcher to wait
/// for the mount. The databases stay open and locked in this process.
pub(crate) fn detach(has_log_file: bool) {
    let _ = setsid();
    if !has_log_file {
        let _ = crate::redirect_stdio_to_null();
    }
    match READY.lock().unwrap_or_else(|e| e.into_inner()).take() {
        Some(fd) => {
            // SAFETY: one byte from a valid buffer to an owned descriptor.
            let _ = unsafe { libc::write(fd.as_raw_fd(), [READY_BYTE].as_ptr().cast(), 1) };
            drop(fd);
        }
        None => {
            // Only reached when `fork_launcher` did not run for a daemonized
            // mount: a mismatch of its condition with the serving paths.
            log::error!("daemonized mount without a launcher; nobody waits for the mount");
        }
    }
}

extern "C" fn forward_signal(signal: libc::c_int) {
    let child = CHILD.load(Ordering::SeqCst);
    if child > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe { libc::kill(child, signal) };
    }
}

const FORWARDED: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

fn set_forwarding(on: bool) {
    let handler = if on {
        forward_signal as extern "C" fn(libc::c_int) as libc::sighandler_t
    } else {
        libc::SIG_DFL
    };
    for signal in FORWARDED {
        // SAFETY: installs a handler that only calls kill(2), or the default.
        unsafe { libc::signal(signal, handler) };
    }
}

/// The exit status a shell reports for `status`.
fn exit_code(status: WaitStatus) -> Option<i32> {
    match status {
        WaitStatus::Exited(_, code) => Some(code),
        WaitStatus::Signaled(_, signal, _) => Some(128 + signal as i32),
        _ => None,
    }
}

fn wait_blocking(child: Pid) -> i32 {
    loop {
        match waitpid(child, None) {
            Ok(status) => {
                if let Some(code) = exit_code(status) {
                    return code;
                }
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => {
                eprintln!("error: waiting for the mount process {child}: {e}");
                return 1;
            }
        }
    }
}

/// The launcher: relay the child's startup result, then wait for its mount.
/// While the child starts it shares the caller's stdio and process group, so
/// its own errors are printed and its status is the launcher's. Once it has
/// detached its stdio is gone: the launcher reports for it.
fn supervise(child: Pid, read: OwnedFd, mp: &Path, mount_wait: Duration, forward: bool) -> i32 {
    if forward {
        CHILD.store(child.as_raw(), Ordering::SeqCst);
        set_forwarding(true);
    }
    let mut byte = [0u8; 1];
    let ready = loop {
        // SAFETY: reads at most one byte into a valid buffer.
        let n = unsafe { libc::read(read.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        if n == 1 {
            break byte[0] == READY_BYTE;
        }
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        // EOF: the child exited (or failed) before it detached.
        break false;
    };
    drop(read);
    if !ready {
        return wait_blocking(child);
    }
    // Detached: the old forked parent's behaviour (a signal to the launcher
    // no longer reaches the serving process).
    if forward {
        set_forwarding(false);
    }
    let start = Instant::now();
    while start.elapsed() < mount_wait {
        if crate::is_fuse_mount(mp) {
            return 0;
        }
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::EINTR) => {}
            Ok(status) => {
                if let Some(code) = exit_code(status) {
                    // A child that served and unmounted before this poll
                    // saw the mount exits 0.
                    if code != 0 {
                        eprintln!(
                            "error: the mount process {child} exited with status {code} before {} was mounted",
                            mp.display()
                        );
                    }
                    return code;
                }
            }
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!(
        "error: timed out waiting for mount at {} (child pid {child})",
        mp.display()
    );
    let _ = ratarmount_fuse::unmount(mp);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fork a child that runs `child` (as the daemonized mount would) and
    /// return what the launcher decides.
    fn launch(child: impl FnOnce(OwnedFd), mp: &Path, wait: Duration) -> i32 {
        let _processes = ratarmount_index::test_process::spawning();
        let (read, write) = cloexec_pipe().unwrap();
        match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => {
                drop(write);
                // The test runner's own signal dispositions stay as they are.
                let code = supervise(child, read, mp, wait, false);
                let _ = waitpid(child, None);
                code
            }
            ForkResult::Child => {
                drop(read);
                child(write);
                unsafe { libc::_exit(0) }
            }
        }
    }

    /// Regression (#183): a startup failure in the forked child (before it
    /// detaches) is the launcher's exit status, as when one process did both.
    #[test]
    fn regression_daemon_launcher_relays_startup_status() {
        let dir = tempfile::tempdir().unwrap();
        let code = launch(
            |_fd| unsafe { libc::_exit(2) },
            dir.path(),
            Duration::from_secs(5),
        );
        assert_eq!(code, 2);
        let code = launch(
            |_fd| unsafe {
                libc::raise(libc::SIGKILL);
            },
            dir.path(),
            Duration::from_secs(5),
        );
        assert_eq!(code, 128 + libc::SIGKILL);
        // Exiting 0 before detaching (nothing to serve) is success.
        let code = launch(|_fd| {}, dir.path(), Duration::from_secs(5));
        assert_eq!(code, 0);
    }

    /// Regression (#183): after the child detached, its failure before the
    /// mount appeared is reported with its status instead of waiting out the
    /// mount timeout; a child that never mounts times out with status 1.
    #[test]
    fn regression_daemon_launcher_after_detach() {
        let dir = tempfile::tempdir().unwrap();
        let start = Instant::now();
        let code = launch(
            |fd| {
                unsafe { libc::write(fd.as_raw_fd(), [READY_BYTE].as_ptr().cast(), 1) };
                drop(fd);
                std::thread::sleep(Duration::from_millis(100));
                unsafe { libc::_exit(3) }
            },
            dir.path(),
            Duration::from_secs(30),
        );
        assert_eq!(code, 3);
        assert!(start.elapsed() < Duration::from_secs(10));
        let code = launch(
            |fd| {
                unsafe { libc::write(fd.as_raw_fd(), [READY_BYTE].as_ptr().cast(), 1) };
                drop(fd);
                std::thread::sleep(Duration::from_secs(3));
            },
            dir.path(),
            Duration::from_millis(300),
        );
        assert_eq!(code, 1);
    }
}
