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
//! So the launcher forks *before* opening databases or logs: [`fork_launcher`] runs
//! right after the mount point is planned and the FUSE backend is checked.
//! The child does all of the startup (journal recovery, the factory and its
//! index, the overlay and its lock, the control socket) with the caller's
//! stdio and session, so errors and progress are printed as before. The
//! launcher holds no database and only supervises: it relays the child's exit
//! status while the child starts, and once the child [`detach`]es (right
//! before it serves) it waits for the mount exactly as the old forked parent
//! did. No lock is ever handed over, so there is no window between a release
//! and a re-acquire.

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, setsid, ForkResult, Pid};

/// The child's end of the readiness pipe, taken by [`detach`].
static READY: Mutex<Option<OwnedFd>> = Mutex::new(None);

/// The child the launcher forwards SIGINT, SIGTERM and SIGHUP to while it
/// starts (0: none).
static CHILD: AtomicI32 = AtomicI32::new(0);
static STARTUP_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// How long the launcher waits for the mount once the child detached (the
/// old forked parent's bound).
const MOUNT_WAIT: Duration = Duration::from_secs(30);

/// The byte [`detach`] writes to the readiness pipe.
const READY_BYTE: u8 = b'R';

/// A pipe whose ends are both close-on-exec. `pipe` then `FD_CLOEXEC`
/// (portable; there is no `pipe2` on macOS): the launcher calls this before
/// any thread exists, so nothing can fork or exec in between.
fn cloexec_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let pipe = nix::unistd::pipe()?;
    for fd in [&pipe.0, &pipe.1] {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok(pipe)
}

/// Fork the serving process. Returns only in the child; the launcher exits
/// with the status [`supervise`] decides.
pub(crate) fn fork_launcher(mp: &Path) {
    fork_launcher_with(mp, || {});
}

fn fork_launcher_with(mp: &Path, before_forwarding: impl FnOnce()) {
    // O_CLOEXEC keeps the write end out of every program the child runs
    // (fusermount3, git, tar), so a child's exit is always seen as EOF.
    let (read, write) = match cloexec_pipe() {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("error: pipe failed: {e}");
            std::process::exit(1);
        }
    };
    // A signal to the launcher between fork and handler installation must
    // stay pending: otherwise it kills only the launcher and orphans startup.
    let blocked = BlockedSignals::new().unwrap_or_else(|e| {
        eprintln!("error: blocking launcher signals: {e}");
        std::process::exit(1);
    });
    // SAFETY: only synchronous argument/metadata/backend preflight ran. No
    // database or worker thread exists; the child continues startup on its own.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(write);
            before_forwarding();
            let forwarding = ForwardSignals::new(child).unwrap_or_else(|e| {
                eprintln!("error: forwarding launcher signals: {e}");
                stop_and_reap(child);
                std::process::exit(1);
            });
            drop(blocked);
            // A `:temp:` overlay, should one exist, is the child's.
            crate::relinquish_temp_overlay();
            std::process::exit(supervise(child, read, mp, MOUNT_WAIT, Some(forwarding)));
        }
        Ok(ForkResult::Child) => {
            drop(read);
            *READY.lock().unwrap_or_else(|e| e.into_inner()) = Some(write);
            drop(blocked);
        }
        Err(e) => {
            eprintln!("error: fork failed: {e}");
            std::process::exit(1);
        }
    }
}

/// In the forked child, right before serving: leave the caller's session,
/// drop its stdio and tell the launcher to wait
/// for the mount. The databases stay open and locked in this process.
pub(crate) fn detach() {
    setsid().unwrap_or_else(|e| {
        eprintln!("error: detaching mount session: {e}");
        std::process::exit(1);
    });
    // The logger owns a separate descriptor; --log-file does not redirect
    // stdout/stderr. Keeping these pipes open hangs callers using output().
    crate::redirect_stdio_to_null().unwrap_or_else(|e| {
        eprintln!("error: detaching mount stdio: {e}");
        std::process::exit(1);
    });
    match READY.lock().unwrap_or_else(|e| e.into_inner()).take() {
        Some(fd) => {
            loop {
                // SAFETY: one byte from a valid buffer to an owned descriptor.
                if unsafe { libc::write(fd.as_raw_fd(), [READY_BYTE].as_ptr().cast(), 1) } == 1 {
                    break;
                }
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    log::error!("daemon launcher disappeared before readiness: {e}");
                    std::process::exit(1);
                }
            }
            drop(fd);
        }
        None => {
            // Only reached when `fork_launcher` did not run for a daemonized
            // mount: a mismatch of its condition with the serving paths.
            log::error!("daemonized mount without a launcher; nobody waits for the mount");
            std::process::exit(1);
        }
    }
}

extern "C" fn forward_signal(signal: libc::c_int) {
    STARTUP_SIGNAL.store(signal, Ordering::SeqCst);
    let child = CHILD.load(Ordering::SeqCst);
    if child > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe { libc::kill(child, signal) };
    }
}

const FORWARDED: [Signal; 3] = [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP];

struct BlockedSignals(SigSet);

impl BlockedSignals {
    fn new() -> nix::Result<Self> {
        let mut signals = SigSet::empty();
        for signal in FORWARDED {
            signals.add(signal);
        }
        signals.thread_swap_mask(SigmaskHow::SIG_BLOCK).map(Self)
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        self.0
            .thread_set_mask()
            .expect("restore launcher signal mask");
    }
}

struct ForwardSignals(Vec<(Signal, SigAction)>);

impl ForwardSignals {
    /// Called with FORWARDED blocked, before the launcher unmasks signals.
    fn new(child: Pid) -> nix::Result<Self> {
        let mut saved = Self(Vec::new());
        STARTUP_SIGNAL.store(0, Ordering::SeqCst);
        CHILD.store(child.as_raw(), Ordering::SeqCst);
        let action = SigAction::new(
            SigHandler::Handler(forward_signal),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        for signal in FORWARDED {
            // SAFETY: the handler only reads an atomic and calls kill(2).
            let inherited = unsafe { sigaction(signal, &action) }?;
            saved.0.push((signal, inherited));
            if inherited.handler() == SigHandler::SigIgn {
                // Background jobs/nohup may inherit ignored signals. Do not
                // turn them into startup cancellation in the launcher.
                unsafe { sigaction(signal, &inherited) }?;
            }
        }
        Ok(saved)
    }
}

impl Drop for ForwardSignals {
    fn drop(&mut self) {
        let _blocked = BlockedSignals::new().expect("block launcher signals");
        CHILD.store(0, Ordering::SeqCst);
        for (signal, action) in &self.0 {
            // SAFETY: restore the exact inherited disposition, including SIG_IGN.
            unsafe { sigaction(*signal, action) }.expect("restore launcher signal handler");
        }
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
fn supervise(
    child: Pid,
    read: OwnedFd,
    mp: &Path,
    mount_wait: Duration,
    forwarding: Option<ForwardSignals>,
) -> i32 {
    let mut byte = [0u8; 1];
    let ready = loop {
        // Some startup paths already installed graceful serving handlers.
        // They can absorb TERM before FUSE exists, so forwarding alone does
        // not cancel startup. Retire the child even if it announces readiness.
        if forwarding.is_some() {
            let signal = STARTUP_SIGNAL.load(Ordering::SeqCst);
            if signal != 0 {
                drop(forwarding);
                stop_and_reap(child);
                if crate::is_fuse_mount(mp) {
                    let _ = ratarmount_fuse::unmount(mp);
                }
                return 128 + signal;
            }
        }
        let mut poll = libc::pollfd {
            fd: read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Bounded poll also observes a signal delivered just before this
        // call; a restarted blocking read could otherwise wait forever.
        if unsafe { libc::poll(&mut poll, 1, 50) } <= 0 {
            continue;
        }
        if forwarding.is_some() && STARTUP_SIGNAL.load(Ordering::SeqCst) != 0 {
            continue;
        }
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
    // EOF also means the child has gone. Stop forwarding before reaping it,
    // so a late signal cannot target a PID that waitpid has made reusable.
    drop(forwarding);
    if !ready {
        return wait_blocking(child);
    }
    // Detached: the old forked parent's behaviour (a signal to the launcher
    // no longer reaches the serving process).
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
    // Do not leave a child that can mount later, or keep overlay locks after
    // the launcher has reported failure. Stop it before the final unmount.
    stop_and_reap(child);
    let _ = ratarmount_fuse::unmount(mp);
    1
}

fn stop_and_reap(child: Pid) {
    let _ = nix::sys::signal::kill(child, Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(status) if exit_code(status).is_some() => return,
            Err(nix::errno::Errno::ECHILD) => return,
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let _ = nix::sys::signal::kill(child, Signal::SIGKILL);
    wait_blocking(child);
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
                let code = supervise(child, read, mp, wait, None);
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

    /// Regression: both readiness descriptors must close across exec, without
    /// raw descriptor adoption or a generic fcntl inventory exception.
    #[test]
    fn regression_daemon_launcher_pipe_cloexec() {
        let (read, write) = cloexec_pipe().unwrap();
        for fd in [&read, &write] {
            assert!(rustix::io::fcntl_getfd(fd)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC));
        }
    }

    /// Regression: a timed-out child kept serving/holding locks after the
    /// launcher failed. Even a child ignoring TERM must be killed and reaped.
    #[test]
    fn regression_daemon_launcher_timeout_reaps_child() {
        let _processes = ratarmount_index::test_process::spawning();
        let dir = tempfile::tempdir().unwrap();
        let (read, write) = cloexec_pipe().unwrap();
        match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => {
                drop(write);
                let started = Instant::now();
                let code = supervise(child, read, dir.path(), Duration::ZERO, None);
                let reaped = waitpid(child, Some(WaitPidFlag::WNOHANG));
                // Cleanup on failure too, before asserting.
                if reaped != Err(nix::errno::Errno::ECHILD) {
                    let _ = nix::sys::signal::kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                }
                assert_eq!(code, 1);
                assert_eq!(reaped, Err(nix::errno::Errno::ECHILD));
                assert!(started.elapsed() < Duration::from_secs(5));
            }
            ForkResult::Child => unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                libc::write(write.as_raw_fd(), [READY_BYTE].as_ptr().cast(), 1);
                loop {
                    libc::pause();
                }
            },
        }
    }

    /// Regression: a signal arriving just after fork killed only the launcher,
    /// leaving startup running. Exercise the actual fork path in an isolated
    /// process so the test runner's handlers and exit status remain untouched.
    #[test]
    fn regression_daemon_launcher_pending_signal_is_relayed() {
        const CHILD_CASE: &str = "RATARMOUNT_TEST_DAEMON_PENDING_SIGNAL";
        if let Some(case) = std::env::var_os(CHILD_CASE) {
            if case == "caught" {
                // Temporary overlays/live commits can already have installed
                // this handler during startup. Forwarding must still cancel.
                crate::overlay_commit::install_term_signal_flag();
            }
            if case == "ignored" {
                unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
            }
            // The test runner starts only this test. The forked child's path
            // below uses only async-signal-safe calls before it is terminated.
            let mp =
                std::path::PathBuf::from(std::env::var_os("RATARMOUNT_TEST_DAEMON_MP").unwrap());
            fork_launcher_with(&mp, || unsafe {
                libc::raise(libc::SIGTERM);
            });
            unsafe {
                if case == "ignored" {
                    libc::_exit(0);
                }
                libc::alarm(5);
                loop {
                    libc::pause();
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        for case in ["default", "caught", "ignored"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "daemon::tests::regression_daemon_launcher_pending_signal_is_relayed",
                ])
                .env(CHILD_CASE, case)
                .env("RATARMOUNT_TEST_DAEMON_MP", dir.path())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("launcher did not relay the pending signal");
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            // A launcher killed before installing its handler has signal(), not
            // code() == 143; successful supervision also reaps the serving child.
            assert_eq!(
                status.code(),
                Some(if case == "ignored" {
                    0
                } else {
                    128 + libc::SIGTERM
                })
            );
        }
    }

    /// Regression: an absent launcher was ignored and the child mounted even
    /// though nobody could report success or supervise its startup.
    #[test]
    fn regression_daemon_launcher_disappearance_cancels_child() {
        const CHILD_CASE: &str = "RATARMOUNT_TEST_DAEMON_LOST_LAUNCHER";
        if std::env::var_os(CHILD_CASE).is_some() {
            let (read, write) = cloexec_pipe().unwrap();
            drop(read);
            *READY.lock().unwrap() = Some(write);
            detach();
            std::process::exit(0);
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daemon::tests::regression_daemon_launcher_disappearance_cancels_child",
            ])
            .env(CHILD_CASE, "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(1));
    }
}
