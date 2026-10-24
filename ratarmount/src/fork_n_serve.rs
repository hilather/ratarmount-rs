//! N FUSE sessions in one process, and the daemon handoff in front of them.
//!
//! Foreground (`-f`) keeps the locks taken at overlay open and does not fork.
//! Daemon mode closes every parent SQLite connection, takes the worker-free
//! permit, forks once, and the child reacquires every top before any session.
//! Failure cleanup is `fusermount -u` with no `-z`, and only for a mount this
//! process reported whose `(st_dev, st_ino)` still matches.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, setsid, ForkResult, Pid};
use ratarmount_compositing::WriteOverlay;
use ratarmount_core::MountSource;
use ratarmount_fuse::oplog::MountActivity;
use ratarmount_fuse::PassthroughOptions;

use crate::fork_n;

pub(crate) struct TopHandle {
    pub name: String,
    pub overlay_dir: PathBuf,
    pub mountpoint: PathBuf,
    pub overlay: Arc<WriteOverlay>,
}

/// Two counters so a later INT does not erase a pending TERM.
struct ForkNSignalState;

static SIGINT_SEEN: AtomicU64 = AtomicU64::new(0);
static SIGTERM_SEEN: AtomicU64 = AtomicU64::new(0);
static WATCHER_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl ForkNSignalState {
    fn install() {
        SIGINT_SEEN.store(0, Ordering::SeqCst);
        SIGTERM_SEEN.store(0, Ordering::SeqCst);
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_fork_n_signal as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        }
    }

    fn sigint() -> u64 {
        SIGINT_SEEN.load(Ordering::SeqCst)
    }

    fn sigterm() -> u64 {
        SIGTERM_SEEN.load(Ordering::SeqCst)
    }
}

extern "C" fn on_fork_n_signal(signal: libc::c_int) {
    if signal == libc::SIGINT {
        SIGINT_SEEN.fetch_add(1, Ordering::SeqCst);
    } else if signal == libc::SIGTERM {
        SIGTERM_SEEN.fetch_add(1, Ordering::SeqCst);
    }
}

pub(crate) fn serve(
    args: &crate::Args,
    tops: Vec<TopHandle>,
    foreground: bool,
    direct_io: bool,
) -> ! {
    if foreground {
        ForkNSignalState::install();
        // Locks were taken by `open_with_frozen_excludes`. Recheck hardlinks
        // before any session. No second quota scan.
        hold_after_locks();
        if let Err(message) = recheck_hardlinks(&tops) {
            eprintln!("error: {message}");
            process::exit(2);
        }
        ratarmount_core::fork_n::set_phase(ratarmount_core::fork_n::WorkerPhase::Serving);
        mount_cohort(args, &tops, direct_io, None);
    }
    daemon_handoff(args, tops, direct_io);
}

fn daemon_handoff(args: &crate::Args, tops: Vec<TopHandle>, direct_io: bool) -> ! {
    for top in &tops {
        if let Err(err) = top.overlay.release_connection() {
            eprintln!("error: fork-n cannot release {}: {err}", top.name);
            process::exit(2);
        }
    }
    if let Err(message) = ratarmount_index::close_disk_sqlite_for_fork() {
        eprintln!("error: {message}");
        process::exit(2);
    }
    if let Err(message) = ratarmount_core::fork_n::worker_free_permit() {
        eprintln!("error: {message}");
        process::exit(2);
    }
    let (parent_end, child_end) = match UnixStream::pair() {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("error: fork-n report pipe: {err}");
            process::exit(1);
        }
    };
    ForkNSignalState::install();
    let parent_sigint = ForkNSignalState::sigint();
    let parent_sigterm = ForkNSignalState::sigterm();
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(child_end);
            #[cfg(debug_assertions)]
            if let Ok(path) = std::env::var("RATARMOUNT_TEST_FORK_N_CHILD_PID") {
                let _ = fs::write(path, format!("{child}\n"));
            }
            parent_loop(parent_end, child, parent_sigint, parent_sigterm);
        }
        Ok(ForkResult::Child) => {
            drop(parent_end);
            let _ = setsid();
            // Counters were copied at fork. The child starts from zero and
            // the inherited handler keeps incrementing this address space.
            SIGINT_SEEN.store(0, Ordering::SeqCst);
            SIGTERM_SEEN.store(0, Ordering::SeqCst);
            if let Err(message) = ratarmount_index::reopen_disk_sqlite_after_fork() {
                eprintln!("error: {message}");
                process::exit(2);
            }
            if let Err(message) = child_locks(&tops) {
                eprintln!("error: {message}");
                process::exit(2);
            }
            hold_after_locks();
            if let Err(message) = recheck_hardlinks(&tops) {
                eprintln!("error: {message}");
                process::exit(2);
            }
            ratarmount_core::fork_n::set_phase(ratarmount_core::fork_n::WorkerPhase::Serving);
            mount_cohort(args, &tops, direct_io, Some(child_end));
        }
        Err(err) => {
            eprintln!("error: fork failed: {err}");
            process::exit(1);
        }
    }
}

fn child_locks(tops: &[TopHandle]) -> Result<(), String> {
    for top in tops {
        top.overlay
            .reacquire_exclusive()
            .map_err(|err| format!("fork-n cannot lock {}: {err}", top.name))?;
        top.overlay
            .rescan_quota()
            .map_err(|err| format!("fork-n cannot rescan {}: {err}", top.name))?;
    }
    Ok(())
}

fn recheck_hardlinks(tops: &[TopHandle]) -> Result<(), String> {
    for top in tops {
        fork_n::walk_top(&top.overlay_dir)?;
    }
    Ok(())
}

fn hold_after_locks() {
    #[cfg(debug_assertions)]
    {
        let Ok(hold) = std::env::var("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_LOCKS") else {
            return;
        };
        if let Ok(marker) = std::env::var("RATARMOUNT_TEST_FORK_N_LOCK_MARKER") {
            let _ = fs::write(&marker, format!("locks-held\n{}\n", process::id()));
        }
        let start = Instant::now();
        while Path::new(&hold).exists() && start.elapsed() < Duration::from_secs(60) {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

struct Report {
    name: String,
    dev: u64,
    ino: u64,
    mount_id: u64,
    path: PathBuf,
}

fn mount_cohort(
    args: &crate::Args,
    tops: &[TopHandle],
    direct_io: bool,
    mut report_to: Option<UnixStream>,
) -> ! {
    let passthrough = PassthroughOptions {
        mode: args.passthrough,
        copy: args.passthrough_copy,
        copy_max: args.passthrough_copy_max,
        copy_total_max: args.passthrough_copy_total_max,
    };
    let readahead = ratarmount_fuse::parse_byte_size(&args.readahead).unwrap_or(0);
    let fuse_opts = args.fuse.clone();
    let activity = MountActivity::default();
    let mut reports: Vec<Report> = Vec::new();
    let mut handles = Vec::new();
    for top in tops {
        if ForkNSignalState::sigint() > 0 || ForkNSignalState::sigterm() > 0 {
            fail_partial(&reports, report_to.as_mut(), std::mem::take(&mut handles));
        }
        if fail_mount_is(&top.name) {
            fail_partial(&reports, report_to.as_mut(), std::mem::take(&mut handles));
        }
        let source: Arc<dyn MountSource> = top.overlay.clone();
        let mountpoint = top.mountpoint.clone();
        let overlay = Arc::clone(&top.overlay);
        let opts = fuse_opts.clone();
        let activity = activity.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let result = super::mount_blocking(
                source,
                &mountpoint,
                true,
                true,
                Some(overlay),
                &opts,
                readahead,
                passthrough,
                direct_io,
                activity,
            );
            let _ = tx.send(result.map_err(|err| err.to_string()));
        });
        let mounted = wait_mounted(&top.mountpoint, &rx);
        if let Err(message) = mounted {
            eprintln!("error: fork-n mount {}: {message}", top.name);
            handles.push(handle);
            fail_partial(&reports, report_to.as_mut(), std::mem::take(&mut handles));
        }
        let (dev, ino) = match fs::metadata(&top.mountpoint) {
            Ok(meta) => (meta.dev(), meta.ino()),
            Err(err) => {
                eprintln!(
                    "error: fork-n cannot stat {}: {err}",
                    top.mountpoint.display()
                );
                handles.push(handle);
                fail_partial(&reports, report_to.as_mut(), std::mem::take(&mut handles));
            }
        };
        let mount_id = mount_id_of(&top.mountpoint);
        let report = Report {
            name: top.name.clone(),
            dev,
            ino,
            mount_id,
            path: top.mountpoint.clone(),
        };
        if let Some(pipe) = report_to.as_mut() {
            let _ = writeln!(
                pipe,
                "report {} {dev} {ino} {mount_id} {}",
                report.name,
                report.path.display()
            );
            let _ = pipe.flush();
        }
        reports.push(report);
        handles.push(handle);
        hold_after_report(&top.name);
    }
    if ForkNSignalState::sigint() > 0 || ForkNSignalState::sigterm() > 0 {
        fail_partial(&reports, report_to.as_mut(), std::mem::take(&mut handles));
    }
    if let Some(pipe) = report_to.as_mut() {
        let _ = writeln!(pipe, "ready");
        let _ = pipe.flush();
    }
    let paths: Vec<PathBuf> = tops.iter().map(|t| t.mountpoint.clone()).collect();
    WATCHER_STOP.store(false, Ordering::SeqCst);
    let watcher = thread::spawn(move || signal_watcher(paths));
    for handle in handles {
        let _ = handle.join();
    }
    WATCHER_STOP.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    process::exit(0);
}

fn wait_mounted(
    path: &Path,
    rx: &std::sync::mpsc::Receiver<Result<(), String>>,
) -> Result<(), String> {
    let start = Instant::now();
    let bound = Duration::from_secs(30);
    loop {
        if let Ok(result) = rx.try_recv() {
            return result;
        }
        if super::wait_until_mounted(path, Duration::from_millis(50)) {
            return Ok(());
        }
        if start.elapsed() >= bound {
            return Err(format!("timed out waiting for {}", path.display()));
        }
    }
}

fn fail_partial(
    reports: &[Report],
    pipe: Option<&mut UnixStream>,
    handles: Vec<thread::JoinHandle<()>>,
) -> ! {
    // Reports line up with the sessions already started. A mount that failed
    // before or during Session::new has a handle and no report.
    let mut unmounted = vec![false; handles.len()];
    for (index, report) in reports.iter().enumerate() {
        if still_ours(report) {
            fusermount_once(&report.path);
            if index < unmounted.len() {
                unmounted[index] = true;
            }
        }
    }
    if let Some(pipe) = pipe {
        let _ = writeln!(pipe, "cleanup");
        let _ = pipe.flush();
    }
    // Join only the sessions this process unmounted. A stomped mount is not
    // ours; waiting for it never returns. Dropping that handle and exiting
    // abandons the thread with the process. Do not lazy-unmount here.
    for (handle, did_unmount) in handles.into_iter().zip(unmounted) {
        if did_unmount {
            let _ = handle.join();
        }
    }
    process::exit(1);
}

fn still_ours(report: &Report) -> bool {
    let Ok(meta) = fs::metadata(&report.path) else {
        return false;
    };
    if meta.dev() != report.dev || meta.ino() != report.ino {
        return false;
    }
    report.mount_id == 0 || mount_id_of(&report.path) == report.mount_id
}

fn fusermount_once(path: &Path) {
    #[cfg(debug_assertions)]
    if let Ok(bin) = std::env::var("RATARMOUNT_TEST_FUSERMOUNT") {
        let _ = Command::new(bin).arg("-u").arg(path).status();
        return;
    }
    let _ = Command::new("fusermount3")
        .arg("-u")
        .arg(path)
        .status()
        .or_else(|_| Command::new("fusermount").arg("-u").arg(path).status());
}

/// TERM unmounts with `-u`. Lazy `-z` runs only after a non-lazy attempt was
/// busy and a TERM is pending. INT alone never calls `unmount_lazy`.
fn signal_watcher(paths: Vec<PathBuf>) {
    let mut seen_int = 0u64;
    let mut seen_term = 0u64;
    while !WATCHER_STOP.load(Ordering::SeqCst) {
        let now_int = ForkNSignalState::sigint();
        let now_term = ForkNSignalState::sigterm();
        if now_int == seen_int && now_term == seen_term {
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        let fresh_term = now_term > seen_term;
        seen_int = now_int;
        seen_term = now_term;
        if !fresh_term {
            for path in &paths {
                fusermount_once(path);
            }
            continue;
        }
        for path in &paths {
            let busy = fusermount_once_busy(path);
            // Lazy only after a non-lazy attempt reported busy, and only for TERM.
            if busy {
                let _ = ratarmount_fuse::unmount_lazy(path);
            }
        }
    }
}

fn fusermount_once_busy(path: &Path) -> bool {
    #[cfg(debug_assertions)]
    if let Ok(bin) = std::env::var("RATARMOUNT_TEST_FUSERMOUNT") {
        let output = Command::new(bin).arg("-u").arg(path).output();
        return output.is_ok_and(|out| {
            !out.status.success()
                && String::from_utf8_lossy(&out.stderr)
                    .to_ascii_lowercase()
                    .contains("busy")
        });
    }
    let output = Command::new("fusermount3")
        .arg("-u")
        .arg(path)
        .output()
        .or_else(|_| Command::new("fusermount").arg("-u").arg(path).output());
    output.is_ok_and(|out| {
        !out.status.success()
            && String::from_utf8_lossy(&out.stderr)
                .to_ascii_lowercase()
                .contains("busy")
    })
}

fn parent_loop(pipe: UnixStream, child: Pid, base_int: u64, base_term: u64) -> ! {
    let _ = pipe.set_read_timeout(Some(Duration::from_millis(50)));
    let mut reader = BufReader::new(pipe);
    let mut reports: Vec<Report> = Vec::new();
    let mut saw_cleanup = false;
    let mut cancelled = false;
    let mut line = String::new();
    let started = Instant::now();
    let deadline = Duration::from_secs(45);
    loop {
        if started.elapsed() > deadline {
            let _ = kill(child, Signal::SIGKILL);
            cancelled = true;
            break;
        }
        let pending =
            ForkNSignalState::sigint() > base_int || ForkNSignalState::sigterm() > base_term;
        if pending {
            cancelled = true;
        }
        forward_launcher_signal(child, base_int, base_term);
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // Channel EOF before `ready` is cancellation. `ready` exits
                // the launcher, so this path has not accepted the cohort.
                cancelled = true;
                break;
            }
            Ok(_) => {
                let line = line.trim_end();
                if line == "ready" {
                    // Cancellation is sticky against a queued Ready.
                    if cancelled
                        || ForkNSignalState::sigint() > base_int
                        || ForkNSignalState::sigterm() > base_term
                    {
                        cancelled = true;
                        break;
                    }
                    process::exit(0);
                }
                if line == "cleanup" {
                    saw_cleanup = true;
                    continue;
                }
                if let Some(report) = parse_report(line) {
                    reports.push(report);
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::TimedOut
                    || err.kind() == io::ErrorKind::WouldBlock =>
            {
                continue;
            }
            Err(_) => {
                cancelled = true;
                break;
            }
        }
    }
    if cancelled {
        let _ = kill(child, Signal::SIGTERM);
    }
    let status = waitpid(child, None);
    let child_gone = matches!(
        status,
        Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _))
    );
    if child_gone
        && !saw_cleanup
        && (cancelled || matches!(status, Ok(WaitStatus::Signaled(_, _, _))))
    {
        for report in &reports {
            if still_ours(report) {
                fusermount_once(&report.path);
            }
        }
    }
    let child_code = match status {
        Ok(WaitStatus::Exited(_, code)) => Some(code),
        _ => None,
    };
    process::exit(launcher_exit_code(
        cancelled || started.elapsed() > deadline,
        child_code,
    ));
}

/// Cancellation and the cohort deadline are exit 1 even when the child
/// status is 0. A child exit is forwarded only when the launcher accepted it.
fn launcher_exit_code(cancelled: bool, child_code: Option<i32>) -> i32 {
    if cancelled {
        1
    } else {
        child_code.unwrap_or(1)
    }
}

fn forward_launcher_signal(child: Pid, base_int: u64, base_term: u64) {
    if ForkNSignalState::sigterm() > base_term {
        let _ = kill(child, Signal::SIGTERM);
    } else if ForkNSignalState::sigint() > base_int {
        let _ = kill(child, Signal::SIGINT);
    }
}

fn parse_report(line: &str) -> Option<Report> {
    let mut parts = line.splitn(6, ' ');
    if parts.next()? != "report" {
        return None;
    }
    let name = parts.next()?.to_string();
    let dev = parts.next()?.parse().ok()?;
    let ino = parts.next()?.parse().ok()?;
    let mount_id = parts.next()?.parse().ok()?;
    let path = PathBuf::from(parts.next()?);
    Some(Report {
        name,
        dev,
        ino,
        mount_id,
        path,
    })
}

fn mount_id_of(path: &Path) -> u64 {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return 0;
    };
    let want = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let want = want.to_string_lossy().replace(' ', "\\040");
    for line in text.lines() {
        let mut parts = line.split(' ');
        let Some(id) = parts.next().and_then(|s| s.parse().ok()) else {
            continue;
        };
        let _parent = parts.next();
        let _majmin = parts.next();
        let _root = parts.next();
        let Some(mountpoint) = parts.next() else {
            continue;
        };
        if mountpoint == want {
            return id;
        }
    }
    0
}

fn fail_mount_is(name: &str) -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var("RATARMOUNT_TEST_FORK_N_FAIL_MOUNT")
            .ok()
            .is_some_and(|value| value == name)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = name;
        false
    }
}

fn hold_after_report(name: &str) {
    #[cfg(debug_assertions)]
    {
        let Ok(hold_name) = std::env::var("RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT") else {
            return;
        };
        if hold_name != name {
            return;
        }
        let Ok(hold) = std::env::var("RATARMOUNT_TEST_FORK_N_REPORT_HOLD") else {
            return;
        };
        if let Ok(marker) = std::env::var("RATARMOUNT_TEST_FORK_N_REPORT_HELD") {
            let _ = fs::write(marker, format!("report-held\n{name}\n"));
        }
        let start = Instant::now();
        while Path::new(&hold).exists() && start.elapsed() < Duration::from_secs(60) {
            thread::sleep(Duration::from_millis(20));
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = name;
    }
}

#[cfg(test)]
mod tests {
    use super::launcher_exit_code;

    /// Regression: channel EOF before ready is cancellation, so a child
    /// status of 0 does not become launcher exit 0.
    #[test]
    fn fork_n_launcher_cancel_eof_is_nonzero() {
        assert_eq!(launcher_exit_code(true, Some(0)), 1);
        assert_eq!(launcher_exit_code(false, Some(0)), 0);
        assert_eq!(launcher_exit_code(false, Some(2)), 2);
    }
}
