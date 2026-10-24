//! N FUSE sessions in one process, and the daemon handoff in front of them.
//!
//! Foreground (`-f`) keeps the locks `open` already holds and does not fork.
//! Daemon mode drops every parent connection, forks once, and the child
//! reopens each top before the hardlink recheck. Failure cleanup is
//! `fusermount -u` with no `-z`, and only for a mount this process reported
//! whose `(st_dev, st_ino, mount_id)` still matches. This slice does not call
//! `unmount_lazy`.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, setsid, ForkResult, Pid};
use ratarmount_core::MountSource;
use ratarmount_fuse::oplog::MountActivity;
use ratarmount_fuse::PassthroughOptions;

use crate::fork_n;

pub(crate) struct TopHandle {
    pub name: String,
    pub overlay_dir: PathBuf,
    pub mountpoint: PathBuf,
    pub overlay: Arc<ratarmount_compositing::WriteOverlay>,
}

pub(crate) fn serve(
    args: &crate::Args,
    tops: Vec<TopHandle>,
    foreground: bool,
    direct_io: bool,
) -> ! {
    if foreground {
        for top in &tops {
            if let Err(err) = top.overlay.hold_exclusive() {
                eprintln!("error: fork-n cannot lock {}: {err}", top.name);
                process::exit(2);
            }
        }
        note_fusermount_honored();
        hold_after_locks();
        if let Err(message) = recheck_hardlinks(&tops) {
            eprintln!("error: {message}");
            process::exit(2);
        }
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
    let (parent_end, child_end) = match UnixStream::pair() {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("error: fork-n report pipe: {err}");
            process::exit(1);
        }
    };
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(child_end);
            parent_loop(parent_end, child);
        }
        Ok(ForkResult::Child) => {
            drop(parent_end);
            let _ = setsid();
            if let Err(message) = child_locks(&tops) {
                eprintln!("error: {message}");
                process::exit(2);
            }
            note_fusermount_honored();
            hold_after_locks();
            if let Err(message) = recheck_hardlinks(&tops) {
                exit_hardlink_child(&message);
            }
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
    }
    Ok(())
}

fn recheck_hardlinks(tops: &[TopHandle]) -> Result<(), String> {
    for top in tops {
        fork_n::walk_top(&top.overlay_dir)?;
    }
    Ok(())
}

/// Append `fusermount-honored` before the recheck and before the lock hold,
/// so the ready-log file already contains that line when `locks-held` appears.
fn note_fusermount_honored() {
    #[cfg(debug_assertions)]
    {
        if std::env::var_os("RATARMOUNT_TEST_FUSERMOUNT").is_none() {
            return;
        }
        let Ok(path) = std::env::var("RATARMOUNT_TEST_FORK_N_READY_LOG") else {
            return;
        };
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "fusermount-honored");
        }
    }
}

fn note_ready() {
    #[cfg(debug_assertions)]
    {
        let Ok(path) = std::env::var("RATARMOUNT_TEST_FORK_N_READY_LOG") else {
            return;
        };
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "ready");
        }
    }
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
        while Path::new(&hold).exists() && start.elapsed() < Duration::from_secs(120) {
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
        if fail_mount_is(&top.name) {
            fail_partial(&reports, report_to.as_mut(), std::mem::take(&mut handles));
        }
        let source: Arc<dyn MountSource> = top.overlay.clone();
        let mountpoint = top.mountpoint.clone();
        let overlay = Arc::clone(&top.overlay);
        let opts = fuse_opts.clone();
        let activity = activity.clone();
        let pass = passthrough;
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
                pass,
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
    if let Some(pipe) = report_to.as_mut() {
        let _ = writeln!(pipe, "ready");
        let _ = pipe.flush();
    }
    note_ready();
    for handle in handles {
        let _ = handle.join();
    }
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

/// Forward a child `Exited` status unchanged. EOF before `ready` is not
/// cancellation: the hardlink recheck exits 2 and the launcher must exit 2.
/// A signaled child that never wrote `cleanup` is unmounted once here.
fn parent_loop(pipe: UnixStream, child: Pid) -> ! {
    let _ = pipe.set_read_timeout(Some(Duration::from_millis(50)));
    let mut reader = BufReader::new(pipe);
    let mut reports: Vec<Report> = Vec::new();
    let mut saw_cleanup = false;
    let mut line = String::new();
    let started = Instant::now();
    let deadline = Duration::from_secs(180);
    loop {
        if started.elapsed() > deadline {
            let _ = kill(child, Signal::SIGKILL);
            break;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let line = line.trim_end();
                if line == "ready" {
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
            Err(_) => break,
        }
    }
    let status = waitpid(child, None);
    let signaled = matches!(status, Ok(WaitStatus::Signaled(_, _, _)));
    if !saw_cleanup && (signaled || started.elapsed() > deadline) {
        for report in &reports {
            if still_ours(report) {
                fusermount_once(&report.path);
            }
        }
    }
    let code = match status {
        Ok(WaitStatus::Exited(pid, code)) => {
            // Printed only after waitpid. A launcher that exits 2 without
            // waiting never emits this line, so the hardlink test can tell
            // a forwarded child status from a constant of its own.
            note_forwarded(pid, code);
            code
        }
        _ => 1,
    };
    process::exit(code);
}

/// The daemon child records the pid that wrote `locks-held`, a nonce only
/// that process chose, and the hardlink refusal status 2. Then it exits 2.
fn exit_hardlink_child(message: &str) -> ! {
    eprintln!("error: {message}");
    #[cfg(debug_assertions)]
    {
        if let Ok(path) = std::env::var("RATARMOUNT_TEST_FORK_N_CHILD_EXIT") {
            let pid = process::id();
            let nonce = child_exit_nonce();
            let _ = fs::write(&path, format!("{pid} {nonce} 2\n"));
            eprintln!("fork-n child-exit {pid} {nonce} 2");
        }
    }
    process::exit(2);
}

#[cfg(debug_assertions)]
fn child_exit_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!("{:016x}{:08x}", nanos, process::id())
}

/// Echo the child's nonce only when `waitpid` reported that same pid exiting
/// with the same code. The nonce is not on the launcher pipe.
#[cfg_attr(not(debug_assertions), allow(unused_variables))]
fn note_forwarded(pid: Pid, code: i32) {
    #[cfg(debug_assertions)]
    {
        let Ok(path) = std::env::var("RATARMOUNT_TEST_FORK_N_CHILD_EXIT") else {
            return;
        };
        let Ok(text) = fs::read_to_string(path) else {
            return;
        };
        let mut parts = text.split_whitespace();
        let Some(file_pid) = parts.next().and_then(|value| value.parse::<i32>().ok()) else {
            return;
        };
        let Some(nonce) = parts.next() else {
            return;
        };
        let Some(file_code) = parts.next().and_then(|value| value.parse::<i32>().ok()) else {
            return;
        };
        if file_pid == pid.as_raw() && file_code == code {
            eprintln!("fork-n forwarded {file_pid} {nonce} {code}");
        }
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
        while Path::new(&hold).exists() && start.elapsed() < Duration::from_secs(120) {
            thread::sleep(Duration::from_millis(20));
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = name;
    }
}
