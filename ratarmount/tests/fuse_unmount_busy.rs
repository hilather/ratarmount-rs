//! A briefly busy FUSE mount (desktop watchers such as gvfsd-trash probing a new
//! mount) must not turn a one-shot EBUSY into a failed unmount.
//!
//! Each test holds a file open inside the mount, triggers an unmount, waits
//! until the first unmount attempt has hit EBUSY, releases the file 200 ms later
//! and expects the retry to finish the unmount without a lazy (`-z`) fallback.
#![cfg(target_os = "linux")]

use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;
use nix::unistd::Pid;

const MOUNT_DEADLINE: Duration = Duration::from_secs(10);
const TRIGGER_DEADLINE: Duration = Duration::from_secs(10);
const EXIT_DEADLINE: Duration = Duration::from_secs(10);
const HOLD_AFTER_TRIGGER: Duration = Duration::from_millis(200);

/// Streamed child output plus a one-shot "first unmount attempt was busy" signal.
struct Log {
    text: Arc<Mutex<String>>,
    trigger: Receiver<()>,
    /// Never sent on; disconnects when the reader thread hits EOF.
    eof: Receiver<()>,
}

impl Log {
    fn attach(child: &mut Child) -> Log {
        Log::attach_reader(child.stderr.take().expect("piped stderr"))
    }

    fn attach_reader(reader: impl Read + Send + 'static) -> Log {
        let text = Arc::new(Mutex::new(String::new()));
        let (tx, trigger) = mpsc::channel();
        let (eof_tx, eof) = mpsc::channel::<()>();
        let sink = Arc::clone(&text);
        thread::spawn(move || {
            let _eof_tx = eof_tx;
            let mut fired = false;
            for line in BufReader::new(reader).lines() {
                let Ok(line) = line else { break };
                if !fired && is_busy_trigger(&line) {
                    fired = true;
                    let _ = tx.send(());
                }
                let mut t = sink.lock().unwrap();
                t.push_str(&line);
                t.push('\n');
            }
        });
        Log { text, trigger, eof }
    }

    /// After the child is reaped, wait (bounded) for the reader to consume the rest of the pipe
    /// so assertions see the full log.
    fn drain(&self) {
        let _ = self.eof.recv_timeout(Duration::from_secs(5));
    }

    fn text(&self) -> String {
        self.text.lock().unwrap().clone()
    }

    fn wait_trigger(&self, what: &str) {
        match self.trigger.recv_timeout(TRIGGER_DEADLINE) {
            Ok(()) => {}
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                panic!(
                    "{what}: no busy marker within {TRIGGER_DEADLINE:?} (the mount was never \
                     busy at unmount time)\n{}",
                    self.text()
                )
            }
        }
    }

    fn wait_contains(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.text().contains(needle) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        self.text().contains(needle)
    }
}

/// The new debug retry marker, or the literal fusermount3 stderr older builds inherit.
fn is_busy_trigger(line: &str) -> bool {
    line.contains("busy (attempt") || line.contains("Device or resource busy")
}

/// Holds `<mnt>/file` open until told to release.
struct Holder {
    release: Sender<Duration>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Holder {
    fn start(path: PathBuf) -> Holder {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<Duration>();
        let thread = thread::spawn(move || {
            let f = File::open(&path).expect("holder open");
            ready_tx.send(()).unwrap();
            if let Ok(after) = release_rx.recv() {
                thread::sleep(after);
            }
            drop(f);
        });
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("holder ready");
        Holder {
            release,
            thread: Some(thread),
        }
    }

    fn release_after(&mut self, after: Duration) {
        let _ = self.release.send(after);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    src: PathBuf,
    mnt: PathBuf,
}

fn setup() -> Option<Env> {
    if let Some(why) = skip_reason() {
        eprintln!("{why}");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let src = root.join("src");
    let mnt = root.join("mnt");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&mnt).unwrap();
    fs::create_dir_all(root.join("home")).unwrap();
    fs::create_dir_all(root.join("cache")).unwrap();
    fs::write(src.join("file"), b"hello\n").unwrap();
    Some(Env {
        _dir: dir,
        root,
        src,
        mnt,
    })
}

fn skip_reason() -> Option<&'static str> {
    if !Path::new("/dev/fuse").exists() {
        return Some("skip: /dev/fuse missing");
    }
    if !on_path("fusermount3") {
        return Some("skip: fusermount3 not on PATH");
    }
    None
}

fn on_path(bin: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| env::split_paths(&paths).any(|p| p.join(bin).is_file()))
}

fn ratarmount_bin() -> PathBuf {
    if let Some(p) = env::var_os("RATARMOUNT_TEST_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(env!("CARGO_BIN_EXE_ratarmount"))
}

fn command(e: &Env) -> Command {
    let mut cmd = Command::new(ratarmount_bin());
    cmd.env("HOME", e.root.join("home"))
        .env("XDG_CACHE_HOME", e.root.join("cache"))
        .env("TMPDIR", &e.root)
        .env("LC_ALL", "C")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

/// A running `ratarmount -f` daemon. Drop does a lazy unmount and SIGKILLs the exact pid.
struct Daemon {
    child: Child,
    mnt: PathBuf,
    log: Log,
}

impl Daemon {
    fn start(e: &Env, control: bool) -> Daemon {
        let mut cmd = command(e);
        cmd.args(["-f", "-d", "3", "-w", ":temp:"]);
        if control {
            cmd.arg("--control-interface");
        }
        cmd.arg(&e.src).arg(&e.mnt).process_group(0);
        let mut child = cmd.spawn().expect("spawn ratarmount");
        let log = Log::attach(&mut child);
        let mut d = Daemon {
            child,
            mnt: e.mnt.clone(),
            log,
        };
        let deadline = Instant::now() + MOUNT_DEADLINE;
        while !(mount_visible(&d.mnt) && d.mnt.join("file").exists()) {
            if let Ok(Some(st)) = d.child.try_wait() {
                panic!("daemon exited before mount: {st}\n{}", d.log.text());
            }
            assert!(
                Instant::now() < deadline,
                "mount did not appear\n{}",
                d.log.text()
            );
            thread::sleep(Duration::from_millis(50));
        }
        d
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap()
    }

    fn wait_exit(&mut self) -> Option<ExitStatus> {
        wait_child(&mut self.child, EXIT_DEADLINE)
    }

    fn assert_clean_exit(&mut self, what: &str) {
        let st = self.wait_exit();
        self.log.drain();
        assert!(
            st.is_some_and(|s| s.success()),
            "{what}: daemon did not exit 0 within {EXIT_DEADLINE:?}: {st:?}\n{}",
            self.log.text()
        );
        assert!(
            !mount_visible(&self.mnt),
            "{what}: mount still listed\n{}",
            self.log.text()
        );
        assert_no_lazy(&self.log.text(), what);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) && !mount_visible(&self.mnt) {
            return;
        }
        // Failure-path cleanup only: the tests themselves never unmount lazily
        // (`assert_no_lazy`). This just keeps a failed test from leaking a mount.
        let _ = Command::new("fusermount3")
            .args(["-u", "-z"])
            .arg(&self.mnt)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        kill_unreaped(&mut self.child);
        let _ = self.child.wait();
    }
}

/// SIGKILL `child` only while it is still unreaped. Once reaped its pid may belong
/// to an unrelated process, so it must never be signalled. Returns whether it signalled.
fn kill_unreaped(child: &mut Child) -> bool {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return false;
    }
    child.kill().is_ok()
}

fn assert_no_lazy(log: &str, what: &str) {
    assert!(
        !log.contains("lazy unmount") && !log.contains("-u -z"),
        "{what}: unmounted through the lazy fallback, not the retry\n{log}"
    );
}

fn wait_child(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(st)) = child.try_wait() {
            return Some(st);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn mount_visible(mnt: &Path) -> bool {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let want = mnt.to_string_lossy();
    text.lines()
        .any(|line| line.split_whitespace().nth(4).is_some_and(|mp| mp == want))
}

/// Read the control file in a thread so a wedged mount cannot hang the test.
fn read_control_unmount(mnt: &Path) {
    let path = mnt.join(".ratarmount-control").join("unmount");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut s = String::new();
        let r = File::open(&path).and_then(|mut f| f.read_to_string(&mut s));
        let _ = tx.send(r.map(|_| s));
    });
    // The result is irrelevant (the mount may vanish mid-read); only bound the wait.
    let _ = rx.recv_timeout(Duration::from_secs(10));
}

/// Regression: SIGTERM on a `:temp:` write mount hit one busy `fusermount3 -u`,
/// ignored the error and left the mount (and daemon) up.
#[test]
fn regression_sigterm_unmount_retries_while_busy() {
    let Some(e) = setup() else { return };
    let mut d = Daemon::start(&e, false);
    let mut holder = Holder::start(e.mnt.join("file"));
    nix::sys::signal::kill(Pid::from_raw(d.pid()), Signal::SIGTERM).unwrap();
    d.log.wait_trigger("SIGTERM");
    holder.release_after(HOLD_AFTER_TRIGGER);
    let st = d.wait_exit();
    d.log.drain();
    assert!(
        st.is_some(),
        "daemon still running {EXIT_DEADLINE:?} after SIGTERM + release\n{}",
        d.log.text()
    );
    assert!(
        !mount_visible(&e.mnt),
        "mount still listed after SIGTERM\n{}",
        d.log.text()
    );
    assert_no_lazy(&d.log.text(), "SIGTERM");
}

/// Regression: `ratarmount -u` exited 1 on the first EBUSY.
#[test]
fn regression_dash_u_retries_while_busy() {
    let Some(e) = setup() else { return };
    let mut d = Daemon::start(&e, false);
    let mut holder = Holder::start(e.mnt.join("file"));
    let mut cmd = command(&e);
    cmd.args(["-d", "3", "-u"]).arg(&e.mnt);
    let mut u = cmd.spawn().expect("spawn ratarmount -u");
    let ulog = Log::attach(&mut u);
    ulog.wait_trigger("ratarmount -u");
    holder.release_after(HOLD_AFTER_TRIGGER);
    let st = wait_child(&mut u, EXIT_DEADLINE);
    ulog.drain();
    assert!(
        st.is_some_and(|s| s.success()),
        "ratarmount -u did not exit 0: {st:?}\n{}",
        ulog.text()
    );
    d.assert_clean_exit("ratarmount -u");
}

/// Regression: the in-FS `.ratarmount-control/unmount` file unmounted inside the
/// FUSE request thread while the opener's open was pending, so it was always busy.
#[test]
fn regression_control_file_unmount() {
    let Some(e) = setup() else { return };
    let mut d = Daemon::start(&e, true);
    let mut holder = Holder::start(e.mnt.join("file"));
    read_control_unmount(&e.mnt);
    d.log.wait_trigger("control file");
    holder.release_after(HOLD_AFTER_TRIGGER);
    d.assert_clean_exit("control file");
}

/// Regression: a control-file unmount that exhausts its retries must warn, leave the
/// mount usable, and let a later read of the control file try again.
#[test]
fn regression_control_file_unmount_exhaustion_then_retry() {
    let Some(e) = setup() else { return };
    let mut d = Daemon::start(&e, true);
    let mut holder = Holder::start(e.mnt.join("file"));
    read_control_unmount(&e.mnt);
    assert!(
        d.log
            .wait_contains("control file unmount", Duration::from_secs(10))
            && d.log.wait_contains("failed", Duration::from_secs(1)),
        "no control-file unmount failure warning while the mount is held\n{}",
        d.log.text()
    );
    assert!(
        mount_visible(&e.mnt),
        "mount vanished while a file was still open\n{}",
        d.log.text()
    );
    assert!(
        matches!(d.child.try_wait(), Ok(None)),
        "daemon exited while a file was still open\n{}",
        d.log.text()
    );
    holder.release_after(Duration::ZERO);
    read_control_unmount(&e.mnt);
    d.assert_clean_exit("control file second read");
}

/// Regression: cleanup SIGKILLed the saved pid after the daemon was reaped (pid reuse could hit
/// an unrelated process). A reaped child must not be signalled; a live one must be.
#[test]
fn regression_cleanup_never_signals_reaped_child() {
    let mut gone = Command::new("true").spawn().expect("spawn true");
    gone.wait().expect("reap");
    assert!(!kill_unreaped(&mut gone), "signalled a reaped child");

    let mut live = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    assert!(kill_unreaped(&mut live), "did not kill a live child");
    let st = live.wait().expect("reap sleep");
    assert!(!st.success());
}
