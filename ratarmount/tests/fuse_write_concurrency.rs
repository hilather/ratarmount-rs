//! Concurrent FUSE writers in one directory must not deadlock on kernel notify.
#![cfg(target_os = "linux")]

use std::env;
use std::fs::{self, File};
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;
use nix::unistd::Pid;

const MOUNT_DEADLINE: Duration = Duration::from_secs(10);
const PHASE1_DEADLINE: Duration = Duration::from_secs(20);
const WAVE_DEADLINE: Duration = Duration::from_secs(30);
const UNMOUNT_DEADLINE: Duration = Duration::from_secs(10);
const DAEMON_EXIT_DEADLINE: Duration = Duration::from_secs(10);
const KILL_REAP: Duration = Duration::from_secs(2);
const LAZY_UNMOUNT_DEADLINE: Duration = Duration::from_secs(8);
const DAEMON_KILL_REAP: Duration = Duration::from_secs(5);

const CHURN_WORKERS: u32 = 4;
const MUTATORS: u32 = 2;
const ITERS: u32 = 100;

const PHASE1_SH: &str = r#"dir=$1
work=$2
append=$3
m4body=$4
ndbody=$5
cp "$dir/m1" "$work/m1.orig" || { echo "cp m1 failed" >&2; exit 5; }
cp "$dir/m2" "$work/m2.orig" || { echo "cp m2 failed" >&2; exit 5; }
orig=$(stat -c %s "$work/m1.orig") || exit 5
if [ "$orig" != 10 ]; then
  echo "m1 original size $orig want 10" >&2
  exit 5
fi
printf '%s' "$append" >> "$dir/m1" || { echo "append m1 failed" >&2; exit 3; }
cat "$work/m1.orig" > "$work/m1.expect" || exit 5
printf '%s' "$append" >> "$work/m1.expect" || exit 5
cmp -s "$work/m1.expect" "$dir/m1" || { echo "m1 bytes mismatch" >&2; exit 5; }
got=$(stat -c %s "$dir/m1") || exit 5
want=$(stat -c %s "$work/m1.expect") || exit 5
if [ "$got" != "$want" ]; then
  echo "m1 size $got want $want" >&2
  exit 5
fi
truncate -s 3 "$work/m2.orig" || { echo "local truncate failed" >&2; exit 8; }
truncate -s 3 "$dir/m2" || { echo "truncate m2 failed" >&2; exit 8; }
cmp -s "$work/m2.orig" "$dir/m2" || { echo "m2 bytes mismatch" >&2; exit 5; }
got=$(stat -c %s "$dir/m2") || exit 5
if [ "$got" != 3 ]; then
  echo "m2 size $got want 3" >&2
  exit 5
fi
rm "$dir/m4" || { echo "unlink m4 failed" >&2; exit 4; }
if stat "$dir/m4" >/dev/null 2>"$work/m4.err"; then
  echo "m4 still present" >&2
  exit 9
fi
if ! grep -q "No such file or directory" "$work/m4.err"; then
  echo "m4 stat was not ENOENT" >&2
  cat "$work/m4.err" >&2
  exit 9
fi
printf '%s' "$m4body" > "$dir/m4" || { echo "recreate m4 failed" >&2; exit 3; }
printf '%s' "$m4body" > "$work/m4.expect" || exit 5
cmp -s "$work/m4.expect" "$dir/m4" || { echo "m4 bytes mismatch" >&2; exit 5; }
got=$(stat -c %s "$dir/m4") || exit 5
want=$(stat -c %s "$work/m4.expect") || exit 5
if [ "$got" != "$want" ]; then
  echo "m4 size $got want $want" >&2
  exit 5
fi
printf '%s' 'xy' > "$dir/m5" || { echo "overwrite m5 failed" >&2; exit 3; }
printf '%s' 'xy' > "$work/m5.expect" || exit 5
cmp -s "$work/m5.expect" "$dir/m5" || { echo "m5 bytes mismatch" >&2; exit 5; }
got=$(stat -c %s "$dir/m5") || exit 5
want=$(stat -c %s "$work/m5.expect") || exit 5
if [ "$got" != "$want" ]; then
  echo "m5 size $got want $want" >&2
  exit 5
fi
mkdir "$dir/nd" || { echo "mkdir nd failed" >&2; exit 11; }
printf '%s' "$ndbody" > "$dir/nd/f" || { echo "create nd/f failed" >&2; exit 3; }
printf '%s' "$ndbody" > "$work/nd.expect" || exit 5
cmp -s "$work/nd.expect" "$dir/nd/f" || { echo "nd/f bytes mismatch" >&2; exit 5; }
got=$(stat -c %s "$dir/nd/f") || exit 5
want=$(stat -c %s "$work/nd.expect") || exit 5
if [ "$got" != "$want" ]; then
  echo "nd/f size $got want $want" >&2
  exit 5
fi
exit 0
"#;

const CHURN_SH: &str = r#"id=$1
dir=$2
iters=$3
builtin cd "$dir" || exit 9
n=1
while [ "$n" -le "$iters" ]; do
  echo x > "t${id}-${n}" || exit 3
  rm "t${id}-${n}" || exit 4
  slot=$(( (n % 20) + 6 ))
  stat "m${slot}" >/dev/null 2>&1 || true
  stat "nope${id}-${n}" >/dev/null 2>&1 || true
  n=$((n + 1))
done
exit 0
"#;

const MUTATOR_SH: &str = r#"w=$1
dir=$2
iters=$3
work=$4
builtin cd "$dir" || exit 9
n=1
while [ "$n" -le "$iters" ]; do
  name="s${w}-${n}"
  stat "$name" >/dev/null 2>&1 || exit 6
  rm "$name" || exit 4
  payload="mut${w}-${n}"
  printf '%s' "$payload" > "$name" || exit 3
  printf '%s' "$payload" > "$work/expect-${w}-${n}" || exit 5
  cmp -s "$work/expect-${w}-${n}" "$name" || exit 5
  got=$(stat -c %s "$name") || exit 5
  want=$(stat -c %s "$work/expect-${w}-${n}") || exit 5
  if [ "$got" != "$want" ]; then
    exit 5
  fi
  n=$((n + 1))
done
exit 0
"#;

struct Worker {
    child: Child,
    pgid: i32,
    label: String,
    log: PathBuf,
    status: Option<ExitStatus>,
}

struct MountGuard {
    mnt: PathBuf,
    daemon: Child,
    daemon_pid: u32,
    daemon_log: PathBuf,
    workers: Vec<Worker>,
    armed: bool,
    /// Graceful `fusermount3 -u` already returned. Drop must not lazy-unmount.
    defused: bool,
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.defused {
            self.armed = false;
            self.sigkill_daemon();
            let _ = reap_child(&mut self.daemon, DAEMON_KILL_REAP);
            return;
        }
        self.deadlock_cleanup();
    }
}

impl MountGuard {
    /// Kill worker groups, lazy-unmount, then SIGKILL the daemon. All waits bounded.
    fn deadlock_cleanup(&mut self) {
        if !self.armed || self.defused {
            return;
        }
        self.armed = false;
        for w in &self.workers {
            kill_process_group(w.pgid);
        }
        self.reap_workers(KILL_REAP);
        let _ = run_fusermount(&["-u", "-z"], &self.mnt, LAZY_UNMOUNT_DEADLINE);
        self.reap_workers(KILL_REAP);
        self.sigkill_daemon();
        let _ = reap_child(&mut self.daemon, DAEMON_KILL_REAP);
        if mount_visible(&self.mnt) {
            let _ = run_fusermount(&["-u", "-z"], &self.mnt, LAZY_UNMOUNT_DEADLINE);
        }
    }

    fn reap_workers(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let mut pending = false;
            for w in &mut self.workers {
                if w.status.is_some() {
                    continue;
                }
                match w.child.try_wait() {
                    Ok(Some(st)) => w.status = Some(st),
                    Ok(None) => pending = true,
                    Err(_) => pending = true,
                }
            }
            if !pending || Instant::now() >= deadline {
                return;
            }
            sleep_up_to(deadline, Duration::from_millis(20));
        }
    }

    fn sigkill_daemon(&mut self) {
        match self.daemon.try_wait() {
            Ok(Some(_)) => {}
            _ => signal_kill_pid(self.daemon_pid),
        }
    }
}

/// Regression: concurrent FUSE writers in one directory deadlock when kernel
/// invalidation runs on the request thread (parent i_rwsem held across notify).
#[test]
fn fuse_concurrent_writers_same_dir_no_deadlock() {
    if let Some(msg) = skip_reason() {
        eprintln!("{msg}");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("rrs84-fuse-conc-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    let tar = build_fixture(root);
    let ov = root.join("ov");
    let work = root.join("work");
    fs::create_dir_all(&ov).expect("overlay dir");
    fs::create_dir_all(&work).expect("work dir");
    let mnt_raw = root.join("mnt");
    fs::create_dir_all(&mnt_raw).expect("mnt dir");
    let mnt = mnt_raw.canonicalize().expect("canonicalize mnt");

    let phase1_sh = root.join("phase1.sh");
    let churn_sh = root.join("churn.sh");
    let mutator_sh = root.join("mutator.sh");
    fs::write(&phase1_sh, PHASE1_SH).expect("phase1.sh");
    fs::write(&churn_sh, CHURN_SH).expect("churn.sh");
    fs::write(&mutator_sh, MUTATOR_SH).expect("mutator.sh");

    let daemon_log = root.join("daemon.log");
    let mut guard = spawn_daemon(&ratarmount_bin(), &ov, &tar, &mnt, &daemon_log);
    if let Err(e) = guard.wait_mounted() {
        panic!("{e}");
    }

    let phase1_log = root.join("phase1.log");
    guard.spawn_worker(
        &phase1_sh,
        &[
            guard_dir(&mnt),
            work.display().to_string(),
            "APPEND-PHASE1".to_string(),
            "m4-recreated".to_string(),
            "nd-file-body".to_string(),
        ],
        &phase1_log,
        "phase1",
    );
    match guard.wait_workers(PHASE1_DEADLINE) {
        Wait::Done => {}
        Wait::Timeout => {
            panic!(
                "phase 1 exceeded 20s deadline (daemon pid {})\n{}",
                guard.daemon_pid,
                tail(&phase1_log)
            );
        }
        Wait::Error(e) => panic!("phase 1 wait: {e}"),
    }
    guard.assert_workers_ok("phase 1");
    guard.workers.clear();

    for id in 1..=CHURN_WORKERS {
        let log = root.join(format!("churn-{id}.log"));
        guard.spawn_worker(
            &churn_sh,
            &[id.to_string(), guard_dir(&mnt), ITERS.to_string()],
            &log,
            &format!("churn-{id}"),
        );
    }
    for w in 1..=MUTATORS {
        let log = root.join(format!("mut-{w}.log"));
        guard.spawn_worker(
            &mutator_sh,
            &[
                w.to_string(),
                guard_dir(&mnt),
                ITERS.to_string(),
                work.display().to_string(),
            ],
            &log,
            &format!("mut-{w}"),
        );
    }

    match guard.wait_workers(WAVE_DEADLINE) {
        Wait::Done => {}
        Wait::Timeout => {
            let pending: Vec<String> = guard
                .workers
                .iter()
                .filter(|w| w.status.is_none())
                .map(|w| format!("{} pid {}", w.label, w.child.id()))
                .collect();
            let n = pending.len();
            let pid = guard.daemon_pid;
            let detail = pending.join(", ");
            guard.deadlock_cleanup();
            panic!("deadlock: {n} workers did not finish in 30s (daemon pid {pid}; {detail})");
        }
        Wait::Error(e) => panic!("wave wait: {e} (daemon pid {})", guard.daemon_pid),
    }
    guard.assert_workers_ok("wave");

    // Finish in-flight notifier ioctls before umount. Unmounting while
    // FUSE_NOTIFY_INVAL_* is inside the kernel can stall the daemon join.
    thread::sleep(Duration::from_millis(200));
    if let Err(e) = guard.graceful_unmount() {
        panic!("{e}");
    }
}

fn guard_dir(mnt: &Path) -> String {
    mnt.join("d").display().to_string()
}

fn ratarmount_bin() -> PathBuf {
    if let Some(p) = env::var_os("RATARMOUNT_TEST_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(env!("CARGO_BIN_EXE_ratarmount"))
}

fn skip_reason() -> Option<&'static str> {
    if !Path::new("/dev/fuse").exists() {
        return Some("skip: /dev/fuse missing");
    }
    if !on_path("fusermount3") {
        return Some("skip: fusermount3 not on PATH");
    }
    if !on_path("bash") {
        return Some("skip: bash missing");
    }
    None
}

fn on_path(bin: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| env::split_paths(&paths).any(|p| p.join(bin).is_file()))
}

fn member_body(i: u32) -> String {
    let s = format!("member-{i:02}\n");
    assert_eq!(s.len(), 10, "{s:?}");
    s
}

fn build_fixture(root: &Path) -> PathBuf {
    let src = root.join("src").join("d");
    fs::create_dir_all(&src).expect("src/d");
    for i in 1..=40 {
        fs::write(src.join(format!("m{i}")), member_body(i)).expect("member");
    }
    for n in 1..=100 {
        fs::write(src.join(format!("s1-{n}")), format!("stable-s1-{n}\n")).expect("s1");
        fs::write(src.join(format!("s2-{n}")), format!("stable-s2-{n}\n")).expect("s2");
    }
    let tar = root.join("a.tar");
    let status = Command::new("tar")
        .args(["-C", root.join("src").to_str().expect("src utf8"), "-cf"])
        .arg(&tar)
        .arg("d")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "tar -cf failed: {status}");
    tar
}

fn spawn_daemon(bin: &Path, ov: &Path, tar: &Path, mnt: &Path, log_path: &Path) -> MountGuard {
    let log = File::create(log_path).expect("daemon log");
    let mut cmd = Command::new(bin);
    cmd.arg("-f")
        .arg("-w")
        .arg(ov)
        .arg(tar)
        .arg(mnt)
        .env("LC_ALL", "C")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .process_group(0);
    let mut daemon = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {} -f -w: {e}", bin.display()));
    let (_pgid, early) = confirm_group(&mut daemon);
    let daemon_pid = daemon.id();
    let guard = MountGuard {
        mnt: mnt.to_path_buf(),
        daemon,
        daemon_pid,
        daemon_log: log_path.to_path_buf(),
        workers: Vec::new(),
        armed: true,
        defused: false,
    };
    if let Some(st) = early {
        panic!(
            "daemon pid {daemon_pid} exited before mount: {st}\n{}",
            tail(log_path)
        );
    }
    guard
}

impl MountGuard {
    fn wait_mounted(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + MOUNT_DEADLINE;
        loop {
            if mount_visible(&self.mnt) {
                return Ok(());
            }
            match self.daemon.try_wait() {
                Ok(Some(st)) => {
                    return Err(format!(
                        "daemon pid {} exited before mount: {st}\n{}",
                        self.daemon_pid,
                        tail(&self.daemon_log)
                    ));
                }
                Ok(None) => {}
                Err(e) => return Err(format!("daemon try_wait: {e}")),
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "mount {} did not appear within 10s (daemon pid {})\n{}",
                    self.mnt.display(),
                    self.daemon_pid,
                    tail(&self.daemon_log)
                ));
            }
            sleep_up_to(deadline, Duration::from_millis(50));
        }
    }

    fn spawn_worker(&mut self, script: &Path, args: &[String], log_path: &Path, label: &str) {
        let log = File::create(log_path).unwrap_or_else(|e| panic!("log {label}: {e}"));
        let mut cmd = Command::new("bash");
        cmd.arg(script)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone worker log")))
            .stderr(Stdio::from(log))
            .process_group(0);
        let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {label}: {e}"));
        let (pgid, early) = confirm_group(&mut child);
        self.workers.push(Worker {
            child,
            pgid,
            label: label.to_string(),
            log: log_path.to_path_buf(),
            status: early,
        });
    }

    fn wait_workers(&mut self, timeout: Duration) -> Wait {
        let deadline = Instant::now() + timeout;
        loop {
            let mut pending = false;
            for w in &mut self.workers {
                if w.status.is_some() {
                    continue;
                }
                match w.child.try_wait() {
                    Ok(Some(st)) => w.status = Some(st),
                    Ok(None) => pending = true,
                    Err(e) => return Wait::Error(e),
                }
            }
            if !pending {
                return Wait::Done;
            }
            if Instant::now() >= deadline {
                return Wait::Timeout;
            }
            sleep_up_to(deadline, Duration::from_millis(20));
        }
    }

    fn assert_workers_ok(&self, what: &str) {
        for w in &self.workers {
            match w.status {
                Some(st) if st.success() => {}
                Some(st) => panic!(
                    "{what}: {} exited {st} (daemon pid {})\n{}",
                    w.label,
                    self.daemon_pid,
                    tail(&w.log)
                ),
                None => panic!("{what}: {} has no exit status", w.label),
            }
        }
    }

    fn graceful_unmount(&mut self) -> Result<(), String> {
        if !run_fusermount(&["-u"], &self.mnt, UNMOUNT_DEADLINE) {
            return Err(format!(
                "fusermount3 -u {} did not succeed within 10s (daemon pid {})\n{}",
                self.mnt.display(),
                self.daemon_pid,
                tail(&self.daemon_log)
            ));
        }
        // Defuse the lazy-unmount path. A later panic still SIGKILLs the daemon.
        self.defused = true;
        match reap_child(&mut self.daemon, DAEMON_EXIT_DEADLINE) {
            Some(st) if st.success() => {
                if mount_visible(&self.mnt) {
                    self.defused = false;
                    return Err(format!(
                        "mount {} still listed after daemon exit (pid {})",
                        self.mnt.display(),
                        self.daemon_pid
                    ));
                }
                self.armed = false;
                Ok(())
            }
            Some(st) => Err(format!(
                "daemon pid {} exited {st}, want success\n{}",
                self.daemon_pid,
                tail(&self.daemon_log)
            )),
            None => Err(format!(
                "daemon pid {} did not exit within 10s after fusermount3 -u\n{}\n{}",
                self.daemon_pid,
                proc_snapshot(self.daemon_pid),
                tail(&self.daemon_log)
            )),
        }
    }
}

enum Wait {
    Done,
    Timeout,
    Error(io::Error),
}

fn confirm_group(child: &mut Child) -> (i32, Option<ExitStatus>) {
    let pid = child.id();
    let pgid = i32::try_from(pid).unwrap_or_else(|_| panic!("pid {pid} does not fit i32"));
    let deadline = Instant::now() + Duration::from_millis(200);
    loop {
        if let Some(pgrp) = read_pgrp(pid) {
            assert_eq!(pgrp, pgid, "pid {pid} process group is {pgrp}, want {pgid}");
            return (pgid, None);
        }
        match child.try_wait() {
            Ok(Some(st)) => return (pgid, Some(st)),
            Ok(None) if Instant::now() >= deadline => {
                panic!("pid {pid} running but process group unreadable");
            }
            Ok(None) => sleep_up_to(deadline, Duration::from_millis(10)),
            Err(e) => panic!("try_wait pid {pid}: {e}"),
        }
    }
}

fn read_pgrp(pid: u32) -> Option<i32> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = text.split_once(')')?.1;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    let _ppid = fields.next()?;
    fields.next()?.parse().ok()
}

fn mount_visible(mnt: &Path) -> bool {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let want = mnt.to_string_lossy();
    text.lines()
        .any(|line| line.split_whitespace().nth(4).is_some_and(|mp| mp == want))
}

fn run_fusermount(args: &[&str], mnt: &Path, timeout: Duration) -> bool {
    let mut cmd = Command::new("fusermount3");
    cmd.args(args)
        .arg(mnt)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let pgid = i32::try_from(child.id()).unwrap_or(0);
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group(pgid);
                    signal_kill_pid(child.id());
                    let _ = reap_child(&mut child, KILL_REAP);
                    return false;
                }
                sleep_up_to(deadline, Duration::from_millis(20));
            }
            Err(_) => return false,
        }
    }
}

fn reap_child(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                sleep_up_to(deadline, Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

fn sleep_up_to(deadline: Instant, step: Duration) {
    let now = Instant::now();
    if now >= deadline {
        return;
    }
    thread::sleep(deadline.saturating_duration_since(now).min(step));
}

/// `kill(-pgid, SIGKILL)`. Refuses pid 0 / -1, which would hit this process or every process.
fn kill_process_group(pgid: i32) {
    if pgid <= 1 {
        return;
    }
    let Some(neg) = pgid.checked_neg() else {
        return;
    };
    if neg >= -1 {
        return;
    }
    let _ = nix::sys::signal::kill(Pid::from_raw(neg), Signal::SIGKILL);
}

fn signal_kill_pid(pid: u32) {
    let Ok(raw) = i32::try_from(pid) else {
        return;
    };
    if raw <= 1 {
        return;
    }
    let _ = nix::sys::signal::kill(Pid::from_raw(raw), Signal::SIGKILL);
}

fn proc_snapshot(pid: u32) -> String {
    let mut out = String::new();
    let task_dir = format!("/proc/{pid}/task");
    let Ok(tasks) = fs::read_dir(&task_dir) else {
        return format!("no /proc/{pid}");
    };
    for ent in tasks.flatten() {
        let tid = ent.file_name();
        let tid = tid.to_string_lossy();
        let base = ent.path();
        let comm = fs::read_to_string(base.join("comm")).unwrap_or_default();
        let wchan = fs::read_to_string(base.join("wchan")).unwrap_or_default();
        let stack = fs::read_to_string(base.join("stack")).unwrap_or_default();
        let stack_short: String = stack.lines().take(12).collect::<Vec<_>>().join(" | ");
        out.push_str(&format!(
            "tid {tid} comm {} wchan {} stack {stack_short}\n",
            comm.trim(),
            wchan.trim()
        ));
    }
    out
}

fn tail(path: &Path) -> String {
    let Ok(bytes) = fs::read(path) else {
        return String::new();
    };
    let start = bytes.len().saturating_sub(4096);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}
