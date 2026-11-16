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

#[path = "support/unmount.rs"]
mod unmount;

const MOUNT_DEADLINE: Duration = Duration::from_secs(10);
const PHASE1_DEADLINE: Duration = Duration::from_secs(20);
/// A wave worker that finishes no iteration for this long is stalled. The deadlock this test
/// guards stops every worker for good, so it still fails here. Overlay writes are durable (about
/// 1,000 fsyncs per wave on the single request thread), so on a disk busy with writeback the
/// whole wave takes far longer than one window while every worker still progresses (#249: two
/// `dd conv=fsync` writers gave waves of 9-227 s, idle 4-5 s, and gaps of up to 12.8 s between
/// one worker's iterations).
const WAVE_STALL: Duration = Duration::from_secs(60);
/// Bound on the whole wave even while workers progress.
const WAVE_CAP: Duration = Duration::from_secs(600);
const UNMOUNT_DEADLINE: Duration = Duration::from_secs(10);
/// Daemon exit after `fusermount3 -u`. Usually milliseconds; a loaded host
/// (shared CI, slow fsync of overlay/index files) has taken ~5-10s on base
/// acec114 too. Still bounded, so a stuck notifier join fails the test.
const DAEMON_EXIT_DEADLINE: Duration = Duration::from_secs(30);
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
  printf '%s\n' "$n" > "$RRS_PROGRESS" || exit 7
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
  printf '%s\n' "$n" > "$RRS_PROGRESS" || exit 7
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
    /// File outside the mount the worker rewrites after each finished iteration.
    progress: Option<PathBuf>,
    observed: WorkerProgress,
}

struct WorkerProgress {
    last_progress: String,
    last_change: Instant,
}

impl WorkerProgress {
    fn new(now: Instant) -> Self {
        Self {
            last_progress: String::new(),
            last_change: now,
        }
    }

    fn observe(&mut self, text: &str, now: Instant) {
        // An empty read is a rewrite in flight, not progress.
        if !text.is_empty() && text != self.last_progress {
            self.last_progress = text.to_string();
            self.last_change = now;
        }
    }
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
        // Only groups whose leader is unreaped: a reaped leader's pgid may name another group.
        for w in self.workers.iter().filter(|w| w.status.is_none()) {
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

/// Regression: `MountGuard::deadlock_cleanup` sent SIGKILL to the process group of every worker,
/// including workers already reaped, whose pgid may since name an unrelated group. Only groups of
/// unreaped workers are signalled. Needs no FUSE.
#[test]
fn regression_deadlock_cleanup_never_signals_a_reaped_workers_group() {
    use std::os::unix::process::ExitStatusExt;
    let dir = tempfile::tempdir().unwrap();
    let group = || {
        Command::new("sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap()
    };
    // The pgid recorded for a reaped worker now names a live, unrelated group.
    let mut unrelated = group();
    let mut reaped = Command::new("true").spawn().unwrap();
    let reaped_status = reaped.wait().unwrap();
    let running = group();
    let running_pgid = i32::try_from(running.id()).unwrap();
    let worker = |child, pgid, status| Worker {
        child,
        pgid,
        label: "worker".into(),
        log: dir.path().join("worker.log"),
        status,
        progress: None,
        observed: WorkerProgress::new(Instant::now()),
    };
    let daemon = Command::new("sleep").arg("60").spawn().unwrap();
    let mut guard = MountGuard {
        mnt: dir.path().join("mnt"),
        daemon_pid: daemon.id(),
        daemon,
        daemon_log: dir.path().join("daemon.log"),
        workers: vec![
            worker(
                reaped,
                i32::try_from(unrelated.id()).unwrap(),
                Some(reaped_status),
            ),
            worker(running, running_pgid, None),
        ],
        armed: true,
        defused: false,
    };
    guard.deadlock_cleanup();
    let alive = unrelated.try_wait().unwrap().is_none();
    let _ = unrelated.kill();
    let _ = unrelated.wait();
    assert!(alive, "the recorded pgid of a reaped worker was signalled");
    assert_eq!(
        guard.workers[1].status.and_then(|s| s.signal()),
        Some(Signal::SIGKILL as i32),
        "an unreaped worker's group was not killed"
    );
}

/// Regression (#249): progressing waves can outlast a stall window, but one stuck worker
/// still fails and the overall cap remains distinct. Simulate time: the former shell fixture
/// could itself flake when scheduling or I/O delayed its 100 ms iterations by 1.5 s.
#[test]
fn regression_wave_wait_tolerates_slow_progress_and_flags_a_stall() {
    let start = Instant::now();
    let deadline = start + WAVE_CAP;
    let mut workers = [WorkerProgress::new(start), WorkerProgress::new(start)];
    for iteration in 1..=6 {
        let now = start + WAVE_STALL / 2 * iteration;
        for worker in &mut workers {
            worker.observe(&format!("{iteration}\n"), now);
        }
        assert!(wave_verdict(workers.iter().enumerate(), now, WAVE_STALL, deadline).is_none());
    }
    // Both can finish after three stall windows without a whole-wave timeout.
    let now = start + WAVE_STALL * 3;
    assert!(matches!(
        wave_verdict(std::iter::empty(), now, WAVE_STALL, deadline),
        Some(Wait::Done)
    ));

    // The other worker's progress must not extend worker 1's deadline.
    let now = now + WAVE_STALL;
    workers[0].observe("7\n", now);
    assert!(matches!(
        wave_verdict(workers.iter().enumerate(), now, WAVE_STALL, deadline),
        Some(Wait::Stalled(ids)) if ids == vec![1]
    ));

    // Keep both workers advancing until exactly the cap, without any stalled worker.
    let mut workers = [WorkerProgress::new(start), WorkerProgress::new(start)];
    for iteration in 1..=20 {
        let now = start + WAVE_STALL / 2 * iteration;
        for worker in &mut workers {
            worker.observe(&format!("{iteration}\n"), now);
        }
        let verdict = wave_verdict(workers.iter().enumerate(), now, WAVE_STALL, deadline);
        if now < deadline {
            assert!(verdict.is_none(), "{verdict:?}");
        } else {
            assert!(matches!(verdict, Some(Wait::OverCap)), "{verdict:?}");
        }
    }
}

/// Regression (#249 review): a full stop, including before the first marker, must fail.
/// Missing, empty (truncate in flight), and unchanged markers cannot refresh the stall timer.
#[test]
fn regression_wave_wait_missing_empty_and_unchanged_markers_stall() {
    let start = Instant::now();
    let deadline = start + WAVE_CAP;
    let mut workers = [WorkerProgress::new(start), WorkerProgress::new(start)];
    workers[1].observe("1\n", start + Duration::from_secs(10));
    let before_stall = start + WAVE_STALL - Duration::from_secs(1);
    workers[0].observe("", before_stall);
    workers[1].observe("1\n", before_stall);
    assert!(wave_verdict(
        workers.iter().enumerate(),
        before_stall,
        WAVE_STALL,
        deadline
    )
    .is_none());
    assert!(matches!(
        wave_verdict(workers.iter().enumerate(), start + WAVE_STALL, WAVE_STALL, deadline),
        Some(Wait::Stalled(ids)) if ids == vec![0]
    ));

    let now = start + WAVE_STALL + Duration::from_secs(10);
    workers[1].observe("", now);
    workers[1].observe("1\n", now);
    assert!(matches!(
        wave_verdict(workers.iter().enumerate(), now, WAVE_STALL, deadline),
        Some(Wait::Stalled(ids)) if ids == vec![0, 1]
    ));
    // A stopped wave is still a stall if the next poll is delayed past the overall cap.
    assert!(matches!(
        wave_verdict(workers.iter().enumerate(), deadline, WAVE_STALL, deadline),
        Some(Wait::Stalled(ids)) if ids == vec![0, 1]
    ));
}

fn unmounted_guard(root: &Path) -> MountGuard {
    let daemon = Command::new("sleep").arg("600").spawn().unwrap();
    MountGuard {
        mnt: root.join("mnt"),
        daemon_pid: daemon.id(),
        daemon,
        daemon_log: root.join("daemon.log"),
        workers: Vec::new(),
        armed: true,
        defused: false,
    }
}

/// Regression (#249 review): the real worker scripts must publish completed iterations outside
/// their working directory. A fast FUSE run also passed with the marker writes removed.
#[test]
fn regression_wave_worker_scripts_publish_progress() {
    if !on_path("bash") || !on_path("sleep") {
        eprintln!("skip: bash or sleep missing (pure wave timing tests still run)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    let source = dir.path().join("source");
    fs::create_dir(&work).unwrap();
    fs::create_dir(&source).unwrap();
    for n in 1..=2 {
        fs::write(source.join(format!("s1-{n}")), "original").unwrap();
    }
    let mut guard = unmounted_guard(dir.path());
    for (label, script) in [("churn", CHURN_SH), ("mutator", MUTATOR_SH)] {
        let path = dir.path().join(format!("{label}.sh"));
        fs::write(&path, script).unwrap();
        guard.spawn_worker(
            &path,
            &[
                "1".into(),
                source.display().to_string(),
                "2".into(),
                work.display().to_string(),
            ],
            &dir.path().join(format!("{label}.log")),
            label,
            Some(&work.join(format!("{label}.progress"))),
        );
    }
    assert!(matches!(
        guard.wait_workers(WAVE_STALL, WAVE_CAP),
        Wait::Done
    ));
    guard.assert_workers_ok("marker scripts");
    for label in ["churn", "mutator"] {
        assert_eq!(
            fs::read_to_string(work.join(format!("{label}.progress"))).unwrap(),
            "2\n",
            "{label} did not publish its final completed iteration"
        );
    }
}

/// Regression (#249 review): exercise real marker reads, process-group diagnostics and cleanup
/// without relying on a short scheduling window or mounting FUSE.
#[test]
fn regression_wave_stall_report_and_cleanup() {
    use std::os::unix::process::ExitStatusExt;

    if !on_path("bash") || !on_path("sleep") {
        eprintln!("skip: bash or sleep missing (pure wave timing tests still run)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("stuck.sh");
    // Publish the descendant's pid so diagnostics must find the whole group, not just bash.
    fs::write(
        &script,
        "sleep 600 &\nprintf '%s\\n' \"$!\" > \"$RRS_PROGRESS\"\nwait\n",
    )
    .unwrap();
    let progress = dir.path().join("progress");
    let mut guard = unmounted_guard(dir.path());
    guard.spawn_worker(
        &script,
        &[],
        &dir.path().join("worker.log"),
        "stuck",
        Some(&progress),
    );
    let ready_deadline = Instant::now() + WAVE_STALL;
    let descendant: u32 = loop {
        if let Some(pid) = fs::read_to_string(&progress)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            break pid;
        }
        assert!(
            Instant::now() < ready_deadline,
            "worker never published readiness"
        );
        sleep_up_to(ready_deadline, Duration::from_millis(20));
    };
    // Zero makes the first poll report a stall, independently of scheduler latency.
    assert!(matches!(
        guard.wait_workers(Duration::ZERO, WAVE_CAP),
        Wait::Stalled(ids) if ids == vec![0]
    ));
    let report = guard.stall_report(&[0]);
    assert!(
        report.contains(&format!("last iteration {descendant}")),
        "{report}"
    );
    for pid in [guard.daemon_pid, guard.workers[0].child.id(), descendant] {
        assert!(
            report.contains(&format!("tid {pid} ")),
            "missing pid {pid}: {report}"
        );
    }
    assert!(report.contains("wchan"), "{report}");
    guard.deadlock_cleanup();
    assert_eq!(
        guard.workers[0].status.and_then(|s| s.signal()),
        Some(libc::SIGKILL)
    );
    assert_eq!(
        guard.daemon.try_wait().unwrap().unwrap().signal(),
        Some(libc::SIGKILL)
    );
    let deadline = Instant::now() + KILL_REAP;
    loop {
        let stat = fs::read_to_string(format!("/proc/{descendant}/stat"));
        // A killed descendant may await reaping by init after its shell is killed.
        if stat
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            || stat.as_ref().is_ok_and(|s| {
                s.rsplit_once(')').is_some_and(|(_, fields)| {
                    matches!(fields.split_whitespace().next(), Some("Z" | "X"))
                })
            })
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "worker descendant still running: {stat:?}"
        );
        sleep_up_to(deadline, Duration::from_millis(20));
    }
}

/// Regression: Latin-1 file names must return EILSEQ without a U+FFFD overlay row.
#[test]
fn regression_non_utf8_name_create_leaves_no_overlay_row() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    if let Some(msg) = skip_reason() {
        eprintln!("{msg}");
        return;
    }
    if !on_path("tar") {
        eprintln!("skip: tar missing");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    let tar = build_fixture(root);
    let ov = root.join("ov");
    let mnt = root.join("mnt");
    fs::create_dir(&ov).unwrap();
    fs::create_dir(&mnt).unwrap();
    let mut guard = spawn_daemon(&ratarmount_bin(), &ov, &tar, &mnt, &root.join("daemon.log"));
    guard.wait_mounted().unwrap();
    for bytes in [b"caf\xe9".as_slice(), b"caf\xe8".as_slice()] {
        let path = mnt.join(OsStr::from_bytes(bytes));
        let err = File::create(&path).expect_err("invalid UTF-8 create must fail");
        assert_eq!(err.raw_os_error(), Some(libc::EILSEQ));
        assert_eq!(
            fs::symlink_metadata(&path).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }
    assert!(!mnt.join("caf�").exists());
    guard.graceful_unmount().unwrap();
    let db = rusqlite::Connection::open_with_flags(
        ov.join(".ratarmount.overlay.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let rows: u64 = db.query_row(
        "SELECT count(*) FROM files WHERE instr(path, char(65533)) > 0 OR instr(name, char(65533)) > 0",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(
        rows, 0,
        "invalid names must not create replacement-character rows"
    );
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
        None,
    );
    match guard.wait_workers(PHASE1_DEADLINE, PHASE1_DEADLINE) {
        Wait::Done => {}
        Wait::Stalled(_) | Wait::OverCap => {
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
            Some(&work.join(format!("progress-churn-{id}"))),
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
            Some(&work.join(format!("progress-mut-{w}"))),
        );
    }

    let wave_start = Instant::now();
    match guard.wait_workers(WAVE_STALL, WAVE_CAP) {
        Wait::Done => {}
        Wait::Stalled(stuck) => {
            let detail = guard.stall_report(&stuck);
            let pid = guard.daemon_pid;
            let elapsed = wave_start.elapsed();
            guard.deadlock_cleanup();
            panic!(
                "deadlock: {} workers finished no iteration in {WAVE_STALL:?} \
                 (daemon pid {pid}; wave ran {elapsed:?})\n{detail}",
                stuck.len()
            );
        }
        Wait::OverCap => {
            let pending: Vec<usize> = (0..guard.workers.len())
                .filter(|&i| guard.workers[i].status.is_none())
                .collect();
            let detail = guard.stall_report(&pending);
            let pid = guard.daemon_pid;
            guard.deadlock_cleanup();
            panic!(
                "wave still progressing but unfinished after {WAVE_CAP:?} (daemon pid {pid})\n{detail}"
            );
        }
        Wait::Error(e) => panic!("wave wait: {e} (daemon pid {})", guard.daemon_pid),
    }
    guard.assert_workers_ok("wave");

    // Flake hedge only: let the last queued FUSE_NOTIFY_INVAL_* land before
    // umount. Runs after every worker exited 0, so it cannot turn a deadlock
    // into a pass; a stuck notifier join still fails the bounded daemon-exit wait.
    // A slow daemon exit under host load was also seen on base acec114.
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

    fn spawn_worker(
        &mut self,
        script: &Path,
        args: &[String],
        log_path: &Path,
        label: &str,
        progress: Option<&Path>,
    ) {
        let log = File::create(log_path).unwrap_or_else(|e| panic!("log {label}: {e}"));
        let mut cmd = Command::new("bash");
        cmd.arg(script).args(args).env("LC_ALL", "C");
        if let Some(p) = progress {
            cmd.env("RRS_PROGRESS", p);
        }
        cmd.stdin(Stdio::null())
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
            progress: progress.map(Path::to_path_buf),
            observed: WorkerProgress::new(Instant::now()),
        });
    }

    /// Wait until every worker exits. `Stalled` names the unfinished workers whose progress
    /// file did not change for `stall` (a worker without one is stalled `stall` after its spawn);
    /// `OverCap` means workers still progressed when `cap` ran out.
    fn wait_workers(&mut self, stall: Duration, cap: Duration) -> Wait {
        let deadline = Instant::now() + cap;
        loop {
            let now = Instant::now();
            for w in &mut self.workers {
                if w.status.is_some() {
                    continue;
                }
                match w.child.try_wait() {
                    Ok(Some(st)) => {
                        w.status = Some(st);
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => return Wait::Error(e),
                }
                if let Some(p) = &w.progress {
                    if let Ok(text) = fs::read_to_string(p) {
                        w.observed.observe(&text, now);
                    }
                }
            }
            let pending = self
                .workers
                .iter()
                .enumerate()
                .filter(|(_, w)| w.status.is_none())
                .map(|(i, w)| (i, &w.observed));
            if let Some(verdict) = wave_verdict(pending, now, stall, deadline) {
                return verdict;
            }
            sleep_up_to(deadline, Duration::from_millis(20));
        }
    }

    /// Wait channels of the daemon's threads and of every process in the named workers'
    /// groups, read before cleanup kills them: a notify deadlock shows a daemon thread in a
    /// `/dev/fuse` write, a slow disk shows the request thread in `jbd2_log_wait_commit`.
    fn stall_report(&self, workers: &[usize]) -> String {
        let mut out = format!("daemon threads:\n{}", proc_snapshot(self.daemon_pid));
        for &i in workers {
            let w = &self.workers[i];
            let last = w.observed.last_progress.trim();
            out.push_str(&format!(
                "{} pid {} last iteration {} ({:?} ago):\n",
                w.label,
                w.child.id(),
                if last.is_empty() { "none" } else { last },
                w.observed.last_change.elapsed()
            ));
            for pid in group_members(w.pgid) {
                let cmd = fs::read_to_string(format!("/proc/{pid}/cmdline"))
                    .unwrap_or_default()
                    .replace('\0', " ");
                out.push_str(&format!("  {pid} {}\n  {}", cmd.trim(), proc_snapshot(pid)));
            }
        }
        out
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
        // Bounded EBUSY retry (desktop probers of the new mount); a mount that
        // stays busy fails the test with its holders logged.
        if let Err(e) = graceful_fusermount_u(&self.mnt) {
            unmount::log_holders(&self.mnt);
            return Err(format!(
                "{e} (daemon pid {})\n{}",
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
                "daemon pid {} did not exit within {:?} after fusermount3 -u\n{}\n{}",
                self.daemon_pid,
                DAEMON_EXIT_DEADLINE,
                proc_snapshot(self.daemon_pid),
                tail(&self.daemon_log)
            )),
        }
    }
}

#[derive(Debug)]
enum Wait {
    Done,
    /// Indices into `MountGuard::workers`.
    Stalled(Vec<usize>),
    OverCap,
    Error(io::Error),
}

/// Pure decision shared by the real polling loop and tests with a simulated clock.
fn wave_verdict<'a>(
    pending: impl Iterator<Item = (usize, &'a WorkerProgress)>,
    now: Instant,
    stall: Duration,
    deadline: Instant,
) -> Option<Wait> {
    let mut any_pending = false;
    let mut stuck = Vec::new();
    for (i, progress) in pending {
        any_pending = true;
        if now.duration_since(progress.last_change) >= stall {
            stuck.push(i);
        }
    }
    if !any_pending {
        Some(Wait::Done)
    } else if !stuck.is_empty() {
        Some(Wait::Stalled(stuck))
    } else if now >= deadline {
        Some(Wait::OverCap)
    } else {
        None
    }
}

/// Live processes whose process group is `pgid`.
fn group_members(pgid: i32) -> Vec<u32> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .filter(|&pid| read_pgrp(pid) == Some(pgid))
        .collect();
    pids.sort_unstable();
    pids
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

/// How long a graceful unmount keeps retrying a busy mount (desktop watchers such as
/// gvfsd-trash and gvfs-udisks2-volume-monitor probe each new mount). Separate
/// from the per-attempt `UNMOUNT_DEADLINE`.
const BUSY_RETRY: Duration = Duration::from_secs(1);

/// EBUSY from fusermount: stderr ends with the strerror (`failed to unmount <path>: <strerror>`),
/// so the echoed mountpoint is never inspected. glibc and musl spell EBUSY differently.
fn stderr_is_busy(stderr: &str) -> bool {
    let end = stderr.trim_end();
    end.ends_with(": Device or resource busy") || end.ends_with(": Resource busy")
}

/// `fusermount3 -u` with stderr captured, retried every 50 ms while it reports
/// "Device or resource busy". Never lazy: a mount that stays busy fails the test.
fn graceful_fusermount_u(mnt: &Path) -> Result<(), String> {
    let deadline = Instant::now() + BUSY_RETRY;
    loop {
        let mut cmd = Command::new("fusermount3");
        cmd.arg("-u")
            .arg(mnt)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = cmd.spawn().map_err(|e| format!("spawn fusermount3: {e}"))?;
        let pgid = i32::try_from(child.id()).unwrap_or(0);
        let Some(st) = reap_child(&mut child, UNMOUNT_DEADLINE) else {
            kill_process_group(pgid);
            signal_kill_pid(child.id());
            let _ = reap_child(&mut child, KILL_REAP);
            return Err(format!(
                "fusermount3 -u {} did not finish within {UNMOUNT_DEADLINE:?}",
                mnt.display()
            ));
        };
        if st.success() {
            return Ok(());
        }
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = io::Read::read_to_string(&mut pipe, &mut stderr);
        }
        if !stderr_is_busy(&stderr) || Instant::now() >= deadline {
            return Err(format!(
                "fusermount3 -u {} failed ({st}): {}",
                mnt.display(),
                stderr.trim()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
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
