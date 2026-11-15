//! Regression (#183): a daemonized mount (no `-f`) opened its databases and
//! took their SQLite locks before `fork()`. POSIX `fcntl` locks are not
//! inherited, and the launcher's exit released them, so the serving process
//! held no kernel lock on its overlay database (or its index) for its whole
//! life: another process could write the live database, or roll back the
//! serving process's live `-journal` as if it were hot. The launcher now forks
//! before it opens anything, and the serving process takes every lock itself.

use std::fs;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const OVERLAY_DB: &str = ".ratarmount.overlay.sqlite";
/// SQLite's lock bytes: PENDING, RESERVED and the SHARED range.
const LOCK_START: i64 = 0x4000_0000;
const LOCK_LEN: i64 = 512;

fn available() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return false;
    }
    if Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: fusermount3 unavailable");
        return false;
    }
    true
}

fn base_tar(path: &Path) {
    let mut tar = tar::Builder::new(fs::File::create(path).unwrap());
    let mut header = tar::Header::new_gnu();
    let body = b"base\n";
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(1_700_000_000);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    tar.append_data(&mut header, "a.txt", &body[..]).unwrap();
    tar.finish().unwrap();
}

/// Who holds a lock conflicting with a write lock on SQLite's lock bytes of
/// `path`, as `(pid, is_write)`, seen from this process (which holds none).
fn lock_holder(path: &Path) -> Option<(i32, bool)> {
    let file = fs::File::open(path).unwrap();
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_start = LOCK_START as _;
    lock.l_len = LOCK_LEN as _;
    // SAFETY: F_GETLK fills `lock`; it neither takes nor releases a lock.
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) },
        0
    );
    // Closing `file` releases nothing: this process holds no lock on it.
    (i32::from(lock.l_type) != libc::F_UNLCK)
        .then_some((lock.l_pid, i32::from(lock.l_type) == libc::F_WRLCK))
}

fn alive(pid: i32) -> bool {
    // A zombie of an exited serving process is reaped by init, not by us.
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|stat| {
            !stat
                .rsplit(')')
                .next()
                .is_some_and(|rest| rest.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

fn cmdline(pid: i32) -> String {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
        .unwrap_or_default()
}

/// `BEGIN IMMEDIATE` from a separate connection with no busy timeout.
fn begin_immediate(db: &Path) -> rusqlite::Result<()> {
    let conn = rusqlite::Connection::open(db)?;
    conn.busy_timeout(Duration::ZERO)?;
    conn.execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
}

fn is_busy(result: &rusqlite::Result<()>) -> bool {
    matches!(
        result,
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::DatabaseBusy
    )
}

struct Daemon {
    mnt: PathBuf,
    mounted: bool,
}

impl Daemon {
    fn start(
        args: &[&str],
        overlay: &Path,
        base: &Path,
        mnt: &Path,
        env: &[(&str, &Path)],
    ) -> Self {
        fs::create_dir_all(mnt).unwrap();
        let cache = base.parent().unwrap().join("cache");
        let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        command
            .env("XDG_CACHE_HOME", &cache)
            .env("HOME", &cache)
            .args(args)
            .arg("-w")
            .arg(overlay)
            .arg(base)
            .arg(mnt);
        for (key, value) in env {
            command.env(key, value);
        }
        let out: Output = command.output().unwrap();
        assert!(
            out.status.success(),
            "launcher failed: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Self {
            mnt: mnt.to_path_buf(),
            mounted: true,
        }
    }

    fn unmount(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !Command::new("fusermount3")
            .arg("-u")
            .arg(&self.mnt)
            .status()
            .unwrap()
            .success()
        {
            assert!(Instant::now() < deadline, "unmount stayed busy");
            std::thread::sleep(Duration::from_millis(100));
        }
        self.mounted = false;
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.mounted {
            let _ = Command::new("fusermount3")
                .arg("-uz")
                .arg(&self.mnt)
                .status();
        }
    }
}

fn wait_exit(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while alive(pid) {
        assert!(
            Instant::now() < deadline,
            "serving process {pid} did not exit"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The serving process of `mnt` holds the overlay database's lock, a
/// separate process's `BEGIN IMMEDIATE` is busy, and the index's shared lock
/// is held by the same process. After unmount and exit the database is free.
fn check_daemon_holds_locks(name: &str, args: &[&str]) {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base.tar");
    base_tar(&base);
    let overlay = tmp.path().join("overlay");
    let mnt = tmp.path().join("mnt");
    let mut daemon = Daemon::start(args, &overlay, &base, &mnt, &[]);
    let db = overlay.join(OVERLAY_DB);
    let (pid, write) = lock_holder(&db).unwrap_or_else(|| {
        panic!("{name}: nobody holds the overlay database's lock while the mount serves")
    });
    assert!(write, "{name}: the serving process holds an exclusive lock");
    assert!(
        alive(pid),
        "{name}: the lock holder {pid} is the live server"
    );
    assert!(
        cmdline(pid).contains(mnt.to_str().unwrap()),
        "{name}: the lock holder {pid} serves {}: {}",
        mnt.display(),
        cmdline(pid)
    );
    let busy = begin_immediate(&db);
    assert!(
        is_busy(&busy),
        "{name}: BEGIN IMMEDIATE from another process must be busy: {busy:?}"
    );
    let index = tmp.path().join("base.tar.index.sqlite");
    if index.exists() {
        let (index_pid, _) = lock_holder(&index)
            .unwrap_or_else(|| panic!("{name}: the serving process holds no index lock"));
        assert_eq!(index_pid, pid, "{name}: index lock held by the server");
    }
    // The mount still serves.
    assert_eq!(fs::read(mnt.join("a.txt")).unwrap(), b"base\n");
    daemon.unmount();
    wait_exit(pid);
    begin_immediate(&db).unwrap_or_else(|e| panic!("{name}: free after exit: {e}"));
}

/// Regression (#183): every daemonizing path (FUSE only, FUSE with NFS, FUSE
/// with another export) serves holding the overlay database's lock.
#[test]
fn regression_183_daemonized_mount_holds_overlay_lock() {
    if !available() {
        return;
    }
    check_daemon_holds_locks("fuse", &[]);
    check_daemon_holds_locks("fuse+nfs", &["--nfs", "--nfs-bind", "127.0.0.1:0"]);
    check_daemon_holds_locks("fuse+http", &["--http", "--http-bind", "127.0.0.1:0"]);
}

/// Regression (#183, PR #339): right after `fusermount3 -u`, another
/// process's `OverlayMeta::read` saw the serving process's live `-journal`,
/// took it for a hot journal and rolled back a write the server went on to
/// commit. The `RATARMOUNT_TEST_JOURNAL_HOLD` seam parks the serving process
/// (once the mount is up) inside a write transaction whose journal is on disk: a reader must be
/// refused and leave the database and the journal byte for byte as they were.
#[test]
fn regression_183_reader_cannot_roll_back_live_journal() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base.tar");
    base_tar(&base);
    let overlay = tmp.path().join("overlay");
    let mnt = tmp.path().join("mnt");
    let ready = tmp.path().join("ready");
    let mut daemon = Daemon::start(
        &["--index-file", ":memory:"],
        &overlay,
        &base,
        &mnt,
        &[("RATARMOUNT_TEST_JOURNAL_HOLD", ready.as_path())],
    );
    // A write the server commits before the held transaction starts.
    fs::write(mnt.join("new.txt"), b"new\n").unwrap();
    // The mount is up: let the server start its transaction.
    fs::write(tmp.path().join("ready.go"), b"go").unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "the hold never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let db = overlay.join(OVERLAY_DB);
    let journal = overlay.join(format!("{OVERLAY_DB}-journal"));
    let db_before = fs::read(&db).unwrap();
    let journal_before = fs::read(&journal).unwrap();
    assert!(
        journal_before.len() > 512 && journal_before[..8] != [0; 8],
        "the held transaction's journal is on disk"
    );
    let read = ratarmount_compositing::OverlayMeta::read(&overlay);
    assert!(
        read.is_err(),
        "a reader during a live write must be refused"
    );
    assert!(
        is_busy(&begin_immediate(&db)),
        "BEGIN IMMEDIATE must stay busy"
    );
    assert_eq!(fs::read(&db).unwrap(), db_before, "database untouched");
    assert_eq!(
        fs::read(&journal).unwrap(),
        journal_before,
        "live journal untouched"
    );
    let (pid, _) = lock_holder(&db).expect("the serving process holds the lock");
    // End the server mid-transaction; its journal is hot now and the
    // rollback is the reader's to do. The startup writes it committed stay.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    wait_exit(pid);
    daemon.unmount();
    let meta = ratarmount_compositing::OverlayMeta::read(&overlay)
        .unwrap()
        .expect("overlay record");
    assert!(meta.get("test_scratch").is_none(), "held write rolled back");
    assert!(
        meta.get("readonly_rules").is_some(),
        "the server's committed startup write survives"
    );
    // The file written through the mount before the hold survives too.
    let mnt2 = tmp.path().join("mnt2");
    let mut again = Daemon::start(&["--index-file", ":memory:"], &overlay, &base, &mnt2, &[]);
    assert_eq!(fs::read(mnt2.join("new.txt")).unwrap(), b"new\n");
    again.unmount();
}
