//! Acquisition tests (design §11 "Acquisition, identity, and low
//! descriptors"). The test binary's constructor installed the wrappers (one
//! thread at load: `regression_sqlite_hook_installed_with_one_thread`).
//!
//! Rows whose outcome depends on a descriptor (which slot, retained or
//! closed) run in a child of this test binary: in the parent, other tests'
//! open connections make SQLite's reuse-selection `stat` fire first, which
//! refuses before the descriptor is opened.

// `libc::stat` field types differ on macOS.
#![allow(clippy::unnecessary_cast)]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags};

use super::imp::seams::{Seam, Seams};
use super::imp::ArmGuard;
use super::*;

const RO: OpenFlags = OpenFlags::SQLITE_OPEN_READ_ONLY;
const RW: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE;
const RWC: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE.union(OpenFlags::SQLITE_OPEN_CREATE);

const CHILD_ENV: &str = "RATARMOUNT_TEST_ACQUIRE_CHILD";
const RESULT_ENV: &str = "RATARMOUNT_TEST_ACQUIRE_RESULT";
const DB_ENV: &str = "RATARMOUNT_TEST_ACQUIRE_DB";

fn make_db(path: &Path, value: i64) {
    let c = Connection::open(path).unwrap();
    c.execute_batch(&format!(
        "CREATE TABLE t(x); INSERT INTO t VALUES ({value})"
    ))
    .unwrap();
}

fn id_of(path: &Path) -> DbId {
    let m = std::fs::metadata(path).unwrap();
    (m.dev(), m.ino())
}

fn existing(path: &Path, require_nonempty: bool) -> Expect {
    Expect::Existing {
        id: id_of(path),
        require_nonempty,
    }
}

fn fd_is_open(fd: i32) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

fn fd_stat(fd: i32) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0, "fstat({fd})");
    st
}

fn fd_id(fd: i32) -> DbId {
    let st = fd_stat(fd);
    (st.st_dev as u64, st.st_ino as u64)
}

fn is_dev_null(fd: i32) -> bool {
    let null = std::fs::metadata("/dev/null").unwrap();
    let st = fd_stat(fd);
    st.st_rdev as u64 == null.rdev()
        && (st.st_mode as u32) & libc::S_IFMT as u32 == libc::S_IFCHR as u32
}

fn mkfifo(path: &Path) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

fn count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM t", [], |r| r.get(0))
        .unwrap()
}

/// A canonical temporary directory (macOS `/var` is a symlink).
fn tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

/// Run `row` in a child of this test binary (watchdog: 60 s) and return
/// what it wrote to its result file.
fn run_child(row: &str, db: Option<&Path>) -> String {
    run_child_in(row, db, None)
}

/// [`run_child`] with the child's working directory set to `cwd`.
fn run_child_in(row: &str, db: Option<&Path>, cwd: Option<&Path>) -> String {
    let (_dir, dir) = tempdir();
    let result = dir.join("result");
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "checked_open::acquire::tests::acquire_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CHILD_ENV, row)
    .env(RESULT_ENV, &result);
    if let Some(db) = db {
        cmd.env(DB_ENV, db);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let out_path = dir.join("out");
    let err_path = dir.join("err");
    cmd.stdout(std::fs::File::create(&out_path).unwrap())
        .stderr(std::fs::File::create(&err_path).unwrap());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child row {row} hung (a blocking open?)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let got = std::fs::read_to_string(&result).unwrap_or_default();
    assert!(
        status.success() && got.starts_with("ok"),
        "child row {row} failed ({status}): result {got:?}\nstdout: {}\nstderr: {}",
        std::fs::read_to_string(&out_path).unwrap_or_default(),
        std::fs::read_to_string(&err_path).unwrap_or_default()
    );
    got
}

/// Does another process see a lock on `db`? `BEGIN IMMEDIATE` (busy timeout
/// 0) and `F_GETLK` over SQLite's lock bytes, in one child.
fn other_process_sees_lock(db: &Path) -> bool {
    let got = run_child("probe", Some(db));
    match got.trim() {
        "ok busy locked" => true,
        "ok acquired unlocked" => false,
        other => panic!("probe disagrees with itself: {other}"),
    }
}

fn write_result(text: &str) {
    std::fs::write(std::env::var_os(RESULT_ENV).unwrap(), text).unwrap();
}

/// The child half of [`run_child`] (a no-op unless spawned).
#[test]
fn acquire_child() {
    let Ok(row) = std::env::var(CHILD_ENV) else {
        return;
    };
    let detail = match row.as_str() {
        "probe" => probe_row(),
        r if r.starts_with("validate:") => validate_row(&r["validate:".len()..]),
        r if r.starts_with("fifo:") => fifo_row(&r["fifo:".len()..]),
        "fresh" => fresh_row(),
        "closed_stdin" => closed_stdin_row(),
        r if r.starts_with("low:") => low_row(&r["low:".len()..]),
        "reenter" => reenter_row(),
        "rwretry" => rw_retry_row(),
        "uri_relative" => uri_relative_row(),
        other => panic!("unknown row {other}"),
    };
    write_result(&format!("ok {detail}"));
}

fn probe_row() -> String {
    let db = PathBuf::from(std::env::var_os(DB_ENV).unwrap());
    let conn = Connection::open(&db).unwrap();
    conn.busy_timeout(Duration::ZERO).unwrap();
    let immediate = match conn.execute_batch("BEGIN IMMEDIATE") {
        Ok(()) => {
            conn.execute_batch("ROLLBACK").unwrap();
            "acquired"
        }
        Err(rusqlite::Error::SqliteFailure(e, _))
            if matches!(
                e.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            "busy"
        }
        Err(e) => panic!("probe: {e}"),
    };
    drop(conn);
    // PENDING, RESERVED and the SHARED range (`0x40000000`, 2 + 510 bytes).
    let file = std::fs::File::open(&db).unwrap();
    let mut lk: libc::flock = unsafe { std::mem::zeroed() };
    lk.l_type = libc::F_WRLCK as _;
    lk.l_whence = libc::SEEK_SET as _;
    lk.l_start = 0x4000_0000;
    lk.l_len = 512;
    use std::os::fd::AsRawFd;
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lk) },
        0
    );
    let getlk = if lk.l_type as i32 == libc::F_UNLCK as i32 {
        "unlocked"
    } else {
        "locked"
    };
    format!("{immediate} {getlk}")
}

/// Regression (r9 T1): SQLite's own descriptor is judged, not the name. The
/// database name holds another file at the open (another database, an empty
/// file, a `/dev/null` symlink, a FIFO: AFTER_PRESTAT, done before the call)
/// and A is restored right after SQLite's real `open` (AFTER_SQLITE_OPEN), so
/// any later look at the name sees A again. Refused; nothing is written.
#[test]
fn regression_checked_open_validates_sqlites_descriptor() {
    for kind in ["other", "empty", "devnull", "fifo"] {
        run_child(&format!("validate:{kind}"), None);
    }
}

fn validate_row(kind: &str) -> String {
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let expect = existing(&a, true);
    let a_bytes = std::fs::read(&a).unwrap();
    let sub = dir.join("sub");
    match kind {
        "other" => make_db(&sub, 2),
        "empty" => drop(std::fs::File::create(&sub).unwrap()),
        "devnull" => std::os::unix::fs::symlink("/dev/null", &sub).unwrap(),
        "fifo" => mkfifo(&sub),
        _ => unreachable!(),
    }
    let regular = matches!(kind, "other" | "empty");
    let keep = dir.join("sub.keep");
    let sub_bytes = if regular {
        std::fs::hard_link(&sub, &keep).unwrap();
        Some((std::fs::read(&sub).unwrap(), id_of(&sub)))
    } else {
        None
    };
    let saved = dir.join("a.saved");
    std::fs::rename(&a, &saved).unwrap();
    std::fs::rename(&sub, &a).unwrap();
    let (s, a2) = (saved.clone(), a.clone());
    let _seams = Seams::set(move |seam| {
        if seam == Seam::AfterRealOpen && s.exists() {
            std::fs::rename(&s, &a2).unwrap();
        }
    });
    let refusal = open_checked(&a, RWC, NameMode::Path, expect).unwrap_err();
    drop(_seams);
    match (kind, &refusal.error) {
        ("other" | "empty", AcquireError::OtherFile { actual }) => {
            assert_eq!(Some(*actual), sub_bytes.as_ref().map(|s| s.1));
            let fd = refusal.retained_fd.expect("a regular mismatch is retained");
            assert!(fd_is_open(fd));
            assert_eq!(fd_id(fd), *actual);
        }
        ("devnull" | "fifo", AcquireError::NotRegular { .. }) => {
            assert_eq!(refusal.retained_fd, None, "a non-regular file is closed");
        }
        _ => panic!("{kind}: unexpected refusal {refusal}"),
    }
    assert!(!saved.exists(), "A was restored by the seam");
    assert_eq!(std::fs::read(&a).unwrap(), a_bytes, "A unchanged");
    if let Some((bytes, _)) = sub_bytes {
        assert_eq!(
            std::fs::read(&keep).unwrap(),
            bytes,
            "the substitute unchanged"
        );
    }
    for side in ["-journal", "-wal", "-shm"] {
        let mut p = a.clone().into_os_string();
        p.push(side);
        assert!(!Path::new(&p).exists(), "{side} created");
    }
    format!("{kind}: {refusal}")
}

/// Regression (r9 T3): a FIFO at the database name must not block the
/// acquisition (read-only open of a FIFO without a writer blocks forever);
/// the refusal is the validation's, not merely some SQLite error.
#[test]
fn regression_checked_open_fifo_does_not_block() {
    for mode in ["ro", "rw"] {
        run_child(&format!("fifo:{mode}"), None);
    }
}

fn fifo_row(mode: &str) -> String {
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let expect = existing(&a, true);
    std::fs::remove_file(&a).unwrap();
    mkfifo(&a);
    let flags = if mode == "ro" { RO } else { RW };
    let refusal = open_checked(&a, flags, NameMode::Path, expect).unwrap_err();
    assert!(
        matches!(refusal.error, AcquireError::NotRegular { mode } if mode & 0o170000 == 0o010000),
        "{refusal}"
    );
    assert_eq!(refusal.retained_fd, None);
    format!("{mode}: {refusal}")
}

/// Regression (r9 T2): a non-empty file planted where the classification saw
/// nothing is `NotFresh`, its descriptor retained and its bytes unchanged; a
/// genuine absence is created and identified by SQLite's own descriptor.
#[test]
fn regression_checked_open_fresh_rejects_nonempty_file() {
    run_child("fresh", None);
}

fn fresh_row() -> String {
    let (_t, dir) = tempdir();
    let x = dir.join("x.sqlite");
    // Classified absent, then planted.
    std::fs::write(&x, b"planted").unwrap();
    let refusal = open_checked(&x, RWC, NameMode::Path, Expect::Fresh).unwrap_err();
    assert!(
        matches!(refusal.error, AcquireError::NotFresh { len: 7 }),
        "{refusal}"
    );
    let fd = refusal.retained_fd.expect("retained");
    assert!(fd_is_open(fd));
    assert_eq!(fd_id(fd), id_of(&x));
    assert_eq!(std::fs::read(&x).unwrap(), b"planted");
    // A genuine fresh database.
    let y = dir.join("y.sqlite");
    let got = open_checked(&y, RWC, NameMode::Path, Expect::Fresh).unwrap();
    assert_eq!(got.verification, Verification::UnixDescriptor);
    assert_eq!(got.id, Some(id_of(&y)));
    got.conn.execute_batch("CREATE TABLE t(x)").unwrap();
    // `Existing` never creates a database that vanished.
    let z = dir.join("z.sqlite");
    let gone = Expect::Existing {
        id: id_of(&y),
        require_nonempty: false,
    };
    let refusal = open_checked(&z, RWC, NameMode::Path, gone).unwrap_err();
    assert!(
        matches!(refusal.error, AcquireError::Sqlite(_)),
        "{refusal}"
    );
    assert!(!z.exists(), "an Existing open created the file");
    "fresh".into()
}

/// Regression (r9 v2 #1): a reused descriptor (SQLite's `findReusableFd`,
/// parked while this process holds a lock on the inode) is accepted when
/// every selection `stat` agrees, and no lock is lost.
#[test]
fn regression_checked_open_reuse_preserves_locks() {
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let holder = Connection::open(&a).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (2)")
        .unwrap();
    let r1 = open_checked(&a, RO, NameMode::Path, existing(&a, true)).unwrap();
    assert_eq!(r1.verification, Verification::UnixDescriptor);
    assert_eq!(r1.id, Some(id_of(&a)));
    drop(r1); // parked: the holder keeps a lock on the inode
    let r2 = open_checked(&a, RO, NameMode::Path, existing(&a, true));
    assert!(other_process_sees_lock(&a), "the holder's lock survived");
    let r2 = r2.unwrap();
    assert_eq!(r2.verification, Verification::UnixReuse);
    assert_eq!(r2.id, Some(id_of(&a)));
    assert_eq!(count(&r2.conn), 1);
    holder.execute_batch("COMMIT").unwrap();
    assert_eq!(count(&r2.conn), 2);
}

/// Regression (r9 v3 #1, AFTER_ARMED_STAT): the reuse-selection `stat` sees
/// X (another database with a parked descriptor) at A's name, then A is
/// restored before SQLite's later `stat`. The first mismatch persists: a
/// later agreeing stat is no false success.
#[test]
fn regression_checked_open_reuse_checks_every_stat() {
    let (_t, dir) = tempdir();
    let (a, x) = (dir.join("a.sqlite"), dir.join("x.sqlite"));
    make_db(&a, 1);
    make_db(&x, 2);
    let expect = existing(&a, true);
    let id_x = id_of(&x);
    let holder = Connection::open(&x).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (3)")
        .unwrap();
    drop(Connection::open_with_flags(&x, RO).unwrap()); // parks an RO descriptor of X
    let saved = dir.join("a.saved");
    std::fs::rename(&a, &saved).unwrap();
    std::fs::rename(&x, &a).unwrap();
    let (a2, x2, s2) = (a.clone(), x.clone(), saved.clone());
    let stats = std::rc::Rc::new(std::cell::Cell::new(0));
    let seen = stats.clone();
    let seams = Seams::set(move |seam| {
        if let Seam::AfterArmedStat(n) = seam {
            seen.set(n);
            if n == 1 {
                std::fs::rename(&a2, &x2).unwrap();
                std::fs::rename(&s2, &a2).unwrap();
            }
        }
    });
    let refusal = open_checked(&a, RO, NameMode::Path, expect).unwrap_err();
    drop(seams);
    assert!(other_process_sees_lock(&x), "X's holder keeps its lock");
    assert!(
        matches!(refusal.error, AcquireError::OtherFile { actual } if actual == id_x),
        "{refusal}"
    );
    assert!(
        stats.get() >= 2,
        "the later agreeing stat ran: {}",
        stats.get()
    );
    assert_eq!(refusal.retained_fd, None, "a reuse opens no descriptor");
    holder.execute_batch("COMMIT").unwrap();
}

/// Regression (R11-S2 review #3, `sqlite3.c` read-write retry): the
/// read-write open lands on X (swapped in after the first selection `stat`,
/// A restored right after the real `open`) and is refused with EACCES; SQLite
/// then retries read-only and reuses a parked read-only descriptor of A with
/// no `open` call at all, so it returns a connection. The latched mismatch
/// still refuses it, X's descriptor is retained, and the holder's lock on A
/// survives (the reused descriptor is re-parked, not closed).
#[test]
fn regression_checked_open_rw_refusal_then_ro_reuse_refuses() {
    run_child("rwretry", None);
}

fn rw_retry_row() -> String {
    let (_t, dir) = tempdir();
    let (a, x) = (dir.join("a.sqlite"), dir.join("x.sqlite"));
    make_db(&a, 1);
    make_db(&x, 2);
    let (a_bytes, id_x) = (std::fs::read(&a).unwrap(), id_of(&x));
    let expect = existing(&a, true);
    let holder = Connection::open(&a).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (2)")
        .unwrap();
    drop(Connection::open_with_flags(&a, RO).unwrap()); // parks an RO descriptor of A
    let saved = dir.join("a.saved");
    let (a2, x2, s2) = (a.clone(), x.clone(), saved.clone());
    let stats = std::rc::Rc::new(std::cell::Cell::new(0));
    let seen = stats.clone();
    let mut opened = false;
    // Filesystem only: the stat seam runs under SQLite's unix mutex.
    let seams = Seams::set(move |seam| match seam {
        Seam::AfterArmedStat(n) => {
            seen.set(n);
            if n == 1 {
                let _ = std::fs::rename(&a2, &s2);
                let _ = std::fs::rename(&x2, &a2);
            }
        }
        Seam::AfterRealOpen if !opened => {
            opened = true;
            let _ = std::fs::rename(&a2, &x2);
            let _ = std::fs::rename(&s2, &a2);
        }
        _ => {}
    });
    let result = open_checked(&a, RW, NameMode::Path, expect);
    drop(seams);
    assert!(other_process_sees_lock(&a), "the holder's lock survived");
    let refusal = result.expect_err("the read-only reuse was accepted");
    assert!(
        matches!(refusal.error, AcquireError::OtherFile { actual } if actual == id_x),
        "{refusal}"
    );
    let fd = refusal.retained_fd.expect("X's descriptor is retained");
    assert!(fd >= 3 && fd_is_open(fd));
    assert_eq!(fd_id(fd), id_x);
    assert!(
        stats.get() >= 2,
        "the retry's selection stat ran: {}",
        stats.get()
    );
    assert!(!saved.exists(), "A was restored by the seam");
    assert_eq!(std::fs::read(&a).unwrap(), a_bytes, "A unchanged");
    for side in ["-journal", "-wal", "-shm"] {
        let mut p = x.clone().into_os_string();
        p.push(side);
        assert!(!Path::new(&p).exists(), "X{side} created");
    }
    holder.execute_batch("COMMIT").unwrap();
    assert_eq!(count(&holder), 2);
    format!("rwretry: {refusal}")
}

/// Regression (r9 v3 #3, AFTER_PRESTAT): the marked record's own inode is
/// truncated after classification. The acquisition says `EmptyRecord` (a
/// lost record, never an unrecorded one) and modifies nothing beyond the
/// intentional truncate; an unmarked empty file opens.
#[test]
fn regression_checked_open_marked_truncation_is_not_empty_record() {
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let marked = existing(&a, true);
    let unmarked = existing(&a, false);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&a)
        .unwrap()
        .set_len(0)
        .unwrap();
    for flags in [RO, RWC] {
        let refusal = open_checked(&a, flags, NameMode::Path, marked).unwrap_err();
        assert!(
            matches!(refusal.error, AcquireError::EmptyRecord),
            "{refusal}"
        );
    }
    assert_eq!(std::fs::metadata(&a).unwrap().len(), 0);
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["a.sqlite"], "nothing else was created");
    let got = open_checked(&a, RO, NameMode::Path, unmarked).unwrap();
    assert_eq!(got.id, Some(id_of(&a)));
}

/// Regression (r9 v1 #5): when `fstat` of SQLite's descriptor fails, the
/// descriptor is neither handed to SQLite nor closed (it may be an inode this
/// process holds locks on): the holder's lock survives.
#[test]
fn regression_checked_open_fstat_failure_retains_fd() {
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let holder = Connection::open(&a).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (2)")
        .unwrap();
    let seams = Seams::set(|_| {}).fail_fstat(libc::EIO);
    let refusal = open_checked(&a, RO, NameMode::Path, existing(&a, true)).unwrap_err();
    drop(seams);
    // The behavioral probe first: a diagnostic failure must not hide lock loss.
    assert!(other_process_sees_lock(&a));
    assert!(
        matches!(refusal.error, AcquireError::Fstat(libc::EIO)),
        "{refusal}"
    );
    let fd = refusal.retained_fd.expect("retained");
    assert!(fd_is_open(fd));
    assert_eq!(fd_id(fd), id_of(&a));
    holder.execute_batch("COMMIT").unwrap();
}

/// Regression (r9 v1 #3 / Fable N7): arming is per thread. While one thread
/// is armed (held inside SQLite's open), another thread's plain opens pass
/// through, and its own checked open of the same database collects its own
/// evidence; both succeed.
#[test]
fn regression_checked_open_arming_is_thread_local() {
    let (_t, dir) = tempdir();
    let (a, b) = (dir.join("a.sqlite"), dir.join("b.sqlite"));
    make_db(&a, 1);
    make_db(&b, 1);
    let expect = existing(&a, true);
    let (inside_tx, inside_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let a1 = a.clone();
    let t1 = std::thread::spawn(move || {
        let _seams = Seams::set(move |seam| {
            // No panics here: this runs inside SQLite's `open` callback.
            if seam == Seam::AfterRealOpen {
                let _ = inside_tx.send(ArmGuard::peek().is_none());
                let _ = go_rx.recv_timeout(Duration::from_secs(30));
            }
        });
        open_checked(&a1, RO, NameMode::Path, expect).map(|g| (g.verification, g.id))
    });
    let callback_took_evidence = inside_rx.recv_timeout(Duration::from_secs(30)).unwrap();
    assert!(callback_took_evidence);
    assert!(ArmGuard::peek().is_none(), "this thread is not armed");
    let plain = Connection::open(&b).unwrap();
    plain.execute_batch("INSERT INTO t VALUES (2)").unwrap();
    assert_eq!(count(&Connection::open_with_flags(&a, RO).unwrap()), 1);
    let mine = open_checked(&a, RO, NameMode::Path, expect).unwrap();
    assert_eq!(mine.id, Some(id_of(&a)));
    go_tx.send(()).unwrap();
    let theirs = t1.join().unwrap().unwrap();
    assert_eq!(theirs, (Verification::UnixDescriptor, Some(id_of(&a))));
}

/// Regression: a checked open on a thread already inside one refuses with
/// `Reentrant` before arming, and the outer evidence is intact.
#[test]
fn regression_checked_open_reentrant_arm_refuses() {
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let guard = ArmGuard::arm(Expect::Fresh).unwrap();
    ArmGuard::update(|o| {
        o.stats = 3;
        o.latch(Mismatch::NotFresh { len: 9 });
    });
    let before = ArmGuard::peek().unwrap();
    assert!(matches!(
        ArmGuard::arm(existing(&a, true)),
        Err(AcquireError::Reentrant)
    ));
    let refusal = open_checked(&a, RO, NameMode::Path, existing(&a, true)).unwrap_err();
    assert!(
        matches!(refusal.error, AcquireError::Reentrant),
        "{refusal}"
    );
    assert_eq!(ArmGuard::peek(), Some(before));
    assert_eq!(guard.finish(), before);
    assert_eq!(ArmGuard::peek(), None);
    // Disarmed again: an ordinary checked open works.
    open_checked(&a, RO, NameMode::Path, existing(&a, true)).unwrap();
}

/// Regression (R11-S2 skeptic #1): the callbacks take the evidence out of
/// thread-local storage while they run, so a nested `open_checked` from
/// inside one (another library's `open` wrapper, here a seam) saw the thread
/// unarmed and succeeded. It must refuse with `Reentrant`, from the `open`
/// callback (fresh descriptor) and from the `stat` callback (reuse, under
/// SQLite's unix mutex: before the fix that nested open could hang), and the
/// outer acquisition still succeeds with its own evidence. In a child: a
/// hang trips the watchdog.
#[test]
fn regression_checked_open_reentry_from_callback_refuses() {
    run_child("reenter", None);
}

fn reenter_row() -> String {
    use std::cell::RefCell;
    use std::rc::Rc;
    let (_t, dir) = tempdir();
    let (a, b) = (dir.join("a.sqlite"), dir.join("b.sqlite"));
    make_db(&a, 1);
    make_db(&b, 1);
    let expect_b = existing(&b, true);
    let holder = Connection::open(&a).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (2)")
        .unwrap();
    let mut out = Vec::new();
    for (want_seam, want_verification) in [
        ("open", Verification::UnixDescriptor),
        ("stat", Verification::UnixReuse),
    ] {
        // (seam, active, nested result): no panics inside the callback.
        type Seen = Vec<(&'static str, bool, String)>;
        let seen: Rc<RefCell<Seen>> = Rc::default();
        let (rec, b2) = (seen.clone(), b.clone());
        let seams = Seams::set(move |seam| {
            let name = match seam {
                Seam::AfterRealOpen => "open",
                Seam::AfterArmedStat(_) => "stat",
                Seam::AfterLowFdFill => return,
            };
            if name != want_seam || !rec.borrow().is_empty() {
                return;
            }
            let active = ArmGuard::active();
            let nested = match open_checked(&b2, RO, NameMode::Path, expect_b) {
                Ok(got) => format!("acquired {:?}", got.verification),
                Err(r) => match r.error {
                    AcquireError::Reentrant => "reentrant".to_string(),
                    other => format!("refused {other}"),
                },
            };
            rec.borrow_mut().push((name, active, nested));
        });
        let outer = open_checked(&a, RO, NameMode::Path, existing(&a, true));
        drop(seams);
        let outer = outer.unwrap_or_else(|r| panic!("{want_seam}: outer refused: {r}"));
        assert_eq!(outer.verification, want_verification, "{want_seam}");
        assert_eq!(outer.id, Some(id_of(&a)));
        assert_eq!(count(&outer.conn), 1);
        assert_eq!(
            *seen.borrow(),
            [(want_seam, true, "reentrant".to_string())],
            "{want_seam}: the nested open from the callback"
        );
        assert!(!ArmGuard::active() && ArmGuard::peek().is_none());
        // Parks this descriptor (the holder's lock): the next pass reuses it.
        drop(outer);
        out.push(want_seam);
    }
    assert!(other_process_sees_lock(&a), "the holder's lock survived");
    holder.execute_batch("COMMIT").unwrap();
    // Disarmed again: an ordinary checked open of B works.
    let got = open_checked(&b, RO, NameMode::Path, expect_b).unwrap();
    assert_eq!(got.id, Some(id_of(&b)));
    format!("reenter: {}", out.join(" "))
}

/// Regression (r9 v1 #2): with stdin closed after a holder took its lock,
/// SQLite's next open would land on descriptor 0 and `robust_open` would
/// close it, releasing the holder's lock. The fill keeps the lock and the
/// holder can still write.
#[test]
fn regression_closed_stdin_after_lock_preserves_lock() {
    run_child("closed_stdin", None);
}

fn closed_stdin_row() -> String {
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let holder = open_checked(&a, RW, NameMode::Path, existing(&a, true)).unwrap();
    holder
        .conn
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (2)")
        .unwrap();
    unsafe { libc::close(0) };
    let r = open_checked(&a, RO, NameMode::Path, existing(&a, true));
    assert!(other_process_sees_lock(&a), "the holder's lock survived");
    let r = r.unwrap();
    assert_eq!(r.retained_low_fd, None);
    assert!(is_dev_null(0), "stdin was filled with /dev/null");
    drop(r);
    assert!(
        other_process_sees_lock(&a),
        "the holder's lock survived the drop"
    );
    holder.conn.execute_batch("COMMIT").unwrap();
    assert_eq!(count(&holder.conn), 2);
    "closed_stdin".into()
}

/// Regression (r9 v2 #3 / v3 #5, AFTER_LOW_FD_FILL): another thread empties
/// a standard slot between the fill and SQLite's `open`. Read-only (any slot)
/// and writable fd 0 are duplicated to a high slot and the low one retained;
/// a failed duplicate retains it and refuses; writable stdout/stderr is
/// re-pointed at `/dev/null` and refused as a possible lock release, also for
/// a mismatching file or a failed `fstat` (`rw1fstat`); a failed `fstat` or
/// a mismatch at a read-only low slot keeps both descriptors. An SQLite error
/// after an accepted low-slot duplicate (`memerr0`) reports the kept slot. A
/// FIFO at the name (`fifo0`) closes the high duplicate and reports the low
/// slot, still open on the FIFO.
#[test]
fn regression_low_fd_window_policy() {
    for row in [
        "ro0",
        "ro2",
        "rw0",
        "dupfail",
        "rw1",
        "rw2mismatch",
        "fstat0",
        "mismatch0",
        "rw1fstat",
        "memerr0",
        "fifo0",
    ] {
        let got = run_child(&format!("low:{row}"), None);
        if got.contains("skip:") {
            eprintln!("{}", got.trim_start_matches("ok "));
        }
    }
}

fn low_row(row: &str) -> String {
    let (_t, dir) = tempdir();
    // `memerr0`: `/proc/self/mem` is accepted (a regular file), then SQLite's
    // header read fails with EIO.
    let mem = row == "memerr0";
    if mem && !Path::new("/proc/self/mem").exists() {
        return format!("skip: {row}: /proc is not mounted");
    }
    let a = if mem {
        PathBuf::from("/proc/self/mem")
    } else {
        let a = dir.join("a.sqlite");
        make_db(&a, 1);
        a
    };
    let expect = existing(&a, !mem);
    let slot = match row {
        "ro2" => 2,
        "rw1" | "rw1fstat" => 1,
        "rw2mismatch" => 2,
        _ => 0,
    };
    let flags = if row.starts_with("rw") { RW } else { RO };
    // A mismatch row has no holder: its open connection would make SQLite's
    // reuse-selection `stat` refuse before the descriptor is opened.
    let mismatch = row.contains("mismatch");
    let fifo = row == "fifo0";
    let holder = (!mismatch && !mem && !fifo).then(|| {
        let holder = Connection::open(&a).unwrap();
        holder
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (2)")
            .unwrap();
        holder
    });
    if mismatch {
        let x = dir.join("x.sqlite");
        make_db(&x, 9);
        std::fs::rename(&a, dir.join("a.saved")).unwrap();
        std::fs::rename(&x, &a).unwrap();
    }
    if fifo {
        std::fs::rename(&a, dir.join("a.saved")).unwrap();
        mkfifo(&a);
    }
    let mut fillers = Vec::new();
    let mut old_limit: libc::rlimit = unsafe { std::mem::zeroed() };
    if row == "dupfail" {
        // No free descriptor at 3 or above.
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut old_limit) };
        let lim = libc::rlimit {
            rlim_cur: 64,
            rlim_max: old_limit.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) }, 0);
        loop {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            if fd < 0 {
                break;
            }
            fillers.push(fd);
        }
    }
    let mut closed = false;
    let mut seams = Seams::set(move |seam| {
        if seam == Seam::AfterLowFdFill && !closed {
            closed = true;
            unsafe { libc::close(slot) };
        }
    });
    if row == "fstat0" || row == "rw1fstat" {
        seams = seams.fail_fstat(libc::EIO);
    }
    let result = open_checked(&a, flags, NameMode::Path, expect);
    drop(seams);
    if row == "dupfail" {
        for fd in fillers {
            unsafe { libc::close(fd) };
        }
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &old_limit) },
            0
        );
    }
    // The behavioral probe first: a diagnostic failure must not hide lock
    // loss. Rows with a holder whose lock must survive; `rw1` is the
    // documented limit (re-pointing closed a descriptor of the holder's
    // inode), probed in its arm.
    if holder.is_some() && !row.starts_with("rw1") {
        assert!(other_process_sees_lock(&a), "{row}: the lock survived");
    }
    let detail = match (row, result) {
        ("ro0" | "ro2" | "rw0", Ok(got)) => {
            assert_eq!(got.retained_low_fd, Some(slot));
            assert_eq!(got.verification, Verification::UnixDescriptor);
            assert!(fd_is_open(slot));
            assert_eq!(fd_id(slot), id_of(&a), "the low slot is retained");
            assert_eq!(count(&got.conn), 1);
            holder.unwrap().execute_batch("COMMIT").unwrap();
            format!("{row}: acquired")
        }
        ("dupfail", Err(refusal)) => {
            assert!(
                matches!(
                    refusal.error,
                    AcquireError::LowDescriptor {
                        fd: 0,
                        locks_may_be_released: false
                    }
                ),
                "{refusal}"
            );
            assert_eq!(refusal.retained_fd, Some(0));
            assert_eq!(fd_id(0), id_of(&a));
            holder.unwrap().execute_batch("COMMIT").unwrap();
            format!("{row}: {refusal}")
        }
        ("rw1" | "rw2mismatch" | "rw1fstat", Err(refusal)) => {
            assert!(
                matches!(
                    refusal.error,
                    AcquireError::LowDescriptor { fd, locks_may_be_released: true } if fd == slot
                ),
                "{refusal}"
            );
            assert!(is_dev_null(slot), "re-pointed at /dev/null");
            if row == "rw1" {
                // The documented limit: re-pointing closed a descriptor of
                // the holder's inode, so its locks are gone.
                assert!(!other_process_sees_lock(&a));
            }
            format!("{row}: {refusal}")
        }
        ("fstat0" | "mismatch0", Err(refusal)) => {
            let want_fstat = row == "fstat0";
            assert!(
                if want_fstat {
                    matches!(refusal.error, AcquireError::Fstat(libc::EIO))
                } else {
                    matches!(refusal.error, AcquireError::OtherFile { .. })
                },
                "{refusal}"
            );
            let fd = refusal.retained_fd.expect("retained");
            assert!(fd >= 3);
            assert_eq!(fd_id(fd), fd_id(0), "both descriptors kept");
            if want_fstat {
                holder.unwrap().execute_batch("COMMIT").unwrap();
            }
            format!("{row}: {refusal}")
        }
        ("memerr0", Err(refusal)) => {
            // The duplicate went to SQLite (and was closed with its failed
            // connection); the low slot stays open and is reported.
            assert!(
                matches!(refusal.error, AcquireError::Sqlite(_)),
                "{refusal}"
            );
            assert_eq!(refusal.retained_fd, Some(0));
            assert!(fd_is_open(0));
            assert_eq!(fd_id(0), id_of(&a), "slot 0 still holds the opened file");
            format!("{row}: {refusal}")
        }
        ("fifo0", Err(refusal)) => {
            // The high duplicate of a non-regular file is closed; the low
            // slot stays open on the FIFO and is reported.
            assert!(
                matches!(refusal.error, AcquireError::NotRegular { mode } if mode & 0o170000 == 0o010000),
                "{refusal}"
            );
            assert_eq!(refusal.retained_fd, Some(0));
            let st = fd_stat(0);
            assert_eq!(
                (st.st_mode as u32) & libc::S_IFMT as u32,
                libc::S_IFIFO as u32
            );
            assert_eq!(fd_id(0), id_of(&a), "slot 0 holds the FIFO");
            format!("{row}: {refusal}")
        }
        (row, Ok(_)) => panic!("{row}: acquired"),
        (row, Err(refusal)) => panic!("{row}: {refusal}"),
    };
    detail
}

fn sqlite_err() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR), None)
}

/// Design §5 "Final decision", every row (Fable N3: an SQLite error after an
/// accepted fresh descriptor is that SQLite error, decided only after the
/// low-descriptor and latched-mismatch rows).
#[test]
fn regression_checked_open_decision_table() {
    let id = (7, 42);
    let existing = Expect::Existing {
        id,
        require_nonempty: true,
    };
    let base = Acquisition::new(existing);
    let ok = || Connection::open_in_memory();
    let low = |fatal, released| {
        Some(Low {
            fd: 1,
            fatal,
            released,
        })
    };
    let other = Some(Mismatch::OtherFile { actual: (7, 43) });
    type Want = fn(&Result<Acquired, Refusal>) -> bool;
    let rows: Vec<(&str, Acquisition, bool, Want)> = vec![
        (
            "fatal low beats mismatch and error",
            Acquisition {
                low: low(true, true),
                refusal: other,
                first: Some(id),
                ..base
            },
            false,
            |r| {
                matches!(
                    r,
                    Err(Refusal {
                        error: AcquireError::LowDescriptor {
                            fd: 1,
                            locks_may_be_released: true
                        },
                        retained_fd: None
                    })
                )
            },
        ),
        (
            "unreleased fatal low reports the retained slot",
            Acquisition {
                low: low(true, false),
                ..base
            },
            true,
            |r| {
                matches!(
                    r,
                    Err(Refusal {
                        error: AcquireError::LowDescriptor {
                            locks_may_be_released: false,
                            ..
                        },
                        retained_fd: Some(1)
                    })
                )
            },
        ),
        (
            "mismatch beats a SQLite error",
            Acquisition {
                refusal: other,
                retained: Some(9),
                ..base
            },
            false,
            |r| {
                matches!(
                    r,
                    Err(Refusal {
                        error: AcquireError::OtherFile { .. },
                        retained_fd: Some(9)
                    })
                )
            },
        ),
        (
            "mismatch refuses a returned connection",
            Acquisition {
                refusal: other,
                stats: 2,
                ..base
            },
            true,
            |r| {
                matches!(
                    r,
                    Err(Refusal {
                        error: AcquireError::OtherFile { .. },
                        ..
                    })
                )
            },
        ),
        (
            "N3: SQLite error after an accepted fresh descriptor",
            Acquisition {
                first: Some(id),
                opened: true,
                stats: 1,
                ..base
            },
            false,
            |r| {
                matches!(
                    r,
                    Err(Refusal {
                        error: AcquireError::Sqlite(_),
                        retained_fd: None
                    })
                )
            },
        ),
        (
            "SQLite error after a kept low slot reports that slot",
            Acquisition {
                first: Some(id),
                opened: true,
                low: low(false, false),
                ..base
            },
            false,
            |r| {
                matches!(
                    r,
                    Err(Refusal {
                        error: AcquireError::Sqlite(_),
                        retained_fd: Some(1)
                    })
                )
            },
        ),
        (
            "a retained descriptor is reported before a kept low slot",
            Acquisition {
                refusal: other,
                low: low(false, false),
                retained: Some(9),
                ..base
            },
            false,
            |r| {
                matches!(
                    r,
                    Err(Refusal {
                        error: AcquireError::OtherFile { .. },
                        retained_fd: Some(9)
                    })
                )
            },
        ),
        ("SQLite error, no evidence", base, false, |r| {
            matches!(
                r,
                Err(Refusal {
                    error: AcquireError::Sqlite(_),
                    ..
                })
            )
        }),
        (
            "accepted descriptor",
            Acquisition {
                first: Some(id),
                opened: true,
                low: low(false, false),
                ..base
            },
            true,
            |r| {
                matches!(
                    r,
                    Ok(Acquired {
                        id: Some((7, 42)),
                        verification: Verification::UnixDescriptor,
                        retained_low_fd: Some(1),
                        ..
                    })
                )
            },
        ),
        (
            "verified reuse",
            Acquisition { stats: 2, ..base },
            true,
            |r| {
                matches!(
                    r,
                    Ok(Acquired {
                        id: Some((7, 42)),
                        verification: Verification::UnixReuse,
                        ..
                    })
                )
            },
        ),
        ("reuse without a stat", base, true, |r| {
            matches!(
                r,
                Err(Refusal {
                    error: AcquireError::ReusedUnverified,
                    ..
                })
            )
        }),
        (
            "Fresh never accepts a reuse",
            Acquisition {
                stats: 1,
                ..Acquisition::new(Expect::Fresh)
            },
            true,
            |r| {
                matches!(
                    r,
                    Err(Refusal {
                        error: AcquireError::ReusedUnverified,
                        ..
                    })
                )
            },
        ),
    ];
    for (name, a, connected, want) in rows {
        let result = if connected { ok() } else { Err(sqlite_err()) };
        let got = decide(a, result);
        assert!(want(&got), "{name}: {got:?}");
    }
}

/// Regression (Fable N3), end to end on Linux: `/proc/self/mem` is a regular
/// file whose descriptor is accepted, and SQLite's header read then fails
/// with EIO. The result is that SQLite error, not a validation refusal.
#[cfg(target_os = "linux")]
#[test]
fn regression_checked_open_sqlite_error_after_accepted_descriptor() {
    let mem = Path::new("/proc/self/mem");
    if !mem.exists() {
        eprintln!("skip: /proc is not mounted");
        return;
    }
    let refusal = open_checked(mem, RO, NameMode::Path, existing(mem, false)).unwrap_err();
    assert!(
        matches!(refusal.error, AcquireError::Sqlite(_)) && refusal.retained_fd.is_none(),
        "{refusal}"
    );
}

/// The native `struct stat` layout as SQLite's amalgamation sees it (its
/// large-file defines first), from a C probe compiled and run at test time:
/// `(size, align, st_dev, st_ino, st_mode, st_size)`. `None` without a C
/// compiler (`CC`, split on whitespace so it may carry arguments, else `cc`).
/// It compiles for the host, so under `--target` it is meaningful only when
/// the target is the host (the only such catalog row). Never in a build script: that would run in
/// every consumer build and break the stub-compiler cross-check (Fable nit 8).
fn native_c_stat_layout(dir: &Path) -> Option<(usize, usize, usize, usize, usize, usize)> {
    let cc_line = std::env::var("CC").unwrap_or_default();
    let mut words = cc_line.split_whitespace();
    let cc = words.next().unwrap_or("cc").to_owned();
    let cc_args: Vec<String> = words.map(str::to_owned).collect();
    let source = dir.join("stat_probe.c");
    let exe = dir.join("stat_probe");
    std::fs::write(
        &source,
        "#define _LARGE_FILE 1\n\
         #ifndef _FILE_OFFSET_BITS\n#define _FILE_OFFSET_BITS 64\n#endif\n\
         #define _LARGEFILE_SOURCE 1\n\
         #include <stddef.h>\n#include <stdio.h>\n#include <sys/stat.h>\n\
         int main(void) {\n\
           printf(\"%zu %zu %zu %zu %zu %zu\\n\", sizeof(struct stat),\n\
                  _Alignof(struct stat), offsetof(struct stat, st_dev),\n\
                  offsetof(struct stat, st_ino), offsetof(struct stat, st_mode),\n\
                  offsetof(struct stat, st_size));\n\
           return 0;\n\
         }\n",
    )
    .unwrap();
    let built = Command::new(&cc)
        .args(&cc_args)
        .arg("-std=c11")
        .arg("-o")
        .arg(&exe)
        .arg(&source)
        .status();
    match built {
        Ok(status) if status.success() => {}
        Ok(status) => panic!("the C stat probe did not compile with {cc:?}: {status}"),
        Err(e) => {
            eprintln!("skip: no C compiler ({cc:?}: {e}); native stat probe not run");
            return None;
        }
    }
    let out = Command::new(&exe).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let v: Vec<usize> = String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();
    assert_eq!(v.len(), 6, "{v:?}");
    Some((v[0], v[1], v[2], v[3], v[4], v[5]))
}

/// Pins `libc::stat` to the native `struct stat` the wrappers read (Fable
/// nit 8: size, alignment and the four fields judged), and a real round trip
/// through the installed `stat`/`open` wrappers.
///
/// Regression (#151, design §5 "ABI and TLS"; S2 review deferred it to S4):
/// the per-target table alone could agree with `libc::stat` while both
/// disagreed with the system headers SQLite is compiled against; a C probe
/// with SQLite's large-file defines must report the same layout (`skip:` for
/// that half without a C compiler).
#[test]
fn regression_sqlite_syscall_stat_abi() {
    use std::mem::{align_of, offset_of, size_of};
    // (size, align, st_dev, st_ino, st_mode, st_size)
    let want: (usize, usize, usize, usize, usize, usize) =
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            (144, 8, 0, 8, 24, 48)
        } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            (128, 8, 0, 8, 16, 48)
        } else if cfg!(target_os = "macos") {
            (144, 8, 0, 8, 4, 96)
        } else {
            unreachable!("not a verified target")
        };
    let got = (
        size_of::<libc::stat>(),
        align_of::<libc::stat>(),
        offset_of!(libc::stat, st_dev),
        offset_of!(libc::stat, st_ino),
        offset_of!(libc::stat, st_mode),
        offset_of!(libc::stat, st_size),
    );
    assert_eq!(got, want);
    let (_t, dir) = tempdir();
    if let Some(native) = native_c_stat_layout(&dir) {
        assert_eq!(native, want, "C headers vs the pinned table");
    }
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let got = open_checked(&a, RO, NameMode::Path, existing(&a, true)).unwrap();
    assert_eq!(got.id, Some(id_of(&a)));
    assert_eq!(count(&got.conn), 1);
}

/// The request is refused before anything is armed.
#[test]
fn regression_checked_open_invalid_requests() {
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let e = existing(&a, true);
    for (flags, mode) in [
        (RO | OpenFlags::SQLITE_OPEN_MEMORY, NameMode::Path),
        (RO | OpenFlags::SQLITE_OPEN_SHARED_CACHE, NameMode::Path),
        (RW, NameMode::Immutable),
        (RO | OpenFlags::SQLITE_OPEN_CREATE, NameMode::Immutable),
        (OpenFlags::default(), NameMode::Immutable),
    ] {
        let refusal = open_checked(&a, flags, mode, e).unwrap_err();
        assert!(
            matches!(refusal.error, AcquireError::InvalidRequest(_)),
            "{flags:?} {mode:?}: {refusal}"
        );
        assert_eq!(ArmGuard::peek(), None);
    }
    // SQLITE_OPEN_URI (part of `OpenFlags::default()`) is stripped.
    let got = open_checked(&a, OpenFlags::default(), NameMode::Path, e).unwrap();
    assert_eq!(got.id, Some(id_of(&a)));
}

/// The pinned VFS's name on this target.
fn want_vfs() -> &'static str {
    if cfg!(target_os = "macos") {
        "unix-posix"
    } else {
        "unix"
    }
}

/// Regression (#153, Fable r11 N1): a name with SQLite URI syntax opens the
/// literal file through the pinned VFS. libsqlite3-sys compiles
/// `SQLITE_USE_URI`, so stripping `SQLITE_OPEN_URI` alone does nothing: a
/// relative `file:x?vfs=unix-none` would be parsed as a URI (VFS override),
/// and a URI `modeof=` would `stat` another path inside the armed window.
/// Absolute names (a relative one is made absolute) and the percent-encoded
/// immutable URI keep every such name literal.
#[test]
fn regression_checked_open_uri_cannot_override_vfs() {
    // Relative names, in a child whose working directory is a temp dir (the
    // parent's must not change under parallel tests).
    let (_t, cwd) = tempdir();
    let got = run_child_in("uri_relative", None, Some(&cwd));
    assert_eq!(got.trim(), "ok literal");

    let (_t, dir) = tempdir();
    let sub = dir.join("file:d");
    std::fs::create_dir(&sub).unwrap();
    for name in [
        dir.join("a?vfs=unix-none"),
        dir.join("b%3Fvfs=unix-none"),
        dir.join("c#vfs=unix-none"),
        sub.join("x?vfs=unix-none&mode=memory"),
    ] {
        make_db(&name, 1);
        for flags in [RO, OpenFlags::default()] {
            let got = open_checked(&name, flags, NameMode::Path, existing(&name, true))
                .unwrap_or_else(|r| panic!("{name:?}: {r}"));
            assert_eq!(got.id, Some(id_of(&name)), "{name:?}");
            assert_eq!(vfs_name(&got.conn), want_vfs(), "{name:?}");
            assert_eq!(count(&got.conn), 1, "{name:?}");
        }
    }

    // A fresh database whose name carries `modeof=`: created literally, with
    // the mode a plain name gets, not the mode of the `modeof` target.
    let target = dir.join("target");
    std::fs::write(&target, b"x").unwrap();
    std::fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let plain = dir.join("plain.sqlite");
    // (A `/` in the value would make it a directory path, so `target` is
    // named relative to the working directory as SQLite would resolve it.)
    let modeof = dir.join("m?modeof=target&vfs=unix-none");
    for name in [&plain, &modeof] {
        let got = open_checked(name, RWC, NameMode::Path, Expect::Fresh)
            .unwrap_or_else(|r| panic!("{name:?}: {r}"));
        assert_eq!(vfs_name(&got.conn), want_vfs());
        assert_eq!(got.id, Some(id_of(name)));
    }
    let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o777;
    assert_eq!(mode(&modeof), mode(&plain));

    // The immutable URI encodes every reserved byte: the literal file opens,
    // read-only.
    let weird = dir.join("e?vfs=unix-none&modeof=x#y%41 z");
    make_db(&weird, 7);
    let got = open_checked(&weird, RO, NameMode::Immutable, existing(&weird, true)).unwrap();
    assert_eq!(got.id, Some(id_of(&weird)));
    assert_eq!(vfs_name(&got.conn), want_vfs());
    assert_eq!(
        got.conn
            .query_row("SELECT x FROM t", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert!(got.conn.execute_batch("INSERT INTO t VALUES (8)").is_err());
    assert_eq!(
        immutable_uri(&weird),
        format!(
            "file:{}/e%3Fvfs%3Dunix-none%26modeof%3Dx%23y%2541%20z?mode=ro&immutable=1",
            dir.display()
        )
    );
}

/// The child half of [`regression_checked_open_uri_cannot_override_vfs`]:
/// relative names under this process's working directory.
fn uri_relative_row() -> String {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    let literal = cwd.join("file:x?vfs=unix-none");
    make_db(&literal, 3);
    let got = open_checked(
        Path::new("file:x?vfs=unix-none"),
        OpenFlags::default(),
        NameMode::Path,
        existing(&literal, true),
    )
    .unwrap();
    assert_eq!(got.id, Some(id_of(&literal)));
    assert_eq!(vfs_name(&got.conn), want_vfs());
    assert_eq!(count(&got.conn), 1);
    drop(got);
    // `modeof=` names a file that exists; as a URI it would set the new
    // database's mode (and be `stat`ed while armed). It is a literal name.
    std::fs::write(cwd.join("target"), b"x").unwrap();
    std::fs::set_permissions(
        cwd.join("target"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let relative = "file:y?modeof=target&vfs=unix-none";
    let got = open_checked(Path::new(relative), RWC, NameMode::Path, Expect::Fresh).unwrap();
    assert_eq!(vfs_name(&got.conn), want_vfs());
    let created = cwd.join(relative);
    assert_eq!(got.id, Some(id_of(&created)));
    assert!(!cwd.join("y").exists());
    "literal".into()
}

/// The VFS SQLite actually opened the main database with.
fn vfs_name(conn: &Connection) -> String {
    use rusqlite::ffi;
    let mut name: *mut std::os::raw::c_char = std::ptr::null_mut();
    // SAFETY: SQLITE_FCNTL_VFSNAME writes a sqlite3_malloc'd string.
    unsafe {
        let rc = ffi::sqlite3_file_control(
            conn.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_VFSNAME,
            (&mut name as *mut *mut std::os::raw::c_char).cast(),
        );
        assert_eq!(rc, ffi::SQLITE_OK);
        let s = std::ffi::CStr::from_ptr(name)
            .to_string_lossy()
            .into_owned();
        ffi::sqlite3_free(name.cast());
        s
    }
}

/// Regression (r9 v2 #4): checked opens pin the VFS whose syscall table
/// carries the wrappers: `"unix-posix"` on macOS (no AFP/dotlock/nolock
/// selection by pathname), `"unix"` on Linux; a reused descriptor goes
/// through the same VFS and the holder's lock survives the reuse and close.
#[test]
fn regression_macos_checked_open_uses_posix_vfs() {
    let want = if cfg!(target_os = "macos") {
        "unix-posix"
    } else {
        "unix"
    };
    let (_t, dir) = tempdir();
    let a = dir.join("a.sqlite");
    make_db(&a, 1);
    let holder = Connection::open(&a).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (2)")
        .unwrap();
    let r1 = open_checked(&a, RO, NameMode::Path, existing(&a, true)).unwrap();
    assert_eq!(r1.verification, Verification::UnixDescriptor);
    assert_eq!(vfs_name(&r1.conn), want);
    drop(r1);
    let r2 = open_checked(&a, RO, NameMode::Path, existing(&a, true)).unwrap();
    assert_eq!(r2.verification, Verification::UnixReuse);
    assert_eq!(vfs_name(&r2.conn), want);
    drop(r2);
    assert!(other_process_sees_lock(&a), "the holder's lock survived");
    holder.execute_batch("COMMIT").unwrap();
}

/// Regression (S3 review nit): the seams carry a `RATARMOUNT_TEST_` string
/// for the release check (`packaging/test-no-test-hooks-in-release.sh`).
/// This checks the prefix and that the string is in a linked binary; this
/// test references the constant itself, so it does not prove that
/// `seams::fire`'s reference alone keeps it in a non-test build.
#[test]
fn regression_seams_carry_release_marker() {
    assert!(super::imp::seams::RELEASE_MARKER.starts_with("RATARMOUNT_TEST_"));
    let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let marker = super::imp::seams::RELEASE_MARKER.as_bytes();
    assert!(
        exe.windows(marker.len()).any(|w| w == marker),
        "the linked binary keeps the marker"
    );
}
