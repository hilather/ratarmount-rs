//! Primitive regressions of the managed byte reader (#151, R11-S7).

use super::*;
use rusqlite::Connection;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::Ordering;

#[cfg(unix)]
use super::lock_probe::other_process_sees_lock;

/// A canonical temporary directory (macOS `/var` is a symlink).
fn tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

/// A real database with some rows.
fn database(path: &Path, wal: bool) {
    let c = Connection::open(path).unwrap();
    if wal {
        c.pragma_update(None, "journal_mode", "WAL").unwrap();
    }
    c.execute_batch(
        "CREATE TABLE t(x BLOB); INSERT INTO t VALUES (randomblob(300000)), (randomblob(5000));",
    )
    .unwrap();
}

/// A connection holding SHARED on the main file (an open read transaction).
fn holder(path: &Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.execute_batch("BEGIN").unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
        .unwrap();
    assert!(n > 0);
    c
}

#[cfg(unix)]
fn fds_on(path: &Path) -> usize {
    #[cfg(target_os = "linux")]
    {
        let want = std::fs::canonicalize(path).unwrap();
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|e| std::fs::read_link(e.path()).ok().as_deref() == Some(want.as_path()))
            .count()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        0
    }
}

/// Regression: an internal read of a file that is open as a database in this
/// process (same name, then a hard link to it) dropped a `File` and so
/// released the connection's POSIX locks; another process could then take a
/// write lock. The managed cursor's close leaves the lock in place; a raw
/// `File` close (the negative control) releases it.
#[cfg(unix)]
#[test]
fn regression_internal_cursor_close_keeps_posix_lock() {
    for wal in [false, true] {
        let (_d, dir) = tempdir();
        let db = dir.join("index.sqlite");
        database(&db, wal);
        let alias = dir.join("alias");
        std::fs::hard_link(&db, &alias).unwrap();
        let h = holder(&db);
        assert!(other_process_sees_lock(&db), "holder must hold SHARED");
        for name in [&db, &alias, &db] {
            let mut c = ManagedReadCursor::open(name).unwrap();
            let mut all = Vec::new();
            c.read_to_end(&mut all).unwrap();
            assert_eq!(all.len() as u64, std::fs::metadata(&db).unwrap().len());
            let other = c.independent_cursor();
            drop(c);
            assert!(other_process_sees_lock(&db), "lock kept with a cursor open");
            drop(other);
            assert!(
                other_process_sees_lock(&db),
                "wal={wal}: the managed close released the holder's lock"
            );
            // The whole-file helpers too.
            sha256_hex(name).unwrap();
            read(name).unwrap();
            assert!(other_process_sees_lock(&db));
        }
        // Negative control: the oracle discriminates.
        drop(std::fs::File::open(&alias).unwrap());
        assert!(
            !other_process_sees_lock(&db),
            "a raw close must release the lock (oracle check)"
        );
        drop(h);
        let h2 = holder(&db);
        assert!(other_process_sees_lock(&db));
        drop(h2);
        assert!(!other_process_sees_lock(&db), "released after the holder");
    }
}

/// Regression: a cursor opened BEFORE the connection took its lock (cursor
/// first, database second) also leaves the lock in place on close.
#[cfg(unix)]
#[test]
fn regression_internal_cursor_before_sqlite_open_keeps_lock() {
    let (_d, dir) = tempdir();
    let db = dir.join("x.sqlite");
    database(&db, false);
    let mut c = ManagedReadCursor::open(&db).unwrap();
    let h = holder(&db);
    let mut buf = [0u8; 100];
    c.read_exact(&mut buf).unwrap();
    assert_eq!(&buf[..16], b"SQLite format 3\0");
    drop(c);
    assert!(other_process_sees_lock(&db));
    drop(h);
    assert!(!other_process_sees_lock(&db));
}

/// Regression: independent cursors share one owner with separate offsets.
#[test]
fn regression_internal_cursor_clones_have_independent_offsets() {
    let (_d, dir) = tempdir();
    let f = dir.join("f");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&f, &data).unwrap();
    let mut a = ManagedReadCursor::open(&f).unwrap();
    let mut b = a.independent_cursor();
    let mut x = [0u8; 10];
    a.seek(SeekFrom::Start(1000)).unwrap();
    a.read_exact(&mut x).unwrap();
    assert_eq!(&x[..], &data[1000..1010]);
    b.read_exact(&mut x).unwrap();
    assert_eq!(&x[..], &data[..10]);
    assert_eq!(b.seek(SeekFrom::End(-5)).unwrap(), data.len() as u64 - 5);
    let mut rest = Vec::new();
    b.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, &data[data.len() - 5..]);
    a.read_exact(&mut x).unwrap();
    assert_eq!(&x[..], &data[1010..1020]);
    let mut all = Vec::new();
    let mut c = a.independent_cursor();
    c.read_to_end(&mut all).unwrap();
    assert_eq!(all, data);
    assert_eq!(a.len().unwrap(), data.len() as u64);
    // Each read is at most MAX_READ_CHUNK bytes.
    let mut big = vec![0u8; 1 << 20];
    assert_eq!(c.read_at(&mut big, 0).unwrap(), MAX_READ_CHUNK);
}

/// Regression: repeated managed opens while a lock is held reuse SQLite's
/// parked descriptor instead of growing (Linux: counted in /proc/self/fd).
#[cfg(unix)]
#[test]
fn regression_internal_cursor_reopen_reuses_sqlite_deferred_fd() {
    let (_d, dir) = tempdir();
    let db = dir.join("x.sqlite");
    database(&db, true);
    let h = holder(&db);
    let base = fds_on(&db);
    for _ in 0..50 {
        let c = ManagedReadCursor::open(&db).unwrap();
        c.len().unwrap();
        drop(c);
    }
    let after = fds_on(&db);
    if cfg!(target_os = "linux") {
        assert!(
            after <= base + 1,
            "parked descriptors grew: {base} -> {after}"
        );
    } else {
        eprintln!("skip: descriptor count is Linux-only (/proc/self/fd)");
    }
    assert!(other_process_sees_lock(&db));
    drop(h);
}

/// Regression: a file that shrinks while it is read gives an error, never a
/// digest over SQLite's zero-filled tail.
#[test]
fn regression_internal_cursor_short_read_never_hashes_zero_fill() {
    let (_d, dir) = tempdir();
    let f = dir.join("f");
    std::fs::write(&f, vec![7u8; 400_000]).unwrap();
    let path = f.clone();
    let mut reads = 0;
    let got = seams::with(
        move |s| {
            if s == Seam::BeforeRead {
                reads += 1;
                if reads == 2 {
                    // Shrink inside the read in flight (64 KiB reads: the
                    // second covers 65536..131072), after its length check.
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(100_000)
                        .unwrap();
                }
            }
            Ok(())
        },
        || sha256_hex(&f),
    );
    let e = got.expect_err("a short read must fail");
    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "{e}");
}

/// Regression: an acquisition or read failure is an error (no raw reader
/// fallback), with the injected error preserved.
#[test]
fn regression_internal_cursor_failure_has_no_raw_fallback() {
    let (_d, dir) = tempdir();
    let f = dir.join("f");
    std::fs::write(&f, b"data").unwrap();
    for seam in [Seam::BeforeOpen, Seam::AfterOpen, Seam::BeforeRead] {
        let got = seams::with(
            move |s| {
                if s == seam {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            },
            || read(&f),
        );
        let e = got.expect_err("no fallback");
        assert!(e.to_string().contains("injected"), "{seam:?}: {e}");
    }
    assert_eq!(
        ManagedReadCursor::open(&dir.join("missing"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(
        ManagedReadCursor::open(&dir).is_err(),
        "a directory is no byte file"
    );
}

/// Regression: an empty file on an ordinary filesystem reads as EOF; a
/// 1-byte file (which SQLite's xFileSize reports as 0) reads its byte.
#[test]
fn regression_internal_cursor_empty_native_file_reads_eof() {
    let (_d, dir) = tempdir();
    let one = dir.join("one");
    std::fs::write(&one, b"Z").unwrap();
    assert_eq!(ManagedReadCursor::open(&one).unwrap().len().unwrap(), 1);
    assert_eq!(read(&one).unwrap(), b"Z");
    let (_d, dir) = tempdir();
    let f = dir.join("empty");
    std::fs::write(&f, b"").unwrap();
    let mut c = ManagedReadCursor::open(&f).unwrap();
    assert_eq!(c.len().unwrap(), 0);
    let mut buf = [0u8; 8];
    assert_eq!(c.read(&mut buf).unwrap(), 0);
    assert_eq!(read(&f).unwrap(), b"");
    assert_eq!(
        sha256_hex(&f).unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

/// Regression: on macOS FAT/exFAT SQLite cannot register an empty file
/// read-only; the acquisition error propagates (no raw fallback, the file is
/// unchanged). Needs `RATARMOUNT_TEST_FAT_DIR` (a FAT/exFAT mount) on macOS;
/// the always-on half injects the acquisition error.
#[test]
fn regression_internal_cursor_macos_empty_fat_reports_acquisition_error() {
    let (_d, dir) = tempdir();
    let f = dir.join("empty");
    std::fs::write(&f, b"").unwrap();
    let got = seams::with(
        |s| {
            if s == Seam::AfterOpen {
                Err(io::Error::other("SQLite code 778 (injected)"))
            } else {
                Ok(())
            }
        },
        || ManagedReadCursor::open(&f),
    );
    assert!(got.is_err());
    assert_eq!(std::fs::metadata(&f).unwrap().len(), 0);
    match std::env::var_os("RATARMOUNT_TEST_FAT_DIR") {
        Some(fat) if cfg!(target_os = "macos") => {
            let f = PathBuf::from(fat).join("ratarmount-empty-managed-read");
            std::fs::write(&f, b"").unwrap();
            assert!(ManagedReadCursor::open(&f).is_err());
            assert_eq!(std::fs::metadata(&f).unwrap().len(), 0, "file unchanged");
            std::fs::remove_file(&f).unwrap();
        }
        _ => eprintln!("skip: no macOS FAT/exFAT fixture (RATARMOUNT_TEST_FAT_DIR)"),
    }
}

// --------------------------------------------------------------------------
// Children: closed standard descriptors and umasks.
// --------------------------------------------------------------------------

const CHILD_ENV: &str = "RATARMOUNT_TEST_MANAGED_READ_CHILD";
const DIR_ENV: &str = "RATARMOUNT_TEST_MANAGED_READ_DIR";

/// Run a row in a child of this test binary; returns its result file.
fn run_child(row: &str, dir: &Path) -> String {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "managed_read::tests::managed_read_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, row)
        .env(DIR_ENV, dir)
        .output()
        .unwrap();
    let got = std::fs::read_to_string(dir.join("result")).unwrap_or_default();
    assert!(
        out.status.success() && got.starts_with("ok"),
        "child {row} failed ({}): {got:?}\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    got
}

/// The child half of [`run_child`] (a no-op unless spawned).
#[test]
fn managed_read_child() {
    let Ok(row) = std::env::var(CHILD_ENV) else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).unwrap());
    let detail = child_row(&row, &dir);
    std::fs::write(dir.join("result"), format!("ok {detail}")).unwrap();
}

#[cfg(unix)]
fn child_row(row: &str, dir: &Path) -> String {
    if let Some(fd) = row.strip_prefix("closed:") {
        let fd: libc::c_int = fd.parse().unwrap();
        let db = dir.join("x.sqlite");
        database(&db, false);
        let h = holder(&db);
        assert!(other_process_sees_lock(&db));
        // SAFETY: the child owns its standard descriptors.
        unsafe { libc::close(fd) };
        let digest = sha256_hex(&db).unwrap();
        assert_eq!(digest.len(), 64);
        let kept = other_process_sees_lock(&db);
        // SAFETY: F_GETFD on a descriptor number.
        let filled = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        drop(h);
        return format!("kept={kept} filled={filled}");
    }
    if row == "fill_fails" {
        let db = dir.join("x.sqlite");
        database(&db, false);
        let h = holder(&db);
        // SAFETY: as above.
        unsafe { libc::close(0) };
        FAIL_LOW_FD_FILL.with(|f| f.set(true));
        let before = XOPEN_CALLS.load(Ordering::SeqCst);
        let refused = ManagedReadCursor::open(&db).is_err();
        let after = XOPEN_CALLS.load(Ordering::SeqCst);
        let kept = other_process_sees_lock(&db);
        drop(h);
        return format!("xopen={} kept={kept} err={refused}", after - before);
    }
    if let Some(umask) = row.strip_prefix("umask:") {
        let umask = u32::from_str_radix(umask, 8).unwrap();
        // SAFETY: a single-threaded child.
        unsafe { libc::umask(umask as libc::mode_t) };
        return mode_rows(dir, umask);
    }
    panic!("unknown row {row}")
}

#[cfg(not(unix))]
fn child_row(row: &str, _dir: &Path) -> String {
    panic!("unknown row {row}")
}

/// Regression: with a standard descriptor closed, SQLite's `robust_open`
/// closed the new descriptor that landed on it (releasing this process's
/// locks on the file). The guard fills 0, 1 and 2 first.
#[cfg(unix)]
#[test]
fn regression_internal_cursor_closed_stdin_keeps_lock() {
    for fd in 0..3 {
        let (_d, dir) = tempdir();
        let got = run_child(&format!("closed:{fd}"), &dir);
        assert_eq!(got.trim(), "ok kept=true filled=true", "fd {fd}");
    }
}

/// Regression: when a vacant standard descriptor cannot be filled the open
/// is refused before SQLite's `xOpen` (zero calls) and the lock stays.
#[cfg(unix)]
#[test]
fn regression_internal_cursor_low_fd_fill_failure_refuses_before_xopen() {
    let (_d, dir) = tempdir();
    let got = run_child("fill_fails", &dir);
    assert_eq!(got.trim(), "ok xopen=0 kept=true err=true");
}

// --------------------------------------------------------------------------
// Copy modes.
// --------------------------------------------------------------------------

#[cfg(unix)]
fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

/// The per-umask rows (in a child: the umask is the child's own).
#[cfg(unix)]
fn mode_rows(dir: &Path, umask: u32) -> String {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    let mut report = Vec::new();
    for src_mode in [0o600u32, 0o640, 0o644, 0o664, 0o751] {
        let src = dir.join(format!("src-{src_mode:o}"));
        std::fs::write(&src, vec![1u8; 300_000]).unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(src_mode)).unwrap();

        // Exclusive-new: created with src & !umask, exact after the copy.
        let dest = dir.join(format!("excl-{src_mode:o}"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (s2, d2) = (Arc::clone(&seen), dest.clone());
        let copy = seams::with(
            move |s| {
                if s == Seam::BeforePermissions {
                    s2.lock().unwrap().push(mode_of(&d2));
                }
                Ok(())
            },
            || {
                copy_exclusive_new(
                    &src,
                    &dest,
                    CopySourcePermissions::Exact,
                    CopyDigest::Sha256,
                )
            },
        )
        .unwrap();
        assert_eq!(copy.len, 300_000);
        assert_eq!(
            copy.sha256.as_deref(),
            Some(sha256_hex(&src).unwrap().as_str())
        );
        assert_eq!(seen.lock().unwrap()[0], src_mode & !umask, "creation mode");
        assert_eq!(mode_of(&dest), src_mode, "exact source mode after the copy");
        // An existing destination is untouched.
        let sentinel = dir.join(format!("sentinel-{src_mode:o}"));
        std::fs::write(&sentinel, b"keep").unwrap();
        std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o604)).unwrap();
        let e = copy_exclusive_new(
            &src,
            &sentinel,
            CopySourcePermissions::Exact,
            CopyDigest::None,
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
        assert_eq!(mode_of(&sentinel), 0o604);

        // Create-or-truncate: exact mode BEFORE the first write, for an
        // absent and for a pre-existing (0-byte, 0666) destination.
        for existing in [false, true] {
            let dest = dir.join(format!("trunc-{src_mode:o}-{existing}"));
            if existing {
                std::fs::write(&dest, b"").unwrap();
                std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o666)).unwrap();
            }
            let seen = Arc::new(Mutex::new(Vec::new()));
            let (s2, d2) = (Arc::clone(&seen), dest.clone());
            let n = seams::with(
                move |s| {
                    if s == Seam::BeforeFirstWrite {
                        s2.lock().unwrap().push(mode_of(&d2));
                    }
                    Ok(())
                },
                || copy_create_or_truncate(&src, &dest),
            )
            .unwrap();
            assert_eq!(n, 300_000);
            assert_eq!(seen.lock().unwrap()[0], src_mode, "mode before data");
            assert_eq!(mode_of(&dest), src_mode);
            assert_eq!(std::fs::read(&dest).unwrap(), std::fs::read(&src).unwrap());

            // A mid-copy read error leaves a partial file with the exact mode.
            let dest = dir.join(format!("partial-{src_mode:o}-{existing}"));
            if existing {
                std::fs::write(&dest, b"").unwrap();
            }
            let mut reads = 0;
            let e = seams::with(
                move |s| {
                    if s == Seam::BeforeRead {
                        reads += 1;
                        if reads == 2 {
                            return Err(io::Error::other("injected read error"));
                        }
                    }
                    Ok(())
                },
                || copy_create_or_truncate(&src, &dest),
            )
            .unwrap_err();
            assert!(e.to_string().contains("injected"));
            let partial = std::fs::metadata(&dest).unwrap().len();
            assert!(partial > 0 && partial < 300_000, "partial {partial}");
            assert_eq!(mode_of(&dest), src_mode, "partial file mode");
        }
        report.push(format!("{src_mode:o}"));
    }
    report.join(",")
}

/// Regression: the copy helpers create with the source mode under the umask
/// and end (exclusive-new) or start writing (create-or-truncate) with the
/// exact source mode; an existing exclusive destination is untouched; a
/// mid-copy read error leaves a partial create-or-truncate destination with
/// the exact source mode. Umasks 002, 022 and 077, each in a fresh child.
#[cfg(unix)]
#[test]
fn regression_exclusive_create_mode_table() {
    for umask in ["002", "022", "077"] {
        let (_d, dir) = tempdir();
        let got = run_child(&format!("umask:{umask}"), &dir);
        assert_eq!(got.trim(), "ok 600,640,644,664,751", "umask {umask}");
    }
}

/// Regression: a failed exclusive copy (source read error, permission
/// failure) removes only the destination it created and reports the error;
/// a source changed during the copy is refused.
#[test]
fn regression_internal_copy_destination_failures() {
    let (_d, dir) = tempdir();
    let src = dir.join("src");
    std::fs::write(&src, vec![3u8; 300_000]).unwrap();
    for seam in [
        Seam::BeforeRead,
        Seam::BeforePermissions,
        Seam::BeforePublish,
    ] {
        let dest = dir.join(format!("dest-{seam:?}"));
        let e = seams::with(
            move |s| {
                if s == seam {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            },
            || copy_exclusive_new(&src, &dest, CopySourcePermissions::Exact, CopyDigest::None),
        )
        .unwrap_err();
        assert!(e.to_string().contains("injected"));
        assert!(!dest.exists(), "{seam:?}: owned destination removed");
    }
    // The source replaced at its name during the copy: refused.
    let dest = dir.join("moved");
    let (s2, d2) = (src.clone(), dir.join("other"));
    std::fs::write(&d2, vec![3u8; 300_000]).unwrap();
    let mut renamed = false;
    let e = seams::with(
        move |s| {
            if s == Seam::BeforeRead && !renamed {
                renamed = true;
                std::fs::rename(&d2, &s2).unwrap();
            }
            Ok(())
        },
        || copy_exclusive_new(&src, &dest, CopySourcePermissions::Exact, CopyDigest::None),
    )
    .unwrap_err();
    assert!(e.to_string().contains("changed while it was copied"), "{e}");
    assert!(!dest.exists());
}
