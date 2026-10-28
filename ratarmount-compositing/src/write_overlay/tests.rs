#![allow(clippy::disallowed_methods)]

use super::*;

/// Offline commit without a classified base: the in-crate fixtures open
/// overlays with `new_for_tests`, which record no base to check.
fn commit_overlay(
    write_overlay: impl AsRef<Path>,
    archive_file: impl AsRef<Path>,
    opts: &CommitOverlayOptions,
) -> Result<bool> {
    let _seal_commit = SealCommitGuard::acquire(write_overlay.as_ref())?;
    commit_overlay_inner(write_overlay.as_ref(), archive_file.as_ref(), None, opts)
}

use ratarmount_compress::{open_seekable_bzip2, open_seekable_xz};
use std::process::Command as StdCommand;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[cfg(unix)]
fn regression_240_overlay_lock_held(root: &Path) -> bool {
    use std::os::fd::AsRawFd;

    let file = File::open(root).unwrap();
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
        false
    } else {
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        true
    }
}

/// Regression: live and on-exit commits must take the overlay flock before
/// their archive guard and retain it through publication, reopen and cleanup.
#[cfg(unix)]
#[test]
fn regression_240_live_commit_holds_overlay_lock_through_publication() {
    use ratarmount_compress::commit_journal::fault;

    for live in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar.zst");
        write_single_frame_tar_zst(&archive, &[ustar_file("old", b"original")]);
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("overlay");
        let mut ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
        ov.set_commit_mode(CommitMode::Append);
        fs::write(overlay.join("new"), b"committed").unwrap();
        let reached_archive = Arc::new(AtomicBool::new(false));
        let reached = reached_archive.clone();
        let locked_overlay = overlay.clone();
        fault::install(move |step| {
            if matches!(step, "before replace" | "copy publish") {
                assert!(regression_240_overlay_lock_held(&locked_overlay));
                reached.store(true, Ordering::SeqCst);
            }
            Ok(())
        });
        let result = if live {
            ov.commit_live(&archive, |path| {
                assert!(regression_240_overlay_lock_held(&overlay));
                reopen_tar_zst(path, false)
            })
        } else {
            ov.commit_atomic(&archive)
        };
        fault::clear();
        assert!(result.unwrap(), "live={live}");
        assert!(reached_archive.load(Ordering::SeqCst), "live={live}");
        assert_ne!(fs::read(&archive).unwrap(), before, "live={live}");
        assert_eq!(overlay.join("new").exists(), !live);
        assert!(!regression_240_overlay_lock_held(&overlay));
    }
}

/// Regression: mounted commit/recovery entries must recheck sealing through
/// their own connection after taking the overlay flock, before archive writes.
#[cfg(unix)]
#[test]
fn regression_240_live_entries_recheck_seal_under_overlay_lock() {
    for entry in [
        "atomic",
        "live",
        "remote_interval",
        "recovery",
        "recovery_with_records",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        fs::write(&archive, pack_tar(&[ustar_file("old", b"original")])).unwrap();
        let before = fs::read(&archive).unwrap();
        let overlay = dir.path().join("overlay");
        let ov = Arc::new(overlay_with_base(Arc::new(NullBase), &overlay));
        fs::write(overlay.join("new"), b"must not be committed").unwrap();
        drop(SealCommitGuard::acquire(&overlay).unwrap());
        // Keep the worker between acquiring the directory lock and inspecting its
        // connection. Unlike a timing-only assertion, the flock probe below
        // proves it reached that operation boundary before the seal is set.
        let db = ov.db.lock().unwrap();
        let committing = ov.clone();
        let target = archive.clone();
        let operation = std::thread::spawn(move || match entry {
            "atomic" => committing.commit_atomic(&target),
            "live" => committing.commit_live(&target, |_| panic!("sealed commit reopened base")),
            "remote_interval" => committing.commit_remote_interval(Duration::ZERO, |_| {
                panic!("sealed remote commit reopened base")
            }),
            "recovery_with_records" => committing
                .recover_member_journal_with_records(&target, &crate::MountRecords::default())
                .map(|_| false),
            _ => committing.recover_member_journal(&target).map(|_| false),
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut locked = false;
        while std::time::Instant::now() < deadline {
            if regression_240_overlay_lock_held(&overlay) {
                locked = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        crate::OverlayMeta::set(&db, "sealed_at", "test seal before commit check").unwrap();
        drop(db);
        let error = operation.join().unwrap().unwrap_err();
        assert!(
            locked,
            "{entry} did not acquire the overlay lock before checking its database"
        );
        assert!(error.to_string().contains("is sealed"), "{entry}: {error}");
        assert_eq!(fs::read(&archive).unwrap(), before, "{entry}");
        assert!(!ratarmount_compress::commit_journal::journal_path(&archive).exists());
        assert!(!regression_240_overlay_lock_held(&overlay));
    }
}

/// Regression: forced recovery with admitted records must refuse a sealed
/// overlay without changing a pending journal or archive, and unsealed replay
/// must retain the overlay lock through journal cleanup.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_239_recovery_entries_guard_pending_journal() {
    use ratarmount_compress::commit_journal::{self, fault};

    for with_records in [false, true] {
        for complete in [false, true] {
            for sealed in [true, false] {
                let dir = tempfile::tempdir().unwrap();
                let archive = dir.path().join("base.tar");
                let original = pack_tar(&[ustar_file("old", b"original")]);
                let replacement = pack_tar(&[ustar_file("new", b"replacement")]);
                fs::write(&archive, &original).unwrap();
                let overlay = dir.path().join("overlay");
                let mut ov = overlay_with_base(Arc::new(NullBase), &overlay);
                ov.force_base_mismatch = true;
                let suffix_path = dir.path().join("suffix");
                fs::write(&suffix_path, &replacement).unwrap();
                let mut suffix = File::open(suffix_path).unwrap();
                let stop = if complete {
                    "locator complete"
                } else {
                    "archive truncate"
                };
                commit_journal::replace_suffix_with_hook(&archive, 0, &mut suffix, &mut |step| {
                    if step == stop {
                        Err(io::Error::other("simulated crash"))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
                let before = fs::read(&archive).unwrap();
                let journal = commit_journal::journal_path(&archive);
                let journal_before = fs::read(&journal).unwrap();
                assert_eq!(
                    commit_journal::pending(&archive).unwrap().unwrap().complete,
                    complete
                );
                if sealed {
                    ov.set_meta("sealed_at", "test seal before recovery")
                        .unwrap();
                }
                let replayed = Arc::new(AtomicBool::new(false));
                let reached = replayed.clone();
                let locked_overlay = overlay.clone();
                fault::install(move |step| {
                    if matches!(step, "rollback truncate" | "rollback unlink") {
                        assert!(!sealed, "sealed recovery reached a write");
                        assert!(regression_240_overlay_lock_held(&locked_overlay));
                        reached.store(true, Ordering::SeqCst);
                    }
                    Ok(())
                });
                let result = if with_records {
                    ov.recover_member_journal_with_records(
                        &archive,
                        &crate::MountRecords::default(),
                    )
                } else {
                    ov.recover_member_journal(&archive)
                };
                fault::clear();
                if sealed {
                    let error = result.unwrap_err();
                    assert!(error.to_string().contains("is sealed"), "{error}");
                    assert_eq!(fs::read(&archive).unwrap(), before);
                    assert_eq!(fs::read(&journal).unwrap(), journal_before);
                    assert!(!replayed.load(Ordering::SeqCst));
                } else {
                    result.unwrap();
                    assert!(replayed.load(Ordering::SeqCst));
                    assert_eq!(
                        fs::read(&archive).unwrap(),
                        if complete { replacement } else { original }
                    );
                    assert!(!journal.exists());
                }
            }
        }
    }
}

/// Regression: a panicking policy must not poison every subsequent mutation.
#[test]
fn regression_policy_panic_does_not_poison_mutations() {
    struct PanicOnce(AtomicBool);
    impl OverlayPolicy for PanicOnce {
        fn check_mutation(&self, _: OverlayMutation, _: &[&str]) -> io::Result<()> {
            assert!(
                !self.0.swap(false, Ordering::SeqCst),
                "injected policy panic"
            );
            Ok(())
        }
        fn check_write(&self, _: &str, _: u64, _: u64, _: u64) -> io::Result<()> {
            Ok(())
        }
    }
    let td = tempfile::tempdir().unwrap();
    let mut ov = WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), td.path()).unwrap();
    ov.set_policy(Some(Arc::new(PanicOnce(AtomicBool::new(true)))));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ov.mkdir("/first", 0o755)))
            .is_err()
    );
    ov.mkdir("/second", 0o755).unwrap();
}

/// Regression: truncating a large archive member charges/copies only the final extent.
#[cfg(unix)]
#[test]
fn regression_truncate_large_member_under_small_quota() {
    let (td, ov, policy) = policy_overlay(
        Arc::new(MemBase::with(&[
            ("/zero", b"large member"),
            ("/prefix", b"large member"),
            ("/open", b"large member"),
        ])),
        3,
    );
    ov.truncate("/zero", 0).unwrap();
    ov.truncate("/prefix", 3).unwrap();
    let fd = ov
        .open_overlay_fd("/open", libc::O_WRONLY | libc::O_TRUNC)
        .unwrap();
    ov.close_overlay_fd(fd);
    assert_eq!(fs::read(td.path().join("prefix")).unwrap(), b"lar");
    assert_eq!(fs::metadata(td.path().join("zero")).unwrap().len(), 0);
    assert_eq!(fs::metadata(td.path().join("open")).unwrap().len(), 0);
    assert_eq!(policy.usage(), (3, 3));
}

/// Regression: Linux O_RDONLY|O_TRUNC must truncate under a policy too.
#[cfg(target_os = "linux")]
#[test]
fn regression_readonly_trunc_open_matches_kernel() {
    let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 8);
    let file = policy_file(&ov, "/file");
    ov.write_at(&file, "/file", 0, b"data").unwrap();
    let fd = ov
        .open_overlay_fd("/file", libc::O_RDONLY | libc::O_TRUNC)
        .unwrap();
    ov.close_overlay_fd(fd);
    assert_eq!(file.metadata().unwrap().len(), 0);
    assert_eq!(policy.usage(), (0, 1));
    ov.finish_owned_write_fd(file);
}

/// Regression: repeated create/unlink/write cannot evade quota via open inodes.
#[cfg(unix)]
#[test]
fn regression_unlinked_writers_retain_growth_until_last_close() {
    use std::os::fd::AsRawFd;
    let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 8);
    let first = policy_file(&ov, "/file");
    ov.unlink("/file").unwrap();
    ov.write_at(&first, "/file", 0, b"1234").unwrap();
    let alias = ov.clone_overlay_fd(first.as_raw_fd(), "/file").unwrap();
    let second = policy_file(&ov, "/file");
    ov.unlink("/file").unwrap();
    ov.truncate_file(&second, "/file", 4).unwrap();
    let third = policy_file(&ov, "/file");
    ov.unlink("/file").unwrap();
    assert_eq!(
        ov.write_at(&third, "/file", 0, b"x").unwrap_err().kind(),
        io::ErrorKind::QuotaExceeded
    );
    ov.finish_owned_write_fd(first);
    assert_eq!(policy.usage().0, 8, "duplicate still owns the charge");
    ov.finish_owned_write_fd(alias);
    assert_eq!(policy.usage().0, 4);
    ov.write_at(&third, "/file", 0, b"x").unwrap();
    ov.finish_owned_write_fd(second);
    ov.finish_owned_write_fd(third);
    assert_eq!(policy.usage(), (0, 0));
}

/// Regression: slow COW decompression must not hold the global policy lock.
#[cfg(unix)]
#[test]
fn regression_slow_cow_does_not_block_small_write() {
    let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/large", b"abcdef")])), 8);
    let small = policy_file(&ov, "/small");
    let ov = Arc::new(ov);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    *ov.cow_before_read_hook.lock().unwrap() = Some(Box::new(move || {
        started_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
    }));
    let copy_ov = ov.clone();
    let copy = std::thread::spawn(move || copy_ov.ensure_modifiable("/large"));
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(policy.usage().0, 6, "COW extent reserved before reading");
    let write_ov = ov.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let write = std::thread::spawn(move || {
        let result = write_ov.write_at(&small, "/small", 0, b"xy");
        write_ov.finish_owned_write_fd(small);
        done_tx.send(result).unwrap();
    });
    let result = done_rx.recv_timeout(Duration::from_secs(5));
    resume_tx.send(()).unwrap();
    copy.join().unwrap().unwrap();
    write.join().unwrap();
    assert_eq!(result.unwrap().unwrap(), 2);
    assert_eq!(policy.usage(), (8, 2));
}

/// Regression: rename's SQL retry/backoff must not monopolize policy checks.
#[test]
fn regression_rename_retry_releases_policy_gate() {
    let (_td, ov, _) = policy_overlay(Arc::new(MemBase::with(&[("/source", b"x")])), 8);
    let ov = Arc::new(ov);
    let weak = Arc::downgrade(&ov);
    ov.set_rename_before_tx_hook(Some(Box::new(move || {
        assert!(weak.upgrade().unwrap().policy_gate.try_lock().is_ok());
        Err(OverlayError::Msg("injected retry".into()))
    })));
    ov.rename("/source", "/dest").unwrap();
}

/// Regression: post-persist read_dir failure disables further commits rather than duplicating members.
#[test]
fn regression_commit_cleanup_read_dir_failure_disables_interval() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", b"seed")]);
    let (_td, ov, _) = policy_overlay(open_tar_zst_base(&archive, false), 8);
    let fd = ov.create_file("/new", 0o644).unwrap();
    ov.close_overlay_fd(fd);
    ov.account_reset_failure.store(true, Ordering::SeqCst);
    let err = ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("persist succeeded; overlay cleanup failed"),
        "{err}"
    );
    assert!(ov.interval_disabled());
    let persisted = fs::read(&archive).unwrap();
    assert!(ov
        .commit_live(&archive, |_| panic!("disabled commit reopened"))
        .is_err());
    assert_eq!(fs::read(&archive).unwrap(), persisted);
    assert!(open_tar_zst_base(&archive, false)
        .lookup("/new", 0)
        .is_some());
}

/// Regression: append-mode descriptors must charge growth even with offset zero.
#[cfg(target_os = "linux")]
#[test]
fn regression_overlay_policy_append_cannot_bypass_quota() {
    use std::os::fd::FromRawFd;
    let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 4);
    let file = unsafe {
        File::from_raw_fd(
            ov.open_overlay_fd("/append", libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND)
                .unwrap(),
        )
    };
    ov.write_at(&file, "/append", 0, b"ab").unwrap();
    ov.write_at(&file, "/append", 0, b"cd").unwrap();
    assert_eq!(policy.usage(), (4, 1));
    assert_eq!(
        ov.write_at(&file, "/append", 0, b"e").unwrap_err().kind(),
        io::ErrorKind::QuotaExceeded
    );
    assert_eq!(file.metadata().unwrap().len(), 4);
    ov.finish_owned_write_fd(file);
}

/// Regression: a failed COW must not publish the short prefix or keep its quota (#126).
#[test]
fn regression_overlay_policy_accounts_partial_cow_failure() {
    struct PartialReader(io::Cursor<Vec<u8>>);
    impl Read for PartialReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.position() >= 3 {
                return Err(io::Error::other("injected read failure"));
            }
            self.0.read(buf)
        }
    }
    impl Seek for PartialReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }
    struct PartialBase;
    impl MountSource for PartialBase {
        fn list(&self, _: &str) -> Option<ListResult> {
            None
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            (path == "/partial").then(|| mem_file_info(path, 6))
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(PartialReader(io::Cursor::new(b"abc".to_vec()))))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }
    let (td, ov, policy) = policy_overlay(Arc::new(PartialBase), 8);
    let host = td.path().join("partial");
    let err = ov.ensure_modifiable("/partial");
    let bytes = fs::read(&host).ok();
    assert!(
        err.is_err() && bytes.is_none() && policy.usage() == (0, 0),
        "failed COW must drop the partial and refund; err={err:?} bytes={bytes:?} usage={:?}",
        policy.usage()
    );
}

/// Regression: a 6-byte member whose read returns 3 bytes then EOF is not
/// published, and the quota charge is refunded to the pre-COW usage (#126).
#[test]
fn regression_overlay_policy_accounts_short_cow_eof_slack() {
    struct EofAfter3(io::Cursor<Vec<u8>>);
    impl Read for EofAfter3 {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.position() >= 3 {
                return Ok(0);
            }
            let room = (3 - self.0.position()) as usize;
            let n = room.min(buf.len());
            self.0.read(&mut buf[..n])
        }
    }
    impl Seek for EofAfter3 {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }
    struct ShortBase;
    impl MountSource for ShortBase {
        fn list(&self, _: &str) -> Option<ListResult> {
            None
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            (path == "/short").then(|| mem_file_info(path, 6))
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(EofAfter3(io::Cursor::new(b"abcdef".to_vec()))))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }
    let (td, ov, policy) = policy_overlay(Arc::new(ShortBase), 8);
    let before = policy.usage();
    let host = td.path().join("short");
    let err = ov.ensure_modifiable("/short");
    let bytes = fs::read(&host).ok();
    assert!(
        matches!(
            &err,
            Err(OverlayError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ) && bytes.is_none()
            && policy.usage() == before,
        "short EOF must not publish and must refund the quota charge; err={err:?} bytes={bytes:?} before={before:?} usage={:?}",
        policy.usage()
    );
}

/// Regression: without a quota policy, a 6-byte member whose read returns 3
/// bytes then EOF is not published and leaves no staging file (#126).
#[test]
fn regression_cow_short_eof_default_path_not_published() {
    struct EofAfter3(io::Cursor<Vec<u8>>);
    impl Read for EofAfter3 {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.position() >= 3 {
                return Ok(0);
            }
            let room = (3 - self.0.position()) as usize;
            let n = room.min(buf.len());
            self.0.read(&mut buf[..n])
        }
    }
    impl Seek for EofAfter3 {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }
    struct ShortBase;
    impl MountSource for ShortBase {
        fn list(&self, _: &str) -> Option<ListResult> {
            None
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            (path == "/short").then(|| mem_file_info(path, 6))
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(EofAfter3(io::Cursor::new(b"abcdef".to_vec()))))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }
    let td = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new_for_tests(Arc::new(ShortBase), td.path()).unwrap();
    let host = td.path().join("short");
    let err = ov.ensure_modifiable("/short");
    let bytes = fs::read(&host).ok();
    let staged = fs::read_dir(td.path())
        .unwrap()
        .flatten()
        .any(|ent| name_has_cow_prefix(&ent.file_name().to_string_lossy()));
    assert!(
        matches!(
            &err,
            Err(OverlayError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ) && bytes.is_none()
            && !staged,
        "short EOF must not publish the final name or leave staging; err={err:?} bytes={bytes:?} staged={staged}"
    );
}

fn name_has_cow_prefix(name: &str) -> bool {
    has_ascii_prefix(name, COW_STAGING_PREFIX)
}

/// Regression: a reader that dies mid-copy must not leave the short bytes at
/// the final name, and a crashed `.ratarmount.overlay.cow-` temp must not be
/// committed (#126).
#[test]
fn regression_cow_crash_mid_copy_hides_partial_and_skips_commit() {
    let original = b"abcdef";
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let mount_tar = dir.path().join("mount.tar");
    let one_tar = dir.path().join("one.tar");
    {
        let mut f = File::create(&mount_tar).unwrap();
        ratarmount_formats_tar::write_ustar_members(
            &mut f,
            &[
                ustar_file("big.bin", original),
                ustar_file("keep.txt", b"keep"),
            ],
        )
        .unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut f).unwrap();
    }
    {
        let mut f = File::create(&one_tar).unwrap();
        ratarmount_formats_tar::write_ustar_members(&mut f, &[ustar_file("big.bin", original)])
            .unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut f).unwrap();
    }

    struct CrashReader {
        overlay: PathBuf,
        data: Vec<u8>,
        pos: usize,
    }
    impl Read for CrashReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= 3 {
                let host = self.overlay.join("big.bin");
                let staged = fs::read_dir(&self.overlay)
                    .map(|rd| {
                        rd.flatten()
                            .any(|ent| name_has_cow_prefix(&ent.file_name().to_string_lossy()))
                    })
                    .unwrap_or(false);
                let bytes = fs::read(&host).ok();
                assert!(
                    staged && !host.exists(),
                    "mid-copy must stage a .ratarmount.overlay.cow- file and leave big.bin absent; staged={staged} big.bin={bytes:?}"
                );
                return Err(io::Error::other("injected read failure"));
            }
            let n = (3 - self.pos)
                .min(buf.len())
                .min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
    impl Seek for CrashReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            let len = self.data.len() as i64;
            let cur = self.pos as i64;
            let next = match pos {
                SeekFrom::Start(n) => n as i64,
                SeekFrom::Current(n) => cur + n,
                SeekFrom::End(n) => len + n,
            };
            if next < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "seek before start",
                ));
            }
            self.pos = next as usize;
            Ok(self.pos as u64)
        }
    }
    struct CrashBase {
        overlay: PathBuf,
        big: Vec<u8>,
    }
    impl MountSource for CrashBase {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path != "/" {
                return None;
            }
            let mut map = BTreeMap::new();
            map.insert(
                "big.bin".into(),
                mem_file_info("/big.bin", self.big.len() as u64),
            );
            map.insert("keep.txt".into(), mem_file_info("/keep.txt", 4));
            Some(ListResult::Infos(map))
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            match path {
                "/" => Some(create_root_file_info()),
                "/big.bin" => Some(mem_file_info(path, self.big.len() as u64)),
                "/keep.txt" => Some(mem_file_info(path, 4)),
                _ => None,
            }
        }
        fn open(
            &self,
            file_info: &FileInfo,
            _: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            let path = file_info.userdata.iter().rev().find_map(|u| match u {
                UserData::Other(s) => s.strip_prefix("mem:"),
                _ => None,
            });
            if path == Some("/big.bin") {
                return Ok(Box::new(CrashReader {
                    overlay: self.overlay.clone(),
                    data: self.big.clone(),
                    pos: 0,
                }));
            }
            Ok(Box::new(io::Cursor::new(b"keep".to_vec())))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    let ov = WriteOverlay::new_for_tests(
        Arc::new(CrashBase {
            overlay: overlay.clone(),
            big: original.to_vec(),
        }),
        &overlay,
    )
    .unwrap();
    ov.unlink("/keep.txt").unwrap();
    assert!(ov.lookup("/keep.txt", 0).is_none());
    let err = ov.ensure_modifiable("/big.bin");
    assert!(err.is_err(), "{err:?}");
    assert!(
        !overlay.join("big.bin").exists(),
        "host big.bin must be absent, got {:?}",
        fs::read(overlay.join("big.bin")).ok()
    );
    assert!(
        fs::read_dir(&overlay)
            .unwrap()
            .flatten()
            .all(|ent| { !name_has_cow_prefix(&ent.file_name().to_string_lossy()) }),
        "failed COW must drop its staging temp"
    );
    drop(ov);

    fs::create_dir_all(overlay.join("sub")).unwrap();
    fs::write(overlay.join(".ratarmount.overlay.cow-Ab12Cd"), b"short").unwrap();
    fs::write(
        overlay.join("sub").join(".ratarmount.overlay.cow-Ab12Cd"),
        b"short",
    )
    .unwrap();
    fs::write(
        overlay.join("sub").join(".RATARMOUNT.OVERLAY.COW-Xy"),
        b"short",
    )
    .unwrap();
    let plan = collect_overlay_commit_plan(&overlay).unwrap();
    assert!(
        plan.append_entries
            .iter()
            .all(|(p, _)| { p != "big.bin" && !p.split('/').any(name_has_cow_prefix) }),
        "commit plan must omit the partial and cow temps: {:?}",
        plan.append_entries
    );
    match commit_overlay(&overlay, &one_tar, &yes_commit_opts()) {
        Ok(_) => {
            let src = open_uncompressed_tar_base(&one_tar, false);
            assert_eq!(read_member(src.as_ref(), "/big.bin"), original);
        }
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: commit_overlay needs GNU tar: {e}");
        }
        Err(e) => panic!("{e}"),
    }

    let ov = WriteOverlay::new_for_tests(open_uncompressed_tar_base(&mount_tar, false), &overlay)
        .unwrap();
    assert!(!overlay.join(".ratarmount.overlay.cow-Ab12Cd").exists());
    assert!(!overlay
        .join("sub")
        .join(".ratarmount.overlay.cow-Ab12Cd")
        .exists());
    assert!(!overlay
        .join("sub")
        .join(".RATARMOUNT.OVERLAY.COW-Xy")
        .exists());
    assert!(overlay.join(HIDDEN_DB).is_file());
    assert!(overlay.join(OVERLAY_MARKER).is_file());
    assert!(ov.is_deleted("/keep.txt"));
    assert!(ov.lookup("/keep.txt", 0).is_none());
    let fi = ov.lookup("/big.bin", 0).unwrap();
    assert_eq!(fi.size, original.len() as u64);
    assert_eq!(ov.read(&fi, original.len(), 0).unwrap(), original);
}

/// Regression: an unreadable overlay directory must not fail reopen (#126 v3).
///
/// Symptom: the copy-on-write staging sweep returned the directory error,
/// so `WriteOverlay::new` failed when a subdirectory was mode 000.
#[cfg(unix)]
#[test]
fn regression_cow_v3_unreadable_dir_reopen() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skip: euid 0 ignores mode 000");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    drop(WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay).unwrap());
    let locked = overlay.join("locked");
    fs::create_dir(&locked).unwrap();
    fs::write(
        locked.join(format!("{COW_STAGING_PREFIX}Ab12Cd")),
        b"leftover",
    )
    .unwrap();
    struct RestoreMode {
        path: PathBuf,
    }
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755));
        }
    }
    let _restore = RestoreMode {
        path: locked.clone(),
    };
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    }
    let err = WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay).err();
    assert!(
        err.is_none(),
        "unreadable dir must not fail reopen: {err:?}"
    );
}

/// Regression: a second open must not sweep another holder's staging file (#126 v3).
///
/// Symptom: `PRAGMA LOCKING_MODE = EXCLUSIVE` keeps only a shared lock until
/// the first write. After schema creation, a reopen does not write, so a
/// second `WriteOverlay::new` succeeded and deleted the in-progress temp.
#[test]
fn regression_cow_v3_second_open_keeps_staging() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    drop(WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay).unwrap());
    let first = WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay).unwrap();
    let staging = overlay.join(format!("{COW_STAGING_PREFIX}Ab12Cd"));
    fs::write(&staging, b"in-progress").unwrap();
    match WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), &overlay) {
        Ok(_) => panic!("second open must be refused while the first holds the lock"),
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("locked") || msg.contains("busy"),
                "second open must be refused with the database lock, got {e}"
            );
        }
    }
    assert_eq!(fs::read(&staging).unwrap(), b"in-progress");
    drop(first);
}

/// Regression: `persist_noclobber` AlreadyExists refunds the reservation (#126 v3).
///
/// Symptom: a final name created after the reservation and before publish
/// was counted or replaced. The existing bytes must stay, the reservation
/// must be refunded by Drop, and the staging temp must be removed.
#[test]
fn regression_cow_v3_already_exists_refunds() {
    let (td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/race", b"abcdef")])), 64);
    let host = td.path().join("race");
    let existing = b"keep-me";
    let ov = Arc::new(ov);
    let host_for_hook = host.clone();
    *ov.cow_before_read_hook.lock().unwrap() = Some(Box::new(move || {
        fs::write(&host_for_hook, existing).unwrap();
    }));
    let before = policy.usage();
    ov.ensure_modifiable("/race").unwrap();
    assert_eq!(
        policy.usage(),
        before,
        "AlreadyExists must skip file_created and let Drop refund the reservation"
    );
    assert_eq!(fs::read(&host).unwrap(), existing);
    assert!(
        fs::read_dir(td.path())
            .unwrap()
            .flatten()
            .all(|ent| { !name_has_cow_prefix(&ent.file_name().to_string_lossy()) }),
        "staging temp must be removed"
    );
}

/// Regression: a persist error other than `AlreadyExists` refunds the reservation (#126 v3).
///
/// Symptom: replacing the parent directory with a regular file makes
/// `persist_noclobber` return `ENOTDIR` (`NotADirectory`, not `ENOENT`:
/// the path component exists and is not a directory). That must not
/// publish `/d/race`, must not run `file_created`, and Drop must refund.
#[cfg(unix)]
#[test]
fn regression_cow_v3_persist_error_refunds() {
    let (td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/d/race", b"abcdef")])), 64);
    fs::create_dir(td.path().join("d")).unwrap();
    let overlay = td.path().to_path_buf();
    *ov.cow_before_persist_hook.lock().unwrap() = Some(Box::new(move || {
        let parent = overlay.join("d");
        fs::rename(&parent, overlay.join("d.held")).unwrap();
        fs::write(&parent, b"not-a-directory").unwrap();
    }));
    let before = policy.usage();
    let err = match ov.ensure_modifiable("/d/race").unwrap_err() {
        OverlayError::Io(err) => err,
        other => panic!("persist error must be io, got {other}"),
    };
    assert_eq!(
        err.kind(),
        io::ErrorKind::NotADirectory,
        "non-AlreadyExists persist error must surface, got {err}"
    );
    assert_eq!(
        policy.usage(),
        before,
        "persist error must skip file_created and let Drop refund the reservation"
    );
    assert!(
        !td.path().join("d").join("race").exists(),
        "final name must not be published"
    );
}

/// Regression: a directory fsync error after publish keeps the charge (#126 v3).
///
/// Symptom: ignoring the parent `sync_all` error would report success, and
/// refunding after `file_created` would drop a file that is already named.
#[cfg(unix)]
#[test]
fn regression_cow_v3_dir_fsync_error_keeps_charge() {
    let (td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/m", b"abcdef")])), 64);
    FAIL_COW_DIR_FSYNC.set(true);
    let err = match ov.ensure_modifiable("/m").unwrap_err() {
        OverlayError::Io(err) => err,
        other => panic!("directory fsync error must be io, got {other}"),
    };
    assert!(
        err.to_string().contains("injected directory fsync failure"),
        "{err}"
    );
    assert_eq!(fs::read(td.path().join("m")).unwrap(), b"abcdef");
    assert_eq!(
        policy.usage(),
        (6, 1),
        "published file must stay charged after a parent fsync error"
    );
}

/// Regression: read-only opens of an existing host file must not invoke a write policy.
#[cfg(unix)]
#[test]
fn regression_overlay_policy_read_open_still_allowed() {
    let td = tempfile::tempdir().unwrap();
    let mut ov = WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[])), td.path()).unwrap();
    ov.mkdir("/locked", 0o755).unwrap();
    let file = policy_file(&ov, "/locked/file");
    ov.write_at(&file, "/locked/file", 0, b"base").unwrap();
    ov.finish_owned_write_fd(file);
    ov.set_policy(Some(Arc::new(CountingPolicy::new(0))));
    let fd = ov.open_overlay_fd("/locked/file", libc::O_RDONLY).unwrap();
    ov.close_overlay_fd(fd);
    assert!(
        matches!(ov.reset_overlay_contents(), Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::ReadOnlyFilesystem)
    );
    assert_eq!(fs::read(td.path().join("locked/file")).unwrap(), b"base");
}

struct CountingPolicy {
    limit: u64,
    usage: Mutex<(u64, u64)>,
}

impl CountingPolicy {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            usage: Mutex::new((0, 0)),
        }
    }
    fn usage(&self) -> (u64, u64) {
        *self.usage.lock().unwrap()
    }
}

impl OverlayPolicy for CountingPolicy {
    fn check_mutation(&self, _: OverlayMutation, paths: &[&str]) -> io::Result<()> {
        if paths
            .iter()
            .any(|p| *p == "/locked" || p.starts_with("/locked/"))
        {
            return Err(io::Error::new(io::ErrorKind::ReadOnlyFilesystem, "locked"));
        }
        Ok(())
    }
    fn check_write(&self, _: &str, offset: u64, len: u64, current_size: u64) -> io::Result<()> {
        let growth = offset.saturating_add(len).saturating_sub(current_size);
        if self.usage().0.saturating_add(growth) > self.limit {
            return Err(io::Error::new(io::ErrorKind::QuotaExceeded, "quota"));
        }
        Ok(())
    }
    fn bytes_changed(&self, _: &str, added: u64, removed: u64) {
        let mut usage = self.usage.lock().unwrap();
        usage.0 = usage
            .0
            .checked_add(added)
            .unwrap()
            .checked_sub(removed)
            .unwrap();
    }
    fn file_created(&self, _: &str) {
        self.usage.lock().unwrap().1 += 1;
    }
    fn file_removed(&self, _: &str) {
        self.usage.lock().unwrap().1 -= 1;
    }
}

/// Regression: policy-path COW applies the member's mode and mtime on the
/// staging fd before publish (#126 v3, Keystone).
///
/// Symptom: dropping the fd `fchmod`/`futimens` step on the Unix policy
/// path publishes the copy with the umask mode and the current time.
#[cfg(unix)]
#[test]
fn regression_cow_policy_applies_member_mode_and_mtime() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut base = MemBase::with(&[("/m", b"abcdef")]);
    let info = base.files.get_mut("/m").unwrap();
    info.mode = ratarmount_core::S_IFREG | 0o751;
    info.mtime = 1_000_000_000.0;
    let (td, ov, _policy) = policy_overlay(Arc::new(base), 64);
    ov.ensure_modifiable("/m").unwrap();
    let md = fs::symlink_metadata(td.path().join("m")).unwrap();
    assert_eq!(
        md.permissions().mode() & 0o7777,
        0o751,
        "member mode must be applied"
    );
    assert_eq!(md.mtime(), 1_000_000_000, "member mtime must be applied");
    assert_eq!(fs::read(td.path().join("m")).unwrap(), b"abcdef");
}

fn policy_overlay(
    base: Arc<dyn MountSource>,
    limit: u64,
) -> (tempfile::TempDir, WriteOverlay, Arc<CountingPolicy>) {
    let td = tempfile::tempdir().unwrap();
    let mut ov = WriteOverlay::new_for_tests(base, td.path()).unwrap();
    let policy = Arc::new(CountingPolicy::new(limit));
    ov.set_policy(Some(policy.clone()));
    (td, ov, policy)
}

#[cfg(unix)]
fn policy_file(ov: &WriteOverlay, path: &str) -> File {
    use std::os::fd::FromRawFd;
    unsafe {
        File::from_raw_fd(
            ov.open_overlay_fd(path, libc::O_RDWR | libc::O_CREAT)
                .unwrap(),
        )
    }
}

/// Regression: readonly paths reject COW, both rename endpoints, and all mutations before side effects.
#[test]
fn regression_overlay_policy_denials_leave_names_unchanged() {
    let (td, ov, policy) = policy_overlay(
        Arc::new(MemBase::with(&[
            ("/locked/file", b"base"),
            ("/outside", b"source"),
        ])),
        64,
    );
    let results = [
        ov.ensure_modifiable("/locked/file"),
        ov.create_file("/locked/new", 0o644)
            .map(|fd| ov.close_overlay_fd(fd)),
        ov.mkdir("/locked/dir", 0o755),
        ov.unlink("/locked/file"),
        ov.unlink_parked("/locked/file").map(|_| ()),
        ov.rmdir("/locked/empty"),
        ov.truncate("/locked/file", 0),
        ov.create_symlink("/locked/link", "target"),
        ov.rename("/locked/file", "/moved"),
        ov.rename("/outside", "/locked/file"),
        ov.rename_parked("/outside", "/locked/file").map(|_| ()),
    ];
    for result in results {
        assert!(
            matches!(result, Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::ReadOnlyFilesystem)
        );
    }
    assert!(!td.path().join("locked").exists());
    assert!(!td.path().join("outside").exists());
    assert_eq!(policy.usage(), (0, 0));
    assert_eq!(ov.lookup("/locked/file", 0).unwrap().size, 4);
}

/// Regression: COW, sparse writes, overwrite, truncate, symlink and rename-over account actual host growth once.
#[cfg(unix)]
#[test]
fn regression_overlay_policy_accounts_cow_truncate_rename_and_reset() {
    let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/base", b"abcdef")])), 64);
    ov.ensure_modifiable("/base").unwrap();
    ov.ensure_modifiable("/base").unwrap();
    assert_eq!(policy.usage(), (6, 1));
    let file = policy_file(&ov, "/base");
    ov.write_at(&file, "/base", 8, b"xy").unwrap();
    assert_eq!(policy.usage(), (10, 1));
    ov.write_at(&file, "/base", 0, b"xy").unwrap();
    assert_eq!(policy.usage(), (10, 1));
    ov.truncate("/base", 3).unwrap();
    assert_eq!(policy.usage(), (3, 1));
    let fd = ov.create_file("/base", 0o644).unwrap();
    ov.close_overlay_fd(fd);
    assert_eq!(policy.usage(), (0, 1));
    ov.create_symlink("/link", "foo").unwrap();
    assert_eq!(policy.usage(), (3, 2));
    ov.unlink("/link").unwrap();
    assert_eq!(policy.usage(), (0, 1));
    ov.write_at(&file, "/base", 0, b"abc").unwrap();
    let dst = policy_file(&ov, "/dest");
    ov.write_at(&dst, "/dest", 0, b"1234").unwrap();
    assert_eq!(policy.usage(), (7, 2));
    ov.rename("/base", "/dest").unwrap();
    assert_eq!(policy.usage(), (3, 1));
    // Detached growth remains charged; shrinking releases only that growth.
    ov.write_at(&dst, "/dest", 8, b"orphan").unwrap();
    ov.truncate_file(&dst, "/dest", 1).unwrap();
    assert_eq!(policy.usage(), (3, 1));
    ov.finish_owned_write_fd(file);
    ov.finish_owned_write_fd(dst);
    ov.create_symlink("/dangling", "/missing/target").unwrap();
    ov.reset_overlay_contents().unwrap();
    assert_eq!(policy.usage(), (0, 0));
}

/// Regression: quota refusal cannot leave a full COW copy or enlarge a truncated file.
#[cfg(unix)]
#[test]
fn regression_overlay_policy_quota_cow_and_truncate() {
    let (td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[("/large", b"abcdef")])), 4);
    assert!(
        matches!(ov.ensure_modifiable("/large"), Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::QuotaExceeded)
    );
    assert!(!td.path().join("large").exists());
    let file = policy_file(&ov, "/small");
    ov.write_at(&file, "/small", 0, b"abcd").unwrap();
    assert_eq!(
        ov.write_at(&file, "/small", 4, b"x").unwrap_err().kind(),
        io::ErrorKind::QuotaExceeded
    );
    assert!(
        matches!(ov.truncate("/small", 5), Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::QuotaExceeded)
    );
    assert_eq!(file.metadata().unwrap().len(), 4);
    let refused = ov.open_overlay_fd(
        "/small",
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC,
    );
    assert!(
        matches!(refused, Err(OverlayError::Io(ref e)) if e.kind() == io::ErrorKind::AlreadyExists)
    );
    assert_eq!(file.metadata().unwrap().len(), 4);
    assert_eq!(policy.usage(), (4, 1));
    let fd = ov
        .open_overlay_fd("/small", libc::O_RDWR | libc::O_TRUNC)
        .unwrap();
    ov.close_overlay_fd(fd);
    assert_eq!(policy.usage(), (0, 1));
    ov.finish_owned_write_fd(file);
}

/// Regression: concurrent checks cannot both spend the same quota allowance.
#[cfg(unix)]
#[test]
fn regression_overlay_policy_concurrent_writes_do_not_overspend() {
    let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 8);
    let ov = Arc::new(ov);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = ["/a", "/b"]
        .into_iter()
        .map(|path| {
            let ov = ov.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let file = policy_file(&ov, path);
                barrier.wait();
                let result = ov.write_at(&file, path, 0, b"12345678");
                ov.finish_owned_write_fd(file);
                result
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .find_map(|r| r.as_ref().err())
            .unwrap()
            .kind(),
        io::ErrorKind::QuotaExceeded
    );
    assert_eq!(policy.usage(), (8, 2));
}

/// Regression: commit cleanup must release quota for removed host files.
#[cfg(unix)]
#[test]
fn regression_overlay_policy_commit_cleanup_releases_usage() {
    let (_td, ov, policy) = policy_overlay(Arc::new(MemBase::with(&[])), 8);
    let file = policy_file(&ov, "/file");
    ov.write_at(&file, "/file", 0, b"abcd").unwrap();
    ov.finish_owned_write_fd(file);
    let plan = OverlayCommitPlan {
        known_hashes: BTreeMap::new(),
        written_hashes: BTreeMap::new(),
        metadata: BTreeMap::new(),
        xattrs: BTreeMap::new(),
        deletions_nul: Vec::new(),
        appends_nul: Vec::new(),
        deleted_paths: HashSet::new(),
        append_entries: vec![("file".into(), false)],
    };
    ov.forget_committed_overlay(&plan).unwrap();
    assert_eq!(policy.usage(), (0, 0));
}

fn write_zero_file(path: &Path, n: usize) {
    fs::write(path, vec![0u8; n]).unwrap();
}

/// Regression: POSIX empty TAR is recognized as uncompressed TAR.
#[test]
fn is_uncompressed_tar_posix_empty_1024_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.tar");
    {
        let mut f = File::create(&path).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut f).unwrap();
    }
    assert!(
        is_uncompressed_tar(&path).unwrap(),
        "1024-zero POSIX empty TAR"
    );
    assert!(
        !ratarmount_compress::looks_like_tar(&path).unwrap(),
        "looks_like_tar must stay false on 1024 zeros"
    );
}

#[test]
fn is_uncompressed_tar_gnu_empty_10240_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.tar");
    write_zero_file(&path, 10240);
    assert!(is_uncompressed_tar(&path).unwrap());
}

#[test]
fn is_uncompressed_tar_rejects_too_short_or_unaligned() {
    let dir = tempfile::tempdir().unwrap();
    for n in [0usize, 512, 1025] {
        let path = dir.path().join(format!("z{n}.tar"));
        write_zero_file(&path, n);
        assert!(
            !is_uncompressed_tar(&path).unwrap(),
            "{n}-byte zeros must not be an empty TAR"
        );
    }
}

#[test]
fn is_uncompressed_tar_rejects_over_10240_zero_head_tail_dirty_middle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dirty.tar");
    let mut buf = vec![0u8; 20 * 1024];
    buf[12 * 1024] = 1;
    fs::write(&path, &buf).unwrap();
    assert!(!is_uncompressed_tar(&path).unwrap());
}

#[test]
fn warn_large_zstd_window_1024_one_frame_does_not_warn() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.tar.zst");
    let mut eof = Vec::new();
    ratarmount_formats_tar::write_tar_eof(&mut eof).unwrap();
    let zst = ratarmount_compress::encode_zstd_frame(&eof, 3).unwrap();
    fs::write(&path, zst).unwrap();
    let map = scan_zstd_frames_path(&path).unwrap();
    assert_eq!(map.frames.len(), 1);
    assert_eq!(map.frames[0].uncompressed_size, 1024);
    assert!(!last_zstd_plain_needs_warn(map.frames[0].uncompressed_size));
}

#[test]
fn warn_large_zstd_window_last_frame_over_64mib_warns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.tar.zst");
    let plain = vec![0u8; (LAST_FRAME_WARN_BYTES as usize) + 1];
    let zst = ratarmount_compress::encode_zstd_frame(&plain, 3).unwrap();
    fs::write(&path, zst).unwrap();
    let map = scan_zstd_frames_path(&path).unwrap();
    assert_eq!(map.frames.len(), 1);
    assert!(map.frames[0].uncompressed_size > LAST_FRAME_WARN_BYTES);
    assert!(last_zstd_plain_needs_warn(map.frames[0].uncompressed_size));
}

fn write_sample_zip(path: &Path, members: &[(&str, &[u8], CompressionMethod)]) {
    let file = File::create(path).unwrap();
    let mut zw = ZipWriter::new(file);
    for (name, data, method) in members {
        let opts = SimpleFileOptions::default().compression_method(*method);
        zw.start_file(*name, opts).unwrap();
        zw.write_all(data).unwrap();
    }
    zw.finish().unwrap();
}

fn assert_committed_baseline(
    overlay: &Path,
    archive: &Path,
    info: &crate::overlay_meta::OverlayCreateInfo,
) {
    let meta = crate::OverlayMeta::read(overlay).unwrap().unwrap();
    let stamp = ratarmount_index::ArchiveDigestStamp::read(archive).unwrap();
    let digest = format!(
        "sha256:{}",
        ratarmount_index::sha256_hex(&fs::read(archive).unwrap())
    );
    assert_eq!(meta.base_digest(), Some(digest.as_str()));
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    assert_eq!(meta.get("base_size"), Some(stamp.size.to_string().as_str()));
    assert_eq!(
        meta.get("base_mtime_ns"),
        Some(stamp.mtime_ns.to_string().as_str())
    );
    assert_eq!(
        meta.stack_digest(),
        Some(crate::overlay_meta::stack_digest(&digest, &[]).as_str())
    );
    assert!(meta.get("base_committed_at").is_some());
    assert!(meta.get("base_mismatch_forced_at").is_none());
    let conn = Connection::open(info.index_path.as_ref().unwrap()).unwrap();
    let cached: (String, String, String, String) = conn
        .query_row(
            "SELECT size, mtime_ns, inode, sha256 FROM overlay_base_digests",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        cached,
        (
            stamp.size.to_string(),
            stamp.mtime_ns.to_string(),
            stamp.inode.to_string(),
            digest[7..].to_owned()
        )
    );
    // Use the same default creation context as mount startup, with no override.
    drop(WriteOverlay::new_with_create_info_for_tests(Arc::new(NullBase), overlay, info).unwrap());
    fs::OpenOptions::new()
        .append(true)
        .open(archive)
        .unwrap()
        .write_all(b"external change")
        .unwrap();
    let error = WriteOverlay::new_with_create_info_for_tests(Arc::new(NullBase), overlay, info)
        .err()
        .expect("external archive change must be refused");
    assert!(error.to_string().contains("base mismatch"), "{error}");
}

fn commit_baseline_case(
    extension: &str,
    mode: CommitMode,
    live: bool,
    atomic: bool,
    manifest: bool,
) {
    if extension == "tar" && mode == CommitMode::Copy {
        if let Err(error) = ensure_gnu_tar() {
            eprintln!("skip: {error}");
            return;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join(format!("base.{extension}"));
    let members = [ustar_file("old", b"original")];
    match extension {
        "zip" => write_sample_zip(&archive, &[("old", b"original", CompressionMethod::Stored)]),
        "tar.zst" => fs::write(&archive, concat_zstd_frames(&[&pack_tar(&members)], true)).unwrap(),
        _ => fs::write(&archive, pack_tar(&members)).unwrap(),
    }
    let overlay = dir.path().join("overlay");
    let index = dir.path().join("custom-index.sqlite");
    Connection::open(&index)
        .unwrap()
        .execute_batch("CREATE TABLE files (name TEXT);")
        .unwrap();
    let info = crate::overlay_meta::OverlayCreateInfo {
        base_url: archive.to_str().unwrap().to_owned(),
        index_path: Some(index),
        ..Default::default()
    };
    let base = match extension {
        "tar" => open_uncompressed_tar_base(&archive, false),
        "tar.zst" => open_tar_zst_base(&archive, false),
        _ => Arc::new(NullBase) as Arc<dyn MountSource>,
    };
    let mut ov = WriteOverlay::new_with_create_info_for_tests(base, &overlay, &info).unwrap();
    ov.set_commit_mode(mode);
    fs::write(overlay.join("new"), b"new payload").unwrap();
    if live {
        assert!(ov
            .commit_live_idle(&archive, Duration::ZERO, |path| {
                Ok(if extension == "tar" {
                    open_uncompressed_tar_base(path, false)
                } else {
                    open_tar_zst_base(path, false)
                })
            })
            .unwrap());
        assert!(!overlay.join("new").exists());
    } else if atomic {
        assert!(ov.commit_atomic(&archive).unwrap());
    } else {
        drop(ov);
        let opts = CommitOverlayOptions {
            mode,
            manifest_hashes: manifest.then(|| "all".to_owned()),
            ..yes_commit_opts()
        };
        assert!(commit_overlay(&overlay, &archive, &opts).unwrap());
        assert_committed_baseline(&overlay, &archive, &info);
        return;
    }
    drop(ov);
    assert_committed_baseline(&overlay, &archive, &info);
}

/// Regression: offline TAR commits left the overlay bound to the old archive bytes.
#[test]
fn regression_commit_overlay_tar_refreshes_baseline() {
    for mode in [CommitMode::Copy, CommitMode::Append] {
        commit_baseline_case("tar", mode, false, false, false);
    }
    commit_baseline_case("tar", CommitMode::Copy, false, false, true);
}

/// Regression: zstd splice and append commits caused a mismatch on remount.
#[test]
fn regression_commit_overlay_tar_zst_refreshes_baseline() {
    for mode in [CommitMode::Copy, CommitMode::Append] {
        commit_baseline_case("tar.zst", mode, false, false, false);
    }
}

/// Regression: rebuilding ZIP left its recorded digest and size stale.
#[test]
fn regression_commit_overlay_zip_refreshes_baseline() {
    commit_baseline_case("zip", CommitMode::Copy, false, false, false);
}

/// Regression: interval and on-exit commits required force-base-mismatch afterward.
#[test]
fn regression_live_commit_refreshes_baseline() {
    for extension in ["tar", "tar.zst"] {
        for mode in [CommitMode::Copy, CommitMode::Append] {
            commit_baseline_case(extension, mode, true, false, false);
            commit_baseline_case(extension, mode, false, true, false);
        }
    }
}

#[cfg(unix)]
mod archive_metadata_regressions {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::rc::Rc;

    struct FaultGuard;

    impl Drop for FaultGuard {
        fn drop(&mut self) {
            ratarmount_compress::commit_journal::fault::clear();
        }
    }

    fn assert_replaced(archive: &Path, before: &fs::Metadata) {
        let after = File::open(archive).unwrap().metadata().unwrap();
        assert_ne!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.mode() & 0o777, before.mode() & 0o777);
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
    }

    fn set_mode(archive: &Path, mode: u32) -> fs::Metadata {
        fs::set_permissions(archive, fs::Permissions::from_mode(mode)).unwrap();
        File::open(archive).unwrap().metadata().unwrap()
    }

    fn ordinary_copy(route: &str) {
        for extension in ["tar", "tar.zst"] {
            if extension == "tar" {
                if let Err(error) = ensure_gnu_tar() {
                    eprintln!("skip: {error}");
                    continue;
                }
            }
            for mode in [0o644, 0o640] {
                let dir = tempfile::tempdir().unwrap();
                let archive = dir.path().join(format!("base.{extension}"));
                let plain = pack_tar(&[ustar_file("old", b"original")]);
                fs::write(
                    &archive,
                    if extension == "tar" {
                        plain
                    } else {
                        concat_zstd_frames(&[&plain], true)
                    },
                )
                .unwrap();
                let before = set_mode(&archive, mode);
                let base = if extension == "tar" {
                    open_uncompressed_tar_base(&archive, false)
                } else {
                    open_tar_zst_base(&archive, false)
                };
                let overlay = dir.path().join("overlay");
                let mut ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
                ov.set_commit_mode(CommitMode::Copy);
                fs::write(overlay.join("new"), b"new payload").unwrap();
                match route {
                    "offline" => {
                        drop(ov);
                        assert!(commit_overlay(
                            &overlay,
                            &archive,
                            &CommitOverlayOptions {
                                mode: CommitMode::Copy,
                                ..yes_commit_opts()
                            },
                        )
                        .unwrap());
                    }
                    "idle" => assert!(ov
                        .commit_live_idle(&archive, Duration::ZERO, |path| {
                            Ok(if extension == "tar" {
                                open_uncompressed_tar_base(path, false)
                            } else {
                                open_tar_zst_base(path, false)
                            })
                        })
                        .unwrap()),
                    "atomic" => assert!(ov.commit_atomic(&archive).unwrap()),
                    _ => unreachable!(),
                }
                let reopened = if extension == "tar" {
                    open_uncompressed_tar_base(&archive, false)
                } else {
                    open_tar_zst_base(&archive, false)
                };
                assert_eq!(read_member(reopened.as_ref(), "/new"), b"new payload");
                assert_eq!(read_member(reopened.as_ref(), "/old"), b"original");
                assert_replaced(&archive, &before);
            }
        }
    }

    /// Regression: offline copy commits replaced 0644/0640 TAR and zstd archives with 0600 files.
    #[test]
    fn regression_235_archive_offline_copy_modes() {
        ordinary_copy("offline");
    }

    /// Regression: live idle copy publication discarded the TAR/zstd archive's mode.
    #[test]
    fn regression_235_archive_live_idle_copy_modes() {
        ordinary_copy("idle");
    }

    /// Regression: atomic copy publication discarded the TAR/zstd archive's mode.
    #[test]
    fn regression_235_archive_atomic_copy_modes() {
        ordinary_copy("atomic");
    }

    /// Regression: provenance direct TAR copy publication discarded the archive's mode.
    #[test]
    fn regression_235_archive_provenance_copy_modes() {
        for mode in [0o644, 0o640] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("base.tar");
            provenance_fixture(&archive, false);
            let before = set_mode(&archive, mode);
            let overlay = dir.path().join("overlay");
            let ov = WriteOverlay::new_for_tests(
                Arc::new(provenance_base(&archive, "utf-8").unwrap()),
                &overlay,
            )
            .unwrap();
            fs::write(overlay.join("new"), b"new payload").unwrap();
            drop(ov);
            assert!(commit_overlay(
                &overlay,
                &archive,
                &CommitOverlayOptions {
                    mode: CommitMode::Copy,
                    manifest_hashes: Some("new".into()),
                    ..yes_commit_opts()
                },
            )
            .unwrap());
            let reopened = provenance_base(&archive, "utf-8").unwrap();
            assert_eq!(read_member(&reopened, "/new"), b"new payload");
            assert_eq!(read_member(&reopened, "/trace"), b"training payload");
            assert_replaced(&archive, &before);
        }
    }

    /// Regression: provenance Auto's ENOSPC rollback/copy fallback published a 0600 TAR.
    #[test]
    fn regression_235_archive_provenance_auto_rollback_modes() {
        for mode in [0o644, 0o640] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("base.tar");
            fs::write(&archive, pack_tar(&[ustar_file("old", b"original")])).unwrap();
            let before = set_mode(&archive, mode);
            assert_eq!(before.nlink(), 1);
            let overlay = dir.path().join("overlay");
            let ov =
                WriteOverlay::new_for_tests(open_uncompressed_tar_base(&archive, false), &overlay)
                    .unwrap();
            fs::write(overlay.join("new"), b"new payload").unwrap();
            drop(ov);
            let injected = Rc::new(Cell::new(false));
            let rolled_back = Rc::new(Cell::new(false));
            let (fault_injected, fault_rolled_back) = (injected.clone(), rolled_back.clone());
            ratarmount_compress::commit_journal::fault::install(move |step| {
                if step == "archive write" && !fault_injected.replace(true) {
                    return Err(io::Error::from_raw_os_error(libc::ENOSPC));
                }
                if step == "rollback unlink" {
                    fault_rolled_back.set(true);
                }
                Ok(())
            });
            let _fault = FaultGuard;
            assert!(commit_overlay(
                &overlay,
                &archive,
                &CommitOverlayOptions {
                    mode: CommitMode::Auto,
                    manifest_hashes: Some("new".into()),
                    ..yes_commit_opts()
                },
            )
            .unwrap());
            assert!(
                injected.get(),
                "the adds-only Auto route must attempt append"
            );
            assert!(
                rolled_back.get(),
                "the failed append must roll back before copying"
            );
            let reopened = provenance_base(&archive, "utf-8").unwrap();
            assert_eq!(read_member(&reopened, "/new"), b"new payload");
            assert_eq!(read_member(&reopened, "/old"), b"original");
            assert_replaced(&archive, &before);
        }
    }

    /// Regression: ZIP rebuilding replaced the archive's 0644/0640 mode with 0600.
    #[test]
    fn regression_235_archive_zip_copy_modes() {
        for mode in [0o644, 0o640] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("base.zip");
            write_sample_zip(
                &archive,
                &[
                    ("old", b"original", CompressionMethod::Stored),
                    ("nested/keep", b"keep", CompressionMethod::Deflated),
                ],
            );
            let before = set_mode(&archive, mode);
            let overlay = dir.path().join("overlay");
            let ov = WriteOverlay::new_for_tests(Arc::new(NullBase), &overlay).unwrap();
            fs::write(overlay.join("new"), b"new payload").unwrap();
            drop(ov);
            assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).unwrap());
            let mut reopened = ZipArchive::new(File::open(&archive).unwrap()).unwrap();
            for (path, expected) in [
                ("new", &b"new payload"[..]),
                ("old", &b"original"[..]),
                ("nested/keep", &b"keep"[..]),
            ] {
                let mut bytes = Vec::new();
                reopened
                    .by_name(path)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes, expected);
            }
            assert_replaced(&archive, &before);
        }
    }

    /// Regression: gzip/bzip2/xz recompression published private temporary permissions.
    #[test]
    fn regression_235_archive_recompress_modes() {
        for format in [
            CompressionFormat::Gzip,
            CompressionFormat::Bzip2,
            CompressionFormat::Xz,
        ] {
            for mode in [0o644, 0o640] {
                let dir = tempfile::tempdir().unwrap();
                let archive = dir.path().join("base.compressed");
                let plain = dir.path().join("new.tar");
                let expected = pack_tar(&[ustar_file("new", b"new payload")]);
                fs::write(&plain, &expected).unwrap();
                fs::write(&archive, b"old archive bytes").unwrap();
                let before = set_mode(&archive, mode);
                recompress_replace(
                    &plain,
                    &archive,
                    format,
                    &before,
                    &crate::journal_recovery::Rows::None,
                    &mut || Ok(()),
                )
                .unwrap();
                let file = File::open(&archive).unwrap();
                let mut decoder: Box<dyn Read> = match format {
                    CompressionFormat::Gzip => Box::new(flate2::read::MultiGzDecoder::new(file)),
                    CompressionFormat::Bzip2 => Box::new(bzip2::read::MultiBzDecoder::new(file)),
                    CompressionFormat::Xz => Box::new(xz2::read::XzDecoder::new(file)),
                    _ => unreachable!(),
                };
                let mut decoded = Vec::new();
                decoder.read_to_end(&mut decoded).unwrap();
                assert_eq!(decoded, expected);
                assert_replaced(&archive, &before);
            }
        }
    }

    fn oversized_commit(fail_mode: bool) {
        for mode in [0o644, 0o640] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("base.tar.zst");
            let plain = pack_tar(&[ustar_file("old", b"original")]);
            fs::write(&archive, concat_zstd_frames(&[&plain], true)).unwrap();
            let before = set_mode(&archive, mode);
            assert_eq!(before.nlink(), 1);
            assert!(scan_zstd_frames_path(&archive)
                .unwrap()
                .seek_table
                .is_some());
            let old_bytes = fs::read(&archive).unwrap();
            let overlay = dir.path().join("overlay");
            let ov =
                WriteOverlay::new_for_tests(open_tar_zst_base(&archive, false), &overlay).unwrap();
            fs::write(overlay.join("new"), b"new payload").unwrap();
            drop(ov);
            let mode_attempted = Rc::new(Cell::new(false));
            let copy_opens = Rc::new(Cell::new(0));
            let (fault_mode_attempted, fault_copy_opens) =
                (mode_attempted.clone(), copy_opens.clone());
            ratarmount_compress::commit_journal::fault::install(move |step| {
                if step == "copy source open" {
                    fault_copy_opens.set(fault_copy_opens.get() + 1);
                }
                if step == "archive metadata mode"
                    && !fault_mode_attempted.replace(true)
                    && fail_mode
                {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                Ok(())
            });
            let _fault = FaultGuard;
            let _size_limit = ratarmount_compress::zstd_splice_seek_table_limit_for_test(0);
            let result = commit_overlay(
                &overlay,
                &archive,
                &CommitOverlayOptions {
                    mode: CommitMode::Auto,
                    ..yes_commit_opts()
                },
            );
            assert!(
                mode_attempted.get(),
                "the oversized publisher must restore mode"
            );
            assert_eq!(copy_opens.get(), 0, "Auto must not enter a copy fallback");
            if fail_mode {
                assert!(
                    result.is_err(),
                    "fchmod failure must abort commit: {result:?}"
                );
                let after = File::open(&archive).unwrap().metadata().unwrap();
                assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
                assert_eq!(after.mode() & 0o777, mode);
                assert_eq!(fs::read(&archive).unwrap(), old_bytes);
                assert!(overlay.join("new").exists());
            } else {
                assert!(result.unwrap());
                assert!(
                    scan_zstd_frames_path(&archive)
                        .unwrap()
                        .seek_table
                        .is_none(),
                    "forced overflow must drop the footer"
                );
                let reopened = open_tar_zst_base(&archive, false);
                assert_eq!(read_member(reopened.as_ref(), "/new"), b"new payload");
                assert_eq!(read_member(reopened.as_ref(), "/old"), b"original");
                assert_replaced(&archive, &before);
            }
        }
    }

    /// Regression: an oversized zstd append copy discarded the original archive's metadata.
    #[test]
    fn regression_235_archive_oversized_append_copy_modes() {
        oversized_commit(false);
    }

    /// Regression: oversized zstd fchmod errors must abort rather than permit Auto copy fallback.
    #[test]
    fn regression_235_archive_oversized_append_mode_failure_no_fallback() {
        oversized_commit(true);
    }
}

/// Re-run test `name` in a child whose cwd is `cwd` and whose `TMPDIR` does
/// not exist, so any scratch allocation in `$TMPDIR` fails (or, on a real
/// host, would land on another filesystem). `vars` carry absolute inputs.
#[cfg(unix)]
fn run_bare_name_child(name: &str, cwd: &Path, vars: &[(&str, &Path)]) {
    let mut cmd = StdCommand::new(std::env::current_exe().unwrap());
    cmd.env("RATARMOUNT_BARE_NAME_CHILD", "1")
        .env("TMPDIR", cwd.join("does-not-exist"))
        .current_dir(cwd)
        .args([name, "--exact", "--nocapture"]);
    for (k, v) in vars {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "child stdout: {}\nchild stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("running 1 test"),
        "child must have run the test"
    );
}

#[cfg(unix)]
fn in_bare_name_child() -> bool {
    std::env::var_os("RATARMOUNT_BARE_NAME_CHILD").is_some()
}

/// Regression: #134 `recompress_replace` on a bare relative `dest` staged
/// its temp file in `$TMPDIR`; `persist` then failed with EXDEV when
/// `$TMPDIR` was on another filesystem.
#[cfg(unix)]
#[test]
fn regression_134_recompress_replace_bare_name_stages_beside_dest() {
    if in_bare_name_child() {
        let plain = PathBuf::from(std::env::var_os("RM134_PLAIN").unwrap());
        for (dest, fmt) in [
            ("t.tar.gz", CompressionFormat::Gzip),
            ("t.tar.bz2", CompressionFormat::Bzip2),
        ] {
            // The replace is gated on the stamp of an existing `dest`.
            fs::write(dest, b"old").unwrap();
            let source = fs::metadata(dest).unwrap();
            recompress_replace(
                &plain,
                Path::new(dest),
                fmt,
                &source,
                &crate::journal_recovery::Rows::None,
                &mut || Ok(()),
            )
            .unwrap_or_else(|e| panic!("{dest}: {e}"));
            assert!(fs::metadata(dest).unwrap().len() > 0);
        }
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.tar");
    fs::write(&plain, vec![0u8; 10240]).unwrap();
    run_bare_name_child(
        "write_overlay::tests::regression_134_recompress_replace_bare_name_stages_beside_dest",
        dir.path(),
        &[("RM134_PLAIN", &plain)],
    );
    assert!(dir.path().join("t.tar.gz").is_file());
    assert!(dir.path().join("t.tar.bz2").is_file());
}

/// Regression: #134 ZIP `--commit-overlay` of a bare relative `t.zip`
/// staged the rebuilt ZIP in `$TMPDIR` (EXDEV on `persist`).
#[cfg(unix)]
#[test]
fn regression_134_commit_overlay_zip_bare_name_stages_beside_dest() {
    if in_bare_name_child() {
        let overlay = PathBuf::from(std::env::var_os("RM134_OVERLAY").unwrap());
        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
            ..Default::default()
        };
        commit_overlay(&overlay, Path::new("t.zip"), &opts).expect("commit_overlay bare zip");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("t.zip");
    write_sample_zip(
        &zip_path,
        &[("old.txt", b"old zip\n", CompressionMethod::Stored)],
    );
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    {
        let base = Arc::new(NullBase) as Arc<dyn MountSource>;
        let _ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        fs::write(overlay.join("new.txt"), b"hello bare zip\n").unwrap();
    }
    run_bare_name_child(
        "write_overlay::tests::regression_134_commit_overlay_zip_bare_name_stages_beside_dest",
        dir.path(),
        &[("RM134_OVERLAY", &overlay)],
    );
    let mut archive = ZipArchive::new(File::open(&zip_path).unwrap()).unwrap();
    let mut body = String::new();
    archive
        .by_name("new.txt")
        .unwrap()
        .read_to_string(&mut body)
        .unwrap();
    assert_eq!(body, "hello bare zip\n");
}

/// Regression: ZIP --commit-overlay add file (full rebuild) → reopen list/read.
/// Symptom: commit-overlay rejected non-TAR archives (upstream #154).
#[test]
fn commit_overlay_zip_add_file() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("a.zip");
    write_sample_zip(
        &zip_path,
        &[
            ("old.txt", b"old zip\n", CompressionMethod::Stored),
            ("nested/keep.txt", b"keep me\n", CompressionMethod::Deflated),
        ],
    );

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let base = Arc::new(NullBase) as Arc<dyn MountSource>;
    {
        let _ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        fs::write(overlay.join("new.txt"), b"hello zip commit\n").unwrap();
    }

    let opts = CommitOverlayOptions {
        yes: true,
        debug: 0,
        ..Default::default()
    };
    commit_overlay(&overlay, &zip_path, &opts).expect("commit_overlay zip");

    // Still a ZIP after commit
    let magic = fs::read(&zip_path).unwrap();
    assert!(
        magic.len() >= 4 && &magic[..2] == b"PK",
        "archive should remain ZIP after commit"
    );

    let file = File::open(&zip_path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();
    let names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.name_for_index(i).map(|s| s.to_string()))
        .collect();
    assert!(
        names
            .iter()
            .any(|n| normalize_archive_rel_path(n) == "old.txt"),
        "zip listing: {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| normalize_archive_rel_path(n) == "nested/keep.txt"),
        "zip listing: {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| normalize_archive_rel_path(n) == "new.txt"),
        "zip listing: {names:?}"
    );

    // Read overlay-added content
    {
        let mut f = archive.by_name("new.txt").unwrap();
        let mut body = String::new();
        f.read_to_string(&mut body).unwrap();
        assert_eq!(body, "hello zip commit\n");
    }
    // Unchanged stored member still readable
    {
        let mut f = archive.by_name("old.txt").unwrap();
        let mut body = String::new();
        f.read_to_string(&mut body).unwrap();
        assert_eq!(body, "old zip\n");
    }
    // Unchanged deflated member still readable
    {
        let mut f = archive.by_name("nested/keep.txt").unwrap();
        let mut body = String::new();
        f.read_to_string(&mut body).unwrap();
        assert_eq!(body, "keep me\n");
    }
}

/// Regression: ZIP commit replaces existing member and honors DB delete.
#[test]
fn commit_overlay_zip_replace_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("b.zip");
    write_sample_zip(
        &zip_path,
        &[
            ("keep.txt", b"keep\n", CompressionMethod::Stored),
            ("gone.txt", b"remove me\n", CompressionMethod::Stored),
            ("mut.txt", b"old mut\n", CompressionMethod::Deflated),
        ],
    );

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let base = Arc::new(NullBase) as Arc<dyn MountSource>;
    {
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        // Replace mut.txt via overlay file (also marks delete+append on commit walk)
        fs::write(overlay.join("mut.txt"), b"new mut\n").unwrap();
        // Delete gone.txt in overlay DB (base would have had it)
        // NullBase has no files; insert deleted row directly to simulate unlink of base path.
        {
            let db = ov.db.lock().expect("db");
            db.execute(
                r#"INSERT OR REPLACE INTO "files" (path,name,deleted) VALUES ('','gone.txt',1)"#,
                [],
            )
            .unwrap();
        }
        // Drop overlay so exclusive SQLite lock is released before commit.
        drop(ov);
    }

    let opts = CommitOverlayOptions {
        yes: true,
        debug: 0,
        ..Default::default()
    };
    commit_overlay(&overlay, &zip_path, &opts).expect("commit_overlay zip replace/delete");

    let file = File::open(&zip_path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();
    let names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.name_for_index(i).map(|s| s.to_string()))
        .collect();
    assert!(
        names
            .iter()
            .any(|n| normalize_archive_rel_path(n) == "keep.txt"),
        "{names:?}"
    );
    assert!(
        !names
            .iter()
            .any(|n| normalize_archive_rel_path(n) == "gone.txt"),
        "gone.txt should be deleted: {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| normalize_archive_rel_path(n) == "mut.txt"),
        "{names:?}"
    );
    let mut f = archive.by_name("mut.txt").unwrap();
    let mut body = String::new();
    f.read_to_string(&mut body).unwrap();
    assert_eq!(body, "new mut\n");
}

#[test]
fn is_zip_archive_detects_pk_magic() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("c.zip");
    write_sample_zip(&zip_path, &[("x", b"y", CompressionMethod::Stored)]);
    assert!(is_zip_archive(&zip_path).unwrap());

    let tarish = dir.path().join("not-a-zip.bin");
    fs::write(&tarish, b"ustar is not here but also not PK").unwrap();
    assert!(!is_zip_archive(&tarish).unwrap());
}

#[test]
fn commit_overlay_add_file() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("data");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("old.txt"), b"old\n").unwrap();
    let tar = dir.path().join("a.tar");
    let st = StdCommand::new("tar")
        .args(["-cf"])
        .arg(&tar)
        .arg("-C")
        .arg(&src)
        .arg("old.txt")
        .status()
        .unwrap();
    assert!(st.success());

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    // Create hidden DB so schema exists (optional for append-only)
    let base = Arc::new(NullBase) as Arc<dyn MountSource>;
    {
        let _ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        fs::write(overlay.join("new.txt"), b"hello commit\n").unwrap();
        // Drop overlay so exclusive SQLite lock is released before commit.
    }

    let opts = CommitOverlayOptions {
        yes: true,
        debug: 0,
        ..Default::default()
    };
    match commit_overlay(&overlay, &tar, &opts) {
        Ok(_) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        Err(e) => panic!("commit_overlay: {e}"),
    }

    let list = StdCommand::new("tar")
        .args(["-tf"])
        .arg(&tar)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&list.stdout);
    assert!(text.contains("new.txt"), "tar listing: {text}");
    assert!(text.contains("old.txt"), "tar listing: {text}");
}

#[test]
fn commit_overlay_add_file_tar_gz() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("data");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("old.txt"), b"old gz\n").unwrap();
    let tgz = dir.path().join("a.tar.gz");
    let st = StdCommand::new("tar")
        .args(["-czf"])
        .arg(&tgz)
        .arg("-C")
        .arg(&src)
        .arg("old.txt")
        .status()
        .unwrap();
    assert!(st.success());

    // Sanity: starts with gzip magic
    let magic = fs::read(&tgz).unwrap();
    assert!(magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b);

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let base = Arc::new(NullBase) as Arc<dyn MountSource>;
    {
        let _ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        fs::write(overlay.join("new.txt"), b"hello gzip commit\n").unwrap();
    }

    let opts = CommitOverlayOptions {
        yes: true,
        debug: 0,
        ..Default::default()
    };
    match commit_overlay(&overlay, &tgz, &opts) {
        Ok(_) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        Err(e) => panic!("commit_overlay tar.gz: {e}"),
    }

    // Still gzip-compressed after commit
    let magic = fs::read(&tgz).unwrap();
    assert!(
        magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b,
        "archive should remain gzip after commit"
    );

    // List via tar -tzf (or gunzip | tar if needed)
    let list = StdCommand::new("tar")
        .args(["-tzf"])
        .arg(&tgz)
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "tar -tzf failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let text = String::from_utf8_lossy(&list.stdout);
    assert!(text.contains("new.txt"), "tar.gz listing: {text}");
    assert!(text.contains("old.txt"), "tar.gz listing: {text}");

    // Extract new.txt and verify content
    let extract = dir.path().join("out");
    fs::create_dir_all(&extract).unwrap();
    let st = StdCommand::new("tar")
        .args(["-xzf"])
        .arg(&tgz)
        .arg("-C")
        .arg(&extract)
        .arg("new.txt")
        .status()
        .unwrap();
    assert!(st.success());
    let body = fs::read_to_string(extract.join("new.txt")).unwrap();
    assert_eq!(body, "hello gzip commit\n");
}

/// Regression: offline append must not bless a stale prefix index with fresh tarstats.
#[test]
fn commit_overlay_append_invalidates_stale_sidecar() {
    for zstd in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(if zstd { "a.tar.zst" } else { "a.tar" });
        append_fixture(&archive, zstd);
        let sidecar = append_index(&archive, zstd);
        if zstd {
            write_split_tar_zst(
                &archive,
                &[ustar_file("prefix", b"changed")],
                &[ustar_file("last", b"last")],
                true,
            );
        } else {
            fs::write(
                &archive,
                pack_tar(&[
                    ustar_file("prefix", b"changed"),
                    ustar_file("last", b"last"),
                ]),
            )
            .unwrap();
        }
        let root = dir.path().join("ov");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("new"), b"new contents").unwrap();
        assert!(commit_overlay(
            &root,
            &archive,
            &CommitOverlayOptions {
                mode: CommitMode::Append,
                ..yes_commit_opts()
            }
        )
        .unwrap());
        assert!(
            !sidecar.exists(),
            "stale index must be invalidated before patching"
        );
        let base = if zstd {
            open_tar_zst_base(&archive, false)
        } else {
            open_uncompressed_tar_base(&archive, false)
        };
        assert_eq!(read_member(base.as_ref(), "/prefix"), b"changed");
        assert_eq!(read_member(base.as_ref(), "/last"), b"last");
        assert_eq!(read_member(base.as_ref(), "/new"), b"new contents");
    }
}

/// Regression: successful append followed by reopen failure must refuse stale reads.
#[test]
fn live_commit_append_reopen_failure_refuses_base_reads() {
    for zstd in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(if zstd { "a.tar.zst" } else { "a.tar" });
        append_fixture(&archive, zstd);
        let base = if zstd {
            open_tar_zst_base(&archive, false)
        } else {
            open_uncompressed_tar_base(&archive, false)
        };
        let old = base.lookup("/last", 0).unwrap();
        let mut ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
        ov.set_commit_mode(CommitMode::Append);
        fs::write(ov.root().join("new"), b"new").unwrap();
        assert!(ov
            .commit_live(&archive, |_| Err(OverlayError::Msg("reopen failed".into())))
            .is_err());
        assert!(ov.interval_disabled());
        assert!(ov.content_generation() > 0);
        assert!(ov.open(&old, 0).is_err());
        assert!(ov.root().join("new").exists());
    }
}

/// Regression (R7-B3): a `--commit-manifest` (provenance) append whose
/// baseline restamp fails after the splice returned `Committed` without the
/// ordinary append branches' handling: the interval stayed on and the
/// mounted source kept serving the pre-splice frame map over the new bytes.
#[cfg(unix)]
#[test]
fn regression_provenance_append_committed_refuses_stale_frame_map() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar.zst");
    append_fixture(&archive, true);
    let base = open_tar_zst_base(&archive, false);
    let old = base.lookup("/last", 0).unwrap();
    let mut ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
    ov.set_commit_mode(CommitMode::Append);
    ov.set_manifest_hashes(Some("new".into()));
    fs::write(ov.root().join("new"), b"new").unwrap();
    // An open transaction on the mount's connection makes the restamp's
    // BEGIN IMMEDIATE fail after the splice.
    ov.db.lock().unwrap().execute_batch("BEGIN").unwrap();
    let err = ov
        .commit_live(&archive, |_| panic!("a committed splice must not reopen"))
        .unwrap_err();
    assert!(matches!(err, OverlayError::Committed(_)), "{err}");
    assert!(ov.interval_disabled(), "interval commits stay enabled");
    assert!(
        ov.open(&old, 0).is_err(),
        "stale pre-splice frame map still served"
    );
}

/// Regression: recovery of a failed append keeps the old live index readable.
#[cfg(unix)]
#[test]
fn live_commit_append_failure_recovers_before_next_tick() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar");
    let (_, last) = append_fixture(&archive, false);
    let base = open_uncompressed_tar_base(&archive, false);
    let ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
    let offset = fs::metadata(&archive).unwrap().len() - 1024;
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"partial new member").unwrap();
    assert!(
        ratarmount_compress::commit_journal::replace_suffix_with_hook(
            &archive,
            offset,
            &mut suffix,
            &mut |step| {
                if step == "archive write" {
                    Err(io::Error::from_raw_os_error(libc::ENOSPC))
                } else {
                    Ok(())
                }
            },
        )
        .is_err()
    );
    ov.recover_member_journal(&archive).unwrap();
    assert!(!ov.interval_disabled());
    assert_eq!(read_member(&ov, "/last"), last);
}

/// Regression: failed rollback must refuse base reads instead of serving torn bytes.
#[cfg(unix)]
#[test]
fn live_commit_append_recovery_failure_refuses_base_reads() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar");
    append_fixture(&archive, false);
    let base = open_uncompressed_tar_base(&archive, false);
    let old = base.lookup("/last", 0).unwrap();
    let ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"new").unwrap();
    assert!(
        ratarmount_compress::commit_journal::replace_suffix_with_hook(
            &archive,
            512,
            &mut suffix,
            &mut |step| {
                if step == "archive truncate" {
                    Err(io::Error::other("crash"))
                } else {
                    Ok(())
                }
            },
        )
        .is_err()
    );
    File::options()
        .append(true)
        .open(&archive)
        .unwrap()
        .write_all(b"unrelated bytes")
        .unwrap();
    assert!(ov
        .commit_live(&archive, |_| panic!("must refuse recovery"))
        .is_err());
    assert!(ov.interval_disabled());
    assert!(ov.open(&old, 0).is_err());
}

/// Regression: a touch during suffix staging must refuse and retry, in
/// `append` and in `auto` alike. R7-D1: `auto` used to copy the touched
/// file, a file the commit gate never judged; the archive changed since
/// the gate, so no copy runs and the next commit appends in place.
#[cfg(unix)]
#[test]
fn live_commit_append_stale_preparation_retries_without_a_copy() {
    use std::os::unix::fs::MetadataExt;
    for mode in [CommitMode::Append, CommitMode::Auto] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        append_fixture(&archive, false);
        let before = fs::metadata(&archive).unwrap().ino();
        let mut ov = WriteOverlay::new_for_tests(
            open_uncompressed_tar_base(&archive, false),
            dir.path().join("ov"),
        )
        .unwrap();
        ov.set_commit_mode(mode);
        fs::write(ov.root().join("new"), b"new").unwrap();
        APPEND_PREPARE_TOUCH.set(true);
        let result = ov.commit_live(&archive, |p| Ok(open_uncompressed_tar_base(p, false)));
        assert!(!ov.interval_disabled(), "{mode:?}");
        assert!(result.is_err(), "{mode:?}");
        assert_eq!(before, fs::metadata(&archive).unwrap().ino(), "{mode:?}");
        assert!(ov
            .commit_live(&archive, |p| Ok(open_uncompressed_tar_base(p, false)))
            .unwrap());
        assert_eq!(before, fs::metadata(&archive).unwrap().ino(), "{mode:?}");
        assert_eq!(read_member(&ov, "/new"), b"new");
    }
}

/// Regression: trailing garbage rejected during append preparation must not disable ticks.
#[test]
fn live_commit_append_checksum_error_keeps_interval_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar");
    append_fixture(&archive, false);
    let good = fs::read(&archive).unwrap();
    let mut ov = WriteOverlay::new_for_tests(
        open_uncompressed_tar_base(&archive, false),
        dir.path().join("ov"),
    )
    .unwrap();
    ov.set_commit_mode(CommitMode::Append);
    fs::write(ov.root().join("new"), b"new").unwrap();
    File::options()
        .append(true)
        .open(&archive)
        .unwrap()
        .write_all(&[0x37; 512])
        .unwrap();
    assert!(ov
        .commit_live(&archive, |_| panic!("invalid append must not reopen"))
        .is_err());
    assert!(!ov.interval_disabled());
    fs::write(&archive, good).unwrap();
    assert!(ov
        .commit_live(&archive, |p| Ok(open_uncompressed_tar_base(p, false)))
        .unwrap());
    assert_eq!(read_member(&ov, "/new"), b"new");
}

fn append_fixture(path: &Path, zstd: bool) -> (Vec<u8>, Vec<u8>) {
    let mut seed = 42u32;
    let prefix: Vec<_> = (0..2 * 1024 * 1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    let last = vec![0; 8192];
    if zstd {
        write_split_tar_zst(
            path,
            &[ustar_file("prefix", &prefix)],
            &[ustar_file("last", &last)],
            true,
        );
    } else {
        fs::write(
            path,
            pack_tar(&[ustar_file("prefix", &prefix), ustar_file("last", &last)]),
        )
        .unwrap();
    }
    (prefix, last)
}

fn append_index(path: &Path, zstd: bool) -> PathBuf {
    let sidecar = ratarmount_index::default_index_path(path);
    let opts = OpenOptions {
        write_index: true,
        index_minimum_file_count: 0,
        ..OpenOptions::default()
    };
    if zstd {
        SqliteIndexedTar::create_index_body(
            path,
            open_seekable_zstd(path).unwrap(),
            Some(&sidecar),
            &opts,
            "test",
        )
        .unwrap();
    } else {
        SqliteIndexedTar::create_index(path, path, Some(&sidecar), &opts, "test", &mut None)
            .unwrap();
    }
    sidecar
}

fn append_warm_open(path: &Path, zstd: bool, sidecar: &Path) -> Arc<dyn MountSource> {
    SqliteIndex::open_read_only(sidecar)
        .unwrap()
        .check_tarstats_matches_archive(path)
        .unwrap();
    if zstd {
        Arc::new(
            SqliteIndexedTar::open_with_existing_index_body(
                path,
                open_seekable_zstd(path).unwrap(),
                sidecar,
                OpenOptions::default(),
            )
            .unwrap(),
        )
    } else {
        Arc::new(
            SqliteIndexedTar::open_with_existing_index(
                path,
                path,
                sidecar,
                OpenOptions::default(),
                &mut None,
            )
            .unwrap(),
        )
    }
}

/// Regression: adds-only interval commits copied the entire archive and inode.
#[test]
fn live_commit_append_inode_space_sidecar_and_copy_content() {
    use std::os::unix::fs::MetadataExt;
    if let Err(e) = ensure_gnu_tar() {
        eprintln!("skip: {e}");
        return;
    }
    for zstd in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(if zstd { "a.tar.zst" } else { "a.tar" });
        let (prefix, last) = append_fixture(&archive, zstd);
        let copy = dir
            .path()
            .join(if zstd { "copy.tar.zst" } else { "copy.tar" });
        fs::copy(&archive, &copy).unwrap();
        let sidecar = append_index(&archive, zstd);
        let base = append_warm_open(&archive, zstd, &sidecar);
        let root = dir.path().join("overlay");
        let mut ov = overlay_with_base(base, &root);
        ov.set_commit_mode(CommitMode::Append);
        let added = vec![0x91; 150_000];
        fs::write(root.join("new"), &added).unwrap();
        set_mtime_age(&root.join("new"), Duration::from_secs(30));
        // The offline path needs its own folder: a mounted overlay holds
        // its deletion database exclusively.
        let copy_root = dir.path().join("copy-overlay");
        fs::create_dir(&copy_root).unwrap();
        fs::copy(root.join("new"), copy_root.join("new")).unwrap();
        assert!(commit_overlay(&copy_root, &copy, &yes_commit_opts()).unwrap());
        let before = fs::metadata(&archive).unwrap();
        assert!(ov
            .commit_live_idle(&archive, Duration::from_secs(1), |path| {
                patch_sidecar_if_present(
                    path,
                    &ov.last_patch_window().unwrap(),
                    &OpenOptions {
                        index_file_path: Some(sidecar.clone()),
                        ..OpenOptions::default()
                    },
                )?;
                Ok(append_warm_open(path, zstd, &sidecar))
            })
            .unwrap());
        let after = fs::metadata(&archive).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert!(
            after.blocks() * 512 <= before.blocks() * 512 + added.len() as u64 + 64 * 1024,
            "append allocated the prefix again"
        );
        let copied = if zstd {
            open_tar_zst_base(&copy, false)
        } else {
            open_uncompressed_tar_base(&copy, false)
        };
        let mut got_names: Vec<_> = ov
            .list_dirents("/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        let mut copy_names: Vec<_> = copied
            .list_dirents("/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        got_names.sort();
        copy_names.sort();
        assert_eq!(got_names, copy_names);
        for (name, expected) in [("/prefix", &prefix), ("/last", &last), ("/new", &added)] {
            assert_eq!(read_member(&ov, name), *expected);
            assert_eq!(read_member(copied.as_ref(), name), *expected);
        }
        assert!(!root.join("new").exists());
        assert!(!ratarmount_compress::commit_journal::journal_path(&archive).exists());
        fs::write(root.join("second"), b"second tick").unwrap();
        assert!(ov
            .commit_live(&archive, |path| {
                patch_sidecar_if_present(
                    path,
                    &ov.last_patch_window().unwrap(),
                    &OpenOptions {
                        index_file_path: Some(sidecar.clone()),
                        ..OpenOptions::default()
                    },
                )?;
                Ok(append_warm_open(path, zstd, &sidecar))
            })
            .unwrap());
        assert_eq!(read_member(&ov, "/second"), b"second tick");
        assert_eq!(read_member(&ov, "/new"), added);
    }
}

/// Regression: uncompressed append must work without GNU tar and keep zero-tail bytes.
#[test]
fn commit_overlay_append_uncompressed_zero_tail_without_tools() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar");
    let old = vec![0; 8192];
    fs::write(&archive, pack_tar(&[ustar_file("old", &old)])).unwrap();
    let sidecar = append_index(&archive, false);
    let before = fs::metadata(&archive).unwrap().ino();
    let root = dir.path().join("ov");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("new"), b"new bytes").unwrap();
    assert!(commit_overlay(
        &root,
        &archive,
        &CommitOverlayOptions {
            mode: CommitMode::Append,
            ..yes_commit_opts()
        }
    )
    .unwrap());
    assert_eq!(before, fs::metadata(&archive).unwrap().ino());
    let base = append_warm_open(&archive, false, &sidecar);
    assert_eq!(read_member(base.as_ref(), "/old"), old);
    assert_eq!(read_member(base.as_ref(), "/new"), b"new bytes");
}

/// Regression: auto must not mutate another hard link, or append replacements.
#[test]
fn commit_overlay_append_auto_hardlink_and_replacement_fallback() {
    use std::os::unix::fs::MetadataExt;
    for hardlink in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar.zst");
        append_fixture(&archive, true);
        let old = fs::read(&archive).unwrap();
        let alias = dir.path().join("alias.tar.zst");
        if hardlink {
            fs::hard_link(&archive, &alias).unwrap();
        }
        let root = dir.path().join("ov");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join(if hardlink { "new" } else { "last" }),
            b"new bytes",
        )
        .unwrap();
        let before = fs::metadata(&archive).unwrap().ino();
        assert!(commit_overlay(
            &root,
            &archive,
            &CommitOverlayOptions {
                mode: CommitMode::Auto,
                ..yes_commit_opts()
            }
        )
        .unwrap());
        assert_ne!(before, fs::metadata(&archive).unwrap().ino());
        if hardlink {
            assert_eq!(fs::read(alias).unwrap(), old);
        }
        let base = open_tar_zst_base(&archive, false);
        assert_eq!(
            read_member(base.as_ref(), if hardlink { "/new" } else { "/last" }),
            b"new bytes"
        );
    }
}

/// Regression: auto should append eligible seekable files, but never a table-less zstd.
#[test]
fn commit_overlay_append_auto_requires_seek_table() {
    use std::os::unix::fs::MetadataExt;
    for seek_table in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar.zst");
        write_split_tar_zst(
            &archive,
            &[ustar_file("prefix", b"prefix")],
            &[ustar_file("last", b"last")],
            seek_table,
        );
        let root = dir.path().join("ov");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("new"), b"new bytes").unwrap();
        let before = fs::metadata(&archive).unwrap().ino();
        assert!(commit_overlay(
            &root,
            &archive,
            &CommitOverlayOptions {
                mode: CommitMode::Auto,
                ..yes_commit_opts()
            }
        )
        .unwrap());
        assert_eq!(before == fs::metadata(&archive).unwrap().ino(), seek_table);
        assert_eq!(
            read_member(open_tar_zst_base(&archive, false).as_ref(), "/new"),
            b"new bytes"
        );
    }
}

/// Regression: the first append to an empty TAR truncates at offset 0; recovery
/// must still open that zero-length archive, restore its EOF blocks and clear
/// the journal before the pending overlay can be committed again.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_240_empty_tar_offset_zero_crash_recovers() {
    use ratarmount_compress::commit_journal::{fault, journal_path, recover};

    for empty_len in [1024, 10240] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("empty.tar");
        let original = vec![0; empty_len];
        fs::write(&archive, &original).unwrap();
        let root = dir.path().join("ov");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("first"), b"first committed member").unwrap();
        let options = CommitOverlayOptions {
            mode: CommitMode::Append,
            ..yes_commit_opts()
        };
        let truncated = Arc::new(AtomicBool::new(false));
        let reached = truncated.clone();
        let target = archive.clone();
        fault::install(move |step| match step {
            "archive truncate" => {
                assert_eq!(
                    fs::metadata(&target).unwrap().len(),
                    0,
                    "the first empty-TAR commit must rewrite from offset 0"
                );
                reached.store(true, Ordering::SeqCst);
                Err(io::Error::other("crash after offset-0 truncation"))
            }
            // Preserve the on-disk crash state instead of rolling back in
            // the committing process, so recovery must reopen the empty file.
            "before cleanup" => Err(io::Error::other("process stopped before cleanup")),
            _ => Ok(()),
        });
        let crashed = commit_overlay(&root, &archive, &options);
        fault::clear();
        assert!(crashed.is_err(), "{crashed:?}");
        assert!(truncated.load(Ordering::SeqCst));
        assert_eq!(fs::metadata(&archive).unwrap().len(), 0);
        assert!(journal_path(&archive).is_file());

        assert!(recover(&archive).unwrap());
        assert_eq!(fs::read(&archive).unwrap(), original);
        assert!(!journal_path(&archive).exists());
        assert!(
            !recover(&archive).unwrap(),
            "recovery must clear the locator"
        );
        assert!(root.join("first").exists());
        assert!(commit_overlay(&root, &archive, &options).unwrap());
        assert_eq!(
            read_member(
                open_uncompressed_tar_base(&archive, false).as_ref(),
                "/first"
            ),
            b"first committed member"
        );
    }
}

/// Regression: crash during append must recover full contents and matching sidecar.
#[test]
fn commit_overlay_append_crash_listing_hashes_and_sidecar() {
    use ratarmount_compress::commit_journal::{recover, replace_suffix_with_hook};
    for zstd in [false, true] {
        for stop in 1..=19 {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join(if zstd { "a.tar.zst" } else { "a.tar" });
            let (prefix, last) = append_fixture(&archive, zstd);
            let old = fs::read(&archive).unwrap();
            let sidecar = append_index(&archive, zstd);
            let mut tail = tempfile::tempfile().unwrap();
            let added = vec![0x93; 150_000];
            let (offset, window) = if zstd {
                let map = scan_zstd_frames_path(&archive).unwrap();
                let from = find_last_n_tar_window(&archive, &map, "test").unwrap().0;
                ratarmount_compress::write_zstd_splice_suffix(
                    &mut File::open(&archive).unwrap(),
                    &map,
                    from,
                    |mut input, start, mut out| {
                        rewrite_tar_suffix(
                            &mut input,
                            start,
                            &RewriteTarSuffix {
                                deleted_paths: &HashSet::new(),
                                append: &[ustar_file("new", &added)],
                                encoding: "utf-8",
                            },
                            &mut out,
                        )
                        .map(|_| ())
                    },
                    &mut tail,
                )
                .unwrap();
                (
                    map.frames[from].compressed_offset,
                    IndexPatchWindow {
                        window_start: map.frames[from].uncompressed_offset,
                        from_frame: Some(from),
                        offsets_shifted: false,
                    },
                )
            } else {
                ratarmount_formats_tar::write_ustar_members(
                    &mut tail,
                    &[ustar_file("new", &added)],
                )
                .unwrap();
                ratarmount_formats_tar::write_tar_eof(&mut tail).unwrap();
                let offset = old.len() as u64 - 1024;
                (
                    offset,
                    IndexPatchWindow {
                        window_start: offset,
                        from_frame: None,
                        offsets_shifted: false,
                    },
                )
            };
            tail.rewind().unwrap();
            let mut expected = old[..offset as usize].to_vec();
            tail.read_to_end(&mut expected).unwrap();
            let mut step = 0;
            let _ = replace_suffix_with_hook(&archive, offset, &mut tail, &mut |_| {
                step += 1;
                if step == stop {
                    Err(io::Error::other("injected crash"))
                } else {
                    Ok(())
                }
            });
            recover(&archive).unwrap();
            let actual = fs::read(&archive).unwrap();
            assert!(
                actual == old || actual == expected,
                "third state: zstd={zstd} step={stop}"
            );
            let committed = actual == expected;
            if committed {
                patch_sidecar_if_present(
                    &archive,
                    &window,
                    &OpenOptions {
                        index_file_path: Some(sidecar.clone()),
                        ..OpenOptions::default()
                    },
                )
                .unwrap();
            }
            let warm = append_warm_open(&archive, zstd, &sidecar);
            let full = if zstd {
                open_tar_zst_base(&archive, false)
            } else {
                open_uncompressed_tar_base(&archive, false)
            };
            let names: HashSet<_> = full
                .list_dirents("/")
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
            assert_eq!(
                names,
                if committed {
                    HashSet::from(["prefix".into(), "last".into(), "new".into()])
                } else {
                    HashSet::from(["prefix".into(), "last".into()])
                }
            );
            assert_eq!(warm.lookup("/new", 0).is_some(), committed);
            for (name, bytes) in [("/prefix", &prefix), ("/last", &last), ("/new", &added)] {
                if name == "/new" && !committed {
                    continue;
                }
                let hash = |data: &[u8]| {
                    ratarmount_index::sha256_hex_stream(&mut std::io::Cursor::new(data)).unwrap()
                };
                assert_eq!(hash(&read_member(warm.as_ref(), name)), hash(bytes));
                assert_eq!(hash(&read_member(full.as_ref(), name)), hash(bytes));
            }
        }
    }
}

fn yes_commit_opts() -> CommitOverlayOptions {
    CommitOverlayOptions {
        yes: true,
        debug: 0,
        ..Default::default()
    }
}

/// Soft-skip GNU tar commit tests when the host tar is missing/wrong, or when
/// `--delete --ignore-zeros` hits the known Debian 1.35 lseek EOVERFLOW bug
/// (stderr/`Err` carry `lseek` / `Value too large for defined data type`).
fn soft_skip_gnu_tar_commit(err: &impl std::fmt::Display) -> bool {
    let s = err.to_string();
    s.contains("GNU tar")
        || s.contains("lseek")
        || s.contains("Value too large for defined data type")
}

fn sibling_index_sqlite_paths(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".index.sqlite"))
        })
        .collect();
    out.sort();
    out
}

fn padded_ustar_span(payload_len: usize) -> usize {
    512 + payload_len.div_ceil(512) * 512
}

/// Regression: offline --commit-overlay appends into multi-frame .tar.zst
/// without rewriting prefix frames.
#[test]
fn commit_overlay_tar_zst_multi_frame_append() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("off-mf-prefix");
    let last = generated_payload("off-mf-last");
    let extra = generated_payload("off-mf-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("prefix.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let before = fs::read(&archive).unwrap();
    let map = scan_zstd_frames_path(&archive).unwrap();
    let rewrite_start = map.frames.last().unwrap().compressed_offset as usize;
    let prefix_bytes = before[..rewrite_start].to_vec();

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    fs::write(overlay.join("new.txt"), &extra).unwrap();

    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
    let after = fs::read(&archive).unwrap();
    assert_eq!(
        &after[..rewrite_start],
        prefix_bytes.as_slice(),
        "prefix frames must stay byte-identical"
    );
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

/// Regression: offline --commit-overlay last-window replace keeps one name.
#[test]
fn commit_overlay_tar_zst_last_window_replace() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("off-rw-prefix");
    let old = generated_payload("off-rw-old");
    let new = generated_payload("off-rw-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("prefix.txt", &prefix)],
        &[ustar_file("last.txt", &old)],
        false,
    );
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    fs::write(overlay.join("last.txt"), &new).unwrap();

    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    assert_eq!(read_member(src.as_ref(), "/last.txt"), new);
    let names = src.list("/").expect("list");
    let n = match names {
        ListResult::Infos(m) => m.keys().filter(|k| *k == "last.txt").count(),
        ListResult::Names(v) => v.iter().filter(|k| *k == "last.txt").count(),
    };
    assert_eq!(n, 1, "replaced name must appear once");
}

/// Regression: prefix-frame delete via offline --commit-overlay.
#[test]
fn commit_overlay_tar_zst_earlier_frame_delete() {
    let dir = tempfile::tempdir().unwrap();
    let keep = generated_payload("off-ef-keep");
    let old = generated_payload("off-ef-old");
    let last = generated_payload("off-ef-last");
    let archive = dir.path().join("a.tar.zst");
    let f0 = pack_tar_no_eof(&[ustar_file("keep.txt", &keep)]);
    let f1 = pack_tar_no_eof(&[ustar_file("old.txt", &old)]);
    let mut f2 = pack_tar_no_eof(&[ustar_file("last.txt", &last)]);
    ratarmount_formats_tar::write_tar_eof(&mut f2).unwrap();
    fs::write(&archive, concat_zstd_frames(&[&f0, &f1, &f2], false)).unwrap();

    let before = fs::read(&archive).unwrap();
    let map = scan_zstd_frames_path(&archive).unwrap();
    assert!(map.frames.len() >= 3);
    let prefix_end = map.frames[1].compressed_offset as usize;
    let prefix_bytes = before[..prefix_end].to_vec();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    ov.unlink("/old.txt").expect("unlink prefix-frame member");
    drop(ov);

    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
    let after = fs::read(&archive).unwrap();
    assert_eq!(
        &after[..prefix_end],
        prefix_bytes.as_slice(),
        "prefix before rewrite start must stay byte-identical"
    );
    let src = open_tar_zst_base(&archive, false);
    assert!(
        src.lookup("/old.txt", 0).is_none(),
        "deleted name must be gone"
    );
    assert_eq!(read_member(src.as_ref(), "/keep.txt"), keep);
    assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
}

/// Regression: offsetheader in frame k but frame k starts mid-member.
/// Ceiling stays at k when the suffix still has a later header; opaque
/// prefix of `big.bin` is copied. Floor-skip coverage is
/// `commit_overlay_tar_zst_earlier_frame_delete`.
#[test]
fn commit_overlay_tar_zst_header_straddle_delete() {
    let dir = tempfile::tempdir().unwrap();
    let keep = generated_payload("off-hs-keep");
    let big = generated_payload("off-hs-big").repeat(200);
    let gone = generated_payload("off-hs-gone");
    let last = generated_payload("off-hs-last");
    let tar = pack_tar(&[
        ustar_file("keep.txt", &keep),
        ustar_file("big.bin", &big),
        ustar_file("gone.txt", &gone),
        ustar_file("last.txt", &last),
    ]);
    let keep_end = padded_ustar_span(keep.len());
    let mid_big = keep_end + 512 + big.len() / 2;
    assert!(mid_big < keep_end + padded_ustar_span(big.len()));
    let archive = dir.path().join("a.tar.zst");
    fs::write(
        &archive,
        concat_zstd_frames(
            &[&tar[..keep_end], &tar[keep_end..mid_big], &tar[mid_big..]],
            false,
        ),
    )
    .unwrap();

    let map = scan_zstd_frames_path(&archive).unwrap();
    assert_eq!(map.frames.len(), 3);
    let base = open_tar_zst_base(&archive, false);
    let ohs = all_tar_offsetheaders(base.as_ref(), "gone.txt").expect("ohs");
    let min_oh = *ohs.iter().min().expect("oh");
    let k = frame_covering_uncomp(&map, min_oh).expect("frame k");
    assert_eq!(k, 2, "gone.txt header must live in frame 2");

    let before = fs::read(&archive).unwrap();
    let prefix_km1 = map.frames[k - 1].compressed_offset as usize;
    let prefix_bytes = before[..prefix_km1].to_vec();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(Arc::clone(&base), &overlay);
    ov.unlink("/gone.txt")
        .expect("unlink straddling-window name");
    drop(ov);

    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
    let after = fs::read(&archive).unwrap();
    assert_eq!(
        &after[..prefix_km1],
        prefix_bytes.as_slice(),
        "prefix before k-1 must stay byte-identical"
    );
    let src = open_tar_zst_base(&archive, false);
    assert!(src.lookup("/gone.txt", 0).is_none());
    assert_eq!(read_member(src.as_ref(), "/keep.txt"), keep);
    assert_eq!(read_member(src.as_ref(), "/big.bin"), big);
    assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
}

/// Regression: concatenated complete-TAR later-frame delete must apply
/// even when the caller omits `--ignore-zeros` (default offline CLI).
#[test]
fn commit_overlay_tar_zst_concatenated_delete_without_ignore_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("off-i0-prefix");
    let last = generated_payload("off-i0-last");
    let archive = dir.path().join("a.tar.zst");
    write_complete_tar_frames_zst(
        &archive,
        &[
            pack_tar(&[ustar_file("prefix.txt", &prefix)]),
            pack_tar(&[ustar_file("last.txt", &last)]),
        ],
    );
    let before = fs::read(&archive).unwrap();
    let map = scan_zstd_frames_path(&archive).unwrap();
    assert!(map.frames.len() >= 2);
    let prefix_end = map.frames[1].compressed_offset as usize;
    let prefix_bytes = before[..prefix_end].to_vec();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
    ov.unlink("/last.txt")
        .expect("unlink later complete-TAR frame");
    drop(ov);

    assert!(
        commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"),
        "offline commit without -i must still persist the later-frame delete"
    );
    let after = fs::read(&archive).unwrap();
    assert_eq!(
        &after[..prefix_end],
        prefix_bytes.as_slice(),
        "prefix complete-TAR frame must stay byte-identical"
    );
    let src = open_tar_zst_base(&archive, true);
    assert!(
        src.lookup("/last.txt", 0).is_none(),
        "later-frame name must be gone after offline commit without -i"
    );
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
}

/// Regression: concatenated complete-TAR later-frame delete needs --ignore-zeros
/// only for the mount that created the tombstone, not for offline classification.
#[test]
fn commit_overlay_tar_zst_concatenated_delete_ignore_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("off-i-prefix");
    let last = generated_payload("off-i-last");
    let archive = dir.path().join("a.tar.zst");
    write_complete_tar_frames_zst(
        &archive,
        &[
            pack_tar(&[ustar_file("prefix.txt", &prefix)]),
            pack_tar(&[ustar_file("last.txt", &last)]),
        ],
    );
    let before = fs::read(&archive).unwrap();
    let map = scan_zstd_frames_path(&archive).unwrap();
    assert!(map.frames.len() >= 2);
    let prefix_end = map.frames[1].compressed_offset as usize;
    let prefix_bytes = before[..prefix_end].to_vec();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
    ov.unlink("/last.txt")
        .expect("unlink later complete-TAR frame");
    drop(ov);

    let opts = CommitOverlayOptions {
        yes: true,
        debug: 0,
        ignore_zeros: true,
        ..Default::default()
    };
    assert!(commit_overlay(&overlay, &archive, &opts).expect("commit"));
    let after = fs::read(&archive).unwrap();
    assert_eq!(
        &after[..prefix_end],
        prefix_bytes.as_slice(),
        "prefix complete-TAR frame must stay byte-identical"
    );
    let src = open_tar_zst_base(&archive, true);
    assert!(
        src.lookup("/last.txt", 0).is_none(),
        "later-frame name must be gone when classified with ignore_zeros"
    );
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
}

/// Regression: live persist of a single-frame concatenated `.tar.zst`
/// must reinsert members after the first interior TAR EOF when patching
/// the sibling sidecar. `window_start` is 0 for a one-frame archive, so
/// `ignore_zeros: false` (default live CLI opts) used to wipe the suffix
/// and stop at the first EOF — the appended overlay file vanished on
/// warm remount.
#[test]
fn live_commit_tar_zst_single_frame_concatenated_patches_sidecar_after_interior_eof() {
    let dir = tempfile::tempdir().unwrap();
    let first = generated_payload("live-1f-first");
    let second = generated_payload("live-1f-second");
    let extra = generated_payload("live-1f-new");
    let archive = dir.path().join("a.tar.zst");
    let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
    combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
    fs::write(&archive, concat_zstd_frames(&[&combined], false)).unwrap();
    let map = scan_zstd_frames_path(&archive).unwrap();
    assert_eq!(map.frames.len(), 1, "fixture must be one zstd frame");

    let sidecar = ratarmount_index::default_index_path(&archive);
    {
        let body = open_seekable_zstd(&archive).expect("open zstd");
        let opts = OpenOptions {
            ignore_zeros: true,
            gnu_incremental: Some(false),
            ..OpenOptions::default()
        };
        let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
            &archive,
            body,
            Some(&sidecar),
            &opts,
            "test",
        )
        .expect("create sidecar");
    }
    assert!(sidecar.is_file(), "pre-existing sidecar");

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, true))
        .expect("live commit append"));
    let window = ov.last_patch_window().expect("stashed window");
    assert_eq!(
        window.window_start, 0,
        "single-frame persist rewrites from uncompressed offset 0"
    );

    // Live CLI passes the mount OpenOptions (ignore_zeros: false).
    let mount_opts = OpenOptions {
        ignore_zeros: false,
        gnu_incremental: Some(false),
        ..OpenOptions::default()
    };
    patch_sidecar_if_present(&archive, &window, &mount_opts).expect("patch sidecar");

    let body = open_seekable_zstd(&archive).expect("fresh zstd");
    let src = ratarmount_formats_tar::SqliteIndexedTar::open_with_existing_index_body(
        &archive,
        body,
        &sidecar,
        OpenOptions {
            ignore_zeros: true,
            ..OpenOptions::default()
        },
    )
    .expect("warm-open patched sidecar");
    assert_eq!(read_member(&src, "/first.txt"), first);
    assert_eq!(
        read_member(&src, "/second.txt"),
        second,
        "second complete TAR after the interior EOF must stay in the sidecar"
    );
    assert_eq!(
        read_member(&src, "/new.txt"),
        extra,
        "appended overlay file after the interior EOF must be reinserted \
         (ignore_zeros: false on the patch would stop after first.txt)"
    );
}

/// Regression: uncompressed concatenated TAR sidecar patch from
/// `window_start` 0 (unclassified delete / first-frame rewrite) must
/// reinsert members after the interior TAR EOF. Mount CLI opts default
/// to `ignore_zeros: false` and used to wipe the suffix.
#[test]
fn patch_sidecar_uncompressed_concatenated_keeps_later_members() {
    let dir = tempfile::tempdir().unwrap();
    let first = generated_payload("patch-tar-first");
    let second = generated_payload("patch-tar-second");
    let archive = dir.path().join("a.tar");
    let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
    combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
    fs::write(&archive, &combined).unwrap();

    let sidecar = ratarmount_index::default_index_path(&archive);
    {
        let opts = OpenOptions {
            ignore_zeros: true,
            gnu_incremental: Some(false),
            ..OpenOptions::default()
        };
        let mut materialised = None;
        let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index(
            &archive,
            &archive,
            Some(&sidecar),
            &opts,
            "test",
            &mut materialised,
        )
        .expect("create sidecar");
    }
    assert!(sidecar.is_file(), "pre-existing sidecar");

    let mount_opts = OpenOptions {
        ignore_zeros: false,
        gnu_incremental: Some(false),
        ..OpenOptions::default()
    };
    patch_sidecar_if_present(
        &archive,
        &IndexPatchWindow {
            window_start: 0,
            from_frame: None,
            offsets_shifted: true,
        },
        &mount_opts,
    )
    .expect("patch sidecar");

    let mut materialised = None;
    let src = ratarmount_formats_tar::SqliteIndexedTar::open_with_existing_index(
        &archive,
        &archive,
        &sidecar,
        OpenOptions {
            ignore_zeros: true,
            ..OpenOptions::default()
        },
        &mut materialised,
    )
    .expect("warm-open patched sidecar");
    assert_eq!(read_member(&src, "/first.txt"), first);
    assert_eq!(
        read_member(&src, "/second.txt"),
        second,
        "second complete TAR after the interior EOF must stay in the sidecar"
    );
}

/// Regression: offline later-frame delete must reinsert later complete-TAR
/// frames when patching a sibling sidecar (not stop at the first TAR EOF).
#[test]
fn commit_overlay_tar_zst_concatenated_delete_patches_sidecar_later_frame() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("off-i0-sc-prefix");
    let mid = generated_payload("off-i0-sc-mid");
    let last = generated_payload("off-i0-sc-last");
    let archive = dir.path().join("a.tar.zst");
    write_complete_tar_frames_zst(
        &archive,
        &[
            pack_tar(&[ustar_file("prefix.txt", &prefix)]),
            pack_tar(&[ustar_file("mid.txt", &mid)]),
            pack_tar(&[ustar_file("last.txt", &last)]),
        ],
    );
    let sidecar = ratarmount_index::default_index_path(&archive);
    {
        let body = open_seekable_zstd(&archive).expect("open zstd");
        let opts = OpenOptions {
            ignore_zeros: true,
            gnu_incremental: Some(false),
            ..OpenOptions::default()
        };
        let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
            &archive,
            body,
            Some(&sidecar),
            &opts,
            "test",
        )
        .expect("create sidecar");
    }
    assert!(sidecar.is_file(), "pre-existing sidecar");

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
    ov.unlink("/prefix.txt")
        .expect("unlink first complete-TAR frame");
    drop(ov);

    assert!(
        commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"),
        "offline commit without -i must persist the first-frame delete"
    );

    let idx = ratarmount_index::SqliteIndex::open_read_only(&sidecar).expect("open patched");
    idx.check_tarstats_matches_archive(&archive)
        .expect("patched tarstats must match spliced archive");

    let body = open_seekable_zstd(&archive).expect("fresh zstd");
    let src = ratarmount_formats_tar::SqliteIndexedTar::open_with_existing_index_body(
        &archive,
        body,
        &sidecar,
        OpenOptions {
            ignore_zeros: true,
            ..OpenOptions::default()
        },
    )
    .expect("warm-open patched sidecar");
    assert!(
        src.lookup("/prefix.txt", 0).is_none(),
        "first-frame name must be gone from the patched sidecar"
    );
    assert_eq!(
        read_member(&src, "/mid.txt"),
        mid,
        "next complete-TAR frame must be reinserted when patching with ignore_zeros"
    );
    assert_eq!(
        read_member(&src, "/last.txt"),
        last,
        "later complete-TAR frame after another kept EOF must be reinserted \
         (ignore_zeros: false on the patch would stop after mid.txt)"
    );
}

/// Regression: offline --commit-overlay must not create a sibling *.index.sqlite.
#[test]
fn commit_overlay_tar_zst_no_durable_index() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("off-idx-seed");
    let extra = generated_payload("off-idx-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let preexisting = dir.path().join("preexisting.index.sqlite");
    fs::write(&preexisting, b"leave-me").unwrap();
    let before_sidecars = sibling_index_sqlite_paths(dir.path());
    let before_pre = fs::read(&preexisting).unwrap();

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));

    let after_sidecars = sibling_index_sqlite_paths(dir.path());
    assert_eq!(
        after_sidecars, before_sidecars,
        "commit must not create or rename index sidecars: {after_sidecars:?}"
    );
    assert_eq!(fs::read(&preexisting).unwrap(), before_pre);
    let archive_name = archive.file_name().unwrap().to_string_lossy();
    let next_to = archive.with_file_name(format!("{archive_name}.index.sqlite"));
    assert!(!next_to.exists(), "must not write {}", next_to.display());
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

/// Regression: offline --commit-overlay patches an existing sibling sidecar
/// (does not create one when missing).
#[test]
fn commit_overlay_tar_zst_patches_existing_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("off-patch-prefix");
    let last = generated_payload("off-patch-last");
    let extra = generated_payload("off-patch-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("prefix.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let before = fs::read(&archive).unwrap();
    let map = scan_zstd_frames_path(&archive).unwrap();
    let prefix_end = map.frames.last().unwrap().compressed_offset as usize;
    let prefix_bytes = before[..prefix_end].to_vec();

    let sidecar = ratarmount_index::default_index_path(&archive);
    {
        let body = open_seekable_zstd(&archive).expect("open zstd");
        let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
            &archive,
            body,
            Some(&sidecar),
            &OpenOptions::default(),
            "test",
        )
        .expect("create sidecar");
    }
    assert!(sidecar.is_file(), "pre-existing sidecar");
    let idx_before = fs::metadata(&sidecar).unwrap();

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));

    assert!(
        sidecar.is_file(),
        "must patch existing sidecar, not delete it"
    );
    let idx_after = fs::metadata(&sidecar).unwrap();
    assert!(
        idx_after.len() > 0,
        "sidecar must remain a real SQLite file"
    );
    let _ = idx_before;

    let after = fs::read(&archive).unwrap();
    assert_eq!(
        &after[..prefix_end],
        prefix_bytes.as_slice(),
        "prefix frames must stay byte-identical"
    );

    let idx = ratarmount_index::SqliteIndex::open_read_only(&sidecar).expect("open patched");
    idx.check_tarstats_matches_archive(&archive)
        .expect("patched tarstats must match spliced archive");

    let body = open_seekable_zstd(&archive).expect("fresh zstd");
    let src = ratarmount_formats_tar::SqliteIndexedTar::open_with_existing_index_body(
        &archive,
        body,
        &sidecar,
        OpenOptions::default(),
    )
    .expect("warm-open patched sidecar");
    assert_eq!(read_member(&src, "/prefix.txt"), prefix);
    assert_eq!(read_member(&src, "/last.txt"), last);
    assert_eq!(read_member(&src, "/new.txt"), extra);
}

#[test]
fn commit_overlay_tar_zst_single_frame_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("off-sf-seed");
    let extra = generated_payload("off-sf-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

#[test]
fn commit_overlay_tar_zst_seek_table_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("off-st-prefix");
    let last = generated_payload("off-st-last");
    let extra = generated_payload("off-st-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("prefix.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        true,
    );
    let before = fs::read(&archive).unwrap();
    assert!(seek_table_footer_present(&before));
    let map = scan_zstd_frames_path(&archive).unwrap();
    let rewrite_start = map.frames.last().unwrap().compressed_offset as usize;
    let prefix_bytes = before[..rewrite_start].to_vec();

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));

    let after = fs::read(&archive).unwrap();
    assert_eq!(&after[..rewrite_start], prefix_bytes.as_slice());
    assert!(
        seek_table_footer_present(&after),
        "seek-table footer must be rewritten"
    );
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

#[test]
fn commit_overlay_tar_zst_empty() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("off-empty");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let before = fs::read(&archive).unwrap();
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let committed = commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit");
    assert!(!committed);
    assert_eq!(fs::read(&archive).unwrap(), before);
}

#[test]
fn commit_overlay_plain_zst_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("plain.zst");
    let zst = ratarmount_compress::encode_zstd_frame(b"not-a-tar-body", 3).unwrap();
    fs::write(&archive, zst).unwrap();
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    fs::write(overlay.join("x.txt"), b"x").unwrap();
    let err = commit_overlay(&overlay, &archive, &yes_commit_opts())
        .unwrap_err()
        .to_string();
    assert!(err.contains("got Zstd"), "{err}");
    assert!(err.contains("not a TAR"), "{err}");
}

/// Minimal immutable empty base for WriteOverlay construction in tests.
struct NullBase;
impl MountSource for NullBase {
    fn list(&self, _path: &str) -> Option<ListResult> {
        Some(ListResult::Infos(Default::default()))
    }
    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        if path == "/" {
            Some(create_root_file_info())
        } else {
            None
        }
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "null base"))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

/// Regression: unlinking an archive member must hide it without a per-lookup
/// SQL probe, including after the overlay is reopened from the same folder.
#[test]
fn tombstone_cache_hides_unlinked_base_across_remount() {
    struct OneFile;
    impl MountSource for OneFile {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                let mut map = BTreeMap::new();
                map.insert("keep.txt".into(), keep_info());
                map.insert("other.txt".into(), other_info());
                Some(ListResult::Infos(map))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            match path {
                "/" => Some(create_root_file_info()),
                "/keep.txt" => Some(keep_info()),
                "/other.txt" => Some(other_info()),
                _ => None,
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "one file"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }
    fn keep_info() -> FileInfo {
        FileInfo {
            size: 4,
            mtime: 0.0,
            mode: ratarmount_core::S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                offset: 0,
                offsetheader: Some(0),
                istar: true,
                issparse: false,
                isgenerated: false,
                recursiondepth: 0,
            })],
        }
    }
    fn other_info() -> FileInfo {
        let mut fi = keep_info();
        fi.size = 5;
        fi
    }

    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(OneFile) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
    assert!(!ov.is_deleted("/keep.txt"));
    assert!(ov.lookup("/keep.txt", 0).is_some());
    for _ in 0..64 {
        assert!(!ov.is_deleted("/other.txt"));
    }
    ov.unlink("/keep.txt").unwrap();
    assert!(ov.is_deleted("/keep.txt"));
    assert!(ov.lookup("/keep.txt", 0).is_none());
    assert!(ov.lookup("/other.txt", 0).is_some());
    assert!(
        ov.list_deleted("/").iter().any(|name| name == "keep.txt"),
        "root listing must still hide the tombstone"
    );
    drop(ov);

    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    assert!(
        ov.is_deleted("/keep.txt"),
        "reopen must load tombstones from the overlay database"
    );
    assert!(ov.lookup("/keep.txt", 0).is_none());
    assert!(!ov.is_deleted("/other.txt"));
    let fd = ov.create_file("/keep.txt", 0o644).unwrap();
    drop(unsafe {
        use std::os::unix::io::FromRawFd;
        std::fs::File::from_raw_fd(fd)
    });
    assert!(!ov.is_deleted("/keep.txt"));
    let restored = ov.lookup("/keep.txt", 0).expect("recreated overlay file");
    assert!(
        matches!(restored.userdata.last(), Some(UserData::Other(s)) if s.starts_with("overlay:")),
        "create after unlink must clear the tombstone and serve the overlay file"
    );
}

/// Archive base with one member, `/keep.txt` (lookup `Some`, so unlink
/// writes a `deleted = 1` tombstone row).
struct KeepBase;
impl MountSource for KeepBase {
    fn list(&self, path: &str) -> Option<ListResult> {
        if path == "/" {
            let mut map = BTreeMap::new();
            map.insert("keep.txt".into(), keep_base_info());
            Some(ListResult::Infos(map))
        } else {
            None
        }
    }
    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        match path {
            "/" => Some(create_root_file_info()),
            "/keep.txt" => Some(keep_base_info()),
            _ => None,
        }
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "keep base"))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}
fn keep_base_info() -> FileInfo {
    FileInfo {
        size: 4,
        mtime: 0.0,
        mode: ratarmount_core::S_IFREG | 0o644,
        linkname: String::new(),
        uid: 0,
        gid: 0,
        userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
            offset: 0,
            offsetheader: Some(0),
            istar: true,
            issparse: false,
            isgenerated: false,
            recursiondepth: 0,
        })],
    }
}

/// Overlay folder whose database holds a `/keep.txt` tombstone.
fn overlay_with_keep_tombstone() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(KeepBase) as Arc<dyn MountSource>, &overlay).unwrap();
    ov.unlink("/keep.txt").unwrap();
    assert!(ov.lookup("/keep.txt", 0).is_none());
    drop(ov);
    (dir, overlay)
}

/// Regression: the mounted updater must require its initialized record even
/// when its original acquisition was fresh and optional (Sweep 4: corrupt
/// through the mount's own EXCLUSIVE connection, never another connection).
#[test]
fn regression_background_base_digest_required_record_lost_refuses() {
    for already_marked in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("base.tar");
        fs::write(&archive, b"uncached base digest bytes").unwrap();
        let overlay = tmp.path().join("overlay");
        let info = crate::overlay_meta::OverlayCreateInfo {
            base_url: archive.to_str().unwrap().into(),
            ..Default::default()
        };
        let open = || {
            WriteOverlay::new_with_create_info_for_tests(Arc::new(KeepBase), &overlay, &info)
                .unwrap()
        };
        if already_marked {
            drop(open());
        }
        assert_eq!(overlay.join(OVERLAY_MARKER).exists(), already_marked);
        let mounted = open();
        let pending = mounted
            .pending_base()
            .unwrap()
            .expect("pending archive digest");
        let digest = pending.hash(&|| Ok(())).unwrap();
        let rows = |db: &Connection| -> Vec<(String, String)> {
            db.prepare("SELECT key,value FROM meta ORDER BY key")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let before = {
            let db = mounted.db.lock().unwrap();
            let before = rows(&db);
            assert!(before
                .iter()
                .any(|(k, v)| k == "base_digest_kind" && v == "pending"));
            db.execute_batch("DROP TABLE files").unwrap();
            before
        };
        for marker in overlay_markers(&overlay).unwrap() {
            fs::remove_file(marker).unwrap();
        }
        let error = mounted.record_base_digest(&pending, &digest).unwrap_err();
        assert_eq!(
            error.to_string(),
            crate::overlay_meta::NO_FILES_TABLE,
            "already_marked={already_marked}"
        );
        assert_eq!(
            rows(&mounted.db.lock().unwrap()),
            before,
            "no digest/stack update"
        );
    }
}

fn reopen_keep_overlay(overlay: &Path) -> Result<WriteOverlay> {
    WriteOverlay::new_for_tests(Arc::new(KeepBase) as Arc<dyn MountSource>, overlay)
}

/// Remove the overlay database by exact name (plus SQLite sidecars), never
/// a `sqlite*` glob, which would also take the marker.
fn remove_overlay_db(overlay: &Path) {
    for suf in ["", "-journal", "-shm", "-wal"] {
        let _ = fs::remove_file(overlay.join(format!("{HIDDEN_DB}{suf}")));
    }
}

fn msg_of(r: Result<WriteOverlay>) -> String {
    match r {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected the overlay open to be refused"),
    }
}

fn has_files_table(db: &Path) -> bool {
    let c = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    c.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'files'",
        [],
        |_| Ok(()),
    )
    .optional()
    .unwrap()
    .is_some()
}

/// Regression: #96, a deleted overlay database was silently recreated, so
/// every tombstone was lost and unlinked archive members reappeared.
#[test]
fn overlay_open_refuses_missing_db_after_use() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    assert!(overlay.join(OVERLAY_MARKER).is_file());
    remove_overlay_db(&overlay);
    let msg = msg_of(reopen_keep_overlay(&overlay));
    assert!(
        msg.contains("database") && msg.contains("is missing"),
        "{msg}"
    );
    assert!(
        !overlay.join(HIDDEN_DB).exists(),
        "refusal must not create the DB"
    );
    let msg2 = msg_of(reopen_keep_overlay(&overlay));
    assert_eq!(msg, msg2);
}

/// Regression: #96, a dropped `files` table was recreated empty by SCHEMA.
#[test]
fn overlay_open_refuses_db_without_files_table() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    let db = overlay.join(HIDDEN_DB);
    Connection::open(&db)
        .unwrap()
        .execute_batch(r#"DROP TABLE "files";"#)
        .unwrap();
    let msg = msg_of(reopen_keep_overlay(&overlay));
    assert!(msg.contains("has no files table"), "{msg}");
    assert!(!has_files_table(&db), "refusal must not run SCHEMA");
    assert!(msg.contains("on purpose, remove"), "{msg}");
    assert!(msg.contains(" and "), "marker and DB both named: {msg}");
    assert_eq!(msg, msg_of(reopen_keep_overlay(&overlay)));
    // Without the marker (overlay from an older build) a non-empty DB
    // without the table is still refused.
    fs::remove_file(overlay.join(OVERLAY_MARKER)).unwrap();
    assert!(msg_of(reopen_keep_overlay(&overlay)).contains("has no files table"));
    assert!(!has_files_table(&db));
}

/// Regression: #96, a truncated (0-byte) database in a marked folder.
#[test]
fn overlay_open_refuses_zero_byte_db_in_used_folder() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    remove_overlay_db(&overlay);
    fs::write(overlay.join(HIDDEN_DB), b"").unwrap();
    let msg = msg_of(reopen_keep_overlay(&overlay));
    assert!(msg.contains("is missing or empty"), "{msg}");
    assert_eq!(
        fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len(),
        0,
        "refusal must not initialize the file"
    );
}

/// Regression: #96, offline `--commit-overlay` on a used folder whose
/// database is gone committed without the tombstones.
#[test]
fn overlay_commit_plan_refuses_missing_db_after_use() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    assert!(collect_overlay_commit_plan(&overlay).is_ok());
    remove_overlay_db(&overlay);
    let msg = match collect_overlay_commit_plan(&overlay) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("commit plan must be refused"),
    };
    assert!(msg.contains("refusing to commit"), "{msg}");
    assert!(
        msg.contains(OVERLAY_MARKER) && msg.contains("on purpose"),
        "{msg}"
    );
}

/// Regression: #97 review, the old marker name started with the DB name,
/// so `rm ov/.ratarmount.overlay.sqlite*` deleted it too.
#[test]
fn overlay_open_refuses_after_db_glob_rm() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    for ent in fs::read_dir(&overlay).unwrap().flatten() {
        if ent.file_name().to_string_lossy().starts_with(HIDDEN_DB) {
            fs::remove_file(ent.path()).unwrap();
        }
    }
    assert!(overlay.join(OVERLAY_MARKER).is_file());
    let msg = msg_of(reopen_keep_overlay(&overlay));
    assert!(msg.contains("is missing"), "{msg}");
    let hint = format!(
        "to discard this overlay's deletions on purpose, remove {}",
        overlay
            .canonicalize()
            .unwrap()
            .join(OVERLAY_MARKER)
            .display()
    );
    assert!(msg.contains(&hint), "{msg}");
}

/// The pre-rename marker name still guards the folder; it is migrated to
/// the new name and then deleted, so a reset is one file.
#[test]
fn overlay_open_accepts_legacy_marker() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    fs::rename(
        overlay.join(OVERLAY_MARKER),
        overlay.join(LEGACY_OVERLAY_MARKER),
    )
    .unwrap();
    let ov = reopen_keep_overlay(&overlay).unwrap();
    assert!(ov.lookup("/keep.txt", 0).is_none());
    drop(ov);
    assert!(
        overlay.join(OVERLAY_MARKER).is_file(),
        "legacy marker is migrated to the new name"
    );
    assert!(
        !overlay.join(LEGACY_OVERLAY_MARKER).exists(),
        "legacy removed"
    );
    // The old glob takes the DB; the new marker stays.
    for ent in fs::read_dir(&overlay).unwrap().flatten() {
        if ent.file_name().to_string_lossy().starts_with(HIDDEN_DB) {
            fs::remove_file(ent.path()).unwrap();
        }
    }
    let msg = msg_of(reopen_keep_overlay(&overlay));
    assert!(msg.contains(OVERLAY_MARKER), "{msg}");
}

/// Regression: folders an earlier build migrated kept both markers, so a
/// reset needed two removals. The next open drops the legacy one.
#[test]
fn overlay_open_removes_legacy_marker_when_both_present() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    fs::write(overlay.join(LEGACY_OVERLAY_MARKER), b"").unwrap();
    let ov = reopen_keep_overlay(&overlay).unwrap();
    assert!(ov.lookup("/keep.txt", 0).is_none(), "tombstone kept");
    drop(ov);
    assert!(overlay.join(OVERLAY_MARKER).is_file());
    assert!(!overlay.join(LEGACY_OVERLAY_MARKER).exists());
}

/// Every marker present is named in the reset hint (here: legacy could
/// not be cleaned because the DB was already gone).
#[test]
fn overlay_refusal_lists_every_marker() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    fs::write(overlay.join(LEGACY_OVERLAY_MARKER), b"").unwrap();
    remove_overlay_db(&overlay);
    let msg = msg_of(reopen_keep_overlay(&overlay));
    assert!(
        msg.contains(OVERLAY_MARKER) && msg.contains(LEGACY_OVERLAY_MARKER),
        "{msg}"
    );
    let msg = match collect_overlay_commit_plan(&overlay) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("commit must be refused"),
    };
    assert!(
        msg.contains(OVERLAY_MARKER) && msg.contains(LEGACY_OVERLAY_MARKER),
        "{msg}"
    );
}

/// Regression (Keystone, #97): the commit refusal said only "missing" and
/// printed the overlay path as given.
#[test]
fn overlay_commit_refusal_missing_or_empty_canonical() {
    let (dir, overlay) = overlay_with_keep_tombstone();
    remove_overlay_db(&overlay);
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&overlay, &link).unwrap();
    let msg = match collect_overlay_commit_plan(&link) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("commit must be refused"),
    };
    let canon = overlay.canonicalize().unwrap();
    assert!(msg.contains("is missing or empty"), "{msg}");
    assert!(
        msg.contains(&canon.join(HIDDEN_DB).display().to_string()),
        "{msg}"
    );
    assert!(!msg.contains(&format!("{}/", link.display())), "{msg}");
}

/// Regression (Robo-Ilya, #97): the database and markers were visible to
/// lookup through the mount.
#[test]
fn overlay_internal_names_hidden_from_lookup() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    let ov = reopen_keep_overlay(&overlay).unwrap();
    for p in [
        format!("/{HIDDEN_DB}"),
        format!("/{HIDDEN_DB}-journal"),
        format!("/{OVERLAY_MARKER}"),
        format!("/{LEGACY_OVERLAY_MARKER}"),
        format!("/sub/{OVERLAY_MARKER}"),
        format!("/{COW_STAGING_PREFIX}Ab12Cd"),
    ] {
        assert!(ov.lookup(&p, 0).is_none(), "{p}");
        assert!(!ov.has_file(&p), "{p}");
    }
    // Planted after open, so startup sweep cannot remove it. Lookup and
    // has_file still have to treat the staging prefix as bookkeeping.
    let planted_name = format!("{COW_STAGING_PREFIX}Ab12Cd");
    fs::write(overlay.join(&planted_name), b"short").unwrap();
    let planted = format!("/{planted_name}");
    assert!(ov.lookup(&planted, 0).is_none(), "{planted}");
    assert!(!ov.has_file(&planted), "{planted}");
    // A base-archive member with the database name is hidden too.
    struct DbNamedBase;
    impl MountSource for DbNamedBase {
        fn list(&self, _: &str) -> Option<ListResult> {
            None
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            (path == "/.ratarmount.overlay.sqlite").then(keep_base_info)
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let ov2 = WriteOverlay::new_for_tests(Arc::new(DbNamedBase), dir.path().join("o")).unwrap();
    // Remove the host DB so only the base member could answer.
    fs::remove_file(dir.path().join("o").join(HIDDEN_DB)).unwrap();
    assert!(ov2.lookup("/.ratarmount.overlay.sqlite", 0).is_none());
}

/// Regression (Robo-Ilya, #97): create/delete/rename/truncate of the
/// database or a marker through the mount could destroy the tombstones.
#[test]
fn overlay_internal_names_refuse_mutation() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    let db_len = fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len();
    let ov = reopen_keep_overlay(&overlay).unwrap();
    let denied = |r: Result<()>| match r {
        Err(OverlayError::Io(e)) => e.kind() == io::ErrorKind::PermissionDenied,
        _ => false,
    };
    for p in [
        format!("/{HIDDEN_DB}"),
        format!("/{HIDDEN_DB}-journal"),
        format!("/{OVERLAY_MARKER}"),
        format!("/{LEGACY_OVERLAY_MARKER}"),
        format!("/sub/{OVERLAY_MARKER}"),
    ] {
        assert!(denied(ov.create_file(&p, 0o644).map(|_| ())), "create {p}");
        assert!(
            denied(ov.open_overlay_fd(&p, libc::O_RDONLY).map(|_| ())),
            "open {p}"
        );
        assert!(
            denied(ov.open_overlay_fd(&p, libc::O_WRONLY).map(|_| ())),
            "open w {p}"
        );
        assert!(denied(ov.unlink(&p)), "unlink {p}");
        assert!(denied(ov.mkdir(&p, 0o755)), "mkdir {p}");
        assert!(denied(ov.rmdir(&p)), "rmdir {p}");
        assert!(denied(ov.truncate(&p, 0)), "truncate {p}");
        assert!(denied(ov.create_symlink(&p, "x")), "symlink {p}");
        assert!(denied(ov.rename(&p, "/x")), "rename from {p}");
        assert!(denied(ov.rename("/keep.txt", &p)), "rename to {p}");
        assert!(denied(ov.ensure_modifiable(&p)), "cow {p}");
    }
    drop(ov);
    assert_eq!(fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len(), db_len);
    assert!(overlay.join(OVERLAY_MARKER).is_file());
    let ov = reopen_keep_overlay(&overlay).unwrap();
    assert!(ov.lookup("/keep.txt", 0).is_none(), "tombstone kept");
}

/// Keystone (#99): on a case-insensitive overlay folder a case variant
/// of the database or marker name is the real file, so it is refused and
/// hidden like the exact name.
#[test]
fn overlay_internal_names_ignore_ascii_case() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    let db_len = fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len();
    let ov = reopen_keep_overlay(&overlay).unwrap();
    let denied = |r: Result<()>| match r {
        Err(OverlayError::Io(e)) => e.kind() == io::ErrorKind::PermissionDenied,
        _ => false,
    };
    for p in [
        "/.RATARMOUNT.OVERLAY.SQLITE",
        "/.Ratarmount-Overlay.Used",
        "/.Ratarmount.Overlay.Sqlite-journal",
        "/sub/.RATARMOUNT-OVERLAY.USED/foo",
    ] {
        assert!(denied(ov.create_file(p, 0o644).map(|_| ())), "create {p}");
        assert!(denied(ov.unlink(p)), "unlink {p}");
        assert!(denied(ov.mkdir(p, 0o755)), "mkdir {p}");
        assert!(denied(ov.truncate(p, 0)), "truncate {p}");
        assert!(denied(ov.rename("/keep.txt", p)), "rename to {p}");
        assert!(ov.lookup(p, 0).is_none(), "lookup {p}");
    }
    drop(ov);
    assert_eq!(fs::metadata(overlay.join(HIDDEN_DB)).unwrap().len(), db_len);
    if cfg!(target_os = "linux") {
        assert!(!overlay.join(".RATARMOUNT.OVERLAY.SQLITE").exists());
    }
}

/// Plan skeptic (round 2): SMB/SFTP pass full paths, so a path *beneath*
/// a bookkeeping name must be refused before `create_dir_all`, hidden from
/// lookup/listing, and skipped by the commit walk.
#[test]
fn overlay_internal_names_refused_beneath_any_component() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    let ov = reopen_keep_overlay(&overlay).unwrap();
    let denied = |r: Result<()>| match r {
        Err(OverlayError::Io(e)) => e.kind() == io::ErrorKind::PermissionDenied,
        _ => false,
    };
    let p = format!("/sub/{OVERLAY_MARKER}/foo");
    assert!(denied(ov.create_file(&p, 0o644).map(|_| ())), "create {p}");
    assert!(denied(ov.mkdir(&p, 0o755)), "mkdir {p}");
    assert!(denied(ov.rename("/keep.txt", &p)), "rename to {p}");
    assert!(!overlay.join("sub").join(OVERLAY_MARKER).exists());
    assert!(ov.lookup(&format!("/{HIDDEN_DB}/."), 0).is_none());
    // A child planted on the host under that name is invisible and
    // never appended by commit.
    fs::create_dir_all(overlay.join("sub").join(OVERLAY_MARKER)).unwrap();
    fs::write(overlay.join("sub").join(OVERLAY_MARKER).join("foo"), b"x").unwrap();
    assert!(ov.lookup(&p, 0).is_none());
    assert!(ov.list(&format!("/sub/{OVERLAY_MARKER}")).is_none());
    drop(ov);
    let plan =
        collect_overlay_commit_plan_from_conn(&overlay, None, None, &HashSet::new()).unwrap();
    assert!(
        !plan.append_entries.is_empty()
            && plan
                .append_entries
                .iter()
                .all(|(e, _)| !e.split('/').any(is_overlay_internal_name)),
        "{:?}",
        plan.append_entries
    );
}

/// Plan skeptic (round 2): a non-regular entry under either marker name
/// fails closed even when the other marker is a regular file.
#[test]
fn overlay_markers_fail_closed_on_non_regular_sibling() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(LEGACY_OVERLAY_MARKER), b"").unwrap();
    fs::create_dir(dir.path().join(OVERLAY_MARKER)).unwrap();
    let e = overlay_markers(dir.path()).unwrap_err().to_string();
    assert!(e.contains("not a regular file"), "{e}");
    assert!(e.contains(OVERLAY_MARKER), "{e}");
}

/// Regression: a first open that fails after the marker was created
/// (SCHEMA on a read-only 0-byte database) must not leave the marker.
#[test]
fn overlay_first_open_failure_removes_marker() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    fs::create_dir(&overlay).unwrap();
    let db = overlay.join(HIDDEN_DB);
    fs::write(&db, b"").unwrap();
    fs::set_permissions(&db, fs::Permissions::from_mode(0o444)).unwrap();
    if fs::OpenOptions::new().write(true).open(&db).is_ok() {
        eprintln!("skip: read-only file is writable (running as root?)");
        return;
    }
    let r = reopen_keep_overlay(&overlay);
    assert!(r.is_err(), "SCHEMA on a read-only DB must fail");
    assert!(
        !overlay.join(OVERLAY_MARKER).exists(),
        "marker must be removed"
    );
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(fs::metadata(&db).unwrap().len(), 0);
    reopen_keep_overlay(&overlay).expect("folder still opens as new");
}

/// Robo-Ilya: a directory at the database path is named as such.
#[test]
fn overlay_open_db_path_directory_is_named() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    remove_overlay_db(&overlay);
    fs::create_dir(overlay.join(HIDDEN_DB)).unwrap();
    let msg = msg_of(reopen_keep_overlay(&overlay));
    assert!(msg.contains("is a directory, not a database file"), "{msg}");
    let msg = match collect_overlay_commit_plan(&overlay) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("commit must be refused"),
    };
    assert!(msg.contains("is a directory"), "{msg}");
}

#[test]
fn overlay_open_accepts_new_empty_and_zero_byte() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let empty = dir.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let zero = dir.path().join("zero");
    fs::create_dir(&zero).unwrap();
    fs::write(zero.join(HIDDEN_DB), b"").unwrap();
    for ov in [&missing, &empty, &zero] {
        let o = reopen_keep_overlay(ov).unwrap_or_else(|e| panic!("{}: {e}", ov.display()));
        drop(o);
        assert!(ov.join(OVERLAY_MARKER).is_file(), "{}", ov.display());
        assert!(has_files_table(&ov.join(HIDDEN_DB)));
    }
}

/// Regression: (#160): a failed first open of a folder holding a 0-byte
/// database "put it back" by truncating the file through a descriptor of
/// its own. Closing that descriptor released every fcntl lock this
/// process held on the file, so another connection's SHARED lock was gone
/// (another process could then take EXCLUSIVE under it). The holder keeps
/// its lock, the file stays 0 bytes (SQLite's rollback), and the holder
/// still reads and writes.
#[test]
fn regression_failed_open_cleanup_keeps_empty_db_holders_lock() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().canonicalize().unwrap().join("zero");
    fs::create_dir(&overlay).unwrap();
    let db = overlay.join(HIDDEN_DB);
    fs::write(&db, b"").unwrap();
    let holder = Connection::open(&db).unwrap();
    holder
        .execute_batch("BEGIN; SELECT count(*) FROM sqlite_master;")
        .unwrap();
    assert!(
        crate::overlay_db::other_process_sees_lock(&db),
        "the holder's SHARED lock"
    );
    // The schema commit needs EXCLUSIVE, which the holder's SHARED lock
    // refuses: the open fails and takes the cleanup path.
    let error = msg_of(reopen_keep_overlay(&overlay));
    assert!(
        error.contains("locked") || error.contains("busy"),
        "{error}"
    );
    assert_eq!(
        fs::metadata(&db).unwrap().len(),
        0,
        "rolled back to 0 bytes"
    );
    assert!(
        crate::overlay_db::other_process_sees_lock(&db),
        "the failed open's cleanup released the holder's lock"
    );
    holder
        .execute_batch("SELECT count(*) FROM sqlite_master; COMMIT; CREATE TABLE t (x);")
        .unwrap();
}

/// Regression: (#160 fix round): the failed first open removed the
/// database name whenever a stat before SQLite's open found nothing, even
/// when the name held another file by the time of the cleanup. A new
/// database the open created is removed; a file put at the name after
/// SQLite's open is left alone.
#[test]
fn regression_failed_first_open_removes_only_the_database_it_opened() {
    let dir = tempfile::tempdir().unwrap();
    let fresh = dir.path().canonicalize().unwrap().join("fresh");
    fs::create_dir(&fresh).unwrap();
    FAIL_SCHEMA_STEP.with(|seam| *seam.borrow_mut() = Some(Box::new(|| {})));
    let error = msg_of(reopen_keep_overlay(&fresh));
    assert!(error.contains("schema step failed"), "{error}");
    assert!(!fresh.join(HIDDEN_DB).exists(), "the new database stayed");

    let swapped = dir.path().canonicalize().unwrap().join("swapped");
    fs::create_dir(&swapped).unwrap();
    let db = swapped.join(HIDDEN_DB);
    let other = dir.path().join("other.sqlite");
    fs::write(&other, b"another file").unwrap();
    let (hook_db, hook_other) = (db.clone(), other.clone());
    FAIL_SCHEMA_STEP.with(|seam| {
        *seam.borrow_mut() = Some(Box::new(move || {
            fs::rename(&hook_other, &hook_db).unwrap();
        }))
    });
    let error = msg_of(reopen_keep_overlay(&swapped));
    assert!(error.contains("schema step failed"), "{error}");
    assert_eq!(
        fs::read(&db).unwrap(),
        b"another file",
        "the cleanup removed a file it never opened"
    );
}

/// Overlays created before the marker existed get it on their next open.
#[test]
fn overlay_open_backfills_marker() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    fs::remove_file(overlay.join(OVERLAY_MARKER)).unwrap();
    let ov = reopen_keep_overlay(&overlay).unwrap();
    assert!(ov.lookup("/keep.txt", 0).is_none(), "tombstone kept");
    assert!(overlay.join(OVERLAY_MARKER).is_file());
}

/// Regression: #222 a writable mount followed a symlinked database and wrote
/// through it instead of refusing with a next step.
#[cfg(unix)]
#[test]
fn regression_mount_refuses_symlinked_db() {
    let (dir, overlay) = overlay_with_keep_tombstone();
    let real = dir.path().join("real.sqlite");
    fs::rename(overlay.join(HIDDEN_DB), &real).unwrap();
    std::os::unix::fs::symlink(&real, overlay.join(HIDDEN_DB)).unwrap();
    let before = fs::read(&real).unwrap();
    for _ in 0..2 {
        let error = msg_of(reopen_keep_overlay(&overlay));
        assert!(
            error.contains("is a symlink; it must be a regular file"),
            "{error}"
        );
        assert!(
            error.contains("move the database file into place of the link"),
            "{error}"
        );
        assert!(error.contains("retry the writable mount"), "{error}");
        assert_eq!(fs::read(&real).unwrap(), before, "target unchanged");
    }
    fs::remove_file(&real).unwrap();
    // Regression: #239 dangling database links have the same policy refusal.
    assert!(
        msg_of(reopen_keep_overlay(&overlay)).contains("is a symlink; it must be a regular file")
    );
}

/// Regression: #222 swapping the classified database for a symlink to the
/// same inode bypassed identity checks; SQLite must refuse before any write.
#[cfg(unix)]
#[test]
fn regression_mount_refuses_db_swapped_for_symlink_after_classify() {
    let (dir, overlay) = overlay_with_keep_tombstone();
    let db = overlay.canonicalize().unwrap().join(HIDDEN_DB);
    let real = dir.path().join("real.sqlite");
    let before = fs::read(&db).unwrap();
    let id = crate::overlay_db::file_id(&fs::metadata(&db).unwrap());
    let target = real.clone();
    crate::overlay_db::AFTER_CLASSIFY.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |path| {
            fs::rename(path, &target).unwrap();
            std::os::unix::fs::symlink(&target, path).unwrap();
        }));
    });
    let result = reopen_keep_overlay(&overlay);
    crate::overlay_db::AFTER_CLASSIFY.with(|hook| *hook.borrow_mut() = None);
    assert!(
        fs::symlink_metadata(&db).unwrap().file_type().is_symlink(),
        "seam ran"
    );
    assert_eq!(
        crate::overlay_db::file_id(&fs::metadata(&db).unwrap()),
        id,
        "same inode"
    );
    let error = msg_of(result);
    assert!(
        error.contains("is a symlink; it must be a regular file"),
        "{error}"
    );
    assert!(
        error.contains("move the database file into place of the link"),
        "{error}"
    );
    assert!(error.contains("retry the writable mount"), "{error}");
    assert_eq!(fs::read(&real).unwrap(), before, "target unchanged");
}

/// Regression: #239 a writable mount refuses every companion link, both
/// at admission and when planted immediately before SQLite acquisition.
#[cfg(unix)]
#[test]
fn regression_mount_refuses_symlinked_companions() {
    for suffix in ["-wal", "-journal", "-shm"] {
        for after_classify in [false, true] {
            let (dir, overlay) = overlay_with_keep_tombstone();
            let db = overlay.canonicalize().unwrap().join(HIDDEN_DB);
            let companion = PathBuf::from(format!("{}{suffix}", db.display()));
            let target = dir.path().join("target");
            fs::write(&target, b"").unwrap();
            let before = fs::read(&db).unwrap();
            let marker_before = fs::read(overlay.join(OVERLAY_MARKER)).unwrap();
            if after_classify {
                let companion = companion.clone();
                let target = target.clone();
                crate::overlay_db::AFTER_CLASSIFY.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move |_| {
                        std::os::unix::fs::symlink(&target, &companion).unwrap();
                    }));
                });
            } else {
                std::os::unix::fs::symlink(&target, &companion).unwrap();
            }
            let result = reopen_keep_overlay(&overlay);
            crate::overlay_db::AFTER_CLASSIFY.with(|hook| *hook.borrow_mut() = None);
            let error = msg_of(result);
            assert!(
                error.contains(&companion.display().to_string()),
                "{suffix} seam={after_classify}: {error}"
            );
            assert!(
                error.contains("is a symlink; it must be a regular file"),
                "{error}"
            );
            assert!(fs::symlink_metadata(&companion)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(fs::read(&db).unwrap(), before, "database unchanged");
            assert_eq!(fs::read(&target).unwrap(), b"", "target unchanged");
            assert_eq!(
                fs::read(overlay.join(OVERLAY_MARKER)).unwrap(),
                marker_before
            );
        }
    }
}

/// Regression (r17 skeptic #2, R7-E2): a dangling symlink at the
/// database path was read as "no database" by `fs::metadata`. B8: a first
/// open (no marker yet) created a fresh database THROUGH the symlink,
/// outside the overlay. B7: the offline commit plan was built without the
/// tombstones. Both refuse; nothing is created at the target.
#[cfg(unix)]
#[test]
fn regression_dangling_db_symlink_is_not_an_absent_database() {
    let dir = tempfile::tempdir().unwrap();
    let mut failed = Vec::new();
    for site in ["B8 WriteOverlay::open", "B7 collect_overlay_commit_plan"] {
        let overlay = dir.path().join(site.split(' ').next().unwrap());
        fs::create_dir(&overlay).unwrap();
        let target = dir.path().join(format!(
            "{}-nowhere.sqlite",
            site.split(' ').next().unwrap()
        ));
        std::os::unix::fs::symlink(&target, overlay.join(HIDDEN_DB)).unwrap();
        let refused = if site.starts_with("B8") {
            WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
                .is_err()
        } else {
            collect_overlay_commit_plan(&overlay).is_err()
        };
        if !refused || target.exists() {
            failed.push(format!(
                "{site}: refused={refused} created={}",
                target.exists()
            ));
        }
    }
    assert!(failed.is_empty(), "failed rows: {failed:?}");
}

/// Regression: the marker must not be created through a planted symlink.
#[test]
fn overlay_marker_symlink_is_refused_and_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside.txt");
    fs::write(&outside, b"secret").unwrap();
    let dangling_target = dir.path().join("created-outside");
    for (name, target) in [("a", &outside), ("b", &dangling_target)] {
        let overlay = dir.path().join(name);
        fs::create_dir(&overlay).unwrap();
        std::os::unix::fs::symlink(target, overlay.join(OVERLAY_MARKER)).unwrap();
        let r = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay);
        assert!(r.is_err(), "symlinked marker must be refused");
    }
    assert_eq!(fs::read(&outside).unwrap(), b"secret");
    assert!(!dangling_target.exists());
}

#[test]
fn overlay_marker_is_hidden_kept_on_reset_and_not_committed() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    let ov = reopen_keep_overlay(&overlay).unwrap();
    let names: Vec<String> = ov
        .list_dirents("/")
        .unwrap()
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert!(!names.iter().any(|n| n == OVERLAY_MARKER), "{names:?}");
    assert!(ov.list_deleted("/").iter().any(|n| n == OVERLAY_MARKER));
    reset_overlay_dir(&overlay).unwrap();
    assert!(overlay.join(OVERLAY_MARKER).is_file());
    assert!(overlay.join(HIDDEN_DB).is_file());
    drop(ov);
    let plan =
        collect_overlay_commit_plan_from_conn(&overlay, None, None, &HashSet::new()).unwrap();
    assert!(
        plan.append_entries.iter().all(|(p, _)| p != OVERLAY_MARKER),
        "{:?}",
        plan.append_entries
    );
    assert!(!plan.deleted_paths.contains(OVERLAY_MARKER));
}

/// Regression: a failing tombstone SELECT at open became an empty set, so
/// every unlinked archive member reappeared. Opening must fail instead.
#[test]
fn overlay_open_fails_when_tombstone_query_errors() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    {
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        conn.execute_batch(r#"ALTER TABLE "files" RENAME COLUMN "deleted" TO "deleted_x";"#)
            .unwrap();
    } // EXCLUSIVE locking: drop before reopening.
    match reopen_keep_overlay(&overlay) {
        Ok(ov) => panic!(
            "overlay opened with an unreadable tombstone table; /keep.txt visible: {}",
            ov.lookup("/keep.txt", 0).is_some()
        ),
        Err(e) => assert!(
            matches!(e, OverlayError::Sqlite(_)) && e.to_string().contains("no such column"),
            "want the tombstone SELECT error, got {e}"
        ),
    }
}

/// Regression: an unreadable tombstone row was dropped by
/// `filter_map(ok)`, opening with a partial set (that member reappears).
#[test]
fn overlay_open_fails_when_a_tombstone_row_is_unreadable() {
    let (_dir, overlay) = overlay_with_keep_tombstone();
    {
        let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
        conn.execute(
            r#"INSERT INTO "files" (path, name, deleted) VALUES ('', X'FF', 1)"#,
            [],
        )
        .unwrap();
        let kind: String = conn
            .query_row(
                r#"SELECT typeof(name) FROM "files" WHERE path = '' AND deleted = 1 AND typeof(name) = 'blob'"#,
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kind, "blob", "TEXT affinity keeps blobs as blobs");
    }
    match reopen_keep_overlay(&overlay) {
        Ok(_) => panic!("overlay opened with a partial tombstone set"),
        Err(e) => assert!(
            matches!(
                e,
                OverlayError::Sqlite(rusqlite::Error::InvalidColumnType(..))
            ),
            "want InvalidColumnType from the tombstone row, got {e}"
        ),
    }
}

/// Regression: prune EACCES after a committed delete left `is_deleted` true.
///
/// Symptom: `forget_committed_overlay` deleted the `gone` row, then
/// `prune_empty_overlay_ancestors` returned before `tombstone_forget_many`,
/// so the in-memory set still hid `gone`.
#[test]
fn forget_committed_overlay_forgets_tombstone_when_prune_fails() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skip: euid 0 ignores mode 0o555");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(NullBase) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();

    let sub = ov.root.join("sub");
    fs::create_dir_all(sub.join("nested")).unwrap();
    fs::write(sub.join("nested").join("f"), b"payload").unwrap();
    {
        let db = ov.db.lock().expect("overlay db");
        db.execute(
            r#"INSERT OR REPLACE INTO "files" (path,name,deleted) VALUES ('','gone',1)"#,
            [],
        )
        .unwrap();
    }
    ov.tombstone_remember("gone");
    assert!(
        ov.is_deleted("gone"),
        "fixture must seed the in-memory tombstone"
    );

    // `sub` at 0o555 blocks removing `nested`. Restore before TempDir drops.
    struct RestoreMode {
        path: PathBuf,
        mode: u32,
    }
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
        }
    }
    let original_mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(&sub).unwrap().permissions().mode()
    };
    let _restore = RestoreMode {
        path: sub.clone(),
        mode: original_mode,
    };
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o555)).unwrap();
    }

    let plan = OverlayCommitPlan {
        known_hashes: BTreeMap::new(),
        written_hashes: BTreeMap::new(),
        metadata: BTreeMap::new(),
        xattrs: BTreeMap::new(),
        deletions_nul: Vec::new(),
        appends_nul: Vec::new(),
        deleted_paths: ["gone".into()].into_iter().collect(),
        append_entries: vec![("sub/nested/f".into(), false)],
    };
    let err = ov
        .forget_committed_overlay(&plan)
        .expect_err("prune remove_dir(sub/nested) must fail");
    let OverlayError::Io(ioe) = &err else {
        panic!("expected io::PermissionDenied from prune, got {err}");
    };
    assert_eq!(
        ioe.kind(),
        io::ErrorKind::PermissionDenied,
        "expected EACCES from prune, got {err}"
    );
    {
        let db = ov.db.lock().expect("overlay db");
        let n: i64 = db
            .query_row(
                r#"SELECT COUNT(*) FROM "files" WHERE path = '' AND name = 'gone'"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "gone row must be deleted before prune fails");
    }
    assert!(
        !ov.is_deleted("gone"),
        "committed tombstone must leave the cache when prune fails"
    );
}

/// Regression: overlay open/create must not follow host symlinks outside root.
///
/// Symptom: `realpath` is join+normpath only; `libc::open` / `File::create`
/// follow symlinks, so a pre-seeded symlink under the overlay folder can
/// redirect writes to arbitrary host paths.
#[test]
fn overlay_rejects_symlink_escape_outside_root() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let outside_file = outside.join("secret.txt");
    fs::write(&outside_file, b"secret-data").unwrap();

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    // Plant a file symlink and a directory symlink pointing outside the overlay.
    std::os::unix::fs::symlink(&outside_file, overlay.join("escape")).unwrap();
    std::os::unix::fs::symlink(&outside, overlay.join("outdir")).unwrap();

    let base = Arc::new(NullBase) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();

    // create_file through file symlink must fail and not clobber outside content.
    let err = ov.create_file("/escape", 0o644);
    assert!(
        err.is_err(),
        "create_file through escape symlink must fail, got Ok"
    );
    assert_eq!(
        fs::read(&outside_file).unwrap(),
        b"secret-data",
        "outside file must remain untouched after create_file"
    );

    // open_overlay_fd must not follow the escape symlink either.
    let err = ov.open_overlay_fd("/escape", libc::O_RDWR | libc::O_CREAT);
    assert!(
        err.is_err(),
        "open_overlay_fd through escape symlink must fail, got Ok"
    );
    assert_eq!(
        fs::read(&outside_file).unwrap(),
        b"secret-data",
        "outside file must remain untouched after open_overlay_fd"
    );

    // create under a directory symlink must not write outside the overlay.
    let err = ov.create_file("/outdir/pwned.txt", 0o644);
    assert!(
        err.is_err(),
        "create_file under dir symlink must fail, got Ok"
    );
    assert!(
        !outside.join("pwned.txt").exists(),
        "must not create files outside overlay via dir symlink"
    );

    // mkdir via escape dir symlink must fail.
    let err = ov.mkdir("/outdir/evil-dir", 0o755);
    assert!(err.is_err(), "mkdir under dir symlink must fail, got Ok");
    assert!(
        !outside.join("evil-dir").exists(),
        "must not mkdir outside overlay via dir symlink"
    );

    // Normal create inside overlay still works.
    let fd = ov.create_file("/safe.txt", 0o644).expect("safe create");
    assert!(fd >= 0);
    unsafe {
        libc::close(fd);
    }
    assert!(overlay.join("safe.txt").exists() || ov.root().join("safe.txt").exists());
}

/// Counts `list()` so we can prove WriteOverlay uses `base.list_dirents`.
struct ListCallCounter {
    inner: ratarmount_formats_zip::ZipMountSource,
    list_calls: std::sync::atomic::AtomicUsize,
}

impl MountSource for ListCallCounter {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.list_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.list(path)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.inner.list_dirents(path)
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.inner.lookup(path, file_version)
    }

    fn versions(&self, path: &str) -> u32 {
        self.inner.versions(path)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(file_info, buffering)
    }

    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }
}

fn zip_counted_base() -> (
    tempfile::TempDir,
    Arc<ListCallCounter>,
    &'static [u8],
    &'static [u8],
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overlay-base.zip");
    let a: &'static [u8] = b"alpha-payload\n";
    let b: &'static [u8] = b"bravo-bytes-here\n";
    write_sample_zip(
        &path,
        &[
            ("a.txt", a, CompressionMethod::Stored),
            ("b.bin", b, CompressionMethod::Stored),
        ],
    );
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..ratarmount_core::OpenOptions::default()
    };
    let zip = ratarmount_formats_zip::ZipMountSource::open(&path, None, &opts, "test", true)
        .expect("open zip");
    let counted = Arc::new(ListCallCounter {
        inner: zip,
        list_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    (dir, counted, a, b)
}

/// Regression: `-w` readdir called `base.list()`.
#[test]
fn overlay_list_dirents_base_plus_overlay_minus_deletes_without_base_list() {
    let (dir, counted, _a, b) = zip_counted_base();
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let ov = WriteOverlay::new_for_tests(Arc::clone(&counted) as Arc<dyn MountSource>, &overlay)
        .expect("overlay");

    ov.unlink("/a.txt").expect("delete base a.txt");
    let fd = ov.create_file("/c.txt", 0o644).expect("overlay create");
    unsafe {
        libc::close(fd);
    }
    fs::write(ov.root().join("c.txt"), b"overlay-only\n").unwrap();

    let dents = ov.list_dirents("/").expect("cheap overlay dirents");
    assert_eq!(
        counted.list_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "WriteOverlay::list_dirents must not call base.list() (fat FileInfo map)"
    );
    let by_name: BTreeMap<_, _> = dents.into_iter().map(|d| (d.name, d.size)).collect();
    assert!(
        !by_name.contains_key("a.txt"),
        "deleted base name must be gone: {by_name:?}"
    );
    assert_eq!(by_name.get("b.bin").copied(), Some(b.len() as u64));
    assert_eq!(
        by_name.get("c.txt").copied(),
        Some(b"overlay-only\n".len() as u64)
    );
    assert!(
        !by_name.keys().any(|n| n.starts_with(HIDDEN_DB)),
        "overlay DB must stay hidden: {by_name:?}"
    );
}

/// Regression: create-then-list reported leftover base size.
#[test]
fn overlay_list_dirents_create_empty_has_size_zero() {
    let (dir, counted, a, _b) = zip_counted_base();
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let ov = WriteOverlay::new_for_tests(Arc::clone(&counted) as Arc<dyn MountSource>, &overlay)
        .expect("overlay");

    assert!(
        !a.is_empty(),
        "base member must have a leftover size to regress against"
    );
    let fd = ov
        .create_file("/a.txt", 0o644)
        .expect("create empty overlay");
    unsafe {
        libc::close(fd);
    }

    let dents = ov.list_dirents("/").expect("cheap overlay dirents");
    assert_eq!(
        counted.list_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "WriteOverlay::list_dirents must not call base.list()"
    );
    let a_dent = dents
        .iter()
        .find(|d| d.name == "a.txt")
        .expect("overlay-created a.txt");
    assert_eq!(
        a_dent.size,
        0,
        "create-then-list must not report leftover base size {}",
        a.len()
    );
}

fn catalog_member_path(m: &ratarmount_index::VisibleMember) -> String {
    if m.path.is_empty() || m.path == "/" {
        format!("/{}", m.name)
    } else {
        format!("{}/{}", m.path, m.name)
    }
}

fn overlay_write_bytes(ov: &WriteOverlay, path: &str, bytes: &[u8]) {
    let fd = ov.create_file(path, 0o644).expect("create");
    {
        use std::os::unix::io::FromRawFd;
        let mut f = unsafe { File::from_raw_fd(fd) };
        f.write_all(bytes).unwrap();
    }
    ov.release_write_fd(fd);
}

/// Documented extract order: catalog flatten, then overlay-only names.
fn concat_catalog_then_overlay(catalog: &[String], overlay: &[String]) -> Vec<String> {
    let mut out = catalog.to_vec();
    out.extend(overlay.iter().cloned());
    out
}

/// Forwards to `inner` except `/gen.txt`, a generated `S_IFREG` (not a flatten payload).
struct WithGeneratedReg {
    inner: Arc<dyn MountSource>,
}

impl MountSource for WithGeneratedReg {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.inner.list(path)
    }
    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        if normpath(path) == "/gen.txt" {
            return Some(FileInfo {
                size: 1,
                mtime: 0.0,
                mode: ratarmount_core::S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                    offset: 0,
                    offsetheader: Some(0),
                    istar: true,
                    issparse: false,
                    isgenerated: true,
                    recursiondepth: 0,
                })],
            });
        }
        self.inner.lookup(path, file_version)
    }
    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(file_info, buffering)
    }
    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }
}

/// Regression: overlay create is visible after catalog flatten members.
/// Catalog flatten stays overlay-free; COW of a catalog path is not overlay-only.
#[test]
fn regression_overlay_only_names_listed_after_catalog_flatten() {
    let dir = tempfile::tempdir().unwrap();
    let z = b"z-payload\n";
    let a = b"a-payload\n";
    let bytes = pack_tar(&[
        ustar_file("z.txt", z),
        ustar_file("a.txt", a),
        ustar_symlink("link.txt", "a.txt"),
    ]);
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..ratarmount_core::OpenOptions::default()
    };
    let tar = SqliteIndexedTar::create_index_from_reader(
        std::io::Cursor::new(bytes),
        Path::new("overlay-extract.tar"),
        None,
        &opts,
        "test",
    )
    .expect("index tar");
    let catalog = tar
        .index()
        .list_visible_files_by_offset()
        .expect("flatten stays overlay-free");
    let catalog_paths: Vec<String> = catalog.iter().map(catalog_member_path).collect();
    assert_eq!(
        catalog_paths,
        vec!["/z.txt".to_string(), "/a.txt".to_string()],
        "offset flatten is archive order, not name order; symlink is not a payload"
    );

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    // Default CLI stack is FileVersionLayer then WriteOverlay; last userdata
    // is `versionlayer:file`, not Tar.
    let stacked = crate::FileVersionLayer::new(Arc::new(WithGeneratedReg {
        inner: Arc::new(tar) as Arc<dyn MountSource>,
    }));
    let ov =
        WriteOverlay::new_for_tests(Arc::new(stacked) as Arc<dyn MountSource>, &overlay).unwrap();
    let z_fi = ov.current_base().lookup("/z.txt", 0).expect("z.txt");
    assert!(
        matches!(z_fi.userdata.last(), Some(UserData::Other(s)) if s == "versionlayer:file"),
        "FileVersionLayer must own last userdata: {:?}",
        z_fi.userdata.last()
    );
    overlay_write_bytes(&ov, "/new.txt", b"overlay-create\n");
    overlay_write_bytes(&ov, "/ov/nested.bin", b"nested-only\n");
    overlay_write_bytes(&ov, "/z.txt", b"cow-replace\n");
    overlay_write_bytes(&ov, "/link.txt", b"was-symlink\n");
    overlay_write_bytes(&ov, "/gen.txt", b"was-generated\n");

    let ov_names = overlay_only_names(&ov);
    assert_eq!(
        ov_names,
        vec![
            "/gen.txt".to_string(),
            "/link.txt".to_string(),
            "/new.txt".to_string(),
            "/ov/nested.bin".to_string()
        ],
        "creates + symlink replace + generated S_IFREG; COW of /z.txt excluded: {ov_names:?}"
    );
    assert!(
        !ov_names.iter().any(|p| p == "/z.txt" || p == "/a.txt"),
        "catalog flatten payloads must not appear in overlay_only_names: {ov_names:?}"
    );
    assert!(
        !catalog_paths
            .iter()
            .any(|p| { p == "/new.txt" || p == "/ov/nested.bin" || p == "/link.txt" }),
        "catalog flatten must stay overlay-free: {catalog_paths:?}"
    );

    assert_eq!(
        concat_catalog_then_overlay(&catalog_paths, &ov_names),
        vec![
            "/z.txt".to_string(),
            "/a.txt".to_string(),
            "/gen.txt".to_string(),
            "/link.txt".to_string(),
            "/new.txt".to_string(),
            "/ov/nested.bin".to_string(),
        ],
        "overlay-only host paths listed last"
    );
    assert!(ov.has_file("/new.txt"));
    assert!(ov.has_file("/ov/nested.bin"));
    assert!(ov.has_file("/link.txt"));
    assert!(ov.has_file("/gen.txt"));
}

/// Regression: restore loop must not SeekFrom::Start to cookie.offset on overlay names.
/// Dummy CompactOpenCookie (offsetheader = -1) would seek the base at garbage.
#[test]
fn regression_overlay_only_restore_does_not_seek_cookie_offset() {
    let dir = tempfile::tempdir().unwrap();
    let z = b"z-payload\n";
    let a = b"a-payload\n";
    let bytes = pack_tar(&[ustar_file("z.txt", z), ustar_file("a.txt", a)]);
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..ratarmount_core::OpenOptions::default()
    };
    let tar = SqliteIndexedTar::create_index_from_reader(
        std::io::Cursor::new(bytes.clone()),
        Path::new("overlay-restore.tar"),
        None,
        &opts,
        "test",
    )
    .expect("index tar");
    let catalog = tar.index().list_visible_files_by_offset().expect("flatten");

    struct StartLog {
        inner: std::io::Cursor<Vec<u8>>,
        starts: Vec<u64>,
    }
    impl Read for StartLog {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }
    impl Seek for StartLog {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            if let SeekFrom::Start(n) = from {
                self.starts.push(n);
            }
            self.inner.seek(from)
        }
    }

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let ov = WriteOverlay::new_for_tests(Arc::new(tar) as Arc<dyn MountSource>, &overlay).unwrap();
    overlay_write_bytes(&ov, "/new.txt", b"overlay-create\n");
    let ov_names = overlay_only_names(&ov);
    assert_eq!(ov_names, vec!["/new.txt".to_string()]);

    let mut reader = StartLog {
        inner: std::io::Cursor::new(bytes),
        starts: Vec::new(),
    };
    for mem in &catalog {
        reader.seek(SeekFrom::Start(mem.cookie.offset)).unwrap();
        let mut buf = vec![0u8; mem.cookie.size as usize];
        reader.read_exact(&mut buf).unwrap();
    }
    let catalog_starts = reader.starts.len();
    assert!(
        catalog_starts >= 2,
        "catalog restore seeks: {:?}",
        reader.starts
    );

    for virt in ov_names {
        assert!(
            ov.has_file(&virt),
            "overlay-only {virt} must open via has_file / overlay fd"
        );
        let fi = ov.lookup(&virt, 0).expect("overlay lookup");
        match fi.userdata.last() {
            Some(UserData::Other(s)) if s.starts_with("overlay:") => {}
            other => {
                panic!("overlay-only must not carry a catalog CompactOpenCookie: {other:?}")
            }
        }
        let mut r = ov.open(&fi, 0).expect("overlay fd");
        let mut body = Vec::new();
        r.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"overlay-create\n");
    }
    assert_eq!(
        reader.starts.len(),
        catalog_starts,
        "overlay names must not SeekFrom::Start cookie.offset, starts={:?}",
        reader.starts
    );
}

fn make_tiny_tar(dir: &Path, members: &[(&str, &[u8])]) -> PathBuf {
    let tree = dir.join("tree");
    fs::create_dir_all(&tree).unwrap();
    for (name, body) in members {
        let p = tree.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, body).unwrap();
    }
    let tar = dir.join("a.tar");
    let mut cmd = StdCommand::new("tar");
    cmd.arg("-cf").arg(&tar).arg("-C").arg(&tree);
    for (name, _) in members {
        cmd.arg(name);
    }
    assert!(cmd.status().unwrap().success());
    tar
}

#[test]
fn overlay_rename_and_symlink_persist() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    let fd = ov.create_file("/src.txt", 0o644).unwrap();
    unsafe {
        libc::close(fd);
    }
    fs::write(overlay.join("src.txt"), b"renamed-bytes\n").unwrap();
    ov.rename("/src.txt", "/dst.txt").expect("rename");
    assert!(ov.lookup("/src.txt", 0).is_none());
    let fi = ov.lookup("/dst.txt", 0).expect("dst");
    assert_eq!(fi.size, b"renamed-bytes\n".len() as u64);

    ov.create_symlink("/link", "dst.txt").expect("symlink");
    let link = ov.lookup("/link", 0).expect("link info");
    assert!(ratarmount_core::is_lnk_mode(link.mode));
    assert_eq!(link.linkname, "dst.txt");
    let dents = ov.list_dirents("/").unwrap();
    let names: Vec<_> = dents.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"dst.txt"), "{names:?}");
    assert!(names.contains(&"link"), "{names:?}");
}

/// Regression: renaming (or COW-ing) a base symlink must materialize a
/// symlink in the overlay — copying its "content" yielded an empty
/// regular file, and a later commit dropped the link member entirely.
#[test]
fn rename_base_symlink_stays_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let base_dir = dir.path().join("base");
    fs::create_dir_all(&base_dir).unwrap();
    fs::write(base_dir.join("target.txt"), b"payload\n").unwrap();
    std::os::unix::fs::symlink("target.txt", base_dir.join("link")).unwrap();

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let base = crate::folder::FolderMountSource::new(&base_dir).unwrap();
    let ov = WriteOverlay::new_for_tests(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();

    ov.rename("/link", "/link2").expect("rename symlink");
    let meta = fs::symlink_metadata(overlay.join("link2")).expect("overlay link2");
    assert!(
        meta.file_type().is_symlink(),
        "rename must COW a symlink as a symlink, got {:?}",
        meta.file_type()
    );
    assert_eq!(
        fs::read_link(overlay.join("link2")).unwrap(),
        std::path::PathBuf::from("target.txt")
    );
    let fi = ov.lookup("/link2", 0).expect("lookup link2");
    assert!(ratarmount_core::is_lnk_mode(fi.mode));
    assert_eq!(fi.linkname, "target.txt");
    assert!(ov.lookup("/link", 0).is_none(), "old name must be gone");
}

/// Regression: rmdir must refuse non-empty union dirs (base children
/// included) and non-directories — committing a bare dir tombstone would
/// recursively delete or orphan the children depending on commit format.
#[test]
fn rmdir_refuses_nonempty_and_non_dir() {
    let dir = tempfile::tempdir().unwrap();
    let base_dir = dir.path().join("base");
    fs::create_dir_all(base_dir.join("full")).unwrap();
    fs::write(base_dir.join("full").join("a.txt"), b"a\n").unwrap();
    fs::create_dir_all(base_dir.join("empty")).unwrap();
    fs::write(base_dir.join("file.txt"), b"f\n").unwrap();

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let base = crate::folder::FolderMountSource::new(&base_dir).unwrap();
    let ov = WriteOverlay::new_for_tests(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();

    let err = ov.rmdir("/full").expect_err("non-empty base dir");
    assert!(
        err.to_string().contains("not empty"),
        "unexpected error: {err}"
    );
    let err = ov.rmdir("/file.txt").expect_err("file is not a dir");
    assert!(
        err.to_string().contains("not a directory"),
        "unexpected error: {err}"
    );
    let err = ov.rmdir("/missing").expect_err("missing path");
    assert!(
        err.to_string().contains("no such directory"),
        "unexpected error: {err}"
    );
    ov.rmdir("/empty").expect("empty dir rmdir");
    assert!(
        ov.lookup("/empty", 0).is_none(),
        "empty dir must be gone from the union view"
    );
    // Children of the refused dir are untouched.
    let fi = ov.lookup("/full/a.txt", 0).expect("child survives");
    assert_eq!(fi.size, 2);
}

/// Regression: rename must not modify the destination when the source
/// COW fails — copy the source first.
#[test]
fn rename_keeps_destination_when_source_cow_fails() {
    struct FailOpenBase;
    impl MountSource for FailOpenBase {
        fn list(&self, _path: &str) -> Option<ListResult> {
            Some(ListResult::Infos(Default::default()))
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(create_root_file_info());
            }
            if path == "/src" {
                return Some(FileInfo {
                    size: 5,
                    mtime: 0.0,
                    mode: ratarmount_core::S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                });
            }
            None
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "boom"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let ov = WriteOverlay::new_for_tests(Arc::new(FailOpenBase) as Arc<dyn MountSource>, &overlay)
        .unwrap();
    let fd = ov.create_file("/dst", 0o644).unwrap();
    unsafe {
        libc::close(fd);
    }
    fs::write(overlay.join("dst"), b"precious\n").unwrap();

    let err = ov.rename("/src", "/dst").expect_err("source COW must fail");
    assert!(
        err.to_string().contains("boom"),
        "expected the COW error, got: {err}"
    );
    assert_eq!(
        fs::read(overlay.join("dst")).unwrap(),
        b"precious\n",
        "destination must survive a failed rename"
    );
    assert!(ov.lookup("/dst", 0).is_some(), "dst still listed");
}

#[test]
fn live_commit_uncompressed_tar_add_replace_delete_no_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let old_payload = dir.path().join("old-expected.bin");
    fs::write(&old_payload, b"old-body\n").unwrap();
    let new_payload = dir.path().join("new-expected.bin");
    fs::write(&new_payload, b"new-body-unique\n").unwrap();
    let replaced_payload = dir.path().join("replaced-expected.bin");
    fs::write(&replaced_payload, b"replaced-body\n").unwrap();

    let tar = make_tiny_tar(
        dir.path(),
        &[
            ("old.txt", &fs::read(&old_payload).unwrap()),
            ("gone.txt", b"delete-me\n"),
            ("keep.txt", b"orig-keep\n"),
        ],
    );
    let _ = replaced_payload;

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..ratarmount_core::OpenOptions::default()
    };
    let mut materialised = None;
    let base = ratarmount_formats_tar::SqliteIndexedTar::create_index(
        &tar,
        &tar,
        None,
        &opts,
        "test",
        &mut materialised,
    )
    .expect("index tar");
    let ov = WriteOverlay::new_for_tests(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();
    fs::write(overlay.join("new.txt"), fs::read(&new_payload).unwrap()).unwrap();
    fs::write(overlay.join("keep.txt"), b"replaced-body\n").unwrap();
    ov.unlink("/gone.txt").expect("mark gone deleted");

    match ov.commit_uncompressed_tar_atomic(&tar) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("commit_uncompressed_tar_atomic: {other:?}"),
    }

    let list = StdCommand::new("tar")
        .args(["-tf"])
        .arg(&tar)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&list.stdout);
    assert!(text.contains("new.txt"), "{text}");
    assert!(text.contains("old.txt"), "{text}");
    assert!(text.contains("keep.txt"), "{text}");
    assert!(
        !text.contains("gone.txt"),
        "deleted member still listed: {text}"
    );
    let new_count = text
        .lines()
        .filter(|l| l.trim_end_matches('/') == "new.txt")
        .count();
    assert_eq!(new_count, 1, "first commit must not duplicate: {text}");

    let extracted = dir.path().join("ex");
    fs::create_dir_all(&extracted).unwrap();
    assert!(StdCommand::new("tar")
        .args(["-xf"])
        .arg(&tar)
        .arg("-C")
        .arg(&extracted)
        .status()
        .unwrap()
        .success());
    assert!(
        fs::read(extracted.join("new.txt")).unwrap() == fs::read(&new_payload).unwrap(),
        "new.txt must cmp to overlay source file"
    );
    assert_eq!(
        fs::read(extracted.join("keep.txt")).unwrap(),
        b"replaced-body\n"
    );

    ov.reset_overlay_contents().expect("reset");
    assert!(!overlay.join("new.txt").exists());
    match ov.commit_uncompressed_tar_atomic(&tar) {
        Ok(false) => {}
        Ok(true) => panic!("second commit with empty overlay must be a no-op"),
        Err(e) => panic!("second commit: {e}"),
    }
    let list2 = StdCommand::new("tar")
        .args(["-tf"])
        .arg(&tar)
        .output()
        .unwrap();
    let text2 = String::from_utf8_lossy(&list2.stdout);
    let new_count2 = text2
        .lines()
        .filter(|l| l.trim_end_matches('/') == "new.txt")
        .count();
    assert_eq!(new_count2, 1, "second tick must not duplicate: {text2}");
}

/// Regression: GNU tar `--delete` without `--ignore-zeros` stops at the
/// first TAR EOF and rewrites only the first complete archive, destroying
/// later concatenated members (symptom: `second.txt` gone after deleting
/// `first.txt` from `cat a.tar b.tar`).
#[test]
fn live_commit_uncompressed_tar_concatenated_delete_keeps_later_archive() {
    let dir = tempfile::tempdir().unwrap();
    let first = generated_payload("live-tar-first");
    let second = generated_payload("live-tar-second");
    let archive = dir.path().join("a.tar");
    let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
    combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
    fs::write(&archive, &combined).unwrap();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_uncompressed_tar_base(&archive, true), &overlay);
    ov.unlink("/first.txt")
        .expect("unlink first complete-TAR member");
    match ov.commit_live(&archive, |p| Ok(open_uncompressed_tar_base(p, true))) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("live commit concatenated delete: {other:?}"),
    }

    let src = open_uncompressed_tar_base(&archive, true);
    assert!(
        src.lookup("/first.txt", 0).is_none(),
        "deleted first-frame name must be gone"
    );
    assert_eq!(
        read_member(src.as_ref(), "/second.txt"),
        second,
        "later complete TAR must survive GNU tar --delete"
    );
}

/// Regression: offline `--commit-overlay` used the same GNU tar `--delete`
/// without `--ignore-zeros`, so a first-frame delete dropped later
/// concatenated archives (and later-frame deletes were "Not found").
#[test]
fn commit_overlay_uncompressed_tar_concatenated_delete_keeps_later_archive() {
    let dir = tempfile::tempdir().unwrap();
    let first = generated_payload("off-tar-first");
    let second = generated_payload("off-tar-second");
    let archive = dir.path().join("a.tar");
    let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
    combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
    fs::write(&archive, &combined).unwrap();
    let before = fs::read(&archive).unwrap();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_uncompressed_tar_base(&archive, true), &overlay);
    ov.unlink("/first.txt")
        .expect("unlink first complete-TAR member");
    drop(ov);

    match commit_overlay(&overlay, &archive, &yes_commit_opts()) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            // #73: offline uncompressed must not mutate the archive when GNU
            // tar `--delete` fails (Debian lseek EOVERFLOW). Soft-skip the
            // member asserts on broken hosts after checking fail-closed.
            assert_eq!(
                fs::read(&archive).unwrap(),
                before,
                "offline uncompressed commit must leave archive unchanged on GNU tar delete failure"
            );
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("offline concatenated delete: {other:?}"),
    }

    let src = open_uncompressed_tar_base(&archive, true);
    assert!(
        src.lookup("/first.txt", 0).is_none(),
        "deleted first-frame name must be gone"
    );
    assert_eq!(
        read_member(src.as_ref(), "/second.txt"),
        second,
        "later complete TAR must survive offline GNU tar --delete"
    );
}

/// Regression: later-frame delete on a concatenated uncompressed TAR must
/// apply (GNU tar without `--ignore-zeros` reported "Not found in archive",
/// which persist filtered as success, and the member stayed on disk).
#[test]
fn commit_overlay_uncompressed_tar_concatenated_later_frame_delete() {
    let dir = tempfile::tempdir().unwrap();
    let first = generated_payload("off-tar-later-first");
    let second = generated_payload("off-tar-later-second");
    let archive = dir.path().join("a.tar");
    let mut combined = pack_tar(&[ustar_file("first.txt", &first)]);
    combined.extend(pack_tar(&[ustar_file("second.txt", &second)]));
    fs::write(&archive, &combined).unwrap();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_uncompressed_tar_base(&archive, true), &overlay);
    ov.unlink("/second.txt")
        .expect("unlink later complete-TAR member");
    drop(ov);

    match commit_overlay(&overlay, &archive, &yes_commit_opts()) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("offline later-frame delete: {other:?}"),
    }

    let src = open_uncompressed_tar_base(&archive, true);
    assert!(
        src.lookup("/second.txt", 0).is_none(),
        "later-frame name must be gone after offline commit"
    );
    assert_eq!(read_member(src.as_ref(), "/first.txt"), first);
}

/// Regression: `BzDecoder` (not multi) dropped later bzip2 streams
/// during `--commit-overlay` materialize. Symptom: `second.txt` gone
/// after deleting `first.txt` from `cat a.tar.bz2 b.tar.bz2`.
#[test]
fn commit_overlay_tar_bz2_concatenated_delete_keeps_later_archive() {
    let dir = tempfile::tempdir().unwrap();
    let first = generated_payload("off-bz2-del-first");
    let second = generated_payload("off-bz2-del-second");
    let archive = dir.path().join("a.tar.bz2");
    write_concatenated_tar_bz2(
        &archive,
        &[ustar_file("first.txt", &first)],
        &[ustar_file("second.txt", &second)],
    );

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_bz2_base(&archive, true), &overlay);
    ov.unlink("/first.txt")
        .expect("unlink first complete-TAR member");
    drop(ov);

    match commit_overlay(&overlay, &archive, &yes_commit_opts()) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("offline concatenated tar.bz2 delete: {other:?}"),
    }

    let src = open_tar_bz2_base(&archive, true);
    assert!(
        src.lookup("/first.txt", 0).is_none(),
        "deleted first-stream name must be gone"
    );
    assert_eq!(
        read_member(src.as_ref(), "/second.txt"),
        second,
        "later bzip2 stream must survive offline GNU tar --delete"
    );
}

/// Regression: `XzDecoder::new` (not multi) dropped later xz streams
/// during `--commit-overlay` materialize. Symptom: `second.txt` gone
/// after deleting `first.txt` from `cat a.tar.xz b.tar.xz`.
#[test]
fn commit_overlay_tar_xz_concatenated_delete_keeps_later_archive() {
    let dir = tempfile::tempdir().unwrap();
    let first = generated_payload("off-xz-del-first");
    let second = generated_payload("off-xz-del-second");
    let archive = dir.path().join("a.tar.xz");
    write_concatenated_tar_xz(
        &archive,
        &[ustar_file("first.txt", &first)],
        &[ustar_file("second.txt", &second)],
    );

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_xz_base(&archive, true), &overlay);
    ov.unlink("/first.txt")
        .expect("unlink first complete-TAR member");
    drop(ov);

    match commit_overlay(&overlay, &archive, &yes_commit_opts()) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("offline concatenated tar.xz delete: {other:?}"),
    }

    let src = open_tar_xz_base(&archive, true);
    assert!(
        src.lookup("/first.txt", 0).is_none(),
        "deleted first-stream name must be gone"
    );
    assert_eq!(
        read_member(src.as_ref(), "/second.txt"),
        second,
        "later xz stream must survive offline GNU tar --delete"
    );
}

/// Base that lists `gone.txt` but strips TAR userdata (AutoMount nested
/// archive, foreign sidecar, or any wrapper that hides `offsetheader`).
struct NoTarOffsetheaderBase;

impl MountSource for NoTarOffsetheaderBase {
    fn list(&self, _path: &str) -> Option<ListResult> {
        Some(ListResult::Infos(Default::default()))
    }
    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        if path == "/" {
            return Some(create_root_file_info());
        }
        if path == "/gone.txt" || path == "gone.txt" {
            return Some(FileInfo {
                size: 9,
                mtime: 0.0,
                mode: ratarmount_core::S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            });
        }
        None
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "no-tar-oh base"))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

struct TarOffsetheaderBase {
    gone_oh: u64,
}

impl MountSource for TarOffsetheaderBase {
    fn list(&self, _path: &str) -> Option<ListResult> {
        Some(ListResult::Infos(Default::default()))
    }
    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        if path == "/" {
            return Some(create_root_file_info());
        }
        if path == "/gone.txt" || path == "gone.txt" {
            return Some(tar_fi_at(self.gone_oh));
        }
        None
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "tar-oh base"))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

fn two_member_tar(dir: &Path) -> (PathBuf, u64, u64) {
    let keep = b"keep-body";
    let gone = b"gone-body";
    let bytes = pack_tar(&[ustar_file("keep.txt", keep), ustar_file("gone.txt", gone)]);
    let archive = dir.join("a.tar");
    fs::write(&archive, &bytes).unwrap();
    let eof = {
        let mut f = File::open(&archive).unwrap();
        find_last_tar_eof(&mut f, 0).unwrap().unwrap_or(0)
    };
    let gone_oh = 512 + pad512_for_test(keep.len() as u64);
    (archive, eof, gone_oh)
}

fn pad512_for_test(n: u64) -> u64 {
    n.div_ceil(512) * 512
}

/// Regression: unclassified delete + append must not patch from EOF only.
///
/// Symptom: AutoMount (or any wrapper that hides TAR userdata) made
/// `min_deleted_offsetheader` skip a real archive delete; the append
/// branch then set `window_start = EOF`. GNU tar `--delete` still
/// removed the member, so the sidecar kept a ghost row.
#[test]
fn regression_unclassified_delete_plus_append_does_not_patch_from_eof() {
    let dir = tempfile::tempdir().unwrap();
    let (archive, eof, gone_oh) = two_member_tar(dir.path());
    assert!(gone_oh > 0 && gone_oh < eof, "gone_oh={gone_oh} eof={eof}");

    let plan = OverlayCommitPlan {
        known_hashes: BTreeMap::new(),
        written_hashes: BTreeMap::new(),
        metadata: BTreeMap::new(),
        xattrs: BTreeMap::new(),
        deletions_nul: Vec::new(),
        appends_nul: Vec::new(),
        deleted_paths: ["gone.txt".into()].into_iter().collect(),
        append_entries: vec![("new.txt".into(), false)],
    };
    let window =
        uncompressed_patch_window(&archive, &NoTarOffsetheaderBase, &plan).expect("window");
    assert!(
        window.offsets_shifted,
        "unclassified archive delete must force a suffix rewrite"
    );
    assert_eq!(
        window.window_start, 0,
        "must full-reparse, not EOF {eof} (gone lived at {gone_oh})"
    );
    assert_ne!(
        window.window_start, eof,
        "EOF-only patch would leave gone.txt in the sidecar"
    );
}

#[test]
fn classified_delete_plus_append_still_starts_at_min_offsetheader() {
    let dir = tempfile::tempdir().unwrap();
    let (archive, eof, gone_oh) = two_member_tar(dir.path());
    let plan = OverlayCommitPlan {
        known_hashes: BTreeMap::new(),
        written_hashes: BTreeMap::new(),
        metadata: BTreeMap::new(),
        xattrs: BTreeMap::new(),
        deletions_nul: Vec::new(),
        appends_nul: Vec::new(),
        deleted_paths: ["gone.txt".into()].into_iter().collect(),
        append_entries: vec![("new.txt".into(), false)],
    };
    let window = uncompressed_patch_window(&archive, &TarOffsetheaderBase { gone_oh }, &plan)
        .expect("window");
    assert!(window.offsets_shifted);
    assert_eq!(window.window_start, gone_oh);
    assert_ne!(window.window_start, eof);
    assert_ne!(window.window_start, 0);
}

#[test]
fn overlay_only_replace_plus_append_still_starts_at_eof() {
    let dir = tempfile::tempdir().unwrap();
    let (archive, eof, _) = two_member_tar(dir.path());
    let plan = OverlayCommitPlan {
        known_hashes: BTreeMap::new(),
        written_hashes: BTreeMap::new(),
        metadata: BTreeMap::new(),
        xattrs: BTreeMap::new(),
        deletions_nul: Vec::new(),
        appends_nul: Vec::new(),
        deleted_paths: ["brand-new.txt".into()].into_iter().collect(),
        append_entries: vec![("brand-new.txt".into(), false)],
    };
    let window =
        uncompressed_patch_window(&archive, &NoTarOffsetheaderBase, &plan).expect("window");
    assert!(!window.offsets_shifted);
    assert_eq!(
        window.window_start, eof,
        "overlay-only add must still patch from pre-append EOF"
    );
}

/// Regression: GNU `tar --append` patch window is `find_last_tar_eof`, not
/// `metadata().len()` (EOF padding would skip the new members).
#[test]
fn live_commit_gnu_append_window_is_eof_not_len() {
    let dir = tempfile::tempdir().unwrap();
    let tar = make_tiny_tar(dir.path(), &[("old.txt", b"keep\n")]);
    let file_len = fs::metadata(&tar).unwrap().len();
    let eof = {
        let mut f = File::open(&tar).unwrap();
        find_last_tar_eof(&mut f, 0).unwrap().unwrap_or(0)
    };
    assert!(
        eof < file_len,
        "GNU tar pads past the two-zero EOF: eof={eof} len={file_len}"
    );

    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..ratarmount_core::OpenOptions::default()
    };
    let mut materialised = None;
    let base = ratarmount_formats_tar::SqliteIndexedTar::create_index(
        &tar,
        &tar,
        None,
        &opts,
        "test",
        &mut materialised,
    )
    .expect("index tar");
    let ov = WriteOverlay::new_for_tests(Arc::new(base) as Arc<dyn MountSource>, &overlay).unwrap();
    fs::write(overlay.join("new.txt"), b"appended\n").unwrap();
    match ov.commit_atomic(&tar) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("commit_atomic: {other:?}"),
    }
    let window = ov.last_patch_window().expect("stashed window");
    assert_eq!(
        window.window_start, eof,
        "window_start must be last TAR EOF, not file len {file_len}"
    );
    assert!(!window.offsets_shifted);
    assert!(window.from_frame.is_none());
}

#[test]
fn live_commit_rejects_gzip_and_zip() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("t");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a"), b"x").unwrap();
    let tgz = dir.path().join("a.tar.gz");
    let st = StdCommand::new("tar")
        .args(["-czf"])
        .arg(&tgz)
        .arg("-C")
        .arg(&src)
        .arg("a")
        .status()
        .unwrap();
    assert!(st.success());
    let err = live_commit_is_supported(&tgz).unwrap_err().to_string();
    assert!(err.contains("uncompressed"), "{err}");
    assert!(err.contains("gzip"), "{err}");

    let zip = dir.path().join("a.zip");
    write_sample_zip(&zip, &[("a", b"x", CompressionMethod::Stored)]);
    let err = live_commit_is_supported(&zip).unwrap_err().to_string();
    assert!(
        err.contains("ZIP") || err.contains("uncompressed TAR"),
        "{err}"
    );
}

pub(crate) fn generated_payload(tag: &str) -> Vec<u8> {
    format!("p-{tag}-{}\n", std::process::id()).into_bytes()
}

/// Regression: add-only xattrs must use append and manifests must retain
/// pre-patch index hashes while hashing newly committed payloads.
#[test]
fn regression_provenance_append_manifest_reuses_index_hash() {
    for compressed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(if compressed {
            "base.tar.zst"
        } else {
            "base.tar"
        });
        let (prefix, _) = append_fixture(&archive, compressed);
        let sidecar = append_index(&archive, compressed);
        let expected = ratarmount_index::sha256_hex_stream(&mut &prefix[..]).unwrap();
        {
            let idx = SqliteIndex::open_writable(&sidecar).unwrap();
            let fi = idx.lookup("/prefix", 0).unwrap().unwrap();
            idx.insert_xattr(
                tar_offsetheaders_in(&fi).next().unwrap() as i64,
                "user.hash.sha256",
                expected.as_bytes(),
            )
            .unwrap();
        }
        let root = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        let fd = ov.create_file("/new", 0o644).unwrap();
        ov.close_overlay_fd(fd);
        fs::write(root.join("new"), b"new payload").unwrap();
        ov.set_xattr("/new", "user.teacher", b"teacher", 0).unwrap();
        drop(ov);
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(&archive).unwrap().ino()
        };
        let opts = CommitOverlayOptions {
            yes: true,
            debug: 0,
            mode: CommitMode::Append,
            manifest_hashes: Some("new".into()),
            ..Default::default()
        };
        assert!(commit_overlay(&root, &archive, &opts).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(&archive).unwrap().ino(), inode);
        }
        let manifest = fs::read_to_string(format!("{}.manifest.jsonl", archive.display())).unwrap();
        let rows: BTreeMap<String, serde_json::Value> = manifest
            .lines()
            .map(|line| {
                let row: serde_json::Value = serde_json::from_str(line).unwrap();
                (row["path"].as_str().unwrap().into(), row)
            })
            .collect();
        assert_eq!(rows["prefix"]["sha256"], expected);
        assert_eq!(
            rows["new"]["sha256"],
            ratarmount_index::sha256_hex_stream(&mut &b"new payload"[..]).unwrap()
        );
        assert!(rows["last"]["sha256"].is_null());
        let base = append_warm_open(&archive, compressed, &sidecar);
        let fi = base.lookup("/new", 0).unwrap();
        assert_eq!(
            base.get_xattr(&fi, "user.teacher"),
            Some(b"teacher".to_vec())
        );
    }
}

/// Regression: offline manifest commits rejected overlays below symlinked parents (/var on macOS).
#[cfg(unix)]
#[test]
fn regression_provenance_manifest_symlinked_overlay_parent() {
    for compressed in [false, true] {
        for mode in [CommitMode::Copy, CommitMode::Append] {
            for xattrs in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let real = dir.path().join("real");
                fs::create_dir(&real).unwrap();
                let alias = dir.path().join("alias");
                std::os::unix::fs::symlink(&real, &alias).unwrap();
                let archive = dir.path().join(if compressed {
                    "base.tar.zst"
                } else {
                    "base.tar"
                });
                append_fixture(&archive, compressed);
                let root = alias.join("ov");
                let ov = WriteOverlay::new_for_tests(
                    Arc::new(provenance_base(&archive, "utf-8").unwrap()),
                    &root,
                )
                .unwrap();
                assert_eq!(ov.root, real.join("ov").canonicalize().unwrap());
                put_overlay_bytes(&ov, "/new", b"new payload");
                if xattrs {
                    ov.set_xattr("/new", "user.teacher", b"teacher", 0).unwrap();
                }
                drop(ov);
                assert!(commit_overlay(
                    &root,
                    &archive,
                    &CommitOverlayOptions {
                        yes: true,
                        mode,
                        manifest_hashes: Some("new".into()),
                        ..Default::default()
                    }
                )
                .unwrap());
                let base = provenance_base(&archive, "utf-8").unwrap();
                let fi = base.lookup("/new", 0).unwrap();
                assert_eq!(base.read(&fi, 100, 0).unwrap(), b"new payload");
                assert_eq!(
                    base.get_xattr(&fi, "user.teacher"),
                    xattrs.then(|| b"teacher".to_vec())
                );
                let manifest =
                    fs::read_to_string(format!("{}.manifest.jsonl", archive.display())).unwrap();
                assert!(manifest.contains(
                    &ratarmount_index::sha256_hex_stream(&mut &b"new payload"[..]).unwrap()
                ));
            }
        }
    }
}

/// Regression: queued renames must carry provenance through intermediate names
/// even while the host rename has completed and SQLite replay still fails.
#[test]
fn regression_provenance_queued_rename_keeps_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    provenance_fixture(&archive, false);
    let ov = WriteOverlay::new_for_tests(
        Arc::new(provenance_base(&archive, "utf-8").unwrap()),
        dir.path().join("ov"),
    )
    .unwrap();
    ov.set_xattr("/trace", "user.train_ok", b"false", 0)
        .unwrap();
    ov.set_rename_tx_failures(100);
    ov.rename("/trace", "/x").unwrap();
    assert_eq!(ov.xattrs_for_path("/x").unwrap()["user.train_ok"], b"false");
    ov.rename("/x", "/y").unwrap();
    assert_eq!(ov.xattrs_for_path("/y").unwrap()["user.teacher"], b"old");
    ov.set_rename_tx_failures(0);
    ov.replay_pending_rows().unwrap();
    assert_eq!(ov.xattrs_for_path("/y").unwrap()["user.train_ok"], b"false");
    assert!(ov.lookup("/x", 0).is_none());
}

/// Regression: manifest-only commits must hash payloads in the shared writer
/// even when there are no xattrs to trigger the provenance replacement path.
#[test]
fn regression_provenance_manifest_without_xattrs() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    fs::write(&archive, pack_tar(&[ustar_file("old", b"old")])).unwrap();
    let root = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(provenance_base(&archive, "utf-8").unwrap()), &root)
            .unwrap();
    put_overlay_bytes(&ov, "/new", b"new payload");
    drop(ov);
    let mut plan = collect_overlay_commit_plan(&root).unwrap();
    assert!(!plan.has_metadata_changes());
    let mut hashes = BTreeMap::new();
    persist_provenance_plan(
        &archive,
        &root,
        &plan,
        "utf-8",
        CommitMode::Copy,
        Some(&mut hashes),
        &crate::journal_recovery::Rows::None,
        &fs::metadata(&archive).unwrap(),
        &mut || Ok(()),
    )
    .unwrap();
    let expected = ratarmount_index::sha256_hex_stream(&mut &b"new payload"[..]).unwrap();
    assert_eq!(hashes.get("/new"), Some(&expected));
    plan.written_hashes = hashes;
    write_commit_manifest(&archive, &plan, "utf-8", "new").unwrap();
    let manifest = fs::read_to_string(format!("{}.manifest.jsonl", archive.display())).unwrap();
    assert!(manifest.contains(&expected));
    let reopened =
        WriteOverlay::new_for_tests(Arc::new(provenance_base(&archive, "utf-8").unwrap()), &root)
            .unwrap();
    reopened.set_xattr("/new", "user.empty", b"", 1).unwrap();
    assert_eq!(reopened.xattrs_for_path("/new").unwrap()["user.empty"], b"");
}

fn provenance_fixture(path: &Path, compressed: bool) {
    let attrs = vec![
        ("user.teacher".into(), b"old".to_vec()),
        ("user.binary".into(), vec![0xff, 0, b'\n', b'=']),
    ];
    let mut member = ustar_file("trace", b"training payload");
    member.xattrs = &attrs;
    if compressed {
        write_single_frame_tar_zst(path, &[member]);
    } else {
        fs::write(path, pack_tar(&[member])).unwrap();
    }
}

/// Regression: chmod/utimens must not copy archive bytes, and mode/mtime
/// must survive reopen and TAR commit for both archive and overlay files.
#[test]
fn regression_overlay_chmod_metadata_only_reopen_commit() {
    for compressed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(if compressed {
            "base.tar.zst"
        } else {
            "base.tar"
        });
        provenance_fixture(&archive, compressed);
        let root = dir.path().join("overlay");
        let base = Arc::new(provenance_base(&archive, "utf-8").unwrap());
        let ov = WriteOverlay::new_for_tests(base.clone(), &root).unwrap();
        let fd = ov.create_file("/built", 0o600).unwrap();
        ov.close_overlay_fd(fd);
        let attrs = OverlayMetadata {
            mode: Some(0o751),
            atime: Some(1234.25),
            mtime: Some(5678.5),
            ..Default::default()
        };
        for path in ["/trace", "/built"] {
            ov.set_metadata(path, &attrs).unwrap();
            let fi = ov.lookup(path, 0).unwrap();
            assert_eq!(fi.mode & 0o7777, 0o751);
            assert_eq!(fi.mtime, 5678.5);
            assert_eq!(overlay_atime(&fi), 1234.25);
        }
        assert!(!root.join("trace").exists(), "chmod copied archive payload");
        assert_eq!(read_member(&ov, "/trace"), b"training payload");
        let modes: Vec<_> = ov
            .list_dirents("/")
            .unwrap()
            .into_iter()
            .map(|d| d.mode & 0o7777)
            .collect();
        assert_eq!(modes, [0o751, 0o751]);
        drop(ov);
        let ov = WriteOverlay::new_for_tests(base, &root).unwrap();
        assert_eq!(ov.lookup("/trace", 0).unwrap().mode & 0o7777, 0o751);
        assert_eq!(overlay_atime(&ov.lookup("/trace", 0).unwrap()), 1234.25);
        // Omitted timestamps are unchanged by a later chmod.
        ov.set_metadata(
            "/trace",
            &OverlayMetadata {
                mode: Some(0o755),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(ov.lookup("/trace", 0).unwrap().mtime, 5678.5);
        assert!(ov
            .commit_live(&archive, |p| Ok(Arc::new(provenance_base(p, "utf-8")?)))
            .unwrap());
        assert!(ov.metadata_for_path("/trace").is_none());
        let committed = provenance_base(&archive, "utf-8").unwrap();
        assert_eq!(committed.lookup("/trace", 0).unwrap().mode & 0o7777, 0o755);
        assert_eq!(committed.lookup("/built", 0).unwrap().mode & 0o7777, 0o751);
        assert_eq!(committed.lookup("/trace", 0).unwrap().mtime, 5678.0);
        assert_eq!(read_member(&committed, "/trace"), b"training payload");
    }
}

/// Regression: a nested archive-only chmod must not require materialized
/// parent directories; creation modes must not be masked by the daemon.
#[test]
fn regression_overlay_chmod_nested_and_create_modes() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    fs::write(&archive, pack_tar(&[ustar_file("sub/script", b"payload")])).unwrap();
    let root = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(provenance_base(&archive, "utf-8").unwrap()), &root)
            .unwrap();
    ov.set_metadata(
        "/sub/script",
        &OverlayMetadata {
            mode: Some(0o755),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!root.join("sub").exists());
    assert_eq!(read_member(&ov, "/sub/script"), b"payload");
    ov.set_metadata(
        "/",
        &OverlayMetadata {
            mode: Some(0o751),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(ov.lookup("/", 0).unwrap().mode & 0o7777, 0o751);
    let fd = ov
        .open_overlay_fd_with_mode("/built", libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o777)
        .unwrap();
    ov.close_overlay_fd(fd);
    assert_eq!(ov.lookup("/built", 0).unwrap().mode & 0o7777, 0o777);
    assert!(ov
        .open_overlay_fd_with_mode("/built", libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600)
        .is_err());
    ov.mkdir("/dir", 0o777).unwrap();
    let fd = ov.create_file("/dir/child", 0o751).unwrap();
    ov.close_overlay_fd(fd);
    ov.set_metadata(
        "/dir",
        &OverlayMetadata {
            mode: Some(0o750),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(ov
        .commit_live(&archive, |p| Ok(Arc::new(provenance_base(p, "utf-8")?)))
        .unwrap());
    assert_eq!(ov.lookup("/sub/script", 0).unwrap().mode & 0o7777, 0o755);
    assert_eq!(ov.lookup("/dir", 0).unwrap().mode & 0o7777, 0o750);
}

/// Regression: a combined truncate/touch must keep the requested mtime;
/// failed chown must not truncate and chmod must never follow a host symlink.
#[test]
fn regression_overlay_chmod_setattr_order_and_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    fs::write(
        &archive,
        pack_tar(&[
            ustar_file("trace", b"training payload"),
            ustar_symlink("archive-link", "trace"),
        ]),
    )
    .unwrap();
    let root = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(provenance_base(&archive, "utf-8").unwrap()), &root)
            .unwrap();
    ov.set_metadata(
        "/archive-link",
        &OverlayMetadata {
            mtime: Some(1234.5),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!root.join("archive-link").exists());
    ov.rename("/archive-link", "/moved-link").unwrap();
    assert_eq!(ov.lookup("/moved-link", 0).unwrap().mtime, 1234.5);
    assert!(ov
        .set_attributes(
            "/trace",
            Some(0),
            &OverlayMetadata {
                uid: Some(123),
                ..Default::default()
            }
        )
        .is_err());
    assert_eq!(ov.lookup("/trace", 0).unwrap().size, 16);
    ov.set_attributes(
        "/trace",
        Some(3),
        &OverlayMetadata {
            mode: Some(0o755),
            mtime: Some(42.5),
            ..Default::default()
        },
    )
    .unwrap();
    let fi = ov.lookup("/trace", 0).unwrap();
    assert_eq!(fi.size, 3);
    assert_eq!(fi.mtime, 42.5);
    assert_eq!(fi.mode & 0o7777, 0o755);
    ov.create_symlink("/link", "trace").unwrap();
    assert!(ov
        .set_metadata(
            "/link",
            &OverlayMetadata {
                mode: Some(0o600),
                ..Default::default()
            }
        )
        .is_err());
    assert_eq!(ov.lookup("/trace", 0).unwrap().mode & 0o7777, 0o755);
}

/// Regression: metadata-only chmod is included in offline commit plans.
#[test]
fn regression_overlay_chmod_offline_commit() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    provenance_fixture(&archive, false);
    let root = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(provenance_base(&archive, "utf-8").unwrap()), &root)
            .unwrap();
    ov.set_metadata(
        "/trace",
        &OverlayMetadata {
            mode: Some(0o755),
            ..Default::default()
        },
    )
    .unwrap();
    drop(ov);
    assert!(commit_overlay(
        &root,
        &archive,
        &CommitOverlayOptions {
            yes: true,
            ..Default::default()
        }
    )
    .unwrap());
    assert_eq!(
        provenance_base(&archive, "utf-8")
            .unwrap()
            .lookup("/trace", 0)
            .unwrap()
            .mode
            & 0o7777,
        0o755
    );
}

/// Regression: COW, rename and recreation must preserve or discard the
/// correct inode's mode rather than resurrect metadata from an old name.
#[test]
fn regression_overlay_chmod_copy_up_rename_recreate() {
    for policy in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        provenance_fixture(&archive, false);
        let root = dir.path().join("ov");
        let mut ov = WriteOverlay::new_for_tests(
            Arc::new(provenance_base(&archive, "utf-8").unwrap()),
            &root,
        )
        .unwrap();
        if policy {
            ov.set_policy(Some(Arc::new(CountingPolicy::new(u64::MAX))));
        }
        ov.set_metadata(
            "/trace",
            &OverlayMetadata {
                mode: Some(0o751),
                mtime: Some(1234.0),
                ..Default::default()
            },
        )
        .unwrap();
        let fd = ov.open_overlay_fd("/trace", libc::O_RDWR).unwrap();
        ov.close_overlay_fd(fd);
        assert_eq!(ov.lookup("/trace", 0).unwrap().mode & 0o7777, 0o751);
        assert_eq!(ov.lookup("/trace", 0).unwrap().mtime, 1234.0);
        let fd = ov.create_file("/moved", 0o600).unwrap();
        ov.close_overlay_fd(fd);
        ov.rename("/trace", "/moved").unwrap();
        let mode: u32 = ov
            .db
            .lock()
            .unwrap()
            .query_row("SELECT mode FROM files WHERE name='moved'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(mode & 0o7777, 0o751);
        assert_eq!(ov.lookup("/moved", 0).unwrap().mode & 0o7777, 0o751);
        ov.unlink("/moved").unwrap();
        let fd = ov.create_file("/moved", 0o640).unwrap();
        ov.close_overlay_fd(fd);
        assert_eq!(ov.lookup("/moved", 0).unwrap().mode & 0o7777, 0o640);
        assert!(ov.metadata_for_path("/moved").is_none());
    }
}

/// Regression: chmod and utimens must obey read-only globs; chown and
/// invalid times fail explicitly instead of reporting a successful no-op.
#[test]
fn regression_overlay_chmod_readonly_and_chown() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    provenance_fixture(&archive, false);
    let mut ov = WriteOverlay::new_for_tests(
        Arc::new(provenance_base(&archive, "utf-8").unwrap()),
        dir.path().join("ov"),
    )
    .unwrap();
    let fd = ov.create_file("/host", 0o644).unwrap();
    ov.close_overlay_fd(fd);
    let err = ov
        .set_metadata(
            "/host",
            &OverlayMetadata {
                uid: Some(123),
                mode: Some(0o777),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, OverlayError::Io(e) if e.raw_os_error() == Some(libc::EPERM)));
    assert_eq!(ov.lookup("/host", 0).unwrap().mode & 0o7777, 0o644);
    assert!(ov
        .set_metadata(
            "/host",
            &OverlayMetadata {
                mtime: Some(f64::NAN),
                ..Default::default()
            }
        )
        .is_err());
    ov.set_policy(Some(Arc::new(
        crate::overlay_policy::ReadOnlyGlobs::new(["trace", "host"]).unwrap(),
    )));
    for path in ["/trace", "/host"] {
        for attrs in [
            OverlayMetadata {
                mode: Some(0o755),
                ..Default::default()
            },
            OverlayMetadata {
                mtime: Some(10.0),
                ..Default::default()
            },
        ] {
            let err = ov.set_metadata(path, &attrs).unwrap_err();
            assert!(
                matches!(err, OverlayError::Io(e) if e.kind() == io::ErrorKind::ReadOnlyFilesystem)
            );
        }
    }
}

/// Regression: xattr-only edits must not copy archive payloads, lose binary
/// values, ignore create/replace flags, or bypass read-only policy.
#[test]
fn regression_provenance_metadata_only_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    provenance_fixture(&archive, false);
    let base = Arc::new(provenance_base(&archive, "utf-8").unwrap());
    let mut ov = WriteOverlay::new_for_tests(base, dir.path().join("ov")).unwrap();
    let error = |r: Result<()>| match r.unwrap_err() {
        OverlayError::Io(e) => e.raw_os_error().unwrap_or_else(|| {
            assert_eq!(e.kind(), io::ErrorKind::ReadOnlyFilesystem);
            libc::EROFS
        }),
        e => panic!("{e}"),
    };
    assert_eq!(
        error(ov.set_xattr("/trace", "user.teacher", b"x", 1)),
        libc::EEXIST
    );
    assert_eq!(
        error(ov.set_xattr("/trace", "user.absent", b"x", 2)),
        missing_xattr_errno()
    );
    assert_eq!(
        error(ov.set_xattr("/trace", "security.label", b"x", 0)),
        libc::EPERM
    );
    assert_eq!(
        error(ov.set_xattr("/trace", "user.x", b"x", 3)),
        libc::EINVAL
    );
    assert_eq!(
        error(ov.set_xattr("/trace", "user.x", &vec![0; 65537], 0)),
        libc::E2BIG
    );
    ov.set_xattr("/trace", "user.teacher", b"new", 2).unwrap();
    ov.set_xattr("/trace", "user.train_ok", b"false", 1)
        .unwrap();
    ov.remove_xattr("/trace", "user.binary").unwrap();
    assert_eq!(
        error(ov.remove_xattr("/trace", "user.binary")),
        missing_xattr_errno()
    );
    let fi = ov.lookup("/trace", 0).unwrap();
    assert_eq!(ov.get_xattr(&fi, "user.teacher"), Some(b"new".to_vec()));
    assert_eq!(ov.list_xattr(&fi), ["user.teacher", "user.train_ok"]);
    assert_eq!(read_member(&ov, "/trace"), b"training payload");
    assert!(!ov.has_file("/trace"));
    for name in ["a", "b", "c"] {
        ov.set_xattr("/trace", &format!("user.{name}"), &vec![0; 65536], 0)
            .unwrap();
    }
    assert_eq!(
        error(ov.set_xattr("/trace", "user.d", &vec![0; 65536], 0)),
        libc::E2BIG
    );
    ov.set_policy(Some(Arc::new(
        crate::ReadOnlyGlobs::new(["trace"]).unwrap(),
    )));
    assert_eq!(
        error(ov.set_xattr("/trace", "user.teacher", b"blocked", 0)),
        libc::EROFS
    );
    assert_eq!(
        error(ov.remove_xattr("/trace", "user.teacher")),
        libc::EROFS
    );
}

/// Regression: opening a legacy overlay adds xattrs without losing deletion rows.
#[test]
fn regression_provenance_migration_preserves_tombstones() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    provenance_fixture(&archive, false);
    let root = dir.path().join("ov");
    let base = Arc::new(provenance_base(&archive, "utf-8").unwrap());
    {
        let ov = WriteOverlay::new_for_tests(base.clone(), &root).unwrap();
        ov.unlink("/trace").unwrap();
    }
    {
        let db = Connection::open(root.join(HIDDEN_DB)).unwrap();
        db.execute("DROP TABLE xattrs", []).unwrap();
    }
    let ov = WriteOverlay::new_for_tests(base, &root).unwrap();
    assert!(ov.lookup("/trace", 0).is_none());
    assert!(root.join(OVERLAY_MARKER).exists());
    let fd = ov.create_file("/new", 0o644).unwrap();
    ov.close_overlay_fd(fd);
    ov.set_xattr("/new", "user.test", b"yes", 0).unwrap();
    drop(ov);
    let ov =
        WriteOverlay::new_for_tests(Arc::new(provenance_base(&archive, "utf-8").unwrap()), &root)
            .unwrap();
    assert_eq!(ov.xattrs_for_path("/new").unwrap()["user.test"], b"yes");
    assert!(ov.is_deleted("/trace"));
}

/// Regression: metadata-only replacement must survive copy/append-fallback,
/// suffix reindex, remount, and binary PAX decoding for TAR and tar.zst.
#[test]
fn regression_provenance_commit_roundtrip_and_manifest() {
    for compressed in [false, true] {
        for mode in [CommitMode::Copy, CommitMode::Append] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join(if compressed {
                "base.tar.zst"
            } else {
                "base.tar"
            });
            provenance_fixture(&archive, compressed);
            let sidecar = append_index(&archive, compressed);
            let root = dir.path().join("ov");
            let ov = WriteOverlay::new_for_tests(
                Arc::new(provenance_base(&archive, "utf-8").unwrap()),
                &root,
            )
            .unwrap();
            ov.set_xattr("/trace", "user.train_ok", b"false", 0)
                .unwrap();
            ov.remove_xattr("/trace", "user.teacher").unwrap();
            assert!(!root.join("trace").exists());
            drop(ov);
            let opts = CommitOverlayOptions {
                mode,
                yes: true,
                debug: 0,
                manifest_hashes: Some("all".into()),
                ..Default::default()
            };
            assert!(commit_overlay(&root, &archive, &opts).unwrap());
            let base = append_warm_open(&archive, compressed, &sidecar);
            let fi = base.lookup("/trace", 0).unwrap();
            assert_eq!(
                base.get_xattr(&fi, "user.train_ok"),
                Some(b"false".to_vec())
            );
            assert_eq!(
                base.get_xattr(&fi, "user.binary"),
                Some(vec![0xff, 0, b'\n', b'='])
            );
            assert_eq!(base.get_xattr(&fi, "user.teacher"), None);
            assert_eq!(read_member(base.as_ref(), "/trace"), b"training payload");
            let manifest = PathBuf::from(format!("{}.manifest.jsonl", archive.display()));
            let rows: Vec<serde_json::Value> = fs::read_to_string(&manifest)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["path"], "trace");
            assert_eq!(rows[0]["size"], 16);
            assert_eq!(
                rows[0]["sha256"],
                ratarmount_index::sha256_hex_stream(&mut &b"training payload"[..]).unwrap()
            );
            assert_eq!(
                rows[0]["xattrs"]["user.binary"],
                serde_json::json!([255, 0, 10, 61])
            );
            let old = fs::read(&manifest).unwrap();
            let plan = collect_overlay_commit_plan(&root).unwrap();
            assert!(write_commit_manifest(&archive, &plan, "utf-8", "invalid").is_err());
            assert_eq!(fs::read(&manifest).unwrap(), old);
            FAIL_MANIFEST_PUBLISH.set(true);
            assert!(write_commit_manifest(&archive, &plan, "utf-8", "all").is_err());
            assert_eq!(fs::read(&manifest).unwrap(), old);
            write_commit_manifest(&archive, &plan, "utf-8", "none").unwrap();
            let next: serde_json::Value =
                serde_json::from_str(fs::read_to_string(&manifest).unwrap().trim()).unwrap();
            assert!(next["sha256"].is_null());
            assert!(next["commit_id"].as_u64() > rows[0]["commit_id"].as_u64());
        }
    }
}

/// Regression: live cleanup must forget only committed xattr rows and leave
/// the archive serving the new metadata and unchanged payload bytes.
#[test]
fn regression_provenance_live_cleanup_and_rename() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar.zst");
    provenance_fixture(&archive, true);
    let root = dir.path().join("ov");
    let mut ov =
        WriteOverlay::new_for_tests(Arc::new(provenance_base(&archive, "utf-8").unwrap()), &root)
            .unwrap();
    ov.set_manifest_hashes(Some("new".into()));
    ov.set_xattr("/trace", "user.train_ok", b"false", 0)
        .unwrap();
    assert!(ov
        .commit_live(&archive, |p| Ok(Arc::new(provenance_base(p, "utf-8")?)))
        .unwrap());
    assert!(collect_overlay_commit_plan_from_conn(
        &root,
        Some(&ov.db.lock().unwrap()),
        None,
        &HashSet::new()
    )
    .unwrap()
    .is_empty());
    assert_eq!(
        ov.xattrs_for_path("/trace").unwrap()["user.train_ok"],
        b"false"
    );
    ov.rename("/trace", "/moved").unwrap();
    assert_eq!(
        ov.xattrs_for_path("/moved").unwrap()["user.teacher"],
        b"old"
    );
    ov.unlink("/moved").unwrap();
    let fd = ov.create_file("/moved", 0o644).unwrap();
    ov.close_overlay_fd(fd);
    assert!(ov.xattrs_for_path("/moved").unwrap().is_empty());
}

pub(crate) fn ustar_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
    UstarMember {
        xattrs: &[],
        path,
        payload: UstarPayload::File { bytes },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}

fn ustar_symlink<'a>(path: &'a str, target: &'a str) -> UstarMember<'a> {
    UstarMember {
        xattrs: &[],
        path,
        payload: UstarPayload::Symlink { target },
        mode: 0o777,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}

fn pack_tar(members: &[UstarMember<'_>]) -> Vec<u8> {
    let mut buf = Vec::new();
    ratarmount_formats_tar::write_ustar_members(&mut buf, members).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut buf).unwrap();
    buf
}

fn pack_tar_no_eof(members: &[UstarMember<'_>]) -> Vec<u8> {
    let mut buf = Vec::new();
    ratarmount_formats_tar::write_ustar_members(&mut buf, members).unwrap();
    buf
}

pub(crate) fn concat_zstd_frames(plains: &[&[u8]], with_seek_table: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut entries = Vec::new();
    for p in plains {
        let f = ratarmount_compress::encode_zstd_frame(p, 3).unwrap();
        entries.push((f.len() as u32, p.len() as u32));
        out.extend_from_slice(&f);
    }
    if with_seek_table {
        out.extend_from_slice(&ratarmount_compress::build_seek_table_skippable(&entries));
    }
    out
}

/// One uncompressed TAR split across two zstd frames (EOF only in the last frame).
pub(crate) fn write_split_tar_zst(
    path: &Path,
    first: &[UstarMember<'_>],
    last: &[UstarMember<'_>],
    with_seek_table: bool,
) {
    let f0 = pack_tar_no_eof(first);
    let mut f1 = pack_tar_no_eof(last);
    ratarmount_formats_tar::write_tar_eof(&mut f1).unwrap();
    fs::write(path, concat_zstd_frames(&[&f0, &f1], with_seek_table)).unwrap();
}

fn write_single_frame_tar_zst(path: &Path, members: &[UstarMember<'_>]) {
    let tar = pack_tar(members);
    fs::write(path, concat_zstd_frames(&[&tar], false)).unwrap();
}

fn write_complete_tar_frames_zst(path: &Path, frames: &[Vec<u8>]) {
    let refs: Vec<&[u8]> = frames.iter().map(|v| v.as_slice()).collect();
    fs::write(path, concat_zstd_frames(&refs, false)).unwrap();
}

pub(crate) fn reopen_tar_zst(
    path: &Path,
    ignore_zeros: bool,
) -> std::result::Result<Arc<dyn MountSource>, OverlayError> {
    let body = open_seekable_zstd(path).map_err(|e| OverlayError::Msg(e.to_string()))?;
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ignore_zeros,
        ..ratarmount_core::OpenOptions::default()
    };
    ratarmount_formats_tar::SqliteIndexedTar::create_index_body(path, body, None, &opts, "test")
        .map(|t| Arc::new(t) as Arc<dyn MountSource>)
        .map_err(|e| OverlayError::Msg(e.to_string()))
}

fn open_tar_zst_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
    reopen_tar_zst(path, ignore_zeros).expect("index tar.zst")
}

fn bz2_compress(plain: &[u8]) -> Vec<u8> {
    let mut enc = BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    enc.write_all(plain).unwrap();
    enc.finish().unwrap()
}

fn xz_compress(plain: &[u8]) -> Vec<u8> {
    let mut enc = XzEncoder::new(Vec::new(), 0);
    enc.write_all(plain).unwrap();
    enc.finish().unwrap()
}

fn write_concatenated_tar_bz2(path: &Path, first: &[UstarMember<'_>], second: &[UstarMember<'_>]) {
    let mut out = bz2_compress(&pack_tar(first));
    out.extend(bz2_compress(&pack_tar(second)));
    fs::write(path, out).unwrap();
}

fn write_concatenated_tar_xz(path: &Path, first: &[UstarMember<'_>], second: &[UstarMember<'_>]) {
    let mut out = xz_compress(&pack_tar(first));
    out.extend(xz_compress(&pack_tar(second)));
    fs::write(path, out).unwrap();
}

fn open_compressed_tar_base(
    path: &Path,
    body: Arc<dyn ratarmount_compress::SeekableBody>,
    ignore_zeros: bool,
    label: &str,
) -> Arc<dyn MountSource> {
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ignore_zeros,
        ..ratarmount_core::OpenOptions::default()
    };
    ratarmount_formats_tar::SqliteIndexedTar::create_index_body(path, body, None, &opts, "test")
        .map(|t| Arc::new(t) as Arc<dyn MountSource>)
        .unwrap_or_else(|e| panic!("index {label}: {e}"))
}

fn open_tar_bz2_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
    let body = open_seekable_bzip2(path).expect("open seekable bzip2");
    open_compressed_tar_base(path, body, ignore_zeros, "tar.bz2")
}

fn open_tar_xz_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
    let body = open_seekable_xz(path).expect("open seekable xz");
    open_compressed_tar_base(path, body, ignore_zeros, "tar.xz")
}

fn open_uncompressed_tar_base(path: &Path, ignore_zeros: bool) -> Arc<dyn MountSource> {
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ignore_zeros,
        ..ratarmount_core::OpenOptions::default()
    };
    let mut materialised = None;
    Arc::new(
        ratarmount_formats_tar::SqliteIndexedTar::create_index(
            path,
            path,
            None,
            &opts,
            "test",
            &mut materialised,
        )
        .expect("index uncompressed tar"),
    )
}

fn read_member(src: &dyn MountSource, path: &str) -> Vec<u8> {
    let fi = src
        .lookup(path, 0)
        .unwrap_or_else(|| panic!("missing {path}"));
    src.read(&fi, fi.size as usize, 0).expect("read member")
}

fn overlay_with_base(base: Arc<dyn MountSource>, overlay: &Path) -> WriteOverlay {
    fs::create_dir_all(overlay).unwrap();
    WriteOverlay::new_for_tests(base, overlay).unwrap()
}

fn seek_table_footer_present(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let n = bytes.len();
    u32::from_le_bytes(bytes[n - 4..].try_into().unwrap()) == 0x8F92_EAB1
}

#[test]
fn live_commit_accepts_tar_zst() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("accept");
    let path = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&path, &[ustar_file("seed.txt", &seed)]);
    live_commit_is_supported(&path).expect(".tar.zst must be accepted");

    let tzst = dir.path().join("b.tzst");
    write_single_frame_tar_zst(&tzst, &[ustar_file("seed.txt", &seed)]);
    live_commit_is_supported(&tzst).expect(".tzst must be accepted");

    let zstd = dir.path().join("c.tar.zstd");
    write_single_frame_tar_zst(&zstd, &[ustar_file("seed.txt", &seed)]);
    live_commit_is_supported(&zstd).expect(".tar.zstd must be accepted");

    let plain = dir.path().join("plain.zst");
    let not_tar = ratarmount_compress::encode_zstd_frame(b"not-a-tar-body", 3).unwrap();
    fs::write(&plain, not_tar).unwrap();
    let err = live_commit_is_supported(&plain).unwrap_err().to_string();
    assert!(
        err.contains("plain .zst") && err.contains("not a TAR"),
        "{err}"
    );
}

#[test]
fn live_commit_tar_zst_multi_frame_append() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("mf-prefix");
    let last = generated_payload("mf-last");
    let extra = generated_payload("mf-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("prefix.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let map_before = scan_zstd_frames_path(&archive).unwrap();
    let expected_start = map_before.frames.last().unwrap().uncompressed_offset;
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();

    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("commit"));
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    let window = ov.last_patch_window().expect("stashed zstd window");
    assert_eq!(window.from_frame, Some(map_before.frames.len() - 1));
    assert!(!window.offsets_shifted);
    assert_eq!(
        window.window_start, expected_start,
        "last-N window must start at the last frame's uncompressed offset"
    );
}

#[test]
fn live_commit_tar_zst_single_frame_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("sf-seed");
    let extra = generated_payload("sf-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();

    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("commit"));
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

#[test]
fn live_commit_tar_zst_seek_table_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("st-prefix");
    let last = generated_payload("st-last");
    let extra = generated_payload("st-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("prefix.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        true,
    );
    let before = fs::read(&archive).unwrap();
    assert!(seek_table_footer_present(&before));
    let map = scan_zstd_frames_path(&archive).unwrap();
    assert!(map.seek_table.is_some());
    let rewrite_start = map.frames.last().unwrap().compressed_offset as usize;
    let prefix_bytes = before[..rewrite_start].to_vec();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("commit"));

    let after = fs::read(&archive).unwrap();
    assert_eq!(
        &after[..rewrite_start],
        prefix_bytes.as_slice(),
        "prefix frames must stay byte-identical"
    );
    assert!(
        seek_table_footer_present(&after),
        "seek-table footer must be rewritten"
    );
    let out_map = scan_zstd_frames_path(&archive).unwrap();
    assert!(out_map.seek_table.is_some());
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

#[test]
fn live_commit_tar_zst_last_frame_starts_mid_member() {
    let dir = tempfile::tempdir().unwrap();
    let big = generated_payload("mid-big").repeat(200);
    let after = generated_payload("mid-after");
    let extra = generated_payload("mid-new");
    let tar = pack_tar(&[ustar_file("big.bin", &big), ustar_file("after.txt", &after)]);
    // First member: 512-byte header + payload. Split inside the payload.
    let mid = 512 + big.len() / 2;
    assert!(mid < 512 + big.len(), "split must be mid-payload");
    let archive = dir.path().join("a.tar.zst");
    fs::write(
        &archive,
        concat_zstd_frames(&[&tar[..mid], &tar[mid..]], false),
    )
    .unwrap();

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("commit"));
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/big.bin"), big);
    assert_eq!(read_member(src.as_ref(), "/after.txt"), after);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

#[test]
fn live_commit_tar_zst_last_window_replace_two_ticks() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("rw-seed");
    let tick1 = generated_payload("rw-t1");
    let tick2 = generated_payload("rw-t2");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("seed.txt", &seed)],
        &[ustar_file("keep.txt", b"keep\n")],
        false,
    );
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("tick.bin"), &tick1).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("tick 1"));
    assert!(!overlay.join("tick.bin").exists());

    fs::write(overlay.join("tick.bin"), &tick2).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("tick 2"));
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/tick.bin"), tick2);
    assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
}

#[test]
fn live_commit_tar_zst_earlier_frame_delete_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("ef-prefix");
    let last = generated_payload("ef-last");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("old.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let before = fs::read(&archive).unwrap();
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    ov.unlink("/old.txt").expect("unlink prefix member");
    let err = ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .unwrap_err()
        .to_string();
    assert!(err.contains("append-only"), "{err}");
    assert!(err.contains("/old.txt"), "{err}");
    assert_eq!(
        fs::read(&archive).unwrap(),
        before,
        "archive must be unchanged"
    );
}

/// Regression: same name in frame 0 and last frame; unlink must fail the tick.
#[test]
fn live_commit_tar_zst_same_name_both_frames_unlink_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = generated_payload("dup-v1");
    let v2 = generated_payload("dup-v2");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("dup.txt", &v1)],
        &[ustar_file("dup.txt", &v2)],
        false,
    );
    let before = fs::read(&archive).unwrap();
    // ignore_zeros so both versions are indexed (split-suffix still one stream).
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    ov.unlink("/dup.txt").expect("unlink newest");
    let err = ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .unwrap_err()
        .to_string();
    assert!(err.contains("append-only"), "{err}");
    assert!(err.contains("/dup.txt"), "{err}");
    assert_eq!(fs::read(&archive).unwrap(), before);
}

#[test]
fn live_commit_tar_zst_mixed_plan_skips_pending_appends() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("mix-old");
    let last = generated_payload("mix-last");
    let extra = generated_payload("mix-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("old.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let before = fs::read(&archive).unwrap();
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    ov.unlink("/old.txt").expect("unlink earlier-frame name");
    let err = ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .unwrap_err()
        .to_string();
    assert!(err.contains("append-only"), "{err}");
    assert!(err.contains("pending appends"), "{err}");
    assert_eq!(fs::read(&archive).unwrap(), before);
    let src = open_tar_zst_base(&archive, false);
    assert!(
        src.lookup("/new.txt", 0).is_none(),
        "new name must not be persisted when the tick fails"
    );
    assert!(overlay.join("new.txt").exists());
}

#[test]
fn live_commit_tar_zst_reopen_fail_keeps_overlay_and_disables() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("rf-seed");
    let extra = generated_payload("rf-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();

    let err = ov
        .commit_live(&archive, |_| {
            Err(OverlayError::Msg("stub reopen fail".into()))
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("remount required"), "{err}");
    assert!(
        overlay.join("new.txt").exists(),
        "overlay must be kept after reopen failure"
    );
    assert!(ov.interval_disabled());
    assert_eq!(read_member(&ov, "/seed.txt"), seed);

    let second = ov
        .commit_live(&archive, |_| {
            panic!("second tick must not persist after interval_disabled")
        })
        .unwrap_err()
        .to_string();
    assert!(
        second.contains("remount required"),
        "second tick skipped via interval_disabled, not Ok(false): {second}"
    );
    assert!(overlay.join("new.txt").exists());
    // Persist did run on the first tick — remount should see the new member.
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

#[test]
fn live_commit_tar_zst_empty_second_tick() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("es-seed");
    let extra = generated_payload("es-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("first tick"));
    assert!(!overlay.join("new.txt").exists());
    match ov.commit_live(&archive, |p| reopen_tar_zst(p, false)) {
        Ok(false) => {}
        other => panic!("empty second tick must be Ok(false), got {other:?}"),
    }
}

fn set_mtime_age(path: &Path, age: Duration) {
    use std::os::unix::ffi::OsStrExt;
    let ts = SystemTime::now()
        .checked_sub(age)
        .expect("mtime age within epoch");
    let d = ts
        .duration_since(std::time::UNIX_EPOCH)
        .expect("mtime after epoch");
    let spec = libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    };
    let times = [spec, spec];
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    assert_eq!(rc, 0, "utimensat {}", path.display());
}

/// Regression: interval settle time skips files still being written.
#[test]
fn live_commit_idle_skips_recent_keeps_overlay() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("idle-seed");
    let settled = generated_payload("idle-settled");
    let hot = generated_payload("idle-hot");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("settled.txt"), &settled).unwrap();
    fs::write(overlay.join("hot.txt"), &hot).unwrap();
    set_mtime_age(&overlay.join("settled.txt"), Duration::from_secs(30));

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("idle tick"));
    assert!(
        !overlay.join("settled.txt").exists(),
        "settled file must leave the overlay"
    );
    assert!(
        overlay.join("hot.txt").exists(),
        "recently modified file must stay in the overlay"
    );
    assert_eq!(fs::read(overlay.join("hot.txt")).unwrap(), hot);

    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    assert_eq!(read_member(src.as_ref(), "/settled.txt"), settled);
    assert!(
        src.lookup("/hot.txt", 0).is_none(),
        "hot file must not be in the archive yet"
    );
    assert_eq!(
        read_member(&ov as &dyn MountSource, "/hot.txt"),
        hot,
        "mount view still serves the overlay copy"
    );
}

/// Descriptors whose target is under `root`, including unlinked files
/// (`readlink` appends ` (deleted)`). Ignores the rest of the process so
/// the leak check stays valid when other tests hold fds.
#[cfg(unix)]
fn count_fds_under(root: &Path) -> Option<usize> {
    let prefix = root.to_string_lossy();
    let rd = std::fs::read_dir("/proc/self/fd").ok()?;
    Some(
        rd.flatten()
            .filter(|ent| {
                std::fs::read_link(ent.path())
                    .ok()
                    .is_some_and(|target| target.to_string_lossy().starts_with(prefix.as_ref()))
            })
            .count(),
    )
}

/// Regression: `open_overlay_fd` materialized a missing host file via
/// `create_file_inner` and discarded the raw fd (`into_raw_fd` is not
/// Drop-closed). Interval persist wipes the overlay copy, so the next
/// FUSE/NFS/9P rewrite leaked one descriptor each time — long-lived
/// `--commit-overlay-interval` mounts hit EMFILE.
#[cfg(unix)]
#[test]
fn open_overlay_fd_create_does_not_leak_materialize_fd() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay);
    let Some(before) = count_fds_under(&overlay) else {
        eprintln!("skip: /proc/self/fd not available");
        return;
    };
    const N: usize = 32;
    for i in 0..N {
        let path = format!("/rewrite-{i}.txt");
        let fd = ov
            .open_overlay_fd(&path, libc::O_RDWR | libc::O_CREAT)
            .expect("first O_CREAT open");
        ov.close_overlay_fd(fd);
        // Same as interval `forget_committed_overlay`: host file is gone.
        fs::remove_file(overlay.join(format!("rewrite-{i}.txt"))).expect("wipe overlay host");
        let fd = ov
            .open_overlay_fd(&path, libc::O_RDWR | libc::O_CREAT)
            .expect("post-wipe O_CREAT open");
        ov.close_overlay_fd(fd);
    }
    let after = count_fds_under(&overlay).expect("/proc/self/fd after loop");
    assert_eq!(
        after, before,
        "Regression: discarded create_file_inner fd leaked on missing-file \
         O_CREAT (overlay fds before={before} after={after}; 32×2 opens would leak 64)"
    );
}

/// Regression: interval settle must not persist a file that still has an
/// open write fd. FUSE keeps that fd across pauses; unlinking would send
/// later pwrite bytes to a detached inode (silent truncation).
#[test]
fn live_commit_idle_skips_open_write_fd() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("idle-open-seed");
    let first = generated_payload("idle-open-first");
    let second = generated_payload("idle-open-second");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    let fd = ov.create_file("/open.txt", 0o644).expect("create");
    let n = unsafe { libc::write(fd, first.as_ptr() as *const _, first.len()) };
    assert_eq!(n as usize, first.len(), "first write");
    set_mtime_age(&overlay.join("open.txt"), Duration::from_secs(30));

    match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
        reopen_tar_zst(p, false)
    }) {
        Ok(false) => {}
        other => panic!("open write fd must skip idle persist, got {other:?}"),
    }
    assert!(
        overlay.join("open.txt").exists(),
        "open write fd must keep the overlay file"
    );

    let n = unsafe {
        libc::pwrite(
            fd,
            second.as_ptr() as *const _,
            second.len(),
            first.len() as i64,
        )
    };
    assert_eq!(n as usize, second.len(), "second write after skipped tick");
    ov.close_overlay_fd(fd);
    set_mtime_age(&overlay.join("open.txt"), Duration::from_secs(30));

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("idle tick after close"));
    assert!(!overlay.join("open.txt").exists());

    let mut want = first.clone();
    want.extend_from_slice(&second);
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/open.txt"), want);
}

/// Regression: NFS WRITE used to `drop(File)` (close) and then
/// `release_write_fd`. The pin map is keyed by fd number; the kernel can
/// reuse that number for a still-open FUSE writer. Interval settle would
/// persist/unlink the still-open file (later pwrite → detached inode).
#[test]
fn live_commit_idle_skips_open_write_fd_after_fd_reuse() {
    use std::os::unix::io::FromRawFd;

    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("idle-reuse-seed");
    let keep = generated_payload("idle-reuse-keep");
    let nfs_bytes = generated_payload("idle-reuse-nfs");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);

    let nfs_fd = ov
        .open_overlay_fd("/nfs.txt", libc::O_RDWR | libc::O_CREAT)
        .expect("nfs open");
    let n = unsafe { libc::write(nfs_fd, nfs_bytes.as_ptr() as *const _, nfs_bytes.len()) };
    assert_eq!(n as usize, nfs_bytes.len(), "nfs write");
    let nfs_file = unsafe { std::fs::File::from_raw_fd(nfs_fd) };
    ov.finish_owned_write_fd(nfs_file);

    // Long-lived FUSE-style writer. If the OS reused `nfs_fd`, the pin
    // must now belong to this file — not a stale closed number.
    let keep_fd = ov.create_file("/keep.txt", 0o644).expect("keep create");
    let n = unsafe { libc::write(keep_fd, keep.as_ptr() as *const _, keep.len()) };
    assert_eq!(n as usize, keep.len(), "keep write");
    set_mtime_age(&overlay.join("keep.txt"), Duration::from_secs(30));
    set_mtime_age(&overlay.join("nfs.txt"), Duration::from_secs(30));

    match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
        reopen_tar_zst(p, false)
    }) {
        Ok(_) => {}
        Err(e) => panic!("idle tick after fd reuse: {e}"),
    }
    assert!(
        overlay.join("keep.txt").exists(),
        "still-open writer must stay in the overlay after a finished NFS \
         WRITE reuses/closes another fd (keep_fd={keep_fd}, nfs_fd={nfs_fd})"
    );

    let extra = generated_payload("idle-reuse-extra");
    let n = unsafe {
        libc::pwrite(
            keep_fd,
            extra.as_ptr() as *const _,
            extra.len(),
            keep.len() as i64,
        )
    };
    assert_eq!(n as usize, extra.len(), "pwrite after skipped tick");
    ov.close_overlay_fd(keep_fd);
    set_mtime_age(&overlay.join("keep.txt"), Duration::from_secs(30));

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("idle tick after keep close"));
    assert!(!overlay.join("keep.txt").exists());

    let mut want = keep.clone();
    want.extend_from_slice(&extra);
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/keep.txt"), want);
    assert_eq!(read_member(src.as_ref(), "/nfs.txt"), nfs_bytes);
}

/// Regression: SMB/SFTP/9P/WebDAV WRITE used to `drop(File)` (close) and
/// then `release_write_fd`. Same pin-map / fd-reuse class as NFS.
#[test]
fn live_commit_idle_skips_open_write_fd_after_protocol_write_fd_reuse() {
    use std::os::unix::io::FromRawFd;

    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("idle-proto-seed");
    let keep = generated_payload("idle-proto-keep");
    let proto_bytes = generated_payload("idle-proto-write");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);

    // Fixed sequence: unpin while the fd is still open, then close.
    let proto_fd = ov
        .open_overlay_fd("/proto.txt", libc::O_RDWR | libc::O_CREAT)
        .expect("proto open");
    let n = unsafe {
        libc::write(
            proto_fd,
            proto_bytes.as_ptr() as *const _,
            proto_bytes.len(),
        )
    };
    assert_eq!(n as usize, proto_bytes.len(), "proto write");
    let proto_file = unsafe { std::fs::File::from_raw_fd(proto_fd) };
    ov.finish_owned_write_fd(proto_file);

    let keep_fd = ov.create_file("/keep.txt", 0o644).expect("keep create");
    let n = unsafe { libc::write(keep_fd, keep.as_ptr() as *const _, keep.len()) };
    assert_eq!(n as usize, keep.len(), "keep write");
    set_mtime_age(&overlay.join("keep.txt"), Duration::from_secs(30));
    set_mtime_age(&overlay.join("proto.txt"), Duration::from_secs(30));

    match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
        reopen_tar_zst(p, false)
    }) {
        Ok(_) => {}
        Err(e) => panic!("idle tick after protocol fd reuse: {e}"),
    }
    assert!(
        overlay.join("keep.txt").exists(),
        "still-open writer must stay in the overlay after a finished protocol \
         WRITE reuses/closes another fd (keep_fd={keep_fd}, proto_fd={proto_fd})"
    );

    let extra = generated_payload("idle-proto-extra");
    let n = unsafe {
        libc::pwrite(
            keep_fd,
            extra.as_ptr() as *const _,
            extra.len(),
            keep.len() as i64,
        )
    };
    assert_eq!(n as usize, extra.len(), "pwrite after skipped tick");
    ov.close_overlay_fd(keep_fd);
    set_mtime_age(&overlay.join("keep.txt"), Duration::from_secs(30));

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("idle tick after keep close"));
    assert!(!overlay.join("keep.txt").exists());

    let mut want = keep.clone();
    want.extend_from_slice(&extra);
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/keep.txt"), want);
    assert_eq!(read_member(src.as_ref(), "/proto.txt"), proto_bytes);
}

/// Regression: interval settle keyed the write-open pin by overlay path.
/// After `rename`, the host file moved but the pin still named the old
/// path, so a tick persisted and unlinked the renamed inode. Later
/// `pwrite` bytes hit the detached inode and never reached the archive.
///
/// Overlay-only create plus an unpinned sibling: same tick persists the
/// sibling (`Ok(true)`) and leaves the renamed writer on disk.
#[test]
fn live_commit_idle_skips_open_write_fd_after_rename() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("idle-rename-seed");
    let first = generated_payload("idle-rename-first");
    let second = generated_payload("idle-rename-second");
    let sibling = generated_payload("idle-rename-sibling");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    let fd = ov.create_file("/open.txt", 0o644).expect("create");
    let n = unsafe { libc::write(fd, first.as_ptr() as *const _, first.len()) };
    assert_eq!(n as usize, first.len(), "first write");
    ov.rename("/open.txt", "/renamed.txt")
        .expect("rename open write fd");
    fs::write(overlay.join("sibling.txt"), &sibling).unwrap();
    set_mtime_age(&overlay.join("renamed.txt"), Duration::from_secs(30));
    set_mtime_age(&overlay.join("sibling.txt"), Duration::from_secs(30));

    match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
        reopen_tar_zst(p, false)
    }) {
        Ok(true) => {}
        other => panic!(
            "idle tick must persist the unpinned sibling and skip the renamed writer, got {other:?}"
        ),
    }
    assert!(
        overlay.join("renamed.txt").exists(),
        "renamed open write fd must keep the overlay file"
    );
    assert!(
        !overlay.join("sibling.txt").exists(),
        "unpinned idle sibling must leave the overlay (proves we did not fail-closed the whole tick)"
    );
    assert!(
        !overlay.join("open.txt").exists(),
        "rename must have left the old overlay name"
    );

    let n = unsafe {
        libc::pwrite(
            fd,
            second.as_ptr() as *const _,
            second.len(),
            first.len() as i64,
        )
    };
    assert_eq!(n as usize, second.len(), "second write after rename+tick");
    ov.close_overlay_fd(fd);
    set_mtime_age(&overlay.join("renamed.txt"), Duration::from_secs(30));

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("idle tick after close"));
    assert!(!overlay.join("renamed.txt").exists());

    let mut want = first.clone();
    want.extend_from_slice(&second);
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/renamed.txt"), want);
    assert_eq!(read_member(src.as_ref(), "/sibling.txt"), sibling);
    assert!(
        src.lookup("/open.txt", 0).is_none(),
        "old name must not remain in the archive"
    );
}

/// Regression: after the hot file settles, a later tick persists it once.
#[test]
fn live_commit_idle_second_tick_after_settle() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("idle2-seed");
    let settled = generated_payload("idle2-settled");
    let later = generated_payload("idle2-later");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("settled.txt"), &settled).unwrap();
    fs::write(overlay.join("later.txt"), &later).unwrap();
    set_mtime_age(&overlay.join("settled.txt"), Duration::from_secs(30));

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("first idle tick"));
    assert!(overlay.join("later.txt").exists());

    set_mtime_age(&overlay.join("later.txt"), Duration::from_secs(30));
    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("second idle tick"));
    assert!(!overlay.join("later.txt").exists());

    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/settled.txt"), settled);
    assert_eq!(read_member(src.as_ref(), "/later.txt"), later);
    match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
        reopen_tar_zst(p, false)
    }) {
        Ok(false) => {}
        other => panic!("third tick must be empty, got {other:?}"),
    }
}

/// Regression: a hot replace must not delete the base member without appending.
#[test]
fn live_commit_idle_hot_replace_leaves_base_member() {
    let dir = tempfile::tempdir().unwrap();
    let orig = generated_payload("idle-rep-orig");
    let newer = generated_payload("idle-rep-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("keep.txt", &orig)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("keep.txt"), &newer).unwrap();

    match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
        reopen_tar_zst(p, false)
    }) {
        Ok(false) => {}
        other => panic!("hot replace must not persist, got {other:?}"),
    }
    assert!(overlay.join("keep.txt").exists());
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(
        read_member(src.as_ref(), "/keep.txt"),
        orig,
        "base member must survive a skipped hot replace"
    );
    assert_eq!(read_member(&ov as &dyn MountSource, "/keep.txt"), newer);
}

/// Regression: live interval must persist a later complete-TAR-frame
/// delete after remount without `-i`.
///
/// Tombstones survive in the overlay DB. `current_base()` after a default
/// remount does not see later-frame names, so classification used to skip
/// the delete, return success, and `forget_committed_overlay` dropped the
/// tombstone — the member reappeared on the next `-i` remount.
#[test]
fn live_commit_idle_tar_zst_concatenated_delete_without_ignore_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("live-i0-prefix");
    let last = generated_payload("live-i0-last");
    let archive = dir.path().join("a.tar.zst");
    write_complete_tar_frames_zst(
        &archive,
        &[
            pack_tar(&[ustar_file("prefix.txt", &prefix)]),
            pack_tar(&[ustar_file("last.txt", &last)]),
        ],
    );
    let before = fs::read(&archive).unwrap();
    let map = scan_zstd_frames_path(&archive).unwrap();
    assert!(map.frames.len() >= 2);
    let prefix_end = map.frames[1].compressed_offset as usize;
    let prefix_bytes = before[..prefix_end].to_vec();

    let overlay = dir.path().join("ov");
    {
        let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
        ov.unlink("/last.txt")
            .expect("unlink later complete-TAR frame");
    }

    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    assert!(
        ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
            reopen_tar_zst(p, false)
        })
        .expect("live idle commit without -i must persist later-frame delete"),
        "interval tick must persist the remounted tombstone"
    );
    let after = fs::read(&archive).unwrap();
    assert_eq!(
        &after[..prefix_end],
        prefix_bytes.as_slice(),
        "prefix complete-TAR frame must stay byte-identical"
    );
    let src = open_tar_zst_base(&archive, true);
    assert!(
        src.lookup("/last.txt", 0).is_none(),
        "later-frame name must be gone after live commit without -i"
    );
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    assert!(
        ov.lookup("/last.txt", 0).is_none(),
        "interval cleanup must not resurrect the forgotten tombstone"
    );
}

/// Regression: delete tombstones are already settled and commit on an idle tick.
#[test]
fn live_commit_idle_commits_delete_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let keep = generated_payload("idle-del-keep");
    let gone = generated_payload("idle-del-gone");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(
        &archive,
        &[ustar_file("keep.txt", &keep), ustar_file("gone.txt", &gone)],
    );
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    ov.unlink("/gone.txt").expect("tombstone");

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("idle delete tick"));
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/keep.txt"), keep);
    assert!(
        src.lookup("/gone.txt", 0).is_none(),
        "deleted member must leave the archive"
    );
    assert!(ov.lookup("/gone.txt", 0).is_none());
}

/// Regression: a hot nested sibling must keep its parent dir in the overlay.
#[test]
fn live_commit_idle_nested_hot_sibling_keeps_parent() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("idle-nest-seed");
    let settled = generated_payload("idle-nest-settled");
    let hot = generated_payload("idle-nest-hot");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::create_dir_all(overlay.join("dir")).unwrap();
    fs::write(overlay.join("dir/settled.txt"), &settled).unwrap();
    fs::write(overlay.join("dir/hot.txt"), &hot).unwrap();
    set_mtime_age(&overlay.join("dir/settled.txt"), Duration::from_secs(30));

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("idle nested tick"));
    assert!(!overlay.join("dir/settled.txt").exists());
    assert!(
        overlay.join("dir/hot.txt").exists(),
        "hot sibling must keep the parent dir"
    );
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/dir/settled.txt"), settled);
    assert!(src.lookup("/dir/hot.txt", 0).is_none());
    assert_eq!(read_member(&ov as &dyn MountSource, "/dir/hot.txt"), hot);
}

/// Regression: after the last file in a new dir settles, prune the empty
/// parent so a later tick does not persist a bare directory member.
#[test]
fn live_commit_idle_prunes_empty_parent_after_last_file() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("idle-prune-seed");
    let only = generated_payload("idle-prune-only");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::create_dir_all(overlay.join("dir")).unwrap();
    fs::write(overlay.join("dir/only.txt"), &only).unwrap();
    set_mtime_age(&overlay.join("dir/only.txt"), Duration::from_secs(30));
    // Dir mtime is refreshed by the file write; backdate so a leftover
    // empty dir would look idle on the next tick if it were not pruned.
    set_mtime_age(&overlay.join("dir"), Duration::from_secs(30));

    assert!(ov
        .commit_live_idle(&archive, Duration::from_secs(10), |p| reopen_tar_zst(
            p, false
        ))
        .expect("idle prune tick"));
    assert!(
        !overlay.join("dir").exists(),
        "empty parent must be pruned from the overlay"
    );
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/dir/only.txt"), only);

    match ov.commit_live_idle(&archive, Duration::from_secs(10), |p| {
        reopen_tar_zst(p, false)
    }) {
        Ok(false) => {}
        other => panic!("second tick must not persist leftover dir, got {other:?}"),
    }
}

fn wait_inflight(ov: &WriteOverlay, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if ov.persist_inflight_for_test() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("inflight flag never set within {timeout:?}");
}

fn zstd_magic_ok(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == [0x28, 0xB5, 0x2F, 0xFD]
}

/// Count ustar names after decoding every zstd frame (`tar -tf`).
fn tar_zst_member_count(archive: &Path, name: &str) -> usize {
    let map = scan_zstd_frames_path(archive).unwrap();
    let mut src = File::open(archive).unwrap();
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    ratarmount_compress::decode_zstd_frames_to(&mut src, &map, 0, tmp.as_file_mut()).unwrap();
    let out = StdCommand::new("tar")
        .args(["-tf"])
        .arg(tmp.path())
        .output()
        .expect("tar -tf");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.trim_end_matches('/') == name)
        .count()
}

/// Regression: two interval fires during injected long persist → second Coalesced.
#[test]
fn overlay_commit_queue_second_interval_coalesced() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("q-coal-seed");
    let extra = generated_payload("q-coal-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = Arc::new(overlay_with_base(
        open_tar_zst_base(&archive, false),
        &overlay,
    ));
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    set_mtime_age(&overlay.join("new.txt"), Duration::from_secs(30));
    ov.set_persist_delay_for_test(Duration::from_millis(400));

    let archive_t = archive.clone();
    let ov_t = Arc::clone(&ov);
    let first = std::thread::spawn(move || {
        ov_t.enqueue_commit(
            &archive_t,
            CommitKind::IntervalIdle(Duration::from_secs(10)),
            |p| reopen_tar_zst(p, false),
        )
    });
    wait_inflight(&ov, Duration::from_secs(2));
    // Inflight is set before persist delay; splice has not started yet.
    // Sibling-tmp + atomic replace is what keeps readers off a truncated file.
    let during = fs::read(&archive).unwrap();
    assert!(
        zstd_magic_ok(&during),
        "archive path must still be a zstd file while inflight"
    );

    let second = ov
        .enqueue_commit(
            &archive,
            CommitKind::IntervalIdle(Duration::from_secs(10)),
            |_| panic!("second interval tick must not start persist"),
        )
        .expect("coalesce");
    assert_eq!(second, CommitOutcome::Coalesced);

    let first = first
        .join()
        .expect("first tick thread")
        .expect("first tick");
    assert_eq!(first, CommitOutcome::DidWork);
    assert!(!ov.persist_inflight_for_test());
    assert!(!overlay.join("new.txt").exists());
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    let after = fs::read(&archive).unwrap();
    assert!(zstd_magic_ok(&after));
}

/// Regression: on-exit waits for inflight interval then one commit_atomic
/// of remaining files (same plan is not spliced twice).
#[test]
fn overlay_commit_queue_on_exit_waits_then_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("q-wait-seed");
    let extra = generated_payload("q-wait-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = Arc::new(overlay_with_base(
        open_tar_zst_base(&archive, false),
        &overlay,
    ));
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    set_mtime_age(&overlay.join("new.txt"), Duration::from_secs(30));
    ov.set_persist_delay_for_test(Duration::from_millis(300));

    let archive_t = archive.clone();
    let ov_t = Arc::clone(&ov);
    let interval = std::thread::spawn(move || {
        ov_t.enqueue_commit(
            &archive_t,
            CommitKind::IntervalIdle(Duration::from_secs(10)),
            |p| reopen_tar_zst(p, false),
        )
    });
    wait_inflight(&ov, Duration::from_secs(2));

    let on_exit = ov
        .enqueue_commit(&archive, CommitKind::OnExit, |_| {
            panic!("on-exit must not reopen")
        })
        .expect("on-exit");
    assert_eq!(
        on_exit,
        CommitOutcome::Nothing,
        "interval already committed the idle plan; on-exit must not splice again"
    );
    let interval = interval.join().expect("interval thread").expect("interval");
    assert_eq!(interval, CommitOutcome::DidWork);

    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
    assert_eq!(tar_zst_member_count(&archive, "new.txt"), 1);
}

/// Regression: empty interval polls must not shrink the on-exit wait
/// (2× last DidWork persist).
#[test]
fn overlay_commit_queue_empty_tick_does_not_shrink_persist_duration() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("q-dur-seed");
    let extra = generated_payload("q-dur-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    set_mtime_age(&overlay.join("new.txt"), Duration::from_secs(30));

    assert_eq!(
        ov.enqueue_commit(
            &archive,
            CommitKind::IntervalIdle(Duration::from_secs(10)),
            |p| reopen_tar_zst(p, false),
        )
        .expect("did work"),
        CommitOutcome::DidWork
    );
    let after_work = ov.last_persist_duration_for_test();
    assert!(
        after_work > Duration::ZERO,
        "DidWork must record a persist duration, got {after_work:?}"
    );

    assert_eq!(
        ov.enqueue_commit(
            &archive,
            CommitKind::IntervalIdle(Duration::from_secs(10)),
            |p| reopen_tar_zst(p, false),
        )
        .expect("empty"),
        CommitOutcome::Nothing
    );
    assert_eq!(
        ov.last_persist_duration_for_test(),
        after_work,
        "empty poll must not overwrite last DidWork duration"
    );
}

/// Regression: on-exit waits then commit_atomic remaining (idle A by
/// interval, still-hot B by on-exit); each name once.
#[test]
fn overlay_commit_queue_on_exit_commits_remaining_hot() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("q-hot-seed");
    let idle = generated_payload("q-hot-idle");
    let hot = generated_payload("q-hot-hot");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = Arc::new(overlay_with_base(
        open_tar_zst_base(&archive, false),
        &overlay,
    ));
    fs::write(overlay.join("idle.txt"), &idle).unwrap();
    fs::write(overlay.join("hot.txt"), &hot).unwrap();
    set_mtime_age(&overlay.join("idle.txt"), Duration::from_secs(30));
    ov.set_persist_delay_for_test(Duration::from_millis(300));

    let archive_t = archive.clone();
    let ov_t = Arc::clone(&ov);
    let interval = std::thread::spawn(move || {
        ov_t.enqueue_commit(
            &archive_t,
            CommitKind::IntervalIdle(Duration::from_secs(10)),
            |p| reopen_tar_zst(p, false),
        )
    });
    wait_inflight(&ov, Duration::from_secs(2));

    let on_exit = ov
        .enqueue_commit(&archive, CommitKind::OnExit, |_| {
            panic!("on-exit must not reopen")
        })
        .expect("on-exit");
    let interval = interval.join().expect("interval thread").expect("interval");
    assert_eq!(interval, CommitOutcome::DidWork);
    assert_eq!(on_exit, CommitOutcome::DidWork);
    assert!(!overlay.join("idle.txt").exists());
    // On-exit persist does not reset the overlay folder.
    assert!(overlay.join("hot.txt").exists());

    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/idle.txt"), idle);
    assert_eq!(read_member(src.as_ref(), "/hot.txt"), hot);
    assert_eq!(tar_zst_member_count(&archive, "idle.txt"), 1);
    assert_eq!(tar_zst_member_count(&archive, "hot.txt"), 1);
}

/// Regression: on-exit wait timeout during persist delay must not splice
/// until inflight clears (commit_atomic does not forget overlay files).
#[test]
fn overlay_commit_queue_on_exit_timeout_waits_inflight() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("q-to-seed");
    let idle = generated_payload("q-to-idle");
    let hot = generated_payload("q-to-hot");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = Arc::new(overlay_with_base(
        open_tar_zst_base(&archive, false),
        &overlay,
    ));
    fs::write(overlay.join("idle.txt"), &idle).unwrap();
    fs::write(overlay.join("hot.txt"), &hot).unwrap();
    set_mtime_age(&overlay.join("idle.txt"), Duration::from_secs(30));
    ov.set_persist_delay_for_test(Duration::from_millis(400));
    ov.set_on_exit_wait_min_for_test(Duration::from_millis(1));

    let archive_t = archive.clone();
    let ov_t = Arc::clone(&ov);
    let interval = std::thread::spawn(move || {
        ov_t.enqueue_commit(
            &archive_t,
            CommitKind::IntervalIdle(Duration::from_secs(10)),
            |p| reopen_tar_zst(p, false),
        )
    });
    wait_inflight(&ov, Duration::from_secs(2));

    let on_exit = ov
        .enqueue_commit(&archive, CommitKind::OnExit, |_| {
            panic!("on-exit must not reopen")
        })
        .expect("on-exit");
    let interval = interval.join().expect("interval thread").expect("interval");
    assert_eq!(interval, CommitOutcome::DidWork);
    assert_eq!(on_exit, CommitOutcome::DidWork);
    assert_eq!(tar_zst_member_count(&archive, "idle.txt"), 1);
    assert_eq!(tar_zst_member_count(&archive, "hot.txt"), 1);
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/idle.txt"), idle);
    assert_eq!(read_member(src.as_ref(), "/hot.txt"), hot);
}

/// Regression: live prefix-frame delete still fail-closed via enqueue.
#[test]
fn overlay_commit_queue_prefix_frame_delete_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("q-ef-prefix");
    let last = generated_payload("q-ef-last");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("old.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let before = fs::read(&archive).unwrap();
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    ov.unlink("/old.txt").expect("unlink prefix member");
    let err = ov
        .enqueue_commit(
            &archive,
            CommitKind::IntervalIdle(Duration::from_secs(10)),
            |p| reopen_tar_zst(p, false),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("append-only"), "{err}");
    assert!(err.contains("/old.txt"), "{err}");
    assert!(err.contains("--commit-overlay"), "{err}");
    assert_eq!(
        fs::read(&archive).unwrap(),
        before,
        "archive must be unchanged"
    );
}

/// Regression: FileVersionLayer wrap (factory default); same name in both frames.
#[test]
fn live_commit_tar_zst_file_version_layer_same_name_unlink_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = generated_payload("fvl-v1");
    let v2 = generated_payload("fvl-v2");
    let archive = dir.path().join("a.tar.zst");
    // Two complete-TAR frames so both versions exist only with ignore_zeros.
    write_complete_tar_frames_zst(
        &archive,
        &[
            pack_tar(&[ustar_file("dup.txt", &v1)]),
            pack_tar(&[ustar_file("dup.txt", &v2)]),
        ],
    );
    let before = fs::read(&archive).unwrap();
    let tar = open_tar_zst_base(&archive, true);
    let layered = crate::FileVersionLayer::new(tar);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(Arc::new(layered) as Arc<dyn MountSource>, &overlay);
    assert!(ov.current_base().versions("/dup.txt") > 1);
    ov.unlink("/dup.txt").expect("unlink newest");
    let err = ov
        .commit_live(&archive, |p| reopen_tar_zst(p, true))
        .unwrap_err()
        .to_string();
    assert!(err.contains("append-only"), "{err}");
    assert!(err.contains("/dup.txt"), "{err}");
    assert_eq!(fs::read(&archive).unwrap(), before);
}

/// Regression: overlay symlink must persist as a symlink (`linkname` remounts).
#[test]
fn live_commit_tar_zst_overlay_symlink_persists_linkname() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("sy-seed");
    let target = format!("tgt-{}", std::process::id());
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    ov.create_symlink("/link", &target)
        .expect("overlay symlink");
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("commit symlink"));
    let src = open_tar_zst_base(&archive, false);
    let fi = src.lookup("/link", 0).expect("symlink remounted");
    assert!(
        ratarmount_core::is_lnk_mode(fi.mode),
        "expected symlink mode, got {:o}",
        fi.mode
    );
    assert_eq!(fi.linkname, target);
    assert_eq!(read_member(src.as_ref(), "/seed.txt"), seed);
}

/// Regression: FileVersionLayer(AutoMount) reports versions()==1; unlink still rejects.
#[test]
fn live_commit_tar_zst_file_version_layer_automount_same_name_unlink_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = generated_payload("am-v1");
    let v2 = generated_payload("am-v2");
    let archive = dir.path().join("a.tar.zst");
    write_complete_tar_frames_zst(
        &archive,
        &[
            pack_tar(&[ustar_file("dup.txt", &v1)]),
            pack_tar(&[ustar_file("dup.txt", &v2)]),
        ],
    );
    let before = fs::read(&archive).unwrap();
    let tar = open_tar_zst_base(&archive, true);
    let open_nested: crate::OpenNestedFn =
        Arc::new(|_p| Err(io::Error::other("no nested open in live-commit test")));
    let automount = crate::AutoMountLayer::new(tar, 1, open_nested);
    assert_eq!(
        automount.versions("/dup.txt"),
        1,
        "AutoMount default versions() is 1 if exists"
    );
    let layered = crate::FileVersionLayer::new(Arc::new(automount) as Arc<dyn MountSource>);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(Arc::new(layered) as Arc<dyn MountSource>, &overlay);
    ov.unlink("/dup.txt").expect("unlink newest");
    let err = ov
        .commit_live(&archive, |p| reopen_tar_zst(p, true))
        .unwrap_err()
        .to_string();
    assert!(err.contains("append-only"), "{err}");
    assert!(err.contains("/dup.txt"), "{err}");
    assert_eq!(fs::read(&archive).unwrap(), before);
}

/// Regression: versions()==1 still walks .versions/{i} until miss.
#[test]
fn live_commit_tar_zst_versions_undercount_still_probes_version_paths() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = generated_payload("uc-v1");
    let v2 = generated_payload("uc-v2");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("dup.txt", &v1)],
        &[ustar_file("dup.txt", &v2)],
        false,
    );
    let before = fs::read(&archive).unwrap();
    let map = scan_zstd_frames_path(&archive).unwrap();
    let last_start = map.frames.last().unwrap().uncompressed_offset;
    let base = Arc::new(VersionsUndercount {
        oldest: tar_fi_at(0),
        newest: tar_fi_at(last_start),
    }) as Arc<dyn MountSource>;
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(base, &overlay);
    assert_eq!(ov.current_base().versions("/dup.txt"), 1);
    assert!(ov.current_base().lookup("/dup.txt.versions/1", 0).is_some());
    ov.unlink("/dup.txt").expect("unlink newest");
    let err = ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .unwrap_err()
        .to_string();
    assert!(err.contains("append-only"), "{err}");
    assert!(err.contains("/dup.txt"), "{err}");
    assert_eq!(fs::read(&archive).unwrap(), before);
}

fn tar_fi_at(offsetheader: u64) -> FileInfo {
    FileInfo {
        size: 1,
        mtime: 0.0,
        mode: ratarmount_core::S_IFREG | 0o644,
        linkname: String::new(),
        uid: 0,
        gid: 0,
        userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
            offset: offsetheader.saturating_add(512),
            offsetheader: Some(offsetheader),
            istar: false,
            issparse: false,
            isgenerated: false,
            recursiondepth: 0,
        })],
    }
}

/// `versions()` lies (always 1) but `.versions/{i}` serves every copy.
struct VersionsUndercount {
    oldest: FileInfo,
    newest: FileInfo,
}

impl MountSource for VersionsUndercount {
    fn list(&self, _path: &str) -> Option<ListResult> {
        Some(ListResult::Infos(Default::default()))
    }
    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/dup.txt.versions/1" {
            return Some(self.oldest.clone());
        }
        if path == "/dup.txt.versions/2" || path == "/dup.txt" {
            let _ = file_version;
            return Some(self.newest.clone());
        }
        if path == "/" {
            return Some(create_root_file_info());
        }
        None
    }
    fn versions(&self, path: &str) -> u32 {
        if normpath(path) == "/dup.txt" {
            1
        } else {
            0
        }
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "versions-undercount stub",
        ))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

/// Regression: complete-TAR multi-frame remount with ignore_zeros sees prefix + new.
#[test]
fn live_commit_tar_zst_complete_frames_ignore_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("cf-prefix");
    let last = generated_payload("cf-last");
    let extra = generated_payload("cf-new");
    let archive = dir.path().join("a.tar.zst");
    write_complete_tar_frames_zst(
        &archive,
        &[
            pack_tar(&[ustar_file("prefix.txt", &prefix)]),
            pack_tar(&[ustar_file("last.txt", &last)]),
        ],
    );
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, true))
        .expect("commit"));
    let src = open_tar_zst_base(&archive, true);
    assert_eq!(read_member(src.as_ref(), "/prefix.txt"), prefix);
    assert_eq!(read_member(src.as_ref(), "/last.txt"), last);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

#[test]
fn live_commit_tar_zst_complete_frames_without_ignore_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("cf0-prefix");
    let last = generated_payload("cf0-last");
    let extra = generated_payload("cf0-new");
    let archive = dir.path().join("a.tar.zst");
    write_complete_tar_frames_zst(
        &archive,
        &[
            pack_tar(&[ustar_file("prefix.txt", &prefix)]),
            pack_tar(&[ustar_file("last.txt", &last)]),
        ],
    );
    let overlay = dir.path().join("ov");
    // Base indexed with -i so last-frame names exist for classification; reopen without.
    let ov = overlay_with_base(open_tar_zst_base(&archive, true), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("commit"));

    // Default parse stops at the first 512-zero block (end of frame 0).
    let default = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(default.as_ref(), "/prefix.txt"), prefix);
    assert!(
        default.lookup("/last.txt", 0).is_none(),
        "without ignore_zeros, last-frame names stay invisible"
    );
    assert!(
        default.lookup("/new.txt", 0).is_none(),
        "new members live after the first frame EOF"
    );

    // The rewritten last complete TAR frame itself contains last + new, not prefix.
    let map = scan_zstd_frames_path(&archive).unwrap();
    let last_idx = map.frames.len() - 1;
    let mut src = File::open(&archive).unwrap();
    let mut last_plain = Vec::new();
    decode_zstd_frames_to(&mut src, &map, last_idx, &mut last_plain).unwrap();
    let last_tar = ratarmount_formats_tar::SqliteIndexedTar::open_from_reader(
        std::io::Cursor::new(last_plain),
        "last-frame.tar",
        None,
        &ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        },
        "test",
    )
    .expect("index last frame");
    assert!(last_tar.lookup("/prefix.txt", 0).is_none());
    assert_eq!(read_member(&last_tar, "/last.txt"), last);
    assert_eq!(read_member(&last_tar, "/new.txt"), extra);
}

/// Multi-frame live splice records the pre-splice cut, not the new length.
#[test]
fn prefix_compressed_bytes_matches_splice_stats() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("plan-prefix");
    let last = generated_payload("plan-last");
    let extra = generated_payload("plan-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("prefix.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let map = scan_zstd_frames_path(&archive).unwrap();
    assert!(map.frames.len() >= 2, "fixture must be multi-frame");
    let (from_idx, _) = find_last_n_tar_window(&archive, &map, "test").unwrap();
    let pre_cut = map.frames[from_idx].compressed_offset;
    assert!(pre_cut > 0, "prefix frames must occupy compressed bytes");

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    assert!(ov.last_publish_plan().is_none());
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("commit"));
    let plan = ov.last_publish_plan().expect("publish plan");
    assert_eq!(
        plan.prefix_compressed_bytes, pre_cut,
        "prefix must equal SpliceStats.prefix_compressed_bytes / pre-splice frames[from_idx].compressed_offset"
    );
    let post_len = fs::metadata(&archive).unwrap().len();
    assert_ne!(
        plan.prefix_compressed_bytes, post_len,
        "prefix cut is not the post-splice file length"
    );
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
    assert!(
        !fs::read_dir(&overlay).unwrap().flatten().any(|e| e
            .file_name()
            .to_string_lossy()
            .starts_with(".ratarmount-spool-")),
        "real spool must not be created inside the overlay"
    );
}

/// Regression: uncompressed TAR publish plan stores prefix 0.
#[test]
fn uncompressed_tar_publish_plan_has_zero_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let tar = make_tiny_tar(dir.path(), &[("old.txt", b"keep\n")]);
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    let ov =
        WriteOverlay::new_for_tests(open_uncompressed_tar_base(&tar, false), &overlay).unwrap();
    fs::write(overlay.join("new.txt"), b"appended\n").unwrap();
    match ov.commit_atomic(&tar) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("commit_atomic: {other:?}"),
    }
    let plan = ov.last_publish_plan().expect("publish plan");
    assert_eq!(plan.prefix_compressed_bytes, 0);
}

/// Schema and 64-hex id match `IndexPointer::for_blob` only after the patch.
#[test]
fn pointer_plan_matches_index_pointer_for_blob() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("ptr-seed");
    let extra = generated_payload("ptr-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let sidecar = ratarmount_index::default_index_path(&archive);
    {
        let body = open_seekable_zstd(&archive).expect("open zstd");
        let opts = OpenOptions {
            ignore_zeros: true,
            gnu_incremental: Some(false),
            ..OpenOptions::default()
        };
        let _ = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
            &archive,
            body,
            Some(&sidecar),
            &opts,
            "test",
        )
        .expect("create sidecar");
    }

    let unpatched =
        index_pointer_plan_after_patch(&sidecar, Some(&archive)).expect("unpatched plan");
    assert_eq!(
        unpatched.pointer.schema,
        ratarmount_index::INDEX_POINTER_SCHEMA
    );
    assert_eq!(
        unpatched.pointer.index_id.len(),
        ratarmount_index::INDEX_ID_HEX_LEN
    );
    assert!(unpatched
        .pointer
        .index_id
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(unpatched.pointer.etag_sha256, unpatched.pointer.index_id);
    let parsed = ratarmount_index::parse_index_pointer_json(&unpatched.json).expect("json");
    assert_eq!(parsed.index_id, unpatched.pointer.index_id);
    assert_eq!(parsed.schema, unpatched.pointer.schema);

    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("commit"));
    let window = ov.last_patch_window().expect("window");
    // Helper does not patch. Hashing here would still be the pre-commit id.
    let still_unpatched =
        index_pointer_plan_after_patch(&sidecar, Some(&archive)).expect("pre-patch plan");
    assert_eq!(still_unpatched.pointer.index_id, unpatched.pointer.index_id);

    patch_sidecar_if_present(
        &archive,
        &window,
        &OpenOptions {
            ignore_zeros: true,
            gnu_incremental: Some(false),
            ..OpenOptions::default()
        },
    )
    .expect("patch sidecar");

    let patched = index_pointer_plan_after_patch(&sidecar, Some(&archive)).expect("patched");
    let direct = IndexPointer::for_blob(&sidecar, Some(&archive)).expect("for_blob");
    assert_eq!(patched.pointer.schema, direct.schema);
    assert_eq!(patched.pointer.index_id, direct.index_id);
    assert_eq!(patched.pointer.etag_sha256, direct.etag_sha256);
    assert_eq!(
        patched.pointer.index_id.len(),
        ratarmount_index::INDEX_ID_HEX_LEN
    );
    assert_ne!(
        patched.pointer.index_id, unpatched.pointer.index_id,
        "hash changes if the helper runs on the unpatched sidecar"
    );
    let parsed = ratarmount_index::parse_index_pointer_json(&patched.json).expect("json");
    assert_eq!(parsed.index_id, direct.index_id);
    assert_eq!(parsed.schema, ratarmount_index::INDEX_POINTER_SCHEMA);
    assert!(!ratarmount_index::index_pointer_path(&archive).exists());
}

#[test]
fn collect_overlay_commit_plan_from_conn_skips_planted_spool_name() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    fs::create_dir_all(&overlay).unwrap();
    fs::write(overlay.join(".ratarmount-spool-x"), b"planted").unwrap();
    fs::write(overlay.join("real.txt"), b"keep").unwrap();
    let names_before = overlay_entry_names(&overlay);
    let plan =
        collect_overlay_commit_plan_from_conn(&overlay, None, None, &HashSet::new()).unwrap();
    assert!(
        plan.append_entries
            .iter()
            .all(|(p, _)| !p.starts_with(".ratarmount-spool-")),
        "planted spool name must not be an append entry: {:?}",
        plan.append_entries
    );
    assert!(plan
        .append_entries
        .iter()
        .any(|(p, is_dir)| p == "real.txt" && !*is_dir));
    assert!(!plan
        .deleted_paths
        .iter()
        .any(|p| p.starts_with(".ratarmount-spool-")));
    assert_eq!(
        overlay_entry_names(&overlay),
        names_before,
        "real spool must not be created in the overlay"
    );
    assert!(overlay.join(".ratarmount-spool-x").is_file());
}

/// Offline `commit_overlay` must not take the live inflight flag.
#[test]
fn commit_overlay_is_not_enqueued() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("off-q-seed");
    let extra = generated_payload("off-q-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    // The live connection holds LOCKING_MODE=EXCLUSIVE. Drop that file
    // handle so offline commit can open the sqlite, without dropping `ov`.
    {
        let mut db = ov.db.lock().expect("overlay db");
        *db = Connection::open_in_memory().expect("release overlay db");
    }
    assert!(commit_overlay(&overlay, &archive, &yes_commit_opts()).expect("commit"));
    assert!(
        !ov.persist_inflight_for_test(),
        "offline commit_overlay must not enqueue"
    );
    let src = open_tar_zst_base(&archive, false);
    assert_eq!(read_member(src.as_ref(), "/new.txt"), extra);
}

fn fresh_spool(src: &Path) -> RemoteDownload {
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .prefix(".ratarmount-spool-")
        .tempfile()
        .unwrap();
    std::io::copy(&mut fs::File::open(src).unwrap(), &mut file).unwrap();
    file.flush().unwrap();
    let len = file.as_file().metadata().unwrap().len();
    RemoteDownload { file, len }
}

/// Local `commit_live` does not call the publish hook, even if one is installed.
#[test]
fn remote_publish_not_called_for_local() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("loc-seed");
    let extra = generated_payload("loc-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    let calls = Arc::new(AtomicU64::new(0));
    let calls_p = Arc::clone(&calls);
    let archive_dl = archive.clone();
    ov.install_remote_live_commit(
        Box::new(|| {
            Ok(RemoteObjectHead {
                etag: Some("\"e\"".into()),
                len: 1,
            })
        }),
        Box::new(move || Ok(fresh_spool(&archive_dl))),
        Box::new(move |_| {
            calls_p.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        Duration::from_secs(120),
    );
    assert!(ov
        .commit_live(&archive, |p| reopen_tar_zst(p, false))
        .expect("local commit"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "direct commit_live must not publish"
    );
}

/// Regression: prefix-frame delete does not call the publish callback.
#[test]
fn earlier_frame_skips_publish() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("efp-prefix");
    let last = generated_payload("efp-last");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("old.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let before = fs::read(&archive).unwrap();
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    ov.unlink("/old.txt").expect("unlink prefix member");
    let calls = Arc::new(AtomicU64::new(0));
    let calls_p = Arc::clone(&calls);
    let archive_dl = archive.clone();
    let len = before.len() as u64;
    ov.install_remote_live_commit(
        Box::new(move || {
            Ok(RemoteObjectHead {
                etag: Some("\"ef\"".into()),
                len,
            })
        }),
        Box::new(move || Ok(fresh_spool(&archive_dl))),
        Box::new(move |_| {
            calls_p.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        Duration::from_secs(120),
    );
    let err = ov
        .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
            panic!("publish/reopen must not run on earlier-frame error")
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("append-only"), "{err}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "prefix-frame delete must not PUT"
    );
    assert!(!ov.interval_disabled());
    assert_eq!(ov.commit_generation(), 0);
    assert_eq!(fs::read(&archive).unwrap(), before);
    assert_eq!(ov.persist_count_for_test(), 1, "splice was attempted once");
}

/// Regression: retry forgets only overlay bytes that were uploaded.
#[test]
fn publish_500_does_not_disable_interval() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("p500-seed");
    let extra = generated_payload("p500-new");
    let during = generated_payload("p500-during");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    let len = fs::metadata(&archive).unwrap().len();
    let fail_once = Arc::new(AtomicU64::new(1));
    let fail_pub = Arc::clone(&fail_once);
    let archive_dl = archive.clone();
    ov.install_remote_live_commit(
        Box::new(move || {
            Ok(RemoteObjectHead {
                etag: Some("\"e1\"".into()),
                len,
            })
        }),
        Box::new(move || Ok(fresh_spool(&archive_dl))),
        Box::new(move |_| {
            if fail_pub.swap(0, Ordering::SeqCst) == 1 {
                Err(RemotePublishError::Retryable("HTTP 500".into()))
            } else {
                Ok(())
            }
        }),
        Duration::from_secs(120),
    );
    let gen = ov.commit_generation();
    let err = ov
        .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
            panic!("500 must not reopen")
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("500"), "{err}");
    assert!(!ov.interval_disabled());
    assert_eq!(ov.commit_generation(), gen);
    assert!(
        overlay.join("new.txt").is_file(),
        "original overlay file stays"
    );
    assert_eq!(ov.persist_count_for_test(), 1);

    fs::write(overlay.join("during.txt"), &during).unwrap();
    assert_eq!(
        ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
            reopen_tar_zst(p, false)
        })
        .expect("retry"),
        CommitOutcome::DidWork
    );
    assert_eq!(
        ov.persist_count_for_test(),
        1,
        "Spliced retry with a matching ETag must not persist again"
    );
    assert!(
        !overlay.join("new.txt").exists(),
        "stashed plan file is gone"
    );
    assert!(
        overlay.join("during.txt").is_file(),
        "file created during the failed PUT stays"
    );
    assert_eq!(ov.commit_generation(), gen + 1);
    assert!(!ov.interval_disabled());
}

/// Regression: a GCS publish failure is not logged as an S3 publish.
#[test]
fn gs_publish_failure_is_not_labeled_s3() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("gs-fail-seed");
    let extra = generated_payload("gs-fail-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    let len = fs::metadata(&archive).unwrap().len();
    let archive_dl = archive.clone();
    ov.install_remote_live_commit_for(
        "gs://bkt/data/a.tar.zst",
        Box::new(move || {
            Ok(RemoteObjectHead {
                etag: Some("\"e1\"".into()),
                len,
            })
        }),
        Box::new(move || Ok(fresh_spool(&archive_dl))),
        Box::new(|_| Err(RemotePublishError::Retryable("HTTP 500".into()))),
        Duration::from_secs(120),
    );
    let err = ov
        .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
            panic!("500 must not reopen")
        })
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with("gs publish failed:"),
        "GCS failure must name gs, not s3: {err}"
    );
    assert!(!err.contains("s3 publish"), "{err}");
    assert!(overlay.join("new.txt").is_file(), "overlay file stays");
}

/// 412 drops `Spliced` and the next tick downloads instead of resplicing.
#[test]
fn etag_mismatch_regets_instead_of_resplicing() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("etag-seed");
    let extra = generated_payload("etag-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    let len = fs::metadata(&archive).unwrap().len();
    let downloads = Arc::new(AtomicU64::new(0));
    let downloads_d = Arc::clone(&downloads);
    let archive_dl = archive.clone();
    let fail_once = Arc::new(AtomicU64::new(1));
    let fail_pub = Arc::clone(&fail_once);
    let paths = Arc::new(std::sync::Mutex::new(Vec::<PathBuf>::new()));
    let paths_p = Arc::clone(&paths);
    ov.install_remote_live_commit(
        Box::new(move || {
            Ok(RemoteObjectHead {
                etag: Some("\"e1\"".into()),
                len,
            })
        }),
        Box::new(move || {
            downloads_d.fetch_add(1, Ordering::SeqCst);
            Ok(fresh_spool(&archive_dl))
        }),
        Box::new(move |req| {
            paths_p.lock().expect("paths").push(req.staged.clone());
            if fail_pub.swap(0, Ordering::SeqCst) == 1 {
                Err(RemotePublishError::EtagMismatch("HTTP 412".into()))
            } else {
                Ok(())
            }
        }),
        Duration::from_secs(120),
    );
    let err = ov
        .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
            panic!("412 must not reopen")
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("412"), "{err}");
    assert_eq!(downloads.load(Ordering::SeqCst), 1);
    assert_eq!(ov.persist_count_for_test(), 1);
    assert_eq!(ov.commit_generation(), 0);
    assert!(overlay.join("new.txt").is_file());
    let first = paths.lock().expect("paths")[0].clone();
    assert!(!first.exists(), "412 must drop the spliced spool");

    assert_eq!(
        ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
            reopen_tar_zst(p, false)
        })
        .expect("redownload tick"),
        CommitOutcome::DidWork
    );
    assert_eq!(downloads.load(Ordering::SeqCst), 2, "next tick downloads");
    assert_eq!(ov.persist_count_for_test(), 2);
    let second = paths.lock().expect("paths")[1].clone();
    assert_ne!(first, second, "must not resplice the old spool");
    assert!(!overlay.join("new.txt").exists());
}

fn spool_from_bytes(bytes: &[u8]) -> RemoteDownload {
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .prefix(".ratarmount-spool-")
        .tempfile()
        .unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    RemoteDownload {
        file,
        len: bytes.len() as u64,
    }
}

fn count_member(bytes: &[u8], dir: &Path, name: &str) -> u32 {
    let stored = dir.join(format!(
        "stored-{}.tar.zst",
        name.trim_start_matches('/').replace('/', "_")
    ));
    fs::write(&stored, bytes).unwrap();
    open_tar_zst_base(&stored, false).versions(name)
}

/// Regression: a PUT that lands and then times out must not splice again.
#[test]
fn remote_publish_timeout_after_landed_put_keeps_one_member() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("land-seed");
    let extra = generated_payload("land-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    let remote = Arc::new(Mutex::new((
        "\"e1\"".to_string(),
        fs::read(&archive).unwrap(),
    )));
    let remote_h = Arc::clone(&remote);
    let remote_dl = Arc::clone(&remote);
    let remote_pub = Arc::clone(&remote);
    let puts = Arc::new(AtomicU64::new(0));
    let puts_p = Arc::clone(&puts);
    ov.install_remote_live_commit(
        Box::new(move || {
            let g = remote_h.lock().expect("remote");
            Ok(RemoteObjectHead {
                etag: Some(g.0.clone()),
                len: g.1.len() as u64,
            })
        }),
        Box::new(move || {
            let bytes = remote_dl.lock().expect("remote").1.clone();
            Ok(spool_from_bytes(&bytes))
        }),
        Box::new(move |req| {
            let n = puts_p.fetch_add(1, Ordering::SeqCst);
            if !req.skip_object_put {
                let bytes = fs::read(&req.staged).expect("staged");
                let mut g = remote_pub.lock().expect("remote");
                g.1 = bytes;
                g.0 = format!("\"put-{n}\"");
            }
            if n == 0 {
                Err(RemotePublishError::Retryable(
                    "timeout after the body was stored".into(),
                ))
            } else {
                Ok(())
            }
        }),
        Duration::from_millis(200),
    );
    let err = ov
        .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
            panic!("timeout must not reopen")
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("timeout"), "{err}");
    assert_eq!(ov.persist_count_for_test(), 1);
    assert!(!ov.interval_disabled());
    assert_eq!(ov.commit_generation(), 0);
    assert!(overlay.join("new.txt").is_file());

    assert_eq!(
        ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
            reopen_tar_zst(p, false)
        })
        .expect("byte-match retry"),
        CommitOutcome::DidWork
    );
    assert_eq!(
        ov.persist_count_for_test(),
        1,
        "object that already contains the splice must not be persisted again"
    );
    assert!(
        !overlay.join("new.txt").exists(),
        "success path forgets only the stashed plan"
    );
    assert_eq!(ov.commit_generation(), 1);
    assert!(!ov.interval_disabled());
    let stored = remote.lock().expect("remote").1.clone();
    assert_eq!(
        count_member(&stored, dir.path(), "/new.txt"),
        1,
        "one copy of the member"
    );
    assert_eq!(count_member(&stored, dir.path(), "/seed.txt"), 1);
}

/// A moved ETag whose bytes differ is a concurrent writer: splice onto that object once.
#[test]
fn remote_publish_concurrent_object_is_spliced_once() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("conc-seed");
    let other_seed = generated_payload("conc-other");
    let extra = generated_payload("conc-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let other = dir.path().join("other.tar.zst");
    write_single_frame_tar_zst(&other, &[ustar_file("other.txt", &other_seed)]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    let remote = Arc::new(Mutex::new((
        "\"e1\"".to_string(),
        fs::read(&archive).unwrap(),
    )));
    let remote_h = Arc::clone(&remote);
    let remote_dl = Arc::clone(&remote);
    let remote_pub = Arc::clone(&remote);
    let puts = Arc::new(AtomicU64::new(0));
    let puts_p = Arc::clone(&puts);
    ov.install_remote_live_commit(
        Box::new(move || {
            let g = remote_h.lock().expect("remote");
            Ok(RemoteObjectHead {
                etag: Some(g.0.clone()),
                len: g.1.len() as u64,
            })
        }),
        Box::new(move || {
            let bytes = remote_dl.lock().expect("remote").1.clone();
            Ok(spool_from_bytes(&bytes))
        }),
        Box::new(move |req| {
            let n = puts_p.fetch_add(1, Ordering::SeqCst);
            if !req.skip_object_put {
                let bytes = fs::read(&req.staged).expect("staged");
                let mut g = remote_pub.lock().expect("remote");
                g.1 = bytes;
                g.0 = format!("\"put-{n}\"");
            }
            if n == 0 {
                Err(RemotePublishError::Retryable(
                    "timeout after the body was stored".into(),
                ))
            } else {
                Ok(())
            }
        }),
        Duration::from_millis(200),
    );
    let err = ov
        .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
            panic!("timeout must not reopen")
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("timeout"), "{err}");
    {
        let mut g = remote.lock().expect("remote");
        g.0 = "\"concurrent\"".into();
        g.1 = fs::read(&other).unwrap();
    }
    assert_eq!(
        ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
            reopen_tar_zst(p, false)
        })
        .expect("splice onto concurrent object"),
        CommitOutcome::DidWork
    );
    assert_eq!(ov.persist_count_for_test(), 2);
    let stored = remote.lock().expect("remote").1.clone();
    assert_eq!(count_member(&stored, dir.path(), "/new.txt"), 1);
    assert_eq!(count_member(&stored, dir.path(), "/other.txt"), 1);
    assert_eq!(count_member(&stored, dir.path(), "/seed.txt"), 0);
}

/// Regression: a refused partial window forgets the overlay once the object
/// body already matches the spool, so a remount does not append again.
#[test]
fn publish_refuses_partial_window_forgets_matching_object() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = generated_payload("pref-keep");
    let last = generated_payload("last-keep");
    let extra = generated_payload("partial-new");
    let archive = dir.path().join("a.tar.zst");
    write_split_tar_zst(
        &archive,
        &[ustar_file("old.txt", &prefix)],
        &[ustar_file("last.txt", &last)],
        false,
    );
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_tar_zst_base(&archive, false), &overlay);
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    let remote = Arc::new(Mutex::new((
        "\"e1\"".to_string(),
        fs::read(&archive).unwrap(),
    )));
    let remote_h = Arc::clone(&remote);
    let remote_dl = Arc::clone(&remote);
    let remote_pub = Arc::clone(&remote);
    let puts = Arc::new(AtomicU64::new(0));
    let puts_p = Arc::clone(&puts);
    ov.install_remote_live_commit(
        Box::new(move || {
            let g = remote_h.lock().expect("remote");
            Ok(RemoteObjectHead {
                etag: Some(g.0.clone()),
                len: g.1.len() as u64,
            })
        }),
        Box::new(move || {
            let bytes = remote_dl.lock().expect("remote").1.clone();
            Ok(spool_from_bytes(&bytes))
        }),
        Box::new(move |req| {
            let n = puts_p.fetch_add(1, Ordering::SeqCst);
            if !req.skip_object_put {
                let bytes = fs::read(&req.staged).expect("staged");
                let mut g = remote_pub.lock().expect("remote");
                g.1 = bytes;
                g.0 = format!("\"put-{n}\"");
            }
            if n == 0 {
                return Err(RemotePublishError::Retryable(
                    "timeout after the body was stored".into(),
                ));
            }
            assert!(
                req.skip_object_put,
                "second publish must see the object that already matches the spool"
            );
            assert!(
                req.window.window_start > 0,
                "last-frame splice must keep a partial window"
            );
            Err(RemotePublishError::PointerRefused(
                "sidecar file table was not rebuilt from the uploaded spool; leaving the previous pointer"
                    .into(),
            ))
        }),
        Duration::from_millis(200),
    );
    let err = ov
        .enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
            panic!("timeout must not reopen")
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("timeout"), "{err}");
    assert!(overlay.join("new.txt").is_file());
    assert_eq!(ov.persist_count_for_test(), 1);

    assert_eq!(
        ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |p| {
            reopen_tar_zst(p, false)
        })
        .expect("pointer refusal forgets the stashed plan"),
        CommitOutcome::DidWork
    );
    assert!(
        !overlay.join("new.txt").exists(),
        "refused partial window must not leave the overlay file in place"
    );
    assert_eq!(ov.persist_count_for_test(), 1);
    assert!(!ov.interval_disabled());
    let stored = remote.lock().expect("remote").1.clone();
    assert_eq!(count_member(&stored, dir.path(), "/new.txt"), 1);
    assert_eq!(count_member(&stored, dir.path(), "/old.txt"), 1);
    assert_eq!(
        ov.enqueue_commit(&archive, CommitKind::IntervalIdle(Duration::ZERO), |_| {
            panic!("empty overlay must not publish")
        })
        .expect("nothing left to splice"),
        CommitOutcome::Nothing
    );
    assert_eq!(ov.persist_count_for_test(), 1);
}

/// Regression: remote on-exit must not wait forever for a new interval PUT.
#[test]
fn remote_on_exit_bounds_wait_without_disabling() {
    let dir = tempfile::tempdir().unwrap();
    let seed = generated_payload("exit-seed");
    let extra = generated_payload("exit-new");
    let archive = dir.path().join("a.tar.zst");
    write_single_frame_tar_zst(&archive, &[ustar_file("seed.txt", &seed)]);
    let overlay = dir.path().join("ov");
    let ov = Arc::new(overlay_with_base(
        open_tar_zst_base(&archive, false),
        &overlay,
    ));
    fs::write(overlay.join("new.txt"), &extra).unwrap();
    let puts = Arc::new(AtomicU64::new(0));
    let puts_p = Arc::clone(&puts);
    let archive_dl = archive.clone();
    ov.set_persist_delay_for_test(Duration::from_secs(5));
    ov.set_on_exit_wait_min_for_test(Duration::from_millis(50));
    ov.install_remote_live_commit(
        Box::new(|| {
            Ok(RemoteObjectHead {
                etag: Some("\"e\"".into()),
                len: 1,
            })
        }),
        Box::new(move || Ok(fresh_spool(&archive_dl))),
        Box::new(move |_| {
            puts_p.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        Duration::from_millis(200),
    );
    let ov_i = Arc::clone(&ov);
    let archive_i = archive.clone();
    let worker = std::thread::spawn(move || {
        ov_i.enqueue_commit(&archive_i, CommitKind::IntervalIdle(Duration::ZERO), |p| {
            reopen_tar_zst(p, false)
        })
    });
    let started = Instant::now();
    while !ov.persist_inflight_for_test() && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        ov.persist_inflight_for_test(),
        "interval thread did not take the inflight flag"
    );
    let t0 = Instant::now();
    let err = ov
        .enqueue_commit(&archive, CommitKind::OnExit, |_| unreachable!())
        .unwrap_err();
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "remote on-exit waited {elapsed:?}"
    );
    assert!(
        err.to_string().contains("timed out"),
        "expected timeout, got {err}"
    );
    assert!(!ov.interval_disabled());
    assert_eq!(ov.persist_count_for_test(), 0, "timeout must not splice");
    assert_eq!(ov.commit_generation(), 0);
    assert_eq!(
        puts.load(Ordering::SeqCst),
        0,
        "interval must not start a PUT during the on-exit wait"
    );
    assert!(overlay.join("new.txt").is_file());
    let _ = worker.join().expect("interval thread");
}

/// In-memory archive: each path has a body the COW path can read.
struct MemBase {
    files: BTreeMap<String, FileInfo>,
    bodies: BTreeMap<String, Vec<u8>>,
}

impl MemBase {
    fn with(entries: &[(&str, &[u8])]) -> Self {
        let mut files = BTreeMap::new();
        let mut bodies = BTreeMap::new();
        for (path, body) in entries {
            bodies.insert((*path).to_string(), body.to_vec());
            files.insert((*path).to_string(), mem_file_info(path, body.len() as u64));
        }
        Self { files, bodies }
    }

    fn with_dir(path: &str) -> Self {
        let mut files = BTreeMap::new();
        files.insert(
            path.to_string(),
            FileInfo {
                size: 0,
                mtime: 0.0,
                mode: ratarmount_core::S_IFDIR | 0o755,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            },
        );
        Self {
            files,
            bodies: BTreeMap::new(),
        }
    }
}

fn mem_file_info(path: &str, size: u64) -> FileInfo {
    FileInfo {
        size,
        mtime: 0.0,
        mode: ratarmount_core::S_IFREG | 0o644,
        linkname: String::new(),
        uid: 0,
        gid: 0,
        userdata: vec![
            UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                offset: 0,
                offsetheader: Some(0),
                istar: true,
                issparse: false,
                isgenerated: false,
                recursiondepth: 0,
            }),
            UserData::Other(format!("mem:{path}")),
        ],
    }
}

impl MountSource for MemBase {
    fn list(&self, path: &str) -> Option<ListResult> {
        if path != "/" {
            return None;
        }
        let mut map = BTreeMap::new();
        for (path, fi) in &self.files {
            let name = path.trim_start_matches('/');
            if !name.is_empty() && !name.contains('/') {
                map.insert(name.to_string(), fi.clone());
            }
        }
        Some(ListResult::Infos(map))
    }

    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        if path == "/" {
            Some(create_root_file_info())
        } else {
            self.files.get(path).cloned()
        }
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        let path = file_info.userdata.iter().rev().find_map(|u| match u {
            UserData::Other(s) => s.strip_prefix("mem:"),
            _ => None,
        });
        let Some(path) = path else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "mem base"));
        };
        let body = self.bodies.get(path).cloned().unwrap_or_default();
        Ok(Box::new(std::io::Cursor::new(body)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn put_overlay_bytes(ov: &WriteOverlay, path: &str, bytes: &[u8]) {
    let fd = ov.create_file(path, 0o644).unwrap();
    let n = unsafe { libc::write(fd, bytes.as_ptr() as *const _, bytes.len()) };
    assert_eq!(n as usize, bytes.len(), "write {path}");
    unsafe { libc::close(fd) };
}

fn is_overlay_fi(fi: &FileInfo) -> bool {
    matches!(fi.userdata.last(), Some(UserData::Other(s)) if s.starts_with("overlay:"))
}

fn deleted_flag(ov: &WriteOverlay, path: &str) -> Option<i64> {
    ov.files_deleted_flag(path).expect("files row")
}

fn host_ino(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).unwrap().ino()
}

fn fd_ino(fd: &impl std::os::unix::io::AsRawFd) -> u64 {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    assert_eq!(rc, 0, "fstat: {}", io::Error::last_os_error());
    st.st_ino as u64
}

/// Regression: rename-over must not unlink first (#88). Overlay-backed,
/// archive-only, and tombstoned targets each end on the new bytes.
#[test]
fn rename_over_overlay_archive_and_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    put_overlay_bytes(&ov, "/final", b"old-dest");
    put_overlay_bytes(&ov, "/swap", b"new-src");
    let parked = ov
        .rename_parked("/swap", "/final")
        .expect("overlay rename")
        .expect("overlay-backed target is parked");
    let (fi, fd) = parked.into_parts();
    assert!(fd.is_some(), "regular file park keeps an fd");
    assert_eq!(fi.size, b"old-dest".len() as u64);
    drop(fd);
    assert_eq!(fs::read(overlay.join("final")).unwrap(), b"new-src");
    assert!(ov.lookup("/swap", 0).is_none());
    assert!(!ov.is_deleted("/swap"));
    assert!(!ov.is_deleted("/final"));
    let fi = ov.lookup("/final", 0).expect("final");
    assert!(is_overlay_fi(&fi));
    assert_eq!(deleted_flag(&ov, "/final"), Some(0));
    assert_eq!(deleted_flag(&ov, "/swap"), None);
    ov.mkdir("/dir", 0o755).unwrap();
    put_overlay_bytes(&ov, "/file", b"keep");
    let err = ov.rename("/file", "/dir").expect_err("directory target");
    match err {
        OverlayError::Io(e) => {
            assert_eq!(e.kind(), io::ErrorKind::AlreadyExists, "{e}");
        }
        other => panic!("expected Io, got {other}"),
    }
    assert_eq!(fs::read(overlay.join("file")).unwrap(), b"keep");
    assert!(ratarmount_core::is_dir_mode(
        ov.lookup("/dir", 0).expect("dir").mode
    ));

    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[
        ("/src", b"archive-src"),
        ("/final", b"archive-final"),
    ])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
    assert!(!is_overlay_fi(&ov.lookup("/final", 0).unwrap()));
    let parked = ov.rename_parked("/src", "/final").expect("archive rename");
    assert!(parked.is_none(), "archive-only target has no host inode");
    assert_eq!(fs::read(overlay.join("final")).unwrap(), b"archive-src");
    assert!(is_overlay_fi(&ov.lookup("/final", 0).unwrap()));
    assert!(
        ov.lookup("/src", 0).is_none(),
        "archive source is tombstoned"
    );
    assert!(ov.is_deleted("/src"));
    assert!(!ov.is_deleted("/final"));
    assert_eq!(deleted_flag(&ov, "/src"), Some(1));
    assert_eq!(deleted_flag(&ov, "/final"), Some(0));
    drop(ov);
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    assert!(
        ov.is_deleted("/src"),
        "persisted tombstone hides the archive source"
    );
    assert_eq!(fs::read(overlay.join("final")).unwrap(), b"archive-src");
    assert!(is_overlay_fi(&ov.lookup("/final", 0).unwrap()));

    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[("/final", b"archived")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    ov.unlink("/final").unwrap();
    assert!(ov.lookup("/final", 0).is_none());
    assert!(ov.is_deleted("/final"));
    assert!(!overlay.join("final").exists());
    put_overlay_bytes(&ov, "/swap", b"replacement");
    let parked = ov
        .rename_parked("/swap", "/final")
        .expect("rename over tombstone");
    assert!(parked.is_none(), "tombstoned target has no host inode yet");
    assert!(!ov.is_deleted("/final"));
    assert!(is_overlay_fi(&ov.lookup("/final", 0).expect("visible")));
    assert_eq!(fs::read(overlay.join("final")).unwrap(), b"replacement");
    assert_eq!(deleted_flag(&ov, "/final"), Some(0));
    assert!(ov.lookup("/swap", 0).is_none());
}

/// Lookup oracles must fail instead of spinning when the in-memory rename
/// update disappears. `thread::scope` joins every child, so a parent assert
/// that never sets `stop` would hang the child until the job is killed.
const LOOKUP_ORACLE_DEADLINE: Duration = Duration::from_secs(10);

struct StopLookupOnDrop<'a>(&'a AtomicBool);

impl Drop for StopLookupOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn assert_lookup_oracle_deadline(deadline: Instant, waiting_for: &str) {
    assert!(
        Instant::now() < deadline,
        "lookup loop exceeded 10s waiting for {waiting_for}; a missing in-memory rename update must fail the test, not hang"
    );
}

/// Regression: a visible rename-over target never resolves as missing (#88).
#[test]
fn rename_visible_lookup_never_none() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    put_overlay_bytes(&ov, "/final", b"seed");
    let nones = AtomicU64::new(0);
    let samples = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let some_to_none = std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let deadline = Instant::now() + LOOKUP_ORACLE_DEADLINE;
            let mut prev = true;
            let mut flips = 0u64;
            while !stop.load(Ordering::SeqCst) {
                assert_lookup_oracle_deadline(deadline, "the rename loop to stop");
                let some = ov.lookup("/final", 0).is_some();
                samples.fetch_add(1, Ordering::SeqCst);
                if !some {
                    nones.fetch_add(1, Ordering::SeqCst);
                }
                if prev && !some {
                    flips += 1;
                }
                prev = some;
            }
            flips
        });
        // Drop sets `stop` before `handle` joins, including when an assert
        // panics. Declared after `handle` so it runs first.
        let _stop_on_unwind = StopLookupOnDrop(&stop);
        let start = Instant::now();
        while samples.load(Ordering::SeqCst) == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "lookup loop did not start"
            );
            std::thread::yield_now();
        }
        for i in 0..80 {
            put_overlay_bytes(&ov, "/swap", format!("n{i:04}").as_bytes());
            ov.rename("/swap", "/final").expect("rename");
        }
        stop.store(true, Ordering::SeqCst);
        handle.join().expect("lookup thread")
    });
    assert!(samples.load(Ordering::SeqCst) > 0);
    assert_eq!(
        nones.load(Ordering::SeqCst),
        0,
        "visible target was None in {} lookups",
        samples.load(Ordering::SeqCst)
    );
    assert_eq!(some_to_none, 0);
    assert_eq!(fs::read(overlay.join("final")).unwrap(), b"n0079");
    assert!(ov.lookup("/swap", 0).is_none());
}

/// Regression: a tombstoned target stays missing until the rename commits,
/// then becomes visible once (#88).
#[test]
fn rename_tombstone_lookup_none_to_some_once() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov = WriteOverlay::new_for_tests(
        Arc::new(MemBase::with(&[("/final", b"archived")])) as Arc<dyn MountSource>,
        &overlay,
    )
    .unwrap();
    ov.unlink("/final").unwrap();
    assert!(ov.lookup("/final", 0).is_none());
    let seen_none = AtomicBool::new(false);
    let none_to_some = AtomicU64::new(0);
    let some_to_none = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let deadline = Instant::now() + LOOKUP_ORACLE_DEADLINE;
            let mut prev = false;
            let mut saw_none = false;
            while !stop.load(Ordering::SeqCst) {
                assert_lookup_oracle_deadline(deadline, "stop after None->Some");
                let some = ov.lookup("/final", 0).is_some();
                if !some {
                    saw_none = true;
                    seen_none.store(true, Ordering::SeqCst);
                }
                if !prev && some && saw_none {
                    none_to_some.fetch_add(1, Ordering::SeqCst);
                }
                if prev && !some {
                    some_to_none.fetch_add(1, Ordering::SeqCst);
                }
                prev = some;
                std::thread::yield_now();
            }
        });
        // Drop sets `stop` before `handle` joins, including when an assert
        // panics. Declared after `handle` so it runs first.
        let _stop_on_unwind = StopLookupOnDrop(&stop);
        let start = Instant::now();
        while !seen_none.load(Ordering::SeqCst) {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "lookup loop did not observe the tombstone"
            );
            std::thread::yield_now();
        }
        put_overlay_bytes(&ov, "/swap", b"replacement");
        ov.rename("/swap", "/final").unwrap();
        let start = Instant::now();
        while none_to_some.load(Ordering::SeqCst) == 0 {
            assert!(
                start.elapsed() < LOOKUP_ORACLE_DEADLINE,
                "lookup loop exceeded 10s waiting for None->Some; a missing in-memory rename update must fail the test, not hang (some_to_none={})",
                some_to_none.load(Ordering::SeqCst)
            );
            std::thread::yield_now();
        }
        stop.store(true, Ordering::SeqCst);
        handle.join().expect("lookup thread");
    });
    assert_eq!(none_to_some.load(Ordering::SeqCst), 1);
    assert_eq!(some_to_none.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(overlay.join("final")).unwrap(), b"replacement");
}

/// Regression: a failed tombstone transaction after the host rename still
/// returns success. When every retry fails, durable state matches the #88
/// crash table and the rows sit in `pending_rows`. Drop tries one last
/// replay; when that also fails, the queue is lost the same way a process
/// crash loses it. This session's tombstones match the completed rename.
/// Same-session replay is covered by the commit test.
#[test]
fn rename_tx_failure_matches_crash_table() {
    // Visible `to`, archive `from`: `from` reappears from the archive.
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[("/src", b"archive-src")])) as Arc<dyn MountSource>;
    let ov = Arc::new(WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap());
    put_overlay_bytes(&ov, "/dst", b"old-dest");
    let probe = Arc::downgrade(&ov);
    let host = overlay.clone();
    // The one-shot hook fails only the first attempt and does not consume a
    // failure. Two retries consume 2. Drop's replay gets three more attempts;
    // 8 leaves those failing so the queue is lost like a crash.
    ov.set_rename_tx_failures(8);
    ov.set_rename_before_tx_hook(Some(Box::new(move || {
        let probe = probe.upgrade().expect("overlay");
        assert_eq!(fs::read(host.join("dst")).unwrap(), b"archive-src");
        assert!(!host.join("src").exists());
        let src = probe.lookup("/src", 0).expect("archive from reappears");
        assert!(
            !is_overlay_fi(&src),
            "crash window serves the archive member"
        );
        assert!(is_overlay_fi(&probe.lookup("/dst", 0).unwrap()));
        assert_eq!(deleted_flag(&probe, "/src"), None);
        assert_eq!(deleted_flag(&probe, "/dst"), Some(0));
        Err(OverlayError::Msg("injected rename tx failure".into()))
    })));
    ov.rename_parked("/src", "/dst")
        .expect("tx failure still returns success");
    assert!(ov.pending_row_count() >= 1, "queued the failed rename");
    assert!(ov.is_deleted("/src"), "in-memory tombstone applied");
    assert!(ov.lookup("/src", 0).is_none());
    assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));
    assert_eq!(
        deleted_flag(&ov, "/src"),
        None,
        "db still has no from tombstone"
    );
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"archive-src");
    drop(ov);
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    let src = ov
        .lookup("/src", 0)
        .expect("duplicate archive member accepted");
    assert!(!is_overlay_fi(&src));
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"archive-src");
    assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));

    // Overlay-only `from`: lookup is None and a stale deleted=0 row remains.
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov = Arc::new(
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap(),
    );
    put_overlay_bytes(&ov, "/dst", b"old-dest");
    put_overlay_bytes(&ov, "/src", b"new-src");
    let probe = Arc::downgrade(&ov);
    let host = overlay.clone();
    // Same budget as the archive-from case: Drop's replay must also fail.
    ov.set_rename_tx_failures(8);
    ov.set_rename_before_tx_hook(Some(Box::new(move || {
        let probe = probe.upgrade().expect("overlay");
        assert_eq!(fs::read(host.join("dst")).unwrap(), b"new-src");
        assert!(!host.join("src").exists());
        assert!(probe.lookup("/src", 0).is_none());
        assert!(is_overlay_fi(&probe.lookup("/dst", 0).unwrap()));
        assert_eq!(deleted_flag(&probe, "/src"), Some(0));
        Err(OverlayError::Msg("injected rename tx failure".into()))
    })));
    ov.rename("/src", "/dst").expect("success");
    assert!(ov.pending_row_count() >= 1, "queued the failed rename");
    assert!(!ov.is_deleted("/src"));
    assert!(ov.lookup("/src", 0).is_none());
    assert_eq!(deleted_flag(&ov, "/src"), Some(0), "stale present row kept");
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new-src");
    drop(ov);
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    assert!(ov.lookup("/src", 0).is_none());
    assert_eq!(deleted_flag(&ov, "/src"), Some(0));
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new-src");

    // Tombstoned `to`: hidden until open recovery, which must keep the bytes.
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[("/dst", b"archived")])) as Arc<dyn MountSource>;
    let ov = Arc::new(WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap());
    ov.unlink("/dst").unwrap();
    put_overlay_bytes(&ov, "/src", b"replacement");
    let probe = Arc::downgrade(&ov);
    let host = overlay.clone();
    // Same budget as the archive-from case: Drop's replay must also fail.
    ov.set_rename_tx_failures(8);
    ov.set_rename_before_tx_hook(Some(Box::new(move || {
        let probe = probe.upgrade().expect("overlay");
        assert_eq!(fs::read(host.join("dst")).unwrap(), b"replacement");
        assert!(probe.lookup("/dst", 0).is_none(), "still tombstoned");
        assert!(probe.is_deleted("/dst"));
        assert_eq!(deleted_flag(&probe, "/dst"), Some(1));
        Err(OverlayError::Msg("injected rename tx failure".into()))
    })));
    ov.rename("/src", "/dst").expect("success");
    assert!(ov.pending_row_count() >= 1, "queued the failed rename");
    assert!(!ov.is_deleted("/dst"), "in-memory clear");
    assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));
    assert_eq!(deleted_flag(&ov, "/dst"), Some(1), "db row still deleted");
    drop(ov);
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    assert!(!ov.is_deleted("/dst"), "open clears the tombstone");
    assert_eq!(deleted_flag(&ov, "/dst"), Some(0));
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"replacement");
    assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));
}

/// Regression: opening the overlay clears a tombstone that has a host file
/// and leaves a tombstone with no host file (#88). Recovery does not
/// delete the host file.
#[test]
fn clear_tombstone_with_host_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[
        ("/keep.txt", b"archived-keep"),
        ("/other.txt", b"archived-other"),
    ])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
    ov.unlink("/keep.txt").unwrap();
    ov.unlink("/other.txt").unwrap();
    assert!(ov.is_deleted("/keep.txt"));
    assert!(ov.is_deleted("/other.txt"));
    fs::write(overlay.join("keep.txt"), b"hidden-but-committed").unwrap();
    drop(ov);

    let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
    assert!(!ov.is_deleted("/keep.txt"));
    assert!(is_overlay_fi(&ov.lookup("/keep.txt", 0).expect("visible")));
    assert_eq!(
        fs::read(overlay.join("keep.txt")).unwrap(),
        b"hidden-but-committed"
    );
    assert_eq!(deleted_flag(&ov, "/keep.txt"), Some(0));
    assert!(ov.is_deleted("/other.txt"));
    assert!(ov.lookup("/other.txt", 0).is_none());
    assert_eq!(deleted_flag(&ov, "/other.txt"), Some(1));
    assert!(overlay.join(HIDDEN_DB).is_file());
    assert!(overlay.join(OVERLAY_MARKER).is_file());
    drop(ov);

    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    assert!(!ov.is_deleted("/keep.txt"), "clear was persisted");
    assert!(ov.is_deleted("/other.txt"));
    assert_eq!(
        fs::read(overlay.join("keep.txt")).unwrap(),
        b"hidden-but-committed"
    );
}

/// Regression: a host directory with the same name as a tombstone does not
/// clear that tombstone on open (#88).
///
/// Parent directories are created for nested overlay files (`ensure_parent`
/// / `create_dir_all`) while a directory tombstone stays set. That directory
/// is not evidence the archive directory was replaced. Clearing it would
/// resurrect the archive directory and its children. Only a non-directory
/// host entry (file or symlink) is the crash window that should become visible.
#[test]
fn clear_tombstone_keeps_host_directory() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with_dir("/sub")) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
    ov.rmdir("/sub").expect("tombstone the archive directory");
    assert!(ov.is_deleted("/sub"));
    assert_eq!(deleted_flag(&ov, "/sub"), Some(1));
    assert!(!overlay.join("sub").exists());
    fs::create_dir(overlay.join("sub")).unwrap();
    drop(ov);

    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    assert!(
        overlay.join("sub").is_dir(),
        "open must not delete the host directory"
    );
    assert!(
        ov.is_deleted("/sub"),
        "a host directory must not clear the tombstone"
    );
    assert_eq!(deleted_flag(&ov, "/sub"), Some(1));
    assert!(ov.lookup("/sub", 0).is_none());
}

/// Regression: one injected tombstone failure is retried and the rename
/// commits. The caller sees success and nothing is queued (#88).
#[test]
fn rename_tx_retry_transient() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[("/src", b"archive-src")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    ov.set_rename_tx_failures(1);
    ov.rename_parked("/src", "/dst")
        .expect("a single transient failure is retried");
    assert_eq!(ov.pending_row_count(), 0, "retry committed; nothing queued");
    assert_eq!(deleted_flag(&ov, "/src"), Some(1));
    assert_eq!(deleted_flag(&ov, "/dst"), Some(0));
    assert!(ov.is_deleted("/src"));
    assert!(ov.lookup("/src", 0).is_none());
    assert!(is_overlay_fi(&ov.lookup("/dst", 0).unwrap()));
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"archive-src");
}

/// Regression: queued rename rows are written at the start of the next
/// `files` update (`mark_present`), not only at commit time (#88).
#[test]
fn rename_tx_pending_replays_on_next_db_write() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[("/src", b"archive-src")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
    ov.rename("/src", "/dst").expect("rename returns success");
    assert_eq!(ov.pending_row_count(), 1);
    assert_eq!(deleted_flag(&ov, "/src"), None, "sql missed the tombstone");
    assert!(ov.is_deleted("/src"), "memory already hides from");
    ov.set_rename_tx_failures(0);
    put_overlay_bytes(&ov, "/other", b"trigger-replay");
    assert_eq!(
        ov.pending_row_count(),
        0,
        "mark_present replayed the queued rename"
    );
    assert_eq!(deleted_flag(&ov, "/src"), Some(1));
    assert_eq!(deleted_flag(&ov, "/dst"), Some(0));
    assert!(ov.is_deleted("/src"));
    assert!(ov.lookup("/src", 0).is_none());
    assert_eq!(fs::read(overlay.join("other")).unwrap(), b"trigger-replay");
}

/// Regression: a persistent tombstone-tx failure must not let `commit_live`
/// publish an archive `from` that the mount already hides (#88).
///
/// While the fault is installed, commit refuses (the plan would omit the
/// `from` delete, then the overlay reset would show `from` again). After
/// the fault is cleared, the next commit replays the queued rows and
/// deletes `from` from the archive.
#[test]
fn rename_tx_pending_commit_refuses_then_replays() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"pending-src-payload\n";
    let tar = make_tiny_tar(dir.path(), &[("src.txt", payload), ("keep.txt", b"keep\n")]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_uncompressed_tar_base(&tar, true), &overlay);
    // Rename retries plus the commit's replay retries.
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 2);
    ov.rename("/src.txt", "/dst.txt")
        .expect("rename returns success");
    assert!(ov.pending_row_count() >= 1);
    assert!(ov.is_deleted("/src.txt"));
    assert!(
        ov.lookup("/src.txt", 0).is_none(),
        "mount hides archive from"
    );
    assert_eq!(
        deleted_flag(&ov, "/src.txt"),
        None,
        "sql has no from tombstone yet"
    );
    assert_eq!(fs::read(overlay.join("dst.txt")).unwrap(), payload);

    match ov.commit_live(&tar, |p| Ok(open_uncompressed_tar_base(p, true))) {
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("refusing to commit") && msg.contains("reappear"),
                "{msg}"
            );
        }
        Ok(published) => {
            panic!("commit published while rename rows were pending: {published}")
        }
    }
    assert!(
        ov.lookup("/src.txt", 0).is_none(),
        "refused commit must keep from hidden"
    );
    assert!(ov.is_deleted("/src.txt"));
    assert!(
        ov.pending_row_count() >= 1,
        "rows stay queued after the refusal"
    );
    let mid = open_uncompressed_tar_base(&tar, true);
    assert!(
        mid.lookup("/src.txt", 0).is_some(),
        "refused commit must leave the archive member in place"
    );
    assert!(
        mid.lookup("/dst.txt", 0).is_none(),
        "refused commit must not append dst"
    );

    ov.set_rename_tx_failures(0);
    match ov.commit_live(&tar, |p| Ok(open_uncompressed_tar_base(p, true))) {
        Ok(true) => {}
        Err(e) if soft_skip_gnu_tar_commit(&e) => {
            eprintln!("skip: {e}");
            return;
        }
        other => panic!("replay commit: {other:?}"),
    }
    assert_eq!(ov.pending_row_count(), 0, "replay drained the queue");
    let after = open_uncompressed_tar_base(&tar, true);
    assert!(
        after.lookup("/src.txt", 0).is_none(),
        "replayed tombstone deleted archive from; it must not stay as a duplicate"
    );
    assert_eq!(read_member(after.as_ref(), "/dst.txt"), payload);
    assert!(
        ov.lookup("/src.txt", 0).is_none(),
        "mount must not show a duplicate from"
    );
    assert!(after.lookup("/keep.txt", 0).is_some());
    let dst = ov.lookup("/dst.txt", 0).expect("dst visible after commit");
    assert_eq!(dst.size, payload.len() as u64);
}

/// Regression: archive `/a` and `/x`, rename `a`→`x` queued, then `x`→`y`
/// while replay still fails. The second rename must stay behind the first.
/// After the fault clears, remount must hide `/a` and `/x` and show `/y`
/// (#88). Replaying `a`→`x` after `x`→`y` would mark `/x` present again.
#[test]
fn rename_tx_pending_second_rename_keeps_intermediate_hidden() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base =
        Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
    // First rename's direct attempts, then the second rename's replay.
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 2);
    ov.rename("/a", "/x").expect("a->x returns success");
    assert_eq!(ov.pending_row_count(), 1, "a->x queued");
    assert_eq!(deleted_flag(&ov, "/a"), None, "sql has no a tombstone yet");
    ov.rename("/x", "/y").expect("x->y returns success");
    assert_eq!(ov.pending_row_count(), 2, "x->y appended behind a->x");
    assert_eq!(deleted_flag(&ov, "/a"), None);
    assert_eq!(
        deleted_flag(&ov, "/x"),
        None,
        "x->y must not tombstone x while a->x is still queued"
    );
    assert_eq!(deleted_flag(&ov, "/y"), None);
    assert!(ov.lookup("/a", 0).is_none(), "mount hides a");
    assert!(ov.lookup("/x", 0).is_none(), "mount hides x");
    assert!(is_overlay_fi(&ov.lookup("/y", 0).expect("y visible")));
    assert_eq!(fs::read(overlay.join("y")).unwrap(), b"from-a");

    ov.set_rename_tx_failures(0);
    drop(ov);
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    assert_eq!(deleted_flag(&ov, "/a"), Some(1));
    assert_eq!(deleted_flag(&ov, "/x"), Some(1), "/x must stay deleted");
    assert_eq!(deleted_flag(&ov, "/y"), Some(0));
    assert!(ov.lookup("/a", 0).is_none(), "remount must not show /a");
    assert!(
        ov.lookup("/x", 0).is_none(),
        "remount must not show /x; a later a->x replay would resurrect it"
    );
    let y = ov.lookup("/y", 0).expect("/y present");
    assert!(is_overlay_fi(&y));
    assert_eq!(fs::read(overlay.join("y")).unwrap(), b"from-a");
}

/// Regression: replay holds `pending_rows` across take, the failure path,
/// and restore. A contending rename must not write `/x` while `a`→`x` is
/// off the queue (#88).
#[test]
fn rename_tx_pending_replay_holds_queue_lock() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base =
        Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")])) as Arc<dyn MountSource>;
    let ov = Arc::new(WriteOverlay::new_for_tests(base, &overlay).unwrap());
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
    ov.rename("/a", "/x").expect("a->x queued");
    assert_eq!(ov.pending_row_count(), 1);
    ov.set_rename_tx_failures(0);

    let in_replay = Arc::new(AtomicBool::new(false));
    let t2_tried = Arc::new(AtomicBool::new(false));
    let lock_was_held = Arc::new(AtomicBool::new(false));
    let in_replay_hook = Arc::clone(&in_replay);
    let t2_tried_hook = Arc::clone(&t2_tried);
    ov.set_replay_hold_hook(Some(Box::new(move || {
        in_replay_hook.store(true, Ordering::SeqCst);
        let start = std::time::Instant::now();
        while !t2_tried_hook.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(5) {
                return Err(OverlayError::Msg(
                    "replay hook timed out waiting for contender".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // Fail this attempt so the batch is restored while the lock is held.
        Err(OverlayError::Msg("injected replay hold failure".into()))
    })));

    let ov_t2 = Arc::clone(&ov);
    let in_replay_t2 = Arc::clone(&in_replay);
    let t2_tried_t2 = Arc::clone(&t2_tried);
    let lock_was_held_t2 = Arc::clone(&lock_was_held);
    let t2 = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while !in_replay_t2.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(5) {
                panic!("replay hook did not run");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        match ov_t2.pending_rows.try_lock() {
            Ok(guard) => {
                drop(guard);
                lock_was_held_t2.store(false, Ordering::SeqCst);
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                lock_was_held_t2.store(true, Ordering::SeqCst);
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                panic!("pending queue poisoned");
            }
        }
        t2_tried_t2.store(true, Ordering::SeqCst);
        ov_t2.rename("/x", "/y").expect("contending rename");
    });

    ov.mkdir("/trigger", 0o755).expect("trigger replay");
    t2.join().expect("contender");
    assert!(
        lock_was_held.load(Ordering::SeqCst),
        "replay dropped the queue lock before apply/restore"
    );
    assert_eq!(ov.pending_row_count(), 0, "both renames reached sql");
    assert_eq!(deleted_flag(&ov, "/a"), Some(1));
    assert_eq!(deleted_flag(&ov, "/x"), Some(1));
    assert_eq!(deleted_flag(&ov, "/y"), Some(0));
    assert!(ov.lookup("/a", 0).is_none());
    assert!(ov.lookup("/x", 0).is_none());
    assert!(is_overlay_fi(&ov.lookup("/y", 0).expect("y")));
    assert_eq!(fs::read(overlay.join("y")).unwrap(), b"from-a");
}

/// Regression: an unlink tombstone write replays queued rows first (#88).
/// Skipping that replay would leave archive `/a` visible in SQL.
#[test]
fn rename_tx_pending_unlink_replays_before_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base =
        Arc::new(MemBase::with(&[("/a", b"from-a"), ("/z", b"zzz")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
    ov.rename("/a", "/b").expect("queued");
    assert_eq!(ov.pending_row_count(), 1);
    assert_eq!(deleted_flag(&ov, "/a"), None);
    ov.set_rename_tx_failures(0);
    ov.unlink("/z").expect("unlink replays, then tombstones z");
    assert_eq!(ov.pending_row_count(), 0, "unlink drained the queue");
    assert_eq!(deleted_flag(&ov, "/a"), Some(1));
    assert_eq!(deleted_flag(&ov, "/b"), Some(0));
    assert_eq!(deleted_flag(&ov, "/z"), Some(1));
    assert!(ov.lookup("/a", 0).is_none());
    assert!(ov.lookup("/z", 0).is_none());
    assert!(is_overlay_fi(&ov.lookup("/b", 0).expect("b")));
    assert_eq!(fs::read(overlay.join("b")).unwrap(), b"from-a");
}

/// Regression: when replay fails, unlink queues behind the rename instead
/// of tombstoning `/x` in SQL. A later `a`→`x` replay would otherwise
/// mark `/x` present and the unlinked name would come back (#88).
#[test]
fn rename_tx_pending_unlink_queues_behind_failed_replay() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base =
        Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap();
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 2);
    ov.rename("/a", "/x").expect("queued");
    ov.unlink("/x").expect("unlink returns success");
    assert_eq!(ov.pending_row_count(), 2, "unlink appended");
    assert_eq!(
        deleted_flag(&ov, "/x"),
        None,
        "unlink must not write the tombstone ahead of a->x"
    );
    assert!(ov.lookup("/x", 0).is_none(), "memory already hides x");
    ov.set_rename_tx_failures(0);
    drop(ov);
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    assert_eq!(ov.pending_row_count(), 0);
    assert_eq!(deleted_flag(&ov, "/a"), Some(1));
    assert_eq!(deleted_flag(&ov, "/x"), Some(1));
    assert!(ov.lookup("/a", 0).is_none());
    assert!(ov.lookup("/x", 0).is_none());
}

/// Regression: a failed replay puts the batch back. The next present-mark
/// stays behind those rows, and a later successful replay still tombstones
/// `/a` (#88).
///
/// The fault is raised inside `apply_pending_ops_sql` after the first
/// statement. The transaction rolls back, and
/// `try_replay_pending_once_with` restores the batch on that error.
/// Removing that restore drops `a`→`b` and this test's pending count is
/// no longer 2.
#[test]
fn rename_tx_failed_replay_keeps_rows() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[("/a", b"from-a")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
    ov.rename("/a", "/b").expect("queued");
    assert_eq!(ov.pending_row_count(), 1);
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
    ov.mkdir("/c", 0o755)
        .expect("present queues behind the failed replay");
    assert_eq!(
        ov.pending_row_count(),
        2,
        "failed replay must keep a->b and queue present /c"
    );
    assert_eq!(deleted_flag(&ov, "/a"), None, "a->b still unsaved");
    assert_eq!(deleted_flag(&ov, "/c"), None, "present /c still unsaved");
    ov.set_rename_tx_failures(0);
    ov.mkdir("/d", 0o755)
        .expect("later present replays the queue");
    assert_eq!(ov.pending_row_count(), 0);
    assert_eq!(deleted_flag(&ov, "/a"), Some(1));
    assert_eq!(deleted_flag(&ov, "/b"), Some(0));
    assert_eq!(deleted_flag(&ov, "/c"), Some(0));
    assert_eq!(deleted_flag(&ov, "/d"), Some(0));
    assert!(ov.lookup("/a", 0).is_none());
}

/// Regression: restoring a failed batch keeps those rows ahead of anything
/// already queued. Appending them would apply `x`→`y` before `a`→`x` and
/// resurrect `/x` (#88).
#[test]
fn restore_pending_front_keeps_older_rows_ahead() {
    let older = vec![PendingFilesOp::Rename {
        from: "/a".to_string(),
        to: "/x".to_string(),
        mode: ratarmount_core::S_IFREG | 0o644,
        hides_from: true,
        xattrs: BTreeMap::new(),
    }];
    let newer = PendingFilesOp::Rename {
        from: "/x".to_string(),
        to: "/y".to_string(),
        mode: ratarmount_core::S_IFREG | 0o644,
        hides_from: true,
        xattrs: BTreeMap::new(),
    };
    let mut queued = vec![newer.clone()];
    restore_pending_front(&mut queued, older.clone());
    assert_eq!(
        queued.first().map(|op| op.to_string()),
        Some(older[0].to_string())
    );
    assert_eq!(queued, vec![older[0].clone(), newer]);

    let mut empty = Vec::new();
    restore_pending_front(&mut empty, older.clone());
    assert_eq!(empty, older);
}

/// Regression: on-exit `commit_atomic` is the plan-builder call site that
/// does not refuse on its own. The plan must still refuse, name `/a` and
/// `/x`, and warn that an offline `--commit-overlay` would publish them
/// (#88). `commit_live` refuses before `plan_for_commit`, so it does not
/// cover deleting the check inside the plan builder.
#[test]
fn rename_tx_pending_on_exit_names_reappear_paths() {
    let dir = tempfile::tempdir().unwrap();
    let tar = make_tiny_tar(dir.path(), &[("a", b"from-a"), ("x", b"orig-x")]);
    let overlay = dir.path().join("ov");
    let ov = overlay_with_base(open_uncompressed_tar_base(&tar, true), &overlay);
    // a->x direct attempts, x->y replay, and commit_atomic's replay.
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 3);
    ov.rename("/a", "/x").expect("a->x queued");
    ov.rename("/x", "/y").expect("x->y queued");
    assert_eq!(ov.pending_row_count(), 2);
    assert_eq!(deleted_flag(&ov, "/x"), None);
    let err = ov
        .commit_atomic(&tar)
        .expect_err("on-exit commit must refuse while rows are queued");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing to commit")
            && msg.contains("reappear")
            && msg.contains("/a")
            && msg.contains("/x")
            && msg.contains("offline --commit-overlay"),
        "{msg}"
    );
    assert_eq!(ov.pending_row_count(), 2, "refusal must keep the queue");
    let archive = open_uncompressed_tar_base(&tar, true);
    assert!(
        archive.lookup("/a", 0).is_some(),
        "refused commit must leave /a in the archive"
    );
    assert!(
        archive.lookup("/x", 0).is_some(),
        "refused commit must leave /x in the archive"
    );
    assert!(
        archive.lookup("/y", 0).is_none(),
        "refused commit must not publish /y"
    );
}

struct DropCaptureLog;

static DROP_CAPTURED_LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

impl log::Log for DropCaptureLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Error
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Ok(mut lines) = DROP_CAPTURED_LOGS.lock() {
            lines.push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

fn install_drop_capture_log() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        log::set_logger(&DropCaptureLog).expect("install overlay drop log capture");
        log::set_max_level(log::LevelFilter::Error);
    });
}

/// Regression: drop replays once more, then logs the archive paths that
/// will reappear and warns that an offline `--commit-overlay` publishes
/// them (#88).
#[test]
fn rename_tx_pending_drop_logs_reappear_paths() {
    install_drop_capture_log();
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base =
        Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    // Direct attempts plus Drop's three replay attempts.
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS) * 2);
    ov.rename("/a", "/x").expect("queued");
    assert_eq!(ov.pending_row_count(), 1);
    let root = overlay.display().to_string();
    drop(ov);
    let lines = DROP_CAPTURED_LOGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let hit = lines.iter().any(|line| {
        line.contains(&root)
            && line.contains("/a")
            && line.contains("will reappear")
            && line.contains("offline --commit-overlay")
    });
    assert!(hit, "drop log missing reappear paths for {root}: {lines:?}");
}

fn drop_log_reappear_list(root: &str) -> String {
    let lines = DROP_CAPTURED_LOGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let line = lines
        .iter()
        .rev()
        .find(|line| line.contains(root) && line.contains("these paths will reappear on remount:"))
        .unwrap_or_else(|| panic!("drop log missing for {root}: {lines:?}"));
    line.split_once("these paths will reappear on remount: ")
        .and_then(|(_, rest)| rest.split_once('.'))
        .map(|(paths, _)| paths.to_string())
        .unwrap_or_else(|| panic!("could not parse drop log: {line}"))
}

/// Regression: a direct writer's retry holds `pending_rows` across the
/// backoff. Thread B (`x`→`y`) runs in that window. If the lock is free,
/// B tombstones `/x` and A's retry then marks `/x` present (#88).
#[test]
fn rename_tx_retry_window_second_thread_cannot_resurrect_x() {
    for trial in 0..20 {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let base = Arc::new(MemBase::with(&[("/a", b"from-a"), ("/x", b"orig-x")]))
            as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap());
        let entered = Arc::new(AtomicBool::new(false));
        let sampled = Arc::new(AtomicBool::new(false));
        let lock_was_held = Arc::new(AtomicBool::new(false));
        ov.set_rename_before_tx_hook(Some(Box::new(|| {
            Err(OverlayError::Msg(
                "injected first attempt, before the retry wait".into(),
            ))
        })));
        let entered_hook = Arc::clone(&entered);
        let sampled_hook = Arc::clone(&sampled);
        ov.set_direct_retry_wait_hook(Some(Box::new(move || {
            entered_hook.store(true, Ordering::SeqCst);
            let start = Instant::now();
            while !sampled_hook.load(Ordering::SeqCst) {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "trial {trial}: contender did not sample the retry window"
                );
                std::thread::yield_now();
            }
        })));
        let ov_b = Arc::clone(&ov);
        let entered_b = Arc::clone(&entered);
        let sampled_b = Arc::clone(&sampled);
        let lock_b = Arc::clone(&lock_was_held);
        let contender = std::thread::spawn(move || {
            let start = Instant::now();
            while !entered_b.load(Ordering::SeqCst) {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "trial {trial}: retry window did not open"
                );
                std::thread::yield_now();
            }
            match ov_b.pending_rows.try_lock() {
                Ok(guard) => {
                    drop(guard);
                    lock_b.store(false, Ordering::SeqCst);
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    lock_b.store(true, Ordering::SeqCst);
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    panic!("trial {trial}: pending queue poisoned");
                }
            }
            sampled_b.store(true, Ordering::SeqCst);
            ov_b.rename("/x", "/y").expect("x->y");
        });
        ov.rename("/a", "/x").expect("a->x");
        contender.join().expect("contender");
        assert!(
            lock_was_held.load(Ordering::SeqCst),
            "trial {trial}: queue lock was free during the retry wait"
        );
        assert_eq!(
            ov.pending_row_count(),
            0,
            "trial {trial}: both renames committed"
        );
        assert_eq!(deleted_flag(&ov, "/a"), Some(1), "trial {trial}");
        assert_eq!(
            deleted_flag(&ov, "/x"),
            Some(1),
            "trial {trial}: /x resurrected before reopen"
        );
        assert_eq!(deleted_flag(&ov, "/y"), Some(0), "trial {trial}");
        drop(ov);
        let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
        assert_eq!(deleted_flag(&ov, "/a"), Some(1), "trial {trial}");
        assert_eq!(
            deleted_flag(&ov, "/x"),
            Some(1),
            "trial {trial}: /x resurrected on reopen"
        );
        assert_eq!(deleted_flag(&ov, "/y"), Some(0), "trial {trial}");
        assert!(
            ov.lookup("/x", 0).is_none(),
            "trial {trial}: remount shows /x"
        );
        let y = ov.lookup("/y", 0).expect("trial {trial}: /y");
        assert!(is_overlay_fi(&y), "trial {trial}");
        assert_eq!(fs::read(overlay.join("y")).unwrap(), b"from-a");
    }
}

/// Regression: `Drop` recovers a poisoned `pending_rows` or `db` lock and
/// still replays. `expect` on those locks aborts the process (#88).
#[test]
fn drop_recovers_poisoned_pending_and_db_locks() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[("/a", b"from-a")])) as Arc<dyn MountSource>;
    let ov = Arc::new(WriteOverlay::new_for_tests(Arc::clone(&base), &overlay).unwrap());
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
    ov.rename("/a", "/b").expect("queued");
    assert_eq!(ov.pending_row_count(), 1);
    ov.set_rename_tx_failures(0);
    {
        let ov_poison = Arc::clone(&ov);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ov_poison.pending_rows.lock().expect("pending");
            panic!("poison pending rows");
        }));
        assert!(poisoned.is_err(), "pending poison panic was swallowed");
    }
    {
        let ov_poison = Arc::clone(&ov);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ov_poison.db.lock().expect("db");
            panic!("poison db");
        }));
        assert!(poisoned.is_err(), "db poison panic was swallowed");
    }
    assert!(
        ov.pending_rows.lock().is_err(),
        "pending lock must stay poisoned"
    );
    assert!(ov.db.lock().is_err(), "db lock must stay poisoned");
    let ov = Arc::try_unwrap(ov).unwrap_or_else(|_| panic!("only the test holds the overlay"));
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(ov)));
    assert!(dropped.is_ok(), "drop panicked on a poisoned overlay lock");
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    assert_eq!(deleted_flag(&ov, "/a"), Some(1), "drop replay must land");
    assert_eq!(deleted_flag(&ov, "/b"), Some(0));
    assert!(ov.lookup("/a", 0).is_none());
}

/// Regression: resetting the overlay clears `pending_rows`. A later `files`
/// write must not replay rows the reset just wiped (#88).
#[test]
fn reset_overlay_contents_clears_pending_rows() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[("/a", b"archive-a")])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    ov.set_rename_tx_failures(u64::from(RENAME_TX_ATTEMPTS));
    ov.rename("/a", "/b").expect("queued");
    assert_eq!(ov.pending_row_count(), 1);
    // Clear the fault first. A leftover queue whose replay still fails
    // would leave `/a` without a SQL tombstone, and the lookup below would
    // pass even if the queue survived the reset.
    ov.set_rename_tx_failures(0);
    ov.reset_overlay_contents().expect("reset");
    assert_eq!(
        ov.pending_row_count(),
        0,
        "reset must drop queued files updates"
    );
    ov.mkdir("/c", 0o755).expect("later write");
    assert_eq!(
        ov.pending_row_count(),
        0,
        "later write must not replay wiped rows"
    );
    assert_eq!(
        deleted_flag(&ov, "/a"),
        None,
        "queued a->b must not be rewritten after reset"
    );
    assert!(ov.lookup("/a", 0).is_some(), "archive /a stays visible");
}

/// Regression: the drop log lists only names that are still hidden. A later
/// rename that re-exposes an earlier hidden name must not be listed (#88).
/// Keeping `hide.remove(to)` out of the fold lists `/reexposed` as well.
#[test]
fn rename_tx_pending_drop_log_omits_reexposed_name() {
    install_drop_capture_log();
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[
        ("/still-hidden", b"stay"),
        ("/reexposed", b"old"),
    ])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    put_overlay_bytes(&ov, "/fresh", b"new-bytes");
    ov.set_rename_tx_failures(20);
    ov.unlink("/still-hidden").expect("queue still-hidden");
    ov.unlink("/reexposed").expect("queue reexposed behind it");
    ov.rename("/fresh", "/reexposed")
        .expect("re-expose /reexposed");
    assert_eq!(
        ov.pending_reappear_paths(),
        vec!["/still-hidden".to_string()],
        "fold must drop the re-exposed name"
    );
    let root = overlay.display().to_string();
    drop(ov);
    assert_eq!(
        drop_log_reappear_list(&root),
        "/still-hidden",
        "drop log must not list /reexposed"
    );
}

/// Regression: a path SQL already tombstones is not logged as reappearing.
/// Dropping the `deleted = 1` filter lists `/already` (#88).
#[test]
fn rename_tx_pending_drop_log_omits_sql_tombstone() {
    install_drop_capture_log();
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let base = Arc::new(MemBase::with(&[
        ("/already", b"gone"),
        ("/still-hidden", b"stay"),
    ])) as Arc<dyn MountSource>;
    let ov = WriteOverlay::new_for_tests(base, &overlay).unwrap();
    ov.unlink("/already").expect("sql tombstone");
    assert_eq!(deleted_flag(&ov, "/already"), Some(1));
    ov.set_rename_tx_failures(20);
    ov.unlink("/still-hidden").expect("queue still-hidden");
    ov.unlink("/already")
        .expect("queue a path sql already hides");
    assert_eq!(
        ov.pending_reappear_paths(),
        vec!["/still-hidden".to_string()],
        "sql tombstone must be filtered out"
    );
    let root = overlay.display().to_string();
    drop(ov);
    assert_eq!(drop_log_reappear_list(&root), "/still-hidden");
}

/// Regression: mode 000 must not block rename or unlink (#88). Linux parks
/// with `O_PATH`; elsewhere a refused open is metadata-only.
#[test]
fn park_mode000_rename_and_unlink() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    put_overlay_bytes(&ov, "/dst", b"old-mode");
    fs::set_permissions(overlay.join("dst"), fs::Permissions::from_mode(0o000)).unwrap();
    let old_ino = host_ino(&overlay.join("dst"));
    put_overlay_bytes(&ov, "/src", b"kept");
    let parked = ov
        .rename_parked("/src", "/dst")
        .expect("mode 000 rename")
        .expect("parked");
    match parked.fd() {
        Some(fd) => assert_eq!(fd_ino(fd), old_ino),
        None => assert_eq!(parked.file_info().size, b"old-mode".len() as u64),
    }
    #[cfg(target_os = "linux")]
    assert!(parked.fd().is_some(), "Linux O_PATH parks a mode-000 file");
    drop(parked);
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"kept");
    assert!(ov.lookup("/src", 0).is_none());

    put_overlay_bytes(&ov, "/locked", b"secret");
    fs::set_permissions(overlay.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let old_ino = host_ino(&overlay.join("locked"));
    let parked = ov.unlink_parked("/locked").expect("mode 000 unlink");
    let parked = parked.expect("host file was parked");
    match parked.fd() {
        Some(fd) => assert_eq!(fd_ino(fd), old_ino),
        None => assert_eq!(parked.file_info().size, b"secret".len() as u64),
    }
    #[cfg(target_os = "linux")]
    assert!(
        parked.fd().is_some(),
        "Linux O_PATH parks a mode-000 unlink"
    );
    drop(parked);
    assert!(!overlay.join("locked").exists());
    assert!(ov.lookup("/locked", 0).is_none());
}

/// Regression: the parked fd is the pre-rename inode (#88).
#[test]
fn park_fstat_old_inode() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    put_overlay_bytes(&ov, "/dst", b"old-inode");
    put_overlay_bytes(&ov, "/src", b"new-inode");
    let old_ino = host_ino(&overlay.join("dst"));
    let src_ino = host_ino(&overlay.join("src"));
    assert_ne!(old_ino, src_ino);
    let parked = ov.rename_parked("/src", "/dst").unwrap().expect("parked");
    let fd = parked.fd().expect("park open");
    assert_eq!(fd_ino(fd), old_ino);
    assert_eq!(host_ino(&overlay.join("dst")), src_ino);
    assert_ne!(host_ino(&overlay.join("dst")), old_ino);
}

/// Regression: a symlink target is snapshotted, not opened (#88).
#[test]
fn park_symlink_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    ov.create_symlink("/link", "old-target").unwrap();
    put_overlay_bytes(&ov, "/src", b"file");
    let parked = ov
        .rename_parked("/src", "/link")
        .unwrap()
        .expect("symlink parked");
    assert!(parked.fd().is_none(), "symlinks are not opened");
    assert_eq!(parked.file_info().linkname, "old-target");
    assert!(ratarmount_core::is_lnk_mode(parked.file_info().mode));
    let now = ov.lookup("/link", 0).unwrap();
    assert!(!ratarmount_core::is_lnk_mode(now.mode));
    assert!(now.linkname.is_empty());
    assert_eq!(fs::read(overlay.join("link")).unwrap(), b"file");
    assert!(ov.lookup("/src", 0).is_none());
}

/// Regression: plain rename and unlink never open the target (#88).
/// An installed EMFILE park hook must not run, and the park-open counter stays 0.
#[test]
fn plain_rename_and_unlink_do_not_park() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    put_overlay_bytes(&ov, "/dst", b"old-dst");
    put_overlay_bytes(&ov, "/src", b"new-src");
    let hook_calls = Arc::new(AtomicU64::new(0));
    let hook_calls2 = Arc::clone(&hook_calls);
    ov.set_park_open_hook(Some(Box::new(move || {
        hook_calls2.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::from_raw_os_error(libc::EMFILE))
    })));
    ov.rename("/src", "/dst")
        .expect("plain rename over a target");
    assert_eq!(ov.park_open_count(), 0);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new-src");
    assert!(!overlay.join("src").exists());
    assert!(ov.lookup("/src", 0).is_none());

    put_overlay_bytes(&ov, "/gone", b"bye");
    ov.unlink("/gone").expect("plain unlink of a target");
    assert_eq!(ov.park_open_count(), 0);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
    assert!(!overlay.join("gone").exists());
    assert!(ov.lookup("/gone", 0).is_none());
}

/// Regression: park open EMFILE/ENFILE fails rename with `to` unchanged
/// and fails unlink with nothing removed (#88).
#[test]
fn park_open_emfile_leaves_names_unchanged() {
    for code in [libc::EMFILE, libc::ENFILE] {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("ov");
        let ov = WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay)
            .unwrap();
        put_overlay_bytes(&ov, "/dst", b"keep-dst");
        put_overlay_bytes(&ov, "/src", b"keep-src");
        ov.set_park_open_hook(Some(Box::new(move || {
            Err(io::Error::from_raw_os_error(code))
        })));
        let err = ov
            .rename_parked("/src", "/dst")
            .expect_err("park open must fail the rename");
        let OverlayError::Io(err) = err else {
            panic!("expected Io, got {err}");
        };
        assert_eq!(err.raw_os_error(), Some(code), "errno {code}");
        assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"keep-dst");
        assert_eq!(fs::read(overlay.join("src")).unwrap(), b"keep-src");
        assert!(ov.lookup("/dst", 0).is_some());
        assert!(ov.lookup("/src", 0).is_some());
        assert!(!ov.is_deleted("/dst"));
        assert_eq!(ov.park_open_count(), 1, "errno {code}");

        put_overlay_bytes(&ov, "/victim", b"stay");
        let err = ov
            .unlink_parked("/victim")
            .expect_err("park open must fail the unlink");
        let OverlayError::Io(err) = err else {
            panic!("expected Io, got {err}");
        };
        assert_eq!(err.raw_os_error(), Some(code), "errno {code}");
        assert_eq!(fs::read(overlay.join("victim")).unwrap(), b"stay");
        assert!(ov.lookup("/victim", 0).is_some());
        assert!(!ov.is_deleted("/victim"));
        assert_eq!(deleted_flag(&ov, "/victim"), Some(0));
        assert_eq!(ov.park_open_count(), 2, "errno {code}");
    }
}

/// Regression: the before-tx hook fires once and is not restored (#88).
/// A single `Err` fails only that attempt; the retry commits the rename.
#[test]
fn rename_before_tx_hook_is_one_shot() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    put_overlay_bytes(&ov, "/dst", b"old");
    put_overlay_bytes(&ov, "/src", b"new");
    let calls = Arc::new(AtomicU64::new(0));
    let calls2 = Arc::clone(&calls);
    ov.set_rename_before_tx_hook(Some(Box::new(move || {
        calls2.fetch_add(1, Ordering::SeqCst);
        Err(OverlayError::Msg("injected rename tx failure".into()))
    })));
    ov.rename("/src", "/dst")
        .expect("tx failure still returns success");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        deleted_flag(&ov, "/src"),
        None,
        "retry committed the overlay-only delete"
    );
    assert_eq!(ov.pending_row_count(), 0, "retry did not queue the rename");

    put_overlay_bytes(&ov, "/src2", b"second");
    put_overlay_bytes(&ov, "/dst2", b"old2");
    ov.rename("/src2", "/dst2").expect("second rename");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "hook was not restored");
    assert_eq!(deleted_flag(&ov, "/src2"), None, "second tx committed");
    assert_eq!(fs::read(overlay.join("dst2")).unwrap(), b"second");
}

/// Regression: non-Linux park opens add O_NONBLOCK so a FIFO cannot block (#88).
///
/// `#[cfg]` rather than `cfg!`: macOS libc has no `O_PATH`, so that name
/// must not be compiled off Linux.
#[cfg(unix)]
#[test]
fn park_open_flags_set_nonblock_off_linux() {
    let flags = park_open_flags();
    assert_ne!(flags & libc::O_NOFOLLOW, 0);
    assert_ne!(flags & libc::O_CLOEXEC, 0);
    #[cfg(target_os = "linux")]
    {
        assert_eq!(flags, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        assert_eq!(flags & libc::O_NONBLOCK, 0);
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(
            flags,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
        );
    }
}

/// Regression: park-open EACCES is metadata-only (#88).
/// `rename_parked` and `unlink_parked` still change the names; `fd` is
/// `None` and `last_fi` keeps the pre-change attributes.
#[test]
fn park_open_eacces_is_metadata_only() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov =
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap();
    put_overlay_bytes(&ov, "/dst", b"old-dst");
    put_overlay_bytes(&ov, "/src", b"new-src");
    let dst_before = ov.lookup("/dst", 0).expect("dst metadata");
    ov.set_park_open_hook(Some(Box::new(|| {
        Err(io::Error::from_raw_os_error(libc::EACCES))
    })));
    let parked = ov
        .rename_parked("/src", "/dst")
        .expect("EACCES park open still renames")
        .expect("destination parked");
    assert!(parked.fd().is_none(), "metadata-only park");
    assert_eq!(parked.file_info().size, dst_before.size);
    assert_eq!(parked.file_info().mode, dst_before.mode);
    assert_eq!(parked.file_info().linkname, dst_before.linkname);
    assert_eq!(parked.file_info().size, b"old-dst".len() as u64);
    drop(parked);
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new-src");
    assert!(!overlay.join("src").exists());
    assert!(ov.lookup("/src", 0).is_none());
    assert!(ov.lookup("/dst", 0).is_some());
    assert_eq!(ov.park_open_count(), 1);

    put_overlay_bytes(&ov, "/victim", b"stay-bytes");
    let victim_before = ov.lookup("/victim", 0).expect("victim metadata");
    let parked = ov
        .unlink_parked("/victim")
        .expect("EACCES park open still unlinks")
        .expect("victim parked");
    assert!(parked.fd().is_none(), "metadata-only park");
    assert_eq!(parked.file_info().size, victim_before.size);
    assert_eq!(parked.file_info().mode, victim_before.mode);
    assert_eq!(parked.file_info().linkname, victim_before.linkname);
    assert_eq!(parked.file_info().size, b"stay-bytes".len() as u64);
    drop(parked);
    assert!(!overlay.join("victim").exists());
    assert!(ov.lookup("/victim", 0).is_none());
    assert_eq!(ov.park_open_count(), 2);
}

/// Regression: the before-tx hook runs after its mutex guard is dropped (#88).
#[test]
fn rename_before_tx_hook_runs_after_mutex_drop() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("ov");
    let ov = Arc::new(
        WriteOverlay::new_for_tests(Arc::new(NullBase) as Arc<dyn MountSource>, &overlay).unwrap(),
    );
    put_overlay_bytes(&ov, "/dst", b"old");
    put_overlay_bytes(&ov, "/src", b"new");
    let probe = Arc::downgrade(&ov);
    ov.set_rename_before_tx_hook(Some(Box::new(move || {
        let probe = probe.upgrade().expect("overlay");
        assert!(
            probe.rename_before_tx_hook.try_lock().is_ok(),
            "hook ran while its mutex was still held"
        );
        Ok(())
    })));
    ov.rename("/src", "/dst").expect("rename");
    assert_eq!(fs::read(overlay.join("dst")).unwrap(), b"new");
    assert!(!overlay.join("src").exists());
}

fn overlay_entry_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}
#[test]
fn regression_oplog_meta_value_reads_the_exclusively_held_connection() {
    let dir = tempfile::tempdir().unwrap();
    let overlay =
        WriteOverlay::new_for_tests(Arc::new(MemBase::with(&[("/base", b"data")])), dir.path())
            .unwrap();
    assert!(overlay.meta_value("journal_path").unwrap().is_none());
    overlay.set_meta("journal_path", "/trace.jsonl").unwrap();
    assert_eq!(
        overlay.meta_value("journal_path").unwrap().as_deref(),
        Some("/trace.jsonl")
    );
    assert_eq!(
        overlay.base_serving_layer("/base"),
        Some(crate::LayerIndex::Base)
    );
    assert_eq!(overlay.base_serving_layer("/missing"), None);
}

/// Regression (Ilya #2): writes under the virtual `/.ratarmount-control`
/// folder landed in the overlay. Reserved only while the control folder is
/// served; every entry point refuses with `PermissionDenied`.
#[cfg(unix)]
#[test]
fn regression_control_name_reserved_at_every_entry_point() {
    type Op = fn(&WriteOverlay, &str) -> io::Result<()>;
    let ops: Vec<(&str, Op)> = vec![
        ("create_file", |o, p| {
            o.create_file(p, 0o644).map(close_fd).map_err(into_io)
        }),
        ("open O_CREAT", |o, p| {
            o.open_overlay_fd_with_mode(p, libc::O_CREAT | libc::O_WRONLY, 0o644)
                .map(close_fd)
                .map_err(into_io)
        }),
        ("open O_TRUNC", |o, p| {
            o.open_overlay_fd_with_mode(p, libc::O_TRUNC | libc::O_WRONLY, 0o644)
                .map(close_fd)
                .map_err(into_io)
        }),
        ("mkdir", |o, p| o.mkdir(p, 0o755).map_err(into_io)),
        ("symlink", |o, p| o.create_symlink(p, "t").map_err(into_io)),
        ("unlink", |o, p| o.unlink(p).map_err(into_io)),
        ("rmdir", |o, p| o.rmdir(p).map_err(into_io)),
        ("truncate", |o, p| o.truncate(p, 0).map_err(into_io)),
        ("rename source", |o, p| {
            o.rename(p, "/dest").map_err(into_io)
        }),
        ("rename dest", |o, p| o.rename("/a", p).map_err(into_io)),
        ("set_xattr", |o, p| {
            o.set_xattr(p, "user.k", b"v", 0).map_err(into_io)
        }),
        ("remove_xattr", |o, p| {
            o.remove_xattr(p, "user.k").map_err(into_io)
        }),
        ("chmod", |o, p| {
            let m = OverlayMetadata {
                mode: Some(0o600),
                ..Default::default()
            };
            o.set_attributes(p, None, &m).map_err(into_io)
        }),
        ("utimens", |o, p| {
            let m = OverlayMetadata {
                mtime: Some(5.0),
                ..Default::default()
            };
            o.set_attributes(p, None, &m).map_err(into_io)
        }),
        ("set_metadata", |o, p| {
            let m = OverlayMetadata {
                mode: Some(0o600),
                ..Default::default()
            };
            o.set_metadata(p, &m).map_err(into_io)
        }),
        ("set_attributes size", |o, p| {
            o.set_attributes(p, Some(0), &OverlayMetadata::default())
                .map_err(into_io)
        }),
    ];
    fn close_fd(fd: i32) {
        unsafe { libc::close(fd) };
    }
    fn into_io(e: OverlayError) -> io::Error {
        match e {
            OverlayError::Io(e) => e,
            other => io::Error::other(other.to_string()),
        }
    }
    let spellings = [
        "/.ratarmount-control/x",
        "./.ratarmount-control/x",
        "//.ratarmount-control/x",
        "/a/../.ratarmount-control/x",
        "/.ratarmount-control",
    ];
    // The base already holds the reserved name, for unlink/xattr/chmod/rename-from.
    let base = || {
        Arc::new(MemBase::with(&[
            ("/a", b"a"),
            ("/.ratarmount-control/x", b"x"),
            ("/sub/.ratarmount-control/x", b"x"),
        ])) as Arc<dyn MountSource>
    };
    let td = tempfile::tempdir().unwrap();
    let mut on = WriteOverlay::new_for_tests(base(), td.path()).unwrap();
    on.set_control_reserved(true);
    for (name, op) in &ops {
        for path in spellings {
            let err = op(&on, path).expect_err(&format!("{name} {path}"));
            assert_eq!(
                err.kind(),
                io::ErrorKind::PermissionDenied,
                "{name} {path}: {err}"
            );
        }
        // Names that only look similar stay ordinary (the error, if any, is not the refusal).
        for path in ["/sub/.ratarmount-control/x", "/.ratarmount-controlx"] {
            if let Err(e) = op(&on, path) {
                assert!(
                    !e.to_string().contains("reserved control folder"),
                    "{name} {path}: {e}"
                );
            }
        }
    }
    assert!(!td.path().join(".ratarmount-control").exists());
    // Off (no --control-interface, or --control-socket-only): ordinary names.
    let td = tempfile::tempdir().unwrap();
    let off = WriteOverlay::new_for_tests(base(), td.path()).unwrap();
    off.create_file("/.ratarmount-control/new", 0o644)
        .map(close_fd)
        .unwrap();
    off.mkdir("/.ratarmount-control/d", 0o755).unwrap();
    off.set_xattr("/.ratarmount-control/x", "user.k", b"v", 0)
        .unwrap();
    for path in spellings {
        assert!(is_control_reserved_path(path), "{path}");
    }
    assert!(!is_control_reserved_path("/sub/.ratarmount-control/x"));
    assert!(!is_control_reserved_path("/.ratarmount-controlx"));
}

/// Regression: (R11-S7, #151): the remote spool fingerprint and comparison
/// (`file_sha256`, `presplice_fingerprint`, both operands of
/// `files_same_len_and_hash`) hashed with raw `File`s; a spool that is
/// another name of a database open in this process lost its lock.
#[cfg(unix)]
#[test]
fn regression_remote_spool_hash_keeps_aliased_database_lock() {
    use ratarmount_index::managed_read::lock_probe::other_process_sees_lock;
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path().canonicalize().unwrap();
    let db = dir.join("spool.sqlite");
    let c = Connection::open(&db).unwrap();
    c.execute_batch("CREATE TABLE t(x BLOB); INSERT INTO t VALUES (randomblob(100000));")
        .unwrap();
    drop(c);
    let alias = dir.join("alias");
    fs::hard_link(&db, &alias).unwrap();
    let h = Connection::open(&db).unwrap();
    h.execute_batch("BEGIN").unwrap();
    let _: i64 = h
        .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
        .unwrap();
    assert!(other_process_sees_lock(&db));
    let fp = presplice_fingerprint(&alias).unwrap();
    assert_eq!(fp.sha256, file_sha256(&db).unwrap());
    assert!(files_same_len_and_hash(&db, &alias).unwrap());
    assert!(other_process_sees_lock(&db), "lock kept");
    drop(fs::File::open(&alias).unwrap());
    assert!(!other_process_sees_lock(&db), "oracle check");
    drop(h);
}
