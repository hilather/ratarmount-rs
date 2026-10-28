#![allow(
    clippy::disallowed_methods,
    reason = "Journal regression fixtures directly exercise the restricted implementation APIs"
)]

use super::*;

use std::io::{Seek, Write};

/// Regression: #240 copy publication must refuse a read-only archive rather
/// than bypass the VFS reservation with an unsafe raw-descriptor fallback.
#[test]
fn regression_240_copy_requires_writable_reservation() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skip: root can open mode-0444 archives read-write");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    fs::write(&path, b"archive bytes").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    let original = fs::metadata(&path).unwrap();
    let error = guard_copy(&path, &original).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read(&path).unwrap(), b"archive bytes");
    assert!(same_stamp(&original, &fs::metadata(&path).unwrap()));
}

/// Regression: #240 archive guard disposal must preserve an independent
/// SQLite reader's POSIX locks, including refused copy, replace and recovery.
#[test]
fn regression_240_commit_guards_preserve_sqlite_reader() {
    use rusqlite::{Connection, ErrorCode};
    use std::process::Command;

    const PROBE: &str = "RATARMOUNT_240_COMMIT_SQLITE_PROBE";
    if let Some(path) = std::env::var_os(PROBE) {
        let conn = Connection::open(path).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        let result = conn.execute_batch("BEGIN EXCLUSIVE");
        if std::env::var_os("RATARMOUNT_240_COMMIT_SQLITE_FREE").is_some() {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err().sqlite_error_code(),
                Some(ErrorCode::DatabaseBusy)
            );
        }
        return;
    }
    let probe = |path: &Path, free: bool| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        if free {
            command.env("RATARMOUNT_240_COMMIT_SQLITE_FREE", "yes");
        }
        let output = command
            .args([
                "--exact",
                "commit_journal::tests::regression_240_commit_guards_preserve_sqlite_reader",
                "--nocapture",
            ])
            .env(PROBE, path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "outside BEGIN EXCLUSIVE bypassed the reader: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    for alias in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.sqlite");
        let other = dir.path().join("alias");
        let reader = Connection::open(&path).unwrap();
        reader.busy_timeout(std::time::Duration::ZERO).unwrap();
        reader
            .execute_batch(
                "CREATE TABLE data(value); INSERT INTO data VALUES(1); BEGIN; SELECT * FROM data",
            )
            .unwrap();
        fs::hard_link(&path, &other).unwrap();
        let selected = if alias { &other } else { &path };
        let original = fs::metadata(selected).unwrap();
        probe(&path, false);
        let copy = guard_copy(selected, &original);
        let copy_refused = copy.is_err();
        drop(copy);
        probe(&path, false);
        assert!(copy_refused, "copy must refuse a live SQLite reader");
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"replacement").unwrap();
        let replaced = replace_suffix_if_unchanged_with(
            selected,
            0,
            &mut suffix,
            &original,
            &mut || panic!("reader must be checked before archive mutation"),
            &mut |_| Ok(()),
        );
        assert!(matches!(replaced, Err(ReplaceError::Refused(_))));
        probe(&path, false);
        assert!(!recover(selected).unwrap());
        probe(&path, false);
        fs::write(journal_path(selected), b"pending journal").unwrap();
        assert_eq!(
            recover(selected).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "recovery reservation must retain its refusal kind with journal context"
        );
        probe(&path, false);
        fs::remove_file(journal_path(selected)).unwrap();
        assert!(offline_journal_probe(selected).unwrap().0.is_none());
        probe(&path, false);
        reader.execute_batch("COMMIT").unwrap();
        let guard = guard_copy(selected, &fs::metadata(selected).unwrap()).unwrap();
        // A reader starting after reservation must also be excluded until
        // every raw descriptor closes. Merely deferring the final close is
        // insufficient for this overlapping-reader case.
        let denied = reader
            .execute_batch("BEGIN; SELECT * FROM data")
            .unwrap_err();
        assert_eq!(denied.sqlite_error_code(), Some(ErrorCode::DatabaseBusy));
        reader.execute_batch("ROLLBACK").unwrap();
        drop(guard);
        probe(&path, true);
        let original = fs::metadata(selected).unwrap();
        let refused = replace_suffix_if_unchanged_with(
            selected,
            0,
            &mut suffix,
            &original,
            &mut || {
                let denied = reader
                    .execute_batch("BEGIN; SELECT * FROM data")
                    .unwrap_err();
                assert_eq!(denied.sqlite_error_code(), Some(ErrorCode::DatabaseBusy));
                reader.execute_batch("ROLLBACK").unwrap();
                Err(io::Error::other("refuse before writing"))
            },
            &mut |_| Ok(()),
        );
        assert!(matches!(refused, Err(ReplaceError::Refused(_))));
        probe(&path, true);
        // Successful no-op replacement and an error after raw guard open both
        // release their VFS reservation after the raw archive descriptors.
        suffix.set_len(0).unwrap();
        suffix.rewind().unwrap();
        suffix.write_all(&fs::read(selected).unwrap()).unwrap();
        replace_suffix_if_unchanged_with(
            selected,
            0,
            &mut suffix,
            &original,
            &mut || Ok(()),
            &mut |_| Ok(()),
        )
        .unwrap();
        probe(&path, true);
        assert!(
            guard_copy(selected, &original).is_err(),
            "stale stamp must refuse"
        );
        probe(&path, true);
    }
}

/// Regression: ENOSPC must roll back before returning to a live reader.
#[test]
fn append_journal_write_error_rolls_back_immediately() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    fs::write(&path, b"prefix:old contents").unwrap();
    let original = fs::metadata(&path).unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&vec![0x82; 150_000]).unwrap();
    fault::install(|step| {
        if step == "archive write" {
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        } else {
            Ok(())
        }
    });
    let result = replace_suffix_if_unchanged_with(
        &path,
        7,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |_| Ok(()),
    );
    fault::clear();
    assert!(
        matches!(result, Err(ReplaceError::RolledBack(..))),
        "{result:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
    assert!(!journal_path(&path).exists());
    assert_eq!(marker_state(&path), None);
}

/// Regression (R6-K6): `recover_owned` refuses a journal started for another
/// file (a new-inode copy) untouched, and recovers the file's own journal.
#[cfg(unix)]
#[test]
fn append_journal_recover_owned_refuses_foreign_journal() {
    let crash = |path: &Path| {
        fs::write(path, b"prefix:old contents").unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents").unwrap();
        let crashed = replace_suffix_with_hook(path, 7, &mut suffix, &mut |step| {
            if step == "archive truncate" {
                Err(io::Error::other("crash"))
            } else {
                Ok(())
            }
        });
        assert!(crashed.is_err());
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    crash(&path);
    let crashed = fs::read(&path).unwrap();
    let journal = fs::read(journal_path(&path)).unwrap();
    let copy = dir.path().join("copy");
    fs::write(&copy, &crashed).unwrap();
    fs::rename(&copy, &path).unwrap();
    let err = recover_with(&path, &mut authorize_owned, &mut |_| Ok(()))
        .unwrap_err()
        .to_string();
    assert!(err.contains("another file"), "{err}");
    assert_eq!(fs::read(&path).unwrap(), crashed);
    assert_eq!(fs::read(journal_path(&path)).unwrap(), journal);

    let own = dir.path().join("own");
    crash(&own);
    assert!(recover_with(&own, &mut authorize_owned, &mut |_| Ok(()))
        .unwrap()
        .is_some());
    assert_eq!(fs::read(&own).unwrap(), b"prefix:old contents");
    assert!(!journal_path(&own).exists());
}

/// Regression: a cleanup failure after completion must not append the same plan twice.
#[test]
fn append_journal_completed_cleanup_error_is_success() {
    for stop in [
        "locator complete",
        "locator done",
        "journal unlink",
        "locator clear",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"prefix:old contents").unwrap();
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents").unwrap();
        fault::install(move |step| {
            if step == stop {
                Err(io::Error::other("cleanup failed"))
            } else {
                Ok(())
            }
        });
        let result = replace_suffix_if_unchanged_with(
            &path,
            7,
            &mut suffix,
            &original,
            &mut || Ok(()),
            &mut |_| Ok(()),
        );
        fault::clear();
        result.unwrap_or_else(|e| panic!("{stop}: {e:?}"));
        assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
        assert_eq!(marker_state(&path), None, "{stop}");
        assert!(!recover(&path).unwrap());
    }
}

/// Regression: absent journals must not replace ordinary Session open errors.
#[test]
fn append_journal_absent_preserves_open_errors() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    assert!(!recover(&path).unwrap());
    fs::write(&path, b"ordinary file").unwrap();
    assert!(!recover(&path.join("not-a-directory")).unwrap());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(!recover(&path).unwrap());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
}

fn interrupted(path: &Path, step: &str) {
    fs::write(path, b"prefix:old contents").unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"new contents are longer").unwrap();
    assert!(replace_suffix_with_hook(path, 7, &mut suffix, &mut |at| {
        if at == step {
            Err(io::Error::other("crash"))
        } else {
            Ok(())
        }
    })
    .is_err());
}

/// Regression (r16 nit, R7-D3): a process killed between the journal
/// unlink and the locator clear leaves a done (`D`) locator with no
/// journal; recovery keeps it (the journal may sit beside another name),
/// so every later commit was refused with "pending journal; recover
/// before preparing a commit" although recovery had nothing to do. The
/// refusal (append and copy guard) names the documented escape; a real
/// pending journal does not get that advice.
#[test]
fn append_journal_done_locator_without_journal_names_the_escape() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "journal unlink");
    assert!(!journal_path(&path).exists());
    assert_eq!(marker_state(&path), Some(b'D'));
    let original = fs::metadata(&path).unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"more").unwrap();
    let refused = replace_suffix_if_unchanged_with(
        &path,
        7,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |_| Ok(()),
    );
    let Err(ReplaceError::Refused(e)) = refused else {
        panic!("{refused:?}");
    };
    let text = e.to_string();
    assert!(text.contains("recover before preparing a commit"), "{text}");
    assert!(text.contains("setfattr -x"), "{text}");
    assert!(text.contains("xattr -d"), "{text}");
    let guarded = guard_copy(&path, &original).map(drop).unwrap_err();
    assert!(guarded.to_string().contains("setfattr -x"), "{guarded}");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator active");
    assert!(journal_path(&path).exists());
    let original = fs::metadata(&path).unwrap();
    let refused = replace_suffix_if_unchanged_with(
        &path,
        7,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |_| Ok(()),
    );
    let Err(ReplaceError::Refused(e)) = refused else {
        panic!("{refused:?}");
    };
    assert!(!e.to_string().contains("setfattr"), "{e}");
}

/// Regression: symlinks and hard links must find the same pending journal.
#[test]
fn append_journal_alias_recovery() {
    for symlink in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        let alias_dir = dir.path().join("other");
        fs::create_dir(&alias_dir).unwrap();
        let alias = alias_dir.join("alias");
        if symlink {
            std::os::unix::fs::symlink(&path, &alias).unwrap();
        } else {
            fs::hard_link(&path, &alias).unwrap();
        }
        if symlink {
            assert_eq!(journal_path(&path), journal_path(&alias));
        }
        assert!(recover(&alias).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
        assert!(!recover(&path).unwrap());
    }
}

/// Regression: cp/rsync --inplace reuse the inode but must not trigger rollback.
#[test]
fn append_journal_reused_inode_refuses_external_bytes() {
    for bytes in [
        b"prefix:unrelated archive".as_slice(),
        b"WRONG!:new",
        b"prefix:new contents are longer and newer",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, "archive truncate");
        fs::write(&path, bytes).unwrap();
        let error = recover(&path).unwrap_err().to_string();
        assert!(
            error.contains(journal_path(&path).to_str().unwrap()),
            "{error}"
        );
        assert!(error.contains("backup"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

/// Regression: changed device numbers are hints, not a permanent recovery block.
#[test]
fn append_journal_device_change_uses_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "archive truncate");
    let journal = journal_path(&path);
    let mut bytes = fs::read(&journal).unwrap();
    bytes[8..24].fill(0xa7);
    let end = bytes.len() - 4;
    let crc = crc32fast::hash(&bytes[..end]);
    bytes[end..].copy_from_slice(&crc.to_le_bytes());
    fs::write(journal, bytes).unwrap();
    assert!(recover(&path).unwrap());
    assert_eq!(fs::read(path).unwrap(), b"prefix:old contents");
}

/// Regression: a corrupted journal must never be copied into an archive.
#[test]
fn append_journal_crc_refuses_corrupt_tail() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "archive truncate");
    let journal = journal_path(&path);
    let mut bytes = fs::read(&journal).unwrap();
    bytes[unix::HEADER_LEN as usize] ^= 1;
    fs::write(&journal, bytes).unwrap();
    assert!(recover(&path).unwrap_err().to_string().contains("CRC"));
    assert_eq!(fs::read(path).unwrap(), b"prefix:");
}

/// Regression: non-owner writers can recover even when restoring mtime is EPERM.
#[test]
fn append_journal_mtime_eperm_is_nonfatal() {
    assert!(unix::restore_mtime(Err(io::Error::from_raw_os_error(libc::EPERM))).is_ok());
    assert!(unix::restore_mtime(Err(io::Error::from_raw_os_error(libc::EIO))).is_err());
}

/// Regression: a read-only opener must refuse a torn archive it cannot repair.
#[test]
fn append_journal_readonly_recovery_refuses_unwritable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "archive truncate");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skip: root bypasses write permissions; content refusal is tested separately");
    } else {
        let error = recover(&path).unwrap_err().to_string();
        assert!(error.contains(journal_path(&path).to_str().unwrap()));
        assert!(error.contains("write access"));
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(recover(&path).unwrap());
}

/// Regression: a crash during tail replacement must recover byte-for-byte.
#[test]
fn append_journal_crash_every_step_old_or_new() {
    let old: Vec<_> = (0..180_000).map(|i| (i % 251) as u8).collect();
    let tail = vec![0xb1; 150_000];
    let offset = 100_003;
    let mut new = old[..offset].to_vec();
    new.extend_from_slice(&tail);
    for stop in 0..20 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, &old).unwrap();
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(&tail).unwrap();
        let mut step = 0;
        let result = replace_suffix_with_hook(&path, offset as u64, &mut suffix, &mut |_| {
            step += 1;
            if step == stop {
                Err(io::Error::other("injected crash"))
            } else {
                Ok(())
            }
        });
        recover(&path).unwrap();
        assert!(!recover(&path).unwrap(), "recovery is idempotent");
        let actual = fs::read(&path).unwrap();
        assert!(actual == old || actual == new, "third state at step {stop}");
        if stop > 0 && stop < 13 {
            assert!(result.is_err());
            assert_eq!(actual, old, "must roll back before unlink");
            assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
        }
    }
}

/// Regression (R7-E1): a rolled-back replacement reports the locked
/// descriptor's stamp after its cleanup (the only stamp a copy fallback
/// may read), whether its journal was published or not: it equals the
/// archive's stamp afterwards, the old bytes are in place, and a write
/// after the lock was released no longer matches it.
#[test]
fn append_journal_rolled_back_reports_the_locked_stamp() {
    for step in ["journal header", "locator prepare", "archive write"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"prefix:old contents").unwrap();
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents").unwrap();
        fault::install(move |seen| {
            if seen == step {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            Ok(())
        });
        let result = replace_suffix_if_unchanged_with(
            &path,
            7,
            &mut suffix,
            &original,
            &mut || Ok(()),
            &mut |_| Ok(()),
        );
        fault::clear();
        let Err(ReplaceError::RolledBack(_, Some(stamp))) = result else {
            panic!("{step}: {result:?}");
        };
        assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents", "{step}");
        assert!(same_stamp(&stamp, &fs::metadata(&path).unwrap()), "{step}");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert!(!same_stamp(&stamp, &fs::metadata(&path).unwrap()), "{step}");
    }
}

/// The fault seam is consulted at every step of a production replacement,
/// in order, and an instead-of seam's `Err` replaces the step.
#[test]
fn fault_seam_sees_every_replace_step() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    fs::write(&path, b"prefix:old contents").unwrap();
    let original = fs::metadata(&path).unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"new contents").unwrap();
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let log = seen.clone();
    fault::install(move |step| {
        log.borrow_mut().push(step);
        Ok(())
    });
    replace_suffix_if_unchanged_with(
        &path,
        7,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |_| Ok(()),
    )
    .unwrap();
    fault::clear();
    assert_eq!(
        *seen.borrow(),
        [
            "before replace",
            "journal header",
            "journal tail",
            "journal fsync",
            "locator prepare",
            "journal publish",
            "journal directory fsync",
            "locator active",
            "archive truncate",
            "archive write",
            "archive fsync",
            "locator complete",
            "locator done",
            "commit unlink",
            "journal unlink",
            "commit directory sync",
            "commit directory fsync",
            "locator clear",
        ]
    );
    assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");

    // `rollback mtime` replaces `set_times`; EPERM is tolerated as before.
    fs::write(&path, b"prefix:old contents").unwrap();
    let original = fs::metadata(&path).unwrap();
    fault::install(|step| match step {
        "archive write" => Err(io::Error::from_raw_os_error(libc::ENOSPC)),
        "rollback mtime" => Err(io::Error::from_raw_os_error(libc::EPERM)),
        _ => Ok(()),
    });
    let error = replace_suffix_if_unchanged_with(
        &path,
        7,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |_| Ok(()),
    );
    fault::clear();
    assert!(
        matches!(error, Err(ReplaceError::RolledBack(..))),
        "{error:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
    assert!(!journal_path(&path).exists());
}

/// Regression: a second crash during rollback must leave a reusable journal.
#[test]
fn append_journal_interrupted_rollback_retries() {
    use std::io::{Read, Seek, SeekFrom};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    let old = vec![0x52; 80_000];
    fs::write(&path, &old).unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"new").unwrap();
    assert!(
        replace_suffix_with_hook(&path, 1024, &mut suffix, &mut |step| {
            if step == "archive truncate" {
                Err(io::Error::other("crash"))
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    // Model a rollback interrupted after a partial tail write.
    let mut journal = File::open(journal_path(&path)).unwrap();
    journal.seek(SeekFrom::Start(unix::HEADER_LEN)).unwrap();
    let mut partial = [0; 2000];
    journal.read_exact(&mut partial).unwrap();
    let mut archive = fs::OpenOptions::new().write(true).open(&path).unwrap();
    archive.seek(SeekFrom::Start(1024)).unwrap();
    archive.write_all(&partial).unwrap();
    archive.sync_all().unwrap();
    assert!(recover(&path).unwrap());
    assert_eq!(fs::read(&path).unwrap(), old);
    assert!(!recover(&path).unwrap());
}

/// Regression: a stale prepared suffix must not overwrite a newer commit.
#[test]
fn append_journal_stale_preparation_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    fs::write(&path, b"old").unwrap();
    let original = fs::metadata(&path).unwrap();
    fs::write(&path, b"another commit").unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"stale").unwrap();
    let result = replace_suffix_if_unchanged_with(
        &path,
        0,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |_| Ok(()),
    );
    assert!(
        matches!(result, Err(ReplaceError::Refused(_))),
        "{result:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), b"another commit");
    assert!(!journal_path(&path).exists());
}

/// Regression: a journal from a replaced archive must never clobber its successor.
#[test]
fn append_journal_wrong_inode_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    fs::write(&path, b"old archive").unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"new").unwrap();
    assert!(
        replace_suffix_with_hook(&path, 3, &mut suffix, &mut |step| {
            if step == "archive truncate" {
                Err(io::Error::other("crash"))
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    let replacement = dir.path().join("replacement");
    fs::write(&replacement, b"unrelated archive").unwrap();
    fs::rename(replacement, &path).unwrap();
    assert!(recover(&path).is_err());
    assert_eq!(fs::read(path).unwrap(), b"unrelated archive");
}

/// Regression (R6-G2): `pending` reads the header a recovery would act on
/// without writing: the archive, its journal and the locator are unchanged.
#[test]
fn append_journal_pending_reads_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    assert_eq!(pending(&path).unwrap(), None);
    fs::write(&path, b"plain").unwrap();
    assert_eq!(pending(&path).unwrap(), None);
    interrupted(&path, "archive truncate");
    let journal = journal_path(&path);
    let (archive_before, journal_before) = (fs::read(&path).unwrap(), fs::read(&journal).unwrap());
    let found = pending(&path).unwrap().expect("a journal is pending");
    assert_eq!(found.len, b"prefix:old contents".len() as u64);
    assert_eq!(found.offset, 7);
    assert_eq!(found.new_len, 7 + b"new contents are longer".len() as u64);
    let meta = fs::metadata(&path).unwrap();
    assert_eq!(found.ino, std::os::unix::fs::MetadataExt::ino(&meta));
    assert_eq!(fs::read(&path).unwrap(), archive_before);
    assert_eq!(fs::read(&journal).unwrap(), journal_before);
    assert!(recover(&path).unwrap());
    assert_eq!(pending(&path).unwrap(), None);
}

/// Regression (#174): `pending` keeps its long-standing tolerance for a
/// journal entry that is not a regular file (`Ok(None)`), while the
/// read-only offline check refuses it the way recovery does.
#[test]
fn regression_pending_tolerates_nonregular_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    fs::write(&path, b"plain").unwrap();
    fs::create_dir(journal_path(&path)).unwrap();
    assert_eq!(pending(&path).unwrap(), None);
    assert!(offline_journal_probe(&path).is_err());
}

fn marker_present(path: &Path) -> bool {
    // A pending marker refuses the next replacement.
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"x").unwrap();
    replace_suffix_with_hook(path, 0, &mut suffix, &mut |_| Ok(())).is_err()
}

/// Regression (R7): the authorizer runs under the lock, after validation and
/// before any write, and sees the LOCKED file's metadata.
#[test]
fn append_journal_authorize_runs_under_the_lock_before_any_write() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "archive truncate");
    let journal = journal_path(&path);
    let (archive_before, journal_before) = (fs::read(&path).unwrap(), fs::read(&journal).unwrap());
    let ino = fs::metadata(&path).unwrap().ino();
    let mut seen = None;
    let error = recover_with(
        &path,
        &mut |j, m| {
            seen = Some((*j, m.ino()));
            Err(io::Error::other("not mine"))
        },
        &mut |_| panic!("the hook must not run after a refusal"),
    )
    .unwrap_err();
    assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
    let (header, seen_ino) = seen.expect("authorize ran");
    assert_eq!(seen_ino, ino);
    assert!(!header.complete);
    assert_eq!(fs::read(&path).unwrap(), archive_before);
    assert_eq!(fs::read(&journal).unwrap(), journal_before);
    assert!(pending(&path).unwrap().is_some());

    // A file swapped in after the unlocked probe is judged by the locked
    // descriptor, not by the earlier stat.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "archive truncate");
    let crashed = fs::read(&path).unwrap();
    let journal = fs::read(journal_path(&path)).unwrap();
    let swap = path.clone();
    let copy = dir.path().join("copy");
    unix::AFTER_PROBE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            fs::write(&copy, fs::read(&swap).unwrap()).unwrap();
            fs::rename(&copy, &swap).unwrap();
        }));
    });
    let error = recover_with(&path, &mut authorize_owned, &mut |_| Ok(())).unwrap_err();
    unix::AFTER_PROBE.with(|hook| *hook.borrow_mut() = None);
    assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
    assert!(error.to_string().contains("another file"), "{error}");
    assert_eq!(fs::read(&path).unwrap(), crashed);
    assert_eq!(fs::read(journal_path(&path)).unwrap(), journal);
}

/// Regression (R7): a failing `before_unlink` keeps the journal and the
/// marker; the error is `Committed` exactly when the archive holds the new
/// bytes; a second call with a succeeding hook finishes with the locked
/// descriptor's final stamp.
#[test]
fn append_journal_before_unlink_error_keeps_journal_and_marker() {
    use std::os::unix::fs::MetadataExt;
    // A fresh replacement.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    fs::write(&path, b"prefix:old contents").unwrap();
    let original = fs::metadata(&path).unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"new contents").unwrap();
    let mut stamps = Vec::new();
    let error = replace_suffix_if_unchanged_with(
        &path,
        7,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |a| {
            stamps.push(*a);
            Err(io::Error::other("rows busy"))
        },
    )
    .unwrap_err();
    assert!(matches!(error, ReplaceError::Committed(_)), "{error:?}");
    // The hook ran for the replacement and again for its cleanup.
    assert_eq!(stamps.len(), 2);
    assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
    assert!(journal_path(&path).exists());
    assert!(pending(&path).unwrap().expect("journal pending").complete);
    let mut finished = None;
    let applied = recover_with(&path, &mut authorize_forced, &mut |a| {
        finished = Some(*a);
        Ok(())
    })
    .unwrap()
    .expect("applied");
    let meta = fs::metadata(&path).unwrap();
    assert_eq!(finished, Some(applied));
    assert!(applied.rolled_forward);
    assert_eq!(applied.pre_len, b"prefix:old contents".len() as u64);
    assert_eq!(applied.new_len, b"prefix:new contents".len() as u64);
    assert_eq!(applied.final_len, meta.len());
    assert_eq!(applied.ino, meta.ino());
    assert!(!journal_path(&path).exists());
    assert!(!marker_present(&path));

    // A crash after the completion marker: recovery hook fails, then works.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator complete");
    let error = recover_with(&path, &mut authorize_forced, &mut |_| {
        Err(io::Error::other("rows busy"))
    })
    .unwrap_err();
    assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
    assert!(journal_path(&path).exists());
    assert!(recover_with(&path, &mut authorize_forced, &mut |_| Ok(()))
        .unwrap()
        .is_some());
    assert!(!journal_path(&path).exists());

    // A rollback whose hook fails is a journal error, not a commit.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "archive truncate");
    let error = recover_with(&path, &mut authorize_forced, &mut |a| {
        assert!(!a.rolled_forward);
        Err(io::Error::other("rows busy"))
    })
    .unwrap_err();
    assert!(matches!(error, RecoverError::Journal(_)), "{error:?}");
    assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
    assert!(journal_path(&path).exists());
    assert!(recover_with(&path, &mut authorize_forced, &mut |_| Ok(()))
        .unwrap()
        .is_some());
}

/// Regression (R7): the journal path comes from the LOCKED marker. A is
/// probed (J0 beside A), then another opener finishes J0 and starts J1
/// through the hard link B: the locked marker names J1, which the
/// authorizer judges. Before: the stale J0 name did not exist, so the `C`
/// marker was cleared and J1 dropped without being applied.
#[test]
fn append_journal_hardlink_second_journal_is_authorized_under_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (one, two) = (dir.path().join("one"), dir.path().join("two"));
    fs::create_dir(&one).unwrap();
    fs::create_dir(&two).unwrap();
    let (a, b) = (one.join("A"), two.join("B"));
    interrupted(&a, "archive truncate");
    fs::hard_link(&a, &b).unwrap();
    assert_ne!(journal_path(&a), journal_path(&b));
    let (seam_a, seam_b) = (a.clone(), b.clone());
    unix::AFTER_PROBE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            assert!(recover(&seam_a).unwrap());
            let mut suffix = tempfile::tempfile().unwrap();
            suffix.write_all(b"second journal").unwrap();
            assert!(
                replace_suffix_with_hook(&seam_b, 7, &mut suffix, &mut |step| {
                    if step == "locator complete" {
                        Err(io::Error::other("crash"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
        }));
    });
    let mut seen = None;
    let error = recover_with(
        &b,
        &mut |j, _| {
            seen = Some(*j);
            Err(io::Error::other("pre-stamp does not match the rows"))
        },
        &mut |_| panic!("refused"),
    )
    .unwrap_err();
    unix::AFTER_PROBE.with(|hook| *hook.borrow_mut() = None);
    assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
    assert!(seen.expect("authorizer saw J1").complete);
    assert!(journal_path(&b).exists(), "J1 stays");
    assert_eq!(fs::read(&a).unwrap(), b"prefix:second journal");
    assert!(pending(&a).unwrap().is_some());
    // Authorized (forced), J1 rolls forward through either name.
    let applied = recover_with(&a, &mut authorize_forced, &mut |_| Ok(()))
        .unwrap()
        .expect("J1 applied");
    assert!(applied.rolled_forward);
    assert!(!journal_path(&b).exists());
    assert_eq!(fs::read(&a).unwrap(), b"prefix:second journal");
}

/// Regression (R7, R7-C2): a stale prepare locator without a journal is
/// cleared without touching the archive; a done locator is kept (the
/// journal may sit beside another name); a complete one is refused with
/// the locator kept; an active one is an error.
#[test]
fn append_journal_stale_marker_without_journal_is_cleared() {
    for (step, bytes, kept) in [
        ("locator prepare", b"prefix:old contents".as_slice(), None),
        (
            "journal unlink",
            b"prefix:new contents are longer".as_slice(),
            Some(b'D'),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, step);
        let _ = fs::remove_file(journal_path(&path));
        assert!(marker_present(&path), "{step}: a marker is left");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let applied = recover_with(&path, &mut authorize_owned, &mut |_| {
            panic!("nothing to restamp")
        })
        .unwrap();
        assert!(applied.is_none());
        assert_eq!(fs::read(&path).unwrap(), bytes, "{step}");
        assert_eq!(marker_state(&path), kept, "{step}");
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator complete");
    fs::remove_file(journal_path(&path)).unwrap();
    let error = recover_with(&path, &mut authorize_owned, &mut |_| Ok(())).unwrap_err();
    assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
    assert_eq!(marker_state(&path), Some(b'C'));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator active");
    fs::remove_file(journal_path(&path)).unwrap();
    let error = recover_with(&path, &mut authorize_forced, &mut |_| Ok(())).unwrap_err();
    assert!(matches!(error, RecoverError::Journal(_)), "{error:?}");
    assert!(error.to_string().contains("missing or moved"), "{error}");
}

/// Regression (R10-B, #150): the `before_write` guard runs under the lock
/// before the stale-`P` locator is cleared and before a rollback; a refusal
/// writes nothing (locator, archive and journal stay). It never runs on the
/// write-free `D` path or the `C` refusal, so `C` stays `Committed`.
#[test]
fn regression_recover_guard_runs_before_stale_clear_and_rollback() {
    let refuse = || io::Error::other("lost record");
    // Stale `P` without a journal: kept on a refusal, cleared after an Ok.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator prepare");
    let _ = fs::remove_file(journal_path(&path));
    let before = fs::read(&path).unwrap();
    let mut calls = 0;
    let error = recover_guarded(
        &path,
        &mut || {
            calls += 1;
            Err(refuse())
        },
        &mut authorize_owned,
        &mut |_| panic!("nothing to restamp"),
    )
    .unwrap_err();
    assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
    assert_eq!(calls, 1);
    assert_eq!(marker_state(&path), Some(b'P'), "stale locator kept");
    assert_eq!(fs::read(&path).unwrap(), before);
    recover_guarded(&path, &mut || Ok(()), &mut authorize_owned, &mut |_| {
        panic!("nothing to restamp")
    })
    .unwrap();
    assert_eq!(marker_state(&path), None);
    // A torn journal: the guard refuses before the rollback.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator active");
    let before = fs::read(&path).unwrap();
    let journal = fs::read(journal_path(&path)).unwrap();
    let error = recover_guarded(
        &path,
        &mut || Err(refuse()),
        &mut |_, _| panic!("authorize runs after the guard"),
        &mut |_| panic!("nothing applied"),
    )
    .unwrap_err();
    assert!(matches!(error, RecoverError::Refused(_)), "{error:?}");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(journal_path(&path)).unwrap(), journal);
    assert_eq!(marker_state(&path), Some(b'A'));
    // A missing complete journal stays `Committed`; a `D` locator without
    // a journal writes nothing: neither consults the guard.
    for (step, expect_committed) in [("locator complete", true), ("journal unlink", false)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        interrupted(&path, step);
        let _ = fs::remove_file(journal_path(&path));
        let result = recover_guarded(
            &path,
            &mut || panic!("{step}: no write, no guard"),
            &mut authorize_owned,
            &mut |_| Ok(()),
        );
        if expect_committed {
            assert!(
                matches!(result, Err(RecoverError::Committed(_))),
                "{result:?}"
            );
        } else {
            assert!(matches!(result, Ok(None)), "{step}: {result:?}");
        }
    }
}

/// The locator state on `path`'s inode (`None` without a marker).
fn marker_state(path: &Path) -> Option<u8> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let attr = c"user.ratarmount.commit-journal";
    let mut bytes = vec![0u8; 8192];
    #[cfg(target_os = "linux")]
    let n = unsafe {
        libc::getxattr(
            name.as_ptr(),
            attr.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    #[cfg(target_os = "macos")]
    let n = unsafe {
        libc::getxattr(
            name.as_ptr(),
            attr.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            0,
            0,
        )
    };
    (n > 4).then(|| bytes[4])
}

fn remove_marker(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let attr = c"user.ratarmount.commit-journal";
    #[cfg(target_os = "linux")]
    let rc = unsafe { libc::removexattr(name.as_ptr(), attr.as_ptr()) };
    #[cfg(target_os = "macos")]
    let rc = unsafe { libc::removexattr(name.as_ptr(), attr.as_ptr(), 0) };
    assert_eq!(rc, 0, "{}", io::Error::last_os_error());
}

fn sibling(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(COMMIT_JOURNAL_SUFFIX);
    PathBuf::from(name)
}

/// Regression (r15 #1, design test 1c): an attempt that never published a
/// journal must not adopt the journal another file left at the name. B (a
/// complete journal J2, `C` on B) is renamed over A's name after A's `P`
/// and before A's publish; A's attempt fails EEXIST, rolls back nothing,
/// clears only its own `P`, and leaves B, its `C` and J2 alone.
#[test]
fn append_journal_unpublished_attempt_never_adopts_a_sibling_journal() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (d, x) = (root.join("d"), root.join("x"));
    fs::create_dir(&d).unwrap();
    fs::create_dir(&x).unwrap();
    let a = d.join("A");
    fs::write(&a, b"prefix:a old").unwrap();
    let keep = d.join("keep");
    fs::hard_link(&a, &keep).unwrap();
    let a_mtime = fs::metadata(&keep).unwrap().modified().unwrap();
    let xb = x.join("A");
    interrupted(&xb, "locator complete");
    let b_bytes = fs::read(&xb).unwrap();
    let j2_bytes = fs::read(sibling(&xb)).unwrap();
    let original = fs::metadata(&a).unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"a new").unwrap();
    let (seam_b, seam_a) = (xb.clone(), a.clone());
    fault::install(move |step| {
        if step == "locator prepare" {
            fs::rename(sibling(&seam_b), sibling(&seam_a))?;
            fs::rename(&seam_b, &seam_a)?;
        }
        Ok(())
    });
    let mut hooks = 0;
    let result = replace_suffix_if_unchanged_with(
        &a,
        7,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |_| {
            hooks += 1;
            Ok(())
        },
    );
    fault::clear();
    assert!(
        matches!(result, Err(ReplaceError::RolledBack(..))),
        "{result:?}"
    );
    assert_eq!(marker_state(&a), Some(b'C'), "B keeps its complete locator");
    assert_eq!(fs::read(&a).unwrap(), b_bytes, "B untouched");
    assert_eq!(fs::read(sibling(&a)).unwrap(), j2_bytes, "J2 untouched");
    assert_eq!(fs::read(&keep).unwrap(), b"prefix:a old");
    assert_eq!(fs::metadata(&keep).unwrap().modified().unwrap(), a_mtime);
    assert_eq!(marker_state(&keep), None, "A's own prepare locator cleared");
    assert_eq!(hooks, 0);
}

/// Regression (r15 #3, design test 7): a commit whose journal unlink or
/// directory sync failed is retried under the attempt's lock; when the
/// retry fails too the result is an error with the completion kept,
/// never success.
#[test]
fn append_journal_commit_cleanup_retries_then_stays_committed() {
    let run = |faults: &'static [&'static str]| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, b"prefix:old contents").unwrap();
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents").unwrap();
        fault::install(move |step| {
            if faults.contains(&step) {
                Err(io::Error::other(format!("injected {step}")))
            } else {
                Ok(())
            }
        });
        let mut hooks = 0;
        let result = replace_suffix_if_unchanged_with(
            &path,
            7,
            &mut suffix,
            &original,
            &mut || Ok(()),
            &mut |_| {
                hooks += 1;
                Ok(())
            },
        );
        fault::clear();
        (dir, path, result, hooks)
    };
    // (i) the directory sync fails once and the retry succeeds.
    let (_d, path, result, hooks) = run(&["commit directory sync"]);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(hooks, 1);
    assert_eq!(marker_state(&path), None);
    assert!(!journal_path(&path).exists());
    // (ii) the retry fails too: an error, the journal gone, `D` kept.
    let (_d, path, result, hooks) = run(&["commit directory sync", "cleanup directory sync"]);
    assert!(
        matches!(result, Err(ReplaceError::Committed(_))),
        "a failed cleanup is not a success: {result:?}"
    );
    assert_eq!(hooks, 1);
    assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
    assert!(!journal_path(&path).exists());
    assert_eq!(marker_state(&path), Some(b'D'));
    // A later recovery cannot tell where the journal went: `D` stays
    // until the manual escape (Astra v4 F1).
    assert!(!recover(&path).unwrap());
    assert_eq!(marker_state(&path), Some(b'D'));
    remove_marker(&path);
    assert!(!recover(&path).unwrap());
    assert!(!marker_present(&path));
    // (iii) the unlink fails once: rollback re-runs the hook and unlinks.
    let (_d, path, result, hooks) = run(&["commit unlink"]);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(hooks, 2);
    assert_eq!(marker_state(&path), None);
    assert!(!journal_path(&path).exists());
    // (iv) the retry's unlink fails too: committed, journal and `D` kept.
    let (_d, path, result, hooks) = run(&["commit unlink", "rollback unlink"]);
    assert!(
        matches!(result, Err(ReplaceError::Committed(_))),
        "{result:?}"
    );
    assert_eq!(hooks, 2);
    assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents");
    assert!(journal_path(&path).exists());
    assert_eq!(marker_state(&path), Some(b'D'));
}

/// Regression (Astra v4 F1): the completion is kept when the journal's
/// absence is ambiguous. `/d/a` has a hard link `/third/a`; the commit is
/// interrupted after its completion marker; `/d` is renamed to `/saved`.
/// Recovering through `/third/a` cannot see the journal (it moved with
/// `/d`) and must not clear the locator; recovering through `/saved/a`
/// then finds the journal beside the archive and rolls FORWARD.
#[test]
fn append_journal_completion_kept_when_the_journal_moved_with_its_directory() {
    for (step, state) in [("locator done", b'D'), ("locator complete", b'C')] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (d, third, saved) = (root.join("d"), root.join("third"), root.join("saved"));
        fs::create_dir(&d).unwrap();
        fs::create_dir(&third).unwrap();
        interrupted(&d.join("a"), step);
        fs::hard_link(d.join("a"), third.join("a")).unwrap();
        fs::rename(&d, &saved).unwrap();
        let new = b"prefix:new contents are longer".to_vec();
        let first = recover(&third.join("a"));
        // `C` (the hook may not have run) is refused; `D` is a no-op.
        assert_eq!(first.is_ok(), state == b'D', "{step}: {first:?}");
        assert_eq!(
            marker_state(&third.join("a")),
            Some(state),
            "{step}: completion kept"
        );
        assert_eq!(
            pending(&saved.join("a")).unwrap().map(|j| j.complete),
            Some(true)
        );
        assert!(recover(&saved.join("a")).unwrap(), "{step}");
        assert_eq!(
            fs::read(saved.join("a")).unwrap(),
            new,
            "{step}: rolled forward"
        );
        assert_eq!(fs::read(third.join("a")).unwrap(), new);
        assert!(!sibling(&saved.join("a")).exists());
        assert_eq!(marker_state(&third.join("a")), None);
        assert!(!recover(&third.join("a")).unwrap());
        assert_eq!(
            fs::read(third.join("a")).unwrap(),
            new,
            "{step}: idempotent"
        );
    }
}

/// Regression (Astra v3 #1): a journal moves with its renamed directory;
/// `pending` and `recover` find it beside the archive's current name.
#[test]
fn append_journal_moved_directory_journal_is_found_beside_the_archive() {
    for step in ["locator active", "locator complete", "locator done"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (d, saved) = (root.join("d"), root.join("saved"));
        fs::create_dir(&d).unwrap();
        interrupted(&d.join("a"), step);
        fs::rename(&d, &saved).unwrap();
        let a = saved.join("a");
        let found = pending(&a).unwrap();
        assert_eq!(
            found.map(|j| j.complete),
            Some(step != "locator active"),
            "{step}"
        );
        assert!(recover(&a).unwrap(), "{step}");
        let expected: &[u8] = if step == "locator active" {
            b"prefix:old contents"
        } else {
            b"prefix:new contents are longer"
        };
        assert_eq!(fs::read(&a).unwrap(), expected, "{step}");
        assert!(!sibling(&a).exists());
        assert_eq!(marker_state(&a), None);
        assert!(!recover(&a).unwrap(), "{step}: idempotent");
        // The renamed directory's old name now holds journal-free B.
        fs::create_dir(&d).unwrap();
        fs::write(d.join("a"), b"B bytes").unwrap();
        assert!(!recover(&d.join("a")).unwrap());
        assert_eq!(fs::read(d.join("a")).unwrap(), b"B bytes");
    }
    // A sibling carrying another inode's journal is never adopted.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (d, saved, other) = (root.join("d"), root.join("saved"), root.join("other"));
    fs::create_dir(&d).unwrap();
    fs::create_dir(&other).unwrap();
    interrupted(&d.join("a"), "locator complete");
    interrupted(&other.join("b"), "locator complete");
    fs::rename(&d, &saved).unwrap();
    let a = saved.join("a");
    fs::rename(sibling(&a), root.join("moved-away")).unwrap();
    fs::copy(sibling(&other.join("b")), sibling(&a)).unwrap();
    let foreign = fs::read(sibling(&a)).unwrap();
    assert_eq!(pending(&a).unwrap(), None);
    let error = recover(&a).unwrap_err();
    assert!(error.to_string().contains("missing or moved"), "{error}");
    assert_eq!(fs::read(sibling(&a)).unwrap(), foreign);
    assert_eq!(fs::read(&a).unwrap(), b"prefix:new contents are longer");
    assert_eq!(marker_state(&a), Some(b'C'));
}

/// Regression: a complete locator whose journal is gone is refused with
/// the manual escape named, never cleared (the hook may not have run).
#[test]
fn append_journal_complete_locator_without_journal_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator complete");
    fs::remove_file(journal_path(&path)).unwrap();
    let error = recover_with(&path, &mut authorize_owned, &mut |_| Ok(()))
        .expect_err("a complete locator without journal is refused");
    assert!(matches!(error, RecoverError::Committed(_)), "{error:?}");
    let error = error.into_io();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let text = error.to_string();
    assert!(text.contains("missing or moved"), "{text}");
    assert!(text.contains("user.ratarmount.commit-journal"), "{text}");
    assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents are longer");
    assert_eq!(marker_state(&path), Some(b'C'));
    remove_marker(&path);
    assert!(!recover(&path).unwrap());
}

/// Regression (Astra v2 #1): the attempt recovers only the journal file it
/// published. A byte-identical copy renamed over the journal path is
/// another file: nothing is written and the copy stays.
#[test]
fn append_journal_published_journal_replaced_at_the_path_is_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    fs::write(&path, b"prefix:old contents").unwrap();
    let original = fs::metadata(&path).unwrap();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"new contents").unwrap();
    let journal = journal_path(&path);
    let copy = dir.path().join("copy");
    let (seam_journal, seam_copy) = (journal.clone(), copy.clone());
    fault::install(move |step| {
        if step == "locator active" {
            fs::copy(&seam_journal, &seam_copy)?;
            fs::rename(&seam_copy, &seam_journal)?;
            return Err(io::Error::other("injected after the journal was replaced"));
        }
        Ok(())
    });
    let result = replace_suffix_if_unchanged_with(
        &path,
        7,
        &mut suffix,
        &original,
        &mut || Ok(()),
        &mut |_| Ok(()),
    );
    fault::clear();
    let error = result.unwrap_err();
    assert!(matches!(error, ReplaceError::Pending(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("not the journal this attempt published"),
        "{error}"
    );
    assert!(
        journal.exists(),
        "the foreign file at the journal path stays"
    );
    assert_eq!(marker_state(&path), Some(b'A'));
    assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
}

/// Regression: a stale prepare locator is cleared only after the parent
/// directory sync; a stale done locator (the journal unlinked, the clear
/// lost) is kept (Astra v4 F1: absence is ambiguous).
#[test]
fn append_journal_stale_locators_sync_before_clear_and_keep_done() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator prepare");
    assert_eq!(marker_state(&path), Some(b'P'));
    fault::install(|step| {
        if step == "stale marker directory sync" {
            Err(io::Error::other("injected sync"))
        } else {
            Ok(())
        }
    });
    let synced = recover(&path);
    fault::clear();
    assert!(synced.is_err(), "the clear waits for the directory sync");
    assert_eq!(marker_state(&path), Some(b'P'));
    assert!(!recover(&path).unwrap());
    assert_eq!(marker_state(&path), None);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "journal unlink");
    assert!(!journal_path(&path).exists());
    assert!(!recover(&path).unwrap());
    assert!(marker_state(&path).is_some(), "the completion is kept");
    assert_eq!(fs::read(&path).unwrap(), b"prefix:new contents are longer");
}

/// Regression: a rollback whose old bytes are already in place writes
/// nothing (no truncate, copy or mtime), so a second recovery of a
/// rolled-back file keeps the stamp the first one's hook recorded.
#[test]
fn append_journal_rollback_skips_writes_when_old_bytes_are_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    interrupted(&path, "locator active");
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    fault::install(|step| match step {
        "rollback truncate" | "rollback mtime" => {
            Err(io::Error::other(format!("{step}: no write expected")))
        }
        _ => Ok(()),
    });
    let recovered = recover(&path);
    fault::clear();
    assert!(recovered.unwrap(), "recovered without writing");
    assert_eq!(fs::read(&path).unwrap(), b"prefix:old contents");
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
    assert!(!journal_path(&path).exists());
    assert_eq!(marker_state(&path), None);
}

/// The contract of a failed attempt, one case per stop (design §5 cj
/// table): the variant, the bytes, whether the journal is on disk, the
/// locator and how often the hook ran.
#[test]
fn append_journal_failed_attempt_table() {
    #[derive(Debug, PartialEq)]
    enum V {
        Ok,
        Refused,
        RolledBack,
        Pending,
        Committed,
    }
    const OLD: &[u8] = b"prefix:old contents";
    const NEW: &[u8] = b"prefix:new contents";
    // (faults, variant, bytes, journal on disk, locator, hook count)
    type Case = (
        &'static [&'static str],
        V,
        &'static [u8],
        bool,
        Option<u8>,
        usize,
    );
    let table: &[Case] = &[
        (&["journal header"], V::RolledBack, OLD, false, None, 0),
        (&["journal tail"], V::RolledBack, OLD, false, None, 0),
        (&["journal fsync"], V::RolledBack, OLD, false, None, 0),
        (&["locator prepare"], V::RolledBack, OLD, false, None, 0),
        (&["journal publish"], V::RolledBack, OLD, false, None, 1),
        (
            &["journal directory fsync"],
            V::RolledBack,
            OLD,
            false,
            None,
            1,
        ),
        (&["locator active"], V::RolledBack, OLD, false, None, 1),
        (&["archive truncate"], V::RolledBack, OLD, false, None, 1),
        (&["archive write"], V::RolledBack, OLD, false, None, 1),
        (&["archive fsync"], V::RolledBack, OLD, false, None, 1),
        (&["locator complete"], V::Ok, NEW, false, None, 1),
        (&["locator done"], V::Ok, NEW, false, None, 2),
        (&["journal unlink"], V::Ok, NEW, false, None, 1),
        (&["commit directory fsync"], V::Ok, NEW, false, None, 1),
        (&["locator clear"], V::Ok, NEW, false, None, 1),
        (&["before replace"], V::Refused, OLD, false, None, 0),
        (
            &["archive write", "rollback truncate"],
            V::Pending,
            b"prefix:new contents",
            true,
            Some(b'A'),
            0,
        ),
        (
            &["archive write", "rollback unlink"],
            V::Pending,
            OLD,
            true,
            Some(b'P'),
            1,
        ),
        (
            &["locator complete", "rollback unlink"],
            V::Committed,
            NEW,
            true,
            Some(b'D'),
            1,
        ),
        (
            &["archive write", "rollback directory sync"],
            V::Pending,
            OLD,
            false,
            Some(b'P'),
            1,
        ),
    ];
    for (faults, variant, bytes, journal, locator, hooks) in table {
        let faults: &'static [&'static str] = faults;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        fs::write(&path, OLD).unwrap();
        let original = fs::metadata(&path).unwrap();
        let mut suffix = tempfile::tempfile().unwrap();
        suffix.write_all(b"new contents").unwrap();
        fault::install(move |step| {
            if faults.contains(&step) {
                Err(io::Error::other(format!("injected {step}")))
            } else {
                Ok(())
            }
        });
        let mut count = 0;
        let result = replace_suffix_if_unchanged_with(
            &path,
            7,
            &mut suffix,
            &original,
            &mut || Ok(()),
            &mut |_| {
                count += 1;
                Ok(())
            },
        );
        fault::clear();
        let got = match result {
            Ok(()) => V::Ok,
            Err(ReplaceError::Refused(_)) => V::Refused,
            Err(ReplaceError::RolledBack(..)) => V::RolledBack,
            Err(ReplaceError::Pending(_)) => V::Pending,
            Err(ReplaceError::Committed(_)) => V::Committed,
        };
        let case = format!("{faults:?}");
        assert_eq!(&got, variant, "{case}");
        assert_eq!(fs::read(&path).unwrap(), *bytes, "{case}");
        assert_eq!(journal_path(&path).exists(), *journal, "{case}");
        assert_eq!(marker_state(&path), *locator, "{case}");
        assert_eq!(count, *hooks, "{case}");
        if faults == ["archive write", "rollback directory sync"] {
            assert!(!recover(&path).unwrap());
            assert_eq!(marker_state(&path), None);
        }
    }
}

/// Regression: #238 checks refusal under the archive lock before bytes,
/// locator, or journal can change after confirmation.
#[test]
fn regression_238_prewrite_guard_runs_under_lock() {
    use std::os::fd::AsRawFd;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    let before = b"prefix:old contents";
    fs::write(&path, before).unwrap();
    let original = fs::metadata(&path).unwrap();
    let competing = File::open(&path).unwrap();
    let locator = marker_state(&path);
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(b"changed contents").unwrap();
    let mut called = false;
    let result = replace_suffix_if_unchanged_with(
        &path,
        7,
        &mut suffix,
        &original,
        &mut || {
            called = true;
            assert_eq!(
                unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                -1,
                "prewrite guard must run while the archive is locked"
            );
            assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
            Err(io::Error::other("sealed guard refusal"))
        },
        &mut |_| panic!("refused commit cannot restamp its base"),
    );
    assert!(called, "prewrite guard was skipped");
    assert!(
        matches!(result, Err(ReplaceError::Refused(ref e)) if e.to_string() == "sealed guard refusal"),
        "{result:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(marker_state(&path), locator);
    assert!(!journal_path(&path).exists());
    assert!(same_stamp(&original, &fs::metadata(&path).unwrap()));
}
