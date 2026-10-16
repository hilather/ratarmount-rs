//! Durable rollback for an in-place archive suffix replacement.
//!
//! A published journal always means rollback. Unlink, after the new archive is
//! synced, is the commit point. No mutable completion byte can tear. Call
//! `recover` before opening the archive/index, and before each commit.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

pub fn journal_path(archive: &Path) -> PathBuf {
    let mut name = archive.as_os_str().to_os_string();
    name.push(".ratarmount-commit-journal");
    PathBuf::from(name)
}

/// Roll back an interrupted append. The old mtime is restored too, so a
/// pre-commit sidecar still describes exactly the original archive.
pub fn recover(archive: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(journal_path(archive)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
        Ok(m) if !m.is_file() => {
            return Err(io::Error::other("commit journal is not a regular file"))
        }
        Ok(_) => {}
    }
    #[cfg(unix)]
    {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(archive)?;
        let _lock = unix::lock(&file)?;
        unix::rollback(archive, &mut file)
    }
    #[cfg(not(unix))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "append recovery requires Unix",
    ))
}

/// Replace `[offset, EOF)` with a prepared suffix. Staging must finish before
/// calling this; errors leave the journal for `recover`. The caller serializes
/// commits and must stop serving a failed persist until recovery/reopen.
pub fn replace_suffix(archive: &Path, offset: u64, suffix: &mut File) -> io::Result<()> {
    replace_suffix_with_hook(archive, offset, suffix, &mut |_| Ok(()))
}

/// Refuse a staged suffix if another writer changed the archive while it was
/// being prepared. Cooperating append writers hold the same inode lock.
pub fn replace_suffix_if_unchanged(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    original: &fs::Metadata,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix::replace(archive, offset, suffix, Some(original), &mut |_| Ok(()))
    }
    #[cfg(not(unix))]
    {
        let _ = original;
        replace_suffix(archive, offset, suffix)
    }
}

/// Fault-injection/observation hook after each persistence boundary.
#[doc(hidden)]
pub fn replace_suffix_with_hook(
    archive: &Path,
    offset: u64,
    suffix: &mut File,
    hook: &mut dyn FnMut(&'static str) -> io::Result<()>,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix::replace(archive, offset, suffix, None, hook)
    }
    #[cfg(not(unix))]
    {
        let _ = (archive, offset, suffix, hook);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "append commits require Unix",
        ))
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::{Duration, UNIX_EPOCH};

    const MAGIC: &[u8; 8] = b"RMCJ0001";
    const HEADER_LEN: u64 = 64;

    pub(super) struct Lock(File);
    impl Drop for Lock {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
    pub(super) fn lock(file: &File) -> io::Result<Lock> {
        let owned = file.try_clone()?;
        if unsafe { libc::flock(owned.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Lock(owned))
    }
    fn parent(archive: &Path) -> &Path {
        archive
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
    }
    fn sync_parent(archive: &Path) -> io::Result<()> {
        File::open(parent(archive))?.sync_all()
    }

    pub(super) fn replace(
        archive: &Path,
        offset: u64,
        suffix: &mut File,
        original: Option<&fs::Metadata>,
        hook: &mut dyn FnMut(&'static str) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(archive)?;
        let _lock = lock(&file)?;
        if journal_path(archive).try_exists()? {
            return Err(io::Error::other(
                "pending commit journal; recover before preparing another commit",
            ));
        }
        let meta = file.metadata()?;
        if original.is_some_and(|old| {
            old.dev() != meta.dev()
                || old.ino() != meta.ino()
                || old.len() != meta.len()
                || old.mtime() != meta.mtime()
                || old.mtime_nsec() != meta.mtime_nsec()
                || old.ctime() != meta.ctime()
                || old.ctime_nsec() != meta.ctime_nsec()
        }) {
            return Err(io::Error::other(
                "archive changed while preparing append; retry with a fresh plan",
            ));
        }
        if offset > meta.len() {
            return Err(io::Error::other("append offset past archive EOF"));
        }
        let mut journal = tempfile::NamedTempFile::new_in(parent(archive))?;
        journal.write_all(MAGIC)?;
        for value in [
            meta.dev(),
            meta.ino(),
            meta.len(),
            offset,
            meta.mtime() as u64,
            meta.mtime_nsec() as u64,
            0,
        ] {
            journal.write_all(&value.to_le_bytes())?;
        }
        hook("journal header")?;
        file.seek(SeekFrom::Start(offset))?;
        let copied = io::copy(
            &mut (&mut file).take(meta.len() - offset),
            journal.as_file_mut(),
        )?;
        if copied != meta.len() - offset {
            return Err(io::Error::other("archive changed while journaling"));
        }
        hook("journal tail")?;
        journal.as_file().sync_all()?;
        hook("journal fsync")?;
        journal
            .persist_noclobber(journal_path(archive))
            .map_err(|e| e.error)?;
        hook("journal publish")?;
        sync_parent(archive)?;
        hook("journal directory fsync")?;
        file.set_len(offset)?;
        hook("archive truncate")?;
        file.seek(SeekFrom::Start(offset))?;
        suffix.rewind()?;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = suffix.read(&mut buf)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            hook("archive write")?;
        }
        file.sync_all()?;
        hook("archive fsync")?;
        fs::remove_file(journal_path(archive))?;
        hook("journal unlink")?;
        sync_parent(archive)?;
        hook("commit directory fsync")?;
        Ok(())
    }

    pub(super) fn rollback(archive: &Path, file: &mut File) -> io::Result<bool> {
        let mut journal = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(journal_path(archive))
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let mut header = [0; HEADER_LEN as usize];
        journal.read_exact(&mut header)?;
        let get = |i: usize| u64::from_le_bytes(header[i..i + 8].try_into().unwrap());
        let len = get(24);
        let offset = get(32);
        let seconds = get(40) as i64;
        let nanos = get(48);
        let meta = file.metadata()?;
        if &header[..8] != MAGIC
            || meta.dev() != get(8)
            || meta.ino() != get(16)
            || offset > len
            || nanos >= 1_000_000_000
            || get(56) != 0
            || len
                .checked_sub(offset)
                .and_then(|n| n.checked_add(HEADER_LEN))
                != Some(journal.metadata()?.len())
        {
            return Err(io::Error::other(
                "commit journal identity/header mismatch; archive left untouched",
            ));
        }
        file.seek(SeekFrom::Start(offset))?;
        let copied = io::copy(&mut journal, file)?;
        if copied != len - offset {
            return Err(io::Error::other("short commit journal"));
        }
        file.set_len(len)?;
        let mtime = if seconds >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(seconds as u64, nanos as u32))
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
                .and_then(|t| t.checked_add(Duration::from_nanos(nanos)))
        }
        .ok_or_else(|| io::Error::other("commit journal mtime overflow"))?;
        file.set_times(fs::FileTimes::new().set_modified(mtime))?;
        file.sync_all()?;
        fs::remove_file(journal_path(archive))?;
        sync_parent(archive)?;
        log::info!(
            "commit: recovered {} to its original length {len}",
            archive.display()
        );
        Ok(true)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    /// Regression: a crash during tail replacement must recover byte-for-byte.
    #[test]
    fn append_journal_crash_every_step_old_or_new() {
        let old: Vec<_> = (0..180_000).map(|i| (i % 251) as u8).collect();
        let tail = vec![0xb1; 150_000];
        let offset = 100_003;
        let mut new = old[..offset].to_vec();
        new.extend_from_slice(&tail);
        for stop in 0..14 {
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
            if stop > 0 && stop < 11 {
                assert!(result.is_err());
                assert_eq!(actual, old, "must roll back before unlink");
                assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
            }
        }
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
        // Model a rollback interrupted after a partial tail write and length restore.
        let mut journal = File::open(journal_path(&path)).unwrap();
        journal.seek(SeekFrom::Start(64)).unwrap();
        let mut partial = [0; 2000];
        journal.read_exact(&mut partial).unwrap();
        let mut archive = fs::OpenOptions::new().write(true).open(&path).unwrap();
        archive.seek(SeekFrom::Start(1024)).unwrap();
        archive.write_all(&partial).unwrap();
        archive.set_len(old.len() as u64).unwrap();
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
        assert!(replace_suffix_if_unchanged(&path, 0, &mut suffix, &original).is_err());
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
}
