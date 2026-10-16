//! Descriptor-relative cache access. Never follow a cache symlink.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::time::{Duration, SystemTime};

pub(super) const STAGING_MAX_AGE: Duration = Duration::from_secs(30 * 60);

pub(super) struct Directory(pub File);

fn c_name(name: &OsStr) -> io::Result<CString> {
    if name.as_bytes().contains(&b'/') || name == ".." {
        return Err(io::Error::other(
            "cache access requires a single path component",
        ));
    }
    CString::new(name.as_bytes()).map_err(|_| io::Error::other("NUL in cache path"))
}

fn fd_result(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a successful open returns a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

pub(super) fn check_private(meta: &Metadata) -> io::Result<()> {
    if meta.uid() != ratarmount_core::effective_uid() || meta.mode() & 0o022 != 0 {
        return Err(io::Error::other(
            "unsafe synthetic Git cache: must be owned by the current euid and not group/world-writable",
        ));
    }
    Ok(())
}

impl Directory {
    pub fn root(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::other("synthetic Git requires an absolute platform cache root (set XDG_CACHE_HOME or HOME)"));
        }
        let mut dir = Self(File::open("/")?);
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => match dir.child(name) {
                    Ok(child) => dir = child,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        dir.mkdir(name)?;
                        dir = dir.child(name)?;
                    }
                    Err(e) => return Err(e),
                },
                _ => return Err(io::Error::other("invalid synthetic Git cache path")),
            }
        }
        check_private(&dir.0.metadata()?)?;
        dir.0
            .set_permissions(std::fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }

    pub fn child(&self, name: &OsStr) -> io::Result<Self> {
        let name = c_name(name)?;
        // SAFETY: directory fd and NUL-terminated name are valid for this call.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        fd_result(fd).map(Self)
    }

    pub fn file(&self, name: &OsStr) -> io::Result<File> {
        let name = c_name(name)?;
        // O_NONBLOCK prevents a malicious FIFO from hanging validation.
        // SAFETY: directory fd and NUL-terminated name are valid for this call.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        let file = fd_result(fd)?;
        let meta = file.metadata()?;
        check_private(&meta)?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(io::Error::other(
                "synthetic Git cache requires ordinary, unshared files",
            ));
        }
        Ok(file)
    }

    pub fn mkdir(&self, name: &OsStr) -> io::Result<()> {
        let name = c_name(name)?;
        // SAFETY: directory fd and NUL-terminated name are valid for this call.
        if unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn create_file(&self, name: &OsStr) -> io::Result<File> {
        let name = c_name(name)?;
        // SAFETY: valid directory descriptor and terminated single-component name.
        fd_result(unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })
    }

    pub fn staging(&self) -> io::Result<(OsString, Self)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        loop {
            let name = OsString::from(format!(
                ".building-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            let c = c_name(&name)?;
            // SAFETY: valid directory descriptor and terminated generated name.
            if unsafe { libc::mkdirat(self.0.as_raw_fd(), c.as_ptr(), 0o700) } == 0 {
                let dir = self.child(&name)?;
                return Ok((name, dir));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
    }

    pub fn publish(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let from = c_name(from)?;
        let to = c_name(to)?;
        // SAFETY: both names and the pinned parent descriptor are valid.
        if unsafe {
            libc::renameat(
                self.0.as_raw_fd(),
                from.as_ptr(),
                self.0.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn discard(&self, name: &OsStr) -> io::Result<()> {
        self.child(name)?.remove_owned_contents()?;
        self.unlink(name, true)
    }

    pub fn names(&self) -> io::Result<Vec<OsString>> {
        // A separately opened descriptor has its own directory offset.
        let fd = self.child(OsStr::new("."))?.0;
        use std::os::fd::IntoRawFd;
        let raw = fd.into_raw_fd();
        // SAFETY: fdopendir takes ownership on success; closed below on failure.
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(raw);
            }
            return Err(error);
        }
        let mut names = Vec::new();
        // SAFETY: stream remains open, and d_name is terminated by readdir.
        unsafe {
            loop {
                errno::set_errno(errno::Errno(0));
                let entry = libc::readdir(stream);
                if entry.is_null() {
                    let error = errno::errno().0;
                    if error != 0 {
                        libc::closedir(stream);
                        return Err(io::Error::from_raw_os_error(error));
                    }
                    break;
                }
                let bytes = CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes();
                if bytes != b"." && bytes != b".." {
                    names.push(OsString::from_vec(bytes.to_vec()));
                }
            }
            libc::closedir(stream);
        }
        Ok(names)
    }

    fn unlink(&self, name: &OsStr, directory: bool) -> io::Result<()> {
        let name = c_name(name)?;
        // SAFETY: directory fd and NUL-terminated name are valid for this call.
        if unsafe {
            libc::unlinkat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn remove_owned_contents(&self) -> io::Result<()> {
        check_private(&self.0.metadata()?)?;
        for name in self.names()? {
            if let Ok(dir) = self.child(&name) {
                dir.remove_owned_contents()?;
                self.unlink(&name, true)?;
            } else {
                // Refuse links, special files, foreign owners and hardlinks.
                let _file = self.file(&name)?;
                self.unlink(&name, false)?;
            }
        }
        Ok(())
    }

    /// Called with the root directory lock held. New builders have no lock files.
    pub fn reclaim(&self, now: SystemTime) -> io::Result<()> {
        for name in self.names()? {
            let text = name.to_string_lossy();
            if text.starts_with(".building-") {
                if let Ok(dir) = self.child(&name) {
                    let meta = dir.0.metadata()?;
                    if check_private(&meta).is_ok()
                        && old_enough(&meta, now)
                        && dir.remove_owned_contents().is_ok()
                    {
                        self.unlink(&name, true)?;
                    }
                }
            } else if text.ends_with(".lock") {
                // Legacy per-entry locks: never remove a held lock or a recent one.
                if let Ok(file) = self.file(&name) {
                    if old_enough(&file.metadata()?, now) && file.try_lock().is_ok() {
                        self.unlink(&name, false)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn old_enough(meta: &Metadata, now: SystemTime) -> bool {
    meta.modified()
        .ok()
        .and_then(|time| now.duration_since(time).ok())
        .is_some_and(|age| age > STAGING_MAX_AGE)
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Stamp(u64, u64, u64, i64, i64, i64, i64);

impl Stamp {
    pub fn of(meta: &Metadata) -> Self {
        Self(
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    /// Regression: crashes accumulated staging trees and lock files indefinitely.
    #[test]
    fn regression_synthetic_cache_reclaims_only_abandoned_owned_staging_and_unheld_locks() {
        let temp = tempfile::tempdir().unwrap();
        let root = Directory::root(&temp.path().canonicalize().unwrap()).unwrap();
        root.0.lock().unwrap();
        let now = SystemTime::now();
        let old = now - STAGING_MAX_AGE - Duration::from_secs(60);
        for name in [".building-old", ".building-current", "completed-entry"] {
            let path = temp.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("payload"), b"data").unwrap();
            if name != ".building-current" {
                File::open(path).unwrap().set_modified(old).unwrap();
            }
        }
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"outside").unwrap();
        symlink(outside.path(), temp.path().join(".building-symlink")).unwrap();
        for name in ["stale.lock", "held.lock", "recent.lock"] {
            let file = File::create(temp.path().join(name)).unwrap();
            if name != "recent.lock" {
                file.set_modified(old).unwrap();
            }
        }
        let held = File::open(temp.path().join("held.lock")).unwrap();
        held.lock().unwrap();
        root.reclaim(now).unwrap();
        assert!(!temp.path().join(".building-old").exists());
        assert!(!temp.path().join("stale.lock").exists());
        for name in [
            ".building-current",
            "completed-entry",
            ".building-symlink",
            "held.lock",
            "recent.lock",
        ] {
            assert!(temp.path().join(name).exists(), "{name}");
        }
        assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"outside");
        drop(held);
        root.reclaim(now).unwrap();
        assert!(!temp.path().join("held.lock").exists());
    }
}
