//! Advisory file locks released by an explicit `unlock()` (#187).
//!
//! An `flock` belongs to the open file description, not to one descriptor.
//! A child forked by any thread of this process (git, tar, fusermount3)
//! holds a copy of every descriptor until it execs, and a descriptor without
//! `O_CLOEXEC` for its whole life. Closing our descriptor then leaves the lock
//! held by that copy (#184). An explicit `unlock()` releases it whatever
//! other copies exist, so every lock holder calls it at the end of its
//! critical section instead of relying on the close.

use std::fs::File;
use std::io;

/// A file whose advisory lock the caller has already taken. Dropping it, or
/// [`release`](Self::release), unlocks the file explicitly before closing it.
#[derive(Debug)]
pub struct HeldLock {
    file: Option<File>,
    what: &'static str,
}

impl HeldLock {
    /// Takes ownership of `file`, which must already be locked. `what` names
    /// the lock in the warning logged if the release on drop fails.
    pub fn new(file: File, what: &'static str) -> Self {
        Self {
            file: Some(file),
            what,
        }
    }

    pub fn file(&self) -> &File {
        self.file.as_ref().expect("held until released")
    }

    /// Unlocks the file and closes it, reporting an unlock failure.
    pub fn release(mut self) -> io::Result<()> {
        self.file.take().expect("held until released").unlock()
    }
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            unlock_or_log(&file, self.what);
        }
    }
}

/// Unlocks `file` explicitly, logging (not returning) a failure: for
/// destructors and for paths whose result must not change.
pub fn unlock_or_log(file: &File, what: &str) {
    if let Err(error) = file.unlock() {
        log::warn!("releasing the {what} lock: {error}");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    fn locked(path: &std::path::Path) -> File {
        let file = File::create(path).unwrap();
        file.try_lock().unwrap();
        file
    }

    fn free(path: &std::path::Path) -> bool {
        File::open(path).unwrap().try_lock().is_ok()
    }

    /// A sleeping child holding an inherited copy of `file`'s descriptor (the
    /// copy a concurrently forked git child holds until it execs).
    fn child_holding(file: &File) -> Child {
        let fd = file.as_raw_fd();
        let mut command = Command::new("sleep");
        command.arg("30");
        // SAFETY: fcntl is async-signal-safe; it only clears FD_CLOEXEC.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    /// Regression (#187): a lock released only by closing its descriptor
    /// stayed held while a spawned child kept an inherited copy of it.
    #[test]
    fn regression_187_held_lock_released_while_child_keeps_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");

        // Control: the close alone leaves the child's copy holding the lock.
        let plain = locked(&path);
        let mut child = child_holding(&plain);
        drop(plain);
        assert!(!free(&path), "control: the child's copy keeps the lock");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(free(&path));

        for release in [false, true] {
            let held = HeldLock::new(locked(&path), "test");
            let mut child = child_holding(held.file());
            if release {
                held.release().unwrap();
            } else {
                drop(held);
            }
            let released = free(&path);
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(released, "explicit unlock (release: {release})");
        }
    }
}
