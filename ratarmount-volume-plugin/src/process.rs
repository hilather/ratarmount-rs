use crate::options::{mount_args, Options};
use crate::Mounter;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct ProcessMounter {
    binary: PathBuf,
    timeout: Duration,
    children: BTreeMap<PathBuf, Child>,
}

impl ProcessMounter {
    pub fn new(binary: PathBuf, timeout: Duration) -> Self {
        Self {
            binary,
            timeout,
            children: BTreeMap::new(),
        }
    }

    fn detach(&self, path: &Path, lazy: bool) -> Result<(), String> {
        if !is_mounted(path).map_err(|_| "cannot read mountinfo")? {
            return Ok(());
        }
        let mut command = if lazy {
            let mut cmd = Command::new("fusermount3");
            cmd.args(["-u", "-z", "--"]).arg(path);
            cmd
        } else {
            let mut cmd = Command::new(&self.binary);
            cmd.args(["-u", "--"]).arg(path);
            cmd
        };
        if run_bounded(&mut command, Duration::from_secs(10)).unwrap_or(false)
            && !is_mounted(path).map_err(|_| "cannot read mountinfo")?
        {
            return Ok(());
        }
        // Root can still detach a broken mount if fusermount3 is unavailable.
        let mut fallback = Command::new("umount");
        if lazy {
            fallback.arg("-l");
        }
        fallback.arg("--").arg(path);
        if run_bounded(&mut fallback, Duration::from_secs(10)).unwrap_or(false)
            && !is_mounted(path).map_err(|_| "cannot read mountinfo")?
        {
            Ok(())
        } else {
            Err(
                "cannot unmount volume; ensure fusermount3 is installed and the mount is not busy"
                    .into(),
            )
        }
    }

    fn reap(&mut self, path: &Path) {
        if let Some(mut child) = self.children.remove(path) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Mounter for ProcessMounter {
    fn mount(&mut self, opts: &Options, path: &Path) -> Result<(), String> {
        self.unmount(path, true)?;
        let args = mount_args(opts, path)?;
        let child = Command::new(&self.binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot spawn ratarmount executable")?;
        self.children.insert(path.to_owned(), child);
        let deadline = Instant::now() + self.timeout;
        let result = loop {
            match self.alive(path) {
                Ok(true) => {},
                Ok(false) => break Err("ratarmount exited before mount became ready; check source, options and FUSE configuration".into()),
                Err(e) => break Err(e),
            }
            match is_mounted(path) {
                Ok(true) => break Ok(()),
                Ok(false) => {}
                Err(_) => break Err("cannot read mountinfo".into()),
            }
            if Instant::now() >= deadline {
                break Err("timed out waiting for ratarmount".into());
            }
            thread::sleep(Duration::from_millis(25));
        };
        if result.is_err() {
            // Let a partially initialized overlay clean up before forcing exit.
            if let Some(child) = self.children.get(path) {
                // SAFETY: this is our own child and has not yet been reaped.
                unsafe {
                    libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
                }
            }
            self.reap(path);
            self.detach(path, true)?;
        }
        result
    }

    fn unmount(&mut self, path: &Path, lazy: bool) -> Result<(), String> {
        self.detach(path, lazy)?;
        self.reap(path);
        Ok(())
    }

    fn alive(&mut self, path: &Path) -> Result<bool, String> {
        let Some(child) = self.children.get_mut(path) else {
            return Ok(false);
        };
        if child
            .try_wait()
            .map_err(|_| "cannot poll ratarmount child")?
            .is_some()
        {
            self.children.remove(path);
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn reconcile(&mut self, root: &Path) -> Result<(), String> {
        let mut stale: Vec<_> =
            mountpoints(&fs::read("/proc/self/mountinfo").map_err(|_| "cannot read mountinfo")?)
                .into_iter()
                .filter(|p| p.starts_with(root))
                .collect();
        // Nested mounts must be detached before their parents.
        stale.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for path in stale {
            self.detach(&path, true)?;
        }
        Ok(())
    }
}

impl Drop for ProcessMounter {
    fn drop(&mut self) {
        let paths: Vec<_> = self.children.keys().cloned().collect();
        for path in paths {
            let _ = self.detach(&path, true);
            self.reap(&path);
        }
    }
}

fn run_bounded(command: &mut Command, timeout: Duration) -> io::Result<bool> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return result.map(|_| false);
            }
        }
    }
}

pub fn is_mounted(path: &Path) -> io::Result<bool> {
    Ok(mountpoints(&fs::read("/proc/self/mountinfo")?)
        .iter()
        .any(|p| p == path))
}

/// mountinfo escapes spaces, tabs, newlines and backslashes as octal bytes.
pub fn mountpoints(info: &[u8]) -> Vec<PathBuf> {
    info.split(|b| *b == b'\n')
        .filter_map(|line| {
            let field = line.split(|b| *b == b' ').nth(4)?;
            let mut decoded = Vec::new();
            let mut i = 0;
            while i < field.len() {
                if field[i] == b'\\'
                    && i + 3 < field.len()
                    && field[i + 1..i + 4]
                        .iter()
                        .all(|b| (b'0'..=b'7').contains(b))
                {
                    let value = u16::from(field[i + 1] - b'0') * 64
                        + u16::from(field[i + 2] - b'0') * 8
                        + u16::from(field[i + 3] - b'0');
                    decoded.push(u8::try_from(value).ok()?);
                    i += 4;
                } else {
                    decoded.push(field[i]);
                    i += 1;
                }
            }
            Some(PathBuf::from(OsString::from_vec(decoded)))
        })
        .collect()
}
