//! Process and mount operations kept behind a trait for lifecycle tests.

use super::protocol::{ApiError, Attempt, Base};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, ApiError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountState {
    Starting,
    Ready,
    Crashed,
}

pub trait Mounter {
    fn prepare(&mut self, base: &Base, indexes: &Path, timeout: Duration) -> Result<()>;
    fn spawn(
        &mut self,
        base: &Base,
        indexes: &Path,
        attempt: &Attempt,
        quota: Option<u64>,
        readonly: &[String],
    ) -> Result<()>;
    fn poll(&mut self, attempt: &Attempt) -> Result<MountState>;
    fn deleted_paths(&mut self, attempt: &Attempt) -> Result<Option<Vec<String>>>;
    /// Must leave no mounts below path, and stop/reap any owned child, before success.
    fn cleanup(&mut self, path: &Path) -> Result<()>;
}

pub fn base_args(base: &Base, indexes: &Path) -> Vec<OsString> {
    let options = &base.options;
    let mut args: Vec<OsString> = ["--foreground", "--no-file-versions", "--index-folders"]
        .into_iter()
        .map(Into::into)
        .collect();
    // JSON avoids commas in paths being treated as multiple cache folders.
    args.push(
        serde_json::to_string(&[indexes])
            .expect("UTF-8 state directory")
            .into(),
    );
    if options.git_synthetic_head {
        args.push("--git-synthetic-head".into());
    }
    if options.recursive {
        args.push("--recursive".into());
    }
    if let Some(mode) = &options.passthrough {
        args.extend(["--passthrough".into(), mode.into()]);
    }
    let uid = options.uid.unwrap_or_else(|| unsafe { libc::geteuid() });
    let gid = options.gid.unwrap_or_else(|| unsafe { libc::getegid() });
    let mut ownership = format!("noatime,uid={uid},gid={gid}");
    if let Some(mask) = &options.umask {
        ownership.push_str(&format!(",umask={mask}"));
    }
    if options.allow_other {
        ownership.push_str(",allow_other");
    }
    args.extend(["-o".into(), ownership.into()]);
    for bind in &options.binds {
        args.extend(["--bind".into(), bind.into()]);
    }
    args
}

pub fn mount_args(
    base: &Base,
    indexes: &Path,
    attempt: &Attempt,
    quota: Option<u64>,
    readonly: &[String],
) -> Vec<OsString> {
    let mut args = base_args(base, indexes);
    args.extend([
        "--sandbox-inspection-socket".into(),
        super::inspection::socket_path(attempt).into_os_string(),
    ]);
    args.extend(["-w".into(), attempt.overlay_dir.as_os_str().to_owned()]);
    if let Some(quota) = quota {
        args.extend(["--overlay-quota".into(), quota.to_string().into()]);
    }
    for glob in readonly {
        args.extend(["--overlay-readonly".into(), glob.into()]);
    }
    for glob in &base.options.allow_globs {
        args.extend(["--overlay-allow".into(), glob.into()]);
    }
    // Keep the original source positional intact: the child records it as
    // OverlayCreateInfo.base_url when it constructs the write overlay.
    args.extend([
        "--".into(),
        base.source.clone().into(),
        attempt.path.as_os_str().to_owned(),
    ]);
    args
}

pub struct ProcessMounter {
    binary: PathBuf,
    children: BTreeMap<PathBuf, Child>,
}

impl ProcessMounter {
    pub fn new(binary: PathBuf) -> Self {
        Self {
            binary,
            children: BTreeMap::new(),
        }
    }
}

/// Kill an initializing child if the supervisor disappears before it can journal
/// readiness. The getppid check closes the fork-to-prctl race on Linux.
fn supervised(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        let parent = std::process::id() as libc::pid_t;
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(io::Error::other("supervisor exited"));
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

impl Mounter for ProcessMounter {
    fn prepare(&mut self, base: &Base, indexes: &Path, timeout: Duration) -> Result<()> {
        let log = indexes.join("prepare.log");
        let mut command = Command::new(&self.binary);
        command
            .args(base_args(base, indexes))
            .args(["--no-mount", "--"])
            .arg(&base.source)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log)?);
        supervised(&mut command);
        let mut child = command.spawn()?;
        if !wait_bounded(&mut child, timeout)? {
            return Err(ApiError::new(
                "base_open_failed",
                format!("base validation failed or timed out; see {}", log.display()),
            ));
        }
        Ok(())
    }

    fn spawn(
        &mut self,
        base: &Base,
        indexes: &Path,
        attempt: &Attempt,
        quota: Option<u64>,
        readonly: &[String],
    ) -> Result<()> {
        let log = attempt
            .path
            .parent()
            .expect("attempt root")
            .join("mount.log");
        let mut command = Command::new(&self.binary);
        command
            .args(mount_args(base, indexes, attempt, quota, readonly))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(log)?);
        supervised(&mut command);
        self.children.insert(attempt.path.clone(), command.spawn()?);
        Ok(())
    }

    fn poll(&mut self, attempt: &Attempt) -> Result<MountState> {
        let Some(child) = self.children.get_mut(&attempt.path) else {
            return Ok(MountState::Crashed);
        };
        if child.try_wait()?.is_some() {
            self.children.remove(&attempt.path);
            return Ok(MountState::Crashed);
        }
        if mountpoints()?.contains(&attempt.path) {
            Ok(MountState::Ready)
        } else {
            Ok(MountState::Starting)
        }
    }

    fn deleted_paths(&mut self, attempt: &Attempt) -> Result<Option<Vec<String>>> {
        if attempt.status == "crashed" {
            return Ok(None);
        }
        super::inspection::deleted_paths(attempt)
            .map(Some)
            .map_err(Into::into)
    }

    fn cleanup(&mut self, path: &Path) -> Result<()> {
        // Try a normal unmount first for ready mounts, then lazy fallback.
        // Stop initializing children before the final mountinfo scan so they
        // cannot publish a mount after we inspected it.
        if mountpoints()?.contains(&path.to_owned()) {
            let _ = detach(&self.binary, path);
        }
        if let Some(mut child) = self.children.remove(path) {
            if !wait_bounded(&mut child, Duration::from_millis(100))? {
                let _ = child.kill();
                child.wait()?;
            }
        }
        let mut mounts: Vec<_> = mountpoints()?
            .into_iter()
            .filter(|p| p.starts_with(path))
            .collect();
        mounts.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for mount in mounts {
            detach(&self.binary, &mount)?;
        }
        Ok(())
    }
}

impl Drop for ProcessMounter {
    fn drop(&mut self) {
        let paths: Vec<_> = self.children.keys().cloned().collect();
        for path in paths {
            let _ = self.cleanup(&path);
        }
    }
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> io::Result<bool> {
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

fn detach(binary: &Path, path: &Path) -> Result<()> {
    for (program, args) in [
        (binary.as_os_str(), vec!["-u"]),
        (std::ffi::OsStr::new("fusermount3"), vec!["-u", "-z"]),
        (std::ffi::OsStr::new("fusermount"), vec!["-u", "-z"]),
        (
            std::ffi::OsStr::new("umount"),
            vec![if cfg!(target_os = "linux") {
                "-l"
            } else {
                "-f"
            }],
        ),
    ] {
        if let Ok(mut child) = Command::new(program)
            .args(args)
            .arg("--")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let _ = wait_bounded(&mut child, Duration::from_secs(3));
        }
        if !mountpoints()?.contains(&path.to_owned()) {
            return Ok(());
        }
    }
    Err(ApiError::new(
        "unmount_failed",
        format!(
            "cannot unmount {}; attempt retained for retry",
            path.display()
        ),
    ))
}

#[cfg(target_os = "linux")]
pub fn mountpoints() -> io::Result<Vec<PathBuf>> {
    Ok(parse_mountinfo(&fs::read("/proc/self/mountinfo")?))
}

#[cfg(target_os = "macos")]
pub fn mountpoints() -> io::Result<Vec<PathBuf>> {
    let mut entries: *mut libc::statfs = std::ptr::null_mut();
    let count = unsafe { libc::getmntinfo(&mut entries, libc::MNT_NOWAIT) };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(
        unsafe { std::slice::from_raw_parts(entries, count as usize) }
            .iter()
            .map(|entry| {
                let bytes =
                    unsafe { std::ffi::CStr::from_ptr(entry.f_mntonname.as_ptr()) }.to_bytes();
                PathBuf::from(OsString::from_vec(bytes.to_vec()))
            })
            .collect(),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn mountpoints() -> io::Result<Vec<PathBuf>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "sandbox mounts require Linux or macOS",
    ))
}

/// Decode the `\ooo` octal escapes of one mountinfo path field, bytewise.
/// `None` when an escape is out of byte range.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn unescape_mountinfo_field(field: &[u8]) -> Option<Vec<u8>> {
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
    Some(decoded)
}

#[cfg(any(target_os = "linux", test))]
pub fn parse_mountinfo(info: &[u8]) -> Vec<PathBuf> {
    info.split(|b| *b == b'\n')
        .filter_map(|line| {
            let field = line.split(|b| *b == b' ').nth(4)?;
            Some(PathBuf::from(OsString::from_vec(unescape_mountinfo_field(
                field,
            )?)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: daemon children must retain the base URL for overlay metadata.
    #[test]
    fn regression_overlay_meta_child_argv_preserves_base_url() {
        let base = Base {
            name: "base".into(),
            source: "hf://datasets/org/repo@revision/tree.tar".into(),
            options: Default::default(),
        };
        let attempt = Attempt {
            id: "one".into(),
            base: "base".into(),
            path: "/tmp/mount".into(),
            overlay_dir: "/tmp/overlay".into(),
            status: "starting".into(),
        };
        let args = mount_args(&base, Path::new("/tmp/index"), &attempt, None, &[]);
        let parsed =
            crate::parse_args_from(std::iter::once(OsString::from("ratarmount")).chain(args))
                .unwrap();
        let (inputs, mountpoint) = crate::split_bound_inputs_mountpoint(&parsed);
        assert_eq!(inputs, [PathBuf::from(&base.source)]);
        assert_eq!(mountpoint, Some(attempt.path));
        assert_eq!(parsed.write_overlay, Some(attempt.overlay_dir));
    }

    /// Regression: a hung helper must be killed and reaped when its deadline expires.
    #[test]
    fn regression_subprocess_deadline_reaps_child() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::process::tests::sandbox_waiting_child",
                "--ignored",
            ])
            .env("RATARMOUNT_SANDBOX_WAITING_CHILD", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(!wait_bounded(&mut child, Duration::from_millis(40)).unwrap());
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    #[ignore = "subprocess helper for deadline test"]
    fn sandbox_waiting_child() {
        if std::env::var_os("RATARMOUNT_SANDBOX_WAITING_CHILD").is_some() {
            thread::sleep(Duration::from_secs(30));
        }
    }
}
