use crate::{options::MountSpec, Mounter};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{sleep, timeout, Instant};
use tonic::Status;

struct ChildHandle {
    alive: Arc<AtomicBool>,
    stop: oneshot::Sender<()>,
    done: tokio::task::JoinHandle<()>,
}

pub struct ProcessMounter {
    binary: PathBuf,
    overlay_root: PathBuf,
    mount_timeout: Duration,
    children: Mutex<BTreeMap<String, ChildHandle>>,
}

impl ProcessMounter {
    pub fn new(binary: PathBuf, overlay_root: PathBuf, mount_timeout: Duration) -> Self {
        Self {
            binary,
            overlay_root,
            mount_timeout,
            children: Mutex::new(BTreeMap::new()),
        }
    }

    fn overlay_path(&self, target: &str) -> PathBuf {
        self.overlay_root
            .join(format!("{:x}", Sha256::digest(target.as_bytes())))
    }

    fn mount_args(&self, spec: &MountSpec) -> Result<Vec<String>, Status> {
        let mut args = Vec::new();
        let mut cap = None;
        for arg in &spec.args {
            if arg == "--overlay-tmpfs" || arg.starts_with("--overlay-tmpfs=") {
                let overlay = self.overlay_path(&spec.target);
                args.extend(["-w".into(), overlay.to_string_lossy().into_owned()]);
                if let Some(value) = arg.strip_prefix("--overlay-tmpfs=") {
                    cap = Some(crate::options::size(value)?);
                }
            } else if let Some(value) = arg.strip_prefix("--overlay-quota=") {
                let quota = crate::options::size(value)?;
                cap = Some(cap.map_or(quota, |old: u64| old.min(quota)));
            } else {
                args.push(arg.clone());
            }
        }
        if let Some(cap) = cap {
            args.insert(0, format!("--overlay-quota={cap}"));
        }
        Ok(args)
    }

    async fn detach(&self, target: &str) -> Result<(), Status> {
        if !self.mounted(target).await? {
            return Ok(());
        }
        for flags in [&["-u", "--"][..], &["-u", "-z", "--"][..]] {
            let mut command = Command::new("fusermount3");
            command
                .args(flags)
                .arg(target)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let _ = timeout(Duration::from_secs(10), command.status()).await;
            if !self.mounted(target).await? {
                return Ok(());
            }
        }
        Err(Status::internal(
            "unmount failed; install fusermount3 and check mount privileges",
        ))
    }
}

#[tonic::async_trait]
impl Mounter for ProcessMounter {
    async fn mounted(&self, target: &str) -> Result<bool, Status> {
        let info = fs::read("/proc/self/mountinfo")
            .map_err(|_| Status::internal("cannot read Linux mountinfo"))?;
        Ok(mountinfo_contains(&info, target))
    }
    async fn healthy(&self, target: &str) -> Result<bool, Status> {
        Ok(self
            .children
            .lock()
            .await
            .get(target)
            .is_some_and(|c| c.alive.load(Ordering::Acquire)))
    }
    async fn mount(&self, spec: &MountSpec, env: BTreeMap<String, String>) -> Result<(), Status> {
        let args = self.mount_args(spec)?;
        if let Some(source) = spec.args.get(spec.args.len().saturating_sub(2)) {
            if Path::new(source).is_absolute() && !Path::new(source).exists() {
                return Err(Status::not_found("local source does not exist"));
            }
        }
        if spec
            .args
            .iter()
            .any(|arg| arg == "--overlay-tmpfs" || arg.starts_with("--overlay-tmpfs="))
        {
            fs::create_dir_all(&self.overlay_root)
                .map_err(|_| Status::internal("cannot create overlay root"))?;
            fs::set_permissions(&self.overlay_root, fs::Permissions::from_mode(0o700))
                .map_err(|_| Status::internal("cannot protect overlay root"))?;
            require_tmpfs(&self.overlay_root)?;
            let overlay = self.overlay_path(&spec.target);
            fs::create_dir(&overlay)
                .map_err(|_| Status::internal("cannot create private tmpfs overlay"))?;
            fs::set_permissions(&overlay, fs::Permissions::from_mode(0o700))
                .map_err(|_| Status::internal("cannot protect overlay"))?;
        }
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", "/root")
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(target_os = "linux")]
        {
            let parent = std::process::id() as libc::pid_t;
            // SAFETY: only async-signal-safe syscalls run between fork and exec.
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent {
                        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                    }
                    Ok(())
                });
            }
        }
        let mut child = command
            .spawn()
            .map_err(|_| Status::internal("cannot spawn ratarmount"))?;
        let alive = Arc::new(AtomicBool::new(true));
        let alive_worker = alive.clone();
        let (stop, stopped) = oneshot::channel();
        let done = tokio::spawn(async move {
            tokio::select! {
                result = child.wait() => {
                    log::error!("ratarmount CSI child exited ({:?}); waiting for kubelet republish", result.ok());
                },
                _ = stopped => {
                    if timeout(Duration::from_secs(5), child.wait()).await.is_err() {
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                    }
                },
            }
            alive_worker.store(false, Ordering::Release);
        });
        self.children
            .lock()
            .await
            .insert(spec.target.clone(), ChildHandle { alive, stop, done });
        let deadline = Instant::now() + self.mount_timeout;
        loop {
            if !self.healthy(&spec.target).await? {
                return Err(Status::internal("ratarmount exited before mounting; check source, credentials and FUSE configuration"));
            }
            if self.mounted(&spec.target).await? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Status::deadline_exceeded(
                    "timed out waiting for FUSE mount",
                ));
            }
            sleep(Duration::from_millis(25)).await;
        }
    }
    async fn unmount(&self, target: &str) -> Result<(), Status> {
        // Stop the child even when detach fails; retain the journal for retry.
        let detached = self.detach(target).await;
        if let Some(child) = self.children.lock().await.remove(target) {
            let _ = child.stop.send(());
            let _ = child.done.await;
        }
        detached?;
        // Restart cleanup has no PID to trust or signal. PDEATHSIG killed the
        // old child; only its mount and driver-owned overlay need removal.
        match fs::remove_dir_all(self.overlay_path(target)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Status::internal("cannot remove private overlay")),
        }
    }
}

fn require_tmpfs(path: &Path) -> Result<(), Status> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Status::invalid_argument("invalid overlay root"))?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(path.as_ptr(), &mut stat) } == 0
            && stat.f_type == libc::TMPFS_MAGIC
        {
            return Ok(());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = path;
    Err(Status::failed_precondition(
        "overlay root must reside on Linux tmpfs",
    ))
}

pub fn mountinfo_contains(info: &[u8], target: &str) -> bool {
    info.split(|b| *b == b'\n').any(|line| {
        let Some(field) = line.split(|b| *b == b' ').nth(4) else {
            return false;
        };
        let mut decoded = Vec::new();
        let mut i = 0;
        while i < field.len() {
            if field[i] == b'\\' && i + 3 < field.len() {
                let digits = &field[i + 1..i + 4];
                if digits.iter().all(|b| (b'0'..=b'7').contains(b)) {
                    let octal = u16::from(digits[0] - b'0') * 64
                        + u16::from(digits[1] - b'0') * 8
                        + u16::from(digits[2] - b'0');
                    let Ok(byte) = u8::try_from(octal) else {
                        return false;
                    };
                    decoded.push(byte);
                    i += 4;
                    continue;
                }
            }
            decoded.push(field[i]);
            i += 1;
        }
        decoded == target.as_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a larger explicit quota must not override the tmpfs size cap.
    #[test]
    fn regression_tmpfs_private_paths_and_minimum_quota() {
        let mounter = ProcessMounter::new(
            "ratarmount".into(),
            "/dev/shm/csi".into(),
            Duration::from_secs(1),
        );
        let spec = MountSpec {
            volume_id: "base".into(),
            target: "/pods/one".into(),
            readonly: false,
            access_mode: 5,
            args: vec![
                "--foreground".into(),
                "--overlay-tmpfs=2M".into(),
                "--overlay-quota=3M".into(),
                "--".into(),
                "/base.tar".into(),
                "/pods/one".into(),
            ],
        };
        let args = mounter.mount_args(&spec).unwrap();
        assert_eq!(args[0], "--overlay-quota=2097152");
        assert!(args.contains(&"-w".into()));
        assert!(!args.iter().any(|a| a.starts_with("--overlay-tmpfs")));
        let first = mounter.overlay_path(&spec.target);
        let second = mounter.overlay_path("/pods/two");
        assert_ne!(first, second);
        assert_eq!(first, mounter.overlay_path("/pods/one"));
        assert!(first.starts_with("/dev/shm/csi"));
        let mut spec = spec;
        spec.args[2] = "--overlay-quota=1M".into();
        assert_eq!(
            mounter.mount_args(&spec).unwrap()[0],
            "--overlay-quota=1048576"
        );
    }
}
