//! Process and mount operations kept behind a trait for lifecycle tests.

use super::protocol::{ApiError, Attempt, Base, JournalReads, JournalSpec};
use ratarmount_compositing::LowerLayerRecord;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, ApiError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountState {
    Starting,
    Ready,
    Crashed,
}

/// What `Mounter::stop` did (R1c-1 §5.4 Stop). It never forces: no lazy
/// unmount, no force flag and no signal to the FUSE child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopOutcome {
    /// Unmounted, and the child exited (its kept status) or none was recorded
    /// (`None`, which a journaled attempt treats as unclean).
    Stopped { exit: Option<ExitStatus> },
    /// Still mounted: the unmount helper's last line is the busy error.
    Busy,
    /// Unmounted, but the child still serves: another mount of the
    /// superblock (a container's copy of the mount) keeps it alive.
    Detaching,
    /// Still mounted after any other failure; `detail` names it.
    /// `top_removed`: the helper succeeded and unmounted the top one of
    /// several mounts stacked at the path, so the mount table did change.
    Failed { detail: String, top_removed: bool },
}

/// How long the unmount helper may take (its own busy retries take about 1 s).
const HELPER_BOUND: Duration = Duration::from_secs(3);

/// What one attempt's child mounts besides the base: its policy, its lower
/// stack and its operation journal. The empty spec gives the v1 argv.
#[derive(Clone, Copy, Debug, Default)]
pub struct SpawnSpec<'a> {
    pub quota: Option<u64>,
    pub readonly: &'a [String],
    /// Canonical lower paths, bottom first.
    pub lowers: &'a [PathBuf],
    /// Preflighted bundle cache directory, for a retained attempt.
    pub bundle_cache: Option<&'a Path>,
    /// The journal file the supervisor chose, and its options.
    pub journal: Option<(&'a Path, &'a JournalSpec)>,
}

pub trait Mounter {
    fn prepare(&mut self, base: &Base, indexes: &Path, timeout: Duration) -> Result<()>;
    fn spawn(
        &mut self,
        base: &Base,
        indexes: &Path,
        attempt: &Attempt,
        spec: &SpawnSpec<'_>,
    ) -> Result<()>;
    fn poll(&mut self, attempt: &Attempt) -> Result<MountState>;
    fn deleted_paths(&mut self, attempt: &Attempt) -> Result<Option<Vec<String>>>;
    /// The lower layers a ready child composed, as its own overlay recorded
    /// them, answered within `timeout`. Never goes through FUSE.
    fn lower_layers(
        &mut self,
        attempt: &Attempt,
        timeout: Duration,
    ) -> Result<Vec<LowerLayerRecord>>;
    /// Must leave no mounts below path, and stop/reap any owned child, before success.
    fn cleanup(&mut self, path: &Path) -> Result<()>;
    /// Stops a finalizing attempt without forcing anything (R1c-1 §5.4):
    /// the unmount helper's normal unmount only, then up to `wait` for its
    /// child to exit.
    fn stop(&mut self, attempt: &Attempt, wait: Duration) -> Result<StopOutcome>;
    /// The child's `erofs_denied` count over the inspection socket, answered
    /// within `timeout`.
    fn status(&mut self, attempt: &Attempt, timeout: Duration) -> Result<u64>;
    /// Whether a recorded child of the attempt is still running.
    fn child_alive(&mut self, attempt: &Attempt) -> bool;
    /// Forgets the attempt's child entry and kept exit status (the child has
    /// exited); unmounts and signals nothing. Called when a retained
    /// attempt's tree moved, so no entry outlives its path.
    fn forget_child(&mut self, path: &Path);
    /// Every mount point of this process's mount namespace.
    fn mount_points(&self) -> Result<Vec<PathBuf>>;
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

/// Longest argument `execve` takes on Linux (`MAX_ARG_STRLEN` with 4 KiB
/// pages), its terminating NUL included.
pub const MAX_ARG_BYTES: usize = 128 << 10;

/// One journal exclude glob as one argument: as a separate value, a glob
/// that starts with `-` would be parsed as another option.
fn journal_exclude_arg(glob: &str) -> OsString {
    format!("--journal-exclude={glob}").into()
}

/// Most bytes the journal exclude arguments may take of the child's argv
/// together, as `execve` counts them against `ARG_MAX` (2 MiB by default):
/// each argument, its NUL and its pointer.
pub const MAX_EXCLUDE_ARGV_BYTES: usize = 512 << 10;

/// What the journal exclude arguments take of the child's argv.
pub fn excludes_argv_bytes(excludes: &[String]) -> usize {
    excludes
        .iter()
        .map(|glob| journal_exclude_arg(glob).len() + 1 + std::mem::size_of::<*const u8>())
        .sum()
}

/// Why no argv can carry the journal exclude `glob`, if none can: spawning
/// the child would fail only once its attempt exists.
pub fn unspawnable_exclude(glob: &str) -> Option<String> {
    if glob.contains('\0') {
        Some("contains NUL".into())
    } else if journal_exclude_arg(glob).len() >= MAX_ARG_BYTES {
        Some(format!(
            "is longer than one argument may be ({MAX_ARG_BYTES} bytes with its flag and terminating NUL)"
        ))
    } else {
        None
    }
}

pub fn mount_args(
    base: &Base,
    indexes: &Path,
    attempt: &Attempt,
    spec: &SpawnSpec<'_>,
) -> Vec<OsString> {
    let mut args = base_args(base, indexes);
    args.push("--no-recreate-index".into());
    args.extend([
        "--sandbox-inspection-socket".into(),
        super::inspection::socket_path(attempt).into_os_string(),
    ]);
    if let Some(cache) = spec.bundle_cache {
        args.extend([
            "--sandbox-bundle-cache".into(),
            cache.as_os_str().to_owned(),
        ]);
    }
    args.extend(["-w".into(), attempt.overlay_dir.as_os_str().to_owned()]);
    if let Some(quota) = spec.quota {
        args.extend(["--overlay-quota".into(), quota.to_string().into()]);
    }
    for glob in spec.readonly {
        args.extend(["--overlay-readonly".into(), glob.into()]);
    }
    for glob in &base.options.allow_globs {
        args.extend(["--overlay-allow".into(), glob.into()]);
    }
    // Validated, sealed lowers only: never --allow-unsealed-lower or
    // --force-stack-mismatch.
    for lower in spec.lowers {
        args.extend(["--lower".into(), lower.as_os_str().to_owned()]);
    }
    if let Some((path, journal)) = spec.journal {
        args.extend(["--journal".into(), path.as_os_str().to_owned()]);
        for glob in &journal.exclude {
            args.push(journal_exclude_arg(glob));
        }
        if journal.reads == JournalReads::First {
            args.extend(["--journal-reads".into(), "first".into()]);
        }
        if journal.sync {
            args.push("--journal-sync".into());
        }
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
    /// Every reaped child's exit status, by attempt path, from `poll` and
    /// `stop`, kept until `cleanup`: a finalize reads the status of a child
    /// `supervise()` reaped earlier (§5.4 step 4b).
    exits: BTreeMap<PathBuf, ExitStatus>,
    /// Test seams: the unmount helper `stop` runs instead of the daemon's
    /// binary, and a file listing the mounted paths (one per line) read
    /// instead of the mount table.
    #[cfg(test)]
    pub helper: Option<PathBuf>,
    #[cfg(test)]
    mount_table: Option<PathBuf>,
}

impl ProcessMounter {
    pub fn new(binary: PathBuf) -> Self {
        Self {
            binary,
            children: BTreeMap::new(),
            exits: BTreeMap::new(),
            #[cfg(test)]
            helper: None,
            #[cfg(test)]
            mount_table: None,
        }
    }

    /// Records `child` as the attempt's mount process (tests stand in a
    /// child for `spawn`).
    #[cfg(test)]
    pub fn adopt(&mut self, path: &Path, child: Child) {
        self.children.insert(path.into(), child);
    }

    fn mounted(&self) -> io::Result<Vec<PathBuf>> {
        #[cfg(test)]
        if let Some(table) = &self.mount_table {
            return Ok(fs::read_to_string(table)?
                .lines()
                .filter(|line| !line.is_empty())
                .map(PathBuf::from)
                .collect());
        }
        mountpoints()
    }

    /// Runs the unmount helper `<binary> -u -- PATH`, which runs only a
    /// normal `fusermount3 -u` (busy retries for about 1 s; never `-z`), with
    /// `RUST_LOG=off` so debug logging cannot fill its stderr pipe. Bounded
    /// by [`HELPER_BOUND`], killed and reaped there. Returns its status
    /// (`None` when killed) and its last non-empty stderr line.
    fn unmount_helper(&self, path: &Path) -> io::Result<(Option<ExitStatus>, String)> {
        #[cfg(test)]
        let program = self.helper.as_ref().unwrap_or(&self.binary);
        #[cfg(not(test))]
        let program = &self.binary;
        let mut child = Command::new(program)
            .args(["-u", "--"])
            .arg(path)
            .env("RUST_LOG", "off")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let status = wait_status_bounded(&mut child, HELPER_BOUND)?;
        let mut stderr = Vec::new();
        if let Some(mut pipe) = child.stderr.take() {
            // The helper has exited: read what it wrote, never waiting for a
            // descendant that may still hold the pipe.
            use std::io::Read;
            if let Ok(flags) = rustix::fs::fcntl_getfl(&pipe) {
                let _ = rustix::fs::fcntl_setfl(&pipe, flags | rustix::fs::OFlags::NONBLOCK);
            }
            let mut chunk = [0u8; 4096];
            while stderr.len() < 64 << 10 {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => stderr.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        }
        let last = String::from_utf8_lossy(&stderr)
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
            .unwrap_or("")
            .to_owned();
        Ok((status, last))
    }

    /// After the unmount: whether the recorded child exits within `wait`.
    fn wait_child(&mut self, path: &Path, wait: Duration) -> io::Result<StopOutcome> {
        let Some(child) = self.children.get_mut(path) else {
            return Ok(StopOutcome::Stopped {
                exit: self.exits.get(path).copied(),
            });
        };
        let deadline = Instant::now() + wait;
        loop {
            if let Some(status) = child.try_wait()? {
                self.children.remove(path);
                self.exits.insert(path.into(), status);
                return Ok(StopOutcome::Stopped { exit: Some(status) });
            }
            if Instant::now() >= deadline {
                return Ok(StopOutcome::Detaching);
            }
            thread::sleep(Duration::from_millis(20));
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0114-M01","item":"<ratarmount::sandbox::process::ProcessMounter as ratarmount::sandbox::process::Mounter<ratarmount::sandbox::process::ProcessMounter>>::prepare","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"child stdio setup","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )]
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
        spec: &SpawnSpec<'_>,
    ) -> Result<()> {
        let log = attempt
            .path
            .parent()
            .expect("attempt root")
            .join("mount.log");
        let mut command = Command::new(&self.binary);
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0115-M01","item":"<ratarmount::sandbox::process::ProcessMounter as ratarmount::sandbox::process::Mounter<ratarmount::sandbox::process::ProcessMounter>>::spawn","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"child stdio setup","mode_policy":"unchanged-from-e6ca64e","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )]
        command
            .args(mount_args(base, indexes, attempt, spec))
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
        if let Some(status) = child.try_wait()? {
            self.children.remove(&attempt.path);
            self.exits.insert(attempt.path.clone(), status);
            return Ok(MountState::Crashed);
        }
        if self.mounted()?.contains(&attempt.path) {
            Ok(MountState::Ready)
        } else {
            Ok(MountState::Starting)
        }
    }

    /// Through the inspection socket while the child serves (`starting`,
    /// `ready`, and a `finalizing` attempt whose child is still alive, which
    /// holds its overlay database exclusively); offline otherwise (`None`).
    fn deleted_paths(&mut self, attempt: &Attempt) -> Result<Option<Vec<String>>> {
        let serving = match attempt.status.as_str() {
            "starting" | "ready" => true,
            "finalizing" => self.child_alive(attempt),
            _ => false,
        };
        if !serving {
            return Ok(None);
        }
        super::inspection::deleted_paths(attempt)
            .map(Some)
            .map_err(Into::into)
    }

    fn lower_layers(
        &mut self,
        attempt: &Attempt,
        timeout: Duration,
    ) -> Result<Vec<LowerLayerRecord>> {
        super::inspection::lower_layers(attempt, timeout).map_err(Into::into)
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
        self.exits.remove(path);
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

    /// The non-forcing stop (R1c-1 §5.4 Stop): if the attempt's path is
    /// mounted, the helper's normal unmount; the mount table then decides
    /// (still mounted: `Busy` when its last line is the busy error, else
    /// `Failed`, also when the helper succeeded: it unmounted the top one of
    /// several mounts stacked at the path); whether to wait for a child comes
    /// from the child registry, never from the attempt's status.
    fn stop(&mut self, attempt: &Attempt, wait: Duration) -> Result<StopOutcome> {
        let path = &attempt.path;
        if self.mounted()?.contains(path) {
            let (status, last) = self.unmount_helper(path)?;
            if self.mounted()?.contains(path) {
                return Ok(match status {
                    Some(_) if ratarmount_fuse::is_busy_unmount_error(&last) => StopOutcome::Busy,
                    Some(status) if status.success() => StopOutcome::Failed {
                        detail: format!(
                            "the unmount helper unmounted the top mount at {0}, but {0} is still mounted: more than one mount was stacked there{1}",
                            path.display(),
                            if last.is_empty() {
                                String::new()
                            } else {
                                format!("; its last line: {last}")
                            }
                        ),
                        top_removed: true,
                    },
                    Some(status) => StopOutcome::Failed {
                        detail: if last.is_empty() {
                            format!("the unmount helper failed ({status})")
                        } else {
                            last
                        },
                        top_removed: false,
                    },
                    None => StopOutcome::Failed {
                        detail: format!(
                            "the unmount helper did not finish within {} s",
                            HELPER_BOUND.as_secs()
                        ),
                        top_removed: false,
                    },
                });
            }
        }
        Ok(self.wait_child(path, wait)?)
    }

    fn status(&mut self, attempt: &Attempt, timeout: Duration) -> Result<u64> {
        super::inspection::status(attempt, timeout)
            .map(|status| status.erofs_denied)
            .map_err(|e| {
                ApiError::new(
                    "io",
                    format!(
                        "cannot read the erofs_denied count of attempt {}: {e}",
                        attempt.id
                    ),
                )
            })
    }

    fn child_alive(&mut self, attempt: &Attempt) -> bool {
        let Some(child) = self.children.get_mut(&attempt.path) else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                self.children.remove(&attempt.path);
                self.exits.insert(attempt.path.clone(), status);
                false
            }
            Err(_) => false,
        }
    }

    fn forget_child(&mut self, path: &Path) {
        self.children.remove(path);
        self.exits.remove(path);
    }

    fn mount_points(&self) -> Result<Vec<PathBuf>> {
        Ok(self.mounted()?)
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
    Ok(wait_status_bounded(child, timeout)?.is_some_and(|status| status.success()))
}

/// Waits up to `timeout` for `child`: its exit status, or `None` once it was
/// killed and reaped at the bound.
fn wait_status_bounded(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return result.map(|_| None);
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
    Ok(parse_mountinfo(&{
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0116-M01","item":"ratarmount::sandbox::process::mountpoints","disposition":"out-of-family","category":"kernel-or-process-introspection","reason":"/proc or mount-table introspection","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let __inventory_value_0 = fs::read("/proc/self/mountinfo");
        __inventory_value_0
    }?))
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

/// A blocking Unix stream socket with CLOEXEC. `SOCK_CLOEXEC` is taken
/// atomically at `socket()` on Linux, where it exists; on macOS `FD_CLOEXEC`
/// is set right after `socket()` because no `SOCK_CLOEXEC` exists: the
/// supervisor's serve thread, the only caller, is also the only thread that
/// spawns children, so none can inherit the socket in between.
pub(crate) fn stream_socket() -> io::Result<rustix::fd::OwnedFd> {
    use rustix::net::{AddressFamily, SocketType};
    #[cfg(target_os = "linux")]
    {
        rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(Into::into)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
        rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
        Ok(socket)
    }
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
        let args = mount_args(
            &base,
            Path::new("/tmp/index"),
            &attempt,
            &SpawnSpec::default(),
        );
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
        let _processes = ratarmount_index::test_process::spawning();
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

    /// Regression (R1c-1 carry-in 1, Keystone note 1): the inspection socket
    /// must be CLOEXEC — a dropped `SocketFlags::CLOEXEC` would leak it into
    /// every later child. `stream_socket` takes the flag atomically at
    /// `socket()` on Linux and sets `FD_CLOEXEC` right after elsewhere; the
    /// test guards only that the flag is set, not how it got there.
    #[test]
    fn regression_inspection_socket_cloexec() {
        let socket = stream_socket().unwrap();
        let flags = rustix::io::fcntl_getfd(&socket).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    fn write_helper(path: &Path, script: &str, during: &mut dyn FnMut()) {
        // #296: another thread's fork must not inherit a writable helper fd.
        let mut writer = Command::new("sh")
            .arg("-c")
            .arg(r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#)
            .arg("sh")
            .arg(script)
            .arg(path)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        during();
        assert!(writer.wait().unwrap().success());
    }

    /// A `ProcessMounter` whose unmount helper is the script `body` (run as
    /// `HELPER -u -- PATH`, its argv appended to `argv.log`) and whose mount
    /// table is the file `mounts`, listing `path`.
    fn stopper(dir: &Path, body: &str, path: &Path) -> ProcessMounter {
        let helper = dir.join("helper.sh");
        let script = format!(
            "#!/bin/sh\nprintf '%s ' \"$@\" >> '{}'\necho >> '{}'\n{body}\n",
            dir.join("argv.log").display(),
            dir.join("argv.log").display()
        );
        write_helper(&helper, &script, &mut || {});
        let table = dir.join("mounts");
        fs::write(&table, format!("{}\n", path.display())).unwrap();
        let mut mounter = ProcessMounter::new(PathBuf::from("/nonexistent/ratarmount"));
        mounter.helper = Some(helper);
        mounter.mount_table = Some(table);
        mounter
    }

    fn attempt_at(path: &Path, status: &str) -> Attempt {
        Attempt {
            id: "attempt-000001".into(),
            base: "task".into(),
            path: path.into(),
            overlay_dir: path.with_file_name("overlay"),
            status: status.into(),
        }
    }

    /// A child that records any catchable signal and exits 0 once `stop`
    /// exists.
    fn fuse_child(dir: &Path) -> Child {
        Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'echo signal >> {0}/signals' TERM INT HUP; while [ ! -e {0}/stop ]; do sleep 0.02; done; exit 0",
                dir.display()
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    /// Regression: #296 helper exec must survive a child holding forked fds.
    #[cfg(target_os = "linux")]
    #[test]
    fn regression_296_helper_exec_survives_a_paused_forked_child() {
        let _processes = ratarmount_index::test_process::spawning();
        // Isolate the parked fork from other tests' writable descriptors.
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::process::tests::sandbox_paused_forked_child",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains("#296 helper executed"), "{stdout}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "subprocess helper for #296 paused-fork regression"]
    fn sandbox_paused_forked_child() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;

        struct PausedChild {
            release: io::PipeWriter,
            worker: Option<thread::JoinHandle<io::Result<ExitStatus>>>,
        }

        impl Drop for PausedChild {
            fn drop(&mut self) {
                if let Some(worker) = self.worker.take() {
                    let _ = self.release.write_all(b"x");
                    let _ = worker.join();
                }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnt");
        let helper = dir.path().join("helper.sh");
        let table = dir.path().join("mounts");
        let argv = dir.path().join("argv.log");
        fs::write(&table, format!("{}\n", path.display())).unwrap();
        let script = format!(
            "#!/bin/sh\nprintf '%s ' \"$@\" >> '{0}'\necho >> '{0}'\n: > '{1}'\nexit 0\n",
            argv.display(),
            table.display()
        );
        let (mut ready, ready_writer) = io::pipe().unwrap();
        let (release_reader, release) = io::pipe().unwrap();
        let mut paused = PausedChild {
            release,
            worker: None,
        };
        let mut pipes = Some((ready_writer, release_reader));
        write_helper(&helper, &script, &mut || {
            let (ready_writer, release_reader) = pipes.take().unwrap();
            // spawn waits for exec, so it must run on another thread.
            paused.worker = Some(thread::spawn(move || {
                let mut command = Command::new("true");
                // Only async-signal-safe pipe operations before exec.
                unsafe {
                    command.pre_exec(move || {
                        if libc::write(ready_writer.as_raw_fd(), b"x".as_ptr().cast(), 1) != 1 {
                            return Err(io::Error::last_os_error());
                        }
                        let mut byte = 0u8;
                        if libc::read(release_reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1)
                            != 1
                        {
                            return Err(io::Error::from_raw_os_error(libc::EIO));
                        }
                        Ok(())
                    });
                }
                command.spawn()?.wait()
            }));
            ready.read_exact(&mut [0]).unwrap();
        });
        let mut mounter = ProcessMounter::new(PathBuf::from("/nonexistent/ratarmount"));
        mounter.helper = Some(helper);
        mounter.mount_table = Some(table);
        assert_eq!(
            mounter
                .stop(&attempt_at(&path, "ready"), Duration::ZERO)
                .unwrap(),
            StopOutcome::Stopped { exit: None }
        );
        assert_eq!(
            fs::read_to_string(argv).unwrap(),
            format!("-u -- {} \n", path.display())
        );
        paused.release.write_all(b"x").unwrap();
        let exit = paused.worker.take().unwrap().join().unwrap().unwrap();
        assert!(exit.success(), "{exit}");
        println!("#296 helper executed");
    }

    /// Regression (R1c-1 T5, ruling 7): finalize's stop decides from the
    /// mount table, the unmount helper's last line and the child registry,
    /// never from the attempt's status, and never forces: only `-u -- PATH`
    /// runs (no `-z`, `umount -l` or force flag) and the FUSE child gets no
    /// signal. Busy forms (glibc, musl; `(busy)`, `(still busy …)`) are
    /// `Busy`; any other failure, a missing `fusermount3` and a stalled
    /// helper (killed and reaped at its bound) are `Failed`; a child alive
    /// after the unmount is `Detaching`, also for a crashed attempt. A helper
    /// that exits 0 with the path still mounted (it unmounted the top one of
    /// several mounts stacked there) is `Failed` saying so (PR #251 review
    /// round 1, Keystone (3); sweep 1 Claude N2): it read "the unmount helper
    /// failed (exit status: 0)".
    #[test]
    fn regression_supervisor_stop_decides_without_forcing() {
        if !cfg!(target_os = "linux") {
            eprintln!("skip: the sandbox supervisor's finalize is Linux only");
            return;
        }
        let _processes = ratarmount_index::test_process::spawning();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnt");
        let line = |detail: &str| {
            format!(
                "echo 'error unmounting {0}: fusermount failed for {0}: fusermount3: failed to unmount {0}: {detail}' >&2\nexit 1",
                path.display()
            )
        };
        // Not mounted, no child.
        let mut mounter = stopper(dir.path(), "exit 0", &path);
        fs::write(dir.path().join("mounts"), "").unwrap();
        assert_eq!(
            mounter
                .stop(&attempt_at(&path, "ready"), Duration::ZERO)
                .unwrap(),
            StopOutcome::Stopped { exit: None }
        );
        // Busy, in each form.
        for detail in [
            "Device or resource busy (busy)",
            "Resource busy (busy)",
            "Device or resource busy (still busy after 20 attempts over ~1003ms)",
            "Resource busy (still busy after 3 attempts over ~120ms)",
        ] {
            let mut mounter = stopper(dir.path(), &line(detail), &path);
            assert_eq!(
                mounter
                    .stop(&attempt_at(&path, "ready"), Duration::ZERO)
                    .unwrap(),
                StopOutcome::Busy,
                "{detail}"
            );
        }
        // Any other failure, and no fusermount3.
        for (body, needle) in [
            (line("Operation not permitted"), "Operation not permitted"),
            (
                format!(
                    "echo 'error unmounting {}: No such file or directory (os error 2)' >&2\nexit 1",
                    path.display()
                ),
                "No such file or directory",
            ),
        ] {
            let mut mounter = stopper(dir.path(), &body, &path);
            match mounter.stop(&attempt_at(&path, "ready"), Duration::ZERO).unwrap() {
                StopOutcome::Failed { detail, top_removed } => {
                    assert!(detail.contains(needle), "{detail}");
                    assert!(!top_removed);
                }
                other => panic!("{other:?}"),
            }
        }
        // The helper succeeds, but the path stays mounted: `Failed`, saying
        // the helper unmounted only the top one of the mounts stacked at the
        // path, with its last line when it printed one.
        for (body, last) in [
            ("exit 0", None),
            (
                "echo 'note: unmounted' >&2\nexit 0",
                Some("note: unmounted"),
            ),
        ] {
            let mut mounter = stopper(dir.path(), body, &path);
            match mounter
                .stop(&attempt_at(&path, "ready"), Duration::ZERO)
                .unwrap()
            {
                StopOutcome::Failed {
                    detail,
                    top_removed,
                } => {
                    assert!(top_removed);
                    let top = format!("unmounted the top mount at {}", path.display());
                    let still = format!("{} is still mounted", path.display());
                    assert!(detail.contains(&top), "{detail}");
                    assert!(detail.contains(&still), "{detail}");
                    assert!(
                        detail.contains("more than one mount was stacked there"),
                        "{detail}"
                    );
                    assert!(!detail.contains("exit status"), "{detail}");
                    assert_eq!(detail.contains("its last line"), last.is_some(), "{detail}");
                    if let Some(last) = last {
                        assert!(detail.ends_with(last), "{detail}");
                    }
                }
                other => panic!("{other:?}"),
            }
        }
        // A stalled helper: killed and reaped at its bound.
        let mut mounter = stopper(dir.path(), "exec sleep 30", &path);
        let started = Instant::now();
        match mounter
            .stop(&attempt_at(&path, "ready"), Duration::ZERO)
            .unwrap()
        {
            StopOutcome::Failed {
                detail,
                top_removed,
            } => {
                assert!(detail.contains("did not finish"), "{detail}");
                assert!(!top_removed);
            }
            other => panic!("{other:?}"),
        }
        assert!(started.elapsed() < HELPER_BOUND + Duration::from_secs(1));
        // Unmounted, the child alive: Detaching, also for a crashed attempt;
        // the child is never signalled and is reaped once it exits.
        for status in ["ready", "crashed"] {
            let _ = fs::remove_file(dir.path().join("stop"));
            let unmount = format!(": > '{}'", dir.path().join("mounts").display());
            let mut mounter = stopper(dir.path(), &unmount, &path);
            mounter.adopt(&path, fuse_child(dir.path()));
            assert_eq!(
                mounter
                    .stop(&attempt_at(&path, status), Duration::from_millis(100))
                    .unwrap(),
                StopOutcome::Detaching,
                "{status}"
            );
            assert!(mounter.child_alive(&attempt_at(&path, status)));
            fs::write(dir.path().join("stop"), b"").unwrap();
            match mounter
                .stop(&attempt_at(&path, "finalizing"), Duration::from_secs(5))
                .unwrap()
            {
                StopOutcome::Stopped { exit: Some(exit) } => assert!(exit.success()),
                other => panic!("{other:?}"),
            }
        }
        assert!(
            !dir.path().join("signals").exists(),
            "no signal to the child"
        );
        // Only `-u -- PATH`, every time.
        let argv = fs::read_to_string(dir.path().join("argv.log")).unwrap();
        for invocation in argv.lines() {
            assert_eq!(invocation.trim_end(), format!("-u -- {}", path.display()));
        }
        assert!(argv.lines().count() >= 8, "{argv}");
    }

    /// Regression (R1c-1 T5, sweep 2 Codex B2): `poll` dropped a reaped
    /// child's status, so a journaled attempt whose mount exited 1 could not
    /// be told from a clean one. Every reaped status is kept, from `poll` and
    /// from `stop`, until `cleanup`.
    #[test]
    fn regression_supervisor_stop_keeps_exit_status() {
        let _processes = ratarmount_index::test_process::spawning();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnt");
        for code in [0, 1] {
            for reaped_by_poll in [false, true] {
                let mut mounter = stopper(dir.path(), "exit 0", &path);
                fs::write(dir.path().join("mounts"), "").unwrap();
                let child = Command::new("sh")
                    .args(["-c", &format!("exit {code}")])
                    .spawn()
                    .unwrap();
                mounter.adopt(&path, child);
                std::thread::sleep(Duration::from_millis(100));
                let attempt = attempt_at(&path, "ready");
                if reaped_by_poll {
                    assert_eq!(mounter.poll(&attempt).unwrap(), MountState::Crashed);
                }
                match mounter.stop(&attempt, Duration::from_secs(5)).unwrap() {
                    StopOutcome::Stopped { exit: Some(exit) } => {
                        assert_eq!(exit.code(), Some(code), "poll first: {reaped_by_poll}")
                    }
                    other => panic!("{other:?}"),
                }
                // Kept for a retry, forgotten by cleanup.
                assert!(matches!(
                    mounter.stop(&attempt, Duration::ZERO).unwrap(),
                    StopOutcome::Stopped { exit: Some(_) }
                ));
                mounter.mount_table = None;
                mounter.cleanup(&path).unwrap();
                mounter.mount_table = Some(dir.path().join("mounts"));
                assert_eq!(
                    mounter.stop(&attempt, Duration::ZERO).unwrap(),
                    StopOutcome::Stopped { exit: None }
                );
            }
        }
    }

    /// Runs `status` on its own thread and, should it not answer within a
    /// few seconds (a connect waiting on a full backlog), closes `listener`
    /// to release it, so a regression fails instead of hanging. Returns the
    /// answer and how long the read took.
    fn status_with_watchdog(
        attempt: &Attempt,
        timeout: Duration,
        listener: std::os::unix::net::UnixListener,
    ) -> (Result<u64>, Duration) {
        let (done, answered) = std::sync::mpsc::channel();
        let attempt = attempt.clone();
        let call = thread::spawn(move || {
            let started = Instant::now();
            let answer = ProcessMounter::new(PathBuf::from("/nonexistent/ratarmount"))
                .status(&attempt, timeout);
            let _ = done.send(());
            (answer, started.elapsed())
        });
        let _ = answered.recv_timeout(timeout + Duration::from_secs(3));
        drop(listener);
        call.join().unwrap()
    }

    /// Regression (PR #251 review round 1, Keystone (2); sweep 1 Codex B1):
    /// `status` read the child's `erofs_denied` with a fixed 5 s timeout,
    /// whatever it was given, and its connect had no bound at all. A socket
    /// that accepts the connection (its backlog has room) and never answers
    /// fails the read after about the given timeout: at least 80% of it (the
    /// read did wait) and less than a second more. On Linux a listener whose
    /// backlog is full (a child that stopped accepting, its earlier connects
    /// still queued) made the connect wait until the listener closed; it
    /// fails within the timeout too. (BSD and macOS refuse such a connect at
    /// once, so that row is Linux only.)
    #[test]
    fn regression_supervisor_status_read_bounded_by_its_timeout() {
        let timeout = Duration::from_millis(300);
        for full_backlog in [false, true] {
            if full_backlog && !cfg!(target_os = "linux") {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let attempt = attempt_at(&dir.path().join("mnt"), "ready");
            let path = super::super::inspection::socket_path(&attempt);
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            // Backlog 0: the one queued connect fills it.
            let _queued = full_backlog.then(|| {
                rustix::net::listen(&listener, 0).unwrap();
                std::os::unix::net::UnixStream::connect(&path).unwrap()
            });
            let (answer, held) = status_with_watchdog(&attempt, timeout, listener);
            let error = answer.unwrap_err();
            assert_eq!(error.code, "io", "{}", error.message);
            assert!(
                error.message.contains("erofs_denied count of attempt"),
                "{}",
                error.message
            );
            assert!(
                held >= timeout * 8 / 10 && held < timeout + Duration::from_secs(1),
                "full backlog {full_backlog}: held {held:?} for a {timeout:?} timeout"
            );
        }
    }
}
