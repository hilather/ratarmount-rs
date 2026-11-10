//! Detached runtime ownership. Local client termination alone never permits tree deletion.
use super::io::{self as owned, invalid};
use rustix::fd::OwnedFd;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

// N6: one day per phase, well above 120/300/600-second examples. Validate before
// deadline construction; elapsed comparisons also avoid Instant addition entirely.
pub(super) const MAX_TIMEOUT_SECONDS: u64 = 86_400;
pub(super) fn timeout(seconds: u64) -> io::Result<Duration> {
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&seconds) {
        return Err(invalid(
            "timeout_seconds must be in 1..=86400 for execution",
        ));
    }
    Ok(Duration::from_secs(seconds))
}
static INTERRUPTED: AtomicI32 = AtomicI32::new(0);
extern "C" fn on_signal(signal: libc::c_int) {
    INTERRUPTED.store(signal, Ordering::Relaxed);
}
pub(super) struct Signals(Vec<(i32, libc::sigaction)>);
impl Signals {
    pub fn install() -> io::Result<Self> {
        INTERRUPTED.store(0, Ordering::Relaxed);
        let mut guard = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous = unsafe { std::mem::zeroed() };
            action.sa_sigaction = on_signal as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(io::Error::last_os_error());
            }
            guard.0.push((signal, previous));
        }
        Ok(guard)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, previous) in &self.0 {
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}
pub(super) trait Effects {
    type Client;
    fn now(&self) -> Duration;
    fn pause(&mut self);
    fn interrupted(&self) -> bool;
    fn spawn(&mut self, args: &[String], stdout: File, stderr: File) -> io::Result<Self::Client>;
    fn poll(&mut self, child: &mut Self::Client) -> io::Result<Option<i32>>;
    fn reap(&mut self, child: Self::Client) -> io::Result<()>;
}
pub(super) struct Local<'a> {
    executable: &'a Path,
    epoch: Instant,
}
impl<'a> Local<'a> {
    pub fn new(executable: &'a Path) -> Self {
        Self {
            executable,
            epoch: Instant::now(),
        }
    }
}
impl Effects for Local<'_> {
    type Client = Child;
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
    fn pause(&mut self) {
        std::thread::sleep(Duration::from_millis(10));
    }
    fn interrupted(&self) -> bool {
        INTERRUPTED.load(Ordering::Relaxed) != 0
    }
    fn spawn(&mut self, args: &[String], stdout: File, stderr: File) -> io::Result<Child> {
        Command::new(self.executable)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
    }
    fn poll(&mut self, child: &mut Child) -> io::Result<Option<i32>> {
        use std::os::unix::process::ExitStatusExt;
        Ok(child
            .try_wait()?
            .map(|s| s.code().unwrap_or(128 + s.signal().unwrap_or(0))))
    }
    fn reap(&mut self, mut child: Child) -> io::Result<()> {
        let started = self.now();
        while child.try_wait()?.is_none() {
            if self.now().saturating_sub(started) >= Duration::from_secs(2) {
                child.kill()?;
                child.wait()?;
                return Ok(());
            }
            self.pause();
        }
        Ok(())
    }
}
#[derive(Serialize)]
pub(super) struct Phase {
    phase: String,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    stdout_log: String,
    stderr_log: String,
    stdout: Option<String>,
    stderr: Option<String>,
}
impl Phase {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && self.error.is_none()
    }
}
pub(super) struct Runtime<'a, E: Effects> {
    effects: E,
    logs: &'a OwnedFd,
    name: String,
    serial: usize,
    pending: Vec<E::Client>,
}
impl<'a, E: Effects> Runtime<'a, E> {
    pub fn new(effects: E, logs: &'a OwnedFd, name: String) -> Self {
        Self {
            effects,
            logs,
            name,
            serial: 0,
            pending: Vec::new(),
        }
    }
    pub fn invoke(
        &mut self,
        phase: &str,
        args: &[String],
        seconds: u64,
        interruptible: bool,
    ) -> io::Result<Phase> {
        let limit = timeout(seconds)?;
        self.serial += 1;
        let stdout_log = format!("{}-{}-{phase}.stdout.log", self.name, self.serial);
        let stderr_log = format!("{}-{}-{phase}.stderr.log", self.name, self.serial);
        let stdout = owned::create_output(self.logs, &stdout_log)?;
        let stderr = owned::create_output(self.logs, &stderr_log)?;
        let mut result = Phase {
            phase: phase.into(),
            exit_code: None,
            error: None,
            stdout_log,
            stderr_log,
            stdout: None,
            stderr: None,
        };
        let mut child = self.effects.spawn(args, stdout, stderr)?;
        let started = self.effects.now();
        loop {
            if interruptible && self.effects.interrupted() {
                result.error = Some("interrupted".into());
                break;
            }
            match self.effects.poll(&mut child) {
                Ok(Some(code)) => {
                    result.exit_code = Some(code);
                    break;
                }
                Err(error) => {
                    result.error = Some(error.to_string());
                    break;
                }
                Ok(None) => {}
            }
            if self.effects.now().saturating_sub(started) >= limit {
                result.error = Some("timeout".into());
                break;
            }
            self.effects.pause();
        }
        if result.exit_code.is_none() {
            self.pending.push(child);
        } else {
            result.stdout = Some(
                String::from_utf8_lossy(&owned::open_run_log(self.logs, &result.stdout_log)?)
                    .into_owned(),
            );
            result.stderr = Some(
                String::from_utf8_lossy(&owned::open_run_log(self.logs, &result.stderr_log)?)
                    .into_owned(),
            );
        }
        Ok(result)
    }
    fn control(&mut self, verb: &str) -> io::Result<()> {
        let mut args = vec![verb.into()];
        if verb == "rm" {
            args.push("-f".into());
        }
        args.push(self.name.clone());
        let phase = self.invoke(verb, &args, 5, false)?;
        let message = phase.stderr.as_deref().unwrap_or("").to_ascii_lowercase();
        if phase.success()
            || (phase.exit_code.is_some()
                && (message.contains("no such container")
                    || message.contains("no container with name")
                    || (verb == "kill" && message.contains("is not running"))))
        {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "runtime {verb} failed: {} {message}",
            phase.error.as_deref().unwrap_or("nonzero exit")
        )))
    }
    pub fn stop(&mut self) -> io::Result<()> {
        let had_client = !self.pending.is_empty();
        let mut failure = None;
        for verb in ["kill", "rm"] {
            if let Err(error) = self.control(verb) {
                failure.get_or_insert(error);
            }
        }
        for child in std::mem::take(&mut self.pending) {
            if let Err(error) = self.effects.reap(child) {
                failure.get_or_insert(error);
            }
        }
        if had_client {
            // A late run client could create the container after the first removal.
            for verb in ["kill", "rm"] {
                if let Err(error) = self.control(verb) {
                    failure.get_or_insert(error);
                }
            }
        }
        for child in std::mem::take(&mut self.pending) {
            if let Err(error) = self.effects.reap(child) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
// Pre-setup inspection uses a bounded nonblocking stdout pipe, never an unbounded
// Command::output or a new pathname. Only an already-local exact digest is accepted.
pub(super) fn inspect(
    executable: &Path,
    image: &str,
    os: &str,
    architecture: &str,
) -> io::Result<()> {
    let mut child = Command::new(executable)
        .args(["image", "inspect", "--format", "{{json .}}", image])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| invalid("missing inspect stdout"))?;
        rustix::fs::fcntl_setfl(&stdout, rustix::fs::OFlags::NONBLOCK)?;
        let started = Instant::now();
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0; 4096];
            match stdout.read(&mut buffer) {
                Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            if bytes.len() > 64 * 1024 {
                return Err(invalid("image inspect output exceeds 64 KiB"));
            }
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err(invalid("local image inspection failed; no pull permitted"));
                }
                // The child may have exited after the read. Drain its remaining bytes.
                stdout
                    .take((64 * 1024 + 1 - bytes.len()) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 64 * 1024 {
                    return Err(invalid("oversized image identity"));
                }
                break;
            }
            if INTERRUPTED.load(Ordering::Relaxed) != 0 || started.elapsed() >= timeout(30)? {
                return Err(io::Error::other(
                    "image inspection interrupted or timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        #[derive(Deserialize)]
        struct Identity {
            #[serde(rename = "RepoDigests")]
            digests: Vec<String>,
            #[serde(rename = "Os")]
            os: String,
            #[serde(rename = "Architecture")]
            architecture: String,
        }
        let identity: Identity =
            serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
        if !identity.digests.iter().any(|d| d == image)
            || identity.os != os
            || identity.architecture != architecture
        {
            return Err(invalid("local image identity mismatch"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    child.wait()?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Fake {
        time: Duration,
        interrupt: bool,
        fail_stop: bool,
        hang: bool,
        events: Vec<String>,
    }
    impl Effects for Fake {
        type Client = String;
        fn now(&self) -> Duration {
            self.time
        }
        fn pause(&mut self) {
            self.time += Duration::from_secs(1);
        }
        fn interrupted(&self) -> bool {
            self.interrupt && self.time >= Duration::from_secs(1)
        }
        fn spawn(&mut self, args: &[String], stdout: File, stderr: File) -> io::Result<String> {
            drop((stdout, stderr));
            self.events.push(args[0].clone());
            Ok(args[0].clone())
        }
        fn poll(&mut self, child: &mut String) -> io::Result<Option<i32>> {
            Ok(if child == "run" && self.hang {
                None
            } else if self.fail_stop && matches!(child.as_str(), "kill" | "rm") {
                Some(9)
            } else if child == "exec" {
                Some(7)
            } else {
                Some(0)
            })
        }
        fn reap(&mut self, child: String) -> io::Result<()> {
            self.events.push(format!("reap {child}"));
            Ok(())
        }
    }
    fn exercise(fake: Fake, run: impl FnOnce(&mut Runtime<'_, Fake>)) {
        let dir = tempfile::tempdir().unwrap();
        let logs = owned::open_directory(dir.path()).unwrap();
        let mut runtime = Runtime::new(fake, &logs, "unit".into());
        run(&mut runtime);
    }
    // Regression: phase failures lost their exit code or hid the timeout upper bound (N6).
    #[test]
    fn regression_bench_runtime_phase_exits_recorded() {
        for seconds in [0, MAX_TIMEOUT_SECONDS + 1, u64::MAX] {
            assert!(timeout(seconds).is_err());
        }
        assert_eq!(
            timeout(MAX_TIMEOUT_SECONDS).unwrap(),
            Duration::from_secs(86_400)
        );
        exercise(Fake::default(), |r| {
            let before = r.effects.events.len();
            assert!(r.invoke("build", &["exec".into()], u64::MAX, true).is_err());
            assert_eq!(before, r.effects.events.len());
            for phase in ["configure", "build", "test"] {
                let result = r.invoke(phase, &["exec".into()], 600, true).unwrap();
                assert_eq!(result.exit_code, Some(7));
                assert!(!result.success());
            }
        });
    }
    // Regression: interruption deleted a tree before stopping the detached runtime.
    #[test]
    fn regression_bench_interrupt_stops_runtime_before_tree_cleanup() {
        exercise(
            Fake {
                interrupt: true,
                hang: true,
                ..Fake::default()
            },
            |r| {
                let phase = r.invoke("run", &["run".into()], 60, true).unwrap();
                assert_eq!(phase.error.as_deref(), Some("interrupted"));
                r.stop().unwrap();
                r.effects.events.push("cleanup tree".into());
                assert_eq!(
                    r.effects.events,
                    [
                        "run",
                        "kill",
                        "rm",
                        "reap run",
                        "kill",
                        "rm",
                        "cleanup tree"
                    ]
                );
            },
        );
    }
    // Regression: a runtime stop failure incorrectly authorized destructive tree cleanup.
    #[test]
    fn regression_bench_runtime_stop_failure_preserves_tree() {
        exercise(
            Fake {
                fail_stop: true,
                ..Fake::default()
            },
            |r| {
                assert!(r.stop().is_err());
                assert_eq!(r.effects.events, ["kill", "rm"]);
            },
        );
    }
    // Regression: startup completed after removal and left a live detached runtime.
    #[test]
    fn regression_bench_late_run_client_removed_after_reap() {
        exercise(
            Fake {
                hang: true,
                ..Fake::default()
            },
            |r| {
                assert_eq!(
                    r.invoke("run", &["run".into()], 1, true)
                        .unwrap()
                        .error
                        .as_deref(),
                    Some("timeout")
                );
                r.stop().unwrap();
                assert_eq!(
                    r.effects.events,
                    ["run", "kill", "rm", "reap run", "kill", "rm"]
                );
            },
        );
    }
}
