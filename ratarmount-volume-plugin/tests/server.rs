#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn request(socket: &Path, endpoint: &str, body: Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let body = body.to_string();
    write!(
        stream,
        "POST {endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut bytes = String::new();
    stream.read_to_string(&mut bytes).unwrap();
    serde_json::from_str(bytes.split_once("\r\n\r\n").unwrap().1).unwrap()
}

/// Set `FD_CLOEXEC` on every inherited fd above stderr.
///
/// Async-signal-safe for `pre_exec`: a stack `rlimit`, `getrlimit`, and `fcntl`
/// only. No allocation, `/proc` walk, or `sysconf`. `EBADF` is ignored. Fds 0-2
/// stay as they are.
fn scrub_inherited_fds() -> std::io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes a stack `rlimit` and is async-signal-safe.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let end = limit.rlim_cur.min(65_536);
    let mut fd: libc::c_int = 3;
    while (fd as libc::rlim_t) < end {
        // SAFETY: `F_GETFD` / `F_SETFD` only read or replace the descriptor flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        // A closed fd must not be passed to `F_SETFD`; errno stays the `F_GETFD` error.
        let rc = if flags < 0 {
            flags
        } else {
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) }
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EBADF) {
                return Err(err);
            }
        }
        fd += 1;
    }
    Ok(())
}

/// Regression: standalone and systemd sockets must serve HTTP without leaking tokens or listener fds to the child.
///
/// Both arms scrub before exec, setting `FD_CLOEXEC` on fds `3..min(RLIMIT_NOFILE, 65536)`
/// with a stack-only `fcntl` loop (`EBADF` ignored, fds 0-2 untouched). That drops an
/// inheritable non-listener left on fd 3. The systemd arm scrubs at the start of the same
/// `pre_exec` that then `dup2`s the listener onto fd 3 and clears cloexec; a later hook would
/// mark that listener cloexec again. The `socket:` check still fails if an inheritable
/// listener is left on fd 3.
#[test]
fn regression_server_socket_activation_and_environment_only_credentials() {
    for activated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("plugin.sock");
        let state = dir.path().join("state");
        let fake = dir.path().join("ratarmount");
        let token = dir.path().join("token");
        let argv = dir.path().join("argv");
        let fd = dir.path().join("fd");
        fs::write(&fake, format!("#!/bin/sh\nprintf '%s' \"$HF_TOKEN\" > '{}'\ncat /proc/$$/cmdline > '{}'\nreadlink /proc/$$/fd/3 > '{}'\nexit 1\n", token.display(), argv.display(), fd.display())).unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        let inherited = activated.then(|| UnixListener::bind(&socket).unwrap());
        let mut command = if let Some(listener) = &inherited {
            let descriptor = listener.as_raw_fd();
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "LISTEN_PID=$$; export LISTEN_PID; exec \"$@\"", "sh"])
                .arg(env!("CARGO_BIN_EXE_ratarmount-volume-plugin"))
                .env("LISTEN_FDS", "1");
            // SAFETY: only async-signal-safe descriptor operations after fork.
            // Scrub in this hook, before dup2: a later pre_exec would set FD_CLOEXEC
            // on the listener that this hook just placed on fd 3.
            unsafe {
                command.pre_exec(move || {
                    scrub_inherited_fds()?;
                    if libc::dup2(descriptor, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command
        } else {
            let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount-volume-plugin"));
            // SAFETY: only async-signal-safe descriptor operations after fork.
            unsafe {
                command.pre_exec(scrub_inherited_fds);
            }
            command
        };
        let mut child = Guard(
            command
                .arg("--socket")
                .arg(&socket)
                .arg("--state-dir")
                .arg(&state)
                .arg("--ratarmount")
                .arg(&fake)
                .env("HF_TOKEN", "test-env-only-sentinel")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "plugin exited before serving"
            );
            if UnixStream::connect(&socket).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "socket did not appear");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(request(&socket, "/Plugin.Activate", json!({}))["Err"], "");
        assert_eq!(
            request(
                &socket,
                "/VolumeDriver.Create",
                json!({"Name":"data", "Opts":{"source":"hf://org/repo/file.tar"}})
            )["Err"],
            ""
        );
        assert_ne!(
            request(
                &socket,
                "/VolumeDriver.Mount",
                json!({"Name":"data", "ID":"container"})
            )["Err"],
            ""
        );
        assert_eq!(fs::read_to_string(token).unwrap(), "test-env-only-sentinel");
        assert!(
            !String::from_utf8_lossy(&fs::read(argv).unwrap()).contains("test-env-only-sentinel")
        );
        assert!(!fs::read_to_string(state.join("volumes.json"))
            .unwrap()
            .contains("test-env-only-sentinel"));
        assert!(!fs::read_to_string(fd).unwrap().contains("socket:"));
        assert_eq!(
            request(&socket, "/VolumeDriver.Get", json!({"Name":"data"}))["Volume"]["Status"]
                ["Mounted"],
            false
        );
        // SAFETY: signal only the plugin process owned by this test.
        assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) }, 0);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "plugin failed to stop");
            thread::sleep(Duration::from_millis(20));
        }
    }
}
