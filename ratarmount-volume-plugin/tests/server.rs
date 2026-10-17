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

/// Regression: standalone and systemd sockets must serve HTTP without leaking tokens or listener fds to the child.
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
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(descriptor, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command
        } else {
            Command::new(env!("CARGO_BIN_EXE_ratarmount-volume-plugin"))
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
