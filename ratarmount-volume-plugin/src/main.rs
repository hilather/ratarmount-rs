#![forbid(unused_macros)]
#![cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))]

#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use ratarmount_core::owner_socket::{bind_private, socket_path_fits};
    use ratarmount_volume_plugin::{http, process::ProcessMounter, Driver};
    use std::env;
    use std::fs;
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn stop(_: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }

    #[derive(Parser)]
    #[command(
        version,
        about = "Docker / Podman volume driver for the ratarmount CLI"
    )]
    struct Args {
        #[arg(long, default_value = "/run/docker/plugins/ratarmount.sock")]
        socket: PathBuf,
        #[arg(long, default_value = "/var/lib/ratarmount-volume-plugin")]
        state_dir: PathBuf,
        #[arg(long, default_value = "/usr/bin/ratarmount")]
        ratarmount: PathBuf,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
        mount_timeout: u64,
    }

    fn socket_activated() -> bool {
        env::var("LISTEN_PID").ok().as_deref() == Some(&std::process::id().to_string())
    }

    fn listener(path: &Path) -> io::Result<UnixListener> {
        if socket_activated() {
            if env::var("LISTEN_FDS").ok().as_deref() != Some("1") {
                return Err(io::Error::other("expected exactly one systemd socket"));
            }
            // SAFETY: systemd passes ownership of fd 3 to this process.
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0551-M01","item":"ratarmount_volume_plugin::linux::listener","disposition":"out-of-family","category":"runtime-resource-or-descriptor-handoff","reason":"systemd socket activation descriptor","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )]
            let listener = unsafe { UnixListener::from_raw_fd(3) };
            if listener.local_addr()?.as_pathname() != Some(path) {
                return Err(io::Error::other("systemd socket differs from --socket"));
            }
            // systemd clears CLOEXEC when passing descriptors to the service.
            // Children must not keep the activation socket alive after shutdown.
            if unsafe {
                {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-E0112-M01","item":"ratarmount_volume_plugin::linux::listener","disposition":"out-of-family","category":"descriptor-control","reason":"Restore close-on-exec on the inherited systemd activation listener.","creation":{"policy":"none","basis":"F_SETFD changes the existing fd 3 flags after validating its socket address; children cannot retain the listener."}}"###
                    )]
                    let __inventory_value_0 =
                        libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                    __inventory_value_0
                }
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            return Ok(listener);
        }
        socket_path_fits(path)?;
        if let Some(parent) = path.parent() {
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0113-M01","item":"ratarmount_volume_plugin::linux::listener","disposition":"output-owner","category":"socket-parent-directory","reason":"Create the configured volume-plugin socket parent before staged binding.","creation":{"policy":"recursive-directory","basis":"The parent keeps current directory defaults; staging creation and final publication are separately reviewed."}}"###
            )]
            fs::create_dir_all(parent)?;
        }
        match path.symlink_metadata() {
            Ok(meta) if meta.file_type().is_socket() => {
                match std::os::unix::net::UnixStream::connect(path) {
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "socket already in use",
                        ))
                    }
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                        fs::remove_file(path)?
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(_) => return Err(io::Error::other("refusing to replace a non-socket path")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        bind_private(path)
    }

    // Keep connection I/O blocking independently of the listener's poll mode.
    fn configure_accepted_stream(stream: &UnixStream) -> io::Result<()> {
        stream.set_nonblocking(false)
    }

    pub fn run() -> Result<(), String> {
        let args = Args::parse();
        // Refuse an unbindable socket before Driver::open creates --state-dir (#185).
        if !socket_activated() {
            socket_path_fits(&args.socket)
                .map_err(|e| format!("cannot open plugin socket: {e}"))?;
        }
        let driver = Arc::new(Mutex::new(Driver::open(
            &args.state_dir,
            ProcessMounter::new(args.ratarmount, Duration::from_secs(args.mount_timeout)),
        )?));
        let listener =
            listener(&args.socket).map_err(|e| format!("cannot open plugin socket: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "cannot configure socket")?;
        // SAFETY: the handlers only set an atomic flag; no IO or allocation.
        unsafe {
            libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        }
        let active = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        let mut last_poll = std::time::Instant::now();
        let mut error = None;
        while !STOP.load(Ordering::Relaxed) {
            workers.retain(|worker: &thread::JoinHandle<()>| !worker.is_finished());
            if last_poll.elapsed() >= Duration::from_millis(250) {
                if let Ok(mut driver) = driver.try_lock() {
                    driver.supervise();
                }
                last_poll = std::time::Instant::now();
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Err(e) = configure_accepted_stream(&stream) {
                        error = Some(format!("cannot configure plugin connection: {e}"));
                        break;
                    }
                    if active.load(Ordering::Relaxed) >= 32 {
                        drop(stream);
                        continue;
                    }
                    active.fetch_add(1, Ordering::Relaxed);
                    let active = Arc::clone(&active);
                    let driver = Arc::clone(&driver);
                    workers.push(thread::spawn(move || {
                        let _ = http::serve_stream(stream, |endpoint, body| match driver.lock() {
                            Ok(mut driver) => driver.handle(endpoint, body),
                            Err(_) => serde_json::json!({"Err": "driver lock poisoned"}),
                        });
                        active.fetch_sub(1, Ordering::Relaxed);
                    }));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    error = Some("plugin socket accept failed".to_string());
                    break;
                }
            }
        }
        for worker in workers {
            let _ = worker.join();
        }
        drop(driver); // Drop ProcessMounter only after all handlers finish.
        error.map_or(Ok(()), Err)
    }

    pub fn main() {
        if let Err(error) = run() {
            let _ = writeln!(io::stderr(), "ratarmount-volume-plugin: {error}");
            std::process::exit(1);
        }
    }
    #[cfg(test)]
    mod accepted_socket_tests {
        use super::*;
        use std::os::fd::AsRawFd;

        /// Regression: inherited O_NONBLOCK must not abort a delayed request or reply.
        #[test]
        fn regression_accepted_socket_clears_inherited_nonblocking() {
            let dir = tempfile::tempdir().unwrap();
            let listener = UnixListener::bind(dir.path().join("socket")).unwrap();
            listener.set_nonblocking(true).unwrap();
            let _client = std::os::unix::net::UnixStream::connect(
                listener.local_addr().unwrap().as_pathname().unwrap(),
            )
            .unwrap();
            let (stream, _) = listener.accept().unwrap();
            // Linux does not inherit this flag; simulate the BSD accept result.
            stream.set_nonblocking(true).unwrap();
            configure_accepted_stream(&stream).unwrap();
            // SAFETY: F_GETFL only reads flags from the live stream's descriptor.
            let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
            assert_ne!(flags, -1);
            assert_eq!(flags & libc::O_NONBLOCK, 0);
        }
    }

    #[cfg(test)]
    mod owner_only_socket_tests {
        use super::*;
        use ratarmount_core::owner_socket::{staging_names, PROC_SELF_FD};
        use std::os::unix::fs::MetadataExt;

        /// Regression: the plugin socket is owner-only at the final path, a stale
        /// socket from an earlier run is replaced, and a live one or a non-socket is refused.
        #[test]
        fn regression_owner_only_socket_listener_stale_and_live() {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("plugin.sock");
            drop(UnixListener::bind(&sock).unwrap());
            let first = listener(&sock).unwrap();
            assert_eq!(fs::symlink_metadata(&sock).unwrap().mode() & 0o777, 0o600);
            UnixStream::connect(&sock).unwrap();
            let error = listener(&sock).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            drop(first);
            assert!(staging_names(dir.path()).is_empty());

            let file = dir.path().join("file.sock");
            fs::write(&file, b"").unwrap();
            let error = listener(&file).unwrap_err();
            assert!(error.to_string().contains("non-socket"), "{error}");
        }

        /// Regression #185: an over-long socket path under missing parents is refused
        /// before any parent directory is created.
        #[test]
        fn regression_185_too_long_path_creates_no_parent_dirs() {
            let dir = tempfile::tempdir().unwrap();
            let absent = dir.path().join("absent");
            let sock = absent.join("n1").join("n2").join("s".repeat(120));
            let error = listener(&sock).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("107-byte sun_path limit"));
            assert!(
                !absent.exists(),
                "parent dirs left behind: {}",
                absent.display()
            );
        }

        /// Regression #182 (#145 at daemon level): an exactly-107-byte socket path
        /// whose directory is over 93 bytes and does not exist yet gets its parents
        /// created and binds through the `/proc/self/fd` alias of the staging directory.
        #[test]
        fn regression_182_missing_parents_long_dir_exact_107_binds_via_proc_alias() {
            let base = tempfile::tempdir_in("/tmp").unwrap();
            let base_len = base.path().as_os_str().as_encoded_bytes().len();
            let name = "plugin.sock";
            let absent = base.path().join("absent");
            let leaf_len = (107 - name.len() - 1)
                .checked_sub(base_len + "/absent/n1/".len())
                .expect("/tmp temp dir too long");
            let parent = absent.join("n1").join("p".repeat(leaf_len));
            let parent_len = parent.as_os_str().as_encoded_bytes().len();
            assert!(parent_len > 93, "directory is {parent_len} bytes");
            let sock = parent.join(name);
            assert_eq!(sock.as_os_str().as_encoded_bytes().len(), 107);
            assert!(!absent.exists());
            let bound_listener =
                listener(&sock).unwrap_or_else(|e| panic!("bind {}: {e}", sock.display()));
            assert!(fs::symlink_metadata(&parent).unwrap().is_dir());
            let bound = bound_listener
                .local_addr()
                .unwrap()
                .as_pathname()
                .unwrap()
                .to_path_buf();
            assert!(bound.starts_with(PROC_SELF_FD), "{}", bound.display());
            assert_eq!(fs::symlink_metadata(&sock).unwrap().mode() & 0o777, 0o600);
            UnixStream::connect(&sock).unwrap();
            assert!(staging_names(&parent).is_empty());
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ratarmount-volume-plugin requires Linux /proc/self/mountinfo");
        std::process::exit(1);
    }
}
