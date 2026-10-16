#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use ratarmount_volume_plugin::{http, process::ProcessMounter, Driver};
    use std::env;
    use std::fs;
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
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

    fn listener(path: &Path) -> io::Result<UnixListener> {
        if env::var("LISTEN_PID").ok().as_deref() == Some(&std::process::id().to_string()) {
            if env::var("LISTEN_FDS").ok().as_deref() != Some("1") {
                return Err(io::Error::other("expected exactly one systemd socket"));
            }
            // SAFETY: systemd passes ownership of fd 3 to this process.
            let listener = unsafe { UnixListener::from_raw_fd(3) };
            if listener.local_addr()?.as_pathname() != Some(path) {
                return Err(io::Error::other("systemd socket differs from --socket"));
            }
            // systemd clears CLOEXEC when passing descriptors to the service.
            // Children must not keep the activation socket alive after shutdown.
            if unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(listener);
        }
        if let Some(parent) = path.parent() {
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
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    pub fn run() -> Result<(), String> {
        let args = Args::parse();
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
