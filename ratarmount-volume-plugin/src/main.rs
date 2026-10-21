#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use ratarmount_volume_plugin::{http, process::ProcessMounter, Driver};
    use std::env;
    use std::fs;
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    // Copied in ratarmount-csi: the binaries share no crate. Bind inside a 0700
    // sibling directory, chmod 0600, then rename. umask(2) is process-global and
    // would race tokio threads that already exist when the CSI driver binds.
    static SOCKET_STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

    // The staging name stays short so the staged bind path is only a few bytes
    // longer than the target: `sun_path` holds 107 bytes plus the NUL (#145).
    const STAGING_PREFIX: &str = ".rm";
    const STAGING_RANDOM_LEN: usize = 8;
    const SUN_PATH_MAX: usize = 107;
    /// Bytes the staged bind path adds to the parent: `/.rmXXXXXXXX/s`.
    const STAGING_OVERHEAD: usize = 1 + STAGING_PREFIX.len() + STAGING_RANDOM_LEN + 2;
    /// Longest parent directory whose staged bind path still fits `sun_path`.
    const MAX_SOCKET_DIR_LEN: usize = SUN_PATH_MAX - STAGING_OVERHEAD;

    fn staging_name() -> String {
        use std::hash::{BuildHasher, Hasher};
        const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        // RandomState is seeded per process; the inputs keep names distinct within it.
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        hasher.write_u64(SOCKET_STAGING_SEQ.fetch_add(1, Ordering::Relaxed));
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0),
        );
        let mut bits = hasher.finish();
        let mut name = String::from(STAGING_PREFIX);
        for _ in 0..STAGING_RANDOM_LEN {
            name.push(ALPHABET[(bits % 36) as usize] as char);
            bits /= 36;
        }
        name
    }

    fn stage_dir(parent: &Path) -> io::Result<PathBuf> {
        let mut last = None;
        for _ in 0..16 {
            let dir = parent.join(staging_name());
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(dir),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)))
    }

    /// Removes the staging directory, and the staged socket if rename did not run.
    struct StagingDir {
        path: PathBuf,
    }

    impl Drop for StagingDir {
        fn drop(&mut self) {
            let Ok(meta) = fs::symlink_metadata(&self.path) else {
                return;
            };
            // SAFETY: geteuid only reads this process's credential.
            let euid = unsafe { libc::geteuid() };
            if !meta.file_type().is_dir() || meta.uid() != euid {
                return;
            }
            let _ = fs::remove_file(self.path.join("s"));
            let _ = fs::remove_dir(&self.path);
        }
    }

    fn socket_path_fits(path: &Path, parent: &Path) -> io::Result<()> {
        // `sockaddr_un.sun_path` is 108 bytes, including the trailing NUL.
        // An interior NUL would truncate the path the kernel binds.
        let bytes = path.as_os_str().as_encoded_bytes();
        if bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path must contain no NUL",
            ));
        }
        if bytes.len() > SUN_PATH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "socket path {} is {} bytes, over the {SUN_PATH_MAX}-byte sun_path limit",
                    path.display(),
                    bytes.len()
                ),
            ));
        }
        let parent_len = parent.as_os_str().as_encoded_bytes().len();
        if parent_len > MAX_SOCKET_DIR_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "socket path {}: its directory is {parent_len} bytes, but the socket is \
                     bound in a staging directory first, so the directory may be at most \
                     {MAX_SOCKET_DIR_LEN} bytes ({SUN_PATH_MAX}-byte sun_path limit)",
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    /// Publish `staged` at `path` without replacing anything already there. rename(2)
    /// would silently replace a live socket (#117); RENAME_NOREPLACE restores the
    /// EADDRINUSE a plain bind(path) gave. Other errors (EINVAL on a filesystem without
    /// RENAME_NOREPLACE, ENOSYS under a seccomp profile) pass through: no replacing fallback.
    fn rename_noreplace(staged: &Path, path: &Path) -> io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let from = CString::new(staged.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        let to = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // musl's libc crate bindings may lack renameat2 (musl 1.2.3); call the syscall directly.
        // SAFETY: both pointers are valid NUL-terminated strings for the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("socket already in use: {}", path.display()),
            ));
        }
        Err(error)
    }

    fn bind_private(path: &Path) -> io::Result<UnixListener> {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        socket_path_fits(path, parent)?;
        let staging = StagingDir {
            path: stage_dir(parent)?,
        };
        let staged = staging.path.join("s");
        let listener = UnixListener::bind(&staged)?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
        rename_noreplace(&staged, path)?;
        Ok(listener)
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
        bind_private(path)
    }

    // Keep connection I/O blocking independently of the listener's poll mode.
    fn configure_accepted_stream(stream: &UnixStream) -> io::Result<()> {
        stream.set_nonblocking(false)
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
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        fn staging_names(parent: &Path) -> Vec<String> {
            let mut names = Vec::new();
            for entry in fs::read_dir(parent).unwrap() {
                let name = entry.unwrap().file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if name.starts_with(STAGING_PREFIX) {
                    names.push(name.to_string());
                }
            }
            names.sort();
            names
        }

        /// Regression: owner-only socket is mode 0600, staging dir is gone, client uses the final path.
        #[test]
        fn regression_owner_only_socket_final_path() {
            let dir = tempfile::tempdir().unwrap();
            let parent = dir.path();
            let created = stage_dir(parent).unwrap();
            assert_eq!(
                fs::symlink_metadata(&created).unwrap().mode() & 0o777,
                0o700
            );
            fs::remove_dir(&created).unwrap();

            let sock = parent.join("plugin.sock");
            let listener = listener(&sock).unwrap();
            assert_eq!(fs::symlink_metadata(&sock).unwrap().mode() & 0o777, 0o600);
            let bound = listener
                .local_addr()
                .unwrap()
                .as_pathname()
                .unwrap()
                .to_path_buf();
            // local_addr keeps the staging path; the renamed socket is the final path.
            assert_eq!(bound.file_name(), Some(std::ffi::OsStr::new("s")));
            assert_eq!(bound.parent().unwrap().parent(), Some(parent));
            assert_ne!(bound, sock);
            assert!(!bound.exists());
            UnixStream::connect(&sock).unwrap();
            assert!(staging_names(parent).is_empty());
        }

        /// Regression: a leftover `.rm*` staging directory and its socket must not block the next bind.
        #[test]
        fn regression_owner_only_socket_stale_staging_dir() {
            let dir = tempfile::tempdir().unwrap();
            let parent = dir.path();
            let first = stage_dir(parent).unwrap();
            let stale_sock = first.join("s");
            let _stale_listener = UnixListener::bind(&stale_sock).unwrap();
            let sock = parent.join("plugin.sock");
            let listener = listener(&sock).unwrap();
            assert!(fs::symlink_metadata(&first).unwrap().is_dir());
            assert!(fs::symlink_metadata(&stale_sock)
                .unwrap()
                .file_type()
                .is_socket());
            UnixStream::connect(&sock).unwrap();
            assert_eq!(
                staging_names(parent),
                vec![first.file_name().unwrap().to_str().unwrap().to_string()]
            );
            drop(listener);
        }

        /// Regression: publishing onto a directory fails (as AddrInUse) and leaves no staging directory.
        #[test]
        fn regression_owner_only_socket_rename_failure_removes_staging() {
            let dir = tempfile::tempdir().unwrap();
            let parent = dir.path();
            let target = parent.join("plugin.sock");
            fs::create_dir(&target).unwrap();
            // listener() rejects a non-socket before staging; bind_private performs the rename.
            let error = bind_private(&target).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            assert!(fs::symlink_metadata(&target).unwrap().is_dir());
            assert!(staging_names(parent).is_empty());
        }

        /// Regression #117: a second bind onto a live socket must not replace it (rename(2) did).
        #[test]
        fn regression_owner_only_socket_second_bind_is_addr_in_use() {
            let dir = tempfile::tempdir().unwrap();
            let parent = dir.path();
            let sock = parent.join("plugin.sock");
            let first = bind_private(&sock).unwrap();
            let ino = fs::symlink_metadata(&sock).unwrap().ino();
            let error = bind_private(&sock).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            assert_eq!(fs::symlink_metadata(&sock).unwrap().ino(), ino);
            // The first daemon is still the one reachable at the final path.
            let client = UnixStream::connect(&sock).unwrap();
            drop(client);
            drop(first);
            assert!(staging_names(parent).is_empty());
        }

        /// Regression #117: two concurrent starts on one path yield exactly one winner.
        #[test]
        fn regression_owner_only_socket_concurrent_bind_one_winner() {
            let dir = tempfile::tempdir().unwrap();
            let parent = dir.path();
            for i in 0..50 {
                let sock = parent.join(format!("plugin.sock-{i}"));
                let barrier = std::sync::Barrier::new(2);
                let results: Vec<_> = std::thread::scope(|scope| {
                    let handles: Vec<_> = (0..2)
                        .map(|_| {
                            scope.spawn(|| {
                                barrier.wait();
                                bind_private(&sock)
                            })
                        })
                        .collect();
                    handles.into_iter().map(|h| h.join().unwrap()).collect()
                });
                let oks = results.iter().filter(|r| r.is_ok()).count();
                assert_eq!(oks, 1, "iteration {i}: expected exactly one winner");
                for error in results.iter().filter_map(|r| r.as_ref().err()) {
                    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
                }
                UnixStream::connect(&sock).unwrap();
                assert!(staging_names(parent).is_empty());
            }
        }

        /// Regression: a directory too long to stage in is rejected with the real limit and leaves no staging dir.
        #[test]
        fn regression_owner_only_socket_sun_path_removes_staging() {
            let dir = tempfile::tempdir().unwrap();
            let base_len = dir.path().as_os_str().as_encoded_bytes().len();
            // One byte over the staging limit; the target itself still fits sun_path.
            let parent = dir
                .path()
                .join("d".repeat(MAX_SOCKET_DIR_LEN + 1 - base_len - 1));
            fs::create_dir(&parent).unwrap();
            assert!(
                parent
                    .join("plugin.sock")
                    .as_os_str()
                    .as_encoded_bytes()
                    .len()
                    <= 107
            );
            let error = bind_private(&parent.join("plugin.sock")).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            let message = error.to_string();
            assert!(
                message.contains(&format!("at most {MAX_SOCKET_DIR_LEN} bytes")),
                "{message}"
            );
            assert!(message.contains("107-byte sun_path limit"), "{message}");
            assert!(staging_names(&parent).is_empty());
        }

        /// Regression: an interior NUL is rejected before bind, matching validate_socket_path.
        #[test]
        fn regression_owner_only_socket_sun_path_rejects_interior_nul() {
            use std::os::unix::ffi::OsStrExt;
            let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/a\0b"));
            let error = socket_path_fits(path, Path::new("/tmp")).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("NUL"));
        }

        /// Regression #145: the staging name adds a fixed 14 bytes, so a directory of
        /// exactly MAX_SOCKET_DIR_LEN bytes stages at 107 bytes and binds; one more is refused.
        #[test]
        fn regression_owner_only_socket_sun_path_exact_107_binds() {
            assert_eq!(STAGING_OVERHEAD, 14);
            assert_eq!(
                staging_name().len(),
                STAGING_PREFIX.len() + STAGING_RANDOM_LEN
            );
            let base = tempfile::tempdir_in("/tmp").unwrap();
            let base_len = base.path().as_os_str().as_encoded_bytes().len();
            let parent = base
                .path()
                .join("p".repeat(MAX_SOCKET_DIR_LEN - base_len - 1));
            fs::create_dir(&parent).unwrap();
            assert_eq!(
                parent.as_os_str().as_encoded_bytes().len(),
                MAX_SOCKET_DIR_LEN
            );
            let sock = parent.join("plugin.sock");
            let listener = bind_private(&sock).unwrap();
            let bound = listener
                .local_addr()
                .unwrap()
                .as_pathname()
                .unwrap()
                .to_path_buf();
            assert_eq!(bound.as_os_str().as_encoded_bytes().len(), 107);
            assert_eq!(bound.file_name(), Some(std::ffi::OsStr::new("s")));
            UnixStream::connect(&sock).unwrap();
            assert!(staging_names(&parent).is_empty());

            let longer = base.path().join("p".repeat(MAX_SOCKET_DIR_LEN - base_len));
            fs::create_dir(&longer).unwrap();
            let error = bind_private(&longer.join("plugin.sock")).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(staging_names(&longer).is_empty());
        }

        /// Regression #145: a target path over 107 bytes is refused even when its
        /// directory is short enough to stage in (clients could never connect to it).
        #[test]
        fn regression_145_target_over_sun_path_refused() {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("s".repeat(120));
            let error = bind_private(&sock).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("107-byte sun_path limit"));
            assert!(staging_names(dir.path()).is_empty());
        }

        /// Regression #145: a ~90-byte socket path (under sun_path) was refused with the
        /// SUN_LEN error because the staging path added ~30 bytes.
        #[test]
        fn regression_145_ninety_byte_socket_path_binds() {
            let base = tempfile::tempdir().unwrap();
            let base_len = base.path().as_os_str().as_encoded_bytes().len();
            let name = "plugin.sock";
            let leaf_len = 90 - base_len - 2 - name.len();
            assert!(leaf_len >= 1, "temp dir {} too long", base.path().display());
            let parent = base.path().join("q".repeat(leaf_len));
            fs::create_dir(&parent).unwrap();
            let sock = parent.join(name);
            assert_eq!(sock.as_os_str().as_encoded_bytes().len(), 90);
            let listener =
                listener(&sock).unwrap_or_else(|e| panic!("bind {}: {e}", sock.display()));
            let meta = fs::symlink_metadata(&sock).unwrap();
            assert!(meta.file_type().is_socket());
            assert_eq!(meta.mode() & 0o777, 0o600);
            UnixStream::connect(&sock).unwrap();
            assert!(staging_names(&parent).is_empty());
            drop(listener);
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
