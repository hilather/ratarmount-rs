#![forbid(unused_macros)]
#![cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))]

#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use ratarmount_volume_plugin::{http, process::ProcessMounter, Driver};
    use std::env;
    use std::fs;
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{
        DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
    };
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

    // `sun_path` holds 107 bytes plus the NUL (#145).
    const STAGING_PREFIX: &str = ".rm";
    const STAGING_RANDOM_LEN: usize = 8;
    const SUN_PATH_MAX: usize = 107;
    /// Bytes the staged bind path adds to the parent: `/.rmXXXXXXXX/s`.
    const STAGING_OVERHEAD: usize = 1 + STAGING_PREFIX.len() + STAGING_RANDOM_LEN + 2;
    /// Longest parent directory whose staged path fits `sun_path` as is. Longer
    /// directories bind through the staging directory's `/proc/self/fd` alias.
    const MAX_DIRECT_DIR_LEN: usize = SUN_PATH_MAX - STAGING_OVERHEAD;
    const PROC_SELF_FD: &str = "/proc/self/fd";

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

    /// Creates a fresh 0700 staging directory. Anyone who can write to `parent` can
    /// pre-create names so that all 16 attempts hit EEXIST; that is a denial of
    /// service, as one colliding name was before, and never a bind elsewhere.
    fn stage_dir(parent: &Path) -> io::Result<PathBuf> {
        let mut last = None;
        for _ in 0..16 {
            let dir = parent.join(staging_name());
            {
                let __inventory_condition_3626 = {
                    #[expect(
                        clippy::disallowed_types,
                        reason = r###"internal-read:v1 {"id":"IR-E0109-T01","item":"ratarmount_volume_plugin::linux::stage_dir","disposition":"support","category":"builder-type-support","reason":"Builder type support: Construct the private socket staging-directory builder in the volume plugin binary.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
                    )]
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-E0109-M01","item":"ratarmount_volume_plugin::linux::stage_dir","disposition":"support","category":"creation-builder","reason":"Construct the private socket staging-directory builder in the volume plugin binary.","creation":{"policy":"none","basis":"Builder setup is separate from the following mode-0700 staging create operation."}}"###
                    )]
                    let mut __inventory_value_0 = fs::DirBuilder::new();
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-E0110-M01","item":"ratarmount_volume_plugin::linux::stage_dir","disposition":"output-owner","category":"socket-staging-directory","reason":"Create a fresh private socket staging directory with bounded collision retry.","creation":{"policy":"exclusive-directory","basis":"The generated name uses DirBuilder mode 0700; EEXIST retries and no replacing fallback is introduced."}}"###
                    )]
                    let __inventory_value_1 = __inventory_value_0.mode(0o700).create(&dir);
                    __inventory_value_1
                };
                match __inventory_condition_3626 {
                    Ok(()) => return Ok(dir),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        last = Some(error)
                    }
                    Err(error) => return Err(error),
                }
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

    fn socket_path_fits(path: &Path) -> io::Result<()> {
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
        Ok(())
    }

    /// Binds `s` inside the staging directory. When `dir/s` is too long for `sun_path`,
    /// bind through `<proc_self_fd>/<fd>/s`, the alias of an fd open on the staging
    /// directory (Linux has no bindat(2)). The alias must resolve to that directory.
    fn bind_staged(dir: &Path, path: &Path, proc_self_fd: &Path) -> io::Result<UnixListener> {
        let staged = dir.join("s");
        if staged.as_os_str().as_encoded_bytes().len() <= SUN_PATH_MAX {
            return UnixListener::bind(&staged);
        }
        let handle = {
            #[expect(
                clippy::disallowed_types,
                reason = r###"internal-read:v1 {"id":"IR-B0550-T01","item":"ratarmount_volume_plugin::linux::bind_staged","disposition":"support","category":"builder-type-support","reason":"Builder type support: O_DIRECTORY | O_NOFOLLOW handle on the socket staging directory, used only to bind through /proc/self/fd; reads no file content","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
            )]
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0550-M01","item":"ratarmount_volume_plugin::linux::bind_staged","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"out-of-family","baseline_reason":"O_DIRECTORY | O_NOFOLLOW handle on the socket staging directory, used only to bind through /proc/self/fd; reads no file content"}"###
            )]
            let mut __inventory_value_0 = fs::OpenOptions::new();
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0550-M02","item":"ratarmount_volume_plugin::linux::bind_staged","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"O_DIRECTORY | O_NOFOLLOW handle on the socket staging directory, used only to bind through /proc/self/fd; reads no file content","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )]
            let __inventory_value_1 = __inventory_value_0
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(dir);
            __inventory_value_1
        }?;
        let opened = handle.metadata()?;
        let alias = proc_self_fd.join(handle.as_raw_fd().to_string());
        match fs::metadata(&alias) {
            Ok(meta) if meta.dev() == opened.dev() && meta.ino() == opened.ino() => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "socket path {}: its directory is {} bytes; without {} the directory \
                         may be at most {MAX_DIRECT_DIR_LEN} bytes, because the socket is \
                         bound in a staging directory first ({SUN_PATH_MAX}-byte sun_path limit)",
                        path.display(),
                        dir.parent()
                            .map_or(0, |parent| parent.as_os_str().as_encoded_bytes().len()),
                        proc_self_fd.display()
                    ),
                ));
            }
        }
        UnixListener::bind(alias.join("s"))
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0111-M01","item":"ratarmount_volume_plugin::linux::rename_noreplace","disposition":"out-of-family","category":"socket-publication","reason":"Publish the already-bound volume-plugin socket with a no-replace rename syscall.","creation":{"policy":"none","basis":"renameat2 moves the existing staged socket with RENAME_NOREPLACE; it opens no pathname or descriptor."}}"###
        )]
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
        bind_private_with(path, Path::new(PROC_SELF_FD))
    }

    fn bind_private_with(path: &Path, proc_self_fd: &Path) -> io::Result<UnixListener> {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        socket_path_fits(path)?;
        let staging = StagingDir {
            path: stage_dir(parent)?,
        };
        let listener = bind_staged(&staging.path, path, proc_self_fd)?;
        let staged = staging.path.join("s");
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
        rename_noreplace(&staged, path)?;
        Ok(listener)
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
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        fn staging_names(parent: &Path) -> Vec<String> {
            let mut names = Vec::new();
            for entry in fs::read_dir(parent).unwrap() {
                let name = entry.unwrap().file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                let random = name.strip_prefix(STAGING_PREFIX).unwrap_or("");
                if random.len() == STAGING_RANDOM_LEN
                    && random
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                {
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

        /// Regression #145: without /proc a directory over {MAX_DIRECT_DIR_LEN} bytes cannot be
        /// staged; the error names the real limit and no staging dir is left behind.
        #[test]
        fn regression_145_without_proc_long_dir_refused_with_limit() {
            let base = tempfile::tempdir_in("/tmp").unwrap();
            let no_proc = base.path().join("no-proc/self/fd");
            let base_len = base.path().as_os_str().as_encoded_bytes().len();
            let leaf_len = (MAX_DIRECT_DIR_LEN + 1)
                .checked_sub(base_len + 1)
                .expect("/tmp temp dir too long");
            let parent = base.path().join("d".repeat(leaf_len));
            fs::create_dir(&parent).unwrap();
            let sock = parent.join("plugin.sock");
            assert!(sock.as_os_str().as_encoded_bytes().len() <= 107);
            let error = bind_private_with(&sock, &no_proc).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            let message = error.to_string();
            assert!(
                message.contains(&format!("at most {MAX_DIRECT_DIR_LEN} bytes")),
                "{message}"
            );
            assert!(message.contains("107-byte sun_path limit"), "{message}");
            assert!(message.contains("no-proc/self/fd"), "{message}");
            assert!(staging_names(&parent).is_empty());

            // A directory short enough to bind directly never needs /proc.
            let short = base.path().join("plugin.sock");
            let listener = bind_private_with(&short, &no_proc).unwrap();
            UnixStream::connect(&short).unwrap();
            assert!(staging_names(base.path()).is_empty());
            drop(listener);
        }

        /// Regression: an interior NUL is rejected before bind, matching validate_socket_path.
        #[test]
        fn regression_owner_only_socket_sun_path_rejects_interior_nul() {
            use std::os::unix::ffi::OsStrExt;
            let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/a\0b"));
            let error = socket_path_fits(path).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("NUL"));
        }

        /// Regression #145: the staging name adds a fixed 14 bytes, so a directory of exactly
        /// MAX_DIRECT_DIR_LEN bytes binds the staged path at 107 bytes; one more byte binds
        /// through the /proc/self/fd alias instead of being refused.
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
                .join("p".repeat(MAX_DIRECT_DIR_LEN - base_len - 1));
            fs::create_dir(&parent).unwrap();
            assert_eq!(
                parent.as_os_str().as_encoded_bytes().len(),
                MAX_DIRECT_DIR_LEN
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

            let longer = base.path().join("p".repeat(MAX_DIRECT_DIR_LEN - base_len));
            fs::create_dir(&longer).unwrap();
            let longer_sock = longer.join("plugin.sock");
            let listener = bind_private(&longer_sock).unwrap();
            let bound = listener.local_addr().unwrap();
            let bound = bound.as_pathname().unwrap();
            assert!(bound.starts_with(PROC_SELF_FD), "{}", bound.display());
            UnixStream::connect(&longer_sock).unwrap();
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

        /// Regression #145: a directory over 93 bytes with an exactly-107-byte socket path
        /// was refused because the staged bind path added 14 bytes; it must bind and publish.
        #[test]
        fn regression_145_long_dir_exact_107_socket_binds() {
            let base = tempfile::tempdir_in("/tmp").unwrap();
            let base_len = base.path().as_os_str().as_encoded_bytes().len();
            let name = "plugin.sock";
            let leaf_len = (107 - name.len() - 1)
                .checked_sub(base_len + 1)
                .expect("/tmp temp dir too long");
            let parent = base.path().join("p".repeat(leaf_len));
            fs::create_dir(&parent).unwrap();
            let parent_len = parent.as_os_str().as_encoded_bytes().len();
            assert!(parent_len > 93, "directory is {parent_len} bytes");
            let sock = parent.join(name);
            assert_eq!(sock.as_os_str().as_encoded_bytes().len(), 107);
            let listener =
                listener(&sock).unwrap_or_else(|e| panic!("bind {}: {e}", sock.display()));
            let bound = listener
                .local_addr()
                .unwrap()
                .as_pathname()
                .unwrap()
                .to_path_buf();
            // The kernel bound the short /proc alias, not the 120-byte staging path.
            assert!(bound.starts_with(PROC_SELF_FD), "{}", bound.display());
            assert!(
                bound.as_os_str().as_encoded_bytes().len() <= 107,
                "{}",
                bound.display()
            );
            assert_eq!(bound.file_name(), Some(std::ffi::OsStr::new("s")));
            let meta = fs::symlink_metadata(&sock).unwrap();
            assert!(meta.file_type().is_socket());
            assert_eq!(meta.mode() & 0o777, 0o600);
            UnixStream::connect(&sock).unwrap();
            assert!(staging_names(&parent).is_empty());
            drop(listener);
        }

        /// Regression #145: a ~90-byte socket path (under sun_path) was refused with the
        /// SUN_LEN error because the staging path added ~30 bytes.
        #[test]
        fn regression_145_ninety_byte_socket_path_binds() {
            let base = tempfile::tempdir().unwrap();
            let base_len = base.path().as_os_str().as_encoded_bytes().len();
            let name = "plugin.sock";
            let leaf_len = (90 - name.len() - 1)
                .checked_sub(base_len + 1)
                .filter(|&len| len >= 1)
                .unwrap_or_else(|| panic!("temp dir {} too long", base.path().display()));
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
