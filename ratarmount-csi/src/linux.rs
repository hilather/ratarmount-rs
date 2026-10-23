use clap::Parser;
use ratarmount_csi::{
    csi::{identity_server::IdentityServer, node_server::NodeServer},
    process::ProcessMounter,
    Driver,
};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

// Copied in ratarmount-volume-plugin: the binaries share no crate. Bind inside a
// 0700 sibling directory, chmod 0600, then rename. umask(2) is process-global and
// would race these tokio threads.
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
fn bind_staged(dir: &Path, path: &Path, proc_self_fd: &Path) -> io::Result<StdUnixListener> {
    let staged = dir.join("s");
    if staged.as_os_str().as_encoded_bytes().len() <= SUN_PATH_MAX {
        return StdUnixListener::bind(&staged);
    }
    let handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
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
    StdUnixListener::bind(alias.join("s"))
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

fn bind_private(path: &Path) -> io::Result<StdUnixListener> {
    bind_private_with(path, Path::new(PROC_SELF_FD))
}

fn bind_private_with(path: &Path, proc_self_fd: &Path) -> io::Result<StdUnixListener> {
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

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, default_value = "unix:///csi/csi.sock")]
    endpoint: String,
    #[arg(long, env = "NODE_ID")]
    node_id: String,
    #[arg(long, default_value = "/var/lib/ratarmount-csi")]
    state_dir: PathBuf,
    #[arg(long, default_value = "/var/lib/kubelet/pods")]
    target_root: PathBuf,
    #[arg(long, default_value = "/dev/shm/ratarmount-csi")]
    overlay_root: PathBuf,
    #[arg(long, default_value = "/usr/local/bin/ratarmount")]
    ratarmount: PathBuf,
    #[arg(long, default_value_t = 120)]
    mount_timeout_seconds: u64,
}

#[tokio::main]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let socket = args
        .endpoint
        .strip_prefix("unix://")
        .filter(|s| s.starts_with('/'))
        .ok_or("endpoint must be unix:///absolute/path")?;
    ratarmount_csi::options::validate_target(socket)?;
    let path = std::path::Path::new(socket);
    // Refuse an unbindable endpoint before Driver::open creates --state-dir (#185).
    socket_path_fits(path)?;
    let mounter = Arc::new(ProcessMounter::new(
        args.ratarmount,
        args.overlay_root,
        Duration::from_secs(args.mount_timeout_seconds),
    ));
    let driver = Driver::open(args.node_id, &args.state_dir, &args.target_root, mounter).await?;
    std::fs::create_dir_all(path.parent().ok_or("socket has no parent")?)?;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err("refusing to replace non-socket endpoint".into());
        }
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return Err("endpoint already has a listener".into());
        }
        std::fs::remove_file(path)?;
    }
    // The std listener is bound in the staging directory; the fd stays valid across rename.
    let std_listener = bind_private(path)?;
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = tonic::transport::Server::builder()
        .add_service(IdentityServer::new(driver.clone()))
        .add_service(NodeServer::new(driver.clone()))
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async move {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        })
        .await;
    let cleanup = driver.shutdown().await;
    let _ = std::fs::remove_file(path);
    result?;
    cleanup?;
    Ok(())
}

#[cfg(test)]
mod owner_only_socket_tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;

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

        let sock = parent.join("csi.sock");
        let listener = bind_private(&sock).unwrap();
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
        let _stale_listener = std::os::unix::net::UnixListener::bind(&stale_sock).unwrap();
        let sock = parent.join("csi.sock");
        let listener = bind_private(&sock).unwrap();
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
        let target = parent.join("csi.sock");
        fs::create_dir(&target).unwrap();
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
        let sock = parent.join("csi.sock");
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
            let sock = parent.join(format!("csi.sock-{i}"));
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
        let sock = parent.join("csi.sock");
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
        let short = base.path().join("csi.sock");
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
        let sock = parent.join("csi.sock");
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
        let longer_sock = longer.join("csi.sock");
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

    /// Regression #145: a directory over 93 bytes with an exactly-107-byte socket path
    /// was refused because the staged bind path added 14 bytes; it must bind and publish.
    #[test]
    fn regression_145_long_dir_exact_107_socket_binds() {
        let base = tempfile::tempdir_in("/tmp").unwrap();
        let base_len = base.path().as_os_str().as_encoded_bytes().len();
        let name = "csi.sock";
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
            bind_private(&sock).unwrap_or_else(|e| panic!("bind {}: {e}", sock.display()));
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
        let name = "csi.sock";
        let leaf_len = (90 - name.len() - 1)
            .checked_sub(base_len + 1)
            .filter(|&len| len >= 1)
            .unwrap_or_else(|| panic!("temp dir {} too long", base.path().display()));
        let parent = base.path().join("q".repeat(leaf_len));
        fs::create_dir(&parent).unwrap();
        let sock = parent.join(name);
        assert_eq!(sock.as_os_str().as_encoded_bytes().len(), 90);
        let listener =
            bind_private(&sock).unwrap_or_else(|e| panic!("bind {}: {e}", sock.display()));
        let meta = fs::symlink_metadata(&sock).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.mode() & 0o777, 0o600);
        UnixStream::connect(&sock).unwrap();
        assert!(staging_names(&parent).is_empty());
        drop(listener);
    }
}
