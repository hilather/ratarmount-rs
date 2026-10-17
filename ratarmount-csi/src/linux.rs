use clap::Parser;
use ratarmount_csi::{
    csi::{identity_server::IdentityServer, node_server::NodeServer},
    process::ProcessMounter,
    Driver,
};
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
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

fn stage_dir(parent: &Path) -> io::Result<PathBuf> {
    let pid = std::process::id();
    let n = SOCKET_STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let dir = parent.join(format!(".rmsock-{pid}-{nanos}-{n}"));
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
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

fn sun_path_fits(path: &Path) -> io::Result<()> {
    // `sockaddr_un.sun_path` is 108 bytes, including the trailing NUL.
    // An interior NUL would truncate the path the kernel binds.
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() > 107 || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must contain no NUL and be shorter than SUN_LEN",
        ));
    }
    Ok(())
}

fn bind_private(path: &Path) -> io::Result<StdUnixListener> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let staging = StagingDir {
        path: stage_dir(parent)?,
    };
    let staged = staging.path.join("s");
    sun_path_fits(&staged)?;
    let listener = StdUnixListener::bind(&staged)?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
    fs::rename(&staged, path)?;
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
    let mounter = Arc::new(ProcessMounter::new(
        args.ratarmount,
        args.overlay_root,
        Duration::from_secs(args.mount_timeout_seconds),
    ));
    let driver = Driver::open(args.node_id, &args.state_dir, &args.target_root, mounter).await?;
    let path = std::path::Path::new(socket);
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
            if name.starts_with(".rmsock-") {
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

    /// Regression: a leftover `.rmsock-*` directory and its socket must not block the next bind.
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

    /// Regression: rename onto a directory fails and leaves no staging directory.
    #[test]
    fn regression_owner_only_socket_rename_failure_removes_staging() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path();
        let target = parent.join("csi.sock");
        fs::create_dir(&target).unwrap();
        let error = bind_private(&target).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::IsADirectory);
        assert!(fs::symlink_metadata(&target).unwrap().is_dir());
        assert!(staging_names(parent).is_empty());
    }

    /// Regression: a staged path longer than sun_path is rejected and the staging dir is removed.
    #[test]
    fn regression_owner_only_socket_sun_path_removes_staging() {
        let dir = tempfile::tempdir().unwrap();
        let mut parent = dir.path().to_path_buf();
        while parent.as_os_str().as_encoded_bytes().len() <= 100 {
            parent.push("dddddddddddddddddddddddddddddddd");
        }
        fs::create_dir_all(&parent).unwrap();
        let error = bind_private(&parent.join("csi.sock")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "path must contain no NUL and be shorter than SUN_LEN"
        );
        assert!(staging_names(&parent).is_empty());
    }

    /// Regression: an interior NUL is rejected before bind, matching validate_socket_path.
    #[test]
    fn regression_owner_only_socket_sun_path_rejects_interior_nul() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/a\0b"));
        let error = sun_path_fits(path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("NUL"));
    }

    /// Regression: a staged path of exactly 107 bytes (sun_path minus the NUL) binds.
    #[test]
    fn regression_owner_only_socket_sun_path_exact_107_binds() {
        // `/tmp` stays short enough that the staging suffix can land on 107 bytes.
        // Other tests share SOCKET_STAGING_SEQ, so the sequence width can change
        // between the probe and the bind; retry when the measured length misses.
        let base = tempfile::tempdir_in("/tmp").unwrap();
        let mut detail = String::from("no attempt");
        for _ in 0..8 {
            let probe = stage_dir(base.path()).unwrap();
            let name = probe.file_name().unwrap().to_str().unwrap();
            let seq: u64 = name.rsplit('-').next().unwrap().parse().unwrap();
            let next_name_len = name.len() + (seq + 1).to_string().len() - seq.to_string().len();
            let parent_len = 107usize
                .checked_sub(1 + next_name_len + 2)
                .expect("staging name longer than sun_path");
            fs::remove_dir(&probe).unwrap();
            let base_len = base.path().as_os_str().as_encoded_bytes().len();
            let leaf_len = parent_len - base_len - 1;
            assert!(
                (1..200).contains(&leaf_len),
                "cannot place a {parent_len}-byte parent under {} ({base_len} bytes)",
                base.path().display()
            );
            let parent = base.path().join("p".repeat(leaf_len));
            let _ = fs::remove_dir_all(&parent);
            fs::create_dir(&parent).unwrap();
            assert_eq!(parent.as_os_str().as_encoded_bytes().len(), parent_len);
            let sock = parent.join("csi.sock");
            match bind_private(&sock) {
                Ok(listener) => {
                    let bound = listener
                        .local_addr()
                        .unwrap()
                        .as_pathname()
                        .unwrap()
                        .to_path_buf();
                    let len = bound.as_os_str().as_encoded_bytes().len();
                    if len == 107 {
                        assert_eq!(bound.file_name(), Some(std::ffi::OsStr::new("s")));
                        UnixStream::connect(&sock).unwrap();
                        assert!(staging_names(&parent).is_empty());
                        return;
                    }
                    detail = format!("bound {len} bytes at {}", bound.display());
                }
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                    detail = error.to_string();
                }
                Err(error) => panic!("bind failed: {error}"),
            }
        }
        panic!("staged path never landed on exactly 107 bytes ({detail})");
    }
}
