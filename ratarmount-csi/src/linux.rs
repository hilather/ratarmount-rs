use clap::Parser;
use ratarmount_core::owner_socket::{bind_private, socket_path_fits};
use ratarmount_csi::{
    csi::{identity_server::IdentityServer, node_server::NodeServer},
    process::ProcessMounter,
    Driver,
};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

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

/// Creates the endpoint's missing parents, removes a stale socket left by an
/// earlier run, and binds an owner-only listener at `path`.
async fn bind_endpoint(path: &Path) -> Result<StdUnixListener, Box<dyn std::error::Error>> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0037-M01","item":"ratarmount_csi::linux::bind_endpoint","disposition":"output-owner","category":"socket-parent-directory","reason":"Create the CSI listening socket parent before staged socket binding.","creation":{"policy":"recursive-directory","basis":"The parent uses existing std directory defaults; fresh staging mode and no-replace publication are separately reviewed."}}"###
    )]
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
    Ok(bind_private(path)?)
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
    // The std listener is bound in the staging directory; the fd stays valid across rename.
    let std_listener = bind_endpoint(path).await?;
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
    use ratarmount_core::owner_socket::{staging_names, PROC_SELF_FD};
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;

    fn bind(path: &Path) -> Result<StdUnixListener, Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(bind_endpoint(path))
    }

    /// Regression: the endpoint is an owner-only socket at the final path, a stale
    /// socket from an earlier run is replaced, and a live one or a non-socket is refused.
    #[test]
    fn regression_owner_only_socket_endpoint_stale_and_live() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("csi.sock");
        drop(StdUnixListener::bind(&sock).unwrap());
        let listener = bind(&sock).unwrap();
        assert_eq!(fs::symlink_metadata(&sock).unwrap().mode() & 0o777, 0o600);
        UnixStream::connect(&sock).unwrap();
        let error = bind(&sock).unwrap_err();
        assert!(
            error.to_string().contains("already has a listener"),
            "{error}"
        );
        drop(listener);
        assert!(staging_names(dir.path()).is_empty());

        let file = dir.path().join("file.sock");
        fs::write(&file, b"").unwrap();
        let error = bind(&file).unwrap_err();
        assert!(error.to_string().contains("non-socket"), "{error}");
    }

    /// Regression #182 (#145 at daemon level): an exactly-107-byte endpoint whose
    /// directory is over 93 bytes and does not exist yet gets its parents created
    /// and binds through the `/proc/self/fd` alias of the staging directory.
    #[test]
    fn regression_182_missing_parents_long_dir_exact_107_binds_via_proc_alias() {
        let base = tempfile::tempdir_in("/tmp").unwrap();
        let base_len = base.path().as_os_str().as_encoded_bytes().len();
        let name = "csi.sock";
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
        let listener = bind(&sock).unwrap_or_else(|e| panic!("bind {}: {e}", sock.display()));
        assert!(fs::symlink_metadata(&parent).unwrap().is_dir());
        let bound = listener
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
