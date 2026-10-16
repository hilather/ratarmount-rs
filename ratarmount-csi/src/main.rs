use clap::Parser;
use ratarmount_csi::{
    csi::{identity_server::IdentityServer, node_server::NodeServer},
    process::ProcessMounter,
    Driver,
};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::PathBuf;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    if !cfg!(target_os = "linux") {
        return Err("CSI node plugin requires Linux".into());
    }
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
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
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
