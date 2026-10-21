#![cfg(target_os = "linux")]
mod common;
use common::*;
use hyper_util::rt::TokioIo;
use ratarmount_csi::{csi::*, Driver};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Endpoint, Server};
use tower::service_fn;

#[tokio::test]
async fn regression_identity_and_node_rpc_over_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("csi.sock");
    let fake = Arc::new(FakeMounter::default());
    let driver = Driver::open(
        "test-node".into(),
        &dir.path().join("state"),
        dir.path(),
        fake,
    )
    .await
    .unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        Server::builder()
            .add_service(identity_server::IdentityServer::new(driver.clone()))
            .add_service(node_server::NodeServer::new(driver.clone()))
            .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                let _ = stopped.await;
            }),
    );
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_| {
            let socket = socket.clone();
            async move { UnixStream::connect(socket).await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    let mut identity = identity_client::IdentityClient::new(channel.clone());
    let info = identity
        .get_plugin_info(GetPluginInfoRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.name, "ratarmount.csi.hilather.github.io");
    assert_eq!(info.vendor_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        identity
            .probe(ProbeRequest {})
            .await
            .unwrap()
            .into_inner()
            .ready,
        Some(true)
    );
    assert!(identity
        .get_plugin_capabilities(GetPluginCapabilitiesRequest {})
        .await
        .unwrap()
        .into_inner()
        .capabilities
        .is_empty());
    let mut node = node_client::NodeClient::new(channel);
    assert_eq!(
        node.node_get_info(NodeGetInfoRequest {})
            .await
            .unwrap()
            .into_inner()
            .node_id,
        "test-node"
    );
    assert!(node
        .node_get_capabilities(NodeGetCapabilitiesRequest {})
        .await
        .unwrap()
        .into_inner()
        .capabilities
        .is_empty());
    assert_eq!(
        node.node_publish_volume(NodePublishVolumeRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    let req = request(dir.path().join("pod").to_str().unwrap());
    for _ in 0..2 {
        node.node_publish_volume(req.clone()).await.unwrap();
    }
    for _ in 0..2 {
        node.node_unpublish_volume(NodeUnpublishVolumeRequest {
            volume_id: req.volume_id.clone(),
            target_path: req.target_path.clone(),
        })
        .await
        .unwrap();
    }
    assert_eq!(
        node.node_stage_volume(NodeStageVolumeRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );
    drop(identity);
    drop(node);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    driver.shutdown().await.unwrap();
}

/// Regression #185: an over-long endpoint exits 1 before creating any directory:
/// neither the socket's missing parents nor a fresh `--state-dir`, including a
/// state dir that shares the socket's missing ancestor.
#[tokio::test]
async fn regression_185_too_long_endpoint_creates_no_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent");
    let socket = absent.join("n1").join("n2").join("s".repeat(120));
    for state in [dir.path().join("state"), absent.join("state")] {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_ratarmount-csi"))
            .env("NODE_ID", "n")
            .arg("--endpoint")
            .arg(format!("unix://{}", socket.display()))
            .arg("--state-dir")
            .arg(&state)
            .arg("--target-root")
            .arg(dir.path())
            .arg("--ratarmount")
            .arg("/bin/false")
            .stdout(std::process::Stdio::null())
            .output()
            .await
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("107-byte sun_path limit"), "{stderr}");
        assert!(!state.exists(), "state dir created: {}", state.display());
        assert!(
            !absent.exists(),
            "parent dirs left behind: {}",
            absent.display()
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn regression_binary_socket_cli_and_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("binary.sock");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ratarmount-csi"))
        .env("NODE_ID", "env-node")
        .arg("--endpoint")
        .arg(format!("unix://{}", socket.display()))
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--target-root")
        .arg(dir.path())
        .arg("--ratarmount")
        .arg("/bin/false")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "driver exited before creating socket"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "driver did not create socket"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let connect_path = socket.clone();
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_| {
            let path = connect_path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    let mut node = node_client::NodeClient::new(channel);
    assert_eq!(
        node.node_get_info(NodeGetInfoRequest {})
            .await
            .unwrap()
            .into_inner()
            .node_id,
        "env-node"
    );
    let mut req = request(dir.path().join("pod").to_str().unwrap());
    req.volume_context
        .insert("source".into(), "/dev/null".into());
    assert_eq!(
        node.node_publish_volume(req).await.unwrap_err().code(),
        tonic::Code::Internal
    );
    drop(node);
    // SAFETY: this is our still-owned, unreaped child, so its PID cannot be reused.
    assert_eq!(
        unsafe { libc::kill(child.id().unwrap() as libc::pid_t, libc::SIGTERM) },
        0
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(!socket.exists());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("state/journal.json")).unwrap(),
        "{}"
    );
}
