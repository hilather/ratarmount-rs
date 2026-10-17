use crate::{csi::*, options, Journal, Mounter, State};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct Driver {
    node_id: String,
    state: Arc<Mutex<State>>,
    mounter: Arc<dyn Mounter>,
}

impl Driver {
    pub async fn open(
        node_id: String,
        state_dir: &Path,
        target_root: &Path,
        mounter: Arc<dyn Mounter>,
    ) -> Result<Self, Status> {
        if node_id.is_empty() {
            return Err(Status::invalid_argument("NODE_ID must not be empty"));
        }
        options::validate_target(
            target_root
                .to_str()
                .ok_or_else(|| Status::invalid_argument("target root must be UTF-8"))?,
        )?;
        let journal = Journal::open(state_dir)?;
        let entries = journal.load()?;
        let mut state = State {
            journal,
            entries,
            target_root: target_root.into(),
            closing: false,
        };
        for target in state.entries.keys().cloned().collect::<Vec<_>>() {
            state.check_target(&target)?;
            if state.entries[&target].spec.target != target {
                return Err(Status::internal("inconsistent CSI journal"));
            }
            state.remove(&target, mounter.as_ref()).await?;
        }
        Ok(Self {
            node_id,
            state: Arc::new(Mutex::new(state)),
            mounter,
        })
    }

    pub async fn shutdown(&self) -> Result<(), Status> {
        let mut state = self.state.lock().await;
        state.closing = true;
        let mut failure = None;
        for target in state.entries.keys().cloned().collect::<Vec<_>>() {
            if let Err(error) = state.remove(&target, self.mounter.as_ref()).await {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[tonic::async_trait]
impl identity_server::Identity for Driver {
    async fn get_plugin_info(
        &self,
        _: Request<GetPluginInfoRequest>,
    ) -> Result<Response<GetPluginInfoResponse>, Status> {
        Ok(Response::new(GetPluginInfoResponse {
            name: "ratarmount.csi.hilather.github.io".into(),
            vendor_version: env!("CARGO_PKG_VERSION").into(),
            manifest: Default::default(),
        }))
    }
    async fn get_plugin_capabilities(
        &self,
        _: Request<GetPluginCapabilitiesRequest>,
    ) -> Result<Response<GetPluginCapabilitiesResponse>, Status> {
        Ok(Response::new(GetPluginCapabilitiesResponse::default()))
    }
    async fn probe(&self, _: Request<ProbeRequest>) -> Result<Response<ProbeResponse>, Status> {
        Ok(Response::new(ProbeResponse { ready: Some(true) }))
    }
}

#[tonic::async_trait]
impl node_server::Node for Driver {
    async fn node_get_info(
        &self,
        _: Request<NodeGetInfoRequest>,
    ) -> Result<Response<NodeGetInfoResponse>, Status> {
        Ok(Response::new(NodeGetInfoResponse {
            node_id: self.node_id.clone(),
            ..Default::default()
        }))
    }
    async fn node_get_capabilities(
        &self,
        _: Request<NodeGetCapabilitiesRequest>,
    ) -> Result<Response<NodeGetCapabilitiesResponse>, Status> {
        Ok(Response::new(NodeGetCapabilitiesResponse::default()))
    }
    async fn node_publish_volume(
        &self,
        request: Request<NodePublishVolumeRequest>,
    ) -> Result<Response<NodePublishVolumeResponse>, Status> {
        let request = request.into_inner();
        let spec = options::parse(&request)?;
        let env = options::secret_env(&request.secrets)?;
        let driver = self.clone();
        // Finish the journaled operation even if kubelet cancels its RPC.
        tokio::spawn(async move {
            driver
                .state
                .lock()
                .await
                .publish(spec, env, driver.mounter.as_ref())
                .await
        })
        .await
        .map_err(|_| Status::internal("publish worker failed"))??;
        Ok(Response::new(NodePublishVolumeResponse {}))
    }
    async fn node_unpublish_volume(
        &self,
        request: Request<NodeUnpublishVolumeRequest>,
    ) -> Result<Response<NodeUnpublishVolumeResponse>, Status> {
        let request = request.into_inner();
        if request.volume_id.is_empty() {
            return Err(Status::invalid_argument("volume_id is required"));
        }
        options::validate_target(&request.target_path)?;
        let driver = self.clone();
        tokio::spawn(async move {
            let mut state = driver.state.lock().await;
            state.check_target(&request.target_path)?;
            match state.entries.get(&request.target_path) {
                Some(entry) if entry.spec.volume_id != request.volume_id => {
                    return Err(Status::failed_precondition(
                        "target belongs to another volume",
                    ))
                }
                None if driver.mounter.mounted(&request.target_path).await? => {
                    return Err(Status::failed_precondition(
                        "refusing to unmount an unowned target",
                    ))
                }
                None => return Ok(()),
                _ => {}
            }
            state
                .remove(&request.target_path, driver.mounter.as_ref())
                .await
        })
        .await
        .map_err(|_| Status::internal("unpublish worker failed"))??;
        Ok(Response::new(NodeUnpublishVolumeResponse {}))
    }
    async fn node_stage_volume(
        &self,
        _: Request<NodeStageVolumeRequest>,
    ) -> Result<Response<NodeStageVolumeResponse>, Status> {
        Err(Status::unimplemented("staging is not supported"))
    }
    async fn node_unstage_volume(
        &self,
        _: Request<NodeUnstageVolumeRequest>,
    ) -> Result<Response<NodeUnstageVolumeResponse>, Status> {
        Err(Status::unimplemented("staging is not supported"))
    }
    async fn node_get_volume_stats(
        &self,
        _: Request<NodeGetVolumeStatsRequest>,
    ) -> Result<Response<NodeGetVolumeStatsResponse>, Status> {
        Err(Status::unimplemented("volume stats are not supported"))
    }
    async fn node_expand_volume(
        &self,
        _: Request<NodeExpandVolumeRequest>,
    ) -> Result<Response<NodeExpandVolumeResponse>, Status> {
        Err(Status::unimplemented("expansion is not supported"))
    }
}
