#![allow(dead_code)]
use ratarmount_csi::{csi::*, options::MountSpec, Mounter};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tonic::Status;

#[derive(Default)]
pub struct FakeMounter {
    pub mounts: Mutex<BTreeSet<String>>,
    pub env: Mutex<BTreeMap<String, String>>,
    pub publishes: AtomicUsize,
    pub unpublishes: AtomicUsize,
    pub dead: AtomicBool,
    pub fail_mount: AtomicBool,
    pub fail_unmount: AtomicBool,
    pub pause_mount: AtomicBool,
    pub entered: tokio::sync::Notify,
    pub resume: tokio::sync::Notify,
}

#[tonic::async_trait]
impl Mounter for FakeMounter {
    async fn mounted(&self, target: &str) -> Result<bool, Status> {
        Ok(self.mounts.lock().unwrap().contains(target))
    }
    async fn healthy(&self, _: &str) -> Result<bool, Status> {
        Ok(!self.dead.load(Ordering::SeqCst))
    }
    async fn mount(&self, spec: &MountSpec, env: BTreeMap<String, String>) -> Result<(), Status> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        if self.pause_mount.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        *self.env.lock().unwrap() = env;
        self.mounts.lock().unwrap().insert(spec.target.clone());
        if self.fail_mount.load(Ordering::SeqCst) {
            return Err(Status::internal("injected mount failure"));
        }
        Ok(())
    }
    async fn unmount(&self, target: &str) -> Result<(), Status> {
        self.unpublishes.fetch_add(1, Ordering::SeqCst);
        if self.fail_unmount.load(Ordering::SeqCst) {
            return Err(Status::internal("injected unmount failure"));
        }
        self.mounts.lock().unwrap().remove(target);
        Ok(())
    }
}

pub fn request(target: &str) -> NodePublishVolumeRequest {
    NodePublishVolumeRequest {
        volume_id: "fixture".into(),
        target_path: target.into(),
        readonly: true,
        volume_context: [("source".into(), "/fixtures/data.tar".into())].into(),
        volume_capability: Some(VolumeCapability {
            access_type: Some(volume_capability::AccessType::Mount(
                volume_capability::MountVolume::default(),
            )),
            access_mode: Some(volume_capability::AccessMode {
                mode: volume_capability::access_mode::Mode::MultiNodeReaderOnly as i32,
            }),
        }),
        ..Default::default()
    }
}

pub fn write_fake_mounter(dir: &Path, body: &str) -> PathBuf {
    let script = dir.join("fake-mounter");
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    script
}

#[allow(clippy::result_large_err)] // same Status as Mounter::mount
pub async fn mount_retrying_spawn(
    mounter: &impl Mounter,
    spec: &MountSpec,
    env: BTreeMap<String, String>,
) -> Result<(), Status> {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let result = mounter.mount(spec, env.clone()).await;
        let retry = matches!(
            &result,
            Err(err)
                if err.code() == tonic::Code::Internal
                    && err.message() == "cannot spawn ratarmount"
                    && Instant::now() < deadline
        );
        if !retry {
            return result;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}
