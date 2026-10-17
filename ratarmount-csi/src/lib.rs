#![cfg(target_os = "linux")]
#![allow(clippy::result_large_err)]

pub mod csi {
    // Preserve upstream protobuf comments verbatim in generated bindings.
    #![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]
    tonic::include_proto!("csi.v1");
}
pub mod options;
pub mod process;
mod service;
pub use service::Driver;

use options::MountSpec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tonic::Status;

#[tonic::async_trait]
pub trait Mounter: Send + Sync + 'static {
    async fn mounted(&self, target: &str) -> Result<bool, Status>;
    async fn healthy(&self, target: &str) -> Result<bool, Status>;
    async fn mount(&self, spec: &MountSpec, env: BTreeMap<String, String>) -> Result<(), Status>;
    async fn unmount(&self, target: &str) -> Result<(), Status>;
}

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    spec: MountSpec,
    ready: bool,
    created_target: bool,
}

struct Journal {
    dir: PathBuf,
    // Keep the lock for the complete driver lifetime, including recovery.
    _lock: File,
}

impl Journal {
    fn open(dir: &Path) -> Result<Self, Status> {
        fs::create_dir_all(dir).map_err(|_| Status::internal("cannot create state directory"))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| Status::internal("cannot protect state directory"))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join("lock"))
            .map_err(|_| Status::internal("cannot open state lock"))?;
        lock.try_lock()
            .map_err(|_| Status::failed_precondition("state directory is already locked"))?;
        Ok(Self {
            dir: dir.into(),
            _lock: lock,
        })
    }

    fn load(&self) -> Result<BTreeMap<String, Entry>, Status> {
        match fs::read(self.dir.join("journal.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| {
                Status::internal("invalid CSI journal; refusing to discard mount ownership")
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(_) => Err(Status::internal("cannot read CSI journal")),
        }
    }

    fn save(&self, entries: &BTreeMap<String, Entry>) -> Result<(), Status> {
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.dir.join("journal.tmp"))?;
            file.write_all(&serde_json::to_vec(entries)?)?;
            file.sync_all()?;
            fs::rename(self.dir.join("journal.tmp"), self.dir.join("journal.json"))?;
            File::open(&self.dir)?.sync_all()
        })();
        result.map_err(|_| Status::internal("cannot persist CSI journal"))
    }
}

pub(crate) struct State {
    journal: Journal,
    entries: BTreeMap<String, Entry>,
    target_root: PathBuf,
    closing: bool,
}

impl State {
    fn check_target(&self, target: &str) -> Result<(), Status> {
        options::validate_target(target)?;
        let path = Path::new(target);
        if path == self.target_root || !path.starts_with(&self.target_root) {
            return Err(Status::invalid_argument(
                "target is outside configured target root",
            ));
        }
        if path.starts_with(&self.journal.dir) || self.journal.dir.starts_with(path) {
            return Err(Status::invalid_argument(
                "target overlaps the state directory",
            ));
        }
        // Existing ancestors must not redirect kubelet's path into another tree.
        for parent in path.ancestors() {
            match fs::symlink_metadata(parent) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(Status::invalid_argument("target has a symlink component"))
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                // A disconnected FUSE target must still be unmountable.
                Err(e) if parent == path && e.raw_os_error() == Some(libc::ENOTCONN) => {}
                Err(_) => return Err(Status::internal("cannot inspect target path")),
            }
        }
        Ok(())
    }

    async fn remove(&mut self, target: &str, mounter: &dyn Mounter) -> Result<(), Status> {
        mounter.unmount(target).await?;
        if mounter.mounted(target).await? {
            return Err(Status::internal("target remains mounted"));
        }
        let mut next = self.entries.clone();
        if let Some(entry) = next.remove(target) {
            if entry.created_target {
                match fs::remove_dir(target) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(Status::internal("cannot remove owned target directory")),
                }
            }
        }
        self.journal.save(&next)?;
        self.entries = next;
        Ok(())
    }

    async fn publish(
        &mut self,
        spec: MountSpec,
        env: BTreeMap<String, String>,
        mounter: &dyn Mounter,
    ) -> Result<(), Status> {
        if self.closing {
            return Err(Status::unavailable("driver is shutting down"));
        }
        self.check_target(&spec.target)?;
        if self.entries.keys().any(|target| {
            target != &spec.target
                && (Path::new(target).starts_with(&spec.target)
                    || Path::new(&spec.target).starts_with(target))
        }) {
            return Err(Status::already_exists(
                "target overlaps an existing publish target",
            ));
        }
        if let Some(entry) = self.entries.get(&spec.target) {
            if entry.spec != spec {
                return Err(Status::already_exists(
                    "target already published with different parameters",
                ));
            }
            if entry.ready
                && mounter.mounted(&spec.target).await?
                && mounter.healthy(&spec.target).await?
            {
                return Ok(());
            }
            // Only an explicit republish retries a crashed child.
            self.remove(&spec.target, mounter).await?;
        } else if mounter.mounted(&spec.target).await? {
            return Err(Status::already_exists("target has an unowned mount"));
        }
        let created_target = !Path::new(&spec.target).exists();
        let entry = Entry {
            spec: spec.clone(),
            ready: false,
            created_target,
        };
        let mut next = self.entries.clone();
        next.insert(spec.target.clone(), entry);
        // Write intent before mkdir/spawn so restart handles every crash window.
        self.journal.save(&next)?;
        self.entries = next;
        fs::create_dir_all(&spec.target)
            .map_err(|_| Status::internal("cannot create target directory"))?;
        if fs::read_dir(&spec.target)
            .map_err(|_| Status::internal("cannot read target directory"))?
            .next()
            .is_some()
        {
            return Err(Status::failed_precondition(
                "target directory must be empty",
            ));
        }
        if let Err(error) = mounter.mount(&spec, env).await {
            if self.remove(&spec.target, mounter).await.is_err() {
                log::error!("failed to clean up a failed CSI publish; journal retained");
            }
            return Err(error);
        }
        if !mounter.mounted(&spec.target).await? || !mounter.healthy(&spec.target).await? {
            let _ = self.remove(&spec.target, mounter).await;
            return Err(Status::internal("child did not establish a live mount"));
        }
        let mut next = self.entries.clone();
        next.get_mut(&spec.target).unwrap().ready = true;
        self.journal.save(&next)?;
        self.entries = next;
        Ok(())
    }
}
