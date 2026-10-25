#![forbid(unused_macros)]
#![cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))]
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
#[expect(
    clippy::disallowed_types,
    reason = r###"internal-read:v1 {"id":"IR-E0029-T01","item":"ratarmount_csi","disposition":"support","category":"builder-type-support","reason":"Builder type support: Import OpenOptions for the CSI journal and lifetime lock files.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
)]
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0030-M01","item":"<ratarmount_csi::Journal>::open","disposition":"output-owner","category":"runtime-state-directory","reason":"Create the CSI state tree before protecting it and opening the lifetime lock.","creation":{"policy":"recursive-directory","basis":"Journal::open applies 0700 to the state directory immediately after creation; intermediate directory defaults remain unchanged."}}"###
        )]
        fs::create_dir_all(dir).map_err(|_| Status::internal("cannot create state directory"))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| Status::internal("cannot protect state directory"))?;
        let lock = {
#[expect(clippy::disallowed_types, reason = r###"internal-read:v1 {"id":"IR-B0285-T01","item":"<ratarmount_csi::Journal>::open","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-type-support","reason":"Builder type support: Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###)]
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0285-M01","item":"<ratarmount_csi::Journal>::open","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###)]
let mut __inventory_value_0 = OpenOptions::new();
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-E0031-M01","item":"<ratarmount_csi::Journal>::open","disposition":"output-owner","category":"runtime-lock","reason":"Allow creating the CSI lifetime lock without truncating a pre-existing lock.","creation":{"policy":"create-or-open","basis":"The journal lock is read/write, no-follow, mode 0600 and truncate(false), and is retained for the driver lifetime."}}"###)]
let __inventory_value_1 = __inventory_value_0
            .read(true)
            .write(true)
            .create(true);
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0285-M02","item":"<ratarmount_csi::Journal>::open","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###)]
let __inventory_value_2 = __inventory_value_1
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join("lock"));
__inventory_value_2
}
            .map_err(|_| Status::internal("cannot open state lock"))?;
        lock.try_lock()
            .map_err(|_| Status::failed_precondition("state directory is already locked"))?;
        Ok(Self {
            dir: dir.into(),
            _lock: lock,
        })
    }

    fn load(&self) -> Result<BTreeMap<String, Entry>, Status> {
        {
            let __inventory_condition_5296 = {
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0286-M01","item":"<ratarmount_csi::Journal>::load","disposition":"out-of-family","category":"structured-control-record","reason":"daemon state journal","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )]
                let __inventory_value_0 = fs::read(self.dir.join("journal.json"));
                __inventory_value_0
            };
            match __inventory_condition_5296 {
                Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| {
                    Status::internal("invalid CSI journal; refusing to discard mount ownership")
                }),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
                Err(_) => Err(Status::internal("cannot read CSI journal")),
            }
        }
    }

    fn save(&self, entries: &BTreeMap<String, Entry>) -> Result<(), Status> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0288-M01","item":"<ratarmount_csi::Journal>::save","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"directory handle opened only to fsync a directory entry","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let result = (|| -> std::io::Result<()> {
            let mut file = {
                #[expect(
                    clippy::disallowed_types,
                    reason = r###"internal-read:v1 {"id":"IR-B0287-T01","item":"<ratarmount_csi::Journal>::save","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-type-support","reason":"Builder type support: Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
                )]
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0287-M01","item":"<ratarmount_csi::Journal>::save","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###
                )]
                let mut __inventory_value_0 = OpenOptions::new();
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0032-M01","item":"<ratarmount_csi::Journal>::save","disposition":"output-owner","category":"structured-control-record","reason":"Configure CSI journal.tmp replacement output before serializing, syncing and renaming it.","creation":{"policy":"create-or-truncate","basis":"The temporary journal uses no-follow and mode 0600; completed output replaces journal.json only after fsync."}}"###
                )]
                let __inventory_value_1 = __inventory_value_0.write(true).create(true);
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0287-M02","item":"<ratarmount_csi::Journal>::save","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                )]
                let __inventory_value_2 = __inventory_value_1
                    .truncate(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(self.dir.join("journal.tmp"));
                __inventory_value_2
            }?;
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
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0033-M01","item":"<ratarmount_csi::State>::publish","disposition":"output-owner","category":"mountpoint-directory","reason":"Create the CSI publish target after durable mount intent is written and before checking emptiness.","creation":{"policy":"recursive-directory","basis":"The requested target tree uses current directory defaults; the empty-directory check and mounter own later publication."}}"###
        )]
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
