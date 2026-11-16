//! Live overlay inspection when the writer owns SQLite's exclusive lock.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use ratarmount_compositing::{overlay_changes as core, FolderMountSource};
use ratarmount_core::{ArchiveRead, FileInfo, ListResult, MountSource, UserData};

use super::DiffArgs;

struct LiveView {
    lower: Arc<dyn MountSource>,
    host: FolderMountSource,
    root: std::path::PathBuf,
    deleted: BTreeSet<String>,
}

impl LiveView {
    fn removed(&self, path: &str) -> bool {
        let mut path = path.trim_start_matches('/');
        loop {
            if self.deleted.contains(path) {
                return true;
            }
            match path.rsplit_once('/') {
                Some((parent, _)) => path = parent,
                None => return false,
            }
        }
    }
}

impl MountSource for LiveView {
    fn is_immutable(&self) -> bool {
        false
    }
    fn list(&self, path: &str) -> Option<ListResult> {
        if self.removed(path) {
            return None;
        }
        let mut entries = BTreeMap::new();
        for source in [self.lower.as_ref(), &self.host as &dyn MountSource] {
            for child in source.list_dirents(path).unwrap_or_default() {
                let full = format!("{}/{}", path.trim_end_matches('/'), child.name);
                if let Some(fi) = self.lookup(&full, 0) {
                    entries.insert(child.name, fi);
                }
            }
        }
        Some(ListResult::Infos(entries))
    }
    fn lookup(&self, path: &str, version: i32) -> Option<FileInfo> {
        if self.removed(path) {
            return None;
        }
        if let Some(mut fi) = self.host.lookup(path, version) {
            fi.userdata
                .push(UserData::Other(format!("diff-live:{path}")));
            Some(fi)
        } else {
            self.lower.lookup(path, version)
        }
    }
    fn open(&self, fi: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        if let Some(UserData::Other(tag)) = fi.userdata.last() {
            if let Some(path) = tag.strip_prefix("diff-live:") {
                let mut file = {
                    #[expect(
                        clippy::disallowed_types,
                        reason = r###"internal-read:v1 {"id":"IR-B0102-T01","item":"<ratarmount::diff::live::LiveView as ratarmount_core::MountSource<ratarmount::diff::live::LiveView>>::open","disposition":"support","category":"builder-type-support","reason":"Builder type support: O_DIRECTORY handle for a descriptor-relative walk; no file content read","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
                    )]
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0102-M01","item":"<ratarmount::diff::live::LiveView as ratarmount_core::MountSource<ratarmount::diff::live::LiveView>>::open","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"out-of-family","baseline_reason":"O_DIRECTORY handle for a descriptor-relative walk; no file content read"}"###
                    )]
                    let mut __inventory_value_0 = fs::OpenOptions::new();
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0102-M02","item":"<ratarmount::diff::live::LiveView as ratarmount_core::MountSource<ratarmount::diff::live::LiveView>>::open","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"O_DIRECTORY handle for a descriptor-relative walk; no file content read","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                    )]
                    let __inventory_value_1 = __inventory_value_0
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                        .open(&self.root);
                    __inventory_value_1
                }?;
                let mut parts = path.trim_start_matches('/').split('/').peekable();
                while let Some(part) = parts.next() {
                    let flags = libc::O_RDONLY
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK
                        | if parts.peek().is_some() {
                            libc::O_DIRECTORY
                        } else {
                            0
                        };
                    // Pin every host parent; a concurrent directory-to-link swap
                    // cannot redirect an open outside the overlay.
                    // Admitted (R10-C): another name of an open overlay
                    // database is refused without closing a descriptor of it.
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0104-M01","item":"<ratarmount::diff::live::LiveView as ratarmount_core::MountSource<ratarmount::diff::live::LiveView>>::open","disposition":"residual","reason":"overlay payload descriptor (admitted open or borrowed raw descriptor); reverse-order payload ownership needs the excluded coordinator (db_inodes.rs:33)","family":"payload-admitted-readers","issue":"#196","category":"payload-admitted-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                    )]
                    let __inventory_assigned =
                        File::from(ratarmount_core::db_inodes::openat_admitted(
                            Some(file.as_fd()),
                            std::path::Path::new(part),
                            flags,
                            0,
                        )?);
                    file = __inventory_assigned;
                }
                return Ok(Box::new(file));
            }
        }
        self.lower.open(fi, buffering)
    }
}

fn host_paths(
    root: &Path,
    rel: &str,
    excludes: &core::Excludes,
    out: &mut BTreeSet<String>,
) -> io::Result<()> {
    for child in fs::read_dir(root.join(rel))? {
        let child = child?;
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("overlay path is not UTF-8"))?;
        let path = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        core::validate_relative_path(&path)?;
        if excludes.matches(&path, false) {
            continue;
        }
        let meta = fs::symlink_metadata(child.path())?;
        if excludes.matches(&path, meta.is_dir()) {
            continue;
        }
        out.insert(path.clone());
        if meta.is_dir() {
            host_paths(root, &path, excludes, out)?;
        }
    }
    Ok(())
}

pub(super) fn changes(
    args: &DiffArgs,
    source: Arc<dyn MountSource>,
    deleted: Vec<String>,
) -> io::Result<Vec<core::Change>> {
    let opts = args.options();
    let excludes = core::Excludes::new(&opts)?;
    let mut removed = BTreeSet::new();
    for path in deleted {
        // The inspection protocol carries absolute mount paths.
        let path = path.strip_prefix('/').unwrap_or(&path);
        core::validate_relative_path(path)?;
        removed.insert(path.to_owned());
    }
    let mut paths = removed.clone();
    host_paths(&args.directory, "", &excludes, &mut paths)?;
    let top = Arc::new(LiveView {
        lower: source.clone(),
        host: FolderMountSource::new(&args.directory)?,
        root: args.directory.clone(),
        deleted: removed,
    });
    core::compare_paths(paths, top, Some(source), &opts)
}
