//! Live overlay inspection when the writer owns SQLite's exclusive lock.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
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
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                    .open(&self.root)?;
                let mut parts = path.trim_start_matches('/').split('/').peekable();
                while let Some(part) = parts.next() {
                    let name = std::ffi::CString::new(part).map_err(io::Error::other)?;
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
                    let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags) };
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    file = unsafe { File::from_raw_fd(fd) };
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
