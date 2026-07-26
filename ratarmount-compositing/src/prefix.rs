//! Mount under a path prefix (Python `-p` / RemovePrefixMountSource inverse).
//!
//! `PrefixMountSource` makes the entire tree appear under `/prefix/...`.

use std::io;
use std::sync::Arc;

use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource,
};

/// Wrap `inner` so all content is reachable under `prefix`.
pub struct PrefixMountSource {
    prefix: String,
    inner: Arc<dyn MountSource>,
}

impl PrefixMountSource {
    /// `prefix` like `"data"` or `"/data"` → content at `/data/...`.
    pub fn new(prefix: &str, inner: Arc<dyn MountSource>) -> Self {
        let p = prefix.trim().trim_matches('/');
        Self {
            prefix: if p.is_empty() {
                String::new()
            } else {
                format!("/{p}")
            },
            inner,
        }
    }

    fn strip(&self, path: &str) -> Option<String> {
        if self.prefix.is_empty() {
            return Some(normpath(path));
        }
        let path = normpath(path);
        if path == self.prefix {
            return Some("/".into());
        }
        if let Some(rest) = path.strip_prefix(&(self.prefix.clone() + "/")) {
            return Some(format!("/{rest}"));
        }
        if path == "/" {
            return None; // root is the prefix parent
        }
        None
    }
}

impl MountSource for PrefixMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if self.prefix.is_empty() {
            return self.inner.list(&path);
        }
        if path == "/" {
            // Single entry: the prefix name
            let name = self.prefix.trim_start_matches('/').to_string();
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                name,
                FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: libc::S_IFDIR | 0o755,
                    linkname: String::new(),
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    userdata: vec![],
                },
            );
            return Some(ListResult::Infos(map));
        }
        let inner_path = self.strip(&path)?;
        self.inner.list(&inner_path)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match self.list(path)? {
            ListResult::Names(n) => Some(ListModeResult::Names(n)),
            ListResult::Infos(m) => Some(ListModeResult::Modes(
                m.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
        }
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        if self.prefix.is_empty() {
            return self.inner.lookup(&path, file_version);
        }
        if path == self.prefix {
            return Some(FileInfo {
                size: 0,
                mtime: 0.0,
                mode: libc::S_IFDIR | 0o755,
                linkname: String::new(),
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                userdata: vec![],
            });
        }
        let inner_path = self.strip(&path)?;
        self.inner.lookup(&inner_path, file_version)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(file_info, buffering)
    }

    fn versions(&self, path: &str) -> u32 {
        let path = normpath(path);
        if let Some(inner) = self.strip(&path) {
            self.inner.versions(&inner)
        } else {
            0
        }
    }

    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }
}
