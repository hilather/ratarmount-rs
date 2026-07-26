//! Union view of multiple mount sources (rightmost wins).

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource,
};

/// Union of mount sources; later sources override earlier ones for the same path.
pub struct UnionMountSource {
    sources: Vec<Arc<dyn MountSource>>,
}

impl UnionMountSource {
    pub fn new(sources: Vec<Arc<dyn MountSource>>) -> Self {
        Self { sources }
    }

    pub fn sources(&self) -> &[Arc<dyn MountSource>] {
        &self.sources
    }
}

impl MountSource for UnionMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        let mut map: BTreeMap<String, FileInfo> = BTreeMap::new();
        let mut any = false;
        for src in &self.sources {
            if let Some(listing) = src.list(&path) {
                any = true;
                match listing {
                    ListResult::Infos(m) => {
                        for (k, v) in m {
                            map.insert(k, v);
                        }
                    }
                    ListResult::Names(names) => {
                        for name in names {
                            if let Some(fi) = src.lookup(&join(&path, &name), 0) {
                                map.insert(name, fi);
                            }
                        }
                    }
                }
            }
        }
        if any {
            Some(ListResult::Infos(map))
        } else {
            None
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match self.list(path)? {
            ListResult::Infos(m) => Some(ListModeResult::Modes(
                m.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
            ListResult::Names(n) => Some(ListModeResult::Names(n)),
        }
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        // Rightmost wins
        for src in self.sources.iter().rev() {
            if let Some(fi) = src.lookup(&path, file_version) {
                return Some(fi);
            }
        }
        None
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        // Prefer source that can open: try reverse order using path from... we only have FileInfo.
        // Open via re-lookup is safer: not available. Try each source open until one works.
        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no union source could open");
        for src in self.sources.iter().rev() {
            match src.open(file_info, buffering) {
                Ok(r) => return Ok(r),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn is_immutable(&self) -> bool {
        self.sources.iter().all(|s| s.is_immutable())
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}
