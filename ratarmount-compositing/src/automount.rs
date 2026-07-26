//! Automatically mount nested archives as directories (Python `AutoMountLayer`).

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use log::debug;
use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};
use tempfile::NamedTempFile;

/// Open a nested archive from a filesystem path into a MountSource.
pub type OpenNestedFn = Arc<dyn Fn(&Path) -> io::Result<Arc<dyn MountSource>> + Send + Sync>;

const TAG_PREFIX: &str = "automount:";

/// Returns true if `name` looks like a mountable nested archive.
pub fn is_archive_filename(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with(".tar")
        || l.ends_with(".tar.gz")
        || l.ends_with(".tgz")
        || l.ends_with(".tar.bz2")
        || l.ends_with(".tbz2")
        || l.ends_with(".tar.xz")
        || l.ends_with(".txz")
        || l.ends_with(".tar.zst")
        || l.ends_with(".tar.zstd")
        || l.ends_with(".tzst")
        || l.ends_with(".zip")
        || l.ends_with(".jar")
        || l.ends_with(".7z")
        || l.ends_with(".rar")
        || l.ends_with(".iso")
        || l.ends_with(".cab")
        || l.ends_with(".ar")
        || l.ends_with(".a")
        || l.ends_with(".cpio")
}

struct NestedMount {
    source: Arc<dyn MountSource>,
    _persist: PathBuf,
    depth: u32,
}

/// Wraps a mount source and exposes nested archives as subfolders.
pub struct AutoMountLayer {
    root: Arc<dyn MountSource>,
    mounted: HashMap<String, NestedMount>,
    max_depth: u32,
    open_nested: OpenNestedFn,
}

impl AutoMountLayer {
    pub fn new(root: Arc<dyn MountSource>, max_depth: u32, open_nested: OpenNestedFn) -> Self {
        let mut layer = Self {
            root,
            mounted: HashMap::new(),
            max_depth: if max_depth == 0 { 32 } else { max_depth },
            open_nested,
        };
        layer.scan_and_mount();
        layer
    }

    fn scan_and_mount(&mut self) {
        let mut folders = vec!["/".to_string()];
        while let Some(folder) = folders.pop() {
            let depth = self.depth_at(&folder);
            if depth >= self.max_depth {
                continue;
            }
            let Some(names) = self.list_names(&folder) else {
                continue;
            };
            for name in names {
                let full = join(&folder, &name);
                if self.is_dir_at(&full) {
                    folders.push(full);
                    continue;
                }
                if is_archive_filename(&name) && self.try_mount_file(&full, depth + 1) {
                    debug!("automounted {full}");
                    folders.push(full);
                }
            }
        }
    }

    fn depth_at(&self, path: &str) -> u32 {
        let (mp, _) = self.find_mounted(path);
        if mp == "/" {
            0
        } else {
            self.mounted.get(mp).map(|m| m.depth).unwrap_or(0)
        }
    }

    fn list_names(&self, path: &str) -> Option<Vec<String>> {
        let (mp, rest) = self.find_mounted(path);
        let src = self.source_at(mp);
        match src.list(&rest)? {
            ListResult::Infos(m) => Some(m.into_keys().collect()),
            ListResult::Names(n) => Some(n),
        }
    }

    fn is_dir_at(&self, path: &str) -> bool {
        if self.mounted.contains_key(path) {
            return true;
        }
        self.lookup_raw(path)
            .map(|fi| fi.mode & libc::S_IFMT == libc::S_IFDIR)
            .unwrap_or(false)
    }

    fn lookup_raw(&self, path: &str) -> Option<FileInfo> {
        let (mp, rest) = self.find_mounted(path);
        self.source_at(mp).lookup(&rest, 0)
    }

    fn source_at(&self, mount_point: &str) -> Arc<dyn MountSource> {
        if mount_point == "/" {
            Arc::clone(&self.root)
        } else {
            self.mounted
                .get(mount_point)
                .map(|m| Arc::clone(&m.source))
                .unwrap_or_else(|| Arc::clone(&self.root))
        }
    }

    fn find_mounted<'a>(&'a self, path: &str) -> (&'a str, String) {
        let path = normpath(path);
        if path == "/" {
            return ("/", "/".into());
        }
        let mut best: &str = "/";
        for mp in self.mounted.keys() {
            if path == mp.as_str() || path.starts_with(&(mp.clone() + "/")) {
                if mp.len() > best.len() {
                    best = mp.as_str();
                }
            }
        }
        if best == "/" {
            ("/", path)
        } else if path == best {
            (best, "/".into())
        } else {
            (best, path[best.len()..].to_string())
        }
    }

    fn try_mount_file(&mut self, path: &str, depth: u32) -> bool {
        if self.mounted.contains_key(path) {
            return true;
        }
        let Some(fi) = self.lookup_raw(path) else {
            return false;
        };
        if fi.mode & libc::S_IFMT == libc::S_IFDIR {
            return false;
        }
        let (mp, rest) = self.find_mounted(path);
        let parent = self.source_at(mp);
        let Some(fi) = parent.lookup(&rest, 0) else {
            return false;
        };
        let mut reader = match parent.open(&fi, 0) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let mut tmp = match NamedTempFile::new() {
            Ok(t) => t,
            Err(_) => return false,
        };
        if io::copy(&mut reader, &mut tmp).is_err() {
            return false;
        }
        let _ = tmp.flush();
        let tmp_path = tmp.into_temp_path();
        let persist = match tmp_path.keep() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let nested = match (self.open_nested)(&persist) {
            Ok(s) => s,
            Err(e) => {
                debug!("failed to open nested {}: {e}", persist.display());
                let _ = std::fs::remove_file(&persist);
                return false;
            }
        };
        self.mounted.insert(
            path.to_string(),
            NestedMount {
                source: nested,
                _persist: persist,
                depth,
            },
        );
        true
    }

    fn tag(mut fi: FileInfo, mount_point: &str) -> FileInfo {
        fi.userdata
            .push(UserData::Other(format!("{TAG_PREFIX}{mount_point}")));
        fi
    }

    fn tag_map(map: std::collections::BTreeMap<String, FileInfo>, mp: &str) -> std::collections::BTreeMap<String, FileInfo> {
        map.into_iter()
            .map(|(k, v)| (k, Self::tag(v, mp)))
            .collect()
    }

    fn automount_key(fi: &FileInfo) -> Option<&str> {
        fi.userdata.iter().rev().find_map(|u| match u {
            UserData::Other(s) if s.starts_with(TAG_PREFIX) => Some(&s[TAG_PREFIX.len()..]),
            _ => None,
        })
    }
}

impl MountSource for AutoMountLayer {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if let Some(m) = self.mounted.get(&path) {
            return match m.source.list("/")? {
                ListResult::Infos(map) => Some(ListResult::Infos(Self::tag_map(map, &path))),
                ListResult::Names(names) => {
                    let mut map = std::collections::BTreeMap::new();
                    for name in names {
                        if let Some(fi) = m.source.lookup(&join("/", &name), 0) {
                            map.insert(name, Self::tag(fi, &path));
                        }
                    }
                    Some(ListResult::Infos(map))
                }
            };
        }
        let (mp, rest) = self.find_mounted(&path);
        let src = self.source_at(mp);
        let listing = src.list(&rest)?;
        match listing {
            ListResult::Infos(mut map) => {
                for (name, fi) in map.iter_mut() {
                    let full = join(&path, name);
                    if self.mounted.contains_key(&full) {
                        fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
                        fi.size = 0;
                    }
                    // Tag with owning mount for open routing
                    *fi = Self::tag(fi.clone(), mp);
                }
                Some(ListResult::Infos(map))
            }
            ListResult::Names(names) => {
                let mut map = std::collections::BTreeMap::new();
                for name in names {
                    let full = join(&path, &name);
                    let child_rest = join(&rest, &name);
                    if let Some(mut fi) = src.lookup(&child_rest, 0) {
                        if self.mounted.contains_key(&full) {
                            fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
                            fi.size = 0;
                        }
                        map.insert(name, Self::tag(fi, mp));
                    }
                }
                Some(ListResult::Infos(map))
            }
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        // Fast path: do not expand full FileInfo maps (list()) — find() only needs modes.
        let path = normpath(path);
        if let Some(m) = self.mounted.get(&path) {
            return match m.source.list_mode("/")? {
                ListModeResult::Modes(map) => Some(ListModeResult::Modes(map)),
                ListModeResult::Names(names) => Some(ListModeResult::Names(names)),
            };
        }
        let (mp, rest) = self.find_mounted(&path);
        let src = self.source_at(mp);
        match src.list_mode(&rest)? {
            ListModeResult::Modes(mut map) => {
                for (name, mode) in map.iter_mut() {
                    let full = join(&path, name);
                    if self.mounted.contains_key(&full) {
                        *mode = (*mode & 0o7777) | libc::S_IFDIR as u32;
                    }
                }
                Some(ListModeResult::Modes(map))
            }
            ListModeResult::Names(names) => {
                // Promote automounted archives to directories for find -type d semantics.
                let mut modes = std::collections::BTreeMap::new();
                for name in names {
                    let full = join(&path, &name);
                    let child_rest = join(&rest, &name);
                    let mode = if self.mounted.contains_key(&full) {
                        (libc::S_IFDIR | 0o755) as u32
                    } else if let Some(fi) = src.lookup(&child_rest, 0) {
                        fi.mode
                    } else {
                        libc::S_IFREG as u32
                    };
                    modes.insert(name, mode);
                }
                Some(ListModeResult::Modes(modes))
            }
        }
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        if let Some(m) = self.mounted.get(&path) {
            let mut fi = m.source.lookup("/", 0).unwrap_or_else(create_root_file_info);
            fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
            fi.size = 0;
            return Some(Self::tag(fi, &path));
        }
        let (mp, rest) = self.find_mounted(&path);
        if mp != "/" {
            let fi = self.source_at(mp).lookup(&rest, file_version)?;
            return Some(Self::tag(fi, mp));
        }
        let mut fi = self.root.lookup(&path, file_version)?;
        if self.mounted.contains_key(&path) {
            fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
            fi.size = 0;
        }
        Some(Self::tag(fi, "/"))
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if let Some(key) = Self::automount_key(file_info) {
            if key == "/" {
                return self.root.open(file_info, buffering);
            }
            if let Some(m) = self.mounted.get(key) {
                return m.source.open(file_info, buffering);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("automount tag unknown: {key}"),
            ));
        }
        // Untagged (should be rare): root only
        self.root.open(file_info, buffering)
    }

    fn is_immutable(&self) -> bool {
        self.root.is_immutable()
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}
