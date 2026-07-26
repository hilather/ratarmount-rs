//! Path transform layer (Python `--transform REGEX REPLACEMENT`).
//!
//! Rewrites member paths with `regex::Regex::replace_all` for the mount view.
//! Builds an external→internal path map by walking the inner tree (cached).

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource,
};
use regex::Regex;

pub struct TransformMountSource {
    inner: Arc<dyn MountSource>,
    re: Regex,
    replacement: String,
    /// external full path → internal full path
    map: Mutex<Option<BTreeMap<String, String>>>,
}

impl TransformMountSource {
    pub fn new(
        pattern: &str,
        replacement: &str,
        inner: Arc<dyn MountSource>,
    ) -> Result<Self, String> {
        let re = Regex::new(pattern).map_err(|e| format!("--transform regex: {e}"))?;
        Ok(Self {
            inner,
            re,
            replacement: replacement.to_string(),
            map: Mutex::new(None),
        })
    }

    fn transform_path(&self, internal: &str) -> String {
        let t = self.re.replace_all(internal, self.replacement.as_str());
        normpath(t.as_ref())
    }

    fn ensure_map(&self) {
        let mut guard = self.map.lock().expect("transform map");
        if guard.is_some() {
            return;
        }
        let mut map = BTreeMap::new();
        let mut stack = vec!["/".to_string()];
        while let Some(path) = stack.pop() {
            let Some(listing) = self.inner.list(&path) else {
                continue;
            };
            let names: Vec<String> = match listing {
                ListResult::Names(n) => n,
                ListResult::Infos(m) => m.into_keys().collect(),
            };
            for name in names {
                let internal = if path == "/" {
                    format!("/{name}")
                } else {
                    format!("{path}/{name}")
                };
                let external = self.transform_path(&internal);
                map.insert(external.clone(), internal.clone());
                if let Some(fi) = self.inner.lookup(&internal, 0) {
                    if fi.mode & libc::S_IFMT == libc::S_IFDIR {
                        stack.push(internal);
                    }
                }
            }
        }
        // Always map root
        map.insert("/".into(), "/".into());
        *guard = Some(map);
    }

    fn to_internal(&self, external: &str) -> Option<String> {
        self.ensure_map();
        let guard = self.map.lock().ok()?;
        let map = guard.as_ref()?;
        map.get(&normpath(external)).cloned()
    }
}

impl MountSource for TransformMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.ensure_map();
        let path = normpath(path);
        let guard = self.map.lock().ok()?;
        let map = guard.as_ref()?;
        let mut out = BTreeMap::new();
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        };
        for (external, internal) in map.iter() {
            if external == &path {
                continue;
            }
            let name = if path == "/" {
                external
                    .strip_prefix('/')
                    .unwrap_or(external)
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string()
            } else if let Some(rest) = external.strip_prefix(&prefix) {
                rest.split('/').next().unwrap_or("").to_string()
            } else {
                continue;
            };
            if name.is_empty() || out.contains_key(&name) {
                continue;
            }
            // Only direct children
            let child_ext = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };
            if let Some(fi) = map
                .get(&child_ext)
                .and_then(|int| self.inner.lookup(int, 0))
            {
                out.insert(name, fi);
            } else if map
                .keys()
                .any(|e| e.starts_with(&(child_ext.clone() + "/")))
            {
                // directory synthesized
                out.insert(
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
            }
            let _ = internal;
        }
        if out.is_empty() && path != "/" {
            // empty dir or missing
            if map.contains_key(&path) || map.keys().any(|e| e.starts_with(&prefix)) {
                return Some(ListResult::Infos(out));
            }
            return None;
        }
        Some(ListResult::Infos(out))
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
        let internal = self.to_internal(&path)?;
        self.inner.lookup(&internal, file_version).or_else(|| {
            // Directory that only exists after transform aggregation
            if self
                .map
                .lock()
                .ok()
                .and_then(|g| {
                    g.as_ref()
                        .map(|m| m.keys().any(|e| e.starts_with(&(path.clone() + "/"))))
                })
                .unwrap_or(false)
            {
                Some(FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: libc::S_IFDIR | 0o755,
                    linkname: String::new(),
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    userdata: vec![],
                })
            } else {
                None
            }
        })
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(file_info, buffering)
    }

    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }
}
