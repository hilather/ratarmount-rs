//! Path transform layer (Python `--transform REGEX REPLACEMENT`).
//!
//! Rewrites member paths with `regex::Regex::replace_all` for the mount view.
//! Builds an external→internal path map by walking the inner tree (cached).

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

use ratarmount_core::{
    create_root_file_info, normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult,
    ListResult, MountSource,
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
                    if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
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
                        mode: ratarmount_core::S_IFDIR | 0o755,
                        linkname: String::new(),
                        uid: ratarmount_core::effective_uid(),
                        gid: ratarmount_core::effective_gid(),
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

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.ensure_map();
        let path = normpath(path);
        let guard = self.map.lock().ok()?;
        let map = guard.as_ref()?;
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        };

        let mut child_names: Vec<String> = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for external in map.keys() {
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
            if name.is_empty() || !seen.insert(name.clone()) {
                continue;
            }
            child_names.push(name);
        }

        let mut parent_listings: BTreeMap<String, BTreeMap<String, CheapDirent>> = BTreeMap::new();
        for name in &child_names {
            let child_ext = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };
            if let Some(internal) = map.get(&child_ext) {
                parent_listings
                    .entry(internal_parent(internal))
                    .or_default();
            }
        }
        for parent in parent_listings.keys().cloned().collect::<Vec<_>>() {
            if let Some(dents) = self.inner.list_dirents(&parent) {
                let idx = dents.into_iter().map(|d| (d.name.clone(), d)).collect();
                parent_listings.insert(parent, idx);
            }
        }

        let mut out = Vec::new();
        for name in child_names {
            let child_ext = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };
            if let Some(internal) = map.get(&child_ext) {
                let parent = internal_parent(internal);
                let base = internal_basename(internal);
                if let Some(d) = parent_listings.get(&parent).and_then(|idx| idx.get(&base)) {
                    out.push(CheapDirent {
                        name,
                        mode: d.mode,
                        size: d.size,
                    });
                    continue;
                }
            }
            if map
                .keys()
                .any(|e| e.starts_with(&(child_ext.clone() + "/")))
            {
                out.push(CheapDirent {
                    name,
                    mode: ratarmount_core::S_IFDIR | 0o755,
                    size: 0,
                });
            }
        }

        if out.is_empty() && path != "/" {
            if map.contains_key(&path) || map.keys().any(|e| e.starts_with(&prefix)) {
                return Some(out);
            }
            return None;
        }
        Some(out)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let dents = self.list_dirents(path)?;
        Some(ListModeResult::Modes(
            dents.into_iter().map(|d| (d.name, d.mode)).collect(),
        ))
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return None;
        }
        self.inner.search_cheap(pattern)
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
                    mode: ratarmount_core::S_IFDIR | 0o755,
                    linkname: String::new(),
                    uid: ratarmount_core::effective_uid(),
                    gid: ratarmount_core::effective_gid(),
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

    fn content_generation(&self) -> u64 {
        self.inner.content_generation()
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        self.inner.member_seek_is_cheap(file_info)
    }

    fn list_xattr(&self, file_info: &FileInfo) -> Vec<String> {
        self.inner.list_xattr(file_info)
    }

    fn get_xattr(&self, file_info: &FileInfo, key: &str) -> Option<Vec<u8>> {
        self.inner.get_xattr(file_info, key)
    }
}

fn internal_parent(path: &str) -> String {
    if path == "/" {
        return "/".into();
    }
    match path.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => path[..i].to_string(),
    }
}

fn internal_basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_core::OpenOptions;
    use ratarmount_formats_zip::ZipMountSource;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    /// Counts `list()` so we can prove Transform uses `list_dirents` after `ensure_map`.
    struct ListCallCounter {
        inner: ZipMountSource,
        list_calls: AtomicUsize,
    }

    impl MountSource for ListCallCounter {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.list(path)
        }

        fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
            self.inner.list_dirents(path)
        }

        fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
            self.inner.lookup(path, file_version)
        }

        fn versions(&self, path: &str) -> u32 {
            self.inner.versions(path)
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

    fn zip_with_two_members() -> (
        tempfile::TempDir,
        Arc<ListCallCounter>,
        &'static [u8],
        &'static [u8],
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xform.zip");
        let a: &'static [u8] = b"alpha-payload\n";
        let b: &'static [u8] = b"bravo-bytes-here\n";
        {
            let file = std::fs::File::create(&path).unwrap();
            let mut zw = ZipWriter::new(file);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zw.start_file("a.txt", opts).unwrap();
            zw.write_all(a).unwrap();
            zw.start_file("b.bin", opts).unwrap();
            zw.write_all(b).unwrap();
            zw.finish().unwrap();
        }
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let zip = ZipMountSource::open(&path, None, &opts, "test", true).expect("open zip");
        let counted = Arc::new(ListCallCounter {
            inner: zip,
            list_calls: AtomicUsize::new(0),
        });
        (dir, counted, a, b)
    }

    /// Regression: `--transform` readdir called `inner.list()` after `ensure_map`,
    /// or dropped sizes.
    #[test]
    fn transform_list_dirents_forwards_inner_sizes_without_list_after_ensure_map() {
        let (_dir, counted, a, b) = zip_with_two_members();
        let layer =
            TransformMountSource::new("$", "", Arc::clone(&counted) as Arc<dyn MountSource>)
                .expect("identity transform");

        let first = layer.list_dirents("/").expect("warmup dirents");
        let after_map = counted.list_calls.load(Ordering::SeqCst);
        assert!(
            after_map > 0,
            "ensure_map may list() once while building the path map"
        );
        let by_name: BTreeMap<_, _> = first.into_iter().map(|d| (d.name, d.size)).collect();
        assert_eq!(by_name.get("a.txt").copied(), Some(a.len() as u64));
        assert_eq!(by_name.get("b.bin").copied(), Some(b.len() as u64));

        let second = layer.list_dirents("/").expect("second dirents");
        assert_eq!(
            counted.list_calls.load(Ordering::SeqCst),
            after_map,
            "list_dirents must not call inner.list() after ensure_map"
        );
        let by_name: BTreeMap<_, _> = second.into_iter().map(|d| (d.name, d.size)).collect();
        assert_eq!(by_name.get("a.txt").copied(), Some(a.len() as u64));
        assert_eq!(by_name.get("b.bin").copied(), Some(b.len() as u64));
    }

    /// Collapsed/split tree missing a synthesized `S_IFDIR` size-0 parent.
    #[test]
    fn transform_list_dirents_synthesizes_intermediate_dirs() {
        let (_dir, counted, a, b) = zip_with_two_members();
        let layer =
            TransformMountSource::new("^/", "/virt/", Arc::clone(&counted) as Arc<dyn MountSource>)
                .expect("prefix transform");

        let root = layer.list_dirents("/").expect("root dirents");
        assert_eq!(root.len(), 1, "root should show one synthesized parent");
        assert_eq!(root[0].name, "virt");
        assert_eq!(root[0].mode, ratarmount_core::S_IFDIR | 0o755);
        assert_eq!(root[0].size, 0);

        let after_map = counted.list_calls.load(Ordering::SeqCst);
        let kids = layer.list_dirents("/virt").expect("virt dirents");
        assert_eq!(
            counted.list_calls.load(Ordering::SeqCst),
            after_map,
            "second list_dirents must not call inner.list() after ensure_map"
        );
        let by_name: BTreeMap<_, _> = kids.into_iter().map(|d| (d.name, d.size)).collect();
        assert_eq!(by_name.get("a.txt").copied(), Some(a.len() as u64));
        assert_eq!(by_name.get("b.bin").copied(), Some(b.len() as u64));
    }
}
