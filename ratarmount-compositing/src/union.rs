//! Union view of multiple mount sources (rightmost wins).
//!
//! Matches Python `UnionMountSource`: optional folder→sources cache for faster
//! lookup across many archives (depth / entry count / wall-clock timeout).

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::Arc;
use std::time::Instant;

use log::warn;
use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};

/// Options for building the union folder cache (Python `--union-mount-cache-*`).
#[derive(Clone, Debug)]
pub struct UnionMountOptions {
    /// Maximum directory depth to pre-scan (default 1024).
    pub max_cache_depth: usize,
    /// Maximum number of directory paths to cache (default 100_000).
    pub max_cache_entries: usize,
    /// Wall-clock seconds allowed for cache build (default 60).
    pub max_seconds_to_cache: f64,
}

impl Default for UnionMountOptions {
    fn default() -> Self {
        Self {
            max_cache_depth: 1024,
            max_cache_entries: 100_000,
            max_seconds_to_cache: 60.0,
        }
    }
}

/// Union of mount sources; later sources override earlier ones for the same path.
pub struct UnionMountSource {
    sources: Vec<Arc<dyn MountSource>>,
    /// Cached folders: path → which **immutable** sources contain that directory.
    folder_cache: HashMap<String, Vec<usize>>,
    /// Depth actually cached (0 = only `/` or empty).
    folder_cache_depth: usize,
}

impl UnionMountSource {
    pub fn new(sources: Vec<Arc<dyn MountSource>>) -> Self {
        Self::new_with_options(sources, UnionMountOptions::default())
    }

    pub fn new_with_options(sources: Vec<Arc<dyn MountSource>>, opts: UnionMountOptions) -> Self {
        let mut u = Self {
            sources,
            folder_cache: HashMap::new(),
            folder_cache_depth: 0,
        };
        if u.sources.len() > 1 {
            u.build_folder_cache(
                opts.max_cache_depth.max(1),
                opts.max_cache_entries,
                opts.max_seconds_to_cache.max(0.0),
            );
        }
        u
    }

    pub fn sources(&self) -> &[Arc<dyn MountSource>] {
        &self.sources
    }

    pub fn folder_cache_depth(&self) -> usize {
        self.folder_cache_depth
    }

    pub fn folder_cache_len(&self) -> usize {
        self.folder_cache.len()
    }

    fn build_folder_cache(
        &mut self,
        max_cache_depth: usize,
        max_cache_entries: usize,
        max_seconds: f64,
    ) {
        let t0 = Instant::now();
        warn!("Building cache for union mount (timeout after {max_seconds}s)...");

        // Root: only immutable sources (mutable always consulted at runtime).
        let mut entries_left = max_cache_entries;
        let mut folder_cache: HashMap<String, Vec<usize>> = HashMap::new();
        let root_idxs: Vec<usize> = self
            .sources
            .iter()
            .enumerate()
            .filter(|(_, m)| m.is_immutable())
            .map(|(i, _)| i)
            .collect();
        folder_cache.insert("/".into(), root_idxs);
        let mut last: HashMap<String, Vec<usize>> = folder_cache.clone();
        let mut depth_done = 0usize;

        for depth in 1..max_cache_depth {
            let mut new_cache: HashMap<String, Vec<usize>> = HashMap::new();

            for (folder, idxs) in &last {
                for &si in idxs {
                    if t0.elapsed().as_secs_f64() > max_seconds || entries_left == 0 {
                        self.folder_cache = folder_cache;
                        self.folder_cache_depth = depth_done;
                        warn!(
                            "Union mount cache stopped early after {:.3}s ({} folders, depth {})",
                            t0.elapsed().as_secs_f64(),
                            self.folder_cache.len(),
                            self.folder_cache_depth
                        );
                        return;
                    }
                    let Some(listing) = self.sources[si].list(folder) else {
                        continue;
                    };
                    let names: Vec<String> = match listing {
                        ListResult::Names(n) => n,
                        ListResult::Infos(m) => m.into_keys().collect(),
                    };
                    for name in names {
                        if t0.elapsed().as_secs_f64() > max_seconds || entries_left == 0 {
                            self.folder_cache = folder_cache;
                            self.folder_cache_depth = depth_done;
                            warn!(
                                "Union mount cache stopped early after {:.3}s ({} folders, depth {})",
                                t0.elapsed().as_secs_f64(),
                                self.folder_cache.len(),
                                self.folder_cache_depth
                            );
                            return;
                        }
                        let full = join(folder, &name);
                        let Some(fi) = self.sources[si].lookup(&full, 0) else {
                            continue;
                        };
                        if fi.mode & ratarmount_core::S_IFMT != ratarmount_core::S_IFDIR {
                            continue;
                        }
                        entries_left = entries_left.saturating_sub(1);
                        new_cache.entry(full).or_default().push(si);
                    }
                }
            }

            if new_cache.is_empty() {
                break;
            }
            folder_cache.extend(new_cache.iter().map(|(k, v)| (k.clone(), v.clone())));
            depth_done = depth;
            last = new_cache;
        }

        self.folder_cache = folder_cache;
        self.folder_cache_depth = depth_done;
        warn!(
            "Cached mount sources for {} folders up to a depth of {} in {:.3}s for faster union mount.",
            self.folder_cache.len(),
            self.folder_cache_depth,
            t0.elapsed().as_secs_f64()
        );
    }

    /// Sources to query for `path`, using the folder cache when possible.
    fn sources_for_path(&self, path: &str) -> Vec<usize> {
        if self.sources.len() <= 1 || self.folder_cache.is_empty() {
            return (0..self.sources.len()).collect();
        }

        let cached: Option<&Vec<usize>> = if let Some(c) = self.folder_cache.get(path) {
            // path is a cached folder
            Some(c)
        } else if self.folder_cache_depth > 0 && path.starts_with('/') {
            // Look up parent at the cached depth (Python: split with maxdepth+1)
            let parent = parent_at_depth(path, self.folder_cache_depth);
            self.folder_cache.get(&parent)
        } else {
            None
        };

        let mut out = Vec::new();
        for (i, src) in self.sources.iter().enumerate() {
            // Mutable sources always consulted (Python: not m.is_immutable() or m in cached)
            if !src.is_immutable() {
                out.push(i);
            } else if let Some(c) = cached {
                if c.contains(&i) {
                    out.push(i);
                }
            } else {
                // Cache miss past cached depth: consult all immutable sources
                out.push(i);
            }
        }
        // If filter emptied (shouldn't), fall back to all
        if out.is_empty() {
            (0..self.sources.len()).collect()
        } else {
            out
        }
    }

    fn tag_source(mut fi: FileInfo, source_index: usize) -> FileInfo {
        fi.userdata
            .push(UserData::Other(format!("union:{source_index}")));
        fi
    }

    fn source_from_info(&self, file_info: &FileInfo) -> Option<usize> {
        file_info.userdata.iter().rev().find_map(|u| match u {
            UserData::Other(s) if s.starts_with("union:") => s[6..].parse().ok(),
            _ => None,
        })
    }
}

impl MountSource for UnionMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        let mut map: BTreeMap<String, FileInfo> = BTreeMap::new();
        let mut any = false;
        // List merges all sources (cache is for lookup hot path, not listing).
        for (si, src) in self.sources.iter().enumerate() {
            if let Some(listing) = src.list(&path) {
                any = true;
                match listing {
                    ListResult::Infos(m) => {
                        for (k, v) in m {
                            map.insert(k, Self::tag_source(v, si));
                        }
                    }
                    ListResult::Names(names) => {
                        for name in names {
                            if let Some(fi) = src.lookup(&join(&path, &name), 0) {
                                map.insert(name, Self::tag_source(fi, si));
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

        let idxs = self.sources_for_path(&path);

        if file_version <= 0 {
            // Negative / zero: walk rightmost first; accumulate versions
            let mut ver = file_version;
            for &si in idxs.iter().rev() {
                let src = &self.sources[si];
                if let Some(fi) = src.lookup(&path, ver) {
                    return Some(Self::tag_source(fi, si));
                }
                ver += src.versions(&path) as i32;
                if ver > 0 {
                    break;
                }
            }
        } else {
            // Positive version: walk left to right
            let mut ver = file_version;
            for &si in &idxs {
                let src = &self.sources[si];
                if let Some(fi) = src.lookup(&path, ver) {
                    return Some(Self::tag_source(fi, si));
                }
                let n = src.versions(&path) as i32;
                ver -= n;
                if ver < 1 {
                    break;
                }
            }
        }
        None
    }

    fn versions(&self, path: &str) -> u32 {
        let path = normpath(path);
        self.sources.iter().map(|s| s.versions(&path)).sum()
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if let Some(si) = self.source_from_info(file_info) {
            if let Some(src) = self.sources.get(si) {
                // Strip union tag for inner open
                let mut fi = file_info.clone();
                if let Some(UserData::Other(s)) = fi.userdata.last() {
                    if s.starts_with("union:") {
                        fi.userdata.pop();
                    }
                }
                return src.open(&fi, buffering);
            }
        }
        // Fallback: try reverse order
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

/// Parent path at most `depth` levels deep (Python: `'/'.join(path.split('/', depth+1)[:-1])`).
fn parent_at_depth(path: &str, depth: usize) -> String {
    if depth == 0 || path == "/" {
        return "/".into();
    }
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.is_empty() {
        return "/".into();
    }
    // Keep at most `depth` path components for the parent folder of a file at greater depth.
    // Python: split('/', folderCacheDepth + 1)[:-1] then join
    let take = depth.min(parts.len().saturating_sub(1));
    if take == 0 {
        return "/".into();
    }
    format!("/{}", parts[..take].join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::folder::FolderMountSource;
    use std::fs;
    use std::io::Read;

    /// Folder bind that reports immutable so the union cache includes it (like archives).
    struct ImmFolder(FolderMountSource);
    impl MountSource for ImmFolder {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.0.list(path)
        }
        fn lookup(&self, path: &str, v: i32) -> Option<FileInfo> {
            self.0.lookup(path, v)
        }
        fn open(
            &self,
            fi: &FileInfo,
            buffering: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.0.open(fi, buffering)
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    #[test]
    fn parent_at_depth_helpers() {
        assert_eq!(parent_at_depth("/a/b/c", 1), "/a");
        assert_eq!(parent_at_depth("/a/b/c", 2), "/a/b");
        assert_eq!(parent_at_depth("/a/b/c", 5), "/a/b");
        assert_eq!(parent_at_depth("/file", 1), "/");
    }

    #[test]
    fn union_rightmost_wins_and_cache() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        fs::create_dir_all(a.join("sub")).unwrap();
        fs::create_dir_all(b.join("sub")).unwrap();
        fs::write(a.join("sub/x.txt"), b"from-a").unwrap();
        fs::write(b.join("sub/x.txt"), b"from-b").unwrap();
        fs::write(a.join("only-a.txt"), b"a").unwrap();

        let sa = Arc::new(ImmFolder(FolderMountSource::new(&a).unwrap())) as Arc<dyn MountSource>;
        let sb = Arc::new(ImmFolder(FolderMountSource::new(&b).unwrap())) as Arc<dyn MountSource>;
        let u = UnionMountSource::new_with_options(
            vec![sa, sb],
            UnionMountOptions {
                max_cache_depth: 8,
                max_cache_entries: 1000,
                max_seconds_to_cache: 10.0,
            },
        );
        assert!(u.folder_cache_len() >= 2, "expected / and /sub cached");
        assert!(u.folder_cache_depth() >= 1);

        let fi = u.lookup("/sub/x.txt", 0).expect("x.txt");
        let mut r = u.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "from-b");

        let only = u.lookup("/only-a.txt", 0).expect("only-a");
        let mut r = u.open(&only, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "a");
    }

    #[test]
    fn mutable_folders_union_without_cache() {
        // Real FolderMountSource is mutable (like Python) — cache stays shallow but lookup works.
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::write(a.join("x"), b"a").unwrap();
        fs::write(b.join("x"), b"b").unwrap();
        let sa = Arc::new(FolderMountSource::new(&a).unwrap()) as Arc<dyn MountSource>;
        let sb = Arc::new(FolderMountSource::new(&b).unwrap()) as Arc<dyn MountSource>;
        let u = UnionMountSource::new(vec![sa, sb]);
        let fi = u.lookup("/x", 0).unwrap();
        let mut r = u.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "b");
    }

    #[test]
    fn cache_timeout_zero_still_lookups() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        fs::create_dir_all(a.join("sub")).unwrap();
        fs::create_dir_all(b.join("sub")).unwrap();
        let sa = Arc::new(ImmFolder(FolderMountSource::new(&a).unwrap())) as Arc<dyn MountSource>;
        let sb = Arc::new(ImmFolder(FolderMountSource::new(&b).unwrap())) as Arc<dyn MountSource>;
        let u = UnionMountSource::new_with_options(
            vec![sa, sb],
            UnionMountOptions {
                max_cache_depth: 100,
                max_cache_entries: 100,
                max_seconds_to_cache: 0.0,
            },
        );
        assert!(u.lookup("/", 0).is_some());
        assert!(u.lookup("/sub", 0).is_some());
    }
}
