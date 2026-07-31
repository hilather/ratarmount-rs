//! Union view of multiple mount sources (rightmost wins for same type).
//!
//! Matches Python `UnionMountSource`: optional folder→sources cache for faster
//! lookup across many archives (depth / entry count / wall-clock timeout).
//!
//! **Directory-over-symlink policy (B-4 / mxmlnkn/ratarmount#164):** when one
//! source has a real directory at a path and another has a symlink, version-0
//! `lookup` returns a directory (rightmost directory for metadata). `list`
//! merges children from every source that contributes a directory or a
//! followable symlink at that path, and never replaces a listed directory
//! entry with a symlink.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::Arc;
use std::time::Instant;

use log::warn;
use ratarmount_core::{
    create_root_file_info, is_dir_mode, is_lnk_mode, normpath, FileInfo, ListModeResult,
    ListResult, MountSource, UserData,
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
                    // List via the same one-hop symlink follow as B-4 `list`, so
                    // walk continues into symlink→dir branches (immutable archives).
                    let Some(listing) = Self::list_from_source(self.sources[si].as_ref(), folder)
                    else {
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
                        // Cache real directories *and* followable symlink→dir paths.
                        // Previously only S_IFDIR was recorded, so immutable sources
                        // with a symlink branch were dropped from sources_for_path
                        // → lookup/open ENOENT after list still showed their children.
                        if Self::list_from_source(self.sources[si].as_ref(), &full).is_none() {
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

    /// Insert/merge a child into a list map: later sources win, except a directory
    /// is never replaced by a symlink (B-4 / mxmlnkn/ratarmount#164).
    fn merge_list_entry(map: &mut BTreeMap<String, FileInfo>, name: String, fi: FileInfo) {
        if let Some(existing) = map.get(&name) {
            if is_dir_mode(existing.mode) && is_lnk_mode(fi.mode) {
                return;
            }
        }
        map.insert(name, fi);
    }

    /// List a path from one source. If the source has a symlink at `path`, try to
    /// follow one level within that source so symlink→dir branches still contribute.
    fn list_from_source(src: &dyn MountSource, path: &str) -> Option<ListResult> {
        if let Some(listing) = src.list(path) {
            return Some(listing);
        }
        let fi = src.lookup(path, 0)?;
        if !is_lnk_mode(fi.mode) || fi.linkname.is_empty() {
            return None;
        }
        let target = resolve_symlink_target(path, &fi.linkname);
        src.list(&target)
    }
}

impl MountSource for UnionMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        let mut map: BTreeMap<String, FileInfo> = BTreeMap::new();
        let mut any = false;
        // List merges all sources (cache is for lookup hot path, not listing).
        // Sources with a real directory *or* a followable symlink at `path` contribute.
        for (si, src) in self.sources.iter().enumerate() {
            if let Some(listing) = Self::list_from_source(src.as_ref(), &path) {
                any = true;
                match listing {
                    ListResult::Infos(m) => {
                        for (k, v) in m {
                            Self::merge_list_entry(&mut map, k, Self::tag_source(v, si));
                        }
                    }
                    ListResult::Names(names) => {
                        for name in names {
                            if let Some(fi) = src.lookup(&join(&path, &name), 0) {
                                Self::merge_list_entry(&mut map, name, Self::tag_source(fi, si));
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

        if file_version == 0 {
            // Version 0: rightmost wins, but a real directory always beats a symlink
            // so union order cannot hide directory contents (B-4 / #164).
            let mut rightmost_any: Option<(usize, FileInfo)> = None;
            let mut rightmost_dir: Option<(usize, FileInfo)> = None;
            for &si in idxs.iter().rev() {
                if let Some(fi) = self.sources[si].lookup(&path, 0) {
                    if rightmost_any.is_none() {
                        rightmost_any = Some((si, fi.clone()));
                    }
                    if is_dir_mode(fi.mode) {
                        rightmost_dir = Some((si, fi));
                        break;
                    }
                }
            }
            return rightmost_dir
                .or(rightmost_any)
                .map(|(si, fi)| Self::tag_source(fi, si));
        }

        if file_version < 0 {
            // Negative: walk rightmost first; accumulate versions
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

/// Resolve a symlink target relative to the directory containing `path` (one hop).
fn resolve_symlink_target(path: &str, linkname: &str) -> String {
    if linkname.starts_with('/') {
        return normpath(linkname);
    }
    let parent = if path == "/" {
        "/".to_string()
    } else {
        match path.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => path[..i].to_string(),
        }
    };
    if parent == "/" {
        normpath(&format!("/{linkname}"))
    } else {
        normpath(&format!("{parent}/{linkname}"))
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

    /// Regression: Dec 31 1969-style order bug for union symlink vs directory.
    ///
    /// Upstream mxmlnkn/ratarmount#164 / residual B-4: two folder branches where
    /// one has `subdir0` → symlink `./subdir1` and the other has a real
    /// `subdir0/` directory. Lookup type and merged listings must not depend on
    /// mount order — directory wins over symlink; children from both sides merge.
    fn build_b4_branches(root: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let branch1 = root.join("branch1");
        let branch2 = root.join("branch2");
        // branch1: subdir0 → ./subdir1; subdir1/subdir2/file1
        fs::create_dir_all(branch1.join("subdir1/subdir2")).unwrap();
        fs::write(branch1.join("subdir1/subdir2/file1"), b"file1").unwrap();
        std::os::unix::fs::symlink("./subdir1", branch1.join("subdir0")).unwrap();
        // branch2: real dir subdir0/subdir2/file2; subdir1/subdir2/file3
        fs::create_dir_all(branch2.join("subdir0/subdir2")).unwrap();
        fs::write(branch2.join("subdir0/subdir2/file2"), b"file2").unwrap();
        fs::create_dir_all(branch2.join("subdir1/subdir2")).unwrap();
        fs::write(branch2.join("subdir1/subdir2/file3"), b"file3").unwrap();
        (branch1, branch2)
    }

    fn assert_b4_union_policy(u: &UnionMountSource, order_label: &str) {
        let subdir0 = u
            .lookup("/subdir0", 0)
            .unwrap_or_else(|| panic!("{order_label}: /subdir0 missing"));
        assert!(
            is_dir_mode(subdir0.mode),
            "{order_label}: /subdir0 must be directory (mode={:#o}), not symlink",
            subdir0.mode
        );
        assert!(
            !is_lnk_mode(subdir0.mode),
            "{order_label}: /subdir0 must not be a symlink"
        );

        // Root listing: subdir0 entry is directory even if a later branch has a symlink.
        let root_list = u.list("/").expect("list /");
        let ListResult::Infos(root_map) = root_list else {
            panic!("{order_label}: expected Infos at /");
        };
        let root_s0 = root_map
            .get("subdir0")
            .unwrap_or_else(|| panic!("{order_label}: root list missing subdir0"));
        assert!(
            is_dir_mode(root_s0.mode),
            "{order_label}: listed subdir0 must be directory"
        );

        // subdir0/subdir2 must include file2 from the real-dir branch in both orders.
        let listing = u
            .list("/subdir0/subdir2")
            .unwrap_or_else(|| panic!("{order_label}: list /subdir0/subdir2"));
        let ListResult::Infos(map) = listing else {
            panic!("{order_label}: expected Infos for /subdir0/subdir2");
        };
        assert!(
            map.contains_key("file2"),
            "{order_label}: /subdir0/subdir2 must contain file2; got {:?}",
            map.keys().collect::<Vec<_>>()
        );
        // file1 is reachable via the symlink branch once path is treated as a dir union.
        assert!(
            map.contains_key("file1"),
            "{order_label}: /subdir0/subdir2 should also contain file1; got {:?}",
            map.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn union_directory_wins_over_symlink_order_independent() {
        let d = tempfile::tempdir().unwrap();
        let (branch1, branch2) = build_b4_branches(d.path());

        let s1 = Arc::new(FolderMountSource::new(&branch1).unwrap()) as Arc<dyn MountSource>;
        let s2 = Arc::new(FolderMountSource::new(&branch2).unwrap()) as Arc<dyn MountSource>;

        // Order A: symlink branch first, real-dir branch rightmost (historically OK).
        let u_dir_right = UnionMountSource::new(vec![s1.clone(), s2.clone()]);
        assert_b4_union_policy(&u_dir_right, "branch1 then branch2");

        // Order B: real-dir first, symlink rightmost (historically lost file2 + showed symlink).
        let u_lnk_right = UnionMountSource::new(vec![s2, s1]);
        assert_b4_union_policy(&u_lnk_right, "branch2 then branch1");
    }

    /// Regression: union folder cache + immutable sources dropped symlink branches.
    ///
    /// Symptom: `list` of `/subdir0/subdir2` shows `file1` (via one-hop symlink
    /// follow) but `lookup`/`open` return ENOENT because `build_folder_cache`
    /// only recorded real `S_IFDIR` and `sources_for_path` filtered the
    /// symlink-only immutable source out. Mutable FolderMountSource always
    /// consults every source, so this only reproduces with `is_immutable()`.
    #[test]
    fn union_immutable_symlink_branch_lookup_not_enont() {
        let d = tempfile::tempdir().unwrap();
        let (branch1, branch2) = build_b4_branches(d.path());

        let s1 =
            Arc::new(ImmFolder(FolderMountSource::new(&branch1).unwrap())) as Arc<dyn MountSource>;
        let s2 =
            Arc::new(ImmFolder(FolderMountSource::new(&branch2).unwrap())) as Arc<dyn MountSource>;

        let opts = UnionMountOptions {
            max_cache_depth: 8,
            max_cache_entries: 1000,
            max_seconds_to_cache: 10.0,
        };

        for (sources, order_label) in [
            (vec![s1.clone(), s2.clone()], "branch1 then branch2"),
            (vec![s2.clone(), s1.clone()], "branch2 then branch1"),
        ] {
            let u = UnionMountSource::new_with_options(sources, opts.clone());
            assert!(
                u.folder_cache_len() >= 2,
                "{order_label}: expected folder cache to be populated"
            );
            assert_b4_union_policy(&u, order_label);

            // file1 lives only on the symlink branch; file2 only on the real-dir branch.
            let fi1 = u
                .lookup("/subdir0/subdir2/file1", 0)
                .unwrap_or_else(|| panic!("{order_label}: file1 lookup must not ENOENT"));
            let mut r = u.open(&fi1, 0).unwrap_or_else(|e| {
                panic!("{order_label}: open file1: {e}");
            });
            let mut body = String::new();
            r.read_to_string(&mut body).unwrap();
            assert_eq!(body, "file1", "{order_label}: file1 content");

            let fi2 = u
                .lookup("/subdir0/subdir2/file2", 0)
                .unwrap_or_else(|| panic!("{order_label}: file2 lookup must not ENOENT"));
            let mut r = u.open(&fi2, 0).unwrap_or_else(|e| {
                panic!("{order_label}: open file2: {e}");
            });
            let mut body = String::new();
            r.read_to_string(&mut body).unwrap();
            assert_eq!(body, "file2", "{order_label}: file2 content");
        }
    }

    #[test]
    fn resolve_symlink_target_helpers() {
        assert_eq!(resolve_symlink_target("/subdir0", "./subdir1"), "/subdir1");
        assert_eq!(resolve_symlink_target("/a/b", "../c"), "/c");
        assert_eq!(resolve_symlink_target("/a/b", "/abs"), "/abs");
        assert_eq!(resolve_symlink_target("/", "x"), "/x");
    }
}
