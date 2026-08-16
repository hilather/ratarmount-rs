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
//!
//! **Optional symlink resolve (FR-10 / mxmlnkn/ratarmount#160):** when
//! [`UnionMountOptions::resolve_symlinks`] is true, after the normal union pick
//! a winning symlink is followed within its **chosen source** (multi-hop, hop
//! cap + cycle detection). Real directories still beat symlinks at version 0
//! (B-4 is not relaxed). Default is false (preserve symlink FileInfo).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::Instant;

use log::warn;
use ratarmount_core::{
    create_root_file_info, is_dir_mode, is_lnk_mode, normpath, CheapDirent, FileInfo,
    ListModeResult, ListResult, MountSource, UserData,
};

use crate::path_intern::PathIntern;

/// Max symlink hops when [`UnionMountOptions::resolve_symlinks`] is enabled.
const MAX_SYMLINK_RESOLVE_HOPS: usize = 8;

/// Options for building the union folder cache (Python `--union-mount-cache-*`)
/// and optional symlink resolution (Rust `--union-resolve-symlinks`).
#[derive(Clone, Debug)]
pub struct UnionMountOptions {
    /// Maximum directory depth to pre-scan (default 1024).
    pub max_cache_depth: usize,
    /// Maximum number of directory paths to cache (default 100_000).
    pub max_cache_entries: usize,
    /// Wall-clock seconds allowed for cache build (default 60).
    pub max_seconds_to_cache: f64,
    /// When true, follow symlink winners within their source after the union
    /// pick (FR-10 / #160). Default false keeps B-4 + one-hop list behavior.
    pub resolve_symlinks: bool,
}

impl Default for UnionMountOptions {
    fn default() -> Self {
        Self {
            max_cache_depth: 1024,
            max_cache_entries: 100_000,
            max_seconds_to_cache: 60.0,
            resolve_symlinks: false,
        }
    }
}

/// Union of mount sources; later sources override earlier ones for the same path.
pub struct UnionMountSource {
    sources: Vec<Arc<dyn MountSource>>,
    /// Interned folder-cache keys (one string per distinct cached path).
    path_intern: PathIntern,
    /// Cached folders: interned path id → which **immutable** sources contain that directory.
    folder_cache: HashMap<u32, Vec<usize>>,
    /// Depth actually cached (0 = only `/` or empty).
    folder_cache_depth: usize,
    /// When true, resolve winning symlinks within the chosen source (FR-10).
    resolve_symlinks: bool,
}

impl UnionMountSource {
    pub fn new(sources: Vec<Arc<dyn MountSource>>) -> Self {
        Self::new_with_options(sources, UnionMountOptions::default())
    }

    pub fn new_with_options(sources: Vec<Arc<dyn MountSource>>, opts: UnionMountOptions) -> Self {
        let mut u = Self {
            sources,
            path_intern: PathIntern::new(),
            folder_cache: HashMap::new(),
            folder_cache_depth: 0,
            resolve_symlinks: opts.resolve_symlinks,
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

    /// Whether this union resolves symlink winners (see [`UnionMountOptions::resolve_symlinks`]).
    pub fn resolve_symlinks(&self) -> bool {
        self.resolve_symlinks
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

    /// Test-only: true when the live folder cache is keyed by interned path ids.
    ///
    /// A `HashMap<String, _>` store would not type-check against this ascription
    /// (the helper would have to be changed to return `false`).
    #[cfg(test)]
    fn folder_cache_uses_path_ids(&self) -> bool {
        let _: &HashMap<u32, Vec<usize>> = &self.folder_cache;
        true
    }

    /// Test-only: whether `path` is present in the interned folder cache.
    #[cfg(test)]
    fn folder_cache_contains(&self, path: &str) -> bool {
        self.path_intern
            .lookup(path)
            .is_some_and(|id| self.folder_cache.contains_key(&id))
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
        let mut folder_cache: HashMap<u32, Vec<usize>> = HashMap::new();
        let root_idxs: Vec<usize> = self
            .sources
            .iter()
            .enumerate()
            .filter(|(_, m)| m.is_immutable())
            .map(|(i, _)| i)
            .collect();
        let intern = &mut self.path_intern;
        let root_id = intern.intern("/");
        folder_cache.insert(root_id, root_idxs);
        let mut last: HashMap<u32, Vec<usize>> = folder_cache.clone();
        let mut depth_done = 0usize;

        for depth in 1..max_cache_depth {
            let mut new_cache: HashMap<u32, Vec<usize>> = HashMap::new();

            for (&folder_id, idxs) in &last {
                let folder = intern.get(folder_id).to_string();
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
                    // List via the same symlink follow as B-4 `list`, so
                    // walk continues into symlink→dir branches (immutable archives).
                    let Some(listing) = Self::list_from_source(
                        self.sources[si].as_ref(),
                        &folder,
                        self.resolve_symlinks,
                    ) else {
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
                        let full = join(&folder, &name);
                        // Cache real directories *and* followable symlink→dir paths.
                        // Previously only S_IFDIR was recorded, so immutable sources
                        // with a symlink branch were dropped from sources_for_path
                        // → lookup/open ENOENT after list still showed their children.
                        if Self::list_from_source(
                            self.sources[si].as_ref(),
                            &full,
                            self.resolve_symlinks,
                        )
                        .is_none()
                        {
                            continue;
                        }
                        entries_left = entries_left.saturating_sub(1);
                        let full_id = intern.intern(&full);
                        new_cache.entry(full_id).or_default().push(si);
                    }
                }
            }

            if new_cache.is_empty() {
                break;
            }
            folder_cache.extend(new_cache.iter().map(|(&k, v)| (k, v.clone())));
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

        let cached: Option<&Vec<usize>> = self
            .path_intern
            .lookup(path)
            .and_then(|id| self.folder_cache.get(&id))
            .or_else(|| {
                // Look up parent at the cached depth (Python: split with maxdepth+1)
                if self.folder_cache_depth > 0 && path.starts_with('/') {
                    let parent = parent_at_depth(path, self.folder_cache_depth);
                    self.path_intern
                        .lookup(&parent)
                        .and_then(|id| self.folder_cache.get(&id))
                } else {
                    None
                }
            });

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

    /// Try `try_list(path)`. If missing, follow a symlink-at-`path` within `src`
    /// (B-4 one hop, or FR-10 cap) and `try_list` each target.
    /// Distinct from FR-10 *child* resolve after merge.
    fn follow_symlink_then<T>(
        src: &dyn MountSource,
        path: &str,
        resolve_symlinks: bool,
        try_list: impl Fn(&str) -> Option<T>,
    ) -> Option<T> {
        if let Some(v) = try_list(path) {
            return Some(v);
        }
        let fi = src.lookup(path, 0)?;
        if !is_lnk_mode(fi.mode) || fi.linkname.is_empty() {
            return None;
        }
        let max_hops = if resolve_symlinks {
            MAX_SYMLINK_RESOLVE_HOPS
        } else {
            1
        };
        let mut current_path = path.to_string();
        let mut current = fi;
        let mut seen = HashSet::new();
        seen.insert(current_path.clone());
        for _ in 0..max_hops {
            if !is_lnk_mode(current.mode) || current.linkname.is_empty() {
                break;
            }
            let target = resolve_symlink_target(&current_path, &current.linkname);
            if !seen.insert(target.clone()) {
                return None; // cycle
            }
            if let Some(v) = try_list(&target) {
                return Some(v);
            }
            current = src.lookup(&target, 0)?;
            current_path = target;
        }
        None
    }

    fn list_from_source(
        src: &dyn MountSource,
        path: &str,
        resolve_symlinks: bool,
    ) -> Option<ListResult> {
        Self::follow_symlink_then(src, path, resolve_symlinks, |p| src.list(p))
    }

    fn list_dirents_from_source(
        src: &dyn MountSource,
        path: &str,
        resolve_symlinks: bool,
    ) -> Option<Vec<CheapDirent>> {
        Self::follow_symlink_then(src, path, resolve_symlinks, |p| src.list_dirents(p))
    }

    /// Later source wins, except a directory is never replaced by a symlink (B-4).
    fn merge_dirent(map: &mut BTreeMap<String, CheapDirent>, d: CheapDirent) {
        if let Some(existing) = map.get(&d.name) {
            if is_dir_mode(existing.mode) && is_lnk_mode(d.mode) {
                return;
            }
        }
        map.insert(d.name.clone(), d);
    }

    fn list_dirents_b4_only(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let path = normpath(path);
        let mut map: BTreeMap<String, CheapDirent> = BTreeMap::new();
        let mut any = false;
        for src in &self.sources {
            if let Some(dents) =
                Self::list_dirents_from_source(src.as_ref(), &path, self.resolve_symlinks)
            {
                any = true;
                for d in dents {
                    Self::merge_dirent(&mut map, d);
                }
            }
        }
        any.then(|| map.into_values().collect())
    }

    /// After a union pick, optionally follow a winning symlink within `src`.
    /// Returns the final non-symlink FileInfo, or None on cycle / hop limit / broken link.
    fn maybe_resolve_winner(
        src: &dyn MountSource,
        path: &str,
        fi: FileInfo,
        resolve_symlinks: bool,
    ) -> Option<FileInfo> {
        if !resolve_symlinks || !is_lnk_mode(fi.mode) {
            return Some(fi);
        }
        Self::resolve_symlink_chain(src, path, fi)
    }

    /// Follow symlink hops within one source; stop at first non-symlink.
    fn resolve_symlink_chain(src: &dyn MountSource, path: &str, fi: FileInfo) -> Option<FileInfo> {
        let mut current_path = path.to_string();
        let mut current = fi;
        let mut seen = HashSet::new();
        seen.insert(current_path.clone());
        for _ in 0..MAX_SYMLINK_RESOLVE_HOPS {
            if !is_lnk_mode(current.mode) {
                return Some(current);
            }
            if current.linkname.is_empty() {
                return None;
            }
            let target = resolve_symlink_target(&current_path, &current.linkname);
            if !seen.insert(target.clone()) {
                return None; // cycle
            }
            current = src.lookup(&target, 0)?;
            current_path = target;
        }
        // Exceeded hop cap while still a symlink (or last hop still link).
        if is_lnk_mode(current.mode) {
            None
        } else {
            Some(current)
        }
    }

    /// Path userdata from a FileInfo (folder sources store the virtual path).
    fn path_from_file_info(file_info: &FileInfo) -> Option<&str> {
        file_info.userdata.iter().rev().find_map(|u| match u {
            UserData::Other(s) if !s.starts_with("union:") => Some(s.as_str()),
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
        // Sources with a real directory *or* a followable symlink at `path` contribute.
        // Children are merged first (B-4 dir>symlink), then optionally resolved so a
        // resolved file cannot clobber a real directory the way a raw symlink cannot.
        for (si, src) in self.sources.iter().enumerate() {
            if let Some(listing) =
                Self::list_from_source(src.as_ref(), &path, self.resolve_symlinks)
            {
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
        if !any {
            return None;
        }
        if self.resolve_symlinks {
            let names: Vec<String> = map.keys().cloned().collect();
            for name in names {
                let Some(fi) = map.get(&name) else {
                    continue;
                };
                if !is_lnk_mode(fi.mode) {
                    continue;
                }
                let Some(si) = self.source_from_info(fi) else {
                    continue;
                };
                let Some(src) = self.sources.get(si) else {
                    continue;
                };
                let child = join(&path, &name);
                // Strip union tag before resolve so chain uses the source FileInfo.
                let mut inner = fi.clone();
                if let Some(UserData::Other(s)) = inner.userdata.last() {
                    if s.starts_with("union:") {
                        inner.userdata.pop();
                    }
                }
                if let Some(resolved) = Self::resolve_symlink_chain(src.as_ref(), &child, inner) {
                    map.insert(name, Self::tag_source(resolved, si));
                }
                // On cycle/hop failure leave the symlink entry.
            }
        }
        Some(ListResult::Infos(map))
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        if self.resolve_symlinks {
            // Opt-in: same post-merge FR-10 resolve as list(); do not invent a
            // second resolve. On the successful-resolve path, sizes come from
            // the resolved FileInfo so TTL 60s is safe (type is REG — kernel
            // will not readlink). Cycle leftovers stay S_IFLNK, matching list().
            return match self.list(path)? {
                ListResult::Infos(map) => Some(
                    map.into_iter()
                        .map(|(name, fi)| CheapDirent {
                            name,
                            mode: fi.mode,
                            size: fi.size,
                        })
                        .collect(),
                ),
                ListResult::Names(names) => Some(
                    names
                        .into_iter()
                        .map(|name| CheapDirent {
                            name,
                            mode: 0,
                            size: 0,
                        })
                        .collect(),
                ),
            };
        }
        self.list_dirents_b4_only(path)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let dents = self.list_dirents(path)?;
        Some(ListModeResult::Modes(
            dents.into_iter().map(|d| (d.name, d.mode)).collect(),
        ))
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
            // resolve_symlinks does not relax this: real dirs still win first.
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
            let (si, fi) = rightmost_dir.or(rightmost_any)?;
            let fi = Self::maybe_resolve_winner(
                self.sources[si].as_ref(),
                &path,
                fi,
                self.resolve_symlinks,
            )?;
            return Some(Self::tag_source(fi, si));
        }

        if file_version < 0 {
            // Negative: walk rightmost first; accumulate versions
            let mut ver = file_version;
            for &si in idxs.iter().rev() {
                let src = &self.sources[si];
                if let Some(fi) = src.lookup(&path, ver) {
                    let fi =
                        Self::maybe_resolve_winner(src.as_ref(), &path, fi, self.resolve_symlinks)?;
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
                    let fi =
                        Self::maybe_resolve_winner(src.as_ref(), &path, fi, self.resolve_symlinks)?;
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
                // FR-10: if still a symlink and resolve is on, follow within source.
                if self.resolve_symlinks && is_lnk_mode(fi.mode) {
                    if let Some(path) = Self::path_from_file_info(&fi) {
                        match Self::resolve_symlink_chain(src.as_ref(), path, fi.clone()) {
                            Some(resolved) => fi = resolved,
                            None => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "union symlink resolve failed (cycle or hop limit)",
                                ));
                            }
                        }
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

    fn content_generation(&self) -> u64 {
        // Generations only increment, so the sum changes whenever any child
        // bumps (a WriteOverlay branch commit must invalidate merged caches).
        self.sources
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.content_generation()))
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        if let Some(si) = self.source_from_info(file_info) {
            if let Some(src) = self.sources.get(si) {
                let mut fi = file_info.clone();
                if let Some(UserData::Other(s)) = fi.userdata.last() {
                    if s.starts_with("union:") {
                        fi.userdata.pop();
                    }
                }
                return src.member_seek_is_cheap(&fi);
            }
        }
        true
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
                ..Default::default()
            },
        );
        assert!(u.folder_cache_len() >= 2, "expected / and /sub cached");
        assert!(u.folder_cache_depth() >= 1);
        assert!(!u.resolve_symlinks());

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
                ..Default::default()
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
            ..Default::default()
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

    /// FR-10 residual / upstream #160: with `resolve_symlinks`, a winning symlink
    /// is followed within its source so lookup returns the target file/dir and
    /// open reads target content. Default (false) keeps the symlink FileInfo.
    #[test]
    fn fr10_resolve_symlinks_follows_symlink_to_file() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        fs::create_dir_all(&a).unwrap();
        fs::write(a.join("target.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("target.txt", a.join("link.txt")).unwrap();

        let sa = Arc::new(FolderMountSource::new(&a).unwrap()) as Arc<dyn MountSource>;

        // Default: lookup returns a symlink; open via resolved path still needs follow.
        let u_default = UnionMountSource::new(vec![sa.clone()]);
        let fi_link = u_default.lookup("/link.txt", 0).expect("link");
        assert!(
            is_lnk_mode(fi_link.mode),
            "default must preserve symlink (mode={:#o})",
            fi_link.mode
        );
        assert_eq!(fi_link.linkname, "target.txt");

        let u_resolve = UnionMountSource::new_with_options(
            vec![sa],
            UnionMountOptions {
                resolve_symlinks: true,
                ..Default::default()
            },
        );
        assert!(u_resolve.resolve_symlinks());
        let fi = u_resolve
            .lookup("/link.txt", 0)
            .expect("Regression: FR-10 resolve must follow symlink to file");
        assert!(
            !is_lnk_mode(fi.mode),
            "resolve=true lookup must return target file, not symlink (mode={:#o})",
            fi.mode
        );
        let mut r = u_resolve.open(&fi, 0).expect("open resolved file");
        let mut body = String::new();
        r.read_to_string(&mut body).unwrap();
        assert_eq!(body, "payload");
    }

    /// FR-10: multi-hop symlink chain resolves to the final file.
    #[test]
    fn fr10_resolve_symlinks_multi_hop_to_file() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        fs::create_dir_all(&a).unwrap();
        fs::write(a.join("real.txt"), b"hop-payload").unwrap();
        std::os::unix::fs::symlink("real.txt", a.join("mid")).unwrap();
        std::os::unix::fs::symlink("mid", a.join("outer")).unwrap();

        let sa = Arc::new(FolderMountSource::new(&a).unwrap()) as Arc<dyn MountSource>;
        let u = UnionMountSource::new_with_options(
            vec![sa],
            UnionMountOptions {
                resolve_symlinks: true,
                ..Default::default()
            },
        );
        let fi = u
            .lookup("/outer", 0)
            .expect("Regression: multi-hop symlink resolve");
        assert!(!is_lnk_mode(fi.mode));
        let mut r = u.open(&fi, 0).unwrap();
        let mut body = String::new();
        r.read_to_string(&mut body).unwrap();
        assert_eq!(body, "hop-payload");
    }

    /// FR-10: symlink→dir becomes a directory for lookup when resolve is on.
    #[test]
    fn fr10_resolve_symlinks_symlink_to_dir() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        fs::create_dir_all(a.join("realdir")).unwrap();
        fs::write(a.join("realdir/child"), b"c").unwrap();
        std::os::unix::fs::symlink("realdir", a.join("alias")).unwrap();

        let sa = Arc::new(FolderMountSource::new(&a).unwrap()) as Arc<dyn MountSource>;
        let u = UnionMountSource::new_with_options(
            vec![sa],
            UnionMountOptions {
                resolve_symlinks: true,
                ..Default::default()
            },
        );
        let fi = u.lookup("/alias", 0).expect("alias");
        assert!(
            is_dir_mode(fi.mode),
            "resolve=true: symlink→dir must present as directory"
        );
        assert!(!is_lnk_mode(fi.mode));
        let listing = u.list("/alias").expect("list through resolved dir");
        let ListResult::Infos(map) = listing else {
            panic!("expected Infos");
        };
        assert!(map.contains_key("child"));
    }

    /// FR-10: B-4 still holds with resolve_symlinks — real directory wins over
    /// symlink at the same path for version 0; resolve does not prefer the link.
    #[test]
    fn fr10_resolve_still_prefers_real_dir_over_symlink() {
        let d = tempfile::tempdir().unwrap();
        let (branch1, branch2) = build_b4_branches(d.path());
        let s1 = Arc::new(FolderMountSource::new(&branch1).unwrap()) as Arc<dyn MountSource>;
        let s2 = Arc::new(FolderMountSource::new(&branch2).unwrap()) as Arc<dyn MountSource>;
        let opts = UnionMountOptions {
            resolve_symlinks: true,
            ..Default::default()
        };
        // Symlink branch rightmost — without B-4 this would resolve to subdir1.
        let u = UnionMountSource::new_with_options(vec![s2, s1], opts);
        assert_b4_union_policy(&u, "resolve=true branch2 then branch1");
        let subdir0 = u.lookup("/subdir0", 0).unwrap();
        assert!(is_dir_mode(subdir0.mode) && !is_lnk_mode(subdir0.mode));
    }

    /// FR-10: cycle / excessive hops → lookup None (no hang).
    #[test]
    fn fr10_resolve_symlink_cycle_returns_none() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        fs::create_dir_all(&a).unwrap();
        std::os::unix::fs::symlink("b", a.join("a_link")).unwrap();
        std::os::unix::fs::symlink("a_link", a.join("b")).unwrap();

        let sa = Arc::new(FolderMountSource::new(&a).unwrap()) as Arc<dyn MountSource>;
        let u = UnionMountSource::new_with_options(
            vec![sa],
            UnionMountOptions {
                resolve_symlinks: true,
                ..Default::default()
            },
        );
        assert!(
            u.lookup("/a_link", 0).is_none(),
            "Regression: FR-10 cycle must not hang; lookup returns None"
        );
        assert!(u.lookup("/b", 0).is_none());
    }

    /// FR-10: hop cap — long chain beyond MAX_SYMLINK_RESOLVE_HOPS → None.
    #[test]
    fn fr10_resolve_symlink_hop_limit() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        fs::create_dir_all(&a).unwrap();
        // chain_0 → chain_1 → … → chain_N → final (N+1 hops to file; exceed cap)
        let hops = MAX_SYMLINK_RESOLVE_HOPS + 2;
        fs::write(a.join("final"), b"too-deep").unwrap();
        std::os::unix::fs::symlink("final", a.join(format!("chain_{hops}"))).unwrap();
        for i in (0..hops).rev() {
            std::os::unix::fs::symlink(format!("chain_{}", i + 1), a.join(format!("chain_{i}")))
                .unwrap();
        }

        let sa = Arc::new(FolderMountSource::new(&a).unwrap()) as Arc<dyn MountSource>;
        let u = UnionMountSource::new_with_options(
            vec![sa],
            UnionMountOptions {
                resolve_symlinks: true,
                ..Default::default()
            },
        );
        assert!(
            u.lookup("/chain_0", 0).is_none(),
            "Regression: FR-10 hop limit must yield None without hang"
        );
    }

    /// Immutable in-memory tree for interned folder-cache tests.
    struct SynthTree {
        dirs: HashSet<String>,
        files: HashMap<String, Vec<u8>>,
    }

    impl SynthTree {
        fn with_dirs_and_files(dir_list: &[&str], file_list: &[(&str, &[u8])]) -> Self {
            let mut dirs = HashSet::new();
            dirs.insert("/".into());
            for d in dir_list {
                insert_dir_and_ancestors(&mut dirs, d);
            }
            let mut files = HashMap::new();
            for (p, body) in file_list {
                let p = normpath(p);
                if let Some(i) = p.rfind('/') {
                    let parent = if i == 0 { "/" } else { &p[..i] };
                    insert_dir_and_ancestors(&mut dirs, parent);
                }
                files.insert(p, body.to_vec());
            }
            Self { dirs, files }
        }
    }

    fn insert_dir_and_ancestors(dirs: &mut HashSet<String>, path: &str) {
        let path = normpath(path);
        dirs.insert("/".into());
        if path == "/" {
            return;
        }
        let mut acc = String::new();
        for part in path.trim_start_matches('/').split('/') {
            acc.push('/');
            acc.push_str(part);
            dirs.insert(acc.clone());
        }
    }

    fn synth_dir_info(path: &str) -> FileInfo {
        FileInfo {
            size: 0,
            mtime: 0.0,
            mode: ratarmount_core::S_IFDIR | 0o755,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Other(path.to_string())],
        }
    }

    fn synth_file_info(path: &str, size: u64) -> FileInfo {
        FileInfo {
            size,
            mtime: 0.0,
            mode: ratarmount_core::S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Other(path.to_string())],
        }
    }

    impl MountSource for SynthTree {
        fn list(&self, path: &str) -> Option<ListResult> {
            let path = normpath(path);
            if !self.dirs.contains(&path) {
                return None;
            }
            let prefix = if path == "/" {
                "/".to_string()
            } else {
                format!("{path}/")
            };
            let mut map = BTreeMap::new();
            for d in &self.dirs {
                if let Some(rest) = d.strip_prefix(&prefix) {
                    if !rest.is_empty() && !rest.contains('/') {
                        map.insert(rest.to_string(), synth_dir_info(d));
                    }
                }
            }
            for (f, body) in &self.files {
                if let Some(rest) = f.strip_prefix(&prefix) {
                    if !rest.is_empty() && !rest.contains('/') {
                        map.insert(rest.to_string(), synth_file_info(f, body.len() as u64));
                    }
                }
            }
            Some(ListResult::Infos(map))
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            let path = normpath(path);
            if self.dirs.contains(&path) {
                return Some(synth_dir_info(&path));
            }
            self.files
                .get(&path)
                .map(|body| synth_file_info(&path, body.len() as u64))
        }

        fn open(&self, fi: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            let path = fi
                .userdata
                .iter()
                .rev()
                .find_map(|u| match u {
                    UserData::Other(s) if s.starts_with('/') => Some(s.as_str()),
                    _ => None,
                })
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
            let body = self.files.get(path).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("synth file {path}"))
            })?;
            Ok(Box::new(std::io::Cursor::new(body.clone())))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: interned union folder-cache keys.
    ///
    /// Symptom: deep unions stored one owned `String` per cached folder (duplicated
    /// long prefixes). The live cache is keyed by interned path ids.
    #[test]
    fn interned_union_folder_cache_keys() {
        let mut sibs: Vec<String> = (0..8).map(|i| format!("/l1/l2/l3/sib{i}")).collect();
        sibs.push("/l1/l2/l3/l4/l5".into());
        let sib_refs: Vec<&str> = sibs.iter().map(|s| s.as_str()).collect();

        let a = Arc::new(SynthTree::with_dirs_and_files(
            &["/l1/l2/l3/l4/l5"],
            &[("/l1/l2/l3/l4/l5/file_a", b"from-a")],
        )) as Arc<dyn MountSource>;
        let b = Arc::new(SynthTree::with_dirs_and_files(
            &sib_refs,
            &[("/l1/l2/l3/l4/l5/file_b", b"from-b")],
        )) as Arc<dyn MountSource>;

        let u = UnionMountSource::new_with_options(
            vec![a, b],
            UnionMountOptions {
                max_cache_depth: 16,
                max_cache_entries: 10_000,
                max_seconds_to_cache: 10.0,
                ..Default::default()
            },
        );

        assert!(
            u.folder_cache_uses_path_ids(),
            "Regression: folder_cache must be keyed by interned path ids, not String"
        );
        assert!(
            u.folder_cache_len() >= 2,
            "expected / and children cached; len={}",
            u.folder_cache_len()
        );
        assert!(u.folder_cache_contains("/"), "root must be cached");
        assert!(u.folder_cache_contains("/l1"));
        assert!(u.folder_cache_contains("/l1/l2"));
        assert!(u.folder_cache_contains("/l1/l2/l3"));
        assert!(u.folder_cache_contains("/l1/l2/l3/l4"));
        assert!(u.folder_cache_contains("/l1/l2/l3/l4/l5"));
        for i in 0..8 {
            assert!(
                u.folder_cache_contains(&format!("/l1/l2/l3/sib{i}")),
                "sibling sib{i} must be cached"
            );
        }

        let listing = u.list("/l1/l2/l3").expect("list deep dir");
        let ListResult::Infos(map) = listing else {
            panic!("expected Infos");
        };
        assert!(map.contains_key("l4"));
        assert!(map.contains_key("sib0"));
        assert!(map.contains_key("sib7"));

        let modes = u.list_mode("/l1/l2/l3").expect("list_mode");
        let ListModeResult::Modes(modes) = modes else {
            panic!("expected Modes");
        };
        assert!(is_dir_mode(*modes.get("l4").expect("l4 mode")));
        assert!(is_dir_mode(*modes.get("sib3").expect("sib3 mode")));

        let fi_a = u.lookup("/l1/l2/l3/l4/l5/file_a", 0).expect("file_a");
        let mut body = String::new();
        u.open(&fi_a, 0).unwrap().read_to_string(&mut body).unwrap();
        assert_eq!(body, "from-a");

        let fi_b = u.lookup("/l1/l2/l3/l4/l5/file_b", 0).expect("file_b");
        let mut body = String::new();
        u.open(&fi_b, 0).unwrap().read_to_string(&mut body).unwrap();
        assert_eq!(body, "from-b");

        let leaf = u.lookup("/l1/l2/l3/l4/l5", 0).expect("leaf dir");
        assert!(is_dir_mode(leaf.mode));
    }

    /// Counts `list()` so we can prove Union uses `list_dirents` on the default path.
    struct ListCallCounter {
        inner: Arc<dyn MountSource>,
        list_calls: std::sync::atomic::AtomicUsize,
    }

    impl MountSource for ListCallCounter {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.list_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

    fn counted_folder(path: &std::path::Path) -> Arc<ListCallCounter> {
        Arc::new(ListCallCounter {
            inner: Arc::new(FolderMountSource::new(path).unwrap()) as Arc<dyn MountSource>,
            list_calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Regression: 2-folder union readdir called `list()` on the default path.
    #[test]
    fn union_list_dirents_merges_inner_dirents_without_list() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        let a_body = b"from-a-payload\n";
        let b_body = b"from-b-longer-bytes\n";
        let only_a = b"only-a\n";
        fs::write(a.join("x.txt"), a_body).unwrap();
        fs::write(a.join("only-a.txt"), only_a).unwrap();
        fs::write(b.join("x.txt"), b_body).unwrap();

        let ca = counted_folder(&a);
        let cb = counted_folder(&b);
        let u = UnionMountSource::new(vec![
            Arc::clone(&ca) as Arc<dyn MountSource>,
            Arc::clone(&cb) as Arc<dyn MountSource>,
        ]);

        let dents = u.list_dirents("/").expect("union dirents");
        assert_eq!(
            ca.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "default union list_dirents must not call list() on source a"
        );
        assert_eq!(
            cb.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "default union list_dirents must not call list() on source b"
        );
        let by_name: BTreeMap<_, _> = dents.into_iter().map(|d| (d.name, d.size)).collect();
        assert_eq!(by_name.get("x.txt").copied(), Some(b_body.len() as u64));
        assert_eq!(
            by_name.get("only-a.txt").copied(),
            Some(only_a.len() as u64)
        );
    }

    /// Regression: `list_dirents` showed symlink at `/subdir0`, or
    /// `/subdir0/subdir2` missing `file1`/`file2`.
    #[test]
    fn union_list_dirents_b4_dir_wins_and_merges_children() {
        let d = tempfile::tempdir().unwrap();
        let (branch1, branch2) = build_b4_branches(d.path());

        for (left, right, order_label) in [
            (branch1.as_path(), branch2.as_path(), "branch1 then branch2"),
            (branch2.as_path(), branch1.as_path(), "branch2 then branch1"),
        ] {
            let c1 = counted_folder(left);
            let c2 = counted_folder(right);
            let u = UnionMountSource::new(vec![
                Arc::clone(&c1) as Arc<dyn MountSource>,
                Arc::clone(&c2) as Arc<dyn MountSource>,
            ]);

            let root = u
                .list_dirents("/")
                .unwrap_or_else(|| panic!("{order_label}: list_dirents /"));
            let root_s0 = root
                .iter()
                .find(|d| d.name == "subdir0")
                .unwrap_or_else(|| panic!("{order_label}: dirents missing subdir0"));
            assert!(
                is_dir_mode(root_s0.mode),
                "{order_label}: listed subdir0 must be directory (mode={:#o})",
                root_s0.mode
            );
            assert!(
                !is_lnk_mode(root_s0.mode),
                "{order_label}: listed subdir0 must not be a symlink"
            );

            let sub = u.list_dirents("/subdir0/subdir2").unwrap_or_else(|| {
                panic!("{order_label}: list_dirents /subdir0/subdir2");
            });
            let names: HashSet<&str> = sub.iter().map(|d| d.name.as_str()).collect();
            assert!(
                names.contains("file1"),
                "{order_label}: /subdir0/subdir2 must contain file1 (one-hop follow); got {names:?}"
            );
            assert!(
                names.contains("file2"),
                "{order_label}: /subdir0/subdir2 must contain file2 (real dir); got {names:?}"
            );
            assert_eq!(
                c1.list_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{order_label}: B-4 list_dirents must not call list()"
            );
            assert_eq!(
                c2.list_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{order_label}: B-4 list_dirents must not call list()"
            );
            assert_b4_union_policy(&u, order_label);
        }
    }

    /// Regression: FR-10 `list_dirents` advertised `S_IFLNK` while `list()`/`lookup`
    /// are `S_IFREG` on the successful-resolve (symlink→file) fixture.
    #[test]
    fn union_list_dirents_resolve_symlinks_modes_match_list() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        fs::create_dir_all(&a).unwrap();
        let payload = b"payload";
        fs::write(a.join("target.txt"), payload).unwrap();
        std::os::unix::fs::symlink("target.txt", a.join("link.txt")).unwrap();

        let sa = Arc::new(FolderMountSource::new(&a).unwrap()) as Arc<dyn MountSource>;
        let u = UnionMountSource::new_with_options(
            vec![sa],
            UnionMountOptions {
                resolve_symlinks: true,
                ..Default::default()
            },
        );

        let ListResult::Infos(list_map) = u.list("/").expect("list /") else {
            panic!("expected Infos");
        };
        let list_link = list_map.get("link.txt").expect("list has link.txt");
        assert!(
            !is_lnk_mode(list_link.mode),
            "list() must resolve symlink→file to regular (mode={:#o})",
            list_link.mode
        );
        assert_eq!(
            list_link.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFREG
        );
        assert_eq!(list_link.size, payload.len() as u64);

        let dents = u.list_dirents("/").expect("dirents /");
        let dent = dents
            .iter()
            .find(|d| d.name == "link.txt")
            .expect("dirents has link.txt");
        assert_eq!(
            dent.mode, list_link.mode,
            "Regression: FR-10 list_dirents mode must match list()"
        );
        assert_eq!(dent.size, list_link.size);
        assert_eq!(
            dent.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFREG
        );

        let looked = u.lookup("/link.txt", 0).expect("lookup resolved file");
        assert_eq!(
            looked.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFREG,
            "successful-resolve lookup is a regular file"
        );
        assert_eq!(looked.mode, dent.mode);
    }

    /// Flag off: child stays `S_IFLNK`, `list()` not called.
    #[test]
    fn union_list_dirents_default_keeps_symlink_without_list() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        fs::create_dir_all(&a).unwrap();
        fs::write(a.join("target.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("target.txt", a.join("link.txt")).unwrap();

        let counted = counted_folder(&a);
        let u = UnionMountSource::new(vec![Arc::clone(&counted) as Arc<dyn MountSource>]);

        let dents = u.list_dirents("/").expect("dirents /");
        assert_eq!(
            counted.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "default list_dirents must not call list()"
        );
        let dent = dents
            .iter()
            .find(|d| d.name == "link.txt")
            .expect("dirents has link.txt");
        assert!(
            is_lnk_mode(dent.mode),
            "flag off: winning symlink must stay S_IFLNK (mode={:#o})",
            dent.mode
        );
        let fi = u.lookup("/link.txt", 0).expect("lookup");
        assert!(is_lnk_mode(fi.mode));
    }
}
