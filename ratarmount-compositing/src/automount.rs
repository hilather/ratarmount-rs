//! Automatically mount nested archives as directories (Python `AutoMountLayer`).
//!
//! * **Eager** (default): scan the tree at construction and mount all archives.
//! * **Lazy** (`-l`): mount a nested archive on first `list`/`lookup` of that path.
//! * **Strip extension**: mount `foo.tar` at `foo/` instead of `foo.tar/`.
//! * **Transform**: apply a regex replace to the mount point path.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use log::debug;
use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};
use regex::Regex;
use tempfile::NamedTempFile;

/// Open a nested archive from a filesystem path into a MountSource.
pub type OpenNestedFn = Arc<dyn Fn(&Path) -> io::Result<Arc<dyn MountSource>> + Send + Sync>;

const TAG_PREFIX: &str = "automount:";

/// Options controlling nested mount point naming and eagerness.
#[derive(Clone, Debug, Default)]
pub struct AutoMountOptions {
    /// Mount on first access instead of scanning the whole tree up front.
    pub lazy: bool,
    /// Mount `archive.tar` at `archive/` (strip last archive-like extension).
    pub strip_recursive_extension: bool,
    /// `(pattern, replacement)` applied to the full archive path for the mount point.
    pub transform: Option<(String, String)>,
    /// Which suffixes trigger recursive mounting (Python `--recursive-extensions`).
    pub recursive_extensions: RecursiveExtSet,
}

/// Configured set of filename suffixes for recursive automount.
#[derive(Clone, Debug)]
pub struct RecursiveExtSet {
    /// Lowercase suffixes including leading `.` (e.g. `.tar`, `.tar.gz`).
    pub suffixes: Vec<String>,
    /// When true, any non-empty filename is considered (Python `*`).
    pub match_all: bool,
}

impl Default for RecursiveExtSet {
    fn default() -> Self {
        parse_recursive_extensions("/archive,/compressed,/disk,/split")
    }
}

/// Parse Python-style recursive extension selection.
///
/// Supports tokens: `/archive`, `/compressed`, `/disk`, `/document`, `/multimedia`,
/// `/binary`, `/split`, `/all`, bare globs like `.tar`, `.gz*`, and `*` for all files.
pub fn parse_recursive_extensions(spec: &str) -> RecursiveExtSet {
    let mut suffixes = Vec::new();
    let mut match_all = false;
    for raw in spec.split(',') {
        let tok = raw.trim();
        if tok.is_empty() {
            continue;
        }
        let lower = tok.to_ascii_lowercase();
        match lower.as_str() {
            "*" | "/*" => match_all = true,
            "/all" => {
                suffixes.extend(set_archive());
                suffixes.extend(set_compressed());
                suffixes.extend(set_disk());
                suffixes.extend(set_document());
                suffixes.extend(set_multimedia());
                suffixes.extend(set_binary());
                suffixes.extend(set_split());
            }
            "/archive" => suffixes.extend(set_archive()),
            "/compressed" => suffixes.extend(set_compressed()),
            "/disk" => suffixes.extend(set_disk()),
            "/document" => suffixes.extend(set_document()),
            "/multimedia" => suffixes.extend(set_multimedia()),
            "/binary" => suffixes.extend(set_binary()),
            "/split" => suffixes.extend(set_split()),
            s if s.starts_with('.') => {
                // `.gz*` → treat as prefix of suffix `.gz`
                let s = s.trim_end_matches('*');
                suffixes.push(s.to_string());
            }
            s => {
                // bare token without leading dot
                if s.starts_with('/') {
                    // unknown set: ignore
                } else {
                    suffixes.push(format!(".{s}"));
                }
            }
        }
    }
    // de-dup
    suffixes.sort();
    suffixes.dedup();
    if suffixes.is_empty() && !match_all {
        return RecursiveExtSet::default();
    }
    RecursiveExtSet {
        suffixes,
        match_all,
    }
}

fn set_archive() -> Vec<String> {
    [
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
        ".tbz2",
        ".tbz",
        ".tar.xz",
        ".txz",
        ".tar.zst",
        ".tar.zstd",
        ".tzst",
        ".zip",
        ".jar",
        ".7z",
        ".rar",
        ".cab",
        ".ar",
        ".a",
        ".cpio",
        ".sqlar",
        ".squashfs",
        ".asar",
        ".xar",
        ".warc",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
fn set_compressed() -> Vec<String> {
    [
        ".gz", ".bz2", ".xz", ".zst", ".zstd", ".lz4", ".lzip", ".lz", ".lzo", ".z", ".lzma",
        ".zlib",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
fn set_disk() -> Vec<String> {
    [
        ".iso", ".img", ".ext4", ".ext3", ".ext2", ".fat", ".fat12", ".fat16", ".fat32", ".vfat",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
fn set_document() -> Vec<String> {
    [".pdf", ".html", ".htm"]
        .into_iter()
        .map(str::to_string)
        .collect()
}
fn set_multimedia() -> Vec<String> {
    [".ogg", ".oga", ".ogv", ".ogm"]
        .into_iter()
        .map(str::to_string)
        .collect()
}
fn set_binary() -> Vec<String> {
    [".appimage", ".deb", ".apk", ".jar"]
        .into_iter()
        .map(str::to_string)
        .collect()
}
fn set_split() -> Vec<String> {
    // common split suffixes 001..099
    (1..100).map(|i| format!(".{i:03}")).collect()
}

/// Returns true if `name` looks like a mountable nested archive (default extension set).
pub fn is_archive_filename(name: &str) -> bool {
    is_archive_filename_with(name, &RecursiveExtSet::default())
}

/// Returns true if `name` matches the configured recursive extension set.
pub fn is_archive_filename_with(name: &str, set: &RecursiveExtSet) -> bool {
    if set.match_all {
        return !name.is_empty() && name != "." && name != "..";
    }
    let l = name.to_ascii_lowercase();
    set.suffixes.iter().any(|suf| l.ends_with(suf.as_str()))
}

/// Strip a known archive/compression extension for mount-point display.
pub fn strip_archive_extension(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for suf in [
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tar.zst",
        ".tar.zstd",
        ".tar",
        ".tgz",
        ".tbz2",
        ".tbz",
        ".txz",
        ".tzst",
        ".zip",
        ".jar",
        ".7z",
        ".rar",
        ".iso",
        ".cab",
        ".ar",
        ".a",
        ".cpio",
        ".sqlar",
        ".squashfs",
        ".gz",
        ".bz2",
        ".xz",
        ".zst",
    ] {
        if lower.ends_with(suf) && name.len() > suf.len() {
            return name[..name.len() - suf.len()].to_string();
        }
    }
    name.to_string()
}

struct NestedMount {
    source: Arc<dyn MountSource>,
    _persist: PathBuf,
    depth: u32,
}

/// Wraps a mount source and exposes nested archives as subfolders.
pub struct AutoMountLayer {
    root: Arc<dyn MountSource>,
    mounted: Mutex<HashMap<String, NestedMount>>,
    max_depth: u32,
    open_nested: OpenNestedFn,
    lazy: bool,
    strip_ext: bool,
    ext_set: RecursiveExtSet,
    transform: Option<(Regex, String)>,
}

impl AutoMountLayer {
    /// Eagerly scan and mount all nested archives (default).
    pub fn new(root: Arc<dyn MountSource>, max_depth: u32, open_nested: OpenNestedFn) -> Self {
        Self::new_with_options(root, max_depth, open_nested, AutoMountOptions::default())
    }

    /// When `lazy` is true, nested archives mount on first access (Python `-l` / `--lazy`).
    pub fn new_with_lazy(
        root: Arc<dyn MountSource>,
        max_depth: u32,
        open_nested: OpenNestedFn,
        lazy: bool,
    ) -> Self {
        Self::new_with_options(
            root,
            max_depth,
            open_nested,
            AutoMountOptions {
                lazy,
                ..Default::default()
            },
        )
    }

    pub fn new_with_options(
        root: Arc<dyn MountSource>,
        max_depth: u32,
        open_nested: OpenNestedFn,
        opts: AutoMountOptions,
    ) -> Self {
        let transform = opts
            .transform
            .and_then(|(pat, rep)| Regex::new(&pat).ok().map(|re| (re, rep)));
        let layer = Self {
            root,
            mounted: Mutex::new(HashMap::new()),
            max_depth: if max_depth == 0 { 32 } else { max_depth },
            open_nested,
            lazy: opts.lazy,
            strip_ext: opts.strip_recursive_extension,
            ext_set: opts.recursive_extensions,
            transform,
        };
        if !opts.lazy {
            layer.scan_and_mount();
        }
        layer
    }

    fn scan_and_mount(&self) {
        let mut folders = vec!["/".to_string()];
        while let Some(folder) = folders.pop() {
            let depth = self.depth_at(&folder);
            if depth >= self.max_depth {
                continue;
            }
            let Some(names) = self.list_names_no_lazy(&folder) else {
                continue;
            };
            for name in names {
                let full = join(&folder, &name);
                if self.is_dir_raw(&full) {
                    folders.push(full);
                    continue;
                }
                if is_archive_filename_with(&name, &self.ext_set) {
                    if let Some(mp) = self.try_mount_file(&full, depth + 1) {
                        debug!("automounted {full} -> {mp}");
                        folders.push(mp);
                    }
                }
            }
        }
    }

    fn depth_at(&self, path: &str) -> u32 {
        let mounted = self.mounted.lock().expect("automount mutex");
        let (mp, _) = Self::find_mounted_in(&mounted, path);
        if mp == "/" {
            0
        } else {
            mounted.get(mp).map(|m| m.depth).unwrap_or(0)
        }
    }

    fn list_names_no_lazy(&self, path: &str) -> Option<Vec<String>> {
        let mounted = self.mounted.lock().expect("automount mutex");
        let (mp, rest) = Self::find_mounted_in(&mounted, path);
        let src = Self::source_at_locked(&self.root, &mounted, mp);
        match src.list(&rest)? {
            ListResult::Infos(m) => Some(m.into_keys().collect()),
            ListResult::Names(n) => Some(n),
        }
    }

    fn is_dir_raw(&self, path: &str) -> bool {
        {
            let mounted = self.mounted.lock().expect("automount mutex");
            if mounted.contains_key(path) {
                return true;
            }
        }
        self.lookup_raw(path)
            .map(|fi| fi.mode & libc::S_IFMT == libc::S_IFDIR)
            .unwrap_or(false)
    }

    fn lookup_raw(&self, path: &str) -> Option<FileInfo> {
        let mounted = self.mounted.lock().expect("automount mutex");
        let (mp, rest) = Self::find_mounted_in(&mounted, path);
        Self::source_at_locked(&self.root, &mounted, mp).lookup(&rest, 0)
    }

    fn source_at_locked(
        root: &Arc<dyn MountSource>,
        mounted: &HashMap<String, NestedMount>,
        mount_point: &str,
    ) -> Arc<dyn MountSource> {
        if mount_point == "/" {
            Arc::clone(root)
        } else {
            mounted
                .get(mount_point)
                .map(|m| Arc::clone(&m.source))
                .unwrap_or_else(|| Arc::clone(root))
        }
    }

    fn find_mounted_in<'a>(
        mounted: &'a HashMap<String, NestedMount>,
        path: &str,
    ) -> (&'a str, String) {
        let path = normpath(path);
        if path == "/" {
            return ("/", "/".into());
        }
        let mut best: &str = "/";
        for mp in mounted.keys() {
            if (path == mp.as_str() || path.starts_with(&(mp.clone() + "/")))
                && mp.len() > best.len()
            {
                best = mp.as_str();
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

    /// Compute mount point path for an archive file path.
    fn mount_point_for(&self, archive_path: &str) -> String {
        let mut mp = archive_path.to_string();
        if self.strip_ext {
            let name = Path::new(archive_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(archive_path);
            let stripped = strip_archive_extension(name);
            if stripped != name {
                if let Some(parent) = Path::new(archive_path).parent() {
                    let parent_s = parent.to_string_lossy();
                    mp = if parent_s == "/" || parent_s.is_empty() {
                        format!("/{stripped}")
                    } else {
                        format!("{parent_s}/{stripped}")
                    };
                } else {
                    mp = format!("/{stripped}");
                }
            }
        }
        if let Some((re, rep)) = &self.transform {
            let replaced = re.replace_all(archive_path, rep.as_str());
            if !replaced.is_empty() {
                mp = if replaced.starts_with('/') {
                    replaced.into_owned()
                } else {
                    format!("/{replaced}")
                };
            }
        }
        normpath(&mp)
    }

    /// Try to mount archive at `path`. Returns mount point on success.
    fn try_mount_file(&self, path: &str, depth: u32) -> Option<String> {
        let mount_point = self.mount_point_for(path);
        {
            let mounted = self.mounted.lock().expect("automount mutex");
            if mounted.contains_key(&mount_point) || mounted.contains_key(path) {
                return Some(if mounted.contains_key(&mount_point) {
                    mount_point
                } else {
                    path.to_string()
                });
            }
        }

        let fi = self.lookup_raw(path)?;
        if fi.mode & libc::S_IFMT == libc::S_IFDIR {
            return None;
        }

        let (mp, rest) = {
            let mounted = self.mounted.lock().expect("automount mutex");
            let (m, r) = Self::find_mounted_in(&mounted, path);
            (m.to_string(), r)
        };
        let parent = {
            let mounted = self.mounted.lock().expect("automount mutex");
            Self::source_at_locked(&self.root, &mounted, &mp)
        };
        let fi = parent.lookup(&rest, 0)?;
        let mut reader = parent.open(&fi, 0).ok()?;
        let mut tmp = NamedTempFile::new().ok()?;
        io::copy(&mut reader, &mut tmp).ok()?;
        let _ = tmp.flush();
        let tmp_path = tmp.into_temp_path();
        let persist = tmp_path.keep().ok()?;
        let nested = match (self.open_nested)(&persist) {
            Ok(s) => s,
            Err(e) => {
                debug!("failed to open nested {}: {e}", persist.display());
                let _ = std::fs::remove_file(&persist);
                return None;
            }
        };

        let mut mounted = self.mounted.lock().expect("automount mutex");
        // Prefer computed mount_point; if collision with existing non-archive dir, fall back to path.
        let key = if mounted.contains_key(&mount_point) && mount_point != path {
            path.to_string()
        } else {
            mount_point
        };
        mounted.insert(
            key.clone(),
            NestedMount {
                source: nested,
                _persist: persist,
                depth,
            },
        );
        Some(key)
    }

    /// For lazy mode: if `path` is an unmounted archive file, mount it.
    fn ensure_lazy_mount(&self, path: &str) {
        if !self.lazy {
            return;
        }
        let path = normpath(path);
        if path == "/" {
            return;
        }
        {
            let mounted = self.mounted.lock().expect("automount mutex");
            if mounted.contains_key(&path) {
                return;
            }
            // Also check if any parent path is already a mount and path is inside it.
        }
        let name = Path::new(&path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !is_archive_filename_with(name, &self.ext_set) {
            // Path might be inside an unmounted archive: try each path prefix that is an archive.
            let mut prefix = path.clone();
            while let Some(idx) = prefix.rfind('/') {
                if idx == 0 {
                    break;
                }
                let cand = &prefix[..=idx.min(prefix.len() - 1)];
                let _ = cand;
                // walk parents
                let parent = &prefix[..idx];
                let pname = Path::new(parent)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if is_archive_filename_with(pname, &self.ext_set) {
                    let depth = self.depth_at(parent);
                    if depth < self.max_depth {
                        self.try_mount_file(parent, depth + 1);
                    }
                }
                prefix = parent.to_string();
                if prefix.is_empty() || prefix == "/" {
                    break;
                }
            }
            return;
        }
        let depth = self.depth_at(&path);
        if depth >= self.max_depth {
            return;
        }
        // Parent depth
        let parent = Path::new(&path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/".into());
        let parent = if parent.is_empty() {
            "/".to_string()
        } else {
            parent
        };
        let depth = self.depth_at(&parent);
        if depth < self.max_depth {
            self.try_mount_file(&path, depth + 1);
        }
    }

    /// Lazy: when listing a directory, mount archive children so they appear as dirs.
    fn ensure_lazy_children(&self, path: &str) {
        if !self.lazy {
            return;
        }
        let depth = self.depth_at(path);
        if depth >= self.max_depth {
            return;
        }
        let Some(names) = self.list_names_no_lazy(path) else {
            return;
        };
        for name in names {
            if is_archive_filename_with(&name, &self.ext_set) {
                let full = join(path, &name);
                self.try_mount_file(&full, depth + 1);
            }
        }
    }

    fn tag(mut fi: FileInfo, mount_point: &str) -> FileInfo {
        fi.userdata
            .push(UserData::Other(format!("{TAG_PREFIX}{mount_point}")));
        fi
    }

    fn tag_map(
        map: std::collections::BTreeMap<String, FileInfo>,
        mp: &str,
    ) -> std::collections::BTreeMap<String, FileInfo> {
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
        self.ensure_lazy_mount(&path);
        self.ensure_lazy_children(&path);

        let mounted = self.mounted.lock().expect("automount mutex");
        if let Some(m) = mounted.get(&path) {
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
        let (mp, rest) = Self::find_mounted_in(&mounted, &path);
        let src = Self::source_at_locked(&self.root, &mounted, mp);
        let listing = src.list(&rest)?;
        match listing {
            ListResult::Infos(map) => {
                // If strip_ext, rename archive keys to stripped names when mounted there.
                let mut remapped = std::collections::BTreeMap::new();
                for (name, mut fi) in map {
                    let full = join(&path, &name);
                    let mut key = name;
                    if mounted.contains_key(&full) {
                        fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
                        fi.size = 0;
                    } else if self.strip_ext && is_archive_filename_with(&key, &self.ext_set) {
                        let stripped = strip_archive_extension(&key);
                        let alt = join(&path, &stripped);
                        if mounted.contains_key(&alt) {
                            key = stripped;
                            fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
                            fi.size = 0;
                        }
                    }
                    remapped.insert(key, Self::tag(fi, mp));
                }
                Some(ListResult::Infos(remapped))
            }
            ListResult::Names(names) => {
                let mut map = std::collections::BTreeMap::new();
                for name in names {
                    let full = join(&path, &name);
                    let child_rest = join(&rest, &name);
                    if let Some(mut fi) = src.lookup(&child_rest, 0) {
                        let mut key = name;
                        if mounted.contains_key(&full) {
                            fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
                            fi.size = 0;
                        } else if self.strip_ext && is_archive_filename_with(&key, &self.ext_set) {
                            let stripped = strip_archive_extension(&key);
                            let alt = join(&path, &stripped);
                            if mounted.contains_key(&alt) {
                                key = stripped;
                                fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
                                fi.size = 0;
                            }
                        }
                        map.insert(key, Self::tag(fi, mp));
                    }
                }
                Some(ListResult::Infos(map))
            }
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let path = normpath(path);
        self.ensure_lazy_mount(&path);
        self.ensure_lazy_children(&path);

        let mounted = self.mounted.lock().expect("automount mutex");
        if let Some(m) = mounted.get(&path) {
            return match m.source.list_mode("/")? {
                ListModeResult::Modes(map) => Some(ListModeResult::Modes(map)),
                ListModeResult::Names(names) => Some(ListModeResult::Names(names)),
            };
        }
        let (mp, rest) = Self::find_mounted_in(&mounted, &path);
        let src = Self::source_at_locked(&self.root, &mounted, mp);
        match src.list_mode(&rest)? {
            ListModeResult::Modes(map) => {
                let mut remapped = std::collections::BTreeMap::new();
                for (name, mut mode) in map {
                    let full = join(&path, &name);
                    let mut key = name;
                    if mounted.contains_key(&full) {
                        mode = (mode & 0o7777) | libc::S_IFDIR;
                    } else if self.strip_ext && is_archive_filename_with(&key, &self.ext_set) {
                        let stripped = strip_archive_extension(&key);
                        let alt = join(&path, &stripped);
                        if mounted.contains_key(&alt) {
                            key = stripped;
                            mode = (mode & 0o7777) | libc::S_IFDIR;
                        }
                    }
                    remapped.insert(key, mode);
                }
                Some(ListModeResult::Modes(remapped))
            }
            ListModeResult::Names(names) => {
                let mut modes = std::collections::BTreeMap::new();
                for name in names {
                    let full = join(&path, &name);
                    let child_rest = join(&rest, &name);
                    let mut key = name.clone();
                    let mode = if mounted.contains_key(&full) {
                        libc::S_IFDIR | 0o755
                    } else if self.strip_ext && is_archive_filename_with(&name, &self.ext_set) {
                        let stripped = strip_archive_extension(&name);
                        let alt = join(&path, &stripped);
                        if mounted.contains_key(&alt) {
                            key = stripped;
                            libc::S_IFDIR | 0o755
                        } else if let Some(fi) = src.lookup(&child_rest, 0) {
                            fi.mode
                        } else {
                            libc::S_IFREG
                        }
                    } else if let Some(fi) = src.lookup(&child_rest, 0) {
                        fi.mode
                    } else {
                        libc::S_IFREG
                    };
                    modes.insert(key, mode);
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
        self.ensure_lazy_mount(&path);
        // Strip-ext: user may look up /foo for archive /foo.tar
        if self.strip_ext || self.lazy {
            for suf in [
                ".tar", ".tar.gz", ".tgz", ".zip", ".7z", ".tar.bz2", ".tar.xz",
            ] {
                let candidate = format!("{path}{suf}");
                self.ensure_lazy_mount(&candidate);
            }
        }

        let mounted = self.mounted.lock().expect("automount mutex");
        if let Some(m) = mounted.get(&path) {
            let mut fi = m
                .source
                .lookup("/", 0)
                .unwrap_or_else(create_root_file_info);
            fi.mode = (fi.mode & 0o7777) | libc::S_IFDIR;
            fi.size = 0;
            return Some(Self::tag(fi, &path));
        }
        let (mp, rest) = Self::find_mounted_in(&mounted, &path);
        if mp != "/" {
            let fi =
                Self::source_at_locked(&self.root, &mounted, mp).lookup(&rest, file_version)?;
            return Some(Self::tag(fi, mp));
        }
        let mut fi = self.root.lookup(&path, file_version)?;
        if mounted.contains_key(&path) {
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
            let mounted = self.mounted.lock().expect("automount mutex");
            if let Some(m) = mounted.get(key) {
                return m.source.open(file_info, buffering);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("automount tag unknown: {key}"),
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ext_names() {
        assert_eq!(strip_archive_extension("foo.tar"), "foo");
        assert_eq!(strip_archive_extension("foo.tar.gz"), "foo");
        assert_eq!(strip_archive_extension("archive.tgz"), "archive");
        assert_eq!(strip_archive_extension("plain.txt"), "plain.txt");
    }
}
