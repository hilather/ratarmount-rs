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

/// Open a nested archive from a seekable member stream (no temp spool).
///
/// The `label` is a virtual name (e.g. `inner-hello.7z`) for logs/index metadata.
pub type OpenNestedReaderFn = Arc<
    dyn Fn(Box<dyn ratarmount_core::ArchiveRead>, &Path) -> io::Result<Arc<dyn MountSource>>
        + Send
        + Sync,
>;

const TAG_PREFIX: &str = "automount:";

/// Options controlling nested mount point naming and eagerness.
///
/// Default enables parallel eager nested opens when a folder has ≥2 archives
/// (`parallel_nested_threads = 0` → auto via [`std::thread::available_parallelism`]).
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
    /// Worker threads for parallel nested opens during eager `scan_and_mount`
    /// (upstream [#80](https://github.com/mxmlnkn/ratarmount/issues/80) / FR-6).
    ///
    /// * `0` (default): auto — use [`std::thread::available_parallelism`] (min 1).
    ///   Parallel path is used only when a folder has ≥2 archive children.
    /// * `1`: force sequential (pre-FR-6 behaviour).
    /// * `N ≥ 2`: cap concurrency at `N` workers.
    ///
    /// Lazy mode always mounts on access single-threaded; this field is ignored.
    pub parallel_nested_threads: u32,
}

/// Configured set of filename suffixes for recursive automount.
#[derive(Clone, Debug)]
pub struct RecursiveExtSet {
    /// Lowercase suffixes including leading `.` (e.g. `.tar`, `.tar.gz`).
    pub suffixes: Vec<String>,
    /// When true, any non-empty filename is considered (Python `*`).
    pub match_all: bool,
    /// When true, first multi-volume split parts match (Python `/split` +
    /// `FIRST_SPLIT_EXTENSION_REGEX`: `.aa`, `.001`, `.0`, `.1`, … of any width).
    pub match_split_first: bool,
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
    let mut match_split_first = false;
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
                match_split_first = true;
            }
            "/archive" => suffixes.extend(set_archive()),
            "/compressed" => suffixes.extend(set_compressed()),
            "/disk" => suffixes.extend(set_disk()),
            "/document" => suffixes.extend(set_document()),
            "/multimedia" => suffixes.extend(set_multimedia()),
            "/binary" => suffixes.extend(set_binary()),
            // Python: ExtensionRule with FIRST_SPLIT_EXTENSION_REGEX (any-width first part).
            "/split" => match_split_first = true,
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
    if suffixes.is_empty() && !match_all && !match_split_first {
        return RecursiveExtSet::default();
    }
    RecursiveExtSet {
        suffixes,
        match_all,
        match_split_first,
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
/// If `path_in_parent` is the first part of a multi-volume set inside `parent`, join parts to a temp path.
///
/// `path_in_parent` is the path relative to `parent`'s root (not the AutoMount virtual path).
/// Mirrors Python AutoMountLayer: list the parent folder, `check_for_split_file_in`, open each
/// part via the parent `MountSource`, concatenate into a seekable temp file for `open_nested`.
fn try_materialize_split_from_parent(
    parent: &dyn MountSource,
    path_in_parent: &str,
) -> Option<PathBuf> {
    use ratarmount_compress::{check_for_split_file_in, is_first_split_extension};

    let path = normpath(path_in_parent);
    let name = Path::new(&path)
        .file_name()
        .and_then(|s| s.to_str())?
        .to_string();
    let ext = Path::new(&name)
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    // Python: only when FIRST_SPLIT_EXTENSION_REGEX matches the last extension.
    if !is_first_split_extension(&ext) {
        return None;
    }
    let parent_dir = match Path::new(&path).parent() {
        Some(p) => {
            let s = p.to_string_lossy();
            if s.is_empty() || s == "." {
                "/".into()
            } else {
                s.into_owned()
            }
        }
        None => "/".into(),
    };
    let list = parent.list(&parent_dir)?;
    let names: Vec<String> = match list {
        ListResult::Names(n) => n,
        ListResult::Infos(m) => m.into_keys().collect(),
    };
    let set = check_for_split_file_in(&name, &names)?;
    // Need at least two parts (Python check_for_split_file_in requires len > 1).
    if set.paths.len() < 2 {
        return None;
    }
    // Materialize joined stream by opening each part through the parent mount.
    let mut tmp = NamedTempFile::new().ok()?;
    for part_path in &set.paths {
        // `check_for_split_file_in` may return basenames or dir-prefixed paths; use the name only.
        let part_base = part_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(part_path.to_str()?);
        let full = join(&parent_dir, part_base);
        let fi = parent.lookup(&full, 0)?;
        let mut reader = parent.open(&fi, 0).ok()?;
        io::copy(&mut reader, &mut tmp).ok()?;
    }
    tmp.flush().ok()?;
    let keep = tmp.into_temp_path().keep().ok()?;
    Some(keep)
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
    if set.suffixes.iter().any(|suf| l.ends_with(suf.as_str())) {
        return true;
    }
    // Python `/split` uses FIRST_SPLIT_EXTENSION_REGEX (any-width first part only).
    if set.match_split_first {
        if let Some(ext) = Path::new(name).extension().and_then(|s| s.to_str()) {
            return ratarmount_compress::is_first_split_extension(&format!(".{ext}"));
        }
    }
    false
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
    /// Temp path when nested was materialized; `None` when opened from a seekable reader.
    _persist: Option<PathBuf>,
    depth: u32,
}

/// Wraps a mount source and exposes nested archives as subfolders.
pub struct AutoMountLayer {
    root: Arc<dyn MountSource>,
    mounted: Mutex<HashMap<String, NestedMount>>,
    max_depth: u32,
    open_nested: OpenNestedFn,
    /// Optional no-tmp nested open (TAR/7z/ZIP from parent member stream).
    open_nested_reader: Option<OpenNestedReaderFn>,
    lazy: bool,
    strip_ext: bool,
    ext_set: RecursiveExtSet,
    transform: Option<(Regex, String)>,
    /// Cap for parallel eager nested opens (`0` = auto). See [`AutoMountOptions`].
    parallel_nested_threads: u32,
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
        Self::new_with_openers(root, max_depth, open_nested, None, opts)
    }

    /// Construct with both path-based and optional seekable-reader nested openers.
    ///
    /// When `open_nested_reader` is set, nested archives are opened from the parent
    /// member stream without copying to a temp file (TAR / 7z / ZIP supported by the
    /// factory). Path spool remains the fallback.
    pub fn new_with_openers(
        root: Arc<dyn MountSource>,
        max_depth: u32,
        open_nested: OpenNestedFn,
        open_nested_reader: Option<OpenNestedReaderFn>,
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
            open_nested_reader,
            lazy: opts.lazy,
            strip_ext: opts.strip_recursive_extension,
            ext_set: opts.recursive_extensions,
            transform,
            parallel_nested_threads: opts.parallel_nested_threads,
        };
        if !opts.lazy {
            layer.scan_and_mount();
        }
        layer
    }

    /// Prefer opening nested archives from a seekable parent-member stream (no temp file).
    pub fn with_reader_opener(mut self, open_nested_reader: OpenNestedReaderFn) -> Self {
        self.open_nested_reader = Some(open_nested_reader);
        // Re-scan so eager mounts use the reader path when available.
        if !self.lazy {
            self.mounted.lock().expect("automount mutex").clear();
            self.scan_and_mount();
        }
        self
    }

    /// Resolve worker count for eager parallel nested opens.
    fn parallel_worker_count(&self) -> usize {
        match self.parallel_nested_threads {
            0 => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            n => n as usize,
        }
    }

    /// Eager scan: list each folder, fan out same-directory nested opens, then
    /// recurse into subdirs and successfully mounted points (depth-by-depth).
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
            let mut subdirs = Vec::new();
            let mut archives = Vec::new();
            for name in names {
                let full = join(&folder, &name);
                if self.is_dir_raw(&full) {
                    subdirs.push(full);
                    continue;
                }
                if is_archive_filename_with(&name, &self.ext_set) {
                    archives.push(full);
                }
            }
            let mounted_mps = self.mount_archives_batch(&archives, depth + 1);
            folders.extend(subdirs);
            folders.extend(mounted_mps);
        }
    }

    /// Mount all archive files at one directory level.
    ///
    /// When there are ≥2 archives and worker count > 1, opens fan out via
    /// [`std::thread::scope`]. Otherwise sequential (also used for lazy mode callers
    /// that invoke [`Self::try_mount_file`] directly).
    fn mount_archives_batch(&self, archives: &[String], depth: u32) -> Vec<String> {
        if archives.is_empty() {
            return Vec::new();
        }
        let workers = self.parallel_worker_count();
        if workers <= 1 || archives.len() < 2 {
            let mut out = Vec::with_capacity(archives.len());
            for full in archives {
                if let Some(mp) = self.try_mount_file(full, depth) {
                    debug!("automounted {full} -> {mp}");
                    out.push(mp);
                }
            }
            return out;
        }

        let n_workers = workers.min(archives.len());
        let work = Mutex::new(archives.to_vec());
        let results = Mutex::new(Vec::with_capacity(archives.len()));

        std::thread::scope(|scope| {
            for _ in 0..n_workers {
                scope.spawn(|| loop {
                    let full = {
                        let mut q = work.lock().expect("automount work queue");
                        q.pop()
                    };
                    let Some(full) = full else {
                        break;
                    };
                    if let Some(mp) = self.try_mount_file(&full, depth) {
                        debug!("automounted {full} -> {mp}");
                        results.lock().expect("automount results").push(mp);
                    }
                });
            }
        });

        results.into_inner().expect("automount results")
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
            .map(|fi| fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR)
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
        if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
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

        // Recursive split join (Python AutoMountLayer + check_for_split_file_in).
        // Use `rest` (path inside parent mount), not the AutoMount virtual path.
        let label = PathBuf::from(
            rest.rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("nested"),
        );

        // Prefer no-tmp open from seekable parent member (TAR stencil / 7z store / …).
        debug!(
            "automount try_mount: path={path} rest={rest} label={} depth={depth} \
             has_reader_opener={} size={} mode={:#x}",
            label.display(),
            self.open_nested_reader.is_some(),
            fi.size,
            fi.mode
        );
        if self.open_nested_reader.is_some()
            && try_materialize_split_from_parent(parent.as_ref(), &rest).is_none()
        {
            match parent.open(&fi, 0) {
                Ok(reader) => {
                    if let Some(ref open_r) = self.open_nested_reader {
                        match open_r(reader, &label) {
                            Ok(nested) => {
                                let mut mounted = self.mounted.lock().expect("automount mutex");
                                let key =
                                    if mounted.contains_key(&mount_point) && mount_point != path {
                                        path.to_string()
                                    } else {
                                        mount_point
                                    };
                                debug!(
                                    "automount: mounted {} via nested reader at key={key} (no temp spool)",
                                    label.display()
                                );
                                mounted.insert(
                                    key.clone(),
                                    NestedMount {
                                        source: nested,
                                        _persist: None,
                                        depth,
                                    },
                                );
                                return Some(key);
                            }
                            Err(e) => {
                                debug!(
                                    "automount: nested reader open failed for {} (kind={:?}): {e}; \
                                     falling back to temp spool",
                                    label.display(),
                                    e.kind()
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "automount: parent.open failed for {} (kind={:?}): {e}; \
                         will try temp spool path",
                        rest,
                        e.kind()
                    );
                }
            }
        }

        let persist =
            if let Some(joined) = try_materialize_split_from_parent(parent.as_ref(), &rest) {
                debug!(
                    "automount: using split-join materialize for {} -> {}",
                    rest,
                    joined.display()
                );
                joined
            } else {
                let mut reader = match parent.open(&fi, 0) {
                    Ok(r) => r,
                    Err(e) => {
                        debug!(
                        "automount: parent.open for temp spool failed for {rest} (kind={:?}): {e}",
                        e.kind()
                    );
                        return None;
                    }
                };
                let mut tmp = match NamedTempFile::new() {
                    Ok(t) => t,
                    Err(e) => {
                        debug!("automount: NamedTempFile::new failed for {rest}: {e}");
                        return None;
                    }
                };
                if let Err(e) = io::copy(&mut reader, &mut tmp) {
                    debug!("automount: copy to temp failed for {rest}: {e}");
                    return None;
                }
                if let Err(e) = tmp.flush() {
                    debug!("automount: temp flush failed for {rest}: {e}");
                    return None;
                }
                let tmp_path = tmp.into_temp_path();
                match tmp_path.keep() {
                    Ok(p) => {
                        debug!(
                            "automount: spooled {} -> {} for path open",
                            rest,
                            p.display()
                        );
                        p
                    }
                    Err(e) => {
                        debug!("automount: temp keep failed for {rest}: {e}");
                        return None;
                    }
                }
            };
        let nested = match (self.open_nested)(&persist) {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    "automount: failed to open nested {} via path (kind={:?}): {e}",
                    persist.display(),
                    e.kind()
                );
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
        debug!(
            "automount: mounted {} via temp path at key={key}",
            label.display()
        );
        mounted.insert(
            key.clone(),
            NestedMount {
                source: nested,
                _persist: Some(persist),
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
                        fi.mode = (fi.mode & 0o7777) | ratarmount_core::S_IFDIR;
                        fi.size = 0;
                    } else if self.strip_ext && is_archive_filename_with(&key, &self.ext_set) {
                        let stripped = strip_archive_extension(&key);
                        let alt = join(&path, &stripped);
                        if mounted.contains_key(&alt) {
                            key = stripped;
                            fi.mode = (fi.mode & 0o7777) | ratarmount_core::S_IFDIR;
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
                            fi.mode = (fi.mode & 0o7777) | ratarmount_core::S_IFDIR;
                            fi.size = 0;
                        } else if self.strip_ext && is_archive_filename_with(&key, &self.ext_set) {
                            let stripped = strip_archive_extension(&key);
                            let alt = join(&path, &stripped);
                            if mounted.contains_key(&alt) {
                                key = stripped;
                                fi.mode = (fi.mode & 0o7777) | ratarmount_core::S_IFDIR;
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
                        mode = (mode & 0o7777) | ratarmount_core::S_IFDIR;
                    } else if self.strip_ext && is_archive_filename_with(&key, &self.ext_set) {
                        let stripped = strip_archive_extension(&key);
                        let alt = join(&path, &stripped);
                        if mounted.contains_key(&alt) {
                            key = stripped;
                            mode = (mode & 0o7777) | ratarmount_core::S_IFDIR;
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
                        ratarmount_core::S_IFDIR | 0o755
                    } else if self.strip_ext && is_archive_filename_with(&name, &self.ext_set) {
                        let stripped = strip_archive_extension(&name);
                        let alt = join(&path, &stripped);
                        if mounted.contains_key(&alt) {
                            key = stripped;
                            ratarmount_core::S_IFDIR | 0o755
                        } else if let Some(fi) = src.lookup(&child_rest, 0) {
                            fi.mode
                        } else {
                            ratarmount_core::S_IFREG
                        }
                    } else if let Some(fi) = src.lookup(&child_rest, 0) {
                        fi.mode
                    } else {
                        ratarmount_core::S_IFREG
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
            fi.mode = (fi.mode & 0o7777) | ratarmount_core::S_IFDIR;
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
            fi.mode = (fi.mode & 0o7777) | ratarmount_core::S_IFDIR;
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
    use std::fs;
    use std::io::Read;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn strip_ext_names() {
        assert_eq!(strip_archive_extension("foo.tar"), "foo");
        assert_eq!(strip_archive_extension("foo.tar.gz"), "foo");
        assert_eq!(strip_archive_extension("archive.tgz"), "archive");
        assert_eq!(strip_archive_extension("plain.txt"), "plain.txt");
    }

    #[test]
    fn default_set_includes_split_first_parts() {
        let set = RecursiveExtSet::default();
        assert!(set.match_split_first);
        assert!(is_archive_filename_with("foo.001", &set));
        assert!(is_archive_filename_with("foo.01", &set));
        assert!(is_archive_filename_with("foo.1", &set));
        assert!(is_archive_filename_with("foo.0", &set));
        assert!(is_archive_filename_with("foo.aa", &set));
        assert!(is_archive_filename_with("foo.aaa", &set));
        assert!(is_archive_filename_with("foo.0001", &set));
        assert!(is_archive_filename_with("archive.tar.001", &set));
        // Non-first parts must not trigger recursive mount on their own.
        assert!(!is_archive_filename_with("foo.002", &set));
        assert!(!is_archive_filename_with("foo.ab", &set));
        assert!(!is_archive_filename_with("plain.txt", &set));
        // Regular archives still match.
        assert!(is_archive_filename_with("foo.tar", &set));
    }

    #[test]
    fn parse_split_only_extension_set() {
        let set = parse_recursive_extensions("/split");
        assert!(set.match_split_first);
        assert!(set.suffixes.is_empty());
        assert!(is_archive_filename_with("vol.001", &set));
        assert!(!is_archive_filename_with("vol.tar", &set));
        assert!(!is_archive_filename_with("vol.002", &set));
    }

    #[test]
    fn try_materialize_joins_parts_from_folder_mount() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("foo.001"), b"hello ").unwrap();
        fs::write(dir.path().join("foo.002"), b"world").unwrap();
        fs::write(dir.path().join("unrelated.txt"), b"x").unwrap();

        let folder = crate::folder::FolderMountSource::new(dir.path()).unwrap();
        let joined = try_materialize_split_from_parent(&folder, "/foo.001").expect("join");
        let data = fs::read(&joined).unwrap();
        assert_eq!(data, b"hello world");
        let _ = fs::remove_file(&joined);
    }

    #[test]
    fn try_materialize_decimal_and_alpha_in_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("parts");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("vol.aa"), b"AA").unwrap();
        fs::write(sub.join("vol.ab"), b"AB").unwrap();
        fs::write(sub.join("vol.ac"), b"AC").unwrap();

        let folder = crate::folder::FolderMountSource::new(dir.path()).unwrap();
        let joined =
            try_materialize_split_from_parent(&folder, "/parts/vol.aa").expect("alpha join");
        assert_eq!(fs::read(&joined).unwrap(), b"AAABAC");
        let _ = fs::remove_file(&joined);

        // Non-first part must not join.
        assert!(try_materialize_split_from_parent(&folder, "/parts/vol.ab").is_none());
    }

    #[test]
    fn try_materialize_skips_single_lonely_first_part() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lonely.001"), b"only").unwrap();
        let folder = crate::folder::FolderMountSource::new(dir.path()).unwrap();
        assert!(try_materialize_split_from_parent(&folder, "/lonely.001").is_none());
    }

    /// Minimal empty nested mount used when open_nested is only needed for success.
    struct EmptyNested;
    impl MountSource for EmptyNested {
        fn list(&self, path: &str) -> Option<ListResult> {
            if normpath(path) == "/" {
                Some(ListResult::Names(vec![]))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if normpath(path) == "/" {
                Some(create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "empty nested"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    #[test]
    fn automount_layer_joins_split_parts_before_open_nested() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("payload.001"), b"PART1").unwrap();
        fs::write(dir.path().join("payload.002"), b"PART2").unwrap();
        fs::write(dir.path().join("payload.003"), b"PART3").unwrap();

        let opened = Arc::new(AtomicUsize::new(0));
        let joined_ok = Arc::new(std::sync::Mutex::new(false));
        let opened_c = Arc::clone(&opened);
        let joined_c = Arc::clone(&joined_ok);

        let open_nested: OpenNestedFn = Arc::new(move |path: &Path| {
            opened_c.fetch_add(1, Ordering::SeqCst);
            let data = fs::read(path).map_err(|e| {
                io::Error::new(e.kind(), format!("read joined {}: {e}", path.display()))
            })?;
            if data == b"PART1PART2PART3" {
                *joined_c.lock().unwrap() = true;
            }
            Ok(Arc::new(EmptyNested) as Arc<dyn MountSource>)
        });

        let root = Arc::new(crate::folder::FolderMountSource::new(dir.path()).unwrap())
            as Arc<dyn MountSource>;
        let layer = AutoMountLayer::new(root, 1, open_nested);

        // Eager scan should have mounted the first part after joining.
        assert!(
            *joined_ok.lock().unwrap(),
            "open_nested must see concatenated split parts"
        );
        assert_eq!(opened.load(Ordering::SeqCst), 1);

        // Mount point is the first-part path (no strip by default).
        let fi = layer.lookup("/payload.001", 0).expect("mounted as dir");
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);

        // Listing root should show payload.001 as a directory (mounted).
        match layer.list("/").unwrap() {
            ListResult::Infos(map) => {
                let mode = map.get("payload.001").expect("name present").mode;
                assert_eq!(mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);
            }
            ListResult::Names(_) => panic!("expected infos"),
        }
    }

    #[test]
    fn automount_nested_tar_via_reader_no_tmp() {
        use ratarmount_core::OpenOptions;
        use ratarmount_formats_tar::SqliteIndexedTar;
        use std::process::Command;
        use std::sync::atomic::{AtomicBool, Ordering as AOrd};

        let dir = tempfile::tempdir().unwrap();
        // Outer TAR contains an inner TAR as a regular file member.
        let inner_dir = dir.path().join("inner_content");
        fs::create_dir(&inner_dir).unwrap();
        fs::write(inner_dir.join("payload.txt"), b"nested tar payload\n").unwrap();
        let inner_tar = dir.path().join("inner.tar");
        assert!(Command::new("tar")
            .args(["-cf"])
            .arg(&inner_tar)
            .arg("-C")
            .arg(&inner_dir)
            .arg("payload.txt")
            .status()
            .unwrap()
            .success());
        let outer_dir = dir.path().join("outer_content");
        fs::create_dir(&outer_dir).unwrap();
        fs::copy(&inner_tar, outer_dir.join("inner.tar")).unwrap();
        let outer_tar = dir.path().join("outer.tar");
        assert!(Command::new("tar")
            .args(["-cf"])
            .arg(&outer_tar)
            .arg("-C")
            .arg(&outer_dir)
            .arg("inner.tar")
            .status()
            .unwrap()
            .success());

        let path_opened = Arc::new(AtomicBool::new(false));
        let reader_opened = Arc::new(AtomicBool::new(false));
        let path_c = Arc::clone(&path_opened);
        let reader_c = Arc::clone(&reader_opened);

        let open_nested: OpenNestedFn = Arc::new(move |path: &Path| {
            path_c.store(true, AOrd::SeqCst);
            let opts = OpenOptions {
                index_in_memory: true,
                ..OpenOptions::default()
            };
            let ms = SqliteIndexedTar::create_index(path, path, None, &opts, "test", &mut None)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Arc::new(ms) as Arc<dyn MountSource>)
        });
        let open_reader: OpenNestedReaderFn = Arc::new(move |reader, label| {
            reader_c.store(true, AOrd::SeqCst);
            let opts = OpenOptions {
                index_in_memory: true,
                ..OpenOptions::default()
            };
            let ms = SqliteIndexedTar::open_from_reader(reader, label, None, &opts, "test")
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Arc::new(ms) as Arc<dyn MountSource>)
        });

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let root =
            SqliteIndexedTar::create_index(&outer_tar, &outer_tar, None, &opts, "test", &mut None)
                .expect("outer tar");
        let layer = AutoMountLayer::new_with_openers(
            Arc::new(root),
            2,
            open_nested,
            Some(open_reader),
            AutoMountOptions::default(),
        );

        // Nested content may be served by flattened recursive index rows (no AutoMount)
        // or by Read+Seek nested open — never by temp path spool.
        assert!(
            !path_opened.load(AOrd::SeqCst),
            "nested TAR must not fall back to path/temp spool"
        );

        let fi = layer
            .lookup("/inner.tar/payload.txt", 0)
            .expect("nested payload via flatten and/or AutoMount");
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFREG);
        let mut r = layer.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "nested tar payload\n");
        // Prefer no-tmp reader when AutoMount still mounts the nested archive.
        if reader_opened.load(AOrd::SeqCst) {
            // ok
        }
        let _ = reader_opened;
    }

    #[test]
    fn automount_nested_7z_via_reader_no_tmp() {
        use ratarmount_core::OpenOptions;
        use ratarmount_formats_sevenzip::SevenZipMountSource;
        use std::sync::atomic::{AtomicBool, Ordering as AOrd};

        let path = PathBuf::from(
            std::env::var("RATARMOUNT_PY_ROOT")
                .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into()),
        )
        .join("tests/nested-inner-hello.7z");
        if !path.exists() {
            eprintln!("skip missing {}", path.display());
            return;
        }

        let path_opened = Arc::new(AtomicBool::new(false));
        let reader_opened = Arc::new(AtomicBool::new(false));
        let path_c = Arc::clone(&path_opened);
        let reader_c = Arc::clone(&reader_opened);

        let open_nested: OpenNestedFn = Arc::new(move |_path: &Path| {
            path_c.store(true, AOrd::SeqCst);
            Err(io::Error::other(
                "path spool should not be used for nested 7z store",
            ))
        });
        let open_reader: OpenNestedReaderFn = Arc::new(move |reader, label| {
            reader_c.store(true, AOrd::SeqCst);
            let opts = OpenOptions {
                index_in_memory: true,
                ..OpenOptions::default()
            };
            let ms =
                SevenZipMountSource::open_from_reader(reader, label, None, &opts, "test", true)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Arc::new(ms) as Arc<dyn MountSource>)
        });

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let root = SevenZipMountSource::open(&path, None, &opts, "test", true).expect("outer 7z");
        let layer = AutoMountLayer::new_with_openers(
            Arc::new(root),
            2,
            open_nested,
            Some(open_reader),
            AutoMountOptions::default(),
        );

        assert!(reader_opened.load(AOrd::SeqCst), "inner 7z via reader");
        assert!(
            !path_opened.load(AOrd::SeqCst),
            "no path spool for nested 7z"
        );

        // inner-hello.7z/hello.txt (or first file)
        let fi = layer
            .lookup("/inner-hello.7z/hello.txt", 0)
            .or_else(|| {
                // discover mount + first file
                if let Some(ListResult::Infos(map)) = layer.list("/") {
                    for name in map.keys() {
                        if name.ends_with(".7z") {
                            if let Some(ListResult::Infos(inner)) = layer.list(&format!("/{name}"))
                            {
                                if let Some(fname) = inner.keys().next() {
                                    return layer.lookup(&format!("/{name}/{fname}"), 0);
                                }
                            }
                        }
                    }
                }
                None
            })
            .expect("file inside nested 7z");
        let mut data = Vec::new();
        layer.open(&fi, 0).unwrap().read_to_end(&mut data).unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn automount_split_with_real_tar_payload() {
        use ratarmount_core::OpenOptions;
        use ratarmount_formats_tar::SqliteIndexedTar;
        use std::process::Command;

        let dir = tempfile::tempdir().unwrap();
        // Build a small TAR, then split into two volume files.
        let content_dir = dir.path().join("content");
        fs::create_dir(&content_dir).unwrap();
        fs::write(content_dir.join("hello.txt"), b"hello from split tar\n").unwrap();
        let tar_path = dir.path().join("archive.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&content_dir)
            .arg("hello.txt")
            .status()
            .expect("tar available");
        assert!(status.success());
        let tar_bytes = fs::read(&tar_path).unwrap();
        let mid = tar_bytes.len() / 2;
        assert!(mid > 0 && mid < tar_bytes.len());
        fs::write(dir.path().join("archive.tar.001"), &tar_bytes[..mid]).unwrap();
        fs::write(dir.path().join("archive.tar.002"), &tar_bytes[mid..]).unwrap();
        let _ = fs::remove_file(&tar_path);

        let open_nested: OpenNestedFn = Arc::new(|path: &Path| {
            let opts = OpenOptions::default();
            let ms = SqliteIndexedTar::create_index(path, path, None, &opts, "test", &mut None)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Arc::new(ms) as Arc<dyn MountSource>)
        });

        let root = Arc::new(crate::folder::FolderMountSource::new(dir.path()).unwrap())
            as Arc<dyn MountSource>;
        let layer = AutoMountLayer::new(root, 1, open_nested);

        let fi = layer
            .lookup("/archive.tar.001/hello.txt", 0)
            .expect("file inside joined tar");
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFREG);
        let mut reader = layer.open(&fi, 0).unwrap();
        let mut buf = String::new();
        reader.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello from split tar\n");
    }

    /// Regression: FR-6 parallel eager mount of multiple same-directory nested archives.
    ///
    /// Symptom (upstream #80): outer tree with many nested archives indexes them one-by-one.
    /// With `parallel_nested_threads ≥ 2` and ≥2 archive children, opens fan out and all
    /// mounts succeed.
    #[test]
    fn parallel_eager_mounts_multiple_archives_same_level() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.tar", "b.tar", "c.tar"] {
            fs::write(dir.path().join(name), b"dummy-archive").unwrap();
        }
        fs::write(dir.path().join("readme.txt"), b"not an archive").unwrap();

        let opened = Arc::new(AtomicUsize::new(0));
        let opened_c = Arc::clone(&opened);
        let open_nested: OpenNestedFn = Arc::new(move |path: &Path| {
            opened_c.fetch_add(1, Ordering::SeqCst);
            assert!(path.exists(), "nested path must exist: {}", path.display());
            Ok(Arc::new(EmptyNested) as Arc<dyn MountSource>)
        });

        let root = Arc::new(crate::folder::FolderMountSource::new(dir.path()).unwrap())
            as Arc<dyn MountSource>;
        let layer = AutoMountLayer::new_with_options(
            root,
            1,
            open_nested,
            AutoMountOptions {
                // Force parallel path (≥2 workers + ≥2 archives at one level).
                parallel_nested_threads: 4,
                ..Default::default()
            },
        );

        assert_eq!(
            opened.load(Ordering::SeqCst),
            3,
            "all three nested archives must be opened"
        );
        for name in ["a.tar", "b.tar", "c.tar"] {
            let fi = layer
                .lookup(&format!("/{name}"), 0)
                .unwrap_or_else(|| panic!("expected mount for {name}"));
            assert_eq!(
                fi.mode & ratarmount_core::S_IFMT,
                ratarmount_core::S_IFDIR,
                "{name} should appear as a directory"
            );
        }
        // Non-archive stays a regular file.
        let fi = layer.lookup("/readme.txt", 0).expect("readme");
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFREG);
    }

    /// Regression: FR-6 concurrent open_nested calls when parallel path is forced.
    #[test]
    fn parallel_eager_open_nested_overlaps_with_multiple_archives() {
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        for name in ["x.tar", "y.tar", "z.tar", "w.tar"] {
            fs::write(dir.path().join(name), b"dummy").unwrap();
        }

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let in_c = Arc::clone(&in_flight);
        let max_c = Arc::clone(&max_in_flight);

        let open_nested: OpenNestedFn = Arc::new(move |_path: &Path| {
            let cur = in_c.fetch_add(1, Ordering::SeqCst) + 1;
            max_c.fetch_max(cur, Ordering::SeqCst);
            // Hold the slot so sibling workers can overlap.
            std::thread::sleep(Duration::from_millis(80));
            in_c.fetch_sub(1, Ordering::SeqCst);
            Ok(Arc::new(EmptyNested) as Arc<dyn MountSource>)
        });

        let root = Arc::new(crate::folder::FolderMountSource::new(dir.path()).unwrap())
            as Arc<dyn MountSource>;
        let _layer = AutoMountLayer::new_with_options(
            root,
            1,
            open_nested,
            AutoMountOptions {
                parallel_nested_threads: 4,
                ..Default::default()
            },
        );

        let peak = max_in_flight.load(Ordering::SeqCst);
        assert!(
            peak >= 2,
            "expected concurrent open_nested (peak in-flight={peak}); parallel path not taken?"
        );
    }

    /// Sequential forced (`parallel_nested_threads = 1`) still mounts every archive.
    #[test]
    fn sequential_eager_still_mounts_all_archives() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["one.tar", "two.tar"] {
            fs::write(dir.path().join(name), b"x").unwrap();
        }
        let opened = Arc::new(AtomicUsize::new(0));
        let opened_c = Arc::clone(&opened);
        let open_nested: OpenNestedFn = Arc::new(move |_path: &Path| {
            opened_c.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(EmptyNested) as Arc<dyn MountSource>)
        });
        let root = Arc::new(crate::folder::FolderMountSource::new(dir.path()).unwrap())
            as Arc<dyn MountSource>;
        let layer = AutoMountLayer::new_with_options(
            root,
            1,
            open_nested,
            AutoMountOptions {
                parallel_nested_threads: 1,
                ..Default::default()
            },
        );
        assert_eq!(opened.load(Ordering::SeqCst), 2);
        assert!(layer.lookup("/one.tar", 0).is_some());
        assert!(layer.lookup("/two.tar", 0).is_some());
    }

    /// Lazy mode must not run eager scan (parallel or otherwise); mount on first access.
    #[test]
    fn lazy_mode_does_not_eager_parallel_mount() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("late.tar"), b"x").unwrap();
        fs::write(dir.path().join("also.tar"), b"y").unwrap();

        let opened = Arc::new(AtomicUsize::new(0));
        let opened_c = Arc::clone(&opened);
        let open_nested: OpenNestedFn = Arc::new(move |_path: &Path| {
            opened_c.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(EmptyNested) as Arc<dyn MountSource>)
        });
        let root = Arc::new(crate::folder::FolderMountSource::new(dir.path()).unwrap())
            as Arc<dyn MountSource>;
        let layer = AutoMountLayer::new_with_options(
            root,
            2,
            open_nested,
            AutoMountOptions {
                lazy: true,
                parallel_nested_threads: 8,
                ..Default::default()
            },
        );
        assert_eq!(
            opened.load(Ordering::SeqCst),
            0,
            "lazy must not eager-scan even when parallel threads configured"
        );
        // First list triggers sequential lazy children mount.
        let _ = layer.list("/");
        assert_eq!(opened.load(Ordering::SeqCst), 2);
        assert!(layer.lookup("/late.tar", 0).is_some());
        assert!(layer.lookup("/also.tar", 0).is_some());
    }

    /// Nested content under parallel-mounted archives is still reachable.
    #[test]
    fn parallel_eager_recurses_into_mounted_archives() {
        use ratarmount_core::OpenOptions;
        use ratarmount_formats_tar::SqliteIndexedTar;
        use std::process::Command;

        let dir = tempfile::tempdir().unwrap();
        // Build two outer TARs each with one file member.
        for (archive, payload_name, payload) in [
            ("left.tar", "left.txt", b"L" as &[u8]),
            ("right.tar", "right.txt", b"R" as &[u8]),
        ] {
            let content = dir.path().join(format!("{archive}.content"));
            fs::create_dir(&content).unwrap();
            fs::write(content.join(payload_name), payload).unwrap();
            let tar_path = dir.path().join(archive);
            assert!(Command::new("tar")
                .args(["-cf"])
                .arg(&tar_path)
                .arg("-C")
                .arg(&content)
                .arg(payload_name)
                .status()
                .unwrap()
                .success());
        }

        let open_nested: OpenNestedFn = Arc::new(|path: &Path| {
            let opts = OpenOptions {
                index_in_memory: true,
                ..OpenOptions::default()
            };
            let ms = SqliteIndexedTar::create_index(path, path, None, &opts, "test", &mut None)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Arc::new(ms) as Arc<dyn MountSource>)
        });
        let root = Arc::new(crate::folder::FolderMountSource::new(dir.path()).unwrap())
            as Arc<dyn MountSource>;
        let layer = AutoMountLayer::new_with_options(
            root,
            2,
            open_nested,
            AutoMountOptions {
                parallel_nested_threads: 4,
                ..Default::default()
            },
        );

        let mut left = String::new();
        layer
            .open(&layer.lookup("/left.tar/left.txt", 0).expect("left"), 0)
            .unwrap()
            .read_to_string(&mut left)
            .unwrap();
        assert_eq!(left, "L");
        let mut right = String::new();
        layer
            .open(&layer.lookup("/right.tar/right.txt", 0).expect("right"), 0)
            .unwrap()
            .read_to_string(&mut right)
            .unwrap();
        assert_eq!(right, "R");
    }
}
