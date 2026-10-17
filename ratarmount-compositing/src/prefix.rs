//! Mount under a path prefix (Python `-p` / RemovePrefixMountSource inverse).
//!
//! `PrefixMountSource` makes the entire tree appear under `/prefix/...`.

use std::io;
use std::sync::Arc;

use ratarmount_core::{
    create_root_file_info, normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult,
    ListResult, MountSource,
};

/// One source mounted at an absolute path inside the union.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceBind {
    pub mount_path: String,
    pub source: String,
}

/// Validate a mount-relative absolute path before any source is opened.
pub fn validate_mount_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/')
        || path.contains('\0')
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(format!(
            "invalid mount path {path:?}: expected an absolute path without . or .."
        ));
    }
    Ok(())
}

impl std::str::FromStr for SourceBind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (mount_path, source) = value
            .split_once('=')
            .ok_or("expected --bind /MOUNTPATH=SOURCE")?;
        validate_mount_path(mount_path)?;
        if source.is_empty() {
            return Err("bind source must not be empty".into());
        }
        Ok(Self {
            mount_path: normpath(mount_path),
            source: source.into(),
        })
    }
}

/// Wrap `inner` so all content is reachable under `prefix`.
pub struct PrefixMountSource {
    prefix: String,
    inner: Arc<dyn MountSource>,
}

impl PrefixMountSource {
    /// `prefix` like `"data"` or `"/data"` → content at `/data/...`.
    pub fn new(prefix: &str, inner: Arc<dyn MountSource>) -> Self {
        let normalized = normpath(prefix);
        let p = normalized.trim_matches('/');
        Self {
            prefix: if p.is_empty() {
                String::new()
            } else {
                format!("/{p}")
            },
            inner,
        }
    }

    fn next_component<'a>(&'a self, path: &str) -> Option<&'a str> {
        let parent = if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        };
        self.prefix.strip_prefix(&parent)?.split('/').next()
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
        if let Some(name) = self.next_component(&path) {
            return Some(ListResult::Infos(std::collections::BTreeMap::from([(
                name.to_string(),
                create_root_file_info(),
            )])));
        }
        let inner_path = self.strip(&path)?;
        self.inner.list(&inner_path)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let path = normpath(path);
        if self.prefix.is_empty() {
            return self.inner.list_dirents(&path);
        }
        if let Some(name) = self.next_component(&path) {
            return Some(vec![CheapDirent {
                name: name.to_string(),
                mode: ratarmount_core::S_IFDIR | 0o755,
                size: 0,
            }]);
        }
        let inner_path = self.strip(&path)?;
        self.inner.list_dirents(&inner_path)
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return None;
        }
        self.inner.search_cheap(pattern)
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
        if self.prefix.is_empty() {
            return self.inner.lookup(&path, file_version);
        }
        if path == self.prefix || self.next_component(&path).is_some() {
            return Some(FileInfo {
                size: 0,
                mtime: 0.0,
                mode: ratarmount_core::S_IFDIR | 0o755,
                linkname: String::new(),
                uid: ratarmount_core::effective_uid(),
                gid: ratarmount_core::effective_gid(),
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
        if self.next_component(&path).is_some() {
            return 1;
        }
        if let Some(inner) = self.strip(&path) {
            self.inner.versions(&inner)
        } else {
            0
        }
    }

    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }

    fn content_generation(&self) -> u64 {
        self.inner.content_generation()
    }

    fn supports_backing_extents(&self) -> bool {
        self.inner.supports_backing_extents()
    }

    fn backing_extent(&self, file_info: &FileInfo) -> Option<ratarmount_core::BackingExtent> {
        self.inner.backing_extent(file_info)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_core::OpenOptions;
    use ratarmount_formats_zip::ZipMountSource;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    /// Regression: nested bind prefixes appeared as a single name containing a slash.
    #[test]
    fn regression_nested_prefix_lists_each_ancestor() {
        let (_dir, counted, a, _) = zip_with_two_members();
        let prefix = PrefixMountSource::new("/org/name", counted);
        assert_eq!(prefix.list_dirents("/").unwrap()[0].name, "org");
        assert_eq!(prefix.list_dirents("/org").unwrap()[0].name, "name");
        assert!(ratarmount_core::is_dir_mode(
            prefix.lookup("/org", 0).unwrap().mode
        ));
        assert!(prefix.lookup("/organization", 0).is_none());
        assert_eq!(prefix.versions("/org"), 1);
        let fi = prefix.lookup("/org/name/a.txt", 0).unwrap();
        assert_eq!(prefix.read(&fi, 100, 0).unwrap(), a);
        assert!(
            matches!(prefix.list("/org"), Some(ListResult::Infos(map)) if map.contains_key("name"))
        );
    }

    /// Regression: bind syntax must preserve URL equals signs and reject escaping mount paths.
    #[test]
    fn regression_bind_validation_rejects_parent_paths() {
        for value in ["repo=x", "/a/../b=x", "/./a=x", "/a=", "/a", "/a\0=x"] {
            assert!(value.parse::<SourceBind>().is_err(), "{value:?}");
        }
        let bind: SourceBind = "/org/name=https://host/file?x=y".parse().unwrap();
        assert_eq!(bind.source, "https://host/file?x=y");
        assert_eq!(bind.mount_path, "/org/name");
        assert_eq!(
            "/=repo.git@abc".parse::<SourceBind>().unwrap().mount_path,
            "/"
        );
    }

    /// Counts `list()` so we can prove Prefix uses `list_dirents`.
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
        let path = dir.path().join("prefixed.zip");
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

    /// Regression: `--prefix` readdir built a FileInfo map.
    #[test]
    fn prefix_list_dirents_root_is_single_dir_without_fat_list() {
        let (_dir, counted, _a, _b) = zip_with_two_members();
        let prefix = PrefixMountSource::new("data", Arc::clone(&counted) as Arc<dyn MountSource>);

        let dents = prefix
            .list_dirents("/")
            .expect("cheap dirents at prefix root");
        assert_eq!(
            counted.list_calls.load(Ordering::SeqCst),
            0,
            "PrefixMountSource::list_dirents must not call inner.list() (fat FileInfo map)"
        );
        assert_eq!(dents.len(), 1);
        assert_eq!(dents[0].name, "data");
        assert_eq!(dents[0].mode, ratarmount_core::S_IFDIR | 0o755);
        assert_eq!(dents[0].size, 0);
    }

    /// Regression: `/prefix/a.txt` size ≠ ZIP member size.
    #[test]
    fn prefix_list_dirents_forwards_inner_sizes() {
        let (_dir, counted, a, b) = zip_with_two_members();
        let prefix = PrefixMountSource::new("data", Arc::clone(&counted) as Arc<dyn MountSource>);

        let dents = prefix
            .list_dirents("/data")
            .expect("cheap dirents under prefix");
        assert_eq!(
            counted.list_calls.load(Ordering::SeqCst),
            0,
            "PrefixMountSource::list_dirents must not call inner.list() (fat FileInfo map)"
        );
        let by_name: std::collections::BTreeMap<_, _> =
            dents.into_iter().map(|d| (d.name, d.size)).collect();
        assert_eq!(by_name.get("a.txt").copied(), Some(a.len() as u64));
        assert_eq!(by_name.get("b.bin").copied(), Some(b.len() as u64));
    }
}
