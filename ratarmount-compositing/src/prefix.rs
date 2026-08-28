//! Mount under a path prefix (Python `-p` / RemovePrefixMountSource inverse).
//!
//! `PrefixMountSource` makes the entire tree appear under `/prefix/...`.

use std::io;
use std::sync::Arc;

use ratarmount_core::{
    create_root_file_info, normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult,
    ListResult, MountSource,
};

/// Wrap `inner` so all content is reachable under `prefix`.
pub struct PrefixMountSource {
    prefix: String,
    inner: Arc<dyn MountSource>,
}

impl PrefixMountSource {
    /// `prefix` like `"data"` or `"/data"` → content at `/data/...`.
    pub fn new(prefix: &str, inner: Arc<dyn MountSource>) -> Self {
        let p = prefix.trim().trim_matches('/');
        Self {
            prefix: if p.is_empty() {
                String::new()
            } else {
                format!("/{p}")
            },
            inner,
        }
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
        if path == "/" {
            // Single entry: the prefix name
            let name = self.prefix.trim_start_matches('/').to_string();
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                name,
                FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: ratarmount_core::S_IFDIR | 0o755,
                    linkname: String::new(),
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    userdata: vec![],
                },
            );
            return Some(ListResult::Infos(map));
        }
        let inner_path = self.strip(&path)?;
        self.inner.list(&inner_path)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let path = normpath(path);
        if self.prefix.is_empty() {
            return self.inner.list_dirents(&path);
        }
        if path == "/" {
            // Synthetic prefix dir; size 0 is correct (it is a directory).
            return Some(vec![CheapDirent {
                name: self.prefix.trim_start_matches('/').to_string(),
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
        if path == self.prefix {
            return Some(FileInfo {
                size: 0,
                mtime: 0.0,
                mode: ratarmount_core::S_IFDIR | 0o755,
                linkname: String::new(),
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
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

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        self.inner.member_seek_is_cheap(file_info)
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
