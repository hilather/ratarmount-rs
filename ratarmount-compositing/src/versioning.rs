//! File version path API: `<path>.versions/<n>` (Python `FileVersionLayer`).
//!
//! Version 1 is oldest; higher numbers are newer. The most recent version is also
//! available at the plain path (file_version 0).

use std::io;
use std::sync::Arc;

use ratarmount_core::{
    normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
    UserData,
};

const VERSIONS_SUFFIX: &str = ".versions";
const TAG_FILE: &str = "versionlayer:file";
const TAG_FOLDER: &str = "versionlayer:versions-folder";

/// Expose multi-version archive members under virtual `.versions` directories.
pub struct FileVersionLayer {
    inner: Arc<dyn MountSource>,
}

impl FileVersionLayer {
    pub fn new(inner: Arc<dyn MountSource>) -> Self {
        Self { inner }
    }

    /// Decode path with `.versions` segments.
    /// Returns `(real_path, is_versions_folder, file_version)`.
    fn decode(&self, file_path: &str) -> Option<(String, bool, i32)> {
        let parts: Vec<&str> = file_path.trim_start_matches('/').split('/').collect();
        let mut file_path = String::new();
        let mut path_is_versions_folder = false;
        let mut file_version: Option<i32> = None;

        for part in parts {
            if path_is_versions_folder {
                let v: i32 = part.parse().ok()?;
                if v.to_string() != part {
                    return None;
                }
                file_version = Some(v);
                path_is_versions_folder = false;
                continue;
            }

            let tmp = if file_path.is_empty() {
                format!("/{part}")
            } else {
                format!("{file_path}/{part}")
            };

            if self.inner.lookup(&tmp, 0).is_some() {
                file_path = tmp;
                file_version = Some(0);
                continue;
            }

            if part.ends_with(VERSIONS_SUFFIX) && part.len() > VERSIONS_SUFFIX.len() {
                path_is_versions_folder = true;
                file_version = Some(0);
                file_path = tmp[..tmp.len() - VERSIONS_SUFFIX.len()].to_string();
                continue;
            }

            return None;
        }

        let file_version = file_version?;
        Some((
            file_path,
            path_is_versions_folder,
            if path_is_versions_folder {
                0
            } else {
                file_version
            },
        ))
    }

    fn tag_file(mut fi: FileInfo) -> FileInfo {
        fi.userdata.push(UserData::Other(TAG_FILE.into()));
        fi
    }

    fn versions_folder_info(parent: &FileInfo) -> FileInfo {
        FileInfo {
            size: 0,
            mtime: parent.mtime,
            mode: ratarmount_core::S_IFDIR | 0o755,
            linkname: String::new(),
            uid: parent.uid,
            gid: parent.gid,
            userdata: vec![UserData::Other(TAG_FOLDER.into())],
        }
    }
}

impl MountSource for FileVersionLayer {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if let Some(files) = self.inner.list(&path) {
            return Some(files);
        }
        let (real, is_vers, _) = self.decode(&path)?;
        if !is_vers {
            return self.inner.list(&real);
        }
        let n = self.inner.versions(&real);
        if n == 0 {
            return None;
        }
        let names: Vec<String> = (1..=n).map(|i| i.to_string()).collect();
        Some(ListResult::Names(names))
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

    /// Forward cheap dirents from the inner source. Versions-folder listings
    /// are numbered names only — never `inner.list()` (fat `FileInfo` maps).
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let path = normpath(path);
        if let Some(dents) = self.inner.list_dirents(&path) {
            return Some(dents);
        }
        let (real, is_vers, _) = self.decode(&path)?;
        if !is_vers {
            return self.inner.list_dirents(&real);
        }
        let n = self.inner.versions(&real);
        if n == 0 {
            return None;
        }
        Some(
            (1..=n)
                .map(|i| CheapDirent {
                    name: i.to_string(),
                    // Read-only virtual files: bare S_IFREG would render
                    // perm 000 in readdirplus listings (real mode via lookup).
                    mode: ratarmount_core::S_IFREG | 0o444,
                    size: 0,
                })
                .collect(),
        )
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        // Plain path (file_version must be 0 from FUSE)
        let _ = file_version;
        if let Some(fi) = self.inner.lookup(&path, 0) {
            return Some(Self::tag_file(fi));
        }
        let (real, is_vers, ver) = self.decode(&path)?;
        if is_vers {
            let parent = self.inner.lookup(&real, 0)?;
            return Some(Self::versions_folder_info(&parent));
        }
        // Positive version numbers: 1 = oldest
        let fi = self.inner.lookup(&real, ver)?;
        Some(Self::tag_file(fi))
    }

    fn versions(&self, path: &str) -> u32 {
        let path = normpath(path);
        if let Some((real, is_vers, _)) = self.decode(&path) {
            if is_vers {
                return 1;
            }
            return self.inner.versions(&real);
        }
        self.inner.versions(&path)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        // Strip our tag for underlying open.
        let mut fi = file_info.clone();
        if let Some(UserData::Other(s)) = fi.userdata.last() {
            if s == TAG_FOLDER {
                return Err(io::Error::new(
                    io::ErrorKind::IsADirectory,
                    "versions folder",
                ));
            }
            if s == TAG_FILE {
                fi.userdata.pop();
            }
        }
        self.inner.open(&fi, buffering)
    }

    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }

    fn content_generation(&self) -> u64 {
        self.inner.content_generation()
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        let mut fi = file_info.clone();
        if let Some(UserData::Other(s)) = fi.userdata.last() {
            if s == TAG_FOLDER {
                return true;
            }
            if s == TAG_FILE {
                fi.userdata.pop();
            }
        }
        self.inner.member_seek_is_cheap(&fi)
    }

    fn statfs(&self) -> ratarmount_core::StatFs {
        self.inner.statfs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_core::OpenOptions;
    use ratarmount_formats_zip::ZipMountSource;
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    /// Counts `list()` so we can prove FileVersionLayer uses `list_dirents`.
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

    struct ExpensiveInner;

    impl MountSource for ExpensiveInner {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                Some(ListResult::Names(vec!["f".into()]))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(ratarmount_core::create_root_file_info())
            } else if path == "/f" {
                Some(FileInfo {
                    size: 1,
                    mtime: 0.0,
                    mode: ratarmount_core::S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                })
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(io::Cursor::new(vec![b'x'])))
        }
        fn is_immutable(&self) -> bool {
            true
        }
        fn member_seek_is_cheap(&self, _: &FileInfo) -> bool {
            false
        }
    }

    /// Regression: NFS reader LRU pin must see through the factory default wrap.
    #[test]
    fn file_version_layer_forwards_member_seek_is_cheap() {
        let inner = Arc::new(ExpensiveInner) as Arc<dyn MountSource>;
        let layer = FileVersionLayer::new(inner);
        let fi = layer.lookup("/f", 0).expect("file");
        assert!(
            !layer.member_seek_is_cheap(&fi),
            "FileVersionLayer must forward inner false"
        );
    }

    /// Regression: factory wraps every mount in FileVersionLayer; readdir must
    /// reach ZIP/MemIndex list_dirents instead of building a fat FileInfo map.
    #[test]
    fn file_version_layer_list_dirents_forwards_zip_without_fat_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("layer.zip");
        let a = b"alpha-payload\n";
        let b = b"bravo-bytes-here\n";
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
        let layer = FileVersionLayer::new(Arc::clone(&counted) as Arc<dyn MountSource>);

        let dents = layer
            .list_dirents("/")
            .expect("cheap dirents through layer");
        assert_eq!(
            counted.list_calls.load(Ordering::SeqCst),
            0,
            "FileVersionLayer::list_dirents must not call inner.list() (fat FileInfo map)"
        );
        let by_name: std::collections::BTreeMap<_, _> =
            dents.into_iter().map(|d| (d.name, d.size)).collect();
        assert_eq!(by_name.get("a.txt").copied(), Some(a.len() as u64));
        assert_eq!(by_name.get("b.bin").copied(), Some(b.len() as u64));

        let fi = layer.lookup("/a.txt", 0).expect("lookup");
        let mut r = layer.open(&fi, 0).unwrap();
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out).unwrap();
        assert_eq!(out, a);

        // Versions-folder dirents must be readable regular files, not bare
        // S_IFREG with permission bits 000 (regression: perm-less dirents).
        let vdents = layer
            .list_dirents("/a.txt.versions")
            .expect("versions dirents");
        assert_eq!(vdents.len(), 1);
        assert_eq!(vdents[0].name, "1");
        assert_eq!(
            vdents[0].mode,
            ratarmount_core::S_IFREG | 0o444,
            "version entries advertise read-only regular-file mode"
        );
    }

    /// Two versions of one file: `.versions` lists `1` then `2`, not archive-offset order.
    #[test]
    fn file_version_layer_list_dirents_n_ge_2_is_version_number_order() {
        struct TwoVersions;

        impl MountSource for TwoVersions {
            fn list(&self, path: &str) -> Option<ListResult> {
                if path == "/" {
                    Some(ListResult::Names(vec!["f".into()]))
                } else {
                    None
                }
            }
            fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
                if path == "/" {
                    Some(vec![CheapDirent {
                        name: "f".into(),
                        mode: ratarmount_core::S_IFREG | 0o644,
                        size: 2,
                    }])
                } else {
                    None
                }
            }
            fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
                if path == "/" {
                    return Some(ratarmount_core::create_root_file_info());
                }
                if path != "/f" {
                    return None;
                }
                Some(FileInfo {
                    size: if file_version <= 1 { 1 } else { 2 },
                    mtime: 0.0,
                    mode: ratarmount_core::S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                })
            }
            fn versions(&self, path: &str) -> u32 {
                if path == "/f" {
                    2
                } else {
                    0
                }
            }
            fn open(
                &self,
                _: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                Ok(Box::new(io::Cursor::new(vec![b'x'])))
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }

        let layer = FileVersionLayer::new(Arc::new(TwoVersions) as Arc<dyn MountSource>);
        let root = layer.list_dirents("/").expect("root");
        assert_eq!(
            root.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["f"],
            "plain directory stays inner list_dirents order"
        );
        let vdents = layer
            .list_dirents("/f.versions")
            .expect("n>=2 versions dirents");
        let names: Vec<&str> = vdents.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["1", "2"],
            "versions folder is 1..=n, not offset order of the two versions"
        );
        assert_eq!(vdents[0].mode, ratarmount_core::S_IFREG | 0o444);
        assert_eq!(vdents[1].mode, ratarmount_core::S_IFREG | 0o444);
    }
}
