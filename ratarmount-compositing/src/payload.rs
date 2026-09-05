//! G-3 `PayloadCacheLayer`: serve hashed regular files from `payload-v1/`.
//!
//! Gate is `user.hash.sha256` on the inner source. Do not hash on cold `open`.
//! Overlay `userdata` (`overlay:`) is never cached (write overlay must stay
//! immediately consistent). Skip `:memory:` via [`maybe_wrap_payload_cache`].

use std::fs::File;
use std::io;
use std::sync::Arc;

use ratarmount_core::{
    CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource, UserData,
    S_IFMT, S_IFREG,
};
use ratarmount_index::PayloadCache;

const SHA256_XATTR: &str = "user.hash.sha256";

/// Read-through cache of decompressed member bodies keyed by sha256.
pub struct PayloadCacheLayer {
    inner: Arc<dyn MountSource>,
    cache: PayloadCache,
}

impl PayloadCacheLayer {
    pub fn new(inner: Arc<dyn MountSource>, cache: PayloadCache) -> Self {
        Self { inner, cache }
    }
}

/// Default-on when hashes exist and the cache is enabled. Skip `:memory:` and budget 0.
pub fn maybe_wrap_payload_cache(
    inner: Arc<dyn MountSource>,
    index_in_memory: bool,
) -> Arc<dyn MountSource> {
    match PayloadCache::from_env_for_index(index_in_memory) {
        Some(cache) if cache.is_enabled() => Arc::new(PayloadCacheLayer::new(inner, cache)),
        _ => inner,
    }
}

fn is_overlay_userdata(fi: &FileInfo) -> bool {
    fi.userdata
        .iter()
        .any(|u| matches!(u, UserData::Other(s) if s.starts_with("overlay:")))
}

fn is_regular_file(fi: &FileInfo) -> bool {
    fi.mode & S_IFMT == S_IFREG
}

fn sha256_from_xattr(inner: &dyn MountSource, fi: &FileInfo) -> Option<String> {
    let raw = inner.get_xattr(fi, SHA256_XATTR)?;
    let s = std::str::from_utf8(&raw).ok()?.trim();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(s.to_ascii_lowercase())
    } else {
        None
    }
}

impl MountSource for PayloadCacheLayer {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.inner.list(path)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        self.inner.list_mode(path)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.inner.list_dirents(path)
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.inner.lookup(path, file_version)
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        self.inner.search_cheap(pattern)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        // Overlay writes must stay immediately consistent — never serve a stale blob.
        if is_overlay_userdata(file_info) || !is_regular_file(file_info) {
            return self.inner.open(file_info, buffering);
        }
        if file_info.size == 0 || file_info.size > self.cache.member_max() {
            return self.inner.open(file_info, buffering);
        }
        let Some(sha) = sha256_from_xattr(self.inner.as_ref(), file_info) else {
            return self.inner.open(file_info, buffering);
        };
        match self.cache.get_or_fill(&sha, file_info.size, || {
            self.inner.open(file_info, buffering)
        }) {
            Ok(path) => match File::open(&path) {
                Ok(f) => Ok(Box::new(f) as Box<dyn ratarmount_core::ArchiveRead>),
                Err(_) => self.inner.open(file_info, buffering),
            },
            Err(_) => self.inner.open(file_info, buffering),
        }
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        if !is_overlay_userdata(file_info) && is_regular_file(file_info) {
            if let Some(sha) = sha256_from_xattr(self.inner.as_ref(), file_info) {
                if self.cache.lookup(&sha).is_some() {
                    return true;
                }
            }
        }
        self.inner.member_seek_is_cheap(file_info)
    }

    fn content_generation(&self) -> u64 {
        self.inner.content_generation()
    }

    fn versions(&self, path: &str) -> u32 {
        self.inner.versions(path)
    }

    fn statfs(&self) -> ratarmount_core::StatFs {
        self.inner.statfs()
    }

    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
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
    use crate::{FileVersionLayer, WriteOverlay};
    use ratarmount_core::{create_root_file_info, CheapDirent};
    use ratarmount_index::sha256_hex;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct HashedMem {
        name: String,
        body: Vec<u8>,
        sha: String,
        opens: AtomicUsize,
    }

    impl HashedMem {
        fn new(name: &str, body: &[u8]) -> Self {
            Self {
                name: name.to_string(),
                body: body.to_vec(),
                sha: sha256_hex(body),
                opens: AtomicUsize::new(0),
            }
        }

        fn file_info(&self) -> FileInfo {
            FileInfo {
                size: self.body.len() as u64,
                mtime: 0.0,
                mode: S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            }
        }
    }

    impl MountSource for HashedMem {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                let mut map = BTreeMap::new();
                map.insert(self.name.clone(), self.file_info());
                Some(ListResult::Infos(map))
            } else {
                None
            }
        }

        fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
            if path == "/" {
                Some(vec![CheapDirent {
                    name: self.name.clone(),
                    mode: S_IFREG | 0o644,
                    size: self.body.len() as u64,
                }])
            } else {
                None
            }
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(create_root_file_info());
            }
            if path == format!("/{}", self.name) {
                Some(self.file_info())
            } else {
                None
            }
        }

        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(std::io::Cursor::new(self.body.clone())))
        }

        fn is_immutable(&self) -> bool {
            true
        }

        fn list_xattr(&self, _: &FileInfo) -> Vec<String> {
            vec![SHA256_XATTR.to_string()]
        }

        fn get_xattr(&self, _: &FileInfo, key: &str) -> Option<Vec<u8>> {
            if key == SHA256_XATTR {
                Some(self.sha.as_bytes().to_vec())
            } else {
                None
            }
        }
    }

    /// Always reports `user.hash.sha256` (simulates a stale hash on overlay FileInfo).
    struct AlwaysHashXattr {
        inner: Arc<dyn MountSource>,
        sha: String,
    }

    impl MountSource for AlwaysHashXattr {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.inner.list(path)
        }
        fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
            self.inner.list_dirents(path)
        }
        fn lookup(&self, path: &str, v: i32) -> Option<FileInfo> {
            self.inner.lookup(path, v)
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
        fn get_xattr(&self, _: &FileInfo, key: &str) -> Option<Vec<u8>> {
            if key == SHA256_XATTR {
                Some(self.sha.as_bytes().to_vec())
            } else {
                None
            }
        }
        fn list_xattr(&self, _: &FileInfo) -> Vec<String> {
            vec![SHA256_XATTR.to_string()]
        }
    }

    fn overlay_write_bytes(ov: &WriteOverlay, path: &str, bytes: &[u8]) {
        let fd = ov.create_file(path, 0o644).expect("create");
        {
            use std::os::unix::io::FromRawFd;
            let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
            f.write_all(bytes).unwrap();
        }
        ov.release_write_fd(fd);
    }

    /// Regression: second `open` of a hashed member does not read the archive.
    #[test]
    fn payload_cache_second_open_skips_archive() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PayloadCache::with_dir(
            dir.path().join("payload-v1"),
            Some(4 * 1024 * 1024),
            64 * 1024 * 1024,
        );
        let inner = Arc::new(HashedMem::new("a.txt", b"hello-payload"));
        let layer = PayloadCacheLayer::new(Arc::clone(&inner) as _, cache);
        let fi = layer.lookup("/a.txt", 0).unwrap();
        let mut buf = Vec::new();
        layer.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello-payload");
        assert_eq!(inner.opens.load(Ordering::SeqCst), 1);
        buf.clear();
        layer.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello-payload");
        assert_eq!(
            inner.opens.load(Ordering::SeqCst),
            1,
            "second open must hit payload-v1"
        );
    }

    /// Regression: `user.hash.sha256` survives FileVersionLayer into PayloadCacheLayer.
    #[test]
    fn payload_cache_hashes_survive_file_version_layer() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PayloadCache::with_dir(
            dir.path().join("payload-v1"),
            Some(4 * 1024 * 1024),
            64 * 1024 * 1024,
        );
        let inner = Arc::new(HashedMem::new("a.txt", b"versioned-payload"));
        let vers = FileVersionLayer::new(Arc::clone(&inner) as Arc<dyn MountSource>);
        let layer = PayloadCacheLayer::new(Arc::new(vers) as _, cache);
        let fi = layer.lookup("/a.txt", 0).unwrap();
        assert!(
            fi.userdata
                .iter()
                .any(|u| matches!(u, UserData::Other(s) if s == "versionlayer:file")),
            "FileVersionLayer must tag lookup: {:?}",
            fi.userdata
        );
        assert_eq!(
            layer.get_xattr(&fi, SHA256_XATTR).as_deref(),
            Some(inner.sha.as_bytes())
        );
        let mut buf = Vec::new();
        layer.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"versioned-payload");
        assert_eq!(inner.opens.load(Ordering::SeqCst), 1);
        buf.clear();
        layer.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"versioned-payload");
        assert_eq!(
            inner.opens.load(Ordering::SeqCst),
            1,
            "second open through FileVersionLayer must hit payload-v1"
        );
    }

    /// Regression: overlay write of a hashed path must not serve the cached base.
    #[test]
    fn payload_cache_skips_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PayloadCache::with_dir(
            dir.path().join("payload-v1"),
            Some(4 * 1024 * 1024),
            64 * 1024 * 1024,
        );
        let base_body = b"hashed-base-payload";
        let inner = Arc::new(HashedMem::new("f.txt", base_body));
        let sha = inner.sha.clone();
        let layer_base = PayloadCacheLayer::new(Arc::clone(&inner) as _, cache.clone());
        let fi = layer_base.lookup("/f.txt", 0).unwrap();
        let mut buf = Vec::new();
        layer_base
            .open(&fi, 0)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(buf, base_body);
        let opens_after_cache = inner.opens.load(Ordering::SeqCst);

        let ovdir = dir.path().join("ov");
        std::fs::create_dir_all(&ovdir).unwrap();
        let ov = WriteOverlay::new(Arc::clone(&inner) as Arc<dyn MountSource>, &ovdir).unwrap();
        overlay_write_bytes(&ov, "/f.txt", b"NEW-OVERLAY-BYTES");
        let hashed = AlwaysHashXattr {
            inner: Arc::new(ov) as Arc<dyn MountSource>,
            sha: sha.clone(),
        };
        let layer = PayloadCacheLayer::new(Arc::new(hashed) as _, cache.clone());
        let fi = layer.lookup("/f.txt", 0).expect("overlay lookup");
        assert!(
            is_overlay_userdata(&fi),
            "overlay FileInfo must carry overlay: userdata, got {:?}",
            fi.userdata
        );
        buf.clear();
        layer.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(
            buf, b"NEW-OVERLAY-BYTES",
            "overlay open must not serve stale payload-v1"
        );
        assert_eq!(
            inner.opens.load(Ordering::SeqCst),
            opens_after_cache,
            "overlay open must not refill from the archive"
        );
        let cached = cache.lookup(&sha).expect("base blob stays");
        assert_eq!(
            std::fs::read(cached).unwrap(),
            base_body,
            "overlay bytes must not replace the sha256 blob"
        );
    }
}
