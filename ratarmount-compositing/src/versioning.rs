//! File version path API: `<path>.versions/<n>` (Python `FileVersionLayer`).
//!
//! Version 1 is oldest; higher numbers are newer. The most recent version is also
//! available at the plain path (file_version 0).

use std::io;
use std::sync::Arc;

use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, UserData,
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
            mode: libc::S_IFDIR | 0o755,
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
        match self.list(path)? {
            ListResult::Names(n) => Some(ListModeResult::Names(n)),
            ListResult::Infos(m) => Some(ListModeResult::Modes(
                m.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
        }
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

    fn statfs(&self) -> ratarmount_core::StatFs {
        self.inner.statfs()
    }
}


