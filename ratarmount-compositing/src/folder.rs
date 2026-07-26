//! Bind-mount a real directory (Python `FolderMountSource`).

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListResult, MountSource, UserData,
};

/// Expose a host directory as a MountSource.
pub struct FolderMountSource {
    root: PathBuf,
}

impl FolderMountSource {
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let root = path.as_ref().canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", root.display()),
            ));
        }
        Ok(Self { root })
    }

    fn realpath(&self, path: &str) -> PathBuf {
        let path = normpath(path);
        if path == "/" {
            return self.root.clone();
        }
        self.root.join(path.trim_start_matches('/'))
    }

    fn file_info_for(path: &Path, virtual_path: &str) -> io::Result<FileInfo> {
        let meta = fs::symlink_metadata(path)?;
        let linkname = if meta.file_type().is_symlink() {
            fs::read_link(path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(FileInfo {
            size: meta.len(),
            mtime: meta.mtime() as f64,
            mode: meta.mode(),
            linkname,
            uid: meta.uid(),
            gid: meta.gid(),
            userdata: vec![UserData::Other(virtual_path.to_string())],
        })
    }
}

impl MountSource for FolderMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let real = self.realpath(path);
        let rd = fs::read_dir(&real).ok()?;
        let mut map = std::collections::BTreeMap::new();
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            let child_v = if normpath(path) == "/" {
                format!("/{name}")
            } else {
                format!("{}/{name}", normpath(path))
            };
            if let Ok(fi) = Self::file_info_for(&ent.path(), &child_v) {
                map.insert(name, fi);
            }
        }
        Some(ListResult::Infos(map))
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        let real = self.realpath(&path);
        Self::file_info_for(&real, &path).ok()
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if file_info.mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let vpath = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Other(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path userdata"))?;
        let real = self.realpath(vpath);
        Ok(Box::new(File::open(real)?))
    }

    fn is_immutable(&self) -> bool {
        false
    }
}
