//! Bind-mount a real directory (Python `FolderMountSource`).

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use ratarmount_core::{
    create_root_file_info, metadata_gid, metadata_mode, metadata_mtime_secs, metadata_uid,
    normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
    UserData, S_IFDIR, S_IFLNK, S_IFMT,
};
use ratarmount_index::{locate_pattern_matches, DEFAULT_SEARCH_LIMIT};

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
            mtime: metadata_mtime_secs(&meta) as f64,
            mode: metadata_mode(&meta),
            linkname,
            uid: metadata_uid(&meta),
            gid: metadata_gid(&meta),
            userdata: vec![UserData::Other(virtual_path.to_string())],
        })
    }

    /// True when `parent`'s canonical path stays under [`Self::root`].
    ///
    /// Checks the parent, not the final component: `open` follows a final
    /// symlink today. Used so locate does not walk names that escaped via an
    /// intermediate `..` / parent symlink.
    fn parent_stays_under_root(&self, host_path: &Path) -> bool {
        let Some(parent) = host_path.parent() else {
            return false;
        };
        match fs::canonicalize(parent) {
            Ok(canon) => canon.starts_with(&self.root),
            Err(_) => false,
        }
    }

    /// Host-tree glob. `read_dir` + `symlink_metadata` on hits; never [`Self::list`].
    fn walk_search(
        &self,
        mount_dir: &str,
        host_dir: &Path,
        pattern: &str,
        hits: &mut Vec<CheapSearchHit>,
    ) {
        if hits.len() >= DEFAULT_SEARCH_LIMIT {
            return;
        }
        let meta = match fs::symlink_metadata(host_dir) {
            Ok(m) => m,
            Err(_) => return,
        };
        // Do not recurse S_IFLNK directories (would leak /etc via a planted link).
        if metadata_mode(&meta) & S_IFMT == S_IFLNK {
            return;
        }
        if metadata_mode(&meta) & S_IFMT != S_IFDIR {
            return;
        }
        match fs::canonicalize(host_dir) {
            Ok(canon) if canon.starts_with(&self.root) => {}
            _ => return,
        }
        let rd = match fs::read_dir(host_dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        for ent in rd.flatten() {
            if hits.len() >= DEFAULT_SEARCH_LIMIT {
                break;
            }
            let name = ent.file_name().to_string_lossy().into_owned();
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let child_host = host_dir.join(&name);
            if !self.parent_stays_under_root(&child_host) {
                continue;
            }
            let child_mount = if mount_dir == "/" {
                format!("/{name}")
            } else {
                format!("{mount_dir}/{name}")
            };
            let child_meta = match fs::symlink_metadata(&child_host) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let ifmt = metadata_mode(&child_meta) & S_IFMT;
            if ifmt == S_IFDIR {
                self.walk_search(&child_mount, &child_host, pattern, hits);
                continue;
            }
            if !locate_pattern_matches(pattern, &child_mount, &name) {
                continue;
            }
            hits.push(CheapSearchHit {
                path: child_mount,
                name,
                size: child_meta.len() as i64,
                mtime: metadata_mtime_secs(&child_meta) as f64,
                offsetheader: None,
            });
        }
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

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let real = self.realpath(path);
        let rd = fs::read_dir(&real).ok()?;
        let mut dents = Vec::new();
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            // Skip unreadable children (EACCES, race). Do not `?` — that would
            // turn one bad sibling into ENOENT for the whole directory.
            if let Ok(meta) = fs::symlink_metadata(ent.path()) {
                dents.push(CheapDirent {
                    name,
                    mode: metadata_mode(&meta),
                    size: meta.len(),
                });
            }
        }
        Some(dents)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let dents = self.list_dirents(path)?;
        Some(ListModeResult::Modes(
            dents.into_iter().map(|d| (d.name, d.mode)).collect(),
        ))
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        let real = self.realpath(&path);
        Self::file_info_for(&real, &path).ok()
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return None;
        }
        if pattern.is_empty() {
            return Some(Vec::new());
        }
        let mut hits = Vec::new();
        self.walk_search("/", &self.root, pattern, &mut hits);
        hits.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.offsetheader.cmp(&b.offsetheader))
        });
        hits.truncate(DEFAULT_SEARCH_LIMIT);
        Some(hits)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Regression: `dir1 dir2` readdir built `FileInfo` / called fat `list()`.
    /// Default `list_dirents` zeros sizes; matching `symlink_metadata` proves
    /// we did not take that path.
    #[test]
    fn folder_list_dirents_sizes_without_building_fileinfo_map() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.bin");
        std::fs::write(&a, b"alpha-payload\n").unwrap();
        std::fs::write(&b, b"bravo-bytes-here\n").unwrap();
        let src = FolderMountSource::new(dir.path()).unwrap();

        let dents = src
            .list_dirents("/")
            .expect("folder list_dirents must return Some");
        let by_name: std::collections::BTreeMap<_, _> = dents
            .into_iter()
            .map(|d| (d.name, (d.mode, d.size)))
            .collect();

        for name in ["a.txt", "b.bin"] {
            let meta = fs::symlink_metadata(dir.path().join(name)).unwrap();
            let (mode, size) = by_name.get(name).copied().expect(name);
            assert_eq!(mode, metadata_mode(&meta), "{name} mode");
            assert_eq!(size, meta.len(), "{name} size");
        }
    }

    /// A chmod-000 sibling must not drop the other names. On Linux as owner
    /// (or root), `symlink_metadata` still succeeds after chmod 000, so both
    /// names remain; the skip path is `if let Ok(meta)` and would drop only
    /// the failing child, never the whole directory.
    #[test]
    fn folder_list_dirents_chmod_000_sibling_does_not_drop_others() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep.txt");
        let locked = dir.path().join("locked.txt");
        std::fs::write(&keep, b"visible\n").unwrap();
        std::fs::write(&locked, b"secret\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let src = FolderMountSource::new(dir.path()).unwrap();

        let dents = src
            .list_dirents("/")
            .expect("one unreadable sibling must not ENOENT the directory");
        let names: std::collections::HashSet<_> = dents.into_iter().map(|d| d.name).collect();
        assert!(
            names.contains("keep.txt"),
            "chmod-000 sibling must not drop keep.txt: {names:?}"
        );
        // Owner/root can still stat chmod-000, so locked.txt usually remains.
        // The skip path (`if let Ok(meta)`) would drop only that child.
    }
}
