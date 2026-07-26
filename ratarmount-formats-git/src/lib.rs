//! Git repository tree MountSource (`backendName=GitMountSource`).
//!
//! Opens a git repository (worktree with `.git`, or bare) and mounts the tree at
//! HEAD (or a given ref) as a live filesystem-style MountSource (no SQLite index).

use std::collections::BTreeMap;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use git2::{ObjectType, Oid, Repository, Tree};
use ratarmount_core::{
    create_root_file_info, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};
use thiserror::Error;

pub const BACKEND_NAME: &str = "GitMountSource";

#[derive(Debug, Error)]
pub enum GitError {
    #[error(transparent)]
    Git(#[from] git2::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, GitError>;

/// True if `path` is a git worktree (has `.git`) or a bare repository.
pub fn looks_like_git(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    if path.join(".git").exists() {
        return true;
    }
    // Bare repo heuristics: HEAD + objects/ + refs/
    path.join("HEAD").is_file() && path.join("objects").is_dir() && path.join("refs").is_dir()
}

fn git_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("git:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("git:") => Some(s[4..].to_string()),
        _ => None,
    })
}

fn normalize_vpath(path: &str) -> String {
    let p = path.trim_matches('/');
    if p.is_empty() {
        String::new()
    } else {
        p.to_string()
    }
}

pub struct GitMountSource {
    #[allow(dead_code)]
    repo_path: PathBuf,
    /// Commit time (unix seconds) for mtime of all entries.
    commit_time: i64,
    /// Tree oid at the resolved ref.
    tree_oid: Oid,
    /// Optional prefix inside the tree (like Python `prefix`).
    prefix: String,
    /// Keep repository open under a mutex (git2 Repository is not Sync).
    repo: Mutex<Repository>,
}

impl GitMountSource {
    pub fn open(path: impl AsRef<Path>, reference: Option<&str>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_git(path) {
            return Err(GitError::Msg(format!(
                "{} is not a git repository",
                path.display()
            )));
        }
        let repo = Repository::open(path)?;
        let reference = reference
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_reference(&repo));

        let (tree_oid, commit_time) = {
            let obj = repo
                .revparse_single(&reference)
                .or_else(|_| repo.revparse_single("HEAD"))?;
            let commit = obj
                .peel_to_commit()
                .map_err(|e| GitError::Msg(format!("ref {reference} is not a commit: {e}")))?;
            let tree = commit.tree()?;
            let commit_time = commit.time().seconds();
            let tree_oid = tree.id();
            // Drop commit/tree/obj before moving repo into Mutex.
            drop(tree);
            drop(commit);
            drop(obj);
            (tree_oid, commit_time)
        };

        Ok(Self {
            repo_path: path.to_path_buf(),
            commit_time,
            tree_oid,
            prefix: String::new(),
            repo: Mutex::new(repo),
        })
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = normalize_vpath(&prefix.into());
        self
    }

    fn with_repo<R>(&self, f: impl FnOnce(&Repository) -> Result<R>) -> Result<R> {
        let repo = self
            .repo
            .lock()
            .map_err(|_| GitError::Msg("git repo lock poisoned".into()))?;
        f(&repo)
    }

    fn root_tree<'a>(&self, repo: &'a Repository) -> Result<Tree<'a>> {
        let obj = repo.find_object(self.tree_oid, Some(ObjectType::Tree))?;
        Ok(obj.peel_to_tree()?)
    }

    /// Look up a virtual path under prefix+path → git object.
    fn look_up_path<'a>(
        &self,
        repo: &'a Repository,
        path: &str,
    ) -> Result<Option<git2::Object<'a>>> {
        let tree = self.root_tree(repo)?;
        let mut parts: Vec<&str> = Vec::new();
        if !self.prefix.is_empty() {
            parts.extend(self.prefix.split('/').filter(|s| !s.is_empty()));
        }
        let rel = normalize_vpath(path);
        if !rel.is_empty() {
            parts.extend(rel.split('/').filter(|s| !s.is_empty()));
        }
        if parts.is_empty() {
            return Ok(Some(tree.into_object()));
        }
        let mut current = tree.into_object();
        for name in parts {
            let tree = match current.into_tree() {
                Ok(t) => t,
                Err(_) => return Ok(None),
            };
            let entry = match tree.get_name(name) {
                Some(e) => e,
                None => return Ok(None),
            };
            current = entry.to_object(repo)?;
        }
        Ok(Some(current))
    }

    fn convert_mode(obj: &git2::Object<'_>, filemode: i32) -> u32 {
        // git filemodes: 0o100644, 0o100755, 0o120000 (link), 0o040000 (tree), 0o160000 (submodule)
        if filemode == 0o120000 {
            return libc::S_IFLNK | 0o555;
        }
        match obj.kind() {
            Some(ObjectType::Tree) => libc::S_IFDIR | 0o555,
            _ => {
                let exec = filemode & 0o111 != 0;
                let perms = if exec { 0o555 } else { 0o444 };
                libc::S_IFREG | perms
            }
        }
    }

    fn object_to_file_info(
        &self,
        repo: &Repository,
        obj: &git2::Object<'_>,
        vpath: &str,
        filemode: i32,
    ) -> Result<FileInfo> {
        let mode = Self::convert_mode(obj, filemode);
        let (size, linkname) = if mode & libc::S_IFMT == libc::S_IFLNK {
            let blob = obj.peel_to_blob()?;
            let target = String::from_utf8_lossy(blob.content()).into_owned();
            (0, target)
        } else if mode & libc::S_IFMT == libc::S_IFDIR {
            (0, String::new())
        } else if let Ok(blob) = obj.peel_to_blob() {
            (blob.size() as u64, String::new())
        } else {
            (0, String::new())
        };
        let _ = repo;
        Ok(FileInfo {
            size,
            mtime: self.commit_time as f64,
            mode,
            linkname,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            userdata: vec![git_path_userdata(vpath)],
        })
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        self.with_repo(|repo| {
            let obj = match self.look_up_path(repo, path)? {
                Some(o) => o,
                None => return Ok(None),
            };
            let tree = match obj.into_tree() {
                Ok(t) => t,
                Err(_) => return Ok(None),
            };
            let mut map = BTreeMap::new();
            for entry in tree.iter() {
                let name = match entry.name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let child_v = {
                    let base = normalize_vpath(path);
                    if base.is_empty() {
                        format!("/{name}")
                    } else {
                        format!("/{base}/{name}")
                    }
                };
                let child = entry.to_object(repo)?;
                let fi = self.object_to_file_info(repo, &child, &child_v, entry.filemode())?;
                map.insert(name, fi);
            }
            Ok(Some(map))
        })
        .ok()
        .flatten()
    }
}

fn default_reference(repo: &Repository) -> String {
    if let Ok(head) = repo.head() {
        if let Some(name) = head.shorthand() {
            return name.to_string();
        }
    }
    for branch in ["master", "main"] {
        if repo.find_reference(&format!("refs/heads/{branch}")).is_ok() {
            return branch.to_string();
        }
    }
    "HEAD".into()
}

impl MountSource for GitMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let map = self.list_dir(path)?;
        Some(ListResult::Infos(map))
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let map = self.list_dir(path)?;
        Some(ListModeResult::Modes(
            map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
        ))
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path_n = if path == "/" || path.is_empty() {
            return Some(create_root_file_info());
        } else {
            path
        };
        self.with_repo(|repo| {
            let obj = match self.look_up_path(repo, path_n)? {
                Some(o) => o,
                None => return Ok(None),
            };
            // Recover filemode from parent tree when possible.
            let rel = normalize_vpath(path_n);
            let filemode = if rel.is_empty() {
                0o040000
            } else {
                let (parent, name) = match rel.rsplit_once('/') {
                    Some((p, n)) => (p, n),
                    None => ("", rel.as_str()),
                };
                let parent_obj = self.look_up_path(repo, parent)?;
                parent_obj
                    .and_then(|o| o.into_tree().ok())
                    .and_then(|t| t.get_name(name).map(|e| e.filemode()))
                    .unwrap_or(0o100644)
            };
            let vpath = if path_n.starts_with('/') {
                path_n.to_string()
            } else {
                format!("/{path_n}")
            };
            Ok(Some(
                self.object_to_file_info(repo, &obj, &vpath, filemode)?,
            ))
        })
        .ok()
        .flatten()
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
        if file_info.mode & libc::S_IFMT == libc::S_IFLNK {
            return Ok(Box::new(Cursor::new(
                file_info.linkname.as_bytes().to_vec(),
            )));
        }
        let path = path_from_userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing git path userdata")
        })?;
        let data = self
            .with_repo(|repo| {
                let obj = self
                    .look_up_path(repo, &path)?
                    .ok_or_else(|| GitError::Msg(format!("not found: {path}")))?;
                let blob = obj.peel_to_blob()?;
                Ok(blob.content().to_vec())
            })
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_ratarmount_rs_repo() {
        let path = PathBuf::from("/home/mbrewer/projects/ratarmount-rs");
        if !looks_like_git(&path) {
            return;
        }
        let m = GitMountSource::open(&path, None).unwrap();
        let list = m.list("/").expect("list root");
        match list {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("Cargo.toml") || map.contains_key("README.md"),
                    "keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            _ => panic!("expected infos"),
        }
        if let Some(fi) = m.lookup("/Cargo.toml", 0) {
            assert!(fi.size > 0);
            let mut r = m.open(&fi, 0).unwrap();
            let mut s = String::new();
            r.read_to_string(&mut s).unwrap();
            assert!(s.contains("[workspace]") || s.contains("ratarmount"));
        }
    }
}
