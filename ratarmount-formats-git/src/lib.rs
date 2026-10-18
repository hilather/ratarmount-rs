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
    create_root_file_info, CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};
use thiserror::Error;

mod synthetic;
#[cfg(all(test, unix))]
mod synthetic_tests;

pub const COMMIT_XATTR: &str = "user.ratarmount.git.commit";

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

/// Split a local `repo@revision` only when its repository exists. An existing
/// literal path wins, so repositories whose names contain `@` remain usable.
pub fn split_inline_reference(path: &Path) -> Option<(PathBuf, String)> {
    if path.exists() {
        return None;
    }
    let text = path.to_str()?;
    for (at, _) in text.rmatch_indices('@') {
        let candidate = Path::new(&text[..at]);
        if looks_like_git(candidate) {
            return Some((candidate.to_path_buf(), text[at + 1..].to_owned()));
        }
    }
    None
}

/// Parse a local `git:///absolute/path#revision` alias. The fragment defaults to HEAD.
/// `@` is always part of the path here, unlike the legacy inline-ref syntax.
pub fn parse_git_url(input: &str) -> Result<Option<(PathBuf, Option<String>)>> {
    let Some(local) = input.strip_prefix("git://") else {
        return Ok(None);
    };
    if !local.starts_with('/') {
        return Err(GitError::Msg(
            "network git URLs are not supported; clone locally".into(),
        ));
    }
    let (encoded, reference) = match local.split_once('#') {
        Some((path, "")) => return Err(GitError::Msg(format!("empty git revision in {path}"))),
        Some((path, reference)) => (path, Some(reference.to_owned())),
        None => (local, None),
    };
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut bytes = encoded.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(if byte == b'%' {
            let hi = bytes.next().and_then(|b| (b as char).to_digit(16));
            let lo = bytes.next().and_then(|b| (b as char).to_digit(16));
            match (hi, lo) {
                (Some(hi), Some(lo)) => (hi * 16 + lo) as u8,
                _ => {
                    return Err(GitError::Msg(
                        "invalid percent escape in git URL path".into(),
                    ))
                }
            }
        } else {
            byte
        });
    }
    if decoded.contains(&0) {
        return Err(GitError::Msg("NUL in git URL path".into()));
    }
    let path = String::from_utf8(decoded)
        .map_err(|_| GitError::Msg("git URL path must be UTF-8".into()))?;
    Ok(Some((PathBuf::from(path), reference)))
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
    repo_path: PathBuf,
    /// Commit time (unix seconds) for mtime of all entries.
    commit_time: i64,
    /// Tree oid at the resolved ref.
    tree_oid: Oid,
    commit_oid: Oid,
    synthetic: Option<synthetic::SyntheticGit>,
    /// Keep repository open under a mutex (git2 Repository is not Sync).
    repo: Mutex<Repository>,
}

impl GitMountSource {
    /// Object id of the selected tree, including any `with_prefix` subtree.
    pub fn tree_id(&self) -> String {
        self.tree_oid.to_string()
    }

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

        let (tree_oid, commit_time, commit_oid) = {
            let obj = repo
                .revparse_single(&reference)
                .map_err(|e| GitError::Msg(format!("cannot resolve git ref {reference:?}: {e}")))?;
            let commit = obj
                .peel_to_commit()
                .map_err(|e| GitError::Msg(format!("ref {reference} is not a commit: {e}")))?;
            let tree = commit.tree()?;
            let commit_time = commit.time().seconds();
            let tree_oid = tree.id();
            let commit_oid = commit.id();
            // Drop commit/tree/obj before moving repo into Mutex.
            drop(tree);
            drop(commit);
            drop(obj);
            (tree_oid, commit_time, commit_oid)
        };

        log::info!(
            "git: {} ref {reference:?} resolved to {commit_oid}",
            path.display()
        );
        Ok(Self {
            repo_path: repo.path().canonicalize()?,
            commit_time,
            tree_oid,
            commit_oid,
            synthetic: None,
            repo: Mutex::new(repo),
        })
    }

    /// Select a subtree before creating the synthetic repository.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Result<Self> {
        if self.synthetic.is_some() {
            return Err(GitError::Msg(
                "select --git-prefix before synthetic HEAD".into(),
            ));
        }
        let prefix = normalize_vpath(&prefix.into());
        self.tree_oid = self.with_repo(|repo| {
            let obj = self
                .look_up_path(repo, &prefix)?
                .ok_or_else(|| GitError::Msg(format!("git prefix {prefix:?} does not exist")))?;
            obj.into_tree()
                .map(|t| t.id())
                .map_err(|_| GitError::Msg(format!("git prefix {prefix:?} is not a directory")))
        })?;
        Ok(self)
    }

    pub fn resolved_commit(&self) -> Oid {
        self.commit_oid
    }

    /// Object ID of the selected tree (including `--git-prefix`, when applied).
    pub fn tree_id(&self) -> String {
        self.tree_oid.to_string()
    }

    /// Cache a standalone repository and expose its files under `/.git`.
    pub fn with_synthetic_head(mut self, cache_root: &Path) -> Result<Self> {
        self.synthetic = Some(self.with_repo(|repo| {
            synthetic::SyntheticGit::build(
                repo,
                &self.repo_path,
                self.commit_oid,
                self.tree_oid,
                self.commit_time,
                cache_root,
            )
        })?);
        Ok(self)
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

    /// Look up a virtual path in the selected tree.
    fn look_up_path<'a>(
        &self,
        repo: &'a Repository,
        path: &str,
    ) -> Result<Option<git2::Object<'a>>> {
        let tree = self.root_tree(repo)?;
        let mut parts: Vec<&str> = Vec::new();
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
            if entry.filemode() == 0o160000 {
                return Ok(None);
            }
            current = entry.to_object(repo)?;
        }
        Ok(Some(current))
    }

    fn convert_mode(&self, obj: &git2::Object<'_>, filemode: i32) -> u32 {
        // git filemodes: 0o100644, 0o100755, 0o120000 (link), 0o040000 (tree), 0o160000 (submodule)
        if filemode == 0o120000 {
            return ratarmount_core::S_IFLNK | 0o777;
        }
        match obj.kind() {
            Some(ObjectType::Tree) => ratarmount_core::S_IFDIR | 0o755,
            _ => ratarmount_core::S_IFREG | if filemode & 0o111 != 0 { 0o755 } else { 0o644 },
        }
    }

    fn object_to_file_info(
        &self,
        repo: &Repository,
        obj: &git2::Object<'_>,
        vpath: &str,
        filemode: i32,
    ) -> Result<FileInfo> {
        let mode = self.convert_mode(obj, filemode);
        let (size, linkname) = if mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK {
            let blob = obj.peel_to_blob()?;
            let target = String::from_utf8_lossy(blob.content()).into_owned();
            (
                if self.synthetic.is_some() {
                    blob.size() as u64
                } else {
                    0
                },
                target,
            )
        } else if mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
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
            uid: ratarmount_core::effective_uid(),
            gid: ratarmount_core::effective_gid(),
            userdata: vec![git_path_userdata(vpath)],
        })
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        if let Some(synthetic) = &self.synthetic {
            if synthetic::is_git_path(path) {
                return synthetic.list(path);
            }
        }
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
                if entry.filemode() == 0o160000 {
                    ratarmount_core::eprintln!("warning: skipping Git submodule {path}/{name}");
                    continue;
                }
                let child = entry.to_object(repo)?;
                let fi = self.object_to_file_info(repo, &child, &child_v, entry.filemode())?;
                map.insert(name, fi);
            }
            if normalize_vpath(path).is_empty() {
                if let Some(synthetic) = &self.synthetic {
                    map.insert(".git".into(), synthetic.lookup("/.git").unwrap());
                }
            }
            Ok(Some(map))
        })
        .ok()
        .flatten()
    }

    /// Cheap readdir: tree entry `filemode` + blob `size()`, no `FileInfo` userdata.
    fn list_dirents_inner(&self, path: &str) -> Option<Vec<CheapDirent>> {
        if self.synthetic.is_some() && synthetic::is_git_path(path) {
            return self.list_dir(path).map(|map| {
                map.into_iter()
                    .map(|(name, fi)| CheapDirent {
                        name,
                        mode: fi.mode,
                        size: fi.size,
                    })
                    .collect()
            });
        }
        self.with_repo(|repo| {
            let obj = match self.look_up_path(repo, path)? {
                Some(o) => o,
                None => return Ok(None),
            };
            let tree = match obj.into_tree() {
                Ok(t) => t,
                Err(_) => return Ok(None),
            };
            let mut dents = Vec::new();
            for entry in tree.iter() {
                let name = match entry.name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                if entry.filemode() == 0o160000 {
                    ratarmount_core::eprintln!("warning: skipping Git submodule {path}/{name}");
                    continue;
                }
                let child = entry.to_object(repo)?;
                let mode = self.convert_mode(&child, entry.filemode());
                let size = if mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFREG
                    || (self.synthetic.is_some()
                        && mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK)
                {
                    child.peel_to_blob().map(|b| b.size() as u64).unwrap_or(0)
                } else {
                    0
                };
                dents.push(CheapDirent { name, mode, size });
            }
            if self.synthetic.is_some() && normalize_vpath(path).is_empty() {
                dents.push(CheapDirent {
                    name: ".git".into(),
                    mode: ratarmount_core::S_IFDIR | 0o755,
                    size: 0,
                });
            }
            Ok(Some(dents))
        })
        .ok()
        .flatten()
    }
}

fn default_reference(repo: &Repository) -> String {
    if repo.head().is_ok() {
        return "HEAD".into();
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

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.list_dirents_inner(path)
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        if let Some(synthetic) = &self.synthetic {
            if synthetic::is_git_path(path) {
                return synthetic.lookup(path);
            }
        }
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
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK {
            return Ok(Box::new(Cursor::new(
                file_info.linkname.as_bytes().to_vec(),
            )));
        }
        let path = path_from_userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing git path userdata")
        })?;
        if let Some(synthetic) = &self.synthetic {
            if synthetic::is_git_path(&path) {
                return synthetic.open(&path);
            }
        }
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

    fn list_xattr(&self, _file_info: &FileInfo) -> Vec<String> {
        if self.synthetic.is_some() {
            Vec::new()
        } else {
            vec![COMMIT_XATTR.into()]
        }
    }

    fn get_xattr(&self, _file_info: &FileInfo, key: &str) -> Option<Vec<u8>> {
        (self.synthetic.is_none() && key == COMMIT_XATTR)
            .then(|| self.commit_oid.to_string().into_bytes())
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: URL fragments select refs without interpreting `@` in directory names.
    #[test]
    fn regression_git_url_local_paths_and_at_names() {
        for (url, path, reference) in [
            (
                "git:///srv/my%20repo%40home.git#release@1",
                "/srv/my repo@home.git",
                Some("release@1"),
            ),
            ("git:///srv/repo/.git", "/srv/repo/.git", None),
            (
                "git:///srv/repo%23one%25.git#HEAD~1",
                "/srv/repo#one%.git",
                Some("HEAD~1"),
            ),
            ("git:///srv/a+b@c#HEAD", "/srv/a+b@c", Some("HEAD")),
        ] {
            assert_eq!(
                parse_git_url(url).unwrap(),
                Some((PathBuf::from(path), reference.map(str::to_owned)))
            );
        }
        assert!(parse_git_url("/srv/repo@HEAD").unwrap().is_none());
        for url in [
            "git://host/repo#HEAD",
            "git://localhost/repo",
            "git://user@host/repo",
        ] {
            assert_eq!(
                parse_git_url(url).unwrap_err().to_string(),
                "network git URLs are not supported; clone locally"
            );
        }
        for url in [
            "git:///srv/repo%",
            "git:///srv/repo%2",
            "git:///srv/%xx",
            "git:///srv/%00",
            "git:///srv/%ff",
            "git:///srv/repo#",
        ] {
            assert!(parse_git_url(url).is_err(), "{url}");
        }
    }

    /// Regression: gitlinks with absent objects must not hide their sibling files.
    #[test]
    fn regression_git_gitlink_skipped_and_committed_modes_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let repo = Repository::init_bare(temp.path()).unwrap();
        let empty = repo.treebuilder(None).unwrap().write().unwrap();
        let mut tree = repo.treebuilder(None).unwrap();
        tree.insert("dir", empty, 0o040000).unwrap();
        tree.insert("file", repo.blob(b"contents").unwrap(), 0o100644)
            .unwrap();
        tree.insert("run", repo.blob(b"script").unwrap(), 0o100755)
            .unwrap();
        tree.insert("link", repo.blob(b"file").unwrap(), 0o120000)
            .unwrap();
        // A gitlink's target is normally absent in the superproject object database.
        tree.insert(
            "module",
            Oid::from_str("1234567890123456789012345678901234567890").unwrap(),
            0o160000,
        )
        .unwrap();
        let tree_id = tree.write().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature =
            git2::Signature::new("Test", "test@example.com", &git2::Time::new(1234567890, 0))
                .unwrap();
        repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
            .unwrap();
        let source = GitMountSource::open(temp.path(), Some("HEAD")).unwrap();
        assert_eq!(
            format!("git-tree:{}", source.tree_id()),
            format!("git-tree:{tree_id}")
        );
        assert!(source.is_immutable());
        let Some(ListResult::Infos(infos)) = source.list("/") else {
            panic!("missing listing")
        };
        assert!(!infos.contains_key("module"));
        assert!(source.lookup("/module", 0).is_none());
        let dents = source.list_dirents("/").unwrap();
        assert_eq!(dents.len(), 4);
        for (name, mode) in [
            ("dir", 0o040755),
            ("file", 0o100644),
            ("run", 0o100755),
            ("link", 0o120777),
        ] {
            assert_eq!(infos[name].mode, mode);
            assert_eq!(source.lookup(name, 0).unwrap().mode, mode);
            assert_eq!(dents.iter().find(|d| d.name == name).unwrap().mode, mode);
        }
        assert_eq!(source.lookup("link", 0).unwrap().linkname, "file");
        assert_eq!(
            source.with_prefix("dir").unwrap().tree_id(),
            empty.to_string()
        );
    }

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

    fn commit_workdir(dir: &Path) -> git2::Repository {
        let repo = git2::Repository::init(dir).unwrap();
        let mut index = repo.index().unwrap();
        index
            .add_all(["."].iter(), git2::IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = git2::Signature::now("ratarmount", "ratarmount@example.test").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
            .unwrap();
        drop(tree);
        repo
    }

    /// Regression: cheap readdirplus sizes.
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let dir = tempfile::tempdir().unwrap();
        let hello = b"hello-git-dirents";
        std::fs::write(dir.path().join("hello.txt"), hello).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("nested.bin"), b"abcd").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let exec = dir.path().join("run.sh");
            std::fs::write(&exec, b"#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::os::unix::fs::symlink("hello.txt", dir.path().join("link")).unwrap();
        }
        let _repo = commit_workdir(dir.path());

        let src = GitMountSource::open(dir.path(), None).unwrap();
        let dents = src.list_dirents("/").expect("dirents");
        let by_name: BTreeMap<_, _> = dents
            .into_iter()
            .map(|d| (d.name, (d.mode, d.size)))
            .collect();

        let hello_fi = src.lookup("/hello.txt", 0).expect("lookup hello.txt");
        let (hello_mode, hello_size) = by_name.get("hello.txt").copied().expect("hello.txt dirent");
        assert_eq!(hello_size, hello.len() as u64);
        assert_eq!(hello_size, hello_fi.size);
        assert_eq!(hello_mode, hello_fi.mode);
        assert_eq!(
            hello_mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFREG
        );

        let sub_fi = src.lookup("/sub", 0).expect("lookup sub");
        let (sub_mode, sub_size) = by_name.get("sub").copied().expect("sub dirent");
        assert_eq!(sub_size, 0);
        assert_eq!(sub_size, sub_fi.size);
        assert_eq!(sub_mode, sub_fi.mode);
        assert_eq!(sub_mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);

        #[cfg(unix)]
        {
            let link_fi = src.lookup("/link", 0).expect("lookup link");
            let (link_mode, link_size) = by_name.get("link").copied().expect("link dirent");
            assert_eq!(link_size, 0);
            assert_eq!(link_size, link_fi.size);
            assert_eq!(link_mode, link_fi.mode);
            assert_eq!(
                link_mode & ratarmount_core::S_IFMT,
                ratarmount_core::S_IFLNK
            );

            let run_fi = src.lookup("/run.sh", 0).expect("lookup run.sh");
            let (run_mode, run_size) = by_name.get("run.sh").copied().expect("run.sh dirent");
            assert_eq!(run_size, run_fi.size);
            assert_eq!(run_mode, run_fi.mode);
            assert_eq!(run_mode & 0o111, 0o111);
        }

        let nested = src.list_dirents("/sub").expect("sub dirents");
        let n = nested.iter().find(|e| e.name == "nested.bin").unwrap();
        assert_eq!(n.size, 4);
        assert_eq!(src.lookup("/sub/nested.bin", 0).unwrap().size, n.size);
        assert_eq!(src.lookup("/sub/nested.bin", 0).unwrap().mode, n.mode);

        assert!(src.list_dirents("/hello.txt").is_none());
    }
}
