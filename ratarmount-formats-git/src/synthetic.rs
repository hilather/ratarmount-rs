//! A private object store, validated before publication and served without following links.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use git2::{Oid, Repository};
use ratarmount_core::{ArchiveRead, FileInfo, S_IFDIR, S_IFMT, S_IFREG};

use crate::{GitError, Result};

#[cfg(unix)]
use {
    crate::git_path_userdata,
    git2::{Index, ObjectType},
    sha1::{Digest, Sha1},
    std::{
        collections::BTreeSet,
        fs::{self, File},
        io::{Read, Write},
        path::Component,
        time::UNIX_EPOCH,
    },
};

#[cfg(unix)]
#[path = "secure_cache.rs"]
mod secure_cache;
#[cfg(unix)]
use secure_cache::{Directory, Stamp};

#[cfg(unix)]
const HEAD: &[u8] = b"ref: refs/heads/sandbox\n";
#[cfg(unix)]
pub(super) const CONFIG: &[u8] = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = true\n\tlogallrefupdates = false\n\tcheckStat = minimal\n\ttrustctime = false\n\tfsmonitor = false\n[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n";

pub(crate) struct SyntheticGit {
    #[cfg(unix)]
    root: Directory,
    #[cfg(unix)]
    stamps: BTreeMap<String, Stamp>,
    entries: BTreeMap<String, FileInfo>,
}

pub(crate) fn is_git_path(path: &str) -> bool {
    let path = path.trim_matches('/');
    path == ".git" || path.starts_with(".git/")
}

impl SyntheticGit {
    pub(crate) fn build(
        source: &Repository,
        repo_path: &Path,
        commit: Oid,
        tree: Oid,
        timestamp: i64,
        cache_root: &Path,
    ) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (source, repo_path, commit, tree, timestamp, cache_root);
            Err(GitError::Msg(
                "synthetic Git currently requires Unix no-follow cache access".into(),
            ))
        }
        #[cfg(unix)]
        {
            let cache = Directory::root(cache_root)?;
            // Lock the directory itself: no removable lock inode or stale new lock files.
            cache.0.lock()?;
            cache.reclaim(std::time::SystemTime::now())?;
            let repo_key =
                Oid::hash_object(ObjectType::Blob, repo_path.as_os_str().as_encoded_bytes())?;
            let key = format!("{repo_key}-{commit}-{tree}");
            let expected = expected_files(source, tree, timestamp)?;
            let root = match cache.child(key.as_ref()) {
                Ok(root) => root,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let (name, staging) = cache.staging()?;
                    let built = build_repository(source, tree, timestamp, &staging, &expected)
                        .and_then(|()| cache.publish(&name, key.as_ref()).map_err(Into::into));
                    if let Err(e) = built {
                        let _ = cache.discard(&name);
                        return Err(e);
                    }
                    staging
                }
                Err(e) => return Err(e.into()),
            };
            let mut entries = BTreeMap::new();
            let mut stamps = BTreeMap::new();
            let mut actual = BTreeSet::new();
            validate_directory(&root, "", &expected, &mut actual, &mut entries, &mut stamps)
                .map_err(|e| GitError::Msg(format!("invalid synthetic Git cache (unmount and remove the entry before retrying): {e}")))?;
            if actual != expected.keys().cloned().collect() {
                return Err(GitError::Msg(
                    "incomplete synthetic Git cache; remove the entry before retrying".into(),
                ));
            }
            Ok(Self {
                root,
                stamps,
                entries,
            })
        }
    }

    pub(crate) fn lookup(&self, path: &str) -> Option<FileInfo> {
        self.entries.get(path.trim_matches('/')).cloned()
    }

    pub(crate) fn list(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        let path = path.trim_matches('/');
        if self.entries.get(path)?.mode & S_IFMT != S_IFDIR {
            return None;
        }
        let prefix = format!("{path}/");
        Some(
            self.entries
                .range(prefix.clone()..)
                .take_while(|(name, _)| name.starts_with(&prefix))
                .filter_map(|(name, fi)| {
                    let child = &name[prefix.len()..];
                    (!child.contains('/')).then(|| (child.into(), fi.clone()))
                })
                .collect(),
        )
    }

    pub(crate) fn open(&self, path: &str) -> io::Result<Box<dyn ArchiveRead>> {
        let path = path.trim_matches('/');
        if !self
            .entries
            .get(path)
            .is_some_and(|fi| fi.mode & S_IFMT == S_IFREG)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no synthetic Git file",
            ));
        }
        #[cfg(unix)]
        {
            let mut dir = self.root.child(".".as_ref())?;
            let mut parts = path[5..].split('/').peekable();
            while let Some(part) = parts.next() {
                if parts.peek().is_some() {
                    dir = dir.child(part.as_ref())?;
                } else {
                    let file = dir.file(part.as_ref())?;
                    if self.stamps.get(path) != Some(&Stamp::of(&file.metadata()?)) {
                        return Err(io::Error::other(
                            "synthetic Git cache changed after validation",
                        ));
                    }
                    return Ok(Box::new(file));
                }
            }
        }
        Err(io::Error::other("synthetic Git file unavailable"))
    }
}

#[cfg(unix)]
fn commit_bytes(tree: Oid, timestamp: i64) -> Vec<u8> {
    // Inherit only the committer timestamp, normalized to UTC.
    let signature = format!("ratarmount <sandbox@ratarmount.invalid> {timestamp} +0000");
    format!("tree {tree}\nauthor {signature}\ncommitter {signature}\n\nSynthetic sandbox HEAD\n")
        .into_bytes()
}

#[cfg(unix)]
fn index_bytes(source: &Repository, tree: Oid, timestamp: i64) -> Result<Vec<u8>> {
    let mut index = Index::new()?;
    index.read_tree(&source.find_tree(tree)?)?;
    let odb = source.odb()?;
    // Serialize the documented v2 format without cache-tree or other extensions.
    // This avoids reopening an index by pathname while constructing the cache.
    let mut bytes = b"DIRC".to_vec();
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&(index.len() as u32).to_be_bytes());
    let time = timestamp.clamp(0, i32::MAX as i64) as u32;
    for entry in index.iter() {
        let start = bytes.len();
        // ctime, mtime, dev, ino, mode, uid, gid, size (Git truncates size to 32 bits).
        for field in [
            time,
            0,
            time,
            0,
            0,
            0,
            entry.mode,
            0,
            0,
            odb.read_header(entry.id)?.0 as u32,
        ] {
            bytes.extend_from_slice(&field.to_be_bytes());
        }
        bytes.extend_from_slice(entry.id.as_bytes());
        bytes.extend_from_slice(&(entry.path.len().min(0xfff) as u16).to_be_bytes());
        bytes.extend_from_slice(&entry.path);
        bytes.push(0);
        while !(bytes.len() - start).is_multiple_of(8) {
            bytes.push(0);
        }
    }
    let checksum = Sha1::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

#[cfg(unix)]
fn build_repository(
    source: &Repository,
    tree: Oid,
    timestamp: i64,
    root: &Directory,
    expected: &BTreeMap<String, Expected>,
) -> Result<()> {
    // Everything, including staging and intermediate directories, is created
    // relative to pinned directory fds. No templates or source config are used.
    let odb = source.odb()?;
    for (path, value) in expected {
        let mut dir = root.child(".".as_ref())?;
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_some() {
                dir.mkdir(part.as_ref())?;
                dir = dir.child(part.as_ref())?;
            } else {
                let mut file = dir.create_file(part.as_ref())?;
                match value {
                    Expected::Bytes(bytes) => file.write_all(bytes)?,
                    Expected::Object(oid, kind, size) => {
                        let mut encoder =
                            flate2::write::ZlibEncoder::new(file, flate2::Compression::default());
                        write!(encoder, "{} {size}\0", kind.str())?;
                        if *kind == ObjectType::Commit {
                            encoder.write_all(&commit_bytes(tree, timestamp))?;
                        } else {
                            encoder.write_all(odb.read(*oid)?.data())?;
                        }
                        encoder.finish()?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
enum Expected {
    Bytes(Vec<u8>),
    Object(Oid, ObjectType, usize),
}

#[cfg(unix)]
fn object_path(oid: Oid) -> String {
    let hex = oid.to_string();
    format!("objects/{}/{}", &hex[..2], &hex[2..])
}

#[cfg(unix)]
fn expected_files(
    source: &Repository,
    tree: Oid,
    timestamp: i64,
) -> Result<BTreeMap<String, Expected>> {
    fn walk(source: &Repository, oid: Oid, files: &mut BTreeMap<String, Expected>) -> Result<()> {
        let path = object_path(oid);
        if files.contains_key(&path) {
            return Ok(());
        }
        let (size, kind) = source.odb()?.read_header(oid)?;
        files.insert(path, Expected::Object(oid, kind, size));
        if kind == ObjectType::Tree {
            for entry in source.find_tree(oid)?.iter() {
                validate_tree_entry(source, &entry)?;
                walk(source, entry.id(), files)?;
            }
        }
        Ok(())
    }
    let commit = commit_bytes(tree, timestamp);
    let head = Oid::hash_object(ObjectType::Commit, &commit)?;
    let mut expected = BTreeMap::new();
    walk(source, tree, &mut expected)?;
    expected.extend([
        ("HEAD".into(), Expected::Bytes(HEAD.to_vec())),
        ("config".into(), Expected::Bytes(CONFIG.to_vec())),
        (
            "refs/heads/sandbox".into(),
            Expected::Bytes(format!("{head}\n").into_bytes()),
        ),
        (
            "index".into(),
            Expected::Bytes(index_bytes(source, tree, timestamp)?),
        ),
        (
            object_path(head),
            Expected::Object(head, ObjectType::Commit, commit.len()),
        ),
    ]);
    Ok(expected)
}

#[cfg(unix)]
fn validate_directory(
    dir: &Directory,
    path: &str,
    expected: &BTreeMap<String, Expected>,
    actual: &mut BTreeSet<String>,
    entries: &mut BTreeMap<String, FileInfo>,
    stamps: &mut BTreeMap<String, Stamp>,
) -> Result<()> {
    secure_cache::check_private(&dir.0.metadata()?)?;
    insert_metadata(path, &dir.0.metadata()?, entries);
    for name in dir.names()? {
        let name_str = name
            .to_str()
            .ok_or_else(|| GitError::Msg("non-UTF-8 cache filename".into()))?;
        let child = if path.is_empty() {
            name_str.into()
        } else {
            format!("{path}/{name_str}")
        };
        if let Some(value) = expected.get(&child) {
            let mut file = dir.file(&name)?;
            let before = file.metadata()?;
            validate_file(&mut file, value)?;
            let stamp = Stamp::of(&before);
            if stamp != Stamp::of(&file.metadata()?) {
                return Err(GitError::Msg("cache file changed during validation".into()));
            }
            stamps.insert(format!(".git/{child}"), stamp);
            insert_metadata(&child, &before, entries);
            actual.insert(child);
        } else if expected
            .keys()
            .any(|key| key.starts_with(&format!("{child}/")))
        {
            validate_directory(
                &dir.child(&name)?,
                &child,
                expected,
                actual,
                entries,
                stamps,
            )?;
        } else {
            return Err(GitError::Msg(format!("unexpected cache path {child}")));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(file: &mut File, expected: &Expected) -> Result<()> {
    match expected {
        Expected::Bytes(bytes) => {
            let mut actual = Vec::new();
            file.take(bytes.len() as u64 + 1).read_to_end(&mut actual)?;
            if &actual != bytes {
                return Err(GitError::Msg("cache metadata content mismatch".into()));
            }
        }
        Expected::Object(oid, kind, size) => {
            let compressed_len = file.metadata()?.len();
            let mut decoder = flate2::read::ZlibDecoder::new(file);
            let header = format!("{} {size}\0", kind.str());
            let mut actual_header = vec![0; header.len()];
            decoder.read_exact(&mut actual_header)?;
            if actual_header != header.as_bytes() {
                return Err(GitError::Msg("cache object header mismatch".into()));
            }
            let mut hash = Sha1::new();
            hash.update(&actual_header);
            let mut remaining = *size;
            let mut buffer = [0; 64 * 1024];
            while remaining > 0 {
                let len = remaining.min(buffer.len());
                decoder.read_exact(&mut buffer[..len])?;
                hash.update(&buffer[..len]);
                remaining -= len;
            }
            if decoder.read(&mut buffer[..1])? != 0
                || decoder.total_in() != compressed_len
                || hash.finalize().as_slice() != oid.as_bytes()
            {
                return Err(GitError::Msg("cache object content mismatch".into()));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn insert_metadata(path: &str, meta: &fs::Metadata, entries: &mut BTreeMap<String, FileInfo>) {
    let vpath = if path.is_empty() {
        ".git".into()
    } else {
        format!(".git/{path}")
    };
    entries.insert(
        vpath.clone(),
        FileInfo {
            size: if meta.is_file() { meta.len() } else { 0 },
            mtime: meta
                .modified()
                .unwrap_or(UNIX_EPOCH)
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            mode: if meta.is_dir() {
                S_IFDIR | 0o755
            } else {
                S_IFREG | 0o644
            },
            linkname: String::new(),
            uid: ratarmount_core::effective_uid(),
            gid: ratarmount_core::effective_gid(),
            userdata: vec![git_path_userdata(&format!("/{vpath}"))],
        },
    );
}

#[cfg(unix)]
fn validate_tree_entry(source: &Repository, entry: &git2::TreeEntry<'_>) -> Result<()> {
    let name = entry
        .name()
        .ok_or_else(|| GitError::Msg("synthetic Git requires UTF-8 filenames".into()))?;
    if name.eq_ignore_ascii_case(".git")
        || name.contains('\\')
        || Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(GitError::Msg(format!(
            "unsupported synthetic Git tree entry {name:?}"
        )));
    }
    let expected_kind = if entry.filemode() == 0o040000 {
        ObjectType::Tree
    } else {
        ObjectType::Blob
    };
    if entry.filemode() != 0o160000 && source.odb()?.read_header(entry.id())?.1 != expected_kind {
        return Err(GitError::Msg(format!(
            "unexpected Git object type at {name:?}"
        )));
    }
    match entry.filemode() {
        0o040000 | 0o100644 | 0o100755 => {}
        0o120000 => {
            let target = source.find_blob(entry.id())?;
            if std::str::from_utf8(target.content()).is_err() || target.content().contains(&0) {
                return Err(GitError::Msg(format!(
                    "synthetic Git requires UTF-8 symlink targets without NUL: {name:?}"
                )));
            }
        }
        _ => {
            return Err(GitError::Msg(format!(
                "synthetic Git does not support gitlinks or mode {:o} at {name:?}",
                entry.filemode()
            )))
        }
    }
    Ok(())
}

#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;

    /// Regression: platforms without no-follow cache access must fail closed.
    #[test]
    fn regression_synthetic_cache_requires_supported_no_follow_access() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let error =
            SyntheticGit::build(&repo, repo.path(), Oid::zero(), Oid::zero(), 0, dir.path())
                .err()
                .unwrap()
                .to_string();
        assert!(error.contains("requires Unix no-follow cache access"));
    }
}
