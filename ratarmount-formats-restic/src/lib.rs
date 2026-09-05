//! Read-only restic repository snapshot browser (`backendName=ResticMountSource`).
//!
//! Local repos only (`restic:/abs/path`). Presentation:
//!
//! ```text
//! /snapshots/<short-id>/...tree...
//! /latest -> snapshots/<latest-id>
//! /ids/<full-id>/
//! ```
//!
//! Password: `RESTIC_PASSWORD` / `RESTIC_PASSWORD_FILE` (never logged). S3 restic
//! repos, borg, and kopia are residual.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::{
    create_root_file_info, CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData,
};
use thiserror::Error;

mod crypto;
mod repo;
mod url;

pub use repo::{
    parse_index_json, write_synthetic_repo, write_synthetic_repo_v2, IndexFile, SyntheticRepo,
};
pub use url::parse_restic_url;

pub const BACKEND_NAME: &str = "ResticMountSource";

#[derive(Debug, Error)]
pub enum ResticError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, ResticError>;

enum VPath {
    Root,
    Latest,
    SnapshotsDir,
    IdsDir,
    Snapshot {
        id_prefix: String,
        rest: Vec<String>,
        #[allow(dead_code)]
        via_ids: bool,
    },
    Unknown,
}

fn parse_vpath(path: &str) -> VPath {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match parts.as_slice() {
        [] => VPath::Root,
        ["latest"] => VPath::Latest,
        ["snapshots"] => VPath::SnapshotsDir,
        ["ids"] => VPath::IdsDir,
        ["snapshots", id, rest @ ..] => VPath::Snapshot {
            id_prefix: (*id).to_string(),
            rest: rest.iter().map(|s| (*s).to_string()).collect(),
            via_ids: false,
        },
        ["ids", id, rest @ ..] => VPath::Snapshot {
            id_prefix: (*id).to_string(),
            rest: rest.iter().map(|s| (*s).to_string()).collect(),
            via_ids: true,
        },
        _ => VPath::Unknown,
    }
}

fn dir_info(mtime: f64) -> FileInfo {
    FileInfo {
        size: 0,
        mtime,
        mode: ratarmount_core::S_IFDIR | 0o555,
        linkname: String::new(),
        uid: ratarmount_core::effective_uid(),
        gid: ratarmount_core::effective_gid(),
        userdata: Vec::new(),
    }
}

fn link_info(target: &str, mtime: f64) -> FileInfo {
    FileInfo {
        size: 0,
        mtime,
        mode: ratarmount_core::S_IFLNK | 0o777,
        linkname: target.to_string(),
        uid: ratarmount_core::effective_uid(),
        gid: ratarmount_core::effective_gid(),
        userdata: Vec::new(),
    }
}

fn file_userdata(blob_ids: &[String]) -> UserData {
    UserData::Other(format!("restic:blobs:{}", blob_ids.join(",")))
}

/// Read-only restic snapshot browser.
pub struct ResticMountSource {
    repo_path: PathBuf,
    repo: Arc<repo::Repo>,
    mtime: f64,
}

impl fmt::Debug for ResticMountSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResticMountSource")
            .field("repo", &self.repo_path)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl ResticMountSource {
    /// Open using `RESTIC_PASSWORD` / `RESTIC_PASSWORD_FILE`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let password = repo::load_password_from_env()?;
        Self::open_with_password(path, &password)
    }

    pub fn open_with_password(path: impl AsRef<Path>, password: impl AsRef<[u8]>) -> Result<Self> {
        let path = path.as_ref();
        let repo = repo::Repo::open(path, password.as_ref())?;
        Ok(Self {
            repo_path: path.to_path_buf(),
            repo: Arc::new(repo),
            mtime: repo::now_unix(),
        })
    }

    fn snapshot(&self, prefix: &str) -> Option<&repo::SnapshotMeta> {
        self.repo.snapshot_by_prefix(prefix)
    }

    fn walk_tree(&self, tree_id: &str, rest: &[String]) -> Result<Walked> {
        if rest.is_empty() {
            return Ok(Walked::Dir(tree_id.to_string()));
        }
        let tree = self.repo.load_tree(tree_id)?;
        let (name, tail) = rest.split_first().unwrap();
        let node = tree
            .nodes
            .iter()
            .find(|n| n.name == *name)
            .ok_or_else(|| ResticError::Msg(format!("not found: {name}")))?;
        match node.node_type.as_str() {
            "dir" => {
                let sub = node
                    .subtree
                    .as_deref()
                    .ok_or_else(|| ResticError::Msg(format!("dir {name} missing subtree")))?;
                self.walk_tree(sub, tail)
            }
            "file" if tail.is_empty() => Ok(Walked::File(node.clone())),
            "symlink" if tail.is_empty() => Ok(Walked::Symlink(node.clone())),
            _ if tail.is_empty() => Ok(Walked::Other(node.clone())),
            _ => Err(ResticError::Msg(format!("not a directory: {name}"))),
        }
    }

    fn node_to_info(&self, node: &repo::TreeNode) -> FileInfo {
        let mtime = node
            .mtime
            .as_deref()
            .and_then(repo::rfc3339_to_unix)
            .unwrap_or(self.mtime);
        let perms = node.mode & 0o777;
        match node.node_type.as_str() {
            "dir" => FileInfo {
                size: 0,
                mtime,
                mode: ratarmount_core::S_IFDIR | if perms == 0 { 0o555 } else { perms },
                linkname: String::new(),
                uid: node.uid.unwrap_or_else(ratarmount_core::effective_uid),
                gid: node.gid.unwrap_or_else(ratarmount_core::effective_gid),
                userdata: Vec::new(),
            },
            "symlink" => FileInfo {
                size: 0,
                mtime,
                mode: ratarmount_core::S_IFLNK | 0o777,
                linkname: node.linktarget.clone().unwrap_or_default(),
                uid: node.uid.unwrap_or_else(ratarmount_core::effective_uid),
                gid: node.gid.unwrap_or_else(ratarmount_core::effective_gid),
                userdata: Vec::new(),
            },
            _ => {
                let blobs = node.content.clone().unwrap_or_default();
                FileInfo {
                    size: node.size.unwrap_or(0),
                    mtime,
                    mode: ratarmount_core::S_IFREG | if perms == 0 { 0o444 } else { perms },
                    linkname: String::new(),
                    uid: node.uid.unwrap_or_else(ratarmount_core::effective_uid),
                    gid: node.gid.unwrap_or_else(ratarmount_core::effective_gid),
                    userdata: vec![file_userdata(&blobs)],
                }
            }
        }
    }

    fn list_tree(&self, tree_id: &str) -> Result<BTreeMap<String, FileInfo>> {
        let tree = self.repo.load_tree(tree_id)?;
        let mut map = BTreeMap::new();
        for node in &tree.nodes {
            map.insert(node.name.clone(), self.node_to_info(node));
        }
        Ok(map)
    }

    fn list_tree_dirents(&self, tree_id: &str) -> Result<Vec<CheapDirent>> {
        let tree = self.repo.load_tree(tree_id)?;
        Ok(tree
            .nodes
            .iter()
            .map(|n| {
                let fi = self.node_to_info(n);
                CheapDirent {
                    name: n.name.clone(),
                    mode: fi.mode,
                    size: fi.size,
                }
            })
            .collect())
    }
}

enum Walked {
    Dir(String),
    File(repo::TreeNode),
    Symlink(repo::TreeNode),
    Other(repo::TreeNode),
}

fn blobs_from_userdata(fi: &FileInfo) -> Option<Vec<String>> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("restic:blobs:") => {
            let rest = &s["restic:blobs:".len()..];
            if rest.is_empty() {
                Some(Vec::new())
            } else {
                Some(rest.split(',').map(|x| x.to_string()).collect())
            }
        }
        _ => None,
    })
}

impl MountSource for ResticMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        match parse_vpath(path) {
            VPath::Root => {
                let mut map = BTreeMap::new();
                map.insert("snapshots".into(), dir_info(self.mtime));
                map.insert("ids".into(), dir_info(self.mtime));
                if let Some(latest) = self.repo.latest() {
                    map.insert(
                        "latest".into(),
                        link_info(&format!("snapshots/{}", latest.short_id), latest.unix),
                    );
                }
                Some(ListResult::Infos(map))
            }
            VPath::SnapshotsDir => {
                let mut map = BTreeMap::new();
                for s in &self.repo.snapshots {
                    map.insert(s.short_id.clone(), dir_info(s.unix));
                }
                Some(ListResult::Infos(map))
            }
            VPath::IdsDir => {
                let mut map = BTreeMap::new();
                for s in &self.repo.snapshots {
                    map.insert(s.id.clone(), dir_info(s.unix));
                }
                Some(ListResult::Infos(map))
            }
            VPath::Snapshot {
                id_prefix, rest, ..
            } => {
                let snap = self.snapshot(&id_prefix)?;
                match self.walk_tree(&snap.tree, &rest) {
                    Ok(Walked::Dir(tid)) => self.list_tree(&tid).ok().map(ListResult::Infos),
                    _ => None,
                }
            }
            VPath::Latest | VPath::Unknown => None,
        }
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match self.list(path)? {
            ListResult::Infos(map) => Some(ListModeResult::Modes(
                map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
            ListResult::Names(n) => Some(ListModeResult::Names(n)),
        }
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        match parse_vpath(path) {
            VPath::Root => {
                let mut v = vec![
                    CheapDirent {
                        name: "snapshots".into(),
                        mode: ratarmount_core::S_IFDIR | 0o555,
                        size: 0,
                    },
                    CheapDirent {
                        name: "ids".into(),
                        mode: ratarmount_core::S_IFDIR | 0o555,
                        size: 0,
                    },
                ];
                if self.repo.latest().is_some() {
                    v.push(CheapDirent {
                        name: "latest".into(),
                        mode: ratarmount_core::S_IFLNK | 0o777,
                        size: 0,
                    });
                }
                Some(v)
            }
            VPath::SnapshotsDir => Some(
                self.repo
                    .snapshots
                    .iter()
                    .map(|s| CheapDirent {
                        name: s.short_id.clone(),
                        mode: ratarmount_core::S_IFDIR | 0o555,
                        size: 0,
                    })
                    .collect(),
            ),
            VPath::IdsDir => Some(
                self.repo
                    .snapshots
                    .iter()
                    .map(|s| CheapDirent {
                        name: s.id.clone(),
                        mode: ratarmount_core::S_IFDIR | 0o555,
                        size: 0,
                    })
                    .collect(),
            ),
            VPath::Snapshot {
                id_prefix, rest, ..
            } => {
                let snap = self.snapshot(&id_prefix)?;
                match self.walk_tree(&snap.tree, &rest) {
                    Ok(Walked::Dir(tid)) => self.list_tree_dirents(&tid).ok(),
                    _ => None,
                }
            }
            VPath::Latest | VPath::Unknown => None,
        }
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        if path == "/" || path.is_empty() {
            return Some(create_root_file_info());
        }
        match parse_vpath(path) {
            VPath::Root => Some(create_root_file_info()),
            VPath::Latest => self
                .repo
                .latest()
                .map(|s| link_info(&format!("snapshots/{}", s.short_id), s.unix)),
            VPath::SnapshotsDir | VPath::IdsDir => Some(dir_info(self.mtime)),
            VPath::Snapshot {
                id_prefix, rest, ..
            } => {
                let snap = self.snapshot(&id_prefix)?;
                if rest.is_empty() {
                    return Some(dir_info(snap.unix));
                }
                match self.walk_tree(&snap.tree, &rest).ok()? {
                    Walked::Dir(_) => Some(dir_info(snap.unix)),
                    Walked::File(n) | Walked::Symlink(n) | Walked::Other(n) => {
                        Some(self.node_to_info(&n))
                    }
                }
            }
            VPath::Unknown => None,
        }
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        let mode = file_info.mode & ratarmount_core::S_IFMT;
        if mode == ratarmount_core::S_IFDIR {
            return Err(io::Error::other("is a directory"));
        }
        if mode == ratarmount_core::S_IFLNK {
            return Ok(Box::new(Cursor::new(
                file_info.linkname.as_bytes().to_vec(),
            )));
        }
        let blobs = blobs_from_userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing restic blob userdata")
        })?;
        if blobs.is_empty() {
            return Ok(Box::new(Cursor::new(Vec::new())));
        }
        let f = repo::ResticFile::new(Arc::clone(&self.repo), blobs)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Box::new(f))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    const PW: &[u8] = b"test-restic-password-not-a-secret";

    #[test]
    fn parse_restic_index_json_two_packs() {
        let json = br#"{
            "supersedes": [],
            "packs": [
                {
                    "id": "73d04e6125cf3c28a299cc2f3cca3b78ceac396e4fcf9575e34536b26782413c",
                    "blobs": [
                        {
                            "id": "3ec79977ef0cf5de7b08cd12b874cd0f62bbaf7f07f3497a5b1bbcc8cb39b1ce",
                            "type": "data",
                            "offset": 0,
                            "length": 38
                        },
                        {
                            "id": "9ccb846e60d90d4eb915848add7aa7ea1e4bbabfc60e573db9f7bfb2789afbae",
                            "type": "data",
                            "offset": 38,
                            "length": 112,
                            "uncompressed_length": 511
                        }
                    ]
                }
            ]
        }"#;
        let idx = parse_index_json(json).unwrap();
        assert_eq!(idx.packs.len(), 1);
        assert_eq!(idx.packs[0].blobs.len(), 2);
        assert_eq!(idx.packs[0].blobs[0].blob_type, "data");
        assert_eq!(idx.packs[0].blobs[1].uncompressed_length, Some(511));
    }

    fn open_fixture() -> (tempfile::TempDir, ResticMountSource, SyntheticRepo) {
        let dir = tempfile::tempdir().unwrap();
        let info = write_synthetic_repo(dir.path(), PW).unwrap();
        let ms = ResticMountSource::open_with_password(dir.path(), PW).unwrap();
        (dir, ms, info)
    }

    #[test]
    fn restic_list_two_snapshots() {
        let (_dir, ms, info) = open_fixture();
        assert_eq!(info.snapshot_ids.len(), 2);
        let list = ms.list("/snapshots").expect("snapshots dir");
        match list {
            ListResult::Infos(map) => {
                assert_eq!(map.len(), 2, "keys: {:?}", map.keys().collect::<Vec<_>>());
            }
            _ => panic!("expected infos"),
        }
        let dents = ms.list_dirents("/snapshots").unwrap();
        assert_eq!(dents.len(), 2);
        // Second snapshot in the fixture is 2020-06-01 (newer than 2020-01-01).
        let newer_full = &info.snapshot_ids[1];
        let newer_short = dents
            .iter()
            .find(|d| newer_full.starts_with(&d.name))
            .map(|d| d.name.clone())
            .expect("newer snapshot short id");
        let latest = ms.lookup("/latest", 0).unwrap();
        assert_eq!(
            latest.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFLNK
        );
        assert_eq!(latest.linkname, format!("snapshots/{newer_short}"));
        let newer_unix = repo::rfc3339_to_unix("2020-06-01T00:00:00Z").unwrap();
        assert!(
            (latest.mtime - newer_unix).abs() < 0.5,
            "lookup /latest mtime {} vs {newer_unix}",
            latest.mtime
        );
        let listed_latest = match ms.list("/").unwrap() {
            ListResult::Infos(map) => map.get("latest").cloned().expect("list / has latest"),
            _ => panic!("expected infos"),
        };
        assert_eq!(listed_latest.linkname, latest.linkname);
        assert_eq!(listed_latest.mtime, latest.mtime);
        assert!(ms.lookup("/ids", 0).is_some());
        let ids = ms.list("/ids").unwrap();
        match ids {
            ListResult::Infos(map) => assert_eq!(map.len(), 2),
            _ => panic!("expected ids infos"),
        }
    }

    #[test]
    fn restic_read_1k_from_synthetic_pack() {
        let (_dir, ms, info) = open_fixture();
        let snaps = ms.list_dirents("/snapshots").unwrap();
        let short = &snaps[0].name;
        let path = format!("/snapshots/{short}/hello.bin");
        let fi = ms.lookup(&path, 0).expect("hello.bin");
        assert_eq!(fi.size, 1024);
        let mut r = ms.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, info.file_bytes);
        assert_eq!(buf.len(), 1024);
    }

    #[test]
    fn restic_password_redacted_in_debug() {
        let (_dir, ms, _) = open_fixture();
        let d = format!("{ms:?}");
        assert!(
            !d.contains("test-restic-password"),
            "password leaked in Debug: {d}"
        );
        assert!(d.contains("<redacted>"), "Debug should skip password: {d}");
        assert!(d.contains("ResticMountSource"));
    }

    #[test]
    fn restic_password_file_trim_matches_restic_trim_right() {
        assert_eq!(repo::trim_restic_password_file("secret\n\n\r\n"), "secret");
        assert_eq!(repo::trim_restic_password_file("secret\r\n"), "secret");
        assert_eq!(repo::trim_restic_password_file("secret"), "secret");
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn restic_password_file_opens_synthetic_repo() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        write_synthetic_repo(dir.path(), PW).unwrap();
        let pw_path = dir.path().join("pw.txt");
        std::fs::write(&pw_path, b"test-restic-password-not-a-secret\n\n\r\n").unwrap();
        let old_pw = std::env::var_os("RESTIC_PASSWORD");
        let old_file = std::env::var_os("RESTIC_PASSWORD_FILE");
        std::env::remove_var("RESTIC_PASSWORD");
        std::env::set_var("RESTIC_PASSWORD_FILE", &pw_path);
        let opened = ResticMountSource::open(dir.path());
        match old_pw {
            Some(v) => std::env::set_var("RESTIC_PASSWORD", v),
            None => std::env::remove_var("RESTIC_PASSWORD"),
        }
        match old_file {
            Some(v) => std::env::set_var("RESTIC_PASSWORD_FILE", v),
            None => std::env::remove_var("RESTIC_PASSWORD_FILE"),
        }
        let ms = opened.expect("RESTIC_PASSWORD_FILE should open the synthetic repo");
        let dents = ms.list_dirents("/snapshots").unwrap();
        assert_eq!(dents.len(), 2);
    }

    #[test]
    fn restic_v2_compressed_blob_and_unpacked_index() {
        let dir = tempfile::tempdir().unwrap();
        let info = write_synthetic_repo_v2(dir.path(), PW).unwrap();
        let ms = ResticMountSource::open_with_password(dir.path(), PW).unwrap();
        let dents = ms.list_dirents("/snapshots").unwrap();
        assert_eq!(dents.len(), 2);
        let short = &dents[0].name;
        let fi = ms
            .lookup(&format!("/snapshots/{short}/hello.bin"), 0)
            .expect("hello.bin via v2 zstd blob");
        assert_eq!(fi.size, 1024);
        let mut r = ms.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, info.file_bytes);
    }

    #[test]
    fn restic_zstd_decode_capped_rejects_oversize() {
        let zeros = vec![0u8; 64 * 1024];
        let enc = zstd::encode_all(zeros.as_slice(), 3).unwrap();
        let err = repo::zstd_decode_capped(&enc, 1024)
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds"), "expected cap error, got {err}");
        let out = repo::zstd_decode_capped(&enc, 64 * 1024).unwrap();
        assert_eq!(out.len(), 64 * 1024);
    }

    #[test]
    fn restic_init_backup_round_trip() {
        let restic = match std::process::Command::new("restic").arg("version").output() {
            Ok(o) if o.status.success() => "restic",
            _ => {
                eprintln!("skip: restic binary not on PATH");
                return;
            }
        };
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let src = dir.path().join("src");
        fs_create(&src);
        let payload = vec![0xCDu8; 1024];
        std::fs::write(src.join("hello.bin"), &payload).unwrap();
        let status = std::process::Command::new(restic)
            .args(["-r", repo.to_str().unwrap(), "init"])
            .env("RESTIC_PASSWORD", "live-restic-pw")
            .status()
            .unwrap();
        if !status.success() {
            eprintln!("skip: restic init failed");
            return;
        }
        let status = std::process::Command::new(restic)
            .args([
                "-r",
                repo.to_str().unwrap(),
                "backup",
                src.to_str().unwrap(),
            ])
            .env("RESTIC_PASSWORD", "live-restic-pw")
            .status()
            .unwrap();
        assert!(status.success(), "restic backup failed");
        let ms = ResticMountSource::open_with_password(&repo, b"live-restic-pw").unwrap();
        let snaps = ms.list_dirents("/snapshots").unwrap();
        assert_eq!(snaps.len(), 1);
        let found = find_named(&ms, &format!("/snapshots/{}", snaps[0].name), "hello.bin")
            .expect("hello.bin in restic tree");
        let mut r = ms.open(&found, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    fn fs_create(p: &Path) {
        std::fs::create_dir_all(p).unwrap();
    }

    fn find_named(ms: &ResticMountSource, dir: &str, want: &str) -> Option<FileInfo> {
        let dents = ms.list_dirents(dir)?;
        for d in dents {
            let child = if dir == "/" {
                format!("/{}", d.name)
            } else {
                format!("{dir}/{}", d.name)
            };
            if d.name == want {
                return ms.lookup(&child, 0);
            }
            if d.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
                if let Some(fi) = find_named(ms, &child, want) {
                    return Some(fi);
                }
            }
        }
        None
    }
}
