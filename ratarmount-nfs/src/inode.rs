//! Path ↔ fileid map. Never stores cheap readdir `FileInfo`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ratarmount_core::{create_root_file_info, normpath, FileInfo};

/// nfsserve / FUSE root id. Fileid 0 is reserved.
pub const ROOT_FILEID: u64 = 1;

struct InodeEntry {
    path: String,
    /// Only `source.lookup` / `create_root_file_info` — never cheap dirents.
    file_info: Option<FileInfo>,
}

/// Lazy path → fileid table for one NFS export process.
pub struct InodeTable {
    inodes: Mutex<HashMap<u64, InodeEntry>>,
    path_to_id: Mutex<HashMap<String, u64>>,
    next_id: AtomicU64,
}

impl InodeTable {
    pub fn new() -> Self {
        let mut inodes = HashMap::new();
        let mut path_to_id = HashMap::new();
        inodes.insert(
            ROOT_FILEID,
            InodeEntry {
                path: "/".into(),
                file_info: Some(create_root_file_info()),
            },
        );
        path_to_id.insert("/".into(), ROOT_FILEID);
        Self {
            inodes: Mutex::new(inodes),
            path_to_id: Mutex::new(path_to_id),
            next_id: AtomicU64::new(ROOT_FILEID + 1),
        }
    }

    pub fn id_if_present(&self, path: &str) -> Option<u64> {
        let path = normpath(path);
        self.path_to_id
            .lock()
            .expect("inode path map")
            .get(&path)
            .copied()
    }

    /// Assign or reuse a fileid for `path`. Does **not** write `FileInfo`.
    pub fn id_for_path(&self, path: &str) -> u64 {
        let path = normpath(path);
        let mut p2i = self.path_to_id.lock().expect("inode path map");
        if let Some(&id) = p2i.get(&path) {
            return id;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        p2i.insert(path.clone(), id);
        self.inodes.lock().expect("inode map").insert(
            id,
            InodeEntry {
                path,
                file_info: None,
            },
        );
        id
    }

    pub fn path_for_id(&self, id: u64) -> Option<String> {
        self.inodes
            .lock()
            .expect("inode map")
            .get(&id)
            .map(|e| e.path.clone())
    }

    /// Cached lookup-sourced `FileInfo` only.
    pub fn cached_lookup_fi(&self, id: u64) -> Option<FileInfo> {
        self.inodes
            .lock()
            .expect("inode map")
            .get(&id)
            .and_then(|e| e.file_info.clone())
    }

    pub fn store_lookup_fi(&self, id: u64, fi: FileInfo) {
        if let Some(ent) = self.inodes.lock().expect("inode map").get_mut(&id) {
            ent.file_info = Some(fi);
        }
    }

    /// Drop cached lookup `FileInfo` so the next getattr/read re-looks up.
    pub fn clear_lookup_fi(&self, id: u64) {
        if let Some(ent) = self.inodes.lock().expect("inode map").get_mut(&id) {
            ent.file_info = None;
        }
    }

    /// Keep the same fileid after overlay rename (path mapping only).
    pub fn rebind_path(&self, id: u64, new_path: &str) {
        let new_path = normpath(new_path);
        let mut p2i = self.path_to_id.lock().expect("inode path map");
        let mut inodes = self.inodes.lock().expect("inode map");
        if let Some(&old_dest) = p2i.get(&new_path) {
            if old_dest != id {
                p2i.remove(&new_path);
                if let Some(ent) = inodes.get_mut(&old_dest) {
                    ent.file_info = None;
                    ent.path = format!("\0stale-{old_dest}");
                }
            }
        }
        if let Some(ent) = inodes.get_mut(&id) {
            p2i.remove(&ent.path);
            ent.path = new_path.clone();
            ent.file_info = None;
        }
        p2i.insert(new_path, id);
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_one_never_zero() {
        let t = InodeTable::new();
        assert_eq!(t.id_for_path("/"), ROOT_FILEID);
        assert_eq!(t.path_for_id(ROOT_FILEID).as_deref(), Some("/"));
        assert!(t.cached_lookup_fi(ROOT_FILEID).is_some());
    }

    #[test]
    fn stable_ids_no_fileinfo_on_assign() {
        let t = InodeTable::new();
        let a = t.id_for_path("/foo");
        let b = t.id_for_path("/foo");
        assert_eq!(a, b);
        assert!(a >= 2);
        assert!(t.cached_lookup_fi(a).is_none());
        t.store_lookup_fi(
            a,
            FileInfo {
                size: 3,
                mtime: 0.0,
                mode: ratarmount_core::S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            },
        );
        assert_eq!(t.cached_lookup_fi(a).unwrap().size, 3);
    }
}
