//! Path ↔ fileid map. Never stores cheap readdir `FileInfo`.
//!
//! Copied from `ratarmount-nfs/src/inode.rs`: ROOT=1, skip 0; skip 2 because
//! child fileids double as READDIR cookies and NFSv4.1 reserves 1 and 2.
//!
//! Overlay child inodes keep [`InodeAttrCookie`] (no heap `linkname` /
//! `userdata`). [`InodeTable::cached_lookup_fi`] is clone-only — never
//! reconstruct a `FileInfo` from a cookie.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ratarmount_core::{create_root_file_info, normpath, FileInfo, InodeAttrCookie};

/// nfsserve / FUSE root id. Fileid 0 is reserved.
pub const ROOT_FILEID: u64 = 1;

struct InodeEntry {
    path: String,
    /// Fat FileInfo cache. Immutable mounts only (and overlay root).
    /// Overlay child inodes store [`InodeAttrCookie`] instead.
    file_info: Option<FileInfo>,
    /// Compact getattr scalars on overlay child inodes. Not served as
    /// getattr/open truth — those paths re-lookup. Cleared by the generation
    /// sweep. Never `Some` together with `file_info` on a child overlay inode.
    #[allow(dead_code)] // density store; production must not reconstruct FileInfo
    cookie: Option<InodeAttrCookie>,
}

/// Lazy path → fileid table for one export process.
pub struct InodeTable {
    inodes: Mutex<HashMap<u64, InodeEntry>>,
    path_to_id: Mutex<HashMap<String, u64>>,
    next_id: AtomicU64,
    /// When set, child `store_lookup_fi` writes a cookie and leaves
    /// `file_info = None` so [`Self::cached_lookup_fi`] cannot feed a stale
    /// size-0 empty cursor.
    overlay: bool,
}

impl InodeTable {
    pub fn new() -> Self {
        Self::with_overlay(false)
    }

    /// Overlay tables skip the fat `FileInfo` cache on every child inode.
    pub fn with_overlay(overlay: bool) -> Self {
        let mut inodes = HashMap::new();
        let mut path_to_id = HashMap::new();
        inodes.insert(
            ROOT_FILEID,
            InodeEntry {
                path: "/".into(),
                file_info: Some(create_root_file_info()),
                cookie: None,
            },
        );
        path_to_id.insert("/".into(), ROOT_FILEID);
        Self {
            inodes: Mutex::new(inodes),
            path_to_id: Mutex::new(path_to_id),
            // Child fileids double as READDIR cookies; embednfs (NFSv4.1)
            // reserves cookie values 1 and 2 (Linux injects `.` / `..`), so
            // never hand those ids out.
            next_id: AtomicU64::new(ROOT_FILEID + 2),
            overlay,
        }
    }

    /// Overlay tables skip the fat `FileInfo` cache on every child inode.
    pub(crate) fn stores_overlay_cookies(&self) -> bool {
        self.overlay
    }

    fn overlay_stores_cookie(&self, id: u64) -> bool {
        self.overlay && id != ROOT_FILEID
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
                cookie: None,
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

    /// Cached lookup-sourced `FileInfo` only. Never reconstructs from a cookie.
    pub fn cached_lookup_fi(&self, id: u64) -> Option<FileInfo> {
        self.inodes
            .lock()
            .expect("inode map")
            .get(&id)
            .and_then(|e| e.file_info.clone())
    }

    /// Overlay cookie only. Immutable mounts leave this unused.
    #[cfg(test)]
    pub(crate) fn cached_cookie(&self, id: u64) -> Option<InodeAttrCookie> {
        self.inodes
            .lock()
            .expect("inode map")
            .get(&id)
            .and_then(|e| e.cookie)
    }

    pub fn store_lookup_fi(&self, id: u64, fi: FileInfo) {
        if let Some(ent) = self.inodes.lock().expect("inode map").get_mut(&id) {
            if self.overlay_stores_cookie(id) {
                ent.cookie = Some(InodeAttrCookie::from_file_info(&fi));
                ent.file_info = None;
            } else {
                ent.file_info = Some(fi);
                ent.cookie = None;
            }
        }
    }

    /// Drop cached lookup `FileInfo` and overlay cookie so the next
    /// getattr/read re-looks up.
    pub fn clear_lookup_fi(&self, id: u64) {
        if let Some(ent) = self.inodes.lock().expect("inode map").get_mut(&id) {
            ent.file_info = None;
            ent.cookie = None;
        }
    }

    /// Drop every cached lookup `FileInfo` and overlay cookie (live overlay
    /// commit may have shifted base member offsets, invalidating all of
    /// them at once).
    pub fn clear_all_lookup_fi(&self) {
        for ent in self.inodes.lock().expect("inode map").values_mut() {
            ent.file_info = None;
            ent.cookie = None;
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
                    ent.cookie = None;
                    ent.path = format!("\0stale-{old_dest}");
                }
            }
        }
        if let Some(ent) = inodes.get_mut(&id) {
            p2i.remove(&ent.path);
            ent.path = new_path.clone();
            ent.file_info = None;
            ent.cookie = None;
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

    /// Regression: ROOT fileid is 1 never 0.
    #[test]
    fn root_is_one_never_zero() {
        let t = InodeTable::new();
        assert_eq!(ROOT_FILEID, 1);
        assert_eq!(t.id_for_path("/"), ROOT_FILEID);
        assert_eq!(t.path_for_id(ROOT_FILEID).as_deref(), Some("/"));
        assert!(t.cached_lookup_fi(ROOT_FILEID).is_some());
        assert!(t.path_for_id(0).is_none());
    }

    /// Regression: fileid 2 is reserved for readdir cookies.
    #[test]
    fn child_ids_skip_reserved_cookies() {
        let t = InodeTable::new();
        let a = t.id_for_path("/foo");
        assert_ne!(a, 0);
        assert_ne!(a, ROOT_FILEID);
        assert_ne!(a, 2);
        assert_eq!(a, 3);
        assert_eq!(t.id_for_path("/foo"), a);
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
        assert!(
            t.cached_cookie(a).is_none(),
            "immutable mounts keep fat FileInfo, not a cookie"
        );
    }

    #[test]
    fn rebind_keeps_fileid() {
        let t = InodeTable::new();
        let id = t.id_for_path("/old");
        t.rebind_path(id, "/new");
        assert_eq!(t.id_for_path("/new"), id);
        assert_eq!(t.path_for_id(id).as_deref(), Some("/new"));
        assert!(t.id_if_present("/old").is_none());
    }

    fn sample_fi(size: u64) -> FileInfo {
        FileInfo {
            size,
            mtime: 1.5,
            mode: ratarmount_core::S_IFREG | 0o644,
            linkname: "ignored".into(),
            uid: 7,
            gid: 9,
            userdata: vec![ratarmount_core::UserData::Other("overlay:/x".into())],
        }
    }

    /// After overlay store, the inode holds a cookie only — not a fat FileInfo
    /// (and never both `Some`). `cached_lookup_fi` must not reconstruct.
    #[test]
    fn overlay_store_cookie_without_file_info() {
        let t = InodeTable::with_overlay(true);
        let id = t.id_for_path("/cookie.txt");
        let fi = sample_fi(7);
        t.store_lookup_fi(id, fi.clone());
        assert!(
            t.cached_cookie(id).is_some(),
            "overlay store must write a cookie"
        );
        assert!(
            t.cached_lookup_fi(id).is_none(),
            "overlay child must not keep fat FileInfo (no to_file_info)"
        );
        let c = t.cached_cookie(id).unwrap();
        assert_eq!(c.size, fi.size);
        assert_eq!(c.mtime, fi.mtime);
        assert_eq!(c.mode, fi.mode);
        assert_eq!(c.uid, fi.uid);
        assert_eq!(c.gid, fi.gid);
        assert_eq!(t.cached_lookup_fi(ROOT_FILEID).unwrap().size, 0);
        assert!(
            t.cached_cookie(ROOT_FILEID).is_none(),
            "overlay root stays fat FileInfo"
        );
    }

    /// Generation sweep / mutate must drop cookies the same way as FileInfo.
    #[test]
    fn overlay_clear_lookup_drops_cookie() {
        let t = InodeTable::with_overlay(true);
        let id = t.id_for_path("/a");
        t.store_lookup_fi(id, sample_fi(4));
        assert!(t.cached_cookie(id).is_some());
        t.clear_lookup_fi(id);
        assert!(t.cached_cookie(id).is_none());
        t.store_lookup_fi(id, sample_fi(4));
        t.clear_all_lookup_fi();
        assert!(t.cached_cookie(id).is_none());
        assert!(t.cached_lookup_fi(id).is_none());
    }

    /// Overlay rename must drop cookies (stale size/mtime after rebind).
    #[test]
    fn overlay_rebind_drops_cookie() {
        let t = InodeTable::with_overlay(true);
        let id = t.id_for_path("/old");
        t.store_lookup_fi(id, sample_fi(9));
        assert!(t.cached_cookie(id).is_some());
        t.rebind_path(id, "/new");
        assert!(t.cached_cookie(id).is_none());
        assert!(t.cached_lookup_fi(id).is_none());
    }
}
