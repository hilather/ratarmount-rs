//! `MountSource` adapter for 9P2000.L (inode table + reader LRU + overlay).

use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{
    create_root_file_info, is_dir_mode, is_lnk_mode, CheapDirent, FileInfo, MountSource, S_IFMT,
};
use ratarmount_export_core::{
    fill_from_state, io_to_errno, overlay_create_file, overlay_mkdir, overlay_rename,
    overlay_to_io, overlay_truncate, overlay_unlink, InodeTable, ReaderLru, ROOT_FILEID,
};

use crate::proto::{
    Qid, AT_REMOVEDIR, DT_DIR, DT_LNK, DT_REG, QTDIR, QTFILE, QTSYMLINK, SETATTR_SIZE,
};

const MAX_NAME_LEN: usize = 255;

/// Userspace 9P2000.L view of a factory-built [`MountSource`].
pub struct Ratarmount9p {
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    inodes: Arc<InodeTable>,
    readers: Arc<ReaderLru>,
    readahead_bytes: usize,
}

impl Ratarmount9p {
    pub fn new(source: Arc<dyn MountSource>, readahead_bytes: usize, reader_slots: usize) -> Self {
        Self::with_overlay(source, readahead_bytes, reader_slots, None)
    }

    pub fn with_overlay(
        source: Arc<dyn MountSource>,
        readahead_bytes: usize,
        reader_slots: usize,
        overlay: Option<Arc<WriteOverlay>>,
    ) -> Self {
        let overlay_set = overlay.is_some();
        Self {
            source,
            overlay,
            inodes: Arc::new(InodeTable::with_overlay(overlay_set)),
            readers: Arc::new(ReaderLru::new(reader_slots)),
            readahead_bytes,
        }
    }

    pub fn writable(&self) -> bool {
        self.overlay.is_some()
    }

    fn overlay(&self) -> Result<&WriteOverlay, i32> {
        self.overlay.as_deref().ok_or(libc::EROFS)
    }

    fn bump(&self, id: u64) {
        self.readers.invalidate(id);
        self.inodes.clear_lookup_fi(id);
    }

    pub fn file_info(&self, id: u64) -> Result<FileInfo, i32> {
        let path = self.inodes.path_for_id(id).ok_or(libc::ESTALE)?;
        if path == "/" {
            let fi = create_root_file_info();
            self.inodes.store_lookup_fi(id, fi.clone());
            return Ok(fi);
        }
        // Overlay sizes change after create/write/truncate — do not trust cache.
        // Overlay children store cookies, not FileInfo; cached_lookup_fi is None.
        if self.overlay.is_none() {
            if let Some(fi) = self.inodes.cached_lookup_fi(id) {
                return Ok(fi);
            }
        }
        let fi = self.source.lookup(&path, 0).ok_or(libc::ESTALE)?;
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok(fi)
    }

    pub fn path_for_id(&self, id: u64) -> Result<String, i32> {
        self.inodes.path_for_id(id).ok_or(libc::ESTALE)
    }

    pub fn qid_for_id(&self, id: u64) -> Result<Qid, i32> {
        let fi = self.file_info(id)?;
        Ok(qid_from(id, &fi))
    }

    pub fn lookup_child(&self, parent_id: u64, name: &str) -> Result<(u64, Qid), i32> {
        check_name(name)?;
        let parent = self.path_for_id(parent_id)?;
        if name == "." {
            return Ok((parent_id, self.qid_for_id(parent_id)?));
        }
        if name == ".." {
            let p = parent_path(&parent);
            let id = self.inodes.id_for_path(&p);
            return Ok((id, self.qid_for_id(id)?));
        }
        let path = join_path(&parent, name);
        let fi = self.source.lookup(&path, 0).ok_or(libc::ENOENT)?;
        let id = self.inodes.id_for_path(&path);
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok((id, qid_from(id, &fi)))
    }

    pub fn walk_names(&self, start_id: u64, names: &[String]) -> Result<Vec<(u64, Qid)>, i32> {
        if names.is_empty() {
            let q = self.qid_for_id(start_id)?;
            return Ok(vec![(start_id, q)]);
        }
        let mut cur = start_id;
        let mut out = Vec::with_capacity(names.len());
        for (i, name) in names.iter().enumerate() {
            match self.lookup_child(cur, name) {
                Ok((id, q)) => {
                    out.push((id, q));
                    cur = id;
                }
                Err(e) if i == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(out)
    }

    pub fn getattr(&self, id: u64) -> Result<Attr, i32> {
        let fi = self.file_info(id)?;
        Ok(attr_from(id, &fi))
    }

    pub fn read(&self, id: u64, offset: u64, count: u32) -> Result<Vec<u8>, i32> {
        let fi = self.file_info(id)?;
        if is_dir_mode(fi.mode) {
            return Err(libc::EISDIR);
        }
        // Size-0 empty reply uses the re-lookup FileInfo, never a cookie.
        if fi.size == 0 || offset >= fi.size || count == 0 {
            return Ok(Vec::new());
        }
        let (_fi, state) = self
            .readers
            .get_or_open(self.source.as_ref(), &self.inodes, id)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    libc::ESTALE
                } else {
                    io_to_errno(&e)
                }
            })?;
        let want = count as usize;
        fill_from_state(&state, self.readahead_bytes, offset, want).map_err(|e| io_to_errno(&e))
    }

    pub fn readdir(&self, id: u64, offset: u64, count: u32) -> Result<Vec<u8>, i32> {
        let path = self.path_for_id(id)?;
        let fi = self.file_info(id)?;
        if !is_dir_mode(fi.mode) {
            return Err(libc::ENOTDIR);
        }
        let dents = self.source.list_dirents(&path).ok_or(libc::ENOENT)?;
        let parent_path = parent_path(&path);
        let parent_id = self.inodes.id_for_path(&parent_path);
        let parent_fi = self.file_info(parent_id).unwrap_or_else(|_| fi.clone());

        let mut entries: Vec<(u64, Qid, u8, String)> = Vec::with_capacity(dents.len() + 2);
        entries.push((id, qid_from(id, &fi), DT_DIR, ".".into()));
        entries.push((
            parent_id,
            qid_from(parent_id, &parent_fi),
            DT_DIR,
            "..".into(),
        ));
        for CheapDirent { name, mode, size } in dents {
            if name == "." || name == ".." {
                continue;
            }
            let child = join_path(&path, &name);
            let cid = self.inodes.id_for_path(&child);
            let cfi = if size > 0 {
                FileInfo {
                    size,
                    mtime: 0.0,
                    mode,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                }
            } else if let Some(looked) = self.source.lookup(&child, 0) {
                self.inodes.store_lookup_fi(cid, looked.clone());
                looked
            } else {
                FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                }
            };
            entries.push((cid, qid_from(cid, &cfi), dt_from_mode(cfi.mode), name));
        }

        let mut data = Vec::new();
        let max = count as usize;
        for (i, (_id, qid, dt, name)) in entries.into_iter().enumerate() {
            let cookie = (i as u64).saturating_add(1);
            if cookie <= offset {
                continue;
            }
            let raw = crate::proto::encode_dirent(qid, cookie, dt, &name);
            if !data.is_empty() && data.len().saturating_add(raw.len()) > max {
                break;
            }
            if raw.len() > max && data.is_empty() {
                break;
            }
            data.extend_from_slice(&raw);
            if data.len() >= max {
                break;
            }
        }
        Ok(data)
    }

    pub fn statfs(&self) -> StatFs9p {
        let s = self.source.statfs();
        StatFs9p {
            typ: 0x0102_1997, // V9FS_MAGIC
            bsize: u32::try_from(s.bsize.max(512)).unwrap_or(512),
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            fsid: 1,
            namelen: u32::try_from(s.namemax.max(255)).unwrap_or(255),
        }
    }

    pub fn lcreate(&self, dir_id: u64, name: &str, mode: u32) -> Result<(u64, Qid), i32> {
        let ov = self.overlay()?;
        check_name(name)?;
        let parent = self.path_for_id(dir_id)?;
        let path = join_path(&parent, name);
        let fd = overlay_create_file(ov, &path, mode).map_err(|e| io_to_errno(&e))?;
        ov.close_overlay_fd(fd);
        let id = self.inodes.id_for_path(&path);
        self.bump(id);
        let q = self.qid_for_id(id)?;
        Ok((id, q))
    }

    pub fn mkdir(&self, dir_id: u64, name: &str, mode: u32) -> Result<(u64, Qid), i32> {
        let ov = self.overlay()?;
        check_name(name)?;
        let parent = self.path_for_id(dir_id)?;
        let path = join_path(&parent, name);
        overlay_mkdir(ov, &path, mode).map_err(|e| io_to_errno(&e))?;
        let id = self.inodes.id_for_path(&path);
        self.bump(id);
        let q = self.qid_for_id(id)?;
        Ok((id, q))
    }

    pub fn unlinkat(&self, dir_id: u64, name: &str, flags: u32) -> Result<(), i32> {
        let ov = self.overlay()?;
        check_name(name)?;
        let parent = self.path_for_id(dir_id)?;
        let path = join_path(&parent, name);
        let id = self.inodes.id_for_path(&path);
        if flags & AT_REMOVEDIR != 0 {
            ov.rmdir(&path)
                .map_err(|e| io_to_errno(&overlay_to_io(e)))?;
        } else {
            overlay_unlink(ov, &path).map_err(|e| io_to_errno(&e))?;
        }
        self.bump(id);
        Ok(())
    }

    pub fn remove_path(&self, id: u64) -> Result<(), i32> {
        let ov = self.overlay()?;
        let path = self.path_for_id(id)?;
        if path == "/" {
            return Err(libc::EINVAL);
        }
        let is_dir = self
            .file_info(id)
            .map(|fi| is_dir_mode(fi.mode))
            .unwrap_or(false);
        if is_dir {
            ov.rmdir(&path)
                .map_err(|e| io_to_errno(&overlay_to_io(e)))?;
        } else {
            overlay_unlink(ov, &path).map_err(|e| io_to_errno(&e))?;
        }
        self.bump(id);
        Ok(())
    }

    pub fn renameat(
        &self,
        old_dir: u64,
        old_name: &str,
        new_dir: u64,
        new_name: &str,
    ) -> Result<(), i32> {
        let ov = self.overlay()?;
        check_name(old_name)?;
        check_name(new_name)?;
        let from = join_path(&self.path_for_id(old_dir)?, old_name);
        let to = join_path(&self.path_for_id(new_dir)?, new_name);
        let from_id = self.inodes.id_for_path(&from);
        if let Some(dest_id) = self.inodes.id_if_present(&to) {
            self.bump(dest_id);
        }
        overlay_rename(ov, &from, &to).map_err(|e| io_to_errno(&e))?;
        self.inodes.rebind_path(from_id, &to);
        self.bump(from_id);
        Ok(())
    }

    pub fn symlink(&self, dir_id: u64, name: &str, target: &str) -> Result<(u64, Qid), i32> {
        let ov = self.overlay()?;
        check_name(name)?;
        let parent = self.path_for_id(dir_id)?;
        let path = join_path(&parent, name);
        ov.create_symlink(&path, target)
            .map_err(|e| io_to_errno(&overlay_to_io(e)))?;
        let id = self.inodes.id_for_path(&path);
        self.bump(id);
        let q = self.qid_for_id(id)?;
        Ok((id, q))
    }

    pub fn readlink(&self, id: u64) -> Result<String, i32> {
        let fi = self.file_info(id)?;
        if !is_lnk_mode(fi.mode) {
            return Err(libc::EINVAL);
        }
        Ok(fi.linkname)
    }

    pub fn setattr_size(&self, id: u64, valid: u32, size: u64) -> Result<(), i32> {
        if valid & SETATTR_SIZE == 0 {
            if !self.writable() && valid != 0 {
                return Err(libc::EROFS);
            }
            return Ok(());
        }
        let ov = self.overlay()?;
        let path = self.path_for_id(id)?;
        overlay_truncate(ov, &path, size).map_err(|e| io_to_errno(&e))?;
        self.bump(id);
        Ok(())
    }

    pub fn write(&self, id: u64, offset: u64, data: &[u8]) -> Result<u32, i32> {
        let ov = self.overlay()?;
        let path = self.path_for_id(id)?;
        let flags = libc::O_RDWR | libc::O_CREAT;
        let fd = ov
            .open_overlay_fd(&path, flags)
            .map_err(|e| io_to_errno(&overlay_to_io(e)))?;
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let wrote = file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(data));
        ov.finish_owned_write_fd(file);
        wrote.map_err(|e| io_to_errno(&e))?;
        self.bump(id);
        Ok(data.len() as u32)
    }

    pub fn require_write_open(&self, flags: u32) -> Result<(), i32> {
        let acc = flags & 0o3;
        if acc != 0 && !self.writable() {
            return Err(libc::EROFS);
        }
        Ok(())
    }
}

/// Packed getattr fields (minus reserved btime/gen).
pub struct Attr {
    pub qid: Qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
    pub ctime_sec: u64,
    pub ctime_nsec: u64,
}

pub struct StatFs9p {
    pub typ: u32,
    pub bsize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: u64,
    pub namelen: u32,
}

fn qid_from(id: u64, fi: &FileInfo) -> Qid {
    Qid {
        typ: if is_dir_mode(fi.mode) {
            QTDIR
        } else if is_lnk_mode(fi.mode) {
            QTSYMLINK
        } else {
            QTFILE
        },
        version: 0,
        path: id,
    }
}

fn dt_from_mode(mode: u32) -> u8 {
    match mode & S_IFMT {
        x if x == ratarmount_core::S_IFDIR => DT_DIR,
        x if x == ratarmount_core::S_IFLNK => DT_LNK,
        _ => DT_REG,
    }
}

fn unix_time(t: f64) -> (u64, u64) {
    if !t.is_finite() || t <= 0.0 {
        return (0, 0);
    }
    let secs = t.trunc();
    if secs >= u64::MAX as f64 {
        return (u64::MAX, 0);
    }
    (secs as u64, (t.fract() * 1e9) as u64)
}

fn attr_from(id: u64, fi: &FileInfo) -> Attr {
    let (sec, nsec) = unix_time(fi.mtime);
    let nlink = if is_dir_mode(fi.mode) { 2 } else { 1 };
    Attr {
        qid: qid_from(id, fi),
        mode: fi.mode,
        uid: fi.uid,
        gid: fi.gid,
        nlink,
        rdev: 0,
        size: fi.size,
        blksize: 4096,
        blocks: fi.size.div_ceil(512),
        atime_sec: sec,
        atime_nsec: nsec,
        mtime_sec: sec,
        mtime_nsec: nsec,
        ctime_sec: sec,
        ctime_nsec: nsec,
    }
}

fn check_name(name: &str) -> Result<(), i32> {
    if name.is_empty() || name.contains('/') {
        return Err(libc::EINVAL);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(libc::ENAMETOOLONG);
    }
    Ok(())
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn parent_path(path: &str) -> String {
    if path == "/" {
        return "/".into();
    }
    match path.rfind('/') {
        None | Some(0) => "/".into(),
        Some(i) => path[..i].to_string(),
    }
}

pub fn root_id() -> u64 {
    ROOT_FILEID
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use ratarmount_core::ListResult;

    struct EmptyFs;
    impl MountSource for EmptyFs {
        fn list(&self, path: &str) -> Option<ratarmount_core::ListResult> {
            if path == "/" {
                Some(ListResult::Names(Vec::new()))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(Cursor::new(Vec::<u8>::new())))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: writes without overlay are EROFS (not EIO).
    #[test]
    fn writers_erofs_without_overlay() {
        let fs = Ratarmount9p::new(Arc::new(EmptyFs), 0, 8);
        assert_eq!(fs.mkdir(ROOT_FILEID, "d", 0o755).unwrap_err(), libc::EROFS);
        assert_eq!(
            fs.lcreate(ROOT_FILEID, "x", 0o644).unwrap_err(),
            libc::EROFS
        );
        assert_eq!(fs.write(ROOT_FILEID, 0, b"x").unwrap_err(), libc::EROFS);
        assert_eq!(fs.unlinkat(ROOT_FILEID, "x", 0).unwrap_err(), libc::EROFS);
        assert_eq!(
            fs.renameat(ROOT_FILEID, "a", ROOT_FILEID, "b").unwrap_err(),
            libc::EROFS
        );
        assert_eq!(fs.symlink(ROOT_FILEID, "l", "t").unwrap_err(), libc::EROFS);
        assert_eq!(
            fs.require_write_open(libc::O_WRONLY as u32).unwrap_err(),
            libc::EROFS
        );
    }

    fn overlay_fs() -> (tempfile::TempDir, Ratarmount9p) {
        let td = tempfile::tempdir().unwrap();
        let ov = Arc::new(
            WriteOverlay::new(Arc::new(EmptyFs) as Arc<dyn MountSource>, td.path())
                .expect("overlay"),
        );
        let fs = Ratarmount9p::with_overlay(ov.clone(), 0, 8, Some(ov));
        (td, fs)
    }

    /// Regression: write-then-cat empty when 9P READ used a stale size-0
    /// inode cache instead of re-lookup. Production path is `read`.
    #[test]
    fn overlay_open_after_create_write() {
        let (_td, fs) = overlay_fs();
        let (id, _) = fs.lcreate(ROOT_FILEID, "new.txt", 0o644).expect("create");
        assert_eq!(fs.getattr(id).expect("getattr after create").size, 0);
        fs.write(id, 0, b"hello-overlay-payload").expect("write");
        assert!(
            fs.inodes.cached_lookup_fi(id).is_none(),
            "overlay child must not keep a fat FileInfo"
        );
        let buf = fs.read(id, 0, 64).expect("read");
        assert_eq!(
            buf, b"hello-overlay-payload",
            "write-then-cat must not return empty"
        );
        assert_ne!(buf, b"", "payload must not be empty after write");
        assert_eq!(
            fs.getattr(id).expect("getattr after write").size,
            b"hello-overlay-payload".len() as u64
        );
        assert!(fs.inodes.cached_lookup_fi(id).is_none());
    }

    /// Opposite polarity of the size-0 cache bug: create with no write, then
    /// 9P READ must return "".
    #[test]
    fn overlay_open_after_create_reads_empty() {
        let (_td, fs) = overlay_fs();
        let (id, _) = fs.lcreate(ROOT_FILEID, "empty.txt", 0o644).expect("create");
        assert_eq!(fs.getattr(id).expect("getattr").size, 0);
        let buf = fs.read(id, 0, 64).expect("read");
        assert_eq!(buf, b"", "never-written overlay file must read empty");
        assert!(
            fs.inodes.cached_lookup_fi(id).is_none(),
            "overlay child must not keep a fat FileInfo"
        );
    }
}
