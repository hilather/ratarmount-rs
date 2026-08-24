//! `MountSource` adapter for SFTP v3 (inode table + reader LRU + overlay).

use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{
    create_root_file_info, is_dir_mode, is_lnk_mode, CheapDirent, FileInfo, MountSource, S_IFMT,
};
use ratarmount_export_core::{
    fill_from_state, io_to_errno, overlay_create_file, overlay_mkdir, overlay_rename,
    overlay_to_io, overlay_truncate, overlay_unlink, InodeTable, ReaderLru,
};

const MAX_NAME_LEN: usize = 255;

/// OPEN flags used by the SFTP handler (subset of SSH_FXF_*).
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenMode {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub exclusive: bool,
}

/// One OPEN/OPENDIR handle owned by a session.
#[cfg_attr(not(feature = "sftp-russh"), allow(dead_code))]
pub enum SftpHandle {
    File {
        id: u64,
        write: bool,
    },
    Dir {
        path: String,
        /// First READDIR returns names; later calls are EOF.
        exhausted: bool,
    },
}

/// Userspace SFTP view of a factory-built [`MountSource`].
pub struct RatarmountSftp {
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    inodes: Arc<InodeTable>,
    readers: Arc<ReaderLru>,
    readahead_bytes: usize,
}

impl RatarmountSftp {
    pub fn new(source: Arc<dyn MountSource>, readahead_bytes: usize, reader_slots: usize) -> Self {
        Self::with_overlay(source, readahead_bytes, reader_slots, None)
    }

    pub fn with_overlay(
        source: Arc<dyn MountSource>,
        readahead_bytes: usize,
        reader_slots: usize,
        overlay: Option<Arc<WriteOverlay>>,
    ) -> Self {
        Self {
            source,
            overlay,
            inodes: Arc::new(InodeTable::new()),
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

    /// Collapse SFTP paths onto the archive root (`/` + `normpath`).
    pub fn realpath(&self, path: &str) -> String {
        if path.is_empty() || path == "." {
            return "/".into();
        }
        ratarmount_core::normpath(path)
    }

    pub fn file_info_at(&self, path: &str) -> Result<FileInfo, i32> {
        let path = self.realpath(path);
        if path == "/" {
            let fi = create_root_file_info();
            let id = self.inodes.id_for_path("/");
            self.inodes.store_lookup_fi(id, fi.clone());
            return Ok(fi);
        }
        let id = self.inodes.id_for_path(&path);
        if self.overlay.is_none() {
            if let Some(fi) = self.inodes.cached_lookup_fi(id) {
                return Ok(fi);
            }
        }
        let fi = self.source.lookup(&path, 0).ok_or(libc::ENOENT)?;
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok(fi)
    }

    pub fn id_for_path(&self, path: &str) -> u64 {
        self.inodes.id_for_path(&self.realpath(path))
    }

    pub fn path_for_id(&self, id: u64) -> Result<String, i32> {
        self.inodes.path_for_id(id).ok_or(libc::ESTALE)
    }

    pub fn file_info(&self, id: u64) -> Result<FileInfo, i32> {
        let path = self.path_for_id(id)?;
        self.file_info_at(&path)
    }

    /// SSH_FXP_READ: pin the member reader and fill-loop (gzip short read ≠ EOF).
    pub fn read(&self, id: u64, offset: u64, len: u32) -> Result<Vec<u8>, i32> {
        let fi = self.file_info(id)?;
        if is_dir_mode(fi.mode) {
            return Err(libc::EISDIR);
        }
        if fi.size == 0 || offset >= fi.size || len == 0 {
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
        let want = len as usize;
        fill_from_state(&state, self.readahead_bytes, offset, want).map_err(|e| io_to_errno(&e))
    }

    pub fn readdir(&self, path: &str) -> Result<Vec<(String, FileInfo)>, i32> {
        let path = self.realpath(path);
        let fi = self.file_info_at(&path)?;
        if !is_dir_mode(fi.mode) {
            return Err(libc::ENOTDIR);
        }
        let dents = self.source.list_dirents(&path).ok_or(libc::ENOENT)?;
        let parent = parent_path(&path);
        let parent_fi = self.file_info_at(&parent).unwrap_or_else(|_| fi.clone());
        let mut out = Vec::with_capacity(dents.len() + 2);
        out.push((".".into(), fi.clone()));
        out.push(("..".into(), parent_fi));
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
            out.push((name, cfi));
        }
        Ok(out)
    }

    pub fn open_path(&self, path: &str, mode: OpenMode) -> Result<u64, i32> {
        let path = self.realpath(path);
        if mode.write || mode.create || mode.truncate {
            if !self.writable() {
                return Err(libc::EROFS);
            }
            return self.open_write(&path, mode);
        }
        let fi = self.file_info_at(&path)?;
        if is_dir_mode(fi.mode) {
            return Err(libc::EISDIR);
        }
        Ok(self.inodes.id_for_path(&path))
    }

    fn open_write(&self, path: &str, mode: OpenMode) -> Result<u64, i32> {
        let ov = self.overlay()?;
        let exists = self.source.lookup(path, 0).is_some();
        if mode.exclusive && exists {
            return Err(libc::EEXIST);
        }
        if mode.create && !exists {
            let fd = overlay_create_file(ov, path, 0o644).map_err(|e| io_to_errno(&e))?;
            ov.close_overlay_fd(fd);
        } else if !exists {
            return Err(libc::ENOENT);
        }
        if mode.truncate {
            overlay_truncate(ov, path, 0).map_err(|e| io_to_errno(&e))?;
        }
        let id = self.inodes.id_for_path(path);
        self.bump(id);
        Ok(id)
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
        drop(file);
        ov.release_write_fd(fd);
        wrote.map_err(|e| io_to_errno(&e))?;
        self.bump(id);
        Ok(data.len() as u32)
    }

    pub fn mkdir(&self, path: &str, perm: u32) -> Result<(), i32> {
        let ov = self.overlay()?;
        let path = self.realpath(path);
        check_leaf_name(&path)?;
        overlay_mkdir(ov, &path, perm).map_err(|e| io_to_errno(&e))?;
        let id = self.inodes.id_for_path(&path);
        self.bump(id);
        Ok(())
    }

    pub fn remove(&self, path: &str) -> Result<(), i32> {
        let ov = self.overlay()?;
        let path = self.realpath(path);
        check_leaf_name(&path)?;
        let id = self.inodes.id_for_path(&path);
        overlay_unlink(ov, &path).map_err(|e| io_to_errno(&e))?;
        self.bump(id);
        Ok(())
    }

    pub fn rmdir(&self, path: &str) -> Result<(), i32> {
        let ov = self.overlay()?;
        let path = self.realpath(path);
        check_leaf_name(&path)?;
        let id = self.inodes.id_for_path(&path);
        ov.rmdir(&path)
            .map_err(|e| io_to_errno(&overlay_to_io(e)))?;
        self.bump(id);
        Ok(())
    }

    pub fn rename(&self, old: &str, new: &str) -> Result<(), i32> {
        let ov = self.overlay()?;
        let from = self.realpath(old);
        let to = self.realpath(new);
        check_leaf_name(&from)?;
        check_leaf_name(&to)?;
        let from_id = self.inodes.id_for_path(&from);
        if let Some(dest_id) = self.inodes.id_if_present(&to) {
            self.bump(dest_id);
        }
        overlay_rename(ov, &from, &to).map_err(|e| io_to_errno(&e))?;
        self.inodes.rebind_path(from_id, &to);
        self.bump(from_id);
        Ok(())
    }

    pub fn setstat_size(&self, path: &str, size: u64) -> Result<(), i32> {
        let ov = self.overlay()?;
        let path = self.realpath(path);
        overlay_truncate(ov, &path, size).map_err(|e| io_to_errno(&e))?;
        let id = self.inodes.id_for_path(&path);
        self.bump(id);
        Ok(())
    }

    pub fn readlink(&self, path: &str) -> Result<String, i32> {
        let fi = self.file_info_at(path)?;
        if !is_lnk_mode(fi.mode) {
            return Err(libc::EINVAL);
        }
        Ok(fi.linkname)
    }

    pub fn symlink(&self, linkpath: &str, target: &str) -> Result<(), i32> {
        let ov = self.overlay()?;
        let path = self.realpath(linkpath);
        check_leaf_name(&path)?;
        ov.create_symlink(&path, target)
            .map_err(|e| io_to_errno(&overlay_to_io(e)))?;
        let id = self.inodes.id_for_path(&path);
        self.bump(id);
        Ok(())
    }
}

fn check_leaf_name(path: &str) -> Result<(), i32> {
    if path == "/" {
        return Err(libc::EINVAL);
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.is_empty() || name.contains('\0') {
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

/// Unix mode including type bits (SFTP v3 `permissions`).
#[cfg_attr(not(feature = "sftp-russh"), allow(dead_code))]
pub fn sftp_permissions(fi: &FileInfo) -> u32 {
    if fi.mode & S_IFMT == 0 {
        if is_dir_mode(fi.mode) {
            fi.mode | ratarmount_core::S_IFDIR
        } else {
            fi.mode | ratarmount_core::S_IFREG
        }
    } else {
        fi.mode
    }
}

#[cfg_attr(not(feature = "sftp-russh"), allow(dead_code))]
pub fn unix_mtime_u32(t: f64) -> u32 {
    if !t.is_finite() || t <= 0.0 {
        return 0;
    }
    let secs = t.trunc();
    if secs >= u32::MAX as f64 {
        u32::MAX
    } else {
        secs as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};
    use std::sync::Arc;

    use ratarmount_core::{create_root_file_info, ListResult, S_IFREG};
    use ratarmount_export_core::fill_read;

    struct EmptyFs;
    impl MountSource for EmptyFs {
        fn list(&self, path: &str) -> Option<ListResult> {
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

    struct ShortRead(Cursor<Vec<u8>>);
    impl Read for ShortRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }
    impl Seek for ShortRead {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }

    struct ShortFs {
        data: Vec<u8>,
    }
    impl MountSource for ShortFs {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                Some(ListResult::Names(vec!["blob".into()]))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(create_root_file_info())
            } else if path == "/blob" {
                Some(FileInfo {
                    size: self.data.len() as u64,
                    mtime: 1.0,
                    mode: S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                })
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(ShortRead(Cursor::new(self.data.clone()))))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: SFTP READ of a short `Read::read` is not truncated (gzip windows).
    #[test]
    fn fill_read_sftp_read_not_truncated() {
        let payload = b"hello!".to_vec();
        let fs = RatarmountSftp::new(
            Arc::new(ShortFs {
                data: payload.clone(),
            }),
            0,
            8,
        );
        let id = fs
            .open_path(
                "/blob",
                OpenMode {
                    read: true,
                    ..OpenMode::default()
                },
            )
            .unwrap();
        let body = fs.read(id, 0, 6).unwrap();
        assert_eq!(body, b"hello!");
    }

    #[test]
    fn fill_read_loops_until_full() {
        let mut r = ShortRead(Cursor::new(b"abcdef".to_vec()));
        let mut buf = [0u8; 6];
        let n = fill_read(&mut r, &mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf, b"abcdef");
    }

    /// Regression: writes without `-w` / overlay are EROFS.
    #[test]
    fn writers_erofs_without_overlay() {
        let fs = RatarmountSftp::new(Arc::new(EmptyFs), 0, 8);
        assert_eq!(fs.mkdir("/d", 0o755).unwrap_err(), libc::EROFS);
        assert_eq!(
            fs.open_path(
                "/x",
                OpenMode {
                    write: true,
                    create: true,
                    ..OpenMode::default()
                }
            )
            .unwrap_err(),
            libc::EROFS
        );
        assert_eq!(fs.remove("/x").unwrap_err(), libc::EROFS);
        assert_eq!(fs.rmdir("/d").unwrap_err(), libc::EROFS);
        assert_eq!(fs.rename("/a", "/b").unwrap_err(), libc::EROFS);
        assert_eq!(fs.setstat_size("/x", 0).unwrap_err(), libc::EROFS);
    }

    #[test]
    fn overlay_write_roundtrip() {
        let td = tempfile::tempdir().unwrap();
        let ov = Arc::new(
            WriteOverlay::new(Arc::new(EmptyFs) as Arc<dyn MountSource>, td.path())
                .expect("overlay"),
        );
        let fs = RatarmountSftp::with_overlay(ov.clone(), 0, 8, Some(ov));
        fs.mkdir("/d", 0o755).expect("mkdir");
        let id = fs
            .open_path(
                "/d/f",
                OpenMode {
                    write: true,
                    create: true,
                    truncate: true,
                    ..OpenMode::default()
                },
            )
            .expect("create");
        assert_eq!(fs.write(id, 0, b"sftp-ov").unwrap(), 7);
        let fi = fs.file_info_at("/d/f").expect("lookup after write");
        assert!(!is_dir_mode(fi.mode));
        assert_eq!(fi.size, 7);
        let body = fs.read(id, 0, 16).expect("read overlay");
        assert_eq!(body, b"sftp-ov");
        fs.rename("/d/f", "/d/g").expect("rename");
        fs.remove("/d/g").expect("unlink");
        fs.rmdir("/d").expect("rmdir");
    }

    #[test]
    fn realpath_collapses_dotdot_inside_root() {
        let fs = RatarmountSftp::new(Arc::new(EmptyFs), 0, 8);
        assert_eq!(fs.realpath(""), "/");
        assert_eq!(fs.realpath("."), "/");
        assert_eq!(fs.realpath("/a/../b"), "/b");
        assert_eq!(fs.realpath("/../../../etc/passwd"), "/etc/passwd");
    }
}
