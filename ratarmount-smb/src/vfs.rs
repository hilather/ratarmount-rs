//! `MountSource` adapter for SMB2 (inode table + reader LRU + overlay).

use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{
    create_root_file_info, is_dir_mode, is_lnk_mode, CheapDirent, FileInfo, MountSource,
};
use ratarmount_export_core::{
    fill_from_state, io_to_errno, overlay_create_file, overlay_mkdir, overlay_rename,
    overlay_to_io, overlay_truncate, overlay_unlink, InodeTable, ReaderLru, ROOT_FILEID,
};

use crate::smb2::{self, DirEntry, FileMeta};

const MAX_NAME_LEN: usize = 255;

/// Userspace SMB2 view of a factory-built [`MountSource`].
pub struct RatarmountSmb {
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    inodes: Arc<InodeTable>,
    readers: Arc<ReaderLru>,
    readahead_bytes: usize,
}

impl RatarmountSmb {
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

    fn overlay(&self) -> Result<&WriteOverlay, u32> {
        self.overlay.as_deref().ok_or(smb2::STATUS_ACCESS_DENIED)
    }

    fn bump(&self, id: u64) {
        self.readers.invalidate(id);
        self.inodes.clear_lookup_fi(id);
    }

    pub fn file_info(&self, id: u64) -> Result<FileInfo, u32> {
        let path = self
            .inodes
            .path_for_id(id)
            .ok_or(smb2::STATUS_FILE_CLOSED)?;
        if path == "/" {
            let fi = create_root_file_info();
            self.inodes.store_lookup_fi(id, fi.clone());
            return Ok(fi);
        }
        if self.overlay.is_none() {
            if let Some(fi) = self.inodes.cached_lookup_fi(id) {
                return Ok(fi);
            }
        }
        let fi = self
            .source
            .lookup(&path, 0)
            .ok_or(smb2::STATUS_OBJECT_NAME_NOT_FOUND)?;
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok(fi)
    }

    pub fn path_for_id(&self, id: u64) -> Result<String, u32> {
        self.inodes.path_for_id(id).ok_or(smb2::STATUS_FILE_CLOSED)
    }

    pub fn id_for_path(&self, path: &str) -> u64 {
        self.inodes.id_for_path(path)
    }

    pub fn lookup_path(&self, unix_path: &str) -> Result<(u64, FileInfo), u32> {
        let path = ratarmount_core::normpath(unix_path);
        if path == "/" {
            let fi = create_root_file_info();
            self.inodes.store_lookup_fi(ROOT_FILEID, fi.clone());
            return Ok((ROOT_FILEID, fi));
        }
        let fi = self
            .source
            .lookup(&path, 0)
            .ok_or(smb2::STATUS_OBJECT_NAME_NOT_FOUND)?;
        let id = self.inodes.id_for_path(&path);
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok((id, fi))
    }

    pub fn meta_for(&self, id: u64) -> Result<FileMeta, u32> {
        let path = self.path_for_id(id)?;
        let fi = self.file_info(id)?;
        Ok(FileMeta {
            inode: id,
            size: fi.size,
            mtime: fi.mtime,
            is_dir: is_dir_mode(fi.mode),
            is_lnk: is_lnk_mode(fi.mode),
            name: path,
            readonly: !self.writable(),
        })
    }

    pub fn list_dir(&self, id: u64, pattern: &str) -> Result<Vec<DirEntry>, u32> {
        let path = self.path_for_id(id)?;
        let fi = self.file_info(id)?;
        if !is_dir_mode(fi.mode) {
            return Err(smb2::STATUS_NOT_A_DIRECTORY);
        }
        let dents = self
            .source
            .list_dirents(&path)
            .ok_or(smb2::STATUS_OBJECT_NAME_NOT_FOUND)?;
        let mut out = Vec::new();
        let dot = DirEntry {
            name: ".".into(),
            inode: id,
            size: 0,
            mtime: fi.mtime,
            is_dir: true,
            is_lnk: false,
        };
        if smb2::glob_match(pattern, ".") {
            out.push(dot);
        }
        let parent = parent_path(&path);
        let parent_id = self.inodes.id_for_path(&parent);
        if smb2::glob_match(pattern, "..") {
            out.push(DirEntry {
                name: "..".into(),
                inode: parent_id,
                size: 0,
                mtime: fi.mtime,
                is_dir: true,
                is_lnk: false,
            });
        }
        for CheapDirent { name, mode, size } in dents {
            if name == "." || name == ".." {
                continue;
            }
            if !smb2::glob_match(pattern, &name) {
                continue;
            }
            let child = join_path(&path, &name);
            let cid = self.inodes.id_for_path(&child);
            let (is_dir, is_lnk, sz, mtime) = if let Some(looked) = self.source.lookup(&child, 0) {
                self.inodes.store_lookup_fi(cid, looked.clone());
                (
                    is_dir_mode(looked.mode),
                    is_lnk_mode(looked.mode),
                    looked.size,
                    looked.mtime,
                )
            } else {
                (is_dir_mode(mode), is_lnk_mode(mode), size, 0.0)
            };
            out.push(DirEntry {
                name,
                inode: cid,
                size: sz,
                mtime,
                is_dir,
                is_lnk,
            });
        }
        Ok(out)
    }

    pub fn read(&self, id: u64, offset: u64, count: u32) -> Result<Vec<u8>, u32> {
        let fi = self.file_info(id)?;
        if is_dir_mode(fi.mode) {
            return Err(smb2::STATUS_FILE_IS_A_DIRECTORY);
        }
        if fi.size == 0 || offset >= fi.size || count == 0 {
            return Ok(Vec::new());
        }
        let (_fi, state) = self
            .readers
            .get_or_open(self.source.as_ref(), &self.inodes, id)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    smb2::STATUS_OBJECT_NAME_NOT_FOUND
                } else {
                    errno_to_nt(io_to_errno(&e))
                }
            })?;
        let want = (count as usize).min(smb2::MAX_READ as usize);
        fill_from_state(&state, self.readahead_bytes, offset, want)
            .map_err(|e| errno_to_nt(io_to_errno(&e)))
    }

    pub fn create_file(&self, unix_path: &str, mode: u32) -> Result<(u64, FileInfo), u32> {
        let ov = self.overlay()?;
        let path = ratarmount_core::normpath(unix_path);
        check_leaf(&path)?;
        let fd = overlay_create_file(ov, &path, mode).map_err(|e| errno_to_nt(io_to_errno(&e)))?;
        ov.close_overlay_fd(fd);
        let id = self.inodes.id_for_path(&path);
        self.bump(id);
        let fi = self
            .source
            .lookup(&path, 0)
            .ok_or(smb2::STATUS_OBJECT_NAME_NOT_FOUND)?;
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok((id, fi))
    }

    pub fn mkdir(&self, unix_path: &str, mode: u32) -> Result<(u64, FileInfo), u32> {
        let ov = self.overlay()?;
        let path = ratarmount_core::normpath(unix_path);
        check_leaf(&path)?;
        overlay_mkdir(ov, &path, mode).map_err(|e| errno_to_nt(io_to_errno(&e)))?;
        let id = self.inodes.id_for_path(&path);
        self.bump(id);
        let fi = self
            .source
            .lookup(&path, 0)
            .ok_or(smb2::STATUS_OBJECT_NAME_NOT_FOUND)?;
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok((id, fi))
    }

    pub fn unlink(&self, id: u64) -> Result<(), u32> {
        let ov = self.overlay()?;
        let path = self.path_for_id(id)?;
        if path == "/" {
            return Err(smb2::STATUS_ACCESS_DENIED);
        }
        let is_dir = self
            .file_info(id)
            .map(|fi| is_dir_mode(fi.mode))
            .unwrap_or(false);
        if is_dir {
            ov.rmdir(&path)
                .map_err(|e| errno_to_nt(io_to_errno(&overlay_to_io(e))))?;
        } else {
            overlay_unlink(ov, &path).map_err(|e| errno_to_nt(io_to_errno(&e)))?;
        }
        self.bump(id);
        Ok(())
    }

    pub fn truncate(&self, id: u64, size: u64) -> Result<(), u32> {
        let ov = self.overlay()?;
        let path = self.path_for_id(id)?;
        overlay_truncate(ov, &path, size).map_err(|e| errno_to_nt(io_to_errno(&e)))?;
        self.bump(id);
        Ok(())
    }

    pub fn rename(&self, id: u64, new_unix: &str) -> Result<(), u32> {
        let ov = self.overlay()?;
        let from = self.path_for_id(id)?;
        let to = ratarmount_core::normpath(new_unix);
        check_leaf(&to)?;
        if let Some(dest_id) = self.inodes.id_if_present(&to) {
            self.bump(dest_id);
        }
        overlay_rename(ov, &from, &to).map_err(|e| errno_to_nt(io_to_errno(&e)))?;
        self.inodes.rebind_path(id, &to);
        self.bump(id);
        Ok(())
    }

    pub fn write(&self, id: u64, offset: u64, data: &[u8]) -> Result<u32, u32> {
        let ov = self.overlay()?;
        let path = self.path_for_id(id)?;
        let flags = libc::O_RDWR | libc::O_CREAT;
        let fd = ov
            .open_overlay_fd(&path, flags)
            .map_err(|e| errno_to_nt(io_to_errno(&overlay_to_io(e))))?;
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let wrote = file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(data));
        drop(file);
        ov.release_write_fd(fd);
        wrote.map_err(|e| errno_to_nt(io_to_errno(&e)))?;
        self.bump(id);
        Ok(data.len() as u32)
    }
}

pub fn errno_to_nt(e: i32) -> u32 {
    match e {
        x if x == libc::ENOENT => smb2::STATUS_OBJECT_NAME_NOT_FOUND,
        x if x == libc::EACCES => smb2::STATUS_ACCESS_DENIED,
        x if x == libc::EPERM => smb2::STATUS_ACCESS_DENIED,
        x if x == libc::EEXIST => smb2::STATUS_OBJECT_NAME_COLLISION,
        x if x == libc::EISDIR => smb2::STATUS_FILE_IS_A_DIRECTORY,
        x if x == libc::ENOTDIR => smb2::STATUS_NOT_A_DIRECTORY,
        x if x == libc::EROFS => smb2::STATUS_MEDIA_WRITE_PROTECTED,
        x if x == libc::EINVAL => smb2::STATUS_INVALID_PARAMETER,
        x if x == libc::ENOSYS => smb2::STATUS_NOT_SUPPORTED,
        x if x == libc::ENOTEMPTY => smb2::STATUS_DIRECTORY_NOT_EMPTY,
        x if x == libc::ESTALE => smb2::STATUS_FILE_CLOSED,
        _ => smb2::STATUS_ACCESS_DENIED,
    }
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
        Some(0) | None => "/".into(),
        Some(i) => path[..i].to_string(),
    }
}

fn check_leaf(path: &str) -> Result<(), u32> {
    if path == "/" {
        return Err(smb2::STATUS_INVALID_PARAMETER);
    }
    let name = smb2::basename_unix(path);
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.contains('\0') {
        return Err(smb2::STATUS_INVALID_PARAMETER);
    }
    Ok(())
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

    /// Regression: writes without overlay are ACCESS_DENIED (not a generic I/O error).
    #[test]
    fn writers_denied_without_overlay() {
        let fs = RatarmountSmb::new(Arc::new(EmptyFs), 0, 8);
        assert_eq!(
            fs.mkdir("/d", 0o755).unwrap_err(),
            smb2::STATUS_ACCESS_DENIED
        );
        assert_eq!(
            fs.create_file("/x", 0o644).unwrap_err(),
            smb2::STATUS_ACCESS_DENIED
        );
        assert_eq!(
            fs.write(ROOT_FILEID, 0, b"x").unwrap_err(),
            smb2::STATUS_ACCESS_DENIED
        );
        assert_eq!(
            fs.unlink(ROOT_FILEID).unwrap_err(),
            smb2::STATUS_ACCESS_DENIED
        );
    }
}
