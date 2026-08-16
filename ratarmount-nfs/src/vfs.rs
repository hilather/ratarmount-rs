//! `NFSFileSystem` on `MountSource`, with optional write overlay.

use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use async_trait::async_trait;
use nfsserve::nfs::{
    fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, set_mode3, set_size3,
    specdata3, FSF_HOMOGENEOUS, FSF_SYMLINK,
};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{is_dir_mode, is_lnk_mode, FileInfo, MountSource, S_IFMT};

use crate::inode::{InodeTable, ROOT_FILEID};
use crate::names::{decode_filename, encode_filename, join_path, parent_path};
use crate::reader::{fill_from_state, ReaderLru, DEFAULT_READER_SLOTS};

/// Userspace NFSv3 view of a factory-built [`MountSource`].
pub struct RatarmountNfs {
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    inodes: Arc<InodeTable>,
    readers: Arc<ReaderLru>,
    readahead_bytes: usize,
}

impl RatarmountNfs {
    pub fn new(source: Arc<dyn MountSource>, readahead_bytes: usize) -> Self {
        Self::with_overlay(source, readahead_bytes, None)
    }

    pub fn with_overlay(
        source: Arc<dyn MountSource>,
        readahead_bytes: usize,
        overlay: Option<Arc<WriteOverlay>>,
    ) -> Self {
        Self {
            source,
            overlay,
            inodes: Arc::new(InodeTable::new()),
            readers: Arc::new(ReaderLru::new(DEFAULT_READER_SLOTS)),
            readahead_bytes,
        }
    }

    fn writable(&self) -> bool {
        self.overlay.is_some()
    }

    fn overlay(&self) -> Result<&WriteOverlay, nfsstat3> {
        self.overlay.as_deref().ok_or(nfsstat3::NFS3ERR_ROFS)
    }

    fn bump_after_mutate(&self, id: fileid3) {
        self.readers.invalidate(id);
        self.inodes.clear_lookup_fi(id);
    }

    fn file_info_for_id(&self, id: fileid3) -> Result<FileInfo, nfsstat3> {
        let path = self.inodes.path_for_id(id).ok_or(nfsstat3::NFS3ERR_STALE)?;
        if path == "/" {
            let fi = ratarmount_core::create_root_file_info();
            self.inodes.store_lookup_fi(id, fi.clone());
            return Ok(fi);
        }
        // Overlay sizes change after create/write/truncate — do not trust cache.
        if self.overlay.is_none() {
            if let Some(fi) = self.inodes.cached_lookup_fi(id) {
                return Ok(fi);
            }
        }
        let fi = self
            .source
            .lookup(&path, 0)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok(fi)
    }

    fn fattr(id: fileid3, fi: &FileInfo) -> fattr3 {
        let t = unix_float_to_nfs_time(fi.mtime);
        fattr3 {
            ftype: mode_to_ftype(fi.mode),
            mode: fi.mode & 0o7777,
            nlink: 1,
            uid: fi.uid,
            gid: fi.gid,
            size: fi.size,
            used: fi.size,
            rdev: specdata3::default(),
            fsid: 1,
            fileid: id,
            atime: t,
            mtime: t,
            ctime: t,
        }
    }

    /// Path-only id assign, then lookup + cache `FileInfo`.
    pub fn lookup_sync(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let name = decode_filename(filename)?;
        let parent = self
            .inodes
            .path_for_id(dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        if name == "." {
            return Ok(dirid);
        }
        if name == ".." {
            return Ok(self.inodes.id_for_path(&parent_path(&parent)));
        }
        let path = join_path(&parent, &name);
        let fi = self
            .source
            .lookup(&path, 0)
            .ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let id = self.inodes.id_for_path(&path);
        self.inodes.store_lookup_fi(id, fi);
        Ok(id)
    }

    pub fn getattr_sync(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let fi = self.file_info_for_id(id)?;
        Ok(Self::fattr(id, &fi))
    }

    pub fn readdir_sync(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let path = self
            .inodes
            .path_for_id(dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let Some(dents) = self.source.list_dirents(&path) else {
            if let Ok(fi) = self.file_info_for_id(dirid) {
                if !is_dir_mode(fi.mode) {
                    return Err(nfsstat3::NFS3ERR_NOTDIR);
                }
            }
            return Err(nfsstat3::NFS3ERR_NOENT);
        };
        let mut kids: Vec<(u64, String, u32, u64)> = dents
            .into_iter()
            .map(|d| {
                let child = join_path(&path, &d.name);
                let id = self.inodes.id_for_path(&child);
                (id, d.name, d.mode, d.size)
            })
            .collect();
        kids.sort_by_key(|(id, _, _, _)| *id);

        let start_idx = if start_after == 0 {
            0
        } else {
            match kids.iter().position(|(id, _, _, _)| *id == start_after) {
                Some(i) => i + 1,
                None => return Err(nfsstat3::NFS3ERR_BAD_COOKIE),
            }
        };
        let slice = &kids[start_idx..];
        let take = slice.len().min(max_entries);
        let end = start_idx + take >= kids.len();
        let mut entries = Vec::with_capacity(take);
        for (id, name, mode, cheap_size) in &slice[..take] {
            let child = join_path(&path, name);
            let fi = if *cheap_size > 0 {
                FileInfo {
                    size: *cheap_size,
                    mtime: 0.0,
                    mode: *mode,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                }
            } else if let Some(looked) = self.source.lookup(&child, 0) {
                self.inodes.store_lookup_fi(*id, looked.clone());
                looked
            } else {
                FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: *mode,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                }
            };
            // Cheap fi with size>0 is **only** used for READDIRPLUS attrs, not stored.
            entries.push(DirEntry {
                fileid: *id,
                name: encode_filename(name),
                attr: Self::fattr(*id, &fi),
            });
        }
        Ok(ReadDirResult { entries, end })
    }

    pub fn readlink_sync(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        let fi = self.file_info_for_id(id)?;
        if !is_lnk_mode(fi.mode) {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        Ok(nfspath3::from(fi.linkname.as_bytes()))
    }

    pub fn read_sync(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        read_member(
            self.source.as_ref(),
            &self.inodes,
            &self.readers,
            self.readahead_bytes,
            id,
            offset,
            count,
        )
    }

    pub fn create_sync(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let ov = self.overlay()?;
        let name = decode_filename(filename)?;
        let parent = self
            .inodes
            .path_for_id(dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let path = join_path(&parent, &name);
        let mode = match attr.mode {
            set_mode3::mode(m) => m,
            set_mode3::Void => 0o644,
        };
        let fd = ov.create_file(&path, mode).map_err(overlay_to_nfs)?;
        // NFS create is stateless — close the overlay fd (FUSE would keep it).
        close_overlay_fd(fd);
        let id = self.inodes.id_for_path(&path);
        self.bump_after_mutate(id);
        if let Some(fi) = self.source.lookup(&path, 0) {
            self.inodes.store_lookup_fi(id, fi);
        }
        Ok((id, self.getattr_sync(id)?))
    }

    pub fn create_exclusive_sync(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        let name = decode_filename(filename)?;
        let parent = self
            .inodes
            .path_for_id(dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let path = join_path(&parent, &name);
        if self.source.lookup(&path, 0).is_some() {
            return Err(nfsstat3::NFS3ERR_EXIST);
        }
        let (id, _) = self.create_sync(dirid, filename, sattr3::default())?;
        Ok(id)
    }

    pub fn write_sync(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        let ov = self.overlay()?;
        let path = self.inodes.path_for_id(id).ok_or(nfsstat3::NFS3ERR_STALE)?;
        let flags = libc::O_RDWR | libc::O_CREAT;
        let fd = ov.open_overlay_fd(&path, flags).map_err(overlay_to_nfs)?;
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| crate::io_to_nfsstat3(&e))?;
        file.write_all(data)
            .map_err(|e| crate::io_to_nfsstat3(&e))?;
        drop(file);
        self.bump_after_mutate(id);
        self.getattr_sync(id)
    }

    pub fn mkdir_sync(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let ov = self.overlay()?;
        let name = decode_filename(dirname)?;
        let parent = self
            .inodes
            .path_for_id(dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let path = join_path(&parent, &name);
        ov.mkdir(&path, 0o755).map_err(overlay_to_nfs)?;
        let id = self.inodes.id_for_path(&path);
        self.bump_after_mutate(id);
        if let Some(fi) = self.source.lookup(&path, 0) {
            self.inodes.store_lookup_fi(id, fi);
        }
        Ok((id, self.getattr_sync(id)?))
    }

    pub fn remove_sync(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let ov = self.overlay()?;
        let name = decode_filename(filename)?;
        let parent = self
            .inodes
            .path_for_id(dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let path = join_path(&parent, &name);
        let id = self.inodes.id_for_path(&path);
        let is_dir = self
            .source
            .lookup(&path, 0)
            .map(|fi| is_dir_mode(fi.mode))
            .unwrap_or(false);
        if is_dir {
            ov.rmdir(&path).map_err(overlay_to_nfs)?;
        } else {
            ov.unlink(&path).map_err(overlay_to_nfs)?;
        }
        self.bump_after_mutate(id);
        Ok(())
    }

    pub fn setattr_sync(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let ov = self.overlay()?;
        let path = self.inodes.path_for_id(id).ok_or(nfsstat3::NFS3ERR_STALE)?;
        if let set_size3::size(sz) = setattr.size {
            ov.truncate(&path, sz).map_err(overlay_to_nfs)?;
            self.bump_after_mutate(id);
        }
        self.getattr_sync(id)
    }

    pub fn rename_sync(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let ov = self.overlay()?;
        let from_name = decode_filename(from_filename)?;
        let to_name = decode_filename(to_filename)?;
        let from_parent = self
            .inodes
            .path_for_id(from_dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let to_parent = self
            .inodes
            .path_for_id(to_dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let from = join_path(&from_parent, &from_name);
        let to = join_path(&to_parent, &to_name);
        let from_id = self.inodes.id_for_path(&from);
        if let Some(dest_id) = self.inodes.id_if_present(&to) {
            self.bump_after_mutate(dest_id);
        }
        ov.rename(&from, &to).map_err(overlay_to_nfs)?;
        self.inodes.rebind_path(from_id, &to);
        self.bump_after_mutate(from_id);
        Ok(())
    }

    pub fn symlink_sync(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let ov = self.overlay()?;
        let name = decode_filename(linkname)?;
        let parent = self
            .inodes
            .path_for_id(dirid)
            .ok_or(nfsstat3::NFS3ERR_STALE)?;
        let path = join_path(&parent, &name);
        let target = std::str::from_utf8(symlink.as_ref())
            .map_err(|_| nfsstat3::NFS3ERR_INVAL)?
            .to_string();
        ov.create_symlink(&path, &target).map_err(overlay_to_nfs)?;
        let id = self.inodes.id_for_path(&path);
        self.bump_after_mutate(id);
        if let Some(fi) = self.source.lookup(&path, 0) {
            self.inodes.store_lookup_fi(id, fi);
        }
        Ok((id, self.getattr_sync(id)?))
    }
}

fn overlay_to_nfs(err: ratarmount_compositing::OverlayError) -> nfsstat3 {
    match err {
        ratarmount_compositing::OverlayError::Io(e) => crate::io_to_nfsstat3(&e),
        other => crate::io_to_nfsstat3(&io::Error::other(other.to_string())),
    }
}

fn close_overlay_fd(fd: i32) {
    let _ = unsafe { std::fs::File::from_raw_fd(fd) };
}

fn read_member(
    source: &dyn MountSource,
    inodes: &InodeTable,
    readers: &ReaderLru,
    readahead_bytes: usize,
    id: fileid3,
    offset: u64,
    count: u32,
) -> Result<(Vec<u8>, bool), nfsstat3> {
    let path = inodes.path_for_id(id).ok_or(nfsstat3::NFS3ERR_STALE)?;
    let fi_check = if path == "/" {
        ratarmount_core::create_root_file_info()
    } else if let Some(c) = inodes.cached_lookup_fi(id) {
        c
    } else {
        source.lookup(&path, 0).ok_or(nfsstat3::NFS3ERR_STALE)?
    };
    if is_dir_mode(fi_check.mode) {
        return Err(nfsstat3::NFS3ERR_ISDIR);
    }
    let (fi, state) = readers.get_or_open(source, inodes, id).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            nfsstat3::NFS3ERR_STALE
        } else {
            crate::io_to_nfsstat3(&e)
        }
    })?;
    if fi.size == 0 || offset >= fi.size {
        return Ok((Vec::new(), true));
    }
    let buf = fill_from_state(&state, readahead_bytes, offset, count as usize)
        .map_err(|e| crate::io_to_nfsstat3(&e))?;
    let eof = offset.saturating_add(buf.len() as u64) >= fi.size || buf.len() < count as usize;
    Ok((buf, eof))
}

fn mode_to_ftype(mode: u32) -> ftype3 {
    match mode & S_IFMT {
        x if x == ratarmount_core::S_IFDIR => ftype3::NF3DIR,
        x if x == ratarmount_core::S_IFLNK => ftype3::NF3LNK,
        x if x == ratarmount_core::S_IFIFO => ftype3::NF3FIFO,
        x if x == ratarmount_core::S_IFCHR => ftype3::NF3CHR,
        x if x == ratarmount_core::S_IFBLK => ftype3::NF3BLK,
        x if x == ratarmount_core::S_IFSOCK => ftype3::NF3SOCK,
        _ => ftype3::NF3REG,
    }
}

fn unix_float_to_nfs_time(t: f64) -> nfstime3 {
    if t <= 0.0 {
        return nfstime3 {
            seconds: 0,
            nseconds: 0,
        };
    }
    let secs = t.trunc() as u32;
    let nsec = ((t.fract()) * 1e9) as u32;
    nfstime3 {
        seconds: secs,
        nseconds: nsec,
    }
}

#[async_trait]
impl NFSFileSystem for RatarmountNfs {
    fn capabilities(&self) -> VFSCapabilities {
        if self.writable() {
            VFSCapabilities::ReadWrite
        } else {
            VFSCapabilities::ReadOnly
        }
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_FILEID
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        self.lookup_sync(dirid, filename)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        self.getattr_sync(id)
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        self.setattr_sync(id, setattr)
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let source = Arc::clone(&self.source);
        let inodes = Arc::clone(&self.inodes);
        let readers = Arc::clone(&self.readers);
        let readahead = self.readahead_bytes;
        tokio::task::spawn_blocking(move || {
            read_member(
                source.as_ref(),
                &inodes,
                &readers,
                readahead,
                id,
                offset,
                count,
            )
        })
        .await
        .unwrap_or(Err(nfsstat3::NFS3ERR_IO))
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        self.write_sync(id, offset, data)
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        self.create_sync(dirid, filename, attr)
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        self.create_exclusive_sync(dirid, filename)
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        self.mkdir_sync(dirid, dirname)
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        self.remove_sync(dirid, filename)
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        self.rename_sync(from_dirid, from_filename, to_dirid, to_filename)
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        self.readdir_sync(dirid, start_after, max_entries)
    }

    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        self.symlink_sync(dirid, linkname, symlink, attr)
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        self.readlink_sync(id)
    }

    async fn fsinfo(&self, root_fileid: fileid3) -> Result<nfsserve::nfs::fsinfo3, nfsstat3> {
        let dir_attr = match self.getattr_sync(root_fileid) {
            Ok(v) => nfsserve::nfs::post_op_attr::attributes(v),
            Err(_) => nfsserve::nfs::post_op_attr::Void,
        };
        let namemax = self.source.statfs().namemax.min(u64::from(u32::MAX)) as u32;
        Ok(nfsserve::nfs::fsinfo3 {
            obj_attributes: dir_attr,
            rtmax: 1024 * 1024,
            rtpref: 1024 * 1024,
            rtmult: 4096,
            wtmax: if self.writable() { 1024 * 1024 } else { 0 },
            wtpref: if self.writable() { 1024 * 1024 } else { 0 },
            wtmult: if self.writable() { 4096 } else { 0 },
            dtpref: namemax.max(1),
            maxfilesize: u64::MAX,
            time_delta: nfstime3 {
                seconds: 1,
                nseconds: 0,
            },
            properties: FSF_SYMLINK | FSF_HOMOGENEOUS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{self, Cursor};

    use ratarmount_core::{CheapDirent, FileInfo, ListResult, UserData, S_IFLNK, S_IFREG};

    struct Synth {
        files: BTreeMap<String, (FileInfo, Vec<u8>)>,
        dirs: BTreeMap<String, Vec<CheapDirent>>,
        /// When true, `list_dirents` reports size 0 (default MountSource).
        cheap_size_zero: bool,
    }

    impl Synth {
        fn new() -> Self {
            let mut dirs = BTreeMap::new();
            dirs.insert("/".into(), vec![]);
            Self {
                files: BTreeMap::new(),
                dirs,
                cheap_size_zero: false,
            }
        }

        fn add_file(&mut self, path: &str, body: &[u8], userdata: Vec<UserData>) {
            let name = path.rsplit('/').next().unwrap().to_string();
            let parent = if path.matches('/').count() == 1 {
                "/".to_string()
            } else {
                path.rsplit_once('/').unwrap().0.to_string()
            };
            let fi = FileInfo {
                size: body.len() as u64,
                mtime: 1.0,
                mode: S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata,
            };
            self.files.insert(path.into(), (fi.clone(), body.to_vec()));
            self.dirs.entry(parent).or_default().push(CheapDirent {
                name,
                mode: fi.mode,
                size: fi.size,
            });
        }

        fn add_link(&mut self, path: &str, target: &str) {
            let name = path.rsplit('/').next().unwrap().to_string();
            let fi = FileInfo {
                size: target.len() as u64,
                mtime: 1.0,
                mode: S_IFLNK | 0o777,
                linkname: target.into(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            };
            self.files.insert(path.into(), (fi.clone(), Vec::new()));
            self.dirs.entry("/".into()).or_default().push(CheapDirent {
                name,
                mode: fi.mode,
                size: 0,
            });
        }
    }

    impl MountSource for Synth {
        fn list(&self, path: &str) -> Option<ListResult> {
            let dents = self.list_dirents(path)?;
            Some(ListResult::Names(
                dents.into_iter().map(|d| d.name).collect(),
            ))
        }

        fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
            let mut d = self.dirs.get(path)?.clone();
            if self.cheap_size_zero {
                for e in &mut d {
                    e.size = 0;
                }
            }
            Some(d)
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(ratarmount_core::create_root_file_info());
            }
            self.files.get(path).map(|(fi, _)| fi.clone())
        }

        fn open(
            &self,
            file_info: &FileInfo,
            _: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            if file_info.userdata.is_empty() && file_info.size > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing TAR userdata",
                ));
            }
            for (_, body) in self.files.values() {
                if body.len() as u64 == file_info.size {
                    return Ok(Box::new(Cursor::new(body.clone())));
                }
            }
            Ok(Box::new(Cursor::new(Vec::new())))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    fn nfs_of(s: Synth) -> RatarmountNfs {
        RatarmountNfs::new(Arc::new(s), 0)
    }

    fn name(s: &str) -> filename3 {
        filename3::from(s.as_bytes())
    }

    fn stat_u32(s: nfsstat3) -> u32 {
        s as u32
    }

    #[test]
    fn root_and_lookup_stable() {
        let mut s = Synth::new();
        s.add_file("/a.txt", b"hi", vec![UserData::Other("tar".into())]);
        let nfs = nfs_of(s);
        assert_eq!(nfs.root_dir(), 1);
        let id = nfs.lookup_sync(1, &name("a.txt")).unwrap();
        assert!(id >= 2);
        assert_eq!(nfs.lookup_sync(1, &name("a.txt")).unwrap(), id);
        let attr = nfs.getattr_sync(id).unwrap();
        assert_eq!(attr.size, 2);
        assert_eq!(attr.fileid, id);
    }

    #[test]
    fn missing_is_noent_unknown_id_stale() {
        let nfs = nfs_of(Synth::new());
        assert_eq!(
            stat_u32(nfs.lookup_sync(1, &name("nope")).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_NOENT)
        );
        assert_eq!(
            stat_u32(nfs.getattr_sync(99).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_STALE)
        );
    }

    #[test]
    fn readdir_start_after_and_bad_cookie() {
        let mut s = Synth::new();
        s.add_file("/a", b"1", vec![UserData::Other("t".into())]);
        s.add_file("/b", b"2", vec![UserData::Other("t".into())]);
        let nfs = nfs_of(s);
        let all = nfs.readdir_sync(1, 0, 10).unwrap();
        assert_eq!(all.entries.len(), 2);
        assert!(all.end);
        let first = all.entries[0].fileid;
        let rest = nfs.readdir_sync(1, first, 10).unwrap();
        assert_eq!(rest.entries.len(), 1);
        assert!(rest.end);
        assert_eq!(
            stat_u32(nfs.readdir_sync(1, 9999, 10).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_BAD_COOKIE)
        );
    }

    #[test]
    fn writers_rofs() {
        let nfs = nfs_of(Synth::new());
        let empty = sattr3::default();
        assert_eq!(
            stat_u32(nfs.create_sync(1, &name("x"), empty).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_ROFS)
        );
        assert_eq!(
            stat_u32(nfs.write_sync(1, 0, b"x").unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_ROFS)
        );
        assert_eq!(
            stat_u32(nfs.mkdir_sync(1, &name("d")).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_ROFS)
        );
        assert_eq!(
            stat_u32(nfs.remove_sync(1, &name("x")).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_ROFS)
        );
        let sat = sattr3 {
            size: set_size3::size(0),
            ..sattr3::default()
        };
        assert_eq!(
            stat_u32(nfs.setattr_sync(1, sat).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_ROFS)
        );
        assert_eq!(
            stat_u32(nfs.create_exclusive_sync(1, &name("x")).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_ROFS)
        );
        assert_eq!(
            stat_u32(nfs.rename_sync(1, &name("a"), 1, &name("b")).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_ROFS)
        );
        let target = nfspath3::from(&b"t"[..]);
        assert_eq!(
            stat_u32(
                nfs.symlink_sync(1, &name("l"), &target, &sattr3::default())
                    .unwrap_err()
            ),
            stat_u32(nfsstat3::NFS3ERR_ROFS)
        );
    }

    fn overlay_export(base: Synth) -> (tempfile::TempDir, RatarmountNfs) {
        let td = tempfile::tempdir().unwrap();
        let ov = Arc::new(
            WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, td.path()).expect("overlay"),
        );
        let nfs = RatarmountNfs::with_overlay(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            0,
            Some(Arc::clone(&ov)),
        );
        (td, nfs)
    }

    #[test]
    fn overlay_create_write_read_mkdir_readdir() {
        let mut base = Synth::new();
        base.add_file("/keep", b"archive", vec![UserData::Other("t".into())]);
        let (_td, nfs) = overlay_export(base);

        let (id, attr) = nfs
            .create_sync(1, &name("new.txt"), sattr3::default())
            .expect("create");
        assert_eq!(attr.size, 0);
        let attr = nfs.write_sync(id, 0, b"hello-overlay").expect("write");
        assert_eq!(attr.size, 13);
        let got = nfs.getattr_sync(id).expect("getattr");
        assert_eq!(got.size, 13);
        let (buf, eof) = nfs.read_sync(id, 0, 32).expect("read");
        assert_eq!(buf, b"hello-overlay");
        assert!(eof);

        let (_did, _) = nfs.mkdir_sync(1, &name("sub")).expect("mkdir");
        let listing = nfs.readdir_sync(1, 0, 32).expect("readdir");
        let names: Vec<String> = listing
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(e.name.as_ref()).into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "new.txt"), "{names:?}");
        assert!(names.iter().any(|n| n == "sub"), "{names:?}");
        assert!(names.iter().any(|n| n == "keep"), "{names:?}");
    }

    #[test]
    fn overlay_rename_and_symlink() {
        let mut base = Synth::new();
        base.add_file("/keep", b"archive", vec![UserData::Other("t".into())]);
        let (_td, nfs) = overlay_export(base);

        let (id, _) = nfs
            .create_sync(1, &name("src.txt"), sattr3::default())
            .expect("create");
        nfs.write_sync(id, 0, b"moved").expect("write");
        nfs.rename_sync(1, &name("src.txt"), 1, &name("dst.txt"))
            .expect("rename");
        assert_eq!(
            stat_u32(nfs.lookup_sync(1, &name("src.txt")).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_NOENT)
        );
        let dst = nfs.lookup_sync(1, &name("dst.txt")).expect("dst lookup");
        let (buf, _) = nfs.read_sync(dst, 0, 32).expect("read renamed");
        assert_eq!(buf, b"moved");

        let target = nfspath3::from(&b"dst.txt"[..]);
        let (lid, lattr) = nfs
            .symlink_sync(1, &name("link"), &target, &sattr3::default())
            .expect("symlink");
        assert_eq!(lattr.ftype as u32, ftype3::NF3LNK as u32);
        let got = nfs.readlink_sync(lid).expect("readlink");
        assert_eq!(got.as_ref(), b"dst.txt");

        let listing = nfs.readdir_sync(1, 0, 32).expect("readdir");
        let names: Vec<String> = listing
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(e.name.as_ref()).into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "dst.txt"), "{names:?}");
        assert!(names.iter().any(|n| n == "link"), "{names:?}");
        assert!(!names.iter().any(|n| n == "src.txt"), "{names:?}");
    }

    /// Regression: interval live commit wipes overlay files; a later NFS READ
    /// must re-lookup the new TAR base (not open a stale overlay: FileInfo).
    #[test]
    fn overlay_commit_live_then_nfs_read_readdir() {
        use std::fs;
        use std::process::Command as StdCommand;
        use std::sync::Arc;

        let gnu = StdCommand::new("tar").arg("--version").output();
        let gnu_ok = gnu
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("GNU tar"))
            .unwrap_or(false);
        if !gnu_ok {
            eprintln!("skip: GNU tar missing");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("expected.bin");
        fs::write(
            &expected,
            format!("nfs-live-commit-{}\n", std::process::id()),
        )
        .unwrap();
        let tree = dir.path().join("tree");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("seed.txt"), b"seed\n").unwrap();
        let tar = dir.path().join("a.tar");
        assert!(StdCommand::new("tar")
            .args(["-cf"])
            .arg(&tar)
            .arg("-C")
            .arg(&tree)
            .arg("seed.txt")
            .status()
            .unwrap()
            .success());

        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let mut materialised = None;
        let base = ratarmount_formats_tar::SqliteIndexedTar::create_index(
            &tar,
            &tar,
            None,
            &opts,
            "test",
            &mut materialised,
        )
        .expect("index tar");
        let ov_dir = dir.path().join("ov");
        fs::create_dir_all(&ov_dir).unwrap();
        let ov = Arc::new(
            WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &ov_dir).expect("overlay"),
        );
        let nfs = RatarmountNfs::with_overlay(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            0,
            Some(Arc::clone(&ov)),
        );

        let payload = fs::read(&expected).unwrap();
        let (id, _) = nfs
            .create_sync(1, &name("tick.bin"), sattr3::default())
            .expect("create");
        nfs.write_sync(id, 0, &payload).expect("write");
        let (before, _) = nfs.read_sync(id, 0, 64).expect("read overlay");
        assert_eq!(before, payload);

        ov.commit_live_uncompressed_tar(&tar, |p| {
            let mut mat = None;
            ratarmount_formats_tar::SqliteIndexedTar::create_index(
                p, p, None, &opts, "test", &mut mat,
            )
            .map(|t| Arc::new(t) as Arc<dyn MountSource>)
            .map_err(|e| ratarmount_compositing::OverlayError::Msg(e.to_string()))
        })
        .expect("commit_live");

        let listing = nfs.readdir_sync(1, 0, 32).expect("readdir after commit");
        let names: Vec<String> = listing
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(e.name.as_ref()).into_owned())
            .collect();
        assert!(
            names.iter().any(|n| n == "tick.bin"),
            "NFS readdir missing committed name: {names:?}"
        );
        assert!(names.iter().any(|n| n == "seed.txt"), "{names:?}");

        let (got, _) = nfs
            .read_sync(id, 0, 64)
            .expect("NFS read after live commit");
        assert_eq!(
            got, payload,
            "NFS cat after live commit must match overlay file bytes"
        );
    }

    /// Regression: NFS READ after live tar.zst commit must re-lookup the new zstd TAR base.
    /// Catalog: `cargo test -p ratarmount-nfs --lib overlay_commit_live_tar_zst`
    #[test]
    fn overlay_commit_live_tar_zst_then_nfs_read_readdir() {
        use std::fs;
        use std::sync::Arc;

        use ratarmount_formats_tar::{
            write_tar_eof, write_ustar_members, UstarMember, UstarPayload,
        };

        let dir = tempfile::tempdir().unwrap();
        let payload = format!("nfs-live-tarzst-{}\n", std::process::id()).into_bytes();
        let seed = b"seed\n";
        let more = b"more\n";

        let mut frame0 = Vec::new();
        write_ustar_members(
            &mut frame0,
            &[UstarMember {
                path: "seed.txt",
                payload: UstarPayload::File { bytes: seed },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            }],
        )
        .unwrap();
        write_tar_eof(&mut frame0).unwrap();

        let mut frame1 = Vec::new();
        write_ustar_members(
            &mut frame1,
            &[UstarMember {
                path: "more.txt",
                payload: UstarPayload::File { bytes: more },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            }],
        )
        .unwrap();
        write_tar_eof(&mut frame1).unwrap();

        let mut packed = ratarmount_compress::encode_zstd_frame(&frame0, 3).unwrap();
        packed.extend_from_slice(&ratarmount_compress::encode_zstd_frame(&frame1, 3).unwrap());
        let archive = dir.path().join("a.tar.zst");
        fs::write(&archive, packed).unwrap();
        let map = ratarmount_compress::scan_zstd_frames_path(&archive).unwrap();
        assert!(
            map.frames.len() >= 2,
            "fixture must be multi-frame (not single-frame fallback), got {}",
            map.frames.len()
        );

        // Two complete-TAR frames: ignore_zeros so last-frame + committed names are visible.
        let opts = ratarmount_core::OpenOptions {
            index_in_memory: true,
            ignore_zeros: true,
            ..ratarmount_core::OpenOptions::default()
        };
        let body = ratarmount_compress::open_seekable_zstd(&archive).expect("open zstd");
        let base = ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
            &archive, body, None, &opts, "test",
        )
        .expect("index tar.zst");
        let ov_dir = dir.path().join("ov");
        fs::create_dir_all(&ov_dir).unwrap();
        let ov = Arc::new(
            WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, &ov_dir).expect("overlay"),
        );
        let nfs = RatarmountNfs::with_overlay(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            0,
            Some(Arc::clone(&ov)),
        );

        let (id, _) = nfs
            .create_sync(1, &name("tick.bin"), sattr3::default())
            .expect("create");
        nfs.write_sync(id, 0, &payload).expect("write");
        let (before, _) = nfs.read_sync(id, 0, 64).expect("read overlay");
        assert_eq!(before, payload);

        ov.commit_live(&archive, |p| {
            let body = ratarmount_compress::open_seekable_zstd(p)
                .map_err(|e| ratarmount_compositing::OverlayError::Msg(e.to_string()))?;
            ratarmount_formats_tar::SqliteIndexedTar::create_index_body(
                p, body, None, &opts, "test",
            )
            .map(|t| Arc::new(t) as Arc<dyn MountSource>)
            .map_err(|e| ratarmount_compositing::OverlayError::Msg(e.to_string()))
        })
        .expect("commit_live");

        let listing = nfs.readdir_sync(1, 0, 32).expect("readdir after commit");
        let names: Vec<String> = listing
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(e.name.as_ref()).into_owned())
            .collect();
        assert!(
            names.iter().any(|n| n == "tick.bin"),
            "NFS readdir missing committed name: {names:?}"
        );
        assert!(names.iter().any(|n| n == "seed.txt"), "{names:?}");

        let (got, _) = nfs
            .read_sync(id, 0, 64)
            .expect("NFS read after live tar.zst commit");
        assert_eq!(
            got, payload,
            "NFS cat after live tar.zst commit must match overlay file bytes"
        );
    }

    #[test]
    fn overlay_truncate_and_unlink_invalidate_reader() {
        let mut base = Synth::new();
        base.add_file(
            "/member",
            b"0123456789ABCDEF",
            vec![UserData::Other("t".into())],
        );
        let (_td, nfs) = overlay_export(base);
        let id = nfs.lookup_sync(1, &name("member")).expect("lookup");
        let (before, _) = nfs.read_sync(id, 0, 32).expect("read archive");
        assert_eq!(before, b"0123456789ABCDEF");

        let sat = sattr3 {
            size: set_size3::size(4),
            ..sattr3::default()
        };
        let after_tr = nfs.setattr_sync(id, sat).expect("truncate");
        assert_eq!(after_tr.size, 4);
        let (trunc, eof) = nfs.read_sync(id, 0, 32).expect("read truncated");
        assert_eq!(trunc, b"0123");
        assert!(eof);

        nfs.write_sync(id, 0, b"ZZ").expect("replace prefix");
        let (replaced, _) = nfs.read_sync(id, 0, 32).expect("read replaced");
        assert_eq!(replaced, b"ZZ23");

        nfs.remove_sync(1, &name("member")).expect("unlink");
        assert_eq!(
            stat_u32(nfs.lookup_sync(1, &name("member")).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_NOENT)
        );
    }

    #[test]
    fn readlink_and_nametoolong() {
        let mut s = Synth::new();
        s.add_link("/l", "target");
        let nfs = nfs_of(s);
        let id = nfs.lookup_sync(1, &name("l")).unwrap();
        let t = nfs.readlink_sync(id).unwrap();
        assert_eq!(t.as_ref(), b"target");
        let long = filename3::from(vec![b'x'; 256].as_slice());
        assert_eq!(
            stat_u32(nfs.lookup_sync(1, &long).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_NAMETOOLONG)
        );
    }

    #[test]
    fn readdir_size_zero_then_read_uses_lookup_userdata() {
        let mut s = Synth::new();
        s.cheap_size_zero = true;
        s.add_file(
            "/payload",
            b"0123456789",
            vec![UserData::Other("tar-off".into())],
        );
        let nfs = nfs_of(s);
        let listing = nfs.readdir_sync(1, 0, 10).unwrap();
        assert_eq!(listing.entries.len(), 1);
        let id = listing.entries[0].fileid;
        // Inode must not have stored the cheap stub in a way that skips userdata.
        let (buf, eof) = nfs.read_sync(id, 0, 100).unwrap();
        assert_eq!(buf, b"0123456789");
        assert!(eof);
    }

    #[test]
    fn read_dir_isdir() {
        let nfs = nfs_of(Synth::new());
        assert_eq!(
            stat_u32(nfs.read_sync(1, 0, 10).unwrap_err()),
            stat_u32(nfsstat3::NFS3ERR_ISDIR)
        );
    }

    #[test]
    fn concurrent_readers_isolated() {
        let mut s = Synth::new();
        let body: Vec<u8> = (0..200).collect();
        s.add_file("/big", &body, vec![UserData::Other("t".into())]);
        let nfs = Arc::new(nfs_of(s));
        let id = nfs.lookup_sync(1, &name("big")).unwrap();
        std::thread::scope(|scope| {
            let n1 = Arc::clone(&nfs);
            let n2 = Arc::clone(&nfs);
            let h1 = scope.spawn(move || n1.read_sync(id, 0, 100).unwrap());
            let h2 = scope.spawn(move || n2.read_sync(id, 50, 100).unwrap());
            let (a, _) = h1.join().unwrap();
            let (b, _) = h2.join().unwrap();
            assert_eq!(a, body[..100]);
            assert_eq!(b, body[50..150]);
        });
    }
}
