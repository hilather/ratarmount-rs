//! `embednfs::FileSystem` on `MountSource`, with optional write overlay.

use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use embednfs::{
    AccessMask, Attrs, CommitSupport, CreateKind, CreateRequest, CreateResult, DirEntry, DirPage,
    FileSystem, FsCapabilities, FsError, FsLimits, FsResult, FsStats, ObjectType, ReadResult,
    RequestContext, SetAttrs, Symlinks, Timestamp, WriteResult, WriteStability,
};
use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{is_dir_mode, is_lnk_mode, FileInfo, MountSource};

use crate::inode::{InodeTable, ROOT_FILEID};
use crate::names::{join_path, parent_path, MAX_NAME_LEN};
use crate::reader::{fill_from_state, ReaderLru, DEFAULT_READER_SLOTS};

use super::error::io_to_fserror;

/// Approximate NFSv4.1 lease expiry for live `ArchiveRead` slots.
///
/// embednfs 0.4.1 `FileSystem` has no OPEN/CLOSE/`lease_expired` hook.
/// Matches embednfs `DEFAULT_LEASE_TIME_SECS` (90). Not a CLI flag.
pub const READER_IDLE_TTL: Duration = Duration::from_secs(90);

/// Userspace NFSv4.1 view of a factory-built [`MountSource`].
pub struct RatarmountNfs4 {
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    inodes: Arc<InodeTable>,
    readers: Arc<ReaderLru>,
    readahead_bytes: usize,
    change: AtomicU64,
}

impl RatarmountNfs4 {
    pub fn new(source: Arc<dyn MountSource>, readahead_bytes: usize) -> Self {
        Self::with_overlay(source, readahead_bytes, None)
    }

    pub fn with_overlay(
        source: Arc<dyn MountSource>,
        readahead_bytes: usize,
        overlay: Option<Arc<WriteOverlay>>,
    ) -> Self {
        let overlay_set = overlay.is_some();
        Self {
            source,
            overlay,
            inodes: Arc::new(InodeTable::with_overlay(overlay_set)),
            readers: Arc::new(ReaderLru::with_idle_ttl(
                DEFAULT_READER_SLOTS,
                READER_IDLE_TTL,
            )),
            readahead_bytes,
            change: AtomicU64::new(1),
        }
    }

    pub(crate) fn readers(&self) -> Arc<ReaderLru> {
        Arc::clone(&self.readers)
    }

    fn change_id(&self) -> u64 {
        self.change.load(Ordering::Relaxed)
    }

    fn overlay(&self) -> FsResult<&WriteOverlay> {
        self.overlay.as_deref().ok_or(FsError::ReadOnly)
    }

    fn bump_after_mutate(&self, id: u64) {
        self.readers.invalidate(id);
        self.inodes.clear_lookup_fi(id);
        self.change.fetch_add(1, Ordering::Relaxed);
    }

    fn file_info_for_id(&self, id: u64) -> FsResult<FileInfo> {
        let path = self.inodes.path_for_id(id).ok_or(FsError::Stale)?;
        if path == "/" {
            let fi = ratarmount_core::create_root_file_info();
            self.inodes.store_lookup_fi(id, fi.clone());
            return Ok(fi);
        }
        if self.overlay.is_none() {
            if let Some(fi) = self.inodes.cached_lookup_fi(id) {
                return Ok(fi);
            }
        }
        let fi = self.source.lookup(&path, 0).ok_or(FsError::Stale)?;
        self.inodes.store_lookup_fi(id, fi.clone());
        Ok(fi)
    }

    fn attrs(&self, id: u64, fi: &FileInfo) -> Attrs {
        let t = unix_float_to_timestamp(fi.mtime);
        Attrs {
            object_type: mode_to_object_type(fi.mode),
            fileid: id,
            change: self.change_id(),
            size: fi.size,
            space_used: fi.size,
            link_count: if is_dir_mode(fi.mode) { 2 } else { 1 },
            mode: fi.mode & 0o7777,
            uid: fi.uid,
            gid: fi.gid,
            atime: t,
            mtime: t,
            ctime: t,
            birthtime: t,
            archive: false,
            hidden: false,
            system: false,
            has_named_attrs: false,
        }
    }

    fn check_name(name: &str) -> FsResult<()> {
        if name.is_empty() {
            return Err(FsError::InvalidInput);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(FsError::NameTooLong);
        }
        Ok(())
    }

    pub fn lookup_sync(&self, parent: u64, name: &str) -> FsResult<u64> {
        Self::check_name(name)?;
        let parent_path_str = self.inodes.path_for_id(parent).ok_or(FsError::Stale)?;
        if name == "." {
            return Ok(parent);
        }
        if name == ".." {
            return Ok(self.inodes.id_for_path(&parent_path(&parent_path_str)));
        }
        let path = join_path(&parent_path_str, name);
        let fi = self.source.lookup(&path, 0).ok_or(FsError::NotFound)?;
        let id = self.inodes.id_for_path(&path);
        self.inodes.store_lookup_fi(id, fi);
        Ok(id)
    }

    pub fn getattr_sync(&self, id: u64) -> FsResult<Attrs> {
        let fi = self.file_info_for_id(id)?;
        Ok(self.attrs(id, &fi))
    }

    pub fn parent_sync(&self, dir: u64) -> FsResult<Option<u64>> {
        let path = self.inodes.path_for_id(dir).ok_or(FsError::Stale)?;
        if path == "/" {
            return Ok(None);
        }
        Ok(Some(self.inodes.id_for_path(&parent_path(&path))))
    }

    pub fn readdir_sync(
        &self,
        dir: u64,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<u64>> {
        let path = self.inodes.path_for_id(dir).ok_or(FsError::Stale)?;
        let Some(dents) = self.source.list_dirents(&path) else {
            if let Ok(fi) = self.file_info_for_id(dir) {
                if !is_dir_mode(fi.mode) {
                    return Err(FsError::NotDirectory);
                }
            }
            return Err(FsError::NotFound);
        };
        let mut kids: Vec<(u64, String, u32, u64)> = dents
            .into_iter()
            .filter(|d| d.name != "." && d.name != "..")
            .map(|d| {
                let child = join_path(&path, &d.name);
                let id = self.inodes.id_for_path(&child);
                (id, d.name, d.mode, d.size)
            })
            .collect();
        kids.sort_by_key(|(id, _, _, _)| *id);

        // Do not emit `.` / `..`. Linux nfs4_setup_readdir injects them at
        // cookie 0 (reserved cookies 1/2); returning them duplicates `ls -lah`.
        // lookup still handles "." / "..". Child cookies are fileids (> 2).
        let start_idx = if cookie == 0 {
            0
        } else {
            match kids.iter().position(|(id, _, _, _)| *id == cookie) {
                Some(i) => i + 1,
                // Cookie entry vanished (overlay delete between pages): resume
                // at the next surviving id. embednfs maps our error to
                // NFS4ERR_INVAL (no BadCookie variant), which aborts `ls`.
                None => kids
                    .iter()
                    .position(|(id, _, _, _)| *id > cookie)
                    .unwrap_or(kids.len()),
            }
        };
        let max = max_entries as usize;
        let slice = &kids[start_idx..];
        let take = slice.len().min(max);
        let eof = start_idx + take >= kids.len();
        let mut entries = Vec::with_capacity(take);
        for (id, name, mode, cheap_size) in &slice[..take] {
            let child = join_path(&path, name);
            let attrs = if with_attrs {
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
                Some(self.attrs(*id, &fi))
            } else {
                None
            };
            entries.push(DirEntry {
                name: name.clone(),
                handle: *id,
                cookie: *id,
                attrs,
            });
        }
        Ok(DirPage { entries, eof })
    }

    pub fn readlink_sync(&self, id: u64) -> FsResult<String> {
        let fi = self.file_info_for_id(id)?;
        if !is_lnk_mode(fi.mode) {
            return Err(FsError::InvalidInput);
        }
        Ok(fi.linkname)
    }

    pub fn read_sync(&self, id: u64, offset: u64, count: u32) -> FsResult<ReadResult> {
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

    pub fn access_sync(&self, id: u64, requested: AccessMask) -> FsResult<AccessMask> {
        let _ = self.file_info_for_id(id)?;
        let mut granted = AccessMask::READ | AccessMask::LOOKUP | AccessMask::EXECUTE;
        if self.overlay.is_some() {
            granted |= AccessMask::MODIFY | AccessMask::EXTEND | AccessMask::DELETE;
        }
        Ok(requested & granted)
    }

    pub fn create_sync(
        &self,
        parent: u64,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<u64>> {
        let ov = self.overlay()?;
        Self::check_name(name)?;
        let parent_path_str = self.inodes.path_for_id(parent).ok_or(FsError::Stale)?;
        let path = join_path(&parent_path_str, name);
        match req.kind {
            CreateKind::File => {
                let mode = req.attrs.mode.unwrap_or(0o644);
                let fd = ov.create_file(&path, mode).map_err(overlay_to_fs)?;
                // NFS create is stateless — close the overlay fd (FUSE would keep it).
                ov.close_overlay_fd(fd);
            }
            CreateKind::Directory => {
                let mode = req.attrs.mode.unwrap_or(0o755);
                ov.mkdir(&path, mode).map_err(overlay_to_fs)?;
            }
        }
        let id = self.inodes.id_for_path(&path);
        self.bump_after_mutate(id);
        if let Some(fi) = self.source.lookup(&path, 0) {
            self.inodes.store_lookup_fi(id, fi);
        }
        Ok(CreateResult {
            handle: id,
            attrs: self.getattr_sync(id)?,
        })
    }

    pub fn write_sync(&self, id: u64, offset: u64, data: &[u8]) -> FsResult<WriteResult> {
        let ov = self.overlay()?;
        let path = self.inodes.path_for_id(id).ok_or(FsError::Stale)?;
        let flags = libc::O_RDWR | libc::O_CREAT;
        let fd = ov.open_overlay_fd(&path, flags).map_err(overlay_to_fs)?;
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let wrote = file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(data));
        drop(file);
        ov.release_write_fd(fd);
        wrote.map_err(|e| io_to_fserror(&e))?;
        self.bump_after_mutate(id);
        Ok(WriteResult {
            written: u32::try_from(data.len()).unwrap_or(u32::MAX),
            stability: WriteStability::DataSync,
        })
    }

    pub fn remove_sync(&self, parent: u64, name: &str) -> FsResult<()> {
        let ov = self.overlay()?;
        Self::check_name(name)?;
        let parent_path_str = self.inodes.path_for_id(parent).ok_or(FsError::Stale)?;
        let path = join_path(&parent_path_str, name);
        let id = self.inodes.id_for_path(&path);
        let is_dir = self
            .source
            .lookup(&path, 0)
            .map(|fi| is_dir_mode(fi.mode))
            .unwrap_or(false);
        if is_dir {
            ov.rmdir(&path).map_err(overlay_to_fs)?;
        } else {
            ov.unlink(&path).map_err(overlay_to_fs)?;
        }
        self.bump_after_mutate(id);
        Ok(())
    }

    pub fn setattr_sync(&self, id: u64, attrs: &SetAttrs) -> FsResult<Attrs> {
        let ov = self.overlay()?;
        let path = self.inodes.path_for_id(id).ok_or(FsError::Stale)?;
        if let Some(sz) = attrs.size {
            ov.truncate(&path, sz).map_err(overlay_to_fs)?;
            self.bump_after_mutate(id);
        }
        self.getattr_sync(id)
    }

    pub fn rename_sync(
        &self,
        from_dir: u64,
        from_name: &str,
        to_dir: u64,
        to_name: &str,
    ) -> FsResult<()> {
        let ov = self.overlay()?;
        Self::check_name(from_name)?;
        Self::check_name(to_name)?;
        let from_parent = self.inodes.path_for_id(from_dir).ok_or(FsError::Stale)?;
        let to_parent = self.inodes.path_for_id(to_dir).ok_or(FsError::Stale)?;
        let from = join_path(&from_parent, from_name);
        let to = join_path(&to_parent, to_name);
        let from_id = self.inodes.id_for_path(&from);
        if let Some(dest_id) = self.inodes.id_if_present(&to) {
            self.bump_after_mutate(dest_id);
        }
        ov.rename(&from, &to).map_err(overlay_to_fs)?;
        self.inodes.rebind_path(from_id, &to);
        self.bump_after_mutate(from_id);
        Ok(())
    }

    pub fn symlink_sync(
        &self,
        parent: u64,
        name: &str,
        target: &str,
    ) -> FsResult<CreateResult<u64>> {
        let ov = self.overlay()?;
        Self::check_name(name)?;
        let parent_path_str = self.inodes.path_for_id(parent).ok_or(FsError::Stale)?;
        let path = join_path(&parent_path_str, name);
        ov.create_symlink(&path, target).map_err(overlay_to_fs)?;
        let id = self.inodes.id_for_path(&path);
        self.bump_after_mutate(id);
        if let Some(fi) = self.source.lookup(&path, 0) {
            self.inodes.store_lookup_fi(id, fi);
        }
        Ok(CreateResult {
            handle: id,
            attrs: self.getattr_sync(id)?,
        })
    }

    pub fn statfs_sync(&self) -> FsStats {
        FsStats {
            total_bytes: 0,
            free_bytes: 0,
            avail_bytes: 0,
            total_files: 0,
            free_files: 0,
            avail_files: 0,
        }
    }
}

fn read_member(
    source: &dyn MountSource,
    inodes: &InodeTable,
    readers: &ReaderLru,
    readahead_bytes: usize,
    id: u64,
    offset: u64,
    count: u32,
) -> FsResult<ReadResult> {
    let path = inodes.path_for_id(id).ok_or(FsError::Stale)?;
    // A live overlay commit invalidates every cached FileInfo at once (base
    // member offsets shift) — sweep before trusting the cache for the check.
    readers.sweep_if_generation_advanced(source, inodes);
    // Overlay cookies are not FileInfo. Do not reconstruct; re-lookup so a
    // stale size-0 cookie cannot make this READ return EOF.
    let fi_check = if path == "/" {
        ratarmount_core::create_root_file_info()
    } else if inodes.stores_overlay_cookies() {
        source.lookup(&path, 0).ok_or(FsError::Stale)?
    } else if let Some(c) = inodes.cached_lookup_fi(id) {
        c
    } else {
        source.lookup(&path, 0).ok_or(FsError::Stale)?
    };
    if is_dir_mode(fi_check.mode) {
        return Err(FsError::IsDirectory);
    }
    let (fi, state) = readers.get_or_open(source, inodes, id).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            FsError::Stale
        } else {
            io_to_fserror(&e)
        }
    })?;
    if fi.size == 0 || offset >= fi.size {
        return Ok(ReadResult {
            data: Bytes::new(),
            eof: true,
        });
    }
    let buf = fill_from_state(&state, readahead_bytes, offset, count as usize)
        .map_err(|e| io_to_fserror(&e))?;
    let n = buf.len();
    let eof = offset.saturating_add(n as u64) >= fi.size || n < count as usize;
    Ok(ReadResult {
        data: Bytes::from(buf),
        eof,
    })
}

fn overlay_to_fs(err: ratarmount_compositing::OverlayError) -> FsError {
    match err {
        ratarmount_compositing::OverlayError::Io(e) => io_to_fserror(&e),
        other => io_to_fserror(&io::Error::other(other.to_string())),
    }
}

fn mode_to_object_type(mode: u32) -> ObjectType {
    if is_dir_mode(mode) {
        ObjectType::Directory
    } else if is_lnk_mode(mode) {
        ObjectType::Symlink
    } else {
        ObjectType::File
    }
}

fn unix_float_to_timestamp(t: f64) -> Timestamp {
    if t <= 0.0 {
        return Timestamp {
            seconds: 0,
            nanos: 0,
        };
    }
    Timestamp {
        seconds: t.trunc() as i64,
        nanos: (t.fract() * 1e9) as u32,
    }
}

#[async_trait]
impl FileSystem for RatarmountNfs4 {
    type Handle = u64;

    fn root(&self) -> Self::Handle {
        ROOT_FILEID
    }

    fn capabilities(&self) -> FsCapabilities {
        FsCapabilities {
            symlinks: true,
            hard_links: false,
            xattrs: false,
            // Linux kernel CLOSE often sends COMMIT; advertise + implement a no-op
            // (writes already reported DataSync into the overlay file).
            explicit_sync: true,
            case_sensitive: true,
            case_preserving: true,
        }
    }

    fn limits(&self) -> FsLimits {
        let namemax = self.source.statfs().namemax.min(u64::from(u32::MAX)) as u32;
        FsLimits {
            max_name_bytes: namemax.max(1),
            max_read: 1_048_576,
            max_write: if self.overlay.is_some() { 1_048_576 } else { 0 },
            max_file_size: u64::MAX,
        }
    }

    async fn statfs(&self, _ctx: &RequestContext) -> FsResult<FsStats> {
        Ok(self.statfs_sync())
    }

    async fn getattr(&self, _ctx: &RequestContext, handle: &Self::Handle) -> FsResult<Attrs> {
        self.getattr_sync(*handle)
    }

    async fn access(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        requested: AccessMask,
    ) -> FsResult<AccessMask> {
        self.access_sync(*handle, requested)
    }

    async fn lookup(
        &self,
        _ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<Self::Handle> {
        self.lookup_sync(*parent, name)
    }

    async fn parent(
        &self,
        _ctx: &RequestContext,
        dir: &Self::Handle,
    ) -> FsResult<Option<Self::Handle>> {
        self.parent_sync(*dir)
    }

    async fn readdir(
        &self,
        _ctx: &RequestContext,
        dir: &Self::Handle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<Self::Handle>> {
        self.readdir_sync(*dir, cookie, max_entries, with_attrs)
    }

    async fn read(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult> {
        let source = Arc::clone(&self.source);
        let inodes = Arc::clone(&self.inodes);
        let readers = Arc::clone(&self.readers);
        let readahead = self.readahead_bytes;
        let id = *handle;
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
        .unwrap_or(Err(FsError::Io))
    }

    async fn write(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        data: Bytes,
        _requested: WriteStability,
    ) -> FsResult<WriteResult> {
        self.write_sync(*handle, offset, data.as_ref())
    }

    async fn create(
        &self,
        _ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>> {
        self.create_sync(*parent, name, req)
    }

    async fn remove(
        &self,
        _ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<()> {
        self.remove_sync(*parent, name)
    }

    async fn rename(
        &self,
        _ctx: &RequestContext,
        from_dir: &Self::Handle,
        from_name: &str,
        to_dir: &Self::Handle,
        to_name: &str,
    ) -> FsResult<()> {
        self.rename_sync(*from_dir, from_name, *to_dir, to_name)
    }

    async fn setattr(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        self.setattr_sync(*handle, attrs)
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> {
        Some(self)
    }

    fn commit_support(&self) -> Option<&dyn CommitSupport<Self::Handle>> {
        Some(self)
    }
}

#[async_trait]
impl Symlinks<u64> for RatarmountNfs4 {
    async fn create_symlink(
        &self,
        _ctx: &RequestContext,
        parent: &u64,
        name: &str,
        target: &str,
        _attrs: &SetAttrs,
    ) -> FsResult<CreateResult<u64>> {
        self.symlink_sync(*parent, name, target)
    }

    async fn readlink(&self, _ctx: &RequestContext, handle: &u64) -> FsResult<String> {
        self.readlink_sync(*handle)
    }
}

#[async_trait]
impl CommitSupport<u64> for RatarmountNfs4 {
    async fn commit(
        &self,
        _ctx: &RequestContext,
        handle: &u64,
        _offset: u64,
        _count: u32,
    ) -> FsResult<()> {
        // Overlay writes already reached the host file; COMMIT is a verifier bump.
        let _ = self.file_info_for_id(*handle)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{self, Cursor, Read, Seek};

    use ratarmount_core::{CheapDirent, FileInfo, ListResult, UserData, S_IFDIR, S_IFLNK, S_IFREG};

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
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }

    struct Synth {
        files: BTreeMap<String, (FileInfo, Vec<u8>)>,
        dirs: BTreeMap<String, Vec<CheapDirent>>,
        cheap_size_zero: bool,
        short_read: bool,
    }

    impl Synth {
        fn new() -> Self {
            let mut dirs = BTreeMap::new();
            dirs.insert("/".into(), vec![]);
            Self {
                files: BTreeMap::new(),
                dirs,
                cheap_size_zero: false,
                short_read: false,
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

        fn add_dir(&mut self, path: &str) {
            let name = path.rsplit('/').next().unwrap().to_string();
            let parent = if path.matches('/').count() == 1 {
                "/".to_string()
            } else {
                path.rsplit_once('/').unwrap().0.to_string()
            };
            let fi = FileInfo {
                size: 0,
                mtime: 1.0,
                mode: S_IFDIR | 0o755,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            };
            self.files.insert(path.into(), (fi.clone(), Vec::new()));
            self.dirs.entry(parent).or_default().push(CheapDirent {
                name,
                mode: fi.mode,
                size: 0,
            });
            self.dirs.entry(path.into()).or_default();
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
                    if self.short_read {
                        return Ok(Box::new(ShortRead(Cursor::new(body.clone()))));
                    }
                    return Ok(Box::new(Cursor::new(body.clone())));
                }
            }
            Ok(Box::new(Cursor::new(Vec::new())))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    fn nfs_of(s: Synth) -> RatarmountNfs4 {
        RatarmountNfs4::new(Arc::new(s), 0)
    }

    fn ctx() -> RequestContext {
        RequestContext::anonymous()
    }

    #[test]
    fn v4_root_and_lookup_stable() {
        let mut s = Synth::new();
        s.add_file("/a.txt", b"hi", vec![UserData::Other("tar".into())]);
        let nfs = nfs_of(s);
        assert_eq!(nfs.root(), 1);
        let id = nfs.lookup_sync(1, "a.txt").unwrap();
        assert!(id >= 2);
        assert_eq!(nfs.lookup_sync(1, "a.txt").unwrap(), id);
        let attr = nfs.getattr_sync(id).unwrap();
        assert_eq!(attr.size, 2);
        assert_eq!(attr.fileid, id);
        assert_eq!(attr.object_type, ObjectType::File);
        assert_eq!(attr.mode, 0o644);
    }

    #[test]
    fn v4_missing_is_notfound_unknown_handle_stale() {
        let nfs = nfs_of(Synth::new());
        assert_eq!(nfs.lookup_sync(1, "nope").unwrap_err(), FsError::NotFound);
        assert_eq!(nfs.getattr_sync(99).unwrap_err(), FsError::Stale);
    }

    /// Regression: an unknown/vanished readdir cookie resumes at the next
    /// surviving id (empty page at end) instead of an error that embednfs can
    /// only surface as NFS4ERR_INVAL, aborting client listings mid-enumeration.
    #[test]
    fn v4_readdir_cookie_and_unknown() {
        let mut s = Synth::new();
        s.add_file("/a", b"1", vec![UserData::Other("t".into())]);
        s.add_file("/b", b"2", vec![UserData::Other("t".into())]);
        let nfs = nfs_of(s);
        let all = nfs.readdir_sync(1, 0, 10, true).unwrap();
        let kids: Vec<&DirEntry<u64>> = all
            .entries
            .iter()
            .filter(|e| e.name != "." && e.name != "..")
            .collect();
        assert_eq!(kids.len(), 2);
        assert!(all.eof);
        assert_eq!(kids[0].cookie, kids[0].handle);
        // Cookies must not collide with embednfs's reserved values 1 and 2.
        assert!(all.entries.iter().all(|e| e.cookie > 2));
        // Linux nfs4_setup_readdir injects `.` / `..`; we must not also emit them.
        assert!(all.entries.iter().all(|e| e.name != "." && e.name != ".."));
        let first = kids[0].cookie;
        let rest = nfs.readdir_sync(1, first, 10, false).unwrap();
        assert_eq!(rest.entries.len(), 1);
        assert!(rest.entries.iter().all(|e| e.name != "." && e.name != ".."));
        assert!(rest.eof);
        assert!(rest.entries[0].attrs.is_none());
        // Cookie past the last id: empty page, eof — no error.
        let tail = nfs.readdir_sync(1, 9999, 10, false).unwrap();
        assert!(tail.entries.is_empty());
        assert!(tail.eof);
    }

    /// Regression: emitting `.` / `..` from NFSv4 READDIR duplicates them on
    /// Linux (`nfs4_setup_readdir` already injects cookies 1/2).
    #[test]
    fn v4_readdir_does_not_emit_dot_dotdot() {
        let mut s = Synth::new();
        s.add_file("/root.txt", b"r", vec![UserData::Other("t".into())]);
        s.add_dir("/sub");
        s.add_file("/sub/inner.txt", b"i", vec![UserData::Other("t".into())]);
        let nfs = nfs_of(s);

        let root = nfs.readdir_sync(1, 0, 32, true).unwrap();
        assert!(root.entries.iter().all(|e| e.name != "." && e.name != ".."));
        assert!(root.entries.iter().any(|e| e.name == "root.txt"));
        assert!(root.entries.iter().any(|e| e.name == "sub"));
        assert!(root.entries.iter().all(|e| e.cookie > 2));

        let sub_id = nfs.lookup_sync(1, "sub").unwrap();
        let sub = nfs.readdir_sync(sub_id, 0, 32, true).unwrap();
        assert!(sub.entries.iter().all(|e| e.name != "." && e.name != ".."));
        assert!(sub.entries.iter().any(|e| e.name == "inner.txt"));
        assert!(sub.entries.iter().all(|e| e.cookie > 2));
    }

    #[tokio::test]
    async fn v4_writers_readonly() {
        let nfs = nfs_of(Synth::new());
        let c = ctx();
        assert_eq!(
            nfs.write(
                &c,
                &1,
                0,
                Bytes::from_static(b"x"),
                WriteStability::DataSync
            )
            .await
            .unwrap_err(),
            FsError::ReadOnly
        );
        assert_eq!(
            nfs.create(
                &c,
                &1,
                "x",
                CreateRequest {
                    kind: embednfs::CreateKind::File,
                    attrs: SetAttrs::default(),
                },
            )
            .await
            .unwrap_err(),
            FsError::ReadOnly
        );
        assert_eq!(
            nfs.remove(&c, &1, "x").await.unwrap_err(),
            FsError::ReadOnly
        );
        assert_eq!(
            nfs.rename(&c, &1, "a", &1, "b").await.unwrap_err(),
            FsError::ReadOnly
        );
        let sat = SetAttrs {
            size: Some(0),
            ..SetAttrs::default()
        };
        assert_eq!(
            nfs.setattr(&c, &1, &sat).await.unwrap_err(),
            FsError::ReadOnly
        );
        assert_eq!(
            nfs.create_symlink(&c, &1, "l", "t", &SetAttrs::default())
                .await
                .unwrap_err(),
            FsError::ReadOnly
        );
    }

    #[test]
    fn v4_readlink() {
        let mut s = Synth::new();
        s.add_link("/l", "target");
        let nfs = nfs_of(s);
        let id = nfs.lookup_sync(1, "l").unwrap();
        assert_eq!(nfs.readlink_sync(id).unwrap(), "target");
        let attr = nfs.getattr_sync(id).unwrap();
        assert_eq!(attr.object_type, ObjectType::Symlink);
        assert_eq!(attr.fileid, id);
    }

    /// Regression: v4 readdir cheap size 0 then cat must use lookup userdata.
    #[test]
    fn v4_readdir_size_zero_then_read_uses_lookup_userdata() {
        let mut s = Synth::new();
        s.cheap_size_zero = true;
        s.add_file(
            "/payload",
            b"0123456789",
            vec![UserData::Other("tar-off".into())],
        );
        let nfs = nfs_of(s);
        let listing = nfs.readdir_sync(1, 0, 10, true).unwrap();
        let payload = listing
            .entries
            .iter()
            .find(|e| e.name == "payload")
            .expect("size-0 listing must include the real child name");
        let id = payload.handle;
        let got = nfs.read_sync(id, 0, 100).unwrap();
        assert_eq!(&got.data[..], b"0123456789");
        assert!(got.eof);
    }

    /// Regression: v4 short `Read::read` is not EOF (fill-loop).
    #[test]
    fn v4_short_read_is_not_eof() {
        let mut s = Synth::new();
        s.short_read = true;
        s.add_file("/payload", b"abcdef", vec![UserData::Other("t".into())]);
        let nfs = nfs_of(s);
        let id = nfs.lookup_sync(1, "payload").unwrap();
        let got = nfs.read_sync(id, 0, 6).unwrap();
        assert_eq!(&got.data[..], b"abcdef");
        assert!(got.eof);
    }

    #[test]
    fn v4_concurrent_readers_isolated() {
        let mut s = Synth::new();
        let body: Vec<u8> = (0..200).collect();
        s.add_file("/big", &body, vec![UserData::Other("t".into())]);
        let nfs = Arc::new(nfs_of(s));
        let id = nfs.lookup_sync(1, "big").unwrap();
        std::thread::scope(|scope| {
            let n1 = Arc::clone(&nfs);
            let n2 = Arc::clone(&nfs);
            let h1 = scope.spawn(move || n1.read_sync(id, 0, 100).unwrap());
            let h2 = scope.spawn(move || n2.read_sync(id, 50, 100).unwrap());
            let a = h1.join().unwrap();
            let b = h2.join().unwrap();
            assert_eq!(&a.data[..], &body[..100]);
            assert_eq!(&b.data[..], &body[50..150]);
        });
    }

    #[test]
    fn v4_read_dir_isdir() {
        let nfs = nfs_of(Synth::new());
        assert_eq!(nfs.read_sync(1, 0, 10).unwrap_err(), FsError::IsDirectory);
    }

    #[test]
    fn v4_nametoolong() {
        let nfs = nfs_of(Synth::new());
        let long = "x".repeat(256);
        assert_eq!(nfs.lookup_sync(1, &long).unwrap_err(), FsError::NameTooLong);
        assert_eq!(nfs.lookup_sync(1, "").unwrap_err(), FsError::InvalidInput);
    }

    #[test]
    fn v4_parent_of_root_is_none() {
        let mut s = Synth::new();
        s.add_file("/a.txt", b"hi", vec![UserData::Other("t".into())]);
        let nfs = nfs_of(s);
        assert_eq!(nfs.parent_sync(ROOT_FILEID).unwrap(), None);
        let id = nfs.lookup_sync(1, "a.txt").unwrap();
        assert_eq!(nfs.parent_sync(id).unwrap(), Some(ROOT_FILEID));
        assert_eq!(nfs.parent_sync(99).unwrap_err(), FsError::Stale);
    }

    #[test]
    fn v4_access_ro_masks_requested() {
        let nfs = nfs_of(Synth::new());
        let all = AccessMask::READ
            | AccessMask::LOOKUP
            | AccessMask::MODIFY
            | AccessMask::EXTEND
            | AccessMask::DELETE
            | AccessMask::EXECUTE;
        let got = nfs.access_sync(1, all).unwrap();
        assert_eq!(
            got,
            AccessMask::READ | AccessMask::LOOKUP | AccessMask::EXECUTE
        );
        assert!(!got.contains(AccessMask::MODIFY));
        assert_eq!(nfs.access_sync(99, all).unwrap_err(), FsError::Stale);
    }

    #[test]
    fn v4_statfs_and_limits_ro() {
        let nfs = nfs_of(Synth::new());
        let st = nfs.statfs_sync();
        assert_eq!(st.total_bytes, 0);
        assert_eq!(st.free_bytes, 0);
        let lim = nfs.limits();
        assert_eq!(lim.max_write, 0);
        assert_eq!(lim.max_read, 1_048_576);
        assert_eq!(lim.max_name_bytes, 255);
        assert!(nfs.capabilities().symlinks);
        assert!(!nfs.capabilities().hard_links);
    }

    #[tokio::test]
    async fn v4_read_via_trait_spawn_blocking() {
        let mut s = Synth::new();
        s.add_file("/a.txt", b"hello", vec![UserData::Other("t".into())]);
        let nfs = nfs_of(s);
        let c = ctx();
        let id = nfs.lookup(&c, &1, "a.txt").await.unwrap();
        let got = FileSystem::read(&nfs, &c, &id, 0, 16).await.unwrap();
        assert_eq!(&got.data[..], b"hello");
        assert!(got.eof);
    }

    fn overlay_export(base: Synth) -> (tempfile::TempDir, RatarmountNfs4) {
        let td = tempfile::tempdir().unwrap();
        let ov = Arc::new(
            WriteOverlay::new(Arc::new(base) as Arc<dyn MountSource>, td.path()).expect("overlay"),
        );
        let nfs = RatarmountNfs4::with_overlay(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            0,
            Some(Arc::clone(&ov)),
        );
        (td, nfs)
    }

    fn file_create() -> CreateRequest {
        CreateRequest {
            kind: CreateKind::File,
            attrs: SetAttrs::default(),
        }
    }

    #[test]
    fn v4_overlay_create_write_read_mkdir_readdir() {
        let mut base = Synth::new();
        base.add_file("/keep", b"archive", vec![UserData::Other("t".into())]);
        let (_td, nfs) = overlay_export(base);

        let created = nfs
            .create_sync(1, "new.txt", file_create())
            .expect("create");
        assert_eq!(created.attrs.size, 0);
        let wr = nfs
            .write_sync(created.handle, 0, b"hello-overlay")
            .expect("write");
        assert_eq!(wr.written, 13);
        assert_eq!(wr.stability, WriteStability::DataSync);
        let got = nfs.getattr_sync(created.handle).expect("getattr");
        assert_eq!(got.size, 13);
        assert!(got.change > created.attrs.change);
        let data = nfs.read_sync(created.handle, 0, 32).expect("read");
        assert_eq!(&data.data[..], b"hello-overlay");
        assert!(data.eof);

        let dir = nfs
            .create_sync(
                1,
                "sub",
                CreateRequest {
                    kind: CreateKind::Directory,
                    attrs: SetAttrs::default(),
                },
            )
            .expect("mkdir");
        assert_eq!(dir.attrs.object_type, ObjectType::Directory);
        let listing = nfs.readdir_sync(1, 0, 32, false).expect("readdir");
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"new.txt"), "{names:?}");
        assert!(names.contains(&"sub"), "{names:?}");
        assert!(names.contains(&"keep"), "{names:?}");
    }

    /// Regression: write-then-cat empty when NFSv4 READ used a stale size-0
    /// inode cache instead of re-lookup.
    #[test]
    fn v4_overlay_open_after_create_write() {
        let (_td, nfs) = overlay_export(Synth::new());
        let created = nfs
            .create_sync(1, "new.txt", file_create())
            .expect("create");
        assert_eq!(created.attrs.size, 0);
        nfs.write_sync(created.handle, 0, b"hello-overlay-payload")
            .expect("write");
        assert!(
            nfs.inodes.cached_lookup_fi(created.handle).is_none(),
            "overlay child must not keep a fat FileInfo"
        );
        let data = nfs.read_sync(created.handle, 0, 64).expect("read");
        assert_eq!(
            &data.data[..],
            b"hello-overlay-payload",
            "write-then-cat must not return empty"
        );
        assert_ne!(&data.data[..], b"");
        assert!(data.eof);
        let cached = nfs
            .inodes
            .cached_cookie(created.handle)
            .expect("cookie after read");
        assert_eq!(cached.size, b"hello-overlay-payload".len() as u64);
        assert!(nfs.inodes.cached_lookup_fi(created.handle).is_none());
    }

    /// Opposite polarity of the size-0 cache bug: create with no write, then
    /// NFSv4 READ must return "".
    #[test]
    fn v4_overlay_open_after_create_reads_empty() {
        let (_td, nfs) = overlay_export(Synth::new());
        let created = nfs
            .create_sync(1, "empty.txt", file_create())
            .expect("create");
        assert_eq!(created.attrs.size, 0);
        let data = nfs.read_sync(created.handle, 0, 64).expect("read");
        assert_eq!(
            &data.data[..],
            b"",
            "never-written overlay file must read empty"
        );
        assert!(data.eof);
        assert!(
            nfs.inodes.cached_lookup_fi(created.handle).is_none(),
            "overlay child must not keep a fat FileInfo"
        );
    }

    /// After overlay lookup/store, the inode holds a cookie only — not a fat
    /// FileInfo. getattr still re-looks up.
    #[test]
    fn v4_overlay_store_cookie_without_file_info() {
        let (_td, nfs) = overlay_export(Synth::new());
        let created = nfs
            .create_sync(1, "cookie.txt", file_create())
            .expect("create");
        nfs.write_sync(created.handle, 0, b"payload")
            .expect("write");
        let got = nfs.getattr_sync(created.handle).expect("getattr");
        assert_eq!(got.size, b"payload".len() as u64);
        assert!(
            nfs.inodes.cached_cookie(created.handle).is_some(),
            "overlay store must write a cookie"
        );
        assert!(
            nfs.inodes.cached_lookup_fi(created.handle).is_none(),
            "overlay child must not keep fat FileInfo (no to_file_info)"
        );
        assert_eq!(
            nfs.inodes.cached_cookie(created.handle).unwrap().size,
            b"payload".len() as u64
        );
    }

    #[test]
    fn v4_overlay_truncate_and_unlink_invalidate_reader() {
        let mut base = Synth::new();
        base.add_file(
            "/member",
            b"0123456789ABCDEF",
            vec![UserData::Other("t".into())],
        );
        let (_td, nfs) = overlay_export(base);
        let id = nfs.lookup_sync(1, "member").expect("lookup");
        let before = nfs.read_sync(id, 0, 32).expect("read archive");
        assert_eq!(&before.data[..], b"0123456789ABCDEF");

        let sat = SetAttrs {
            size: Some(4),
            ..SetAttrs::default()
        };
        let after_tr = nfs.setattr_sync(id, &sat).expect("truncate");
        assert_eq!(after_tr.size, 4);
        let trunc = nfs.read_sync(id, 0, 32).expect("read truncated");
        assert_eq!(&trunc.data[..], b"0123");
        assert!(trunc.eof);

        nfs.write_sync(id, 0, b"ZZ").expect("replace prefix");
        let replaced = nfs.read_sync(id, 0, 32).expect("read replaced");
        assert_eq!(&replaced.data[..], b"ZZ23");

        nfs.remove_sync(1, "member").expect("unlink");
        assert_eq!(nfs.lookup_sync(1, "member").unwrap_err(), FsError::NotFound);
    }

    #[tokio::test]
    async fn v4_overlay_rename_and_symlink() {
        let mut base = Synth::new();
        base.add_file("/keep", b"archive", vec![UserData::Other("t".into())]);
        let (_td, nfs) = overlay_export(base);
        let c = ctx();
        let created = nfs
            .create(
                &c,
                &1,
                "src.txt",
                CreateRequest {
                    kind: embednfs::CreateKind::File,
                    attrs: SetAttrs::default(),
                },
            )
            .await
            .expect("create");
        nfs.write_sync(created.handle, 0, b"moved").expect("write");
        nfs.rename(&c, &1, "src.txt", &1, "dst.txt")
            .await
            .expect("rename");
        assert_eq!(
            nfs.lookup_sync(1, "src.txt").unwrap_err(),
            FsError::NotFound
        );
        let dst = nfs.lookup_sync(1, "dst.txt").expect("dst");
        let got = nfs.read_sync(dst, 0, 32).expect("read renamed");
        assert_eq!(&got.data[..], b"moved");

        let link = nfs
            .create_symlink(&c, &1, "link", "dst.txt", &SetAttrs::default())
            .await
            .expect("symlink");
        assert_eq!(link.attrs.object_type, ObjectType::Symlink);
        assert_eq!(nfs.readlink_sync(link.handle).expect("readlink"), "dst.txt");

        let page = nfs.readdir_sync(1, 0, 32, false).expect("readdir");
        let names: Vec<&str> = page.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"dst.txt"), "{names:?}");
        assert!(names.contains(&"link"), "{names:?}");
        assert!(!names.contains(&"src.txt"), "{names:?}");
    }

    #[tokio::test]
    async fn v4_overlay_commit_ok() {
        let mut base = Synth::new();
        base.add_file("/a", b"x", vec![UserData::Other("t".into())]);
        let (_td, nfs) = overlay_export(base);
        let c = ctx();
        assert!(nfs.commit_support().is_some());
        nfs.commit(&c, &1, 0, 0).await.expect("commit root");
        let id = nfs.lookup_sync(1, "a").unwrap();
        nfs.commit(&c, &id, 0, 0).await.expect("commit file");
    }

    #[test]
    fn v4_overlay_access_and_limits() {
        let (_td, nfs) = overlay_export(Synth::new());
        let all = AccessMask::READ
            | AccessMask::LOOKUP
            | AccessMask::MODIFY
            | AccessMask::EXTEND
            | AccessMask::DELETE
            | AccessMask::EXECUTE;
        let got = nfs.access_sync(1, all).unwrap();
        assert_eq!(got, all);
        let lim = nfs.limits();
        assert_eq!(lim.max_write, 1_048_576);
    }
}
