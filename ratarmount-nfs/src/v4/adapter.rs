//! `embednfs::FileSystem` on `MountSource` (read-only; overlay writes are PR 4).

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use embednfs::{
    AccessMask, Attrs, CreateRequest, CreateResult, DirEntry, DirPage, FileSystem, FsCapabilities,
    FsError, FsLimits, FsResult, FsStats, ObjectType, ReadResult, RequestContext, SetAttrs,
    Symlinks, Timestamp, WriteResult, WriteStability,
};
use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{is_dir_mode, is_lnk_mode, FileInfo, MountSource};

use crate::inode::{InodeTable, ROOT_FILEID};
use crate::names::{join_path, parent_path, MAX_NAME_LEN};
use crate::reader::{fill_from_state, ReaderLru, DEFAULT_READER_SLOTS};

use super::error::io_to_fserror;

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
        Self {
            source,
            overlay,
            inodes: Arc::new(InodeTable::new()),
            readers: Arc::new(ReaderLru::new(DEFAULT_READER_SLOTS)),
            readahead_bytes,
            change: AtomicU64::new(1),
        }
    }

    fn change_id(&self) -> u64 {
        self.change.load(Ordering::Relaxed)
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
            .map(|d| {
                let child = join_path(&path, &d.name);
                let id = self.inodes.id_for_path(&child);
                (id, d.name, d.mode, d.size)
            })
            .collect();
        kids.sort_by_key(|(id, _, _, _)| *id);

        let start_idx = if cookie == 0 {
            0
        } else {
            match kids.iter().position(|(id, _, _, _)| *id == cookie) {
                Some(i) => i + 1,
                None => return Err(FsError::InvalidInput),
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
        // PR 3 is RO even when an overlay handle is stored (writes land in PR 4).
        let granted = AccessMask::READ | AccessMask::LOOKUP | AccessMask::EXECUTE;
        Ok(requested & granted)
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
    let fi_check = if path == "/" {
        ratarmount_core::create_root_file_info()
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
            explicit_sync: false,
            case_sensitive: true,
            case_preserving: true,
        }
    }

    fn limits(&self) -> FsLimits {
        let namemax = self.source.statfs().namemax.min(u64::from(u32::MAX)) as u32;
        FsLimits {
            max_name_bytes: namemax.max(1),
            max_read: 1_048_576,
            max_write: 0,
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
        _handle: &Self::Handle,
        _offset: u64,
        _data: Bytes,
        _requested: WriteStability,
    ) -> FsResult<WriteResult> {
        Err(FsError::ReadOnly)
    }

    async fn create(
        &self,
        _ctx: &RequestContext,
        _parent: &Self::Handle,
        _name: &str,
        _req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>> {
        Err(FsError::ReadOnly)
    }

    async fn remove(
        &self,
        _ctx: &RequestContext,
        _parent: &Self::Handle,
        _name: &str,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn rename(
        &self,
        _ctx: &RequestContext,
        _from_dir: &Self::Handle,
        _from_name: &str,
        _to_dir: &Self::Handle,
        _to_name: &str,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn setattr(
        &self,
        _ctx: &RequestContext,
        _handle: &Self::Handle,
        _attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        Err(FsError::ReadOnly)
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> {
        Some(self)
    }
}

#[async_trait]
impl Symlinks<u64> for RatarmountNfs4 {
    async fn create_symlink(
        &self,
        _ctx: &RequestContext,
        _parent: &u64,
        _name: &str,
        _target: &str,
        _attrs: &SetAttrs,
    ) -> FsResult<CreateResult<u64>> {
        Err(FsError::ReadOnly)
    }

    async fn readlink(&self, _ctx: &RequestContext, handle: &u64) -> FsResult<String> {
        self.readlink_sync(*handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{self, Cursor, Read, Seek};

    use ratarmount_core::{CheapDirent, FileInfo, ListResult, UserData, S_IFLNK, S_IFREG};

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

    #[test]
    fn v4_readdir_cookie_and_unknown() {
        let mut s = Synth::new();
        s.add_file("/a", b"1", vec![UserData::Other("t".into())]);
        s.add_file("/b", b"2", vec![UserData::Other("t".into())]);
        let nfs = nfs_of(s);
        let all = nfs.readdir_sync(1, 0, 10, true).unwrap();
        assert_eq!(all.entries.len(), 2);
        assert!(all.eof);
        assert_eq!(all.entries[0].cookie, all.entries[0].handle);
        let first = all.entries[0].cookie;
        let rest = nfs.readdir_sync(1, first, 10, false).unwrap();
        assert_eq!(rest.entries.len(), 1);
        assert!(rest.eof);
        assert!(rest.entries[0].attrs.is_none());
        assert_eq!(
            nfs.readdir_sync(1, 9999, 10, false).unwrap_err(),
            FsError::InvalidInput
        );
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
        assert_eq!(listing.entries.len(), 1);
        let id = listing.entries[0].handle;
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
}
