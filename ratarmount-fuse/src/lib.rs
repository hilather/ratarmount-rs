//! FUSE mount using `fuser` low-level API (read + optional write overlay).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, ReplyXattr, Request,
    FUSE_ROOT_ID,
};
use libc::{EIO, ENOENT, ENOSYS, EROFS};
use log::debug;
use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{FileInfo, ListModeResult, ListResult, MountSource};

/// Kernel attribute/entry cache TTL. Short values force re-lookup on every find/stat.
const TTL: Duration = Duration::from_secs(60);
const BLKSIZE: u32 = 256 * 1024;
const DIR_CACHE_TTL: Duration = Duration::from_secs(30);

enum OpenBackend {
    /// Keep the archive member reader open for the lifetime of the fh (critical for cat).
    Source {
        #[allow(dead_code)]
        path: String,
        #[allow(dead_code)]
        file_info: FileInfo,
        reader: Mutex<Box<dyn ratarmount_core::ArchiveRead>>,
    },
    /// Empty file — no underlying open.
    Empty,
    /// OS fd in write overlay
    OverlayFd(i32),
}

struct InodeEntry {
    path: String,
    /// Cached FileInfo to avoid SQLite on every getattr.
    file_info: Option<FileInfo>,
}

struct DirCacheEntry {
    entries: Vec<(String, u32)>,
    at: std::time::Instant,
}

pub struct RatarmountFs {
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    inodes: Mutex<HashMap<u64, InodeEntry>>,
    path_to_ino: Mutex<HashMap<String, u64>>,
    next_ino: AtomicU64,
    handles: Mutex<HashMap<u64, OpenBackend>>,
    next_fh: AtomicU64,
    dir_cache: Mutex<HashMap<String, DirCacheEntry>>,
}

impl RatarmountFs {
    pub fn new(source: Arc<dyn MountSource>, overlay: Option<Arc<WriteOverlay>>) -> Self {
        let mut inodes = HashMap::new();
        let mut path_to_ino = HashMap::new();
        inodes.insert(
            FUSE_ROOT_ID,
            InodeEntry {
                path: "/".into(),
                file_info: Some(ratarmount_core::create_root_file_info()),
            },
        );
        path_to_ino.insert("/".into(), FUSE_ROOT_ID);
        Self {
            source,
            overlay,
            inodes: Mutex::new(inodes),
            path_to_ino: Mutex::new(path_to_ino),
            next_ino: AtomicU64::new(FUSE_ROOT_ID + 1),
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            dir_cache: Mutex::new(HashMap::new()),
        }
    }

    fn ino_for_path(&self, path: &str) -> u64 {
        self.ino_for_path_with_fi(path, None)
    }

    fn ino_for_path_with_fi(&self, path: &str, fi: Option<FileInfo>) -> u64 {
        let mut p2i = self.path_to_ino.lock().unwrap();
        if let Some(&ino) = p2i.get(path) {
            if fi.is_some() {
                if let Some(ent) = self.inodes.lock().unwrap().get_mut(&ino) {
                    if ent.file_info.is_none() {
                        ent.file_info = fi;
                    }
                }
            }
            return ino;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        p2i.insert(path.to_string(), ino);
        self.inodes.lock().unwrap().insert(
            ino,
            InodeEntry {
                path: path.to_string(),
                file_info: fi,
            },
        );
        ino
    }

    fn path_for_ino(&self, ino: u64) -> Option<String> {
        self.inodes
            .lock()
            .unwrap()
            .get(&ino)
            .map(|e| e.path.clone())
    }

    fn cached_fi(&self, ino: u64) -> Option<FileInfo> {
        self.inodes
            .lock()
            .unwrap()
            .get(&ino)
            .and_then(|e| e.file_info.clone())
    }

    fn store_fi(&self, ino: u64, fi: FileInfo) {
        if let Some(ent) = self.inodes.lock().unwrap().get_mut(&ino) {
            ent.file_info = Some(fi);
        }
    }

    fn list_mode_cached(&self, path: &str) -> Option<Vec<(String, u32)>> {
        {
            let cache = self.dir_cache.lock().unwrap();
            if let Some(e) = cache.get(path) {
                if e.at.elapsed() < DIR_CACHE_TTL {
                    return Some(e.entries.clone());
                }
            }
        }
        let listing = self.source.list_mode(path)?;
        let entries: Vec<(String, u32)> = match listing {
            ListModeResult::Modes(m) => m.into_iter().collect(),
            ListModeResult::Names(names) => names
                .into_iter()
                .map(|n| (n, ratarmount_core::S_IFREG))
                .collect(),
        };
        self.dir_cache.lock().unwrap().insert(
            path.to_string(),
            DirCacheEntry {
                entries: entries.clone(),
                at: std::time::Instant::now(),
            },
        );
        Some(entries)
    }

    fn file_attr(ino: u64, fi: &FileInfo) -> FileAttr {
        let kind = mode_to_kind(fi.mode);
        let perm = (fi.mode & 0o7777) as u16;
        let mtime = unix_float_to_system_time(fi.mtime);
        FileAttr {
            ino,
            size: fi.size,
            blocks: fi.size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm,
            nlink: 1,
            uid: fi.uid,
            gid: fi.gid,
            rdev: 0,
            blksize: BLKSIZE,
            flags: 0,
        }
    }

    fn writable(&self) -> bool {
        self.overlay.is_some()
    }

    /// Resolve `FileInfo` for an inode (cache first, then source lookup).
    fn file_info_for_ino(&self, ino: u64) -> Option<FileInfo> {
        if let Some(fi) = self.cached_fi(ino) {
            return Some(fi);
        }
        let path = self.path_for_ino(ino)?;
        let fi = if path == "/" {
            ratarmount_core::create_root_file_info()
        } else {
            self.source.lookup(&path, 0)?
        };
        self.store_fi(ino, fi.clone());
        Some(fi)
    }
}

/// Encode xattr names as concatenated NUL-terminated C strings (FUSE listxattr wire format).
fn encode_xattr_list(keys: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for key in keys {
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(0);
    }
    bytes
}

fn reply_xattr_bytes(size: u32, data: &[u8], reply: ReplyXattr) {
    if size == 0 {
        reply.size(data.len() as u32);
    } else if data.len() <= size as usize {
        reply.data(data);
    } else {
        reply.error(libc::ERANGE);
    }
}

fn mode_to_kind(mode: u32) -> FileType {
    match mode & ratarmount_core::S_IFMT {
        x if x == ratarmount_core::S_IFDIR => FileType::Directory,
        x if x == ratarmount_core::S_IFLNK => FileType::Symlink,
        x if x == ratarmount_core::S_IFIFO => FileType::NamedPipe,
        x if x == ratarmount_core::S_IFCHR => FileType::CharDevice,
        x if x == ratarmount_core::S_IFBLK => FileType::BlockDevice,
        x if x == ratarmount_core::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

fn unix_float_to_system_time(t: f64) -> SystemTime {
    if t <= 0.0 {
        return UNIX_EPOCH;
    }
    let secs = t.trunc() as u64;
    let nsec = ((t.fract()) * 1e9) as u32;
    UNIX_EPOCH + Duration::new(secs, nsec)
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

impl Filesystem for RatarmountFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.path_for_ino(parent) else {
            reply.error(ENOENT);
            return;
        };
        let name = name.to_string_lossy();
        let path = join_path(&parent_path, &name);
        let Some(fi) = self.source.lookup(&path, 0) else {
            reply.error(ENOENT);
            return;
        };
        let ino = self.ino_for_path_with_fi(&path, Some(fi.clone()));
        reply.entry(&TTL, &Self::file_attr(ino, &fi), 0);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if let Some(fi) = self.cached_fi(ino) {
            reply.attr(&TTL, &Self::file_attr(ino, &fi));
            return;
        }
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        let Some(fi) = self.source.lookup(&path, 0) else {
            if path == "/" {
                let fi = ratarmount_core::create_root_file_info();
                reply.attr(&TTL, &Self::file_attr(ino, &fi));
                return;
            }
            reply.error(ENOENT);
            return;
        };
        self.store_fi(ino, fi.clone());
        reply.attr(&TTL, &Self::file_attr(ino, &fi));
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        let Some(entries) = self.list_mode_cached(&path) else {
            reply.error(ENOENT);
            return;
        };

        let mut full: Vec<(u64, FileType, String)> = Vec::new();
        full.push((ino, FileType::Directory, ".".into()));
        full.push((
            if path == "/" {
                ino
            } else {
                let parent = path.rsplit_once('/').map(|(p, _)| {
                    if p.is_empty() {
                        "/".to_string()
                    } else {
                        p.to_string()
                    }
                });
                parent
                    .as_ref()
                    .map(|p| self.ino_for_path(p))
                    .unwrap_or(FUSE_ROOT_ID)
            },
            FileType::Directory,
            "..".into(),
        ));
        for (name, mode) in entries {
            let child = join_path(&path, &name);
            let cino = self.ino_for_path(&child);
            full.push((cino, mode_to_kind(mode), name));
        }

        for (i, (cino, kind, name)) in full.into_iter().enumerate().skip(offset as usize) {
            let next_offset = (i + 1) as i64;
            if reply.add(cino, next_offset, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        // One list() call + attr packing (no N× getattr round-trips for find).
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        let Some(ListResult::Infos(map)) = self.source.list(&path) else {
            // Fall back: modes only
            let Some(entries) = self.list_mode_cached(&path) else {
                reply.error(ENOENT);
                return;
            };
            let self_fi = self
                .cached_fi(ino)
                .unwrap_or_else(ratarmount_core::create_root_file_info);
            let mut full: Vec<(u64, String, FileAttr)> = Vec::new();
            full.push((ino, ".".into(), Self::file_attr(ino, &self_fi)));
            full.push((ino, "..".into(), Self::file_attr(ino, &self_fi)));
            for (name, mode) in entries {
                let child = join_path(&path, &name);
                let fi = FileInfo {
                    size: 0,
                    mtime: self_fi.mtime,
                    mode,
                    linkname: String::new(),
                    uid: self_fi.uid,
                    gid: self_fi.gid,
                    userdata: vec![],
                };
                let cino = self.ino_for_path_with_fi(&child, Some(fi.clone()));
                full.push((cino, name, Self::file_attr(cino, &fi)));
            }
            for (i, (cino, name, attr)) in full.into_iter().enumerate().skip(offset as usize) {
                if reply.add(cino, (i + 1) as i64, name, &TTL, &attr, 0) {
                    break;
                }
            }
            reply.ok();
            return;
        };
        let self_fi = self
            .cached_fi(ino)
            .or_else(|| self.source.lookup(&path, 0))
            .unwrap_or_else(ratarmount_core::create_root_file_info);
        let mut full: Vec<(u64, String, FileAttr)> = Vec::with_capacity(map.len() + 2);
        full.push((ino, ".".into(), Self::file_attr(ino, &self_fi)));
        let parent_ino = if path == "/" {
            ino
        } else {
            path.rsplit_once('/')
                .map(|(p, _)| {
                    let pp = if p.is_empty() { "/" } else { p };
                    self.ino_for_path(pp)
                })
                .unwrap_or(FUSE_ROOT_ID)
        };
        full.push((
            parent_ino,
            "..".into(),
            Self::file_attr(parent_ino, &self_fi),
        ));
        for (name, fi) in map {
            let child = join_path(&path, &name);
            let cino = self.ino_for_path_with_fi(&child, Some(fi.clone()));
            full.push((cino, name, Self::file_attr(cino, &fi)));
        }
        for (i, (cino, name, attr)) in full.into_iter().enumerate().skip(offset as usize) {
            if reply.add(cino, (i + 1) as i64, name, &TTL, &attr, 0) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        let write = (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0;
        if write {
            if let Some(ov) = &self.overlay {
                match ov.open_overlay_fd(&path, flags) {
                    Ok(fd) => {
                        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                        self.handles
                            .lock()
                            .unwrap()
                            .insert(fh, OpenBackend::OverlayFd(fd));
                        reply.opened(fh, 0);
                        return;
                    }
                    Err(e) => {
                        debug!("overlay open: {e}");
                        reply.error(EIO);
                        return;
                    }
                }
            } else {
                reply.error(EROFS);
                return;
            }
        }
        let fi = if let Some(c) = self.cached_fi(ino) {
            c
        } else if let Some(fi) = self.source.lookup(&path, 0) {
            self.store_fi(ino, fi.clone());
            fi
        } else {
            reply.error(ENOENT);
            return;
        };

        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        if fi.size == 0 {
            self.handles.lock().unwrap().insert(fh, OpenBackend::Empty);
            reply.opened(fh, fuser::consts::FOPEN_KEEP_CACHE);
            return;
        }
        match self.source.open(&fi, 0) {
            Ok(reader) => {
                self.handles.lock().unwrap().insert(
                    fh,
                    OpenBackend::Source {
                        path,
                        file_info: fi,
                        reader: Mutex::new(reader),
                    },
                );
                // Allow kernel page cache of archive member data.
                reply.opened(fh, fuser::consts::FOPEN_KEEP_CACHE);
            }
            Err(e) => {
                debug!("open error: {e}");
                reply.error(EIO);
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let mut handles = self.handles.lock().unwrap();
        let Some(backend) = handles.get_mut(&fh) else {
            reply.error(ENOENT);
            return;
        };
        match backend {
            OpenBackend::Empty => {
                reply.data(&[]);
            }
            OpenBackend::OverlayFd(fd) => {
                let mut buf = vec![0u8; size as usize];
                let n = unsafe {
                    libc::pread(
                        *fd,
                        buf.as_mut_ptr() as *mut _,
                        size as usize,
                        offset.max(0),
                    )
                };
                if n < 0 {
                    reply.error(EIO);
                } else {
                    buf.truncate(n as usize);
                    reply.data(&buf);
                }
            }
            OpenBackend::Source { reader, .. } => {
                let r = reader.get_mut().unwrap();
                if let Err(e) = r.seek(std::io::SeekFrom::Start(offset.max(0) as u64)) {
                    debug!("seek error: {e}");
                    reply.error(EIO);
                    return;
                }
                let mut buf = vec![0u8; size as usize];
                match std::io::Read::read(r, &mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        reply.data(&buf);
                    }
                    Err(e) => {
                        debug!("read error: {e}");
                        reply.error(EIO);
                    }
                }
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let fd = {
            let g = self.handles.lock().unwrap();
            match g.get(&fh) {
                Some(OpenBackend::OverlayFd(fd)) => *fd,
                _ => {
                    reply.error(if self.writable() { EIO } else { EROFS });
                    return;
                }
            }
        };
        let n = unsafe { libc::pwrite(fd, data.as_ptr() as *const _, data.len(), offset.max(0)) };
        if n < 0 {
            reply.error(EIO);
        } else {
            reply.written(n as u32);
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(ov) = &self.overlay else {
            reply.error(EROFS);
            return;
        };
        let Some(parent_path) = self.path_for_ino(parent) else {
            reply.error(ENOENT);
            return;
        };
        let name = name.to_string_lossy();
        let path = join_path(&parent_path, &name);
        match ov.create_file(&path, mode) {
            Ok(fd) => {
                let ino = self.ino_for_path(&path);
                let fi = self.source.lookup(&path, 0).unwrap_or_else(|| FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: mode | ratarmount_core::S_IFREG,
                    linkname: String::new(),
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    userdata: vec![],
                });
                let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                self.handles
                    .lock()
                    .unwrap()
                    .insert(fh, OpenBackend::OverlayFd(fd));
                reply.created(&TTL, &Self::file_attr(ino, &fi), 0, fh, 0);
            }
            Err(e) => {
                debug!("create: {e}");
                reply.error(EIO);
            }
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(ov) = &self.overlay else {
            reply.error(EROFS);
            return;
        };
        let Some(parent_path) = self.path_for_ino(parent) else {
            reply.error(ENOENT);
            return;
        };
        let name = name.to_string_lossy();
        let path = join_path(&parent_path, &name);
        match ov.mkdir(&path, mode) {
            Ok(()) => {
                let ino = self.ino_for_path(&path);
                let fi = self.source.lookup(&path, 0).unwrap_or_else(|| FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: mode | ratarmount_core::S_IFDIR,
                    linkname: String::new(),
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    userdata: vec![],
                });
                reply.entry(&TTL, &Self::file_attr(ino, &fi), 0);
            }
            Err(e) => {
                debug!("mkdir: {e}");
                reply.error(EIO);
            }
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(ov) = &self.overlay else {
            reply.error(EROFS);
            return;
        };
        let Some(parent_path) = self.path_for_ino(parent) else {
            reply.error(ENOENT);
            return;
        };
        let path = join_path(&parent_path, &name.to_string_lossy());
        match ov.unlink(&path) {
            Ok(()) => reply.ok(),
            Err(e) => {
                debug!("unlink: {e}");
                reply.error(EIO);
            }
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(ov) = &self.overlay else {
            reply.error(EROFS);
            return;
        };
        let Some(parent_path) = self.path_for_ino(parent) else {
            reply.error(ENOENT);
            return;
        };
        let path = join_path(&parent_path, &name.to_string_lossy());
        match ov.rmdir(&path) {
            Ok(()) => reply.ok(),
            Err(e) => {
                debug!("rmdir: {e}");
                reply.error(EIO);
            }
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        if let Some(sz) = size {
            let Some(ov) = &self.overlay else {
                reply.error(EROFS);
                return;
            };
            if let Err(e) = ov.truncate(&path, sz) {
                debug!("truncate: {e}");
                reply.error(EIO);
                return;
            }
        } else if !self.writable() {
            reply.error(ENOSYS);
            return;
        }
        let fi = self
            .source
            .lookup(&path, 0)
            .unwrap_or_else(ratarmount_core::create_root_file_info);
        reply.attr(&TTL, &Self::file_attr(ino, &fi));
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(OpenBackend::OverlayFd(fd)) = self.handles.lock().unwrap().remove(&fh) {
            unsafe {
                libc::close(fd);
            }
        }
        reply.ok();
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        let Some(fi) = self.source.lookup(&path, 0) else {
            reply.error(ENOENT);
            return;
        };
        reply.data(fi.linkname.as_bytes());
    }

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let Some(fi) = self.file_info_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        let key = name.to_string_lossy();
        match self.source.get_xattr(&fi, &key) {
            Some(value) => reply_xattr_bytes(size, &value, reply),
            None => {
                // Linux: ENODATA; macOS/BSD: ENOATTR (same numeric value on many systems).
                #[cfg(target_os = "linux")]
                reply.error(libc::ENODATA);
                #[cfg(not(target_os = "linux"))]
                reply.error(libc::ENOATTR);
            }
        }
    }

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        let Some(fi) = self.file_info_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        let keys = self.source.list_xattr(&fi);
        let bytes = encode_xattr_list(&keys);
        reply_xattr_bytes(size, &bytes, reply);
    }
}

/// Parse a Python-style `-o` / `--fuse` comma-separated option string into `MountOption`s.
///
/// Unknown tokens become `MountOption::CUSTOM` (passed through to libfuse/kernel).
pub fn parse_fuse_options(s: &str) -> Vec<MountOption> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(mount_option_from_str)
        .collect()
}

fn mount_option_from_str(s: &str) -> MountOption {
    match s {
        "auto_unmount" => MountOption::AutoUnmount,
        "allow_other" => MountOption::AllowOther,
        "allow_root" => MountOption::AllowRoot,
        "default_permissions" => MountOption::DefaultPermissions,
        "dev" => MountOption::Dev,
        "nodev" => MountOption::NoDev,
        "suid" => MountOption::Suid,
        "nosuid" => MountOption::NoSuid,
        "ro" => MountOption::RO,
        "rw" => MountOption::RW,
        "exec" => MountOption::Exec,
        "noexec" => MountOption::NoExec,
        "atime" => MountOption::Atime,
        "noatime" => MountOption::NoAtime,
        "dirsync" => MountOption::DirSync,
        "sync" => MountOption::Sync,
        "async" => MountOption::Async,
        x if x.starts_with("fsname=") => MountOption::FSName(x[7..].into()),
        x if x.starts_with("subtype=") => MountOption::Subtype(x[8..].into()),
        x => MountOption::CUSTOM(x.into()),
    }
}

/// Mount `source` at `mountpoint` (blocking).
///
/// `extra_fuse_opts` is the `-o` / `--fuse` string (comma-separated).
pub fn mount_blocking(
    source: Arc<dyn MountSource>,
    mountpoint: impl AsRef<Path>,
    foreground: bool,
    writable: bool,
    overlay: Option<Arc<WriteOverlay>>,
    extra_fuse_opts: &str,
) -> std::io::Result<()> {
    let mut options = vec![MountOption::FSName("ratarmount".into())];
    if !writable {
        options.push(MountOption::RO);
    }
    for opt in parse_fuse_options(extra_fuse_opts) {
        // User `-o rw` can override default RO for writable overlays; for RO mounts keep RO.
        match &opt {
            MountOption::RW if !writable => continue,
            MountOption::RO => {}
            MountOption::FSName(_) => {
                // Prefer user-supplied fsname if present.
                options.retain(|o| !matches!(o, MountOption::FSName(_)));
            }
            _ => {}
        }
        options.push(opt);
    }
    let _ = foreground;
    let fs = RatarmountFs::new(source, overlay);
    fuser::mount2(fs, mountpoint, &options)?;
    Ok(())
}

pub fn unmount(mountpoint: impl AsRef<Path>) -> std::io::Result<()> {
    let mp = mountpoint.as_ref();
    #[cfg(target_os = "macos")]
    {
        unmount_macos(mp)
    }
    #[cfg(not(target_os = "macos"))]
    {
        unmount_linux(mp)
    }
}

/// Linux: `fusermount3 -u` then `fusermount -u`.
#[cfg(not(target_os = "macos"))]
fn unmount_linux(mp: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("fusermount3")
        .args(["-u"])
        .arg(mp)
        .status()
        .or_else(|_| {
            std::process::Command::new("fusermount")
                .args(["-u"])
                .arg(mp)
                .status()
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "fusermount failed for {}",
            mp.display()
        )))
    }
}

/// macOS: `umount`, then `diskutil unmount` (+ force).
#[cfg(target_os = "macos")]
fn unmount_macos(mp: &Path) -> std::io::Result<()> {
    if let Ok(status) = std::process::Command::new("umount").arg(mp).status() {
        if status.success() {
            return Ok(());
        }
    }
    if let Ok(status) = std::process::Command::new("diskutil")
        .args(["unmount"])
        .arg(mp)
        .status()
    {
        if status.success() {
            return Ok(());
        }
    }
    let status = std::process::Command::new("diskutil")
        .args(["unmount", "force"])
        .arg(mp)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "umount/diskutil unmount failed for {}",
            mp.display()
        )))
    }
}

#[allow(dead_code)]
fn _pb() -> PathBuf {
    PathBuf::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_core::{ListModeResult, ListResult, MountSource, S_IFREG};
    use std::collections::BTreeMap;
    use std::io;

    /// Minimal MountSource that only serves synthetic xattrs for unit tests.
    struct XattrSource {
        fi: FileInfo,
        attrs: BTreeMap<String, Vec<u8>>,
    }

    impl MountSource for XattrSource {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                let mut m = BTreeMap::new();
                m.insert("f".into(), self.fi.clone());
                Some(ListResult::Infos(m))
            } else {
                None
            }
        }

        fn list_mode(&self, path: &str) -> Option<ListModeResult> {
            if path == "/" {
                let mut m = BTreeMap::new();
                m.insert("f".into(), self.fi.mode);
                Some(ListModeResult::Modes(m))
            } else {
                None
            }
        }

        fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
            match path {
                "/" => Some(ratarmount_core::create_root_file_info()),
                "/f" => Some(self.fi.clone()),
                _ => None,
            }
        }

        fn open(
            &self,
            _file_info: &FileInfo,
            _buffering: i32,
        ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(io::Cursor::new(Vec::new())))
        }

        fn is_immutable(&self) -> bool {
            true
        }

        fn list_xattr(&self, _file_info: &FileInfo) -> Vec<String> {
            self.attrs.keys().cloned().collect()
        }

        fn get_xattr(&self, _file_info: &FileInfo, key: &str) -> Option<Vec<u8>> {
            self.attrs.get(key).cloned()
        }
    }

    #[test]
    fn encode_xattr_list_null_terminated() {
        let keys = vec!["user.hash.sha256".into(), "user.hash.crc32".into()];
        let bytes = encode_xattr_list(&keys);
        assert_eq!(bytes, b"user.hash.sha256\0user.hash.crc32\0".as_slice());
    }

    #[test]
    fn source_xattr_roundtrip_via_fs_cache() {
        let digest = b"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447".to_vec();
        let mut attrs = BTreeMap::new();
        attrs.insert("user.hash.sha256".into(), digest.clone());
        let fi = FileInfo {
            size: 12,
            mtime: 0.0,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![],
        };
        let src = Arc::new(XattrSource { fi, attrs });
        let fs = RatarmountFs::new(src, None);

        // Prime inode cache as lookup would.
        let ino = fs.ino_for_path_with_fi("/f", Some(fs.source.lookup("/f", 0).unwrap()));
        let fi = fs.file_info_for_ino(ino).expect("fi");
        let keys = fs.source.list_xattr(&fi);
        assert_eq!(keys, vec!["user.hash.sha256".to_string()]);
        assert_eq!(
            fs.source.get_xattr(&fi, "user.hash.sha256").as_deref(),
            Some(digest.as_slice())
        );
        assert!(fs.source.get_xattr(&fi, "user.hash.md5").is_none());
    }
}
