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
use libc::{EACCES, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, EROFS};
use log::debug;
use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{CheapDirent, FileInfo, MountSource};
use std::io::ErrorKind;

/// Kernel attribute/entry cache TTL. Short values force re-lookup on every find/stat.
const TTL: Duration = Duration::from_secs(60);
/// With a write overlay, sizes change after create/write — do not let the kernel
/// cache attrs for long (or getattr would keep serving create-time size 0).
const OVERLAY_ATTR_TTL: Duration = Duration::from_secs(0);
const BLKSIZE: u32 = 256 * 1024;
const DIR_CACHE_TTL: Duration = Duration::from_secs(30);

/// Map `std::io::Error` to a FUSE/libc errno.
///
/// Password / permission failures must not collapse to generic EIO — that is what
/// users see as "Input/output error" when opening encrypted nested 7z without
/// `--password`.
fn io_to_errno(err: &std::io::Error) -> i32 {
    match err.kind() {
        ErrorKind::NotFound => ENOENT,
        ErrorKind::PermissionDenied => EACCES,
        ErrorKind::IsADirectory => EISDIR,
        ErrorKind::InvalidInput => EINVAL,
        ErrorKind::Unsupported => ENOSYS,
        _ => EIO,
    }
}

/// Fill `buf` from `r` by looping `Read::read` until the buffer is full or true EOF.
///
/// **FUSE contract:** a short reply means end-of-file. Codecs such as seekable
/// gzip / rapidgzip often return one inflate window (~64 KiB) per `Read::read`
/// while more data remains. A single short `read` would make the kernel stop
/// and tools report UnexpectedEof / truncated archives. Always use this helper
/// for archive-backed FUSE reads (including readahead fills).
///
/// Pair with [`readahead_fill`]: the readahead window amortizes many short
/// underlying `read`s into one large fill so sequential `cat` / scanners do not
/// pay a seek+decompress per FUSE request.
fn fill_read_for_fuse(r: &mut dyn std::io::Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match std::io::Read::read(r, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Hard cap for `--readahead` (64 MiB) so a typo cannot pin multi‑GiB RAM per open.
pub const MAX_READAHEAD_BYTES: u64 = 64 * 1024 * 1024;

/// Recommended sequential readahead for short-read decompressors (gzip /
/// rapidgzip / multi-frame zstd members): 1 MiB.
///
/// Kernel FUSE reads are typically ≤128 KiB; codecs often yield ~64 KiB per
/// `Read::read`. A 1 MiB window covers many FUSE requests per seek/decompress
/// without the 64 MiB hard cap. CLI default remains `0` (off); pass this when
/// tuning for sequential thruput on compressed members.
pub const RECOMMENDED_READAHEAD_BYTES: u64 = 1024 * 1024;

/// Parse a human byte size for CLI / config: bare integer or `K`/`M`/`G` (1024-based).
///
/// Accepts `KiB`/`MiB`/`GiB` and mixed case. Examples: `0`, `4096`, `256K`, `1M`, `2MiB`.
pub fn parse_byte_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let lower = s.to_ascii_lowercase();
    let (num_str, mult) = if let Some(rest) = lower.strip_suffix("kib") {
        (rest.trim(), 1024u64)
    } else if let Some(rest) = lower.strip_suffix("mib") {
        (rest.trim(), 1024 * 1024)
    } else if let Some(rest) = lower.strip_suffix("gib") {
        (rest.trim(), 1024 * 1024 * 1024)
    } else if let Some(rest) = lower.strip_suffix('k') {
        (rest.trim(), 1024)
    } else if let Some(rest) = lower.strip_suffix('m') {
        (rest.trim(), 1024 * 1024)
    } else if let Some(rest) = lower.strip_suffix('g') {
        (rest.trim(), 1024 * 1024 * 1024)
    } else {
        (lower.as_str(), 1)
    };
    if num_str.is_empty() {
        return Err(format!("invalid size: {s}"));
    }
    let num: u64 = num_str.parse().map_err(|_| format!("invalid size: {s}"))?;
    num.checked_mul(mult)
        .ok_or_else(|| format!("size overflow: {s}"))
}

/// Clamp readahead to [`MAX_READAHEAD_BYTES`].
pub fn clamp_readahead(bytes: u64) -> u64 {
    bytes.min(MAX_READAHEAD_BYTES)
}

/// Per-open window of decoded/source bytes retained for sequential FUSE reads.
#[derive(Clone, Debug, Default)]
struct ReadAheadWindow {
    /// Absolute file offset of `data[0]`.
    start: u64,
    data: Vec<u8>,
    /// Last fill was short ⇒ true EOF at `start + data.len()`.
    hit_eof: bool,
}

impl ReadAheadWindow {
    fn end_offset(&self) -> u64 {
        self.start.saturating_add(self.data.len() as u64)
    }

    /// Return bytes for `[offset, offset+size)` when fully covered, or a short
    /// EOF slice when the window ends at EOF. `None` means refill required.
    fn try_serve(&self, offset: u64, size: usize) -> Option<Vec<u8>> {
        if size == 0 {
            return Some(Vec::new());
        }
        // Past true EOF: empty without another underlying seek/fill.
        if self.hit_eof && offset >= self.end_offset() {
            return Some(Vec::new());
        }
        if offset < self.start {
            return None;
        }
        let i = match usize::try_from(offset - self.start) {
            Ok(i) => i,
            Err(_) => return None,
        };
        if i >= self.data.len() {
            return None;
        }
        let end = i.saturating_add(size).min(self.data.len());
        let slice = &self.data[i..end];
        if slice.len() == size {
            return Some(slice.to_vec());
        }
        // Partial cover: valid only when the window ends at true EOF.
        if self.hit_eof && end == self.data.len() {
            return Some(slice.to_vec());
        }
        None
    }
}

/// Per-open readahead bookkeeping (window + sequential/random heuristics).
///
/// **Short-read codecs** (gzip/rapidgzip windows, multi-frame zstd):
/// fills always go through [`fill_read_for_fuse`], which loops until the
/// requested buffer is full or true EOF — so a single underlying short
/// `Read::read` never becomes a false FUSE EOF.
///
/// **Sequential vs random:** the first miss and any offset that continues
/// from the previous serve (`last_end`) or from the retained window end use a
/// large fill (`max(size, readahead_bytes)`). Random seeks fill only the
/// request size so scattered I/O does not storm the decompressor with
/// multi‑MiB fills. Sequential continuation after a fill skips a redundant
/// `Seek` when the underlying cursor is already at the requested offset.
#[derive(Clone, Debug, Default)]
struct ReadaheadState {
    window: Option<ReadAheadWindow>,
    /// Known absolute position of the underlying reader after last seek/fill.
    cursor: Option<u64>,
    /// End offset of the last FUSE response (`offset + returned len`).
    last_end: Option<u64>,
}

impl ReadaheadState {
    fn clear(&mut self) {
        self.window = None;
        self.cursor = None;
        self.last_end = None;
    }

    /// True when a miss should pull a full readahead window (not exact size).
    fn is_sequential_miss(&self, offset: u64) -> bool {
        if self.window.is_none() && self.last_end.is_none() {
            // First fill on this open: prime a large window (typical `cat`).
            return true;
        }
        if self.last_end == Some(offset) {
            return true;
        }
        if let Some(w) = self.window.as_ref() {
            if offset == w.end_offset() {
                return true;
            }
        }
        false
    }
}

/// Serve a FUSE read, optionally retaining a sequential readahead window.
///
/// * `readahead_bytes == 0` — exact-size read (legacy); state is cleared.
/// * `readahead_bytes > 0` — sequential misses fill `max(size, readahead_bytes)`
///   so later kernel reads hit the window without another seek/decompress;
///   random misses fill only `size` (upstream #180 / FR-5 + short-read coop).
fn readahead_fill(
    reader: &mut dyn ratarmount_core::ArchiveRead,
    state: &mut ReadaheadState,
    readahead_bytes: usize,
    offset: u64,
    size: usize,
) -> std::io::Result<Vec<u8>> {
    if readahead_bytes == 0 {
        state.clear();
        reader.seek(std::io::SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size];
        let n = fill_read_for_fuse(reader, &mut buf)?;
        buf.truncate(n);
        return Ok(buf);
    }

    if size == 0 {
        return Ok(Vec::new());
    }

    if let Some(w) = state.window.as_ref() {
        if let Some(out) = w.try_serve(offset, size) {
            state.last_end = Some(offset.saturating_add(out.len() as u64));
            return Ok(out);
        }
    }

    let sequential = state.is_sequential_miss(offset);
    let want = if sequential {
        size.max(readahead_bytes)
    } else {
        // Random seek: exact request only — avoid multi‑MiB readahead storm.
        size
    };

    // Skip seek when the prior fill left the cursor at this offset (sequential
    // walk past the window end). Random misses and mid-window straddles seek.
    if state.cursor != Some(offset) {
        reader.seek(std::io::SeekFrom::Start(offset))?;
        state.cursor = Some(offset);
    }

    let mut data = vec![0u8; want];
    let n = fill_read_for_fuse(reader, &mut data)?;
    data.truncate(n);
    state.cursor = Some(offset.saturating_add(n as u64));
    let hit_eof = n < want;
    let out_len = n.min(size);
    let out = data[..out_len].to_vec();
    state.last_end = Some(offset.saturating_add(out_len as u64));
    state.window = Some(ReadAheadWindow {
        start: offset,
        data,
        hit_eof,
    });
    Ok(out)
}

/// Per-open archive reader + optional sequential readahead state.
///
/// Held under its own `Mutex` (behind `Arc`) so FUSE `read` can release the
/// process-wide handle map while decompressing a large readahead fill.
struct SourceReadState {
    reader: Box<dyn ratarmount_core::ArchiveRead>,
    readahead: ReadaheadState,
}

enum OpenBackend {
    /// Keep the archive member reader open for the lifetime of the fh (critical for cat).
    Source {
        #[allow(dead_code)]
        path: String,
        #[allow(dead_code)]
        file_info: FileInfo,
        state: Arc<Mutex<SourceReadState>>,
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
    /// `(name, mode, size)` from cheap [`MountSource::list_dirents`] (no fat FileInfo).
    entries: Vec<(String, u32, u64)>,
    at: std::time::Instant,
}

pub struct RatarmountFs {
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    /// Per-handle sequential readahead size in bytes (`0` = disabled).
    readahead_bytes: usize,
    inodes: Mutex<HashMap<u64, InodeEntry>>,
    path_to_ino: Mutex<HashMap<String, u64>>,
    next_ino: AtomicU64,
    handles: Mutex<HashMap<u64, OpenBackend>>,
    next_fh: AtomicU64,
    dir_cache: Mutex<HashMap<String, DirCacheEntry>>,
}

impl RatarmountFs {
    pub fn new(source: Arc<dyn MountSource>, overlay: Option<Arc<WriteOverlay>>) -> Self {
        Self::with_readahead(source, overlay, 0)
    }

    /// Like [`Self::new`], with application-level sequential readahead (bytes; `0` off).
    ///
    /// Values above [`MAX_READAHEAD_BYTES`] are clamped. For short-read
    /// decompressors prefer [`RECOMMENDED_READAHEAD_BYTES`] (1 MiB).
    pub fn with_readahead(
        source: Arc<dyn MountSource>,
        overlay: Option<Arc<WriteOverlay>>,
        readahead: u64,
    ) -> Self {
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
        let readahead_bytes = usize::try_from(clamp_readahead(readahead)).unwrap_or(usize::MAX);
        Self {
            source,
            overlay,
            readahead_bytes,
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
            // Always refresh when the caller provides FileInfo (lookup/list may
            // carry a fresher size after overlay create/write).
            if let Some(fi) = fi {
                if let Some(ent) = self.inodes.lock().unwrap().get_mut(&ino) {
                    ent.file_info = Some(fi);
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

    /// Cheap readdir listing: name / mode / size (no fat [`FileInfo`] map).
    ///
    /// Always goes through [`MountSource::list_dirents`], never [`MountSource::list`].
    /// Fat `FileInfo` is materialized later at getattr/lookup/open.
    fn list_mode_cached(&self, path: &str) -> Option<Vec<(String, u32, u64)>> {
        {
            let cache = self.dir_cache.lock().unwrap();
            if let Some(e) = cache.get(path) {
                if e.at.elapsed() < DIR_CACHE_TTL {
                    return Some(e.entries.clone());
                }
            }
        }
        let listing = self.source.list_dirents(path)?;
        let entries: Vec<(String, u32, u64)> = listing
            .into_iter()
            .map(|CheapDirent { name, mode, size }| (name, mode, size))
            .collect();
        self.dir_cache.lock().unwrap().insert(
            path.to_string(),
            DirCacheEntry {
                entries: entries.clone(),
                at: std::time::Instant::now(),
            },
        );
        Some(entries)
    }

    /// Shared cheap listing for `readdir` / `readdirplus` (test-visible).
    #[cfg(test)]
    fn readdir_dirents(&self, path: &str) -> Option<Vec<(String, u32, u64)>> {
        self.list_mode_cached(path)
    }

    /// Same resolution as FUSE `readlink` (inode-cached `FileInfo.linkname`).
    #[cfg(test)]
    fn readlink_target(&self, ino: u64) -> Option<String> {
        self.file_info_for_ino(ino).map(|fi| fi.linkname)
    }

    /// Kernel TTL for one `readdirplus` dirent attr.
    ///
    /// Dirents with a nonzero size (real index `list_dirents` sizes) and
    /// directories use the same attr TTL as lookup so `cat` after `find` does
    /// not re-getattr every file. A zero-size non-directory dirent may be a
    /// placeholder (default `list_dirents` fallback, control `status`,
    /// versions-folder entries): caching size 0 for a file that is not really
    /// empty makes the kernel serve reads at EOF, so those revalidate instead.
    fn readdirplus_entry_ttl(&self, attr: &FileAttr) -> Duration {
        if self.overlay.is_some() {
            return OVERLAY_ATTR_TTL;
        }
        if attr.kind == FileType::Directory || attr.size > 0 {
            TTL
        } else {
            Duration::ZERO
        }
    }

    /// FileInfo for `open`. Immutable mounts reuse the lookup/getattr cache;
    /// overlay always re-looks up so create(size 0) → write is visible.
    fn file_info_for_open(&self, ino: u64, path: &str) -> Option<FileInfo> {
        if self.overlay.is_some() {
            if let Some(fi) = self.source.lookup(path, 0) {
                self.store_fi(ino, fi.clone());
                return Some(fi);
            }
            return self.cached_fi(ino);
        }
        if let Some(c) = self.cached_fi(ino) {
            return Some(c);
        }
        let fi = self.source.lookup(path, 0)?;
        self.store_fi(ino, fi.clone());
        Some(fi)
    }

    /// Drop a parent directory listing so create/unlink/mkdir/rmdir are visible
    /// to readdir before the 30s TTL expires.
    fn invalidate_dir_cache(&self, parent: &str) {
        self.dir_cache.lock().unwrap().remove(parent);
    }

    /// Kernel attr/entry TTL: zero when a write overlay can change size/names.
    fn attr_ttl(&self) -> Duration {
        if self.overlay.is_some() {
            OVERLAY_ATTR_TTL
        } else {
            TTL
        }
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

    /// Resolve `FileInfo` for an inode.
    ///
    /// With a write overlay, always re-lookup so size/mtime after create/write
    /// match the on-disk overlay file (cache may still hold create-time size 0).
    fn file_info_for_ino(&self, ino: u64) -> Option<FileInfo> {
        let path = self.path_for_ino(ino)?;
        if path == "/" {
            let fi = ratarmount_core::create_root_file_info();
            self.store_fi(ino, fi.clone());
            return Some(fi);
        }
        if self.overlay.is_some() {
            if let Some(fi) = self.source.lookup(&path, 0) {
                self.store_fi(ino, fi.clone());
                return Some(fi);
            }
        }
        if let Some(fi) = self.cached_fi(ino) {
            return Some(fi);
        }
        let fi = self.source.lookup(&path, 0)?;
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
        reply.entry(&self.attr_ttl(), &Self::file_attr(ino, &fi), 0);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        // Always go through file_info_for_ino: with a write overlay it re-lookups
        // so create (size 0) → write → stat/ls sees the real size.
        let Some(fi) = self.file_info_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        reply.attr(&self.attr_ttl(), &Self::file_attr(ino, &fi));
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
        for (name, mode, _size) in entries {
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
        // Cheap list_mode only — do not call MountSource::list (fat FileInfo map).
        // Full attrs (size/mtime/uid) are filled at getattr/lookup/open.
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        let Some(entries) = self.list_mode_cached(&path) else {
            reply.error(ENOENT);
            return;
        };
        let self_fi = self
            .cached_fi(ino)
            .or_else(|| self.source.lookup(&path, 0))
            .unwrap_or_else(ratarmount_core::create_root_file_info);
        let mut full: Vec<(u64, String, FileAttr)> = Vec::with_capacity(entries.len() + 2);
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
        for (name, mode, size) in entries {
            let child = join_path(&path, &name);
            let fi = FileInfo {
                size,
                mtime: self_fi.mtime,
                mode,
                linkname: String::new(),
                uid: self_fi.uid,
                gid: self_fi.gid,
                userdata: vec![],
            };
            let cino = self.ino_for_path(&child);
            full.push((cino, name, Self::file_attr(cino, &fi)));
        }
        for (i, (cino, name, attr)) in full.into_iter().enumerate().skip(offset as usize) {
            let entry_ttl = self.readdirplus_entry_ttl(&attr);
            if reply.add(cino, (i + 1) as i64, name, &entry_ttl, &attr, 0) {
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
        // Writes always go to the overlay; reads of files that exist in the overlay
        // must also use the overlay FD (not the base archive). Previously RO open
        // used a cached size-0 FileInfo → Empty backend, so write-then-cat returned "".
        if let Some(ov) = &self.overlay {
            if write || ov.has_file(&path) {
                match ov.open_overlay_fd(&path, flags) {
                    Ok(fd) => {
                        if let Some(fi) = self.source.lookup(&path, 0) {
                            self.store_fi(ino, fi);
                        }
                        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                        self.handles
                            .lock()
                            .unwrap()
                            .insert(fh, OpenBackend::OverlayFd(fd));
                        // Do not KEEP_CACHE: size changes after write.
                        reply.opened(fh, 0);
                        return;
                    }
                    Err(e) => {
                        if write {
                            debug!("overlay open: {e}");
                            reply.error(EIO);
                            return;
                        }
                        // RO open of non-overlay path: fall through to base source.
                        debug!("overlay open (read fallthrough): {e}");
                    }
                }
            }
        } else if write {
            reply.error(EROFS);
            return;
        }

        let Some(fi) = self.file_info_for_open(ino, &path) else {
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
                        state: Arc::new(Mutex::new(SourceReadState {
                            reader,
                            readahead: ReadaheadState::default(),
                        })),
                    },
                );
                // Allow kernel page cache of archive member data.
                reply.opened(fh, fuser::consts::FOPEN_KEEP_CACHE);
            }
            Err(e) => {
                debug!("open error path={path} kind={:?}: {e}", e.kind());
                reply.error(io_to_errno(&e));
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
        // Resolve backend under the map lock, then drop it before I/O so a large
        // readahead fill does not stall every other FUSE op on this process.
        enum ReadTarget {
            Empty,
            OverlayFd(i32),
            Source {
                path: String,
                state: Arc<Mutex<SourceReadState>>,
            },
        }
        let target = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh) {
                None => {
                    reply.error(ENOENT);
                    return;
                }
                Some(OpenBackend::Empty) => ReadTarget::Empty,
                Some(OpenBackend::OverlayFd(fd)) => ReadTarget::OverlayFd(*fd),
                Some(OpenBackend::Source { path, state, .. }) => ReadTarget::Source {
                    path: path.clone(),
                    state: Arc::clone(state),
                },
            }
        };
        match target {
            ReadTarget::Empty => {
                reply.data(&[]);
            }
            ReadTarget::OverlayFd(fd) => {
                let mut buf = vec![0u8; size as usize];
                let n = unsafe {
                    libc::pread(fd, buf.as_mut_ptr() as *mut _, size as usize, offset.max(0))
                };
                if n < 0 {
                    reply.error(EIO);
                } else {
                    buf.truncate(n as usize);
                    reply.data(&buf);
                }
            }
            ReadTarget::Source { path, state } => {
                let mut g = state.lock().unwrap();
                let SourceReadState { reader, readahead } = &mut *g;
                let off = offset.max(0) as u64;
                match readahead_fill(
                    reader.as_mut(),
                    readahead,
                    self.readahead_bytes,
                    off,
                    size as usize,
                ) {
                    Ok(buf) => reply.data(&buf),
                    Err(e) => {
                        debug!(
                            "read error path={path} offset={offset} size={size} kind={:?}: {e}",
                            e.kind()
                        );
                        reply.error(io_to_errno(&e));
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
                let fi = self.source.lookup(&path, 0).unwrap_or_else(|| FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: mode | ratarmount_core::S_IFREG,
                    linkname: String::new(),
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    userdata: vec![],
                });
                let ino = self.ino_for_path_with_fi(&path, Some(fi.clone()));
                self.invalidate_dir_cache(&parent_path);
                let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                self.handles
                    .lock()
                    .unwrap()
                    .insert(fh, OpenBackend::OverlayFd(fd));
                reply.created(&self.attr_ttl(), &Self::file_attr(ino, &fi), 0, fh, 0);
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
                let fi = self.source.lookup(&path, 0).unwrap_or_else(|| FileInfo {
                    size: 0,
                    mtime: 0.0,
                    mode: mode | ratarmount_core::S_IFDIR,
                    linkname: String::new(),
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    userdata: vec![],
                });
                let ino = self.ino_for_path_with_fi(&path, Some(fi.clone()));
                self.invalidate_dir_cache(&parent_path);
                reply.entry(&self.attr_ttl(), &Self::file_attr(ino, &fi), 0);
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
            Ok(()) => {
                self.invalidate_dir_cache(&parent_path);
                reply.ok();
            }
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
            Ok(()) => {
                self.invalidate_dir_cache(&parent_path);
                reply.ok();
            }
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
            .file_info_for_ino(ino)
            .or_else(|| self.source.lookup(&path, 0))
            .unwrap_or_else(ratarmount_core::create_root_file_info);
        reply.attr(&self.attr_ttl(), &Self::file_attr(ino, &fi));
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
        // Same cache/overlay policy as getattr — do not force a second source.lookup.
        let Some(fi) = self.file_info_for_ino(ino) else {
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
/// `readahead` is application-level sequential prefetch in bytes (`0` = off);
/// see [`RatarmountFs::with_readahead`] and CLI `--readahead` (upstream #180).
pub fn mount_blocking(
    source: Arc<dyn MountSource>,
    mountpoint: impl AsRef<Path>,
    foreground: bool,
    writable: bool,
    overlay: Option<Arc<WriteOverlay>>,
    extra_fuse_opts: &str,
    readahead: u64,
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
    let fs = RatarmountFs::with_readahead(source, overlay, readahead);
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
    use ratarmount_core::{ListModeResult, ListResult, MountSource, S_IFLNK, S_IFMT, S_IFREG};
    use std::collections::BTreeMap;
    use std::io::{self, Seek};

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

    /// Regression: encrypted nested 7z without password must surface as EACCES, not EIO.
    #[test]
    fn io_to_errno_maps_permission_denied_to_eacces() {
        assert_eq!(
            io_to_errno(&io::Error::new(
                ErrorKind::PermissionDenied,
                "need password"
            )),
            EACCES
        );
        assert_eq!(
            io_to_errno(&io::Error::new(ErrorKind::NotFound, "missing")),
            ENOENT
        );
        assert_eq!(
            io_to_errno(&io::Error::new(ErrorKind::IsADirectory, "dir")),
            EISDIR
        );
        assert_eq!(io_to_errno(&io::Error::other("generic")), EIO);
    }

    /// Reader that yields at most `chunk` bytes per `read` (mimics seekable gzip windows).
    struct ShortReadCursor {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl std::io::Read for ShortReadCursor {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            let n = (self.data.len() - self.pos)
                .min(buf.len())
                .min(self.chunk.max(1));
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn fill_read_for_fuse_assembles_short_codec_reads() {
        // Payload larger than one typical gzip inflate window so a single short
        // `Read::read` would under-fill a FUSE request (kernel treats that as EOF).
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut r = ShortReadCursor {
            data: payload.clone(),
            pos: 0,
            chunk: 64 * 1024 - 10, // ~65526 — same class of short read as inflate
        };
        let mut buf = vec![0u8; payload.len()];
        let n = fill_read_for_fuse(&mut r, &mut buf).expect("fill");
        assert_eq!(
            n,
            payload.len(),
            "must fill full FUSE request, not stop at first short read"
        );
        assert_eq!(buf, payload);
    }

    #[test]
    fn fill_read_for_fuse_true_eof_may_be_short() {
        let payload = b"hello-short-file";
        let mut r = ShortReadCursor {
            data: payload.to_vec(),
            pos: 0,
            chunk: 4,
        };
        let mut buf = vec![0u8; 64]; // request larger than file
        let n = fill_read_for_fuse(&mut r, &mut buf).expect("fill");
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload.as_slice());
    }

    /// Regression: bad archive mtimes (e.g. pre-fix 7z FILETIME) are ≤0 and must
    /// map to Unix epoch so tools do not panic; after the 7z fix they are positive.
    #[test]
    fn unix_float_to_system_time_non_positive_is_epoch() {
        assert_eq!(unix_float_to_system_time(0.0), UNIX_EPOCH);
        assert_eq!(unix_float_to_system_time(-1.0), UNIX_EPOCH);
        // Exact value seen from the wrong FILETIME delta (displayed as Dec 31 1969).
        assert_eq!(unix_float_to_system_time(-1_151_210_664_000.0), UNIX_EPOCH);
    }

    #[test]
    fn unix_float_to_system_time_positive_preserves_seconds() {
        let t = unix_float_to_system_time(1_592_222_400.0); // 2020-06-15 12:00 UTC
        let dur = t.duration_since(UNIX_EPOCH).expect("after epoch");
        assert_eq!(dur.as_secs(), 1_592_222_400);
    }

    /// Empty base archive for overlay unit tests (no members).
    struct EmptyBase;
    impl MountSource for EmptyBase {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                Some(ListResult::Infos(BTreeMap::new()))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(ratarmount_core::create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(ErrorKind::NotFound, "empty base"))
        }
        fn is_immutable(&self) -> bool {
            false
        }
    }

    /// Regression: with a write overlay, getattr/open must not keep create-time size 0
    /// from the inode cache (write-then-cat / stat returned empty size).
    #[test]
    fn overlay_file_info_for_ino_refreshes_size_after_write() {
        use ratarmount_compositing::WriteOverlay;
        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        // Create empty file (size 0) then write payload — same sequence as FUSE create+write.
        let fd = ov.create_file("/new.txt", 0o644).expect("create");
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        f.write_all(b"hello-overlay-payload").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        let stale = FileInfo {
            size: 0,
            mtime: 0.0,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![],
        };
        let ino = fs.ino_for_path_with_fi("/new.txt", Some(stale));
        // Without overlay re-lookup this would stay 0.
        let fi = fs.file_info_for_ino(ino).expect("fi");
        assert_eq!(
            fi.size,
            b"hello-overlay-payload".len() as u64,
            "overlay must re-lookup size after write (was create-time 0)"
        );
        // getattr path uses file_info_for_ino + file_attr (not cached_fi short-circuit).
        let attr = RatarmountFs::file_attr(ino, &fi);
        assert_eq!(
            attr.size,
            b"hello-overlay-payload".len() as u64,
            "getattr-equivalent attr must reflect post-write size"
        );
        assert_eq!(
            fs.attr_ttl(),
            OVERLAY_ATTR_TTL,
            "writable overlay must not pin long kernel attr TTL"
        );
        // After refresh, inode cache must hold the fresh size (not stuck at create-time 0).
        let cached = fs.cached_fi(ino).expect("cached after refresh");
        assert_eq!(cached.size, b"hello-overlay-payload".len() as u64);
        assert!(ov.has_file("/new.txt"));
        let rfd = ov
            .open_overlay_fd("/new.txt", libc::O_RDONLY)
            .expect("overlay open");
        let mut rf = unsafe { std::fs::File::from_raw_fd(rfd) };
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut rf, &mut buf).unwrap();
        assert_eq!(buf, b"hello-overlay-payload");
    }

    /// Regression: dir_cache 30s TTL must not hide overlay creates from readdir.
    /// Symptom: create file under parent, then ls misses the new name until TTL expires.
    #[test]
    fn overlay_create_invalidates_dir_cache_so_list_shows_new_name() {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );

        // Prime dir_cache for "/" while empty (same as first readdir).
        let before = fs.list_mode_cached("/").expect("list root");
        assert!(
            !before.iter().any(|(n, ..)| n == "created.txt"),
            "precondition: new name not listed yet"
        );
        assert!(
            fs.dir_cache.lock().unwrap().contains_key("/"),
            "dir_cache must be primed for the invalidation regression"
        );

        // Overlay create + the same invalidate_dir_cache(parent) create() performs.
        ov.create_file("/created.txt", 0o644).expect("create");
        // Without invalidation, list_mode_cached would keep serving the empty listing.
        fs.invalidate_dir_cache("/");
        let after = fs.list_mode_cached("/").expect("list after create");
        assert!(
            after.iter().any(|(n, ..)| n == "created.txt"),
            "after invalidate, readdir path must list the newly created name"
        );
    }

    /// Counting source: list() builds a fat FileInfo map; list_mode is cheap.
    struct ListCallTracker {
        list_calls: std::sync::atomic::AtomicUsize,
        list_mode_calls: std::sync::atomic::AtomicUsize,
        lookup_calls: std::sync::atomic::AtomicUsize,
        children: BTreeMap<String, FileInfo>,
    }

    impl ListCallTracker {
        fn new(children: BTreeMap<String, FileInfo>) -> Self {
            Self {
                list_calls: std::sync::atomic::AtomicUsize::new(0),
                list_mode_calls: std::sync::atomic::AtomicUsize::new(0),
                lookup_calls: std::sync::atomic::AtomicUsize::new(0),
                children,
            }
        }
    }

    impl MountSource for ListCallTracker {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.list_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if path == "/" {
                Some(ListResult::Infos(self.children.clone()))
            } else {
                None
            }
        }

        fn list_mode(&self, path: &str) -> Option<ListModeResult> {
            self.list_mode_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if path == "/" {
                Some(ListModeResult::Modes(
                    self.children
                        .iter()
                        .map(|(n, fi)| (n.clone(), fi.mode))
                        .collect(),
                ))
            } else {
                None
            }
        }

        fn list_dirents(&self, path: &str) -> Option<Vec<ratarmount_core::CheapDirent>> {
            // Default would call list_mode; implement directly so sizes stream
            // from the cheap path (same data as children, no FileInfo map).
            if path != "/" {
                return None;
            }
            self.list_mode_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(
                self.children
                    .iter()
                    .map(|(n, fi)| ratarmount_core::CheapDirent {
                        name: n.clone(),
                        mode: fi.mode,
                        size: fi.size,
                    })
                    .collect(),
            )
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            self.lookup_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if path == "/" {
                return Some(ratarmount_core::create_root_file_info());
            }
            let name = path.strip_prefix('/').unwrap_or(path);
            self.children.get(name).cloned()
        }

        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(ErrorKind::NotFound, "tracker"))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: readdir / readdirplus must not build a fat FileInfo map via list().
    #[test]
    fn readdir_path_does_not_call_fat_list() {
        let mut children = BTreeMap::new();
        for i in 0..64 {
            children.insert(
                format!("f{i:02}.txt"),
                FileInfo {
                    size: 100 + i,
                    mtime: 1.0,
                    mode: S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                },
            );
        }
        let src = Arc::new(ListCallTracker::new(children.clone()));
        let fs = RatarmountFs::new(Arc::clone(&src) as Arc<dyn MountSource>, None);

        let entries = fs.readdir_dirents("/").expect("cheap readdir listing");
        assert_eq!(entries.len(), children.len());
        for (name, mode, size) in &entries {
            let fi = children.get(name).expect("name from cheap listing");
            assert_eq!(*mode, fi.mode);
            assert_eq!(*size, fi.size);
        }
        assert_eq!(
            src.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "readdir path must not call MountSource::list (fat FileInfo map)"
        );
        assert!(
            src.list_mode_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 1,
            "readdir path must use list_mode"
        );

        // getattr/open still materialize FileInfo via lookup, not list().
        let fi = fs
            .source
            .lookup("/f00.txt", 0)
            .expect("lookup fat FileInfo at getattr boundary");
        assert_eq!(fi.size, 100);
        assert_eq!(
            src.list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "lookup/getattr must not go through list()"
        );
        let attr_for = |mode: u32, size: u64| {
            RatarmountFs::file_attr(
                2,
                &FileInfo {
                    size,
                    mtime: 1.0,
                    mode,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                },
            )
        };
        assert_eq!(
            fs.readdirplus_entry_ttl(&attr_for(S_IFREG, 5)),
            TTL,
            "nonzero dirent sizes must use kernel attr TTL so cat after find is cached"
        );
        assert_eq!(
            fs.readdirplus_entry_ttl(&attr_for(ratarmount_core::S_IFDIR, 0)),
            TTL,
            "directory dirents keep the TTL (size is not load-bearing for dirs)"
        );
        assert_eq!(
            fs.readdirplus_entry_ttl(&attr_for(S_IFREG, 0)),
            Duration::ZERO,
            "zero-size non-dir dirents may be placeholders and must revalidate"
        );
    }

    /// Regression: mixed listing with a placeholder size-0 file (control
    /// `status` next to real-size `pid`/`help`) — the placeholder must not
    /// inherit the 60s TTL from siblings, or `cat` would read EOF from a
    /// kernel-cached i_size of 0 for a non-empty virtual file.
    #[test]
    fn readdirplus_placeholder_zero_size_not_cached_beside_real_sizes() {
        let mut children = BTreeMap::new();
        children.insert(
            "status".into(),
            FileInfo {
                size: 0,
                mtime: 1.0,
                mode: S_IFREG | 0o444,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            },
        );
        children.insert(
            "pid".into(),
            FileInfo {
                size: 7,
                mtime: 1.0,
                mode: S_IFREG | 0o444,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            },
        );
        let src = Arc::new(ListCallTracker::new(children));
        let fs = RatarmountFs::new(Arc::clone(&src) as Arc<dyn MountSource>, None);
        let zero_attr = RatarmountFs::file_attr(
            2,
            &FileInfo {
                size: 0,
                mtime: 1.0,
                mode: S_IFREG | 0o444,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            },
        );
        let real_attr = RatarmountFs::file_attr(
            3,
            &FileInfo {
                size: 7,
                mtime: 1.0,
                mode: S_IFREG | 0o444,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            },
        );
        assert_eq!(
            fs.readdirplus_entry_ttl(&zero_attr),
            Duration::ZERO,
            "placeholder size-0 dirent must revalidate even beside real sizes"
        );
        assert_eq!(
            fs.readdirplus_entry_ttl(&real_attr),
            TTL,
            "real sizes stay kernel-cached"
        );
    }

    /// Regression: readlink after lookup incremented lookup_calls.
    #[test]
    fn readlink_uses_cached_file_info_without_second_lookup() {
        let mut children = BTreeMap::new();
        children.insert(
            "link".into(),
            FileInfo {
                size: 6,
                mtime: 1.0,
                mode: S_IFLNK | 0o777,
                linkname: "target".into(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            },
        );
        let fi = children.get("link").cloned().expect("link FileInfo");
        let src = Arc::new(ListCallTracker::new(children));
        let fs = RatarmountFs::new(Arc::clone(&src) as Arc<dyn MountSource>, None);
        let ino = fs.ino_for_path_with_fi("/link", Some(fi));
        let before = src.lookup_calls.load(std::sync::atomic::Ordering::SeqCst);
        let target = fs.readlink_target(ino).expect("readlink");
        assert_eq!(target, "target");
        assert_eq!(
            src.lookup_calls.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "readlink must reuse inode-cached FileInfo (no second lookup)"
        );
    }

    /// Regression: after `readdir_dirents`, `lookup` mode disagrees with the cheap
    /// dirent on the successful-resolve FR-10 path (type flip under 60s TTL).
    /// Cycle/hop-limit names are a pre-existing list()/lookup split — not asserted.
    #[test]
    fn readdirplus_dirent_type_matches_lookup() {
        use ratarmount_compositing::{FolderMountSource, UnionMountOptions, UnionMountSource};

        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("target.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("target.txt", a.join("link.txt")).unwrap();
        std::fs::write(b.join("other.txt"), b"from-b").unwrap();

        let sa = Arc::new(FolderMountSource::new(&a).unwrap()) as Arc<dyn MountSource>;
        let sb = Arc::new(FolderMountSource::new(&b).unwrap()) as Arc<dyn MountSource>;

        // FR-10 on: list_dirents type must match lookup (S_IFREG after resolve).
        let u_on = Arc::new(UnionMountSource::new_with_options(
            vec![sa.clone(), sb.clone()],
            UnionMountOptions {
                resolve_symlinks: true,
                ..Default::default()
            },
        ));
        let fs_on = RatarmountFs::new(Arc::clone(&u_on) as Arc<dyn MountSource>, None);
        let dents_on = fs_on.readdir_dirents("/").expect("readdir FR-10");
        let link_on = dents_on
            .iter()
            .find(|(n, ..)| n == "link.txt")
            .expect("link.txt dirent");
        assert_eq!(
            link_on.1 & S_IFMT,
            S_IFREG,
            "FR-10 readdirplus must advertise resolved file, not symlink"
        );
        let fi_on = fs_on.source.lookup("/link.txt", 0).expect("lookup FR-10");
        assert_eq!(
            fi_on.mode & S_IFMT,
            S_IFREG,
            "FR-10 lookup must return the target file"
        );
        assert_eq!(
            link_on.1 & S_IFMT,
            fi_on.mode & S_IFMT,
            "cheap dirent type must match lookup after FR-10 resolve"
        );

        // Default off: dirent stays symlink and lookup is symlink.
        let u_off = Arc::new(UnionMountSource::new(vec![sa, sb]));
        let fs_off = RatarmountFs::new(Arc::clone(&u_off) as Arc<dyn MountSource>, None);
        let dents_off = fs_off.readdir_dirents("/").expect("readdir default");
        let link_off = dents_off
            .iter()
            .find(|(n, ..)| n == "link.txt")
            .expect("link.txt dirent default");
        assert_eq!(
            link_off.1 & S_IFMT,
            S_IFLNK,
            "default union must keep symlink in readdir"
        );
        let fi_off = fs_off
            .source
            .lookup("/link.txt", 0)
            .expect("lookup default");
        assert_eq!(fi_off.mode & S_IFMT, S_IFLNK);
        assert_eq!(link_off.1 & S_IFMT, fi_off.mode & S_IFMT);
    }

    /// Regression: immutable open must reuse getattr/lookup FileInfo (no second lookup).
    #[test]
    fn immutable_open_reuses_cached_file_info() {
        let mut children = BTreeMap::new();
        children.insert(
            "a.bin".into(),
            FileInfo {
                size: 64,
                mtime: 1.0,
                mode: S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![],
            },
        );
        let src = Arc::new(ListCallTracker::new(children));
        let fs = RatarmountFs::new(Arc::clone(&src) as Arc<dyn MountSource>, None);
        let fi = fs.source.lookup("/a.bin", 0).expect("lookup");
        let ino = fs.ino_for_path_with_fi("/a.bin", Some(fi));
        let before = src.lookup_calls.load(std::sync::atomic::Ordering::SeqCst);
        let again = fs.file_info_for_open(ino, "/a.bin").expect("cached open");
        assert_eq!(again.size, 64);
        assert_eq!(
            src.lookup_calls.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "immutable open must not re-lookup when inode already has FileInfo"
        );
    }

    /// Regression: unlink must drop parent dir_cache so readdir does not ghost-delete.
    #[test]
    fn overlay_unlink_invalidates_dir_cache_so_list_drops_name() {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );

        ov.create_file("/gone.txt", 0o644).expect("create");
        let listed = fs.list_mode_cached("/").expect("list with file");
        assert!(listed.iter().any(|(n, ..)| n == "gone.txt"));

        ov.unlink("/gone.txt").expect("unlink");
        fs.invalidate_dir_cache("/");
        let after = fs.list_mode_cached("/").expect("list after unlink");
        assert!(
            !after.iter().any(|(n, ..)| n == "gone.txt"),
            "after invalidate, readdir path must not ghost the deleted name"
        );
    }

    /// ino_for_path_with_fi must overwrite stale size-0 FileInfo when lookup provides fresher.
    #[test]
    fn ino_for_path_with_fi_updates_stale_cached_size() {
        let src = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let fs = RatarmountFs::new(src, None);
        let stale = FileInfo {
            size: 0,
            mtime: 0.0,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![],
        };
        let ino = fs.ino_for_path_with_fi("/f", Some(stale));
        assert_eq!(fs.cached_fi(ino).unwrap().size, 0);
        let fresh = FileInfo {
            size: 42,
            mtime: 1.0,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![],
        };
        let ino2 = fs.ino_for_path_with_fi("/f", Some(fresh));
        assert_eq!(ino, ino2);
        assert_eq!(
            fs.cached_fi(ino).unwrap().size,
            42,
            "must replace create-time size 0 with fresher FileInfo"
        );
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

    #[test]
    fn parse_byte_size_plain_and_suffixes() {
        assert_eq!(parse_byte_size("0").unwrap(), 0);
        assert_eq!(parse_byte_size("4096").unwrap(), 4096);
        assert_eq!(parse_byte_size("256K").unwrap(), 256 * 1024);
        assert_eq!(parse_byte_size("1m").unwrap(), 1024 * 1024);
        assert_eq!(parse_byte_size("2MiB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_byte_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("xyz").is_err());
    }

    #[test]
    fn clamp_readahead_caps_at_max() {
        assert_eq!(clamp_readahead(0), 0);
        assert_eq!(clamp_readahead(1024), 1024);
        assert_eq!(
            clamp_readahead(MAX_READAHEAD_BYTES + 1),
            MAX_READAHEAD_BYTES
        );
    }

    /// Seekable in-memory member used to unit-test `readahead_fill`.
    ///
    /// When `max_read_chunk > 0`, each `Read::read` returns at most that many
    /// bytes (mimics rapidgzip / inflate window short returns).
    struct SpyReader {
        data: Vec<u8>,
        pos: u64,
        seeks: u32,
        /// Sum of successful `read` byte counts (proxy for underlying fills).
        bytes_read: usize,
        /// Number of `Read::read` calls (including EOF zeros).
        read_calls: u32,
        /// Cap per `read` when non-zero (short-read codec simulation).
        max_read_chunk: usize,
    }

    impl SpyReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                pos: 0,
                seeks: 0,
                bytes_read: 0,
                read_calls: 0,
                max_read_chunk: 0,
            }
        }

        fn with_short_reads(data: Vec<u8>, max_read_chunk: usize) -> Self {
            let mut s = Self::new(data);
            s.max_read_chunk = max_read_chunk;
            s
        }
    }

    impl std::io::Read for SpyReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_calls += 1;
            let pos = self.pos as usize;
            if pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            let mut n = (self.data.len() - pos).min(buf.len());
            if self.max_read_chunk > 0 {
                n = n.min(self.max_read_chunk);
            }
            buf[..n].copy_from_slice(&self.data[pos..pos + n]);
            self.pos += n as u64;
            self.bytes_read += n;
            Ok(n)
        }
    }

    impl Seek for SpyReader {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            self.seeks += 1;
            let new = match pos {
                io::SeekFrom::Start(o) => o as i64,
                io::SeekFrom::End(o) => self.data.len() as i64 + o,
                io::SeekFrom::Current(o) => self.pos as i64 + o,
            };
            if new < 0 {
                return Err(io::Error::new(ErrorKind::InvalidInput, "seek before 0"));
            }
            self.pos = new as u64;
            Ok(self.pos)
        }
    }

    /// Regression: sequential small FUSE reads with readahead should pull a large
    /// window once, then serve later reads from the window (no extra seeks/reads).
    #[test]
    fn readahead_sequential_small_reads_hit_window() {
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut spy = SpyReader::new(payload.clone());
        let mut state = ReadaheadState::default();
        let readahead = 4096usize;
        let chunk = 512usize;

        for i in 0..8 {
            let off = (i * chunk) as u64;
            let got = readahead_fill(&mut spy, &mut state, readahead, off, chunk).expect("read");
            assert_eq!(got, payload[off as usize..off as usize + chunk]);
        }
        // One seek + one fill of 4096 for the first miss; next 7 chunks hit window.
        assert_eq!(spy.seeks, 1, "sequential hits must not re-seek the member");
        assert_eq!(
            spy.bytes_read, readahead,
            "one readahead-sized underlying fill expected"
        );
        assert_eq!(
            spy.pos, readahead as u64,
            "cursor should rest at end of first window after fill"
        );
        // Mid-window re-read (not only forward) still hits.
        let seeks_before = spy.seeks;
        let got = readahead_fill(&mut spy, &mut state, readahead, 0, chunk).expect("rewind hit");
        assert_eq!(got, payload[..chunk]);
        assert_eq!(spy.seeks, seeks_before, "in-window re-read must not seek");

        // Random seek outside window must refill (exact size only — not full window).
        let off = 8000u64;
        let bytes_before = spy.bytes_read;
        let got = readahead_fill(&mut spy, &mut state, readahead, off, chunk).expect("seek read");
        assert_eq!(got, payload[off as usize..off as usize + chunk]);
        assert!(spy.seeks >= 2, "miss outside window must seek again");
        assert_eq!(
            spy.bytes_read - bytes_before,
            chunk,
            "random miss must not storm with full readahead fill"
        );
    }

    #[test]
    fn readahead_disabled_reads_exact_size_only() {
        let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let mut spy = SpyReader::new(payload.clone());
        let mut state = ReadaheadState::default();
        let got = readahead_fill(&mut spy, &mut state, 0, 100, 64).expect("read");
        assert_eq!(got, payload[100..164]);
        assert!(
            state.window.is_none(),
            "readahead 0 must not retain a window"
        );
        assert_eq!(spy.pos, 164);
        assert_eq!(spy.bytes_read, 64);
    }

    #[test]
    fn readahead_eof_short_read() {
        let payload = b"short-file-payload".to_vec();
        let mut spy = SpyReader::new(payload.clone());
        let mut state = ReadaheadState::default();
        let got = readahead_fill(&mut spy, &mut state, 1024, 0, 64).expect("read");
        assert_eq!(got, payload);
        let seeks_after_first = spy.seeks;
        // Second read past EOF is empty without another underlying seek.
        let got2 =
            readahead_fill(&mut spy, &mut state, 1024, payload.len() as u64, 16).expect("eof");
        assert!(got2.is_empty());
        assert_eq!(
            spy.seeks, seeks_after_first,
            "post-EOF must serve empty from hit_eof window"
        );
    }

    /// Partial serve near true EOF when request size exceeds remaining bytes.
    #[test]
    fn readahead_partial_eof_from_window() {
        let payload: Vec<u8> = (0..100u8).collect();
        let mut spy = SpyReader::new(payload.clone());
        let mut state = ReadaheadState::default();
        let _ = readahead_fill(&mut spy, &mut state, 256, 0, 10).expect("prime");
        let seeks = spy.seeks;
        let got = readahead_fill(&mut spy, &mut state, 256, 80, 50).expect("partial");
        assert_eq!(got, payload[80..]);
        assert_eq!(spy.seeks, seeks, "partial EOF must hit window");
    }

    /// Request that straddles the end of a non-EOF window must refill (not short-read).
    #[test]
    fn readahead_straddle_non_eof_window_refills() {
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut spy = SpyReader::new(payload.clone());
        let mut state = ReadaheadState::default();
        let _ = readahead_fill(&mut spy, &mut state, 1000, 0, 100).expect("prime");
        assert!(!state.window.as_ref().unwrap().hit_eof);
        let seeks = spy.seeks;
        let got = readahead_fill(&mut spy, &mut state, 1000, 900, 200).expect("straddle");
        assert_eq!(got, payload[900..1100]);
        assert!(
            spy.seeks > seeks,
            "straddle of non-EOF window must refill, not return false short read"
        );
    }

    /// Regression: sequential cat over a short-read source (gzip/rapidgzip-style
    /// ~64 KiB windows) must assemble correct bytes and amortize fills via the
    /// readahead window — not stop at the first short `Read::read`.
    #[test]
    fn readahead_sequential_cat_short_read_source_correct() {
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        // ~inflate window class used by seekable gzip / rapidgzip IndexedReader.
        let window_chunk = 64 * 1024 - 10;
        let mut spy = SpyReader::with_short_reads(payload.clone(), window_chunk);
        let mut state = ReadaheadState::default();
        let readahead = RECOMMENDED_READAHEAD_BYTES as usize; // 1 MiB
        let fuse_chunk = 128 * 1024usize; // typical kernel FUSE read size
        let mut out = Vec::with_capacity(payload.len());
        let mut off = 0u64;
        while (off as usize) < payload.len() {
            let want = fuse_chunk.min(payload.len() - off as usize);
            let got = readahead_fill(&mut spy, &mut state, readahead, off, want).expect("cat");
            assert!(
                !got.is_empty() || want == 0,
                "false EOF at off={off} want={want}"
            );
            out.extend_from_slice(&got);
            off += got.len() as u64;
        }
        assert_eq!(out, payload, "sequential cat must match full member");
        // First fill is 1 MiB; subsequent sequential past-window fills continue
        // without seeking when cursor is already at window end.
        assert!(
            spy.seeks <= 1 + (payload.len() / readahead) as u32,
            "sequential short-read cat must not seek every FUSE chunk (seeks={})",
            spy.seeks
        );
        // fill_read_for_fuse must have issued multiple short reads for the 1 MiB fill.
        assert!(
            spy.read_calls > (payload.len() / window_chunk) as u32 / 2,
            "short-read codec should require many underlying read calls (got {})",
            spy.read_calls
        );
    }

    /// Regression: random seeks must not readahead-storm (each miss fills only
    /// the request size, not the full sequential window).
    #[test]
    fn readahead_random_seeks_no_storm() {
        let payload: Vec<u8> = (0..64_000u32).map(|i| (i % 251) as u8).collect();
        let mut spy = SpyReader::new(payload.clone());
        let mut state = ReadaheadState::default();
        let readahead = 16 * 1024usize;
        let chunk = 512usize;
        // Prime sequential window.
        let _ = readahead_fill(&mut spy, &mut state, readahead, 0, chunk).expect("prime");
        assert_eq!(spy.bytes_read, readahead);

        let random_offs = [50_000u64, 1_000, 40_000, 20_000, 55_000];
        let bytes_before = spy.bytes_read;
        let seeks_before = spy.seeks;
        for &off in &random_offs {
            let got = readahead_fill(&mut spy, &mut state, readahead, off, chunk).expect("rand");
            assert_eq!(got, payload[off as usize..off as usize + chunk]);
        }
        let bytes_random = spy.bytes_read - bytes_before;
        let seeks_random = spy.seeks - seeks_before;
        assert_eq!(
            seeks_random,
            random_offs.len() as u32,
            "each random miss must seek once"
        );
        assert_eq!(
            bytes_random,
            chunk * random_offs.len(),
            "random misses must pull exact size only (no {readahead}-byte storm); got {bytes_random}"
        );
    }

    /// Regression: after a random miss, sequential continuation from that point
    /// re-enables the large readahead window (cat after sparse seeks).
    #[test]
    fn readahead_sequential_after_random_uses_large_window() {
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let mut spy = SpyReader::new(payload.clone());
        let mut state = ReadaheadState::default();
        let readahead = 4096usize;
        let chunk = 256usize;

        // First miss is always a large sequential prime (typical open+cat).
        let _ = readahead_fill(&mut spy, &mut state, readahead, 0, chunk).expect("prime");
        assert_eq!(spy.bytes_read, readahead);

        // Random jump mid-file (exact fill only — no storm).
        let start = 10_000u64;
        let bytes_before_rand = spy.bytes_read;
        let got = readahead_fill(&mut spy, &mut state, readahead, start, chunk).expect("random");
        assert_eq!(got, payload[start as usize..start as usize + chunk]);
        assert_eq!(
            spy.bytes_read - bytes_before_rand,
            chunk,
            "random miss after prime must be exact-size only"
        );

        // Next contiguous read is sequential → full readahead from that offset.
        let bytes_before = spy.bytes_read;
        let off = start + chunk as u64;
        let got = readahead_fill(&mut spy, &mut state, readahead, off, chunk).expect("seq");
        assert_eq!(got, payload[off as usize..off as usize + chunk]);
        assert_eq!(
            spy.bytes_read - bytes_before,
            readahead,
            "sequential after random must fill full readahead window"
        );
    }

    /// Regression: walking past the end of a sequential window must not re-seek
    /// when the underlying cursor already sits at that offset (short-read coop).
    #[test]
    fn readahead_sequential_past_window_skips_redundant_seek() {
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut spy = SpyReader::new(payload.clone());
        let mut state = ReadaheadState::default();
        let readahead = 1024usize;
        let chunk = 256usize;

        // Drain first window via hits.
        for i in 0..(readahead / chunk) {
            let off = (i * chunk) as u64;
            let got = readahead_fill(&mut spy, &mut state, readahead, off, chunk).expect("hit");
            assert_eq!(got.len(), chunk);
        }
        assert_eq!(spy.seeks, 1);
        assert_eq!(spy.pos, readahead as u64);

        // Next offset == window end; cursor already there → no seek.
        let off = readahead as u64;
        let got = readahead_fill(&mut spy, &mut state, readahead, off, chunk).expect("continue");
        assert_eq!(got, payload[off as usize..off as usize + chunk]);
        assert_eq!(
            spy.seeks, 1,
            "sequential past window end must skip redundant Seek"
        );
        assert_eq!(spy.bytes_read, readahead * 2);
    }

    #[test]
    fn with_readahead_clamps_and_stores() {
        let src = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let fs = RatarmountFs::with_readahead(src, None, MAX_READAHEAD_BYTES * 2);
        assert_eq!(
            fs.readahead_bytes, MAX_READAHEAD_BYTES as usize,
            "constructor must clamp oversized readahead"
        );
        let fs2 = RatarmountFs::with_readahead(
            Arc::new(EmptyBase) as Arc<dyn MountSource>,
            None,
            RECOMMENDED_READAHEAD_BYTES,
        );
        assert_eq!(
            fs2.readahead_bytes, RECOMMENDED_READAHEAD_BYTES as usize,
            "recommended 1 MiB must store unchanged"
        );
    }

    #[test]
    fn recommended_readahead_within_cap() {
        const {
            assert!(RECOMMENDED_READAHEAD_BYTES > 0);
            assert!(RECOMMENDED_READAHEAD_BYTES <= MAX_READAHEAD_BYTES);
        }
        assert_eq!(
            clamp_readahead(RECOMMENDED_READAHEAD_BYTES),
            RECOMMENDED_READAHEAD_BYTES
        );
    }
}
