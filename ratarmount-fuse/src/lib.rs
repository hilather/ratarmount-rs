//! FUSE mount using `fuser` low-level API (read + optional write overlay).

#[cfg(test)]
mod fuser_tests;

mod passthrough;
pub use passthrough::{PassthroughMode, PassthroughOptions};
use ratarmount_compositing::{overlay_atime, OverlayMetadata};
use ratarmount_core::AttributeMapping;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite,
    ReplyXattr, Request, SessionACL, WriteFlags,
};
use libc::{EACCES, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, EROFS};
use log::{debug, info, warn};
use ratarmount_compositing::{Parked, WriteOverlay};
use ratarmount_core::{CheapDirent, FileInfo, InodeAttrCookie, MountSource};
use std::io::ErrorKind;

const FUSE_ROOT_ID: u64 = INodeNo::ROOT.0;

/// Kernel attribute/entry cache TTL for immutable attrs (read-only mounts and
/// archive members that the write overlay has not shadowed).
const TTL: Duration = Duration::from_secs(60);
/// Overlay-backed files and create placeholders change size after write.
/// A non-zero kernel TTL would keep serving create-time size 0.
const OVERLAY_ATTR_TTL: Duration = Duration::from_secs(0);
const BLKSIZE: u32 = 256 * 1024;
const DIR_CACHE_TTL: Duration = Duration::from_secs(30);

/// Errno for a failed overlay operation: an `OverlayError::Io` keeps its kind
/// (EACCES for a refused bookkeeping name), anything else is EIO.
fn overlay_errno(err: &ratarmount_compositing::OverlayError) -> i32 {
    match err {
        ratarmount_compositing::OverlayError::Io(e) => io_to_errno(e),
        _ => EIO,
    }
}

fn metadata_errno(err: &ratarmount_compositing::OverlayError) -> i32 {
    match err {
        ratarmount_compositing::OverlayError::Io(e) => {
            e.raw_os_error().unwrap_or_else(|| io_to_errno(e))
        }
        _ => EIO,
    }
}

/// Map `std::io::Error` to a FUSE/libc errno.
///
/// Password / permission failures must not collapse to generic EIO — that is what
/// users see as "Input/output error" when opening encrypted nested 7z without
/// `--password`.
///
/// Unmapped raw OS errors pass through, including `EMFILE` and `ENFILE`.
/// Unknown kind-only errors map to `EIO`.
fn io_to_errno(err: &std::io::Error) -> i32 {
    // Rust does not classify both Darwin unsupported-operation errnos as Unsupported.
    // A predicate also handles platforms where these constants are aliases.
    if err
        .raw_os_error()
        .is_some_and(|raw| raw == libc::ENOTSUP || raw == libc::EOPNOTSUPP)
    {
        return ENOSYS;
    }
    match err.kind() {
        ErrorKind::ReadOnlyFilesystem => libc::EROFS,
        ErrorKind::QuotaExceeded => libc::EDQUOT,
        ErrorKind::StorageFull => libc::ENOSPC,
        ErrorKind::NotFound => ENOENT,
        ErrorKind::PermissionDenied => EACCES,
        ErrorKind::IsADirectory => EISDIR,
        ErrorKind::AlreadyExists => EEXIST,
        ErrorKind::InvalidInput => EINVAL,
        ErrorKind::Unsupported => ENOSYS,
        _ => err.raw_os_error().unwrap_or(EIO),
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
#[derive(Debug, Default)]
struct ReadAheadWindow {
    /// Absolute file offset of `data[0]`.
    start: u64,
    data: Vec<u8>,
    /// Last fill was short ⇒ true EOF at `start + data.len()`.
    hit_eof: bool,
    _memory: Option<ratarmount_core::budget::Reservation>,
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
#[derive(Default)]
struct ReadaheadState {
    window: Arc<Mutex<Option<ReadAheadWindow>>>,
    memory_hook: Option<ratarmount_core::budget::PressureHook>,
    /// Known absolute position of the underlying reader after last seek/fill.
    cursor: Option<u64>,
    /// End offset of the last FUSE response (`offset + returned len`).
    last_end: Option<u64>,
}

impl ReadaheadState {
    fn clear(&mut self) {
        *self.window.lock().unwrap() = None;
        self.cursor = None;
        self.last_end = None;
    }

    /// True when a miss should pull a full readahead window (not exact size).
    fn is_sequential_miss(&self, offset: u64) -> bool {
        if self.window.lock().unwrap().is_none() && self.last_end.is_none() {
            // First fill on this open: prime a large window (typical `cat`).
            return true;
        }
        if self.last_end == Some(offset) {
            return true;
        }
        if let Some(w) = self.window.lock().unwrap().as_ref() {
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

    let window = state.window.lock().unwrap();
    if let Some(w) = window.as_ref() {
        if let Some(out) = w.try_serve(offset, size) {
            state.last_end = Some(offset.saturating_add(out.len() as u64));
            return Ok(out);
        }
        // Growing kernel requests may straddle a sequential window. Preserve
        // its tail and continue at the underlying cursor instead of seeking
        // backward, which would cancel the codec's in-flight decode-ahead.
        let end = w.end_offset();
        if state.last_end == Some(offset) && offset >= w.start && offset < end {
            let mut out = w.data[(offset - w.start) as usize..].to_vec();
            state.last_end = Some(end);
            drop(window);
            out.extend(readahead_fill(
                reader,
                state,
                readahead_bytes,
                end,
                size - out.len(),
            )?);
            return Ok(out);
        }
    }

    drop(window);
    let sequential = state.is_sequential_miss(offset);
    let want = if sequential {
        size.max(readahead_bytes)
    } else {
        // Random seek: exact request only — avoid multi‑MiB readahead storm.
        size
    };

    // Skip seek when the prior fill left the cursor at this offset (sequential
    // walk past the window end). Random misses still seek.
    if state.cursor != Some(offset) {
        reader.seek(std::io::SeekFrom::Start(offset))?;
        state.cursor = Some(offset);
    }

    let pool = ratarmount_core::budget::MemoryPool::global(
        "fuse-readahead",
        MAX_READAHEAD_BYTES,
        ratarmount_core::budget::Priority::Speculative,
    );
    if pool.enabled() {
        *state.window.lock().unwrap() = None;
    }
    if pool.enabled() && state.memory_hook.is_none() {
        let weak = Arc::downgrade(&state.window);
        state.memory_hook = Some(pool.on_pressure(move || {
            if let Some(window) = weak.upgrade() {
                if let Ok(mut window) = window.try_lock() {
                    *window = None;
                }
            }
        }));
    }
    let Some(memory) = pool.reserve(want as u64) else {
        return readahead_fill(reader, state, 0, offset, size);
    };
    let mut data = vec![0u8; want];
    let n = fill_read_for_fuse(reader, &mut data)?;
    data.truncate(n);
    state.cursor = Some(offset.saturating_add(n as u64));
    let hit_eof = n < want;
    let out_len = n.min(size);
    let out = data[..out_len].to_vec();
    state.last_end = Some(offset.saturating_add(out_len as u64));
    *state.window.lock().unwrap() = Some(ReadAheadWindow {
        _memory: Some(memory),
        start: offset,
        data,
        hit_eof,
    });
    Ok(out)
}

struct ArchiveAdvice {
    extent: ratarmount_core::BackingExtent,
    end: Option<u64>,
    progress: u64,
}

impl ArchiveAdvice {
    fn new(extent: ratarmount_core::BackingExtent) -> Self {
        Self {
            extent,
            end: None,
            progress: 0,
        }
    }

    fn consumed(&mut self, offset: u64, len: u64) {
        if self.end != Some(offset) {
            self.progress = 0;
        }
        let previous = self.progress;
        self.progress = self.progress.saturating_add(len);
        self.end = offset.checked_add(len);
        #[cfg(target_os = "linux")]
        {
            let fd = self.extent.file.as_raw_fd();
            if previous < 128 * 1024 && self.progress >= 128 * 1024 {
                // SAFETY: the extent owns this descriptor for the entire call.
                unsafe {
                    libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_SEQUENTIAL);
                }
            }
            let len = len.min(self.extent.len.saturating_sub(offset));
            if let Some(start) = self.extent.offset.checked_add(offset) {
                if let (Ok(start), Ok(len)) =
                    (libc::off_t::try_from(start), libc::off_t::try_from(len))
                {
                    if len != 0 {
                        // Never pass len=0 (which would advise the remainder of the archive).
                        unsafe {
                            libc::posix_fadvise(fd, start, len, libc::POSIX_FADV_DONTNEED);
                        }
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (previous, &self.extent);
    }
}

/// Per-open archive reader + optional sequential readahead state.
///
/// Held under its own `Mutex` (behind `Arc`) so FUSE `read` can release the
/// process-wide handle map while decompressing a large readahead fill.
struct SourceReadState {
    reader: Box<dyn ratarmount_core::ArchiveRead>,
    readahead: ReadaheadState,
    advice_extent: Option<ArchiveAdvice>,
}

enum OpenBackend {
    /// Keep the archive member reader open for the lifetime of the fh (critical for cat).
    Source {
        #[allow(dead_code)]
        path: String,
        #[allow(dead_code)]
        file_info: FileInfo,
        state: Arc<Mutex<SourceReadState>>,
        /// `MountSource::content_generation` when this reader was opened. A live
        /// overlay commit bumps the generation and shifts archive offsets, so a
        /// smaller value means this handle must re-lookup and reopen.
        opened_generation: u64,
        /// Opened from a detached archive inode, or marked at detach because this
        /// fh already referred to the name being replaced or unlinked.
        /// [`RatarmountFs::refresh_source_handle_if_stale`] leaves it alone.
        detached: bool,
    },
    /// Empty file — no underlying open.
    Empty,
    /// OS fd in write overlay
    OverlayFd(i32),
}

/// Host fd parked for a detached inode. Drop closes it and, in tests, counts
/// that close. The count is the oracle for "the parked fd was released": a raw
/// `F_GETFD` on the old number can succeed after the kernel reuses it.
struct ParkedFd {
    fd: OwnedFd,
    overlay: Option<Arc<WriteOverlay>>,
    #[cfg(test)]
    drops: Option<Arc<AtomicUsize>>,
}

impl Drop for ParkedFd {
    fn drop(&mut self) {
        if let Some(overlay) = &self.overlay {
            overlay.release_write_fd(self.fd.as_raw_fd());
        }
        #[cfg(test)]
        if let Some(counter) = self.drops.take() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl AsRawFd for ParkedFd {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.fd.as_raw_fd()
    }
}

/// Old file a nodeid keeps answering with after rename-over or unlink (#88).
///
/// `path` is `"\0stale-{ino}"` on the inode entry. This snapshot is the name
/// and attributes from before that rewrite.
struct Detached {
    /// Parked host inode. `Some` for an overlay regular file whose park open
    /// succeeded (`O_PATH` on Linux, `O_RDONLY|O_NONBLOCK` elsewhere).
    /// `None` for an archive-only target and for a metadata-only park
    /// (symlink, or any park-open error other than `EMFILE`/`ENFILE`).
    fd: Option<ParkedFd>,
    /// Snapshot taken before the name moved or was removed.
    /// `None` only when neither the park nor a pre-call lookup produced one.
    last_fi: Option<FileInfo>,
    xattrs: BTreeMap<String, Vec<u8>>,
    /// Name before detach. Archive `OpenBackend::Source::path` uses this,
    /// not `"\0stale-{ino}"`.
    path: String,
}

struct InodeEntry {
    path: String,
    /// Fat FileInfo cache. Immutable mounts, the root, and archive members
    /// the write overlay has not shadowed. Overlay-backed children store
    /// [`InodeAttrCookie`] instead and re-lookup.
    /// Stays `None` for the life of a detached inode.
    file_info: Option<FileInfo>,
    /// Compact getattr scalars on overlay-backed child inodes. Not served as
    /// getattr/open truth — those paths re-lookup. Cleared by the generation
    /// sweep. Never `Some` together with `file_info` on a child overlay inode.
    #[allow(dead_code)] // density store; production must not reconstruct FileInfo
    cookie: Option<InodeAttrCookie>,
    /// Kernel lookup count. Root starts at 1. Every other inode starts at 0.
    /// Never reset when the inode is detached.
    nlookup: u64,
    /// `Some` only while this nodeid is detached (`path` is `"\0stale-{ino}"`
    /// and `path_to_ino` has no entry for it).
    detached: Option<Detached>,
}

#[derive(Debug, PartialEq, Eq)]
enum KernelInval {
    Inode(u64),
    Entry { parent: u64, name: String },
}

/// Sender half of the kernel-notification queue.
///
/// The `Session::run` thread only moves a finished batch onto an unbounded
/// channel. It never writes `FUSE_NOTIFY_*`: the kernel holds the parent
/// `i_rwsem` across `FUSE_NOTIFY_INVAL_ENTRY`, so a notify from the single
/// request thread deadlocks against a task blocked in a FUSE reply.
struct KernelNotifyQueue {
    tx: Mutex<Option<mpsc::Sender<Vec<KernelInval>>>>,
}

impl KernelNotifyQueue {
    fn new() -> Self {
        Self {
            tx: Mutex::new(None),
        }
    }

    /// `true` once [`spawn_notifier`] has installed a sender.
    ///
    /// Unit tests leave this `false`, so they queue nothing.
    fn is_active(&self) -> bool {
        self.tx.lock().unwrap().is_some()
    }

    fn install(&self, tx: mpsc::Sender<Vec<KernelInval>>) {
        *self.tx.lock().unwrap() = Some(tx);
    }

    /// Drop the sender. The notifier thread exits once every sender is gone.
    fn clear(&self) {
        *self.tx.lock().unwrap() = None;
    }

    /// `send` never blocks (unbounded channel). Errors mean the notifier has
    /// already exited; the batch is dropped.
    fn send_batch(&self, batch: Vec<KernelInval>) {
        if batch.is_empty() {
            return;
        }
        let tx = self.tx.lock().unwrap().clone();
        if let Some(tx) = tx {
            let _ = tx.send(batch);
        }
    }
}

/// Kernel invalidation writes. Implemented for [`fuser::Notifier`] and for
/// test sinks that record or fail calls without FUSE.
trait InvalSink: Send + 'static {
    fn inval_inode(&self, ino: u64) -> std::io::Result<()>;
    fn inval_entry(&self, parent: u64, name: &OsStr) -> std::io::Result<()>;
}

impl InvalSink for fuser::Notifier {
    fn inval_inode(&self, ino: u64) -> std::io::Result<()> {
        // Whole inode: offset 0, len -1 (fuser / libfuse convention).
        fuser::Notifier::inval_inode(self, INodeNo(ino), 0, -1)
    }

    fn inval_entry(&self, parent: u64, name: &OsStr) -> std::io::Result<()> {
        fuser::Notifier::inval_entry(self, INodeNo(parent), name)
    }
}

enum NotifyStep {
    Continue,
    Stop,
}

fn is_eintr(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::Interrupted || err.raw_os_error() == Some(libc::EINTR)
}

/// ENOENT: the kernel already dropped the inode or dentry. Normal.
fn is_absent(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::NotFound || err.raw_os_error() == Some(libc::ENOENT)
}

fn is_connection_gone(err: &std::io::Error) -> bool {
    // `ECONNABORTED` is the same end of session as `ENODEV`: the kernel
    // returns it when the connection is aborted, including a normal unmount
    // that interleaves with a `/dev/fuse` read or a notify write.
    matches!(
        err.raw_os_error(),
        Some(libc::ENODEV | libc::ENOTCONN | libc::EBADF | libc::ECONNABORTED)
    )
}

/// Apply one invalidation. Retries `EINTR`. `Stop` means the connection is
/// gone and the notifier thread must exit.
fn dispatch_inval(sink: &impl InvalSink, item: &KernelInval) -> NotifyStep {
    loop {
        let result = match item {
            KernelInval::Inode(ino) => sink.inval_inode(*ino),
            KernelInval::Entry { parent, name } => sink.inval_entry(*parent, OsStr::new(name)),
        };
        match result {
            Ok(()) => return NotifyStep::Continue,
            Err(e) if is_eintr(&e) => continue,
            Err(e) if is_absent(&e) => return NotifyStep::Continue,
            Err(e) if is_connection_gone(&e) => {
                debug!("fuse notifier stopping: {e}");
                return NotifyStep::Stop;
            }
            Err(e) => {
                debug!("fuse kernel notify failed: {e}");
                return NotifyStep::Continue;
            }
        }
    }
}

fn notifier_loop(rx: mpsc::Receiver<Vec<KernelInval>>, sink: impl InvalSink) {
    while let Ok(batch) = rx.recv() {
        let mut stop = false;
        for item in &batch {
            if matches!(dispatch_inval(&sink, item), NotifyStep::Stop) {
                stop = true;
                break;
            }
        }
        if stop {
            // Connection is gone. Drop anything else already queued.
            while rx.try_recv().is_ok() {}
            break;
        }
    }
}

/// Spawn the thread that owns `sink`. The returned sender is unbounded.
/// Dropping every sender ends the thread (`recv` returns disconnect).
fn spawn_notifier(
    sink: impl InvalSink,
) -> (mpsc::Sender<Vec<KernelInval>>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::Builder::new()
        .name("ratarmount-fuse-notify".into())
        .spawn(move || notifier_loop(rx, sink))
        .expect("spawn ratarmount-fuse-notify");
    (tx, handle)
}

struct DirCacheEntry {
    /// `(name, mode, size)` from cheap [`MountSource::list_dirents`] (no fat FileInfo).
    entries: Vec<(String, u32, u64)>,
    at: std::time::Instant,
}

pub struct RatarmountFs {
    passthrough: PassthroughOptions,
    passthrough_enabled: bool,
    #[cfg(all(test, target_os = "linux"))]
    passthrough_auto_privilege: Option<bool>,
    #[cfg(target_os = "linux")]
    passthrough_state: passthrough::linux::State,
    // Writable overlay inodes cannot mix policy-enforcing daemon opens with
    // passthrough opens. Only an explicitly RO mount can pass overlay fds.
    passthrough_readonly_mount: bool,
    #[cfg(target_os = "linux")]
    backing_opens: Mutex<passthrough::OpenBackings<passthrough::linux::RegisteredBacking>>,

    attribute_mapping: AttributeMapping,
    source: Arc<dyn MountSource>,
    overlay: Option<Arc<WriteOverlay>>,
    direct_io: bool,
    read_requests: AtomicU64,
    read_requested_bytes: AtomicU64,
    read_max_request: AtomicU64,
    read_service_ns: AtomicU64,
    /// Per-handle sequential readahead size in bytes (`0` = disabled).
    readahead_bytes: usize,
    inodes: Mutex<HashMap<u64, InodeEntry>>,
    path_to_ino: Mutex<HashMap<String, u64>>,
    next_ino: AtomicU64,
    handles: Mutex<HashMap<u64, OpenBackend>>,
    next_fh: AtomicU64,
    dir_cache: Mutex<HashMap<String, DirCacheEntry>>,
    /// Last seen `MountSource::content_generation`. Live overlay commit replaces
    /// the base archive (member offsets shift); cached FileInfo, overlay cookies,
    /// and dirents are then stale — same contract as NFS
    /// `ReaderLru::sweep_if_generation_advanced`.
    source_generation: AtomicU64,
    /// Queue of kernel invalidations. The `Session::run` thread only enqueues;
    /// `ratarmount-fuse-notify` performs the writes. No sender in unit tests
    /// and until mount, so those paths queue nothing.
    kernel_notify: Arc<KernelNotifyQueue>,
    /// Invalidations queued by a request handler. [`Self::flush_kernel_invals`]
    /// moves the batch onto `kernel_notify` after the FUSE reply, so a
    /// notification never precedes its reply. The single consumer keeps
    /// per-batch order.
    pending_inval: Mutex<Vec<KernelInval>>,
    /// `(parent ino, name)` pairs replied with a non-zero entry TTL.
    ///
    /// This models kernel dentry cache, not our inode cache. The generation
    /// sweep must not clear it: the kernel still holds those dentries.
    entry_advertised: Mutex<HashSet<(u64, String)>>,
    /// Inodes whose attr went to the kernel with a non-zero TTL (write-overlay
    /// mounts only) since their last `Inode` invalidation.
    ///
    /// This models the kernel attr cache, not our inode cache: the generation
    /// sweep and `rebind_after_rename` clear `InodeEntry::file_info` while the
    /// kernel may still hold a 60s attr, so [`Self::drop_stable_attr`] decides
    /// from this set. Never pre-seeded from the inode cache. A leaf lock.
    attr_advertised: Mutex<HashSet<u64>>,
    /// Test hook: cloned into each [`ParkedFd`] so a drop of the detached
    /// entry increments it. Production builds leave this unset.
    #[cfg(test)]
    park_fd_drops: Mutex<Option<Arc<AtomicUsize>>>,
}

#[cfg(any(not(target_os = "macos"), test))]
fn fuse_io_limit(page_size: u32, max_pages_supported: bool) -> u32 {
    page_size
        .saturating_mul(if max_pages_supported { 256 } else { 32 })
        .min(16 * 1024 * 1024)
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
                cookie: None,
                nlookup: 1,
                detached: None,
            },
        );
        path_to_ino.insert("/".into(), FUSE_ROOT_ID);
        let readahead_bytes = usize::try_from(clamp_readahead(readahead)).unwrap_or(usize::MAX);
        Self {
            passthrough: PassthroughOptions::default(),
            passthrough_enabled: false,
            #[cfg(all(test, target_os = "linux"))]
            passthrough_auto_privilege: None,
            #[cfg(target_os = "linux")]
            passthrough_state: passthrough::linux::State::new(
                PassthroughOptions::default().copy_total_max,
            ),
            passthrough_readonly_mount: overlay.is_none(),
            #[cfg(target_os = "linux")]
            backing_opens: Mutex::new(passthrough::OpenBackings::default()),
            attribute_mapping: AttributeMapping::default(),
            source,
            overlay,
            readahead_bytes,
            direct_io: false,
            read_requests: AtomicU64::new(0),
            read_requested_bytes: AtomicU64::new(0),
            read_max_request: AtomicU64::new(0),
            read_service_ns: AtomicU64::new(0),
            inodes: Mutex::new(inodes),
            path_to_ino: Mutex::new(path_to_ino),
            next_ino: AtomicU64::new(FUSE_ROOT_ID + 1),
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            dir_cache: Mutex::new(HashMap::new()),
            source_generation: AtomicU64::new(0),
            kernel_notify: Arc::new(KernelNotifyQueue::new()),
            pending_inval: Mutex::new(Vec::new()),
            entry_advertised: Mutex::new(HashSet::new()),
            attr_advertised: Mutex::new(HashSet::new()),
            #[cfg(test)]
            park_fd_drops: Mutex::new(None),
        }
    }

    /// Override reported ownership and mask permissions without changing stored metadata.
    pub fn with_attribute_mapping(mut self, mapping: AttributeMapping) -> Self {
        self.attribute_mapping = mapping;
        self
    }

    fn mapped_attr(&self, mut attr: FileAttr) -> FileAttr {
        attr.uid = self.attribute_mapping.uid(attr.uid);
        attr.gid = self.attribute_mapping.gid(attr.gid);
        attr.perm = self.attribute_mapping.mode(u32::from(attr.perm)) as u16;
        attr
    }

    fn mapped_file_attr(&self, ino: u64, fi: &FileInfo) -> FileAttr {
        let mut attr = Self::file_attr(ino, fi);
        attr.atime = unix_float_to_system_time(overlay_atime(fi));
        self.mapped_attr(attr)
    }

    /// Bypass the FUSE page cache for source reads. Passthrough is disabled.
    pub fn with_direct_io(mut self, direct_io: bool) -> Self {
        self.direct_io = direct_io;
        self
    }

    fn source_open_flags(&self) -> u32 {
        if self.direct_io {
            FopenFlags::FOPEN_DIRECT_IO.bits()
        } else {
            FopenFlags::FOPEN_KEEP_CACHE.bits()
        }
    }

    /// Set passthrough negotiation and optional per-member copying.
    pub fn with_passthrough(mut self, options: PassthroughOptions) -> Self {
        self.passthrough = options;
        #[cfg(target_os = "linux")]
        {
            self.passthrough_state = passthrough::linux::State::new(options.copy_total_max);
        }
        self
    }

    #[cfg(target_os = "linux")]
    fn passthrough_file(
        &self,
        _ino: u64,
        fh: u64,
        flags: i32,
    ) -> std::io::Result<Option<passthrough::linux::PreparedBacking>> {
        if self.passthrough_state.denied()
            || !self.passthrough_readonly_mount
            || flags & libc::O_ACCMODE != libc::O_RDONLY
        {
            return Ok(None);
        }
        let fi = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh) {
                Some(OpenBackend::OverlayFd(fd)) => {
                    // Duplicate the opened inode, never reopen its pathname.
                    use std::os::fd::BorrowedFd;
                    let fd = unsafe { BorrowedFd::borrow_raw(*fd) }.try_clone_to_owned()?;
                    let file = std::fs::File::from(fd);
                    let len = file.metadata()?.len();
                    return passthrough::linux::prepare(
                        ratarmount_core::BackingExtent {
                            file,
                            offset: 0,
                            len,
                        },
                        self.passthrough,
                        &self.passthrough_state,
                        passthrough::linux::cache_parent,
                    );
                }
                Some(OpenBackend::Source {
                    file_info,
                    detached: false,
                    ..
                }) => Some(file_info.clone()),
                Some(OpenBackend::Empty) => None,
                _ => None,
            }
        };
        let Some(extent) = fi.and_then(|fi| self.source.backing_extent(&fi)) else {
            return Ok(None);
        };
        passthrough::linux::prepare(
            extent,
            self.passthrough,
            &self.passthrough_state,
            passthrough::linux::cache_parent,
        )
    }

    #[cfg(target_os = "linux")]
    fn open_backing(
        &self,
        ino: u64,
        fh: u64,
        flags: i32,
        reply: &ReplyOpen,
    ) -> Option<Arc<passthrough::linux::RegisteredBacking>> {
        if self.direct_io || !self.passthrough_enabled {
            return None;
        }
        self.backing_opens.lock().unwrap().open(ino, fh, || {
            let result = self
                .passthrough_state
                .register(
                    || self.passthrough_file(ino, fh, flags),
                    |file| reply.open_backing(file),
                )
                .map(|registered| {
                    registered.map(|(id, prepared)| {
                        debug!("FUSE passthrough open ino={ino}");
                        passthrough::linux::RegisteredBacking {
                            id,
                            _prepared: prepared,
                        }
                    })
                });
            match result {
                Ok(backing) => backing,
                Err(e) => {
                    debug!("FUSE passthrough open ino={ino}: {e}; using daemon reads");
                    None
                }
            }
        })
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
                    self.write_inode_cache(ent, ino, fi);
                }
            }
            return ino;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        p2i.insert(path.to_string(), ino);
        let (file_info, cookie) = self.inode_cache_from_fi(ino, fi);
        self.inodes.lock().unwrap().insert(
            ino,
            InodeEntry {
                path: path.to_string(),
                file_info,
                cookie,
                nlookup: 0,
                detached: None,
            },
        );
        ino
    }

    /// Overlay-backed children and empty-userdata placeholders store a cookie
    /// only. Root, immutable mounts, and unshadowed archive members keep a fat
    /// [`FileInfo`] so repeated stat/open does not re-query the index.
    fn inode_cache_from_fi(
        &self,
        ino: u64,
        fi: Option<FileInfo>,
    ) -> (Option<FileInfo>, Option<InodeAttrCookie>) {
        match fi {
            Some(fi)
                if self.overlay.is_some() && ino != FUSE_ROOT_ID && !file_info_attr_stable(&fi) =>
            {
                let cookie = InodeAttrCookie::from_file_info(&fi);
                (None, Some(cookie))
            }
            other => (other, None),
        }
    }

    fn write_inode_cache(&self, ent: &mut InodeEntry, ino: u64, fi: FileInfo) {
        // A detached nodeid keeps `file_info` empty for the rest of its life.
        // Repopulating it would let the 60s stable-attr cache apply and re-arm
        // `attr_advertised` (#84 / #92).
        if ent.detached.is_some() {
            return;
        }
        let (file_info, cookie) = self.inode_cache_from_fi(ino, Some(fi));
        ent.file_info = file_info;
        ent.cookie = cookie;
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

    /// Overlay cookie only. Immutable mounts leave this unused.
    #[cfg(test)]
    fn cached_cookie(&self, ino: u64) -> Option<InodeAttrCookie> {
        self.inodes.lock().unwrap().get(&ino).and_then(|e| e.cookie)
    }

    fn store_fi(&self, ino: u64, fi: FileInfo) {
        if let Some(ent) = self.inodes.lock().unwrap().get_mut(&ino) {
            self.write_inode_cache(ent, ino, fi);
        }
    }

    /// Cheap readdir listing: name / mode / size (no fat [`FileInfo`] map).
    ///
    /// Always goes through [`MountSource::list_dirents`], never [`MountSource::list`].
    /// Fat `FileInfo` is materialized later at getattr/lookup/open.
    fn list_mode_cached(&self, path: &str) -> Option<Vec<(String, u32, u64)>> {
        self.sweep_if_generation_advanced();
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

    /// RO archive open used by generation-sweep tests (same backend as FUSE `open`).
    #[cfg(test)]
    fn test_open_ro(&self, path: &str) -> Result<u64, i32> {
        let ino = self.ino_for_path(path);
        let fi = self.file_info_for_open(ino, path).ok_or(ENOENT)?;
        self.open_source_backend(path.to_string(), fi, false)
    }

    #[cfg(test)]
    fn test_read(&self, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>, i32> {
        self.read_handle(fh, offset, size)
    }

    /// Body of [`Filesystem::readdirplus`].
    ///
    /// `add` is `ReplyDirectoryPlus::add`: `true` means the reply buffer is
    /// full. Child inodes come from [`Self::ino_for_path`] and stay at
    /// nlookup 0. This ABI does not count readdirplus as a lookup.
    ///
    /// The trait method only forwards this into a `ReplyDirectoryPlus`.
    /// Unit tests call it directly: fuser 0.15 does not let another crate
    /// build `Request` or `ReplySender`.
    fn readdirplus_fill(
        &self,
        ino: u64,
        offset: u64,
        mut add: impl FnMut(u64, u64, &str, &Duration, &FileAttr) -> bool,
    ) -> Result<(), i32> {
        let path = self.path_for_ino(ino).ok_or(ENOENT)?;
        let entries = self.list_mode_cached(&path).ok_or(ENOENT)?;
        let self_fi = self
            .cached_fi(ino)
            .or_else(|| self.source.lookup(&path, 0))
            .unwrap_or_else(ratarmount_core::create_root_file_info);
        let mut full: Vec<(u64, String, FileAttr)> = Vec::with_capacity(entries.len() + 2);
        full.push((ino, ".".into(), self.mapped_file_attr(ino, &self_fi)));
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
            self.mapped_file_attr(parent_ino, &self_fi),
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
            // Amendment 8: this ABI does not count readdirplus as a lookup.
            // `ino_for_path` leaves the child at nlookup 0. Do not bump here.
            full.push((cino, name, self.mapped_file_attr(cino, &fi)));
        }
        for (i, (cino, name, attr)) in full.into_iter().enumerate().skip(offset as usize) {
            let entry_ttl = self.readdirplus_entry_ttl(&attr);
            if add(cino, (i + 1) as u64, &name, &entry_ttl, &attr) {
                break;
            }
            // Buffered with this TTL for entry and attr (zero with an overlay
            // today, so nothing is recorded). If it ever becomes non-zero
            // under an overlay, `(parent, name)` must go into
            // `entry_advertised` in the same change (see
            // `readdirplus_entry_ttl`).
            self.note_attr_advertised(cino, entry_ttl);
        }
        Ok(())
    }

    /// Kernel TTL for one `readdirplus` dirent attr.
    ///
    /// Dirents with a nonzero size (real index `list_dirents` sizes) and
    /// directories use the same attr TTL as lookup so `cat` after `find` does
    /// not re-getattr every file. A zero-size non-directory dirent may be a
    /// placeholder (default `list_dirents` fallback, control `status`,
    /// versions-folder entries): caching size 0 for a file that is not really
    /// empty makes the kernel serve reads at EOF, so those revalidate instead.
    ///
    /// With an overlay this returns zero, so readdirplus does not advertise a
    /// dentry. If it ever returns non-zero while an overlay is mounted, the
    /// caller must insert `(parent ino, name)` into `entry_advertised` too
    /// (same contract as [`Self::reply_entry_ttl`]).
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

    /// FileInfo for `open`. Immutable mounts and unshadowed archive members
    /// reuse the lookup/getattr cache. Overlay-backed files re-lookup so
    /// create(size 0) → write is visible. Overlay lookup miss → `None`
    /// (do not serve a cookie / create-time size 0).
    fn file_info_for_open(&self, ino: u64, path: &str) -> Option<FileInfo> {
        self.sweep_if_generation_advanced();
        if let Some(fi) = self.cached_stable_fi(ino) {
            return Some(fi);
        }
        if self.overlay.is_some() {
            if let Some(fi) = self.source.lookup(path, 0) {
                self.store_fi(ino, fi.clone());
                return Some(fi);
            }
            return None;
        }
        if let Some(c) = self.cached_fi(ino) {
            return Some(c);
        }
        let fi = self.source.lookup(path, 0)?;
        self.store_fi(ino, fi.clone());
        Some(fi)
    }

    /// Drop cached FileInfos, overlay cookies, and dirents when a live overlay
    /// commit swapped the base archive. `fetch_max` never regresses under
    /// concurrent sweeps.
    fn sweep_if_generation_advanced(&self) {
        let gen = self.source.content_generation();
        let prev = self.source_generation.fetch_max(gen, Ordering::SeqCst);
        if prev < gen {
            // Inode and directory caches are ours. `entry_advertised` and
            // `attr_advertised` track kernel dentries and attrs and must
            // survive this sweep.
            //
            // `detached` and `nlookup` stay too. Clearing the snapshot would
            // make the next getattr of a nodeid the kernel still holds return
            // ENOENT (#88).
            for ent in self.inodes.lock().unwrap().values_mut() {
                ent.file_info = None;
                ent.cookie = None;
            }
            self.dir_cache.lock().unwrap().clear();
        }
    }

    fn open_source_backend(&self, path: String, fi: FileInfo, detached: bool) -> Result<u64, i32> {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        let gen = self.source.content_generation();
        if fi.size == 0 {
            self.handles.lock().unwrap().insert(fh, OpenBackend::Empty);
            return Ok(fh);
        }
        let advice_extent = if self.direct_io {
            self.source.backing_extent(&fi).map(ArchiveAdvice::new)
        } else {
            None
        };
        let reader = self.source.open(&fi, 0).map_err(|e| io_to_errno(&e))?;
        self.handles.lock().unwrap().insert(
            fh,
            OpenBackend::Source {
                path,
                file_info: fi,
                state: Arc::new(Mutex::new(SourceReadState {
                    reader,
                    readahead: ReadaheadState::default(),
                    advice_extent,
                })),
                opened_generation: gen,
                detached,
            },
        );
        Ok(fh)
    }

    /// Re-lookup and reopen an archive-backed fh after `content_generation` advances.
    /// Overlay fds stay put (POSIX unlinked-inode). Missing fh is left for `read`.
    ///
    /// A detached fh keeps the reader it opened. Re-resolving by path would
    /// serve the file that now owns the name, or ENOENT on a tombstone.
    fn refresh_source_handle_if_stale(&self, fh: u64) -> Result<(), i32> {
        self.sweep_if_generation_advanced();
        let gen = self.source.content_generation();
        let path = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh) {
                Some(OpenBackend::Source {
                    path,
                    opened_generation,
                    detached,
                    ..
                }) if !*detached && *opened_generation < gen => path.clone(),
                _ => return Ok(()),
            }
        };
        let Some(fi) = self.source.lookup(&path, 0) else {
            return Err(ENOENT);
        };
        let new_backend = if fi.size == 0 {
            OpenBackend::Empty
        } else {
            let advice_extent = if self.direct_io {
                self.source.backing_extent(&fi).map(ArchiveAdvice::new)
            } else {
                None
            };
            let reader = self.source.open(&fi, 0).map_err(|e| io_to_errno(&e))?;
            OpenBackend::Source {
                path: path.clone(),
                file_info: fi,
                state: Arc::new(Mutex::new(SourceReadState {
                    reader,
                    readahead: ReadaheadState::default(),
                    advice_extent,
                })),
                opened_generation: gen,
                detached: false,
            }
        };
        let mut handles = self.handles.lock().unwrap();
        if let Some(OpenBackend::Source {
            opened_generation, ..
        }) = handles.get(&fh)
        {
            if *opened_generation < gen {
                handles.insert(fh, new_backend);
            }
        }
        Ok(())
    }

    fn read_handle(&self, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>, i32> {
        self.refresh_source_handle_if_stale(fh)?;
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
                None => return Err(ENOENT),
                Some(OpenBackend::Empty) => ReadTarget::Empty,
                Some(OpenBackend::OverlayFd(fd)) => ReadTarget::OverlayFd(*fd),
                Some(OpenBackend::Source { path, state, .. }) => ReadTarget::Source {
                    path: path.clone(),
                    state: Arc::clone(state),
                },
            }
        };
        match target {
            ReadTarget::Empty => Ok(Vec::new()),
            ReadTarget::OverlayFd(fd) => {
                let mut buf = vec![0u8; size as usize];
                let n = unsafe {
                    libc::pread(fd, buf.as_mut_ptr() as *mut _, size as usize, offset.max(0))
                };
                if n < 0 {
                    Err(EIO)
                } else {
                    buf.truncate(n as usize);
                    Ok(buf)
                }
            }
            ReadTarget::Source { path, state } => {
                let mut g = state.lock().unwrap();
                let SourceReadState {
                    reader,
                    readahead,
                    advice_extent,
                } = &mut *g;
                let off = offset.max(0) as u64;
                match readahead_fill(
                    reader.as_mut(),
                    readahead,
                    self.readahead_bytes,
                    off,
                    size as usize,
                ) {
                    Ok(buf) => {
                        if let Some(extent) = advice_extent {
                            extent.consumed(off, buf.len() as u64);
                        }
                        Ok(buf)
                    }
                    Err(e) => {
                        debug!(
                            "read error path={path} offset={offset} size={size} kind={:?}: {e}",
                            e.kind()
                        );
                        Err(io_to_errno(&e))
                    }
                }
            }
        }
    }

    /// Drop a parent directory listing so create/unlink/mkdir/rmdir are visible
    /// to readdir before the 30s TTL expires.
    fn invalidate_dir_cache(&self, parent: &str) {
        self.dir_cache.lock().unwrap().remove(parent);
    }

    /// Overlay path for `parent`/`name`, or the errno to reply.
    fn overlay_child_path(&self, parent: u64, name: &OsStr) -> Result<String, i32> {
        if self.overlay.is_none() {
            return Err(EROFS);
        }
        let parent_path = self.path_for_ino(parent).ok_or(ENOENT)?;
        Ok(join_path(&parent_path, &name.to_string_lossy()))
    }

    fn create_masked_entry(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<(Duration, FileAttr, u64), i32> {
        self.create_entry(parent, name, mode & !umask)
    }

    fn mkdir_masked_entry(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<(Duration, FileAttr), i32> {
        self.mkdir_entry(parent, name, mode & !umask)
    }

    /// Body of `create`, replying-free so it can be unit-tested.
    fn create_entry(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
    ) -> Result<(Duration, FileAttr, u64), i32> {
        let path = self.overlay_child_path(parent, name)?;
        let parent_path = self.path_for_ino(parent).ok_or(ENOENT)?;
        let name = name.to_string_lossy();
        let ov = self.overlay.as_ref().ok_or(EROFS)?;
        let fd = ov.create_file(&path, mode).map_err(|e| {
            debug!("create: {e}");
            overlay_errno(&e)
        })?;
        let fi = self.source.lookup(&path, 0).unwrap_or_else(|| FileInfo {
            size: 0,
            mtime: 0.0,
            mode: mode | ratarmount_core::S_IFREG,
            linkname: String::new(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            userdata: vec![],
        });
        // Drop a previously cached archive member before the new
        // overlay FileInfo replaces it, or the kernel keeps 60s attrs.
        self.note_dir_changed(parent, &name);
        let ino = self.ino_for_path_with_fi(&path, Some(fi.clone()));
        self.invalidate_dir_cache(&parent_path);
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles
            .lock()
            .unwrap()
            .insert(fh, OpenBackend::OverlayFd(fd));
        let ttl = self.reply_entry_ttl(parent, &name, ino, &fi);
        self.bump_nlookup(ino);
        Ok((ttl, self.mapped_file_attr(ino, &fi), fh))
    }

    /// Body of `mkdir`, replying-free so it can be unit-tested.
    fn mkdir_entry(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
    ) -> Result<(Duration, FileAttr), i32> {
        let path = self.overlay_child_path(parent, name)?;
        let parent_path = self.path_for_ino(parent).ok_or(ENOENT)?;
        let name = name.to_string_lossy();
        let ov = self.overlay.as_ref().ok_or(EROFS)?;
        ov.mkdir(&path, mode).map_err(|e| {
            debug!("mkdir: {e}");
            overlay_errno(&e)
        })?;
        let fi = self.source.lookup(&path, 0).unwrap_or_else(|| FileInfo {
            size: 0,
            mtime: 0.0,
            mode: mode | ratarmount_core::S_IFDIR,
            linkname: String::new(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            userdata: vec![],
        });
        self.note_dir_changed(parent, &name);
        let ino = self.ino_for_path_with_fi(&path, Some(fi.clone()));
        self.invalidate_dir_cache(&parent_path);
        let ttl = self.reply_entry_ttl(parent, &name, ino, &fi);
        self.bump_nlookup(ino);
        Ok((ttl, self.mapped_file_attr(ino, &fi)))
    }

    /// Body of `unlink` / `rmdir`, replying-free so it can be unit-tested.
    fn remove_entry(&self, parent: u64, name: &OsStr, dir: bool) -> Result<(), i32> {
        let path = self.overlay_child_path(parent, name)?;
        let parent_path = self.path_for_ino(parent).ok_or(ENOENT)?;
        let name = name.to_string_lossy();
        let ov = self.overlay.as_ref().ok_or(EROFS)?;
        if dir {
            // Directories are not parked. A held directory fd can still
            // GETATTR ENOENT after rmdir.
            ov.rmdir(&path).map_err(|e| {
                debug!("rmdir: {e}");
                overlay_errno(&e)
            })?;
            self.invalidate_dir_cache(&parent_path);
            self.note_dir_changed(parent, &name);
            return Ok(());
        }
        // Snapshot before unlink: afterwards the name is a tombstone.
        let ino = self.existing_ino(&path);
        let snap = ino.and_then(|ino| self.snapshot_file_info(ino, &path));
        let xattrs = self.snapshot_xattrs(snap.as_ref());
        // FUSE-only (#88). Other frontends call `unlink` and never open the file.
        let parked = ov.unlink_parked(&path).map_err(|e| {
            debug!("unlink: {e}");
            overlay_errno(&e)
        })?;
        self.invalidate_dir_cache(&parent_path);
        // While path_to_ino still maps the name, so a 60s member still gets
        // its Entry + Inode from attr_advertised.
        self.note_dir_changed(parent, &name);
        self.detach_unlinked(&path, ino, parked, snap, xattrs);
        self.mark_source_handles_detached(&path);
        Ok(())
    }

    /// Overlay rename for `Filesystem::rename` (#86). Returns an errno.
    ///
    /// With a negotiated FUSE ABI below 7.23 (fuser 0.15 without `abi-7-23`)
    /// the kernel only sends plain `FUSE_RENAME` (flags 0) and fails
    /// `renameat2` flags with EINVAL itself. Any nonzero `flags` that still
    /// arrives is refused here.
    fn rename_paths(
        &self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
        flags: u32,
    ) -> Result<(), i32> {
        let Some(ov) = &self.overlay else {
            return Err(EROFS);
        };
        let parent_path = self.path_for_ino(parent).ok_or(ENOENT)?;
        let newparent_path = self.path_for_ino(newparent).ok_or(ENOENT)?;
        let from = join_path(&parent_path, name);
        let to = join_path(&newparent_path, newname);
        if flags != 0 {
            return Err(EINVAL);
        }
        if from == to {
            return if self.source.lookup(&from, 0).is_some() {
                Ok(())
            } else {
                Err(ENOENT)
            };
        }
        // Snapshot the destination while the name still resolves to the old
        // file. After the host rename, lookup(to) is the incoming file, and
        // drop_stable_attr below clears a fat archive FileInfo.
        let src_ino = self.existing_ino(&from);
        let replaced = self.existing_ino(&to).filter(|ino| Some(*ino) != src_ino);
        let snap = replaced.and_then(|ino| self.snapshot_file_info(ino, &to));
        let xattrs = self.snapshot_xattrs(snap.as_ref());
        // FUSE-only (#88). Other frontends call `rename` and never open the target.
        // The park open runs inside rename_parked, before rename(2).
        let parked = match ov.rename_parked(&from, &to) {
            Ok(parked) => parked,
            Err(ratarmount_compositing::OverlayError::Io(e)) => {
                debug!("rename {from} -> {to}: {e}");
                return Err(io_to_errno(&e));
            }
            Err(e) => {
                debug!("rename {from} -> {to}: {e}");
                return Err(EIO);
            }
        };
        // Kernel cache: queue the old name, both children and both parents
        // before the rebind, while path_to_ino still maps `from` to the
        // source and `to` to a replaced target (afterwards neither does).
        // The handler flushes once, after the reply.
        //
        // No INVAL_ENTRY for the destination name, cached or not. After the
        // reply the kernel has d_moved the source dentry there (unhashing a
        // replaced target itself), so an INVAL_ENTRY on that name would only
        // unhash the moved dentry: a held fd then reads "... (deleted)". The
        // moved inode is at `to` now with TTL 0 attrs, and `Inode(child)`
        // from the old name drops its 60s attr; a replaced target's inode is
        // still dropped below. Later changes to the destination name are
        // kernel ops on that dentry, which the VFS updates itself.
        //
        // Residual: the moved dentry keeps the rest of its 60s entry timeout
        // and neither name stays in `entry_advertised`, so a change made
        // outside the mount (host delete/replace of the overlay copy) is not
        // seen under the destination name for up to 60s. A future option is
        // FUSE_NOTIFY_INVAL_ENTRY with FUSE_EXPIRE_ONLY (ABI 7.38), which
        // expires the dentry without unhashing it, so held fds keep their
        // path; fuser 0.15 does not expose it.
        self.note_entry_changed(parent, name);
        self.entry_advertised
            .lock()
            .unwrap()
            .remove(&(newparent, newname.to_string()));
        if let Some(replaced) = self.existing_ino(&to) {
            self.drop_stable_attr(replaced);
        }
        self.drop_stable_attr(parent);
        if newparent != parent {
            self.drop_stable_attr(newparent);
        }
        self.rebind_after_rename(&from, &to, parked, snap, xattrs);
        // Handles only, after both inode maps are released.
        self.mark_source_handles_detached(&from);
        self.mark_source_handles_detached(&to);
        self.invalidate_dir_cache(&parent_path);
        self.invalidate_dir_cache(&newparent_path);
        Ok(())
    }

    /// FUSE `rename` body: run [`Self::rename_paths`], hand the result to
    /// `reply`, then (on success) flush the queued invalidations.
    fn rename_reply(
        &self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
        flags: u32,
        reply: impl FnOnce(Result<(), i32>),
    ) {
        let result = self.rename_paths(parent, name, newparent, newname, flags);
        let ok = result.is_ok();
        reply(result);
        if ok {
            // Never notify inline: the kernel holds both directories'
            // i_rwsem across FUSE_RENAME.
            self.flush_kernel_invals();
        }
    }

    /// Keep the source inode number across rename; detach a replaced
    /// destination inode (same as export-core `InodeTable::rebind_path`).
    /// The kernel may still hold the old destination inode (open fd, no
    /// FORGET yet); it must not resolve to the file now at `to`.
    /// Clears only the userspace cache; `attr_advertised` keeps the kernel
    /// record so a later `drop_stable_attr` still invalidates.
    ///
    /// One `path_to_ino`-then-`inodes` section. The parked fd moves onto the
    /// map here; dropping `Parked` earlier would close it first.
    fn rebind_after_rename(
        &self,
        from: &str,
        to: &str,
        mut parked: Option<Parked>,
        mut snap: Option<FileInfo>,
        mut xattrs: BTreeMap<String, Vec<u8>>,
    ) {
        // Clone the test counter before either map lock. `build_detached` is
        // a free function and must not borrow `self` under `inodes`.
        let mut drops = self.park_drop_counter();
        let doomed = {
            // Lock order matches ino_for_path_with_fi: path_to_ino, then inodes.
            let mut p2i = self.path_to_ino.lock().unwrap();
            let mut inodes = self.inodes.lock().unwrap();
            let src = p2i.get(from).copied();
            let mut doomed = None;
            if let Some(old_dest) = p2i.get(to).copied() {
                if Some(old_dest) != src {
                    p2i.remove(to);
                    let pre_path = inodes
                        .get(&old_dest)
                        .map(|e| e.path.clone())
                        .unwrap_or_else(|| to.to_string());
                    let detached = build_detached(
                        old_dest,
                        pre_path,
                        parked.take(),
                        snap.take(),
                        drops.take(),
                        self.overlay.clone(),
                        std::mem::take(&mut xattrs),
                    );
                    doomed = install_detached(&mut inodes, old_dest, detached);
                }
            }
            if let Some(src) = src {
                p2i.remove(from);
                if let Some(ent) = inodes.get_mut(&src) {
                    ent.path = to.to_string();
                    ent.file_info = None;
                    ent.cookie = None;
                }
                p2i.insert(to.to_string(), src);
            }
            doomed
        };
        // Close a parked fd the kernel does not reference, outside the locks.
        drop(doomed);
        drop(parked);
        drop(snap);
        drop(drops);
    }

    /// Unlink twin of [`Self::rebind_after_rename`]'s detach half.
    ///
    /// A name the kernel never looked up has no inode. Its parked fd is closed
    /// after both maps are released, same as a replaced inode with `nlookup` 0.
    fn detach_unlinked(
        &self,
        path: &str,
        ino: Option<u64>,
        mut parked: Option<Parked>,
        mut snap: Option<FileInfo>,
        mut xattrs: BTreeMap<String, Vec<u8>>,
    ) {
        let mut drops = self.park_drop_counter();
        let doomed = {
            let mut p2i = self.path_to_ino.lock().unwrap();
            let mut inodes = self.inodes.lock().unwrap();
            if let Some(ino) = ino {
                p2i.remove(path);
                let pre_path = inodes
                    .get(&ino)
                    .map(|e| e.path.clone())
                    .unwrap_or_else(|| path.to_string());
                let detached = build_detached(
                    ino,
                    pre_path,
                    parked.take(),
                    snap.take(),
                    drops.take(),
                    self.overlay.clone(),
                    std::mem::take(&mut xattrs),
                );
                install_detached(&mut inodes, ino, detached)
            } else {
                None
            }
        };
        // Close a parked fd the kernel does not reference, outside the locks.
        drop(doomed);
        drop(parked);
        drop(snap);
        drop(drops);
    }

    /// Archive readers opened on `path` before this rename or unlink keep
    /// those bytes across a later live commit.
    fn mark_source_handles_detached(&self, path: &str) {
        let mut handles = self.handles.lock().unwrap();
        for backend in handles.values_mut() {
            if let OpenBackend::Source {
                path: stored,
                detached,
                ..
            } = backend
            {
                if stored == path {
                    *detached = true;
                }
            }
        }
    }

    /// Stable archive `FileInfo` if the fat cache still has it, otherwise a
    /// lookup while the name still points at the old file.
    fn snapshot_file_info(&self, ino: u64, path: &str) -> Option<FileInfo> {
        if let Some(fi) = self.cached_stable_fi(ino) {
            return Some(fi);
        }
        self.source.lookup(path, 0)
    }

    /// Cloned into each [`ParkedFd`] so tests observe the close. Production
    /// always returns `None`. Taken before the inode-map locks.
    fn park_drop_counter(&self) -> Option<Arc<AtomicUsize>> {
        #[cfg(test)]
        {
            self.park_fd_drops.lock().unwrap().clone()
        }
        #[cfg(not(test))]
        {
            let _ = self;
            None
        }
    }

    fn bump_nlookup(&self, ino: u64) {
        if let Some(ent) = self.inodes.lock().unwrap().get_mut(&ino) {
            ent.nlookup = ent.nlookup.saturating_add(1);
        }
    }

    /// Subtract `n` kernel references. A detached inode is removed only at 0,
    /// and its parked fd is closed after `inodes` is released. A still-linked
    /// inode stays so the next lookup reuses the nodeid. Root is never removed.
    fn forget_nlookup(&self, ino: u64, n: u64) {
        let removed = {
            let mut inodes = self.inodes.lock().unwrap();
            let (left, is_detached) = {
                let Some(ent) = inodes.get_mut(&ino) else {
                    return;
                };
                if n > ent.nlookup {
                    warn!(
                        "forget ino={ino} nlookup={n} exceeds stored {}",
                        ent.nlookup
                    );
                }
                ent.nlookup = ent.nlookup.saturating_sub(n);
                (ent.nlookup, ent.detached.is_some())
            };
            if ino != FUSE_ROOT_ID && left == 0 && is_detached {
                inodes.remove(&ino)
            } else {
                None
            }
        };
        // Parked fd closes here, outside `inodes`.
        drop(removed);
    }

    /// Kernel attr/entry TTL for this `FileInfo`.
    ///
    /// Unshadowed archive members use [`TTL`] (same as a read-only mount).
    /// Overlay-backed files and empty-userdata create placeholders stay at
    /// [`OVERLAY_ATTR_TTL`] so create(size 0) → write → stat cannot pin size 0.
    fn attr_ttl_for_fi(&self, fi: &FileInfo) -> Duration {
        if self.overlay.is_some() && !file_info_attr_stable(fi) {
            OVERLAY_ATTR_TTL
        } else {
            TTL
        }
    }

    fn cached_stable_fi(&self, ino: u64) -> Option<FileInfo> {
        let fi = self.cached_fi(ino)?;
        if self.overlay.is_none() || file_info_attr_stable(&fi) {
            Some(fi)
        } else {
            None
        }
    }

    fn existing_ino(&self, path: &str) -> Option<u64> {
        self.path_to_ino.lock().unwrap().get(path).copied()
    }

    /// Lookup used by FUSE `lookup`. A stable cached `FileInfo` skips
    /// `MountSource::lookup` (overlay SQL, host stat, archive index).
    fn lookup_file_info(&self, path: &str) -> Option<FileInfo> {
        self.sweep_if_generation_advanced();
        if let Some(ino) = self.existing_ino(path) {
            if let Some(fi) = self.cached_stable_fi(ino) {
                return Some(fi);
            }
        }
        let fi = self.source.lookup(path, 0)?;
        self.ino_for_path_with_fi(path, Some(fi.clone()));
        Some(fi)
    }

    /// Drop a fat archive-member cache, and the kernel's attr for `ino` if a
    /// reply advertised one. Returns whether an `Inode` invalidation was
    /// queued.
    ///
    /// The kernel decision reads `attr_advertised`, not `file_info`: a sweep
    /// or rebind may have cleared the userspace cache while the kernel still
    /// holds the 60s attr. Without a notifier (unit tests, before mount) the
    /// record is kept, since nothing would be sent.
    ///
    /// Residual, not handled here: after a live commit the generation sweep
    /// sends nothing to the kernel (lookup/getattr/readdir/read never flush),
    /// so a member the commit replaced can show stale attrs for up to 60s
    /// (until this drop, a later attr reply, or the TTL) and stale
    /// `FOPEN_KEEP_CACHE` pages until an `Inode` invalidation.
    /// `attr_advertised` is also never trimmed on FORGET (inode numbers are
    /// not reused, and the inode map does not shrink either); trimming it
    /// would need per-inode lookup counts.
    fn drop_stable_attr(&self, ino: u64) -> bool {
        {
            let mut inodes = self.inodes.lock().unwrap();
            if let Some(ent) = inodes.get_mut(&ino) {
                if ent.file_info.as_ref().is_some_and(file_info_attr_stable) {
                    ent.file_info = None;
                    ent.cookie = None;
                }
            }
        }
        if !self.kernel_notify.is_active() {
            return false;
        }
        let advertised = self.attr_advertised.lock().unwrap().remove(&ino);
        if advertised {
            self.queue_kernel_inode(ino);
        }
        advertised
    }

    /// Record that `ino`'s attr went to the kernel with `ttl`.
    fn note_attr_advertised(&self, ino: u64, ttl: Duration) {
        if self.overlay.is_some() && !ttl.is_zero() {
            self.attr_advertised.lock().unwrap().insert(ino);
        }
    }

    /// Attr TTL for a getattr/setattr reply, recorded in `attr_advertised`.
    fn reply_attr_ttl(&self, ino: u64, fi: &FileInfo) -> Duration {
        let ttl = self.attr_ttl_for_fi(fi);
        self.note_attr_advertised(ino, ttl);
        ttl
    }

    /// FUSE `getattr` body. `Err(ENOENT)` when the inode is unknown.
    /// `Err(EIO)` when `fstat` of a parked fd fails.
    ///
    /// A detached inode replies with TTL 0 and `nlink` 0 and does not re-arm
    /// `attr_advertised`.
    fn getattr_reply(&self, ino: u64) -> Result<(Duration, FileAttr), i32> {
        enum View {
            Fd(libc::c_int),
            Meta(FileInfo),
            Missing,
            Live,
        }
        // Copy the raw fd under `inodes` and stat after the release.
        let view = {
            let inodes = self.inodes.lock().unwrap();
            match inodes.get(&ino).and_then(|e| e.detached.as_ref()) {
                Some(det) => {
                    if let Some(fd) = &det.fd {
                        View::Fd(fd.as_raw_fd())
                    } else if let Some(fi) = det.last_fi.clone() {
                        View::Meta(fi)
                    } else {
                        View::Missing
                    }
                }
                None => View::Live,
            }
        };
        match view {
            View::Fd(fd) => {
                let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
                // Session::run is one thread, so FORGET cannot close `fd`
                // between the copy and this fstat. Do not dup: the read path
                // sends a GETATTR per read.
                if unsafe { libc::fstat(fd, &mut st) } != 0 {
                    return Err(EIO);
                }
                Ok((
                    Duration::ZERO,
                    self.mapped_attr(file_attr_from_stat(ino, &st)),
                ))
            }
            View::Meta(fi) => Ok((
                Duration::ZERO,
                self.mapped_attr(Self::file_attr_nlink(ino, &fi, 0)),
            )),
            View::Missing => {
                debug!("getattr detached ino={ino} has no metadata");
                Err(ENOENT)
            }
            View::Live => {
                // Stable archive members return the fat cache. Overlay-backed
                // inodes re-lookup so create (size 0) → write → stat/ls sees
                // the real size.
                let fi = self.file_info_for_ino(ino).ok_or(ENOENT)?;
                let ttl = self.reply_attr_ttl(ino, &fi);
                Ok((ttl, self.mapped_file_attr(ino, &fi)))
            }
        }
    }

    fn queue_kernel(&self, item: KernelInval) {
        if !self.kernel_notify.is_active() {
            return;
        }
        self.pending_inval.lock().unwrap().push(item);
    }

    fn queue_kernel_inode(&self, ino: u64) {
        self.queue_kernel(KernelInval::Inode(ino));
    }

    fn queue_kernel_entry(&self, parent: u64, name: &str) {
        self.queue_kernel(KernelInval::Entry {
            parent,
            name: name.to_string(),
        });
    }

    /// Move invalidations queued by this request onto the notifier thread.
    /// Call after the FUSE reply. This never calls the kernel.
    ///
    /// The notification lands shortly after the reply, not before it returns.
    /// create/mkdir/setattr replies carry the fresh attr; the kernel updates
    /// `i_size` on write itself; unlink/rmdir `d_delete` the dentry. The
    /// notify only drops other cached state (parent directory attrs, a 60s
    /// attr of a member whose first write or truncate turned it overlay-backed).
    ///
    /// `send` errors are ignored: the notifier has already exited.
    fn flush_kernel_invals(&self) {
        let batch = std::mem::take(&mut *self.pending_inval.lock().unwrap());
        self.kernel_notify.send_batch(batch);
    }

    /// Entry TTL for lookup/create/mkdir, and the record of names the kernel
    /// may cache.
    ///
    /// A non-zero TTL inserts `(parent, name)` into `entry_advertised`. A zero
    /// TTL (overlay-backed file, create placeholder) does not: there is no
    /// kernel dentry cache to drop later.
    fn reply_entry_ttl(&self, parent: u64, name: &str, ino: u64, fi: &FileInfo) -> Duration {
        let ttl = self.attr_ttl_for_fi(fi);
        // The entry reply carries the child's attr with the same TTL.
        self.note_attr_advertised(ino, ttl);
        if !ttl.is_zero() {
            self.entry_advertised
                .lock()
                .unwrap()
                .insert((parent, name.to_string()));
        }
        ttl
    }

    /// FUSE `lookup` body. `None` is ENOENT (no negative dentry). A non-zero
    /// entry TTL is recorded by [`Self::reply_entry_ttl`].
    fn lookup_entry(&self, parent: u64, name: &OsStr) -> Option<(u64, FileAttr, Duration)> {
        let parent_path = self.path_for_ino(parent)?;
        let name = name.to_string_lossy();
        let path = join_path(&parent_path, name.as_ref());
        let fi = self.lookup_file_info(&path)?;
        let ino = self.ino_for_path_with_fi(&path, Some(fi.clone()));
        let ttl = self.reply_entry_ttl(parent, name.as_ref(), ino, &fi);
        self.bump_nlookup(ino);
        Some((ino, self.mapped_file_attr(ino, &fi), ttl))
    }

    /// Invalidate one directory entry the kernel may have cached, then drop
    /// the child's stable attr.
    ///
    /// When `(parent, name)` is in `entry_advertised`, remove it and queue
    /// `KernelInval::Entry`. `drop_stable_attr` on the child inode, if that
    /// inode exists, is unconditional and outside that branch. It is the only
    /// child-inode invalidation: it queues `Inode` iff the child is in
    /// `attr_advertised` (a reply gave it a non-zero attr TTL), including when
    /// a sweep or rebind already cleared its userspace cache. Do not also call
    /// `queue_kernel_inode` for the child.
    ///
    /// Rename ([`Self::rename_paths`]) calls this for the old name only; the
    /// destination name is forgotten without an INVAL_ENTRY (it would unhash
    /// the dentry the kernel just moved there). Both children and both
    /// parents are dropped before the path map is rebound; the single
    /// `flush_kernel_invals` after the reply sends the batch.
    fn note_entry_changed(&self, parent: u64, name: &str) {
        let key = (parent, name.to_string());
        let advertised = self.entry_advertised.lock().unwrap().remove(&key);
        if advertised {
            self.queue_kernel_entry(parent, name);
        }
        if let Some(parent_path) = self.path_for_ino(parent) {
            let child = join_path(&parent_path, name);
            if let Some(ino) = self.existing_ino(&child) {
                self.drop_stable_attr(ino);
            }
        }
    }

    /// Parent directory attrs and one child name changed (create/unlink/mkdir/rmdir).
    fn note_dir_changed(&self, parent: u64, name: &str) {
        self.drop_stable_attr(parent);
        self.note_entry_changed(parent, name);
    }

    fn file_attr(ino: u64, fi: &FileInfo) -> FileAttr {
        Self::file_attr_nlink(ino, fi, 1)
    }

    /// `nlink` is 0 only for a detached (replaced or unlinked) nodeid. The
    /// moved source inode stays at 1; publishing 0 there makes a held fd read
    /// as `(deleted)`.
    fn file_attr_nlink(ino: u64, fi: &FileInfo, nlink: u32) -> FileAttr {
        let kind = mode_to_kind(fi.mode);
        let perm = (fi.mode & 0o7777) as u16;
        let mtime = unix_float_to_system_time(fi.mtime);
        FileAttr {
            ino: INodeNo(ino),
            size: fi.size,
            blocks: fi.size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm,
            nlink,
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
    /// Unshadowed archive members reuse the fat cache. Overlay-backed files
    /// re-lookup so size/mtime after create/write match the host file (cookie
    /// is not getattr truth). Overlay lookup miss → `None`.
    fn file_info_for_ino(&self, ino: u64) -> Option<FileInfo> {
        self.sweep_if_generation_advanced();
        {
            let inodes = self.inodes.lock().unwrap();
            if let Some(det) = inodes.get(&ino).and_then(|e| e.detached.as_ref()) {
                // Do not store_fi and do not lookup `"\0stale-…"`.
                return det.last_fi.clone();
            }
        }
        let path = self.path_for_ino(ino)?;
        if path == "/" {
            let fi = self
                .overlay
                .as_ref()
                .and_then(|ov| ov.lookup("/", 0))
                .unwrap_or_else(ratarmount_core::create_root_file_info);
            self.store_fi(ino, fi.clone());
            return Some(fi);
        }
        if let Some(fi) = self.cached_stable_fi(ino) {
            return Some(fi);
        }
        if self.overlay.is_some() {
            if let Some(fi) = self.source.lookup(&path, 0) {
                self.store_fi(ino, fi.clone());
                return Some(fi);
            }
            return None;
        }
        if let Some(fi) = self.cached_fi(ino) {
            return Some(fi);
        }
        let fi = self.source.lookup(&path, 0)?;
        self.store_fi(ino, fi.clone());
        Some(fi)
    }

    /// Production `open` (overlay `has_file` → [`OpenBackend::OverlayFd`]).
    ///
    /// Never chooses [`OpenBackend::Empty`] from a cached size 0 when the
    /// overlay has a host file. Overlay getattr/open still re-lookup.
    fn open_inode(&self, ino: u64, flags: i32) -> Result<(u64, u32), i32> {
        if self.inode_is_detached(ino) {
            return self.open_detached(ino, flags);
        }
        let path = self.path_for_ino(ino).ok_or(ENOENT)?;
        let write = (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0;
        // Writes always go to the overlay; reads of files that exist in the overlay
        // must also use the overlay FD (not the base archive). Previously RO open
        // used a cached size-0 FileInfo → Empty backend, so write-then-cat returned "".
        // A stable archive-member cache has already proven this path is not
        // shadowed, so read-only open skips the overlay host stat.
        if let Some(ov) = &self.overlay {
            let shadowed = write || (self.cached_stable_fi(ino).is_none() && ov.has_file(&path));
            if shadowed {
                match ov.open_overlay_fd(&path, flags) {
                    Ok(fd) => {
                        // COW / create replaces the archive member. Drop the fat
                        // cache before storing the overlay cookie.
                        self.drop_stable_attr(ino);
                        if let Some(fi) = self.source.lookup(&path, 0) {
                            self.store_fi(ino, fi);
                        }
                        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                        self.handles
                            .lock()
                            .unwrap()
                            .insert(fh, OpenBackend::OverlayFd(fd));
                        // Do not KEEP_CACHE: size changes after write.
                        return Ok((fh, 0));
                    }
                    Err(e) => {
                        if write {
                            debug!("overlay open: {e}");
                            return Err(overlay_errno(&e));
                        }
                        // RO open of non-overlay path: fall through to base source.
                        debug!("overlay open (read fallthrough): {e}");
                    }
                }
            }
        } else if write {
            return Err(EROFS);
        }

        let fi = self.file_info_for_open(ino, &path).ok_or(ENOENT)?;
        let fh = self.open_source_backend(path, fi, false)?;
        Ok((fh, self.source_open_flags()))
    }

    fn inode_is_detached(&self, ino: u64) -> bool {
        self.inodes
            .lock()
            .unwrap()
            .get(&ino)
            .is_some_and(|e| e.detached.is_some())
    }

    /// Read-only reopen of a parked inode, or a detached archive reader.
    /// A new write open is `EACCES`. Does not call `open_overlay_fd` (that
    /// takes `commit_gate`, which is not reentrant with park).
    fn open_detached(&self, ino: u64, flags: i32) -> Result<(u64, u32), i32> {
        let write = (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0;
        if write {
            return Err(EACCES);
        }
        enum Kind {
            Fd(libc::c_int),
            Archive { path: String, fi: FileInfo },
            Meta,
            Missing,
        }
        let kind = {
            let inodes = self.inodes.lock().unwrap();
            let Some(det) = inodes.get(&ino).and_then(|e| e.detached.as_ref()) else {
                return Err(ENOENT);
            };
            if let Some(fd) = &det.fd {
                Kind::Fd(fd.as_raw_fd())
            } else if let Some(fi) = det.last_fi.clone() {
                if is_detached_archive_file(&fi) {
                    Kind::Archive {
                        path: det.path.clone(),
                        fi,
                    }
                } else {
                    Kind::Meta
                }
            } else {
                Kind::Missing
            }
        };
        match kind {
            Kind::Fd(raw) => {
                let fd = reopen_parked_readonly(raw)?;
                if let Some(ov) = &self.overlay {
                    ov.track_overlay_fd(fd);
                }
                let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                self.handles
                    .lock()
                    .unwrap()
                    .insert(fh, OpenBackend::OverlayFd(fd));
                Ok((fh, 0))
            }
            Kind::Archive { path, fi } => {
                let fh = self.open_source_backend(path, fi, true)?;
                Ok((fh, self.source_open_flags()))
            }
            Kind::Meta => Err(EACCES),
            Kind::Missing => {
                debug!("open detached ino={ino} has no metadata");
                Err(ENOENT)
            }
        }
    }

    fn mutation_path(&self, ino: u64) -> Result<String, i32> {
        self.inodes
            .lock()
            .unwrap()
            .get(&ino)
            .map(|e| e.detached.as_ref().map_or(&e.path, |d| &d.path).clone())
            .ok_or(ENOENT)
    }

    // Duplicate under the table lock to keep RELEASE from closing/reusing the
    // descriptor. All checks and data I/O run after releasing the table lock.
    fn with_overlay_handle<T>(
        &self,
        fh: u64,
        path: &str,
        missing: i32,
        operation: impl FnOnce(&std::fs::File) -> Result<T, i32>,
    ) -> Result<T, i32> {
        struct Copy<'a> {
            overlay: &'a WriteOverlay,
            file: Option<std::fs::File>,
        }
        impl Drop for Copy<'_> {
            fn drop(&mut self) {
                self.overlay
                    .finish_owned_write_fd(self.file.take().unwrap());
            }
        }
        let ov = self.overlay.as_ref().ok_or(EROFS)?;
        let file = {
            let handles = self.handles.lock().unwrap();
            let Some(OpenBackend::OverlayFd(fd)) = handles.get(&fh) else {
                return Err(missing);
            };
            ov.clone_overlay_fd(*fd, path).map_err(|_| EIO)?
        };
        let copy = Copy {
            overlay: ov,
            file: Some(file),
        };
        operation(copy.file.as_ref().unwrap())
    }

    /// Body of WRITE, also exercised without a kernel mount in policy tests.
    fn write_handle(&self, ino: u64, fh: u64, offset: i64, data: &[u8]) -> Result<usize, i32> {
        let ov = self.overlay.as_ref().ok_or(EROFS)?;
        let path = self.mutation_path(ino).map_err(|_| EIO)?;
        self.with_overlay_handle(fh, &path, EIO, |file| {
            ov.write_at(file, &path, offset.max(0) as u64, data)
                .map_err(|e| match e.kind() {
                    ErrorKind::ReadOnlyFilesystem
                    | ErrorKind::QuotaExceeded
                    | ErrorKind::StorageFull => io_to_errno(&e),
                    _ => EIO,
                })
        })
    }

    /// Body of `setattr`. Non-detached behavior is path `truncate`. A detached
    /// inode refuses an fh-less setattr; a write fh `ftruncate`s that fd.
    #[cfg(test)]
    fn setattr_entry(
        &self,
        ino: u64,
        size: Option<u64>,
        fh: Option<u64>,
    ) -> Result<(Duration, FileAttr), i32> {
        self.setattr_metadata_entry(ino, size, fh, &OverlayMetadata::default())
    }

    fn setattr_metadata_entry(
        &self,
        ino: u64,
        size: Option<u64>,
        fh: Option<u64>,
        attrs: &OverlayMetadata,
    ) -> Result<(Duration, FileAttr), i32> {
        if self.inode_is_detached(ino) {
            return self.setattr_detached(ino, size, fh, attrs);
        }
        let path = self.path_for_ino(ino).ok_or(ENOENT)?;
        if size.is_some() || !attrs.is_empty() {
            self.overlay
                .as_ref()
                .ok_or(EROFS)?
                .set_attributes(&path, size, attrs)
                .map_err(|e| metadata_errno(&e))?;
            self.drop_stable_attr(ino);
            self.invalidate_dir_cache(path.rsplit_once('/').map_or("/", |(parent, _)| {
                if parent.is_empty() {
                    "/"
                } else {
                    parent
                }
            }));
        } else if !self.writable() {
            return Err(ENOSYS);
        }
        let fi = self
            .file_info_for_ino(ino)
            .or_else(|| self.source.lookup(&path, 0))
            .unwrap_or_else(ratarmount_core::create_root_file_info);
        let ttl = self.reply_attr_ttl(ino, &fi);
        Ok((ttl, self.mapped_file_attr(ino, &fi)))
    }

    fn setattr_detached(
        &self,
        ino: u64,
        size: Option<u64>,
        fh: Option<u64>,
        attrs: &OverlayMetadata,
    ) -> Result<(Duration, FileAttr), i32> {
        let Some(fh) = fh else {
            return Err(EACCES);
        };
        let path = self.mutation_path(ino)?;
        self.with_overlay_handle(fh, &path, EACCES, |file| {
            let fd = file.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(EIO);
            }
            let acc = flags & libc::O_ACCMODE;
            if acc != libc::O_WRONLY && acc != libc::O_RDWR {
                return Err(EACCES);
            }
            if !attrs.is_empty() {
                self.overlay
                    .as_ref()
                    .ok_or(EROFS)?
                    .set_metadata_file(file, &path, attrs)
                    .map_err(|e| e.raw_os_error().unwrap_or_else(|| io_to_errno(&e)))?;
            }
            if let Some(sz) = size {
                let ov = self.overlay.as_ref().ok_or(EROFS)?;
                ov.truncate_file(file, &path, sz)
                    .map_err(|e| io_to_errno(&e))?;
                if attrs.atime.is_some() || attrs.mtime.is_some() {
                    ov.set_metadata_file(
                        file,
                        &path,
                        &OverlayMetadata {
                            atime: attrs.atime,
                            mtime: attrs.mtime,
                            ..Default::default()
                        },
                    )
                    .map_err(|e| io_to_errno(&e))?;
                }
            }
            let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                return Err(EIO);
            }
            Ok((
                Duration::ZERO,
                self.mapped_attr(file_attr_from_stat(ino, &st)),
            ))
        })
    }

    fn snapshot_xattrs(&self, fi: Option<&FileInfo>) -> BTreeMap<String, Vec<u8>> {
        fi.map(|fi| {
            self.source
                .list_xattr(fi)
                .into_iter()
                .filter_map(|name| self.source.get_xattr(fi, &name).map(|value| (name, value)))
                .collect()
        })
        .unwrap_or_default()
    }

    /// `GETXATTR` body. `Ok(None)` is ENODATA / ENOATTR.
    fn xattr_value(&self, ino: u64, key: &str) -> Result<Option<Vec<u8>>, i32> {
        if let Some(detached) = self
            .inodes
            .lock()
            .unwrap()
            .get(&ino)
            .and_then(|entry| entry.detached.as_ref())
        {
            return Ok(detached.xattrs.get(key).cloned());
        }
        let fi = self.file_info_for_ino(ino).ok_or(ENOENT)?;
        if let (Some(overlay), Some(path)) = (&self.overlay, self.path_for_ino(ino)) {
            return overlay
                .xattrs_for_path(&path)
                .map(|mut attrs| attrs.remove(key))
                .map_err(|e| overlay_errno(&e));
        }
        Ok(self.source.get_xattr(&fi, key))
    }

    /// `LISTXATTR` body.
    fn xattr_list(&self, ino: u64) -> Result<Vec<String>, i32> {
        if let Some(detached) = self
            .inodes
            .lock()
            .unwrap()
            .get(&ino)
            .and_then(|entry| entry.detached.as_ref())
        {
            return Ok(detached.xattrs.keys().cloned().collect());
        }
        let fi = self.file_info_for_ino(ino).ok_or(ENOENT)?;
        if let (Some(overlay), Some(path)) = (&self.overlay, self.path_for_ino(ino)) {
            return overlay
                .xattrs_for_path(&path)
                .map(|attrs| attrs.into_keys().collect())
                .map_err(|e| overlay_errno(&e));
        }
        Ok(self.source.list_xattr(&fi))
    }

    #[cfg(test)]
    fn nlookup_of(&self, ino: u64) -> Option<u64> {
        self.inodes.lock().unwrap().get(&ino).map(|e| e.nlookup)
    }

    /// Install the parked-fd close counter before the rename or unlink that
    /// captures it onto [`Detached`].
    #[cfg(test)]
    fn track_parked_fd_drops(&self, counter: Arc<AtomicUsize>) {
        *self.park_fd_drops.lock().unwrap() = Some(counter);
    }

    #[cfg(test)]
    fn test_fh_is_overlay_fd(&self, fh: u64) -> bool {
        matches!(
            self.handles.lock().unwrap().get(&fh),
            Some(OpenBackend::OverlayFd(_))
        )
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
        reply.error(Errno::ERANGE);
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

/// Far-future saturation for absurd mtimes (2106-02-07). Crafted archives can
/// carry `inf`/`1e999` mtimes (PAX headers parse as f64); `SystemTime` addition
/// with a saturated `u64::MAX` seconds would panic, killing the daemon.
const FAR_FUTURE_SECS: u64 = u32::MAX as u64;

fn setattr_time(time: fuser::TimeOrNow, now: SystemTime) -> f64 {
    let time = match time {
        fuser::TimeOrNow::Now => now,
        fuser::TimeOrNow::SpecificTime(t) => t,
    };
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    }
}

fn unix_float_to_system_time(t: f64) -> SystemTime {
    if t <= 0.0 || t.is_nan() {
        return UNIX_EPOCH;
    }
    let secs = t.trunc() as u64;
    let nsec = ((t.fract()) * 1e9) as u32;
    UNIX_EPOCH
        .checked_add(Duration::new(secs, nsec))
        .unwrap_or(UNIX_EPOCH + Duration::new(FAR_FUTURE_SECS, 0))
}

/// Archive member the write overlay has not replaced.
///
/// Empty userdata is a create placeholder (size 0) and must not be pinned.
/// `overlay:` userdata is the host file and changes on write.
fn file_info_attr_stable(fi: &FileInfo) -> bool {
    !fi.userdata.is_empty()
        && !fi
            .userdata
            .iter()
            .any(|u| matches!(u, ratarmount_core::UserData::Other(s) if s.starts_with("overlay:")))
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Archive regular file whose reader is opened from `last_fi` (not a parked fd).
fn is_detached_archive_file(fi: &FileInfo) -> bool {
    file_info_attr_stable(fi) && (fi.mode & ratarmount_core::S_IFMT) == ratarmount_core::S_IFREG
}

/// `nlink` is forced to 0. Do not publish `st_nlink`.
fn file_attr_from_stat(ino: u64, st: &libc::stat) -> FileAttr {
    // `mode_t` is `u32` on Linux and `u16` on macOS.
    #[cfg(target_os = "macos")]
    let mode = u32::from(st.st_mode);
    #[cfg(not(target_os = "macos"))]
    let mode = st.st_mode;
    let size = u64::try_from(st.st_size).unwrap_or(0);
    let mtime = unix_float_to_system_time(st.st_mtime as f64 + st.st_mtime_nsec as f64 / 1e9);
    let atime = unix_float_to_system_time(st.st_atime as f64 + st.st_atime_nsec as f64 / 1e9);
    FileAttr {
        ino: INodeNo(ino),
        size,
        blocks: size.div_ceil(512),
        atime,
        mtime,
        ctime: mtime,
        crtime: mtime,
        kind: mode_to_kind(mode),
        perm: (mode & 0o7777) as u16,
        nlink: 0,
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: 0,
        blksize: BLKSIZE,
        flags: 0,
    }
}

/// Build the snapshot stored on a detached inode.
///
/// `pre_path` is the name before `InodeEntry.path` becomes `"\0stale-{ino}"`.
/// Archive `OpenBackend::Source::path` uses it. `drops` is moved onto the
/// parked fd when one exists (test close counter).
fn build_detached(
    ino: u64,
    pre_path: String,
    parked: Option<Parked>,
    snap: Option<FileInfo>,
    drops: Option<Arc<AtomicUsize>>,
    overlay: Option<Arc<WriteOverlay>>,
    xattrs: BTreeMap<String, Vec<u8>>,
) -> Detached {
    let (last_fi, raw_fd) = match parked {
        Some(parked) => {
            let (fi, fd) = parked.into_parts();
            (Some(fi), fd)
        }
        None => (snap, None),
    };
    if last_fi.is_none() {
        debug!("detach ino={ino} without FileInfo; getattr/open will return ENOENT");
    }
    #[cfg(not(test))]
    let _ = &drops;
    let fd = raw_fd.map(|owned| {
        if let Some(ov) = &overlay {
            ov.track_overlay_fd(owned.as_raw_fd());
        }
        ParkedFd {
            fd: owned,
            overlay,
            #[cfg(test)]
            drops,
        }
    });
    Detached {
        xattrs,
        fd,
        last_fi,
        path: pre_path,
    }
}

/// Store `detached` and, when the kernel holds no lookup reference, take the
/// entry out so the caller can drop the parked fd outside `inodes`.
fn install_detached(
    inodes: &mut HashMap<u64, InodeEntry>,
    ino: u64,
    detached: Detached,
) -> Option<InodeEntry> {
    let nlookup = {
        let ent = inodes.get_mut(&ino)?;
        ent.path = format!("\0stale-{ino}");
        ent.file_info = None;
        ent.cookie = None;
        ent.detached = Some(detached);
        ent.nlookup
    };
    if nlookup == 0 {
        inodes.remove(&ino)
    } else {
        None
    }
}

/// Reopen a parked descriptor read-only. Linux uses `/proc/self/fd` (the proc
/// entry is a symlink, so no `O_NOFOLLOW` and no `O_PATH`). Other unix dups
/// the already-readable fd.
fn reopen_parked_readonly(raw: libc::c_int) -> Result<libc::c_int, i32> {
    #[cfg(target_os = "linux")]
    {
        let path = std::ffi::CString::new(format!("/proc/self/fd/{raw}")).map_err(|_| EIO)?;
        // O_CLOEXEC so a later exec does not inherit the orphan.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            Err(io_to_errno(&std::io::Error::last_os_error()))
        } else {
            Ok(fd)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let fd = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            Err(io_to_errno(&std::io::Error::last_os_error()))
        } else {
            Ok(fd)
        }
    }
}

/// macOS `OPEN_MAX`. `libc` does not export that constant on apple.
#[cfg(target_os = "macos")]
const MACOS_OPEN_MAX: libc::rlim_t = 10_240;

/// Cap a macOS `RLIMIT_NOFILE` hard limit that may be `RLIM_INFINITY`.
///
/// Pure so the cap is tested on Linux. `open_max` is 10240 on macOS.
#[cfg(any(test, target_os = "macos"))]
fn nofile_soft_target(
    hard: libc::rlim_t,
    sysctl_maxfilesperproc: Option<libc::rlim_t>,
    open_max: libc::rlim_t,
) -> libc::rlim_t {
    let mut cap = open_max;
    if let Some(sys) = sysctl_maxfilesperproc {
        cap = cap.min(sys);
    }
    if hard != libc::RLIM_INFINITY {
        cap = cap.min(hard);
    }
    cap
}

fn nofile_target(hard: libc::rlim_t) -> libc::rlim_t {
    #[cfg(target_os = "macos")]
    {
        nofile_soft_target(hard, macos_maxfilesperproc(), MACOS_OPEN_MAX)
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Linux hard limits for NOFILE are finite. Do not cap by OPEN_MAX.
        hard
    }
}

#[cfg(target_os = "macos")]
fn macos_maxfilesperproc() -> Option<libc::rlim_t> {
    let mut val: i32 = 0;
    let mut len = std::mem::size_of::<i32>();
    let name = std::ffi::CString::new("kern.maxfilesperproc").unwrap();
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut val as *mut i32 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        warn!(
            "sysctl kern.maxfilesperproc failed: {}",
            std::io::Error::last_os_error()
        );
        None
    } else {
        Some(val as libc::rlim_t)
    }
}

/// Raise the soft `RLIMIT_NOFILE` up to the platform target. Failure is logged.
/// The mount continues: a later park then fails closed with `EMFILE`.
fn raise_nofile_soft_to_hard() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        warn!(
            "getrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    let target = nofile_target(lim.rlim_max);
    if lim.rlim_cur >= target {
        return;
    }
    let raised = libc::rlimit {
        rlim_cur: target,
        rlim_max: lim.rlim_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
        warn!(
            "setrlimit(RLIMIT_NOFILE) soft {} -> {target} (hard {}) failed: {}",
            lim.rlim_cur,
            lim.rlim_max,
            std::io::Error::last_os_error()
        );
    }
}

impl Filesystem for RatarmountFs {
    fn init(&mut self, _req: &Request, config: &mut fuser::KernelConfig) -> std::io::Result<()> {
        raise_nofile_soft_to_hard();
        if self.direct_io {
            self.passthrough.mode = PassthroughMode::Off;
            #[cfg(target_os = "linux")]
            if config
                .capabilities()
                .contains(fuser::InitFlags::FUSE_DIRECT_IO_ALLOW_MMAP)
            {
                let _ = config.add_capabilities(fuser::InitFlags::FUSE_DIRECT_IO_ALLOW_MMAP);
            }
        }
        #[cfg(target_os = "linux")]
        {
            let supported = config.kernel_abi() >= fuser::Version(7, 40)
                && config
                    .capabilities()
                    .contains(fuser::InitFlags::FUSE_PASSTHROUGH);
            let privileged = passthrough::linux::has_initial_sys_admin();
            #[cfg(test)]
            let privileged = self.passthrough_auto_privilege.unwrap_or(privileged);
            let eligible = self.passthrough_readonly_mount
                && (self.overlay.is_some() || self.source.supports_backing_extents());
            self.passthrough_enabled =
                passthrough::negotiate(self.passthrough.mode, supported, privileged && eligible)?;
            if self.passthrough_enabled {
                config.set_max_stack_depth(1).map_err(|_| {
                    std::io::Error::other("cannot configure FUSE passthrough stack depth")
                })?;
                config
                    .add_capabilities(fuser::InitFlags::FUSE_PASSTHROUGH)
                    .map_err(|_| std::io::Error::other("cannot negotiate FUSE passthrough"))?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.passthrough_enabled = passthrough::negotiate(self.passthrough.mode, false, false)?;
        }
        info!(
            "FUSE I/O mode: {}",
            if self.passthrough_enabled {
                "daemon until backing registration (passthrough negotiated)"
            } else {
                "daemon (passthrough off, unavailable, unprivileged, or no eligible source)"
            }
        );
        // fuser derives max_pages from max(max_write, max_readahead). Linux
        // kernels advertising MAX_PAGES can accept 256-page requests (1 MiB on
        // 4 KiB systems). Keep the former 32-page cap on older kernels.
        #[cfg(not(target_os = "macos"))]
        {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            let large = cfg!(target_os = "linux")
                && config
                    .capabilities()
                    .contains(fuser::InitFlags::FUSE_MAX_PAGES);
            let max_io = fuse_io_limit(u32::try_from(page_size).unwrap_or(4096), large);
            let _ = config.set_max_write(max_io);
            // Preserve the offered readahead when the kernel's cap is smaller.
            let readahead = match config.set_max_readahead(max_io) {
                Ok(_) => max_io,
                Err(offered) => offered,
            };
            info!("fuse-io-limits max_write={max_io} max_readahead={readahead} max_pages_supported={large}");
        }
        let _ = config.set_max_background(12);
        let _ = config.set_congestion_threshold(9);
        Ok(())
    }

    fn destroy(&mut self) {
        info!(
            "fuse-read-summary requests={} requested_bytes={} max_request={} service_ns={}",
            self.read_requests.load(Ordering::Relaxed),
            self.read_requested_bytes.load(Ordering::Relaxed),
            self.read_max_request.load(Ordering::Relaxed),
            self.read_service_ns.load(Ordering::Relaxed)
        );
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.forget_nlookup(ino.0, nlookup);
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.lookup_entry(parent.0, name) {
            Some((_, attr, ttl)) => reply.entry(&ttl, &attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.getattr_reply(ino.0) {
            Ok((ttl, attr)) => reply.attr(&ttl, &attr),
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(entries) = self.list_mode_cached(&path) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let mut full: Vec<(u64, FileType, String)> = Vec::new();
        full.push((ino.0, FileType::Directory, ".".into()));
        full.push((
            if path == "/" {
                ino.0
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
            let next_offset = (i + 1) as u64;
            if reply.add(INodeNo(cino), next_offset, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        // Cheap list_mode only — do not call MountSource::list (fat FileInfo map).
        // Full attrs (size/mtime/uid) are filled at getattr/lookup/open.
        // nlookup is not bumped; see [`RatarmountFs::readdirplus_fill`].
        match self.readdirplus_fill(ino.0, offset, |cino, off, name, ttl, attr| {
            reply.add(INodeNo(cino), off, name, ttl, attr, Generation(0))
        }) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        match self.open_inode(ino.0, flags.0) {
            Ok((fh, open_flags)) => {
                #[cfg(target_os = "linux")]
                if let Some(backing) = self.open_backing(ino.0, fh, flags.0, &reply) {
                    // KEEP_CACHE is invalid with PASSTHROUGH. The backing file
                    // has its own page cache; daemon replies keep their flags.
                    let flags =
                        FopenFlags::from_bits_retain(open_flags) & !FopenFlags::FOPEN_KEEP_CACHE;
                    reply.opened_passthrough(FileHandle(fh), flags, &backing.id);
                    self.flush_kernel_invals();
                    return;
                }
                reply.opened(FileHandle(fh), FopenFlags::from_bits_retain(open_flags));
                self.flush_kernel_invals();
            }
            Err(e) => {
                debug!("open error kind={e}");
                reply.error(Errno::from_i32(e));
            }
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.read_requests.fetch_add(1, Ordering::Relaxed);
        self.read_requested_bytes
            .fetch_add(u64::from(size), Ordering::Relaxed);
        self.read_max_request
            .fetch_max(u64::from(size), Ordering::Relaxed);
        let start = std::time::Instant::now();
        match self.read_handle(fh.0, (offset as i64).max(0), size) {
            Ok(buf) => reply.data(&buf),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
        self.read_service_ns
            .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.write_handle(ino.0, fh.0, (offset as i64).max(0), data) {
            Err(e) => reply.error(Errno::from_i32(e)),
            Ok(n) => {
                self.drop_stable_attr(ino.0);
                reply.written(n as u32);
                self.flush_kernel_invals();
            }
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        match self.create_masked_entry(parent.0, name, mode, umask) {
            Ok((ttl, attr, fh)) => {
                reply.created(
                    &ttl,
                    &attr,
                    Generation(0),
                    FileHandle(fh),
                    FopenFlags::empty(),
                );
                self.flush_kernel_invals();
            }
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if mode & ratarmount_core::S_IFMT != ratarmount_core::S_IFREG {
            reply.error(Errno::EOPNOTSUPP);
            return;
        }
        match self.create_masked_entry(parent.0, name, mode, umask) {
            Ok((ttl, attr, fh)) => {
                if let Some(OpenBackend::OverlayFd(fd)) = self.handles.lock().unwrap().remove(&fh) {
                    self.overlay.as_ref().unwrap().close_overlay_fd(fd);
                }
                reply.entry(&ttl, &attr, Generation(0));
                self.flush_kernel_invals();
            }
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        match self.mkdir_masked_entry(parent.0, name, mode, umask) {
            Ok((ttl, attr)) => {
                reply.entry(&ttl, &attr, Generation(0));
                self.flush_kernel_invals();
            }
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.remove_entry(parent.0, name, false) {
            Ok(()) => {
                reply.ok();
                self.flush_kernel_invals();
            }
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.remove_entry(parent.0, name, true) {
            Ok(()) => {
                reply.ok();
                self.flush_kernel_invals();
            }
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        self.rename_reply(
            parent.0,
            &name.to_string_lossy(),
            newparent.0,
            &newname.to_string_lossy(),
            flags.bits(),
            |result| match result {
                Ok(()) => reply.ok(),
                Err(errno) => reply.error(Errno::from_i32(errno)),
            },
        );
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let now = SystemTime::now();
        let attrs = OverlayMetadata {
            mode,
            uid,
            gid,
            atime: atime.map(|t| setattr_time(t, now)),
            mtime: mtime.map(|t| setattr_time(t, now)),
        };
        match self.setattr_metadata_entry(ino.0, size, fh.map(|fh| fh.0), &attrs) {
            Ok((ttl, attr)) => {
                reply.attr(&ttl, &attr);
                self.flush_kernel_invals();
            }
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        #[cfg(target_os = "linux")]
        self.backing_opens.lock().unwrap().release(fh.0);
        if let Some(OpenBackend::OverlayFd(fd)) = self.handles.lock().unwrap().remove(&fh.0) {
            if let Some(ov) = &self.overlay {
                ov.close_overlay_fd(fd);
            } else {
                unsafe {
                    libc::close(fd);
                }
            }
        }
        reply.ok();
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        // Same cache/overlay policy as getattr — do not force a second source.lookup.
        let Some(fi) = self.file_info_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        reply.data(fi.linkname.as_bytes());
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        let result = (|| {
            if position != 0 {
                return Err(EINVAL);
            }
            let overlay = self.overlay.as_ref().ok_or(EROFS)?;
            let path = self.path_for_ino(ino.0).ok_or(EACCES)?;
            let name = name.to_str().ok_or(EINVAL)?;
            // macFUSE passes the native CREATE=2/REPLACE=4 bits; the storage API
            // uses the Linux CREATE=1/REPLACE=2 encoding on every platform.
            #[cfg(target_os = "macos")]
            let flags = match flags {
                0 => 0,
                libc::XATTR_CREATE => 1,
                libc::XATTR_REPLACE => 2,
                _ => return Err(EINVAL),
            };
            overlay
                .set_xattr(&path, name, value, flags)
                .map_err(|e| match &e {
                    ratarmount_compositing::OverlayError::Io(e) => {
                        e.raw_os_error().unwrap_or_else(|| io_to_errno(e))
                    }
                    _ => EIO,
                })
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = (|| {
            let overlay = self.overlay.as_ref().ok_or(EROFS)?;
            let path = self.path_for_ino(ino.0).ok_or(EACCES)?;
            let name = name.to_str().ok_or(EINVAL)?;
            overlay.remove_xattr(&path, name).map_err(|e| match &e {
                ratarmount_compositing::OverlayError::Io(e) => {
                    e.raw_os_error().unwrap_or_else(|| io_to_errno(e))
                }
                _ => EIO,
            })
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let key = name.to_string_lossy();
        match self.xattr_value(ino.0, key.as_ref()) {
            Ok(Some(value)) => reply_xattr_bytes(size, &value, reply),
            Err(errno) => reply.error(Errno::from_i32(errno)),
            Ok(None) => {
                // Linux: ENODATA; macOS/BSD: ENOATTR (same numeric value on many systems).
                #[cfg(target_os = "linux")]
                reply.error(Errno::ENODATA);
                #[cfg(not(target_os = "linux"))]
                reply.error(Errno::ENOATTR);
            }
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        match self.xattr_list(ino.0) {
            Ok(keys) => {
                let bytes = encode_xattr_list(&keys);
                reply_xattr_bytes(size, &bytes, reply);
            }
            Err(errno) => reply.error(Errno::from_i32(errno)),
        }
    }
}

/// Parse a Python-style `-o` / `--fuse` comma-separated option string into `MountOption`s.
///
/// Ownership and umask options are consumed by [`AttributeMapping`].
/// Other unknown tokens become `MountOption::CUSTOM` (passed through to libfuse/kernel).
/// `allow_root` and `allow_other` are also CUSTOM here; [`mount_blocking`]
/// extracts them into the session ACL before mounting.
pub fn parse_fuse_options(s: &str) -> Vec<MountOption> {
    s.split(',')
        .map(str::trim)
        .filter(|t| {
            !t.is_empty()
                && !["uid=", "gid=", "umask="]
                    .iter()
                    .any(|key| t.starts_with(key))
        })
        .map(mount_option_from_str)
        .collect()
}

/// Whether fuse.conf explicitly permits non-root allow_other mounts.
pub fn fuse_conf_allows_other(contents: &str) -> bool {
    contents
        .lines()
        .any(|line| line.split('#').next().unwrap_or_default().trim() == "user_allow_other")
}

/// Validate before opening /dev/fuse so fusermount's diagnostic is actionable.
pub fn validate_allow_other(options: &str) -> std::io::Result<()> {
    validate_allow_other_with(
        options,
        unsafe { libc::geteuid() },
        Path::new("/etc/fuse.conf"),
    )
}

fn validate_allow_other_with(options: &str, uid: u32, config: &Path) -> std::io::Result<()> {
    if uid == 0
        || !options
            .split(',')
            .map(str::trim)
            .any(|option| option == "allow_other")
    {
        return Ok(());
    }
    let allowed = match std::fs::read_to_string(config) {
        Ok(contents) => fuse_conf_allows_other(&contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(std::io::Error::new(error.kind(), format!("cannot read {}: {error}; allow_other requires the line user_allow_other in /etc/fuse.conf", config.display()))),
    };
    if allowed {
        Ok(())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
            "allow_other requested by a non-root user: add the uncommented line user_allow_other to /etc/fuse.conf"))
    }
}

fn mount_option_from_str(s: &str) -> MountOption {
    match s {
        "auto_unmount" => MountOption::AutoUnmount,
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

/// Preserve the libfuse option and access policy used before fuser 0.18.
fn mount_config(writable: bool, extra_fuse_opts: &str) -> Config {
    let mut options = vec![MountOption::FSName("ratarmount".into()), MountOption::Exec];
    if !writable {
        options.push(MountOption::RO);
    }
    let mut acl = SessionACL::Owner;
    for opt in parse_fuse_options(extra_fuse_opts) {
        // User `-o rw` can override default RO for writable overlays; for RO mounts keep RO.
        match &opt {
            MountOption::CUSTOM(value) if value == "allow_root" => {
                acl = SessionACL::RootAndOwner;
                continue;
            }
            MountOption::CUSTOM(value) if value == "allow_other" => {
                if acl != SessionACL::RootAndOwner {
                    acl = SessionACL::All;
                }
                continue;
            }
            MountOption::RW if !writable => continue,
            MountOption::RO => {}
            MountOption::FSName(_) => {
                // Prefer user-supplied fsname if present.
                options.retain(|o| !matches!(o, MountOption::FSName(_)));
            }
            _ => {}
        }
        // Session::new now rejects conflicting flags; libfuse previously
        // applied them in order. Keep that last-option-wins behavior.
        options.retain(|old| !mount_options_conflict(old, &opt));
        options.push(opt);
    }
    if acl == SessionACL::Owner {
        for opt in &mut options {
            if *opt == MountOption::AutoUnmount {
                // 0.15 passed allow_other to libfuse but enforced Owner in
                // userspace. 0.18 rejects typed AutoUnmount + Owner, so pass
                // the libfuse option verbatim and keep the same userspace ACL.
                *opt = MountOption::CUSTOM("auto_unmount".into());
            }
        }
        if options.contains(&MountOption::CUSTOM("auto_unmount".into())) {
            options.push(MountOption::CUSTOM("allow_other".into()));
        }
    }
    let mut config = Config::default();
    config.mount_options = options;
    config.acl = acl;
    // Detached raw fds and notification ordering rely on serial requests.
    config.n_threads = Some(1);
    config.clone_fd = false;
    config
}

fn mount_options_conflict(a: &MountOption, b: &MountOption) -> bool {
    use MountOption::*;
    matches!(
        (a, b),
        (RO, RW)
            | (RW, RO)
            | (Dev, NoDev)
            | (NoDev, Dev)
            | (Suid, NoSuid)
            | (NoSuid, Suid)
            | (Exec, NoExec)
            | (NoExec, Exec)
            | (Atime, NoAtime)
            | (NoAtime, Atime)
            | (Sync, Async)
            | (Async, Sync)
    )
}

/// `Session::run` outcome after the mount has been established.
///
/// fuser turns `ENODEV` into `Ok` and returns every other `read` errno.
/// Upstream fuser treats `ECONNABORTED` as the same clean end of session
/// (cberner/fuser#212). The kernel returns it when the connection is aborted,
/// including a normal unmount that wins the race in `fuse_dev_do_read` after
/// a request is dequeued and before it is copied (`!fpq->connected` yields
/// `-ECONNABORTED` even when `abort_with_err` is false). Hundreds of in-flight
/// `FORGET`s make that window likely. Other errnos stay failures.
fn fuse_session_result(res: std::io::Result<()>) -> std::io::Result<()> {
    match res {
        Err(err) if err.raw_os_error() == Some(libc::ECONNABORTED) => {
            info!(
                "FUSE session read returned ECONNABORTED at unmount; treating it as a clean exit"
            );
            Ok(())
        }
        other => other,
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
    mount_blocking_with_passthrough(
        source,
        mountpoint,
        foreground,
        writable,
        overlay,
        extra_fuse_opts,
        readahead,
        PassthroughOptions::default(),
    )
}

/// Like [`mount_blocking`], with explicit passthrough settings.
#[allow(clippy::too_many_arguments)]
pub fn mount_blocking_with_passthrough(
    source: Arc<dyn MountSource>,
    mountpoint: impl AsRef<Path>,
    foreground: bool,
    writable: bool,
    overlay: Option<Arc<WriteOverlay>>,
    extra_fuse_opts: &str,
    readahead: u64,
    passthrough: PassthroughOptions,
) -> std::io::Result<()> {
    mount_blocking_with_io_options(
        source,
        mountpoint,
        foreground,
        writable,
        overlay,
        extra_fuse_opts,
        readahead,
        passthrough,
        false,
    )
}

/// Like [`mount_blocking_with_passthrough`], with an opt-in direct-I/O policy.
#[allow(clippy::too_many_arguments)]
pub fn mount_blocking_with_io_options(
    source: Arc<dyn MountSource>,
    mountpoint: impl AsRef<Path>,
    foreground: bool,
    writable: bool,
    overlay: Option<Arc<WriteOverlay>>,
    extra_fuse_opts: &str,
    readahead: u64,
    mut passthrough: PassthroughOptions,
    direct_io: bool,
) -> std::io::Result<()> {
    if direct_io {
        passthrough.mode = PassthroughMode::Off;
    }
    let mapping = AttributeMapping::parse(extra_fuse_opts)
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    validate_allow_other(extra_fuse_opts)?;
    let config = mount_config(writable, extra_fuse_opts);
    let _ = foreground;
    // Idempotent with `Filesystem::init`. In place before `Session::new`.
    raise_nofile_soft_to_hard();
    let mut fs = RatarmountFs::with_readahead(source, overlay, readahead)
        .with_passthrough(passthrough)
        .with_attribute_mapping(mapping)
        .with_direct_io(direct_io);
    fs.passthrough_readonly_mount = config.mount_options.contains(&MountOption::RO);
    // `mount` does not hand back `Session::notifier`. The notifier thread
    // must exist before `run` so a shadowed archive member can drop a 60s
    // kernel cache, and so those writes never run on the request thread.
    //
    // `run` consumes the session and unmounts before returning. Then drop
    // the sender and join the notifier, whose fd is independently owned.
    // No notification shares a lock with libfuse.
    // `run` also drops the mount on a malformed request. A notify parked on
    // a directory `i_rwsem` returns once the holder drops that lock; the holder was
    // waiting on a reply the session thread sent before `run` returned.
    // After unmount a further write fails with `ENODEV` or `ECONNABORTED`
    // (thread exits), and the dropped sender ends `recv`.
    let kernel_notify = Arc::clone(&fs.kernel_notify);
    let session = fuser::Session::new(fs, mountpoint.as_ref(), &config)?;
    #[cfg(target_os = "linux")]
    if passthrough.mode == PassthroughMode::On {
        passthrough::linux::probe(&session)?;
    }
    let (tx, notifier_thread) = spawn_notifier(session.notifier());
    kernel_notify.install(tx);
    let res = fuse_session_result(session.run());
    kernel_notify.clear();
    let _ = notifier_thread.join();
    res
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

/// Retry schedule for a busy `fusermount3 -u`.
#[cfg(not(target_os = "macos"))]
#[derive(Clone, Copy)]
struct RetryPolicy {
    interval: Duration,
    deadline: Duration,
}

/// Desktop mount watchers (gvfsd-trash probes `.Trash*` on every new mount) hold
/// the mount for a few milliseconds; 50 ms steps over about a second ride that out.
#[cfg(not(target_os = "macos"))]
const UNMOUNT_RETRY: RetryPolicy = RetryPolicy {
    interval: Duration::from_millis(50),
    deadline: Duration::from_secs(1),
};

/// Linux: `fusermount3 -u` (or `fusermount -u` when fusermount3 cannot be spawned),
/// retried while the kernel reports the mount busy.
#[cfg(not(target_os = "macos"))]
fn unmount_linux(mp: &Path) -> std::io::Result<()> {
    unmount_linux_with(mp, &["-u"], UNMOUNT_RETRY, &mut run_fusermount, &mut |m| {
        debug!("{m}")
    })
}

/// Lazy detach (`fusermount3 -u -z`), one attempt. A last resort for callers that
/// must not leave the mount attached, such as the SIGTERM path.
#[cfg(not(target_os = "macos"))]
pub fn unmount_lazy(mountpoint: impl AsRef<Path>) -> std::io::Result<()> {
    let no_retry = RetryPolicy {
        interval: Duration::ZERO,
        deadline: Duration::ZERO,
    };
    unmount_linux_with(
        mountpoint.as_ref(),
        &["-u", "-z"],
        no_retry,
        &mut run_fusermount,
        &mut |m| debug!("{m}"),
    )
}

/// macOS has no lazy unmount; `unmount_macos` already ends in `diskutil unmount force`.
#[cfg(target_os = "macos")]
pub fn unmount_lazy(mountpoint: impl AsRef<Path>) -> std::io::Result<()> {
    unmount_macos(mountpoint.as_ref())
}

/// One `fusermount3` run with a stable locale, so the "busy" match is reliable.
#[cfg(not(target_os = "macos"))]
fn run_fusermount(args: &[&OsStr]) -> std::io::Result<std::process::Output> {
    let run = |prog: &str| {
        std::process::Command::new(prog)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
    };
    run("fusermount3").or_else(|_| run("fusermount"))
}

/// True when fusermount reported EBUSY. fusermount prints `failed to unmount <path>: <strerror>`
/// with the strerror last (under `LC_ALL=C`), so only the very end of stderr is the diagnostic;
/// the echoed path (which may contain the phrase, a newline, or be a bare word) is never stripped.
#[cfg(not(target_os = "macos"))]
fn is_busy_diagnostic(stderr: &str) -> bool {
    let end = stderr.trim_end();
    end.ends_with(": Device or resource busy") || end.ends_with(": Resource busy")
}

#[cfg(not(target_os = "macos"))]
fn unmount_linux_with(
    mp: &Path,
    flags: &[&str],
    retry: RetryPolicy,
    run: &mut dyn FnMut(&[&OsStr]) -> std::io::Result<std::process::Output>,
    note: &mut dyn FnMut(&str),
) -> std::io::Result<()> {
    let mut args: Vec<&OsStr> = flags.iter().map(OsStr::new).collect();
    args.push(mp.as_os_str());
    let start = std::time::Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let out = run(&args)?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let last = stderr
            .lines()
            .map(str::trim)
            .rfind(|l| !l.is_empty())
            .unwrap_or("");
        let detail = if last.is_empty() {
            out.status.to_string()
        } else {
            last.to_string()
        };
        if !is_busy_diagnostic(&stderr) {
            return Err(std::io::Error::other(format!(
                "fusermount failed for {}: {detail}",
                mp.display()
            )));
        }
        note(&format!(
            "fusermount3 -u {}: busy (attempt {attempts}), retrying",
            mp.display()
        ));
        if start.elapsed() + retry.interval > retry.deadline {
            return Err(std::io::Error::new(
                ErrorKind::ResourceBusy,
                format!(
                    "fusermount failed for {}: {detail} (still busy after {attempts} attempts \
                     over ~{}ms)",
                    mp.display(),
                    start.elapsed().as_millis()
                ),
            ));
        }
        std::thread::sleep(retry.interval);
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

    /// Regression: a tiny memory budget must degrade without corrupting reads.
    #[test]
    fn regression_memory_budget_readahead_degrades() {
        let name = std::thread::current().name().unwrap().to_string();
        if std::env::var("RATARMOUNT_BUDGET_TEST").ok().as_deref() != Some(&name) {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env("RATARMOUNT_BUDGET_TEST", &name)
                .status()
                .unwrap()
                .success());
            return;
        }
        ratarmount_core::budget::MemoryBudget::install(32768).unwrap();

        let bytes = vec![37; 8192];
        let mut reader = std::io::Cursor::new(bytes.clone());
        let mut state = ReadaheadState::default();
        for offset in (0..8192).step_by(512) {
            assert_eq!(
                readahead_fill(&mut reader, &mut state, 8192, offset as u64, 512).unwrap(),
                bytes[offset..offset + 512]
            );
            assert!(state.window.lock().unwrap().is_none());
        }
        assert_eq!(
            ratarmount_core::budget::MemoryBudget::global()
                .snapshot()
                .reserved,
            0
        );
        assert_eq!(
            readahead_fill(&mut reader, &mut state, 2048, 0, 512).unwrap(),
            bytes[..512]
        );
        assert!(state.window.lock().unwrap().is_some());
        let pool = ratarmount_core::budget::MemoryPool::global(
            "fuse-readahead",
            MAX_READAHEAD_BYTES,
            ratarmount_core::budget::Priority::Speculative,
        );
        let held = pool.reserve(4096).unwrap();
        assert!(state.window.lock().unwrap().is_none());
        drop(held);
        assert_eq!(
            readahead_fill(&mut reader, &mut state, 2048, 512, 512).unwrap(),
            bytes[512..1024]
        );
    }
    /// Regression: policy errors and Darwin ENOTSUP must preserve historical errno mapping.
    #[test]
    fn regression_io_to_errno_preserves_legacy_raw_errors() {
        for (raw, expected) in [
            (libc::EPERM, libc::EACCES),
            (libc::EACCES, libc::EACCES),
            (libc::EOPNOTSUPP, libc::ENOSYS),
            (libc::ENOTSUP, libc::ENOSYS),
            (libc::ENOTEMPTY, libc::ENOTEMPTY),
            (libc::ENOTDIR, libc::ENOTDIR),
            (libc::ELOOP, libc::ELOOP),
            (libc::EXDEV, libc::EXDEV),
            (libc::EBUSY, libc::EBUSY),
            (libc::EMFILE, libc::EMFILE),
            (libc::ENFILE, libc::ENFILE),
            (libc::EROFS, libc::EROFS),
            (libc::EDQUOT, libc::EDQUOT),
            (libc::ENOSPC, libc::ENOSPC),
        ] {
            assert_eq!(
                io_to_errno(&std::io::Error::from_raw_os_error(raw)),
                expected,
                "raw {raw}"
            );
        }
    }

    use super::*;
    use ratarmount_core::{
        ListModeResult, ListResult, MountSource, UserData, S_IFLNK, S_IFMT, S_IFREG,
    };
    use std::collections::BTreeMap;
    use std::io::{self, Seek};
    use std::process::Command;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    /// Regression: orphan growth stays charged through RELEASE until parked/read fds close.
    #[test]
    fn regression_orphan_quota_survives_release_until_forget() {
        struct Quota(AtomicU64);
        impl ratarmount_compositing::OverlayPolicy for Quota {
            fn check_mutation(
                &self,
                _: ratarmount_compositing::OverlayMutation,
                _: &[&str],
            ) -> io::Result<()> {
                Ok(())
            }
            fn check_write(&self, _: &str, offset: u64, len: u64, current: u64) -> io::Result<()> {
                if self.0.load(Ordering::SeqCst) + (offset + len).saturating_sub(current) > 4 {
                    return Err(io::ErrorKind::QuotaExceeded.into());
                }
                Ok(())
            }
            fn bytes_changed(&self, _: &str, added: u64, removed: u64) {
                self.0.fetch_add(added, Ordering::SeqCst);
                self.0.fetch_sub(removed, Ordering::SeqCst);
            }
        }
        let td = tempfile::tempdir().unwrap();
        let quota = Arc::new(Quota(AtomicU64::new(0)));
        let mut ov = WriteOverlay::new(Arc::new(EmptyBase), td.path()).unwrap();
        ov.set_policy(Some(quota.clone()));
        ov.close_overlay_fd(ov.create_file("/file", 0o644).unwrap());
        let ov = Arc::new(ov);
        let fs = RatarmountFs::new(ov.clone(), Some(ov.clone()));
        let ino = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("file")).unwrap().0;
        let (writer, _) = fs.open_inode(ino, libc::O_RDWR).unwrap();
        fs.remove_entry(FUSE_ROOT_ID, OsStr::new("file"), false)
            .unwrap();
        fs.write_handle(ino, writer, 0, b"data").unwrap();
        if let Some(OpenBackend::OverlayFd(fd)) = fs.handles.lock().unwrap().remove(&writer) {
            ov.close_overlay_fd(fd);
        }
        assert_eq!(quota.0.load(Ordering::SeqCst), 4);
        let (reader, _) = fs.open_inode(ino, libc::O_RDONLY).unwrap();
        fs.forget_nlookup(ino, 1);
        assert_eq!(
            quota.0.load(Ordering::SeqCst),
            4,
            "read descriptor retains charge after FORGET"
        );
        if let Some(OpenBackend::OverlayFd(fd)) = fs.handles.lock().unwrap().remove(&reader) {
            ov.close_overlay_fd(fd);
        }
        assert_eq!(quota.0.load(Ordering::SeqCst), 0);
    }

    /// Regression: WRITE keeps EIO for ordinary pwrite failures and missing inodes.
    #[test]
    fn regression_write_handle_keeps_legacy_eio() {
        let td = tempfile::tempdir().unwrap();
        let ov = Arc::new(WriteOverlay::new(Arc::new(EmptyBase), td.path()).unwrap());
        ov.close_overlay_fd(ov.create_file("/file", 0o644).unwrap());
        let fs = RatarmountFs::new(ov.clone(), Some(ov));
        let ino = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("file")).unwrap().0;
        let (fh, _) = fs.open_inode(ino, libc::O_RDONLY).unwrap();
        assert_eq!(fs.write_handle(ino, fh, 0, b"x"), Err(EIO));
        assert_eq!(fs.write_handle(u64::MAX, fh, 0, b"x"), Err(EIO));
    }

    /// Regression: WRITE and detached SETATTR must release handles before policy/I/O.
    #[test]
    fn regression_overlay_io_releases_handle_table() {
        struct Probe(Mutex<std::sync::Weak<RatarmountFs>>);
        impl ratarmount_compositing::OverlayPolicy for Probe {
            fn check_mutation(
                &self,
                op: ratarmount_compositing::OverlayMutation,
                _: &[&str],
            ) -> io::Result<()> {
                if matches!(
                    op,
                    ratarmount_compositing::OverlayMutation::Write
                        | ratarmount_compositing::OverlayMutation::Truncate
                ) {
                    let fs = self.0.lock().unwrap().upgrade().unwrap();
                    assert!(
                        fs.handles.try_lock().is_ok(),
                        "handle table held during I/O"
                    );
                }
                Ok(())
            }
            fn check_write(&self, _: &str, _: u64, _: u64, _: u64) -> io::Result<()> {
                Ok(())
            }
        }
        let td = tempfile::tempdir().unwrap();
        let probe = Arc::new(Probe(Mutex::new(std::sync::Weak::new())));
        let mut ov = WriteOverlay::new(Arc::new(EmptyBase), td.path()).unwrap();
        ov.close_overlay_fd(ov.create_file("/file", 0o644).unwrap());
        ov.set_policy(Some(probe.clone()));
        let ov = Arc::new(ov);
        let fs = Arc::new(RatarmountFs::new(ov.clone(), Some(ov)));
        *probe.0.lock().unwrap() = Arc::downgrade(&fs);
        let ino = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("file")).unwrap().0;
        let (fh, _) = fs.open_inode(ino, libc::O_RDWR).unwrap();
        assert_eq!(fs.write_handle(ino, fh, 0, b"data"), Ok(4));
        fs.remove_entry(FUSE_ROOT_ID, OsStr::new("file"), false)
            .unwrap();
        fs.setattr_entry(ino, Some(8), Some(fh)).unwrap();
    }

    struct TestPolicy;
    impl ratarmount_compositing::OverlayPolicy for TestPolicy {
        fn check_mutation(
            &self,
            _: ratarmount_compositing::OverlayMutation,
            paths: &[&str],
        ) -> io::Result<()> {
            if paths
                .iter()
                .any(|p| *p == "/locked" || p.starts_with("/locked/"))
            {
                return Err(io::Error::new(
                    io::ErrorKind::ReadOnlyFilesystem,
                    "policy read-only path",
                ));
            }
            Ok(())
        }
        fn check_write(
            &self,
            path: &str,
            offset: u64,
            len: u64,
            current_size: u64,
        ) -> io::Result<()> {
            if path == "/quota" && offset.saturating_add(len) > current_size.max(2) {
                return Err(io::Error::new(io::ErrorKind::QuotaExceeded, "policy quota"));
            }
            Ok(())
        }
    }

    /// Regression: an empty open must not expose a host file that grew after lookup.
    #[cfg(target_os = "linux")]
    #[test]
    fn passthrough_empty_open_stays_empty_after_host_growth() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty");
        std::fs::write(&path, b"").unwrap();
        let source = Arc::new(ratarmount_compositing::FolderMountSource::new(dir.path()).unwrap());
        let fs = RatarmountFs::new(source, None);
        let ino = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("empty"))
            .unwrap()
            .0;
        let (fh, _) = fs.open_inode(ino, libc::O_RDONLY).unwrap();
        assert!(matches!(
            fs.handles.lock().unwrap().get(&fh),
            Some(OpenBackend::Empty)
        ));
        std::fs::write(path, b"must remain invisible to this empty handle").unwrap();
        assert!(fs
            .passthrough_file(ino, fh, libc::O_RDONLY)
            .unwrap()
            .is_none());
        assert!(fs.read_handle(fh, 0, 4096).unwrap().is_empty());
    }

    /// Regression: passthrough must not bypass overlay policy, including a later writer.
    #[cfg(target_os = "linux")]
    #[test]
    fn passthrough_overlay_policy_keeps_writable_mount_on_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let mut overlay = WriteOverlay::new(Arc::new(EmptyBase), dir.path()).unwrap();
        let fd = overlay.create_file("/file", 0o644).unwrap();
        overlay.close_overlay_fd(fd);
        std::fs::write(dir.path().join("file"), b"payload").unwrap();
        overlay.set_policy(Some(Arc::new(TestPolicy)));
        let overlay = Arc::new(overlay);
        let mut fs = RatarmountFs::new(overlay.clone(), Some(overlay.clone()));
        let ino = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("file")).unwrap().0;
        let (fh, _) = fs.open_inode(ino, libc::O_RDONLY).unwrap();
        assert!(fs
            .passthrough_file(ino, fh, libc::O_RDONLY)
            .unwrap()
            .is_none());
        assert!(fs
            .passthrough_file(ino, fh, libc::O_RDWR)
            .unwrap()
            .is_none());
        // A kernel-enforced RO mount cannot open a writer. Its RO fd is safe,
        // even with a policy installed; no write/accounting funnel is bypassed.
        fs.passthrough_readonly_mount = true;
        let file = fs
            .passthrough_file(ino, fh, libc::O_RDONLY)
            .unwrap()
            .unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            file.file.metadata().unwrap().ino(),
            std::fs::metadata(dir.path().join("file")).unwrap().ino()
        );
        assert!(fs
            .passthrough_file(ino, fh, libc::O_RDWR)
            .unwrap()
            .is_none());
        if let Some(OpenBackend::OverlayFd(fd)) = fs.handles.lock().unwrap().remove(&fh) {
            overlay.close_overlay_fd(fd);
        };
    }

    /// Regression: FUSE data writes and namespace mutations preserve policy errnos.
    #[test]
    fn regression_overlay_policy_denials() {
        let td = tempfile::tempdir().unwrap();
        let mut ov = WriteOverlay::new(Arc::new(EmptyBase), td.path()).unwrap();
        ov.mkdir("/locked", 0o755).unwrap();
        ov.mkdir("/locked/empty", 0o755).unwrap();
        for path in ["/locked/file", "/outside", "/quota"] {
            let fd = ov.create_file(path, 0o644).unwrap();
            ov.close_overlay_fd(fd);
        }
        ov.set_policy(Some(Arc::new(TestPolicy)));
        let ov = Arc::new(ov);

        let fd = {
            // A pre-existing writable handle must still consult the policy.
            use std::os::fd::IntoRawFd;
            std::fs::OpenOptions::new()
                .write(true)
                .open(td.path().join("locked/file"))
                .unwrap()
                .into_raw_fd()
        };
        let fs = RatarmountFs::new(ov.clone(), Some(ov));
        let locked = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("locked"))
            .unwrap()
            .0;
        let file = fs.lookup_entry(locked, OsStr::new("file")).unwrap().0;
        let quota = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("quota"))
            .unwrap()
            .0;
        fs.handles
            .lock()
            .unwrap()
            .insert(999, OpenBackend::OverlayFd(fd));
        assert_eq!(
            fs.write_handle(file, 999, 0, b"x").unwrap_err(),
            libc::EROFS
        );
        assert_eq!(
            fs.create_entry(locked, OsStr::new("new"), 0o644)
                .unwrap_err(),
            libc::EROFS
        );
        assert_eq!(
            fs.setattr_entry(file, Some(3), None).unwrap_err(),
            libc::EROFS
        );
        assert_eq!(
            fs.rename_paths(locked, "file", FUSE_ROOT_ID, "moved", 0)
                .unwrap_err(),
            libc::EROFS
        );
        assert_eq!(
            fs.rename_paths(FUSE_ROOT_ID, "outside", locked, "file", 0)
                .unwrap_err(),
            libc::EROFS
        );
        assert_eq!(
            fs.remove_entry(locked, OsStr::new("file"), false)
                .unwrap_err(),
            libc::EROFS
        );
        assert_eq!(
            fs.mkdir_entry(locked, OsStr::new("newdir"), 0o755)
                .unwrap_err(),
            libc::EROFS
        );
        assert_eq!(
            fs.remove_entry(locked, OsStr::new("empty"), true)
                .unwrap_err(),
            libc::EROFS
        );
        let (fh, _) = fs.open_inode(quota, libc::O_RDWR).unwrap();
        assert_eq!(
            fs.write_handle(quota, fh, 0, b"abc").unwrap_err(),
            libc::EDQUOT
        );
        assert_eq!(fs.write_handle(quota, fh, 0, b"ab").unwrap(), 2);
        fs.remove_entry(FUSE_ROOT_ID, OsStr::new("quota"), false)
            .unwrap();
        assert_eq!(
            fs.write_handle(quota, fh, 2, b"c").unwrap_err(),
            libc::EDQUOT
        );
        assert_eq!(
            fs.setattr_entry(quota, Some(3), Some(fh)).unwrap_err(),
            libc::EDQUOT
        );
        assert_eq!(fs.read_handle(fh, 0, 8).unwrap(), b"ab");
        for (kind, errno) in [
            (ErrorKind::ReadOnlyFilesystem, libc::EROFS),
            (ErrorKind::QuotaExceeded, libc::EDQUOT),
            (ErrorKind::StorageFull, libc::ENOSPC),
        ] {
            assert_eq!(io_to_errno(&io::Error::new(kind, "policy")), errno);
        }
    }

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

    /// Regression: crafted mtime `inf` / `1e999` / NaN must saturate, not
    /// panic in `SystemTime` addition (daemon crash via a PAX header).
    #[test]
    fn unix_float_to_system_time_extreme_saturates_without_panic() {
        let far = unix_float_to_system_time(f64::INFINITY);
        assert_eq!(
            far.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            FAR_FUTURE_SECS
        );
        let huge = unix_float_to_system_time(1e300);
        assert_eq!(
            huge.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            FAR_FUTURE_SECS
        );
        assert_eq!(unix_float_to_system_time(f64::NAN), UNIX_EPOCH);
        // u64::MAX seconds would overflow SystemTime on every platform.
        let maxed = unix_float_to_system_time(u64::MAX as f64);
        assert!(maxed.duration_since(UNIX_EPOCH).is_ok());
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
            fs.attr_ttl_for_fi(&fi),
            OVERLAY_ATTR_TTL,
            "overlay-backed file must not pin a long kernel attr TTL"
        );
        // After refresh, overlay inode stores a cookie (not a fat FileInfo).
        let cached = fs.cached_cookie(ino).expect("cached cookie after refresh");
        assert_eq!(cached.size, b"hello-overlay-payload".len() as u64);
        assert!(
            fs.cached_fi(ino).is_none(),
            "overlay child must not keep a fat FileInfo beside the cookie"
        );
        assert!(ov.has_file("/new.txt"));
        let rfd = ov
            .open_overlay_fd("/new.txt", libc::O_RDONLY)
            .expect("overlay open");
        let mut rf = unsafe { std::fs::File::from_raw_fd(rfd) };
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut rf, &mut buf).unwrap();
        assert_eq!(buf, b"hello-overlay-payload");
    }

    /// Regression: write-then-cat empty when open skipped OverlayFd.
    ///
    /// Goes through production [`RatarmountFs::open_inode`] (`has_file` →
    /// OverlayFd). Do not use [`RatarmountFs::test_open_ro`] — that helper
    /// skips `has_file` and goes `file_info_for_open` + `open_source_backend`.
    #[test]
    fn overlay_open_after_create_write() {
        use ratarmount_compositing::WriteOverlay;
        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fd = ov.create_file("/new.txt", 0o644).expect("create");
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        f.write_all(b"hello-overlay-payload").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        assert!(
            ov.has_file("/new.txt"),
            "production open must take the has_file → OverlayFd branch"
        );
        let ino = fs.ino_for_path("/new.txt");
        let (fh, _) = fs.open_inode(ino, libc::O_RDONLY).expect("production open");
        assert!(
            fs.test_fh_is_overlay_fd(fh),
            "has_file must open OverlayFd, not Empty/Source"
        );
        let buf = fs.read_handle(fh, 0, 64).expect("read");
        assert_eq!(
            buf, b"hello-overlay-payload",
            "write-then-cat must not return empty"
        );
        assert_ne!(buf, b"", "payload must not be empty after write");
    }

    /// Opposite polarity of the size-0 cache bug: create with no write, then
    /// production open/read must return "".
    #[test]
    fn overlay_open_after_create_reads_empty() {
        use ratarmount_compositing::WriteOverlay;
        use std::os::unix::io::FromRawFd;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fd = ov.create_file("/empty.txt", 0o644).expect("create");
        drop(unsafe { std::fs::File::from_raw_fd(fd) });

        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        assert!(ov.has_file("/empty.txt"));
        let ino = fs.ino_for_path("/empty.txt");
        let (fh, _) = fs.open_inode(ino, libc::O_RDONLY).expect("production open");
        assert!(
            fs.test_fh_is_overlay_fd(fh),
            "never-written overlay file still opens OverlayFd"
        );
        let buf = fs.read_handle(fh, 0, 64).expect("read");
        assert_eq!(buf, b"", "never-written overlay file must read empty");
    }

    /// After overlay lookup/store, the inode holds a cookie only — not a fat
    /// FileInfo (and never both `Some`).
    #[test]
    fn overlay_store_cookie_without_file_info() {
        use ratarmount_compositing::WriteOverlay;
        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fd = ov.create_file("/cookie.txt", 0o644).expect("create");
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        f.write_all(b"payload").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        let looked = fs.source.lookup("/cookie.txt", 0).expect("lookup");
        let ino = fs.ino_for_path_with_fi("/cookie.txt", Some(looked.clone()));
        assert!(
            fs.cached_cookie(ino).is_some(),
            "overlay store must write a cookie"
        );
        assert!(
            fs.cached_fi(ino).is_none(),
            "overlay child must not keep fat FileInfo"
        );
        assert_eq!(
            fs.cached_cookie(ino).unwrap().size,
            looked.size,
            "cookie size must match the lookup FileInfo"
        );
        assert_eq!(fs.cached_cookie(ino).unwrap().size, b"payload".len() as u64);
    }

    /// Regression: a write mount re-queried the archive index on every stat of
    /// an unmodified member, because the kernel attr TTL was 0 for the whole
    /// mount. Unshadowed members keep a fat `FileInfo` and the 60s TTL. A
    /// write still drops that cache so the next stat sees the overlay size.
    #[test]
    fn overlay_archive_member_stat_skips_repeat_lookup() {
        use ratarmount_compositing::WriteOverlay;
        use std::sync::atomic::{AtomicU64, Ordering};

        struct CountingTar {
            lookups: Arc<AtomicU64>,
            opens: Arc<AtomicU64>,
        }

        fn tar_file(size: u64, offset: u64) -> FileInfo {
            FileInfo {
                size,
                mtime: 1.0,
                mode: S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                    offset,
                    offsetheader: Some(offset),
                    istar: true,
                    issparse: false,
                    isgenerated: false,
                    recursiondepth: 0,
                })],
            }
        }

        impl MountSource for CountingTar {
            fn list(&self, path: &str) -> Option<ListResult> {
                if path == "/" {
                    let mut map = BTreeMap::new();
                    map.insert("a".into(), tar_file(4, 0));
                    map.insert("b".into(), tar_file(5, 4));
                    Some(ListResult::Infos(map))
                } else {
                    None
                }
            }

            fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
                self.lookups.fetch_add(1, Ordering::Relaxed);
                match path {
                    "/" => Some(ratarmount_core::create_root_file_info()),
                    "/a" => Some(tar_file(4, 0)),
                    "/b" => Some(tar_file(5, 4)),
                    _ => None,
                }
            }

            fn open(
                &self,
                fi: &FileInfo,
                _: i32,
            ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
                self.opens.fetch_add(1, Ordering::Relaxed);
                let bytes: &[u8] = if fi.size == 4 { b"aaaa" } else { b"bbbbb" };
                Ok(Box::new(io::Cursor::new(bytes.to_vec())))
            }

            fn is_immutable(&self) -> bool {
                true
            }
        }

        let lookups = Arc::new(AtomicU64::new(0));
        let opens = Arc::new(AtomicU64::new(0));
        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(CountingTar {
            lookups: Arc::clone(&lookups),
            opens: Arc::clone(&opens),
        }) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );

        let ino_a = fs.ino_for_path("/a");
        assert_eq!(
            lookups.load(Ordering::Relaxed),
            0,
            "inode alloc does not look up"
        );
        let fi = fs.lookup_file_info("/a").expect("first lookup");
        assert_eq!(fi.size, 4);
        assert_eq!(lookups.load(Ordering::Relaxed), 1);
        assert_eq!(fs.attr_ttl_for_fi(&fi), TTL);
        assert!(
            fs.cached_fi(ino_a).is_some(),
            "unshadowed member keeps fat FileInfo"
        );
        assert!(fs.cached_cookie(ino_a).is_none());

        for _ in 0..32 {
            let again = fs.file_info_for_ino(ino_a).expect("cached getattr");
            assert_eq!(again.size, 4);
            let looked = fs.lookup_file_info("/a").expect("cached lookup");
            assert_eq!(looked.size, 4);
        }
        assert_eq!(
            lookups.load(Ordering::Relaxed),
            1,
            "repeated stat/lookup of an unmodified member must not hit the archive index"
        );
        assert_eq!(opens.load(Ordering::Relaxed), 0);

        let ino_b = fs.ino_for_path("/b");
        assert_eq!(fs.file_info_for_ino(ino_b).expect("sibling").size, 5);
        assert_eq!(lookups.load(Ordering::Relaxed), 2);
        for _ in 0..8 {
            assert_eq!(fs.file_info_for_ino(ino_b).expect("sibling cache").size, 5);
        }
        assert_eq!(lookups.load(Ordering::Relaxed), 2);
        assert_eq!(fs.attr_ttl_for_fi(&fs.cached_fi(ino_b).unwrap()), TTL);

        let (fh, flags) = fs.open_inode(ino_a, libc::O_RDONLY).expect("read open");
        assert_eq!(
            lookups.load(Ordering::Relaxed),
            2,
            "stable read open skips overlay stat"
        );
        assert!(!fs.test_fh_is_overlay_fd(fh));
        assert_eq!(flags, FopenFlags::FOPEN_KEEP_CACHE.bits());
        assert_eq!(fs.read_handle(fh, 0, 8).expect("read"), b"aaaa");
        assert_eq!(opens.load(Ordering::Relaxed), 1);

        let (wfh, wflags) = fs.open_inode(ino_a, libc::O_WRONLY).expect("write open");
        assert!(fs.test_fh_is_overlay_fd(wfh));
        assert_eq!(
            wflags, 0,
            "overlay open must not keep the kernel data cache"
        );
        assert_eq!(
            lookups.load(Ordering::Relaxed),
            3,
            "copy-on-write looks the member up once"
        );
        assert_eq!(opens.load(Ordering::Relaxed), 2);
        assert!(
            fs.cached_fi(ino_a).is_none(),
            "write drops the fat archive-member cache"
        );
        assert_eq!(fs.cached_cookie(ino_a).expect("overlay cookie").size, 4);

        let fi = fs.file_info_for_ino(ino_a).expect("post-cow getattr");
        assert_eq!(fi.size, 4);
        assert_eq!(fs.attr_ttl_for_fi(&fi), OVERLAY_ATTR_TTL);
        assert!(
            matches!(fi.userdata.last(), Some(UserData::Other(s)) if s.starts_with("overlay:")),
            "shadowed member is served from the overlay"
        );
        assert_eq!(
            lookups.load(Ordering::Relaxed),
            3,
            "overlay getattr must not call the archive index"
        );

        ov.truncate("/a", 1).expect("truncate");
        let fi = fs.file_info_for_ino(ino_a).expect("post-truncate getattr");
        assert_eq!(
            fi.size, 1,
            "stat after truncate must not keep the archive size"
        );
        assert_eq!(fs.attr_ttl_for_fi(&fi), OVERLAY_ATTR_TTL);
        assert!(fs.cached_fi(ino_a).is_none());
        assert_eq!(fs.cached_cookie(ino_a).expect("refreshed cookie").size, 1);
        assert_eq!(lookups.load(Ordering::Relaxed), 3);
        assert_eq!(opens.load(Ordering::Relaxed), 2);

        assert_eq!(
            fs.file_info_for_ino(ino_b)
                .expect("sibling still cached")
                .size,
            5
        );
        assert!(fs.cached_fi(ino_b).is_some());
        assert!(fs.cached_cookie(ino_b).is_none());
        assert_eq!(
            lookups.load(Ordering::Relaxed),
            3,
            "shadowing one member must not invalidate its sibling"
        );
        assert_eq!(fs.attr_ttl_for_fi(&fs.cached_fi(ino_b).unwrap()), TTL);
    }

    /// Live backing store whose member offsets shift when an earlier member is
    /// deleted — the same class as TAR live overlay commit after `unlink a.txt`.
    struct OffsetShiftSource {
        gen: AtomicU64,
        archive: Arc<Mutex<Vec<u8>>>,
        members: Mutex<BTreeMap<String, (u64, u64)>>,
    }

    struct LiveArchiveReader {
        archive: Arc<Mutex<Vec<u8>>>,
        base: u64,
        size: u64,
        pos: u64,
    }

    impl std::io::Read for LiveArchiveReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.size || buf.is_empty() {
                return Ok(0);
            }
            let data = self.archive.lock().unwrap();
            let start = match usize::try_from(self.base.saturating_add(self.pos)) {
                Ok(s) => s,
                Err(_) => return Ok(0),
            };
            let max_end = match usize::try_from(self.base.saturating_add(self.size)) {
                Ok(e) => e,
                Err(_) => return Ok(0),
            };
            if start >= data.len() {
                return Ok(0);
            }
            let n = (max_end.min(data.len()).saturating_sub(start)).min(buf.len());
            buf[..n].copy_from_slice(&data[start..start + n]);
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl Seek for LiveArchiveReader {
        fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
            let new = match from {
                io::SeekFrom::Start(o) => o as i128,
                io::SeekFrom::Current(d) => self.pos as i128 + i128::from(d),
                io::SeekFrom::End(d) => self.size as i128 + i128::from(d),
            };
            if new < 0 {
                return Err(io::Error::new(ErrorKind::InvalidInput, "seek before 0"));
            }
            self.pos = new as u64;
            Ok(self.pos)
        }
    }

    impl OffsetShiftSource {
        fn two_members(a: &[u8], b: &[u8]) -> Arc<Self> {
            let mut archive = Vec::new();
            archive.extend_from_slice(a);
            let b_off = archive.len() as u64;
            archive.extend_from_slice(b);
            let mut members = BTreeMap::new();
            members.insert("a.txt".into(), (0, a.len() as u64));
            members.insert("b.txt".into(), (b_off, b.len() as u64));
            Arc::new(Self {
                gen: AtomicU64::new(0),
                archive: Arc::new(Mutex::new(archive)),
                members: Mutex::new(members),
            })
        }

        /// Delete `a.txt` and slide `b.txt` to offset 0, then bump generation.
        fn commit_delete_a(&self) {
            let mut members = self.members.lock().unwrap();
            let (b_off, b_len) = *members.get("b.txt").expect("b.txt");
            let b_bytes = {
                let archive = self.archive.lock().unwrap();
                archive[b_off as usize..b_off as usize + b_len as usize].to_vec()
            };
            *self.archive.lock().unwrap() = b_bytes;
            members.remove("a.txt");
            members.insert("b.txt".into(), (0, b_len));
            self.gen.fetch_add(1, Ordering::SeqCst);
        }

        fn member_fi(offset: u64, size: u64) -> FileInfo {
            FileInfo {
                size,
                mtime: 1.0,
                mode: S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![UserData::Other(offset.to_string())],
            }
        }
    }

    impl MountSource for OffsetShiftSource {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path != "/" {
                return None;
            }
            let mut m = BTreeMap::new();
            for (name, (off, size)) in self.members.lock().unwrap().iter() {
                m.insert(name.clone(), Self::member_fi(*off, *size));
            }
            Some(ListResult::Infos(m))
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(ratarmount_core::create_root_file_info());
            }
            let name = path.strip_prefix('/').unwrap_or(path);
            let members = self.members.lock().unwrap();
            let (off, size) = members.get(name)?;
            Some(Self::member_fi(*off, *size))
        }

        fn open(&self, fi: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            let offset = fi
                .userdata
                .iter()
                .find_map(|u| match u {
                    UserData::Other(s) => s.parse().ok(),
                    _ => None,
                })
                .unwrap_or(0);
            Ok(Box::new(LiveArchiveReader {
                archive: Arc::clone(&self.archive),
                base: offset,
                size: fi.size,
                pos: 0,
            }))
        }

        fn is_immutable(&self) -> bool {
            false
        }

        fn content_generation(&self) -> u64 {
            self.gen.load(Ordering::SeqCst)
        }
    }

    /// Regression: FUSE `cat` of an already-open base member returned zeros /
    /// wrong bytes after a live overlay commit deleted an earlier member and
    /// shifted archive offsets. NFS sweeps readers on `content_generation`;
    /// FUSE kept the pre-commit `OpenBackend::Source` reader.
    #[test]
    fn overlay_commit_live_delete_shifts_base_read() {
        let a_body = b"0123456789abcdef0123456789abcdef\n";
        let b_body = b"BBBB-distinct-payload-for-shift-detection\n";
        let src = OffsetShiftSource::two_members(a_body, b_body);
        let fs = RatarmountFs::new(Arc::clone(&src) as Arc<dyn MountSource>, None);

        let fh = fs.test_open_ro("/b.txt").expect("open b.txt before commit");
        let before = fs.test_read(fh, 0, 128).expect("read before commit");
        assert_eq!(before, b_body, "precondition: open fh serves b.txt");

        src.commit_delete_a();
        assert!(
            src.content_generation() > 0,
            "commit must bump content_generation"
        );

        let after = fs
            .test_read(fh, 0, 128)
            .expect("FUSE read of b.txt after deleting a.txt and committing");
        assert_eq!(
            after, b_body,
            "base member read after offset-shifting commit must not be stale"
        );
    }

    /// Regression: retaining the legacy 32-page cap splits large sequential reads.
    #[test]
    fn regression_sequential_reads_negotiate_large_pages_with_legacy_fallback() {
        assert_eq!(fuse_io_limit(4096, true), 1024 * 1024);
        assert_eq!(fuse_io_limit(4096, false), 128 * 1024);
        assert_eq!(fuse_io_limit(65536, true), 16 * 1024 * 1024);
        assert_eq!(fuse_io_limit(65536, false), 2 * 1024 * 1024);
    }

    /// Regression: direct I/O applies to source members, never writable overlay fds.
    #[test]
    fn regression_direct_io_member_flags_leave_overlay_cached() {
        let source = OffsetShiftSource::two_members(b"archive", b"other");
        let dir = tempfile::tempdir().unwrap();
        let ov = Arc::new(WriteOverlay::new(source, dir.path()).unwrap());
        let fs = RatarmountFs::new(ov.clone(), Some(ov.clone())).with_direct_io(true);
        let ino = fs.ino_for_path("/a.txt");
        let (fh, flags) = fs.open_inode(ino, libc::O_RDONLY).unwrap();
        assert_eq!(flags, FopenFlags::FOPEN_DIRECT_IO.bits());
        assert_eq!(fs.read_handle(fh, 0, 7).unwrap(), b"archive");
        assert_eq!(fs.source_open_flags(), FopenFlags::FOPEN_DIRECT_IO.bits());
        overlay_write_new(&ov, "/file", b"overlay");
        let ino = fs.ino_for_path("/file");
        let (fh, flags) = fs.open_inode(ino, libc::O_RDONLY).unwrap();
        assert_eq!(flags, 0);
        assert!(fs.test_fh_is_overlay_fd(fh));
        assert_eq!(fs.read_handle(fh, 0, 7).unwrap(), b"overlay");
        let serial = RatarmountFs::new(Arc::new(EmptyBase), None);
        assert_eq!(
            serial.source_open_flags(),
            FopenFlags::FOPEN_KEEP_CACHE.bits()
        );
    }

    /// Regression: creation applies the client's umask once, including executable output.
    #[test]
    fn regression_fuse_setattr_mode_create_umask() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        let (_, attr, fh) = fs
            .create_masked_entry(1, OsStr::new("built"), 0o777, 0o027)
            .unwrap();
        assert_eq!(attr.perm, 0o750);
        assert_eq!(ov.lookup("/built", 0).unwrap().mode & 0o7777, 0o750);
        let (_, attr) = fs
            .mkdir_masked_entry(1, OsStr::new("dir"), 0o777, 0o027)
            .unwrap();
        assert_eq!(attr.perm, 0o750);
        let fd = match fs.handles.lock().unwrap().remove(&fh).unwrap() {
            OpenBackend::OverlayFd(fd) => fd,
            _ => panic!("overlay fd"),
        };
        ov.close_overlay_fd(fd);
    }

    /// Regression: chmod/touch requests were acknowledged without changing attrs.
    #[test]
    fn regression_fuse_setattr_mode_times_and_omit() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        let (_, attr, fh) = fs.create_entry(1, OsStr::new("built"), 0o644).unwrap();
        let ino = attr.ino.0;
        let attrs = OverlayMetadata {
            mode: Some(0o755),
            atime: Some(1234.25),
            mtime: Some(5678.5),
            ..Default::default()
        };
        let (_, attr) = fs
            .setattr_metadata_entry(ino, None, Some(fh), &attrs)
            .unwrap();
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.atime, UNIX_EPOCH + Duration::from_millis(1234250));
        assert_eq!(attr.mtime, UNIX_EPOCH + Duration::from_millis(5678500));
        let (_, attr) = fs
            .setattr_metadata_entry(
                ino,
                None,
                None,
                &OverlayMetadata {
                    mode: Some(0o700),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(attr.perm, 0o700);
        assert_eq!(attr.mtime, UNIX_EPOCH + Duration::from_millis(5678500));
        assert_eq!(
            fs.setattr_metadata_entry(
                ino,
                None,
                None,
                &OverlayMetadata {
                    gid: Some(123),
                    ..Default::default()
                }
            )
            .unwrap_err(),
            libc::EPERM
        );
        let now = UNIX_EPOCH + Duration::from_secs(42);
        assert_eq!(setattr_time(fuser::TimeOrNow::Now, now), 42.0);
        assert_eq!(
            setattr_time(
                fuser::TimeOrNow::SpecificTime(UNIX_EPOCH + Duration::from_secs(9)),
                now
            ),
            9.0
        );
        if let Some(OpenBackend::OverlayFd(fd)) = fs.handles.lock().unwrap().remove(&fh) {
            ov.close_overlay_fd(fd);
        };
    }

    /// Regression: a detached chmod must affect the held inode, never its replacement.
    #[test]
    fn regression_fuse_setattr_mode_detached_inode() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        let (_, attr, fh) = fs.create_entry(1, OsStr::new("built"), 0o644).unwrap();
        let ino = attr.ino.0;
        fs.remove_entry(1, OsStr::new("built"), false).unwrap();
        let fd = ov.create_file("/built", 0o600).unwrap();
        ov.close_overlay_fd(fd);
        let attrs = OverlayMetadata {
            mode: Some(0o755),
            ..Default::default()
        };
        assert_eq!(
            fs.setattr_metadata_entry(ino, None, None, &attrs)
                .unwrap_err(),
            EACCES
        );
        assert_eq!(
            fs.setattr_metadata_entry(ino, None, Some(fh), &attrs)
                .unwrap()
                .1
                .perm,
            0o755
        );
        assert_eq!(ov.lookup("/built", 0).unwrap().mode & 0o7777, 0o600);
        if let Some(OpenBackend::OverlayFd(fd)) = fs.handles.lock().unwrap().remove(&fh) {
            ov.close_overlay_fd(fd);
        };
    }

    /// Regression: executables are allowed unless the user explicitly selects noexec.
    #[test]
    fn regression_fuse_setattr_mode_exec_mount_default() {
        for writable in [false, true] {
            assert!(mount_config(writable, "")
                .mount_options
                .contains(&MountOption::Exec));
            let config = mount_config(writable, "noexec");
            assert!(config.mount_options.contains(&MountOption::NoExec));
            assert!(!config.mount_options.contains(&MountOption::Exec));
        }
    }

    fn overlay_fs_for_rename() -> (tempfile::TempDir, Arc<WriteOverlay>, RatarmountFs) {
        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        (dir, ov, fs)
    }

    fn overlay_write_new(ov: &WriteOverlay, path: &str, body: &[u8]) {
        let fd = ov.create_file(path, 0o644).expect("create");
        // SAFETY: fd was just returned by create_file and is closed once here.
        let n = unsafe { libc::write(fd, body.as_ptr().cast(), body.len()) };
        assert_eq!(n, body.len() as isize, "write {path}");
        unsafe { libc::close(fd) };
    }

    /// Regression: FUSE rename returned ENOSYS (#86). Overwrite keeps the
    /// source inode and detaches the replaced destination inode so a kernel
    /// reference to it cannot resolve to the new file at `to`.
    ///
    /// A looked-up destination (nlookup >= 1) keeps the old size. A destination
    /// that only plain readdir created (nlookup 0) is dropped at detach.
    #[test]
    fn rename_paths_rebinds_source_inode_and_detaches_replaced_destination() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/src", b"source-body");
        overlay_write_new(&ov, "/dst", b"dest");
        let (src_ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("src"))
            .expect("lookup src");
        let (dst_ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("dst"))
            .expect("lookup dst");
        assert_ne!(src_ino, dst_ino);
        assert!(fs.nlookup_of(src_ino).unwrap() >= 1);
        assert!(fs.nlookup_of(dst_ino).unwrap() >= 1);
        fs.list_mode_cached("/").expect("prime dir cache");

        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "dst", 0)
            .expect("rename over existing target");

        assert_eq!(fs.path_for_ino(src_ino).as_deref(), Some("/dst"));
        assert_eq!(fs.path_to_ino.lock().unwrap().get("/dst"), Some(&src_ino));
        assert!(!fs.path_to_ino.lock().unwrap().contains_key("/src"));
        assert_eq!(
            fs.path_for_ino(dst_ino).as_deref(),
            Some(format!("\0stale-{dst_ino}").as_str())
        );
        assert!(
            fs.cached_fi(dst_ino).is_none(),
            "detached inode keeps file_info empty"
        );
        let old = fs
            .file_info_for_ino(dst_ino)
            .expect("replaced destination still answers with the old file");
        assert_eq!(old.size, b"dest".len() as u64);
        assert_ne!(old.size, b"source-body".len() as u64);
        assert_eq!(
            fs.file_info_for_ino(src_ino).expect("renamed").size,
            b"source-body".len() as u64
        );
        assert!(ov.lookup("/src", 0).is_none(), "old name gone");
        let names: Vec<String> = fs
            .list_mode_cached("/")
            .expect("list")
            .into_iter()
            .map(|(n, ..)| n)
            .collect();
        assert!(names.contains(&"dst".to_string()), "{names:?}");
        assert!(
            !names.contains(&"src".to_string()),
            "dir cache dropped: {names:?}"
        );

        // Plain rename to a fresh name, source inode never looked up.
        overlay_write_new(&ov, "/tmp", b"x");
        fs.rename_paths(FUSE_ROOT_ID, "tmp", FUSE_ROOT_ID, "final", 0)
            .expect("plain rename");
        assert!(ov.lookup("/final", 0).is_some());
        assert!(ov.lookup("/tmp", 0).is_none());

        // nlookup 0 (ino_for_path only, no lookup) is dropped at detach.
        overlay_write_new(&ov, "/zero-src", b"zs");
        overlay_write_new(&ov, "/zero-dst", b"zd");
        let zero_dst = fs.ino_for_path("/zero-dst");
        assert_eq!(fs.nlookup_of(zero_dst), Some(0));
        fs.rename_paths(FUSE_ROOT_ID, "zero-src", FUSE_ROOT_ID, "zero-dst", 0)
            .expect("rename over unreferenced destination");
        assert!(fs.path_for_ino(zero_dst).is_none());
        assert!(fs.file_info_for_ino(zero_dst).is_none());
    }

    /// Regression (#86): rename errnos. renameat2 flags are refused (EINVAL),
    /// a directory source gives EISDIR like the other frontends, a missing
    /// source ENOENT, and a read-only mount EROFS.
    #[test]
    fn rename_paths_errnos_flags_dir_missing_readonly() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/a", b"a");
        overlay_write_new(&ov, "/b", b"b");
        ov.mkdir("/d", 0o755).expect("mkdir");
        for flags in [1u32, 2, 4] {
            assert_eq!(
                fs.rename_paths(FUSE_ROOT_ID, "a", FUSE_ROOT_ID, "c", flags),
                Err(EINVAL),
                "flags {flags}"
            );
        }
        assert!(ov.lookup("/a", 0).is_some(), "refused rename left source");
        assert!(ov.lookup("/c", 0).is_none());
        assert_eq!(
            fs.rename_paths(FUSE_ROOT_ID, "d", FUSE_ROOT_ID, "d2", 0),
            Err(EISDIR)
        );
        assert_eq!(
            fs.rename_paths(FUSE_ROOT_ID, "nope", FUSE_ROOT_ID, "x", 0),
            Err(ENOENT)
        );
        assert_eq!(
            fs.rename_paths(FUSE_ROOT_ID, "a", FUSE_ROOT_ID, "d", 0),
            Err(EEXIST),
            "file over directory"
        );
        assert_eq!(
            fs.rename_paths(FUSE_ROOT_ID, "a", FUSE_ROOT_ID, "a", 0),
            Ok(())
        );
        assert_eq!(
            fs.rename_paths(FUSE_ROOT_ID, "nope", FUSE_ROOT_ID, "nope", 0),
            Err(ENOENT)
        );
        assert_eq!(
            fs.rename_paths(999_999, "a", FUSE_ROOT_ID, "x", 0),
            Err(ENOENT),
            "unknown parent inode"
        );

        let ro = RatarmountFs::new(Arc::new(EmptyBase) as Arc<dyn MountSource>, None);
        assert_eq!(
            ro.rename_paths(FUSE_ROOT_ID, "a", FUSE_ROOT_ID, "b", 0),
            Err(EROFS)
        );
    }

    #[test]
    fn io_to_errno_maps_already_exists_to_eexist() {
        assert_eq!(
            io_to_errno(&std::io::Error::new(ErrorKind::AlreadyExists, "x")),
            EEXIST
        );
    }

    /// Regression: raw EMFILE and ENFILE reach FUSE unchanged (#88).
    /// A kind-only error with no raw code stays EIO.
    #[test]
    fn io_to_errno_maps_raw_emfile_and_enfile() {
        assert_eq!(
            io_to_errno(&io::Error::from_raw_os_error(libc::EMFILE)),
            libc::EMFILE
        );
        assert_eq!(
            io_to_errno(&io::Error::from_raw_os_error(libc::ENFILE)),
            libc::ENFILE
        );
        assert_eq!(
            io_to_errno(&io::Error::from_raw_os_error(libc::ENOSPC)),
            libc::ENOSPC
        );
        assert_eq!(io_to_errno(&io::Error::other("generic")), EIO);
    }

    /// Regression: unmount with many in-flight FORGETs returns ECONNABORTED
    /// (os error 103) from fuser 0.15 `Session::run`. That is a clean session
    /// end, same as ENODEV. A real I/O error still fails the mount.
    #[test]
    fn fuse_session_result_treats_econnaborted_as_clean_unmount() {
        let aborted = io::Error::from_raw_os_error(libc::ECONNABORTED);
        assert!(
            fuse_session_result(Err(aborted)).is_ok(),
            "ECONNABORTED must not fail the mount"
        );
        assert!(fuse_session_result(Ok(())).is_ok());
        let io_err = io::Error::from_raw_os_error(libc::EIO);
        let mapped = fuse_session_result(Err(io_err)).expect_err("EIO stays an error");
        assert_eq!(mapped.raw_os_error(), Some(libc::EIO));
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
            state.window.lock().unwrap().is_none(),
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
        assert!(!state.window.lock().unwrap().as_ref().unwrap().hit_eof);
        let seeks = spy.seeks;
        let got = readahead_fill(&mut spy, &mut state, 1000, 900, 200).expect("straddle");
        assert_eq!(got, payload[900..1100]);
        assert!(
            spy.seeks > seeks,
            "straddle of non-EOF window must refill, not return false short read"
        );
    }

    /// Regression: increasing 128 KiB -> 1 MiB FUSE requests must not rewind
    /// at readahead-window boundaries and cancel queued zstd frames.
    #[test]
    fn regression_readahead_growing_requests_do_not_cancel_decode_ahead() {
        let payload: Vec<u8> = (0..5 * 1024 * 1024 + 713)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut spy = SpyReader::with_short_reads(payload.clone(), 128 * 1024);
        let mut state = ReadaheadState::default();
        let mut offset = 0;
        let mut size = 128 * 1024;
        while offset < payload.len() {
            let got =
                readahead_fill(&mut spy, &mut state, 1024 * 1024, offset as u64, size).unwrap();
            assert!(!got.is_empty());
            assert_eq!(got, payload[offset..offset + got.len()]);
            offset += got.len();
            size = (size * 2).min(1024 * 1024);
        }
        assert!(
            readahead_fill(&mut spy, &mut state, 1024 * 1024, offset as u64, size)
                .unwrap()
                .is_empty()
        );
        assert_eq!(spy.seeks, 1, "only the initial seek is needed");
        assert_eq!(spy.bytes_read, payload.len(), "no overlapping refills");
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

    const NOTIFIER_WAIT: Duration = Duration::from_secs(5);
    /// Not a real inode. Flushed after a batch so the test knows the notifier
    /// has finished that batch. Every wait is `recv_timeout(NOTIFIER_WAIT)`.
    const NOTIFIER_SENTINEL_INO: u64 = u64::MAX;

    fn signal_notifier_done(slot: &Mutex<Option<mpsc::Sender<()>>>) {
        if let Some(tx) = slot.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }

    struct RecordingSink {
        tx: mpsc::Sender<KernelInval>,
        done: Mutex<Option<mpsc::Sender<()>>>,
    }

    impl Drop for RecordingSink {
        fn drop(&mut self) {
            signal_notifier_done(&self.done);
        }
    }

    impl InvalSink for RecordingSink {
        fn inval_inode(&self, ino: u64) -> io::Result<()> {
            let _ = self.tx.send(KernelInval::Inode(ino));
            Ok(())
        }

        fn inval_entry(&self, parent: u64, name: &OsStr) -> io::Result<()> {
            let _ = self.tx.send(KernelInval::Entry {
                parent,
                name: name.to_string_lossy().into_owned(),
            });
            Ok(())
        }
    }

    struct NotifyRec {
        rx: mpsc::Receiver<KernelInval>,
        done_rx: mpsc::Receiver<()>,
        thread: thread::JoinHandle<()>,
    }

    fn attach_recording(fs: &RatarmountFs) -> NotifyRec {
        let (item_tx, rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let (tx, thread) = spawn_notifier(RecordingSink {
            tx: item_tx,
            done: Mutex::new(Some(done_tx)),
        });
        fs.kernel_notify.install(tx);
        NotifyRec {
            rx,
            done_rx,
            thread,
        }
    }

    /// Flush `pending_inval`, then a sentinel inode, and return everything the
    /// sink delivered before the sentinel.
    fn flush_recorded(fs: &RatarmountFs, rx: &mpsc::Receiver<KernelInval>) -> Vec<KernelInval> {
        fs.flush_kernel_invals();
        fs.queue_kernel_inode(NOTIFIER_SENTINEL_INO);
        fs.flush_kernel_invals();
        let deadline = Instant::now() + NOTIFIER_WAIT;
        let mut out = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "timeout waiting for notifier batch; got {out:?}"
            );
            match rx.recv_timeout(left) {
                Ok(KernelInval::Inode(ino)) if ino == NOTIFIER_SENTINEL_INO => return out,
                Ok(item) => out.push(item),
                Err(e) => panic!("notifier recv failed ({e}); got {out:?}"),
            }
        }
    }

    fn stop_recording(fs: &RatarmountFs, rec: NotifyRec) {
        fs.kernel_notify.clear();
        rec.done_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("notifier thread ended");
        // Detach. `join` has no timeout; the done channel is the bounded wait.
        drop(rec.thread);
    }

    fn stable_tar_fi(size: u64) -> FileInfo {
        FileInfo {
            size,
            mtime: 1.0,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                offset: 0,
                offsetheader: Some(0),
                istar: true,
                issparse: false,
                isgenerated: false,
                recursiondepth: 0,
            })],
        }
    }

    /// One stable archive member. `file_info_attr_stable` is true (tar userdata).
    struct NamedMember {
        name: String,
        fi: FileInfo,
    }

    impl MountSource for NamedMember {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                let mut m = BTreeMap::new();
                m.insert(self.name.clone(), self.fi.clone());
                Some(ListResult::Infos(m))
            } else {
                None
            }
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(ratarmount_core::create_root_file_info())
            } else if path == format!("/{}", self.name) {
                Some(self.fi.clone())
            } else {
                None
            }
        }

        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(ErrorKind::NotFound, "named member"))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: FUSE_NOTIFY_INVAL_ENTRY on the Session::run thread deadlocks
    /// (kernel holds the parent i_rwsem while a task waits on the FUSE reply).
    /// The sink runs on `ratarmount-fuse-notify`, and a parked sink must not
    /// block a second `flush_kernel_invals`.
    #[test]
    fn notifier_parked_sink_does_not_block_second_flush() {
        let (entered_tx, entered_rx) = mpsc::channel::<(thread::ThreadId, String)>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (seen_tx, seen_rx) = mpsc::channel::<u64>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        // Longer than NOTIFIER_WAIT. A flush that blocks in the sink must still
        // be parked when the 5s deadline fires; this timeout must not release
        // it first and let the flush return.
        let park_for = Duration::from_secs(15);

        struct ParkingSink {
            entered: Mutex<Option<mpsc::Sender<(thread::ThreadId, String)>>>,
            release: Mutex<mpsc::Receiver<()>>,
            seen: mpsc::Sender<u64>,
            park_for: Duration,
            done: Mutex<Option<mpsc::Sender<()>>>,
        }

        impl Drop for ParkingSink {
            fn drop(&mut self) {
                signal_notifier_done(&self.done);
            }
        }

        impl InvalSink for ParkingSink {
            fn inval_inode(&self, ino: u64) -> io::Result<()> {
                if let Some(tx) = self.entered.lock().unwrap().take() {
                    let name = thread::current().name().unwrap_or("").to_string();
                    let _ = tx.send((thread::current().id(), name));
                    let _ = self.release.lock().unwrap().recv_timeout(self.park_for);
                }
                let _ = self.seen.send(ino);
                Ok(())
            }

            fn inval_entry(&self, _: u64, _: &OsStr) -> io::Result<()> {
                Ok(())
            }
        }

        let fs = Arc::new(RatarmountFs::new(
            Arc::new(EmptyBase) as Arc<dyn MountSource>,
            None,
        ));
        let (tx, notifier_thread) = spawn_notifier(ParkingSink {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
            seen: seen_tx,
            park_for,
            done: Mutex::new(Some(done_tx)),
        });
        fs.kernel_notify.install(tx);

        let (caller_tx, caller_rx) = mpsc::channel();
        let (first_done_tx, first_done_rx) = mpsc::channel();
        let fs1 = Arc::clone(&fs);
        thread::spawn(move || {
            let _ = caller_tx.send(thread::current().id());
            fs1.queue_kernel_inode(7);
            fs1.flush_kernel_invals();
            let _ = first_done_tx.send(());
        });

        let (sink_tid, sink_name) = entered_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("sink entered on the notifier thread");
        let caller_tid = caller_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("flush caller reported its thread id");
        assert_ne!(
            sink_tid, caller_tid,
            "kernel notify must not run on the flush caller"
        );
        assert_eq!(sink_name, "ratarmount-fuse-notify");
        first_done_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("first flush returned while the sink is parked");

        let (second_done_tx, second_done_rx) = mpsc::channel();
        let fs2 = Arc::clone(&fs);
        // thread::spawn + recv_timeout, not std::thread::scope: scope joins the
        // caller even after a timeout panic, so a blocked flush would hang the test.
        thread::spawn(move || {
            fs2.queue_kernel_inode(8);
            fs2.flush_kernel_invals();
            let _ = second_done_tx.send(());
        });
        second_done_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("second flush returned within 5s while the notifier sink is still parked");
        assert!(
            seen_rx.try_recv().is_err(),
            "sink must still be parked; no inval delivered yet"
        );

        release_tx.send(()).expect("unpark");
        let first = seen_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("first inval after unpark");
        let second = seen_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("second inval after unpark");
        assert_eq!(first, 7);
        assert_eq!(second, 8);

        fs.kernel_notify.clear();
        done_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("dropping the sender ends the notifier thread");
        drop(notifier_thread);
    }

    /// Regression: mount shutdown drops the notify sender. The thread must end
    /// without a sink call. The wait is `recv_timeout`, not `join`.
    #[test]
    fn notifier_exits_when_sender_dropped() {
        let (done_tx, done_rx) = mpsc::channel();

        struct IdleSink {
            done: Mutex<Option<mpsc::Sender<()>>>,
        }

        impl Drop for IdleSink {
            fn drop(&mut self) {
                signal_notifier_done(&self.done);
            }
        }

        impl InvalSink for IdleSink {
            fn inval_inode(&self, _: u64) -> io::Result<()> {
                Ok(())
            }

            fn inval_entry(&self, _: u64, _: &OsStr) -> io::Result<()> {
                Ok(())
            }
        }

        let (tx, thread) = spawn_notifier(IdleSink {
            done: Mutex::new(Some(done_tx)),
        });
        drop(tx);
        done_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("dropping the sender ends the notifier thread");
        drop(thread);
    }

    /// Regression: ENODEV, ENOTCONN, EBADF, and ECONNABORTED mean the FUSE
    /// connection is gone. The notifier exits on the first of those, without
    /// delivering the rest of the batch, while the sender is still alive.
    #[test]
    fn notifier_exits_on_enodev() {
        for code in [
            libc::ENODEV,
            libc::ENOTCONN,
            libc::EBADF,
            libc::ECONNABORTED,
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let (done_tx, done_rx) = mpsc::channel();

            struct FatalSink {
                code: i32,
                calls: Arc<AtomicUsize>,
                done: Mutex<Option<mpsc::Sender<()>>>,
            }

            impl Drop for FatalSink {
                fn drop(&mut self) {
                    signal_notifier_done(&self.done);
                }
            }

            impl InvalSink for FatalSink {
                fn inval_inode(&self, _: u64) -> io::Result<()> {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::from_raw_os_error(self.code))
                }

                fn inval_entry(&self, _: u64, _: &OsStr) -> io::Result<()> {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::from_raw_os_error(self.code))
                }
            }

            let (tx, thread) = spawn_notifier(FatalSink {
                code,
                calls: Arc::clone(&calls),
                done: Mutex::new(Some(done_tx)),
            });
            tx.send(vec![
                KernelInval::Inode(1),
                KernelInval::Entry {
                    parent: 1,
                    name: "left".into(),
                },
            ])
            .expect("queue batch");
            done_rx
                .recv_timeout(NOTIFIER_WAIT)
                .unwrap_or_else(|_| panic!("errno {code} should end the notifier thread"));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "errno {code}: stop on the first fatal call and drain the rest"
            );
            drop(tx);
            drop(thread);
        }
    }

    /// Regression: the notifier retries EINTR and ignores ENOENT. Neither ends
    /// the thread; a later invalidation is still delivered.
    #[test]
    fn notifier_retries_eintr_and_ignores_not_found() {
        let calls = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(Mutex::new(vec![libc::EINTR, libc::ENOENT]));
        let (ok_tx, ok_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        struct ScriptSink {
            calls: Arc<AtomicUsize>,
            script: Arc<Mutex<Vec<i32>>>,
            ok_tx: mpsc::Sender<u64>,
            done: Mutex<Option<mpsc::Sender<()>>>,
        }

        impl Drop for ScriptSink {
            fn drop(&mut self) {
                signal_notifier_done(&self.done);
            }
        }

        impl InvalSink for ScriptSink {
            fn inval_inode(&self, ino: u64) -> io::Result<()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let code = {
                    let mut script = self.script.lock().unwrap();
                    if script.is_empty() {
                        None
                    } else {
                        Some(script.remove(0))
                    }
                };
                match code {
                    Some(code) => Err(io::Error::from_raw_os_error(code)),
                    None => {
                        let _ = self.ok_tx.send(ino);
                        Ok(())
                    }
                }
            }

            fn inval_entry(&self, _: u64, _: &OsStr) -> io::Result<()> {
                Ok(())
            }
        }

        let (tx, thread) = spawn_notifier(ScriptSink {
            calls: Arc::clone(&calls),
            script,
            ok_tx,
            done: Mutex::new(Some(done_tx)),
        });
        tx.send(vec![KernelInval::Inode(1)]).expect("first batch");
        tx.send(vec![KernelInval::Inode(2)]).expect("second batch");
        let delivered = ok_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("Ok invalidation after EINTR retry and ENOENT");
        assert_eq!(delivered, 2);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "EINTR retried, ENOENT ignored, then the next inode"
        );
        drop(tx);
        done_rx
            .recv_timeout(NOTIFIER_WAIT)
            .expect("sender drop still ends the thread after a retried notify");
        drop(thread);
    }

    /// Regression: create of a never-looked-up name must not send
    /// FUSE_NOTIFY_INVAL_ENTRY. Root attrs are stable (`create_root_file_info`),
    /// so the batch is exactly `Inode(root)`.
    #[test]
    fn entry_advertised_create_unseen_name_sends_root_inode_not_entry() {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        let rec = attach_recording(&fs);
        // The kernel holds root's attr from a getattr reply.
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");

        assert!(
            file_info_attr_stable(&fs.cached_fi(FUSE_ROOT_ID).expect("root fi")),
            "root FileInfo is stable"
        );
        let fd = ov.create_file("/fresh.txt", 0o644).expect("create");
        ov.close_overlay_fd(fd);
        let fi = fs.source.lookup("/fresh.txt", 0).expect("overlay fi");
        assert!(
            fs.attr_ttl_for_fi(&fi).is_zero(),
            "new overlay file has entry TTL 0"
        );
        // Same order as Filesystem::create: note, assign ino, reply TTL, flush.
        fs.note_dir_changed(FUSE_ROOT_ID, "fresh.txt");
        let _ino = fs.ino_for_path_with_fi("/fresh.txt", Some(fi.clone()));
        fs.invalidate_dir_cache("/");
        let ttl = fs.reply_entry_ttl(FUSE_ROOT_ID, "fresh.txt", _ino, &fi);
        assert!(ttl.is_zero());
        assert!(
            !fs.entry_advertised
                .lock()
                .unwrap()
                .contains(&(FUSE_ROOT_ID, "fresh.txt".into())),
            "TTL 0 must not advertise the name"
        );
        let batch = flush_recorded(&fs, &rec.rx);
        assert_eq!(batch, vec![KernelInval::Inode(FUSE_ROOT_ID)]);
        stop_recording(&fs, rec);
    }

    /// Regression: a stable member looked up with a non-zero entry TTL is
    /// advertised. Unlink then sends exactly one Entry(parent, name), exactly
    /// one Inode(child), and Inode(parent) because the root is stable. A second
    /// unlink or create of that name sends no Entry: the pair was consumed.
    #[test]
    fn entry_advertised_lookup_inserts_pair_and_unlink_sends_entry() {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(NamedMember {
            name: "m".into(),
            fi: stable_tar_fi(4),
        }) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        let rec = attach_recording(&fs);
        // The kernel holds root's attr from a getattr reply.
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");

        assert!(file_info_attr_stable(
            &fs.cached_fi(FUSE_ROOT_ID).expect("root")
        ));
        let (child, _attr, ttl) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("m"))
            .expect("lookup helper used by Filesystem::lookup");
        assert_eq!(ttl, TTL, "stable archive member is advertised for 60s");
        assert!(
            fs.entry_advertised
                .lock()
                .unwrap()
                .contains(&(FUSE_ROOT_ID, "m".into())),
            "lookup path must insert (parent, name)"
        );
        assert!(file_info_attr_stable(
            &fs.cached_fi(child).expect("stable child")
        ));

        ov.unlink("/m").expect("unlink");
        fs.invalidate_dir_cache("/");
        fs.note_dir_changed(FUSE_ROOT_ID, "m");
        let batch = flush_recorded(&fs, &rec.rx);
        assert_eq!(
            batch,
            vec![
                KernelInval::Inode(FUSE_ROOT_ID),
                KernelInval::Entry {
                    parent: FUSE_ROOT_ID,
                    name: "m".into(),
                },
                KernelInval::Inode(child),
            ]
        );
        assert!(
            !fs.entry_advertised
                .lock()
                .unwrap()
                .contains(&(FUSE_ROOT_ID, "m".into())),
            "unlink consumes the advertised pair"
        );

        ov.unlink("/m").expect("second unlink");
        fs.note_dir_changed(FUSE_ROOT_ID, "m");
        let again = flush_recorded(&fs, &rec.rx);
        assert!(
            again.is_empty(),
            "second unlink of a consumed name sends no Entry: {again:?}"
        );

        let fd = ov.create_file("/m", 0o644).expect("recreate");
        ov.close_overlay_fd(fd);
        let fi = fs.source.lookup("/m", 0).expect("recreated overlay fi");
        assert!(fs.attr_ttl_for_fi(&fi).is_zero());
        fs.note_dir_changed(FUSE_ROOT_ID, "m");
        let m_ino = fs.ino_for_path_with_fi("/m", Some(fi.clone()));
        let ttl = fs.reply_entry_ttl(FUSE_ROOT_ID, "m", m_ino, &fi);
        assert!(ttl.is_zero());
        let created = flush_recorded(&fs, &rec.rx);
        assert!(
            created.is_empty(),
            "create after the pair was consumed sends no Entry: {created:?}"
        );
        stop_recording(&fs, rec);
    }

    /// Stable archive entries keyed by relative path (`m`, `sub`, `sub/x`)
    /// whose bytes can be read (copy-up on rename needs it).
    /// `file_info_attr_stable` is true for each.
    struct ReadableMembers(Vec<(String, FileInfo)>);

    impl MountSource for ReadableMembers {
        fn list(&self, path: &str) -> Option<ListResult> {
            let dir = path.strip_prefix('/')?;
            if !dir.is_empty()
                && !self
                    .lookup(path, 0)
                    .is_some_and(|fi| fi.mode & S_IFMT == ratarmount_core::S_IFDIR)
            {
                return None;
            }
            let m: BTreeMap<String, FileInfo> = self
                .0
                .iter()
                .filter_map(|(key, fi)| {
                    let (parent, base) = key.rsplit_once('/').unwrap_or(("", key));
                    (parent == dir).then(|| (base.to_string(), fi.clone()))
                })
                .collect();
            Some(ListResult::Infos(m))
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(ratarmount_core::create_root_file_info());
            }
            let name = path.strip_prefix('/')?;
            self.0
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, fi)| fi.clone())
        }

        fn open(&self, fi: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(io::Cursor::new(vec![b'a'; fi.size as usize])))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    fn readable_members_fs(names: &[&str]) -> (tempfile::TempDir, RatarmountFs) {
        let members = names
            .iter()
            .map(|n| (n.to_string(), stable_tar_fi(4)))
            .collect();
        readable_tree_fs(members)
    }

    fn readable_tree_fs(entries: Vec<(String, FileInfo)>) -> (tempfile::TempDir, RatarmountFs) {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(ReadableMembers(entries)) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        (dir, fs)
    }

    /// Archive directory entry; tar userdata keeps `file_info_attr_stable`.
    fn stable_tar_dir_fi() -> FileInfo {
        let mut fi = stable_tar_fi(0);
        fi.mode = ratarmount_core::S_IFDIR | 0o755;
        fi
    }

    /// Regression (#86 on #84): rename of a 60s-advertised archive member must
    /// queue the old name, the stable child inode and the stable parent before
    /// the path map is rebound, and send nothing until the post-reply flush.
    #[test]
    fn rename_paths_queues_old_name_child_and_parent_before_rebind() {
        let (_dir, fs) = readable_members_fs(&["m"]);
        let rec = attach_recording(&fs);
        // The kernel holds root's attr from a getattr reply.
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");
        let (child, _attr, ttl) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("m"))
            .expect("lookup m");
        assert_eq!(ttl, TTL, "stable archive member is advertised for 60s");

        fs.rename_paths(FUSE_ROOT_ID, "m", FUSE_ROOT_ID, "n", 0)
            .expect("rename archive member");
        assert_eq!(
            fs.pending_inval.lock().unwrap().len(),
            3,
            "queued, not sent, until the handler flushes after reply.ok()"
        );
        let batch = flush_recorded(&fs, &rec.rx);
        assert_eq!(
            batch,
            vec![
                KernelInval::Entry {
                    parent: FUSE_ROOT_ID,
                    name: "m".into(),
                },
                KernelInval::Inode(child),
                KernelInval::Inode(FUSE_ROOT_ID),
                // No Entry for "n": that would unhash the moved dentry.
            ]
        );
        assert!(!fs
            .entry_advertised
            .lock()
            .unwrap()
            .contains(&(FUSE_ROOT_ID, "m".into())));
        assert_eq!(fs.path_for_ino(child).as_deref(), Some("/n"));
        let fi = fs.file_info_for_ino(child).expect("renamed member");
        assert!(
            fs.attr_ttl_for_fi(&fi).is_zero(),
            "copied-up member is overlay-backed: TTL 0 from now on"
        );
        stop_recording(&fs, rec);
    }

    /// Regression (#86 on #84): rename of one 60s-advertised member over
    /// another queues the old name and both stable children (the replaced one
    /// before `rebind_after_rename` detaches it) plus the parent, and forgets
    /// the destination name without an INVAL_ENTRY (that unhashed the moved
    /// dentry, so a held fd read "(deleted)").
    #[test]
    fn rename_paths_over_advertised_member_queues_old_name_and_both_children() {
        let (_dir, fs) = readable_members_fs(&["m", "t"]);
        let rec = attach_recording(&fs);
        // The kernel holds root's attr from a getattr reply.
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");
        let (child_m, _, ttl_m) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("m")).expect("m");
        let (child_t, _, ttl_t) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("t")).expect("t");
        assert_eq!((ttl_m, ttl_t), (TTL, TTL));

        fs.rename_paths(FUSE_ROOT_ID, "m", FUSE_ROOT_ID, "t", 0)
            .expect("rename over");
        let batch = flush_recorded(&fs, &rec.rx);
        assert_eq!(
            batch,
            vec![
                KernelInval::Entry {
                    parent: FUSE_ROOT_ID,
                    name: "m".into(),
                },
                KernelInval::Inode(child_m),
                // No Entry for "t": it would unhash the moved dentry.
                KernelInval::Inode(child_t),
                KernelInval::Inode(FUSE_ROOT_ID),
            ]
        );
        assert_eq!(fs.path_for_ino(child_m).as_deref(), Some("/t"));
        assert_ne!(fs.path_for_ino(child_t).as_deref(), Some("/t"));
        assert!(fs.entry_advertised.lock().unwrap().is_empty());
        stop_recording(&fs, rec);
    }

    /// Regression (#86 on #84): a cross-directory rename must also drop the
    /// new parent's 60s attr. Every other rename test used one directory, so
    /// deleting `drop_stable_attr(newparent)` left the suite green.
    #[test]
    fn rename_paths_across_dirs_queues_both_parents() {
        let (_dir, fs) = readable_tree_fs(vec![
            ("m".into(), stable_tar_fi(4)),
            ("sub".into(), stable_tar_dir_fi()),
            ("sub/x".into(), stable_tar_fi(4)),
        ]);
        let names = |dir: &str| -> Vec<String> {
            fs.list_mode_cached(dir)
                .expect("list")
                .into_iter()
                .map(|(n, _, _)| n)
                .collect()
        };
        // Primes the 30s dir cache for /sub; the rename must invalidate it.
        assert_eq!(names("/sub"), vec!["x".to_string()]);
        let rec = attach_recording(&fs);
        // Root's 60s attr must be advertised for its Inode to be queued.
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");
        let (child, _, ttl_m) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("m")).expect("m");
        let (sub, _, ttl_sub) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("sub"))
            .expect("sub");
        assert_eq!((ttl_m, ttl_sub), (TTL, TTL));

        fs.rename_paths(FUSE_ROOT_ID, "m", sub, "n", 0)
            .expect("rename into sub");
        let batch = flush_recorded(&fs, &rec.rx);
        assert_eq!(
            batch,
            vec![
                KernelInval::Entry {
                    parent: FUSE_ROOT_ID,
                    name: "m".into(),
                },
                KernelInval::Inode(child),
                KernelInval::Inode(FUSE_ROOT_ID),
                KernelInval::Inode(sub),
            ]
        );
        assert_eq!(fs.path_for_ino(child).as_deref(), Some("/sub/n"));
        assert_eq!(fs.path_for_ino(sub).as_deref(), Some("/sub"));
        assert!(fs.source.lookup("/m", 0).is_none());
        assert!(fs.source.lookup("/sub/n", 0).is_some());
        let mut sub_names = names("/sub");
        sub_names.sort();
        assert_eq!(sub_names, vec!["n".to_string(), "x".to_string()]);
        assert!(!names("/").contains(&"m".to_string()));
        stop_recording(&fs, rec);
    }

    /// Regression (Robo-Ilya, #97): a create/unlink of the overlay database
    /// through the mount replied EIO (and create truncated the DB). Now the
    /// overlay refuses it and the handlers reply EACCES.
    #[test]
    fn overlay_internal_name_create_unlink_reply_eacces() {
        let (dir, fs) = readable_members_fs(&["m"]);
        let ov = fs.overlay.as_ref().expect("write overlay");
        let db = ov.root().join(ratarmount_compositing::HIDDEN_DB);
        let len = std::fs::metadata(&db).unwrap().len();
        let db_name = OsStr::new(ratarmount_compositing::HIDDEN_DB);
        let marker = OsStr::new(ratarmount_compositing::OVERLAY_MARKER);
        assert_eq!(
            fs.create_entry(FUSE_ROOT_ID, db_name, 0o644).err(),
            Some(EACCES)
        );
        assert_eq!(
            fs.mkdir_entry(FUSE_ROOT_ID, marker, 0o755).err(),
            Some(EACCES)
        );
        assert_eq!(fs.remove_entry(FUSE_ROOT_ID, db_name, false), Err(EACCES));
        assert_eq!(fs.remove_entry(FUSE_ROOT_ID, marker, false), Err(EACCES));
        assert_eq!(fs.remove_entry(FUSE_ROOT_ID, marker, true), Err(EACCES));
        assert_eq!(std::fs::metadata(&db).unwrap().len(), len);
        assert!(fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new(ratarmount_compositing::HIDDEN_DB))
            .is_none());
        drop(dir);
    }

    /// Regression (#86 on #84): the rename handler replies first, then
    /// flushes. Without the flush the invalidations stayed queued (and went
    /// out with some later request, or never).
    #[test]
    fn rename_reply_flushes_after_reply() {
        let (_dir, fs) = readable_members_fs(&["m"]);
        let rec = attach_recording(&fs);
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");
        let (child, _, ttl) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("m")).expect("m");
        assert_eq!(ttl, TTL);

        let mut replied = None;
        fs.rename_reply(FUSE_ROOT_ID, "m", FUSE_ROOT_ID, "n", 0, |result| {
            let queued = fs.pending_inval.lock().unwrap().len();
            let sent = rec.rx.try_recv();
            replied = Some((result, queued, sent));
        });
        let (result, queued, sent) = replied.expect("reply called");
        assert_eq!(result, Ok(()));
        assert_eq!(
            queued, 3,
            "invalidations are queued when the reply goes out"
        );
        assert_eq!(
            sent,
            Err(mpsc::TryRecvError::Empty),
            "nothing sent before the reply"
        );
        assert!(
            fs.pending_inval.lock().unwrap().is_empty(),
            "rename_reply must flush after the reply"
        );
        assert_eq!(
            flush_recorded(&fs, &rec.rx),
            vec![
                KernelInval::Entry {
                    parent: FUSE_ROOT_ID,
                    name: "m".into(),
                },
                KernelInval::Inode(child),
                KernelInval::Inode(FUSE_ROOT_ID),
            ]
        );

        let mut missing = None;
        fs.rename_reply(FUSE_ROOT_ID, "zz", FUSE_ROOT_ID, "y", 0, |result| {
            missing = Some(result);
        });
        assert_eq!(missing, Some(Err(ENOENT)));
        assert!(fs.pending_inval.lock().unwrap().is_empty());
        stop_recording(&fs, rec);
    }

    /// `ReadableMembers` whose `content_generation` the test can bump (a live
    /// commit's generation advance, seen through `WriteOverlay`).
    struct GenMembers(ReadableMembers, Arc<AtomicU64>);

    impl MountSource for GenMembers {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.0.list(path)
        }
        fn lookup(&self, path: &str, v: i32) -> Option<FileInfo> {
            self.0.lookup(path, v)
        }
        fn open(&self, fi: &FileInfo, v: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.0.open(fi, v)
        }
        fn is_immutable(&self) -> bool {
            true
        }
        fn content_generation(&self) -> u64 {
            self.1.load(Ordering::SeqCst)
        }
    }

    /// Write-overlay fs over `GenMembers`: stable file `m`, stable dir `sub`.
    fn gen_members_fs() -> (tempfile::TempDir, RatarmountFs, Arc<AtomicU64>) {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let mut sub = stable_tar_fi(0);
        sub.mode = ratarmount_core::S_IFDIR | 0o755;
        let gen = Arc::new(AtomicU64::new(0));
        let base = Arc::new(GenMembers(
            ReadableMembers(vec![("m".into(), stable_tar_fi(4)), ("sub".into(), sub)]),
            Arc::clone(&gen),
        )) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        (dir, fs, gen)
    }

    /// Bump the source generation and run the sweep a live commit triggers.
    fn advance_generation(fs: &RatarmountFs, gen: &AtomicU64) {
        let before = fs.source.content_generation();
        gen.fetch_add(1, Ordering::SeqCst);
        assert!(fs.source.content_generation() > before);
        fs.sweep_if_generation_advanced();
    }

    /// Regression (#84 follow-up): the generation sweep cleared the stable
    /// cache, so the first write/truncate of a 60s-advertised member queued no
    /// `Inode` and the kernel kept the old attr. A later attr reply re-arms.
    #[test]
    fn drop_after_generation_sweep_still_invalidates_kernel_attr() {
        let (_dir, fs, gen) = gen_members_fs();
        let rec = attach_recording(&fs);
        let (child, _, ttl) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("m")).expect("m");
        assert_eq!(ttl, TTL);
        assert!(fs.cached_fi(child).is_some());
        advance_generation(&fs, &gen);
        assert!(
            fs.cached_fi(child).is_none(),
            "sweep cleared the userspace cache"
        );

        assert!(
            fs.drop_stable_attr(child),
            "kernel still holds the 60s attr"
        );
        assert_eq!(
            flush_recorded(&fs, &rec.rx),
            vec![KernelInval::Inode(child)]
        );
        assert!(!fs.drop_stable_attr(child), "consumed: no second Inode");
        assert!(flush_recorded(&fs, &rec.rx).is_empty());

        let (ttl, _) = fs.getattr_reply(child).expect("getattr m");
        assert_eq!(ttl, TTL, "re-looked-up archive member is advertised again");
        assert!(fs.drop_stable_attr(child));
        assert_eq!(
            flush_recorded(&fs, &rec.rx),
            vec![KernelInval::Inode(child)]
        );
        stop_recording(&fs, rec);
    }

    /// Regression (#84 follow-up): a rename after the sweep queued only the
    /// old name; the moved inode and the parent kept their 60s attrs.
    #[test]
    fn rename_after_generation_sweep_invalidates_child_and_parent() {
        let (_dir, fs, gen) = gen_members_fs();
        let rec = attach_recording(&fs);
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");
        let (child, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("m")).expect("m");
        advance_generation(&fs, &gen);
        assert!(fs.cached_fi(child).is_none());

        fs.rename_paths(FUSE_ROOT_ID, "m", FUSE_ROOT_ID, "n", 0)
            .expect("rename");
        let batch = flush_recorded(&fs, &rec.rx);
        for want in [
            KernelInval::Entry {
                parent: FUSE_ROOT_ID,
                name: "m".into(),
            },
            KernelInval::Inode(child),
            KernelInval::Inode(FUSE_ROOT_ID),
        ] {
            assert!(batch.contains(&want), "{want:?} missing from {batch:?}");
        }
        stop_recording(&fs, rec);
    }

    /// Regression (#84 follow-up): a create/unlink in a 60s-advertised
    /// directory after the sweep left the directory's attr cached.
    #[test]
    fn dir_change_after_generation_sweep_invalidates_parent() {
        let (_dir, fs, gen) = gen_members_fs();
        let rec = attach_recording(&fs);
        let (sub, _, ttl) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("sub"))
            .expect("sub");
        assert_eq!(ttl, TTL);
        assert!(fs.cached_fi(sub).is_some(), "stable archive dir is cached");
        advance_generation(&fs, &gen);
        assert!(fs.cached_fi(sub).is_none());

        fs.note_dir_changed(sub, "new");
        let batch = flush_recorded(&fs, &rec.rx);
        assert!(batch.contains(&KernelInval::Inode(sub)), "{batch:?}");
        stop_recording(&fs, rec);
    }

    /// TTL-0 replies (overlay-backed) never enter `attr_advertised`, and a
    /// read-only mount records nothing.
    #[test]
    fn attr_advertised_skips_ttl_zero_and_read_only() {
        let (_dir, fs) = readable_members_fs(&["m"]);
        let rec = attach_recording(&fs);
        let (child, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("m")).expect("m");
        fs.rename_paths(FUSE_ROOT_ID, "m", FUSE_ROOT_ID, "n", 0)
            .expect("rename");
        flush_recorded(&fs, &rec.rx);
        let (ttl, _) = fs.getattr_reply(child).expect("getattr n");
        assert!(ttl.is_zero(), "copied-up member is overlay-backed");
        assert!(!fs.attr_advertised.lock().unwrap().contains(&child));
        assert!(!fs.drop_stable_attr(child));
        assert!(flush_recorded(&fs, &rec.rx).is_empty());
        stop_recording(&fs, rec);

        let ro = RatarmountFs::new(
            Arc::new(ReadableMembers(vec![("m".into(), stable_tar_fi(4))])) as Arc<dyn MountSource>,
            None,
        );
        let (ttl, _) = ro.getattr_reply(FUSE_ROOT_ID).expect("getattr root");
        assert_eq!(ttl, TTL);
        ro.lookup_entry(FUSE_ROOT_ID, OsStr::new("m")).expect("m");
        assert!(ro.attr_advertised.lock().unwrap().is_empty());
    }

    /// Regression: an overlay-backed name (entry TTL 0) was never advertised.
    /// Unlink sends no Entry and no Inode(child).
    #[test]
    fn entry_advertised_overlay_unlink_sends_no_entry_or_child_inode() {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        let rec = attach_recording(&fs);
        // The kernel holds root's attr from a getattr reply.
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");

        let fd = ov.create_file("/new.txt", 0o644).expect("create");
        ov.close_overlay_fd(fd);
        let fi = fs.source.lookup("/new.txt", 0).expect("overlay fi");
        assert!(!file_info_attr_stable(&fi));
        // create() notes the directory before the new inode exists.
        fs.note_dir_changed(FUSE_ROOT_ID, "new.txt");
        let child = fs.ino_for_path_with_fi("/new.txt", Some(fi.clone()));
        fs.invalidate_dir_cache("/");
        let ttl = fs.reply_entry_ttl(FUSE_ROOT_ID, "new.txt", child, &fi);
        assert!(ttl.is_zero());
        assert!(
            fs.cached_fi(child).is_none(),
            "overlay child keeps no fat FileInfo"
        );
        assert_ne!(child, FUSE_ROOT_ID);
        let create_batch = flush_recorded(&fs, &rec.rx);
        assert_eq!(
            create_batch,
            vec![KernelInval::Inode(FUSE_ROOT_ID)],
            "create of a TTL 0 name invalidates the stable root only"
        );

        ov.unlink("/new.txt").expect("unlink");
        fs.invalidate_dir_cache("/");
        fs.note_dir_changed(FUSE_ROOT_ID, "new.txt");
        let batch = flush_recorded(&fs, &rec.rx);
        assert!(
            batch.iter().all(|item| match item {
                KernelInval::Entry { .. } => false,
                KernelInval::Inode(ino) => *ino != child,
            }),
            "overlay unlink must not send Entry or Inode(child): {batch:?}"
        );
        assert!(
            batch.is_empty(),
            "exact unlink batch is empty (parent attr already dropped): {batch:?}"
        );
        stop_recording(&fs, rec);
    }

    /// Regression: with an overlay, readdirplus entry TTL is 0, including for a
    /// non-zero-size file. It must not insert into `entry_advertised`.
    #[test]
    fn entry_advertised_readdirplus_entry_ttl_is_zero_with_overlay() {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(EmptyBase) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(
            Arc::clone(&ov) as Arc<dyn MountSource>,
            Some(Arc::clone(&ov)),
        );
        let file_attr = RatarmountFs::file_attr(
            2,
            &FileInfo {
                size: 5,
                mtime: 1.0,
                mode: S_IFREG | 0o644,
                linkname: String::new(),
                uid: 0,
                gid: 0,
                userdata: vec![UserData::Tar(ratarmount_core::SQLiteIndexedTarUserData {
                    offset: 0,
                    offsetheader: Some(0),
                    istar: true,
                    issparse: false,
                    isgenerated: false,
                    recursiondepth: 0,
                })],
            },
        );
        let dir_attr = RatarmountFs::file_attr(3, &ratarmount_core::create_root_file_info());
        assert_eq!(fs.readdirplus_entry_ttl(&file_attr), Duration::ZERO);
        assert_eq!(fs.readdirplus_entry_ttl(&dir_attr), Duration::ZERO);
        assert!(
            fs.entry_advertised.lock().unwrap().is_empty(),
            "readdirplus must not advertise entries while its TTL is zero"
        );
    }

    fn overlay_fd_of(fs: &RatarmountFs, fh: u64) -> i32 {
        match fs.handles.lock().unwrap().get(&fh) {
            Some(OpenBackend::OverlayFd(fd)) => *fd,
            _ => panic!("fh {fh} is not an overlay fd"),
        }
    }

    fn pwrite_all(fd: i32, data: &[u8]) {
        let n = unsafe { libc::pwrite(fd, data.as_ptr().cast(), data.len(), 0) };
        assert_eq!(
            n,
            data.len() as isize,
            "pwrite: {}",
            std::io::Error::last_os_error()
        );
    }

    /// Archive bytes owned by the `Cursor` at `open` time, copied out of
    /// `FileInfo` userdata (`bytes:…`). A later map edit is visible only to a
    /// refresh that calls `open` again.
    struct ByteMembers {
        files: Mutex<BTreeMap<String, Vec<u8>>>,
        gen: Arc<AtomicU64>,
        opens: Arc<AtomicUsize>,
    }

    impl MountSource for ByteMembers {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path != "/" {
                return None;
            }
            let files = self.files.lock().unwrap();
            let m = files
                .iter()
                .map(|(name, body)| (name.clone(), byte_fi(body)))
                .collect();
            Some(ListResult::Infos(m))
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(ratarmount_core::create_root_file_info());
            }
            let name = path.strip_prefix('/')?;
            let files = self.files.lock().unwrap();
            files.get(name).map(|body| byte_fi(body))
        }

        fn open(&self, fi: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let body = fi
                .userdata
                .iter()
                .find_map(|u| match u {
                    UserData::Other(s) => s
                        .strip_prefix("bytes:")
                        .map(|rest| rest.as_bytes().to_vec()),
                    _ => None,
                })
                .unwrap_or_default();
            Ok(Box::new(io::Cursor::new(body)))
        }

        fn is_immutable(&self) -> bool {
            true
        }

        fn content_generation(&self) -> u64 {
            self.gen.load(Ordering::SeqCst)
        }
    }

    fn byte_fi(body: &[u8]) -> FileInfo {
        FileInfo {
            size: body.len() as u64,
            mtime: 1.0,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Other(format!(
                "bytes:{}",
                String::from_utf8_lossy(body)
            ))],
        }
    }

    fn byte_members_fs(
        entries: &[(&str, &str)],
    ) -> (tempfile::TempDir, RatarmountFs, Arc<ByteMembers>) {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let mut files = BTreeMap::new();
        for (name, body) in entries {
            files.insert((*name).to_string(), body.as_bytes().to_vec());
        }
        let bytes = Arc::new(ByteMembers {
            files: Mutex::new(files),
            gen: Arc::new(AtomicU64::new(0)),
            opens: Arc::new(AtomicUsize::new(0)),
        });
        let base = Arc::clone(&bytes) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(Arc::clone(&ov) as Arc<dyn MountSource>, Some(ov));
        (dir, fs, bytes)
    }

    struct XattrMembers {
        files: BTreeMap<String, FileInfo>,
    }

    impl MountSource for XattrMembers {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path != "/" {
                return None;
            }
            Some(ListResult::Infos(self.files.clone()))
        }

        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                return Some(ratarmount_core::create_root_file_info());
            }
            self.files.get(path.trim_start_matches('/')).cloned()
        }

        fn open(&self, fi: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(io::Cursor::new(vec![0u8; fi.size as usize])))
        }

        fn is_immutable(&self) -> bool {
            true
        }

        fn get_xattr(&self, fi: &FileInfo, key: &str) -> Option<Vec<u8>> {
            if key != "user.demo" {
                return None;
            }
            fi.userdata.iter().find_map(|u| match u {
                UserData::Other(s) => s.strip_prefix("xattr:").map(|v| v.as_bytes().to_vec()),
                _ => None,
            })
        }

        fn list_xattr(&self, fi: &FileInfo) -> Vec<String> {
            if self.get_xattr(fi, "user.demo").is_some() {
                vec!["user.demo".into()]
            } else {
                Vec::new()
            }
        }
    }

    fn xattr_fi(mode: u32, linkname: &str, value: &str, size: u64) -> FileInfo {
        FileInfo {
            size,
            mtime: 1.0,
            mode,
            linkname: linkname.into(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Other(format!("xattr:{value}"))],
        }
    }

    fn xattr_members_fs(files: BTreeMap<String, FileInfo>) -> (tempfile::TempDir, RatarmountFs) {
        use ratarmount_compositing::WriteOverlay;

        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(XattrMembers { files }) as Arc<dyn MountSource>;
        let ov = Arc::new(WriteOverlay::new(base, dir.path()).expect("overlay"));
        let fs = RatarmountFs::new(Arc::clone(&ov) as Arc<dyn MountSource>, Some(ov));
        (dir, fs)
    }

    /// Regression (#88): rename-over of an overlay file made the old nodeid
    /// GETATTR/OPEN ENOENT (`"\0stale-…"`). It keeps the old bytes, nlink 0,
    /// TTL 0. A new write open is EACCES.
    #[test]
    fn detached_overlay_rename_getattr_open_read_old_bytes() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/dst", b"old-dest");
        overlay_write_new(&ov, "/src", b"new-src");
        let (src_ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("src"))
            .expect("src");
        let (dst_ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("dst"))
            .expect("dst");
        assert!(fs.nlookup_of(dst_ino).unwrap() >= 1);

        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "dst", 0)
            .expect("rename over");

        assert_eq!(
            fs.path_for_ino(dst_ino).as_deref(),
            Some(format!("\0stale-{dst_ino}").as_str())
        );
        assert!(fs.cached_fi(dst_ino).is_none());
        let (ttl, attr) = fs.getattr_reply(dst_ino).expect("detached getattr");
        assert!(ttl.is_zero());
        assert_eq!(attr.nlink, 0);
        assert_eq!(attr.size, b"old-dest".len() as u64);
        let (fh, flags) = fs
            .open_inode(dst_ino, libc::O_RDONLY)
            .expect("reopen parked");
        assert_eq!(flags, 0);
        assert_eq!(fs.test_read(fh, 0, 32).unwrap(), b"old-dest");
        assert_eq!(fs.open_inode(dst_ino, libc::O_RDWR).unwrap_err(), EACCES);
        assert_eq!(fs.open_inode(dst_ino, libc::O_WRONLY).unwrap_err(), EACCES);
        assert_eq!(fs.path_for_ino(src_ino).as_deref(), Some("/dst"));
        let (src_ttl, src_attr) = fs.getattr_reply(src_ino).expect("moved source");
        assert_eq!(src_attr.size, b"new-src".len() as u64);
        assert_eq!(src_attr.nlink, 1);
        assert!(src_ttl.is_zero(), "copied-up source is overlay-backed");
        assert_eq!(fs.xattr_value(dst_ino, "user.demo").unwrap(), None);
    }

    /// Regression (#88): unlink of an overlay file the kernel still holds
    /// kept answering ENOENT. The old id still reads the old body.
    #[test]
    fn detached_overlay_unlink_keeps_attrs_and_bytes() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/gone", b"keep-me");
        let (ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("gone"))
            .expect("lookup");
        fs.remove_entry(FUSE_ROOT_ID, OsStr::new("gone"), false)
            .expect("unlink");
        assert!(fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("gone")).is_none());
        let (ttl, attr) = fs.getattr_reply(ino).expect("detached getattr");
        assert!(ttl.is_zero());
        assert_eq!(attr.nlink, 0);
        let (fh, _) = fs.open_inode(ino, libc::O_RDONLY).expect("reopen");
        assert_eq!(fs.test_read(fh, 0, 32).unwrap(), b"keep-me");
    }

    /// Regression (#88): a reader opened on an archive member before
    /// rename-over, and one opened on the detached id, must keep the old
    /// payload after `content_generation` advances. A still-linked member
    /// still refreshes.
    #[test]
    fn detached_archive_rename_open_skips_refresh() {
        let (_dir, fs, bytes) = byte_members_fs(&[
            ("final", "OLD-FINAL"),
            ("src", "NEW-SRC"),
            ("keep", "KEEP-BEFORE"),
        ]);
        let (final_ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("final"))
            .expect("final");
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("src"))
            .expect("src");
        let (fh_before, _) = fs
            .open_inode(final_ino, libc::O_RDONLY)
            .expect("open final before rename");
        assert!(matches!(
            fs.handles.lock().unwrap().get(&fh_before),
            Some(OpenBackend::Source { .. })
        ));

        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "final", 0)
            .expect("rename over archive member");
        let live = fs.source.lookup("/final", 0).expect("name is the copy-up");
        assert!(
            live.userdata
                .iter()
                .any(|u| matches!(u, UserData::Other(s) if s.starts_with("overlay:"))),
            "post-rename lookup of /final is the overlay file"
        );

        let (fh_detached, flags) = fs
            .open_inode(final_ino, libc::O_RDONLY)
            .expect("open detached archive id");
        assert_eq!(flags, FopenFlags::FOPEN_KEEP_CACHE.bits());
        let (keep_ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("keep"))
            .expect("keep");
        let (fh_keep, _) = fs
            .open_inode(keep_ino, libc::O_RDONLY)
            .expect("open still-linked member");
        let opens_before = bytes.opens.load(Ordering::SeqCst);

        bytes
            .files
            .lock()
            .unwrap()
            .insert("keep".into(), b"KEEP-AFTER".to_vec());
        bytes.gen.fetch_add(1, Ordering::SeqCst);

        assert_eq!(
            fs.test_read(fh_before, 0, 32).unwrap(),
            b"OLD-FINAL",
            "fh opened before rename must not follow the new file"
        );
        assert_eq!(fs.test_read(fh_detached, 0, 32).unwrap(), b"OLD-FINAL");
        assert_eq!(
            bytes.opens.load(Ordering::SeqCst),
            opens_before,
            "detached reads must not reopen"
        );
        assert_eq!(fs.test_read(fh_keep, 0, 32).unwrap(), b"KEEP-AFTER");
        assert!(
            bytes.opens.load(Ordering::SeqCst) > opens_before,
            "still-linked member refreshes"
        );
        assert!(fs.cached_fi(final_ino).is_none());
        let (ttl, attr) = fs.getattr_reply(final_ino).expect("getattr after bump");
        assert!(ttl.is_zero());
        assert_eq!(attr.nlink, 0);
        assert_eq!(attr.size, b"OLD-FINAL".len() as u64);
    }

    /// Regression (#88): unlink of a looked-up archive member keeps the old
    /// bytes across a generation bump. The name is gone.
    #[test]
    fn detached_archive_unlink_keeps_bytes_across_generation() {
        let (_dir, fs, bytes) = byte_members_fs(&[("gone", "ARCHIVE-BODY")]);
        let (ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("gone"))
            .expect("lookup");
        fs.remove_entry(FUSE_ROOT_ID, OsStr::new("gone"), false)
            .expect("unlink");
        assert!(fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("gone")).is_none());
        let (fh, _) = fs.open_inode(ino, libc::O_RDONLY).expect("open detached");
        let opens = bytes.opens.load(Ordering::SeqCst);
        bytes
            .files
            .lock()
            .unwrap()
            .insert("gone".into(), b"REPLACED".to_vec());
        bytes.gen.fetch_add(1, Ordering::SeqCst);
        assert_eq!(fs.test_read(fh, 0, 32).unwrap(), b"ARCHIVE-BODY");
        assert_eq!(bytes.opens.load(Ordering::SeqCst), opens);
    }

    /// Regression (#88): detached GETXATTR and readlink use the pre-rename
    /// FileInfo, not lookup of the name after the replace.
    #[test]
    fn detached_archive_xattr_and_readlink_use_last_fi() {
        let mut files = BTreeMap::new();
        files.insert("reg".into(), xattr_fi(S_IFREG | 0o644, "", "old-reg", 4));
        files.insert(
            "lnk".into(),
            xattr_fi(S_IFLNK | 0o777, "old-target", "old-link", 0),
        );
        files.insert("newreg".into(), xattr_fi(S_IFREG | 0o644, "", "new-reg", 4));
        files.insert(
            "newlnk".into(),
            xattr_fi(S_IFREG | 0o644, "", "new-link", 4),
        );
        let (_dir, fs) = xattr_members_fs(files);
        let (reg, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("reg"))
            .expect("reg");
        let (lnk, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("lnk"))
            .expect("lnk");
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("newreg")).unwrap();
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("newlnk")).unwrap();
        fs.rename_paths(FUSE_ROOT_ID, "newreg", FUSE_ROOT_ID, "reg", 0)
            .unwrap();
        fs.rename_paths(FUSE_ROOT_ID, "newlnk", FUSE_ROOT_ID, "lnk", 0)
            .unwrap();

        assert_eq!(
            fs.xattr_value(reg, "user.demo").unwrap().as_deref(),
            Some(b"old-reg".as_slice())
        );
        assert_eq!(fs.xattr_list(reg).unwrap(), vec!["user.demo".to_string()]);
        let live = fs.source.lookup("/reg", 0).expect("replaced name");
        assert_eq!(
            fs.source.get_xattr(&live, "user.demo"),
            Some(b"new-reg".to_vec())
        );
        assert_eq!(
            fs.xattr_value(lnk, "user.demo").unwrap().as_deref(),
            Some(b"old-link".as_slice())
        );
        assert_eq!(fs.readlink_target(lnk).as_deref(), Some("old-target"));
        assert_eq!(fs.open_inode(lnk, libc::O_RDONLY).unwrap_err(), EACCES);
    }

    /// Regression (#88): a symlink park has no fd. Readlink and getattr use
    /// the snapshot; open is EACCES.
    #[test]
    fn detached_symlink_metadata_only_open_eacces() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        ov.create_symlink("/link", "old-target").expect("symlink");
        overlay_write_new(&ov, "/src", b"file");
        let (link_ino, _, _) = fs
            .lookup_entry(FUSE_ROOT_ID, OsStr::new("link"))
            .expect("link");
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("src")).unwrap();
        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "link", 0)
            .expect("file over symlink");
        assert!(fs
            .inodes
            .lock()
            .unwrap()
            .get(&link_ino)
            .is_some_and(|e| { e.detached.as_ref().is_some_and(|d| d.fd.is_none()) }));
        assert_eq!(fs.readlink_target(link_ino).as_deref(), Some("old-target"));
        let (ttl, attr) = fs.getattr_reply(link_ino).expect("getattr");
        assert!(ttl.is_zero());
        assert_eq!(attr.nlink, 0);
        assert_eq!(attr.kind, FileType::Symlink);
        assert_eq!(fs.open_inode(link_ino, libc::O_RDONLY).unwrap_err(), EACCES);
    }

    /// Regression (#88): the parked fd closes only when FORGET brings nlookup
    /// to 0. The close is counted on `ParkedFd` drop (an fd number can be
    /// reused, so `F_GETFD` is not an oracle).
    #[test]
    fn forget_closes_parked_fd_only_at_zero() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/dst", b"old-dest");
        overlay_write_new(&ov, "/src", b"new-src");
        let counter = Arc::new(AtomicUsize::new(0));
        fs.track_parked_fd_drops(Arc::clone(&counter));
        let (dst, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("dst")).unwrap();
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("dst")).unwrap();
        assert_eq!(fs.nlookup_of(dst), Some(2));
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("src")).unwrap();
        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "dst", 0)
            .unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(fs.path_for_ino(dst).is_some());

        fs.forget_nlookup(dst, 1);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "partial forget keeps the fd"
        );
        assert!(fs.path_for_ino(dst).is_some());

        fs.forget_nlookup(dst, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(fs.path_for_ino(dst).is_none());

        fs.forget_nlookup(dst, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Regression (#88): FORGET of a still-linked file down to 0 keeps the
    /// inode. The next lookup reuses it.
    #[test]
    fn forget_partial_keeps_still_linked_inode() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/p", b"p");
        let (ino, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("p")).unwrap();
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("p")).unwrap();
        assert_eq!(fs.nlookup_of(ino), Some(2));
        fs.forget_nlookup(ino, 1);
        assert_eq!(fs.nlookup_of(ino), Some(1));
        assert_eq!(fs.path_for_ino(ino).as_deref(), Some("/p"));
        assert_eq!(fs.path_to_ino.lock().unwrap().get("/p"), Some(&ino));

        fs.forget_nlookup(ino, 1);
        assert_eq!(fs.nlookup_of(ino), Some(0));
        assert_eq!(fs.path_for_ino(ino).as_deref(), Some("/p"));
        assert_eq!(fs.path_to_ino.lock().unwrap().get("/p"), Some(&ino));

        let (again, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("p")).unwrap();
        assert_eq!(again, ino);
        assert_eq!(fs.nlookup_of(ino), Some(1));
    }

    /// Regression (#88): create after unlink allocates a new nodeid. The
    /// detached id still getattrs until its own FORGET.
    #[test]
    fn create_after_unlink_allocates_new_nodeid() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/a", b"old-a");
        let (old, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("a")).unwrap();
        let n = fs.nlookup_of(old).unwrap();
        fs.remove_entry(FUSE_ROOT_ID, OsStr::new("a"), false)
            .unwrap();
        assert!(fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("a")).is_none());
        let (_ttl, attr, _fh) = fs
            .create_entry(FUSE_ROOT_ID, OsStr::new("a"), 0o644)
            .expect("create");
        assert_ne!(attr.ino.0, old);
        let (got, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("a")).unwrap();
        assert_eq!(got, attr.ino.0);
        assert!(fs.getattr_reply(old).is_ok());
        fs.forget_nlookup(old, n);
        assert!(fs.getattr_reply(old).is_err());
    }

    /// Regression (#88): fh-less SETATTR on a detached id is EACCES and does
    /// not change the orphan. A write fh opened before the rename truncates
    /// that fd. The name keeps the new file's length.
    #[test]
    fn setattr_detached_without_fh_is_eacces_with_write_fh_truncates() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/dst", b"old-dest");
        overlay_write_new(&ov, "/src", b"abcd");
        let (dst, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("dst")).unwrap();
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("src")).unwrap();
        let (write_fh, _) = fs.open_inode(dst, libc::O_RDWR).expect("write fh");
        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "dst", 0)
            .unwrap();

        assert_eq!(fs.setattr_entry(dst, Some(2), None).unwrap_err(), EACCES);
        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        let wfd = overlay_fd_of(&fs, write_fh);
        assert_eq!(unsafe { libc::fstat(wfd, &mut st) }, 0);
        assert_eq!(st.st_size, b"old-dest".len() as i64);

        let (ttl, attr) = fs
            .setattr_entry(dst, Some(3), Some(write_fh))
            .expect("ftruncate write fh");
        assert!(ttl.is_zero());
        assert_eq!(attr.nlink, 0);
        assert_eq!(attr.size, 3);
        assert_eq!(fs.test_read(write_fh, 0, 8).unwrap().len(), 3);

        let live = fs.source.lookup("/dst", 0).expect("new file");
        assert_eq!(live.size, b"abcd".len() as u64);

        let (ro_fh, _) = fs.open_inode(dst, libc::O_RDONLY).expect("reopen");
        assert_eq!(
            fs.setattr_entry(dst, Some(1), Some(ro_fh)).unwrap_err(),
            EACCES
        );
    }

    /// Regression (#88): a write fh opened before rename-over keeps pwrite
    /// on the orphan. lookup of the name sees the incoming file.
    #[test]
    fn pre_rename_writer_keeps_writing_orphan() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/dst", b"old-dest");
        overlay_write_new(&ov, "/src", b"new");
        let (dst, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("dst")).unwrap();
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("src")).unwrap();
        let (fh, _) = fs.open_inode(dst, libc::O_RDWR).unwrap();
        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "dst", 0)
            .unwrap();
        pwrite_all(overlay_fd_of(&fs, fh), b"ORPHAN!\n");
        assert_eq!(fs.test_read(fh, 0, 16).unwrap(), b"ORPHAN!\n");
        let live = fs.source.lookup("/dst", 0).expect("incoming");
        assert_eq!(live.size, b"new".len() as u64);
        let (now, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("dst")).unwrap();
        assert_ne!(now, dst);
        let (fh_live, _) = fs.open_inode(now, libc::O_RDONLY).unwrap();
        assert_eq!(fs.test_read(fh_live, 0, 8).unwrap(), b"new");
    }

    /// Regression (#88): `create_entry` hands the kernel one reference.
    /// Unlink while that count is still positive keeps the inode, the parked
    /// fd, and `last_fi`. FORGET drops them only when nlookup reaches 0.
    #[test]
    fn create_entry_nlookup_is_one_and_unlinked_file_stays_until_forget() {
        let (_dir, _ov, fs) = overlay_fs_for_rename();
        let counter = Arc::new(AtomicUsize::new(0));
        fs.track_parked_fd_drops(Arc::clone(&counter));
        let (_ttl, attr, _fh) = fs
            .create_entry(FUSE_ROOT_ID, OsStr::new("new"), 0o644)
            .expect("create");
        let ino = attr.ino.0;
        assert_eq!(fs.nlookup_of(ino), Some(1), "create replies one lookup");
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("new")).unwrap();
        assert_eq!(fs.nlookup_of(ino), Some(2));

        fs.remove_entry(FUSE_ROOT_ID, OsStr::new("new"), false)
            .expect("unlink");
        assert!(fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("new")).is_none());
        assert!(fs.path_to_ino.lock().unwrap().get("/new").is_none());
        assert_detached_held(&fs, ino, 2);
        assert_eq!(counter.load(Ordering::SeqCst), 0, "parked fd still open");

        fs.forget_nlookup(ino, 1);
        assert_detached_held(&fs, ino, 1);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "partial forget keeps the fd"
        );

        fs.forget_nlookup(ino, 1);
        assert!(fs.nlookup_of(ino).is_none(), "forget to 0 drops the inode");
        assert_eq!(counter.load(Ordering::SeqCst), 1, "parked fd closed at 0");
        assert!(fs.getattr_reply(ino).is_err());
    }

    /// Regression (#88): a created file replaced while nlookup > 0 keeps its
    /// inode, parked fd, and `last_fi` until FORGET brings the count to 0.
    #[test]
    fn create_entry_nlookup_replaced_file_stays_until_forget() {
        let (_dir, _ov, fs) = overlay_fs_for_rename();
        let counter = Arc::new(AtomicUsize::new(0));
        fs.track_parked_fd_drops(Arc::clone(&counter));
        let (_ttl, attr, _fh) = fs
            .create_entry(FUSE_ROOT_ID, OsStr::new("dst"), 0o644)
            .expect("create dst");
        let dst = attr.ino.0;
        assert_eq!(fs.nlookup_of(dst), Some(1));
        fs.create_entry(FUSE_ROOT_ID, OsStr::new("src"), 0o644)
            .expect("create src");
        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "dst", 0)
            .expect("rename over created file");

        let (now, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("dst")).unwrap();
        assert_ne!(now, dst, "the name is the incoming file");
        assert_detached_held(&fs, dst, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        fs.forget_nlookup(dst, 1);
        assert!(fs.nlookup_of(dst).is_none());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(fs.getattr_reply(dst).is_err());
        // create bumped once; the lookup above bumped again.
        assert_eq!(fs.nlookup_of(now), Some(2));
    }

    /// Inode entry, parked fd, and `last_fi` are still stored at `nlookup`.
    fn assert_detached_held(fs: &RatarmountFs, ino: u64, nlookup: u64) {
        let inodes = fs.inodes.lock().unwrap();
        let ent = inodes.get(&ino).expect("inode entry stays");
        assert_eq!(ent.nlookup, nlookup);
        assert_eq!(ent.path, format!("\0stale-{ino}"));
        let det = ent.detached.as_ref().expect("detached snapshot");
        assert!(det.fd.is_some(), "parked fd stays");
        assert!(det.last_fi.is_some(), "last_fi stays");
        drop(inodes);
        let (ttl, attr) = fs.getattr_reply(ino).expect("detached getattr");
        assert!(ttl.is_zero());
        assert_eq!(attr.nlink, 0);
    }

    /// Regression (#88): root starts at nlookup 1 and is never removed.
    /// `readdirplus_fill` (the body of `Filesystem::readdirplus`) leaves each
    /// child at 0 and does not bump root. A lookup bumps that child; FORGET
    /// then brings it back to 0 and keeps the entry.
    #[test]
    fn nlookup_root_starts_at_one_and_readdirplus_does_not_bump_children() {
        let (_dir, ov, fs) = overlay_fs_for_rename();
        assert_eq!(fs.nlookup_of(FUSE_ROOT_ID), Some(1));
        overlay_write_new(&ov, "/c", b"c");
        assert!(
            fs.path_to_ino.lock().unwrap().get("/c").is_none(),
            "readdirplus must be what allocates the child"
        );

        let mut listed: Vec<(u64, String)> = Vec::new();
        fs.readdirplus_fill(FUSE_ROOT_ID, 0, |cino, _off, name, _ttl, _attr| {
            listed.push((cino, name.to_string()));
            false
        })
        .expect("readdirplus");
        let child = listed
            .iter()
            .find(|(_, name)| name == "c")
            .map(|(ino, _)| *ino)
            .expect("readdirplus omitted c");
        assert_eq!(child, fs.ino_for_path("/c"));
        for (cino, name) in &listed {
            if name == "." || name == ".." {
                continue;
            }
            assert_eq!(fs.nlookup_of(*cino), Some(0), "readdirplus bumped {name}");
        }
        assert_eq!(
            fs.nlookup_of(FUSE_ROOT_ID),
            Some(1),
            "readdirplus must not bump root via . or .."
        );

        fs.forget_nlookup(FUSE_ROOT_ID, 1);
        assert_eq!(fs.nlookup_of(FUSE_ROOT_ID), Some(0));
        assert_eq!(fs.path_for_ino(FUSE_ROOT_ID).as_deref(), Some("/"));

        let (id, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("c")).unwrap();
        assert_eq!(id, child);
        assert_eq!(fs.nlookup_of(child), Some(1));
        fs.forget_nlookup(child, 1);
        assert_eq!(fs.nlookup_of(child), Some(0));
        assert_eq!(fs.path_for_ino(child).as_deref(), Some("/c"));
        assert_eq!(fs.path_to_ino.lock().unwrap().get("/c"), Some(&child));
    }

    /// Regression (#88): macOS must not set a soft NOFILE of RLIM_INFINITY.
    /// The cap is min(finite hard, kern.maxfilesperproc, OPEN_MAX).
    ///
    /// Sysctl and OPEN_MAX differ below so ignoring either one fails.
    #[test]
    fn nofile_soft_target_caps_infinite_hard_limit() {
        assert_eq!(
            nofile_soft_target(libc::RLIM_INFINITY, Some(10_240), 10_240),
            10_240
        );
        assert_eq!(nofile_soft_target(512, Some(10_240), 10_240), 512);
        assert_eq!(
            nofile_soft_target(libc::RLIM_INFINITY, None, 10_240),
            10_240
        );
        assert_eq!(
            nofile_soft_target(libc::RLIM_INFINITY, Some(100), 10_240),
            100,
            "sysctl below OPEN_MAX"
        );
        assert_eq!(
            nofile_soft_target(libc::RLIM_INFINITY, Some(50_000), 10_240),
            10_240,
            "OPEN_MAX below sysctl"
        );
        assert_eq!(
            nofile_soft_target(50, Some(100), 10_240),
            50,
            "finite hard below sysctl and OPEN_MAX"
        );
        assert_eq!(
            nofile_soft_target(libc::RLIM_INFINITY, None, 8_192),
            8_192,
            "missing sysctl uses OPEN_MAX"
        );
        let mut before = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut before) },
            0
        );
        raise_nofile_soft_to_hard();
        let mut after = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut after) },
            0
        );
        assert!(
            after.rlim_cur >= before.rlim_cur,
            "soft {} -> {} must not decrease",
            before.rlim_cur,
            after.rlim_cur
        );
    }

    /// Regression (#88): `Filesystem::init` and `mount_blocking` call
    /// [`raise_nofile_soft_to_hard`]. After a lowered soft limit, that raise
    /// sets soft == hard on Linux.
    ///
    /// The probe runs in a re-exec'd child. `RLIMIT_NOFILE` is process-wide,
    /// and a raw `fork` from the multithreaded test harness can deadlock.
    /// The parent never calls `setrlimit`.
    #[test]
    fn nofile_soft_raise_to_hard_after_lower() {
        if std::env::var_os("RATARMOUNT_FUSE_NOFILE_PROBE").is_some() {
            nofile_probe_lower_and_raise();
            return;
        }
        let exe = std::env::current_exe().expect("current_exe");
        let thread = std::thread::current();
        let name = thread
            .name()
            .unwrap_or("tests::nofile_soft_raise_to_hard_after_lower");
        let out = Command::new(exe)
            .arg(name)
            .arg("--exact")
            .arg("--test-threads")
            .arg("1")
            .env("RATARMOUNT_FUSE_NOFILE_PROBE", "1")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .output()
            .expect("spawn nofile probe");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "nofile probe status {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            out.status
        );
    }

    /// Lower soft `RLIMIT_NOFILE`, then run the init/startup raise.
    fn nofile_probe_lower_and_raise() {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) },
            0,
            "getrlimit: {}",
            std::io::Error::last_os_error()
        );
        let hard = lim.rlim_max;
        let target = nofile_target(hard);
        let floor = nofile_open_fd_floor();
        assert!(
            floor < target,
            "cannot lower soft below target {target} (open-fd floor {floor}, hard {hard})"
        );
        let lowered = libc::rlimit {
            rlim_cur: floor,
            rlim_max: hard,
        };
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) },
            0,
            "setrlimit soft {floor}: {}",
            std::io::Error::last_os_error()
        );
        let mut mid = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut mid) }, 0);
        assert!(
            mid.rlim_cur < target,
            "soft {} was not lowered below target {target}",
            mid.rlim_cur
        );
        // Same function `Filesystem::init` and `mount_blocking` call.
        raise_nofile_soft_to_hard();
        let mut after = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut after) },
            0
        );
        assert_eq!(after.rlim_max, hard, "hard limit unchanged");
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            after.rlim_cur, hard,
            "startup raise sets soft == hard (got {})",
            after.rlim_cur
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            after.rlim_cur,
            nofile_target(hard),
            "startup raise sets the macOS cap"
        );
    }

    fn nofile_open_fd_floor() -> libc::rlim_t {
        let dir = if cfg!(target_os = "linux") {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        let n = std::fs::read_dir(dir)
            .map(|rd| rd.filter(|e| e.is_ok()).count())
            .unwrap_or(32);
        (n as libc::rlim_t).saturating_add(16)
    }

    /// Regression (#88 on #92 / #91): rename-over still queues the old name
    /// and both children, with no Entry for the destination, and getattr of
    /// the replaced id now succeeds with TTL 0.
    #[test]
    fn rename_over_still_queues_destination_inode_not_destination_name() {
        let (_dir, fs) = readable_members_fs(&["m", "t"]);
        let rec = attach_recording(&fs);
        fs.getattr_reply(FUSE_ROOT_ID).expect("getattr root");
        let (child_m, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("m")).unwrap();
        let (child_t, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("t")).unwrap();
        fs.rename_paths(FUSE_ROOT_ID, "m", FUSE_ROOT_ID, "t", 0)
            .unwrap();
        assert_eq!(
            flush_recorded(&fs, &rec.rx),
            vec![
                KernelInval::Entry {
                    parent: FUSE_ROOT_ID,
                    name: "m".into(),
                },
                KernelInval::Inode(child_m),
                KernelInval::Inode(child_t),
                KernelInval::Inode(FUSE_ROOT_ID),
            ]
        );
        let (ttl, attr) = fs.getattr_reply(child_t).expect("detached getattr");
        assert!(ttl.is_zero());
        assert_eq!(attr.nlink, 0);
        assert_eq!(attr.size, 4);
        stop_recording(&fs, rec);
    }

    /// Regression (#88): mode 000 still renames and unlinks. Linux park is
    /// O_PATH, so getattr fstats. The read-only proc reopen checks mode.
    /// Root bypasses that EACCES.
    #[cfg(target_os = "linux")]
    #[test]
    fn mode_000_rename_and_unlink_detach_with_fd() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, ov, fs) = overlay_fs_for_rename();
        overlay_write_new(&ov, "/locked", b"secret");
        overlay_write_new(&ov, "/src", b"incoming");
        std::fs::set_permissions(
            ov.root().join("locked"),
            std::fs::Permissions::from_mode(0o000),
        )
        .expect("chmod");
        let (locked, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("locked")).unwrap();
        fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("src")).unwrap();
        fs.rename_paths(FUSE_ROOT_ID, "src", FUSE_ROOT_ID, "locked", 0)
            .expect("rename over mode 000");
        let (ttl, attr) = fs.getattr_reply(locked).expect("fstat O_PATH");
        assert!(ttl.is_zero());
        assert_eq!(attr.nlink, 0);
        let open = fs.open_inode(locked, libc::O_RDONLY);
        if unsafe { libc::geteuid() } == 0 {
            assert!(open.is_ok(), "root bypasses mode 000 on reopen");
        } else {
            assert_eq!(open.unwrap_err(), EACCES);
        }

        overlay_write_new(&ov, "/gone", b"g");
        std::fs::set_permissions(
            ov.root().join("gone"),
            std::fs::Permissions::from_mode(0o000),
        )
        .expect("chmod gone");
        let (gone, _, _) = fs.lookup_entry(FUSE_ROOT_ID, OsStr::new("gone")).unwrap();
        fs.remove_entry(FUSE_ROOT_ID, OsStr::new("gone"), false)
            .expect("unlink mode 000");
        assert!(fs.getattr_reply(gone).is_ok());
    }
}

#[cfg(test)]
mod sandbox_attr_tests {
    use super::*;

    /// Regression: containers must see mapped owners on regular, directory and symlink attrs.
    #[test]
    fn regression_mapped_attrs_include_detached_and_unset() {
        let source =
            Arc::new(ratarmount_compositing::FolderMountSource::new(std::env::temp_dir()).unwrap());
        let plain = RatarmountFs::new(source.clone(), None);
        let mapped = RatarmountFs::new(source, None).with_attribute_mapping(
            AttributeMapping::parse("uid=12345,gid=23456,umask=027").unwrap(),
        );
        for mode in [0o100777, 0o040777, 0o120777] {
            let mut fi = ratarmount_core::create_root_file_info();
            fi.mode = mode;
            fi.uid = 42;
            fi.gid = 43;
            let attr = mapped.mapped_file_attr(7, &fi);
            assert_eq!((attr.uid, attr.gid, attr.perm), (12345, 23456, 0o750));
            let attr = plain.mapped_file_attr(7, &fi);
            assert_eq!((attr.uid, attr.gid, attr.perm), (42, 43, 0o777));
            let detached = mapped.mapped_attr(RatarmountFs::file_attr_nlink(7, &fi, 0));
            assert_eq!(
                (detached.uid, detached.gid, detached.perm, detached.nlink),
                (12345, 23456, 0o750, 0)
            );
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        stat.st_uid = 42;
        stat.st_gid = 43;
        stat.st_mode = 0o100777;
        let attr = mapped.mapped_attr(file_attr_from_stat(7, &stat));
        assert_eq!((attr.uid, attr.gid, attr.perm), (12345, 23456, 0o750));
        assert!(parse_fuse_options("uid=12345,gid=23456,umask=027,noatime")
            .iter()
            .all(|option| *option == MountOption::NoAtime));
    }

    /// Regression: mapped create replies must not store the container's uid/gid in the overlay.
    #[test]
    fn regression_mapped_create_keeps_real_overlay_owner() {
        use std::os::unix::fs::MetadataExt;
        let base = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = Arc::new(ratarmount_compositing::FolderMountSource::new(base.path()).unwrap());
        let overlay = Arc::new(WriteOverlay::new(source, directory.path()).unwrap());
        let fs = RatarmountFs::new(overlay.clone(), Some(overlay.clone())).with_attribute_mapping(
            AttributeMapping::parse("uid=12345,gid=23456,umask=027").unwrap(),
        );
        let (_, attr, _) = fs
            .create_entry(FUSE_ROOT_ID, OsStr::new("created"), 0o666)
            .unwrap();
        let metadata = std::fs::metadata(directory.path().join("created")).unwrap();
        assert_eq!((attr.uid, attr.gid), (12345, 23456));
        assert_eq!(
            (metadata.uid(), metadata.gid()),
            (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
        );
        assert_eq!(u32::from(attr.perm), metadata.mode() & 0o7777 & !0o027);
        let raw = overlay.lookup("/created", 0).unwrap();
        assert_eq!((raw.uid, raw.gid), (metadata.uid(), metadata.gid()));
    }

    /// Regression: allow_other must explain the fuse.conf line before fusermount fails.
    #[test]
    fn regression_allow_other_commented_whitespace_and_missing_config() {
        for contents in [
            "# user_allow_other",
            "  #user_allow_other",
            "",
            "user_allow_other=no",
            "user_allow_other extra",
        ] {
            assert!(!fuse_conf_allows_other(contents), "{contents}");
        }
        for contents in [
            "user_allow_other",
            "  user_allow_other \t",
            "# comment\n\tuser_allow_other # permitted\n",
        ] {
            assert!(fuse_conf_allows_other(contents), "{contents}");
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fuse.conf");
        let error = validate_allow_other_with("allow_other", 1000, &path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("uncommented line user_allow_other to /etc/fuse.conf"));
        assert!(validate_allow_other_with("allow_other", 0, &path).is_ok());
        assert!(validate_allow_other_with("noatime", 1000, &path).is_ok());
        std::fs::write(&path, "# user_allow_other\n user_allow_other # enable\n").unwrap();
        assert!(validate_allow_other_with("allow_other", 1000, &path).is_ok());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod unmount_retry_tests {
    use super::*;

    fn fake_fusermount(code: i32, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    const BUSY: &str = "fusermount3: failed to unmount /m: Device or resource busy\n";

    fn fast_retry() -> RetryPolicy {
        RetryPolicy {
            interval: Duration::from_millis(2),
            deadline: Duration::from_millis(60),
        }
    }

    /// Regression: one transient EBUSY (desktop mount watcher) failed the unmount.
    #[test]
    fn regression_unmount_retries_busy_until_success() {
        let mut calls = 0;
        let mut run = |args: &[&OsStr]| {
            calls += 1;
            assert_eq!(args, [OsStr::new("-u"), OsStr::new("/m")]);
            Ok(if calls < 3 {
                fake_fusermount(1, BUSY)
            } else {
                fake_fusermount(0, "")
            })
        };
        unmount_linux_with(
            Path::new("/m"),
            &["-u"],
            fast_retry(),
            &mut run,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(calls, 3);
    }

    /// Anything other than EBUSY is final: one run, `ErrorKind::Other`, stderr kept.
    #[test]
    fn regression_unmount_not_mounted_is_not_retried() {
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(
                1,
                "fusermount3: entry for /m not found in /etc/mtab\n",
            ))
        };
        let e = unmount_linux_with(
            Path::new("/m"),
            &["-u"],
            fast_retry(),
            &mut run,
            &mut |_| {},
        )
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(e.kind(), ErrorKind::Other);
        let msg = e.to_string();
        assert!(msg.contains("fusermount failed for /m"), "{msg}");
        assert!(msg.contains("not found in /etc/mtab"), "{msg}");
    }

    /// Persistent EBUSY ends in a typed `ResourceBusy` after the deadline.
    #[test]
    fn regression_unmount_busy_forever_is_resource_busy() {
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(1, BUSY))
        };
        let started = std::time::Instant::now();
        let e = unmount_linux_with(
            Path::new("/m"),
            &["-u"],
            fast_retry(),
            &mut run,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(calls > 2, "retried only {calls} times");
        assert_eq!(e.kind(), ErrorKind::ResourceBusy);
        let msg = e.to_string();
        assert!(msg.contains("Device or resource busy"), "{msg}");
        assert!(msg.contains("still busy after"), "{msg}");
    }

    /// A runner that cannot spawn fusermount surfaces the spawn error unretried.
    #[test]
    fn regression_unmount_spawn_error_is_returned() {
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Err(std::io::Error::from(ErrorKind::NotFound))
        };
        let e = unmount_linux_with(
            Path::new("/m"),
            &["-u"],
            fast_retry(),
            &mut run,
            &mut |_| {},
        )
        .unwrap_err();
        assert_eq!((calls, e.kind()), (1, ErrorKind::NotFound));
    }

    /// Regression: the echoed mountpoint is not the diagnostic. A path that contains
    /// "Device or resource busy" with a "No such file or directory" error must fail fast.
    #[test]
    fn regression_unmount_busy_text_in_mountpoint_is_not_busy() {
        let mp = "/tmp/Device or resource busy/mnt";
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(
                1,
                &format!("fusermount3: failed to unmount {mp}: No such file or directory\n"),
            ))
        };
        let e = unmount_linux_with(Path::new(mp), &["-u"], fast_retry(), &mut run, &mut |_| {})
            .unwrap_err();
        assert_eq!((calls, e.kind()), (1, ErrorKind::Other));
    }

    /// A genuinely busy mount whose path also contains the phrase still retries.
    #[test]
    fn regression_unmount_busy_with_busy_text_in_mountpoint_retries() {
        let mp = "/tmp/Device or resource busy/mnt";
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(
                1,
                &format!("fusermount3: failed to unmount {mp}: Device or resource busy\n"),
            ))
        };
        let e = unmount_linux_with(Path::new(mp), &["-u"], fast_retry(), &mut run, &mut |_| {})
            .unwrap_err();
        assert!(calls > 2, "retried only {calls} times");
        assert_eq!(e.kind(), ErrorKind::ResourceBusy);
    }

    /// Regression: relative mountpoints `busy` / `resource` were stripped from the diagnostic,
    /// so a real EBUSY was not retried.
    #[test]
    fn regression_unmount_busy_relative_mountpoint_retries() {
        for mp in ["busy", "resource"] {
            let mut calls = 0;
            let mut run = |_: &[&OsStr]| {
                calls += 1;
                Ok(fake_fusermount(
                    1,
                    &format!("fusermount3: failed to unmount {mp}: Device or resource busy\n"),
                ))
            };
            let e = unmount_linux_with(Path::new(mp), &["-u"], fast_retry(), &mut run, &mut |_| {})
                .unwrap_err();
            assert!(calls > 2, "{mp}: retried only {calls} times");
            assert_eq!(e.kind(), ErrorKind::ResourceBusy, "{mp}");
        }
    }

    /// Regression: a newline inside the mountpoint made its first line look like a busy diagnostic.
    #[test]
    fn regression_unmount_busy_newline_in_mountpoint_is_not_busy() {
        let mp = "/x/Device or resource busy\n/mnt";
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(
                1,
                &format!("fusermount3: failed to unmount {mp}: No such file or directory\n"),
            ))
        };
        let e = unmount_linux_with(Path::new(mp), &["-u"], fast_retry(), &mut run, &mut |_| {})
            .unwrap_err();
        assert_eq!((calls, e.kind()), (1, ErrorKind::Other));
    }

    const MUSL_BUSY: &str = "fusermount3: failed to unmount /m: Resource busy\n";

    /// Regression: musl's strerror(EBUSY) is "Resource busy"; Alpine fusermount3 got no retry.
    #[test]
    fn regression_unmount_musl_busy_text_retries_then_succeeds() {
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(if calls < 3 {
                fake_fusermount(1, MUSL_BUSY)
            } else {
                fake_fusermount(0, "")
            })
        };
        let r = unmount_linux_with(
            Path::new("/m"),
            &["-u"],
            fast_retry(),
            &mut run,
            &mut |_| {},
        );
        assert!(r.is_ok(), "musl busy text was not retried: {r:?}");
        assert_eq!(calls, 3);
    }

    /// Regression: persistent musl EBUSY must end in the typed `ResourceBusy`.
    #[test]
    fn regression_unmount_musl_busy_forever_is_resource_busy() {
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(1, MUSL_BUSY))
        };
        let e = unmount_linux_with(
            Path::new("/m"),
            &["-u"],
            fast_retry(),
            &mut run,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(calls > 2, "retried only {calls} times");
        assert_eq!(e.kind(), ErrorKind::ResourceBusy, "{e}");
    }

    /// Already passes before the musl fix; it keeps the suffix-only match from regressing:
    /// "Resource busy" in the echoed path with a different error is final.
    #[test]
    fn regression_unmount_musl_busy_text_in_mountpoint_is_not_busy() {
        let mp = "/tmp/Resource busy/mnt";
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(
                1,
                &format!("fusermount3: failed to unmount {mp}: No such file or directory\n"),
            ))
        };
        let e = unmount_linux_with(Path::new(mp), &["-u"], fast_retry(), &mut run, &mut |_| {})
            .unwrap_err();
        assert_eq!((calls, e.kind()), (1, ErrorKind::Other));
    }

    /// Regression (K3): the lazy path logged `fusermount3 -u ...: busy (attempt 1), retrying`
    /// with no retry, and the error said "still busy after 1 attempts over ~0ms".
    #[test]
    fn regression_unmount_lazy_busy_does_not_claim_retry() {
        let none = RetryPolicy {
            interval: Duration::ZERO,
            deadline: Duration::ZERO,
        };
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(1, BUSY))
        };
        let mut notes: Vec<String> = Vec::new();
        let e = unmount_linux_with(Path::new("/m"), &["-u", "-z"], none, &mut run, &mut |m| {
            notes.push(m.to_string())
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(e.kind(), ErrorKind::ResourceBusy);
        let retrying: Vec<_> = notes.iter().filter(|m| m.contains("retrying")).collect();
        assert!(retrying.is_empty(), "claimed a retry: {notes:?}");
        let msg = e.to_string();
        assert!(msg.contains("(busy)"), "{msg}");
        assert!(!msg.contains("attempts over"), "{msg}");
        assert!(!msg.contains("still busy after"), "{msg}");
    }

    /// Regression (K3): retry messages name the real flags and appear only when another
    /// attempt follows.
    #[test]
    fn regression_unmount_retry_messages_name_flags_and_count() {
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(if calls < 3 {
                fake_fusermount(1, BUSY)
            } else {
                fake_fusermount(0, "")
            })
        };
        let mut notes: Vec<String> = Vec::new();
        unmount_linux_with(
            Path::new("/m"),
            &["-u", "-z"],
            fast_retry(),
            &mut run,
            &mut |m| notes.push(m.to_string()),
        )
        .unwrap();
        assert_eq!(notes.len(), 2, "{notes:?}");
        for m in &notes {
            assert!(m.contains("fusermount3 -u -z /m"), "{m}");
            assert!(m.contains("busy (attempt"), "{m}");
            assert!(m.contains("retrying"), "{m}");
        }
    }

    /// Regression (K3): when the deadline is hit, the last busy attempt must not log "retrying".
    #[test]
    fn regression_unmount_exhaustion_logs_one_fewer_retry_than_attempts() {
        let mut calls = 0;
        let mut run = |_: &[&OsStr]| {
            calls += 1;
            Ok(fake_fusermount(1, BUSY))
        };
        let mut notes: Vec<String> = Vec::new();
        let e = unmount_linux_with(Path::new("/m"), &["-u"], fast_retry(), &mut run, &mut |m| {
            notes.push(m.to_string())
        })
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ResourceBusy);
        assert_eq!(notes.len() + 1, calls, "{notes:?}");
        assert!(e.to_string().contains("still busy after"), "{e}");
    }
}
