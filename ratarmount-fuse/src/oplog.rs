//! Buffered filesystem operation journal. This is separate from the archive commit journal.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use base64::Engine;
use ratarmount_compositing::{OverlayMutation, OverlayQuota, ReadOnlyGlobs};
use serde_json::{json, Value};

pub const STATUS_KEYS: &[&str] = &[
    "user.ratarmount.base_digest",
    "user.ratarmount.stack_digest",
    "user.ratarmount.sealed",
    "user.ratarmount.layers",
    "user.ratarmount.journal",
    "user.ratarmount.stats",
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Reads {
    #[default]
    All,
    First,
}

#[derive(Clone, Debug)]
pub struct JournalOptions {
    pub path: PathBuf,
    pub exclude: Vec<String>,
    pub reads: Reads,
    pub sync: bool,
}

/// Passed into mount setup, before starting the writer thread (and after fork).
#[derive(Clone, Default)]
pub struct MountActivity {
    pub journal: Option<JournalOptions>,
    pub quota: Option<Arc<OverlayQuota>>,
    pub readonly: Option<Arc<ReadOnlyGlobs>>,
    /// Optional identity for a read-only composed mount. A writable overlay's
    /// held metadata connection takes precedence over these values.
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Caller {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Default, Debug)]
struct Ranges {
    spans: Vec<[u64; 2]>,
    bytes: u64,
    count: u64,
    first_ts: Option<u64>,
    truncated: bool,
}

impl Ranges {
    fn add(&mut self, offset: u64, len: u64, ts: u64, first: bool) {
        self.bytes = self.bytes.saturating_add(len);
        self.count += 1;
        self.first_ts.get_or_insert(ts);
        if len == 0 || (first && !self.spans.is_empty()) {
            return;
        }
        self.spans.push([offset, len]);
        self.spans.sort_unstable_by_key(|r| r[0]);
        let mut merged: Vec<[u64; 2]> = Vec::with_capacity(65);
        for [off, size] in self.spans.drain(..) {
            if let Some(last) = merged.last_mut() {
                let end = last[0].saturating_add(last[1]);
                if off <= end {
                    last[1] = end.max(off.saturating_add(size)) - last[0];
                    continue;
                }
            }
            merged.push([off, size]);
        }
        if merged.len() > 64 {
            self.truncated = true;
            merged.truncate(64);
        }
        self.spans = merged;
    }
}

struct Handle {
    path: String,
    caller: Caller,
    layer: String,
    read: Ranges,
    write: Ranges,
}

#[derive(Default)]
struct Stats {
    bytes_read: u64,
    bytes_written: u64,
    paths: BTreeSet<String>,
    ops: BTreeMap<String, u64>,
    erofs_denied: u64,
}

struct Writer {
    tx: mpsc::SyncSender<Value>,
    join: JoinHandle<io::Result<()>>,
}

// Policy observers run under overlay locks. Capture the precise denied path;
// the request logs it after the operation returns, outside those locks.
thread_local! {
    static DENIAL: RefCell<Option<Option<String>>> = const { RefCell::new(None) };
}

pub struct OpLog {
    start: Instant,
    writer: Mutex<Option<Writer>>,
    failure: Arc<Mutex<Option<String>>>,
    exclude: ReadOnlyGlobs,
    reads: Reads,
    path: Option<PathBuf>,
    handles: Mutex<HashMap<u64, Handle>>,
    dirs: Mutex<HashMap<u64, bool>>,
    comms: Mutex<HashMap<u32, Option<String>>>,
    stats: Mutex<Stats>,
}

impl Default for OpLog {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            writer: Mutex::new(None),
            failure: Arc::new(Mutex::new(None)),
            exclude: ReadOnlyGlobs::new(std::iter::empty::<&str>()).expect("empty globs"),
            reads: Reads::All,
            path: None,
            handles: Mutex::new(HashMap::new()),
            dirs: Mutex::new(HashMap::new()),
            comms: Mutex::new(HashMap::new()),
            stats: Mutex::new(Stats::default()),
        }
    }
}

impl OpLog {
    pub fn open(
        options: &JournalOptions,
        mount: &Path,
        overlay: Option<&Path>,
        metadata: &BTreeMap<String, String>,
    ) -> io::Result<Arc<Self>> {
        let path = validate_path(&options.path, mount, overlay)?;
        let exclude = ReadOnlyGlobs::new(&options.exclude)?;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal must be a regular file",
            ));
        }
        let mut output = BufWriter::new(file);
        // Separate sessions in an append-only file, even after a killed writer.
        if output.get_ref().metadata()?.len() != 0 {
            output.write_all(b"\n")?;
        }
        let start = Instant::now();
        write_line(
            &mut output,
            &json!({"journal": 1, "mount": mount,
            "base_digest": metadata.get("base_digest").map(String::as_str).unwrap_or(""),
            "stack_digest": metadata.get("stack_digest").map(String::as_str).unwrap_or(""),
            "overlay": overlay, "t0": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            "clock": "monotonic_ns"}),
        )?;
        output.flush()?;
        let (tx, rx) = mpsc::sync_channel(1024);
        let failure = Arc::new(Mutex::new(None));
        let failed = failure.clone();
        let sync = options.sync;
        let join = std::thread::Builder::new()
            .name("ratarmount-oplog".into())
            .spawn(move || {
                let result = writer_loop(output, rx, sync);
                if let Err(error) = &result {
                    *failed.lock().unwrap() = Some(error.to_string());
                    log::error!("operation journal writer: {error}");
                }
                result
            })?;
        Ok(Arc::new(Self {
            start,
            writer: Mutex::new(Some(Writer { tx, join })),
            failure,
            exclude,
            reads: options.reads,
            path: Some(path),
            handles: Mutex::new(HashMap::new()),
            dirs: Mutex::new(HashMap::new()),
            comms: Mutex::new(HashMap::new()),
            stats: Mutex::new(Stats::default()),
        }))
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn ts(&self) -> u64 {
        self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64
    }

    fn comm(&self, pid: u32) -> Option<String> {
        let mut cache = self.comms.lock().unwrap();
        if let Some(comm) = cache.get(&pid) {
            return comm.clone();
        }
        #[cfg(target_os = "linux")]
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim_end_matches('\n').to_owned());
        #[cfg(not(target_os = "linux"))]
        let comm = None;
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(pid, comm.clone());
        comm
    }

    fn event(&self, op: &str, path: &str, caller: Caller) -> Value {
        let mut event = json!({"op": op, "ts": self.ts(), "pid": caller.pid,
            "uid": caller.uid, "gid": caller.gid});
        path_field(&mut event, path.as_bytes());
        if self.path.is_some() {
            if let Some(comm) = self.comm(caller.pid) {
                event["comm"] = comm.into();
            }
        }
        event
    }

    fn send(&self, event: Value) -> io::Result<()> {
        if let Some(error) = self.failure.lock().unwrap().as_ref() {
            return Err(io::Error::other(error.clone()));
        }
        let tx = self.writer.lock().unwrap().as_ref().map(|w| w.tx.clone());
        if let Some(tx) = tx {
            tx.send(event)
                .map_err(|_| io::Error::other("operation journal writer stopped"))?;
        }
        Ok(())
    }

    fn emit(&self, event: Value) {
        let path = event["path"].as_str().unwrap_or("");
        let op = event["op"].as_str().unwrap_or("");
        {
            let mut stats = self.stats.lock().unwrap();
            *stats.ops.entry(op.into()).or_default() += 1;
            stats.paths.insert(path.into());
            if op == "denied" && event["errno"] == libc::EROFS {
                stats.erofs_denied += 1;
            }
        }
        if self.path.is_none()
            || self.exclude.protects(path)
            || event["to"]
                .as_str()
                .is_some_and(|to| self.exclude.protects(to))
        {
            return;
        }
        if let Err(error) = self.send(event) {
            log::error!("operation journal: {error}");
        }
    }

    pub fn record(&self, op: &str, path: &str, caller: Caller, to: Option<&str>) {
        let mut event = self.event(op, path, caller);
        if let Some(to) = to {
            event["to"] = to.trim_start_matches('/').into();
        }
        self.emit(event);
    }

    /// Run outside all FUSE handle-table locks. The policy observer only captures
    /// a path here; bounded-channel backpressure happens after the call returns.
    pub fn observe<T>(
        &self,
        caller: Caller,
        what: &str,
        path: &str,
        call: impl FnOnce() -> Result<T, i32>,
    ) -> Result<T, i32> {
        DENIAL.with(|slot| *slot.borrow_mut() = Some(None));
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                DENIAL.with(|s| *s.borrow_mut() = None);
            }
        }
        let _reset = Reset;
        let result = call();
        let denied_path = DENIAL.with(|s| s.borrow_mut().take().flatten());
        if let Err(errno @ (libc::EROFS | libc::EDQUOT | libc::ENOSPC)) = &result {
            self.denied(denied_path.as_deref().unwrap_or(path), what, *errno, caller);
        }
        result
    }

    pub fn attach_rules(self: &Arc<Self>, rules: &ReadOnlyGlobs) {
        let weak = Arc::downgrade(self);
        rules.set_denial_observer(Arc::new(move |path, op| {
            let captured = DENIAL.with(|slot| {
                let mut slot = slot.borrow_mut();
                if let Some(denied) = slot.as_mut() {
                    *denied = Some(path.into());
                    true
                } else {
                    false
                }
            });
            if !captured {
                if let Some(log) = weak.upgrade() {
                    log.denied(path, mutation_name(op), libc::EROFS, Caller::default());
                }
            }
        }));
    }

    fn denied(&self, path: &str, what: &str, errno: i32, caller: Caller) {
        let mut event = self.event("denied", path, caller);
        event["what"] = what.into();
        event["errno"] = errno.into();
        self.emit(event);
    }

    pub fn opened(&self, fh: u64, path: &str, flags: i32, caller: Caller, layer: String) {
        self.handles.lock().unwrap().insert(
            fh,
            Handle {
                path: path.into(),
                caller,
                layer: layer.clone(),
                read: Ranges::default(),
                write: Ranges::default(),
            },
        );
        let mut event = self.event("open", path, caller);
        event["flags"] = match flags & libc::O_ACCMODE {
            libc::O_WRONLY => "w",
            libc::O_RDWR => "rw",
            _ => "r",
        }
        .into();
        event["layer"] = layer.into();
        self.emit(event);
    }

    pub fn io(&self, fh: u64, offset: u64, bytes: u64, write: bool) {
        let mut handles = self.handles.lock().unwrap();
        if let Some(handle) = handles.get_mut(&fh) {
            let ranges = if write {
                &mut handle.write
            } else {
                &mut handle.read
            };
            ranges.add(
                offset,
                bytes,
                self.ts(),
                !write && self.reads == Reads::First,
            );
            let mut stats = self.stats.lock().unwrap();
            if write {
                stats.bytes_written = stats.bytes_written.saturating_add(bytes);
            } else {
                stats.bytes_read = stats.bytes_read.saturating_add(bytes);
            }
        }
    }

    pub fn released(&self, fh: u64) {
        let handle = self.handles.lock().unwrap().remove(&fh);
        if let Some(handle) = handle {
            self.release_handle(handle);
        }
    }

    fn release_handle(&self, handle: Handle) {
        let mut events = [("read", handle.read), ("write", handle.write)];
        events.sort_by_key(|(_, ranges)| ranges.first_ts);
        for (op, ranges) in events {
            if ranges.count == 0 {
                continue;
            }
            let mut event = self.event(op, &handle.path, handle.caller);
            event["bytes"] = ranges.bytes.into();
            event["ranges"] = json!(ranges.spans);
            event["count"] = ranges.count.into();
            event["first_ts"] = json!(ranges.first_ts);
            event["layer"] = handle.layer.clone().into();
            if ranges.truncated {
                event["ranges_truncated"] = true.into();
            }
            self.emit(event);
        }
    }

    pub fn opendir(&self, fh: u64) {
        self.dirs.lock().unwrap().insert(fh, false);
    }
    pub fn releasedir(&self, fh: u64) {
        self.dirs.lock().unwrap().remove(&fh);
    }
    pub fn readdir(&self, fh: u64, path: &str, entries: usize) {
        let first = {
            let mut dirs = self.dirs.lock().unwrap();
            dirs.get_mut(&fh)
                .is_some_and(|seen| !std::mem::replace(seen, true))
        };
        if first {
            let mut event = json!({"op": "readdir", "ts": self.ts(), "entries": entries});
            path_field(&mut event, path.as_bytes());
            self.emit(event);
        }
    }

    pub fn mark(&self, value: &[u8]) -> Result<(), i32> {
        if self.path.is_none() {
            return Err(libc::ENOTSUP);
        }
        if value.len() > 4096 {
            return Err(libc::EINVAL);
        }
        let label = std::str::from_utf8(value).map_err(|_| libc::EINVAL)?;
        self.send(json!({"op": "mark", "ts": self.ts(), "label": label}))
            .map_err(|_| libc::EIO)?;
        *self
            .stats
            .lock()
            .unwrap()
            .ops
            .entry("mark".into())
            .or_default() += 1;
        Ok(())
    }

    pub fn stats(&self, quota: Option<&OverlayQuota>) -> Value {
        let usage = quota.map(OverlayQuota::usage);
        let stats = self.stats.lock().unwrap();
        json!({"bytes_read": stats.bytes_read, "bytes_written": stats.bytes_written,
            "files_touched": stats.paths.len(), "overlay_bytes": usage.as_ref().map(|u| u.bytes),
            "ops": stats.ops, "erofs_denied": usage.map_or(stats.erofs_denied, |u| u.erofs_denied.max(stats.erofs_denied)),
            "journal_error": *self.failure.lock().unwrap()})
    }

    /// Drain outstanding handles and join the writer before returning from unmount.
    pub fn finish(&self) -> io::Result<()> {
        let handles = std::mem::take(&mut *self.handles.lock().unwrap());
        for (_, handle) in handles {
            self.release_handle(handle);
        }
        let writer = self.writer.lock().unwrap().take();
        if let Some(Writer { tx, join }) = writer {
            drop(tx);
            join.join()
                .map_err(|_| io::Error::other("operation journal writer panicked"))??;
        }
        if let Some(error) = self.failure.lock().unwrap().as_ref() {
            return Err(io::Error::other(error.clone()));
        }
        Ok(())
    }
}

impl Drop for OpLog {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            log::error!("operation journal flush: {error}");
        }
    }
}

fn mutation_name(op: OverlayMutation) -> &'static str {
    match op {
        OverlayMutation::CopyOnWrite => "copy_up",
        OverlayMutation::Create => "create",
        OverlayMutation::OpenWrite => "open",
        OverlayMutation::Write => "write",
        OverlayMutation::Mkdir => "mkdir",
        OverlayMutation::Unlink => "unlink",
        OverlayMutation::Rmdir => "rmdir",
        OverlayMutation::Truncate => "truncate",
        OverlayMutation::Symlink => "symlink",
        OverlayMutation::Rename => "rename",
        OverlayMutation::Reset => "reset",
    }
}

pub fn path_field(record: &mut Value, path: &[u8]) {
    let path = path.strip_prefix(b"/").unwrap_or(path);
    match std::str::from_utf8(path) {
        Ok(path) => record["path"] = path.into(),
        Err(_) => {
            record["path_b64"] = base64::engine::general_purpose::STANDARD
                .encode(path)
                .into()
        }
    }
}

fn write_line(output: &mut impl Write, record: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, record)?;
    output.write_all(b"\n")
}

fn writer_loop(
    mut output: BufWriter<File>,
    rx: mpsc::Receiver<Value>,
    sync: bool,
) -> io::Result<()> {
    let mut last_flush = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => write_line(&mut output, &event)?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if last_flush.elapsed() >= Duration::from_millis(100) {
            output.flush()?;
            last_flush = Instant::now();
        }
    }
    output.flush()?;
    if sync {
        output.get_ref().sync_all()?;
    }
    Ok(())
}

/// Resolve existing ancestors, including symlinks, before checking containment.
pub fn validate_path(path: &Path, mount: &Path, overlay: Option<&Path>) -> io::Result<PathBuf> {
    fn resolve(path: &Path, depth: usize) -> io::Result<PathBuf> {
        if depth > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal path has too many components or symlinks",
            ));
        }
        if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
            let target = std::fs::read_link(path)?;
            return resolve(
                &path.parent().unwrap_or(Path::new(".")).join(target),
                depth + 1,
            );
        }
        match path.canonicalize() {
            Ok(path) => Ok(path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let absolute = std::path::absolute(path)?;
                let parent = absolute.parent().ok_or(e)?;
                let resolved = resolve(parent, depth + 1)?;
                Ok(resolved.join(
                    absolute
                        .file_name()
                        .ok_or_else(|| io::Error::other("invalid journal path"))?,
                ))
            }
            Err(e) => Err(e),
        }
    }
    let path = resolve(path, 0)?;
    if path.starts_with(resolve(mount, 0)?)
        || overlay.is_some_and(|dir| resolve(dir, 0).is_ok_and(|dir| path.starts_with(dir)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal path must be outside the mountpoint and overlay directory",
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(path: PathBuf) -> JournalOptions {
        JournalOptions {
            path,
            exclude: vec![".git/**".into()],
            reads: Reads::All,
            sync: true,
        }
    }

    fn records(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }

    #[test]
    fn regression_oplog_ranges_merge_adjacent_overlapping_and_cap_at_64() {
        let mut ranges = Ranges::default();
        for (off, len) in [(10, 5), (0, 5), (5, 8), (3, 4)] {
            ranges.add(off, len, 1, false);
        }
        assert_eq!(ranges.spans, [[0, 15]]);
        assert_eq!(ranges.bytes, 22);
        assert!(!ranges.truncated);
        for i in 1..=70 {
            ranges.add(i * 20, 2, 1, false);
        }
        assert_eq!(ranges.spans.len(), 64);
        assert!(ranges.truncated);
        assert_eq!(ranges.bytes, 162);
        ranges.add(0, u64::MAX, 2, false);
        assert_eq!(ranges.spans, [[0, u64::MAX]]);
        assert_eq!(ranges.bytes, u64::MAX);
    }

    #[test]
    fn regression_oplog_reads_first_keeps_first_range_and_total_bytes() {
        let mut ranges = Ranges::default();
        ranges.add(50, 0, 0, true);
        ranges.add(50, 5, 1, true);
        ranges.add(0, 7, 2, true);
        assert_eq!(ranges.spans, [[50, 5]]);
        assert_eq!(ranges.first_ts, Some(0));
        assert_eq!(ranges.bytes, 12);
        assert_eq!(ranges.count, 3);
    }

    #[test]
    fn regression_oplog_header_records_excludes_and_flush_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace");
        let options = options(path.clone());
        let caller = Caller {
            pid: std::process::id(),
            uid: 7,
            gid: 8,
        };
        let log = OpLog::open(
            &options,
            &dir.path().join("mnt"),
            None,
            &BTreeMap::from([("base_digest".into(), "sha256:test".into())]),
        )
        .unwrap();
        for (fh, path) in [(1, "/src/a"), (2, "/.git/config")] {
            log.opened(fh, path, libc::O_RDWR, caller, "lower:1".into());
            log.io(fh, 0, 5, false);
            log.io(fh, 5, 7, false);
            log.io(fh, 2, 3, true);
            log.released(fh);
        }
        log.record("rename", "/src/a", caller, Some("/src/b"));
        log.opendir(3);
        log.readdir(3, "/", 2);
        log.readdir(3, "/", 2);
        log.releasedir(3);
        log.mark(b"turn 1").unwrap();
        drop(log);
        let events = records(&path);
        assert_eq!(events[0]["journal"], 1);
        assert_eq!(events[0]["clock"], "monotonic_ns");
        assert_eq!(events[0]["base_digest"], "sha256:test");
        chrono::DateTime::parse_from_rfc3339(events[0]["t0"].as_str().unwrap()).unwrap();
        assert_eq!(
            events
                .iter()
                .skip(1)
                .map(|e| e["op"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["open", "read", "write", "rename", "readdir", "mark"]
        );
        assert_eq!(events[1]["flags"], "rw");
        assert_eq!(events[1]["uid"], 7);
        assert_eq!(events[1]["pid"], std::process::id());
        assert_eq!(events[2]["ranges"], json!([[0, 12]]));
        assert_eq!(events[2]["layer"], "lower:1");
        assert_eq!(events[4]["to"], "src/b");
        assert_eq!(events[5]["entries"], 2);
        assert!(events.iter().all(|e| !e.to_string().contains(".git")));
    }

    #[test]
    fn regression_oplog_empty_file_read_is_not_lost() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path().join("trace"));
        let log = OpLog::open(&options, &dir.path().join("mnt"), None, &BTreeMap::new()).unwrap();
        log.opened(
            1,
            "/empty",
            libc::O_RDONLY,
            Caller::default(),
            "base".into(),
        );
        log.io(1, 0, 0, false);
        log.released(1);
        drop(log);
        let events = records(&options.path);
        assert_eq!(events[2]["op"], "read");
        assert_eq!(events[2]["bytes"], 0);
        assert_eq!(events[2]["ranges"], json!([]));
    }

    #[test]
    fn regression_oplog_pending_handle_drained_and_first_mode_wired() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(dir.path().join("trace"));
        options.reads = Reads::First;
        let log = OpLog::open(&options, &dir.path().join("mnt"), None, &BTreeMap::new()).unwrap();
        log.opened(1, "/a", libc::O_RDONLY, Caller::default(), "base".into());
        log.io(1, 3, 2, false);
        log.io(1, 1, 2, false);
        assert_eq!(log.stats(None)["bytes_read"], 4);
        drop(log);
        let events = records(&options.path);
        assert_eq!(events[2]["ranges"], json!([[3, 2]]));
        assert_eq!(events[2]["bytes"], 4);
    }

    #[test]
    fn regression_oplog_policy_observer_deduplicates_and_preserves_errno() {
        use ratarmount_compositing::OverlayPolicy;
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path().join("trace"));
        let log = OpLog::open(&options, &dir.path().join("mnt"), None, &BTreeMap::new()).unwrap();
        let rules = ReadOnlyGlobs::new(["tests/**"]).unwrap();
        log.attach_rules(&rules);
        let caller = Caller {
            pid: 123,
            ..Default::default()
        };
        assert_eq!(
            log.observe(caller, "chmod", "/tests/a", || {
                rules
                    .check_mutation(OverlayMutation::Write, &["/tests/a"])
                    .map_err(|_| libc::EROFS)
            }),
            Err(libc::EROFS)
        );
        for errno in [libc::EDQUOT, libc::ENOSPC, libc::EACCES] {
            let _ = log.observe(caller, "write", "/a", || Err::<(), _>(errno));
        }
        // The same observer also works for policy calls outside FUSE callbacks.
        assert!(rules
            .check_mutation(OverlayMutation::Create, &["/tests/b"])
            .is_err());
        assert_eq!(log.stats(None)["erofs_denied"], 2);
        drop(log);
        let events = records(&options.path);
        assert_eq!(events.len(), 5);
        assert_eq!(events[1]["what"], "chmod");
        assert_eq!(events[1]["pid"], 123);
        assert_eq!(events[2]["errno"], libc::EDQUOT);
        assert_eq!(events[3]["errno"], libc::ENOSPC);
        assert_eq!(events[4]["what"], "create");
    }

    #[test]
    fn regression_oplog_marks_validate_and_non_utf8_paths_use_base64() {
        assert_eq!(OpLog::default().mark(b"turn"), Err(libc::ENOTSUP));
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path().join("trace"));
        let log = OpLog::open(&options, &dir.path().join("mnt"), None, &BTreeMap::new()).unwrap();
        assert_eq!(log.mark(&[255]), Err(libc::EINVAL));
        assert_eq!(log.mark(&vec![b'a'; 4097]), Err(libc::EINVAL));
        log.mark(&vec![b'a'; 4096]).unwrap();
        let mut value = json!({});
        path_field(&mut value, b"/a\xff");
        assert_eq!(value, json!({"path_b64": "Yf8="}));
    }

    #[test]
    fn regression_oplog_refuses_mount_overlay_and_symlink_alias_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().join("mnt");
        let overlay = dir.path().join("ov");
        std::fs::create_dir(&mount).unwrap();
        std::fs::create_dir(&overlay).unwrap();
        std::os::unix::fs::symlink(&mount, dir.path().join("alias")).unwrap();
        std::os::unix::fs::symlink(mount.join("new-log"), dir.path().join("dangling")).unwrap();
        for path in [
            dir.path().join("dangling"),
            mount.join("log"),
            overlay.join("a/log"),
            dir.path().join("alias/log"),
        ] {
            assert!(validate_path(&path, &mount, Some(&overlay)).is_err());
        }
        assert!(validate_path(&dir.path().join("log"), &mount, Some(&overlay)).is_ok());
    }

    #[test]
    fn regression_oplog_bounded_queue_flushes_every_record() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path().join("trace"));
        let log = OpLog::open(&options, &dir.path().join("mnt"), None, &BTreeMap::new()).unwrap();
        for _ in 0..4096 {
            log.record("mkdir", "/a", Caller::default(), None);
        }
        drop(log);
        assert_eq!(records(&options.path).len(), 4097);
    }
}
