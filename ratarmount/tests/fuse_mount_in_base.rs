//! A FUSE mount point equal to, inside, or aliasing its own folder base (or the `-w`
//! overlay directory) deadlocks the single-threaded daemon; ratarmount refuses these
//! layouts with exit code 2 before the overlay database, any fork and the mount.
//!
//! Refusal tests need no mount and run on Linux and macOS. Positive (mounting) tests are
//! Linux-only. Every test owns a `Guard` with a 20 s watchdog: on drop or failure it
//! aborts any FUSE connection the test created through
//! `/sys/fs/fuse/connections/<id>/abort`, kills exactly the processes carrying the test's
//! token or root path, lazily unmounts exactly its own mounts and keeps the directories
//! (printing `LEAKED:`) when it cannot confirm that everything is gone.
#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tempfile::TempDir;

const WATCHDOG: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// Binary, skip
// ---------------------------------------------------------------------------

fn ratarmount_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("RATARMOUNT_TEST_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(env!("CARGO_BIN_EXE_ratarmount"))
}

#[cfg(target_os = "linux")]
fn skip_reason() -> Option<&'static str> {
    if !Path::new("/dev/fuse").exists() {
        return Some("skip: /dev/fuse missing");
    }
    if !on_path("fusermount3") {
        return Some("skip: fusermount3 not on PATH");
    }
    None
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|p| p.join(bin).is_file()))
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Dir,
    /// Hash of the full contents (tiny fixture files) and the length.
    File(u64, u64),
    Link(PathBuf),
    Other,
}

type Snapshot = BTreeMap<PathBuf, Entry>;

fn hash_file(path: &Path) -> (u64, u64) {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut f = File::open(path).ok();
    let mut len = 0u64;
    if let Some(f) = f.as_mut() {
        let mut buf = vec![0u8; 64 * 1024];
        // The complete contents: a same-length rewrite anywhere must be detected.
        loop {
            match f.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf[..n].hash(&mut h),
            }
        }
    }
    if let Ok(md) = fs::symlink_metadata(path) {
        len = md.len();
    }
    (h.finish(), len)
}

/// Walks `root` with `symlink_metadata` (never follows symlinks).
/// FUSE mounts of this test are never touched: a `stat` or `readdir` there goes to the
/// daemon and hangs when it is wedged. A mount point is recorded as `Entry::Other`.
fn snapshot(root: &Path) -> Snapshot {
    fn walk(root: &Path, dir: &Path, mounts: &[PathBuf], out: &mut Snapshot) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for ent in rd.flatten() {
            let path = ent.path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            if mounts.contains(&path) {
                out.insert(rel, Entry::Other);
                continue;
            }
            let Ok(md) = fs::symlink_metadata(&path) else {
                continue;
            };
            let ft = md.file_type();
            if ft.is_symlink() {
                out.insert(rel, Entry::Link(fs::read_link(&path).unwrap_or_default()));
            } else if ft.is_dir() {
                out.insert(rel, Entry::Dir);
                walk(root, &path, mounts, out);
            } else if ft.is_file() {
                let (h, len) = hash_file(&path);
                out.insert(rel, Entry::File(h, len));
            } else {
                out.insert(rel, Entry::Other);
            }
        }
    }
    let mut out = Snapshot::new();
    let mounts = owned_mounts(root);
    walk(root, root, &mounts, &mut out);
    out
}

#[derive(Clone, Copy)]
enum Allowed {
    Exact(&'static str),
    /// Any entry in `dir` whose name starts with `prefix`.
    NamePrefix(&'static str, &'static str),
}

fn allowed_matches(rel: &Path, allowed: &[Allowed]) -> bool {
    allowed.iter().any(|a| match a {
        Allowed::Exact(p) => rel == Path::new(p),
        Allowed::NamePrefix(dir, prefix) => {
            rel.parent() == Some(Path::new(dir))
                && rel
                    .file_name()
                    .is_some_and(|n| n.as_bytes().starts_with(prefix.as_bytes()))
        }
    })
}

/// Differences between two snapshots: every pre-existing entry must be unchanged and
/// present, and every added entry must match the allow-list.
fn snapshot_diff(pre: &Snapshot, post: &Snapshot, allowed: &[Allowed]) -> Vec<String> {
    let mut problems = Vec::new();
    for (rel, entry) in pre {
        match post.get(rel) {
            None => problems.push(format!("removed: {}", rel.display())),
            Some(now) if now != entry && !allowed_matches(rel, allowed) => {
                problems.push(format!("changed: {} ({entry:?} -> {now:?})", rel.display()));
            }
            Some(_) => {}
        }
    }
    for rel in post.keys() {
        if !pre.contains_key(rel) && !allowed_matches(rel, allowed) {
            problems.push(format!("added: {}", rel.display()));
        }
    }
    problems
}

// ---------------------------------------------------------------------------
// Process / mount scanning
// ---------------------------------------------------------------------------

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\'
            && i + 3 < field.len()
            && field[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let v = u16::from(field[i + 1] - b'0') * 64
                + u16::from(field[i + 2] - b'0') * 8
                + u16::from(field[i + 3] - b'0');
            out.push(v as u8);
            i += 4;
        } else {
            out.push(field[i]);
            i += 1;
        }
    }
    out
}

/// `(mount point, fstype, minor of field 3)` for each mountinfo line.
fn mountinfo_entries(bytes: &[u8]) -> Vec<(PathBuf, String, u32)> {
    bytes
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            let f: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
            let mp = unescape(f.get(4)?);
            let dash = f.iter().position(|x| *x == b"-")?;
            let fstype = String::from_utf8_lossy(f.get(dash + 1)?).to_string();
            let minor = std::str::from_utf8(f.get(2)?)
                .ok()?
                .split(':')
                .nth(1)?
                .parse()
                .ok()?;
            Some((PathBuf::from(OsString::from_vec(mp)), fstype, minor))
        })
        .collect()
}

/// FUSE connections (minor numbers) whose mount point is `root` or below it.
fn owned_connections_from(bytes: &[u8], root: &Path) -> Vec<u32> {
    mountinfo_entries(bytes)
        .into_iter()
        .filter(|(mp, fstype, _)| mp.starts_with(root) && fstype.starts_with("fuse"))
        .map(|(_, _, minor)| minor)
        .collect()
}

/// Connection numbers are reused once a mount is gone: a captured number that a FUSE
/// mount outside `root` (another test, another user) now carries is not ours to abort.
fn connection_reused_elsewhere(bytes: &[u8], root: &Path, minor: u32) -> bool {
    mountinfo_entries(bytes)
        .into_iter()
        .any(|(mp, fstype, m)| m == minor && fstype.starts_with("fuse") && !mp.starts_with(root))
}

#[cfg(target_os = "linux")]
fn owned_connections(root: &Path) -> Vec<u32> {
    fs::read("/proc/self/mountinfo")
        .map(|b| owned_connections_from(&b, root))
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn owned_connections(_root: &Path) -> Vec<u32> {
    Vec::new()
}

/// Mount points under `root` (FUSE filesystems only).
fn owned_mounts(root: &Path) -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        fs::read("/proc/self/mountinfo")
            .map(|b| {
                mountinfo_entries(&b)
                    .into_iter()
                    .filter(|(mp, fstype, _)| mp.starts_with(root) && fstype.starts_with("fuse"))
                    .map(|(mp, _, _)| mp)
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let Ok(out) = Command::new("mount").output() else {
            return Vec::new();
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split(" on ").nth(1))
            .filter_map(|r| r.split(" (").next())
            .map(PathBuf::from)
            .filter(|p| p.starts_with(root))
            .collect()
    }
}

/// Alive unless a zombie leader with no live thread.
fn alive_from(leader_state: char, other_thread_states: &[char]) -> bool {
    leader_state != 'Z' || other_thread_states.iter().any(|s| *s != 'Z')
}

fn stat_state(stat: &str) -> Option<char> {
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|s| s.chars().next())
}

#[cfg(target_os = "linux")]
fn pid_alive(pid: i32) -> bool {
    let Some(state) = fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| stat_state(&s))
    else {
        return false;
    };
    let mut others = Vec::new();
    if state == 'Z' {
        if let Ok(rd) = fs::read_dir(format!("/proc/{pid}/task")) {
            for t in rd.flatten() {
                let Some(tid) = t.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
                    continue;
                };
                if tid != pid {
                    if let Some(s) = fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat"))
                        .ok()
                        .and_then(|s| stat_state(&s))
                    {
                        others.push(s);
                    }
                }
            }
        }
    }
    alive_from(state, &others)
}

#[cfg(not(target_os = "linux"))]
fn pid_alive(pid: i32) -> bool {
    Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            let s = s.trim();
            !s.is_empty() && !s.starts_with('Z')
        })
        .unwrap_or(false)
}

fn cmdline_of(pid: i32) -> Option<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        fs::read(format!("/proc/{pid}/cmdline")).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let o = Command::new("ps")
            .args(["-wwo", "command=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        o.status.success().then_some(o.stdout)
    }
}

/// Every process of this uid (except this one) whose command line carries the token or
/// the root path.
fn scan_marker_pids(token: &str, root: &Path) -> Vec<i32> {
    let own = std::process::id() as i32;
    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let me = unsafe { libc::getuid() };
        let Ok(rd) = fs::read_dir("/proc") else {
            return out;
        };
        for ent in rd.flatten() {
            let Some(pid) = ent.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
                continue;
            };
            if pid == own || ent.metadata().map(|m| m.uid()).ok() != Some(me) {
                continue;
            }
            let Ok(cmd) = fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            if contains(&cmd, token.as_bytes()) || contains(&cmd, root.as_os_str().as_bytes()) {
                out.push(pid);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Ok(o) = Command::new("ps")
            .args(["-axwwo", "pid=,command="])
            .output()
        {
            for line in o.stdout.split(|b| *b == b'\n') {
                let text = String::from_utf8_lossy(line);
                let text = text.trim_start();
                let Some((pid, cmd)) = text.split_once(' ') else {
                    continue;
                };
                let Ok(pid) = pid.parse::<i32>() else {
                    continue;
                };
                if pid != own
                    && (cmd.contains(token)
                        || contains(cmd.as_bytes(), root.as_os_str().as_bytes()))
                {
                    out.push(pid);
                }
            }
        }
    }
    out
}

/// Output of a bounded child: a nameless temp file, so a descendant that keeps the
/// descriptor open can never block collection (no pipe, no reader thread).
fn bounded_stdout() -> Option<(File, Stdio)> {
    let f = tempfile::tempfile().ok()?;
    let w = f.try_clone().ok()?;
    Some((f, Stdio::from(w)))
}

fn read_bytes(f: &File) -> Vec<u8> {
    const CAP: usize = 1 << 20;
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut buf = vec![0u8; 8192];
    while out.len() < CAP {
        match f.read_at(&mut buf, off) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                off += n as u64;
            }
        }
    }
    out
}

/// Poll `child` until it exits or `timeout` passes.
fn wait_deadline(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => return None,
        }
    }
}

/// SIGKILL, then reap with `try_wait` for at most `grace`; never a blocking `wait()`
/// (a child stuck in an uninterruptible FUSE call cannot be reaped).
fn kill_and_reap(child: &mut Child, grace: Duration) -> bool {
    kill_unreaped(child);
    wait_deadline(child, grace).is_some()
}

/// A helper command (`fusermount3`, `umount`) with a hard deadline.
fn run_bounded(cmd: &mut Command, timeout: Duration) -> Option<(ExitStatus, Vec<u8>)> {
    let (out, stdio) = bounded_stdout()?;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(stdio)
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    match wait_deadline(&mut child, timeout) {
        Some(st) => Some((st, read_bytes(&out))),
        None => {
            kill_and_reap(&mut child, Duration::from_secs(2));
            None
        }
    }
}

/// SIGKILL `child` only while it is still unreaped (a reaped pid may be reused).
fn kill_unreaped(child: &mut Child) -> bool {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return false;
    }
    child.kill().is_ok()
}

// ---------------------------------------------------------------------------
// Cleanup (ordered, bounded, ownership-checked)
// ---------------------------------------------------------------------------

trait CleanupOps {
    fn owned_connections(&mut self) -> Vec<u32>;
    /// Open `/sys/fs/fuse/connections/<minor>/abort` for writing and hold the handle.
    /// Returns the inode of the opened abort file (the identity of that connection);
    /// `None` when it cannot be opened.
    fn open_abort(&mut self, minor: u32) -> Option<u64>;
    /// Inode of `/sys/fs/fuse/connections/<minor>/abort` as the path resolves it now.
    fn connection_ino(&mut self, minor: u32) -> Option<u64>;
    /// From a fresh mountinfo read: a FUSE mount under the root carries `minor` and no
    /// mount outside the root does.
    fn owns_connection(&mut self, minor: u32) -> bool;
    /// A verified handle for `minor` is held.
    fn has_held(&mut self, minor: u32) -> bool;
    /// Write to the held handle (and drop it).
    fn write_abort(&mut self, minor: u32);
    /// Drop a held handle without writing.
    fn drop_abort(&mut self, minor: u32);
    fn kill_children(&mut self);
    fn marker_pids(&mut self) -> Vec<i32>;
    fn pid_alive(&mut self, pid: i32) -> bool;
    fn kill(&mut self, pid: i32);
    fn owned_mounts(&mut self) -> Vec<PathBuf>;
    fn lazy_unmount(&mut self, mount: &Path);
    fn reap_children(&mut self);
    fn children_reaped(&mut self) -> bool;
    fn connection_dir_exists(&mut self, minor: u32) -> bool;
    fn sleep(&mut self, d: Duration);
}

/// Capture `minor` as ours: the abort file is opened first (the handle pins that
/// connection), then a fresh mountinfo read must show a mount of this root carrying
/// it and the abort file's identity must be unchanged. A verified handle is kept
/// (it keeps referring to this connection even after the mount detaches or the number
/// is reused); otherwise it is dropped. Never reopens a number whose handle is held.
fn capture_connection(ops: &mut dyn CleanupOps, minor: u32) {
    if ops.has_held(minor) {
        return;
    }
    let Some(held) = ops.open_abort(minor) else {
        return;
    };
    if !(ops.owns_connection(minor) && ops.connection_ino(minor) == Some(held)) {
        ops.drop_abort(minor);
    }
}

/// Record every connection of this root and capture a verified handle for each.
fn capture_all(ops: &mut dyn CleanupOps, connections: &mut BTreeSet<u32>) {
    for c in ops.owned_connections() {
        connections.insert(c);
        capture_connection(ops, c);
    }
}

/// Abort `minor` through its verified handle, even when the mount has since left
/// mountinfo. Without a handle a fresh capture needs fresh ownership (the number may
/// have been reused since); otherwise nothing is written (kill + lazy unmount still run).
fn abort_owned(ops: &mut dyn CleanupOps, minor: u32) {
    capture_connection(ops, minor);
    if ops.has_held(minor) {
        ops.write_abort(minor);
    }
}

fn cleanup_with(
    ops: &mut dyn CleanupOps,
    connections: &mut BTreeSet<u32>,
    confirm_override: Option<bool>,
) -> Result<(), String> {
    // 0. Capture before any signal.
    capture_all(ops, connections);
    let mut pids: BTreeSet<i32> = ops.marker_pids().into_iter().collect();
    // 1. Abort every captured connection, independent of the mount still being listed.
    for c in connections.iter() {
        abort_owned(ops, *c);
    }
    // 2. Registered children.
    ops.kill_children();
    // 3. Marker processes, re-verified inside `kill`.
    for pid in &pids {
        ops.kill(*pid);
    }
    // 4. Lazy unmount of owned mounts still listed.
    for m in ops.owned_mounts() {
        ops.lazy_unmount(&m);
    }
    // 5. Reap.
    ops.reap_children();
    // 6. Rescan and repeat 3.
    for pid in ops.marker_pids() {
        ops.kill(pid);
        pids.insert(pid);
    }
    // 7. Confirm.
    if let Some(ok) = confirm_override {
        return if ok {
            Ok(())
        } else {
            Err("confirm_override: unconfirmed".into())
        };
    }
    let deadline = 50; // x 100 ms = 5 s
    let mut report = String::new();
    for _ in 0..deadline {
        report.clear();
        let mounts = ops.owned_mounts();
        if !mounts.is_empty() {
            report += &format!("mounts still listed: {mounts:?}; ");
        }
        if !ops.children_reaped() {
            report += "children not reaped; ";
        }
        let alive: Vec<i32> = pids.iter().copied().filter(|p| ops.pid_alive(*p)).collect();
        if !alive.is_empty() {
            report += &format!("processes alive: {alive:?}; ");
        }
        let conns: Vec<u32> = connections
            .iter()
            .copied()
            .filter(|c| ops.connection_dir_exists(*c))
            .collect();
        if !conns.is_empty() {
            report += &format!("connections remain: {conns:?}; ");
        }
        if report.is_empty() {
            return Ok(());
        }
        ops.sleep(Duration::from_millis(100));
    }
    Err(report)
}

struct RealOps<'a> {
    token: &'a str,
    root: &'a Path,
    children: &'a mut Vec<Child>,
    held: &'a mut BTreeMap<u32, fs::File>,
}

impl<'a> RealOps<'a> {
    fn new(
        token: &'a str,
        root: &'a Path,
        children: &'a mut Vec<Child>,
        held: &'a mut BTreeMap<u32, fs::File>,
    ) -> Self {
        Self {
            token,
            root,
            children,
            held,
        }
    }
}

impl CleanupOps for RealOps<'_> {
    fn owned_connections(&mut self) -> Vec<u32> {
        owned_connections(self.root)
    }
    fn open_abort(&mut self, minor: u32) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let p = format!("/sys/fs/fuse/connections/{minor}/abort");
            let f = OpenOptions::new().write(true).open(p).ok()?;
            // The abort file's parent directory is the connection; the file's own
            // inode is stable for the life of that connection and is not reused by
            // the next one (a new connection creates a new directory and files).
            let ino = f.metadata().ok()?.ino();
            self.held.insert(minor, f);
            Some(ino)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = minor;
            None
        }
    }
    fn connection_ino(&mut self, minor: u32) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(format!("/sys/fs/fuse/connections/{minor}/abort"))
                .ok()
                .map(|m| m.ino())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = minor;
            None
        }
    }
    fn owns_connection(&mut self, minor: u32) -> bool {
        fs::read("/proc/self/mountinfo").is_ok_and(|b| {
            owned_connections_from(&b, self.root).contains(&minor)
                && !connection_reused_elsewhere(&b, self.root, minor)
        })
    }
    fn has_held(&mut self, minor: u32) -> bool {
        self.held.contains_key(&minor)
    }
    fn write_abort(&mut self, minor: u32) {
        if let Some(mut f) = self.held.remove(&minor) {
            let _ = f.write_all(b"1");
        }
    }
    fn drop_abort(&mut self, minor: u32) {
        self.held.remove(&minor);
    }
    fn kill_children(&mut self) {
        for c in self.children.iter_mut() {
            kill_unreaped(c);
        }
    }
    fn marker_pids(&mut self) -> Vec<i32> {
        scan_marker_pids(self.token, self.root)
    }
    fn pid_alive(&mut self, pid: i32) -> bool {
        pid_alive(pid)
    }
    fn kill(&mut self, pid: i32) {
        // Re-verify ownership immediately before signalling; never a process group.
        let Some(cmd) = cmdline_of(pid) else { return };
        let owned = contains(&cmd, self.token.as_bytes())
            || contains(&cmd, self.root.as_os_str().as_bytes());
        if owned && pid_alive(pid) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    fn owned_mounts(&mut self) -> Vec<PathBuf> {
        owned_mounts(self.root)
    }
    fn lazy_unmount(&mut self, mount: &Path) {
        #[cfg(target_os = "linux")]
        let mut cmd = {
            let mut c = Command::new("fusermount3");
            c.arg("-uz").arg(mount);
            c
        };
        #[cfg(not(target_os = "linux"))]
        let mut cmd = {
            let mut c = Command::new("umount");
            c.arg("-f").arg(mount);
            c
        };
        let _ = run_bounded(&mut cmd, Duration::from_secs(3));
    }
    fn reap_children(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        for c in self.children.iter_mut() {
            while matches!(c.try_wait(), Ok(None)) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    fn children_reaped(&mut self) -> bool {
        self.children
            .iter_mut()
            .all(|c| matches!(c.try_wait(), Ok(Some(_))))
    }
    fn connection_dir_exists(&mut self, minor: u32) -> bool {
        // A number a mount outside the root now carries is not ours to wait for.
        let reused = fs::read("/proc/self/mountinfo")
            .is_ok_and(|b| connection_reused_elsewhere(&b, self.root, minor));
        !reused
            && Path::new("/sys/fs/fuse/connections")
                .join(minor.to_string())
                .exists()
    }
    fn sleep(&mut self, d: Duration) {
        thread::sleep(d);
    }
}

struct Guard {
    root: Option<TempDir>,
    aux: Option<TempDir>,
    root_path: PathBuf,
    aux_path: PathBuf,
    token: String,
    children: Vec<Child>,
    connections: BTreeSet<u32>,
    /// Verified abort handles, kept from the moment a connection was captured.
    held: BTreeMap<u32, fs::File>,
    finished: bool,
    confirm_override: Option<bool>,
}

impl Guard {
    fn cleanup(&mut self) -> Result<(), String> {
        let mut ops = RealOps::new(
            &self.token,
            &self.root_path,
            &mut self.children,
            &mut self.held,
        );
        cleanup_with(&mut ops, &mut self.connections, self.confirm_override)
    }

    /// Capture the connections of this root now (ownership-verified handles).
    fn capture_connections(&mut self) {
        let mut ops = RealOps::new(
            &self.token,
            &self.root_path,
            &mut self.children,
            &mut self.held,
        );
        capture_all(&mut ops, &mut self.connections);
    }

    /// Runs once. On failure both directories are kept (never dropped implicitly).
    fn finalize(&mut self) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        match self.cleanup() {
            Ok(()) => {
                self.root.take();
                self.aux.take();
                Ok(())
            }
            Err(report) => {
                if let Some(d) = self.root.take() {
                    let _ = d.keep();
                }
                if let Some(d) = self.aux.take() {
                    let _ = d.keep();
                }
                eprintln!(
                    "LEAKED: {} {} {report}",
                    self.root_path.display(),
                    self.aux_path.display()
                );
                Err(report)
            }
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Never panics, also while unwinding.
        let _ = self.finalize();
    }
}

// ---------------------------------------------------------------------------
// Env / Run
// ---------------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Env {
    guard: Guard,
    root: PathBuf,
    aux: PathBuf,
    token: String,
}

struct Run {
    status: Option<ExitStatus>,
    stdout: File,
    stderr: File,
    prestate: Snapshot,
    child: usize,
}

fn read_all(f: &File) -> String {
    String::from_utf8_lossy(&read_bytes(f)).to_string()
}

impl Run {
    fn stderr_text(&self) -> String {
        read_all(&self.stderr)
    }
    fn stdout_text(&self) -> String {
        read_all(&self.stdout)
    }
    fn code(&self) -> Option<i32> {
        self.status.and_then(|s| s.code())
    }
}

impl Env {
    fn new() -> Env {
        let root_td = tempfile::Builder::new()
            .prefix("rmib-root.")
            .tempdir()
            .unwrap();
        let aux_td = tempfile::Builder::new()
            .prefix("rmib-aux.")
            .tempdir()
            .unwrap();
        let root = root_td.path().canonicalize().unwrap();
        let aux = aux_td.path().canonicalize().unwrap();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let token = format!(
            "rmib-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        for d in ["home", "cache", "tmp", "logs", "stub", "sock"] {
            fs::create_dir(aux.join(d)).unwrap();
        }
        fs::set_permissions(aux.join("sock"), fs::Permissions::from_mode(0o700)).unwrap();
        // Fixture: B/{f1.txt, sub/f2.txt, a/b/}, C/c1.txt, L -> B, tmp/.
        fs::create_dir_all(root.join("B/sub")).unwrap();
        fs::create_dir_all(root.join("B/a/b")).unwrap();
        fs::write(root.join("B/f1.txt"), b"one\n").unwrap();
        fs::write(root.join("B/sub/f2.txt"), b"two\n").unwrap();
        fs::create_dir(root.join("C")).unwrap();
        fs::write(root.join("C/c1.txt"), b"see\n").unwrap();
        std::os::unix::fs::symlink("B", root.join("L")).unwrap();
        fs::create_dir(root.join("tmp")).unwrap();
        Env {
            guard: Guard {
                root: Some(root_td),
                aux: Some(aux_td),
                root_path: root.clone(),
                aux_path: aux.clone(),
                token: token.clone(),
                children: Vec::new(),
                connections: BTreeSet::new(),
                held: BTreeMap::new(),
                finished: false,
                confirm_override: None,
            },
            root,
            aux,
            token,
        }
    }

    fn command(&self, cwd: &Path) -> Command {
        let mut cmd = Command::new(ratarmount_bin());
        cmd.env("HOME", self.aux.join("home"))
            .env("XDG_CACHE_HOME", self.aux.join("cache"))
            .env("TMPDIR", self.aux.join("tmp"))
            .env("LC_ALL", "C")
            .env_remove("RUST_LOG")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::null())
            .current_dir(cwd);
        cmd
    }

    /// Insert `--log-file <aux>/logs/<token>-<name>.log` after argv[0] (or after the
    /// `find`/`serve` word), so a daemon carries the token in its argv after fork/setsid.
    fn marker_args(&self, name: &str, args: &[&str]) -> Vec<OsString> {
        let log = self
            .aux
            .join("logs")
            .join(format!("{}-{name}.log", self.token));
        let mut out: Vec<OsString> = Vec::new();
        let mut rest = args;
        if let Some(first) = args.first() {
            if *first == "find" || *first == "serve" {
                out.push((*first).into());
                rest = &args[1..];
            }
        }
        out.push("--log-file".into());
        out.push(log.into_os_string());
        out.extend(rest.iter().map(OsString::from));
        out
    }

    fn spawn_with(
        &mut self,
        name: &str,
        args: &[&str],
        cwd: Option<&Path>,
        envs: &[(&str, &Path)],
        marker: bool,
    ) -> Run {
        let cwd = cwd.map_or_else(|| self.root.clone(), Path::to_path_buf);
        let mut cmd = self.command(&cwd);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let open = |stream: &str| {
            let path = self.aux.join("logs").join(format!("{name}.{stream}"));
            let w = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            (w, File::open(&path).unwrap())
        };
        let (so_w, so_r) = open("stdout");
        let (se_w, se_r) = open("stderr");
        cmd.stdout(Stdio::from(so_w)).stderr(Stdio::from(se_w));
        if marker {
            cmd.args(self.marker_args(name, args));
        } else {
            cmd.args(args);
        }
        // Immediately before spawn, when no mount of this test exists.
        let prestate = snapshot(&self.root);
        let child = cmd.spawn().expect("spawn ratarmount");
        self.guard.children.push(child);
        Run {
            status: None,
            stdout: so_r,
            stderr: se_r,
            prestate,
            child: self.guard.children.len() - 1,
        }
    }

    /// Wait for the run to exit; on timeout capture connections, abort them and kill.
    fn wait(&mut self, run: &mut Run, watchdog: Duration) {
        let deadline = Instant::now() + watchdog;
        loop {
            let child = &mut self.guard.children[run.child];
            if let Ok(Some(st)) = child.try_wait() {
                run.status = Some(st);
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        // Before any signal: remember the connections (a wedged daemon needs the abort).
        self.guard.capture_connections();
        if run.status.is_none() {
            let g = &mut self.guard;
            let conns = g.connections.clone();
            let mut ops = RealOps::new(&self.token, &self.root, &mut g.children, &mut g.held);
            for c in conns {
                abort_owned(&mut ops, c);
            }
            ops.kill_children();
            eprintln!(
                "watchdog fired; stderr tail:\n{}",
                tail(&run.stderr_text(), 2000)
            );
        }
    }

    /// A probe command (`ls`, `cat`, `sh`) on a mount of this test, supervised by the
    /// guard: registered as a child, bounded, and on timeout the captured FUSE
    /// connections are aborted before the kill and a bounded reap.
    fn probe(&mut self, cmd: &mut Command, timeout: Duration) -> Option<(ExitStatus, Vec<u8>)> {
        let (out, stdio) = bounded_stdout()?;
        let child = cmd
            .stdin(Stdio::null())
            .stdout(stdio)
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        self.guard.children.push(child);
        let idx = self.guard.children.len() - 1;
        if let Some(st) = wait_deadline(&mut self.guard.children[idx], timeout) {
            return Some((st, read_bytes(&out)));
        }
        self.guard.capture_connections();
        for c in self.guard.connections.clone() {
            let g = &mut self.guard;
            let mut ops = RealOps::new(&self.token, &self.root, &mut g.children, &mut g.held);
            abort_owned(&mut ops, c);
        }
        kill_and_reap(&mut self.guard.children[idx], Duration::from_secs(2));
        eprintln!("probe timed out after {timeout:?}");
        None
    }

    fn run(&mut self, name: &str, args: &[&str]) -> Run {
        let mut r = self.spawn_with(name, args, None, &[], true);
        self.wait(&mut r, WATCHDOG);
        r
    }

    fn run_in(&mut self, name: &str, args: &[&str], cwd: &Path) -> Run {
        let mut r = self.spawn_with(name, args, Some(cwd), &[], true);
        self.wait(&mut r, WATCHDOG);
        r
    }

    fn run_with_env(&mut self, name: &str, args: &[&str], envs: &[(&str, &Path)]) -> Run {
        let mut r = self.spawn_with(name, args, None, envs, true);
        self.wait(&mut r, WATCHDOG);
        r
    }

    /// No `--log-file` marker; `args[0]` is the program (arbitrary commands such as `true`).
    fn run_raw(&mut self, name: &str, args: &[&str], watchdog: Duration) -> Run {
        self.raw(name, args, watchdog)
    }

    fn raw(&mut self, name: &str, args: &[&str], watchdog: Duration) -> Run {
        let open = |stream: &str| {
            let path = self.aux.join("logs").join(format!("{name}.{stream}"));
            let w = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            (w, File::open(&path).unwrap())
        };
        let (so_w, so_r) = open("stdout");
        let (se_w, se_r) = open("stderr");
        let mut cmd = Command::new(args[0]);
        cmd.args(&args[1..])
            .stdin(Stdio::null())
            .current_dir(&self.root)
            .stdout(Stdio::from(so_w))
            .stderr(Stdio::from(se_w));
        let prestate = snapshot(&self.root);
        let child = cmd.spawn().expect("spawn raw");
        self.guard.children.push(child);
        let mut run = Run {
            status: None,
            stdout: so_r,
            stderr: se_r,
            prestate,
            child: self.guard.children.len() - 1,
        };
        self.wait(&mut run, watchdog);
        run
    }

    /// Spawn without waiting (long-lived daemon).
    fn spawn(&mut self, name: &str, args: &[&str]) -> Run {
        self.spawn_with(name, args, None, &[], true)
    }

    fn finish(mut self) -> Result<(), String> {
        self.guard.finalize()
    }

    fn assert_refused(&self, run: &Run, words: &[&str], allowed: &[Allowed]) {
        let err = run.stderr_text();
        assert_eq!(
            run.code(),
            Some(2),
            "expected exit 2\nstderr:\n{err}\nstdout:\n{}",
            run.stdout_text()
        );
        assert!(err.contains("error:"), "no `error:` in stderr:\n{err}");
        for w in words {
            assert!(err.contains(w), "stderr lacks {w:?}:\n{err}");
        }
        assert!(
            owned_mounts(&self.root).is_empty(),
            "a mount exists after a refusal:\n{err}"
        );
        let problems = snapshot_diff(&run.prestate, &snapshot(&self.root), allowed);
        assert!(
            problems.is_empty(),
            "refusal changed the tree: {problems:?}\n{err}"
        );
    }
}

fn tail(s: &str, n: usize) -> &str {
    let mut start = s.len().saturating_sub(n);
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

/// One ustar member `hello.txt` plus the end-of-archive blocks, no external `tar`.
fn write_tiny_tar(path: &Path) {
    let mut header = [0u8; 512];
    header[..9].copy_from_slice(b"hello.txt");
    header[100..107].copy_from_slice(b"0000644");
    header[108..115].copy_from_slice(b"0000000");
    header[116..123].copy_from_slice(b"0000000");
    header[124..135].copy_from_slice(b"00000000006");
    header[136..147].copy_from_slice(b"00000000000");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    header[155] = b' ';
    let mut f = File::create(path).unwrap();
    f.write_all(&header).unwrap();
    let mut data = [0u8; 512];
    data[..6].copy_from_slice(b"hello\n");
    f.write_all(&data).unwrap();
    f.write_all(&[0u8; 1024]).unwrap();
}

/// A refusal scenario: fresh env, `setup`, one run, the standard assertions.
fn refusal(
    name: &str,
    setup: impl FnOnce(&Env),
    args: &[&str],
    words: &[&str],
    allowed: &[Allowed],
) -> Env {
    let mut env = Env::new();
    setup(&env);
    let run = env.run(name, args);
    env.assert_refused(&run, words, allowed);
    env
}

fn done(env: Env) {
    env.finish().expect("cleanup confirmed");
}

const INSIDE: &str = "inside the folder being mounted";

// ---------------------------------------------------------------------------
// Harness self-tests
// ---------------------------------------------------------------------------

struct FakeOps {
    log: Vec<String>,
    alive: Vec<i32>,
    mounts: Vec<PathBuf>,
    /// Inode the held abort handle reports.
    held_ino: Option<u64>,
    /// Inode the connection path resolves to after the handle was opened.
    path_ino: Option<u64>,
    /// Fresh mountinfo still shows a mount of this root carrying the connection.
    owned: bool,
    /// The mount is listed under the root (what `owned_connections` reports).
    listed: bool,
    /// Handles held, with the inode of the connection each was opened on.
    held: BTreeMap<u32, u64>,
    /// Inodes of the connections actually written.
    written: Vec<u64>,
}

impl FakeOps {
    fn new(alive: Vec<i32>, mounts: Vec<PathBuf>) -> Self {
        FakeOps {
            log: Vec::new(),
            alive,
            mounts,
            held_ino: Some(7),
            path_ino: Some(7),
            owned: true,
            listed: true,
            held: BTreeMap::new(),
            written: Vec::new(),
        }
    }
}

impl CleanupOps for FakeOps {
    fn owned_connections(&mut self) -> Vec<u32> {
        self.log.push("owned_connections".into());
        if self.listed {
            vec![85]
        } else {
            Vec::new()
        }
    }
    fn open_abort(&mut self, minor: u32) -> Option<u64> {
        self.log.push(format!("open_abort {minor}"));
        if let Some(i) = self.held_ino {
            self.held.insert(minor, i);
        }
        self.held_ino
    }
    fn connection_ino(&mut self, minor: u32) -> Option<u64> {
        self.log.push(format!("connection_ino {minor}"));
        self.path_ino
    }
    fn owns_connection(&mut self, minor: u32) -> bool {
        self.log.push(format!("owns {minor}"));
        self.owned
    }
    fn has_held(&mut self, minor: u32) -> bool {
        self.held.contains_key(&minor)
    }
    fn write_abort(&mut self, minor: u32) {
        self.log.push(format!("abort {minor}"));
        if let Some(i) = self.held.remove(&minor) {
            self.written.push(i);
        }
    }
    fn drop_abort(&mut self, minor: u32) {
        self.log.push(format!("drop_abort {minor}"));
        self.held.remove(&minor);
    }
    fn kill_children(&mut self) {
        self.log.push("kill_children".into());
    }
    fn marker_pids(&mut self) -> Vec<i32> {
        self.log.push("marker_pids".into());
        self.alive.clone()
    }
    fn pid_alive(&mut self, _pid: i32) -> bool {
        false
    }
    fn kill(&mut self, pid: i32) {
        self.log.push(format!("kill {pid}"));
    }
    fn owned_mounts(&mut self) -> Vec<PathBuf> {
        self.log.push("owned_mounts".into());
        std::mem::take(&mut self.mounts)
    }
    fn lazy_unmount(&mut self, m: &Path) {
        self.log.push(format!("lazy {}", m.display()));
    }
    fn reap_children(&mut self) {
        self.log.push("reap".into());
    }
    fn children_reaped(&mut self) -> bool {
        true
    }
    fn connection_dir_exists(&mut self, _minor: u32) -> bool {
        false
    }
    fn sleep(&mut self, _d: Duration) {}
}

#[test]
fn regression_mount_in_base_guard_cleanup_order_capture_abort_kill() {
    let mut ops = FakeOps::new(vec![4242], vec![PathBuf::from("/m")]);
    let mut conns = BTreeSet::new();
    cleanup_with(&mut ops, &mut conns, None).unwrap();
    let pos = |needle: &str| ops.log.iter().position(|l| l == needle).unwrap();
    assert!(pos("owned_connections") < pos("open_abort 85"));
    assert!(pos("open_abort 85") < pos("owns 85"));
    assert!(pos("owns 85") < pos("abort 85"));
    assert!(pos("abort 85") < pos("kill_children"));
    assert!(pos("kill_children") < pos("kill 4242"));
    assert!(pos("kill 4242") < pos("lazy /m"));
    assert!(pos("lazy /m") < pos("reap"));
    assert!(conns.contains(&85));
}

/// Regression: a captured connection number reused by a parallel test's mount was
/// aborted by the first test's cleanup ("Transport endpoint is not connected").
#[test]
fn regression_mount_in_base_guard_stale_connection_reused_elsewhere_is_not_aborted() {
    let root = Path::new("/tmp/rmib-x");
    let mi = b"10 1 0:89 / /tmp/rmib-y/ov/mnt rw - fuse.ratarmount ratarmount rw\n\
               11 1 0:90 / /tmp/rmib-x/mnt rw - fuse.ratarmount ratarmount rw\n";
    assert!(connection_reused_elsewhere(mi, root, 89));
    assert!(!connection_reused_elsewhere(mi, root, 90));
    assert!(!connection_reused_elsewhere(mi, root, 91));
}

/// Regression: cleanup validated ownership of a captured connection number from
/// mountinfo, then reopened `/sys/fs/fuse/connections/<n>/abort` by number; a mount
/// of another test that reused `<n>` between the two was aborted. Ownership must be
/// re-established after the abort file is open, against the same connection.
#[test]
fn regression_mount_in_base_guard_abort_not_written_when_number_reused_after_open() {
    // Reuse after the handle was opened: mountinfo no longer shows our mount.
    let mut ops = FakeOps::new(vec![], vec![]);
    ops.owned = false;
    cleanup_with(&mut ops, &mut BTreeSet::new(), None).unwrap();
    assert!(
        ops.log.contains(&"drop_abort 85".to_string()),
        "{:?}",
        ops.log
    );
    assert!(!ops.log.contains(&"abort 85".to_string()), "{:?}", ops.log);
    // The connection directory now resolves to a different inode (replaced).
    let mut ops = FakeOps::new(vec![], vec![]);
    ops.path_ino = Some(8);
    cleanup_with(&mut ops, &mut BTreeSet::new(), None).unwrap();
    assert!(!ops.log.contains(&"abort 85".to_string()), "{:?}", ops.log);
    // The connection vanished (path gone) or could not be opened.
    let mut ops = FakeOps::new(vec![], vec![]);
    ops.path_ino = None;
    cleanup_with(&mut ops, &mut BTreeSet::new(), None).unwrap();
    assert!(!ops.log.contains(&"abort 85".to_string()), "{:?}", ops.log);
    let mut ops = FakeOps::new(vec![], vec![]);
    ops.held_ino = None;
    cleanup_with(&mut ops, &mut BTreeSet::new(), None).unwrap();
    assert!(
        !ops.log.iter().any(|l| l.starts_with("owns")),
        "{:?}",
        ops.log
    );
    // Verified: written, and the kill + lazy unmount steps run regardless.
    let mut ops = FakeOps::new(vec![], vec![PathBuf::from("/m")]);
    ops.owned = false;
    cleanup_with(&mut ops, &mut BTreeSet::new(), None).unwrap();
    assert!(ops.log.contains(&"kill_children".to_string()));
    assert!(ops.log.contains(&"lazy /m".to_string()));
}

/// Regression: an owned connection whose mount had left mountinfo (self-bind wedge:
/// mount absent, connection present, daemon thread stuck) was never aborted, because
/// cleanup required current mountinfo ownership and kept only the connection number.
/// The verified handle taken at capture time is written after the detach.
#[test]
fn regression_mount_in_base_guard_detached_owned_connection_aborted_via_held_handle() {
    let mut ops = FakeOps::new(vec![], vec![]);
    let mut conns = BTreeSet::new();
    capture_all(&mut ops, &mut conns);
    assert!(conns.contains(&85) && ops.held.contains_key(&85));
    // The mount detaches; the connection stays (the fake's `connection_ino` keeps
    // resolving, mountinfo no longer lists or owns it).
    ops.listed = false;
    ops.owned = false;
    cleanup_with(&mut ops, &mut conns, None).unwrap();
    assert_eq!(ops.written, vec![7], "{:?}", ops.log);
    assert_eq!(
        ops.log.iter().filter(|l| *l == "open_abort 85").count(),
        1,
        "never reopened by number: {:?}",
        ops.log
    );
    assert!(ops.log.contains(&"kill_children".to_string()));
}

/// The number is reused by a foreign mount after capture: the held handle still names
/// the original connection (nothing reopened by number), and without a prior capture a
/// reused number is not aborted at all.
#[test]
fn regression_mount_in_base_guard_reused_after_capture_never_touches_foreign() {
    let mut ops = FakeOps::new(vec![], vec![]);
    let mut conns = BTreeSet::new();
    capture_all(&mut ops, &mut conns);
    // Foreign mount takes number 85: not under our root, new abort file inode.
    ops.listed = false;
    ops.owned = false;
    ops.path_ino = Some(99);
    ops.held_ino = Some(99);
    cleanup_with(&mut ops, &mut conns, None).unwrap();
    assert_eq!(ops.written, vec![7], "only the original: {:?}", ops.log);
    assert_eq!(ops.log.iter().filter(|l| *l == "open_abort 85").count(), 1);
    // A second cleanup has no handle left and no ownership: the foreign one is safe.
    ops.log.clear();
    cleanup_with(&mut ops, &mut conns, None).unwrap();
    assert_eq!(ops.written, vec![7], "{:?}", ops.log);
}

#[test]
fn regression_mount_in_base_guard_pid_alive_zombie_leader_with_live_thread() {
    assert!(!alive_from('Z', &[]));
    assert!(!alive_from('Z', &['Z']));
    assert!(alive_from('Z', &['S']));
    assert!(alive_from('S', &[]));
    assert_eq!(stat_state("123 (a b) c) S 1 2"), Some('S'));
}

#[test]
fn regression_mount_in_base_guard_owned_connections_from_ignores_foreign() {
    let root = Path::new("/tmp/rmib-x");
    let mi = b"10 1 0:85 / /tmp/rmib-x/B.mounted rw - fuse.ratarmount ratarmount rw\n\
               11 1 0:86 / /tmp/other/mnt rw - fuse.ratarmount ratarmount rw\n\
               12 1 0:87 / /tmp/rmib-x/tmpfs rw - tmpfs tmpfs rw\n\
               13 1 0:88 / /tmp/rmib-xy/mnt rw - fuse x x rw\n";
    assert_eq!(owned_connections_from(mi, root), vec![85]);
}

#[test]
fn regression_mount_in_base_guard_log_read_through_retained_fd() {
    let mut env = Env::new();
    let run = env.run_raw(
        "echoer",
        &["sh", "-c", "echo hello-stderr >&2; echo out"],
        WATCHDOG,
    );
    assert_eq!(run.code(), Some(0));
    assert!(run.stderr_text().contains("hello-stderr"));
    assert!(run.stdout_text().contains("out"));
    done(env);
}

#[test]
fn regression_mount_in_base_guard_run_watchdog_returns_none_and_kills() {
    let mut env = Env::new();
    let run = env.run_raw("sleeper", &["sleep", "60"], Duration::from_millis(500));
    assert!(run.status.is_none());
    done(env);
}

#[test]
fn regression_mount_in_base_guard_removes_dirs_when_confirmed() {
    let env = Env::new();
    let (r, a) = (env.root.clone(), env.aux.clone());
    done(env);
    assert!(!r.exists() && !a.exists());
}

#[test]
fn regression_mount_in_base_guard_keeps_both_dirs_when_unconfirmed() {
    let mut env = Env::new();
    env.guard.confirm_override = Some(false);
    let (r, a) = (env.root.clone(), env.aux.clone());
    assert!(env.finish().is_err());
    assert!(r.exists() && a.exists());
    fs::remove_dir_all(r).unwrap();
    fs::remove_dir_all(a).unwrap();
}

#[test]
fn regression_mount_in_base_guard_unwind_failed_cleanup_keeps_dirs() {
    let (tx, rx) = std::sync::mpsc::channel();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = Env::new();
        env.guard.confirm_override = Some(false);
        tx.send((env.root.clone(), env.aux.clone())).unwrap();
        panic!("assert");
    }));
    assert!(res.is_err());
    let (r, a) = rx.recv().unwrap();
    assert!(
        r.exists() && a.exists(),
        "failed cleanup must keep both dirs"
    );
    fs::remove_dir_all(r).unwrap();
    fs::remove_dir_all(a).unwrap();
}

#[test]
fn regression_mount_in_base_guard_drop_during_panic_does_not_abort() {
    let res = std::panic::catch_unwind(|| {
        let _env = Env::new();
        panic!("assert");
    });
    assert!(res.is_err());
}

#[test]
fn regression_mount_in_base_cleanup_never_signals_reaped_child() {
    let mut env = Env::new();
    let run = env.run_raw("quick", &["true"], WATCHDOG);
    assert_eq!(run.code(), Some(0));
    assert!(!kill_unreaped(&mut env.guard.children[run.child]));
    done(env);
}

#[test]
fn regression_mount_in_base_guard_finds_and_kills_detached_grandchild() {
    if !on_path("setsid") {
        eprintln!("skip: no setsid binary");
        return;
    }
    let mut env = Env::new();
    let token = env.token.clone();
    // Double fork: the parent exits, the grandchild is a session leader whose command
    // line carries the token but not the root path.
    let script = format!("setsid sh -c 'while :; do sleep 1; done' {token} >/dev/null 2>&1 &");
    let run = env.run_raw("detach", &["sh", "-c", &script], WATCHDOG);
    assert_eq!(run.code(), Some(0));
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Some(p) = scan_marker_pids(&token, &env.root).first() {
            break *p;
        }
        assert!(Instant::now() < deadline, "grandchild not found");
        thread::sleep(Duration::from_millis(50));
    };
    let cmd = cmdline_of(pid).unwrap();
    assert!(!contains(&cmd, env.root.as_os_str().as_bytes()));
    env.finish().expect("cleanup confirmed");
    assert!(!pid_alive(pid));
}

#[test]
fn regression_mount_in_base_snapshot_detects_added_removed_changed() {
    let env = Env::new();
    let pre = snapshot(&env.root);
    fs::write(env.root.join("new.txt"), b"x").unwrap();
    fs::remove_file(env.root.join("C/c1.txt")).unwrap();
    let mut f = OpenOptions::new()
        .append(true)
        .open(env.root.join("B/f1.txt"))
        .unwrap();
    f.write_all(b"more").unwrap();
    fs::remove_file(env.root.join("L")).unwrap();
    std::os::unix::fs::symlink("C", env.root.join("L")).unwrap();
    let problems = snapshot_diff(&pre, &snapshot(&env.root), &[]);
    let text = problems.join("\n");
    for needle in [
        "added: new.txt",
        "removed: C/c1.txt",
        "changed: B/f1.txt",
        "changed: L",
    ] {
        assert!(text.contains(needle), "{needle} missing in:\n{text}");
    }
    // NamePrefix accepts sidecar siblings.
    fs::write(env.root.join("B/x.tar.index.sqlite-wal"), b"w").unwrap();
    let post = snapshot(&env.root);
    let only: Vec<_> = snapshot_diff(&pre, &post, &[])
        .into_iter()
        .filter(|p| p.contains("sqlite"))
        .collect();
    assert_eq!(only.len(), 1);
    assert!(snapshot_diff(
        &pre,
        &post,
        &[Allowed::NamePrefix("B", "x.tar.index.sqlite")]
    )
    .iter()
    .all(|p| !p.contains("sqlite")));
    done(env);
}

#[test]
fn regression_mount_in_base_snapshot_detects_same_length_rewrite() {
    let env = Env::new();
    let pre = snapshot(&env.root);
    fs::write(env.root.join("B/f1.txt"), b"ONE\n").unwrap();
    let problems = snapshot_diff(&pre, &snapshot(&env.root), &[]);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].starts_with("changed: B/f1.txt"));
    done(env);
}

/// Regression: the snapshot hashed only the first MiB, so a same-length rewrite later
/// in a larger file (an index sidecar) went unnoticed.
#[test]
fn regression_mount_in_base_snapshot_detects_rewrite_beyond_first_mib() {
    let env = Env::new();
    let big = env.root.join("B/big.bin");
    fs::write(&big, vec![7u8; (1 << 20) + 4096]).unwrap();
    let pre = snapshot(&env.root);
    let f = OpenOptions::new().write(true).open(&big).unwrap();
    f.write_all_at(&[8u8], 1 << 20).unwrap();
    let problems = snapshot_diff(&pre, &snapshot(&env.root), &[]);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].starts_with("changed: B/big.bin"));
    done(env);
}

/// Regression: probe children were unsupervised and a descendant holding the output
/// pipe delayed collection; a probe is bounded by files and a try_wait reap.
#[test]
fn regression_mount_in_base_probe_is_bounded_and_ignores_descendant_output_holders() {
    let mut env = Env::new();
    let t0 = Instant::now();
    let (st, out) = env
        .probe(
            Command::new("sh").args(["-c", "sleep 5 & echo hi"]),
            Duration::from_secs(3),
        )
        .expect("finished");
    assert!(st.success());
    assert_eq!(String::from_utf8_lossy(&out).trim(), "hi");
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    let t0 = Instant::now();
    assert!(env
        .probe(Command::new("sleep").arg("30"), Duration::from_millis(300))
        .is_none());
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    // The detached `sleep 5` carries no token or root path: not ours to kill, and it
    // exits by itself.
    done(env);
}

#[test]
fn regression_mount_in_base_snapshot_taken_at_run_includes_test_fixture_additions() {
    let mut env = Env::new();
    fs::write(env.root.join("added-by-test"), b"x").unwrap();
    let run = env.run_raw("noop", &["true"], WATCHDOG);
    let problems = snapshot_diff(&run.prestate, &snapshot(&env.root), &[]);
    assert!(problems.is_empty(), "{problems:?}");
    done(env);
}

// ---------------------------------------------------------------------------
// Refusal tests (exit 2, no FUSE, never skipped)
// ---------------------------------------------------------------------------

#[test]
fn regression_mount_in_base_refuses_b_b_mnt() {
    done(refusal("t1", |_| {}, &["-f", "B", "B/mnt"], &[INSIDE], &[]));
}

#[test]
fn regression_mount_in_base_refuses_deep() {
    done(refusal(
        "t2",
        |_| {},
        &["-f", "B", "B/a/b/mnt"],
        &[INSIDE],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_via_symlink() {
    done(refusal(
        "t3",
        |_| {},
        &["-f", "B", "L/mnt"],
        &[INSIDE, "resolves to"],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_union() {
    done(refusal(
        "t4",
        |_| {},
        &["-f", "C", "B", "B/mnt"],
        &[INSIDE],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_write_overlay_outside() {
    let env = refusal(
        "t5",
        |_| {},
        &["-f", "-w", "ov", "B", "B/mnt"],
        &[INSIDE],
        &[],
    );
    assert!(
        !env.root.join("ov").exists(),
        "the early check creates nothing"
    );
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_mount_inside_overlay_existing() {
    done(refusal(
        "t6a",
        |e| fs::create_dir(e.root.join("ov")).unwrap(),
        &["-f", "-w", "ov", "C", "ov/mnt"],
        &["inside the write-overlay directory (-w)"],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_mount_inside_overlay_absent() {
    let env = refusal(
        "t6b",
        |_| {},
        &["-f", "-w", "ov", "C", "ov/mnt"],
        &["inside the write-overlay directory (-w)"],
        &[],
    );
    assert!(!env.root.join("ov").exists());
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_mount_is_overlay() {
    done(refusal(
        "t7",
        |_| {},
        &["-f", "-w", "ov", "C", "ov"],
        &["is the write-overlay directory (-w)"],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_self_bind() {
    done(refusal(
        "t8",
        |_| {},
        &["-f", "B", "B"],
        &["is the folder being mounted", "B.mounted"],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_daemonized() {
    // No `-f`: the refusal comes before the fork.
    let env = refusal("t9", |_| {}, &["B", "B/mnt"], &[INSIDE], &[]);
    assert!(
        scan_marker_pids(&env.token, &env.root)
            .into_iter()
            .all(|p| !pid_alive(p)),
        "a daemon outlived the refusal"
    );
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_contains_parent() {
    done(refusal(
        "t10",
        |_| {},
        &["-f", "B", "."],
        &["would cover the folder being mounted"],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_overlay_contains() {
    done(refusal(
        "t11",
        |_| {},
        &["-f", "-w", "mnt/ov", "C", "mnt"],
        &["would cover the write-overlay directory (-w)"],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_bind_source() {
    done(refusal(
        "t12",
        |_| {},
        &["-f", "--bind", "/x=B", "B/mnt"],
        &[INSIDE],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_bind_mixed_only_bound_conflicts() {
    done(refusal(
        "t13",
        |_| {},
        &["-f", "C", "--bind", "/x=B", "B/mnt"],
        &[INSIDE],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_dotdot_escape_via_missing() {
    done(refusal(
        "t14",
        |_| {},
        &["-f", "B", "new/../B/mnt"],
        &[INSIDE],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_dangling_symlink_into_base() {
    done(refusal(
        "t15",
        |e| std::os::unix::fs::symlink("B/new", e.root.join("L4")).unwrap(),
        &["-f", "B", "L4/mnt"],
        &[INSIDE],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_default_dot_input() {
    let mut env = Env::new();
    let cwd = env.root.join("B");
    let run = env.run_in("t16", &["-f", "."], &cwd);
    env.assert_refused(&run, &[INSIDE, "pass an explicit mount point"], &[]);
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_default_exists_as_file() {
    done(refusal(
        "t17",
        |e| fs::write(e.root.join("B.mounted"), b"not a directory").unwrap(),
        &["-f", "B"],
        &["default mount point B.mounted exists and is not a directory"],
        &[],
    ));
}

fn make_git_dir(env: &Env) {
    fs::create_dir(env.root.join("B/.git")).unwrap();
    fs::write(env.root.join("B/.git/HEAD"), b"ref: refs/heads/main\n").unwrap();
}

#[test]
fn regression_mount_in_base_refuses_git_inline_ref() {
    done(refusal(
        "t18",
        make_git_dir,
        &["-f", "B@HEAD", "B/mnt"],
        &[INSIDE],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_overlay_symlink_mount_point_inside() {
    let env = refusal(
        "t19",
        |e| std::os::unix::fs::symlink("ov", e.root.join("L2")).unwrap(),
        &["-f", "-w", "ov", "C", "L2/mnt"],
        &["inside the write-overlay directory"],
        &[],
    );
    assert!(!env.root.join("ov").exists());
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_mount_point_is_file() {
    done(refusal(
        "t20",
        |e| fs::write(e.root.join("F"), b"x").unwrap(),
        &["-f", "B", "F"],
        &["not a directory"],
        &[],
    ));
}

#[test]
fn regression_mount_in_base_refuses_overlay_path_is_file() {
    done(refusal(
        "t21",
        |e| fs::write(e.root.join("F"), b"x").unwrap(),
        &["-f", "-w", "F", "C", "mnt"],
        &["write-overlay directory", "not a directory"],
        &[],
    ));
}

fn fs_is_case_insensitive(env: &Env) -> bool {
    let probe = env.root.join(".probe");
    fs::write(&probe, b"").unwrap();
    fs::symlink_metadata(env.root.join(".PROBE")).is_ok()
}

#[test]
fn regression_mount_in_base_refuses_case_alias_overlay_existing_when_fs_is_case_insensitive() {
    let mut env = Env::new();
    if !fs_is_case_insensitive(&env) {
        eprintln!("skip: case-sensitive filesystem");
        done(env);
        return;
    }
    fs::create_dir(env.root.join("ov")).unwrap();
    let run = env.run("t22", &["-f", "-w", "ov", "C", "OV/mnt"]);
    env.assert_refused(&run, &["inside the write-overlay directory"], &[]);
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_index_folder_created_base_before_overlay_db_and_socket() {
    let mut env = Env::new();
    write_tiny_tar(&env.root.join("x.tar"));
    let sock = env.aux.join("sock/inspect.sock");
    let sock_s = sock.to_str().unwrap().to_string();
    let run = env.run(
        "t23",
        &[
            "-f",
            "-w",
            "ov",
            "--sandbox-inspection-socket",
            &sock_s,
            "--index-folders",
            "N",
            "x.tar",
            "N",
            "N/mnt",
        ],
    );
    env.assert_refused(
        &run,
        &[INSIDE],
        &[
            Allowed::Exact("N"),
            Allowed::NamePrefix("N", "x.tar.index.sqlite"),
            Allowed::Exact("ov"),
        ],
    );
    let ov: Vec<_> = fs::read_dir(env.root.join("ov")).unwrap().collect();
    assert!(ov.is_empty(), "overlay database/marker created: {ov:?}");
    assert!(!sock.exists(), "inspection socket created");
    assert!(!env.root.join("N/mnt").exists());
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_index_folder_created_base_daemonized() {
    let mut env = Env::new();
    write_tiny_tar(&env.root.join("x.tar"));
    let run = env.run(
        "t24",
        &["-w", "ov", "--index-folders", "N", "x.tar", "N", "N/mnt"],
    );
    env.assert_refused(
        &run,
        &[INSIDE],
        &[
            Allowed::Exact("N"),
            Allowed::NamePrefix("N", "x.tar.index.sqlite"),
            Allowed::Exact("ov"),
        ],
    );
    assert!(scan_marker_pids(&env.token, &env.root)
        .into_iter()
        .all(|p| !pid_alive(p)));
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_temp_overlay_parent_as_mount_point() {
    let mut env = Env::new();
    let tmp = env.root.join("tmp");
    let run = env.run_with_env(
        "t25",
        &["-f", "-w", ":temp:", "C", "tmp"],
        &[("TMPDIR", &tmp)],
    );
    env.assert_refused(&run, &["would cover the temporary write overlay"], &[]);
    let left: Vec<_> = fs::read_dir(&tmp).unwrap().collect();
    assert!(left.is_empty(), "temporary overlay not removed: {left:?}");
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_case_alias_overlay_absent_when_fs_is_case_insensitive() {
    let mut env = Env::new();
    if !fs_is_case_insensitive(&env) {
        eprintln!("skip: case-sensitive filesystem");
        done(env);
        return;
    }
    let run = env.run("t26", &["-f", "-w", "ov", "C", "OV/mnt"]);
    env.assert_refused(
        &run,
        &["inside the write-overlay directory"],
        &[Allowed::Exact("ov")],
    );
    assert!(fs::read_dir(env.root.join("ov")).unwrap().next().is_none());
    done(env);
}

/// The factory's errors for an operand it cannot open (`open_path_impl`): a missing
/// path (`not found: <path>`) or a `repo@REV` whose repository is not one
/// (`<path> is not a git repository`). Mount errors are `error mounting at ...`.
fn is_factory_operand_rejection(stderr: &str, operand: &str) -> bool {
    stderr.lines().any(|l| {
        !l.contains("error mounting")
            && ((l.contains("not found:") && l.contains(operand))
                || l.trim_end().ends_with("is not a git repository"))
    })
}

#[test]
fn regression_mount_in_base_rev_fallback_rejects_mount_errors() {
    // Regression: exit 1 with a mount error naming B@HEAD passed the fallback.
    assert!(!is_factory_operand_rejection(
        "error mounting at B@HEAD/mnt: device not found",
        "B@HEAD"
    ));
    assert!(!is_factory_operand_rejection(
        "exit\nsomething else",
        "B@HEAD"
    ));
    assert!(is_factory_operand_rejection(
        "error: not found: B@HEAD",
        "B@HEAD"
    ));
    assert!(is_factory_operand_rejection(
        "error: B is not a git repository",
        "B@HEAD"
    ));
}

#[test]
fn regression_mount_in_base_refuses_rev_literal_created_by_index_folders() {
    let mut env = Env::new();
    make_git_dir(&env);
    write_tiny_tar(&env.root.join("x.tar"));
    let run = env.run(
        "t27",
        &[
            "-f",
            "--index-folders",
            "B@HEAD",
            "x.tar",
            "B@HEAD",
            "B@HEAD/mnt",
        ],
    );
    if run.code() == Some(2) {
        env.assert_refused(
            &run,
            &["B@HEAD"],
            &[
                Allowed::Exact("B@HEAD"),
                Allowed::NamePrefix("B@HEAD", "x.tar.index.sqlite"),
            ],
        );
        assert!(!env.root.join("B@HEAD/mnt").exists());
    } else {
        // The factory rejected this operand order before the decisive check. A mount
        // failure (exit 1, `error mounting at ...`) is not a rejection: it would hide a
        // missing refusal, so only the factory's own operand errors count.
        assert_eq!(
            run.code(),
            Some(1),
            "exit {:?} (status {:?}): {}",
            run.code(),
            run.status,
            run.stderr_text()
        );
        assert!(
            is_factory_operand_rejection(&run.stderr_text(), "B@HEAD"),
            "not a factory rejection of B@HEAD: {}",
            run.stderr_text()
        );
        assert!(!env.root.join("B@HEAD/mnt").exists());
        assert!(owned_mounts(&env.root).is_empty());
        assert!(
            scan_marker_pids(&env.token, &env.root).is_empty(),
            "a daemon survived the failed run"
        );
    }
    done(env);
}

#[test]
fn regression_mount_in_base_refuses_nested_index_folder_mount_point() {
    let mut env = Env::new();
    write_tiny_tar(&env.root.join("x.tar"));
    let run = env.run(
        "t28",
        &["-f", "--index-folders", "N/mnt", "x.tar", "N", "N/mnt"],
    );
    env.assert_refused(
        &run,
        &[INSIDE],
        &[
            Allowed::Exact("N"),
            Allowed::Exact("N/mnt"),
            Allowed::NamePrefix("N/mnt", "x.tar.index.sqlite"),
        ],
    );
    done(env);
}

// ---------------------------------------------------------------------------
// No-skip CLI tests: nothing here may compute a default mount point
// ---------------------------------------------------------------------------

fn block_default(env: &Env) {
    // `B.mounted` is a regular file: a wrongly computed default would be an error.
    fs::write(env.root.join("B.mounted"), b"file").unwrap();
}

#[test]
fn regression_mount_in_base_no_mount_exits_0_without_default() {
    let mut env = Env::new();
    block_default(&env);
    let run = env.run("nm", &["--no-mount", "B"]);
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(!run.stderr_text().contains("default mount point"));
    done(env);
}

#[test]
fn regression_mount_in_base_find_exits_0_without_default() {
    let mut env = Env::new();
    block_default(&env);
    write_tiny_tar(&env.root.join("x.tar"));
    let run = env.run("find", &["find", "hello*", "x.tar"]);
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(!run.stderr_text().contains("default mount point"));
    done(env);
}

#[test]
fn regression_mount_in_base_export_only_http_is_ready_without_default() {
    let mut env = Env::new();
    block_default(&env);
    let mut run = env.spawn("http", &["--http", "--http-bind", "127.0.0.1:0", "B"]);
    let deadline = Instant::now() + WATCHDOG;
    let mut ready = false;
    while Instant::now() < deadline {
        let text = run.stderr_text();
        assert!(!text.contains("default mount point"), "{text}");
        assert!(!text.contains("error:"), "{text}");
        if text.contains("HTTP on 127.0.0.1:") {
            ready = true;
            break;
        }
        if matches!(env.guard.children[run.child].try_wait(), Ok(Some(_))) {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let text = run.stderr_text();
    kill_unreaped(&mut env.guard.children[run.child]);
    run.status = None;
    assert!(ready, "export server not ready:\n{text}");
    done(env);
}

#[test]
fn regression_mount_in_base_no_mount_from_deleted_cwd_has_no_cwd_error() {
    let mut env = Env::new();
    let bin = ratarmount_bin();
    let b = env.root.join("B");
    let script = "mkdir g && cd g && rmdir ../g && exec \"$@\"";
    let run = env.raw(
        "deleted-cwd",
        &[
            "sh",
            "-c",
            script,
            "sh",
            bin.to_str().unwrap(),
            "--no-mount",
            b.to_str().unwrap(),
        ],
        WATCHDOG,
    );
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(!run.stderr_text().contains("current directory"));
    done(env);
}

// D4: publish-only keeps HEAD's order and never creates the overlay.

#[test]
fn regression_mount_in_base_publish_only_unusable_overlay_path_still_publishes() {
    let mut env = Env::new();
    write_tiny_tar(&env.root.join("x.tar"));
    fs::write(env.root.join("blocker"), b"file").unwrap();
    let run = env.run(
        "pub1",
        &[
            "-w",
            "blocker/ov",
            "--publish-index-to",
            "out.index.sqlite",
            "x.tar",
        ],
    );
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(env.root.join("out.index.sqlite").exists());
    assert_eq!(fs::read(env.root.join("blocker")).unwrap(), b"file");
    done(env);
}

#[test]
fn regression_mount_in_base_publish_only_does_not_create_overlay() {
    let mut env = Env::new();
    write_tiny_tar(&env.root.join("x.tar"));
    let run = env.run(
        "pub2",
        &[
            "-w",
            "ov",
            "--publish-index-to",
            "out.index.sqlite",
            "x.tar",
        ],
    );
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(!env.root.join("ov").exists());
    done(env);
}

#[test]
fn regression_mount_in_base_publish_only_overlay_tmpfs_unaffected() {
    let mut env = Env::new();
    write_tiny_tar(&env.root.join("x.tar"));
    let run = env.run(
        "pub3",
        &[
            "--overlay-tmpfs",
            "--publish-index-to",
            "out.index.sqlite",
            "x.tar",
        ],
    );
    let err = run.stderr_text();
    assert_eq!(run.code(), Some(0), "{err}");
    assert!(
        !err.contains("unsupported") && !err.contains("tmpfs is supported only"),
        "{err}"
    );
    done(env);
}

// ---------------------------------------------------------------------------
// Positive tests (Linux, real FUSE mounts)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn mount_visible(mnt: &Path) -> bool {
    owned_mounts(mnt.parent().unwrap_or(mnt))
        .iter()
        .any(|m| m.as_os_str().as_bytes() == mnt.as_os_str().as_bytes())
}

/// Mount with `-f`, wait for the exact mount path, list it (bounded, in a subprocess),
/// check the entry, unmount with `-u`, wait for the daemon to exit.
#[cfg(target_os = "linux")]
fn mount_and_check(name: &str, args: &[&str], expected_mp_rel: &str, expected_entry: Option<&str>) {
    mount_and_check_with(
        name,
        |_| {},
        args,
        expected_mp_rel,
        expected_entry,
        |_, _| {},
    );
}

#[cfg(target_os = "linux")]
fn mount_and_check_with(
    name: &str,
    setup: impl FnOnce(&Env),
    args: &[&str],
    expected_mp_rel: &str,
    expected_entry: Option<&str>,
    extra: impl FnOnce(&mut Env, &Path),
) {
    if let Some(r) = skip_reason() {
        eprintln!("{r}");
        return;
    }
    let mut env = Env::new();
    setup(&env);
    let mp = env.root.join(expected_mp_rel);
    let mut full = vec!["-f"];
    full.extend_from_slice(args);
    let mut run = env.spawn(name, &full);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !mount_visible(&mp) {
        if let Ok(Some(st)) = env.guard.children[run.child].try_wait() {
            panic!(
                "daemon exited before the mount appeared: {st}\n{}",
                run.stderr_text()
            );
        }
        assert!(
            Instant::now() < deadline,
            "mount {} did not appear\n{}",
            mp.display(),
            run.stderr_text()
        );
        thread::sleep(Duration::from_millis(50));
    }
    env.guard.capture_connections();
    // Bounded listing in a disposable subprocess, never in the test process.
    // The mount can be listed in mountinfo a moment before the daemon serves it.
    let out = loop {
        let (st, out) = env
            .probe(
                Command::new("ls").arg("-1A").arg(&mp),
                Duration::from_secs(10),
            )
            .expect("ls finished");
        if st.success() {
            break out;
        }
        assert!(
            Instant::now() < deadline,
            "ls of {} kept failing\n{}",
            mp.display(),
            run.stderr_text()
        );
        thread::sleep(Duration::from_millis(100));
    };
    if let Some(entry) = expected_entry {
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.lines().any(|l| l == entry),
            "{entry} missing in:\n{text}"
        );
    }
    extra(&mut env, &mp);
    let um = env.run("umount", &["-u", mp.to_str().unwrap()]);
    assert_eq!(um.code(), Some(0), "{}", um.stderr_text());
    env.wait(&mut run, Duration::from_secs(15));
    assert!(
        run.status.is_some(),
        "daemon did not exit\n{}",
        run.stderr_text()
    );
    done(env);
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_bare_folder_mounts_at_dot_mounted() {
    mount_and_check("p1", &["B"], "B.mounted", Some("f1.txt"));
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_symlink_default_mounts_at_l_mounted() {
    mount_and_check("p2", &["L"], "L.mounted", Some("f1.txt"));
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_sibling_mount_ok() {
    mount_and_check("p3", &["B", "mnt"], "mnt", Some("f1.txt"));
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_nonexistent_sibling_ok() {
    mount_and_check("p4", &["B", "new/deep/mnt"], "new/deep/mnt", Some("f1.txt"));
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_archive_in_dir_ok() {
    mount_and_check_with(
        "p5",
        |e| write_tiny_tar(&e.root.join("B/x.tar")),
        &["B/x.tar", "B/mnt"],
        "B/mnt",
        Some("hello.txt"),
        |_, _| {},
    );
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_bind_mixed_ok() {
    mount_and_check("p6", &["C", "--bind", "/x=B", "mnt"], "mnt", Some("c1.txt"));
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_dotdot_symlink_escape_not_refused() {
    mount_and_check_with(
        "p7",
        |e| std::os::unix::fs::symlink("C", e.root.join("L5")).unwrap(),
        &["B", "L5/../mnt"],
        "mnt",
        Some("f1.txt"),
        |_, _| {},
    );
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_rolling_default_writes_and_reads_back() {
    mount_and_check_with(
        "p8",
        |_| {},
        &["--roll-every", "1d", "-w", "ov", "logs.tar"],
        "logs.000001",
        None,
        |env, _| {
            let root = env.root.clone();
            let (st, out) = env
                .probe(
                    Command::new("sh")
                        .current_dir(&root)
                        .args(["-c", "echo hi > logs.000001/w.txt && cat logs.000001/w.txt"]),
                    Duration::from_secs(10),
                )
                .expect("sh finished");
            assert!(st.success());
            assert_eq!(String::from_utf8_lossy(&out).trim(), "hi");
        },
    );
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_overlay_symlink_dotdot_mount_point_ok() {
    mount_and_check_with(
        "p9",
        |e| std::os::unix::fs::symlink("ov", e.root.join("L2")).unwrap(),
        &["-w", "ov", "C", "L2/../mnt"],
        "mnt",
        Some("c1.txt"),
        |env, _| {
            let names: Vec<_> = fs::read_dir(env.root.join("ov"))
                .unwrap()
                .flatten()
                .map(|e| e.file_name())
                .collect();
            assert!(!names.is_empty(), "overlay has no marker/database");
        },
    );
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_overlay_dangling_link_in_base_ok() {
    mount_and_check_with(
        "p10",
        |e| std::os::unix::fs::symlink("../ov", e.root.join("B/L3")).unwrap(),
        &["-w", "ov/data", "B", "B/L3/mnt"],
        "ov/mnt",
        Some("f1.txt"),
        |_, _| {},
    );
}

#[cfg(target_os = "linux")]
#[test]
fn regression_mount_in_base_index_folder_outside_base_ok() {
    mount_and_check_with(
        "p11",
        |e| write_tiny_tar(&e.root.join("x.tar")),
        &["--index-folders", "idx", "x.tar", "B", "mnt"],
        "mnt",
        Some("hello.txt"),
        |env, mp| {
            assert!(env.root.join("idx").is_dir());
            let (_, out) = env
                .probe(
                    Command::new("ls").arg("-1A").arg(mp),
                    Duration::from_secs(10),
                )
                .expect("ls");
            assert!(String::from_utf8_lossy(&out).lines().any(|l| l == "f1.txt"));
        },
    );
}
