//! Private read-only child channel: SQLite intentionally permits only its owner.

use super::protocol::{Attempt, MAX_RESPONSE};
use ratarmount_compositing::{LowerLayerRecord, OverlayQuota, WriteOverlay};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) struct Inspector {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    path: PathBuf,
}

impl Drop for Inspector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

pub fn socket_path(attempt: &Attempt) -> PathBuf {
    attempt
        .path
        .parent()
        .expect("attempt root")
        .join("inspect.sock")
}

pub(super) fn validate_socket_path(path: &Path) -> io::Result<()> {
    // SAFETY: all-zero sockaddr_un is valid; only the path array length is used.
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let limit = address.sun_path.len();
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() >= limit || bytes.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!(
            "Unix socket path must contain no NUL and be shorter than {limit} bytes (got {}): {}; choose a shorter --socket or --state-dir path",
            bytes.len(), path.display()
        )));
    }
    Ok(())
}

// macOS/BSD accept inherits O_NONBLOCK; handlers use blocking I/O.
fn configure_accepted_stream(stream: &UnixStream) -> io::Result<()> {
    stream.set_nonblocking(false)
}

/// The reply to `status`: one JSON line, which the client decodes as such.
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Writes the mount's read-only rules refused (0 without a policy).
    pub erofs_denied: u64,
}

/// Serves `deleted_paths`, `lower_layers` and `status` for the mount's
/// overlay. `quota` is the mount's quota and policy handle, when it has one.
pub(crate) fn start(
    path: &Path,
    overlay: &Arc<WriteOverlay>,
    quota: Option<Arc<OverlayQuota>>,
) -> io::Result<Inspector> {
    validate_socket_path(path)?;
    let parent = fs::symlink_metadata(
        path.parent()
            .ok_or_else(|| io::Error::other("socket needs a parent"))?,
    )?;
    if !parent.is_dir() || parent.uid() != unsafe { libc::geteuid() } || parent.mode() & 0o077 != 0
    {
        return Err(io::Error::other(
            "inspection socket requires a private owned parent",
        ));
    }
    // The private parent keeps the socket inaccessible until chmod, without a
    // process-global umask change after the mount factory has started threads.
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let overlay = Arc::downgrade(overlay);
    let thread = thread::spawn(move || {
        while !stopping.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Err(error) = configure_accepted_stream(&stream) {
                        log::warn!("cannot configure inspection socket: {error}");
                        continue;
                    }
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    let mut command = String::new();
                    if BufReader::new(&stream)
                        .take(64)
                        .read_line(&mut command)
                        .is_err()
                        || !matches!(
                            command.as_str(),
                            "deleted_paths\n" | "lower_layers\n" | "status\n"
                        )
                    {
                        continue;
                    }
                    let Some(overlay) = overlay.upgrade() else {
                        break;
                    };
                    let reply = if command == "deleted_paths\n" {
                        let mut deleted: Vec<_> =
                            overlay.load_tombstone_paths().into_iter().collect();
                        deleted.sort();
                        serde_json::to_vec(&deleted).ok()
                    } else if command == "status\n" {
                        let erofs_denied = quota.as_ref().map_or(0, |q| q.usage().erofs_denied);
                        serde_json::to_vec(&Status { erofs_denied }).ok()
                    } else {
                        // The layers this mount composed, through its own connection.
                        overlay
                            .meta_value("lower_layers")
                            .ok()
                            .map(|layers| layers.unwrap_or_else(|| "[]".into()).into_bytes())
                    };
                    drop(overlay);
                    if let Some(mut reply) = reply {
                        if reply.len() < MAX_RESPONSE {
                            reply.push(b'\n');
                            let _ = stream.write_all(&reply);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    });
    Ok(Inspector {
        stop,
        thread: Some(thread),
        path: path.into(),
    })
}

pub fn deleted_paths(attempt: &Attempt) -> io::Result<Vec<String>> {
    request(attempt, b"deleted_paths\n", Duration::from_secs(5))
}

/// The child's recorded `lower_layers` (`[]` when it has none), within
/// `timeout` (§5.4).
pub fn lower_layers(attempt: &Attempt, timeout: Duration) -> io::Result<Vec<LowerLayerRecord>> {
    request(attempt, b"lower_layers\n", timeout)
}

/// The child's `erofs_denied` count (R1c-1 §5.4 step 4), within `timeout`.
/// A child whose overlay was dropped ends the connection without an answer,
/// which is an error.
pub fn status(attempt: &Attempt, timeout: Duration) -> io::Result<Status> {
    request(attempt, b"status\n", timeout)
}

/// Sends `command` and reads the one-line reply, all within `timeout` from
/// now: each read gets only the time left, so a reply trickled in small
/// pieces cannot stretch the exchange past it.
fn request<T: serde::de::DeserializeOwned>(
    attempt: &Attempt,
    command: &[u8],
    timeout: Duration,
) -> io::Result<T> {
    let deadline = Instant::now() + timeout;
    let left = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "inspection timed out"))
    };
    let mut stream = UnixStream::connect(socket_path(attempt))?;
    stream.set_write_timeout(Some(left()?))?;
    stream.write_all(command)?;
    let mut reply = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        stream.set_read_timeout(Some(left()?))?;
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Err(io::Error::other("incomplete inspection response"));
        }
        let start = reply.len();
        reply.extend_from_slice(&chunk[..n]);
        if let Some(at) = reply[start..].iter().position(|&b| b == b'\n') {
            break start + at + 1;
        }
        if reply.len() >= MAX_RESPONSE {
            return Err(io::Error::other("oversized inspection response"));
        }
    };
    if end > MAX_RESPONSE {
        return Err(io::Error::other("oversized inspection response"));
    }
    serde_json::from_slice(&reply[..end]).map_err(io::Error::other)
}

#[cfg(test)]
mod accepted_socket_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// Regression: inherited O_NONBLOCK must not abort a delayed request or reply.
    #[test]
    fn regression_accepted_socket_clears_inherited_nonblocking() {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("socket")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let _client = std::os::unix::net::UnixStream::connect(
            listener.local_addr().unwrap().as_pathname().unwrap(),
        )
        .unwrap();
        let (stream, _) = listener.accept().unwrap();
        // Linux does not inherit this flag; simulate the BSD accept result.
        stream.set_nonblocking(true).unwrap();
        configure_accepted_stream(&stream).unwrap();
        // SAFETY: F_GETFL only reads flags from the live stream's descriptor.
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        assert_eq!(flags & libc::O_NONBLOCK, 0);
    }
}
