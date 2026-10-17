//! Private read-only child channel: SQLite intentionally permits only its owner.

use super::protocol::{Attempt, MAX_RESPONSE};
use ratarmount_compositing::WriteOverlay;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

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

pub(crate) fn start(path: &Path, overlay: &Arc<WriteOverlay>) -> io::Result<Inspector> {
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
                        || command != "deleted_paths\n"
                    {
                        continue;
                    }
                    let Some(overlay) = overlay.upgrade() else {
                        break;
                    };
                    let mut deleted: Vec<_> = overlay.load_tombstone_paths().into_iter().collect();
                    deleted.sort();
                    drop(overlay);
                    if let Ok(mut reply) = serde_json::to_vec(&deleted) {
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
    let mut stream = UnixStream::connect(socket_path(attempt))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"deleted_paths\n")?;
    let mut line = Vec::new();
    BufReader::new(stream)
        .take((MAX_RESPONSE + 1) as u64)
        .read_until(b'\n', &mut line)?;
    if line.len() > MAX_RESPONSE || !line.ends_with(b"\n") {
        return Err(io::Error::other(
            "incomplete or oversized inspection response",
        ));
    }
    serde_json::from_slice(&line).map_err(io::Error::other)
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
