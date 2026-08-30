//! Optional HTTP Range export (`http-export` feature).
//!
//! Wraps [`ratarmount_http::spawn_http_thread`] the same way the CLI `--http`
//! path does. Default session features must not depend on this module.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ratarmount_core::MountSource;
use ratarmount_http::{spawn_http_thread, ExportServerHandle, ExportStop, HttpOptions};

use crate::Error;

pub use ratarmount_http::DEFAULT_HTTP_BIND;

/// Handle for a Session-owned HTTP Range server.
///
/// Dropping the handle (or [`Self::join`]) requests [`ExportStop`] so the
/// listener thread can leave its 200 ms poll. Without a stop flag,
/// `spawn_http_thread` would block on `accept` forever (same as CLI FUSE+HTTP).
#[must_use = "dropping HttpHandle stops the Range server"]
pub struct HttpHandle {
    port: u16,
    stop: ExportStop,
    join: Option<ExportServerHandle>,
}

impl HttpHandle {
    /// Bound TCP port (ephemeral `bind.port() == 0` is resolved after listen).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Ask the serve loop to exit (CLI `ExportStop`).
    pub fn request_stop(&self) {
        self.stop.request_stop();
    }

    /// `request_stop` then join the listener thread.
    pub fn join(mut self) -> Result<(), Error> {
        self.request_stop();
        self.join_inner()
    }

    fn join_inner(&mut self) -> Result<(), Error> {
        match self.join.take() {
            Some(h) => h.join().map_err(|e| Error::Internal(e.to_string())),
            None => Ok(()),
        }
    }
}

impl Drop for HttpHandle {
    fn drop(&mut self) {
        self.stop.request_stop();
        let _ = self.join_inner();
    }
}

/// Bind `source` like CLI `--http`. `index_sidecar` is the on-disk 0.7.x path
/// (`None` / `:memory:` → HTTP 404 at `/.ratarmount-control/index.sqlite`).
pub(crate) fn spawn(
    source: Arc<dyn MountSource>,
    index_sidecar: Option<PathBuf>,
    bind: SocketAddr,
) -> Result<HttpHandle, Error> {
    let stop = ExportStop::new();
    let opts = HttpOptions {
        bind,
        stop: Some(stop.clone()),
        overlay: None,
        readahead_bytes: 0,
        webdav: false,
        index_sidecar,
    };
    let handle = spawn_http_thread(source, opts).map_err(|e| Error::Internal(e.to_string()))?;
    Ok(HttpHandle {
        port: handle.port,
        stop,
        join: Some(handle),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpStream};
    use std::path::Path;
    use std::time::{Duration, Instant};

    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};

    use crate::types::{IndexPolicy, OpenRequest, Recreate, SourceSpec};
    use crate::Session;

    fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn write_tar(path: &Path, members: &[UstarMember<'_>]) {
        let mut f = std::fs::File::create(path).unwrap();
        write_ustar_members(&mut f, members).unwrap();
        write_tar_eof(&mut f).unwrap();
        f.flush().unwrap();
    }

    fn open_req(
        tar: &Path,
        index: IndexPolicy,
        explicit: Option<std::path::PathBuf>,
    ) -> OpenRequest {
        OpenRequest {
            source: SourceSpec::Path(tar.to_path_buf()),
            index,
            explicit_index: explicit,
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        }
    }

    fn http_exchange(port: u16, req: &str) -> Vec<u8> {
        let addr = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut last_err = None;
        for _ in 0..20 {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
                Ok(mut s) => {
                    s.set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("read timeout");
                    s.set_write_timeout(Some(Duration::from_secs(2)))
                        .expect("write timeout");
                    s.write_all(req.as_bytes()).expect("write request");
                    let _ = s.shutdown(std::net::Shutdown::Write);
                    let mut out = Vec::new();
                    s.read_to_end(&mut out).expect("read response");
                    return out;
                }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        panic!("connect {addr}: {last_err:?}");
    }

    fn split_head_body(raw: &[u8]) -> (String, &[u8]) {
        let pos = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header terminator");
        let head = String::from_utf8_lossy(&raw[..pos]).into_owned();
        (head, &raw[pos + 4..])
    }

    fn status_line(head: &str) -> &str {
        head.lines().next().unwrap_or("")
    }

    fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        for line in head.lines().skip(1) {
            if let Some((n, v)) = line.split_once(':') {
                if n.eq_ignore_ascii_case(name) {
                    return Some(v.trim());
                }
            }
        }
        None
    }

    fn ephemeral() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn default_http_bind_is_loopback_20491() {
        assert_eq!(DEFAULT_HTTP_BIND.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(DEFAULT_HTTP_BIND.port(), 20491);
        assert_ne!(DEFAULT_HTTP_BIND.port(), 20490);
    }

    /// Range GET of a TAR member matches bytes; stop unblocks join.
    #[test]
    fn start_http_range_then_stop() {
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("http.tar");
        write_tar(
            &tar,
            &[member_file("hello.txt", b"abcdefghijklmnopqrstuvwxyz")],
        );
        let idx = dir.path().join("http.tar.index.sqlite");
        let session =
            Session::open(open_req(&tar, IndexPolicy::Explicit, Some(idx))).expect("open");
        let handle = session.start_http(ephemeral()).expect("start_http");
        let port = handle.port();

        let raw = http_exchange(
            port,
            "GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=5-9\r\n\r\n",
        );
        let (head, body) = split_head_body(&raw);
        assert!(
            status_line(&head).starts_with("HTTP/1.1 206"),
            "status: {head}"
        );
        assert_eq!(header_value(&head, "Content-Range"), Some("bytes 5-9/26"));
        assert_eq!(body, b"fghij");

        let start = Instant::now();
        handle.join().expect("join");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "ExportStop must unblock serve within the 200ms poll"
        );
    }

    /// Path-backed sidecar is served at the control path; tree GET is still the member.
    #[test]
    fn start_http_serves_index_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("idx.tar");
        write_tar(
            &tar,
            &[member_file("hello.txt", b"abcdefghijklmnopqrstuvwxyz")],
        );
        let idx = dir.path().join("idx.tar.index.sqlite");
        let session =
            Session::open(open_req(&tar, IndexPolicy::Explicit, Some(idx.clone()))).expect("open");
        let on_disk = std::fs::read(&idx).expect("sidecar bytes");
        assert!(on_disk.starts_with(b"SQLite format 3"));
        let handle = session.start_http(ephemeral()).expect("start_http");
        let port = handle.port();

        let raw = http_exchange(
            port,
            "GET /.ratarmount-control/index.sqlite HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let (head, body) = split_head_body(&raw);
        assert!(
            status_line(&head).starts_with("HTTP/1.1 200"),
            "sidecar status: {head}"
        );
        assert_eq!(
            header_value(&head, "Content-Type"),
            Some(ratarmount_http::INDEX_MEDIA_TYPE)
        );
        assert_eq!(body, on_disk.as_slice());

        let raw = http_exchange(port, "GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (head, body) = split_head_body(&raw);
        assert!(
            status_line(&head).starts_with("HTTP/1.1 200"),
            "member: {head}"
        );
        assert_eq!(body, b"abcdefghijklmnopqrstuvwxyz");
    }

    /// `:memory:` catalog is not an on-disk sidecar — control GET is 404.
    #[test]
    fn start_http_memory_index_sidecar_is_404() {
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("mem.tar");
        write_tar(
            &tar,
            &[member_file("hello.txt", b"abcdefghijklmnopqrstuvwxyz")],
        );
        let session = Session::open(open_req(&tar, IndexPolicy::Memory, None)).expect("open");
        let handle = session.start_http(ephemeral()).expect("start_http");
        let port = handle.port();

        let raw = http_exchange(
            port,
            "GET /.ratarmount-control/index.sqlite HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let (head, _) = split_head_body(&raw);
        assert!(
            status_line(&head).starts_with("HTTP/1.1 404"),
            ":memory: sidecar: {head}"
        );

        let raw = http_exchange(port, "GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (head, body) = split_head_body(&raw);
        assert!(
            status_line(&head).starts_with("HTTP/1.1 200"),
            "member: {head}"
        );
        assert_eq!(body, b"abcdefghijklmnopqrstuvwxyz");
    }
}
