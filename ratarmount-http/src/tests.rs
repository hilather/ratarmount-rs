//! Crate-level HTTP export tests (no factory / CLI).

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use ratarmount_core::{
    create_root_file_info, CheapDirent, FileInfo, ListResult, MountSource, UserData, S_IFDIR,
    S_IFREG,
};

use crate::{
    parse_http_bind, spawn_http_thread, ExportServerHandle, ExportStop, HttpOptions,
    DEFAULT_HTTP_BIND, DEFAULT_HTTP_PORT,
};

/// One-byte / short-window `Read::read` — gzip inflate windows look like this.
struct ShortRead {
    inner: Cursor<Vec<u8>>,
    chunk: usize,
}

impl Read for ShortRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(self.chunk.max(1));
        self.inner.read(&mut buf[..n])
    }
}

impl Seek for ShortRead {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

struct MemFile {
    data: Vec<u8>,
    mtime: f64,
    /// When set, `open` yields at most this many bytes per `Read::read`.
    short_chunk: Option<usize>,
}

struct MemFs {
    files: BTreeMap<String, MemFile>,
    dirs: BTreeMap<String, Vec<CheapDirent>>,
}

impl MemFs {
    fn fixture() -> Self {
        let hello = b"abcdefghijklmnopqrstuvwxyz".to_vec();
        // Larger than a typical gzip inflate window so one short `Read::read`
        // would truncate the HTTP body if `fill_read` were skipped.
        let gzip_payload: Vec<u8> = (0..80_000u32).map(|i| (i % 251) as u8).collect();
        let mut files = BTreeMap::new();
        files.insert(
            "/hello.txt".into(),
            MemFile {
                data: hello,
                mtime: 1_592_222_400.0,
                short_chunk: None,
            },
        );
        files.insert(
            "/gzip-member.bin".into(),
            MemFile {
                data: gzip_payload,
                mtime: 1_592_222_400.0,
                short_chunk: Some(64 * 1024 - 10),
            },
        );
        files.insert(
            "/sub/child.txt".into(),
            MemFile {
                data: b"nested\n".to_vec(),
                mtime: 0.0,
                short_chunk: None,
            },
        );
        let mut dirs = BTreeMap::new();
        dirs.insert(
            "/".into(),
            vec![
                CheapDirent {
                    name: "hello.txt".into(),
                    mode: S_IFREG | 0o644,
                    size: 26,
                },
                CheapDirent {
                    name: "gzip-member.bin".into(),
                    mode: S_IFREG | 0o644,
                    size: 80_000,
                },
                CheapDirent {
                    name: "sub".into(),
                    mode: S_IFDIR | 0o755,
                    size: 0,
                },
            ],
        );
        dirs.insert(
            "/sub".into(),
            vec![CheapDirent {
                name: "child.txt".into(),
                mode: S_IFREG | 0o644,
                size: 7,
            }],
        );
        Self { files, dirs }
    }

    fn file_info(path: &str, f: &MemFile) -> FileInfo {
        FileInfo {
            size: f.data.len() as u64,
            mtime: f.mtime,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Other(path.into())],
        }
    }
}

impl MountSource for MemFs {
    fn list(&self, path: &str) -> Option<ListResult> {
        let dents = self.dirs.get(path)?;
        Some(ListResult::Names(
            dents.iter().map(|d| d.name.clone()).collect(),
        ))
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.dirs.get(path).cloned()
    }

    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        if path == "/" || self.dirs.contains_key(path) {
            let mut fi = create_root_file_info();
            if path != "/" {
                fi.userdata = vec![UserData::Other(path.into())];
            }
            return Some(fi);
        }
        self.files.get(path).map(|f| Self::file_info(path, f))
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        let path = match file_info.userdata.last() {
            Some(UserData::Other(p)) => p.as_str(),
            _ => {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no path"));
            }
        };
        let f = self
            .files
            .get(path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path))?;
        match f.short_chunk {
            Some(chunk) => Ok(Box::new(ShortRead {
                inner: Cursor::new(f.data.clone()),
                chunk,
            })),
            None => Ok(Box::new(Cursor::new(f.data.clone()))),
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

struct Serving {
    handle: Option<ExportServerHandle>,
    stop: ExportStop,
    addr: SocketAddr,
}

impl Serving {
    fn start() -> Self {
        let stop = ExportStop::new();
        let opts = HttpOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            ..HttpOptions::default()
        };
        let src: Arc<dyn MountSource> = Arc::new(MemFs::fixture());
        let handle = spawn_http_thread(src, opts).expect("bind HTTP");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
        Self {
            handle: Some(handle),
            stop,
            addr,
        }
    }

    fn exchange(&self, req: &str) -> Vec<u8> {
        let mut last_err = None;
        for _ in 0..20 {
            match TcpStream::connect_timeout(&self.addr, Duration::from_secs(1)) {
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
        panic!("connect {}: {:?}", self.addr, last_err);
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.request_stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
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

#[test]
fn parse_http_bind_empty_is_20491() {
    assert_eq!(parse_http_bind("").unwrap(), DEFAULT_HTTP_BIND);
    assert_eq!(parse_http_bind("20491").unwrap().port(), DEFAULT_HTTP_PORT);
    assert_eq!(DEFAULT_HTTP_PORT, 20491);
    assert_ne!(DEFAULT_HTTP_PORT, 20490);
}

#[test]
fn head_accept_ranges() {
    let srv = Serving::start();
    let raw = srv.exchange("HEAD /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 200"),
        "status: {head}"
    );
    assert_eq!(header_value(&head, "Accept-Ranges"), Some("bytes"));
    assert_eq!(header_value(&head, "Content-Length"), Some("26"));
    assert!(header_value(&head, "Last-Modified").is_some());
    assert!(body.is_empty(), "HEAD must not send a body");
}

#[test]
fn get_range_206_bytes_match() {
    let srv = Serving::start();
    let raw =
        srv.exchange("GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=5-9\r\n\r\n");
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 206"),
        "status: {head}"
    );
    assert_eq!(header_value(&head, "Content-Range"), Some("bytes 5-9/26"));
    assert_eq!(header_value(&head, "Accept-Ranges"), Some("bytes"));
    assert_eq!(body, b"fghij");
}

/// Regression: HTTP GET of gzip member is not truncated.
#[test]
fn regression_http_get_gzip_member_is_not_truncated() {
    let srv = Serving::start();
    let raw = srv.exchange("GET /gzip-member.bin HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 200"),
        "status: {head}"
    );
    let want: Vec<u8> = (0..80_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        body.len(),
        want.len(),
        "gzip-window short Read::read must be fill-looped, not treated as HTTP EOF"
    );
    assert_eq!(body, want.as_slice());
}

#[test]
fn serve_returns_after_stop() {
    let stop = ExportStop::new();
    let opts = HttpOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        stop: Some(stop.clone()),
        ..HttpOptions::default()
    };
    let src: Arc<dyn MountSource> = Arc::new(MemFs::fixture());
    let handle = spawn_http_thread(src, opts).expect("bind");
    std::thread::sleep(Duration::from_millis(50));
    stop.request_stop();
    let start = std::time::Instant::now();
    handle.join().expect("serve join");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "ExportStop must unblock serve within the 200ms poll"
    );
}

#[test]
fn dotdot_escape_is_400() {
    let srv = Serving::start();
    for target in ["/../secret", "/foo/../hello.txt", "/%2e%2e/hello.txt"] {
        let raw = srv.exchange(&format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n"));
        let (head, body) = split_head_body(&raw);
        assert!(
            status_line(&head).starts_with("HTTP/1.1 400"),
            "target {target} status: {head}"
        );
        let body_s = String::from_utf8_lossy(body);
        assert!(
            body_s.contains("path escape") || body_s.contains("bad"),
            "body: {body_s}"
        );
    }
}

#[test]
fn directory_get_is_html_with_child_names() {
    let srv = Serving::start();
    let raw = srv.exchange("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 200"),
        "status: {head}"
    );
    let ct = header_value(&head, "Content-Type").unwrap_or("");
    assert!(ct.contains("text/html"), "content-type: {ct}");
    let html = String::from_utf8_lossy(body);
    assert!(html.contains("hello.txt"), "listing: {html}");
    assert!(html.contains("gzip-member.bin"), "listing: {html}");
    assert!(html.contains("sub"), "listing: {html}");
}

#[test]
fn range_unsatisfiable_is_416() {
    let srv = Serving::start();
    let raw =
        srv.exchange("GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=99-100\r\n\r\n");
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 416"),
        "status: {head}"
    );
    assert_eq!(header_value(&head, "Content-Range"), Some("bytes */26"));
}
