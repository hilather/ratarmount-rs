//! Crate-level HTTP export tests (no factory / CLI).

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ratarmount_core::{
    create_root_file_info, CheapDirent, FileInfo, ListResult, MountSource, UserData, S_IFDIR,
    S_IFREG,
};

use crate::{
    parse_http_bind, parse_webdav_bind, spawn_http_thread, spawn_webdav_thread, ExportServerHandle,
    ExportStop, HttpOptions, WebDavOptions, DEFAULT_HTTP_BIND, DEFAULT_HTTP_PORT,
    DEFAULT_WEBDAV_BIND, DEFAULT_WEBDAV_PORT,
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

/// Serialize WebDAV tests that spawn a listener (env credentials are process-global).
static WEBDAV_ENV_LOCK: Mutex<()> = Mutex::new(());
const WEBDAV_USER_ENV: &str = "RATARMOUNT_WEBDAV_USER";
const WEBDAV_PASSWORD_ENV: &str = "RATARMOUNT_WEBDAV_PASSWORD";

fn lock_webdav_env() -> MutexGuard<'static, ()> {
    let g = WEBDAV_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var(WEBDAV_USER_ENV);
    std::env::remove_var(WEBDAV_PASSWORD_ENV);
    g
}

const LOCK_EXCLUSIVE: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    "<D:lockinfo xmlns:D=\"DAV:\">",
    "<D:lockscope><D:exclusive/></D:lockscope>",
    "<D:locktype><D:write/></D:locktype>",
    "</D:lockinfo>"
);

fn lock_request(path: &str) -> String {
    format!(
        "LOCK {path} HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{LOCK_EXCLUSIVE}",
        LOCK_EXCLUSIVE.len()
    )
}

fn lock_token_from_head(head: &str) -> String {
    let v = header_value(head, "Lock-Token").expect("Lock-Token header");
    v.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

struct Serving {
    handle: Option<ExportServerHandle>,
    stop: ExportStop,
    addr: SocketAddr,
    _overlay_dir: Option<tempfile::TempDir>,
    _webdav_env: Option<MutexGuard<'static, ()>>,
}

impl Serving {
    fn start() -> Self {
        Self::start_http()
    }

    fn start_http() -> Self {
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
            _overlay_dir: None,
            _webdav_env: None,
        }
    }

    fn start_webdav() -> Self {
        let env = lock_webdav_env();
        let stop = ExportStop::new();
        let opts = WebDavOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            ..WebDavOptions::default()
        };
        let src: Arc<dyn MountSource> = Arc::new(MemFs::fixture());
        let handle = spawn_webdav_thread(src, opts).expect("bind WebDAV");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
        Self {
            handle: Some(handle),
            stop,
            addr,
            _overlay_dir: None,
            _webdav_env: Some(env),
        }
    }

    fn start_webdav_overlay() -> Self {
        let env = lock_webdav_env();
        let stop = ExportStop::new();
        let td = tempfile::tempdir().expect("overlay tempdir");
        let base: Arc<dyn MountSource> = Arc::new(MemFs::fixture());
        let ov = Arc::new(crate::test_overlay::new_overlay(base, td.path()).expect("overlay"));
        let opts = WebDavOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            overlay: Some(Arc::clone(&ov)),
            ..WebDavOptions::default()
        };
        let src: Arc<dyn MountSource> = ov;
        let handle = spawn_webdav_thread(src, opts).expect("bind WebDAV overlay");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
        Self {
            handle: Some(handle),
            stop,
            addr,
            _overlay_dir: Some(td),
            _webdav_env: Some(env),
        }
    }

    fn start_webdav_basic(user: &str, pass: &str) -> Self {
        let env = lock_webdav_env();
        std::env::set_var(WEBDAV_USER_ENV, user);
        std::env::set_var(WEBDAV_PASSWORD_ENV, pass);
        let stop = ExportStop::new();
        let opts = WebDavOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            ..WebDavOptions::default()
        };
        let src: Arc<dyn MountSource> = Arc::new(MemFs::fixture());
        let handle = spawn_webdav_thread(src, opts).expect("bind WebDAV basic");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
        Self {
            handle: Some(handle),
            stop,
            addr,
            _overlay_dir: None,
            _webdav_env: Some(env),
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
        if self._webdav_env.is_some() {
            std::env::remove_var(WEBDAV_USER_ENV);
            std::env::remove_var(WEBDAV_PASSWORD_ENV);
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
    assert!(
        html.contains("href=\"/hello.txt\""),
        "root file href must be path-absolute: {html}"
    );
    assert!(
        html.contains("href=\"/sub/\""),
        "directory href must be path-absolute with trailing slash: {html}"
    );
}

#[test]
fn nested_directory_listing_hrefs_are_path_absolute() {
    let srv = Serving::start();
    let raw = srv.exchange("GET /sub HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 200"),
        "status: {head}"
    );
    let html = String::from_utf8_lossy(body);
    assert!(
        html.contains("href=\"/sub/child.txt\""),
        "GET /sub (no trailing slash) must not emit href=\"child.txt\": {html}"
    );
    let raw_slash = srv.exchange("GET /sub/ HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head_slash, body_slash) = split_head_body(&raw_slash);
    assert!(
        status_line(&head_slash).starts_with("HTTP/1.1 200"),
        "GET /sub/ status: {head_slash}"
    );
    let html_slash = String::from_utf8_lossy(body_slash);
    assert!(
        html_slash.contains("href=\"/sub/child.txt\""),
        "listing: {html_slash}"
    );
    let child = srv.exchange("GET /sub/child.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (chead, cbody) = split_head_body(&child);
    assert!(
        status_line(&chead).starts_with("HTTP/1.1 200"),
        "status: {chead}"
    );
    assert_eq!(cbody, b"nested\n");
}

#[test]
fn head_error_responses_have_no_body() {
    let srv = Serving::start();
    let missing = srv.exchange("HEAD /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&missing);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 404"),
        "status: {head}"
    );
    assert_eq!(header_value(&head, "Content-Length"), Some("10")); // "not found\n"
    assert!(body.is_empty(), "HEAD 404 must not send a body: {body:?}");

    let escape = srv.exchange("HEAD /../secret HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&escape);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 400"),
        "status: {head}"
    );
    assert_eq!(header_value(&head, "Content-Length"), Some("12")); // "path escape\n"
    assert!(body.is_empty(), "HEAD 400 must not send a body: {body:?}");
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

#[test]
fn parse_webdav_bind_empty_is_20492() {
    assert_eq!(parse_webdav_bind("").unwrap(), DEFAULT_WEBDAV_BIND);
    assert_eq!(
        parse_webdav_bind("20492").unwrap().port(),
        DEFAULT_WEBDAV_PORT
    );
    assert_eq!(DEFAULT_WEBDAV_PORT, 20492);
    assert_ne!(DEFAULT_WEBDAV_PORT, DEFAULT_HTTP_PORT);
}

#[test]
fn propfind_depth_1_xml() {
    let srv = Serving::start_webdav();
    let raw = srv.exchange(
        "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: 1\r\nContent-Length: 0\r\n\r\n",
    );
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 207"),
        "status: {head}"
    );
    let ct = header_value(&head, "Content-Type").unwrap_or("");
    assert!(ct.contains("xml"), "content-type: {ct}");
    let xml = String::from_utf8_lossy(body);
    assert!(xml.contains("multistatus"), "xml: {xml}");
    assert!(
        xml.contains("<D:getcontentlength>26</D:getcontentlength>"),
        "hello.txt length missing: {xml}"
    );
    assert!(xml.contains("/hello.txt"), "href hello.txt: {xml}");
    assert!(
        xml.contains("<D:collection/>"),
        "root/sub must be collections: {xml}"
    );
    assert!(xml.contains("/sub/"), "dir href trailing slash: {xml}");
    assert!(xml.contains("getlastmodified") || xml.contains("getcontentlength"));
}

/// GET/HEAD on the WebDAV listener reuse the P-5 Range handler.
#[test]
fn webdav_get_reuses_http_handler() {
    let srv = Serving::start_webdav();
    let raw = srv.exchange("GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 200"),
        "status: {head}"
    );
    assert_eq!(body, b"abcdefghijklmnopqrstuvwxyz");
    let ranged =
        srv.exchange("GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=5-9\r\n\r\n");
    let (rhead, rbody) = split_head_body(&ranged);
    assert!(
        status_line(&rhead).starts_with("HTTP/1.1 206"),
        "status: {rhead}"
    );
    assert_eq!(rbody, b"fghij");
}

#[test]
fn put_without_overlay_is_403() {
    let srv = Serving::start_webdav();
    let raw =
        srv.exchange("PUT /new.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello");
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 403"),
        "status: {head}"
    );
}

/// PUT then GET through WriteOverlay (`-w`).
#[test]
fn put_then_get_with_overlay() {
    let srv = Serving::start_webdav_overlay();
    let body = b"webdav-put\n";
    let put = format!(
        "PUT /new.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    );
    let raw = srv.exchange(&put);
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 201"),
        "PUT status: {head}"
    );
    let get = srv.exchange("GET /new.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (ghead, gbody) = split_head_body(&get);
    assert!(
        status_line(&ghead).starts_with("HTTP/1.1 200"),
        "GET status: {ghead}"
    );
    assert_eq!(gbody, body);
}

#[test]
fn propfind_depth_infinity_is_403() {
    let srv = Serving::start_webdav();
    for depth in ["infinity", "Infinity", "2"] {
        let raw = srv.exchange(&format!(
            "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: {depth}\r\nContent-Length: 0\r\n\r\n"
        ));
        let (head, body) = split_head_body(&raw);
        assert!(
            status_line(&head).starts_with("HTTP/1.1 403"),
            "Depth {depth} status: {head}"
        );
        let s = String::from_utf8_lossy(body);
        assert!(
            s.to_ascii_lowercase().contains("infinity")
                || s.contains("not supported")
                || !s.is_empty(),
            "body: {s}"
        );
    }
    let missing =
        srv.exchange("PROPFIND / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    let (head, _) = split_head_body(&missing);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 403"),
        "missing Depth must be infinity → 403: {head}"
    );
}

#[test]
fn put_on_http_export_is_405() {
    let srv = Serving::start_http();
    let raw =
        srv.exchange("PUT /new.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello");
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 405"),
        "plain HTTP PUT must stay 405 not 403: {head}"
    );
}

#[test]
fn options_dav_class_2() {
    let srv = Serving::start_webdav();
    let raw = srv.exchange("OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 200"),
        "status: {head}"
    );
    assert_eq!(header_value(&head, "DAV"), Some("1,2"));
    let allow = header_value(&head, "Allow").unwrap_or("");
    for m in ["LOCK", "UNLOCK", "COPY", "PROPPATCH", "PUT", "PROPFIND"] {
        assert!(allow.contains(m), "Allow missing {m}: {allow}");
    }
}

/// Regression: LOCK then PUT without If is 423.
#[test]
fn regression_lock_then_put_without_if_is_423() {
    let srv = Serving::start_webdav_overlay();
    let locked = srv.exchange(&lock_request("/hello.txt"));
    let (lhead, _) = split_head_body(&locked);
    assert!(
        status_line(&lhead).starts_with("HTTP/1.1 200"),
        "LOCK: {lhead}"
    );
    let put =
        srv.exchange("PUT /hello.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nabcd");
    let (phead, _) = split_head_body(&put);
    assert!(
        status_line(&phead).starts_with("HTTP/1.1 423"),
        "PUT without If must be 423: {phead}"
    );
}

/// Regression: LOCK then PUT with If token is 204/201 (Finder save-in-place stand-in).
#[test]
fn regression_lock_then_put_with_if_token_is_204_or_201() {
    let srv = Serving::start_webdav_overlay();
    let locked = srv.exchange(&lock_request("/hello.txt"));
    let (lhead, lbody) = split_head_body(&locked);
    assert!(
        status_line(&lhead).starts_with("HTTP/1.1 200"),
        "LOCK: {lhead}"
    );
    let token = lock_token_from_head(&lhead);
    assert!(token.starts_with("opaquelocktoken:"), "token: {token}");
    let xml = String::from_utf8_lossy(lbody);
    assert!(xml.contains("lockdiscovery"), "{xml}");
    assert!(xml.contains("exclusive"), "{xml}");
    let put = srv.exchange(&format!(
        "PUT /hello.txt HTTP/1.1\r\nHost: localhost\r\nIf: <{token}>\r\nContent-Length: 4\r\n\r\nxyz\n"
    ));
    let (phead, _) = split_head_body(&put);
    let line = status_line(&phead);
    assert!(
        line.starts_with("HTTP/1.1 204") || line.starts_with("HTTP/1.1 201"),
        "PUT with If: {phead}"
    );
}

/// Regression: COPY of locked source without If is 201 (dest unlocked; Finder duplicate).
#[test]
fn regression_copy_of_locked_source_without_if_is_201() {
    let srv = Serving::start_webdav_overlay();
    let locked = srv.exchange(&lock_request("/hello.txt"));
    let (lhead, _) = split_head_body(&locked);
    assert!(
        status_line(&lhead).starts_with("HTTP/1.1 200"),
        "LOCK: {lhead}"
    );
    let copy = srv.exchange(
        "COPY /hello.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /copied.txt\r\nDepth: 0\r\n\r\n",
    );
    let (chead, _) = split_head_body(&copy);
    assert!(
        status_line(&chead).starts_with("HTTP/1.1 201"),
        "COPY locked source: {chead}"
    );
}

/// Regression: COPY onto locked dest without If is 423.
#[test]
fn regression_copy_onto_locked_dest_without_if_is_423() {
    let srv = Serving::start_webdav_overlay();
    let put =
        srv.exchange("PUT /dest.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nold");
    let (phead, _) = split_head_body(&put);
    assert!(
        status_line(&phead).starts_with("HTTP/1.1 201"),
        "PUT dest: {phead}"
    );
    let locked = srv.exchange(&lock_request("/dest.txt"));
    let (lhead, _) = split_head_body(&locked);
    assert!(
        status_line(&lhead).starts_with("HTTP/1.1 200"),
        "LOCK dest: {lhead}"
    );
    let copy = srv.exchange(
        "COPY /hello.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /dest.txt\r\nDepth: 0\r\nOverwrite: T\r\n\r\n",
    );
    let (chead, _) = split_head_body(&copy);
    assert!(
        status_line(&chead).starts_with("HTTP/1.1 423"),
        "COPY onto locked dest: {chead}"
    );
}

/// Regression: MOVE both locked needs both If tokens.
#[test]
fn regression_move_both_locked_needs_both_if_tokens() {
    let srv = Serving::start_webdav_overlay();
    let put_a =
        srv.exchange("PUT /a.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nA");
    assert!(
        status_line(&split_head_body(&put_a).0).starts_with("HTTP/1.1 201"),
        "PUT a"
    );
    let put_b =
        srv.exchange("PUT /b.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nB");
    assert!(
        status_line(&split_head_body(&put_b).0).starts_with("HTTP/1.1 201"),
        "PUT b"
    );
    let la = srv.exchange(&lock_request("/a.txt"));
    let (ha, _) = split_head_body(&la);
    assert!(status_line(&ha).starts_with("HTTP/1.1 200"), "LOCK a: {ha}");
    let ta = lock_token_from_head(&ha);
    let lb = srv.exchange(&lock_request("/b.txt"));
    let (hb, _) = split_head_body(&lb);
    assert!(status_line(&hb).starts_with("HTTP/1.1 200"), "LOCK b: {hb}");
    let tb = lock_token_from_head(&hb);
    let one = srv.exchange(&format!(
        "MOVE /a.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /b.txt\r\nOverwrite: T\r\nIf: <{ta}>\r\n\r\n"
    ));
    let (one_h, _) = split_head_body(&one);
    assert!(
        status_line(&one_h).starts_with("HTTP/1.1 423"),
        "one token: {one_h}"
    );
    let both = srv.exchange(&format!(
        "MOVE /a.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /b.txt\r\nOverwrite: T\r\nIf: <{ta}> <{tb}>\r\n\r\n"
    ));
    let (both_h, _) = split_head_body(&both);
    let line = status_line(&both_h);
    assert!(
        line.starts_with("HTTP/1.1 201") || line.starts_with("HTTP/1.1 204"),
        "both tokens: {both_h}"
    );
}

#[test]
fn unlock_unknown_token_is_409() {
    let srv = Serving::start_webdav();
    let raw = srv.exchange(
        "UNLOCK /hello.txt HTTP/1.1\r\nHost: localhost\r\nLock-Token: <opaquelocktoken:deadbeef>\r\n\r\n",
    );
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 409"),
        "UNLOCK unknown: {head}"
    );
}

#[test]
fn shared_lock_is_403() {
    let srv = Serving::start_webdav();
    let body = concat!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<D:lockinfo xmlns:D=\"DAV:\">",
        "<D:lockscope><D:shared/></D:lockscope>",
        "<D:locktype><D:write/></D:locktype>",
        "</D:lockinfo>"
    );
    let raw = srv.exchange(&format!(
        "LOCK /hello.txt HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    let (head, b) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 403"),
        "shared LOCK: {head}"
    );
    let s = String::from_utf8_lossy(b);
    assert!(s.to_ascii_lowercase().contains("exclusive"), "body: {s}");
}

#[test]
fn copy_file_overlay_then_get() {
    let srv = Serving::start_webdav_overlay();
    let copy = srv.exchange(
        "COPY /hello.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /copied.txt\r\nDepth: 0\r\n\r\n",
    );
    let (chead, _) = split_head_body(&copy);
    assert!(
        status_line(&chead).starts_with("HTTP/1.1 201"),
        "COPY: {chead}"
    );
    let get = srv.exchange("GET /copied.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (ghead, gbody) = split_head_body(&get);
    assert!(
        status_line(&ghead).starts_with("HTTP/1.1 200"),
        "GET copy: {ghead}"
    );
    assert_eq!(gbody, b"abcdefghijklmnopqrstuvwxyz");
}

#[test]
fn copy_without_overlay_is_403() {
    let srv = Serving::start_webdav();
    let raw = srv.exchange(
        "COPY /hello.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /x.txt\r\nDepth: 0\r\n\r\n",
    );
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 403"),
        "COPY without -w: {head}"
    );
}

#[test]
fn copy_depth_infinity_is_403() {
    let srv = Serving::start_webdav_overlay();
    for depth in ["infinity", "Infinity"] {
        let raw = srv.exchange(&format!(
            "COPY /hello.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /x.txt\r\nDepth: {depth}\r\n\r\n"
        ));
        let (head, _) = split_head_body(&raw);
        assert!(
            status_line(&head).starts_with("HTTP/1.1 403"),
            "Depth {depth}: {head}"
        );
    }
    let missing =
        srv.exchange("COPY /hello.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /x.txt\r\n\r\n");
    let (head, _) = split_head_body(&missing);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 403"),
        "missing Depth is infinity: {head}"
    );
}

#[test]
fn copy_overwrite_f_dest_exists_is_412() {
    let srv = Serving::start_webdav_overlay();
    let raw = srv.exchange(
        "COPY /hello.txt HTTP/1.1\r\nHost: localhost\r\nDestination: /sub/child.txt\r\nDepth: 0\r\nOverwrite: F\r\n\r\n",
    );
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 412"),
        "Overwrite F: {head}"
    );
}

#[test]
fn copy_depth_1_with_nested_collection_is_403() {
    let srv = Serving::start_webdav_overlay();
    let mk = srv.exchange("MKCOL /tree HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        status_line(&split_head_body(&mk).0).starts_with("HTTP/1.1 201"),
        "MKCOL /tree"
    );
    let mk2 = srv.exchange("MKCOL /tree/nested HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        status_line(&split_head_body(&mk2).0).starts_with("HTTP/1.1 201"),
        "MKCOL /tree/nested"
    );
    let raw = srv.exchange(
        "COPY /tree HTTP/1.1\r\nHost: localhost\r\nDestination: /out\r\nDepth: 1\r\n\r\n",
    );
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 403"),
        "nested collection COPY: {head}"
    );
}

#[test]
fn proppatch_dead_property_207_403() {
    let srv = Serving::start_webdav();
    let body = concat!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:Z=\"urn:example\">",
        "<D:set><D:prop>",
        "<D:getlastmodified>x</D:getlastmodified>",
        "<Z:deadprop>nope</Z:deadprop>",
        "</D:prop></D:set></D:propertyupdate>"
    );
    let raw = srv.exchange(&format!(
        "PROPPATCH /hello.txt HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    let (head, xml) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 207"),
        "PROPPATCH: {head}"
    );
    let s = String::from_utf8_lossy(xml);
    assert!(s.contains("HTTP/1.1 200 OK"), "{s}");
    assert!(s.contains("HTTP/1.1 403 Forbidden"), "{s}");
}

/// Regression: Basic missing is 401.
#[test]
fn regression_basic_missing_is_401() {
    let srv = Serving::start_webdav_basic("dav", "s3cret");
    let raw = srv.exchange(
        "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\nContent-Length: 0\r\n\r\n",
    );
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 401"),
        "missing Basic: {head}"
    );
    let wa = header_value(&head, "WWW-Authenticate").unwrap_or("");
    assert!(
        wa.contains("Basic") && wa.contains("ratarmount"),
        "WWW-Authenticate: {wa}"
    );
}

/// Regression: Basic matching is 207 PROPFIND (crate from_env, no CLI).
#[test]
fn regression_basic_matching_is_207_propfind() {
    let srv = Serving::start_webdav_basic("dav", "s3cret");
    let auth = crate::webdav::basic_auth_header("dav", "s3cret");
    let raw = srv.exchange(&format!(
        "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\nAuthorization: {auth}\r\nContent-Length: 0\r\n\r\n"
    ));
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 207"),
        "matching Basic: {head}"
    );
}

#[test]
fn http_state_debug_redacts_password() {
    let st = crate::handler::HttpState {
        source: Arc::new(MemFs::fixture()),
        chunk: 1024,
        overlay: None,
        webdav: true,
        locks: Mutex::new(crate::webdav::LockTable::default()),
        basic: Some(("u".into(), "secret-pass".into())),
        index_sidecar: None,
        sidecar: Default::default(),
    };
    let d = format!("{st:?}");
    assert!(!d.contains("secret-pass"), "{d}");
    assert!(d.contains("***"), "{d}");
}

/// Regression: HTTP GET of the sidecar is Content-Type `INDEX_MEDIA_TYPE`,
/// not a FUSE control file, and `--http` still serves the indexed tree.
/// Every test that serves the index sidecar (managed reads, process-wide
/// `XOPEN_CALLS`) holds this, so the admission test's open count is not
/// moved by another test's reads.
static SIDECAR_SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn index_content_type() {
    let _g = SIDECAR_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let td = tempfile::tempdir().expect("sidecar tempdir");
    let sidecar = td.path().join("archive.tar.index.sqlite");
    let blob = b"SQLite format 3\0portable-index-bytes";
    std::fs::write(&sidecar, blob).unwrap();

    let stop = ExportStop::new();
    let opts = HttpOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        stop: Some(stop.clone()),
        index_sidecar: Some(sidecar),
        ..HttpOptions::default()
    };
    let src: Arc<dyn MountSource> = Arc::new(MemFs::fixture());
    let handle = spawn_http_thread(src, opts).expect("bind HTTP");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
    let srv = Serving {
        handle: Some(handle),
        stop,
        addr,
        _overlay_dir: Some(td),
        _webdav_env: None,
    };

    let raw =
        srv.exchange("GET /.ratarmount-control/index.sqlite HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 200"),
        "status: {head}"
    );
    assert_eq!(
        header_value(&head, "Content-Type"),
        Some(crate::INDEX_MEDIA_TYPE)
    );
    assert_eq!(body, blob.as_slice());
    let link = header_value(&head, "Link").unwrap_or("");
    assert!(
        link.contains("describedby") && link.contains(crate::INDEX_MEDIA_TYPE),
        "outbound Link on index resource: {link}"
    );

    // Tree export is still members, not host archive bytes.
    let raw = srv.exchange("GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 200"),
        "member: {head}"
    );
    assert_eq!(body, b"abcdefghijklmnopqrstuvwxyz");
}

#[test]
fn index_sidecar_missing_is_404() {
    let srv = Serving::start_http();
    let raw =
        srv.exchange("GET /.ratarmount-control/index.sqlite HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, _) = split_head_body(&raw);
    assert!(
        status_line(&head).starts_with("HTTP/1.1 404"),
        ":memory: / no sidecar: {head}"
    );
}

/// R11-S7 (#151): the index sidecar endpoint reads through managed readers
/// under an eight-reader admission.
#[cfg(unix)]
mod sidecar_s7 {
    use super::*;
    use crate::handler::{SidecarAdmission, SidecarStage, INDEX_SIDECAR_READERS};
    use ratarmount_index::managed_read::lock_probe::other_process_sees_lock;
    use ratarmount_index::managed_read::XOPEN_CALLS;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Condvar;
    use std::time::Instant;

    /// The sidecar tests count the process-wide managed opens.
    use super::SIDECAR_SERIAL as SERIAL;

    struct Srv {
        handle: Option<ExportServerHandle>,
        stop: ExportStop,
        addr: SocketAddr,
    }

    impl Drop for Srv {
        fn drop(&mut self) {
            self.stop.request_stop();
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn serve(sidecar: &Path, adm: SidecarAdmission) -> Srv {
        crate::serve::TEST_SIDECAR_ADMISSION
            .lock()
            .unwrap()
            .push((sidecar.to_path_buf(), adm));
        let stop = ExportStop::new();
        let opts = HttpOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            index_sidecar: Some(sidecar.to_path_buf()),
            ..HttpOptions::default()
        };
        let handle = spawn_http_thread(Arc::new(MemFs::fixture()), opts).expect("bind HTTP");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
        Srv {
            handle: Some(handle),
            stop,
            addr,
        }
    }

    fn admission(
        hook: impl Fn(SidecarStage) -> io::Result<()> + Send + Sync + 'static,
    ) -> SidecarAdmission {
        SidecarAdmission {
            hook: Some(Arc::new(hook)),
            ..SidecarAdmission::default()
        }
    }

    /// A WAL index of about `rows` x 100 KiB, checkpointed into the main file.
    fn wal_index(path: &Path, rows: usize) -> Vec<u8> {
        let c = rusqlite::Connection::open(path).unwrap();
        c.pragma_update(None, "journal_mode", "WAL").unwrap();
        c.execute_batch("CREATE TABLE t(x BLOB)").unwrap();
        for _ in 0..rows {
            c.execute("INSERT INTO t VALUES (randomblob(100000))", [])
                .unwrap();
        }
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        drop(c);
        std::fs::read(path).unwrap()
    }

    /// A connection holding SHARED for its life (WAL keeps the main-file
    /// lock; an open read transaction pins it).
    fn holder(path: &Path) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(path).unwrap();
        c.execute_batch("BEGIN").unwrap();
        let _: i64 = c
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        c
    }

    const GET: &str = "GET /.ratarmount-control/index.sqlite HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const HEAD: &str = "HEAD /.ratarmount-control/index.sqlite HTTP/1.1\r\nHost: localhost\r\n\r\n";

    fn range(a: u64, b: u64) -> String {
        format!(
            "GET /.ratarmount-control/index.sqlite HTTP/1.1\r\nHost: localhost\r\nRange: bytes={a}-{b}\r\n\r\n"
        )
    }

    fn exchange(addr: SocketAddr, req: &str) -> Vec<u8> {
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }

    fn status(raw: &[u8]) -> u16 {
        let (head, _) = split_head_body(raw);
        status_line(&head)[9..12].parse().unwrap()
    }

    /// Descriptors of this process open on `path` (Linux: /proc/self/fd).
    fn fds_on(path: &Path) -> usize {
        let want = path.canonicalize().unwrap();
        std::fs::read_dir("/proc/self/fd")
            .map(|it| {
                it.flatten()
                    .filter(|e| std::fs::read_link(e.path()).ok().as_deref() == Some(&want))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Descriptors of this process that the server on `port` owns: sockets
    /// on that port (listener and accepted connections, from
    /// /proc/net/tcp{,6}) plus descriptors on `path` (Linux only). Other
    /// tests of this binary run concurrently, so the whole-process count is
    /// no oracle; this one is.
    fn server_fds(port: u16, path: &Path) -> usize {
        let mut inodes = std::collections::HashSet::new();
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(text) = std::fs::read_to_string(table) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                let port_of = |c: &str| {
                    c.rsplit(':')
                        .next()
                        .and_then(|p| u16::from_str_radix(p, 16).ok())
                };
                if cols.len() > 9
                    && (port_of(cols[1]) == Some(port) || port_of(cols[2]) == Some(port))
                {
                    inodes.insert(format!("socket:[{}]", cols[9]));
                }
            }
        }
        let sockets = std::fs::read_dir("/proc/self/fd")
            .map(|it| {
                it.flatten()
                    .filter(|e| {
                        std::fs::read_link(e.path())
                            .ok()
                            .is_some_and(|l| inodes.contains(&*l.to_string_lossy()))
                    })
                    .count()
            })
            .unwrap_or(0);
        sockets + fds_on(path)
    }

    /// Wait until [`server_fds`] is back to `want` (descriptors close on the
    /// server threads after the client saw its reply).
    fn settle(port: u16, path: &Path, want: usize) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let got = server_fds(port, path);
            if got <= want {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "server descriptors never settled: {got} > {want}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn tempdir() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().canonicalize().unwrap();
        (d, p)
    }

    /// Regression: serving the sidecar opened it with a raw `File` per
    /// request; closing it released the locks of a connection of this
    /// process on the same index (here a WAL session holding SHARED). GET,
    /// Range and HEAD keep the lock; a missing sidecar is still 404.
    #[test]
    fn regression_http_index_sidecar_get_keeps_index_lock() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (_d, dir) = tempdir();
        let idx = dir.join("a.index.sqlite");
        let bytes = wal_index(&idx, 3);
        let h = holder(&idx);
        assert!(other_process_sees_lock(&idx));
        let srv = serve(&idx, SidecarAdmission::default());
        let raw = exchange(srv.addr, GET);
        assert_eq!(status(&raw), 200);
        assert_eq!(split_head_body(&raw).1, bytes.as_slice());
        assert!(other_process_sees_lock(&idx), "GET kept the lock");
        let raw = exchange(srv.addr, &range(100, 199));
        assert_eq!(status(&raw), 206);
        assert_eq!(split_head_body(&raw).1, &bytes[100..200]);
        let raw = exchange(srv.addr, HEAD);
        assert_eq!(status(&raw), 200);
        let (head, body) = split_head_body(&raw);
        assert_eq!(
            header_value(&head, "Content-Length"),
            Some(bytes.len().to_string().as_str())
        );
        assert!(body.is_empty());
        assert!(
            other_process_sees_lock(&idx),
            "Range and HEAD kept the lock"
        );
        drop(std::fs::File::open(&idx).unwrap());
        assert!(!other_process_sees_lock(&idx), "oracle check");
        drop(h);
        drop(srv);
        std::fs::remove_file(&idx).unwrap();
        let srv = serve(&idx, SidecarAdmission::default());
        assert_eq!(status(&exchange(srv.addr, GET)), 404);
    }

    /// Regression: a sidecar that came up short ended the body with a
    /// successful `break` (a truncated download looked complete); an
    /// unreadable sidecar is an error before any 200 header.
    #[test]
    fn regression_http_index_sidecar_read_failure_is_not_complete() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (_d, dir) = tempdir();
        let idx = dir.join("a.index.sqlite");
        let bytes = wal_index(&idx, 3);
        // Shrunk after the length was taken: short body, never complete.
        let i2 = idx.clone();
        let srv = serve(
            &idx,
            admission(move |s| {
                if s == SidecarStage::Acquired {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&i2)?
                        .set_len(1000)?;
                }
                Ok(())
            }),
        );
        let raw = exchange(srv.addr, GET);
        let (head, body) = split_head_body(&raw);
        assert!(status_line(&head).contains("200"), "{head}");
        let advertised: usize = header_value(&head, "Content-Length")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(advertised, bytes.len());
        assert!(body.len() < advertised, "short body is not complete");
        drop(srv);
        // A read error mid-body.
        std::fs::write(&idx, &bytes).unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = Arc::clone(&n);
        let srv = serve(
            &idx,
            admission(move |s| {
                if s == SidecarStage::BeforeChunk && n2.fetch_add(1, Ordering::SeqCst) == 1 {
                    return Err(io::Error::other("injected"));
                }
                Ok(())
            }),
        );
        let raw = exchange(srv.addr, GET);
        assert!(split_head_body(&raw).1.len() < bytes.len());
        drop(srv);
        // Unreadable: 500, no 200 header (skip as root).
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&idx, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&idx).is_ok() {
            eprintln!("skip: running as root, cannot make the sidecar unreadable");
        } else {
            let srv = serve(&idx, SidecarAdmission::default());
            assert_eq!(status(&exchange(srv.addr, GET)), 500);
        }
        std::fs::set_permissions(&idx, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    struct Gate {
        open: Mutex<bool>,
        cv: Condvar,
        acquired: AtomicUsize,
        fail_chunks: AtomicBool,
    }

    impl Gate {
        fn wait_acquired(&self, n: usize) {
            let deadline = Instant::now() + Duration::from_secs(20);
            while self.acquired.load(Ordering::SeqCst) < n {
                assert!(
                    Instant::now() < deadline,
                    "admitted readers never reached {n}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        fn set(&self, open: bool) {
            *self.open.lock().unwrap() = open;
            self.cv.notify_all();
        }
    }

    /// Regression: one raw descriptor per in-flight sidecar request, with no
    /// bound. Real loopback requests against a WAL index whose main-file lock
    /// a session holds: eight admitted readers are held after acquisition;
    /// more requests (HEAD included) get 503 without any byte open; the
    /// descriptors on the inode stay within baseline + 8 during and after
    /// repeated waves (parked descriptors are reused); read errors and
    /// disconnects give their permits back; the lock stays until the session
    /// lets go. Descriptor counts are Linux-only (/proc/self/fd).
    #[test]
    fn regression_http_index_sidecar_descriptor_bound() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (_d, dir) = tempdir();
        let idx = dir.join("a.index.sqlite");
        let bytes = Arc::new(wal_index(&idx, 4));
        let h = holder(&idx);
        let base = fds_on(&idx);
        let gate = Arc::new(Gate {
            open: Mutex::new(false),
            cv: Condvar::new(),
            acquired: AtomicUsize::new(0),
            fail_chunks: AtomicBool::new(false),
        });
        let g2 = Arc::clone(&gate);
        let srv = serve(
            &idx,
            admission(move |s| {
                match s {
                    SidecarStage::Acquired => {
                        g2.acquired.fetch_add(1, Ordering::SeqCst);
                        let mut open = g2.open.lock().unwrap();
                        while !*open {
                            open = g2.cv.wait(open).unwrap();
                        }
                    }
                    SidecarStage::BeforeChunk if g2.fail_chunks.load(Ordering::SeqCst) => {
                        return Err(io::Error::other("injected"));
                    }
                    _ => {}
                }
                Ok(())
            }),
        );
        let linux = cfg!(target_os = "linux");
        // The listener plus the session's descriptors on the index.
        let settled = server_fds(srv.addr.port(), &idx);
        for wave in 0..3 {
            gate.set(false);
            gate.acquired.store(0, Ordering::SeqCst);
            let clients: Vec<_> = (0..INDEX_SIDECAR_READERS)
                .map(|i| {
                    let (addr, bytes) = (srv.addr, Arc::clone(&bytes));
                    std::thread::spawn(move || {
                        let req = if i % 2 == 0 {
                            GET.to_string()
                        } else {
                            range(0, 99)
                        };
                        let raw = exchange(addr, &req);
                        let body = split_head_body(&raw).1.to_vec();
                        if i % 2 == 0 {
                            assert_eq!(body, *bytes);
                        } else {
                            assert_eq!(body, &bytes[..100]);
                        }
                    })
                })
                .collect();
            gate.wait_acquired(INDEX_SIDECAR_READERS);
            let opens = XOPEN_CALLS.load(Ordering::SeqCst);
            for req in [GET.to_string(), HEAD.to_string(), range(5, 9)] {
                assert_eq!(status(&exchange(srv.addr, &req)), 503, "wave {wave}");
            }
            assert_eq!(
                XOPEN_CALLS.load(Ordering::SeqCst),
                opens,
                "a refused request opened nothing"
            );
            if linux {
                let during = fds_on(&idx);
                assert!(during <= base + INDEX_SIDECAR_READERS, "{base} -> {during}");
            }
            assert!(other_process_sees_lock(&idx));
            gate.set(true);
            for c in clients {
                c.join().unwrap();
            }
            if linux {
                let after = fds_on(&idx);
                assert!(
                    after <= base + INDEX_SIDECAR_READERS,
                    "wave {wave}: {base} -> {after} (parked descriptors must be reused)"
                );
            } else {
                eprintln!("skip: descriptor counts are Linux-only");
            }
        }
        // Read errors and disconnects release their permits.
        gate.fail_chunks.store(true, Ordering::SeqCst);
        for _ in 0..INDEX_SIDECAR_READERS + 2 {
            exchange(srv.addr, GET);
        }
        gate.fail_chunks.store(false, Ordering::SeqCst);
        for _ in 0..INDEX_SIDECAR_READERS + 2 {
            let mut s = TcpStream::connect(srv.addr).unwrap();
            s.write_all(GET.as_bytes()).unwrap();
            drop(s);
        }
        // All eight permits are available again.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            gate.set(false);
            gate.acquired.store(0, Ordering::SeqCst);
            let clients: Vec<_> = (0..INDEX_SIDECAR_READERS)
                .map(|_| {
                    let addr = srv.addr;
                    std::thread::spawn(move || status(&exchange(addr, HEAD)))
                })
                .collect();
            std::thread::sleep(Duration::from_millis(300));
            let got = gate.acquired.load(Ordering::SeqCst);
            gate.set(true);
            let codes: Vec<u16> = clients.into_iter().map(|c| c.join().unwrap()).collect();
            if got == INDEX_SIDECAR_READERS && codes.iter().all(|&c| c == 200) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "permits never recovered: {codes:?}"
            );
        }
        if linux {
            assert!(fds_on(&idx) <= base + INDEX_SIDECAR_READERS);
            // Every connection closed and every reader parked or reused:
            // the server's descriptors are back where they started, apart
            // from the (at most eight) parked index descriptors.
            settle(srv.addr.port(), &idx, settled + INDEX_SIDECAR_READERS);
            let deadline = Instant::now() + Duration::from_secs(20);
            while server_fds(srv.addr.port(), &idx) - fds_on(&idx) > settled - base {
                assert!(Instant::now() < deadline, "a socket was left behind");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        assert!(other_process_sees_lock(&idx), "lock held throughout");
        drop(srv);
        drop(h);
        assert!(
            !other_process_sees_lock(&idx),
            "released once the session lets go (parked descriptors closed)"
        );
        if linux {
            assert_eq!(fds_on(&idx), 0, "no descriptor left after release");
        }
    }

    /// Regression: a client that requests the sidecar and stops reading held
    /// its reader (and permit) forever, so eight such clients made every
    /// later request 503. The body has a write timeout; the permits come
    /// back while the stalled sockets are still open.
    #[test]
    fn regression_http_index_sidecar_stalled_reader_releases_reader() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (_d, dir) = tempdir();
        let idx = dir.join("big.index.sqlite");
        // A WAL index larger than the loopback socket buffers, whose
        // main-file lock a session holds throughout.
        let bytes = Arc::new(wal_index(&idx, 320));
        let h = holder(&idx);
        assert!(other_process_sees_lock(&idx));
        let gate = Arc::new(Gate {
            open: Mutex::new(true),
            cv: Condvar::new(),
            acquired: AtomicUsize::new(0),
            fail_chunks: AtomicBool::new(false),
        });
        let g2 = Arc::clone(&gate);
        let srv = serve(
            &idx,
            SidecarAdmission {
                write_timeout: Duration::from_millis(300),
                ..admission(move |s| {
                    if s == SidecarStage::Acquired {
                        g2.acquired.fetch_add(1, Ordering::SeqCst);
                        let mut open = g2.open.lock().unwrap();
                        while !*open {
                            open = g2.cv.wait(open).unwrap();
                        }
                    }
                    Ok(())
                })
            },
        );
        let stalled: Vec<TcpStream> = (0..INDEX_SIDECAR_READERS)
            .map(|_| {
                let mut s = TcpStream::connect(srv.addr).unwrap();
                s.write_all(GET.as_bytes()).unwrap();
                s
            })
            .collect();
        gate.wait_acquired(INDEX_SIDECAR_READERS);
        let saturated = status(&exchange(srv.addr, HEAD));
        assert_eq!(saturated, 503, "eight stalled readers hold every permit");
        // Every permit comes back while the stalled sockets are still open:
        // eight readers are admitted at once, and a ninth is refused.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            gate.set(false);
            gate.acquired.store(0, Ordering::SeqCst);
            let clients: Vec<_> = (0..INDEX_SIDECAR_READERS)
                .map(|_| {
                    let addr = srv.addr;
                    std::thread::spawn(move || status(&exchange(addr, HEAD)))
                })
                .collect();
            std::thread::sleep(Duration::from_millis(300));
            let got = gate.acquired.load(Ordering::SeqCst);
            let ninth = (got == INDEX_SIDECAR_READERS).then(|| status(&exchange(srv.addr, HEAD)));
            gate.set(true);
            let codes: Vec<u16> = clients.into_iter().map(|c| c.join().unwrap()).collect();
            if got == INDEX_SIDECAR_READERS && codes.iter().all(|&c| c == 200) {
                assert_eq!(ninth, Some(503), "only eight permits");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "stalled readers never released every permit: {got} admitted, {codes:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // A full read still works and the session's lock was never released.
        assert_eq!(split_head_body(&exchange(srv.addr, GET)).1, &bytes[..]);
        assert!(other_process_sees_lock(&idx), "lock held throughout");
        drop(stalled);
        drop(srv);
        drop(h);
        assert!(!other_process_sees_lock(&idx));
    }
}
