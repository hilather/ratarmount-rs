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

use ratarmount_compositing::WriteOverlay;

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
        let ov = Arc::new(WriteOverlay::new(base, td.path()).expect("overlay"));
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
    };
    let d = format!("{st:?}");
    assert!(!d.contains("secret-pass"), "{d}");
    assert!(d.contains("***"), "{d}");
}
