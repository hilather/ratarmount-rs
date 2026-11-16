use super::{
    get, head, post, profile_summary, put, request, HttpError, HttpResponse, Profile,
    ProfileSummary, Request, TransportKind,
};
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(super) const TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const BODY_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct Captured {
    pub(super) raw_head: Vec<u8>,
    pub(super) body: Vec<u8>,
}

impl Captured {
    pub(super) fn head(&self) -> &str {
        std::str::from_utf8(&self.raw_head).unwrap()
    }

    pub(super) fn all(&self, name: &str) -> Vec<&str> {
        self.head()
            .split("\r\n")
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
            .collect()
    }

    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.all(name).into_iter().next()
    }

    pub(super) fn has_raw_line(&self, line: &str) -> bool {
        self.raw_head
            .split(|b| *b == b'\n')
            .any(|bytes| bytes.strip_suffix(b"\r") == Some(line.as_bytes()))
    }
}

pub(super) enum Script {
    Reply(Vec<u8>),
    Silent,
}

pub(super) struct Mock {
    pub(super) base: String,
    thread: Option<JoinHandle<io::Result<Vec<Captured>>>>,
}

impl Mock {
    pub(super) fn new(replies: Vec<Vec<u8>>) -> Self {
        Self::with_scripts(replies.into_iter().map(Script::Reply).collect())
    }

    pub(super) fn with_scripts(scripts: Vec<Script>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let thread = thread::spawn(move || {
            let mut requests = Vec::new();
            for script in scripts {
                let mut stream = accept_until(&listener, Instant::now() + TIMEOUT)?;
                stream.set_read_timeout(Some(TIMEOUT))?;
                stream.set_write_timeout(Some(TIMEOUT))?;
                requests.push(read_request(&mut stream)?);
                match script {
                    Script::Reply(bytes) => stream.write_all(&bytes)?,
                    Script::Silent => {
                        // Hold the connection until the client times out; never send a reply.
                        let mut byte = [0];
                        match stream.read(&mut byte) {
                            Ok(0) => {}
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::TimedOut
                                        | io::ErrorKind::WouldBlock
                                        | io::ErrorKind::ConnectionReset
                                ) => {}
                            other => {
                                return Err(io::Error::other(format!("silent peer: {other:?}")))
                            }
                        }
                    }
                }
            }
            Ok(requests)
        });
        Self {
            base,
            thread: Some(thread),
        }
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub(super) fn get(&self, path: &str) -> Request {
        get_request(Profile::Direct, &self.url(path))
    }

    pub(super) fn request(&self, method: &str, path: &str) -> Request {
        request(Profile::Direct, method, &self.url(path)).timeout(TIMEOUT)
    }

    pub(super) fn finish(mut self) -> Vec<Captured> {
        self.thread
            .take()
            .unwrap()
            .join()
            .expect("mock thread panicked")
            .expect("mock exchange failed")
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            // Still join on assertion failure, without causing a double panic.
            if !thread::panicking() {
                result
                    .expect("mock thread panicked")
                    .expect("mock exchange failed");
            } else if !matches!(result, Ok(Ok(_))) {
                eprintln!("mock also failed while unwinding: {result:?}");
            }
        }
    }
}

pub(super) fn accept_until(listener: &TcpListener, deadline: Instant) -> io::Result<TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return into_blocking(stream),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mock accept deadline",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

// macOS/BSD accept() inherits the listener's O_NONBLOCK, and socket timeouts do
// not clear it; the mock handlers use blocking reads and writes.
pub(super) fn into_blocking(stream: TcpStream) -> io::Result<TcpStream> {
    stream.set_nonblocking(false)?;
    Ok(stream)
}

pub(super) fn read_line(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    while !line.ends_with(b"\r\n") {
        if line.len() >= 64 * 1024 || Instant::now() >= deadline {
            return Err(io::Error::other("mock line exceeded bounds"));
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
    }
    Ok(line)
}

pub(super) fn read_request(stream: &mut TcpStream) -> io::Result<Captured> {
    let deadline = Instant::now() + TIMEOUT;
    let mut raw_head = Vec::new();
    while !raw_head.ends_with(b"\r\n\r\n") {
        raw_head.extend(read_line(stream, deadline)?);
        if raw_head.len() > 64 * 1024 {
            return Err(io::Error::other("mock head exceeded bounds"));
        }
    }
    let mut request = Captured {
        raw_head,
        body: Vec::new(),
    };
    if request
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let line = read_line(stream, deadline)?;
            let size = std::str::from_utf8(&line)
                .ok()
                .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
                .ok_or_else(|| io::Error::other("invalid mock chunk size"))?;
            if size == 0 {
                if read_line(stream, deadline)? != b"\r\n" {
                    return Err(io::Error::other("unexpected mock trailers"));
                }
                break;
            }
            read_body(stream, &mut request.body, size)?;
            let mut crlf = [0; 2];
            stream.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(io::Error::other("invalid mock chunk terminator"));
            }
        }
    } else if let Some(length) = request.header("content-length") {
        let length = length
            .parse()
            .map_err(|_| io::Error::other("invalid mock content length"))?;
        read_body(stream, &mut request.body, length)?;
    }
    Ok(request)
}

pub(super) fn read_body(
    stream: &mut TcpStream,
    body: &mut Vec<u8>,
    length: usize,
) -> io::Result<()> {
    let end = body
        .len()
        .checked_add(length)
        .filter(|n| *n <= BODY_LIMIT)
        .ok_or_else(|| io::Error::other("mock body exceeded bounds"))?;
    let start = body.len();
    body.resize(end, 0);
    stream.read_exact(&mut body[start..])
}

pub(super) fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status} Mock\r\nConnection: close\r\n").into_bytes();
    if !headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
    {
        bytes.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    for (name, value) in headers {
        bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(body);
    bytes
}

pub(super) fn get_request(profile: Profile, url: &str) -> Request {
    get(profile, url).timeout(TIMEOUT)
}

#[test]
fn contract_status_body_headers_display() {
    let mock = Mock::new(vec![
        response(404, &[("X-Reason", "missing")], b"absent"),
        response(200, &[], b"ok"),
        response(304, &[], b""),
    ]);
    let url = mock.url("/missing");
    let error = get_request(Profile::Direct, &url).call().unwrap_err();
    assert_eq!(error.to_string(), format!("{url}: status code 404"));
    assert!(error.source().is_none());
    let HttpError::Status(404, response) = error else {
        panic!("expected Status(404)")
    };
    assert_eq!(response.status(), 404);
    assert_eq!(response.get_url(), url);
    assert_eq!(response.header("x-reason"), Some("missing"));
    assert_eq!(response.into_string().unwrap(), "absent");
    assert_eq!(mock.get("/ok").call().unwrap().into_string().unwrap(), "ok");
    assert_eq!(mock.get("/cached").call().unwrap().status(), 304);
    assert_eq!(mock.finish().len(), 3);
    let status = HttpError::Status(403, HttpResponse::for_test(403, &url, &[], b""));
    let display = status.to_string();
    let io = status.into_io();
    assert_eq!(io.kind(), io::ErrorKind::Other);
    assert_eq!(io.to_string(), display);
}

#[test]
fn contract_status_display_redirected() {
    let mock = Mock::new(vec![
        response(302, &[("Location", "/final")], b""),
        response(404, &[], b"missing"),
    ]);
    let first = mock.url("/first");
    let final_url = mock.url("/final");
    let error = get_request(Profile::Direct, &first).call().unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("{final_url}: status code 404 (redirected from {first})")
    );
    let HttpError::Status(404, response) = error else {
        panic!("expected redirected Status")
    };
    assert_eq!(response.get_url(), final_url);
    assert_eq!(response.into_string().unwrap(), "missing");
    assert_eq!(mock.finish().len(), 2);
}

#[test]
fn contract_header_access() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\nLink: first\r\nlInK: second\r\nBad-First: \xff\r\nbAD-fIRST: valid\r\nGood-First: valid\r\ngood-first: \x01\r\n\r\n";
    let mock = Mock::new(vec![raw.to_vec()]);
    let response = mock.get("/").call().unwrap();
    assert_eq!(response.header("LINK"), Some("first"));
    assert_eq!(response.all("link"), ["first", "second"]);
    assert_eq!(response.header("bad-first"), None);
    assert_eq!(response.all("BAD-FIRST"), ["valid"]);
    assert_eq!(response.header("GOOD-first"), Some("valid"));
    assert_eq!(response.all("good-first"), ["valid"]);
    assert_eq!(response.header("absent"), None);
    assert!(response.all("absent").is_empty());
    assert_eq!(
        response.header_names(),
        [
            "content-length",
            "connection",
            "link",
            "link",
            "bad-first",
            "bad-first",
            "good-first",
            "good-first"
        ]
    );
    assert!(response.into_string().unwrap().is_empty());
    mock.finish();
    let made = HttpResponse::for_test(
        207,
        "http://example.test/",
        &[
            ("Link", " first "),
            ("link", "second"),
            ("Bad", "\u{1}"),
            ("BAD", "valid"),
        ],
        b"xml",
    );
    assert_eq!(made.header("LINK"), Some("first"));
    assert_eq!(made.all("Link"), ["first", "second"]);
    assert_eq!(made.header("bad"), None);
    assert_eq!(made.all("bad"), ["valid"]);
    assert_eq!(made.header_names(), ["link", "link", "bad", "bad"]);
    assert_eq!(made.into_string().unwrap(), "xml");
}

#[test]
fn contract_caller_header_casing_on_wire() {
    let mock = Mock::new(vec![response(200, &[], b""), response(207, &[], b"")]);
    mock.get("/get")
        .set("X-Amz-Date", "date")
        .set("x-ms-date", "other")
        .set("Authorization", "Bearer token")
        .set("X-Replaced", "old")
        .set("x-REPLACED", "new")
        .call()
        .unwrap();
    mock.request("PROPFIND", "/dav")
        .set("Depth", "1")
        .set("X-Mixed-Case", "value")
        .send_bytes(b"query")
        .unwrap();
    let requests = mock.finish();
    for line in [
        "X-Amz-Date: date",
        "x-ms-date: other",
        "Authorization: Bearer token",
        "x-REPLACED: new",
    ] {
        assert!(
            requests[0].has_raw_line(line),
            "missing exact caller spelling {line}"
        );
    }
    assert_eq!(requests[0].all("x-replaced"), ["new"]);
    assert!(!requests[0].has_raw_line("X-Replaced: old"));
    assert!(requests[1].head().starts_with("PROPFIND /dav HTTP/1.1\r\n"));
    assert!(requests[1].has_raw_line("Depth: 1"));
    assert!(requests[1].has_raw_line("X-Mixed-Case: value"));
    assert_eq!(requests[1].body, b"query");
}

#[test]
fn contract_into_string_cap_and_lossy() {
    // Regression: one byte over the cap must fail, including with a streaming body.
    let limit = 10 * 1024 * 1024;
    let mock = Mock::new(vec![
        response(200, &[], &vec![b'a'; limit]),
        response(200, &[], &vec![b'b'; limit + 1]),
        response(200, &[], b"a\xffz"),
    ]);
    let exact = mock.get("/exact").call().unwrap().into_string().unwrap();
    assert_eq!(exact.len(), limit);
    assert!(exact.bytes().all(|b| b == b'a'));
    let error = mock
        .get("/large")
        .call()
        .unwrap()
        .into_string()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(error.to_string(), "response too big for into_string");
    assert_eq!(
        mock.get("/lossy").call().unwrap().into_string().unwrap(),
        "a\u{fffd}z"
    );
    assert_eq!(mock.finish().len(), 3);
}

#[test]
fn contract_framing_reader_with_and_without_length() {
    let mock = Mock::new(vec![response(200, &[], b""), response(200, &[], b"")]);
    let body = b"reader payload";
    mock.request("PUT", "/length")
        .set("Content-Length", &body.len().to_string())
        .send_reader(&body[..])
        .unwrap();
    mock.request("POST", "/chunked")
        .send_reader(&body[..])
        .unwrap();
    let requests = mock.finish();
    assert_eq!(requests[0].header("content-length"), Some("14"));
    assert_eq!(requests[0].header("transfer-encoding"), None);
    assert_eq!(requests[1].header("content-length"), None);
    assert_eq!(requests[1].header("transfer-encoding"), Some("chunked"));
    for request in requests {
        assert_eq!(request.body, body);
    }
}

#[test]
fn contract_bodiless_put_post_framing() {
    let mock = Mock::new(vec![response(200, &[], b""); 3]);
    put(Profile::Direct, &mock.url("/put"))
        .timeout(TIMEOUT)
        .call()
        .unwrap();
    post(Profile::Direct, &mock.url("/post"))
        .timeout(TIMEOUT)
        .call()
        .unwrap();
    post(Profile::Direct, &mock.url("/bytes"))
        .timeout(TIMEOUT)
        .send_bytes(&[])
        .unwrap();
    let requests = mock.finish();
    for request in &requests {
        assert!(request.body.is_empty());
        assert_eq!(request.header("transfer-encoding"), None);
    }
    for request in &requests[..2] {
        assert!(matches!(request.header("content-length"), None | Some("0")));
    }
    assert_eq!(requests[2].header("content-length"), Some("0"));
}

#[test]
fn contract_gzip_and_x_gzip_decoded() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"decoded payload").unwrap();
    let compressed = encoder.finish().unwrap();
    let mock = Mock::new(
        ["gzip", "x-gzip"]
            .into_iter()
            .map(|encoding| response(200, &[("Content-Encoding", encoding)], &compressed))
            .collect(),
    );
    for path in ["/gzip", "/x-gzip"] {
        let response = mock.get(path).call().unwrap();
        assert_eq!(response.header("Content-Encoding"), None);
        assert_eq!(response.header("Content-Length"), None);
        assert!(response.all("content-encoding").is_empty());
        assert!(!response
            .header_names()
            .iter()
            .any(|n| n == "content-length" || n == "content-encoding"));
        let mut bytes = Vec::new();
        response.into_reader().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"decoded payload");
    }
    assert_eq!(mock.finish().len(), 2);
}

#[test]
fn contract_gzip_head_strips_headers() {
    let mock = Mock::new(vec![response(
        200,
        &[("Content-Encoding", "gzip"), ("Content-Length", "123")],
        b"",
    )]);
    let response = head(Profile::Direct, &mock.url("/head"))
        .timeout(TIMEOUT)
        .call()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(response.header("content-length"), None);
    assert!(response.all("content-length").is_empty());
    assert_eq!(response.header_names(), ["connection"]);
    assert!(mock.finish()[0].head().starts_with("HEAD /head "));
}

#[test]
fn contract_accept_encoding_rule() {
    let mock = Mock::new(vec![response(200, &[], b""); 3]);
    mock.get("/auto").call().unwrap();
    mock.get("/range").set("rAnGe", "bytes=0-1").call().unwrap();
    mock.get("/identity")
        .set("Accept-Encoding", "identity")
        .call()
        .unwrap();
    let requests = mock.finish();
    assert!(requests[0].has_raw_line("accept-encoding: gzip"));
    assert_eq!(requests[0].all("accept-encoding"), ["gzip"]);
    assert_eq!(requests[1].header("accept-encoding"), None);
    assert_eq!(requests[2].all("accept-encoding"), ["identity"]);
    assert!(requests[2].has_raw_line("Accept-Encoding: identity"));
}

#[test]
fn contract_url_normalisation() {
    let mock = Mock::new(vec![response(200, &[], b"")]);
    let response = mock.get("/a b.index.sqlite").call().unwrap();
    assert_eq!(response.get_url(), mock.url("/a%20b.index.sqlite"));
    assert!(mock.finish()[0]
        .head()
        .starts_with("GET /a%20b.index.sqlite HTTP/1.1\r\n"));
}

pub(super) const PROXY_CHILD: &str = "RATARMOUNT_HTTP_CONTRACT_PROXY_CHILD";
pub(super) const PROXY_PASS: &str = "HTTP_CONTRACT_PROXY_CHILD_PASSED";

#[test]
fn contract_env_proxy_ignored_child() {
    if std::env::var_os(PROXY_CHILD).is_none() {
        eprintln!("skip: proxy child only runs when re-executed by its parent");
        return;
    }
    let mock = Mock::new(vec![response(200, &[], b"origin"); 3]);
    for profile in [
        Profile::Direct,
        Profile::Pooled,
        Profile::Probe { timeout: TIMEOUT },
    ] {
        assert_eq!(
            get_request(profile, &mock.url("/"))
                .call()
                .unwrap()
                .into_string()
                .unwrap(),
            "origin"
        );
    }
    assert_eq!(mock.finish().len(), 3);
    println!("{PROXY_PASS}");
}

#[test]
fn contract_env_proxy_ignored() {
    let _spawning = crate::test_process::spawning();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let proxy_listener = listener.try_clone().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let watcher = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(65);
        let mut count = 0;
        while !stopped.load(Ordering::Acquire) && Instant::now() < deadline {
            match proxy_listener.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
                    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
                    count += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("proxy listener failed: {e}"),
            }
        }
        count
    });
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "http_client::tests::contract_env_proxy_ignored_child",
            "--nocapture",
        ])
        .env(PROXY_CHILD, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(key, &proxy);
    }
    command.env_remove("NO_PROXY").env_remove("no_proxy");
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let timed_out = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break true;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().unwrap();
    stop.store(true, Ordering::Release);
    let count = watcher.join().expect("proxy watcher panicked");
    // The parent's handle pins the port even if the bounded watcher exits early.
    drop(listener);
    assert!(!timed_out, "proxy child exceeded watchdog");
    assert!(output.status.success(), "proxy child failed: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(PROXY_PASS),
        "child pass marker missing: {output:?}"
    );
    assert_eq!(
        count, 0,
        "environment proxy unexpectedly received a connection"
    );
}

#[test]
fn contract_propfind_with_body_and_send_string() {
    let mock = Mock::new(vec![
        response(207, &[], b"multistatus"),
        response(200, &[], b""),
    ]);
    let xml = "<propfind>\u{e9}</propfind>";
    let response = mock
        .request("PROPFIND", "/dav")
        .set("Content-Type", "application/xml")
        .send_string(xml)
        .unwrap();
    assert_eq!(response.status(), 207);
    assert_eq!(response.into_string().unwrap(), "multistatus");
    post(Profile::Direct, &mock.url("/text"))
        .timeout(TIMEOUT)
        .send_string("x")
        .unwrap();
    let requests = mock.finish();
    assert!(requests[0].head().starts_with("PROPFIND /dav HTTP/1.1\r\n"));
    assert_eq!(requests[0].all("content-type"), ["application/xml"]);
    assert_eq!(
        requests[0].header("content-length"),
        Some(xml.len().to_string().as_str())
    );
    assert_eq!(requests[0].header("transfer-encoding"), None);
    assert_eq!(requests[0].body, xml.as_bytes());
    assert_eq!(requests[1].header("content-type"), None);
    assert_eq!(requests[1].header("content-length"), Some("1"));
    assert_eq!(requests[1].body, b"x");
}

#[test]
fn contract_head_request() {
    let mock = Mock::new(vec![response(200, &[("Content-Length", "999")], b"")]);
    let response = head(Profile::Direct, &mock.url("/head"))
        .timeout(TIMEOUT)
        .call()
        .unwrap();
    assert_eq!(response.header("content-length"), Some("999"));
    assert_eq!(response.into_string().unwrap(), "");
    assert!(mock.finish()[0]
        .head()
        .starts_with("HEAD /head HTTP/1.1\r\n"));
}

#[test]
fn contract_get_url_final() {
    let mock = Mock::new(vec![
        response(302, &[("Location", "/final")], b""),
        response(200, &[], b"ok"),
    ]);
    let final_response = mock.get("/first").call().unwrap();
    assert_eq!(final_response.get_url(), mock.url("/final"));
    assert_eq!(final_response.into_string().unwrap(), "ok");
    assert_eq!(mock.finish().len(), 2);
    for profile in [Profile::Pooled, Profile::Probe { timeout: TIMEOUT }] {
        let mock = Mock::new(vec![response(302, &[("Location", "/unfollowed")], b"")]);
        let url = mock.url("/first");
        let response = get_request(profile, &url).call().unwrap();
        assert_eq!(response.status(), 302);
        assert_eq!(response.get_url(), url);
        assert_eq!(response.header("location"), Some("/unfollowed"));
        assert_eq!(mock.finish().len(), 1);
    }
}

#[test]
fn contract_profile_summary_values() {
    let expected = ProfileSummary {
        redirects: 0,
        reuse: true,
        max_idle_connections: Some(128),
        max_idle_connections_per_host: Some(64),
        idle_timeout: None,
        connect_timeout: Some(Duration::from_secs(30)),
        overall_timeout: None,
        read_timeout: None,
        write_timeout: None,
        env_proxy: false,
    };
    assert_eq!(profile_summary(&Profile::Pooled), expected);
    let direct = ProfileSummary {
        redirects: 5,
        reuse: false,
        max_idle_connections: None,
        max_idle_connections_per_host: None,
        ..expected
    };
    assert_eq!(profile_summary(&Profile::Direct), direct);
    let timeout = Duration::from_secs(3);
    assert_eq!(
        profile_summary(&Profile::Probe { timeout }),
        ProfileSummary {
            redirects: 0,
            overall_timeout: Some(timeout),
            ..direct
        }
    );
}

#[test]
fn contract_send_sync_static() {
    fn assert_traits<T: Send + Sync + 'static>() {}
    assert_traits::<Request>();
    assert_traits::<HttpResponse>();
    assert_traits::<HttpError>();
    assert_traits::<Box<dyn Read + Send + Sync + 'static>>();
}

#[test]
fn contract_transport_error_shape() {
    let mock = Mock::with_scripts(vec![Script::Silent]);
    let url = mock.url("/timeout");
    let error = get(Profile::Direct, &url)
        .timeout(Duration::from_millis(300))
        .call()
        .unwrap_err();
    let HttpError::Transport(transport) = &error else {
        panic!("expected transport error")
    };
    assert_eq!(transport.kind(), TransportKind::Io);
    assert_eq!(format!("{:?}", transport.kind()), "Io");
    assert_eq!(transport.url(), Some(url.as_str()));
    assert!(transport
        .to_string()
        .starts_with(&format!("{url}: Network Error")));
    assert_eq!(
        transport
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let display = error.to_string();
    let io = error.into_io();
    assert_eq!(io.kind(), io::ErrorKind::TimedOut);
    assert_eq!(io.to_string(), display);
    assert_eq!(mock.finish().len(), 1);
    let error = get_request(Profile::Direct, "ftp://example.test/file")
        .call()
        .unwrap_err();
    let HttpError::Transport(transport) = &error else {
        panic!("expected unknown scheme")
    };
    assert_eq!(transport.kind(), TransportKind::UnknownScheme);
    assert_eq!(transport.message(), Some("unknown scheme 'ftp'"));
    assert_eq!(transport.url(), Some("ftp://example.test/file"));
    assert_eq!(error.into_io().kind(), io::ErrorKind::Other);
    let error = HttpError::from(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
    let HttpError::Transport(transport) = &error else {
        panic!("expected IO transport")
    };
    assert_eq!(transport.kind(), TransportKind::Io);
    assert_eq!(transport.message(), None);
    assert_eq!(transport.url(), None);
    assert_eq!(error.to_string(), "Network Error: denied");
    assert_eq!(error.into_io().kind(), io::ErrorKind::PermissionDenied);
    let parse = url::Url::parse("://invalid").unwrap_err();
    let error = HttpError::from(parse);
    let HttpError::Transport(transport) = &error else {
        panic!("expected URL transport")
    };
    assert_eq!(transport.kind(), TransportKind::InvalidUrl);
    assert_eq!(
        transport.message(),
        Some("failed to parse URL: RelativeUrlWithoutBase")
    );
    assert_eq!(transport.url(), None);
    assert_eq!(
        transport
            .source()
            .unwrap()
            .downcast_ref::<url::ParseError>(),
        Some(&parse)
    );
    assert_eq!(error.into_io().kind(), io::ErrorKind::Other);
}

#[test]
fn contract_mock_accept_clears_inherited_nonblocking() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = thread::spawn(move || -> io::Result<()> {
        let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        thread::sleep(Duration::from_millis(200));
        stream.write_all(b"late")
    });
    let server = (|| -> io::Result<[u8; 4]> {
        let accepted = accept_until(&listener, Instant::now() + TIMEOUT)?;
        // Simulate the macOS/BSD inheritance explicitly so the check holds on Linux too.
        accepted.set_nonblocking(true)?;
        let mut stream = into_blocking(accepted)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        let mut buf = [0; 4];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    })();
    // Join before asserting so a server-side failure never detaches the client.
    let client = client.join().expect("client thread panicked");
    assert_eq!(&server.unwrap(), b"late");
    client.unwrap();
}
