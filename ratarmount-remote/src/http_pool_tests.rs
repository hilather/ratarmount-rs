use super::*;
use crate::{HttpRangeFile, SecretString};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::Condvar;

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn range(&self) -> (u64, u64) {
        let (start, end) = self
            .header("range")
            .unwrap()
            .strip_prefix("bytes=")
            .unwrap()
            .split_once('-')
            .unwrap();
        (start.parse().unwrap(), end.parse().unwrap())
    }
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    fragmented: bool,
    body_gate: Option<Arc<BodyGate>>,
}

impl Response {
    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: vec![("Content-Length".into(), "0".into())],
            body: vec![],
            fragmented: false,
            body_gate: None,
        }
    }

    fn redirect(url: String) -> Self {
        let mut response = Self::empty(302);
        response.headers.push(("Location".into(), url));
        response
    }

    fn ranged(req: &Request, size: u64) -> Self {
        if req.method == "HEAD" {
            return Self {
                status: 200,
                headers: vec![
                    ("Content-Length".into(), size.to_string()),
                    ("Accept-Ranges".into(), "bytes".into()),
                ],
                body: vec![],
                fragmented: false,
                body_gate: None,
            };
        }
        let (start, end) = req.range();
        let end = end.min(size - 1);
        let body = pattern(start, (end - start + 1) as usize);
        Self {
            status: 206,
            headers: vec![
                ("Content-Length".into(), body.len().to_string()),
                (
                    "Content-Range".into(),
                    format!("bytes {start}-{end}/{size}"),
                ),
            ],
            body,
            fragmented: false,
            body_gate: None,
        }
    }
}

fn pattern(start: u64, len: usize) -> Vec<u8> {
    (start..start + len as u64)
        .map(|p| ((p.wrapping_mul(37) + p / 251) % 256) as u8)
        .collect()
}

struct Server {
    url: String,
    accepts: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Server {
    fn spawn(handler: impl Fn(Request) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let accepts = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let count = Arc::clone(&accepts);
        let stop = Arc::clone(&stopped);
        let handler = Arc::new(handler);
        let join = thread::spawn(move || {
            let mut clients = vec![];
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        count.fetch_add(1, Ordering::Relaxed);
                        let handler = Arc::clone(&handler);
                        let stop = Arc::clone(&stop);
                        clients.push(thread::spawn(move || serve(stream, &stop, &*handler)));
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
            for client in clients {
                client.join().unwrap();
            }
        });
        Self {
            url,
            accepts,
            stopped,
            join: Some(join),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        self.join.take().unwrap().join().unwrap();
    }
}

fn serve(mut stream: TcpStream, stopped: &AtomicBool, handler: &impl Fn(Request) -> Response) {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    while !stopped.load(Ordering::Relaxed) {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(_) => return,
        }
        let mut words = line.split_whitespace();
        let method = words.next().unwrap().to_string();
        let path = words.next().unwrap().to_string();
        let mut headers = vec![];
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.trim().split_once(':').unwrap();
            headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
        let len = headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .map_or(0, |(_, v)| v.parse::<usize>().unwrap());
        let mut body = vec![0; len];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let response = handler(Request {
            method,
            path,
            headers,
            body,
        });
        let mut head = format!("HTTP/1.1 {} Test\r\n", response.status);
        for (name, value) in response.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        if stream.write_all(head.as_bytes()).is_err() {
            return;
        }
        if let Some(gate) = response.body_gate {
            gate.block();
        }
        let fragment = if response.fragmented { 137 } else { 64 * 1024 };
        for part in response.body.chunks(fragment) {
            if stream.write_all(part).is_err() {
                return;
            }
            if response.fragmented {
                thread::yield_now();
            }
        }
    }
}

fn options() -> HttpAuthOptions {
    HttpAuthOptions {
        bearer_token: Some(SecretString::new("private-bearer-token".into())),
    }
}

/// Regression: each sequential HTTP read used to create another TCP connection.
#[test]
fn regression_http_sequential_reads_reuse_one_tcp_connection() {
    let server = Server::spawn(|req| Response::ranged(&req, 8192));
    for parallel in [1, 8] {
        let mut file = HttpRangeFile::open(&server.url).unwrap();
        file.parallel = parallel;
        let mut data = [0; 127];
        for i in 0..16 {
            file.read_exact(&mut data).unwrap();
            assert_eq!(data.as_slice(), pattern(i * 127, 127));
        }
    }
    // Both readers, their HEADs and all GETs reuse the same socket.
    assert_eq!(server.accepts.load(Ordering::Relaxed), 1);
}

/// Regression: Bearer tokens were unsupported and must never appear in Debug.
#[test]
fn regression_http_bearer_origin_header_and_secret_debug() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let server = Server::spawn(move |req| {
        assert_eq!(
            req.header("authorization"),
            Some("Bearer private-bearer-token")
        );
        count.fetch_add(1, Ordering::Relaxed);
        Response::ranged(&req, 8192)
    });
    let auth = options();
    assert!(!format!("{auth:?}").contains("private-bearer-token"));
    let mut file = HttpRangeFile::open_with_auth(&server.url, auth).unwrap();
    assert!(!format!("{file:?}").contains("private-bearer-token"));
    file.read_exact(&mut [0; 32]).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

/// Regression: every read repeated the origin redirect; origin credentials must
/// stay off the redirected host, and an expired signed URL must refresh just once.
#[test]
fn regression_http_redirect_cached_and_expiry_reresolves_once() {
    for expired_status in [401, 403, 404, 410] {
        let target_calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&target_calls);
        let target = Server::spawn(move |req| {
            assert!(req.header("authorization").is_none());
            assert!(req.header("cookie").is_none());
            let n = count.fetch_add(1, Ordering::Relaxed);
            if n >= 3 && req.path == "/signed/1" {
                return Response::empty(expired_status);
            }
            Response::ranged(&req, 8192)
        });
        let origin_calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&origin_calls);
        let target_url = target.url.clone();
        let origin = Server::spawn(move |req| {
            assert_eq!(
                req.header("authorization"),
                Some("Bearer private-bearer-token")
            );
            let n = count.fetch_add(1, Ordering::Relaxed) + 1;
            Response::redirect(format!("{target_url}/signed/{n}"))
        });
        let mut file = HttpRangeFile::open_with_auth(&origin.url, options()).unwrap();
        file.parallel = 1;
        file.read_exact(&mut [0; 16]).unwrap();
        file.read_exact(&mut [0; 16]).unwrap();
        assert_eq!(origin_calls.load(Ordering::Relaxed), 1);
        for _ in 0..4 {
            file.read_exact(&mut [0; 16]).unwrap();
        }
        assert_eq!(origin_calls.load(Ordering::Relaxed), 2);
    }
}

/// Regression: no-HEAD servers must cache the first ranged GET's redirect too.
#[test]
fn regression_http_first_range_redirect_cached_without_probe() {
    let target = Server::spawn(|req| {
        assert!(req.header("authorization").is_none());
        Response::ranged(&req, 8192)
    });
    let target_url = target.url.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let origin = Server::spawn(move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        Response::redirect(target_url.clone())
    });
    let mut file = HttpRangeFile::range_backed_with_auth(&origin.url, 8192, options());
    file.parallel = 1;
    for _ in 0..5 {
        file.read_exact(&mut [0; 31]).unwrap();
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

/// Regression: sequential HTTP reads had no overlapping ranges; responses must
/// remain ordered and a mid-stream seek must discard every old prefetch result.
#[test]
fn regression_http_parallel_64mib_ranges_ordered_and_seek_discards_prefetch() {
    const SIZE: u64 = 64 * 1024 * 1024;
    let started = Arc::new((Mutex::new(0usize), Condvar::new()));
    let gate = Arc::clone(&started);
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            let (start, end) = req.range();
            if start >= 16 * 1024 * 1024 && end - start > 1024 * 1024 {
                let (lock, ready) = &*gate;
                let mut count = lock.lock().unwrap();
                *count += 1;
                ready.notify_all();
                let (count, timeout) = ready
                    .wait_timeout_while(count, Duration::from_secs(5), |n| *n < 4)
                    .unwrap();
                assert!(
                    !timeout.timed_out() || *count >= 4,
                    "four ranges must overlap"
                );
            }
        }
        Response::ranged(&req, SIZE)
    });
    let mut file = HttpRangeFile::open(&server.url).unwrap();
    file.parallel = 8;
    // A single large read_exact must also reach the parallel path after a short first read.
    let mut data = vec![0; SIZE as usize];
    file.read_exact(&mut data).unwrap();
    assert_eq!(data.len(), SIZE as usize);
    assert_eq!(data, pattern(0, SIZE as usize));
    assert!(*started.0.lock().unwrap() >= 4);
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_exact(&mut [0; 65536]).unwrap();
    file.read_exact(&mut [0; 65536]).unwrap();
    assert!(file.prefetch.is_some());
    assert!(file.prefetch.as_ref().unwrap().pending.len() <= 8);
    let offset = 47 * 1024 * 1024 + 739;
    file.seek(SeekFrom::Start(offset)).unwrap();
    assert!(file.prefetch.is_none());
    let mut sample = vec![0; 16384];
    file.read_exact(&mut sample).unwrap();
    assert_eq!(sample, pattern(offset, 16384));
}

/// Regression: short socket reads are not EOF, while truncated range bodies are errors.
#[test]
fn regression_http_short_reads_fill_and_truncated_body_fails() {
    let server = Server::spawn(|req| {
        let mut response = Response::ranged(&req, 128 * 1024);
        response.fragmented = true;
        response
    });
    let mut file = HttpRangeFile::open(&server.url).unwrap();
    let mut data = vec![];
    file.read_to_end(&mut data).unwrap();
    assert_eq!(data, pattern(0, 128 * 1024));
    // A separate one-shot server for an actual closed/truncated socket.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
        }
        socket.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-31/8192\r\nContent-Length: 32\r\nConnection: close\r\n\r\nabc").unwrap();
    });
    let mut file = HttpRangeFile::range_backed(&url, 8192);
    assert!(file.read(&mut [0; 32]).is_err());
    worker.join().unwrap();
}

/// Regression: servers that ignore Range still serve the requested offset.
#[test]
fn regression_http_ignored_range_200_skips_to_offset() {
    let server = Server::spawn(|_| Response {
        status: 200,
        headers: vec![("Content-Length".into(), "8192".into())],
        body: pattern(0, 8192),
        fragmented: false,
        body_gate: None,
    });
    let mut file = HttpRangeFile::range_backed(&server.url, 8192);
    file.seek(SeekFrom::Start(501)).unwrap();
    let mut sample = [0; 123];
    file.read_exact(&mut sample).unwrap();
    assert_eq!(sample.as_slice(), pattern(501, 123));
}

/// Regression: malformed/mismatched Content-Range used to return unrelated bytes.
#[test]
fn regression_http_content_range_mismatch_fails_closed() {
    for header in [
        None,
        Some("bytes 1-32/8192"),
        Some("bytes 0-30/8192"),
        Some("bytes 0-31/9999"),
        Some("bytes 0-31/*"),
        Some("items 0-31/8192"),
    ] {
        let server = Server::spawn(move |_| Response {
            status: 206,
            headers: header
                .map(|h| {
                    vec![
                        ("Content-Range".into(), h.into()),
                        ("Content-Length".into(), "32".into()),
                    ]
                })
                .unwrap_or_default(),
            body: vec![0; 32],
            fragmented: false,
            body_gate: None,
        });
        let mut file = HttpRangeFile::range_backed(&server.url, 8192);
        assert_eq!(
            file.read(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

/// Regression: invalid parallelism must not spawn unbounded workers or disable reads.
#[test]
fn regression_http_parallel_env_bounded() {
    for (input, expected) in [
        (None, 8),
        (Some("1"), 1),
        (Some("0"), 1),
        (Some("8"), 8),
        (Some("99999"), 64),
        (Some("bad"), 8),
    ] {
        assert_eq!(parse_parallelism(input), expected);
    }
}

/// Regression: mismatches are rejected before reading any response bytes (pure unit test).
#[test]
fn regression_http_content_range_validation_unit() {
    for (header, start, end, size, good) in [
        ("bytes 0-31/8192", 0, 31, Some(8192), true),
        ("bytes 0-31/*", 0, 31, None, true),
        ("bytes 4-35/36", 4, 100, None, true),
        ("bytes 0-31/32", 0, 31, Some(8192), false),
        ("bytes 31-0/8192", 0, 31, None, false),
        ("bytes 0-31/31", 0, 31, None, false),
        ("bytes 0-18446744073709551615/*", 0, u64::MAX, None, false),
    ] {
        let resp: ureq::Response = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: {header}\r\nContent-Length: 32\r\n\r\n"
        )
        .parse()
        .unwrap();
        let result = validate_content_range(&resp, start, end, size);
        assert_eq!(result.is_ok(), good, "{header}");
    }
}

/// Regression: simultaneous expired ranges must share one origin refresh.
#[test]
fn regression_http_parallel_expiry_single_origin_refresh() {
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let gate = Arc::clone(&barrier);
    let target = Server::spawn(move |req| {
        assert!(req.header("authorization").is_none());
        assert!(req.header("cookie").is_none());
        if req.method == "GET" && req.path == "/signed/1" {
            gate.wait();
            return Response::empty(403);
        }
        Response::ranged(&req, 8192)
    });
    let target_url = target.url.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let origin = Server::spawn(move |req| {
        assert_eq!(
            req.header("authorization"),
            Some("Bearer private-bearer-token")
        );
        assert_eq!(req.header("cookie"), Some("session=private-cookie"));
        let n = count.fetch_add(1, Ordering::Relaxed) + 1;
        Response::redirect(format!("{target_url}/signed/{n}"))
    });
    let source = Arc::new(HttpRangeSource::new(
        HttpLocation {
            url: origin.url.clone(),
            auth: None,
            cookie: Some("session=private-cookie".into()),
        },
        options(),
    ));
    source.request("HEAD", None).unwrap();
    let readers: Vec<_> = (0..4)
        .map(|i| {
            let source = Arc::clone(&source);
            thread::spawn(move || {
                let start = i * 32;
                assert_eq!(
                    source.fetch(start, start + 31, 8192, None).unwrap(),
                    pattern(start, 32)
                );
            })
        })
        .collect();
    for reader in readers {
        reader.join().unwrap();
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

/// Regression: failed HEAD on the redirected host repeated the origin for the GET probe.
#[test]
fn regression_http_head_rejected_redirect_cached_for_range_probe() {
    let target = Server::spawn(|req| {
        assert!(req.header("authorization").is_none());
        if req.method == "HEAD" {
            Response::empty(405)
        } else {
            Response::ranged(&req, 8192)
        }
    });
    let url = target.url.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let origin = Server::spawn(move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        Response::redirect(url.clone())
    });
    let mut file = HttpRangeFile::open_with_auth(&origin.url, options()).unwrap();
    file.read_exact(&mut [0; 32]).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

/// Regression: a refreshed but still forbidden target must return an error, not loop.
#[test]
fn regression_http_expired_redirect_retry_is_bounded() {
    let target = Server::spawn(|req| {
        if req.method == "HEAD" {
            Response::ranged(&req, 8192)
        } else {
            Response::empty(403)
        }
    });
    let url = target.url.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let origin = Server::spawn(move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        Response::redirect(url.clone())
    });
    let mut file = HttpRangeFile::open_with_auth(&origin.url, options()).unwrap();
    assert!(file.read(&mut [0; 32]).is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

/// Regression: explicit Bearer must also reach full GET fallback and bounded GET helpers.
#[test]
fn regression_http_bearer_full_get_and_capped_helper() {
    let server = Server::spawn(|req| {
        assert_eq!(
            req.header("authorization"),
            Some("Bearer private-bearer-token")
        );
        Response {
            status: 200,
            headers: vec![("Content-Length".into(), "128".into())],
            body: if req.method == "HEAD" {
                vec![]
            } else {
                pattern(0, 128)
            },
            fragmented: false,
            body_gate: None,
        }
    });
    let mut file = HttpRangeFile::open_with_auth(&server.url, options()).unwrap();
    assert!(!file.uses_ranges());
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, pattern(0, 128));
    assert_eq!(
        crate::fetch_http_bytes_capped_with_auth(&server.url, 128, options()).unwrap(),
        bytes
    );
}

/// Regression: random seeks must not trigger sequential range windows.
#[test]
fn regression_http_random_reads_stay_single_request() {
    let ranges = Arc::new(Mutex::new(vec![]));
    let seen = Arc::clone(&ranges);
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            seen.lock().unwrap().push(req.range());
        }
        Response::ranged(&req, 64 * 1024 * 1024)
    });
    let mut file = HttpRangeFile::open(&server.url).unwrap();
    for start in [4096, 1024, 9199] {
        file.seek(SeekFrom::Start(start)).unwrap();
        let mut bytes = [0; 32];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), pattern(start, 32));
        assert!(file.prefetch.is_none());
    }
    assert_eq!(
        *ranges.lock().unwrap(),
        [(4096, 4127), (1024, 1055), (9199, 9230)]
    );
}

/// Regression: HTTP offsets above i64::MAX must not wrap or panic in seek arithmetic.
#[test]
fn regression_http_seek_large_offset_does_not_wrap() {
    let mut file = HttpRangeFile::range_backed("http://127.0.0.1:1/unrequested", 8192);
    assert_eq!(file.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
    assert_eq!(file.read(&mut [0; 1]).unwrap(), 0);
    assert!(file.seek(SeekFrom::Current(1)).is_err());
    assert_eq!(file.stream_position().unwrap(), u64::MAX);
    assert!(file.seek(SeekFrom::End(i64::MIN)).is_err());
}

/// Regression: relative redirects must strip credentials, switch POST to GET on
/// 303, and preserve keep-alive when consuming a small redirect response.
#[test]
fn regression_http_relative_redirect_strips_auth_and_post_body() {
    let server = Server::spawn(|req| {
        if req.path == "/origin" {
            assert_eq!(req.method, "POST");
            assert_eq!(req.body, b"payload");
            assert_eq!(
                req.header("authorization"),
                Some("Bearer private-bearer-token")
            );
            let mut response = Response::redirect("/final".into());
            response.status = 303;
            response
        } else {
            assert_eq!(req.path, "/final");
            assert_eq!(req.method, "GET");
            assert!(req.body.is_empty());
            assert!(req.header("authorization").is_none());
            assert!(req.header("cookie").is_none());
            Response::empty(200)
        }
    });
    post(&format!("{}/origin", server.url))
        .set("Authorization", "Bearer private-bearer-token")
        .set("Cookie", "secret=cookie")
        .send_string("payload")
        .unwrap();
    assert_eq!(server.accepts.load(Ordering::Relaxed), 1);
}

/// Regression: a redirect loop must stop after the configured five hops.
#[test]
fn regression_http_redirect_loop_is_bounded() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let server = Server::spawn(move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        Response::redirect("/loop".into())
    });
    assert!(get(&server.url).call().is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 6);
}

/// Regression: following a redirect must not reset an explicit per-request timeout.
#[test]
fn regression_http_redirect_preserves_overall_timeout() {
    let server = Server::spawn(|req| {
        let hop: usize = req.path.trim_start_matches('/').parse().unwrap_or(0);
        thread::sleep(Duration::from_millis(40));
        if hop < 4 {
            Response::redirect(format!("/{}", hop + 1))
        } else {
            Response::empty(200)
        }
    });
    assert!(get(&server.url)
        .timeout(Duration::from_millis(100))
        .call()
        .is_err());
}

#[derive(Default)]
struct BodyGate {
    started: AtomicUsize,
    released: Mutex<bool>,
    ready: Condvar,
}

impl BodyGate {
    fn block(&self) {
        let released = self.released.lock().unwrap();
        self.started.fetch_add(1, Ordering::SeqCst);
        self.ready.notify_all();
        drop(
            self.ready
                .wait_while(released, |released| !*released)
                .unwrap(),
        );
    }

    fn wait_started(&self, count: usize) {
        let (guard, timeout) = self
            .ready
            .wait_timeout_while(
                self.released.lock().unwrap(),
                Duration::from_secs(5),
                |_| self.started.load(Ordering::SeqCst) < count,
            )
            .unwrap();
        drop(guard);
        assert!(!timeout.timed_out(), "stalled body request did not arrive");
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.ready.notify_all();
    }
}

struct ReleaseGate(Arc<BodyGate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn stalled_response(req: &Request, size: u64, gate: &Arc<BodyGate>) -> Response {
    let (start, end) = req.range();
    Response {
        status: 206,
        headers: vec![
            ("Content-Length".into(), (end - start + 1).to_string()),
            (
                "Content-Range".into(),
                format!("bytes {start}-{end}/{size}"),
            ),
        ],
        body: vec![0],
        fragmented: false,
        body_gate: Some(Arc::clone(gate)),
    }
}

/// Regression: seeking or releasing a file waited for stalled prefetch bodies.
#[test]
fn regression_http_stalled_prefetch_seek_and_drop_do_not_wait() {
    const SIZE: u64 = 64 * 1024 * 1024;
    let gate = Arc::new(BodyGate::default());
    let server_gate = Arc::clone(&gate);
    let server = Server::spawn(move |req| {
        if req.method == "GET" && req.range().0 >= 8 * 1024 * 1024 {
            stalled_response(&req, SIZE, &server_gate)
        } else {
            Response::ranged(&req, SIZE)
        }
    });
    // Release before Server::drop on both success and an assertion unwind.
    let _release = ReleaseGate(Arc::clone(&gate));
    for seek in [true, false] {
        let mut file = HttpRangeFile::open(&server.url).unwrap();
        file.parallel = 8;
        file.read_exact(&mut vec![0; 64 * 1024]).unwrap();
        file.read_exact(&mut vec![0; HTTP_RANGE_CHUNK as usize])
            .unwrap();
        file.read_exact(&mut vec![0; 64 * 1024]).unwrap();
        gate.wait_started(if seek { 1 } else { 2 });
        let start = Instant::now();
        if seek {
            file.seek(SeekFrom::Start(1024)).unwrap();
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "seek waited for network I/O"
            );
            file.read_exact(&mut [0; 16]).unwrap();
        } else {
            drop(file);
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "drop waited for network I/O"
            );
        }
    }
}

/// Regression: an ignored Range downloaded the entire prefix after cancellation.
#[test]
fn regression_http_cancelled_200_prefix_stops_skipping() {
    struct CancelAfterRead<'a> {
        cancelled: &'a AtomicBool,
        calls: usize,
    }
    impl Read for CancelAfterRead<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            self.cancelled.store(true, Ordering::Relaxed);
            buf.fill(0);
            Ok(buf.len())
        }
    }
    let cancelled = AtomicBool::new(false);
    let mut reader = CancelAfterRead {
        cancelled: &cancelled,
        calls: 0,
    };
    assert_eq!(
        skip_prefix(&mut reader, 64 * 1024 * 1024, Some(&cancelled))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(reader.calls, 1);
}

/// Regression: two adjacent archive-header reads launched eight unnecessary chunks.
#[test]
fn regression_http_small_headers_do_not_prefetch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            assert_eq!(req.range().1 - req.range().0 + 1, 512);
            count.fetch_add(1, Ordering::Relaxed);
        }
        Response::ranged(&req, 64 * 1024 * 1024)
    });
    let mut file = HttpRangeFile::open(&server.url).unwrap();
    file.read_exact(&mut [0; 512]).unwrap();
    file.read_exact(&mut [0; 512]).unwrap();
    file.seek(SeekFrom::Start(4096)).unwrap();
    assert!(file.prefetch.is_none());
    file.read_exact(&mut [0; 512]).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 3);
}

/// Regression: a sequential run immediately filled the maximum window rather than ramping.
#[test]
fn regression_http_prefetch_window_ramps_one_two_four_eight() {
    let server = Server::spawn(|req| Response::ranged(&req, 64 * 1024 * 1024));
    let source = Arc::new(HttpRangeSource::new(
        HttpLocation {
            url: server.url.clone(),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    ));
    source.request("HEAD", None).unwrap();
    let budget = Arc::new(PrefetchBudget::new(8));
    let mut prefetch = Prefetch::with_budget(source, 0, 64 * 1024 * 1024, 8, budget);
    let mut buf = vec![0; HTTP_RANGE_CHUNK as usize];
    for (chunk, window) in [1, 2, 4, 8].into_iter().enumerate() {
        assert_eq!(prefetch.window, window);
        prefetch.fill().unwrap();
        assert_eq!(prefetch.pending.len(), window);
        assert_eq!(
            prefetch
                .read(chunk as u64 * HTTP_RANGE_CHUNK, &mut buf)
                .unwrap(),
            Some(buf.len())
        );
    }
}

/// Regression: a transient failure stayed at the front forever, even after seeking to the same offset.
#[test]
fn regression_http_transient_prefetch_error_retries_same_offset() {
    let failed = Arc::new(AtomicBool::new(false));
    let fail = Arc::clone(&failed);
    let server = Server::spawn(move |req| {
        if req.method == "GET" && req.range().0 == 64 * 1024 && !fail.swap(true, Ordering::Relaxed)
        {
            Response::empty(503)
        } else {
            Response::ranged(&req, 16 * 1024 * 1024)
        }
    });
    let mut file = HttpRangeFile::open(&server.url).unwrap();
    file.read_exact(&mut vec![0; 64 * 1024]).unwrap();
    assert!(file.read(&mut [0; 65536]).is_err());
    assert!(file.prefetch.is_none());
    assert_eq!(file.stream_position().unwrap(), 64 * 1024);
    file.seek(SeekFrom::Start(64 * 1024)).unwrap();
    let mut buf = [0; 65536];
    file.read_exact(&mut buf).unwrap();
    assert_eq!(buf.as_slice(), pattern(64 * 1024, buf.len()));
}

/// Regression: rebuilding a worker error discarded its raw errno and source.
#[test]
fn regression_http_prefetch_error_preserves_original_errno() {
    let source = Arc::new(HttpRangeSource::new(
        HttpLocation {
            url: "http://127.0.0.1:1/unused".into(),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    ));
    let mut prefetch = Prefetch::with_budget(source, 1, 1, 8, Arc::new(PrefetchBudget::new(1)));
    prefetch.pending.push_back(PendingRange {
        start: 0,
        worker: Some(thread::spawn(|| Err(io::Error::from_raw_os_error(104)))),
        data: None,
    });
    assert_eq!(
        prefetch.read(0, &mut [0]).unwrap_err().raw_os_error(),
        Some(104)
    );
}

/// Regression: many file windows or detached workers could exceed the process budget.
#[test]
fn regression_http_prefetch_budget_shared_across_100_files_and_detached_workers() {
    const SIZE: u64 = 64 * 1024 * 1024;
    let gate = Arc::new(BodyGate::default());
    let stalled = Arc::clone(&gate);
    let server = Server::spawn(move |req| stalled_response(&req, SIZE, &stalled));
    let _release = ReleaseGate(Arc::clone(&gate));
    let budget = Arc::new(PrefetchBudget::new(4));
    let mut windows = vec![];
    for _ in 0..100 {
        let source = Arc::new(HttpRangeSource::new(
            HttpLocation {
                url: server.url.clone(),
                auth: None,
                cookie: None,
            },
            HttpAuthOptions::default(),
        ));
        let mut window = Prefetch::with_budget(source, 0, SIZE, 8, Arc::clone(&budget));
        window.fill().unwrap();
        windows.push(window);
    }
    gate.wait_started(4);
    assert_eq!(budget.used.load(Ordering::Acquire), 4);
    assert_eq!(windows.iter().map(|w| w.pending.len()).sum::<usize>(), 4);
    // Check saturation while the windows still own their permits. After drop,
    // a cancelled worker may observe cancellation before its first socket read
    // and legitimately exit/release its permit before the next assertion.
    let source = Arc::new(HttpRangeSource::new(
        HttpLocation {
            url: server.url.clone(),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    ));
    let mut next = Prefetch::with_budget(source, 0, SIZE, 8, Arc::clone(&budget));
    assert_eq!(next.read(0, &mut [0]).unwrap(), None);
    assert_eq!(gate.started.load(Ordering::Relaxed), 4);
    let start = Instant::now();
    drop(windows);
    assert!(start.elapsed() < Duration::from_secs(1));
    next.fill().unwrap();
    assert!(budget.used.load(Ordering::Acquire) <= 4);
    drop(next);
    gate.release();
    let deadline = Instant::now() + Duration::from_secs(5);
    while budget.used.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(budget.used.load(Ordering::Acquire), 0);
}

/// Regression: completed but unconsumed payloads must remain charged to the process cap.
#[test]
fn regression_http_completed_prefetch_payload_retains_budget_permit() {
    let budget = Arc::new(PrefetchBudget::new(1));
    let server = Server::spawn(|req| Response::ranged(&req, HTTP_RANGE_CHUNK));
    let source = Arc::new(HttpRangeSource::new(
        HttpLocation {
            url: server.url.clone(),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    ));
    let mut prefetch = Prefetch::with_budget(source, 0, HTTP_RANGE_CHUNK, 8, Arc::clone(&budget));
    prefetch.fill().unwrap();
    let front = prefetch.pending.front_mut().unwrap();
    front.data = Some(front.worker.take().unwrap().join().unwrap().unwrap());
    assert_eq!(budget.used.load(Ordering::Acquire), 1);
    assert!(budget.try_acquire().is_none());
    let mut chunk = vec![0; HTTP_RANGE_CHUNK as usize];
    prefetch.read(0, &mut chunk).unwrap();
    assert_eq!(budget.used.load(Ordering::Acquire), 0);
}

/// Regression: shared HTTP defaults imposed new timeouts on slow gateways and full downloads.
#[test]
fn regression_http_shared_agent_preserves_ureq_default_timeouts() {
    let config = format!("{:?}", agent());
    assert!(config.contains("timeout_connect: Some(30s)"), "{config}");
    assert!(config.contains("timeout_read: None"), "{config}");
    assert!(config.contains("timeout_write: None"), "{config}");
    assert!(config.contains("timeout: None"), "{config}");
}

/// Regression: an invalid process cap must not remove the default bound.
#[test]
fn regression_http_prefetch_limit_env_is_bounded() {
    for (input, limit) in [
        (None, 64),
        (Some("0"), 1),
        (Some("4"), 4),
        (Some("bad"), 64),
        (Some("99999"), 1024),
    ] {
        assert_eq!(parse_prefetch_limit(input), limit);
    }
}

/// Regression: a rejected HEAD probe must consume the range probe through EOF for reuse.
#[test]
fn regression_http_range_probe_consumes_eof_and_reuses_connection() {
    let server = Server::spawn(|req| {
        if req.method == "HEAD" {
            Response::empty(405)
        } else {
            Response::ranged(&req, 8192)
        }
    });
    let mut file = HttpRangeFile::open(&server.url).unwrap();
    file.read_exact(&mut [0; 16]).unwrap();
    assert_eq!(server.accepts.load(Ordering::Relaxed), 1);
}

/// Regression: fallback buffered 300/304 response bodies as file content.
#[test]
fn regression_http_full_get_fallback_rejects_non_success_status() {
    for status in [300, 304] {
        let server = Server::spawn(move |req| {
            if req.method == "HEAD" {
                Response {
                    status: 200,
                    headers: vec![("Content-Length".into(), "1".into())],
                    body: vec![],
                    fragmented: false,
                    body_gate: None,
                }
            } else {
                Response::empty(status)
            }
        });
        assert!(HttpRangeFile::open_with_auth(&server.url, HttpAuthOptions::default()).is_err());
    }
}

fn range_cache_in(dir: &std::path::Path, cap: u64) -> RangeCache {
    RangeCache::with_dirs(
        dir.join("payload-v1/range-v1"),
        dir.join("payload-v1"),
        cap,
        HTTP_RANGE_CHUNK,
    )
}

fn file_with_cache(server: &Server, cache: RangeCache) -> HttpRangeFile {
    let mut source = HttpRangeSource::new(
        HttpLocation {
            url: server.url.clone(),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    );
    source.cache = Some(cache);
    let probe = crate::probe_http_source(&source).unwrap();
    let mut file =
        HttpRangeFile::from_source(Arc::new(source), probe.content_length.unwrap(), None);
    file.parallel = 8;
    file
}

/// Regression: a second reader refetched every byte, and changed ETags reused stale chunks.
#[test]
fn regression_http_range_cache_second_reader_zero_gets_and_etag_change() {
    let dir = tempfile::tempdir().unwrap();
    let cache = range_cache_in(dir.path(), 32 * 1024 * 1024);
    let gets = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&gets);
    let version = Arc::new(AtomicUsize::new(1));
    let current = Arc::clone(&version);
    const SIZE: u64 = 3 * HTTP_RANGE_CHUNK + 17;
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            count.fetch_add(1, Ordering::Relaxed);
        }
        let mut resp = Response::ranged(&req, SIZE);
        resp.headers.push((
            "ETag".into(),
            format!("\"v{}\"", current.load(Ordering::Relaxed)),
        ));
        resp
    });
    let mut first = file_with_cache(&server, cache.clone());
    let mut bytes = vec![0; SIZE as usize];
    first.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, pattern(0, SIZE as usize));
    assert_eq!(gets.load(Ordering::Relaxed), 4);
    assert!(first.complete_file().is_some());
    let before = gets.load(Ordering::Relaxed);
    let mut second = file_with_cache(&server, cache.clone());
    second.read_exact(&mut bytes).unwrap();
    assert_eq!(
        gets.load(Ordering::Relaxed),
        before,
        "warm reader must issue zero GETs, including prefetch"
    );
    assert_eq!(bytes, pattern(0, SIZE as usize));
    second.seek(SeekFrom::Start(HTTP_RANGE_CHUNK - 3)).unwrap();
    let mut crossing = [0; 9];
    second.read_exact(&mut crossing).unwrap();
    assert_eq!(crossing.as_slice(), pattern(HTTP_RANGE_CHUNK - 3, 9));
    assert_eq!(gets.load(Ordering::Relaxed), before);
    version.store(2, Ordering::Relaxed);
    let mut changed = file_with_cache(&server, cache);
    changed.read_exact(&mut [0; 16]).unwrap();
    assert_eq!(gets.load(Ordering::Relaxed), before + 1);
}

/// Regression: weak or absent ETags (and disabled caches) must not persist bytes by URL.
#[test]
fn regression_http_range_cache_weak_missing_etag_and_zero_cap() {
    for (etag, cap) in [(None, 1024), (Some("W/\"v1\""), 1024), (Some("\"v1\""), 0)] {
        let dir = tempfile::tempdir().unwrap();
        let gets = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&gets);
        let server = Server::spawn(move |req| {
            if req.method == "GET" {
                count.fetch_add(1, Ordering::Relaxed);
            }
            let mut resp = Response::ranged(&req, 16);
            if let Some(etag) = etag {
                resp.headers.push(("ETag".into(), etag.into()));
            }
            resp
        });
        let cache = range_cache_in(dir.path(), cap);
        for _ in 0..2 {
            let mut file = file_with_cache(&server, cache.clone());
            file.read_exact(&mut [0; 16]).unwrap();
            assert!(file.complete_file().is_none());
        }
        assert_eq!(gets.load(Ordering::Relaxed), 2);
    }
}

/// Regression: known Hub identities must permit caching even when CDN responses have no ETag.
#[test]
fn regression_http_range_cache_explicit_hub_token_without_etag() {
    let dir = tempfile::tempdir().unwrap();
    let cache = range_cache_in(dir.path(), 1024);
    let gets = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&gets);
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            count.fetch_add(1, Ordering::Relaxed);
        }
        Response::ranged(&req, 16)
    });
    let token = ContentToken::HfCommitPath {
        endpoint: "https://huggingface.co".into(),
        repo_kind: "model".into(),
        repo: "org/model".into(),
        commit: "a".repeat(40),
        path: "weights.bin".into(),
        size: 16,
    };
    for _ in 0..2 {
        let mut file = file_with_cache(&server, cache.clone()).with_content_token(token.clone());
        let mut buf = [0; 16];
        file.read_exact(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), pattern(0, 16));
        assert!(file.complete_file().is_some());
    }
    assert_eq!(gets.load(Ordering::Relaxed), 1);
}

/// Regression: short, mismatched and ignored range responses must never poison the disk cache.
#[test]
fn regression_http_range_cache_rejects_short_mismatched_or_unverified_response() {
    for mode in ["short", "range", "etag", "missing-etag", "ignored"] {
        let dir = tempfile::tempdir().unwrap();
        let cache = range_cache_in(dir.path(), 1024);
        let broken = Arc::new(AtomicBool::new(true));
        let bad = Arc::clone(&broken);
        let server = Server::spawn(move |req| {
            let mut resp = Response::ranged(&req, 16);
            resp.headers.push(("ETag".into(), "\"v1\"".into()));
            if req.method == "GET" && bad.load(Ordering::Relaxed) {
                match mode {
                    "short" => {
                        resp.body.truncate(3);
                        resp.headers.retain(|(k, _)| k != "Content-Length");
                        resp.headers.push(("Content-Length".into(), "3".into()));
                    }
                    "range" => {
                        for (k, v) in &mut resp.headers {
                            if k == "Content-Range" {
                                *v = "bytes 1-15/16".into();
                            }
                        }
                    }
                    "etag" => {
                        for (k, v) in &mut resp.headers {
                            if k == "ETag" {
                                *v = "\"v2\"".into();
                            }
                        }
                    }
                    "missing-etag" => resp.headers.retain(|(k, _)| k != "ETag"),
                    "ignored" => {
                        resp.status = 200;
                        resp.headers.retain(|(k, _)| k != "Content-Range");
                    }
                    _ => unreachable!(),
                }
            }
            resp
        });
        let mut file = file_with_cache(&server, cache.clone());
        let mut buf = [0; 16];
        let result = file.read_exact(&mut buf);
        if ["short", "range"].contains(&mode) {
            assert!(result.is_err(), "{mode}");
        }
        assert!(
            file.complete_file().is_none(),
            "bad {mode} response was cached"
        );
        broken.store(false, Ordering::Relaxed);
        let mut retry = file_with_cache(&server, cache);
        retry.read_exact(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), pattern(0, 16));
        assert!(retry.complete_file().is_some());
    }
}

/// Regression: two readers filling one persistent file must never publish partial bytes.
#[test]
fn regression_http_range_cache_two_threads_fill_without_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let cache = range_cache_in(dir.path(), 1024);
    let server = Server::spawn(|req| {
        let mut resp = Response::ranged(&req, 128);
        resp.headers.push(("ETag".into(), "\"v1\"".into()));
        resp
    });
    let first = file_with_cache(&server, cache.clone());
    let second = file_with_cache(&server, cache.clone());
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = [first, second]
        .into_iter()
        .map(|mut file| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let mut bytes = [0; 128];
                file.read_exact(&mut bytes).unwrap();
                assert_eq!(bytes.as_slice(), pattern(0, 128));
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let mut warm = file_with_cache(&server, cache);
    let mut bytes = [0; 128];
    warm.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes.as_slice(), pattern(0, 128));
}

/// Regression: cache hits must remain usable when every HTTP prefetch permit is occupied.
#[test]
fn regression_http_range_cache_hits_do_not_acquire_prefetch_permits() {
    let dir = tempfile::tempdir().unwrap();
    let cache = range_cache_in(dir.path(), 1024);
    let gets = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&gets);
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            count.fetch_add(1, Ordering::Relaxed);
        }
        let mut resp = Response::ranged(&req, 16);
        resp.headers.push(("ETag".into(), "\"v1\"".into()));
        resp
    });
    let mut file = file_with_cache(&server, cache.clone());
    file.read_exact(&mut [0; 16]).unwrap();
    let budget = Arc::new(PrefetchBudget::new(1));
    let _held = budget.try_acquire().unwrap();
    let warm = file_with_cache(&server, cache);
    let mut prefetch =
        Prefetch::with_budget(Arc::clone(&warm.source), 0, 16, 8, Arc::clone(&budget));
    let mut buf = [0; 16];
    assert_eq!(prefetch.read(0, &mut buf).unwrap(), Some(16));
    assert_eq!(budget.used.load(Ordering::Acquire), 1);
    assert_eq!(gets.load(Ordering::Relaxed), 1);
    assert_eq!(buf.as_slice(), pattern(0, 16));
}

/// Regression: a GET-based size probe must retain the verified identity for the first read.
#[test]
fn regression_http_range_cache_get_probe_captures_identity() {
    let dir = tempfile::tempdir().unwrap();
    let cache = range_cache_in(dir.path(), 1024);
    let gets = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&gets);
    let server = Server::spawn(move |req| {
        if req.method == "HEAD" {
            return Response::empty(405);
        }
        count.fetch_add(1, Ordering::Relaxed);
        let mut response = Response::ranged(&req, 16);
        response.headers.push(("ETag".into(), "\"v1\"".into()));
        response
    });
    let mut first = file_with_cache(&server, cache.clone());
    first.read_exact(&mut [0; 16]).unwrap();
    assert_eq!(gets.load(Ordering::Relaxed), 2); // one metadata GET and one chunk GET
    let mut second = file_with_cache(&server, cache);
    let probed = gets.load(Ordering::Relaxed);
    second.read_exact(&mut [0; 16]).unwrap();
    assert_eq!(
        gets.load(Ordering::Relaxed),
        probed,
        "only the metadata probe may GET on remount"
    );
}

/// Regression: an unprobed reader must persist its first partial range once a strong ETag arrives.
#[test]
fn regression_http_range_cache_unprobed_partial_read_does_not_refetch_aligned_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let cache = range_cache_in(dir.path(), 1024);
    let gets = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&gets);
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            count.fetch_add(1, Ordering::Relaxed);
        }
        let mut response = Response::ranged(&req, 128);
        response.headers.push(("ETag".into(), "\"v1\"".into()));
        response
    });
    let mut source = HttpRangeSource::new(
        HttpLocation {
            url: server.url.clone(),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    );
    source.cache = Some(cache.clone());
    let mut first = HttpRangeFile::from_source(Arc::new(source), 128, None);
    let mut buf = [0; 3];
    first.seek(SeekFrom::Start(7)).unwrap();
    first.read_exact(&mut buf).unwrap();
    assert_eq!(buf.as_slice(), pattern(7, 3));
    assert_eq!(gets.load(Ordering::Relaxed), 1);
    let mut second = file_with_cache(&server, cache);
    let mut all = [0; 128];
    second.read_exact(&mut all).unwrap();
    assert_eq!(all.as_slice(), pattern(0, 128));
    assert_eq!(gets.load(Ordering::Relaxed), 2);
}

/// Regression: HEAD/GET ETag differences failed reads, including when disk caching was disabled.
#[test]
fn regression_http_range_cache_etag_changes_bypass_without_failing_reads() {
    for (cap, get_etag) in [(0, "\"get\""), (1024, "\"get\""), (1024, "W/\"head\"")] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::spawn(move |req| {
            let etag = if req.method == "HEAD" {
                "\"head\""
            } else {
                get_etag
            };
            let mut response = Response::ranged(&req, 16);
            response.headers.push(("ETag".into(), etag.into()));
            response
        });
        let mut file = file_with_cache(&server, range_cache_in(temp.path(), cap));
        let mut bytes = [0; 16];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), pattern(0, 16));
        assert!(file.complete_file().is_none());
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), pattern(0, 16));
    }
}

/// Regression: explicit commit/hash tokens did not pin the first observed strong CDN ETag.
#[test]
fn regression_http_range_cache_explicit_token_etag_change_disables_cache() {
    let temp = tempfile::tempdir().unwrap();
    let version = Arc::new(AtomicUsize::new(1));
    let current = version.clone();
    let server = Server::spawn(move |req| {
        let mut response = Response::ranged(&req, 16);
        response.headers.push((
            "ETag".into(),
            format!("\"v{}\"", current.load(Ordering::Relaxed)),
        ));
        response
    });
    let mut file = file_with_cache(&server, range_cache_in(temp.path(), 1024)).with_content_token(
        ContentToken::HfCommitPath {
            endpoint: "https://huggingface.co".into(),
            repo_kind: "models".into(),
            repo: "org/model".into(),
            commit: "a".repeat(40),
            path: "f".into(),
            size: 16,
        },
    );
    version.store(2, Ordering::Relaxed);
    let mut bytes = [0; 16];
    file.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes.as_slice(), pattern(0, 16));
    assert!(file.source.token(16).is_none());
    assert!(file.complete_file().is_none());
}

/// Regression: sparse TAR header reads fetched 4 MiB per 512-byte header with a strong ETag.
#[test]
fn regression_http_range_cache_small_random_headers_do_not_overfetch() {
    let temp = tempfile::tempdir().unwrap();
    let requested = Arc::new(Mutex::new(Vec::new()));
    let requests = requested.clone();
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            requests.lock().unwrap().push(req.range());
        }
        let mut response = Response::ranged(&req, 32 * HTTP_RANGE_CHUNK);
        response.headers.push(("ETag".into(), "\"v1\"".into()));
        response
    });
    let mut file = file_with_cache(&server, range_cache_in(temp.path(), 64 * HTTP_RANGE_CHUNK));
    for offset in [0, HTTP_RANGE_CHUNK * 3, HTTP_RANGE_CHUNK * 7] {
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut bytes = [0; 512];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), pattern(offset, 512));
    }
    assert_eq!(
        requested.lock().unwrap().as_slice(),
        &[
            (0, 511),
            (HTTP_RANGE_CHUNK * 3, HTTP_RANGE_CHUNK * 3 + 511),
            (HTTP_RANGE_CHUNK * 7, HTTP_RANGE_CHUNK * 7 + 511)
        ]
    );
}

/// Regression: prefetch stopped at cached windows and never scheduled the later cold shard pages.
#[test]
fn regression_http_range_cache_prefetch_skips_cached_windows() {
    let temp = tempfile::tempdir().unwrap();
    let cache = RangeCache::with_dirs(
        temp.path().join("payload-v1/range-v1"),
        temp.path().join("payload-v1"),
        128,
        4,
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let ranges = requests.clone();
    let server = Server::spawn(move |req| {
        if req.method == "GET" {
            ranges.lock().unwrap().push(req.range());
        }
        let mut response = Response::ranged(&req, 12);
        response.headers.push(("ETag".into(), "\"v1\"".into()));
        response
    });
    let file = file_with_cache(&server, cache.clone());
    cache
        .put(&file.source.token(12).unwrap(), 0, &pattern(0, 4))
        .unwrap();
    let budget = Arc::new(PrefetchBudget::new(1));
    let mut prefetch = Prefetch::with_budget(file.source, 0, 12, 8, budget);
    prefetch.fill().unwrap();
    assert_eq!(prefetch.pending.front().unwrap().start, 4);
    let mut bytes = [0; 4];
    assert_eq!(prefetch.read(0, &mut bytes).unwrap(), Some(4));
    assert_eq!(bytes.as_slice(), pattern(0, 4));
    assert_eq!(prefetch.read(4, &mut bytes).unwrap(), Some(4));
    assert_eq!(bytes.as_slice(), pattern(4, 4));
    assert_eq!(requests.lock().unwrap().as_slice(), &[(4, 7)]);
}

/// Regression: an explicit strong ETag also has to match the first GET on an unprobed reader.
#[test]
fn regression_http_range_cache_explicit_strong_etag_mismatch_bypasses() {
    let temp = tempfile::tempdir().unwrap();
    let server = Server::spawn(|req| {
        let mut response = Response::ranged(&req, 16);
        response.headers.push(("ETag".into(), "\"actual\"".into()));
        response
    });
    let source = HttpRangeSource::new(
        HttpLocation {
            url: server.url.clone(),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    )
    .with_range_cache(range_cache_in(temp.path(), 1024))
    .with_content_token(ContentToken::StrongEtag {
        resource: server.url.clone(),
        etag: "\"expected\"".into(),
        size: 16,
    });
    let mut file = HttpRangeFile::from_source(Arc::new(source), 16, None);
    let mut bytes = [0; 16];
    file.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes.as_slice(), pattern(0, 16));
    assert!(file.source.token(16).is_none());
    assert!(file.complete_file().is_none());
}
