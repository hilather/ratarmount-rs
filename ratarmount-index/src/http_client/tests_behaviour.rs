//! Redirect, stale-connection and body-error contracts against bounded loopback servers.

use super::tests::{accept_until, get_request, read_request, response, Captured, Mock, TIMEOUT};
use super::{get, head, post, put, HttpError, HttpResponse, Profile, TransportKind};
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// Engine-specific (2.12.1). S4b flips these and records the flip in its PR (PLAN §2, OQ-15b).
// response.rs:412-415 exposes the close-delimited socket error directly.
// chunked/decoder.rs:170-191 returns Ok(0) mid-chunk, while :54-62 rejects boundary EOF.
const CLOSE_DELIMITED_RST_IS_ERROR: bool = true;
const CHUNKED_FIN_MID_CHUNK_TRUNCATES: bool = true;

struct Server<T: Debug> {
    base: String,
    thread: Option<JoinHandle<io::Result<T>>>,
}

impl<T: Debug + Send + 'static> Server<T> {
    fn spawn(handler: impl FnOnce(&TcpListener) -> io::Result<T> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        Self {
            base,
            thread: Some(thread::spawn(move || handler(&listener))),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn finish(mut self) -> T {
        self.thread
            .take()
            .unwrap()
            .join()
            .expect("server thread panicked")
            .expect("server exchange failed")
    }
}

impl<T: Debug> Drop for Server<T> {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !thread::panicking() {
                result
                    .expect("server thread panicked")
                    .expect("server exchange failed");
            } else if !matches!(result, Ok(Ok(_))) {
                eprintln!("server also failed while unwinding: {result:?}");
            }
        }
    }
}

fn accept(listener: &TcpListener) -> io::Result<TcpStream> {
    let stream = accept_until(listener, Instant::now() + TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}

fn raw_response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status} Mock\r\n").into_bytes();
    for (name, value) in headers {
        bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(body);
    bytes
}

fn reset(stream: TcpStream) -> io::Result<()> {
    socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
    drop(stream);
    Ok(())
}

// A failed write, channel timeout or unwinding must also release the untimed client read.
struct ResetOnDrop(Option<TcpStream>);

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if let Err(error) = reset(self.0.take().unwrap()) {
            if thread::panicking() {
                eprintln!("reset also failed while unwinding: {error}");
            } else {
                panic!("server reset failed: {error}");
            }
        }
    }
}

fn hold_until_peer_gone(mut stream: TcpStream) -> io::Result<()> {
    let deadline = Instant::now() + TIMEOUT;
    let mut bytes = [0; 256];
    while Instant::now() < deadline {
        // Bound the entire hold even if the peer sends unexpected extra bytes.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn assert_no_pending_connection(listener: &TcpListener) -> io::Result<()> {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other("unexpected extra connection")),
    }
}

fn receive<T>(receiver: &mpsc::Receiver<T>) -> io::Result<T> {
    receiver.recv_timeout(TIMEOUT).map_err(io::Error::other)
}

fn io_kind(error: impl Into<HttpError>) -> io::ErrorKind {
    error.into().into_io().kind()
}

fn body(response: HttpResponse) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    response.into_reader().read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn assert_framed_error(error: io::Error) {
    let kind = io_kind(error);
    assert!(
        matches!(
            kind,
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ),
        "framed body error: {kind:?}"
    );
}

fn redirect_chain(hops: usize, final_reply: Vec<u8>) -> Mock {
    let mut replies: Vec<_> = (1..=hops)
        .map(|hop| response(302, &[("Location", &format!("/hop{hop}"))], b""))
        .collect();
    replies.push(final_reply);
    Mock::new(replies)
}

fn assert_transport(error: HttpError, kind: TransportKind, message: &str) {
    let HttpError::Transport(transport) = error else {
        panic!("expected transport error: {error:?}");
    };
    assert_eq!(transport.kind(), kind);
    assert_eq!(transport.message(), Some(message));
}

#[test]
fn contract_redirect_hop_limit() {
    let mock = redirect_chain(4, response(200, &[], b"done"));
    let reply = mock.get("/first").call().unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.get_url(), mock.url("/hop4"));
    assert_eq!(body(reply).unwrap(), b"done");
    assert_eq!(mock.finish().len(), 5);

    // The fifth redirect response is refused before a sixth request can be sent.
    let mock = redirect_chain(4, response(302, &[("Location", "/hop5")], b""));
    assert_transport(
        mock.get("/first").call().unwrap_err(),
        TransportKind::TooManyRedirects,
        "reached max redirects (5)",
    );
    assert_eq!(mock.finish().len(), 5);
}

#[test]
fn contract_redirect_limit_checked_before_location() {
    // unit.rs:165-187 checks the limit even for an otherwise unfollowed status,
    // and before either a missing Location or an invalid URL can take precedence.
    for last in [
        response(304, &[("Location", "/unused")], b""),
        response(302, &[], b""),
        response(300, &[("Location", "http://[::1")], b""),
    ] {
        let mock = redirect_chain(4, last);
        assert_transport(
            mock.get("/first").call().unwrap_err(),
            TransportKind::TooManyRedirects,
            "reached max redirects (5)",
        );
        assert_eq!(mock.finish().len(), 5);
    }
}

#[test]
fn contract_redirect_unfollowed_3xx_returned() {
    for (status, headers) in [
        (300, vec![("Location", "/unused")]),
        (304, vec![("Location", "/unused")]),
        (305, vec![("Location", "/unused")]),
        (302, vec![]),
    ] {
        let mock = Mock::new(vec![response(status, &headers, b"")]);
        let url = mock.url("/first");
        let reply = get_request(Profile::Direct, &url).call().unwrap();
        assert_eq!(reply.status(), status);
        assert_eq!(reply.get_url(), url);
        assert_eq!(reply.header("location"), headers.first().map(|(_, v)| *v));
        assert_eq!(reply.header("connection"), Some("close"));
        assert_eq!(mock.finish().len(), 1);
    }
}

#[test]
fn contract_redirect_bad_location() {
    // unit.rs:183-203 joins Location before dispatching on the redirect status.
    for status in [300, 302] {
        let mock = Mock::new(vec![response(status, &[("Location", "http://[::1")], b"")]);
        assert_transport(
            mock.get("/first").call().unwrap_err(),
            TransportKind::InvalidUrl,
            "Bad redirection: http://[::1",
        );
        assert_eq!(mock.finish().len(), 1);
    }
}

#[test]
fn contract_redirect_307_308_method_rules() {
    for status in [307, 308] {
        for method in ["PUT", "POST"] {
            let mock = Mock::new(vec![response(status, &[("Location", "/unused")], b"")]);
            let reply = mock.request(method, "/first").send_bytes(b"body").unwrap();
            assert_eq!(reply.status(), status);
            assert_eq!(reply.header("location"), Some("/unused"));
            let requests = mock.finish();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].head().starts_with(&format!("{method} /first ")));
            assert_eq!(requests[0].body, b"body");
        }
        for method in ["GET", "HEAD"] {
            let mock = Mock::new(vec![
                response(status, &[("Location", "/next")], b""),
                response(200, &[], b""),
            ]);
            let url = mock.url("/first");
            let req = if method == "HEAD" {
                head(Profile::Direct, &url)
            } else {
                get(Profile::Direct, &url)
            };
            let reply = req.timeout(TIMEOUT).call().unwrap();
            assert_eq!(reply.status(), 200);
            assert_eq!(reply.get_url(), mock.url("/next"));
            let requests = mock.finish();
            assert_eq!(requests.len(), 2);
            for (captured, path) in requests.iter().zip(["/first", "/next"]) {
                assert!(captured
                    .head()
                    .starts_with(&format!("{method} {path} HTTP/1.1\r\n")));
            }
        }
    }
}

#[test]
fn contract_redirect_303_post_becomes_bodiless_get() {
    for (method, status, next_method) in [
        ("POST", 303, "GET"),
        ("PUT", 301, "GET"),
        ("POST", 302, "GET"),
        ("HEAD", 301, "HEAD"),
    ] {
        let mock = Mock::new(vec![
            response(status, &[("Location", "/next")], b""),
            response(200, &[], b""),
        ]);
        let req = mock.request(method, "/first");
        let reply = if method == "HEAD" {
            req.call()
        } else {
            req.send_bytes(b"payload")
        };
        assert_eq!(reply.unwrap().status(), 200);
        let requests = mock.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].head().starts_with(&format!("{method} /first ")));
        assert_eq!(
            requests[0].body,
            if method == "HEAD" {
                &b""[..]
            } else {
                &b"payload"[..]
            }
        );
        assert!(requests[1]
            .head()
            .starts_with(&format!("{next_method} /next HTTP/1.1\r\n")));
        assert!(requests[1].body.is_empty());
        assert_eq!(requests[1].header("content-length"), None);
        assert_eq!(requests[1].header("transfer-encoding"), None);
    }
}

#[test]
fn contract_redirect_strips_credentials_and_length() {
    // unit.rs:219-225 and :387-388 strip credentials even on the same origin.
    let mock = Mock::new(vec![
        response(302, &[("Location", "/same-origin")], b""),
        response(200, &[], b""),
    ]);
    mock.get("/first")
        .set("Authorization", "Bearer private")
        .set("Cookie", "session=private")
        .set("X-Keep-Me", "Byte-Exact")
        .call()
        .unwrap();
    let requests = mock.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].all("authorization"), ["Bearer private"]);
    assert_eq!(requests[0].all("cookie"), ["session=private"]);
    assert!(requests[1].all("authorization").is_empty());
    assert!(requests[1].all("cookie").is_empty());
    assert!(requests[1].has_raw_line("X-Keep-Me: Byte-Exact"));

    let mock = Mock::new(vec![
        response(301, &[("Location", "/next")], b""),
        response(200, &[], b""),
    ]);
    put(Profile::Direct, &mock.url("/first"))
        .timeout(TIMEOUT)
        .set("Content-Length", "4")
        .send_reader(&b"body"[..])
        .unwrap();
    let requests = mock.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].header("content-length"), Some("4"));
    assert_eq!(requests[0].body, b"body");
    assert!(requests[1].head().starts_with("GET /next HTTP/1.1\r\n"));
    assert_eq!(requests[1].header("content-length"), None);
    assert!(requests[1].body.is_empty());
}

#[test]
fn contract_redirect_status_display_multi_hop() {
    // error.rs:215 uses the first history entry, rather than the preceding hop.
    for (hops, status, payload) in [(2, 404, &b"missing"[..]), (1, 401, &b"denied"[..])] {
        let mock = redirect_chain(hops, response(status, &[], payload));
        let first = mock.url("/first");
        let final_url = mock.url(&format!("/hop{hops}"));
        let error = get_request(Profile::Direct, &first).call().unwrap_err();
        let expected = if status == 404 {
            format!("{final_url}: status code 404 (redirected from {first})")
        } else {
            format!("{final_url}: status code 401 (redirected from {first})")
        };
        assert_eq!(error.to_string(), expected);
        let HttpError::Status(code, reply) = error else {
            panic!("expected readable Status response");
        };
        assert_eq!(code, status);
        assert_eq!(reply.status(), status);
        assert_eq!(reply.get_url(), final_url);
        assert_eq!(body(reply).unwrap(), payload);
        assert_eq!(mock.finish().len(), hops + 1);
    }
}

#[test]
fn contract_pooled_probe_3xx_passthrough() {
    for profile in [Profile::Pooled, Profile::Probe { timeout: TIMEOUT }] {
        for status in [300, 301, 303, 307, 308] {
            let mock = Mock::new(vec![response(status, &[("Location", "/elsewhere")], b"")]);
            let url = mock.url("/first");
            let reply = get_request(profile, &url).call().unwrap();
            assert_eq!(reply.status(), status);
            assert_eq!(reply.get_url(), url);
            assert_eq!(reply.header("location"), Some("/elsewhere"));
            assert_eq!(mock.finish().len(), 1);
        }
    }
    let mock = Mock::new(vec![response(303, &[("Location", "/elsewhere")], b"")]);
    let url = mock.url("/first");
    let reply = post(Profile::Pooled, &url)
        .timeout(TIMEOUT)
        .send_bytes(b"payload")
        .unwrap();
    assert_eq!(reply.status(), 303);
    assert_eq!(reply.get_url(), url);
    assert_eq!(reply.header("location"), Some("/elsewhere"));
    let requests = mock.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].head().starts_with("POST /first HTTP/1.1\r\n"));
    assert_eq!(requests[0].body, b"payload");
}

#[derive(Clone, Copy)]
enum Stale {
    Get,
    Post,
    Deadline,
}

fn stale_server(mode: Stale) -> (Server<Vec<Vec<Captured>>>, mpsc::Sender<()>) {
    let (done, completed) = mpsc::channel();
    let server = Server::spawn(move |listener| {
        let mut a = accept(listener)?;
        let first = read_request(&mut a)?;
        a.write_all(&raw_response(200, &[("Content-Length", "3")], b"one"))?;
        // Keep A live until request #2 defeats the idle-socket peek (stream.rs:223-240).
        let second = read_request(&mut a)?;
        if matches!(mode, Stale::Deadline) {
            thread::sleep(Duration::from_millis(1200));
        }
        drop(a);
        let mut requests = vec![vec![first, second]];
        if !matches!(mode, Stale::Post) {
            let mut b = accept(listener)?;
            requests.push(vec![read_request(&mut b)?]);
            if matches!(mode, Stale::Deadline) {
                hold_until_peer_gone(b)?;
            } else {
                b.write_all(&response(200, &[], b"two"))?;
            }
        }
        // Once the call has returned, any forbidden retry has already connected.
        receive(&completed)?;
        assert_no_pending_connection(listener)?;
        Ok(requests)
    });
    (server, done)
}

fn prime_pool(server: &Server<Vec<Vec<Captured>>>) {
    // Reading the last length-delimited byte returns A to the pool (response.rs:876-879).
    assert_eq!(
        get_request(Profile::Pooled, &server.url("/one"))
            .call()
            .unwrap()
            .into_string()
            .unwrap(),
        "one"
    );
}

fn assert_stale_gets(requests: &[Vec<Captured>]) {
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].len(), 2);
    assert_eq!(requests[1].len(), 1);
    assert!(requests[0][0].head().starts_with("GET /one HTTP/1.1\r\n"));
    let line = "GET /two HTTP/1.1\r\n";
    assert_eq!(
        requests[0][1].head().lines().next(),
        requests[1][0].head().lines().next()
    );
    assert!(requests[0][1].head().starts_with(line));
    assert!(requests[1][0].head().starts_with(line));
}

#[test]
fn contract_pooled_stale_get_retried() {
    let (server, done) = stale_server(Stale::Get);
    prime_pool(&server);
    let result = get_request(Profile::Pooled, &server.url("/two"))
        .call()
        .unwrap()
        .into_string();
    done.send(()).unwrap();
    let requests = server.finish();
    assert_eq!(result.unwrap(), "two");
    assert_stale_gets(&requests);
}

#[test]
fn contract_pooled_stale_bodied_post_not_replayed() {
    // unit.rs:132-150 excludes both this method and its nonempty body from replay.
    let (server, done) = stale_server(Stale::Post);
    prime_pool(&server);
    let result = post(Profile::Pooled, &server.url("/two"))
        .timeout(TIMEOUT)
        .send_bytes(b"payload");
    done.send(()).unwrap();
    let requests = server.finish();
    let error = result.unwrap_err();
    assert!(matches!(&error, HttpError::Transport(_)));
    assert!(matches!(
        io_kind(error),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
    ));
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].len(), 2);
    assert!(requests[0][0].head().starts_with("GET /one HTTP/1.1\r\n"));
    assert!(requests[0][1].head().starts_with("POST /two HTTP/1.1\r\n"));
    assert_eq!(requests[0][1].body, b"payload");
}

#[test]
fn contract_pooled_stale_retry_shares_deadline() {
    // unit.rs:304 reuses the same Unit/deadline, leaving only 0.8 s after A closes.
    let (server, done) = stale_server(Stale::Deadline);
    prime_pool(&server);
    let start = Instant::now();
    let result = get(Profile::Pooled, &server.url("/two"))
        .timeout(Duration::from_secs(2))
        .call();
    let elapsed = start.elapsed();
    eprintln!("P3 shared deadline: {elapsed:?}");
    done.send(()).unwrap();
    let requests = server.finish();
    assert_eq!(io_kind(result.unwrap_err()), io::ErrorKind::TimedOut);
    assert!(
        (Duration::from_millis(1900)..Duration::from_millis(2900)).contains(&elapsed),
        "shared deadline: {elapsed:?}"
    );
    assert_stale_gets(&requests);
}

#[test]
fn contract_slow_body_timed_out() {
    for profile in [Profile::Direct, Profile::Pooled] {
        let server = Server::spawn(|listener| {
            let mut stream = accept(listener)?;
            let captured = read_request(&mut stream)?;
            stream.write_all(&response(200, &[("Content-Length", "10")], b"abc"))?;
            hold_until_peer_gone(stream)?;
            Ok(captured)
        });
        let start = Instant::now();
        let reply = get(profile, &server.url("/slow"))
            .timeout(Duration::from_millis(500))
            .call()
            .unwrap();
        assert_eq!(reply.status(), 200);
        let error = body(reply).unwrap_err();
        let elapsed = start.elapsed();
        eprintln!("B1 {profile:?} body deadline: {elapsed:?}");
        server.finish();
        assert_eq!(io_kind(error), io::ErrorKind::TimedOut);
        assert!(
            (Duration::from_millis(400)..TIMEOUT).contains(&elapsed),
            "slow body: {elapsed:?}"
        );
    }
}

fn reset_body(
    headers: &[(&str, &str)],
    partial: &[u8],
    decoded_prefix: &[u8],
) -> (io::Result<usize>, Vec<u8>) {
    let reply = raw_response(200, headers, partial);
    let (read, partial_read) = mpsc::channel();
    let server = Server::spawn(move |listener| {
        let mut guard = ResetOnDrop(Some(accept(listener)?));
        let stream = guard.0.as_mut().unwrap();
        let captured = read_request(stream)?;
        stream.write_all(&reply)?;
        receive(&partial_read)?;
        // Drop the guard before returning, also on every error/timeout path above.
        drop(guard);
        Ok(captured)
    });
    // No deadline: avoids post-reset timeout setters on closed sockets (D4,
    // request.rs:122-124 and stream.rs:83-90). The guard bounds all exits instead.
    let reply = get(Profile::Direct, &server.url("/reset")).call().unwrap();
    assert_eq!(reply.status(), 200);
    let mut reader = reply.into_reader();
    let mut bytes = vec![0; decoded_prefix.len()];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, decoded_prefix);
    read.send(()).unwrap();
    let result = reader.read_to_end(&mut bytes);
    drop(reader);
    server.finish();
    (result, bytes)
}

#[test]
fn contract_framed_body_premature_close() {
    // response.rs:865-883 distinguishes an incomplete length from a successful EOF.
    let mock = Mock::new(vec![response(200, &[("Content-Length", "10")], b"abcd")]);
    let error = body(mock.get("/fin").call().unwrap()).unwrap_err();
    eprintln!("B2 length + FIN: {:?}", error.kind());
    assert_framed_error(error);
    assert_eq!(mock.finish().len(), 1);
    for (label, headers, partial) in [
        ("length", vec![("Content-Length", "10")], &b"abcd"[..]),
        (
            "chunked",
            vec![("Transfer-Encoding", "chunked")],
            &b"a\r\nabcd"[..],
        ),
    ] {
        let (result, bytes) = reset_body(&headers, partial, b"abcd");
        let error = result.unwrap_err();
        eprintln!("B2 {label} + RST: {:?}", error.kind());
        assert_framed_error(error);
        assert_eq!(bytes, b"abcd");
    }
}

// Stored DEFLATE blocks keep the fixture portable and make a half-body reset meaningful.
// The complete fixture is decoded through the facade before either damaged variant is used.
fn gzip_fixture() -> (Vec<u8>, Vec<u8>) {
    let mut state = 0x1234_5678_u32;
    let plain: Vec<u8> = (0..128 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    let mut chunks = plain.chunks(u16::MAX as usize).peekable();
    while let Some(chunk) = chunks.next() {
        gzip.push(u8::from(chunks.peek().is_none()));
        let length = chunk.len() as u16;
        gzip.extend_from_slice(&length.to_le_bytes());
        gzip.extend_from_slice(&(!length).to_le_bytes());
        gzip.extend_from_slice(chunk);
    }
    let mut crc = !0_u32;
    for byte in &plain {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    gzip.extend_from_slice(&(!crc).to_le_bytes());
    gzip.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    (plain, gzip)
}

fn assert_complete_gzip(plain: &[u8], gzip: &[u8]) {
    let mock = Mock::new(vec![response(200, &[("Content-Encoding", "gzip")], gzip)]);
    assert_eq!(body(mock.get("/complete").call().unwrap()).unwrap(), plain);
    assert_eq!(mock.finish().len(), 1);
}

#[test]
fn contract_truncated_gzip_errors() {
    let (plain, gzip) = gzip_fixture();
    assert_complete_gzip(&plain, &gzip);
    // Remove the trailer AND stored deflate data, but complete the HTTP framing.
    let cut = &gzip[..gzip.len() - 8 - 37];
    for encoding in ["gzip", "x-gzip"] {
        let mock = Mock::new(vec![response(200, &[("Content-Encoding", encoding)], cut)]);
        let error = body(mock.get("/truncated").call().unwrap()).unwrap_err();
        // Observed on 2.12.1: UnexpectedEof from the decoder (response.rs:664-672).
        eprintln!("G1 {encoding}: {:?}", error.kind());
        assert_eq!(mock.finish().len(), 1);
    }
}

#[test]
fn contract_reset_during_gzip_errors() {
    let (plain, gzip) = gzip_fixture();
    assert_complete_gzip(&plain, &gzip);
    let length = gzip.len().to_string();
    let (result, bytes) = reset_body(
        &[("Content-Encoding", "gzip"), ("Content-Length", &length)],
        &gzip[..gzip.len() / 2],
        &plain[..1024],
    );
    let error = result.unwrap_err();
    eprintln!("G2 gzip + RST: {:?}", error.kind());
    assert_framed_error(error);
    assert!(bytes.len() < plain.len());
    assert_eq!(bytes, plain[..bytes.len()]);
}

#[test]
fn contract_engine_close_delimited_rst() {
    let headers = [("Connection", "close")];
    let mock = Mock::new(vec![raw_response(200, &headers, b"abcd")]);
    assert_eq!(body(mock.get("/fin").call().unwrap()).unwrap(), b"abcd");
    assert_eq!(mock.finish().len(), 1);
    let (result, bytes) = reset_body(&headers, b"abcd", b"abcd");
    if CLOSE_DELIMITED_RST_IS_ERROR {
        let error = result.unwrap_err();
        eprintln!("E1 close-delimited + RST: {:?}", error.kind());
        assert!(matches!(
            io_kind(error),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
        ));
    } else {
        result.unwrap();
    }
    assert_eq!(bytes, b"abcd");
}

#[test]
fn contract_engine_chunked_fin() {
    let headers = [("Transfer-Encoding", "chunked"), ("Connection", "close")];
    let mock = Mock::new(vec![
        raw_response(200, &headers, b"a\r\nabcd"),
        raw_response(200, &headers, b"4\r\nabcd\r\n"),
    ]);
    let mid_chunk = body(mock.get("/mid-chunk").call().unwrap());
    if CHUNKED_FIN_MID_CHUNK_TRUNCATES {
        assert_eq!(mid_chunk.unwrap(), b"abcd");
        eprintln!("E2 FIN mid-chunk: Ok(4), truncated");
    } else {
        assert_framed_error(mid_chunk.unwrap_err());
    }
    let error = body(mock.get("/boundary").call().unwrap()).unwrap_err();
    eprintln!("E2 FIN at chunk boundary: {:?}", error.kind());
    if CHUNKED_FIN_MID_CHUNK_TRUNCATES {
        assert_eq!(io_kind(error), io::ErrorKind::InvalidInput);
    }
    assert_eq!(mock.finish().len(), 2);
}
