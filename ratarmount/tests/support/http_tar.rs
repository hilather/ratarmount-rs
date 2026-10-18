//! Shared test HTTP server (one small tar, Range support).

/// A tiny HTTP stub serving one small tar with Range support; returns the base URL
/// (`http://127.0.0.1:PORT`). Serves until the test process exits.
pub fn serve_tar_stub() -> String {
    serve_tar_stub_forbidding(None)
}

/// [`serve_tar_stub`] that answers `403 Forbidden` while `forbid` exists, so a
/// test can expire the "signed URL" mid-run by creating that file.
pub fn serve_tar_stub_forbidding(forbid: Option<std::path::PathBuf>) -> String {
    use std::io::{BufRead, BufReader, Write};
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(5);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "a.txt", &b"hello"[..])
        .unwrap();
    let body = builder.into_inner().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut socket) = stream else { continue };
            let body = body.clone();
            let forbid = forbid.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut first = String::new();
                if reader.read_line(&mut first).unwrap_or(0) == 0 {
                    return;
                }
                let mut range = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        let v = v.trim();
                        let (a, b) = v.split_once('-').unwrap();
                        let a: usize = a.parse().unwrap_or(0);
                        let b: usize = b.parse().unwrap_or(body.len() - 1);
                        range = Some((a, b.min(body.len() - 1)));
                    }
                }
                if forbid.as_ref().is_some_and(|f| f.exists()) {
                    let _ = socket.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    return;
                }
                let head = first.starts_with("HEAD ");
                let (status, slice, extra) = match range {
                    Some((a, b)) if a < body.len() => (
                        "206 Partial Content",
                        &body[a..=b],
                        format!("Content-Range: bytes {a}-{b}/{}\r\n", body.len()),
                    ),
                    _ => ("200 OK", &body[..], String::new()),
                };
                let _ = write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nETag: \"v1\"\r\n{extra}Connection: close\r\n\r\n",
                    slice.len()
                );
                if !head {
                    let _ = socket.write_all(slice);
                }
            });
        }
    });
    base
}
