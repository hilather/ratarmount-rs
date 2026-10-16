//! Bounded HTTP/1.1 POST framing. Each connection gets one response and closes.
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;

fn line(reader: &mut impl BufRead, budget: &mut usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take((*budget + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "cannot read HTTP headers")?;
    if bytes.len() > *budget || !bytes.ends_with(b"\r\n") {
        return Err("invalid or oversized HTTP headers".into());
    }
    *budget -= bytes.len();
    bytes.truncate(bytes.len() - 2);
    Ok(bytes)
}

fn request(reader: &mut impl BufRead) -> Result<(String, Vec<u8>), String> {
    let mut budget = MAX_HEADER;
    let first = line(reader, &mut budget)?;
    let first = std::str::from_utf8(&first).map_err(|_| "invalid HTTP request line")?;
    let parts: Vec<_> = first.split(' ').collect();
    if parts.len() != 3 || parts[0] != "POST" || !["HTTP/1.1", "HTTP/1.0"].contains(&parts[2]) {
        return Err("expected HTTP POST".into());
    }
    let endpoint = parts[1].to_owned();
    let mut length = None;
    let mut chunked = false;
    loop {
        let header = line(reader, &mut budget)?;
        if header.is_empty() {
            break;
        }
        let header = std::str::from_utf8(&header).map_err(|_| "invalid HTTP header")?;
        let (name, value) = header.split_once(':').ok_or("invalid HTTP header")?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("duplicate Content-Length".into());
            }
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid Content-Length".into());
            }
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "invalid Content-Length")?,
            );
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                return Err("unsupported Transfer-Encoding".into());
            }
            chunked = true;
        }
        if name.eq_ignore_ascii_case("expect") {
            return Err("Expect is unsupported".into());
        }
    }
    if chunked && length.is_some() {
        return Err("ambiguous HTTP body framing".into());
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let size_line = line(reader, &mut budget)?;
            let size_str = std::str::from_utf8(&size_line).map_err(|_| "invalid chunk size")?;
            let size = usize::from_str_radix(size_str.split(';').next().unwrap_or_default(), 16)
                .map_err(|_| "invalid chunk size")?;
            if size > MAX_BODY - body.len() {
                return Err("HTTP body too large".into());
            }
            if size == 0 {
                while !line(reader, &mut budget)?.is_empty() {}
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader
                .read_exact(&mut body[start..])
                .map_err(|_| "truncated HTTP body")?;
            let mut end = [0; 2];
            reader
                .read_exact(&mut end)
                .map_err(|_| "truncated HTTP chunk")?;
            if end != *b"\r\n" {
                return Err("invalid chunk terminator".into());
            }
        }
    } else {
        let size = length.unwrap_or(0);
        if size > MAX_BODY {
            return Err("HTTP body too large".into());
        }
        body.resize(size, 0);
        reader
            .read_exact(&mut body)
            .map_err(|_| "truncated HTTP body")?;
    }
    Ok((endpoint, body))
}

/// The same framing entry point is used by the server and fake-mounter tests.
pub fn serve_one(
    stream: &mut (impl Read + Write),
    handler: impl FnOnce(&str, &[u8]) -> Value,
) -> io::Result<()> {
    let response = match request(&mut BufReader::new(&mut *stream)) {
        Ok((endpoint, body)) => handler(&endpoint, &body),
        Err(error) => json!({"Err": error}),
    };
    let bytes = serde_json::to_vec(&response)?;
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

pub fn serve_stream(
    mut stream: UnixStream,
    handler: impl FnOnce(&str, &[u8]) -> Value,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    serve_one(&mut stream, handler)
}
