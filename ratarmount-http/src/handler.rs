//! One GET/HEAD per connection: lookup, directory HTML, file `fill_read`.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use ratarmount_core::{is_dir_mode, CheapDirent, FileInfo, MountSource};
use ratarmount_export_core::fill_read;

use crate::request::{
    archive_path, last_modified_header, parse_request, resolve_range, Method, PathError,
    ResolvedRange,
};

pub(crate) struct HttpState {
    pub source: Arc<dyn MountSource>,
    pub chunk: usize,
}

pub(crate) fn handle_connection(mut stream: TcpStream, state: &HttpState) -> io::Result<()> {
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            return write_response(
                &mut stream,
                405,
                "Method Not Allowed",
                "text/plain; charset=utf-8",
                b"method not allowed\n",
                true,
                &[("Allow", "GET, HEAD")],
            );
        }
        Err(e)
            if e.kind() == io::ErrorKind::InvalidInput
                || e.kind() == io::ErrorKind::InvalidData =>
        {
            return write_response(
                &mut stream,
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                b"bad request\n",
                true,
                &[],
            );
        }
        Err(e) => return Err(e),
    };

    let send_body = req.method != Method::Head;

    let path = match archive_path(&req.path) {
        Ok(p) => p,
        Err(PathError::Escape) => {
            return write_response(
                &mut stream,
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                b"path escape\n",
                send_body,
                &[],
            );
        }
        Err(PathError::BadRequest) => {
            return write_response(
                &mut stream,
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                b"bad path\n",
                send_body,
                &[],
            );
        }
    };

    let Some(fi) = state.source.lookup(&path, 0) else {
        return write_response(
            &mut stream,
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            b"not found\n",
            send_body,
            &[],
        );
    };

    if is_dir_mode(fi.mode) {
        return handle_dir(&mut stream, state, &path, !send_body);
    }

    handle_file(
        &mut stream,
        state,
        &fi,
        req.method == Method::Head,
        req.range.as_deref(),
    )
}

fn read_request(stream: &mut TcpStream) -> io::Result<crate::request::HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        if buf.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request headers too large",
            ));
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = crate::request::headers_end(&buf) {
            return parse_request(&buf[..end]);
        }
    }
}

fn handle_dir(stream: &mut TcpStream, state: &HttpState, path: &str, head: bool) -> io::Result<()> {
    let dents = state.source.list_dirents(path).unwrap_or_default();
    let body = dir_listing_html(path, &dents);
    write_response(
        stream,
        200,
        "OK",
        "text/html; charset=utf-8",
        body.as_bytes(),
        !head,
        &[],
    )
}

fn dir_listing_html(path: &str, dents: &[CheapDirent]) -> String {
    let title = html_escape(path);
    let mut s = String::new();
    s.push_str("<!DOCTYPE html>\n<html><head><title>Index of ");
    s.push_str(&title);
    s.push_str("</title></head><body>\n<h1>Index of ");
    s.push_str(&title);
    s.push_str("</h1>\n<ul>\n");
    for d in dents {
        let name = html_escape(&d.name);
        let href = child_href(path, &d.name, is_dir_mode(d.mode));
        s.push_str("<li><a href=\"");
        s.push_str(&href);
        s.push_str("\">");
        s.push_str(&name);
        s.push_str("</a> ");
        s.push_str(&d.size.to_string());
        s.push(' ');
        s.push_str(&format!("{:o}", d.mode));
        s.push_str("</li>\n");
    }
    s.push_str("</ul>\n</body></html>\n");
    s
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Path-absolute href so `GET /sub` (no trailing slash) still links to `/sub/child.txt`.
/// Directory entries get a trailing `/` so a later relative browse stays under that dir.
fn child_href(parent: &str, name: &str, is_dir: bool) -> String {
    let mut href = String::from("/");
    if parent != "/" {
        for seg in parent.trim_start_matches('/').split('/') {
            if seg.is_empty() {
                continue;
            }
            href.push_str(&percent_encode_segment(seg));
            href.push('/');
        }
    }
    href.push_str(&percent_encode_segment(name));
    if is_dir && !href.ends_with('/') {
        href.push('/');
    }
    href
}

fn percent_encode_segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn handle_file(
    stream: &mut TcpStream,
    state: &HttpState,
    fi: &FileInfo,
    head: bool,
    range_header: Option<&str>,
) -> io::Result<()> {
    let resolved = resolve_range(range_header, fi.size);
    let (status, reason, start, content_len, content_range) = match resolved {
        ResolvedRange::Full => (200u16, "OK", 0u64, fi.size, None),
        ResolvedRange::Partial { start, end } => {
            let len = end.saturating_sub(start).saturating_add(1);
            let cr = format!("bytes {start}-{end}/{}", fi.size);
            (206, "Partial Content", start, len, Some(cr))
        }
        ResolvedRange::Unsatisfiable => {
            let cr = format!("bytes */{}", fi.size);
            return write_response(
                stream,
                416,
                "Range Not Satisfiable",
                "application/octet-stream",
                b"",
                !head,
                &[("Accept-Ranges", "bytes"), ("Content-Range", cr.as_str())],
            );
        }
    };

    let mut lines: Vec<String> = vec![
        format!("HTTP/1.1 {status} {reason}"),
        "Connection: close".into(),
        "Accept-Ranges: bytes".into(),
        "Content-Type: application/octet-stream".into(),
        format!("Content-Length: {content_len}"),
    ];
    if let Some(cr) = content_range {
        lines.push(format!("Content-Range: {cr}"));
    }
    if let Some(lm) = last_modified_header(fi.mtime) {
        lines.push(format!("Last-Modified: {lm}"));
    }
    let mut head_bytes = lines.join("\r\n");
    head_bytes.push_str("\r\n\r\n");
    stream.write_all(head_bytes.as_bytes())?;

    if head || content_len == 0 {
        return Ok(());
    }

    // One `open` + `fill_read` for this GET (including Range). Do not reopen
    // per chunk: gzip short `Read::read` is not EOF.
    let mut reader = state.source.open(fi, 0)?;
    if start > 0 {
        reader.seek(SeekFrom::Start(start))?;
    }
    let mut remaining = content_len;
    let chunk = state.chunk.max(1);
    let mut buf = vec![0u8; chunk];
    while remaining > 0 {
        let want = (remaining as usize).min(buf.len());
        let n = fill_read(reader.as_mut(), &mut buf[..want])?;
        if n == 0 {
            break;
        }
        stream.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    send_body: bool,
    extra: &[(&str, &str)],
) -> io::Result<()> {
    let mut s = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    stream.write_all(s.as_bytes())?;
    if send_body {
        stream.write_all(body)?;
    }
    Ok(())
}
