//! One request per connection: GET/HEAD Range, optional WebDAV.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{is_dir_mode, CheapDirent, FileInfo, MountSource};
use ratarmount_export_core::fill_read;

use crate::request::{
    archive_path, last_modified_header, parse_request, percent_encode_segment, resolve_range,
    HttpRequest, Method, PathError, ResolvedRange,
};
use crate::webdav::{
    delete_overlay, destination_archive_path, drain_body, mkcol_overlay, move_overlay,
    overlay_status, parent_is_dir, parse_depth, propfind_multistatus, put_overlay, PropfindDepth,
    MAX_PUT_BYTES,
};

pub(crate) struct HttpState {
    pub source: Arc<dyn MountSource>,
    pub chunk: usize,
    pub overlay: Option<Arc<WriteOverlay>>,
    pub webdav: bool,
}

fn allow_list(webdav: bool) -> &'static str {
    if webdav {
        "OPTIONS, GET, HEAD, PROPFIND, PUT, DELETE, MKCOL, MOVE"
    } else {
        "GET, HEAD"
    }
}

pub(crate) fn handle_connection(mut stream: TcpStream, state: &HttpState) -> io::Result<()> {
    let (req, leftover) = match read_request(&mut stream) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            return write_response(
                &mut stream,
                405,
                "Method Not Allowed",
                "text/plain; charset=utf-8",
                b"method not allowed\n",
                true,
                &[("Allow", allow_list(state.webdav))],
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

    if state.webdav && req.method == Method::Options {
        let _ = drain_body(&mut stream, &leftover, req.content_length.unwrap_or(0));
        return write_response(
            &mut stream,
            200,
            "OK",
            "text/plain; charset=utf-8",
            b"",
            false,
            &[("Allow", allow_list(true)), ("DAV", "1")],
        );
    }

    if !state.webdav && !matches!(req.method, Method::Get | Method::Head) {
        return write_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"method not allowed\n",
            true,
            &[("Allow", allow_list(false))],
        );
    }

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

    match req.method {
        Method::Get | Method::Head => {
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
        Method::Propfind => handle_propfind(&mut stream, state, &req, &path, &leftover),
        Method::Put => handle_put(&mut stream, state, &req, &path, leftover),
        Method::Delete => handle_delete(&mut stream, state, &req, &path, &leftover),
        Method::Mkcol => handle_mkcol(&mut stream, state, &req, &path, &leftover),
        Method::Move => handle_move(&mut stream, state, &req, &path, &leftover),
        Method::Options => unreachable!("OPTIONS handled before path parse"),
    }
}

fn overlay_or_403<'a>(
    stream: &mut TcpStream,
    state: &'a HttpState,
) -> io::Result<Option<&'a WriteOverlay>> {
    match state.overlay.as_deref() {
        Some(ov) => Ok(Some(ov)),
        None => {
            write_response(
                stream,
                403,
                "Forbidden",
                "text/plain; charset=utf-8",
                b"read-only (need overlay / -w)\n",
                true,
                &[("DAV", "1")],
            )?;
            Ok(None)
        }
    }
}

fn handle_propfind(
    stream: &mut TcpStream,
    state: &HttpState,
    req: &HttpRequest,
    path: &str,
    leftover: &[u8],
) -> io::Result<()> {
    let _ = drain_body(stream, leftover, req.content_length.unwrap_or(0));
    match parse_depth(req.depth.as_deref()) {
        PropfindDepth::ForbiddenInfinity => write_response(
            stream,
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"Depth infinity is not supported\n",
            true,
            &[("DAV", "1")],
        ),
        depth => {
            let Some(fi) = state.source.lookup(path, 0) else {
                return write_response(
                    stream,
                    404,
                    "Not Found",
                    "text/plain; charset=utf-8",
                    b"not found\n",
                    true,
                    &[("DAV", "1")],
                );
            };
            let body = propfind_multistatus(state.source.as_ref(), path, &fi, depth);
            write_response(
                stream,
                207,
                "Multi-Status",
                "application/xml; charset=utf-8",
                body.as_bytes(),
                true,
                &[("DAV", "1")],
            )
        }
    }
}

fn handle_put(
    stream: &mut TcpStream,
    state: &HttpState,
    req: &HttpRequest,
    path: &str,
    leftover: Vec<u8>,
) -> io::Result<()> {
    let Some(ov) = overlay_or_403(stream, state)? else {
        return Ok(());
    };
    if path == "/" {
        return write_response(
            stream,
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"cannot PUT root\n",
            true,
            &[("DAV", "1")],
        );
    }
    if let Some(fi) = state.source.lookup(path, 0) {
        if is_dir_mode(fi.mode) {
            return write_response(
                stream,
                405,
                "Method Not Allowed",
                "text/plain; charset=utf-8",
                b"PUT on collection\n",
                true,
                &[("Allow", allow_list(true)), ("DAV", "1")],
            );
        }
    }
    if !parent_is_dir(state.source.as_ref(), path) {
        return write_response(
            stream,
            409,
            "Conflict",
            "text/plain; charset=utf-8",
            b"parent missing\n",
            true,
            &[("DAV", "1")],
        );
    }
    let Some(len) = req.content_length else {
        return write_response(
            stream,
            411,
            "Length Required",
            "text/plain; charset=utf-8",
            b"Content-Length required\n",
            true,
            &[("DAV", "1")],
        );
    };
    if len > MAX_PUT_BYTES {
        return write_response(
            stream,
            413,
            "Payload Too Large",
            "text/plain; charset=utf-8",
            b"PUT too large\n",
            true,
            &[("DAV", "1")],
        );
    }
    match put_overlay(ov, path, stream, &leftover, len) {
        Ok(existed) => {
            let (status, reason) = if existed {
                (204u16, "No Content")
            } else {
                (201, "Created")
            };
            write_response(
                stream,
                status,
                reason,
                "text/plain; charset=utf-8",
                b"",
                false,
                &[("DAV", "1")],
            )
        }
        Err(e) => {
            let (status, reason) = overlay_status(&e);
            write_response(
                stream,
                status,
                reason,
                "text/plain; charset=utf-8",
                b"put failed\n",
                true,
                &[("DAV", "1")],
            )
        }
    }
}

fn handle_delete(
    stream: &mut TcpStream,
    state: &HttpState,
    req: &HttpRequest,
    path: &str,
    leftover: &[u8],
) -> io::Result<()> {
    let _ = drain_body(stream, leftover, req.content_length.unwrap_or(0));
    let Some(ov) = overlay_or_403(stream, state)? else {
        return Ok(());
    };
    if path == "/" {
        return write_response(
            stream,
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"cannot DELETE root\n",
            true,
            &[("DAV", "1")],
        );
    }
    if state.source.lookup(path, 0).is_none() {
        return write_response(
            stream,
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            b"not found\n",
            true,
            &[("DAV", "1")],
        );
    }
    match delete_overlay(ov, path) {
        Ok(()) => write_response(
            stream,
            204,
            "No Content",
            "text/plain; charset=utf-8",
            b"",
            false,
            &[("DAV", "1")],
        ),
        Err(e) => {
            let (status, reason) = overlay_status(&e);
            write_response(
                stream,
                status,
                reason,
                "text/plain; charset=utf-8",
                b"delete failed\n",
                true,
                &[("DAV", "1")],
            )
        }
    }
}

fn handle_mkcol(
    stream: &mut TcpStream,
    state: &HttpState,
    req: &HttpRequest,
    path: &str,
    leftover: &[u8],
) -> io::Result<()> {
    let _ = drain_body(stream, leftover, req.content_length.unwrap_or(0));
    let Some(ov) = overlay_or_403(stream, state)? else {
        return Ok(());
    };
    if path == "/" {
        return write_response(
            stream,
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"MKCOL root\n",
            true,
            &[("Allow", allow_list(true)), ("DAV", "1")],
        );
    }
    if req.content_length.unwrap_or(0) > 0 {
        // RFC 4918: MKCOL with a body we do not understand.
        return write_response(
            stream,
            415,
            "Unsupported Media Type",
            "text/plain; charset=utf-8",
            b"MKCOL body not supported\n",
            true,
            &[("DAV", "1")],
        );
    }
    if state.source.lookup(path, 0).is_some() {
        return write_response(
            stream,
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"MKCOL exists\n",
            true,
            &[("Allow", allow_list(true)), ("DAV", "1")],
        );
    }
    if !parent_is_dir(state.source.as_ref(), path) {
        return write_response(
            stream,
            409,
            "Conflict",
            "text/plain; charset=utf-8",
            b"parent missing\n",
            true,
            &[("DAV", "1")],
        );
    }
    match mkcol_overlay(ov, path) {
        Ok(()) => write_response(
            stream,
            201,
            "Created",
            "text/plain; charset=utf-8",
            b"",
            false,
            &[("DAV", "1")],
        ),
        Err(e) => {
            let (status, reason) = overlay_status(&e);
            write_response(
                stream,
                status,
                reason,
                "text/plain; charset=utf-8",
                b"mkcol failed\n",
                true,
                &[("DAV", "1")],
            )
        }
    }
}

fn handle_move(
    stream: &mut TcpStream,
    state: &HttpState,
    req: &HttpRequest,
    path: &str,
    leftover: &[u8],
) -> io::Result<()> {
    let _ = drain_body(stream, leftover, req.content_length.unwrap_or(0));
    let Some(ov) = overlay_or_403(stream, state)? else {
        return Ok(());
    };
    let Some(dest_raw) = req.destination.as_deref() else {
        return write_response(
            stream,
            400,
            "Bad Request",
            "text/plain; charset=utf-8",
            b"Destination required\n",
            true,
            &[("DAV", "1")],
        );
    };
    let dest = match destination_archive_path(dest_raw) {
        Ok(p) => p,
        Err(PathError::Escape) => {
            return write_response(
                stream,
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                b"path escape\n",
                true,
                &[("DAV", "1")],
            );
        }
        Err(PathError::BadRequest) => {
            return write_response(
                stream,
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                b"bad Destination\n",
                true,
                &[("DAV", "1")],
            );
        }
    };
    if path == "/" || dest == "/" || path == dest {
        return write_response(
            stream,
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"invalid MOVE paths\n",
            true,
            &[("DAV", "1")],
        );
    }
    if state.source.lookup(path, 0).is_none() {
        return write_response(
            stream,
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            b"not found\n",
            true,
            &[("DAV", "1")],
        );
    }
    let overwrite = req
        .overwrite
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("T"))
        .unwrap_or(true);
    if !overwrite && state.source.lookup(&dest, 0).is_some() {
        return write_response(
            stream,
            412,
            "Precondition Failed",
            "text/plain; charset=utf-8",
            b"destination exists\n",
            true,
            &[("DAV", "1")],
        );
    }
    if !parent_is_dir(state.source.as_ref(), &dest) {
        return write_response(
            stream,
            409,
            "Conflict",
            "text/plain; charset=utf-8",
            b"parent missing\n",
            true,
            &[("DAV", "1")],
        );
    }
    match move_overlay(ov, path, &dest) {
        Ok(()) => write_response(
            stream,
            201,
            "Created",
            "text/plain; charset=utf-8",
            b"",
            false,
            &[("DAV", "1")],
        ),
        Err(e) => {
            let (status, reason) = overlay_status(&e);
            write_response(
                stream,
                status,
                reason,
                "text/plain; charset=utf-8",
                b"move failed\n",
                true,
                &[("DAV", "1")],
            )
        }
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<(HttpRequest, Vec<u8>)> {
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
            let req = parse_request(&buf[..end])?;
            let leftover = buf[end..].to_vec();
            return Ok((req, leftover));
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
