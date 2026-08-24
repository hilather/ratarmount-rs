//! HTTP/1.1 request line / headers, URL path, and `Range` (no httparse).

use std::fmt;
use std::io;

/// Parsed origin-form request (GET/HEAD plus WebDAV when enabled).
#[derive(Clone)]
pub(crate) struct HttpRequest {
    pub method: Method,
    pub path: String,
    pub range: Option<String>,
    pub depth: Option<String>,
    pub content_length: Option<u64>,
    pub destination: Option<String>,
    pub overwrite: Option<String>,
    pub if_header: Option<String>,
    pub lock_token: Option<String>,
    pub authorization: Option<String>,
    pub timeout: Option<String>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("range", &self.range)
            .field("depth", &self.depth)
            .field("content_length", &self.content_length)
            .field("destination", &self.destination)
            .field("overwrite", &self.overwrite)
            .field("if_header", &self.if_header)
            .field("lock_token", &self.lock_token)
            .field("authorization", &self.authorization.as_ref().map(|_| "***"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Head,
    Options,
    Propfind,
    Put,
    Delete,
    Mkcol,
    Move,
    Lock,
    Unlock,
    Copy,
    Proppatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathError {
    BadRequest,
    Escape,
}

/// Inclusive byte range after clamping to `size`, or unsatisfiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedRange {
    /// Full entity (no Range, or Range ignored).
    Full,
    /// Inclusive `start..=end` (end < size).
    Partial {
        start: u64,
        end: u64,
    },
    Unsatisfiable,
}

/// Split headers at `\r\n\r\n` (or `\n\n`).
pub(crate) fn headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
}

pub(crate) fn parse_request(header_block: &[u8]) -> io::Result<HttpRequest> {
    let text = std::str::from_utf8(header_block)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request is not UTF-8"))?;
    let mut lines = text.split('\n');
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty request"))?
        .trim_end_matches('\r');
    let mut parts = request_line.splitn(3, ' ');
    let method_s = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing target"))?;
    let method = match method_s {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "OPTIONS" => Method::Options,
        "PROPFIND" => Method::Propfind,
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        "MKCOL" => Method::Mkcol,
        "MOVE" => Method::Move,
        "LOCK" => Method::Lock,
        "UNLOCK" => Method::Unlock,
        "COPY" => Method::Copy,
        "PROPPATCH" => Method::Proppatch,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("method {other}"),
            ));
        }
    };
    if target.len() > 8192 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request target too long",
        ));
    }
    let mut range = None;
    let mut depth = None;
    let mut content_length = None;
    let mut destination = None;
    let mut overwrite = None;
    let mut if_header = None;
    let mut lock_token = None;
    let mut authorization = None;
    let mut timeout = None;
    for line in lines {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("range") && range.is_none() {
            range = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("depth") && depth.is_none() {
            depth = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") && content_length.is_none() {
            let n: u64 = value.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")
            })?;
            content_length = Some(n);
        } else if name.eq_ignore_ascii_case("destination") && destination.is_none() {
            destination = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("overwrite") && overwrite.is_none() {
            overwrite = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("if") && if_header.is_none() {
            if_header = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("lock-token") && lock_token.is_none() {
            lock_token = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("authorization") && authorization.is_none() {
            authorization = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("timeout") && timeout.is_none() {
            timeout = Some(value.to_string());
        }
    }
    Ok(HttpRequest {
        method,
        path: target.to_string(),
        range,
        depth,
        content_length,
        destination,
        overwrite,
        if_header,
        lock_token,
        authorization,
        timeout,
    })
}

/// Collect every opaque state token from a WebDAV `If` header (RFC 4918).
///
/// `If: <t1> <t2>` and tagged `</src> (<t1>) </dest> (<t2>)` both yield two
/// tokens. Resource tags (`</path>`, `http(s)://…`) are skipped. Does not stop
/// at the first match.
pub(crate) fn collect_if_tokens(header: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = header.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(rel_end) = bytes[i + 1..].iter().position(|&c| c == b'>') {
                let inner = header[i + 1..i + 1 + rel_end].trim();
                i += rel_end + 2;
                if inner.is_empty() || is_if_resource_tag(inner) {
                    continue;
                }
                out.push(inner.to_string());
                continue;
            }
        }
        i += 1;
    }
    out
}

fn is_if_resource_tag(inner: &str) -> bool {
    inner.starts_with('/') || inner.contains("://")
}

/// Strip optional `<>` around a `Lock-Token` header value.
pub(crate) fn normalize_lock_token(s: &str) -> String {
    s.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

/// RFC 3986 unreserved + encode the rest of a path segment.
pub(crate) fn percent_encode_segment(s: &str) -> String {
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

/// URL-decode the request target, reject `..` segments, then [`ratarmount_core::normpath`].
pub(crate) fn archive_path(target: &str) -> Result<String, PathError> {
    let without_abs = strip_absolute_form(target);
    let path_part = without_abs
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(without_abs);
    let path_part = path_part
        .split_once('#')
        .map(|(p, _)| p)
        .unwrap_or(path_part);
    if path_part.is_empty() {
        return Err(PathError::BadRequest);
    }
    let decoded = percent_decode(path_part).map_err(|_| PathError::BadRequest)?;
    if decoded.as_bytes().contains(&0) {
        return Err(PathError::BadRequest);
    }
    if path_escapes(&decoded) {
        return Err(PathError::Escape);
    }
    Ok(ratarmount_core::normpath(&decoded))
}

fn strip_absolute_form(target: &str) -> &str {
    for prefix in ["http://", "https://"] {
        if let Some(rest) = target
            .get(..prefix.len())
            .filter(|p| p.eq_ignore_ascii_case(prefix))
            .and_then(|_| target.get(prefix.len()..))
        {
            if let Some(slash) = rest.find('/') {
                return &rest[slash..];
            }
            return "/";
        }
    }
    target
}

fn path_escapes(decoded: &str) -> bool {
    decoded.split('/').any(|seg| seg == "..")
}

fn percent_decode(s: &str) -> Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(());
                }
                let h = hex_val(bytes[i + 1])?;
                let l = hex_val(bytes[i + 2])?;
                out.push((h << 4) | l);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

/// Resolve `Range` against entity `size`. Multiple ranges: first only.
pub(crate) fn resolve_range(header: Option<&str>, size: u64) -> ResolvedRange {
    let Some(h) = header.map(str::trim).filter(|s| !s.is_empty()) else {
        return ResolvedRange::Full;
    };
    let Some(spec) = h.strip_prefix("bytes=") else {
        return ResolvedRange::Full;
    };
    let first = spec.split(',').next().unwrap_or("").trim();
    if first.is_empty() {
        return ResolvedRange::Full;
    }
    match parse_one_range(first, size) {
        None => ResolvedRange::Full,
        Some(None) => ResolvedRange::Unsatisfiable,
        Some(Some((start, end))) => ResolvedRange::Partial { start, end },
    }
}

/// `None` = malformed (ignore). `Some(None)` = unsatisfiable. `Some(Some(start,end))`.
fn parse_one_range(spec: &str, size: u64) -> Option<Option<(u64, u64)>> {
    if let Some(suffix) = spec.strip_prefix('-') {
        let n: u64 = suffix.parse().ok()?;
        if n == 0 || size == 0 {
            return Some(None);
        }
        let start = size.saturating_sub(n);
        return Some(Some((start, size - 1)));
    }
    let (a, b) = spec.split_once('-')?;
    if a.is_empty() {
        return None;
    }
    let start: u64 = a.parse().ok()?;
    if start >= size {
        return Some(None);
    }
    let end = if b.is_empty() {
        size - 1
    } else {
        let e: u64 = b.parse().ok()?;
        if e < start {
            return None;
        }
        e.min(size - 1)
    };
    Some(Some((start, end)))
}

/// IMF-fixdate for `Last-Modified` (`mtime` Unix seconds, GMT).
pub(crate) fn http_date_gmt(unix_secs: u64) -> String {
    const WDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const MONTH_DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let wday = WDAYS[(unix_secs / 86400 % 7) as usize];
    let mut days = unix_secs / 86400;
    let tod = unix_secs % 86400;
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
    let sec = tod % 60;

    let mut year = 1970u64;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
        if year > 9999 {
            year = 9999;
            days = 0;
            break;
        }
    }
    let mut month = 0usize;
    while month < 12 {
        let mut md = MONTH_DAYS[month];
        if month == 1 && is_leap(year) {
            md = 29;
        }
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;
    format!(
        "{wday}, {day:02} {mon} {year} {hour:02}:{min:02}:{sec:02} GMT",
        mon = MONTHS[month.min(11)]
    )
}

#[allow(clippy::manual_is_multiple_of)] // MSRV 1.74: `is_multiple_of` is newer
fn is_leap(year: u64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

pub(crate) fn last_modified_header(mtime: f64) -> Option<String> {
    if !mtime.is_finite() || mtime <= 0.0 {
        return None;
    }
    let secs = mtime.trunc() as u64;
    Some(http_date_gmt(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_http_date() {
        assert_eq!(http_date_gmt(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            http_date_gmt(1_592_222_400),
            "Mon, 15 Jun 2020 12:00:00 GMT"
        );
    }

    #[test]
    fn decode_and_reject_dotdot() {
        assert_eq!(archive_path("/foo/bar").unwrap(), "/foo/bar");
        assert_eq!(archive_path("/foo/%20b").unwrap(), "/foo/ b");
        assert_eq!(
            archive_path("/%2e%2e/secret").unwrap_err(),
            PathError::Escape
        );
        assert_eq!(archive_path("/foo/../bar").unwrap_err(), PathError::Escape);
        assert_eq!(archive_path("/..").unwrap_err(), PathError::Escape);
        assert_eq!(archive_path("/foo/bar/..").unwrap_err(), PathError::Escape);
        assert_eq!(archive_path("/foo/./bar").unwrap(), "/foo/bar");
        assert_eq!(archive_path("/%zz").unwrap_err(), PathError::BadRequest);
    }

    #[test]
    fn range_first_only_and_416() {
        assert_eq!(
            resolve_range(Some("bytes=5-9"), 26),
            ResolvedRange::Partial { start: 5, end: 9 }
        );
        assert_eq!(
            resolve_range(Some("bytes=0-1,2-3"), 10),
            ResolvedRange::Partial { start: 0, end: 1 }
        );
        assert_eq!(
            resolve_range(Some("bytes=20-"), 10),
            ResolvedRange::Unsatisfiable
        );
        assert_eq!(
            resolve_range(Some("bytes=-3"), 10),
            ResolvedRange::Partial { start: 7, end: 9 }
        );
        assert_eq!(
            resolve_range(Some("bytes=2-999"), 10),
            ResolvedRange::Partial { start: 2, end: 9 }
        );
        assert_eq!(resolve_range(Some("items=1-2"), 10), ResolvedRange::Full);
        assert_eq!(
            resolve_range(Some("bytes=0-0"), 1),
            ResolvedRange::Partial { start: 0, end: 0 }
        );
        assert_eq!(
            resolve_range(Some("bytes=0-0"), 0),
            ResolvedRange::Unsatisfiable
        );
    }

    #[test]
    fn if_header_collects_all_opaque_tokens() {
        let two = collect_if_tokens("<t1> <t2>");
        assert_eq!(two, vec!["t1".to_string(), "t2".to_string()]);
        let tagged =
            collect_if_tokens("</src> (<opaquelocktoken:aaa>) </dest> (<opaquelocktoken:bbb>)");
        assert_eq!(
            tagged,
            vec![
                "opaquelocktoken:aaa".to_string(),
                "opaquelocktoken:bbb".to_string()
            ]
        );
        let url_tagged = collect_if_tokens("<http://host/src> (<t1>) <https://host/dest> (<t2>)");
        assert_eq!(url_tagged, vec!["t1".to_string(), "t2".to_string()]);
        assert!(collect_if_tokens("</only/path>").is_empty());
    }

    #[test]
    fn parse_lock_copy_proppatch_headers() {
        let req = parse_request(
            b"LOCK /hello.txt HTTP/1.1\r\nDepth: 0\r\nIf: <t1> <t2>\r\nLock-Token: <opaquelocktoken:abc>\r\nAuthorization: Basic dXNlcjpwYXNz\r\nTimeout: Second-600\r\n\r\n",
        )
        .unwrap();
        assert_eq!(req.method, Method::Lock);
        assert_eq!(req.depth.as_deref(), Some("0"));
        assert_eq!(req.if_header.as_deref(), Some("<t1> <t2>"));
        assert_eq!(req.lock_token.as_deref(), Some("<opaquelocktoken:abc>"));
        assert_eq!(req.authorization.as_deref(), Some("Basic dXNlcjpwYXNz"));
        assert_eq!(req.timeout.as_deref(), Some("Second-600"));
        let dbg = format!("{req:?}");
        assert!(
            !dbg.contains("dXNlcjpwYXNz"),
            "Authorization redacted: {dbg}"
        );
        assert!(dbg.contains("authorization"), "debug has field: {dbg}");

        let copy = parse_request(b"COPY /a HTTP/1.1\r\nDestination: /b\r\n\r\n").unwrap();
        assert_eq!(copy.method, Method::Copy);
        let patch = parse_request(b"PROPPATCH /a HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(patch.method, Method::Proppatch);
        let unlock = parse_request(b"UNLOCK /a HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(unlock.method, Method::Unlock);
    }
}
