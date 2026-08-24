//! WebDAV file download-to-temp for `webdav://` / `webdavs://` (and plain http(s) with Basic auth).
//!
//! Maps `webdav` → `http` and `webdavs` → `https`, then GETs the resource with optional
//! Basic authentication from URL userinfo. Optionally issues a Depth-0 PROPFIND for size.

use std::io::{self, Seek, SeekFrom, Write};

use log::debug;
use tempfile::NamedTempFile;
use url::Url;

use crate::{RemoteError, Result, USER_AGENT};

/// Parsed WebDAV location (HTTP URL + optional Basic credentials).
#[derive(Debug, Clone)]
pub struct WebDavLocation {
    /// `http://` or `https://` request URL without userinfo.
    pub http_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Map `webdav://` → `http://`, `webdavs://` → `https://`; accept `http`/`https` as-is.
///
/// Credentials are stripped from the request URL and returned separately for the
/// `Authorization: Basic …` header.
pub fn parse_webdav_url(url_str: &str) -> Result<WebDavLocation> {
    let rewritten = map_webdav_scheme(url_str)?;
    let url = Url::parse(&rewritten).map_err(|e| RemoteError::Url(e.to_string()))?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(RemoteError::UnsupportedScheme(other.to_string()));
        }
    }
    if url.host_str().is_none() {
        return Err(RemoteError::Url("webdav URL missing host".into()));
    }
    if url.path().is_empty() || url.path() == "/" {
        // Allow root path; some servers serve a file there. Still need a host.
    }

    // url crate percent-decodes username/password.
    let username = if url.username().is_empty() {
        None
    } else {
        Some(url.username().to_string())
    };
    let password = url.password().map(|s| s.to_string());

    // Rebuild URL without credentials for the wire request.
    let mut clean = url.clone();
    let _ = clean.set_username("");
    let _ = clean.set_password(None);

    Ok(WebDavLocation {
        http_url: clean.to_string(),
        username,
        password,
    })
}

/// Rewrite `webdav://…` / `webdavs://…` prefixes to `http://` / `https://`.
fn map_webdav_scheme(url_str: &str) -> Result<String> {
    // Case-insensitive scheme match on the prefix before "://".
    let Some((scheme, rest)) = url_str.split_once("://") else {
        return Err(RemoteError::Url(format!("not a URL: {url_str}")));
    };
    let mapped = match scheme.to_ascii_lowercase().as_str() {
        "webdav" => "http",
        "webdavs" => "https",
        "http" | "https" => scheme,
        other => {
            return Err(RemoteError::UnsupportedScheme(other.to_string()));
        }
    };
    Ok(format!("{mapped}://{rest}"))
}

/// RFC 7617 Basic auth header value (`Basic <base64(user:pass)>`), if credentials present.
pub fn basic_auth_header(username: &str, password: Option<&str>) -> String {
    let raw = format!("{}:{}", username, password.unwrap_or(""));
    format!("Basic {}", base64_encode(raw.as_bytes()))
}

/// Minimal base64 encoder (no external dependency for a single auth header).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn apply_auth(mut req: ureq::Request, loc: &WebDavLocation) -> ureq::Request {
    if let Some(user) = loc.username.as_deref() {
        let hdr = basic_auth_header(user, loc.password.as_deref());
        req = req.set("Authorization", &hdr);
    }
    req
}

/// Optional Depth-0 PROPFIND; returns `getcontentlength` when present.
///
/// Failures are non-fatal — callers fall back to a plain GET.
pub fn propfind_content_length(loc: &WebDavLocation) -> Result<Option<u64>> {
    const BODY: &str = concat!(
        r#"<?xml version="1.0" encoding="utf-8" ?>"#,
        r#"<D:propfind xmlns:D="DAV:"><D:prop><D:getcontentlength/></D:prop></D:propfind>"#
    );
    let req = ureq::request("PROPFIND", &loc.http_url)
        .set("User-Agent", USER_AGENT)
        .set("Depth", "0")
        .set("Content-Type", "application/xml; charset=utf-8");
    let req = apply_auth(req, loc);
    let resp = match req.send_string(BODY) {
        Ok(r) => r,
        Err(e) => {
            debug!("PROPFIND {} failed: {e}", loc.http_url);
            return Ok(None);
        }
    };
    let status = resp.status();
    // 207 Multi-Status is the usual success; some servers may answer 200.
    if status != 207 && !(200..300).contains(&status) {
        debug!("PROPFIND {} -> HTTP {status}", loc.http_url);
        return Ok(None);
    }
    let body = resp
        .into_string()
        .map_err(|e| RemoteError::WebDav(e.to_string()))?;
    Ok(parse_getcontentlength(&body))
}

/// Extract the first numeric `getcontentlength` value from a PROPFIND multistatus body.
pub fn parse_getcontentlength(xml: &str) -> Option<u64> {
    // Case-insensitive tag search; tolerate optional namespace prefixes (D:getcontentlength).
    let lower = xml.to_ascii_lowercase();
    let mut search = lower.as_str();
    while let Some(idx) = search.find("getcontentlength") {
        let after_name = &search[idx + "getcontentlength".len()..];
        // Expect `>` or whitespace then `>` before the text content.
        let Some(gt) = after_name.find('>') else {
            search = &search[idx + 1..];
            continue;
        };
        // Skip self-closing or empty.
        let before_gt = after_name[..gt].trim();
        if before_gt.ends_with('/') {
            search = &search[idx + 1..];
            continue;
        }
        let content = &after_name[gt + 1..];
        let end_tag = content.find('<')?;
        let text = content[..end_tag].trim();
        if let Ok(n) = text.parse::<u64>() {
            return Some(n);
        }
        search = &search[idx + 1..];
    }
    None
}

/// One Depth-1 PROPFIND entry (href + collection flag + size).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebDavDirent {
    pub name: String,
    /// Request URL for this resource (`http(s)://…`).
    pub href: String,
    pub is_dir: bool,
    pub size: u64,
}

const PROPFIND_BODY: &str = concat!(
    r#"<?xml version="1.0" encoding="utf-8" ?>"#,
    r#"<D:propfind xmlns:D="DAV:">"#,
    r#"<D:prop><D:resourcetype/><D:getcontentlength/><D:getlastmodified/></D:prop>"#,
    r#"</D:propfind>"#
);

/// Depth-0/1 PROPFIND; `depth == 0` is self only, `1` includes children.
pub fn propfind_entries(loc: &WebDavLocation, depth: u32) -> Result<Vec<WebDavDirent>> {
    let depth_s = if depth == 0 { "0" } else { "1" };
    let req = ureq::request("PROPFIND", &loc.http_url)
        .set("User-Agent", USER_AGENT)
        .set("Depth", depth_s)
        .set("Content-Type", "application/xml; charset=utf-8");
    let req = apply_auth(req, loc);
    let resp = match req.send_string(PROPFIND_BODY) {
        Ok(r) => r,
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            return Err(RemoteError::WebDav(format!(
                "PROPFIND HTTP {code} for {}: {body}",
                loc.http_url
            )));
        }
        Err(e) => {
            return Err(RemoteError::WebDav(format!(
                "PROPFIND {} failed: {e}",
                loc.http_url
            )));
        }
    };
    let status = resp.status();
    if status != 207 && !(200..300).contains(&status) {
        return Err(RemoteError::WebDav(format!(
            "PROPFIND HTTP {status} for {}",
            loc.http_url
        )));
    }
    let body = resp
        .into_string()
        .map_err(|e| RemoteError::WebDav(e.to_string()))?;
    Ok(parse_propfind_dirents(&body, &loc.http_url))
}

/// Parse a PROPFIND multistatus body into dirents (skips the self href).
pub fn parse_propfind_dirents(xml: &str, self_url: &str) -> Vec<WebDavDirent> {
    let self_path = href_path(self_url);
    let mut out = Vec::new();
    for block in xml_elem_inners(xml, "response") {
        let Some(href) = xml_elem_text(&block, "href") else {
            continue;
        };
        let href = href.trim().to_string();
        if href.is_empty() {
            continue;
        }
        let is_dir = resourcetype_is_collection(&block);
        let size = xml_elem_text(&block, "getcontentlength")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let path = href_path(&href);
        if paths_equal(&path, &self_path) {
            continue;
        }
        let name = path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let abs = resolve_webdav_href(self_url, &href);
        out.push(WebDavDirent {
            name,
            href: abs,
            is_dir,
            size: if is_dir { 0 } else { size },
        });
    }
    out
}

fn find_open_tag(lower: &str, from: usize, tag: &str) -> Option<usize> {
    let mut search = from;
    while search < lower.len() {
        let rel = lower[search..].find(tag)?;
        let abs = search + rel;
        if abs == 0 {
            search = abs + 1;
            continue;
        }
        let prev = lower.as_bytes()[abs - 1];
        let is_open = match prev {
            b'<' => true,
            b':' => lower[..abs]
                .rfind('<')
                .is_some_and(|lt| !lower[lt + 1..abs].contains(['<', '>'])),
            _ => false,
        };
        if is_open {
            return Some(abs);
        }
        search = abs + 1;
    }
    None
}

fn find_close_lt(lower: &str, from: usize, tag: &str) -> Option<usize> {
    let mut search = from;
    while search < lower.len() {
        let rel = lower[search..].find(tag)?;
        let abs = search + rel;
        if let Some(lt) = lower[..abs].rfind("</") {
            let between = &lower[lt + 2..abs];
            if between.is_empty() || (between.ends_with(':') && !between.contains(['<', '>'])) {
                return Some(lt);
            }
        }
        search = abs + 1;
    }
    None
}

fn xml_elem_inners(xml: &str, tag: &str) -> Vec<String> {
    let lower = xml.to_ascii_lowercase();
    let tag = tag.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(name_at) = find_open_tag(&lower, search_from, &tag) {
        let Some(gt) = lower[name_at..].find('>') else {
            break;
        };
        let content_at = name_at + gt + 1;
        if xml[..content_at].trim_end().ends_with("/>") {
            search_from = content_at;
            continue;
        }
        let Some(close_lt) = find_close_lt(&lower, content_at, &tag) else {
            break;
        };
        out.push(xml[content_at..close_lt].to_string());
        search_from = close_lt + 1;
    }
    out
}

fn xml_elem_text(xml: &str, tag: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    let tag = tag.to_ascii_lowercase();
    let name_at = find_open_tag(&lower, 0, &tag)?;
    let gt = lower[name_at..].find('>')?;
    let before_gt = xml[name_at + tag.len()..name_at + gt].trim();
    if before_gt.ends_with('/') {
        return None;
    }
    let content_at = name_at + gt + 1;
    let end = xml[content_at..].find('<')?;
    Some(xml[content_at..content_at + end].trim().to_string())
}

fn href_path(href: &str) -> String {
    let trimmed = href.trim();
    let path = if let Ok(u) = Url::parse(trimmed) {
        u.path().to_string()
    } else {
        trimmed.split('?').next().unwrap_or(trimmed).to_string()
    };
    percent_decode_path(&path)
}

fn percent_decode_path(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn paths_equal(a: &str, b: &str) -> bool {
    let na = a.trim_end_matches('/');
    let nb = b.trim_end_matches('/');
    na == nb || na.is_empty() && nb.is_empty()
}

fn resolve_webdav_href(base: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }
    if let Ok(base_u) = Url::parse(base) {
        if let Ok(joined) = base_u.join(href) {
            return joined.to_string();
        }
    }
    href.to_string()
}

/// True when a PROPFIND `<resourcetype>` contains a `<collection>` **element**.
///
/// Href / property text containing the word `collection` must not count
/// (`/dav/collection/a.tar` is a file).
fn resourcetype_is_collection(block: &str) -> bool {
    for inner in xml_elem_inners(block, "resourcetype") {
        let lower = inner.to_ascii_lowercase();
        if find_open_tag(&lower, 0, "collection").is_some() {
            return true;
        }
    }
    false
}

fn parse_propfind_self_is_collection(xml: &str) -> bool {
    xml_elem_inners(xml, "response")
        .first()
        .map(|b| resourcetype_is_collection(b))
        .unwrap_or(false)
}

/// `true` when Depth-0 PROPFIND says this URL is a DAV collection.
///
/// PROPFIND 4xx / transport errors on a URL **without** a trailing slash are
/// `Ok(false)` so GET/Range file open can still run (same as Depth-0 size probe).
pub fn webdav_is_collection(loc: &WebDavLocation) -> Result<bool> {
    match propfind_self_is_collection(loc) {
        Ok(v) => Ok(v),
        Err(_) if loc.http_url.ends_with('/') => Ok(true),
        Err(e) => {
            debug!(
                "webdav PROPFIND {} failed ({e}); treating as file",
                loc.http_url
            );
            Ok(false)
        }
    }
}

fn propfind_self_is_collection(loc: &WebDavLocation) -> Result<bool> {
    let req = ureq::request("PROPFIND", &loc.http_url)
        .set("User-Agent", USER_AGENT)
        .set("Depth", "0")
        .set("Content-Type", "application/xml; charset=utf-8");
    let req = apply_auth(req, loc);
    let resp = match req.send_string(PROPFIND_BODY) {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            debug!("PROPFIND {} -> HTTP {code}", loc.http_url);
            return Ok(false);
        }
        Err(e) => {
            return Err(RemoteError::WebDav(format!(
                "PROPFIND {} failed: {e}",
                loc.http_url
            )));
        }
    };
    if resp.status() != 207 && !(200..300).contains(&resp.status()) {
        return Ok(false);
    }
    let body = resp.into_string().unwrap_or_default();
    Ok(parse_propfind_self_is_collection(&body))
}

/// Download a WebDAV (or HTTP with Basic auth) file into a tempfile via GET.
pub fn fetch_webdav_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_webdav_url(url_str)?;
    fetch_webdav_location_to_temp(&loc)
}

pub fn fetch_webdav_location_to_temp(loc: &WebDavLocation) -> Result<(NamedTempFile, u64)> {
    if let Ok(Some(size)) = propfind_content_length(loc) {
        debug!("webdav PROPFIND {} getcontentlength={size}", loc.http_url);
    } else {
        debug!("webdav PROPFIND {} skipped or no size", loc.http_url);
    }

    let req = ureq::get(&loc.http_url).set("User-Agent", USER_AGENT);
    let req = apply_auth(req, loc);
    let resp = req.call().map_err(|e| RemoteError::WebDav(e.to_string()))?;
    if !(200..300).contains(&resp.status()) {
        return Err(RemoteError::WebDav(format!(
            "HTTP {} for {}",
            resp.status(),
            loc.http_url
        )));
    }
    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    tmp.as_file().seek(SeekFrom::Start(0))?;
    debug!("webdav GET {} -> {n} bytes", loc.http_url);
    Ok((tmp, n))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn map_schemes() {
        let loc = parse_webdav_url("webdav://example.com/a.tar").unwrap();
        assert_eq!(loc.http_url, "http://example.com/a.tar");
        assert!(loc.username.is_none());

        let loc = parse_webdav_url("webdavs://example.com/a.tar").unwrap();
        assert_eq!(loc.http_url, "https://example.com/a.tar");

        let loc = parse_webdav_url("https://example.com/dav/a.tar").unwrap();
        assert_eq!(loc.http_url, "https://example.com/dav/a.tar");
    }

    #[test]
    fn parse_basic_auth_from_url() {
        let loc = parse_webdav_url("webdav://alice:s3cret@host.example/files/x.bin").unwrap();
        assert_eq!(loc.http_url, "http://host.example/files/x.bin");
        assert_eq!(loc.username.as_deref(), Some("alice"));
        assert_eq!(loc.password.as_deref(), Some("s3cret"));
        let hdr = basic_auth_header("alice", Some("s3cret"));
        // echo -n 'alice:s3cret' | base64
        assert_eq!(hdr, "Basic YWxpY2U6czNjcmV0");
    }

    #[test]
    fn base64_padding() {
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn parse_getcontentlength_variants() {
        let xml = r#"<?xml version="1.0"?>
        <d:multistatus xmlns:d="DAV:">
          <d:response>
            <d:propstat>
              <d:prop>
                <d:getcontentlength>12345</d:getcontentlength>
              </d:prop>
            </d:propstat>
          </d:response>
        </d:multistatus>"#;
        assert_eq!(parse_getcontentlength(xml), Some(12345));

        let bare = "<getcontentlength>99</getcontentlength>";
        assert_eq!(parse_getcontentlength(bare), Some(99));

        assert_eq!(parse_getcontentlength("<nope/>"), None);
    }

    #[test]
    fn parse_propfind_dirents_folder_children() {
        let xml = r#"<?xml version="1.0"?>
        <D:multistatus xmlns:D="DAV:">
          <D:response>
            <D:href>/dir/</D:href>
            <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
          </D:response>
          <D:response>
            <D:href>/dir/a.tar</D:href>
            <D:propstat><D:prop><D:getcontentlength>42</D:getcontentlength><D:resourcetype/></D:prop></D:propstat>
          </D:response>
          <D:response>
            <D:href>/dir/sub/</D:href>
            <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
          </D:response>
        </D:multistatus>"#;
        let ents = parse_propfind_dirents(xml, "http://host.example/dir/");
        assert_eq!(ents.len(), 2, "{ents:?}");
        let file = ents.iter().find(|e| e.name == "a.tar").expect("a.tar");
        assert!(!file.is_dir);
        assert_eq!(file.size, 42);
        let sub = ents.iter().find(|e| e.name == "sub").expect("sub");
        assert!(sub.is_dir);
        assert_eq!(sub.size, 0);
    }

    #[test]
    fn parse_propfind_href_collection_is_file() {
        let xml = r#"<?xml version="1.0"?>
        <D:multistatus xmlns:D="DAV:">
          <D:response>
            <D:href>/collection/</D:href>
            <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
          </D:response>
          <D:response>
            <D:href>/collection/a.tar</D:href>
            <D:propstat><D:prop><D:getcontentlength>42</D:getcontentlength><D:resourcetype/></D:prop></D:propstat>
          </D:response>
        </D:multistatus>"#;
        let ents = parse_propfind_dirents(xml, "http://host.example/collection/");
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].name, "a.tar");
        assert!(!ents[0].is_dir, "href containing 'collection' is not a dir");
        assert_eq!(ents[0].size, 42);
    }
}
