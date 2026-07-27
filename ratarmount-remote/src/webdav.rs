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

/// Download a WebDAV (or HTTP with Basic auth) file into a tempfile via GET.
pub fn fetch_webdav_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_webdav_url(url_str)?;
    fetch_webdav_location_to_temp(&loc)
}

pub fn fetch_webdav_location_to_temp(loc: &WebDavLocation) -> Result<(NamedTempFile, u64)> {
    if let Ok(Some(size)) = propfind_content_length(loc) {
        debug!(
            "webdav PROPFIND {} getcontentlength={size}",
            loc.http_url
        );
    } else {
        debug!("webdav PROPFIND {} skipped or no size", loc.http_url);
    }

    let req = ureq::get(&loc.http_url).set("User-Agent", USER_AGENT);
    let req = apply_auth(req, loc);
    let resp = req
        .call()
        .map_err(|e| RemoteError::WebDav(e.to_string()))?;
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
}
