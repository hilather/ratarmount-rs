//! Dropbox file download-to-temp for `dropbox://` URLs.
//!
//! Mirrors Python ratarmount's `FixedDropboxDriveFileSystem` / `DROPBOX_TOKEN` path:
//! materialize a single remote file via the official Dropbox content API.
//!
//! # URL shape
//!
//! | Input | Dropbox API path |
//! |-------|------------------|
//! | `dropbox:///path/to/file.tar` | `/path/to/file.tar` |
//! | `dropbox://path/to/file.tar` | `/path/to/file.tar` |
//! | `dropbox://folder/archive.tar` | `/folder/archive.tar` |
//!
//! Everything after `dropbox://` is the remote path. A leading `/` is added when
//! missing (Dropbox requires absolute paths). Trailing `/` is stripped. Empty
//! paths after normalization are rejected.
//!
//! # Auth / API
//!
//! - Token: env `DROPBOX_TOKEN` (required)
//! - Download: `POST https://content.dropboxapi.com/2/files/download` with
//!   `Authorization: Bearer …` and `Dropbox-API-Arg: {"path":"…"}`
//! - Optional override for tests / proxies: `RATARMOUNT_DROPBOX_API_URL` or
//!   `DROPBOX_API_URL`

use std::io::{self, Seek, SeekFrom, Write};

use log::debug;
use tempfile::NamedTempFile;

use crate::{RemoteError, Result, USER_AGENT};

/// Official Dropbox content-download endpoint.
pub const DEFAULT_DROPBOX_DOWNLOAD_URL: &str =
    "https://content.dropboxapi.com/2/files/download";

/// Parsed Dropbox file location (API path only; token is never stored here).
#[derive(Clone, PartialEq, Eq)]
pub struct DropboxLocation {
    /// Absolute Dropbox path (`/…`), no trailing slash.
    pub path: String,
}

impl std::fmt::Debug for DropboxLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropboxLocation")
            .field("path", &self.path)
            .finish()
    }
}

impl std::fmt::Display for DropboxLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dropbox://{}", self.path.trim_start_matches('/'))
    }
}

/// Parse `dropbox://…` into a Dropbox API path (Python factory parity).
///
/// Does **not** use hierarchical URL host/path split: Dropbox has no host, so
/// `dropbox://folder/file` means path `/folder/file` (not host=`folder`).
pub fn parse_dropbox_url(url_str: &str) -> Result<DropboxLocation> {
    let Some((scheme, rest)) = url_str.split_once("://") else {
        return Err(RemoteError::Url(format!("not a URL: {url_str}")));
    };
    if !scheme.eq_ignore_ascii_case("dropbox") {
        return Err(RemoteError::UnsupportedScheme(scheme.to_string()));
    }

    // Strip optional query/fragment if a caller embeds them.
    let rest = rest
        .split_once(['?', '#'])
        .map(|(p, _)| p)
        .unwrap_or(rest);

    let mut path = rest.to_string();
    if !path.is_empty() && !path.starts_with('/') {
        path.insert(0, '/');
    }
    while path.ends_with('/') {
        path.pop();
    }
    // Percent-decode common encodings so spaces etc. work when URL-encoded.
    path = percent_decode_path(&path);

    if path.is_empty() {
        return Err(RemoteError::Url(
            "dropbox URL missing path (expected dropbox:///path/to/file or dropbox://path/to/file)"
                .into(),
        ));
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }

    Ok(DropboxLocation { path })
}

/// Minimal percent-decoder for path segments (`%XX` → byte). Invalid sequences kept.
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

/// Build `Dropbox-API-Arg` JSON for `files/download`.
pub fn dropbox_api_arg(path: &str) -> String {
    format!(r#"{{"path":"{}"}}"#, json_escape(path))
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Load `DROPBOX_TOKEN` or return a clear error.
pub fn load_dropbox_token() -> Result<String> {
    match std::env::var("DROPBOX_TOKEN") {
        Ok(t) if !t.is_empty() => Ok(t),
        Ok(_) | Err(_) => Err(RemoteError::Dropbox(
            "Please set the DROPBOX_TOKEN environment variable to mount dropbox:// URLs. \
             Create an OAuth 2 access token for your Dropbox app \
             (files.metadata.read + files.content.read)."
                .into(),
        )),
    }
}

/// Resolve download API URL (tests may override).
pub fn dropbox_download_url() -> String {
    std::env::var("RATARMOUNT_DROPBOX_API_URL")
        .or_else(|_| std::env::var("DROPBOX_API_URL"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_DROPBOX_DOWNLOAD_URL.to_string())
}

/// Redact an access token from error / log text.
pub fn redact_token(msg: &str, token: &str) -> String {
    if token.is_empty() {
        return msg.to_string();
    }
    msg.replace(token, "***")
}

/// Download `dropbox://…` using `DROPBOX_TOKEN` into a tempfile.
pub fn fetch_dropbox_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_dropbox_url(url_str)?;
    let token = load_dropbox_token()?;
    let api_url = dropbox_download_url();
    fetch_dropbox_location_to_temp(&loc, &token, &api_url)
}

/// Download a parsed location with an explicit token and content API URL.
pub fn fetch_dropbox_location_to_temp(
    loc: &DropboxLocation,
    token: &str,
    api_url: &str,
) -> Result<(NamedTempFile, u64)> {
    if token.is_empty() {
        return Err(RemoteError::Dropbox(
            "DROPBOX_TOKEN is empty; cannot download dropbox:// URLs".into(),
        ));
    }
    if loc.path.is_empty() || loc.path == "/" {
        return Err(RemoteError::Dropbox(
            "dropbox path is empty; expected a file path under the account or app folder".into(),
        ));
    }

    let api_arg = dropbox_api_arg(&loc.path);
    let auth = format!("Bearer {token}");

    debug!(
        "dropbox POST {} Dropbox-API-Arg={} (token redacted)",
        api_url, api_arg
    );

    // Official API uses POST with empty body; Dropbox-API-Arg carries the path.
    let resp = ureq::post(api_url)
        .set("User-Agent", USER_AGENT)
        .set("Authorization", &auth)
        .set("Dropbox-API-Arg", &api_arg)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&[])
        .map_err(|e| {
            RemoteError::Dropbox(redact_token(
                &format!("download {} via {api_url}: {e}", loc.path),
                token,
            ))
        })?;

    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp
            .into_string()
            .unwrap_or_else(|_| String::new());
        let detail = redact_token(&body, token);
        // Prefer a short summary when Dropbox returns JSON error_summary.
        let summary = extract_error_summary(&detail).unwrap_or(detail.as_str());
        return Err(RemoteError::Dropbox(format!(
            "HTTP {status} downloading {}: {summary}",
            loc.path
        )));
    }

    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = io::copy(&mut reader, &mut tmp).map_err(|e| {
        RemoteError::Dropbox(redact_token(
            &format!("writing download of {}: {e}", loc.path),
            token,
        ))
    })?;
    tmp.flush()?;
    tmp.as_file().seek(SeekFrom::Start(0))?;
    debug!("dropbox download {} -> {n} bytes", loc.path);
    Ok((tmp, n))
}

/// Best-effort extract of Dropbox JSON `error_summary` without a full JSON parser.
fn extract_error_summary(body: &str) -> Option<&str> {
    let key = "\"error_summary\"";
    let idx = body.find(key)?;
    let after = &body[idx + key.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(&after[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn parse_triple_slash() {
        let loc = parse_dropbox_url("dropbox:///path/to/file.tar").unwrap();
        assert_eq!(loc.path, "/path/to/file.tar");
    }

    #[test]
    fn parse_no_leading_slash_adds_one() {
        let loc = parse_dropbox_url("dropbox://path/to/file.tar").unwrap();
        assert_eq!(loc.path, "/path/to/file.tar");
        let loc = parse_dropbox_url("dropbox://folder/archive.tar").unwrap();
        assert_eq!(loc.path, "/folder/archive.tar");
    }

    #[test]
    fn parse_strips_trailing_slash() {
        let loc = parse_dropbox_url("dropbox:///trailing/").unwrap();
        assert_eq!(loc.path, "/trailing");
        let loc = parse_dropbox_url("dropbox://trailing/").unwrap();
        assert_eq!(loc.path, "/trailing");
    }

    #[test]
    fn parse_rejects_empty() {
        for u in ["dropbox://", "dropbox:///", "dropbox:////"] {
            let err = parse_dropbox_url(u).unwrap_err();
            assert!(
                err.to_string().contains("missing path") || err.to_string().contains("url"),
                "url={u} err={err}"
            );
        }
    }

    #[test]
    fn parse_rejects_other_scheme() {
        let err = parse_dropbox_url("https://example.com/a").unwrap_err();
        assert!(matches!(err, RemoteError::UnsupportedScheme(_)));
    }

    #[test]
    fn parse_percent_decode() {
        let loc = parse_dropbox_url("dropbox:///My%20Files/a.tar").unwrap();
        assert_eq!(loc.path, "/My Files/a.tar");
    }

    #[test]
    fn api_arg_json() {
        assert_eq!(
            dropbox_api_arg("/path/to/file.tar"),
            r#"{"path":"/path/to/file.tar"}"#
        );
        assert_eq!(
            dropbox_api_arg(r#"/weird"quote"#),
            r#"{"path":"/weird\"quote"}"#
        );
    }

    #[test]
    fn redact_token_hides_secret() {
        let token = "sl.Bsecret-token-value-xyz";
        let msg = format!("Authorization: Bearer {token} failed");
        let red = redact_token(&msg, token);
        assert!(!red.contains("secret-token"));
        assert!(red.contains("***"));
    }

    #[test]
    fn display_and_debug_have_no_token_field() {
        let loc = DropboxLocation {
            path: "/a/b.tar".into(),
        };
        let d = format!("{loc:?}");
        let s = format!("{loc}");
        assert!(d.contains("/a/b.tar"));
        assert!(!d.to_ascii_lowercase().contains("token"));
        assert!(s.contains("dropbox://"));
        assert!(s.contains("a/b.tar"));
    }

    #[test]
    fn extract_error_summary_ok() {
        let body = r#"{"error_summary": "path/not_found/...", "error": {".tag": "path"}}"#;
        assert_eq!(
            extract_error_summary(body),
            Some("path/not_found/...")
        );
    }

    /// Minimal Dropbox content-API mock: POST + Bearer + Dropbox-API-Arg.
    struct MockDropbox {
        addr: String,
        posts: Arc<AtomicUsize>,
        log: Arc<Mutex<Vec<String>>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    #[derive(Clone)]
    struct MockDropboxConfig {
        body: Vec<u8>,
        /// Required Bearer token (without "Bearer " prefix).
        require_token: String,
        /// If set, require Dropbox-API-Arg path to match.
        require_path: Option<String>,
        /// If true, always 401.
        force_unauthorized: bool,
    }

    impl MockDropbox {
        fn spawn(cfg: MockDropboxConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let posts = Arc::new(AtomicUsize::new(0));
            let log = Arc::new(Mutex::new(Vec::new()));
            let posts_c = Arc::clone(&posts);
            let log_c = Arc::clone(&log);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(32) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut content_length: usize = 0;
                    let mut auth_hdr: Option<String> = None;
                    let mut api_arg: Option<String> = None;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        if let Some(v) = line.strip_prefix("Content-Length:") {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                        if let Some(v) = line.strip_prefix("Authorization:") {
                            auth_hdr = Some(v.trim().to_string());
                        }
                        // Header name is case-sensitive in our client; accept common variants.
                        let lower = line.to_ascii_lowercase();
                        if lower.starts_with("dropbox-api-arg:") {
                            api_arg = Some(line.split_once(':').unwrap().1.trim().to_string());
                        }
                    }
                    if content_length > 0 {
                        let mut buf = vec![0u8; content_length];
                        let _ = Read::read_exact(&mut reader, &mut buf);
                    }

                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if let Some(a) = &auth_hdr {
                            // Never store raw token in test log assertions beyond presence.
                            lg.push(format!(
                                "Authorization: {}",
                                if a.contains(&cfg.require_token) {
                                    "Bearer ***"
                                } else {
                                    a.as_str()
                                }
                            ));
                        }
                        if let Some(arg) = &api_arg {
                            lg.push(format!("Dropbox-API-Arg: {arg}"));
                        }
                    }

                    let is_post = request_line.starts_with("POST ");
                    if !is_post {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }
                    posts_c.fetch_add(1, Ordering::SeqCst);

                    if cfg.force_unauthorized {
                        let body = br#"{"error_summary": "invalid_access_token/..."}"#;
                        let _ = write!(
                            stream,
                            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(body);
                        continue;
                    }

                    let expected_auth = format!("Bearer {}", cfg.require_token);
                    if auth_hdr.as_deref() != Some(expected_auth.as_str()) {
                        let body = br#"{"error_summary": "invalid_access_token/..."}"#;
                        let _ = write!(
                            stream,
                            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(body);
                        continue;
                    }

                    if let Some(want_path) = &cfg.require_path {
                        let want_arg = dropbox_api_arg(want_path);
                        if api_arg.as_deref() != Some(want_arg.as_str()) {
                            let body = format!(
                                r#"{{"error_summary": "path/not_found/...", "got": {:?}}}"#,
                                api_arg
                            );
                            let _ = write!(
                                stream,
                                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(body.as_bytes());
                            continue;
                        }
                    }

                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                        cfg.body.len()
                    );
                    let _ = stream.write_all(hdr.as_bytes());
                    let _ = stream.write_all(&cfg.body);
                }
            });
            Self {
                addr,
                posts,
                log,
                _join: Some(join),
            }
        }

        fn download_url(&self) -> String {
            // Path can be anything; client posts to the full URL we give it.
            format!("{}/2/files/download", self.addr)
        }
    }

    #[test]
    fn fetch_with_mock_server() {
        let body = b"dropbox-mock-archive-bytes".to_vec();
        let token = "sl.test-token-abc123";
        let mock = MockDropbox::spawn(MockDropboxConfig {
            body: body.clone(),
            require_token: token.into(),
            require_path: Some("/vault/a.tar".into()),
            force_unauthorized: false,
        });
        let loc = parse_dropbox_url("dropbox:///vault/a.tar").unwrap();
        let (mut tmp, size) =
            fetch_dropbox_location_to_temp(&loc, token, &mock.download_url()).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert_eq!(mock.posts.load(Ordering::SeqCst), 1);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.contains("Bearer ***")),
            "expected redacted auth in mock log: {log:?}"
        );
        assert!(
            log.iter()
                .any(|l| l.contains(r#"Dropbox-API-Arg: {"path":"/vault/a.tar"}"#)),
            "log={log:?}"
        );
    }

    #[test]
    fn fetch_wrong_token_errors_clearly() {
        let mock = MockDropbox::spawn(MockDropboxConfig {
            body: b"secret".to_vec(),
            require_token: "correct-token".into(),
            require_path: None,
            force_unauthorized: false,
        });
        let loc = parse_dropbox_url("dropbox://file.tar").unwrap();
        let err =
            fetch_dropbox_location_to_temp(&loc, "wrong-token", &mock.download_url()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("401") || msg.contains("invalid_access_token") || msg.contains("dropbox"),
            "unexpected: {msg}"
        );
        assert!(!msg.contains("wrong-token"), "token leaked: {msg}");
        assert!(!msg.contains("correct-token"), "token leaked: {msg}");
    }

    #[test]
    fn fetch_empty_token_errors() {
        let loc = parse_dropbox_url("dropbox://a.tar").unwrap();
        let err = fetch_dropbox_location_to_temp(&loc, "", "http://127.0.0.1:9/x").unwrap_err();
        assert!(err.to_string().contains("DROPBOX_TOKEN") || err.to_string().contains("empty"));
    }

    #[test]
    fn load_token_missing_message() {
        // Do not clear a real DROPBOX_TOKEN if present; only assert message shape via empty path.
        // We unit-test the error text by calling the function only when unset, else skip.
        if std::env::var("DROPBOX_TOKEN").is_ok() {
            return;
        }
        let err = load_dropbox_token().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("DROPBOX_TOKEN"), "{msg}");
    }
}
