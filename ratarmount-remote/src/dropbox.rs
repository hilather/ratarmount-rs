//! Dropbox access for `dropbox://` URLs.
//!
//! Mirrors Python ratarmount's `FixedDropboxDriveFileSystem` / `DROPBOX_TOKEN` path:
//! - single-file materialize via the official Dropbox content API
//! - folder browse via `files/list_folder` (+ continue) exposed as [`DropboxMountSource`]
//!
//! # URL shape
//!
//! | Input | Dropbox API path |
//! |-------|------------------|
//! | `dropbox:///path/to/file.tar` | `/path/to/file.tar` |
//! | `dropbox://path/to/file.tar` | `/path/to/file.tar` |
//! | `dropbox://folder/archive.tar` | `/folder/archive.tar` |
//! | `dropbox:///` (folder mount root) | `""` (account / app root) |
//!
//! Everything after `dropbox://` is the remote path. A leading `/` is added when
//! missing (Dropbox requires absolute paths for non-root). Trailing `/` is stripped.
//! Empty paths after normalization are rejected by [`parse_dropbox_url`] (file
//! download) but allowed by [`parse_dropbox_url_allow_root`] (folder mount).
//!
//! # Auth / API
//!
//! - Token: env `DROPBOX_TOKEN` (required)
//! - Download: `POST https://content.dropboxapi.com/2/files/download` with
//!   `Authorization: Bearer …` and `Dropbox-API-Arg: {"path":"…"}`
//! - List: `POST https://api.dropboxapi.com/2/files/list_folder` (+ `/continue`)
//! - Metadata: `POST https://api.dropboxapi.com/2/files/get_metadata`
//! - Optional overrides for tests / proxies:
//!   - download: `RATARMOUNT_DROPBOX_API_URL` or `DROPBOX_API_URL`
//!   - RPC base (list/metadata): `RATARMOUNT_DROPBOX_RPC_URL` or `DROPBOX_RPC_URL`
//!
//! # Listing cache TTL
//!
//! [`DropboxMountSource`] caches `list_folder` results per virtual directory.
//! Cache entries expire after [`DEFAULT_DROPBOX_LIST_TTL_SECS`] (30s), overridable
//! via env `RATARMOUNT_DROPBOX_LIST_TTL_SECS` (set to `0` to disable caching).
//! Expired entries are re-fetched on the next list/lookup that needs them.
//!
//! # Content download / HTTP Range
//!
//! The Dropbox content download endpoint accepts HTTP `Range` on many setups.
//! - [`fetch_dropbox_range_bytes`] downloads a single inclusive byte window (prefix /
//!   partial reads for callers that do not need the whole object).
//! - Full materialize ([`fetch_dropbox_location_to_temp`] /
//!   [`fetch_dropbox_location_to_temp_prefer_range`]) prefers sequential Range
//!   chunks ([`crate::HTTP_RANGE_CHUNK`]) when the object size is known and exceeds
//!   [`DEFAULT_DROPBOX_RANGE_THRESHOLD`]; otherwise falls back to a single full-body
//!   download. Token redaction on errors is unchanged.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use log::debug;
use ratarmount_core::{
    create_root_file_info, is_dir_mode, normpath, CheapDirent, FileInfo, ListResult, MountSource,
    UserData, S_IFDIR, S_IFMT, S_IFREG,
};
use tempfile::NamedTempFile;

use crate::{
    parse_content_range_total, range_chunk_windows, RemoteError, Result, HTTP_RANGE_CHUNK,
    USER_AGENT,
};

/// Official Dropbox content-download endpoint.
pub const DEFAULT_DROPBOX_DOWNLOAD_URL: &str = "https://content.dropboxapi.com/2/files/download";

/// Official Dropbox RPC API base (list_folder, get_metadata).
pub const DEFAULT_DROPBOX_RPC_BASE: &str = "https://api.dropboxapi.com";

/// Default TTL for [`DropboxMountSource`] `list_folder` cache entries (seconds).
pub const DEFAULT_DROPBOX_LIST_TTL_SECS: u64 = 30;

/// Files larger than this prefer chunked Range downloads (1 MiB).
pub const DEFAULT_DROPBOX_RANGE_THRESHOLD: u64 = 1024 * 1024;
/// Parsed Dropbox file/folder location (API path only; token is never stored here).
#[derive(Clone, PartialEq, Eq)]
pub struct DropboxLocation {
    /// Absolute Dropbox path (`/…`), or empty string for account/app root.
    /// No trailing slash except when empty (root).
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
        if self.path.is_empty() {
            write!(f, "dropbox:///")
        } else {
            write!(f, "dropbox://{}", self.path.trim_start_matches('/'))
        }
    }
}

/// Parse `dropbox://…` into a Dropbox API path (Python factory parity).
///
/// Does **not** use hierarchical URL host/path split: Dropbox has no host, so
/// `dropbox://folder/file` means path `/folder/file` (not host=`folder`).
/// Rejects empty/root-only paths (use [`parse_dropbox_url_allow_root`] for mounts).
pub fn parse_dropbox_url(url_str: &str) -> Result<DropboxLocation> {
    let loc = parse_dropbox_url_allow_root(url_str)?;
    if loc.path.is_empty() {
        return Err(RemoteError::Url(
            "dropbox URL missing path (expected dropbox:///path/to/file or dropbox://path/to/file)"
                .into(),
        ));
    }
    Ok(loc)
}

/// Like [`parse_dropbox_url`], but allows account/app root (`dropbox:///` → path `""`).
pub fn parse_dropbox_url_allow_root(url_str: &str) -> Result<DropboxLocation> {
    let Some((scheme, rest)) = url_str.split_once("://") else {
        return Err(RemoteError::Url(format!("not a URL: {url_str}")));
    };
    if !scheme.eq_ignore_ascii_case("dropbox") {
        return Err(RemoteError::UnsupportedScheme(scheme.to_string()));
    }

    // Strip optional query/fragment if a caller embeds them.
    let rest = rest.split_once(['?', '#']).map(|(p, _)| p).unwrap_or(rest);

    let mut path = rest.to_string();
    if !path.is_empty() && !path.starts_with('/') {
        path.insert(0, '/');
    }
    while path.ends_with('/') {
        path.pop();
    }
    // Percent-decode common encodings so spaces etc. work when URL-encoded.
    path = percent_decode_path(&path);

    // Root: empty after strip, or sole `/` already stripped to empty.
    if path.is_empty() {
        return Ok(DropboxLocation {
            path: String::new(),
        });
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

/// Resolve RPC API base URL for list_folder / get_metadata (tests may override).
///
/// Trailing `/` is stripped. Paths `/2/files/list_folder` etc. are appended by callers.
pub fn dropbox_rpc_base() -> String {
    std::env::var("RATARMOUNT_DROPBOX_RPC_URL")
        .or_else(|_| std::env::var("DROPBOX_RPC_URL"))
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
        .unwrap_or_else(|| DEFAULT_DROPBOX_RPC_BASE.to_string())
}

/// Listing cache TTL in seconds (`RATARMOUNT_DROPBOX_LIST_TTL_SECS`, default 30).
///
/// `0` disables caching (every list re-fetches). Invalid / non-numeric values fall
/// back to [`DEFAULT_DROPBOX_LIST_TTL_SECS`].
pub fn dropbox_list_ttl_secs() -> u64 {
    match std::env::var("RATARMOUNT_DROPBOX_LIST_TTL_SECS") {
        Ok(s) if !s.is_empty() => s.parse::<u64>().unwrap_or(DEFAULT_DROPBOX_LIST_TTL_SECS),
        _ => DEFAULT_DROPBOX_LIST_TTL_SECS,
    }
}
/// Redact an access token from error / log text.
pub fn redact_token(msg: &str, token: &str) -> String {
    if token.is_empty() {
        return msg.to_string();
    }
    msg.replace(token, "***")
}

/// Download `dropbox://…` using `DROPBOX_TOKEN` into a tempfile.
///
/// Prefers chunked Range when the API supports it and the object is large; see
/// [`fetch_dropbox_location_to_temp_prefer_range`].
pub fn fetch_dropbox_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_dropbox_url(url_str)?;
    let token = load_dropbox_token()?;
    let api_url = dropbox_download_url();
    fetch_dropbox_location_to_temp(&loc, &token, &api_url)
}

/// Download a parsed location with an explicit token and content API URL.
///
/// Equivalent to [`fetch_dropbox_location_to_temp_prefer_range`] with unknown size
/// (may probe with `Range: bytes=0-0` before falling back to full body).
pub fn fetch_dropbox_location_to_temp(
    loc: &DropboxLocation,
    token: &str,
    api_url: &str,
) -> Result<(NamedTempFile, u64)> {
    fetch_dropbox_location_to_temp_prefer_range(loc, token, api_url, None)
}

/// Download a Dropbox file, preferring sequential HTTP Range chunks when feasible.
///
/// - When `known_size` is `Some(n)` and `n > `[`DEFAULT_DROPBOX_RANGE_THRESHOLD`],
///   tries chunked Range materialization first.
/// - When size is unknown, probes with `Range: bytes=0-0`; on 206 + total size above
///   threshold, uses chunked Range. If the probe returns a full body (Range ignored),
///   that body is kept (no second download).
/// - On any Range failure or when the object is small / ranges unsupported, falls
///   back to a single full-body download.
pub fn fetch_dropbox_location_to_temp_prefer_range(
    loc: &DropboxLocation,
    token: &str,
    api_url: &str,
    known_size: Option<u64>,
) -> Result<(NamedTempFile, u64)> {
    if token.is_empty() {
        return Err(RemoteError::Dropbox(
            "DROPBOX_TOKEN is empty; cannot download dropbox:// URLs".into(),
        ));
    }
    if loc.path.is_empty() {
        return Err(RemoteError::Dropbox(
            "dropbox path is empty; expected a file path under the account or app folder".into(),
        ));
    }

    let size_for_range = match known_size {
        Some(n) if n > DEFAULT_DROPBOX_RANGE_THRESHOLD => Some(n),
        Some(_) => None, // small known size → full body
        None => match probe_dropbox_download(loc, token, api_url) {
            Ok(DropboxProbe::RangesOk(n)) if n > DEFAULT_DROPBOX_RANGE_THRESHOLD => Some(n),
            Ok(DropboxProbe::RangesOk(_)) => None,
            Ok(DropboxProbe::FullBody(bytes)) => {
                return bytes_to_tempfile(loc, token, bytes);
            }
            Ok(DropboxProbe::Unusable) => None,
            Err(e) => {
                debug!(
                    "dropbox range probe failed for {}: {e}; full download",
                    loc.path
                );
                None
            }
        },
    };

    if let Some(size) = size_for_range {
        debug!(
            "dropbox prefer-range: {} ({size} bytes) in {}-byte chunks",
            loc.path, HTTP_RANGE_CHUNK
        );
        match fetch_dropbox_via_ranges(loc, token, api_url, size) {
            Ok(v) => return Ok(v),
            Err(e) => {
                debug!(
                    "dropbox range download failed for {}: {e}; falling back to full body",
                    loc.path
                );
            }
        }
    }

    fetch_dropbox_full_body(loc, token, api_url)
}

/// Result of a content-API Range probe (`bytes=0-0`).
enum DropboxProbe {
    /// 206 Partial Content with known total size.
    RangesOk(u64),
    /// Server ignored Range and returned the full object body.
    FullBody(Vec<u8>),
    /// Ranges / size not usable from this probe.
    Unusable,
}

fn bytes_to_tempfile(
    loc: &DropboxLocation,
    token: &str,
    bytes: Vec<u8>,
) -> Result<(NamedTempFile, u64)> {
    let mut tmp = NamedTempFile::new()?;
    tmp.write_all(&bytes).map_err(|e| {
        RemoteError::Dropbox(redact_token(
            &format!("writing download of {}: {e}", loc.path),
            token,
        ))
    })?;
    tmp.flush()?;
    tmp.as_file().seek(SeekFrom::Start(0))?;
    let n = bytes.len() as u64;
    debug!("dropbox download {} -> {n} bytes", loc.path);
    Ok((tmp, n))
}

/// Download an inclusive byte range (`start..=end`) from a Dropbox file.
///
/// Best-effort helper for callers that only need a prefix or window. Expects the
/// content endpoint to honor `Range` with HTTP 206; returns a clear error on 200
/// (range ignored) or other status codes. Token is redacted in error messages.
pub fn fetch_dropbox_range_bytes(
    loc: &DropboxLocation,
    token: &str,
    api_url: &str,
    start: u64,
    end_inclusive: u64,
) -> Result<Vec<u8>> {
    if token.is_empty() {
        return Err(RemoteError::Dropbox(
            "DROPBOX_TOKEN is empty; cannot download dropbox:// URLs".into(),
        ));
    }
    if loc.path.is_empty() {
        return Err(RemoteError::Dropbox(
            "dropbox path is empty; expected a file path under the account or app folder".into(),
        ));
    }
    if end_inclusive < start {
        return Err(RemoteError::Dropbox(format!(
            "invalid range {start}-{end_inclusive} for {}",
            loc.path
        )));
    }
    let expected = end_inclusive - start + 1;
    let (status, _content_range, bytes) =
        dropbox_download_request(loc, token, api_url, Some((start, end_inclusive)))?;
    if status == 206 {
        if bytes.len() as u64 != expected {
            return Err(RemoteError::Dropbox(format!(
                "range bytes={start}-{end_inclusive} for {} returned {} bytes, expected {expected}",
                loc.path,
                bytes.len()
            )));
        }
        return Ok(bytes);
    }
    if status == 200 {
        return Err(RemoteError::Dropbox(format!(
            "HTTP 200 (Range ignored) downloading {} bytes={start}-{end_inclusive}; \
             content endpoint did not return 206 Partial Content",
            loc.path
        )));
    }
    // Non-success already mapped inside dropbox_download_request for error bodies;
    // defensive path for unexpected 2xx.
    Err(RemoteError::Dropbox(format!(
        "HTTP {status} downloading {} range bytes={start}-{end_inclusive}",
        loc.path
    )))
}

/// Probe via `Range: bytes=0-0` on the content download endpoint.
fn probe_dropbox_download(
    loc: &DropboxLocation,
    token: &str,
    api_url: &str,
) -> Result<DropboxProbe> {
    let api_arg = dropbox_api_arg(&loc.path);
    let auth = format!("Bearer {token}");
    debug!(
        "dropbox probe POST {} Dropbox-API-Arg={} Range=bytes=0-0 (token redacted)",
        api_url, api_arg
    );
    let resp = match ureq::post(api_url)
        .set("User-Agent", USER_AGENT)
        .set("Authorization", &auth)
        .set("Dropbox-API-Arg", &api_arg)
        .set("Content-Type", "application/octet-stream")
        .set("Range", "bytes=0-0")
        .send_bytes(&[])
    {
        Ok(r) => r,
        Err(ureq::Error::Status(status, r)) => {
            let body = r.into_string().unwrap_or_else(|_| String::new());
            let detail = redact_token(&body, token);
            let summary = extract_error_summary(&detail).unwrap_or(detail.as_str());
            return Err(RemoteError::Dropbox(format!(
                "HTTP {status} probing {}: {summary}",
                loc.path
            )));
        }
        Err(e) => {
            return Err(RemoteError::Dropbox(redact_token(
                &format!("probe {} via {api_url}: {e}", loc.path),
                token,
            )));
        }
    };
    let status = resp.status();
    let content_range = resp.header("Content-Range").map(|s| s.to_string());
    let content_length = resp
        .header("Content-Length")
        .and_then(|s| s.parse::<u64>().ok());
    if status == 206 {
        if let Some(total) = parse_content_range_total(content_range.as_deref()) {
            let _ = resp.into_string();
            return Ok(DropboxProbe::RangesOk(total));
        }
        let _ = resp.into_string();
        return Ok(DropboxProbe::Unusable);
    }
    if (200..300).contains(&status) {
        // Range ignored. Avoid buffering huge bodies into RAM for reuse.
        if content_length.is_some_and(|n| n > DEFAULT_DROPBOX_RANGE_THRESHOLD) {
            let mut reader = resp.into_reader();
            let _ = io::copy(&mut reader, &mut io::sink());
            return Ok(DropboxProbe::Unusable);
        }
        let mut reader = resp.into_reader();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).map_err(|e| {
            RemoteError::Dropbox(redact_token(
                &format!("reading probe of {}: {e}", loc.path),
                token,
            ))
        })?;
        return Ok(DropboxProbe::FullBody(bytes));
    }
    let _ = resp.into_string();
    Ok(DropboxProbe::Unusable)
}

/// Sequential Range materialization into a tempfile (like HTTP prefer-range).
fn fetch_dropbox_via_ranges(
    loc: &DropboxLocation,
    token: &str,
    api_url: &str,
    size: u64,
) -> Result<(NamedTempFile, u64)> {
    let mut tmp = NamedTempFile::new()?;
    if size == 0 {
        tmp.flush()?;
        return Ok((tmp, 0));
    }
    let mut written = 0u64;
    for (start, end) in range_chunk_windows(size, HTTP_RANGE_CHUNK) {
        let range = format!("bytes={start}-{end}");
        let (status, _cr, chunk) =
            dropbox_download_request(loc, token, api_url, Some((start, end)))?;
        if status == 206 {
            let expected = end - start + 1;
            if chunk.len() as u64 != expected {
                return Err(RemoteError::Dropbox(format!(
                    "range {range} for {} returned {} bytes, expected {expected}",
                    loc.path,
                    chunk.len()
                )));
            }
            tmp.write_all(&chunk).map_err(|e| {
                RemoteError::Dropbox(redact_token(
                    &format!("writing range {range} of {}: {e}", loc.path),
                    token,
                ))
            })?;
            written += chunk.len() as u64;
        } else if status == 200 && start == 0 {
            // Server ignored Range and returned the full body on the first chunk.
            tmp.write_all(&chunk).map_err(|e| {
                RemoteError::Dropbox(redact_token(
                    &format!("writing download of {}: {e}", loc.path),
                    token,
                ))
            })?;
            tmp.flush()?;
            tmp.as_file().seek(SeekFrom::Start(0))?;
            debug!(
                "dropbox download {} -> {} bytes (full body; Range ignored)",
                loc.path,
                chunk.len()
            );
            return Ok((tmp, chunk.len() as u64));
        } else {
            return Err(RemoteError::Dropbox(format!(
                "HTTP {status} for range {range} on {}",
                loc.path
            )));
        }
    }
    if written != size {
        return Err(RemoteError::Dropbox(format!(
            "range download size mismatch for {}: wrote {written}, expected {size}",
            loc.path
        )));
    }
    tmp.flush()?;
    tmp.as_file().seek(SeekFrom::Start(0))?;
    debug!("dropbox range download {} -> {written} bytes", loc.path);
    Ok((tmp, written))
}

/// Single full-body content download (no Range header); streams to tempfile.
fn fetch_dropbox_full_body(
    loc: &DropboxLocation,
    token: &str,
    api_url: &str,
) -> Result<(NamedTempFile, u64)> {
    let api_arg = dropbox_api_arg(&loc.path);
    let auth = format!("Bearer {token}");

    debug!(
        "dropbox POST {} Dropbox-API-Arg={} (full body, token redacted)",
        api_url, api_arg
    );

    let resp = match ureq::post(api_url)
        .set("User-Agent", USER_AGENT)
        .set("Authorization", &auth)
        .set("Dropbox-API-Arg", &api_arg)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&[])
    {
        Ok(r) => r,
        Err(ureq::Error::Status(status, r)) => {
            let body = r.into_string().unwrap_or_else(|_| String::new());
            let detail = redact_token(&body, token);
            let summary = extract_error_summary(&detail).unwrap_or(detail.as_str());
            return Err(RemoteError::Dropbox(format!(
                "HTTP {status} downloading {}: {summary}",
                loc.path
            )));
        }
        Err(e) => {
            return Err(RemoteError::Dropbox(redact_token(
                &format!("download {} via {api_url}: {e}", loc.path),
                token,
            )));
        }
    };

    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_else(|_| String::new());
        let detail = redact_token(&body, token);
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

/// POST content download with optional inclusive Range; buffers response body.
///
/// Used for Range windows (bounded by [`HTTP_RANGE_CHUNK`]) and prefix helpers.
/// On error status, returns `RemoteError` with redacted body summary.
fn dropbox_download_request(
    loc: &DropboxLocation,
    token: &str,
    api_url: &str,
    range: Option<(u64, u64)>,
) -> Result<(u16, Option<String>, Vec<u8>)> {
    let api_arg = dropbox_api_arg(&loc.path);
    let auth = format!("Bearer {token}");

    debug!(
        "dropbox POST {} Dropbox-API-Arg={} range={:?} (token redacted)",
        api_url, api_arg, range
    );

    let mut req = ureq::post(api_url)
        .set("User-Agent", USER_AGENT)
        .set("Authorization", &auth)
        .set("Dropbox-API-Arg", &api_arg)
        .set("Content-Type", "application/octet-stream");
    if let Some((start, end)) = range {
        req = req.set("Range", &format!("bytes={start}-{end}"));
    }

    let resp = match req.send_bytes(&[]) {
        Ok(r) => r,
        Err(ureq::Error::Status(status, r)) => {
            let body = r.into_string().unwrap_or_else(|_| String::new());
            let detail = redact_token(&body, token);
            let summary = extract_error_summary(&detail).unwrap_or(detail.as_str());
            let range_note = range
                .map(|(s, e)| format!(" range bytes={s}-{e}"))
                .unwrap_or_default();
            return Err(RemoteError::Dropbox(format!(
                "HTTP {status} downloading {}{range_note}: {summary}",
                loc.path
            )));
        }
        Err(e) => {
            return Err(RemoteError::Dropbox(redact_token(
                &format!("download {} via {api_url}: {e}", loc.path),
                token,
            )));
        }
    };

    let status = resp.status();
    let content_range = resp.header("Content-Range").map(|s| s.to_string());
    let mut reader = resp.into_reader();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|e| {
        RemoteError::Dropbox(redact_token(
            &format!("reading download of {}: {e}", loc.path),
            token,
        ))
    })?;
    Ok((status, content_range, bytes))
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

// ---------------------------------------------------------------------------
// Folder listing / metadata
// ---------------------------------------------------------------------------

/// Kind of a Dropbox list/metadata entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropboxEntryKind {
    File,
    Folder,
}

/// One entry from `files/list_folder` or `files/get_metadata`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropboxEntry {
    pub name: String,
    /// Absolute Dropbox path (`path_display` or reconstructed). Empty only for root.
    pub path: String,
    pub kind: DropboxEntryKind,
    /// File size in bytes; 0 for folders.
    pub size: u64,
    /// Optional `server_modified` ISO-8601 timestamp string.
    pub server_modified: Option<String>,
}

impl DropboxEntry {
    fn to_file_info(&self) -> FileInfo {
        let mode = match self.kind {
            DropboxEntryKind::Folder => S_IFDIR | 0o755,
            DropboxEntryKind::File => S_IFREG | 0o644,
        };
        let mtime = self
            .server_modified
            .as_deref()
            .and_then(parse_dropbox_mtime)
            .unwrap_or(0.0);
        FileInfo {
            size: self.size,
            mtime,
            mode,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            // Store absolute Dropbox API path for open/list join.
            userdata: vec![UserData::Other(self.path.clone())],
        }
    }
}

/// Parse Dropbox `server_modified` (`2015-05-12T15:50:38Z`) to unix seconds as f64.
fn parse_dropbox_mtime(s: &str) -> Option<f64> {
    // Accept trailing Z only (Dropbox API); use chrono when available.
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok().or_else(|| {
        // Some responses omit fractional seconds; try with Z forced.
        if s.ends_with('Z') {
            chrono::DateTime::parse_from_rfc3339(s).ok()
        } else {
            chrono::DateTime::parse_from_rfc3339(&format!("{s}Z")).ok()
        }
    })?;
    Some(dt.timestamp() as f64)
}

fn list_folder_url(rpc_base: &str) -> String {
    format!("{}/2/files/list_folder", rpc_base.trim_end_matches('/'))
}

fn list_folder_continue_url(rpc_base: &str) -> String {
    format!(
        "{}/2/files/list_folder/continue",
        rpc_base.trim_end_matches('/')
    )
}

fn metadata_url(rpc_base: &str) -> String {
    format!("{}/2/files/get_metadata", rpc_base.trim_end_matches('/'))
}

/// POST JSON to a Dropbox RPC endpoint; return response body string.
fn dropbox_rpc_post(url: &str, token: &str, body: &str) -> Result<String> {
    let auth = format!("Bearer {token}");
    debug!("dropbox RPC POST {url} body={body} (token redacted)");
    let resp = ureq::post(url)
        .set("User-Agent", USER_AGENT)
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_string(body)
        .map_err(|e| RemoteError::Dropbox(redact_token(&format!("RPC {url}: {e}"), token)))?;
    let status = resp.status();
    let text = resp.into_string().unwrap_or_else(|_| String::new());
    if !(200..300).contains(&status) {
        let detail = redact_token(&text, token);
        let summary = extract_error_summary(&detail).unwrap_or(detail.as_str());
        return Err(RemoteError::Dropbox(format!(
            "HTTP {status} from {url}: {summary}"
        )));
    }
    Ok(text)
}

/// Parse one Dropbox metadata/list entry object.
fn parse_entry_value(v: &serde_json::Value) -> Option<DropboxEntry> {
    let obj = v.as_object()?;
    let tag = obj.get(".tag").and_then(|t| t.as_str()).unwrap_or("");
    let kind = match tag {
        "file" => DropboxEntryKind::File,
        "folder" => DropboxEntryKind::Folder,
        // deleted / other → skip
        _ => return None,
    };
    let name = obj
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return None;
    }
    let path = obj
        .get("path_display")
        .and_then(|p| p.as_str())
        .or_else(|| obj.get("path_lower").and_then(|p| p.as_str()))
        .unwrap_or("")
        .to_string();
    let size = if kind == DropboxEntryKind::File {
        obj.get("size").and_then(|s| s.as_u64()).unwrap_or(0)
    } else {
        0
    };
    let server_modified = obj
        .get("server_modified")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    Some(DropboxEntry {
        name,
        path,
        kind,
        size,
        server_modified,
    })
}

/// List all entries in a Dropbox folder (handles `has_more` / continue).
///
/// `path` is the Dropbox API path (`""` for root, otherwise `/…`).
pub fn list_dropbox_folder(path: &str, token: &str, rpc_base: &str) -> Result<Vec<DropboxEntry>> {
    if token.is_empty() {
        return Err(RemoteError::Dropbox(
            "DROPBOX_TOKEN is empty; cannot list dropbox:// folders".into(),
        ));
    }
    let list_url = list_folder_url(rpc_base);
    let cont_url = list_folder_continue_url(rpc_base);

    // Dropbox root is empty string; non-root must be absolute.
    let api_path = if path == "/" { "" } else { path };
    let body = format!(
        r#"{{"path":"{}","recursive":false,"include_media_info":false,"include_deleted":false,"include_has_explicit_shared_members":false}}"#,
        json_escape(api_path)
    );

    let mut text = dropbox_rpc_post(&list_url, token, &body)?;
    let mut entries = Vec::new();

    loop {
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| RemoteError::Dropbox(format!("list_folder JSON parse error: {e}")))?;
        if let Some(arr) = v.get("entries").and_then(|e| e.as_array()) {
            for item in arr {
                if let Some(ent) = parse_entry_value(item) {
                    entries.push(ent);
                }
            }
        }
        let has_more = v.get("has_more").and_then(|h| h.as_bool()).unwrap_or(false);
        if !has_more {
            break;
        }
        let cursor = v.get("cursor").and_then(|c| c.as_str()).ok_or_else(|| {
            RemoteError::Dropbox("list_folder has_more=true but cursor missing".into())
        })?;
        let cont_body = format!(r#"{{"cursor":"{}"}}"#, json_escape(cursor));
        text = dropbox_rpc_post(&cont_url, token, &cont_body)?;
    }

    debug!(
        "dropbox list_folder path={api_path:?} -> {} entries",
        entries.len()
    );
    Ok(entries)
}

/// Fetch metadata for a single path (`""` / `/…`).
pub fn get_dropbox_metadata(path: &str, token: &str, rpc_base: &str) -> Result<DropboxEntry> {
    if token.is_empty() {
        return Err(RemoteError::Dropbox(
            "DROPBOX_TOKEN is empty; cannot get dropbox metadata".into(),
        ));
    }
    let api_path = if path == "/" { "" } else { path };
    // Dropbox get_metadata rejects empty path for account root in some configs;
    // callers often use list_folder for root instead. Still send path as given.
    let url = metadata_url(rpc_base);
    let body = format!(
        r#"{{"path":"{}","include_media_info":false,"include_deleted":false,"include_has_explicit_shared_members":false}}"#,
        json_escape(api_path)
    );
    let text = dropbox_rpc_post(&url, token, &body)?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| RemoteError::Dropbox(format!("get_metadata JSON parse error: {e}")))?;
    parse_entry_value(&v).ok_or_else(|| {
        RemoteError::Dropbox(format!(
            "get_metadata for {api_path:?}: missing or unsupported entry (.tag)"
        ))
    })
}

/// True when `path` is a Dropbox folder (via get_metadata, or list_folder fallback).
pub fn dropbox_path_is_folder(path: &str, token: &str, rpc_base: &str) -> Result<bool> {
    let api_path = if path == "/" { "" } else { path };
    // Root is always a folder.
    if api_path.is_empty() {
        return Ok(true);
    }
    match get_dropbox_metadata(api_path, token, rpc_base) {
        Ok(ent) => Ok(ent.kind == DropboxEntryKind::Folder),
        Err(e) => {
            // Fallback: if list_folder succeeds, treat as folder.
            debug!("get_metadata failed for {api_path}: {e}; trying list_folder");
            match list_dropbox_folder(api_path, token, rpc_base) {
                Ok(_) => Ok(true),
                Err(_) => Err(e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DropboxMountSource
// ---------------------------------------------------------------------------

/// Cached `list_folder` result with fetch timestamp for TTL expiry.
struct ListingCacheEntry {
    entries: Vec<DropboxEntry>,
    fetched_at: Instant,
}

/// Mount a Dropbox folder as a [`MountSource`] (list + download-on-open).
///
/// Auth: `DROPBOX_TOKEN`. On file open, content is downloaded to a kept temp file
/// (cleaned up when this source is dropped). Large files use chunked HTTP Range
/// downloads when the content endpoint supports them (see module docs).
///
/// Directory listings are cached with a TTL ([`DEFAULT_DROPBOX_LIST_TTL_SECS`] /
/// `RATARMOUNT_DROPBOX_LIST_TTL_SECS`); expired entries re-fetch on next use.
pub struct DropboxMountSource {
    /// Dropbox absolute path of mount root (`""` = account/app root).
    root: String,
    token: String,
    download_url: String,
    rpc_base: String,
    /// Listing cache TTL; `Duration::ZERO` disables caching.
    list_ttl: Duration,
    /// Virtual path → listed entries cache (TTL-based).
    listing_cache: Mutex<BTreeMap<String, ListingCacheEntry>>,
    /// Temp files kept for open handles (deleted on Drop).
    temp_files: Mutex<Vec<PathBuf>>,
}

impl std::fmt::Debug for DropboxMountSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropboxMountSource")
            .field("root", &self.root)
            .field("download_url", &self.download_url)
            .field("rpc_base", &self.rpc_base)
            .field("list_ttl_secs", &self.list_ttl.as_secs())
            .finish_non_exhaustive()
    }
}

impl Drop for DropboxMountSource {
    fn drop(&mut self) {
        if let Ok(mut files) = self.temp_files.lock() {
            for p in files.drain(..) {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

impl DropboxMountSource {
    /// Open a `dropbox://…` folder URL using `DROPBOX_TOKEN` and default endpoints.
    pub fn open(url_str: &str) -> Result<Self> {
        let token = load_dropbox_token()?;
        Self::open_with_token(url_str, &token)
    }

    /// Open with an explicit token (still uses env for API URL overrides).
    pub fn open_with_token(url_str: &str, token: &str) -> Result<Self> {
        Self::open_with_endpoints(url_str, token, &dropbox_download_url(), &dropbox_rpc_base())
    }

    /// Open with explicit token and endpoints (unit tests).
    ///
    /// Verifies the target path is a folder (or root) via metadata/list.
    pub fn open_with_endpoints(
        url_str: &str,
        token: &str,
        download_url: &str,
        rpc_base: &str,
    ) -> Result<Self> {
        if token.is_empty() {
            return Err(RemoteError::Dropbox(
                "DROPBOX_TOKEN is empty; cannot mount dropbox:// folders".into(),
            ));
        }
        let loc = parse_dropbox_url_allow_root(url_str)?;
        if !dropbox_path_is_folder(&loc.path, token, rpc_base)? {
            return Err(RemoteError::Dropbox(format!(
                "{} is a file, not a folder; use resolve_to_local / fetch_dropbox_to_temp for single-file materialize",
                loc
            )));
        }
        Ok(Self {
            root: loc.path,
            token: token.to_string(),
            download_url: download_url.to_string(),
            rpc_base: rpc_base.trim_end_matches('/').to_string(),
            list_ttl: Duration::from_secs(dropbox_list_ttl_secs()),
            listing_cache: Mutex::new(BTreeMap::new()),
            temp_files: Mutex::new(Vec::new()),
        })
    }

    /// Override listing cache TTL (e.g. tests). `0` disables caching.
    pub fn with_list_ttl_secs(mut self, secs: u64) -> Self {
        self.list_ttl = Duration::from_secs(secs);
        self
    }

    /// Dropbox API path for a virtual mount path.
    fn dropbox_path(&self, virtual_path: &str) -> String {
        let v = normpath(virtual_path);
        if v == "/" {
            return self.root.clone();
        }
        let rel = v.trim_start_matches('/');
        if self.root.is_empty() {
            format!("/{rel}")
        } else {
            format!("{}/{rel}", self.root.trim_end_matches('/'))
        }
    }

    fn list_dir_entries(&self, virtual_path: &str) -> Result<Vec<DropboxEntry>> {
        let v = normpath(virtual_path);
        let now = Instant::now();
        {
            let cache = self
                .listing_cache
                .lock()
                .map_err(|_| RemoteError::Dropbox("listing cache lock poisoned".into()))?;
            if let Some(cached) = cache.get(&v) {
                // TTL 0 → never hit; otherwise reuse while age < TTL.
                if !self.list_ttl.is_zero() && now.duration_since(cached.fetched_at) < self.list_ttl
                {
                    return Ok(cached.entries.clone());
                }
            }
        }
        let db_path = self.dropbox_path(&v);
        let entries = list_dropbox_folder(&db_path, &self.token, &self.rpc_base)?;
        let mut cache = self
            .listing_cache
            .lock()
            .map_err(|_| RemoteError::Dropbox("listing cache lock poisoned".into()))?;
        cache.insert(
            v,
            ListingCacheEntry {
                entries: entries.clone(),
                fetched_at: Instant::now(),
            },
        );
        Ok(entries)
    }

    fn lookup_entry(&self, virtual_path: &str) -> Result<Option<DropboxEntry>> {
        let v = normpath(virtual_path);
        if v == "/" {
            return Ok(Some(DropboxEntry {
                name: String::new(),
                path: self.root.clone(),
                kind: DropboxEntryKind::Folder,
                size: 0,
                server_modified: None,
            }));
        }
        // Prefer parent listing (one list_folder covers siblings).
        let parent = match v.rsplit_once('/') {
            Some(("", _)) => "/".to_string(),
            Some((p, _)) if !p.is_empty() => p.to_string(),
            _ => "/".to_string(),
        };
        let name = v.rsplit('/').next().unwrap_or("").to_string();
        let entries = self.list_dir_entries(&parent)?;
        if let Some(ent) = entries.into_iter().find(|e| e.name == name) {
            return Ok(Some(ent));
        }
        // Fallback: direct metadata
        let db_path = self.dropbox_path(&v);
        match get_dropbox_metadata(&db_path, &self.token, &self.rpc_base) {
            Ok(ent) => Ok(Some(ent)),
            Err(_) => Ok(None),
        }
    }
}

impl MountSource for DropboxMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let entries = self.list_dir_entries(path).ok()?;
        let mut map = BTreeMap::new();
        for ent in entries {
            // Ensure userdata holds absolute dropbox path for open.
            let mut fi = ent.to_file_info();
            if fi.userdata.is_empty() {
                fi.userdata = vec![UserData::Other(ent.path.clone())];
            }
            map.insert(ent.name, fi);
        }
        Some(ListResult::Infos(map))
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        // TTL map / list_folder entries already carry size+kind; do not call fat `list()`.
        let entries = self.list_dir_entries(path).ok()?;
        Some(
            entries
                .into_iter()
                .map(|ent| CheapDirent {
                    name: ent.name,
                    mode: match ent.kind {
                        DropboxEntryKind::Folder => S_IFDIR | 0o755,
                        DropboxEntryKind::File => S_IFREG | 0o644,
                    },
                    size: ent.size,
                })
                .collect(),
        )
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        let ent = self.lookup_entry(&path).ok().flatten()?;
        Some(ent.to_file_info())
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if is_dir_mode(file_info.mode) || file_info.mode & S_IFMT == S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let db_path = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Other(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing dropbox path userdata")
            })?;
        if db_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty dropbox path",
            ));
        }
        let loc = DropboxLocation {
            path: db_path.to_string(),
        };
        // Prefer chunked Range when size is known (from list/metadata) and large.
        let known_size = if file_info.size > 0 {
            Some(file_info.size)
        } else {
            None
        };
        let (tmp, size) = fetch_dropbox_location_to_temp_prefer_range(
            &loc,
            &self.token,
            &self.download_url,
            known_size,
        )
        .map_err(|e| io::Error::other(format!("dropbox download {db_path}: {e}")))?;

        // Small files: buffer in memory for a simple seekable handle.
        // Large files: keep temp path and open File.
        const MEMORY_THRESHOLD: u64 = 4 * 1024 * 1024;
        if size <= MEMORY_THRESHOLD {
            let mut buf = Vec::with_capacity(size as usize);
            let mut f = tmp.into_file();
            f.seek(SeekFrom::Start(0))?;
            f.read_to_end(&mut buf)?;
            return Ok(Box::new(Cursor::new(buf)));
        }

        let kept = tmp
            .into_temp_path()
            .keep()
            .map_err(|e| io::Error::other(format!("keep temp: {}", e.error)))?;
        {
            let mut guard = self
                .temp_files
                .lock()
                .map_err(|_| io::Error::other("temp_files lock poisoned"))?;
            guard.push(kept.clone());
        }
        Ok(Box::new(File::open(kept)?))
    }

    fn is_immutable(&self) -> bool {
        // Remote folder can change server-side; treat as mutable (no aggressive caching beyond list).
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
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
    fn parse_allow_root_empty() {
        for u in ["dropbox://", "dropbox:///", "dropbox:////"] {
            let loc = parse_dropbox_url_allow_root(u).unwrap();
            assert_eq!(loc.path, "", "url={u}");
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
        assert_eq!(extract_error_summary(body), Some("path/not_found/..."));
    }

    /// Minimal Dropbox content-API mock: POST + Bearer + Dropbox-API-Arg.
    struct MockDropbox {
        addr: String,
        posts: Arc<AtomicUsize>,
        log: Arc<StdMutex<Vec<String>>>,
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
        /// If true, honor `Range` with 206 + Content-Range.
        honor_range: bool,
    }

    fn parse_bytes_range(h: &str) -> Option<(u64, u64)> {
        let rest = h.trim().strip_prefix("bytes=")?;
        let (s, e) = rest.split_once('-')?;
        Some((s.parse().ok()?, e.parse().ok()?))
    }

    impl MockDropbox {
        fn spawn(cfg: MockDropboxConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let posts = Arc::new(AtomicUsize::new(0));
            let log = Arc::new(StdMutex::new(Vec::new()));
            let posts_c = Arc::clone(&posts);
            let log_c = Arc::clone(&log);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut content_length: usize = 0;
                    let mut auth_hdr: Option<String> = None;
                    let mut api_arg: Option<String> = None;
                    let mut range_hdr: Option<String> = None;
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
                        if let Some(v) = line.strip_prefix("Range:") {
                            range_hdr = Some(v.trim().to_string());
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
                        if let Some(r) = &range_hdr {
                            lg.push(format!("Range: {r}"));
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

                    if cfg.honor_range {
                        if let Some(rh) = range_hdr.as_deref().and_then(parse_bytes_range) {
                            let total = cfg.body.len() as u64;
                            if total == 0 {
                                let hdr = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n";
                                let _ = stream.write_all(hdr.as_bytes());
                                continue;
                            }
                            let start = rh.0.min(total - 1);
                            let end = rh.1.min(total - 1).max(start);
                            let slice = &cfg.body[start as usize..=end as usize];
                            let hdr = format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{total}\r\n\
                                 Content-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                                slice.len()
                            );
                            let _ = stream.write_all(hdr.as_bytes());
                            let _ = stream.write_all(slice);
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
            honor_range: false,
        });
        let loc = parse_dropbox_url("dropbox:///vault/a.tar").unwrap();
        let (mut tmp, size) =
            fetch_dropbox_location_to_temp(&loc, token, &mock.download_url()).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        // Probe (Range ignored → FullBody reuse) or single full GET.
        assert!(mock.posts.load(Ordering::SeqCst) >= 1);
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
            honor_range: false,
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

    // -----------------------------------------------------------------------
    // Combined RPC + content mock for folder browse
    // -----------------------------------------------------------------------

    #[derive(Clone)]
    struct FolderFile {
        /// Path relative to mount root folder, e.g. "a.tar" or "sub/b.txt"
        rel: String,
        body: Vec<u8>,
    }

    /// Mock that serves list_folder, get_metadata, and download on one listener.
    struct MockDropboxFs {
        addr: String,
        list_calls: Arc<AtomicUsize>,
        #[allow(dead_code)]
        meta_calls: Arc<AtomicUsize>,
        download_calls: Arc<AtomicUsize>,
        #[allow(dead_code)]
        log: Arc<StdMutex<Vec<String>>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockDropboxFs {
        /// `root` is the Dropbox path of the mounted folder (e.g. "/vault").
        fn spawn(token: &str, root: &str, files: Vec<FolderFile>, subfolders: Vec<String>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let list_calls = Arc::new(AtomicUsize::new(0));
            let meta_calls = Arc::new(AtomicUsize::new(0));
            let download_calls = Arc::new(AtomicUsize::new(0));
            let log = Arc::new(StdMutex::new(Vec::new()));
            let lc = Arc::clone(&list_calls);
            let mc = Arc::clone(&meta_calls);
            let dc = Arc::clone(&download_calls);
            let log_c = Arc::clone(&log);
            let token = token.to_string();
            let root = root.to_string();
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(128) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut content_length: usize = 0;
                    let mut auth_hdr: Option<String> = None;
                    let mut api_arg: Option<String> = None;
                    let mut range_hdr: Option<String> = None;
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
                        if let Some(v) = line.strip_prefix("Range:") {
                            range_hdr = Some(v.trim().to_string());
                        }
                        let lower = line.to_ascii_lowercase();
                        if lower.starts_with("dropbox-api-arg:") {
                            api_arg = Some(line.split_once(':').unwrap().1.trim().to_string());
                        }
                    }
                    let mut body_bytes = vec![0u8; content_length];
                    if content_length > 0 {
                        let _ = Read::read_exact(&mut reader, &mut body_bytes);
                    }
                    let req_body = String::from_utf8_lossy(&body_bytes).into_owned();

                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if !req_body.is_empty() {
                            lg.push(format!("body: {req_body}"));
                        }
                        if let Some(r) = &range_hdr {
                            lg.push(format!("Range: {r}"));
                        }
                    }

                    let expected_auth = format!("Bearer {token}");
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

                    let path_part = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .to_string();

                    // Download: Dropbox-API-Arg header (honor Range with 206 when present).
                    if path_part.contains("/files/download") {
                        dc.fetch_add(1, Ordering::SeqCst);
                        let want = api_arg.as_deref().unwrap_or("");
                        // Match {"path":"..."}
                        let mut found: Option<&FolderFile> = None;
                        for f in &files {
                            let full = if root.is_empty() {
                                format!("/{}", f.rel)
                            } else {
                                format!("{}/{}", root.trim_end_matches('/'), f.rel)
                            };
                            if want.contains(&full) {
                                found = Some(f);
                                break;
                            }
                        }
                        if let Some(f) = found {
                            if let Some(rh) = range_hdr.as_deref().and_then(parse_bytes_range) {
                                let total = f.body.len() as u64;
                                if total == 0 {
                                    let hdr = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n";
                                    let _ = stream.write_all(hdr.as_bytes());
                                    continue;
                                }
                                let start = rh.0.min(total - 1);
                                let end = rh.1.min(total - 1).max(start);
                                let slice = &f.body[start as usize..=end as usize];
                                let hdr = format!(
                                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{total}\r\n\
                                     Content-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                                    slice.len()
                                );
                                let _ = stream.write_all(hdr.as_bytes());
                                let _ = stream.write_all(slice);
                            } else {
                                let hdr = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                                    f.body.len()
                                );
                                let _ = stream.write_all(hdr.as_bytes());
                                let _ = stream.write_all(&f.body);
                            }
                        } else {
                            let body = br#"{"error_summary": "path/not_found/..."}"#;
                            let _ = write!(
                                stream,
                                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(body);
                        }
                        continue;
                    }

                    // get_metadata
                    if path_part.contains("/files/get_metadata") {
                        mc.fetch_add(1, Ordering::SeqCst);
                        let path = extract_json_string_field(&req_body, "path").unwrap_or_default();
                        if path == root || (path.is_empty() && root.is_empty()) {
                            let name = if root.is_empty() {
                                String::new()
                            } else {
                                root.rsplit('/').next().unwrap_or("").to_string()
                            };
                            let json = format!(
                                r#"{{".tag":"folder","name":"{name}","path_display":"{path}","path_lower":"{}"}}"#,
                                path.to_ascii_lowercase()
                            );
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                json.len(),
                                json
                            );
                            continue;
                        }
                        // file under root?
                        let mut found_file = None;
                        for f in &files {
                            let full = if root.is_empty() {
                                format!("/{}", f.rel)
                            } else {
                                format!("{}/{}", root.trim_end_matches('/'), f.rel)
                            };
                            if path == full {
                                found_file = Some((f, full));
                                break;
                            }
                        }
                        if let Some((f, full)) = found_file {
                            let name = f.rel.rsplit('/').next().unwrap_or(&f.rel);
                            let json = format!(
                                r#"{{".tag":"file","name":"{name}","path_display":"{full}","path_lower":"{}","size":{},"server_modified":"2020-01-02T03:04:05Z"}}"#,
                                full.to_ascii_lowercase(),
                                f.body.len()
                            );
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                json.len(),
                                json
                            );
                            continue;
                        }
                        // subfolder?
                        let mut found_folder = false;
                        for sf in &subfolders {
                            let full = if root.is_empty() {
                                format!("/{sf}")
                            } else {
                                format!("{}/{}", root.trim_end_matches('/'), sf)
                            };
                            if path == full {
                                let name = sf.rsplit('/').next().unwrap_or(sf);
                                let json = format!(
                                    r#"{{".tag":"folder","name":"{name}","path_display":"{full}","path_lower":"{}"}}"#,
                                    full.to_ascii_lowercase()
                                );
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    json.len(),
                                    json
                                );
                                found_folder = true;
                                break;
                            }
                        }
                        if found_folder {
                            continue;
                        }
                        let body = br#"{"error_summary": "path/not_found/..."}"#;
                        let _ = write!(
                            stream,
                            "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(body);
                        continue;
                    }

                    // list_folder / continue
                    if path_part.contains("/files/list_folder/continue") {
                        // No pagination in this mock — empty more.
                        let json = r#"{"entries":[],"cursor":"","has_more":false}"#;
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json.len(),
                            json
                        );
                        continue;
                    }

                    if path_part.contains("/files/list_folder") {
                        lc.fetch_add(1, Ordering::SeqCst);
                        let list_path =
                            extract_json_string_field(&req_body, "path").unwrap_or_default();
                        // Only root listing supported for this mock.
                        if list_path != root && !(list_path.is_empty() && root.is_empty()) {
                            // Subfolder listing: only files with rel under that subfolder
                            let prefix = if root.is_empty() {
                                list_path.trim_start_matches('/').to_string()
                            } else {
                                list_path
                                    .strip_prefix(&format!("{}/", root.trim_end_matches('/')))
                                    .unwrap_or("")
                                    .to_string()
                            };
                            let mut ents = Vec::new();
                            for f in &files {
                                if let Some(rest) = f.rel.strip_prefix(&format!("{prefix}/")) {
                                    if !rest.contains('/') {
                                        let full = if root.is_empty() {
                                            format!("/{}", f.rel)
                                        } else {
                                            format!("{}/{}", root.trim_end_matches('/'), f.rel)
                                        };
                                        ents.push(format!(
                                            r#"{{".tag":"file","name":"{rest}","path_display":"{full}","path_lower":"{}","size":{},"server_modified":"2020-01-02T03:04:05Z"}}"#,
                                            full.to_ascii_lowercase(),
                                            f.body.len()
                                        ));
                                    }
                                }
                            }
                            let json = format!(
                                r#"{{"entries":[{}],"cursor":"c1","has_more":false}}"#,
                                ents.join(",")
                            );
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                json.len(),
                                json
                            );
                            continue;
                        }

                        let mut ents = Vec::new();
                        // Immediate files (no / in rel)
                        for f in &files {
                            if !f.rel.contains('/') {
                                let full = if root.is_empty() {
                                    format!("/{}", f.rel)
                                } else {
                                    format!("{}/{}", root.trim_end_matches('/'), f.rel)
                                };
                                ents.push(format!(
                                    r#"{{".tag":"file","name":"{}","path_display":"{full}","path_lower":"{}","size":{},"server_modified":"2020-01-02T03:04:05Z"}}"#,
                                    f.rel,
                                    full.to_ascii_lowercase(),
                                    f.body.len()
                                ));
                            }
                        }
                        // Top-level subfolders
                        for sf in &subfolders {
                            if !sf.contains('/') {
                                let full = if root.is_empty() {
                                    format!("/{sf}")
                                } else {
                                    format!("{}/{}", root.trim_end_matches('/'), sf)
                                };
                                ents.push(format!(
                                    r#"{{".tag":"folder","name":"{sf}","path_display":"{full}","path_lower":"{}"}}"#,
                                    full.to_ascii_lowercase()
                                ));
                            }
                        }
                        let json = format!(
                            r#"{{"entries":[{}],"cursor":"c0","has_more":false}}"#,
                            ents.join(",")
                        );
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json.len(),
                            json
                        );
                        continue;
                    }

                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                }
            });
            Self {
                addr,
                list_calls,
                meta_calls,
                download_calls,
                log,
                _join: Some(join),
            }
        }

        fn rpc_base(&self) -> String {
            self.addr.clone()
        }

        fn download_url(&self) -> String {
            format!("{}/2/files/download", self.addr)
        }
    }

    fn extract_json_string_field(body: &str, key: &str) -> Option<String> {
        let pat = format!("\"{key}\"");
        let idx = body.find(&pat)?;
        let after = body[idx + pat.len()..].trim_start();
        let after = after.strip_prefix(':')?.trim_start();
        let after = after.strip_prefix('"')?;
        let end = after.find('"')?;
        Some(after[..end].to_string())
    }

    #[test]
    fn list_folder_with_mock() {
        let token = "sl.folder-token";
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![
                FolderFile {
                    rel: "a.tar".into(),
                    body: b"AAA".to_vec(),
                },
                FolderFile {
                    rel: "notes.txt".into(),
                    body: b"hello notes".to_vec(),
                },
            ],
            vec!["subdir".into()],
        );
        let entries = list_dropbox_folder("/vault", token, &mock.rpc_base()).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.tar"), "{names:?}");
        assert!(names.contains(&"notes.txt"), "{names:?}");
        assert!(names.contains(&"subdir"), "{names:?}");
        let a = entries.iter().find(|e| e.name == "a.tar").unwrap();
        assert_eq!(a.kind, DropboxEntryKind::File);
        assert_eq!(a.size, 3);
        assert_eq!(a.path, "/vault/a.tar");
        let sub = entries.iter().find(|e| e.name == "subdir").unwrap();
        assert_eq!(sub.kind, DropboxEntryKind::Folder);
        assert!(mock.list_calls.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn get_metadata_folder_and_file() {
        let token = "sl.meta-token";
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![FolderFile {
                rel: "a.tar".into(),
                body: b"data".to_vec(),
            }],
            vec![],
        );
        let folder = get_dropbox_metadata("/vault", token, &mock.rpc_base()).unwrap();
        assert_eq!(folder.kind, DropboxEntryKind::Folder);
        let file = get_dropbox_metadata("/vault/a.tar", token, &mock.rpc_base()).unwrap();
        assert_eq!(file.kind, DropboxEntryKind::File);
        assert_eq!(file.size, 4);
        assert!(dropbox_path_is_folder("/vault", token, &mock.rpc_base()).unwrap());
        assert!(!dropbox_path_is_folder("/vault/a.tar", token, &mock.rpc_base()).unwrap());
    }

    #[test]
    fn mount_source_list_and_open() {
        let token = "sl.mount-token";
        let file_body = b"dropbox-folder-file-bytes".to_vec();
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![
                FolderFile {
                    rel: "a.tar".into(),
                    body: file_body.clone(),
                },
                FolderFile {
                    rel: "readme.txt".into(),
                    body: b"readme".to_vec(),
                },
            ],
            vec!["nested".into()],
        );
        let ms = DropboxMountSource::open_with_endpoints(
            "dropbox:///vault",
            token,
            &mock.download_url(),
            &mock.rpc_base(),
        )
        .unwrap();

        assert!(ms.is_dir("/"));
        let list = ms.list("/").expect("list root");
        let ListResult::Infos(map) = list else {
            panic!("expected Infos");
        };
        assert!(map.contains_key("a.tar"), "{map:?}");
        assert!(map.contains_key("readme.txt"), "{map:?}");
        assert!(map.contains_key("nested"), "{map:?}");
        assert!(is_dir_mode(map["nested"].mode));
        assert!(!is_dir_mode(map["a.tar"].mode));

        let fi = ms.lookup("/a.tar", 0).expect("lookup a.tar");
        assert_eq!(fi.size, file_body.len() as u64);
        let mut reader = ms.open(&fi, 0).unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, file_body);
        assert!(mock.download_calls.load(Ordering::SeqCst) >= 1);

        // Opening a folder must fail.
        let nested = ms.lookup("/nested", 0).unwrap();
        assert!(ms.open(&nested, 0).is_err());
    }

    /// Regression: cheap list_dirents must expose index sizes (readdirplus TTL).
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let token = "sl.dirents-token";
        let file_body = b"dropbox-dirent-bytes";
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![
                FolderFile {
                    rel: "a.tar".into(),
                    body: file_body.to_vec(),
                },
                FolderFile {
                    rel: "readme.txt".into(),
                    body: b"readme".to_vec(),
                },
            ],
            vec!["nested".into()],
        );
        let ms = DropboxMountSource::open_with_endpoints(
            "dropbox:///vault",
            token,
            &mock.download_url(),
            &mock.rpc_base(),
        )
        .unwrap();

        let dents = ms.list_dirents("/").expect("dirents");
        let a = dents.iter().find(|d| d.name == "a.tar").expect("a.tar");
        assert_eq!(a.size, file_body.len() as u64);
        assert_eq!(a.mode & S_IFMT, S_IFREG);
        let nested = dents.iter().find(|d| d.name == "nested").expect("nested");
        assert_eq!(nested.size, 0);
        assert_eq!(nested.mode & S_IFMT, S_IFDIR);
        assert_eq!(ms.lookup("/a.tar", 0).unwrap().size, a.size);
        assert_eq!(ms.lookup("/readme.txt", 0).unwrap().size, 6);
        // fat `list()` is not required for sized dirents (TTL map / recorded entries).
    }

    #[test]
    fn mount_source_rejects_file_url() {
        let token = "sl.file-only";
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![FolderFile {
                rel: "only.tar".into(),
                body: b"x".to_vec(),
            }],
            vec![],
        );
        // Mounting a file path should error with a clear message.
        let err = DropboxMountSource::open_with_endpoints(
            "dropbox:///vault/only.tar",
            token,
            &mock.download_url(),
            &mock.rpc_base(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("file") || msg.contains("folder"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn mount_source_nested_list() {
        let token = "sl.nested";
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![
                FolderFile {
                    rel: "top.txt".into(),
                    body: b"top".to_vec(),
                },
                FolderFile {
                    rel: "nested/inner.bin".into(),
                    body: b"inner-bytes".to_vec(),
                },
            ],
            vec!["nested".into()],
        );
        let ms = DropboxMountSource::open_with_endpoints(
            "dropbox:///vault",
            token,
            &mock.download_url(),
            &mock.rpc_base(),
        )
        .unwrap();
        let list = ms.list("/nested").expect("list nested");
        let ListResult::Infos(map) = list else {
            panic!("expected Infos");
        };
        assert!(map.contains_key("inner.bin"), "{map:?}");
        let fi = ms.lookup("/nested/inner.bin", 0).unwrap();
        let mut r = ms.open(&fi, 0).unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"inner-bytes");
    }

    #[test]
    fn listing_cache_ttl_revalidates() {
        let token = "sl.ttl-token";
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![FolderFile {
                rel: "a.txt".into(),
                body: b"x".to_vec(),
            }],
            vec![],
        );

        // TTL disabled: every list re-fetches.
        let ms_no_cache = DropboxMountSource::open_with_endpoints(
            "dropbox:///vault",
            token,
            &mock.download_url(),
            &mock.rpc_base(),
        )
        .unwrap()
        .with_list_ttl_secs(0);
        let _ = ms_no_cache.list("/").expect("list 1");
        let after_first = mock.list_calls.load(Ordering::SeqCst);
        let _ = ms_no_cache.list("/").expect("list 2");
        let after_second = mock.list_calls.load(Ordering::SeqCst);
        assert!(
            after_second > after_first,
            "TTL=0 should re-fetch: first={after_first} second={after_second}"
        );

        // Long TTL: second list hits cache.
        let before_cached = mock.list_calls.load(Ordering::SeqCst);
        let ms_cached = DropboxMountSource::open_with_endpoints(
            "dropbox:///vault",
            token,
            &mock.download_url(),
            &mock.rpc_base(),
        )
        .unwrap()
        .with_list_ttl_secs(3600);
        let _ = ms_cached.list("/").expect("list warm");
        let after_warm = mock.list_calls.load(Ordering::SeqCst);
        assert!(after_warm > before_cached, "warm list should RPC");
        let _ = ms_cached.list("/").expect("list cached");
        assert_eq!(
            mock.list_calls.load(Ordering::SeqCst),
            after_warm,
            "long TTL should not re-fetch"
        );
    }

    #[test]
    fn listing_cache_expires_after_ttl() {
        let token = "sl.ttl-expire";
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![FolderFile {
                rel: "b.txt".into(),
                body: b"y".to_vec(),
            }],
            vec![],
        );
        let ms = DropboxMountSource::open_with_endpoints(
            "dropbox:///vault",
            token,
            &mock.download_url(),
            &mock.rpc_base(),
        )
        .unwrap()
        .with_list_ttl_secs(1);
        let _ = ms.list("/").expect("list warm");
        let after_warm = mock.list_calls.load(Ordering::SeqCst);
        // Still within TTL.
        let _ = ms.list("/").expect("list within ttl");
        assert_eq!(mock.list_calls.load(Ordering::SeqCst), after_warm);
        // Sleep past TTL.
        thread::sleep(Duration::from_millis(1100));
        let _ = ms.list("/").expect("list after ttl");
        assert!(
            mock.list_calls.load(Ordering::SeqCst) > after_warm,
            "expired cache should re-fetch"
        );
    }

    #[test]
    fn range_bytes_prefix_helper() {
        let body: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let token = "sl.range-prefix";
        let mock = MockDropbox::spawn(MockDropboxConfig {
            body: body.clone(),
            require_token: token.into(),
            require_path: Some("/big.bin".into()),
            force_unauthorized: false,
            honor_range: true,
        });
        let loc = parse_dropbox_url("dropbox:///big.bin").unwrap();
        let got = fetch_dropbox_range_bytes(&loc, token, &mock.download_url(), 10, 19).unwrap();
        assert_eq!(got, &body[10..=19]);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.contains("Range: bytes=10-19")),
            "log={log:?}"
        );
        assert_eq!(mock.posts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn prefer_range_chunked_download() {
        // > threshold and multi-chunk relative to HTTP_RANGE_CHUNK when large enough.
        // Use size just above DEFAULT_DROPBOX_RANGE_THRESHOLD so we take the Range path;
        // with HTTP_RANGE_CHUNK (4 MiB) this is still a single window — assert Range used.
        let size = (DEFAULT_DROPBOX_RANGE_THRESHOLD + 64 * 1024) as usize;
        let body: Vec<u8> = (0u8..=251).cycle().take(size).collect();
        let token = "sl.range-chunk";
        let mock = MockDropbox::spawn(MockDropboxConfig {
            body: body.clone(),
            require_token: token.into(),
            require_path: Some("/large.bin".into()),
            force_unauthorized: false,
            honor_range: true,
        });
        let loc = parse_dropbox_url("dropbox:///large.bin").unwrap();
        let (mut tmp, n) = fetch_dropbox_location_to_temp_prefer_range(
            &loc,
            token,
            &mock.download_url(),
            Some(body.len() as u64),
        )
        .unwrap();
        assert_eq!(n, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("Range: bytes=")),
            "expected Range GETs, log={log:?}"
        );
        // Full-body path would be a single POST without Range after known_size branch.
        assert!(mock.posts.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn prefer_range_multi_chunk_download() {
        // Force multiple Range windows: size > HTTP_RANGE_CHUNK.
        let size = (HTTP_RANGE_CHUNK + 128 * 1024) as usize;
        let body: Vec<u8> = (0u8..=251).cycle().take(size).collect();
        let token = "sl.range-multi";
        let mock = MockDropbox::spawn(MockDropboxConfig {
            body: body.clone(),
            require_token: token.into(),
            require_path: Some("/huge.bin".into()),
            force_unauthorized: false,
            honor_range: true,
        });
        let loc = parse_dropbox_url("dropbox:///huge.bin").unwrap();
        let (mut tmp, n) = fetch_dropbox_location_to_temp_prefer_range(
            &loc,
            token,
            &mock.download_url(),
            Some(body.len() as u64),
        )
        .unwrap();
        assert_eq!(n, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let posts = mock.posts.load(Ordering::SeqCst);
        assert!(
            posts >= 2,
            "expected multi-chunk Range download, posts={posts}"
        );
        let log = mock.log.lock().unwrap();
        let range_lines: Vec<_> = log
            .iter()
            .filter(|l| l.starts_with("Range: bytes="))
            .collect();
        assert!(
            range_lines.len() >= 2,
            "expected ≥2 Range headers, log={log:?}"
        );
    }

    #[test]
    fn mount_source_open_large_uses_range() {
        let size = (DEFAULT_DROPBOX_RANGE_THRESHOLD + 32 * 1024) as usize;
        let body: Vec<u8> = (0u8..=199).cycle().take(size).collect();
        let token = "sl.mount-range";
        let mock = MockDropboxFs::spawn(
            token,
            "/vault",
            vec![FolderFile {
                rel: "big.bin".into(),
                body: body.clone(),
            }],
            vec![],
        );
        let ms = DropboxMountSource::open_with_endpoints(
            "dropbox:///vault",
            token,
            &mock.download_url(),
            &mock.rpc_base(),
        )
        .unwrap();
        let fi = ms.lookup("/big.bin", 0).expect("lookup");
        assert_eq!(fi.size, body.len() as u64);
        let mut r = ms.open(&fi, 0).unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("Range: bytes=")),
            "mount open of large file should Range, log={log:?}"
        );
    }

    #[test]
    fn dropbox_list_ttl_secs_default() {
        // Do not mutate env if already set; just sanity-check the constant path.
        if std::env::var("RATARMOUNT_DROPBOX_LIST_TTL_SECS").is_err() {
            assert_eq!(dropbox_list_ttl_secs(), DEFAULT_DROPBOX_LIST_TTL_SECS);
        }
    }
}
