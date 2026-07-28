//! Remote URL access for Phase 10.
//!
//! - `file://` → local path
//! - `http(s)://` → fetch to temp (prefer Range when supported) and live Range I/O via
//!   [`resolve_http`] / [`open_http_range`] / [`HttpRangeFile`]
//! - `s3://bucket/key` → GetObject to temp (AWS env credentials)
//! - `ssh://` / `sftp://` / `scp://` → SFTP download to temp
//! - `webdav://` / `webdavs://` → WebDAV GET to temp (optional PROPFIND, Basic auth)
//! - `smb://` → download via Samba `smbclient` CLI when present
//! - `dropbox://` → Dropbox content API download to temp (`DROPBOX_TOKEN`); folder browse via
//!   [`DropboxMountSource`] (`files/list_folder` + download on open)
//! - other schemes → clear "not yet" errors

mod dropbox;
mod s3;
mod smb;
mod ssh;
mod webdav;

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use log::debug;
use tempfile::NamedTempFile;
use thiserror::Error;
use url::Url;

pub use dropbox::{
    dropbox_api_arg, dropbox_download_url, dropbox_path_is_folder, dropbox_rpc_base,
    fetch_dropbox_location_to_temp, fetch_dropbox_to_temp, get_dropbox_metadata,
    list_dropbox_folder, load_dropbox_token, parse_dropbox_url, parse_dropbox_url_allow_root,
    redact_token, DropboxEntry, DropboxEntryKind, DropboxLocation, DropboxMountSource,
    DEFAULT_DROPBOX_DOWNLOAD_URL, DEFAULT_DROPBOX_RPC_BASE,
};
pub use s3::{fetch_s3_to_temp, parse_s3_url, S3Location};
pub use smb::{
    fetch_smb_to_temp, find_smbclient, parse_smb_url, smbclient_download_args, SmbLocation,
};
pub use ssh::{fetch_ssh_to_temp, parse_ssh_url, SshLocation};
pub use webdav::{
    fetch_webdav_to_temp, parse_getcontentlength, parse_webdav_url, propfind_content_length,
    WebDavLocation,
};

/// Chunk size for sequential Range GET materialization (4 MiB).
pub const HTTP_RANGE_CHUNK: u64 = 4 * 1024 * 1024;

pub(crate) const USER_AGENT: &str = "ratarmount-rs/0.1";

#[derive(Debug, Error)]
pub enum RemoteError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("url: {0}")]
    Url(String),
    #[error("http: {0}")]
    Http(String),
    #[error("s3: {0}")]
    S3(String),
    #[error("ssh: {0}")]
    Ssh(String),
    #[error("webdav: {0}")]
    WebDav(String),
    #[error("smb: {0}")]
    Smb(String),
    #[error("dropbox: {0}")]
    Dropbox(String),
    #[error("unsupported remote scheme: {0}")]
    UnsupportedScheme(String),
}

pub type Result<T> = std::result::Result<T, RemoteError>;

/// True if `s` looks like a URL with a scheme (not a bare Windows path).
pub fn is_remote_url(s: &str) -> bool {
    Url::parse(s).is_ok_and(|u| {
        matches!(
            u.scheme(),
            "http"
                | "https"
                | "file"
                | "ftp"
                | "s3"
                | "ssh"
                | "sftp"
                | "scp"
                | "smb"
                | "webdav"
                | "webdavs"
                | "dropbox"
        )
    })
}

/// Resolve a path or URL to a local filesystem path suitable for openers.
/// Remote schemes download into a kept temp file; caller must keep [`RemoteLocal`] alive.
pub fn resolve_to_local(input: &str) -> Result<RemoteLocal> {
    if !is_remote_url(input) {
        return Ok(RemoteLocal::Local(PathBuf::from(input)));
    }
    let url = Url::parse(input).map_err(|e| RemoteError::Url(e.to_string()))?;
    match url.scheme() {
        "file" => {
            let path = url
                .to_file_path()
                .map_err(|_| RemoteError::Url(format!("invalid file URL: {input}")))?;
            Ok(RemoteLocal::Local(path))
        }
        "http" | "https" => {
            // Prefer Range materialization when the server supports it (fsspec-style path).
            let (tmp, size) = fetch_http_to_temp_prefer_range(url.as_str())?;
            keep_fetched(input, tmp, size)
        }
        "s3" => {
            let (tmp, size) = fetch_s3_to_temp(input)?;
            keep_fetched(input, tmp, size)
        }
        "ssh" | "sftp" | "scp" => {
            let (tmp, size) = fetch_ssh_to_temp(input)?;
            keep_fetched(input, tmp, size)
        }
        "webdav" | "webdavs" => {
            let (tmp, size) = fetch_webdav_to_temp(input)?;
            keep_fetched(input, tmp, size)
        }
        "smb" => {
            let (tmp, size) = fetch_smb_to_temp(input)?;
            keep_fetched(input, tmp, size)
        }
        "dropbox" => {
            let (tmp, size) = fetch_dropbox_to_temp(input)?;
            keep_fetched(input, tmp, size)
        }
        other => Err(RemoteError::UnsupportedScheme(other.to_string())),
    }
}

fn keep_fetched(input: &str, tmp: NamedTempFile, size: u64) -> Result<RemoteLocal> {
    let path = tmp
        .into_temp_path()
        .keep()
        .map_err(|e| RemoteError::Io(e.error))?;
    debug!("fetched {input} -> {} ({size} bytes)", path.display());
    Ok(RemoteLocal::Fetched { path, size })
}

/// Local path plus optional lifetime for fetched remote bodies.
#[derive(Debug)]
pub enum RemoteLocal {
    Local(PathBuf),
    /// Downloaded remote object; path is deleted when dropped unless `persist`.
    Fetched {
        path: PathBuf,
        size: u64,
    },
}

impl RemoteLocal {
    pub fn path(&self) -> &Path {
        match self {
            Self::Local(p) | Self::Fetched { path: p, .. } => p,
        }
    }
}

impl Drop for RemoteLocal {
    fn drop(&mut self) {
        if let Self::Fetched { path, .. } = self {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Metadata from an HTTP probe (HEAD and/or Range GET).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProbe {
    pub content_length: Option<u64>,
    /// True when the server advertises or demonstrates byte-range support.
    pub accept_ranges: bool,
}

/// Parse `Content-Range: bytes start-end/total` and return `total` when present.
pub fn parse_content_range_total(header: Option<&str>) -> Option<u64> {
    let h = header?;
    // e.g. "bytes 0-0/12345" or "bytes 0-1023/*"
    let after_slash = h.rsplit_once('/')?.1.trim();
    if after_slash == "*" {
        return None;
    }
    after_slash.parse().ok()
}

/// Whether `Accept-Ranges` (or equivalent) indicates byte ranges are usable.
pub fn accept_ranges_bytes(header: Option<&str>) -> bool {
    header
        .map(|s| {
            let lower = s.to_ascii_lowercase();
            lower.contains("bytes") && !lower.contains("none")
        })
        .unwrap_or(false)
}

/// Compute inclusive byte-range windows for sequential chunk download.
///
/// Returns `(start, end_inclusive)` pairs covering `0..size` in steps of `chunk`.
pub fn range_chunk_windows(size: u64, chunk: u64) -> Vec<(u64, u64)> {
    if size == 0 || chunk == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0u64;
    while start < size {
        let end = (start + chunk - 1).min(size - 1);
        out.push((start, end));
        start = end + 1;
    }
    out
}

/// Probe an HTTP(S) URL for Content-Length and Accept-Ranges support.
///
/// Tries HEAD first; on failure or missing length with ranges advertised, probes with
/// `Range: bytes=0-0` (206 + Content-Range total).
pub fn probe_http(url: &str) -> Result<HttpProbe> {
    match ureq::head(url)
        .set("User-Agent", USER_AGENT)
        .call()
    {
        Ok(resp) if (200..300).contains(&resp.status()) => {
            let content_length = resp
                .header("Content-Length")
                .and_then(|s| s.parse::<u64>().ok());
            let accept_ranges = accept_ranges_bytes(resp.header("Accept-Ranges"));
            if accept_ranges && content_length.is_some() {
                return Ok(HttpProbe {
                    content_length,
                    accept_ranges: true,
                });
            }
            if accept_ranges {
                // Ranges OK but size unknown — try Content-Range probe.
                if let Some(probe) = probe_range_size(url)? {
                    return Ok(probe);
                }
            }
            // No usable range path from HEAD alone.
            if content_length.is_some() && !accept_ranges {
                return Ok(HttpProbe {
                    content_length,
                    accept_ranges: false,
                });
            }
            // Fall through to range probe when length missing or ambiguous.
            if let Some(probe) = probe_range_size(url)? {
                return Ok(probe);
            }
            return Ok(HttpProbe {
                content_length,
                accept_ranges: false,
            });
        }
        Ok(resp) => {
            debug!("HEAD {url} -> {}, probing with Range GET", resp.status());
        }
        Err(e) => {
            debug!("HEAD {url} failed: {e}, probing with Range GET");
        }
    }

    if let Some(probe) = probe_range_size(url)? {
        return Ok(probe);
    }

    // Last resort: no size / no ranges from probes; full GET will discover body length.
    Ok(HttpProbe {
        content_length: None,
        accept_ranges: false,
    })
}

/// Issue `GET` with `Range: bytes=0-0`. Returns probe meta on 206; `None` if ranges unusable.
fn probe_range_size(url: &str) -> Result<Option<HttpProbe>> {
    let resp = match ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Range", "bytes=0-0")
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            debug!("Range probe {url} failed: {e}");
            return Ok(None);
        }
    };
    let status = resp.status();
    if status == 206 {
        // Prefer Content-Range total (Content-Length on 206 is only the partial length).
        let total = parse_content_range_total(resp.header("Content-Range"));
        return Ok(Some(HttpProbe {
            content_length: total,
            accept_ranges: true,
        }));
    }
    if (200..300).contains(&status) {
        // Server ignored Range (full body). Not usable as range-capable.
        let content_length = resp
            .header("Content-Length")
            .and_then(|s| s.parse::<u64>().ok());
        return Ok(Some(HttpProbe {
            content_length,
            accept_ranges: false,
        }));
    }
    debug!("Range probe {url} -> HTTP {status}");
    Ok(None)
}

/// Full GET download to a tempfile (works without Range support).
pub fn fetch_http_to_temp(url: &str) -> Result<(NamedTempFile, u64)> {
    fetch_http_full_get(url)
}

/// Download via sequential Range GETs when supported; otherwise full GET.
///
/// Used by [`resolve_to_local`] so the factory materialization path benefits without
/// factory changes. Matches the Python fsspec-style prefer-range path.
pub fn fetch_http_to_temp_prefer_range(url: &str) -> Result<(NamedTempFile, u64)> {
    let probe = probe_http(url)?;
    if probe.accept_ranges {
        if let Some(size) = probe.content_length {
            debug!(
                "HTTP prefer-range: downloading {url} ({size} bytes) in {}-byte chunks",
                HTTP_RANGE_CHUNK
            );
            match fetch_http_via_ranges(url, size) {
                Ok(v) => return Ok(v),
                Err(e) => {
                    debug!("HTTP range download failed for {url}: {e}; falling back to full GET");
                }
            }
        }
    }
    debug!("HTTP full GET for {url} (ranges unavailable or incomplete probe)");
    fetch_http_full_get(url)
}

fn fetch_http_full_get(url: &str) -> Result<(NamedTempFile, u64)> {
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| RemoteError::Http(e.to_string()))?;
    if !(200..300).contains(&resp.status()) {
        return Err(RemoteError::Http(format!(
            "HTTP {} for {url}",
            resp.status()
        )));
    }
    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    tmp.as_file().seek(SeekFrom::Start(0))?;
    Ok((tmp, n))
}

/// Sequential Range GET materialization into a tempfile.
fn fetch_http_via_ranges(url: &str, size: u64) -> Result<(NamedTempFile, u64)> {
    let mut tmp = NamedTempFile::new()?;
    if size == 0 {
        tmp.flush()?;
        return Ok((tmp, 0));
    }
    let mut written = 0u64;
    for (start, end) in range_chunk_windows(size, HTTP_RANGE_CHUNK) {
        let range = format!("bytes={start}-{end}");
        let resp = ureq::get(url)
            .set("User-Agent", USER_AGENT)
            .set("Range", &range)
            .call()
            .map_err(|e| RemoteError::Http(e.to_string()))?;
        let status = resp.status();
        if status == 206 {
            let mut reader = resp.into_reader();
            let expected = end - start + 1;
            let n = io::copy(&mut reader, &mut tmp)?;
            if n != expected {
                return Err(RemoteError::Http(format!(
                    "range {range} returned {n} bytes, expected {expected}"
                )));
            }
            written += n;
        } else if status == 200 && start == 0 {
            // Server ignored Range and returned the full body on the first chunk.
            let mut reader = resp.into_reader();
            let n = io::copy(&mut reader, &mut tmp)?;
            tmp.flush()?;
            tmp.as_file().seek(SeekFrom::Start(0))?;
            return Ok((tmp, n));
        } else {
            return Err(RemoteError::Http(format!(
                "HTTP {status} for range {range} on {url}"
            )));
        }
    }
    if written != size {
        return Err(RemoteError::Http(format!(
            "range download size mismatch: wrote {written}, expected {size}"
        )));
    }
    tmp.flush()?;
    tmp.as_file().seek(SeekFrom::Start(0))?;
    Ok((tmp, written))
}

/// Seekable HTTP reader using Range requests when the server supports them.
/// Falls back to full download into memory if ranges are unavailable.
///
/// Prefer [`open_http_range`] / [`resolve_http`] for the public entry points.
/// [`resolve_to_local`] still fully materializes HTTP(S) for path-based openers.
pub struct HttpRangeFile {
    url: String,
    size: u64,
    pos: u64,
    /// Optional fully buffered body if ranges unavailable
    buffered: Option<Vec<u8>>,
}

impl std::fmt::Debug for HttpRangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRangeFile")
            .field("url", &self.url)
            .field("size", &self.size)
            .field("pos", &self.pos)
            .field("uses_ranges", &self.uses_ranges())
            .finish()
    }
}

impl HttpRangeFile {
    /// Open `url`, using live Range GETs when the server supports ranges and size is known.
    ///
    /// Without usable ranges, buffers the full response body in memory.
    pub fn open(url: &str) -> Result<Self> {
        let probe = probe_http(url)?;
        if probe.accept_ranges {
            if let Some(size) = probe.content_length {
                return Ok(Self::range_backed(url, size));
            }
        }

        // Fallback: full download into memory (fine for test fixtures / small objects)
        let (mut tmp, size) = fetch_http_full_get(url)?;
        let mut buf = Vec::with_capacity(size as usize);
        tmp.read_to_end(&mut buf)?;
        Ok(Self {
            url: url.to_string(),
            size: buf.len() as u64,
            pos: 0,
            buffered: Some(buf),
        })
    }

    /// Construct a live Range-backed reader (no probe; caller must know size).
    pub fn range_backed(url: &str, size: u64) -> Self {
        Self {
            url: url.to_string(),
            size,
            pos: 0,
            buffered: None,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// True when reads issue live Range GETs (not a fully buffered body).
    pub fn uses_ranges(&self) -> bool {
        self.buffered.is_none()
    }
}

/// Open a seekable HTTP reader using live Range GETs when possible.
///
/// Equivalent to [`HttpRangeFile::open`].
pub fn open_http_range(url: &str) -> Result<HttpRangeFile> {
    HttpRangeFile::open(url)
}

/// HTTP access preferring live Range I/O over full materialization.
///
/// Unlike [`resolve_to_local`] (which always produces a local path for HTTP), this returns a
/// live [`HttpRangeFile`] when the server supports byte ranges and the object size is known.
#[derive(Debug)]
pub enum RemoteHttp {
    /// Live Range-backed reader (server supports ranges + known size).
    Range(HttpRangeFile),
    /// Full body written to a temp file (ranges unavailable or incomplete probe).
    Materialized(RemoteLocal),
}

impl RemoteHttp {
    /// True when this is a live Range-backed handle (not fully buffered or on-disk).
    pub fn uses_ranges(&self) -> bool {
        match self {
            Self::Range(f) => f.uses_ranges(),
            Self::Materialized(_) => false,
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Self::Range(f) => f.len(),
            Self::Materialized(RemoteLocal::Fetched { size, .. }) => *size,
            Self::Materialized(RemoteLocal::Local(p)) => {
                std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Local path when materialized; `None` for live Range handles.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Range(_) => None,
            Self::Materialized(r) => Some(r.path()),
        }
    }
}

/// Resolve an HTTP(S) URL, preferring live Range I/O without full materialize.
///
/// - Server advertises ranges **and** size is known → [`RemoteHttp::Range`]
/// - Otherwise → [`RemoteHttp::Materialized`] (full GET to a kept temp file)
///
/// [`resolve_to_local`] remains the full-materialize path for path-based openers.
pub fn resolve_http(url: &str) -> Result<RemoteHttp> {
    let probe = probe_http(url)?;
    if probe.accept_ranges {
        if let Some(size) = probe.content_length {
            debug!("HTTP live Range for {url} ({size} bytes)");
            return Ok(RemoteHttp::Range(HttpRangeFile::range_backed(url, size)));
        }
    }
    debug!("HTTP materialize for {url} (ranges unavailable or size unknown)");
    let (tmp, size) = fetch_http_full_get(url)?;
    Ok(RemoteHttp::Materialized(keep_fetched(url, tmp, size)?))
}

/// Unified access handle: local path materialization **or** live HTTP Range I/O.
///
/// Lets the factory choose Range vs path without breaking [`RemoteLocal::path`] users.
/// Non-HTTP schemes always resolve to [`RemoteAccess::Path`].
#[derive(Debug)]
pub enum RemoteAccess {
    /// Local filesystem path (native or fully fetched remote).
    Path(RemoteLocal),
    /// Live HTTP Range (or materialized HTTP when ranges are unusable).
    Http(RemoteHttp),
}

impl RemoteAccess {
    pub fn uses_ranges(&self) -> bool {
        match self {
            Self::Path(_) => false,
            Self::Http(h) => h.uses_ranges(),
        }
    }

    /// Path when available (local or materialized); `None` for live Range HTTP.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Path(r) => Some(r.path()),
            Self::Http(h) => h.path(),
        }
    }
}

/// Resolve a path or URL, preferring live HTTP Range access for `http(s)://`.
///
/// Other schemes match [`resolve_to_local`]. For a guaranteed local path, use
/// [`resolve_to_local`] / [`materialize_input`] instead.
pub fn resolve_access(input: &str) -> Result<RemoteAccess> {
    if !is_remote_url(input) {
        return Ok(RemoteAccess::Path(RemoteLocal::Local(PathBuf::from(input))));
    }
    let url = Url::parse(input).map_err(|e| RemoteError::Url(e.to_string()))?;
    match url.scheme() {
        "http" | "https" => Ok(RemoteAccess::Http(resolve_http(url.as_str())?)),
        _ => Ok(RemoteAccess::Path(resolve_to_local(input)?)),
    }
}

impl Read for HttpRangeFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        if let Some(data) = &self.buffered {
            let start = self.pos as usize;
            let end = (self.pos as usize + buf.len()).min(data.len());
            let n = end - start;
            buf[..n].copy_from_slice(&data[start..end]);
            self.pos += n as u64;
            return Ok(n);
        }
        let end = (self.pos + buf.len() as u64).min(self.size);
        if end <= self.pos {
            return Ok(0);
        }
        // Inclusive Range end
        let range = format!("bytes={}-{}", self.pos, end - 1);
        let resp = ureq::get(&self.url)
            .set("User-Agent", USER_AGENT)
            .set("Range", &range)
            .call()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let status = resp.status();
        if status == 206 {
            let mut reader = resp.into_reader();
            let mut chunk = vec![0u8; (end - self.pos) as usize];
            reader.read_exact(&mut chunk)?;
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            self.pos += n as u64;
            return Ok(n);
        }
        if status == 200 {
            // Server ignored Range and returned the full body; skip to pos then read.
            let mut reader = resp.into_reader();
            let skip = self.pos;
            if skip > 0 {
                io::copy(&mut reader.by_ref().take(skip), &mut io::sink())?;
            }
            let need = (end - self.pos) as usize;
            let mut chunk = vec![0u8; need];
            reader.read_exact(&mut chunk)?;
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            self.pos += n as u64;
            return Ok(n);
        }
        Err(io::Error::other(format!(
            "HTTP {status} for range {range} on {}",
            self.url
        )))
    }
}

impl Seek for HttpRangeFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.size as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Materialize any supported remote (or copy local path for uniform API).
pub fn materialize_input(input: &str) -> Result<RemoteLocal> {
    resolve_to_local(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn file_url_local() {
        let p = std::env::temp_dir().join("ratarmount-remote-test.txt");
        std::fs::write(&p, b"hi").unwrap();
        let url = Url::from_file_path(&p).unwrap().to_string();
        let local = resolve_to_local(&url).unwrap();
        assert_eq!(local.path(), p);
        assert_eq!(std::fs::read(local.path()).unwrap(), b"hi");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn detect_schemes() {
        assert!(is_remote_url("https://example.com/a.tar"));
        assert!(is_remote_url("file:///tmp/x"));
        assert!(is_remote_url("s3://bucket/key.tar"));
        assert!(is_remote_url("ssh://user@host/path.tar"));
        assert!(is_remote_url("sftp://user@host//abs/path.tar"));
        assert!(is_remote_url("webdav://host.example/files/a.tar"));
        assert!(is_remote_url("webdavs://host.example/files/a.tar"));
        assert!(is_remote_url("smb://server/share/a.tar"));
        assert!(is_remote_url("dropbox:///path/to/file.tar"));
        assert!(is_remote_url("dropbox://path/to/file.tar"));
        assert!(!is_remote_url("/tmp/x"));
        assert!(!is_remote_url("relative/path"));
    }

    #[test]
    fn dropbox_resolve_errors_without_token() {
        // When DROPBOX_TOKEN is unset, resolve must fail clearly — not "unsupported scheme".
        if std::env::var("DROPBOX_TOKEN").is_ok() {
            return;
        }
        let err = resolve_to_local("dropbox:///some/archive.tar").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("DROPBOX_TOKEN") || msg.contains("dropbox"),
            "unexpected: {msg}"
        );
        assert!(
            !msg.to_ascii_lowercase().contains("unsupported remote scheme"),
            "dropbox should be a supported scheme: {msg}"
        );
    }

    #[test]
    fn dropbox_parse_export() {
        let loc = parse_dropbox_url("dropbox://folder/nested/a.tar").unwrap();
        assert_eq!(loc.path, "/folder/nested/a.tar");
    }

    #[test]
    fn unsupported_scheme_message() {
        // `ftp` is recognized as remote but not implemented yet.
        let err = resolve_to_local("ftp://host.example/a.tar").unwrap_err();
        assert!(
            err.to_string().contains("unsupported") || err.to_string().contains("ftp"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn smb_resolve_errors_without_live_server() {
        // Without a real SMB server this must fail clearly (missing smbclient or
        // connection/auth error). Must not panic or claim "unsupported scheme".
        let err = resolve_to_local("smb://127.0.0.1/nosuchshare/a.tar").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("smb") || msg.contains("smbclient"),
            "unexpected: {msg}"
        );
        assert!(
            !msg.to_ascii_lowercase().contains("unsupported remote scheme"),
            "smb should be a supported scheme: {msg}"
        );
    }

    #[test]
    fn smb_parse_export() {
        let loc = parse_smb_url("smb://u:p@host/share/dir/f.tar").unwrap();
        assert_eq!(loc.share, "share");
        assert_eq!(loc.path, "dir/f.tar");
        assert_eq!(loc.user.as_deref(), Some("u"));
    }

    #[test]
    fn parse_content_range_total_ok() {
        assert_eq!(
            parse_content_range_total(Some("bytes 0-0/12345")),
            Some(12345)
        );
        assert_eq!(
            parse_content_range_total(Some("bytes 100-199/1000")),
            Some(1000)
        );
        assert_eq!(parse_content_range_total(Some("bytes 0-0/*")), None);
        assert_eq!(parse_content_range_total(None), None);
    }

    #[test]
    fn accept_ranges_bytes_logic() {
        assert!(accept_ranges_bytes(Some("bytes")));
        assert!(accept_ranges_bytes(Some("Bytes")));
        assert!(!accept_ranges_bytes(Some("none")));
        assert!(!accept_ranges_bytes(Some("NONE")));
        assert!(!accept_ranges_bytes(None));
    }

    #[test]
    fn range_chunk_windows_basic() {
        assert_eq!(range_chunk_windows(0, 4), Vec::<(u64, u64)>::new());
        assert_eq!(range_chunk_windows(10, 4), vec![(0, 3), (4, 7), (8, 9)]);
        assert_eq!(range_chunk_windows(4, 4), vec![(0, 3)]);
        assert_eq!(range_chunk_windows(5, 4), vec![(0, 3), (4, 4)]);
        // empty body / zero chunk
        assert!(range_chunk_windows(100, 0).is_empty());
    }

    /// Minimal HTTP/1.1 mock server for unit tests.
    struct MockHttp {
        addr: String,
        /// Recorded request first-lines / headers of interest.
        log: Arc<Mutex<Vec<String>>>,
        range_gets: Arc<AtomicUsize>,
        full_gets: Arc<AtomicUsize>,
        _join: Option<thread::JoinHandle<()>>,
    }

    #[derive(Clone)]
    struct MockConfig {
        body: Vec<u8>,
        /// Advertise Accept-Ranges: bytes on HEAD/GET.
        accept_ranges: bool,
        /// Honor Range header with 206.
        honor_range: bool,
        /// If true, HEAD returns 405.
        head_rejects: bool,
    }

    impl MockHttp {
        fn spawn(cfg: MockConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let log = Arc::new(Mutex::new(Vec::new()));
            let range_gets = Arc::new(AtomicUsize::new(0));
            let full_gets = Arc::new(AtomicUsize::new(0));
            let log_c = Arc::clone(&log);
            let range_c = Arc::clone(&range_gets);
            let full_c = Arc::clone(&full_gets);
            let join = thread::spawn(move || {
                // Serve a handful of requests then exit when listener is dropped / timeout-ish.
                listener
                    .set_nonblocking(false)
                    .ok();
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut headers = Vec::new();
                    let mut range_hdr: Option<String> = None;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        headers.push(line.clone());
                        if let Some(v) = line.strip_prefix("Range:") {
                            range_hdr = Some(v.trim().to_string());
                        }
                    }
                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if let Some(r) = &range_hdr {
                            lg.push(format!("Range: {r}"));
                        }
                    }

                    let is_head = request_line.starts_with("HEAD ");
                    let is_get = request_line.starts_with("GET ");

                    if is_head && cfg.head_rejects {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }

                    if is_head {
                        let mut resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
                            cfg.body.len()
                        );
                        if cfg.accept_ranges {
                            resp.push_str("Accept-Ranges: bytes\r\n");
                        }
                        resp.push_str("\r\n");
                        let _ = stream.write_all(resp.as_bytes());
                        continue;
                    }

                    if !is_get {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }

                    if cfg.honor_range {
                        if let Some(r) = range_hdr.as_deref() {
                            // Parse bytes=start-end
                            if let Some(spec) = r.strip_prefix("bytes=") {
                                let parts: Vec<&str> = spec.splitn(2, '-').collect();
                                if parts.len() == 2 {
                                    let start: u64 = parts[0].parse().unwrap_or(0);
                                    let end: u64 = if parts[1].is_empty() {
                                        (cfg.body.len() as u64).saturating_sub(1)
                                    } else {
                                        parts[1].parse().unwrap_or(0)
                                    };
                                    let start = start as usize;
                                    let end = (end as usize).min(cfg.body.len().saturating_sub(1));
                                    if start < cfg.body.len() && start <= end {
                                        range_c.fetch_add(1, Ordering::SeqCst);
                                        let slice = &cfg.body[start..=end];
                                        let hdr = format!(
                                            "HTTP/1.1 206 Partial Content\r\n\
                                             Content-Length: {}\r\n\
                                             Content-Range: bytes {}-{}/{}\r\n\
                                             Accept-Ranges: bytes\r\n\
                                             Connection: close\r\n\r\n",
                                            slice.len(),
                                            start,
                                            end,
                                            cfg.body.len()
                                        );
                                        let _ = stream.write_all(hdr.as_bytes());
                                        let _ = stream.write_all(slice);
                                        continue;
                                    }
                                }
                            }
                        }
                    }

                    // Full GET
                    full_c.fetch_add(1, Ordering::SeqCst);
                    let mut hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
                        cfg.body.len()
                    );
                    if cfg.accept_ranges {
                        hdr.push_str("Accept-Ranges: bytes\r\n");
                    }
                    hdr.push_str("\r\n");
                    let _ = stream.write_all(hdr.as_bytes());
                    let _ = stream.write_all(&cfg.body);
                }
            });
            Self {
                addr,
                log,
                range_gets,
                full_gets,
                _join: Some(join),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{}{}", self.addr, path)
        }
    }

    #[test]
    fn prefer_range_downloads_in_chunks() {
        // Body larger than a tiny artificial chunk plan: use small body with overridden windows
        // by setting body size and verifying Range requests were used.
        let body: Vec<u8> = (0u8..=255).cycle().take(12_000).collect();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
        });
        let url = mock.url("/blob.bin");
        let (mut tmp, size) = fetch_http_to_temp_prefer_range(&url).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert!(
            mock.range_gets.load(Ordering::SeqCst) >= 1,
            "expected Range GETs, log={:?}",
            mock.log.lock().unwrap()
        );
        // Full GET should not be the materialization path when ranges work.
        // (probe may not full-GET; range path uses only 206s)
        assert_eq!(mock.full_gets.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn prefer_range_falls_back_to_full_get() {
        let body = b"hello-no-ranges-server".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: false,
            honor_range: false,
            head_rejects: false,
        });
        let url = mock.url("/blob.bin");
        let (mut tmp, size) = fetch_http_to_temp_prefer_range(&url).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert_eq!(mock.range_gets.load(Ordering::SeqCst), 0);
        assert!(mock.full_gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn prefer_range_when_head_rejected_uses_range_probe() {
        let body: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: true,
        });
        let url = mock.url("/blob.bin");
        let (mut tmp, size) = fetch_http_to_temp_prefer_range(&url).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert!(mock.range_gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn http_range_file_seek_and_read() {
        let body: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
        });
        let url = mock.url("/blob.bin");
        let mut f = HttpRangeFile::open(&url).unwrap();
        assert!(f.uses_ranges());
        assert_eq!(f.len(), body.len() as u64);

        f.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = [0u8; 16];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &body[100..116]);

        f.seek(SeekFrom::End(-4)).unwrap();
        let mut tail = [0u8; 4];
        f.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, &body[body.len() - 4..]);

        f.seek(SeekFrom::Start(0)).unwrap();
        let mut head = [0u8; 8];
        f.read_exact(&mut head).unwrap();
        assert_eq!(&head, &body[..8]);

        assert!(mock.range_gets.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn http_range_file_fallback_buffer() {
        let body = b"buffered-fallback-body".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: false,
            honor_range: false,
            head_rejects: false,
        });
        let url = mock.url("/blob.bin");
        let mut f = HttpRangeFile::open(&url).unwrap();
        assert!(!f.uses_ranges());
        assert_eq!(f.len(), body.len() as u64);
        f.seek(SeekFrom::Start(9)).unwrap();
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"fallback");
    }

    #[test]
    fn resolve_to_local_http_uses_prefer_range() {
        let body = b"resolve-path-body".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
        });
        let url = mock.url("/a.tar");
        let local = resolve_to_local(&url).unwrap();
        assert_eq!(std::fs::read(local.path()).unwrap(), body);
        assert!(mock.range_gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn resolve_http_uses_live_range_when_supported() {
        let body: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
        });
        let url = mock.url("/live.bin");
        let access = resolve_http(&url).unwrap();
        assert!(
            access.uses_ranges(),
            "expected live Range path, got {access:?}"
        );
        assert!(access.path().is_none());
        assert_eq!(access.len(), body.len() as u64);
        // Materialization must not have happened (no full GET after probe HEAD).
        assert_eq!(mock.full_gets.load(Ordering::SeqCst), 0);

        let RemoteHttp::Range(mut f) = access else {
            panic!("expected RemoteHttp::Range");
        };
        f.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 32];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &body[10..42]);
        assert!(mock.range_gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn resolve_http_materializes_without_ranges() {
        let body = b"no-range-server-body".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: false,
            honor_range: false,
            head_rejects: false,
        });
        let url = mock.url("/full.bin");
        let access = resolve_http(&url).unwrap();
        assert!(!access.uses_ranges());
        let path = access.path().expect("materialized path");
        assert_eq!(std::fs::read(path).unwrap(), body);
        assert!(matches!(access, RemoteHttp::Materialized(_)));
        assert!(mock.full_gets.load(Ordering::SeqCst) >= 1);
        assert_eq!(mock.range_gets.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn open_http_range_public_api() {
        let body = b"open-http-range-api".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
        });
        let url = mock.url("/api.bin");
        let mut f = open_http_range(&url).unwrap();
        assert!(f.uses_ranges());
        assert_eq!(f.url(), url);
        let mut got = Vec::new();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn resolve_access_http_prefers_range() {
        let body = b"access-range".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
        });
        let url = mock.url("/acc.bin");
        let acc = resolve_access(&url).unwrap();
        assert!(acc.uses_ranges());
        assert!(acc.path().is_none());
        match acc {
            RemoteAccess::Http(RemoteHttp::Range(mut f)) => {
                f.seek(SeekFrom::Start(0)).unwrap();
                let mut buf = [0u8; 12];
                f.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, b"access-range");
            }
            other => panic!("expected Http Range, got {other:?}"),
        }
    }

    #[test]
    fn resolve_access_local_path() {
        let p = std::env::temp_dir().join("ratarmount-remote-access-local.txt");
        std::fs::write(&p, b"local").unwrap();
        let acc = resolve_access(p.to_str().unwrap()).unwrap();
        assert!(!acc.uses_ranges());
        assert_eq!(acc.path(), Some(p.as_path()));
        let _ = std::fs::remove_file(p);
    }

    /// Minimal WebDAV-capable mock: PROPFIND (207) + GET with optional Basic auth.
    struct MockWebDav {
        /// `http://127.0.0.1:port` base (no trailing slash).
        http_base: String,
        propfinds: Arc<AtomicUsize>,
        gets: Arc<AtomicUsize>,
        log: Arc<Mutex<Vec<String>>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    #[derive(Clone)]
    struct MockWebDavConfig {
        body: Vec<u8>,
        /// If set, require `Authorization: Basic …` matching this user:pass.
        require_basic: Option<(String, String)>,
        /// Answer PROPFIND with getcontentlength.
        propfind_size: bool,
    }

    impl MockWebDav {
        fn spawn(cfg: MockWebDavConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let http_base = format!("http://{}", listener.local_addr().unwrap());
            let propfinds = Arc::new(AtomicUsize::new(0));
            let gets = Arc::new(AtomicUsize::new(0));
            let log = Arc::new(Mutex::new(Vec::new()));
            let pf_c = Arc::clone(&propfinds);
            let get_c = Arc::clone(&gets);
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
                    }
                    // Drain request body if any (PROPFIND).
                    if content_length > 0 {
                        let mut buf = vec![0u8; content_length];
                        let _ = std::io::Read::read_exact(&mut reader, &mut buf);
                    }

                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if let Some(a) = &auth_hdr {
                            lg.push(format!("Authorization: {a}"));
                        }
                    }

                    if let Some((user, pass)) = &cfg.require_basic {
                        let expected = webdav::basic_auth_header(user, Some(pass));
                        if auth_hdr.as_deref() != Some(expected.as_str()) {
                            let body = b"unauthorized";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"dav\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(body);
                            continue;
                        }
                    }

                    let is_propfind = request_line.starts_with("PROPFIND ");
                    let is_get = request_line.starts_with("GET ");

                    if is_propfind {
                        pf_c.fetch_add(1, Ordering::SeqCst);
                        if !cfg.propfind_size {
                            let _ = write!(
                                stream,
                                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            );
                            continue;
                        }
                        let xml = format!(
                            r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/file.bin</D:href>
    <D:propstat>
      <D:prop>
        <D:getcontentlength>{}</D:getcontentlength>
        <D:resourcetype/>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#,
                            cfg.body.len()
                        );
                        let hdr = format!(
                            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            xml.len()
                        );
                        let _ = stream.write_all(hdr.as_bytes());
                        let _ = stream.write_all(xml.as_bytes());
                        continue;
                    }

                    if is_get {
                        get_c.fetch_add(1, Ordering::SeqCst);
                        let hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            cfg.body.len()
                        );
                        let _ = stream.write_all(hdr.as_bytes());
                        let _ = stream.write_all(&cfg.body);
                        continue;
                    }

                    let _ = write!(
                        stream,
                        "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                }
            });
            Self {
                http_base,
                propfinds,
                gets,
                log,
                _join: Some(join),
            }
        }

        /// `webdav://127.0.0.1:port/path` (maps to this mock's HTTP listener).
        fn webdav_url(&self, path: &str) -> String {
            let rest = self.http_base.strip_prefix("http://").unwrap();
            format!("webdav://{rest}{path}")
        }

        fn webdav_url_with_auth(&self, user: &str, pass: &str, path: &str) -> String {
            let rest = self.http_base.strip_prefix("http://").unwrap();
            format!("webdav://{user}:{pass}@{rest}{path}")
        }
    }

    #[test]
    fn webdav_fetch_with_propfind_and_get() {
        let body = b"webdav-file-body-content".to_vec();
        let mock = MockWebDav::spawn(MockWebDavConfig {
            body: body.clone(),
            require_basic: None,
            propfind_size: true,
        });
        let url = mock.webdav_url("/files/a.tar");
        let (mut tmp, size) = fetch_webdav_to_temp(&url).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert!(
            mock.propfinds.load(Ordering::SeqCst) >= 1,
            "expected PROPFIND, log={:?}",
            mock.log.lock().unwrap()
        );
        assert!(mock.gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn webdav_basic_auth_required() {
        let body = b"secret-dav-payload".to_vec();
        let mock = MockWebDav::spawn(MockWebDavConfig {
            body: body.clone(),
            require_basic: Some(("davuser".into(), "davpass".into())),
            propfind_size: true,
        });
        // Without credentials → failure
        let bare = mock.webdav_url("/secret.bin");
        assert!(fetch_webdav_to_temp(&bare).is_err());

        let authed = mock.webdav_url_with_auth("davuser", "davpass", "/secret.bin");
        let (mut tmp, size) = fetch_webdav_to_temp(&authed).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert!(mock.gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn resolve_to_local_webdav() {
        let body = b"resolve-webdav-body".to_vec();
        let mock = MockWebDav::spawn(MockWebDavConfig {
            body: body.clone(),
            require_basic: None,
            propfind_size: false, // GET still works if PROPFIND 404s
        });
        let url = mock.webdav_url("/a.tar");
        let local = resolve_to_local(&url).unwrap();
        assert_eq!(std::fs::read(local.path()).unwrap(), body);
        assert!(mock.gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn webdav_parse_maps_webdavs() {
        let loc = parse_webdav_url("webdavs://files.example.com/vault/x.tar").unwrap();
        assert_eq!(loc.http_url, "https://files.example.com/vault/x.tar");
    }
}
