//! Remote URL access for Phase 10.
//!
//! - `file://` → local path
//! - `http(s)://` → fetch to temp (prefer Range when supported) and live Range I/O via
//!   [`resolve_http`] / [`open_http_range`] / [`HttpRangeFile`].
//!   **HTTP auth** (upstream [#157](https://github.com/mxmlnkn/ratarmount/issues/157) / FR-2):
//!   - **Basic:** URL userinfo (`https://user:pass@host/path`) and/or env
//!     [`HTTP_USER_ENV`] / [`HTTP_PASSWORD_ENV`] → `Authorization: Basic …`
//!   - **Cookie:** env [`HTTP_COOKIE_ENV`] (raw Cookie header) or
//!     [`HTTP_COOKIE_FILE_ENV`] (Netscape jar / simple cookie lines) → `Cookie: …`
//!
//!   Both may be sent together on HEAD, GET, and Range requests. Not a browser cookie
//!   jar (no `Set-Cookie` persistence / per-domain store).
//! - `s3://bucket/key` → GetObject to temp with prefer-range for large objects
//!   (env keys → ECS/IMDS role → optional anonymous); live Range via [`open_s3_range`] / [`S3RangeFile`];
//!   PutObject / multipart via [`put_s3_file`] (abort on error; anonymous is GET-only);
//!   V-2 pointer PUT via [`publish_index_to_s3`] (blob then pointer, fail-closed)
//! - `ssh://` / `sftp://` / `scp://` → SFTP download to temp (OpenSSH config subset:
//!   `HostName`/`User`/`Port`/`IdentityFile`/`IdentitiesOnly`/`ProxyJump`/`Include`;
//!   URL fields override destination User/Port; path via `RATARMOUNT_SSH_CONFIG` or
//!   `~/.ssh/config`. Residual: ProxyCommand, Match, live hop handshake without sshd)
//! - `webdav://` / `webdavs://` → WebDAV GET to temp (optional PROPFIND, Basic auth)
//! - `smb://` → download via Samba `smbclient` CLI when present
//! - `dropbox://` → Dropbox content API download to temp (`DROPBOX_TOKEN`); folder browse via
//!   [`DropboxMountSource`] (`files/list_folder` + download on open). Listings use a TTL cache
//!   (`RATARMOUNT_DROPBOX_LIST_TTL_SECS`, default 30s); large opens prefer chunked HTTP Range.
//! - other schemes → clear "not yet" errors

mod dropbox;
mod index_sibling;
mod s3;
mod smb;
mod smb2_client;
mod ssh;
mod webdav;

// --- inbound protocol modules (worktree PRs: one `mod` + `pub use` pair only) ---
mod folder;
pub use folder::{try_open_remote_folder, RemoteDirent, RemoteFolderMountSource, RemoteListing};
mod ftp;
pub use ftp::{
    fetch_ftp_to_temp, open_ftp_folder, open_ftp_range, parse_ftp_url, parse_ftp_url_allow_prefix,
    redact_ftp_url, FtpLocation, FtpRangeFile, FtpScheme,
};
mod gcs;
pub use gcs::{
    fetch_gcs_range_bytes, fetch_gcs_to_temp, open_gcs_folder, open_gcs_range, parse_gcs_url,
    GcsListing, GcsLocation, GcsRangeFile,
};
mod azure;
pub use azure::{
    fetch_azure_range_bytes, fetch_azure_to_temp, open_azure_folder, open_azure_range,
    parse_azure_url, AzureListing, AzureLocation, AzureRangeFile,
};
mod rclone;
pub use rclone::{
    find_rclone, open_rclone, open_rclone_folder, parse_rclone_url, rclone_cat_args,
    rclone_lsjson_args, rclone_lsjson_stat_args, RcloneHandle, RcloneLocation, RCLONE_BIN_ENV,
};
mod oci;
pub use oci::{
    fetch_oci_image, fetch_oci_index_referrer, list_oci_index_referrers, parse_docker_url,
    parse_oci_url, OciBlobRangeFile, OciImage, OciLayer, OciLocation, OciReferrer,
    OCI_DOCKER_CONFIG_ENV, OCI_INDEX_ARTIFACT_TYPE, OCI_PASSWORD_ENV, OCI_USER_ENV,
};
mod ipfs;
pub use ipfs::{
    ipfs_api, ipfs_gateway, open_ipfs, open_ipfs_at, open_ipfs_folder, open_ipfs_folder_at,
    parse_ipfs_url, IpfsHandle, IpfsListing, IpfsLocation, IpfsScheme, DEFAULT_IPFS_API,
    DEFAULT_IPFS_GATEWAY, IPFS_API_ENV, IPFS_GATEWAY_ENV,
};
// --- end inbound protocol modules ---

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use log::debug;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::Url;

pub(crate) use azure::fetch_azure_bytes_capped;
pub use dropbox::{
    dropbox_api_arg, dropbox_download_url, dropbox_list_ttl_secs, dropbox_path_is_folder,
    dropbox_rpc_base, fetch_dropbox_location_to_temp, fetch_dropbox_location_to_temp_prefer_range,
    fetch_dropbox_range_bytes, fetch_dropbox_to_temp, get_dropbox_metadata, list_dropbox_folder,
    load_dropbox_token, parse_dropbox_url, parse_dropbox_url_allow_root, redact_token,
    DropboxEntry, DropboxEntryKind, DropboxLocation, DropboxMountSource,
    DEFAULT_DROPBOX_DOWNLOAD_URL, DEFAULT_DROPBOX_LIST_TTL_SECS, DEFAULT_DROPBOX_RANGE_THRESHOLD,
    DEFAULT_DROPBOX_RPC_BASE,
};
pub(crate) use gcs::fetch_gcs_bytes_capped;
pub use index_sibling::{
    fetch_index_sibling_bytes_capped, fetch_index_sibling_to_temp, is_object_store_archive_url,
    publish_index_to_s3, S3IndexPointer, INDEX_MEDIA_TYPE, INDEX_POINTER_SCHEMA,
};
pub(crate) use s3::fetch_s3_bytes_capped;
pub use s3::{
    fetch_s3_location_range_bytes, fetch_s3_location_to_temp,
    fetch_s3_location_to_temp_prefer_range, fetch_s3_range_bytes, fetch_s3_to_temp,
    fetch_s3_to_temp_prefer_range, open_s3_range, parse_s3_url, parse_s3_url_allow_prefix,
    put_s3_file, put_s3_location, s3_abort_multipart_upload, s3_create_and_abort_multipart_upload,
    s3_create_multipart_upload, S3Location, S3PutObject, S3PutResult, S3RangeFile,
    DEFAULT_S3_RANGE_THRESHOLD, S3_PUT_PART_SIZE, S3_PUT_PART_THRESHOLD,
};
pub use smb::{
    fetch_smb_to_temp, find_smbclient, parse_smb_url, smbclient_download_args, SmbLocation,
};
pub use smb2_client::{Smb2Client, Smb2Open};
pub use ssh::{
    expand_tilde, fetch_ssh_to_temp, host_line_matches, host_pattern_matches, load_ssh_config,
    parse_proxy_jump_list, parse_ssh_config_file, parse_ssh_config_reader, parse_ssh_url,
    resolve_ssh_connect, resolve_ssh_connect_default, ssh_config_path, SshConfig, SshConfigMatch,
    SshConnectParams, SshLocation, SshProxyHop, SSH_CONFIG_ENV,
};
pub use webdav::{
    fetch_webdav_to_temp, parse_getcontentlength, parse_webdav_url, propfind_content_length,
    WebDavLocation,
};

/// Chunk size for sequential Range GET materialization (4 MiB).
pub const HTTP_RANGE_CHUNK: u64 = 4 * 1024 * 1024;

/// Env: HTTP Basic username when the URL has no userinfo (FR-2 / #157).
pub const HTTP_USER_ENV: &str = "RATARMOUNT_HTTP_USER";
/// Env: HTTP Basic password (pairs with [`HTTP_USER_ENV`], or fills missing URL password).
pub const HTTP_PASSWORD_ENV: &str = "RATARMOUNT_HTTP_PASSWORD";
/// Env: raw HTTP `Cookie` header value for `http(s)://` (FR-2 residual / #157).
///
/// Example: `session=abc; token=xyz`. Wins over [`HTTP_COOKIE_FILE_ENV`] when both are set.
pub const HTTP_COOKIE_ENV: &str = "RATARMOUNT_HTTP_COOKIE";
/// Env: path to a cookie file used when [`HTTP_COOKIE_ENV`] is unset.
///
/// Accepts a Netscape HTTP cookie file and/or simple non-comment lines of
/// `name=value` (joined with `"; "` into a single `Cookie` header). Not a full
/// browser jar: no `Set-Cookie` persistence and no per-domain filtering.
pub const HTTP_COOKIE_FILE_ENV: &str = "RATARMOUNT_HTTP_COOKIE_FILE";

pub(crate) const USER_AGENT: &str = "ratarmount-rs/0.1";

/// Optional HTTP Basic credentials for `http(s)://` opens.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpAuth {
    pub username: String,
    /// When `None`, Basic auth uses an empty password (`user:`).
    pub password: Option<String>,
}

impl HttpAuth {
    /// `Authorization` header value: `Basic <base64(user:pass)>`.
    pub fn authorization_header(&self) -> String {
        webdav::basic_auth_header(&self.username, self.password.as_deref())
    }
}

impl std::fmt::Debug for HttpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuth")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .finish()
    }
}

/// HTTP(S) request target: clean URL (no userinfo) + optional Basic auth and/or Cookie.
#[derive(Clone)]
pub struct HttpLocation {
    /// `http://` or `https://` URL without userinfo.
    pub url: String,
    pub auth: Option<HttpAuth>,
    /// Raw `Cookie` header value from env / file, if any.
    pub cookie: Option<String>,
}

impl std::fmt::Debug for HttpLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpLocation")
            .field("url", &self.url)
            .field("auth", &self.auth)
            .field("cookie", &self.cookie.as_deref().map(redact_cookie_header))
            .finish()
    }
}

/// Redact cookie header values for logs / Debug (`name=***; other=***`).
///
/// Never log full cookie secrets (same policy as passwords / Dropbox tokens).
pub fn redact_cookie_header(cookie: &str) -> String {
    cookie
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            Some(match part.split_once('=') {
                Some((name, _)) => format!("{}=***", name.trim()),
                None => "***".to_string(),
            })
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Parse cookie file text into a single `Cookie` header value.
///
/// - **Netscape** lines: tab-separated fields; name/value are fields 6 and 7
///   (1-based). `#HttpOnly_` domain prefix is accepted.
/// - **Simple**: non-comment lines containing `=` are treated as Cookie fragments
///   and joined with `"; "`.
///
/// Comment lines (`#…`) and blanks are ignored. Returns `None` when nothing usable
/// is found.
pub fn parse_cookie_file_contents(text: &str) -> Option<String> {
    let mut netscape_pairs: Vec<String> = Vec::new();
    let mut raw_lines: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Netscape HttpOnly marker (still a cookie record).
        if let Some(rest) = line.strip_prefix("#HttpOnly_") {
            if let Some(pair) = parse_netscape_cookie_line(rest) {
                netscape_pairs.push(pair);
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some(pair) = parse_netscape_cookie_line(line) {
            netscape_pairs.push(pair);
        } else if line.contains('=') {
            raw_lines.push(line.to_string());
        }
    }
    if !netscape_pairs.is_empty() {
        return Some(netscape_pairs.join("; "));
    }
    if raw_lines.is_empty() {
        None
    } else {
        Some(raw_lines.join("; "))
    }
}

fn parse_netscape_cookie_line(line: &str) -> Option<String> {
    // domain \t include_subdomains \t path \t secure \t expiry \t name \t value
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() < 7 {
        return None;
    }
    let name = parts[5].trim();
    let value = parts[6].trim();
    if name.is_empty() {
        return None;
    }
    Some(format!("{name}={value}"))
}

/// Parse an `http://` / `https://` URL for wire requests.
///
/// **Basic credentials** resolution order:
/// 1. URL userinfo (`https://user:pass@host/path`) — username required for this branch;
///    password may fall back to [`HTTP_PASSWORD_ENV`] when the URL has a user but no password.
/// 2. Else [`HTTP_USER_ENV`] (+ optional [`HTTP_PASSWORD_ENV`]).
///
/// **Cookie** (independent of Basic; both may be sent):
/// 1. [`HTTP_COOKIE_ENV`] if non-empty
/// 2. Else contents of the file at [`HTTP_COOKIE_FILE_ENV`] (see [`parse_cookie_file_contents`])
///
/// Residual: not a browser cookie jar (`Set-Cookie` persistence / per-domain store).
pub fn parse_http_url(url_str: &str) -> Result<HttpLocation> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(RemoteError::UnsupportedScheme(other.to_string())),
    }
    if url.host_str().is_none() {
        return Err(RemoteError::Url("http URL missing host".into()));
    }

    let url_user = if url.username().is_empty() {
        None
    } else {
        Some(url.username().to_string())
    };
    let url_pass = url.password().map(|s| s.to_string());

    let auth = if let Some(username) = url_user {
        let password = url_pass.or_else(|| non_empty_env(HTTP_PASSWORD_ENV));
        Some(HttpAuth { username, password })
    } else {
        load_http_auth_from_env()
    };
    let cookie = load_http_cookie()?;

    let mut clean = url.clone();
    let _ = clean.set_username("");
    let _ = clean.set_password(None);

    Ok(HttpLocation {
        url: clean.to_string(),
        auth,
        cookie,
    })
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn load_http_auth_from_env() -> Option<HttpAuth> {
    let username = non_empty_env(HTTP_USER_ENV)?;
    let password = non_empty_env(HTTP_PASSWORD_ENV);
    Some(HttpAuth { username, password })
}

/// Load Cookie header from [`HTTP_COOKIE_ENV`] or [`HTTP_COOKIE_FILE_ENV`].
fn load_http_cookie() -> Result<Option<String>> {
    if let Some(c) = non_empty_env(HTTP_COOKIE_ENV) {
        return Ok(Some(c));
    }
    let Some(path) = non_empty_env(HTTP_COOKIE_FILE_ENV) else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path).map_err(|e| {
        RemoteError::Http(format!(
            "failed to read {HTTP_COOKIE_FILE_ENV} ({path}): {e}"
        ))
    })?;
    match parse_cookie_file_contents(&text) {
        Some(c) if !c.is_empty() => Ok(Some(c)),
        _ => Err(RemoteError::Http(format!(
            "{HTTP_COOKIE_FILE_ENV} ({path}) has no usable cookies"
        ))),
    }
}

/// Attach Basic `Authorization` and/or `Cookie` headers for HTTP(S) requests.
fn apply_http_auth(
    mut req: ureq::Request,
    auth: Option<&HttpAuth>,
    cookie: Option<&str>,
) -> ureq::Request {
    if let Some(a) = auth {
        req = req.set("Authorization", &a.authorization_header());
    }
    if let Some(c) = cookie {
        if !c.is_empty() {
            req = req.set("Cookie", c);
        }
    }
    req
}

fn http_unauthorized(url: &str) -> RemoteError {
    RemoteError::Http(format!(
        "HTTP 401 Unauthorized for {url}; provide credentials via URL userinfo \
         (https://user:pass@host/...), {HTTP_USER_ENV}/{HTTP_PASSWORD_ENV}, \
         or Cookie via {HTTP_COOKIE_ENV}/{HTTP_COOKIE_FILE_ENV}"
    ))
}

fn http_status_err(status: u16, url: &str) -> RemoteError {
    if status == 401 {
        http_unauthorized(url)
    } else {
        RemoteError::Http(format!("HTTP {status} for {url}"))
    }
}

fn map_ureq_http_error(err: ureq::Error, url: &str) -> RemoteError {
    match err {
        ureq::Error::Status(401, _) => http_unauthorized(url),
        ureq::Error::Status(code, _) => RemoteError::Http(format!("HTTP {code} for {url}")),
        other => RemoteError::Http(other.to_string()),
    }
}

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
    #[error("ssh_config Include cycle: {0}")]
    SshIncludeCycle(String),
    #[error("webdav: {0}")]
    WebDav(String),
    #[error("smb: {0}")]
    Smb(String),
    #[error("dropbox: {0}")]
    Dropbox(String),
    #[error("gcs: {0}")]
    Gcs(String),
    #[error("azure: {0}")]
    Azure(String),
    #[error("ftp: {0}")]
    Ftp(String),
    #[error("ipfs: {0}")]
    Ipfs(String),
    #[error("rclone: {0}")]
    Rclone(String),
    #[error("oci: {0}")]
    Oci(String),
    #[error("unsupported remote scheme: {0}")]
    UnsupportedScheme(String),
}

pub type Result<T> = std::result::Result<T, RemoteError>;

/// Known inbound schemes. Checked as a **prefix** before `://` — not via
/// WHATWG [`Url::parse`], which rejects `rclone://remote:path` and
/// `docker://ubuntu:24.04` (`invalid port number`).
const REMOTE_SCHEMES: &[&str] = &[
    "http", "https", "file", "ftp", "ftps", "s3", "gs", "az", "azure", "ssh", "sftp", "scp", "smb",
    "webdav", "webdavs", "dropbox", "oci", "docker", "ghcr", "ipfs", "ipns", "rclone",
];

/// ASCII-lowercase scheme before the first `://`, if any.
///
/// `rclone+remote:path` has no `://`; the `rclone+` prefix (case-insensitive)
/// is still scheme `rclone` so [`is_remote_url`] does not treat it as a local path.
pub fn remote_url_scheme(s: &str) -> Option<String> {
    if s.len() >= 7 && s[..7].eq_ignore_ascii_case("rclone+") {
        return Some("rclone".into());
    }
    let (scheme, _) = s.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    Some(scheme.to_ascii_lowercase())
}

fn is_known_remote_scheme(scheme: &str) -> bool {
    REMOTE_SCHEMES.contains(&scheme)
}

/// True if `s` looks like a URL with a known remote scheme (not a bare Windows path).
///
/// Scheme-prefix only: `rclone://gdrive:bucket/x` and `docker://ubuntu:24.04`
/// are remote even when [`Url::parse`] fails.
pub fn is_remote_url(s: &str) -> bool {
    remote_url_scheme(s).is_some_and(|scheme| is_known_remote_scheme(&scheme))
}

/// Copy a seekable/stream body into a kept temp file.
fn keep_from_reader(input: &str, mut r: impl Read) -> Result<RemoteLocal> {
    let mut tmp = NamedTempFile::new()?;
    let size = io::copy(&mut r, &mut tmp)?;
    keep_fetched(input, tmp, size)
}

/// Resolve a path or URL to a local filesystem path suitable for openers.
/// Remote schemes download into a kept temp file; caller must keep [`RemoteLocal`] alive.
///
/// `oci://` / `docker://` / `ghcr://` are layer-union mounts (factory
/// [`open_remote_input`]); they are not single-file downloads.
pub fn resolve_to_local(input: &str) -> Result<RemoteLocal> {
    if !is_remote_url(input) {
        return Ok(RemoteLocal::Local(PathBuf::from(input)));
    }
    let scheme = remote_url_scheme(input).unwrap_or_default();
    match scheme.as_str() {
        "file" => {
            let url = Url::parse(input).map_err(|e| RemoteError::Url(e.to_string()))?;
            let path = url
                .to_file_path()
                .map_err(|_| RemoteError::Url(format!("invalid file URL: {input}")))?;
            Ok(RemoteLocal::Local(path))
        }
        "http" | "https" => {
            // Prefer Range materialization when the server supports it (fsspec-style path).
            let (tmp, size) = fetch_http_to_temp_prefer_range(input)?;
            keep_fetched(input, tmp, size)
        }
        "s3" => {
            // Prefer chunked Range materialization for large objects (fsspec-style).
            let (tmp, size) = fetch_s3_to_temp_prefer_range(input)?;
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
        "ftp" | "ftps" => {
            let (tmp, size) = fetch_ftp_to_temp(input).map_err(|e| match e {
                RemoteError::Ftp(_) => e,
                other => RemoteError::Ftp(other.to_string()),
            })?;
            keep_fetched(input, tmp, size)
        }
        "gs" => {
            let f = open_gcs_range(input).map_err(|e| match e {
                RemoteError::Gcs(_) => e,
                other => RemoteError::Gcs(other.to_string()),
            })?;
            keep_from_reader(input, f)
        }
        "az" | "azure" => {
            let f = open_azure_range(input).map_err(|e| match e {
                RemoteError::Azure(_) => e,
                other => RemoteError::Azure(other.to_string()),
            })?;
            keep_from_reader(input, f)
        }
        "ipfs" | "ipns" => {
            let f = open_ipfs(input).map_err(|e| match e {
                RemoteError::Ipfs(_) => e,
                other => RemoteError::Ipfs(other.to_string()),
            })?;
            keep_from_reader(input, f)
        }
        "rclone" => {
            let f = open_rclone(input).map_err(|e| match e {
                RemoteError::Rclone(_) => e,
                other => RemoteError::Rclone(other.to_string()),
            })?;
            keep_from_reader(input, f)
        }
        "oci" | "docker" | "ghcr" => Err(RemoteError::Oci(
            "oci:// / docker:// / ghcr:// is a layer-union image mount, not a single-file download"
                .into(),
        )),
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
    /// RFC 8288 `Link` header from a successful **archive** HEAD (inbound `describedby`).
    pub link: Option<String>,
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
/// `Range: bytes=0-0` (206 + Content-Range total). Sends Basic auth and/or Cookie when
/// configured (URL userinfo / env).
pub fn probe_http(url: &str) -> Result<HttpProbe> {
    let loc = parse_http_url(url)?;
    probe_http_location(&loc)
}

fn probe_http_location(loc: &HttpLocation) -> Result<HttpProbe> {
    let url = loc.url.as_str();
    let mut link = None;
    match apply_http_auth(
        ureq::head(url).set("User-Agent", USER_AGENT),
        loc.auth.as_ref(),
        loc.cookie.as_deref(),
    )
    .call()
    {
        Ok(resp) if (200..300).contains(&resp.status()) => {
            link = resp
                .header("Link")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let content_length = resp
                .header("Content-Length")
                .and_then(|s| s.parse::<u64>().ok());
            let accept_ranges = accept_ranges_bytes(resp.header("Accept-Ranges"));
            if accept_ranges && content_length.is_some() {
                return Ok(HttpProbe {
                    content_length,
                    accept_ranges: true,
                    link,
                });
            }
            if accept_ranges {
                // Ranges OK but size unknown — try Content-Range probe.
                if let Some(mut probe) = probe_range_size(loc)? {
                    if probe.link.is_none() {
                        probe.link = link;
                    }
                    return Ok(probe);
                }
            }
            // No usable range path from HEAD alone.
            if content_length.is_some() && !accept_ranges {
                return Ok(HttpProbe {
                    content_length,
                    accept_ranges: false,
                    link,
                });
            }
            // Fall through to range probe when length missing or ambiguous.
            if let Some(mut probe) = probe_range_size(loc)? {
                if probe.link.is_none() {
                    probe.link = link;
                }
                return Ok(probe);
            }
            return Ok(HttpProbe {
                content_length,
                accept_ranges: false,
                link,
            });
        }
        Ok(resp) if resp.status() == 401 => {
            return Err(http_unauthorized(url));
        }
        Ok(resp) => {
            debug!("HEAD {url} -> {}, probing with Range GET", resp.status());
        }
        Err(ureq::Error::Status(401, _)) => {
            return Err(http_unauthorized(url));
        }
        Err(e) => {
            debug!("HEAD {url} failed: {e}, probing with Range GET");
        }
    }

    if let Some(mut probe) = probe_range_size(loc)? {
        if probe.link.is_none() {
            probe.link = link;
        }
        return Ok(probe);
    }

    // Last resort: no size / no ranges from probes; full GET will discover body length.
    Ok(HttpProbe {
        content_length: None,
        accept_ranges: false,
        link,
    })
}

/// Issue `GET` with `Range: bytes=0-0`. Returns probe meta on 206; `None` if ranges unusable.
fn probe_range_size(loc: &HttpLocation) -> Result<Option<HttpProbe>> {
    let url = loc.url.as_str();
    let resp = match apply_http_auth(
        ureq::get(url)
            .set("User-Agent", USER_AGENT)
            .set("Range", "bytes=0-0"),
        loc.auth.as_ref(),
        loc.cookie.as_deref(),
    )
    .call()
    {
        Ok(r) => r,
        Err(ureq::Error::Status(401, _)) => {
            return Err(http_unauthorized(url));
        }
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
            link: None,
        }));
    }
    if status == 401 {
        return Err(http_unauthorized(url));
    }
    if (200..300).contains(&status) {
        // Server ignored Range (full body). Not usable as range-capable.
        let content_length = resp
            .header("Content-Length")
            .and_then(|s| s.parse::<u64>().ok());
        return Ok(Some(HttpProbe {
            content_length,
            accept_ranges: false,
            link: None,
        }));
    }
    debug!("Range probe {url} -> HTTP {status}");
    Ok(None)
}

/// Inclusive Range GET of `url` (`bytes=start-end`). Used for remote tarstats edges.
pub fn fetch_http_range_bytes(url: &str, start: u64, end_inclusive: u64) -> Result<Vec<u8>> {
    let loc = parse_http_url(url)?;
    let range = format!("bytes={start}-{end_inclusive}");
    let resp = apply_http_auth(
        ureq::get(loc.url.as_str())
            .set("User-Agent", USER_AGENT)
            .set("Range", &range),
        loc.auth.as_ref(),
        loc.cookie.as_deref(),
    )
    .call()
    .map_err(|e| map_ureq_http_error(e, loc.url.as_str()))?;
    let status = resp.status();
    if status != 206 && !(200..300).contains(&status) {
        return Err(http_status_err(status, loc.url.as_str()));
    }
    let mut reader = resp.into_reader();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Inclusive Range GET of `url`, streaming the body to EOF as SHA-256 hex.
///
/// `end_inclusive` is written into the `Range` header only. The response body
/// is hashed until `n == 0` (same as [`fetch_http_range_bytes`] `read_to_end`).
/// Status set matches that helper: `206` or `200..300`. Do not cap the read at
/// `end-start+1` or `Content-Length` (HTTP 200 / ignored Range would change
/// fingerprints).
pub fn hash_http_range_sha256(url: &str, start: u64, end_inclusive: u64) -> Result<String> {
    let loc = parse_http_url(url)?;
    let range = format!("bytes={start}-{end_inclusive}");
    let resp = apply_http_auth(
        ureq::get(loc.url.as_str())
            .set("User-Agent", USER_AGENT)
            .set("Range", &range),
        loc.auth.as_ref(),
        loc.cookie.as_deref(),
    )
    .call()
    .map_err(|e| map_ureq_http_error(e, loc.url.as_str()))?;
    let status = resp.status();
    if status != 206 && !(200..300).contains(&status) {
        return Err(http_status_err(status, loc.url.as_str()));
    }
    let mut reader = resp.into_reader();
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Full GET download to a tempfile (works without Range support).
pub fn fetch_http_to_temp(url: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_http_url(url)?;
    fetch_http_full_get(&loc)
}

/// GET at most `max_bytes`. Errors if the body is larger or the status is not 2xx.
///
/// Used for `{url}.index.ptr` so a cache-miss mount cannot slurp an unbounded object.
pub fn fetch_http_bytes_capped(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let loc = parse_http_url(url)?;
    let resp = apply_http_auth(
        ureq::get(loc.url.as_str()).set("User-Agent", USER_AGENT),
        loc.auth.as_ref(),
        loc.cookie.as_deref(),
    )
    .call()
    .map_err(|e| map_ureq_http_error(e, loc.url.as_str()))?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        return Err(http_status_err(status, loc.url.as_str()));
    }
    let buf = read_at_most(&mut resp.into_reader(), max_bytes)?;
    if buf.len() as u64 > max_bytes {
        return Err(RemoteError::Http(format!("body exceeds {max_bytes} bytes")));
    }
    Ok(buf)
}

/// Read at most `max_bytes + 1` so the caller can detect overflow without a full slurp.
pub(crate) fn read_at_most(reader: &mut impl Read, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    io::copy(&mut reader.take(max_bytes.saturating_add(1)), &mut buf)?;
    Ok(buf)
}

/// Download via sequential Range GETs when supported; otherwise full GET.
///
/// Used by [`resolve_to_local`] so the factory materialization path benefits without
/// factory changes. Matches the Python fsspec-style prefer-range path.
pub fn fetch_http_to_temp_prefer_range(url: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_http_url(url)?;
    let probe = probe_http_location(&loc)?;
    if probe.accept_ranges {
        if let Some(size) = probe.content_length {
            debug!(
                "HTTP prefer-range: downloading {} ({size} bytes) in {}-byte chunks",
                loc.url, HTTP_RANGE_CHUNK
            );
            match fetch_http_via_ranges(&loc, size) {
                Ok(v) => return Ok(v),
                Err(e) => {
                    // Auth failures must not silently fall back (would 401 again).
                    if matches!(&e, RemoteError::Http(msg) if msg.contains("401")) {
                        return Err(e);
                    }
                    debug!(
                        "HTTP range download failed for {}: {e}; falling back to full GET",
                        loc.url
                    );
                }
            }
        }
    }
    debug!(
        "HTTP full GET for {} (ranges unavailable or incomplete probe)",
        loc.url
    );
    fetch_http_full_get(&loc)
}

fn fetch_http_full_get(loc: &HttpLocation) -> Result<(NamedTempFile, u64)> {
    let resp = apply_http_auth(
        ureq::get(&loc.url).set("User-Agent", USER_AGENT),
        loc.auth.as_ref(),
        loc.cookie.as_deref(),
    )
    .call()
    .map_err(|e| map_ureq_http_error(e, &loc.url))?;
    if !(200..300).contains(&resp.status()) {
        return Err(http_status_err(resp.status(), &loc.url));
    }
    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    tmp.as_file().seek(SeekFrom::Start(0))?;
    Ok((tmp, n))
}

/// Sequential Range GET materialization into a tempfile.
fn fetch_http_via_ranges(loc: &HttpLocation, size: u64) -> Result<(NamedTempFile, u64)> {
    let mut tmp = NamedTempFile::new()?;
    if size == 0 {
        tmp.flush()?;
        return Ok((tmp, 0));
    }
    let mut written = 0u64;
    for (start, end) in range_chunk_windows(size, HTTP_RANGE_CHUNK) {
        let range = format!("bytes={start}-{end}");
        let resp = apply_http_auth(
            ureq::get(&loc.url)
                .set("User-Agent", USER_AGENT)
                .set("Range", &range),
            loc.auth.as_ref(),
            loc.cookie.as_deref(),
        )
        .call()
        .map_err(|e| map_ureq_http_error(e, &loc.url))?;
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
            return Err(http_status_err(status, &loc.url));
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
///
/// Basic auth and/or Cookie from the open URL / env are retained for subsequent Range GETs.
pub struct HttpRangeFile {
    /// Wire URL without userinfo.
    url: String,
    auth: Option<HttpAuth>,
    cookie: Option<String>,
    size: u64,
    pos: u64,
    /// Optional fully buffered body if ranges unavailable
    buffered: Option<Vec<u8>>,
}

impl std::fmt::Debug for HttpRangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRangeFile")
            .field("url", &self.url)
            .field("auth", &self.auth)
            .field("cookie", &self.cookie.as_deref().map(redact_cookie_header))
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
        let loc = parse_http_url(url)?;
        let probe = probe_http_location(&loc)?;
        if probe.accept_ranges {
            if let Some(size) = probe.content_length {
                return Ok(Self::from_location(loc, size, None));
            }
        }

        // Fallback: full download into memory (fine for test fixtures / small objects)
        let (mut tmp, size) = fetch_http_full_get(&loc)?;
        let mut buf = Vec::with_capacity(size as usize);
        tmp.read_to_end(&mut buf)?;
        Ok(Self::from_location(loc, buf.len() as u64, Some(buf)))
    }

    fn from_location(loc: HttpLocation, size: u64, buffered: Option<Vec<u8>>) -> Self {
        Self {
            url: loc.url,
            auth: loc.auth,
            cookie: loc.cookie,
            size,
            pos: 0,
            buffered,
        }
    }

    /// Construct a live Range-backed reader (no probe; caller must know size).
    ///
    /// Parses Basic auth and Cookie from URL userinfo / env the same way as [`open`].
    pub fn range_backed(url: &str, size: u64) -> Self {
        match parse_http_url(url) {
            Ok(loc) => Self::from_location(loc, size, None),
            Err(_) => Self {
                url: url.to_string(),
                auth: None,
                cookie: None,
                size,
                pos: 0,
                buffered: None,
            },
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Basic auth retained for live Range GETs, if any.
    pub fn auth(&self) -> Option<&HttpAuth> {
        self.auth.as_ref()
    }

    /// Cookie header retained for live Range GETs, if any.
    pub fn cookie(&self) -> Option<&str> {
        self.cookie.as_deref()
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
    let loc = parse_http_url(url)?;
    let probe = probe_http_location(&loc)?;
    if probe.accept_ranges {
        if let Some(size) = probe.content_length {
            debug!("HTTP live Range for {} ({size} bytes)", loc.url);
            return Ok(RemoteHttp::Range(HttpRangeFile::from_location(
                loc, size, None,
            )));
        }
    }
    debug!(
        "HTTP materialize for {} (ranges unavailable or size unknown)",
        loc.url
    );
    let (tmp, size) = fetch_http_full_get(&loc)?;
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
    let scheme = remote_url_scheme(input).unwrap_or_default();
    match scheme.as_str() {
        "http" | "https" => Ok(RemoteAccess::Http(resolve_http(input)?)),
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
        let resp = apply_http_auth(
            ureq::get(&self.url)
                .set("User-Agent", USER_AGENT)
                .set("Range", &range),
            self.auth.as_ref(),
            self.cookie.as_deref(),
        )
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(401, _) => io::Error::other(format!(
                "HTTP 401 Unauthorized for {}; check URL userinfo, {}/{}, or Cookie via {}/{}",
                self.url, HTTP_USER_ENV, HTTP_PASSWORD_ENV, HTTP_COOKIE_ENV, HTTP_COOKIE_FILE_ENV
            )),
            other => io::Error::other(other.to_string()),
        })?;
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
        if status == 401 {
            return Err(io::Error::other(format!(
                "HTTP 401 Unauthorized for {}; check URL userinfo, {}/{}, or Cookie via {}/{}",
                self.url, HTTP_USER_ENV, HTTP_PASSWORD_ENV, HTTP_COOKIE_ENV, HTTP_COOKIE_FILE_ENV
            )));
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
        assert!(is_remote_url("ftp://host.example/a.tar"));
        assert!(is_remote_url("ftps://host.example/a.tar"));
        assert!(is_remote_url("gs://bucket/obj.tar"));
        assert!(is_remote_url("az://container/blob.tar"));
        assert!(is_remote_url("azure://container/blob.tar"));
        assert!(is_remote_url("ipfs://bafyhash/path"));
        assert!(is_remote_url("ipns://name/path"));
        assert!(is_remote_url("oci://ghcr.io/org/img:tag"));
        assert!(is_remote_url("ghcr://org/img:tag"));
        // WHATWG-invalid (colon after host-like segment) must still be remote.
        assert!(is_remote_url("rclone://gdrive:bucket/x"));
        assert!(is_remote_url("rclone://remote:path"));
        assert!(is_remote_url("rclone+gdrive:bucket/path"));
        assert!(is_remote_url("rclone+gdrive://bucket/path"));
        assert!(is_remote_url("RCLONE+gdrive:bucket/path"));
        assert!(is_remote_url("docker://ubuntu:24.04"));
        assert!(!is_remote_url("/tmp/x"));
        assert!(!is_remote_url("relative/path"));
        assert!(!is_remote_url("C:\\windows\\path"));
    }

    /// Regression: docker://ubuntu:24.04 is not a local path.
    ///
    /// `Url::parse` fails (`invalid port number`); a prefix check must still
    /// treat it as remote so factory does not `open()` a local file of that name.
    #[test]
    fn docker_ubuntu_tag_is_not_a_local_path() {
        const URL: &str = "docker://ubuntu:24.04";
        assert!(
            url::Url::parse(URL).is_err(),
            "precondition: WHATWG parse must fail for {URL}"
        );
        assert!(is_remote_url(URL), "{URL} must be a remote scheme");
        match resolve_to_local(URL) {
            Ok(RemoteLocal::Local(ref p)) => panic!("{URL} must not resolve as local path {p:?}"),
            Ok(other) => panic!("{URL} must not materialize as {other:?}"),
            Err(RemoteError::Oci(msg)) => {
                assert!(
                    msg.contains("layer-union") || msg.contains("oci://"),
                    "{msg}"
                );
            }
            Err(e) => panic!("expected RemoteError::Oci, got {e}"),
        }
        match resolve_access(URL) {
            Ok(RemoteAccess::Path(RemoteLocal::Local(ref p))) => {
                panic!("{URL} must not be a local path {p:?}")
            }
            Ok(_) => panic!("{URL} must not materialize via resolve_access"),
            Err(RemoteError::Oci(_)) => {}
            Err(e) => panic!("expected RemoteError::Oci, got {e}"),
        }
    }

    #[test]
    fn is_remote_url_rclone_plus_form() {
        const PLUS: &str = "rclone+gdrive:bucket/path";
        const PLUS_SLASH: &str = "rclone+gdrive://bucket/path";
        assert_eq!(remote_url_scheme(PLUS).as_deref(), Some("rclone"));
        assert_eq!(remote_url_scheme(PLUS_SLASH).as_deref(), Some("rclone"));
        assert_eq!(
            remote_url_scheme("RCLONE+gdrive:bucket/path").as_deref(),
            Some("rclone")
        );
        assert!(is_remote_url(PLUS), "{PLUS} must be a remote scheme");
        assert!(is_remote_url(PLUS_SLASH));
        match resolve_to_local(PLUS) {
            Ok(RemoteLocal::Local(ref p)) => {
                panic!("{PLUS} must not resolve as local path {p:?}")
            }
            Ok(_) => {}
            Err(RemoteError::Rclone(_)) | Err(RemoteError::Io(_)) | Err(RemoteError::Url(_)) => {}
            Err(e) => panic!("unexpected error for rclone+ URL: {e}"),
        }
    }

    #[test]
    fn rclone_colon_path_is_remote_not_local() {
        const URL: &str = "rclone://gdrive:bucket/x";
        assert!(
            url::Url::parse(URL).is_err(),
            "precondition: WHATWG parse must fail for {URL}"
        );
        assert!(is_remote_url(URL));
        match resolve_to_local(URL) {
            Ok(RemoteLocal::Local(ref p)) => panic!("{URL} must not resolve as local path {p:?}"),
            Ok(_) => {}
            Err(RemoteError::Rclone(_)) | Err(RemoteError::Io(_)) | Err(RemoteError::Url(_)) => {}
            Err(e) => panic!("unexpected error for rclone URL: {e}"),
        }
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
            !msg.to_ascii_lowercase()
                .contains("unsupported remote scheme"),
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
            !msg.to_ascii_lowercase()
                .contains("unsupported remote scheme"),
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
        /// If set, require `Authorization: Basic …` matching this user:pass.
        require_basic: Option<(String, String)>,
        /// If set, require exact `Cookie` header value.
        require_cookie: Option<String>,
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
                listener.set_nonblocking(false).ok();
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut headers = Vec::new();
                    let mut range_hdr: Option<String> = None;
                    let mut auth_hdr: Option<String> = None;
                    let mut cookie_hdr: Option<String> = None;
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
                        if let Some(v) = line.strip_prefix("Authorization:") {
                            auth_hdr = Some(v.trim().to_string());
                        }
                        // Case-insensitive Cookie: (HTTP headers are case-insensitive).
                        let lower = line.to_ascii_lowercase();
                        if let Some(rest) = lower.strip_prefix("cookie:") {
                            let start = line.len() - rest.len();
                            cookie_hdr = Some(line[start..].trim().to_string());
                        }
                    }
                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if let Some(r) = &range_hdr {
                            lg.push(format!("Range: {r}"));
                        }
                        if let Some(a) = &auth_hdr {
                            lg.push(format!("Authorization: {a}"));
                        }
                        if let Some(c) = &cookie_hdr {
                            lg.push(format!("Cookie: {c}"));
                        } else {
                            lg.push("Cookie: absent".into());
                        }
                    }

                    if let Some((user, pass)) = &cfg.require_basic {
                        let expected = webdav::basic_auth_header(user, Some(pass));
                        if auth_hdr.as_deref() != Some(expected.as_str()) {
                            let body = b"unauthorized";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"http\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(body);
                            continue;
                        }
                    }

                    if let Some(expected_cookie) = &cfg.require_cookie {
                        if cookie_hdr.as_deref() != Some(expected_cookie.as_str()) {
                            let body = b"unauthorized cookie";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Cookie\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(body);
                            continue;
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

        /// `http://user:pass@127.0.0.1:port/path`
        fn url_with_auth(&self, user: &str, pass: &str, path: &str) -> String {
            let rest = self.addr.strip_prefix("http://").unwrap();
            format!("http://{user}:{pass}@{rest}{path}")
        }
    }

    /// Serialize tests that mutate process environment for HTTP auth.
    static HTTP_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct HttpEnvGuard {
        saved: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl HttpEnvGuard {
        fn acquire(keys: &[&str]) -> Self {
            let lock = HTTP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut saved = Vec::new();
            for &k in keys {
                saved.push((k.to_string(), std::env::var(k).ok()));
                std::env::remove_var(k);
            }
            Self { saved, _lock: lock }
        }

        fn set(&self, key: &str, val: &str) {
            std::env::set_var(key, val);
        }
    }

    impl Drop for HttpEnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    #[test]
    fn fetch_http_bytes_capped_rejects_oversize() {
        let body = vec![b'x'; 64];
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: false,
            honor_range: false,
            head_rejects: false,
            require_basic: None,
            require_cookie: None,
        });
        let url = mock.url("/ptr");
        let got = fetch_http_bytes_capped(&url, 64).unwrap();
        assert_eq!(got, body);
        let err = fetch_http_bytes_capped(&url, 16).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "{err}");
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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
            require_basic: None,
            require_cookie: None,
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

    // --- FR-2 / #157: HTTP Basic authentication ---

    #[test]
    fn parse_http_url_strips_userinfo() {
        let loc = parse_http_url("https://alice:s3cret@files.example.com/a.tar").unwrap();
        assert_eq!(loc.url, "https://files.example.com/a.tar");
        let auth = loc.auth.expect("auth");
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password.as_deref(), Some("s3cret"));
        assert_eq!(
            auth.authorization_header(),
            webdav::basic_auth_header("alice", Some("s3cret"))
        );
    }

    #[test]
    fn parse_http_url_env_fallback() {
        let _g = HttpEnvGuard::acquire(&[HTTP_USER_ENV, HTTP_PASSWORD_ENV]);
        _g.set(HTTP_USER_ENV, "envuser");
        _g.set(HTTP_PASSWORD_ENV, "envpass");
        let loc = parse_http_url("http://127.0.0.1:9/blob.bin").unwrap();
        let auth = loc.auth.expect("env auth");
        assert_eq!(auth.username, "envuser");
        assert_eq!(auth.password.as_deref(), Some("envpass"));
        // URL userinfo wins over env.
        let loc2 = parse_http_url("http://urluser:urlpass@127.0.0.1:9/x").unwrap();
        let auth2 = loc2.auth.expect("url auth");
        assert_eq!(auth2.username, "urluser");
        assert_eq!(auth2.password.as_deref(), Some("urlpass"));
    }

    /// Regression: HTTP Basic auth via URL userinfo on GET materialize.
    #[test]
    fn http_basic_auth_from_url_userinfo() {
        let body = b"auth-url-payload".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: false,
            honor_range: false,
            head_rejects: false,
            require_basic: Some(("alice".into(), "s3cret".into())),
            require_cookie: None,
        });
        let bare = mock.url("/secret.bin");
        let err = fetch_http_to_temp(&bare).unwrap_err().to_string();
        assert!(
            err.contains("401"),
            "expected clear 401 without credentials, got {err}"
        );
        assert!(
            err.contains(HTTP_USER_ENV) || err.contains("userinfo") || err.contains("user:pass"),
            "401 should mention credential sources, got {err}"
        );

        let authed = mock.url_with_auth("alice", "s3cret", "/secret.bin");
        let (mut tmp, size) = fetch_http_to_temp(&authed).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("Authorization: Basic ")),
            "expected Authorization on GET, log={log:?}"
        );
    }

    /// Regression: HTTP Basic auth via RATARMOUNT_HTTP_USER / RATARMOUNT_HTTP_PASSWORD.
    #[test]
    fn http_basic_auth_from_env() {
        let body = b"auth-env-payload".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: false,
            honor_range: false,
            head_rejects: false,
            require_basic: Some(("envuser".into(), "envpass".into())),
            require_cookie: None,
        });
        let _g = HttpEnvGuard::acquire(&[HTTP_USER_ENV, HTTP_PASSWORD_ENV]);
        _g.set(HTTP_USER_ENV, "envuser");
        _g.set(HTTP_PASSWORD_ENV, "envpass");
        let url = mock.url("/env.bin");
        let (mut tmp, size) = fetch_http_to_temp_prefer_range(&url).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }

    /// Regression: Authorization Basic sent on live Range GETs after open.
    #[test]
    fn http_basic_auth_on_range_requests() {
        let body: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
            require_basic: Some(("rangeuser".into(), "rangepass".into())),
            require_cookie: None,
        });
        let url = mock.url_with_auth("rangeuser", "rangepass", "/ranged.bin");
        let mut f = HttpRangeFile::open(&url).unwrap();
        assert!(f.uses_ranges());
        // Credentials stripped from stored URL.
        assert!(!f.url().contains("rangepass"));
        assert!(!f.url().contains("rangeuser@"));
        assert_eq!(f.auth().map(|a| a.username.as_str()), Some("rangeuser"));

        f.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = [0u8; 32];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &body[100..132]);
        assert!(mock.range_gets.load(Ordering::SeqCst) >= 1);
        let log = mock.log.lock().unwrap();
        let auth_count = log
            .iter()
            .filter(|l| l.starts_with("Authorization: Basic "))
            .count();
        assert!(
            auth_count >= 2,
            "expected Basic auth on probe + Range GET, log={log:?}"
        );
    }

    /// Regression: wrong password → clear HTTP 401, not a generic transport error.
    #[test]
    fn http_basic_auth_401_clear_error() {
        let body = b"nope".to_vec();
        let mock = MockHttp::spawn(MockConfig {
            body,
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
            require_basic: Some(("good".into(), "pass".into())),
            require_cookie: None,
        });
        let bad = mock.url_with_auth("good", "wrong", "/x.bin");
        let err = open_http_range(&bad).unwrap_err().to_string();
        assert!(err.contains("401"), "got {err}");
        assert!(
            err.contains("Unauthorized") || err.contains(HTTP_USER_ENV),
            "got {err}"
        );
    }

    // --- FR-2 residual / #157: Cookie-based HTTP authentication ---

    #[test]
    fn redact_cookie_header_hides_values() {
        assert_eq!(
            redact_cookie_header("session=abc; token=xyz"),
            "session=***; token=***"
        );
        assert_eq!(redact_cookie_header("solo=secret"), "solo=***");
        assert_eq!(redact_cookie_header("  a=1 ; b=2  "), "a=***; b=***");
        // Malformed fragment without '=' still redacted.
        assert_eq!(redact_cookie_header("noequals"), "***");
    }

    #[test]
    fn parse_cookie_file_simple_and_netscape() {
        let simple = parse_cookie_file_contents("session=abc\ntoken=xyz\n").unwrap();
        assert_eq!(simple, "session=abc; token=xyz");

        let netscape = "\
# Netscape HTTP Cookie File
.example.com\tTRUE\t/\tFALSE\t0\tsession\tabc123
.example.com\tTRUE\t/\tTRUE\t0\ttoken\txyz789
";
        assert_eq!(
            parse_cookie_file_contents(netscape).as_deref(),
            Some("session=abc123; token=xyz789")
        );

        let httponly = "#HttpOnly_.example.com\tTRUE\t/\tFALSE\t0\thid\tval\n";
        assert_eq!(
            parse_cookie_file_contents(httponly).as_deref(),
            Some("hid=val")
        );

        assert!(parse_cookie_file_contents("# only comments\n\n").is_none());
    }

    #[test]
    fn parse_http_url_cookie_from_env() {
        let _g = HttpEnvGuard::acquire(&[
            HTTP_USER_ENV,
            HTTP_PASSWORD_ENV,
            HTTP_COOKIE_ENV,
            HTTP_COOKIE_FILE_ENV,
        ]);
        _g.set(HTTP_COOKIE_ENV, "session=abc; token=xyz");
        let loc = parse_http_url("http://127.0.0.1:9/blob.bin").unwrap();
        assert!(loc.auth.is_none());
        assert_eq!(loc.cookie.as_deref(), Some("session=abc; token=xyz"));
        // Debug must not leak cookie values.
        let dbg = format!("{loc:?}");
        assert!(
            !dbg.contains("abc") && !dbg.contains("xyz"),
            "Debug leaked cookie value: {dbg}"
        );
        assert!(dbg.contains("session=***") || dbg.contains("***"), "{dbg}");
    }

    #[test]
    fn parse_http_url_cookie_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookies.txt");
        std::fs::write(
            &path,
            "# Netscape HTTP Cookie File\n\
             .example.com\tTRUE\t/\tFALSE\t0\tsid\tfilecookie\n",
        )
        .unwrap();
        let _g = HttpEnvGuard::acquire(&[
            HTTP_USER_ENV,
            HTTP_PASSWORD_ENV,
            HTTP_COOKIE_ENV,
            HTTP_COOKIE_FILE_ENV,
        ]);
        _g.set(HTTP_COOKIE_FILE_ENV, path.to_str().unwrap());
        let loc = parse_http_url("http://127.0.0.1:9/blob.bin").unwrap();
        assert_eq!(loc.cookie.as_deref(), Some("sid=filecookie"));
    }

    #[test]
    fn parse_http_url_cookie_env_wins_over_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookies.txt");
        std::fs::write(&path, "fromfile=1\n").unwrap();
        let _g = HttpEnvGuard::acquire(&[
            HTTP_USER_ENV,
            HTTP_PASSWORD_ENV,
            HTTP_COOKIE_ENV,
            HTTP_COOKIE_FILE_ENV,
        ]);
        _g.set(HTTP_COOKIE_ENV, "fromenv=1");
        _g.set(HTTP_COOKIE_FILE_ENV, path.to_str().unwrap());
        let loc = parse_http_url("http://127.0.0.1:9/x").unwrap();
        assert_eq!(loc.cookie.as_deref(), Some("fromenv=1"));
    }

    /// Regression: Cookie header sent on GET materialize; absent without env.
    #[test]
    fn http_cookie_auth_from_env() {
        let body = b"cookie-payload".to_vec();
        let cookie = "session=s3cr3t-session; role=user";
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: false,
            honor_range: false,
            head_rejects: false,
            require_basic: None,
            require_cookie: Some(cookie.into()),
        });
        let url = mock.url("/cookie.bin");

        // Without cookie → 401.
        let _g = HttpEnvGuard::acquire(&[
            HTTP_USER_ENV,
            HTTP_PASSWORD_ENV,
            HTTP_COOKIE_ENV,
            HTTP_COOKIE_FILE_ENV,
        ]);
        let err = fetch_http_to_temp(&url).unwrap_err().to_string();
        assert!(
            err.contains("401"),
            "expected 401 without cookie, got {err}"
        );
        assert!(
            err.contains(HTTP_COOKIE_ENV) || err.contains("Unauthorized"),
            "401 should mention cookie/credential sources, got {err}"
        );

        _g.set(HTTP_COOKIE_ENV, cookie);
        let (mut tmp, size) = fetch_http_to_temp(&url).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l == &format!("Cookie: {cookie}")),
            "expected Cookie on GET, log={log:?}"
        );
    }

    /// Regression: Cookie + Basic Authorization both sent when both configured.
    #[test]
    fn http_basic_and_cookie_together() {
        let body = b"both-auth-payload".to_vec();
        let cookie = "sid=combo";
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: false,
            honor_range: false,
            head_rejects: false,
            require_basic: Some(("alice".into(), "s3cret".into())),
            require_cookie: Some(cookie.into()),
        });
        let _g = HttpEnvGuard::acquire(&[
            HTTP_USER_ENV,
            HTTP_PASSWORD_ENV,
            HTTP_COOKIE_ENV,
            HTTP_COOKIE_FILE_ENV,
        ]);
        _g.set(HTTP_COOKIE_ENV, cookie);
        // URL Basic + env Cookie.
        let url = mock.url_with_auth("alice", "s3cret", "/both.bin");
        let (mut tmp, size) = fetch_http_to_temp(&url).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("Authorization: Basic ")),
            "expected Basic, log={log:?}"
        );
        assert!(
            log.iter().any(|l| l == &format!("Cookie: {cookie}")),
            "expected Cookie, log={log:?}"
        );
    }

    /// Regression: Cookie retained on live Range GETs after open.
    #[test]
    fn http_cookie_on_range_requests() {
        let body: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let cookie = "range=cookie-val";
        let mock = MockHttp::spawn(MockConfig {
            body: body.clone(),
            accept_ranges: true,
            honor_range: true,
            head_rejects: false,
            require_basic: None,
            require_cookie: Some(cookie.into()),
        });
        let _g = HttpEnvGuard::acquire(&[
            HTTP_USER_ENV,
            HTTP_PASSWORD_ENV,
            HTTP_COOKIE_ENV,
            HTTP_COOKIE_FILE_ENV,
        ]);
        _g.set(HTTP_COOKIE_ENV, cookie);
        let url = mock.url("/ranged-cookie.bin");
        let mut f = HttpRangeFile::open(&url).unwrap();
        assert!(f.uses_ranges());
        assert_eq!(f.cookie(), Some(cookie));
        // Debug redacts cookie values.
        let dbg = format!("{f:?}");
        assert!(
            !dbg.contains("cookie-val"),
            "HttpRangeFile Debug leaked cookie: {dbg}"
        );

        f.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = [0u8; 32];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &body[100..132]);
        assert!(mock.range_gets.load(Ordering::SeqCst) >= 1);
        let log = mock.log.lock().unwrap();
        let cookie_line = format!("Cookie: {cookie}");
        let cookie_count = log.iter().filter(|l| *l == &cookie_line).count();
        assert!(
            cookie_count >= 2,
            "expected Cookie on probe + Range GET, log={log:?}"
        );
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
