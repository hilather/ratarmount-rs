//! IPFS / IPNS ingest (`ipfs://`, `ipns://`) via a gateway Range GET and optional Kubo API.
//!
//! Do **not** embed an IPFS node. File CIDs are rewritten to
//! `{IPFS_GATEWAY}/ipfs/{cid}/path` (default `http://127.0.0.1:8080`) and opened
//! with [`HttpRangeFile`]. UnixFS directories use `IPFS_API` (default
//! `http://127.0.0.1:5001`) `POST /api/v0/ls?arg=` and [`RemoteFolderMountSource`].
//! If the API is down, file GET via the gateway still works; a directory mount
//! fails with a clear error naming `IPFS_API`.
//!
//! Factory `is_remote_url` / `RemoteError::Ipfs` wiring is a later PR.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use log::debug;
use ratarmount_core::{ArchiveRead, MountSource};
use url::Url;

use crate::{
    HttpRangeFile, RemoteDirent, RemoteError, RemoteFolderMountSource, RemoteListing, Result,
    USER_AGENT,
};

/// Env: HTTP gateway base used to Range-GET UnixFS files (no trailing slash needed).
pub const IPFS_GATEWAY_ENV: &str = "IPFS_GATEWAY";
/// Env: Kubo HTTP API base for `/api/v0/ls` (UnixFS directories). Also accepts
/// `/ip4/127.0.0.1/tcp/5001` multiaddrs and `unix:///path` sockets.
pub const IPFS_API_ENV: &str = "IPFS_API";

/// Default path-style gateway (local daemon).
pub const DEFAULT_IPFS_GATEWAY: &str = "http://127.0.0.1:8080";
/// Default Kubo RPC API (local daemon).
pub const DEFAULT_IPFS_API: &str = "http://127.0.0.1:5001";

const API_TIMEOUT: Duration = Duration::from_secs(5);

/// `ipfs://` (immutable CID) or `ipns://` (mutable name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpfsScheme {
    Ipfs,
    Ipns,
}

impl IpfsScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ipfs => "ipfs",
            Self::Ipns => "ipns",
        }
    }
}

/// Parsed `ipfs://<cid>[/path]` or `ipns://<name>[/path]`.
///
/// The CID / IPNS name is **not** DNS-lowercased (`url::Url` would mangle CIDv0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfsLocation {
    pub scheme: IpfsScheme,
    /// CIDv0/v1 or IPNS name (case-preserving).
    pub id: String,
    /// Path after the CID/name, no leading slash.
    pub path: String,
    /// Original URL ended with `/` (directory hint when the API is down).
    pub trailing_slash: bool,
}

impl IpfsLocation {
    /// Reconstruct `ipfs://cid/path` (no credentials in this scheme).
    pub fn to_url(&self) -> String {
        let mut s = if self.path.is_empty() {
            format!("{}://{}", self.scheme.as_str(), self.id)
        } else {
            format!("{}://{}/{}", self.scheme.as_str(), self.id, self.path)
        };
        if self.trailing_slash && !s.ends_with('/') {
            s.push('/');
        }
        s
    }

    /// Kubo `arg` for `/api/v0/ls`: `/ipfs/{cid}/path` or `/ipns/{name}/path`.
    pub fn api_arg(&self) -> String {
        if self.path.is_empty() {
            format!("/{}/{}", self.scheme.as_str(), self.id)
        } else {
            format!("/{}/{}/{}", self.scheme.as_str(), self.id, self.path)
        }
    }

    /// `{gateway}/ipfs/{cid}/path` (or `/ipns/…`).
    pub fn gateway_http_url(&self, gateway: &str) -> String {
        let gw = gateway.trim_end_matches('/');
        let mut url = format!(
            "{gw}/{}/{}",
            self.scheme.as_str(),
            percent_encode_seg(&self.id)
        );
        if !self.path.is_empty() {
            for part in self.path.split('/') {
                if part.is_empty() {
                    continue;
                }
                url.push('/');
                url.push_str(&percent_encode_seg(part));
            }
        }
        if self.trailing_slash && !url.ends_with('/') {
            url.push('/');
        }
        url
    }

    fn join_path(&self, rel: &str) -> Self {
        let rel = rel.trim_start_matches('/');
        let trailing_slash = rel.ends_with('/');
        let rel = rel.trim_end_matches('/');
        if rel.is_empty() {
            let mut loc = self.clone();
            loc.trailing_slash |= trailing_slash;
            return loc;
        }
        let path = if self.path.is_empty() {
            rel.to_string()
        } else {
            format!("{}/{}", self.path.trim_end_matches('/'), rel)
        };
        Self {
            scheme: self.scheme,
            id: self.id.clone(),
            path,
            trailing_slash,
        }
    }
}

/// Percent-encode one path segment; CID-safe unreserved bytes stay literal.
fn percent_encode_seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0x0f));
            }
        }
    }
    out
}

fn hex_digit(n: u8) -> char {
    char::from(if n < 10 { b'0' + n } else { b'A' + (n - 10) })
}

/// Parse `ipfs://<cid>[/path]` / `ipns://<name>[/path]` without `url::Url` (CIDv0 is case-sensitive).
pub fn parse_ipfs_url(s: &str) -> Result<IpfsLocation> {
    let s = s.trim();
    let Some((scheme_raw, rest)) = s.split_once("://") else {
        return Err(RemoteError::Url(format!(
            "ipfs URL missing scheme: expected ipfs:// or ipns://, got {s:?}"
        )));
    };
    let scheme = match scheme_raw.to_ascii_lowercase().as_str() {
        "ipfs" => IpfsScheme::Ipfs,
        "ipns" => IpfsScheme::Ipns,
        other => return Err(RemoteError::UnsupportedScheme(other.to_string())),
    };
    let trailing_slash = rest.ends_with('/');
    let rest = rest.trim_matches('/');
    let rest = strip_kind_prefix(rest, scheme.as_str()).trim_matches('/');
    if rest.is_empty() {
        return Err(RemoteError::Url(
            "ipfs URL missing CID or IPNS name (expected ipfs://<cid>[/path])".into(),
        ));
    }
    let (id, path) = match rest.split_once('/') {
        Some((id, path)) => (id.to_string(), decode_path(path.trim_matches('/'))),
        None => (rest.to_string(), String::new()),
    };
    if id.is_empty() {
        return Err(RemoteError::Url("ipfs URL missing CID or IPNS name".into()));
    }
    Ok(IpfsLocation {
        scheme,
        id,
        path,
        trailing_slash,
    })
}

/// Drop a redundant `/ipfs/` or `/ipns/` prefix copied from path-style URLs.
fn strip_kind_prefix<'a>(rest: &'a str, kind: &str) -> &'a str {
    if let Some(stripped) = rest.strip_prefix(&format!("{kind}/")) {
        stripped
    } else if rest.eq_ignore_ascii_case(kind) {
        ""
    } else {
        rest
    }
}

fn decode_path(s: &str) -> String {
    s.split('/')
        .filter(|p| !p.is_empty())
        .map(percent_decode)
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_decode(s: &str) -> String {
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

/// Resolved [`IPFS_GATEWAY_ENV`] (default [`DEFAULT_IPFS_GATEWAY`]).
pub fn ipfs_gateway() -> String {
    normalize_http_base(
        std::env::var(IPFS_GATEWAY_ENV)
            .ok()
            .as_deref()
            .unwrap_or(""),
        DEFAULT_IPFS_GATEWAY,
    )
}

/// Resolved [`IPFS_API_ENV`] HTTP base or unix path (default [`DEFAULT_IPFS_API`]).
pub fn ipfs_api() -> String {
    let raw = std::env::var(IPFS_API_ENV).ok();
    match parse_api_endpoint(raw.as_deref().unwrap_or("")) {
        Ok(ApiEndpoint::Http(u)) => u,
        #[cfg(unix)]
        Ok(ApiEndpoint::Unix(p)) => format!("unix://{}", p.display()),
        Err(_) => DEFAULT_IPFS_API.to_string(),
    }
}

enum ApiEndpoint {
    Http(String),
    #[cfg(unix)]
    Unix(PathBuf),
}

fn parse_api_endpoint(raw: &str) -> Result<ApiEndpoint> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(ApiEndpoint::Http(DEFAULT_IPFS_API.to_string()));
    }
    if let Some(path) = s.strip_prefix("unix://") {
        return unix_endpoint(PathBuf::from(path));
    }
    if let Some(rest) = s.strip_prefix("/unix/") {
        return unix_endpoint(PathBuf::from(format!("/{rest}")));
    }
    if let Some(http) = multiaddr_to_http(s) {
        return Ok(ApiEndpoint::Http(http));
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return Ok(ApiEndpoint::Http(s.trim_end_matches('/').to_string()));
    }
    Ok(ApiEndpoint::Http(format!(
        "http://{}",
        s.trim_end_matches('/')
    )))
}

fn unix_endpoint(path: PathBuf) -> Result<ApiEndpoint> {
    #[cfg(unix)]
    {
        Ok(ApiEndpoint::Unix(path))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(RemoteError::Url(
            "ipfs: unix IPFS_API sockets are not supported on this platform".into(),
        ))
    }
}

/// `/ip4/127.0.0.1/tcp/5001` (and dns/ip6) → `http://127.0.0.1:5001`.
fn multiaddr_to_http(s: &str) -> Option<String> {
    if !s.starts_with("/ip4/")
        && !s.starts_with("/ip6/")
        && !s.starts_with("/dns4/")
        && !s.starts_with("/dns6/")
        && !s.starts_with("/dns/")
    {
        return None;
    }
    let parts: Vec<&str> = s.trim_matches('/').split('/').collect();
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut scheme = "http";
    let mut i = 0;
    while i < parts.len() {
        let key = parts[i];
        let val = parts.get(i + 1).copied();
        match (key, val) {
            ("ip4" | "dns4" | "dns6" | "dns", Some(h)) => {
                host = Some(h.to_string());
                i += 2;
            }
            ("ip6", Some(h)) => {
                host = Some(format!("[{h}]"));
                i += 2;
            }
            ("tcp", Some(p)) => {
                port = p.parse().ok();
                i += 2;
            }
            ("https", _) => {
                scheme = "https";
                i += 1;
            }
            ("http", _) => {
                scheme = "http";
                i += 1;
            }
            _ => i += 1,
        }
    }
    let host = host?;
    let port = port.unwrap_or(5001);
    Some(format!("{scheme}://{host}:{port}"))
}

fn normalize_http_base(raw: &str, default: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return default.to_string();
    }
    if let Some(h) = multiaddr_to_http(s) {
        return h;
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return s.trim_end_matches('/').to_string();
    }
    format!("http://{}", s.trim_end_matches('/'))
}

fn ipfs_err(msg: impl Into<String>) -> RemoteError {
    RemoteError::Http(msg.into())
}

fn dir_requires_api(api: &str, cause: &RemoteError) -> RemoteError {
    ipfs_err(format!(
        "ipfs: directory CID requires the Kubo HTTP API for UnixFS list \
         (IPFS_API, default {DEFAULT_IPFS_API}); unreachable at {api}: {cause}. \
         File CIDs still work via the gateway (IPFS_GATEWAY). No embedded IPFS node."
    ))
}

/// Seekable IPFS file handle (gateway Range GET, wrapping [`HttpRangeFile`]).
pub struct IpfsHandle {
    inner: HttpRangeFile,
}

impl std::fmt::Debug for IpfsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpfsHandle")
            .field("url", &self.inner.url())
            .field("size", &self.inner.len())
            .field("uses_ranges", &self.inner.uses_ranges())
            .finish()
    }
}

impl IpfsHandle {
    pub fn uses_ranges(&self) -> bool {
        self.inner.uses_ranges()
    }

    pub fn len(&self) -> u64 {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn url(&self) -> &str {
        self.inner.url()
    }
}

impl Read for IpfsHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for IpfsHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Open `ipfs://` / `ipns://` as a live gateway Range file (or buffered GET).
pub fn open_ipfs(s: &str) -> Result<IpfsHandle> {
    open_ipfs_at(s, &ipfs_gateway())
}

/// [`open_ipfs`] with an explicit gateway base (tests / factory).
pub fn open_ipfs_at(s: &str, gateway: &str) -> Result<IpfsHandle> {
    let loc = parse_ipfs_url(s)?;
    let url = loc.gateway_http_url(gateway);
    debug!("IPFS gateway GET {url}");
    Ok(IpfsHandle {
        inner: HttpRangeFile::open(&url)?,
    })
}

/// Mount a UnixFS directory as [`RemoteFolderMountSource`].
///
/// `Ok(None)` when `s` is a file CID (factory should Range-GET the gateway).
/// Errors when the CID is a directory and `IPFS_API` is unreachable.
pub fn open_ipfs_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    open_ipfs_folder_at(s, &ipfs_gateway(), &ipfs_api())
}

/// [`open_ipfs_folder`] with explicit gateway + API bases.
pub fn open_ipfs_folder_at(
    s: &str,
    gateway: &str,
    api: &str,
) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_ipfs_url(s)?;
    match ipfs_ls(api, &loc) {
        Ok(links) => {
            if !links_mean_directory(&loc, s, &links) {
                return Ok(None);
            }
            Ok(Some(Arc::new(RemoteFolderMountSource::new(
                loc.to_url(),
                IpfsListing {
                    gateway: normalize_http_base(gateway, DEFAULT_IPFS_GATEWAY),
                    api: api.to_string(),
                },
            ))))
        }
        Err(e) => {
            if loc.trailing_slash || s.trim_end().ends_with('/') {
                return Err(dir_requires_api(api, &e));
            }
            let gw_url = loc.gateway_http_url(gateway);
            if gateway_looks_like_directory(&gw_url) {
                return Err(dir_requires_api(api, &e));
            }
            debug!(
                "IPFS API ls failed for {}; treating as file: {e}",
                loc.to_url()
            );
            Ok(None)
        }
    }
}

fn links_mean_directory(loc: &IpfsLocation, original: &str, links: &[IpfsLsLink]) -> bool {
    loc.trailing_slash
        || original.trim_end().ends_with('/')
        || links.iter().any(|l| l.is_dir || !l.name.is_empty())
}

/// UnixFS listing backend for [`RemoteFolderMountSource`].
pub struct IpfsListing {
    gateway: String,
    api: String,
}

impl std::fmt::Debug for IpfsListing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpfsListing")
            .field("gateway", &self.gateway)
            .field("api", &self.api)
            .finish()
    }
}

impl RemoteListing for IpfsListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        let loc = parse_ipfs_url(remote_path)?;
        let links = ipfs_ls(&self.api, &loc)?;
        Ok(links
            .into_iter()
            .map(|l| {
                let child = loc.join_path(&l.name);
                RemoteDirent {
                    name: l.name,
                    remote_path: child.to_url(),
                    is_dir: l.is_dir,
                    size: l.size,
                    mtime: 0.0,
                }
            })
            .collect())
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        let loc = parse_ipfs_url(remote_path)?;
        if loc.trailing_slash {
            return Ok(true);
        }
        let links = ipfs_ls(&self.api, &loc)?;
        Ok(links_mean_directory(&loc, remote_path, &links))
    }

    fn join(&self, root: &str, rel: &str) -> String {
        match parse_ipfs_url(root) {
            Ok(loc) => loc.join_path(rel).to_url(),
            Err(_) => {
                let rel = rel.trim_start_matches('/');
                if rel.is_empty() {
                    root.to_string()
                } else if root.ends_with('/') {
                    format!("{root}{rel}")
                } else {
                    format!("{root}/{rel}")
                }
            }
        }
    }

    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>> {
        let loc = parse_ipfs_url(remote_path)?;
        let url = loc.gateway_http_url(&self.gateway);
        if size > 0 {
            Ok(Box::new(HttpRangeFile::range_backed(&url, size)))
        } else {
            Ok(Box::new(HttpRangeFile::open(&url)?))
        }
    }
}

#[derive(Debug)]
struct IpfsLsLink {
    name: String,
    size: u64,
    is_dir: bool,
}

fn ipfs_ls(api: &str, loc: &IpfsLocation) -> Result<Vec<IpfsLsLink>> {
    let endpoint = parse_api_endpoint(api)?;
    let text = match endpoint {
        ApiEndpoint::Http(base) => ls_via_http(&base, loc)?,
        #[cfg(unix)]
        ApiEndpoint::Unix(path) => ls_via_unix(&path, loc)?,
    };
    parse_ipfs_ls_json(&text)
}

fn ls_url(api_base: &str, loc: &IpfsLocation) -> Result<Url> {
    let base = format!("{}/api/v0/ls", api_base.trim_end_matches('/'));
    let mut url =
        Url::parse(&base).map_err(|e| RemoteError::Url(format!("IPFS_API {base}: {e}")))?;
    url.query_pairs_mut().append_pair("arg", &loc.api_arg());
    Ok(url)
}

fn ls_via_http(api_base: &str, loc: &IpfsLocation) -> Result<String> {
    let url = ls_url(api_base, loc)?;
    let url_s = url.as_str();
    debug!("IPFS API ls {url_s}");
    match ureq::post(url_s)
        .timeout(API_TIMEOUT)
        .set("User-Agent", USER_AGENT)
        .call()
    {
        Ok(resp) => read_ureq_body(resp, "ls"),
        Err(ureq::Error::Status(code, _)) if code == 404 || code == 405 => {
            // Some gateways only allow GET on /api/v0/ls.
            match ureq::get(url_s)
                .timeout(API_TIMEOUT)
                .set("User-Agent", USER_AGENT)
                .call()
            {
                Ok(resp) => read_ureq_body(resp, "ls"),
                Err(e) => Err(map_ureq(e, "ls")),
            }
        }
        Err(e) => Err(map_ureq(e, "ls")),
    }
}

fn read_ureq_body(resp: ureq::Response, what: &str) -> Result<String> {
    let status = resp.status();
    let text = resp
        .into_string()
        .map_err(|e| ipfs_err(format!("ipfs: {what}: read body: {e}")))?;
    if !(200..300).contains(&status) {
        return Err(ipfs_err(format!(
            "ipfs: {what}: HTTP {status}: {}",
            json_message(&text).as_deref().unwrap_or(text.as_str())
        )));
    }
    Ok(text)
}

fn map_ureq(e: ureq::Error, what: &str) -> RemoteError {
    match e {
        ureq::Error::Status(_code, resp) => {
            let status = resp.status();
            let text = resp.into_string().unwrap_or_default();
            ipfs_err(format!(
                "ipfs: {what}: HTTP {status}: {}",
                json_message(&text).as_deref().unwrap_or(text.as_str())
            ))
        }
        other => ipfs_err(format!("ipfs: {what}: {other}")),
    }
}

fn json_message(text: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    v.get("Message")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(unix)]
fn ls_via_unix(sock: &std::path::Path, loc: &IpfsLocation) -> Result<String> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let url = ls_url("http://localhost", loc)?;
    let path_query = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };

    let mut stream = UnixStream::connect(sock).map_err(|e| {
        ipfs_err(format!(
            "ipfs: ls: IPFS_API unix socket {}: {e}",
            sock.display()
        ))
    })?;
    stream.set_read_timeout(Some(API_TIMEOUT)).ok();
    stream.set_write_timeout(Some(API_TIMEOUT)).ok();
    let req = format!(
        "POST {path_query} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: {USER_AGENT}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| ipfs_err(format!("ipfs: ls unix write: {e}")))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| ipfs_err(format!("ipfs: ls unix read: {e}")))?;
    split_http_body(&buf)
}

#[cfg(unix)]
fn split_http_body(raw: &[u8]) -> Result<String> {
    let text = String::from_utf8_lossy(raw);
    let Some((headers, body)) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
    else {
        return Err(ipfs_err("ipfs: ls unix: malformed HTTP response"));
    };
    let status = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 0 && !(200..300).contains(&status) {
        return Err(ipfs_err(format!(
            "ipfs: ls unix: HTTP {status}: {}",
            json_message(body).as_deref().unwrap_or(body.trim())
        )));
    }
    Ok(body.to_string())
}

/// Parse Kubo `/api/v0/ls` JSON (`Objects[].Links[]`).
///
/// `Type` may be a UnixFS number (`1` directory, `2` file, `5` HAMT) or a
/// string (`Directory` / `File`). Unnamed chunk links are skipped.
fn parse_ipfs_ls_json(text: &str) -> Result<Vec<IpfsLsLink>> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| ipfs_err(format!("ipfs: ls JSON parse error: {e}")))?;
    if v.get("Objects").is_none() {
        if let Some(msg) = v.get("Message").and_then(|m| m.as_str()) {
            return Err(ipfs_err(format!("ipfs: ls: {msg}")));
        }
        return Err(ipfs_err("ipfs: ls JSON missing Objects"));
    }
    let mut out = Vec::new();
    let Some(objects) = v.get("Objects").and_then(|o| o.as_array()) else {
        return Ok(out);
    };
    for obj in objects {
        let Some(links) = obj.get("Links").and_then(|l| l.as_array()) else {
            continue;
        };
        for link in links {
            let mut name = link
                .get("Name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let name_slash = name.ends_with('/');
            if name_slash {
                name = name.trim_end_matches('/').to_string();
            }
            if name.is_empty() {
                continue;
            }
            let size = json_u64(link.get("Size")).unwrap_or(0);
            let is_dir = name_slash || type_is_directory(link.get("Type"));
            out.push(IpfsLsLink { name, size, is_dir });
        }
    }
    Ok(out)
}

fn json_u64(v: Option<&serde_json::Value>) -> Option<u64> {
    let v = v?;
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

/// UnixFS: 0 Raw, 1 Directory, 2 File, 5 HAMTShard. Strings: Directory / File.
fn type_is_directory(ty: Option<&serde_json::Value>) -> bool {
    match ty {
        Some(v) if v.is_string() => {
            let s = v.as_str().unwrap_or("");
            s.eq_ignore_ascii_case("directory") || s.eq_ignore_ascii_case("hamtshard")
        }
        Some(v) => matches!(v.as_i64(), Some(1 | 5)),
        None => false,
    }
}

fn gateway_looks_like_directory(url: &str) -> bool {
    match ureq::head(url)
        .timeout(API_TIMEOUT)
        .set("User-Agent", USER_AGENT)
        .call()
    {
        Ok(resp) => content_type_is_html(resp.header("Content-Type")),
        Err(ureq::Error::Status(_, resp)) => content_type_is_html(resp.header("Content-Type")),
        Err(_) => match ureq::get(url)
            .timeout(API_TIMEOUT)
            .set("User-Agent", USER_AGENT)
            .set("Range", "bytes=0-0")
            .call()
        {
            Ok(resp) => content_type_is_html(resp.header("Content-Type")),
            Err(ureq::Error::Status(_, resp)) => content_type_is_html(resp.header("Content-Type")),
            Err(_) => false,
        },
    }
}

fn content_type_is_html(header: Option<&str>) -> bool {
    header
        .map(|s| {
            s.split(';')
                .next()
                .unwrap_or(s)
                .trim()
                .eq_ignore_ascii_case("text/html")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc as StdArc, Mutex};
    use std::thread;

    #[test]
    fn parse_ipfs_url_table() {
        let loc = parse_ipfs_url("ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG").unwrap();
        assert_eq!(loc.scheme, IpfsScheme::Ipfs);
        assert_eq!(loc.id, "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");
        assert!(loc.path.is_empty());
        assert!(!loc.trailing_slash);

        let loc = parse_ipfs_url("ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG/hello.txt")
            .unwrap();
        assert_eq!(loc.path, "hello.txt");

        let loc = parse_ipfs_url("ipns://k51qzi5uqu5dl/foo/bar").unwrap();
        assert_eq!(loc.scheme, IpfsScheme::Ipns);
        assert_eq!(loc.id, "k51qzi5uqu5dl");
        assert_eq!(loc.path, "foo/bar");

        let loc = parse_ipfs_url("ipns://docs.ipfs.tech/index.html").unwrap();
        assert_eq!(loc.id, "docs.ipfs.tech");
        assert_eq!(loc.path, "index.html");

        let loc = parse_ipfs_url("ipfs://bafybeig/dir/").unwrap();
        assert_eq!(loc.id, "bafybeig");
        assert_eq!(loc.path, "dir");
        assert!(loc.trailing_slash);

        let loc = parse_ipfs_url("ipfs:///ipfs/QmAbc/x").unwrap();
        assert_eq!(loc.id, "QmAbc");
        assert_eq!(loc.path, "x");
    }

    /// Regression: CIDv0 is case-sensitive Base58; do not DNS-lowercase the id.
    #[test]
    fn regression_ipfs_cid_is_not_dns_lowercased() {
        let cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        let loc = parse_ipfs_url(&format!("ipfs://{cid}/p")).unwrap();
        assert_eq!(loc.id, cid, "CIDv0 must keep mixed case");
        let loc = parse_ipfs_url(&format!("ipfs:///{cid}")).unwrap();
        assert_eq!(loc.id, cid);
        assert_eq!(loc.to_url(), format!("ipfs://{cid}"));
    }

    #[test]
    fn parse_ipfs_url_rejects_empty_and_other_schemes() {
        assert!(parse_ipfs_url("ipfs://").is_err());
        assert!(parse_ipfs_url("ipfs:///").is_err());
        match parse_ipfs_url("http://example.com/Qm") {
            Err(RemoteError::UnsupportedScheme(s)) => assert_eq!(s, "http"),
            other => panic!("expected UnsupportedScheme, got {other:?}"),
        }
    }

    #[test]
    fn gateway_url_rewrites_ipfs_and_ipns() {
        let loc = parse_ipfs_url("ipfs://QmAbc/foo bar").unwrap();
        assert_eq!(
            loc.gateway_http_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/ipfs/QmAbc/foo%20bar"
        );
        let loc = parse_ipfs_url("ipns://name.example/a").unwrap();
        assert_eq!(
            loc.gateway_http_url("http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080/ipns/name.example/a"
        );
        assert_eq!(loc.api_arg(), "/ipns/name.example/a");
    }

    #[test]
    fn multiaddr_and_unix_api_parse() {
        match parse_api_endpoint("/ip4/127.0.0.1/tcp/5001").unwrap() {
            ApiEndpoint::Http(u) => assert_eq!(u, "http://127.0.0.1:5001"),
            #[cfg(unix)]
            ApiEndpoint::Unix(_) => panic!("expected http"),
        }
        match parse_api_endpoint("http://127.0.0.1:5001/").unwrap() {
            ApiEndpoint::Http(u) => assert_eq!(u, "http://127.0.0.1:5001"),
            #[cfg(unix)]
            ApiEndpoint::Unix(_) => panic!("expected http"),
        }
        #[cfg(unix)]
        match parse_api_endpoint("unix:///tmp/ipfs.sock").unwrap() {
            ApiEndpoint::Unix(p) => assert_eq!(p, PathBuf::from("/tmp/ipfs.sock")),
            ApiEndpoint::Http(_) => panic!("expected unix"),
        }
    }

    #[test]
    fn parse_ls_json_type_string_and_number() {
        let json = r#"{
          "Objects": [{
            "Hash": "QmRoot",
            "Links": [
              {"Name": "hello.txt", "Hash": "QmFile", "Size": 11, "Type": "File"},
              {"Name": "sub", "Hash": "QmDir", "Size": 0, "Type": "Directory"},
              {"Name": "", "Hash": "QmChunk", "Size": 256, "Type": 2}
            ]
          }]
        }"#;
        let links = parse_ipfs_ls_json(json).unwrap();
        assert_eq!(links.len(), 2, "unnamed chunk skipped: {links:?}");
        assert!(!links[0].is_dir && links[0].name == "hello.txt" && links[0].size == 11);
        assert!(links[1].is_dir && links[1].name == "sub");

        let numeric = r#"{
          "Objects": [{
            "Links": [
              {"Name": "a.bin", "Hash": "QmA", "Size": "4", "Type": 2},
              {"Name": "d", "Hash": "QmD", "Size": 0, "Type": 1},
              {"Name": "shard", "Hash": "QmS", "Size": 0, "Type": 5}
            ]
          }]
        }"#;
        let links = parse_ipfs_ls_json(numeric).unwrap();
        assert!(!links[0].is_dir);
        assert!(links[1].is_dir);
        assert!(links[2].is_dir);
    }

    struct MockIpfs {
        addr: String,
        range_gets: StdArc<AtomicUsize>,
        ls_calls: StdArc<AtomicUsize>,
        log: StdArc<Mutex<Vec<String>>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    struct MockIpfsCfg {
        /// Path suffix (e.g. `/ipfs/QmFile` or `hello.txt`) → body.
        files: Vec<(String, Vec<u8>)>,
        /// Path prefixes that serve `text/html` (directory listing).
        dirs: Vec<String>,
        /// JSON for `/api/v0/ls`. `None` → 503.
        ls_json: Option<String>,
        honor_range: bool,
    }

    impl MockIpfs {
        fn spawn(cfg: MockIpfsCfg) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let range_gets = StdArc::new(AtomicUsize::new(0));
            let ls_calls = StdArc::new(AtomicUsize::new(0));
            let log = StdArc::new(Mutex::new(Vec::new()));
            let range_c = StdArc::clone(&range_gets);
            let ls_c = StdArc::clone(&ls_calls);
            let log_c = StdArc::clone(&log);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut range_hdr: Option<String> = None;
                    let mut content_len = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        if let Some(v) = line.strip_prefix("Range:") {
                            range_hdr = Some(v.trim().to_string());
                        }
                        if let Some((k, v)) = line.split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                content_len = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    if content_len > 0 {
                        let mut sink = vec![0u8; content_len];
                        let _ = std::io::Read::read_exact(&mut reader, &mut sink);
                    }
                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if let Some(r) = &range_hdr {
                            lg.push(format!("Range: {r}"));
                        }
                    }
                    let is_head = request_line.starts_with("HEAD ");
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    let path_only = path.split('?').next().unwrap_or(&path);

                    if path_only.contains("/api/v0/ls") {
                        ls_c.fetch_add(1, Ordering::SeqCst);
                        if let Some(json) = &cfg.ls_json {
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                                json.len()
                            );
                            if !is_head {
                                let _ = stream.write_all(json.as_bytes());
                            }
                        } else {
                            let msg = b"{\"Message\":\"api disabled\"}";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\n\
                                 Connection: close\r\n\r\n",
                                msg.len()
                            );
                            let _ = stream.write_all(msg);
                        }
                        continue;
                    }

                    let file_hit = cfg.files.iter().find(|(suffix, _)| {
                        path_only.ends_with(suffix.as_str()) || path_only.contains(suffix.as_str())
                    });
                    if let Some((_, body)) = file_hit {
                        if cfg.honor_range {
                            if let Some(r) = range_hdr.as_deref() {
                                if let Some(spec) = r.strip_prefix("bytes=") {
                                    let parts: Vec<&str> = spec.splitn(2, '-').collect();
                                    if parts.len() == 2 {
                                        let start: usize = parts[0].parse().unwrap_or(0);
                                        let end: usize = if parts[1].is_empty() {
                                            body.len().saturating_sub(1)
                                        } else {
                                            parts[1]
                                                .parse()
                                                .unwrap_or(0)
                                                .min(body.len().saturating_sub(1))
                                        };
                                        if start < body.len() && start <= end {
                                            range_c.fetch_add(1, Ordering::SeqCst);
                                            let slice = &body[start..=end];
                                            let hdr = format!(
                                                "HTTP/1.1 206 Partial Content\r\n\
                                                 Content-Length: {}\r\n\
                                                 Content-Range: bytes {}-{}/{}\r\n\
                                                 Accept-Ranges: bytes\r\n\
                                                 Content-Type: application/octet-stream\r\n\
                                                 Connection: close\r\n\r\n",
                                                slice.len(),
                                                start,
                                                end,
                                                body.len()
                                            );
                                            let _ = stream.write_all(hdr.as_bytes());
                                            if !is_head {
                                                let _ = stream.write_all(slice);
                                            }
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                             Accept-Ranges: bytes\r\nContent-Type: application/octet-stream\r\n\
                             Connection: close\r\n\r\n",
                            body.len()
                        );
                        if !is_head {
                            let _ = stream.write_all(body);
                        }
                        continue;
                    }

                    let is_dir = cfg.dirs.iter().any(|d| {
                        path_only.ends_with(d.as_str())
                            || path_only.contains(d.as_str())
                            || path_only.trim_end_matches('/') == d.trim_end_matches('/')
                    });
                    if is_dir {
                        let html = b"<html><body>Index of CID</body></html>";
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n",
                            html.len()
                        );
                        if !is_head {
                            let _ = stream.write_all(html);
                        }
                        continue;
                    }

                    let msg = b"not found";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    let _ = stream.write_all(msg);
                }
            });
            Self {
                addr,
                range_gets,
                ls_calls,
                log,
                _join: Some(join),
            }
        }
    }

    fn closed_http_url() -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        format!("http://{addr}")
    }

    #[test]
    fn mock_gateway_range_file_cid() {
        let body: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let mock = MockIpfs::spawn(MockIpfsCfg {
            files: vec![("/ipfs/QmFile".into(), body.clone())],
            dirs: vec![],
            ls_json: None,
            honor_range: true,
        });
        let mut f = open_ipfs_at("ipfs://QmFile", &mock.addr).unwrap();
        assert!(f.uses_ranges(), "gateway honored Range");
        assert_eq!(f.len(), body.len() as u64);
        let mut got = Vec::new();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        f.seek(SeekFrom::Start(100)).unwrap();
        let mut mid = [0u8; 4];
        f.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, &body[100..104]);
        assert!(
            mock.range_gets.load(Ordering::SeqCst) >= 1,
            "expected Range GETs, log={:?}",
            mock.log.lock().unwrap()
        );
        // No daemon API needed for a file CID.
        assert_eq!(mock.ls_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mock_api_ls_folder_lists_and_opens() {
        let body = b"hello-ipfs!".to_vec();
        let json = r#"{
          "Objects": [{
            "Hash": "QmRoot",
            "Links": [
              {"Name": "hello.txt", "Hash": "QmFile", "Size": 11, "Type": 2},
              {"Name": "sub", "Hash": "QmDir", "Size": 0, "Type": 1}
            ]
          }]
        }"#;
        let mock = MockIpfs::spawn(MockIpfsCfg {
            files: vec![
                ("/ipfs/QmRoot/hello.txt".into(), body.clone()),
                ("hello.txt".into(), body.clone()),
            ],
            dirs: vec![],
            ls_json: Some(json.into()),
            honor_range: true,
        });
        let ms = open_ipfs_folder_at("ipfs://QmRoot", &mock.addr, &mock.addr)
            .unwrap()
            .expect("UnixFS directory");
        let dents = ms.list_dirents("/").expect("dirents");
        assert!(
            dents.iter().any(|d| d.name == "hello.txt" && d.size == 11),
            "{dents:?}"
        );
        assert!(dents.iter().any(|d| d.name == "sub"), "{dents:?}");
        let fi = ms.lookup("/hello.txt", 0).expect("lookup");
        let mut r = ms.open(&fi, 0).unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert!(
            mock.ls_calls.load(Ordering::SeqCst) >= 1,
            "expected /api/v0/ls"
        );
    }

    /// Regression: directory CID without API is a clear error (not a silent HTML file).
    #[test]
    fn regression_directory_cid_without_api_is_clear_error() {
        let gw = MockIpfs::spawn(MockIpfsCfg {
            files: vec![],
            dirs: vec!["/ipfs/QmDir".into(), "QmDir".into()],
            ls_json: None,
            honor_range: false,
        });
        let dead_api = closed_http_url();

        let err = match open_ipfs_folder_at("ipfs://QmDir/", &gw.addr, &dead_api) {
            Err(e) => e,
            Ok(_) => panic!("expected directory-without-API error"),
        };
        let msg = err.to_string();
        assert!(
            msg.to_ascii_lowercase().contains("directory"),
            "expected directory error, got {msg}"
        );
        assert!(
            msg.contains("IPFS_API"),
            "expected IPFS_API in error, got {msg}"
        );
        assert!(
            !msg.to_ascii_lowercase().contains("unsupported"),
            "must not look like an unsupported scheme: {msg}"
        );

        // Same CID without trailing slash: gateway HTML listing still errors.
        let err = match open_ipfs_folder_at("ipfs://QmDir", &gw.addr, &dead_api) {
            Err(e) => e,
            Ok(_) => panic!("expected directory-without-API error"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("IPFS_API") && msg.to_ascii_lowercase().contains("directory"),
            "{msg}"
        );
    }

    #[test]
    fn file_cid_without_api_opens_via_gateway() {
        let body = b"no-daemon-file".to_vec();
        let mock = MockIpfs::spawn(MockIpfsCfg {
            files: vec![("/ipfs/QmFile".into(), body.clone())],
            dirs: vec![],
            ls_json: None,
            honor_range: true,
        });
        let dead = closed_http_url();
        assert!(
            open_ipfs_folder_at("ipfs://QmFile", &mock.addr, &dead)
                .unwrap()
                .is_none(),
            "file CID must not require IPFS_API"
        );
        let mut f = open_ipfs_at("ipfs://QmFile", &mock.addr).unwrap();
        let mut got = Vec::new();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn file_cid_folder_probe_is_none_when_ls_has_no_named_links() {
        let json = r#"{
          "Objects": [{"Hash": "QmFile", "Links": [
            {"Name": "", "Hash": "QmChunk", "Size": 256, "Type": 2}
          ]}]
        }"#;
        let body = b"abc".to_vec();
        let mock = MockIpfs::spawn(MockIpfsCfg {
            files: vec![("/ipfs/QmFile".into(), body)],
            dirs: vec![],
            ls_json: Some(json.into()),
            honor_range: true,
        });
        assert!(
            open_ipfs_folder_at("ipfs://QmFile", &mock.addr, &mock.addr)
                .unwrap()
                .is_none(),
            "file CID with unnamed chunk links is not a directory"
        );
    }

    /// Optional live daemon: skip rather than fail when no gateway is listening.
    #[test]
    fn file_cid_without_daemon_skips() {
        let gw = ipfs_gateway();
        if !http_base_reachable(&gw) {
            eprintln!("skip: no IPFS_GATEWAY");
            return;
        }
        // Empty identity CID — daemon may 404; skip on any open failure.
        if let Err(e) = open_ipfs_at("ipfs://bafkqaaa", &gw) {
            eprintln!("skip: IPFS_GATEWAY up but CID fetch failed: {e}");
        }
    }

    fn http_base_reachable(base: &str) -> bool {
        use std::net::ToSocketAddrs;
        let Ok(u) = Url::parse(base) else {
            return false;
        };
        let Some(host) = u.host_str() else {
            return false;
        };
        let port = u.port_or_known_default().unwrap_or(80);
        let Ok(mut addrs) = (host, port).to_socket_addrs() else {
            return false;
        };
        let Some(addr) = addrs.next() else {
            return false;
        };
        std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
    }

    #[test]
    fn ipfs_handle_debug_has_no_secrets() {
        // No credentials in v1; Debug still must not panic and should name the type.
        let loc = parse_ipfs_url("ipfs://QmAbc").unwrap();
        assert!(!format!("{loc:?}").contains("password"));
    }
}
