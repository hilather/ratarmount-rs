//! FTP / FTPS ingest (`ftp://`, `ftps://`) with REST/SIZE Range or full RETR,
//! and LIST/MLSD directory mounts via [`open_ftp_folder`].
//!
//! - **URL:** `ftp://[user[:pass]@]host[:port]/path` (default port 21).
//!   `ftps://` is explicit AUTH TLS (same default port). Implicit FTPS (990) is residual.
//! - **Auth:** URL userinfo; else [`FTP_USER_ENV`] / [`FTP_PASSWORD_ENV`]; else anonymous
//!   `anonymous` / `ratarmount@`.
//! - **Range:** `SIZE` for length + `REST offset` + `RETR` → live [`FtpRangeFile`].
//!   If either is missing, full RETR is buffered (same shape as non-Range HTTP).
//! - **Folder:** [`open_ftp_folder`] prefers MLSD, falls back to Unix LIST
//!   (`RemoteListing`). [`parse_ftp_url`] still requires a file path; use
//!   [`parse_ftp_url_allow_prefix`] when the path may be `/`.
//! - **FTPS:** `suppaftp` rustls (explicit AUTH TLS). Roots from [`FTP_CA_FILE_ENV`] or a
//!   system CA bundle. Do not add `native-tls`.
//!
//! Factory `resolve_to_local` / `UnsupportedScheme` wiring is a later PR.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use log::debug;
use ratarmount_core::{ArchiveRead, MountSource};
use tempfile::NamedTempFile;
use url::Url;

use crate::folder::{RemoteDirent, RemoteFolderMountSource, RemoteListing};
use crate::{RemoteError, Result};

/// Hard cap on listed FTP entries (not silent truncate).
pub const FTP_LIST_KEY_CAP: usize = 100_000;

/// Env: FTP username when the URL has no userinfo.
pub const FTP_USER_ENV: &str = "RATARMOUNT_FTP_USER";
/// Env: FTP password (pairs with [`FTP_USER_ENV`], or fills a URL username with no password).
pub const FTP_PASSWORD_ENV: &str = "RATARMOUNT_FTP_PASSWORD";
/// Env: PEM CA bundle for `ftps://` (explicit AUTH TLS). Otherwise a system CA path is tried.
pub const FTP_CA_FILE_ENV: &str = "RATARMOUNT_FTP_CA_FILE";

const DEFAULT_FTP_PORT: u16 = 21;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ANONYMOUS_USER: &str = "anonymous";
const ANONYMOUS_PASS: &str = "ratarmount@";

const SYSTEM_CA_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// `ftp://` (cleartext) or `ftps://` (explicit AUTH TLS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpScheme {
    Ftp,
    Ftps,
}

impl FtpScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ftp => "ftp",
            Self::Ftps => "ftps",
        }
    }
}

/// Parsed FTP/FTPS location. Password is never shown in [`Debug`].
#[derive(Clone)]
pub struct FtpLocation {
    pub scheme: FtpScheme,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    /// Remote path with a single leading `/` (percent-decoded).
    pub path: String,
}

impl std::fmt::Debug for FtpLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpLocation")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &redact_secret(&self.password))
            .field("path", &self.path)
            .finish()
    }
}

impl FtpLocation {
    /// Wire-style URL with password replaced by `***` (same policy as HTTP Basic).
    pub fn redacted_url(&self) -> String {
        format!(
            "{}://{}:***@{}:{}{}",
            self.scheme.as_str(),
            self.user,
            self.host,
            self.port,
            self.path
        )
    }
}

/// Redact URL userinfo passwords: `ftp://user:***@host/…`.
pub fn redact_ftp_url(s: &str) -> String {
    let Some((scheme, rest)) = s.split_once("://") else {
        return s.to_string();
    };
    let Some(at) = rest.find('@') else {
        return s.to_string();
    };
    let userinfo = &rest[..at];
    let hostpart = &rest[at + 1..];
    if let Some((user, _)) = userinfo.split_once(':') {
        format!("{scheme}://{user}:***@{hostpart}")
    } else {
        s.to_string()
    }
}

fn redact_secret(s: &str) -> &'static str {
    if s.is_empty() {
        ""
    } else {
        "***"
    }
}

/// Parse `ftp://` / `ftps://[user[:pass]@]host[:port]/path`.
///
/// Empty path / `/` is an error (file ingest). Use [`parse_ftp_url_allow_prefix`]
/// for directory mounts.
pub fn parse_ftp_url(url_str: &str) -> Result<FtpLocation> {
    let loc = parse_ftp_url_allow_prefix(url_str)?;
    if loc.path.is_empty() || loc.path == "/" {
        return Err(RemoteError::Url(
            "ftp URL missing file path (expected ftp://host/path)".into(),
        ));
    }
    Ok(loc)
}

/// Like [`parse_ftp_url`], but an empty path / `/` is the FTP root (folder mount).
pub fn parse_ftp_url_allow_prefix(url_str: &str) -> Result<FtpLocation> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    let scheme = match url.scheme() {
        "ftp" => FtpScheme::Ftp,
        "ftps" => FtpScheme::Ftps,
        other => return Err(RemoteError::UnsupportedScheme(other.to_string())),
    };
    let host = url
        .host_str()
        .ok_or_else(|| RemoteError::Url("ftp URL missing host".into()))?
        .to_string();
    let port = url.port().unwrap_or(DEFAULT_FTP_PORT);

    let url_user = if url.username().is_empty() {
        None
    } else {
        Some(url.username().to_string())
    };
    let url_pass = url.password().map(std::string::ToString::to_string);
    let (user, password) = resolve_ftp_auth(url_user, url_pass);

    let path = ftp_path_from_url(&url);
    Ok(FtpLocation {
        scheme,
        host,
        port,
        user,
        password,
        path,
    })
}

fn ftp_path_from_url(url: &Url) -> String {
    let Some(segments) = url.path_segments() else {
        return String::new();
    };
    let joined = segments
        .filter(|s| !s.is_empty())
        .map(percent_decode_path)
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        "/".into()
    } else {
        format!("/{joined}")
    }
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

fn resolve_ftp_auth(url_user: Option<String>, url_pass: Option<String>) -> (String, String) {
    if let Some(user) = url_user {
        let password = url_pass
            .or_else(|| non_empty_env(FTP_PASSWORD_ENV))
            .unwrap_or_else(|| {
                if user == ANONYMOUS_USER {
                    ANONYMOUS_PASS.to_string()
                } else {
                    String::new()
                }
            });
        return (user, password);
    }
    if let Some(user) = non_empty_env(FTP_USER_ENV) {
        let password = non_empty_env(FTP_PASSWORD_ENV).unwrap_or_default();
        return (user, password);
    }
    (ANONYMOUS_USER.to_string(), ANONYMOUS_PASS.to_string())
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|v| {
        let t = v.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

fn ftp_io(msg: impl Into<String>) -> RemoteError {
    RemoteError::Io(io::Error::other(msg.into()))
}

fn ftp_denied(msg: impl Into<String>) -> RemoteError {
    RemoteError::Io(io::Error::new(io::ErrorKind::PermissionDenied, msg.into()))
}

fn map_ftp(err: suppaftp::FtpError) -> RemoteError {
    match err {
        suppaftp::FtpError::ConnectionError(e) => RemoteError::Io(e),
        other => ftp_io(format!("ftp: {other}")),
    }
}

fn map_ftp_login(err: suppaftp::FtpError) -> RemoteError {
    match err {
        suppaftp::FtpError::UnexpectedResponse(resp)
            if matches!(resp.status.code(), 430 | 530 | 331) =>
        {
            ftp_denied(format!(
                "ftp: login failed ({}); check URL userinfo or {}/{}",
                resp.status.code(),
                FTP_USER_ENV,
                FTP_PASSWORD_ENV
            ))
        }
        other => map_ftp(other),
    }
}

fn u64_to_usize(n: u64) -> Result<usize> {
    usize::try_from(n).map_err(|_| ftp_io(format!("ftp: offset {n} does not fit usize")))
}

/// Open a seekable FTP reader: live REST/RETR when SIZE+REST work, else a buffered body.
pub fn open_ftp_range(url: &str) -> Result<FtpRangeFile> {
    FtpRangeFile::open(url)
}

/// Full RETR into a tempfile (non-Range fallback / factory materialize).
pub fn fetch_ftp_to_temp(url: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_ftp_url(url)?;
    fetch_ftp_location_to_temp(&loc)
}

fn fetch_ftp_location_to_temp(loc: &FtpLocation) -> Result<(NamedTempFile, u64)> {
    let bytes = with_session(loc, |c| c.retr_all(&loc.path))?;
    let mut tmp = NamedTempFile::new()?;
    tmp.write_all(&bytes)?;
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok((tmp, bytes.len() as u64))
}

/// Seekable FTP reader using REST+RETR when the server supports SIZE and REST.
pub struct FtpRangeFile {
    loc: FtpLocation,
    size: u64,
    pos: u64,
    /// Full body when REST/SIZE are unusable.
    buffered: Option<Vec<u8>>,
}

impl std::fmt::Debug for FtpRangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpRangeFile")
            .field("url", &self.loc.redacted_url())
            .field("user", &self.loc.user)
            .field("password", &redact_secret(&self.loc.password))
            .field("size", &self.size)
            .field("pos", &self.pos)
            .field("uses_ranges", &self.uses_ranges())
            .finish()
    }
}

impl FtpRangeFile {
    pub fn open(url: &str) -> Result<Self> {
        let loc = parse_ftp_url(url)?;
        Self::open_location(&loc)
    }

    pub fn open_location(loc: &FtpLocation) -> Result<Self> {
        debug!("FTP open {}", loc.redacted_url());
        match probe_ftp(loc) {
            Ok(FtpProbe::RangesOk(size)) => {
                debug!("FTP live REST for {} ({size} bytes)", loc.redacted_url());
                Ok(Self::range_backed(loc.clone(), size))
            }
            Ok(FtpProbe::FullBody(bytes)) => {
                let size = bytes.len() as u64;
                debug!(
                    "FTP materialize {} ({size} bytes, REST/SIZE unusable)",
                    loc.redacted_url()
                );
                Ok(Self {
                    loc: loc.clone(),
                    size,
                    pos: 0,
                    buffered: Some(bytes),
                })
            }
            Err(e) => Err(e),
        }
    }

    pub fn range_backed(loc: FtpLocation, size: u64) -> Self {
        Self {
            loc,
            size,
            pos: 0,
            buffered: None,
        }
    }

    pub fn location(&self) -> &FtpLocation {
        &self.loc
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// True when reads issue live REST+RETR (not a fully buffered body).
    pub fn uses_ranges(&self) -> bool {
        self.buffered.is_none()
    }
}

enum FtpProbe {
    RangesOk(u64),
    FullBody(Vec<u8>),
}

fn probe_ftp(loc: &FtpLocation) -> Result<FtpProbe> {
    with_session(loc, |c| {
        let size = match c.size_of(&loc.path) {
            Ok(n) => n,
            Err(e) => {
                debug!("FTP SIZE unsupported for {}: {e}", loc.redacted_url());
                return c.retr_all(&loc.path).map(FtpProbe::FullBody);
            }
        };
        match c.rest(0) {
            Ok(()) => Ok(FtpProbe::RangesOk(size)),
            Err(e) => {
                debug!(
                    "FTP REST unsupported for {}: {e}; full RETR",
                    loc.redacted_url()
                );
                c.retr_all(&loc.path).map(FtpProbe::FullBody)
            }
        }
    })
}

enum FtpClient {
    Plain(suppaftp::FtpStream),
    Tls(suppaftp::RustlsFtpStream),
}

fn with_session<R>(loc: &FtpLocation, f: impl FnOnce(&mut FtpClient) -> Result<R>) -> Result<R> {
    let mut client = connect_ftp(loc)?;
    let out = f(&mut client);
    let _ = client.quit();
    out
}

fn connect_ftp(loc: &FtpLocation) -> Result<FtpClient> {
    let addr = resolve_ftp_addr(&loc.host, loc.port)?;
    match loc.scheme {
        FtpScheme::Ftp => {
            let mut s =
                suppaftp::FtpStream::connect_timeout(addr, CONNECT_TIMEOUT).map_err(map_ftp)?;
            s.set_passive_nat_workaround(true);
            s.login(&loc.user, &loc.password).map_err(map_ftp_login)?;
            s.transfer_type(suppaftp::types::FileType::Binary)
                .map_err(map_ftp)?;
            Ok(FtpClient::Plain(s))
        }
        FtpScheme::Ftps => {
            let cfg = rustls_client_config()?;
            let connector = suppaftp::RustlsConnector::from(cfg);
            let s = suppaftp::RustlsFtpStream::connect_timeout(addr, CONNECT_TIMEOUT)
                .map_err(map_ftp)?;
            let mut s = s.into_secure(connector, &loc.host).map_err(map_ftp)?;
            s.set_passive_nat_workaround(true);
            s.login(&loc.user, &loc.password).map_err(map_ftp_login)?;
            s.transfer_type(suppaftp::types::FileType::Binary)
                .map_err(map_ftp)?;
            Ok(FtpClient::Tls(s))
        }
    }
}

fn resolve_ftp_addr(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| ftp_io(format!("ftp: resolve {host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| ftp_io(format!("ftp: no addresses for {host}:{port}")))
}

fn rustls_client_config() -> Result<Arc<suppaftp::rustls::ClientConfig>> {
    let _ = suppaftp::rustls::crypto::ring::default_provider().install_default();
    let store = rustls_root_store()?;
    let cfg = suppaftp::rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn rustls_root_store() -> Result<suppaftp::rustls::RootCertStore> {
    let mut store = suppaftp::rustls::RootCertStore::empty();
    if let Some(path) = non_empty_env(FTP_CA_FILE_ENV) {
        add_pem_file(&mut store, Path::new(&path))?;
        if store.is_empty() {
            return Err(ftp_io(format!(
                "ftp: FTPS CA file {path} contained no usable certificates"
            )));
        }
        return Ok(store);
    }
    for candidate in SYSTEM_CA_BUNDLES {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            match add_pem_file(&mut store, &p) {
                Ok(()) if !store.is_empty() => return Ok(store),
                Ok(()) | Err(_) => {
                    store = suppaftp::rustls::RootCertStore::empty();
                }
            }
        }
    }
    Err(ftp_io(format!(
        "ftp: FTPS needs CA certificates (set {FTP_CA_FILE_ENV} or install a system CA bundle)"
    )))
}

fn add_pem_file(store: &mut suppaftp::rustls::RootCertStore, path: &Path) -> Result<()> {
    use suppaftp::rustls::pki_types::pem::PemObject;
    use suppaftp::rustls::pki_types::CertificateDer;

    let iter = CertificateDer::pem_file_iter(path)
        .map_err(|e| ftp_io(format!("ftp: read CA {}: {e}", path.display())))?;
    let certs: Vec<CertificateDer<'static>> = iter
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ftp_io(format!("ftp: parse CA {}: {e}", path.display())))?;
    let (ok, _bad) = store.add_parsable_certificates(certs);
    if ok == 0 {
        return Err(ftp_io(format!(
            "ftp: no valid certificates in {}",
            path.display()
        )));
    }
    Ok(())
}

impl FtpClient {
    fn size_of(&mut self, path: &str) -> Result<u64> {
        let n = match self {
            Self::Plain(s) => s.size(path).map_err(map_ftp)?,
            Self::Tls(s) => s.size(path).map_err(map_ftp)?,
        };
        Ok(n as u64)
    }

    fn rest(&mut self, offset: u64) -> Result<()> {
        let off = u64_to_usize(offset)?;
        match self {
            Self::Plain(s) => s.resume_transfer(off).map_err(map_ftp),
            Self::Tls(s) => s.resume_transfer(off).map_err(map_ftp),
        }
    }

    fn retr_all(&mut self, path: &str) -> Result<Vec<u8>> {
        self.retr_from(path, 0, None)
    }

    fn retr_from(&mut self, path: &str, offset: u64, max: Option<u64>) -> Result<Vec<u8>> {
        if offset > 0 {
            self.rest(offset)?;
        }
        match self {
            Self::Plain(s) => retr_fill_plain(s, path, max),
            Self::Tls(s) => retr_fill_tls(s, path, max),
        }
    }

    fn quit(&mut self) -> Result<()> {
        match self {
            Self::Plain(s) => s.quit().map_err(map_ftp),
            Self::Tls(s) => s.quit().map_err(map_ftp),
        }
    }

    fn cwd(&mut self, path: &str) -> Result<()> {
        match self {
            Self::Plain(s) => s.cwd(path).map_err(map_ftp),
            Self::Tls(s) => s.cwd(path).map_err(map_ftp),
        }
    }

    fn mlsd(&mut self, path: &str) -> Result<Vec<String>> {
        let arg = ftp_list_arg(path);
        match self {
            Self::Plain(s) => s.mlsd(arg).map_err(map_ftp),
            Self::Tls(s) => s.mlsd(arg).map_err(map_ftp),
        }
    }

    fn list(&mut self, path: &str) -> Result<Vec<String>> {
        let arg = ftp_list_arg(path);
        match self {
            Self::Plain(s) => s.list(arg).map_err(map_ftp),
            Self::Tls(s) => s.list(arg).map_err(map_ftp),
        }
    }
}

fn ftp_list_arg(path: &str) -> Option<&str> {
    let t = path.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

fn ftp_url_looks_like_dir(url_str: &str, loc: &FtpLocation) -> bool {
    if loc.path.is_empty() || loc.path == "/" || loc.path.ends_with('/') {
        return true;
    }
    url_str
        .split_once("://")
        .map(|(_, rest)| rest.ends_with('/'))
        .unwrap_or(false)
}

fn ftp_location_is_dir(url_str: &str, loc: &FtpLocation) -> Result<bool> {
    if ftp_url_looks_like_dir(url_str, loc) {
        return Ok(true);
    }
    with_session(loc, |c| match c.size_of(&loc.path) {
        Ok(_) => Ok(false),
        Err(_) => match c.cwd(&loc.path) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        },
    })
}

fn ftp_child_path(parent: &str, name: &str) -> String {
    let p = parent.trim_end_matches('/');
    if p.is_empty() || p == "/" {
        format!("/{name}")
    } else if p.starts_with('/') {
        format!("{p}/{name}")
    } else {
        format!("/{p}/{name}")
    }
}

/// Parse one MLSD line (`type=dir|file;size=…; name`). Skip `.` / `..`.
fn parse_mlsd_line(line: &str) -> Option<(String, bool, u64)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (facts, name) = line.split_once(' ')?;
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    let name = name
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(name)
        .to_string();
    let mut typ: Option<String> = None;
    let mut size = 0u64;
    for fact in facts.split(';') {
        let fact = fact.trim();
        if fact.is_empty() {
            continue;
        }
        let Some((k, v)) = fact.split_once('=') else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "type" => typ = Some(v.trim().to_ascii_lowercase()),
            "size" => size = v.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    let is_dir = match typ.as_deref() {
        Some("dir") => true,
        Some("file") => false,
        _ => return None,
    };
    Some((name, is_dir, if is_dir { 0 } else { size }))
}

/// Parse one Unix LIST line. Skip blank, `total N`, and symlinks (`l`).
fn parse_unix_list_line(line: &str) -> Option<(String, bool, u64)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let first = *tokens.first()?;
    if first.eq_ignore_ascii_case("total") {
        return None;
    }
    let kind = first.chars().next()?;
    let is_dir = match kind {
        'd' => true,
        '-' => false,
        'l' => return None,
        _ => return None,
    };
    let name = *tokens.last()?;
    if name == "." || name == ".." || name == first {
        return None;
    }
    let size = if is_dir {
        0
    } else if tokens.len() >= 5 {
        tokens[4].parse().unwrap_or(0)
    } else {
        0
    };
    Some((name.to_string(), is_dir, size))
}

fn collect_ftp_dirents(lines: &[String], parent: &str, mlsd: bool) -> Result<Vec<RemoteDirent>> {
    let mut out = Vec::new();
    for line in lines {
        let parsed = if mlsd {
            parse_mlsd_line(line)
        } else {
            parse_unix_list_line(line)
        };
        let Some((name, is_dir, size)) = parsed else {
            continue;
        };
        if out.len() >= FTP_LIST_KEY_CAP {
            return Err(ftp_io(format!(
                "ftp listing too large (>{FTP_LIST_KEY_CAP} entries) for {parent}; \
                 listing is not silently truncated"
            )));
        }
        out.push(RemoteDirent {
            name: name.clone(),
            remote_path: ftp_child_path(parent, &name),
            is_dir,
            size,
            mtime: 0.0,
        });
    }
    Ok(out)
}

struct FtpListing {
    loc: FtpLocation,
}

impl RemoteListing for FtpListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        with_session(&self.loc, |c| {
            let (lines, mlsd) = match c.mlsd(remote_path) {
                Ok(lines) => (lines, true),
                Err(e) => {
                    debug!("FTP MLSD failed for {remote_path}: {e}; falling back to LIST");
                    (c.list(remote_path)?, false)
                }
            };
            collect_ftp_dirents(&lines, remote_path, mlsd)
        })
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        if remote_path.is_empty() || remote_path == "/" || remote_path.ends_with('/') {
            return Ok(true);
        }
        let mut loc = self.loc.clone();
        loc.path = if remote_path.starts_with('/') {
            remote_path.to_string()
        } else {
            format!("/{remote_path}")
        };
        ftp_location_is_dir("", &loc)
    }

    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>> {
        let mut loc = self.loc.clone();
        loc.path = if remote_path.starts_with('/') {
            remote_path.to_string()
        } else {
            format!("/{remote_path}")
        };
        if size > 0 {
            Ok(Box::new(FtpRangeFile::range_backed(loc, size)))
        } else {
            Ok(Box::new(FtpRangeFile::open_location(&loc)?))
        }
    }
}

/// Open `ftp://` / `ftps://` as a remote folder when the path is a directory.
///
/// `Ok(None)` if the path is a file (factory should fall through to [`open_ftp_range`]).
pub fn open_ftp_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_ftp_url_allow_prefix(s)?;
    if !ftp_location_is_dir(s, &loc)? {
        return Ok(None);
    }
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        loc.path.clone(),
        FtpListing { loc },
    ))))
}

fn retr_fill_plain(
    stream: &mut suppaftp::FtpStream,
    path: &str,
    max: Option<u64>,
) -> Result<Vec<u8>> {
    retr_fill_stream(
        stream.retr_as_stream(path).map_err(map_ftp)?,
        |data| stream.finalize_retr_stream(data),
        max,
    )
}

fn retr_fill_tls(
    stream: &mut suppaftp::RustlsFtpStream,
    path: &str,
    max: Option<u64>,
) -> Result<Vec<u8>> {
    retr_fill_stream(
        stream.retr_as_stream(path).map_err(map_ftp)?,
        |data| stream.finalize_retr_stream(data),
        max,
    )
}

fn retr_fill_stream<S: Read>(
    mut data: S,
    finalize: impl FnOnce(S) -> suppaftp::FtpResult<()>,
    max: Option<u64>,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let read_res = if let Some(max) = max {
        let need = u64_to_usize(max)?;
        buf.resize(need, 0);
        fill_read(&mut data, &mut buf).map(|n| {
            buf.truncate(n);
        })
    } else {
        data.read_to_end(&mut buf)
            .map(|_| ())
            .map_err(RemoteError::from)
    };
    // Finalize drops the data connection then reads the control reply.
    let _ = finalize(data);
    read_res?;
    Ok(buf)
}

/// Loop `Read::read` until `buf` is full or EOF (short FTP/TCP reads are not EOF).
fn fill_read(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(filled)
}

impl Read for FtpRangeFile {
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
        let remaining = self.size.saturating_sub(self.pos);
        let want = (buf.len() as u64).min(remaining);
        if want == 0 {
            return Ok(0);
        }
        let chunk = with_session(&self.loc, |c| {
            c.retr_from(&self.loc.path, self.pos, Some(want))
        })
        .map_err(|e| io::Error::other(e.to_string()))?;
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for FtpRangeFile {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write as IoWrite};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    const FTP_ENV_KEYS: &[&str] = &[FTP_USER_ENV, FTP_PASSWORD_ENV, FTP_CA_FILE_ENV];

    struct MockFtp {
        addr: String,
        log: Arc<Mutex<Vec<String>>>,
        retrs: Arc<AtomicUsize>,
        rests: Arc<AtomicUsize>,
        sizes: Arc<AtomicUsize>,
        _join: Option<thread::JoinHandle<()>>,
    }

    #[derive(Clone)]
    struct MockConfig {
        body: Vec<u8>,
        honor_size: bool,
        honor_rest: bool,
        /// If set, USER/PASS must match.
        require_user: Option<(String, String)>,
        honor_mlsd: bool,
        honor_list: bool,
        honor_cwd: bool,
        mlsd_body: String,
        list_body: String,
    }

    impl Default for MockConfig {
        fn default() -> Self {
            Self {
                body: Vec::new(),
                honor_size: true,
                honor_rest: true,
                require_user: None,
                honor_mlsd: false,
                honor_list: false,
                honor_cwd: true,
                mlsd_body: String::new(),
                list_body: String::new(),
            }
        }
    }

    impl MockFtp {
        fn spawn(cfg: MockConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let bound = listener.local_addr().unwrap();
            let addr = format!("{bound}");
            let log = Arc::new(Mutex::new(Vec::new()));
            let retrs = Arc::new(AtomicUsize::new(0));
            let rests = Arc::new(AtomicUsize::new(0));
            let sizes = Arc::new(AtomicUsize::new(0));
            let log_c = Arc::clone(&log);
            let retr_c = Arc::clone(&retrs);
            let rest_c = Arc::clone(&rests);
            let size_c = Arc::clone(&sizes);
            let join = thread::spawn(move || {
                listener.set_nonblocking(false).ok();
                for stream in listener.incoming().take(64) {
                    let Ok(stream) = stream else { continue };
                    serve_control(stream, &cfg, &log_c, &retr_c, &rest_c, &size_c);
                }
            });
            Self {
                addr,
                log,
                retrs,
                rests,
                sizes,
                _join: Some(join),
            }
        }

        fn url(&self, path: &str) -> String {
            let p = path.trim_start_matches('/');
            format!("ftp://{}/{}", self.addr, p)
        }

        fn url_with_auth(&self, user: &str, pass: &str, path: &str) -> String {
            let p = path.trim_start_matches('/');
            format!("ftp://{user}:{pass}@{}/{}", self.addr, p)
        }
    }

    fn write_line(stream: &mut TcpStream, line: &str) {
        let _ = write!(stream, "{line}\r\n");
        let _ = stream.flush();
    }

    fn serve_control(
        mut stream: TcpStream,
        cfg: &MockConfig,
        log: &Arc<Mutex<Vec<String>>>,
        retrs: &Arc<AtomicUsize>,
        rests: &Arc<AtomicUsize>,
        sizes: &Arc<AtomicUsize>,
    ) {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        write_line(&mut stream, "220 ratarmount mock FTP");
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut rest_offset: u64 = 0;
        let mut data_listener: Option<TcpListener> = None;
        let mut logged_in = false;
        let mut pending_user: Option<String> = None;

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            if line.is_empty() {
                break;
            }
            let raw = line.trim_end_matches(['\r', '\n']);
            if raw.is_empty() {
                continue;
            }
            let (cmd, arg) = split_ftp_cmd(raw);
            {
                let mut lg = log.lock().unwrap();
                if cmd == "PASS" {
                    lg.push("PASS ***".into());
                } else {
                    lg.push(if arg.is_empty() {
                        cmd.clone()
                    } else {
                        format!("{cmd} {arg}")
                    });
                }
            }

            match cmd.as_str() {
                "USER" => {
                    pending_user = Some(arg);
                    write_line(&mut stream, "331 Password required");
                }
                "PASS" => {
                    let user = pending_user.clone().unwrap_or_default();
                    let ok = match &cfg.require_user {
                        Some((u, p)) => user == *u && arg == *p,
                        None => true,
                    };
                    if ok {
                        logged_in = true;
                        write_line(&mut stream, "230 Logged in");
                    } else {
                        write_line(&mut stream, "530 Login incorrect");
                    }
                }
                "TYPE" => {
                    write_line(&mut stream, "200 Type set to I");
                }
                "SIZE" => {
                    sizes.fetch_add(1, Ordering::SeqCst);
                    if !logged_in {
                        write_line(&mut stream, "530 Not logged in");
                    } else if cfg.honor_size {
                        write_line(&mut stream, &format!("213 {}", cfg.body.len()));
                    } else {
                        write_line(&mut stream, "502 SIZE not implemented");
                    }
                }
                "REST" => {
                    rests.fetch_add(1, Ordering::SeqCst);
                    if !cfg.honor_rest {
                        write_line(&mut stream, "502 REST not implemented");
                    } else {
                        rest_offset = arg.parse().unwrap_or(0);
                        write_line(&mut stream, &format!("350 Restarting at {rest_offset}"));
                    }
                }
                "PASV" => match TcpListener::bind("127.0.0.1:0") {
                    Ok(l) => {
                        let a = l.local_addr().unwrap();
                        let ip = match a.ip() {
                            std::net::IpAddr::V4(v) => v.octets(),
                            _ => [127, 0, 0, 1],
                        };
                        let port = a.port();
                        let p1 = port / 256;
                        let p2 = port % 256;
                        write_line(
                            &mut stream,
                            &format!(
                                "227 Entering Passive Mode ({},{},{},{},{p1},{p2})",
                                ip[0], ip[1], ip[2], ip[3]
                            ),
                        );
                        data_listener = Some(l);
                    }
                    Err(_) => write_line(&mut stream, "425 Can't open data connection"),
                },
                "RETR" => {
                    retrs.fetch_add(1, Ordering::SeqCst);
                    if !logged_in {
                        write_line(&mut stream, "530 Not logged in");
                        continue;
                    }
                    let Some(listener) = data_listener.take() else {
                        write_line(&mut stream, "425 PASV required");
                        continue;
                    };
                    write_line(&mut stream, "150 Opening data connection");
                    match accept_with_timeout(&listener, Duration::from_secs(3)) {
                        Ok(mut data) => {
                            let start = rest_offset.min(cfg.body.len() as u64) as usize;
                            let _ = data.write_all(&cfg.body[start..]);
                            let _ = data.flush();
                            let _ = data.shutdown(Shutdown::Write);
                            write_line(&mut stream, "226 Transfer complete");
                        }
                        Err(_) => write_line(&mut stream, "425 Can't open data connection"),
                    }
                    rest_offset = 0;
                }
                "QUIT" => {
                    write_line(&mut stream, "221 Bye");
                    break;
                }
                "AUTH" => {
                    write_line(&mut stream, "502 AUTH not implemented");
                }
                "CWD" => {
                    if !logged_in {
                        write_line(&mut stream, "530 Not logged in");
                    } else if cfg.honor_cwd {
                        write_line(&mut stream, "250 Directory changed");
                    } else {
                        write_line(&mut stream, "550 Failed to change directory");
                    }
                }
                "MLSD" => {
                    if !logged_in {
                        write_line(&mut stream, "530 Not logged in");
                    } else if cfg.honor_mlsd {
                        send_data_text(&mut stream, &mut data_listener, &cfg.mlsd_body);
                    } else {
                        write_line(&mut stream, "502 MLSD not implemented");
                    }
                }
                "LIST" => {
                    if !logged_in {
                        write_line(&mut stream, "530 Not logged in");
                    } else if cfg.honor_list {
                        send_data_text(&mut stream, &mut data_listener, &cfg.list_body);
                    } else {
                        write_line(&mut stream, "502 LIST not implemented");
                    }
                }
                _ => write_line(&mut stream, "502 Command not implemented"),
            }
        }
    }

    fn send_data_text(stream: &mut TcpStream, data_listener: &mut Option<TcpListener>, text: &str) {
        let Some(listener) = data_listener.take() else {
            write_line(stream, "425 PASV required");
            return;
        };
        write_line(stream, "150 Opening data connection");
        match accept_with_timeout(&listener, Duration::from_secs(3)) {
            Ok(mut data) => {
                let payload = if text.ends_with('\n') {
                    text.to_string()
                } else {
                    format!("{text}\r\n")
                };
                let _ = data.write_all(payload.as_bytes());
                let _ = data.flush();
                let _ = data.shutdown(Shutdown::Write);
                write_line(stream, "226 Transfer complete");
            }
            Err(_) => write_line(stream, "425 Can't open data connection"),
        }
    }

    fn split_ftp_cmd(line: &str) -> (String, String) {
        match line.split_once(' ') {
            Some((c, a)) => (c.to_ascii_uppercase(), a.to_string()),
            None => (line.to_ascii_uppercase(), String::new()),
        }
    }

    fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> io::Result<TcpStream> {
        listener.set_nonblocking(true)?;
        let start = Instant::now();
        loop {
            match listener.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false)?;
                    return Ok(s);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if start.elapsed() > timeout {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "data accept timeout",
                        ));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[test]
    fn parse_ftp_url_basic() {
        let loc = parse_ftp_url("ftp://files.example.com/archives/a.tar").unwrap();
        assert_eq!(loc.scheme, FtpScheme::Ftp);
        assert_eq!(loc.host, "files.example.com");
        assert_eq!(loc.port, 21);
        assert_eq!(loc.path, "/archives/a.tar");
        assert_eq!(loc.user, ANONYMOUS_USER);
        assert_eq!(loc.password, ANONYMOUS_PASS);
    }

    #[test]
    fn parse_ftps_url_port_and_userinfo() {
        let loc = parse_ftp_url("ftps://alice:s3cret@host.example:990/dir/f.bin").unwrap();
        assert_eq!(loc.scheme, FtpScheme::Ftps);
        assert_eq!(loc.port, 990);
        assert_eq!(loc.user, "alice");
        assert_eq!(loc.password, "s3cret");
        assert_eq!(loc.path, "/dir/f.bin");
    }

    #[test]
    fn parse_percent_decoded_path() {
        let loc = parse_ftp_url("ftp://host/my%20file.tar").unwrap();
        assert_eq!(loc.path, "/my file.tar");
    }

    #[test]
    fn parse_missing_host_and_path() {
        assert!(parse_ftp_url("ftp:///nohost").is_err());
        let err = parse_ftp_url("ftp://host.example/")
            .unwrap_err()
            .to_string();
        assert!(err.contains("path"), "{err}");
        let err = parse_ftp_url("http://host/x").unwrap_err().to_string();
        assert!(err.contains("unsupported"), "{err}");
    }

    #[test]
    fn parse_env_credentials_when_url_has_no_userinfo() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        _g.set(FTP_USER_ENV, "envuser");
        _g.set(FTP_PASSWORD_ENV, "envpass");
        let loc = parse_ftp_url("ftp://host.example/a.tar").unwrap();
        assert_eq!(loc.user, "envuser");
        assert_eq!(loc.password, "envpass");
    }

    #[test]
    fn parse_url_user_env_password() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        _g.set(FTP_PASSWORD_ENV, "from-env");
        let loc = parse_ftp_url("ftp://bob@host.example/a.tar").unwrap();
        assert_eq!(loc.user, "bob");
        assert_eq!(loc.password, "from-env");
    }

    #[test]
    fn redact_ftp_url_hides_password() {
        assert_eq!(
            redact_ftp_url("ftp://alice:s3cret@host.example/a.tar"),
            "ftp://alice:***@host.example/a.tar"
        );
        assert_eq!(
            redact_ftp_url("ftps://alice:s3cret@host:21/x"),
            "ftps://alice:***@host:21/x"
        );
        // No password in userinfo: unchanged.
        assert_eq!(
            redact_ftp_url("ftp://alice@host/a.tar"),
            "ftp://alice@host/a.tar"
        );
    }

    #[test]
    fn regression_ftp_userinfo_redacted_in_debug() {
        let loc = parse_ftp_url("ftp://alice:s3cret@host.example/a.tar").unwrap();
        let dbg = format!("{loc:?}");
        assert!(
            !dbg.contains("s3cret"),
            "FtpLocation Debug leaked password: {dbg}"
        );
        assert!(dbg.contains("alice"), "{dbg}");
        assert!(dbg.contains("***"), "{dbg}");
        let redacted = loc.redacted_url();
        assert!(!redacted.contains("s3cret"), "{redacted}");
        assert!(redacted.contains("alice:***@"), "{redacted}");
    }

    #[test]
    fn regression_ftp_size_rest_retr_range_reads() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let body: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let mock = MockFtp::spawn(MockConfig {
            body: body.clone(),
            honor_size: true,
            honor_rest: true,
            require_user: None,
            ..Default::default()
        });
        let url = mock.url("/blob.bin");
        let mut f = open_ftp_range(&url).unwrap();
        assert!(f.uses_ranges(), "expected live REST");
        assert_eq!(f.len(), body.len() as u64);
        f.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = [0u8; 64];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &body[100..164]);
        f.seek(SeekFrom::End(-16)).unwrap();
        let mut tail = [0u8; 16];
        f.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, &body[body.len() - 16..]);
        assert!(mock.sizes.load(Ordering::SeqCst) >= 1);
        assert!(mock.rests.load(Ordering::SeqCst) >= 1);
        assert!(mock.retrs.load(Ordering::SeqCst) >= 1);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("SIZE ")),
            "expected SIZE, log={log:?}"
        );
        assert!(
            log.iter().any(|l| l.starts_with("REST ")),
            "expected REST, log={log:?}"
        );
        assert!(
            log.iter().any(|l| l.starts_with("RETR ")),
            "expected RETR, log={log:?}"
        );
        assert!(
            !log.iter()
                .any(|l| l.contains("s3cret") || l.contains("ratarmount@")),
            "password leaked in mock log: {log:?}"
        );
    }

    #[test]
    fn regression_ftp_no_size_materializes() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let body = b"hello-ftp-materialize".to_vec();
        let mock = MockFtp::spawn(MockConfig {
            body: body.clone(),
            honor_size: false,
            honor_rest: true,
            require_user: None,
            ..Default::default()
        });
        let mut f = open_ftp_range(&mock.url("/m.bin")).unwrap();
        assert!(!f.uses_ranges());
        let mut got = Vec::new();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        f.seek(SeekFrom::Start(6)).unwrap();
        let mut mid = [0u8; 3];
        f.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, b"ftp");
    }

    #[test]
    fn regression_ftp_no_rest_materializes() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let body = b"rest-unsupported-body".to_vec();
        let mock = MockFtp::spawn(MockConfig {
            body: body.clone(),
            honor_size: true,
            honor_rest: false,
            require_user: None,
            ..Default::default()
        });
        let mut f = open_ftp_range(&mock.url("/n.bin")).unwrap();
        assert!(!f.uses_ranges());
        let mut got = Vec::new();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn fetch_ftp_to_temp_roundtrip() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let body = b"tempfile-body".to_vec();
        let mock = MockFtp::spawn(MockConfig {
            body: body.clone(),
            honor_size: false,
            honor_rest: false,
            require_user: None,
            ..Default::default()
        });
        let (mut tmp, size) = fetch_ftp_to_temp(&mock.url("/t.bin")).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn url_userinfo_is_sent() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let body = b"auth-ok".to_vec();
        let mock = MockFtp::spawn(MockConfig {
            body: body.clone(),
            honor_size: true,
            honor_rest: true,
            require_user: Some(("alice".into(), "s3cret".into())),
            ..Default::default()
        });
        let url = mock.url_with_auth("alice", "s3cret", "/a.bin");
        let mut f = open_ftp_range(&url).unwrap();
        let dbg = format!("{f:?}");
        assert!(
            !dbg.contains("s3cret"),
            "FtpRangeFile Debug leaked password: {dbg}"
        );
        let mut got = Vec::new();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let log = mock.log.lock().unwrap();
        assert!(log.iter().any(|l| l == "USER alice"), "{log:?}");
        assert!(log.iter().any(|l| l == "PASS ***"), "{log:?}");
        assert!(
            !log.iter().any(|l| l.contains("s3cret")),
            "password in log: {log:?}"
        );
    }

    #[test]
    fn wrong_password_is_permission_denied() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let mock = MockFtp::spawn(MockConfig {
            body: b"nope".to_vec(),
            honor_size: true,
            honor_rest: true,
            require_user: Some(("alice".into(), "s3cret".into())),
            ..Default::default()
        });
        let err = open_ftp_range(&mock.url_with_auth("alice", "wrong", "/x.bin")).unwrap_err();
        match err {
            RemoteError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
                let msg = e.to_string();
                assert!(
                    !msg.contains("wrong") && !msg.contains("s3cret"),
                    "password in error: {msg}"
                );
                assert!(msg.contains(FTP_USER_ENV) || msg.contains("login"), "{msg}");
            }
            other => panic!("expected Io PermissionDenied, got {other}"),
        }
    }

    #[test]
    fn ftp_scheme_is_already_remote_url() {
        // `ftp` is in `is_remote_url` on HEAD; factory ingest is PR-12.
        assert!(crate::is_remote_url("ftp://host.example/a.tar"));
    }

    #[test]
    fn ftps_skip_without_cert() {
        // Building a rustls ClientConfig needs a CA bundle. Skip when neither
        // RATARMOUNT_FTP_CA_FILE nor a system bundle is usable (no extra TLS crate).
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        if rustls_root_store().is_err() {
            eprintln!("skip: no CA bundle for FTPS ({FTP_CA_FILE_ENV} or system certs)");
            return;
        }
        // Plaintext mock does not speak AUTH TLS — error must be clear, not a panic.
        let mock = MockFtp::spawn(MockConfig {
            body: b"tls".to_vec(),
            honor_size: true,
            honor_rest: true,
            require_user: None,
            ..Default::default()
        });
        let url = format!("ftps://{}/file.bin", mock.addr);
        let err = open_ftp_range(&url).unwrap_err().to_string();
        assert!(
            err.to_ascii_lowercase().contains("ftp")
                || err.to_ascii_lowercase().contains("tls")
                || err.contains("502")
                || err.contains("AUTH"),
            "unexpected FTPS error: {err}"
        );
        assert!(!err.contains("native-tls"), "{err}");
    }

    #[test]
    fn parse_ftp_url_root_still_errors() {
        let err = parse_ftp_url("ftp://h/").unwrap_err().to_string();
        assert!(err.contains("path"), "{err}");
        let loc = parse_ftp_url_allow_prefix("ftp://h/").unwrap();
        assert_eq!(loc.host, "h");
        assert_eq!(loc.path, "/");
        let loc = parse_ftp_url_allow_prefix("ftp://files.example.com/archives/").unwrap();
        assert_eq!(loc.path, "/archives");
    }

    #[test]
    fn parse_ftp_mlsd_and_unix_list_lines() {
        let (name, is_dir, size) =
            parse_mlsd_line("type=file;size=11;modify=20260824120000; a.tar").unwrap();
        assert_eq!(name, "a.tar");
        assert!(!is_dir);
        assert_eq!(size, 11);
        let (name, is_dir, size) = parse_mlsd_line("type=dir;modify=20260824120000; sub").unwrap();
        assert_eq!(name, "sub");
        assert!(is_dir);
        assert_eq!(size, 0);
        assert!(parse_mlsd_line("type=cdir; .").is_none());
        assert!(parse_mlsd_line("type=pdir; ..").is_none());

        assert!(parse_unix_list_line("").is_none());
        assert!(parse_unix_list_line("total 12").is_none());
        let (name, is_dir, size) =
            parse_unix_list_line("drwxr-xr-x  2 user group 4096 Jan 1 12:00 sub").unwrap();
        assert_eq!(name, "sub");
        assert!(is_dir);
        assert_eq!(size, 0);
        let (name, is_dir, size) =
            parse_unix_list_line("-rw-r--r--   1 user   group    1234 Jan  1 12:00   a.tar")
                .unwrap();
        assert_eq!(name, "a.tar");
        assert!(!is_dir);
        assert_eq!(size, 1234);
        assert!(
            parse_unix_list_line("lrwxrwxrwx 1 user group 8 Jan 1 12:00 link -> dest").is_none()
        );
    }

    #[test]
    fn ftp_list_cap_errors_not_truncate() {
        let lines: Vec<String> = (0..=FTP_LIST_KEY_CAP)
            .map(|i| format!("type=file;size=1; f{i}"))
            .collect();
        let err = collect_ftp_dirents(&lines, "/", true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("too large") || err.contains("truncated"),
            "{err}"
        );
        assert!(
            err.contains(&FTP_LIST_KEY_CAP.to_string()) || err.contains("100000"),
            "{err}"
        );
    }

    /// Regression: FTP directory URL lists sizes via MLSD.
    #[test]
    fn open_ftp_folder_lists_sizes() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let mlsd = concat!(
            "type=cdir; .\r\n",
            "type=pdir; ..\r\n",
            "type=file;size=11; a.tar\r\n",
            "type=dir; sub\r\n",
            "type=file;size=7; b.bin\r\n",
        );
        let mock = MockFtp::spawn(MockConfig {
            honor_size: false,
            honor_mlsd: true,
            honor_list: false,
            honor_cwd: true,
            mlsd_body: mlsd.into(),
            ..Default::default()
        });
        let url = mock.url("/data/");
        let ms = open_ftp_folder(&url)
            .unwrap()
            .expect("ftp folder URL should mount");
        let dents = ms.list_dirents("/").expect("dirents");
        assert!(
            dents.iter().any(|d| d.name == "a.tar" && d.size == 11),
            "{dents:?}"
        );
        assert!(
            dents.iter().any(|d| d.name == "b.bin" && d.size == 7),
            "{dents:?}"
        );
        assert!(dents.iter().any(|d| d.name == "sub"), "{dents:?}");
        assert!(!dents.iter().any(|d| d.name == "." || d.name == ".."));
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("MLSD")),
            "expected MLSD, log={log:?}"
        );
    }

    #[test]
    fn open_ftp_folder_falls_back_to_unix_list() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let list = concat!(
            "total 12\r\n",
            "drwxr-xr-x 2 user group 4096 Jan 1 12:00 sub\r\n",
            "-rw-r--r-- 1 user group   11 Jan 1 12:00 a.tar\r\n",
            "lrwxrwxrwx 1 user group    8 Jan 1 12:00 link -> dest\r\n",
            "\r\n",
            "-rw-r--r--   1 user   group    7 Jan  1 12:00   b.bin\r\n",
        );
        let mock = MockFtp::spawn(MockConfig {
            honor_size: false,
            honor_mlsd: false,
            honor_list: true,
            honor_cwd: true,
            list_body: list.into(),
            ..Default::default()
        });
        let ms = open_ftp_folder(&mock.url("/data/"))
            .unwrap()
            .expect("folder");
        let dents = ms.list_dirents("/").expect("dirents");
        assert!(
            dents.iter().any(|d| d.name == "a.tar" && d.size == 11),
            "{dents:?}"
        );
        assert!(
            dents.iter().any(|d| d.name == "b.bin" && d.size == 7),
            "{dents:?}"
        );
        assert!(dents.iter().any(|d| d.name == "sub"), "{dents:?}");
        assert!(!dents.iter().any(|d| d.name == "link"), "symlinks skipped");
        let log = mock.log.lock().unwrap();
        assert!(log.iter().any(|l| l.starts_with("LIST")), "{log:?}");
    }

    #[test]
    fn open_ftp_folder_file_url_is_none() {
        let _g = EnvGuard::acquire(FTP_ENV_KEYS);
        let mock = MockFtp::spawn(MockConfig {
            body: b"not-a-dir".to_vec(),
            honor_size: true,
            honor_rest: true,
            honor_cwd: false,
            ..Default::default()
        });
        assert!(
            open_ftp_folder(&mock.url("/blob.bin")).unwrap().is_none(),
            "file URL must return Ok(None)"
        );
    }
}
