//! Azure Blob `az://container/blob` Range GET and prefix listing (List Blobs).
//!
//! Also accepts `azure://`. Not `wasb://` in v1.
//!
//! # File wire
//!
//! `https://{account}.blob.core.windows.net/{container}/{blob}` GET +
//! `x-ms-version: 2020-10-02` + `Range: bytes=start-end`. Account comes from
//! [`AZURE_ACCOUNT_ENV`], not the URL host. Endpoint override:
//! [`AZURE_ENDPOINT_ENV`] (Azurite).
//!
//! # List wire
//!
//! `GET …/{container}?restype=container&comp=list&delimiter=/&prefix=` +
//! `NextMarker` loop. Cap [`AZURE_LIST_KEY_CAP`] then error.
//!
//! # Auth order
//!
//! 1. `AZURE_STORAGE_SAS_TOKEN` (query append; redacted in logs)
//! 2. `AZURE_STORAGE_KEY` SharedKey HMAC-SHA256
//! 3. IMDS MSI `http://169.254.169.254/metadata/identity/oauth2/token`
//!    (`Metadata: true`, resource `https://storage.azure.com/`)
//!    override [`AZURE_IMDS_BASE_ENV`] for tests
//! 4. Anonymous if `RATARMOUNT_AZURE_ANONYMOUS=1`
//!
//! `AZURE_STORAGE_ACCOUNT` is required for non-anonymous (and to form the host
//! unless [`AZURE_ENDPOINT_ENV`] is set). R2/MinIO remain S3.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, Mac};
use log::debug;
use ratarmount_core::{ArchiveRead, MountSource};
use sha2::Sha256;
use tempfile::NamedTempFile;
use url::Url;

use crate::folder::{RemoteDirent, RemoteFolderMountSource, RemoteListing};
use crate::{parse_content_range_total, RemoteError, Result, USER_AGENT};

type HmacSha256 = Hmac<Sha256>;

/// Live Range threshold (1 MiB), matching S3/GCS.
pub const DEFAULT_AZURE_RANGE_THRESHOLD: u64 = 1024 * 1024;
/// Hard cap on listed blobs + prefixes.
pub const AZURE_LIST_KEY_CAP: usize = 100_000;
pub const AZURE_LIST_PAGE_CAP: usize = 10_000;

pub const AZURE_ACCOUNT_ENV: &str = "AZURE_STORAGE_ACCOUNT";
pub const AZURE_SAS_ENV: &str = "AZURE_STORAGE_SAS_TOKEN";
pub const AZURE_KEY_ENV: &str = "AZURE_STORAGE_KEY";
pub const AZURE_ENDPOINT_ENV: &str = "AZURE_STORAGE_ENDPOINT";
pub const AZURE_ANON_ENV: &str = "RATARMOUNT_AZURE_ANONYMOUS";
pub const AZURE_IMDS_BASE_ENV: &str = "RATARMOUNT_AZURE_IMDS_BASE";

const DEFAULT_IMDS_BASE: &str = "http://169.254.169.254";
const X_MS_VERSION: &str = "2020-10-02";
const IMDS_TIMEOUT: Duration = Duration::from_secs(2);
const CREDS_EXPIRY_SKEW: Duration = Duration::from_secs(120);
const IMDS_RESOURCE: &str = "https://storage.azure.com/";

/// Parsed `az://container/blob` (account is env, not host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureLocation {
    pub container: String,
    pub blob: String,
}

/// Parse `az://container/blob/with/slashes` or `azure://…`. Blob required for file open.
pub fn parse_azure_url(url_str: &str) -> Result<AzureLocation> {
    let loc = parse_azure_url_allow_prefix(url_str)?;
    if loc.blob.is_empty() {
        return Err(RemoteError::Url("az URL missing blob name".into()));
    }
    Ok(loc)
}

/// Like [`parse_azure_url`], but an empty blob is the container root (prefix folder).
pub fn parse_azure_url_allow_prefix(url_str: &str) -> Result<AzureLocation> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    match url.scheme() {
        "az" | "azure" => {}
        other => return Err(RemoteError::UnsupportedScheme(other.to_string())),
    }
    let container = url
        .host_str()
        .ok_or_else(|| RemoteError::Url("az URL missing container (az://container/blob)".into()))?
        .to_string();
    if container.is_empty() {
        return Err(RemoteError::Url(
            "az URL missing container (az://container/blob)".into(),
        ));
    }
    let blob = url.path().trim_start_matches('/').to_string();
    Ok(AzureLocation { container, blob })
}

fn azure_err(msg: impl Into<String>) -> RemoteError {
    RemoteError::Io(io::Error::other(format!("azure: {}", msg.into())))
}

fn azure_auth_err(msg: impl Into<String>) -> RemoteError {
    RemoteError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("azure: {}", msg.into()),
    ))
}

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|v| {
        let t = v.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

fn anonymous_enabled() -> bool {
    env_truthy(AZURE_ANON_ENV)
}

fn imds_base() -> String {
    non_empty_env(AZURE_IMDS_BASE_ENV)
        .unwrap_or_else(|| DEFAULT_IMDS_BASE.into())
        .trim_end_matches('/')
        .to_string()
}

fn storage_account() -> Option<String> {
    non_empty_env(AZURE_ACCOUNT_ENV)
}

fn custom_endpoint() -> Option<String> {
    non_empty_env(AZURE_ENDPOINT_ENV).map(|s| s.trim_end_matches('/').to_string())
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn encode_blob_path(blob: &str) -> String {
    blob.split('/')
        .map(urlencoding_encode)
        .collect::<Vec<_>>()
        .join("/")
}

const B64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(B64_TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64_TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(B64_TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(B64_TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64_TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(B64_TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64_TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(B64_TABLE[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !bytes.len().is_multiple_of(4) {
        return Err(azure_err("AZURE_STORAGE_KEY is not valid base64"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    #[allow(clippy::chunks_exact_to_as_chunks)] // MSRV 1.74: `as_chunks` is 1.88+
    for chunk in bytes.chunks_exact(4) {
        let a = val(chunk[0]).ok_or_else(|| azure_err("AZURE_STORAGE_KEY is not valid base64"))?;
        let b = val(chunk[1]).ok_or_else(|| azure_err("AZURE_STORAGE_KEY is not valid base64"))?;
        let c = if chunk[2] == b'=' {
            None
        } else {
            Some(val(chunk[2]).ok_or_else(|| azure_err("AZURE_STORAGE_KEY is not valid base64"))?)
        };
        let d = if chunk[3] == b'=' {
            None
        } else {
            Some(val(chunk[3]).ok_or_else(|| azure_err("AZURE_STORAGE_KEY is not valid base64"))?)
        };
        out.push((a << 2) | (b >> 4));
        if let Some(c) = c {
            out.push((b << 4) | (c >> 2));
            if let Some(d) = d {
                out.push((c << 6) | d);
            }
        }
    }
    Ok(out)
}

/// Redact a SAS token for logs / Debug (`sv=…&sig=***`).
pub fn redact_sas_token(sas: &str) -> String {
    let sas = sas.trim().trim_start_matches('?');
    if sas.is_empty() {
        return String::new();
    }
    sas.split('&')
        .map(|part| {
            let part = part.trim();
            match part.split_once('=') {
                Some((k, _))
                    if k.eq_ignore_ascii_case("sig")
                        || k.eq_ignore_ascii_case("signature")
                        || k.eq_ignore_ascii_case("sk") =>
                {
                    format!("{k}=***")
                }
                Some((k, v)) if v.len() > 12 && k.eq_ignore_ascii_case("sig") => {
                    format!("{k}=***")
                }
                Some((k, _)) => format!("{k}=***"),
                None => "***".into(),
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn append_sas(url: &str, sas: &str) -> String {
    let sas = sas.trim().trim_start_matches('?');
    if sas.is_empty() {
        return url.to_string();
    }
    if url.contains('?') {
        format!("{url}&{sas}")
    } else {
        format!("{url}?{sas}")
    }
}

fn redact_url_sas(url: &str, sas: Option<&str>) -> String {
    match sas {
        Some(s) if !s.is_empty() && url.contains(s.trim().trim_start_matches('?')) => {
            url.replace(s.trim().trim_start_matches('?'), "***")
        }
        _ => url.to_string(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredSource {
    Sas,
    SharedKey,
    Imds,
    Anonymous,
}

struct CachedToken {
    access_token: String,
    expiration: chrono::DateTime<chrono::Utc>,
}

static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

#[cfg(test)]
fn clear_token_cache() {
    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        *guard = None;
    }
}

fn token_still_valid(tok: &CachedToken) -> bool {
    let skew = chrono::Duration::from_std(CREDS_EXPIRY_SKEW).unwrap_or_default();
    chrono::Utc::now() + skew < tok.expiration
}

fn take_cached_token() -> Option<String> {
    let guard = TOKEN_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .filter(|t| token_still_valid(t))
        .map(|t| t.access_token.clone())
}

fn store_cached_token(token: CachedToken) {
    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        *guard = Some(token);
    }
}

enum AzureAuth {
    Sas { token: String, account: String },
    SharedKey { account: String, key: Vec<u8> },
    Bearer { token: String, account: String },
    Anonymous { account: String },
}

impl AzureAuth {
    fn account(&self) -> &str {
        match self {
            Self::Sas { account, .. }
            | Self::SharedKey { account, .. }
            | Self::Bearer { account, .. }
            | Self::Anonymous { account } => account,
        }
    }

    fn source(&self) -> CredSource {
        match self {
            Self::Sas { .. } => CredSource::Sas,
            Self::SharedKey { .. } => CredSource::SharedKey,
            Self::Bearer { .. } => CredSource::Imds,
            Self::Anonymous { .. } => CredSource::Anonymous,
        }
    }

    fn sas(&self) -> Option<&str> {
        match self {
            Self::Sas { token, .. } => Some(token.as_str()),
            _ => None,
        }
    }
}

impl std::fmt::Debug for AzureAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sas { account, token } => f
                .debug_struct("AzureAuth::Sas")
                .field("account", account)
                .field("token", &redact_sas_token(token))
                .finish(),
            Self::SharedKey { account, .. } => f
                .debug_struct("AzureAuth::SharedKey")
                .field("account", account)
                .field("key", &"***")
                .finish(),
            Self::Bearer { account, .. } => f
                .debug_struct("AzureAuth::Bearer")
                .field("account", account)
                .field("token", &"***")
                .finish(),
            Self::Anonymous { account } => f
                .debug_struct("AzureAuth::Anonymous")
                .field("account", account)
                .finish(),
        }
    }
}

fn parse_oauth_token_json(body: &str) -> Result<CachedToken> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| azure_err(format!("failed to parse MSI token JSON: {e}")))?;
    let access_token = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| azure_err("MSI token JSON missing access_token"))?
        .to_string();
    let expires_in = v
        .get("expires_in")
        .and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(3600);
    let expiration = chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64);
    Ok(CachedToken {
        access_token,
        expiration,
    })
}

fn fetch_imds_token() -> Result<CachedToken> {
    let url = format!(
        "{}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={}",
        imds_base(),
        urlencoding_encode(IMDS_RESOURCE)
    );
    debug!("azure: fetching IMDS MSI token");
    let resp = ureq::get(&url)
        .set("User-Agent", USER_AGENT)
        .set("Metadata", "true")
        .timeout(IMDS_TIMEOUT)
        .call()
        .map_err(|e| azure_err(format!("IMDS GET: {e}")))?;
    let status = resp.status();
    let body = resp.into_string().unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(azure_err(format!("IMDS GET status {status}: {body}")));
    }
    parse_oauth_token_json(&body)
}

fn require_account(tried: &str) -> Result<String> {
    storage_account()
        .ok_or_else(|| azure_err(format!("AZURE_STORAGE_ACCOUNT is required ({tried})")))
}

fn resolve_auth() -> Result<AzureAuth> {
    if let Some(token) = non_empty_env(AZURE_SAS_ENV) {
        let account = require_account("SAS")?;
        return Ok(AzureAuth::Sas { token, account });
    }
    if let Some(key_b64) = non_empty_env(AZURE_KEY_ENV) {
        let account = require_account("SharedKey")?;
        let key = base64_decode(&key_b64)?;
        return Ok(AzureAuth::SharedKey { account, key });
    }
    if let Some(tok) = take_cached_token() {
        let account = require_account("cached IMDS")?;
        return Ok(AzureAuth::Bearer {
            token: tok,
            account,
        });
    }

    let mut tried: Vec<&str> = vec!["env AZURE_STORAGE_SAS_TOKEN", "env AZURE_STORAGE_KEY"];
    let mut role_errors: Vec<String> = Vec::new();

    tried.push("IMDS MSI");
    match fetch_imds_token() {
        Ok(tok) => {
            let account = require_account("IMDS")?;
            let bearer = tok.access_token.clone();
            store_cached_token(tok);
            return Ok(AzureAuth::Bearer {
                token: bearer,
                account,
            });
        }
        Err(e) => {
            debug!("azure: IMDS failed: {e}");
            role_errors.push(format!("IMDS: {e}"));
        }
    }

    if anonymous_enabled() {
        let account = storage_account().unwrap_or_else(|| "anonymous".into());
        return Ok(AzureAuth::Anonymous { account });
    }

    let mut msg = format!(
        "no Azure credentials found for az://; tried: {}; \
         set AZURE_STORAGE_SAS_TOKEN, AZURE_STORAGE_KEY, run with a managed identity, \
         or set RATARMOUNT_AZURE_ANONYMOUS=1 for public containers (AZURE_STORAGE_ACCOUNT required except anonymous+endpoint)",
        tried.join(", ")
    );
    if !role_errors.is_empty() {
        msg.push_str(&format!(" (role errors: {})", role_errors.join("; ")));
    }
    Err(azure_err(msg))
}

fn rfc1123_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn blob_url(auth: &AzureAuth, loc: &AzureLocation) -> String {
    let path = if loc.blob.is_empty() {
        format!("/{}", loc.container)
    } else {
        format!("/{}/{}", loc.container, encode_blob_path(&loc.blob))
    };
    let base = if let Some(ep) = custom_endpoint() {
        ep
    } else {
        format!("https://{}.blob.core.windows.net", auth.account())
    };
    let url = format!("{base}{path}");
    if let Some(sas) = auth.sas() {
        append_sas(&url, sas)
    } else {
        url
    }
}

fn list_url(auth: &AzureAuth, container: &str, prefix: &str, marker: Option<&str>) -> String {
    let mut q = format!(
        "restype=container&comp=list&delimiter=%2F&prefix={}",
        urlencoding_encode(prefix)
    );
    if let Some(m) = marker.filter(|t| !t.is_empty()) {
        q.push_str("&marker=");
        q.push_str(&urlencoding_encode(m));
    }
    let base = if let Some(ep) = custom_endpoint() {
        ep
    } else {
        format!("https://{}.blob.core.windows.net", auth.account())
    };
    let mut url = format!("{base}/{container}?{q}");
    if let Some(sas) = auth.sas() {
        url = append_sas(&url, sas);
    }
    url
}

/// SharedKey string-to-sign for GET (empty body). `canonical_resource` starts with `/{account}/…`.
fn shared_key_string_to_sign(
    range: Option<&str>,
    x_ms_date: &str,
    canonical_resource: &str,
) -> String {
    let mut s = String::from("GET\n");
    // Content-Encoding, Language, Length, MD5, Type, Date,
    // If-Modified-Since, If-Match, If-None-Match, If-Unmodified-Since
    for _ in 0..10 {
        s.push('\n');
    }
    if let Some(r) = range {
        s.push_str(r);
    }
    s.push('\n');
    s.push_str("x-ms-date:");
    s.push_str(x_ms_date);
    s.push('\n');
    s.push_str("x-ms-version:");
    s.push_str(X_MS_VERSION);
    s.push('\n');
    s.push_str(canonical_resource);
    s
}

fn shared_key_authorization(account: &str, key: &[u8], string_to_sign: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(string_to_sign.as_bytes());
    let sig = base64_encode(&mac.finalize().into_bytes());
    format!("SharedKey {account}:{sig}")
}

fn canonical_resource_blob(account: &str, loc: &AzureLocation) -> String {
    if loc.blob.is_empty() {
        format!("/{account}/{}", loc.container)
    } else {
        format!("/{account}/{}/{}", loc.container, loc.blob)
    }
}

fn canonical_resource_list(
    account: &str,
    container: &str,
    prefix: &str,
    marker: Option<&str>,
) -> String {
    let mut s = format!("/{account}/{container}\ncomp:list\ndelimiter:/");
    if let Some(m) = marker.filter(|t| !t.is_empty()) {
        s.push_str("\nmarker:");
        s.push_str(m);
    }
    s.push_str("\nprefix:");
    s.push_str(prefix);
    s.push_str("\nrestype:container");
    s
}

fn apply_azure_headers(
    mut req: ureq::Request,
    auth: &AzureAuth,
    range: Option<&str>,
    string_to_sign: Option<&str>,
    x_ms_date: &str,
) -> ureq::Request {
    req = req
        .set("User-Agent", USER_AGENT)
        .set("x-ms-version", X_MS_VERSION)
        .set("x-ms-date", x_ms_date);
    if let Some(r) = range {
        req = req.set("Range", r);
    }
    match auth {
        AzureAuth::SharedKey { account, key } => {
            let sts = string_to_sign.expect("SharedKey needs string-to-sign");
            let hdr = shared_key_authorization(account, key, sts);
            req = req.set("Authorization", &hdr);
        }
        AzureAuth::Bearer { token, .. } => {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }
        AzureAuth::Sas { .. } | AzureAuth::Anonymous { .. } => {}
    }
    req
}

fn azure_status_error(
    source: CredSource,
    status: u16,
    loc: &AzureLocation,
    body: &str,
) -> RemoteError {
    let kind = if source == CredSource::Anonymous {
        "anonymous GetBlob"
    } else {
        "GetBlob"
    };
    let msg = format!(
        "{kind} HTTP {status} for az://{}/{}: {body}",
        loc.container, loc.blob
    );
    if status == 401 || status == 403 {
        azure_auth_err(msg)
    } else {
        azure_err(msg)
    }
}

fn azure_get_blob(
    loc: &AzureLocation,
    range: Option<(u64, u64)>,
) -> Result<(CredSource, ureq::Response)> {
    let auth = resolve_auth()?;
    let url = blob_url(&auth, loc);
    let range_value = range.map(|(start, end)| format!("bytes={start}-{end}"));
    let x_ms_date = rfc1123_now();
    let sts = match &auth {
        AzureAuth::SharedKey { account, .. } => Some(shared_key_string_to_sign(
            range_value.as_deref(),
            &x_ms_date,
            &canonical_resource_blob(account, loc),
        )),
        _ => None,
    };
    debug!(
        "azure GET {} (auth={:?}, range={:?})",
        redact_url_sas(&url, auth.sas()),
        auth.source(),
        range_value
    );
    let req = apply_azure_headers(
        ureq::get(&url),
        &auth,
        range_value.as_deref(),
        sts.as_deref(),
        &x_ms_date,
    );
    let resp = req
        .call()
        .map_err(|e| azure_err(format!("GetBlob az://{}/{}: {e}", loc.container, loc.blob)))?;
    Ok((auth.source(), resp))
}

enum AzureProbe {
    RangesOk(u64),
    FullBody(Vec<u8>),
    Unusable,
}

fn probe_azure_blob(loc: &AzureLocation) -> Result<AzureProbe> {
    let (source, resp) = match azure_get_blob(loc, Some((0, 0))) {
        Ok(v) => v,
        Err(e) => {
            debug!("azure probe request failed: {e}");
            return Ok(AzureProbe::Unusable);
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
            return Ok(AzureProbe::RangesOk(total));
        }
        let _ = resp.into_string();
        return Ok(AzureProbe::Unusable);
    }
    if (200..300).contains(&status) {
        if content_length.is_some_and(|n| n > DEFAULT_AZURE_RANGE_THRESHOLD) {
            let mut reader = resp.into_reader();
            let _ = io::copy(&mut reader, &mut io::sink());
            return Ok(AzureProbe::Unusable);
        }
        let mut reader = resp.into_reader();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        return Ok(AzureProbe::FullBody(bytes));
    }
    debug!(
        "azure probe az://{}/{} -> HTTP {status} (auth={source:?})",
        loc.container, loc.blob
    );
    let _ = resp.into_string();
    Ok(AzureProbe::Unusable)
}

fn fetch_azure_full_get(loc: &AzureLocation) -> Result<Vec<u8>> {
    let (source, resp) = azure_get_blob(loc, None)?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(azure_status_error(source, status, loc, &body));
    }
    let mut reader = resp.into_reader();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Download `az://container/blob` to a tempfile (GET only).
pub fn fetch_azure_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_azure_url(url_str)?;
    fetch_azure_location_to_temp(&loc)
}

fn fetch_azure_location_to_temp(loc: &AzureLocation) -> Result<(NamedTempFile, u64)> {
    let (source, resp) = azure_get_blob(loc, None)?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(azure_status_error(source, status, loc, &body));
    }
    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok((tmp, n))
}

/// Inclusive byte range GET (`start..=end_inclusive`). Expects HTTP 206.
pub fn fetch_azure_range_bytes(url_str: &str, start: u64, end_inclusive: u64) -> Result<Vec<u8>> {
    let loc = parse_azure_url(url_str)?;
    if end_inclusive < start {
        return Err(azure_err(format!(
            "invalid range {start}-{end_inclusive} for az://{}/{}",
            loc.container, loc.blob
        )));
    }
    let expected = end_inclusive - start + 1;
    let (source, resp) = azure_get_blob(&loc, Some((start, end_inclusive)))?;
    let status = resp.status();
    if status == 206 {
        let mut reader = resp.into_reader();
        let mut bytes = Vec::with_capacity(expected as usize);
        reader.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != expected {
            return Err(azure_err(format!(
                "range bytes={start}-{end_inclusive} for az://{}/{} returned {} bytes, expected {expected}",
                loc.container,
                loc.blob,
                bytes.len()
            )));
        }
        return Ok(bytes);
    }
    if status == 200 {
        let _ = resp.into_string();
        return Err(azure_err(format!(
            "HTTP 200 (Range ignored) GetBlob az://{}/{} bytes={start}-{end_inclusive}",
            loc.container, loc.blob
        )));
    }
    let body = resp.into_string().unwrap_or_default();
    Err(azure_status_error(source, status, &loc, &body))
}

/// Seekable Azure Blob reader using live Range GETs.
pub struct AzureRangeFile {
    loc: AzureLocation,
    size: u64,
    pos: u64,
    buffered: Option<Vec<u8>>,
}

impl std::fmt::Debug for AzureRangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureRangeFile")
            .field("container", &self.loc.container)
            .field("blob", &self.loc.blob)
            .field("size", &self.size)
            .field("pos", &self.pos)
            .field("uses_ranges", &self.uses_ranges())
            .finish()
    }
}

impl AzureRangeFile {
    pub fn open(url_str: &str) -> Result<Self> {
        let loc = parse_azure_url(url_str)?;
        Self::open_location(&loc)
    }

    pub fn open_location(loc: &AzureLocation) -> Result<Self> {
        match probe_azure_blob(loc) {
            Ok(AzureProbe::RangesOk(size)) => Ok(Self::range_backed(loc.clone(), size)),
            Ok(AzureProbe::FullBody(bytes)) => {
                let size = bytes.len() as u64;
                Ok(Self {
                    loc: loc.clone(),
                    size,
                    pos: 0,
                    buffered: Some(bytes),
                })
            }
            Ok(AzureProbe::Unusable) | Err(_) => {
                let buf = fetch_azure_full_get(loc)?;
                Ok(Self {
                    loc: loc.clone(),
                    size: buf.len() as u64,
                    pos: 0,
                    buffered: Some(buf),
                })
            }
        }
    }

    pub fn range_backed(loc: AzureLocation, size: u64) -> Self {
        Self {
            loc,
            size,
            pos: 0,
            buffered: None,
        }
    }

    pub fn location(&self) -> &AzureLocation {
        &self.loc
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn uses_ranges(&self) -> bool {
        self.buffered.is_none()
    }
}

pub fn open_azure_range(url_str: &str) -> Result<AzureRangeFile> {
    AzureRangeFile::open(url_str)
}

impl Read for AzureRangeFile {
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
        let range_start = self.pos;
        let range_end = end - 1;
        let (source, resp) = azure_get_blob(&self.loc, Some((range_start, range_end)))
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
        let body = resp.into_string().unwrap_or_default();
        Err(io::Error::other(
            azure_status_error(source, status, &self.loc, &body).to_string(),
        ))
    }
}

impl Seek for AzureRangeFile {
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

// ---------------------------------------------------------------------------
// List Blobs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureListEntry {
    pub name: String,
    pub key: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AzureListedBlob {
    name: String,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AzureListPage {
    blobs: Vec<AzureListedBlob>,
    prefixes: Vec<String>,
    next_marker: Option<String>,
}

fn azure_list_prefix(blob: &str) -> String {
    if blob.is_empty() || blob.ends_with('/') {
        blob.to_string()
    } else {
        format!("{blob}/")
    }
}

fn xml_tag_boundary(b: u8) -> bool {
    b == b'>' || b == b' ' || b == b'/' || b == b'\t' || b == b'\n' || b == b'\r'
}

fn xml_blocks(xml: &str, tag: &str) -> Vec<String> {
    let lower = xml.to_ascii_lowercase();
    let open_plain = format!("<{tag}");
    let close_plain = format!("</{tag}>");
    let mut out = Vec::new();
    let mut search_from = 0;
    while search_from < lower.len() {
        let rest = &lower[search_from..];
        let Some(rel) = rest.find(&open_plain) else {
            break;
        };
        let abs = search_from + rel;
        let after_tag = abs + open_plain.len();
        let next = lower.as_bytes().get(after_tag).copied().unwrap_or(b'>');
        if !xml_tag_boundary(next) {
            search_from = abs + 1;
            continue;
        }
        let after_name = match lower[abs..].find('>') {
            Some(g) => abs + g + 1,
            None => break,
        };
        let Some(c) = lower[after_name..].find(&close_plain) else {
            break;
        };
        out.push(xml[after_name..after_name + c].to_string());
        search_from = after_name + c + close_plain.len();
    }
    out
}

fn xml_tag_text(xml: &str, tag: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    let mut search = 0;
    while search < lower.len() {
        let rest = &lower[search..];
        let rel = rest.find(tag)?;
        let abs = search + rel;
        if abs == 0 {
            search = abs + 1;
            continue;
        }
        let prev = lower.as_bytes()[abs - 1];
        if prev != b'<' && prev != b':' {
            search = abs + 1;
            continue;
        }
        let after_name = abs + tag.len();
        let gt = lower[after_name..].find('>')?;
        let before_gt = xml[after_name..after_name + gt].trim();
        if before_gt.ends_with('/') {
            search = after_name + gt + 1;
            continue;
        }
        let content_at = after_name + gt + 1;
        let end = xml[content_at..].find('<')?;
        let text = xml[content_at..content_at + end].trim();
        return Some(
            text.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'"),
        );
    }
    None
}

fn parse_list_blobs_xml(xml: &str) -> AzureListPage {
    let next_marker = xml_tag_text(xml, "nextmarker").filter(|s| !s.is_empty());
    let mut blobs = Vec::new();
    for block in xml_blocks(xml, "blob") {
        // Skip BlobPrefix inner accidental matches: BlobPrefix also contains <Name>.
        if block.to_ascii_lowercase().contains("<blobprefix") {
            continue;
        }
        let Some(name) = xml_tag_text(&block, "name").filter(|s| !s.is_empty()) else {
            continue;
        };
        let size = xml_tag_text(&block, "content-length")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        blobs.push(AzureListedBlob { name, size });
    }
    let mut prefixes = Vec::new();
    for block in xml_blocks(xml, "blobprefix") {
        if let Some(p) = xml_tag_text(&block, "name").filter(|s| !s.is_empty()) {
            prefixes.push(p);
        }
    }
    AzureListPage {
        blobs,
        prefixes,
        next_marker,
    }
}

fn azure_list_page(container: &str, prefix: &str, marker: Option<&str>) -> Result<AzureListPage> {
    let auth = resolve_auth()?;
    let url = list_url(&auth, container, prefix, marker);
    let x_ms_date = rfc1123_now();
    let sts = match &auth {
        AzureAuth::SharedKey { account, .. } => Some(shared_key_string_to_sign(
            None,
            &x_ms_date,
            &canonical_resource_list(account, container, prefix, marker),
        )),
        _ => None,
    };
    debug!(
        "azure LIST {} (auth={:?})",
        redact_url_sas(&url, auth.sas()),
        auth.source()
    );
    let req = apply_azure_headers(ureq::get(&url), &auth, None, sts.as_deref(), &x_ms_date);
    let resp = req
        .call()
        .map_err(|e| azure_err(format!("List Blobs az://{container}/{prefix}: {e}")))?;
    let status = resp.status();
    let body = resp.into_string().unwrap_or_default();
    if !(200..300).contains(&status) {
        let msg = format!("List Blobs HTTP {status} for az://{container}/{prefix}: {body}");
        return Err(if status == 401 || status == 403 {
            azure_auth_err(msg)
        } else {
            azure_err(msg)
        });
    }
    Ok(parse_list_blobs_xml(&body))
}

fn azure_child_entry(prefix: &str, key: &str, size: u64, is_dir: bool) -> Option<AzureListEntry> {
    let rest = if prefix.is_empty() {
        key
    } else {
        key.strip_prefix(prefix)?
    };
    let name = rest.trim_end_matches('/');
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some(AzureListEntry {
        name: name.to_string(),
        key: key.to_string(),
        is_dir,
        size: if is_dir { 0 } else { size },
    })
}

pub fn list_azure_prefix(loc: &AzureLocation) -> Result<Vec<AzureListEntry>> {
    list_azure_prefix_capped(loc, AZURE_LIST_KEY_CAP)
}

pub fn list_azure_prefix_capped(loc: &AzureLocation, cap: usize) -> Result<Vec<AzureListEntry>> {
    let prefix = azure_list_prefix(&loc.blob);
    let mut marker: Option<String> = None;
    let mut out: Vec<AzureListEntry> = Vec::new();
    let mut total = 0usize;
    let mut pages = 0usize;
    let page_cap = cap.saturating_add(1).min(AZURE_LIST_PAGE_CAP);
    loop {
        pages = pages.saturating_add(1);
        if pages > page_cap {
            return Err(azure_err(format!(
                "azure prefix too large (>{cap} keys) for az://{}/{}; listing is not silently truncated",
                loc.container, loc.blob
            )));
        }
        let page = azure_list_page(&loc.container, &prefix, marker.as_deref())?;
        let n = page.blobs.len() + page.prefixes.len();
        if page.next_marker.is_some() && n == 0 {
            return Err(azure_err(
                "truncated List Blobs page with no keys; listing is not complete",
            ));
        }
        total = total.saturating_add(n);
        if total > cap {
            return Err(azure_err(format!(
                "azure prefix too large (>{cap} keys) for az://{}/{}; listing is not silently truncated",
                loc.container, loc.blob
            )));
        }
        for obj in &page.blobs {
            if let Some(ent) = azure_child_entry(&prefix, &obj.name, obj.size, false) {
                out.push(ent);
            }
        }
        for cp in &page.prefixes {
            if let Some(ent) = azure_child_entry(&prefix, cp, 0, true) {
                out.push(ent);
            }
        }
        let Some(next) = page
            .next_marker
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            break;
        };
        if marker.as_deref() == Some(next) {
            return Err(azure_err(
                "truncated List Blobs page repeated NextMarker; listing is not complete",
            ));
        }
        marker = Some(next.to_string());
    }
    Ok(out)
}

pub fn azure_location_is_dir(loc: &AzureLocation) -> Result<bool> {
    if loc.blob.is_empty() || loc.blob.ends_with('/') {
        return Ok(true);
    }
    let page = match azure_list_page(&loc.container, &loc.blob, None) {
        Ok(p) => p,
        Err(e) => {
            debug!(
                "azure list probe az://{}/{} failed ({e}); treating as blob",
                loc.container, loc.blob
            );
            return Ok(false);
        }
    };
    let has_exact = page.blobs.iter().any(|o| o.name == loc.blob);
    if has_exact {
        return Ok(false);
    }
    let child_prefix = azure_list_prefix(&loc.blob);
    let has_child_prefix = page
        .prefixes
        .iter()
        .any(|p| p == &child_prefix || p.starts_with(&child_prefix));
    let has_child_key = page
        .blobs
        .iter()
        .any(|o| o.name.starts_with(&child_prefix) && o.name != loc.blob);
    Ok(has_child_prefix || has_child_key)
}

/// Prefix listing backend for [`RemoteFolderMountSource`].
pub struct AzureListing {
    pub container: String,
}

impl AzureListing {
    pub fn new(container: impl Into<String>) -> Self {
        Self {
            container: container.into(),
        }
    }
}

impl RemoteListing for AzureListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        let loc = AzureLocation {
            container: self.container.clone(),
            blob: remote_path.trim_start_matches('/').to_string(),
        };
        Ok(list_azure_prefix(&loc)?
            .into_iter()
            .map(|e| RemoteDirent {
                name: e.name,
                remote_path: e.key,
                is_dir: e.is_dir,
                size: e.size,
                mtime: 0.0,
            })
            .collect())
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        azure_location_is_dir(&AzureLocation {
            container: self.container.clone(),
            blob: remote_path.trim_start_matches('/').to_string(),
        })
    }

    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>> {
        let loc = AzureLocation {
            container: self.container.clone(),
            blob: remote_path.to_string(),
        };
        if size > 0 {
            Ok(Box::new(AzureRangeFile::range_backed(loc, size)))
        } else {
            Ok(Box::new(AzureRangeFile::open_location(&loc)?))
        }
    }
}

/// Open `az://container[/prefix]` as a folder. `Ok(None)` if it is not a directory.
pub fn open_azure_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_azure_url_allow_prefix(s)?;
    if !azure_location_is_dir(&loc)? {
        return Ok(None);
    }
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        loc.blob,
        AzureListing::new(loc.container),
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use std::thread;

    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            clear_token_cache();
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
            clear_token_cache();
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    const AZ_ENV_KEYS: &[&str] = &[
        AZURE_ACCOUNT_ENV,
        AZURE_SAS_ENV,
        AZURE_KEY_ENV,
        AZURE_ENDPOINT_ENV,
        AZURE_ANON_ENV,
        AZURE_IMDS_BASE_ENV,
    ];

    fn parse_bytes_range(header: &str, total: usize) -> Option<(usize, usize)> {
        let h = header.trim();
        let rest = h.strip_prefix("bytes=")?;
        let (a, b) = rest.split_once('-')?;
        let start: usize = a.parse().ok()?;
        if b.is_empty() {
            if total == 0 {
                return None;
            }
            return Some((start, total - 1));
        }
        let end: usize = b.parse().ok()?;
        Some((start, end))
    }

    struct MockAzure {
        base_url: String,
        log: Arc<StdMutex<Vec<String>>>,
        gets: Arc<AtomicUsize>,
        auth_headers: Arc<AtomicUsize>,
        range_headers: Arc<AtomicUsize>,
        list_gets: Arc<AtomicUsize>,
        saw_sas: Arc<AtomicUsize>,
        _join: Option<thread::JoinHandle<()>>,
    }

    enum MockMode {
        Object {
            body: Vec<u8>,
            require_auth: bool,
        },
        List {
            page1: String,
            page2: String,
            file_body: Vec<u8>,
        },
        Imds {
            body: String,
        },
        NotFound,
    }

    impl MockAzure {
        fn spawn(mode: MockMode) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let log = Arc::new(StdMutex::new(Vec::new()));
            let gets = Arc::new(AtomicUsize::new(0));
            let auth_headers = Arc::new(AtomicUsize::new(0));
            let range_headers = Arc::new(AtomicUsize::new(0));
            let list_gets = Arc::new(AtomicUsize::new(0));
            let saw_sas = Arc::new(AtomicUsize::new(0));
            let log_c = Arc::clone(&log);
            let gets_c = Arc::clone(&gets);
            let auth_c = Arc::clone(&auth_headers);
            let range_c = Arc::clone(&range_headers);
            let list_c = Arc::clone(&list_gets);
            let sas_c = Arc::clone(&saw_sas);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut has_auth = false;
                    let mut range_hdr: Option<String> = None;
                    let mut metadata: Option<String> = None;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        let lower = line.to_ascii_lowercase();
                        if lower.starts_with("authorization:") {
                            has_auth = true;
                        }
                        if let Some(rest) = lower.strip_prefix("range:") {
                            let _ = rest;
                            if let Some((_, v)) = line.split_once(':') {
                                range_hdr = Some(v.trim().to_string());
                            }
                        }
                        if lower.starts_with("metadata:") {
                            if let Some((_, v)) = line.split_once(':') {
                                metadata = Some(v.trim().to_string());
                            }
                        }
                    }
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    if path.contains("sig=") || path.contains("sv=") {
                        sas_c.fetch_add(1, Ordering::SeqCst);
                    }
                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if has_auth {
                            lg.push("Authorization: present".into());
                        } else {
                            lg.push("Authorization: absent".into());
                        }
                        if let Some(ref r) = range_hdr {
                            lg.push(format!("Range: {r}"));
                        }
                    }
                    if has_auth {
                        auth_c.fetch_add(1, Ordering::SeqCst);
                    }
                    if range_hdr.is_some() {
                        range_c.fetch_add(1, Ordering::SeqCst);
                    }
                    let is_get = request_line.starts_with("GET ");
                    match &mode {
                        MockMode::Object { body, require_auth } => {
                            if !is_get {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                continue;
                            }
                            if *require_auth && !has_auth && !path.contains("sig=") {
                                let msg = b"AuthenticationFailed";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    msg.len()
                                );
                                let _ = stream.write_all(msg);
                                continue;
                            }
                            gets_c.fetch_add(1, Ordering::SeqCst);
                            if let Some(ref r) = range_hdr {
                                if let Some((start, end)) = parse_bytes_range(r, body.len()) {
                                    if start >= body.len() {
                                        let msg = b"InvalidRange";
                                        let _ = write!(
                                            stream,
                                            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                            msg.len()
                                        );
                                        let _ = stream.write_all(msg);
                                        continue;
                                    }
                                    let end = end.min(body.len().saturating_sub(1));
                                    let slice = &body[start..=end];
                                    let cr = format!("bytes {}-{}/{}", start, end, body.len());
                                    let _ = write!(
                                        stream,
                                        "HTTP/1.1 206 Partial Content\r\nContent-Range: {cr}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                                        slice.len()
                                    );
                                    let _ = stream.write_all(slice);
                                    continue;
                                }
                            }
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(body);
                        }
                        MockMode::List {
                            page1,
                            page2,
                            file_body,
                        } => {
                            if path.contains("comp=list") {
                                list_c.fetch_add(1, Ordering::SeqCst);
                                gets_c.fetch_add(1, Ordering::SeqCst);
                                let body = if path.contains("marker=") {
                                    page2.as_bytes()
                                } else {
                                    page1.as_bytes()
                                };
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = stream.write_all(body);
                                continue;
                            }
                            gets_c.fetch_add(1, Ordering::SeqCst);
                            if let Some(ref r) = range_hdr {
                                if let Some((start, end)) = parse_bytes_range(r, file_body.len()) {
                                    let end = end.min(file_body.len().saturating_sub(1));
                                    if start <= end && start < file_body.len() {
                                        let slice = &file_body[start..=end];
                                        let cr =
                                            format!("bytes {}-{}/{}", start, end, file_body.len());
                                        let _ = write!(
                                            stream,
                                            "HTTP/1.1 206 Partial Content\r\nContent-Range: {cr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                            slice.len()
                                        );
                                        let _ = stream.write_all(slice);
                                        continue;
                                    }
                                }
                            }
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                file_body.len()
                            );
                            let _ = stream.write_all(file_body);
                        }
                        MockMode::Imds { body } => {
                            if !is_get {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                continue;
                            }
                            if metadata.as_deref() != Some("true") {
                                let msg = b"Metadata header required";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    msg.len()
                                );
                                let _ = stream.write_all(msg);
                                continue;
                            }
                            gets_c.fetch_add(1, Ordering::SeqCst);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                        }
                        MockMode::NotFound => {
                            gets_c.fetch_add(1, Ordering::SeqCst);
                            let msg = b"BlobNotFound";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                msg.len()
                            );
                            let _ = stream.write_all(msg);
                        }
                    }
                }
            });
            Self {
                base_url,
                log,
                gets,
                auth_headers,
                range_headers,
                list_gets,
                saw_sas,
                _join: Some(join),
            }
        }
    }

    #[test]
    fn parse_az_and_azure_schemes() {
        let a = parse_azure_url("az://mycontainer/path/to/blob.bin").unwrap();
        assert_eq!(a.container, "mycontainer");
        assert_eq!(a.blob, "path/to/blob.bin");
        let b = parse_azure_url("azure://ctr/x").unwrap();
        assert_eq!(b.container, "ctr");
        assert_eq!(b.blob, "x");
        assert!(parse_azure_url("wasb://ctr/x").is_err());
        assert!(parse_azure_url("az://only-container").is_err());
        let root = parse_azure_url_allow_prefix("az://only-container").unwrap();
        assert!(root.blob.is_empty());
    }

    #[test]
    fn redact_sas_hides_sig() {
        let sas = "sv=2020-10-02&ss=b&srt=sco&sp=rl&se=2099-01-01T00:00:00Z&sig=SUPERSECRETVALUE";
        let red = redact_sas_token(sas);
        assert!(!red.contains("SUPERSECRETVALUE"), "{red}");
        assert!(red.contains("sig=***"), "{red}");
    }

    #[test]
    fn sas_and_hmac_redacted_in_debug() {
        let sas = AzureAuth::Sas {
            token: "sv=2020-10-02&sig=SECRETSIGVALUE".into(),
            account: "acct".into(),
        };
        let d = format!("{sas:?}");
        assert!(!d.contains("SECRETSIGVALUE"), "{d}");
        let key = AzureAuth::SharedKey {
            account: "acct".into(),
            key: b"account-key-material-secret".to_vec(),
        };
        let d = format!("{key:?}");
        assert!(!d.contains("account-key-material-secret"), "{d}");
        assert!(d.contains("***"), "{d}");
    }

    #[test]
    fn azure_range_file_live_reads_206() {
        let body: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let mock = MockAzure::spawn(MockMode::Object {
            body: body.clone(),
            require_auth: true,
        });
        let _g = EnvGuard::acquire(AZ_ENV_KEYS);
        _g.set(AZURE_ACCOUNT_ENV, "devstoreaccount1");
        _g.set(AZURE_ENDPOINT_ENV, &mock.base_url);
        _g.set(
            AZURE_KEY_ENV,
            &base64_encode(b"azure-account-key-material!!"),
        );
        _g.set(AZURE_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let mut f = open_azure_range("az://ctr/live.bin").unwrap();
        assert!(f.uses_ranges());
        assert_eq!(f.len(), body.len() as u64);
        let mut prefix = [0u8; 16];
        f.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, &body[..16]);
        f.seek(SeekFrom::Start(1000)).unwrap();
        let mut mid = [0u8; 32];
        f.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, &body[1000..1032]);
        assert!(mock.range_headers.load(Ordering::SeqCst) >= 2);
        assert!(mock.auth_headers.load(Ordering::SeqCst) >= 2);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.contains("Authorization: present")),
            "SharedKey must send Authorization, log={log:?}"
        );
    }

    #[test]
    fn sas_appended_no_sharedkey_header() {
        let body = b"sas-object".to_vec();
        let mock = MockAzure::spawn(MockMode::Object {
            body: body.clone(),
            require_auth: true,
        });
        let sas = "sv=2020-10-02&ss=b&srt=sco&sp=rl&sig=SUPERSECRETVALUE";
        let _g = EnvGuard::acquire(AZ_ENV_KEYS);
        _g.set(AZURE_ACCOUNT_ENV, "devstoreaccount1");
        _g.set(AZURE_ENDPOINT_ENV, &mock.base_url);
        _g.set(AZURE_SAS_ENV, sas);
        _g.set(AZURE_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let mut f = open_azure_range("az://ctr/obj.bin").unwrap();
        let mut got = Vec::new();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert!(
            mock.saw_sas.load(Ordering::SeqCst) >= 1,
            "SAS must be query-appended"
        );
        assert_eq!(
            mock.auth_headers.load(Ordering::SeqCst),
            0,
            "SAS must not send SharedKey Authorization"
        );
        let log = mock.log.lock().unwrap();
        let joined = log.join("\n");
        assert!(
            !joined.contains("SUPERSECRETVALUE") || joined.contains("sig="),
            "request log may include query; Debug of auth must not: {joined}"
        );
        let auth = resolve_auth().unwrap();
        let d = format!("{auth:?}");
        assert!(!d.contains("SUPERSECRETVALUE"), "SAS leaked in Debug: {d}");
    }

    #[test]
    fn imds_json_token() {
        let body = r#"{"access_token":"eyJhbGciOi.imds-msi-token","expires_in":"3600","token_type":"Bearer"}"#;
        let mock = MockAzure::spawn(MockMode::Imds { body: body.into() });
        let _g = EnvGuard::acquire(AZ_ENV_KEYS);
        _g.set(AZURE_ACCOUNT_ENV, "acct");
        _g.set(AZURE_IMDS_BASE_ENV, &mock.base_url);
        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source(), CredSource::Imds);
        let d = format!("{auth:?}");
        assert!(!d.contains("imds-msi-token"), "token leaked: {d}");
        assert!(mock.gets.load(Ordering::SeqCst) >= 1);
        let before = mock.gets.load(Ordering::SeqCst);
        let _ = resolve_auth().unwrap();
        assert_eq!(mock.gets.load(Ordering::SeqCst), before);
    }

    #[test]
    fn anonymous_range_get() {
        let body: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        let mock = MockAzure::spawn(MockMode::Object {
            body: body.clone(),
            require_auth: false,
        });
        let _g = EnvGuard::acquire(AZ_ENV_KEYS);
        _g.set(AZURE_ANON_ENV, "1");
        _g.set(AZURE_ACCOUNT_ENV, "pub");
        _g.set(AZURE_ENDPOINT_ENV, &mock.base_url);
        _g.set(AZURE_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let mut f = open_azure_range("az://ctr/obj.bin").unwrap();
        let mut got = vec![0u8; 16];
        f.read_exact(&mut got).unwrap();
        assert_eq!(got, &body[..16]);
        assert_eq!(mock.auth_headers.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn anonymous_fetch_azure_to_temp() {
        let payload = b"azure-index-sibling-bytes".to_vec();
        let mock = MockAzure::spawn(MockMode::Object {
            body: payload.clone(),
            require_auth: false,
        });
        let _g = EnvGuard::acquire(AZ_ENV_KEYS);
        _g.set(AZURE_ANON_ENV, "1");
        _g.set(AZURE_ACCOUNT_ENV, "pub");
        _g.set(AZURE_ENDPOINT_ENV, &mock.base_url);
        _g.set(AZURE_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let (mut tmp, size) = fetch_azure_to_temp("az://ctr/obj.bin").unwrap();
        assert_eq!(size, payload.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    const PAGE1: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults>
  <Blobs>
    <Blob><Name>prefix/a.tar</Name><Properties><Content-Length>11</Content-Length></Properties></Blob>
  </Blobs>
  <NextMarker>page-2</NextMarker>
</EnumerationResults>"#;

    const PAGE2: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults>
  <Blobs>
    <Blob><Name>prefix/b.bin</Name><Properties><Content-Length>7</Content-Length></Properties></Blob>
    <BlobPrefix><Name>prefix/sub/</Name></BlobPrefix>
  </Blobs>
  <NextMarker></NextMarker>
</EnumerationResults>"#;

    #[test]
    fn two_page_list_follows_next_marker() {
        let mock = MockAzure::spawn(MockMode::List {
            page1: PAGE1.into(),
            page2: PAGE2.into(),
            file_body: b"hello-world".to_vec(),
        });
        let _g = EnvGuard::acquire(AZ_ENV_KEYS);
        _g.set(AZURE_ANON_ENV, "1");
        _g.set(AZURE_ACCOUNT_ENV, "acct");
        _g.set(AZURE_ENDPOINT_ENV, &mock.base_url);
        _g.set(AZURE_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let loc = AzureLocation {
            container: "ctr".into(),
            blob: "prefix/".into(),
        };
        let ents = list_azure_prefix(&loc).unwrap();
        assert!(
            ents.iter().any(|e| e.name == "a.tar" && e.size == 11),
            "{ents:?}"
        );
        assert!(
            ents.iter().any(|e| e.name == "b.bin" && e.size == 7),
            "page 2 missing: {ents:?}"
        );
        assert!(ents.iter().any(|e| e.name == "sub" && e.is_dir));
        assert!(mock.list_gets.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn open_azure_folder_none_if_not_dir() {
        let xml = r#"<EnumerationResults>
  <Blobs>
    <Blob><Name>prefix/a.tar</Name><Properties><Content-Length>11</Content-Length></Properties></Blob>
  </Blobs>
</EnumerationResults>"#;
        let mock = MockAzure::spawn(MockMode::List {
            page1: xml.into(),
            page2: xml.into(),
            file_body: b"hello-world".to_vec(),
        });
        let _g = EnvGuard::acquire(AZ_ENV_KEYS);
        _g.set(AZURE_ANON_ENV, "1");
        _g.set(AZURE_ACCOUNT_ENV, "acct");
        _g.set(AZURE_ENDPOINT_ENV, &mock.base_url);
        _g.set(AZURE_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let none = open_azure_folder("az://ctr/prefix/a.tar").unwrap();
        assert!(none.is_none(), "exact blob is not a folder");
        let some = open_azure_folder("az://ctr/prefix/")
            .unwrap()
            .expect("trailing slash is a folder");
        let dents = some.list_dirents("/").expect("dirents");
        assert!(dents.iter().any(|d| d.name == "a.tar"));
    }

    #[test]
    fn file_open_errors_on_missing_blob() {
        let mock = MockAzure::spawn(MockMode::NotFound);
        let _g = EnvGuard::acquire(AZ_ENV_KEYS);
        _g.set(AZURE_ANON_ENV, "1");
        _g.set(AZURE_ACCOUNT_ENV, "acct");
        _g.set(AZURE_ENDPOINT_ENV, &mock.base_url);
        _g.set(AZURE_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let err = open_azure_range("az://ctr/missing.bin")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("404") || err.contains("BlobNotFound") || err.contains("GetBlob"),
            "{err}"
        );
    }

    #[test]
    fn parse_list_blobs_skips_blobprefix_as_blob() {
        let page = parse_list_blobs_xml(PAGE2);
        assert_eq!(page.blobs.len(), 1);
        assert_eq!(page.blobs[0].name, "prefix/b.bin");
        assert_eq!(page.prefixes, vec!["prefix/sub/".to_string()]);
        assert!(page.next_marker.is_none());
    }

    #[test]
    fn shared_key_string_includes_range_and_version() {
        let sts = shared_key_string_to_sign(
            Some("bytes=0-0"),
            "Fri, 26 Jun 2015 23:39:38 GMT",
            "/acct/ctr/blob",
        );
        assert!(sts.starts_with("GET\n"));
        assert!(sts.contains("bytes=0-0"));
        assert!(sts.contains("x-ms-version:2020-10-02"));
        assert!(sts.contains("/acct/ctr/blob"));
        assert!(!sts.contains("SECRET"));
    }

    #[test]
    fn base64_roundtrip_account_key() {
        let raw = b"azure-account-key-material!!";
        let enc = base64_encode(raw);
        assert_eq!(base64_decode(&enc).unwrap(), raw);
    }
}
