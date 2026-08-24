//! GCS `gs://bucket/object` Range GET (XML path-style) and prefix listing (JSON).
//!
//! # File wire
//!
//! XML API path-style GET: `https://storage.googleapis.com/{bucket}/{object}`
//! with `Range`. Object names percent-encode each path segment (`/` stays).
//! JSON `alt=media` is **not** the file MVP.
//!
//! # List wire
//!
//! JSON `GET https://storage.googleapis.com/storage/v1/b/{bucket}/o?prefix=&delimiter=/&pageToken=`
//! (Bearer). Loop `nextPageToken`. Cap [`GCS_LIST_KEY_CAP`] then error (not silent
//! truncate).
//!
//! # Auth order
//!
//! 1. `CLOUDSDK_AUTH_ACCESS_TOKEN` / `GOOGLE_OAUTH_ACCESS_TOKEN` Bearer
//! 2. `GOOGLE_APPLICATION_CREDENTIALS` service-account JSON (RS256 JWT via
//!    `jsonwebtoken` → oauth2 token, cached until expiry−120s)
//! 3. GCE/GKE IMDS `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`
//!    with `Metadata-Flavor: Google` (override [`GCS_IMDS_BASE_ENV`] for tests)
//! 4. Anonymous GET if `RATARMOUNT_GCS_ANONYMOUS=1` / `CLOUDSDK_ANONYMOUS=1`
//!
//! HMAC `GOOGLE_HMAC_KEY`/`GOOGLE_HMAC_SECRET` (GOOG1) is residual.
//!
//! Factory `gs://` dispatch is a later PR. R2/MinIO remain S3 (`AWS_ENDPOINT_URL`).

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::debug;
use ratarmount_core::{ArchiveRead, MountSource};
use url::Url;

use crate::folder::{RemoteDirent, RemoteFolderMountSource, RemoteListing};
use crate::{parse_content_range_total, RemoteError, Result, USER_AGENT};

/// Objects larger than this prefer live Range (1 MiB), matching S3.
pub const DEFAULT_GCS_RANGE_THRESHOLD: u64 = 1024 * 1024;

/// Hard cap on listed objects + prefixes (not silent truncate).
pub const GCS_LIST_KEY_CAP: usize = 100_000;
/// Hard cap on JSON list pages.
pub const GCS_LIST_PAGE_CAP: usize = 10_000;

/// Env: GCE metadata base override (tests).
pub const GCS_IMDS_BASE_ENV: &str = "RATARMOUNT_GCS_IMDS_BASE";
/// Env: XML/JSON API base override (tests / private endpoints).
pub const GCS_ENDPOINT_ENV: &str = "RATARMOUNT_GCS_ENDPOINT";

const DEFAULT_GCS_HOST: &str = "storage.googleapis.com";
const DEFAULT_IMDS_BASE: &str = "http://169.254.169.254";
const GCS_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const CREDS_EXPIRY_SKEW: Duration = Duration::from_secs(120);
const IMDS_TIMEOUT: Duration = Duration::from_secs(2);

/// Parsed `gs://bucket/object`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsLocation {
    pub bucket: String,
    pub object: String,
}

/// Parse `gs://bucket/object/with/slashes`. Object is required for file open.
pub fn parse_gcs_url(url_str: &str) -> Result<GcsLocation> {
    let loc = parse_gcs_url_allow_prefix(url_str)?;
    if loc.object.is_empty() {
        return Err(RemoteError::Url("gs URL missing object name".into()));
    }
    Ok(loc)
}

/// Like [`parse_gcs_url`], but an empty object is the bucket root (prefix folder).
pub fn parse_gcs_url_allow_prefix(url_str: &str) -> Result<GcsLocation> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    if url.scheme() != "gs" {
        return Err(RemoteError::UnsupportedScheme(url.scheme().to_string()));
    }
    let bucket = url
        .host_str()
        .ok_or_else(|| RemoteError::Url("gs URL missing bucket (gs://bucket/object)".into()))?
        .to_string();
    if bucket.is_empty() {
        return Err(RemoteError::Url(
            "gs URL missing bucket (gs://bucket/object)".into(),
        ));
    }
    let object = url.path().trim_start_matches('/').to_string();
    Ok(GcsLocation { bucket, object })
}

fn gcs_err(msg: impl Into<String>) -> RemoteError {
    RemoteError::Io(io::Error::other(format!("gcs: {}", msg.into())))
}

fn gcs_auth_err(msg: impl Into<String>) -> RemoteError {
    RemoteError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("gcs: {}", msg.into()),
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
    env_truthy("RATARMOUNT_GCS_ANONYMOUS") || env_truthy("CLOUDSDK_ANONYMOUS")
}

fn imds_base() -> String {
    non_empty_env(GCS_IMDS_BASE_ENV)
        .unwrap_or_else(|| DEFAULT_IMDS_BASE.into())
        .trim_end_matches('/')
        .to_string()
}

fn api_endpoint() -> String {
    non_empty_env(GCS_ENDPOINT_ENV)
        .unwrap_or_else(|| format!("https://{DEFAULT_GCS_HOST}"))
        .trim_end_matches('/')
        .to_string()
}

/// Minimal path-segment encode (RFC 3986 unreserved).
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

fn encode_object_path(object: &str) -> String {
    object
        .split('/')
        .map(urlencoding_encode)
        .collect::<Vec<_>>()
        .join("/")
}

/// XML path-style object URL (not JSON `alt=media`).
fn gcs_xml_object_url(loc: &GcsLocation) -> String {
    format!(
        "{}/{}/{}",
        api_endpoint(),
        loc.bucket,
        encode_object_path(&loc.object)
    )
}

fn gcs_list_url(bucket: &str, prefix: &str, page_token: Option<&str>) -> String {
    let mut url = format!(
        "{}/storage/v1/b/{}/o?delimiter=%2F&prefix={}",
        api_endpoint(),
        urlencoding_encode(bucket),
        urlencoding_encode(prefix)
    );
    if let Some(tok) = page_token.filter(|t| !t.is_empty()) {
        url.push_str("&pageToken=");
        url.push_str(&urlencoding_encode(tok));
    }
    url
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredSource {
    EnvToken,
    Adc,
    Imds,
    Anonymous,
}

struct CachedToken {
    access_token: String,
    expiration: chrono::DateTime<chrono::Utc>,
}

static TOKEN_CACHE: Mutex<Option<(CredSource, CachedToken)>> = Mutex::new(None);

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

fn take_cached_token() -> Option<(CredSource, String)> {
    let guard = TOKEN_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .filter(|(_, t)| token_still_valid(t))
        .map(|(src, t)| (*src, t.access_token.clone()))
}

fn store_cached_token(source: CredSource, token: CachedToken) {
    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        *guard = Some((source, token));
    }
}

struct ResolvedAuth {
    source: CredSource,
    /// `None` = anonymous (no Authorization).
    bearer: Option<String>,
}

impl std::fmt::Debug for ResolvedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedAuth")
            .field("source", &self.source)
            .field("bearer", &self.bearer.as_ref().map(|_| "***"))
            .finish()
    }
}

fn parse_oauth_token_json(body: &str) -> Result<CachedToken> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| gcs_err(format!("failed to parse OAuth token JSON: {e}")))?;
    let access_token = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| gcs_err("OAuth token JSON missing access_token"))?
        .to_string();
    let expires_in = v
        .get("expires_in")
        .and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_i64().and_then(|n| u64::try_from(n).ok()))
        })
        .unwrap_or(3600);
    let expiration = chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64);
    Ok(CachedToken {
        access_token,
        expiration,
    })
}

fn load_env_access_token() -> Option<String> {
    non_empty_env("CLOUDSDK_AUTH_ACCESS_TOKEN")
        .or_else(|| non_empty_env("GOOGLE_OAUTH_ACCESS_TOKEN"))
}

fn fetch_imds_token() -> Result<CachedToken> {
    let url = format!(
        "{}/computeMetadata/v1/instance/service-accounts/default/token",
        imds_base()
    );
    debug!("gcs: fetching IMDS token");
    let resp = ureq::get(&url)
        .set("User-Agent", USER_AGENT)
        .set("Metadata-Flavor", "Google")
        .timeout(IMDS_TIMEOUT)
        .call()
        .map_err(|e| gcs_err(format!("IMDS GET {url}: {e}")))?;
    let status = resp.status();
    let body = resp.into_string().unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(gcs_err(format!("IMDS GET {url}: status {status}: {body}")));
    }
    parse_oauth_token_json(&body)
}

fn exchange_jwt_for_token(sa: &serde_json::Value) -> Result<CachedToken> {
    let client_email = sa
        .get("client_email")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| gcs_err("ADC JSON missing client_email"))?;
    let private_key = sa
        .get("private_key")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| gcs_err("ADC JSON missing private_key"))?;
    let token_uri = sa
        .get("token_uri")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_TOKEN_URI);

    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client_email,
        "scope": GCS_SCOPE,
        "aud": token_uri,
        "iat": now,
        "exp": now + 3600,
    });
    let header = Header::new(Algorithm::RS256);
    let key = EncodingKey::from_rsa_pem(private_key.as_bytes())
        .map_err(|e| gcs_err(format!("ADC RSA private key: {e}")))?;
    let jwt =
        encode(&header, &claims, &key).map_err(|e| gcs_err(format!("ADC JWT encode: {e}")))?;

    let body = format!(
        "grant_type={}&assertion={}",
        urlencoding_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        urlencoding_encode(&jwt)
    );
    debug!("gcs: exchanging ADC JWT at {token_uri}");
    let resp = ureq::post(token_uri)
        .set("User-Agent", USER_AGENT)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration::from_secs(15))
        .send_string(&body)
        .map_err(|e| gcs_err(format!("ADC token POST {token_uri}: {e}")))?;
    let status = resp.status();
    let text = resp.into_string().unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(gcs_auth_err(format!(
            "ADC token POST {token_uri}: status {status}"
        )));
    }
    parse_oauth_token_json(&text)
}

fn fetch_adc_token() -> Result<CachedToken> {
    let path = non_empty_env("GOOGLE_APPLICATION_CREDENTIALS")
        .ok_or_else(|| gcs_err("GOOGLE_APPLICATION_CREDENTIALS unset"))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| gcs_err(format!("reading ADC file {path}: {e}")))?;
    let sa: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| gcs_err(format!("parsing ADC JSON {path}: {e}")))?;
    exchange_jwt_for_token(&sa)
}

fn resolve_auth() -> Result<ResolvedAuth> {
    if let Some(tok) = load_env_access_token() {
        return Ok(ResolvedAuth {
            source: CredSource::EnvToken,
            bearer: Some(tok),
        });
    }
    if let Some((source, tok)) = take_cached_token() {
        debug!("gcs: using cached {source:?} token");
        return Ok(ResolvedAuth {
            source,
            bearer: Some(tok),
        });
    }

    let mut tried: Vec<&str> = vec!["env CLOUDSDK_AUTH_ACCESS_TOKEN / GOOGLE_OAUTH_ACCESS_TOKEN"];
    let mut role_errors: Vec<String> = Vec::new();

    tried.push("GOOGLE_APPLICATION_CREDENTIALS ADC");
    if non_empty_env("GOOGLE_APPLICATION_CREDENTIALS").is_some() {
        match fetch_adc_token() {
            Ok(tok) => {
                let bearer = tok.access_token.clone();
                store_cached_token(CredSource::Adc, tok);
                return Ok(ResolvedAuth {
                    source: CredSource::Adc,
                    bearer: Some(bearer),
                });
            }
            Err(e) => {
                debug!("gcs: ADC failed: {e}");
                role_errors.push(format!("ADC: {e}"));
            }
        }
    }

    tried.push("GCE/GKE IMDS");
    match fetch_imds_token() {
        Ok(tok) => {
            let bearer = tok.access_token.clone();
            store_cached_token(CredSource::Imds, tok);
            return Ok(ResolvedAuth {
                source: CredSource::Imds,
                bearer: Some(bearer),
            });
        }
        Err(e) => {
            debug!("gcs: IMDS failed: {e}");
            role_errors.push(format!("IMDS: {e}"));
        }
    }

    if anonymous_enabled() {
        debug!("gcs: using anonymous access");
        return Ok(ResolvedAuth {
            source: CredSource::Anonymous,
            bearer: None,
        });
    }

    let mut msg = format!(
        "no GCS credentials found for gs://; tried: {}; \
         set CLOUDSDK_AUTH_ACCESS_TOKEN / GOOGLE_OAUTH_ACCESS_TOKEN, \
         GOOGLE_APPLICATION_CREDENTIALS (ADC), run on GCE/GKE with a service account, \
         or set RATARMOUNT_GCS_ANONYMOUS=1 / CLOUDSDK_ANONYMOUS=1 for public buckets",
        tried.join(", ")
    );
    if !role_errors.is_empty() {
        msg.push_str(&format!(" (role errors: {})", role_errors.join("; ")));
    }
    Err(gcs_err(msg))
}

fn apply_gcs_auth(mut req: ureq::Request, auth: &ResolvedAuth) -> ureq::Request {
    req = req.set("User-Agent", USER_AGENT);
    if let Some(tok) = &auth.bearer {
        req = req.set("Authorization", &format!("Bearer {tok}"));
    }
    req
}

fn gcs_status_error(source: CredSource, status: u16, loc: &GcsLocation, body: &str) -> RemoteError {
    let kind = if source == CredSource::Anonymous {
        "anonymous GetObject"
    } else {
        "GetObject"
    };
    let msg = format!(
        "{kind} HTTP {status} for gs://{}/{}: {body}",
        loc.bucket, loc.object
    );
    if status == 401 || status == 403 {
        gcs_auth_err(msg)
    } else {
        gcs_err(msg)
    }
}

fn gcs_get_object(
    loc: &GcsLocation,
    range: Option<(u64, u64)>,
) -> Result<(CredSource, ureq::Response)> {
    let auth = resolve_auth()?;
    let url = gcs_xml_object_url(loc);
    let range_value = range.map(|(start, end)| format!("bytes={start}-{end}"));
    debug!(
        "gcs GET xml {url} (auth={:?}, range={:?})",
        auth.source, range_value
    );
    let mut req = apply_gcs_auth(ureq::get(&url), &auth);
    if let Some(ref r) = range_value {
        req = req.set("Range", r);
    }
    let resp = req
        .call()
        .map_err(|e| gcs_err(format!("GetObject gs://{}/{}: {e}", loc.bucket, loc.object)))?;
    Ok((auth.source, resp))
}

enum GcsProbe {
    RangesOk(u64),
    FullBody(Vec<u8>),
    Unusable,
}

fn probe_gcs_object(loc: &GcsLocation) -> Result<GcsProbe> {
    let (source, resp) = match gcs_get_object(loc, Some((0, 0))) {
        Ok(v) => v,
        Err(e) => {
            debug!("gcs probe request failed: {e}");
            return Ok(GcsProbe::Unusable);
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
            return Ok(GcsProbe::RangesOk(total));
        }
        let _ = resp.into_string();
        return Ok(GcsProbe::Unusable);
    }
    if (200..300).contains(&status) {
        if content_length.is_some_and(|n| n > DEFAULT_GCS_RANGE_THRESHOLD) {
            let mut reader = resp.into_reader();
            let _ = io::copy(&mut reader, &mut io::sink());
            return Ok(GcsProbe::Unusable);
        }
        let mut reader = resp.into_reader();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        return Ok(GcsProbe::FullBody(bytes));
    }
    debug!(
        "gcs probe gs://{}/{} -> HTTP {status} (auth={source:?})",
        loc.bucket, loc.object
    );
    let _ = resp.into_string();
    Ok(GcsProbe::Unusable)
}

fn fetch_gcs_full_get(loc: &GcsLocation) -> Result<Vec<u8>> {
    let (source, resp) = gcs_get_object(loc, None)?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(gcs_status_error(source, status, loc, &body));
    }
    let mut reader = resp.into_reader();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Seekable GCS reader using live Range GETs on the XML path-style API.
pub struct GcsRangeFile {
    loc: GcsLocation,
    size: u64,
    pos: u64,
    buffered: Option<Vec<u8>>,
}

impl std::fmt::Debug for GcsRangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsRangeFile")
            .field("bucket", &self.loc.bucket)
            .field("object", &self.loc.object)
            .field("size", &self.size)
            .field("pos", &self.pos)
            .field("uses_ranges", &self.uses_ranges())
            .finish()
    }
}

impl GcsRangeFile {
    pub fn open(url_str: &str) -> Result<Self> {
        let loc = parse_gcs_url(url_str)?;
        Self::open_location(&loc)
    }

    pub fn open_location(loc: &GcsLocation) -> Result<Self> {
        match probe_gcs_object(loc) {
            Ok(GcsProbe::RangesOk(size)) => Ok(Self::range_backed(loc.clone(), size)),
            Ok(GcsProbe::FullBody(bytes)) => {
                let size = bytes.len() as u64;
                Ok(Self {
                    loc: loc.clone(),
                    size,
                    pos: 0,
                    buffered: Some(bytes),
                })
            }
            Ok(GcsProbe::Unusable) | Err(_) => {
                let buf = fetch_gcs_full_get(loc)?;
                Ok(Self {
                    loc: loc.clone(),
                    size: buf.len() as u64,
                    pos: 0,
                    buffered: Some(buf),
                })
            }
        }
    }

    pub fn range_backed(loc: GcsLocation, size: u64) -> Self {
        Self {
            loc,
            size,
            pos: 0,
            buffered: None,
        }
    }

    pub fn location(&self) -> &GcsLocation {
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

/// Open a seekable GCS reader using live Range GET when possible.
pub fn open_gcs_range(url_str: &str) -> Result<GcsRangeFile> {
    GcsRangeFile::open(url_str)
}

impl Read for GcsRangeFile {
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
        let (source, resp) = gcs_get_object(&self.loc, Some((range_start, range_end)))
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
            gcs_status_error(source, status, &self.loc, &body).to_string(),
        ))
    }
}

impl Seek for GcsRangeFile {
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
// JSON listing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsListEntry {
    pub name: String,
    pub key: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GcsListedObject {
    name: String,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GcsListPage {
    objects: Vec<GcsListedObject>,
    prefixes: Vec<String>,
    next_page_token: Option<String>,
}

fn gcs_list_prefix(object: &str) -> String {
    if object.is_empty() || object.ends_with('/') {
        object.to_string()
    } else {
        format!("{object}/")
    }
}

fn json_u64(v: &serde_json::Value) -> u64 {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

fn parse_gcs_list_json(text: &str) -> Result<GcsListPage> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| gcs_err(format!("list JSON: {e}")))?;
    let mut objects = Vec::new();
    if let Some(items) = v.get("items").and_then(|x| x.as_array()) {
        for item in items {
            let Some(name) = item.get("name").and_then(|x| x.as_str()) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let size = item.get("size").map(json_u64).unwrap_or(0);
            objects.push(GcsListedObject {
                name: name.to_string(),
                size,
            });
        }
    }
    let mut prefixes = Vec::new();
    if let Some(arr) = v.get("prefixes").and_then(|x| x.as_array()) {
        for p in arr {
            if let Some(s) = p.as_str().filter(|s| !s.is_empty()) {
                prefixes.push(s.to_string());
            }
        }
    }
    let next_page_token = v
        .get("nextPageToken")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(GcsListPage {
        objects,
        prefixes,
        next_page_token,
    })
}

fn gcs_list_page(bucket: &str, prefix: &str, page_token: Option<&str>) -> Result<GcsListPage> {
    let auth = resolve_auth()?;
    let url = gcs_list_url(bucket, prefix, page_token);
    debug!("gcs LIST {url} (auth={:?})", auth.source);
    let req = apply_gcs_auth(ureq::get(&url), &auth);
    let resp = req
        .call()
        .map_err(|e| gcs_err(format!("list gs://{bucket}/{prefix}: {e}")))?;
    let status = resp.status();
    let body = resp.into_string().unwrap_or_default();
    if !(200..300).contains(&status) {
        let msg = format!("list HTTP {status} for gs://{bucket}/{prefix}: {body}");
        return Err(if status == 401 || status == 403 {
            gcs_auth_err(msg)
        } else {
            gcs_err(msg)
        });
    }
    parse_gcs_list_json(&body)
}

fn gcs_child_entry(prefix: &str, key: &str, size: u64, is_dir: bool) -> Option<GcsListEntry> {
    let rest = if prefix.is_empty() {
        key
    } else {
        key.strip_prefix(prefix)?
    };
    let name = rest.trim_end_matches('/');
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some(GcsListEntry {
        name: name.to_string(),
        key: key.to_string(),
        is_dir,
        size: if is_dir { 0 } else { size },
    })
}

/// List immediate children of a GCS prefix (`delimiter=/`), following `pageToken`.
pub fn list_gcs_prefix(loc: &GcsLocation) -> Result<Vec<GcsListEntry>> {
    list_gcs_prefix_capped(loc, GCS_LIST_KEY_CAP)
}

pub fn list_gcs_prefix_capped(loc: &GcsLocation, cap: usize) -> Result<Vec<GcsListEntry>> {
    let prefix = gcs_list_prefix(&loc.object);
    let mut token: Option<String> = None;
    let mut out: Vec<GcsListEntry> = Vec::new();
    let mut total = 0usize;
    let mut pages = 0usize;
    let page_cap = cap.saturating_add(1).min(GCS_LIST_PAGE_CAP);
    loop {
        pages = pages.saturating_add(1);
        if pages > page_cap {
            return Err(gcs_err(format!(
                "gcs prefix too large (>{cap} keys) for gs://{}/{}; listing is not silently truncated",
                loc.bucket, loc.object
            )));
        }
        let page = gcs_list_page(&loc.bucket, &prefix, token.as_deref())?;
        let n = page.objects.len() + page.prefixes.len();
        if page.next_page_token.is_some() && n == 0 {
            return Err(gcs_err(
                "truncated GCS list page with no keys; listing is not complete",
            ));
        }
        total = total.saturating_add(n);
        if total > cap {
            return Err(gcs_err(format!(
                "gcs prefix too large (>{cap} keys) for gs://{}/{}; listing is not silently truncated",
                loc.bucket, loc.object
            )));
        }
        for obj in &page.objects {
            if let Some(ent) = gcs_child_entry(&prefix, &obj.name, obj.size, false) {
                out.push(ent);
            }
        }
        for cp in &page.prefixes {
            if let Some(ent) = gcs_child_entry(&prefix, cp, 0, true) {
                out.push(ent);
            }
        }
        let Some(next) = page
            .next_page_token
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            break;
        };
        if token.as_deref() == Some(next) {
            return Err(gcs_err(
                "truncated GCS list page repeated nextPageToken; listing is not complete",
            ));
        }
        token = Some(next.to_string());
    }
    Ok(out)
}

/// Directory probe: empty object, trailing `/`, or children exist without an exact object.
pub fn gcs_location_is_dir(loc: &GcsLocation) -> Result<bool> {
    if loc.object.is_empty() || loc.object.ends_with('/') {
        return Ok(true);
    }
    let page = match gcs_list_page(&loc.bucket, &loc.object, None) {
        Ok(p) => p,
        Err(e) => {
            debug!(
                "gcs list probe gs://{}/{} failed ({e}); treating as object",
                loc.bucket, loc.object
            );
            return Ok(false);
        }
    };
    let has_exact = page.objects.iter().any(|o| o.name == loc.object);
    if has_exact {
        return Ok(false);
    }
    let child_prefix = gcs_list_prefix(&loc.object);
    let has_child_prefix = page
        .prefixes
        .iter()
        .any(|p| p == &child_prefix || p.starts_with(&child_prefix));
    let has_child_key = page
        .objects
        .iter()
        .any(|o| o.name.starts_with(&child_prefix) && o.name != loc.object);
    Ok(has_child_prefix || has_child_key)
}

/// Prefix listing backend for [`RemoteFolderMountSource`].
pub struct GcsListing {
    pub bucket: String,
}

impl GcsListing {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
        }
    }
}

impl RemoteListing for GcsListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        let loc = GcsLocation {
            bucket: self.bucket.clone(),
            object: remote_path.trim_start_matches('/').to_string(),
        };
        Ok(list_gcs_prefix(&loc)?
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
        gcs_location_is_dir(&GcsLocation {
            bucket: self.bucket.clone(),
            object: remote_path.trim_start_matches('/').to_string(),
        })
    }

    fn open_range(&self, remote_path: &str, size: u64) -> Result<Box<dyn ArchiveRead>> {
        let loc = GcsLocation {
            bucket: self.bucket.clone(),
            object: remote_path.to_string(),
        };
        if size > 0 {
            Ok(Box::new(GcsRangeFile::range_backed(loc, size)))
        } else {
            Ok(Box::new(GcsRangeFile::open_location(&loc)?))
        }
    }
}

/// Open `gs://bucket[/prefix]` as a folder. `Ok(None)` if it is not a directory.
pub fn open_gcs_folder(s: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_gcs_url_allow_prefix(s)?;
    if !gcs_location_is_dir(&loc)? {
        return Ok(None);
    }
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        loc.object,
        GcsListing::new(loc.bucket),
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

    const GCS_ENV_KEYS: &[&str] = &[
        "CLOUDSDK_AUTH_ACCESS_TOKEN",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "RATARMOUNT_GCS_ANONYMOUS",
        "CLOUDSDK_ANONYMOUS",
        GCS_IMDS_BASE_ENV,
        GCS_ENDPOINT_ENV,
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

    struct MockGcs {
        base_url: String,
        log: Arc<StdMutex<Vec<String>>>,
        gets: Arc<AtomicUsize>,
        posts: Arc<AtomicUsize>,
        auth_headers: Arc<AtomicUsize>,
        range_headers: Arc<AtomicUsize>,
        list_gets: Arc<AtomicUsize>,
        _join: Option<thread::JoinHandle<()>>,
    }

    enum MockMode {
        Object {
            body: Vec<u8>,
            require_auth: bool,
            honor_range: bool,
        },
        List {
            page1: String,
            page2: String,
            file_body: Vec<u8>,
        },
        Imds {
            body: String,
        },
        Oauth {
            body: String,
        },
        NotFound,
    }

    impl MockGcs {
        fn spawn(mode: MockMode) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let log = Arc::new(StdMutex::new(Vec::new()));
            let gets = Arc::new(AtomicUsize::new(0));
            let posts = Arc::new(AtomicUsize::new(0));
            let auth_headers = Arc::new(AtomicUsize::new(0));
            let range_headers = Arc::new(AtomicUsize::new(0));
            let list_gets = Arc::new(AtomicUsize::new(0));
            let log_c = Arc::clone(&log);
            let gets_c = Arc::clone(&gets);
            let posts_c = Arc::clone(&posts);
            let auth_c = Arc::clone(&auth_headers);
            let range_c = Arc::clone(&range_headers);
            let list_c = Arc::clone(&list_gets);
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
                    let mut meta_flavor: Option<String> = None;
                    let mut content_len: usize = 0;
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
                        if lower.starts_with("metadata-flavor:") {
                            if let Some((_, v)) = line.split_once(':') {
                                meta_flavor = Some(v.trim().to_string());
                            }
                        }
                        if let Some(rest) = lower.strip_prefix("content-length:") {
                            content_len = rest.trim().parse().unwrap_or(0);
                        }
                    }
                    if content_len > 0 {
                        let mut dump = vec![0u8; content_len];
                        let _ = reader.read_exact(&mut dump);
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
                    let is_post = request_line.starts_with("POST ");
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    match &mode {
                        MockMode::Object {
                            body,
                            require_auth,
                            honor_range,
                        } => {
                            if !is_get {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                continue;
                            }
                            if *require_auth && !has_auth {
                                let msg = b"Unauthorized";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    msg.len()
                                );
                                let _ = stream.write_all(msg);
                                continue;
                            }
                            gets_c.fetch_add(1, Ordering::SeqCst);
                            if *honor_range {
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
                            if path.contains("/storage/v1/") {
                                list_c.fetch_add(1, Ordering::SeqCst);
                                gets_c.fetch_add(1, Ordering::SeqCst);
                                let body = if path.contains("pageToken=") {
                                    page2.as_bytes()
                                } else {
                                    page1.as_bytes()
                                };
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
                            if meta_flavor.as_deref() != Some("Google") {
                                let msg = b"Metadata-Flavor required";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
                        MockMode::Oauth { body } => {
                            if !is_post {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                continue;
                            }
                            posts_c.fetch_add(1, Ordering::SeqCst);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                        }
                        MockMode::NotFound => {
                            gets_c.fetch_add(1, Ordering::SeqCst);
                            let msg = b"NoSuchKey";
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
                posts,
                auth_headers,
                range_headers,
                list_gets,
                _join: Some(join),
            }
        }
    }

    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDaPdrZ+9GN0dGk
ydGbPeXiYFNZkTnvBxzyHtCl8HbkSkY63xR+M8yPaBdf0TxIhO0qt07ThwVUO8zp
Ja2DYA/dmWQRtUkOue1a2xfelHfKaxiMaNVUKGxaWtmGt44kQWR5Xqyr/zjQL+Re
1XdOwmLXE8klvb7agDSdvjLnYHEIbbXcSBkLg4YvNmDYkIplBkkma/3i/bQfNHL4
iVBKcDBa2Vch7PSpb6oXZB479Y7nDF46tba0uvEgJdSKjGPaZH/q7RFBDd4mM0bg
CN/XPgBpNhUFOfdBK06Ur3AaEv1gpUfbt1TJxIgTdhZ9JlV18h7lYmudIvIQ8FHM
/Oa/D8urAgMBAAECggEAQKVz74A1abIOTKbvrPGf5/eqmOx44cIUo+/W1GCvhx4t
QYEVG/ESFiS6T8q19bFSY4XbFrN3M6VnJGThyfmpmXW3e7tcgb03fuNJZchK163z
npvrHTvAJN+mcc5rj3fDYGRX97bpSFn3ZtQKvEy+ZIFa4xAaubSiYVuWzoz1zo3M
u8d3oC9BNyzS5lyTvd2a0Lb/VBe+uGokibr9H/vxahwLeaKzgZ0q/uDudH9T3D/1
GvquiJ1IzuLlsbDuFxfnfOqvOsfZ9i1HEOLlUQT78xr0IwLiSJrjMf6Er8pM0141
0AsX6qTjGkelVHL1T7qKmB0ogeZRBkbmaBZYs1lN6QKBgQD6pwqWIZWfSW6fF1Rj
k97/4OSSObxXiHseDpCl7HQo8IDp1igz5f4nzv5S0NrItykxycl9snfOwHlvh6nr
ePVechWJR+JCYvHBKVcysH/lhVJV3y7ZdrY/1PLbxm7wi4luahEGK1/fnVXpkEmn
0ZEztyiTXuwowGrHA03Bj9jMrQKBgQDe5cyE/R42x2xX4wbtaHGc0goTwVIZNs2g
jnWkFyfvwdXatoqs5k0QqaPLsIznPUZPH7TiE3KF3iC5FYXcTGn+Spe69iLhzHh0
0aK7l56kI8TYo730gkunJzS3sLcSJrWv4ANhuu66zWn9DhbtuNjI2/ftfJCNMz9W
qN1ofr7stwKBgQDHpspt725opGsy2bhkYOKd2pr2RnrZFmNK+7sIDyIvgfKNUAJR
5H7fYqd9e9LpUcvEVsDiGIgJ7ZJM3jjg0UZQ5np1EQcObhW3EKDeRWx6fAmrUMzW
dxKQIaUYniS8AcmEY4QP7/i7+2z1T/L7c5g/I0N0r4VYqHvk7aK/7T55OQKBgEJM
LaHcu7DlbhdSAox4xVo0qySnGqk/QLghx2HwNUO97sLoCqVUttVe78Y1FCPveMsu
Dho0WJryr979RNx6qggl3a2Ralyo+acdd36+oUQHE5SwV16zppboNWjxmfI/K0lN
oxPdiwZq9Lx9BVrd4TUVIFA1/bTR6mP3RCvBjz5PAoGABIXfm+1/2b0LcgIr5FV6
V6DhWILm4DvGGTwbT1OqXF0xoHVWOhBpgQo2C999QOX1p4qBl22wZDOloWHTn8T+
wFOFIyLdw0RYF+SyxtM3ZX8+LjO3CXoCP7UI3kjQCNEn7RGt5w7FSDcedlpwV+R3
c8kyOVCJusup7SdkiG+QF64=
-----END PRIVATE KEY-----
";

    #[test]
    fn parse_bucket_object() {
        let l = parse_gcs_url("gs://my-bucket/path/to/archive.tar.gz").unwrap();
        assert_eq!(l.bucket, "my-bucket");
        assert_eq!(l.object, "path/to/archive.tar.gz");
    }

    #[test]
    fn reject_missing_object() {
        assert!(parse_gcs_url("gs://only-bucket/").is_err());
        assert!(parse_gcs_url("gs://only-bucket").is_err());
    }

    #[test]
    fn parse_allow_prefix_empty() {
        let root = parse_gcs_url_allow_prefix("gs://only-bucket").unwrap();
        assert_eq!(root.bucket, "only-bucket");
        assert!(root.object.is_empty());
        let slash = parse_gcs_url_allow_prefix("gs://only-bucket/").unwrap();
        assert!(slash.object.is_empty());
        let pref = parse_gcs_url_allow_prefix("gs://b/prefix/").unwrap();
        assert_eq!(pref.object, "prefix/");
    }

    #[test]
    fn parse_gcs_list_json_two_kinds() {
        let json = r#"{
            "prefixes": ["prefix/sub/"],
            "items": [{"name": "prefix/a.tar", "size": "11"}],
            "nextPageToken": "page-2"
        }"#;
        let page = parse_gcs_list_json(json).unwrap();
        assert_eq!(page.next_page_token.as_deref(), Some("page-2"));
        assert_eq!(page.objects[0].name, "prefix/a.tar");
        assert_eq!(page.objects[0].size, 11);
        assert_eq!(page.prefixes, vec!["prefix/sub/".to_string()]);
    }

    #[test]
    fn gcs_range_file_live_reads_206() {
        let body: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let mock = MockGcs::spawn(MockMode::Object {
            body: body.clone(),
            require_auth: true,
            honor_range: true,
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("CLOUDSDK_AUTH_ACCESS_TOKEN", "ya29.test-token");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let mut f = open_gcs_range("gs://b/live.bin").unwrap();
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
            log.iter().any(|l| l == "Range: bytes=0-0"),
            "expected size probe, log={log:?}"
        );
    }

    #[test]
    fn anonymous_range_get_no_authorization() {
        let body: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let mock = MockGcs::spawn(MockMode::Object {
            body: body.clone(),
            require_auth: false,
            honor_range: true,
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("RATARMOUNT_GCS_ANONYMOUS", "1");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let mut f = open_gcs_range("gs://public/path/obj.bin").unwrap();
        let mut got = vec![0u8; 50];
        f.seek(SeekFrom::Start(100)).unwrap();
        f.read_exact(&mut got).unwrap();
        assert_eq!(got, &body[100..150]);
        assert_eq!(
            mock.auth_headers.load(Ordering::SeqCst),
            0,
            "anonymous Range must not send Authorization"
        );
    }

    #[test]
    fn imds_json_token() {
        let body = r#"{"access_token":"ya29.imds-token","expires_in":3600,"token_type":"Bearer"}"#;
        let mock = MockGcs::spawn(MockMode::Imds { body: body.into() });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set(GCS_IMDS_BASE_ENV, &mock.base_url);

        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source, CredSource::Imds);
        assert_eq!(auth.bearer.as_deref(), Some("ya29.imds-token"));
        assert!(mock.gets.load(Ordering::SeqCst) >= 1);
        let before = mock.gets.load(Ordering::SeqCst);
        let auth2 = resolve_auth().unwrap();
        assert_eq!(auth2.source, CredSource::Imds);
        assert_eq!(mock.gets.load(Ordering::SeqCst), before);
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("ya29.imds-token"), "token leaked: {dbg}");
    }

    #[test]
    fn adc_jwt_exchanges_at_token_uri() {
        let oauth = MockGcs::spawn(MockMode::Oauth {
            body: r#"{"access_token":"ya29.adc-token","expires_in":3600}"#.into(),
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sa = serde_json::json!({
            "type": "service_account",
            "client_email": "test@proj.iam.gserviceaccount.com",
            "private_key": TEST_RSA_PEM,
            "token_uri": format!("{}/token", oauth.base_url),
        });
        std::fs::write(tmp.path(), sa.to_string()).unwrap();
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set(
            "GOOGLE_APPLICATION_CREDENTIALS",
            tmp.path().to_str().unwrap(),
        );
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source, CredSource::Adc);
        assert_eq!(auth.bearer.as_deref(), Some("ya29.adc-token"));
        assert!(oauth.posts.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn missing_creds_lists_chain() {
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let err = resolve_auth().unwrap_err().to_string();
        assert!(
            err.contains("CLOUDSDK_AUTH_ACCESS_TOKEN") || err.contains("env"),
            "unexpected: {err}"
        );
        assert!(
            err.contains("IMDS") || err.contains("ADC"),
            "chain should list ADC/IMDS: {err}"
        );
        assert!(
            err.contains("RATARMOUNT_GCS_ANONYMOUS") || err.contains("CLOUDSDK_ANONYMOUS"),
            "should mention anonymous option: {err}"
        );
    }

    const PAGE1: &str = r#"{
        "items": [{"name": "prefix/a.tar", "size": "11"}],
        "nextPageToken": "page-2"
    }"#;
    const PAGE2: &str = r#"{
        "items": [{"name": "prefix/b.bin", "size": "7"}],
        "prefixes": ["prefix/sub/"]
    }"#;

    #[test]
    fn two_page_list_follows_page_token() {
        let file_body = b"hello-world".to_vec();
        let mock = MockGcs::spawn(MockMode::List {
            page1: PAGE1.into(),
            page2: PAGE2.into(),
            file_body: file_body.clone(),
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("RATARMOUNT_GCS_ANONYMOUS", "1");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let loc = GcsLocation {
            bucket: "bucket".into(),
            object: "prefix/".into(),
        };
        let ents = list_gcs_prefix(&loc).unwrap();
        assert!(
            ents.iter().any(|e| e.name == "a.tar" && e.size == 11),
            "page 1 missing: {ents:?}"
        );
        assert!(
            ents.iter().any(|e| e.name == "b.bin" && e.size == 7),
            "page 2 missing (truncated page treated as complete?): {ents:?}"
        );
        assert!(ents.iter().any(|e| e.name == "sub" && e.is_dir));
        assert!(mock.list_gets.load(Ordering::SeqCst) >= 2);
    }

    /// Regression: empty gs://bucket without trailing slash is a prefix folder
    /// when list returns children.
    #[test]
    fn empty_gs_bucket_without_trailing_slash_is_prefix_folder() {
        let page = r#"{"items":[{"name":"a.tar","size":"4"}],"prefixes":["sub/"]}"#;
        let mock = MockGcs::spawn(MockMode::List {
            page1: page.into(),
            page2: "{}".into(),
            file_body: b"data".to_vec(),
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("RATARMOUNT_GCS_ANONYMOUS", "1");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let ms = open_gcs_folder("gs://bucket")
            .unwrap()
            .expect("gs://bucket without slash is a prefix folder when children exist");
        let dents = ms.list_dirents("/").expect("dirents");
        assert!(
            dents.iter().any(|d| d.name == "a.tar" && d.size == 4),
            "{dents:?}"
        );
        assert!(dents.iter().any(|d| d.name == "sub"));
    }

    #[test]
    fn file_open_errors_on_missing_object() {
        assert!(parse_gcs_url("gs://bucket").is_err());
        let mock = MockGcs::spawn(MockMode::NotFound);
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("CLOUDSDK_AUTH_ACCESS_TOKEN", "tok");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let err = open_gcs_range("gs://bucket/missing.bin")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("404") || err.contains("NoSuchKey") || err.contains("GetObject"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn open_folder_none_for_exact_object() {
        let json = r#"{"items":[{"name":"prefix/a.tar","size":"11"}]}"#;
        let mock = MockGcs::spawn(MockMode::List {
            page1: json.into(),
            page2: "{}".into(),
            file_body: b"hello-world".to_vec(),
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("RATARMOUNT_GCS_ANONYMOUS", "1");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let none = open_gcs_folder("gs://bucket/prefix/a.tar").unwrap();
        assert!(none.is_none(), "exact object is not a folder");
    }
}
