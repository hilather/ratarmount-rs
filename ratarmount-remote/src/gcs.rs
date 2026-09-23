//! GCS `gs://bucket/object` Range GET (XML path-style), prefix listing, and
//! a single live-commit PUT (GOOG1 or bearer; no multipart).
//!
//! # File wire
//!
//! XML API path-style GET: `https://storage.googleapis.com/{bucket}/{object}`
//! with `Range`. Object names percent-encode each path segment (`/` stays).
//! JSON `alt=media` is **not** the file MVP. HMAC Range is sent unsigned.
//!
//! # List wire
//!
//! Bearer/ADC/IMDS: JSON
//! `GET https://storage.googleapis.com/storage/v1/b/{bucket}/o?prefix=&delimiter=/&pageToken=`
//! Loop `nextPageToken`. Cap [`GCS_LIST_KEY_CAP`] then error (not silent
//! truncate).
//!
//! HMAC GOOG1: XML ListBucket `GET …/{bucket}?delimiter=/&prefix=&marker=&max-keys=`
//! (query params stay on the wire **unsigned**; STS CanonicalizedResource is
//! `/{bucket}` only). Residual: GOOG4-HMAC-SHA256 if live keys reject V2.
//!
//! # Auth order
//!
//! 1. `CLOUDSDK_AUTH_ACCESS_TOKEN` / `GOOGLE_OAUTH_ACCESS_TOKEN` Bearer
//! 2. `GOOGLE_HMAC_KEY` + `GOOGLE_HMAC_SECRET` both non-empty → GOOG1 HMAC
//!    (**before** the ADC/IMDS token cache)
//! 3. `GOOGLE_APPLICATION_CREDENTIALS` service-account JSON (RS256 JWT via
//!    `jsonwebtoken` → oauth2 token, cached until expiry−120s)
//! 4. GCE/GKE IMDS `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`
//!    with `Metadata-Flavor: Google` (override [`GCS_IMDS_BASE_ENV`] for tests)
//! 5. Anonymous GET if `RATARMOUNT_GCS_ANONYMOUS=1` / `CLOUDSDK_ANONYMOUS=1`
//!
//! Factory `gs://` dispatch is a later PR. R2/MinIO remain S3 (`AWS_ENDPOINT_URL`).

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::debug;
use md5::{Digest, Md5};
use ratarmount_core::{ArchiveRead, MountSource};
use sha1::Sha1;
use tempfile::NamedTempFile;
use url::Url;

type HmacSha1 = Hmac<Sha1>;

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
/// GET, HEAD, and list. Do not use this token for PUT.
const GCS_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
/// Service-account PUT only. Never stored in the read-mount cache.
const GCS_WRITE_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_write";
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

/// XML ListBucket URL. Query params stay on the wire unsigned (not in the STS).
fn gcs_xml_list_url(bucket: &str, prefix: &str, marker: Option<&str>) -> String {
    let mut url = format!(
        "{}/{}?delimiter=/&prefix={}&max-keys=1000",
        api_endpoint(),
        bucket,
        urlencoding_encode(prefix)
    );
    if let Some(m) = marker.filter(|t| !t.is_empty()) {
        url.push_str("&marker=");
        url.push_str(&urlencoding_encode(m));
    }
    url
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredSource {
    EnvToken,
    Hmac,
    Adc,
    Imds,
    Anonymous,
}

struct HmacKeys {
    access_id: String,
    secret: String,
}

impl std::fmt::Debug for HmacKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKeys")
            .field("access_id", &self.access_id)
            .field("secret", &redact_secret(&self.secret))
            .finish()
    }
}

fn redact_secret(s: &str) -> &'static str {
    if s.is_empty() {
        ""
    } else {
        "***"
    }
}

struct CachedToken {
    access_token: String,
    expiration: chrono::DateTime<chrono::Utc>,
    /// OAuth scope this token was minted with. Read and write do not share a slot.
    scope: String,
}

struct TokenCache {
    read: Option<(CredSource, CachedToken)>,
    write: Option<(CredSource, CachedToken)>,
}

static TOKEN_CACHE: Mutex<TokenCache> = Mutex::new(TokenCache {
    read: None,
    write: None,
});

fn cache_lock() -> std::sync::MutexGuard<'static, TokenCache> {
    TOKEN_CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
fn clear_token_cache() {
    let mut guard = cache_lock();
    guard.read = None;
    guard.write = None;
}

fn token_still_valid(tok: &CachedToken) -> bool {
    let skew = chrono::Duration::from_std(CREDS_EXPIRY_SKEW).unwrap_or_default();
    chrono::Utc::now() + skew < tok.expiration
}

/// Read-mount cache only. A `devstorage.read_write` token is not returned.
fn take_cached_token() -> Option<(CredSource, String)> {
    let guard = cache_lock();
    guard
        .read
        .as_ref()
        .filter(|(_, t)| t.scope == GCS_SCOPE && token_still_valid(t))
        .map(|(src, t)| (*src, t.access_token.clone()))
}

fn take_write_cached_token() -> Option<(CredSource, String)> {
    let guard = cache_lock();
    guard
        .write
        .as_ref()
        .filter(|(_, t)| t.scope == GCS_WRITE_SCOPE && token_still_valid(t))
        .map(|(src, t)| (*src, t.access_token.clone()))
}

fn store_cached_token(source: CredSource, token: CachedToken) {
    let mut guard = cache_lock();
    if token.scope == GCS_WRITE_SCOPE {
        guard.write = Some((source, token));
    } else {
        guard.read = Some((source, token));
    }
}

struct ResolvedAuth {
    source: CredSource,
    /// `None` = anonymous (no Authorization).
    bearer: Option<String>,
    hmac: Option<HmacKeys>,
}

impl std::fmt::Debug for ResolvedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedAuth")
            .field("source", &self.source)
            .field("bearer", &self.bearer.as_ref().map(|_| "***"))
            .field("hmac", &self.hmac)
            .finish()
    }
}

fn parse_oauth_token_json(body: &str, scope: &str) -> Result<CachedToken> {
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
        scope: scope.to_string(),
    })
}

fn load_env_access_token() -> Option<String> {
    non_empty_env("CLOUDSDK_AUTH_ACCESS_TOKEN")
        .or_else(|| non_empty_env("GOOGLE_OAUTH_ACCESS_TOKEN"))
}

fn fetch_imds_token() -> Result<CachedToken> {
    // No `scopes` query: the read mount keeps the metadata server's default token.
    fetch_imds_token_scoped(None)
}

fn fetch_imds_token_scoped(scope: Option<&str>) -> Result<CachedToken> {
    let mut url = format!(
        "{}/computeMetadata/v1/instance/service-accounts/default/token",
        imds_base()
    );
    if let Some(scope) = scope {
        url.push_str("?scopes=");
        url.push_str(&urlencoding_encode(scope));
    }
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
    parse_oauth_token_json(&body, scope.unwrap_or(GCS_SCOPE))
}

fn exchange_jwt_for_token(sa: &serde_json::Value, scope: &str) -> Result<CachedToken> {
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
        "scope": scope,
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
    parse_oauth_token_json(&text, scope)
}

fn fetch_adc_token() -> Result<CachedToken> {
    fetch_adc_token_with_scope(GCS_SCOPE)
}

fn fetch_adc_token_with_scope(scope: &str) -> Result<CachedToken> {
    let path = non_empty_env("GOOGLE_APPLICATION_CREDENTIALS")
        .ok_or_else(|| gcs_err("GOOGLE_APPLICATION_CREDENTIALS unset"))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| gcs_err(format!("reading ADC file {path}: {e}")))?;
    let sa: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| gcs_err(format!("parsing ADC JSON {path}: {e}")))?;
    exchange_jwt_for_token(&sa, scope)
}

fn load_hmac_keys() -> Option<HmacKeys> {
    let access_id = non_empty_env("GOOGLE_HMAC_KEY")?;
    let secret = non_empty_env("GOOGLE_HMAC_SECRET")?;
    Some(HmacKeys { access_id, secret })
}

fn resolve_auth() -> Result<ResolvedAuth> {
    if let Some(tok) = load_env_access_token() {
        return Ok(ResolvedAuth {
            source: CredSource::EnvToken,
            bearer: Some(tok),
            hmac: None,
        });
    }
    // HMAC before take_cached_token(): a warm ADC/IMDS cache must not shadow keys.
    if let Some(keys) = load_hmac_keys() {
        debug!("gcs: using HMAC GOOG1");
        return Ok(ResolvedAuth {
            source: CredSource::Hmac,
            bearer: None,
            hmac: Some(keys),
        });
    }
    if let Some((source, tok)) = take_cached_token() {
        debug!("gcs: using cached {source:?} token");
        return Ok(ResolvedAuth {
            source,
            bearer: Some(tok),
            hmac: None,
        });
    }

    let mut tried: Vec<&str> = vec![
        "env CLOUDSDK_AUTH_ACCESS_TOKEN / GOOGLE_OAUTH_ACCESS_TOKEN",
        "GOOGLE_HMAC_KEY / GOOGLE_HMAC_SECRET",
    ];
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
                    hmac: None,
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
                hmac: None,
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
            hmac: None,
        });
    }

    let mut msg = format!(
        "no GCS credentials found for gs://; tried: {}; \
         set CLOUDSDK_AUTH_ACCESS_TOKEN / GOOGLE_OAUTH_ACCESS_TOKEN, \
         GOOGLE_HMAC_KEY + GOOGLE_HMAC_SECRET (GOOG1), \
         GOOGLE_APPLICATION_CREDENTIALS (ADC), run on GCE/GKE with a service account, \
         or set RATARMOUNT_GCS_ANONYMOUS=1 / CLOUDSDK_ANONYMOUS=1 for public buckets",
        tried.join(", ")
    );
    if !role_errors.is_empty() {
        msg.push_str(&format!(" (role errors: {})", role_errors.join("; ")));
    }
    Err(gcs_err(msg))
}

/// Credentials for one PUT. Env bearer and GOOG1 HMAC are used as-is.
/// A service account mints [`GCS_WRITE_SCOPE`] and does not reuse a cached
/// `devstorage.read_only` token. Anonymous is an error.
fn resolve_put_auth() -> Result<ResolvedAuth> {
    if let Some(tok) = load_env_access_token() {
        return Ok(ResolvedAuth {
            source: CredSource::EnvToken,
            bearer: Some(tok),
            hmac: None,
        });
    }
    if let Some(keys) = load_hmac_keys() {
        debug!("gcs: using HMAC GOOG1 for PUT");
        return Ok(ResolvedAuth {
            source: CredSource::Hmac,
            bearer: None,
            hmac: Some(keys),
        });
    }
    if let Some((source, tok)) = take_write_cached_token() {
        debug!("gcs: using cached write-scoped {source:?} token");
        return Ok(ResolvedAuth {
            source,
            bearer: Some(tok),
            hmac: None,
        });
    }

    if non_empty_env("GOOGLE_APPLICATION_CREDENTIALS").is_some() {
        match fetch_adc_token_with_scope(GCS_WRITE_SCOPE) {
            Ok(tok) => {
                let bearer = tok.access_token.clone();
                store_cached_token(CredSource::Adc, tok);
                return Ok(ResolvedAuth {
                    source: CredSource::Adc,
                    bearer: Some(bearer),
                    hmac: None,
                });
            }
            Err(e) => {
                debug!("gcs: ADC write-scope exchange failed: {e}");
            }
        }
    }

    match fetch_imds_token_scoped(Some(GCS_WRITE_SCOPE)) {
        Ok(tok) => {
            let bearer = tok.access_token.clone();
            store_cached_token(CredSource::Imds, tok);
            return Ok(ResolvedAuth {
                source: CredSource::Imds,
                bearer: Some(bearer),
                hmac: None,
            });
        }
        Err(e) => {
            debug!("gcs: IMDS write-scope token failed: {e}");
        }
    }

    if anonymous_enabled() {
        return Err(gcs_auth_err(
            "anonymous credentials cannot PUT gs:// objects",
        ));
    }
    Err(gcs_err(
        "no GCS credentials found for gs:// PUT; set GOOGLE_HMAC_KEY + GOOGLE_HMAC_SECRET, \
         a bearer token, or GOOGLE_APPLICATION_CREDENTIALS with devstorage.read_write",
    ))
}

fn reject_anonymous_put(auth: &ResolvedAuth) -> Result<()> {
    if auth.source == CredSource::Anonymous || (auth.hmac.is_none() && auth.bearer.is_none()) {
        return Err(gcs_auth_err(
            "anonymous credentials cannot PUT gs:// objects",
        ));
    }
    Ok(())
}

/// GOOG1 string-to-sign (AWS V2). Range is not included (unsigned on the wire).
///
/// Content-MD5 and Content-Type are hard-coded empty. GET and HEAD stay on
/// this helper. A PUT that sets those headers must use [`goog1_put_string_to_sign`].
fn goog1_string_to_sign(verb: &str, date: &str, resource: &str) -> String {
    format!("{verb}\n\n\n{date}\n{resource}")
}

/// GOOG1 PUT string-to-sign. Field order is verb, Content-MD5, Content-Type,
/// Date, resource. Do not call [`goog1_string_to_sign`] for a body PUT.
fn goog1_put_string_to_sign(
    verb: &str,
    content_md5: &str,
    content_type: &str,
    date: &str,
    resource: &str,
) -> String {
    format!("{verb}\n{content_md5}\n{content_type}\n{date}\n{resource}")
}

fn content_md5_b64(body: &[u8]) -> String {
    base64_encode(&Md5::digest(body))
}

/// Stream MD5 of a staged file. Does not keep the bytes.
fn content_md5_path(path: &std::path::Path) -> Result<(String, u64)> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| gcs_err(format!("reading {} for Content-MD5: {e}", path.display())))?;
    let mut hasher = Md5::new();
    let mut buf = [0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((base64_encode(hasher.finalize().as_slice()), len))
}

fn goog1_canonical_resource_object(bucket: &str, object: &str) -> String {
    format!("/{bucket}/{}", encode_object_path(object))
}

fn goog1_canonical_resource_list(bucket: &str) -> String {
    format!("/{bucket}")
}

#[cfg(test)]
fn goog1_sts_object(bucket: &str, object: &str, date: &str, _range: Option<&str>) -> String {
    goog1_string_to_sign(
        "GET",
        date,
        &goog1_canonical_resource_object(bucket, object),
    )
}

#[cfg(test)]
fn goog1_sts_list(bucket: &str, date: &str) -> String {
    goog1_string_to_sign("GET", date, &goog1_canonical_resource_list(bucket))
}

fn rfc1123_gmt(dt: chrono::DateTime<chrono::Utc>) -> String {
    const WDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    use chrono::{Datelike, Timelike};
    let wd = WDAYS[dt.weekday().num_days_from_monday() as usize];
    let mon = MONTHS[(dt.month() as usize).saturating_sub(1)];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        wd,
        dt.day(),
        mon,
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
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

fn goog1_authorization(access_id: &str, secret: &str, sts: &str) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
        .map_err(|e| gcs_err(format!("HMAC-SHA1 key: {e}")))?;
    mac.update(sts.as_bytes());
    let sig = base64_encode(&mac.finalize().into_bytes());
    Ok(format!("GOOG1 {access_id}:{sig}"))
}

fn apply_gcs_auth(
    mut req: ureq::Request,
    auth: &ResolvedAuth,
    verb: &str,
    resource: &str,
    date: &str,
) -> Result<ureq::Request> {
    req = req.set("User-Agent", USER_AGENT);
    if auth.source == CredSource::Hmac {
        let keys = auth
            .hmac
            .as_ref()
            .ok_or_else(|| gcs_err("HMAC auth missing keys"))?;
        let sts = goog1_string_to_sign(verb, date, resource);
        let hdr = goog1_authorization(&keys.access_id, &keys.secret, &sts)?;
        req = req.set("Date", date).set("Authorization", &hdr);
        return Ok(req);
    }
    if let Some(tok) = &auth.bearer {
        req = req.set("Authorization", &format!("Bearer {tok}"));
    }
    Ok(req)
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
    let resource = goog1_canonical_resource_object(&loc.bucket, &loc.object);
    let date = rfc1123_gmt(chrono::Utc::now());
    let mut req = apply_gcs_auth(ureq::get(&url), &auth, "GET", &resource, &date)?;
    // Range is not in the STS; apply after signing.
    if let Some(ref r) = range_value {
        req = req.set("Range", r);
    }
    let resp = req
        .timeout(crate::OBJECT_STORE_IO_TIMEOUT)
        .call()
        .map_err(|e| gcs_err(format!("GetObject gs://{}/{}: {e}", loc.bucket, loc.object)))?;
    Ok((auth.source, resp))
}

/// HEAD metadata for a live-commit tick. Missing keys are an error (do not create).
///
/// The verb is `HEAD` on the empty-MD5 helper. Anonymous GET stays allowed.
#[derive(Clone, Debug)]
pub struct GcsHead {
    pub etag: Option<String>,
    pub len: u64,
}

/// `HEAD` the object. ETag is the raw header value (quotes included).
pub fn head_gcs_object(url_str: &str) -> Result<GcsHead> {
    let loc = parse_gcs_url(url_str)?;
    let auth = resolve_auth()?;
    let url = gcs_xml_object_url(&loc);
    debug!("gcs HEAD {url} (auth={:?})", auth.source);
    let resource = goog1_canonical_resource_object(&loc.bucket, &loc.object);
    let date = rfc1123_gmt(chrono::Utc::now());
    let req = apply_gcs_auth(ureq::head(&url), &auth, "HEAD", &resource, &date)?;
    let resp = req
        .timeout(crate::OBJECT_STORE_IO_TIMEOUT)
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(status, resp) => {
                let body = resp.into_string().unwrap_or_default();
                gcs_status_error(auth.source, status, &loc, &body)
            }
            other => gcs_err(format!("HEAD gs://{}/{}: {other}", loc.bucket, loc.object)),
        })?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(gcs_status_error(auth.source, status, &loc, &body));
    }
    let etag = resp.header("etag").map(str::to_string);
    let len = resp
        .header("Content-Length")
        .or_else(|| resp.header("content-length"))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| {
            gcs_err(format!(
                "HEAD gs://{}/{} missing Content-Length",
                loc.bucket, loc.object
            ))
        })?;
    Ok(GcsHead { etag, len })
}

fn apply_gcs_put_auth(
    mut req: ureq::Request,
    auth: &ResolvedAuth,
    content_md5: &str,
    content_type: &str,
    resource: &str,
    date: &str,
) -> Result<ureq::Request> {
    req = req
        .set("User-Agent", USER_AGENT)
        .set("Content-MD5", content_md5)
        .set("Content-Type", content_type);
    if auth.source == CredSource::Hmac {
        let keys = auth
            .hmac
            .as_ref()
            .ok_or_else(|| gcs_err("HMAC auth missing keys"))?;
        // Bearer tokens do not reach this signer.
        let sts = goog1_put_string_to_sign("PUT", content_md5, content_type, date, resource);
        let hdr = goog1_authorization(&keys.access_id, &keys.secret, &sts)?;
        req = req.set("Date", date).set("Authorization", &hdr);
        return Ok(req);
    }
    if let Some(tok) = &auth.bearer {
        req = req.set("Authorization", &format!("Bearer {tok}"));
    }
    Ok(req)
}

fn finish_gcs_put(loc: &GcsLocation, resp: ureq::Response) -> Result<()> {
    let status = resp.status();
    if !(200..300).contains(&status) {
        let text = resp.into_string().unwrap_or_default();
        return Err(gcs_err(format!(
            "PutObject HTTP {status} for gs://{}/{}: {text}",
            loc.bucket, loc.object
        )));
    }
    Ok(())
}

fn map_gcs_put_send(loc: &GcsLocation, err: ureq::Error) -> RemoteError {
    match err {
        ureq::Error::Status(status, resp) => {
            let text = resp.into_string().unwrap_or_default();
            let msg = format!(
                "PutObject HTTP {status} for gs://{}/{}: {text}",
                loc.bucket, loc.object
            );
            if status == 401 || status == 403 {
                gcs_auth_err(msg)
            } else {
                gcs_err(msg)
            }
        }
        other => gcs_err(format!(
            "PutObject gs://{}/{}: {other}",
            loc.bucket, loc.object
        )),
    }
}

fn send_gcs_put(
    loc: &GcsLocation,
    auth: &ResolvedAuth,
    md5: &str,
    content_type: &str,
    content_length: u64,
    body: impl Read,
) -> Result<()> {
    let date = rfc1123_gmt(chrono::Utc::now());
    let resource = goog1_canonical_resource_object(&loc.bucket, &loc.object);
    let url = gcs_xml_object_url(loc);
    debug!(
        "gcs PUT {url} (auth={:?}, bytes={content_length}, content-type={content_type})",
        auth.source
    );
    let req = apply_gcs_put_auth(ureq::put(&url), auth, md5, content_type, &resource, &date)?
        .set("Content-Length", &content_length.to_string());
    let resp = req
        .timeout(crate::OBJECT_STORE_IO_TIMEOUT)
        .send(body)
        .map_err(|e| map_gcs_put_send(loc, e))?;
    finish_gcs_put(loc, resp)
}

/// One PutObject of an in-memory body. No multipart and no resumable session.
///
/// `content_type` is the GOOG1 field and the `Content-Type` header.
/// `Content-MD5` is the base64 MD5 of `body` (not hex). Anonymous credentials
/// error before any request. Bearer auth sends `Authorization: Bearer` and
/// does not use the GOOG1 signer. The HMAC secret is not logged.
/// Archive spools use [`put_gcs_file`] so the bytes are not held twice.
pub fn put_gcs_object(loc: &GcsLocation, body: &[u8], content_type: &str) -> Result<()> {
    let auth = resolve_put_auth()?;
    reject_anonymous_put(&auth)?;
    let md5 = content_md5_b64(body);
    send_gcs_put(
        loc,
        &auth,
        &md5,
        content_type,
        body.len() as u64,
        std::io::Cursor::new(body),
    )
}

/// One PutObject of a staged file. MD5 is hashed from disk, then the file is
/// streamed with `Content-Length` set to that byte count. No second full copy.
pub fn put_gcs_file(loc: &GcsLocation, path: &std::path::Path, content_type: &str) -> Result<()> {
    let auth = resolve_put_auth()?;
    reject_anonymous_put(&auth)?;
    let (md5, len) = content_md5_path(path)?;
    let file = std::fs::File::open(path)
        .map_err(|e| gcs_err(format!("opening {} for PUT: {e}", path.display())))?;
    send_gcs_put(loc, &auth, &md5, content_type, len, file)
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

/// Full GetObject of at most `max_bytes` (no Range). Errors if the body is larger.
pub(crate) fn fetch_gcs_bytes_capped(url_str: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let loc = parse_gcs_url(url_str)?;
    let (source, resp) = gcs_get_object(&loc, None)?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(gcs_status_error(source, status, &loc, &body));
    }
    let buf = crate::read_at_most(&mut resp.into_reader(), max_bytes)?;
    if buf.len() as u64 > max_bytes {
        return Err(gcs_err(format!(
            "body exceeds {max_bytes} bytes for gs://{}/{}",
            loc.bucket, loc.object
        )));
    }
    Ok(buf)
}

/// Download `gs://bucket/object` to a tempfile (GET only).
pub fn fetch_gcs_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_gcs_url(url_str)?;
    fetch_gcs_location_to_temp(&loc)
}

fn gcs_spool_file() -> Result<NamedTempFile> {
    let tmp = NamedTempFile::new()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(tmp)
}

fn fetch_gcs_location_to_temp(loc: &GcsLocation) -> Result<(NamedTempFile, u64)> {
    let (source, resp) = gcs_get_object(loc, None)?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(gcs_status_error(source, status, loc, &body));
    }
    let mut reader = resp.into_reader();
    let mut tmp = gcs_spool_file()?;
    let n = io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok((tmp, n))
}

fn gcs_bytes_to_tempfile(bytes: &[u8]) -> Result<(NamedTempFile, u64)> {
    let mut tmp = gcs_spool_file()?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok((tmp, bytes.len() as u64))
}

/// Sequential Range materialization into a mode `0o600` tempfile.
fn fetch_gcs_via_ranges(loc: &GcsLocation, size: u64) -> Result<(NamedTempFile, u64)> {
    let mut tmp = gcs_spool_file()?;
    if size == 0 {
        tmp.flush()?;
        return Ok((tmp, 0));
    }
    let mut written = 0u64;
    for (start, end) in crate::range_chunk_windows(size, crate::HTTP_RANGE_CHUNK) {
        let range = format!("bytes={start}-{end}");
        let (source, resp) = gcs_get_object(loc, Some((start, end)))?;
        let status = resp.status();
        if status == 206 {
            let expected = end - start + 1;
            let mut reader = resp.into_reader();
            let n = io::copy(&mut reader, &mut tmp)?;
            if n != expected {
                return Err(gcs_err(format!(
                    "range {range} for gs://{}/{} returned {n} bytes, expected {expected}",
                    loc.bucket, loc.object
                )));
            }
            written += n;
        } else if status == 200 && start == 0 {
            let mut reader = resp.into_reader();
            let n = io::copy(&mut reader, &mut tmp)?;
            tmp.flush()?;
            tmp.as_file_mut().seek(SeekFrom::Start(0))?;
            debug!(
                "gcs download gs://{}/{} -> {n} bytes (full body; Range ignored)",
                loc.bucket, loc.object
            );
            return Ok((tmp, n));
        } else {
            let body = resp.into_string().unwrap_or_default();
            return Err(gcs_status_error(source, status, loc, &body));
        }
    }
    if written != size {
        return Err(gcs_err(format!(
            "range download size mismatch for gs://{}/{}: wrote {written}, expected {size}",
            loc.bucket, loc.object
        )));
    }
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    debug!(
        "gcs range download gs://{}/{} -> {written} bytes",
        loc.bucket, loc.object
    );
    Ok((tmp, written))
}

/// Download a GCS object, preferring sequential HTTP Range chunks when feasible.
///
/// Same threshold and fallback as S3: above [`DEFAULT_GCS_RANGE_THRESHOLD`]
/// uses Range; a failed Range or a small object falls back to one full GET.
/// The tempfile is mode `0o600` in the system temp dir (not the overlay).
/// `fetch_gcs_to_temp` stays the single full GET and is not this path.
pub fn fetch_gcs_location_to_temp_prefer_range(
    loc: &GcsLocation,
    known_size: Option<u64>,
) -> Result<(NamedTempFile, u64)> {
    let size_for_range = match known_size {
        Some(n) if n > DEFAULT_GCS_RANGE_THRESHOLD => Some(n),
        Some(_) => None,
        None => match probe_gcs_object(loc) {
            Ok(GcsProbe::RangesOk(n)) if n > DEFAULT_GCS_RANGE_THRESHOLD => Some(n),
            Ok(GcsProbe::RangesOk(_)) => None,
            Ok(GcsProbe::FullBody(bytes)) => {
                return gcs_bytes_to_tempfile(&bytes);
            }
            Ok(GcsProbe::Unusable) => None,
            Err(e) => {
                debug!(
                    "gcs range probe failed for gs://{}/{}: {e}; full download",
                    loc.bucket, loc.object
                );
                None
            }
        },
    };
    if let Some(size) = size_for_range {
        debug!(
            "gcs prefer-range: gs://{}/{} ({size} bytes) in {}-byte chunks",
            loc.bucket,
            loc.object,
            crate::HTTP_RANGE_CHUNK
        );
        match fetch_gcs_via_ranges(loc, size) {
            Ok(v) => return Ok(v),
            Err(e) => {
                debug!(
                    "gcs range download failed for gs://{}/{}: {e}; falling back to full GET",
                    loc.bucket, loc.object
                );
            }
        }
    }
    fetch_gcs_location_to_temp(loc)
}

/// Inclusive byte range GET (`start..=end_inclusive`). Expects HTTP 206.
pub fn fetch_gcs_range_bytes(url_str: &str, start: u64, end_inclusive: u64) -> Result<Vec<u8>> {
    let loc = parse_gcs_url(url_str)?;
    if end_inclusive < start {
        return Err(gcs_err(format!(
            "invalid range {start}-{end_inclusive} for gs://{}/{}",
            loc.bucket, loc.object
        )));
    }
    let expected = end_inclusive - start + 1;
    let (source, resp) = gcs_get_object(&loc, Some((start, end_inclusive)))?;
    let status = resp.status();
    if status == 206 {
        let mut reader = resp.into_reader();
        let mut bytes = Vec::with_capacity(expected as usize);
        reader.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != expected {
            return Err(gcs_err(format!(
                "range bytes={start}-{end_inclusive} for gs://{}/{} returned {} bytes, expected {expected}",
                loc.bucket,
                loc.object,
                bytes.len()
            )));
        }
        return Ok(bytes);
    }
    if status == 200 {
        let _ = resp.into_string();
        return Err(gcs_err(format!(
            "HTTP 200 (Range ignored) GetObject gs://{}/{} bytes={start}-{end_inclusive}",
            loc.bucket, loc.object
        )));
    }
    let body = resp.into_string().unwrap_or_default();
    Err(gcs_status_error(source, status, &loc, &body))
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
    if auth.source == CredSource::Hmac {
        return gcs_list_page_xml(bucket, prefix, page_token, &auth);
    }
    let url = gcs_list_url(bucket, prefix, page_token);
    debug!("gcs LIST {url} (auth={:?})", auth.source);
    let date = rfc1123_gmt(chrono::Utc::now());
    let req = apply_gcs_auth(ureq::get(&url), &auth, "GET", "", &date)?;
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

fn gcs_list_page_xml(
    bucket: &str,
    prefix: &str,
    marker: Option<&str>,
    auth: &ResolvedAuth,
) -> Result<GcsListPage> {
    let url = gcs_xml_list_url(bucket, prefix, marker);
    let resource = goog1_canonical_resource_list(bucket);
    let date = rfc1123_gmt(chrono::Utc::now());
    debug!("gcs LIST xml {url} (auth={:?})", auth.source);
    let req = apply_gcs_auth(ureq::get(&url), auth, "GET", &resource, &date)?;
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
    Ok(parse_gcs_list_xml(&body))
}

/// Parse a GCS XML ListBucket body (one page). Cloned from S3 `xml_blocks` /
/// `xml_tag_text` (no XML crate).
fn parse_gcs_list_xml(xml: &str) -> GcsListPage {
    let is_truncated = xml_tag_text(xml, "istruncated")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut objects = Vec::new();
    for block in xml_blocks(xml, "contents") {
        let Some(name) = xml_tag_text(&block, "key").filter(|s| !s.is_empty()) else {
            continue;
        };
        let size = xml_tag_text(&block, "size")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        objects.push(GcsListedObject { name, size });
    }
    let mut prefixes = Vec::new();
    for block in xml_blocks(xml, "commonprefixes") {
        if let Some(p) = xml_tag_text(&block, "prefix").filter(|s| !s.is_empty()) {
            prefixes.push(p);
        }
    }
    let next_page_token = xml_tag_text(xml, "nextmarker")
        .filter(|s| !s.is_empty())
        .or_else(|| {
            if is_truncated {
                objects.last().map(|o| o.name.clone())
            } else {
                None
            }
        });
    GcsListPage {
        objects,
        prefixes,
        next_page_token,
    }
}

fn xml_blocks(xml: &str, tag: &str) -> Vec<String> {
    let lower = xml.to_ascii_lowercase();
    let open_plain = format!("<{tag}");
    let open_ns = format!(":{tag}");
    let close_plain = format!("</{tag}>");
    let close_ns = format!(":{tag}>");
    let mut out = Vec::new();
    let mut search_from = 0;
    while search_from < lower.len() {
        let rest = &lower[search_from..];
        let rel = match rest.find(&open_plain) {
            Some(i) => {
                if i > 0 && rest.as_bytes()[i - 1] == b'/' {
                    search_from += i + 1;
                    continue;
                }
                i
            }
            None => match rest.find(&open_ns) {
                Some(i) if i > 0 && rest.as_bytes()[i - 1] == b'<' => i,
                _ => break,
            },
        };
        let abs = search_from + rel;
        let after_name = match lower[abs..].find('>') {
            Some(g) => abs + g + 1,
            None => break,
        };
        let close_rel = lower[after_name..].find(&close_plain).or_else(|| {
            lower[after_name..].find(&close_ns).and_then(|i| {
                let at = after_name + i;
                lower[..at].rfind('<').map(|_| i)
            })
        });
        let Some(c) = close_rel else { break };
        let inner = xml[after_name..after_name + c].to_string();
        out.push(inner);
        search_from = after_name + c + 1;
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
        return Some(xml_unescape(text));
    }
    None
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
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
        "GOOGLE_HMAC_KEY",
        "GOOGLE_HMAC_SECRET",
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
        requests: Arc<AtomicUsize>,
        bodies: Arc<StdMutex<Vec<Vec<u8>>>>,
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
        XmlList {
            xml: String,
            file_body: Vec<u8>,
        },
        NotFound,
        /// Records every method, including PUT, and returns 200 with an empty body.
        AcceptPut,
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
            let requests = Arc::new(AtomicUsize::new(0));
            let bodies = Arc::new(StdMutex::new(Vec::new()));
            let log_c = Arc::clone(&log);
            let gets_c = Arc::clone(&gets);
            let posts_c = Arc::clone(&posts);
            let auth_c = Arc::clone(&auth_headers);
            let range_c = Arc::clone(&range_headers);
            let list_c = Arc::clone(&list_gets);
            let requests_c = Arc::clone(&requests);
            let bodies_c = Arc::clone(&bodies);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut has_auth = false;
                    let mut auth_value: Option<String> = None;
                    let mut range_hdr: Option<String> = None;
                    let mut meta_flavor: Option<String> = None;
                    let mut content_len: usize = 0;
                    let mut content_md5: Option<String> = None;
                    let mut content_type: Option<String> = None;
                    let mut date_hdr: Option<String> = None;
                    let mut saw_length = false;
                    requests_c.fetch_add(1, Ordering::SeqCst);
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
                            if let Some((_, v)) = line.split_once(':') {
                                auth_value = Some(v.trim().to_string());
                            }
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
                            saw_length = true;
                        }
                        if lower.starts_with("content-md5:") {
                            if let Some((_, v)) = line.split_once(':') {
                                content_md5 = Some(v.trim().to_string());
                            }
                        }
                        if lower.starts_with("content-type:") {
                            if let Some((_, v)) = line.split_once(':') {
                                content_type = Some(v.trim().to_string());
                            }
                        }
                        if lower.starts_with("date:") {
                            if let Some((_, v)) = line.split_once(':') {
                                date_hdr = Some(v.trim().to_string());
                            }
                        }
                    }
                    let mut dump = Vec::new();
                    if content_len > 0 {
                        dump.resize(content_len, 0);
                        let _ = reader.read_exact(&mut dump);
                        bodies_c.lock().unwrap().push(dump.clone());
                    }
                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if has_auth {
                            lg.push("Authorization: present".into());
                            if let Some(ref v) = auth_value {
                                lg.push(format!("Authorization-Value: {v}"));
                            }
                        } else {
                            lg.push("Authorization: absent".into());
                        }
                        if let Some(ref r) = range_hdr {
                            lg.push(format!("Range: {r}"));
                        }
                        if let Some(ref v) = content_md5 {
                            lg.push(format!("Content-MD5: {v}"));
                        }
                        if let Some(ref v) = content_type {
                            lg.push(format!("Content-Type: {v}"));
                        }
                        if let Some(ref v) = date_hdr {
                            lg.push(format!("Date: {v}"));
                        }
                        if saw_length {
                            lg.push(format!("Content-Length: {content_len}"));
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
                        MockMode::XmlList { xml, file_body } => {
                            if path.contains("/storage/v1/") {
                                let msg = b"json list not used for HMAC";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    msg.len()
                                );
                                let _ = stream.write_all(msg);
                                continue;
                            }
                            if path.contains('?')
                                && (path.contains("prefix=") || path.contains("delimiter="))
                            {
                                list_c.fetch_add(1, Ordering::SeqCst);
                                gets_c.fetch_add(1, Ordering::SeqCst);
                                let body = xml.as_bytes();
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
                        MockMode::AcceptPut => {
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            );
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
                requests,
                bodies,
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
    fn anonymous_fetch_gcs_to_temp() {
        let payload = b"gcs-index-sibling-bytes".to_vec();
        let mock = MockGcs::spawn(MockMode::Object {
            body: payload.clone(),
            require_auth: false,
            honor_range: true,
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("RATARMOUNT_GCS_ANONYMOUS", "1");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let (mut tmp, size) = fetch_gcs_to_temp("gs://public/path/obj.bin").unwrap();
        assert_eq!(size, payload.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
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

    const GOOG1_DATE: &str = "Mon, 24 Aug 2026 12:00:00 GMT";

    #[test]
    fn goog1_sts_object_ignores_range() {
        let a = goog1_sts_object("bkt", "obj.bin", GOOG1_DATE, None);
        let b = goog1_sts_object("bkt", "obj.bin", GOOG1_DATE, Some("bytes=0-99"));
        assert_eq!(a, b);
        assert_eq!(a, "GET\n\n\nMon, 24 Aug 2026 12:00:00 GMT\n/bkt/obj.bin");
        assert!(!a.to_ascii_lowercase().contains("range"));
    }

    #[test]
    fn goog1_sts_object_path_is_encode_object_path() {
        let sts = goog1_sts_object("bkt", "a b/x", GOOG1_DATE, None);
        let encoded = encode_object_path("a b/x");
        assert_eq!(encoded, "a%20b/x");
        assert_eq!(sts, format!("GET\n\n\n{GOOG1_DATE}\n/bkt/{encoded}"));
        assert!(sts.contains("/bkt/a%20b/x"));
        assert!(!sts.contains("/bkt/a b/x"));
    }

    #[test]
    fn goog1_sts_list_is_bucket_only() {
        let sts = goog1_sts_list("bkt", GOOG1_DATE);
        assert_eq!(sts, format!("GET\n\n\n{GOOG1_DATE}\n/bkt"));
        assert!(sts.ends_with("/bkt"));
        assert!(!sts.contains('?'));
        assert!(!sts.contains("prefix"));
        assert!(!sts.contains("delimiter"));
        assert!(!sts.contains("marker"));
        assert!(!sts.contains("max-keys"));
    }

    /// Regression: HMAC GET sends Authorization GOOG1
    #[test]
    fn regression_hmac_get_sends_authorization_goog1() {
        let body: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let mock = MockGcs::spawn(MockMode::Object {
            body: body.clone(),
            require_auth: true,
            honor_range: true,
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("GOOGLE_HMAC_KEY", "GOOG1ACCESS");
        _g.set("GOOGLE_HMAC_SECRET", "supersecret");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let mut f = open_gcs_range("gs://bkt/obj.bin").unwrap();
        let mut got = vec![0u8; 16];
        f.read_exact(&mut got).unwrap();
        assert_eq!(&got, &body[..16]);
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter()
                .any(|l| l.starts_with("Authorization-Value: GOOG1 GOOG1ACCESS:")),
            "expected GOOG1 Authorization, log={log:?}"
        );
        assert!(
            !log.iter().any(|l| l.contains("supersecret")),
            "HMAC secret leaked in mock log: {log:?}"
        );
        assert!(
            log.iter().any(|l| l.starts_with("Range: ")),
            "Range must still be sent (unsigned), log={log:?}"
        );
    }

    #[test]
    fn hmac_secret_redacted_in_debug() {
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("GOOGLE_HMAC_KEY", "GOOG1ACCESS");
        _g.set("GOOGLE_HMAC_SECRET", "supersecret");
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source, CredSource::Hmac);
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("supersecret"), "secret leaked: {dbg}");
        assert!(dbg.contains("***"), "{dbg}");
        assert!(dbg.contains("Hmac") || dbg.contains("GOOG1ACCESS"), "{dbg}");
    }

    #[test]
    fn hmac_list_uses_xml_not_json() {
        let xml = concat!(
            "<ListBucketResult>",
            "<Contents><Key>prefix/a.tar</Key><Size>11</Size></Contents>",
            "<CommonPrefixes><Prefix>prefix/sub/</Prefix></CommonPrefixes>",
            "<IsTruncated>false</IsTruncated>",
            "</ListBucketResult>"
        );
        let mock = MockGcs::spawn(MockMode::XmlList {
            xml: xml.into(),
            file_body: b"hello-world".to_vec(),
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("GOOGLE_HMAC_KEY", "GOOG1ACCESS");
        _g.set("GOOGLE_HMAC_SECRET", "supersecret");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        let loc = GcsLocation {
            bucket: "bucket".into(),
            object: "prefix/".into(),
        };
        let ents = list_gcs_prefix(&loc).unwrap();
        assert!(
            ents.iter().any(|e| e.name == "a.tar" && e.size == 11),
            "{ents:?}"
        );
        assert!(ents.iter().any(|e| e.name == "sub" && e.is_dir), "{ents:?}");
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter()
                .any(|l| l.contains("GET /bucket?") && l.contains("prefix=")),
            "XML list URL should keep unsigned query, log={log:?}"
        );
        assert!(
            !log.iter().any(|l| l.contains("/storage/v1/")),
            "HMAC list must not use JSON API, log={log:?}"
        );
        assert!(
            log.iter()
                .any(|l| l.starts_with("Authorization-Value: GOOG1 ")),
            "expected GOOG1 on XML list, log={log:?}"
        );
        assert!(mock.list_gets.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn hmac_bearer_preferred_when_token_and_hmac_both_set() {
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("CLOUDSDK_AUTH_ACCESS_TOKEN", "ya29.wins");
        _g.set("GOOGLE_HMAC_KEY", "GOOG1ACCESS");
        _g.set("GOOGLE_HMAC_SECRET", "supersecret");
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source, CredSource::EnvToken);
        assert_eq!(auth.bearer.as_deref(), Some("ya29.wins"));
        assert!(auth.hmac.is_none());
    }

    #[test]
    fn hmac_selected_even_if_adc_token_is_cached() {
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("GOOGLE_HMAC_KEY", "GOOG1ACCESS");
        _g.set("GOOGLE_HMAC_SECRET", "supersecret");
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        store_cached_token(
            CredSource::Adc,
            CachedToken {
                access_token: "ya29.cached-should-not-win".into(),
                expiration: chrono::Utc::now() + chrono::Duration::hours(1),
                scope: GCS_SCOPE.to_string(),
            },
        );
        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source, CredSource::Hmac);
        assert!(auth.bearer.is_none());
        assert_eq!(
            auth.hmac.as_ref().map(|h| h.access_id.as_str()),
            Some("GOOG1ACCESS")
        );
    }

    fn log_field(log: &[String], prefix: &str) -> String {
        log.iter()
            .find_map(|l| l.strip_prefix(prefix).map(|s| s.trim().to_string()))
            .unwrap_or_else(|| panic!("missing {prefix} in {log:?}"))
    }

    /// Known fixture: MD5 is field 2, content-type is field 3.
    /// GET stays on the empty-MD5 helper.
    #[test]
    fn goog1_put_string_to_sign_puts_md5_and_content_type_in_fields() {
        let md5 = "XUFAKrxLKna5cZ2REBfFkg==";
        let content_type = "application/octet-stream";
        let resource = "/bkt/obj.bin";
        let sts = goog1_put_string_to_sign("PUT", md5, content_type, GOOG1_DATE, resource);
        assert_eq!(
            sts,
            "PUT\nXUFAKrxLKna5cZ2REBfFkg==\napplication/octet-stream\nMon, 24 Aug 2026 12:00:00 GMT\n/bkt/obj.bin"
        );
        let fields: Vec<&str> = sts.split('\n').collect();
        assert_eq!(fields.len(), 5, "{sts}");
        assert_eq!(fields[1], md5, "field 2 is Content-MD5");
        assert_eq!(fields[2], content_type, "field 3 is Content-Type");
        let get_sts = goog1_string_to_sign("GET", GOOG1_DATE, resource);
        assert_eq!(
            get_sts,
            "GET\n\n\nMon, 24 Aug 2026 12:00:00 GMT\n/bkt/obj.bin"
        );
        assert_ne!(
            sts,
            goog1_string_to_sign("PUT", GOOG1_DATE, resource),
            "PUT must not use the empty-MD5 helper"
        );
    }

    /// The mock records PUT. The fixture secret is not in the log, and the
    /// Authorization value matches the PUT string-to-sign rather than the GET helper.
    #[test]
    fn gcs_put_records_put_and_not_the_secret() {
        let secret = "supersecret";
        let mock = MockGcs::spawn(MockMode::AcceptPut);
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("GOOGLE_HMAC_KEY", "GOOG1ACCESS");
        _g.set("GOOGLE_HMAC_SECRET", secret);
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let loc = parse_gcs_url("gs://bkt/obj.bin").unwrap();
        put_gcs_object(&loc, b"hello", "application/octet-stream").unwrap();
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("PUT ")),
            "mock must record PUT, log={log:?}"
        );
        assert!(
            log.iter().all(|l| !l.contains(secret)),
            "fixture secret leaked: {log:?}"
        );
        let md5 = log_field(&log, "Content-MD5:");
        let content_type = log_field(&log, "Content-Type:");
        let date = log_field(&log, "Date:");
        let auth = log_field(&log, "Authorization-Value:");
        assert_eq!(md5, "XUFAKrxLKna5cZ2REBfFkg==");
        assert_eq!(content_type, "application/octet-stream");
        let resource = "/bkt/obj.bin";
        let put_sts = goog1_put_string_to_sign("PUT", &md5, &content_type, &date, resource);
        let expect = goog1_authorization("GOOG1ACCESS", secret, &put_sts).unwrap();
        assert_eq!(auth, expect, "PUT signer mismatch, sts={put_sts:?}");
        let get_form = goog1_string_to_sign("PUT", &date, resource);
        let not_get = goog1_authorization("GOOG1ACCESS", secret, &get_form).unwrap();
        assert_ne!(
            auth, not_get,
            "PUT must not be signed with the empty-MD5 helper"
        );
    }

    #[test]
    fn gcs_bearer_put_sends_content_md5_not_hmac() {
        let mock = MockGcs::spawn(MockMode::AcceptPut);
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("CLOUDSDK_AUTH_ACCESS_TOKEN", "ya29.bearer-put");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let loc = parse_gcs_url("gs://bkt/obj.bin").unwrap();
        put_gcs_object(&loc, b"hello", "application/json").unwrap();
        let log = mock.log.lock().unwrap();
        assert!(log.iter().any(|l| l.starts_with("PUT ")), "{log:?}");
        let auth = log_field(&log, "Authorization-Value:");
        assert_eq!(auth, "Bearer ya29.bearer-put");
        assert!(!auth.starts_with("GOOG1"), "{auth}");
        assert_eq!(log_field(&log, "Content-MD5:"), "XUFAKrxLKna5cZ2REBfFkg==");
        assert_eq!(log_field(&log, "Content-Type:"), "application/json");
        assert!(
            !log.iter().any(|l| l.starts_with("Date:")),
            "bearer PUT must not send the GOOG1 Date field, log={log:?}"
        );
    }

    #[test]
    fn gcs_anonymous_put_errors_before_request() {
        let mock = MockGcs::spawn(MockMode::AcceptPut);
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("RATARMOUNT_GCS_ANONYMOUS", "1");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let loc = parse_gcs_url("gs://bkt/obj.bin").unwrap();
        let err = put_gcs_object(&loc, b"hello", "application/octet-stream")
            .unwrap_err()
            .to_string();
        assert!(err.contains("anonymous"), "{err}");
        assert_eq!(
            mock.requests.load(Ordering::SeqCst),
            0,
            "anonymous PUT must not send a request"
        );
    }

    #[test]
    fn gcs_prefer_range_spool_is_0600_and_uses_chunks() {
        let extra = DEFAULT_GCS_RANGE_THRESHOLD as usize + 16;
        let body: Vec<u8> = (0u8..=255).cycle().take(extra).collect();
        let mock = MockGcs::spawn(MockMode::Object {
            body: body.clone(),
            require_auth: false,
            honor_range: true,
        });
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("RATARMOUNT_GCS_ANONYMOUS", "1");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let loc = parse_gcs_url("gs://bkt/big.bin").unwrap();
        let (mut tmp, size) = fetch_gcs_location_to_temp_prefer_range(&loc, None).unwrap();
        assert_eq!(size, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "spool mode {mode:o}");
        }
        let log = mock.log.lock().unwrap();
        assert!(
            log.iter()
                .any(|l| l.starts_with("Range: bytes=0-") && l != "Range: bytes=0-0"),
            "expected a content range after the probe, log={log:?}"
        );
    }

    fn b64url_decode(input: &str) -> Vec<u8> {
        fn val(c: u8) -> u8 {
            match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                _ => 0,
            }
        }
        let bytes: Vec<u8> = input.bytes().filter(|b| *b != b'=').collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let n = ((val(bytes[i]) as u32) << 18)
                | ((val(bytes[i + 1]) as u32) << 12)
                | ((val(bytes[i + 2]) as u32) << 6)
                | (val(bytes[i + 3]) as u32);
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
            out.push(n as u8);
            i += 4;
        }
        match bytes.len() - i {
            2 => {
                let n = ((val(bytes[i]) as u32) << 18) | ((val(bytes[i + 1]) as u32) << 12);
                out.push((n >> 16) as u8);
            }
            3 => {
                let n = ((val(bytes[i]) as u32) << 18)
                    | ((val(bytes[i + 1]) as u32) << 12)
                    | ((val(bytes[i + 2]) as u32) << 6);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            _ => {}
        }
        out
    }

    fn jwt_scope_from_form(form: &[u8]) -> String {
        let form = std::str::from_utf8(form).expect("jwt form");
        let assertion = form
            .split('&')
            .find_map(|p| p.strip_prefix("assertion="))
            .expect("assertion");
        let payload = assertion.split('.').nth(1).expect("jwt payload");
        let json: serde_json::Value =
            serde_json::from_slice(&b64url_decode(payload)).expect("jwt json");
        json["scope"].as_str().expect("scope").to_string()
    }

    /// Regression: a service-account PUT mints devstorage.read_write and does
    /// not reuse the read_only token from GET.
    #[test]
    fn gcs_put_jwt_scope_is_read_write_and_get_stays_read_only() {
        let oauth = MockGcs::spawn(MockMode::Oauth {
            body: r#"{"access_token":"ya29.adc-scope","expires_in":3600}"#.into(),
        });
        let storage = MockGcs::spawn(MockMode::AcceptPut);
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
        _g.set(GCS_ENDPOINT_ENV, &storage.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");

        fetch_gcs_to_temp("gs://bkt/obj.bin").unwrap();
        let forms = oauth.bodies.lock().unwrap();
        assert_eq!(forms.len(), 1, "GET must exchange one JWT");
        assert_eq!(
            jwt_scope_from_form(&forms[0]),
            "https://www.googleapis.com/auth/devstorage.read_only"
        );
        drop(forms);

        let loc = parse_gcs_url("gs://bkt/obj.bin").unwrap();
        put_gcs_object(&loc, b"hello", "application/octet-stream").unwrap();
        let forms = oauth.bodies.lock().unwrap();
        assert_eq!(
            forms.len(),
            2,
            "PUT must not reuse the read_only cached token"
        );
        assert_eq!(
            jwt_scope_from_form(&forms[1]),
            "https://www.googleapis.com/auth/devstorage.read_write"
        );
        drop(forms);
        let log = storage.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("GET ")),
            "GET still ran, log={log:?}"
        );
        assert!(
            log.iter().any(|l| l.starts_with("PUT ")),
            "PUT ran, log={log:?}"
        );
        assert!(
            log.iter()
                .any(|l| l == "Authorization-Value: Bearer ya29.adc-scope"),
            "bearer on the wire, log={log:?}"
        );
    }

    #[test]
    fn gcs_put_file_streams_with_content_length() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(200_000).collect();
        let mock = MockGcs::spawn(MockMode::AcceptPut);
        let _g = EnvGuard::acquire(GCS_ENV_KEYS);
        _g.set("GOOGLE_HMAC_KEY", "GOOG1ACCESS");
        _g.set("GOOGLE_HMAC_SECRET", "supersecret");
        _g.set(GCS_ENDPOINT_ENV, &mock.base_url);
        _g.set(GCS_IMDS_BASE_ENV, "http://127.0.0.1:1");
        let mut staged = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut staged, &payload).unwrap();
        std::io::Write::flush(&mut staged).unwrap();
        let loc = parse_gcs_url("gs://bkt/obj.bin").unwrap();
        put_gcs_file(&loc, staged.path(), "application/octet-stream").unwrap();
        let log = mock.log.lock().unwrap();
        assert!(log.iter().any(|l| l.starts_with("PUT ")), "{log:?}");
        assert_eq!(
            log_field(&log, "Content-Length:"),
            payload.len().to_string()
        );
        assert_eq!(log_field(&log, "Content-MD5:"), content_md5_b64(&payload));
        assert!(
            log.iter().all(|l| !l.contains("supersecret")),
            "secret leaked: {log:?}"
        );
        drop(log);
        let bodies = mock.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0], payload);
    }
}
