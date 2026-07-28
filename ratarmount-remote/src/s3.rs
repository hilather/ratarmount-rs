//! S3 GetObject download-to-temp for `s3://bucket/key` (AWS SigV4 + ureq).
//!
//! # Credential chain (in order)
//!
//! 1. **Explicit env keys** — `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
//!    (optional `AWS_SESSION_TOKEN`)
//! 2. **Container / IMDS instance role** when access key is unset or empty:
//!    - ECS task role: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or
//!      `AWS_CONTAINER_CREDENTIALS_FULL_URI` (+ optional
//!      `AWS_CONTAINER_AUTHORIZATION_TOKEN` /
//!      `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`)
//!    - EC2 IMDS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
//!      (IMDSv2 token PUT first, then role name + credentials GETs)
//! 3. **Anonymous** if `AWS_ANONYMOUS=1` / `RATARMOUNT_S3_ANONYMOUS=1`
//!    (unsigned GET; no `Authorization` header — for public buckets)
//! 4. Else a clear error listing what was tried
//!
//! Instance-role credentials are cached until near `Expiration` (JSON field).
//!
//! # Other env
//!
//! | Env | Purpose |
//! |-----|---------|
//! | `AWS_REGION` / `AWS_DEFAULT_REGION` | Default `us-east-1` |
//! | `AWS_ENDPOINT_URL` / `S3_ENDPOINT_URL` | MinIO / LocalStack (path-style) |
//! | `RATARMOUNT_IMDS_BASE` / `AWS_EC2_METADATA_SERVICE_ENDPOINT` | Override IMDS base (tests) |

use std::io::{Seek, SeekFrom, Write};
use std::sync::Mutex;
use std::time::Duration;

use hmac::{Hmac, Mac};
use log::debug;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use url::Url;

use crate::{RemoteError, Result, USER_AGENT};

type HmacSha256 = Hmac<Sha256>;

/// Default EC2 Instance Metadata Service base URL.
const DEFAULT_IMDS_BASE: &str = "http://169.254.169.254";
/// Default ECS credentials host for relative URIs.
const DEFAULT_ECS_CREDS_HOST: &str = "http://169.254.170.2";
/// Refresh cached role creds this long before their stated expiration.
const CREDS_EXPIRY_SKEW: Duration = Duration::from_secs(120);

/// Parsed `s3://bucket/key` location.
#[derive(Debug, Clone)]
pub struct S3Location {
    pub bucket: String,
    pub key: String,
}

/// Parse `s3://bucket/key/with/slashes`.
pub fn parse_s3_url(url_str: &str) -> Result<S3Location> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    if url.scheme() != "s3" {
        return Err(RemoteError::UnsupportedScheme(url.scheme().to_string()));
    }
    let bucket = url
        .host_str()
        .ok_or_else(|| RemoteError::Url("s3 URL missing bucket (s3://bucket/key)".into()))?
        .to_string();
    let key = url.path().trim_start_matches('/').to_string();
    if key.is_empty() {
        return Err(RemoteError::Url("s3 URL missing object key".into()));
    }
    Ok(S3Location { bucket, key })
}

#[derive(Clone, Debug)]
struct AwsCreds {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    /// Absolute UTC expiry when known (IMDS / ECS); `None` for static env keys.
    expiration: Option<chrono::DateTime<chrono::Utc>>,
}

/// How credentials were obtained (for logging / errors).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredSource {
    Env,
    Container,
    Imds,
    Anonymous,
}

#[derive(Clone, Debug)]
struct ResolvedAuth {
    source: CredSource,
    /// `None` means unsigned / anonymous GET.
    creds: Option<AwsCreds>,
}

/// Process-wide cache for temporary role credentials (IMDS / ECS).
static ROLE_CREDS_CACHE: Mutex<Option<(CredSource, AwsCreds)>> = Mutex::new(None);

fn region() -> String {
    std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| "us-east-1".into())
}

fn custom_endpoint() -> Option<String> {
    std::env::var("AWS_ENDPOINT_URL")
        .or_else(|_| std::env::var("S3_ENDPOINT_URL"))
        .ok()
        .filter(|s| !s.is_empty())
}

/// True when anonymous / public-bucket access is explicitly enabled.
fn anonymous_enabled() -> bool {
    env_truthy("AWS_ANONYMOUS") || env_truthy("RATARMOUNT_S3_ANONYMOUS")
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

fn imds_base() -> String {
    non_empty_env("RATARMOUNT_IMDS_BASE")
        .or_else(|| non_empty_env("AWS_EC2_METADATA_SERVICE_ENDPOINT"))
        .unwrap_or_else(|| DEFAULT_IMDS_BASE.into())
        .trim_end_matches('/')
        .to_string()
}

fn creds_still_valid(creds: &AwsCreds) -> bool {
    match creds.expiration {
        None => true,
        Some(exp) => {
            let skew = chrono::Duration::from_std(CREDS_EXPIRY_SKEW).unwrap_or_default();
            chrono::Utc::now() + skew < exp
        }
    }
}

fn take_cached_role_creds() -> Option<(CredSource, AwsCreds)> {
    let guard = ROLE_CREDS_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .filter(|(_, c)| creds_still_valid(c))
        .cloned()
}

fn store_role_creds(source: CredSource, creds: AwsCreds) {
    if let Ok(mut guard) = ROLE_CREDS_CACHE.lock() {
        *guard = Some((source, creds));
    }
}

/// Clear the role-credential cache (used by tests).
#[cfg(test)]
fn clear_role_creds_cache() {
    if let Ok(mut guard) = ROLE_CREDS_CACHE.lock() {
        *guard = None;
    }
}

fn load_env_credentials() -> Result<Option<AwsCreds>> {
    let access_key = non_empty_env("AWS_ACCESS_KEY_ID");
    let secret_key = non_empty_env("AWS_SECRET_ACCESS_KEY");
    match (access_key, secret_key) {
        (Some(access_key), Some(secret_key)) => {
            let session_token = non_empty_env("AWS_SESSION_TOKEN");
            Ok(Some(AwsCreds {
                access_key,
                secret_key,
                session_token,
                expiration: None,
            }))
        }
        (Some(_), None) => Err(RemoteError::S3(
            "AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is missing or empty".into(),
        )),
        (None, Some(_)) => Err(RemoteError::S3(
            "AWS_SECRET_ACCESS_KEY is set but AWS_ACCESS_KEY_ID is missing or empty".into(),
        )),
        (None, None) => Ok(None),
    }
}

fn parse_credential_json(body: &str) -> Result<AwsCreds> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        RemoteError::S3(format!("failed to parse instance/container credentials JSON: {e}"))
    })?;
    let access_key = v
        .get("AccessKeyId")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| RemoteError::S3("credentials JSON missing AccessKeyId".into()))?
        .to_string();
    let secret_key = v
        .get("SecretAccessKey")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| RemoteError::S3("credentials JSON missing SecretAccessKey".into()))?
        .to_string();
    let session_token = v
        .get("Token")
        .or_else(|| v.get("SessionToken"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let expiration = v
        .get("Expiration")
        .and_then(|x| x.as_str())
        .and_then(parse_expiration);
    Ok(AwsCreds {
        access_key,
        secret_key,
        session_token,
        expiration,
    })
}

fn parse_expiration(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    // IMDS/ECS typically use RFC 3339 ("2024-01-02T03:04:05Z").
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
                .ok()
                .map(|ndt| ndt.and_utc())
        })
}

fn http_get_text(url: &str, extra_headers: &[(&str, &str)]) -> Result<String> {
    let mut req = ureq::get(url).set("User-Agent", USER_AGENT);
    for (k, v) in extra_headers {
        req = req.set(k, v);
    }
    // Short timeout: IMDS/ECS should be local; long hangs are unhelpful offline.
    req = req.timeout(Duration::from_secs(2));
    let resp = req
        .call()
        .map_err(|e| RemoteError::S3(format!("credential HTTP GET {url}: {e}")))?;
    let status = resp.status();
    let body = resp.into_string().unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(RemoteError::S3(format!(
            "credential HTTP GET {url}: status {status}: {body}"
        )));
    }
    Ok(body)
}

fn http_put_text(url: &str, extra_headers: &[(&str, &str)]) -> Result<String> {
    let mut req = ureq::put(url).set("User-Agent", USER_AGENT);
    for (k, v) in extra_headers {
        req = req.set(k, v);
    }
    req = req.timeout(Duration::from_secs(2));
    let resp = req
        .call()
        .map_err(|e| RemoteError::S3(format!("credential HTTP PUT {url}: {e}")))?;
    let status = resp.status();
    let body = resp.into_string().unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(RemoteError::S3(format!(
            "credential HTTP PUT {url}: status {status}: {body}"
        )));
    }
    Ok(body)
}

fn container_auth_headers() -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(token) = non_empty_env("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
        out.push(("Authorization".into(), token));
    } else if let Some(path) = non_empty_env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
        if let Ok(token) = std::fs::read_to_string(&path) {
            let t = token.trim();
            if !t.is_empty() {
                out.push(("Authorization".into(), t.to_string()));
            }
        }
    }
    out
}

fn container_credentials_url() -> Option<String> {
    if let Some(full) = non_empty_env("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
        return Some(full);
    }
    if let Some(rel) = non_empty_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        let rel = if rel.starts_with('/') {
            rel
        } else {
            format!("/{rel}")
        };
        return Some(format!(
            "{}{}",
            DEFAULT_ECS_CREDS_HOST.trim_end_matches('/'),
            rel
        ));
    }
    None
}

fn fetch_container_credentials() -> Result<AwsCreds> {
    let url = container_credentials_url().ok_or_else(|| {
        RemoteError::S3(
            "no ECS container credentials URI \
             (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI / FULL_URI)"
                .into(),
        )
    })?;
    let auth = container_auth_headers();
    let headers: Vec<(&str, &str)> = auth.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    debug!("s3: fetching ECS container credentials from {url}");
    let body = http_get_text(&url, &headers)?;
    parse_credential_json(&body)
}

/// IMDSv2 token, then list role + fetch credentials. Falls back to IMDSv1 (no token)
/// if the token PUT fails (common on older paths / some mocks).
fn fetch_imds_credentials() -> Result<AwsCreds> {
    let base = imds_base();
    let token = match http_put_text(
        &format!("{base}/latest/api/token"),
        &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
    ) {
        Ok(t) => {
            let t = t.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        Err(e) => {
            debug!("s3: IMDSv2 token request failed ({e}); trying IMDSv1");
            None
        }
    };

    let headers: Vec<(&str, &str)> = match &token {
        Some(t) => vec![("X-aws-ec2-metadata-token", t.as_str())],
        None => Vec::new(),
    };

    let role_list_url = format!("{base}/latest/meta-data/iam/security-credentials/");
    debug!("s3: listing IMDS IAM roles at {role_list_url}");
    let roles_body = http_get_text(&role_list_url, &headers)?;
    let role = roles_body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| {
            RemoteError::S3("IMDS returned no IAM role name under security-credentials/".into())
        })?
        .to_string();

    let creds_url = format!("{base}/latest/meta-data/iam/security-credentials/{role}");
    debug!("s3: fetching IMDS credentials for role {role}");
    let body = http_get_text(&creds_url, &headers)?;
    parse_credential_json(&body)
}

/// Resolve auth for a GetObject: env → container/IMDS (cached) → anonymous → error.
fn resolve_auth() -> Result<ResolvedAuth> {
    // 1. Explicit env keys
    if let Some(creds) = load_env_credentials()? {
        return Ok(ResolvedAuth {
            source: CredSource::Env,
            creds: Some(creds),
        });
    }

    // 2. Cached role credentials
    if let Some((source, creds)) = take_cached_role_creds() {
        debug!("s3: using cached {:?} credentials", source);
        return Ok(ResolvedAuth {
            source,
            creds: Some(creds),
        });
    }

    let mut tried: Vec<&str> = vec!["env AWS_ACCESS_KEY_ID"];
    let mut role_errors: Vec<String> = Vec::new();

    // 2a. ECS container credentials
    if container_credentials_url().is_some() {
        tried.push("ECS container role");
        match fetch_container_credentials() {
            Ok(creds) => {
                store_role_creds(CredSource::Container, creds.clone());
                return Ok(ResolvedAuth {
                    source: CredSource::Container,
                    creds: Some(creds),
                });
            }
            Err(e) => {
                debug!("s3: container credentials failed: {e}");
                role_errors.push(format!("ECS: {e}"));
            }
        }
    } else {
        tried.push("ECS container role (URI unset)");
    }

    // 2b. EC2 IMDS
    tried.push("EC2 IMDS");
    match fetch_imds_credentials() {
        Ok(creds) => {
            store_role_creds(CredSource::Imds, creds.clone());
            return Ok(ResolvedAuth {
                source: CredSource::Imds,
                creds: Some(creds),
            });
        }
        Err(e) => {
            debug!("s3: IMDS credentials failed: {e}");
            role_errors.push(format!("IMDS: {e}"));
        }
    }

    // 3. Anonymous if enabled (also covers intentional empty keys + flag)
    if anonymous_enabled() {
        debug!("s3: using anonymous (unsigned) access");
        return Ok(ResolvedAuth {
            source: CredSource::Anonymous,
            creds: None,
        });
    }

    // 4. Clear error
    let mut msg = format!(
        "no AWS credentials found for s3://; tried: {}; \
         set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, run on ECS/EC2 with a task/instance role, \
         or set AWS_ANONYMOUS=1 / RATARMOUNT_S3_ANONYMOUS=1 for public buckets",
        tried.join(", ")
    );
    if !role_errors.is_empty() {
        msg.push_str(&format!(" (role errors: {})", role_errors.join("; ")));
    }
    Err(RemoteError::S3(msg))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Build host + URI path + https flag for the GetObject request.
fn s3_request_target(loc: &S3Location, region: &str) -> (String, String, bool) {
    if let Some(endpoint) = custom_endpoint() {
        let ep = endpoint.trim_end_matches('/');
        let (scheme, rest) = if let Some(r) = ep.strip_prefix("https://") {
            ("https", r)
        } else if let Some(r) = ep.strip_prefix("http://") {
            ("http", r)
        } else {
            ("https", ep)
        };
        // Path-style: {endpoint}/{bucket}/{key}
        let host = rest.split('/').next().unwrap_or(rest).to_string();
        let path = format!(
            "/{}/{}",
            loc.bucket,
            loc.key
                .split('/')
                .map(urlencoding_encode)
                .collect::<Vec<_>>()
                .join("/")
        );
        (host, path, scheme == "https")
    } else {
        // Virtual-hosted–style: https://{bucket}.s3.{region}.amazonaws.com/{key}
        let host = if region == "us-east-1" {
            format!("{}.s3.amazonaws.com", loc.bucket)
        } else {
            format!("{}.s3.{region}.amazonaws.com", loc.bucket)
        };
        let path = format!(
            "/{}",
            loc.key
                .split('/')
                .map(urlencoding_encode)
                .collect::<Vec<_>>()
                .join("/")
        );
        (host, path, true)
    }
}

/// Download `s3://bucket/key` to a tempfile.
///
/// Credential chain: env keys → ECS/IMDS role → anonymous (if enabled) → error.
/// See module docs for env knobs.
pub fn fetch_s3_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_s3_url(url_str)?;
    fetch_s3_location_to_temp(&loc)
}

pub fn fetch_s3_location_to_temp(loc: &S3Location) -> Result<(NamedTempFile, u64)> {
    let auth = resolve_auth()?;
    let region = region();
    let (host, uri_path, use_https) = s3_request_target(loc, &region);

    let url = if use_https {
        format!("https://{host}{uri_path}")
    } else {
        format!("http://{host}{uri_path}")
    };
    debug!("s3 GET {url} (auth={:?})", auth.source);

    let resp = match &auth.creds {
        None => {
            // Anonymous: plain GET, no Authorization (public buckets).
            ureq::get(&url)
                .set("User-Agent", USER_AGENT)
                .call()
                .map_err(|e| {
                    RemoteError::S3(format!(
                        "anonymous GetObject s3://{}/{}: {e}",
                        loc.bucket, loc.key
                    ))
                })?
        }
        Some(creds) => {
            let now = chrono::Utc::now();
            let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
            let date_stamp = now.format("%Y%m%d").to_string();
            let payload_hash = sha256_hex(b"");
            let mut headers_to_sign: Vec<(&str, String)> = vec![
                ("host", host.clone()),
                ("x-amz-content-sha256", payload_hash.clone()),
                ("x-amz-date", amz_date.clone()),
            ];
            if let Some(token) = &creds.session_token {
                headers_to_sign.push(("x-amz-security-token", token.clone()));
            }
            headers_to_sign.sort_by(|a, b| a.0.cmp(b.0));

            let signed_headers = headers_to_sign
                .iter()
                .map(|(k, _)| *k)
                .collect::<Vec<_>>()
                .join(";");
            let canonical_headers = headers_to_sign
                .iter()
                .map(|(k, v)| format!("{k}:{}\n", v.trim()))
                .collect::<String>();

            let canonical_request = format!(
                "GET\n{uri_path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
            );
            let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
                sha256_hex(canonical_request.as_bytes())
            );
            let signature = hex::encode(hmac_sha256(
                &signing_key(&creds.secret_key, &date_stamp, &region, "s3"),
                string_to_sign.as_bytes(),
            ));
            let authorization = format!(
                "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
                creds.access_key
            );

            let mut req = ureq::get(&url)
                .set("User-Agent", USER_AGENT)
                .set("Authorization", &authorization)
                .set("x-amz-content-sha256", &payload_hash)
                .set("x-amz-date", &amz_date);
            if let Some(token) = &creds.session_token {
                req = req.set("x-amz-security-token", token);
            }
            req.call().map_err(|e| {
                RemoteError::S3(format!("GetObject s3://{}/{}: {e}", loc.bucket, loc.key))
            })?
        }
    };

    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        let kind = if auth.source == CredSource::Anonymous {
            "anonymous GetObject"
        } else {
            "GetObject"
        };
        return Err(RemoteError::S3(format!(
            "{kind} HTTP {status} for s3://{}/{}: {body}",
            loc.bucket, loc.key
        )));
    }

    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = std::io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok((tmp, n))
}

/// Minimal path-segment encode (RFC 3986 unreserved + leave already-safe chars).
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::thread;

    /// Serialize tests that mutate process environment / credential cache.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            clear_role_creds_cache();
            let mut saved = Vec::new();
            for &k in keys {
                saved.push((k.to_string(), std::env::var(k).ok()));
                std::env::remove_var(k);
            }
            Self {
                saved,
                _lock: lock,
            }
        }

        fn set(&self, key: &str, val: &str) {
            std::env::set_var(key, val);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            clear_role_creds_cache();
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    const AWS_ENV_KEYS: &[&str] = &[
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ENDPOINT_URL",
        "S3_ENDPOINT_URL",
        "AWS_ANONYMOUS",
        "RATARMOUNT_S3_ANONYMOUS",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "RATARMOUNT_IMDS_BASE",
        "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    ];

    fn sample_creds_json(exp: &str) -> String {
        format!(
            r#"{{
            "AccessKeyId": "ASIA_TEST_KEY",
            "SecretAccessKey": "test-secret-key-material",
            "Token": "session-token-abc",
            "Expiration": "{exp}"
        }}"#
        )
    }

    fn far_future_expiration() -> String {
        (chrono::Utc::now() + chrono::Duration::hours(6))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    /// Minimal HTTP/1.1 mock that routes by path prefix.
    struct MockMeta {
        addr: String,
        base_url: String,
        log: Arc<StdMutex<Vec<String>>>,
        gets: Arc<AtomicUsize>,
        puts: Arc<AtomicUsize>,
        _join: Option<thread::JoinHandle<()>>,
    }

    enum MetaMode {
        /// ECS-style: GET any path → credentials JSON (optional Authorization).
        Container {
            body: String,
            require_auth: Option<String>,
        },
        /// IMDS: PUT /latest/api/token, GET role list, GET role creds.
        Imds {
            role: String,
            body: String,
            /// If true, require IMDSv2 token header on GETs.
            require_token: bool,
        },
    }

    impl MockMeta {
        fn spawn(mode: MetaMode) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let local = listener.local_addr().unwrap();
            let base_url = format!("http://{local}");
            let addr = base_url.clone();
            let log = Arc::new(StdMutex::new(Vec::new()));
            let gets = Arc::new(AtomicUsize::new(0));
            let puts = Arc::new(AtomicUsize::new(0));
            let log_c = Arc::clone(&log);
            let gets_c = Arc::clone(&gets);
            let puts_c = Arc::clone(&puts);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut headers = Vec::new();
                    let mut auth: Option<String> = None;
                    let mut imds_token: Option<String> = None;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        headers.push(line.clone());
                        if let Some(v) = line.strip_prefix("Authorization:") {
                            auth = Some(v.trim().to_string());
                        }
                        let lower = line.to_ascii_lowercase();
                        if let Some(rest) = lower.strip_prefix("x-aws-ec2-metadata-token:") {
                            // recover original value from `line`
                            if let Some(v) = line.split_once(':') {
                                imds_token = Some(v.1.trim().to_string());
                            }
                            let _ = rest;
                        }
                    }
                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                    }

                    let is_put = request_line.starts_with("PUT ");
                    let is_get = request_line.starts_with("GET ");
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();

                    match &mode {
                        MetaMode::Container {
                            body,
                            require_auth,
                        } => {
                            if !is_get {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                continue;
                            }
                            if let Some(need) = require_auth {
                                if auth.as_deref() != Some(need.as_str()) {
                                    let msg = b"unauthorized";
                                    let _ = write!(
                                        stream,
                                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        msg.len()
                                    );
                                    let _ = stream.write_all(msg);
                                    continue;
                                }
                            }
                            gets_c.fetch_add(1, Ordering::SeqCst);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                        }
                        MetaMode::Imds {
                            role,
                            body,
                            require_token,
                        } => {
                            if is_put && path.starts_with("/latest/api/token") {
                                puts_c.fetch_add(1, Ordering::SeqCst);
                                let tok = b"mock-imds-token";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    tok.len()
                                );
                                let _ = stream.write_all(tok);
                                continue;
                            }
                            if !is_get {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                continue;
                            }
                            if *require_token
                                && imds_token.as_deref() != Some("mock-imds-token")
                            {
                                let msg = b"IMDSv2 token required";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    msg.len()
                                );
                                let _ = stream.write_all(msg);
                                continue;
                            }
                            gets_c.fetch_add(1, Ordering::SeqCst);
                            if path == "/latest/meta-data/iam/security-credentials/"
                                || path == "/latest/meta-data/iam/security-credentials"
                            {
                                let list = format!("{role}\n");
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{list}",
                                    list.len()
                                );
                            } else if path
                                == format!("/latest/meta-data/iam/security-credentials/{role}")
                            {
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                            } else {
                                let msg = b"not found";
                                let _ = write!(
                                    stream,
                                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    msg.len()
                                );
                                let _ = stream.write_all(msg);
                            }
                        }
                    }
                }
            });
            Self {
                addr,
                base_url,
                log,
                gets,
                puts,
                _join: Some(join),
            }
        }
    }

    /// Path-style S3 mock: GET /{bucket}/{key} → body; records Authorization presence.
    struct MockS3 {
        base_url: String,
        log: Arc<StdMutex<Vec<String>>>,
        gets: Arc<AtomicUsize>,
        auth_headers: Arc<AtomicUsize>,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockS3 {
        fn spawn(body: Vec<u8>, require_auth: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let local = listener.local_addr().unwrap();
            let base_url = format!("http://{local}");
            let log = Arc::new(StdMutex::new(Vec::new()));
            let gets = Arc::new(AtomicUsize::new(0));
            let auth_headers = Arc::new(AtomicUsize::new(0));
            let log_c = Arc::clone(&log);
            let gets_c = Arc::clone(&gets);
            let auth_c = Arc::clone(&auth_headers);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(32) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut has_auth = false;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        if line.to_ascii_lowercase().starts_with("authorization:") {
                            has_auth = true;
                        }
                    }
                    {
                        let mut lg = log_c.lock().unwrap();
                        lg.push(request_line.trim().to_string());
                        if has_auth {
                            lg.push("Authorization: present".into());
                        } else {
                            lg.push("Authorization: absent".into());
                        }
                    }
                    if has_auth {
                        auth_c.fetch_add(1, Ordering::SeqCst);
                    }
                    if !request_line.starts_with("GET ") {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }
                    if require_auth && !has_auth {
                        let msg = b"AccessDenied";
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
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(&body);
                }
            });
            Self {
                base_url,
                log,
                gets,
                auth_headers,
                _join: Some(join),
            }
        }
    }

    #[test]
    fn parse_bucket_key() {
        let l = parse_s3_url("s3://my-bucket/path/to/archive.tar.gz").unwrap();
        assert_eq!(l.bucket, "my-bucket");
        assert_eq!(l.key, "path/to/archive.tar.gz");
    }

    #[test]
    fn reject_missing_key() {
        assert!(parse_s3_url("s3://only-bucket/").is_err());
    }

    #[test]
    fn sig_helpers_smoke() {
        assert_eq!(sha256_hex(b"").len(), 64);
        assert!(!hmac_sha256(b"key", b"data").is_empty());
    }

    #[test]
    fn parse_credential_json_with_expiration() {
        let exp = far_future_expiration();
        let json = sample_creds_json(&exp);
        let c = parse_credential_json(&json).unwrap();
        assert_eq!(c.access_key, "ASIA_TEST_KEY");
        assert_eq!(c.secret_key, "test-secret-key-material");
        assert_eq!(c.session_token.as_deref(), Some("session-token-abc"));
        assert!(c.expiration.is_some());
        assert!(creds_still_valid(&c));
    }

    #[test]
    fn parse_credential_json_expired_not_valid() {
        let json = sample_creds_json("2000-01-01T00:00:00Z");
        let c = parse_credential_json(&json).unwrap();
        assert!(!creds_still_valid(&c));
    }

    #[test]
    fn env_credentials_preferred() {
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAENV");
        _g.set("AWS_SECRET_ACCESS_KEY", "envsecret");
        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source, CredSource::Env);
        let c = auth.creds.unwrap();
        assert_eq!(c.access_key, "AKIAENV");
        assert_eq!(c.secret_key, "envsecret");
    }

    #[test]
    fn incomplete_env_keys_error() {
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAONLY");
        let err = resolve_auth().unwrap_err().to_string();
        assert!(
            err.contains("AWS_SECRET_ACCESS_KEY"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn container_credentials_full_uri() {
        let exp = far_future_expiration();
        let body = sample_creds_json(&exp);
        let mock = MockMeta::spawn(MetaMode::Container {
            body,
            require_auth: Some("Bearer task-token".into()),
        });
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            &format!("{}/v2/credentials/task", mock.base_url),
        );
        _g.set("AWS_CONTAINER_AUTHORIZATION_TOKEN", "Bearer task-token");
        // Point IMDS at an unreachable address so a hang is not possible if chain falls through.
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source, CredSource::Container);
        let c = auth.creds.unwrap();
        assert_eq!(c.access_key, "ASIA_TEST_KEY");
        assert_eq!(c.session_token.as_deref(), Some("session-token-abc"));
        assert!(mock.gets.load(Ordering::SeqCst) >= 1);

        // Second resolve hits cache (no extra GET required, though mock may still be up).
        let before = mock.gets.load(Ordering::SeqCst);
        let auth2 = resolve_auth().unwrap();
        assert_eq!(auth2.source, CredSource::Container);
        assert_eq!(
            mock.gets.load(Ordering::SeqCst),
            before,
            "cached container creds should not re-fetch"
        );
        let _ = &mock.addr;
        let _ = &mock.log;
    }

    #[test]
    fn imds_v2_credentials() {
        let exp = far_future_expiration();
        let body = sample_creds_json(&exp);
        let mock = MockMeta::spawn(MetaMode::Imds {
            role: "MyInstanceRole".into(),
            body,
            require_token: true,
        });
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("RATARMOUNT_IMDS_BASE", &mock.base_url);

        let auth = resolve_auth().unwrap();
        assert_eq!(auth.source, CredSource::Imds);
        let c = auth.creds.unwrap();
        assert_eq!(c.access_key, "ASIA_TEST_KEY");
        assert!(mock.puts.load(Ordering::SeqCst) >= 1);
        assert!(mock.gets.load(Ordering::SeqCst) >= 2); // list + creds

        // Cache
        let before_gets = mock.gets.load(Ordering::SeqCst);
        let auth2 = resolve_auth().unwrap();
        assert_eq!(auth2.source, CredSource::Imds);
        assert_eq!(mock.gets.load(Ordering::SeqCst), before_gets);
        let _ = &mock.log;
    }

    #[test]
    fn anonymous_public_get() {
        let payload = b"public-s3-object-bytes".to_vec();
        let s3 = MockS3::spawn(payload.clone(), false);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ANONYMOUS", "1");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        // Ensure role probes fail fast if chain order regresses
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let (mut tmp, size) = fetch_s3_to_temp("s3://public-bucket/path/obj.bin").unwrap();
        assert_eq!(size, payload.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
        assert!(s3.gets.load(Ordering::SeqCst) >= 1);
        assert_eq!(
            s3.auth_headers.load(Ordering::SeqCst),
            0,
            "anonymous GET must not send Authorization"
        );
        let log = s3.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.contains("Authorization: absent")),
            "log={log:?}"
        );
    }

    #[test]
    fn anonymous_failure_message_distinct() {
        let s3 = MockS3::spawn(b"nope".to_vec(), true); // requires auth → 403 for anonymous
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("RATARMOUNT_S3_ANONYMOUS", "true");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let err = fetch_s3_to_temp("s3://bucket/key.bin")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("anonymous") && (err.contains("403") || err.contains("Forbidden")),
            "expected anonymous failure, got: {err}"
        );
    }

    #[test]
    fn missing_creds_lists_chain() {
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        // Force IMDS to a closed port so resolve fails quickly.
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let err = resolve_auth().unwrap_err().to_string();
        assert!(
            err.contains("AWS_ACCESS_KEY_ID") || err.contains("env"),
            "unexpected: {err}"
        );
        assert!(
            err.contains("IMDS") || err.contains("ECS") || err.contains("container"),
            "chain should list role sources: {err}"
        );
        assert!(
            err.contains("AWS_ANONYMOUS") || err.contains("RATARMOUNT_S3_ANONYMOUS"),
            "should mention anonymous option: {err}"
        );
    }

    #[test]
    fn empty_env_keys_fall_through_to_anonymous() {
        let payload = b"empty-key-anon".to_vec();
        let s3 = MockS3::spawn(payload.clone(), false);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        // Intentionally empty keys should not count as "explicit env".
        _g.set("AWS_ACCESS_KEY_ID", "");
        _g.set("AWS_SECRET_ACCESS_KEY", "");
        _g.set("AWS_ANONYMOUS", "1");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let (mut tmp, size) = fetch_s3_to_temp("s3://b/k").unwrap();
        assert_eq!(size, payload.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn signed_get_with_env_against_mock() {
        let payload = b"signed-object".to_vec();
        let s3 = MockS3::spawn(payload.clone(), true);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("AWS_REGION", "us-east-1");

        let (mut tmp, size) = fetch_s3_to_temp("s3://mybucket/obj.bin").unwrap();
        assert_eq!(size, payload.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
        assert!(s3.auth_headers.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn container_relative_uri_builds_default_host() {
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set(
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "/v2/credentials/abc",
        );
        let url = container_credentials_url().unwrap();
        assert_eq!(url, "http://169.254.170.2/v2/credentials/abc");
    }

    #[test]
    fn imds_base_override_env() {
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://10.0.0.1:9090/");
        assert_eq!(imds_base(), "http://10.0.0.1:9090");
        _g.set("RATARMOUNT_IMDS_BASE", "http://mock.local");
        // RATARMOUNT_IMDS_BASE takes precedence
        assert_eq!(imds_base(), "http://mock.local");
    }
}
