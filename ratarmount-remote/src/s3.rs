//! S3 GetObject / PutObject for `s3://bucket/key` (AWS SigV4 + ureq).
//!
//! # Upload
//!
//! [`put_s3_object`] sends at most 8 MiB. Larger staged files use
//! [`put_s3_multipart`] (8 MiB parts). A copied prefix of at least 5 MiB is
//! `UploadPartCopy` of `bytes=0-{prefix-1}`; a zero prefix uploads every byte.
//! Multipart canonical queries are the sorted query string (not empty). The
//! payload hash is SHA-256 of the bytes sent on that request, never
//! `UNSIGNED-PAYLOAD`. Empty bodies (create, copy, abort) hash `b""`.
//! Anonymous credentials are rejected. Writes use [`OBJECT_STORE_IO_TIMEOUT`].
//!
//! # Download paths
//!
//! - **Full GetObject** — single GET of the whole object (small objects / fallback)
//! - **Range GetObject** — signed (or anonymous) GET with `Range: bytes=start-end`
//!   ([`fetch_s3_range_bytes`], inclusive end)
//! - **Prefer-range materialize** — when object size is known and exceeds
//!   [`DEFAULT_S3_RANGE_THRESHOLD`], sequential Range GETs in
//!   [`crate::HTTP_RANGE_CHUNK`] windows into a tempfile; else full GET
//! - **Live Range I/O** — [`S3RangeFile`] / [`open_s3_range`] issues per-read Range GETs
//!
//! Size discovery uses a `Range: bytes=0-0` probe (`Content-Range` total), matching
//! the HTTP / Dropbox prefer-range patterns in this crate.
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

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// Per-thread stand-in for AWS env vars. Parallel `s3_*` tests in other modules
/// also mutate `AWS_ENDPOINT_URL`; a process-global env would cross wires.
#[cfg(test)]
struct TestS3Override {
    access_key: String,
    secret_key: String,
    region: String,
    endpoint: String,
    anonymous: bool,
}

#[cfg(test)]
thread_local! {
    // `const { RefCell::new(None) }` needs Rust 1.79; MSRV is 1.74.
    #[allow(clippy::missing_const_for_thread_local)]
    static TEST_S3_OVERRIDE: std::cell::RefCell<Option<TestS3Override>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn test_s3_override() -> Option<TestS3Override> {
    TEST_S3_OVERRIDE.with(|slot| {
        slot.borrow().as_ref().map(|over| TestS3Override {
            access_key: over.access_key.clone(),
            secret_key: over.secret_key.clone(),
            region: over.region.clone(),
            endpoint: over.endpoint.clone(),
            anonymous: over.anonymous,
        })
    })
}

use hmac::{Hmac, Mac};
use log::debug;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use url::Url;

use crate::{
    parse_content_range_total, range_chunk_windows, RemoteError, Result, HTTP_RANGE_CHUNK,
    USER_AGENT,
};

/// Objects larger than this prefer chunked Range downloads (1 MiB).
pub const DEFAULT_S3_RANGE_THRESHOLD: u64 = 1024 * 1024;

/// PutObject ceiling and multipart part size (8 MiB). Above 10_000 parts is an error.
const S3_PUT_PART_BYTES: u64 = 8 * 1024 * 1024;
/// S3 rejects `UploadPartCopy` below this except as the last part (5 MiB).
const S3_COPY_PART_MIN: u64 = 5 * 1024 * 1024;
const S3_MULTIPART_MAX_PARTS: u64 = 10_000;

/// Socket budget for object-store GET chunks and PUT / multipart calls.
/// IMDS and ECS credential fetches stay on their own 2s timeout.
pub const OBJECT_STORE_IO_TIMEOUT: Duration = Duration::from_secs(120);

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
///
/// Rejects an empty key (`s3://bucket` / `s3://bucket/`). Folder mounts use
/// [`parse_s3_url_allow_prefix`].
pub fn parse_s3_url(url_str: &str) -> Result<S3Location> {
    let loc = parse_s3_url_allow_prefix(url_str)?;
    if loc.key.is_empty() {
        return Err(RemoteError::Url("s3 URL missing object key".into()));
    }
    Ok(loc)
}

/// Like [`parse_s3_url`], but an empty key is the bucket root (prefix folder).
pub fn parse_s3_url_allow_prefix(url_str: &str) -> Result<S3Location> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    if url.scheme() != "s3" {
        return Err(RemoteError::UnsupportedScheme(url.scheme().to_string()));
    }
    let bucket = url
        .host_str()
        .ok_or_else(|| RemoteError::Url("s3 URL missing bucket (s3://bucket/key)".into()))?
        .to_string();
    let key = url.path().trim_start_matches('/').to_string();
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
    #[cfg(test)]
    if let Some(over) = test_s3_override() {
        return over.region;
    }
    std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| "us-east-1".into())
}

fn custom_endpoint() -> Option<String> {
    #[cfg(test)]
    if let Some(over) = test_s3_override() {
        if !over.endpoint.is_empty() {
            return Some(over.endpoint);
        }
    }
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
        RemoteError::S3(format!(
            "failed to parse instance/container credentials JSON: {e}"
        ))
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
    #[cfg(test)]
    if let Some(over) = test_s3_override() {
        if over.anonymous {
            return Ok(ResolvedAuth {
                source: CredSource::Anonymous,
                creds: None,
            });
        }
        return Ok(ResolvedAuth {
            source: CredSource::Env,
            creds: Some(AwsCreds {
                access_key: over.access_key,
                secret_key: over.secret_key,
                session_token: None,
                expiration: None,
            }),
        });
    }
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

/// Issue GetObject, optionally with an inclusive `Range: bytes=start-end`.
///
/// SigV4 signs the `Range` header when present (required by AWS). Anonymous mode
/// sends an unsigned GET with the same optional Range.
fn s3_get_object(
    loc: &S3Location,
    range: Option<(u64, u64)>,
) -> Result<(CredSource, ureq::Response)> {
    let auth = resolve_auth()?;
    let region = region();
    let (host, uri_path, use_https) = s3_request_target(loc, &region);

    let url = if use_https {
        format!("https://{host}{uri_path}")
    } else {
        format!("http://{host}{uri_path}")
    };
    let range_value = range.map(|(start, end)| format!("bytes={start}-{end}"));
    debug!(
        "s3 GET {url} (auth={:?}, range={:?})",
        auth.source, range_value
    );

    let resp = match &auth.creds {
        None => {
            // Anonymous: plain GET, no Authorization (public buckets).
            let mut req = ureq::get(&url).set("User-Agent", USER_AGENT);
            if let Some(ref r) = range_value {
                req = req.set("Range", r);
            }
            req.call().map_err(|e| {
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
            if let Some(ref r) = range_value {
                // Range must be included in the SigV4 signed headers for AWS.
                headers_to_sign.push(("range", r.clone()));
            }
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

            let canonical_request =
                format!("GET\n{uri_path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
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
            if let Some(ref r) = range_value {
                req = req.set("Range", r);
            }
            if let Some(token) = &creds.session_token {
                req = req.set("x-amz-security-token", token);
            }
            req.call().map_err(|e| {
                RemoteError::S3(format!("GetObject s3://{}/{}: {e}", loc.bucket, loc.key))
            })?
        }
    };

    Ok((auth.source, resp))
}

fn s3_status_error(source: CredSource, status: u16, loc: &S3Location, body: &str) -> RemoteError {
    let kind = if source == CredSource::Anonymous {
        "anonymous GetObject"
    } else {
        "GetObject"
    };
    RemoteError::S3(format!(
        "{kind} HTTP {status} for s3://{}/{}: {body}",
        loc.bucket, loc.key
    ))
}

struct S3CallCtx {
    source: CredSource,
    creds: AwsCreds,
    region: String,
    host: String,
    uri_path: String,
    https: bool,
}

struct S3HttpResult {
    status: u16,
    body: String,
    etag: Option<String>,
}

struct MultipartPlan {
    /// Part 1 is `UploadPartCopy` of `[0, prefix)`.
    copy_prefix: bool,
    /// Part 1 is a normal `UploadPart` of a prefix below [`S3_COPY_PART_MIN`].
    upload_prefix: bool,
    /// First byte of the trailing `UploadPart`s.
    data_from: u64,
    /// One empty `UploadPart` (S3 rejects a complete with zero parts).
    empty_object: bool,
    len: u64,
    prefix: u64,
}

/// Anonymous GET stays allowed. Writes need a signing key.
fn prepare_s3_write(loc: &S3Location) -> Result<S3CallCtx> {
    let auth = resolve_auth()?;
    let Some(creds) = auth.creds else {
        return Err(RemoteError::S3(
            "anonymous credentials cannot PutObject or upload multipart; public buckets stay GET-only"
                .into(),
        ));
    };
    let region = region();
    let (host, uri_path, https) = s3_request_target(loc, &region);
    Ok(S3CallCtx {
        source: auth.source,
        creds,
        region,
        host,
        uri_path,
        https,
    })
}

fn s3_http_url(https: bool, host: &str, path: &str, query: &str) -> String {
    let scheme = if https { "https" } else { "http" };
    if query.is_empty() {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}{path}?{query}")
    }
}

/// `/{bucket}/{key}` with the same per-segment encoding as [`s3_request_target`].
fn copy_source_header(loc: &S3Location) -> String {
    let key = loc
        .key
        .split('/')
        .map(urlencoding_encode)
        .collect::<Vec<_>>()
        .join("/");
    format!("/{}/{}", urlencoding_encode(&loc.bucket), key)
}

impl S3CallCtx {
    /// SigV4 for one write. Payload hash is SHA-256 of `body` (empty when the
    /// request has no bytes). `query` is the canonical string, not a blank line.
    fn sign(
        &self,
        verb: &str,
        query: &str,
        body: &[u8],
        extra_signed: &[(&str, &str)],
    ) -> (String, String, String) {
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = sha256_hex(body);
        let mut headers_to_sign: Vec<(&str, String)> = vec![
            ("host", self.host.clone()),
            ("x-amz-content-sha256", payload_hash.clone()),
            ("x-amz-date", amz_date.clone()),
        ];
        if let Some(token) = &self.creds.session_token {
            headers_to_sign.push(("x-amz-security-token", token.clone()));
        }
        for (name, value) in extra_signed {
            debug_assert!(
                !name.bytes().any(|b| b.is_ascii_uppercase()),
                "signed header {name} must be lowercase"
            );
            headers_to_sign.push((*name, (*value).to_string()));
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
            "{verb}\n{}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            self.uri_path
        );
        let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = hex::encode(hmac_sha256(
            &signing_key(&self.creds.secret_key, &date_stamp, &self.region, "s3"),
            string_to_sign.as_bytes(),
        ));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.creds.access_key
        );
        (authorization, payload_hash, amz_date)
    }

    /// `extra_signed` names are lowercase and are part of the canonical request.
    /// `unsigned` is sent but not signed (`If-Match` on PutObject and Complete).
    fn execute(
        &self,
        verb: &str,
        query_params: &[(&str, &str)],
        body: &[u8],
        extra_signed: &[(&str, &str)],
        unsigned: &[(&str, &str)],
        upload_id: Option<&str>,
    ) -> Result<S3HttpResult> {
        let query = s3_canonical_query(query_params);
        // Upload id and canonical query only. Never the secret, session token, or Authorization.
        debug!(
            "s3 {verb} {} query={query} upload_id={} (auth={:?})",
            self.uri_path,
            upload_id.unwrap_or("-"),
            self.source
        );
        let (authorization, payload_hash, amz_date) = self.sign(verb, &query, body, extra_signed);
        let url = s3_http_url(self.https, &self.host, &self.uri_path, &query);
        let mut req = ureq::request(verb, &url)
            .set("User-Agent", USER_AGENT)
            .set("Authorization", &authorization)
            .set("x-amz-content-sha256", &payload_hash)
            .set("x-amz-date", &amz_date);
        if let Some(token) = &self.creds.session_token {
            req = req.set("x-amz-security-token", token);
        }
        for (name, value) in extra_signed {
            req = req.set(name, value);
        }
        for (name, value) in unsigned {
            req = req.set(name, value);
        }
        let resp = match req.timeout(OBJECT_STORE_IO_TIMEOUT).send_bytes(body) {
            Ok(resp) => resp,
            Err(ureq::Error::Status(_, resp)) => resp,
            Err(e) => {
                return Err(RemoteError::S3(format!(
                    "{verb} {} query={query}: {e}",
                    self.uri_path
                )));
            }
        };
        let status = resp.status();
        let etag = resp.header("etag").map(str::to_string);
        let resp_body = resp.into_string().unwrap_or_default();
        Ok(S3HttpResult {
            status,
            body: resp_body,
            etag,
        })
    }
}

fn ensure_s3_write_ok(op: &str, resp: &S3HttpResult) -> Result<()> {
    if resp.status == 412 {
        return Err(RemoteError::S3(format!(
            "{op} HTTP 412 precondition failed: {}",
            resp.body
        )));
    }
    if !(200..300).contains(&resp.status) {
        return Err(RemoteError::S3(format!(
            "{op} HTTP {}: {}",
            resp.status, resp.body
        )));
    }
    Ok(())
}

fn require_etag(op: &str, resp: &S3HttpResult) -> Result<String> {
    ensure_s3_write_ok(op, resp)?;
    if let Some(etag) = resp.etag.as_deref().filter(|s| !s.is_empty()) {
        return Ok(etag.to_string());
    }
    xml_tag_text(&resp.body, "etag")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| RemoteError::S3(format!("{op} response missing ETag")))
}

fn xml_text(s: &str) -> String {
    // Quotes stay literal so `<ETag>"abc"</ETag>` matches S3's ETag text.
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn complete_multipart_xml(parts: &[(u32, String)]) -> String {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        xml.push_str("<Part><PartNumber>");
        xml.push_str(&number.to_string());
        xml.push_str("</PartNumber><ETag>");
        xml.push_str(&xml_text(etag));
        xml.push_str("</ETag></Part>");
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

fn plan_multipart(len: u64, prefix: u64) -> Result<MultipartPlan> {
    if prefix > len {
        return Err(RemoteError::S3(format!(
            "copy_prefix {prefix} exceeds staged object length {len}"
        )));
    }
    let copy_prefix = prefix >= S3_COPY_PART_MIN;
    let upload_prefix = prefix > 0 && !copy_prefix;
    let data_from = if prefix > 0 { prefix } else { 0 };
    let data_len = len - data_from;
    let data_parts = if data_len == 0 {
        0
    } else {
        data_len.div_ceil(S3_PUT_PART_BYTES)
    };
    let prefix_parts = u64::from(prefix > 0);
    let empty_object = len == 0;
    let total = if empty_object {
        1
    } else {
        prefix_parts + data_parts
    };
    if total > S3_MULTIPART_MAX_PARTS {
        return Err(RemoteError::S3(format!(
            "multipart upload needs {total} parts (limit {S3_MULTIPART_MAX_PARTS}); not widening the 8 MiB part size"
        )));
    }
    Ok(MultipartPlan {
        copy_prefix,
        upload_prefix,
        data_from,
        empty_object,
        len,
        prefix,
    })
}

fn read_file_at(file: &mut File, offset: u64, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn create_multipart(ctx: &S3CallCtx) -> Result<String> {
    let resp = ctx.execute("POST", &[("uploads", "")], b"", &[], &[], None)?;
    ensure_s3_write_ok("CreateMultipartUpload", &resp)?;
    let id = xml_tag_text(&resp.body, "uploadid")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            RemoteError::S3(format!(
                "CreateMultipartUpload response missing UploadId: {}",
                resp.body
            ))
        })?;
    debug!(
        "s3 CreateMultipartUpload upload_id={id} (auth={:?})",
        ctx.source
    );
    Ok(id)
}

fn abort_multipart(ctx: &S3CallCtx, upload_id: &str) -> Result<()> {
    let resp = ctx.execute(
        "DELETE",
        &[("uploadId", upload_id)],
        b"",
        &[],
        &[],
        Some(upload_id),
    )?;
    ensure_s3_write_ok("AbortMultipartUpload", &resp)
}

fn upload_part(ctx: &S3CallCtx, part_number: u32, upload_id: &str, body: &[u8]) -> Result<String> {
    let pn = part_number.to_string();
    let resp = ctx.execute(
        "PUT",
        &[("partNumber", pn.as_str()), ("uploadId", upload_id)],
        body,
        &[],
        &[],
        Some(upload_id),
    )?;
    require_etag("UploadPart", &resp)
}

fn upload_part_copy(
    ctx: &S3CallCtx,
    loc: &S3Location,
    part_number: u32,
    prefix: u64,
    if_match: Option<&str>,
    upload_id: &str,
) -> Result<String> {
    let pn = part_number.to_string();
    // Inclusive end: the half-open span `[0, prefix)` is `bytes=0-{prefix-1}`.
    let range = format!("bytes=0-{}", prefix - 1);
    let source = copy_source_header(loc);
    let mut extra = vec![
        ("x-amz-copy-source", source.as_str()),
        ("x-amz-copy-source-range", range.as_str()),
    ];
    if let Some(etag) = if_match {
        extra.push(("x-amz-copy-source-if-match", etag));
    }
    let resp = ctx.execute(
        "PUT",
        &[("partNumber", pn.as_str()), ("uploadId", upload_id)],
        b"",
        &extra,
        &[],
        Some(upload_id),
    )?;
    require_etag("UploadPartCopy", &resp)
}

fn complete_multipart(
    ctx: &S3CallCtx,
    upload_id: &str,
    if_match: Option<&str>,
    parts: &[(u32, String)],
) -> Result<()> {
    let xml = complete_multipart_xml(parts);
    let resp = match if_match {
        Some(etag) => ctx.execute(
            "POST",
            &[("uploadId", upload_id)],
            xml.as_bytes(),
            &[],
            &[("If-Match", etag)],
            Some(upload_id),
        )?,
        None => ctx.execute(
            "POST",
            &[("uploadId", upload_id)],
            xml.as_bytes(),
            &[],
            &[],
            Some(upload_id),
        )?,
    };
    ensure_s3_write_ok("CompleteMultipartUpload", &resp)
}

fn upload_all_parts(
    ctx: &S3CallCtx,
    loc: &S3Location,
    file: &mut File,
    if_match: Option<&str>,
    upload_id: &str,
    plan: &MultipartPlan,
) -> Result<()> {
    let mut part_number: u32 = 1;
    let mut parts: Vec<(u32, String)> = Vec::new();
    if plan.copy_prefix {
        let etag = upload_part_copy(ctx, loc, part_number, plan.prefix, if_match, upload_id)?;
        parts.push((part_number, etag));
        part_number += 1;
    } else if plan.upload_prefix {
        let n = usize::try_from(plan.prefix).map_err(|_| {
            RemoteError::S3(format!(
                "copy prefix {} does not fit in memory",
                plan.prefix
            ))
        })?;
        let buf = read_file_at(file, 0, n)?;
        let etag = upload_part(ctx, part_number, upload_id, &buf)?;
        parts.push((part_number, etag));
        part_number += 1;
    }
    if plan.empty_object {
        let etag = upload_part(ctx, part_number, upload_id, b"")?;
        parts.push((part_number, etag));
    } else {
        let mut offset = plan.data_from;
        while offset < plan.len {
            let n64 = (plan.len - offset).min(S3_PUT_PART_BYTES);
            let n = usize::try_from(n64)
                .map_err(|_| RemoteError::S3(format!("part length {n64} does not fit usize")))?;
            let buf = read_file_at(file, offset, n)?;
            let etag = upload_part(ctx, part_number, upload_id, &buf)?;
            parts.push((part_number, etag));
            part_number += 1;
            offset += n64;
        }
    }
    complete_multipart(ctx, upload_id, if_match, &parts)
}

/// PutObject for a body of at most 8 MiB.
///
/// `if_match`, when set, is sent as `If-Match` (the ETag from download).
/// Anonymous credentials are an error. The payload hash is SHA-256 of `body`.
pub fn put_s3_object(loc: &S3Location, body: &[u8], if_match: Option<&str>) -> Result<()> {
    let ctx = prepare_s3_write(loc)?;
    if body.len() as u64 > S3_PUT_PART_BYTES {
        return Err(RemoteError::S3(format!(
            "PutObject body is {} bytes; max is {S3_PUT_PART_BYTES} (use multipart)",
            body.len()
        )));
    }
    let resp = match if_match {
        Some(etag) => ctx.execute("PUT", &[], body, &[], &[("If-Match", etag)], None)?,
        None => ctx.execute("PUT", &[], body, &[], &[], None)?,
    };
    ensure_s3_write_ok("PutObject", &resp)
}

/// Multipart upload of a staged file (8 MiB parts).
///
/// `copy_prefix` of `None` or `Some(0)` uploads every byte. `Some(n)` with
/// `n >= 5 MiB` copies `bytes=0-{n-1}` as part 1 and uploads the rest.
/// A smaller non-zero prefix is a normal `UploadPart` of those bytes (a copy
/// part below 5 MiB would be rejected). `if_match` is
/// `x-amz-copy-source-if-match` on the copy and `If-Match` on complete.
/// Any error after create aborts. A 412 does not call complete.
/// More than 10_000 parts is an error; the part size stays 8 MiB.
pub fn put_s3_multipart(
    loc: &S3Location,
    staged: &Path,
    copy_prefix: Option<u64>,
    if_match: Option<&str>,
) -> Result<()> {
    let ctx = prepare_s3_write(loc)?;
    let mut file = File::open(staged)
        .map_err(|e| RemoteError::S3(format!("staged file {}: {e}", staged.display())))?;
    let len = file.metadata()?.len();
    let prefix = copy_prefix.unwrap_or(0);
    let plan = plan_multipart(len, prefix)?;
    let upload_id = create_multipart(&ctx)?;
    match upload_all_parts(&ctx, loc, &mut file, if_match, &upload_id, &plan) {
        Ok(()) => Ok(()),
        Err(e) => match abort_multipart(&ctx, &upload_id) {
            Ok(()) => Err(e),
            Err(abort_err) => Err(RemoteError::S3(format!("{e}; abort failed: {abort_err}"))),
        },
    }
}

/// Download `s3://bucket/key` to a tempfile.
///
/// Prefers chunked Range materialization for large objects (see
/// [`fetch_s3_location_to_temp_prefer_range`]). Credential chain: env keys →
/// ECS/IMDS role → anonymous (if enabled) → error. See module docs for env knobs.
pub fn fetch_s3_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_s3_url(url_str)?;
    fetch_s3_location_to_temp(&loc)
}

/// Full GetObject of at most `max_bytes` (no Range). Errors if the body is larger.
pub(crate) fn fetch_s3_bytes_capped(url_str: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let loc = parse_s3_url(url_str)?;
    let (source, resp) = s3_get_object(&loc, None)?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(s3_status_error(source, status, &loc, &body));
    }
    let buf = crate::read_at_most(&mut resp.into_reader(), max_bytes)?;
    if buf.len() as u64 > max_bytes {
        return Err(RemoteError::S3(format!(
            "body exceeds {max_bytes} bytes for s3://{}/{}",
            loc.bucket, loc.key
        )));
    }
    Ok(buf)
}

/// Download a parsed location, preferring Range chunks for large objects.
pub fn fetch_s3_location_to_temp(loc: &S3Location) -> Result<(NamedTempFile, u64)> {
    fetch_s3_location_to_temp_prefer_range(loc, None)
}

/// Download `s3://…`, preferring sequential Range GETs when feasible.
///
/// Convenience wrapper around [`fetch_s3_location_to_temp_prefer_range`].
pub fn fetch_s3_to_temp_prefer_range(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_s3_url(url_str)?;
    fetch_s3_location_to_temp_prefer_range(&loc, None)
}

/// Download an S3 object, preferring sequential HTTP Range chunks when feasible.
///
/// - When `known_size` is `Some(n)` and `n > `[`DEFAULT_S3_RANGE_THRESHOLD`],
///   tries chunked Range materialization first.
/// - When size is unknown, probes with `Range: bytes=0-0`; on 206 + total size
///   above threshold, uses chunked Range. If the probe returns a full body
///   (Range ignored) that body is kept (no second download).
/// - On any Range failure or when the object is small / ranges unsupported,
///   falls back to a single full-body GetObject.
pub fn fetch_s3_location_to_temp_prefer_range(
    loc: &S3Location,
    known_size: Option<u64>,
) -> Result<(NamedTempFile, u64)> {
    let size_for_range = match known_size {
        Some(n) if n > DEFAULT_S3_RANGE_THRESHOLD => Some(n),
        Some(_) => None, // small known size → full body
        None => match probe_s3_object(loc) {
            Ok(S3Probe::RangesOk(n)) if n > DEFAULT_S3_RANGE_THRESHOLD => Some(n),
            Ok(S3Probe::RangesOk(_)) => None,
            Ok(S3Probe::FullBody(bytes)) => {
                return bytes_to_tempfile(&bytes);
            }
            Ok(S3Probe::Unusable) => None,
            Err(e) => {
                debug!(
                    "s3 range probe failed for s3://{}/{}: {e}; full download",
                    loc.bucket, loc.key
                );
                None
            }
        },
    };

    if let Some(size) = size_for_range {
        debug!(
            "s3 prefer-range: s3://{}/{} ({size} bytes) in {}-byte chunks",
            loc.bucket, loc.key, HTTP_RANGE_CHUNK
        );
        match fetch_s3_via_ranges(loc, size) {
            Ok(v) => return Ok(v),
            Err(e) => {
                debug!(
                    "s3 range download failed for s3://{}/{}: {e}; falling back to full GET",
                    loc.bucket, loc.key
                );
            }
        }
    }

    fetch_s3_full_get(loc)
}

/// Download an inclusive byte range (`start..=end`) from an S3 object.
///
/// Expects HTTP 206 Partial Content. Returns a clear error on 200 (Range ignored)
/// or other status codes. `end` is inclusive (HTTP Range semantics).
pub fn fetch_s3_range_bytes(url_str: &str, start: u64, end_inclusive: u64) -> Result<Vec<u8>> {
    let loc = parse_s3_url(url_str)?;
    fetch_s3_location_range_bytes(&loc, start, end_inclusive)
}

/// Inclusive byte range GetObject for a parsed location (`start..=end_inclusive`).
pub fn fetch_s3_location_range_bytes(
    loc: &S3Location,
    start: u64,
    end_inclusive: u64,
) -> Result<Vec<u8>> {
    if end_inclusive < start {
        return Err(RemoteError::S3(format!(
            "invalid range {start}-{end_inclusive} for s3://{}/{}",
            loc.bucket, loc.key
        )));
    }
    let expected = end_inclusive - start + 1;
    let (source, resp) = s3_get_object(loc, Some((start, end_inclusive)))?;
    let status = resp.status();
    if status == 206 {
        let mut reader = resp.into_reader();
        let mut bytes = Vec::with_capacity(expected as usize);
        reader.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != expected {
            return Err(RemoteError::S3(format!(
                "range bytes={start}-{end_inclusive} for s3://{}/{} returned {} bytes, expected {expected}",
                loc.bucket,
                loc.key,
                bytes.len()
            )));
        }
        return Ok(bytes);
    }
    if status == 200 {
        // Drain body so the connection is not left half-open.
        let _ = resp.into_string();
        return Err(RemoteError::S3(format!(
            "HTTP 200 (Range ignored) GetObject s3://{}/{} bytes={start}-{end_inclusive}; \
             endpoint did not return 206 Partial Content",
            loc.bucket, loc.key
        )));
    }
    let body = resp.into_string().unwrap_or_default();
    Err(s3_status_error(source, status, loc, &body))
}

/// Result of a GetObject Range probe (`bytes=0-0`).
enum S3Probe {
    /// 206 Partial Content with known total size.
    RangesOk(u64),
    /// Server ignored Range and returned the full object body (small enough to keep).
    FullBody(Vec<u8>),
    /// Ranges / size not usable from this probe.
    Unusable,
}

fn bytes_to_tempfile(bytes: &[u8]) -> Result<(NamedTempFile, u64)> {
    let mut tmp = NamedTempFile::new()?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok((tmp, bytes.len() as u64))
}

/// Probe via `Range: bytes=0-0` for Content-Range total size.
fn probe_s3_object(loc: &S3Location) -> Result<S3Probe> {
    // Empty-object edge: Range 0-0 may 416; treat as unusable and full-GET.
    let (source, resp) = match s3_get_object(loc, Some((0, 0))) {
        Ok(v) => v,
        Err(e) => {
            debug!("s3 probe request failed: {e}");
            return Ok(S3Probe::Unusable);
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
            return Ok(S3Probe::RangesOk(total));
        }
        let _ = resp.into_string();
        return Ok(S3Probe::Unusable);
    }
    if (200..300).contains(&status) {
        // Range ignored. Avoid buffering huge bodies into RAM for reuse.
        if content_length.is_some_and(|n| n > DEFAULT_S3_RANGE_THRESHOLD) {
            let mut reader = resp.into_reader();
            let _ = io::copy(&mut reader, &mut io::sink());
            return Ok(S3Probe::Unusable);
        }
        let mut reader = resp.into_reader();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        return Ok(S3Probe::FullBody(bytes));
    }
    // 416 on empty object, 403, etc.
    debug!(
        "s3 probe s3://{}/{} -> HTTP {status} (auth={source:?})",
        loc.bucket, loc.key
    );
    let _ = resp.into_string();
    Ok(S3Probe::Unusable)
}

/// Sequential Range materialization into a tempfile.
fn fetch_s3_via_ranges(loc: &S3Location, size: u64) -> Result<(NamedTempFile, u64)> {
    let mut tmp = NamedTempFile::new()?;
    if size == 0 {
        tmp.flush()?;
        return Ok((tmp, 0));
    }
    let mut written = 0u64;
    for (start, end) in range_chunk_windows(size, HTTP_RANGE_CHUNK) {
        let range = format!("bytes={start}-{end}");
        let (source, resp) = s3_get_object(loc, Some((start, end)))?;
        let status = resp.status();
        if status == 206 {
            let expected = end - start + 1;
            let mut reader = resp.into_reader();
            let n = io::copy(&mut reader, &mut tmp)?;
            if n != expected {
                return Err(RemoteError::S3(format!(
                    "range {range} for s3://{}/{} returned {n} bytes, expected {expected}",
                    loc.bucket, loc.key
                )));
            }
            written += n;
        } else if status == 200 && start == 0 {
            // Server ignored Range and returned the full body on the first chunk.
            let mut reader = resp.into_reader();
            let n = io::copy(&mut reader, &mut tmp)?;
            tmp.flush()?;
            tmp.as_file_mut().seek(SeekFrom::Start(0))?;
            debug!(
                "s3 download s3://{}/{} -> {n} bytes (full body; Range ignored)",
                loc.bucket, loc.key
            );
            return Ok((tmp, n));
        } else {
            let body = resp.into_string().unwrap_or_default();
            return Err(s3_status_error(source, status, loc, &body));
        }
    }
    if written != size {
        return Err(RemoteError::S3(format!(
            "range download size mismatch for s3://{}/{}: wrote {written}, expected {size}",
            loc.bucket, loc.key
        )));
    }
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    debug!(
        "s3 range download s3://{}/{} -> {written} bytes",
        loc.bucket, loc.key
    );
    Ok((tmp, written))
}

/// Single full-body GetObject (no Range header); streams to tempfile.
fn fetch_s3_full_get(loc: &S3Location) -> Result<(NamedTempFile, u64)> {
    let (source, resp) = s3_get_object(loc, None)?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(s3_status_error(source, status, loc, &body));
    }
    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok((tmp, n))
}

/// Seekable S3 reader using live Range GetObject requests.
///
/// Falls back to a fully buffered body when size cannot be determined via Range
/// probe. Prefer [`open_s3_range`] for the public entry point.
pub struct S3RangeFile {
    loc: S3Location,
    size: u64,
    pos: u64,
    /// Optional fully buffered body if ranges unavailable.
    buffered: Option<Vec<u8>>,
}

impl std::fmt::Debug for S3RangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3RangeFile")
            .field("bucket", &self.loc.bucket)
            .field("key", &self.loc.key)
            .field("size", &self.size)
            .field("pos", &self.pos)
            .field("uses_ranges", &self.uses_ranges())
            .finish()
    }
}

impl S3RangeFile {
    /// Open `s3://…`, using live Range GETs when size is known via probe.
    ///
    /// Without a usable size, buffers the full object in memory.
    pub fn open(url_str: &str) -> Result<Self> {
        let loc = parse_s3_url(url_str)?;
        Self::open_location(&loc)
    }

    /// Open a parsed location (see [`S3RangeFile::open`]).
    pub fn open_location(loc: &S3Location) -> Result<Self> {
        match probe_s3_object(loc) {
            Ok(S3Probe::RangesOk(size)) => Ok(Self::range_backed(loc.clone(), size)),
            Ok(S3Probe::FullBody(bytes)) => {
                let size = bytes.len() as u64;
                Ok(Self {
                    loc: loc.clone(),
                    size,
                    pos: 0,
                    buffered: Some(bytes),
                })
            }
            Ok(S3Probe::Unusable) | Err(_) => {
                let (mut tmp, size) = fetch_s3_full_get(loc)?;
                let mut buf = Vec::with_capacity(size as usize);
                tmp.read_to_end(&mut buf)?;
                Ok(Self {
                    loc: loc.clone(),
                    size: buf.len() as u64,
                    pos: 0,
                    buffered: Some(buf),
                })
            }
        }
    }

    /// Construct a live Range-backed reader (no probe; caller must know size).
    pub fn range_backed(loc: S3Location, size: u64) -> Self {
        Self {
            loc,
            size,
            pos: 0,
            buffered: None,
        }
    }

    pub fn location(&self) -> &S3Location {
        &self.loc
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

/// Open a seekable S3 reader using live Range GetObject when possible.
///
/// Equivalent to [`S3RangeFile::open`].
pub fn open_s3_range(url_str: &str) -> Result<S3RangeFile> {
    S3RangeFile::open(url_str)
}

impl Read for S3RangeFile {
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
        let range_start = self.pos;
        let range_end = end - 1;
        let (source, resp) = s3_get_object(&self.loc, Some((range_start, range_end)))
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
        let body = resp.into_string().unwrap_or_default();
        Err(io::Error::other(
            s3_status_error(source, status, &self.loc, &body).to_string(),
        ))
    }
}

impl Seek for S3RangeFile {
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

/// Hard cap on ListObjectsV2 keys + common prefixes (not silent truncate).
pub const S3_LIST_KEY_CAP: usize = 100_000;
/// Hard cap on ListObjectsV2 pages (empty truncated pages must not loop forever).
pub const S3_LIST_PAGE_CAP: usize = 10_000;

/// One immediate child from ListObjectsV2 (`Contents` or `CommonPrefixes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3ListEntry {
    pub name: String,
    /// Full object key or common-prefix string (dirs end with `/`).
    pub key: String,
    pub is_dir: bool,
    pub size: u64,
}

/// One ListObjectsV2 page (continuation is the caller's job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListObjectsV2Page {
    pub objects: Vec<S3ListedObject>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
}

/// A `Contents` row from ListObjectsV2 XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3ListedObject {
    pub key: String,
    pub size: u64,
}

fn s3_list_prefix(key: &str) -> String {
    if key.is_empty() || key.ends_with('/') {
        key.to_string()
    } else {
        format!("{key}/")
    }
}

fn s3_canonical_query(params: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (urlencoding_encode(k), urlencoding_encode(v)))
        .collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn s3_list_request_target(bucket: &str, region: &str) -> (String, String, bool) {
    if let Some(endpoint) = custom_endpoint() {
        let ep = endpoint.trim_end_matches('/');
        let (scheme, rest) = if let Some(r) = ep.strip_prefix("https://") {
            ("https", r)
        } else if let Some(r) = ep.strip_prefix("http://") {
            ("http", r)
        } else {
            ("https", ep)
        };
        let host = rest.split('/').next().unwrap_or(rest).to_string();
        (host, format!("/{bucket}"), scheme == "https")
    } else {
        let host = if region == "us-east-1" {
            format!("{bucket}.s3.amazonaws.com")
        } else {
            format!("{bucket}.s3.{region}.amazonaws.com")
        };
        (host, "/".to_string(), true)
    }
}

/// Parse a ListObjectsV2 XML body (one page). Does not follow continuation.
pub fn parse_list_objects_v2_xml(xml: &str) -> ListObjectsV2Page {
    let is_truncated = xml_tag_text(xml, "istruncated")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let next_continuation_token =
        xml_tag_text(xml, "nextcontinuationtoken").filter(|s| !s.is_empty());
    let mut objects = Vec::new();
    for block in xml_blocks(xml, "contents") {
        let Some(key) = xml_tag_text(&block, "key").filter(|s| !s.is_empty()) else {
            continue;
        };
        let size = xml_tag_text(&block, "size")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        objects.push(S3ListedObject { key, size });
    }
    let mut common_prefixes = Vec::new();
    for block in xml_blocks(xml, "commonprefixes") {
        if let Some(p) = xml_tag_text(&block, "prefix").filter(|s| !s.is_empty()) {
            common_prefixes.push(p);
        }
    }
    ListObjectsV2Page {
        objects,
        common_prefixes,
        is_truncated,
        next_continuation_token,
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
                // `<tag` at start or after non-name char; skip `</tag`.
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
                // require `</pref:tag>`
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
        // tag name start: `<tag` or `:tag`
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

fn s3_list_objects_v2_page(
    bucket: &str,
    prefix: &str,
    continuation: Option<&str>,
) -> Result<ListObjectsV2Page> {
    let auth = resolve_auth()?;
    let region = region();
    let (host, uri_path, use_https) = s3_list_request_target(bucket, &region);
    let mut params: Vec<(&str, &str)> =
        vec![("list-type", "2"), ("delimiter", "/"), ("max-keys", "1000")];
    if !prefix.is_empty() {
        params.push(("prefix", prefix));
    }
    if let Some(tok) = continuation {
        params.push(("continuation-token", tok));
    }
    let query = s3_canonical_query(&params);
    let url = if use_https {
        format!("https://{host}{uri_path}?{query}")
    } else {
        format!("http://{host}{uri_path}?{query}")
    };
    debug!("s3 ListObjectsV2 {url} (auth={:?})", auth.source);

    let resp = match &auth.creds {
        None => ureq::get(&url)
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| {
                RemoteError::S3(format!(
                    "anonymous ListObjectsV2 s3://{bucket}/{prefix}: {e}"
                ))
            })?,
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
                "GET\n{uri_path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
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
                RemoteError::S3(format!("ListObjectsV2 s3://{bucket}/{prefix}: {e}"))
            })?
        }
    };

    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(RemoteError::S3(format!(
            "ListObjectsV2 HTTP {status} for s3://{bucket}/{prefix}: {body}"
        )));
    }
    let body = resp
        .into_string()
        .map_err(|e| RemoteError::S3(e.to_string()))?;
    Ok(parse_list_objects_v2_xml(&body))
}

fn s3_child_entry(prefix: &str, key: &str, size: u64, is_dir: bool) -> Option<S3ListEntry> {
    let rest = if prefix.is_empty() {
        key
    } else {
        key.strip_prefix(prefix)?
    };
    let name = rest.trim_end_matches('/');
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some(S3ListEntry {
        name: name.to_string(),
        key: key.to_string(),
        is_dir,
        size: if is_dir { 0 } else { size },
    })
}

/// List immediate children of an S3 prefix (`Delimiter=/`), following continuation tokens.
///
/// Errors (does not silently truncate) when more than [`S3_LIST_KEY_CAP`] keys are listed,
/// or when a page is truncated without `NextContinuationToken`.
pub fn list_s3_prefix(loc: &S3Location) -> Result<Vec<S3ListEntry>> {
    list_s3_prefix_capped(loc, S3_LIST_KEY_CAP)
}

/// ListObjectsV2 loop with an explicit key cap (tests use a small cap).
pub fn list_s3_prefix_capped(loc: &S3Location, cap: usize) -> Result<Vec<S3ListEntry>> {
    let prefix = s3_list_prefix(&loc.key);
    let mut token: Option<String> = None;
    let mut out: Vec<S3ListEntry> = Vec::new();
    let mut total = 0usize;
    let mut pages = 0usize;
    let page_cap = cap.saturating_add(1).min(S3_LIST_PAGE_CAP);
    loop {
        pages = pages.saturating_add(1);
        if pages > page_cap {
            return Err(RemoteError::S3(format!(
                "s3 prefix too large (>{cap} keys) for s3://{}/{}; listing is not silently truncated",
                loc.bucket, loc.key
            )));
        }
        let page = s3_list_objects_v2_page(&loc.bucket, &prefix, token.as_deref())?;
        let n = page.objects.len() + page.common_prefixes.len();
        // Empty truncated pages never increment `total`; treat as incomplete, not a hang.
        if page.is_truncated && n == 0 {
            return Err(RemoteError::S3(
                "truncated ListObjectsV2 page with no keys; listing is not complete".into(),
            ));
        }
        total = total.saturating_add(n);
        if total > cap {
            return Err(RemoteError::S3(format!(
                "s3 prefix too large (>{cap} keys) for s3://{}/{}; listing is not silently truncated",
                loc.bucket, loc.key
            )));
        }
        for obj in &page.objects {
            if let Some(ent) = s3_child_entry(&prefix, &obj.key, obj.size, false) {
                out.push(ent);
            }
        }
        for cp in &page.common_prefixes {
            if let Some(ent) = s3_child_entry(&prefix, cp, 0, true) {
                out.push(ent);
            }
        }
        if !page.is_truncated {
            break;
        }
        let Some(next) = page
            .next_continuation_token
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            return Err(RemoteError::S3(
                "truncated ListObjectsV2 page without NextContinuationToken; listing is not complete"
                    .into(),
            ));
        };
        if token.as_deref() == Some(next) {
            return Err(RemoteError::S3(
                "truncated ListObjectsV2 page repeated NextContinuationToken; listing is not complete"
                    .into(),
            ));
        }
        token = Some(next.to_string());
    }
    Ok(out)
}

/// One lock for every test that mutates `AWS_*` / IMDS env. `folder` and
/// `index_sibling` tests take this too; separate mutexes raced under `s3_`.
#[cfg(test)]
pub(crate) static S3_AWS_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Directory probe: empty key, trailing `/`, or children exist without an exact object.
///
/// ListBucket failures on a non-prefix key (no trailing `/`) are `Ok(false)` so
/// GetObject-only IAM can still Range-open the object.
pub fn s3_location_is_dir(loc: &S3Location) -> Result<bool> {
    if loc.key.is_empty() || loc.key.ends_with('/') {
        return Ok(true);
    }
    let page = match s3_list_objects_v2_page(&loc.bucket, &loc.key, None) {
        Ok(p) => p,
        Err(e) => {
            debug!(
                "s3 ListObjectsV2 probe s3://{}/{} failed ({e}); treating as object",
                loc.bucket, loc.key
            );
            return Ok(false);
        }
    };
    let has_exact = page.objects.iter().any(|o| o.key == loc.key);
    if has_exact {
        return Ok(false);
    }
    let child_prefix = s3_list_prefix(&loc.key);
    let has_child_prefix = page
        .common_prefixes
        .iter()
        .any(|p| p == &child_prefix || p.starts_with(&child_prefix));
    let has_child_key = page
        .objects
        .iter()
        .any(|o| o.key.starts_with(&child_prefix) && o.key != loc.key);
    Ok(has_child_prefix || has_child_key)
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
    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&str]) -> Self {
            let lock = super::S3_AWS_ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            clear_role_creds_cache();
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
                        MetaMode::Container { body, require_auth } => {
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
                            if *require_token && imds_token.as_deref() != Some("mock-imds-token") {
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

    /// Path-style S3 mock: GET /{bucket}/{key} → body; honors Range; records Authorization.
    struct MockS3 {
        base_url: String,
        log: Arc<StdMutex<Vec<String>>>,
        gets: Arc<AtomicUsize>,
        auth_headers: Arc<AtomicUsize>,
        range_headers: Arc<AtomicUsize>,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockS3 {
        fn spawn(body: Vec<u8>, require_auth: bool) -> Self {
            Self::spawn_with_options(body, require_auth, true)
        }

        /// `honor_range`: when false, ignore Range and always return full 200 body.
        fn spawn_with_options(body: Vec<u8>, require_auth: bool, honor_range: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let local = listener.local_addr().unwrap();
            let base_url = format!("http://{local}");
            let log = Arc::new(StdMutex::new(Vec::new()));
            let gets = Arc::new(AtomicUsize::new(0));
            let auth_headers = Arc::new(AtomicUsize::new(0));
            let range_headers = Arc::new(AtomicUsize::new(0));
            let log_c = Arc::clone(&log);
            let gets_c = Arc::clone(&gets);
            let auth_c = Arc::clone(&auth_headers);
            let range_c = Arc::clone(&range_headers);
            // Enough connections for multi-chunk prefer-range + probes.
            let max_conns = 64usize;
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(max_conns) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut has_auth = false;
                    let mut range_hdr: Option<String> = None;
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

                    // Honor Range with 206 when requested and body non-empty.
                    if honor_range {
                        if let Some(ref r) = range_hdr {
                            if let Some((start, end)) = parse_bytes_range(r, body.len()) {
                                if body.is_empty() {
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
                                if start > end || start >= body.len() {
                                    let msg = b"InvalidRange";
                                    let _ = write!(
                                        stream,
                                        "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        msg.len()
                                    );
                                    let _ = stream.write_all(msg);
                                    continue;
                                }
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
                    let _ = stream.write_all(&body);
                }
            });
            Self {
                base_url,
                log,
                gets,
                auth_headers,
                range_headers,
                _join: Some(join),
            }
        }
    }

    /// Parse `bytes=start-end` (inclusive). `end` may be omitted (`bytes=start-`).
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

    #[test]
    fn parse_bucket_key() {
        let l = parse_s3_url("s3://my-bucket/path/to/archive.tar.gz").unwrap();
        assert_eq!(l.bucket, "my-bucket");
        assert_eq!(l.key, "path/to/archive.tar.gz");
    }

    #[test]
    fn reject_missing_key() {
        assert!(parse_s3_url("s3://only-bucket/").is_err());
        assert!(parse_s3_url("s3://only-bucket").is_err());
    }

    #[test]
    fn parse_s3_url_allow_prefix_empty_folder_key() {
        let root = parse_s3_url_allow_prefix("s3://only-bucket").unwrap();
        assert_eq!(root.bucket, "only-bucket");
        assert!(root.key.is_empty());
        let slash = parse_s3_url_allow_prefix("s3://only-bucket/").unwrap();
        assert!(slash.key.is_empty());
        let pref = parse_s3_url_allow_prefix("s3://b/prefix/").unwrap();
        assert_eq!(pref.key, "prefix/");
    }

    #[test]
    fn list_objects_v2_page_parse_folder_truncated() {
        let xml = r#"<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix>prefix/</Prefix>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>page-2-token</NextContinuationToken>
  <Contents>
    <Key>prefix/a.tar</Key>
    <Size>42</Size>
  </Contents>
</ListBucketResult>"#;
        let page = parse_list_objects_v2_xml(xml);
        assert!(page.is_truncated, "truncated page must not look complete");
        assert_eq!(
            page.next_continuation_token.as_deref(),
            Some("page-2-token")
        );
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "prefix/a.tar");
        assert_eq!(page.objects[0].size, 42);
        assert!(page.common_prefixes.is_empty());
    }

    #[test]
    fn list_objects_v2_page_parse_folder_common_prefixes() {
        let xml = r#"<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>prefix/b.bin</Key><Size>7</Size></Contents>
  <CommonPrefixes><Prefix>prefix/sub/</Prefix></CommonPrefixes>
</ListBucketResult>"#;
        let page = parse_list_objects_v2_xml(xml);
        assert!(!page.is_truncated);
        assert!(page.next_continuation_token.is_none());
        assert_eq!(page.common_prefixes, vec!["prefix/sub/".to_string()]);
        let kids: Vec<_> = page
            .objects
            .iter()
            .filter_map(|o| s3_child_entry("prefix/", &o.key, o.size, false))
            .chain(
                page.common_prefixes
                    .iter()
                    .filter_map(|p| s3_child_entry("prefix/", p, 0, true)),
            )
            .collect();
        assert_eq!(kids.len(), 2);
        assert!(kids
            .iter()
            .any(|e| e.name == "b.bin" && !e.is_dir && e.size == 7));
        assert!(kids.iter().any(|e| e.name == "sub" && e.is_dir));
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
        assert!(err.contains("AWS_SECRET_ACCESS_KEY"), "unexpected: {err}");
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

    #[test]
    fn signed_range_get_asserts_auth_and_range() {
        let body: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let s3 = MockS3::spawn(body.clone(), true);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("AWS_REGION", "us-east-1");

        let got = fetch_s3_range_bytes("s3://mybucket/obj.bin", 10, 19).unwrap();
        assert_eq!(got, &body[10..=19]);
        assert!(s3.auth_headers.load(Ordering::SeqCst) >= 1);
        assert!(s3.range_headers.load(Ordering::SeqCst) >= 1);
        let log = s3.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l == "Range: bytes=10-19"),
            "expected Range header in log={log:?}"
        );
        assert!(
            log.iter().any(|l| l.contains("Authorization: present")),
            "expected Authorization for signed Range, log={log:?}"
        );
    }

    #[test]
    fn anonymous_range_get_no_authorization() {
        let body: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let s3 = MockS3::spawn(body.clone(), false);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ANONYMOUS", "1");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let got = fetch_s3_range_bytes("s3://public/path/obj.bin", 100, 149).unwrap();
        assert_eq!(got, &body[100..=149]);
        assert_eq!(
            s3.auth_headers.load(Ordering::SeqCst),
            0,
            "anonymous Range must not send Authorization"
        );
        assert!(s3.range_headers.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn prefer_range_chunked_download() {
        // Just above threshold → Range path; with 4 MiB chunk this is one window.
        let size = (DEFAULT_S3_RANGE_THRESHOLD + 64 * 1024) as usize;
        let body: Vec<u8> = (0u8..=251).cycle().take(size).collect();
        let s3 = MockS3::spawn(body.clone(), true);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("AWS_REGION", "us-east-1");

        let loc = parse_s3_url("s3://b/large.bin").unwrap();
        let (mut tmp, n) =
            fetch_s3_location_to_temp_prefer_range(&loc, Some(body.len() as u64)).unwrap();
        assert_eq!(n, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert!(
            s3.range_headers.load(Ordering::SeqCst) >= 1,
            "expected Range GETs"
        );
        let log = s3.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with("Range: bytes=")),
            "log={log:?}"
        );
        assert!(
            log.iter().any(|l| l.contains("Authorization: present")),
            "signed prefer-range must send Authorization, log={log:?}"
        );
    }

    #[test]
    fn prefer_range_multi_chunk_download() {
        let size = (HTTP_RANGE_CHUNK + 128 * 1024) as usize;
        let body: Vec<u8> = (0u8..=251).cycle().take(size).collect();
        let s3 = MockS3::spawn(body.clone(), true);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("AWS_REGION", "us-east-1");

        let loc = parse_s3_url("s3://b/huge.bin").unwrap();
        let (mut tmp, n) =
            fetch_s3_location_to_temp_prefer_range(&loc, Some(body.len() as u64)).unwrap();
        assert_eq!(n, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let ranges = s3.range_headers.load(Ordering::SeqCst);
        assert!(
            ranges >= 2,
            "expected multi-chunk Range download, ranges={ranges}"
        );
        let log = s3.log.lock().unwrap();
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
    fn prefer_range_small_object_uses_full_get() {
        let body = b"tiny-object".to_vec();
        let s3 = MockS3::spawn(body.clone(), true);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("AWS_REGION", "us-east-1");

        // known small size → full GET, no Range
        let loc = parse_s3_url("s3://b/small.bin").unwrap();
        let (mut tmp, n) =
            fetch_s3_location_to_temp_prefer_range(&loc, Some(body.len() as u64)).unwrap();
        assert_eq!(n, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        assert_eq!(
            s3.range_headers.load(Ordering::SeqCst),
            0,
            "small known size must not use Range"
        );
        assert!(s3.auth_headers.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn prefer_range_probes_then_downloads() {
        let size = (DEFAULT_S3_RANGE_THRESHOLD + 32 * 1024) as usize;
        let body: Vec<u8> = (0u8..=199).cycle().take(size).collect();
        let s3 = MockS3::spawn(body.clone(), true);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("AWS_REGION", "us-east-1");

        // Unknown size → probe 0-0 then chunked Range.
        let (mut tmp, n) = fetch_s3_to_temp("s3://b/probed.bin").unwrap();
        assert_eq!(n, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        let log = s3.log.lock().unwrap();
        assert!(
            log.iter().any(|l| l == "Range: bytes=0-0"),
            "expected size probe, log={log:?}"
        );
        assert!(
            s3.range_headers.load(Ordering::SeqCst) >= 2,
            "probe + at least one data Range"
        );
    }

    #[test]
    fn prefer_range_falls_back_when_range_ignored() {
        let size = (DEFAULT_S3_RANGE_THRESHOLD + 64 * 1024) as usize;
        let body: Vec<u8> = (0u8..=180).cycle().take(size).collect();
        // honor_range=false → 200 full body even when Range sent
        let s3 = MockS3::spawn_with_options(body.clone(), true, false);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("AWS_REGION", "us-east-1");

        let loc = parse_s3_url("s3://b/no-range.bin").unwrap();
        let (mut tmp, n) =
            fetch_s3_location_to_temp_prefer_range(&loc, Some(body.len() as u64)).unwrap();
        assert_eq!(n, body.len() as u64);
        let mut got = Vec::new();
        tmp.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn s3_range_file_live_reads() {
        let body: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let s3 = MockS3::spawn(body.clone(), true);
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        _g.set("AWS_ENDPOINT_URL", &s3.base_url);
        _g.set("AWS_REGION", "us-east-1");

        let mut f = open_s3_range("s3://b/live.bin").unwrap();
        assert!(f.uses_ranges());
        assert_eq!(f.len(), body.len() as u64);
        let mut prefix = [0u8; 16];
        f.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, &body[..16]);
        f.seek(SeekFrom::Start(1000)).unwrap();
        let mut mid = [0u8; 32];
        f.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, &body[1000..1032]);
        assert!(s3.range_headers.load(Ordering::SeqCst) >= 2);
        assert!(s3.auth_headers.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn range_bytes_invalid_window() {
        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        _g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        let err = fetch_s3_range_bytes("s3://b/k", 10, 5)
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid range"), "got: {err}");
    }

    const FIXTURE_SECRET: &str = "fixture-secret-do-not-log";

    struct CaptureLog;

    static CAPTURED_LOGS: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

    impl log::Log for CaptureLog {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.level() <= log::Level::Debug
                && metadata.target().starts_with("ratarmount_remote")
        }

        fn log(&self, record: &log::Record<'_>) {
            if !self.enabled(record.metadata()) {
                return;
            }
            if let Ok(mut lines) = CAPTURED_LOGS.lock() {
                lines.push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    fn install_capture_log() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = log::set_logger(&CaptureLog);
        });
        log::set_max_level(log::LevelFilter::Debug);
    }

    fn captured_logs() -> Vec<String> {
        CAPTURED_LOGS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn assert_logs_omit_secret(lines: &[String]) {
        let redacted: Vec<String> = lines
            .iter()
            .map(|l| l.replace(FIXTURE_SECRET, "[secret]"))
            .collect();
        assert!(
            lines.iter().all(|l| !l.contains(FIXTURE_SECRET)),
            "debug log contains the fixture secret: {redacted:?}"
        );
        assert!(
            lines.iter().all(|l| !l.contains("AWS4-HMAC-SHA256")),
            "debug log contains an Authorization value: {redacted:?}"
        );
    }

    struct OverrideGuard;

    impl OverrideGuard {
        fn signed(endpoint: &str) -> Self {
            TEST_S3_OVERRIDE.with(|slot| {
                *slot.borrow_mut() = Some(TestS3Override {
                    access_key: "AKIA_FIXTURE_KEY".into(),
                    secret_key: FIXTURE_SECRET.into(),
                    region: "us-east-1".into(),
                    endpoint: endpoint.to_string(),
                    anonymous: false,
                });
            });
            Self
        }

        fn anonymous(endpoint: &str) -> Self {
            TEST_S3_OVERRIDE.with(|slot| {
                *slot.borrow_mut() = Some(TestS3Override {
                    access_key: String::new(),
                    secret_key: FIXTURE_SECRET.into(),
                    region: "us-east-1".into(),
                    endpoint: endpoint.to_string(),
                    anonymous: true,
                });
            });
            Self
        }
    }

    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            TEST_S3_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
        }
    }

    #[derive(Clone)]
    struct CapturedS3Req {
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl CapturedS3Req {
        fn header(&self, name: &str) -> &str {
            self.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
                .unwrap_or("")
        }

        fn query(&self) -> &str {
            self.target.split_once('?').map(|(_, q)| q).unwrap_or("")
        }

        fn path_only(&self) -> &str {
            self.target
                .split_once('?')
                .map(|(p, _)| p)
                .unwrap_or(self.target.as_str())
        }
    }

    fn summarize_reqs(reqs: &[CapturedS3Req]) -> String {
        reqs.iter()
            .map(|r| format!("{} {} body={}", r.method, r.target, r.body.len()))
            .collect::<Vec<_>>()
            .join("; ")
    }

    struct MockReply {
        status: u16,
        reason: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> Option<CapturedS3Req> {
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).ok()?;
        if request_line.is_empty() {
            return None;
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("/").to_string();
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            if line == "\r\n" || line == "\n" || line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let n = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; n];
        if n > 0 {
            reader.read_exact(&mut body).ok()?;
        }
        Some(CapturedS3Req {
            method,
            target,
            headers,
            body,
        })
    }

    fn mock_s3_write_reply(
        method: &str,
        target: &str,
        headers: &[(String, String)],
        upload_id: &str,
        copy_412: bool,
    ) -> MockReply {
        let has = |name: &str| headers.iter().any(|(k, _)| k == name);
        if method == "POST" && target.contains("uploads=") {
            let body = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <InitiateMultipartUploadResult><UploadId>{upload_id}</UploadId>\
                 </InitiateMultipartUploadResult>"
            );
            return MockReply {
                status: 200,
                reason: "OK",
                headers: vec![("Content-Type".into(), "application/xml".into())],
                body: body.into_bytes(),
            };
        }
        if method == "DELETE" {
            return MockReply {
                status: 204,
                reason: "No Content",
                headers: Vec::new(),
                body: Vec::new(),
            };
        }
        if method == "PUT" && has("x-amz-copy-source") {
            if copy_412 {
                return MockReply {
                    status: 412,
                    reason: "Precondition Failed",
                    headers: Vec::new(),
                    body: b"PreconditionFailed".to_vec(),
                };
            }
            return MockReply {
                status: 200,
                reason: "OK",
                headers: vec![("ETag".into(), "\"etag-copy\"".into())],
                body: b"<CopyPartResult><ETag>\"etag-copy\"</ETag></CopyPartResult>".to_vec(),
            };
        }
        if method == "PUT" {
            return MockReply {
                status: 200,
                reason: "OK",
                headers: vec![("ETag".into(), "\"etag-part\"".into())],
                body: Vec::new(),
            };
        }
        if method == "POST" {
            return MockReply {
                status: 200,
                reason: "OK",
                headers: vec![("Content-Type".into(), "application/xml".into())],
                body: b"<CompleteMultipartUploadResult></CompleteMultipartUploadResult>".to_vec(),
            };
        }
        MockReply {
            status: 405,
            reason: "Method Not Allowed",
            headers: Vec::new(),
            body: b"method".to_vec(),
        }
    }

    fn write_http(stream: &mut std::net::TcpStream, reply: &MockReply) {
        let _ = write!(stream, "HTTP/1.1 {} {}\r\n", reply.status, reply.reason);
        for (k, v) in &reply.headers {
            let _ = write!(stream, "{k}: {v}\r\n");
        }
        let _ = write!(
            stream,
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            reply.body.len()
        );
        let _ = stream.write_all(&reply.body);
    }

    struct MockS3Write {
        base_url: String,
        reqs: Arc<StdMutex<Vec<CapturedS3Req>>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockS3Write {
        fn spawn(upload_id: &str, copy_412: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let local = listener.local_addr().unwrap();
            let base_url = format!("http://{local}");
            let reqs = Arc::new(StdMutex::new(Vec::new()));
            let reqs_c = Arc::clone(&reqs);
            let upload_id_owned = upload_id.to_string();
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(32) {
                    let Ok(mut stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    let Some(req) = read_http_request(&mut stream) else {
                        continue;
                    };
                    let reply = mock_s3_write_reply(
                        &req.method,
                        &req.target,
                        &req.headers,
                        &upload_id_owned,
                        copy_412,
                    );
                    reqs_c.lock().unwrap().push(req);
                    write_http(&mut stream, &reply);
                }
            });
            Self {
                base_url,
                reqs,
                _join: Some(join),
            }
        }

        fn requests(&self) -> Vec<CapturedS3Req> {
            self.reqs.lock().unwrap().clone()
        }
    }

    /// Recompute SigV4 from the bytes and query on the wire.
    /// A signer that hashed `b""` or signed an empty query will not match.
    fn assert_sigv4_covers(req: &CapturedS3Req) {
        let auth = req.header("authorization");
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 "),
            "missing sigv4 authorization on {} {}",
            req.method,
            req.target
        );
        let signed_headers = auth
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .unwrap_or("")
            .trim();
        let signature = auth
            .split("Signature=")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string();
        let payload_hash = req.header("x-amz-content-sha256");
        assert_eq!(
            payload_hash,
            sha256_hex(&req.body),
            "payload hash must be SHA-256 of the bytes sent"
        );
        assert_ne!(payload_hash, "UNSIGNED-PAYLOAD");
        let amz_date = req.header("x-amz-date");
        assert_eq!(amz_date.len(), 16, "x-amz-date={amz_date}");
        let date_stamp = &amz_date[..8];
        let mut canonical_headers = String::new();
        for name in signed_headers.split(';') {
            assert!(!name.is_empty(), "empty signed header in {signed_headers}");
            let value = req.header(name).trim();
            assert!(
                !value.is_empty(),
                "signed header {name} missing on {} {}",
                req.method,
                req.target
            );
            canonical_headers.push_str(&format!("{name}:{value}\n"));
        }
        let canonical = format!(
            "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            req.method,
            req.path_only(),
            req.query()
        );
        let scope = format!("{date_stamp}/us-east-1/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let expect = hex::encode(hmac_sha256(
            &signing_key(FIXTURE_SECRET, date_stamp, "us-east-1", "s3"),
            string_to_sign.as_bytes(),
        ));
        assert_eq!(
            signature,
            expect,
            "signature does not cover canonical query {:?} for {} {}\n{canonical}",
            req.query(),
            req.method,
            req.target
        );
    }

    fn write_prefix_file(prefix: u64, suffix: &[u8]) -> NamedTempFile {
        let mut staged = NamedTempFile::new().unwrap();
        let chunk = vec![0xABu8; 64 * 1024];
        let mut left = prefix;
        while left > 0 {
            let n = (left as usize).min(chunk.len());
            staged.write_all(&chunk[..n]).unwrap();
            left -= n as u64;
        }
        staged.write_all(suffix).unwrap();
        staged.flush().unwrap();
        staged
    }

    #[test]
    fn s3_put_signs_body_hash_not_empty_payload() {
        install_capture_log();
        let s3 = MockS3Write::spawn("uid-put", false);
        let _over = OverrideGuard::signed(&s3.base_url);
        let loc = parse_s3_url("s3://mybucket/dir/obj.bin").unwrap();
        let body = b"put-body-not-empty";
        let log_from = captured_logs().len();
        put_s3_object(&loc, body, Some("\"src-etag\"")).unwrap();
        let logs = captured_logs();
        let logs = &logs[log_from.min(logs.len())..];
        let reqs = s3.requests();
        assert_eq!(reqs.len(), 1, "{}", summarize_reqs(&reqs));
        let req = &reqs[0];
        assert_eq!(req.method, "PUT");
        assert_eq!(req.query(), "", "PutObject signs an empty canonical query");
        assert_eq!(req.body, body);
        assert_ne!(req.header("x-amz-content-sha256"), sha256_hex(b""));
        assert_eq!(req.header("if-match"), "\"src-etag\"");
        assert_sigv4_covers(req);
        assert!(
            logs.iter()
                .any(|l| l.contains("s3 PUT") && l.contains("query= upload_id=-")),
            "expected the empty canonical query in the debug log"
        );
        assert_logs_omit_secret(logs);
    }

    #[test]
    fn s3_multipart_signs_partnumber_and_uploadid() {
        install_capture_log();
        let upload_id = "uid-mp-1";
        let s3 = MockS3Write::spawn(upload_id, false);
        let _over = OverrideGuard::signed(&s3.base_url);
        let loc = parse_s3_url("s3://mybucket/dir/obj.bin").unwrap();
        let mut staged = NamedTempFile::new().unwrap();
        let body = b"multipart-body-not-empty";
        staged.write_all(body).unwrap();
        staged.flush().unwrap();
        let log_from = captured_logs().len();
        put_s3_multipart(&loc, staged.path(), Some(0), Some("\"src-etag\"")).unwrap();
        let logs = captured_logs();
        let logs = &logs[log_from.min(logs.len())..];
        let reqs = s3.requests();

        let create_q = s3_canonical_query(&[("uploads", "")]);
        assert_eq!(create_q, "uploads=");
        let create = reqs
            .iter()
            .find(|r| r.method == "POST" && r.query() == create_q)
            .unwrap_or_else(|| panic!("missing CreateMultipartUpload: {}", summarize_reqs(&reqs)));
        assert!(create.body.is_empty());
        assert_sigv4_covers(create);

        let part_q = s3_canonical_query(&[("partNumber", "1"), ("uploadId", upload_id)]);
        assert_eq!(part_q, format!("partNumber=1&uploadId={upload_id}"));
        let part = reqs
            .iter()
            .find(|r| r.method == "PUT" && r.query() == part_q)
            .unwrap_or_else(|| panic!("missing UploadPart: {}", summarize_reqs(&reqs)));
        assert_eq!(part.body, body);
        assert_ne!(part.header("x-amz-content-sha256"), sha256_hex(b""));
        assert!(
            part.header("x-amz-copy-source").is_empty(),
            "prefix 0 must not UploadPartCopy"
        );
        assert_sigv4_covers(part);

        let complete_q = s3_canonical_query(&[("uploadId", upload_id)]);
        assert!(!complete_q.contains("partNumber"));
        let complete = reqs
            .iter()
            .find(|r| r.method == "POST" && r.query() == complete_q)
            .unwrap_or_else(|| {
                panic!("missing CompleteMultipartUpload: {}", summarize_reqs(&reqs))
            });
        let complete_xml = String::from_utf8(complete.body.clone()).unwrap();
        assert!(
            complete_xml.contains("\"etag-part\""),
            "complete body lost the part etag: {complete_xml}"
        );
        assert_eq!(complete.header("if-match"), "\"src-etag\"");
        assert_sigv4_covers(complete);

        assert!(
            logs.iter().any(|l| l.contains(&format!("query={part_q}"))),
            "log must include the signed part query, not only the verb"
        );
        assert!(logs.iter().any(|l| l.contains("query=uploads=")));
        assert!(logs
            .iter()
            .any(|l| { l.contains("s3 POST") && l.contains(&format!("query={complete_q}")) }));
        assert_logs_omit_secret(logs);
    }

    #[test]
    fn s3_upload_part_copy_range_is_inclusive_and_if_match() {
        install_capture_log();
        let upload_id = "uid-copy-1";
        let s3 = MockS3Write::spawn(upload_id, false);
        let _over = OverrideGuard::signed(&s3.base_url);
        let prefix = S3_COPY_PART_MIN;
        let suffix = b"SUFFIX!!";
        let staged = write_prefix_file(prefix, suffix);
        let loc = parse_s3_url("s3://mybucket/dir/obj.bin").unwrap();
        let etag = "\"src-etag\"";
        let log_from = captured_logs().len();
        put_s3_multipart(&loc, staged.path(), Some(prefix), Some(etag)).unwrap();
        let logs = captured_logs();
        let logs = &logs[log_from.min(logs.len())..];
        let reqs = s3.requests();

        let copy_q = s3_canonical_query(&[("partNumber", "1"), ("uploadId", upload_id)]);
        let copy = reqs
            .iter()
            .find(|r| r.method == "PUT" && r.query() == copy_q)
            .unwrap_or_else(|| panic!("missing UploadPartCopy: {}", summarize_reqs(&reqs)));
        let range = format!("bytes=0-{}", prefix - 1);
        assert_eq!(copy.header("x-amz-copy-source-range"), range);
        assert_ne!(
            copy.header("x-amz-copy-source-range"),
            format!("bytes=0-{prefix}"),
            "copy range end is inclusive, not the prefix length"
        );
        assert_eq!(copy.header("x-amz-copy-source-if-match"), etag);
        assert_eq!(copy.header("x-amz-copy-source"), "/mybucket/dir/obj.bin");
        assert!(copy.body.is_empty(), "UploadPartCopy sends no body");
        assert_sigv4_covers(copy);
        let signed = copy
            .header("authorization")
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .unwrap_or("");
        for name in [
            "x-amz-copy-source",
            "x-amz-copy-source-if-match",
            "x-amz-copy-source-range",
        ] {
            assert!(
                signed.split(';').any(|h| h == name),
                "SignedHeaders={signed} missing {name}"
            );
        }

        let part2_q = s3_canonical_query(&[("partNumber", "2"), ("uploadId", upload_id)]);
        let part2 = reqs
            .iter()
            .find(|r| r.method == "PUT" && r.query() == part2_q)
            .unwrap_or_else(|| panic!("missing suffix UploadPart: {}", summarize_reqs(&reqs)));
        assert_eq!(part2.body, suffix);
        assert_sigv4_covers(part2);

        let complete_q = s3_canonical_query(&[("uploadId", upload_id)]);
        let complete = reqs
            .iter()
            .find(|r| r.method == "POST" && r.query() == complete_q)
            .unwrap_or_else(|| panic!("missing complete: {}", summarize_reqs(&reqs)));
        assert_eq!(complete.header("if-match"), etag);
        assert_sigv4_covers(complete);
        assert_logs_omit_secret(logs);
    }

    #[test]
    fn s3_copy_412_does_not_complete() {
        install_capture_log();
        let upload_id = "uid-copy-412";
        let s3 = MockS3Write::spawn(upload_id, true);
        let _over = OverrideGuard::signed(&s3.base_url);
        let prefix = S3_COPY_PART_MIN;
        let staged = write_prefix_file(prefix, b"SUFFIX!!");
        let loc = parse_s3_url("s3://mybucket/dir/obj.bin").unwrap();
        let log_from = captured_logs().len();
        let err = put_s3_multipart(&loc, staged.path(), Some(prefix), Some("\"src-etag\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("412"), "{err}");
        let reqs = s3.requests();
        let puts: Vec<_> = reqs.iter().filter(|r| r.method == "PUT").collect();
        assert_eq!(puts.len(), 1, "{}", summarize_reqs(&reqs));
        let range = format!("bytes=0-{}", prefix - 1);
        assert_eq!(puts[0].header("x-amz-copy-source-range"), range);
        assert_eq!(puts[0].header("x-amz-copy-source-if-match"), "\"src-etag\"");
        assert_eq!(
            puts[0].query(),
            s3_canonical_query(&[("partNumber", "1"), ("uploadId", upload_id)])
        );
        assert_sigv4_covers(puts[0]);
        assert!(
            !reqs.iter().any(|r| {
                r.method == "POST" && r.query().split('&').any(|p| p.starts_with("uploadId="))
            }),
            "412 must not CompleteMultipartUpload: {}",
            summarize_reqs(&reqs)
        );
        let abort_q = s3_canonical_query(&[("uploadId", upload_id)]);
        let abort = reqs
            .iter()
            .find(|r| r.method == "DELETE" && r.query() == abort_q)
            .unwrap_or_else(|| panic!("missing abort: {}", summarize_reqs(&reqs)));
        assert_sigv4_covers(abort);
        let logs = captured_logs();
        let logs = &logs[log_from.min(logs.len())..];
        assert!(logs
            .iter()
            .any(|l| l.contains(&format!("query={}", puts[0].query()))));
        assert!(
            !logs.iter().any(|l| {
                l.contains("s3 POST") && l.contains(&format!("query=uploadId={upload_id}"))
            }),
            "log must not record CompleteMultipartUpload for {upload_id}"
        );
        assert_logs_omit_secret(logs);
    }

    #[test]
    fn s3_anonymous_put_errors() {
        install_capture_log();
        let s3 = MockS3Write::spawn("uid-anon", false);
        let _over = OverrideGuard::anonymous(&s3.base_url);
        let loc = parse_s3_url("s3://mybucket/dir/obj.bin").unwrap();
        let log_from = captured_logs().len();
        let err = put_s3_object(&loc, b"nope", Some("\"etag\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("anonymous"), "{err}");
        let err = put_s3_multipart(&loc, Path::new("/no/such/staged-object"), None, None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("anonymous"),
            "auth must fail before opening the staged file: {err}"
        );
        assert!(
            s3.requests().is_empty(),
            "anonymous PUT must not hit the network"
        );
        let logs = captured_logs();
        assert_logs_omit_secret(&logs[log_from.min(logs.len())..]);
    }
}
