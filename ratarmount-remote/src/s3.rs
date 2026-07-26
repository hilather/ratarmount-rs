//! S3 GetObject download-to-temp for `s3://bucket/key` (AWS SigV4 + ureq).

use std::io::Write;

use hmac::{Hmac, Mac};
use log::debug;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use url::Url;

use crate::{RemoteError, Result};

type HmacSha256 = Hmac<Sha256>;

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

struct AwsCreds {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

fn load_credentials() -> Result<AwsCreds> {
    let access_key = std::env::var("AWS_ACCESS_KEY_ID")
        .map_err(|_| RemoteError::S3("AWS_ACCESS_KEY_ID not set (needed for s3:// URLs)".into()))?;
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").map_err(|_| {
        RemoteError::S3("AWS_SECRET_ACCESS_KEY not set (needed for s3:// URLs)".into())
    })?;
    let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
    Ok(AwsCreds {
        access_key,
        secret_key,
        session_token,
    })
}

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

/// Download `s3://bucket/key` to a tempfile.
///
/// Env:
/// - `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / optional `AWS_SESSION_TOKEN`
/// - `AWS_REGION` or `AWS_DEFAULT_REGION` (default `us-east-1`)
/// - `AWS_ENDPOINT_URL` or `S3_ENDPOINT_URL` for MinIO / LocalStack (path-style)
pub fn fetch_s3_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_s3_url(url_str)?;
    fetch_s3_location_to_temp(&loc)
}

pub fn fetch_s3_location_to_temp(loc: &S3Location) -> Result<(NamedTempFile, u64)> {
    let creds = load_credentials()?;
    let region = region();
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let (host, uri_path, use_https) = if let Some(endpoint) = custom_endpoint() {
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
    };

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

    let url = if use_https {
        format!("https://{host}{uri_path}")
    } else {
        format!("http://{host}{uri_path}")
    };
    debug!("s3 GET {url}");

    let mut req = ureq::get(&url)
        .set("User-Agent", "ratarmount-rs/0.1")
        .set("Authorization", &authorization)
        .set("x-amz-content-sha256", &payload_hash)
        .set("x-amz-date", &amz_date);
    if let Some(token) = &creds.session_token {
        req = req.set("x-amz-security-token", token);
    }

    let resp = req
        .call()
        .map_err(|e| RemoteError::S3(format!("GetObject s3://{}/{}: {e}", loc.bucket, loc.key)))?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        let body = resp.into_string().unwrap_or_default();
        return Err(RemoteError::S3(format!(
            "GetObject HTTP {status} for s3://{}/{}: {body}",
            loc.bucket, loc.key
        )));
    }

    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = std::io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
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
}
