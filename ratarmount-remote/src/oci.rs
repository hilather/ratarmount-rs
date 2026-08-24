//! OCI / Docker registry fetch (`oci://`, `docker://`, `ghcr://`).
//!
//! Manifest + layer **descriptors** only. Blob bodies are [`OciBlobRangeFile`]
//! (Bearer on Range GET). Layer TAR/gzip/zstd open is factory `open_from_live_range`
//! (PR-12). This module does not construct `OciImageMountSource` and does not
//! depend on compress/tar/compositing.
//!
//! URL parser is custom (not `url::Url`): `docker://ubuntu:24.04` is not a
//! valid WHATWG URL.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use log::debug;
use serde_json::Value;
use url::Url;

use crate::webdav::basic_auth_header;
use crate::{RemoteError, Result, USER_AGENT};

/// Env: registry username (wins over docker config / GHCR token).
pub const OCI_USER_ENV: &str = "RATARMOUNT_OCI_USER";
/// Env: registry password / token.
pub const OCI_PASSWORD_ENV: &str = "RATARMOUNT_OCI_PASSWORD";
/// Env: path to a docker `config.json` (tests / non-default home).
pub const OCI_DOCKER_CONFIG_ENV: &str = "RATARMOUNT_DOCKER_CONFIG";

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";

const DOCKER_HUB_REGISTRY: &str = "registry-1.docker.io";
const CRED_HELPER_TIMEOUT: Duration = Duration::from_secs(5);

/// Parsed OCI / Docker image reference.
#[derive(Clone, PartialEq, Eq)]
pub struct OciLocation {
    /// Registry host (and optional `:port`). Docker Hub is [`DOCKER_HUB_REGISTRY`].
    pub registry: String,
    /// Repository name (`library/ubuntu`, `org/img`).
    pub name: String,
    /// Tag when no digest is set; default `latest`.
    pub tag: String,
    /// `sha256:…` / `sha512:…` when the ref used `@digest`.
    pub digest: Option<String>,
}

impl std::fmt::Debug for OciLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciLocation")
            .field("registry", &self.registry)
            .field("name", &self.name)
            .field("tag", &self.tag)
            .field("digest", &self.digest)
            .finish()
    }
}

impl OciLocation {
    /// Manifest reference: digest if present, otherwise the tag.
    pub fn manifest_ref(&self) -> &str {
        self.digest.as_deref().unwrap_or(&self.tag)
    }

    /// Registry origin (`http://` for loopback, else `https://`).
    pub fn registry_base_url(&self) -> String {
        registry_base_url(&self.registry)
    }

    /// `GET /v2/<name>/manifests/<ref>` URL.
    pub fn manifest_url(&self) -> String {
        format!(
            "{}/v2/{}/manifests/{}",
            self.registry_base_url(),
            self.name,
            self.manifest_ref()
        )
    }

    /// `GET /v2/<name>/blobs/<digest>` URL.
    pub fn blob_url(&self, digest: &str) -> String {
        format!(
            "{}/v2/{}/blobs/{digest}",
            self.registry_base_url(),
            self.name
        )
    }
}

/// Image descriptors after a successful manifest fetch (no layer bodies).
#[derive(Clone)]
pub struct OciImage {
    pub location: OciLocation,
    pub layers: Vec<OciLayer>,
}

impl std::fmt::Debug for OciImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciImage")
            .field("location", &self.location)
            .field("layers", &self.layers)
            .finish()
    }
}

/// One layer descriptor. [`Self::open_blob`] issues Bearer Range GETs.
#[derive(Clone)]
pub struct OciLayer {
    pub digest: String,
    pub media_type: String,
    pub size: u64,
    pub blob_url: String,
    bearer: Option<String>,
}

impl std::fmt::Debug for OciLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciLayer")
            .field("digest", &self.digest)
            .field("media_type", &self.media_type)
            .field("size", &self.size)
            .field("blob_url", &self.blob_url)
            .field("bearer", &self.bearer.as_ref().map(|_| "***"))
            .finish()
    }
}

impl OciLayer {
    /// Live Range reader for this blob. Safe to call again (factory `reopen`).
    pub fn open_blob(&self) -> Result<OciBlobRangeFile> {
        Ok(OciBlobRangeFile {
            url: self.blob_url.clone(),
            bearer: self.bearer.clone(),
            size: self.size,
            pos: 0,
            buffered: None,
        })
    }
}

/// Seekable OCI blob reader. Sends `Authorization: Bearer` on Range GET when
/// a token was cached; omits the header when anonymous. Not [`crate::HttpRangeFile`].
pub struct OciBlobRangeFile {
    url: String,
    bearer: Option<String>,
    size: u64,
    pos: u64,
    buffered: Option<Vec<u8>>,
}

impl std::fmt::Debug for OciBlobRangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciBlobRangeFile")
            .field("url", &self.url)
            .field("bearer", &self.bearer.as_ref().map(|_| "***"))
            .field("size", &self.size)
            .field("pos", &self.pos)
            .field("uses_ranges", &self.uses_ranges())
            .finish()
    }
}

impl OciBlobRangeFile {
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

/// Parse `oci://` / `docker://` / `ghcr://` / unschemed Docker refs.
///
/// Ordered rules (design P-1): strip scheme; `@sha256:`/`@sha512:` digest;
/// tag vs host port; registry from first segment with `.` or `:`; Hub
/// `library/` prefix; `ghcr://` default registry.
pub fn parse_oci_url(s: &str) -> Result<OciLocation> {
    parse_oci_ref(s)
}

/// Alias of [`parse_oci_url`] (`docker://ubuntu:24.04` is not a WHATWG URL).
pub fn parse_docker_url(s: &str) -> Result<OciLocation> {
    parse_oci_ref(s)
}

/// Fetch the image manifest and layer descriptors. Does not download blobs.
pub fn fetch_oci_image(s: &str) -> Result<OciImage> {
    let loc = parse_oci_url(s)?;
    let creds = lookup_oci_credentials(&loc.registry);
    let (manifest, bearer) = fetch_image_manifest(&loc, creds.as_ref())?;
    let layers = layers_from_manifest(&loc, &manifest, bearer.as_deref())?;
    for layer in &layers {
        debug!(
            "OCI layer {} ({} bytes, {})",
            layer.digest, layer.size, layer.media_type
        );
    }
    Ok(OciImage {
        location: loc,
        layers,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OciScheme {
    None,
    Oci,
    Docker,
    Ghcr,
}

fn parse_oci_ref(s: &str) -> Result<OciLocation> {
    let s = s.trim();
    if s.is_empty() {
        return Err(RemoteError::Url("empty OCI reference".into()));
    }
    let (scheme, rest) = strip_oci_scheme(s)?;
    if rest.is_empty() {
        return Err(RemoteError::Url("OCI reference missing name".into()));
    }

    let (rest, digest) = split_digest(rest)?;
    let (name_and_reg, tag) = split_tag(&rest);

    let (mut registry, mut name) = split_registry_and_name(&name_and_reg, scheme)?;
    registry = normalize_registry(&registry);
    if is_docker_hub(&registry) && !name.contains('/') {
        name = format!("library/{name}");
    }
    if name.is_empty() || name.starts_with('/') || name.ends_with('/') {
        return Err(RemoteError::Url(format!(
            "OCI reference missing repository name: {s}"
        )));
    }

    Ok(OciLocation {
        registry,
        name,
        tag: tag.unwrap_or_else(|| "latest".into()),
        digest,
    })
}

fn strip_oci_scheme(s: &str) -> Result<(OciScheme, &str)> {
    let Some((scheme, rest)) = s.split_once("://") else {
        return Ok((OciScheme::None, s));
    };
    match scheme.to_ascii_lowercase().as_str() {
        "oci" => Ok((OciScheme::Oci, rest)),
        "docker" => Ok((OciScheme::Docker, rest)),
        "ghcr" => Ok((OciScheme::Ghcr, rest)),
        other => Err(RemoteError::UnsupportedScheme(other.to_string())),
    }
}

fn split_digest(s: &str) -> Result<(String, Option<String>)> {
    for algo in ["@sha256:", "@sha512:"] {
        if let Some(idx) = s.find(algo) {
            let digest = s[idx + 1..].to_string();
            if digest.len() < algo.len() {
                return Err(RemoteError::Url(format!("OCI digest empty in {s}")));
            }
            return Ok((s[..idx].to_string(), Some(digest)));
        }
    }
    if s.contains("@") {
        return Err(RemoteError::Url(format!(
            "OCI digest must be @sha256: or @sha512:, got {s}"
        )));
    }
    Ok((s.to_string(), None))
}

/// Tag is after the last `:` that is not a host port (`^[0-9]+$` on the first
/// path segment). Default `None` → caller uses `latest`.
fn split_tag(rest: &str) -> (String, Option<String>) {
    let Some(colon) = rest.rfind(':') else {
        return (rest.to_string(), None);
    };
    let suffix = &rest[colon + 1..];
    let first_slash = rest.find('/');
    let is_host_port = match first_slash {
        Some(slash) => {
            colon < slash
                && !suffix.is_empty()
                && rest[colon + 1..slash].chars().all(|c| c.is_ascii_digit())
        }
        None => !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()),
    };
    if is_host_port {
        (rest.to_string(), None)
    } else {
        (rest[..colon].to_string(), Some(suffix.to_string()))
    }
}

fn split_registry_and_name(rest: &str, scheme: OciScheme) -> Result<(String, String)> {
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return Err(RemoteError::Url("OCI reference missing name".into()));
    }
    let (first, remainder) = match rest.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (rest, None),
    };
    let first_is_registry = first.contains('.') || first.contains(':');
    if scheme == OciScheme::Ghcr && !first_is_registry {
        let name = rest.to_string();
        return Ok(("ghcr.io".into(), name));
    }
    if first_is_registry {
        let name = remainder.unwrap_or("").to_string();
        if name.is_empty() {
            return Err(RemoteError::Url(format!(
                "OCI reference {rest} has registry but no repository name"
            )));
        }
        return Ok((first.to_string(), name));
    }
    Ok((DOCKER_HUB_REGISTRY.to_string(), rest.to_string()))
}

fn normalize_registry(registry: &str) -> String {
    match registry {
        "docker.io" | "index.docker.io" | "registry.docker.io" => DOCKER_HUB_REGISTRY.to_string(),
        other => other.to_string(),
    }
}

fn is_docker_hub(registry: &str) -> bool {
    registry == DOCKER_HUB_REGISTRY || registry == "docker.io" || registry == "index.docker.io"
}

fn registry_base_url(registry: &str) -> String {
    let host = registry_host(registry);
    if is_loopback_host(host) {
        format!("http://{registry}")
    } else {
        format!("https://{registry}")
    }
}

fn registry_host(registry: &str) -> &str {
    if let Some((h, p)) = registry.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            return h;
        }
    }
    registry
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

struct OciCreds {
    user: String,
    password: String,
}

fn fetch_image_manifest(
    loc: &OciLocation,
    creds: Option<&OciCreds>,
) -> Result<(Value, Option<String>)> {
    let url = loc.manifest_url();
    match registry_get_json(&url, None, MANIFEST_ACCEPT) {
        Ok(v) => resolve_manifest(loc, v, None, creds),
        Err(FetchErr::Unauthorized(ch)) => {
            let bearer = fetch_bearer_token(loc, ch.as_ref(), creds)?;
            let v = registry_get_json(&url, bearer.as_deref(), MANIFEST_ACCEPT).map_err(
                |e| match e {
                    FetchErr::Unauthorized(_) => auth_denied(loc, "manifest"),
                    FetchErr::Other(e) => e,
                },
            )?;
            resolve_manifest(loc, v, bearer, creds)
        }
        Err(FetchErr::Other(e)) => Err(e),
    }
}

fn resolve_manifest(
    loc: &OciLocation,
    v: Value,
    bearer: Option<String>,
    creds: Option<&OciCreds>,
) -> Result<(Value, Option<String>)> {
    if !is_index_manifest(&v) {
        return Ok((v, bearer));
    }
    let digest = pick_index_digest(&v)?;
    let url = format!(
        "{}/v2/{}/manifests/{digest}",
        loc.registry_base_url(),
        loc.name
    );
    match registry_get_json(&url, bearer.as_deref(), MANIFEST_ACCEPT) {
        Ok(child) => Ok((child, bearer)),
        Err(FetchErr::Unauthorized(ch)) => {
            let bearer = fetch_bearer_token(loc, ch.as_ref(), creds)?;
            let child = registry_get_json(&url, bearer.as_deref(), MANIFEST_ACCEPT).map_err(
                |e| match e {
                    FetchErr::Unauthorized(_) => auth_denied(loc, "index manifest"),
                    FetchErr::Other(e) => e,
                },
            )?;
            Ok((child, bearer))
        }
        Err(FetchErr::Other(e)) => Err(e),
    }
}

fn is_index_manifest(v: &Value) -> bool {
    let mt = v.get("mediaType").and_then(|x| x.as_str()).unwrap_or("");
    let mt_l = mt.to_ascii_lowercase();
    if mt_l.contains("image.index") || mt_l.contains("manifest.list") {
        return true;
    }
    v.get("manifests").is_some() && v.get("layers").is_none()
}

fn pick_index_digest(v: &Value) -> Result<String> {
    let manifests = v
        .get("manifests")
        .and_then(|m| m.as_array())
        .ok_or_else(|| RemoteError::Http("OCI index missing manifests".into()))?;
    let want_arch = oci_arch();
    let mut first_linux: Option<String> = None;
    for m in manifests {
        let digest = m
            .get("digest")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        if digest.is_empty() {
            continue;
        }
        let os = m
            .get("platform")
            .and_then(|p| p.get("os"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let arch = m
            .get("platform")
            .and_then(|p| p.get("architecture"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if os == "linux" || os.is_empty() {
            if first_linux.is_none() {
                first_linux = Some(digest.clone());
            }
            if os == "linux" && arch == want_arch {
                return Ok(digest);
            }
        }
    }
    first_linux.ok_or_else(|| RemoteError::Http("OCI index has no linux manifest".into()))
}

fn layers_from_manifest(
    loc: &OciLocation,
    manifest: &Value,
    bearer: Option<&str>,
) -> Result<Vec<OciLayer>> {
    let layers = manifest
        .get("layers")
        .and_then(|l| l.as_array())
        .ok_or_else(|| RemoteError::Http("OCI manifest missing layers".into()))?;
    let mut out = Vec::with_capacity(layers.len());
    for layer in layers {
        let digest = layer
            .get("digest")
            .and_then(|d| d.as_str())
            .ok_or_else(|| RemoteError::Http("OCI layer missing digest".into()))?
            .to_string();
        let media_type = layer
            .get("mediaType")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        let size = layer.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
        if !layer_media_type_supported(&media_type) {
            debug!("OCI skipping unsupported layer media type {media_type} ({digest})");
            continue;
        }
        out.push(OciLayer {
            blob_url: loc.blob_url(&digest),
            digest,
            media_type,
            size,
            bearer: bearer.map(str::to_string),
        });
    }
    if out.is_empty() {
        return Err(RemoteError::Http(
            "OCI manifest has no tar/gzip/zstd layers".into(),
        ));
    }
    Ok(out)
}

fn layer_media_type_supported(mt: &str) -> bool {
    let l = mt.to_ascii_lowercase();
    l.contains("tar") || l.is_empty()
}

enum FetchErr {
    Unauthorized(Option<BearerChallenge>),
    Other(RemoteError),
}

fn registry_get_json(
    url: &str,
    bearer: Option<&str>,
    accept: &str,
) -> std::result::Result<Value, FetchErr> {
    let mut req = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", accept);
    if let Some(t) = bearer {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    match req.call() {
        Ok(resp) => {
            let status = resp.status();
            if !(200..300).contains(&status) {
                return Err(FetchErr::Other(RemoteError::Http(format!(
                    "HTTP {status} for {url}"
                ))));
            }
            let body = resp
                .into_string()
                .map_err(|e| FetchErr::Other(RemoteError::Http(format!("reading {url}: {e}"))))?;
            serde_json::from_str(&body).map_err(|e| {
                FetchErr::Other(RemoteError::Http(format!("OCI JSON from {url}: {e}")))
            })
        }
        Err(ureq::Error::Status(401, resp)) => {
            let ch = resp
                .header("WWW-Authenticate")
                .and_then(parse_bearer_challenge);
            Err(FetchErr::Unauthorized(ch))
        }
        Err(ureq::Error::Status(status, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            let snippet: String = body.chars().take(200).collect();
            Err(FetchErr::Other(RemoteError::Http(format!(
                "HTTP {status} for {url}: {snippet}"
            ))))
        }
        Err(e) => Err(FetchErr::Other(RemoteError::Http(e.to_string()))),
    }
}

fn fetch_bearer_token(
    loc: &OciLocation,
    challenge: Option<&BearerChallenge>,
    creds: Option<&OciCreds>,
) -> Result<Option<String>> {
    let Some(ch) = challenge else {
        if creds.is_some() {
            return Err(auth_denied(loc, "token (no WWW-Authenticate Bearer)"));
        }
        return Ok(None);
    };
    let scope = ch
        .scope
        .clone()
        .unwrap_or_else(|| format!("repository:{}:pull", loc.name));
    let service = ch.service.clone().unwrap_or_else(|| loc.registry.clone());
    let mut token_url = Url::parse(&ch.realm)
        .map_err(|e| RemoteError::Http(format!("OCI token realm {}: {e}", ch.realm)))?;
    token_url
        .query_pairs_mut()
        .append_pair("service", &service)
        .append_pair("scope", &scope);
    let url = token_url.to_string();
    let mut req = ureq::get(&url).set("User-Agent", USER_AGENT);
    if let Some(c) = creds {
        req = req.set(
            "Authorization",
            &basic_auth_header(&c.user, Some(&c.password)),
        );
    }
    match req.call() {
        Ok(resp) => {
            let body = resp
                .into_string()
                .map_err(|e| RemoteError::Http(format!("OCI token response: {e}")))?;
            let v: Value = serde_json::from_str(&body)
                .map_err(|e| RemoteError::Http(format!("OCI token JSON: {e}")))?;
            let token = v
                .get("token")
                .or_else(|| v.get("access_token"))
                .and_then(|t| t.as_str())
                .ok_or_else(|| RemoteError::Http("OCI token response missing token".into()))?;
            if token.is_empty() {
                return Err(RemoteError::Http("OCI token response empty token".into()));
            }
            Ok(Some(token.to_string()))
        }
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => {
            Err(auth_denied(loc, "token"))
        }
        Err(ureq::Error::Status(status, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            let snippet: String = body.chars().take(200).collect();
            Err(RemoteError::Http(format!(
                "HTTP {status} fetching OCI token: {snippet}"
            )))
        }
        Err(e) => Err(RemoteError::Http(e.to_string())),
    }
}

fn auth_denied(loc: &OciLocation, what: &str) -> RemoteError {
    RemoteError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "OCI {what} unauthorized for {}/{} (tried {OCI_USER_ENV}/{OCI_PASSWORD_ENV}, docker config, GITHUB_TOKEN)",
            loc.registry, loc.name
        ),
    ))
}

fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let lower = header.to_ascii_lowercase();
    let idx = lower.find("bearer")?;
    let rest = header[idx + 6..].trim();
    let params = parse_auth_params(rest);
    let realm = params.get("realm")?.clone();
    Some(BearerChallenge {
        realm,
        service: params.get("service").cloned(),
        scope: params.get("scope").cloned(),
    })
}

fn parse_auth_params(s: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b',' || (b[i] as char).is_ascii_whitespace()) {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let key_start = i;
        while i < b.len() && b[i] != b'=' {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let key = s[key_start..i].trim().to_ascii_lowercase();
        i += 1;
        while i < b.len() && (b[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        let val = if i < b.len() && b[i] == b'"' {
            i += 1;
            let vs = i;
            while i < b.len() && b[i] != b'"' {
                i += 1;
            }
            let v = s[vs..i].to_string();
            if i < b.len() {
                i += 1;
            }
            v
        } else {
            let vs = i;
            while i < b.len() && b[i] != b',' {
                i += 1;
            }
            s[vs..i].trim().to_string()
        };
        if !key.is_empty() {
            map.insert(key, val);
        }
    }
    map
}

fn lookup_oci_credentials(registry: &str) -> Option<OciCreds> {
    if let Ok(user) = std::env::var(OCI_USER_ENV) {
        if !user.is_empty() {
            let password = std::env::var(OCI_PASSWORD_ENV).unwrap_or_default();
            return Some(OciCreds { user, password });
        }
    }
    if let Some(c) = creds_from_docker_config(registry) {
        return Some(c);
    }
    if registry_host(registry) == "ghcr.io" || registry.ends_with(".ghcr.io") {
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if !token.is_empty() {
                let user = std::env::var("USERNAME").unwrap_or_else(|_| "x-access-token".into());
                return Some(OciCreds {
                    user,
                    password: token,
                });
            }
        }
    }
    None
}

fn creds_from_docker_config(registry: &str) -> Option<OciCreds> {
    let path = docker_config_path()?;
    let text = std::fs::read_to_string(&path).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let keys = docker_auth_keys(registry);
    if let Some(auths) = v.get("auths").and_then(|a| a.as_object()) {
        for k in &keys {
            if let Some(entry) = auths.get(k) {
                if let Some(c) = creds_from_auth_entry(entry) {
                    return Some(c);
                }
            }
        }
    }
    if let Some(helpers) = v.get("credHelpers").and_then(|h| h.as_object()) {
        for k in &keys {
            if let Some(helper) = helpers.get(k).and_then(|x| x.as_str()) {
                if let Some(c) = creds_from_helper(helper, k) {
                    return Some(c);
                }
            }
        }
    }
    if let Some(store) = v.get("credsStore").and_then(|s| s.as_str()) {
        if let Some(c) = creds_from_helper(store, registry_host(registry)) {
            return Some(c);
        }
    }
    None
}

fn docker_config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var(OCI_DOCKER_CONFIG_ENV) {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
        let joined = pb.join("config.json");
        if joined.is_file() {
            return Some(joined);
        }
    }
    if let Ok(dir) = std::env::var("DOCKER_CONFIG") {
        let joined = Path::new(&dir).join("config.json");
        if joined.is_file() {
            return Some(joined);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let p = Path::new(&home).join(".docker/config.json");
    p.is_file().then_some(p)
}

fn docker_auth_keys(registry: &str) -> Vec<String> {
    let host = registry_host(registry);
    let mut keys = vec![
        registry.to_string(),
        host.to_string(),
        format!("https://{registry}"),
        format!("https://{host}"),
        format!("http://{registry}"),
        format!("http://{host}"),
    ];
    if is_docker_hub(registry) {
        keys.push("https://index.docker.io/v1/".into());
        keys.push("https://index.docker.io/v1".into());
        keys.push("docker.io".into());
    }
    keys
}

fn creds_from_auth_entry(entry: &Value) -> Option<OciCreds> {
    if let Some(auth) = entry.get("auth").and_then(|a| a.as_str()) {
        let raw = base64_decode(auth)?;
        let s = String::from_utf8(raw).ok()?;
        let (user, password) = match s.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (s, String::new()),
        };
        return Some(OciCreds { user, password });
    }
    let user = entry.get("username").and_then(|u| u.as_str())?;
    let password = entry.get("password").and_then(|p| p.as_str()).unwrap_or("");
    Some(OciCreds {
        user: user.to_string(),
        password: password.to_string(),
    })
}

fn creds_from_helper(helper: &str, server: &str) -> Option<OciCreds> {
    if helper.is_empty() {
        return None;
    }
    let bin = format!("docker-credential-{helper}");
    let mut child = Command::new(&bin)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(server.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let status = wait_with_timeout(&mut child, CRED_HELPER_TIMEOUT).ok()?;
    if !status.success() {
        return None;
    }
    let mut stdout = child.stdout.take()?;
    let mut buf = String::new();
    stdout.read_to_string(&mut buf).ok()?;
    let v: Value = serde_json::from_str(&buf).ok()?;
    let user = v.get("Username").and_then(|u| u.as_str())?;
    let secret = v.get("Secret").and_then(|s| s.as_str()).unwrap_or("");
    Some(OciCreds {
        user: user.to_string(),
        password: secret.to_string(),
    })
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> io::Result<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(st) => return Ok(st),
            None if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "docker-credential helper timed out",
                ));
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
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
    // `usize::is_multiple_of` is 1.87+; keep `%` for workspace MSRV 1.74.
    #[allow(clippy::manual_is_multiple_of)]
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        let c = if chunk[2] == b'=' { 0 } else { val(chunk[2])? };
        let d = if chunk[3] == b'=' { 0 } else { val(chunk[3])? };
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

impl Read for OciBlobRangeFile {
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
        let range = format!("bytes={}-{}", self.pos, end - 1);
        let mut req = ureq::get(&self.url)
            .set("User-Agent", USER_AGENT)
            .set("Range", &range);
        if let Some(t) = &self.bearer {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        let resp = req.call().map_err(|e| match e {
            ureq::Error::Status(401, _) | ureq::Error::Status(403, _) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("OCI blob 401/403 for {}", self.url),
            ),
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
        if status == 401 || status == 403 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("OCI blob HTTP {status} for {}", self.url),
            ));
        }
        Err(io::Error::other(format!(
            "HTTP {status} for range {range} on {}",
            self.url
        )))
    }
}

impl Seek for OciBlobRangeFile {
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
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

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

    const OCI_ENV_KEYS: &[&str] = &[
        OCI_USER_ENV,
        OCI_PASSWORD_ENV,
        OCI_DOCKER_CONFIG_ENV,
        "DOCKER_CONFIG",
        "GITHUB_TOKEN",
        "USERNAME",
        "HOME",
    ];

    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOKEN: &str = "test-oci-bearer-token";

    #[test]
    fn parse_oci_url_table() {
        let cases: &[(&str, &str, &str, &str, Option<&str>)] = &[
            (
                "ubuntu:24.04",
                DOCKER_HUB_REGISTRY,
                "library/ubuntu",
                "24.04",
                None,
            ),
            (
                "library/ubuntu:24.04",
                DOCKER_HUB_REGISTRY,
                "library/ubuntu",
                "24.04",
                None,
            ),
            (
                "docker://ubuntu:24.04",
                DOCKER_HUB_REGISTRY,
                "library/ubuntu",
                "24.04",
                None,
            ),
            (
                "oci://ghcr.io/org/img:tag",
                "ghcr.io",
                "org/img",
                "tag",
                None,
            ),
            (
                "docker://ghcr.io/org/img:tag",
                "ghcr.io",
                "org/img",
                "tag",
                None,
            ),
            (
                "localhost:5000/foo/bar:v1",
                "localhost:5000",
                "foo/bar",
                "v1",
                None,
            ),
            (
                "oci://localhost:5000/foo/bar:v1",
                "localhost:5000",
                "foo/bar",
                "v1",
                None,
            ),
            (
                "ghcr://org/name:latest",
                "ghcr.io",
                "org/name",
                "latest",
                None,
            ),
            (
                "ubuntu@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                DOCKER_HUB_REGISTRY,
                "library/ubuntu",
                "latest",
                Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ),
        ];
        for (input, registry, name, tag, digest) in cases {
            let loc = parse_oci_url(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(loc.registry, *registry, "registry {input}");
            assert_eq!(loc.name, *name, "name {input}");
            assert_eq!(loc.tag, *tag, "tag {input}");
            assert_eq!(loc.digest.as_deref(), *digest, "digest {input}");
            let via_docker = parse_docker_url(input).unwrap();
            assert_eq!(via_docker, loc, "parse_docker_url {input}");
        }
        // WHATWG `Url` treats `:24.04` as a port; our parser must still accept it.
        assert!(url::Url::parse("docker://ubuntu:24.04").is_err());
    }

    #[test]
    fn parse_localhost_port_without_tag_is_latest() {
        let loc = parse_oci_url("localhost:5000/foo/bar").unwrap();
        assert_eq!(loc.registry, "localhost:5000");
        assert_eq!(loc.name, "foo/bar");
        assert_eq!(loc.tag, "latest");
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_oci_url("").is_err());
        assert!(parse_oci_url("oci://").is_err());
    }

    #[test]
    fn credentials_and_debug_redact_secrets() {
        let layer = OciLayer {
            digest: DIGEST_A.into(),
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            size: 4,
            blob_url: "http://127.0.0.1/v2/n/blobs/sha256:aa".into(),
            bearer: Some(TOKEN.into()),
        };
        let dbg = format!("{layer:?}");
        assert!(!dbg.contains(TOKEN), "OciLayer Debug leaked bearer: {dbg}");
        assert!(dbg.contains("***"), "{dbg}");
        let blob = layer.open_blob().unwrap();
        let dbg = format!("{blob:?}");
        assert!(
            !dbg.contains(TOKEN),
            "OciBlobRangeFile Debug leaked bearer: {dbg}"
        );
    }

    struct MockOci {
        addr: String,
        log: Arc<Mutex<Vec<String>>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockOci {
        fn spawn(blob: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let bound = listener.local_addr().unwrap();
            let addr = format!("{bound}");
            let log = Arc::new(Mutex::new(Vec::new()));
            let log_c = Arc::clone(&log);
            let blob_c = blob;
            let join = thread::spawn(move || {
                listener.set_nonblocking(false).ok();
                for stream in listener.incoming().take(64) {
                    let Ok(stream) = stream else { continue };
                    serve_oci(stream, &blob_c, &log_c);
                }
            });
            Self {
                addr,
                log,
                _join: Some(join),
            }
        }
    }

    fn serve_oci(mut stream: std::net::TcpStream, blob: &[u8], log: &Arc<Mutex<Vec<String>>>) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        let mut auth: Option<String> = None;
        let mut range: Option<String> = None;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            if line == "\r\n" || line == "\n" || line.is_empty() {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("authorization:") {
                let start = line.len() - rest.len();
                auth = Some(line[start..].trim().to_string());
            }
            if let Some(v) = line.strip_prefix("Range:") {
                range = Some(v.trim().to_string());
            }
        }
        let req = request_line.trim().to_string();
        {
            let mut lg = log.lock().unwrap();
            lg.push(req.clone());
            match &auth {
                Some(a) if a.starts_with("Bearer ") => lg.push("Authorization: Bearer ***".into()),
                Some(a) if a.starts_with("Basic ") => lg.push("Authorization: Basic ***".into()),
                Some(_) => lg.push("Authorization: other".into()),
                None => lg.push("Authorization: absent".into()),
            }
            if let Some(r) = &range {
                lg.push(format!("Range: {r}"));
            }
        }

        let path = req.split_whitespace().nth(1).unwrap_or("");
        let is_get = req.starts_with("GET ");

        if !is_get {
            let _ = write!(
                stream,
                "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            return;
        }

        if path.starts_with("/token") {
            let body = format!(r#"{{"token":"{TOKEN}"}}"#);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            return;
        }

        let bearer_ok = auth.as_deref() == Some(&format!("Bearer {TOKEN}"));

        if path.contains("/manifests/") {
            if !bearer_ok {
                let realm = match stream.local_addr() {
                    Ok(a) => format!("http://{a}/token"),
                    Err(_) => "http://127.0.0.1/token".into(),
                };
                let www = format!(
                    "Bearer realm=\"{realm}\",service=\"registry\",scope=\"repository:foo/bar:pull\""
                );
                let body = b"unauthorized";
                let _ = write!(
                    stream,
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {www}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(body);
                return;
            }
            let manifest = format!(
                r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{DIGEST_A}","size":{}}}]}}"#,
                blob.len()
            );
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oci.image.manifest.v1+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{manifest}",
                manifest.len()
            );
            return;
        }

        if path.contains("/blobs/") {
            if !bearer_ok {
                let body = b"unauthorized blob";
                let _ = write!(
                    stream,
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"/token\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(body);
                return;
            }
            if let Some(r) = range.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
                let parts: Vec<&str> = r.splitn(2, '-').collect();
                if parts.len() == 2 {
                    let start: u64 = parts[0].parse().unwrap_or(0);
                    let end: u64 = if parts[1].is_empty() {
                        (blob.len() as u64).saturating_sub(1)
                    } else {
                        parts[1].parse().unwrap_or(0)
                    };
                    let start = start as usize;
                    let end = (end as usize).min(blob.len().saturating_sub(1));
                    if start < blob.len() && start <= end {
                        let slice = &blob[start..=end];
                        let hdr = format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                            slice.len(),
                            blob.len()
                        );
                        let _ = stream.write_all(hdr.as_bytes());
                        let _ = stream.write_all(slice);
                        return;
                    }
                }
            }
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                blob.len()
            );
            let _ = stream.write_all(hdr.as_bytes());
            let _ = stream.write_all(blob);
            return;
        }

        let _ = write!(
            stream,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn fetch_oci_image_bearer_on_manifest_and_blob_range() {
        let _g = EnvGuard::acquire(OCI_ENV_KEYS);
        let body = b"oci-layer-bytes!!".to_vec();
        let mock = MockOci::spawn(body.clone());
        let url = format!("oci://{}/foo/bar:v1", mock.addr);
        let loc = parse_oci_url(&url).unwrap();
        assert_eq!(loc.registry, mock.addr);
        assert_eq!(loc.name, "foo/bar");
        assert_eq!(loc.tag, "v1");

        let img = fetch_oci_image(&url).expect("fetch_oci_image");
        assert_eq!(img.layers.len(), 1);
        assert_eq!(img.layers[0].digest, DIGEST_A);
        assert_eq!(img.layers[0].size, body.len() as u64);
        assert!(
            img.layers[0].blob_url.contains("/blobs/"),
            "{}",
            img.layers[0].blob_url
        );
        let dbg = format!("{img:?}");
        assert!(!dbg.contains(TOKEN), "OciImage Debug leaked token: {dbg}");

        let mut blob = img.layers[0].open_blob().unwrap();
        assert!(blob.uses_ranges());
        let mut got = Vec::new();
        blob.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        blob.seek(SeekFrom::Start(4)).unwrap();
        let mut mid = [0u8; 5];
        blob.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, b"layer");

        let log = mock.log.lock().unwrap().clone();
        assert!(
            log.iter().any(|l| l.contains("/manifests/v1")),
            "manifest GET missing: {log:?}"
        );
        assert!(
            log.iter().any(|l| l.contains("/token")),
            "token GET missing: {log:?}"
        );
        let manifest_authed = log
            .windows(2)
            .any(|w| w[0].contains("/manifests/") && w[1] == "Authorization: Bearer ***");
        assert!(manifest_authed, "manifest GET must send Bearer: {log:?}");
        let blob_range_authed = log.windows(3).any(|w| {
            w[0].contains("/blobs/")
                && w[1] == "Authorization: Bearer ***"
                && w[2].starts_with("Range:")
        }) || log.windows(3).any(|w| {
            w[0].contains("/blobs/")
                && w[1].starts_with("Range:")
                && w.iter().any(|l| l == "Authorization: Bearer ***")
        });
        // Order: request line, Authorization, optional Range.
        let blob_ok = log.iter().enumerate().any(|(i, l)| {
            l.contains("/blobs/")
                && log
                    .get(i + 1)
                    .is_some_and(|a| a == "Authorization: Bearer ***")
                && log.iter().any(|r| r.starts_with("Range:"))
        });
        assert!(
            blob_ok || blob_range_authed,
            "Regression: blob Range GET uses Bearer; log={log:?}"
        );
        assert!(
            !log.iter().any(|l| l.contains(TOKEN)),
            "raw bearer in mock log: {log:?}"
        );
    }

    /// Regression: blob Range GET uses Bearer (not Basic / not omitted).
    #[test]
    fn regression_blob_range_get_uses_bearer() {
        let _g = EnvGuard::acquire(OCI_ENV_KEYS);
        let body = b"range-bearer-body".to_vec();
        let mock = MockOci::spawn(body);
        let img = fetch_oci_image(&format!("oci://{}/foo/bar:v1", mock.addr)).unwrap();
        let mut f = img.layers[0].open_blob().unwrap();
        let mut buf = [0u8; 4];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"rang");
        let log = mock.log.lock().unwrap().clone();
        assert!(
            log.iter().any(|l| l.contains("/blobs/")),
            "no blob GET: {log:?}"
        );
        for (i, line) in log.iter().enumerate() {
            if line.contains("/blobs/") {
                let auth = log.get(i + 1).map(|s| s.as_str()).unwrap_or("");
                assert_eq!(
                    auth, "Authorization: Bearer ***",
                    "Regression: blob Range GET uses Bearer; around {line}: {log:?}"
                );
                assert!(!auth.contains("Basic"), "blob GET used Basic: {log:?}");
            }
        }
        assert!(log.iter().any(|l| l.starts_with("Range:")));
    }

    #[test]
    fn docker_config_auths_are_used_for_token() {
        let _g = EnvGuard::acquire(OCI_ENV_KEYS);
        let dir = tempfile::tempdir().unwrap();
        // echo -n 'alice:s3cret' | base64
        let cfg = dir.path().join("config.json");
        std::fs::write(&cfg, r#"{"auths":{"ghcr.io":{"auth":"YWxpY2U6czNjcmV0"}}}"#).unwrap();
        _g.set(OCI_DOCKER_CONFIG_ENV, cfg.to_str().unwrap());
        let c = creds_from_docker_config("ghcr.io").expect("docker config auths");
        assert_eq!(c.user, "alice");
        assert_eq!(c.password, "s3cret");
        let dbg = format!(
            "{:?}",
            OciLayer {
                digest: "sha256:x".into(),
                media_type: "tar".into(),
                size: 1,
                blob_url: "http://x".into(),
                bearer: Some(c.password.clone()),
            }
        );
        assert!(!dbg.contains("s3cret"), "{dbg}");
    }

    #[test]
    fn parse_bearer_challenge_quoted_scope_with_comma() {
        let h = r#"Bearer realm="https://auth.example/token",service="registry",scope="repository:foo/bar:pull,push""#;
        let ch = parse_bearer_challenge(h).unwrap();
        assert_eq!(ch.realm, "https://auth.example/token");
        assert_eq!(ch.service.as_deref(), Some("registry"));
        assert_eq!(ch.scope.as_deref(), Some("repository:foo/bar:pull,push"));
    }
}
