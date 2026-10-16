//! Commit-pinned Hugging Face Hub files and directory trees over blocking HTTP.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, SystemTime};

use ratarmount_core::{ArchiveRead, CheapDirent, FileInfo, ListResult, MountSource, UserData};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    http_pool, HttpAuthOptions, HttpLocation, HttpRangeFile, RemoteDirent, RemoteError,
    RemoteFolderMountSource, RemoteListing, Result, USER_AGENT,
};

const MAX_ENTRIES: usize = 1_000_000;
// Even mirrors returning one entry per page can reach the entry limit.
const MAX_PAGES: usize = MAX_ENTRIES + 1;
const MAX_BUFFER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_API_RETRIES: usize = 3;
const MAX_JSON_BYTES: u64 = 256 * 1024 * 1024;
const TOKEN_HELP: &str =
    "set HF_TOKEN (or HUGGING_FACE_HUB_TOKEN), HF_TOKEN_PATH, HF_HOME/token, or $XDG_CACHE_HOME/huggingface/token (default ~/.cache/huggingface/token)";

fn error(message: impl Into<String>) -> RemoteError {
    RemoteError::Hf(message.into())
}

pub(crate) fn map_http_error(repo: &str, err: ureq::Error) -> RemoteError {
    let ureq::Error::Status(status, response) = err else {
        return error(format!("Hub request failed for {repo}"));
    };
    let code = response.header("X-Error-Code").map(str::to_owned);
    let detail = match code.as_deref() {
        Some("RepoNotFound") => "repository not found or private",
        Some("GatedRepo") => "gated repository; request access or accept its terms",
        Some("RevisionNotFound") => "revision not found",
        Some("EntryNotFound") => "entry not found",
        _ if status == 401 => "repository not found or private",
        _ if status == 403 => "access forbidden; check repository access and gated terms",
        _ if status == 429 => "Hub rate limit exceeded",
        _ => "Hub request failed",
    };
    let hint = if matches!(status, 401 | 403)
        || matches!(code.as_deref(), Some("RepoNotFound" | "GatedRepo"))
    {
        format!("; {TOKEN_HELP}")
    } else {
        String::new()
    };
    RemoteError::HfStatus {
        status,
        code,
        message: format!("HTTP {status} for Hub repo {repo}: {detail}{hint}"),
    }
}

fn retry_after(value: Option<&str>, now: SystemTime) -> Duration {
    let seconds = value
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            let date = chrono::DateTime::parse_from_rfc2822(value?).ok()?;
            let now = now.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
            Some((date.timestamp().max(0) as u64).saturating_sub(now))
        })
        .unwrap_or(1);
    Duration::from_secs(seconds.min(5))
}

fn clean_token(value: String) -> Option<String> {
    let value = value.replace(['\r', '\n'], "").trim().to_string();
    (!value.is_empty()).then_some(value)
}

// Python expanduser followed by expandvars, with unknown variables left intact.
fn expand_env_path(path: &str, env: &impl Fn(&str) -> Option<String>) -> String {
    let path = if path == "~" || path.starts_with("~/") {
        env("HOME")
            .map(|home| format!("{home}{}", &path[1..]))
            .unwrap_or_else(|| path.into())
    } else {
        path.into()
    };
    let mut out = String::new();
    let mut rest = path.as_str();
    while let Some(start) = rest.find('$') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let variable = if let Some(braced) = after.strip_prefix('{') {
            braced.find('}').map(|end| (&braced[..end], end + 2))
        } else {
            let len = after
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            (len > 0).then_some((&after[..len], len))
        };
        if let Some((name, len)) = variable {
            if let Some(value) = env(name) {
                out.push_str(&value);
            } else {
                out.push_str(&rest[start..start + 1 + len]);
            }
            rest = &after[len..];
        } else {
            out.push('$');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

static HTTP_TOKEN_WARNING: Once = Once::new();

fn warn_plain_http(config: &Config, once: &Once) -> bool {
    let mut warned = false;
    if config.endpoint.scheme() == "http" && config.token.is_some() {
        once.call_once(|| {
            log::warn!("HF_ENDPOINT uses plain HTTP: the Hub token will be sent in cleartext; use HTTPS for remote endpoints");
            warned = true;
        });
    }
    warned
}

enum CachedFile {
    Ready {
        source: Arc<http_pool::HttpRangeSource>,
        size: u64,
        buffered: Option<Arc<[u8]>>,
    },
    TooLarge,
}

fn bounded_body(mut reader: impl Read, cap: u64) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    reader.by_ref().take(cap).read_to_end(&mut bytes)?;
    // Keep the overflow byte on the stack instead of growing a full buffer.
    Ok((reader.read(&mut [0; 1])? == 0).then_some(bytes))
}

type FileCache = Arc<Mutex<BTreeMap<String, Arc<Mutex<Option<CachedFile>>>>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfLocation {
    /// API collection: models, datasets, or spaces.
    pub kind: String,
    pub repo: String,
    pub revision: String,
    pub path: String,
}

fn decode(s: &str) -> Result<String> {
    let mut out = Vec::new();
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let a = bytes.next().and_then(|c| (c as char).to_digit(16));
            let b = bytes.next().and_then(|c| (c as char).to_digit(16));
            match (a, b) {
                (Some(a), Some(b)) => out.push((a * 16 + b) as u8),
                _ => return Err(error("invalid percent escape in hf URL")),
            }
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).map_err(|_| error("hf URL is not UTF-8"))
}

pub(crate) fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            write!(out, "%{b:02X}").unwrap();
        }
    }
    out
}

pub(crate) fn encode_path(s: &str) -> String {
    s.split('/').map(encode).collect::<Vec<_>>().join("/")
}

fn valid_path(s: &str) -> bool {
    !s.is_empty()
        && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
        && !s.chars().any(|c| c.is_control() || c == '\\')
}

/// Parse Hub paths without treating the repo owner as a DNS host.
/// Legacy model file paths use `name@revision/path` to disambiguate `org/name`.
pub fn parse_hf_url(input: &str) -> Result<HfLocation> {
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| error("expected hf:// URL"))?;
    if !scheme.eq_ignore_ascii_case("hf") || rest.contains(['?', '#']) {
        return Err(error(
            "invalid hf:// URL (queries and fragments are not supported)",
        ));
    }
    let (kind, rest) = if let Some(s) = rest.strip_prefix("datasets/") {
        ("datasets", s)
    } else if let Some(s) = rest.strip_prefix("spaces/") {
        ("spaces", s)
    } else {
        ("models", rest)
    };
    let parts: Vec<_> = rest.trim_end_matches('/').split('/').collect();
    let repo_parts = if parts[0].contains('@') || parts.len() == 1 {
        1
    } else {
        2
    };
    let last = parts[repo_parts - 1];
    let (name, rev) = last
        .split_once('@')
        .map_or((last, None), |(n, r)| (n, Some(r)));
    let repo = if repo_parts == 1 {
        name.to_string()
    } else {
        format!("{}/{name}", parts[0])
    };
    if !valid_path(&repo)
        || !repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
    {
        return Err(error("invalid Hub repository id"));
    }
    let mut path_start = repo_parts;
    let revision = match rev {
        None => "main".into(),
        Some("refs") if parts.get(path_start) == Some(&"pr") => {
            let number = parts
                .get(path_start + 1)
                .ok_or_else(|| error("expected refs/pr/N"))?;
            if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
                return Err(error("expected numeric refs/pr/N"));
            }
            path_start += 2;
            format!("refs/pr/{number}")
        }
        Some("refs")
            if parts.get(path_start..path_start + 2) == Some(&["convert", "parquet"][..]) =>
        {
            path_start += 2;
            "refs/convert/parquet".into()
        }
        Some(r) => decode(r)?,
    };
    if !valid_path(&revision) || revision.contains('@') || revision == "refs" {
        return Err(error(
            "invalid Hub revision; encode slashes in other branch names as %2F",
        ));
    }
    let path = decode(&parts[path_start..].join("/"))?;
    if !path.is_empty() && !valid_path(&path) {
        return Err(error("invalid path in Hub repository"));
    }
    Ok(HfLocation {
        kind: kind.into(),
        repo,
        revision,
        path,
    })
}

#[derive(Clone)]
struct Config {
    endpoint: Url,
    token: Option<SecretString>,
    cache: Option<PathBuf>,
    offline: bool,
}

impl Config {
    fn from_env() -> Result<Self> {
        Self::from_values(|key| std::env::var(key).ok())
    }

    fn from_values(env: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let endpoint = env("HF_ENDPOINT").unwrap_or_else(|| "https://huggingface.co".into());
        let endpoint = Url::parse(&format!("{}/", endpoint.trim_end_matches('/')))
            .map_err(|_| error("HF_ENDPOINT must be an absolute HTTP(S) URL"))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(error(
                "HF_ENDPOINT must be an HTTP(S) URL without credentials, query or fragment",
            ));
        }
        // Match huggingface_hub: select the first nonempty raw environment value,
        // then clean it; a whitespace-only HF_TOKEN does not select the legacy token.
        let token = env("HF_TOKEN")
            .filter(|s| !s.is_empty())
            .or_else(|| env("HUGGING_FACE_HUB_TOKEN"))
            .and_then(clean_token);
        let token = if token.is_some() {
            token
        } else {
            let home = env("HF_HOME").unwrap_or_else(|| {
                let cache = env("XDG_CACHE_HOME").unwrap_or_else(|| "~/.cache".into());
                format!("{cache}/huggingface")
            });
            let home = expand_env_path(&home, &env);
            let path = env("HF_TOKEN_PATH").unwrap_or_else(|| format!("{home}/token"));
            match std::fs::read_to_string(expand_env_path(&path, &env)) {
                Ok(value) => clean_token(value),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(error(format!(
                        "cannot read Hub token file: {e}; {TOKEN_HELP}"
                    )))
                }
            }
        }
        .map(SecretString::new);
        let cache = env("RATARMOUNT_HF_TREE_CACHE")
            .map(PathBuf::from)
            .or_else(|| {
                env("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| env("HOME").map(|p| PathBuf::from(p).join(".cache")))
                    .map(|p| p.join("ratarmount/hf-tree-v1"))
            });
        let offline = env("HF_HUB_OFFLINE")
            .filter(|s| !s.is_empty())
            .or_else(|| env("TRANSFORMERS_OFFLINE"))
            .is_some_and(|s| {
                matches!(s.to_ascii_uppercase().as_str(), "1" | "TRUE" | "YES" | "ON")
            });
        Ok(Self {
            endpoint,
            token,
            cache,
            offline,
        })
    }

    fn online(&self) -> Result<()> {
        if self.offline {
            Err(error("HF_HUB_OFFLINE is enabled: hf:// requires network access; cached listings alone do not contain file data (offline Hub snapshots are a separate backend)"))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) fn commit_test_repo(endpoint: &str, token: Option<&str>) -> HfRepo {
    let config = Config::from_values(|key| match key {
        "HF_ENDPOINT" => Some(endpoint.into()),
        "HF_TOKEN" => token.map(str::to_owned),
        "HF_TOKEN_PATH" => Some("/nonexistent/ratarmount-hf-commit-token".into()),
        _ => None,
    })
    .unwrap();
    HfRepo {
        location: parse_hf_url("hf://datasets/org/data/a.tar").unwrap(),
        commit: "a".repeat(40),
        config,
        files: Arc::default(),
    }
}

/// A revision resolved exactly once. Clones and all file/sidecar requests retain this SHA.
#[derive(Clone)]
pub struct HfRepo {
    pub location: HfLocation,
    pub commit: String,
    config: Config,
    files: FileCache,
}

impl HfRepo {
    pub fn resolve(input: &str) -> Result<Self> {
        Self::with_config(parse_hf_url(input)?, Config::from_env()?)
    }

    fn with_config(location: HfLocation, config: Config) -> Result<Self> {
        config.online()?;
        let mut repo = Self {
            location,
            config,
            commit: String::new(),
            files: Arc::default(),
        };
        let url = repo.api_url(&format!("revision/{}", encode(&repo.location.revision)));
        let response = repo.get_api(&url)?;
        let value = read_json(response.into_reader())?;
        let sha = value["sha"]
            .as_str()
            .ok_or_else(|| error("Hub revision response has no sha"))?;
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(error("Hub returned an invalid commit SHA"));
        }
        repo.commit = sha.to_ascii_lowercase();
        log::info!(
            "hf: {}/{}@{} resolved commit {}",
            repo.location.kind,
            repo.location.repo,
            repo.location.revision,
            repo.commit
        );
        Ok(repo)
    }

    pub(crate) fn api_url(&self, suffix: &str) -> String {
        format!(
            "{}api/{}/{}/{suffix}",
            self.config.endpoint,
            self.location.kind,
            encode_path(&self.location.repo)
        )
    }

    /// Only Hub-origin requests may use the token selected by the read backend.
    pub(crate) fn write_request(&self, method: &str, url: &str) -> Result<http_pool::HttpRequest> {
        self.config.online()?;
        let token = self.config.token.as_ref().ok_or_else(|| {
            error(format!(
                "publishing requires a Hub token with write scope; {TOKEN_HELP}"
            ))
        })?;
        let parsed = Url::parse(url).map_err(|_| error("invalid Hub write URL"))?;
        if parsed.origin() != self.config.endpoint.origin()
            || !parsed.path().starts_with(self.config.endpoint.path())
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(error("Hub write URL escapes HF_ENDPOINT"));
        }
        warn_plain_http(&self.config, &HTTP_TOKEN_WARNING);
        Ok(http_pool::request(method, url)
            .set("User-Agent", USER_AGENT)
            .set(
                "Authorization",
                &format!("Bearer {}", token.expose_secret()),
            )
            .timeout(Duration::from_secs(300)))
    }

    pub(crate) fn lfs_batch_url(&self) -> String {
        let prefix = if self.location.kind == "models" {
            String::new()
        } else {
            format!("{}/", self.location.kind)
        };
        format!(
            "{}{prefix}{}.git/info/lfs/objects/batch",
            self.config.endpoint,
            encode_path(&self.location.repo)
        )
    }

    /// Require the normal Hub token before preparing a publication (no network request).
    pub fn require_publish_token(&self) -> Result<()> {
        self.write_request("POST", &self.api_url("commit/main"))
            .map(|_| ())
    }

    /// Choose the archive branch when it is a branch, otherwise `main`.
    pub fn publish_branch(&self, explicit: Option<&str>) -> Result<String> {
        if let Some(branch) = explicit {
            if !valid_path(branch) {
                return Err(error("invalid --publish-revision branch"));
            }
            return Ok(branch.into());
        }
        if self.location.revision == "main" {
            return Ok("main".into());
        }
        let refs = read_json(self.get_api(&self.api_url("refs"))?.into_reader())?;
        let branch = refs["branches"].as_array().is_some_and(|branches| {
            branches
                .iter()
                .any(|b| b["name"].as_str() == Some(&self.location.revision))
        });
        Ok(if branch {
            self.location.revision.clone()
        } else {
            "main".into()
        })
    }

    /// Resolve another revision using the same endpoint and credentials.
    pub fn at_revision(&self, revision: &str) -> Result<Self> {
        if !valid_path(revision) {
            return Err(error("invalid Hub revision"));
        }
        let mut location = self.location.clone();
        location.revision = revision.into();
        Self::with_config(location, self.config.clone())
    }

    pub fn resolve_url(&self, path: &str) -> String {
        let prefix = if self.location.kind == "models" {
            String::new()
        } else {
            format!("{}/", self.location.kind)
        };
        format!(
            "{}{prefix}{}/resolve/{}/{}",
            self.config.endpoint,
            encode_path(&self.location.repo),
            self.commit,
            encode_path(path)
        )
    }

    fn get_api(&self, url: &str) -> Result<ureq::Response> {
        self.get_with_retries(url, MAX_API_RETRIES)
    }

    fn get(&self, url: &str) -> Result<ureq::Response> {
        self.get_with_retries(url, 0)
    }

    fn get_with_retries(&self, url: &str, retries: usize) -> Result<ureq::Response> {
        self.config.online()?;
        let parsed = Url::parse(url).map_err(|_| error("invalid Hub API URL"))?;
        if parsed.origin() != self.config.endpoint.origin()
            || !parsed.path().starts_with(self.config.endpoint.path())
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(error("Hub pagination/sidecar URL escapes HF_ENDPOINT"));
        }
        warn_plain_http(&self.config, &HTTP_TOKEN_WARNING);
        for attempt in 0..=retries {
            let mut req = http_pool::get(url)
                .set("User-Agent", USER_AGENT)
                .timeout(Duration::from_secs(60));
            if let Some(token) = &self.config.token {
                req = req.set(
                    "Authorization",
                    &format!("Bearer {}", token.expose_secret()),
                );
            }
            match req.call() {
                Err(ureq::Error::Status(429, response)) if attempt < retries => {
                    let wait = retry_after(response.header("Retry-After"), SystemTime::now());
                    drop(response);
                    std::thread::sleep(wait);
                }
                result => return result.map_err(|e| map_http_error(&self.location.repo, e)),
            }
        }
        unreachable!("last attempt returns its result")
    }

    /// Authenticated sidecar download; the pooled transport strips auth on redirects.
    pub fn fetch_bytes(&self, url: &str, cap: u64) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.get(url)?
            .into_reader()
            .take(cap.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap {
            return Err(error("Hub response exceeds size limit"));
        }
        Ok(bytes)
    }

    /// Stream large index sidecars to disk without a second in-memory copy.
    pub fn fetch_to_temp(&self, url: &str, cap: u64) -> Result<tempfile::NamedTempFile> {
        let mut tmp = tempfile::NamedTempFile::new()?;
        let mut body = self.get(url)?.into_reader().take(cap.saturating_add(1));
        if io::copy(&mut body, &mut tmp)? > cap {
            return Err(error("Hub response exceeds size limit"));
        }
        tmp.flush()?;
        Ok(tmp)
    }

    /// Reuse AI-0b's source, including its expiring redirect target, across opens.
    pub fn open_file(&self, path: &str) -> Result<HttpRangeFile> {
        self.config.online()?;
        if !valid_path(path) {
            return Err(error("expected a file path in Hub repository"));
        }
        let slot = self
            .files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(path.into())
            .or_default()
            .clone();
        // Only initialization of this file is serialized, not other shards or reads.
        let mut file = slot.lock().unwrap_or_else(|e| e.into_inner());
        if file.is_none() {
            *file = Some(self.probe_file(path)?);
        }
        match file.as_ref().unwrap() {
            CachedFile::Ready { source, size, buffered } => {
                Ok(HttpRangeFile::from_source(source.clone(), *size, buffered.clone()))
            }
            CachedFile::TooLarge => Err(error(format!(
                "Hub file {}/{} ignores Range and exceeds the 64 MiB buffer limit; use an endpoint with Range support or download it locally",
                self.location.repo, path
            ))),
        }
    }

    fn probe_file(&self, path: &str) -> Result<CachedFile> {
        let source = Arc::new(
            http_pool::HttpRangeSource::new(
                HttpLocation {
                    url: self.resolve_url(path),
                    auth: None,
                    cookie: None,
                },
                HttpAuthOptions {
                    bearer_token: self.config.token.clone(),
                },
            )
            .with_hub_repo(self.location.repo.clone()),
        );
        // Some Hub/CDN HEAD responses omit Accept-Ranges.
        let response = match source.request("GET", Some((0, 0))) {
            Err(ureq::Error::Status(416, response))
                if response.header("Content-Range") == Some("bytes */0") =>
            {
                return Ok(CachedFile::Ready {
                    source,
                    size: 0,
                    buffered: Some(Arc::from([])),
                });
            }
            result => result,
        }
        .map_err(|e| map_http_error(&self.location.repo, e))?;
        for header in ["X-Repo-Commit", "X-Linked-Etag", "X-Linked-Size", "ETag"] {
            if let Some(value) = response.header(header) {
                log::debug!("hf: {}/{} {header}={value}", self.location.repo, path);
            }
        }
        if response
            .header("X-Repo-Commit")
            .is_some_and(|sha| !sha.eq_ignore_ascii_case(&self.commit))
        {
            return Err(error("Hub file response does not match the pinned commit"));
        }
        if response.status() == 206 {
            let size = http_pool::validate_content_range(&response, 0, 0, None)?
                .ok_or_else(|| error("Hub range response has no total length"))?;
            let mut bytes = Vec::new();
            response.into_reader().take(2).read_to_end(&mut bytes)?;
            if bytes.len() != 1 {
                return Err(error("invalid Hub range probe body"));
            }
            Ok(CachedFile::Ready {
                source,
                size,
                buffered: None,
            })
        } else if response.status() == 200 {
            if response
                .header("Content-Length")
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|size| size > MAX_BUFFER_BYTES)
            {
                return Ok(CachedFile::TooLarge);
            }
            match bounded_body(response.into_reader(), MAX_BUFFER_BYTES)? {
                Some(bytes) => Ok(CachedFile::Ready {
                    source,
                    size: bytes.len() as u64,
                    buffered: Some(bytes.into()),
                }),
                None => Ok(CachedFile::TooLarge),
            }
        } else {
            Err(error("unexpected Hub range response"))
        }
    }

    pub fn materialize(&self) -> Result<crate::RemoteLocal> {
        crate::keep_from_reader(
            &self.resolve_url(&self.location.path),
            self.open_file(&self.location.path)?,
        )
    }

    fn cache_identity(&self) -> Value {
        json!({"endpoint": self.config.endpoint.as_str(), "kind": self.location.kind,
            "repo": self.location.repo, "commit": self.commit, "path": self.location.path})
    }

    fn tree_cache_path(&self) -> Option<PathBuf> {
        let key = hex::encode(Sha256::digest(self.cache_identity().to_string().as_bytes()));
        self.config
            .cache
            .as_ref()
            .map(|p| p.join(format!("{key}.json")))
    }

    /// `None` means the tree API returned EntryNotFound; try opening it as a file.
    fn tree(&self) -> Result<Option<Value>> {
        self.config.online()?;
        let identity = self.cache_identity();
        if let Some(path) = self.tree_cache_path() {
            if let Ok(file) = std::fs::File::open(path) {
                if let Ok(cached) = read_json(file) {
                    if cached["identity"] == identity && entries(&cached["entries"]).is_ok() {
                        return Ok(Some(cached["entries"].clone()));
                    }
                }
            }
        }
        let suffix = if self.location.path.is_empty() {
            String::new()
        } else {
            format!("/{}", encode_path(&self.location.path))
        };
        let mut url = format!(
            "{}?recursive=true",
            self.api_url(&format!("tree/{}{suffix}", self.commit))
        );
        let mut visited = BTreeSet::new();
        let mut all = Vec::new();
        let mut json_bytes = 0u64;
        for page in 0..MAX_PAGES {
            if !visited.insert(url.clone()) {
                return Err(error("Hub tree pagination cycle"));
            }
            let response = match self.get_api(&url) {
                Err(RemoteError::HfStatus {
                    status: 404, code, ..
                }) if page == 0
                    && !self.location.path.is_empty()
                    && code.as_deref() == Some("EntryNotFound") =>
                {
                    return Ok(None)
                }
                r => r?,
            };
            let next = next_link(response.all("Link").join(",").as_str(), &url)?;
            let body = read_json(response.into_reader())?;
            json_bytes += body.to_string().len() as u64;
            if json_bytes > MAX_JSON_BYTES {
                return Err(error("Hub tree JSON exceeds size limit"));
            }
            let items = body
                .as_array()
                .ok_or_else(|| error("Hub tree response is not an array"))?;
            all.extend(items.iter().cloned());
            if all.len() > MAX_ENTRIES {
                return Err(error("Hub tree exceeds one million entries"));
            }
            if let Some(next) = next {
                let parsed = Url::parse(&next).map_err(|_| error("invalid Hub pagination URL"))?;
                let current = Url::parse(&url).map_err(|_| error("invalid Hub tree URL"))?;
                if parsed.origin() != current.origin() {
                    return Err(error("Hub pagination URL escapes HF_ENDPOINT"));
                }
                if decode(parsed.path())? != decode(current.path())? {
                    return Err(error("Hub pagination changed the pinned tree path"));
                }
                url = next;
                continue;
            }
            let all = Value::Array(all);
            entries(&all)?;
            if let Some(path) = self.tree_cache_path() {
                let save = || -> io::Result<()> {
                    let parent = path.parent().unwrap();
                    std::fs::create_dir_all(parent)?;
                    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
                    serde_json::to_writer(
                        &mut tmp,
                        &json!({"identity": identity, "entries": all}),
                    )?;
                    tmp.flush()?;
                    tmp.persist(&path).map_err(|e| e.error)?;
                    Ok(())
                };
                if let Err(e) = save() {
                    log::warn!("hf listing cache unavailable: {e}");
                }
            }
            return Ok(Some(all));
        }
        Err(error("Hub tree pagination exceeds 10000 pages"))
    }

    pub fn folder(&self) -> Result<Option<Arc<dyn MountSource>>> {
        let Some(tree) = self.tree()? else {
            return Ok(None);
        };
        let listing = HfListing::new(self.clone(), &tree)?;
        let source = Arc::new(RemoteFolderMountSource::new(
            self.location.path.clone(),
            listing,
        ));
        Ok(Some(Arc::new(HfMountSource {
            inner: source,
            commit: self.commit.clone(),
            folder: true,
        })))
    }
}

fn read_json(reader: impl Read) -> Result<Value> {
    let mut bytes = Vec::new();
    reader.take(MAX_JSON_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(error("Hub JSON exceeds size limit"));
    }
    serde_json::from_slice(&bytes).map_err(|e| error(format!("invalid Hub JSON: {e}")))
}

fn next_link(header: &str, base: &str) -> Result<Option<String>> {
    let (mut angle, mut quoted, mut escaped) = (false, false, false);
    let parts: Vec<_> = header
        .split(|c| {
            if escaped {
                escaped = false;
                return false;
            }
            match c {
                '\\' if quoted => escaped = true,
                '<' if !quoted => angle = true,
                '>' if !quoted => angle = false,
                '"' if !angle => quoted = !quoted,
                ',' if !angle && !quoted => return true,
                _ => {}
            }
            false
        })
        .collect();
    if angle || quoted || escaped {
        return Err(error("malformed Hub pagination Link header"));
    }
    for part in parts {
        if part.trim().is_empty() {
            continue;
        }
        let Some((target, params)) = part
            .trim()
            .strip_prefix('<')
            .and_then(|p| p.split_once('>'))
        else {
            return Err(error("malformed Hub pagination Link header"));
        };
        if params.split(';').any(|p| {
            p.trim().split_once('=').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("rel")
                    && v.trim()
                        .trim_matches('"')
                        .split_whitespace()
                        .any(|r| r.eq_ignore_ascii_case("next"))
            })
        }) {
            return Url::parse(base)
                .and_then(|u| u.join(target))
                .map(|u| Some(u.into()))
                .map_err(|_| error("invalid Hub pagination URL"));
        }
    }
    Ok(None)
}

fn entries(tree: &Value) -> Result<BTreeMap<String, RemoteDirent>> {
    let mut entries = BTreeMap::new();
    for value in tree
        .as_array()
        .ok_or_else(|| error("invalid cached Hub tree"))?
    {
        let path = value["path"]
            .as_str()
            .filter(|p| valid_path(p))
            .ok_or_else(|| error("invalid Hub tree path"))?;
        let is_dir = match value["type"].as_str() {
            Some("directory") => true,
            Some("file") => false,
            _ => return Err(error("invalid Hub tree entry type")),
        };
        let size = if is_dir {
            0
        } else {
            value["size"]
                .as_u64()
                .ok_or_else(|| error("invalid Hub file size"))?
        };
        if entries
            .insert(
                path.to_string(),
                RemoteDirent {
                    name: path.rsplit('/').next().unwrap().into(),
                    remote_path: path.into(),
                    is_dir,
                    size,
                    mtime: 0.0,
                },
            )
            .is_some()
        {
            return Err(error("duplicate Hub tree path"));
        }
    }
    Ok(entries)
}

struct HfListing {
    repo: HfRepo,
    entries: BTreeMap<String, RemoteDirent>,
    children: BTreeMap<String, Vec<RemoteDirent>>,
}

impl HfListing {
    fn new(repo: HfRepo, tree: &Value) -> Result<Self> {
        let mut entries = entries(tree)?;
        if !repo.location.path.is_empty() {
            let prefix = format!("{}/", repo.location.path);
            if entries.keys().any(|path| !path.starts_with(&prefix)) {
                return Err(error("Hub tree entry is outside the requested directory"));
            }
        }
        let paths: Vec<_> = entries.keys().cloned().collect();
        for path in paths {
            let mut parent = path.as_str();
            while let Some((p, _)) = parent.rsplit_once('/') {
                entries.entry(p.into()).or_insert_with(|| RemoteDirent {
                    name: p.rsplit('/').next().unwrap().into(),
                    remote_path: p.into(),
                    is_dir: true,
                    size: 0,
                    mtime: 0.0,
                });
                parent = p;
            }
        }
        let mut children: BTreeMap<String, Vec<RemoteDirent>> = BTreeMap::new();
        for entry in entries.values() {
            children
                .entry(
                    entry
                        .remote_path
                        .rsplit_once('/')
                        .map_or("", |(p, _)| p)
                        .into(),
                )
                .or_default()
                .push(entry.clone());
        }
        Ok(Self {
            repo,
            entries,
            children,
        })
    }
}

impl RemoteListing for HfListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        Ok(self
            .children
            .get(remote_path.trim_matches('/'))
            .cloned()
            .unwrap_or_default())
    }
    fn stat(&self, remote_path: &str) -> Result<Option<RemoteDirent>> {
        Ok(self.entries.get(remote_path.trim_matches('/')).cloned())
    }
    fn open_range(&self, remote_path: &str, _size: u64) -> Result<Box<dyn ArchiveRead>> {
        Ok(Box::new(
            self.repo.open_file(remote_path.trim_matches('/'))?,
        ))
    }
}

/// Preserve source behavior while exposing the pinned commit on its root and entries.
pub struct HfMountSource {
    inner: Arc<dyn MountSource>,
    commit: String,
    folder: bool,
}
impl HfMountSource {
    pub fn new(inner: Arc<dyn MountSource>, commit: String) -> Self {
        Self {
            inner,
            commit,
            folder: false,
        }
    }
}
impl MountSource for HfMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.inner.list(path)
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.inner.list_dirents(path)
    }
    fn lookup(&self, path: &str, version: i32) -> Option<FileInfo> {
        self.inner.lookup(path, version)
    }
    fn open(&self, fi: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        if self.folder {
            // RemoteDirent puts its path first. Compositing layers append routing
            // tags; RemoteFolderMountSource would otherwise use the last tag as a path.
            let mut original = fi.clone();
            if let Some(path) = original
                .userdata
                .iter()
                .position(|u| matches!(u, UserData::Other(_)))
            {
                original.userdata.truncate(path + 1);
            }
            return self.inner.open(&original, buffering);
        }
        self.inner.open(fi, buffering)
    }
    fn member_seek_is_cheap(&self, fi: &FileInfo) -> bool {
        self.inner.member_seek_is_cheap(fi)
    }
    fn search_cheap(&self, pattern: &str) -> Option<Vec<ratarmount_core::CheapSearchHit>> {
        self.inner.search_cheap(pattern)
    }
    fn versions(&self, path: &str) -> u32 {
        self.inner.versions(path)
    }
    fn statfs(&self) -> ratarmount_core::StatFs {
        self.inner.statfs()
    }
    fn is_immutable(&self) -> bool {
        true
    }
    fn list_xattr(&self, fi: &FileInfo) -> Vec<String> {
        let mut names = self.inner.list_xattr(fi);
        if !names.iter().any(|name| name == "user.hf.commit") {
            names.push("user.hf.commit".into());
        }
        names
    }
    fn get_xattr(&self, fi: &FileInfo, key: &str) -> Option<Vec<u8>> {
        // AutoMount synthesizes its root FileInfo instead of forwarding lookup.
        if key == "user.hf.commit" {
            Some(self.commit.as_bytes().to_vec())
        } else {
            self.inner.get_xattr(fi, key)
        }
    }
}

pub fn open_hf_range(input: &str) -> Result<HttpRangeFile> {
    let repo = HfRepo::resolve(input)?;
    repo.open_file(&repo.location.path)
}

#[cfg(test)]
mod tests;
