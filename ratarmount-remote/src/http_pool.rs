//! Shared blocking HTTP transport and bounded per-file sequential readahead.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ratarmount_index::{ContentToken, RangeCache};
use secrecy::ExposeSecret;

use crate::{apply_http_auth, HttpAuthOptions, HttpLocation, HTTP_RANGE_CHUNK, USER_AGENT};

pub(crate) fn redacted_url(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return "[invalid URL]".into();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

pub(crate) fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .redirects(0)
            .max_idle_connections(128)
            .max_idle_connections_per_host(64)
            // Never propagate origin Authorization or Cookie headers through a redirect.
            .redirect_auth_headers(ureq::RedirectAuthHeaders::Never)
            .build()
    })
}

// A small request builder keeps one Agent/pool while following redirects explicitly.
// Headers and per-request timeouts survive the hop; credentials never do.
pub(crate) struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    timeout: Option<Duration>,
    linked_sha256: Option<Arc<Mutex<Option<String>>>>,
}

pub(crate) fn request(method: &str, url: &str) -> HttpRequest {
    HttpRequest {
        method: method.into(),
        url: url.into(),
        headers: vec![],
        timeout: None,
        linked_sha256: None,
    }
}

pub(crate) fn get(url: &str) -> HttpRequest {
    request("GET", url)
}
pub(crate) fn head(url: &str) -> HttpRequest {
    request("HEAD", url)
}
pub(crate) fn post(url: &str) -> HttpRequest {
    request("POST", url)
}

// Preserve ureq's status/response error type for existing protocol callers.
#[allow(clippy::result_large_err)]
impl HttpRequest {
    pub(crate) fn set(mut self, name: &str, value: &str) -> Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.into(), value.into()));
        self
    }

    pub(crate) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub(crate) fn call(self) -> Result<ureq::Response, ureq::Error> {
        self.send(None)
    }

    pub(crate) fn send_bytes(self, body: &[u8]) -> Result<ureq::Response, ureq::Error> {
        self.send(Some(body))
    }

    pub(crate) fn send_string(mut self, body: &str) -> Result<ureq::Response, ureq::Error> {
        if !self
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("Content-Type"))
        {
            self = self.set("Content-Type", "text/plain; charset=utf-8");
        }
        self.send_bytes(body.as_bytes())
    }

    fn send(mut self, mut body: Option<&[u8]>) -> Result<ureq::Response, ureq::Error> {
        let deadline = self
            .timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));
        for hop in 0..=5 {
            let mut req = agent().request(&self.method, &self.url);
            for (name, value) in &self.headers {
                req = req.set(name, value);
            }
            if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(
                        io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out").into(),
                    );
                }
                req = req.timeout(remaining);
            }
            let resp = match body {
                Some(bytes) => req.send_bytes(bytes),
                None => req.call(),
            }
            .map_err(|e| match e {
                // Other protocol backends also display these errors directly. Drop
                // the transport's URL-bearing source chain before it can be logged.
                ureq::Error::Transport(err) => ureq::Error::from(io::Error::other(format!(
                    "HTTP {:?} for {}",
                    err.kind(),
                    redacted_url(&self.url)
                ))),
                status => status,
            })?;
            if let (Some(capture), Some(value)) =
                (&self.linked_sha256, resp.header("X-Linked-Etag"))
            {
                let value = value
                    .trim_matches('"')
                    .strip_prefix("sha256:")
                    .unwrap_or(value.trim_matches('"'));
                if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    capture
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get_or_insert_with(|| value.to_ascii_lowercase());
                }
            }
            let status = resp.status();
            let redirect = matches!(status, 301..=303)
                || (matches!(status, 307 | 308)
                    && ["GET", "HEAD", "OPTIONS", "TRACE"].contains(&self.method.as_str()));
            let Some(location) = resp.header("Location").filter(|_| redirect) else {
                return Ok(resp);
            };
            if hop == 5 {
                return Err(io::Error::other("HTTP redirect limit exceeded").into());
            }
            let mut target = url::Url::parse(&self.url)?.join(location)?;
            if !["http", "https"].contains(&target.scheme()) {
                return Err(io::Error::other("HTTP redirect to unsupported scheme").into());
            }
            // Do not allow redirect userinfo to implicitly add Authorization either.
            let _ = target.set_username("");
            let _ = target.set_password(None);
            self.url = target.to_string();
            self.headers.retain(|(n, _)| {
                !["authorization", "cookie", "host", "content-length"]
                    .iter()
                    .any(|h| n.eq_ignore_ascii_case(h))
            });
            if matches!(status, 301..=303) && !["GET", "HEAD"].contains(&self.method.as_str()) {
                self.method = "GET".into();
                body = None;
            }
            // Small redirect bodies can be consumed for keep-alive; never slurp an
            // unbounded response just to follow Location.
            if resp
                .header("Content-Length")
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|n| n <= 8192)
            {
                io::copy(&mut resp.into_reader(), &mut io::sink())?;
            }
        }
        unreachable!("bounded redirect loop returns on its last iteration")
    }
}

pub(crate) fn parallelism() -> usize {
    parse_parallelism(std::env::var("RATARMOUNT_HTTP_PARALLEL").ok().as_deref())
}

fn parse_parallelism(value: Option<&str>) -> usize {
    value
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 64)
}

#[derive(Clone)]
struct Target {
    url: String,
    generation: u64,
    redirected: bool,
}

#[derive(Default)]
struct CacheIdentity {
    token: Option<ContentToken>,
    etag: Option<String>,
    disabled: bool,
}

/// Shared HTTP transport with verified persistent range caching.
pub struct HttpRangeSource {
    pub(crate) location: HttpLocation,
    pub(crate) options: HttpAuthOptions,
    target: Mutex<Option<Target>>,
    content_token: Mutex<CacheIdentity>,
    cache: Option<RangeCache>,
    hub_repo: Option<String>,
    hub_cache: Option<Arc<crate::hf_cache::HubCacheFile>>,
    linked_sha256: Arc<Mutex<Option<String>>>,
}

#[allow(clippy::result_large_err)]
impl HttpRangeSource {
    pub fn new(location: HttpLocation, options: HttpAuthOptions) -> Self {
        Self {
            location,
            options,
            target: Mutex::new(None),
            content_token: Mutex::new(CacheIdentity::default()),
            cache: RangeCache::from_env(),
            hub_repo: None,
            hub_cache: None,
            linked_sha256: Arc::default(),
        }
    }

    pub(crate) fn with_hub_repo(mut self, repo: String) -> Self {
        self.hub_repo = Some(repo);
        self
    }

    pub(crate) fn with_hub_cache(mut self, cache: Arc<crate::hf_cache::HubCacheFile>) -> Self {
        self.hub_cache = Some(cache);
        self
    }

    pub fn url(&self) -> &str {
        &self.location.url
    }

    /// Supply an identity already verified by the backend (for example a pinned
    /// Hub commit and path, or X-Linked-Etag SHA-256). The caller must bind this
    /// identity to the URL's bytes; branch names and weak ETags are not identities.
    pub fn with_content_token(self, token: ContentToken) -> Self {
        self.set_content_token(token);
        self
    }

    pub(crate) fn set_content_token(&self, token: ContentToken) {
        let mut identity = self.content_token.lock().unwrap_or_else(|e| e.into_inner());
        if let ContentToken::StrongEtag { etag, .. } = &token {
            if identity.etag.as_ref().is_some_and(|first| first != etag) {
                identity.disabled = true;
            } else {
                identity.etag = Some(etag.clone());
            }
        }
        identity.token = Some(token);
    }

    fn token(&self, size: u64) -> Option<ContentToken> {
        let identity = self.content_token.lock().unwrap_or_else(|e| e.into_inner());
        if identity.disabled {
            return None;
        }
        identity.token.clone().filter(|t| t.size() == size)
    }

    pub(crate) fn observe_identity(&self, resp: &ureq::Response, size: u64) {
        if !self.cache.as_ref().is_some_and(|cache| cache.is_enabled()) {
            return;
        }
        let Some(etag) = resp
            .header("ETag")
            .filter(|v| ContentToken::is_strong_etag(v))
        else {
            return;
        };
        let mut identity = self.content_token.lock().unwrap_or_else(|e| e.into_inner());
        if identity.disabled {
            return;
        }
        if identity.etag.as_ref().is_some_and(|first| first != etag) {
            // Cache validators are advisory. Edge-specific ETags must never fail I/O.
            identity.disabled = true;
            return;
        }
        identity.etag = Some(etag.into());
        if identity.token.is_none() {
            identity.token = Some(ContentToken::StrongEtag {
                resource: self.url().into(),
                etag: etag.into(),
                size,
            });
        }
    }

    /// Use an explicit disk cache (useful to embedders and isolated mounts).
    pub fn with_range_cache(mut self, cache: RangeCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub(crate) fn initialize_hub_cache(&self) {
        if let Some(hub) = &self.hub_cache {
            hub.initialize();
        }
    }

    pub(crate) fn store_buffered(&self, bytes: Arc<[u8]>) {
        if let Some(hub) = &self.hub_cache {
            hub.buffered(bytes);
        }
    }

    pub(crate) fn backing_file(&self, size: u64) -> Option<std::fs::File> {
        if let Some(hub) = &self.hub_cache {
            if let Some(local) = hub.local().filter(|b| b.size == size) {
                return local.backing_file();
            }
            let cache = self.cache.as_ref()?;
            hub.complete(cache, &self.token(size)?);
            return hub.local().filter(|b| b.size == size)?.backing_file();
        }
        self.cache
            .as_ref()?
            .complete_backing_file(&self.token(size)?)
    }

    #[cfg(test)]
    pub(crate) fn wait_for_publication(&self) {
        if let Some(hub) = &self.hub_cache {
            hub.wait();
        }
    }

    /// Contiguous completed cache file. Hub publication is asynchronous; this
    /// returns None until its worker finishes and never waits for that worker.
    pub fn complete_file(&self, size: u64) -> Option<std::path::PathBuf> {
        if let Some(local) = self
            .hub_cache
            .as_ref()
            .and_then(|cache| cache.local())
            .filter(|b| b.size == size)
        {
            return Some(local.path.clone());
        }
        let cache = self.cache.as_ref()?;
        let token = self.token(size)?;
        if let Some(hub) = &self.hub_cache {
            hub.complete(cache, &token)
        } else {
            cache.complete_file(&token)
        }
    }

    fn read_cached_into(&self, start: u64, size: u64, buf: &mut [u8]) -> Option<usize> {
        if let Some(local) = self
            .hub_cache
            .as_ref()
            .and_then(|cache| cache.local())
            .filter(|b| b.size == size)
        {
            return local.read_at(start, buf).ok();
        }
        let cache = self.cache.as_ref()?;
        let token = self.token(size)?;
        let n = cache.read_into(&token, start, buf)?;
        self.observe_chunk(cache, &token, start / cache.chunk_size());
        Some(n)
    }

    fn observe_chunk(&self, cache: &RangeCache, token: &ContentToken, chunk: u64) {
        if let Some(hub) = &self.hub_cache {
            hub.observed(cache, token, chunk);
        }
    }

    fn store_chunk(&self, cache: &RangeCache, token: &ContentToken, chunk: u64, bytes: &[u8]) {
        if let Err(err) = cache.put(token, chunk, bytes) {
            log::debug!("range-v1 store skipped: {err}");
        } else {
            self.observe_chunk(cache, token, chunk);
        }
    }

    fn cache_available(&self, start: u64, end: u64, size: u64) -> bool {
        if self
            .hub_cache
            .as_ref()
            .and_then(|hub| hub.local())
            .is_some_and(|b| b.size == size)
        {
            return true;
        }
        let (Some(cache), Some(token)) = (&self.cache, self.token(size)) else {
            return false;
        };
        (start / cache.chunk_size()..=end / cache.chunk_size())
            .all(|chunk| cache.contains(&token, chunk))
    }

    #[cfg(test)]
    pub(crate) fn without_range_cache(mut self) -> Self {
        self.cache = None;
        self
    }

    pub(crate) fn linked_sha256(&self) -> Option<String> {
        self.linked_sha256
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn call(
        &self,
        url: &str,
        origin: bool,
        method: &str,
        range: Option<(u64, u64)>,
        timeout: Option<Duration>,
    ) -> Result<ureq::Response, ureq::Error> {
        let mut req = request(method, url)
            .set("User-Agent", USER_AGENT)
            .set("Accept-Encoding", "identity");
        if self.hub_repo.is_some() {
            req.linked_sha256 = Some(Arc::clone(&self.linked_sha256));
        }
        if let Some((start, end)) = range {
            req = req.set("Range", &format!("bytes={start}-{end}"));
        }
        if origin {
            req = apply_http_auth(
                req,
                self.location.auth.as_ref(),
                self.location.cookie.as_deref(),
            );
            if let Some(token) = &self.options.bearer_token {
                req = req.set(
                    "Authorization",
                    &format!("Bearer {}", token.expose_secret()),
                );
            }
        }
        if let Some(timeout) = timeout {
            req = req.timeout(timeout);
        }
        req.call()
    }

    fn resolve(
        &self,
        target: &mut Option<Target>,
        method: &str,
        range: Option<(u64, u64)>,
        timeout: Option<Duration>,
    ) -> Result<ureq::Response, ureq::Error> {
        let result = self.call(self.url(), true, method, range, timeout);
        // A HEAD rejected by the final host still resolved Location for the GET probe.
        let response = match &result {
            Ok(resp) | Err(ureq::Error::Status(_, resp)) => Some(resp),
            Err(_) => None,
        };
        if let Some(resp) = response {
            *target = Some(Target {
                url: resp.get_url().to_string(),
                generation: target.as_ref().map_or(0, |t| t.generation + 1),
                redirected: resp.get_url() != self.url(),
            });
        }
        result
    }

    pub(crate) fn request(
        &self,
        method: &str,
        range: Option<(u64, u64)>,
    ) -> Result<ureq::Response, ureq::Error> {
        let resp = self.request_with_timeout(method, range, None)?;
        if method == "HEAD" && resp.status() == 200 {
            if let Some(size) = resp.header("Content-Length").and_then(|v| v.parse().ok()) {
                self.observe_identity(&resp, size);
            }
        }
        Ok(resp)
    }

    fn request_with_timeout(
        &self,
        method: &str,
        range: Option<(u64, u64)>,
        timeout: Option<Duration>,
    ) -> Result<ureq::Response, ureq::Error> {
        let target = {
            let mut guard = self.target.lock().unwrap_or_else(|e| e.into_inner());
            match &*guard {
                Some(target) => target.clone(),
                None => return self.resolve(&mut guard, method, range, timeout),
            }
        };
        let result = self.call(&target.url, !target.redirected, method, range, timeout);
        if target.redirected
            && matches!(&result, Err(ureq::Error::Status(401 | 403 | 404 | 410, _)))
        {
            // Single-flight refresh: parallel requests that failed against the same old
            // signed URL share one re-resolution, even if the new URL is identical.
            drop(result);
            let mut guard = self.target.lock().unwrap_or_else(|e| e.into_inner());
            if guard
                .as_ref()
                .is_some_and(|t| t.generation == target.generation)
            {
                return self.resolve(&mut guard, method, range, timeout);
            }
            let refreshed = guard.as_ref().unwrap().clone();
            drop(guard);
            return self.call(
                &refreshed.url,
                !refreshed.redirected,
                method,
                range,
                timeout,
            );
        }
        result
    }

    fn range_reader(
        &self,
        start: u64,
        end: u64,
        size: u64,
        cancelled: Option<&AtomicBool>,
    ) -> io::Result<(Box<dyn Read + Send + Sync>, u16, Option<ContentToken>)> {
        check_cancelled(cancelled)?;
        let timeout = cancelled.map(|_| Duration::from_secs(60));
        let resp = self
            .request_with_timeout("GET", Some((start, end)), timeout)
            .map_err(|e| {
                io::Error::other(match &self.hub_repo {
                    Some(repo) => crate::hf::map_http_error(repo, e),
                    None => crate::map_ureq_http_error(e, self.url()),
                })
            })?;
        let status = resp.status();
        if status == 206 {
            validate_content_range(&resp, start, end, Some(size))?;
        } else if status != 200 {
            return Err(io::Error::other(format!("HTTP {status} for range request")));
        }
        let mut cache_token = None;
        if status == 206 {
            self.observe_identity(&resp, size);
            cache_token = self.token(size);
            if let Some(ContentToken::StrongEtag { etag, .. }) = &cache_token {
                if resp.header("ETag") != Some(etag.as_str()) {
                    // Weak or absent GET validators cannot verify the strong
                    // identity learned from HEAD. Keep the read, bypass cache.
                    self.content_token
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .disabled = true;
                    cache_token = None;
                }
            }
        }
        let mut reader = resp.into_reader();
        if status == 200 {
            skip_prefix(&mut reader, start, cancelled)?;
        }
        Ok((reader, status, cache_token))
    }

    fn window_len(&self, start: u64, size: u64) -> u64 {
        let len = HTTP_RANGE_CHUNK.min(size - start);
        if let Some(cache) = self.cache.as_ref().filter(|c| c.is_enabled()) {
            if self.token(size).is_some() {
                return len.min(cache.chunk_size() - start % cache.chunk_size());
            }
        }
        len
    }

    // Cache hits borrow the caller's storage. Verified misses fetch a reusable
    // aligned chunk; sources without verified identity retain the direct path.
    pub fn read_into(&self, start: u64, size: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.read_into_with_pattern(start, size, buf, false)
    }

    pub(crate) fn read_into_with_pattern(
        &self,
        start: u64,
        size: u64,
        buf: &mut [u8],
        sequential: bool,
    ) -> io::Result<usize> {
        let len = (buf.len() as u64).min(self.window_len(start, size)) as usize;
        if let Some(n) = self.read_cached_into(start, size, &mut buf[..len]) {
            return Ok(n);
        }
        if (sequential
            || len >= 256 * 1024
            || self.hub_cache.is_some() && (start > 0 || len as u64 == size))
            && self.cache.as_ref().is_some_and(|c| c.is_enabled())
            && self.token(size).is_some()
        {
            let data = self.fetch(start, start + len as u64 - 1, size, None)?;
            buf[..data.len()].copy_from_slice(&data);
            return Ok(data.len());
        }
        let (mut reader, status, token) =
            self.range_reader(start, start + len as u64 - 1, size, None)?;
        reader.read_exact(&mut buf[..len])?;
        finish_range(&mut reader, status)?;
        if let (Some(cache), Some(token)) = (&self.cache, token) {
            if start.is_multiple_of(cache.chunk_size())
                && len as u64 == cache.chunk_size().min(size - start)
            {
                self.store_chunk(cache, &token, start / cache.chunk_size(), &buf[..len]);
            }
        }
        Ok(len)
    }

    fn fetch_network(
        &self,
        start: u64,
        end: u64,
        size: u64,
        cancelled: Option<&AtomicBool>,
    ) -> io::Result<Vec<u8>> {
        let (mut reader, status, token) = self.range_reader(start, end, size, cancelled)?;
        let len = usize::try_from(end - start + 1)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "HTTP range too large"))?;
        let data = read_chunk(&mut reader, len, cancelled)?;
        finish_range(&mut reader, status)?;
        check_cancelled(cancelled)?;
        if let (Some(cache), Some(token)) = (&self.cache, token) {
            if start.is_multiple_of(cache.chunk_size())
                && data.len() as u64 == cache.chunk_size().min(size - start)
            {
                self.store_chunk(cache, &token, start / cache.chunk_size(), &data);
            }
        }
        Ok(data)
    }

    pub(crate) fn fetch(
        &self,
        start: u64,
        end: u64,
        size: u64,
        cancelled: Option<&AtomicBool>,
    ) -> io::Result<Vec<u8>> {
        let (Some(cache), Some(token)) = (&self.cache, self.token(size)) else {
            return self.fetch_network(start, end, size, cancelled);
        };
        if !cache.is_enabled() {
            return self.fetch_network(start, end, size, cancelled);
        }
        let mut out = Vec::new();
        for chunk in start / cache.chunk_size()..=end / cache.chunk_size() {
            check_cancelled(cancelled)?;
            let first = chunk * cache.chunk_size();
            let last = first + cache.chunk_size().min(size - first) - 1;
            let mut bytes = match cache.get(&token, chunk) {
                Some(bytes) => {
                    self.observe_chunk(cache, &token, chunk);
                    bytes
                }
                None => {
                    let mut bytes = vec![0; (last - first + 1) as usize];
                    match self.read_cached_into(first, size, &mut bytes) {
                        Some(n) if n == bytes.len() => bytes,
                        _ => self.fetch_network(first, last, size, cancelled)?,
                    }
                }
            };
            let from = start.saturating_sub(first) as usize;
            let until = (end.min(last) - first + 1) as usize;
            if start / cache.chunk_size() == end / cache.chunk_size() {
                bytes.drain(..from);
                bytes.truncate(until - from);
                return Ok(bytes);
            }
            out.extend_from_slice(&bytes[from..until]);
        }
        Ok(out)
    }
}

fn skip_prefix(
    reader: &mut impl Read,
    mut remaining: u64,
    cancelled: Option<&AtomicBool>,
) -> io::Result<()> {
    let mut scratch = [0; 8192];
    while remaining > 0 {
        check_cancelled(cancelled)?;
        let len = remaining.min(scratch.len() as u64) as usize;
        match reader.read(&mut scratch[..len]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short ignored-Range body",
                ))
            }
            Ok(n) => remaining -= n as u64,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    check_cancelled(cancelled)
}

fn read_chunk(
    reader: &mut impl Read,
    len: usize,
    cancelled: Option<&AtomicBool>,
) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut scratch = [0; 64 * 1024];
    while data.len() < len {
        check_cancelled(cancelled)?;
        let need = (len - data.len()).min(scratch.len());
        match reader.read(&mut scratch[..need]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short HTTP range body",
                ))
            }
            Ok(n) => {
                check_cancelled(cancelled)?;
                // Reserve payload storage only after the first bytes actually arrive.
                if data.is_empty() {
                    data.reserve_exact(len);
                }
                data.extend_from_slice(&scratch[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(data)
}

fn finish_range(reader: &mut impl Read, status: u16) -> io::Result<()> {
    if status == 206 && reader.read(&mut [0])? != 0 {
        return Err(invalid_range());
    }
    Ok(())
}

fn check_cancelled(cancelled: Option<&AtomicBool>) -> io::Result<()> {
    if cancelled.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "HTTP prefetch cancelled",
        ));
    }
    Ok(())
}

fn invalid_range() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP Content-Range does not match requested range",
    )
}

/// Validate every 206 before exposing bytes, including the known object length.
/// An unknown total (`*`) is only allowed for callers that do not know the length.
pub(crate) fn validate_content_range(
    resp: &ureq::Response,
    start: u64,
    end: u64,
    size: Option<u64>,
) -> io::Result<Option<u64>> {
    let header = resp.header("Content-Range").ok_or_else(invalid_range)?;
    let (span, total) = header
        .strip_prefix("bytes ")
        .and_then(|s| s.split_once('/'))
        .ok_or_else(invalid_range)?;
    let (first, last) = span.split_once('-').ok_or_else(invalid_range)?;
    let first: u64 = first.parse().map_err(|_| invalid_range())?;
    let last: u64 = last.parse().map_err(|_| invalid_range())?;
    let total = if total == "*" {
        None
    } else {
        Some(total.parse::<u64>().map_err(|_| invalid_range())?)
    };
    let expected_end = total.map_or(end, |n| end.min(n.saturating_sub(1)));
    if first != start
        || last != expected_end
        || last < first
        || total.is_some_and(|n| n <= last)
        || size.is_some_and(|n| total != Some(n))
    {
        return Err(invalid_range());
    }
    if let Some(len) = resp.header("Content-Length") {
        if len.parse::<u64>().ok() != last.checked_sub(first).and_then(|n| n.checked_add(1)) {
            return Err(invalid_range());
        }
    }
    Ok(total)
}

// A permit covers a running worker AND its completed payload until consumed.
// Detached workers retain their permits, so repeated seeks cannot evade the cap.
struct PrefetchBudget {
    limit: usize,
    used: AtomicUsize,
}

impl PrefetchBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<PrefetchPermit> {
        ratarmount_core::try_update_usize(&self.used, Ordering::AcqRel, Ordering::Acquire, |used| {
            (used < self.limit).then_some(used + 1)
        })
        .ok()
        .map(|_| PrefetchPermit(Arc::clone(self)))
    }
}

struct PrefetchPermit(Arc<PrefetchBudget>);

impl Drop for PrefetchPermit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

fn parse_prefetch_limit(value: Option<&str>) -> usize {
    value
        .and_then(|s| s.parse().ok())
        .unwrap_or(64)
        .clamp(1, 1024)
}

fn prefetch_budget() -> Arc<PrefetchBudget> {
    static BUDGET: OnceLock<Arc<PrefetchBudget>> = OnceLock::new();
    Arc::clone(BUDGET.get_or_init(|| {
        Arc::new(PrefetchBudget::new(parse_prefetch_limit(
            std::env::var("RATARMOUNT_HTTP_PREFETCH_LIMIT")
                .ok()
                .as_deref(),
        )))
    }))
}

struct FetchedChunk {
    data: Vec<u8>,
    _permit: PrefetchPermit,
}

struct PendingRange {
    start: u64,
    worker: Option<JoinHandle<io::Result<FetchedChunk>>>,
    data: Option<FetchedChunk>,
}

pub(crate) struct Prefetch {
    source: Arc<HttpRangeSource>,
    size: u64,
    next: u64,
    position: u64,
    parallel: usize,
    window: usize,
    budget: Arc<PrefetchBudget>,
    cancelled: Arc<AtomicBool>,
    pending: VecDeque<PendingRange>,
}

impl Prefetch {
    pub(crate) fn new(
        source: Arc<HttpRangeSource>,
        start: u64,
        size: u64,
        parallel: usize,
    ) -> Self {
        Self::with_budget(source, start, size, parallel, prefetch_budget())
    }

    fn with_budget(
        source: Arc<HttpRangeSource>,
        start: u64,
        size: u64,
        parallel: usize,
        budget: Arc<PrefetchBudget>,
    ) -> Self {
        Self {
            source,
            size,
            next: start,
            position: start,
            parallel,
            window: 1,
            budget,
            cancelled: Arc::new(AtomicBool::new(false)),
            pending: VecDeque::new(),
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        let horizon = self
            .position
            .saturating_add(HTTP_RANGE_CHUNK * self.parallel as u64)
            .min(self.size);
        while self.pending.len() < self.window && self.next < horizon {
            let start = self.next;
            let end = start + self.source.window_len(start, self.size) - 1;
            if self.source.cache_available(start, end, self.size) {
                self.next = end + 1;
                continue;
            }
            let Some(permit) = self.budget.try_acquire() else {
                break;
            };
            let source = Arc::clone(&self.source);
            let size = self.size;
            let cancelled = Arc::clone(&self.cancelled);
            let worker = thread::Builder::new()
                .name("http-range".into())
                .spawn(move || {
                    let data = source.fetch(start, end, size, Some(&cancelled))?;
                    Ok(FetchedChunk {
                        data,
                        _permit: permit,
                    })
                })?;
            self.pending.push_back(PendingRange {
                start,
                worker: Some(worker),
                data: None,
            });
            self.next = end + 1;
        }
        Ok(())
    }

    // None means capacity is occupied elsewhere; the caller can read synchronously.
    pub(crate) fn read(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<Option<usize>> {
        self.position = pos;
        if self.pending.front().is_none_or(|range| pos < range.start) {
            if let Some(n) = self.source.read_cached_into(pos, self.size, buf) {
                self.position = pos + n as u64;
                self.next = self.next.max(self.position);
                self.fill()?;
                return Ok(Some(n));
            }
        }
        self.fill()?;
        let Some(front) = self.pending.front_mut() else {
            return Ok(None);
        };
        if pos < front.start {
            // The skipped disk window was evicted after scheduling. Read just
            // that gap synchronously while preserving the later queued workers.
            let n = buf.len().min((front.start - pos) as usize);
            let n = self
                .source
                .read_into_with_pattern(pos, self.size, &mut buf[..n], true)?;
            self.position = pos + n as u64;
            return Ok(Some(n));
        }
        if let Some(worker) = front.worker.take() {
            // Move the original io::Error out, preserving its source and raw errno.
            front.data = Some(
                worker
                    .join()
                    .map_err(|_| io::Error::other("HTTP range worker panicked"))??,
            );
        }
        let data = &front.data.as_ref().unwrap().data;
        let offset = (pos - front.start) as usize;
        let n = buf.len().min(data.len() - offset);
        buf[..n].copy_from_slice(&data[offset..offset + n]);
        self.position = pos + n as u64;
        if offset + n == data.len() {
            self.pending.pop_front();
            self.window = (self.window * 2).min(self.parallel);
        }
        Ok(Some(n))
    }
}

impl Drop for Prefetch {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        // Dropping JoinHandles detaches I/O. Each worker owns its source, cancel flag
        // and budget permit until it exits; no seek/release waits for network progress.
    }
}

#[cfg(test)]
#[path = "http_pool_tests.rs"]
mod tests;
