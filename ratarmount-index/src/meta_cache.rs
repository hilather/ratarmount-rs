//! V-3 process-local LRU for **whole sidecar blob downloads**.
//!
//! Lookup is URL-first (`sha256(backend | canonical_url)`). Etag lives in a
//! JSON header for optional pointer revalidation and is **not** part of the key
//! (a remount without `.ptr` must still hit). Returns a filesystem path, never
//! a `Vec<u8>`. Not payload bodies (G-3). Not `HttpRangeFile`.
//!
//! Layout: `$XDG_CACHE_HOME/ratarmount/meta-v3/{key}` + `{key}.hdr`.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use serde::{Deserialize, Serialize};

use crate::sha256_hex;

/// Whole-sidecar blob cap (bytes). Larger downloads stay tempfiles.
pub const META_SIDECAR_WHOLE_MAX: u64 = 64 * 1024 * 1024;

/// Env cap for the LRU directory. `0` disables. Default [`META_CACHE_BYTES_DEFAULT`].
pub const META_CACHE_BYTES_ENV: &str = "RATARMOUNT_META_CACHE_BYTES";

/// Default `RATARMOUNT_META_CACHE_BYTES` (256 MiB).
pub const META_CACHE_BYTES_DEFAULT: u64 = 256 * 1024 * 1024;

const META_V3_DIRNAME: &str = "meta-v3";

static PART_SEQ: AtomicU64 = AtomicU64::new(0);

/// XDG LRU of whole sidecar files keyed by canonical backend+url.
pub struct MetaCache {
    dir: PathBuf,
    /// `None` disables lookup and store.
    budget: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MetaHeader {
    #[serde(default)]
    etag: String,
    len: u64,
    /// Hex SHA-256 of the blob bytes (fail-closed on same-length tears).
    #[serde(default)]
    sha256: String,
    fetched_at: u64,
    #[serde(default)]
    last_hit: u64,
}

impl MetaCache {
    /// Directory + budget from env (`XDG_CACHE_HOME`, [`META_CACHE_BYTES_ENV`]).
    pub fn from_env() -> Self {
        Self {
            dir: meta_v3_dir(),
            budget: cache_budget(),
        }
    }

    /// Canonical cache identity: `backend|url` (no etag, no auth headers).
    pub fn identity(backend: &str, url: &str) -> String {
        cache_identity(backend, url)
    }

    /// URL-first. Returns a filesystem path for `SqliteIndex::open_read_only`.
    /// Never materializes the sidecar as `Vec<u8>`.
    pub fn get_or_fetch_path<E, F>(
        &self,
        backend_url: &str,
        pointer_etag: Option<&str>,
        fetch: F,
    ) -> std::result::Result<PathBuf, E>
    where
        F: FnOnce() -> std::result::Result<PathBuf, E>,
        E: From<io::Error>,
    {
        self.get_or_fetch_path_with_etag(backend_url, pointer_etag, || fetch().map(|p| (p, None)))
    }

    /// Like [`Self::get_or_fetch_path`], but the fetcher may supply an HTTP ETag
    /// stored in the header (revalidation only; not the lookup key).
    pub fn get_or_fetch_path_with_etag<E, F>(
        &self,
        backend_url: &str,
        pointer_etag: Option<&str>,
        fetch: F,
    ) -> std::result::Result<PathBuf, E>
    where
        F: FnOnce() -> std::result::Result<(PathBuf, Option<String>), E>,
        E: From<io::Error>,
    {
        let pointer_etag = pointer_etag.map(str::trim).filter(|s| !s.is_empty());
        if self.should_skip(backend_url) {
            return fetch().map(|(p, _)| p);
        }
        let key = sha256_hex(backend_url.as_bytes());
        if let Some(path) = self.lookup(&key, pointer_etag) {
            return Ok(path);
        }
        debug!(
            "V-3 meta cache miss {}",
            redact_identity_for_log(backend_url)
        );
        let (fetched, http_etag) = fetch()?;
        let etag = pointer_etag
            .map(str::to_string)
            .or(http_etag)
            .filter(|s| !s.is_empty());
        match self.install(&key, &fetched, etag.as_deref()) {
            Ok(p) => Ok(p),
            Err(e) => {
                debug!("V-3 meta cache store failed: {e}; using fetch path");
                if fetched.exists() {
                    Ok(fetched)
                } else {
                    Err(E::from(e))
                }
            }
        }
    }

    fn should_skip(&self, backend_url: &str) -> bool {
        if self.budget.is_none() {
            return true;
        }
        let url = identity_url(backend_url);
        url.starts_with("file://") || url.eq_ignore_ascii_case(":memory:")
    }

    fn lookup(&self, key: &str, pointer_etag: Option<&str>) -> Option<PathBuf> {
        let blob = self.blob_path(key);
        let hdr = match self.read_header(key) {
            Ok(h) => h,
            Err(_) => {
                self.invalidate_key(key);
                return None;
            }
        };
        let meta = match fs::metadata(&blob) {
            Ok(m) if m.is_file() => m,
            _ => {
                self.invalidate_key(key);
                return None;
            }
        };
        if meta.len() != hdr.len || hdr.len == 0 || hdr.sha256.is_empty() {
            debug!("V-3 meta cache corrupt {key} (len mismatch, empty, or missing sha256)");
            self.invalidate_key(key);
            return None;
        }
        match blob_sha256(&blob) {
            Ok(got) if got == hdr.sha256 => {}
            _ => {
                debug!("V-3 meta cache corrupt {key} (sha256 mismatch)");
                self.invalidate_key(key);
                return None;
            }
        }
        if let Some(etag) = pointer_etag {
            if hdr.etag != etag {
                debug!("V-3 meta cache etag mismatch {key}");
                return None;
            }
        }
        self.touch(key, &hdr);
        debug!("V-3 meta cache hit {key} -> {}", blob.display());
        Some(blob)
    }

    fn install(&self, key: &str, src: &Path, etag: Option<&str>) -> io::Result<PathBuf> {
        let meta = fs::metadata(src)?;
        if !meta.is_file() {
            return Ok(src.to_path_buf());
        }
        let len = meta.len();
        if len == 0 || len > META_SIDECAR_WHOLE_MAX {
            return Ok(src.to_path_buf());
        }
        let Some(budget) = self.budget else {
            return Ok(src.to_path_buf());
        };
        if len > budget {
            return Ok(src.to_path_buf());
        }
        self.ensure_dir()?;
        self.evict_until(budget.saturating_sub(len), Some(key))?;
        let dest = self.blob_path(key);
        if src != dest.as_path() {
            let seq = PART_SEQ.fetch_add(1, Ordering::Relaxed);
            let part = self
                .dir
                .join(format!("{key}.{}.{seq}.part", std::process::id()));
            if let Err(e) = fs::copy(src, &part) {
                let _ = fs::remove_file(&part);
                return Err(e);
            }
            if let Ok(f) = File::open(&part) {
                let _ = f.sync_all();
            }
            if let Err(e) = fs::rename(&part, &dest) {
                let _ = fs::remove_file(&part);
                return Err(e);
            }
        }
        let sha256 = match blob_sha256(&dest) {
            Ok(h) => h,
            Err(e) => {
                self.invalidate_key(key);
                return Err(e);
            }
        };
        let now = unix_now();
        let hdr = MetaHeader {
            etag: etag.unwrap_or("").to_string(),
            len,
            sha256,
            fetched_at: now,
            last_hit: now,
        };
        if let Err(e) = self.write_header(key, &hdr) {
            self.invalidate_key(key);
            return Err(e);
        }
        if src != dest.as_path() && !path_is_under(&self.dir, src) {
            let _ = fs::remove_file(src);
        }
        debug!(
            "V-3 meta cache store {key} -> {} ({len} bytes)",
            dest.display()
        );
        Ok(dest)
    }

    fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    fn blob_path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }

    fn hdr_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.hdr"))
    }

    fn read_header(&self, key: &str) -> io::Result<MetaHeader> {
        let bytes = fs::read(self.hdr_path(key))?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn write_header(&self, key: &str, hdr: &MetaHeader) -> io::Result<()> {
        let part = self.dir.join(format!("{key}.hdr.part"));
        let json =
            serde_json::to_vec(hdr).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        {
            let mut f = File::create(&part)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        fs::rename(part, self.hdr_path(key))?;
        Ok(())
    }

    fn touch(&self, key: &str, hdr: &MetaHeader) {
        let mut next = hdr.clone();
        next.last_hit = unix_now().max(hdr.last_hit.saturating_add(1));
        let _ = self.write_header(key, &next);
    }

    fn invalidate_key(&self, key: &str) {
        let _ = fs::remove_file(self.blob_path(key));
        let _ = fs::remove_file(self.hdr_path(key));
        if let Ok(iter) = fs::read_dir(&self.dir) {
            for ent in iter.flatten() {
                let name = ent.file_name();
                let n = name.to_string_lossy();
                if n.starts_with(key) && n.ends_with(".part") {
                    let _ = fs::remove_file(ent.path());
                }
            }
        }
    }

    fn evict_until(&self, max_used: u64, keep: Option<&str>) -> io::Result<()> {
        let mut entries = self.list_entries()?;
        let mut used: u64 = entries.iter().map(|e| e.len).sum();
        if used <= max_used {
            return Ok(());
        }
        entries.sort_by_key(|e| e.last_hit);
        for e in entries {
            if used <= max_used {
                break;
            }
            if keep == Some(e.key.as_str()) {
                continue;
            }
            debug!("V-3 meta cache evict {} ({} bytes)", e.key, e.len);
            self.invalidate_key(&e.key);
            used = used.saturating_sub(e.len);
        }
        Ok(())
    }

    fn list_entries(&self) -> io::Result<Vec<CacheEntry>> {
        let mut out = Vec::new();
        let iter = match fs::read_dir(&self.dir) {
            Ok(i) => i,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for ent in iter {
            let ent = ent?;
            let name = ent.file_name();
            let name = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            if !is_key_name(name) {
                continue;
            }
            let hdr = match self.read_header(name) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let len = match fs::metadata(ent.path()) {
                Ok(m) if m.is_file() => m.len(),
                _ => continue,
            };
            out.push(CacheEntry {
                key: name.to_string(),
                len,
                last_hit: hdr.last_hit,
            });
        }
        Ok(out)
    }
}

struct CacheEntry {
    key: String,
    len: u64,
    last_hit: u64,
}

/// `backend|canonical_url` — etag / Cookie / Authorization are not in the key.
pub fn cache_identity(backend: &str, url: &str) -> String {
    let url = url.trim();
    let url = url.split_once('#').map(|(b, _)| b).unwrap_or(url);
    format!("{backend}|{url}")
}

/// True when `path` is a V-3 XDG blob (do not unlink on successful install copy).
pub fn is_meta_cache_path(path: &Path) -> bool {
    path_is_under(&meta_v3_dir(), path)
}

/// Delete a cached blob + header. No-op when `path` is not under meta-v3.
pub fn invalidate_meta_cache_file(path: &Path) {
    if !is_meta_cache_path(path) {
        let _ = fs::remove_file(path);
        return;
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        MetaCache::from_env().invalidate_key(name);
    } else {
        let _ = fs::remove_file(path);
    }
}

/// Drop the LRU entry for `backend|url` (wire blob, even after decompress).
pub fn invalidate_meta_cache_identity(backend: &str, url: &str) {
    let identity = cache_identity(backend, url);
    let key = sha256_hex(identity.as_bytes());
    MetaCache::from_env().invalidate_key(&key);
}

fn blob_sha256(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    crate::sha256_hex_stream(&mut f)
}

fn identity_url(backend_url: &str) -> &str {
    backend_url
        .split_once('|')
        .map(|(_, u)| u)
        .unwrap_or(backend_url)
        .trim()
}

fn redact_identity_for_log(identity: &str) -> String {
    let url = identity_url(identity);
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(at) = rest.rfind('@') {
            return format!("{}://***@{}", &url[..scheme_end], &rest[at + 1..]);
        }
    }
    url.to_string()
}

fn is_key_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn cache_budget() -> Option<u64> {
    match std::env::var(META_CACHE_BYTES_ENV) {
        Ok(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Some(META_CACHE_BYTES_DEFAULT);
            }
            match s.parse::<u64>() {
                Ok(0) => None,
                Ok(n) => Some(n),
                Err(_) => Some(META_CACHE_BYTES_DEFAULT),
            }
        }
        Err(_) => Some(META_CACHE_BYTES_DEFAULT),
    }
}

fn xdg_cache_home() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache"))
}

fn meta_v3_dir() -> PathBuf {
    #[cfg(test)]
    {
        // `cargo test` must not write into the developer's ~/.cache when XDG is unset.
        if std::env::var_os("XDG_CACHE_HOME").is_none() {
            use std::sync::OnceLock;
            static FALLBACK: OnceLock<PathBuf> = OnceLock::new();
            return FALLBACK
                .get_or_init(|| {
                    let p = std::env::temp_dir()
                        .join(format!("ratarmount-meta-v3-test-{}", std::process::id()));
                    let _ = fs::create_dir_all(&p);
                    p.join("ratarmount").join(META_V3_DIRNAME)
                })
                .clone();
        }
    }
    xdg_cache_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ratarmount")
        .join(META_V3_DIRNAME)
}

#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn path_is_under(root: &Path, path: &Path) -> bool {
    if path.starts_with(root) {
        return true;
    }
    match (fs::canonicalize(root), fs::canonicalize(path)) {
        (Ok(r), Ok(p)) => p.starts_with(&r),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cache_in(dir: &Path) -> MetaCache {
        MetaCache {
            dir: dir.join("meta-v3"),
            budget: Some(META_CACHE_BYTES_DEFAULT),
        }
    }

    #[test]
    fn identity_strips_fragment_and_excludes_etag() {
        assert_eq!(
            cache_identity("http", "https://h/a.index.sqlite#x"),
            "http|https://h/a.index.sqlite"
        );
        assert!(!cache_identity("http", "https://h/a").contains("etag"));
    }

    #[test]
    fn get_or_fetch_path_url_first_hit_returns_path_not_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path());
        let fetches = AtomicUsize::new(0);
        let body = b"SQLite format 3\0sidecar-v3";
        let fetch = || {
            fetches.fetch_add(1, Ordering::SeqCst);
            let p = dir
                .path()
                .join(format!("src-{}", fetches.load(Ordering::SeqCst)));
            fs::write(&p, body).unwrap();
            Ok::<_, io::Error>(p)
        };
        let id = cache_identity("http", "http://127.0.0.1/a.tar.index.sqlite");
        let p1 = cache.get_or_fetch_path(&id, None, fetch).unwrap();
        assert!(p1.starts_with(&cache.dir), "{}", p1.display());
        assert_eq!(fs::read(&p1).unwrap(), body);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        let p2 = cache.get_or_fetch_path(&id, None, fetch).unwrap();
        assert_eq!(p2, p1);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert!(p2.is_file());
    }

    #[test]
    fn remount_without_pointer_is_cache_hit() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path());
        let fetches = AtomicUsize::new(0);
        let fetch = || {
            fetches.fetch_add(1, Ordering::SeqCst);
            let p = dir.path().join("blob");
            fs::write(&p, b"SQLite format 3\0well-known").unwrap();
            Ok::<_, io::Error>(p)
        };
        let id = cache_identity("http", "http://127.0.0.1/a.tar.zst.index.sqlite");
        cache.get_or_fetch_path(&id, None, fetch).unwrap();
        cache.get_or_fetch_path(&id, None, fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pointer_etag_mismatch_refetches_once() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path());
        let fetches = AtomicUsize::new(0);
        let fetch = || {
            let n = fetches.fetch_add(1, Ordering::SeqCst) + 1;
            let p = dir.path().join(format!("b{n}"));
            fs::write(&p, format!("SQLite format 3\0v{n}").as_bytes()).unwrap();
            Ok::<_, io::Error>(p)
        };
        let id = cache_identity("http", "http://h/idx.sqlite");
        let p1 = cache.get_or_fetch_path(&id, Some("etag-a"), fetch).unwrap();
        assert_eq!(fs::read(&p1).unwrap(), b"SQLite format 3\0v1");
        let p2 = cache.get_or_fetch_path(&id, Some("etag-b"), fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(&p2).unwrap(), b"SQLite format 3\0v2");
        cache.get_or_fetch_path(&id, Some("etag-b"), fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn corrupt_blob_refetches() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path());
        let fetches = AtomicUsize::new(0);
        let fetch = || {
            fetches.fetch_add(1, Ordering::SeqCst);
            let p = dir
                .path()
                .join(format!("s{}", fetches.load(Ordering::SeqCst)));
            fs::write(&p, b"SQLite format 3\0ok").unwrap();
            Ok::<_, io::Error>(p)
        };
        let id = cache_identity("http", "http://h/corrupt.sqlite");
        let p1 = cache.get_or_fetch_path(&id, None, fetch).unwrap();
        fs::write(&p1, b"truncated").unwrap();
        let p2 = cache.get_or_fetch_path(&id, None, fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(&p2).unwrap(), b"SQLite format 3\0ok");
    }

    /// Regression: same-length torn blob fails closed via header sha256.
    #[test]
    fn same_length_tear_refetches() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path());
        let fetches = AtomicUsize::new(0);
        let body = b"SQLite format 3\0ok-sidecar";
        let fetch = || {
            fetches.fetch_add(1, Ordering::SeqCst);
            let p = dir
                .path()
                .join(format!("t{}", fetches.load(Ordering::SeqCst)));
            fs::write(&p, body).unwrap();
            Ok::<_, io::Error>(p)
        };
        let id = cache_identity("http", "http://h/torn.sqlite");
        let p1 = cache.get_or_fetch_path(&id, None, fetch).unwrap();
        let tear = vec![b'x'; body.len()];
        fs::write(&p1, &tear).unwrap();
        let p2 = cache.get_or_fetch_path(&id, None, fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(&p2).unwrap(), body);
    }

    /// Regression: fetch tempfile is not unlinked until the header is durable.
    #[test]
    fn install_keeps_src_if_header_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path());
        fs::create_dir_all(&cache.dir).unwrap();
        let id = cache_identity("http", "http://h/hdrfail");
        let key = crate::sha256_hex(id.as_bytes());
        fs::create_dir(cache.dir.join(format!("{key}.hdr"))).unwrap();
        let src = dir.path().join("keep-me");
        fs::write(&src, b"SQLite format 3\0xx").unwrap();
        let p = cache
            .get_or_fetch_path(&id, None, || Ok::<_, io::Error>(src.clone()))
            .unwrap();
        assert_eq!(p, src);
        assert!(
            src.is_file(),
            "must not delete fetch tempfile before header is durable"
        );
    }

    #[test]
    fn file_url_and_memory_skip_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path());
        let fetches = AtomicUsize::new(0);
        let fetch = || {
            fetches.fetch_add(1, Ordering::SeqCst);
            let p = dir.path().join("local");
            fs::write(&p, b"local-idx").unwrap();
            Ok::<_, io::Error>(p)
        };
        let file_id = cache_identity("file", "file:///tmp/a.index.sqlite");
        let p1 = cache.get_or_fetch_path(&file_id, None, fetch).unwrap();
        let p2 = cache.get_or_fetch_path(&file_id, None, fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert_eq!(p1, p2);
        assert!(!path_is_under(&cache.dir, &p1));

        let mem_id = cache_identity("http", ":memory:");
        cache.get_or_fetch_path(&mem_id, None, fetch).unwrap();
        cache.get_or_fetch_path(&mem_id, None, fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn budget_zero_disables() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MetaCache {
            dir: dir.path().join("meta-v3"),
            budget: None,
        };
        let fetches = AtomicUsize::new(0);
        let fetch = || {
            fetches.fetch_add(1, Ordering::SeqCst);
            let p = dir
                .path()
                .join(format!("t{}", fetches.load(Ordering::SeqCst)));
            fs::write(&p, b"x").unwrap();
            Ok::<_, io::Error>(p)
        };
        let id = cache_identity("http", "http://h/z.sqlite");
        cache.get_or_fetch_path(&id, None, fetch).unwrap();
        cache.get_or_fetch_path(&id, None, fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn oversized_blob_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path());
        let fetches = AtomicUsize::new(0);
        let fetch = || {
            fetches.fetch_add(1, Ordering::SeqCst);
            let p = dir.path().join("big");
            fs::write(&p, vec![0u8; (META_SIDECAR_WHOLE_MAX as usize) + 1]).unwrap();
            Ok::<_, io::Error>(p)
        };
        let id = cache_identity("http", "http://h/big.sqlite");
        let p = cache.get_or_fetch_path(&id, None, fetch).unwrap();
        assert!(!path_is_under(&cache.dir, &p));
        cache.get_or_fetch_path(&id, None, fetch).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn lru_evicts_oldest_hit() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MetaCache {
            dir: dir.path().join("meta-v3"),
            budget: Some(8),
        };
        let write = |name: &str, body: &[u8]| {
            let p = dir.path().join(name);
            fs::write(&p, body).unwrap();
            p
        };
        let a = cache_identity("http", "http://h/a");
        let b = cache_identity("http", "http://h/b");
        let c = cache_identity("http", "http://h/c");
        cache
            .get_or_fetch_path(&a, None, || Ok::<_, io::Error>(write("a", b"aaaa")))
            .unwrap();
        cache
            .get_or_fetch_path(&b, None, || Ok::<_, io::Error>(write("b", b"bbbb")))
            .unwrap();
        // Touch `a` so `b` is colder, then insert `c` (4 bytes) under an 8-byte cap
        // that already holds 8. Evict `b`.
        let a_miss = AtomicUsize::new(0);
        cache
            .get_or_fetch_path(&a, None, || {
                a_miss.fetch_add(1, Ordering::SeqCst);
                Ok::<_, io::Error>(write("a2", b"xxxx"))
            })
            .unwrap();
        assert_eq!(a_miss.load(Ordering::SeqCst), 0);
        cache
            .get_or_fetch_path(&c, None, || Ok::<_, io::Error>(write("c", b"cccc")))
            .unwrap();
        cache
            .get_or_fetch_path(&a, None, || {
                a_miss.fetch_add(1, Ordering::SeqCst);
                Ok::<_, io::Error>(write("a3", b"yyyy"))
            })
            .unwrap();
        assert_eq!(a_miss.load(Ordering::SeqCst), 0);
        let b_miss = AtomicUsize::new(0);
        cache
            .get_or_fetch_path(&b, None, || {
                b_miss.fetch_add(1, Ordering::SeqCst);
                Ok::<_, io::Error>(write("b2", b"BBBB"))
            })
            .unwrap();
        assert_eq!(b_miss.load(Ordering::SeqCst), 1);
    }

    /// Regression: returned handle is a path `SqliteIndex::open_read_only` can use.
    #[test]
    fn cached_path_opens_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("real.sqlite");
        {
            crate::SqliteIndex::create_writable(Some(&src)).unwrap();
        }
        let body = fs::read(&src).unwrap();
        let cache = cache_in(dir.path());
        let id = cache_identity("http", "http://h/real.index.sqlite");
        let path = cache
            .get_or_fetch_path(&id, None, || {
                let p = dir.path().join("dl");
                fs::write(&p, &body).unwrap();
                Ok::<_, io::Error>(p)
            })
            .unwrap();
        assert!(path_is_under(&cache.dir, &path));
        crate::SqliteIndex::open_read_only(&path).unwrap();
    }
}
