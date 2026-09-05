//! G-3 decompressed-member LRU (`payload-v1/`), sibling of `local-index-v1/`.
//!
//! Keys are lowercase hex SHA-256 of **decompressed member bytes**. Layout:
//! [`platform_cache_root()`]`/payload-v1/{hh}/{sha256}` plus `{sha256}.hdr`.
//! Never writes `meta-v3/` or nests under `local-index-v1/`.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::HASH_STREAM_CHUNK;

/// Env cap for the LRU directory. `0` disables writes. Default [`PAYLOAD_CACHE_BYTES_DEFAULT`].
pub const PAYLOAD_CACHE_BYTES_ENV: &str = "RATARMOUNT_PAYLOAD_CACHE_BYTES";

/// Override directory (highest priority; skips platform / XDG roots).
pub const PAYLOAD_CACHE_DIR_ENV: &str = "RATARMOUNT_PAYLOAD_CACHE_DIR";

/// Per-member size skip. `0` disables caching. Default [`PAYLOAD_CACHE_MEMBER_MAX_DEFAULT`].
pub const PAYLOAD_CACHE_MEMBER_MAX_ENV: &str = "RATARMOUNT_PAYLOAD_CACHE_MEMBER_MAX";

/// Default `RATARMOUNT_PAYLOAD_CACHE_BYTES` (4 GiB).
pub const PAYLOAD_CACHE_BYTES_DEFAULT: u64 = 4 * 1024 * 1024 * 1024;

/// Default `RATARMOUNT_PAYLOAD_CACHE_MEMBER_MAX` (64 MiB).
pub const PAYLOAD_CACHE_MEMBER_MAX_DEFAULT: u64 = 64 * 1024 * 1024;

const PAYLOAD_V1_DIRNAME: &str = "payload-v1";
const PAYLOAD_SCHEMA: &str = "ratarmount.payload-v1";
const SHA256_HEX_LEN: usize = 64;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// LRU of decompressed member bodies keyed by sha256.
#[derive(Clone, Debug)]
pub struct PayloadCache {
    dir: PathBuf,
    /// `None` disables lookup and store (`RATARMOUNT_PAYLOAD_CACHE_BYTES=0`).
    budget: Option<u64>,
    member_max: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PayloadHeader {
    schema: String,
    len: u64,
    last_hit: u64,
}

struct CacheEntry {
    key: String,
    len: u64,
    last_hit: u64,
}

impl PayloadCache {
    /// Directory + budget from env. `None` when disabled or `:memory:`.
    ///
    /// WHY: `:memory:` indexes must not create `payload-v1/` (no durable catalog).
    pub fn from_env_for_index(index_in_memory: bool) -> Option<Self> {
        if index_in_memory {
            return None;
        }
        let budget = cache_budget()?;
        Some(Self {
            dir: payload_v1_dir(),
            budget: Some(budget),
            member_max: member_max_from_env(),
        })
    }

    /// Test/helper constructor. `budget = None` disables store.
    pub fn with_dir(dir: PathBuf, budget: Option<u64>, member_max: u64) -> Self {
        Self {
            dir,
            budget,
            member_max,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn member_max(&self) -> u64 {
        self.member_max
    }

    pub fn is_enabled(&self) -> bool {
        self.budget.is_some() && self.member_max > 0
    }

    /// Existing `{hh}/{sha256}` whose header length matches the blob.
    pub fn lookup(&self, sha256: &str) -> Option<PathBuf> {
        self.budget?;
        let key = normalize_sha256(sha256)?;
        let blob = self.blob_path(&key);
        let hdr = match self.read_header(&key) {
            Ok(h) if h.schema == PAYLOAD_SCHEMA => h,
            _ => {
                self.invalidate_key(&key);
                return None;
            }
        };
        let meta = match fs::metadata(&blob) {
            Ok(m) if m.is_file() => m,
            _ => {
                self.invalidate_key(&key);
                return None;
            }
        };
        if meta.len() != hdr.len || hdr.len == 0 {
            debug!("payload-v1 corrupt {key} (len mismatch or empty)");
            self.invalidate_key(&key);
            return None;
        }
        self.touch(&key, &hdr);
        debug!("payload-v1 hit {key} -> {}", blob.display());
        Some(blob)
    }

    /// Copy `reader` to `{sha256}.tmp.{pid}` + rename. Fail-closed on short/hash mismatch.
    pub fn install_from_reader<R: Read>(
        &self,
        sha256: &str,
        expected_len: u64,
        reader: &mut R,
    ) -> io::Result<PathBuf> {
        let Some(budget) = self.budget else {
            return Err(io::Error::other(
                "RATARMOUNT_PAYLOAD_CACHE_BYTES=0 disables payload-v1; not meta-v3",
            ));
        };
        let Some(key) = normalize_sha256(sha256) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload-v1 key must be 64 hex sha256",
            ));
        };
        if expected_len == 0 || expected_len > self.member_max || expected_len > budget {
            return Err(io::Error::other(
                "payload-v1 skip: member empty, over member max, or over budget",
            ));
        }
        if let Some(existing) = self.lookup(&key) {
            if fs::metadata(&existing).map(|m| m.len()).unwrap_or(0) == expected_len {
                return Ok(existing);
            }
        }
        self.ensure_fanout(&key)?;
        self.evict_until(budget.saturating_sub(expected_len), Some(&key))?;
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .fanout_dir(&key)
            .join(format!("{key}.tmp.{}.{}", std::process::id(), seq));
        let dest = self.blob_path(&key);
        let written_hash = match copy_hash_to_tmp(&tmp, reader, expected_len) {
            Ok(h) => h,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        if written_hash != key {
            let _ = fs::remove_file(&tmp);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload-v1 fail-closed: sha256 mismatch",
            ));
        }
        if let Ok(f) = File::open(&tmp) {
            let _ = f.sync_all();
        }
        if let Err(e) = fs::rename(&tmp, &dest) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        let now = unix_now();
        let hdr = PayloadHeader {
            schema: PAYLOAD_SCHEMA.to_string(),
            len: expected_len,
            last_hit: now,
        };
        if let Err(e) = self.write_header(&key, &hdr) {
            self.invalidate_key(&key);
            return Err(e);
        }
        debug!(
            "payload-v1 store {key} -> {} ({expected_len} bytes)",
            dest.display()
        );
        Ok(dest)
    }

    /// Hit or fill. `fill` is not called on a valid lookup (second open skips the archive).
    pub fn get_or_fill<R, F>(&self, sha256: &str, expected_len: u64, fill: F) -> io::Result<PathBuf>
    where
        R: Read,
        F: FnOnce() -> io::Result<R>,
    {
        if let Some(path) = self.lookup(sha256) {
            if fs::metadata(&path).map(|m| m.len()).unwrap_or(0) == expected_len {
                return Ok(path);
            }
        }
        let mut reader = fill()?;
        self.install_from_reader(sha256, expected_len, &mut reader)
    }

    fn blob_path(&self, key: &str) -> PathBuf {
        self.fanout_dir(key).join(key)
    }

    fn hdr_path(&self, key: &str) -> PathBuf {
        self.fanout_dir(key).join(format!("{key}.hdr"))
    }

    fn fanout_dir(&self, key: &str) -> PathBuf {
        self.dir.join(&key[..2])
    }

    fn ensure_dir(path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    fn ensure_fanout(&self, key: &str) -> io::Result<()> {
        Self::ensure_dir(&self.dir)?;
        Self::ensure_dir(&self.fanout_dir(key))
    }

    fn read_header(&self, key: &str) -> io::Result<PayloadHeader> {
        let bytes = fs::read(self.hdr_path(key))?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn write_header(&self, key: &str, hdr: &PayloadHeader) -> io::Result<()> {
        self.ensure_fanout(key)?;
        let part = self.fanout_dir(key).join(format!("{key}.hdr.part"));
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

    fn touch(&self, key: &str, hdr: &PayloadHeader) {
        let mut next = hdr.clone();
        next.last_hit = unix_now().max(hdr.last_hit.saturating_add(1));
        let _ = self.write_header(key, &next);
    }

    fn invalidate_key(&self, key: &str) {
        let _ = fs::remove_file(self.blob_path(key));
        let _ = fs::remove_file(self.hdr_path(key));
        let fan = self.fanout_dir(key);
        if let Ok(iter) = fs::read_dir(&fan) {
            for ent in iter.flatten() {
                let name = ent.file_name();
                let n = name.to_string_lossy();
                if n.starts_with(key) && (n.ends_with(".part") || n.contains(".tmp.")) {
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
        let mut remaining = entries.len();
        for e in entries {
            if used <= max_used {
                break;
            }
            if keep == Some(e.key.as_str()) {
                continue;
            }
            if remaining <= 1 {
                break;
            }
            debug!(
                "payload-v1 evict {} ({} bytes, last_hit {})",
                e.key, e.len, e.last_hit
            );
            self.invalidate_key(&e.key);
            used = used.saturating_sub(e.len);
            remaining = remaining.saturating_sub(1);
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
        for fan in iter {
            let fan = fan?;
            let fan_name = fan.file_name();
            let fan_name = match fan_name.to_str() {
                Some(s) if is_fanout_name(s) => s,
                _ => continue,
            };
            let _ = fan_name;
            let sub = match fs::read_dir(fan.path()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for ent in sub {
                let ent = ent?;
                let name = ent.file_name();
                let name = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                let Some(key) = normalize_sha256(name) else {
                    continue;
                };
                let path = ent.path();
                let len = match fs::metadata(&path) {
                    Ok(m) if m.is_file() => m.len(),
                    _ => continue,
                };
                if len == 0 {
                    continue;
                }
                let last_hit = match self.read_header(&key) {
                    Ok(h) if h.schema == PAYLOAD_SCHEMA => h.last_hit,
                    _ => file_mtime_unix(&path),
                };
                out.push(CacheEntry { key, len, last_hit });
            }
        }
        Ok(out)
    }
}

/// Platform `payload-v1` directory (env + OS). Sibling of `local-index-v1/`.
pub fn payload_v1_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(PAYLOAD_CACHE_DIR_ENV) {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    #[cfg(test)]
    {
        // `cargo test` must not write into the developer's cache when overrides are unset.
        if std::env::var_os("XDG_CACHE_HOME").is_none() {
            use std::sync::OnceLock;
            static FALLBACK: OnceLock<PathBuf> = OnceLock::new();
            return FALLBACK
                .get_or_init(|| {
                    let p = std::env::temp_dir()
                        .join(format!("ratarmount-payload-v1-test-{}", std::process::id()));
                    let _ = fs::create_dir_all(&p);
                    p.join("ratarmount").join(PAYLOAD_V1_DIRNAME)
                })
                .clone();
        }
    }
    crate::platform_cache_root().join(PAYLOAD_V1_DIRNAME)
}

/// True when `path` is under this process's `payload-v1` root.
pub fn is_payload_cache_path(path: &Path) -> bool {
    path_is_under(&payload_v1_dir(), path)
}

fn copy_hash_to_tmp<R: Read>(tmp: &Path, reader: &mut R, expected_len: u64) -> io::Result<String> {
    let mut f = File::create(tmp)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_STREAM_CHUNK];
    let mut written = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if written + n as u64 > expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload-v1 fail-closed: longer than expected",
            ));
        }
        f.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        written += n as u64;
    }
    if written != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "payload-v1 fail-closed: short member",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn normalize_sha256(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() == SHA256_HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(s.to_ascii_lowercase())
    } else {
        None
    }
}

fn is_fanout_name(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn file_mtime_unix(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_budget() -> Option<u64> {
    match std::env::var(PAYLOAD_CACHE_BYTES_ENV) {
        Ok(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Some(PAYLOAD_CACHE_BYTES_DEFAULT);
            }
            match s.parse::<u64>() {
                Ok(0) => None,
                Ok(n) => Some(n),
                Err(_) => Some(PAYLOAD_CACHE_BYTES_DEFAULT),
            }
        }
        Err(_) => Some(PAYLOAD_CACHE_BYTES_DEFAULT),
    }
}

fn member_max_from_env() -> u64 {
    match std::env::var(PAYLOAD_CACHE_MEMBER_MAX_ENV) {
        Ok(s) => {
            let s = s.trim();
            if s.is_empty() {
                return PAYLOAD_CACHE_MEMBER_MAX_DEFAULT;
            }
            match s.parse::<u64>() {
                Ok(n) => n,
                Err(_) => PAYLOAD_CACHE_MEMBER_MAX_DEFAULT,
            }
        }
        Err(_) => PAYLOAD_CACHE_MEMBER_MAX_DEFAULT,
    }
}

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
    use crate::local_cache::platform_cache_root_from;
    use crate::{is_meta_cache_path, sha256_hex};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cache_in(dir: &Path, budget: u64) -> PayloadCache {
        PayloadCache::with_dir(dir.join(PAYLOAD_V1_DIRNAME), Some(budget), 64 * 1024)
    }

    fn set_last_hit(cache: &PayloadCache, sha: &str, ts: u64) {
        let mut hdr: PayloadHeader =
            serde_json::from_slice(&fs::read(cache.hdr_path(sha)).unwrap()).unwrap();
        hdr.last_hit = ts;
        fs::write(cache.hdr_path(sha), serde_json::to_vec(&hdr).unwrap()).unwrap();
    }

    /// Regression: second fill of a hashed member does not read the archive.
    #[test]
    fn payload_cache_second_open_does_not_read_archive() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), PAYLOAD_CACHE_BYTES_DEFAULT);
        let body = b"decompressed-member-bytes";
        let sha = sha256_hex(body);
        let fills = AtomicUsize::new(0);
        let fill = || {
            fills.fetch_add(1, Ordering::SeqCst);
            Ok::<_, io::Error>(Cursor::new(body.to_vec()))
        };
        let p1 = cache.get_or_fill(&sha, body.len() as u64, fill).unwrap();
        assert_eq!(fs::read(&p1).unwrap(), body);
        assert_eq!(fills.load(Ordering::SeqCst), 1);
        let p2 = cache.get_or_fill(&sha, body.len() as u64, fill).unwrap();
        assert_eq!(p2, p1);
        assert_eq!(fills.load(Ordering::SeqCst), 1);
        let rel = p1.strip_prefix(&cache.dir).unwrap();
        let comps: Vec<_> = rel
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert_eq!(comps.len(), 2, "{comps:?}");
        assert_eq!(comps[0], &sha[..2]);
        assert_eq!(comps[1], sha);
    }

    /// Regression: `:memory:` never creates `payload-v1/`.
    #[test]
    fn payload_cache_skips_memory() {
        let _g = crate::meta_cache::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload-v1");
        let old_dir = std::env::var_os(PAYLOAD_CACHE_DIR_ENV);
        std::env::set_var(PAYLOAD_CACHE_DIR_ENV, &payload);
        let cache = PayloadCache::from_env_for_index(true);
        let created = payload.exists();
        match old_dir {
            Some(v) => std::env::set_var(PAYLOAD_CACHE_DIR_ENV, v),
            None => std::env::remove_var(PAYLOAD_CACHE_DIR_ENV),
        }
        assert!(cache.is_none(), "memory index must skip payload-v1");
        assert!(!created, "payload-v1 must not be created for :memory:");
    }

    /// Regression: payload-v1 must not write `meta-v3/` or nest under local-index-v1.
    #[test]
    fn payload_cache_not_meta_v3() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), PAYLOAD_CACHE_BYTES_DEFAULT);
        let body = b"not-a-sidecar";
        let sha = sha256_hex(body);
        let path = cache
            .install_from_reader(&sha, body.len() as u64, &mut Cursor::new(body.as_slice()))
            .unwrap();
        assert!(path.starts_with(&cache.dir), "{}", path.display());
        assert!(!is_meta_cache_path(&path), "{}", path.display());
        let as_str = path.to_string_lossy();
        assert!(
            !as_str.contains("meta-v3"),
            "must not write meta-v3: {}",
            path.display()
        );
        assert!(
            !as_str.contains("local-index-v1"),
            "payload-v1 must not nest under local-index-v1: {}",
            path.display()
        );
        let meta = dir.path().join("ratarmount").join("meta-v3");
        assert!(
            !meta.exists()
                || fs::read_dir(&meta)
                    .map(|it| it.count() == 0)
                    .unwrap_or(true),
            "payload-v1 must not create meta-v3: {}",
            meta.display()
        );
    }

    /// Regression: LRU cap deletes oldest `last_hit` sha256 blobs.
    #[test]
    fn payload_cache_lru_evicts() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), PAYLOAD_CACHE_BYTES_DEFAULT);
        let a = b"aaaa";
        let b = b"bbbb";
        let c = b"cccc";
        let sa = sha256_hex(a);
        let sb = sha256_hex(b);
        let sc = sha256_hex(c);
        let pa = cache
            .install_from_reader(&sa, a.len() as u64, &mut Cursor::new(a.as_slice()))
            .unwrap();
        let pb = cache
            .install_from_reader(&sb, b.len() as u64, &mut Cursor::new(b.as_slice()))
            .unwrap();
        let pc = cache
            .install_from_reader(&sc, c.len() as u64, &mut Cursor::new(c.as_slice()))
            .unwrap();
        set_last_hit(&cache, &sa, 100);
        set_last_hit(&cache, &sb, 1);
        set_last_hit(&cache, &sc, 200);
        cache.evict_until(8, None).unwrap();
        assert!(pa.is_file(), "newer a must survive");
        assert!(
            !pb.is_file(),
            "oldest last_hit (b) must be evicted under an 8-byte cap"
        );
        assert!(pc.is_file(), "newest c must survive");
        assert!(
            !cache.hdr_path(&sb).exists(),
            "eviction must drop the hdr pair"
        );
    }

    /// Regression: truncated tmp is not published (fail-closed).
    #[test]
    fn payload_cache_fail_closed_short() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), PAYLOAD_CACHE_BYTES_DEFAULT);
        let body = b"only-five-bytes-here";
        let sha = sha256_hex(body);
        let err = cache
            .install_from_reader(
                &sha,
                body.len() as u64 + 8,
                &mut Cursor::new(body.as_slice()),
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            cache.lookup(&sha).is_none(),
            "short copy must not publish a blob"
        );
        assert!(!cache.blob_path(&sha).exists());
    }

    /// Regression: macOS without XDG uses Library/Caches/ratarmount/payload-v1
    /// as a **sibling** of local-index-v1, never a child.
    #[test]
    fn payload_cache_macos_library_caches() {
        let root = platform_cache_root_from(None, Some(Path::new("/Users/me")), None);
        let payload = root.join(PAYLOAD_V1_DIRNAME);
        let index = root.join("local-index-v1");
        assert_eq!(payload.parent(), Some(root.as_path()));
        assert_eq!(index.parent(), Some(root.as_path()));
        assert!(
            !payload.starts_with(&index),
            "payload-v1 must not nest under local-index-v1: {} vs {}",
            payload.display(),
            index.display()
        );
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                payload,
                PathBuf::from("/Users/me/Library/Caches/ratarmount/payload-v1")
            );
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            assert_eq!(
                payload,
                PathBuf::from("/Users/me/.cache/ratarmount/payload-v1")
            );
        }
    }
}
