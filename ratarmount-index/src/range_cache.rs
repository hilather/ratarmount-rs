//! Verified remote bytes in aligned chunks, sharing the payload-v1 disk budget.
//!
//! Publication is a synced temporary file followed by rename. Cache failures are
//! misses. Open readers survive eviction on Unix. There is no interprocess lock:
//! other writers are reconciled periodically, so concurrent processes may briefly
//! exceed the cap. Private directories and no-follow opens protect cache paths.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default aligned remote chunk size (4 MiB).
pub const RANGE_CACHE_CHUNK_DEFAULT: u64 = 4 * 1024 * 1024;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);
const TEMP_MAX_AGE: Duration = Duration::from_secs(3600);
const TOUCH_INTERVAL_NANOS: u64 = 5_000_000_000;

/// Identity verified by the caller against remote metadata, never a URL alone.
///
/// ETags and object versions are scoped to their resource (canonical origin URL
/// or object-store resource). Hub commits must be resolved immutable hex IDs,
/// not branch names. SHA-256 tokens additionally verify the assembled whole file.
#[derive(Clone, Debug, Serialize)]
pub enum ContentToken {
    Sha256 {
        sha256: String,
        size: u64,
    },
    HfCommitPath {
        endpoint: String,
        repo_kind: String,
        repo: String,
        commit: String,
        path: String,
        size: u64,
    },
    StrongEtag {
        resource: String,
        etag: String,
        size: u64,
    },
    ObjectVersion {
        resource: String,
        version: String,
        size: u64,
    },
}

impl ContentToken {
    pub fn size(&self) -> u64 {
        match self {
            Self::Sha256 { size, .. }
            | Self::HfCommitPath { size, .. }
            | Self::StrongEtag { size, .. }
            | Self::ObjectVersion { size, .. } => *size,
        }
    }

    /// Validate the syntax of a strong RFC 9110 entity tag.
    pub fn is_strong_etag(etag: &str) -> bool {
        let bytes = etag.as_bytes();
        bytes.len() >= 2
            && bytes[0] == b'"'
            && bytes[bytes.len() - 1] == b'"'
            && bytes[1..bytes.len() - 1]
                .iter()
                .all(|&b| b == 0x21 || b >= 0x23 && b != 0x7f)
    }

    fn key(&self, chunk_size: u64) -> Option<String> {
        let valid = match self {
            Self::Sha256 { sha256, .. } => is_hex(sha256, 64),
            Self::HfCommitPath {
                endpoint,
                repo,
                commit,
                path,
                ..
            } => {
                !endpoint.is_empty()
                    && !repo.is_empty()
                    && !path.is_empty()
                    && (is_hex(commit, 40) || is_hex(commit, 64))
            }
            Self::StrongEtag { resource, etag, .. } => {
                !resource.is_empty() && Self::is_strong_etag(etag)
            }
            Self::ObjectVersion {
                resource, version, ..
            } => !resource.is_empty() && !version.is_empty(),
        };
        if !valid {
            return None;
        }
        let encoded = serde_json::to_vec(&(self, chunk_size)).ok()?;
        Some(crate::sha256_hex(&encoded))
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Clone, Debug)]
pub struct RangeCache {
    dir: PathBuf,
    cap: u64,
    chunk_size: u64,
    budget: SharedBudget,
}

#[derive(Serialize, Deserialize)]
struct RangeHeader {
    len: u64,
    last_hit: u64,
    sha256: String,
}

impl RangeCache {
    /// Uses the payload cap and a range-v1 sibling of the payload directory.
    pub fn from_env() -> Option<Self> {
        let cap = crate::payload_cache::cache_budget()?;
        let payload = crate::payload_v1_dir();
        let dir = payload.with_file_name("range-v1");
        Some(Self::with_dirs(
            dir,
            payload,
            cap,
            RANGE_CACHE_CHUNK_DEFAULT,
        ))
    }

    /// Explicit roots for embedders/tests. Both caches must use the same payload root.
    /// A zero cap disables reads and writes; chunk size must be nonzero.
    pub fn with_dirs(dir: PathBuf, payload_dir: PathBuf, cap: u64, chunk_size: u64) -> Self {
        assert!(chunk_size > 0 && chunk_size <= usize::MAX as u64);
        let budget = SharedBudget::new(payload_dir, dir.clone());
        Self {
            dir,
            cap,
            chunk_size,
            budget,
        }
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn is_enabled(&self) -> bool {
        self.cap > 0
    }

    fn base(&self, token: &ContentToken) -> Option<PathBuf> {
        if !self.is_enabled() {
            return None;
        }
        let key = token.key(self.chunk_size)?;
        Some(self.dir.join(&key[..2]).join(key))
    }

    fn chunk_len(&self, token: &ContentToken, chunk: u64) -> Option<u64> {
        let start = chunk.checked_mul(self.chunk_size)?;
        (start < token.size()).then(|| self.chunk_size.min(token.size() - start))
    }

    fn path(base: &Path, suffix: impl std::fmt::Display) -> PathBuf {
        base.with_file_name(format!(
            "{}.{}",
            base.file_name().unwrap().to_string_lossy(),
            suffix
        ))
    }

    fn open(&self, path: &Path, expected: u64) -> Option<File> {
        check_cache_dirs(&self.dir, path.parent()?).ok()?;
        let file = open_regular(path).ok()?;
        (file.metadata().ok()?.len() == expected).then_some(file)
    }

    fn header(&self, path: &Path) -> Option<RangeHeader> {
        let file = open_regular(&header_path(path)).ok()?;
        let mut bytes = Vec::new();
        file.take(8192).read_to_end(&mut bytes).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn touch(&self, path: &Path, mut hdr: RangeHeader) {
        let now = timestamp();
        self.budget.touch(path, hdr.len, now);
        // Model loading can read 4 KiB pages: keep exact in-process recency but
        // avoid syncing a header on every page. Cross-process recency is coarse.
        if now.saturating_sub(hdr.last_hit) >= TOUCH_INTERVAL_NANOS {
            hdr.last_hit = now;
            let _ = write_header(path, &hdr);
        }
    }

    /// Check for an intact published chunk without loading it into RAM.
    pub fn contains(&self, token: &ContentToken, chunk: u64) -> bool {
        let Some(base) = self.base(token) else {
            return false;
        };
        let Some(len) = self.chunk_len(token, chunk) else {
            return false;
        };
        [
            (Self::path(&base, "complete"), token.size()),
            (Self::path(&base, chunk), len),
        ]
        .iter()
        .any(|(path, size)| {
            self.open(path, *size).is_some()
                && self.header(path).is_some_and(|hdr| hdr.len == *size)
        })
    }

    /// Read a slice from one cached chunk, avoiding a 4 MiB allocation on small reads.
    pub fn read_into(&self, token: &ContentToken, offset: u64, buf: &mut [u8]) -> Option<usize> {
        let base = self.base(token)?;
        let chunk = offset / self.chunk_size;
        let len = self.chunk_len(token, chunk)?;
        let whole = Self::path(&base, "complete");
        let (path, mut file, seek, expected) = match self.open(&whole, token.size()) {
            Some(file) => (whole, file, offset, token.size()),
            None => {
                let path = Self::path(&base, chunk);
                let file = self.open(&path, len)?;
                (path, file, offset % self.chunk_size, len)
            }
        };
        let hdr = self.header(&path)?;
        if hdr.len != expected {
            return None;
        }
        let n = buf.len().min((len - offset % self.chunk_size) as usize);
        file.seek(SeekFrom::Start(seek)).ok()?;
        file.read_exact(&mut buf[..n]).ok()?;
        self.touch(&path, hdr);
        Some(n)
    }

    /// Read one exact, verified-size chunk. Torn files and symlinks are misses.
    pub fn get(&self, token: &ContentToken, chunk: u64) -> Option<Vec<u8>> {
        let base = self.base(token)?;
        let len = self.chunk_len(token, chunk)?;
        let whole = Self::path(&base, "complete");
        if let Some(mut file) = self.open(&whole, token.size()) {
            let hdr = self.header(&whole)?;
            if hdr.len != token.size() {
                return None;
            }
            file.seek(SeekFrom::Start(chunk * self.chunk_size)).ok()?;
            let mut data = vec![0; len as usize];
            file.read_exact(&mut data).ok()?;
            self.touch(&whole, hdr);
            return Some(data);
        }
        let path = Self::path(&base, chunk);
        let mut file = self.open(&path, len)?;
        let hdr = self.header(&path)?;
        if hdr.len != len {
            return None;
        }
        let mut data = vec![0; len as usize];
        file.read_exact(&mut data).ok()?;
        if crate::sha256_hex(&data) != hdr.sha256 {
            return None;
        }
        self.touch(&path, hdr);
        Some(data)
    }

    /// Publish only a complete aligned chunk. Complete files replace their chunks
    /// with a contiguous file, counting the bytes once against the shared cap.
    pub fn put(&self, token: &ContentToken, chunk: u64, bytes: &[u8]) -> io::Result<()> {
        let base = self
            .base(token)
            .ok_or_else(|| io::Error::other("range cache disabled or invalid token"))?;
        let len = self
            .chunk_len(token, chunk)
            .ok_or_else(|| io::Error::other("invalid chunk index"))?;
        if len != bytes.len() as u64 || len > self.cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "short or oversized range cache chunk",
            ));
        }
        ensure_cache_dirs(&self.dir, base.parent().unwrap())?;
        let whole = Self::path(&base, "complete");
        if self.open(&whole, token.size()).is_some()
            && self
                .header(&whole)
                .is_some_and(|hdr| hdr.len == token.size())
        {
            return Ok(());
        }
        let path = Self::path(&base, chunk);
        let mut tmp = temporary(path.parent().unwrap())?;
        tmp.write_all(bytes)?;
        tmp.as_file().sync_all()?;
        write_header(
            &path,
            &RangeHeader {
                len,
                last_hit: timestamp(),
                sha256: crate::sha256_hex(bytes),
            },
        )?;
        tmp.persist(&path).map_err(|e| e.error)?;
        self.budget.install(&path, len, self.cap, &[])?;
        // A concurrent assembler may have finished after our initial check.
        if self.open(&whole, token.size()).is_some()
            && self
                .header(&whole)
                .is_some_and(|hdr| hdr.len == token.size())
        {
            self.budget.remove(&path);
            return Ok(());
        }
        if token.size() <= self.cap
            && self.budget.chunk_count(&base) == token.size().div_ceil(self.chunk_size)
        {
            let _ = self.complete_file(token);
        }
        Ok(())
    }

    /// Returns a contiguous file only when every chunk is present. A caller should
    /// open it promptly: another cache writer may evict this path after return.
    pub fn complete_file(&self, token: &ContentToken) -> Option<PathBuf> {
        let base = self.base(token)?;
        if token.size() > self.cap {
            return None;
        }
        let whole = Self::path(&base, "complete");
        if self.open(&whole, token.size()).is_some() {
            if let Some(hdr) = self.header(&whole).filter(|hdr| hdr.len == token.size()) {
                self.touch(&whole, hdr);
                return Some(whole);
            }
        }
        ensure_cache_dirs(&self.dir, base.parent()?).ok()?;
        let mut tmp = temporary(base.parent()?).ok()?;
        let mut hasher = Sha256::new();
        let mut chunks = Vec::new();
        let mut scratch = [0; 64 * 1024];
        for chunk in 0..token.size().div_ceil(self.chunk_size) {
            let path = Self::path(&base, chunk);
            let len = self.chunk_len(token, chunk)?;
            let mut file = self.open(&path, len)?;
            let hdr = self.header(&path)?;
            if hdr.len != len {
                return None;
            }
            let mut chunk_hash = Sha256::new();
            let mut remaining = len;
            while remaining > 0 {
                let take = remaining.min(scratch.len() as u64) as usize;
                file.read_exact(&mut scratch[..take]).ok()?;
                hasher.update(&scratch[..take]);
                chunk_hash.update(&scratch[..take]);
                tmp.write_all(&scratch[..take]).ok()?;
                remaining -= take as u64;
            }
            if format!("{:x}", chunk_hash.finalize()) != hdr.sha256 {
                return None;
            }
            chunks.push(path);
        }
        let sha256 = format!("{:x}", hasher.finalize());
        if let ContentToken::Sha256 {
            sha256: expected, ..
        } = token
        {
            if !expected.eq_ignore_ascii_case(&sha256) {
                for path in chunks {
                    self.budget.remove(&path);
                }
                return None;
            }
        }
        tmp.as_file().sync_all().ok()?;
        write_header(
            &whole,
            &RangeHeader {
                len: token.size(),
                last_hit: timestamp(),
                sha256,
            },
        )
        .ok()?;
        tmp.persist(&whole).ok()?;
        self.budget
            .install(&whole, token.size(), self.cap, &chunks)
            .ok()?;
        Some(whole)
    }
}

pub(crate) fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub(crate) fn header_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.hdr",
        path.file_name().unwrap().to_string_lossy()
    ))
}

pub(crate) fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::other("cache directory is not a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn ensure_cache_dirs(root: &Path, fan: &Path) -> io::Result<()> {
    ensure_private_dir(root)?;
    ensure_private_dir(fan)
}

fn check_cache_dirs(root: &Path, fan: &Path) -> io::Result<()> {
    for path in [root, fan] {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(io::Error::other("cache directory is not a real directory"));
        }
    }
    Ok(())
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::other("cache entry is not a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("cache entry is not regular"));
    }
    Ok(file)
}

pub(crate) fn temporary(dir: &Path) -> io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new().prefix(".tmp-").tempfile_in(dir)
}

fn write_header(path: &Path, hdr: &RangeHeader) -> io::Result<()> {
    let mut tmp = temporary(path.parent().unwrap())?;
    serde_json::to_writer(&mut tmp, hdr)?;
    tmp.as_file().sync_all()?;
    tmp.persist(header_path(path)).map_err(|e| e.error)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct SharedBudget(Arc<Mutex<Accounting>>);

#[derive(Debug)]
struct Accounting {
    roots: [PathBuf; 2],
    entries: HashMap<PathBuf, (u64, u64)>,
    lru: BTreeSet<(u64, PathBuf)>,
    chunks: HashMap<PathBuf, u64>,
    used: u64,
    reconciled: Option<Instant>,
}

type BudgetRegistry = HashMap<[PathBuf; 2], Arc<Mutex<Accounting>>>;

impl SharedBudget {
    pub(crate) fn for_payload(dir: &Path) -> Self {
        Self::new(dir.to_path_buf(), dir.with_file_name("range-v1"))
    }

    fn new(payload: PathBuf, range: PathBuf) -> Self {
        static REGISTRY: OnceLock<Mutex<BudgetRegistry>> = OnceLock::new();
        let roots = [payload, range];
        let mut registry = REGISTRY
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Self(Arc::clone(registry.entry(roots.clone()).or_insert_with(
            || {
                Arc::new(Mutex::new(Accounting {
                    roots,
                    entries: HashMap::new(),
                    lru: BTreeSet::new(),
                    chunks: HashMap::new(),
                    used: 0,
                    reconciled: None,
                }))
            },
        )))
    }

    pub(crate) fn touch(&self, path: &Path, len: u64, hit: u64) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // A reader may have opened the inode just before another thread evicted
        // it. Do not reintroduce its now-absent path into the accounting.
        if fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() == len) {
            state.record(path.to_path_buf(), len, hit);
        }
    }

    fn chunk_count(&self, base: &Path) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .chunks
            .get(base)
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn remove(&self, path: &Path) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .delete(path);
    }

    pub(crate) fn install(
        &self,
        path: &Path,
        len: u64,
        cap: u64,
        replaced: &[PathBuf],
    ) -> io::Result<()> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.reconcile()?;
        if !fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() == len) {
            return Ok(());
        }
        for old in replaced {
            state.delete(old);
        }
        state.record(path.to_path_buf(), len, timestamp());
        while state.used > cap {
            let Some((_, oldest)) = state.lru.first().cloned() else {
                break;
            };
            if !state.delete(&oldest) {
                break;
            }
        }
        Ok(())
    }
}

impl Accounting {
    fn chunk_base(path: &Path) -> Option<PathBuf> {
        let name = path.file_name()?.to_str()?;
        let (key, index) = name.split_once('.')?;
        if !is_hex(key, 64) || index.parse::<u64>().is_err() {
            return None;
        }
        Some(path.with_file_name(key))
    }

    fn forget(&mut self, path: &Path) {
        if let Some((len, hit)) = self.entries.remove(path) {
            self.used = self.used.saturating_sub(len);
            self.lru.remove(&(hit, path.to_path_buf()));
            if let Some(base) = Self::chunk_base(path) {
                if let Some(count) = self.chunks.get_mut(&base) {
                    *count -= 1;
                    if *count == 0 {
                        self.chunks.remove(&base);
                    }
                }
            }
        }
    }

    fn record(&mut self, path: PathBuf, len: u64, hit: u64) {
        self.forget(&path);
        self.used = self.used.saturating_add(len);
        self.lru.insert((hit, path.clone()));
        if let Some(base) = Self::chunk_base(&path) {
            *self.chunks.entry(base).or_default() += 1;
        }
        self.entries.insert(path, (len, hit));
    }

    fn delete(&mut self, path: &Path) -> bool {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
        let _ = fs::remove_file(header_path(path));
        self.forget(path);
        true
    }

    fn reconcile(&mut self) -> io::Result<()> {
        if self
            .reconciled
            .is_some_and(|last| last.elapsed() < RECONCILE_INTERVAL)
        {
            return Ok(());
        }
        self.entries.clear();
        self.lru.clear();
        self.chunks.clear();
        self.used = 0;
        for root in self.roots.clone() {
            let fans = match fs::read_dir(&root) {
                Ok(fans) if fs::symlink_metadata(&root)?.is_dir() => fans,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for fan in fans.flatten() {
                if !fan.file_type().is_ok_and(|kind| kind.is_dir())
                    || !is_hex(&fan.file_name().to_string_lossy(), 2)
                {
                    continue;
                }
                for entry in fs::read_dir(fan.path())?.flatten() {
                    if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                        continue;
                    }
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let path = entry.path();
                    let Ok(meta) = entry.metadata() else {
                        continue;
                    };
                    if name.starts_with(".tmp-")
                        || name.contains(".tmp.")
                        || name.ends_with(".part")
                    {
                        if meta
                            .modified()
                            .ok()
                            .and_then(|t| t.elapsed().ok())
                            .is_some_and(|age| age > TEMP_MAX_AGE)
                        {
                            let _ = fs::remove_file(path);
                        }
                        continue;
                    }
                    let key = name.split('.').next().unwrap_or("");
                    if !is_hex(key, 64) || name.ends_with(".hdr") {
                        continue;
                    }
                    let hit = open_regular(&header_path(&path))
                        .ok()
                        .and_then(|file| {
                            serde_json::from_reader::<_, serde_json::Value>(file.take(8192)).ok()
                        })
                        .and_then(|v| v.get("last_hit").and_then(|v| v.as_u64()))
                        .unwrap_or(0);
                    self.record(path, meta.len(), hit);
                }
            }
        }
        self.reconciled = Some(Instant::now());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PayloadCache;
    use std::io::Cursor;

    fn cache(dir: &Path, cap: u64) -> RangeCache {
        RangeCache::with_dirs(dir.join("range-v1"), dir.join("payload-v1"), cap, 4)
    }

    fn token(label: &str, size: u64) -> ContentToken {
        ContentToken::StrongEtag {
            resource: "https://example.test/model".into(),
            etag: format!("\"{label}\""),
            size,
        }
    }

    /// Regression: repeat range reads must survive reopening the disk cache.
    #[test]
    fn regression_range_cache_second_open_and_wrong_token() {
        let dir = tempfile::tempdir().unwrap();
        let first = cache(dir.path(), 100);
        let id = token("v1", 10);
        first.put(&id, 0, b"abcd").unwrap();
        first.put(&id, 2, b"ij").unwrap();
        assert!(first.complete_file(&id).is_none());
        first.put(&id, 1, b"efgh").unwrap();
        let second = cache(dir.path(), 100);
        assert_eq!(second.get(&id, 0).unwrap(), b"abcd");
        assert_eq!(second.get(&id, 2).unwrap(), b"ij");
        let whole = second.complete_file(&id).unwrap();
        assert_eq!(fs::read(&whole).unwrap(), b"abcdefghij");
        let base = first.base(&id).unwrap();
        assert!(
            !RangeCache::path(&base, 0).exists(),
            "completion must replace chunks, not double disk usage"
        );
        assert_eq!(second.budget.0.lock().unwrap().used, 10);
        assert!(second.get(&token("v2", 10), 0).is_none());
        let other = ContentToken::StrongEtag {
            resource: "https://other.test/model".into(),
            etag: "\"v1\"".into(),
            size: 10,
        };
        assert!(
            second.get(&other, 0).is_none(),
            "ETag scope must include the resource"
        );
    }

    /// Regression: payload and range stores used independent caps and rescanned on every write.
    #[test]
    fn regression_range_cache_shared_payload_lru_and_zero_cap() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 8);
        let payload = PayloadCache::with_dir(dir.path().join("payload-v1"), Some(8), 8);
        let id = token("big", 12);
        range.put(&id, 0, b"aaaa").unwrap();
        let digest = crate::sha256_hex(b"bbbb");
        let blob = payload
            .install_from_reader(&digest, 4, &mut Cursor::new(b"bbbb"))
            .unwrap();
        assert_eq!(range.get(&id, 0).unwrap(), b"aaaa"); // range is newer than payload
        range.put(&id, 1, b"cccc").unwrap();
        assert!(
            !blob.exists(),
            "range installation must evict the oldest payload"
        );
        assert!(range.contains(&id, 0));
        // Accounting stays in process; no reconciliation is needed for this fill.
        let scanned = range.budget.0.lock().unwrap().reconciled;
        payload
            .install_from_reader(&digest, 4, &mut Cursor::new(b"bbbb"))
            .unwrap();
        assert!(
            !range.contains(&id, 0),
            "payload installation must evict the oldest range"
        );
        assert!(range.contains(&id, 1));
        assert_eq!(range.budget.0.lock().unwrap().used, 8);
        assert_eq!(range.budget.0.lock().unwrap().reconciled, scanned);
        assert!(cache(dir.path(), 0).get(&id, 1).is_none());
        assert!(cache(dir.path(), 0).put(&id, 2, b"dddd").is_err());
        let disabled = PayloadCache::with_dir(payload.dir().to_path_buf(), Some(0), 8);
        assert!(!disabled.is_enabled());
        assert!(disabled.lookup(&digest).is_none());
    }

    /// Regression: torn temps, truncated chunks and bad lengths were exposed as valid bytes.
    #[test]
    fn regression_range_cache_torn_temp_truncated_chunk_and_complete() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 100);
        let id = token("v1", 8);
        range.put(&id, 0, b"abcd").unwrap();
        let base = range.base(&id).unwrap();
        let chunk = RangeCache::path(&base, 0);
        fs::write(&chunk, b"ab").unwrap();
        assert!(range.get(&id, 0).is_none());
        assert!(range.read_into(&id, 0, &mut [0; 2]).is_none());
        assert!(!range.contains(&id, 0));
        assert!(range.put(&id, 1, b"short").is_err());
        assert!(range.put(&id, u64::MAX, b"abcd").is_err());
        let mut tmp = temporary(base.parent().unwrap()).unwrap();
        tmp.write_all(b"torn").unwrap();
        // Simulate a process that crashed leaving a temporary file behind.
        let (_, temp_path) = tmp.keep().unwrap();
        let old = SystemTime::now() - TEMP_MAX_AGE - Duration::from_secs(1);
        File::options()
            .write(true)
            .open(&temp_path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        range.budget.0.lock().unwrap().reconciled = None;
        range.budget.0.lock().unwrap().reconcile().unwrap();
        assert!(
            !temp_path.exists(),
            "periodic reconciliation reclaims abandoned temps"
        );
        assert!(range.get(&id, 1).is_none());
        range.put(&id, 0, b"abcd").unwrap();
        range.put(&id, 1, b"efgh").unwrap();
        let whole = range.complete_file(&id).unwrap();
        fs::remove_file(header_path(&whole)).unwrap();
        assert!(
            range.get(&id, 0).is_none(),
            "missing completion header must be a miss"
        );
        range.put(&id, 0, b"abcd").unwrap();
        range.put(&id, 1, b"efgh").unwrap();
        assert_eq!(
            fs::read(range.complete_file(&id).unwrap()).unwrap(),
            b"abcdefgh"
        );
        fs::write(&whole, b"abc").unwrap();
        assert!(range.get(&id, 0).is_none());
        assert!(range.complete_file(&id).is_none());
    }

    /// Regression: a cache symlink must never supply bytes or overwrite its target.
    #[cfg(unix)]
    #[test]
    fn regression_range_cache_symlink_chunk_header_and_directory() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 100);
        let id = token("v1", 8);
        range.put(&id, 0, b"abcd").unwrap();
        let base = range.base(&id).unwrap();
        let chunk = RangeCache::path(&base, 0);
        let outside = dir.path().join("outside");
        fs::write(&outside, b"evil").unwrap();
        fs::remove_file(&chunk).unwrap();
        symlink(&outside, &chunk).unwrap();
        assert!(range.get(&id, 0).is_none());
        range.put(&id, 0, b"abcd").unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"evil");
        let hdr = header_path(&chunk);
        let saved = dir.path().join("header");
        fs::rename(&hdr, &saved).unwrap();
        symlink(&saved, &hdr).unwrap();
        assert!(range.get(&id, 0).is_none());
        let fan = base.parent().unwrap();
        let renamed = dir.path().join("fan");
        fs::rename(fan, &renamed).unwrap();
        symlink(&renamed, fan).unwrap();
        assert!(range.get(&id, 0).is_none());
        assert!(range.put(&id, 1, b"efgh").is_err());
        let permissions = fs::metadata(&range.dir).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(permissions.mode() & 0o777, 0o700);
    }

    /// Regression: simultaneous installs must not share temporary/header filenames.
    #[test]
    fn regression_range_cache_concurrent_fill_without_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 100);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let range = range.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let id = token("v1", 8);
                    barrier.wait();
                    for _ in 0..10 {
                        range.put(&id, 0, b"abcd").unwrap();
                        range.put(&id, 1, b"efgh").unwrap();
                        assert_eq!(range.get(&id, 0).unwrap(), b"abcd");
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(
            fs::read(range.complete_file(&token("v1", 8)).unwrap()).unwrap(),
            b"abcdefgh"
        );
    }

    /// Regression: unverifiable tokens and a completed SHA-256 mismatch cannot be reused.
    #[test]
    fn regression_range_cache_rejects_weak_identity_and_sha256_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 100);
        for etag in ["W/\"weak\"", "unquoted", "\"bad\nvalue\""] {
            let id = ContentToken::StrongEtag {
                resource: "https://example.test".into(),
                etag: etag.into(),
                size: 4,
            };
            assert!(range.put(&id, 0, b"abcd").is_err());
        }
        let id = ContentToken::Sha256 {
            sha256: crate::sha256_hex(b"abcdefgh"),
            size: 8,
        };
        range.put(&id, 0, b"abcd").unwrap();
        range.put(&id, 1, b"xxxx").unwrap();
        assert!(range.complete_file(&id).is_none());
        assert!(range.get(&id, 0).is_none());
        range.put(&id, 0, b"abcd").unwrap();
        range.put(&id, 1, b"efgh").unwrap();
        assert!(range.complete_file(&id).is_some());
    }

    /// Regression: eviction may unlink a file, but must preserve already open readers.
    #[cfg(unix)]
    #[test]
    fn regression_range_cache_eviction_preserves_open_reader() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 4);
        let id = token("v1", 4);
        range.put(&id, 0, b"abcd").unwrap();
        let mut held = File::open(range.complete_file(&id).unwrap()).unwrap();
        range.put(&token("v2", 4), 0, b"efgh").unwrap();
        assert!(range.get(&id, 0).is_none());
        let mut bytes = Vec::new();
        held.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcd");
    }
    /// Regression: the shared environment cap must disable both stores, including lookups.
    #[test]
    fn regression_range_cache_env_zero_disables_both_and_override_roots_match() {
        let _guard = crate::meta_cache::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let old_cap = std::env::var_os(crate::PAYLOAD_CACHE_BYTES_ENV);
        let old_dir = std::env::var_os(crate::PAYLOAD_CACHE_DIR_ENV);
        std::env::set_var(crate::PAYLOAD_CACHE_BYTES_ENV, "0");
        std::env::set_var(crate::PAYLOAD_CACHE_DIR_ENV, dir.path().join("payload-v1"));
        let disabled_range = RangeCache::from_env().is_none();
        let disabled_payload = PayloadCache::from_env_for_index(false).is_none();
        std::env::set_var(crate::PAYLOAD_CACHE_BYTES_ENV, "8");
        let range = RangeCache::from_env().unwrap();
        let payload = PayloadCache::from_env_for_index(false).unwrap();
        for (name, previous) in [
            (crate::PAYLOAD_CACHE_BYTES_ENV, old_cap),
            (crate::PAYLOAD_CACHE_DIR_ENV, old_dir),
        ] {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        assert!(disabled_range && disabled_payload);
        assert_eq!(range.dir(), dir.path().join("range-v1"));
        assert_eq!(payload.dir(), dir.path().join("payload-v1"));
        assert!(Arc::ptr_eq(
            &range.budget.0,
            &SharedBudget::for_payload(payload.dir()).0
        ));
    }

    /// Regression: other processes' payload/range installs must join the LRU at reconciliation.
    #[test]
    fn regression_range_cache_reconciliation_imports_both_stores() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 8);
        let id = token("v1", 12);
        range.put(&id, 0, b"abcd").unwrap();
        let scanned = range.budget.0.lock().unwrap().reconciled;
        // Simulate a different process publishing a payload without this registry.
        let key = crate::sha256_hex(b"old!");
        let path = dir.path().join("payload-v1").join(&key[..2]).join(&key);
        ensure_private_dir(path.parent().unwrap()).unwrap();
        fs::write(&path, b"old!").unwrap();
        fs::write(header_path(&path), br#"{"len":4,"last_hit":1}"#).unwrap();
        range.budget.0.lock().unwrap().reconciled = Some(Instant::now() - RECONCILE_INTERVAL);
        range.put(&id, 1, b"efgh").unwrap();
        assert!(
            !path.exists(),
            "old foreign payload must count toward the shared cap"
        );
        let state = range.budget.0.lock().unwrap();
        assert_eq!(state.used, 8);
        assert_ne!(state.reconciled, scanned);
    }
    /// Regression: hot page reads must update LRU without fsyncing a header for each page.
    #[test]
    fn regression_range_cache_hot_reads_batch_disk_recency_updates() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 100);
        let id = token("v1", 8);
        range.put(&id, 0, b"abcd").unwrap();
        let path = RangeCache::path(&range.base(&id).unwrap(), 0);
        let initial = range.header(&path).unwrap().last_hit;
        for _ in 0..20 {
            assert_eq!(range.read_into(&id, 1, &mut [0; 1]), Some(1));
        }
        assert_eq!(range.header(&path).unwrap().last_hit, initial);
        assert!(range.budget.0.lock().unwrap().entries[&path].1 > initial);
        let mut hdr = range.header(&path).unwrap();
        hdr.last_hit = 0;
        write_header(&path, &hdr).unwrap();
        assert_eq!(range.get(&id, 0).unwrap(), b"abcd");
        assert!(range.header(&path).unwrap().last_hit >= initial);
    }
}
