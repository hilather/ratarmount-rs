//! Verified remote bytes in aligned chunks, sharing the payload-v1 disk budget.
//!
//! Publication is a synced temporary file followed by rename. Cache failures are
//! misses. Open readers survive eviction on Unix. There is no interprocess lock:
//! other writers are reconciled periodically, so concurrent processes may briefly
//! exceed the cap. Private directories and no-follow opens protect cache paths.

use std::collections::{BTreeSet, HashMap, HashSet};
#[cfg_attr(
    internal_read_inventory,
    expect(
        clippy::disallowed_types,
        reason = r###"internal-read:v1 {"id":"IR-E0080-T01","item":"ratarmount_index::range_cache","disposition":"support","category":"builder-type-support","reason":"Builder type support: Import OpenOptions for the range cache no-follow input/output helpers.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
    )
)]
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default aligned remote chunk size (4 MiB).
pub const RANGE_CACHE_CHUNK_DEFAULT: u64 = 4 * 1024 * 1024;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);
const TEMP_MAX_AGE: Duration = Duration::from_secs(3600);
const MAX_HEADER_BYTES: u64 = 64 * 1024 * 1024;
const TOUCH_INTERVAL_NANOS: u64 = 5_000_000_000;

/// Identity verified by the caller against remote metadata, never a URL alone.
///
/// ETags and object versions are scoped to their resource (canonical origin URL
/// or object-store resource). Hub commits must be resolved immutable hex IDs,
/// not branch names. SHA-256 tokens additionally verify the assembled whole file.
#[derive(Clone, Debug, Serialize)]
pub enum ContentToken {
    /// A complete piece verified against metainfo before publication. For v2,
    /// `file` is the path in the file tree and `piece` is relative to that file.
    TorrentPiece {
        infohash: String,
        file: Option<String>,
        piece: u64,
        size: u64,
    },
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
    VerifiedSha256 {
        token: Box<ContentToken>,
        sha256: String,
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
            Self::VerifiedSha256 { token, .. } => token.size(),
            Self::Sha256 { size, .. }
            | Self::TorrentPiece { size, .. }
            | Self::HfCommitPath { size, .. }
            | Self::StrongEtag { size, .. }
            | Self::ObjectVersion { size, .. } => *size,
        }
    }

    /// Add an independently supplied whole-file digest without losing the backend identity.
    pub fn with_sha256(self, sha256: String) -> Self {
        Self::VerifiedSha256 {
            token: Box::new(self),
            sha256,
        }
    }

    fn expected_sha256(&self) -> Option<&str> {
        match self {
            Self::Sha256 { sha256, .. } | Self::VerifiedSha256 { sha256, .. } => Some(sha256),
            _ => None,
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
            Self::TorrentPiece { infohash, .. } => is_hex(infohash, 40) || is_hex(infohash, 64),
            Self::VerifiedSha256 { token, sha256 } => {
                is_hex(sha256, 64) && token.key(chunk_size).is_some()
            }
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

type VerifiedChunks = HashMap<(PathBuf, u64, String), FileStamp>;
type CachedHeaders = HashMap<PathBuf, (FileStamp, Arc<RangeHeader>)>;

#[derive(Clone, Debug)]
pub struct RangeCache {
    dir: PathBuf,
    root: PathBuf,
    cap: u64,
    chunk_size: u64,
    budget: SharedBudget,
    verified: Arc<Mutex<VerifiedChunks>>,
    headers: Arc<Mutex<CachedHeaders>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RangeHeader {
    len: u64,
    last_hit: u64,
    sha256: String,
    #[serde(default)]
    chunk_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64, i64, i64),
}

fn file_stamp(file: &File) -> io::Result<FileStamp> {
    let meta = file.metadata()?;
    Ok(FileStamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        #[cfg(unix)]
        unix: {
            use std::os::unix::fs::MetadataExt;
            (
                meta.dev(),
                meta.ino(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec(),
            )
        },
    })
}

impl RangeCache {
    /// Uses the shared payload cap and range-v1 inside the payload cache directory.
    pub fn from_env() -> Option<Self> {
        let cap = crate::payload_cache::cache_budget()?;
        let payload = crate::payload_v1_dir();
        let dir = payload.join("range-v1");
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
        let root = payload_dir.clone();
        let budget = SharedBudget::new(payload_dir, dir.clone());
        Self {
            dir,
            root,
            cap,
            chunk_size,
            budget,
            verified: Arc::default(),
            headers: Arc::default(),
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
        check_private_dir(&self.root).ok()?;
        check_cache_dirs(&self.dir, path.parent()?).ok()?;
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0463-M01","item":"<ratarmount_index::range_cache::RangeCache>::open","disposition":"residual","reason":"range-cache completion owner, header or recency read; needs broader lifecycle work","family":"range-cache","issue":"#196","category":"range-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        let file = open_regular(path).ok()?;
        (file.metadata().ok()?.len() == expected).then_some(file)
    }

    fn header(&self, path: &Path) -> Option<Arc<RangeHeader>> {
        let hdr_path = header_path(path);
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0464-M01","item":"<ratarmount_index::range_cache::RangeCache>::header","disposition":"residual","reason":"range-cache completion owner, header or recency read; needs broader lifecycle work","family":"range-cache","issue":"#196","category":"range-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        let file = open_regular(&hdr_path).ok()?;
        let stamp = file_stamp(&file).ok()?;
        if let Some((_, header)) = self
            .headers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .filter(|(old, _)| *old == stamp)
        {
            return Some(Arc::clone(header));
        }
        let header: RangeHeader = serde_json::from_reader(file.take(MAX_HEADER_BYTES)).ok()?;
        let header = Arc::new(header);
        let mut headers = self.headers.lock().unwrap_or_else(|e| e.into_inner());
        if headers.len() >= 128 {
            headers.clear();
        }
        headers.insert(path.to_path_buf(), (stamp, Arc::clone(&header)));
        Some(header)
    }

    fn touch(&self, path: &Path, len: u64) {
        self.budget.touch(path, len, timestamp());
    }

    fn memo_matches(&self, key: &(PathBuf, u64, String), stamp: &FileStamp) -> bool {
        #[cfg(unix)]
        {
            self.verified
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(key)
                == Some(stamp)
        }
        #[cfg(not(unix))]
        {
            // Without inode/ctime identity, restored mtimes could hide changes.
            let _ = (key, stamp);
            false
        }
    }

    fn verified_chunk(
        &self,
        token: &ContentToken,
        chunk: u64,
    ) -> Option<(File, u64, PathBuf, u64)> {
        let base = self.base(token)?;
        let len = self.chunk_len(token, chunk)?;
        let whole = Self::path(&base, "complete");
        let (mut file, offset, path, expected_len) = match self.open(&whole, token.size()) {
            Some(file) => (file, chunk * self.chunk_size, whole, token.size()),
            None => {
                let path = Self::path(&base, chunk);
                (self.open(&path, len)?, 0, path, len)
            }
        };
        let hdr = self.header(&path)?;
        if hdr.len != expected_len {
            return None;
        }
        let (verify_offset, verify_len, expected, memo_chunk) = if expected_len == token.size()
            && path.extension().is_some_and(|ext| ext == "complete")
        {
            match hdr.chunk_hashes.get(chunk as usize) {
                Some(hash) => (offset, len, hash.as_str(), chunk),
                None => (0, token.size(), hdr.sha256.as_str(), u64::MAX),
            }
        } else {
            (0, len, hdr.sha256.as_str(), chunk)
        };
        let stamp = file_stamp(&file).ok()?;
        let memo_key = (path.clone(), memo_chunk, expected.to_string());
        let verified = self.memo_matches(&memo_key, &stamp)
            || (path.extension().is_some_and(|ext| ext == "complete")
                && self.memo_matches(&(path.clone(), u64::MAX, hdr.sha256.clone()), &stamp));
        if !verified {
            file.seek(SeekFrom::Start(verify_offset)).ok()?;
            let mut hasher = Sha256::new();
            let mut scratch = [0; 64 * 1024];
            let mut remaining = verify_len;
            while remaining > 0 {
                let n = remaining.min(scratch.len() as u64) as usize;
                file.read_exact(&mut scratch[..n]).ok()?;
                hasher.update(&scratch[..n]);
                remaining -= n as u64;
            }
            if format!("{:x}", hasher.finalize()) != expected {
                return None;
            }
            let after = file_stamp(&file).ok()?;
            if after != stamp {
                #[cfg(unix)]
                let unlinked = {
                    use std::os::unix::fs::MetadataExt;
                    file.metadata().ok()?.nlink() == 0
                        && after.len == stamp.len
                        && after.modified == stamp.modified
                };
                #[cfg(not(unix))]
                let unlinked = false;
                if !unlinked {
                    return None;
                }
            }
            let mut memo = self.verified.lock().unwrap_or_else(|e| e.into_inner());
            if memo.len() >= 1024 {
                memo.clear();
            }
            memo.insert(memo_key, file_stamp(&file).ok()?);
        }
        Some((file, offset, path, hdr.len))
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

    /// Verify the containing chunk before returning a slice. Immutable file
    /// fingerprints memoize verification so page reads do not rehash 4 MiB each.
    pub fn read_into(&self, token: &ContentToken, offset: u64, buf: &mut [u8]) -> Option<usize> {
        let chunk = offset / self.chunk_size;
        let len = self.chunk_len(token, chunk)?;
        let (mut file, first, path, disk_len) = self.verified_chunk(token, chunk)?;
        let relative = offset % self.chunk_size;
        let n = buf.len().min((len - relative) as usize);
        file.seek(SeekFrom::Start(first + relative)).ok()?;
        file.read_exact(&mut buf[..n]).ok()?;
        self.touch(&path, disk_len);
        Some(n)
    }

    /// Return one checksum-verified chunk; corruption and symlinks are misses.
    pub fn get(&self, token: &ContentToken, chunk: u64) -> Option<Vec<u8>> {
        let len = self.chunk_len(token, chunk)?;
        let (mut file, offset, path, disk_len) = self.verified_chunk(token, chunk)?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut data = vec![0; len as usize];
        file.read_exact(&mut data).ok()?;
        self.touch(&path, disk_len);
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
        ensure_private_dir(&self.root)?;
        ensure_cache_dirs(&self.dir, base.parent().unwrap())?;
        let whole = Self::path(&base, "complete");
        if fs::symlink_metadata(&whole).is_ok() {
            if self.verified_chunk(token, chunk).is_some() {
                return Ok(());
            }
            // A checksum miss must be repairable; metadata alone cannot make
            // a corrupt completed file suppress every subsequent refill.
            self.budget.remove(&whole);
        }
        let small = token.size() <= self.chunk_size;
        let path = if small {
            whole.clone()
        } else {
            Self::path(&base, chunk)
        };
        let digest = crate::sha256_hex(bytes);
        if small
            && token
                .expected_sha256()
                .is_some_and(|expected| !expected.eq_ignore_ascii_case(&digest))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "range cache sha256 mismatch",
            ));
        }
        let mut tmp = temporary(path.parent().unwrap())?;
        tmp.write_all(bytes)?;
        tmp.as_file().sync_all()?;
        write_header(
            &path,
            &RangeHeader {
                len,
                last_hit: timestamp(),
                sha256: digest.clone(),
                chunk_hashes: if small { vec![digest] } else { vec![] },
            },
        )?;
        tmp.persist(&path).map_err(|e| e.error)?;
        self.budget.install(&path, len, self.cap, &[])?;
        // A concurrent assembler may have finished after our initial check.
        if !small
            && self.open(&whole, token.size()).is_some()
            && self
                .header(&whole)
                .is_some_and(|hdr| hdr.len == token.size())
        {
            self.budget.remove(&path);
        }
        Ok(())
    }

    /// Drop this identity after its verified bytes have moved to an external cache.
    /// Held readers remain valid on Unix; external blobs do not use this budget.
    pub fn remove_file(&self, token: &ContentToken) {
        let Some(base) = self.base(token) else {
            return;
        };
        self.budget.remove(&Self::path(&base, "complete"));
        for chunk in 0..token.size().div_ceil(self.chunk_size) {
            self.budget.remove(&Self::path(&base, chunk));
        }
    }

    /// Returns a contiguous file only when every chunk is present. A caller should
    /// open it promptly: another cache writer may evict this path after return.
    pub fn complete_file(&self, token: &ContentToken) -> Option<PathBuf> {
        self.complete_with_file(token).map(|(path, _)| path)
    }

    /// Return the descriptor used to verify completion, avoiding a pathname
    /// reopen between verification and passthrough. Its cursor starts at zero.
    pub fn complete_backing_file(&self, token: &ContentToken) -> Option<File> {
        let (_, mut file) = self.complete_with_file(token)?;
        file.seek(SeekFrom::Start(0)).ok()?;
        Some(file)
    }

    fn complete_with_file(&self, token: &ContentToken) -> Option<(PathBuf, File)> {
        let base = self.base(token)?;
        if token.size() > self.cap {
            return None;
        }
        let flight = self.budget.completion_lock(&base);
        let _flight = flight.lock().unwrap_or_else(|e| e.into_inner());
        let whole = Self::path(&base, "complete");
        if let Some(mut file) = self.open(&whole, token.size()) {
            if let Some(hdr) = self.header(&whole).filter(|hdr| hdr.len == token.size()) {
                let stamp = file_stamp(&file).ok()?;
                let key = (whole.clone(), u64::MAX, hdr.sha256.clone());
                let verified = self.memo_matches(&key, &stamp);
                if !verified {
                    let mut hasher = Sha256::new();
                    let mut scratch = [0; 64 * 1024];
                    loop {
                        let n = file.read(&mut scratch).ok()?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&scratch[..n]);
                    }
                    let digest = format!("{:x}", hasher.finalize());
                    if digest != hdr.sha256
                        || token
                            .expected_sha256()
                            .is_some_and(|sha| !sha.eq_ignore_ascii_case(&digest))
                    {
                        return None;
                    }
                    let mut memo = self.verified.lock().unwrap_or_else(|e| e.into_inner());
                    if memo.len() >= 1024 {
                        memo.clear();
                    }
                    memo.insert(key, stamp);
                }
                self.touch(&whole, hdr.len);
                return Some((whole, file));
            }
        }
        ensure_private_dir(&self.root).ok()?;
        ensure_cache_dirs(&self.dir, base.parent()?).ok()?;
        #[cfg(test)]
        self.budget
            .0
            .completed_builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut tmp = temporary(base.parent()?).ok()?;
        let mut hasher = Sha256::new();
        let mut chunks = Vec::new();
        let mut chunk_hashes = Vec::new();
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
            chunk_hashes.push(hdr.sha256.clone());
            chunks.push(path);
        }
        let sha256 = format!("{:x}", hasher.finalize());
        if token
            .expected_sha256()
            .is_some_and(|expected| !expected.eq_ignore_ascii_case(&sha256))
        {
            for path in chunks {
                self.budget.remove(&path);
            }
            return None;
        }
        tmp.as_file().sync_all().ok()?;
        write_header(
            &whole,
            &RangeHeader {
                len: token.size(),
                last_hit: timestamp(),
                sha256,
                chunk_hashes,
            },
        )
        .ok()?;
        let file = tmp.persist(&whole).ok()?;
        let hdr = self.header(&whole)?;
        {
            let stamp = file_stamp(&file).ok()?;
            let mut memo = self.verified.lock().unwrap_or_else(|e| e.into_inner());
            if memo.len() >= 1024 {
                memo.clear();
            }
            memo.insert((whole.clone(), u64::MAX, hdr.sha256.clone()), stamp);
        }
        self.budget
            .install(&whole, token.size(), self.cap, &chunks)
            .ok()?;
        Some((whole, file))
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

#[cfg(unix)]
fn safe_owner_and_mode(owner: u32, current: u32, mode: u32) -> bool {
    owner == current && mode & 0o022 == 0
}

pub(crate) fn check_private_dir(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::other("cache directory is not a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !safe_owner_and_mode(meta.uid(), unsafe { libc::geteuid() }, meta.mode()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cache directory owner or permissions are unsafe",
            ));
        }
    }
    Ok(())
}

pub(crate) fn ensure_private_dir(path: &Path) -> io::Result<()> {
    #[cfg_attr(
        internal_read_inventory,
        expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0081-M01","item":"ratarmount_index::range_cache::ensure_private_dir","disposition":"support","category":"creation-builder","reason":"Construct the builder used to create a private recursive cache directory.","creation":{"policy":"none","basis":"This is setup; the create event separately owns recursive mode-0700 directory creation."}}"###
        )
    )]
    #[cfg_attr(
        internal_read_inventory,
        expect(
            clippy::disallowed_types,
            reason = r###"internal-read:v1 {"id":"IR-E0081-T01","item":"ratarmount_index::range_cache::ensure_private_dir","disposition":"support","category":"builder-type-support","reason":"Builder type support: Construct the builder used to create a private recursive cache directory.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
        )
    )]
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    #[cfg_attr(
        internal_read_inventory,
        expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0082-M01","item":"ratarmount_index::range_cache::ensure_private_dir","disposition":"output-owner","category":"range-cache-directory","reason":"Create the range cache directory tree and validate its owner/private permissions.","creation":{"policy":"private-recursive-directory","basis":"The builder requests 0700 on Unix, check_private_dir validates ownership/mode, and permissions are reset to 0700 afterward."}}"###
        )
    )]
    builder.create(path)?;
    check_private_dir(path)?;
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
    check_private_dir(root)?;
    check_private_dir(fan)
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::other("cache entry is not a regular file"));
    }
    #[cfg_attr(
        internal_read_inventory,
        expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0465-M01","item":"ratarmount_index::range_cache::open_regular","disposition":"support","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","family":"range-cache","issue":"#196","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"residual","baseline_reason":"range-cache completion owner / persisted original open helper"}"###
        )
    )]
    #[cfg_attr(
        internal_read_inventory,
        expect(
            clippy::disallowed_types,
            reason = r###"internal-read:v1 {"id":"IR-B0465-T01","item":"ratarmount_index::range_cache::open_regular","disposition":"support","reason":"Builder type support: range-cache completion owner / persisted original open helper","family":"range-cache","issue":"#196","mode_policy":"unchanged-from-e6ca64e","category":"builder-type-support","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
        )
    )]
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg_attr(
        internal_read_inventory,
        expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0465-M02","item":"ratarmount_index::range_cache::open_regular","disposition":"residual","reason":"range-cache completion owner / persisted original open helper","family":"range-cache","issue":"#196","mode_policy":"unchanged-from-e6ca64e","category":"range-cache","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )
    )]
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("cache entry is not regular"));
    }
    Ok(file)
}

pub(crate) fn temporary(dir: &Path) -> io::Result<tempfile::NamedTempFile> {
    {
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0466-M01","item":"ratarmount_index::range_cache::temporary","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )
        )]
        let __inventory_value_0 = tempfile::Builder::new().prefix(".tmp-").tempfile_in(dir);
        __inventory_value_0
    }
}

fn write_header(path: &Path, hdr: &RangeHeader) -> io::Result<()> {
    let mut tmp = temporary(path.parent().unwrap())?;
    serde_json::to_writer(&mut tmp, hdr)?;
    tmp.as_file().sync_all()?;
    tmp.persist(header_path(path)).map_err(|e| e.error)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct SharedBudget(Arc<BudgetInner>);

#[derive(Debug)]
struct BudgetInner {
    roots: [PathBuf; 2],
    state: Mutex<Accounting>,
    maintenance: Mutex<()>,
    warned: Mutex<HashSet<&'static str>>,
    completions: Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>,
    #[cfg(test)]
    faults: Mutex<IoFaults>,
    #[cfg(test)]
    completed_builds: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct IoFaults {
    unreadable: HashSet<PathBuf>,
    undeletable: HashSet<PathBuf>,
    scan_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    delete_gate: Option<(PathBuf, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
}

impl BudgetInner {
    fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, Accounting>> {
        self.state.lock()
    }
}

#[derive(Debug)]
struct Accounting {
    entries: HashMap<PathBuf, (u64, u64)>,
    lru: BTreeSet<(u64, PathBuf)>,
    used: u64,
    reconciled: Option<Instant>,
    scan_changes: Option<HashSet<PathBuf>>,
    dirty: HashMap<PathBuf, u64>,
    flushed: Instant,
}

type BudgetRegistry = HashMap<[PathBuf; 2], Arc<BudgetInner>>;

impl SharedBudget {
    pub(crate) fn for_payload(dir: &Path) -> Self {
        Self::new(dir.to_path_buf(), dir.join("range-v1"))
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
                Arc::new(BudgetInner {
                    roots,
                    state: Mutex::new(Accounting {
                        entries: HashMap::new(),
                        lru: BTreeSet::new(),
                        used: 0,
                        reconciled: None,
                        scan_changes: None,
                        dirty: HashMap::new(),
                        flushed: Instant::now(),
                    }),
                    maintenance: Mutex::new(()),
                    warned: Mutex::default(),
                    completions: Mutex::default(),
                    #[cfg(test)]
                    faults: Mutex::default(),
                    #[cfg(test)]
                    completed_builds: std::sync::atomic::AtomicUsize::new(0),
                })
            },
        )))
    }

    fn warn_once(&self, kind: &'static str, path: &Path, error: &io::Error) {
        if self
            .0
            .warned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(kind)
        {
            log::warn!("body cache {kind}: {}: {error}", path.display());
        }
    }

    pub(crate) fn touch(&self, path: &Path, len: u64, hit: u64) {
        // Never wait behind maintenance on a page read. Filesystem work also
        // stays outside this short bookkeeping critical section.
        if !fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() == len) {
            return;
        }
        let mut state = match self.0.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        if state.lru.last().is_some_and(|(_, newest)| newest == path)
            && state
                .entries
                .get(path)
                .is_some_and(|(_, previous)| hit.saturating_sub(*previous) < 1_000_000_000)
        {
            return;
        }
        state.record(path.to_path_buf(), len, hit);
        state.dirty.insert(path.to_path_buf(), hit);
    }

    fn completion_lock(&self, base: &Path) -> Arc<Mutex<()>> {
        let mut flights = self.0.completions.lock().unwrap_or_else(|e| e.into_inner());
        flights.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = flights.get(base).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        flights.insert(base.to_path_buf(), Arc::downgrade(&lock));
        lock
    }

    fn read_dir(&self, path: &Path) -> io::Result<fs::ReadDir> {
        #[cfg(test)]
        if self.0.faults.lock().unwrap().unreadable.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        fs::read_dir(path)
    }

    fn unlink(&self, path: &Path) -> io::Result<()> {
        #[cfg(test)]
        {
            let gate = {
                let mut faults = self.0.faults.lock().unwrap();
                if faults
                    .delete_gate
                    .as_ref()
                    .is_some_and(|(target, _, _)| target == path)
                {
                    faults.delete_gate.take()
                } else {
                    None
                }
            };
            if let Some((_, started, resume)) = gate {
                started.wait();
                resume.wait();
            }
        }
        #[cfg(test)]
        if self.0.faults.lock().unwrap().undeletable.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        fs::remove_file(path)
    }

    fn delete(&self, path: &Path) {
        let unlink = || -> io::Result<()> {
            for root in &self.0.roots {
                if path.starts_with(root) {
                    check_private_dir(root)?;
                }
            }
            check_private_dir(path.parent().unwrap())?;
            self.unlink(path)
        };
        match unlink() {
            Ok(()) => {
                let _ = fs::remove_file(header_path(path));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => self.warn_once("cannot evict entry (excluded from accounting)", path, &e),
        }
        // An undeletable head must not prevent eviction of the remaining files.
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .forget(path);
    }

    pub(crate) fn remove(&self, path: &Path) {
        let _maintenance = self.0.maintenance.lock().unwrap_or_else(|e| e.into_inner());
        self.delete(path);
    }

    /// Publication has already succeeded. Reconciliation/eviction are best effort
    /// and can never turn that successful publication into a reported I/O failure.
    pub(crate) fn install(
        &self,
        path: &Path,
        len: u64,
        cap: u64,
        replaced: &[PathBuf],
    ) -> io::Result<()> {
        let _maintenance = self.0.maintenance.lock().unwrap_or_else(|e| e.into_inner());
        self.reconcile();
        if fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() == len) {
            for old in replaced {
                self.delete(old);
            }
            self.0.lock().unwrap_or_else(|e| e.into_inner()).record(
                path.to_path_buf(),
                len,
                timestamp(),
            );
        }
        loop {
            let oldest = {
                let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                if state.used <= cap {
                    None
                } else {
                    state.lru.first().map(|(_, path)| path.clone())
                }
            };
            let Some(oldest) = oldest else {
                break;
            };
            self.delete(&oldest);
        }
        self.flush_recency(false);
        Ok(())
    }

    fn flush_recency(&self, force: bool) {
        let dirty = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if !force && state.flushed.elapsed().as_nanos() < TOUCH_INTERVAL_NANOS as u128 {
                return;
            }
            state.flushed = Instant::now();
            std::mem::take(&mut state.dirty)
        };
        for (path, hit) in dirty {
            let save = || -> io::Result<()> {
                check_private_dir(path.parent().unwrap())?;
                #[cfg_attr(
                    internal_read_inventory,
                    expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0467-M01","item":"<ratarmount_index::range_cache::SharedBudget>::flush_recency","disposition":"residual","reason":"range-cache completion owner, header or recency read; needs broader lifecycle work","family":"range-cache","issue":"#196","category":"range-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                    )
                )]
                let mut header: serde_json::Value = serde_json::from_reader(
                    open_regular(&header_path(&path))?.take(MAX_HEADER_BYTES),
                )?;
                if {
#[cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0468-M01","item":"<ratarmount_index::range_cache::SharedBudget>::flush_recency","disposition":"residual","reason":"range-cache completion owner, header or recency read; needs broader lifecycle work","family":"range-cache","issue":"#196","category":"range-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###))]
let __inventory_value_0 = open_regular(&path);
__inventory_value_0
}.is_err() {
                    return Ok(());
                }
                header["last_hit"] = hit.into();
                let mut tmp = temporary(path.parent().unwrap())?;
                serde_json::to_writer(&mut tmp, &header)?;
                tmp.as_file().sync_all()?;
                tmp.persist(header_path(&path)).map_err(|e| e.error)?;
                Ok(())
            };
            if let Err(e) = save() {
                self.warn_once("cannot persist recency", &path, &e);
            }
        }
    }

    fn reconcile(&self) {
        let roots = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state
                .reconciled
                .is_some_and(|last| last.elapsed() < RECONCILE_INTERVAL)
            {
                return;
            }
            state.scan_changes = Some(HashSet::new());
            self.0.roots.clone()
        };
        #[cfg(test)]
        {
            let gate = self.0.faults.lock().unwrap().scan_gate.take();
            if let Some((started, resume)) = gate {
                started.wait();
                resume.wait();
            }
        }
        let mut scanned = HashMap::new();
        let mut unreadable = Vec::new();
        for root in roots {
            let fans = match check_private_dir(&root).and_then(|_| self.read_dir(&root)) {
                Ok(fans) => fans,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    self.warn_once("cannot scan directory", &root, &e);
                    unreadable.push(root);
                    continue;
                }
            };
            for fan in fans.flatten() {
                if !fan.file_type().is_ok_and(|kind| kind.is_dir())
                    || !is_hex(&fan.file_name().to_string_lossy(), 2)
                {
                    continue;
                }
                let entries =
                    match check_private_dir(&fan.path()).and_then(|_| self.read_dir(&fan.path())) {
                        Ok(entries) => entries,
                        Err(e) => {
                            self.warn_once("cannot scan directory", &fan.path(), &e);
                            unreadable.push(fan.path());
                            continue;
                        }
                    };
                for entry in entries.flatten() {
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
                    if !is_hex(name.split('.').next().unwrap_or(""), 64) || name.ends_with(".hdr") {
                        continue;
                    }
                    #[cfg_attr(
                        internal_read_inventory,
                        expect(
                            clippy::disallowed_methods,
                            reason = r###"internal-read:v1 {"id":"IR-B0469-M01","item":"<ratarmount_index::range_cache::SharedBudget>::reconcile","disposition":"residual","reason":"range-cache completion owner, header or recency read; needs broader lifecycle work","family":"range-cache","issue":"#196","category":"range-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                        )
                    )]
                    let hit = open_regular(&header_path(&path))
                        .ok()
                        .and_then(|file| {
                            serde_json::from_reader::<_, serde_json::Value>(
                                file.take(MAX_HEADER_BYTES),
                            )
                            .ok()
                        })
                        .and_then(|v| v.get("last_hit").and_then(|v| v.as_u64()))
                        .unwrap_or(0);
                    scanned.insert(path, (meta.len(), hit));
                }
            }
        }
        // Merge a filesystem snapshot without losing hits that arrived during I/O.
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let changes = state.scan_changes.take().unwrap_or_default();
        let stale: Vec<_> = state
            .entries
            .keys()
            .filter(|path| {
                !changes.contains(*path)
                    && !scanned.contains_key(*path)
                    && !unreadable.iter().any(|dir| path.starts_with(dir))
            })
            .cloned()
            .collect();
        for path in stale {
            state.forget(&path);
        }
        for (path, (len, hit)) in scanned {
            if !changes.contains(&path) {
                let hit = state
                    .entries
                    .get(&path)
                    .map_or(hit, |(_, current)| hit.max(*current));
                state.record(path, len, hit);
            }
        }
        state.reconciled = Some(Instant::now());
    }
}

impl Accounting {
    fn forget(&mut self, path: &Path) {
        if let Some(changes) = &mut self.scan_changes {
            changes.insert(path.to_path_buf());
        }
        if let Some((len, hit)) = self.entries.remove(path) {
            self.used = self.used.saturating_sub(len);
            self.lru.remove(&(hit, path.to_path_buf()));
        }
        self.dirty.remove(path);
    }

    fn record(&mut self, path: PathBuf, len: u64, hit: u64) {
        if let Some(changes) = &mut self.scan_changes {
            changes.insert(path.clone());
        }
        if let Some((old_len, old_hit)) = self.entries.remove(&path) {
            self.used = self.used.saturating_sub(old_len);
            self.lru.remove(&(old_hit, path.clone()));
        }
        self.used = self.used.saturating_add(len);
        self.lru.insert((hit, path.clone()));
        self.entries.insert(path, (len, hit));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PayloadCache;
    use std::io::Cursor;

    fn cache(dir: &Path, cap: u64) -> RangeCache {
        RangeCache::with_dirs(
            dir.join("payload-v1/range-v1"),
            dir.join("payload-v1"),
            cap,
            4,
        )
    }

    fn token(label: &str, size: u64) -> ContentToken {
        ContentToken::StrongEtag {
            resource: "https://example.test/model".into(),
            etag: format!("\"{label}\""),
            size,
        }
    }

    /// Regression: repeat range reads must survive reopening the disk cache.
    /// Regression: torrent cache keys aliased different pieces or v2 file paths.
    #[test]
    fn regression_torrent_piece_content_token_isolation() {
        let make = |hash: &str, file: Option<&str>, piece| ContentToken::TorrentPiece {
            infohash: hash.into(),
            file: file.map(str::to_owned),
            piece,
            size: 7,
        };
        let hash = "ab".repeat(20);
        let key = make(&hash, None, 0).key(4096).unwrap();
        assert_ne!(key, make(&hash, None, 1).key(4096).unwrap());
        assert_ne!(key, make(&hash, Some("a"), 0).key(4096).unwrap());
        assert_ne!(
            make(&hash, Some("a"), 0).key(4096),
            make(&hash, Some("b"), 0).key(4096)
        );
        assert_ne!(key, make(&"ab".repeat(32), None, 0).key(4096).unwrap());
        assert!(make("not-an-infohash", None, 0).key(4096).is_none());
        assert_eq!(make(&hash, None, 0).size(), 7);
    }

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
        range.budget.reconcile();
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
        assert_eq!(range.dir(), dir.path().join("payload-v1/range-v1"));
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
        let mut hdr = (*range.header(&path).unwrap()).clone();
        hdr.last_hit = 0;
        write_header(&path, &hdr).unwrap();
        let mut state = range.budget.0.lock().unwrap();
        state.record(path.clone(), 4, 0);
        drop(state);
        assert_eq!(range.get(&id, 0).unwrap(), b"abcd");
        range.budget.flush_recency(true);
        assert!(range.header(&path).unwrap().last_hit >= initial);
    }
    /// Regression: unreadable fanout directories caused every install to rescan and skip eviction.
    #[test]
    fn regression_range_cache_unreadable_fanout_still_evicts_and_marks_reconciled() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 8);
        let id = token("v1", 16);
        range.put(&id, 0, b"aaaa").unwrap();
        range.put(&id, 1, b"bbbb").unwrap();
        let unreadable = range.base(&id).unwrap().parent().unwrap().to_path_buf();
        range
            .budget
            .0
            .faults
            .lock()
            .unwrap()
            .unreadable
            .insert(unreadable);
        range.budget.0.lock().unwrap().reconciled = None;
        range.put(&id, 2, b"cccc").unwrap();
        assert!(!range.contains(&id, 0));
        let reconciled = range.budget.0.lock().unwrap().reconciled;
        assert!(reconciled.is_some());
        range.put(&id, 3, b"dddd").unwrap();
        assert_eq!(range.budget.0.lock().unwrap().reconciled, reconciled);
        assert_eq!(range.budget.0.lock().unwrap().used, 8);
        assert_eq!(range.budget.0.warned.lock().unwrap().len(), 1);
    }

    /// Regression: an undeletable LRU head prevented eviction of all later entries.
    #[test]
    fn regression_range_cache_undeletable_head_does_not_stall_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let mut range = cache(dir.path(), 8);
        let id = token("v1", 16);
        range.put(&id, 0, b"aaaa").unwrap();
        range.put(&id, 1, b"bbbb").unwrap();
        let head = RangeCache::path(&range.base(&id).unwrap(), 0);
        range
            .budget
            .0
            .faults
            .lock()
            .unwrap()
            .undeletable
            .insert(head.clone());
        range.cap = 4;
        range.put(&id, 2, b"cccc").unwrap();
        assert!(head.exists());
        assert!(!range.budget.0.lock().unwrap().entries.contains_key(&head));
        assert!(!range.contains(&id, 1));
        assert!(range.contains(&id, 2));
        assert_eq!(range.budget.0.lock().unwrap().used, 4);
        assert_eq!(range.budget.0.warned.lock().unwrap().len(), 1);
    }

    /// Regression: last-chunk publication copied the whole file on the read path, possibly twice.
    #[test]
    fn regression_range_cache_completion_is_on_demand_and_single_flight() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 8);
        let id = token("v1", 8);
        range.put(&id, 0, b"abcd").unwrap();
        range.put(&id, 1, b"efgh").unwrap();
        let base = range.base(&id).unwrap();
        assert!(!RangeCache::path(&base, "complete").exists());
        let start = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let range = range.clone();
                let id = id.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    range.complete_file(&id).unwrap()
                })
            })
            .collect();
        for worker in workers {
            assert_eq!(fs::read(worker.join().unwrap()).unwrap(), b"abcdefgh");
        }
        assert_eq!(
            range
                .budget
                .0
                .completed_builds
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(!RangeCache::path(&base, 0).exists());
        assert!(!RangeCache::path(&base, 1).exists());
        assert_eq!(range.budget.0.lock().unwrap().used, 8);
    }

    /// Regression: both payload lookup and fill returned paths that range eviction could unlink before open.
    #[cfg(unix)]
    #[test]
    fn regression_payload_cache_lookup_and_fill_fds_survive_range_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 4);
        let payload = PayloadCache::with_dir(dir.path().join("payload-v1"), Some(4), 4);
        let sha = crate::sha256_hex(b"old!");
        let mut filled = payload
            .get_or_fill(&sha, 4, || Ok(Cursor::new(b"old!")))
            .unwrap();
        let mut looked_up = payload.lookup(&sha).unwrap();
        range.put(&token("new", 4), 0, b"new!").unwrap();
        assert!(payload.lookup(&sha).is_none());
        let mut a = Vec::new();
        let mut b = Vec::new();
        filled.read_to_end(&mut a).unwrap();
        looked_up.read_to_end(&mut b).unwrap();
        assert_eq!(a, b"old!");
        assert_eq!(b, b"old!");
    }

    /// Regression: maintenance failure reported a fill error after the payload blob was already published.
    #[test]
    fn regression_payload_cache_published_blob_succeeds_when_reconcile_cannot_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("payload-v1");
        ensure_private_dir(&root).unwrap();
        fs::write(root.join("range-v1"), b"not a directory").unwrap();
        let payload = PayloadCache::with_dir(root, Some(4), 4);
        let path = payload
            .install_from_reader(&crate::sha256_hex(b"good"), 4, &mut Cursor::new(b"good"))
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"good");
    }

    /// Regression: small cached reads skipped the checksum and returned same-length corruption.
    #[test]
    fn regression_range_cache_slice_and_get_reject_same_length_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 16);
        let id = token("v1", 8);
        range.put(&id, 0, b"abcd").unwrap();
        assert_eq!(range.read_into(&id, 0, &mut [0; 1]), Some(1));
        let path = RangeCache::path(&range.base(&id).unwrap(), 0);
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        fs::write(&path, b"evil").unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert!(range.get(&id, 0).is_none());
        assert!(range.read_into(&id, 0, &mut [0; 1]).is_none());
        let small = token("small", 4);
        range.put(&small, 0, b"good").unwrap();
        let whole = range.complete_file(&small).unwrap();
        assert_eq!(range.read_into(&small, 0, &mut [0; 1]), Some(1));
        fs::write(whole, b"evil").unwrap();
        assert!(range.complete_file(&small).is_none());
        assert!(range.get(&small, 0).is_none());
        assert!(range.read_into(&small, 0, &mut [0; 1]).is_none());
        range.put(&id, 0, b"abcd").unwrap();
        assert_eq!(range.read_into(&id, 0, &mut [0; 1]), Some(1));
        range.put(&small, 0, b"good").unwrap();
        assert_eq!(range.get(&small, 0).unwrap(), b"good");
    }

    /// Regression: cache readers trusted writable directories and followed shared cache ownership.
    #[cfg(unix)]
    #[test]
    fn regression_range_cache_read_refuses_group_or_world_writable_dirs() {
        use std::os::unix::fs::PermissionsExt;
        assert!(!safe_owner_and_mode(1001, 1000, 0o700));
        assert!(safe_owner_and_mode(1000, 1000, 0o700));
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 16);
        let id = token("v1", 8);
        range.put(&id, 0, b"abcd").unwrap();
        for path in [
            &range.root,
            &range.dir,
            range.base(&id).unwrap().parent().unwrap(),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o770)).unwrap();
            assert!(range.get(&id, 0).is_none());
            assert!(range.read_into(&id, 0, &mut [0; 1]).is_none());
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// Regression: slow reconciliation held the same mutex needed by every cached page hit.
    #[test]
    fn regression_range_cache_hits_do_not_wait_for_directory_scan() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 8);
        let id = token("v1", 16);
        range.put(&id, 0, b"aaaa").unwrap();
        range.put(&id, 1, b"bbbb").unwrap();
        let start = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        range.budget.0.faults.lock().unwrap().scan_gate = Some((start.clone(), resume.clone()));
        range.budget.0.lock().unwrap().reconciled = None;
        let writer = {
            let range = range.clone();
            let id = id.clone();
            std::thread::spawn(move || range.put(&id, 2, b"cccc").unwrap())
        };
        start.wait();
        let (sent, received) = std::sync::mpsc::channel();
        let reader = {
            let range = range.clone();
            let id = id.clone();
            std::thread::spawn(move || sent.send(range.get(&id, 1)).unwrap())
        };
        let hit = received.recv_timeout(Duration::from_secs(2));
        resume.wait();
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(hit.unwrap().unwrap(), b"bbbb");
    }
    /// Regression: large completed-file checksum manifests exceeded the old 8 KiB header read cap.
    #[test]
    fn regression_range_cache_large_completion_header_remains_readable() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 1024);
        let id = token("large-header", 512);
        for chunk in 0..128 {
            range.put(&id, chunk, b"abcd").unwrap();
        }
        let path = range.complete_file(&id).unwrap();
        assert!(fs::metadata(header_path(&path)).unwrap().len() > 8192);
        let reopened = cache(dir.path(), 1024);
        assert_eq!(reopened.get(&id, 127).unwrap(), b"abcd");
        assert_eq!(reopened.read_into(&id, 509, &mut [0; 3]), Some(3));
        assert!(reopened.complete_file(&id).is_some());
    }

    /// Regression: a slow unlink during eviction blocked cached readers on the shared mutex.
    #[test]
    fn regression_range_cache_hits_do_not_wait_for_eviction_unlink() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 8);
        let id = token("v1", 16);
        range.put(&id, 0, b"aaaa").unwrap();
        range.put(&id, 1, b"bbbb").unwrap();
        let started = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        range.budget.0.faults.lock().unwrap().delete_gate = Some((
            RangeCache::path(&range.base(&id).unwrap(), 0),
            started.clone(),
            resume.clone(),
        ));
        let writer = {
            let range = range.clone();
            let id = id.clone();
            std::thread::spawn(move || range.put(&id, 2, b"cccc").unwrap())
        };
        started.wait();
        let (sent, received) = std::sync::mpsc::channel();
        let reader = {
            let range = range.clone();
            let id = id.clone();
            std::thread::spawn(move || sent.send(range.get(&id, 1)).unwrap())
        };
        let hit = received.recv_timeout(Duration::from_secs(2));
        resume.wait();
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(hit.unwrap().unwrap(), b"bbbb");
    }
    /// Regression: a racing unlink of the just-published blob must not skip the budget eviction loop.
    #[test]
    fn regression_range_cache_missing_published_path_still_enforces_budget() {
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 12);
        let id = token("v1", 16);
        for (chunk, bytes) in [b"aaaa", b"bbbb", b"cccc"].into_iter().enumerate() {
            range.put(&id, chunk as u64, bytes).unwrap();
        }
        let missing = RangeCache::path(&range.base(&id).unwrap(), 3);
        range.budget.install(&missing, 4, 4, &[]).unwrap();
        assert_eq!(range.budget.0.lock().unwrap().used, 4);
        assert!(!range.contains(&id, 0));
        assert!(!range.contains(&id, 1));
        assert!(range.contains(&id, 2));
    }
    /// Regression: eviction followed a replaced cache-root symlink and removed an unrelated file.
    #[cfg(unix)]
    #[test]
    fn regression_range_cache_eviction_refuses_replaced_root_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let range = cache(dir.path(), 8);
        let id = token("v1", 12);
        range.put(&id, 0, b"aaaa").unwrap();
        let path = RangeCache::path(&range.base(&id).unwrap(), 0);
        let relative = path.strip_prefix(&range.dir).unwrap();
        let outside = dir.path().join("outside");
        let victim = outside.join(relative);
        ensure_private_dir(victim.parent().unwrap()).unwrap();
        fs::write(&victim, b"keep").unwrap();
        fs::rename(&range.dir, dir.path().join("old-range")).unwrap();
        symlink(&outside, &range.dir).unwrap();
        range.budget.install(&path, 4, 0, &[]).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(range.get(&id, 0).is_none());
    }
}

#[cfg(test)]
mod hub_handoff_tests {
    use super::*;

    /// Regression: reopening a completed cache pathname could hand passthrough an unverified replacement.
    #[test]
    fn regression_range_cache_backing_fd_survives_complete_path_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RangeCache::with_dirs(dir.path().join("range-v1"), dir.path().into(), 1024, 4);
        let token = ContentToken::Sha256 {
            sha256: crate::sha256_hex(b"original"),
            size: 8,
        };
        cache.put(&token, 0, b"orig").unwrap();
        cache.put(&token, 1, b"inal").unwrap();
        let mut fd = cache.complete_backing_file(&token).unwrap();
        let path = cache.complete_file(&token).unwrap();
        fs::rename(&path, dir.path().join("old-complete")).unwrap();
        fs::write(&path, b"tampered").unwrap();
        let mut bytes = Vec::new();
        fd.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(cache.complete_backing_file(&token).is_none());
    }

    /// Regression: handing a whole file to the Hub left chunks and a complete copy under the shared budget.
    #[test]
    fn regression_range_cache_hub_handoff_removes_only_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RangeCache::with_dirs(dir.path().join("range-v1"), dir.path().into(), 1024, 4);
        let id = ContentToken::Sha256 {
            sha256: crate::sha256_hex(b"abcdefgh"),
            size: 8,
        };
        let other = ContentToken::Sha256 {
            sha256: crate::sha256_hex(b"ijkl"),
            size: 4,
        };
        cache.put(&id, 0, b"abcd").unwrap();
        cache.put(&id, 1, b"efgh").unwrap();
        cache.put(&other, 0, b"ijkl").unwrap();
        let mut held = File::open(cache.complete_file(&id).unwrap()).unwrap();
        cache.remove_file(&id);
        assert!(!cache.contains(&id, 0));
        assert!(!cache.contains(&id, 1));
        assert!(cache.complete_file(&id).is_none());
        assert_eq!(cache.get(&other, 0).unwrap(), b"ijkl");
        let mut bytes = Vec::new();
        held.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcdefgh");
        cache.put(&id, 0, b"abcd").unwrap();
        cache.remove_file(&id);
        assert!(!cache.contains(&id, 0));
    }
}
