//! G-3 decompressed-member LRU (`payload-v1/`), sibling of `local-index-v1/`.
//!
//! Keys are lowercase hex SHA-256 of **decompressed member bytes**. Layout:
//! [`platform_cache_root()`]`/payload-v1/{hh}/{sha256}` plus `{sha256}.hdr`.
//! Never writes `meta-v3/` or nests under `local-index-v1/`.

#[cfg_attr(
    internal_read_inventory,
    expect(
        clippy::disallowed_types,
        reason = r###"internal-read:v1 {"id":"IR-E0078-T01","item":"ratarmount_index::payload_cache","disposition":"support","category":"builder-type-support","reason":"Builder type support: Import OpenOptions for exclusive payload-cache staging output.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
    )
)]
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::range_cache::{
    check_private_dir, ensure_private_dir, open_regular, temporary, timestamp, SharedBudget,
};
use crate::HASH_STREAM_CHUNK;

/// Shared payload-v1 + range-v1 byte cap. `0` disables both. Default [`PAYLOAD_CACHE_BYTES_DEFAULT`].
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
    shared_budget: SharedBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PayloadHeader {
    schema: String,
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
            shared_budget: SharedBudget::for_payload(&payload_v1_dir()),
            dir: payload_v1_dir(),
            budget: Some(budget),
            member_max: member_max_from_env(),
        })
    }

    /// Test/helper constructor. `budget = None` disables store.
    pub fn with_dir(dir: PathBuf, budget: Option<u64>, member_max: u64) -> Self {
        Self {
            shared_budget: SharedBudget::for_payload(&dir),
            dir,
            budget: budget.filter(|n| *n > 0),
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

    /// Open `{hh}/{sha256}` whose header length matches the blob. The owned fd
    /// remains readable after another installer unlinks its cache path.
    ///
    /// A missing header or blob is a miss, not corruption: install writes the
    /// header then renames the tmp, so a concurrent lookup must not unlink a
    /// just-published (or about-to-be-renamed) file.
    pub fn lookup(&self, sha256: &str) -> Option<File> {
        self.budget?;
        let key = normalize_sha256(sha256)?;
        let blob = self.blob_path(&key);
        check_private_dir(&self.dir).ok()?;
        check_private_dir(&self.fanout_dir(&key)).ok()?;
        let hdr = match self.read_header(&key) {
            Ok(h) if h.schema == PAYLOAD_SCHEMA => h,
            _ => return None,
        };
        if fs::symlink_metadata(&self.dir)
            .ok()?
            .file_type()
            .is_symlink()
            || fs::symlink_metadata(self.fanout_dir(&key))
                .ok()?
                .file_type()
                .is_symlink()
        {
            return None;
        }
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0458-M01","item":"<ratarmount_index::payload_cache::PayloadCache>::lookup","disposition":"residual","reason":"payload-cache blob owner / staging reopen; payload cache ownership and backing export are excluded","family":"payload-cache","issue":"#196","category":"payload-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        let file = open_regular(&blob).ok()?;
        let meta = file.metadata().ok()?;
        if meta.len() != hdr.len || hdr.len == 0 {
            debug!("payload-v1 corrupt {key} (len mismatch or empty)");
            self.invalidate_key(&key);
            return None;
        }
        self.touch(&key, &hdr);
        debug!("payload-v1 hit {key} -> {}", blob.display());
        Some(file)
    }

    /// Copy `reader` to `{sha256}.tmp.{pid}` + rename. Fail-closed on short/hash mismatch.
    pub fn install_from_reader<R: Read>(
        &self,
        sha256: &str,
        expected_len: u64,
        reader: &mut R,
    ) -> io::Result<PathBuf> {
        self.install_open(sha256, expected_len, reader)
            .map(|(path, _)| path)
    }

    fn install_open<R: Read>(
        &self,
        sha256: &str,
        expected_len: u64,
        reader: &mut R,
    ) -> io::Result<(PathBuf, File)> {
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
            if existing.metadata().map(|m| m.len()).unwrap_or(0) == expected_len {
                return Ok((self.blob_path(&key), existing));
            }
        }
        self.ensure_fanout(&key)?;
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
        if let Ok(f) = {
            #[cfg_attr(
                internal_read_inventory,
                expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0459-M01","item":"<ratarmount_index::payload_cache::PayloadCache>::install_open","disposition":"residual","reason":"payload-cache sync reopen of its own staging file (payload_cache.rs:195); payload cache ownership is excluded","family":"payload-cache","issue":"#196","category":"payload-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )
            )]
            let __inventory_value_0 = File::open(&tmp);
            __inventory_value_0
        } {
            let _ = f.sync_all();
        }
        let now = timestamp();
        let hdr = PayloadHeader {
            schema: PAYLOAD_SCHEMA.to_string(),
            len: expected_len,
            last_hit: now,
        };
        // Header before rename so a concurrent lookup never sees a blob without
        // metadata; missing blob is a miss (not an unlink).
        if let Err(e) = self.write_header(&key, &hdr) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0460-M01","item":"<ratarmount_index::payload_cache::PayloadCache>::install_open","disposition":"residual","reason":"payload-cache blob owner / staging reopen; payload cache ownership and backing export are excluded","family":"payload-cache","issue":"#196","category":"payload-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        let file = match open_regular(&tmp) {
            Ok(file) => file,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        if let Err(e) = fs::rename(&tmp, &dest) {
            let _ = fs::remove_file(&tmp);
            self.invalidate_key(&key);
            return Err(e);
        }
        if let Err(e) = self.shared_budget.install(&dest, expected_len, budget, &[]) {
            log::warn!("payload-v1 published; cache maintenance failed: {e}");
        }
        debug!(
            "payload-v1 store {key} -> {} ({expected_len} bytes)",
            dest.display()
        );
        Ok((dest, file))
    }

    /// Hit or fill, returning an owned read fd immune to path eviction races.
    /// `fill` is not called on a valid lookup (second open skips the archive).
    pub fn get_or_fill<R, F>(&self, sha256: &str, expected_len: u64, fill: F) -> io::Result<File>
    where
        R: Read,
        F: FnOnce() -> io::Result<R>,
    {
        if let Some(path) = self.lookup(sha256) {
            if path.metadata().map(|m| m.len()).unwrap_or(0) == expected_len {
                return Ok(path);
            }
        }
        let mut reader = fill()?;
        self.install_open(sha256, expected_len, &mut reader)
            .map(|(_, file)| file)
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

    fn ensure_fanout(&self, key: &str) -> io::Result<()> {
        ensure_private_dir(&self.dir)?;
        ensure_private_dir(&self.fanout_dir(key))
    }

    fn read_header(&self, key: &str) -> io::Result<PayloadHeader> {
        let mut bytes = Vec::new();
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0461-M01","item":"<ratarmount_index::payload_cache::PayloadCache>::read_header","disposition":"residual","reason":"payload-cache header read (payload_cache.rs:266-270): payload-v1 cache, not the meta-v3 metadata cache, so not mandatory","family":"payload-cache","issue":"#196","category":"payload-cache","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )
        )]
        open_regular(&self.hdr_path(key))?
            .take(8192)
            .read_to_end(&mut bytes)?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn write_header(&self, key: &str, hdr: &PayloadHeader) -> io::Result<()> {
        self.ensure_fanout(key)?;
        let mut part = temporary(&self.fanout_dir(key))?;
        let json =
            serde_json::to_vec(hdr).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        part.write_all(&json)?;
        part.as_file().sync_all()?;
        part.persist(self.hdr_path(key)).map_err(|e| e.error)?;
        Ok(())
    }

    fn touch(&self, key: &str, hdr: &PayloadHeader) {
        let mut next = hdr.clone();
        next.last_hit = timestamp().max(hdr.last_hit.saturating_add(1));
        self.shared_budget
            .touch(&self.blob_path(key), hdr.len, next.last_hit);
        // Persist recency in batches during shared cache maintenance.
    }

    fn invalidate_key(&self, key: &str) {
        self.shared_budget.remove(&self.blob_path(key));
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
    let mut f = {
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_types,
                reason = r###"internal-read:v1 {"id":"IR-B0462-T01","item":"ratarmount_index::payload_cache::copy_hash_to_tmp","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-type-support","reason":"Builder type support: Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
            )
        )]
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0462-M01","item":"ratarmount_index::payload_cache::copy_hash_to_tmp","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###
            )
        )]
        let mut __inventory_value_0 = OpenOptions::new();
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-E0079-M01","item":"ratarmount_index::payload_cache::copy_hash_to_tmp","disposition":"output-owner","category":"payload-cache-staging","reason":"Configure exclusive creation of the payload temporary file before hashing and length-checking streamed output.","creation":{"policy":"exclusive-new-file","basis":"create_new cannot replace an existing file; existing default/umask permissions are retained until cache publication."}}"###
            )
        )]
        let __inventory_value_1 = __inventory_value_0.write(true).create_new(true);
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0462-M02","item":"ratarmount_index::payload_cache::copy_hash_to_tmp","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )
        )]
        let __inventory_value_2 = __inventory_value_1.open(tmp);
        __inventory_value_2
    }?;
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

pub(crate) fn cache_budget() -> Option<u64> {
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
        cache
            .shared_budget
            .touch(&cache.blob_path(sha), hdr.len, ts);
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
        let mut first = cache.get_or_fill(&sha, body.len() as u64, fill).unwrap();
        let mut bytes = Vec::new();
        first.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, body);
        let p1 = cache.blob_path(&sha);
        assert_eq!(fills.load(Ordering::SeqCst), 1);
        let mut second = cache.get_or_fill(&sha, body.len() as u64, fill).unwrap();
        let mut bytes = Vec::new();
        second.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, body);
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
    /// Driven through `install_from_reader` with a small budget (not only `evict_until`).
    #[test]
    fn payload_cache_lru_evicts() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), 8);
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
        set_last_hit(&cache, &sa, 1);
        set_last_hit(&cache, &sb, 200);
        let pc = cache
            .install_from_reader(&sc, c.len() as u64, &mut Cursor::new(c.as_slice()))
            .unwrap();
        assert!(
            !pa.is_file(),
            "oldest last_hit (a) must be evicted when installing c under an 8-byte cap"
        );
        assert!(pb.is_file(), "newer b must survive");
        assert!(pc.is_file(), "newest c must survive");
        assert!(
            !cache.hdr_path(&sa).exists(),
            "eviction must drop the hdr pair"
        );
    }

    /// Regression: overlapping lookup must not drop a blob that has no `.hdr` yet.
    #[test]
    fn payload_cache_lookup_missing_hdr_does_not_drop_blob() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), PAYLOAD_CACHE_BYTES_DEFAULT);
        let body = b"just-renamed-blob";
        let sha = sha256_hex(body);
        cache.ensure_fanout(&sha).unwrap();
        let dest = cache.blob_path(&sha);
        fs::write(&dest, body).unwrap();
        assert!(cache.lookup(&sha).is_none(), "no hdr is a miss");
        assert!(
            dest.is_file(),
            "lookup must not unlink a blob waiting for hdr"
        );
        let cache2 = cache.clone();
        let sha2 = sha.clone();
        let dest2 = dest.clone();
        let lookups = std::thread::spawn(move || {
            for _ in 0..200 {
                let _ = cache2.lookup(&sha2);
                assert!(
                    dest2.is_file(),
                    "concurrent lookup must not drop the just-renamed blob"
                );
            }
        });
        let p = cache
            .install_from_reader(&sha, body.len() as u64, &mut Cursor::new(body.as_slice()))
            .unwrap();
        lookups.join().expect("lookup thread");
        assert_eq!(fs::read(&p).unwrap(), body);
        assert!(cache.lookup(&sha).is_some());
    }

    /// Regression: members larger than the v1 cap are not stored.
    #[test]
    fn payload_cache_skips_over_member_max() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PayloadCache::with_dir(
            dir.path().join(PAYLOAD_V1_DIRNAME),
            Some(PAYLOAD_CACHE_BYTES_DEFAULT),
            8,
        );
        let body = b"0123456789";
        let sha = sha256_hex(body);
        let err = cache
            .install_from_reader(&sha, body.len() as u64, &mut Cursor::new(body.as_slice()))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("member max") || msg.contains("skip"), "{msg}");
        assert!(cache.lookup(&sha).is_none());
        assert!(
            !cache.blob_path(&sha).exists(),
            "over-max member must not leave a dest blob"
        );
    }

    /// Regression: digest ≠ key is fail-closed (no dest blob).
    #[test]
    fn payload_cache_fail_closed_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), PAYLOAD_CACHE_BYTES_DEFAULT);
        let body = b"aaaa";
        let sha = sha256_hex(b"bbbb");
        let err = cache
            .install_from_reader(&sha, body.len() as u64, &mut Cursor::new(body.as_slice()))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            cache.lookup(&sha).is_none(),
            "hash mismatch must not publish"
        );
        assert!(!cache.blob_path(&sha).exists());
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
