//! Local-archive index cache (`local-index-v1/`), distinct from V-3 `meta-v3/`
//! and G-3 `payload-v1/`.
//!
//! User-cache policy (`IndexPolicy::UserCache`) stores 0.7.x sidecars as
//! `{sha256}.sqlite` plus a JSON header. Remote sidecar **downloads** stay in
//! `meta-v3/` (`MetaCache`); mixing the two would evict the wrong class of blobs.
//! Decompressed member bodies live in sibling `payload-v1/` (never a child of
//! this directory).
//!
//! Layout: [`platform_cache_root()`]`/local-index-v1/{hex}.sqlite` + `{hex}.json`.
//! Root is platform-specific (macOS `Library/Caches` unless XDG override);
//! `meta-v3` keeps `xdg_cache_home()` and is not migrated.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use serde::{Deserialize, Serialize};

use crate::location::{path_is_usable_existing_index, possible_index_paths, IndexLocation};
use crate::sha256_hex;

/// Env cap for the LRU directory. `0` disables writes. Default [`LOCAL_INDEX_CACHE_BYTES_DEFAULT`].
pub const LOCAL_INDEX_CACHE_BYTES_ENV: &str = "RATARMOUNT_LOCAL_INDEX_CACHE_BYTES";

/// Override directory (highest priority; skips platform / XDG roots).
pub const LOCAL_INDEX_DIR_ENV: &str = "RATARMOUNT_LOCAL_INDEX_DIR";

/// Default `RATARMOUNT_LOCAL_INDEX_CACHE_BYTES` (2 GiB).
pub const LOCAL_INDEX_CACHE_BYTES_DEFAULT: u64 = 2 * 1024 * 1024 * 1024;

const LOCAL_INDEX_V1_DIRNAME: &str = "local-index-v1";
const LOCAL_INDEX_SCHEMA: &str = "ratarmount.local-index-v1";

/// LRU of local-archive sqlite sidecars keyed by archive identity.
pub struct LocalIndexCache {
    dir: PathBuf,
    /// `None` disables lookup and store (`RATARMOUNT_LOCAL_INDEX_CACHE_BYTES=0`).
    budget: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalIndexHeader {
    schema: String,
    /// Archive path only — never member names (privacy).
    path: String,
    size: u64,
    mtime_ns: u64,
    file_id: String,
    last_open_unix: u64,
}

struct ArchiveIdentity {
    canonical_path: String,
    size: u64,
    mtime_ns: u64,
    file_id: String,
}

impl ArchiveIdentity {
    fn key(&self) -> String {
        sha256_hex(&identity_bytes(
            &self.canonical_path,
            self.size,
            self.mtime_ns,
            &self.file_id,
        ))
    }
}

impl LocalIndexCache {
    /// Directory + budget from env.
    pub fn from_env() -> Self {
        Self {
            dir: local_index_v1_dir(),
            budget: cache_budget(),
        }
    }

    /// Existing usable `{hex}.sqlite` for `archive`, touching `last_open_unix`.
    pub fn lookup(&self, archive: &Path) -> Option<PathBuf> {
        self.budget?;
        let id = archive_identity(archive);
        let key = id.key();
        let sqlite = self.sqlite_path(&key);
        if !path_is_usable_existing_index(&sqlite) {
            return None;
        }
        self.touch(&key, &id);
        // WHY: allocate evicts before the sqlite body exists; remounts must trim.
        let _ = self.enforce_budget();
        debug!("local-index-v1 hit {key} -> {}", sqlite.display());
        Some(sqlite)
    }

    /// Create-path for `archive`: ensure `0700` dir, write JSON, evict to cap.
    ///
    /// Does not write the sqlite body (factory / `SqliteIndex` does). Never
    /// creates under `meta-v3/` or next to the archive.
    pub fn allocate(&self, archive: &Path) -> io::Result<PathBuf> {
        let Some(budget) = self.budget else {
            return Err(io::Error::other(
                "RATARMOUNT_LOCAL_INDEX_CACHE_BYTES=0 disables local-index-v1; not meta-v3",
            ));
        };
        let id = archive_identity(archive);
        let key = id.key();
        self.ensure_dir()?;
        self.evict_until(budget, Some(&key))?;
        self.write_header(&key, &id, unix_now_secs())?;
        let sqlite = self.sqlite_path(&key);
        debug!(
            "local-index-v1 allocate {key} -> {} (budget {budget})",
            sqlite.display()
        );
        Ok(sqlite)
    }

    /// Drop every `{hex}.sqlite`+`.json` pair. Does not touch `meta-v3/` or siblings.
    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_dir_all(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Re-run LRU eviction (after a sqlite body is published).
    pub fn enforce_budget(&self) -> io::Result<()> {
        let Some(budget) = self.budget else {
            return Ok(());
        };
        self.evict_until(budget, None)
    }

    fn sqlite_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.sqlite"))
    }

    fn json_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
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

    fn read_header(&self, key: &str) -> io::Result<LocalIndexHeader> {
        let bytes = fs::read(self.json_path(key))?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn write_header(&self, key: &str, id: &ArchiveIdentity, last_open_unix: u64) -> io::Result<()> {
        let hdr = LocalIndexHeader {
            schema: LOCAL_INDEX_SCHEMA.to_string(),
            path: id.canonical_path.clone(),
            size: id.size,
            mtime_ns: id.mtime_ns,
            file_id: id.file_id.clone(),
            last_open_unix,
        };
        self.ensure_dir()?;
        let part = self.dir.join(format!("{key}.json.part"));
        let json =
            serde_json::to_vec(&hdr).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        {
            let mut f = File::create(&part)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        fs::rename(part, self.json_path(key))?;
        Ok(())
    }

    fn touch(&self, key: &str, id: &ArchiveIdentity) {
        let prev = self
            .read_header(key)
            .ok()
            .map(|h| h.last_open_unix)
            .unwrap_or(0);
        let now = unix_now_secs().max(prev.saturating_add(1));
        let _ = self.write_header(key, id, now);
    }

    fn invalidate_key(&self, key: &str) {
        let _ = fs::remove_file(self.sqlite_path(key));
        let _ = fs::remove_file(self.json_path(key));
        let _ = fs::remove_file(self.dir.join(format!("{key}.json.part")));
    }

    fn evict_until(&self, max_used: u64, keep: Option<&str>) -> io::Result<()> {
        let mut entries = self.list_entries()?;
        let mut used: u64 = entries.iter().map(|e| e.len).sum();
        if used <= max_used {
            return Ok(());
        }
        entries.sort_by_key(|e| e.last_open_unix);
        let mut remaining = entries.len();
        for e in entries {
            if used <= max_used {
                break;
            }
            if keep == Some(e.key.as_str()) {
                continue;
            }
            // Single entry larger than the cap stays (cannot get under otherwise).
            if remaining <= 1 {
                break;
            }
            debug!(
                "local-index-v1 evict {} ({} bytes, last_open_unix {})",
                e.key, e.len, e.last_open_unix
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
        for ent in iter {
            let ent = ent?;
            let name = ent.file_name();
            let name = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            let Some(key) = key_from_sqlite_name(name) else {
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
            let last_open_unix = match self.read_header(key) {
                Ok(h) if h.schema == LOCAL_INDEX_SCHEMA => h.last_open_unix,
                _ => file_mtime_unix(&path),
            };
            out.push(CacheEntry {
                key: key.to_string(),
                len,
                last_open_unix,
            });
        }
        Ok(out)
    }
}

struct CacheEntry {
    key: String,
    len: u64,
    last_open_unix: u64,
}

/// Platform `local-index-v1` directory (env + OS). Never `meta-v3/`.
pub fn local_index_v1_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(LOCAL_INDEX_DIR_ENV) {
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
                    let p = std::env::temp_dir().join(format!(
                        "ratarmount-local-index-v1-test-{}",
                        std::process::id()
                    ));
                    let _ = fs::create_dir_all(&p);
                    p.join("ratarmount").join(LOCAL_INDEX_V1_DIRNAME)
                })
                .clone();
        }
    }
    platform_local_index_root(
        env_path("XDG_CACHE_HOME").as_deref(),
        env_path("HOME").as_deref(),
        env_path("LOCALAPPDATA").as_deref(),
    )
}

/// True when `path` is under this process's `local-index-v1` root.
pub fn is_local_index_cache_path(path: &Path) -> bool {
    path_is_under(&local_index_v1_dir(), path)
}

/// Extra-dirs existing files, then a `local-index-v1` hit. Never sibling well-known.
///
/// URL archives use the same sha256 identity (path string, size/mtime/file_id 0
/// when there is no local file) so UserCache does not fall through to the legacy
/// flattened `$XDG_CACHE_HOME/ratarmount/*.index.sqlite` parent.
pub fn find_existing_user_cache_index(archive: &Path, extra_dirs: &[PathBuf]) -> Option<PathBuf> {
    if let Some(p) = find_existing_extra_dir_index(archive, extra_dirs) {
        return Some(p);
    }
    LocalIndexCache::from_env().lookup(archive)
}

/// User-cache create/load path. Never `:memory:`. Never `meta-v3/`.
///
/// URL sources pin `{hex}.sqlite` here (identity is the URL string). Remote
/// sidecar **downloads** still live in `meta-v3/`; discovery may copy a hit
/// onto this dest. Never the CliCompat flattened XDG parent.
pub fn resolve_user_cache_index_location(
    archive: &Path,
    extra_dirs: &[PathBuf],
    recreate: bool,
) -> io::Result<IndexLocation> {
    if !recreate {
        if let Some(p) = find_existing_extra_dir_index(archive, extra_dirs) {
            return Ok(IndexLocation::Path(p));
        }
    }
    let cache = LocalIndexCache::from_env();
    if !recreate {
        if let Some(p) = cache.lookup(archive) {
            return Ok(IndexLocation::Path(p));
        }
    }
    cache.allocate(archive).map(IndexLocation::Path)
}

/// After factory `publish_tmp` of a UserCache sidecar, trim the LRU.
pub fn enforce_local_index_budget_if_path(path: &Path) {
    if !is_local_index_cache_path(path) {
        return;
    }
    let _ = LocalIndexCache::from_env().enforce_budget();
}

fn find_existing_extra_dir_index(archive: &Path, extra_dirs: &[PathBuf]) -> Option<PathBuf> {
    let extras: Vec<PathBuf> = extra_dirs
        .iter()
        .filter(|d| !d.as_os_str().is_empty())
        .cloned()
        .collect();
    if extras.is_empty() {
        return None;
    }
    possible_index_paths(archive, &extras)
        .into_iter()
        .find(|p| path_is_usable_existing_index(p))
}

/// Parent of `local-index-v1/` and `payload-v1/` (and not `meta-v3/`).
///
/// Linux: `${XDG_CACHE_HOME:-$HOME/.cache}/ratarmount/`.
/// macOS: `~/Library/Caches/ratarmount/` unless XDG is set.
/// Windows: `%LOCALAPPDATA%\ratarmount\`.
///
/// WHY: joining `payload-v1` onto `local-index-v1/` mixed G-3 into the 2 GiB
/// index LRU. `meta-v3` stays on `xdg_cache_home()` (`$HOME/.cache` on macOS)
/// so existing remote remounts do not miss.
pub fn platform_cache_root() -> PathBuf {
    platform_cache_root_from(
        env_path("XDG_CACHE_HOME").as_deref(),
        env_path("HOME").as_deref(),
        env_path("LOCALAPPDATA").as_deref(),
    )
}

pub(crate) fn platform_cache_root_from(
    xdg_cache_home: Option<&Path>,
    home: Option<&Path>,
    local_appdata: Option<&Path>,
) -> PathBuf {
    if let Some(xdg) = xdg_cache_home {
        if !xdg.as_os_str().is_empty() {
            return xdg.join("ratarmount");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home {
            return home.join("Library").join("Caches").join("ratarmount");
        }
    }
    #[cfg(windows)]
    {
        if let Some(app) = local_appdata {
            if !app.as_os_str().is_empty() {
                return app.join("ratarmount");
            }
        }
    }
    let _ = local_appdata;
    home.map(|h| h.join(".cache"))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ratarmount")
}

fn platform_local_index_root(
    xdg_cache_home: Option<&Path>,
    home: Option<&Path>,
    local_appdata: Option<&Path>,
) -> PathBuf {
    platform_cache_root_from(xdg_cache_home, home, local_appdata).join(LOCAL_INDEX_V1_DIRNAME)
}

fn archive_identity(archive: &Path) -> ArchiveIdentity {
    let canonical = fs::canonicalize(archive)
        .unwrap_or_else(|_| archive.to_path_buf())
        .to_string_lossy()
        .into_owned();
    match fs::metadata(archive) {
        Ok(m) => ArchiveIdentity {
            canonical_path: canonical,
            size: m.len(),
            mtime_ns: mtime_ns(&m),
            file_id: file_id(&m),
        },
        Err(_) => ArchiveIdentity {
            canonical_path: canonical,
            size: 0,
            mtime_ns: 0,
            file_id: "0".into(),
        },
    }
}

fn identity_bytes(canonical: &str, size: u64, mtime_ns: u64, file_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(canonical.len() + file_id.len() + 40);
    v.extend_from_slice(canonical.as_bytes());
    v.push(0);
    v.extend_from_slice(size.to_string().as_bytes());
    v.push(0);
    v.extend_from_slice(mtime_ns.to_string().as_bytes());
    v.push(0);
    v.extend_from_slice(file_id.as_bytes());
    v
}

fn mtime_ns(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.mtime() as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(meta.mtime_nsec().max(0) as u64)
    }
    #[cfg(not(unix))]
    {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

fn file_id(meta: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.ino().to_string()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        match (meta.volume_serial_number(), meta.file_index()) {
            (Some(vol), Some(idx)) => format!("{vol:08x}:{idx:016x}"),
            _ => "0".into(),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = meta;
        "0".into()
    }
}

fn key_from_sqlite_name(name: &str) -> Option<&str> {
    let hex = name.strip_suffix(".sqlite")?;
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hex)
    } else {
        None
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
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
    match std::env::var(LOCAL_INDEX_CACHE_BYTES_ENV) {
        Ok(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Some(LOCAL_INDEX_CACHE_BYTES_DEFAULT);
            }
            match s.parse::<u64>() {
                Ok(0) => None,
                Ok(n) => Some(n),
                Err(_) => Some(LOCAL_INDEX_CACHE_BYTES_DEFAULT),
            }
        }
        Err(_) => Some(LOCAL_INDEX_CACHE_BYTES_DEFAULT),
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
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
    use crate::is_meta_cache_path;
    use serde_json::Value;

    fn cache_in(dir: &Path, budget: u64) -> LocalIndexCache {
        LocalIndexCache {
            dir: dir.join(LOCAL_INDEX_V1_DIRNAME),
            budget: Some(budget),
        }
    }

    fn write_archive(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    /// Regression: local-index-v1 keys are sha256 hex; files are `{hex}.sqlite` + `{hex}.json`.
    #[test]
    fn local_index_cache_writes_sha256_sqlite_and_json() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), LOCAL_INDEX_CACHE_BYTES_DEFAULT);
        let archive = write_archive(dir.path(), "foo.tar", b"archive-bytes");
        let sqlite = cache.allocate(&archive).unwrap();
        let name = sqlite.file_name().unwrap().to_string_lossy();
        assert!(
            name.ends_with(".sqlite"),
            "expected {{hex}}.sqlite, got {name}"
        );
        let hex = name.strip_suffix(".sqlite").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let json_path = cache.json_path(hex);
        assert!(json_path.is_file(), "{}", json_path.display());
        let hdr: LocalIndexHeader = serde_json::from_slice(&fs::read(&json_path).unwrap()).unwrap();
        assert_eq!(hdr.schema, LOCAL_INDEX_SCHEMA);
        assert!(hdr.path.ends_with("foo.tar"), "{}", hdr.path);
        assert_eq!(hdr.size, b"archive-bytes".len() as u64);
        assert!(!hdr.file_id.is_empty());
        let v: Value = serde_json::from_slice(&fs::read(&json_path).unwrap()).unwrap();
        assert!(v.get("members").is_none(), "must not store member names");
        fs::write(&sqlite, b"idx").unwrap();
        assert_eq!(
            cache.lookup(&archive).as_deref(),
            Some(sqlite.as_path()),
            "same identity must hit"
        );
    }

    fn set_last_open(cache: &LocalIndexCache, sqlite: &Path, ts: u64) {
        let hex = key_from_sqlite_name(sqlite.file_name().unwrap().to_str().unwrap()).unwrap();
        let mut hdr: LocalIndexHeader =
            serde_json::from_slice(&fs::read(cache.json_path(hex)).unwrap()).unwrap();
        hdr.last_open_unix = ts;
        fs::write(cache.json_path(hex), serde_json::to_vec(&hdr).unwrap()).unwrap();
    }

    /// Regression: LRU cap deletes oldest `last_open_unix` `{hex}.sqlite`+`.json` pairs.
    #[test]
    fn local_index_cache_lru_evicts_oldest_last_open() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), 8);
        let a = write_archive(dir.path(), "a.tar", b"aaaa");
        let b = write_archive(dir.path(), "b.tar", b"bbbb");
        let c = write_archive(dir.path(), "c.tar", b"cccc");
        let pa = cache.allocate(&a).unwrap();
        fs::write(&pa, b"aaaa").unwrap();
        let pb = cache.allocate(&b).unwrap();
        fs::write(&pb, b"bbbb").unwrap();
        let pc = cache.allocate(&c).unwrap();
        fs::write(&pc, b"cccc").unwrap();
        // Pin order so same-second unix timestamps cannot tie-break via readdir.
        set_last_open(&cache, &pa, 100);
        set_last_open(&cache, &pb, 1);
        set_last_open(&cache, &pc, 200);
        cache.enforce_budget().unwrap();
        assert!(pa.is_file(), "newer a must survive");
        assert!(
            !pb.is_file(),
            "oldest last_open (b) must be evicted under an 8-byte cap"
        );
        assert!(pc.is_file(), "newest c must survive");
        let b_key = key_from_sqlite_name(pb.file_name().unwrap().to_str().unwrap()).unwrap();
        assert!(
            !cache.json_path(b_key).exists(),
            "eviction must drop the json pair"
        );
    }

    /// Regression: eviction never deletes sibling `{archive}.index.sqlite`.
    #[test]
    fn local_index_cache_lru_never_deletes_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), 4);
        let archive = write_archive(dir.path(), "a.tar", b"data");
        let sibling = PathBuf::from(format!("{}.index.sqlite", archive.display()));
        fs::write(&sibling, b"SIBLING-INDEX").unwrap();
        let p = cache.allocate(&archive).unwrap();
        fs::write(&p, b"1234").unwrap();
        let other = write_archive(dir.path(), "b.tar", b"xxxx");
        let p2 = cache.allocate(&other).unwrap();
        fs::write(&p2, b"1234").unwrap();
        cache.enforce_budget().unwrap();
        assert_eq!(fs::read(&sibling).unwrap(), b"SIBLING-INDEX");
        assert!(sibling.is_file());
    }

    /// Regression: UserCache helper must not write `meta-v3/`.
    #[test]
    fn local_index_cache_does_not_write_meta_v3() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), LOCAL_INDEX_CACHE_BYTES_DEFAULT);
        let archive = write_archive(dir.path(), "a.tar", b"x");
        let sqlite = cache.allocate(&archive).unwrap();
        fs::write(&sqlite, b"idx").unwrap();
        assert!(is_local_index_cache_path(&sqlite) || sqlite.starts_with(&cache.dir));
        assert!(!is_meta_cache_path(&sqlite), "{}", sqlite.display());
        let meta = dir.path().join("ratarmount").join("meta-v3");
        assert!(
            !meta.exists()
                || fs::read_dir(&meta)
                    .map(|it| it.count() == 0)
                    .unwrap_or(true),
            "local-index-v1 must not create meta-v3: {}",
            meta.display()
        );
    }

    #[test]
    fn local_index_v1_dir_name_is_not_meta_v3() {
        let xdg =
            platform_local_index_root(Some(Path::new("/xdg")), Some(Path::new("/home/me")), None);
        assert_eq!(
            xdg,
            PathBuf::from("/xdg/ratarmount").join(LOCAL_INDEX_V1_DIRNAME)
        );
        assert_ne!(xdg.file_name().unwrap(), "meta-v3");
    }

    #[test]
    fn local_index_xdg_override_beats_home() {
        let p = platform_local_index_root(
            Some(Path::new("/tmp/xdg-cache")),
            Some(Path::new("/Users/me")),
            Some(Path::new("/home/me/AppData/Local")),
        );
        assert_eq!(
            p,
            PathBuf::from("/tmp/xdg-cache/ratarmount").join(LOCAL_INDEX_V1_DIRNAME)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn local_index_macos_without_xdg_uses_library_caches() {
        let p = platform_local_index_root(None, Some(Path::new("/Users/me")), None);
        assert_eq!(
            p,
            PathBuf::from("/Users/me/Library/Caches/ratarmount").join(LOCAL_INDEX_V1_DIRNAME)
        );
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    #[test]
    fn local_index_linux_without_xdg_uses_home_cache() {
        let p = platform_local_index_root(None, Some(Path::new("/home/me")), None);
        assert_eq!(
            p,
            PathBuf::from("/home/me/.cache/ratarmount").join(LOCAL_INDEX_V1_DIRNAME)
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_index_cache_dir_mode_0700() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), LOCAL_INDEX_CACHE_BYTES_DEFAULT);
        let archive = write_archive(dir.path(), "a.tar", b"x");
        cache.allocate(&archive).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&cache.dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "cache dir must be 0700, got {mode:o}");
    }

    #[test]
    fn local_index_cache_clear_wipes_only_this_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), LOCAL_INDEX_CACHE_BYTES_DEFAULT);
        let archive = write_archive(dir.path(), "a.tar", b"x");
        let sibling = dir.path().join("a.tar.index.sqlite");
        fs::write(&sibling, b"sib").unwrap();
        let sqlite = cache.allocate(&archive).unwrap();
        fs::write(&sqlite, b"idx").unwrap();
        cache.clear().unwrap();
        assert!(
            !cache.dir.exists() || fs::read_dir(&cache.dir).map(|i| i.count()).unwrap_or(0) == 0
        );
        assert_eq!(fs::read(&sibling).unwrap(), b"sib");
    }

    #[test]
    fn local_index_cache_disabled_budget_skips_store() {
        let dir = tempfile::tempdir().unwrap();
        let cache = LocalIndexCache {
            dir: dir.path().join(LOCAL_INDEX_V1_DIRNAME),
            budget: None,
        };
        let archive = write_archive(dir.path(), "a.tar", b"x");
        assert!(cache.lookup(&archive).is_none());
        let err = cache.allocate(&archive).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("local-index-v1"), "{msg}");
        assert!(msg.contains("not meta-v3"), "{msg}");
        assert!(!cache.dir.exists());
    }

    /// Regression: UserCache URL pins `{hex}.sqlite`, not flattened XDG `http:__*`.
    #[test]
    fn local_index_resolve_user_cache_url_pins_sha256_not_flattened() {
        let _g = crate::meta_cache::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let cache_dir = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        let old_dir = std::env::var_os(LOCAL_INDEX_DIR_ENV);
        let old_xdg = std::env::var_os("XDG_CACHE_HOME");
        std::env::set_var(LOCAL_INDEX_DIR_ENV, cache_dir.path());
        std::env::set_var("XDG_CACHE_HOME", xdg.path());
        let archive = Path::new("https://example.invalid/a.tar");
        let loc = resolve_user_cache_index_location(archive, &[], false).unwrap();
        let p = loc.as_path().unwrap().to_path_buf();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let flattened = possible_index_paths(archive, &[xdg.path().join("ratarmount")]);
        let flattened_exists = flattened.iter().any(|f| f.exists());
        let mkdir_https = Path::new("https:").exists();
        match old_dir {
            Some(v) => std::env::set_var(LOCAL_INDEX_DIR_ENV, v),
            None => std::env::remove_var(LOCAL_INDEX_DIR_ENV),
        }
        match old_xdg {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }
        assert!(p.starts_with(cache_dir.path()), "{}", p.display());
        let hex = name.strip_suffix(".sqlite").unwrap_or("");
        assert_eq!(hex.len(), 64, "{name}");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
        assert!(!name.contains("http"), "{name}");
        assert!(
            !flattened_exists,
            "must not write flattened XDG {flattened:?}"
        );
        assert!(!mkdir_https, "must not mkdir URL parents");
        assert!(!is_meta_cache_path(&p), "{}", p.display());
    }

    /// Regression: two published sqlites over the cap drop the oldest without a third key.
    #[test]
    fn local_index_cache_enforce_budget_after_publish_without_third_key() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), 4);
        let a = write_archive(dir.path(), "a.tar", b"aaaa");
        let b = write_archive(dir.path(), "b.tar", b"bbbb");
        let pa = cache.allocate(&a).unwrap();
        fs::write(&pa, b"aaaa").unwrap();
        let pb = cache.allocate(&b).unwrap();
        fs::write(&pb, b"bbbb").unwrap();
        set_last_open(&cache, &pa, 100);
        set_last_open(&cache, &pb, 1);
        cache.lookup(&a).unwrap();
        assert!(pa.is_file(), "newer a must survive lookup trim");
        assert!(
            !pb.is_file(),
            "oldest b must be evicted on lookup without allocating a third key"
        );
    }

    #[test]
    fn local_index_identity_differs_for_distinct_archives() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(dir.path(), LOCAL_INDEX_CACHE_BYTES_DEFAULT);
        let a = write_archive(dir.path(), "a.tar", b"same");
        let b = write_archive(dir.path(), "b.tar", b"same");
        let pa = cache.allocate(&a).unwrap();
        let pb = cache.allocate(&b).unwrap();
        assert_ne!(pa, pb, "path is part of the identity key");
    }

    #[test]
    fn local_index_from_env_override_dir_is_not_meta_v3() {
        let _g = crate::meta_cache::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let cache_dir = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        let old_dir = std::env::var_os(LOCAL_INDEX_DIR_ENV);
        let old_xdg = std::env::var_os("XDG_CACHE_HOME");
        std::env::set_var(LOCAL_INDEX_DIR_ENV, cache_dir.path());
        std::env::set_var("XDG_CACHE_HOME", xdg.path());
        let archive_dir = tempfile::tempdir().unwrap();
        let archive = write_archive(archive_dir.path(), "a.tar", b"x");
        let loc = resolve_user_cache_index_location(&archive, &[], false).unwrap();
        let p = loc.as_path().unwrap().to_path_buf();
        let under_override = p.starts_with(cache_dir.path());
        let in_meta = is_meta_cache_path(&p);
        let meta_v3 = xdg.path().join("ratarmount").join("meta-v3");
        let meta_empty = !meta_v3.exists()
            || fs::read_dir(&meta_v3)
                .map(|it| it.count() == 0)
                .unwrap_or(true);
        match old_dir {
            Some(v) => std::env::set_var(LOCAL_INDEX_DIR_ENV, v),
            None => std::env::remove_var(LOCAL_INDEX_DIR_ENV),
        }
        match old_xdg {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }
        assert!(under_override, "{}", p.display());
        assert!(!in_meta, "{}", p.display());
        assert!(meta_empty, "from_env UserCache must not write meta-v3");
    }

    #[test]
    fn local_index_extra_dirs_win_over_cache() {
        let dir = tempfile::tempdir().unwrap();
        let extra = tempfile::tempdir().unwrap();
        let archive = write_archive(dir.path(), "a.tar", b"x");
        let candidates = possible_index_paths(&archive, &[extra.path().to_path_buf()]);
        fs::write(&candidates[0], b"EXTRA").unwrap();
        let loc = resolve_user_cache_index_location(&archive, &[extra.path().to_path_buf()], false)
            .unwrap();
        assert_eq!(loc, IndexLocation::Path(candidates[0].clone()));
        assert!(!is_meta_cache_path(&candidates[0]));
    }
}
