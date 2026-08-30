//! SQLite index compatible with Python `ratarmountcore.SQLiteIndex` (v0.7.0).
//!
//! Portable HTTP/OCI blobs use [`INDEX_MEDIA_TYPE`] (`v1` = this SQLite sidecar
//! family). That is distinct from [`INDEX_VERSION`] (`"0.7.0"` = `files` schema)
//! and is not SOCI / eStargz / nydus zTOC.
//!
//! Locate over `files` is [`SqliteIndex::search`] (glob/LIKE by default). Optional
//! FTS5 is [`SqliteIndex::ensure_fts5`] + [`SqliteIndex::search_fts`]. Workspace
//! rusqlite 0.32 has no `fts5` cargo feature; bundled libsqlite3-sys always
//! compiles `SQLITE_ENABLE_FTS5`, so FTS5 cannot be compiled out. [`INDEX_VERSION`]
//! stays `"0.7.0"`. Normal [`SqliteIndex::create_writable`] / cold index does
//! **not** create `"files_fts"`.

mod dirent_order;
mod hashing;
mod location;
mod mem;
mod meta_cache;
mod nested;
mod patch;
mod search;

pub use dirent_order::{cmp_offset_then_name, DirentOrder, VisibleMember};
pub use hashing::{
    compute_hashes_limited, fill_content_hashes, hash_hex, normalize_algorithm, sha256_hex,
    sha256_hex_stream, HASH_STREAM_CHUNK, SUPPORTED_HASH_ALGORITHMS,
};
pub use location::{
    archive_base_from_index_path, bind_local_index_id, default_index_folders, default_index_path,
    expand_user, index_id_path, index_pointer_path, index_pointer_path_for_index_file,
    is_index_url, load_index_pointer, materialize_index_file, maybe_fetch_index_url,
    object_store_sibling_index_candidates, parse_index_folders, parse_index_id,
    parse_index_pointer_json, parse_link_describedby, possible_index_paths, prune_index_snapshots,
    publish_index_pointer, resolve_index_id_path, resolve_index_location, sibling_index_candidates,
    sibling_index_id_candidates, sibling_index_id_url, sibling_index_pointer_url,
    sibling_index_url, snapshot_index_id, store_index_pointer_atomic, IndexLocation, IndexPointer,
    INDEX_ID_HEX_LEN, INDEX_LINK_REL, INDEX_MEDIA_TYPE, INDEX_POINTER_KEEP_LAST,
    INDEX_POINTER_SCHEMA, MEMORY_INDEX,
};
pub use meta_cache::{
    cache_identity, invalidate_meta_cache_file, invalidate_meta_cache_identity, is_meta_cache_path,
    MetaCache, META_CACHE_BYTES_DEFAULT, META_CACHE_BYTES_ENV, META_SIDECAR_WHOLE_MAX,
};
pub use search::{locate_pattern_matches, SearchHit, SearchQuery, DEFAULT_SEARCH_LIMIT};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use ratarmount_core::{
    create_root_file_info, query_normpath, FileInfo, SQLiteIndexedTarUserData, UserData,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use thiserror::Error;

use mem::{mem_index_from_sql_rows, MemIndex, MemIndexBuilder, SqlMemRow, StringPool};
use ratarmount_core::OpenOptions;

pub use mem::{CompactOpenCookie, IndexDirent, DIR_SHARD_COUNT, DIR_SHARD_THRESHOLD};
pub use nested::{
    DurableNestedBlob, DurableSevenZipArchive, DurableSevenZipCoder, DurableSevenZipFileEntry,
    DurableSevenZipFolder, DurableSevenZipPackInfo, DurableZipMember, NestedBodyFingerprint,
    NestedMemberKey, CREATE_NESTED_INDEXES_SQL, NESTED_BLOB_MAGIC, NESTED_BLOB_VERSION,
    NESTED_FINGERPRINT_SAMPLE, NESTED_FORMAT_AR, NESTED_FORMAT_CPIO, NESTED_FORMAT_SEVENZIP,
    NESTED_FORMAT_TAR, NESTED_FORMAT_ZIP, NESTED_INDEXES_TABLE,
};

/// Max `files` rows for which a full MemIndex projection is kept after seal/open.
pub const MEM_INDEX_MAX_FILES: u64 = 500_000;

/// Engine cap for [`SqliteIndex::list_dirents_page`] (`LIMIT`).
pub const MAX_DIR_PAGE: u32 = 10_000;

/// One newest-wins directory row from [`SqliteIndex::list_dirents_page`].
///
/// Unlike [`IndexDirent`], this includes `mtime` (additive SELECT; no schema bump).
#[derive(Clone, Debug, PartialEq)]
pub struct PagedDirent {
    pub name: String,
    pub size: u64,
    pub mode: u32,
    /// Unix seconds as stored (`files.mtime` REAL). `None` if the column is NULL.
    pub mtime: Option<f64>,
    /// Header offset; `-1` when SQL stored NULL.
    pub offsetheader: i64,
    pub linkname: String,
}

/// Must match Python `SQLiteIndex.__version__` (`files` schema).
///
/// Distinct from [`INDEX_MEDIA_TYPE`] (`v1` blob family). Additive Rust-only
/// tables such as `"files_fts"` (see [`SqliteIndex::ensure_fts5`]) do not bump
/// this string. Python ignores unknown tables. FTS5 is compiled into bundled
/// sqlite (`SQLITE_ENABLE_FTS5`); rusqlite 0.32 has no `fts5` cargo feature.
pub const INDEX_VERSION: &str = "0.7.0";

/// Embedded core schema (`create-index-tables.sql`). Compression side tables are runtime-only
/// (same as Python: created lazily / on open-write, not in the base SQL script).
pub const CREATE_TABLES_SQL: &str = include_str!("../create-index-tables.sql");

/// Python `SQLiteIndex` compression side-table names.
///
/// Schemas (Python `synchronize_compression_offsets` / `_store_gzip_index`):
/// - `gzipindex` / `gzipindexes` / `gztoolindex`: `( data BLOB )` — one or more opaque
///   indexed_gzip / rapidgzip / gztool seek-index blobs.
/// - `bzip2blocks` / `zstdblocks`: `( blockoffset INTEGER PRIMARY KEY, dataoffset INTEGER )`.
///
/// **Note:** Importing these blobs into seekable gzip/zstd/bzip2 decoder backends is a
/// follow-up (storage + schema parity only in this crate).
pub const COMPRESSION_TABLE_GZIPINDEX: &str = "gzipindex";
pub const COMPRESSION_TABLE_GZIPINDEXES: &str = "gzipindexes";
pub const COMPRESSION_TABLE_GZTOOLINDEX: &str = "gztoolindex";
pub const COMPRESSION_TABLE_BZIP2BLOCKS: &str = "bzip2blocks";
pub const COMPRESSION_TABLE_ZSTDBLOCKS: &str = "zstdblocks";

/// All known compression side-table names (Python `clear_compression_offsets` list).
pub const COMPRESSION_TABLE_NAMES: &[&str] = &[
    COMPRESSION_TABLE_BZIP2BLOCKS,
    COMPRESSION_TABLE_GZIPINDEX,
    COMPRESSION_TABLE_GZIPINDEXES,
    COMPRESSION_TABLE_GZTOOLINDEX,
    COMPRESSION_TABLE_ZSTDBLOCKS,
];

/// CREATE IF NOT EXISTS for compression side tables (Python runtime DDL).
pub const CREATE_COMPRESSION_TABLES_SQL: &str = r#"
/* indexed_gzip / rapidgzip multi-blob and single-blob seek indexes */
CREATE TABLE IF NOT EXISTS "gzipindex" ( "data" BLOB );
CREATE TABLE IF NOT EXISTS "gzipindexes" ( "data" BLOB );
/* rapidgzip gztool-format seek index (1+ blobs) */
CREATE TABLE IF NOT EXISTS "gztoolindex" ( "data" BLOB );
/* bzip2 / zstd block → data offset maps */
CREATE TABLE IF NOT EXISTS "bzip2blocks" (
    "blockoffset" INTEGER PRIMARY KEY,
    "dataoffset" INTEGER
);
CREATE TABLE IF NOT EXISTS "zstdblocks" (
    "blockoffset" INTEGER PRIMARY KEY,
    "dataoffset" INTEGER
);
/* Nested archive durable indexes (Rust-only; warm remount of embedded ZIP/TAR/7z) */
CREATE TABLE IF NOT EXISTS "nestedindexes" (
    "member_key" TEXT PRIMARY KEY,
    "body_size" INTEGER NOT NULL,
    "prefix_sha256" TEXT NOT NULL,
    "suffix_sha256" TEXT NOT NULL,
    "mid_sha256" TEXT NOT NULL DEFAULT '',
    "format" TEXT NOT NULL,
    "schema_version" INTEGER NOT NULL,
    "blob" BLOB NOT NULL
);
"#;

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid index: {0}")]
    Invalid(String),
    #[error("mismatching index: {0}")]
    Mismatch(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("remote index: {0}")]
    Remote(String),
    #[error("index is not open")]
    NotOpen,
}

pub type Result<T> = std::result::Result<T, IndexError>;

/// Archive fingerprint stored under the `tarstats` metadata key (Python parity + extension).
///
/// Written when an on-disk index is built so warm reopen can reject a sibling
/// `*.index.sqlite` that no longer matches the archive file (size/mtime/content samples).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarStats {
    pub st_size: u64,
    /// Whole-second mtime (`MetadataExt::mtime` / Python `st_mtime` truncated).
    pub st_mtime: i64,
    /// Nanosecond component when present in the stored JSON.
    pub st_mtime_ns: Option<i64>,
    /// Hex SHA-256 of the first up-to-512 bytes of the archive (Rust extension).
    pub prefix512_sha256: Option<String>,
    /// Hex SHA-256 of the last up-to-512 bytes of the archive (Rust extension).
    pub suffix512_sha256: Option<String>,
    /// Hex SHA-256 of the entire archive when `st_size <= TARSTATS_FULL_HASH_MAX` (Rust extension).
    ///
    /// Catches same-size in-place replaces where only a middle member payload changes
    /// (TAR headers at 0..512 stay identical).
    pub full_sha256: Option<String>,
}

/// Max sample size for archive content fingerprint (first/last of file).
pub const TARSTATS_SAMPLE_BYTES: usize = 512;

/// Archives at or below this size store a full-file SHA-256 in `tarstats` (cheap).
pub const TARSTATS_FULL_HASH_MAX: u64 = 256 * 1024;

/// Parse Python/Rust `tarstats` JSON (`st_size`, `st_mtime`, optional samples).
pub fn parse_tarstats_json(json: &str) -> Result<TarStats> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| IndexError::Invalid(format!("tarstats JSON parse failed: {e}")))?;
    let st_size = v
        .get("st_size")
        .and_then(|x| x.as_u64().or_else(|| x.as_i64().map(|i| i as u64)))
        .ok_or_else(|| IndexError::Invalid("tarstats missing st_size".into()))?;
    // Python may store st_mtime as float; accept number and truncate toward zero.
    let st_mtime = match v.get("st_mtime") {
        Some(serde_json::Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i
            } else if let Some(f) = n.as_f64() {
                f as i64
            } else {
                return Err(IndexError::Invalid("tarstats st_mtime not a number".into()));
            }
        }
        Some(_) => {
            return Err(IndexError::Invalid("tarstats st_mtime not a number".into()));
        }
        None => {
            return Err(IndexError::Invalid("tarstats missing st_mtime".into()));
        }
    };
    let st_mtime_ns = v.get("st_mtime_ns").and_then(|x| {
        x.as_i64()
            .or_else(|| x.as_u64().map(|u| u as i64))
            .or_else(|| x.as_f64().map(|f| f as i64))
    });
    let prefix512_sha256 = v
        .get("prefix512_sha256")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let suffix512_sha256 = v
        .get("suffix512_sha256")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let full_sha256 = v
        .get("full_sha256")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    Ok(TarStats {
        st_size,
        st_mtime,
        st_mtime_ns,
        prefix512_sha256,
        suffix512_sha256,
        full_sha256,
    })
}

/// Build [`TarStats`] from filesystem metadata (Unix `st_size` / `st_mtime`), without content samples.
pub fn tar_stats_from_metadata(meta: &std::fs::Metadata) -> TarStats {
    use std::os::unix::fs::MetadataExt;
    TarStats {
        st_size: meta.size(),
        st_mtime: meta.mtime(),
        st_mtime_ns: Some(meta.mtime_nsec()),
        prefix512_sha256: None,
        suffix512_sha256: None,
        full_sha256: None,
    }
}

/// SHA-256 hex of the first and last up-to-[`TARSTATS_SAMPLE_BYTES`] of `path`.
pub fn archive_edge_hashes(path: &Path) -> Result<(String, String)> {
    use std::io::{Seek, SeekFrom};

    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut buf = [0u8; TARSTATS_SAMPLE_BYTES];
    let prefix_len = TARSTATS_SAMPLE_BYTES.min(len as usize);
    let prefix_hex = hashing::sha256_hex_window(&mut f, &mut buf, prefix_len)?;

    let suffix_hex = if len == 0 || len as usize <= TARSTATS_SAMPLE_BYTES {
        prefix_hex.clone()
    } else {
        f.seek(SeekFrom::End(-(TARSTATS_SAMPLE_BYTES as i64)))?;
        hashing::sha256_hex_window(&mut f, &mut buf, TARSTATS_SAMPLE_BYTES)?
    };
    Ok((prefix_hex, suffix_hex))
}

/// Full-file SHA-256 when `path` is at most [`TARSTATS_FULL_HASH_MAX`] bytes.
///
/// Streams until EOF (no second size cap, no file-sized `Vec`). Policy cap is
/// the `st_size` gate only — do not change [`TARSTATS_FULL_HASH_MAX`].
pub fn archive_full_hash(path: &Path) -> Result<Option<String>> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > TARSTATS_FULL_HASH_MAX {
        return Ok(None);
    }
    Ok(Some(hashing::sha256_hex_stream(&mut f)?))
}

/// Full fingerprint: metadata + content samples (edges; full hash when small).
pub fn tar_stats_from_path(path: &Path) -> Result<TarStats> {
    let meta = std::fs::metadata(path)?;
    let mut stats = tar_stats_from_metadata(&meta);
    match archive_edge_hashes(path) {
        Ok((p, s)) => {
            stats.prefix512_sha256 = Some(p);
            stats.suffix512_sha256 = Some(s);
        }
        Err(e) => {
            // Still store size/mtime; warm open may only get partial protection.
            log::warn!("tarstats: could not hash edges of {}: {e}", path.display());
        }
    }
    match archive_full_hash(path) {
        Ok(h) => stats.full_sha256 = h,
        Err(e) => {
            log::warn!("tarstats: could not full-hash {}: {e}", path.display());
        }
    }
    Ok(stats)
}

/// Compare hex SHA-256 fingerprints without requiring a matching case.
fn tarstats_hex_eq(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Validate stored `tarstats` against a remote archive fingerprint (HTTP Range /
/// OCI layer size).
///
/// Path-based [`SqliteIndex::check_tarstats_matches_archive`] is a **no-op** when
/// `archive_path` does not exist (URL labels, `oci:{digest}`). After materializing
/// a remote sidecar, call this so a swapped catalog is not trusted.
///
/// * `st_size` is `Content-Length` / Range length / OCI layer `size`.
/// * Edge hashes are SHA-256 hex of the first and last up-to-[`TARSTATS_SAMPLE_BYTES`].
/// * When `st_size <= TARSTATS_FULL_HASH_MAX`, pass `full_sha256`.
///
/// Mismatch → [`IndexError::Mismatch`] (caller cold-indexes; fail-open).
pub fn check_tarstats_matches_remote(
    stored: &TarStats,
    st_size: u64,
    prefix512_sha256: Option<&str>,
    suffix512_sha256: Option<&str>,
    full_sha256: Option<&str>,
) -> Result<()> {
    if stored.st_size != st_size {
        return Err(IndexError::Mismatch(format!(
            "remote archive size mismatch: index tarstats st_size={} current={st_size}",
            stored.st_size
        )));
    }

    let use_full = stored.full_sha256.is_some()
        && (st_size <= TARSTATS_FULL_HASH_MAX || full_sha256.is_some());
    if use_full {
        match (stored.full_sha256.as_deref(), full_sha256) {
            (Some(want), Some(got)) if tarstats_hex_eq(want, got) => {}
            (Some(_), Some(_)) => {
                return Err(IndexError::Mismatch(
                    "remote archive full content fingerprint mismatch".into(),
                ));
            }
            (Some(_), None) => {
                return Err(IndexError::Mismatch(
                    "remote archive full content fingerprint unavailable".into(),
                ));
            }
            (None, _) => {}
        }
        return Ok(());
    }

    if let Some(want) = stored.prefix512_sha256.as_deref() {
        match prefix512_sha256 {
            Some(got) if tarstats_hex_eq(want, got) => {}
            Some(_) => {
                return Err(IndexError::Mismatch(
                    "remote archive prefix fingerprint mismatch".into(),
                ));
            }
            None => {
                return Err(IndexError::Mismatch(
                    "remote archive prefix fingerprint unavailable".into(),
                ));
            }
        }
    }
    if let Some(want) = stored.suffix512_sha256.as_deref() {
        match suffix512_sha256 {
            Some(got) if tarstats_hex_eq(want, got) => {}
            Some(_) => {
                return Err(IndexError::Mismatch(
                    "remote archive suffix fingerprint mismatch".into(),
                ));
            }
            None => {
                return Err(IndexError::Mismatch(
                    "remote archive suffix fingerprint unavailable".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Serialize [`TarStats`] to the compact JSON form used by format builders.
pub fn serialize_tarstats(stats: &TarStats) -> String {
    let mut obj = serde_json::json!({
        "st_size": stats.st_size,
        "st_mtime": stats.st_mtime,
    });
    if let Some(ns) = stats.st_mtime_ns {
        obj["st_mtime_ns"] = serde_json::json!(ns);
    }
    if let Some(ref p) = stats.prefix512_sha256 {
        obj["prefix512_sha256"] = serde_json::json!(p);
    }
    if let Some(ref s) = stats.suffix512_sha256 {
        obj["suffix512_sha256"] = serde_json::json!(s);
    }
    if let Some(ref f) = stats.full_sha256 {
        obj["full_sha256"] = serde_json::json!(f);
    }
    obj.to_string()
}

/// Open and query an existing ratarmount SQLite index.
///
/// Connection is behind a `Mutex` so the type is `Sync` for FUSE multi-threaded callbacks.
/// Read-only opens load a compact in-memory projection (string pool + fixed rows) when
/// the table is not huge. Cold builds fill that projection at insert time via
/// [`MemIndexBuilder`] so seal does not re-scan SQLite into fat `FileInfo` maps.
pub struct SqliteIndex {
    path: Option<PathBuf>,
    conn: Mutex<Connection>,
    read_only: bool,
    mem: Option<MemIndex>,
    /// Populated during [`create_writable`] inserts; taken at seal into [`Self::mem`].
    mem_builder: Mutex<Option<MemIndexBuilder>>,
    /// Nested compact-only: no SQLite `files` rows; MemIndex is the sole file table.
    compact_only: bool,
    /// Well-known dest while [`Self::path`] is `{dest}.tmp.{pid}`. `None` after
    /// [`Self::publish_tmp`], for `:memory:`, compact-only, and in-place
    /// [`Self::open_writable`]. Drop of an unpublished tmp unlinks tmp only.
    publish_target: Option<PathBuf>,
}

/// Monotonic suffix so two [`SqliteIndex::create_writable`] calls in one process
/// do not share `{dest}.tmp.{pid}`.
static WRITABLE_TMP_SEQ: AtomicU32 = AtomicU32::new(0);

/// Staging path for a cold writable build: `{dest}.tmp.{pid}.{seq}` next to dest.
fn writable_tmp_path(dest: &Path) -> PathBuf {
    let seq = WRITABLE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut s = dest.as_os_str().to_os_string();
    s.push(format!(".tmp.{}.{}", std::process::id(), seq));
    PathBuf::from(s)
}

fn sqlite_path_companion(db: &Path, suffix: &str) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Unlink path-keyed SQLite journals only — never the database file itself.
fn unlink_sqlite_journals(path: &Path) {
    let _ = std::fs::remove_file(sqlite_path_companion(path, "-wal"));
    let _ = std::fs::remove_file(sqlite_path_companion(path, "-shm"));
    let _ = std::fs::remove_file(sqlite_path_companion(path, "-journal"));
}

fn unlink_sqlite_path_and_journals(path: &Path) {
    let _ = std::fs::remove_file(path);
    unlink_sqlite_journals(path);
}

fn pid_is_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true
    }
}

/// `{pid}` or `{pid}.{seq}` after `{dest}.tmp.`. Rejects `-wal` / `-shm` suffixes.
fn parse_writable_tmp_pid(rest: &str) -> Option<u32> {
    let mut parts = rest.split('.');
    let pid = parts.next()?.parse().ok()?;
    match parts.next() {
        None => Some(pid),
        Some(seq) if seq.parse::<u32>().is_ok() && parts.next().is_none() => Some(pid),
        _ => None,
    }
}

/// Whether this process still has `path` open (a live [`SqliteIndex`] tmp).
/// Fail-closed: if fds cannot be inspected, treat as held.
fn path_held_by_this_process(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let Ok(rd) = std::fs::read_dir("/proc/self/fd") else {
            return true;
        };
        for ent in rd.flatten() {
            let Ok(link) = std::fs::read_link(ent.path()) else {
                continue;
            };
            if link == target || link == *path {
                return true;
            }
            if let Ok(canon) = std::fs::canonicalize(&link) {
                if canon == target {
                    return true;
                }
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        true
    }
}

/// Best-effort unlink of disconnected `{dest}.tmp.*` leftovers (dead pid, or
/// same-pid with no open fd). Never unlinks a live tmp held by this or another
/// process. Unique `{pid}.{seq}` names mean a second in-process writer does not
/// need to steal the first's file; Drop already unlinks unpublished tmp.
fn reap_stale_writable_tmps(dest: &Path) {
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let Some(name) = dest.file_name() else {
        return;
    };
    let mut prefix = name.to_os_string();
    prefix.push(".tmp.");
    let prefix = prefix.to_string_lossy().into_owned();
    let Ok(rd) = std::fs::read_dir(parent) else {
        return;
    };
    let self_pid = std::process::id();
    for ent in rd.flatten() {
        let fname = ent.file_name();
        let fname = fname.to_string_lossy();
        let Some(rest) = fname.strip_prefix(&prefix) else {
            continue;
        };
        let Some(pid) = parse_writable_tmp_pid(rest) else {
            continue;
        };
        let path = ent.path();
        if pid == self_pid {
            if path_held_by_this_process(&path) {
                continue;
            }
            unlink_sqlite_path_and_journals(&path);
        } else if !pid_is_alive(pid) {
            unlink_sqlite_path_and_journals(&path);
        }
    }
}

impl SqliteIndex {
    /// Open an existing index file read-only (Phase 0).
    ///
    /// Prints the Python harness line and loads a compact [`MemIndex`] when the
    /// row count is within [`MEM_INDEX_MAX_FILES`]. Session paging uses
    /// [`Self::open_catalog_read_only`] instead.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_read_only_inner(path, true, true)
    }

    /// SQL-only read-only catalog. No stdout. `mem` stays `None`. Still
    /// [`Self::validate_loaded`].
    pub fn open_catalog_read_only(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_read_only_inner(path, false, false)
    }

    fn open_read_only_inner(
        path: impl AsRef<Path>,
        announce: bool,
        load_mem: bool,
    ) -> Result<Self> {
        let path = path.as_ref();
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // Favor lookup/list latency on warm mounts (find / getattr storms).
        conn.execute_batch(
            r#"
            PRAGMA temp_store = MEMORY;
            PRAGMA cache_size = -65536;
            PRAGMA mmap_size = 268435456;
            PRAGMA query_only = ON;
            "#,
        )?;
        let mut idx = Self {
            path: Some(path.to_path_buf()),
            conn: Mutex::new(conn),
            read_only: true,
            mem: None,
            mem_builder: Mutex::new(None),
            compact_only: false,
            publish_target: None,
        };
        idx.validate_loaded()?;
        if load_mem {
            if let Ok(n) = idx.file_count_db() {
                if n > 0 && n <= MEM_INDEX_MAX_FILES {
                    idx.mem = Some(idx.load_mem_index()?);
                }
            }
        }
        if announce {
            // Harness contract: Python prints this when logger level is WARNING+
            println!(
                "Successfully loaded offset dictionary from {}",
                path.display()
            );
        }
        Ok(idx)
    }

    /// Create a new writable index at `path` (or `:memory:`).
    ///
    /// Applies Python-compatible bulk-build PRAGMAs (exclusive lock, memory temp,
    /// journal off, synchronous off) so cold index creation stays fast.
    ///
    /// On-disk: opens `{dest}.tmp.{pid}.{seq}` in dest's directory and does **not**
    /// unlink dest. Inserts go to tmp until [`Self::publish_tmp`] /
    /// [`Self::into_read_only`]. Drop of an unpublished tmp unlinks tmp and
    /// leaves dest (stricter than the old `remove_file` dest at create).
    ///
    /// Also starts a [`MemIndexBuilder`] so path/name strings are interned and
    /// compact rows are filled at insert time (no fat dual maps at seal).
    pub fn create_writable(path: Option<&Path>) -> Result<Self> {
        let (conn, path_buf, publish_target) = match path {
            Some(dest) => {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // Concurrent readers keep dest's inode; do not remove_file dest.
                reap_stale_writable_tmps(dest);
                let tmp = writable_tmp_path(dest);
                (Connection::open(&tmp)?, Some(tmp), Some(dest.to_path_buf()))
            }
            None => (Connection::open_in_memory()?, None, None),
        };
        // Match Python `SQLiteIndex._open_sql_db` — large speedup for bulk inserts.
        conn.execute_batch(
            r#"
            PRAGMA locking_mode = EXCLUSIVE;
            PRAGMA temp_store = MEMORY;
            PRAGMA journal_mode = OFF;
            PRAGMA synchronous = OFF;
            "#,
        )?;
        conn.execute_batch(CREATE_TABLES_SQL)?;
        // Python creates compression side tables lazily; we ensure them on build so
        // writers can store seek indexes without a separate ensure step.
        conn.execute_batch(CREATE_COMPRESSION_TABLES_SQL)?;
        Ok(Self {
            path: path_buf,
            conn: Mutex::new(conn),
            read_only: false,
            mem: None,
            mem_builder: Mutex::new(Some(MemIndexBuilder::new())),
            compact_only: false,
            publish_target,
        })
    }

    /// Nested file table: compact MemIndex only — **no** SQLite `files` inserts.
    ///
    /// Used by nested AutoMount reader opens. Top-level warm remount still uses
    /// [`create_writable`] / on-disk SQLite.
    pub fn create_compact_only() -> Result<Self> {
        // Minimal in-memory SQLite shell so metadata helpers that touch `conn` stay
        // safe; the `files` table is never written for compact-only indexes.
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(CREATE_TABLES_SQL)?;
        Ok(Self {
            path: None,
            conn: Mutex::new(conn),
            read_only: false,
            mem: None,
            mem_builder: Mutex::new(Some(MemIndexBuilder::new())),
            compact_only: true,
            publish_target: None,
        })
    }

    /// Create index for a format open: compact-only when
    /// [`OpenOptions::index_compact_only`], else path / `:memory:` SQLite.
    pub fn create_writable_for_open(
        index_path: Option<&Path>,
        options: &OpenOptions,
    ) -> Result<Self> {
        if options.index_compact_only {
            return Self::create_compact_only();
        }
        if options.index_in_memory {
            return Self::create_writable(None);
        }
        if let Some(p) = index_path {
            return Self::create_writable(Some(p));
        }
        Self::create_writable(None)
    }

    fn file_count_db(&self) -> Result<u64> {
        if self.compact_only {
            return Ok(0);
        }
        self.with_conn(|conn| {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM \"files\"", [], |r| r.get(0))?;
            Ok(n as u64)
        })
    }

    /// Load compact MemIndex from SQLite (warm open / path without builder).
    fn load_mem_index(&self) -> Result<MemIndex> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                       uid, gid, istar, issparse, isgenerated, recursiondepth
                FROM "files"
                ORDER BY path, name, offsetheader
                "#,
            )?;
            let mut sql_rows = Vec::new();
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let path: String = row.get(0)?;
                let name: String = row.get(1)?;
                if name.is_empty() {
                    continue;
                }
                // NULL offsetheader (Python-written non-TAR rows) must not
                // fail the whole warm open; -1 is the MemIndex "none" sentinel.
                let offsetheader: Option<i64> = row.get(2)?;
                let offsetheader = offsetheader.unwrap_or(-1);
                let offset: i64 = row.get(3)?;
                let size: i64 = row.get(4)?;
                let mtime: f64 = row.get(5)?;
                let mode: i64 = row.get(6)?;
                let linkname: String = row.get(8).unwrap_or_default();
                let uid: i64 = row.get(9).unwrap_or(0);
                let gid: i64 = row.get(10).unwrap_or(0);
                let istar: bool = row.get::<_, i64>(11).unwrap_or(0) != 0;
                let issparse: bool = row.get::<_, i64>(12).unwrap_or(0) != 0;
                let isgenerated: bool = row.get::<_, i64>(13).unwrap_or(0) != 0;
                let recursiondepth: i64 = row.get(14).unwrap_or(0);
                sql_rows.push(SqlMemRow {
                    path,
                    name,
                    offsetheader,
                    offset: offset.max(0) as u64,
                    size: size.max(0) as u64,
                    mtime,
                    mode: mode as u32,
                    linkname,
                    uid: uid.max(0) as u32,
                    gid: gid.max(0) as u32,
                    istar,
                    issparse,
                    isgenerated,
                    recursiondepth: recursiondepth.max(0) as u32,
                });
            }
            Ok(mem_index_from_sql_rows(sql_rows))
        })
    }

    /// Finalize MemIndex from the insert-time builder, or load from SQLite.
    fn seal_mem_index(&mut self) -> Result<()> {
        if self.mem.is_some() {
            return Ok(());
        }
        let builder = self
            .mem_builder
            .lock()
            .expect("mem_builder mutex poisoned")
            .take();
        if let Some(b) = builder {
            let n = b.count();
            // Compact-only has no SQLite fallback — always seal MemIndex when non-empty.
            if n > 0 && (self.compact_only || n <= MEM_INDEX_MAX_FILES) {
                self.mem = Some(b.finish());
            }
            return Ok(());
        }
        if self.compact_only {
            return Ok(());
        }
        if let Ok(n) = self.file_count_db() {
            if n > 0 && n <= MEM_INDEX_MAX_FILES {
                self.mem = Some(self.load_mem_index()?);
            }
        }
        Ok(())
    }

    /// True when the hot path uses the compact MemIndex projection.
    pub fn has_mem_index(&self) -> bool {
        self.mem.is_some()
    }

    /// Nested compact-only: no SQLite `files` table as the file-table store.
    pub fn is_compact_only(&self) -> bool {
        self.compact_only
    }

    /// SQLite `files` row count (always 0 for compact-only).
    pub fn files_table_row_count(&self) -> Result<u64> {
        self.file_count_db()
    }

    /// Unique interned strings in MemIndex (`None` if no MemIndex).
    pub fn mem_pool_unique_count(&self) -> Option<usize> {
        self.mem.as_ref().map(|m| m.pool_unique_count())
    }

    /// Regression helper: directory path is shared across ≥2 names in MemIndex.
    pub fn mem_dir_path_is_shared(&self, dir: &str) -> bool {
        self.mem.as_ref().is_some_and(|m| m.dir_path_is_shared(dir))
    }

    pub fn mem_uses_path_segments(&self) -> bool {
        self.mem.as_ref().is_some_and(|m| m.uses_path_segments())
    }

    pub fn mem_is_soa_layout(&self) -> bool {
        self.mem.as_ref().is_some_and(|m| m.is_soa_layout())
    }

    pub fn mem_is_dir_sharded(&self) -> bool {
        self.mem.as_ref().is_some_and(|m| m.is_dir_sharded())
    }

    pub fn mem_path_table_is_csr(&self) -> bool {
        self.mem.as_ref().is_some_and(|m| m.path_table_is_csr())
    }

    pub fn mem_pool_is_sealed_slab(&self) -> bool {
        self.mem.as_ref().is_some_and(|m| m.pool_is_sealed_slab())
    }

    /// Compact open cookie without materializing fat [`FileInfo`].
    pub fn lookup_open_cookie(
        &self,
        path: &str,
        file_version: i32,
    ) -> Result<Option<CompactOpenCookie>> {
        let path = query_normpath(path);
        if path == "/" {
            return Ok(None);
        }
        let (dir, name) = split_path(&path);
        if let Some(mem) = &self.mem {
            return Ok(mem.lookup_open_cookie(dir.as_str(), name.as_str(), file_version));
        }
        Ok(None)
    }

    /// Share a pooled string with format sidecars (post-seal, existing only).
    pub fn lookup_pooled_string(&self, s: &str) -> Option<std::sync::Arc<str>> {
        self.mem.as_ref().and_then(|m| m.lookup_pooled(s))
    }

    /// Intern during build so ZIP/7z sidecars share the compact string pool.
    pub fn intern_during_build(&self, s: &str) -> Option<std::sync::Arc<str>> {
        let mut g = self.mem_builder.lock().ok()?;
        Some(g.as_mut()?.intern_shared(s))
    }

    /// Export sealed MemIndex as a durable nested blob (compact rows + fingerprint).
    pub fn export_nested_blob(
        &self,
        format: &str,
        fingerprint: nested::NestedBodyFingerprint,
        zip_members: Vec<nested::DurableZipMember>,
    ) -> Result<Vec<u8>> {
        self.export_nested_blob_with_sidecars(format, fingerprint, zip_members, None)
    }

    /// Export nested blob with optional ZIP / 7z structure sidecars.
    pub fn export_nested_blob_with_sidecars(
        &self,
        format: &str,
        fingerprint: nested::NestedBodyFingerprint,
        zip_members: Vec<nested::DurableZipMember>,
        sevenzip: Option<nested::DurableSevenZipArchive>,
    ) -> Result<Vec<u8>> {
        let mem = self
            .mem
            .as_ref()
            .ok_or_else(|| IndexError::Invalid("no MemIndex to export".into()))?;
        let blob = nested::DurableNestedBlob::from_mem_index_with_sidecars(
            format,
            fingerprint,
            mem,
            zip_members,
            sevenzip,
        );
        blob.to_bytes()
    }

    /// Create a sealed compact-only index from a durable nested blob (import hit).
    pub fn create_compact_from_nested_blob(blob: &nested::DurableNestedBlob) -> Result<Self> {
        let mem = blob.to_mem_index();
        // Minimal shell DB (unused for file table).
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(CREATE_TABLES_SQL)?;
        Ok(Self {
            path: None,
            conn: Mutex::new(conn),
            read_only: true,
            mem: Some(mem),
            mem_builder: Mutex::new(None),
            compact_only: true,
            publish_target: None,
        })
    }

    /// Ensure `nestedindexes` side table exists (outer writable index).
    pub fn ensure_nested_indexes_table(&self) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if self.compact_only {
            return Err(IndexError::Invalid(
                "compact-only index cannot store nestedindexes".into(),
            ));
        }
        self.with_conn(|conn| {
            conn.execute_batch(nested::CREATE_NESTED_INDEXES_SQL)?;
            // Legacy outer indexes created before mid_sha256.
            let _ = conn.execute(
                r#"ALTER TABLE "nestedindexes" ADD COLUMN "mid_sha256" TEXT NOT NULL DEFAULT ''"#,
                [],
            );
            Ok(())
        })
    }

    /// Store a nested durable blob on the outer index (keyed by member identity).
    pub fn set_nested_index(
        &self,
        key: &nested::NestedMemberKey,
        fingerprint: &nested::NestedBodyFingerprint,
        format: &str,
        blob: &[u8],
    ) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.ensure_nested_indexes_table()?;
        let sk = key.storage_key();
        self.with_conn(|conn| {
            // Migrate legacy tables that lack mid_sha256.
            let _ = conn.execute(
                r#"ALTER TABLE "nestedindexes" ADD COLUMN "mid_sha256" TEXT NOT NULL DEFAULT ''"#,
                [],
            );
            conn.execute(
                r#"INSERT OR REPLACE INTO "nestedindexes"
                   (member_key, body_size, prefix_sha256, suffix_sha256, mid_sha256, format, schema_version, blob)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
                params![
                    sk,
                    fingerprint.body_size as i64,
                    fingerprint.prefix_sha256,
                    fingerprint.suffix_sha256,
                    fingerprint.mid_sha256,
                    format,
                    nested::NESTED_BLOB_VERSION as i64,
                    blob,
                ],
            )?;
            Ok(())
        })
    }

    /// Load nested durable blob if present and fingerprint matches.
    pub fn get_nested_index(
        &self,
        key: &nested::NestedMemberKey,
        fingerprint: &nested::NestedBodyFingerprint,
        format: &str,
    ) -> Result<Option<nested::DurableNestedBlob>> {
        if self.compact_only {
            return Ok(None);
        }
        let sk = key.storage_key();
        self.with_conn(|conn| {
            // Table may not exist on legacy indexes.
            let exists: i64 = conn.query_row(
                r#"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='nestedindexes'"#,
                [],
                |r| r.get(0),
            )?;
            if exists == 0 {
                return Ok(None);
            }
            // Prefer mid-aware SELECT; fall back if legacy schema lacks the column.
            type NestedRow = (
                i64,
                String,
                String,
                String,
                String,
                i64,
                Vec<u8>,
            );
            let map_full = |r: &rusqlite::Row<'_>| -> rusqlite::Result<NestedRow> {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            };
            let row: Option<NestedRow> = conn
                .query_row(
                    r#"SELECT body_size, prefix_sha256, suffix_sha256,
                              COALESCE(mid_sha256, ''), format, schema_version, blob
                       FROM "nestedindexes" WHERE member_key = ?1"#,
                    params![sk],
                    map_full,
                )
                .optional()
                .or_else(|_| {
                    conn.query_row(
                        r#"SELECT body_size, prefix_sha256, suffix_sha256, format, schema_version, blob
                           FROM "nestedindexes" WHERE member_key = ?1"#,
                        params![sk],
                        |r| {
                            Ok((
                                r.get(0)?,
                                r.get(1)?,
                                r.get(2)?,
                                String::new(),
                                r.get(3)?,
                                r.get(4)?,
                                r.get(5)?,
                            ))
                        },
                    )
                    .optional()
                })?;
            let Some((sz, pre, suf, mid, fmt, _ver, blob_bytes)) = row else {
                return Ok(None);
            };
            let stored_fp = nested::NestedBodyFingerprint {
                body_size: sz as u64,
                prefix_sha256: pre,
                suffix_sha256: suf,
                mid_sha256: mid,
            };
            if fmt != format || !stored_fp.matches(fingerprint) {
                return Ok(None);
            }
            let blob = nested::DurableNestedBlob::from_bytes(&blob_bytes)?;
            if !blob.is_valid_for(format, fingerprint) {
                return Ok(None);
            }
            Ok(Some(blob))
        })
    }

    /// Whether a nestedindexes row exists for `key` (ignores fingerprint; for tests).
    pub fn has_nested_index_key(&self, key: &nested::NestedMemberKey) -> Result<bool> {
        if self.compact_only {
            return Ok(false);
        }
        let sk = key.storage_key();
        self.with_conn(|conn| {
            let exists: i64 = conn.query_row(
                r#"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='nestedindexes'"#,
                [],
                |r| r.get(0),
            )?;
            if exists == 0 {
                return Ok(false);
            }
            let n: i64 = conn.query_row(
                r#"SELECT COUNT(*) FROM "nestedindexes" WHERE member_key = ?1"#,
                params![sk],
                |r| r.get(0),
            )?;
            Ok(n > 0)
        })
    }

    /// Begin an exclusive write transaction for bulk index builds.
    pub fn begin_write(&self) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if self.compact_only {
            return Ok(());
        }
        self.with_conn(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE")?;
            Ok(())
        })
    }

    /// Commit the current write transaction.
    pub fn commit_write(&self) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if self.compact_only {
            return Ok(());
        }
        self.with_conn(|conn| {
            conn.execute_batch("COMMIT")?;
            Ok(())
        })
    }

    /// Finalize a freshly built index: commit if needed, then reopen is left to caller.
    pub fn finalize_build(&self) -> Result<()> {
        if self.read_only || self.compact_only {
            return Ok(());
        }
        self.with_conn(|conn| {
            // Safe even if no transaction is open (no-op or error ignored).
            let _ = conn.execute_batch("COMMIT");
            // Nudge planner after bulk insert (best-effort).
            let _ = conn.execute_batch("PRAGMA optimize");
            Ok(())
        })
    }

    /// Publish a `{dest}.tmp.{pid}` cold build onto the well-known dest path.
    ///
    /// Close the tmp connection **without** WAL (WAL/shm names follow the path
    /// passed to `Connection::open`, not the directory entry after `rename(2)`),
    /// rename tmp → dest, set [`Self::path`] to dest, open dest, enable WAL, then
    /// reopen dest read-only. No-op for `:memory:`, compact-only, in-place
    /// [`Self::open_writable`], or an already-published index.
    ///
    /// Factory side-table writers call this **after** writes. [`Self::into_read_only`]
    /// calls it when a publish target is set.
    pub fn publish_tmp(&mut self) -> Result<()> {
        if self.publish_target.is_none() || self.compact_only {
            return Ok(());
        }
        if self.read_only {
            self.publish_target = None;
            return Ok(());
        }
        let dest = match self.publish_target.clone() {
            Some(p) => p,
            None => return Ok(()),
        };
        let tmp = match self.path.clone() {
            Some(p) => p,
            None => {
                self.publish_target = None;
                return Ok(());
            }
        };

        self.finalize_build()?;
        self.with_conn(|conn| {
            // Drop intermediary tables so Python's completeness check accepts the index.
            let _ = conn.execute_batch(
                r#"
                DROP TABLE IF EXISTS "filestmp";
                DROP TABLE IF EXISTS "parentfolders";
                "#,
            );
            Ok(())
        })?;

        // Close tmp (journal still OFF). Do not WAL the tmp name.
        {
            let mut guard = self.conn.lock().expect("sqlite mutex poisoned");
            *guard = Connection::open_in_memory()?;
        }
        {
            let f = std::fs::File::open(&tmp)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &dest)?;
        self.publish_target = None;
        self.path = Some(dest.clone());
        // WAL/shm names follow dest's path, not inode. A live reader still holds
        // snapshot N's companions under those names; unlink names (not dest) so
        // the next WAL open creates N+1 companions instead of replaying N.
        unlink_sqlite_journals(&dest);

        {
            let mut guard = self.conn.lock().expect("sqlite mutex poisoned");
            let conn = Connection::open(&dest)?;
            conn.busy_timeout(std::time::Duration::from_secs(10))?;
            conn.execute_batch(
                r#"
                PRAGMA temp_store = MEMORY;
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA locking_mode = NORMAL;
                "#,
            )?;
            // Force an unlock transition if EXCLUSIVE leaked across rename.
            let _: i64 = conn.query_row(r#"SELECT COUNT(*) FROM "files""#, [], |r| r.get(0))?;
            *guard = Connection::open_with_flags(
                &dest,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            guard.execute_batch(
                r#"
                PRAGMA query_only = ON;
                PRAGMA temp_store = MEMORY;
                PRAGMA cache_size = -65536;
                PRAGMA mmap_size = 268435456;
                "#,
            )?;
        }
        self.read_only = true;
        Ok(())
    }

    /// Seal a writable build into a read-only mount index (keeps in-memory DBs alive).
    ///
    /// Prefer this over `drop` + `open_read_only` so `--index-file :memory:` works and
    /// we avoid an extra open syscall for on-disk indexes.
    ///
    /// Promotes the insert-time compact [`MemIndexBuilder`] to the hot MemIndex (string
    /// pool + compact rows) when the row count is within [`MEM_INDEX_MAX_FILES`].
    ///
    /// On-disk tmp builds call [`Self::publish_tmp`] (close tmp, rename, WAL dest).
    /// In-place / `:memory:` indexes leave bulk-build `locking_mode=EXCLUSIVE` /
    /// `journal_mode=OFF` and **reopen** as a true read-only connection. Otherwise
    /// the exclusive file lock is not fully released until the connection is closed,
    /// and factory side-table writers (`open_writable` for gzip/zstd/bzip2 blocks,
    /// `--index-minimum-file-count`) hit `database is locked` while the mount still
    /// holds the index.
    pub fn into_read_only(mut self) -> Result<Self> {
        if self.publish_target.is_some() {
            self.publish_tmp()?;
        } else {
            self.finalize_build()?;
            if !self.read_only {
                if !self.compact_only {
                    let path = self.path.clone();
                    self.with_conn(|conn| {
                        // Drop intermediary tables so Python's completeness check accepts the index.
                        let _ = conn.execute_batch(
                            r#"
                    DROP TABLE IF EXISTS "filestmp";
                    DROP TABLE IF EXISTS "parentfolders";
                    "#,
                        );
                        // Exit bulk-build EXCLUSIVE + journal OFF. WAL allows concurrent RO
                        // (mount) + RW (side tables) opens after we reopen below.
                        let _ = conn.execute_batch(
                            r#"
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;
                    PRAGMA locking_mode = NORMAL;
                    "#,
                        );
                        // Force an unlock transition out of EXCLUSIVE (SQLite defers until unlock).
                        let _: i64 =
                            conn.query_row(r#"SELECT COUNT(*) FROM "files""#, [], |r| r.get(0))?;
                        Ok(())
                    })?;

                    if let Some(ref p) = path {
                        // Close the exclusive-era handle and reopen RO so no exclusive file
                        // lock remains for factory open_writable / discard-index helpers.
                        let mut guard = self.conn.lock().expect("sqlite mutex poisoned");
                        *guard = Connection::open_with_flags(
                            p,
                            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                        )?;
                        guard.execute_batch(
                            r#"
                    PRAGMA query_only = ON;
                    PRAGMA temp_store = MEMORY;
                    PRAGMA cache_size = -65536;
                    PRAGMA mmap_size = 268435456;
                    "#,
                        )?;
                    } else {
                        // Pure :memory: — keep the same connection; no second openers.
                        self.with_conn(|conn| {
                            conn.execute_batch(
                                r#"
                    PRAGMA query_only = ON;
                    PRAGMA temp_store = MEMORY;
                    PRAGMA cache_size = -65536;
                    "#,
                            )?;
                            Ok(())
                        })?;
                    }
                }
                self.read_only = true;
            }
        }
        self.seal_mem_index()?;
        // Compact-only: never keep a SQLite files table as the file store.
        if self.compact_only {
            // Ensure files stays empty (we never insert, but be explicit).
            let _ = self.with_conn(|conn| {
                let _ = conn.execute(r#"DELETE FROM "files""#, []);
                Ok(())
            });
            println!("Successfully loaded compact offset dictionary (no SQLite files table)");
        } else if let Some(path) = &self.path {
            println!(
                "Successfully loaded offset dictionary from {}",
                path.display()
            );
        } else {
            println!("Successfully loaded offset dictionary from :memory:");
        }
        Ok(self)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub(crate) fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        f(&conn)
    }

    fn validate_loaded(&self) -> Result<()> {
        let tables = self.table_names()?;
        if !tables.iter().any(|t| t == "files") {
            return Err(IndexError::Invalid("SQLite index is empty".into()));
        }
        if tables
            .iter()
            .any(|t| t == "filestmp" || t == "parentfolders")
        {
            let has_rows = |name: &str| -> Result<bool> {
                if !tables.iter().any(|t| t == name) {
                    return Ok(false);
                }
                self.with_conn(|conn| {
                    let q = format!("SELECT 1 FROM \"{name}\" LIMIT 1");
                    let mut stmt = conn.prepare(&q)?;
                    Ok(stmt.exists([])?)
                })
            };
            if has_rows("filestmp")? || has_rows("parentfolders")? {
                return Err(IndexError::Invalid("SQLite index is incomplete".into()));
            }
        }
        Ok(())
    }

    fn table_names(&self) -> Result<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT name FROM sqlite_master WHERE type='table' OR type='view'")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn metadata(&self) -> Result<BTreeMap<String, String>> {
        let tables = self.table_names()?;
        if !tables.iter().any(|t| t == "metadata") {
            return Ok(BTreeMap::new());
        }
        self.with_conn(|conn| {
            let mut map = BTreeMap::new();
            let mut stmt = conn.prepare("SELECT key, value FROM metadata")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for r in rows {
                let (k, v) = r?;
                map.insert(k, v);
            }
            Ok(map)
        })
    }

    pub fn backend_name(&self) -> Result<Option<String>> {
        Ok(self.metadata()?.get("backendName").cloned())
    }

    /// Require `backendName` when present (Python `check_metadata_backend`).
    pub fn check_backend_name(&self, expected: &str) -> Result<()> {
        if let Some(name) = self.backend_name()? {
            if name != expected {
                return Err(IndexError::Mismatch(format!(
                    "backendName mismatch: index has {name:?}, expected {expected:?}"
                )));
            }
        }
        Ok(())
    }

    /// Read stored `tarstats` fingerprint, if present.
    pub fn tarstats(&self) -> Result<Option<TarStats>> {
        match self.metadata()?.get("tarstats") {
            Some(json) => Ok(Some(parse_tarstats_json(json)?)),
            None => Ok(None),
        }
    }

    /// Write `tarstats` from live path metadata + edge hashes (no-op when not a real file).
    ///
    /// Used by format builders and compression side-table writers so warm reopen can
    /// reject a stale sibling index after the archive is replaced in place.
    pub fn store_tarstats_for_path(&self, path: &Path) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if !path.exists() {
            return Ok(());
        }
        let stats = tar_stats_from_path(path)?;
        let json = serialize_tarstats(&stats);
        self.store_metadata_key_value("tarstats", &json)
    }

    /// Validate stored `tarstats` against the live archive file (Python `check_archive_stats`).
    ///
    /// Policy (stricter than Python's optional mtime flag; fail closed for silent wrong data):
    /// - No `tarstats` key → `Ok` (legacy indexes / synthetic nested labels without stats).
    /// - `archive_path` does not exist → `Ok` (virtual labels; cannot fingerprint).
    ///   URL / `oci:{digest}` labels hit this no-op; after fetching a remote sidecar
    ///   call [`check_tarstats_matches_remote`] instead.
    /// - Size or whole-second mtime mismatch → [`IndexError::Mismatch`] (caller rebuilds).
    /// - When edge SHA-256 samples are stored, they must match (catches same-size/same-second replaces).
    ///
    /// Call **before** trusting `files` rows or compression side tables (RGZI / zstdblocks /
    /// bzip2blocks) from an on-disk warm index.
    pub fn check_tarstats_matches_archive(&self, archive_path: &Path) -> Result<()> {
        let Some(stored) = self.tarstats()? else {
            return Ok(());
        };
        if !archive_path.exists() {
            return Ok(());
        }
        let meta = std::fs::metadata(archive_path)?;
        let actual_meta = tar_stats_from_metadata(&meta);
        if stored.st_size != actual_meta.st_size {
            return Err(IndexError::Mismatch(format!(
                "archive size mismatch for {}: index tarstats st_size={} current={}",
                archive_path.display(),
                stored.st_size,
                actual_meta.st_size
            )));
        }
        if stored.st_mtime != actual_meta.st_mtime {
            return Err(IndexError::Mismatch(format!(
                "archive mtime mismatch for {}: index tarstats st_mtime={} current={}",
                archive_path.display(),
                stored.st_mtime,
                actual_meta.st_mtime
            )));
        }
        // Content samples: only when present in the index (Python indexes omit them).
        if let Some(ref want_full) = stored.full_sha256 {
            match archive_full_hash(archive_path)? {
                Some(got) if got == *want_full => {}
                Some(_) => {
                    return Err(IndexError::Mismatch(format!(
                        "archive full content fingerprint mismatch for {}",
                        archive_path.display()
                    )));
                }
                None => {
                    // File grew past full-hash threshold while size field still matched
                    // (should not happen if st_size matched); treat as mismatch.
                    return Err(IndexError::Mismatch(format!(
                        "archive full content fingerprint unavailable for {}",
                        archive_path.display()
                    )));
                }
            }
        } else if stored.prefix512_sha256.is_some() || stored.suffix512_sha256.is_some() {
            let (prefix, suffix) = archive_edge_hashes(archive_path)?;
            if let Some(ref want) = stored.prefix512_sha256 {
                if want != &prefix {
                    return Err(IndexError::Mismatch(format!(
                        "archive prefix fingerprint mismatch for {}",
                        archive_path.display()
                    )));
                }
            }
            if let Some(ref want) = stored.suffix512_sha256 {
                if want != &suffix {
                    return Err(IndexError::Mismatch(format!(
                        "archive suffix fingerprint mismatch for {}",
                        archive_path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn file_count(&self) -> Result<u64> {
        if let Some(m) = &self.mem {
            return Ok(m.count());
        }
        self.file_count_db()
    }

    /// Remove the on-disk index when `file_count() < minimum` (`minimum == 0` → no-op).
    ///
    /// Used for B-119 / `--index-minimum-file-count`: small archives keep a live
    /// SQLite connection (unlinked file still works) but leave no sidecar on disk.
    /// Returns `true` when the path was removed (or already missing after the check).
    pub fn discard_on_disk_if_below_minimum(&self, minimum: u64) -> Result<bool> {
        if minimum == 0 {
            return Ok(false);
        }
        let Some(path) = self.path() else {
            return Ok(false);
        };
        let count = self.file_count_db()?;
        if count >= minimum {
            return Ok(false);
        }
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    /// Number of distinct index rows (versions) for `path` (0 if missing).
    pub fn version_count(&self, path: &str) -> Result<u32> {
        let path = query_normpath(path);
        if path == "/" {
            return Ok(1);
        }
        let (dir, name) = split_path(&path);
        if let Some(mem) = &self.mem {
            return Ok(mem.version_count(dir.as_str(), name.as_str()));
        }
        self.with_conn(|conn| {
            let n: i64 = conn.query_row(
                r#"SELECT COUNT(*) FROM "files" WHERE "path" = ?1 AND "name" = ?2"#,
                params![dir, name],
                |r| r.get(0),
            )?;
            Ok(n as u32)
        })
    }

    pub fn lookup(&self, path: &str, file_version: i32) -> Result<Option<FileInfo>> {
        let path = query_normpath(path);
        if path == "/" {
            return Ok(Some(create_root_file_info()));
        }

        let (dir, name) = split_path(&path);

        if let Some(mem) = &self.mem {
            return Ok(mem.lookup(dir.as_str(), name.as_str(), file_version));
        }

        // file_version: 0 = most recent (DESC + offset 0), >0 = oldest-first occurrence
        let (order, offset) = if file_version <= 0 {
            ("DESC", (-file_version) as i64)
        } else {
            ("ASC", (file_version - 1) as i64)
        };

        let sql = format!(
            r#"
            SELECT path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                   uid, gid, istar, issparse, isgenerated, recursiondepth
            FROM "files"
            WHERE "path" = ?1 AND "name" = ?2
            ORDER BY "offsetheader" {order}
            LIMIT 1 OFFSET ?3
            "#
        );
        self.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(&sql)?;
            let row = stmt
                .query_row(params![dir, name, offset], row_to_file_info)
                .optional()?;
            Ok(row)
        })
    }

    /// Directory listing as name → FileInfo (Python `list`).
    ///
    /// Root is stored as SQL path `""` (empty), matching Python
    /// `_query_normpath(path).rstrip('/')` for `"/"`.
    pub fn list(&self, path: &str) -> Result<Option<BTreeMap<String, FileInfo>>> {
        let path = query_normpath(path);
        // "/" -> "" ; "/foo/" -> "/foo"
        let dir = path.trim_end_matches('/').to_string();

        if let Some(mem) = &self.mem {
            return Ok(mem.list(dir.as_str()));
        }

        self.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                r#"
                SELECT name, offsetheader, offset, size, mtime, mode, type, linkname,
                       uid, gid, istar, issparse, isgenerated, recursiondepth
                FROM "files"
                WHERE "path" = ?1
                ORDER BY "offsetheader"
                "#,
            )?;
            let mut map: BTreeMap<String, FileInfo> = BTreeMap::new();
            let mut rows = stmt.query(params![dir])?;
            let mut got = false;
            while let Some(row) = rows.next()? {
                got = true;
                let name: String = row.get(0)?;
                if name.is_empty() {
                    continue;
                }
                let fi = file_info_from_named_row(row)?;
                map.insert(name, fi);
            }
            Ok(if got { Some(map) } else { None })
        })
    }

    pub fn list_mode(&self, path: &str) -> Result<Option<BTreeMap<String, u32>>> {
        match self.list_dirents(path)? {
            Some(dents) => Ok(Some(dents.into_iter().map(|d| (d.name, d.mode)).collect())),
            None => Ok(None),
        }
    }

    /// Cheap readdir: names / modes / sizes / open cookies without fat [`FileInfo`].
    pub fn list_dirents(&self, path: &str) -> Result<Option<Vec<IndexDirent>>> {
        let path = query_normpath(path);
        let dir = path.trim_end_matches('/').to_string();

        if let Some(mem) = &self.mem {
            return Ok(mem.list_dirents(dir.as_str()));
        }

        self.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                r#"
                SELECT name, offsetheader, offset, size, mode, linkname,
                       istar, issparse, isgenerated, recursiondepth
                FROM "files"
                WHERE "path" = ?1
                ORDER BY "offsetheader"
                "#,
            )?;
            let mut by_name: BTreeMap<String, IndexDirent> = BTreeMap::new();
            let mut rows = stmt.query(params![dir])?;
            let mut got = false;
            while let Some(row) = rows.next()? {
                got = true;
                let name: String = row.get(0)?;
                if name.is_empty() {
                    continue;
                }
                // offsetheader is nullable (Python writers leave it NULL for
                // non-TAR rows); read it like list()/lookup() do so one such
                // row cannot fail the whole directory listing. NULL maps to
                // the -1 sentinel (CompactOpenCookie treats < 0 as none).
                let offsetheader: Option<i64> = row.get(1)?;
                let offsetheader = offsetheader.unwrap_or(-1);
                let offset: i64 = row.get(2)?;
                let size: i64 = row.get(3)?;
                let mode: i64 = row.get(4)?;
                let linkname: String = row.get(5).unwrap_or_default();
                let istar: bool = row.get::<_, i64>(6).unwrap_or(0) != 0;
                let issparse: bool = row.get::<_, i64>(7).unwrap_or(0) != 0;
                let isgenerated: bool = row.get::<_, i64>(8).unwrap_or(0) != 0;
                let recursiondepth: i64 = row.get(9).unwrap_or(0);
                let size_u = size.max(0) as u64;
                let mode_u = mode as u32;
                by_name.insert(
                    name.clone(),
                    IndexDirent {
                        name,
                        mode: mode_u,
                        size: size_u,
                        linkname,
                        cookie: CompactOpenCookie {
                            offsetheader,
                            offset: offset.max(0) as u64,
                            size: size_u,
                            mode: mode_u,
                            istar,
                            issparse,
                            isgenerated,
                            recursiondepth: recursiondepth.max(0) as u32,
                        },
                    },
                );
            }
            Ok(if got {
                Some(by_name.into_values().collect())
            } else {
                None
            })
        })
    }

    /// Keyset-paged newest-wins directory listing (dumpdir tombstones omitted).
    ///
    /// Does **not** change [`Self::list_dirents`] (FUSE still sees tombstones).
    /// `limit` is capped at [`MAX_DIR_PAGE`]. `after_name` is exclusive (`name > after`).
    ///
    /// Returns `(page, next_name, total_hint)` where `next_name` is the last name
    /// of a full page (pass as the next `after_name`) and `total_hint` is a cheap
    /// COUNT of newest-wins names in this directory excluding dumpdir rows.
    pub fn list_dirents_page(
        &self,
        path: &str,
        after_name: Option<&str>,
        limit: u32,
    ) -> Result<(Vec<PagedDirent>, Option<String>, Option<u64>)> {
        let path = query_normpath(path);
        let dir = path.trim_end_matches('/').to_string();
        let limit = limit.min(MAX_DIR_PAGE);
        let after = after_name.unwrap_or("");
        let dumpdir = crate::search::DUMPDIR_DELETE_LINKNAME;

        let total_hint = if self.compact_only {
            None
        } else {
            self.with_conn(|conn| {
                let mut stmt = conn.prepare_cached(
                    r#"
                    WITH newest AS (
                      SELECT name, linkname,
                             ROW_NUMBER() OVER (
                               PARTITION BY name
                               ORDER BY COALESCE(offsetheader, -1) DESC, name
                             ) AS rn
                      FROM "files"
                      WHERE "path" = ?1
                        AND "name" != ''
                    )
                    SELECT COUNT(*) FROM newest
                    WHERE rn = 1
                      AND COALESCE(linkname, '') != ?2
                    "#,
                )?;
                let n: i64 = stmt.query_row(params![dir, dumpdir], |r| r.get(0))?;
                Ok(n.max(0) as u64)
            })
            .ok()
        };

        if limit == 0 {
            return Ok((Vec::new(), None, total_hint));
        }

        if self.compact_only {
            return Ok((Vec::new(), None, total_hint));
        }

        let fetch = i64::from(limit).saturating_add(1);
        let mut rows = self.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                r#"
                WITH newest AS (
                  SELECT name, size, mode, mtime, offsetheader, linkname,
                         ROW_NUMBER() OVER (
                           PARTITION BY name
                           ORDER BY COALESCE(offsetheader, -1) DESC, name
                         ) AS rn
                  FROM "files"
                  WHERE "path" = ?1
                    AND "name" != ''
                )
                SELECT name, size, mode, mtime, offsetheader, linkname
                FROM newest
                WHERE rn = 1
                  AND COALESCE(linkname, '') != ?2
                  AND name > ?3
                ORDER BY name
                LIMIT ?4
                "#,
            )?;
            let mut q = stmt.query(params![dir, dumpdir, after, fetch])?;
            let mut out = Vec::new();
            while let Some(row) = q.next()? {
                let name: String = row.get(0)?;
                let size: i64 = row.get(1).unwrap_or(0);
                let mode: i64 = row.get(2).unwrap_or(0);
                let mtime: Option<f64> = row.get(3)?;
                let offsetheader: Option<i64> = row.get(4)?;
                let linkname: String = row.get(5).unwrap_or_default();
                out.push(PagedDirent {
                    name,
                    size: size.max(0) as u64,
                    mode: mode as u32,
                    mtime,
                    offsetheader: offsetheader.unwrap_or(-1),
                    linkname,
                });
            }
            Ok(out)
        })?;

        let next_name = if rows.len() as u32 > limit {
            rows.pop();
            rows.last().map(|r| r.name.clone())
        } else {
            None
        };
        Ok((rows, next_name, total_hint))
    }

    /// Store version rows used by Python writers.
    pub fn store_versions(&self, ratarmount_version: &str) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if self.compact_only {
            let _ = ratarmount_version;
            return Ok(());
        }
        let versions = [("ratarmount", ratarmount_version), ("index", INDEX_VERSION)];
        self.with_conn(|conn| {
            for (name, ver) in versions {
                let parts: Vec<&str> = ver.split('.').collect();
                let major: Option<i64> = parts.first().and_then(|s| {
                    s.chars()
                        .filter(|c| c.is_ascii_digit())
                        .collect::<String>()
                        .parse()
                        .ok()
                });
                let minor: Option<i64> = parts.get(1).and_then(|s| {
                    s.chars()
                        .filter(|c| c.is_ascii_digit())
                        .collect::<String>()
                        .parse()
                        .ok()
                });
                let patch: Option<i64> = parts.get(2).and_then(|s| {
                    s.chars()
                        .filter(|c| c.is_ascii_digit())
                        .collect::<String>()
                        .parse()
                        .ok()
                });
                conn.execute(
                    r#"INSERT OR REPLACE INTO "versions" (name, version, major, minor, patch)
                       VALUES (?1, ?2, ?3, ?4, ?5)"#,
                    params![name, ver, major, minor, patch],
                )?;
            }
            Ok(())
        })
    }

    pub fn store_metadata_key_value(&self, key: &str, value: &str) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if self.compact_only {
            let _ = (key, value);
            return Ok(());
        }
        self.with_conn(|conn| {
            conn.execute(
                r#"INSERT OR REPLACE INTO "metadata" (key, value) VALUES (?1, ?2)"#,
                params![key, value],
            )?;
            Ok(())
        })
    }

    /// SQL `files.type` for the exact PK `(path, name, offsetheader)` (test/debug).
    ///
    /// Newest-only [`lookup`] cannot see dumpdir’s dual rows (`oh` and `oh+1`) or
    /// a nested-as-directory row at `offsetheader+1`. `FileInfo` / MemIndex omit `type`.
    pub fn sql_files_type(&self, path: &str, name: &str, offsetheader: i64) -> Result<Option<i64>> {
        if self.compact_only {
            return Ok(None);
        }
        self.with_conn(|conn| {
            let v: Option<i64> = conn
                .query_row(
                    r#"SELECT type FROM "files"
                       WHERE path = ?1 AND name = ?2 AND offsetheader = ?3"#,
                    params![path, name, offsetheader],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(v)
        })
    }

    /// Insert one files row (used by format builders). Prefer [`insert_files_batch`] for cold index.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_file(
        &self,
        path: &str,
        name: &str,
        offsetheader: i64,
        offset: i64,
        size: i64,
        mtime: f64,
        mode: i64,
        typeflag: i64,
        linkname: &str,
        uid: i64,
        gid: i64,
        istar: bool,
        issparse: bool,
        isgenerated: bool,
        recursiondepth: i64,
    ) -> Result<()> {
        self.insert_files_batch(&[FileRow::new(
            path,
            name,
            offsetheader,
            offset,
            size,
            mtime,
            mode,
            typeflag,
            linkname,
            uid,
            gid,
            istar,
            issparse,
            isgenerated,
            recursiondepth,
        )])
    }

    /// Bulk insert `files` rows with a prepared statement (Python `executemany` path).
    ///
    /// Caller should wrap the whole build in [`begin_write`] / [`commit_write`] for best speed.
    ///
    /// Also feeds the insert-time [`MemIndexBuilder`] (string pool + compact rows) when
    /// this index was created via [`create_writable`].
    ///
    /// Compatibility path for patch/search/ASAR and other formats. TAR/ZIP/7z cold
    /// builds use [`insert_files_batch_soa`] so the flush window is not a `Vec<FileRow>`.
    pub fn insert_files_batch(&self, rows: &[FileRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        // Compact-only nested: MemIndex builder is the sole file-table store.
        if !self.compact_only {
            self.with_conn(|conn| {
                let mut stmt = conn.prepare_cached(INSERT_FILES_SQL)?;
                for r in rows {
                    bind_files_row(
                        &mut stmt,
                        &r.path,
                        &r.name,
                        r.offsetheader,
                        r.offset,
                        r.size,
                        r.mtime,
                        r.mode,
                        r.typeflag,
                        &r.linkname,
                        r.uid,
                        r.gid,
                        r.istar,
                        r.issparse,
                        r.isgenerated,
                        r.recursiondepth,
                    )?;
                }
                Ok(())
            })?;
        }
        // Compact projection at parse/build time (shared path/name segments + SoA).
        if let Ok(mut guard) = self.mem_builder.lock() {
            if let Some(b) = guard.as_mut() {
                b.push_rows(rows);
            }
        }
        Ok(())
    }

    /// Bind the existing single-row `INSERT OR REPLACE` from a [`FileRowSoa`] window.
    ///
    /// Does **not** clear `rows` — callers must [`FileRowSoa::clear`] after each flush
    /// so the window pool stays *O(512)*. Reconstructs one [`FileRow`] at a time only
    /// for [`MemIndexBuilder::push_row`]. Does not allocate a temporary `Vec<FileRow>`.
    pub fn insert_files_batch_soa(&self, rows: &FileRowSoa) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if !self.compact_only {
            self.with_conn(|conn| {
                let mut stmt = conn.prepare_cached(INSERT_FILES_SQL)?;
                for i in 0..rows.len() {
                    bind_files_row(
                        &mut stmt,
                        rows.path_at(i),
                        rows.name_at(i),
                        rows.offsetheader[i],
                        rows.offset[i],
                        rows.size[i],
                        rows.mtime[i],
                        rows.mode[i],
                        rows.typeflag[i],
                        rows.linkname_at(i),
                        rows.uid[i],
                        rows.gid[i],
                        rows.istar[i],
                        rows.issparse[i],
                        rows.isgenerated[i],
                        rows.recursiondepth[i],
                    )?;
                }
                Ok(())
            })?;
        }
        if let Ok(mut guard) = self.mem_builder.lock() {
            if let Some(b) = guard.as_mut() {
                for i in 0..rows.len() {
                    let row = rows.file_row_at(i);
                    b.push_row(&row);
                }
            }
        }
        Ok(())
    }

    /// Open an existing on-disk index for read/write (e.g. to fill content-hash xattrs).
    ///
    /// Does not truncate or recreate the core schema. Ensures compression side tables
    /// exist (`CREATE IF NOT EXISTS`) for Python parity. Fails if the file is missing
    /// or incomplete.
    pub fn open_writable(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        // Brief wait if a concurrent reader is finishing (mount RO + side-table write).
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            r#"
            PRAGMA temp_store = MEMORY;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA locking_mode = NORMAL;
            "#,
        )?;
        conn.execute_batch(CREATE_COMPRESSION_TABLES_SQL)?;
        let idx = Self {
            path: Some(path.to_path_buf()),
            conn: Mutex::new(conn),
            read_only: false,
            mem: None,
            // Existing DB: do not build MemIndex on write; open_read_only loads it.
            mem_builder: Mutex::new(None),
            compact_only: false,
            publish_target: None,
        };
        idx.validate_loaded()?;
        Ok(idx)
    }

    /// Ensure Python compression side tables exist (`CREATE IF NOT EXISTS`).
    ///
    /// Safe to call multiple times. No-op on read-only indexes (returns error).
    pub fn ensure_compression_tables(&self) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.with_conn(|conn| {
            conn.execute_batch(CREATE_COMPRESSION_TABLES_SQL)?;
            Ok(())
        })
    }

    /// Whether a compression side table exists (by name).
    ///
    /// Recognized names: `gzipindex`, `gzipindexes`, `gztoolindex`, `bzip2blocks`,
    /// `zstdblocks` (any other name still checks `sqlite_master`).
    pub fn has_compression_table(&self, name: &str) -> Result<bool> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row(
                r#"SELECT COUNT(*) FROM sqlite_master
                   WHERE (type='table' OR type='view') AND name = ?1"#,
                params![name],
                |r| r.get(0),
            )?;
            Ok(n > 0)
        })
    }

    /// Drop all compression side tables (Python `clear_compression_offsets`).
    pub fn clear_compression_offsets(&self) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.with_conn(|conn| {
            for table in COMPRESSION_TABLE_NAMES {
                conn.execute(&format!("DROP TABLE IF EXISTS \"{table}\""), [])?;
            }
            Ok(())
        })
    }

    /// Read gzip seek-index blobs from `gzipindexes` (preferred) or legacy `gzipindex`.
    ///
    /// Returns row order as stored (append order). Empty if neither table exists or
    /// both are empty. Blobs are opaque (indexed_gzip / rapidgzip compatible); decoder
    /// import is a follow-up outside this crate.
    pub fn get_gzip_index_blobs(&self) -> Result<Vec<Vec<u8>>> {
        if self.has_compression_table(COMPRESSION_TABLE_GZIPINDEXES)? {
            let blobs = self.read_data_blobs(COMPRESSION_TABLE_GZIPINDEXES)?;
            if !blobs.is_empty() {
                return Ok(blobs);
            }
        }
        if self.has_compression_table(COMPRESSION_TABLE_GZIPINDEX)? {
            return self.read_data_blobs(COMPRESSION_TABLE_GZIPINDEX);
        }
        Ok(Vec::new())
    }

    /// Replace gzip seek-index storage with a single blob (Python single-blob path:
    /// table name `gzipindex` for downward compatibility).
    pub fn set_gzip_index_blob(&self, blob: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.with_conn(|conn| {
            conn.execute(
                &format!("DROP TABLE IF EXISTS \"{COMPRESSION_TABLE_GZIPINDEXES}\""),
                [],
            )?;
            conn.execute(
                &format!("DROP TABLE IF EXISTS \"{COMPRESSION_TABLE_GZIPINDEX}\""),
                [],
            )?;
            conn.execute(
                &format!("CREATE TABLE \"{COMPRESSION_TABLE_GZIPINDEX}\" ( \"data\" BLOB )"),
                [],
            )?;
            conn.execute(
                &format!("INSERT INTO \"{COMPRESSION_TABLE_GZIPINDEX}\" (data) VALUES (?1)"),
                params![blob],
            )?;
            Ok(())
        })
    }

    /// Append one gzip seek-index blob to `gzipindexes` (multi-blob path).
    ///
    /// If only legacy `gzipindex` exists with rows, migrates those rows into
    /// `gzipindexes` first (Python stores multi-blob under `gzipindexes`).
    pub fn append_gzip_index_blob(&self, blob: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.with_conn(|conn| {
            let has_indexes = table_exists(conn, COMPRESSION_TABLE_GZIPINDEXES)?;
            let has_index = table_exists(conn, COMPRESSION_TABLE_GZIPINDEX)?;
            if !has_indexes {
                conn.execute(
                    &format!("CREATE TABLE \"{COMPRESSION_TABLE_GZIPINDEXES}\" ( \"data\" BLOB )"),
                    [],
                )?;
                if has_index {
                    // Migrate legacy single-blob rows, then drop singular table.
                    conn.execute(
                        &format!(
                            "INSERT INTO \"{COMPRESSION_TABLE_GZIPINDEXES}\" (data)
                             SELECT data FROM \"{COMPRESSION_TABLE_GZIPINDEX}\""
                        ),
                        [],
                    )?;
                    conn.execute(
                        &format!("DROP TABLE IF EXISTS \"{COMPRESSION_TABLE_GZIPINDEX}\""),
                        [],
                    )?;
                }
            }
            conn.execute(
                &format!("INSERT INTO \"{COMPRESSION_TABLE_GZIPINDEXES}\" (data) VALUES (?1)"),
                params![blob],
            )?;
            Ok(())
        })
    }

    /// Read gztool-format seek-index blobs (`gztoolindex` table).
    pub fn get_gztool_index_blobs(&self) -> Result<Vec<Vec<u8>>> {
        if !self.has_compression_table(COMPRESSION_TABLE_GZTOOLINDEX)? {
            return Ok(Vec::new());
        }
        self.read_data_blobs(COMPRESSION_TABLE_GZTOOLINDEX)
    }

    /// Replace `gztoolindex` with a single blob.
    pub fn set_gztool_index_blob(&self, blob: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.with_conn(|conn| {
            conn.execute(
                &format!("DROP TABLE IF EXISTS \"{COMPRESSION_TABLE_GZTOOLINDEX}\""),
                [],
            )?;
            conn.execute(
                &format!("CREATE TABLE \"{COMPRESSION_TABLE_GZTOOLINDEX}\" ( \"data\" BLOB )"),
                [],
            )?;
            conn.execute(
                &format!("INSERT INTO \"{COMPRESSION_TABLE_GZTOOLINDEX}\" (data) VALUES (?1)"),
                params![blob],
            )?;
            Ok(())
        })
    }

    /// Append one blob to `gztoolindex`.
    pub fn append_gztool_index_blob(&self, blob: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.with_conn(|conn| {
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS \"{COMPRESSION_TABLE_GZTOOLINDEX}\" ( \"data\" BLOB )"
                ),
                [],
            )?;
            conn.execute(
                &format!("INSERT INTO \"{COMPRESSION_TABLE_GZTOOLINDEX}\" (data) VALUES (?1)"),
                params![blob],
            )?;
            Ok(())
        })
    }

    /// Read bzip2 block map as `(blockoffset, dataoffset)` pairs (opaque to this crate).
    pub fn get_bzip2_blocks(&self) -> Result<Vec<(i64, i64)>> {
        self.read_block_offset_table(COMPRESSION_TABLE_BZIP2BLOCKS)
    }

    /// Replace `bzip2blocks` with the given map (Python `CREATE TABLE` + `executemany`).
    pub fn set_bzip2_blocks(&self, blocks: &[(i64, i64)]) -> Result<()> {
        self.write_block_offset_table(COMPRESSION_TABLE_BZIP2BLOCKS, blocks)
    }

    /// Read zstd block map as `(blockoffset, dataoffset)` pairs (opaque to this crate).
    pub fn get_zstd_blocks(&self) -> Result<Vec<(i64, i64)>> {
        self.read_block_offset_table(COMPRESSION_TABLE_ZSTDBLOCKS)
    }

    /// Replace `zstdblocks` with the given map.
    pub fn set_zstd_blocks(&self, blocks: &[(i64, i64)]) -> Result<()> {
        self.write_block_offset_table(COMPRESSION_TABLE_ZSTDBLOCKS, blocks)
    }

    fn read_data_blobs(&self, table: &str) -> Result<Vec<Vec<u8>>> {
        // Table names are internal constants only — never user-controlled.
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&format!("SELECT data FROM \"{table}\" ORDER BY rowid"))?;
            let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    fn read_block_offset_table(&self, table: &str) -> Result<Vec<(i64, i64)>> {
        if !self.has_compression_table(table)? {
            return Ok(Vec::new());
        }
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT blockoffset, dataoffset FROM \"{table}\" ORDER BY blockoffset"
            ))?;
            let rows =
                stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    fn write_block_offset_table(&self, table: &str, blocks: &[(i64, i64)]) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.with_conn(|conn| {
            conn.execute(&format!("DROP TABLE IF EXISTS \"{table}\""), [])?;
            conn.execute(
                &format!(
                    "CREATE TABLE \"{table}\" (
                        \"blockoffset\" INTEGER PRIMARY KEY,
                        \"dataoffset\" INTEGER
                    )"
                ),
                [],
            )?;
            let mut stmt = conn.prepare(&format!("INSERT INTO \"{table}\" VALUES (?1, ?2)"))?;
            for &(blockoffset, dataoffset) in blocks {
                stmt.execute(params![blockoffset, dataoffset])?;
            }
            Ok(())
        })
    }

    /// Insert one xattr via the `xattrs` view (Python `setxattrs` / INSERT trigger).
    ///
    /// Do not use `INSERT OR REPLACE` — it would bypass the instead-of-insert trigger.
    pub fn insert_xattr(&self, offsetheader: i64, key: &str, value: &[u8]) -> Result<()> {
        self.insert_xattrs_batch(&[(offsetheader, key.to_string(), value.to_vec())])
    }

    /// Bulk insert xattrs (Python `executemany('INSERT INTO "xattrs" VALUES (?,?,?)', …)`).
    pub fn insert_xattrs_batch(&self, rows: &[(i64, String, Vec<u8>)]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        self.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                r#"INSERT INTO "xattrs" (offsetheader, key, value) VALUES (?1, ?2, ?3)"#,
            )?;
            for (oh, key, value) in rows {
                stmt.execute(params![oh, key, value])?;
            }
            Ok(())
        })
    }

    /// List xattr keys for a file identified by `offsetheader`.
    pub fn list_xattr_keys(&self, offsetheader: i64) -> Result<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare_cached(r#"SELECT key FROM "xattrs" WHERE offsetheader = ?1"#)?;
            let rows = stmt.query_map(params![offsetheader], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// Get one xattr value by `offsetheader` and key.
    pub fn get_xattr(&self, offsetheader: i64, key: &str) -> Result<Option<Vec<u8>>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                r#"SELECT value FROM "xattrs" WHERE offsetheader = ?1 AND key = ?2"#,
            )?;
            let row = stmt
                .query_row(params![offsetheader, key], |row| row.get::<_, Vec<u8>>(0))
                .optional()?;
            Ok(row)
        })
    }

    /// Regular-file rows eligible for content hashing: `(offsetheader, offset, size)`.
    ///
    /// Matches Python `_compute_and_store_hashes` filters: `S_IFREG`, non-generated,
    /// non-null offsetheader, `size > 0`.
    pub(crate) fn regular_file_payloads(&self) -> Result<Vec<(i64, i64, u64)>> {
        // S_IFREG = 0x8000; S_IFMT = 0xF000
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT offsetheader, offset, size
                FROM "files"
                WHERE size > 0
                  AND (mode & 0xF000) = 0x8000
                  AND offsetheader IS NOT NULL
                  AND NOT isgenerated
                ORDER BY offsetheader ASC
                "#,
            )?;
            let mut rows = stmt.query([])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let oh: i64 = row.get(0)?;
                let off: i64 = row.get(1)?;
                let size: i64 = row.get(2)?;
                if size > 0 {
                    out.push((oh, off, size as u64));
                }
            }
            Ok(out)
        })
    }
}

impl Drop for SqliteIndex {
    fn drop(&mut self) {
        if self.publish_target.take().is_none() {
            return;
        }
        let Some(tmp) = self.path.take() else {
            return;
        };
        // Close the tmp connection before unlink so SQLite is not writing an
        // unlinked name; dest's inode is never removed here.
        if let Ok(mut guard) = self.conn.lock() {
            if let Ok(dummy) = Connection::open_in_memory() {
                *guard = dummy;
            }
        }
        unlink_sqlite_path_and_journals(&tmp);
    }
}

/// Prepared single-row `INSERT OR REPLACE` used by both [`SqliteIndex::insert_files_batch`]
/// and [`SqliteIndex::insert_files_batch_soa`]. Do not change — `create-index-tables.sql`
/// / `INDEX_VERSION` stay 0.7.x.
const INSERT_FILES_SQL: &str = r#"
                INSERT OR REPLACE INTO "files"
                (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                 uid, gid, istar, issparse, isgenerated, recursiondepth)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
                "#;

#[allow(clippy::too_many_arguments)]
fn bind_files_row(
    stmt: &mut rusqlite::CachedStatement<'_>,
    path: &str,
    name: &str,
    offsetheader: i64,
    offset: i64,
    size: i64,
    mtime: f64,
    mode: i64,
    typeflag: i64,
    linkname: &str,
    uid: i64,
    gid: i64,
    istar: bool,
    issparse: bool,
    isgenerated: bool,
    recursiondepth: i64,
) -> rusqlite::Result<()> {
    stmt.execute(params![
        path,
        name,
        offsetheader,
        offset,
        size,
        mtime,
        mode,
        typeflag,
        linkname,
        uid,
        gid,
        istar,
        issparse,
        isgenerated,
        recursiondepth,
    ])?;
    Ok(())
}

/// One row for the `files` table (bulk or single insert).
#[derive(Debug, Clone)]
pub struct FileRow {
    pub path: String,
    pub name: String,
    pub offsetheader: i64,
    pub offset: i64,
    pub size: i64,
    pub mtime: f64,
    pub mode: i64,
    pub typeflag: i64,
    pub linkname: String,
    pub uid: i64,
    pub gid: i64,
    pub istar: bool,
    pub issparse: bool,
    pub isgenerated: bool,
    pub recursiondepth: i64,
}

impl FileRow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: impl Into<String>,
        name: impl Into<String>,
        offsetheader: i64,
        offset: i64,
        size: i64,
        mtime: f64,
        mode: i64,
        typeflag: i64,
        linkname: impl Into<String>,
        uid: i64,
        gid: i64,
        istar: bool,
        issparse: bool,
        isgenerated: bool,
        recursiondepth: i64,
    ) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            offsetheader,
            offset,
            size,
            mtime,
            mode,
            typeflag,
            linkname: linkname.into(),
            uid,
            gid,
            istar,
            issparse,
            isgenerated,
            recursiondepth,
        }
    }
}

/// Build-only SoA flush window for TAR / ZIP / 7z cold index (P2).
///
/// Interns full `path` / `name` / `linkname` TEXT in a **window-local** string pool
/// (`""` → id 0). Not live `EntrySoa` (no `typeflag`, drops empty names, REPLACE
/// is in-place by SoA index). Call [`Self::clear`] after every
/// [`SqliteIndex::insert_files_batch_soa`] so the pool does not grow with the archive.
pub struct FileRowSoa {
    pool: StringPool,
    path_id: Vec<u32>,
    name_id: Vec<u32>,
    linkname_id: Vec<u32>,
    offsetheader: Vec<i64>,
    offset: Vec<i64>,
    size: Vec<i64>,
    mtime: Vec<f64>,
    mode: Vec<i64>,
    typeflag: Vec<i64>,
    uid: Vec<i64>,
    gid: Vec<i64>,
    istar: Vec<bool>,
    issparse: Vec<bool>,
    isgenerated: Vec<bool>,
    recursiondepth: Vec<i64>,
}

impl FileRowSoa {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            pool: StringPool::new(),
            path_id: Vec::with_capacity(n),
            name_id: Vec::with_capacity(n),
            linkname_id: Vec::with_capacity(n),
            offsetheader: Vec::with_capacity(n),
            offset: Vec::with_capacity(n),
            size: Vec::with_capacity(n),
            mtime: Vec::with_capacity(n),
            mode: Vec::with_capacity(n),
            typeflag: Vec::with_capacity(n),
            uid: Vec::with_capacity(n),
            gid: Vec::with_capacity(n),
            istar: Vec::with_capacity(n),
            issparse: Vec::with_capacity(n),
            isgenerated: Vec::with_capacity(n),
            recursiondepth: Vec::with_capacity(n),
        }
    }

    pub fn len(&self) -> usize {
        self.path_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.path_id.is_empty()
    }

    /// Drop column vecs and reset the window pool to `{""}` (id 0 only).
    pub fn clear(&mut self) {
        self.pool = StringPool::new();
        self.path_id.clear();
        self.name_id.clear();
        self.linkname_id.clear();
        self.offsetheader.clear();
        self.offset.clear();
        self.size.clear();
        self.mtime.clear();
        self.mode.clear();
        self.typeflag.clear();
        self.uid.clear();
        self.gid.clear();
        self.istar.clear();
        self.issparse.clear();
        self.isgenerated.clear();
        self.recursiondepth.clear();
    }

    /// Stage one row from `&str` (format-builder hot path). Interns TEXT; no [`FileRow`].
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        path: &str,
        name: &str,
        offsetheader: i64,
        offset: i64,
        size: i64,
        mtime: f64,
        mode: i64,
        typeflag: i64,
        linkname: &str,
        uid: i64,
        gid: i64,
        istar: bool,
        issparse: bool,
        isgenerated: bool,
        recursiondepth: i64,
    ) {
        self.path_id.push(self.pool.intern_id(path));
        self.name_id.push(self.pool.intern_id(name));
        self.linkname_id.push(self.pool.intern_id(linkname));
        self.offsetheader.push(offsetheader);
        self.offset.push(offset);
        self.size.push(size);
        self.mtime.push(mtime);
        self.mode.push(mode);
        self.typeflag.push(typeflag);
        self.uid.push(uid);
        self.gid.push(gid);
        self.istar.push(istar);
        self.issparse.push(issparse);
        self.isgenerated.push(isgenerated);
        self.recursiondepth.push(recursiondepth);
    }

    /// Tests / optional; TAR/ZIP/7z cold builders must call [`Self::push`].
    pub fn push_file_row(&mut self, row: &FileRow) {
        self.push(
            &row.path,
            &row.name,
            row.offsetheader,
            row.offset,
            row.size,
            row.mtime,
            row.mode,
            row.typeflag,
            &row.linkname,
            row.uid,
            row.gid,
            row.istar,
            row.issparse,
            row.isgenerated,
            row.recursiondepth,
        );
    }

    pub fn path_id_at(&self, i: usize) -> u32 {
        self.path_id[i]
    }

    pub fn pool_unique_count(&self) -> usize {
        self.pool.unique_count()
    }

    fn path_at(&self, i: usize) -> &str {
        self.pool.get(self.path_id[i])
    }

    fn name_at(&self, i: usize) -> &str {
        self.pool.get(self.name_id[i])
    }

    fn linkname_at(&self, i: usize) -> &str {
        self.pool.get(self.linkname_id[i])
    }

    /// One short-lived [`FileRow`] for [`MemIndexBuilder::push_row`] only.
    fn file_row_at(&self, i: usize) -> FileRow {
        FileRow::new(
            self.path_at(i),
            self.name_at(i),
            self.offsetheader[i],
            self.offset[i],
            self.size[i],
            self.mtime[i],
            self.mode[i],
            self.typeflag[i],
            self.linkname_at(i),
            self.uid[i],
            self.gid[i],
            self.istar[i],
            self.issparse[i],
            self.isgenerated[i],
            self.recursiondepth[i],
        )
    }
}

fn split_path(path: &str) -> (String, String) {
    // Match Python: path, name = path.rsplit('/', 1) after normpath;
    // root children live under SQL path "".
    if path == "/" {
        return (String::new(), String::new());
    }
    match path.rsplit_once('/') {
        Some(("", name)) => (String::new(), name.to_string()),
        Some((dir, name)) => (dir.to_string(), name.to_string()),
        None => (String::new(), path.to_string()),
    }
}

pub(crate) fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        r#"SELECT COUNT(*) FROM sqlite_master
           WHERE (type='table' OR type='view') AND name = ?1"#,
        params![name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn row_to_file_info(row: &Row<'_>) -> rusqlite::Result<FileInfo> {
    // columns: path, name, offsetheader, offset, size, mtime, mode, type, linkname,
    //          uid, gid, istar, issparse, isgenerated, recursiondepth
    let offsetheader: Option<i64> = row.get(2)?;
    let offset: i64 = row.get(3)?;
    let size: i64 = row.get(4)?;
    let mtime: f64 = row.get(5)?;
    let mode: i64 = row.get(6)?;
    let linkname: String = row.get(8).unwrap_or_default();
    let uid: i64 = row.get(9).unwrap_or(0);
    let gid: i64 = row.get(10).unwrap_or(0);
    let istar: bool = row.get::<_, i64>(11).unwrap_or(0) != 0;
    let issparse: bool = row.get::<_, i64>(12).unwrap_or(0) != 0;
    let isgenerated: bool = row.get::<_, i64>(13).unwrap_or(0) != 0;
    let recursiondepth: i64 = row.get(14).unwrap_or(0);

    Ok(FileInfo {
        size: size.max(0) as u64,
        mtime,
        mode: mode as u32,
        linkname,
        uid: uid as u32,
        gid: gid as u32,
        userdata: vec![UserData::Tar(SQLiteIndexedTarUserData {
            offset: offset.max(0) as u64,
            offsetheader: offsetheader.map(|v| v.max(0) as u64),
            istar,
            issparse,
            isgenerated,
            recursiondepth: recursiondepth.max(0) as u32,
        })],
    })
}

fn file_info_from_named_row(row: &Row<'_>) -> rusqlite::Result<FileInfo> {
    // name, offsetheader, offset, size, mtime, mode, type, linkname, uid, gid, ...
    let offsetheader: Option<i64> = row.get(1)?;
    let offset: i64 = row.get(2)?;
    let size: i64 = row.get(3)?;
    let mtime: f64 = row.get(4)?;
    let mode: i64 = row.get(5)?;
    let linkname: String = row.get(7).unwrap_or_default();
    let uid: i64 = row.get(8).unwrap_or(0);
    let gid: i64 = row.get(9).unwrap_or(0);
    let istar: bool = row.get::<_, i64>(10).unwrap_or(0) != 0;
    let issparse: bool = row.get::<_, i64>(11).unwrap_or(0) != 0;
    let isgenerated: bool = row.get::<_, i64>(12).unwrap_or(0) != 0;
    let recursiondepth: i64 = row.get(13).unwrap_or(0);

    Ok(FileInfo {
        size: size.max(0) as u64,
        mtime,
        mode: mode as u32,
        linkname,
        uid: uid as u32,
        gid: gid as u32,
        userdata: vec![UserData::Tar(SQLiteIndexedTarUserData {
            offset: offset.max(0) as u64,
            offsetheader: offsetheader.map(|v| v.max(0) as u64),
            istar,
            issparse,
            isgenerated,
            recursiondepth: recursiondepth.max(0) as u32,
        })],
    })
}

/// Count rows in the `files` table of an on-disk index (no mem projection).
///
/// Lightweight helper for factory gates that only have a path (B-119).
pub fn index_file_row_count(path: impl AsRef<Path>) -> Result<u64> {
    let path = path.as_ref();
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    // Favor a quick meta-only open; ignore mmap for a one-shot COUNT.
    let _ = conn.execute_batch("PRAGMA query_only = ON;");
    let n: i64 = conn.query_row(r#"SELECT COUNT(*) FROM "files""#, [], |r| r.get(0))?;
    Ok(n as u64)
}

/// If `minimum > 0` and the on-disk index has strictly fewer than `minimum` `files`
/// rows, remove the file. Returns `Ok(true)` when removed.
///
/// No-op when `minimum == 0`, the path is missing, or the count is at/above the gate.
pub fn discard_index_file_if_below_minimum(path: impl AsRef<Path>, minimum: u64) -> Result<bool> {
    if minimum == 0 {
        return Ok(false);
    }
    let path = path.as_ref();
    if !path.exists() {
        return Ok(false);
    }
    let count = index_file_row_count(path)?;
    if count >= minimum {
        return Ok(false);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py_fixture(rel: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join(rel)
    }

    fn one_file_row() -> FileRow {
        FileRow::new(
            "/",
            "only.txt",
            0,
            512,
            4,
            0.0,
            0o100644,
            i64::from(b'0'),
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        )
    }

    /// Regression: B-119 — small indexes are removed when below the minimum.
    #[test]
    fn index_minimum_file_count_discards_small_on_disk_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.index.sqlite");
        {
            let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.store_metadata_key_value("backendName", "SQLiteIndexedTar")
                .unwrap();
            // One file row only.
            idx.insert_files_batch(&[one_file_row()]).unwrap();
            let idx = idx.into_read_only().unwrap();
            assert_eq!(idx.file_count_db().unwrap(), 1);
            assert!(idx.discard_on_disk_if_below_minimum(1000).unwrap());
            // Live connection still answers after unlink.
            assert_eq!(idx.file_count_db().unwrap(), 1);
        }
        assert!(
            !path.exists(),
            "on-disk index should be removed when count < minimum"
        );
    }

    #[test]
    fn index_minimum_file_count_keeps_index_at_or_above_minimum() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keep.index.sqlite");
        {
            let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.store_metadata_key_value("backendName", "SQLiteIndexedTar")
                .unwrap();
            idx.insert_files_batch(&[one_file_row()]).unwrap();
            let idx = idx.into_read_only().unwrap();
            assert!(!idx.discard_on_disk_if_below_minimum(1).unwrap());
            assert!(!idx.discard_on_disk_if_below_minimum(0).unwrap());
        }
        assert!(path.exists(), "index should remain when count >= minimum");
        assert_eq!(index_file_row_count(&path).unwrap(), 1);
        assert!(!discard_index_file_if_below_minimum(&path, 1).unwrap());
        assert!(discard_index_file_if_below_minimum(&path, 2).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn open_nested_tar_index() {
        let path = py_fixture("tests/nested-tar.index.sqlite");
        if !path.exists() {
            eprintln!("skip: fixture missing at {}", path.display());
            return;
        }
        let idx = SqliteIndex::open_read_only(&path).expect("open index");
        assert!(idx.file_count().unwrap() > 0);
        let root = idx.list("/").unwrap().expect("root list");
        assert!(!root.is_empty(), "expected entries under /");
        // nested-tar typically has foo/
        let any = root.keys().next().cloned();
        assert!(any.is_some());
    }

    #[test]
    fn create_empty_index_in_memory() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.store_versions("0.1.0").unwrap();
        idx.store_metadata_key_value("backendName", "SQLiteIndexedTar")
            .unwrap();
        assert_eq!(idx.file_count().unwrap(), 0);
        assert_eq!(
            idx.backend_name().unwrap().as_deref(),
            Some("SQLiteIndexedTar")
        );
    }

    #[test]
    fn parse_tarstats_json_size_mtime_and_float_mtime() {
        let s = parse_tarstats_json(r#"{"st_size":1024,"st_mtime":1700000000,"st_mtime_ns":123}"#)
            .unwrap();
        assert_eq!(s.st_size, 1024);
        assert_eq!(s.st_mtime, 1_700_000_000);
        assert_eq!(s.st_mtime_ns, Some(123));
        assert!(s.prefix512_sha256.is_none());

        let f = parse_tarstats_json(r#"{"st_size":10,"st_mtime":1.9}"#).unwrap();
        assert_eq!(f.st_size, 10);
        assert_eq!(f.st_mtime, 1);
        assert_eq!(f.st_mtime_ns, None);
    }

    /// Regression: `archive_full_hash` streams; policy cap unchanged; digest matches one-shot.
    #[test]
    fn regression_archive_full_hash_streams_empty_small_and_cap() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.bin");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(
            archive_full_hash(&empty).unwrap().as_deref(),
            hash_hex("sha256", b"").as_deref()
        );

        let small = dir.path().join("small.bin");
        std::fs::write(&small, b"abc").unwrap();
        assert_eq!(
            archive_full_hash(&small).unwrap().as_deref(),
            hash_hex("sha256", b"abc").as_deref()
        );

        let at_cap = dir.path().join("at_cap.bin");
        let cap_bytes = vec![0x5Au8; TARSTATS_FULL_HASH_MAX as usize];
        std::fs::write(&at_cap, &cap_bytes).unwrap();
        assert_eq!(
            archive_full_hash(&at_cap).unwrap().as_deref(),
            hash_hex("sha256", &cap_bytes).as_deref()
        );

        let over = dir.path().join("over.bin");
        std::fs::write(&over, vec![0u8; TARSTATS_FULL_HASH_MAX as usize + 1]).unwrap();
        assert_eq!(archive_full_hash(&over).unwrap(), None);
    }

    /// Regression: edge hashes use exact window lengths (0-byte / 1-byte / ≤512 / >512).
    #[test]
    fn regression_archive_edge_hashes_exact_windows() {
        let dir = tempfile::tempdir().unwrap();

        let empty = dir.path().join("e.bin");
        std::fs::write(&empty, b"").unwrap();
        let (p, s) = archive_edge_hashes(&empty).unwrap();
        let empty_hex = hash_hex("sha256", b"").unwrap();
        assert_eq!(p, empty_hex);
        assert_eq!(s, empty_hex);

        let one = dir.path().join("one.bin");
        std::fs::write(&one, b"Z").unwrap();
        let (p, s) = archive_edge_hashes(&one).unwrap();
        let one_hex = hash_hex("sha256", b"Z").unwrap();
        assert_eq!(p, one_hex);
        assert_eq!(s, one_hex);

        let small = dir.path().join("le512.bin");
        let small_bytes = vec![0x11u8; 512];
        std::fs::write(&small, &small_bytes).unwrap();
        let (p, s) = archive_edge_hashes(&small).unwrap();
        let small_hex = hash_hex("sha256", &small_bytes).unwrap();
        assert_eq!(p, small_hex);
        assert_eq!(s, p);

        let big = dir.path().join("gt512.bin");
        let mut big_bytes = vec![0x22u8; 800];
        for (i, b) in big_bytes.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        std::fs::write(&big, &big_bytes).unwrap();
        let (p, s) = archive_edge_hashes(&big).unwrap();
        assert_eq!(p, hash_hex("sha256", &big_bytes[..512]).unwrap());
        assert_eq!(
            s,
            hash_hex("sha256", &big_bytes[big_bytes.len() - 512..]).unwrap()
        );
        assert_ne!(p, s);
    }

    /// Regression: warm index must not be trusted when archive size/mtime/content no longer match tarstats.
    #[test]
    fn check_tarstats_matches_archive_rejects_size_or_mtime_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"old-content").unwrap();
        let idx_path = dir.path().join("a.tar.index.sqlite");
        {
            let mut idx = SqliteIndex::create_writable(Some(&idx_path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.store_tarstats_for_path(&archive).unwrap();
            let ts = idx.tarstats().unwrap().unwrap();
            assert!(ts.prefix512_sha256.is_some());
            assert!(ts.suffix512_sha256.is_some());
            assert!(
                ts.full_sha256.is_some(),
                "tiny archive should store full_sha256"
            );
            idx.publish_tmp().unwrap();
        }

        let idx = SqliteIndex::open_read_only(&idx_path).unwrap();
        idx.check_tarstats_matches_archive(&archive)
            .expect("matching archive should pass");

        // Size change.
        std::fs::write(&archive, b"new-content-longer").unwrap();
        let err = idx
            .check_tarstats_matches_archive(&archive)
            .expect_err("size mismatch");
        assert!(
            matches!(err, IndexError::Mismatch(_)),
            "expected Mismatch, got {err:?}"
        );

        // Same size, different content (tar block-padding class) → edge hash mismatch.
        // Pad to same length as original "old-content" (11 bytes).
        std::fs::write(&archive, b"Xld-content").unwrap();
        assert_eq!(
            std::fs::metadata(&archive).unwrap().len(),
            b"old-content".len() as u64
        );
        // Force same mtime as stored so only content samples fire.
        {
            let stored = idx.tarstats().unwrap().unwrap();
            let when = std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(stored.st_mtime.max(0) as u64);
            let times = std::fs::FileTimes::new().set_modified(when);
            std::fs::File::options()
                .write(true)
                .open(&archive)
                .unwrap()
                .set_times(times)
                .unwrap();
        }
        let err = idx
            .check_tarstats_matches_archive(&archive)
            .expect_err("content fingerprint mismatch");
        assert!(
            matches!(err, IndexError::Mismatch(_)),
            "expected Mismatch for content sample, got {err:?}"
        );

        // Missing tarstats is allowed (legacy).
        let idx2 = SqliteIndex::create_writable(None).unwrap();
        idx2.check_tarstats_matches_archive(&archive)
            .expect("no tarstats → Ok");
    }

    /// Regression: a wrong-size remote sidecar must not be used. Path tarstats is a
    /// no-op for URL / `oci:{digest}` labels.
    #[test]
    fn remote_tarstats_size_mismatch() {
        let stored = TarStats {
            st_size: 1000,
            st_mtime: 0,
            st_mtime_ns: None,
            prefix512_sha256: Some("aa".into()),
            suffix512_sha256: Some("bb".into()),
            full_sha256: None,
        };
        let err = check_tarstats_matches_remote(&stored, 2000, Some("aa"), Some("bb"), None)
            .expect_err("size mismatch");
        assert!(
            matches!(err, IndexError::Mismatch(_)),
            "expected Mismatch, got {err:?}"
        );
        check_tarstats_matches_remote(&stored, 1000, Some("aa"), Some("bb"), None)
            .expect("matching size and edges");
        check_tarstats_matches_remote(&stored, 1000, Some("AA"), Some("BB"), None)
            .expect("hex fingerprint compare is case-insensitive");
        let err = check_tarstats_matches_remote(&stored, 1000, Some("cc"), Some("bb"), None)
            .expect_err("prefix mismatch");
        assert!(matches!(err, IndexError::Mismatch(_)));

        let small = TarStats {
            st_size: 64,
            st_mtime: 0,
            st_mtime_ns: None,
            prefix512_sha256: None,
            suffix512_sha256: None,
            full_sha256: Some("deadbeef".into()),
        };
        check_tarstats_matches_remote(&small, 64, None, None, Some("deadbeef")).unwrap();
        let err = check_tarstats_matches_remote(&small, 64, None, None, Some("cafebabe"))
            .expect_err("full hash mismatch");
        assert!(matches!(err, IndexError::Mismatch(_)));
        let err = check_tarstats_matches_remote(&small, 64, None, None, None)
            .expect_err("full hash required when stored");
        assert!(matches!(err, IndexError::Mismatch(_)));

        // Path-based check is a no-op when the archive label is not on disk.
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.store_metadata_key_value("tarstats", &serialize_tarstats(&stored))
            .unwrap();
        idx.check_tarstats_matches_archive(Path::new("http://example.com/a.tar"))
            .expect("missing URL path is a no-op");
        idx.check_tarstats_matches_archive(Path::new("oci:sha256:deadbeef"))
            .expect("oci label is a no-op");
        // The remote helper still rejects the swapped catalog.
        let stored_now = idx.tarstats().unwrap().unwrap();
        assert!(check_tarstats_matches_remote(&stored_now, 9999, None, None, None).is_err());
    }

    #[test]
    fn xattr_insert_list_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.index.sqlite");
        let mut idx = SqliteIndex::create_writable(Some(&path)).unwrap();
        idx.store_versions("0.1.0").unwrap();

        // Minimal files row so schema is realistic; xattrs only need offsetheader.
        idx.insert_file(
            "", "bar", 512, 1024, 4, 0.0, 0o100644, 0, "", 1000, 1000, true, false, false, 0,
        )
        .unwrap();

        idx.insert_xattr(512, "user.hash.sha256", b"deadbeef")
            .unwrap();
        idx.insert_xattr(512, "user.hash.crc32", b"7e3265a8")
            .unwrap();

        let mut keys = idx.list_xattr_keys(512).unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "user.hash.crc32".to_string(),
                "user.hash.sha256".to_string()
            ]
        );
        assert_eq!(
            idx.get_xattr(512, "user.hash.crc32").unwrap().as_deref(),
            Some(b"7e3265a8".as_slice())
        );
        assert_eq!(
            idx.get_xattr(512, "user.hash.sha256").unwrap().as_deref(),
            Some(b"deadbeef".as_slice())
        );
        assert!(idx.get_xattr(512, "missing").unwrap().is_none());
        assert!(idx.list_xattr_keys(999).unwrap().is_empty());

        // Reopen writable and ensure persistence.
        idx.publish_tmp().unwrap();
        drop(idx);
        let idx2 = SqliteIndex::open_writable(&path).unwrap();
        assert_eq!(
            idx2.get_xattr(512, "user.hash.crc32").unwrap().as_deref(),
            Some(b"7e3265a8".as_slice())
        );
    }

    #[test]
    fn fill_content_hashes_from_temp_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("payload.bin");
        // layout: 8 bytes padding, then "foo\n"
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(b"foo\n");
        std::fs::write(&archive, &blob).unwrap();

        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.insert_file(
            "", "bar", 0, 8, // offset into archive
            4, // size
            0.0, 0o100644, 0, "", 0, 0, true, false, false, 0,
        )
        .unwrap();

        fill_content_hashes(
            &idx,
            &archive,
            &["crc32".into(), "sha256".into(), "md5".into(), "sha1".into()],
        )
        .unwrap();

        let keys = idx.list_xattr_keys(0).unwrap();
        assert_eq!(keys.len(), 4);
        assert_eq!(
            idx.get_xattr(0, "user.hash.crc32").unwrap().as_deref(),
            Some(b"7e3265a8".as_slice())
        );
        assert_eq!(
            idx.get_xattr(0, "user.hash.sha256").unwrap().as_deref(),
            Some(b"b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c".as_slice())
        );
    }

    #[test]
    fn compression_side_tables_created_on_build() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        for name in COMPRESSION_TABLE_NAMES {
            assert!(
                idx.has_compression_table(name).unwrap(),
                "expected table {name} after create_writable"
            );
        }
    }

    #[test]
    fn gzip_index_blob_roundtrip_memory() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        assert!(idx.get_gzip_index_blobs().unwrap().is_empty());

        let blob = b"indexed-gzip-seek-blob-v1".to_vec();
        idx.set_gzip_index_blob(&blob).unwrap();
        assert!(idx
            .has_compression_table(COMPRESSION_TABLE_GZIPINDEX)
            .unwrap());
        assert_eq!(idx.get_gzip_index_blobs().unwrap(), vec![blob.clone()]);

        // Append migrates singular → plural and adds second blob.
        let blob2 = b"second-chunk".to_vec();
        idx.append_gzip_index_blob(&blob2).unwrap();
        assert!(idx
            .has_compression_table(COMPRESSION_TABLE_GZIPINDEXES)
            .unwrap());
        assert_eq!(idx.get_gzip_index_blobs().unwrap(), vec![blob, blob2]);
    }

    #[test]
    fn gzip_index_blob_roundtrip_reopen_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("comp.index.sqlite");
        {
            let mut idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.set_gzip_index_blob(b"persist-me").unwrap();
            idx.set_bzip2_blocks(&[(0, 0), (100, 50), (200, 120)])
                .unwrap();
            idx.set_zstd_blocks(&[(1, 10), (2, 20)]).unwrap();
            idx.set_gztool_index_blob(b"gztool-blob").unwrap();
            idx.publish_tmp().unwrap();
        }

        let idx = SqliteIndex::open_writable(&path).unwrap();
        assert_eq!(
            idx.get_gzip_index_blobs().unwrap(),
            vec![b"persist-me".to_vec()]
        );
        assert_eq!(
            idx.get_bzip2_blocks().unwrap(),
            vec![(0, 0), (100, 50), (200, 120)]
        );
        assert_eq!(idx.get_zstd_blocks().unwrap(), vec![(1, 10), (2, 20)]);
        assert_eq!(
            idx.get_gztool_index_blobs().unwrap(),
            vec![b"gztool-blob".to_vec()]
        );

        // Read-only reopen also sees the data (tables already present).
        drop(idx);
        let ro = SqliteIndex::open_read_only(&path).unwrap();
        assert!(ro
            .has_compression_table(COMPRESSION_TABLE_GZIPINDEX)
            .unwrap());
        assert_eq!(
            ro.get_gzip_index_blobs().unwrap(),
            vec![b"persist-me".to_vec()]
        );
        assert_eq!(
            ro.get_bzip2_blocks().unwrap(),
            vec![(0, 0), (100, 50), (200, 120)]
        );
    }

    #[test]
    fn bzip2_zstd_blocks_replace_and_clear() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.set_bzip2_blocks(&[(5, 15)]).unwrap();
        idx.set_zstd_blocks(&[(7, 17)]).unwrap();
        assert_eq!(idx.get_bzip2_blocks().unwrap(), vec![(5, 15)]);
        assert_eq!(idx.get_zstd_blocks().unwrap(), vec![(7, 17)]);

        // Replace overwrites.
        idx.set_bzip2_blocks(&[(1, 2), (3, 4)]).unwrap();
        assert_eq!(idx.get_bzip2_blocks().unwrap(), vec![(1, 2), (3, 4)]);

        idx.clear_compression_offsets().unwrap();
        for name in COMPRESSION_TABLE_NAMES {
            assert!(
                !idx.has_compression_table(name).unwrap(),
                "expected {name} dropped"
            );
        }
        assert!(idx.get_gzip_index_blobs().unwrap().is_empty());
        assert!(idx.get_bzip2_blocks().unwrap().is_empty());
        assert!(idx.get_zstd_blocks().unwrap().is_empty());

        // ensure recreates empty tables after clear.
        idx.ensure_compression_tables().unwrap();
        assert!(idx
            .has_compression_table(COMPRESSION_TABLE_ZSTDBLOCKS)
            .unwrap());
    }

    #[test]
    fn compression_writes_reject_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ro.index.sqlite");
        {
            let mut idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.publish_tmp().unwrap();
        }
        let ro = SqliteIndex::open_read_only(&path).unwrap();
        assert!(ro.set_gzip_index_blob(b"x").is_err());
        assert!(ro.set_bzip2_blocks(&[(0, 0)]).is_err());
        assert!(ro.clear_compression_offsets().is_err());
    }

    fn multi_under_dir(n: usize) -> Vec<FileRow> {
        (0..n)
            .map(|i| {
                FileRow::new(
                    "/shared/dir",
                    format!("f{i:04}.txt"),
                    i as i64 * 100,
                    i as i64 * 100 + 32,
                    4,
                    0.0,
                    0o100644,
                    i64::from(b'0'),
                    "",
                    0,
                    0,
                    false,
                    false,
                    false,
                    0,
                )
            })
            .collect()
    }

    /// Regression: cold build fills compact MemIndex at insert time (string pool + rows).
    #[test]
    fn compact_mem_index_built_at_insert_time() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&multi_under_dir(24)).unwrap();
        idx.store_versions("0.1.0").unwrap();
        idx.commit_write().unwrap();
        let idx = idx.into_read_only().unwrap();

        assert!(idx.has_mem_index());
        assert!(idx.mem_is_soa_layout());
        assert!(idx.mem_uses_path_segments());
        assert_eq!(idx.file_count().unwrap(), 24);
        assert!(
            idx.mem_dir_path_is_shared("/shared/dir"),
            "directory path must be interned/shared across names"
        );
        let unique = idx.mem_pool_unique_count().unwrap();
        // segments shared + 24 names (not full path × 24)
        assert!(
            unique < 40,
            "expected compact path segments + names, got {unique}"
        );

        let fi = idx
            .lookup("/shared/dir/f0007.txt", 0)
            .unwrap()
            .expect("lookup");
        assert_eq!(fi.size, 4);
        let cookie = idx
            .lookup_open_cookie("/shared/dir/f0007.txt", 0)
            .unwrap()
            .expect("open cookie");
        assert_eq!(cookie.size, 4);
        let listed = idx.list("/shared/dir").unwrap().expect("list");
        assert_eq!(listed.len(), 24);
        let modes = idx.list_mode("/shared/dir").unwrap().expect("modes");
        assert_eq!(modes.len(), 24);
    }

    /// Regression: warm open_read_only also uses compact pool (not fat triple maps).
    #[test]
    fn compact_mem_index_on_open_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compact.index.sqlite");
        {
            let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.begin_write().unwrap();
            idx.insert_files_batch(&multi_under_dir(12)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.commit_write().unwrap();
            let idx = idx.into_read_only().unwrap();
            assert!(idx.has_mem_index());
        }
        let ro = SqliteIndex::open_read_only(&path).unwrap();
        assert!(ro.has_mem_index());
        assert!(ro.mem_dir_path_is_shared("/shared/dir"));
        assert_eq!(ro.file_count().unwrap(), 12);
        assert!(ro.lookup("/shared/dir/f0001.txt", 0).unwrap().is_some());
    }

    /// Regression: after seal, a second open_writable must not hit `database is locked`
    /// while the sealed RO index connection is still live (factory side tables / B-119).
    #[test]
    fn into_read_only_releases_exclusive_for_second_opener() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("side.index.sqlite");
        let sealed = {
            let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.begin_write().unwrap();
            idx.insert_files_batch(&[one_file_row()]).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.commit_write().unwrap();
            idx.into_read_only().unwrap()
        };
        assert!(sealed.path().is_some());
        // Concurrent with sealed still in scope (mount holds this).
        let w = SqliteIndex::open_writable(&path).expect("open_writable while RO live");
        w.set_zstd_blocks(&[(0, 0), (100, 50)])
            .expect("write side table while mount RO holds index");
        assert_eq!(w.get_zstd_blocks().unwrap().len(), 2);
        // B-119 path: row count via a third connection
        assert_eq!(index_file_row_count(&path).unwrap(), 1);
        drop(sealed);
    }

    fn named_file_row(name: &str) -> FileRow {
        FileRow::new(
            "",
            name,
            0,
            512,
            4,
            0.0,
            0o100644,
            i64::from(b'0'),
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        )
    }

    fn catalog_rows(prefix: &str, n: usize) -> Vec<FileRow> {
        (0..n)
            .map(|i| {
                FileRow::new(
                    "",
                    format!("{prefix}-{i:04}.txt"),
                    i as i64 * 512,
                    i as i64 * 512 + 32,
                    4,
                    0.0,
                    0o100644,
                    i64::from(b'0'),
                    "",
                    0,
                    0,
                    false,
                    false,
                    false,
                    0,
                )
            })
            .collect()
    }

    #[cfg(unix)]
    fn file_ino(path: &Path) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.ino())
    }

    /// Regression: `-c` must not unlink dest; a live reader keeps snapshot N.
    /// Dest-wal/shm inodes must change so WAL on dest does not replay N.
    #[test]
    fn regression_reader_survives_writer_full_build() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("snap.index.sqlite");
        #[cfg(unix)]
        let dest_wal = sqlite_path_companion(&dest, "-wal");
        #[cfg(unix)]
        let dest_shm = sqlite_path_companion(&dest, "-shm");
        const N: usize = 512;
        {
            let idx = SqliteIndex::create_writable(Some(&dest)).unwrap();
            idx.begin_write().unwrap();
            idx.insert_files_batch(&catalog_rows("old", N)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.commit_write().unwrap();
            let idx = idx.into_read_only().unwrap();
            assert_eq!(idx.path(), Some(dest.as_path()));
        }
        let reader = SqliteIndex::open_read_only(&dest).unwrap();
        reader
            .with_conn(|conn| {
                conn.execute_batch("PRAGMA cache_size = 1; PRAGMA mmap_size = 0;")?;
                Ok(())
            })
            .unwrap();
        let hits = reader
            .search_query(&SearchQuery::glob("old-*.txt"))
            .expect("reader search before rewrite");
        assert_eq!(hits.len(), N);

        #[cfg(unix)]
        let wal_ino_before = file_ino(&dest_wal);
        #[cfg(unix)]
        let shm_ino_before = file_ino(&dest_shm);

        let writer = SqliteIndex::create_writable(Some(&dest)).unwrap();
        assert!(dest.exists(), "create_writable must not remove_file dest");
        let tmp = writer.path().expect("tmp path").to_path_buf();
        assert_ne!(tmp, dest, "cold build writes dest.tmp.pid.seq");
        assert!(tmp.exists(), "cold build writes dest.tmp.pid.seq");
        writer.begin_write().unwrap();
        writer.insert_files_batch(&catalog_rows("new", N)).unwrap();
        writer.store_versions("0.1.0").unwrap();
        writer.commit_write().unwrap();

        let mid = reader
            .search_query(&SearchQuery::glob("old-*.txt"))
            .expect("reader search mid-insert");
        assert_eq!(mid.len(), N);

        let writer = writer.into_read_only().unwrap();
        assert_eq!(writer.path(), Some(dest.as_path()));
        assert!(!tmp.exists(), "publish renames tmp onto dest");
        let tmp_wal = sqlite_path_companion(&tmp, "-wal");
        assert!(
            !tmp_wal.exists(),
            "WAL must not follow the tmp name after publish"
        );

        #[cfg(unix)]
        {
            let wal_ino_after = file_ino(&dest_wal);
            assert_ne!(
                wal_ino_before, wal_ino_after,
                "publish must unlink dest-wal then recreate, not reuse snapshot N"
            );
            if shm_ino_before.is_some() {
                assert_ne!(
                    shm_ino_before,
                    file_ino(&dest_shm),
                    "publish must not reuse snapshot N dest-shm"
                );
            }
        }

        let after = reader
            .search_query(&SearchQuery::glob("old-*.txt"))
            .expect("reader search after publish");
        assert_eq!(after.len(), N, "open reader stays on inode N after rename");
        assert!(
            reader
                .search_query(&SearchQuery::glob("new-*.txt"))
                .unwrap()
                .is_empty(),
            "reader must not see the tmp/N+1 catalog"
        );

        drop(writer);
        let fresh = SqliteIndex::open_read_only(&dest).unwrap();
        let fresh_hits = fresh.search_query(&SearchQuery::glob("new-*.txt")).unwrap();
        assert_eq!(fresh_hits.len(), N);
        assert!(fresh
            .search_query(&SearchQuery::glob("old-*.txt"))
            .unwrap()
            .is_empty());
    }

    /// Regression: Drop mid-insert unlinks tmp and leaves the previous well-known file.
    #[test]
    fn regression_drop_unpublished_tmp_leaves_dest() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("keep.index.sqlite");
        {
            let idx = SqliteIndex::create_writable(Some(&dest)).unwrap();
            idx.begin_write().unwrap();
            idx.insert_files_batch(&[named_file_row("old.txt")])
                .unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.commit_write().unwrap();
            let _ = idx.into_read_only().unwrap();
        }
        let orig = std::fs::read(&dest).unwrap();
        let tmp;
        {
            let writer = SqliteIndex::create_writable(Some(&dest)).unwrap();
            tmp = writer.path().expect("tmp path").to_path_buf();
            writer
                .insert_files_batch(&[named_file_row("new.txt")])
                .unwrap();
            assert!(tmp.exists());
            drop(writer);
        }
        assert!(!tmp.exists(), "Drop unpublished tmp unlinks tmp");
        assert!(
            !sqlite_path_companion(&tmp, "-wal").exists(),
            "Drop unpublished tmp unlinks tmp-wal"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            orig,
            "failed -c must not replace a good sidecar"
        );
        let ro = SqliteIndex::open_read_only(&dest).unwrap();
        let hits = ro.search_query(&SearchQuery::glob("*.txt")).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/old.txt");
    }

    #[test]
    fn regression_writable_tmp_paths_are_unique_in_process() {
        let dest = Path::new("/tmp/x.index.sqlite");
        let a = writable_tmp_path(dest);
        let b = writable_tmp_path(dest);
        assert_ne!(a, b);
        assert!(a
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(&format!(".tmp.{}", std::process::id())));
        assert_eq!(parse_writable_tmp_pid("12"), Some(12));
        assert_eq!(parse_writable_tmp_pid("12.3"), Some(12));
        assert_eq!(parse_writable_tmp_pid("12.3-wal"), None);
        assert_eq!(parse_writable_tmp_pid("12-wal"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn regression_create_writable_reaps_same_pid_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("keep.index.sqlite");
        let leftover = writable_tmp_path(&dest);
        std::fs::write(&leftover, b"stale-tmp").unwrap();
        let idx = SqliteIndex::create_writable(Some(&dest)).unwrap();
        assert!(
            !leftover.exists(),
            "disconnected same-pid leftover tmp must be reaped"
        );
        let live = idx.path().unwrap().to_path_buf();
        assert!(live.exists());
        assert_ne!(live, leftover);
        drop(idx);
        assert!(!live.exists());
        assert!(!dest.exists(), "unpublished tmp must not replace dest");
    }

    /// Regression: a second in-process `create_writable` must not unlink a live
    /// same-pid staging file (unique seq is not enough if reap deletes by pid).
    #[test]
    fn regression_create_writable_does_not_reap_live_same_pid_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("keep.index.sqlite");
        let first = SqliteIndex::create_writable(Some(&dest)).unwrap();
        first
            .insert_files_batch(&[named_file_row("held.txt")])
            .unwrap();
        let first_tmp = first.path().expect("tmp path").to_path_buf();
        assert!(first_tmp.exists());
        let second = SqliteIndex::create_writable(Some(&dest)).unwrap();
        assert!(first_tmp.exists(), "live same-pid tmp must not be reaped");
        let second_tmp = second.path().expect("tmp path").to_path_buf();
        assert_ne!(first_tmp, second_tmp);
        drop(second);
        assert!(
            first_tmp.exists(),
            "dropping the second writer leaves the first tmp"
        );
        drop(first);
        assert!(!first_tmp.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn regression_create_writable_reaps_dead_pid_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("keep.index.sqlite");
        let mut orphan = dest.as_os_str().to_os_string();
        orphan.push(".tmp.4294967295");
        let orphan = PathBuf::from(orphan);
        std::fs::write(&orphan, b"dead-pid-tmp").unwrap();
        let idx = SqliteIndex::create_writable(Some(&dest)).unwrap();
        assert!(
            !orphan.exists(),
            "dead-pid dest.tmp.* leftover must be reaped"
        );
        drop(idx);
    }

    /// Nested compact-only: no SQLite files table as file-table store.
    #[test]
    fn nested_compact_only_no_sqlite_files_table() {
        let opts = OpenOptions {
            index_compact_only: true,
            ..OpenOptions::default()
        };
        let idx = SqliteIndex::create_writable_for_open(None, &opts).unwrap();
        assert!(idx.is_compact_only());
        idx.begin_write().unwrap();
        idx.insert_files_batch(&multi_under_dir(8)).unwrap();
        idx.store_versions("0.1.0").unwrap();
        idx.store_metadata_key_value("backendName", "test").unwrap();
        idx.commit_write().unwrap();
        let idx = idx.into_read_only().unwrap();

        assert!(idx.is_compact_only());
        assert!(idx.has_mem_index());
        assert_eq!(
            idx.files_table_row_count().unwrap(),
            0,
            "compact-only must not use SQLite files as the nested file table"
        );
        assert_eq!(idx.file_count().unwrap(), 8);
        assert!(idx.lookup("/shared/dir/f0002.txt", 0).unwrap().is_some());
        assert!(idx.mem_is_soa_layout());
        assert!(idx.mem_uses_path_segments());
    }

    /// Path segments + SoA + optional sharding contracts on multi-dir trees.
    #[test]
    fn multi_dir_path_segments_and_sharding_contracts() {
        let opts = OpenOptions {
            index_compact_only: true,
            ..OpenOptions::default()
        };
        let idx = SqliteIndex::create_writable_for_open(None, &opts).unwrap();
        let mut rows = Vec::new();
        // Deep tree
        for i in 0..5 {
            rows.push(FileRow::new(
                "/a/b/c/d",
                format!("leaf{i}.txt"),
                i as i64,
                i as i64 + 10,
                1,
                0.0,
                0o100644,
                0,
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            ));
        }
        // Many dirs → sharding
        let n_dirs = (DIR_SHARD_THRESHOLD as usize) + 5;
        for i in 0..n_dirs {
            rows.push(FileRow::new(
                format!("/wide{i}"),
                "x.txt",
                1000 + i as i64,
                2000 + i as i64,
                2,
                0.0,
                0o100644,
                0,
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            ));
        }
        idx.insert_files_batch(&rows).unwrap();
        let idx = idx.into_read_only().unwrap();
        assert!(idx.mem_uses_path_segments());
        assert!(idx.mem_is_soa_layout());
        assert!(idx.mem_is_dir_sharded());
        assert!(idx.lookup("/a/b/c/d/leaf2.txt", 0).unwrap().is_some());
        assert!(idx.lookup("/wide0/x.txt", 0).unwrap().is_some());
        assert!(idx
            .lookup(&format!("/wide{}/x.txt", n_dirs - 1), 0)
            .unwrap()
            .is_some());
    }

    /// Regression: sealed path-mount / SQLite MemIndex uses SoA + CSR + sealed slab
    /// (same dense live store as nested; no fat residual rows).
    #[test]
    fn regression_sealed_path_mount_memindex_uses_soa_csr_slab() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        let mut rows = multi_under_dir(80);
        for i in 0..4 {
            rows.push(FileRow::new(
                format!("/other{i}"),
                "x.bin",
                10_000 + i as i64,
                10_000 + i as i64,
                16 + i as i64,
                0.0,
                0o040755,
                0,
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            ));
        }
        idx.insert_files_batch(&rows).unwrap();
        idx.store_versions("0.1.0").unwrap();
        idx.commit_write().unwrap();
        let idx = idx.into_read_only().unwrap();

        assert!(idx.has_mem_index());
        assert!(idx.mem_is_soa_layout());
        assert!(idx.mem_uses_path_segments());
        assert!(idx.mem_path_table_is_csr());
        assert!(idx.mem_pool_is_sealed_slab());

        let dents = idx.list_dirents("/shared/dir").unwrap().expect("dirents");
        let listed = idx.list("/shared/dir").unwrap().expect("list");
        assert_eq!(dents.len(), listed.len());
        assert_eq!(dents.len(), 80);
        for d in &dents {
            let fi = listed.get(&d.name).expect("name in list()");
            assert_eq!(d.mode, fi.mode);
            assert_eq!(d.size, fi.size);
            let cookie = idx
                .lookup_open_cookie(&format!("/shared/dir/{}", d.name), 0)
                .unwrap()
                .expect("cookie");
            assert_eq!(d.cookie, cookie);
        }
    }

    /// Regression: a NULL `offsetheader` row (Python writers emit it for
    /// non-TAR members) must not fail `list_dirents`/`list_mode` on the SQL
    /// path or `load_mem_index` on warm open — `list()`/`lookup()` already
    /// tolerate NULL via `Option<i64>`.
    #[test]
    fn regression_null_offsetheader_rows_still_list() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        // Raw SQL: FileRow cannot express NULL offsetheader.
        idx.with_conn(|conn| {
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'nullrow.txt', NULL, 0, 3, 1.0, 33188, 0, '',
                           0, 0, 0, 0, 0, 0)"#,
                [],
            )?;
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'plain.txt', 512, 512, 5, 1.0, 33188, 0, '',
                           0, 0, 1, 0, 0, 0)"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        idx.commit_write().unwrap();

        // Pre-seal SQL fallback (mem projection not built yet).
        let dents = idx
            .list_dirents("/")
            .expect("list_dirents must not error on NULL offsetheader")
            .expect("root listing present");
        let names: Vec<&str> = dents.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"nullrow.txt"), "{names:?}");
        assert!(names.contains(&"plain.txt"), "{names:?}");
        let nullrow = dents.iter().find(|d| d.name == "nullrow.txt").unwrap();
        assert_eq!(nullrow.size, 3);
        assert!(
            nullrow.cookie.offsetheader < 0,
            "NULL maps to the -1 no-header sentinel, got {}",
            nullrow.cookie.offsetheader
        );
        let modes = idx
            .list_mode("/")
            .expect("list_mode must not error on NULL offsetheader")
            .expect("root modes present");
        assert_eq!(modes.len(), 2);

        // Warm path: sealing must survive the NULL row too.
        let idx = idx.into_read_only().expect("seal with NULL row");
        let dents = idx.list_dirents("/").unwrap().expect("dirents after seal");
        assert_eq!(dents.len(), 2);
        let nullrow = dents.iter().find(|d| d.name == "nullrow.txt").unwrap();
        assert_eq!(nullrow.size, 3);
        assert!(nullrow.cookie.offsetheader < 0);
        // Fat path parity: lookup still yields no header offset for the row.
        let fi = idx.lookup("/nullrow.txt", 0).unwrap().expect("lookup");
        assert_eq!(fi.size, 3);
        let Some(ratarmount_core::UserData::Tar(ud)) = fi.userdata.first() else {
            panic!("expected Tar userdata");
        };
        assert_eq!(ud.offsetheader, None);
    }

    #[derive(Debug, PartialEq)]
    struct FilesSqlRow {
        path: String,
        name: String,
        offsetheader: i64,
        offset: i64,
        size: i64,
        mtime: i64,
        mode: i64,
        typeflag: i64,
        linkname: String,
        uid: i64,
        gid: i64,
        istar: i64,
        issparse: i64,
        isgenerated: i64,
        recursiondepth: i64,
    }

    fn dump_files_sql(idx: &SqliteIndex) -> Vec<FilesSqlRow> {
        idx.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"SELECT path, name, offsetheader, offset, size, CAST(mtime AS INTEGER),
                          mode, type, linkname, uid, gid, istar, issparse, isgenerated,
                          recursiondepth
                   FROM "files" ORDER BY path, name, offsetheader"#,
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(FilesSqlRow {
                    path: r.get(0)?,
                    name: r.get(1)?,
                    offsetheader: r.get(2)?,
                    offset: r.get(3)?,
                    size: r.get(4)?,
                    mtime: r.get(5)?,
                    mode: r.get(6)?,
                    typeflag: r.get(7)?,
                    linkname: r.get(8)?,
                    uid: r.get(9)?,
                    gid: r.get(10)?,
                    istar: r.get(11)?,
                    issparse: r.get(12)?,
                    isgenerated: r.get(13)?,
                    recursiondepth: r.get(14)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(IndexError::from)
        })
        .unwrap()
    }

    fn sample_logical_rows() -> Vec<FileRow> {
        vec![
            FileRow::new(
                "/shared/prefix",
                "a.txt",
                0,
                100,
                10,
                1.0,
                0o100644,
                8,
                "",
                1,
                2,
                false,
                false,
                false,
                0,
            ),
            FileRow::new(
                "/shared/prefix",
                "b.txt",
                512,
                612,
                20,
                2.0,
                0o100644,
                i64::from(b'0'),
                "link",
                3,
                4,
                true,
                true,
                false,
                1,
            ),
            FileRow::new(
                "/shared/prefix",
                "",
                1024,
                1124,
                0,
                3.0,
                0,
                0xffff,
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            ),
            // REPLACE: same PK as a.txt, new size/mtime.
            FileRow::new(
                "/shared/prefix",
                "a.txt",
                0,
                100,
                99,
                9.0,
                0o100644,
                8,
                "",
                1,
                2,
                false,
                false,
                false,
                0,
            ),
        ]
    }

    /// Regression: fat `FileRow` window / ZIP 1-row insert — SoA flush must match
    /// `insert_files_batch` SQL (including `type`) and REPLACE / empty-name split.
    #[test]
    fn regression_insert_files_batch_soa_matches_file_row_sql_and_replace() {
        let rows = sample_logical_rows();
        let idx_a = SqliteIndex::create_writable(None).unwrap();
        idx_a.begin_write().unwrap();
        idx_a.insert_files_batch(&rows).unwrap();
        idx_a.commit_write().unwrap();

        let mut soa = FileRowSoa::with_capacity(rows.len());
        for r in &rows {
            soa.push_file_row(r);
        }
        let idx_b = SqliteIndex::create_writable(None).unwrap();
        idx_b.begin_write().unwrap();
        idx_b.insert_files_batch_soa(&soa).unwrap();
        soa.clear();
        idx_b.commit_write().unwrap();

        assert_eq!(dump_files_sql(&idx_a), dump_files_sql(&idx_b));
        assert_eq!(
            idx_a.sql_files_type("/shared/prefix", "a.txt", 0).unwrap(),
            Some(8)
        );
        assert_eq!(
            idx_b.sql_files_type("/shared/prefix", "a.txt", 0).unwrap(),
            Some(8),
            "SoA bind must store type on the SoA index, not only via dump equality"
        );
        assert_eq!(
            idx_a.sql_files_type("/shared/prefix", "", 1024).unwrap(),
            Some(0xffff)
        );
        // REPLACE updated size; empty name is in SQL.
        let dump = dump_files_sql(&idx_a);
        let a_row = dump
            .iter()
            .find(|r| r.path == "/shared/prefix" && r.name == "a.txt" && r.offsetheader == 0)
            .expect("replaced a.txt");
        assert_eq!(a_row.size, 99, "REPLACE must update size");
        assert!(dump.iter().any(|r| r.name.is_empty()));

        let idx_b = idx_b.into_read_only().unwrap();
        assert!(
            idx_b.lookup("/shared/prefix/a.txt", 0).unwrap().is_some(),
            "MemIndex keeps named REPLACE row"
        );
        assert!(
            idx_b.lookup("/shared/prefix/", 0).unwrap().is_none()
                || idx_b
                    .list("/shared/prefix")
                    .unwrap()
                    .map(|m| !m.contains_key(""))
                    .unwrap_or(true),
            "MemIndex skips empty name"
        );
        let listed = idx_b.list("/shared/prefix").unwrap().expect("list");
        assert!(
            !listed.contains_key(""),
            "empty-name SQL row must not appear in MemIndex list"
        );
        assert!(listed.contains_key("a.txt"));
        assert!(listed.contains_key("b.txt"));
        let fi = listed.get("a.txt").unwrap();
        assert_eq!(fi.size, 99);
        assert_eq!(fi.mtime, 9.0);
    }

    /// Regression: fat `FileRow` window / ZIP 1-row insert — compact_only skips SQL.
    #[test]
    fn regression_insert_files_batch_soa_compact_only_skips_sql() {
        let opts = OpenOptions {
            index_compact_only: true,
            ..OpenOptions::default()
        };
        let idx = SqliteIndex::create_writable_for_open(None, &opts).unwrap();
        let mut soa = FileRowSoa::with_capacity(1);
        soa.push(
            "/d",
            "f.txt",
            0,
            512,
            4,
            0.0,
            0o100644,
            i64::from(b'0'),
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        );
        idx.insert_files_batch_soa(&soa).unwrap();
        soa.clear();
        idx.store_versions("0.1.0").unwrap();
        let idx = idx.into_read_only().unwrap();
        assert_eq!(idx.files_table_row_count().unwrap(), 0);
        assert_eq!(idx.sql_files_type("/d", "f.txt", 0).unwrap(), None);
        assert!(idx.lookup("/d/f.txt", 0).unwrap().is_some());
    }

    #[test]
    fn insert_files_batch_soa_interns_identical_full_path_ids() {
        let mut soa = FileRowSoa::with_capacity(2);
        soa.push(
            "/same/full/path",
            "a",
            0,
            0,
            1,
            0.0,
            0,
            0,
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        );
        soa.push(
            "/same/full/path",
            "b",
            1,
            0,
            1,
            0.0,
            0,
            0,
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        );
        assert_eq!(
            soa.path_id_at(0),
            soa.path_id_at(1),
            "same full path string must share one path_id (not prefix segments)"
        );
    }

    /// Regression: fat `FileRow` window / ZIP 1-row insert — clear resets the window pool.
    #[test]
    fn regression_insert_files_batch_soa_clear_drops_window_pool() {
        let mut soa = FileRowSoa::with_capacity(2);
        soa.push(
            "/old/path",
            "x",
            0,
            0,
            1,
            0.0,
            0,
            8,
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        );
        assert!(soa.pool_unique_count() > 1);
        soa.clear();
        assert_eq!(
            soa.pool_unique_count(),
            1,
            "clear must leave only interned empty string (id 0)"
        );
        assert!(soa.is_empty());
        soa.push(
            "/new/path",
            "y",
            0,
            0,
            1,
            0.0,
            0,
            8,
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        );
        assert_eq!(
            soa.pool_unique_count(),
            3,
            "after clear, pool is {{'', path, name}} with no leftover /old/path"
        );
        assert_eq!(soa.path_at(0), "/new/path");
    }

    #[test]
    fn sql_files_type_is_pk_exact() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.insert_files_batch(&[
            FileRow::new(
                "",
                "foo",
                0,
                0,
                4,
                0.0,
                0o100644,
                i64::from(b'D'),
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            ),
            FileRow::new(
                "",
                "foo",
                1,
                0,
                0,
                0.0,
                0o40755,
                i64::from(b'D'),
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            ),
            FileRow::new(
                "",
                "foo",
                2,
                0,
                0,
                0.0,
                0o40755,
                i64::from(b'5'),
                "",
                0,
                0,
                false,
                false,
                true,
                0,
            ),
        ])
        .unwrap();
        assert_eq!(
            idx.sql_files_type("", "foo", 0).unwrap(),
            Some(i64::from(b'D'))
        );
        assert_eq!(
            idx.sql_files_type("", "foo", 1).unwrap(),
            Some(i64::from(b'D'))
        );
        assert_eq!(
            idx.sql_files_type("", "foo", 2).unwrap(),
            Some(i64::from(b'5'))
        );
        assert_eq!(idx.sql_files_type("", "foo", 99).unwrap(), None);
    }

    #[test]
    fn regression_insert_files_batch_soa_open_writable_sql_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("side.sqlite");
        {
            let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.store_metadata_key_value("backendName", "test").unwrap();
            let _ = idx.into_read_only().unwrap();
        }
        let idx = SqliteIndex::open_writable(&path).unwrap();
        let mut soa = FileRowSoa::with_capacity(1);
        soa.push(
            "/", "only.txt", 0, 512, 4, 0.0, 0o100644, 8, "", 0, 0, false, false, false, 0,
        );
        idx.insert_files_batch_soa(&soa).unwrap();
        soa.clear();
        assert_eq!(idx.sql_files_type("/", "only.txt", 0).unwrap(), Some(8));
    }

    fn write_page_fixture(path: &Path) {
        let idx = SqliteIndex::create_writable(Some(path)).unwrap();
        idx.store_versions("0.1.0").unwrap();
        idx.store_metadata_key_value("backendName", "SQLiteIndexedTar")
            .unwrap();
        let dumpdir = crate::search::DUMPDIR_DELETE_LINKNAME;
        let mut rows = Vec::new();
        for i in 0..30 {
            rows.push(FileRow::new(
                "",
                format!("n{i:02}.txt"),
                i as i64,
                512 + i as i64,
                4,
                1_700_000_000.0 + i as f64,
                0o100644,
                i64::from(b'0'),
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            ));
        }
        // Newest-wins: same name, higher offsetheader should win.
        rows.push(FileRow::new(
            "",
            "n00.txt",
            100,
            999,
            99,
            1_800_000_000.0,
            0o100644,
            i64::from(b'0'),
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        ));
        rows.push(FileRow::new(
            "",
            "gone.txt",
            500,
            0,
            0,
            0.0,
            0,
            i64::from(b'D'),
            dumpdir,
            0,
            0,
            false,
            false,
            true,
            0,
        ));
        // NULL offsetheader (Python non-TAR) then a later non-NULL duplicate.
        rows.push(FileRow::new(
            "",
            "nullwin.txt",
            50,
            0,
            99,
            0.0,
            0o100644,
            i64::from(b'0'),
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        ));
        idx.insert_files_batch(&rows).unwrap();
        idx.with_conn(|conn| {
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'nullwin.txt', NULL, 0, 1, 0, 33188, 48, '', 0, 0, 0, 0, 0, 0)"#,
                [],
            )?;
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'nullonly.txt', NULL, 0, 3, 0, 33188, 48, '', 0, 0, 0, 0, 0, 0)"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let _ = idx.into_read_only().unwrap();
    }

    /// Catalog RO open must not print the harness line and must not load MemIndex.
    ///
    /// libtest captures `println!`, so the silent-open assertion uses a child
    /// of this test binary (`--nocapture`).
    #[test]
    fn open_catalog_read_only() {
        if let Ok(p) = std::env::var("RATARMOUNT_OPEN_CATALOG_CHILD") {
            let idx = SqliteIndex::open_catalog_read_only(p).expect("open_catalog_read_only");
            assert!(!idx.has_mem_index(), "catalog mem must stay None");
            assert!(idx.file_count_db().unwrap() < MEM_INDEX_MAX_FILES);
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cat.index.sqlite");
        {
            let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.store_metadata_key_value("backendName", "SQLiteIndexedTar")
                .unwrap();
            idx.insert_files_batch(&[one_file_row()]).unwrap();
            let _ = idx.into_read_only().unwrap();
        }
        assert!(
            std::fs::metadata(&path).unwrap().len() > 0,
            "sidecar should exist"
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env("RATARMOUNT_OPEN_CATALOG_CHILD", &path)
            .args(["tests::open_catalog_read_only", "--exact", "--nocapture"])
            .output()
            .expect("spawn open_catalog_read_only child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "child failed: stdout={stdout} stderr={stderr}"
        );
        assert!(
            !stdout.contains("Successfully loaded offset dictionary"),
            "catalog open must not print harness line: {stdout}"
        );
    }

    /// Dumpdir tombstone absent; keyset pages; window SQL prepares.
    #[test]
    fn list_dirents_page() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page.index.sqlite");
        write_page_fixture(&path);
        let idx = SqliteIndex::open_catalog_read_only(&path).unwrap();

        let fuse = idx.list_dirents("/").unwrap().expect("fuse list");
        assert!(
            fuse.iter().any(|d| d.name == "gone.txt"),
            "list_dirents must still return dumpdir tombstones"
        );

        let (page1, next, total) = idx.list_dirents_page("/", None, 10).unwrap();
        assert!(
            page1.iter().all(|d| d.name != "gone.txt"),
            "dumpdir tombstone must be absent from page: {:?}",
            page1.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
        assert_eq!(page1.len(), 10);
        assert_eq!(page1[0].name, "n00.txt");
        assert_eq!(page1[0].size, 99, "newest-wins by offsetheader");
        assert_eq!(page1[0].mtime, Some(1_800_000_000.0));
        assert_eq!(page1[0].offsetheader, 100);
        let next = next.expect("more pages");
        assert_eq!(next, page1.last().unwrap().name);
        let hint = total.expect("COUNT");
        assert_eq!(hint, 32, "30 nXX + nullwin + nullonly, dumpdir excluded");

        let (page2, next2, _) = idx.list_dirents_page("/", Some(next.as_str()), 10).unwrap();
        assert_eq!(page2.len(), 10);
        let names1: Vec<_> = page1.iter().map(|d| d.name.as_str()).collect();
        let names2: Vec<_> = page2.iter().map(|d| d.name.as_str()).collect();
        for n in &names1 {
            assert!(!names2.contains(n), "overlap {n}");
        }
        assert!(names2[0] > names1[names1.len() - 1]);
        assert!(next2.is_some());

        let (last, last_next, _) = idx
            .list_dirents_page("/", Some(page2.last().unwrap().name.as_str()), 20)
            .unwrap();
        assert_eq!(last.len(), 12);
        assert!(last_next.is_none());
        let mut all: Vec<String> = names1
            .into_iter()
            .chain(names2)
            .chain(last.iter().map(|d| d.name.as_str()))
            .map(|s| s.to_string())
            .collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 32);
        assert!(!all.iter().any(|n| n == "gone.txt"));

        let (full, _, _) = idx.list_dirents_page("/", None, 100).unwrap();
        let nullwin = full.iter().find(|d| d.name == "nullwin.txt").unwrap();
        assert_eq!(nullwin.size, 99, "non-NULL offsetheader wins over NULL");
        assert_eq!(nullwin.offsetheader, 50);
        let nullonly = full.iter().find(|d| d.name == "nullonly.txt").unwrap();
        assert_eq!(
            nullonly.offsetheader, -1,
            "NULL-only offsetheader is the -1 sentinel"
        );
    }
}
