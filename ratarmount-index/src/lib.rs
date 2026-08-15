//! SQLite index compatible with Python `ratarmountcore.SQLiteIndex` (v0.7.0).

mod hashing;
mod location;
mod mem;
mod nested;

pub use hashing::{
    compute_hashes_limited, fill_content_hashes, hash_hex, normalize_algorithm,
    SUPPORTED_HASH_ALGORITHMS,
};
pub use location::{
    default_index_folders, default_index_path, expand_user, is_index_url, materialize_index_file,
    maybe_fetch_index_url, parse_index_folders, possible_index_paths, resolve_index_location,
    sibling_index_url, IndexLocation, MEMORY_INDEX,
};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ratarmount_core::{
    create_root_file_info, query_normpath, FileInfo, SQLiteIndexedTarUserData, UserData,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use thiserror::Error;

use mem::{mem_index_from_sql_rows, MemIndex, MemIndexBuilder, SqlMemRow};
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

/// Must match Python `SQLiteIndex.__version__`.
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
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};

    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();

    let mut prefix = vec![0u8; TARSTATS_SAMPLE_BYTES.min(len as usize)];
    if !prefix.is_empty() {
        f.read_exact(&mut prefix)?;
    }
    let prefix_hex = format!("{:x}", Sha256::digest(&prefix));

    let suffix_hex = if len == 0 {
        prefix_hex.clone()
    } else if len as usize <= TARSTATS_SAMPLE_BYTES {
        // Entire file already in prefix.
        prefix_hex.clone()
    } else {
        let mut suffix = vec![0u8; TARSTATS_SAMPLE_BYTES];
        f.seek(SeekFrom::End(-(TARSTATS_SAMPLE_BYTES as i64)))?;
        f.read_exact(&mut suffix)?;
        format!("{:x}", Sha256::digest(&suffix))
    };
    Ok((prefix_hex, suffix_hex))
}

/// Full-file SHA-256 when `path` is at most [`TARSTATS_FULL_HASH_MAX`] bytes.
pub fn archive_full_hash(path: &Path) -> Result<Option<String>> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > TARSTATS_FULL_HASH_MAX {
        return Ok(None);
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.read_to_end(&mut buf)?;
    Ok(Some(format!("{:x}", Sha256::digest(&buf))))
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
}

impl SqliteIndex {
    /// Open an existing index file read-only (Phase 0).
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
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
        };
        idx.validate_loaded()?;
        // Load compact projection for archives with a manageable file count.
        if let Ok(n) = idx.file_count_db() {
            if n > 0 && n <= MEM_INDEX_MAX_FILES {
                idx.mem = Some(idx.load_mem_index()?);
            }
        }
        // Harness contract: Python prints this when logger level is WARNING+
        println!(
            "Successfully loaded offset dictionary from {}",
            path.display()
        );
        Ok(idx)
    }

    /// Create a new writable index at `path` (or `:memory:`).
    ///
    /// Applies Python-compatible bulk-build PRAGMAs (exclusive lock, memory temp,
    /// journal off, synchronous off) so cold index creation stays fast.
    ///
    /// Also starts a [`MemIndexBuilder`] so path/name strings are interned and
    /// compact rows are filled at insert time (no fat dual maps at seal).
    pub fn create_writable(path: Option<&Path>) -> Result<Self> {
        let (conn, path_buf) = match path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // Truncate any prior incomplete index so CREATE IF NOT EXISTS is clean.
                if p.exists() {
                    std::fs::remove_file(p)?;
                }
                (Connection::open(p)?, Some(p.to_path_buf()))
            }
            None => (Connection::open_in_memory()?, None),
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
                let offsetheader: i64 = row.get(2)?;
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

    /// Seal a writable build into a read-only mount index (keeps in-memory DBs alive).
    ///
    /// Prefer this over `drop` + `open_read_only` so `--index-file :memory:` works and
    /// we avoid an extra open syscall for on-disk indexes.
    ///
    /// Promotes the insert-time compact [`MemIndexBuilder`] to the hot MemIndex (string
    /// pool + compact rows) when the row count is within [`MEM_INDEX_MAX_FILES`].
    ///
    /// On-disk indexes leave bulk-build `locking_mode=EXCLUSIVE` / `journal_mode=OFF` and
    /// **reopen** as a true read-only connection. Otherwise the exclusive file lock is not
    /// fully released until the connection is closed, and factory side-table writers
    /// (`open_writable` for gzip/zstd/bzip2 blocks, `--index-minimum-file-count`) hit
    /// `database is locked` while the mount still holds the index.
    pub fn into_read_only(mut self) -> Result<Self> {
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

    fn with_conn<F, T>(&self, f: F) -> Result<T>
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
                SELECT name, offsetheader, offset, size, mode,
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
                let offsetheader: i64 = row.get(1)?;
                let offset: i64 = row.get(2)?;
                let size: i64 = row.get(3)?;
                let mode: i64 = row.get(4)?;
                let istar: bool = row.get::<_, i64>(5).unwrap_or(0) != 0;
                let issparse: bool = row.get::<_, i64>(6).unwrap_or(0) != 0;
                let isgenerated: bool = row.get::<_, i64>(7).unwrap_or(0) != 0;
                let recursiondepth: i64 = row.get(8).unwrap_or(0);
                let size_u = size.max(0) as u64;
                let mode_u = mode as u32;
                by_name.insert(
                    name.clone(),
                    IndexDirent {
                        name,
                        mode: mode_u,
                        size: size_u,
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
                let mut stmt = conn.prepare_cached(
                    r#"
                INSERT OR REPLACE INTO "files"
                (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                 uid, gid, istar, issparse, isgenerated, recursiondepth)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
                "#,
                )?;
                for r in rows {
                    stmt.execute(params![
                        r.path,
                        r.name,
                        r.offsetheader,
                        r.offset,
                        r.size,
                        r.mtime,
                        r.mode,
                        r.typeflag,
                        r.linkname,
                        r.uid,
                        r.gid,
                        r.istar,
                        r.issparse,
                        r.isgenerated,
                        r.recursiondepth,
                    ])?;
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

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
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

    /// Regression: warm index must not be trusted when archive size/mtime/content no longer match tarstats.
    #[test]
    fn check_tarstats_matches_archive_rejects_size_or_mtime_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, b"old-content").unwrap();
        let idx_path = dir.path().join("a.tar.index.sqlite");
        {
            let idx = SqliteIndex::create_writable(Some(&idx_path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.store_tarstats_for_path(&archive).unwrap();
            let ts = idx.tarstats().unwrap().unwrap();
            assert!(ts.prefix512_sha256.is_some());
            assert!(ts.suffix512_sha256.is_some());
            assert!(
                ts.full_sha256.is_some(),
                "tiny archive should store full_sha256"
            );
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

    #[test]
    fn xattr_insert_list_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.index.sqlite");
        let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
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
            let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.set_gzip_index_blob(b"persist-me").unwrap();
            idx.set_bzip2_blocks(&[(0, 0), (100, 50), (200, 120)])
                .unwrap();
            idx.set_zstd_blocks(&[(1, 10), (2, 20)]).unwrap();
            idx.set_gztool_index_blob(b"gztool-blob").unwrap();
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
            let idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.store_versions("0.1.0").unwrap();
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
}
