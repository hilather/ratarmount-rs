//! SQLite index compatible with Python `ratarmountcore.SQLiteIndex` (v0.7.0).

mod location;

pub use location::{
    default_index_folders, default_index_path, expand_user, parse_index_folders,
    possible_index_paths, resolve_index_location, IndexLocation, MEMORY_INDEX,
};

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ratarmount_core::{
    create_root_file_info, query_normpath, FileInfo, SQLiteIndexedTarUserData, UserData,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use thiserror::Error;

/// In-memory projection of the `files` table for RO mounts (avoids SQLite on hot paths).
struct MemIndex {
    /// (dir, name) → versions newest-last (by offsetheader).
    by_key: HashMap<(String, String), Vec<FileInfo>>,
    /// dir → name → FileInfo (newest version).
    by_dir: HashMap<String, BTreeMap<String, FileInfo>>,
    /// dir → name → mode (newest).
    modes: HashMap<String, BTreeMap<String, u32>>,
    count: u64,
}

/// Must match Python `SQLiteIndex.__version__`.
pub const INDEX_VERSION: &str = "0.7.0";

/// Embedded core schema (`create-index-tables.sql`). Compression side tables are runtime-only.
pub const CREATE_TABLES_SQL: &str = include_str!("../create-index-tables.sql");

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
    #[error("index is not open")]
    NotOpen,
}

pub type Result<T> = std::result::Result<T, IndexError>;

/// Open and query an existing ratarmount SQLite index.
///
/// Connection is behind a `Mutex` so the type is `Sync` for FUSE multi-threaded callbacks.
/// Read-only opens load a full in-memory projection when the table is not huge.
pub struct SqliteIndex {
    path: Option<PathBuf>,
    conn: Mutex<Connection>,
    read_only: bool,
    mem: Option<MemIndex>,
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
        };
        idx.validate_loaded()?;
        // Load into RAM for archives with a manageable file count (typical mounts).
        if let Ok(n) = idx.file_count_db() {
            if n > 0 && n <= 500_000 {
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
        Ok(Self {
            path: path_buf,
            conn: Mutex::new(conn),
            read_only: false,
            mem: None,
        })
    }

    fn file_count_db(&self) -> Result<u64> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM \"files\"", [], |r| r.get(0))?;
            Ok(n as u64)
        })
    }

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
            let mut by_key: HashMap<(String, String), Vec<FileInfo>> = HashMap::new();
            let mut by_dir: HashMap<String, BTreeMap<String, FileInfo>> = HashMap::new();
            let mut modes: HashMap<String, BTreeMap<String, u32>> = HashMap::new();
            let mut count = 0u64;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let path: String = row.get(0)?;
                let name: String = row.get(1)?;
                if name.is_empty() {
                    continue;
                }
                let fi = row_to_file_info(row)?;
                count += 1;
                by_key
                    .entry((path.clone(), name.clone()))
                    .or_default()
                    .push(fi.clone());
                by_dir
                    .entry(path.clone())
                    .or_default()
                    .insert(name.clone(), fi.clone());
                modes
                    .entry(path)
                    .or_default()
                    .insert(name, fi.mode);
            }
            Ok(MemIndex {
                by_key,
                by_dir,
                modes,
                count,
            })
        })
    }

    /// Begin an exclusive write transaction for bulk index builds.
    pub fn begin_write(&self) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
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
        self.with_conn(|conn| {
            conn.execute_batch("COMMIT")?;
            Ok(())
        })
    }

    /// Finalize a freshly built index: commit if needed, then reopen is left to caller.
    pub fn finalize_build(&self) -> Result<()> {
        if self.read_only {
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
    pub fn into_read_only(mut self) -> Result<Self> {
        self.finalize_build()?;
        if !self.read_only {
            self.with_conn(|conn| {
                // Drop intermediary tables so Python's completeness check accepts the index.
                let _ = conn.execute_batch(
                    r#"
                    DROP TABLE IF EXISTS "filestmp";
                    DROP TABLE IF EXISTS "parentfolders";
                    "#,
                );
                conn.execute_batch(
                    r#"
                    PRAGMA locking_mode = NORMAL;
                    PRAGMA query_only = ON;
                    PRAGMA temp_store = MEMORY;
                    PRAGMA cache_size = -65536;
                    PRAGMA mmap_size = 268435456;
                    "#,
                )?;
                Ok(())
            })?;
            self.read_only = true;
        }
        if self.mem.is_none() {
            if let Ok(n) = self.file_count_db() {
                if n > 0 && n <= 500_000 {
                    self.mem = Some(self.load_mem_index()?);
                }
            }
        }
        if let Some(path) = &self.path {
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
        if tables.iter().any(|t| t == "filestmp" || t == "parentfolders") {
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
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_master WHERE type='table' OR type='view'",
            )?;
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

    pub fn file_count(&self) -> Result<u64> {
        if let Some(m) = &self.mem {
            return Ok(m.count);
        }
        self.file_count_db()
    }

    /// Number of distinct index rows (versions) for `path` (0 if missing).
    pub fn version_count(&self, path: &str) -> Result<u32> {
        let path = query_normpath(path);
        if path == "/" {
            return Ok(1);
        }
        let (dir, name) = split_path(&path);
        if let Some(mem) = &self.mem {
            return Ok(mem
                .by_key
                .get(&(dir, name))
                .map(|v| v.len() as u32)
                .unwrap_or(0));
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
            let Some(versions) = mem.by_key.get(&(dir, name)) else {
                return Ok(None);
            };
            if versions.is_empty() {
                return Ok(None);
            }
            // versions stored oldest→newest (ORDER BY offsetheader ASC)
            let idx = if file_version <= 0 {
                let n = (-file_version) as usize;
                versions.len().saturating_sub(1 + n)
            } else {
                (file_version as usize).saturating_sub(1)
            };
            return Ok(versions.get(idx).cloned());
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
            return Ok(mem.by_dir.get(&dir).cloned());
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
        let path = query_normpath(path);
        let dir = path.trim_end_matches('/').to_string();

        if let Some(mem) = &self.mem {
            return Ok(mem.modes.get(&dir).cloned());
        }

        self.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                r#"SELECT name, mode FROM "files" WHERE "path" = ?1 ORDER BY "offsetheader""#,
            )?;
            let mut map = BTreeMap::new();
            let mut rows = stmt.query(params![dir])?;
            let mut got = false;
            while let Some(row) = rows.next()? {
                got = true;
                let name: String = row.get(0)?;
                if name.is_empty() {
                    continue;
                }
                let mode: i64 = row.get(1)?;
                map.insert(name, mode as u32);
            }
            Ok(if got { Some(map) } else { None })
        })
    }

    /// Store version rows used by Python writers.
    pub fn store_versions(&self, ratarmount_version: &str) -> Result<()> {
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        let versions = [
            ("ratarmount", ratarmount_version),
            ("index", INDEX_VERSION),
        ];
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
    pub fn insert_files_batch(&self, rows: &[FileRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        if self.read_only {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn py_fixture(rel: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT").unwrap_or_else(|_| {
            "/home/mbrewer/projects/ratarmount".into()
        });
        PathBuf::from(root).join(rel)
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
}
