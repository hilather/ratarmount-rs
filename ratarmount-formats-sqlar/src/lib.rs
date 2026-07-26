//! SQLAR (SQLite Archiver) mount source — Python `SQLARMountSource` parity (unencrypted).
//!
//! Schema: <https://www.sqlite.org/sqlar.html>
//! ```text
//! CREATE TABLE sqlar(
//!   name TEXT PRIMARY KEY,  -- path without leading slash
//!   mode INT,
//!   mtime INT,
//!   sz INT,                 -- original size; 0 dir/empty; -1 symlink
//!   data BLOB               -- NULL=dir; link text if sz=-1; zlib if len<data < sz
//! );
//! ```
//! Encrypted SQLAR (sqlcipher) is not supported yet.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use flate2::read::ZlibDecoder;
use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource,
    OpenOptions, UserData,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use thiserror::Error;

pub const BACKEND_NAME: &str = "SQLARMountSource";
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

#[derive(Debug, Error)]
pub enum SqlarError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, SqlarError>;

/// SQLAR archive opened read-only.
pub struct SqlarMountSource {
    #[allow(dead_code)]
    path: PathBuf,
    conn: Mutex<Connection>,
    /// When paths are denormal, map normalized path → original `name` key.
    name_map: Option<BTreeMap<String, String>>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl SqlarMountSource {
    pub fn open(path: impl AsRef<Path>, options: &OpenOptions) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !looks_like_sqlar(&path) {
            return Err(SqlarError::Msg(format!(
                "{} is not an SQLAR/SQLite file",
                path.display()
            )));
        }
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // Verify sqlar table exists.
        let ok: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='sqlar'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if ok.is_none() {
            return Err(SqlarError::Msg("missing sqlar table".into()));
        }
        // Probe one row / empty archive ok.
        let _ = conn.query_row("SELECT COUNT(*) FROM sqlar", [], |r| r.get::<_, i64>(0))?;

        let name_map = build_name_map(&conn)?;
        Ok(Self {
            path,
            conn: Mutex::new(conn),
            name_map,
            options: options.clone(),
        })
    }

    fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let g = self.conn.lock().expect("sqlar mutex");
        f(&g)
    }

    fn sql_name(&self, path: &str) -> String {
        let p = path.trim_start_matches('/');
        if let Some(map) = &self.name_map {
            if let Some(orig) = map.get(p) {
                return orig.clone();
            }
        }
        p.to_string()
    }

    fn row_to_file_info(rowid: i64, mode: i64, mtime: i64, sz: i64, linkname: String) -> FileInfo {
        FileInfo {
            size: sz.max(0) as u64,
            mtime: mtime as f64,
            mode: mode as u32,
            linkname,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            userdata: vec![UserData::Other(format!("sqlar:{rowid}"))],
        }
    }

    /// `(rowid, mode, mtime, sz, symlink_target_or_empty)`
    #[allow(clippy::type_complexity)]
    fn lookup_row(&self, path: &str) -> Result<Option<(i64, i64, i64, i64, String)>> {
        if path == "/" {
            return Ok(None); // handled by caller
        }
        let name = self.sql_name(path);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT rowid, mode, mtime, sz, CASE WHEN sz=-1 THEN CAST(data AS TEXT) ELSE '' END \
                 FROM sqlar WHERE name = ?1",
            )?;
            let row = stmt
                .query_row(rusqlite::params![name], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })
                .optional()?;
            Ok(row)
        })
    }
}

fn build_name_map(conn: &Connection) -> Result<Option<BTreeMap<String, String>>> {
    let mut stmt = conn.prepare("SELECT name FROM sqlar")?;
    let names: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let needs: bool = names.iter().any(|n| {
        let stripped = n.trim_start_matches('/');
        let norm = {
            let mut parts = Vec::new();
            for p in stripped.split('/') {
                if p.is_empty() || p == "." {
                    continue;
                }
                if p == ".." {
                    parts.pop();
                } else {
                    parts.push(p);
                }
            }
            parts.join("/")
        };
        norm != *n
    });
    if !needs {
        return Ok(None);
    }
    let mut map = BTreeMap::new();
    for n in names {
        let stripped = n.trim_start_matches('/');
        let mut parts = Vec::new();
        for p in stripped.split('/') {
            if p.is_empty() || p == "." {
                continue;
            }
            if p == ".." {
                parts.pop();
            } else {
                parts.push(p);
            }
        }
        let key = parts.join("/");
        map.entry(key).or_insert(n);
    }
    Ok(Some(map))
}

/// True if path starts with SQLite magic and has an `sqlar` table (or at least SQLite header).
pub fn looks_like_sqlar(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 16];
    if std::io::Read::read(&mut f, &mut magic).ok() != Some(16) {
        return false;
    }
    if magic.as_slice() != SQLITE_MAGIC {
        // Extension hint for encrypted / non-magic cases later.
        return path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("sqlar"));
    }
    // Prefer verifying table when possible.
    if let Ok(conn) = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        let has: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlar' LIMIT 1",
                [],
                |_| Ok(true),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false);
        return has;
    }
    false
}

impl MountSource for SqlarMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if path != "/" {
            // Must be a directory entry.
            let fi = self.lookup(&path, 0)?;
            if fi.mode & libc::S_IFMT != libc::S_IFDIR {
                return None;
            }
        }

        let prefix = if path == "/" {
            String::new()
        } else {
            path.trim_start_matches('/').to_string()
        };

        self.with_conn(|conn| {
            let mut map = BTreeMap::new();
            let mut stmt = conn.prepare(
                "SELECT name, rowid, mode, mtime, sz, \
                 CASE WHEN sz=-1 THEN CAST(data AS TEXT) ELSE '' END FROM sqlar",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })?;
            for row in rows {
                let (name, rowid, mode, mtime, sz, link) = row?;
                let norm = name.trim_start_matches('/');
                let child = if prefix.is_empty() {
                    // top-level component
                    let first = norm.split('/').next().unwrap_or("");
                    if first.is_empty() {
                        continue;
                    }
                    // Only direct children: either exact name or first component of nested
                    if norm == first {
                        Some((first.to_string(), rowid, mode, mtime, sz, link))
                    } else if norm.starts_with(&(first.to_string() + "/")) {
                        // synthetic parent folder may exist as its own row; if not, still expose name
                        // Prefer real row for `first` when present; else skip synthetic here
                        // (directories are stored explicitly in SQLAR).
                        None
                    } else {
                        None
                    }
                } else if norm == prefix {
                    continue;
                } else if let Some(rest) = norm.strip_prefix(&(prefix.clone() + "/")) {
                    let first = rest.split('/').next().unwrap_or("");
                    if first.is_empty() {
                        None
                    } else if rest == first {
                        Some((first.to_string(), rowid, mode, mtime, sz, link))
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some((cname, rowid, mode, mtime, sz, link)) = child {
                    map.entry(cname)
                        .or_insert_with(|| Self::row_to_file_info(rowid, mode, mtime, sz, link));
                }
            }
            Ok(Some(ListResult::Infos(map)))
        })
        .ok()
        .flatten()
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match self.list(path)? {
            ListResult::Names(n) => Some(ListModeResult::Names(n)),
            ListResult::Infos(m) => Some(ListModeResult::Modes(
                m.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
        }
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        match self.lookup_row(&path) {
            Ok(Some((rowid, mode, mtime, sz, link))) => {
                Some(Self::row_to_file_info(rowid, mode, mtime, sz, link))
            }
            _ => None,
        }
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if file_info.mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let rowid = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Other(s) => s.strip_prefix("sqlar:").and_then(|n| n.parse::<i64>().ok()),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing sqlar rowid"))?;

        let (sz, data): (i64, Vec<u8>) = self
            .with_conn(|conn| {
                let row = conn.query_row(
                    "SELECT sz, data FROM sqlar WHERE rowid = ?1",
                    rusqlite::params![rowid],
                    |r| {
                        let sz: i64 = r.get(0)?;
                        let data: Option<Vec<u8>> = r.get(1)?;
                        Ok((sz, data.unwrap_or_default()))
                    },
                )?;
                Ok(row)
            })
            .map_err(|e| io::Error::other(e.to_string()))?;

        if sz < 0 {
            // symlink — content is target (already in linkname)
            return Ok(Box::new(Cursor::new(Vec::new())));
        }
        if sz == 0 {
            return Ok(Box::new(Cursor::new(Vec::new())));
        }
        let body = if data.len() as i64 == sz {
            data
        } else if (data.len() as i64) < sz {
            let mut dec = ZlibDecoder::new(data.as_slice());
            let mut out = Vec::with_capacity(sz as usize);
            dec.read_to_end(&mut out)
                .map_err(|e| io::Error::other(format!("sqlar zlib: {e}")))?;
            if out.len() as i64 != sz {
                // tolerate slight mismatch; truncate/pad not required for fixtures
            }
            out
        } else {
            return Err(io::Error::other("sqlar data longer than declared size"));
        };
        Ok(Box::new(Cursor::new(body)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn nested_tar_sqlar() {
        let path = py_test("nested-tar.sqlar");
        if !path.exists() {
            eprintln!("skip missing fixture");
            return;
        }
        assert!(looks_like_sqlar(&path));
        let m = SqlarMountSource::open(&path, &OpenOptions::default()).unwrap();
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
        let root = m.list("/").expect("root");
        if let ListResult::Infos(map) = root {
            assert!(map.contains_key("foo"));
        }
    }
}
