//! Locate over the 0.7.x `files` catalog (F-3).
//!
//! Default query is SQL `GLOB` (or `LIKE` when the pattern uses `%`/`_` and no
//! glob metacharacters). Optional FTS5 is an additive `"files_fts"` table created
//! only by [`SqliteIndex::ensure_fts5`] — never by [`SqliteIndex::create_writable`].
//!
//! Workspace rusqlite 0.32 has no `fts5` cargo feature. Bundled libsqlite3-sys
//! always compiles `SQLITE_ENABLE_FTS5`, so FTS5 cannot be compiled out of the
//! binary. “Optional FTS5” means the table and `MATCH` query, not a second sqlite
//! build. [`crate::INDEX_VERSION`] stays `"0.7.0"`; Python ignores unknown tables.

use rusqlite::{params, Connection, Row};

use crate::{table_exists, IndexError, Result, SqliteIndex};

/// Cap on locate hits when the caller does not set [`SearchQuery::limit`].
pub const DEFAULT_SEARCH_LIMIT: usize = 10_000;

/// Additive FTS5 virtual table (not in `create-index-tables.sql`).
pub(crate) const FILES_FTS_TABLE: &str = "files_fts";

/// GNU dumpdir whiteout stored in `files.linkname` (formats-tar marker).
const DUMPDIR_DELETE_LINKNAME: &str = "\0GNU.dumpdir.delete";

const CREATE_FILES_FTS_SQL: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS "files_fts" USING fts5(
  fullpath,
  hashes,
  path UNINDEXED,
  name UNINDEXED,
  offsetheader UNINDEXED,
  tokenize = 'unicode61'
);
"#;

/// SQL expression for the locate full path (`/name` at root, `path || '/' || name`).
const SQL_FULLPATH: &str = r#"CASE
    WHEN "path" IS NULL OR "path" = '' OR "path" = '/' THEN '/' || "name"
    ELSE "path" || '/' || "name"
END"#;

/// One catalog hit from [`SqliteIndex::search`] / [`SqliteIndex::search_fts`].
#[derive(Clone, Debug, PartialEq)]
pub struct SearchHit {
    /// Full path (`/name` or `/dir/name`), suitable for TSV locate output.
    pub path: String,
    /// Basename (`files.name`).
    pub name: String,
    pub size: i64,
    pub mtime: f64,
    pub offsetheader: Option<i64>,
    /// `user.hash.*` xattrs as `(key, utf-8 value)` when [`SearchQuery::include_hashes`].
    pub hashes: Vec<(String, String)>,
}

/// Locate query. Glob/LIKE is the default; FTS5 `MATCH` is opt-in.
#[derive(Clone, Debug)]
pub struct SearchQuery<'a> {
    pub pattern: &'a str,
    /// Use FTS5 `MATCH` on `"files_fts"` (must already exist).
    pub fts: bool,
    /// Attach `user.hash.*` xattrs to each hit.
    pub include_hashes: bool,
    /// Maximum rows (default [`DEFAULT_SEARCH_LIMIT`]).
    pub limit: usize,
}

impl<'a> SearchQuery<'a> {
    /// Locate-style glob/LIKE (no FTS5).
    pub fn glob(pattern: &'a str) -> Self {
        Self {
            pattern,
            fts: false,
            include_hashes: false,
            limit: DEFAULT_SEARCH_LIMIT,
        }
    }

    /// FTS5 `MATCH` over `fullpath` + hash payload. Caller must have run
    /// [`SqliteIndex::ensure_fts5`].
    pub fn fts(pattern: &'a str) -> Self {
        Self {
            pattern,
            fts: true,
            include_hashes: false,
            limit: DEFAULT_SEARCH_LIMIT,
        }
    }
}

impl SqliteIndex {
    /// Locate-style glob/LIKE over `files`. Does not create or query `"files_fts"`.
    ///
    /// `*.fits` matches any basename in any directory. `**` collapses to `*`.
    /// A pattern that contains `/` matches the reconstructed full path only.
    /// Generated parent rows and GNU dumpdir tombstones are omitted.
    pub fn search(&self, pattern: &str) -> Result<Vec<SearchHit>> {
        self.search_query(&SearchQuery::glob(pattern))
    }

    /// FTS5 `MATCH` over `"files_fts"` when that table exists.
    ///
    /// Returns [`IndexError::Invalid`] if `"files_fts"` is missing — this method
    /// never calls [`Self::ensure_fts5`] (normal cold index / mount must not
    /// grow an FTS table).
    pub fn search_fts(&self, pattern: &str) -> Result<Vec<SearchHit>> {
        self.search_query(&SearchQuery::fts(pattern))
    }

    /// Run a glob or FTS5 locate query.
    pub fn search_query(&self, q: &SearchQuery<'_>) -> Result<Vec<SearchHit>> {
        if self.is_compact_only() {
            return Ok(Vec::new());
        }
        if q.pattern.is_empty() || q.limit == 0 {
            return Ok(Vec::new());
        }
        self.with_conn(|conn| {
            let mut hits = if q.fts {
                search_fts_match(conn, q.pattern, q.limit)?
            } else {
                search_glob_like(conn, q.pattern, q.limit)?
            };
            if q.include_hashes {
                fill_hit_hashes(conn, &mut hits)?;
            }
            Ok(hits)
        })
    }

    /// Create (if needed) and refill the additive `"files_fts"` table.
    ///
    /// Not invoked from [`Self::create_writable`] / cold index. Find `--fts`
    /// (F3-2) is the expected caller. Idempotent.
    pub fn ensure_fts5(&self) -> Result<()> {
        if self.is_read_only() {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if self.is_compact_only() {
            return Ok(());
        }
        self.with_conn(ensure_files_fts_table)
    }

    /// Whether the additive `"files_fts"` table exists (FTS5 or otherwise).
    pub fn has_files_fts(&self) -> Result<bool> {
        self.with_conn(|conn| table_exists(conn, FILES_FTS_TABLE))
    }
}

/// Refill `"files_fts"` when it already exists (F-2 suffix patch hook).
pub(crate) fn refill_files_fts(conn: &Connection) -> Result<()> {
    conn.execute(r#"DELETE FROM "files_fts""#, [])?;
    fill_files_fts(conn)?;
    let n: i64 = conn.query_row(r#"SELECT COUNT(*) FROM "files_fts""#, [], |r| r.get(0))?;
    log::debug!("files_fts built, {n} rows");
    Ok(())
}

fn ensure_files_fts_table(conn: &Connection) -> Result<()> {
    if !table_exists(conn, FILES_FTS_TABLE)? {
        conn.execute_batch(CREATE_FILES_FTS_SQL)?;
    }
    refill_files_fts(conn)
}

fn fill_files_fts(conn: &Connection) -> Result<()> {
    conn.execute(
        r#"
            INSERT INTO "files_fts" (fullpath, hashes, path, name, offsetheader)
            SELECT
              CASE
                WHEN f."path" IS NULL OR f."path" = '' OR f."path" = '/' THEN '/' || f."name"
                ELSE f."path" || '/' || f."name"
              END,
              COALESCE((
                SELECT group_concat(substr(x."key", 11) || ' ' || CAST(x."value" AS TEXT), ' ')
                FROM "xattrs" x
                WHERE x."offsetheader" IS f."offsetheader"
                  AND x."key" LIKE 'user.hash.%'
              ), ''),
              f."path",
              f."name",
              f."offsetheader"
            FROM "files" f
            WHERE COALESCE(f."isgenerated", 0) = 0
              AND COALESCE(f."linkname", '') != ?1
              AND f."name" != ''
            "#,
        params![DUMPDIR_DELETE_LINKNAME],
    )?;
    Ok(())
}

fn catalog_filter_sql(table: &str) -> String {
    let p = if table.is_empty() {
        String::new()
    } else {
        format!("{table}.")
    };
    format!(
        r#"
        COALESCE({p}"isgenerated", 0) = 0
        AND COALESCE({p}"linkname", '') != ?1
        AND {p}"name" != ''
        "#
    )
}

fn search_glob_like(conn: &Connection, pattern: &str, limit: usize) -> Result<Vec<SearchHit>> {
    let glob = collapse_globstars(pattern);
    let use_like = is_like_pattern(&glob);
    let full_path = glob.contains('/');
    let bound = if full_path && !glob.starts_with('/') {
        format!("/{glob}")
    } else {
        glob
    };
    let pred = if full_path {
        if use_like {
            format!("{SQL_FULLPATH} LIKE ?2")
        } else {
            format!("{SQL_FULLPATH} GLOB ?2")
        }
    } else if use_like {
        r#""name" LIKE ?2"#.to_string()
    } else {
        r#""name" GLOB ?2"#.to_string()
    };
    let sql = format!(
        r#"
        SELECT {SQL_FULLPATH} AS fullpath, "name", "size", "mtime", "offsetheader"
        FROM "files"
        WHERE {filter}
          AND {pred}
        ORDER BY fullpath, "offsetheader"
        LIMIT ?3
        "#,
        filter = catalog_filter_sql(""),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params![DUMPDIR_DELETE_LINKNAME, bound, limit_i64(limit)],
        row_to_hit,
    )?;
    collect_hits(rows)
}

fn search_fts_match(conn: &Connection, pattern: &str, limit: usize) -> Result<Vec<SearchHit>> {
    if !table_exists(conn, FILES_FTS_TABLE)? {
        return Err(IndexError::Invalid(
            "files_fts is not present; call ensure_fts5".into(),
        ));
    }
    let sql = format!(
        r#"
        SELECT CASE
            WHEN f."path" IS NULL OR f."path" = '' OR f."path" = '/' THEN '/' || f."name"
            ELSE f."path" || '/' || f."name"
        END AS fullpath, f."name", f."size", f."mtime", f."offsetheader"
        FROM "files_fts"
        JOIN "files" f
          ON f."name" = "files_fts"."name"
         AND COALESCE(f."path", '') = COALESCE("files_fts"."path", '')
         AND f."offsetheader" IS "files_fts"."offsetheader"
        WHERE "files_fts" MATCH ?2
          AND {filter}
        ORDER BY fullpath, f."offsetheader"
        LIMIT ?3
        "#,
        filter = catalog_filter_sql("f"),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params![DUMPDIR_DELETE_LINKNAME, pattern, limit_i64(limit)],
        row_to_hit,
    )?;
    collect_hits(rows)
}

fn row_to_hit(row: &Row<'_>) -> rusqlite::Result<SearchHit> {
    Ok(SearchHit {
        path: row.get(0)?,
        name: row.get(1)?,
        size: row.get(2)?,
        mtime: row.get(3)?,
        offsetheader: row.get(4)?,
        hashes: Vec::new(),
    })
}

fn collect_hits(
    rows: rusqlite::MappedRows<'_, impl FnMut(&Row<'_>) -> rusqlite::Result<SearchHit>>,
) -> Result<Vec<SearchHit>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn fill_hit_hashes(conn: &Connection, hits: &mut [SearchHit]) -> Result<()> {
    if hits.is_empty() {
        return Ok(());
    }
    let mut stmt = conn.prepare(
        r#"
        SELECT "key", "value" FROM "xattrs"
        WHERE "offsetheader" IS ?1
          AND "key" LIKE 'user.hash.%'
        ORDER BY "key"
        "#,
    )?;
    for hit in hits.iter_mut() {
        let rows = stmt.query_map(params![hit.offsetheader], |row| {
            let key: String = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            Ok((key, String::from_utf8_lossy(&value).into_owned()))
        })?;
        let mut hashes = Vec::new();
        for row in rows {
            hashes.push(row?);
        }
        hit.hashes = hashes;
    }
    Ok(())
}

/// `**` (and longer star runs) → a single `*` (GLOB has no recursive glob).
fn collapse_globstars(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '*' {
            out.push('*');
            while chars.peek() == Some(&'*') {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn is_like_pattern(pattern: &str) -> bool {
    !pattern.contains(['*', '?', '[']) && pattern.contains(['%', '_'])
}

fn limit_i64(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileRow, SqliteIndex, CREATE_TABLES_SQL, INDEX_VERSION};

    fn file_row(path: &str, name: &str, offsetheader: i64, isgenerated: bool) -> FileRow {
        FileRow::new(
            path,
            name,
            offsetheader,
            offsetheader + 512,
            4,
            1.0,
            0o100644,
            0,
            "",
            0,
            0,
            true,
            false,
            isgenerated,
            0,
        )
    }

    fn dumpdir_row(name: &str, offsetheader: i64) -> FileRow {
        FileRow::new(
            "",
            name,
            offsetheader,
            offsetheader + 512,
            0,
            1.0,
            0o100644,
            0,
            DUMPDIR_DELETE_LINKNAME,
            0,
            0,
            true,
            false,
            false,
            0,
        )
    }

    fn hit_paths(hits: &[SearchHit]) -> Vec<&str> {
        hits.iter().map(|h| h.path.as_str()).collect()
    }

    fn seed_catalog(idx: &SqliteIndex) {
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "a.fits", 0, false),
            file_row("/dir", "b.fits", 512, false),
            file_row("", "readme.txt", 1024, false),
            file_row("/dir", "nested.txt", 1536, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();
    }

    /// Regression: locate `*.fits` returns every matching basename without FUSE.
    #[test]
    fn search_glob() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        seed_catalog(&idx);

        let hits = idx.search("*.fits").unwrap();
        assert_eq!(hit_paths(&hits), vec!["/a.fits", "/dir/b.fits"]);
        assert_eq!(hits[0].name, "a.fits");
        assert_eq!(hits[0].size, 4);
        assert_eq!(hits[0].mtime, 1.0);
        assert_eq!(hits[0].offsetheader, Some(0));
        assert!(hits[0].hashes.is_empty());

        let dir = idx.search("/dir/*").unwrap();
        assert_eq!(hit_paths(&dir), vec!["/dir/b.fits", "/dir/nested.txt"]);

        let rel = idx.search("dir/*.fits").unwrap();
        assert_eq!(hit_paths(&rel), vec!["/dir/b.fits"]);

        let exact = idx.search("readme.txt").unwrap();
        assert_eq!(hit_paths(&exact), vec!["/readme.txt"]);

        let stars = idx.search("**/*.fits").unwrap();
        assert_eq!(
            hit_paths(&stars),
            vec!["/dir/b.fits"],
            "** collapses to *; slash means full-path GLOB /*/*.fits"
        );

        let like = idx.search("%.txt").unwrap();
        assert_eq!(hit_paths(&like), vec!["/dir/nested.txt", "/readme.txt"]);

        assert!(idx.search("nope").unwrap().is_empty());
        assert!(idx.search("").unwrap().is_empty());
        assert_eq!(INDEX_VERSION, "0.7.0");
    }

    /// Regression: FTS5 MATCH on path + `user.hash.*` payload under default features.
    #[test]
    fn search_fts5() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        seed_catalog(&idx);
        idx.insert_xattr(
            0,
            "user.hash.sha256",
            b"b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
        )
        .unwrap();
        idx.insert_xattr(0, "user.hash.crc32", b"7e3265a8").unwrap();

        assert!(
            !idx.has_files_fts().unwrap(),
            "FTS table is not created until ensure_fts5"
        );
        let err = idx.search_fts("fits").unwrap_err();
        assert!(
            err.to_string().contains("files_fts"),
            "MATCH requires ensure_fts5, got {err}"
        );

        idx.ensure_fts5().unwrap();
        assert!(idx.has_files_fts().unwrap());
        assert_eq!(INDEX_VERSION, "0.7.0");

        let by_token = idx.search_fts("fits").unwrap();
        assert_eq!(hit_paths(&by_token), vec!["/a.fits", "/dir/b.fits"]);

        let by_hash = idx
            .search_fts("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")
            .unwrap();
        assert_eq!(hit_paths(&by_hash), vec!["/a.fits"]);

        let by_crc = idx.search_fts("7e3265a8").unwrap();
        assert_eq!(hit_paths(&by_crc), vec!["/a.fits"]);

        let q = SearchQuery {
            include_hashes: true,
            ..SearchQuery::fts("crc32")
        };
        let with_hashes = idx.search_query(&q).unwrap();
        assert_eq!(hit_paths(&with_hashes), vec!["/a.fits"]);
        let keys: Vec<&str> = with_hashes[0]
            .hashes
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(keys, vec!["user.hash.crc32", "user.hash.sha256"]);

        // Glob stays glob: token "fits" is not a basename.
        assert!(idx.search("fits").unwrap().is_empty());

        idx.ensure_fts5()
            .expect("ensure_fts5 is idempotent (rebuilds)");
        assert_eq!(idx.search_fts("fits").unwrap().len(), 2);
    }

    /// Regression: generated parents and dumpdir tombstones are not locate hits.
    #[test]
    fn search_skips_generated() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "keep.fits", 0, false),
            file_row("", "ghost.fits", 512, true),
            dumpdir_row("deleted.fits", 1024),
        ])
        .unwrap();
        idx.commit_write().unwrap();

        let hits = idx.search("*.fits").unwrap();
        assert_eq!(hit_paths(&hits), vec!["/keep.fits"]);

        idx.ensure_fts5().unwrap();
        let fts = idx.search_fts("fits").unwrap();
        assert_eq!(hit_paths(&fts), vec!["/keep.fits"]);
    }

    /// Regression: cold `create_writable` must not grow `"files_fts"`.
    #[test]
    fn ensure_fts5_not_on_create_writable() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        assert!(
            !idx.has_files_fts().unwrap(),
            "create_writable must not call ensure_fts5"
        );
        assert!(
            !CREATE_TABLES_SQL.contains("files_fts"),
            "files_fts must stay out of the 0.7.x CREATE_TABLES_SQL"
        );
        assert_eq!(INDEX_VERSION, "0.7.0");
        idx.with_conn(|conn| {
            assert!(!table_exists(conn, FILES_FTS_TABLE)?);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn collapse_globstars_collapses_runs() {
        assert_eq!(collapse_globstars("**/*.fits"), "*/*.fits");
        assert_eq!(collapse_globstars("*.fits"), "*.fits");
        assert_eq!(collapse_globstars("***"), "*");
    }
}
