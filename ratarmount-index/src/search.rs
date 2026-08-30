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

use ratarmount_core::CheapSearchHit;
use rusqlite::{params, Connection, Row};

use crate::{table_exists, IndexError, Result, SqliteIndex};

/// Cap on locate hits when the caller does not set [`SearchQuery::limit`].
pub const DEFAULT_SEARCH_LIMIT: usize = 10_000;

/// Additive FTS5 virtual table (not in `create-index-tables.sql`).
pub(crate) const FILES_FTS_TABLE: &str = "files_fts";

/// GNU dumpdir whiteout stored in `files.linkname` (formats-tar marker).
pub(crate) const DUMPDIR_DELETE_LINKNAME: &str = "\0GNU.dumpdir.delete";

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

/// Same as [`SQL_FULLPATH`] qualified for the FTS `files` alias `f`.
const SQL_FULLPATH_F: &str = r#"CASE
    WHEN f."path" IS NULL OR f."path" = '' OR f."path" = '/' THEN '/' || f."name"
    ELSE f."path" || '/' || f."name"
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

/// Exclusive composite keyset for [`SearchQuery::after`].
///
/// Locate keeps every `(fullpath, offsetheader)` version — no newest-wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindAfter<'a> {
    pub fullpath: &'a str,
    pub offsetheader: Option<i64>,
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
    /// Re-sort today's path-order `LIMIT` set by [`crate::cmp_offset_then_name`].
    /// Does not change membership. Default find / control search stay path order.
    pub offset_order: bool,
    /// Exclusive `(fullpath, offsetheader)` keyset. `None` = first page.
    pub after: Option<FindAfter<'a>>,
}

impl<'a> SearchQuery<'a> {
    /// Locate-style glob/LIKE (no FTS5).
    pub fn glob(pattern: &'a str) -> Self {
        Self {
            pattern,
            fts: false,
            include_hashes: false,
            limit: DEFAULT_SEARCH_LIMIT,
            offset_order: false,
            after: None,
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
            offset_order: false,
            after: None,
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
                search_fts_match(conn, q.pattern, q.limit, q.after)?
            } else {
                search_glob_like(conn, q.pattern, q.limit, q.after)?
            };
            if q.include_hashes {
                fill_hit_hashes(conn, &mut hits)?;
            }
            if q.offset_order {
                hits.sort_by(|a, b| {
                    crate::cmp_offset_then_name(a.offsetheader, &a.path, b.offsetheader, &b.path)
                });
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

    /// Cheap locate: SoA `scan_glob` when `mem` is present, else SQL `search_query`.
    ///
    /// `fts:` is not a SoA scan — returns [`IndexError::Invalid`] so format
    /// one-liners map it to [`None`] (SearchFn step 1 / SQL `MATCH`).
    /// Empty archive (`mem: None`) and huge catalogs (`n > MEM_INDEX_MAX_FILES`)
    /// use SQL on this connection — do not treat missing mem as “no search.”
    pub fn search_cheap(&self, pattern: &str) -> Result<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return Err(IndexError::Invalid(
                "fts: is SQL MATCH only; search_cheap does not scan SoA".into(),
            ));
        }
        if let Some(mem) = &self.mem {
            return Ok(mem.scan_glob(pattern));
        }
        let hits = self.search_query(&SearchQuery::glob(pattern))?;
        Ok(hits.into_iter().map(CheapSearchHit::from).collect())
    }
}

impl From<SearchHit> for CheapSearchHit {
    fn from(h: SearchHit) -> Self {
        Self {
            path: h.path,
            name: h.name,
            size: h.size,
            mtime: h.mtime,
            offsetheader: h.offsetheader,
        }
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

/// Exclusive keyset: `(fullpath, COALESCE(offsetheader,-1))` strictly after `after`.
fn keyset_sql(fullpath_expr: &str, offset_expr: &str, after: bool) -> (String, u32) {
    if after {
        (
            format!(
                r#"AND (
              {fullpath_expr} > ?3
              OR ({fullpath_expr} = ?3 AND COALESCE({offset_expr}, -1) > COALESCE(?4, -1))
            )"#
            ),
            5,
        )
    } else {
        (String::new(), 3)
    }
}

fn search_glob_like(
    conn: &Connection,
    pattern: &str,
    limit: usize,
    after: Option<FindAfter<'_>>,
) -> Result<Vec<SearchHit>> {
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
    let (after_sql, limit_idx) = keyset_sql(SQL_FULLPATH, r#""offsetheader""#, after.is_some());
    let sql = format!(
        r#"
        SELECT {SQL_FULLPATH} AS fullpath, "name", "size", "mtime", "offsetheader"
        FROM "files"
        WHERE {filter}
          AND {pred}
          {after_sql}
        ORDER BY fullpath, COALESCE("offsetheader", -1)
        LIMIT ?{limit_idx}
        "#,
        filter = catalog_filter_sql(""),
    );
    let mut stmt = conn.prepare(&sql)?;
    collect_mapped_hits(&mut stmt, DUMPDIR_DELETE_LINKNAME, &bound, after, limit)
}

fn search_fts_match(
    conn: &Connection,
    pattern: &str,
    limit: usize,
    after: Option<FindAfter<'_>>,
) -> Result<Vec<SearchHit>> {
    if !table_exists(conn, FILES_FTS_TABLE)? {
        return Err(IndexError::Invalid(
            "files_fts is not present; call ensure_fts5".into(),
        ));
    }
    let (after_sql, limit_idx) = keyset_sql(SQL_FULLPATH_F, r#"f."offsetheader""#, after.is_some());
    let sql = format!(
        r#"
        SELECT {SQL_FULLPATH_F} AS fullpath, f."name", f."size", f."mtime", f."offsetheader"
        FROM "files_fts"
        JOIN "files" f
          ON f."name" = "files_fts"."name"
         AND COALESCE(f."path", '') = COALESCE("files_fts"."path", '')
         AND f."offsetheader" IS "files_fts"."offsetheader"
        WHERE "files_fts" MATCH ?2
          AND {filter}
          {after_sql}
        ORDER BY fullpath, COALESCE(f."offsetheader", -1)
        LIMIT ?{limit_idx}
        "#,
        filter = catalog_filter_sql("f"),
    );
    let mut stmt = conn.prepare(&sql)?;
    collect_mapped_hits(&mut stmt, DUMPDIR_DELETE_LINKNAME, pattern, after, limit)
}

fn collect_mapped_hits(
    stmt: &mut rusqlite::Statement<'_>,
    dumpdir: &str,
    pattern: &str,
    after: Option<FindAfter<'_>>,
    limit: usize,
) -> Result<Vec<SearchHit>> {
    match after {
        None => {
            let rows = stmt.query_map(params![dumpdir, pattern, limit_i64(limit)], row_to_hit)?;
            collect_hits(rows)
        }
        Some(a) => {
            let rows = stmt.query_map(
                params![
                    dumpdir,
                    pattern,
                    a.fullpath,
                    a.offsetheader,
                    limit_i64(limit)
                ],
                row_to_hit,
            )?;
            collect_hits(rows)
        }
    }
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

/// Whether `pattern` matches `fullpath` / `name` with SQL GLOB (or LIKE) rules.
///
/// Same predicates as [`search_glob_like`]: `**` → `*`, `/` ⇒ full-path, LIKE
/// when the pattern uses `%`/`_` and no glob metacharacters. Not SMB glob.
pub fn locate_pattern_matches(pattern: &str, fullpath: &str, name: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let glob = collapse_globstars(pattern);
    let use_like = is_like_pattern(&glob);
    let full_path = glob.contains('/');
    let bound = if full_path && !glob.starts_with('/') {
        format!("/{glob}")
    } else {
        glob
    };
    if full_path {
        if use_like {
            sql_like_match(fullpath, &bound)
        } else {
            sql_glob_match(fullpath, &bound)
        }
    } else if use_like {
        sql_like_match(name, &bound)
    } else {
        sql_glob_match(name, &bound)
    }
}

/// SQLite `GLOB` (case-sensitive): `*` any sequence, `?` one character, `[abc]`.
pub fn sql_glob_match(text: &str, pattern: &str) -> bool {
    glob_match_slices(
        &text.chars().collect::<Vec<_>>(),
        &pattern.chars().collect::<Vec<_>>(),
    )
}

fn glob_match_slices(text: &[char], pat: &[char]) -> bool {
    let mut ti = 0usize;
    let mut pi = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;
    while ti < text.len() {
        if pi < pat.len() && pat[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
            continue;
        }
        if pi < pat.len() && char_class_or_q(text[ti], pat, &mut pi) {
            ti += 1;
            continue;
        }
        if let Some(sp) = star_pi {
            star_ti += 1;
            ti = star_ti;
            pi = sp + 1;
            continue;
        }
        return false;
    }
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Advance `pi` past one pattern atom that must match `ch`. `?` or literal or `[...]`.
fn char_class_or_q(ch: char, pat: &[char], pi: &mut usize) -> bool {
    if *pi >= pat.len() {
        return false;
    }
    if pat[*pi] == '?' {
        *pi += 1;
        return true;
    }
    if pat[*pi] == '[' {
        return match_char_class(ch, pat, pi);
    }
    if pat[*pi] == ch {
        *pi += 1;
        return true;
    }
    false
}

fn match_char_class(ch: char, pat: &[char], pi: &mut usize) -> bool {
    // pat[*pi] == '['
    let start = *pi + 1;
    let mut j = start;
    let mut found_close = None;
    while j < pat.len() {
        if pat[j] == ']' && j > start {
            found_close = Some(j);
            break;
        }
        j += 1;
    }
    let Some(close) = found_close else {
        // Unclosed `[` is a literal.
        let ok = pat[*pi] == ch;
        *pi += 1;
        return ok;
    };
    let inner = &pat[start..close];
    let (negate, body) = if inner.first() == Some(&'!') || inner.first() == Some(&'^') {
        (true, &inner[1..])
    } else {
        (false, inner)
    };
    let mut matched = false;
    let mut k = 0usize;
    while k < body.len() {
        if k + 2 < body.len() && body[k + 1] == '-' {
            let lo = body[k];
            let hi = body[k + 2];
            if ch >= lo && ch <= hi {
                matched = true;
                break;
            }
            k += 3;
        } else {
            if body[k] == ch {
                matched = true;
                break;
            }
            k += 1;
        }
    }
    *pi = close + 1;
    if negate {
        !matched
    } else {
        matched
    }
}

/// SQLite `LIKE` (ASCII case-insensitive): `%` any sequence, `_` one character.
pub fn sql_like_match(text: &str, pattern: &str) -> bool {
    like_match_slices(
        &text.chars().map(ascii_lower).collect::<Vec<_>>(),
        &pattern.chars().map(ascii_lower).collect::<Vec<_>>(),
    )
}

fn ascii_lower(c: char) -> char {
    if c.is_ascii_uppercase() {
        c.to_ascii_lowercase()
    } else {
        c
    }
}

fn like_match_slices(text: &[char], pat: &[char]) -> bool {
    let mut ti = 0usize;
    let mut pi = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;
    while ti < text.len() {
        if pi < pat.len() && pat[pi] == '%' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
            continue;
        }
        if pi < pat.len() && (pat[pi] == '_' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
            continue;
        }
        if let Some(sp) = star_pi {
            star_ti += 1;
            ti = star_ti;
            pi = sp + 1;
            continue;
        }
        return false;
    }
    while pi < pat.len() && pat[pi] == '%' {
        pi += 1;
    }
    pi == pat.len()
}

/// `**` (and longer star runs) → a single `*` (GLOB has no recursive glob).
pub(crate) fn collapse_globstars(pattern: &str) -> String {
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

    /// Regression: `--offset-order` re-sorts today's path-order LIMIT set only.
    /// Path order A,B,C; offset order C,A,B; `limit=2` + offset_order → A,B.
    #[test]
    fn dirent_order_limit_membership_glob_and_fts() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "a.fits", 200, false),
            file_row("", "b.fits", 300, false),
            file_row("", "c.fits", 100, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();

        let path = idx.search("*.fits").unwrap();
        assert_eq!(hit_paths(&path), vec!["/a.fits", "/b.fits", "/c.fits"]);

        let offset = idx
            .search_query(&SearchQuery {
                offset_order: true,
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(hit_paths(&offset), vec!["/c.fits", "/a.fits", "/b.fits"]);

        let limited = idx
            .search_query(&SearchQuery {
                limit: 2,
                offset_order: true,
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(
            hit_paths(&limited),
            vec!["/a.fits", "/b.fits"],
            "LIMIT stays path-order membership; then re-sort (not C+A)"
        );

        idx.ensure_fts5().unwrap();
        let fts_limited = idx
            .search_query(&SearchQuery {
                limit: 2,
                offset_order: true,
                ..SearchQuery::fts("fits")
            })
            .unwrap();
        assert_eq!(
            hit_paths(&fts_limited),
            vec!["/a.fits", "/b.fits"],
            "FTS LIMIT stays path-order membership"
        );
    }

    /// Regression: shared comparator; raw-SQL NULL `offsetheader` hit sorts last.
    #[test]
    fn dirent_order_null_search_hit_sorts_last() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.with_conn(|conn| {
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'null.fits', NULL, 0, 3, 1.0, 33188, 0, '',
                           0, 0, 0, 0, 0, 0)"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        idx.insert_files_batch(&[file_row("", "plain.fits", 512, false)])
            .unwrap();
        idx.commit_write().unwrap();

        let hits = idx
            .search_query(&SearchQuery {
                offset_order: true,
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(hit_paths(&hits), vec!["/plain.fits", "/null.fits"]);
        assert_eq!(hits[0].offsetheader, Some(512));
        assert_eq!(hits[1].offsetheader, None);
    }

    fn cheap_paths(hits: &[CheapSearchHit]) -> Vec<&str> {
        hits.iter().map(|h| h.path.as_str()).collect()
    }

    /// Regression: SQL locate does not build FileInfo (`mem` stays None).
    #[test]
    fn search_query_no_mem_no_fileinfo() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        seed_catalog(&idx);
        assert!(
            !idx.has_mem_index(),
            "writable build leaves mem: None until seal"
        );
        let hits = idx.search("*.fits").unwrap();
        assert_eq!(hit_paths(&hits), vec!["/a.fits", "/dir/b.fits"]);
        assert!(!idx.has_mem_index(), "search_query must not load MemIndex");
        let cheap = idx.search_cheap("*.fits").unwrap();
        assert_eq!(cheap_paths(&cheap), vec!["/a.fits", "/dir/b.fits"]);
        assert!(!idx.has_mem_index());
    }

    /// Regression: compact-only SQL locate stays empty; SoA scan_glob hits.
    #[test]
    fn scan_glob_compact() {
        let idx = SqliteIndex::create_compact_only().unwrap();
        idx.insert_files_batch(&[
            file_row("", "a.fits", 0, false),
            file_row("/dir", "b.fits", 512, false),
            file_row("", "readme.txt", 1024, false),
        ])
        .unwrap();
        let idx = idx.into_read_only().unwrap();
        assert!(idx.is_compact_only());
        assert!(idx.has_mem_index());
        assert!(
            idx.search("*.fits").unwrap().is_empty(),
            "search_query compact-only stays empty for SQL/CLI"
        );
        let hits = idx.search_cheap("*.fits").unwrap();
        assert_eq!(cheap_paths(&hits), vec!["/a.fits", "/dir/b.fits"]);
    }

    /// Regression: two offsetheaders, same catalog path — SoA hit count == SQL.
    #[test]
    fn scan_glob_two_offsetheader_equals_sql() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("/dir", "a.fits", 0, false),
            file_row("/dir", "a.fits", 512, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();
        let sql = idx.search("*.fits").unwrap();
        assert_eq!(sql.len(), 2);
        let idx = idx.into_read_only().unwrap();
        assert!(idx.has_mem_index());
        let soa = idx.search_cheap("*.fits").unwrap();
        assert_eq!(soa.len(), sql.len());
        assert_eq!(cheap_paths(&soa), hit_paths(&sql));
        assert_eq!(soa[0].offsetheader, sql[0].offsetheader);
        assert_eq!(soa[1].offsetheader, sql[1].offsetheader);
    }

    /// Regression: `fts:` never enters SoA scan (SqliteIndex returns Err → None).
    #[test]
    fn search_cheap_fts_prefix_is_none() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        seed_catalog(&idx);
        let idx = idx.into_read_only().unwrap();
        let err = idx.search_cheap("fts:fits").unwrap_err();
        assert!(
            err.to_string().contains("fts:"),
            "fts: must not scan SoA, got {err}"
        );
    }

    fn seed_duplicate_path(idx: &SqliteIndex) {
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "a.fits", 0, false),
            file_row("", "dup.fits", 512, false),
            file_row("", "dup.fits", 1024, false),
            file_row("", "z.fits", 1536, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();
    }

    /// Regression: composite keyset keeps both versions of the same fullpath.
    #[test]
    fn search_query_after_keyset_keeps_duplicate_paths() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        seed_duplicate_path(&idx);

        let all = idx.search("*.fits").unwrap();
        assert_eq!(
            all.iter()
                .map(|h| (h.path.as_str(), h.offsetheader))
                .collect::<Vec<_>>(),
            vec![
                ("/a.fits", Some(0)),
                ("/dup.fits", Some(512)),
                ("/dup.fits", Some(1024)),
                ("/z.fits", Some(1536)),
            ]
        );

        let page1 = idx
            .search_query(&SearchQuery {
                limit: 2,
                after: None,
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(
            page1
                .iter()
                .map(|h| (h.path.as_str(), h.offsetheader))
                .collect::<Vec<_>>(),
            vec![("/a.fits", Some(0)), ("/dup.fits", Some(512))]
        );

        let page2 = idx
            .search_query(&SearchQuery {
                limit: 2,
                after: Some(FindAfter {
                    fullpath: "/dup.fits",
                    offsetheader: Some(512),
                }),
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(
            page2
                .iter()
                .map(|h| (h.path.as_str(), h.offsetheader))
                .collect::<Vec<_>>(),
            vec![("/dup.fits", Some(1024)), ("/z.fits", Some(1536))],
            "same-path later offsetheader must not be skipped"
        );
    }

    /// Regression: `after` is exclusive on `(fullpath, offsetheader)`.
    #[test]
    fn search_query_after_is_exclusive() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        seed_catalog(&idx);

        let rest = idx
            .search_query(&SearchQuery {
                after: Some(FindAfter {
                    fullpath: "/a.fits",
                    offsetheader: Some(0),
                }),
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(hit_paths(&rest), vec!["/dir/b.fits"]);

        let none = idx
            .search_query(&SearchQuery {
                after: Some(FindAfter {
                    fullpath: "/dir/b.fits",
                    offsetheader: Some(512),
                }),
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert!(none.is_empty());
    }

    /// Regression: `--offset-order` re-sorts the keyset page only.
    #[test]
    fn search_query_after_offset_order_resorts_page_only() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "a.fits", 200, false),
            file_row("", "b.fits", 300, false),
            file_row("", "c.fits", 100, false),
            file_row("", "d.fits", 50, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();

        let page = idx
            .search_query(&SearchQuery {
                limit: 2,
                offset_order: true,
                after: Some(FindAfter {
                    fullpath: "/a.fits",
                    offsetheader: Some(200),
                }),
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(
            hit_paths(&page),
            vec!["/c.fits", "/b.fits"],
            "membership is B,C in path order; offset re-sort of that page is C,B (not D)"
        );
    }

    /// Regression: NULL offsetheader uses -1 sentinel in the keyset.
    #[test]
    fn search_query_after_null_offsetheader() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.with_conn(|conn| {
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'null.fits', NULL, 0, 3, 1.0, 33188, 0, '',
                           0, 0, 0, 0, 0, 0)"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        idx.insert_files_batch(&[file_row("", "plain.fits", 512, false)])
            .unwrap();
        idx.commit_write().unwrap();

        let first = idx
            .search_query(&SearchQuery {
                limit: 1,
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(hit_paths(&first), vec!["/null.fits"]);
        assert_eq!(first[0].offsetheader, None);

        let rest = idx
            .search_query(&SearchQuery {
                after: Some(FindAfter {
                    fullpath: "/null.fits",
                    offsetheader: None,
                }),
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert_eq!(hit_paths(&rest), vec!["/plain.fits"]);
    }

    /// Regression: FTS keyset keeps both MATCH hits for the same fullpath.
    #[test]
    fn search_query_after_fts_keeps_duplicate_paths() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        seed_duplicate_path(&idx);
        idx.ensure_fts5().unwrap();

        let page1 = idx
            .search_query(&SearchQuery {
                limit: 2,
                after: None,
                ..SearchQuery::fts("fits")
            })
            .unwrap();
        assert_eq!(
            page1
                .iter()
                .map(|h| (h.path.as_str(), h.offsetheader))
                .collect::<Vec<_>>(),
            vec![("/a.fits", Some(0)), ("/dup.fits", Some(512))]
        );

        let page2 = idx
            .search_query(&SearchQuery {
                limit: 2,
                after: Some(FindAfter {
                    fullpath: "/dup.fits",
                    offsetheader: Some(512),
                }),
                ..SearchQuery::fts("fits")
            })
            .unwrap();
        assert_eq!(
            page2
                .iter()
                .map(|h| (h.path.as_str(), h.offsetheader))
                .collect::<Vec<_>>(),
            vec![("/dup.fits", Some(1024)), ("/z.fits", Some(1536))],
            "FTS same-path later offsetheader must not be skipped"
        );
    }

    /// Same fullpath SQL NULL and stored -1 share the COALESCE sentinel.
    #[test]
    fn search_query_after_null_and_minus_one_same_path() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.with_conn(|conn| {
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'dup.fits', NULL, 0, 3, 1.0, 33188, 0, '',
                           0, 0, 0, 0, 0, 0)"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        idx.insert_files_batch(&[file_row("", "dup.fits", -1, false)])
            .unwrap();
        idx.commit_write().unwrap();

        let all = idx.search("*.fits").unwrap();
        assert_eq!(all.len(), 2, "unpaged locate still emits both rows");
        assert!(all.iter().any(|h| h.offsetheader.is_none()));
        assert!(all.iter().any(|h| h.offsetheader == Some(-1)));

        let rest = idx
            .search_query(&SearchQuery {
                after: Some(FindAfter {
                    fullpath: "/dup.fits",
                    offsetheader: None,
                }),
                ..SearchQuery::glob("*.fits")
            })
            .unwrap();
        assert!(
            rest.is_empty(),
            "NULL and -1 are the same keyset sentinel; after None must not emit -1"
        );
    }
}
