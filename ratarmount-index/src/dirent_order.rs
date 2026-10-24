//! Opt-in catalog order by `offsetheader` (V-5).
//!
//! Default [`SqliteIndex::list_dirents`] is unchanged. Offset order is a sort of
//! that newest-wins set (NULL / cookie `< 0` last). Flatten is a **global**
//! payload list, not a concatenation of per-directory offset lists.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use ratarmount_core::{S_IFMT, S_IFREG};
use rusqlite::OpenFlags;

use crate::{CompactOpenCookie, IndexDirent, IndexError, Result, SqliteIndex, MAX_DIR_PAGE};

/// GNU dumpdir whiteout stored in `files.linkname` (formats-tar marker).
pub(crate) const DUMPDIR_DELETE_LINKNAME: &str = "\0GNU.dumpdir.delete";

/// Listing order for [`SqliteIndex::list_dirents_ordered`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirentOrder {
    /// Today's [`SqliteIndex::list_dirents`] (SQL UTF-8 or sealed intern-id).
    Name,
    /// Newest-wins `list_dirents` set sorted by [`cmp_offset_then_name`].
    OffsetHeader,
}

/// Mount-visible payload member for sequential open (newest-wins, dumpdir-aware).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleMember {
    /// SQL `files.path` (`""` at root, else `/dir`).
    pub path: String,
    pub name: String,
    pub cookie: CompactOpenCookie,
}

/// Shared V-5 comparator: real offsets ASC; NULL / cookie `< 0` last; then UTF-8 name.
///
/// Remaining ties keep input order (`slice::sort` / `sort_by`, not `sort_unstable`).
/// Never `COALESCE` / `unwrap_or(0)` / fat `.max(0)`.
pub fn cmp_offset_then_name(
    a_oh: Option<i64>,
    a_name: &str,
    b_oh: Option<i64>,
    b_name: &str,
) -> Ordering {
    match (offset_sort_key(a_oh), offset_sort_key(b_oh)) {
        (Some(a), Some(b)) => a.cmp(&b).then_with(|| a_name.cmp(b_name)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a_name.cmp(b_name),
    }
}

fn offset_sort_key(oh: Option<i64>) -> Option<i64> {
    match oh {
        Some(v) if v >= 0 => Some(v),
        _ => None,
    }
}

pub(crate) fn cookie_offset_key(cookie: &CompactOpenCookie) -> Option<i64> {
    if cookie.offsetheader < 0 {
        None
    } else {
        Some(cookie.offsetheader)
    }
}

pub(crate) fn catalog_fullpath(path: &str, name: &str) -> String {
    if path.is_empty() || path == "/" {
        format!("/{name}")
    } else {
        format!("{path}/{name}")
    }
}

fn sort_dirents_by_offset(dents: &mut [IndexDirent]) {
    dents.sort_by(|a, b| {
        cmp_offset_then_name(
            cookie_offset_key(&a.cookie),
            &a.name,
            cookie_offset_key(&b.cookie),
            &b.name,
        )
    });
}

fn is_dumpdir_tombstone(linkname: &str) -> bool {
    linkname == DUMPDIR_DELETE_LINKNAME
}

/// Payload members for sequential open: newest-wins regular files, not dirs,
/// not dumpdir tombstones, not generated, not TAR hardlinks (`S_IFREG` +
/// nonempty `linkname`).
fn is_payload_regular(mode: u32, linkname: &str, isgenerated: bool) -> bool {
    if isgenerated || is_dumpdir_tombstone(linkname) {
        return false;
    }
    if mode & S_IFMT != S_IFREG {
        return false;
    }
    if !linkname.is_empty() {
        return false;
    }
    true
}

impl SqliteIndex {
    /// Prepare the optional archive-order index once, without changing paging
    /// semantics on failure. Ordinary read-only callers pass `false`.
    ///
    /// `allow_sidecar_writes` explicitly permits opening a separate writable
    /// connection to a local sidecar (Session uses its original open policy).
    /// The catalog's read-only connection is never upgraded. In-memory and
    /// remote-cache files are never modified, even with this permission.
    pub fn prepare_offset_order_index(&self, allow_sidecar_writes: bool) {
        self.offset_order_index.get_or_init(|| {
            let result = self.with_conn(|conn| {
                let exists: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'files_offsetheader')",
                    [], |row| row.get(0),
                )?;
                if exists {
                    return Ok(());
                }
                let path = self.path.as_ref().ok_or_else(|| {
                    IndexError::Invalid("in-memory catalog".into())
                })?;
                let metadata = std::fs::metadata(path)?;
                if crate::is_meta_cache_path(path) || metadata.permissions().readonly() {
                    return Err(IndexError::Invalid("sidecar is read-only or remote-cached".into()));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.nlink() > 1 {
                        return Err(IndexError::Invalid("sidecar shares its inode with another path".into()));
                    }
                }
                let canonical = std::fs::canonicalize(path)?;
                let snapshot = canonical.file_name().and_then(|name| name.to_str())
                    .and_then(|name| name.strip_suffix(".sqlite"))
                    .and_then(|name| name.rsplit_once(".index."))
                    .is_some_and(|(_, id)| crate::parse_index_id(id).is_ok());
                if snapshot || crate::index_pointer_path_for_index_file(&canonical).is_file() {
                    return Err(IndexError::Invalid("published index bytes are pinned by SHA-256".into()));
                }
                let sql = "CREATE INDEX IF NOT EXISTS files_offsetheader ON files(offsetheader)";
                if !self.read_only && !conn.is_readonly(rusqlite::MAIN_DB)? {
                    conn.execute_batch(sql)?;
                } else if allow_sidecar_writes {
                    // Match open_writable's connection settings without CREATE:
                    // a removed sidecar must not be recreated by an optimization.
                    let writer = crate::open_database(
                        path,
                        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                        crate::checked_open::NameMode::Path,
                    )?;
                    writer.busy_timeout(std::time::Duration::from_secs(10))?;
                    writer.execute_batch(
                        "PRAGMA temp_store = MEMORY;
                         PRAGMA journal_mode = WAL;
                         PRAGMA synchronous = NORMAL;
                         PRAGMA locking_mode = NORMAL;"
                    )?;
                    writer.execute_batch(sql)?;
                } else {
                    return Err(IndexError::Invalid("read-only catalog".into()));
                }
                Ok(())
            });
            if let Err(error) = result {
                log::debug!("archive-order paging is unindexed; scanning each page: {error}");
            }
        });
    }

    /// Newest-wins directory listing in [`DirentOrder`].
    ///
    /// `Name` is exactly [`Self::list_dirents`]. `OffsetHeader` is that same set
    /// sorted with [`cmp_offset_then_name`]. No raw multi-row SQL.
    pub fn list_dirents_ordered(
        &self,
        path: &str,
        order: DirentOrder,
    ) -> Result<Option<Vec<IndexDirent>>> {
        let mut dents = match self.list_dirents(path)? {
            Some(d) => d,
            None => return Ok(None),
        };
        if matches!(order, DirentOrder::OffsetHeader) {
            sort_dirents_by_offset(&mut dents);
        }
        Ok(Some(dents))
    }

    /// Global newest-wins payload members in offset order (V-5 flatten).
    ///
    /// Not a concatenation of per-directory offset lists. Dumpdir is newest-wins
    /// including tombstones, then omit. Hardlinks and generated rows are dropped.
    pub fn list_visible_files_by_offset(&self) -> Result<Vec<VisibleMember>> {
        let mut members = if let Some(mem) = &self.mem {
            mem.newest_dirents()
                .into_iter()
                .filter_map(|(path, d)| {
                    if is_payload_regular(d.mode, &d.linkname, d.cookie.isgenerated) {
                        Some(VisibleMember {
                            path,
                            name: d.name,
                            cookie: d.cookie,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            self.sql_visible_newest_payloads()?
        };
        members.sort_by(|a, b| {
            cmp_offset_then_name(
                cookie_offset_key(&a.cookie),
                &catalog_fullpath(&a.path, &a.name),
                cookie_offset_key(&b.cookie),
                &catalog_fullpath(&b.path, &b.name),
            )
        });
        Ok(members)
    }

    /// Bounded SQL keyset page of the same newest-wins payload set as
    /// [`Self::list_visible_files_by_offset`]. `after` is exclusive
    /// `(offsetheader, fullpath)`; unknown/negative offsets sort last as `None`.
    ///
    /// Filters are applied after choosing the newest version, so tombstones,
    /// directories, links, and generated rows cannot resurrect older payloads.
    /// At most `MAX_DIR_PAGE + 1` rows are returned (one lookahead for callers).
    /// Compact-only indexes have no SQL catalog and return an error.
    pub fn list_visible_files_by_offset_page(
        &self,
        after: Option<(Option<i64>, &str)>,
        limit: u32,
    ) -> Result<Vec<VisibleMember>> {
        if self.compact_only {
            return Err(IndexError::Invalid(
                "offset paging requires a SQL catalog".into(),
            ));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.prepare_offset_order_index(false);
        let limit = limit.min(MAX_DIR_PAGE + 1);
        let (after_offset, after_path) = after.unwrap_or((None, ""));
        let after_offset = offset_sort_key(after_offset);
        let unknown_only = after.is_some() && after_offset.is_none();
        self.with_conn(|conn| {
            let mut out = Vec::new();
            // Keep real offsets in their own range query so the offsetheader
            // index can seek directly to the cursor. Unknown offsets form a
            // final path-ordered tail and never collide with a real offset.
            for unknown in [false, true] {
                if (!unknown && unknown_only) || out.len() == limit as usize {
                    continue;
                }
                let (keyset, order) = if unknown {
                    (
                        "(offsetheader IS NULL OR offsetheader < 0) AND fullpath > ?4",
                        "fullpath",
                    )
                } else {
                    (
                        "offsetheader >= ?3 AND (offsetheader > ?3 OR fullpath > ?4)",
                        "offsetheader, fullpath",
                    )
                };
                let sql = format!(
                    r#"
                    WITH candidates AS (
                      SELECT f.*, f.rowid AS version_rowid,
                        CASE WHEN path = '' OR path = '/' THEN '/' || name
                             ELSE path || '/' || name END AS fullpath
                      FROM "files" AS f
                    )
                    SELECT path, name, offsetheader, offset, size, mode,
                           istar, issparse, isgenerated, recursiondepth
                    FROM candidates AS f
                    WHERE {keyset}
                      AND name != ''
                      AND (mode & ?1) = ?2
                      AND COALESCE(linkname, '') = ''
                      AND COALESCE(isgenerated, 0) = 0
                      AND NOT EXISTS (
                        SELECT 1 FROM "files" AS newer
                        WHERE newer.path = f.path AND newer.name = f.name
                          AND (newer.offsetheader > f.offsetheader
                               OR (f.offsetheader IS NULL AND newer.offsetheader IS NOT NULL)
                               OR (newer.offsetheader IS f.offsetheader
                                   AND newer.rowid > f.version_rowid))
                      )
                    ORDER BY {order}
                    LIMIT ?5
                    "#,
                );
                let mut stmt = conn.prepare_cached(&sql)?;
                let rows = stmt.query_map(
                    rusqlite::params![
                        i64::from(S_IFMT),
                        i64::from(S_IFREG),
                        after_offset.unwrap_or(0),
                        if unknown && !unknown_only {
                            ""
                        } else {
                            after_path
                        },
                        i64::from(limit) - out.len() as i64,
                    ],
                    |row| {
                        Ok(VisibleMember {
                            path: row.get(0)?,
                            name: row.get(1)?,
                            cookie: CompactOpenCookie {
                                offsetheader: row.get::<_, Option<i64>>(2)?.unwrap_or(-1),
                                offset: row.get::<_, i64>(3)?.max(0) as u64,
                                size: row.get::<_, i64>(4)?.max(0) as u64,
                                mode: row.get::<_, i64>(5)? as u32,
                                istar: row.get::<_, Option<i64>>(6)?.unwrap_or(0) != 0,
                                issparse: row.get::<_, Option<i64>>(7)?.unwrap_or(0) != 0,
                                isgenerated: row.get::<_, Option<i64>>(8)?.unwrap_or(0) != 0,
                                recursiondepth: row.get::<_, Option<i64>>(9)?.unwrap_or(0).max(0)
                                    as u32,
                            },
                        })
                    },
                )?;
                for row in rows {
                    out.push(row?);
                }
            }
            Ok(out)
        })
    }

    fn sql_visible_newest_payloads(&self) -> Result<Vec<VisibleMember>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT path, name, offsetheader, offset, size, mode, linkname,
                       istar, issparse, isgenerated, recursiondepth
                FROM "files"
                ORDER BY "offsetheader"
                "#,
            )?;
            let mut by_key: BTreeMap<(String, String), (VisibleMember, String)> = BTreeMap::new();
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let path: String = row.get(0)?;
                let name: String = row.get(1)?;
                if name.is_empty() {
                    continue;
                }
                let offsetheader: Option<i64> = row.get(2)?;
                let offsetheader = offsetheader.unwrap_or(-1);
                let offset: i64 = row.get(3)?;
                let size: i64 = row.get(4)?;
                let mode: i64 = row.get(5)?;
                let linkname: String = row.get(6).unwrap_or_default();
                let istar: bool = row.get::<_, i64>(7).unwrap_or(0) != 0;
                let issparse: bool = row.get::<_, i64>(8).unwrap_or(0) != 0;
                let isgenerated: bool = row.get::<_, i64>(9).unwrap_or(0) != 0;
                let recursiondepth: i64 = row.get(10).unwrap_or(0);
                let size_u = size.max(0) as u64;
                let mode_u = mode as u32;
                by_key.insert(
                    (path.clone(), name.clone()),
                    (
                        VisibleMember {
                            path,
                            name,
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
                        linkname,
                    ),
                );
            }
            Ok(by_key
                .into_values()
                .filter_map(|(m, link)| {
                    if is_payload_regular(m.cookie.mode, &link, m.cookie.isgenerated) {
                        Some(m)
                    } else {
                        None
                    }
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileRow, SqliteIndex};
    use rusqlite::params;

    const REG: i64 = 0o100644;
    const DIR: i64 = 0o040755;

    fn file_row(path: &str, name: &str, oh: i64, isgenerated: bool) -> FileRow {
        FileRow::new(
            path,
            name,
            oh,
            oh + 512,
            4,
            1.0,
            REG,
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

    fn file_row_link(path: &str, name: &str, oh: i64, linkname: &str, mode: i64) -> FileRow {
        FileRow::new(
            path,
            name,
            oh,
            oh + 512,
            4,
            1.0,
            mode,
            0,
            linkname,
            0,
            0,
            true,
            false,
            false,
            0,
        )
    }

    fn names(dents: &[IndexDirent]) -> Vec<&str> {
        dents.iter().map(|d| d.name.as_str()).collect()
    }

    fn visible_names(rows: &[VisibleMember]) -> Vec<String> {
        rows.iter()
            .map(|m| catalog_fullpath(&m.path, &m.name))
            .collect()
    }

    fn collect_offset_pages(idx: &SqliteIndex, limit: u32) -> Vec<VisibleMember> {
        let mut all: Vec<VisibleMember> = Vec::new();
        loop {
            let after = all.last().map(|row| {
                (
                    cookie_offset_key(&row.cookie),
                    catalog_fullpath(&row.path, &row.name),
                )
            });
            let page = idx
                .list_visible_files_by_offset_page(
                    after
                        .as_ref()
                        .map(|(offset, path)| (*offset, path.as_str())),
                    limit,
                )
                .unwrap();
            if page.is_empty() {
                return all;
            }
            assert!(page.len() <= limit as usize);
            all.extend(page);
            assert!(all.len() < 100, "cursor must make progress");
        }
    }

    fn has_offset_order_index(idx: &SqliteIndex) -> bool {
        idx.with_conn(|conn| Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'files_offsetheader')",
            [], |row| row.get(0),
        )?)).unwrap()
    }

    fn build_offset_sidecar(path: &std::path::Path) {
        let mut idx = SqliteIndex::create_writable(Some(path)).unwrap();
        idx.insert_files_batch(&[
            file_row("", "z", 0, false),
            file_row("/d", "a", 512, false),
            file_row("", "last", 1024, false),
        ])
        .unwrap();
        idx.publish_tmp().unwrap();
    }

    /// Regression: normal cold builds must not pay for an unused secondary index.
    #[test]
    fn offset_page_normal_build_has_no_index_until_writable_paging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lazy.sqlite");
        build_offset_sidecar(&path);
        let idx = SqliteIndex::open_writable(&path).unwrap();
        assert!(!has_offset_order_index(&idx));
        let expected = idx.list_visible_files_by_offset().unwrap();
        assert!(!has_offset_order_index(&idx));
        assert_eq!(collect_offset_pages(&idx, 1), expected);
        assert!(has_offset_order_index(&idx));
    }

    /// Regression: read-only connections page without creating an auxiliary index.
    #[test]
    fn offset_page_read_only_connection_stays_unindexed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("readonly.sqlite");
        build_offset_sidecar(&path);
        let idx = SqliteIndex::open_catalog_read_only(&path).unwrap();
        let expected = idx.list_visible_files_by_offset().unwrap();
        assert!(!has_offset_order_index(&idx));
        for size in [1, 2, 7] {
            assert_eq!(collect_offset_pages(&idx, size), expected);
        }
        assert!(!has_offset_order_index(&idx));
    }

    /// Regression: memory catalogs must not get the optional disk-sidecar index.
    #[test]
    fn offset_page_memory_catalog_stays_unindexed() {
        let idx = insert_za_unsealed();
        let expected = idx.list_visible_files_by_offset().unwrap();
        idx.prepare_offset_order_index(true);
        assert_eq!(collect_offset_pages(&idx, 1), expected);
        assert!(!has_offset_order_index(&idx));
    }

    /// Regression: remote-cache blobs must not be changed even with write permission.
    #[test]
    fn offset_page_remote_cached_sidecar_stays_unindexed() {
        let _guard = crate::meta_cache::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        struct RestoreXdg(Option<std::ffi::OsString>);
        impl Drop for RestoreXdg {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var("XDG_CACHE_HOME", value),
                    None => std::env::remove_var("XDG_CACHE_HOME"),
                }
            }
        }
        let _restore = RestoreXdg(std::env::var_os("XDG_CACHE_HOME"));
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CACHE_HOME", dir.path());
        let path = dir.path().join("ratarmount/meta-v3/remote.sqlite");
        build_offset_sidecar(&path);
        assert!(crate::is_meta_cache_path(&path));
        let idx = SqliteIndex::open_catalog_read_only(&path).unwrap();
        let expected = idx.list_visible_files_by_offset().unwrap();
        idx.prepare_offset_order_index(true);
        assert_eq!(collect_offset_pages(&idx, 1), expected);
        assert!(!has_offset_order_index(&idx));
    }

    /// Regression: a locked CREATE INDEX must fall back once without breaking pages.
    #[test]
    fn offset_page_locked_index_creation_falls_back_without_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.sqlite");
        build_offset_sidecar(&path);
        let idx = SqliteIndex::open_writable(&path).unwrap();
        idx.with_conn(|conn| {
            conn.busy_timeout(std::time::Duration::ZERO)?;
            Ok(())
        })
        .unwrap();
        let expected = idx.list_visible_files_by_offset().unwrap();
        let blocker = rusqlite::Connection::open(&path).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert_eq!(collect_offset_pages(&idx, 1), expected);
        assert!(!has_offset_order_index(&idx));
        blocker.execute_batch("ROLLBACK").unwrap();
        assert_eq!(collect_offset_pages(&idx, 2), expected);
        assert!(
            !has_offset_order_index(&idx),
            "failed creation is attempted only once"
        );
    }

    /// Regression: equal offsets need the full path tie-breaker, with NULL offsets last.
    #[test]
    fn offset_page_equal_and_unknown_offsets_no_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("order.sqlite");
        let mut idx = SqliteIndex::create_writable(Some(&path)).unwrap();
        idx.insert_files_batch(&[
            file_row("/z", "same", 10, false),
            file_row("/a", "same", 10, false),
            file_row("", "zero", 0, false),
            file_row("", "negative", -2, false),
            file_row("", "maximum", i64::MAX - 512, false),
        ])
        .unwrap();
        idx.with_conn(|conn| {
            conn.execute(
                r#"INSERT INTO files (path, name, offsetheader, offset, size, mode)
                   VALUES ('', 'unknown', NULL, 0, 0, ?1)"#,
                [REG],
            )?;
            Ok(())
        })
        .unwrap();
        let expected = idx.list_visible_files_by_offset().unwrap();
        for size in [1, 2, 7] {
            assert_eq!(collect_offset_pages(&idx, size), expected);
        }
        idx.publish_tmp().unwrap();
        drop(idx);
        // The public Session catalog has no in-memory projection.
        let idx = SqliteIndex::open_catalog_read_only(&path).unwrap();
        assert!(!idx.has_mem_index());
        assert_eq!(collect_offset_pages(&idx, 1), expected);
        assert!(idx
            .list_visible_files_by_offset_page(None, 0)
            .unwrap()
            .is_empty());
        drop(idx);
        // Existing Python/older Rust sidecars need no schema migration.
        let idx = SqliteIndex::open_writable(&path).unwrap();
        idx.with_conn(|conn| {
            conn.execute("DROP INDEX files_offsetheader", [])?;
            Ok(())
        })
        .unwrap();
        drop(idx);
        let idx = SqliteIndex::open_catalog_read_only(&path).unwrap();
        assert_eq!(collect_offset_pages(&idx, 2), expected);
        assert!(!has_offset_order_index(&idx));
    }

    /// Regression: filtering before newest-wins resurrects deleted or non-payload versions.
    #[test]
    fn offset_page_newest_tombstone_directory_link_generated_hide_old_payload() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.insert_files_batch(&[
            file_row("", "gone", 0, false),
            file_row_link("", "gone", 100, DUMPDIR_DELETE_LINKNAME, REG),
            file_row("", "directory", 1, false),
            file_row_link("", "directory", 101, "", DIR),
            file_row("", "link", 2, false),
            file_row_link("", "link", 102, "target", REG),
            file_row("", "generated", 3, false),
            file_row("", "generated", 103, true),
            file_row("", "keep", 4, false),
            file_row("", "keep", 104, false),
            file_row_link("", "symlink", 105, "target", 0o120777),
        ])
        .unwrap();
        let rows = collect_offset_pages(&idx, 1);
        assert_eq!(visible_names(&rows), ["/keep"]);
        assert_eq!(rows[0].cookie.offsetheader, 104);
        assert_eq!(rows, idx.list_visible_files_by_offset().unwrap());
    }

    /// Regression: nullable foreign primary keys permit duplicate NULL versions.
    #[test]
    fn offset_page_duplicate_null_versions_do_not_resurrect_tombstone() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.with_conn(|conn| {
            for (name, linkname) in [
                ("keep", ""),
                ("keep", ""),
                ("gone", ""),
                ("gone", DUMPDIR_DELETE_LINKNAME),
            ] {
                conn.execute(
                    r#"INSERT INTO files (path, name, offsetheader, offset, size, mode, linkname)
                       VALUES ('', ?1, NULL, 0, 0, ?2, ?3)"#,
                    rusqlite::params![name, REG, linkname],
                )?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(visible_names(&collect_offset_pages(&idx, 1)), ["/keep"]);
    }

    fn insert_za_unsealed() -> SqliteIndex {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "z.txt", 100, false),
            file_row("", "a.txt", 500, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();
        idx
    }

    fn insert_za_sealed() -> SqliteIndex {
        insert_za_unsealed().into_read_only().unwrap()
    }

    /// Regression: unsealed SQL default `list_dirents` stays UTF-8, not offset.
    #[test]
    fn dirent_order_sql_unsealed_is_utf8() {
        let idx = insert_za_unsealed();
        let dents = idx.list_dirents("/").unwrap().expect("root");
        assert_eq!(names(&dents), ["a.txt", "z.txt"]);
        assert!(
            !idx.mem_pool_is_sealed_slab(),
            "unsealed must stay on SQL fallback"
        );
    }

    /// Regression: builder-sealed mem default is intern-id (insert `z` then `a`).
    #[test]
    fn dirent_order_builder_sealed_mem_is_intern_id() {
        let idx = insert_za_sealed();
        assert!(
            idx.mem_pool_is_sealed_slab(),
            "insert_files_batch must project mem"
        );
        let dents = idx.list_dirents("/").unwrap().expect("root");
        assert_eq!(
            names(&dents),
            ["z.txt", "a.txt"],
            "sealed intern-id follows insert order, not UTF-8"
        );
    }

    #[test]
    fn dirent_order_name_equals_list_dirents() {
        let sql = insert_za_unsealed();
        let a = sql.list_dirents("/").unwrap();
        let b = sql.list_dirents_ordered("/", DirentOrder::Name).unwrap();
        assert_eq!(a, b);

        let mem = insert_za_sealed();
        let a = mem.list_dirents("/").unwrap();
        let b = mem.list_dirents_ordered("/", DirentOrder::Name).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn dirent_order_offset_header_asc() {
        for idx in [insert_za_unsealed(), insert_za_sealed()] {
            let dents = idx
                .list_dirents_ordered("/", DirentOrder::OffsetHeader)
                .unwrap()
                .expect("root");
            assert_eq!(names(&dents), ["z.txt", "a.txt"]);
            assert_eq!(dents[0].cookie.offsetheader, 100);
            assert_eq!(dents[1].cookie.offsetheader, 500);
        }
    }

    #[test]
    fn dirent_order_membership_equals_default() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "z.txt", 100, false),
            file_row("", "a.txt", 500, false),
            file_row("", "ghost.txt", 50, true),
        ])
        .unwrap();
        idx.commit_write().unwrap();

        let default = idx.list_dirents("/").unwrap().expect("root");
        let ordered = idx
            .list_dirents_ordered("/", DirentOrder::OffsetHeader)
            .unwrap()
            .expect("root");
        let mut def_names: Vec<&str> = names(&default);
        let mut ord_names: Vec<&str> = names(&ordered);
        def_names.sort_unstable();
        ord_names.sort_unstable();
        assert_eq!(def_names, ord_names);
        assert!(
            def_names.contains(&"ghost.txt"),
            "list API keeps isgenerated"
        );
        let by_name: BTreeMap<_, _> = default
            .iter()
            .map(|d| (d.name.as_str(), d.cookie))
            .collect();
        for d in &ordered {
            assert_eq!(by_name.get(d.name.as_str()).copied(), Some(d.cookie));
        }
    }

    /// Regression: NULL `offsetheader` still lists on the offset-order path.
    #[test]
    fn dirent_order_null_offsetheader_sorts_last() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
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

        let default = idx.list_dirents("/").unwrap().expect("root");
        assert_eq!(names(&default), ["nullrow.txt", "plain.txt"]);
        let nullrow = default.iter().find(|d| d.name == "nullrow.txt").unwrap();
        assert!(nullrow.cookie.offsetheader < 0);

        let ordered = idx
            .list_dirents_ordered("/", DirentOrder::OffsetHeader)
            .unwrap()
            .expect("root");
        assert_eq!(names(&ordered), ["plain.txt", "nullrow.txt"]);
        assert!(ordered[1].cookie.offsetheader < 0);
        assert_ne!(
            ordered[1].cookie.offsetheader, 0,
            "NULL must not be treated as 0"
        );
    }

    /// Optional sealed-mem NULL: file-backed raw SQL + drop + open + seal.
    #[test]
    fn dirent_order_null_offsetheader_load_mem_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("null.index.sqlite");
        {
            let mut idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.begin_write().unwrap();
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
            idx.publish_tmp().unwrap();
        }
        let idx = SqliteIndex::open_writable(&path).unwrap();
        let idx = idx.into_read_only().unwrap();
        assert!(
            idx.mem_pool_is_sealed_slab(),
            "warm remount projects mem via load_mem_index"
        );
        let ordered = idx
            .list_dirents_ordered("/", DirentOrder::OffsetHeader)
            .unwrap()
            .expect("root");
        assert_eq!(names(&ordered), ["plain.txt", "nullrow.txt"]);
        assert!(ordered[1].cookie.offsetheader < 0);
    }

    #[test]
    fn dirent_order_newest_wins_max_offsetheader() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "same.txt", 100, false),
            file_row("", "same.txt", 500, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();

        for order in [DirentOrder::Name, DirentOrder::OffsetHeader] {
            let dents = idx.list_dirents_ordered("/", order).unwrap().expect("root");
            assert_eq!(dents.len(), 1);
            assert_eq!(dents[0].name, "same.txt");
            assert_eq!(dents[0].cookie.offsetheader, 500);
        }
    }

    #[test]
    fn dirent_order_newest_wins_null_vs_zero() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.with_conn(|conn| {
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'same.txt', NULL, 0, 3, 1.0, 33188, 0, '',
                           0, 0, 0, 0, 0, 0)"#,
                [],
            )?;
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'same.txt', 0, 512, 5, 1.0, 33188, 0, '',
                           0, 0, 1, 0, 0, 0)"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        idx.commit_write().unwrap();

        for order in [DirentOrder::Name, DirentOrder::OffsetHeader] {
            let dents = idx.list_dirents_ordered("/", order).unwrap().expect("root");
            assert_eq!(dents.len(), 1);
            assert_eq!(
                dents[0].cookie.offsetheader, 0,
                "NULL never beats oh=0 (COALESCE would collide here)"
            );
        }
    }

    /// Regression: dumpdir newest-then-filter omits a live oh=100 after tomb 500.
    #[test]
    fn dirent_order_dumpdir_newest_then_filter() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "gone.txt", 100, false),
            file_row_link("", "gone.txt", 500, DUMPDIR_DELETE_LINKNAME, REG),
            file_row("", "keep.txt", 200, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();

        let flat = idx.list_visible_files_by_offset().unwrap();
        let names = visible_names(&flat);
        assert!(
            !names.iter().any(|n| n.ends_with("gone.txt")),
            "must not resurrect oh=100 after tombstone 500: {names:?}"
        );
        assert_eq!(names, vec!["/keep.txt".to_string()]);
    }

    #[test]
    fn dirent_order_flatten_excludes_hardlinks_dirs_generated() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("", "payload.txt", 100, false),
            file_row_link("", "hard.txt", 200, "payload.txt", REG),
            file_row_link("", "subdir", 300, "", DIR),
            file_row("", "ghost.txt", 400, true),
        ])
        .unwrap();
        idx.commit_write().unwrap();

        let flat = idx.list_visible_files_by_offset().unwrap();
        assert_eq!(visible_names(&flat), vec!["/payload.txt".to_string()]);
    }

    #[test]
    fn dirent_order_flatten_is_global_not_per_dir_concat() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("/z", "m00", 0, false),
            file_row("/a", "m00", 512, false),
            file_row("/z", "m01", 1024, false),
            file_row("/a", "m01", 1536, false),
        ])
        .unwrap();
        idx.commit_write().unwrap();

        let flat = idx.list_visible_files_by_offset().unwrap();
        assert_eq!(
            visible_names(&flat),
            vec![
                "/z/m00".to_string(),
                "/a/m00".to_string(),
                "/z/m01".to_string(),
                "/a/m01".to_string(),
            ]
        );
        let concat_a_then_z: Vec<String> = {
            let mut a = idx
                .list_dirents_ordered("/a", DirentOrder::OffsetHeader)
                .unwrap()
                .unwrap();
            let z = idx
                .list_dirents_ordered("/z", DirentOrder::OffsetHeader)
                .unwrap()
                .unwrap();
            a.extend(z);
            a.iter().map(|d| d.name.clone()).collect()
        };
        assert_ne!(
            flat.iter().map(|m| m.name.clone()).collect::<Vec<_>>(),
            concat_a_then_z,
            "flatten must not be per-dir concat"
        );
    }

    #[test]
    fn dirent_order_two_null_oh_stable() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.with_conn(|conn| {
            for name in ["b-null.txt", "a-null.txt"] {
                conn.execute(
                    r#"INSERT INTO "files"
                       (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                        uid, gid, istar, issparse, isgenerated, recursiondepth)
                       VALUES ('', ?1, NULL, 0, 1, 1.0, 33188, 0, '',
                               0, 0, 0, 0, 0, 0)"#,
                    params![name],
                )?;
            }
            conn.execute(
                r#"INSERT INTO "files"
                   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
                    uid, gid, istar, issparse, isgenerated, recursiondepth)
                   VALUES ('', 'real.txt', 100, 100, 1, 1.0, 33188, 0, '',
                           0, 0, 1, 0, 0, 0)"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        idx.commit_write().unwrap();

        let ordered = idx
            .list_dirents_ordered("/", DirentOrder::OffsetHeader)
            .unwrap()
            .expect("root");
        assert_eq!(ordered[0].name, "real.txt");
        let tails: Vec<&str> = ordered[1..].iter().map(|d| d.name.as_str()).collect();
        assert_eq!(tails.len(), 2);
        assert!(tails.contains(&"a-null.txt") && tails.contains(&"b-null.txt"));
        for d in &ordered[1..] {
            assert!(d.cookie.offsetheader < 0);
        }
    }
}
