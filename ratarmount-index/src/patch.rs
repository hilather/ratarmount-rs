//! Incremental 0.7.x index patch: suffix-delete by uncompressed `offsetheader`.
//!
//! F-2 persist callers wrap [`SqliteIndex::delete_from_offsetheader`] plus suffix
//! insert in one [`SqliteIndex::begin_write`] / [`SqliteIndex::commit_write`]
//! (`BEGIN IMMEDIATE`). This module does not fork [`crate::INDEX_VERSION`].

use rusqlite::{params, Connection};

use crate::{table_exists, IndexError, Result, SqliteIndex};

impl SqliteIndex {
    /// Delete catalog rows whose uncompressed TAR `offsetheader` is at or after
    /// `window_start`.
    ///
    /// Used by incremental reindex (F-2) after a last-frame splice or GNU tar
    /// append/delete: prefix rows stay; the caller re-parses the suffix and
    /// inserts. NULL `offsetheader` rows (Python non-TAR members) are **not**
    /// treated as 0 and are never deleted.
    ///
    /// Also drops matching `xattrsdata` rows and, when present, `fileunions`
    /// rows with the same `IS NOT NULL AND offsetheader >= window_start`
    /// predicate. `nestedindexes` keys whose [`crate::NestedMemberKey::storage_key`]
    /// encodes `oh=` ≥ `window_start` are dropped after parsing `oh=` in Rust
    /// (not SQL `substr`). Keys without `oh=` (NULL offsetheader) stay.
    /// `parentfolders` / `filestmp` are not patched (dropped on seal).
    ///
    /// This method does **not** begin a transaction. Standalone tests should
    /// wrap it with [`Self::begin_write`] / [`Self::commit_write`]. F2-2 wraps
    /// delete + suffix insert in one txn so concurrent readers never see a
    /// suffix hole.
    ///
    /// Does not truncate the database ([`Self::create_writable`]) and does not
    /// touch MemIndex (`open_writable` already has `mem: None`).
    ///
    /// Returns the number of `files` rows deleted.
    pub fn delete_from_offsetheader(&self, window_start: i64) -> Result<u64> {
        if self.is_read_only() {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if self.is_compact_only() {
            return Ok(0);
        }
        self.with_conn(|conn| {
            let n = delete_offsetheader_suffix(conn, "files", window_start)?;
            delete_offsetheader_suffix(conn, "xattrsdata", window_start)?;
            delete_offsetheader_suffix(conn, "fileunions", window_start)?;
            delete_nestedindexes_suffix(conn, window_start)?;
            Ok(n)
        })
    }

    /// Rebuild optional `files_fts` after a suffix patch (F-3).
    ///
    /// No-op when `files_fts` is missing (normal 0.7.x indexes). When the
    /// table exists, refill it from `files` + `user.hash.*` xattrs. Does not
    /// create the table ([`Self::ensure_fts5`]).
    pub fn rebuild_fts_if_present(&self) -> Result<()> {
        if self.is_read_only() {
            return Err(IndexError::Invalid("index is read-only".into()));
        }
        if self.is_compact_only() {
            return Ok(());
        }
        self.with_conn(|conn| {
            if !table_exists(conn, crate::search::FILES_FTS_TABLE)? {
                return Ok(());
            }
            crate::search::refill_files_fts(conn)
        })
    }
}

/// Parse `oh=` from [`crate::NestedMemberKey::storage_key`].
///
/// `path|oh={n}|sz={sz}` → `Some(n)`. `path|sz={sz}` (NULL offsetheader) →
/// `None` and is never treated as 0.
fn parse_oh_from_nested_storage_key(member_key: &str) -> Option<i64> {
    member_key.split('|').find_map(|part| {
        let rest = part.strip_prefix("oh=")?;
        rest.parse::<i64>().ok()
    })
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
        params![table, column],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn delete_offsetheader_suffix(conn: &Connection, table: &str, window_start: i64) -> Result<u64> {
    if !table_exists(conn, table)? {
        return Ok(0);
    }
    if !column_exists(conn, table, "offsetheader")? {
        return Ok(0);
    }
    // Table names are internal constants — never user-controlled.
    let sql = match table {
        "files" => r#"DELETE FROM "files" WHERE offsetheader IS NOT NULL AND offsetheader >= ?1"#,
        "xattrsdata" => {
            r#"DELETE FROM "xattrsdata" WHERE offsetheader IS NOT NULL AND offsetheader >= ?1"#
        }
        "fileunions" => {
            r#"DELETE FROM "fileunions" WHERE offsetheader IS NOT NULL AND offsetheader >= ?1"#
        }
        _ => return Ok(0),
    };
    let n = conn.execute(sql, params![window_start])?;
    Ok(n as u64)
}

fn delete_nestedindexes_suffix(conn: &Connection, window_start: i64) -> Result<()> {
    if !table_exists(conn, crate::NESTED_INDEXES_TABLE)? {
        return Ok(());
    }
    let mut stmt = conn.prepare(r#"SELECT member_key FROM "nestedindexes""#)?;
    let keys = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut to_delete = Vec::new();
    for key in keys {
        let key = key?;
        if let Some(oh) = parse_oh_from_nested_storage_key(&key) {
            if oh >= window_start {
                to_delete.push(key);
            }
        }
    }
    drop(stmt);
    let mut del = conn.prepare(r#"DELETE FROM "nestedindexes" WHERE member_key = ?1"#)?;
    for key in to_delete {
        del.execute(params![key])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FileRow, NestedBodyFingerprint, NestedMemberKey, SqliteIndex, INDEX_VERSION,
        NESTED_FORMAT_ZIP,
    };
    use rusqlite::Connection;

    fn file_row(name: &str, offsetheader: i64) -> FileRow {
        FileRow::new(
            "",
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
            false,
            0,
        )
    }

    fn dummy_fingerprint(body_size: u64) -> NestedBodyFingerprint {
        NestedBodyFingerprint {
            body_size,
            prefix_sha256: "aa".into(),
            suffix_sha256: "bb".into(),
            mid_sha256: String::new(),
        }
    }

    fn root_names(idx: &SqliteIndex) -> Vec<String> {
        let mut names: Vec<String> = idx
            .list("/")
            .unwrap()
            .unwrap_or_default()
            .into_keys()
            .collect();
        names.sort();
        names
    }

    fn sql_file_names(path: &std::path::Path) -> Vec<String> {
        let conn = Connection::open(path).unwrap();
        let mut stmt = conn
            .prepare(r#"SELECT name FROM "files" ORDER BY name"#)
            .unwrap();
        let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    fn sql_file_count(path: &std::path::Path) -> i64 {
        let conn = Connection::open(path).unwrap();
        conn.query_row(r#"SELECT COUNT(*) FROM "files""#, [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn parse_oh_from_nested_storage_key_null_is_not_zero() {
        let with_oh = NestedMemberKey {
            member_path: "inner.zip".into(),
            offsetheader: Some(1024),
            body_size: 10,
        };
        assert_eq!(
            parse_oh_from_nested_storage_key(&with_oh.storage_key()),
            Some(1024)
        );
        let none = NestedMemberKey {
            member_path: "inner.zip".into(),
            offsetheader: None,
            body_size: 10,
        };
        assert_eq!(parse_oh_from_nested_storage_key(&none.storage_key()), None);
        assert_eq!(
            parse_oh_from_nested_storage_key("inner.zip|sz=10"),
            None,
            "NULL offsetheader storage key must not parse as 0"
        );
        assert_eq!(parse_oh_from_nested_storage_key("p|oh=0|sz=1"), Some(0));
        assert_eq!(parse_oh_from_nested_storage_key("p|oh=-1|sz=1"), Some(-1));
    }

    #[test]
    fn delete_from_offsetheader_keeps_prefix() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[
            file_row("prefix.txt", 0),
            file_row("mid.txt", 512),
            file_row("suffix.txt", 1024),
        ])
        .unwrap();
        idx.insert_xattr(0, "user.hash.sha256", b"prefix").unwrap();
        idx.insert_xattr(1024, "user.hash.sha256", b"suffix")
            .unwrap();
        idx.commit_write().unwrap();

        idx.begin_write().unwrap();
        let deleted = idx.delete_from_offsetheader(1024).unwrap();
        idx.commit_write().unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(idx.files_table_row_count().unwrap(), 2);
        assert_eq!(root_names(&idx), vec!["mid.txt", "prefix.txt"]);
        assert!(idx.lookup("/suffix.txt", 0).unwrap().is_none());
        assert_eq!(
            idx.get_xattr(0, "user.hash.sha256").unwrap().as_deref(),
            Some(b"prefix".as_slice())
        );
        assert!(idx.get_xattr(1024, "user.hash.sha256").unwrap().is_none());
        assert_eq!(INDEX_VERSION, "0.7.0");
    }

    /// Regression: NULL `offsetheader` must not be treated as 0, so a suffix
    /// delete from `window_start = 0` (or any window) leaves that row in place.
    #[test]
    fn regression_patch_null_offsetheader() {
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
            Ok(())
        })
        .unwrap();
        idx.insert_files_batch(&[file_row("zero.txt", 0), file_row("later.txt", 512)])
            .unwrap();
        idx.insert_xattr(0, "user.hash.crc32", b"zero").unwrap();
        // xattrsdata NULL offsetheader (must not vanish as if it were 0).
        idx.with_conn(|conn| {
            conn.execute(
                r#"INSERT INTO "xattrsdata" (offsetheader, keyid, value)
                   SELECT NULL, id, x'00' FROM "xattrkeys" LIMIT 1"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let nested_null = NestedMemberKey {
            member_path: "nullnest.zip".into(),
            offsetheader: None,
            body_size: 8,
        };
        let nested_zero = NestedMemberKey {
            member_path: "zeronest.zip".into(),
            offsetheader: Some(0),
            body_size: 8,
        };
        idx.set_nested_index(
            &nested_null,
            &dummy_fingerprint(8),
            NESTED_FORMAT_ZIP,
            b"blob-null",
        )
        .unwrap();
        idx.set_nested_index(
            &nested_zero,
            &dummy_fingerprint(8),
            NESTED_FORMAT_ZIP,
            b"blob-zero",
        )
        .unwrap();
        idx.commit_write().unwrap();

        idx.begin_write().unwrap();
        let deleted = idx.delete_from_offsetheader(0).unwrap();
        idx.commit_write().unwrap();
        assert_eq!(deleted, 2, "only non-NULL files rows at/after 0");
        assert_eq!(root_names(&idx), vec!["nullrow.txt"]);
        let fi = idx
            .lookup("/nullrow.txt", 0)
            .unwrap()
            .expect("NULL row kept");
        assert_eq!(fi.size, 3);
        let Some(ratarmount_core::UserData::Tar(ud)) = fi.userdata.first() else {
            panic!("expected Tar userdata");
        };
        assert_eq!(ud.offsetheader, None);
        assert!(
            idx.has_nested_index_key(&nested_null).unwrap(),
            "nestedindexes key without oh= must survive window_start=0"
        );
        assert!(
            !idx.has_nested_index_key(&nested_zero).unwrap(),
            "oh=0 is a real suffix offset and must be deleted"
        );

        // Any later window also leaves the NULL files row.
        idx.begin_write().unwrap();
        let deleted = idx.delete_from_offsetheader(512).unwrap();
        idx.rebuild_fts_if_present().unwrap();
        idx.commit_write().unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(root_names(&idx), vec!["nullrow.txt"]);
        assert!(idx.has_nested_index_key(&nested_null).unwrap());
    }

    #[test]
    fn delete_from_offsetheader_nestedindexes_oh() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[file_row("a.tar", 0), file_row("b.tar", 2048)])
            .unwrap();
        let prefix = NestedMemberKey {
            member_path: "a.tar".into(),
            offsetheader: Some(0),
            body_size: 16,
        };
        let suffix = NestedMemberKey {
            member_path: "b.tar".into(),
            offsetheader: Some(2048),
            body_size: 16,
        };
        let none = NestedMemberKey {
            member_path: "plain.zip".into(),
            offsetheader: None,
            body_size: 16,
        };
        for (k, tag) in [
            (&prefix, b"p".as_slice()),
            (&suffix, b"s".as_slice()),
            (&none, b"n".as_slice()),
        ] {
            idx.set_nested_index(k, &dummy_fingerprint(16), NESTED_FORMAT_ZIP, tag)
                .unwrap();
        }
        idx.commit_write().unwrap();

        idx.begin_write().unwrap();
        let deleted = idx.delete_from_offsetheader(1024).unwrap();
        idx.commit_write().unwrap();
        assert_eq!(deleted, 1);
        assert!(idx.lookup("/a.tar", 0).unwrap().is_some());
        assert!(idx.lookup("/b.tar", 0).unwrap().is_none());
        assert!(idx.has_nested_index_key(&prefix).unwrap());
        assert!(!idx.has_nested_index_key(&suffix).unwrap());
        assert!(
            idx.has_nested_index_key(&none).unwrap(),
            "nestedindexes without oh= is not a suffix row"
        );
    }

    /// Regression: delete + suffix insert in one BEGIN IMMEDIATE must not expose
    /// a suffix hole to a concurrent snapshot (WAL readers see old or new).
    #[test]
    fn regression_patch_txn_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("patch.index.sqlite");
        {
            let mut idx = SqliteIndex::create_writable(Some(&path)).unwrap();
            idx.begin_write().unwrap();
            idx.insert_files_batch(&[file_row("prefix.txt", 0), file_row("old-suffix.txt", 1024)])
                .unwrap();
            idx.store_versions("0.1.0").unwrap();
            idx.commit_write().unwrap();
            idx.publish_tmp().unwrap();
        }

        let idx = SqliteIndex::open_writable(&path).unwrap();
        assert!(!idx.has_mem_index(), "open_writable leaves mem: None");

        idx.begin_write().unwrap();
        let deleted = idx.delete_from_offsetheader(1024).unwrap();
        assert_eq!(deleted, 1);
        // Concurrent connection still sees the last committed snapshot (2 rows).
        assert_eq!(
            sql_file_count(&path),
            2,
            "uncommitted delete must not be visible"
        );
        assert_eq!(
            sql_file_names(&path),
            vec!["old-suffix.txt".to_string(), "prefix.txt".to_string()]
        );

        idx.insert_files_batch(&[file_row("new-suffix.txt", 1024)])
            .unwrap();
        assert_eq!(
            sql_file_count(&path),
            2,
            "uncommitted insert must not appear as a suffix hole (1 prefix-only)"
        );
        idx.rebuild_fts_if_present().unwrap();
        idx.commit_write().unwrap();

        assert_eq!(sql_file_count(&path), 2);
        assert_eq!(
            sql_file_names(&path),
            vec!["new-suffix.txt".to_string(), "prefix.txt".to_string()]
        );
        assert!(idx.lookup("/prefix.txt", 0).unwrap().is_some());
        assert!(idx.lookup("/new-suffix.txt", 0).unwrap().is_some());
        assert!(idx.lookup("/old-suffix.txt", 0).unwrap().is_none());
    }

    #[test]
    fn rebuild_fts_if_present_noop_when_missing() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.rebuild_fts_if_present().unwrap();
        assert!(
            !idx.has_files_fts().unwrap(),
            "rebuild must not create files_fts"
        );
    }

    /// Regression: suffix patch refills an existing FTS5 table so MATCH follows
    /// the new `files` rows (and does not create the table when missing).
    #[test]
    fn rebuild_fts_if_present_after_patch() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[file_row("prefix.txt", 0), file_row("old-suffix.txt", 1024)])
            .unwrap();
        idx.commit_write().unwrap();
        idx.ensure_fts5().unwrap();
        assert_eq!(idx.search_fts("old").unwrap().len(), 1);
        assert_eq!(idx.search_fts("prefix").unwrap().len(), 1);

        idx.begin_write().unwrap();
        let deleted = idx.delete_from_offsetheader(1024).unwrap();
        assert_eq!(deleted, 1);
        idx.insert_files_batch(&[file_row("new-suffix.txt", 1024)])
            .unwrap();
        idx.rebuild_fts_if_present().unwrap();
        idx.commit_write().unwrap();

        assert!(idx.search_fts("old").unwrap().is_empty());
        assert_eq!(idx.search_fts("new").unwrap().len(), 1);
        assert_eq!(idx.search_fts("prefix").unwrap().len(), 1);
        assert_eq!(INDEX_VERSION, "0.7.0");
    }

    #[test]
    fn delete_from_offsetheader_fileunions_if_present() {
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        idx.insert_files_batch(&[file_row("a.txt", 0), file_row("b.txt", 512)])
            .unwrap();
        idx.with_conn(|conn| {
            conn.execute(
                r#"CREATE TABLE "fileunions" (
                    "path" TEXT,
                    "offsetheader" INTEGER
                )"#,
                [],
            )?;
            conn.execute(
                r#"INSERT INTO "fileunions" (path, offsetheader) VALUES ('a', 0), ('b', 512), ('n', NULL)"#,
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let deleted = idx.delete_from_offsetheader(512).unwrap();
        idx.commit_write().unwrap();
        assert_eq!(deleted, 1);
        idx.with_conn(|conn| {
            let n: i64 =
                conn.query_row(r#"SELECT COUNT(*) FROM "fileunions""#, [], |r| r.get(0))?;
            assert_eq!(n, 2, "prefix + NULL fileunions rows remain");
            let nulls: i64 = conn.query_row(
                r#"SELECT COUNT(*) FROM "fileunions" WHERE offsetheader IS NULL"#,
                [],
                |r| r.get(0),
            )?;
            assert_eq!(nulls, 1);
            Ok(())
        })
        .unwrap();
    }
}
