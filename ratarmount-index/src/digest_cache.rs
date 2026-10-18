//! Full base digests, cached only in an existing writable archive index.

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::{sha256_hex_stream, IndexError, Result};

/// Cheap local identity used both by the cache and overlay remount checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveDigestStamp {
    pub size: u64,
    pub mtime_ns: i128,
    pub inode: u64,
}

impl ArchiveDigestStamp {
    pub fn read(path: &Path) -> std::io::Result<Self> {
        let metadata = fs::metadata(path)?;
        let modified = metadata.modified()?;
        let mtime_ns = match modified.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i128,
            Err(e) => -(e.duration().as_nanos() as i128),
        };
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        };
        #[cfg(not(unix))]
        let inode = 0;
        Ok(Self {
            size: metadata.len(),
            mtime_ns,
            inode,
        })
    }
}

/// SHA-256 of every archive byte (unlike tarstats, no small-file policy cap).
/// Uses the same streaming hasher as `archive_full_hash`. Cache failures are
/// optional optimizations; neither a missing index nor its parent is created.
pub fn cached_archive_digest(path: &Path, index: Option<&Path>) -> Result<String> {
    cached_with(path, index, false, |path| {
        Ok(sha256_hex_stream(&mut fs::File::open(path)?)?)
    })
}

/// The cached SHA-256 of `path`, or `None` on a miss. Never hashes the archive.
pub fn peek_archive_digest(path: &Path, index: Option<&Path>) -> Result<Option<String>> {
    match cached_with(path, index, false, |_| {
        Err(IndexError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "digest not cached",
        )))
    }) {
        Ok(digest) => Ok(Some(digest)),
        Err(IndexError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Like [`cached_archive_digest`], but the caller supplies the hashing (for
/// example a cancellable stream). The result is cached like any other.
pub fn cached_archive_digest_with(
    path: &Path,
    index: Option<&Path>,
    hash: impl FnOnce(&Path) -> std::io::Result<String>,
) -> Result<String> {
    cached_with(path, index, false, |path| Ok(hash(path)?))
}

/// Rehash after an intentional archive commit and replace its cached identity.
/// Unlike `cached_archive_digest`, this never trusts a pre-commit cache hit.
pub fn refresh_archive_digest(path: &Path, index: Option<&Path>) -> Result<String> {
    cached_with(path, index, true, |path| {
        Ok(sha256_hex_stream(&mut fs::File::open(path)?)?)
    })
}

fn cached_with(
    path: &Path,
    index: Option<&Path>,
    refresh: bool,
    hash: impl FnOnce(&Path) -> Result<String>,
) -> Result<String> {
    let path = path.canonicalize()?;
    let stamp = ArchiveDigestStamp::read(&path)?;
    // Keep raw OS bytes: two non-UTF-8 paths must not share a lossy cache key.
    let key = path.as_os_str().as_encoded_bytes();
    let size = stamp.size.to_string();
    let mtime = stamp.mtime_ns.to_string();
    let inode = stamp.inode.to_string();
    let conn =
        index.and_then(|index| {
            let metadata = fs::metadata(index).ok()?;
            if !metadata.is_file() || metadata.permissions().readonly() {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() > 1 {
                    return None;
                }
            }
            let index = index.canonicalize().ok()?;
            let snapshot = index
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".sqlite"))
                .and_then(|name| name.rsplit_once(".index."))
                .is_some_and(|(_, id)| crate::parse_index_id(id).is_ok());
            // Never add cache tables to published immutable snapshots or remote caches.
            if crate::is_meta_cache_path(&index)
                || crate::index_pointer_path_for_index_file(&index).is_file()
                || snapshot
            {
                return None;
            }
            let conn =
                Connection::open_with_flags(index, OpenFlags::SQLITE_OPEN_READ_WRITE).ok()?;
            conn.busy_timeout(std::time::Duration::ZERO).ok()?;
            let has_files: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='files')",
            [], |row| row.get(0),
        ).ok()?;
            if !has_files {
                return None;
            }
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS overlay_base_digests (
                path BLOB PRIMARY KEY, size TEXT NOT NULL, mtime_ns TEXT NOT NULL,
                inode TEXT NOT NULL, sha256 TEXT NOT NULL
            );",
            )
            .ok()?;
            Some(conn)
        });
    if let Some(conn) = &conn {
        if !refresh {
            if let Ok(Some(digest)) = conn
                .query_row(
                    "SELECT sha256 FROM overlay_base_digests
             WHERE path=?1 AND size=?2 AND mtime_ns=?3 AND inode=?4",
                    params![key, size, mtime, inode],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            {
                if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Ok(format!("sha256:{digest}"));
                }
            }
        }
    }
    let digest = hash(&path)?;
    if ArchiveDigestStamp::read(&path)? != stamp {
        return Err(IndexError::Io(std::io::Error::other(
            "base changed while hashing",
        )));
    }
    if let Some(conn) = &conn {
        let _ = conn.execute(
            "INSERT OR REPLACE INTO overlay_base_digests VALUES (?1, ?2, ?3, ?4, ?5)",
            params![key, size, mtime, inode, digest],
        );
    }
    Ok(format!("sha256:{digest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a second overlay rehashed the same archive instead of using its index.
    #[test]
    fn regression_digest_cache_reuses_and_invalidates() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let index = dir.path().join("a.tar.index.sqlite");
        Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        let digest = cached_archive_digest(&archive, Some(&index)).unwrap();
        assert_eq!(
            digest,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            cached_with(&archive, Some(&index), false, |_| panic!("cache miss")).unwrap(),
            digest
        );
        fs::write(&archive, b"changed").unwrap();
        assert_ne!(
            cached_archive_digest(&archive, Some(&index)).unwrap(),
            digest
        );
    }

    /// Regression: a commit refresh trusted a stale digest for an unchanged stat tuple.
    #[test]
    fn regression_digest_cache_commit_refresh_replaces_same_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let index = dir.path().join("a.tar.index.sqlite");
        let conn = Connection::open(&index).unwrap();
        conn.execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        let expected = cached_archive_digest(&archive, Some(&index)).unwrap();
        conn.execute(
            "UPDATE overlay_base_digests SET sha256=?1",
            ["0".repeat(64)],
        )
        .unwrap();
        assert_ne!(
            cached_archive_digest(&archive, Some(&index)).unwrap(),
            expected
        );
        assert_eq!(
            refresh_archive_digest(&archive, Some(&index)).unwrap(),
            expected
        );
        assert_eq!(
            cached_with(&archive, Some(&index), false, |_| panic!("cache miss")).unwrap(),
            expected
        );
    }

    /// Regression: digest caching must not initialize missing or unrelated databases.
    #[test]
    fn regression_digest_cache_never_creates_index() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a");
        fs::write(&archive, b"abc").unwrap();
        let index = dir.path().join("missing");
        cached_archive_digest(&archive, Some(&index)).unwrap();
        assert!(!index.exists());
        let conn = Connection::open(&index).unwrap();
        cached_archive_digest(&archive, Some(&index)).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }

    /// Regression: protected or busy indexes must stay unchanged while hashing still succeeds.
    #[test]
    fn regression_digest_cache_readonly_snapshot_and_locked_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let index = dir
            .path()
            .join(format!("a.tar.index.{}.sqlite", "a".repeat(64)));
        let conn = Connection::open(&index).unwrap();
        conn.execute_batch("CREATE TABLE files (name TEXT)")
            .unwrap();
        drop(conn);
        let before = fs::read(&index).unwrap();
        cached_archive_digest(&archive, Some(&index)).unwrap();
        assert_eq!(fs::read(&index).unwrap(), before);
        let ordinary = dir.path().join("a.tar.index.sqlite");
        fs::rename(&index, &ordinary).unwrap();
        let conn = Connection::open(&ordinary).unwrap();
        conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
        cached_archive_digest(&archive, Some(&ordinary)).unwrap();
        conn.execute_batch("ROLLBACK").unwrap();
        drop(conn);
        assert_eq!(fs::read(&ordinary).unwrap(), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&ordinary, fs::Permissions::from_mode(0o444)).unwrap();
            cached_archive_digest(&archive, Some(&ordinary)).unwrap();
            assert_eq!(fs::read(&ordinary).unwrap(), before);
        }
    }

    /// Regression: files above the tarstats full-hash cap still get a strong digest.
    #[test]
    fn regression_digest_cache_hashes_above_tarstats_cap() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_len(crate::TARSTATS_FULL_HASH_MAX + 1)
            .unwrap();
        let expected = sha256_hex_stream(&mut fs::File::open(file.path()).unwrap()).unwrap();
        assert_eq!(
            cached_archive_digest(file.path(), None).unwrap(),
            format!("sha256:{expected}")
        );
    }
}
